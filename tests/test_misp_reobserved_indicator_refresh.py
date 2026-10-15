"""Re-reported indicators refresh their MISP ``last_seen`` (2026-10).

``MISPWriter.push_items`` drops every (type, value) the source already holds in MISP (the PR-F7
cross-event prefetch), so an IOC a feed keeps listing was never written again. The incremental
MISP → Neo4j sync reads only attributes whose MISP timestamp moved, ``Indicator.last_updated``
stayed at the first import, and ``decay_ioc_confidence`` lowered the node at 90 / 180 days and
retired it at 365 days while the feed still listed it.

Now, when a source reports an indicator again and the stored copy's ``last_seen`` (or, without
one, its MISP ``timestamp``) is older than ``EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`` (default 30),
the writer edits that copy's ``last_seen`` (and nothing else) through ``update_attribute``. The
prefetch reads uuid and dates from the rows it already lists. On the sync side the edited
attribute is inside the next window, its node is merged again (``last_updated`` moves, a decay
retirement is lifted) and the source's first-seen claim is unchanged.

Fixtures: a Feodo Tracker item as the collector emits it and MISP 2.5 ``attributes/restSearch``
rows (field names and formats of the API).
"""

from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from collectors import misp_writer as mw  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _attribute_changed_since  # noqa: E402

NOW = datetime.now(timezone.utc)
TAG = "source:Feodo-Tracker"


def _feodo_item(value: str) -> Dict[str, Any]:
    """A Feodo Tracker indicator as ``FeodoCollector.collect`` emits it."""
    return {
        "indicator_type": "ipv4",
        "value": value,
        "zone": ["global"],
        "tag": "feodo_tracker",
        "source": ["feodo_tracker"],
        "first_seen": "2024-05-01 10:00:00",
        "last_seen": "2024-06-01",
        "last_online": "2024-06-01",
        "confidence_score": 0.4,
        "malware_family": "Emotet",
        "port": "443",
        "status": "offline",
        "reference": f"https://feodotracker.abuse.ch/browse/host/{value}/",
        "tags": ["c2_status:offline", "port:443"],
        "threat_type": "botnet_cc",
        "threat_type_desc": "Botnet Command&Control server (C&C)",
        "to_ids": False,
    }


def _misp_iso(when: Optional[datetime]) -> Optional[str]:
    return None if when is None else when.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def _stored(value: str, uuid: str, *, last_seen: Optional[datetime], written: datetime, event: str = "41") -> dict:
    """One row of MISP 2.5 ``attributes/restSearch`` (returnFormat json)."""
    return {
        "id": str(abs(hash(uuid)) % 100000),
        "event_id": event,
        "object_id": "0",
        "object_relation": None,
        "category": "Network activity",
        "type": "ip-dst",
        "to_ids": False,
        "uuid": uuid,
        "timestamp": str(int(written.timestamp())),
        "distribution": "5",
        "sharing_group_id": "0",
        "comment": 'TF_META:{"malware_family": "Emotet", "last_seen": "2024-06-01"}',
        "deleted": False,
        "disable_correlation": False,
        "first_seen": "2024-05-01T10:00:00.000000+00:00",
        "last_seen": _misp_iso(last_seen),
        "value": value,
        "Event": {"org_id": "1", "distribution": "0", "id": event, "info": "EdgeGuard-feodo_tracker-2026-07-01"},
        "Tag": [{"name": TAG}, {"name": "tlp:white"}],
    }


class _Misp:
    """Stands in for MISP behind ``MISPWriter.session.post``: lists ``stored``, answers edits."""

    def __init__(self, stored: List[dict], edit_status: int = 200, tag: str = TAG):
        self.stored = stored
        self.edit_status = edit_status
        self.tag = tag
        self.edits: List[tuple] = []
        self.listings = 0

    def post(self, url: str, json: Optional[dict] = None, **_kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        if "/attributes/edit/" in url:
            uuid = url.rsplit("/", 1)[1]
            self.edits.append((uuid, body))
            r.status_code = self.edit_status
            row = next(a for a in self.stored if a["uuid"] == uuid)
            r.json.return_value = {"Attribute": {**row, **body["Attribute"], "Tag": row["Tag"]}}
        elif "attributes/restSearch" in url and "tags" in body:
            self.listings += 1
            r.json.return_value = {"response": {"Attribute": [a for a in self.stored if self.tag in body["tags"]]}}
        else:  # per-event prefetch of today's event: empty
            r.json.return_value = {"response": {"Attribute": []}}
        return r


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(mw, "MISP_PREFETCH_EXISTING_ATTRS", True)
    monkeypatch.setattr(mw, "MISP_CROSS_EVENT_DEDUP", True)
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0")
    monkeypatch.delenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", raising=False)
    monkeypatch.delenv("EDGEGUARD_MISP_REFRESH_MAX_PER_RUN", raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    yield


def _push(items: List[dict], misp: _Misp):
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = misp.post
    pushed: List[dict] = []

    def push_batch(_self, _event_id, batch):
        pushed.extend(batch)
        return len(batch), 0

    with (
        patch.object(mw.MISPWriter, "_get_or_create_event", return_value="50"),
        patch.object(mw.MISPWriter, "_push_batch", push_batch),
    ):
        result = writer.push_items(items, batch_size=50)
    return result, pushed, writer


# --------------------------------------------------------------------------- the decision


def test_stale_reobserved_indicator_gets_last_seen_and_nothing_else():
    misp = _Misp(
        [_stored("203.0.113.10", "u-stale", last_seen=NOW - timedelta(days=60), written=NOW - timedelta(days=90))]
    )
    before = time.time()
    (ok, failed), pushed, writer = _push([_feodo_item("203.0.113.10"), _feodo_item("198.51.100.7")], misp)

    assert [a["value"] for a in pushed] == ["198.51.100.7"], "the known indicator is still not pushed again"
    assert (ok, failed) == (1, 0)
    assert [uuid for uuid, _ in misp.edits] == ["u-stale"]
    changes = misp.edits[0][1]["Attribute"]
    assert set(changes) == {"last_seen"}, "value, type, tags and comment are never sent in this path"
    refreshed = datetime.fromisoformat(changes["last_seen"])
    assert before - 1 <= refreshed.timestamp() <= time.time() + 1, "the run's time"
    assert writer.stats["attributes_refreshed"] == 1 and writer.stats["attributes_refresh_failed"] == 0
    assert misp.listings == 1, "uuid and dates come from the listing the prefetch already makes"


def test_a_recent_last_seen_from_the_source_is_written_instead_of_the_run_time():
    """AbuseIPDB's blacklist sends ``lastReportedAt``: when that claim lies inside the interval it is
    the value written (the source's own date); a stale or missing claim gives the run's time."""
    reported = (NOW - timedelta(days=3)).replace(microsecond=0)
    row = _stored("192.0.2.44", "u-abuse", last_seen=NOW - timedelta(days=70), written=NOW - timedelta(days=70))
    row["Tag"] = [{"name": "source:AbuseIPDB"}, {"name": "tlp:white"}]
    misp = _Misp([row], tag="source:AbuseIPDB")
    item = {  # AbuseIPDBCollector, blacklist endpoint (first_seen omitted: the endpoint has none)
        "indicator_type": "ipv4",
        "value": "192.0.2.44",
        "zone": ["global"],
        "tag": "abuseipdb",
        "source": ["abuseipdb"],
        "last_seen": reported.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "confidence_score": 1.0,
        "abuse_score": 100,
        "total_reports": 412,
        "num_distinct_users": 97,
        "country": "NL",
        "last_reported": reported.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "description": "AbuseIPDB blacklist entry",
    }
    _push([item], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-abuse"]
    assert datetime.fromisoformat(misp.edits[0][1]["Attribute"]["last_seen"]) == reported


@pytest.mark.parametrize(
    "last_seen_days, written_days, expected",
    [
        (60, 5, True),  # an old last_seen decides even when MISP wrote the copy recently
        (5, 400, False),  # a recent last_seen: no edit
        (None, 45, True),  # no last_seen: the MISP timestamp decides
        (None, 10, False),
        (31, 31, True),
        (29, 29, False),
    ],
)
def test_last_seen_or_else_the_timestamp_is_compared_with_the_interval(last_seen_days, written_days, expected):
    last_seen = None if last_seen_days is None else NOW - timedelta(days=last_seen_days)
    misp = _Misp([_stored("203.0.113.10", "u-1", last_seen=last_seen, written=NOW - timedelta(days=written_days))])
    _push([_feodo_item("203.0.113.10")], misp)
    assert bool(misp.edits) is expected


def test_the_most_recently_seen_copy_decides_and_is_the_one_edited():
    misp = _Misp(
        [
            _stored("203.0.113.10", "u-old", last_seen=NOW - timedelta(days=300), written=NOW - timedelta(days=300)),
            _stored("203.0.113.10", "u-newer", last_seen=NOW - timedelta(days=40), written=NOW - timedelta(days=40)),
        ]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-newer"]

    misp = _Misp(
        [
            _stored("203.0.113.10", "u-old", last_seen=NOW - timedelta(days=300), written=NOW - timedelta(days=300)),
            _stored("203.0.113.10", "u-fresh", last_seen=NOW - timedelta(days=2), written=NOW - timedelta(days=2)),
        ]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert misp.edits == [], "one fresh copy is enough: the node was synced recently"


def test_only_indicators_are_refreshed():
    row = _stored("CVE-2021-44228", "u-cve", last_seen=NOW - timedelta(days=200), written=NOW - timedelta(days=200))
    row["type"] = "vulnerability"
    misp = _Misp([row])
    (ok, failed), pushed, _ = _push(
        [{"type": "vulnerability", "cve_id": "CVE-2021-44228", "tag": "feodo_tracker"}], misp
    )
    assert pushed == [] and misp.edits == [], "CVEs keep their own update path (NVD)"


def test_interval_zero_switches_the_refresh_off(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "0")
    misp = _Misp(
        [_stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=900), written=NOW - timedelta(days=900))]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert misp.edits == []


def test_interval_is_configurable(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "7")
    misp = _Misp([_stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=10), written=NOW - timedelta(days=10))])
    _push([_feodo_item("203.0.113.10")], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-1"]


def test_per_run_cap_takes_the_longest_unseen_first(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_MAX_PER_RUN", "2")
    misp = _Misp(
        [
            _stored("203.0.113.1", "u-40", last_seen=NOW - timedelta(days=40), written=NOW - timedelta(days=40)),
            _stored("203.0.113.2", "u-200", last_seen=NOW - timedelta(days=200), written=NOW - timedelta(days=200)),
            _stored("203.0.113.3", "u-90", last_seen=NOW - timedelta(days=90), written=NOW - timedelta(days=90)),
        ]
    )
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push([_feodo_item(f"203.0.113.{n}") for n in (1, 2, 3)], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-200", "u-90"]
    assert any("[REFRESH] 3 re-reported" in r.message and "1 left for a later run" in r.message for r in caplog.records)


def test_a_failed_refresh_is_counted_and_does_not_fail_the_push(caplog):
    misp = _Misp(
        [_stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=60), written=NOW - timedelta(days=60))],
        edit_status=403,
    )
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        (ok, failed), _pushed, writer = _push([_feodo_item("203.0.113.10")], misp)
    assert (ok, failed) == (0, 0)
    assert writer.stats["attributes_refreshed"] == 0 and writer.stats["attributes_refresh_failed"] == 1
    assert any("[REFRESH]" in r.message and "1 failed" in r.message for r in caplog.records)


def test_the_push_summary_names_the_refreshed_attributes(caplog):
    misp = _Misp([_stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=60), written=NOW - timedelta(days=60))])
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push([_feodo_item("203.0.113.10")], misp)
    assert any(
        "0 new attributes to push" in r.message and "last_seen refreshed on 1 existing attribute" in r.message
        for r in caplog.records
    )


# --------------------------------------------------------------------------- the prefetch


def test_prefetch_records_only_the_keys_asked_for():
    rows = [
        _stored("203.0.113.10", "u-a", last_seen=None, written=NOW - timedelta(days=50)),
        _stored("198.51.100.7", "u-b", last_seen=NOW - timedelta(days=3), written=NOW - timedelta(days=3)),
    ]
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = _Misp(rows).post
    asked: Dict[Any, Any] = {("ip-dst", "203.0.113.10"): None}
    keys = writer._get_existing_source_attribute_keys(TAG, last_seen_of=asked)
    assert keys == {("ip-dst", "203.0.113.10"), ("ip-dst", "198.51.100.7")}, "the duplicate keys are unchanged"
    assert list(asked) == [("ip-dst", "203.0.113.10")], "nothing is kept for keys the push does not report"
    when, uuid = asked[("ip-dst", "203.0.113.10")]
    assert uuid == "u-a" and when == float(rows[0]["timestamp"]), "no last_seen: the MISP timestamp"
    assert writer._get_existing_source_attribute_keys(TAG) == keys, "the call without the mapping is as before"


# --------------------------------------------------------------------------- the sync side


def _edited_row(refreshed: datetime) -> dict:
    """The stored row after the refresh, as MISP lists it: new last_seen, new timestamp."""
    row = _stored("203.0.113.10", "u-1", last_seen=refreshed, written=refreshed)
    row["Tag"] = [{"name": TAG}, {"name": "tlp:white"}, {"name": "zone:Global"}]
    return row


def test_the_edited_attribute_is_inside_the_next_incremental_window():
    previous_sync = NOW - timedelta(days=3)
    stale = _stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=60), written=NOW - timedelta(days=90))
    assert not _attribute_changed_since(stale, previous_sync), "unedited, the copy was never read again"
    assert _attribute_changed_since(_edited_row(NOW - timedelta(hours=1)), previous_sync)


def test_the_sync_keeps_the_first_seen_claim_and_takes_the_refreshed_last_seen():
    refreshed = (NOW - timedelta(hours=1)).replace(microsecond=0)
    event = {"id": 41, "info": "EdgeGuard-feodo_tracker-2026-07-01", "date": "2026-07-01", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_edited_row(refreshed), event)
    assert item["value"] == "203.0.113.10" and item["tag"] == "feodo_tracker"
    assert datetime.fromisoformat(item["first_seen_at_source"]) == datetime(2024, 5, 1, 10, tzinfo=timezone.utc), (
        "the source's first-seen claim does not move"
    )
    assert datetime.fromisoformat(item["last_seen_at_source"]) == refreshed


def test_the_indicator_merge_refreshes_last_updated_and_keeps_first_seen():
    """The batch MERGE the sync runs for the edited attribute: ``last_updated`` and the decay
    reactivation are unconditional, ``first_imported_at`` is set on create only, and the edge keeps
    the earliest first-seen claim and the latest last-seen claim."""
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    refreshed = (NOW - timedelta(hours=1)).replace(microsecond=0).isoformat()
    client.merge_indicators_batch(
        [
            {
                "indicator_type": "ipv4",
                "value": "203.0.113.10",
                "tag": "feodo_tracker",
                "zone": ["global"],
                "first_seen_at_source": "2024-05-01T10:00:00+00:00",
                "last_seen_at_source": refreshed,
            }
        ],
        source_id="feodo_tracker",
    )
    cypher = next(c.args[0] for c in session.run.call_args_list if c.args and "MERGE (n:Indicator" in c.args[0])
    on_create, rest = cypher.split("ON MATCH SET", 1)
    assert "n.first_imported_at = datetime()" in on_create and "first_imported_at" not in rest
    node_set = rest.split("MERGE (n)-[r:SOURCED_FROM]->(s)", 1)[0]
    assert "n.last_updated = datetime()" in node_set, "every merge of the node moves last_updated"
    assert "n.retired_at = CASE WHEN coalesce(n.retired_by, '') = 'decay' THEN null" in node_set
    assert "n.last_decayed_tier = null" in node_set
    assert "WHEN datetime(item.first_seen_at_source) < r.source_reported_first_at" in cypher, "earliest claim kept"
    assert "WHEN datetime(item.last_seen_at_source) > r.source_reported_last_at" in cypher, "latest claim taken"
    rows = next(v for c in session.run.call_args_list for v in c.kwargs.values() if isinstance(v, list) and v)
    assert rows[0]["first_seen_at_source"] == "2024-05-01T10:00:00+00:00"
    assert rows[0]["last_seen_at_source"] == refreshed
    assert json.loads(rows[0]["raw_data"])["last_seen_at_source"] == refreshed
