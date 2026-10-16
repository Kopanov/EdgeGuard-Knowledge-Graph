"""Re-reported indicators refresh their stored MISP copy (2026-10).

``MISPWriter.push_items`` drops every (type, value) the source already holds in MISP (the PR-F7
cross-event prefetch), so an IOC a feed keeps listing was never written again. The incremental
MISP → Neo4j sync reads only attributes whose MISP timestamp moved, ``Indicator.last_updated``
stayed at the first import, and ``decay_ioc_confidence`` lowered the node at 90 / 180 days and
retired it at 365 days while the feed still listed it.

Now, when a source reports an indicator again and MISP last wrote the stored copy (its
``timestamp``) more than ``EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`` ago (default 30), the writer
edits that copy through ``update_attribute``: ``last_seen`` only, set to the source's claim when it
is later than the stored one and otherwise re-sent unchanged, so the field never holds the time of
a run. MISP stamps the edited attribute anew; that moves it into the next sync window and resets
the decision, so a copy is edited at most once per interval. Only copies in EdgeGuard's own events
are edited. The edits stop at a per-run cap, a time budget, or after five failures in a row, and
are paced and checked against the parent-DAG liveness callback every 50 edits. On the sync side
the edited attribute is inside the next window, its node is merged again (``last_updated`` moves,
a decay retirement is lifted) and the source's claims are unchanged.

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
OWN_EVENT = "EdgeGuard-feodo_tracker-2026-07-01"
STORED_FIRST_SEEN = "2024-05-01T10:00:00.000000+00:00"


def _feodo_item(value: str, last_seen: Optional[str] = "2024-06-01") -> Dict[str, Any]:
    """A Feodo Tracker indicator as ``FeodoCollector.collect`` emits it."""
    return {
        "indicator_type": "ipv4",
        "value": value,
        "zone": ["global"],
        "tag": "feodo_tracker",
        "source": ["feodo_tracker"],
        "first_seen": "2024-05-01 10:00:00",
        "last_seen": last_seen,
        "last_online": last_seen,
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


def _stored(
    value: str,
    uuid: str,
    *,
    last_seen: Optional[datetime],
    written: datetime,
    event: str = "41",
    info: str = OWN_EVENT,
    first_seen: Optional[str] = STORED_FIRST_SEEN,
) -> dict:
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
        "first_seen": first_seen,
        "last_seen": _misp_iso(last_seen),
        "value": value,
        "Event": {"org_id": "1", "distribution": "0", "id": event, "info": info},
        "Tag": [{"name": TAG}, {"name": "tlp:white"}],
    }


class _Misp:
    """Stands in for MISP behind ``MISPWriter.session.post``: lists ``stored``, answers edits.

    An accepted edit is stored as MISP 2.5 stores it (``AttributesController::edit``): a ``last_seen``
    sent as null keeps the stored value, and the attribute gets a new ``timestamp`` (``stamp=False``
    answers without one, as if the edit had not been saved). ``statuses`` scripts the HTTP status of
    successive edits; after it is used up, ``edit_status`` applies.
    """

    def __init__(self, stored: List[dict], edit_status: int = 200, tag: str = TAG, stamp: bool = True):
        self.stored = stored
        self.edit_status = edit_status
        self.statuses: List[int] = []
        self.tag = tag
        self.stamp = stamp
        self.edits: List[tuple] = []
        self.listings = 0

    def post(self, url: str, json: Optional[dict] = None, **_kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        if "/attributes/edit/" in url:
            uuid = url.rsplit("/", 1)[1]
            self.edits.append((uuid, body))
            r.status_code = self.statuses.pop(0) if self.statuses else self.edit_status
            row = next(a for a in self.stored if a["uuid"] == uuid)
            if r.status_code == 200:
                for key, sent in body["Attribute"].items():
                    if sent is not None:
                        row[key] = sent
                if self.stamp:
                    row["timestamp"] = str(int(time.time()))
            r.json.return_value = {"Attribute": dict(row)}
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
    for name in (
        "EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS",
        "EDGEGUARD_MISP_REFRESH_MAX_PER_RUN",
        "EDGEGUARD_MISP_REFRESH_MAX_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(mw.time, "sleep", lambda _s: None)
    yield


def _push(items: List[dict], misp: _Misp, liveness_callback=None):
    writer = mw.MISPWriter(
        url="https://misp.test", api_key="dummy", verify_ssl=False, liveness_callback=liveness_callback
    )
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


def _stale(n: int, days: int = 60) -> List[dict]:
    return [
        _stored(f"203.0.113.{i}", f"u-{i}", last_seen=NOW - timedelta(days=400), written=NOW - timedelta(days=days))
        for i in range(1, n + 1)
    ]


# --------------------------------------------------------------------------- the decision


def test_stale_copy_is_edited_with_its_stored_last_seen_and_nothing_else():
    stored_last_seen = NOW - timedelta(days=60)
    misp = _Misp([_stored("203.0.113.10", "u-stale", last_seen=stored_last_seen, written=NOW - timedelta(days=90))])
    before = time.time()
    (ok, failed), pushed, writer = _push([_feodo_item("203.0.113.10"), _feodo_item("198.51.100.7")], misp)

    assert [a["value"] for a in pushed] == ["198.51.100.7"], "the known indicator is still not pushed again"
    assert (ok, failed) == (1, 0)
    assert [uuid for uuid, _ in misp.edits] == ["u-stale"]
    changes = misp.edits[0][1]["Attribute"]
    assert set(changes) == {"last_seen"}, "value, type, tags and comment are never sent in this path"
    assert changes["last_seen"] == _misp_iso(stored_last_seen), (
        "the source's claim (2024-06-01) is older than the stored one: the stored value is re-sent, "
        "never the time of the run"
    )
    assert int(misp.stored[0]["timestamp"]) >= int(before), "MISP stamps the edited copy anew"
    assert writer.stats["attributes_refreshed"] == 1 and writer.stats["attributes_refresh_failed"] == 0
    assert writer.stats["attributes_refresh_deferred"] == 0
    assert misp.listings == 1, "uuid and dates come from the listing the prefetch already makes"


def test_a_rerun_misp_holds_entirely_refreshes_without_an_event_lookup():
    """2026-10: with a complete cross-event listing the duplicate check runs before the event
    lookup, so a re-run whose indicators MISP holds entirely neither looks up nor creates the day's
    event, and the stale stored copy is still refreshed."""
    misp = _Misp([_stored("203.0.113.10", "u-stale", last_seen=None, written=NOW - timedelta(days=90))])
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = misp.post
    lookup = MagicMock(return_value="50")
    with patch.object(mw.MISPWriter, "_get_or_create_event", lookup):
        assert writer.push_items([_feodo_item("203.0.113.10")], batch_size=50) == (0, 0)
    lookup.assert_not_called()
    assert [uuid for uuid, _ in misp.edits] == ["u-stale"]
    assert writer.stats["attributes_refreshed"] == 1


def test_a_copy_written_today_is_not_refreshed_when_the_listing_is_checked_first():
    """With the cross-event check first, an indicator also held in today's event is a refresh
    candidate before the per-event check. The copy MISP wrote last decides, and today's copy was
    written today, so nothing is edited, as when the per-event check dropped it first."""
    misp = _Misp(
        [
            _stored("203.0.113.10", "u-old", last_seen=None, written=NOW - timedelta(days=200)),
            _stored(
                "203.0.113.10",
                "u-today",
                last_seen=None,
                written=NOW,
                event="50",
                info=f"EdgeGuard-feodo_tracker-{NOW.strftime('%Y-%m-%d')}",
            ),
        ]
    )
    (ok, failed), pushed, _writer = _push([_feodo_item("203.0.113.10")], misp)
    assert (ok, failed) == (0, 0) and pushed == []
    assert misp.edits == []


class _PartialListingMisp(_Misp):
    """``_Misp`` whose source listing stops early: page 1 is a full page of 5,000 rows (``page_one``
    and filler rows), page 2 fails with ``failure`` (an HTTP status, or an exception raised as
    ``requests`` raises it). The per-event request answers the stored rows of the event asked for.
    ``calls`` records the requests in order; ``_push_partial`` adds the event lookup."""

    PAGE = 5000

    def __init__(self, page_one: List[dict], today: List[dict], failure: Any):
        super().__init__(page_one + today)
        filler = [
            _stored(f"10.0.{i // 250}.{i % 250}", f"u-fill-{i}", last_seen=None, written=NOW - timedelta(days=2))
            for i in range(self.PAGE - len(page_one))
        ]
        self.page_one = page_one + filler
        self.failure = failure
        self.calls: List[tuple] = []

    def post(self, url: str, json: Optional[dict] = None, **kwargs: Any) -> MagicMock:
        body = json or {}
        r = MagicMock()
        r.status_code = 200
        if "attributes/restSearch" in url and "tags" in body:
            self.calls.append(("listing", body["page"]))
            if body["page"] == 1:
                r.json.return_value = {"response": {"Attribute": self.page_one}}
                return r
            if isinstance(self.failure, Exception):
                raise self.failure
            r.status_code = self.failure
            r.json.return_value = {}
            return r
        if "attributes/restSearch" in url and "eventid" in body:
            self.calls.append(("per_event", body["eventid"]))
            r.json.return_value = {
                "response": {"Attribute": [a for a in self.stored if a["event_id"] == body["eventid"]]}
            }
            return r
        if "/attributes/edit/" in url:
            self.calls.append(("edit", url.rsplit("/", 1)[1]))
        return super().post(url, json=json, **kwargs)


def _push_partial(items: List[dict], misp: _PartialListingMisp):
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = misp.post
    pushed: List[dict] = []

    def lookup(_self, source, _date):
        misp.calls.append(("lookup", source))
        return "50"

    def push_batch(_self, _event_id, batch):
        pushed.extend(batch)
        return len(batch), 0

    with (
        patch.object(mw.MISPWriter, "_get_or_create_event", lookup),
        patch.object(mw.MISPWriter, "_push_batch", push_batch),
    ):
        result = writer.push_items(items, batch_size=50)
    return result, pushed


_LISTING_FAILURES = [
    pytest.param(500, id="http-500"),
    pytest.param(mw.requests.exceptions.ConnectionError("connection reset"), id="connection-error"),
]


@pytest.mark.parametrize("failure", _LISTING_FAILURES)
def test_a_partial_listing_keeps_the_event_lookup_first_so_todays_copy_is_seen(failure):
    """2026-10: a listing that stopped early is not checked before the event lookup. Page 1 holds
    a stale copy of the indicator from an earlier event; its copy in today's event lies on page 2,
    which failed. The per-event filter finds today's copy first, so nothing is refreshed: checked
    first, the partial keys would skip the indicator and edit the stale copy although MISP wrote
    today's copy today."""
    today = f"EdgeGuard-feodo_tracker-{NOW.strftime('%Y-%m-%d')}"
    misp = _PartialListingMisp(
        page_one=[_stored("203.0.113.10", "u-old", last_seen=None, written=NOW - timedelta(days=200))],
        today=[_stored("203.0.113.10", "u-today", last_seen=None, written=NOW, event="50", info=today)],
        failure=failure,
    )
    (ok, failed), pushed = _push_partial([_feodo_item("203.0.113.10")], misp)
    assert (ok, failed) == (0, 0) and pushed == []
    assert misp.calls == [("listing", 1), ("listing", 2), ("lookup", "feodo_tracker"), ("per_event", "50")]
    assert misp.edits == [], "today's copy was written today: no refresh is due"


@pytest.mark.parametrize("failure", _LISTING_FAILURES)
def test_a_partial_listing_still_refreshes_a_stale_copy_it_read(failure):
    """With the event lookup first (a listing that stopped early), an indicator absent from today's
    event and held in the partial keys is skipped by the cross-event filter after the per-event
    one, and its stale copy read on page 1 is refreshed, as before 2026-10."""
    misp = _PartialListingMisp(
        page_one=[_stored("203.0.113.10", "u-old", last_seen=None, written=NOW - timedelta(days=200))],
        today=[],
        failure=failure,
    )
    (ok, failed), pushed = _push_partial([_feodo_item("203.0.113.10")], misp)
    assert (ok, failed) == (0, 0) and pushed == []
    assert misp.calls == [
        ("listing", 1),
        ("listing", 2),
        ("lookup", "feodo_tracker"),
        ("per_event", "50"),
        ("edit", "u-old"),
    ]
    assert [uuid for uuid, _ in misp.edits] == ["u-old"]


def test_a_later_last_seen_from_the_source_is_written():
    """AbuseIPDB's blacklist sends ``lastReportedAt``: a claim later than the stored ``last_seen`` is
    the value written (the source's own date)."""
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
    "stored_days, first_seen, reported, expected",
    [
        (60, STORED_FIRST_SEEN, None, "stored"),  # the source sends no last_seen
        (60, STORED_FIRST_SEEN, "2024-06-01", "stored"),  # an older claim does not move it back
        (60, STORED_FIRST_SEEN, (NOW + timedelta(days=2)).isoformat(), "stored"),  # nor a future one
        (None, STORED_FIRST_SEEN, None, None),  # nothing stored, nothing claimed: null, as stored
        (None, STORED_FIRST_SEEN, "2024-04-01", None),  # before first_seen: MISP would refuse it
        (None, STORED_FIRST_SEEN, "2024-06-01", "reported"),
        (None, None, "2024-06-01", "reported"),
    ],
    ids=[
        "no-claim",
        "older-claim",
        "future-claim",
        "nothing-stored-no-claim",
        "claim-before-first-seen",
        "claim-nothing-stored",
        "claim-no-dates-stored",
    ],
)
def test_the_value_sent_is_a_claim_of_the_source(stored_days, first_seen, reported, expected):
    stored_last_seen = None if stored_days is None else NOW - timedelta(days=stored_days)
    misp = _Misp(
        [
            _stored(
                "203.0.113.10",
                "u-1",
                last_seen=stored_last_seen,
                written=NOW - timedelta(days=45),
                first_seen=first_seen,
            )
        ]
    )
    item = _feodo_item("203.0.113.10", last_seen=reported)
    item["first_seen"] = "2024-01-01 00:00:00"  # the collector's own check keeps every claim here
    _push([item], misp)
    sent = misp.edits[0][1]["Attribute"]["last_seen"]
    want = {"stored": _misp_iso(stored_last_seen), None: None}.get(expected, expected)
    if expected == "reported":
        assert datetime.fromisoformat(sent) == datetime.fromisoformat(f"{reported}T00:00:00+00:00")
    else:
        assert sent == want


@pytest.mark.parametrize(
    "last_seen_days, written_days, expected",
    [
        # Feodo Tracker's list has been frozen since 2026-03-04: an old last_online on a copy the
        # baseline wrote days ago is no reason to edit it.
        (220, 2, False),
        (5, 400, True),  # MISP's write time decides, not the source's claim
        (None, 45, True),
        (None, 10, False),
        (31, 31, True),
        (29, 29, False),
    ],
)
def test_the_misp_timestamp_is_compared_with_the_interval(last_seen_days, written_days, expected):
    last_seen = None if last_seen_days is None else NOW - timedelta(days=last_seen_days)
    misp = _Misp([_stored("203.0.113.10", "u-1", last_seen=last_seen, written=NOW - timedelta(days=written_days))])
    _push([_feodo_item("203.0.113.10")], misp)
    assert bool(misp.edits) is expected


def test_a_copy_is_edited_at_most_once_per_interval():
    """The edit resets the timestamp the decision reads. A claim just inside the interval used to
    be written as the new last_seen and crossed the cutoff two days later: a second edit."""
    row = _stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=100), written=NOW - timedelta(days=100))
    misp = _Misp([row])
    just_inside = (NOW - timedelta(days=29)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    _push([_feodo_item("203.0.113.10", last_seen=just_inside)], misp)
    assert len(misp.edits) == 1
    assert datetime.fromisoformat(row["last_seen"]) == datetime.fromisoformat(just_inside)

    # Two days later: every stored date is two days older, and the feed repeats its claim.
    row["timestamp"] = str(int(row["timestamp"]) - 2 * 86400)
    row["last_seen"] = _misp_iso(datetime.fromisoformat(row["last_seen"]) - timedelta(days=2))
    _push([_feodo_item("203.0.113.10", last_seen=(NOW - timedelta(days=31)).isoformat())], misp)
    assert len(misp.edits) == 1, "no second edit inside the interval"


def test_the_copy_misp_wrote_last_decides_and_is_the_one_edited():
    misp = _Misp(
        [
            _stored("203.0.113.10", "u-old", last_seen=NOW - timedelta(days=30), written=NOW - timedelta(days=300)),
            _stored("203.0.113.10", "u-newer", last_seen=NOW - timedelta(days=300), written=NOW - timedelta(days=40)),
        ]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-newer"]

    misp = _Misp(
        [
            _stored("203.0.113.10", "u-old", last_seen=NOW - timedelta(days=300), written=NOW - timedelta(days=300)),
            _stored("203.0.113.10", "u-fresh", last_seen=NOW - timedelta(days=300), written=NOW - timedelta(days=2)),
        ]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert misp.edits == [], "one copy written recently is enough: the node was synced recently"


def test_only_copies_in_edgeguard_events_are_edited():
    """The listing finds the source tag in any event. A newer copy an analyst (or a federated
    organisation) keeps in their own event is not EdgeGuard's to edit, and the sync never reads it."""
    misp = _Misp(
        [
            _stored("203.0.113.10", "u-own", last_seen=None, written=NOW - timedelta(days=200)),
            _stored(
                "203.0.113.10",
                "u-analyst",
                last_seen=None,
                written=NOW - timedelta(days=50),
                event="77",
                info="Phishing wave triage (analyst copy)",
            ),
        ]
    )
    (ok, failed), pushed, _ = _push([_feodo_item("203.0.113.10")], misp)
    assert pushed == [], "the duplicate check still counts the analyst's copy"
    assert [uuid for uuid, _ in misp.edits] == ["u-own"]

    misp = _Misp(
        [_stored("203.0.113.10", "u-analyst", last_seen=None, written=NOW - timedelta(days=50), info="Triage")]
    )
    _push([_feodo_item("203.0.113.10")], misp)
    assert misp.edits == []


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
    misp = _Misp(_stale(1, days=900))
    _push([_feodo_item("203.0.113.1")], misp)
    assert misp.edits == []


def test_interval_is_configurable(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS", "7")
    misp = _Misp(_stale(1, days=10))
    _push([_feodo_item("203.0.113.1")], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-1"]


def test_an_edit_misp_did_not_stamp_counts_as_failed():
    """A refresh exists to move the attribute's timestamp: an answer without a newer one is not a
    refresh, whatever its ``last_seen`` shows."""
    misp = _Misp(_stale(1), stamp=False)
    _push_result, _pushed, writer = _push([_feodo_item("203.0.113.1")], misp)
    assert len(misp.edits) == 1
    assert writer.stats["attributes_refreshed"] == 0 and writer.stats["attributes_refresh_failed"] == 1
    assert writer.stats["attributes_unconfirmed"] == 1


# --------------------------------------------------------------------------- bounds of one run


def test_per_run_cap_takes_the_longest_unwritten_first(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_MAX_PER_RUN", "2")
    misp = _Misp(
        [
            _stored("203.0.113.1", "u-40", last_seen=NOW - timedelta(days=400), written=NOW - timedelta(days=40)),
            _stored("203.0.113.2", "u-200", last_seen=NOW - timedelta(days=40), written=NOW - timedelta(days=200)),
            _stored("203.0.113.3", "u-90", last_seen=NOW - timedelta(days=40), written=NOW - timedelta(days=90)),
        ]
    )
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push_result, _pushed, writer = _push([_feodo_item(f"203.0.113.{n}") for n in (1, 2, 3)], misp)
    assert [uuid for uuid, _ in misp.edits] == ["u-200", "u-90"]
    assert writer.stats["attributes_refresh_deferred"] == 1
    assert any(
        "[REFRESH] 3 re-reported" in r.message
        and "1 left for a later run" in r.message
        and "EDGEGUARD_MISP_REFRESH_MAX_PER_RUN=2" in r.message
        for r in caplog.records
    )


def test_a_failed_refresh_is_counted_and_does_not_fail_the_push(caplog):
    misp = _Misp(_stale(1), edit_status=403)
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        (ok, failed), _pushed, writer = _push([_feodo_item("203.0.113.1")], misp)
    assert (ok, failed) == (0, 0)
    assert writer.stats["attributes_refreshed"] == 0 and writer.stats["attributes_refresh_failed"] == 1
    assert any("[REFRESH]" in r.message and "1 failed" in r.message for r in caplog.records)


def test_the_refresh_stops_after_five_failed_edits_in_a_row(caplog):
    """MISP failing: each failed edit costs up to three attempts, so trying every due edit could
    outlast the collector task. A success in between resets the count."""
    misp = _Misp(_stale(14))
    misp.statuses = [403] * 4 + [200] + [403] * 5
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push_result, _pushed, writer = _push([_feodo_item(f"203.0.113.{n}") for n in range(1, 15)], misp)
    assert len(misp.edits) == 10, "four failures, a success, then five failures: the rest is not attempted"
    assert writer.stats["attributes_refreshed"] == 1 and writer.stats["attributes_refresh_failed"] == 9
    assert writer.stats["attributes_refresh_deferred"] == 4
    assert any("4 left for a later run (stopped after 5 failed edits in a row)" in r.message for r in caplog.records)


def test_the_refresh_stops_when_its_time_budget_is_spent(monkeypatch, caplog):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_MAX_SECONDS", "100")
    clock = iter(range(0, 10_000, 60))  # every reading of the clock is 60 s later
    monkeypatch.setattr(mw.time, "monotonic", lambda: next(clock))
    misp = _Misp(_stale(5))
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push_result, _pushed, writer = _push([_feodo_item(f"203.0.113.{n}") for n in range(1, 6)], misp)
    assert len(misp.edits) == 2, "started at 0 s; the edit at 60 s still starts, none at 120 s"
    assert writer.stats["attributes_refreshed"] == 2 and writer.stats["attributes_refresh_deferred"] == 3
    assert any("EDGEGUARD_MISP_REFRESH_MAX_SECONDS=100 spent" in r.message for r in caplog.records)


def test_a_time_budget_of_zero_means_no_limit(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_REFRESH_MAX_SECONDS", "0")
    clock = iter(range(0, 10_000_000, 100_000))
    monkeypatch.setattr(mw.time, "monotonic", lambda: next(clock))
    misp = _Misp(_stale(5))
    _push([_feodo_item(f"203.0.113.{n}") for n in range(1, 6)], misp)
    assert len(misp.edits) == 5


def test_every_50_edits_the_liveness_callback_runs_and_the_edits_pause(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "2.5")
    pauses: List[float] = []
    monkeypatch.setattr(mw.time, "sleep", pauses.append)
    liveness = MagicMock()
    misp = _Misp(_stale(51))
    _push([_feodo_item(f"203.0.113.{n}") for n in range(1, 52)], misp, liveness_callback=liveness)
    assert len(misp.edits) == 51
    assert liveness.call_count == 1, "after edit 50, not after the last edit"
    assert pauses == [2.5]


def test_a_liveness_callback_that_raises_stops_the_remaining_edits():
    """The parent DAG run failed: the callback raises to abort the orphaned collector."""

    class ParentRunFailed(RuntimeError):
        pass

    misp = _Misp(_stale(60))
    with pytest.raises(ParentRunFailed):
        _push(
            [_feodo_item(f"203.0.113.{n}") for n in range(1, 61)],
            misp,
            liveness_callback=MagicMock(side_effect=ParentRunFailed("parent DAG run is no longer running")),
        )
    assert len(misp.edits) == 50


def test_the_push_summary_names_the_refreshed_attributes(caplog):
    misp = _Misp(_stale(1))
    with caplog.at_level(logging.INFO, logger=mw.logger.name):
        _push([_feodo_item("203.0.113.1")], misp)
    assert any(
        "0 new attributes to push" in r.message and "1 existing attribute(s) refreshed" in r.message
        for r in caplog.records
    )


# --------------------------------------------------------------------------- the prefetch


def test_prefetch_records_only_the_keys_asked_for_in_edgeguard_events():
    rows = [
        _stored("203.0.113.10", "u-a", last_seen=None, written=NOW - timedelta(days=50)),
        _stored("198.51.100.7", "u-b", last_seen=NOW - timedelta(days=3), written=NOW - timedelta(days=3)),
        _stored("203.0.113.10", "u-c", last_seen=None, written=NOW - timedelta(days=1), info="Analyst event"),
    ]
    writer = mw.MISPWriter(url="https://misp.test", api_key="dummy", verify_ssl=False)
    writer.session = MagicMock()
    writer.session.post.side_effect = _Misp(rows).post
    asked: Dict[Any, Any] = {("ip-dst", "203.0.113.10"): None}
    keys = writer._get_existing_source_attribute_keys(TAG, stored_copy_of=asked)
    assert keys == {("ip-dst", "203.0.113.10"), ("ip-dst", "198.51.100.7")}, "the duplicate keys are unchanged"
    assert list(asked) == [("ip-dst", "203.0.113.10")], "nothing is kept for keys the push does not report"
    copy = asked[("ip-dst", "203.0.113.10")]
    assert copy == mw.StoredCopy(
        written=float(rows[0]["timestamp"]), uuid="u-a", first_seen=STORED_FIRST_SEEN, last_seen=None
    ), "the copy in the EdgeGuard event, not the newer one in the analyst's event"
    assert writer._get_existing_source_attribute_keys(TAG) == keys, "the call without the mapping is as before"


# --------------------------------------------------------------------------- the sync side


def _edited_row(stored_last_seen: datetime, written: datetime) -> dict:
    """The stored row after a refresh, as MISP lists it: the source's dates kept, a new timestamp."""
    row = _stored("203.0.113.10", "u-1", last_seen=stored_last_seen, written=written)
    row["Tag"] = [{"name": TAG}, {"name": "tlp:white"}, {"name": "zone:Global"}]
    return row


def test_the_edited_attribute_is_inside_the_next_incremental_window():
    previous_sync = NOW - timedelta(days=3)
    stale = _stored("203.0.113.10", "u-1", last_seen=NOW - timedelta(days=60), written=NOW - timedelta(days=90))
    assert not _attribute_changed_since(stale, previous_sync), "unedited, the copy was never read again"
    assert _attribute_changed_since(_edited_row(NOW - timedelta(days=60), NOW - timedelta(hours=1)), previous_sync)


def test_the_sync_reads_the_source_claims_unchanged():
    stored_last_seen = (NOW - timedelta(days=60)).replace(microsecond=0)
    event = {"id": 41, "info": OWN_EVENT, "date": "2026-07-01", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        _edited_row(stored_last_seen, NOW - timedelta(hours=1)), event
    )
    assert item["value"] == "203.0.113.10" and item["tag"] == "feodo_tracker"
    assert datetime.fromisoformat(item["first_seen_at_source"]) == datetime(2024, 5, 1, 10, tzinfo=timezone.utc), (
        "the source's first-seen claim does not move"
    )
    assert datetime.fromisoformat(item["last_seen_at_source"]) == stored_last_seen, (
        "the last-seen claim is the source's, not the time of the refresh"
    )


def test_the_indicator_merge_records_the_report_and_keeps_first_seen():
    """The batch MERGE the sync runs for the edited attribute. ``last_updated`` moves on every
    write (a database fact). Since 2026-10-16 the node no longer reactivates unconditionally: it
    records the report forward only and applies the one aging rule, so its age moves only when the
    report is newer (``indicator_aging``). ``first_imported_at`` is set on create only, and the edge
    keeps the earliest first-seen claim and the latest last-seen claim."""
    from indicator_aging import aging_set_clause, node_report_items
    from neo4j_client import Neo4jClient

    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    claimed = (NOW - timedelta(days=60)).replace(microsecond=0).isoformat()
    event = {"id": 41, "info": OWN_EVENT, "date": "2026-07-01", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        _edited_row((NOW - timedelta(days=60)).replace(microsecond=0), NOW - timedelta(hours=1)), event
    )
    client.merge_indicators_batch([item], source_id="feodo_tracker")
    cypher = next(c.args[0] for c in session.run.call_args_list if c.args and "MERGE (n:Indicator" in c.args[0])
    on_create, rest = cypher.split("ON MATCH SET", 1)
    assert "n.first_imported_at = datetime()" in on_create and "first_imported_at = " not in rest
    node_set = rest.split("MERGE (n)-[r:SOURCED_FROM]->(s)", 1)[0]
    assert "n.last_updated = datetime()" in node_set, "every merge of the node moves last_updated"
    assert node_report_items("n", "item.report", "item.source_id") in node_set
    assert node_set.index(node_report_items("n", "item.report", "item.source_id")) < node_set.index(
        aging_set_clause("n")
    ), "the rule, in a SET clause of its own, reads the report recorded in the same write"
    assert "retired_by, '') = 'decay' THEN null" not in node_set, "no unconditional reactivation"
    assert "last_decayed" not in cypher
    assert "WHEN datetime(item.first_seen_at_source) < r.source_reported_first_at" in cypher, "earliest claim kept"
    assert "WHEN datetime(item.last_seen_at_source) > r.source_reported_last_at" in cypher, "latest claim taken"
    rows = next(v for c in session.run.call_args_list for v in c.kwargs.values() if isinstance(v, list) and v)
    assert datetime.fromisoformat(rows[0]["first_seen_at_source"]) == datetime(2024, 5, 1, 10, tzinfo=timezone.utc)
    assert rows[0]["last_seen_at_source"] == item["last_seen_at_source"]
    assert datetime.fromisoformat(rows[0]["last_seen_at_source"]).isoformat() == claimed
    assert json.loads(rows[0]["raw_data"])["last_seen_at_source"] == item["last_seen_at_source"]


# --------------------------------------------------------------------------- the refresh and aging (2026-10-16)


def test_a_refresh_that_keeps_the_source_date_does_not_make_the_indicator_younger():
    """The refresh moves MISP's timestamp (T) and keeps the source's ``last_seen`` (L) unless the
    source claims a later one. The indicator ages from ``min(T, L)``, so the edited copy still
    reports L: re-writing the copy does not reset its age."""
    stored_last_seen = (NOW - timedelta(days=60)).replace(microsecond=0)
    edited_at = (NOW - timedelta(hours=1)).replace(microsecond=0)
    event = {"id": 41, "info": OWN_EVENT, "date": "2026-07-01", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_edited_row(stored_last_seen, edited_at), event)
    assert datetime.fromisoformat(item["recorded_at"]) == edited_at, "T: the edit"
    assert datetime.fromisoformat(item["reported_at"]) == stored_last_seen, "the source's own date"
    assert item["reported_basis"] == "source_date" and item["report_ref"] == "u-1"


def test_a_refresh_with_a_later_source_claim_moves_the_report_time():
    """The source now claims a later ``last_seen``: the refresh sends it and the indicator ages from it."""
    copy = mw.StoredCopy(
        written=(NOW - timedelta(days=40)).timestamp(),
        uuid="u-1",
        first_seen=STORED_FIRST_SEEN,
        last_seen=(NOW - timedelta(days=60)).isoformat(),
    )
    later = (NOW - timedelta(days=2)).replace(microsecond=0)
    sent = mw._refreshed_last_seen(copy, later.isoformat(), NOW.timestamp())
    assert datetime.fromisoformat(sent) == later
    row = _edited_row(later, NOW - timedelta(minutes=5))
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        row, {"id": 41, "info": OWN_EVENT, "date": "2026-07-01", "Tag": []}
    )
    assert datetime.fromisoformat(item["reported_at"]) == later and item["reported_basis"] == "source_date"


def test_a_refresh_of_an_undated_source_reports_the_time_of_the_edit():
    """SSL Blacklist and MalwareBazaar store no ``last_seen``: the report time is T, so a refresh (at
    most once per EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS) brings a still-listed indicator back to tier 0,
    and one re-reported within the window keeps its older time until the window passes (30 days,
    well inside the first tier at 90)."""
    edited_at = (NOW - timedelta(minutes=5)).replace(microsecond=0)
    row = _edited_row(NOW - timedelta(days=60), edited_at)
    row.pop("last_seen")
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        row, {"id": 41, "info": OWN_EVENT, "date": "2026-07-01", "Tag": []}
    )
    assert datetime.fromisoformat(item["reported_at"]) == edited_at and item["reported_basis"] == "misp_recorded"
