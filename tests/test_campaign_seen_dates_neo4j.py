"""Campaign first / last seen on a real Neo4j (2026-10-25): the seen dates of its indicators.

An OTX indicator's ``SOURCED_FROM`` edge carries no first-seen / last-seen claim (OTX is not on the
reliable first-seen allowlist), but the source's latest report, ``r.last_reported_at``. The campaign
build read the claims alone, so a campaign whose indicators all came from OTX took EdgeGuard's import
time as its first and last seen (296 of 539 campaigns on the hosted graph, 2026-10-25). The build and
the alert enrichment now read the seen dates of ``indicator_seen_dates``: per edge the claim, else the
latest report; the first seen date never later than the first import; the indicator's own times only
when no edge dates it.

The indicators are written as production writes them: an item shaped as the collector emits it, the
attribute ``MISPWriter`` builds from it with the fields MISP adds when it stores it (the key set of a
stored OTX attribute, 2026-10-25), ``parse_attribute`` and ``merge_indicators_batch``. The OTX test
checks the edge shape before relying on it. Dates are relative to the run, so the fixture never ages
out of the aging rule. Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT`` (the indicators and campaigns
the production code creates get the label right after), refuses any other node.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

ACTOR = "it-seen-actor"
CAMPAIGN = f"{ACTOR} Campaign"
FAMILY = "it-seen-family"

FIXTURE = f"""
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Source:{LABEL} {{source_id: 'threatfox'}})
CREATE (a:ThreatActor:{LABEL} {{name: '{ACTOR}', uuid: 'u-seen-actor', source: ['alienvault_otx']}})
CREATE (m:Malware:{LABEL} {{name: '{FAMILY}', uuid: 'u-seen-family', source: ['alienvault_otx']}})
CREATE (m)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx']}}]->(a)
"""

# The fields MISP 2.5 adds to an attribute it stores (the key set of a stored OTX attribute on
# 2026-10-25, besides the writer's type, value, comment, to_ids, Tag, first_seen and last_seen, and
# the event summary a search adds, which the sync passes to ``parse_attribute`` as the event).
_MISP_FIELDS = {
    "category": "Network activity",
    "deleted": False,
    "disable_correlation": False,
    "distribution": "5",
    "object_id": "0",
    "object_relation": None,
    "sharing_group_id": "0",
}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver, monkeypatch):
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _misp_time(when: datetime) -> str:
    """A time as MISP 2.5 lists an attribute's ``first_seen`` / ``last_seen``."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def _stored(item: dict, n: int, recorded: datetime) -> dict:
    """The attribute ``MISPWriter`` builds from ``item``, as MISP stores and lists it."""
    from collectors.misp_writer import MISPWriter

    attr = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False).create_attribute(item)
    assert attr is not None
    for key in ("first_seen", "last_seen"):
        if attr.get(key):
            attr[key] = _misp_time(datetime.fromisoformat(attr[key]).astimezone(timezone.utc))
    return {
        **_MISP_FIELDS,
        **attr,
        "id": str(5000 + n),
        "event_id": "77",
        "uuid": f"6f3c1d5e-0000-4000-8000-{5000 + n:012d}",
        "timestamp": str(int(recorded.timestamp())),
    }


def _otx_item(value: str, created: datetime, modified: datetime) -> dict:
    """An indicator as the OTX collector emits it: ``first_seen`` / ``last_seen`` are the indicator's
    ``created`` / ``modified`` (zone-less, as the OTX API gives them)."""
    return {
        "indicator_type": "domain",
        "value": value,
        "zone": ["global"],
        "tag": "alienvault_otx",
        "source": ["alienvault_otx"],
        "confidence_score": 0.5,
        "description": "",
        "indicator_role": "",
        "is_active": True,
        "pulse_malware_families": [FAMILY],
        "pulse_malware_actor_pairs": [],
        "pulse_id": "it-seen-pulse",
        "several_actor_pulses": [],
        "several_actor_pulses_by_name": [],
        "pulse_name": "IT seen dates",
        "pulse_tags": [],
        "pulse_references": [],
        "pulse_author": "it",
        "pulse_tlp": "white",
        "attack_ids": [],
        "targeted_countries": [],
        "otx_industries": [],
        "first_seen": created.strftime("%Y-%m-%dT%H:%M:%S"),
        "last_seen": modified.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def _threatfox_item(value: str, first: datetime, last: datetime) -> dict:
    """An IOC as the ThreatFox collector emits it (``"YYYY-MM-DD HH:MM:SS UTC"`` dates)."""
    return {
        "indicator_type": "domain",
        "value": value,
        "zone": ["global"],
        "tag": "threatfox",
        "source": ["threatfox"],
        "first_seen": first.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "last_seen": last.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "last_updated": _now().isoformat(),
        "confidence_score": 0.75,
        "malware_family": FAMILY,
        "threat_type": "botnet_cc",
        "threat_type_desc": "",
        "ioc_id": "it-seen-ioc",
        "malware_alias": "",
        "malware_malpedia": "",
        "reporter": "it",
        "reference": "",
        "tags": [],
    }


def _merge(client, raw_driver, source_id: str, attrs: list) -> None:
    """Parse ``attrs`` as the sync parses them and merge them; the nodes the merge creates get the
    suite's label, so the cleanup removes them."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    event = {"id": 77, "info": f"EdgeGuard-{source_id}-it", "date": _now().date().isoformat(), "Tag": []}
    syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
    items = [syncer.parse_attribute(attr, event)[0] for attr in attrs]
    try:
        assert client.merge_indicators_batch(items, source_id=source_id) == (len(items), 0)
    finally:
        with raw_driver.session() as session:
            session.run(f"MATCH (n:Indicator) WHERE NOT n:{LABEL} SET n:{LABEL}")


def _indicates(raw_driver, *values: str) -> None:
    """``build_relationships`` links an indicator to its family; here the link is written directly."""
    with raw_driver.session() as session:
        session.run(
            f"MATCH (m:Malware:{LABEL} {{name: $family}}) UNWIND $values AS v "
            f"MATCH (i:Indicator:{LABEL} {{value: v}}) "
            "CREATE (i)-[:INDICATES {match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx']}]->(m)",
            family=FAMILY,
            values=list(values),
        )


def _build(client, raw_driver) -> dict:
    """The campaign's dates after ``build_campaign_nodes`` as the enrichment run calls it."""
    import enrichment_jobs

    enrichment_jobs.build_campaign_nodes(client)
    with raw_driver.session() as session:
        session.run(f"MATCH (c:Campaign) WHERE NOT c:{LABEL} SET c:{LABEL}")
        row = session.run(
            "MATCH (c:Campaign {name: $name}) RETURN c.first_seen AS first, c.last_seen AS last, "
            "c.indicator_count AS indicators",
            name=CAMPAIGN,
        ).single()
    assert row is not None, "the campaign was not built"
    return {"first": row["first"].to_native(), "last": row["last"].to_native(), "indicators": row["indicators"]}


def _node_times(raw_driver) -> dict:
    with raw_driver.session() as session:
        return {
            r["v"]: (r["fi"].to_native(), r["lu"].to_native())
            for r in session.run(
                f"MATCH (i:Indicator:{LABEL}) RETURN i.value AS v, i.first_imported_at AS fi, i.last_updated AS lu"
            )
        }


def _alert_dates(client, value: str) -> tuple:
    """``first_seen`` / ``last_updated`` of the alert enrichment's answer for ``value``."""
    from alert_processor import AlertProcessor

    answer = AlertProcessor(neo4j_client=client).enrich_alert_read_only(
        {"alert_id": "it-seen", "zone": "global", "threat": {"indicator": value, "type": "domain"}}
    )
    assert answer.query_metadata["indicator_found"] is True
    return _parse(answer.enrichment["first_seen"]), _parse(answer.enrichment["last_updated"])


def _parse(text: str) -> datetime:
    """An ISO-8601 time as the payload gives it (Neo4j's nanoseconds cut to microseconds)."""
    head, sep, rest = text.partition(".")
    if sep:
        digits = "".join(ch for ch in rest if ch.isdigit())
        rest = digits[:6] + rest[len(digits) :]
        text = f"{head}.{rest}"
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_an_otx_only_campaign_is_dated_by_the_reports_not_by_the_import(client, raw_driver):
    now = _now()
    reports = {"it-seen-a.example": now - timedelta(days=200), "it-seen-b.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    # The edge shape of a stored OTX indicator: no claim, the report the attribute's last_seen dates.
    with raw_driver.session() as session:
        edges = {
            r["v"]: r
            for r in session.run(
                f"MATCH (i:Indicator:{LABEL})-[r:SOURCED_FROM]->(:Source {{source_id: 'alienvault_otx'}}) "
                "RETURN i.value AS v, r.source_reported_first_at AS first_at, r.source_reported_last_at AS last_at, "
                "r.last_reported_at AS reported"
            )
        }
    assert set(edges) == set(reports)
    for value, report in reports.items():
        assert (edges[value]["first_at"], edges[value]["last_at"]) == (None, None), "OTX gives no claim"
        assert edges[value]["reported"].to_native() == report
    _indicates(raw_driver, *reports)

    campaign = _build(client, raw_driver)

    times = _node_times(raw_driver)
    assert campaign["indicators"] == 2
    # The latest report of each indicator: the earliest for first seen, the latest for last seen.
    # (OTX's ``created`` stays in MISP's first_seen: the sync drops OTX's claims.)
    assert campaign["first"] == reports["it-seen-a.example"]
    assert campaign["last"] == reports["it-seen-b.example"]
    assert campaign["first"] < min(fi for fi, _ in times.values()), "not the import time"
    assert campaign["last"] < max(lu for _, lu in times.values()), "not the last write"
    # The alert enrichment reads the same dates.
    assert _alert_dates(client, "it-seen-a.example") == (reports["it-seen-a.example"],) * 2


def test_the_earliest_claim_and_the_latest_report_of_any_source(client, raw_driver):
    """One indicator from ThreatFox (first-seen and last-seen claims) and from OTX (a later report):
    first seen is ThreatFox's claim, last seen OTX's report, later than ThreatFox's last claim."""
    now = _now()
    value = "it-seen-mixed.example"
    tf_first, tf_last, otx_report = now - timedelta(days=300), now - timedelta(days=60), now - timedelta(days=30)
    _merge(
        client,
        raw_driver,
        "threatfox",
        [_stored(_threatfox_item(value, tf_first, tf_last), 1, now - timedelta(days=1))],
    )
    _merge(
        client,
        raw_driver,
        "alienvault_otx",
        [_stored(_otx_item(value, otx_report - timedelta(days=5), otx_report), 2, now - timedelta(days=1))],
    )
    _indicates(raw_driver, value)

    campaign = _build(client, raw_driver)

    assert (campaign["first"], campaign["last"]) == (tf_first, otx_report)
    assert _alert_dates(client, value) == (tf_first, otx_report)


def test_a_report_after_the_first_import_leaves_first_seen_at_the_import(client, raw_driver):
    """An edge keeps a source's latest report only: an indicator EdgeGuard imported 100 days ago that
    OTX reported again 10 days ago is first seen at its import, not 10 days ago."""
    now = _now()
    value = "it-seen-again.example"
    imported, report = now - timedelta(days=100), now - timedelta(days=10)
    with raw_driver.session() as session:
        session.run(
            f"CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: $v, "
            "source: ['alienvault_otx'], zone: ['global'], edgeguard_managed: true, active: true, "
            "first_imported_at: datetime($imported), last_updated: datetime($imported)})",
            v=value,
            imported=imported.isoformat(),
        )
    _merge(
        client,
        raw_driver,
        "alienvault_otx",
        [_stored(_otx_item(value, report - timedelta(days=3), report), 3, now - timedelta(days=1))],
    )
    _indicates(raw_driver, value)

    campaign = _build(client, raw_driver)

    assert (campaign["first"], campaign["last"]) == (imported, report)
    assert _alert_dates(client, value) == (imported, report)


def test_a_stored_campaign_takes_an_earlier_first_seen_and_keeps_a_later_last_seen(client, raw_driver):
    """``c.first_seen`` only moves earlier and ``c.last_seen`` only later: a campaign an earlier build
    dated by the import time gets the reports' first seen, and keeps its later last seen (a graph
    built from empty does not have it)."""
    now = _now()
    stored = now - timedelta(days=1)
    with raw_driver.session() as session:
        session.run(
            f"CREATE (:Campaign:{LABEL} {{name: $name, actor_name: $actor, uuid: $uuid, edgeguard_managed: true, "
            "active: true, first_seen: datetime($stored), last_seen: datetime($stored)})",
            name=CAMPAIGN,
            actor=ACTOR,
            uuid=compute_node_uuid("Campaign", {"name": CAMPAIGN}),
            stored=stored.isoformat(),
        )
    reports = {"it-seen-c.example": now - timedelta(days=200), "it-seen-d.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), 10 + n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *reports)

    campaign = _build(client, raw_driver)

    assert campaign["first"] == reports["it-seen-c.example"], "an earlier first seen applies"
    assert campaign["last"] == stored, "the later stored last seen stays"


def test_an_indicator_no_source_dated_takes_its_own_times(client, raw_driver):
    """An indicator an alert created has no SOURCED_FROM edge: its first import and last write."""
    value = "it-seen-alert.example"
    try:
        assert client.create_indicator_from_alert(value, "domain", "global")
    finally:
        with raw_driver.session() as session:
            session.run(f"MATCH (n:Indicator) WHERE NOT n:{LABEL} SET n:{LABEL}")
    _indicates(raw_driver, value)

    campaign = _build(client, raw_driver)

    imported, written = _node_times(raw_driver)[value]
    assert (campaign["first"], campaign["last"]) == (imported, written)
    assert _alert_dates(client, value) == (imported, written)
