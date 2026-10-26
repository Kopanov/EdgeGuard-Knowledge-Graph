"""Campaign first / last seen on a real Neo4j (2026-10-25): the seen dates of its indicators.

An OTX indicator's ``SOURCED_FROM`` edge carries no first-seen / last-seen claim (OTX is not on the
reliable first-seen allowlist), but the source's latest report, ``r.last_reported_at``. The campaign
build read the claims alone, so a campaign whose indicators all came from OTX took EdgeGuard's import
time as its first and last seen. The build and the alert enrichment now read the seen dates of
``indicator_seen_dates``: per edge the claim, else the latest report; the first seen date never later
than the first import; the indicator's own times only when no edge dates it. The acceptance script's
check of the seen dates (``scripts/verify_fresh_baseline.py``, check 13e) runs on the campaigns built
here: they pass it, a sync after the build leaves it passing, and import-time dates fail it, as do a
missing stored date and one that does not compare (a String). With every member edge written after the
build no member is dated by an edge, and an import-time date is no longer caught (``edge_dated_members``
is then 0, which the script reports as informational).

The indicators are written as production writes them: an item shaped as the collector emits it, the
attribute ``MISPWriter`` builds from it with the fields MISP adds when it stores it (the key set of a
stored OTX attribute, 2026-10-25), ``parse_attribute`` and ``merge_indicators_batch``. The OTX test
checks the edge shape before relying on it. Dates are relative to the run, so the fixture never ages
out of the aging rule. Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT`` (the indicators and campaigns
the production code creates get the label right after), refuses any other node.
"""

from __future__ import annotations

import importlib.util
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

SCRIPT = TESTS.parent / "scripts" / "verify_fresh_baseline.py"

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

    try:
        enrichment_jobs.build_campaign_nodes(client)
    finally:
        with raw_driver.session() as session:
            session.run(f"MATCH (c:Campaign) WHERE NOT c:{LABEL} SET c:{LABEL}")
    with raw_driver.session() as session:
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


# The cutoff of check 13e: only the edges no write touched since the build count.
_CUTOFF = "WHERE r.updated_at <= m.updated_at AND r.updated_at <= c.last_updated "


def _acceptance(raw_driver, without_cutoff: bool = False) -> dict:
    """Check 13e of the acceptance script on this database (its statement as the script sends it);
    ``without_cutoff`` drops its cutoff, to show what the cutoff keeps out."""
    spec = importlib.util.spec_from_file_location("verify_fresh_baseline_seen_dates", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    statement = module.CAMPAIGN_SEEN_DATES_CHECK_QUERY
    assert _CUTOFF in statement
    if without_cutoff:
        statement = statement.replace(_CUTOFF, "")
    with raw_driver.session() as session:
        return dict(session.run(statement).single())


def _parse(text: str) -> datetime:
    """A time of the payload (``iso_str``: the driver value's native ``isoformat()``, microseconds at
    most), as an aware datetime."""
    parsed = datetime.fromisoformat(text)
    assert parsed.tzinfo is not None, f"the payload time {text!r} has no offset"
    return parsed


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


def test_the_acceptance_check_on_a_graph_without_campaigns(client, raw_driver):
    """Check 13e before any build: one row of zero counts (Neo4j's sum over no rows is 0, not null), which
    the script reports as informational."""
    assert _acceptance(raw_driver) == {
        "campaigns": 0,
        "members": 0,
        "edge_dated_members": 0,
        "campaigns_without_edge_dated_member": 0,
        "campaigns_without_edge_dated_member_names": [],
        "first_seen_after_members": 0,
        "last_seen_before_members": 0,
        "examples": [],
    }


def test_the_acceptance_check_passes_after_a_build_and_a_later_sync_leaves_it_passing(client, raw_driver):
    """Check 13e on a campaign the build dated passes. A source that reports a member after the build,
    with a first-seen claim earlier than the campaign's first seen, leaves it passing (the cutoff keeps
    the new edge out; without it the check would fail); the next build takes the claim."""
    now = _now()
    reports = {"it-seen-e.example": now - timedelta(days=200), "it-seen-f.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), 20 + n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *reports)
    _build(client, raw_driver)

    r = _acceptance(raw_driver)
    assert (r["campaigns"], r["members"], r["edge_dated_members"]) == (1, 2, 2)
    assert (r["campaigns_without_edge_dated_member"], r["campaigns_without_edge_dated_member_names"]) == (0, [])
    assert (r["first_seen_after_members"], r["last_seen_before_members"], r["examples"]) == (0, 0, [])

    claim = now - timedelta(days=400)
    tf_item = _threatfox_item("it-seen-e.example", claim, now - timedelta(days=50))
    _merge(client, raw_driver, "threatfox", [_stored(tf_item, 22, now - timedelta(hours=1))])
    r = _acceptance(raw_driver)
    assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (0, 0), "the later sync is left out"
    assert _acceptance(raw_driver, without_cutoff=True)["first_seen_after_members"] == 1, "what the cutoff keeps out"

    assert _build(client, raw_driver)["first"] == claim
    r = _acceptance(raw_driver)
    assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (0, 0)


def test_the_acceptance_check_fails_on_dates_a_build_without_the_reports_stored(client, raw_driver):
    """The import time as first seen (what the build stored for indicators without a claim before it read
    the reports) fails check 13e, and so does a last seen before a member's latest report."""
    now = _now()
    reports = {"it-seen-g.example": now - timedelta(days=200), "it-seen-h.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), 30 + n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *reports)
    built = _build(client, raw_driver)
    assert _acceptance(raw_driver)["first_seen_after_members"] == 0

    with raw_driver.session() as session:
        session.run(
            "MATCH (c:Campaign {name: $name}) MATCH (i:Indicator)-[:PART_OF_CAMPAIGN]->(c) "
            "WITH c, min(i.first_imported_at) AS imported SET c.first_seen = imported",
            name=CAMPAIGN,
        )
    r = _acceptance(raw_driver)
    assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (1, 0)
    assert [x["campaign"] for x in r["examples"]] == [CAMPAIGN]

    early = reports["it-seen-h.example"] - timedelta(days=1)
    with raw_driver.session() as session:
        session.run(
            "MATCH (c:Campaign {name: $name}) SET c.first_seen = datetime($first), c.last_seen = datetime($early)",
            name=CAMPAIGN,
            first=built["first"].isoformat(),
            early=early.isoformat(),
        )
    r = _acceptance(raw_driver)
    assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (0, 1)


def test_the_acceptance_check_fails_on_a_missing_or_incomparable_stored_date(client, raw_driver):
    """A campaign whose members the edges date (first and last) always has both dates after a build: a
    missing one, or one stored as a String (Neo4j compares a String and a DateTime as null), fails check
    13e instead of being left out or passing."""
    now = _now()
    reports = {"it-seen-i.example": now - timedelta(days=200), "it-seen-j.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), 40 + n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *reports)
    built = _build(client, raw_driver)
    assert _acceptance(raw_driver)["first_seen_after_members"] == 0

    for change, expected in (
        ("SET c.first_seen = null", (1, 0)),
        ("SET c.first_seen = toString(c.first_seen)", (1, 0)),
        ("SET c.last_seen = null", (0, 1)),
        ("SET c.last_seen = toString(c.last_seen)", (0, 1)),
    ):
        with raw_driver.session() as session:
            session.run(f"MATCH (c:Campaign {{name: $name}}) {change}", name=CAMPAIGN)
        r = _acceptance(raw_driver)
        assert (r["campaigns"], r["members"]) == (1, 2), change
        assert (r["first_seen_after_members"], r["last_seen_before_members"]) == expected, change
        # Restored by hand: a build keeps a String date (it compares as null with the new one).
        with raw_driver.session() as session:
            session.run(
                "MATCH (c:Campaign {name: $name}) SET c.first_seen = datetime($first), c.last_seen = datetime($last)",
                name=CAMPAIGN,
                first=built["first"].isoformat(),
                last=built["last"].isoformat(),
            )
        r = _acceptance(raw_driver)
        assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (0, 0), change


def test_with_every_member_edge_written_after_the_build_no_member_is_dated_by_an_edge(client, raw_driver):
    """Once a sync has written every member edge after the build, the cutoff leaves each member only its
    first import, which an import-time first seen also covers: the statement finds no defect in such a
    campaign, and ``edge_dated_members`` is 0, so the script reports the check as informational, not as
    passed."""
    now = _now()
    reports = {"it-seen-k.example": now - timedelta(days=200), "it-seen-l.example": now - timedelta(days=120)}
    attrs = [
        _stored(_otx_item(value, report - timedelta(days=10), report), 50 + n, now - timedelta(days=2))
        for n, (value, report) in enumerate(reports.items())
    ]
    _merge(client, raw_driver, "alienvault_otx", attrs)
    _indicates(raw_driver, *reports)
    _build(client, raw_driver)
    with raw_driver.session() as session:
        session.run(
            "MATCH (c:Campaign {name: $name}) MATCH (i:Indicator)-[:PART_OF_CAMPAIGN]->(c) "
            "WITH c, min(i.first_imported_at) AS imported SET c.first_seen = imported",
            name=CAMPAIGN,
        )
    r = _acceptance(raw_driver)
    assert (r["edge_dated_members"], r["first_seen_after_members"]) == (2, 1), "the edges date the members"

    _merge(client, raw_driver, "alienvault_otx", attrs)  # the next sync writes both member edges again
    r = _acceptance(raw_driver)
    assert (r["members"], r["edge_dated_members"]) == (2, 0)
    assert (r["first_seen_after_members"], r["last_seen_before_members"]) == (0, 0), "not caught without an edge"
    assert (r["campaigns_without_edge_dated_member"], r["campaigns_without_edge_dated_member_names"]) == (1, [CAMPAIGN])
