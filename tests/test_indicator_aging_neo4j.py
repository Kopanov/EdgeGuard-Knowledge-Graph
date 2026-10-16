"""One aging rule for indicators, on a real Neo4j with APOC (2026-10-16, ``src/indicator_aging.py``).

Mocked sessions cannot show what the Cypher does with ``SET n += <map>``, nulls, DateTime
arithmetic and the forward-only CASEs. This module runs the production writers and the job:

* a full sync after a retirement neither reactivates the node nor restores its confidence; a
  newer report reactivates it in the same write, and after that one write every aging property
  (``aging_basis`` included) follows the new report; the job corrects a stale ``aging_basis``; a
  source date later than the MISP time is capped;
* duplicates and reports in either order, and the in-memory, paged and incremental sync paths,
  leave identical aging properties;
* an ``edgeguard_enriched`` indicator ages like an ``edgeguard_managed`` one;
* a CVE gets no lifecycle property when EdgeGuard matches it and is never retired; CASM-shaped CVE /
  CVSS / Vulnerability and ISIM-shaped IP / Host / SoftwareVersion nodes are unchanged after the job
  and after a sync, and ``merge_cve`` / ``merge_vulnerabilities_batch`` matching a partner CVE or
  Vulnerability add no lifecycle property;
* the ``SOURCED_FROM`` edge keeps its source's report forward only in any order; ``source_confidence``
  keeps the highest incoming value in either order; the aged confidence stops at the 0.10 floor;
* a write, the sync's and the alert's, evaluates the rule at the database's current time and stores
  it (``aging_evaluated_at``); a write of a newer report after a job that changed nothing evaluates
  that report at the write's own, later time; the alert path reads a report committed while it
  waited for the node;
* a manual decommission is kept; an alert does not advance the report time;
* the job follows the tiers, writes nothing on a second run with the same ``as_of`` (a test's time)
  and leaves an Indicator with no time, and every other label, untouched;
* the time never moves backwards on a node (``aging_evaluated_at``): a job with an older ``as_of``
  after a newer one, and a write at the database's time before it, change nothing, a node retired at
  the newer time included; two jobs and a write in every order end in the state of the latest time
  and never move a node back on the way; a node evaluated before the property existed gets it once;
  a job that selected a node while a write held it waits for that write and evaluates what it wrote.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT`` (every node a writer MERGEs is created with the label
first), refuses any other node.
"""

from __future__ import annotations

import itertools
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import enrichment_jobs  # noqa: E402
import neo4j_client  # noqa: E402
from indicator_aging import AgingPolicy  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

UTC = timezone.utc
POLICY = AgingPolicy()
SOURCES = ("feodo_tracker", "threatfox", "alienvault_otx", "nvd", "resilmesh")
AGING_PROPS = (
    "last_reported_at",
    "last_reported_source",
    "last_reported_ref",
    "last_recorded_at",
    "source_confidence",
    "confidence_score",
    "aging_basis",
    "aging_tier",
    "aging_factor",
    "aging_since",
    "active",
    "retired_at",
    "retired_by",
)
LIFECYCLE_PROPS = AGING_PROPS + ("last_decayed_tier", "last_decayed_at")
EVENT = {"id": "41", "info": "EdgeGuard-feodo_tracker-2026-10-14", "date": "2026-10-14", "Tag": []}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(f"UNWIND $ids AS sid CREATE (:Source:{LABEL} {{source_id: sid}})", ids=list(SOURCES))
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def _db_now(raw_driver) -> datetime:
    """The database's current time, the clock every evaluation reads (2026-10-16), to the second."""
    with raw_driver.session() as session:
        now = session.run("RETURN datetime() AS now").single()["now"]
    return _native(now).replace(microsecond=0)


def _indicator(raw_driver, value: str, **props) -> None:
    """An Indicator node with the test label, EdgeGuard-created unless ``props`` say otherwise
    (``edgeguard_managed=None`` and ``first_imported_at=None`` make a partner-created node)."""
    base = {"uuid": f"u-{value}", "edgeguard_managed": True, "first_imported_at": _now() - timedelta(days=900)}
    base.update(props)
    base = {k: v for k, v in base.items() if v is not None}
    with raw_driver.session() as session:
        session.run(f"MATCH (n:Indicator:{LABEL} {{value: $v}}) DETACH DELETE n", v=value)
        session.run(f"CREATE (n:Indicator:{LABEL} {{indicator_type: 'ipv4', value: $v}}) SET n += $p", v=value, p=base)


def _native(value):
    return value.to_native() if hasattr(value, "to_native") else value


def _props(raw_driver, label: str, key: str, value) -> dict:
    with raw_driver.session() as session:
        rows = list(session.run(f"MATCH (n:{label}:{LABEL} {{{key}: $v}}) RETURN properties(n) AS p", v=value))
    assert len(rows) == 1, f"one {label} {value} expected, found {len(rows)}"
    return {k: _native(v) for k, v in rows[0]["p"].items()}


def _aging(raw_driver, value: str) -> dict:
    p = _props(raw_driver, "Indicator", "value", value)
    return {k: p.get(k) for k in AGING_PROPS}


def _edge(raw_driver, value: str, source: str) -> dict:
    with raw_driver.session() as session:
        row = session.run(
            f"MATCH (:Indicator:{LABEL} {{value: $v}})-[r:SOURCED_FROM]->(:Source {{source_id: $s}}) "
            "RETURN properties(r) AS p",
            v=value,
            s=source,
        ).single()
    return {k: _native(v) for k, v in row["p"].items()}


EDGE_REPORT_PROPS = ("last_reported_at", "last_reported_ref", "last_reported_source", "last_recorded_at")


def _edge_report(raw_driver, value: str, source: str) -> dict:
    """The report properties of the indicator's ``SOURCED_FROM`` edge to ``source``."""
    edge = _edge(raw_driver, value, source)
    return {k: edge.get(k) for k in EDGE_REPORT_PROPS}


def _attr(
    value: str,
    uuid: str,
    recorded: datetime,
    last_seen: datetime | None,
    *,
    tag: str = "Feodo-Tracker",
    confidence: str = "high",
) -> dict:
    """A MISP 2.5 attribute as ``events/view`` lists it (the shape of the hosted baseline's Feodo rows);
    ``confidence`` is the level of its ``confidence:`` tag (high 0.8, medium 0.5, low 0.3)."""
    return {
        "id": str(abs(hash(uuid)) % 100000),
        "event_id": "41",
        "type": "ip-dst",
        "category": "Network activity",
        "to_ids": False,
        "uuid": uuid,
        "timestamp": str(int(recorded.timestamp())),
        "comment": 'TF_META:{"malware_family": "Emotet"}',
        "first_seen": "2023-01-01T00:00:00.000000+00:00",
        "last_seen": last_seen.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00") if last_seen else None,
        "value": value,
        "Tag": [{"name": f"source:{tag}"}, {"name": "tlp:white"}, {"name": f"confidence:{confidence}"}],
    }


def _item(attr: dict) -> dict:
    from run_misp_to_neo4j import MISPToNeo4jSync

    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
    return item


def _write(client, *attrs, source: str = "feodo_tracker") -> None:
    assert client.merge_indicators_batch([_item(a) for a in attrs], source_id=source) == (len(attrs), 0)


# ================================================================ retirement, reactivation, the cap


def test_a_full_sync_after_retirement_neither_reactivates_nor_restores_confidence(client, raw_driver):
    now = _now()
    _indicator(raw_driver, "203.0.113.10")
    history = _attr("203.0.113.10", "a-1", now - timedelta(days=2), now - timedelta(days=800))
    _write(client, history)
    retired = _aging(raw_driver, "203.0.113.10")
    basis = now - timedelta(days=800)
    assert retired["last_reported_at"] == basis and retired["aging_basis"] == "source_date"
    assert (retired["active"], retired["retired_by"]) == (False, "decay")
    assert retired["retired_at"] == retired["aging_since"] == basis + timedelta(days=730)
    assert (retired["source_confidence"], retired["confidence_score"]) == (0.8, 0.44)
    assert (retired["aging_tier"], retired["aging_factor"]) == (3, 0.55)
    enrichment_jobs.decay_ioc_confidence(client, as_of=_now())
    _write(client, history)  # the full sync reads the same attribute again
    _write(client, history)
    assert _aging(raw_driver, "203.0.113.10") == retired


def test_a_newer_report_reactivates_in_the_same_write(client, raw_driver):
    now = _now()
    _indicator(raw_driver, "203.0.113.11")
    _write(client, _attr("203.0.113.11", "a-2", now - timedelta(days=2), now - timedelta(days=800)))
    assert _aging(raw_driver, "203.0.113.11")["active"] is False
    _write(client, _attr("203.0.113.11", "a-3", now - timedelta(days=1), now - timedelta(days=10)))
    got = _aging(raw_driver, "203.0.113.11")
    assert (got["active"], got["retired_at"], got["retired_by"]) == (True, None, None)
    assert (got["last_reported_at"], got["last_reported_ref"], got["last_reported_source"]) == (
        now - timedelta(days=10),
        "a-3",
        "feodo_tracker",
    )
    assert (got["aging_tier"], got["confidence_score"], got["aging_since"]) == (0, 0.8, now - timedelta(days=10))
    edge = _edge(raw_driver, "203.0.113.11", "feodo_tracker")
    assert (edge["last_reported_at"], edge["last_reported_ref"]) == (now - timedelta(days=10), "a-3")
    assert edge["last_recorded_at"] == now - timedelta(days=1)


def test_one_newer_report_write_sets_the_aging_from_that_report(client, raw_driver):
    """2026-10-16: the rule runs in a SET clause of its own after the clause that records the report,
    so after one write of a newer report every aging property follows that report: here a retired
    node aged from a source date is reported again with only a MISP time (another kind of basis)."""
    now = _now()
    _indicator(raw_driver, "203.0.113.17")
    _write(client, _attr("203.0.113.17", "a-5", now - timedelta(days=3), now - timedelta(days=800)))
    old = _aging(raw_driver, "203.0.113.17")
    assert (old["aging_basis"], old["aging_tier"], old["active"]) == ("source_date", 3, False)
    _write(client, _attr("203.0.113.17", "a-6", now - timedelta(days=1), None))
    got = _aging(raw_driver, "203.0.113.17")
    assert got["last_reported_at"] == now - timedelta(days=1)
    assert (got["aging_basis"], got["aging_tier"], got["aging_since"], got["active"]) == (
        "misp_recorded",
        0,
        now - timedelta(days=1),
        True,
    )
    assert (got["retired_at"], got["retired_by"], got["confidence_score"]) == (None, None, 0.8)
    assert _props(raw_driver, "Indicator", "value", "203.0.113.17")["last_reported_basis"] == "misp_recorded"
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=_now())["changed"] == 0, "the job agrees"


def test_the_job_corrects_a_stale_aging_basis(client, raw_driver):
    """2026-10-16: the job writes a node when any aging property differs from what the rule gives,
    ``aging_basis`` among them; the rule derives it from the recorded report (``last_reported_basis``),
    so an ``aging_basis`` that disagrees with the report is put right."""
    now = _now()
    _indicator(
        raw_driver,
        "203.0.113.18",
        last_reported_at=now - timedelta(days=10),
        last_reported_basis="source_date",
        source_confidence=0.8,
        confidence_score=0.8,
        aging_basis="first_imported",
        aging_tier=0,
        aging_factor=1.0,
        aging_since=now - timedelta(days=10),
        active=True,
    )
    result = enrichment_jobs.decay_ioc_confidence(client, as_of=now)
    assert result["changed"] == 1
    got = _aging(raw_driver, "203.0.113.18")
    assert (got["aging_basis"], got["aging_tier"], got["active"]) == ("source_date", 0, True)
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=now)["changed"] == 0


def test_a_source_date_later_than_the_misp_time_is_capped(client, raw_driver):
    now = _now()
    _indicator(raw_driver, "203.0.113.12")
    capped = _attr("203.0.113.12", "a-4", now - timedelta(days=5), now - timedelta(days=1), tag="ThreatFox")
    _write(client, capped, source="threatfox")
    got = _aging(raw_driver, "203.0.113.12")
    assert got["last_reported_at"] == got["last_recorded_at"] == now - timedelta(days=5)
    assert got["aging_basis"] == "misp_recorded" and got["last_reported_source"] == "threatfox"


# ================================================================ order, duplicates, sync paths


def test_reports_and_duplicates_in_either_order_give_the_same_node(client, raw_driver):
    now = _now()
    older = _attr("203.0.113.13", "b-1", now - timedelta(days=1), now - timedelta(days=200))
    newer = _attr("203.0.113.13", "b-2", now - timedelta(days=3), now - timedelta(days=100))
    tie_a = _attr("203.0.113.13", "b-9", now - timedelta(days=4), now - timedelta(days=100))
    results = []
    edges = []
    for batches in (
        [[older], [newer], [tie_a]],
        [[tie_a], [newer], [older]],
        [[older, tie_a, newer]],
        [[newer, older]],
        [[newer], [older]],  # a newer report first, then an older copy of the same source
    ):
        _indicator(raw_driver, "203.0.113.13")
        for batch in batches:
            _write(client, *batch)
        results.append(_aging(raw_driver, "203.0.113.13"))
        edges.append(_edge_report(raw_driver, "203.0.113.13", "feodo_tracker"))
    for got in results:
        assert got == results[0]
    assert results[0]["last_reported_ref"] == "b-2", "an equal time goes to the smaller uuid"
    assert results[0]["last_recorded_at"] == now - timedelta(days=1)
    assert (results[0]["aging_tier"], results[0]["confidence_score"]) == (1, 0.68)
    # 2026-10-16: the SOURCED_FROM edge keeps its source's report forward only, in any order, and
    # agrees with the node (one source here).
    for got in edges:
        assert got == edges[0]
    assert edges[0] == {k: results[0][k] for k in EDGE_REPORT_PROPS}


def _sync(client, attributes, path: str) -> None:
    """One sync of ``attributes`` on ``path``."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    sync = MISPToNeo4jSync(neo4j_client=client)
    sync._create_relationships = lambda rels, source_id: 0
    sync._write_cross_item_relationships = lambda rels: 0
    getattr(sync, path)("41", EVENT, attributes)


def test_full_incremental_and_paged_syncs_give_the_same_aging(client, raw_driver, monkeypatch):
    now = _now()
    values = ("203.0.113.20", "203.0.113.21", "203.0.113.22")
    old = [
        _attr(values[0], "c-1", now - timedelta(days=40), now - timedelta(days=300)),
        _attr(values[1], "c-2", now - timedelta(days=40), None),
        _attr(values[2], "c-3", now - timedelta(days=40), now - timedelta(days=900)),
    ]
    new = [
        _attr(values[0], "c-4", now - timedelta(days=1), now - timedelta(days=20)),
        _attr(values[2], "c-5", now - timedelta(days=1), now - timedelta(days=950)),
    ]

    def run(plan) -> dict:
        for v in values:
            _indicator(raw_driver, v)
        for attrs, path in plan:
            _sync(client, attrs, path)
        # The node's aging and (2026-10-16) the report its SOURCED_FROM edge keeps.
        return {v: {**_aging(raw_driver, v), "edge": _edge_report(raw_driver, v, "feodo_tracker")} for v in values}

    from run_misp_to_neo4j import MISPToNeo4jSync

    monkeypatch.setattr(MISPToNeo4jSync, "_ATTR_PAGE_SIZE", 2)
    full = run([(old + new, "_process_event_attributes")])
    assert run([(old, "_process_event_attributes"), (new, "_process_event_attributes")]) == full, "incremental"
    assert run([(list(reversed(old + new)), "_process_large_event_paged")]) == full, "paged, reversed"
    assert run([(new, "_process_large_event_paged"), (old, "_process_event_attributes")]) == full, "late arrival"
    assert full[values[2]]["active"] is False and full[values[2]]["last_reported_ref"] == "c-3"
    assert full[values[1]]["aging_basis"] == "misp_recorded"
    for v in values:
        assert full[v]["edge"] == {k: full[v][k] for k in EDGE_REPORT_PROPS}, v


# ================================================================ the confidence


def test_source_confidence_keeps_the_highest_incoming_value_in_either_order(client, raw_driver):
    """``source_confidence`` is the highest confidence a source gave (max-wins over incoming values
    only); the aged ``confidence_score`` follows it, whichever report comes first."""
    now = _now()
    high = _attr("203.0.113.14", "h-1", now - timedelta(days=2), now - timedelta(days=100))
    medium = _attr(
        "203.0.113.14", "h-2", now - timedelta(days=1), now - timedelta(days=100), tag="ThreatFox", confidence="medium"
    )
    results = []
    for order in ((high, "feodo_tracker"), (medium, "threatfox")), ((medium, "threatfox"), (high, "feodo_tracker")):
        _indicator(raw_driver, "203.0.113.14")
        for attr, source in order:
            _write(client, attr, source=source)
        results.append(_aging(raw_driver, "203.0.113.14"))
    assert results[0] == results[1]
    assert results[0]["source_confidence"] == 0.8, "a later, lower confidence does not lower it"
    assert results[0]["confidence_score"] == POLICY.confidence(0.8, 100) == 0.68


def test_the_aged_confidence_never_falls_below_the_floor(client, raw_driver):
    """``max(0.10, round(source_confidence × factor, 2))``: 0.15 × 0.55 = 0.0825 gives 0.10, not 0.08."""
    _indicator(
        raw_driver,
        "203.0.113.15",
        last_reported_at=AS_OF - timedelta(days=400),
        aging_basis="source_date",
        source_confidence=0.15,
        confidence_score=0.15,
        active=True,
    )
    enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)
    got = _aging(raw_driver, "203.0.113.15")
    assert (got["aging_tier"], got["aging_factor"]) == (3, 0.55)
    assert got["confidence_score"] == POLICY.confidence(0.15, 400) == 0.10


def test_a_sync_write_evaluates_at_the_database_time(client, raw_driver):
    """2026-10-16: a sync's write evaluates the rule at the database's current time and stores it as
    ``aging_evaluated_at``; no run passes a time. A node 735 days old at that time is written retired,
    and the job right after it, at the database's time as well, changes nothing."""
    before = _db_now(raw_driver)
    _indicator(raw_driver, "203.0.113.19")
    report = _attr("203.0.113.19", "r-2", before - timedelta(days=2), before - timedelta(days=735))
    _sync(client, [report], "_process_event_attributes")
    after = _db_now(raw_driver) + timedelta(seconds=1)
    got = _aging(raw_driver, "203.0.113.19")
    assert (got["active"], got["aging_tier"], got["retired_by"]) == (False, 3, "decay")
    assert before <= _props(raw_driver, "Indicator", "value", "203.0.113.19")["aging_evaluated_at"] <= after
    assert enrichment_jobs.decay_ioc_confidence(client)["changed"] == 0, "the job at the database's time agrees"


def test_a_newer_report_after_a_job_that_changed_nothing_is_evaluated_at_the_write_time(client, raw_driver):
    """2026-10-16: the job stores ``aging_evaluated_at`` only with a change. A node aged at an earlier
    time, its state still right now, is left as it is by the job (its stored time stays the earlier
    one); a write of a newer report then evaluates that report at the time of the write, not at the
    stored time: 92 days old now (the first tier), it would be 87 days old at the stored time."""
    now = _db_now(raw_driver)
    stored_at = now - timedelta(days=5)
    basis = now - timedelta(days=100)
    _indicator(
        raw_driver,
        "203.0.113.95",
        last_reported_at=basis,
        last_reported_basis="source_date",
        last_reported_ref="o-1",
        last_reported_source="feodo_tracker",
        last_recorded_at=basis + timedelta(days=1),
        source_confidence=0.8,
        confidence_score=0.68,
        aging_basis="source_date",
        aging_tier=1,
        aging_factor=0.85,
        aging_since=basis + timedelta(days=90),
        active=True,
        aging_evaluated_at=stored_at,
    )
    assert enrichment_jobs.decay_ioc_confidence(client)["changed"] == 0, "the state at the stored time holds now"
    assert _evaluated_at(raw_driver, "203.0.113.95") == stored_at, "a job that changes nothing stores no time"
    newer = now - timedelta(days=92)
    _write(client, _attr("203.0.113.95", "o-2", now - timedelta(days=1), newer))
    got = _aging(raw_driver, "203.0.113.95")
    assert got["last_reported_at"] == newer and got["last_reported_ref"] == "o-2"
    assert (got["aging_tier"], got["aging_factor"], got["confidence_score"]) == (1, 0.85, 0.68)
    assert got["aging_since"] == newer + timedelta(days=90)
    assert _evaluated_at(raw_driver, "203.0.113.95") >= now, "the time of the write"
    assert POLICY.tier(87) == 0, "at the stored time the newer report would still be in tier 0"


# ================================================================ whoever created the node


def test_an_enriched_indicator_ages_like_a_managed_one(client, raw_driver):
    now = _now()
    _indicator(raw_driver, "203.0.113.30")
    _indicator(raw_driver, "203.0.113.31", edgeguard_managed=None, first_imported_at=None)  # a partner created it
    for value, uuid in (("203.0.113.30", "d-1"), ("203.0.113.31", "d-1")):
        _write(client, _attr(value, uuid, now - timedelta(days=2), now - timedelta(days=400)))
    managed, enriched = _aging(raw_driver, "203.0.113.30"), _aging(raw_driver, "203.0.113.31")
    assert managed == enriched and managed["aging_tier"] == 3 and managed["active"] is True
    assert _props(raw_driver, "Indicator", "value", "203.0.113.31")["edgeguard_enriched"] is True
    enrichment_jobs.decay_ioc_confidence(client, as_of=now + timedelta(days=400))
    managed, enriched = _aging(raw_driver, "203.0.113.30"), _aging(raw_driver, "203.0.113.31")
    assert managed == enriched and (managed["active"], managed["retired_by"]) == (False, "decay")


# ================================================================ labels that do not age

CASM_CVE = {
    "cve_id": "CVE-2024-3400",
    "description": "A command injection in GlobalProtect.",
    "published": "2024-04-12T08:15:06.230",
    "last_modified": "2024-04-23T19:02:21.637",
    "cwe": ["CWE-77"],
    "cpe_type": ["o"],
    "ref_tags": ["Vendor Advisory"],
    "result_impacts": ["Execution"],
}

PARTNER_GRAPH = f"""
CREATE (cve:CVE:{LABEL} {{cve_id: 'CVE-2023-4966', description: 'Citrix Bleed', published: '2023-10-10T14:15:10.017',
        last_modified: '2024-02-01T00:15:47.743', cwe: ['CWE-119'], cpe_type: ['a'], ref_tags: [], result_impacts: []}})
CREATE (cvss:CVSSv31:{LABEL} {{base_score: 9.4, base_severity: 'CRITICAL',
        vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L'}})
CREATE (cve)-[:HAS_CVSS_v31]->(cvss)
CREATE (v:Vulnerability:{LABEL} {{description: 'Assumed vulnerability with ID CVE-2023-4966', status: ['estimated']}})
CREATE (v)-[:REFERS_TO]->(cve)
CREATE (:Vulnerability:{LABEL} {{cve_id: 'CVE-2023-4966', description: 'Citrix Bleed (partner twin)', status: ['confirmed']}})
CREATE (sw:SoftwareVersion:{LABEL} {{version: 'cpe:2.3:a:citrix:netscaler_gateway:13.1:*:*:*:*:*:*:*',
        cve_timestamp: '2026-10-01T10:00:00'}})
CREATE (v)-[:IN {{start: '2026-10-01T10:00:00', end: '2026-10-15T10:00:00'}}]->(sw)
CREATE (h:Host:{LABEL} {{hostname: 'gw01'}})
CREATE (sw)-[:ON {{start: '2026-09-01T10:00:00', end: '2026-10-15T10:00:00'}}]->(h)
CREATE (ip:IP:{LABEL} {{address: '203.0.113.40', version: 4, tag: ['dmz'], status: 'rediscovered'}})
CREATE (ip)-[:HAS_ASSIGNED {{start: '2026-08-01T00:00:00', end: '2026-08-15T00:00:00'}}]->(:Node:{LABEL} {{id: 'n1'}})
"""


def _partner_snapshot(raw_driver) -> list:
    with raw_driver.session() as session:
        nodes = sorted(
            (sorted(r["labels"]), sorted((k, str(v)) for k, v in r["p"].items()))
            for r in session.run(
                f"MATCH (n:{LABEL}) WHERE n:CVE OR n:CVSSv31 OR n:Vulnerability OR n:SoftwareVersion OR n:Host "
                "OR n:IP OR n:Node RETURN labels(n) AS labels, properties(n) AS p"
            )
        )
        rels = sorted(
            (r["t"], sorted((k, str(v)) for k, v in r["p"].items()))
            for r in session.run(
                f"MATCH (:{LABEL})-[r]->(:{LABEL}) WHERE type(r) <> 'SOURCED_FROM' RETURN type(r) AS t, properties(r) AS p"
            )
        )
    return nodes + rels


def test_partner_nodes_are_unchanged_after_the_job_and_a_sync(client, raw_driver):
    with raw_driver.session() as session:
        session.run(PARTNER_GRAPH)
    before = _partner_snapshot(raw_driver)
    now = _now()
    _indicator(raw_driver, "203.0.113.40")  # the same address as the ISIM IP node: another label
    _write(client, _attr("203.0.113.40", "e-1", now - timedelta(days=1), now - timedelta(days=800)))
    enrichment_jobs.decay_ioc_confidence(client, as_of=now)
    enrichment_jobs.decay_ioc_confidence(client, as_of=now + timedelta(days=1000))
    assert _partner_snapshot(raw_driver) == before
    assert _aging(raw_driver, "203.0.113.40")["retired_by"] == "decay", "the indicator itself aged"


def test_a_sync_that_matches_partner_cve_and_vulnerability_nodes_adds_no_lifecycle(client, raw_driver):
    """The writers that do MATCH partner nodes: ``merge_cve`` on a CASM-created CVE and
    ``merge_vulnerabilities_batch`` on a ``cve_id``-keyed Vulnerability EdgeGuard did not create. They
    add EdgeGuard's own properties (sources, ``edgeguard_enriched``), but no ``active``, ``retired_*``
    or aging property, and they change none of the partner's properties; neither does the job."""
    with raw_driver.session() as session:
        session.run(PARTNER_GRAPH)
    cve_before = _props(raw_driver, "CVE", "cve_id", "CVE-2023-4966")
    twin_before = _props(raw_driver, "Vulnerability", "cve_id", "CVE-2023-4966")
    assert client.merge_cve({"cve_id": "CVE-2023-4966", "zone": ["global"]}, source_id="nvd")
    assert client.merge_vulnerabilities_batch(
        [{"cve_id": "CVE-2023-4966", "zone": ["global"], "tag": "nvd"}], source_id="nvd"
    ) == (1, 0)
    enrichment_jobs.decay_ioc_confidence(client, as_of=_now() + timedelta(days=2000))
    for label, before in (("CVE", cve_before), ("Vulnerability", twin_before)):
        after = _props(raw_driver, label, "cve_id", "CVE-2023-4966")
        assert after["edgeguard_enriched"] is True, label
        assert {k: after.get(k) for k in before} == before, f"the partner's {label} properties are unchanged"
        assert not [p for p in LIFECYCLE_PROPS if p in after and p != "confidence_score"], (label, after)


def test_a_cve_gets_no_lifecycle_on_match_and_is_never_retired(client, raw_driver):
    with raw_driver.session() as session:
        session.run(f"CREATE (c:CVE:{LABEL}) SET c += $p", p=CASM_CVE)  # CASM created it
        session.run(
            f"CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2019-0708', edgeguard_managed: true, active: true, "
            "confidence_score: 0.9, first_imported_at: datetime('2024-01-01T00:00:00Z'), "
            "last_updated: datetime('2024-01-01T00:00:00Z')})"
        )
        session.run(
            f"CREATE (v:Vulnerability:{LABEL} {{cve_id: 'CVE-2019-0708', active: true, confidence_score: 0.9, "
            "last_updated: datetime('2023-01-01T00:00:00Z'), first_imported_at: datetime('2023-01-01T00:00:00Z')})"
        )
    assert client.merge_cve({"cve_id": "CVE-2024-3400", "zone": ["global"]}, source_id="nvd")
    casm = _props(raw_driver, "CVE", "cve_id", "CVE-2024-3400")
    assert casm["edgeguard_enriched"] is True
    assert not [p for p in LIFECYCLE_PROPS if p in casm and p != "confidence_score"], casm
    stored = _props(raw_driver, "CVE", "cve_id", "CVE-2019-0708")
    vuln = _props(raw_driver, "Vulnerability", "cve_id", "CVE-2019-0708")
    enrichment_jobs.decay_ioc_confidence(client, as_of=_now() + timedelta(days=2000))
    assert _props(raw_driver, "CVE", "cve_id", "CVE-2019-0708") == stored
    assert _props(raw_driver, "Vulnerability", "cve_id", "CVE-2019-0708") == vuln, "no Vulnerability tiers"
    assert client.merge_cve({"cve_id": "CVE-2019-0708", "zone": ["global"]}, source_id="nvd")
    again = _props(raw_driver, "CVE", "cve_id", "CVE-2019-0708")
    assert again["active"] is True and "retired_at" not in again and "aging_tier" not in again


# ================================================================ decommission, alerts


@pytest.mark.parametrize("retired_by", ["analyst", None], ids=["named", "legacy"])
def test_a_manual_decommission_is_kept(client, raw_driver, retired_by):
    now = _now()
    decommissioned = datetime(2026, 9, 1, tzinfo=UTC)
    _indicator(raw_driver, "203.0.113.50", active=False, retired_at=decommissioned, retired_by=retired_by)
    _write(client, _attr("203.0.113.50", "f-1", now - timedelta(days=1), now - timedelta(days=5)))
    enrichment_jobs.decay_ioc_confidence(client, as_of=now + timedelta(days=1000))
    got = _aging(raw_driver, "203.0.113.50")
    assert (got["active"], got["retired_at"], got["retired_by"]) == (False, decommissioned, retired_by)
    assert got["last_reported_ref"] == "f-1", "the report is still recorded"


def test_an_alert_does_not_advance_the_report_time(client, raw_driver):
    now = _now()
    _indicator(raw_driver, "203.0.113.60")
    _write(client, _attr("203.0.113.60", "g-1", now - timedelta(days=2), now - timedelta(days=800)))
    retired = _aging(raw_driver, "203.0.113.60")
    assert client.create_indicator_from_alert("203.0.113.60", "ipv4", "global", alert_data={"alert_id": "a1"})
    got = _aging(raw_driver, "203.0.113.60")
    assert got == retired, "an alert is not a report (to be designed with the ResilMesh alert integration)"


# ================================================================ the job

AS_OF = datetime(2026, 10, 16, 3, 0, tzinfo=UTC)


def test_the_job_follows_the_tiers_and_is_idempotent(client, raw_driver):
    ages = {"203.0.113.70": 10, "203.0.113.71": 100, "203.0.113.72": 200, "203.0.113.73": 400, "203.0.113.74": 800}
    for value, days in ages.items():
        _indicator(
            raw_driver,
            value,
            last_reported_at=AS_OF - timedelta(days=days),
            aging_basis="source_date",
            source_confidence=0.8,
            confidence_score=0.8,
            active=True,
            first_imported_at=AS_OF - timedelta(days=days - 1),
        )
    _indicator(raw_driver, "203.0.113.75", first_imported_at=AS_OF - timedelta(days=120), confidence_score=0.5)
    _indicator(raw_driver, "203.0.113.76", first_imported_at=AS_OF - timedelta(days=200), confidence_score=0.6)
    _indicator(raw_driver, "203.0.113.77", edgeguard_managed=None, first_imported_at=None, confidence_score=0.5)
    result = enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)
    assert result["changed"] == 7 and result["no_time"] == 1 and result["retired"] == 1
    for value, days in ages.items():
        got = _aging(raw_driver, value)
        tier = POLICY.tier(days)
        basis = AS_OF - timedelta(days=days)
        assert got["aging_tier"] == tier and got["aging_factor"] == POLICY.factor(tier), value
        assert got["confidence_score"] == POLICY.confidence(0.8, days), value
        assert got["active"] is (days < 730), value
        if days >= 730:
            assert got["retired_at"] == got["aging_since"] == basis + timedelta(days=730)
        else:
            assert got["aging_since"] == basis + timedelta(days=POLICY.tier_start(tier)) and got["retired_at"] is None
    first = _aging(raw_driver, "203.0.113.75")
    assert (first["aging_basis"], first["aging_tier"]) == ("first_imported", 1)
    assert first["confidence_score"] == 0.5, "no source_confidence yet: the stored value is kept"
    assert _aging(raw_driver, "203.0.113.76")["aging_tier"] == 2
    untouched = _props(raw_driver, "Indicator", "value", "203.0.113.77")
    assert not [p for p in AGING_PROPS if p in untouched and p != "confidence_score"], untouched

    snapshot = {v: _aging(raw_driver, v) for v in list(ages) + ["203.0.113.75", "203.0.113.76"]}
    again = enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)
    assert again["changed"] == 0
    assert {v: _aging(raw_driver, v) for v in snapshot} == snapshot, "a second run with the same as_of writes nothing"
    later = enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF + timedelta(days=100))
    assert later["changed"] > 0
    assert _aging(raw_driver, "203.0.113.70")["aging_tier"] == 1, "aged into the first tier"
    for value, days in ages.items():
        got = _aging(raw_driver, value)
        assert got["confidence_score"] == POLICY.confidence(0.8, days + 100), "recomputed, not multiplied step by step"
    # 2026-10-16: the earlier time again changes nothing: each node keeps the later time's state.
    aged_later = {v: _aging(raw_driver, v) for v in snapshot}
    back = enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)
    assert back["changed"] == 0
    assert {v: _aging(raw_driver, v) for v in snapshot} == aged_later, "an older as_of never moves a node back"


# ================================================================ the time never moves backwards


def _evaluated_at(raw_driver, value: str):
    return _props(raw_driver, "Indicator", "value", value).get("aging_evaluated_at")


def _reported(raw_driver, value: str, basis: datetime) -> None:
    """An Indicator whose latest report (``o-1``, Feodo Tracker, source date ``basis``) is already
    recorded, so every write of that report below leaves the basis as it is."""
    _indicator(
        raw_driver,
        value,
        last_reported_at=basis,
        last_reported_basis="source_date",
        last_reported_ref="o-1",
        last_reported_source="feodo_tracker",
        last_recorded_at=basis + timedelta(days=1),
        source_confidence=0.8,
        confidence_score=0.8,
        active=True,
    )


def _rewrite(client, value: str, basis: datetime) -> None:
    """A sync writes the report ``o-1`` again, at the database's current time."""
    _write(client, _attr(value, "o-1", basis + timedelta(days=1), basis))


def test_an_older_evaluation_after_a_newer_one_changes_nothing(client, raw_driver):
    """2026-10-16: a job at a later time (a test's ``as_of``) ages a node into the third tier and
    retires another; then a job with an older ``as_of`` and a sync write at the database's current
    time, both before that later time, evaluate at the time stored on each node: nothing comes back
    to life, no tier falls, ``aging_since`` and ``aging_evaluated_at`` stay."""
    now = _db_now(raw_driver)
    newer, older = now + timedelta(days=200), now - timedelta(days=5)
    bases = {"203.0.113.90": now - timedelta(days=600), "203.0.113.91": now - timedelta(days=300)}
    for value, basis in bases.items():
        _reported(raw_driver, value, basis)
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=newer)["changed"] == 2
    retired, tier3 = _aging(raw_driver, "203.0.113.90"), _aging(raw_driver, "203.0.113.91")
    assert (retired["active"], retired["retired_by"], retired["aging_tier"]) == (False, "decay", 3)
    assert retired["aging_since"] == retired["retired_at"] == bases["203.0.113.90"] + timedelta(days=730)
    assert (tier3["active"], tier3["aging_tier"], tier3["confidence_score"]) == (True, 3, 0.44)
    assert tier3["aging_since"] == bases["203.0.113.91"] + timedelta(days=365)
    assert {_evaluated_at(raw_driver, v) for v in bases} == {newer}

    assert enrichment_jobs.decay_ioc_confidence(client, as_of=older)["changed"] == 0, "a job with an older time"
    for value, basis in bases.items():
        _rewrite(client, value, basis)  # a sync writes the same report again, at the database's time
    assert _aging(raw_driver, "203.0.113.90") == retired, "still retired, retired_at and aging_since kept"
    assert _aging(raw_driver, "203.0.113.91") == tier3, "still the third tier"
    assert {_evaluated_at(raw_driver, v) for v in bases} == {newer}, "the stored time never decreases"
    # At the database's time itself the rule gives the earlier states: the stored time is what holds them.
    assert POLICY.tier(300) == 2 and 600 < POLICY.retire_days


@pytest.mark.parametrize("latest", ["job", "write"])
@pytest.mark.parametrize(
    "order",
    list(itertools.permutations(range(3))),
    ids=lambda o: "-".join(str(i) for i in o),
)
def test_two_jobs_and_a_write_in_any_order_end_in_the_latest_state(client, raw_driver, order, latest):
    """2026-10-16: two jobs (a test's ``as_of``) and a sync write (the database's current time), in
    every order, end in the state of the latest of their times with that time stored, and no step moves
    the node back (tier, ``aging_since`` and the time never decrease; nothing reactivates).

    ``latest="job"``: a job at 100 days (tier 1), the write at 300 days (tier 2), a job at 800 days
    (retired). ``latest="write"``: jobs at 350 days (tier 2) and 550 days (tier 3), the write at 750
    days (retired), the write's own time stored."""
    now = _db_now(raw_driver)
    if latest == "job":
        basis = now - timedelta(days=300)
        steps = [("job", basis + timedelta(days=100)), ("write", None), ("job", basis + timedelta(days=800))]
    else:
        basis = now - timedelta(days=750)
        steps = [("job", basis + timedelta(days=350)), ("job", basis + timedelta(days=550)), ("write", None)]
    value = "203.0.113.92"
    _reported(raw_driver, value, basis)
    seen = []
    for index in order:
        kind, when = steps[index]
        if kind == "job":
            enrichment_jobs.decay_ioc_confidence(client, as_of=when)
        else:
            _rewrite(client, value, basis)
        seen.append({**_aging(raw_driver, value), "evaluated_at": _evaluated_at(raw_driver, value)})
    for before, after in itertools.pairwise(seen):
        assert after["aging_tier"] >= before["aging_tier"]
        assert after["aging_since"] >= before["aging_since"]
        assert after["evaluated_at"] >= before["evaluated_at"]
        assert before["active"] or not after["active"], "a retired node never reactivates without a newer report"
    final = seen[-1]
    if latest == "job":
        assert final["evaluated_at"] == steps[2][1]
    else:
        assert now <= final["evaluated_at"] <= _db_now(raw_driver) + timedelta(seconds=1), "the write's own time"
    assert (final["active"], final["retired_by"], final["aging_tier"], final["confidence_score"]) == (
        False,
        "decay",
        3,
        0.44,
    )
    assert final["aging_since"] == final["retired_at"] == basis + timedelta(days=730)


def test_a_node_without_the_time_gets_it_once(client, raw_driver):
    """2026-10-16: a node aged before ``aging_evaluated_at`` existed, its values right for the job's
    time, is written once by the job to store the time; the next run with the same time writes
    nothing, and a later time alone is no change."""
    _indicator(
        raw_driver,
        "203.0.113.93",
        last_reported_at=AS_OF - timedelta(days=10),
        last_reported_basis="source_date",
        source_confidence=0.8,
        confidence_score=0.8,
        aging_basis="source_date",
        aging_tier=0,
        aging_factor=1.0,
        aging_since=AS_OF - timedelta(days=10),
        active=True,
    )
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)["changed"] == 1
    assert _evaluated_at(raw_driver, "203.0.113.93") == AS_OF
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF)["changed"] == 0
    assert enrichment_jobs.decay_ioc_confidence(client, as_of=AS_OF + timedelta(days=5))["changed"] == 0
    assert _evaluated_at(raw_driver, "203.0.113.93") == AS_OF, "written only with a change of the aging"


def test_the_job_waits_for_a_write_in_progress_and_evaluates_what_it_wrote(client, raw_driver):
    """2026-10-16: a job with an older time (a test's ``as_of``, as a job whose clock is behind)
    selects a node as changing (third tier at its time) while a write of the node, retiring it at the
    database's current time, is still open. The job locks the node before it reads it
    (``apoc.lock.nodes``), so it waits for that write, then reads the retired node and its later time
    and writes nothing. Reading before the lock, it would have written the third tier it computed
    before the write committed: the node active again, at the older time."""
    from indicator_aging import aging_set_clause

    now = _db_now(raw_driver)
    value = "203.0.113.94"
    basis = now - timedelta(days=800)
    _reported(raw_driver, value, basis)
    enrichment_jobs.decay_ioc_confidence(client, as_of=now - timedelta(days=500))
    assert _aging(raw_driver, value)["aging_tier"] == 2
    older = now - timedelta(days=400)

    outcome: dict = {}

    def older_job() -> None:
        try:
            outcome["result"] = enrichment_jobs.decay_ioc_confidence(client, as_of=older)
        except Exception as exc:  # pragma: no cover - reported below
            outcome["error"] = exc

    job = threading.Thread(target=older_job, daemon=True)
    session = raw_driver.session()
    tx = session.begin_transaction()
    try:
        # A write, as the writers make it: a property set (which takes the node's write lock until
        # the commit), then the rule in a clause of its own, at the database's current time.
        tx.run(
            f"MATCH (n:Indicator:{LABEL} {{value: $v}}) SET n.last_updated = datetime() " + aging_set_clause("n"),
            v=value,
        ).consume()
        job.start()
        time.sleep(3)
        waited = job.is_alive()
        tx.commit()
    finally:
        if not tx.closed():
            tx.rollback()
        session.close()
        if job.ident is not None:
            job.join(timeout=120)
    assert waited, "the job waits for the open write of the node"
    assert not job.is_alive() and "error" not in outcome, outcome
    assert outcome["result"]["changed"] == 1, "the job selected the node before the write committed"
    got = _aging(raw_driver, value)
    assert (got["active"], got["retired_by"], got["aging_tier"]) == (False, "decay", 3)
    assert got["aging_since"] == got["retired_at"] == basis + timedelta(days=730)
    assert _evaluated_at(raw_driver, value) >= now, "the write's time, not the job's older one"


def test_the_alert_path_ages_from_a_report_committed_while_it_waited(client, raw_driver):
    """2026-10-16: the alert path applies the rule in a second statement of its transaction. A sync
    write of a newer report is open on a retired node when an alert arrives: the alert's statement
    waits for the node's lock, and its second statement then reads the newer report and keeps the
    node active. In one statement the planner read the basis with the MERGE, before the lock: the
    alert aged the node from the old report and retired it again."""
    from indicator_aging import aging_set_clause

    now = _db_now(raw_driver)
    value = "203.0.113.96"
    _indicator(raw_driver, value)
    _write(client, _attr(value, "o-1", now - timedelta(days=2), now - timedelta(days=800)))
    assert _aging(raw_driver, value)["active"] is False
    newer = now - timedelta(days=10)

    outcome: dict = {}

    def alert() -> None:
        try:
            outcome["ok"] = client.create_indicator_from_alert(value, "ipv4", "global", alert_data={"alert_id": "a2"})
        except Exception as exc:  # pragma: no cover - reported below
            outcome["error"] = exc

    thread = threading.Thread(target=alert, daemon=True)
    session = raw_driver.session()
    tx = session.begin_transaction()
    try:
        tx.run(
            f"MATCH (n:Indicator:{LABEL} {{value: $v}}) "
            "SET n.last_reported_at = datetime($at), n.last_reported_basis = 'source_date', "
            "n.last_reported_ref = 'o-2', n.last_reported_source = 'feodo_tracker' " + aging_set_clause("n"),
            v=value,
            at=newer.isoformat(),
        ).consume()
        thread.start()
        time.sleep(3)
        waited = thread.is_alive()
        tx.commit()
    finally:
        if not tx.closed():
            tx.rollback()
        session.close()
        if thread.ident is not None:
            thread.join(timeout=120)
    assert waited, "the alert waits for the open write of the node"
    assert not thread.is_alive() and outcome.get("ok") is True, outcome
    got = _aging(raw_driver, value)
    assert got["last_reported_at"] == newer and got["last_reported_ref"] == "o-2"
    assert (got["active"], got["retired_by"], got["aging_tier"]) == (True, None, 0)
    assert got["aging_since"] == newer
