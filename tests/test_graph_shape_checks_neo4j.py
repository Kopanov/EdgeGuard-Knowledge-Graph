"""The graph-shape statements of the acceptance script on a real Neo4j with APOC (2026-11-02).

``src/graph_shape_checks.py`` judges each family of links the writers build against the claims stored on the
nodes, and the CVE score coverage. The unit tests pin the statements' text and judge the verdicts on rows; only
a database shows what the counters count, and a counter that always returns 0 passes every graph. This module
runs every statement on a small graph with stored nodes and edges and asserts each counter exactly:

* a Technique with and without its ``IN_TACTIC``, an ATT&CK for ICS Technique next to a Tactic of the same
  short name in the other domain, a Technique whose Tactic does not exist;
* MITRE actors, malware and tools with ``uses_techniques`` claims with and without their ``mitre_explicit``
  link (one only labelled ``otx_pulse``), a revoked id translated through the committed revoked-id map to a
  successor that exists, a claim whose Technique does not exist, MITRE nodes without a claim;
* indicators with ``attack_ids`` with and without their ``USES_TECHNIQUE``;
* zoned nodes with their Sector link, with a link of the wrong type, without one, with a sector no feed gave,
  with ``global`` only;
* NVD CVEs with and without a CVSS sub-node of each version, REJECTED ones (``status`` as a list and as a
  single value), CVEs only another feed delivered and CVEs EdgeGuard did not create.

Then the writers' own steps (``build_relationships`` steps 1, 5, 6, 8, 10 and 7a-7d, through
``_safe_run_batched`` as production runs them) build the links from the claims, and every statement passes on
what they wrote. Last, the acceptance script itself (``run_checks``) runs on the graph, its statements sent to
this database, and reports these counters and the sizes of the sets its own statements judge.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes
only nodes labelled ``EdgeGuardIT`` (every node a writer MERGEs exists beforehand with the label), refuses any
other node.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from neo4j import READ_ACCESS  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import build_relationships  # noqa: E402
import graph_shape_checks as gsc  # noqa: E402
import neo4j_client  # noqa: E402
from attack_revoked import technique_successors  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

SCRIPT = TESTS.parent / "scripts" / "verify_fresh_baseline.py"

# A revoked technique id of the committed map whose successor the graph holds.
REVOKED_ID, SUCCESSOR_ID = "T1086", "T1059.001"

# The graph. ``source`` stays a list on every node with a mitre_explicit link (the script's check 2 reads it
# with ``IN``); a single value is used where the statements read it through ``as_list``.
FIXTURE = f"""
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (nvd:Source:{LABEL} {{source_id: 'nvd'}})
CREATE (tf:Source:{LABEL} {{source_id: 'threatfox'}})
CREATE (mitre:Source:{LABEL} {{source_id: 'mitre_attck'}})
CREATE (energy:Sector:{LABEL} {{name: 'energy'}})
CREATE (finance:Sector:{LABEL} {{name: 'finance'}})
CREATE (health:Sector:{LABEL} {{name: 'healthcare'}})
CREATE (:Sector:{LABEL} {{name: 'global'}})

CREATE (exe:Tactic:{LABEL} {{mitre_id: 'TA0002', shortname: 'execution', attack_domain: 'enterprise'}})
CREATE (:Tactic:{LABEL} {{mitre_id: 'TA0003', shortname: 'persistence', attack_domain: 'enterprise'}})
CREATE (iexe:Tactic:{LABEL} {{mitre_id: 'TA0104', shortname: 'execution', attack_domain: 'ics'}})

// two phases whose Tactics exist, one linked
CREATE (t1059:Technique:{LABEL} {{mitre_id: 'T1059', attack_domain: 'enterprise',
        tactic_phases: ['execution', 'persistence']}})
CREATE (t1059)-[:IN_TACTIC {{edgeguard_managed: true}}]->(exe)
// ICS: its Tactic is the ICS 'execution', not the Enterprise one (also linked, across domains)
CREATE (t0807:Technique:{LABEL} {{mitre_id: 'T0807', attack_domain: 'ics', tactic_phases: ['Execution']}})
CREATE (t0807)-[:IN_TACTIC {{edgeguard_managed: true}}]->(iexe)
CREATE (t0807)-[:IN_TACTIC {{edgeguard_managed: true}}]->(exe)
// a phase without a Tactic in the graph (no attack_domain: Enterprise)
CREATE (:Technique:{LABEL} {{mitre_id: 'T1001', tactic_phases: ['command-and-control']}})
CREATE (ps:Technique:{LABEL} {{mitre_id: '{SUCCESSOR_ID}'}})
CREATE (t1486:Technique:{LABEL} {{mitre_id: 'T1486'}})
CREATE (t1055:Technique:{LABEL} {{mitre_id: 'T1055'}})

// T1486 linked only as otx_pulse; T9998 not in the graph; the revoked id linked to its successor
CREATE (a1:ThreatActor:{LABEL} {{name: 'apt-one', source: ['mitre_attck'], zone: ['global'],
        uses_techniques: ['T1059', 'T1486', '{REVOKED_ID}', 'T9998']}})
CREATE (a1)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1059)
CREATE (a1)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(ps)
CREATE (a1)-[:EMPLOYS_TECHNIQUE {{match_type: 'otx_pulse', edgeguard_managed: true}}]->(t1486)
// a single claim stored as a single value
CREATE (a2:ThreatActor:{LABEL} {{name: 'apt-two', source: ['mitre_attck'], zone: ['finance'],
        uses_techniques: 'T1055'}})
CREATE (a2)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1055)
CREATE (a2)-[:SOURCED_FROM {{source: 'mitre_attck', zones: ['finance'], edgeguard_managed: true}}]->(mitre)
CREATE (a2)-[:TARGETS {{edgeguard_managed: true}}]->(finance)
// not from MITRE: no claim needed; its mitre_explicit link is the defect check 2 counts
CREATE (a3:ThreatActor:{LABEL} {{name: 'otx-actor', source: ['alienvault_otx']}})
CREATE (a3)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1055)
// from MITRE without a claim (``source`` a single value)
CREATE (:ThreatActor:{LABEL} {{name: 'apt-four', source: 'mitre_attck'}})

CREATE (m1:Malware:{LABEL} {{name: 'malware-one', source: ['mitre_attck'], zone: 'energy',
        uses_techniques: ['T1486', 'T1055']}})
CREATE (m1)-[:IMPLEMENTS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1486)
CREATE (:Malware:{LABEL} {{name: 'malware-two', source: ['threatfox']}})
CREATE (m3:Malware:{LABEL} {{name: 'malware-three', source: ['mitre_attck', 'alienvault_otx'],
        uses_techniques: ['{REVOKED_ID}']}})
CREATE (m3)-[:IMPLEMENTS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(ps)
CREATE (tool1:Tool:{LABEL} {{name: 'tool-one', source: ['mitre_attck'], uses_techniques: ['T1059']}})
CREATE (tool1)-[:IMPLEMENTS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1059)
CREATE (:Tool:{LABEL} {{name: 'tool-two', source: ['mitre_attck']}})

// OTX: T1486 without its link, T9997 not in the graph; energy linked, finance only by AFFECTS (wrong type)
CREATE (i1:Indicator:{LABEL} {{value: '203.0.113.10', source: ['alienvault_otx'], zone: ['energy', 'finance'],
        attack_ids: ['T1059', 'T1486', 'T9997']}})
CREATE (i1)-[:USES_TECHNIQUE {{edgeguard_managed: true}}]->(t1059)
CREATE (i1)-[:SOURCED_FROM {{source: 'alienvault_otx', zones: ['energy', 'finance'], edgeguard_managed: true}}]->(otx)
CREATE (i1)-[:TARGETS {{edgeguard_managed: true}}]->(energy)
CREATE (i1)-[:AFFECTS {{edgeguard_managed: true}}]->(finance)
// its feed gave energy, not its finance zone: that sector is not judged (check 10j reports it)
CREATE (i2:Indicator:{LABEL} {{value: 'bad.example', source: ['threatfox'], zone: ['finance'], attack_ids: 'T1055'}})
CREATE (i2)-[:USES_TECHNIQUE {{edgeguard_managed: true}}]->(t1055)
CREATE (i2)-[:SOURCED_FROM {{source: 'threatfox', zones: ['energy'], edgeguard_managed: true}}]->(tf)
CREATE (i3:Indicator:{LABEL} {{value: '198.51.100.7', source: ['threatfox']}})
// a partner's relationship type: not EdgeGuard's
CREATE (i3)-[:ON]->(tf)

// linked by a partner's AFFECTS (no ownership marker); EdgeGuard did not create the CVE
CREATE (cz:CVE:{LABEL} {{cve_id: 'CVE-2026-0001', source: ['nvd'], zone: ['healthcare']}})
CREATE (cz)-[:SOURCED_FROM {{source: 'nvd', zones: ['healthcare'], edgeguard_managed: true}}]->(nvd)
CREATE (cz)-[:AFFECTS]->(health)
"""

# 60 scored NVD CVEs (each CVSS version, ``source`` and ``status`` as a list, a single value or absent), 45
# unscored ones, 10 REJECTED (5 as a list, 5 as a single value), 10 scored CVEs only CISA KEV delivered and 3
# scored NVD CVEs EdgeGuard did not create.
CVES = f"""
UNWIND range(1, 60) AS i
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2026-1' + right('000' + toString(i), 3), edgeguard_managed: true,
        source: CASE WHEN i <= 5 THEN 'nvd' ELSE ['nvd', 'cisa_kev'] END,
        status: CASE i % 3 WHEN 0 THEN null WHEN 1 THEN ['Analyzed'] ELSE 'Modified' END}})
FOREACH (_ IN CASE WHEN i % 4 = 0 THEN [1] ELSE [] END | CREATE (c)-[:HAS_CVSS_v2]->(:CVSSv2:{LABEL}))
FOREACH (_ IN CASE WHEN i % 4 = 1 THEN [1] ELSE [] END | CREATE (c)-[:HAS_CVSS_v30]->(:CVSSv30:{LABEL}))
FOREACH (_ IN CASE WHEN i % 4 = 2 THEN [1] ELSE [] END | CREATE (c)-[:HAS_CVSS_v31]->(:CVSSv31:{LABEL}))
FOREACH (_ IN CASE WHEN i % 4 = 3 THEN [1] ELSE [] END | CREATE (c)-[:HAS_CVSS_v40]->(:CVSSv40:{LABEL}))
WITH count(*) AS scored
UNWIND range(1, 45) AS i
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-2' + right('000' + toString(i), 3), edgeguard_managed: true,
        source: ['nvd'], status: ['Awaiting Analysis']}})
WITH count(*) AS unscored
UNWIND range(1, 10) AS i
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2026-3' + right('000' + toString(i), 3), edgeguard_managed: true,
        source: ['nvd'], status: CASE WHEN i <= 5 THEN ['REJECTED'] ELSE 'Rejected' END}})
WITH count(*) AS rejected
UNWIND range(1, 10) AS i
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2026-4' + right('000' + toString(i), 3), edgeguard_managed: true,
        source: ['cisa_kev']}})-[:HAS_CVSS_v31]->(:CVSSv31:{LABEL})
WITH count(*) AS kev
UNWIND range(1, 3) AS i
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2026-5' + right('000' + toString(i), 3), source: ['nvd']}})
        -[:HAS_CVSS_v31]->(:CVSSv31:{LABEL})
"""

# What each statement returns on that graph (``examples`` sorted).
IN_TACTIC_ROW = {
    "techniques": 6,
    "with_phases": 3,
    "claims_with_target": 3,  # T1059: execution, persistence; T0807: the ICS execution only
    "edge_missing": 1,  # T1059 -> persistence
    "tactic_missing": 1,  # T1001
    "examples": ["T1001", "T1059"],
}
EMPLOYS_ROW = {
    "claims": 5,
    "claiming_actors": 2,
    "target_missing": 1,  # T9998
    "claims_with_target": 4,
    "edge_missing": 1,  # T1486, linked as otx_pulse only
    "examples": ["apt-one -> T1486"],
    "mitre_nodes": 3,  # apt-one, apt-two, apt-four
}
IMPLEMENTS_ROWS = {
    "Malware": {
        "claims": 3,
        "claiming_malware": 2,
        "target_missing": 0,
        "claims_with_target": 3,
        "edge_missing": 1,
        "examples": ["malware-one -> T1055"],
        "mitre_nodes": 2,
    },
    "Tool": {
        "claims": 1,
        "claiming_tools": 1,
        "target_missing": 0,
        "claims_with_target": 1,
        "edge_missing": 0,
        "examples": [],
        "mitre_nodes": 2,
    },
}
USES_ROW = {
    "claims": 4,
    "claiming_indicators": 2,
    "target_missing": 1,  # T9997
    "claims_with_target": 3,
    "edge_missing": 1,
    "examples": ["203.0.113.10 -> T1486"],
}
SECTOR_ROW = {
    "zoned_nodes": 4,  # 203.0.113.10, CVE-2026-0001, malware-one, apt-two
    "node_sectors": 5,
    "sector_link_missing": 2,
    "examples": ["Indicator 203.0.113.10 -> finance", "Malware malware-one -> energy"],
}
COVERAGE_ROW = {"nvd_cves_not_rejected": 105, "nvd_cves_with_cvss": 60}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def graph(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
        session.run(CVES)
    yield raw_driver
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _write(driver, statement: str, **params) -> None:
    with driver.session() as session:
        session.run(statement, **params)


def _rows(driver, statement: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """The statement's rows, read in a read transaction (the acceptance script sends ``accessMode: Read``)."""
    with driver.session(default_access_mode=READ_ACCESS) as session:
        return session.execute_read(lambda tx: [r.data() for r in tx.run(statement, params or {})])


def _row(driver, statement: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rows = _rows(driver, statement, params)
    assert len(rows) == 1, rows
    row = rows[0]
    if "examples" in row:
        row["examples"] = sorted(row["examples"])
    return row


def _technique_rows(driver, revoked: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    params = gsc.technique_params(revoked)
    return {
        "ThreatActor": _row(driver, gsc.EMPLOYS_TECHNIQUE_COMPLETE_QUERY, params),
        **{label: _row(driver, st, params) for label, st in gsc.IMPLEMENTS_TECHNIQUE_COMPLETE_QUERIES.items()},
        "Indicator": _row(driver, gsc.USES_TECHNIQUE_COMPLETE_QUERY, params),
    }


def _all_rows(driver) -> Dict[str, Dict[str, Any]]:
    return {
        "in_tactic": _row(driver, gsc.IN_TACTIC_COMPLETE_QUERY),
        **_technique_rows(driver, technique_successors()),
        "sector": _row(driver, gsc.SECTOR_LINKS_COMPLETE_QUERY, gsc.sector_params()),
        "coverage": _row(driver, gsc.CVE_CVSS_COVERAGE_QUERY),
    }


def _verdicts(rows: Dict[str, Dict[str, Any]]) -> Dict[str, Optional[bool]]:
    return {
        "in_tactic": gsc.in_tactic_verdict(rows["in_tactic"]),
        "ThreatActor": gsc.technique_claims_verdict(rows["ThreatActor"]),
        "Malware": gsc.technique_claims_verdict(rows["Malware"]),
        "Tool": gsc.technique_claims_verdict(rows["Tool"]),
        "implements": gsc.combined_verdict(
            (gsc.technique_claims_verdict(rows["Malware"]), gsc.technique_claims_verdict(rows["Tool"]))
        ),
        "Indicator": gsc.technique_claims_verdict(rows["Indicator"]),
        "sector": gsc.sector_links_verdict(rows["sector"]),
        "coverage": gsc.cvss_coverage_verdict(rows["coverage"]),
    }


def test_the_revoked_id_of_the_fixture_is_in_the_committed_map():
    assert technique_successors()[REVOKED_ID] == SUCCESSOR_ID


def test_each_statement_counts_what_the_graph_holds(graph):
    rows = _all_rows(graph)

    assert rows["in_tactic"] == IN_TACTIC_ROW
    assert rows["ThreatActor"] == EMPLOYS_ROW
    assert rows["Malware"] == IMPLEMENTS_ROWS["Malware"]
    assert rows["Tool"] == IMPLEMENTS_ROWS["Tool"]
    assert rows["Indicator"] == USES_ROW
    assert rows["sector"] == SECTOR_ROW
    assert rows["coverage"] == COVERAGE_ROW
    assert _verdicts(rows) == {
        "in_tactic": False,
        "ThreatActor": False,
        "Malware": False,
        "Tool": True,
        "implements": False,
        "Indicator": False,
        "sector": False,
        "coverage": True,  # 60 of 105
    }


def test_the_revoked_id_counts_as_its_successor_only_through_the_map(graph):
    """Without the map (it could not be read) the revoked id names no Technique: a missing target, never a
    missing link."""
    rows = _technique_rows(graph, {})
    assert rows["ThreatActor"] == dict(EMPLOYS_ROW, target_missing=2, claims_with_target=3)
    assert rows["Malware"] == dict(IMPLEMENTS_ROWS["Malware"], target_missing=1, claims_with_target=2)
    # the successor exists without a link from the claiming node: the translated claim is a missing link
    _write(graph, "MATCH (:Malware {name: 'malware-three'})-[r:IMPLEMENTS_TECHNIQUE]->() DELETE r")
    malware = _technique_rows(graph, technique_successors())["Malware"]
    assert (malware["edge_missing"], sorted(malware["examples"])) == (
        2,
        ["malware-one -> T1055", f"malware-three -> {SUCCESSOR_ID}"],
    )


def test_each_counter_follows_its_defect(graph):
    """One change at a time: the counters move by exactly what changed."""
    _write(
        graph,
        "MATCH (t:Technique {mitre_id: 'T1059'}), (tc:Tactic {shortname: 'persistence'}) CREATE (t)-[:IN_TACTIC]->(tc)",
    )
    assert _row(graph, gsc.IN_TACTIC_COMPLETE_QUERY) == dict(IN_TACTIC_ROW, edge_missing=0, examples=["T1001"])
    _write(graph, f"CREATE (:Tactic:{LABEL} {{shortname: 'Command-And-Control', attack_domain: 'enterprise'}})")
    in_tactic = _row(graph, gsc.IN_TACTIC_COMPLETE_QUERY)
    assert in_tactic == dict(IN_TACTIC_ROW, claims_with_target=4, edge_missing=1, tactic_missing=0, examples=["T1001"])
    assert gsc.in_tactic_verdict(in_tactic) is False  # the Tactic exists now, its link does not

    # the otx_pulse link labelled mitre_explicit, as step 5 labels it
    _write(
        graph,
        "MATCH (:ThreatActor {name: 'apt-one'})-[r:EMPLOYS_TECHNIQUE {match_type: 'otx_pulse'}]->() "
        "SET r.match_type = 'mitre_explicit'",
    )
    employs = _technique_rows(graph, technique_successors())["ThreatActor"]
    assert employs == dict(EMPLOYS_ROW, edge_missing=0, examples=[])
    assert gsc.technique_claims_verdict(employs) is True

    # a link of another type to the right Sector is no link; the right type is
    _write(
        graph,
        "MATCH (i:Indicator {value: '203.0.113.10'}), (s:Sector {name: 'finance'}) CREATE (i)-[:TARGETS]->(s)",
    )
    assert _row(graph, gsc.SECTOR_LINKS_COMPLETE_QUERY, gsc.sector_params()) == dict(
        SECTOR_ROW, sector_link_missing=1, examples=["Malware malware-one -> energy"]
    )


def test_the_writers_links_pass_every_statement(graph):
    """``build_relationships`` steps 1, 5, 6, 10, 8 and 7a-7d on the claims: every link a statement looks for is
    one the writer builds, so a graph the writers completed passes every statement."""
    _write(graph, f"CREATE (:Tactic:{LABEL} {{shortname: 'command-and-control', attack_domain: 'enterprise'}})")
    client = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert client.connect()
    try:
        for step in _writer_steps():
            stats: Dict[str, Any] = {}
            ok = build_relationships._safe_run_batched(
                client,
                step["label"],
                step["outer"],
                step["inner"],
                stats,
                step["key"],
                skip_query=step["skip"],
                params=step["params"],
            )
            assert ok, step["label"]
    finally:
        client.close()

    rows = _all_rows(graph)
    assert rows["in_tactic"] == dict(IN_TACTIC_ROW, claims_with_target=4, edge_missing=0, tactic_missing=0, examples=[])
    for label in ("ThreatActor", "Malware", "Tool", "Indicator"):
        assert (rows[label]["edge_missing"], rows[label]["examples"]) == (0, []), label
    # the claims without a Technique are still counted, not linked
    assert (rows["ThreatActor"]["target_missing"], rows["Indicator"]["target_missing"]) == (1, 1)
    assert rows["sector"] == dict(SECTOR_ROW, sector_link_missing=0, examples=[])
    assert set(_verdicts(rows).values()) == {True}


def test_the_coverage_fails_under_half_and_judges_nothing_under_100_cves(graph):
    # ten scored CVEs lose their sub-node: 50 of 105
    _write(
        graph,
        "MATCH (c:CVE)-[r]->(s) WHERE c.cve_id IN [x IN range(1, 10) | 'CVE-2026-1' + right('000' + toString(x), 3)] "
        "DETACH DELETE s",
    )
    row = _row(graph, gsc.CVE_CVSS_COVERAGE_QUERY)
    assert row == {"nvd_cves_not_rejected": 105, "nvd_cves_with_cvss": 50}
    assert gsc.cvss_coverage_verdict(row) is False
    # six unscored CVEs fewer: 99, too few to judge
    _write(
        graph, "MATCH (c:CVE) WHERE c.cve_id STARTS WITH 'CVE-2026-2' AND c.cve_id <= 'CVE-2026-2006' DETACH DELETE c"
    )
    row = _row(graph, gsc.CVE_CVSS_COVERAGE_QUERY)
    assert row == {"nvd_cves_not_rejected": 99, "nvd_cves_with_cvss": 50}
    assert gsc.cvss_coverage_verdict(row) is None


def test_empty_sets_judge_nothing_and_lost_claims_fail(graph):
    # no Technique: IN_TACTIC judges nothing, and the actor's claims reach no Technique
    _write(graph, "MATCH (t:Technique) DETACH DELETE t")
    rows = _all_rows(graph)
    assert rows["in_tactic"] == {
        "techniques": 0,
        "with_phases": 0,
        "claims_with_target": 0,
        "edge_missing": 0,
        "tactic_missing": 0,
        "examples": [],
    }
    assert rows["ThreatActor"] == dict(EMPLOYS_ROW, target_missing=5, claims_with_target=0, edge_missing=0, examples=[])
    assert rows["Indicator"] == dict(USES_ROW, target_missing=4, claims_with_target=0, edge_missing=0, examples=[])
    verdicts = _verdicts(rows)
    assert (verdicts["in_tactic"], verdicts["ThreatActor"], verdicts["implements"], verdicts["Indicator"]) == (
        None,
        None,
        None,
        None,
    )

    # MITRE malware and tools whose claims were lost: nothing claimed while MITRE nodes exist
    _write(graph, "MATCH (n) WHERE n:Malware OR n:Tool REMOVE n.uses_techniques")
    rows = _technique_rows(graph, technique_successors())
    for label, claimants in (("Malware", "claiming_malware"), ("Tool", "claiming_tools")):
        assert rows[label] == {
            "claims": 0,
            claimants: 0,
            "target_missing": 0,
            "claims_with_target": 0,
            "edge_missing": 0,
            "examples": [],
            "mitre_nodes": 2,
        }, label
        assert gsc.technique_claims_verdict(rows[label]) is False, label
    # and without MITRE nodes of the label, nothing to judge
    _write(graph, "MATCH (n) WHERE n:Malware OR n:Tool SET n.source = ['threatfox']")
    rows = _technique_rows(graph, technique_successors())
    assert (rows["Malware"]["mitre_nodes"], rows["Tool"]["mitre_nodes"]) == (0, 0)
    assert gsc.technique_claims_verdict(rows["Malware"]) is None

    # no node sector a feed gave: the zoned nodes keep only global
    _write(graph, "MATCH (n) WHERE n.zone IS NOT NULL SET n.zone = ['global']")
    sector = _row(graph, gsc.SECTOR_LINKS_COMPLETE_QUERY, gsc.sector_params())
    assert sector == {"zoned_nodes": 0, "node_sectors": 0, "sector_link_missing": 0, "examples": []}
    assert gsc.sector_links_verdict(sector) is None


def _writer_steps() -> List[Dict[str, Any]]:
    """The ``build_relationships`` steps that build the links the statements judge (1, 5, 6, 10, 8, 7a-7d),
    rendered as the baseline renders them (``$revoked`` from the committed map)."""
    steps: List[Dict[str, Any]] = []

    class _Client:
        def connect(self):
            return True

        def close(self):
            pass

        def run(self, query, **kw):
            return [{"count": 0, "c": 0}]

    def _batched(client, label, outer, inner, stats, key, batch_size=5000, skip_query=None, params=None):
        steps.append({"label": label, "outer": outer, "inner": inner, "key": key, "skip": skip_query, "params": params})
        return True

    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(build_relationships, "Neo4jClient", _Client)
        mp.setattr(build_relationships, "_safe_run_batched", _batched)
        mp.setattr(build_relationships, "query_pause", lambda: None)
        build_relationships.build_relationships()
    finally:
        mp.undo()

    sector_inners = {
        s.inner
        for s in (
            build_relationships._Q7A_STATEMENTS,
            build_relationships._Q7B_STATEMENTS,
            build_relationships._Q7C_STATEMENTS,
            build_relationships._Q7D_STATEMENTS,
        )
    }
    chosen = [s for s in steps if "MERGE (t)-[r:IN_TACTIC]->(tc)" in s["inner"] or s["inner"] in sector_inners]
    for label, claims, rel_type, _match_type in gsc.TECHNIQUE_CLAIM_LINKS:
        chosen += [
            s
            for s in steps
            if re.fullmatch(
                rf"MATCH \((\w+):{label}\) WHERE size\(coalesce\(\1\.{claims}, \[\]\)\) > 0 RETURN \1", s["outer"]
            )
            and f":{rel_type}]->(t)" in s["inner"]
        ]
    assert len(chosen) == 9, [s["label"] for s in chosen]
    return chosen


def _script():
    spec = importlib.util.spec_from_file_location("verify_fresh_baseline_graph_shape", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_acceptance_script_reports_these_counters(graph, monkeypatch):
    """``run_checks`` with its statements sent to this database: the new checks' verdicts and details, and the
    sizes the script's own statements count (2026-11-02)."""
    vfb = _script()
    monkeypatch.setattr(vfb, "_post", lambda statement, params=None, timeout=180: _rows(graph, statement, params))
    rep = vfb.run_checks(False, False, False, False)
    checks = {c["check"]: c for c in rep.checks}

    def detail(name: str) -> Dict[str, Any]:
        d = dict(checks[name]["detail"])
        if "examples" in d:
            d["examples"] = sorted(d["examples"])
        return d

    assert checks["in_tactic_complete"]["ok"] is False and detail("in_tactic_complete") == IN_TACTIC_ROW
    assert checks["employs_technique_complete"]["ok"] is False
    assert detail("employs_technique_complete") == dict(EMPLOYS_ROW, revoked_map=vfb.load_revoked_ids().version)
    implements = checks["implements_technique_complete"]
    assert implements["ok"] is False
    for label in ("Malware", "Tool"):
        assert (
            dict(implements["detail"][label], examples=sorted(implements["detail"][label]["examples"]))
            == (IMPLEMENTS_ROWS[label])
        )
    assert checks["uses_technique_complete"]["ok"] is False
    assert {k: v for k, v in detail("uses_technique_complete").items() if k != "revoked_map"} == USES_ROW
    assert checks["sector_links_complete"]["ok"] is False and detail("sector_links_complete") == SECTOR_ROW
    assert checks["cve_cvss_coverage"]["ok"] is True
    assert detail("cve_cvss_coverage") == dict(COVERAGE_ROW, share_with_cvss=0.571)
    for name in (
        "in_tactic_complete",
        "employs_technique_complete",
        "implements_technique_complete",
        "uses_technique_complete",
        "sector_links_complete",
        "cve_cvss_coverage",
    ):
        assert checks[name]["mandatory"] is True, name

    # check 9: three IN_TACTIC links, one across domains
    assert checks["in_tactic_same_domain"]["ok"] is False
    assert detail("in_tactic_same_domain") == {"judged_edges": 3, "c": 1}
    # check 2: seven mitre_explicit links, one from a node not from MITRE
    assert checks["mitre_explicit_only_from_mitre_nodes"]["ok"] is False
    assert detail("mitre_explicit_only_from_mitre_nodes") == {"judged_edges": 7, "c": 1}
    # the links to a Sector: four, three of them EdgeGuard's
    assert checks["no_global_sector_edges"]["detail"] == {"c": 0, "judged_edges": 4}
    assert checks["sector_links_name_only_feeds_that_gave_the_sector"]["detail"]["judged_edges"] == 3
    # the edges of EdgeGuard's types: every edge but the partner's ON
    edges = _row(
        graph, "MATCH ()-[r]->() RETURN count(r) AS all, sum(CASE WHEN type(r) = 'ON' THEN 1 ELSE 0 END) AS on"
    )
    assert edges["on"] == 1
    for name in ("ownership_marker_on_edges", "no_legacy_relationship_properties"):
        assert checks[name]["detail"]["judged_edges"] == edges["all"] - 1, name
    nodes = _row(graph, "MATCH (n) RETURN count(n) AS c")["c"]
    assert checks["ownership_marker_on_nodes"]["detail"]["examined_nodes"] == nodes
