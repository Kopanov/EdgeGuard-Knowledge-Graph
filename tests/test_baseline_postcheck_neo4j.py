"""The baseline postcheck end to end on a real Neo4j with APOC (2026-11-02, invariants INV-4 to INV-6).

``tests/test_baseline_postcheck_shape.py`` judges the postcheck on the rows of the 730-day graph through a fake
session; only a database shows that the statements of ``graph_shape_checks`` count what the postcheck reads from
them. This module stores a small baseline graph (Source nodes keyed by their canonical ids, ATT&CK tactics,
techniques with their kill-chain phases and ``IN_TACTIC``, MITRE actors, malware and tools with
``uses_techniques`` and their ``mitre_explicit`` links, NVD CVEs with and without a CVSS sub-node, indicators
``SOURCED_FROM`` their sources) and runs the real ``assert_baseline_postconditions`` of the baseline DAG on it
through ``Neo4jClient``, with the task states and the collector XComs of a run. Each test then removes what a
defect removes (an edge, the claims, the scores, a source's edges) and asserts the verdict.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only
nodes labelled ``EdgeGuardIT``, refuses a database that holds any other node. The postcheck reads every node of
a label, so the database holds nothing else while it runs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS.parent / "dags", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402
from source_registry import all_sources  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

RUN = "manual__2026-11-02T08:00:00+00:00"
CHAIN = ("full_neo4j_sync", "build_relationships", "run_enrichment_jobs")

# 120 NVD CVEs, 80 of them scored (0.667), two REJECTED ones (not judged), 3 CISA KEV CVEs.
NVD_CVES, NVD_SCORED = 120, 80
OTX_ITEMS, THREATFOX_ITEMS, KEV_ITEMS = 20, 10, 3

FIXTURE = f"""
UNWIND $sources AS sid
CREATE (:Source:{LABEL} {{source_id: sid}})
WITH count(*) AS _
MATCH (mitre:Source {{source_id: 'mitre_attck'}})
CREATE (exe:Tactic:{LABEL} {{mitre_id: 'TA0002', shortname: 'execution', attack_domain: 'enterprise'}})
CREATE (per:Tactic:{LABEL} {{mitre_id: 'TA0003', shortname: 'persistence', attack_domain: 'enterprise'}})
CREATE (t1059:Technique:{LABEL} {{mitre_id: 'T1059', attack_domain: 'enterprise',
        tactic_phases: ['execution', 'persistence']}})
CREATE (t1055:Technique:{LABEL} {{mitre_id: 'T1055', attack_domain: 'enterprise', tactic_phases: ['execution']}})
CREATE (t1486:Technique:{LABEL} {{mitre_id: 'T1486', attack_domain: 'enterprise', tactic_phases: ['execution']}})
CREATE (t1059)-[:IN_TACTIC {{edgeguard_managed: true}}]->(exe)
CREATE (t1059)-[:IN_TACTIC {{edgeguard_managed: true}}]->(per)
CREATE (t1055)-[:IN_TACTIC {{edgeguard_managed: true}}]->(exe)
CREATE (t1486)-[:IN_TACTIC {{edgeguard_managed: true}}]->(exe)
CREATE (a:ThreatActor:{LABEL} {{name: 'apt-one', source: ['mitre_attck'], uses_techniques: ['T1059', 'T1486']}})
CREATE (a)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1059)
CREATE (a)-[:EMPLOYS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1486)
CREATE (m:Malware:{LABEL} {{name: 'malware-one', source: ['mitre_attck'], uses_techniques: ['T1055']}})
CREATE (m)-[:IMPLEMENTS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1055)
CREATE (tl:Tool:{LABEL} {{name: 'tool-one', source: ['mitre_attck'], uses_techniques: ['T1059']}})
CREATE (tl)-[:IMPLEMENTS_TECHNIQUE {{match_type: 'mitre_explicit', edgeguard_managed: true}}]->(t1059)
WITH mitre, [exe, per, t1059, t1055, t1486, a, m, tl] AS attack
UNWIND attack AS n
CREATE (n)-[:SOURCED_FROM {{source: 'mitre_attck', edgeguard_managed: true}}]->(mitre)
WITH count(*) AS _
MATCH (nvd:Source {{source_id: 'nvd'}})
UNWIND range(1, $nvd_cves) AS i
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2026-' + toString(10000 + i), source: ['nvd'], edgeguard_managed: true}})
CREATE (c)-[:SOURCED_FROM {{source: 'nvd', edgeguard_managed: true}}]->(nvd)
WITH c, i WHERE i <= $nvd_scored
CREATE (v:CVSSv31:{LABEL} {{cve_id: c.cve_id, base_score: 7.5}})
CREATE (c)-[:HAS_CVSS_v31 {{edgeguard_managed: true}}]->(v)
CREATE (v)-[:HAS_CVSS_v31 {{edgeguard_managed: true}}]->(c)
WITH count(*) AS _
MATCH (nvd:Source {{source_id: 'nvd'}})
CREATE (r1:CVE:{LABEL} {{cve_id: 'CVE-2026-0001', source: ['nvd'], status: ['REJECTED'], edgeguard_managed: true}})
CREATE (r2:CVE:{LABEL} {{cve_id: 'CVE-2026-0002', source: 'nvd', status: 'Rejected', edgeguard_managed: true}})
CREATE (r1)-[:SOURCED_FROM {{source: 'nvd', edgeguard_managed: true}}]->(nvd)
CREATE (r2)-[:SOURCED_FROM {{source: 'nvd', edgeguard_managed: true}}]->(nvd)
WITH count(*) AS _
MATCH (kev:Source {{source_id: 'cisa_kev'}})
UNWIND range(1, $kev) AS i
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2025-' + toString(20000 + i), source: ['cisa_kev'], edgeguard_managed: true}})
CREATE (c)-[:SOURCED_FROM {{source: 'cisa_kev', edgeguard_managed: true}}]->(kev)
WITH count(*) AS _
MATCH (otx:Source {{source_id: 'alienvault_otx'}})
UNWIND range(1, $otx) AS i
CREATE (n:Indicator:{LABEL} {{value: '203.0.113.' + toString(i), source: ['alienvault_otx']}})
CREATE (n)-[:SOURCED_FROM {{source: 'alienvault_otx', edgeguard_managed: true}}]->(otx)
WITH count(*) AS _
MATCH (tf:Source {{source_id: 'threatfox'}})
UNWIND range(1, $threatfox) AS i
CREATE (n:Indicator:{LABEL} {{value: 'bad' + toString(i) + '.example', source: ['threatfox']}})
CREATE (n)-[:SOURCED_FROM {{source: 'threatfox', edgeguard_managed: true}}]->(tf)
"""

MITRE_ITEMS = 8  # the 2 tactics, 3 techniques, 1 actor, 1 malware and 1 tool above


def _status(source: str, count: int, **extra) -> dict:
    return {"source": source, "success": True, "count": count, "failed": 0, **extra}


def _skipped(source: str, reason_class: str) -> dict:
    return _status(source, 0, skipped=True, skip_reason=reason_class, skip_reason_class=reason_class)


# What the collector tasks returned, by task id (the collectors' status dicts, ``make_status``).
XCOMS: Dict[str, Optional[dict]] = {
    "tier1_core.collect_cisa": _status("cisa_kev", KEV_ITEMS),
    "tier1_core.collect_mitre": _status("mitre", MITRE_ITEMS),
    "tier1_core.collect_otx": _status("otx", OTX_ITEMS),
    "tier1_core.collect_nvd": _status("nvd", NVD_CVES + 2),
    "tier2_feeds.collect_abuseipdb": _skipped("abuseipdb", "missing_abuseipdb_key"),
    "tier2_feeds.collect_threatfox": _status("threatfox", THREATFOX_ITEMS),
    "tier2_feeds.collect_urlhaus": _skipped("urlhaus", "missing_abusech_key"),
    "tier2_feeds.collect_feodo": None,  # the task failed
    "tier2_feeds.collect_sslblacklist": _skipped("sslbl", "transient_external_error"),
    "tier2_feeds.collect_cisa_ics": _skipped("cisa_ics", "cisa_ics_disabled_by_flag"),
    "tier2_feeds.collect_malwarebazaar": _skipped("malwarebazaar", "malwarebazaar_disabled_by_flag"),
}
STATES = {"tier2_feeds.collect_feodo": "failed"}


@pytest.fixture(scope="module")
def driver():
    yield from open_test_database()


@pytest.fixture(scope="module")
def ep():
    from stub_cleanup import dag_module_import

    with dag_module_import():
        import edgeguard_pipeline

    return edgeguard_pipeline


@pytest.fixture(autouse=True)
def graph(driver):
    with driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n").consume()
        session.run(
            FIXTURE,
            sources=[s.canonical_id for s in all_sources()],
            nvd_cves=NVD_CVES,
            nvd_scored=NVD_SCORED,
            kev=KEV_ITEMS,
            otx=OTX_ITEMS,
            threatfox=THREATFOX_ITEMS,
        ).consume()
    yield driver
    with driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n").consume()


def _write(driver, statement: str, **params) -> None:
    with driver.session() as session:
        session.run(statement, **params).consume()


def _ti(ep, xcoms, states):
    all_states = {task: "success" for task in (*CHAIN, *ep._BASELINE_COLLECTOR_TASKS.values())}
    all_states.update(states)
    ti = MagicMock()
    ti.dag_id, ti.run_id = "edgeguard_baseline", RUN
    ti.get_task_states.side_effect = lambda dag_id, task_ids, run_ids: {RUN: {t: all_states.get(t) for t in task_ids}}
    ti.xcom_pull.side_effect = lambda task_ids=None, **_kw: xcoms.get(task_ids)
    del ti.get_dagrun  # Airflow 3's RuntimeTaskInstance
    return ti


def _lines(log, level: str) -> List[str]:
    """The messages ``ep.logger`` received at ``level``, formatted."""
    out = []
    for call in getattr(log, level).call_args_list:
        msg, *args = call.args
        out.append(msg % tuple(args) if args else msg)
    return out


def _postcheck(ep, monkeypatch, xcoms=None, states=None, conf=None, required="", log=None):
    """The real postcheck on the test database; returns the AirflowException message, or None when it passed."""
    monkeypatch.delenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT", raising=False)
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", required)
    real_client = neo4j_client.Neo4jClient
    user, password = os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    ti = _ti(ep, XCOMS if xcoms is None else xcoms, STATES if states is None else states)
    log = log if log is not None else MagicMock()
    with (
        patch("neo4j_client.Neo4jClient", side_effect=lambda: real_client(URI, user, password)),
        patch.object(ep, "logger", log),
    ):
        try:
            assert (
                ep.assert_baseline_postconditions(ti=ti, task_instance=ti, dag_run=MagicMock(conf=conf or {})) is None
            )
        except ep.AirflowException:
            return "\n".join(_lines(log, "error"))
    assert any(x.startswith("[BASELINE-POSTCHECK] all invariants OK") for x in _lines(log, "info"))
    return None


def test_the_stored_baseline_passes_and_its_counters_read_the_stored_graph(ep, monkeypatch, graph):
    log = MagicMock()
    assert _postcheck(ep, monkeypatch, log=log) is None
    infos = "\n".join(_lines(log, "info"))
    assert (
        "IN_TACTIC 3 techniques, 3 with phases, 4 phases with a Tactic, 0 missing, 0 techniques without a Tactic"
        in infos
    )
    assert "EMPLOYS_TECHNIQUE from ThreatActor 2 claims, 2 with a Technique, 0 missing, 1 MITRE nodes" in infos
    assert "IMPLEMENTS_TECHNIQUE from Malware 1 claims, 1 with a Technique, 0 missing, 1 MITRE nodes" in infos
    assert "IMPLEMENTS_TECHNIQUE from Tool 1 claims, 1 with a Technique, 0 missing, 1 MITRE nodes" in infos
    assert "INV-5 CVE score coverage: 80 of 120 non-rejected NVD CVEs have a CVSS sub-node (0.667)" in infos
    assert "cisa_kev 3/3, mitre_attck 8/8, alienvault_otx 20/20, nvd 122/122, threatfox 10/10" in infos, infos
    table = "\n".join(x for x in _lines(log, "warning") if "delivered nothing" in x)
    assert "tier2_feeds.collect_feodo" in table and "task failed" in table
    assert "skipped (cisa_ics_disabled_by_flag)" in table


def test_a_lost_in_tactic_link_fails(ep, monkeypatch, graph):
    _write(
        graph,
        f"MATCH (:Technique:{LABEL} {{mitre_id: 'T1059'}})-[r:IN_TACTIC]->(:Tactic {{shortname: 'persistence'}}) DELETE r",
    )
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert "[INV-4] IN_TACTIC: 1 of the 4 kill-chain phases whose Tactic exists have no IN_TACTIC link" in errors
    assert "link (e.g. T1059)." in errors
    # Always judged: a limited run fails as well.
    assert _postcheck(ep, monkeypatch, conf={"collection_limit": 500}) is not None


@pytest.mark.parametrize(
    "label, rel_type, numbers",
    [("ThreatActor", "EMPLOYS_TECHNIQUE", "1 of the 2"), ("Malware", "IMPLEMENTS_TECHNIQUE", "1 of the 1")],
)
def test_a_lost_technique_link_fails(ep, monkeypatch, graph, label, rel_type, numbers):
    _write(
        graph,
        f"MATCH (:{label}:{LABEL})-[r:{rel_type}]->(:Technique {{mitre_id: $tid}}) DELETE r",
        tid="T1486" if label == "ThreatActor" else "T1055",
    )
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert f"[INV-4] {rel_type} (mitre_explicit): {numbers} uses_techniques claims of {label} nodes" in errors


def test_an_otx_pulse_link_does_not_stand_for_the_mitre_link(ep, monkeypatch, graph):
    _write(
        graph,
        f"MATCH (:ThreatActor:{LABEL})-[r:EMPLOYS_TECHNIQUE]->(:Technique {{mitre_id: 'T1486'}}) SET r.match_type = 'otx_pulse'",
    )
    assert "[INV-4] EMPLOYS_TECHNIQUE (mitre_explicit): 1 of the 2" in (_postcheck(ep, monkeypatch) or "")


def test_lost_claims_fail_an_unlimited_run_only(ep, monkeypatch, graph):
    _write(graph, f"MATCH (n:{LABEL}) WHERE n:ThreatActor OR n:Malware OR n:Tool REMOVE n.uses_techniques")
    _write(graph, f"MATCH (t:Technique:{LABEL}) REMOVE t.tactic_phases")
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert "[INV-4] tactic claims: of 3 techniques 0 carry tactic_phases, 0 phases reach a Tactic" in errors
    assert "[INV-4] ThreatActor claims: 1 MITRE ThreatActor nodes and not one uses_techniques claim" in errors
    assert (
        "[INV-4] Malware claims: 1 MITRE Malware nodes" in errors
        and "[INV-4] Tool claims: 1 MITRE Tool nodes" in errors
    )
    assert _postcheck(ep, monkeypatch, conf={"collection_limit": 500}) is None


def test_mitre_delivered_and_no_technique_fails(ep, monkeypatch, graph):
    _write(graph, f"MATCH (n:{LABEL}) WHERE n:Technique OR n:ThreatActor OR n:Malware OR n:Tool DETACH DELETE n")
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert (
        "[INV-4] ATT&CK shape: the MITRE collector delivered 8 items in this run and the graph holds no Technique"
        in errors
    )
    # MITRE failed in this run: nothing to judge INV-4 on (INV-6 still compares what delivered).
    no_mitre = dict(XCOMS, **{"tier1_core.collect_mitre": None})
    assert _postcheck(ep, monkeypatch, xcoms=no_mitre, states={**STATES, "tier1_core.collect_mitre": "failed"}) is None


def test_lost_cve_scores_fail(ep, monkeypatch, graph):
    # 21 of the 80 scored CVEs lose their sub-node: 59 of 120 (0.492) remain.
    _write(
        graph,
        f"MATCH (c:CVE:{LABEL})-[:HAS_CVSS_v31]->(v:CVSSv31) WITH v ORDER BY v.cve_id LIMIT 21 DETACH DELETE v",
    )
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert "[INV-5] CVE score coverage: 59 of the 120 non-rejected NVD CVEs have a CVSS sub-node (0.492" in errors
    # Not judged when NVD did not deliver in this run.
    no_nvd = dict(XCOMS, **{"tier1_core.collect_nvd": _skipped("nvd", "nvd_auth_denied")})
    assert _postcheck(ep, monkeypatch, xcoms=no_nvd) is None


def test_lost_source_edges_fail_below_nine_tenths(ep, monkeypatch, graph):
    _write(
        graph, "MATCH (:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) WITH r LIMIT 2 DELETE r"
    )
    assert _postcheck(ep, monkeypatch) is None  # 18 of 20 = 0.9
    _write(
        graph, "MATCH (:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) WITH r LIMIT 1 DELETE r"
    )
    errors = _postcheck(ep, monkeypatch)
    assert errors is not None
    assert (
        "[INV-6] alienvault_otx: 17 SOURCED_FROM edges for the 20 items tier1_core.collect_otx delivered in this run "
        "(0.850; at least 0.9 required)" in errors
    )


def test_a_required_source_without_data_fails(ep, monkeypatch, graph):
    _write(graph, "MATCH (:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) DELETE r")
    skipped = dict(XCOMS, **{"tier1_core.collect_otx": _skipped("otx", "otx_auth_denied")})
    assert _postcheck(ep, monkeypatch, xcoms=skipped) is None
    errors = _postcheck(ep, monkeypatch, xcoms=skipped, required="otx,virustotal")
    assert errors is not None
    assert (
        "[INV-6] otx is named in EDGEGUARD_BASELINE_REQUIRED_SOURCES and alienvault_otx holds no SOURCED_FROM edge "
        "(tier1_core.collect_otx: skipped (otx_auth_denied))" in errors
    )
    assert "virustotal" not in errors
