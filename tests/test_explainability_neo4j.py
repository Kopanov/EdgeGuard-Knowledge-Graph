"""Explainability on a real Neo4j (2026-10): ``r.cited_ids`` on links a revoked ATT&CK id led to.

A link that reaches a technique through the revoked-id map records the id the source cited
(``r.cited_ids``); a link every source made to the technique's own id carries none. Two writers
are run as production runs them: ``build_relationships`` step 8 (OTX ``attack_ids``) through
``_safe_run_batched`` and ``apoc.periodic.iterate``, and the sync's
``create_misp_relationships_batch``, whose shared ``SET`` clause now handles ``cited_ids`` for every
relationship type. Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from build_rel_queries import assigned_queries  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import build_relationships  # noqa: E402
import neo4j_client  # noqa: E402
from attack_revoked import technique_successors  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


FIXTURE = f"""
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'it.example', uuid: 'u-i',
        source: ['alienvault_otx'], attack_ids: ['T1086', 'T1059.001', 'T1566']}})
CREATE (i)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'], misp_event_ids: ['5']}}]->(otx)
CREATE (:Technique:{LABEL} {{mitre_id: 'T1059.001', uuid: 'u-t1'}})
CREATE (:Technique:{LABEL} {{mitre_id: 'T1566', uuid: 'u-t2'}})
CREATE (:ThreatActor:{LABEL} {{name: 'apt29', uuid: 'u-a', source: ['alienvault_otx']}})
CREATE (:Malware:{LABEL} {{name: 'cobalt strike', uuid: 'u-m', source: ['alienvault_otx']}})
"""


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _cited(raw_driver, query):
    with raw_driver.session() as session:
        return {r["target"]: r["cited"] for r in session.run(query)}


def test_build_relationships_records_the_cited_id_on_a_translated_link(client, raw_driver):
    assert technique_successors()["T1086"] == "T1059.001"
    (outer,) = assigned_queries("_q8_outer")
    (inner,) = assigned_queries("_q8_inner")
    query = (
        "MATCH (:Indicator {value: 'it.example'})-[r:USES_TECHNIQUE]->(t:Technique) "
        "RETURN t.mitre_id AS target, r.cited_ids AS cited"
    )
    for _ in range(2):  # a second run adds nothing twice
        ok = build_relationships._safe_run_batched(
            client, "it", outer, inner, {}, "indicator_uses_technique", params={"revoked": technique_successors()}
        )
        assert ok
        # T1086 (revoked into T1059.001) and T1059.001 itself make one link, which names T1086;
        # the link to T1566 was cited as itself and carries no property.
        assert _cited(raw_driver, query) == {"T1059.001": ["T1086"], "T1566": None}


def test_the_sync_writer_records_cited_ids_on_technique_rows_only(client, raw_driver):
    base = {"confidence": 0.5, "misp_event_id": "5", "match_type": "misp_attribute_tag"}
    rows = [
        {
            **base,
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1059.001"},
            "cited_ids": ["T1086"],
        },
        {
            **base,
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1566"},
            "cited_ids": [],
        },
        {
            **base,
            "rel_type": "USES_MALWARE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Malware",
            "to_key": {"name": "cobalt strike"},
        },
    ]
    for _ in range(2):
        client.create_misp_relationships_batch(rows, source_id="alienvault_otx")
    techniques = _cited(
        raw_driver,
        "MATCH (:ThreatActor {name: 'apt29'})-[r:EMPLOYS_TECHNIQUE]->(t:Technique) "
        "RETURN t.mitre_id AS target, r.cited_ids AS cited",
    )
    assert techniques == {"T1059.001": ["T1086"], "T1566": None}
    malware = _cited(
        raw_driver,
        "MATCH (:ThreatActor {name: 'apt29'})-[r:USES_MALWARE]->(m:Malware) RETURN m.name AS target, r.cited_ids AS cited",
    )
    assert malware == {"cobalt strike": None}, "a row without cited_ids leaves the property absent"


CAMPAIGN_FIXTURE = f"""
CREATE (a:ThreatActor:{LABEL} {{name: 'fin7', uuid: 'u-fin7', source: ['mitre_attck'], tags: ['mitre']}})
CREATE (carbanak:Malware:{LABEL} {{name: 'carbanak', uuid: 'u-carbanak'}})
CREATE (griffon:Malware:{LABEL} {{name: 'griffon', uuid: 'u-griffon'}})
CREATE (carbanak)-[:ATTRIBUTED_TO {{match_type: 'otx_pulse', confidence_score: 0.6, sources: ['alienvault_otx']}}]->(a)
CREATE (griffon)-[:ATTRIBUTED_TO {{match_type: 'mitre_explicit', confidence_score: 0.95, sources: ['mitre_attck']}}]->(a)
CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'fin7.example', uuid: 'u-fin7-i', active: true,
        first_imported_at: datetime('2026-10-01T00:00:00Z')}})
CREATE (i)-[:INDICATES {{match_type: 'malware_family', confidence_score: 0.8, sources: ['threatfox']}}]->(carbanak)
CREATE (i)-[:INDICATES {{match_type: 'otx_pulse', confidence_score: 0.5, sources: ['alienvault_otx']}}]->(griffon)
"""


def test_campaign_links_state_their_evidence_and_its_strength(client, raw_driver, monkeypatch):
    """``campaign_grouping`` on every campaign link, with the confidence of the evidence it rests on:
    RUNS the actor's strongest attribution (0.95); a malware link its ATTRIBUTED_TO (0.6, 0.95); the
    indicator its best path, each path as strong as its weaker link (max(min(0.8, 0.6), min(0.5, 0.95)) = 0.6)."""
    import enrichment_jobs

    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    with raw_driver.session() as session:
        session.run(CAMPAIGN_FIXTURE)
    for _ in range(2):  # recomputed on every run: the same answer
        enrichment_jobs.build_campaign_nodes(client)
        with raw_driver.session() as session:
            session.run(f"MATCH (c:Campaign) SET c:{LABEL}")  # removed with the fixture
            rows = {
                (r["from"], r["type"]): (r["label"], r["confidence"])
                for r in session.run(
                    "MATCH (n)-[r:RUNS|PART_OF_CAMPAIGN]->(:Campaign {actor_name: 'fin7'}) "
                    "RETURN coalesce(n.name, n.value) AS from, type(r) AS type, r.match_type AS label, "
                    "r.confidence_score AS confidence"
                )
            }
        assert rows == {
            ("fin7", "RUNS"): ("campaign_grouping", 0.95),
            ("carbanak", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.6),
            ("griffon", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.95),
            ("fin7.example", "PART_OF_CAMPAIGN"): ("campaign_grouping", 0.6),
        }
