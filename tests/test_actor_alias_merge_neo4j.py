"""The actor alias merge on a real Neo4j with APOC (2026-10).

Mocked sessions cannot show what ``apoc.refactor.mergeNodes`` does to property types. Its
``combine`` stores equal values as one string: two OTX names of one actor, both with ``source =
["alienvault_otx"]``, came out of the merge with ``source`` as a string, and ``apoc.coll.toSet`` on
it rolled back every batch. This module runs ``merge_alias_duplicate_actors`` on a database and
checks the node, its edges and their property types afterwards.

It runs only when ``EDGEGUARD_IT_NEO4J_URI`` is set (``EDGEGUARD_IT_NEO4J_USER``,
``EDGEGUARD_IT_NEO4J_PASSWORD``); the CI job ``neo4j-integration`` starts a throwaway Neo4j with
APOC for it. Every node it writes carries the label ``EdgeGuardIT``, and it refuses a database that
holds any other node.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

URI = os.getenv("EDGEGUARD_IT_NEO4J_URI", "")
if not URI and os.getenv("EDGEGUARD_IT_NEO4J_REQUIRED") == "1":  # the CI job: a skip would pass vacuously
    raise RuntimeError("EDGEGUARD_IT_NEO4J_REQUIRED=1 but EDGEGUARD_IT_NEO4J_URI is not set")
pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

if URI:
    os.environ.setdefault("NEO4J_PASSWORD", "integration-test")
    os.environ.setdefault("MISP_API_KEY", "integration-test")

import enrichment_jobs  # noqa: E402
import neo4j_client  # noqa: E402
from neo4j import GraphDatabase  # noqa: E402

LABEL = "EdgeGuardIT"

# Live cases from the 730-day graph (2026-10-15): an ATT&CK alias, two OTX names of one actor (the
# blocker), a never_merge name, and two ATT&CK nodes that are never merged.
FIXTURE = f"""
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (mitre:Source:{LABEL} {{source_id: 'mitre_attck'}})
CREATE (apt28:ThreatActor:{LABEL} {{name: 'apt28', uuid: 'u-apt28', source: ['mitre_attck', 'alienvault_otx'],
        aliases: ['APT28', 'Fancy Bear'], zone: ['global']}})
CREATE (fb:ThreatActor:{LABEL} {{name: 'fancy bear', uuid: 'u-fb', source: ['alienvault_otx'], zone: ['global']}})
CREATE (clop:ThreatActor:{LABEL} {{name: 'clop', uuid: 'u-clop', source: ['alienvault_otx'], zone: ['global'],
        pulse_ids: ['p1']}})
CREATE (cl0p:ThreatActor:{LABEL} {{name: 'cl0p', uuid: 'u-cl0p', source: ['alienvault_otx'], zone: ['global'],
        pulse_ids: ['p1']}})
CREATE (medusa:ThreatActor:{LABEL} {{name: 'medusa', uuid: 'u-medusa', source: ['alienvault_otx']}})
CREATE (mg:ThreatActor:{LABEL} {{name: 'medusa group', uuid: 'u-mg', source: ['mitre_attck'], aliases: ['Medusa']}})
CREATE (apt29:ThreatActor:{LABEL} {{name: 'apt29', uuid: 'u-apt29', source: ['mitre_attck'], aliases: ['UNC2452']}})
CREATE (unc:ThreatActor:{LABEL} {{name: 'unc2452', uuid: 'u-unc', source: ['mitre_attck']}})
CREATE (m:Malware:{LABEL} {{name: 'clop ransomware', uuid: 'u-m'}})
CREATE (t:Technique:{LABEL} {{mitre_id: 'T1486', uuid: 'u-t'}})
CREATE (m)-[:ATTRIBUTED_TO {{sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p1'],
        misp_event_ids: ['1'], match_type: 'otx_pulse', confidence: 0.5, src_uuid: 'u-m', trg_uuid: 'u-clop'}}]->(clop)
CREATE (m)-[:ATTRIBUTED_TO {{sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p1'],
        misp_event_ids: ['1'], match_type: 'otx_pulse', confidence: 0.5, src_uuid: 'u-m', trg_uuid: 'u-cl0p'}}]->(cl0p)
CREATE (cl0p)-[:USES_TECHNIQUE {{sources: ['alienvault_otx'], source_refs: ['alienvault_otx:p2'],
        misp_event_ids: ['2'], src_uuid: 'u-cl0p', trg_uuid: 'u-t'}}]->(t)
CREATE (clop)-[:SOURCED_FROM {{source: 'alienvault_otx', src_uuid: 'u-clop'}}]->(otx)
CREATE (cl0p)-[:SOURCED_FROM {{source: 'alienvault_otx', src_uuid: 'u-cl0p'}}]->(otx)
CREATE (fb)-[:SOURCED_FROM {{source: 'alienvault_otx', src_uuid: 'u-fb'}}]->(otx)
CREATE (apt28)-[:SOURCED_FROM {{source: 'mitre_attck', src_uuid: 'u-apt28'}}]->(mitre)
"""


def _actor(key, synonyms=(), attack=None):
    return {"name": key, "key": key, "mitre_attack": attack, "origins": [], "records": [], "synonyms": list(synonyms)}


REFERENCE = {
    "schema_version": 1,
    "version": "2026.10.15",
    "actors": [
        _actor("apt28", ["fancy bear"], "G0007"),
        _actor("apt29", ["unc2452"], "G0016"),
        _actor("clop", ["cl0p"]),
        _actor("medusa group", [], "G1051"),
    ],
    "ambiguous": [{"key": "medusa", "actors": ["medusa group"], "never_merge": {"reason": "test"}}],
}


@pytest.fixture(scope="module")
def raw_driver():
    driver = GraphDatabase.driver(
        URI, auth=(os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", ""))
    )
    deadline = time.monotonic() + 120
    while True:
        try:
            driver.verify_connectivity()
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(2)
    with driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
        if foreign:
            driver.close()
            pytest.fail(f"refusing to run: the database holds {foreign} nodes this test did not write")
        try:
            session.run("RETURN apoc.version() AS v").single()
        except Exception as exc:
            driver.close()
            pytest.fail(f"APOC is not installed on the test database: {exc}")
    yield driver
    with driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
    driver.close()


@pytest.fixture
def graph(raw_driver, monkeypatch, tmp_path):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    path = tmp_path / "canonical_threat_actors.json"
    path.write_text(json.dumps(REFERENCE), encoding="utf-8")
    monkeypatch.setenv("EDGEGUARD_CANONICAL_THREAT_ACTORS", str(path))
    monkeypatch.delenv(enrichment_jobs._ACTOR_ALIAS_MERGE_ENV_FLAG, raising=False)
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    client = SimpleNamespace(driver=neo4j_client._TimeoutDriver(raw_driver))
    return client, raw_driver


def _one(driver, query, **params):
    with driver.session() as session:
        record = session.run(query, **params).single()
        return record.data() if record else None


def _names(driver):
    with driver.session() as session:
        return sorted(r["name"] for r in session.run(f"MATCH (a:ThreatActor:{LABEL}) RETURN a.name AS name"))


class TestMergeOnNeo4j:
    def test_apoc_combine_stores_two_equal_lists_as_one_string(self, graph):
        """Why the merge statement wraps lists: on this database, ``combine`` turns two equal
        single-element lists into a string, which ``apoc.coll.toSet`` cannot take. If APOC changes
        this, the test says so; the wrapping stays correct either way."""
        _, driver = graph
        with driver.session() as session:
            record = session.run(
                "MATCH (c:ThreatActor {name: 'clop'}), (d:ThreatActor {name: 'cl0p'}) "
                "CALL apoc.refactor.mergeNodes([c, d], {properties: {source: 'combine', `.*`: 'discard'}, "
                "mergeRels: true, produceSelfRel: false}) YIELD node "
                "RETURN apoc.meta.cypher.type(node.source) AS source_type, node.source AS source"
            ).single()
        assert (record["source_type"], record["source"]) == ("STRING", "alienvault_otx")

    def test_two_names_with_the_same_single_source_merge_and_keep_lists(self, graph):
        client, driver = graph
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["errors"] == 0 and res["apoc_missing"] == 0
        assert res["merged"] == 2  # fancy bear -> apt28 (both rules), cl0p -> clop (reference)
        assert res["skipped_blocked"] == 1  # medusa: never_merge in the reference
        assert _names(driver) == ["apt28", "apt29", "clop", "medusa", "medusa group", "unc2452"]

        clop = _one(
            driver,
            "MATCH (a:ThreatActor {name: 'clop'}) RETURN a.source AS source, a.zone AS zone, "
            "a.aliases AS aliases, a.pulse_ids AS pulse_ids, a.uuid AS uuid",
        )
        assert clop == {
            "source": ["alienvault_otx"],
            "zone": ["global"],
            "aliases": ["cl0p"],
            "pulse_ids": ["p1"],
            "uuid": "u-clop",
        }
        apt28 = _one(driver, "MATCH (a:ThreatActor {name: 'apt28'}) RETURN a.aliases AS aliases, a.source AS source")
        assert set(apt28["aliases"]) == {"APT28", "Fancy Bear", "fancy bear"}
        assert sorted(apt28["source"]) == ["alienvault_otx", "mitre_attck"]

    def test_edges_move_collapse_and_keep_their_types(self, graph):
        client, driver = graph
        enrichment_jobs.merge_alias_duplicate_actors(client)
        attributed = _one(
            driver,
            "MATCH (:Malware {name: 'clop ransomware'})-[r:ATTRIBUTED_TO]->(a:ThreatActor) "
            "RETURN count(r) AS n, collect(a.name) AS actors, head(collect(r.sources)) AS sources, "
            "head(collect(r.source_refs)) AS refs, head(collect(r.misp_event_ids)) AS events, "
            "head(collect(r.trg_uuid)) AS trg",
        )
        assert attributed == {
            "n": 1,
            "actors": ["clop"],
            "sources": ["alienvault_otx"],
            "refs": ["alienvault_otx:p1"],
            "events": ["1"],
            "trg": "u-clop",
        }
        technique = _one(
            driver,
            "MATCH (a:ThreatActor)-[r:USES_TECHNIQUE]->(:Technique {mitre_id: 'T1486'}) "
            "RETURN a.name AS actor, r.src_uuid AS src, r.sources AS sources",
        )
        assert technique == {"actor": "clop", "src": "u-clop", "sources": ["alienvault_otx"]}
        sourced = _one(
            driver,
            "MATCH (:ThreatActor {name: 'clop'})-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'}) "
            "RETURN count(r) AS n, head(collect(r.source)) AS source",
        )
        assert sourced == {"n": 1, "source": "alienvault_otx"}  # the scalar source id stays a scalar

    def test_a_second_run_merges_nothing(self, graph):
        client, driver = graph
        enrichment_jobs.merge_alias_duplicate_actors(client)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["merged"] == 0 and res["errors"] == 0

    def test_without_the_reference_only_attack_aliases_merge(self, graph, monkeypatch, tmp_path):
        client, driver = graph
        monkeypatch.setenv("EDGEGUARD_CANONICAL_THREAT_ACTORS", str(tmp_path / "missing.json"))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["errors"] == 0 and res["merged"] == 2  # fancy bear -> apt28, medusa -> medusa group
        assert _names(driver) == ["apt28", "apt29", "cl0p", "clop", "medusa group", "unc2452"]

    def test_the_merge_statement_refuses_a_canonical_that_is_neither_attack_nor_named(self, graph):
        _, driver = graph
        with driver.session() as session:
            record = session.run(
                enrichment_jobs._ACTOR_ALIAS_MERGE_APPLY_CYPHER,
                groups=[
                    {"canonical": "clop", "duplicates": ["cl0p"]},
                    {"canonical": "apt29", "duplicates": ["unc2452"]},
                ],
                strategy=enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY,
                mitre_source="mitre_attck",
                reference_canonicals=[],
            ).single()
        assert record["merged"] == 0  # clop is not ATT&CK-sourced and not named; unc2452 is ATT&CK-sourced
        assert "cl0p" in _names(driver) and "unc2452" in _names(driver)
