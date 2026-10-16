"""Two graph-data corrections of 2026-10 on a real Neo4j with APOC.

* ``Technique.is_subtechnique`` follows the ATT&CK id. Every sync wrote ``false`` onto every
  sub-technique, because the MISP round trip carries no flag (all 506 dotted Technique nodes of the
  hosted graph on 2026-10-16); the next sync of a sub-technique now sets ``true`` on the stored node.
* Q9 (``build_relationships``, ``Indicator → Malware`` by family) names in ``r.sources`` only the
  feeds that state the indicator's ``malware_family``. OTX was listed among them although its
  collector never writes one, so a family-labelled IOC an OTX pulse also listed got OTX, with that
  pulse and its MISP event, on its Q9 link. Step 9b still credits OTX where the pulse names the family.

Steps run as production runs them, through ``_safe_run_batched`` and ``apoc.periodic.iterate``.
Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
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

from build_rel_queries import assigned_query  # noqa: E402
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_attack_revoked_objects import _parse, _technique  # noqa: E402
from test_entity_description_source import mitre_items, synced, written  # noqa: E402

import build_relationships  # noqa: E402
import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

FIXTURE = f"""
CREATE (tf:Source:{LABEL} {{source_id: 'threatfox'}})
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Source:{LABEL} {{source_id: 'mitre_attck'}})
CREATE (:Malware:{LABEL} {{name: 'emotet', uuid: 'u-emotet', source: ['threatfox'], aliases: ['Heodo']}})
CREATE (listed:Indicator:{LABEL} {{value: '198.51.100.7', indicator_type: 'ipv4', uuid: 'u-listed',
        source: ['threatfox', 'alienvault_otx'], malware_family: 'Emotet'}})
CREATE (listed)-[:SOURCED_FROM {{source: 'threatfox', source_refs: ['threatfox:1001'], misp_event_ids: ['21']}}]->(tf)
CREATE (listed)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'],
        misp_event_ids: ['31']}}]->(otx)
CREATE (named:Indicator:{LABEL} {{value: '198.51.100.8', indicator_type: 'ipv4', uuid: 'u-named',
        source: ['threatfox', 'alienvault_otx'], malware_family: 'Emotet', pulse_malware_families: ['Emotet']}})
CREATE (named)-[:SOURCED_FROM {{source: 'threatfox', source_refs: ['threatfox:1002'], misp_event_ids: ['22']}}]->(tf)
CREATE (named)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p2'],
        misp_event_ids: ['32']}}]->(otx)
CREATE (:Technique:{LABEL} {{mitre_id: 'T1059.001', uuid: 'u-ps', is_subtechnique: false}})
CREATE (:Technique:{LABEL} {{mitre_id: 'T1059', uuid: 'u-csi', is_subtechnique: false}})
"""
# ``listed``: ThreatFox labels the IOC and an OTX pulse lists it without naming the family.
# ``named``: the OTX pulse names the family too (the shape of all 12 Q9 links crediting OTX on the
# hosted graph of 2026-10-16). The Techniques are stored as the sync left them before 2026-10.


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


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
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _run_step(client, outer_name, inner_name, stat_key, skip_name, params=None):
    ok = build_relationships._safe_run_batched(
        client,
        stat_key,
        assigned_query(outer_name),
        assigned_query(inner_name),
        {},
        stat_key,
        skip_query=assigned_query(skip_name),
        params=params,
    )
    assert ok, f"{stat_key} failed"


def _q9(client):
    _run_step(client, "_q9_outer", "_q9_inner", "indicates_family", "_q9_skip")


def _q9b(client):
    params = build_relationships._software_id_params(client)
    _run_step(client, "_q9b_outer", "_q9b_inner", "indicates_pulse", "_q9b_skip", params=params)


def _indicates(driver) -> dict:
    with driver.session() as session:
        rows = session.run(
            f"MATCH (i:Indicator:{LABEL})-[r:INDICATES]->(m:Malware:{LABEL} {{name: 'emotet'}}) "
            "RETURN i.value AS ioc, r.sources AS sources, r.source_refs AS refs, r.misp_event_ids AS events, "
            "r.match_type AS match_type, r.confidence_score AS confidence"
        ).data()
    links: dict = {}
    for row in rows:
        assert row["ioc"] not in links, f"one INDICATES link per indicator expected: {row['ioc']}"
        links[row["ioc"]] = {
            "sources": sorted(row["sources"]),
            "refs": sorted(row["refs"]),
            "events": sorted(row["events"]),
            "match_type": row["match_type"],
            "confidence": row["confidence"],
        }
    return links


THREATFOX_ONLY = {
    "sources": ["threatfox"],
    "refs": ["threatfox:1001"],
    "events": ["21"],
    "match_type": "malware_family",
    "confidence": 0.8,
}


def test_q9_names_only_the_feeds_that_state_the_family(client, raw_driver):
    _q9(client)
    links = _indicates(raw_driver)
    assert links["198.51.100.7"] == THREATFOX_ONLY, "OTX listed the IOC but stated no family"
    assert links["198.51.100.8"]["sources"] == ["threatfox"], "Q9 alone credits the label feed only"


def test_9b_still_credits_otx_where_its_pulse_names_the_family(client, raw_driver):
    _q9(client)
    _q9b(client)
    links = _indicates(raw_driver)
    assert links["198.51.100.8"] == {
        "sources": ["alienvault_otx", "threatfox"],
        "refs": ["alienvault_otx:p2", "threatfox:1002"],
        "events": ["22", "32"],
        "match_type": "malware_family",
        "confidence": 0.8,
    }, "the pulse names the family: 9b adds OTX's provenance and keeps Q9's evidence and confidence"
    assert links["198.51.100.7"] == THREATFOX_ONLY, "9b links only the families a pulse names"
    # A second run of both steps changes nothing.
    _q9(client)
    _q9b(client)
    assert _indicates(raw_driver) == links


def _technique_flags(driver) -> dict:
    with driver.session() as session:
        rows = session.run(f"MATCH (t:Technique:{LABEL}) RETURN t.mitre_id AS id, t.is_subtechnique AS flag").data()
    return {row["id"]: row["flag"] for row in rows}


def test_the_next_sync_marks_a_stored_sub_technique_and_leaves_its_parent(client, raw_driver):
    sub = synced(written("technique", mitre_items()["technique"]))  # T1059.001, as the sync reads it from MISP
    parent_record = _parse(
        [
            _technique(
                "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830", "T1059", "Command and Scripting Interpreter"
            )
        ]
    )["techniques"][0]
    parent = synced(written("technique", parent_record))
    assert "is_subtechnique" not in sub and "is_subtechnique" not in parent, "MISP carries no flag"
    assert client.merge_technique(sub, source_id="mitre_attck")
    assert client.merge_technique(parent, source_id="mitre_attck")
    assert _technique_flags(raw_driver) == {"T1059.001": True, "T1059": False}
