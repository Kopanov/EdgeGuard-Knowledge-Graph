"""The technique steps' ``[SKIP]`` counts on a real Neo4j with APOC (2026-11-02).

Each technique step translates a revoked ATT&CK id to its successor before it matches a ``Technique``
(``$revoked``, ``attack_revoked.technique_successors``). The six counts of rows without a technique
re-bound the UNWIND variable to the translated id: ``UNWIND x AS tid WITH coalesce($revoked[...], tid)
AS tid WHERE NOT EXISTS { MATCH (t:Technique {mitre_id: tid}) }``. On Neo4j 2026.03.1 (the image of
``docker-compose.yml`` and of the CI job) the subquery in that ``WHERE`` reads the UNWIND binding, the
id before the translation, so a revoked id whose successor exists counted as a skip: the 730-day
baseline of 2026-11-01 logged 44,268 for step 8, 1,945 for 6b and 399 for 5b. On the finished graph the
old statements count 44,268, 1,945 and 381, where 21,207, 148 and 27 rows lack a technique. Neo4j 2026.10.1 reads the projected value; the renamed statements count the
same on both.

Each node of the fixture cites ``T1002`` (revoked into ``T1560``, which exists) and the tactic id
``TA0003`` (no technique): one row without a technique per step. The database holds the uniqueness
constraint on ``Technique.mitre_id`` the live graph has (``Neo4jClient.create_constraints``), so the
subquery is planned on its index as it is there; the module drops it when it created it. The statements
are the ones ``build_relationships`` sends, run through ``_safe_run_batched`` as production runs them.
Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import inspect
import logging
import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_build_relationships_skip_counts import TECHNIQUE_SKIPS, _sent_statements  # noqa: E402

import build_relationships  # noqa: E402
import neo4j_client  # noqa: E402
from attack_revoked import technique_successors  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

CITED = "['T1002', 'TA0003']"

FIXTURE = f"""
CREATE (mitre:Source:{LABEL} {{source_id: 'mitre_attck'}})
CREATE (otx:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Technique:{LABEL} {{mitre_id: 'T1560', uuid: 'u-t1560'}})
CREATE (a:ThreatActor:{LABEL} {{name: 'it actor', uuid: 'u-a', source: ['mitre_attck', 'alienvault_otx'],
        uses_techniques: {CITED}, reported_techniques: {CITED}}})
CREATE (m:Malware:{LABEL} {{name: 'it malware', uuid: 'u-m', source: ['mitre_attck', 'alienvault_otx'],
        uses_techniques: {CITED}, reported_techniques: {CITED}}})
CREATE (tool:Tool:{LABEL} {{mitre_id: 'S9999', name: 'it tool', uuid: 'u-tool', source: ['mitre_attck'],
        uses_techniques: {CITED}}})
CREATE (i:Indicator:{LABEL} {{indicator_type: 'domain', value: 'it-skip.example', uuid: 'u-i',
        source: ['alienvault_otx'], attack_ids: {CITED}}})
CREATE (a)-[:SOURCED_FROM {{source: 'mitre_attck', source_refs: ['mitre_attck:G9999'], misp_event_ids: ['1']}}]->(mitre)
CREATE (a)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'], misp_event_ids: ['2']}}]->(otx)
CREATE (m)-[:SOURCED_FROM {{source: 'mitre_attck', source_refs: ['mitre_attck:S9998'], misp_event_ids: ['1']}}]->(mitre)
CREATE (m)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'], misp_event_ids: ['2']}}]->(otx)
CREATE (tool)-[:SOURCED_FROM {{source: 'mitre_attck', source_refs: ['mitre_attck:S9999'], misp_event_ids: ['1']}}]->(mitre)
CREATE (i)-[:SOURCED_FROM {{source: 'alienvault_otx', source_refs: ['alienvault_otx:p1'], misp_event_ids: ['2']}}]->(otx)
"""

# The edge each technique step writes, from the node the fixture gives it.
LINKS = {
    "ThreatActor → Technique (ATT&CK explicit)": ("ThreatActor", "EMPLOYS_TECHNIQUE"),
    "ThreatActor → Technique (reported)": ("ThreatActor", "EMPLOYS_TECHNIQUE"),
    "Malware → Technique (MITRE explicit)": ("Malware", "IMPLEMENTS_TECHNIQUE"),
    "Malware → Technique (reported)": ("Malware", "IMPLEMENTS_TECHNIQUE"),
    "Indicator → Technique (attack_ids)": ("Indicator", "USES_TECHNIQUE"),
    "Tool → Technique (MITRE explicit)": ("Tool", "IMPLEMENTS_TECHNIQUE"),
}


# The live graph's constraint on the property the technique steps match (``Neo4jClient.create_constraints``).
TECHNIQUE_KEY = "CREATE CONSTRAINT technique_key IF NOT EXISTS FOR (t:Technique) REQUIRE (t.mitre_id) IS UNIQUE"


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture(scope="module")
def technique_key(raw_driver):
    """The uniqueness constraint on ``Technique.mitre_id``, dropped afterwards when this module created it."""
    with raw_driver.session() as session:
        existed = session.run("SHOW CONSTRAINTS YIELD name WHERE name = 'technique_key' RETURN count(*) AS c").single()[
            "c"
        ]
        session.run(TECHNIQUE_KEY).consume()
    yield
    if not existed:
        with raw_driver.session() as session:
            session.run("DROP CONSTRAINT technique_key IF EXISTS").consume()


@pytest.fixture
def client(raw_driver, technique_key, monkeypatch):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


@pytest.fixture
def steps(monkeypatch):
    """The technique steps as ``build_relationships`` sends them: label -> (outer, inner, skip)."""
    with monkeypatch.context() as m:
        sent = _sent_statements(m)
    return {label: (outer, inner, skip) for label, outer, inner, skip in sent if label in TECHNIQUE_SKIPS}


def _count(raw_driver, statement):
    with raw_driver.session() as session:
        return session.run(statement, revoked=technique_successors()).single()["c"]


def _shadowed(skip: str, var: str) -> str:
    """The skip statement as it was before 2026-11-02: the UNWIND variable re-bound to the translated id."""
    return skip.replace("AS _cited ", f"AS {var} ", 1).replace(
        f"toString(_cited)], _cited) AS {var}", f"toString({var})], {var}) AS {var}", 1
    )


def test_the_map_translates_the_cited_id():
    assert technique_successors()["T1002"] == "T1560"


def test_the_constraint_is_the_live_graphs(client, raw_driver):
    assert TECHNIQUE_KEY in inspect.getsource(neo4j_client.Neo4jClient.create_constraints)
    with raw_driver.session() as session:
        rows = [
            dict(r)
            for r in session.run(
                "SHOW CONSTRAINTS YIELD name, type, labelsOrTypes, properties WHERE name = 'technique_key' "
                "RETURN type, labelsOrTypes, properties"
            )
        ]
    assert [(r["type"], r["labelsOrTypes"], r["properties"]) for r in rows] == [
        ("NODE_PROPERTY_UNIQUENESS", ["Technique"], ["mitre_id"])
    ]


def test_each_technique_step_counts_one_row_without_a_technique(client, raw_driver, steps, caplog):
    """The tactic id is the one row without a technique; ``T1002`` reaches ``T1560`` and is linked."""
    assert set(steps) == set(TECHNIQUE_SKIPS)
    for label, (outer, inner, skip) in steps.items():
        assert _count(raw_driver, skip) == 1, label
        caplog.clear()
        with caplog.at_level(logging.INFO, logger=build_relationships.logger.name):
            assert build_relationships._safe_run_batched(
                client, label, outer, inner, {}, "it", skip_query=skip, params={"revoked": technique_successors()}
            ), label
        skip_lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith(f"  [SKIP] {label}: ")]
        assert skip_lines == [f"  [SKIP] {label}: 1 {build_relationships._DEFAULT_SKIP_REASON}"], label
    with raw_driver.session() as session:
        links = {
            (r["kind"], r["type"], tuple(r["cited"] or ()))
            for r in session.run(
                f"MATCH (n:{LABEL})-[r]->(:Technique {{mitre_id: 'T1560'}}) "
                "RETURN [l IN labels(n) WHERE l <> $it][0] AS kind, type(r) AS type, r.cited_ids AS cited",
                it=LABEL,
            )
        }
    assert {(kind, rel) for kind, rel, _ in links} == set(LINKS.values())
    assert {cited for _, _, cited in links} == {("T1002",)}, "every link names the id the source cited"


def test_the_shadowed_form_counted_the_cited_id(client, raw_driver, steps):
    """The form before 2026-11-02 counts the revoked id as a skip on a Neo4j whose subquery reads the
    UNWIND binding (2026.03.1, shown on the 730-day graph); Neo4j 2026.10.1 reads the projected value,
    with the constraint as without it, and there both forms agree and the check skips."""
    counts = {
        label: _count(raw_driver, _shadowed(skip, TECHNIQUE_SKIPS[label][1])) for label, (_o, _i, skip) in steps.items()
    }
    if set(counts.values()) == {1}:
        pytest.skip(f"this Neo4j reads the projected value in the subquery (counts {counts})")
    assert counts == dict.fromkeys(steps, 2)
