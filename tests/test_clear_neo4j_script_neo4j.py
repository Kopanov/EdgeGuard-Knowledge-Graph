"""``scripts/clear_neo4j.py`` on a real Neo4j (2026-10).

The default run and ``--label`` delete only the nodes EdgeGuard created (``edgeguard_managed =
true``): a partner's ``Vulnerability`` and ``CVE``, nodes whose marker is ``false`` or the string
``"true"``, and the partner's relationships stay. ``tests/test_clear_neo4j_script.py`` runs the
statements on an in-memory graph that implements Cypher's meaning as its author reads it; this module
runs them on a database. Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS.parent / "scripts", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

# First, so its guards (and the settings it defaults) apply before the script and the client load.
from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

import clear_neo4j  # noqa: E402

import baseline_checkpoint  # noqa: E402
import destructive_ops_audit  # noqa: E402
import neo4j_client  # noqa: E402

# EdgeGuard's nodes beside a partner's on one database.
FIXTURE = f"""
CREATE (i:Indicator:{LABEL} {{value: '203.0.113.7', edgeguard_managed: true}})
CREATE (m:Malware:{LABEL} {{name: 'emotet', edgeguard_managed: true}})
CREATE (v:Vulnerability:{LABEL} {{cve_id: 'CVE-2024-0001', edgeguard_managed: true}})
CREATE (c:CVE:{LABEL} {{cve_id: 'CVE-2024-0001', edgeguard_managed: true}})
CREATE (pv:Vulnerability:{LABEL} {{cve_id: 'CVE-2023-9999', status: 'open'}})
CREATE (pc:CVE:{LABEL} {{cve_id: 'CVE-2023-9999', edgeguard_enriched: true}})
CREATE (h:Host:{LABEL} {{hostname: 'srv-01'}})
CREATE (f:Indicator:{LABEL} {{value: '198.51.100.1', edgeguard_managed: false}})
CREATE (s:Indicator:{LABEL} {{value: '198.51.100.2', edgeguard_managed: 'true'}})
CREATE (i)-[:INDICATES {{edgeguard_managed: true}}]->(m)
CREATE (v)-[:REFERS_TO {{edgeguard_managed: true}}]->(c)
CREATE (i)-[:EXPLOITS {{edgeguard_managed: true}}]->(pc)
CREATE (h)-[:HAS_VULNERABILITY]->(pv)
CREATE (pv)-[:REFERS_TO {{edgeguard_managed: true}}]->(pc)
"""

PARTNER = {
    ("Vulnerability", "CVE-2023-9999"),
    ("CVE", "CVE-2023-9999"),
    ("Host", "srv-01"),
    ("Indicator", "198.51.100.1"),
    ("Indicator", "198.51.100.2"),
}
EDGEGUARD = {
    ("Indicator", "203.0.113.7"),
    ("Malware", "emotet"),
    ("Vulnerability", "CVE-2024-0001"),
    ("CVE", "CVE-2024-0001"),
}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver, tmp_path, monkeypatch):
    monkeypatch.setenv(destructive_ops_audit.AUDIT_PATH_ENV, str(tmp_path / "destructive_ops.jsonl"))
    monkeypatch.setattr(baseline_checkpoint, "clear_checkpoint", lambda **kw: None)
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n").consume()
        session.run(FIXTURE).consume()
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _nodes(raw_driver) -> set:
    with raw_driver.session() as session:
        rows = session.run(
            f"MATCH (n:{LABEL}) RETURN [l IN labels(n) WHERE l <> '{LABEL}'][0] AS label, "
            "coalesce(n.value, n.name, n.cve_id, n.hostname) AS key"
        ).data()
    return {(r["label"], r["key"]) for r in rows}


def _relationship_types(raw_driver) -> list:
    with raw_driver.session() as session:
        rows = session.run(f"MATCH (:{LABEL})-[r]->(:{LABEL}) RETURN type(r) AS t ORDER BY t").data()
    return [r["t"] for r in rows]


def test_the_default_run_keeps_the_partner_data(raw_driver, client):
    assert _nodes(raw_driver) == PARTNER | EDGEGUARD

    assert clear_neo4j.clear(client, recreate_sources=False) == 0

    assert _nodes(raw_driver) == PARTNER
    assert _relationship_types(raw_driver) == ["HAS_VULNERABILITY", "REFERS_TO"]


def test_label_deletes_only_the_edgeguard_nodes_of_that_label(raw_driver, client):
    assert clear_neo4j.clear(client, label="Vulnerability", recreate_sources=False) == 0

    assert _nodes(raw_driver) == (PARTNER | EDGEGUARD) - {("Vulnerability", "CVE-2024-0001")}
    assert _relationship_types(raw_driver) == ["EXPLOITS", "HAS_VULNERABILITY", "INDICATES", "REFERS_TO"]


def test_the_preview_counts_match_the_database(raw_driver, client):
    assert client.count_edgeguard_managed() == {"managed": 4, "others": 5, "enriched": 1}
    assert client.count_edgeguard_managed("Vulnerability") == {"managed": 1, "others": 1, "enriched": 0}
