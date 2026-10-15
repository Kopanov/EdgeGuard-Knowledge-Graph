"""The node count query of the ``edgeguard_neo4j_nodes`` gauge on a real Neo4j (2026-10).

``Neo4jClient.count_nodes_by_label`` must return a row for every label, also for a label without
nodes (Alert in the compose deployment, Campaign before the first enrichment). Written with the label
as a literal next to ``count(n)`` in one RETURN, the literal is a grouping key and Cypher returns no
row for an empty label; the client then raised and no count was ever recorded. A mocked session only
shows what its author assumed, so this module runs the query on a database. Same guards as
``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only
nodes labelled ``EdgeGuardIT``, refuses any other node.
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

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

# Two indicators, one malware, one source; no Alert and no Campaign.
FIXTURE = f"""
CREATE (:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '203.0.113.7', uuid: 'u-i1'}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'domain', value: 'example.invalid', uuid: 'u-i2'}})
CREATE (:Malware:{LABEL} {{name: 'emotet', uuid: 'u-m'}})
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
"""


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


def test_every_label_has_a_count_and_an_empty_label_counts_zero(client):
    counts = client.count_nodes_by_label()

    assert set(counts) == set(neo4j_client.NODE_COUNT_LABELS)
    assert (counts["Indicator"], counts["Malware"], counts["Source"]) == (2, 1, 1)
    assert counts["Alert"] == 0 and counts["Campaign"] == 0
    assert sum(counts.values()) == 4


def test_the_former_query_shape_returns_no_row_for_an_empty_label(raw_driver, client):
    """Pins the Cypher behaviour the query is written around (a grouping key on empty input)."""
    with raw_driver.session() as session:
        former = list(session.run("MATCH (n:Alert) RETURN 'Alert' AS label, count(n) AS count"))
        current = [
            r.data() for r in session.run("MATCH (n:Alert) WITH count(n) AS c RETURN 'Alert' AS label, c AS count")
        ]
    assert former == []
    assert current == [{"label": "Alert", "count": 0}]
