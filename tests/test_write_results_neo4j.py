"""A write that fails while the server executes it, on a real Neo4j (2026-10-16).

The server reports such an error with the statement's result, not when ``session.run`` returns
(``tests/test_neo4j_write_results.py`` shows it with the real driver against a scripted server).
Here a source timestamp the server cannot parse (``datetime('not-a-date')``, evaluated per row while
the statement runs) makes the Indicator batch MERGE and the ``SOURCED_FROM`` upsert of a single-item
merge fail on a database: the batch's rows must count as errors and the merge must return False.
Before 2026-10-16 both reported success, and nothing had been written. Same guards as
``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``, writes only nodes
labelled ``EdgeGuardIT``, refuses any other node.
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

VALUES = ("203.0.113.31", "203.0.113.32", "203.0.113.33")
FIXTURE = f"""
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Malware:{LABEL} {{name: 'emotet', uuid: 'u-m', edgeguard_managed: true}})
""" + "\n".join(
    f"CREATE (:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '{v}', uuid: 'u-{v}', edgeguard_managed: true}})"
    for v in VALUES
)
SOURCE_LINKS = (
    f"MATCH (n:{LABEL})-[r:SOURCED_FROM]->(:Source:{LABEL} {{source_id: 'alienvault_otx'}}) "
    "RETURN labels(n) AS labels, count(r) AS links"
)


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver, monkeypatch):
    monkeypatch.setattr(neo4j_client, "query_pause", lambda *_a, **_k: None)
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n").consume()
        session.run(FIXTURE).consume()
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _links(raw_driver, label: str) -> int:
    with raw_driver.session() as session:
        return sum(r["links"] for r in session.run(SOURCE_LINKS) if label in r["labels"])


def _indicators(first_seen: str):
    return [
        {"indicator_type": "ipv4", "value": v, "tag": "alienvault_otx", "zone": ["global"], "first_seen_at_source": t}
        for v, t in zip(VALUES, ("2026-10-01T00:00:00Z", first_seen, "2026-10-01T00:00:00Z"), strict=True)
    ]


class TestBatchMerge:
    def test_a_valid_batch_is_written(self, client, raw_driver):
        assert client.merge_indicators_batch(_indicators("2026-10-01T00:00:00Z"), source_id="alienvault_otx") == (3, 0)
        assert _links(raw_driver, "Indicator") == 3

    def test_a_batch_the_server_fails_counts_its_rows_as_errors(self, client, raw_driver):
        assert client.merge_indicators_batch(_indicators("not-a-date"), source_id="alienvault_otx") == (0, 3)
        assert _links(raw_driver, "Indicator") == 0, "the statement rolled back as a whole"


class TestSingleItemMerge:
    def test_a_valid_merge_links_the_source(self, client, raw_driver):
        ok = client.merge_malware(
            {"name": "emotet", "tag": "alienvault_otx", "first_seen_at_source": "2026-10-01T00:00:00Z"},
            source_id="alienvault_otx",
        )
        assert ok is True
        assert _links(raw_driver, "Malware") == 1

    def test_a_source_link_the_server_fails_returns_false(self, client, raw_driver):
        ok = client.merge_malware(
            {"name": "emotet", "tag": "alienvault_otx", "first_seen_at_source": "not-a-date"},
            source_id="alienvault_otx",
        )
        assert ok is False
        assert _links(raw_driver, "Malware") == 0
