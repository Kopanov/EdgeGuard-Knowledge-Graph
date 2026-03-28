"""Chunked Neo4j sync (OOM mitigation) in run_misp_to_neo4j.sync_to_neo4j."""

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from run_misp_to_neo4j import (  # noqa: E402
    NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
    MISPToNeo4jSync,
    _neo4j_sync_item_sort_rank,
    _parse_neo4j_sync_chunk_size,
)


def test_neo4j_sync_item_sort_rank_order():
    tactic = {"type": "tactic", "name": "TA"}
    tech = {"type": "technique", "mitre_id": "T1059"}
    ind = {"indicator_type": "ipv4", "value": "1.1.1.1"}
    assert _neo4j_sync_item_sort_rank(tactic) < _neo4j_sync_item_sort_rank(tech)
    assert _neo4j_sync_item_sort_rank(tech) < _neo4j_sync_item_sort_rank(ind)


def test_sync_to_neo4j_respects_chunk_size(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE", "400")
    neo = MagicMock()
    neo.merge_indicators_batch.side_effect = lambda items, source_id="misp": (len(items), 0)

    syncer = MISPToNeo4jSync(neo4j_client=neo)
    items = [
        {
            "indicator_type": "ipv4",
            "value": f"10.0.0.{i}",
            "tag": "misp",
            "relationships": [{"rel_type": "INDICATES", "dummy": i}],
        }
        for i in range(900)
    ]

    ok, err, rels = syncer.sync_to_neo4j(items)
    assert rels == []
    assert ok == 900
    assert err == 0
    assert neo.merge_indicators_batch.call_count == 3

    for it in items:
        assert "relationships" not in it


def test_parse_neo4j_sync_chunk_size_explicit_single_pass():
    assert _parse_neo4j_sync_chunk_size("", 100) == (
        NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
        str(NEO4J_SYNC_CHUNK_SIZE_DEFAULT),
        False,
    )
    assert _parse_neo4j_sync_chunk_size("all", 50) == (50, "all", True)
    assert _parse_neo4j_sync_chunk_size("ALL", 50) == (50, "ALL", True)
    assert _parse_neo4j_sync_chunk_size("0", 50) == (50, "0", True)
    sz, lab, sp = _parse_neo4j_sync_chunk_size("500", 10_000)
    assert sz == 500 and sp is False and lab == "500"
    sz, lab, sp = _parse_neo4j_sync_chunk_size("not-a-number", 100)
    assert sz == NEO4J_SYNC_CHUNK_SIZE_DEFAULT and sp is False
    assert "invalid" in lab

    # Leading zeros: int path → 0 → same as single-pass
    sz0, _, sp0 = _parse_neo4j_sync_chunk_size("00", 10)
    assert sz0 == 10 and sp0 is True

    sz_all, _, sp_all = _parse_neo4j_sync_chunk_size("  ALL  ", 5)
    assert sz_all == 5 and sp_all is True


def test_sync_to_neo4j_single_pass_all(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE", "all")
    neo = MagicMock()
    neo.merge_indicators_batch.side_effect = lambda items, source_id="misp": (len(items), 0)

    syncer = MISPToNeo4jSync(neo4j_client=neo)
    items = [
        {
            "indicator_type": "ipv4",
            "value": f"10.0.1.{i}",
            "tag": "misp",
            "relationships": [],
        }
        for i in range(900)
    ]

    ok, err, rels = syncer.sync_to_neo4j(items)
    assert ok == 900 and err == 0 and rels == []
    assert neo.merge_indicators_batch.call_count == 1


def test_sync_to_neo4j_single_pass_zero(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE", "0")
    neo = MagicMock()
    neo.merge_indicators_batch.side_effect = lambda items, source_id="misp": (len(items), 0)

    syncer = MISPToNeo4jSync(neo4j_client=neo)
    items = [
        {
            "indicator_type": "ipv4",
            "value": f"10.0.2.{i}",
            "tag": "misp",
            "relationships": [],
        }
        for i in range(100)
    ]

    syncer.sync_to_neo4j(items)
    assert neo.merge_indicators_batch.call_count == 1


def test_create_relationships_respects_rel_batch_size(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_REL_BATCH_SIZE", "3")
    neo = MagicMock()
    neo.create_misp_relationships_batch.side_effect = lambda chunk, source_id="misp": len(chunk)

    syncer = MISPToNeo4jSync(neo4j_client=neo)
    rels = [
        {
            "rel_type": "USES",
            "from_key": {"name": f"A{i}"},
            "to_key": {"mitre_id": f"T{i}"},
        }
        for i in range(7)
    ]
    n = syncer._create_relationships(rels, "misp")
    assert n == 7
    assert neo.create_misp_relationships_batch.call_count == 3
