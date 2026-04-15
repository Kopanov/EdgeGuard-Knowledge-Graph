"""Cross-item relationship building must not mix entities from different MISP events."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# test_graphql_api may register a MagicMock as sys.modules["neo4j_client"] — drop it.
if "neo4j_client" in sys.modules:
    del sys.modules["neo4j_client"]
if "run_misp_to_neo4j" in sys.modules:
    del sys.modules["run_misp_to_neo4j"]

from run_misp_to_neo4j import (  # noqa: E402
    MISPToNeo4jSync,
    _dedupe_parsed_items,
)


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


def test_per_event_cross_item_fewer_edges_than_global_pool(syncer: MISPToNeo4jSync):
    """Two actors and two techniques in separate events → 2 EMPLOYS_TECHNIQUE total, not 2×2."""
    actor_a = {"type": "actor", "name": "ActorA", "tag": "misp"}
    actor_b = {"type": "actor", "name": "ActorB", "tag": "misp"}
    t1 = {"type": "technique", "mitre_id": "T1059", "tag": "misp", "name": "Scripting"}
    t2 = {"type": "technique", "mitre_id": "T1566", "tag": "misp", "name": "Phishing"}

    ev1 = _dedupe_parsed_items([actor_a, t1])
    ev2 = _dedupe_parsed_items([actor_b, t2])
    per_event = len(syncer._build_cross_item_relationships(ev1)) + len(syncer._build_cross_item_relationships(ev2))

    merged = _dedupe_parsed_items([actor_a, actor_b, t1, t2])
    global_count = len(syncer._build_cross_item_relationships(merged))

    assert per_event == 2
    assert global_count == 4
    assert global_count > per_event


def test_dedupe_parsed_items_keeps_one_row_per_key(syncer: MISPToNeo4jSync):
    dup_indicators = [
        {"indicator_type": "ipv4", "value": "10.0.0.1", "tag": "misp"},
        {"indicator_type": "ipv4", "value": "10.0.0.1", "tag": "misp"},
    ]
    u = _dedupe_parsed_items(dup_indicators)
    assert len(u) == 1
    # Single indicator, no malware/vuln in pool → no pairwise
    # INDICATES / EMPLOYS_TECHNIQUE / ATTRIBUTED_TO
    cross = syncer._build_cross_item_relationships(u)
    assert not any(r.get("rel_type") in ("INDICATES", "EMPLOYS_TECHNIQUE", "ATTRIBUTED_TO") for r in cross)
