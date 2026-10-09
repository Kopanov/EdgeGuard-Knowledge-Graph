"""Cross-item relationship building must not mix entities from different source reports.

2026-10 (fresh-baseline PR): pairing is scoped by the OTX pulse id
(``item["pulse_id"]``), not by MISP event membership. Items from two
different pulses — even inside one event — are never linked, and items
without a pulse id are never paired at all.
"""

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


def test_cross_item_pairs_only_within_one_pulse_not_across_the_pool(syncer: MISPToNeo4jSync):
    """Two pulses, each with one malware and one actor → 2 ATTRIBUTED_TO total, not 2×2.

    Pre-2026-10 the builder paired everything in the same MISP event, so a
    merged pool produced the cross product. Post-change the pulse id is the
    only pairing scope: merging the pool changes nothing."""
    mal_a = {"type": "malware", "name": "MalA", "tag": "misp", "pulse_id": "pulse-A"}
    act_a = {"type": "actor", "name": "ActorA", "tag": "misp", "pulse_id": "pulse-A"}
    mal_b = {"type": "malware", "name": "MalB", "tag": "misp", "pulse_id": "pulse-B"}
    act_b = {"type": "actor", "name": "ActorB", "tag": "misp", "pulse_id": "pulse-B"}

    ev1 = _dedupe_parsed_items([mal_a, act_a])
    ev2 = _dedupe_parsed_items([mal_b, act_b])
    per_event = len(syncer._build_cross_item_relationships(ev1)) + len(syncer._build_cross_item_relationships(ev2))

    merged = _dedupe_parsed_items([mal_a, act_a, mal_b, act_b])
    merged_rels = syncer._build_cross_item_relationships(merged)

    assert per_event == 2
    assert len(merged_rels) == 2
    pairs = {(r["from_key"]["name"], r["to_key"]["name"]) for r in merged_rels}
    assert pairs == {("MalA", "ActorA"), ("MalB", "ActorB")}, "no cross-pulse ATTRIBUTED_TO may be emitted"


def test_actor_and_technique_in_one_event_no_longer_pair(syncer: MISPToNeo4jSync):
    """EMPLOYS_TECHNIQUE from co-membership is gone — those edges now come
    from the node's ``uses_techniques`` / ``reported_techniques`` lists in
    ``build_relationships`` (Q5 / Q5b)."""
    actor = {"type": "actor", "name": "ActorA", "tag": "misp", "pulse_id": "pulse-A"}
    tech = {"type": "technique", "mitre_id": "T1059", "tag": "misp", "name": "Scripting", "pulse_id": "pulse-A"}
    rels = syncer._build_cross_item_relationships(_dedupe_parsed_items([actor, tech]))
    assert rels == []


def test_dedupe_parsed_items_keeps_one_row_per_key(syncer: MISPToNeo4jSync):
    dup_indicators = [
        {"indicator_type": "ipv4", "value": "10.0.0.1", "tag": "misp", "pulse_id": "pulse-A"},
        {"indicator_type": "ipv4", "value": "10.0.0.1", "tag": "misp", "pulse_id": "pulse-A"},
    ]
    u = _dedupe_parsed_items(dup_indicators)
    assert len(u) == 1
    # Single indicator, no malware in the pulse → no pairwise
    # INDICATES / EMPLOYS_TECHNIQUE / ATTRIBUTED_TO
    cross = syncer._build_cross_item_relationships(u)
    assert not any(r.get("rel_type") in ("INDICATES", "EMPLOYS_TECHNIQUE", "ATTRIBUTED_TO") for r in cross)
