"""Provenance tests for MISP attribute UUID and event-id traceability.

Covers the 2026-04 fixes that:
  - Populate ``misp_attribute_id`` on every parsed item (Indicator,
    Vulnerability, ThreatActor, Malware, Technique, Tactic, Tool) from
    ``attr.uuid`` (the stable cross-instance identifier, not ``attr.id``).
  - Stamp ``misp_event_id`` on every relationship dict produced by
    ``parse_attribute`` so the downstream batch merger can accumulate
    ``r.misp_event_ids[]`` on the resulting Neo4j edge.
  - Stamp ``misp_event_id`` on every relationship produced by
    ``_build_cross_item_relationships``.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Force a clean import path — the parse_attribute path is cached aggressively
# in some other test modules and we want the post-fix module here.
for _mod in ("neo4j_client", "run_misp_to_neo4j"):
    if _mod in sys.modules:
        del sys.modules[_mod]

from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


# ---------------------------------------------------------------------------
# parse_attribute → item dicts carry misp_attribute_id from attr.uuid
# ---------------------------------------------------------------------------


def test_indicator_item_carries_attribute_uuid(syncer: MISPToNeo4jSync):
    attr = {
        "type": "ip-dst",
        "value": "203.0.113.5",
        "uuid": "11111111-aaaa-bbbb-cccc-222222222222",
        "Tag": [],
    }
    full_event = {"id": 42, "info": "report", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == "11111111-aaaa-bbbb-cccc-222222222222"
    assert item["misp_event_id"] == "42"


def test_vulnerability_item_carries_attribute_uuid(syncer: MISPToNeo4jSync):
    attr = {
        "type": "vulnerability",
        "value": "CVE-2025-99999",
        "uuid": "33333333-aaaa-bbbb-cccc-444444444444",
        "Tag": [],
    }
    full_event = {"id": 7, "info": "kev", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == "33333333-aaaa-bbbb-cccc-444444444444"


def test_threat_actor_item_carries_attribute_uuid(syncer: MISPToNeo4jSync):
    attr = {
        "type": "threat-actor",
        "value": "APT-Test",
        "uuid": "55555555-aaaa-bbbb-cccc-666666666666",
        "Tag": [],
    }
    full_event = {"id": 9, "info": "actor", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == "55555555-aaaa-bbbb-cccc-666666666666"


def test_malware_item_carries_attribute_uuid(syncer: MISPToNeo4jSync):
    attr = {
        "type": "malware-type",
        "value": "Emotet",
        "uuid": "77777777-aaaa-bbbb-cccc-888888888888",
        "Tag": [],
    }
    full_event = {"id": 11, "info": "malware", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == "77777777-aaaa-bbbb-cccc-888888888888"


def test_technique_item_carries_attribute_uuid(syncer: MISPToNeo4jSync):
    attr = {
        "type": "text",
        "value": "T1059: Command and Scripting Interpreter",
        "uuid": "99999999-aaaa-bbbb-cccc-aaaaaaaaaaaa",
        "Tag": [],
    }
    full_event = {"id": 13, "info": "ttp", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == "99999999-aaaa-bbbb-cccc-aaaaaaaaaaaa"


def test_missing_uuid_falls_back_to_empty_string(syncer: MISPToNeo4jSync):
    attr = {"type": "ip-dst", "value": "198.51.100.10", "Tag": []}  # no uuid
    full_event = {"id": 99, "info": "x", "date": "2026-04-01", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["misp_attribute_id"] == ""  # empty, not None — merger skips append


# ---------------------------------------------------------------------------
# parse_attribute → relationships carry misp_event_id
# ---------------------------------------------------------------------------


def test_parse_attribute_indicator_targets_carries_event_id(syncer: MISPToNeo4jSync):
    """An indicator with a sector tag emits a TARGETS rel stamped with event id."""
    attr = {
        "type": "ip-dst",
        "value": "203.0.113.99",
        "uuid": "10000000-0000-0000-0000-000000000001",
        "Tag": [{"name": "target-sector:finance"}, {"name": "zone:finance"}],
    }
    full_event = {"id": 5150, "info": "x", "date": "2026-04-01", "Tag": []}
    _item, rels = syncer.parse_attribute(attr, full_event)
    targets = [r for r in rels if r.get("rel_type") == "TARGETS"]
    assert targets, "expected at least one TARGETS rel"
    for r in targets:
        assert r.get("misp_event_id") == "5150"


def test_parse_attribute_indicator_exploits_carries_event_id(syncer: MISPToNeo4jSync):
    """An indicator tagged with a CVE emits an EXPLOITS rel stamped with event id."""
    attr = {
        "type": "ip-dst",
        "value": "203.0.113.50",
        "uuid": "10000000-0000-0000-0000-000000000002",
        "Tag": [{"name": "exploits-cve:CVE-2025-1111"}],
    }
    full_event = {"id": 6260, "info": "x", "date": "2026-04-01", "Tag": []}
    _item, rels = syncer.parse_attribute(attr, full_event)
    exploits = [r for r in rels if r.get("rel_type") == "EXPLOITS"]
    assert exploits, "expected an EXPLOITS rel"
    for r in exploits:
        assert r.get("misp_event_id") == "6260"


# ---------------------------------------------------------------------------
# _build_cross_item_relationships → all rels carry misp_event_id
# ---------------------------------------------------------------------------


def test_cross_item_rels_inherit_event_id(syncer: MISPToNeo4jSync):
    """Cross-item edges (single-event contract) should be stamped with the
    common event id pulled from the items themselves."""
    items = [
        {
            "type": "actor",
            "name": "APT-Test",
            "misp_event_id": "777",
        },
        {
            "type": "technique",
            "mitre_id": "T1059",
            "misp_event_id": "777",
        },
        {
            "type": "malware",
            "name": "Emotet",
            "misp_event_id": "777",
        },
        {
            "indicator_type": "ipv4",
            "value": "203.0.113.5",
            "type": "indicator",
            "misp_event_id": "777",
        },
    ]
    rels = syncer._build_cross_item_relationships(items)
    assert rels, "expected cross-item relationships"
    for r in rels:
        assert r.get("misp_event_id") == "777", (
            f"rel_type={r.get('rel_type')} missing event id stamp"
        )


def test_cross_item_rels_handle_missing_event_id(syncer: MISPToNeo4jSync):
    """When items carry no event id (legacy code path) the rels still build,
    just with an empty stamp — the merger's CASE expression will skip the
    array append."""
    items = [
        {"type": "actor", "name": "APT-X"},
        {"type": "technique", "mitre_id": "T1078"},
    ]
    rels = syncer._build_cross_item_relationships(items)
    assert rels, "expected at least an EMPLOYS_TECHNIQUE rel"
    for r in rels:
        assert r.get("misp_event_id") == ""
