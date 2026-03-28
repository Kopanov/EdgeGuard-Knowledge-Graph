"""Zone / multizone resolution on MISP attributes (parse_attribute)."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

if "neo4j_client" in sys.modules:
    del sys.modules["neo4j_client"]
if "run_misp_to_neo4j" in sys.modules:
    del sys.modules["run_misp_to_neo4j"]

from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402


@pytest.fixture
def syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


def test_attribute_zone_tags_override_event_zones(syncer: MISPToNeo4jSync):
    attr = {
        "type": "domain",
        "value": "evil.example",
        "Tag": [{"name": "zone:healthcare"}],
    }
    full_event = {
        "id": 1,
        "info": "EdgeGuard-FINANCE-misp-2024-01-01",
        "date": "2024-01-01",
        "Tag": [{"name": "zone:finance"}, {"name": "zone:energy"}],
    }
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["zone"] == ["healthcare"]


def test_event_level_multizone_when_attr_has_no_zone(syncer: MISPToNeo4jSync):
    attr = {
        "type": "ip-dst",
        "value": "192.0.2.10",
        "Tag": [],
    }
    full_event = {
        "id": 2,
        "info": "Some report",
        "date": "2024-01-02",
        "Tag": [{"name": "zone:finance"}, {"name": "zone:healthcare"}],
    }
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["zone"] == ["finance", "healthcare"]


def test_global_fallback_when_only_global_tags(syncer: MISPToNeo4jSync):
    attr = {"type": "domain", "value": "x.test", "Tag": [{"name": "zone:global"}]}
    full_event = {"id": 3, "info": "No sector", "date": "2024-01-03", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["zone"] == ["global"]


def test_global_plus_specific_on_attribute_drops_global(syncer: MISPToNeo4jSync):
    attr = {
        "type": "domain",
        "value": "mixed.example",
        "Tag": [{"name": "zone:global"}, {"name": "zone:energy"}],
    }
    full_event = {"id": 4, "info": "EdgeGuard-GLOBAL-nvd-2024-01-04", "date": "2024-01-04", "Tag": []}
    item, _rels = syncer.parse_attribute(attr, full_event)
    assert item is not None
    assert item["zone"] == ["energy"]
