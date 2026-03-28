"""Regression: Cypher injection guards must allow CVSS sub-node labels and HAS_CVSS_* rel types."""

from __future__ import annotations

import os
import sys

import pytest

# test_graphql_api.py registers a MagicMock as sys.modules["neo4j_client"] (import order).
# Drop it so this module always binds to the real neo4j_client guards.
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if "neo4j_client" in sys.modules:
    del sys.modules["neo4j_client"]

from neo4j_client import (
    _ALLOWED_NODE_LABELS,
    _validate_label,
    _validate_rel_type,
    nonempty_graph_string,
    normalize_cve_id_for_graph,
    resolve_vulnerability_cve_id,
)

# Every primary Neo4j node label used in neo4j_client MERGE/MATCH or merge_node paths
# must appear in _ALLOWED_NODE_LABELS (regression guard when adding topology / intel types).
_REQUIRED_NODE_LABELS = frozenset(
    {
        "Alert",
        "Application",
        "Campaign",
        "CVE",
        "CVSSv2",
        "CVSSv30",
        "CVSSv31",
        "CVSSv40",
        "Component",
        "Device",
        "Host",
        "IP",
        "Indicator",
        "Malware",
        "Mission",
        "MissionDependency",
        "NetworkService",
        "Node",
        "OrganizationUnit",
        "Role",
        "Sector",
        "SoftwareVersion",
        "Source",
        "Subnet",
        "Tactic",
        "Technique",
        "ThreatActor",
        "Tool",
        "User",
        "Vulnerability",
    }
)


def test_validate_label_allows_cvss_subnodes():
    for lbl in ("CVSSv2", "CVSSv30", "CVSSv31", "CVSSv40"):
        assert _validate_label(lbl) == lbl


def test_validate_label_rejects_unknown():
    with pytest.raises(ValueError, match="not an allowed node label"):
        _validate_label("EvilLabel")


def test_validate_rel_type_allows_has_cvss():
    assert _validate_rel_type("HAS_CVSS_v31") == "HAS_CVSS_v31"


def test_validate_rel_type_rejects_injection():
    with pytest.raises(ValueError, match="relationship type"):
        _validate_rel_type("FOO BAR")


def test_allowlist_covers_all_neo4j_client_node_labels():
    missing = _REQUIRED_NODE_LABELS - _ALLOWED_NODE_LABELS
    assert not missing, f"_ALLOWED_NODE_LABELS missing: {sorted(missing)}"


def test_resolve_vulnerability_cve_id_prefers_explicit_field():
    assert (
        resolve_vulnerability_cve_id({"type": "vulnerability", "value": "CVE-2099-1", "cve_id": "CVE-2025-32432"})
        == "CVE-2025-32432"
    )


def test_resolve_vulnerability_cve_id_from_misp_value():
    assert resolve_vulnerability_cve_id({"type": "vulnerability", "value": "cve-2025-32432"}) == "CVE-2025-32432"


def test_resolve_vulnerability_cve_id_requires_type_for_value_fallback():
    assert resolve_vulnerability_cve_id({"value": "CVE-2025-32432"}) is None


def test_normalize_cve_id_for_graph_rejects_blank():
    assert normalize_cve_id_for_graph(None) is None
    assert normalize_cve_id_for_graph("") is None
    assert normalize_cve_id_for_graph("   ") is None


def test_normalize_cve_id_for_graph_uppercases():
    assert normalize_cve_id_for_graph(" cve-2024-1 ") == "CVE-2024-1"


def test_nonempty_graph_string_rejects_blank():
    assert nonempty_graph_string(None) is None
    assert nonempty_graph_string("") is None
    assert nonempty_graph_string("  \t  ") is None


def test_nonempty_graph_string_trims():
    assert nonempty_graph_string("  foo  ") == "foo"
