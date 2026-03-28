"""
Align ``_ALLOWED_NODE_LABELS`` with ResilMesh canonical CSVs (when present).

CSV location (monorepo layout): ``ResilMesh/data model - general/Neo4j/``.
If those files are missing (e.g. EdgeGuard-only clone), tests are skipped.
"""

from __future__ import annotations

import csv
import io
import os
import re
import sys
from pathlib import Path

import pytest

# See tests/test_neo4j_client_guards.py — test_graphql_api stubs neo4j_client globally.
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
if "neo4j_client" in sys.modules:
    del sys.modules["neo4j_client"]

from neo4j_client import _ALLOWED_NODE_LABELS, _validate_rel_type

# tests/ -> EdgeGuard-Knowledge-Graph/ -> ResilMesh/
_RESILMESH_ROOT = Path(__file__).resolve().parents[2]
_NODES_CSV = _RESILMESH_ROOT / "data model - general" / "Neo4j" / "neo4j_nodes_properties.csv"
_RELS_CSV = _RESILMESH_ROOT / "data model - general" / "Neo4j" / "neo4j_relationships_properties.csv"

_BRACKET_LABEL = re.compile(r"^\[([^\]]+)\]")


def _skip_if_no_csv(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"Model CSV not found (expected ResilMesh layout): {path}")


def _node_labels_from_nodes_csv(path: Path) -> set[str]:
    """First column entries like ``[CVE]``."""
    text = path.read_text(encoding="utf-8")
    labels: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Type of Node"):
            continue
        m = _BRACKET_LABEL.match(line)
        if m:
            labels.add(m.group(1))
    return labels


def _labels_and_rels_from_relationships_csv(path: Path) -> tuple[set[str], set[str]]:
    """
    Parse Head [Label], REL, Tail [Label] rows.
    Uses csv module so commas inside quoted JSON in the last column are safe.
    """
    raw = path.read_text(encoding="utf-8")
    reader = csv.reader(io.StringIO(raw))
    header = next(reader, None)
    if not header or "Head" not in "".join(header):
        return set(), set()

    node_labels: set[str] = set()
    rel_types: set[str] = set()

    for row in reader:
        if len(row) < 3:
            continue
        head, rel, tail = row[0].strip(), row[1].strip(), row[2].strip()
        hm = _BRACKET_LABEL.match(head)
        tm = _BRACKET_LABEL.match(tail)
        if hm:
            node_labels.add(hm.group(1))
        if tm:
            node_labels.add(tm.group(1))
        if rel and not rel.startswith("["):
            rel_types.add(rel)
    return node_labels, rel_types


def test_nodes_csv_labels_are_allowlisted():
    _skip_if_no_csv(_NODES_CSV)
    from_csv = _node_labels_from_nodes_csv(_NODES_CSV)
    assert from_csv, f"No labels parsed from {_NODES_CSV}"
    missing = from_csv - _ALLOWED_NODE_LABELS
    assert not missing, f"Add to _ALLOWED_NODE_LABELS in neo4j_client.py (or fix CSV): {sorted(missing)}"


def test_relationships_csv_endpoints_are_allowlisted():
    _skip_if_no_csv(_RELS_CSV)
    nodes_from_rels, rel_types = _labels_and_rels_from_relationships_csv(_RELS_CSV)
    assert nodes_from_rels, f"No endpoint labels parsed from {_RELS_CSV}"
    missing = nodes_from_rels - _ALLOWED_NODE_LABELS
    assert not missing, f"Relationship CSV references node labels not in _ALLOWED_NODE_LABELS: {sorted(missing)}"


def test_relationships_csv_rel_types_are_safe_identifiers():
    _skip_if_no_csv(_RELS_CSV)
    _, rel_types = _labels_and_rels_from_relationships_csv(_RELS_CSV)
    assert rel_types, "No relationship types parsed"
    for rt in sorted(rel_types):
        _validate_rel_type(rt)


def test_relationship_endpoints_listed_in_nodes_csv_doc():
    """
    Every node type used as head/tail in ``neo4j_relationships_properties.csv``
    should have a row in ``neo4j_nodes_properties.csv`` (documentation parity).
    """
    _skip_if_no_csv(_NODES_CSV)
    _skip_if_no_csv(_RELS_CSV)
    nodes_file = _node_labels_from_nodes_csv(_NODES_CSV)
    rel_endpoints, _ = _labels_and_rels_from_relationships_csv(_RELS_CSV)
    only_in_rels = rel_endpoints - nodes_file
    assert not only_in_rels, (
        "Add rows to neo4j_nodes_properties.csv for types referenced in "
        f"neo4j_relationships_properties.csv: {sorted(only_in_rels)}"
    )
