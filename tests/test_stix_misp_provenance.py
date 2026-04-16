"""Tests for the 2026-04 STIX exporter MISP-provenance attachment.

The exporter now adds two custom properties to every SDO that originates
from a Neo4j node carrying MISP traceability:

  - ``x_edgeguard_misp_event_ids``   (union of array + scalar)
  - ``x_edgeguard_misp_attribute_ids`` (union of array + scalar)

These mirror the existing ``x_edgeguard_zones`` pattern: omitted entirely
when the source node has no values; never None when present.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

from stix_exporter import StixExporter, _attach_misp_provenance

# ---------------------------------------------------------------------------
# Fake Neo4j harness (same shape as test_stix_exporter.py)
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)


class _FakeSession:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, _cypher: str, **_params: Any) -> _FakeResult:
        return _FakeResult(self._rows)


class _FakeDriver:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._session = _FakeSession(rows)

    def session(self, **_kwargs: Any):
        return self._session


def _mk_client(rows: List[Dict[str, Any]]) -> Any:
    client = MagicMock()
    client.driver = _FakeDriver(rows)
    client.is_connected.return_value = True
    return client


# ---------------------------------------------------------------------------
# Direct helper tests
# ---------------------------------------------------------------------------


def test_attach_misp_provenance_emits_array_when_array_present():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        "misp_event_ids": ["1001", "1002"],
        "misp_attribute_ids": ["uuid-a", "uuid-b"],
    }
    _attach_misp_provenance(sdo, props)
    assert sdo["x_edgeguard_misp_event_ids"] == ["1001", "1002"]
    assert sdo["x_edgeguard_misp_attribute_ids"] == ["uuid-a", "uuid-b"]


def test_attach_misp_provenance_unions_array_and_scalar():
    """Scalar should be included even when an array is present, in case the
    scalar (first-seen) was not yet copied into the array."""
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        "misp_event_id": "scalar-only",
        "misp_event_ids": ["array-1"],
        "misp_attribute_id": "scalar-attr",
        "misp_attribute_ids": ["array-attr"],
    }
    _attach_misp_provenance(sdo, props)
    assert "scalar-only" in sdo["x_edgeguard_misp_event_ids"]
    assert "array-1" in sdo["x_edgeguard_misp_event_ids"]
    assert "scalar-attr" in sdo["x_edgeguard_misp_attribute_ids"]
    assert "array-attr" in sdo["x_edgeguard_misp_attribute_ids"]


def test_attach_misp_provenance_dedupes_overlap():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        "misp_event_id": "1001",
        "misp_event_ids": ["1001", "1002"],
    }
    _attach_misp_provenance(sdo, props)
    assert sdo["x_edgeguard_misp_event_ids"] == ["1001", "1002"]


def test_attach_misp_provenance_omits_field_when_empty():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    _attach_misp_provenance(sdo, {})
    assert "x_edgeguard_misp_event_ids" not in sdo
    assert "x_edgeguard_misp_attribute_ids" not in sdo


def test_attach_misp_provenance_handles_scalar_only():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {"misp_event_id": "777"}
    _attach_misp_provenance(sdo, props)
    assert sdo["x_edgeguard_misp_event_ids"] == ["777"]


# ---------------------------------------------------------------------------
# Integration test through the full exporter
# ---------------------------------------------------------------------------


def test_export_indicator_emits_misp_provenance_on_seed_sdo():
    rows = [
        {
            "seed": {
                "value": "203.0.113.5",
                "indicator_type": "ipv4",
                "misp_event_id": "5000",
                "misp_event_ids": ["5000", "5001"],
                "misp_attribute_id": "uuid-aaa",
                "misp_attribute_ids": ["uuid-aaa", "uuid-bbb"],
            },
            "malware": [],
            "vulns": [],
            "techniques": [],
            "sectors": [],
        }
    ]
    bundle = StixExporter(_mk_client(rows)).export_indicator("203.0.113.5")
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators, "expected an indicator SDO in the bundle"
    seed = indicators[0]
    # Both fields must be set, deduped, and contain the union.
    assert sorted(seed["x_edgeguard_misp_event_ids"]) == ["5000", "5001"]
    assert sorted(seed["x_edgeguard_misp_attribute_ids"]) == ["uuid-aaa", "uuid-bbb"]
