"""Tests for the STIX exporter MISP-provenance attachment.

The exporter adds two custom properties to every SDO that originates
from a Neo4j node carrying MISP traceability:

  - ``x_edgeguard_misp_event_ids``     (from ``misp_event_ids[]`` array)
  - ``x_edgeguard_misp_attribute_ids`` (from ``misp_attribute_ids[]`` array)

PR #33 round 10 dropped the legacy scalars ``misp_event_id`` and
``misp_attribute_id``; STIX export now reads only the array fields.
The custom property is omitted entirely when the source node has no
values; the resulting list is deduped and stringified.
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


def test_attach_misp_provenance_dedupes_within_array():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        "misp_event_ids": ["1001", "1001", "1002"],
        "misp_attribute_ids": ["uuid-a", "uuid-a"],
    }
    _attach_misp_provenance(sdo, props)
    assert sdo["x_edgeguard_misp_event_ids"] == ["1001", "1002"]
    assert sdo["x_edgeguard_misp_attribute_ids"] == ["uuid-a"]


def test_attach_misp_provenance_omits_field_when_empty():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    _attach_misp_provenance(sdo, {})
    assert "x_edgeguard_misp_event_ids" not in sdo
    assert "x_edgeguard_misp_attribute_ids" not in sdo


def test_attach_misp_provenance_ignores_legacy_scalar_keys():
    """PR #33 round 10: legacy scalar keys are no longer read. If a stale
    consumer somehow still sets the scalar, the helper ignores it — only
    the array contributes to the SDO custom property."""
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        # legacy scalars (should be ignored)
        "misp_event_id": "ignored-scalar",
        "misp_attribute_id": "ignored-scalar-attr",
        # canonical array
        "misp_event_ids": ["1001"],
        "misp_attribute_ids": ["uuid-a"],
    }
    _attach_misp_provenance(sdo, props)
    assert sdo["x_edgeguard_misp_event_ids"] == ["1001"]
    assert "ignored-scalar" not in sdo["x_edgeguard_misp_event_ids"]
    assert sdo["x_edgeguard_misp_attribute_ids"] == ["uuid-a"]
    assert "ignored-scalar-attr" not in sdo["x_edgeguard_misp_attribute_ids"]


def test_attach_misp_provenance_omits_when_only_legacy_scalars_present():
    """A node carrying only the dropped legacy scalars (no array) should
    produce no x_edgeguard_misp_* custom property — the field is omitted."""
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {"misp_event_id": "777", "misp_attribute_id": "uuid-z"}
    _attach_misp_provenance(sdo, props)
    assert "x_edgeguard_misp_event_ids" not in sdo
    assert "x_edgeguard_misp_attribute_ids" not in sdo


def test_attach_misp_provenance_filters_none_and_empty_strings():
    sdo: Dict[str, Any] = {"type": "indicator", "id": "indicator--x"}
    props = {
        "misp_event_ids": [None, "", "1001", None, "1002"],
    }
    _attach_misp_provenance(sdo, props)
    # None and empty-string entries are dropped; remaining values dedupe + stringify.
    assert sdo["x_edgeguard_misp_event_ids"] == ["1001", "1002"]


# ---------------------------------------------------------------------------
# Integration test through the full exporter
# ---------------------------------------------------------------------------


def test_export_indicator_emits_misp_provenance_on_seed_sdo():
    rows = [
        {
            "seed": {
                "value": "203.0.113.5",
                "indicator_type": "ipv4",
                "misp_event_ids": ["5000", "5001"],
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
    assert sorted(seed["x_edgeguard_misp_event_ids"]) == ["5000", "5001"]
    assert sorted(seed["x_edgeguard_misp_attribute_ids"]) == ["uuid-aaa", "uuid-bbb"]
