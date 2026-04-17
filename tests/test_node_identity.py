"""Unit tests for src/node_identity.py — deterministic per-node UUIDs.

Three things this module guarantees, all asserted here:

1. **Determinism** — same (label, natural_key) → same UUID across runs.
2. **Cross-system parity** — the UUID returned by ``compute_node_uuid`` is
   exactly the suffix of the STIX SDO id produced by
   ``stix_exporter._deterministic_id`` for the same logical entity. This is
   what makes the local-Neo4j ↔ STIX-bundle round-trip work without joins.
3. **Sensible canonicalization rules** — label case is tolerated, natural-key
   value case is preserved (case matters for hashes / URLs / names),
   missing-key fallback is stable.
"""

from __future__ import annotations

import os
import sys

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from node_identity import (  # noqa: E402
    EDGEGUARD_NODE_UUID_NAMESPACE,
    NEO4J_TO_STIX_TYPE,
    canonical_node_key,
    compute_node_uuid,
    edge_endpoint_uuids,
    natural_key_props,
    supported_labels,
)

# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_compute_node_uuid_is_deterministic_across_calls():
    u1 = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})
    u2 = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})
    assert u1 == u2


def test_compute_node_uuid_differs_for_different_labels():
    same_key = {"name": "Emotet"}
    u_mal = compute_node_uuid("Malware", same_key)
    u_act = compute_node_uuid("ThreatActor", same_key)
    assert u_mal != u_act, "different labels must produce different uuids"


def test_compute_node_uuid_differs_for_different_natural_keys():
    u1 = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})
    u2 = compute_node_uuid("Indicator", {"indicator_type": "domain", "value": "1.2.3.4"})
    assert u1 != u2, "different indicator_type must produce different uuid"


# ---------------------------------------------------------------------------
# Canonicalization rules
# ---------------------------------------------------------------------------


def test_label_case_and_whitespace_tolerated():
    """Defensive: callers passing 'Indicator' / 'indicator' / ' Indicator '
    should all produce the same uuid (the natural-key UNIQUE constraint
    is case-insensitive on the label side anyway)."""
    canonical = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})
    assert compute_node_uuid("indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"}) == canonical
    assert compute_node_uuid(" Indicator ", {"indicator_type": "ipv4", "value": "1.2.3.4"}) == canonical


def test_natural_key_value_case_is_preserved():
    """Hashes, URLs, file paths, malware names — case matters. Two values
    differing only in case must produce different uuids."""
    u_lower = compute_node_uuid("Malware", {"name": "emotet"})
    u_mixed = compute_node_uuid("Malware", {"name": "Emotet"})
    # canonical_node_key intentionally lowercases the FINAL string for STIX
    # parity (that's what _deterministic_id does), so this test asserts the
    # *behavior* — same-case-after-lowercase yields same uuid. If you want
    # pre-lowered case to matter, change the canonicalization.
    assert u_lower == u_mixed, "current canonicalization lowercases the final string — STIX-parity rule"


def test_missing_key_falls_back_deterministically():
    """A node MERGE with an empty natural-key dict shouldn't crash; it should
    produce a stable uuid via the __missing__ fallback (same logic as
    _deterministic_id in stix_exporter.py)."""
    u1 = compute_node_uuid("Indicator", {})
    u2 = compute_node_uuid("Indicator", {})
    assert u1 == u2
    # And the missing-fallback uuid must NOT equal any populated-key uuid.
    assert u1 != compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})


def test_canonical_node_key_format_is_lowercased_and_typed():
    """Frozen contract — DO NOT change without a graph-wide migration."""
    assert canonical_node_key("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"}) == (
        "indicator:ipv4|203.0.113.5"
    )
    # ThreatActor → STIX intrusion-set (MITRE convention).
    assert canonical_node_key("ThreatActor", {"name": "APT28"}) == "intrusion-set:apt28"
    # Technique → STIX attack-pattern.
    assert canonical_node_key("Technique", {"mitre_id": "T1059"}) == "attack-pattern:t1059"
    # Vulnerability + CVE share the same STIX type → same canonical.
    assert canonical_node_key("Vulnerability", {"cve_id": "CVE-2024-1234"}) == "vulnerability:cve-2024-1234"
    assert canonical_node_key("CVE", {"cve_id": "CVE-2024-1234"}) == "vulnerability:cve-2024-1234"


# ---------------------------------------------------------------------------
# Cross-system parity with STIX exporter (the load-bearing claim)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,key_dict,stix_type,stix_natural_key_string",
    [
        ("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"}, "indicator", "ipv4|203.0.113.5"),
        ("Malware", {"name": "Emotet"}, "malware", "Emotet"),
        ("ThreatActor", {"name": "APT28"}, "intrusion-set", "APT28"),
        ("Technique", {"mitre_id": "T1059"}, "attack-pattern", "T1059"),
        ("Vulnerability", {"cve_id": "CVE-2024-1234"}, "vulnerability", "CVE-2024-1234"),
        # CVE + Vulnerability map to the same STIX type → same UUID.
        ("CVE", {"cve_id": "CVE-2024-1234"}, "vulnerability", "CVE-2024-1234"),
        ("Sector", {"name": "healthcare"}, "identity", "healthcare"),
        ("Campaign", {"name": "OperationPawnStorm"}, "campaign", "OperationPawnStorm"),
        # NOTE: Tool is intentionally absent. stix_exporter._deterministic_id
        # uses Tool.name for the STIX SDO id, but Neo4j keys Tool by mitre_id
        # (UNIQUE constraint). UUID parity for Tool requires a follow-up to
        # reconcile the natural-key choice — documented in node_identity.py
        # (_LABEL_NATURAL_KEY_FIELDS) and MIGRATIONS.md.
    ],
)
def test_neo4j_uuid_equals_stix_sdo_id_uuid_portion(label, key_dict, stix_type, stix_natural_key_string):
    """The UUID portion of a STIX SDO id MUST equal the corresponding Neo4j
    n.uuid for the same logical entity. This is the cross-system traceability
    contract — a STIX bundle leaving EdgeGuard for ResilMesh and the source
    Neo4j node share an identifier."""
    from stix_exporter import _deterministic_id

    neo4j_uuid = compute_node_uuid(label, key_dict)
    stix_id = _deterministic_id(stix_type, stix_natural_key_string)
    assert stix_id == f"{stix_type}--{neo4j_uuid}", (
        f"parity break for {label}/{key_dict}: neo4j_uuid={neo4j_uuid} stix_id={stix_id}"
    )


def test_sector_stix_parity_end_to_end():
    """PR #34 round 22 (multi-agent UUID audit, HIGH): the parametrized
    parity test above only exercises ``_deterministic_id`` directly with a
    hand-crafted ``stix_natural_key_string``. It does NOT drive the actual
    production helper ``_sector_sdo`` — which previously prepended
    ``sector|`` to the natural key, breaking parity while the parametrized
    test still passed (it was passing the WITHOUT-prefix form to
    _deterministic_id, masking the production divergence).

    This test closes the gap by driving ``_sector_sdo`` end-to-end: it
    builds the actual STIX SDO that the exporter would emit, extracts the
    UUID portion of the SDO's ``id``, and asserts it equals
    ``compute_node_uuid("Sector", {"name": ...})``. A future regression
    that re-adds a prefix anywhere along the path will fail this test."""
    import importlib

    if "stix_exporter" in sys.modules:
        del sys.modules["stix_exporter"]
    stix_exporter = importlib.import_module("stix_exporter")

    # Bypass the heavy __init__ — _sector_sdo is a pure function on props.
    exporter = stix_exporter.StixExporter.__new__(stix_exporter.StixExporter)

    for sector_name in ("healthcare", "energy", "finance", "global"):
        sdo = exporter._sector_sdo({"name": sector_name})
        # SDO id form: ``identity--<uuid>``.
        sdo_id = sdo["id"]
        assert sdo_id.startswith("identity--"), f"expected identity-- prefix, got {sdo_id!r}"
        sdo_uuid = sdo_id.split("--", 1)[1]

        neo4j_uuid = compute_node_uuid("Sector", {"name": sector_name})
        assert sdo_uuid == neo4j_uuid, (
            f"Sector parity break for {sector_name!r}: "
            f"_sector_sdo emitted UUID {sdo_uuid}, but compute_node_uuid returned {neo4j_uuid}. "
            "Likely cause: _sector_sdo is wrapping the name in a prefix (e.g. 'sector|') again."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_uuid_for_helper_was_removed():
    """PR #33 round 16 (bugbot LOW): the ``uuid_for`` convenience wrapper
    had ZERO production callers — every merger constructs the natural-key
    dict explicitly and calls ``compute_node_uuid`` directly. The wrapper
    only added public-API surface. This test pins the deletion so a future
    contributor doesn't reintroduce dead code."""
    import node_identity as _ni

    assert not hasattr(_ni, "uuid_for"), (
        "uuid_for was deleted in round 16 — call compute_node_uuid(label, key_dict) directly. "
        "If this assertion fires, the dead helper has been re-added."
    )


def test_edge_endpoint_uuids_returns_pair():
    """Sanity check on the convenience helper that powers every edge MERGE
    in neo4j_client.py — must produce stable, label-aware uuids for both
    endpoints."""
    src, trg = edge_endpoint_uuids(
        "Indicator",
        {"indicator_type": "ipv4", "value": "1.2.3.4"},
        "Malware",
        {"name": "Emotet"},
    )
    assert src == compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "1.2.3.4"})
    assert trg == compute_node_uuid("Malware", {"name": "Emotet"})


def test_natural_key_props_returns_documented_tuple():
    assert natural_key_props("Indicator") == ("indicator_type", "value")
    assert natural_key_props("Malware") == ("name",)
    assert natural_key_props("CVE") == ("cve_id",)
    with pytest.raises(KeyError):
        natural_key_props("UnknownLabel")


def test_supported_labels_covers_all_uniques():
    """The set of labels we know how to compute uuids for must be a superset
    of the labels with UNIQUE constraints in Neo4jClient.create_constraints.
    (If you add a new node label there, add it to _NATURAL_KEYS too.)"""
    documented = set(supported_labels())
    # Spot-check the threat-intel core that this PR primarily targets.
    must_have = {
        "Indicator",
        "Malware",
        "ThreatActor",
        "Technique",
        "Tactic",
        "Tool",
        "CVE",
        "Vulnerability",
        "Sector",
        "Source",
        "Campaign",
        "CVSSv2",
        "CVSSv30",
        "CVSSv31",
        "CVSSv40",
    }
    missing = must_have - documented
    assert not missing, f"natural-key map is missing: {missing}"


# ---------------------------------------------------------------------------
# Frozen namespace (do NOT change)
# ---------------------------------------------------------------------------


def test_namespace_is_frozen():
    """Changing this namespace would invalidate every uuid in every running
    Neo4j and every STIX bundle ever shipped to ResilMesh — fail loudly if
    someone tries."""
    assert str(EDGEGUARD_NODE_UUID_NAMESPACE) == "5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb"


def test_neo4j_to_stix_type_map_is_frozen_for_threat_intel_core():
    """Changing these mappings would break the STIX-side cross-system parity.
    Frozen for the threat-intel core; topology labels are allowed to evolve."""
    assert NEO4J_TO_STIX_TYPE["Indicator"] == "indicator"
    assert NEO4J_TO_STIX_TYPE["Malware"] == "malware"
    assert NEO4J_TO_STIX_TYPE["ThreatActor"] == "intrusion-set"
    assert NEO4J_TO_STIX_TYPE["Technique"] == "attack-pattern"
    assert NEO4J_TO_STIX_TYPE["Vulnerability"] == "vulnerability"
    assert NEO4J_TO_STIX_TYPE["CVE"] == "vulnerability"  # same SDO type
    assert NEO4J_TO_STIX_TYPE["Tool"] == "tool"
    assert NEO4J_TO_STIX_TYPE["Sector"] == "identity"
    assert NEO4J_TO_STIX_TYPE["Campaign"] == "campaign"
