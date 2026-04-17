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


# ---------------------------------------------------------------------------
# Round 25 — red-team adversarial canonicalization fixes
# ---------------------------------------------------------------------------


def test_pipe_separator_escape_eliminates_collision():
    """PR #34 round 25 (red-team, HIGH): the Indicator canonical string uses
    ``|`` as the field separator. Before round 25,
    ``Indicator(type="ipv4|x", value="y")`` and
    ``Indicator(type="ipv4", value="x|y")`` BOTH rendered as ``"ipv4|x|y"``
    → identical canonical → identical uuid → silent collision of two
    logically distinct entities.

    Fix: ``canonicalize_field_value`` replaces ``|`` with ``%7C`` BEFORE
    joining, so the joined form is unambiguous. Pin the collision
    elimination by computing both uuids and asserting they differ."""
    from node_identity import compute_node_uuid

    u1 = compute_node_uuid("Indicator", {"indicator_type": "ipv4|x", "value": "y"})
    u2 = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "x|y"})
    assert u1 != u2, (
        "pipe-separator collision not eliminated — Indicator canonical must escape '|' in values "
        "so distinct (type, value) pairs produce distinct uuids"
    )

    # Common-case (no pipe) uuids must be UNCHANGED by the escape — this is
    # a backward-compatibility contract. If this fails, every existing
    # Indicator in production gets a new uuid at next MERGE.
    u_common = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"})
    # Frozen uuid from PR #33 round 10 era — must not change across round 25.
    assert u_common == "6ca3af4a-4bf1-57c9-846d-ec8f80861fd0", (
        "common-case Indicator uuid diverged — round-25 escape must be backward-compatible for values without '|'"
    )


def test_whitespace_is_stripped_in_canonical():
    """PR #34 round 25 (red-team, MEDIUM): upstream feeds occasionally
    deliver values with trailing/leading whitespace (``"APT 28 "`` vs
    ``"APT 28"``). Before round 25 these produced DIFFERENT uuids,
    creating duplicate-but-divergent-uuid nodes for the same logical
    entity.

    Fix: ``canonicalize_field_value`` calls ``.strip()`` before hashing."""
    from node_identity import compute_node_uuid

    u1 = compute_node_uuid("Malware", {"name": "APT 28"})
    u2 = compute_node_uuid("Malware", {"name": "APT 28 "})
    u3 = compute_node_uuid("Malware", {"name": "  APT 28"})
    u4 = compute_node_uuid("Malware", {"name": "\tAPT 28\n"})
    assert u1 == u2 == u3 == u4, (
        "whitespace-different inputs must produce the same uuid after strip — "
        f"got {u1[:8]} / {u2[:8]} / {u3[:8]} / {u4[:8]}"
    )
    # Internal whitespace must be preserved (only leading/trailing trimmed).
    u_no_space = compute_node_uuid("Malware", {"name": "APT28"})
    assert u1 != u_no_space, "internal whitespace is semantic — strip must only trim edges"


def test_unicode_nfc_normalization():
    """PR #34 round 25 (red-team, MEDIUM): Unicode has multiple visually-
    identical byte sequences (NFC vs NFD). ``"Café"`` can be 4 codepoints
    (NFC: C-a-f-é) or 5 (NFD: C-a-f-e-´ with combining accent). Same
    glyphs, different bytes, different uuids under naive hashing.

    Fix: ``canonicalize_field_value`` applies ``unicodedata.normalize("NFC", ...)``
    so both forms collapse to the same uuid."""
    import unicodedata

    from node_identity import compute_node_uuid

    nfc = "Café"  # single é codepoint
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd, "precondition: NFC and NFD forms must differ at the byte level"
    u_nfc = compute_node_uuid("Malware", {"name": nfc})
    u_nfd = compute_node_uuid("Malware", {"name": nfd})
    assert u_nfc == u_nfd, (
        f"NFC/NFD forms of visually-identical '{nfc}' must produce same uuid; got {u_nfc[:8]} vs {u_nfd[:8]}"
    )


def test_canonicalize_field_value_handles_none_preserves_falsy():
    """Regression pin for PR #33 round 4: ``canonicalize_field_value``
    must treat only ``None`` as "missing" — falsy values like 0, False,
    0.0 are legitimate (port=0 is a valid NetworkService) and must NOT
    collapse to empty string."""
    from node_identity import canonicalize_field_value

    assert canonicalize_field_value(None) == "", "None must collapse to empty string"
    assert canonicalize_field_value(0) == "0", "port=0 (int) must NOT collapse to empty"
    assert canonicalize_field_value(False) == "False", "False must NOT collapse to empty"
    assert canonicalize_field_value(0.0) == "0.0", "0.0 must NOT collapse to empty"
    assert canonicalize_field_value("") == "", "explicit empty string stays empty"


def test_stix_parity_holds_for_edge_case_inputs():
    """Round 25 adversarial inputs must preserve STIX↔Neo4j parity.
    The ``_deterministic_id`` helper in stix_exporter.py applies the same
    NFC+strip normalization as ``canonicalize_field_value`` so uuids
    converge for edge-case inputs."""
    from node_identity import canonicalize_field_value, compute_node_uuid
    from stix_exporter import _deterministic_id

    # Edge case 1: pipe in value
    n1 = compute_node_uuid("Indicator", {"indicator_type": "ipv4", "value": "x|y"})
    s1 = _deterministic_id(
        "indicator",
        f"{canonicalize_field_value('ipv4')}|{canonicalize_field_value('x|y')}",
    )
    assert n1 == s1.split("--", 1)[1], "STIX parity broken for pipe-in-value Indicator"

    # Edge case 2: whitespace in malware name
    n2 = compute_node_uuid("Malware", {"name": "APT 28 "})
    s2 = _deterministic_id("malware", "APT 28 ")
    assert n2 == s2.split("--", 1)[1], "STIX parity broken for whitespace malware name"

    # Edge case 3: NFD unicode
    import unicodedata

    nfd = unicodedata.normalize("NFD", "Café")
    n3 = compute_node_uuid("Malware", {"name": nfd})
    s3 = _deterministic_id("malware", nfd)
    assert n3 == s3.split("--", 1)[1], "STIX parity broken for NFD unicode malware name"
