"""Deterministic per-node UUID computation for cross-environment traceability.

Why this module exists
----------------------
EdgeGuard MERGEs nodes by stable natural keys (Indicator by ``(indicator_type,
value)``, Malware by ``name``, CVE by ``cve_id``, etc. — see
``Neo4jClient.create_constraints``). Natural keys work for **idempotent ingest**
on a single Neo4j, but they fall short for two adjacent workflows the user
needs:

1. **Custom incremental delta sync (local Neo4j → cloud Neo4j).** Pushing
   deltas keyed only on natural keys forces the cloud consumer to re-resolve
   every node before it can re-attach edges. Slow on large graphs and brittle
   to natural-key changes (e.g. CVE re-canonicalization).
2. **Self-describing edge serialization** for LLM/RAG consumers that operate
   on edge documents without joining back to the connected nodes.

Both are solved by a **deterministic UUIDv5** computed from
``(label, natural_key)``. UUIDv5 is reproducible — given the same inputs, every
process anywhere produces the same UUID — so a node's ``uuid`` is identical on
local and cloud, and edges can carry ``src_uuid`` / ``trg_uuid`` properties
that resolve correctly across environments.

Namespace reuse
---------------
We deliberately reuse ``EDGEGUARD_STIX_NAMESPACE`` (defined in
``src/stix_exporter.py``) so that:

  Neo4j Indicator (indicator_type=ipv4, value=203.0.113.5)  →  n.uuid = "abc-123-..."
  STIX SDO id for the same indicator                         →  "indicator--abc-123-..."

The UUID portion is identical, providing **cross-system traceability** between
EdgeGuard's Neo4j and the STIX bundles it ships to ResilMesh.

Canonicalization rules
----------------------
The same ``(label, natural_key)`` MUST yield the same UUID on every machine
and in every Python version. To guarantee that — AND to deliver UUID parity
with the STIX exporter's `_deterministic_id` — we use a fixed per-label
natural-key serialization scheme that exactly matches the strings that the
existing STIX SDO ID generator produces:

  Neo4j  Indicator(indicator_type="ipv4", value="203.0.113.5")
    → canonical:  ``"indicator:ipv4|203.0.113.5"``  (lowercased)
    → uuid5(NS, canonical)                         = "abc-123-..."

  STIX   _deterministic_id("indicator", "ipv4|203.0.113.5")
    → canonical:  ``"indicator:ipv4|203.0.113.5"``  (lowercased)
    → uuid5(NS, canonical)                         = "abc-123-..."

Same UUID → cross-system traceability. The STIX exporter wraps it in
``indicator--<uuid>``; Neo4j stores it as ``n.uuid``.

If you change ANY of these rules you break every existing UUID — never
modify them without a coordinated migration of the entire graph.
"""

from __future__ import annotations

import uuid as _uuid_mod
from typing import Any, Dict, Tuple

# --------------------------------------------------------------------------- #
# Namespace — MUST match src/stix_exporter.py:EDGEGUARD_STIX_NAMESPACE
# --------------------------------------------------------------------------- #
#
# Reused intentionally so the UUID portion of a STIX SDO id equals the
# corresponding Neo4j n.uuid for the same logical entity. Do NOT change this
# value — it would invalidate every uuid in every running Neo4j and every
# STIX bundle ever shipped to ResilMesh.
EDGEGUARD_NODE_UUID_NAMESPACE = _uuid_mod.UUID("5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb")


# --------------------------------------------------------------------------- #
# Per-label natural-key map — single source of truth
# --------------------------------------------------------------------------- #
#
# Maps Neo4j node label → tuple of property names that uniquely identify a
# node under that label. Mirrors the UNIQUE constraints declared in
# Neo4jClient.create_constraints. If you add a new node label there, add it
# here too — otherwise compute_node_uuid_for_label() will raise KeyError on
# the first MERGE for that label.
_NATURAL_KEYS: Dict[str, Tuple[str, ...]] = {
    # MISP / threat-intel core
    "Indicator": ("indicator_type", "value"),
    "Malware": ("name",),
    "ThreatActor": ("name",),
    "Technique": ("mitre_id",),
    "Tactic": ("mitre_id",),
    "Tool": ("mitre_id",),
    "CVE": ("cve_id",),
    "Vulnerability": ("cve_id",),
    "Sector": ("name",),
    "Source": ("source_id",),
    # CVSS sub-nodes — one per CVE per version
    "CVSSv2": ("cve_id",),
    "CVSSv30": ("cve_id",),
    "CVSSv31": ("cve_id",),
    "CVSSv40": ("cve_id",),
    # Enrichment-derived
    "Campaign": ("name",),
    # ResilMesh / topology
    "IP": ("address",),
    "Host": ("hostname",),
    "Device": ("device_id",),
    "Subnet": ("range",),
    "NetworkService": ("port", "protocol"),
    "SoftwareVersion": ("version",),
    "Application": ("name",),
    "Role": ("permission",),
}


def supported_labels() -> Tuple[str, ...]:
    """Return the set of node labels for which a deterministic uuid is defined."""
    return tuple(_NATURAL_KEYS.keys())


def natural_key_props(label: str) -> Tuple[str, ...]:
    """Return the natural-key property names for a label.

    Raises ``KeyError`` for unknown labels — fail loudly so a missing label
    surfaces in the calling MERGE rather than silently producing a wrong uuid
    from an empty key dict.
    """
    return _NATURAL_KEYS[label]


# --------------------------------------------------------------------------- #
# Neo4j label → STIX type translation (for cross-system uuid parity)
# --------------------------------------------------------------------------- #
#
# Maps the Neo4j label to the STIX 2.1 SDO type used by ``stix_exporter``.
# The canonical string fed into ``uuid5`` uses the STIX type, not the Neo4j
# label, so the resulting UUID is identical to the suffix of the STIX SDO id
# produced by ``_deterministic_id`` for the same logical entity.
#
# Labels not in this map fall back to the lowercased label name (stable but
# without STIX parity — appropriate for topology / ResilMesh-owned nodes that
# are not exported via STIX anyway).
NEO4J_TO_STIX_TYPE: Dict[str, str] = {
    "Indicator": "indicator",
    "Malware": "malware",
    "ThreatActor": "intrusion-set",  # MITRE ATT&CK convention
    "Technique": "attack-pattern",
    "Tool": "tool",
    "Tactic": "x-mitre-tactic",
    "CVE": "vulnerability",
    "Vulnerability": "vulnerability",
    "Sector": "identity",
    "Campaign": "campaign",
    # CVSS sub-nodes don't map to a STIX SDO; use a custom prefix that's
    # still deterministic and never collides with real STIX types.
    "CVSSv2": "x-edgeguard-cvssv2",
    "CVSSv30": "x-edgeguard-cvssv30",
    "CVSSv31": "x-edgeguard-cvssv31",
    "CVSSv40": "x-edgeguard-cvssv40",
    # Source nodes are EdgeGuard-internal — also custom prefix.
    "Source": "x-edgeguard-source",
}


# --------------------------------------------------------------------------- #
# Canonicalization + uuid computation
# --------------------------------------------------------------------------- #


# Lowercased-key view of ``_NATURAL_KEYS`` — DERIVED from the single source
# of truth so the two maps cannot drift out of sync. ``canonical_node_key``
# normalizes the label to lowercase before lookup; the lowercase keys here
# match. Use ``_NATURAL_KEYS`` from public API helpers (``natural_key_props``,
# ``uuid_for``); use ``_LABEL_NATURAL_KEY_FIELDS`` only in the canonicalization
# inner loop.
#
# Note on Tool: the natural key is ``mitre_id`` (Neo4j's UNIQUE constraint on
# Tool is on ``mitre_id``). The STIX exporter's ``_deterministic_id("tool", …)``
# happens to be called with ``name`` for the SDO id, so Tool SDO IDs do NOT
# have UUID parity with Neo4j ``n.uuid``. Documented in CLOUD_SYNC.md and
# MIGRATIONS.md. Reconciliation deferred (would break cached STIX IDs).
_LABEL_NATURAL_KEY_FIELDS: Dict[str, Tuple[str, ...]] = {
    label.lower(): fields for label, fields in _NATURAL_KEYS.items()
}


def _natural_key_string(canonical_label: str, key_dict: Dict[str, Any]) -> str:
    """Per-label natural-key string serialization.

    Matches the strings that ``stix_exporter._deterministic_id`` is called
    with (e.g. for Indicator: ``f"{indicator_type}|{value}"``) so the resulting
    UUID is identical across systems. Labels not handled explicitly fall back
    to a sorted ``key=value|...`` form (deterministic but no STIX parity).

    ``canonical_label`` MUST be already lowercased + stripped — caller's job.
    """
    fields = _LABEL_NATURAL_KEY_FIELDS.get(canonical_label)
    if fields is not None:
        return "|".join(str(key_dict.get(f, "") or "") for f in fields)
    # Generic fallback — topology / unknown labels. Deterministic but no
    # STIX-side counterpart, so parity isn't relevant.
    parts = [f"{k}={('' if v is None else str(v))}" for k, v in sorted(key_dict.items())]
    return "|".join(parts)


def canonical_node_key(label: str, key_dict: Dict[str, Any]) -> str:
    """Stable string serialization of (label, natural_key) for UUID hashing.

    Form: ``f"{stix_or_label_type}:{natural_key_string}".lower()`` —
    matches ``_deterministic_id`` exactly so ``compute_node_uuid`` and that
    helper produce the same UUID for the same logical entity.

    Examples (frozen — do NOT change without a graph-wide migration):

        canonical_node_key("Indicator", {"indicator_type": "ipv4", "value": "203.0.113.5"})
        → "indicator:ipv4|203.0.113.5"

        canonical_node_key("ThreatActor", {"name": "APT28"})
        → "intrusion-set:apt28"   (note: STIX type, lowercased)

        canonical_node_key("Vulnerability", {"cve_id": "CVE-2024-1234"})
        → "vulnerability:cve-2024-1234"
    """
    canonical_label = (label or "").lower().strip()
    # NEO4J_TO_STIX_TYPE keyed by the canonical (proper-case) label name —
    # accept any case from the caller by reverse-lookup if needed.
    obj_type = NEO4J_TO_STIX_TYPE.get(label) or NEO4J_TO_STIX_TYPE.get(label.strip()) or canonical_label
    # Fall through one more time if the input came in lowercased (like "indicator").
    if obj_type == canonical_label and obj_type != label.strip():
        # Try the title-cased version — covers callers that lowercase the label.
        for known in NEO4J_TO_STIX_TYPE:
            if known.lower() == canonical_label:
                obj_type = NEO4J_TO_STIX_TYPE[known]
                break
    nks = _natural_key_string(canonical_label, key_dict)
    if not nks:
        # Mirror _deterministic_id's defensive fallback so the namespace stays
        # within a single deterministic family — a missing key still produces
        # a stable uuid rather than crashing.
        nks = f"__missing__:{obj_type}"
    return f"{obj_type}:{nks}".lower()


def compute_node_uuid(label: str, key_dict: Dict[str, Any]) -> str:
    """Compute the deterministic UUIDv5 for a node from (label, natural_key).

    Returns a plain UUID string (no ``label--`` prefix). The STIX exporter
    wraps the same UUID with ``f"{stix_type}--{uuid}"`` to form an SDO id —
    so for any label in NEO4J_TO_STIX_TYPE, the SDO id's UUID portion
    equals this function's return value.
    """
    canonical = canonical_node_key(label, key_dict)
    return str(_uuid_mod.uuid5(EDGEGUARD_NODE_UUID_NAMESPACE, canonical))


def uuid_for(label: str, props: Dict[str, Any]) -> str:
    """Compute a node's uuid from its full property dict.

    Convenience wrapper that pulls the configured natural-key props out of
    ``props`` and passes them to ``compute_node_uuid``. Use this when you
    have the full data dict at hand (e.g. inside ``merge_node_with_source``).

    Raises ``KeyError`` for unknown labels — see ``natural_key_props``.
    """
    keys = natural_key_props(label)
    return compute_node_uuid(label, {k: props.get(k) for k in keys})


def edge_endpoint_uuids(
    from_label: str,
    from_key: Dict[str, Any],
    to_label: str,
    to_key: Dict[str, Any],
) -> Tuple[str, str]:
    """Compute (src_uuid, trg_uuid) for an edge whose endpoints are described
    by their labels + natural keys.

    Used by every edge MERGE site to stamp ``r.src_uuid`` and ``r.trg_uuid``
    so edges become self-describing across environments.
    """
    return compute_node_uuid(from_label, from_key), compute_node_uuid(to_label, to_key)
