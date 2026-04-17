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

import unicodedata
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
    # PR #34 round 23: extend coverage so local→cloud delta-sync works for
    # User identities + processed Alerts. Both have well-defined UNIQUE
    # constraints already (see Neo4jClient.create_constraints).
    "User": ("username", "domain"),
    "Alert": ("alert_id",),
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
    # CVE and Vulnerability BOTH map to STIX type "vulnerability" — this is
    # intentional. They are two Neo4j-side views of the same logical CVE
    # (CVE = NVD-canonical / ResilMesh-shared, Vulnerability =
    # EdgeGuard-managed / MISP-derived) connected via REFERS_TO edges. STIX
    # only has ONE vulnerability SDO per CVE, so both nodes deterministically
    # produce the same n.uuid. Operational consequence: any cloud-sync /
    # delta-sync recipe MUST scope MATCH-by-uuid to the label
    # (e.g. ``MATCH (v:Vulnerability {uuid: $u})`` not bare
    # ``MATCH (v {uuid: $u})``) — see docs/CLOUD_SYNC.md "CVE/Vulnerability
    # twin-node design" for the worked recipe. Bugbot caught this on PR #33
    # round 5 as a footgun in the unscoped MATCH form.
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
    # PR #34 round 23: User and Alert get custom EdgeGuard prefixes (we don't
    # STIX-export either today). User could in principle map to STIX
    # ``identity`` (identity_class="individual"), but Sector ALSO maps to
    # ``identity`` and shares the ``|`` separator in its natural-key form —
    # in the (astronomically unlikely) case of a Sector named ``alice|corp``
    # vs a User ``(alice, corp)``, the two would canonicalize identically
    # and collide on uuid. Custom prefixes are collision-free by construction.
    # If we ever STIX-export Users, switch to ``identity`` and add a User-
    # side natural-key disambiguator at the same time (do NOT just flip the
    # prefix without auditing the Sector overlap).
    "User": "x-edgeguard-user",
    "Alert": "x-edgeguard-alert",
}

# Lowercase-keyed mirror — derived from NEO4J_TO_STIX_TYPE so the two cannot
# drift. Used by canonical_node_key for case-insensitive label lookup. The
# original case-tolerance pattern (try original, try stripped, then a
# guarded reverse-lookup loop) had a bug: when the input label was already
# lowercase the guard was False and the loop was skipped, returning the
# lowercased Neo4j label instead of the proper STIX type for any label
# where the two differ (ThreatActor → intrusion-set, Technique →
# attack-pattern, CVE/Vulnerability → vulnerability, Sector → identity,
# Tactic → x-mitre-tactic). Bugbot caught this on PR #33; the simpler
# single-lookup form below cannot exhibit the same bug.
_STIX_TYPE_BY_LC_LABEL: Dict[str, str] = {k.lower(): v for k, v in NEO4J_TO_STIX_TYPE.items()}


# --------------------------------------------------------------------------- #
# Canonicalization + uuid computation
# --------------------------------------------------------------------------- #


# Lowercased-key view of ``_NATURAL_KEYS`` — DERIVED from the single source
# of truth so the two maps cannot drift out of sync. ``canonical_node_key``
# normalizes the label to lowercase before lookup; the lowercase keys here
# match. Use ``_NATURAL_KEYS`` from the public ``natural_key_props`` helper;
# use ``_LABEL_NATURAL_KEY_FIELDS`` only in the canonicalization inner loop.
#
# Note on Tool: the natural key is ``mitre_id`` (Neo4j's UNIQUE constraint on
# Tool is on ``mitre_id``). The STIX exporter's ``_deterministic_id("tool", …)``
# happens to be called with ``name`` for the SDO id, so Tool SDO IDs do NOT
# have UUID parity with Neo4j ``n.uuid``. Documented in CLOUD_SYNC.md and
# MIGRATIONS.md. Reconciliation deferred (would break cached STIX IDs).
_LABEL_NATURAL_KEY_FIELDS: Dict[str, Tuple[str, ...]] = {
    label.lower(): fields for label, fields in _NATURAL_KEYS.items()
}


def canonicalize_field_value(v: Any) -> str:
    """Render a single natural-key field value to its canonical-string form.

    Applied identically on both the Neo4j side (``compute_node_uuid``) and
    the STIX side (``stix_exporter._deterministic_id``) — exported as a
    public helper so the two paths stay in lockstep. Every edit here MUST
    be mirrored in the STIX exporter's call sites (enforced by
    ``tests/test_node_identity.py::test_neo4j_uuid_equals_stix_sdo_id_uuid_portion``).

    Transformations applied, in order:

    1. ``None`` → empty string ``""`` (explicit check — NEVER use ``v or ""``
       which would also collapse 0, False, 0.0 and silently produce uuid
       collisions with missing-key form; see PR #33 round 4).
    2. ``unicodedata.normalize("NFC", ...)`` — canonicalize Unicode composition
       so the visually-identical NFC ``"Café"`` (1 char é) and NFD
       ``"Café"`` (combining grave + e) produce the same uuid. (PR #34
       round 25: red-team audit surfaced that visually-same strings with
       different byte sequences were producing divergent uuids.)
    3. ``.strip()`` — trim leading/trailing whitespace. ``Malware("APT 28 ")``
       and ``Malware("APT 28")`` are treated as the same logical entity.
       (PR #34 round 25: trailing-space in upstream feed data was
       producing duplicate-but-divergent-uuid Malware nodes.)
    4. Replace ``|`` with ``%7C`` — the pipe character is the natural-key
       field SEPARATOR when joining multi-field keys (e.g. Indicator's
       ``type|value``). If a value itself contains ``|``, the joined form
       becomes ambiguous: ``Indicator(type="ipv4|x", value="y")`` and
       ``Indicator(type="ipv4", value="x|y")`` would both render as
       ``"ipv4|x|y"`` and collide on uuid. Escaping eliminates the
       ambiguity. (PR #34 round 25: red-team audit.)
    """
    if v is None:
        return ""
    s = unicodedata.normalize("NFC", str(v)).strip()
    # ``%7C`` is the URL-encoding for ``|`` — visually distinct, safe for
    # Cypher (no reserved chars), preserves canonical-string printability.
    return s.replace("|", "%7C")


def _natural_key_string(canonical_label: str, key_dict: Dict[str, Any]) -> str:
    """Per-label natural-key string serialization.

    Matches the strings that ``stix_exporter._deterministic_id`` is called
    with (e.g. for Indicator: ``f"{indicator_type}|{value}"``) so the resulting
    UUID is identical across systems. Labels not handled explicitly fall back
    to a sorted ``key=value|...`` form (deterministic but no STIX parity).

    ``canonical_label`` MUST be already lowercased + stripped — caller's job.

    PR #34 round 25: individual field values are routed through
    ``canonicalize_field_value`` for NFC-normalize + strip + pipe-escape.
    The same helper is called on the STIX side at every multi-field call
    site so parity holds even for edge-case inputs.
    """
    fields = _LABEL_NATURAL_KEY_FIELDS.get(canonical_label)
    if fields is not None:
        return "|".join(canonicalize_field_value(key_dict.get(f)) for f in fields)
    # Generic fallback — topology / unknown labels. Deterministic but no
    # STIX-side counterpart, so parity isn't relevant.
    parts = [f"{k}={canonicalize_field_value(v)}" for k, v in sorted(key_dict.items())]
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
    # Single lookup against the lowercase-keyed mirror — case-tolerant by
    # construction. Falls through to the lowercased label name itself for
    # topology / unknown labels (no STIX parity, but still deterministic).
    obj_type = _STIX_TYPE_BY_LC_LABEL.get(canonical_label, canonical_label)
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


# PR #33 round 16: deleted ``uuid_for`` (a convenience wrapper that
# extracted natural-key fields from a full props dict before delegating to
# ``compute_node_uuid``). Zero production callers — every merger already
# constructs the natural-key dict explicitly when it needs an uuid. The
# function only added public-API surface and a maintenance burden.


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
