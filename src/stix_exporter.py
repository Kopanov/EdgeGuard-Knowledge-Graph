"""Graph → STIX 2.1 exporter for ResilMesh integration.

This module is a **prototype** proposal implementation — see
``docs/STIX21_EXPORTER_PROPOSAL.md`` for design notes, open questions and
the list of follow-ups. It builds STIX 2.1 bundles centred on a single
seed object (indicator / threat actor / technique / CVE) plus the
immediate threat-intel neighbourhood, so ResilMesh can enrich an asset
with "what do we know about this indicator/actor/etc." without pulling
the whole graph.

Key design decisions (see proposal doc for justification):
- Uses the ``stix2`` SDK (already pinned in ``pyproject.toml``) for object
  construction so we get ID generation, timestamp formatting and schema
  validation for free.
- STIX IDs are **deterministic** (UUIDv5 over the node's natural key) so
  re-exports of the same graph state produce the same bundle — ResilMesh
  can diff bundles safely.
- All Cypher queries filter on ``x.edgeguard_managed = true OR x.edgeguard_enriched = true`` — nodes EdgeGuard created or enriched — (strict
  equality — null fails) so we never leak ResilMesh-owned
  asset/vulnerability nodes into an outbound bundle. Originally written
  as ``coalesce(x.edgeguard_managed, true) = true``, which defaulted
  missing properties to ``true`` and let ResilMesh-owned nodes pass the
  filter — fixed in the bugbot pass on PR #25.
- ``EMPLOYS_TECHNIQUE`` (attribution: ThreatActor/Campaign → Technique),
  ``IMPLEMENTS_TECHNIQUE`` (capability: Malware/Tool → Technique), and
  ``USES_TECHNIQUE`` (observation: Indicator → Technique) all collapse
  back to STIX 2.1 ``relationship_type: "uses"`` on export. Pre-release
  fresh start has no legacy ``USES`` edges; the read paths match only
  the post-PR-#24 specialised edge types.
- ATT&CK tactics are emitted as ``kill_chain_phases`` on the
  ``attack-pattern`` SDO, not as standalone objects (per STIX 2.1 ATT&CK
  convention).

Export hardening (2026-10):

- **Bounded exports.** Every ``export_*`` method takes a ``limit``
  argument (default ``_DEFAULT_LIMIT``, hard maximum ``_MAX_LIMIT``) that
  is applied per related-node collection inside the Cypher
  (``ORDER BY <natural key> LIMIT $limit`` before each ``collect``), so a
  highly connected seed such as T1059 cannot produce an unbounded bundle.
  The seed match is itself reduced to one deterministic row so the
  per-collection limits are well defined. The REST layer exposes the same
  bound as a validated ``?limit=`` query parameter.
- **Batched source aggregates.** The per-source MIN/MAX timestamps on the
  ``SOURCED_FROM`` edges are fetched with one ``UNWIND`` query per node
  label and bundle (``_prefetch_source_aggregates``) instead of one query
  per node.
- **Provenance and custom properties (strict-parser compliance).** STIX
  2.1 permits only ``type``, ``id`` and ``objects`` on a Bundle, and
  ``stix2.parse`` with the default ``allow_custom=False`` rejects both
  bundle-level custom properties and undeclared ``x_`` properties on
  objects (``ExtraPropertiesError``). Verified against stix2 3.0.2: an
  object whose ``extensions`` map declares an
  ``extension-definition--*`` entry with
  ``extension_type: "toplevel-property-extension"`` is accepted with its
  top-level extension properties intact, and ``extension-definition``
  objects parse natively. The exporter therefore emits (a) an EdgeGuard
  producer ``identity`` object, referenced by ``created_by_ref`` from
  every SDO/SRO, that carries the former bundle-level provenance
  (exporter, git SHA, generation time) as top-level extension
  properties, and (b) a single ``extension-definition`` object
  (``EDGEGUARD_EXTENSION_ID``) declaring every ``x_edgeguard_*``
  property name (``EDGEGUARD_EXTENSION_PROPERTIES``). Each object that
  carries at least one ``x_edgeguard_*`` property declares the extension
  in its ``extensions`` map. The property-extension (nested) form was
  also accepted by stix2 but was rejected here because it would move the
  properties that ResilMesh already reads at the top level. ``Tactic``
  nodes are not reachable from any ``export_*`` path; the
  ``x-mitre-tactic`` custom type they map to is not strictly parseable
  and is retained only for MITRE convention.
- **TLP markings.** The four STIX 2.1 TLP ``marking-definition`` objects
  (the fixed identifiers from the specification, as shipped in
  ``stix2.TLP_*``) are included when referenced, and every SDO carries
  ``object_marking_refs`` derived from the node's ``tlp`` property; SROs
  carry the most restrictive marking of their two endpoints and of the
  relationship's own ``tlp`` (curated-package links, 2026-10).
- **Patterns.** Indicator patterns are built in this module from the
  STIX 2.1 patterning grammar: ``email-addr``, ``file:hashes`` keyed by
  the detected algorithm, ``x509-certificate:hashes`` for TLS certificate
  fingerprints, ``file:name``, ``url``, ``domain-name``, ``ipv4-addr`` /
  ``ipv6-addr`` (chosen by the address, 2026-10); values are escaped.
- **Relationships and vocabularies.** ``_edge_to_sro`` maps each graph
  edge type to the ``relationship_type`` permitted by the STIX 2.1
  relationship summary table for the (source, target) SDO pair, reversing
  direction where the specification models the pair the other way round;
  unknown pairs fall back to ``related-to``. Sector identities use the
  ``industry-sector-ov`` vocabulary. ``stix_relationship_mappings`` lists
  the table for ``GET /stix/types``.
- **Timestamps.** Node timestamps written with Cypher ``datetime()`` reach
  the exporter as ``neo4j.time.DateTime``; ``_iso_str`` converts them to
  Python values and ``_stix_ts`` cuts any fraction beyond six digits, the
  most ``stix2`` accepts (nine digits made every such export fail).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import unicodedata
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import stix2

from attack_revoked import load_revoked_ids

logger = logging.getLogger(__name__)

# Per-collection bound on related nodes in an export (see the module
# docstring). The default and maximum follow the REST read clamps in
# ``query_api.py`` (``Query(..., ge=1, le=500)``); the route declares the
# same two values on its ``?limit=`` parameter.
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500


def _clamp_limit(limit: Any) -> int:
    """Coerce ``limit`` into ``[1, _MAX_LIMIT]``; non-integers fall back to the default."""
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return _DEFAULT_LIMIT
    return max(1, min(value, _MAX_LIMIT))


# Per-query timeout (seconds). Matches ``_NEO4J_QUERY_TIMEOUT`` in
# ``query_api.py`` so a pathological export can't tie up the request
# handler indefinitely — the driver aborts the query on timeout and the
# caller surfaces the usual Neo4j timeout error.
_STIX_QUERY_TIMEOUT = 300

# Default traversal depth for export_* methods. depth=2 matches the
# behavior shipped before the knob existed — full 1-hop neighborhood
# plus any documented second-level expansion (e.g. actor→malware→
# technique). depth=1 returns only the seed plus its primary relation
# type (the first group each exporter processes) and is intended for
# ResilMesh smoke tests that want a minimal bundle.
_DEFAULT_DEPTH = 2

# Optional git SHA baked into bundle provenance so ResilMesh can tell
# exactly which EdgeGuard build produced a given bundle. Populated from
# the EDGEGUARD_GIT_SHA env var at import time; empty string if unset.
_GIT_SHA = os.environ.get("EDGEGUARD_GIT_SHA", "")

# PR (S5) (bugbot LOW): the previously-defined ``_EMIT_SIGHTINGS``
# env-var hook for opt-in Sighting SRO emission was removed — it was
# evaluated on import but never read by any function (no consumer
# existed; the implementation was deferred to a follow-up PR). Will
# be reintroduced together with the actual per-source aggregation
# Cypher when that follow-up lands. The env var name
# ``EDGEGUARD_STIX_EMIT_SIGHTINGS`` is reserved for that future use
# but has no effect today.


# PR (S5) (bugbot LOW): consolidated to a shared module to
# kill the duplication with ``alert_processor._iso_str``. Single source
# of truth — bug fix in one place propagates to all callers.
from source_truthful_timestamps import iso_str as _iso_str  # noqa: E402

# 2026-10: the digits after the sixth fractional digit of an ISO-8601 time of day (``_stix_ts``).
_STIX_EXCESS_FRACTION_RE = re.compile(r"(T\d{2}:\d{2}:\d{2}\.\d{6})\d+")


def _producer_created_modified(props: Dict[str, Any]) -> Dict[str, str]:
    """Return ``{created, modified}`` kwargs for stix2 SDK constructors,
    sourced from EdgeGuard's DB-local timestamps when present.

    PR (S5) (Cross-Checker v3 F3 MED): STIX 2.1 §3.2 says
    ``created`` = "when the producer created this version of the
    object". For EdgeGuard re-exporting threat-intel data, the
    closest analogue is ``n.first_imported_at`` (when EdgeGuard
    first MERGEd the node). Without this override, stix2 SDK
    auto-stamps ``created = now()`` — every SDO emitted today says
    "created today" even for entities EdgeGuard has tracked for
    months. Same fix for ``modified`` from ``n.last_updated``.

    ``_tactic_sdo`` already does this manually (it's a custom dict,
    not via stix2 SDK). This helper brings the 6 SDK-built SDOs
    (Malware/IntrusionSet/AttackPattern/Tool/Campaign/Vulnerability)
    into the same convention.

    Falls back to "now" when the node lacks the corresponding field.
    Z-suffix-normalized for stix2 validator compatibility.
    """
    now_iso = _stix_ts(_dt.datetime.now(_dt.timezone.utc).isoformat()) or ""
    created = _stix_ts(_iso_str(props.get("first_imported_at"))) or now_iso
    modified = _stix_ts(_iso_str(props.get("last_updated"))) or now_iso
    return {"created": created, "modified": modified}


def _indicator_created_modified(props: Dict[str, Any]) -> Dict[str, str]:
    """``{created, modified}`` of an indicator SDO (2026-10-16, ``indicator_aging``).

    ``created`` is ``first_imported_at`` as for every SDO. ``modified`` is the latest of
    ``created``, ``last_recorded_at`` (the latest MISP record of a report) and ``aging_since``
    (when the indicator's aging state last changed), so it moves when a source reports the
    indicator again or its confidence or lifecycle changes, and not when a full sync merely
    writes the node again (``last_updated``, which it read before).
    """
    base = _producer_created_modified(props)
    created = base["created"]
    latest, latest_at = created, _parse_stix_ts(created)
    for key in ("last_recorded_at", "aging_since"):
        ts = _stix_ts(_iso_str(props.get(key)))
        at = _parse_stix_ts(ts) if ts else None
        if ts and at is not None and (latest_at is None or at > latest_at):
            latest, latest_at = ts, at
    return {"created": created, "modified": latest}


def _parse_stix_ts(ts: str) -> Optional[_dt.datetime]:
    """A ``_stix_ts`` string as an aware datetime (None when unparsable)."""
    try:
        return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _attach_indicator_aging(sdo: Dict[str, Any], props: Dict[str, Any]) -> None:
    """The indicator's aging as ``x_edgeguard_*`` properties (``_INDICATOR_AGING_FIELDS``),
    each when the node has it; ``source_confidence`` falls back to ``confidence_score``."""
    values = dict(props)
    if values.get("source_confidence") is None and values.get("confidence_score") is not None:
        values["source_confidence"] = values["confidence_score"]
    for neo_key, stix_key in _INDICATOR_AGING_FIELDS:
        value = values.get(neo_key)
        if value is None:
            continue
        if neo_key.endswith("_at"):
            value = _iso_str(value)
        sdo[stix_key] = value


def _stix_ts(s: Optional[str]) -> Optional[str]:
    """Normalize an ISO-8601 timestamp string for stix2 SDK acceptance.

    PR (S5) (post-redesign): stix2's `valid_from` validator
    rejects the ``+00:00`` UTC offset form ("not in a recognizable
    format"); it requires the ``Z`` short form. Both ``coerce_iso``
    output and Python's ``datetime.isoformat()`` produce ``+00:00`` —
    we normalize at the stix2 boundary instead of mutating those
    helpers (Neo4j and OpenCTI both accept either form, so the rest
    of the codebase stays in the more-explicit ``+00:00`` form).

    PR (S5) (Bug Hunter v2 #5 MED): also handle non-UTC
    offsets. A future collector that emits an Eastern-time-stamped
    value like ``"2024-03-15T14:00:00-04:00"`` would have previously
    flowed through unchanged → stix2 rejects it ("not a recognizable
    format") → the entire SDO build crashes → the indicator silently
    disappears from the bundle. Fix: parse and normalize to UTC ``Z``
    form. If parsing fails, fall back to passthrough so the existing
    error surfaces at the stix2 layer rather than swallowing here.

    2026-10: fractional seconds beyond six digits are cut to six (stix2
    3.0.2 accepts at most six). ``_iso_str`` already converts driver
    temporals to Python values, which print at most six; the cut keeps a
    nanosecond string from any other path (a stored ISO string, a driver
    value outside Python's range) from failing the whole export.
    """
    if not s:
        return s
    s = _STIX_EXCESS_FRACTION_RE.sub(r"\1", s, count=1)
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    if s.endswith("Z"):
        return s
    # Possibly a non-UTC offset — try to parse and normalize to Z.
    # Anything Python's fromisoformat accepts is good; anything else
    # passes through and stix2 will surface the error properly.
    try:
        parsed = _dt.datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return s
    if parsed.tzinfo is None:
        # Naive — assume UTC to avoid silently dropping the value.
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    else:
        parsed = parsed.astimezone(_dt.timezone.utc)
    # ``.isoformat()`` on a UTC datetime yields ``+00:00``; collapse to Z.
    out = parsed.isoformat()
    return out[:-6] + "Z" if out.endswith("+00:00") else out


# ---------------------------------------------------------------------------
# Deterministic IDs
# ---------------------------------------------------------------------------

# Fixed namespace so UUIDv5 is stable across processes/machines. This
# value is arbitrary but MUST NOT change — doing so would break ID
# stability for ResilMesh consumers that cache by STIX ID.
#
# CROSS-MODULE INVARIANT (PR-N2 §9-B1): this MUST equal
# ``node_identity.EDGEGUARD_NODE_UUID_NAMESPACE``. The deliberate
# duplication exists so each module reads correctly in isolation —
# the reuse is what makes ``compute_node_uuid("Indicator", {...})``
# (Neo4j ``n.uuid``) and ``_deterministic_id("indicator", "...")``
# (STIX SDO id UUID portion) produce the same value for the same
# logical entity, enabling cross-system traceability between Neo4j
# and STIX bundles consumed by ResilMesh.
#
# The runtime guard immediately below raises at module-load time if
# the two literals ever drift — the audit (Devil's Advocate F2)
# correctly noted that the comments say "MUST match" but nothing was
# actually enforcing it. Pre-PR-N2, a routine refactor that edited
# one literal without the other would have silently broken every
# Neo4j↔STIX cross-reference; subsequent migration to repair would
# require re-stamping every node + re-exporting every bundle.
EDGEGUARD_STIX_NAMESPACE = uuid.UUID("5f2e1f9a-6a1b-5e0f-9b25-ed9ea2d574cb")

# PR-N2 §9-B1: enforce parity at import time. ``assert`` is avoided
# because Python's ``-O`` flag strips assertions; we use an explicit
# ``raise`` instead so the check fires in production too.
from node_identity import EDGEGUARD_NODE_UUID_NAMESPACE as _EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK  # noqa: E402

if EDGEGUARD_STIX_NAMESPACE != _EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK:
    raise RuntimeError(
        "FATAL: UUID namespace drift detected between "
        "stix_exporter.EDGEGUARD_STIX_NAMESPACE "
        f"({EDGEGUARD_STIX_NAMESPACE}) and "
        "node_identity.EDGEGUARD_NODE_UUID_NAMESPACE "
        f"({_EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK}). "
        "These MUST be identical so Neo4j n.uuid and STIX SDO id UUIDs "
        "match for the same logical entity (cross-system traceability). "
        "If you genuinely need to migrate the namespace, follow the "
        "coordinated migration in node_identity.py's FROZEN block — "
        "do NOT just edit one of the literals."
    )

del _EDGEGUARD_NODE_UUID_NAMESPACE_FOR_PARITY_CHECK


def _deterministic_id(obj_type: str, natural_key: str) -> str:
    """Return a deterministic STIX 2.1 ID for ``obj_type`` + ``natural_key``.

    STIX IDs look like ``indicator--<uuid>``; we use UUIDv5 with a fixed
    namespace so the same (type, key) pair always yields the same ID.

    PR #34 round 25: apply the same NFC + strip normalization that
    ``node_identity.canonicalize_field_value`` applies on the Neo4j side,
    so cross-system uuid parity holds even for edge-case inputs
    (trailing whitespace, NFD-encoded strings). The ``|``-escape is NOT
    applied here because ``natural_key`` may already be a joined
    multi-field string (e.g. ``"ipv4|203.0.113.5"``) — callers of this
    function at multi-field SDO types MUST pre-escape each individual
    field via ``node_identity.canonicalize_field_value`` BEFORE joining.
    """
    if not natural_key:
        natural_key = f"__missing__:{obj_type}"
    natural_key = unicodedata.normalize("NFC", natural_key).strip()
    name = f"{obj_type}:{natural_key}".lower()
    return f"{obj_type}--{uuid.uuid5(EDGEGUARD_STIX_NAMESPACE, name)}"


# ---------------------------------------------------------------------------
# Producer identity, extension definition, TLP markings
# ---------------------------------------------------------------------------

# Deterministic identifiers of the two provenance objects every bundle
# carries. Both derive from ``EDGEGUARD_STIX_NAMESPACE`` so they are stable
# across processes and releases; consumers may cache them.
EDGEGUARD_IDENTITY_NAME = "EdgeGuard Knowledge Graph"
EDGEGUARD_IDENTITY_ID = _deterministic_id("identity", EDGEGUARD_IDENTITY_NAME)
EDGEGUARD_EXTENSION_ID = _deterministic_id("extension-definition", "edgeguard-provenance")

# Version stamps of the identity and the extension definition. These are
# fixed (not wall-clock) so the two objects are byte-stable across exports;
# ``modified`` and ``version`` are bumped when the definition changes.
_PROVENANCE_OBJECTS_CREATED = "2026-10-11T00:00:00.000Z"
# 1.1.0 (2026-10-14): relationship provenance properties on SROs.
# 1.2.0 (2026-10-15): x_edgeguard_status (NVD's record status) on vulnerabilities.
# 1.3.0 (2026-10-15): explainability. x_edgeguard_cited_ids on SROs (the ATT&CK ids the sources
#   cited that ATT&CK revoked into the target technique) and x_edgeguard_merged_from on
#   intrusion-sets (the names of the actor nodes EdgeGuard folded into this one).
# 1.4.0 (2026-10-15): FIRST EPSS and CISA's SSVC decision points on vulnerabilities. ``modified`` is
#   later than that of 1.3.0, as STIX versioning requires of a new version of an object.
# 1.5.0 (2026-10-16): x_edgeguard_evidence_types on the SROs of campaign links (the relationship
#   types a campaign link rests on: ATTRIBUTED_TO, USES_MALWARE, INDICATES).
# 1.6.0 (2026-10-16): x_edgeguard_description_source on SDOs with a description: the source whose
#   text the description is (``description_ranking``). ``modified`` is later than that of 1.5.0.
# 1.7.0 (2026-10-16): the aging of an indicator (``indicator_aging``): x_edgeguard_last_reported_at,
#   _last_reported_source, _last_reported_ref, _source_confidence, _aging_basis, _aging_tier,
#   _active and _retired_by on indicators. ``modified`` is later than that of 1.6.0.
_EXTENSION_MODIFIED = "2026-10-16T18:00:00.000Z"
_EXTENSION_VERSION = "1.7.0"
_EXTENSION_SCHEMA_URL = (
    "https://github.com/Kopanov/EdgeGuard-Knowledge-Graph/blob/main/docs/RESILMESH_QUICKSTART_STIX.md"
    "#edgeguard-extension-definition"
)

# Vulnerability enrichment fields promoted to top-level extension
# properties by ``_vulnerability_sdo`` (Neo4j property, STIX property).
_VULNERABILITY_PROMOTED_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("cvss_score", "x_edgeguard_cvss_score"),
    ("severity", "x_edgeguard_severity"),
    ("attack_vector", "x_edgeguard_attack_vector"),
    ("published", "x_edgeguard_published"),
    ("last_modified", "x_edgeguard_last_modified"),
    ("cisa_exploit_add", "x_edgeguard_cisa_exploit_add"),
    ("cisa_action_due", "x_edgeguard_cisa_action_due"),
    ("cisa_required_action", "x_edgeguard_cisa_required_action"),
    ("cisa_vulnerability_name", "x_edgeguard_cisa_vulnerability_name"),
    ("cwe", "x_edgeguard_cwe"),
    ("cisa_cwes", "x_edgeguard_cisa_cwes"),
    ("ref_tags", "x_edgeguard_ref_tags"),
    ("reference_urls", "x_edgeguard_reference_urls"),
    ("affected_products", "x_edgeguard_affected_products"),
    # 2026-10: which CVSS version ``x_edgeguard_cvss_score`` is (3.1, 3.0, 2.0 or 4.0), and CISA
    # KEV's knownRansomwareCampaignUse ("Known" / "Unknown").
    ("cvss_version", "x_edgeguard_cvss_version"),
    ("known_ransomware_use", "x_edgeguard_known_ransomware_use"),
    # 2026-10: NVD's record status, ["rejected"] or ["active"]; without it a rejected CVE exported
    # like an active one.
    ("status", "x_edgeguard_status"),
    # 2026-10: FIRST EPSS (``cve_feed_enrichment``): the probability of exploitation in the next 30
    # days, its percentile, the date of the scores and the model; CISA's SSVC decision points from
    # NVD's record, with the SSVC version and the time of CISA's decision.
    ("epss_score", "x_edgeguard_epss_score"),
    ("epss_percentile", "x_edgeguard_epss_percentile"),
    ("epss_score_date", "x_edgeguard_epss_score_date"),
    ("epss_model_version", "x_edgeguard_epss_model_version"),
    ("ssvc_exploitation", "x_edgeguard_ssvc_exploitation"),
    ("ssvc_automatable", "x_edgeguard_ssvc_automatable"),
    ("ssvc_technical_impact", "x_edgeguard_ssvc_technical_impact"),
    ("ssvc_version", "x_edgeguard_ssvc_version"),
    ("ssvc_timestamp", "x_edgeguard_ssvc_timestamp"),
)

# 2026-10-16: the aging of an indicator (``indicator_aging``), as top-level extension properties of
# the indicator SDO (Neo4j property, STIX property). ``source_confidence`` falls back to
# ``confidence_score`` on a node written before its writes kept it.
_INDICATOR_AGING_FIELDS: Tuple[Tuple[str, str], ...] = (
    ("last_reported_at", "x_edgeguard_last_reported_at"),
    ("last_reported_source", "x_edgeguard_last_reported_source"),
    ("last_reported_ref", "x_edgeguard_last_reported_ref"),
    ("source_confidence", "x_edgeguard_source_confidence"),
    ("aging_basis", "x_edgeguard_aging_basis"),
    ("aging_tier", "x_edgeguard_aging_tier"),
    ("active", "x_edgeguard_active"),
    ("retired_by", "x_edgeguard_retired_by"),
)

# Every top-level ``x_edgeguard_*`` property the exporter can emit. The
# extension definition declares this list as ``extension_properties``
# (required for ``toplevel-property-extension``); a test asserts that no
# emitted property is missing from it.
EDGEGUARD_EXTENSION_PROPERTIES: Tuple[str, ...] = (
    (
        # Producer identity
        "x_edgeguard_exporter",
        "x_edgeguard_git_sha",
        "x_edgeguard_generated_at",
        # Source-truthful and import-wall-clock timestamps (all SDO types)
        "x_edgeguard_first_seen_at_source",
        "x_edgeguard_last_seen_at_source",
        "x_edgeguard_first_imported_at",
        "x_edgeguard_last_updated",
        "x_edgeguard_first_seen_inferred",
        # Zones and MISP traceability
        "x_edgeguard_zones",
        "x_edgeguard_misp_event_ids",
        "x_edgeguard_misp_attribute_ids",
        # Relationship provenance on SROs (2026-10): who asserts the link, which records, which kind of evidence
        "x_edgeguard_match_type",
        "x_edgeguard_sources",
        "x_edgeguard_source_refs",
        # Explainability (2026-10): ids the sources cited before an ATT&CK revocation moved the link,
        # and the actor nodes folded into an intrusion-set
        "x_edgeguard_cited_ids",
        "x_edgeguard_merged_from",
        # Explainability (2026-10-16): the relationship types a campaign link rests on
        "x_edgeguard_evidence_types",
        # Explainability (2026-10-16): the source whose text an SDO's description is
        "x_edgeguard_description_source",
    )
    + tuple(stix_key for _, stix_key in _VULNERABILITY_PROMOTED_FIELDS)
    + tuple(stix_key for _, stix_key in _INDICATOR_AGING_FIELDS)
)

_EXTENSION_PREFIX = "x_edgeguard_"

# STIX 2.1 TLP marking definitions. The identifiers are fixed by the
# specification (section 7.2.1.4) and ``stix2`` rejects any TLP
# marking-definition that deviates from them, so the SDK constants are
# the single source. Node ``tlp`` values follow the write-side ladder in
# ``neo4j_client._tlp_rank_case`` (red > amber+strict > amber > green >
# white = clear). Levels without a STIX 2.1 built-in map to the nearest
# built-in that is at least as restrictive: ``clear`` is the TLP 2.0 name
# of WHITE; ``amber+strict`` has no 2.1 equivalent and is exported as RED
# rather than loosened to AMBER.
_TLP_MARKING_BY_LEVEL: Dict[str, Any] = {
    "white": stix2.TLP_WHITE,
    "clear": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": stix2.TLP_RED,
    "red": stix2.TLP_RED,
}
_TLP_MARKINGS_BY_ID: Dict[str, Any] = {
    m.id: m for m in (stix2.TLP_WHITE, stix2.TLP_GREEN, stix2.TLP_AMBER, stix2.TLP_RED)
}
_TLP_RANK_BY_ID: Dict[str, int] = {
    stix2.TLP_WHITE.id: 1,
    stix2.TLP_GREEN.id: 2,
    stix2.TLP_AMBER.id: 3,
    stix2.TLP_RED.id: 4,
}


# Set once the fallback to TLP:WHITE in ``_default_tlp_marking_id`` has been
# logged, so a misconfigured deployment produces one warning per process
# rather than one per exported node.
_TLP_DEFAULT_WARNED = False


def _default_tlp_marking_id() -> str:
    """Marking applied when a node carries no ``tlp`` property.

    This is the deployment default ``config.EDGEGUARD_DEFAULT_TLP``
    (``white`` unless configured) — the same value the write side stamps
    on nodes that arrive without a TLP, so export and storage agree. When
    the configuration cannot be read, or names a level outside the TLP
    ladder, TLP:WHITE is applied and a warning is logged once per process.
    """
    global _TLP_DEFAULT_WARNED
    level = "white"
    problem: Optional[str] = None
    try:
        import config

        level = str(getattr(config, "EDGEGUARD_DEFAULT_TLP", "white") or "white").strip().lower()
    except Exception as exc:
        problem = f"configuration could not be read ({type(exc).__name__}: {exc})"
    marking = _TLP_MARKING_BY_LEVEL.get(level)
    if marking is None:
        problem = problem or f"configured level {level!r} is not a TLP level"
        marking = stix2.TLP_WHITE
    if problem and not _TLP_DEFAULT_WARNED:
        _TLP_DEFAULT_WARNED = True
        logger.warning(
            "[stix-export] Deployment default TLP (EDGEGUARD_DEFAULT_TLP) unavailable: %s; "
            "TLP:WHITE applied to nodes without a tlp property",
            problem,
        )
    return marking.id


def _marking_ref_for(props: Dict[str, Any]) -> str:
    """Return the TLP ``marking-definition`` id for a node's ``tlp`` property.

    A node with no TLP receives the deployment default (see
    ``_default_tlp_marking_id``). A non-empty value outside the known
    ladder is exported as TLP:AMBER — restricted rather than public — and
    logged, because the level was asserted by a source but cannot be
    interpreted.
    """
    raw = props.get("tlp")
    level = str(raw).strip().lower() if raw is not None else ""
    if not level:
        # Node carries no TLP: apply the deployment default.
        return _default_tlp_marking_id()
    marking = _TLP_MARKING_BY_LEVEL.get(level)
    if marking is None:
        logger.warning(
            "[stix-export] Unrecognised TLP level %r on exported node; marking the SDO TLP:AMBER",
            raw,
        )
        return stix2.TLP_AMBER.id
    return marking.id


def _most_restrictive_marking(*marking_ids: Optional[str]) -> str:
    """Return the highest-ranked TLP marking id among ``marking_ids``."""
    known = [m for m in marking_ids if m in _TLP_RANK_BY_ID]
    if not known:
        return _default_tlp_marking_id()
    return max(known, key=lambda m: _TLP_RANK_BY_ID[m])


def _relationship_marking_ref(rel: Optional[Dict[str, Any]]) -> Optional[str]:
    """The TLP marking id of a graph relationship's own ``tlp``; ``None`` when it has none (2026-10).

    Curated-package links carry the package's level in ``r.tlp``: the link and the provenance on
    it are as restricted as the package, whatever the endpoints' markings. A level outside the
    ladder is exported as TLP:AMBER, like an unrecognised node level.
    """
    raw = (rel or {}).get("tlp")
    level = str(raw).strip().lower() if raw is not None else ""
    if not level:
        return None
    marking = _TLP_MARKING_BY_LEVEL.get(level)
    if marking is None:
        logger.warning(
            "[stix-export] Unrecognised TLP level %r on an exported relationship; marking the SRO TLP:AMBER", raw
        )
        return stix2.TLP_AMBER.id
    return marking.id


def _relationship_tlp_rank(level: str) -> int:
    """Rank of a relationship TLP level on the marking ladder (0 when it has none)."""
    marking_id = _relationship_marking_ref({"tlp": level})
    return _TLP_RANK_BY_ID.get(marking_id, 0) if marking_id else 0


# STIX 2.1 ``industry-sector-ov`` values for EdgeGuard zones. ``global``
# is the "no sector" marker and has no vocabulary value; sectors outside
# this map are exported as a named identity without ``sectors``.
_INDUSTRY_SECTOR_OV: Dict[str, str] = {
    "healthcare": "healthcare",
    "energy": "energy",
    "finance": "financial-services",
}


def _industry_sectors(name: str) -> Optional[List[str]]:
    """Map an EdgeGuard sector name to ``industry-sector-ov`` (``None`` when unmapped)."""
    key = (name or "").strip().lower()
    vocab = _INDUSTRY_SECTOR_OV.get(key)
    return [vocab] if vocab else None


# Graph edge → STIX 2.1 relationship, keyed by (edge type, source SDO type,
# target SDO type) in GRAPH direction; the value is (relationship_type,
# reverse). ``reverse=True`` swaps source and target because the STIX 2.1
# relationship summary table defines the pair in the opposite direction.
# Pairs the table does not define at all are emitted as ``related-to``.
#
# - indicator → malware / attack-pattern: ``indicates`` (table: indicator
#   indicates attack-pattern, campaign, infrastructure, intrusion-set,
#   malware, threat-actor, tool).
# - indicator → vulnerability (EXPLOITS): the table defines no
#   indicator → vulnerability pair, so ``related-to``.
# - indicator → identity (TARGETS): ``indicator`` has no ``targets``
#   relationship in the table, so ``related-to``.
# - malware → intrusion-set (ATTRIBUTED_TO): ``attributed-to`` is defined
#   only for campaign / intrusion-set sources. MITRE ATT&CK — the origin
#   of these edges — models the pair as ``intrusion-set uses malware``,
#   which the table defines; the SRO is therefore reversed.
# - intrusion-set / malware / tool → attack-pattern: ``uses``.
# - intrusion-set → campaign (RUNS): the table defines ``campaign
#   attributed-to intrusion-set``; reversed.
# - vulnerability → identity (AFFECTS): ``vulnerability`` has no outgoing
#   relationships in the table, so ``related-to``.
_SRO_BY_EDGE: Dict[Tuple[str, str, str], Tuple[str, bool]] = {
    ("INDICATES", "indicator", "malware"): ("indicates", False),
    ("USES_TECHNIQUE", "indicator", "attack-pattern"): ("indicates", False),
    ("EXPLOITS", "indicator", "vulnerability"): ("related-to", False),
    ("TARGETS", "indicator", "identity"): ("related-to", False),
    ("ATTRIBUTED_TO", "malware", "intrusion-set"): ("uses", True),
    ("EMPLOYS_TECHNIQUE", "intrusion-set", "attack-pattern"): ("uses", False),
    ("IMPLEMENTS_TECHNIQUE", "malware", "attack-pattern"): ("uses", False),
    ("IMPLEMENTS_TECHNIQUE", "tool", "attack-pattern"): ("uses", False),
    ("RUNS", "intrusion-set", "campaign"): ("attributed-to", True),
    ("AFFECTS", "vulnerability", "identity"): ("related-to", False),
    # 2026-10: the rest of the graph's relationships (every one EdgeGuard writes that has a
    # STIX form; IN_TACTIC is a kill-chain phase on the attack-pattern, not an SRO).
    # - intrusion-set → malware / tool (USES_MALWARE / USES_TOOL, MITRE's group → software): ``uses``.
    # - attack-pattern → attack-pattern (SUBTECHNIQUE_OF): ``subtechnique-of``, the relationship
    #   type MITRE ATT&CK's own STIX uses (not in the 2.1 summary table, which leaves the type open).
    # - malware → vulnerability (EXPLOITS): ``exploits``; intrusion-set → vulnerability: the table
    #   has no ``exploits`` for intrusion-set, so ``targets``.
    # - intrusion-set / malware → identity (TARGETS a sector): ``targets``.
    # - malware → campaign (PART_OF_CAMPAIGN): the table defines ``campaign uses malware``; reversed.
    #   indicator → campaign: ``indicates``.
    ("USES_MALWARE", "intrusion-set", "malware"): ("uses", False),
    ("USES_TOOL", "intrusion-set", "tool"): ("uses", False),
    ("SUBTECHNIQUE_OF", "attack-pattern", "attack-pattern"): ("subtechnique-of", False),
    ("EXPLOITS", "malware", "vulnerability"): ("exploits", False),
    ("EXPLOITS", "intrusion-set", "vulnerability"): ("targets", False),
    ("TARGETS", "intrusion-set", "identity"): ("targets", False),
    ("TARGETS", "malware", "identity"): ("targets", False),
    ("PART_OF_CAMPAIGN", "malware", "campaign"): ("uses", True),
    ("PART_OF_CAMPAIGN", "indicator", "campaign"): ("indicates", False),
}


def stix_relationship_mappings() -> List[Dict[str, str]]:
    """``_SRO_BY_EDGE`` as rows for the ``GET /stix/types`` discovery answer (2026-10).

    ``graph_source`` / ``graph_target`` are the STIX types of the graph relationship's endpoints in
    graph direction; ``source`` / ``target`` are the SRO's, reversed where the specification models
    the pair the other way round. Derived from the table itself, so the discovery answer cannot
    drift from what ``_edge_to_sro`` emits; a pair absent from the table is exported as
    ``related-to`` in graph direction.
    """
    rows: List[Dict[str, str]] = []
    for (edge_type, graph_source, graph_target), (relationship_type, reverse) in sorted(_SRO_BY_EDGE.items()):
        rows.append(
            {
                "graph_relationship": edge_type,
                "graph_source": graph_source,
                "graph_target": graph_target,
                "relationship_type": relationship_type,
                "source": graph_target if reverse else graph_source,
                "target": graph_source if reverse else graph_target,
            }
        )
    return rows


# Relationship provenance on SROs (2026-10). Graph relationships carry ``sources`` (who
# asserts them), ``source_refs`` (``"<source>:<record id>"``), ``misp_event_ids`` and
# ``match_type``; the SRO carries them as ``x_edgeguard_*`` properties, the confidence as the
# STIX ``confidence`` (0–100), and each record id as an ``external_reference`` — with a link
# for the sources whose records have a public page.
_RECORD_URL_TEMPLATES: Dict[str, str] = {
    "alienvault_otx": "https://otx.alienvault.com/pulse/{id}",
    "threatfox": "https://threatfox.abuse.ch/ioc/{id}/",
    "urlhaus": "https://urlhaus.abuse.ch/url/{id}/",
}
# ATT&CK id prefix → page (``TA`` before ``T``); sub-technique ``T1566.001`` → ``T1566/001``.
_ATTACK_URL_PATHS: Tuple[Tuple[str, str], ...] = (
    ("TA", "tactics"),
    ("T", "techniques"),
    ("G", "groups"),
    ("S", "software"),
    ("M", "mitigations"),
    ("C", "campaigns"),
)
# Bounds per SRO: an OTX-reported link can name hundreds of pulses.
_MAX_EXTERNAL_REFERENCES = 20
_MAX_SOURCE_REFS = 200
# Relationship property → SRO extension property, with its bound (``None`` = unbounded).
_SRO_PROVENANCE_LISTS: Tuple[Tuple[str, str, Optional[int]], ...] = (
    ("sources", "x_edgeguard_sources", None),
    ("source_refs", "x_edgeguard_source_refs", _MAX_SOURCE_REFS),
    ("misp_event_ids", "x_edgeguard_misp_event_ids", None),
    # 2026-10 (explainability): only on links a revoked ATT&CK id led to
    ("cited_ids", "x_edgeguard_cited_ids", None),
    # 2026-10-16 (explainability): only on campaign links (RUNS, PART_OF_CAMPAIGN), the relationship
    # types they rest on (ATTRIBUTED_TO, USES_MALWARE and, on an indicator's link, INDICATES)
    ("evidence_types", "x_edgeguard_evidence_types", None),
)


# ---------------------------------------------------------------------------
# Pattern builder — STIX 2.1 patterning grammar (section 9)
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_SSDEEP_RE = re.compile(r"^\d+:[A-Za-z0-9/+]*:[A-Za-z0-9/+]*$")
_TLSH_RE = re.compile(r"^(T1)?[A-Fa-f0-9]{70}$")
# hash-algorithm-ov key by hexadecimal digest length.
_HASH_ALGORITHM_BY_HEX_LENGTH: Dict[int, str] = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
_HEX_LENGTH_BY_HASH_ALGORITHM: Dict[str, int] = {a: n for n, a in _HASH_ALGORITHM_BY_HEX_LENGTH.items()}
# Declared EdgeGuard / MISP hash types and their vocabulary key.
_HASH_ALGORITHM_BY_TYPE: Dict[str, str] = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha-1": "SHA-1",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "ssdeep": "SSDEEP",
    "tlsh": "TLSH",
}
_HASH_INDICATOR_TYPES = frozenset(_HASH_ALGORITHM_BY_TYPE) | {"hash"}
# TLS certificate fingerprints (SSL Blacklist, 2026-10) and the declared hash type of each: a
# digest of a certificate, so the pattern is on ``x509-certificate``, not on ``file``.
_X509_FINGERPRINT_HASH_TYPES: Dict[str, str] = {"x509-fingerprint-sha1": "sha1"}
# IP address types: the declared family applies only when the value is not an address (see
# ``_build_pattern``).
_IPV4_TYPES = frozenset({"ipv4", "ip", "ip-src", "ip-dst", "ip-src|port", "ip-dst|port"})
_IPV6_TYPES = frozenset({"ipv6"})
_DOMAIN_TYPES = frozenset({"domain", "hostname"})
_URL_TYPES = frozenset({"url", "uri"})
_EMAIL_TYPES = frozenset({"email", "email-src", "email-dst", "email-addr"})
_FILENAME_TYPES = frozenset({"filename", "file-name"})
# Custom hash key used when the algorithm cannot be determined. Permitted
# by the ``hashes`` type rules (3-250 ASCII characters from
# ``[A-Za-z0-9_-]``) and preferable to mislabelling the digest.
_UNKNOWN_HASH_KEY = "UNKNOWN"


def _escape_stix_value(value: str) -> str:
    """Escape a value for a single-quoted STIX pattern string literal (backslash, then quote)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _hash_algorithm(indicator_type: str, value: str) -> str:
    """Pick the ``hashes`` key for a digest (``file`` and ``x509-certificate`` patterns).

    The declared type wins when the value matches its format; otherwise
    the format decides (32/40/64/128 hexadecimal characters, SSDEEP and
    TLSH shapes). A digest that matches none of these is keyed
    ``UNKNOWN`` so the pattern stays valid without asserting an
    algorithm — the pattern validator rejects a digest whose format does
    not match the declared algorithm.
    """
    digest = value.strip()
    is_hex = bool(_HEX_RE.match(digest))
    declared = _HASH_ALGORITHM_BY_TYPE.get(indicator_type)
    if declared is not None:
        expected_len = _HEX_LENGTH_BY_HASH_ALGORITHM.get(declared)
        if expected_len is not None and is_hex and len(digest) == expected_len:
            return declared
        if declared == "SSDEEP" and _SSDEEP_RE.match(digest):
            return declared
        if declared == "TLSH" and _TLSH_RE.match(digest):
            return declared
    if is_hex and len(digest) in _HASH_ALGORITHM_BY_HEX_LENGTH:
        return _HASH_ALGORITHM_BY_HEX_LENGTH[len(digest)]
    if _SSDEEP_RE.match(digest):
        return "SSDEEP"
    if _TLSH_RE.match(digest):
        return "TLSH"
    return _UNKNOWN_HASH_KEY


def _build_pattern(indicator_type: Optional[str], value: str) -> str:
    """Build a STIX 2.1 pattern literal for an indicator row.

    Observable mapping (STIX 2.1 section 6): IP addresses → ``ipv4-addr``
    or ``ipv6-addr`` by the address itself (the declared family applies
    only to a value that is not an address), domain/hostname →
    ``domain-name``, URL → ``url``, e-mail address → ``email-addr``,
    digests → ``file:hashes.'<ALGO>'`` (algorithm from the declared type or
    the digest format, see ``_hash_algorithm``), TLS certificate
    fingerprints → ``x509-certificate:hashes.'<ALGO>'``, file names →
    ``file:name``. A blank or unrecognised type is inferred from the
    value's shape with the shared ``ioc_normalize.infer_indicator_type``
    helper; when that fails the pattern uses the custom observable type
    ``x-edgeguard-observable``, which is valid under the patterning grammar
    and states that no standard object type applies instead of
    mislabelling the value. STIX requires a pattern on every Indicator, so
    this never returns ``None``.
    """
    itype = (indicator_type or "").strip().lower()
    raw = value if isinstance(value, str) else str(value)
    recognised = (
        _HASH_INDICATOR_TYPES | _IPV4_TYPES | _IPV6_TYPES | _DOMAIN_TYPES | _URL_TYPES | _EMAIL_TYPES | _FILENAME_TYPES
    )
    if itype not in recognised and itype not in _X509_FINGERPRINT_HASH_TYPES:
        from ioc_normalize import infer_indicator_type

        itype = infer_indicator_type(raw) or itype
    safe = _escape_stix_value(raw.strip())
    if itype in _IPV4_TYPES or itype in _IPV6_TYPES:
        from ioc_normalize import ip_address_type

        # 2026-10: MISP keeps IPv4 and IPv6 under one ``ip-src`` / ``ip-dst`` type, and graphs
        # synced before then hold IPv6 addresses typed ``ipv4``: the address decides.
        family = ip_address_type(raw) or ("ipv6" if itype in _IPV6_TYPES else "ipv4")
        # ``ip-src|port`` style values carry a port suffix; the address part is the observable.
        address = safe.split("|", 1)[0]
        return f"[{family}-addr:value = '{address}']"
    if itype in _X509_FINGERPRINT_HASH_TYPES:
        algorithm = _hash_algorithm(_X509_FINGERPRINT_HASH_TYPES[itype], raw)
        return f"[x509-certificate:hashes.'{algorithm}' = '{safe}']"
    if itype in _DOMAIN_TYPES:
        return f"[domain-name:value = '{safe}']"
    if itype in _URL_TYPES:
        return f"[url:value = '{safe}']"
    if itype in _EMAIL_TYPES:
        return f"[email-addr:value = '{safe}']"
    if itype in _HASH_INDICATOR_TYPES:
        algorithm = _hash_algorithm(itype, raw)
        return f"[file:hashes.'{algorithm}' = '{safe}']"
    if itype in _FILENAME_TYPES:
        return f"[file:name = '{safe}']"
    return f"[x-edgeguard-observable:value = '{safe}']"


# ---------------------------------------------------------------------------
# Main exporter
# ---------------------------------------------------------------------------


class StixExporter:
    """Build STIX 2.1 bundles from the EdgeGuard threat-intel graph.

    Each ``export_*`` method returns a ``dict`` (the serialised bundle)
    ready to be handed to a FastAPI response. Returning a dict rather
    than a ``stix2.Bundle`` instance keeps the API layer free of a hard
    dependency on the SDK's object classes.
    """

    # MIME type ResilMesh expects for STIX 2.1 payloads.
    MEDIA_TYPE = "application/stix+json;version=2.1"

    def __init__(self, neo4j_client: Any) -> None:
        """Wrap a connected Neo4jClient (or any object exposing ``.driver``)."""
        self.client = neo4j_client
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1 — triple-converged
        # HIGH): per-call cache for the source-truthful edge aggregate.
        # Without it, ``_node_to_sdo`` runs one Cypher round-trip PER node
        # in the bundle — depth=2 with 20 nodes = 21 RTTs ≈ 100-200 ms
        # latency on every ResilMesh enrichment call (DoS-able by a single
        # depth-heavy export request). The cache is keyed by
        # (label, sorted-natural-key-tuple) so repeat lookups for the same
        # entity within one bundle don't re-query.
        # Cleared at the start of every public ``export_*`` method.
        self._aggregate_cache: Dict[Any, Dict[str, Any]] = {}
        # TLP marking id per emitted SDO id, so SROs can inherit the most
        # restrictive marking of their endpoints. Bundle-scoped like the
        # aggregate cache.
        self._marking_by_id: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_indicator(self, value: str, depth: int = _DEFAULT_DEPTH, limit: int = _DEFAULT_LIMIT) -> Dict[str, Any]:
        """Bundle one indicator + its 1-hop neighbourhood.

        Neighbourhood: INDICATES→Malware, EXPLOITS→CVE/Vulnerability,
        USES_TECHNIQUE→Technique, TARGETS→Sector, PART_OF_CAMPAIGN→Campaign.
        Every SRO carries the provenance of its graph relationship
        (``_edge_to_sro``, 2026-10).

        ``depth=1`` returns a minimal bundle with only the indicator's
        primary relation type (``INDICATES→Malware``). ``depth=2``
        (the default) returns the full 1-hop neighborhood across all
        four relation types. The Cypher always fetches everything —
        ``depth`` is a Python-side filter that saves bundle size, not
        query time. A future optimisation would push the filter into
        the query itself.

        ``limit`` bounds every related-node collection (malware, CVEs,
        techniques, sectors) inside the query; it is clamped to
        ``[1, _MAX_LIMIT]``. Each collection is ordered by its natural
        key before the limit is applied so truncation is deterministic.
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        limit = _clamp_limit(limit)
        # Each OPTIONAL MATCH is aggregated into a collect() before the next
        # one starts. Without the WITH ... collect() fence pattern the four
        # OPTIONAL MATCH clauses form a Cartesian product — every row from
        # stage N is multiplied by every row in stage N+1, so a well-
        # connected indicator (a C2 IP with 10 malware × 20 CVEs × 15
        # techniques × 5 sectors = 15 000 intermediate rows) blows up long
        # before the outer DISTINCT collapses them. Same pattern as the
        # round-2/round-4 fixes to export_threat_actor and export_technique.
        # The seed is reduced to one row (the unique key is
        # (indicator_type, value), so one value may exist under several
        # types) and every stage is ordered and limited before it is
        # collected. A CVE may exist as twin ``CVE`` / ``Vulnerability``
        # nodes sharing one cve_id (and one STIX id); the EXPLOITS stage
        # keeps one node per cve_id — the ``CVE`` twin when present, the
        # same preference as ``export_cve`` — before the bound, so twins
        # never take two of the ``limit`` slots; the edges to both twins
        # stay with it and their provenance is merged (``_merge_rel_props``).
        rows = self._run(
            """
            MATCH (i:Indicator {value: $value})
            WHERE (i.edgeguard_managed = true OR i.edgeguard_enriched = true)
            WITH i ORDER BY i.indicator_type LIMIT 1
            OPTIONAL MATCH (i)-[r1:INDICATES]->(m:Malware)
              WHERE (m.edgeguard_managed = true OR m.edgeguard_enriched = true)
            WITH i, m, r1 ORDER BY m.name LIMIT $limit
            WITH i, collect({n: m, r: properties(r1)}) AS malware
            OPTIONAL MATCH (i)-[r2:EXPLOITS]->(v)
              WHERE (v:CVE OR v:Vulnerability)
                AND (v.edgeguard_managed = true OR v.edgeguard_enriched = true)
            WITH i, malware, v, r2 ORDER BY (CASE WHEN v:CVE THEN 0 ELSE 1 END)
            WITH i, malware, v.cve_id AS cve_key, head(collect(v)) AS vn, collect(properties(r2)) AS r2s
            WITH i, malware, {n: vn, r: r2s} AS vr ORDER BY vr.n.cve_id LIMIT $limit
            WITH i, malware, collect(vr) AS vulns
            OPTIONAL MATCH (i)-[r3:USES_TECHNIQUE]->(t:Technique)
              WHERE (t.edgeguard_managed = true OR t.edgeguard_enriched = true)
            WITH i, malware, vulns, t, r3 ORDER BY t.mitre_id LIMIT $limit
            WITH i, malware, vulns, collect({n: t, r: properties(r3)}) AS techniques
            OPTIONAL MATCH (i)-[r4:TARGETS]->(s:Sector)
              WHERE (s.edgeguard_managed = true OR s.edgeguard_enriched = true)
            WITH i, malware, vulns, techniques, s, r4 ORDER BY s.name LIMIT $limit
            WITH i, malware, vulns, techniques, collect({n: s, r: properties(r4)}) AS sectors
            OPTIONAL MATCH (i)-[r5:PART_OF_CAMPAIGN]->(c:Campaign)
              WHERE (c.edgeguard_managed = true OR c.edgeguard_enriched = true)
            WITH i, malware, vulns, techniques, sectors, c, r5 ORDER BY c.name LIMIT $limit
            RETURN i AS seed,
                   malware,
                   vulns,
                   techniques,
                   sectors,
                   collect({n: c, r: properties(r5)}) AS campaigns
            """,
            {"value": value, "limit": limit},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        malware = _with_rels(row["malware"])
        vulns = _with_rels(row["vulns"]) if depth >= 2 else []
        techniques = _with_rels(row["techniques"]) if depth >= 2 else []
        sectors = _with_rels(row["sectors"]) if depth >= 2 else []
        campaigns = _with_rels(row.get("campaigns")) if depth >= 2 else []
        self._prefetch_source_aggregates(
            [("Indicator", dict(seed))]
            + [("Malware", m) for m, _ in malware]
            + [("Vulnerability", v) for v, _ in vulns]
            + [("Technique", t) for t, _ in techniques]
            + [("Sector", s) for s, _ in sectors]
            + [("Campaign", c) for c, _ in campaigns]
        )

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Indicator", dict(seed))
        self._add(objects, seed_sdo)

        for md, rel in malware:
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            self._add(objects, self._edge_to_sro("INDICATES", seed_sdo["id"], m_sdo["id"], rel))
        # depth=1 short-circuit: bundle contains only the primary
        # relation type (INDICATES→Malware). See the docstring above.
        if depth < 2:
            return self._bundle(objects.values())
        for vd, rel in vulns:
            v_sdo = self._node_to_sdo("Vulnerability", vd)
            self._add(objects, v_sdo)
            self._add(objects, self._edge_to_sro("EXPLOITS", seed_sdo["id"], v_sdo["id"], rel))
        for td, rel in techniques:
            t_sdo = self._node_to_sdo("Technique", td)
            self._add(objects, t_sdo)
            self._add(objects, self._edge_to_sro("USES_TECHNIQUE", seed_sdo["id"], t_sdo["id"], rel))
        for sd, rel in sectors:
            s_sdo = self._node_to_sdo("Sector", sd)
            self._add(objects, s_sdo)
            self._add(objects, self._edge_to_sro("TARGETS", seed_sdo["id"], s_sdo["id"], rel))
        for cd, rel in campaigns:
            c_sdo = self._node_to_sdo("Campaign", cd)
            self._add(objects, c_sdo)
            self._add(objects, self._edge_to_sro("PART_OF_CAMPAIGN", seed_sdo["id"], c_sdo["id"], rel))

        return self._bundle(objects.values())

    def export_threat_actor(
        self, name: str, depth: int = _DEFAULT_DEPTH, limit: int = _DEFAULT_LIMIT
    ) -> Dict[str, Any]:
        """Bundle centred on a ThreatActor + attributed malware + TTPs + campaigns.

        ``depth=1`` returns only actor + attributed malware (primary
        relation). ``depth=2`` (default) adds actor techniques, the
        malware→technique chain, campaigns and (2026-10) the actor's
        ``USES_MALWARE`` / ``USES_TOOL`` software, the CVEs it ``EXPLOITS``
        and the sectors it ``TARGETS``. See ``export_indicator``
        for the general semantics; ``limit`` bounds each collection
        (malware, actor techniques, malware→technique pairs, campaigns).

        Actor resolution is case-insensitive and alias-aware, identical to
        ``GET /actors/{name}/summary``: actor names are stored lower-case
        at write time (``node_identity.canonicalize_merge_key``) while
        aliases keep display case, hence ``toLower(trim(...))`` on both
        the input and each alias. When several actors match, a canonical
        name hit wins over an alias-only hit, then the lowest name, so
        the seed is deterministic.

        The query uses a ``WITH ... collect(DISTINCT ...)`` step between
        every ``OPTIONAL MATCH`` to avoid the Cartesian product that
        would otherwise arise from chaining 5 optional matches. Without
        the intermediate aggregation, Neo4j produces
        O(malware × actor_tech × mal_tech × campaigns) intermediate
        rows before the final ``DISTINCT`` collapses them — a
        well-connected actor group (e.g. APT28) would generate
        thousands of throwaway rows, materially impacting query
        latency. Aggregating at each step keeps the row count bounded
        by the size of one collection at a time.

        The malware → technique pairs are bounded inside a ``CALL``
        subquery (variable scope clause, Neo4j 5.23+): a plain ``MATCH``
        there means malware without ``IMPLEMENTS_TECHNIQUE`` edges
        produces no row and cannot consume a slot of the bound, while
        the aggregating ``RETURN collect(...)`` always yields exactly one
        row, so an actor without any such pair still exports.
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        limit = _clamp_limit(limit)
        rows = self._run(
            """
            MATCH (a:ThreatActor)
            WHERE (a.edgeguard_managed = true OR a.edgeguard_enriched = true)
              AND (a.name = toLower(trim($name))
                   OR any(x IN coalesce(a.aliases, []) WHERE toLower(trim(x)) = toLower(trim($name))))
            WITH a, (CASE WHEN a.name = toLower(trim($name)) THEN 0 ELSE 1 END) AS _match_rank
            ORDER BY _match_rank, a.name
            LIMIT 1
            WITH a
            OPTIONAL MATCH (m:Malware)-[r1:ATTRIBUTED_TO]->(a)
              WHERE (m.edgeguard_managed = true OR m.edgeguard_enriched = true)
            WITH a, m, r1 ORDER BY m.name LIMIT $limit
            WITH a, collect({n: m, r: properties(r1)}) AS malware
            OPTIONAL MATCH (a)-[r2:EMPLOYS_TECHNIQUE]->(t:Technique)
              WHERE (t.edgeguard_managed = true OR t.edgeguard_enriched = true)
            WITH a, malware, t, r2 ORDER BY t.mitre_id LIMIT $limit
            WITH a, malware, collect({n: t, r: properties(r2)}) AS actor_tech
            CALL (malware) {
                UNWIND malware AS m_pair
                WITH m_pair.n AS m_each
                WHERE m_each IS NOT NULL
                MATCH (m_each)-[r3:IMPLEMENTS_TECHNIQUE]->(mt:Technique)
                  WHERE (mt.edgeguard_managed = true OR mt.edgeguard_enriched = true)
                WITH m_each, mt, r3 ORDER BY m_each.name, mt.mitre_id LIMIT $limit
                RETURN collect({m: m_each, t: mt, r: properties(r3)}) AS mal_tech
            }
            OPTIONAL MATCH (a)-[r4:RUNS]->(c:Campaign)
              WHERE (c.edgeguard_managed = true OR c.edgeguard_enriched = true)
            WITH a, malware, actor_tech, mal_tech, c, r4 ORDER BY c.name LIMIT $limit
            WITH a, malware, actor_tech, mal_tech, collect({n: c, r: properties(r4)}) AS campaigns
            OPTIONAL MATCH (a)-[r5:USES_MALWARE]->(um:Malware)
              WHERE (um.edgeguard_managed = true OR um.edgeguard_enriched = true)
            WITH a, malware, actor_tech, mal_tech, campaigns, um, r5 ORDER BY um.name LIMIT $limit
            WITH a, malware, actor_tech, mal_tech, campaigns, collect({n: um, r: properties(r5)}) AS uses_malware
            OPTIONAL MATCH (a)-[r6:USES_TOOL]->(tool:Tool)
              WHERE (tool.edgeguard_managed = true OR tool.edgeguard_enriched = true)
            WITH a, malware, actor_tech, mal_tech, campaigns, uses_malware, tool, r6
                 ORDER BY tool.mitre_id, tool.name LIMIT $limit
            WITH a, malware, actor_tech, mal_tech, campaigns, uses_malware,
                 collect({n: tool, r: properties(r6)}) AS tools
            OPTIONAL MATCH (a)-[r7:EXPLOITS]->(cve:CVE)
              WHERE (cve.edgeguard_managed = true OR cve.edgeguard_enriched = true)
            WITH a, malware, actor_tech, mal_tech, campaigns, uses_malware, tools, cve, r7
                 ORDER BY cve.cve_id LIMIT $limit
            WITH a, malware, actor_tech, mal_tech, campaigns, uses_malware, tools,
                 collect({n: cve, r: properties(r7)}) AS exploits
            OPTIONAL MATCH (a)-[r8:TARGETS]->(s:Sector)
              WHERE (s.edgeguard_managed = true OR s.edgeguard_enriched = true)
            WITH a, malware, actor_tech, mal_tech, campaigns, uses_malware, tools, exploits, s, r8
                 ORDER BY s.name LIMIT $limit
            RETURN a AS seed,
                   malware,
                   actor_tech,
                   mal_tech,
                   campaigns,
                   uses_malware,
                   tools,
                   exploits,
                   collect({n: s, r: properties(r8)}) AS sectors
            """,
            {"name": name, "limit": limit},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        malware = _with_rels(row["malware"])
        actor_tech = _with_rels(row["actor_tech"]) if depth >= 2 else []
        mal_tech_pairs: List[Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]] = []
        if depth >= 2:
            for pair in row["mal_tech"] or []:
                m = pair.get("m") if isinstance(pair, dict) else None
                t = pair.get("t") if isinstance(pair, dict) else None
                if m and t:
                    mal_tech_pairs.append((dict(m), dict(t), dict(pair.get("r") or {})))
        campaigns = _with_rels(row["campaigns"]) if depth >= 2 else []
        uses_malware = _with_rels(row.get("uses_malware")) if depth >= 2 else []
        tools = _with_rels(row.get("tools")) if depth >= 2 else []
        exploits = _with_rels(row.get("exploits")) if depth >= 2 else []
        sectors = _with_rels(row.get("sectors")) if depth >= 2 else []
        self._prefetch_source_aggregates(
            [("ThreatActor", dict(seed))]
            + [("Malware", m) for m, _ in malware]
            + [("Technique", t) for t, _ in actor_tech]
            + [("Malware", m) for m, _, _ in mal_tech_pairs]
            + [("Technique", t) for _, t, _ in mal_tech_pairs]
            + [("Campaign", c) for c, _ in campaigns]
            + [("Malware", m) for m, _ in uses_malware]
            + [("Tool", t) for t, _ in tools]
            + [("Vulnerability", v) for v, _ in exploits]
            + [("Sector", sd) for sd, _ in sectors]
        )

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("ThreatActor", dict(seed))
        self._add(objects, seed_sdo)

        mal_ids: Dict[str, str] = {}
        for md, rel in malware:
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            mal_ids[md.get("name", "")] = m_sdo["id"]
            # Graph direction: (Malware)-[:ATTRIBUTED_TO]->(ThreatActor).
            # ``_edge_to_sro`` emits the STIX 2.1 form of this pair,
            # ``intrusion-set uses malware`` (MITRE ATT&CK convention).
            self._add(objects, self._edge_to_sro("ATTRIBUTED_TO", m_sdo["id"], seed_sdo["id"], rel))

        # depth=1: primary relation only (actor + attributed malware).
        if depth < 2:
            return self._bundle(objects.values())

        for td, rel in actor_tech:
            t_sdo = self._node_to_sdo("Technique", td)
            self._add(objects, t_sdo)
            self._add(objects, self._edge_to_sro("EMPLOYS_TECHNIQUE", seed_sdo["id"], t_sdo["id"], rel))
        for md, td, rel in mal_tech_pairs:
            m_sdo_id = mal_ids.get(md.get("name", "")) or self._add(objects, self._node_to_sdo("Malware", md))
            t_sdo = self._node_to_sdo("Technique", td)
            self._add(objects, t_sdo)
            # _add returns Optional[str] (None when the sdo is None or was
            # deduplicated away), so guard before building the SRO. This
            # is a no-op in practice because the Malware SDO always gets
            # an ID, but it keeps mypy honest and avoids a crash if the
            # invariant ever drifts.
            if m_sdo_id is None:
                continue
            self._add(objects, self._edge_to_sro("IMPLEMENTS_TECHNIQUE", m_sdo_id, t_sdo["id"], rel))
        for cd, rel in campaigns:
            c_sdo = self._node_to_sdo("Campaign", cd)
            self._add(objects, c_sdo)
            # The graph edge is (ThreatActor)-[:RUNS]->(Campaign) — the
            # actor owns/operates the campaign. STIX 2.1 expresses this
            # as `relationship_type: attributed-to` with source_ref on
            # the campaign and target_ref on the intrusion-set; the
            # reversal is performed by ``_edge_to_sro``. See
            # https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h
            self._add(objects, self._edge_to_sro("RUNS", seed_sdo["id"], c_sdo["id"], rel))
        # 2026-10: the actor's MITRE software, the CVEs it exploits and the sectors it targets
        # (curated-package claims included — ``x_edgeguard_sources`` says who asserts each).
        for md, rel in uses_malware:
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            self._add(objects, self._edge_to_sro("USES_MALWARE", seed_sdo["id"], m_sdo["id"], rel))
        for tool_d, rel in tools:
            tool_sdo = self._node_to_sdo("Tool", tool_d)
            self._add(objects, tool_sdo)
            self._add(objects, self._edge_to_sro("USES_TOOL", seed_sdo["id"], tool_sdo["id"], rel))
        for vd, rel in exploits:
            v_sdo = self._node_to_sdo("Vulnerability", vd)
            self._add(objects, v_sdo)
            self._add(objects, self._edge_to_sro("EXPLOITS", seed_sdo["id"], v_sdo["id"], rel))
        for sd, rel in sectors:
            s_sdo = self._node_to_sdo("Sector", sd)
            self._add(objects, s_sdo)
            self._add(objects, self._edge_to_sro("TARGETS", seed_sdo["id"], s_sdo["id"], rel))

        return self._bundle(objects.values())

    def export_technique(
        self, mitre_id: str, depth: int = _DEFAULT_DEPTH, limit: int = _DEFAULT_LIMIT
    ) -> Dict[str, Any]:
        """Bundle centred on a Technique + everything that uses it.

        ``depth=1`` returns the technique plus only the ThreatActors
        that employ it (primary relation). ``depth=2`` (default) also
        includes Malware, Tools, Indicators and (2026-10) the
        ``SUBTECHNIQUE_OF`` parent and sub-techniques. See ``export_indicator``
        for the general semantics; ``limit`` bounds each of the four
        collections (T1059 is the documented hotspot).

        Uses ``WITH ... collect(DISTINCT ...) AS ...`` between every
        ``OPTIONAL MATCH`` for the same reason as ``export_threat_actor``:
        chaining four optional matches without aggregation produces a
        Cartesian product of O(actors × malware × tools × indicators)
        intermediate rows that a final ``DISTINCT`` collapses. A
        well-connected technique (T1059 command-and-scripting is the
        hotspot called out in the proposal doc) would generate thousands
        of throwaway rows under the naive query shape. Aggregating at
        each step bounds the row count by the size of one collection at
        a time.

        2026-10: a technique id ATT&CK revoked (``T1086``) is answered with the bundle of its
        successor (``T1059.001``): the graph keeps no node for a revoked technique, and the links
        feeds made to the old id are on the successor (``attack_revoked``).
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        limit = _clamp_limit(limit)
        successor = load_revoked_ids().technique_successor(mitre_id)
        if successor is not None:
            # A request parameter: logged at DEBUG, and only as the normalised id that matched the
            # map (an ATT&CK id pattern), never the raw value (no line can be injected).
            logger.debug(
                "STIX export: technique %s is a revoked ATT&CK id; exporting its successor %s",
                str(mitre_id).strip().upper(),
                successor,
            )
            mitre_id = successor
        # ``Technique.mitre_id`` is unique, so the seed is a single row
        # without an explicit LIMIT 1.
        rows = self._run(
            """
            MATCH (t:Technique {mitre_id: $mid})
            WHERE (t.edgeguard_managed = true OR t.edgeguard_enriched = true)
            WITH t
            OPTIONAL MATCH (a:ThreatActor)-[r1:EMPLOYS_TECHNIQUE]->(t)
              WHERE (a.edgeguard_managed = true OR a.edgeguard_enriched = true)
            WITH t, a, r1 ORDER BY a.name LIMIT $limit
            WITH t, collect({n: a, r: properties(r1)}) AS actors
            OPTIONAL MATCH (m:Malware)-[r2:IMPLEMENTS_TECHNIQUE]->(t)
              WHERE (m.edgeguard_managed = true OR m.edgeguard_enriched = true)
            WITH t, actors, m, r2 ORDER BY m.name LIMIT $limit
            WITH t, actors, collect({n: m, r: properties(r2)}) AS malware
            OPTIONAL MATCH (tool:Tool)-[r3:IMPLEMENTS_TECHNIQUE]->(t)
              WHERE (tool.edgeguard_managed = true OR tool.edgeguard_enriched = true)
            WITH t, actors, malware, tool, r3 ORDER BY tool.mitre_id, tool.name LIMIT $limit
            WITH t, actors, malware, collect({n: tool, r: properties(r3)}) AS tools
            OPTIONAL MATCH (i:Indicator)-[r4:USES_TECHNIQUE]->(t)
              WHERE (i.edgeguard_managed = true OR i.edgeguard_enriched = true)
            WITH t, actors, malware, tools, i, r4 ORDER BY i.value, i.indicator_type LIMIT $limit
            WITH t, actors, malware, tools, collect({n: i, r: properties(r4)}) AS indicators
            OPTIONAL MATCH (t)-[r5:SUBTECHNIQUE_OF]->(p:Technique)
              WHERE (p.edgeguard_managed = true OR p.edgeguard_enriched = true)
            WITH t, actors, malware, tools, indicators, p, r5 ORDER BY p.mitre_id LIMIT $limit
            WITH t, actors, malware, tools, indicators, collect({n: p, r: properties(r5)}) AS parents
            OPTIONAL MATCH (sub:Technique)-[r6:SUBTECHNIQUE_OF]->(t)
              WHERE (sub.edgeguard_managed = true OR sub.edgeguard_enriched = true)
            WITH t, actors, malware, tools, indicators, parents, sub, r6 ORDER BY sub.mitre_id LIMIT $limit
            RETURN t AS seed,
                   actors,
                   malware,
                   tools,
                   indicators,
                   parents,
                   collect({n: sub, r: properties(r6)}) AS subtechniques
            """,
            {"mid": mitre_id, "limit": limit},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        actors = _with_rels(row["actors"])
        malware = _with_rels(row["malware"]) if depth >= 2 else []
        tools = _with_rels(row["tools"]) if depth >= 2 else []
        indicators = _with_rels(row["indicators"]) if depth >= 2 else []
        parents = _with_rels(row.get("parents")) if depth >= 2 else []
        subtechniques = _with_rels(row.get("subtechniques")) if depth >= 2 else []
        self._prefetch_source_aggregates(
            [("Technique", dict(seed))]
            + [("ThreatActor", a) for a, _ in actors]
            + [("Malware", m) for m, _ in malware]
            + [("Tool", tool) for tool, _ in tools]
            + [("Indicator", i) for i, _ in indicators]
            + [("Technique", p) for p, _ in parents]
            + [("Technique", sub) for sub, _ in subtechniques]
        )

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Technique", dict(seed))
        self._add(objects, seed_sdo)

        for ad, rel in actors:
            a_sdo = self._node_to_sdo("ThreatActor", ad)
            self._add(objects, a_sdo)
            self._add(objects, self._edge_to_sro("EMPLOYS_TECHNIQUE", a_sdo["id"], seed_sdo["id"], rel))
        # depth=1: primary relation only (technique + attributed actors).
        if depth < 2:
            return self._bundle(objects.values())
        for md, rel in malware:
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            self._add(objects, self._edge_to_sro("IMPLEMENTS_TECHNIQUE", m_sdo["id"], seed_sdo["id"], rel))
        for tool_d, rel in tools:
            tool_sdo = self._node_to_sdo("Tool", tool_d)
            self._add(objects, tool_sdo)
            self._add(objects, self._edge_to_sro("IMPLEMENTS_TECHNIQUE", tool_sdo["id"], seed_sdo["id"], rel))
        for idn, rel in indicators:
            i_sdo = self._node_to_sdo("Indicator", idn)
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("USES_TECHNIQUE", i_sdo["id"], seed_sdo["id"], rel))
        # 2026-10: the ATT&CK hierarchy — the parent of a sub-technique and the sub-techniques
        # of a technique (``subtechnique-of``, MITRE's own relationship type).
        for pd, rel in parents:
            p_sdo = self._node_to_sdo("Technique", pd)
            self._add(objects, p_sdo)
            self._add(objects, self._edge_to_sro("SUBTECHNIQUE_OF", seed_sdo["id"], p_sdo["id"], rel))
        for sd, rel in subtechniques:
            sub_sdo = self._node_to_sdo("Technique", sd)
            self._add(objects, sub_sdo)
            self._add(objects, self._edge_to_sro("SUBTECHNIQUE_OF", sub_sdo["id"], seed_sdo["id"], rel))

        return self._bundle(objects.values())

    def export_cve(self, cve_id: str, depth: int = _DEFAULT_DEPTH, limit: int = _DEFAULT_LIMIT) -> Dict[str, Any]:
        """Bundle centred on a CVE/Vulnerability + exploiting indicators + affected sectors.

        ``depth=1`` returns the CVE plus only the exploiting Indicators
        (primary relation). ``depth=2`` (default) also includes affected
        sectors and (2026-10) the ThreatActors and Malware that exploit it. See ``export_indicator`` for the general semantics;
        ``limit`` bounds the indicator and sector collections.

        A CVE may exist as two twin nodes (``CVE`` — NVD canonical — and
        ``Vulnerability`` — MISP derived) that share one cve_id and one
        STIX id. The SDO properties are taken from one twin — the ``CVE``
        node when present, because it carries the NVD enrichment promoted
        by ``_vulnerability_sdo`` — while the EXPLOITS and AFFECTS
        relationships are walked from every twin, so edges that exist
        only on the other twin still enter the bundle. Each neighbour is
        one row before each bound — a neighbour linked to both twins is
        one SRO, whose provenance merges both edges (``_merge_rel_props``)
        — and rows without a match sort last, so they never displace real
        neighbours.
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        limit = _clamp_limit(limit)
        rows = self._run(
            """
            MATCH (v)
            WHERE (v:CVE OR v:Vulnerability)
              AND v.cve_id = $cve_id
              AND (v.edgeguard_managed = true OR v.edgeguard_enriched = true)
            WITH v ORDER BY (CASE WHEN v:CVE THEN 0 ELSE 1 END)
            WITH head(collect(v)) AS seed, collect(v) AS twins
            UNWIND twins AS tw
            OPTIONAL MATCH (i:Indicator)-[r1:EXPLOITS]->(tw)
              WHERE (i.edgeguard_managed = true OR i.edgeguard_enriched = true)
            WITH seed, twins, i, collect(properties(r1)) AS r1s
                 ORDER BY (CASE WHEN i IS NULL THEN 1 ELSE 0 END), i.value, i.indicator_type LIMIT $limit
            WITH seed, twins, collect({n: i, r: r1s}) AS indicators
            UNWIND twins AS tw
            OPTIONAL MATCH (x)-[r2:EXPLOITS]->(tw)
              WHERE (x:ThreatActor OR x:Malware)
                AND (x.edgeguard_managed = true OR x.edgeguard_enriched = true)
            WITH seed, twins, indicators, x, collect(properties(r2)) AS r2s
                 ORDER BY (CASE WHEN x IS NULL THEN 1 ELSE 0 END), x.name LIMIT $limit
            WITH seed, twins, indicators,
                 collect({n: x, r: r2s, kind: CASE WHEN x:ThreatActor THEN "ThreatActor" ELSE "Malware" END})
                     AS threats
            UNWIND twins AS tw
            OPTIONAL MATCH (tw)-[r3:AFFECTS]->(s:Sector)
              WHERE (s.edgeguard_managed = true OR s.edgeguard_enriched = true)
            WITH seed, indicators, threats, s, collect(properties(r3)) AS r3s
                 ORDER BY (CASE WHEN s IS NULL THEN 1 ELSE 0 END), s.name LIMIT $limit
            RETURN seed,
                   indicators,
                   threats,
                   collect({n: s, r: r3s}) AS sectors
            """,
            {"cve_id": cve_id, "limit": limit},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        indicators = _with_rels(row["indicators"])
        sectors = _with_rels(row["sectors"]) if depth >= 2 else []
        threats: List[Tuple[str, Dict[str, Any], Dict[str, Any]]] = []
        if depth >= 2:
            for item in row.get("threats") or []:
                if isinstance(item, dict) and item.get("n") is not None:
                    kind = "ThreatActor" if item.get("kind") == "ThreatActor" else "Malware"
                    threats.append((kind, dict(item["n"]), _merge_rel_props(item.get("r"))))
        self._prefetch_source_aggregates(
            [("Vulnerability", dict(seed))]
            + [("Indicator", i) for i, _ in indicators]
            + [(kind, x) for kind, x, _ in threats]
            + [("Sector", s) for s, _ in sectors]
        )

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Vulnerability", dict(seed))
        self._add(objects, seed_sdo)

        for idn, rel in indicators:
            i_sdo = self._node_to_sdo("Indicator", idn)
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("EXPLOITS", i_sdo["id"], seed_sdo["id"], rel))
        # depth=1: primary relation only (CVE + exploiting indicators).
        if depth < 2:
            return self._bundle(objects.values())
        # 2026-10: the actors and malware that exploit the CVE (curated-package claims
        # included; ``x_edgeguard_sources`` says who asserts each link).
        for kind, xd, rel in threats:
            x_sdo = self._node_to_sdo(kind, xd)
            self._add(objects, x_sdo)
            self._add(objects, self._edge_to_sro("EXPLOITS", x_sdo["id"], seed_sdo["id"], rel))
        for sd, rel in sectors:
            s_sdo = self._node_to_sdo("Sector", sd)
            self._add(objects, s_sdo)
            self._add(objects, self._edge_to_sro("AFFECTS", seed_sdo["id"], s_sdo["id"], rel))

        return self._bundle(objects.values())

    # ------------------------------------------------------------------
    # Node → SDO mapping
    # ------------------------------------------------------------------

    def _enrich_props_with_source_aggregates(self, label: str, props: Dict[str, Any]) -> Dict[str, Any]:
        """Pull per-source MIN(first)/MAX(last) aggregates from the
        ``SOURCED_FROM`` edges and inject them into the props dict so
        the per-type SDO builders find them under the same keys they
        used to read from the node.

        PR (S5) (architecture redesign): per-source timestamps
        live on edges (``r.source_reported_first_at`` /
        ``r.source_reported_last_at``), not on the node. The STIX
        ``valid_from`` semantics still want a single value per
        Indicator — we compute it as MIN across all SOURCED_FROM edges
        so the bundle reflects "the earliest claim from any source
        about when this entity was first observed". MAX symmetric for
        last_seen.

        PR (S5) (Bug Hunter v2 #3 MED): for ``Campaign`` the
        SOURCED_FROM edges don't carry source claims (Campaign is a
        derived aggregate built by enrichment_jobs). We instead read
        the campaign's own ``first_seen`` / ``last_seen`` properties —
        which the campaign builder already aggregates correctly across
        the campaign's indicators. So Campaign SDOs DO get the
        ``x_edgeguard_*`` extensions, just sourced from a different
        place than other entity types.

        The aggregates are read from the bundle-scoped cache populated by
        ``_prefetch_source_aggregates`` (one query per label and bundle).
        A node missing from the cache — a direct caller that did not
        prefetch — is fetched on its own through the same batched path,
        so the export methods never issue per-node queries.

        PR (S5) (Bug Hunter v2 #4 + Logic Tracker v2 F8 MED):
        previously the silent-bail paths returned props with NO log
        — operator could not see why ``x_edgeguard_*`` extensions were
        missing from a bundle. Now both bail paths emit a WARNING.

        Returns a new dict (does not mutate the input). Safe for
        labels without a SOURCED_FROM edge — props is returned
        unchanged when no edges exist.
        """
        # ----- Special case: Campaign reads its own pre-aggregated props
        if label == "Campaign":
            out = dict(props)
            if props.get("first_seen") is not None and "first_seen_at_source" not in out:
                out["first_seen_at_source"] = props["first_seen"]
            if props.get("last_seen") is not None and "last_seen_at_source" not in out:
                out["last_seen_at_source"] = props["last_seen"]
            return out

        cache_key = self._aggregate_cache_key(label, props)
        if cache_key is None:
            return props
        if cache_key not in self._aggregate_cache:
            self._prefetch_source_aggregates([(label, props)])
        agg = self._aggregate_cache.get(cache_key) or {}

        out = dict(props)
        if agg.get("first_seen_at_source") is not None:
            out["first_seen_at_source"] = agg["first_seen_at_source"]
        if agg.get("last_seen_at_source") is not None:
            out["last_seen_at_source"] = agg["last_seen_at_source"]
        return out

    @staticmethod
    def _aggregate_cache_key(label: str, props: Dict[str, Any]) -> Optional[Tuple[str, Tuple[Tuple[str, Any], ...]]]:
        """Return ``(label, sorted natural-key items)`` or ``None`` when the
        label carries no per-source claims or a natural-key value is missing.

        ``Source`` is the source itself and ``Sector`` is a category; both
        are skipped. A missing natural-key value is logged (the SDO is
        emitted without the ``x_edgeguard_*_at_source`` properties).
        """
        from node_identity import natural_key_props

        if label in ("Source", "Sector", "Campaign"):
            return None
        try:
            keys = natural_key_props(label)
        except KeyError:
            return None
        # Sort so the key is order-independent for multi-key labels.
        key_items = tuple(sorted((k, props.get(k)) for k in keys))
        if any(v is None for _, v in key_items):
            logger.warning(
                "STIX source-aggregate skipped for %s — missing natural-key value(s) %s; "
                "x_edgeguard_first_seen_at_source extension will be absent from this SDO",
                label,
                dict(key_items),
            )
            return None
        return (label, key_items)

    def _prefetch_source_aggregates(self, nodes: Iterable[Tuple[str, Dict[str, Any]]]) -> None:
        """Populate the aggregate cache for ``nodes`` with ONE query per label.

        The natural keys of the not-yet-cached nodes are grouped by label
        and sent as a single ``UNWIND $rows`` statement that returns one
        row per matched node (grouped by the natural-key columns) with
        ``min(r.source_reported_first_at)`` / ``max(r.source_reported_last_at)``
        over its ``SOURCED_FROM`` edges. Every requested key is written to
        the cache (an empty dict when the node returned no row) so a
        later lookup never falls back to a per-node query. A failed query
        is logged and leaves the affected keys empty — the SDOs are still
        emitted, without the source-truthful properties.
        """
        from neo4j_client import _validate_label
        from node_identity import natural_key_props

        pending: Dict[str, Dict[Tuple[str, Tuple[Tuple[str, Any], ...]], Dict[str, Any]]] = {}
        for label, props in nodes:
            cache_key = self._aggregate_cache_key(label, props)
            if cache_key is None or cache_key in self._aggregate_cache:
                continue
            pending.setdefault(label, {})[cache_key] = dict(cache_key[1])

        for label, keyed_rows in pending.items():
            # Validate the label before f-string interpolation (Cypher
            # injection guard, project rule). The callers pass fixed
            # labels, but this is the boundary where a future caller
            # could pass an attacker-controlled value.
            _validate_label(label)
            keys = natural_key_props(label)
            where = " AND ".join(f"n.`{k}` = row.`{k}`" for k in keys)
            key_columns = ", ".join(f"n.`{k}` AS `{k}`" for k in keys)
            if label in ("CVE", "Vulnerability"):
                # Twin ``CVE`` / ``Vulnerability`` nodes share the cve_id and
                # the STIX id; match either label so the aggregate covers
                # the SOURCED_FROM edges of both twins (the RETURN groups
                # by cve_id, which merges them into one row).
                match_clause = f"MATCH (n) WHERE (n:CVE OR n:Vulnerability) AND {where}"
            else:
                match_clause = f"MATCH (n:{label}) WHERE {where}"
            cypher = f"""
                UNWIND $rows AS row
                {match_clause}
                OPTIONAL MATCH (n)-[r:SOURCED_FROM]->(:Source)
                RETURN {key_columns},
                       min(r.source_reported_first_at) AS first_seen_at_source,
                       max(r.source_reported_last_at) AS last_seen_at_source
            """
            # Mark every requested key as resolved up front; rows that
            # come back overwrite the placeholder.
            for cache_key in keyed_rows:
                self._aggregate_cache[cache_key] = {}
            try:
                rows = self._run(cypher, {"rows": list(keyed_rows.values())})
            except Exception as e:
                logger.warning(
                    "STIX source-aggregate query FAILED for %s (%d node(s)): %s: %s — "
                    "SDOs emitted without x_edgeguard_*_at_source properties",
                    label,
                    len(keyed_rows),
                    type(e).__name__,
                    e,
                )
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                returned_key = (label, tuple(sorted((k, r.get(k)) for k in keys)))
                if returned_key not in keyed_rows:
                    continue
                self._aggregate_cache[returned_key] = {
                    "first_seen_at_source": r.get("first_seen_at_source"),
                    "last_seen_at_source": r.get("last_seen_at_source"),
                }

    def _reset_export_cache(self) -> None:
        """Clear the bundle-scoped caches (source aggregates, SDO markings).

        PR (S5): called at the start of every public ``export_*``
        method so subsequent exports don't see stale aggregates from
        prior calls. The cache is bundle-scoped — eliminates N+1
        within one bundle without leaking state across bundles.
        """
        self._aggregate_cache.clear()
        self._marking_by_id.clear()

    def _node_to_sdo(self, label: str, props: Dict[str, Any]) -> Dict[str, Any]:
        """Turn a Neo4j node dict into a STIX 2.1 SDO dict.

        We build objects through the stix2 SDK so the library enforces
        schema and emits correct timestamps, then serialise back to a
        plain dict for the bundle (``stix2.parsing.dict_to_stix2`` would
        round-trip but the dict form is what FastAPI serialises anyway).

        After the SDO is built, any EdgeGuard zone tags on the source
        node (stored in Neo4j as ``n.zone`` list — ``healthcare``,
        ``energy``, ``finance``, ``global``) are attached to the SDO as
        an ``x_edgeguard_zones`` custom property. This resolves open
        question §7.4 of the proposal doc: ResilMesh can filter bundles
        by sector without traversing the graph itself.

        PR (S5) (architecture redesign): the source-truthful
        first_seen / last_seen used to live on the node; they're now
        on the per-source ``SOURCED_FROM`` edges. We aggregate across
        edges (MIN/MAX) here before passing to the per-type builder
        so ``valid_from`` and ``x_edgeguard_*`` extensions remain
        populated correctly.
        """
        # Enrich with per-source aggregates BEFORE delegating to type
        # builders so they see the same `first_seen_at_source` /
        # `last_seen_at_source` keys they used to read from the node.
        props = self._enrich_props_with_source_aggregates(label, props)
        label = label.lower()
        if label == "indicator":
            sdo = self._indicator_sdo(props)
        elif label == "malware":
            sdo = self._malware_sdo(props)
        elif label == "threatactor":
            sdo = self._actor_sdo(props)
        elif label == "technique":
            sdo = self._technique_sdo(props)
        elif label == "tool":
            sdo = self._tool_sdo(props)
        elif label == "tactic":
            # PR (S5) (Logic Tracker v2 F1 HIGH): Tactic was
            # missing from the dispatcher and silently routed to
            # ``x-edgeguard-unknown``, so MITRE x-mitre-tactic SDOs
            # never received the source-truthful x_edgeguard_*
            # extensions even though the per-source edges DID get
            # populated correctly. Fix: explicit dispatcher branch +
            # dedicated builder that emits MITRE's canonical
            # ``x-mitre-tactic`` custom SDO type.
            sdo = self._tactic_sdo(props)
        elif label == "campaign":
            sdo = self._campaign_sdo(props)
        elif label in ("cve", "vulnerability"):
            sdo = self._vulnerability_sdo(props)
        elif label == "sector":
            sdo = self._sector_sdo(props)
        else:
            # Unknown — never happens with well-formed graph, but fail soft.
            sdo = {
                "type": "x-edgeguard-unknown",
                "id": _deterministic_id("x-edgeguard-unknown", str(props)),
                "spec_version": "2.1",
            }
        _attach_zones(sdo, props)
        _attach_misp_provenance(sdo, props)
        _attach_description_source(sdo, props)
        # Remember the SDO's marking so SROs can inherit the most
        # restrictive marking of their endpoints (``_edge_to_sro``).
        refs = sdo.get("object_marking_refs") or []
        if refs:
            self._marking_by_id[sdo["id"]] = refs[0]
        return sdo

    # ---- per-type constructors ----------------------------------------

    def _apply_source_truthful_custom_props(self, sdo_dict: Dict[str, Any], props: Dict[str, Any]) -> Dict[str, Any]:
        """Attach the EdgeGuard source-truthful / import-wall-clock
        timestamp custom properties to any STIX 2.1 SDO dict.

        PR (S5) (Logic Tracker + Cross-Checker HIGH): originally
        these `x_edgeguard_*` fields were only added to the Indicator
        SDO. Vulnerability / Malware / ThreatActor / Technique / Tactic /
        Tool / Campaign SDOs shipped to ResilMesh without the
        source-truth extension — so the PR's named bug ("Indicator.
        valid_from = 1970 epoch leak") was only half-fixed: downstream
        STIX consumers still lost the source-truth signal for every
        non-Indicator entity type.

        The three custom properties emitted (all optional, all gated on
        presence + `_iso_str` coercion so a `neo4j.time.DateTime`
        serializes as a plain string):

        - ``x_edgeguard_first_seen_at_source`` — source-truthful first
          observation (STIX 2.1 §11.2 producer extension, analogous to
          the OpenCTI `first_seen` concept for non-Indicator SDOs)
        - ``x_edgeguard_last_seen_at_source`` — source-truthful last
          observation (analogous to OpenCTI `last_seen`)
        - ``x_edgeguard_first_imported_at`` — EdgeGuard-local
          "when we first synced this node" wall-clock, DB-record
          semantic (analogous to OpenCTI `created_at`)
        - ``x_edgeguard_last_updated`` — EdgeGuard-local last-sync
          wall-clock (analogous to OpenCTI `updated_at`). Cross-Checker
          F8: symmetric with `first_imported_at`; consumers polling for
          "has this SDO been touched since my last read" need the pair.
        """
        if props.get("first_seen_at_source"):
            sdo_dict["x_edgeguard_first_seen_at_source"] = _iso_str(props["first_seen_at_source"])
        if props.get("last_seen_at_source"):
            sdo_dict["x_edgeguard_last_seen_at_source"] = _iso_str(props["last_seen_at_source"])
        if props.get("first_imported_at"):
            sdo_dict["x_edgeguard_first_imported_at"] = _iso_str(props["first_imported_at"])
        if props.get("last_updated"):
            sdo_dict["x_edgeguard_last_updated"] = _iso_str(props["last_updated"])
        return sdo_dict

    def _indicator_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        value = props.get("value", "")
        ind_type = props.get("indicator_type", "")
        pattern = _build_pattern(ind_type, value)
        # PR #34 round 25: pre-escape individual fields via
        # ``canonicalize_field_value`` BEFORE joining with ``|`` so the
        # resulting natural_key string cannot be ambiguous with another
        # (type, value) pair where ``|`` appears in a different position.
        # E.g. Indicator(type="ipv4|x", value="y") and
        # Indicator(type="ipv4", value="x|y") used to both render as
        # ``"ipv4|x|y"`` → same uuid → collision. Escaping disambiguates.
        from node_identity import canonicalize_field_value

        stix_id = _deterministic_id(
            "indicator",
            f"{canonicalize_field_value(ind_type)}|{canonicalize_field_value(value)}",
        )
        # PR (S5): valid_from is the canonical STIX 2.1 timestamp for
        # "when did the world first observe this indicator". Resolution
        # order:
        #   1. n.first_seen_at_source — source-truthful, populated from
        #      MISP-native attr.first_seen / NVD published / etc. (see
        #      source_truthful_timestamps.py)
        #   2. n.first_imported_at — when EdgeGuard first synced the
        #      node (always set on ON CREATE; never overwritten)
        #   3. n.first_seen — legacy field name; preserved for back-compat
        #      with any node that hasn't been re-synced since the field
        #      was added
        #
        # The previous code fell back to "1970-01-01T00:00:00Z" when
        # ``props.get("first_seen")`` was missing — and PR #34 R17
        # had dropped that field, so EVERY indicator shipped with
        # valid_from=1970-01-01 to ResilMesh. The audit Logic Tracker
        # caught this; this fix kills the epoch leak.
        #
        # PR (S5) (bugbot HIGH): explicitly cast each candidate
        # via ``_iso_str`` so a ``neo4j.time.DateTime`` returned by the
        # driver becomes a plain ISO-8601 string before stix2 sees it.
        # Without the cast, ``stix2.utils.parse_into_datetime()`` raises
        # because it doesn't recognize the neo4j driver type.
        # PR (S5) (Cross-Checker F1 — MEDIUM): replace the
        # ``"1970-01-01T00:00:00Z"`` tail-of-chain fallback with the
        # CURRENT wall-clock. STIX 2.1 §4.8 `valid_from` semantic is
        # "time from which this Indicator is considered valid". A
        # 1970 sentinel reads to consumers as a real claim and is
        # misleading. OpenCTI's convention + MITRE's own indicator SDOs
        # use the object's ``created`` timestamp when no source first-
        # seen exists — we mirror that here via ``now()`` (our ``created``
        # is auto-stamped by stix2 at this same instant).
        # PR (S5) (Bug Hunter v2 #1 HIGH): dropped the back-compat
        # ``props.get("first_seen")`` step in the chain. The legacy node
        # field was being written by the alert-path Indicator merge (see
        # neo4j_client.py:merge_resilmesh_indicator BEFORE this commit) —
        # which polluted ``valid_from`` with the alert-arrival wall-clock
        # for any indicator that arrived via an alert. The alert path
        # is now fixed; consumers reading the legacy ``i.first_seen``
        # field on ANY remaining baseline node get None here, falling
        # through to ``first_imported_at`` (the canonical DB-local sync
        # time) — semantically correct.
        # PR-M2 design choice (c): split the resolution into
        # source-truthful vs inferred so we can stamp
        # ``x_edgeguard_first_seen_inferred`` on the inferred branches.
        # Spec: docs/TIMESTAMPS.md "valid_from fallback chain".
        source_truthful = _iso_str(props.get("first_seen_at_source"))
        if source_truthful:
            valid_from = _stix_ts(source_truthful)
            valid_from_inferred = False
        else:
            inferred = _iso_str(props.get("first_imported_at")) or _dt.datetime.now(_dt.timezone.utc).isoformat()
            valid_from = _stix_ts(inferred)
            valid_from_inferred = True
        # PR-M2: apply ``_producer_created_modified`` so Indicator
        # SDO's ``created`` / ``modified`` come from EdgeGuard's
        # ``first_imported_at`` / ``last_updated`` (concepts 3 / 4 in
        # docs/TIMESTAMPS.md), not from the stix2 SDK's auto-stamp of
        # current wall-clock. Brings Indicator into line with the 6
        # other SDK-built SDO helpers (Malware/IntrusionSet/AttackPattern/
        # Tool/Campaign/Vulnerability) that already use this helper.
        obj = stix2.Indicator(
            id=stix_id,
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            name=props.get("name") or f"{ind_type}:{value}",
            indicator_types=_listify(props.get("indicator_classification") or ["malicious-activity"]),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
            **_indicator_created_modified(props),
        )
        # PR (S5): expose source-truthful + import-wall-clock timestamps
        # as producer-specific custom properties so consumers can
        # distinguish the two semantics. Mirrors the OpenCTI / STIX 2.1
        # best-practice pattern. Now applied via shared helper so every
        # SDO type emits the same envelope (Logic Tracker HIGH —
        # previously only Indicator got the custom props).
        sdo_dict = self._apply_source_truthful_custom_props(_to_dict(obj), props)
        # PR-M2: mark indicators whose valid_from came from the fallback
        # chain so consumers can filter for source-truthful evidence
        # only. Conscientious consumers (analyst UIs) check the flag;
        # automation consumers can use valid_from directly.
        if valid_from_inferred:
            sdo_dict["x_edgeguard_first_seen_inferred"] = True
        _attach_indicator_aging(sdo_dict, props)
        return sdo_dict

    def _malware_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("malware", name)
        # _listify returns Optional[list[str]]; fall back to the default so
        # the `any(...)` iteration below can't hit None.
        malware_types = _listify(props.get("malware_types") or ["unknown"]) or ["unknown"]
        is_family = any("family" in (mt or "").lower() for mt in malware_types) or bool(props.get("is_family"))
        obj = stix2.Malware(
            id=stix_id,
            name=name,
            is_family=is_family,
            malware_types=malware_types,
            aliases=_listify(props.get("aliases")),
            description=props.get("description"),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
            **_producer_created_modified(props),
        )
        # PR (S5) (Logic Tracker HIGH): source-truthful +
        # import-wall-clock custom props now emitted on every SDO type.
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

    def _actor_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        # Default to intrusion-set (group convention, matches MITRE ATT&CK).
        stix_id = _deterministic_id("intrusion-set", name)
        obj = stix2.IntrusionSet(
            id=stix_id,
            name=name,
            aliases=_listify(props.get("aliases")),
            description=props.get("description"),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
            **_producer_created_modified(props),
        )
        sdo = self._apply_source_truthful_custom_props(_to_dict(obj), props)
        # 2026-10 (explainability): the actor nodes the alias merge folded into this one; their
        # intrusion-set ids (derived from the names) no longer appear in exports.
        merged_from = sorted({m for m in (_listify(props.get("merged_from")) or []) if isinstance(m, str) and m})
        if merged_from:
            sdo["x_edgeguard_merged_from"] = merged_from
        return sdo

    def _technique_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        mitre_id = props.get("mitre_id") or props.get("external_id") or ""
        name = props.get("name", mitre_id)
        stix_id = _deterministic_id("attack-pattern", mitre_id or name)

        kcp: List[Dict[str, str]] = []
        # Tactic → kill_chain_phases. We accept either a list of phases
        # stored on the node or the legacy ``tactic_phases`` property.
        phases = props.get("tactic_phases") or props.get("kill_chain_phases") or []
        for phase in phases:
            if isinstance(phase, dict):
                name_ = phase.get("phase_name") or phase.get("name")
            else:
                name_ = str(phase)
            if name_:
                kcp.append({"kill_chain_name": "mitre-attack", "phase_name": str(name_).lower()})

        ext_refs = []
        if mitre_id:
            ext_refs.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre_id,
                    "url": f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}",
                }
            )

        kwargs: Dict[str, Any] = {
            "id": stix_id,
            "name": name,
            "description": props.get("description"),
            "created_by_ref": EDGEGUARD_IDENTITY_ID,
            "object_marking_refs": [_marking_ref_for(props)],
            "allow_custom": True,
        }
        if kcp:
            kwargs["kill_chain_phases"] = kcp
        if ext_refs:
            kwargs["external_references"] = ext_refs
        kwargs.update(_producer_created_modified(props))
        obj = stix2.AttackPattern(**kwargs)
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

    def _tool_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("tool", name)
        obj = stix2.Tool(
            id=stix_id,
            name=name,
            tool_types=_listify(props.get("tool_types") or ["unknown"]),
            description=props.get("description"),
            aliases=_listify(props.get("aliases")),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
            **_producer_created_modified(props),
        )
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

    def _tactic_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        """Build a MITRE ``x-mitre-tactic`` custom SDO.

        PR (S5) (Logic Tracker v2 F1 HIGH): Tactic was
        missing from ``_node_to_sdo`` so MITRE-derived Tactic nodes
        either fell through to the ``x-edgeguard-unknown`` bucket OR
        (after this fix) emit the canonical MITRE custom type.

        STIX 2.1 has no first-class Tactic SDO. MITRE ATT&CK STIX
        bundles model tactics two ways:
        1. As ``kill_chain_phases`` on attack-pattern (which our
           Technique SDO already does — see ``_technique_sdo``).
        2. As standalone ``x-mitre-tactic`` custom SDOs with their
           own description, x-mitre-shortname, and external_references.

        We emit (2) here so consumers that want the full tactic-
        as-entity (description, source-truthful timestamps,
        cross-references) can resolve them — without disturbing the
        kill-chain-phase representation embedded on attack-patterns.
        """
        mitre_id = props.get("mitre_id") or ""
        name = props.get("name", mitre_id)
        stix_id = _deterministic_id("x-mitre-tactic", mitre_id or name)
        ext_refs = []
        if mitre_id:
            ext_refs.append(
                {
                    "source_name": "mitre-attack",
                    "external_id": mitre_id,
                    "url": f"https://attack.mitre.org/tactics/{mitre_id}",
                }
            )
        # PR (S5) (bugbot c136baf MED): STIX 2.1 §3.2 + §11.2
        # require ``created`` + ``modified`` on EVERY SDO including
        # custom types. Every other SDO builder uses the stix2 SDK
        # which auto-stamps these. Since x-mitre-tactic is a custom
        # type the SDK doesn't natively model, we stamp them here:
        # - ``created`` = node's first_imported_at (when EdgeGuard
        #   first added the Tactic — closest analogue to STIX's
        #   "when this object was created by the producer")
        # - ``modified`` = last_updated (when last touched).
        # Both fall back to NOW if the node lacks them (defensive).
        # Z-suffix normalized for STIX validator compatibility.
        now_iso = _stix_ts(_dt.datetime.now(_dt.timezone.utc).isoformat())
        created = _stix_ts(_iso_str(props.get("first_imported_at"))) or now_iso
        modified = _stix_ts(_iso_str(props.get("last_updated"))) or now_iso
        sdo: Dict[str, Any] = {
            "type": "x-mitre-tactic",
            "spec_version": "2.1",
            "id": stix_id,
            "created": created,
            "modified": modified,
            "created_by_ref": EDGEGUARD_IDENTITY_ID,
            "object_marking_refs": [_marking_ref_for(props)],
            "name": name,
            "description": props.get("description"),
        }
        if props.get("shortname"):
            sdo["x_mitre_shortname"] = props["shortname"]
        if ext_refs:
            sdo["external_references"] = ext_refs
        # Stamp source-truthful + DB-local timestamps via the shared helper.
        return self._apply_source_truthful_custom_props(sdo, props)

    def _campaign_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        name = props.get("name", "")
        stix_id = _deterministic_id("campaign", name)
        obj = stix2.Campaign(
            id=stix_id,
            name=name,
            description=props.get("description"),
            aliases=_listify(props.get("aliases")),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
            **_producer_created_modified(props),
        )
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

    def _vulnerability_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = props.get("cve_id") or props.get("name") or ""
        stix_id = _deterministic_id("vulnerability", cve_id)
        ext_refs = []
        if cve_id:
            ext_refs.append(
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )

        # PR-N23 BLOCKER #3 (proactive audit 2026-04-22): pre-N23 the
        # STIX Vulnerability SDO emitted ONLY ``name`` + ``description``
        # + ``external_references`` — dropping 13+ enrichment fields
        # silently on every export. ResilMesh cloud dashboards showed
        # ``severity="UNKNOWN"`` for every CVE, even though Neo4j knew
        # the real CVSS score + severity + CISA KEV status. The
        # ``published`` / ``last_modified`` fields PR-N19 Fix #1 worked
        # so hard to preserve were also being stripped at this boundary.
        #
        # Fix: emit each enrichment field as an ``x_edgeguard_*`` STIX
        # custom-property via ``allow_custom=True``. STIX 2.1 allows
        # producer-specific custom props on any SDO as long as the key
        # starts with ``x_``. ResilMesh consumers that know to look for
        # the ``x_edgeguard_*`` prefix get the full enrichment; STIX
        # consumers that don't, still get the valid Vulnerability SDO.
        kwargs: Dict[str, Any] = {
            "id": stix_id,
            "name": cve_id,
            "description": props.get("description"),
            "created_by_ref": EDGEGUARD_IDENTITY_ID,
            "object_marking_refs": [_marking_ref_for(props)],
            "allow_custom": True,
        }
        if ext_refs:
            kwargs["external_references"] = ext_refs

        # Promote CVSS + severity + CISA KEV + NVD dates + CWE /
        # references to STIX top-level extension properties so the SDO
        # actually carries the Neo4j enrichment through to ResilMesh
        # (``x_edgeguard_cvss_score``, ``x_edgeguard_severity``,
        # ``x_edgeguard_published``, ``x_edgeguard_last_modified``, the
        # ``x_edgeguard_cisa_*`` fields, ``x_edgeguard_cwe``,
        # ``x_edgeguard_ref_tags``, ``x_edgeguard_reference_urls``, ...).
        # The field list is the module-level
        # ``_VULNERABILITY_PROMOTED_FIELDS`` so the extension definition
        # declares exactly the same names.
        for neo4j_key, stix_key in _VULNERABILITY_PROMOTED_FIELDS:
            val = props.get(neo4j_key)
            # Skip None / empty strings / empty collections so we don't
            # bloat the STIX bundle with "x_edgeguard_cvss_score: null".
            if val is None or val == "" or val == [] or val == {}:
                continue
            kwargs[stix_key] = val

        kwargs.update(_producer_created_modified(props))
        obj = stix2.Vulnerability(**kwargs)
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

    def _sector_sdo(self, props: Dict[str, Any]) -> Dict[str, Any]:
        # PR #34 round 22 (multi-agent UUID audit, HIGH): the previous
        # ``f"sector|{name}"`` natural-key form prefixed every Sector
        # canonical with ``sector|`` to disambiguate against generic STIX
        # ``identity`` SDOs (which can represent users, organizations, etc.).
        # That defensive prefix BROKE the central PR #34 parity contract:
        # ``compute_node_uuid("Sector", {"name": name})`` canonicalizes to
        # ``"identity:{name}"`` (no prefix) — different string, different
        # UUID. The Neo4j n.uuid and the STIX SDO id UUID portion diverged
        # for every Sector. EdgeGuard only ever emits sector-type identity
        # SDOs, so the disambiguation prefix was dead defense. Drop it to
        # restore parity. Pinned by test_sector_stix_parity_end_to_end.
        name = props.get("name") or props.get("sector") or ""
        stix_id = _deterministic_id("identity", name)
        # ``sectors`` values come from the STIX 2.1 ``industry-sector-ov``
        # vocabulary (``_INDUSTRY_SECTOR_OV``); the EdgeGuard zone name is
        # kept as the identity ``name``. Unmapped zones (``global`` is the
        # "no sector" marker) are exported without ``sectors``.
        obj = stix2.Identity(
            id=stix_id,
            name=name,
            identity_class="class",
            sectors=_industry_sectors(name),
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[_marking_ref_for(props)],
            allow_custom=True,
        )
        return _to_dict(obj)

    # ------------------------------------------------------------------
    # Edge → SRO
    # ------------------------------------------------------------------

    def _edge_to_sro(
        self, edge_type: str, source_ref: str, target_ref: str, rel_props: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build a deterministic Relationship SRO for a graph edge.

        ``edge_type`` is the EdgeGuard relationship type in graph
        direction (``source_ref`` → ``target_ref``). The STIX
        ``relationship_type`` — and, where the specification models the
        pair the other way round, the direction — comes from
        ``_SRO_BY_EDGE`` (see the table for the rationale per pair);
        pairs absent from the table are emitted as ``related-to`` in graph
        direction. The SRO carries ``created_by_ref`` and the most
        restrictive ``object_marking_refs`` of its two endpoints and, since
        2026-10, of the relationship's own ``tlp`` (curated-package links).

        ``rel_props`` (2026-10) are the graph relationship's properties: the SRO
        then also carries its ``confidence`` (0–100), its record ids as
        ``external_references`` and ``x_edgeguard_match_type`` /
        ``x_edgeguard_sources`` / ``x_edgeguard_source_refs`` /
        ``x_edgeguard_misp_event_ids`` (``_attach_relationship_provenance``).
        """
        source_type = source_ref.split("--", 1)[0]
        target_type = target_ref.split("--", 1)[0]
        mapping = _SRO_BY_EDGE.get((edge_type, source_type, target_type))
        if mapping is None:
            logger.warning(
                "[stix-export] No STIX 2.1 relationship mapping for %s (%s -> %s); emitting related-to",
                edge_type,
                source_type,
                target_type,
            )
            relationship_type, reverse = "related-to", False
        else:
            relationship_type, reverse = mapping
        if reverse:
            source_ref, target_ref = target_ref, source_ref
        rel = rel_props or {}
        marking_by_id = getattr(self, "_marking_by_id", {})
        # 2026-10 (curated packages, TLP fix): a curated link carries the package's level in
        # ``r.tlp``; taking only the endpoints' markings exported such links as TLP:WHITE.
        marking = _most_restrictive_marking(
            marking_by_id.get(source_ref), marking_by_id.get(target_ref), _relationship_marking_ref(rel)
        )
        stix_id = _deterministic_id("relationship", f"{source_ref}|{relationship_type}|{target_ref}")
        optional: Dict[str, Any] = {}
        confidence = rel.get("confidence_score")
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool) and 0 <= confidence <= 1:
            optional["confidence"] = int(round(confidence * 100))
        external_references = _external_references(rel.get("source_refs"))
        if external_references:
            optional["external_references"] = external_references
        obj = stix2.Relationship(
            id=stix_id,
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            created_by_ref=EDGEGUARD_IDENTITY_ID,
            object_marking_refs=[marking],
            allow_custom=True,
            **optional,
        )
        sro = _to_dict(obj)
        _attach_relationship_provenance(sro, rel)
        return sro

    # ------------------------------------------------------------------
    # Bundle assembly
    # ------------------------------------------------------------------

    def _add(self, objects: Dict[str, Dict[str, Any]], sdo: Optional[Dict[str, Any]]) -> Optional[str]:
        """Insert a SDO/SRO into the bundle dict, keyed by its STIX id.

        The first SDO with an id is kept. A second SRO with the same id (two graph edges that
        express one STIX relationship, e.g. ``ATTRIBUTED_TO`` and ``USES_MALWARE``) adds its
        provenance to the first (``_merge_relationship``, 2026-10).
        """
        if not sdo:
            return None
        existing = objects.setdefault(sdo["id"], sdo)
        if existing is not sdo and existing.get("type") == "relationship" and sdo.get("type") == "relationship":
            _merge_relationship(existing, sdo)
        return sdo["id"]

    def _bundle(self, objects: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        # PR #37: bundle assembly is now FULLY DETERMINISTIC. The
        # previous form used ``uuid.uuid4()`` for ``bundle.id`` and
        # iterated ``objects`` in dict-insertion order (which depends
        # on Cypher row order — Neo4j does NOT guarantee row order
        # absent ``ORDER BY``). Two consecutive identical exports
        # produced different bundle IDs and different object array
        # orders, so ResilMesh's ``diff bundles`` saw "everything
        # changed" on every poll — directly contradicting the
        # docstring promise (line 16) that "ResilMesh can diff
        # bundles safely". The audit (Devil's Advocate + Logic Tracker
        # both flagged this independently) made it Tier S for PR #37.
        #
        # Determinism plan:
        #   1. Sort ``objects`` by ``id`` (stable across runs).
        #   2. Compute ``bundle.id`` as ``uuid5`` of the sorted-id
        #      content hash, so identical content → identical id.
        #   3. Provenance ``generated_at`` is OPTIONALLY frozen by the
        #      ``EDGEGUARD_DETERMINISTIC_BUNDLE`` env var so callers
        #      that need byte-stable bundles (CI fixtures, snapshot
        #      tests, ResilMesh diff polls) can opt in. Default keeps
        #      the wall-clock timestamp for forensics — so an operator
        #      can still answer "when was this bundle generated" from
        #      the bundle alone.
        #
        # Strict-parser compliance (see the module docstring): a STIX 2.1
        # Bundle carries only ``type``, ``id`` and ``objects``. The
        # former bundle-level ``x_edgeguard_source`` provenance now lives
        # on the EdgeGuard producer ``identity`` (referenced by every
        # object's ``created_by_ref``); the ``extension-definition`` that
        # declares the ``x_edgeguard_*`` top-level properties and the TLP
        # ``marking-definition`` objects referenced by the bundle are
        # appended as well, so the bundle is self-contained.
        exported = [o for o in objects if o]
        for o in exported:
            _declare_extension(o)
        all_objects: List[Dict[str, Any]] = exported + [_producer_identity(), _extension_definition()]
        marking_ids = {ref for o in all_objects for ref in (o.get("object_marking_refs") or [])}
        all_objects.extend(
            _to_dict(_TLP_MARKINGS_BY_ID[mid]) for mid in sorted(marking_ids) if mid in _TLP_MARKINGS_BY_ID
        )
        objects_list = sorted(all_objects, key=lambda o: o.get("id", ""))
        # Hash over the sorted ids only (NOT full payloads — payload
        # field churn within an SDO would change the id otherwise; the
        # bundle "identity" is "which objects are in it", not "what's
        # the current snapshot of each").
        ids_payload = json.dumps([o.get("id", "") for o in objects_list], separators=(",", ":"))
        content_hash = hashlib.sha256(ids_payload.encode("utf-8")).hexdigest()
        bundle_id = "bundle--" + str(uuid.uuid5(EDGEGUARD_STIX_NAMESPACE, content_hash))
        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects_list,
        }

    def _empty_bundle(self) -> Dict[str, Any]:
        return self._bundle([])

    # ------------------------------------------------------------------
    # Neo4j helper
    # ------------------------------------------------------------------

    def _run(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run a Cypher query, returning a list of row dicts.

        Sessions are opened with ``default_access_mode="READ"`` so Neo4j
        itself rejects any accidental write from this API surface — the
        same defense-in-depth pattern used by the graph-explore and
        admin-query endpoints in ``query_api.py``. The STIX exporter is a
        strictly read-only consumer; a bug that produced a MERGE/CREATE
        here should fail at the driver rather than silently mutate the
        shared graph that ResilMesh also writes to.
        """
        driver = getattr(self.client, "driver", None)
        if driver is None:
            logger.warning("StixExporter: Neo4j driver not connected")
            return []
        with driver.session(default_access_mode="READ") as session:
            result = session.run(cypher, **params, timeout=_STIX_QUERY_TIMEOUT)
            return [dict(record) for record in result]


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _listify(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        out = [str(v) for v in value if v is not None]
        return out or None
    return [str(value)]


def _unit_confidence(value: Any) -> float:
    """A ``confidence_score`` in [0, 1], or ``-1.0`` when absent or not a unit-interval number."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1:
        return float(value)
    return -1.0


def _merge_rel_props(rels: Any) -> Dict[str, Any]:
    """One provenance map from the property maps of the graph edges behind one SRO (2026-10).

    A single map is returned unchanged. Several maps arise when edges share an SRO: the twin
    ``CVE`` / ``Vulnerability`` nodes share one STIX id, and ``ATTRIBUTED_TO`` and
    ``USES_MALWARE`` both become ``intrusion-set uses malware``. The merged map carries the
    union of ``sources`` / ``source_refs`` / ``misp_event_ids``, the highest
    ``confidence_score``, the ``match_type`` of the strongest edge (on a tie, the
    alphabetically first) and the most restrictive ``tlp``, so the result does not depend on
    row order.
    """
    if isinstance(rels, dict):
        return dict(rels)
    maps = [dict(r) for r in rels or [] if isinstance(r, dict) and r]
    if len(maps) <= 1:
        return maps[0] if maps else {}
    merged: Dict[str, Any] = {}
    for prop, _key, _cap in _SRO_PROVENANCE_LISTS:
        values = sorted({v for r in maps for v in (_listify(r.get(prop)) or [])})
        if values:
            merged[prop] = values
    best = max(_unit_confidence(r.get("confidence_score")) for r in maps)
    if best >= 0:
        merged["confidence_score"] = best

    def _match_types(candidates: List[Dict[str, Any]]) -> List[str]:
        return sorted({r["match_type"] for r in candidates if isinstance(r.get("match_type"), str) and r["match_type"]})

    strongest = [r for r in maps if _unit_confidence(r.get("confidence_score")) == best]
    match_types = _match_types(strongest) or _match_types(maps)
    if match_types:
        merged["match_type"] = match_types[0]
    # 2026-10 (curated packages): a link's own TLP — the SRO is as restricted as its most
    # restricted edge (a curated edge to one CVE twin, a feed edge to the other).
    levels = sorted({str(r["tlp"]).strip().lower() for r in maps if str(r.get("tlp") or "").strip()})
    if levels:
        merged["tlp"] = max(levels, key=_relationship_tlp_rank)
    return merged


def _with_rels(items: Any) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """``[(node, relationship)]`` property pairs from a collected export list (2026-10).

    The export queries collect ``{n: node, r: properties(rel)}`` maps so each SRO can carry
    the provenance of its graph relationship; where one neighbour is reached over several
    edges (CVE twins), ``r`` is the list of their property maps, merged by
    ``_merge_rel_props``. Entries without a node (an OPTIONAL MATCH that found nothing) are
    dropped; a plain node (no map) yields an empty relationship.
    """
    out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for item in items or []:
        if item is None:
            continue
        if isinstance(item, dict) and "n" in item and set(item) <= {"n", "r", "kind"}:
            node = item.get("n")
            if node is None:
                continue
            out.append((dict(node), _merge_rel_props(item.get("r"))))
        else:
            out.append((dict(item), {}))
    return out


def _record_url(source: str, record_id: str) -> Optional[str]:
    """Public page of a source record (``_RECORD_URL_TEMPLATES``, ATT&CK by id prefix); ``None`` if none."""
    if source == "mitre_attck":
        for prefix, path in _ATTACK_URL_PATHS:
            rest = record_id[len(prefix) :]
            if record_id.startswith(prefix) and rest[:1].isdigit():
                return f"https://attack.mitre.org/{path}/{record_id.replace('.', '/')}/"
        return None
    template = _RECORD_URL_TEMPLATES.get(source)
    return template.format(id=quote(record_id, safe="")) if template else None


def _external_references(source_refs: Any) -> List[Dict[str, str]]:
    """STIX ``external_references`` from ``"<source>:<record id>"`` strings (deduplicated, bounded).

    Sorted before the bound, in the order of ``x_edgeguard_source_refs``: a long list cites the
    same records on every export, and they are the first ones of that property.
    """
    out: List[Dict[str, str]] = []
    raws = source_refs if isinstance(source_refs, (list, tuple)) else []
    for raw in sorted({r for r in raws if isinstance(r, str)}):
        source, sep, record_id = raw.partition(":")
        if not sep or not source or not record_id:
            continue
        ref = {"source_name": source, "external_id": record_id}
        url = _record_url(source, record_id)
        if url:
            ref["url"] = url
        out.append(ref)
        if len(out) >= _MAX_EXTERNAL_REFERENCES:
            break
    return out


def _attach_relationship_provenance(sro: Dict[str, Any], rel: Dict[str, Any]) -> None:
    """Attach the graph relationship's provenance to an SRO dict (omitted when absent).

    ``x_edgeguard_match_type`` (kind of evidence), ``x_edgeguard_sources`` (who asserts the
    link — e.g. ``mitre_attck``, ``alienvault_otx``, ``coreideas``), ``x_edgeguard_source_refs``
    (their record ids, bounded), ``x_edgeguard_misp_event_ids``, on a link a revoked ATT&CK
    id led to, ``x_edgeguard_cited_ids`` and, on a campaign link (2026-10-16),
    ``x_edgeguard_evidence_types``. Set after the stix2 SDK serialisation, like
    ``_attach_misp_provenance``.
    """
    if not isinstance(sro, dict) or not rel:
        return
    match_type = rel.get("match_type")
    if isinstance(match_type, str) and match_type:
        sro["x_edgeguard_match_type"] = match_type
    for prop, key, cap in _SRO_PROVENANCE_LISTS:
        values = _listify(rel.get(prop))
        if values:
            sro[key] = sorted(dict.fromkeys(values))[:cap] if cap else sorted(dict.fromkeys(values))


def _merge_relationship(existing: Dict[str, Any], incoming: Dict[str, Any]) -> None:
    """Fold the provenance of a second SRO with the same id into the first (2026-10).

    Both SROs are read back into relationship-property form and merged by ``_merge_rel_props``;
    ``confidence``, ``external_references`` and the ``x_edgeguard_*`` provenance of ``existing``
    are then rebuilt from the merged map, so the result does not depend on which edge came
    first. The capped lists stay exact: each SRO holds the first entries of its sorted list, and
    the first entries of the merged list are among them.
    """

    def _as_rel_props(sro: Dict[str, Any]) -> Dict[str, Any]:
        props: Dict[str, Any] = {}
        confidence = sro.get("confidence")
        if isinstance(confidence, int) and not isinstance(confidence, bool):
            props["confidence_score"] = confidence / 100
        if sro.get("x_edgeguard_match_type"):
            props["match_type"] = sro["x_edgeguard_match_type"]
        for prop, key, _cap in _SRO_PROVENANCE_LISTS:
            if sro.get(key):
                props[prop] = sro[key]
        return props

    # 2026-10 (curated packages, TLP fix): the merged SRO keeps the more restrictive marking of the
    # two — a curated edge (``r.tlp``) and a feed edge can become the same SRO.
    existing["object_marking_refs"] = [
        _most_restrictive_marking(
            *(existing.get("object_marking_refs") or []), *(incoming.get("object_marking_refs") or [])
        )
    ]
    merged = _merge_rel_props([_as_rel_props(existing), _as_rel_props(incoming)])
    for key in ("confidence", "external_references", "x_edgeguard_match_type") + tuple(
        key for _prop, key, _cap in _SRO_PROVENANCE_LISTS
    ):
        existing.pop(key, None)
    confidence = _unit_confidence(merged.get("confidence_score"))
    if confidence >= 0:
        existing["confidence"] = int(round(confidence * 100))
    external_references = _external_references(merged.get("source_refs"))
    if external_references:
        existing["external_references"] = external_references
    _attach_relationship_provenance(existing, merged)


def _extract_zones(props: Dict[str, Any]) -> List[str]:
    """Return the EdgeGuard zone list from a Neo4j node dict.

    Neo4j stores zones on ``n.zone`` (array of strings like
    ``["healthcare", "global"]``) per ``neo4j_client.py`` merge
    semantics. Fall back to ``zones`` (plural) if present, and accept a
    scalar string for defensive tolerance. Empty/null → ``[]``.

    PR-N6 hotfix #1 (audit 09, Cross-Checker F2): defense-in-depth
    VALID_ZONES filter. Every writer today validates zones against
    the whitelist before storing on Neo4j, so in principle this
    filter is redundant. But ``_extract_zones`` is the last stop
    before zones flow out to ResilMesh via STIX — if ANY writer ever
    slips an unvalidated zone through (a future bug, an out-of-band
    Cypher write, a direct Bolt query from an ops script), this
    prevents the corruption from propagating to downstream
    consumers. Also logs a WARNING so the operator notices.
    """
    from config import VALID_ZONES

    raw = props.get("zone")
    if raw is None:
        raw = props.get("zones")
    if raw is None:
        return []
    if isinstance(raw, str):
        candidates = [raw] if raw else []
    elif isinstance(raw, (list, tuple)):
        candidates = [str(z) for z in raw if z]
    else:
        return []

    valid = [z for z in candidates if z in VALID_ZONES]
    # Log a single WARN per call if ANY candidate was dropped — a
    # non-zero rate is the signal that upstream write-path validation
    # has regressed somewhere.
    if len(valid) != len(candidates):
        dropped = [z for z in candidates if z not in VALID_ZONES]
        logger.warning(
            "[stix-export] Dropped %d non-canonical zone(s) %r from Neo4j node "
            "while exporting to STIX — check upstream write-path validation.",
            len(dropped),
            dropped,
        )
    return valid


def _bundle_provenance() -> Dict[str, Any]:
    """Build the provenance dict carried by the producer identity.

    Kept in a module-level helper so tests can freeze the timestamp by
    monkeypatching ``_utcnow``. ``git_sha`` is read from the module
    constant so it is stable for a given process lifetime.

    PR #37: when ``EDGEGUARD_DETERMINISTIC_BUNDLE`` is truthy, the
    ``generated_at`` timestamp is omitted entirely so the bundle dict
    becomes byte-stable across runs of the same graph state. Used by
    ResilMesh diff-poll callers + CI snapshot tests. Default OFF so
    forensic "when did this bundle leave EdgeGuard" use cases keep
    working without code change.
    """
    provenance: Dict[str, Any] = {
        "producer": EDGEGUARD_IDENTITY_NAME,
        "exporter": "stix_exporter",
        "git_sha": _GIT_SHA or None,
    }
    if not _is_truthy_env("EDGEGUARD_DETERMINISTIC_BUNDLE"):
        provenance["generated_at"] = _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return provenance


def _producer_identity() -> Dict[str, Any]:
    """Build the EdgeGuard producer ``identity`` SDO.

    Every exported object references it through ``created_by_ref``. It
    carries the provenance that used to sit on the bundle as top-level
    extension properties (``x_edgeguard_exporter``,
    ``x_edgeguard_git_sha`` when known, ``x_edgeguard_generated_at``
    unless ``EDGEGUARD_DETERMINISTIC_BUNDLE`` is set). ``created`` and
    ``modified`` are fixed so the object is byte-stable; the identity is
    marked TLP:WHITE because it describes the producer, not the data.
    """
    provenance = _bundle_provenance()
    custom: Dict[str, Any] = {"x_edgeguard_exporter": provenance["exporter"]}
    if provenance.get("git_sha"):
        custom["x_edgeguard_git_sha"] = provenance["git_sha"]
    if provenance.get("generated_at"):
        custom["x_edgeguard_generated_at"] = provenance["generated_at"]
    obj = stix2.Identity(
        id=EDGEGUARD_IDENTITY_ID,
        created=_PROVENANCE_OBJECTS_CREATED,
        modified=_PROVENANCE_OBJECTS_CREATED,
        name=provenance["producer"],
        identity_class="system",
        description="Producer of this STIX 2.1 bundle: the EdgeGuard threat-intelligence knowledge graph exporter.",
        object_marking_refs=[stix2.TLP_WHITE.id],
        extensions={EDGEGUARD_EXTENSION_ID: {"extension_type": "toplevel-property-extension"}},
        allow_custom=True,
        **custom,
    )
    return _to_dict(obj)


def _extension_definition() -> Dict[str, Any]:
    """Build the ``extension-definition`` that declares the ``x_edgeguard_*`` properties.

    ``extension_types`` is ``toplevel-property-extension`` so the
    properties stay at the top level of each object (where ResilMesh
    reads them) while remaining acceptable to strict STIX 2.1 parsers;
    ``extension_properties`` lists every property name the exporter can
    emit (``EDGEGUARD_EXTENSION_PROPERTIES``).
    """
    obj = stix2.ExtensionDefinition(
        id=EDGEGUARD_EXTENSION_ID,
        created=_PROVENANCE_OBJECTS_CREATED,
        modified=_EXTENSION_MODIFIED,
        created_by_ref=EDGEGUARD_IDENTITY_ID,
        name="EdgeGuard provenance and enrichment properties",
        description=(
            "Top-level properties prefixed x_edgeguard_ carrying EdgeGuard provenance "
            "(source-truthful and import timestamps, zones, MISP traceability, NVD and CISA KEV "
            "enrichment, exporter build information) and, on relationships, who asserts the link "
            "(sources, their record ids, the kind of evidence)."
        ),
        schema=_EXTENSION_SCHEMA_URL,
        version=_EXTENSION_VERSION,
        extension_types=["toplevel-property-extension"],
        extension_properties=list(EDGEGUARD_EXTENSION_PROPERTIES),
    )
    return _to_dict(obj)


def _declare_extension(sdo: Dict[str, Any]) -> None:
    """Declare the EdgeGuard extension on ``sdo`` when it carries ``x_edgeguard_*`` properties.

    In-place mutation. Objects without such properties are left
    untouched so lean objects (for example sector identities) do not
    grow an ``extensions`` map. An existing ``extensions`` map is
    extended, not replaced.
    """
    if not isinstance(sdo, dict):
        return
    if not any(isinstance(k, str) and k.startswith(_EXTENSION_PREFIX) for k in sdo):
        return
    extensions = sdo.get("extensions")
    if not isinstance(extensions, dict):
        extensions = {}
        sdo["extensions"] = extensions
    extensions.setdefault(EDGEGUARD_EXTENSION_ID, {"extension_type": "toplevel-property-extension"})


def _is_truthy_env(name: str) -> bool:
    """Same boolean parsing the rest of the codebase uses for env vars
    (1/true/yes/on). Centralized here to keep the deterministic-bundle
    behavior easy to swap without spelunking."""
    val = os.getenv(name, "").strip().lower()
    return val in {"1", "true", "yes", "on"}


def _utcnow() -> _dt.datetime:
    """Return the current UTC time. Overridable in tests."""
    return _dt.datetime.now(_dt.timezone.utc)


def _attach_zones(sdo: Dict[str, Any], props: Dict[str, Any]) -> None:
    """Attach ``x_edgeguard_zones`` to an SDO dict when the source node has zones.

    In-place mutation. The custom property is omitted entirely when the
    node has no zones — this keeps bundles from growing an empty field
    on every single object. The stix2 SDK serialisation does not round-
    trip this custom property (it is not declared on the Python class),
    so we set it on the already-serialised dict.
    """
    if not isinstance(sdo, dict):
        return
    zones = _extract_zones(props)
    if zones:
        sdo["x_edgeguard_zones"] = zones


def _attach_description_source(sdo: Dict[str, Any], props: Dict[str, Any]) -> None:
    """Attach ``x_edgeguard_description_source`` (2026-10-16): the canonical id of the source whose text
    the SDO's ``description`` is (the node's ``description_source``, ``description_ranking``). Omitted
    when the SDO has no description or the node names no source (a node written before 2026-10-16, a
    campaign EdgeGuard built). The text of every source, the chosen one included, stays in MISP: the
    node's ``SOURCED_FROM`` edge to each source names its MISP events (docs/RUNBOOK.md, "Retrieving raw
    MISP data from a Neo4j node")."""
    if not isinstance(sdo, dict) or not sdo.get("description"):
        return
    source = props.get("description_source")
    if isinstance(source, str) and source:
        sdo["x_edgeguard_description_source"] = source


def _attach_misp_provenance(sdo: Dict[str, Any], props: Dict[str, Any]) -> None:
    """Attach ``x_edgeguard_misp_event_ids`` and ``x_edgeguard_misp_attribute_ids``
    custom properties to an SDO dict when the source node carries MISP traceability.

    Mirrors the ``_attach_zones`` pattern (in-place mutation, omitted when empty,
    set after stix2 SDK serialisation since these are non-standard fields). Closes
    the trace loop for ResilMesh consumers: a STIX bundle object can be resolved
    back to the originating MISP event(s) and attribute(s) without round-tripping
    through Neo4j.

    Field semantics (PR #33 round 10 — array-only after legacy-scalar drop):
    - ``x_edgeguard_misp_event_ids``: ``misp_event_ids[]`` deduped and stringified.
      Omitted from SDO when the source node has no array.
    - ``x_edgeguard_misp_attribute_ids``: ``misp_attribute_ids[]`` deduped. Only
      present on Indicator-derived SDOs in practice; harmless on other SDOs
      (omitted when empty).
    """
    if not isinstance(sdo, dict):
        return

    def _gather(array_key: str) -> List[str]:
        arr = props.get(array_key)
        if not isinstance(arr, (list, tuple)):
            return []
        out: List[str] = []
        seen: set = set()
        for v in arr:
            if v is None:
                continue
            s = str(v)
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    events = _gather("misp_event_ids")
    if events:
        sdo["x_edgeguard_misp_event_ids"] = events

    attrs = _gather("misp_attribute_ids")
    if attrs:
        sdo["x_edgeguard_misp_attribute_ids"] = attrs


def _to_dict(stix_obj: Any) -> Dict[str, Any]:
    """Serialise a stix2 SDO/SRO to a plain dict."""
    # stix2 objects expose ``serialize`` (json) and ``.get`` on __dict__.
    # The simplest stable round-trip is ``json.loads(obj.serialize())``.
    import json

    return json.loads(stix_obj.serialize())
