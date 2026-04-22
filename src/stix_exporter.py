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
- All Cypher queries filter on ``x.edgeguard_managed = true`` (strict
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
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import unicodedata
import uuid
from typing import Any, Dict, Iterable, List, Optional

import stix2

logger = logging.getLogger(__name__)

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
    """
    if not s:
        return s
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
# Pattern helper — reuse the escape + type mapping from MISPToNeo4jSync
# instead of re-implementing it. We instantiate the class lazily with
# ``__new__`` to avoid triggering its heavy ``__init__`` (which would try
# to connect to MISP).
# ---------------------------------------------------------------------------

_pattern_helper: Any = None


def _get_pattern_helper() -> Any:
    """Return a bare instance of MISPToNeo4jSync for pattern helpers.

    We only need ``_value_to_stix_pattern``/``_escape_stix_value``; both
    are pure and do not touch ``self``'s network state, so skipping
    ``__init__`` is safe.
    """
    global _pattern_helper
    if _pattern_helper is None:
        from run_misp_to_neo4j import MISPToNeo4jSync

        _pattern_helper = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    return _pattern_helper


def _build_pattern(indicator_type: Optional[str], value: str) -> str:
    """Build a STIX 2.1 pattern literal for an indicator row.

    Falls back to a generic ``artifact`` match if the MISP type is not
    recognised — that way we never drop an indicator just because its
    type is exotic; the proposal lists pattern coverage as a follow-up.
    """
    helper = _get_pattern_helper()
    pattern = helper._value_to_stix_pattern(indicator_type or "", value)
    if pattern:
        return pattern
    # Fallback: emit a valid but coarse pattern. STIX requires a pattern
    # on indicator SDOs so we must not return None here.
    safe = helper._escape_stix_value(value)
    return f"[artifact:payload_bin = '{safe}']"


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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def export_indicator(self, value: str, depth: int = _DEFAULT_DEPTH) -> Dict[str, Any]:
        """Bundle one indicator + its 1-hop neighbourhood.

        Neighbourhood: INDICATES→Malware, EXPLOITS→CVE/Vulnerability,
        USES_TECHNIQUE→Technique, TARGETS→Sector.

        ``depth=1`` returns a minimal bundle with only the indicator's
        primary relation type (``INDICATES→Malware``). ``depth=2``
        (the default) returns the full 1-hop neighborhood across all
        four relation types. The Cypher always fetches everything —
        ``depth`` is a Python-side filter that saves bundle size, not
        query time. A future optimisation would push the filter into
        the query itself.
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        # Each OPTIONAL MATCH is aggregated into a collect() before the next
        # one starts. Without the WITH ... collect() fence pattern the four
        # OPTIONAL MATCH clauses form a Cartesian product — every row from
        # stage N is multiplied by every row in stage N+1, so a well-
        # connected indicator (a C2 IP with 10 malware × 20 CVEs × 15
        # techniques × 5 sectors = 15 000 intermediate rows) blows up long
        # before the outer DISTINCT collapses them. Same pattern as the
        # round-2/round-4 fixes to export_threat_actor and export_technique.
        rows = self._run(
            """
            MATCH (i:Indicator {value: $value})
            WHERE i.edgeguard_managed = true
            OPTIONAL MATCH (i)-[:INDICATES]->(m:Malware)
              WHERE m.edgeguard_managed = true
            WITH i, collect(DISTINCT m) AS malware
            OPTIONAL MATCH (i)-[:EXPLOITS]->(v)
              WHERE (v:CVE OR v:Vulnerability)
                AND v.edgeguard_managed = true
            WITH i, malware, collect(DISTINCT v) AS vulns
            OPTIONAL MATCH (i)-[:USES_TECHNIQUE]->(t:Technique)
              WHERE t.edgeguard_managed = true
            WITH i, malware, vulns, collect(DISTINCT t) AS techniques
            OPTIONAL MATCH (i)-[:TARGETS]->(s:Sector)
              WHERE s.edgeguard_managed = true
            RETURN i AS seed,
                   malware,
                   vulns,
                   techniques,
                   collect(DISTINCT s) AS sectors
            """,
            {"value": value},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Indicator", dict(seed))
        self._add(objects, seed_sdo)

        for m in _nonnull(row["malware"]):
            m_sdo = self._node_to_sdo("Malware", dict(m))
            self._add(objects, m_sdo)
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], m_sdo["id"]),
            )
        # depth=1 short-circuit: bundle contains only the primary
        # relation type (INDICATES→Malware). See the docstring above.
        if depth < 2:
            return self._bundle(objects.values())
        for v in _nonnull(row["vulns"]):
            v_sdo = self._node_to_sdo("Vulnerability", dict(v))
            self._add(objects, v_sdo)
            # STIX has no "exploits" vocab term; "indicates" is the closest
            # defined value and matches the Indicator→Vulnerability semantics.
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], v_sdo["id"]),
            )
        for t in _nonnull(row["techniques"]):
            t_sdo = self._node_to_sdo("Technique", dict(t))
            self._add(objects, t_sdo)
            # Indicator→Technique: STIX 2.1 vocabulary for indicator
            # source_ref allows "indicates". We use "indicates" here
            # (not "uses") — see proposal doc §5.
            self._add(
                objects,
                self._edge_to_sro("indicates", seed_sdo["id"], t_sdo["id"]),
            )
        for s in _nonnull(row["sectors"]):
            s_sdo = self._node_to_sdo("Sector", dict(s))
            self._add(objects, s_sdo)
            self._add(
                objects,
                self._edge_to_sro("targets", seed_sdo["id"], s_sdo["id"]),
            )

        return self._bundle(objects.values())

    def export_threat_actor(self, name: str, depth: int = _DEFAULT_DEPTH) -> Dict[str, Any]:
        """Bundle centred on a ThreatActor + attributed malware + TTPs + campaigns.

        ``depth=1`` returns only actor + attributed malware (primary
        relation). ``depth=2`` (default) adds actor techniques, the
        malware→technique chain, and campaigns. See ``export_indicator``
        for the general semantics.

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
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        rows = self._run(
            """
            MATCH (a:ThreatActor)
            WHERE (a.name = $name OR $name IN coalesce(a.aliases, []))
              AND a.edgeguard_managed = true
            WITH a
            OPTIONAL MATCH (m:Malware)-[:ATTRIBUTED_TO]->(a)
              WHERE m.edgeguard_managed = true
            WITH a, collect(DISTINCT m) AS malware
            OPTIONAL MATCH (a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
              WHERE t.edgeguard_managed = true
            WITH a, malware, collect(DISTINCT t) AS actor_tech
            UNWIND (CASE WHEN size(malware) = 0 THEN [null] ELSE malware END) AS m_each
            OPTIONAL MATCH (m_each)-[:IMPLEMENTS_TECHNIQUE]->(mt:Technique)
              WHERE m_each IS NOT NULL AND mt.edgeguard_managed = true
            WITH a, malware, actor_tech,
                 collect(DISTINCT CASE WHEN mt IS NULL THEN null ELSE {m: m_each, t: mt} END) AS mal_tech_raw
            WITH a, malware, actor_tech,
                 [pair IN mal_tech_raw WHERE pair IS NOT NULL] AS mal_tech
            OPTIONAL MATCH (a)-[:RUNS]->(c:Campaign)
              WHERE c.edgeguard_managed = true
            RETURN a AS seed,
                   malware,
                   actor_tech,
                   mal_tech,
                   collect(DISTINCT c) AS campaigns
            """,
            {"name": name},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("ThreatActor", dict(seed))
        self._add(objects, seed_sdo)

        mal_ids: Dict[str, str] = {}
        for m in _nonnull(row["malware"]):
            md = dict(m)
            m_sdo = self._node_to_sdo("Malware", md)
            self._add(objects, m_sdo)
            mal_ids[md.get("name", "")] = m_sdo["id"]
            self._add(
                objects,
                self._edge_to_sro("attributed-to", m_sdo["id"], seed_sdo["id"]),
            )

        # depth=1: primary relation only (actor + attributed malware).
        if depth < 2:
            return self._bundle(objects.values())

        for t in _nonnull(row["actor_tech"]):
            t_sdo = self._node_to_sdo("Technique", dict(t))
            self._add(objects, t_sdo)
            self._add(
                objects,
                self._edge_to_sro("uses", seed_sdo["id"], t_sdo["id"]),
            )
        for pair in row["mal_tech"] or []:
            m = pair.get("m") if isinstance(pair, dict) else None
            t = pair.get("t") if isinstance(pair, dict) else None
            if not m or not t:
                continue
            md = dict(m)
            td = dict(t)
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
            self._add(
                objects,
                self._edge_to_sro("uses", m_sdo_id, t_sdo["id"]),
            )
        for c in _nonnull(row["campaigns"]):
            c_sdo = self._node_to_sdo("Campaign", dict(c))
            self._add(objects, c_sdo)
            # The graph edge is (ThreatActor)-[:RUNS]->(Campaign) — the
            # actor owns/operates the campaign. STIX 2.1 expresses this
            # as `relationship_type: attributed-to` with source_ref on
            # the campaign and target_ref on the intrusion-set. See
            # https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_i4tjv75ce50h
            self._add(
                objects,
                self._edge_to_sro("attributed-to", c_sdo["id"], seed_sdo["id"]),
            )

        return self._bundle(objects.values())

    def export_technique(self, mitre_id: str, depth: int = _DEFAULT_DEPTH) -> Dict[str, Any]:
        """Bundle centred on a Technique + everything that uses it.

        ``depth=1`` returns the technique plus only the ThreatActors
        that employ it (primary relation). ``depth=2`` (default) also
        includes Malware, Tools, and Indicators. See ``export_indicator``
        for the general semantics.

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
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        rows = self._run(
            """
            MATCH (t:Technique {mitre_id: $mid})
            WHERE t.edgeguard_managed = true
            WITH t
            OPTIONAL MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t)
              WHERE a.edgeguard_managed = true
            WITH t, collect(DISTINCT a) AS actors
            OPTIONAL MATCH (m:Malware)-[:IMPLEMENTS_TECHNIQUE]->(t)
              WHERE m.edgeguard_managed = true
            WITH t, actors, collect(DISTINCT m) AS malware
            OPTIONAL MATCH (tool:Tool)-[:IMPLEMENTS_TECHNIQUE]->(t)
              WHERE tool.edgeguard_managed = true
            WITH t, actors, malware, collect(DISTINCT tool) AS tools
            OPTIONAL MATCH (i:Indicator)-[:USES_TECHNIQUE]->(t)
              WHERE i.edgeguard_managed = true
            RETURN t AS seed,
                   actors,
                   malware,
                   tools,
                   collect(DISTINCT i) AS indicators
            """,
            {"mid": mitre_id},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Technique", dict(seed))
        self._add(objects, seed_sdo)

        for a in _nonnull(row["actors"]):
            a_sdo = self._node_to_sdo("ThreatActor", dict(a))
            self._add(objects, a_sdo)
            self._add(objects, self._edge_to_sro("uses", a_sdo["id"], seed_sdo["id"]))
        # depth=1: primary relation only (technique + attributed actors).
        if depth < 2:
            return self._bundle(objects.values())
        for m in _nonnull(row["malware"]):
            m_sdo = self._node_to_sdo("Malware", dict(m))
            self._add(objects, m_sdo)
            self._add(objects, self._edge_to_sro("uses", m_sdo["id"], seed_sdo["id"]))
        for tool in _nonnull(row["tools"]):
            tool_sdo = self._node_to_sdo("Tool", dict(tool))
            self._add(objects, tool_sdo)
            self._add(objects, self._edge_to_sro("uses", tool_sdo["id"], seed_sdo["id"]))
        for i in _nonnull(row["indicators"]):
            i_sdo = self._node_to_sdo("Indicator", dict(i))
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("indicates", i_sdo["id"], seed_sdo["id"]))

        return self._bundle(objects.values())

    def export_cve(self, cve_id: str, depth: int = _DEFAULT_DEPTH) -> Dict[str, Any]:
        """Bundle centred on a CVE/Vulnerability + exploiting indicators + affected sectors.

        ``depth=1`` returns the CVE plus only the exploiting Indicators
        (primary relation). ``depth=2`` (default) also includes affected
        sectors. See ``export_indicator`` for the general semantics.
        """
        # PR (S5) (Red Team H1 + Prod #1 + Perf F1): clear
        # the per-export-call source-aggregate cache so subsequent
        # bundles never see stale aggregates from a prior export.
        self._reset_export_cache()
        rows = self._run(
            """
            MATCH (v)
            WHERE (v:CVE OR v:Vulnerability)
              AND v.cve_id = $cve_id
              AND v.edgeguard_managed = true
            OPTIONAL MATCH (i:Indicator)-[:EXPLOITS]->(v)
              WHERE i.edgeguard_managed = true
            WITH v, collect(DISTINCT i) AS indicators
            OPTIONAL MATCH (v)-[:AFFECTS]->(s:Sector)
              WHERE s.edgeguard_managed = true
            RETURN v AS seed,
                   indicators,
                   collect(DISTINCT s) AS sectors
            """,
            {"cve_id": cve_id},
        )
        if not rows:
            return self._empty_bundle()
        row = rows[0]
        seed = row["seed"]
        if seed is None:
            return self._empty_bundle()

        objects: Dict[str, Dict[str, Any]] = {}
        seed_sdo = self._node_to_sdo("Vulnerability", dict(seed))
        self._add(objects, seed_sdo)

        for i in _nonnull(row["indicators"]):
            i_sdo = self._node_to_sdo("Indicator", dict(i))
            self._add(objects, i_sdo)
            self._add(objects, self._edge_to_sro("indicates", i_sdo["id"], seed_sdo["id"]))
        # depth=1: primary relation only (CVE + exploiting indicators).
        if depth < 2:
            return self._bundle(objects.values())
        for s in _nonnull(row["sectors"]):
            s_sdo = self._node_to_sdo("Sector", dict(s))
            self._add(objects, s_sdo)
            self._add(objects, self._edge_to_sro("targets", seed_sdo["id"], s_sdo["id"]))

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

        PR (S5) (Red Team H1 + Prod #1 + Perf F1 HIGH ×3):
        cached per-export-call to eliminate the N+1 query problem.

        PR (S5) (Bug Hunter v2 #4 + Logic Tracker v2 F8 MED):
        previously the silent-bail paths returned props with NO log
        — operator could not see why ``x_edgeguard_*`` extensions were
        missing from a bundle. Now both bail paths emit a WARNING.

        Returns a new dict (does not mutate the input). Safe for
        labels without a SOURCED_FROM edge — props is returned
        unchanged when no edges exist.
        """
        # PR (S5) (bugbot c136baf LOW): validate ``label``
        # before f-string interpolation per project rule. Today's
        # callers all pass hardcoded labels via _node_to_sdo, but
        # the import boundary is the right place to defend against
        # any future caller that might pass an attacker-controlled
        # value (e.g. via a label query parameter).
        from neo4j_client import _validate_label
        from node_identity import natural_key_props

        _validate_label(label)

        # ----- Special case: Campaign reads its own pre-aggregated props
        if label == "Campaign":
            out = dict(props)
            if props.get("first_seen") is not None and "first_seen_at_source" not in out:
                out["first_seen_at_source"] = props["first_seen"]
            if props.get("last_seen") is not None and "last_seen_at_source" not in out:
                out["last_seen_at_source"] = props["last_seen"]
            return out

        try:
            keys = natural_key_props(label)
        except KeyError:
            return props
        # Skip Source / Sector — they don't carry per-source claims
        # (Source IS the source; Sector is a category).
        if label in ("Source", "Sector"):
            return props

        # Build cache key from (label, sorted natural-key tuple).
        # Sort so order-independent for multi-key labels like NetworkService.
        cache_key = (label, tuple(sorted((k, props.get(k)) for k in keys)))

        # If any natural-key value is None we can't safely look up — bail
        # (with WARNING so operator can see the missing extension).
        if any(v is None for _, v in cache_key[1]):
            logger.warning(
                "STIX source-aggregate skipped for %s — missing natural-key value(s) %s; "
                "x_edgeguard_first_seen_at_source extension will be absent from this SDO",
                label,
                {k: v for k, v in cache_key[1]},
            )
            return props

        # Per-export-call cache hit?
        if cache_key in self._aggregate_cache:
            agg = self._aggregate_cache[cache_key]
        else:
            where = " AND ".join(f"n.`{k}` = $key_{k}" for k in keys)
            params = {f"key_{k}": props.get(k) for k in keys}
            try:
                rows = self._run(
                    f"""
                    MATCH (n:{label}) WHERE {where}
                    OPTIONAL MATCH (n)-[r:SOURCED_FROM]->(:Source)
                    RETURN min(r.source_reported_first_at) AS first_seen_at_source,
                           max(r.source_reported_last_at) AS last_seen_at_source
                    """,
                    params,
                )
            except Exception as e:
                # If the lookup fails (driver issue, transient), we still
                # return a valid SDO — just without the source-truthful
                # extension. The caller's ``valid_from`` chain falls
                # through to ``first_imported_at``. Log so operators see
                # the silent degradation.
                logger.warning(
                    "STIX source-aggregate query FAILED for %s key=%s: %s: %s — "
                    "SDO emitted without x_edgeguard_* extensions",
                    label,
                    params,
                    type(e).__name__,
                    e,
                )
                return props
            agg = rows[0] if rows else {}
            self._aggregate_cache[cache_key] = agg

        out = dict(props)
        if agg.get("first_seen_at_source") is not None:
            out["first_seen_at_source"] = agg["first_seen_at_source"]
        if agg.get("last_seen_at_source") is not None:
            out["last_seen_at_source"] = agg["last_seen_at_source"]
        return out

    def _reset_export_cache(self) -> None:
        """Clear the per-export-call source-aggregate cache.

        PR (S5): called at the start of every public ``export_*``
        method so subsequent exports don't see stale aggregates from
        prior calls. The cache is bundle-scoped — eliminates N+1
        within one bundle without leaking state across bundles.
        """
        self._aggregate_cache.clear()

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
            allow_custom=True,
            **_producer_created_modified(props),
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
            allow_custom=True,
            **_producer_created_modified(props),
        )
        return self._apply_source_truthful_custom_props(_to_dict(obj), props)

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
            "allow_custom": True,
        }
        if ext_refs:
            kwargs["external_references"] = ext_refs

        # Promote CVSS + severity + CISA KEV + NVD dates + CWE /
        # references to STIX custom properties so the SDO actually
        # carries the Neo4j enrichment through to ResilMesh.
        _promoted_fields = (
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
        )
        for neo4j_key, stix_key in _promoted_fields:
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
        obj = stix2.Identity(
            id=stix_id,
            name=name,
            identity_class="class",
            sectors=[name] if name else None,
            allow_custom=True,
        )
        return _to_dict(obj)

    # ------------------------------------------------------------------
    # Edge → SRO
    # ------------------------------------------------------------------

    def _edge_to_sro(self, relationship_type: str, source_ref: str, target_ref: str) -> Dict[str, Any]:
        """Build a deterministic Relationship SRO between two SDOs."""
        stix_id = _deterministic_id("relationship", f"{source_ref}|{relationship_type}|{target_ref}")
        obj = stix2.Relationship(
            id=stix_id,
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            allow_custom=True,
        )
        return _to_dict(obj)

    # ------------------------------------------------------------------
    # Bundle assembly
    # ------------------------------------------------------------------

    def _add(self, objects: Dict[str, Dict[str, Any]], sdo: Optional[Dict[str, Any]]) -> Optional[str]:
        """Insert a SDO/SRO into the bundle dict, keyed by its STIX id."""
        if not sdo:
            return None
        objects.setdefault(sdo["id"], sdo)
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
        objects_list = sorted(
            list(objects),
            key=lambda o: o.get("id", ""),
        )
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
            "x_edgeguard_source": _bundle_provenance(),
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


def _nonnull(items: Any) -> List[Any]:
    """Drop None entries from a collect() result."""
    return [x for x in (items or []) if x is not None]


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
    """Build the bundle-level ``x_edgeguard_source`` dict.

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
        "producer": "EdgeGuard Knowledge Graph",
        "exporter": "stix_exporter",
        "git_sha": _GIT_SHA or None,
        "spec_version": "2.1",
    }
    if not _is_truthy_env("EDGEGUARD_DETERMINISTIC_BUNDLE"):
        provenance["generated_at"] = _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    return provenance


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
