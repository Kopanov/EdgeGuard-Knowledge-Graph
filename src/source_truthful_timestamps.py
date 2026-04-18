"""Per-source first_seen / last_seen extraction for the MISP→Neo4j sync.

Why this module exists
----------------------
The proactive-audit Logic Tracker found (Tier S item S5) that EdgeGuard
ships ``Indicator.valid_from = 1970-01-01T00:00:00Z`` to ResilMesh on
EVERY indicator, because:

1. ``parse_attribute`` populated ``item["first_seen"]`` from
   ``event_info.get("date")`` — the **MISP event date**, which is
   "when EdgeGuard wrote the MISP event", NOT "when the world first
   observed this indicator".
2. PR #34 round 17 deliberately removed ``first_seen`` from the
   Neo4j Indicator/Vulnerability batch MERGE because the value was
   unreliable. So the Neo4j node had no ``first_seen``.
3. ``stix_exporter._build_indicator`` falls back to a 1970 epoch
   sentinel when ``first_seen`` is missing — ResilMesh receives
   year-1970 timestamps every poll.

The Source-Truth Investigator audit confirmed that 9 of 11
collectors DO capture a reliable upstream first-seen field, but it
silently drops at the MISPWriter handoff (only NVD survives via
``NVD_META`` JSON in the comment field) OR at the
``parse_attribute`` reader.

Design — OpenCTI / MISP / STIX 2.1 industry consensus
-----------------------------------------------------
Two distinct properties on every Indicator/Vulnerability/Malware/
ThreatActor/Campaign node:

* ``n.first_seen_at_source``: source-truthful first observation,
  ISO-8601 with TZ. NULLable. The source's own claim about when
  the world first saw this entity.
* ``n.first_imported_at``: EdgeGuard's first MERGE wall-clock time,
  ISO-8601 with TZ. **Always set on ON CREATE; never overwritten.**

Same shape for ``last_seen_at_source`` vs ``last_updated``.

This mirrors the OpenCTI model exactly — ``first_seen`` (source
truth) vs ``created_at`` (DB-local). It also maps cleanly onto
STIX 2.1: ``Indicator.valid_from = first_seen_at_source`` (canonical
STIX field), ``first_imported_at`` becomes a producer-specific
``x_edgeguard_*`` extension.

Allowlist — only TRUSTED upstream sources populate first_seen_at_source
----------------------------------------------------------------------
Not all sources have a meaningful "first seen" semantic:

* ✅ NVD ``published`` — when NVD first published the CVE (canonical)
* ✅ CISA ``dateAdded`` — when KEV listed the CVE (canonical)
* ✅ MITRE ATT&CK STIX ``created`` — STIX object creation (canonical)
* ✅ VirusTotal ``first_submission_date`` — first submission to VT (canonical)
* ✅ AbuseIPDB ``firstSeen`` — first report to AbuseIPDB (canonical)
* ✅ ThreatFox ``first_seen`` — first sighting by ThreatFox (canonical)
* ✅ URLhaus ``dateadded`` — when URL was added (canonical)
* ✅ Feodo Tracker ``first_seen`` — first C2 IP sighting (canonical)
* ✅ SSL Blacklist ``date`` — first listing (canonical)
* ❌ OTX pulse ``created`` — when the pulse was AUTHORED, NOT when
  the indicator was first observed. Misleading; excluded.
* ❌ CyberCure synthetic ``now()`` — useless; excluded.
* ❌ MISP-collector / sector feeds ``event.date`` — pipeline
  metadata; excluded.

When the source is NOT in the allowlist OR the source's first_seen
field is missing, ``first_seen_at_source`` is set to NULL (not the
sync time). NULL semantically means "we don't know"; it's
intentionally distinct from ``first_imported_at`` which always has a
value.

Baseline + incremental correctness
----------------------------------
The Cypher pattern uses MIN logic for first_seen_at_source so
out-of-order arrivals work correctly:

  ON CREATE SET n.first_seen_at_source = item.first_seen_at_source
  SET n.first_seen_at_source = CASE
    WHEN item.first_seen_at_source IS NOT NULL
     AND (n.first_seen_at_source IS NULL OR item.first_seen_at_source < n.first_seen_at_source)
    THEN item.first_seen_at_source
    ELSE n.first_seen_at_source
  END

Scenarios this handles correctly:
* Baseline writes 2019-01-15 (NVD); incremental tomorrow writes
  same → 2019 preserved (MIN keeps older)
* Out-of-order: incremental writes NULL today, baseline backfills
  2019-01-15 next week → 2019 takes over (MIN of NULL+value = value)
* MISP attribute re-uploaded with truncated first_seen=event_date
  (newer than original) → REJECTED, original older value preserved
* Multi-source: NVD writes 2019, then OTX writes NULL → 2019 stays
* Incremental re-touches existing node from baseline →
  ``first_imported_at`` UNCHANGED (ON CREATE only); MIN preserves
  earliest source observation
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Allowlist — sources whose first_seen / last_seen we trust
# ---------------------------------------------------------------------------

# Keyed on the ORIGINAL source tag (raw_data.original_source if present,
# falling back to source_id). This matters because indicators may be
# relayed: ThreatFox → OTX → MISP → EdgeGuard. The relay step doesn't
# change the upstream truth, but the source_id of the COLLECTOR that
# fetched the relayed copy might be "otx". We need to credit the
# original source's first_seen, not the relay's.
_RELIABLE_FIRST_SEEN_SOURCES: frozenset = frozenset(
    {
        "nvd",
        "cisa",
        "mitre_attck",
        "mitre",
        "virustotal",
        "vt",
        "abuseipdb",
        "threatfox",
        "urlhaus",
        "feodo_tracker",
        "feodo",
        "ssl_blacklist",
        "abusech_ssl",
    }
)


def _normalize_source_key(source_id: Optional[str]) -> str:
    """Lowercase + strip; identifies sources case-insensitively."""
    if not source_id:
        return ""
    return str(source_id).strip().lower()


def is_reliable_first_seen_source(source_id: Optional[str]) -> bool:
    """Return True if the named source provides a canonical
    first-seen-by-source timestamp we should trust.

    Rejects relay-only sources (OTX whose pulse-created date is when
    the analyst wrote the pulse, NOT when the IOC first appeared in
    the world) and synthetic sources (CyberCure now()).
    """
    return _normalize_source_key(source_id) in _RELIABLE_FIRST_SEEN_SOURCES


# ---------------------------------------------------------------------------
# Future-date clamp
# ---------------------------------------------------------------------------


def _clamp_future_to_now(iso: Optional[str]) -> Optional[str]:
    """Clamp a future-dated ISO timestamp to UTC now.

    Defensive: an upstream feed bug or operator clock drift could
    produce a value like 2099-01-01. We never trust the future —
    silently clamp + WARNING log so it surfaces in operator dashboards.

    Returns the original string when the value is in the past or
    parse fails (we'd rather pass an unparseable string downstream
    than swallow it; the merge layer already handles odd inputs).
    """
    if not iso:
        return iso
    try:
        # Tolerate a trailing "Z" (Python's fromisoformat doesn't accept it pre-3.11)
        normalized = iso.replace("Z", "+00:00") if iso.endswith("Z") else iso
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        # Unparseable; leave for the downstream layer to handle.
        return iso

    now = datetime.now(timezone.utc)
    if parsed > now:
        logger.warning(
            "Source-truthful timestamp %s is in the future (now=%s) — clamping to now. "
            "Likely upstream feed bug or clock drift.",
            iso,
            now.isoformat(),
        )
        return now.isoformat()
    return iso


# ---------------------------------------------------------------------------
# Per-attribute extraction — the main entry point used by parse_attribute
# ---------------------------------------------------------------------------


def coerce_iso(val: Any) -> Optional[str]:
    """Canonical ISO-8601 coercion helper for source-truthful timestamp
    values arriving from collectors / MISP / NVD JSON.

    PR (S5) commit X (bugbot LOW): consolidated here as the **single
    source of truth**. Previously this logic existed both as a
    private ``_coerce_iso`` in this module AND as a private
    ``_coerce_to_iso`` in ``run_misp_to_neo4j``. Bugbot correctly
    flagged the duplication as a divergence risk — a bug fix in one
    copy wouldn't propagate to the other. ``run_misp_to_neo4j``
    now imports this function directly (no circular import:
    ``run_misp_to_neo4j`` already imports
    ``extract_source_truthful_timestamps`` from this module, so the
    dependency arrow already points the same way).

    Handles None/empty, Unix int/float epoch, datetime objects, and
    passthrough strings. Returns ``None`` for unparseable / empty inputs
    so the caller can distinguish "missing" from "set to wall-clock now".
    """
    if val is None:
        return None
    if isinstance(val, str) and not val.strip():
        return None
    if isinstance(val, (int, float)):
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, str):
        return val
    return None


# Backward-compat alias kept private — internal callers in this module
# still spell it _coerce_iso. Public consumers should use coerce_iso.
_coerce_iso = coerce_iso


def iso_str(val: Any) -> Optional[str]:
    """Public utility: coerce a Neo4j-driver temporal value (or anything
    date-like) into a plain ISO-8601 string for JSON / STIX serialization.

    PR (S5) commit X (bugbot LOW): consolidated here from the previously-
    duplicated copies in ``stix_exporter._iso_str`` and
    ``alert_processor._iso_str``. Single source of truth — bug fix in
    one place propagates to all callers.

    The neo4j Python driver returns ``neo4j.time.DateTime`` objects when
    reading a node's DateTime property. Those don't round-trip through
    ``stix2.utils.parse_into_datetime()`` (it raises) or through
    ``json.dumps`` (no default serializer). The fix is to convert to a
    plain ISO string at every read site that hands the value to a
    third-party serializer.

    Both ``neo4j.time.DateTime`` and Python's ``datetime.datetime``
    expose ``.isoformat()``; for any other type we fall back to ``str()``
    which is correct for already-string values and harmless for None.
    """
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        try:
            return val.isoformat()
        except (TypeError, ValueError):
            pass
    if isinstance(val, str):
        return val if val.strip() else None
    try:
        s = str(val).strip()
        return s or None
    except Exception:
        return None


def extract_source_truthful_timestamps(
    attr: Dict[str, Any],
    source_id: Optional[str],
    *,
    nvd_meta: Optional[Dict[str, Any]] = None,
    tf_meta: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Extract ``(first_seen_at_source, last_seen_at_source)`` for one
    MISP attribute, returning ``(None, None)`` when the source is not
    on the reliable allowlist.

    Resolution order (first-non-empty wins per field):

    1. **MISP-native attribute fields** (``attr["first_seen"]`` /
       ``attr["last_seen"]``). MISPWriter populates these for every
       indicator (``misp_writer.py:create_indicator_attribute``) and
       every vulnerability (``misp_writer.py:create_vulnerability_attribute``,
       added in PR S5 follow-up to fix bugbot MED). MISP 2.4.120+
       supports them natively. **This is the canonical, lossless
       round-trip path** — the upstream collector's value is preserved
       through MISP and read back here unchanged. ALL 9 allowlisted
       sources rely on Layer 1 as the primary path.
    2. **Source-specific META JSON** carried in the MISP attribute
       comment. **Layer 2 only exists for sources that already
       persist a structured-metadata blob in the comment field for
       other reasons** (NVD ships ``NVD_META`` JSON for CVSS / CWE /
       reference data; ThreatFox ships ``TF_META`` JSON for malware
       family / Malpedia / reporter). The 7 other allowlisted sources
       (CISA, MITRE, VirusTotal, AbuseIPDB, URLhaus, Feodo, SSL
       Blacklist) do NOT have a Layer 2 fallback — by design. Each
       ships only a free-text comment (no structured JSON), so there
       is nothing to parse back. Their first-seen value flows through
       Layer 1 (MISP-native fields) exclusively. If Layer 1 is empty
       AND the source is one of those 7, the function returns
       ``None`` — semantically "we don't know" — and the caller's
       MERGE preserves any prior value via MIN logic.
    3. **None** — signal "we don't know"; caller's MERGE preserves
       any existing value via MIN logic.

    Coverage matrix (PR S5 final state):

    +---------------+---------+---------+---------------------------+
    | Source        | Layer 1 | Layer 2 | Notes                     |
    +===============+=========+=========+===========================+
    | NVD           |   ✅    |   ✅    | NVD_META.published        |
    | CISA          |   ✅    |   ❌    | dateAdded via Layer 1     |
    | MITRE         |   ✅    |   ❌    | STIX created via Layer 1  |
    | VirusTotal    |   ✅    |   ❌    | first_submission via L1   |
    | AbuseIPDB     |   ✅    |   ❌    | firstSeen via Layer 1     |
    | ThreatFox     |   ✅    |   ✅    | TF_META.first_seen        |
    | URLhaus       |   ✅    |   ❌    | dateadded via Layer 1     |
    | Feodo         |   ✅    |   ❌    | first_seen via Layer 1    |
    | SSL Blacklist |   ✅    |   ❌    | date via Layer 1          |
    +---------------+---------+---------+---------------------------+

    Adding Layer 2 for the 7 source-without-META-JSON sources would
    require introducing new comment-encoded JSON blobs (``CISA_META``,
    ``VT_META``, etc.) — significant new code for a marginal
    safety net (Layer 1 already covers them with the MISP 2.4.120+
    native-field round-trip). Tracked as a possible follow-up if
    operational evidence shows Layer 1 dropouts for any source.

    Future-dated values are clamped to ``now()`` with a WARNING log.
    Unreliable / relay-only sources (OTX, CyberCure, MISP-only)
    return ``(None, None)`` regardless of what the attribute
    contains — their first_seen field is semantically wrong for our
    purpose (pulse-publish-date, not IOC first-seen).

    PR (S5) commit X (bugbot LOW): removed the dead ``otx_meta``
    parameter + the corresponding unreachable ``elif src in
    {"otx", ...}`` branch. OTX is excluded from the allowlist so
    the branch could never fire. If OTX ever exposes a reliable
    per-IOC first-seen field, add it back to the allowlist + add
    the ``otx_meta`` parameter back here.

    Parameters
    ----------
    attr:
        The MISP attribute dict (from PyMISP).
    source_id:
        The original source identifier, normalized lowercase. Caller
        should resolve relays — pass the tag of the source that
        ORIGINALLY observed the indicator, not the relay collector.
    nvd_meta, tf_meta:
        Pre-parsed source-specific META JSON dicts (when the parser
        already extracted them for other purposes). Avoids re-parsing
        the comment field.
    """
    if not is_reliable_first_seen_source(source_id):
        return (None, None)

    # Layer 1: MISP-native attribute fields (the lossless round-trip path)
    first_seen = _coerce_iso(attr.get("first_seen"))
    last_seen = _coerce_iso(attr.get("last_seen"))

    # Layer 2: source-specific META JSON fallback
    src = _normalize_source_key(source_id)
    if src in {"nvd"} and nvd_meta:
        first_seen = first_seen or _coerce_iso(nvd_meta.get("published"))
        last_seen = last_seen or _coerce_iso(nvd_meta.get("last_modified"))
    elif src == "threatfox" and tf_meta:
        first_seen = first_seen or _coerce_iso(tf_meta.get("first_seen"))
        last_seen = last_seen or _coerce_iso(tf_meta.get("last_seen"))

    return (_clamp_future_to_now(first_seen), _clamp_future_to_now(last_seen))


# PR (S5) commit X (bugbot LOW): removed the unused
# ``extract_from_attribute_json`` convenience wrapper. The audit caught
# that no production code path called it — the only callers were tests.
# Production parse_attribute already has the META dicts pre-parsed for
# other purposes (NVD_META scoring, TF_META reference URLs, etc.) and
# passes them directly to ``extract_source_truthful_timestamps`` via
# kwargs. If a future caller genuinely needs comment-auto-parsing they
# can re-add the helper or do the JSON parse inline.
