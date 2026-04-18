"""Per-source first_seen / last_seen extraction + edge stamping for MISP→Neo4j.

Model: two pairs, honest naming
-------------------------------

EdgeGuard stores timestamps in TWO semantically-distinct places:

**Node properties — DB-local facts ONLY.** Cannot be misread as
real-world claims.

* ``n.first_imported_at`` — when EdgeGuard first MERGEd this node.
  ON CREATE SET only; never overwritten. Set once per node lifetime.
* ``n.last_updated`` — when EdgeGuard last MERGEd / touched this node.
  Refreshed to ``datetime()`` on every MERGE.

**Edge properties on ``(:Node)-[r:SOURCED_FROM]->(:Source)`` —
per-source claims.** One edge per (entity, source) pair.

* ``r.imported_at`` / ``r.updated_at`` — DB-local facts scoped to THIS
  source. When EdgeGuard first/last saw this source report this entity.
* ``r.source_reported_first_at`` — the source's OWN claim about when
  it first recorded the entity. Nullable (NULL = "we don't have a
  meaningful claim from this source"). MIN CASE with AND-guard:
  earliest claim wins; stale imports cannot regress.
* ``r.source_reported_last_at`` — the source's own last-reported
  claim. Nullable. MAX CASE with AND-guard: latest claim wins.

**Why the edge design**: an indicator reported by NVD + AbuseIPDB +
ThreatFox has three SOURCED_FROM edges. Each edge preserves that
source's specific claim. Aggregating to a single node property would
destroy the per-source provenance. Queries that want a single
canonical value compute ``MIN(r.source_reported_first_at)`` / ``MAX(...)``
across the edges on read (STIX valid_from, alert enrichment, campaign
aggregate all do this).

**The names are deliberate**. ``source_reported_first_at`` on the
edge makes explicit: "what the source claims", not "first observed
in reality". (Sources record "when we cataloged it", not "when
observed in the wild". NVD's ``published`` is catalog-date; CISA's
``dateAdded`` is list-date; MITRE's ``created`` is TAXII-store-date.)

Why this module exists
----------------------
The proactive-audit Logic Tracker found (Tier S item S5) that EdgeGuard
was shipping ``Indicator.valid_from = 1970-01-01T00:00:00Z`` to ResilMesh
on every indicator. Multiple upstream handoffs were silently dropping
the source's first-seen claim. This module:

1. Defines the ``_RELIABLE_FIRST_SEEN_SOURCES`` allowlist — which
   sources have a meaningfully-semantic first-reported timestamp
   (NVD, CISA, MITRE, VirusTotal, AbuseIPDB, ThreatFox, URLhaus,
   Feodo Tracker, SSL Blacklist) vs. excluded (OTX pulse-publish-date,
   CyberCure synthetic now, MISP pipeline metadata).
2. Exposes ``extract_source_truthful_timestamps(attr, source_id, ...)``
   which reads MISP-native + Layer-2 META-JSON fallbacks and returns
   ``(first_seen, last_seen)`` claims for the allowlisted source.
3. Exposes ``coerce_iso()`` and ``iso_str()`` — input-hardened ISO-8601
   coercion helpers (ASCII gate on shape check, calendar-date validation,
   int-epoch sanity bounds, future-date clamping). Used by MISPWriter
   on write and by STIX/alert readers on read.

The caller (``run_misp_to_neo4j.parse_attribute``) stuffs the
extracted ``(first_seen, last_seen)`` pair into the item dict as
``item["first_seen_at_source"]`` / ``item["last_seen_at_source"]``,
and ``neo4j_client`` forwards them to the edge MERGE Cypher as
``r.source_reported_first_at`` / ``r.source_reported_last_at``.

Allowlist — WHAT EACH SOURCE'S TIMESTAMP ACTUALLY MEANS
-------------------------------------------------------
Names in the allowlist must match the exact tag each collector emits
(see ``test_collector_emitted_tags_match_allowlist`` for the pin).
Dual-aliases (``cisa`` / ``cisa_kev``) are retained because
``config.SOURCE_TAGS`` maps the human label to one form but legacy
callers / tests use the other.

* ✅ ``nvd`` — NVD ``published`` (when NVD published the CVE to its
  catalog; NOT when first exploited)
* ✅ ``cisa`` / ``cisa_kev`` — CISA ``dateAdded`` (when CISA added it
  to KEV; typically AFTER attacks observed in the wild)
* ✅ ``mitre_attck`` / ``mitre`` — STIX ``created`` from MITRE's TAXII
  server (when MITRE cataloged the technique/malware/actor; NOT when
  first observed in the wild — MITRE imports often batch-stamp at
  2017-05-31 from the original CTI content)
* ✅ ``virustotal`` / ``vt`` — ``first_submission_date`` (when first
  submitted to VT's scanner; NOT when first seen in the wild)
* ✅ ``abuseipdb`` — ``firstSeen`` (when first reported to AbuseIPDB;
  the blacklist endpoint intentionally emits NULL for first_seen —
  see abuseipdb_collector.py for rationale)
* ✅ ``threatfox`` — ``first_seen`` (when first tracked by ThreatFox)
* ✅ ``urlhaus`` — ``dateadded`` (when added to URLhaus catalog;
  ``last_online`` → ``last_seen``)
* ✅ ``feodo_tracker`` / ``feodo`` — ``first_seen`` (when first C2 IP
  sighted by Feodo Tracker)
* ✅ ``ssl_blacklist`` / ``abusech_ssl`` — CSV ``Listingdate``
* ❌ ``alienvault_otx`` — pulse.created is the pulse-author-time,
  NOT the IOC first-observed time. Excluded.
* ❌ ``cybercure`` — synthetic ``now()``. Excluded.
* ❌ ``misp`` — MISP-collector / sector feeds; pipeline metadata only.

**When the source is NOT in the allowlist OR the source's field
is missing, the extractor returns (None, None).** The edge MIN/MAX
CASE with AND-guard then preserves any prior value — NULL never
overwrites a populated claim.

Stale-import + regression protection
------------------------------------
The MIN/MAX CASE pattern on the edge (applied in 3 Cypher sites:
``merge_indicators_batch``, ``merge_vulnerabilities_batch``,
``_upsert_sourced_relationship``) handles every realistic scenario:

* Baseline writes 2019-01-15 (NVD); incremental tomorrow re-writes
  same value → MIN keeps 2019.
* Out-of-order: incremental writes NULL today (NULL AND-guard blocks
  the overwrite); baseline backfills 2019 next week → 2019 wins.
* Stale MISP re-upload with `first_seen = event_date` (newer than
  original) → MIN rejects the later value; original preserved.
* Source corrects itself (NVD re-reports with earlier published
  date): MIN accepts the legitimate backdate.
* New source arrives (NVD already wrote 2019, now ThreatFox reports
  2024): a NEW edge is created for ThreatFox with its own 2024 claim;
  NVD's edge 2019 is untouched. STIX aggregate `valid_from` = MIN
  across both edges = 2019.
* Incremental re-touches existing node → ``n.first_imported_at``
  UNCHANGED (ON CREATE SET only); per-source edges'
  ``source_reported_first_at`` preserve earliest via MIN.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prometheus counter wiring (defensive import)
# ---------------------------------------------------------------------------
# Imported defensively so this module stays importable in test contexts
# that don't bring up prometheus_client (or that monkey-patch the
# metrics registry between tests). The four ``_metric_*`` shims are
# unconditionally callable; they no-op when the import fails.
#
# Counter design and label-cardinality budget live in
# ``src/metrics_server.py`` next to the ``SOURCE_TRUTHFUL_*`` Counter
# definitions. Spawned-task chip 5b from the PR #41 audit.
try:
    from metrics_server import (
        record_source_truthful_claim_accepted as _metric_accept,
    )
    from metrics_server import (
        record_source_truthful_claim_dropped as _metric_drop,
    )
    from metrics_server import (
        record_source_truthful_coerce_rejected as _metric_coerce_reject,
    )
    from metrics_server import (
        record_source_truthful_future_clamp as _metric_future_clamp,
    )
except ImportError:  # pragma: no cover — defensive
    # Mypy enforces "all conditional function variants must have
    # identical signatures" — keep these no-ops in lock-step with
    # the metrics_server helpers they shadow. If you change a helper
    # signature, change BOTH places.
    def _metric_accept(source_id: Optional[str], field: str) -> None:
        return None

    def _metric_drop(source_id: Optional[str], reason: str, field: str) -> None:
        return None

    def _metric_coerce_reject(reason: str) -> None:
        return None

    def _metric_future_clamp() -> None:
        return None


# ---------------------------------------------------------------------------
# Sanity bounds for int/float Unix epoch parsing in coerce_iso
# ---------------------------------------------------------------------------
# PR (S5) (Devil's Advocate v3 #3 + user-driven design principle):
# **Honest NULL > arbitrary floor**. Earlier we used a 1990-01-01 floor on
# the rationale that "no legitimate threat-intel timestamp predates this".
# Devil's Advocate correctly pointed out that CVE-1999-XXXX series exists
# (and CVE-1988 Morris worm reference), and NVD does occasionally publish
# CVE records that legitimately reference earlier-discovered vulnerabilities.
# Silently dropping those (returning None, letting MIN preserve a NEWER
# value) loses real data — the kind of ambiguous fabrication the user's
# principle explicitly forbids: "if we can't identify the date of the
# origin, we don't use ambiguous naming".
#
# What we DO reject: epoch sentinels (0, -1) and overflow-causing values.
# What we ACCEPT: any int/float in (0, 253402300799] that
# ``datetime.fromtimestamp`` can parse — including pre-1990 dates.
# An entry that says "first observed 1985-12-15" is honest data, not a
# bug; we let it through and the consumer can decide how to interpret it.
_INT_EPOCH_FLOOR = 1  # 1970-01-01T00:00:01 UTC (rejects 0 + negative sentinels)
_INT_EPOCH_CEIL = 253_402_300_799  # 9999-12-31 UTC (datetime.fromtimestamp limit)


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
        # CISA: collector emits "cisa_kev" (config.SOURCE_TAGS["cisa"] =
        # "cisa_kev"); legacy collectors / tests / direct callers may
        # still pass "cisa". Both must be on the allowlist or the CISA
        # passthrough fix in PR (S5) is dead. Bugbot caught the
        # misalignment in commit ac25b07.
        "cisa",
        "cisa_kev",
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
        _metric_future_clamp()
        return now.isoformat()
    return iso


# ---------------------------------------------------------------------------
# Per-attribute extraction — the main entry point used by parse_attribute
# ---------------------------------------------------------------------------


def coerce_iso(val: Any) -> Optional[str]:
    """Canonical ISO-8601 coercion helper for source-truthful timestamp
    values arriving from collectors / MISP / NVD JSON.

    PR (S5) (bugbot LOW): consolidated here as the **single
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

    PR (S5) (bugbot MED): date-only strings (e.g. CISA KEV's
    ``"2026-04-16"``) are now normalized to a full ISO-8601 datetime
    by appending ``T00:00:00+00:00``. Without this, downstream Neo4j
    Cypher ``datetime(item.first_seen_at_source)`` calls would crash
    on the date-only format (Neo4j's ``datetime()`` requires a time
    component) — taking the entire vulnerability batch MERGE down.
    The most affected source is CISA KEV: ``dateAdded`` is universally
    date-only. Same potential exposure for any other feed that ships
    bare dates.
    """
    if val is None:
        return None
    if isinstance(val, str) and not val.strip():
        return None
    if isinstance(val, (int, float)):
        # PR (S5) (Red Team #4 HIGH + Bug Hunter v2 #7 HIGH):
        # bound the int/float epoch to reject SENTINELS and OVERFLOW
        # values only — see _INT_EPOCH_FLOOR / _INT_EPOCH_CEIL above
        # and the comment block immediately preceding them for the
        # full reasoning.
        #
        # Failure modes the bounds defend against:
        # - Without ANY bound: malformed JSON ints (``2**63``, negative
        #   sentinels like ``-1``, millisecond-encoded epochs
        #   misinterpreted as seconds) raise ``OverflowError`` / ``OSError``,
        #   crashing the entire ``parse_attribute`` call.
        # - 0 / negative sentinels would anchor MIN(source_reported_first_at)
        #   permanently at the Unix epoch, reintroducing the original
        #   "1970-leak" bug through a different door.
        #
        # What we do NOT do: add a synthetic "year 1990" sanity floor.
        # An earlier draft of this PR rejected anything before
        # 631152000 (1990-01-01 UTC) on the theory that pre-1990
        # timestamps are not legitimate threat-intel claims. The
        # Devil's Advocate / pre-release review reversed that: a
        # source genuinely reporting "first observed 1985-12-15" is
        # honest data, not a parse error, and EdgeGuard's posture is
        # honest-NULL (we let the source claim through and let the
        # consumer interpret). The floor is 1 (rejects only 0 and
        # negative sentinels) and the ceil is the datetime.fromtimestamp
        # limit (rejects overflow). Anything between is accepted.
        try:
            if not (_INT_EPOCH_FLOOR <= val <= _INT_EPOCH_CEIL):
                # Counter (PR follow-up): operators can see the sentinel-vs-overflow
                # distribution to spot a misbehaving collector dumping 0 / -1 vs.
                # one accidentally feeding millisecond epochs as seconds.
                _metric_coerce_reject("sentinel_epoch")
                return None
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            _metric_coerce_reject("overflow")
            return None
    if isinstance(val, datetime):
        return val.isoformat()
    if isinstance(val, str):
        # PR (S5) (Red Team HIGH ×2 + Red Team v2 H3 HIGH):
        # defensive input validation on string parsing.
        # - Red Team #1: ``str.isdigit()`` returns True for fullwidth
        #   Unicode digits (e.g. "２０２４"). Without an ASCII gate,
        #   non-ASCII date strings would pass the shape check, get
        #   the timezone suffix appended, and then crash Neo4j's
        #   Cypher ``datetime()`` — taking the entire UNWIND batch
        #   down.
        # - Red Team #3: invalid calendar dates like "2024-13-99" pass
        #   the shape check but are rejected by Cypher datetime().
        #   Same batch-crash exposure.
        # - Red Team v2 H3: previously the FULL-STRING branch (anything
        #   not exactly 10 chars) just returned the string unchanged,
        #   without validation. So ``"2024-13-99T10:00:00Z"`` (length
        #   20 — fails the date-only shape check) flowed through
        #   unguarded → Cypher datetime() rejected → entire UNWIND
        #   batch crashed. Fix: validate ALL string inputs via
        #   ``datetime.fromisoformat``; return None on parse failure.
        s = val.strip()
        # 1. Date-only branch (YYYY-MM-DD, 10 chars): normalize to UTC
        #    midnight after validating the calendar date is real.
        if (
            len(s) == 10
            and s.isascii()
            and s[4] == "-"
            and s[7] == "-"
            and s[:4].isdigit()
            and s[5:7].isdigit()
            and s[8:10].isdigit()
        ):
            try:
                datetime.fromisoformat(s)
            except ValueError:
                _metric_coerce_reject("malformed_string")
                return None
            return s + "T00:00:00+00:00"
        # 2. Full-string branch: validate via fromisoformat (with the
        #    Z-tolerance shim used elsewhere in the module).
        normalized = s.replace("Z", "+00:00") if s.endswith("Z") else s
        try:
            datetime.fromisoformat(normalized)
        except (ValueError, TypeError):
            # Unparseable — return None so the caller's MIN/MAX logic
            # preserves any prior value rather than crashing the
            # downstream Cypher ``datetime()`` call. Logged at the
            # caller layer (extract_source_truthful_timestamps) where
            # source_id context is available for better triage.
            _metric_coerce_reject("malformed_string")
            return None
        return s
    return None


# Backward-compat alias kept private — internal callers in this module
# still spell it _coerce_iso. Public consumers should use coerce_iso.
_coerce_iso = coerce_iso


def iso_str(val: Any) -> Optional[str]:
    """Public utility: coerce a Neo4j-driver temporal value (or anything
    date-like) into a plain ISO-8601 string for JSON / STIX serialization.

    PR (S5) (bugbot LOW): consolidated here from the previously-
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

    PR (S5) (bugbot LOW): removed the dead ``otx_meta``
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
        # Single emit (field="both") — we never even attempt per-field
        # extraction for unreliable sources, so per-field counters would
        # double-count this case.
        _metric_drop(source_id, "source_not_in_allowlist", "both")
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

    # Final accept/drop accounting per field. Counter is emitted AFTER
    # both layers run (so a Layer-2 fallback that fills in a missing
    # Layer-1 value counts as accepted, not dropped). Honest-NULL drops
    # — source on the allowlist but neither layer supplied a value —
    # are counted under reason=no_data_from_source so operators can
    # see the per-source baseline rate.
    final_first = _clamp_future_to_now(first_seen)
    final_last = _clamp_future_to_now(last_seen)
    if final_first is not None:
        _metric_accept(source_id, "first_seen")
    else:
        _metric_drop(source_id, "no_data_from_source", "first_seen")
    if final_last is not None:
        _metric_accept(source_id, "last_seen")
    else:
        _metric_drop(source_id, "no_data_from_source", "last_seen")
    return (final_first, final_last)


# PR (S5) (bugbot LOW): removed the unused
# ``extract_from_attribute_json`` convenience wrapper. The audit caught
# that no production code path called it — the only callers were tests.
# Production parse_attribute already has the META dicts pre-parsed for
# other purposes (NVD_META scoring, TF_META reference URLs, etc.) and
# passes them directly to ``extract_source_truthful_timestamps`` via
# kwargs. If a future caller genuinely needs comment-auto-parsing they
# can re-add the helper or do the JSON parse inline.
