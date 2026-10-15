#!/usr/bin/env python3
"""
EdgeGuard Prototype - AlienVault OTX Collector
Collects threat pulses from AlienVault OTX and pushes to MISP

Production-ready features:
- Comprehensive error handling
- Retry logic with exponential backoff
- Circuit breaker pattern for outage handling
- Health checks before collection
- Prometheus metrics integration
- Timeout handling for API calls
- Detailed logging
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

# Import MISP writer
from actor_name_hygiene import clean_actor_names

# Import baseline checkpoint (incremental cursor only — no page-based checkpointing)
from baseline_checkpoint import (
    get_source_incremental,
    update_source_incremental,
)

# Shared utilities
from collectors.collector_utils import (
    OTX_API_KEY_PLACEHOLDERS,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)
from collectors.misp_writer import MISPWriter
from config import (
    OTX_API_KEY,
    OTX_BASELINE_MAX_PAGES,
    OTX_INCREMENTAL_LOOKBACK_DAYS,
    OTX_INCREMENTAL_MAX_PAGES,
    OTX_INCREMENTAL_OVERLAP_SEC,
    OTX_INDUSTRY_ZONE_ALIASES,
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_text,
    resolve_collection_limit,
)

# Import resilience utilities
from resilience import (
    check_service_health,
    get_circuit_breaker,
    record_collection_failure,
    record_collection_success,
)

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Configuration constants
OTX_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
OTX_REQUEST_TIMEOUT = 120  # Read timeout (seconds)
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# Circuit breaker for OTX (shared registry — see resilience.py)
OTX_CIRCUIT_BREAKER = get_circuit_breaker("otx", failure_threshold=3, recovery_timeout=3600)


def _pulse_item_key(item: Dict[str, Any]) -> str:
    """Same-run identity of an OTX item (what two pulses naming the same thing share)."""
    if "indicator_type" in item and "value" in item:
        return f"{item.get('indicator_type')}:{item.get('value')}"
    if item.get("type") == "malware":
        return f"malware:{item.get('name')}"
    if item.get("type") == "vulnerability":
        return f"cve:{item.get('cve_id')}"
    if item.get("type") == "actor":
        return f"actor:{item.get('name')}"
    return str(item)


# 2026-10 (regular-update linking, audit follow-up): the families and adversaries a pulse
# names travel on EVERY indicator of the pulse (``OTX_META.mf`` / ``.adv`` →
# ``Indicator.pulse_malware_families`` / ``.pulse_malware_actor_pairs``), so build_relationships
# Q9b / Q2d can link from the indicator side. The same-run pairing in the sync covers
# the baseline only: after it, a known family is a cross-event duplicate in MISP and is
# never re-pushed, so a later pulse's IOCs had no family in their event and got no edge.
_MAX_PULSE_FAMILIES = 20
_MAX_PULSE_ADVERSARIES = 5
_MAX_PULSE_PAIRS = 50  # families × adversaries of ONE pulse, encoded "family::adversary"
_PULSE_NAME_PLACEHOLDERS = frozenset({"", "unknown", "n/a", "none", "null", "-"})

# OTX indicator types whose value is a hex digest of something other than a file: an import hash, a
# PE hash, a TLS client fingerprint and a certificate fingerprint. MISPWriter types a generic
# ``hash`` by its digest length (md5 / sha1 / sha256 / sha512), which would store these as file
# hashes, so they are not collected (2026-10). Typed ``sha256`` before that, MISP dropped them.
_NON_FILE_HASH_TYPES = frozenset({"FileHash-IMPHASH", "FileHash-PEHASH", "JA3", "SSLCertFingerprint"})


def _pulse_actor_pairs(families: List[str], adversaries: List[str]) -> List[str]:
    """``"family::adversary"`` for every family × adversary named by ONE pulse. Encoding the pair
    (Bugbot on PR #145) keeps the same-pulse guarantee when the lists of several pulses are unioned on a
    shared IOC — two flat lists would cross-link a family from pulse A with an actor from pulse B."""
    out: List[str] = []
    for fam in families:
        for adv in adversaries:
            if fam and adv and "::" not in fam and "::" not in adv:
                out.append(f"{fam}::{adv}")
            if len(out) >= _MAX_PULSE_PAIRS:
                return out
    return out


def _pulse_family_names(families: Any) -> List[str]:
    """Family names a pulse lists (``malware_families`` entries are strings or ``{"name": ...}``),
    trimmed, placeholder-free, de-duplicated case-insensitively, first-seen order, capped."""
    out: List[str] = []
    seen: set = set()
    for fam in families or []:
        name = (fam if isinstance(fam, str) else (fam or {}).get("name", "")) if fam is not None else ""
        name = str(name).strip()
        key = name.lower()
        if key in _PULSE_NAME_PLACEHOLDERS or key in seen:
            continue
        seen.add(key)
        out.append(name[:128])
        if len(out) >= _MAX_PULSE_FAMILIES:
            break
    return out


def _fold_duplicate_pulse_item(kept: Dict[str, Any], dup: Dict[str, Any]) -> None:
    """Fold a same-run duplicate into the kept item.

    2026-10 (fresh-baseline PR, Bugbot finding): the kept item used to be the
    first pulse's copy and the later pulses were dropped, so a malware family
    or actor named in five pulses of one run reached MISP with the first
    pulse's ``pulse_id`` only — report-scoped ``INDICATES`` / ``ATTRIBUTED_TO``
    then paired it with IOCs of that one pulse and left the IOCs of the other
    four unlinked although they shared a pulse with it. Every later pulse now
    contributes its id to ``report_ids`` (``MITRE_USES_TECHNIQUES.rids`` /
    ``OTX_META.report_ids`` on the MISP attribute; the sync groups on
    ``[pulse_id] + report_ids``) and its ATT&CK ids to ``reported_techniques``.
    """
    # Copy-on-write (Bugbot on PR #134, round 2): ``reported_techniques`` is the pulse's
    # ``pulse_attack_ids`` list object, shared by reference with ``attack_ids`` in
    # ``pulse_meta`` and with every sibling item of the same pulse. Appending in place
    # would leak the later pulse's ATT&CK ids onto indicators and entities that never
    # appeared in it. Always rebind a fresh list on the kept item before extending it.
    dup_pid = dup.get("pulse_id")
    if dup_pid and dup_pid != kept.get("pulse_id"):
        rids = list(kept.get("report_ids") or [])
        if dup_pid not in rids:
            rids.append(dup_pid)
        kept["report_ids"] = rids
    extra_tids = [t for t in (dup.get("reported_techniques") or []) if t not in (kept.get("reported_techniques") or [])]
    if extra_tids:
        kept["reported_techniques"] = list(kept.get("reported_techniques") or []) + extra_tids
    # Families / adversaries of every pulse that listed the IOC (copy-on-write as above).
    for _list_key in ("pulse_malware_families", "pulse_malware_actor_pairs"):
        _extra = [x for x in (dup.get(_list_key) or []) if x not in (kept.get(_list_key) or [])]
        if _extra:
            kept[_list_key] = list(kept.get(_list_key) or []) + _extra


def _dedupe_pulse_items(processed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One item per identity, keeping the first copy and folding the rest into it."""
    kept_by_key: Dict[str, Dict[str, Any]] = {}
    unique: List[Dict[str, Any]] = []
    for item in processed:
        if not (item.get("value") or item.get("name") or item.get("cve_id")):
            continue
        key = _pulse_item_key(item)
        kept = kept_by_key.get(key)
        if kept is None:
            kept_by_key[key] = item
            unique.append(item)
        else:
            _fold_duplicate_pulse_item(kept, item)
    return unique


class OTXCollector:
    """
    AlienVault OTX Collector.

    Production-ready features:
    - Retry logic with exponential backoff
    - Circuit breaker pattern for extended outages
    - Health checks before collection
    - Prometheus metrics integration
    - Timeout handling
    - Comprehensive error logging
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = "https://otx.alienvault.com"
        self.api_key = optional_api_key_effective(OTX_API_KEY, OTX_API_KEY_PLACEHOLDERS)
        self.tag = SOURCE_TAGS["otx"]
        self.misp_writer = misp_writer or MISPWriter()
        self.source_name = "otx"

        # Create a session for better connection handling
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            }
        )

        # Get circuit breaker for this collector
        self.circuit_breaker = OTX_CIRCUIT_BREAKER

    @staticmethod
    def _max_pulse_modified_iso(pulses: List[Dict]) -> Optional[str]:
        """Latest OTX pulse ``modified`` timestamp among *pulses* (ISO string), or None."""
        best: Optional[datetime] = None
        for p in pulses:
            raw = p.get("modified")
            if not raw or not isinstance(raw, str):
                continue
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue
            if best is None or dt > best:
                best = dt
        return best.isoformat() if best else None

    def health_check(self) -> Dict[str, Any]:
        """
        Check OTX API health.

        Returns:
            Dict with health status
        """
        try:
            start_time = time.time()
            response = self.session.get(
                f"{self.base_url}/api/v1/pulses/subscribed",
                params={"limit": 1},
                timeout=(OTX_CONNECT_TIMEOUT, OTX_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
            )
            response_time = time.time() - start_time

            if response.status_code == 200:
                return {
                    "healthy": True,
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
            else:
                return {
                    "healthy": False,
                    "error": f"HTTP {response.status_code}",
                    "response_time_ms": round(response_time * 1000, 2),
                }
        except requests.exceptions.Timeout as e:
            return {"healthy": False, "error": f"Timeout: {e}"}
        except requests.exceptions.ConnectionError as e:
            return {"healthy": False, "error": f"Connection error: {e}"}
        except Exception as e:
            return {"healthy": False, "error": f"{type(e).__name__}: {e}"}

    def check_service_available(self) -> bool:
        """
        Check if OTX service is available before collection.
        Uses circuit breaker state if available, otherwise does health check.

        Returns:
            True if service is available, False otherwise
        """
        # Check circuit breaker state
        if not self.circuit_breaker.can_execute():
            logger.warning(f"OTX circuit breaker is {self.circuit_breaker.state.name} - skipping collection")
            return False

        # Then do health check
        return check_service_health(self.source_name, self.health_check)

    def detect_sectors(self, text: str) -> List[str]:
        """Detect sectors from text using canonical scorer."""
        return detect_zones_from_text(text)

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_pulses(self, limit: int = None, modified_since: str = None, page: int = 1) -> List[Dict]:
        """
        Fetch pulses from OTX API with retry logic.

        Args:
            limit: Maximum number of pulses to fetch per page
            modified_since: ISO timestamp to fetch pulses modified since (for historical)
            page: Page number for pagination

        Returns:
            List of pulse dicts
        """
        params = {"limit": limit or 50, "page": page}
        if modified_since:
            params["modified_since"] = modified_since

        ms_dbg = modified_since[:19] if modified_since else "latest"
        logger.info(f"Fetching pulses from OTX... (page={page}, modified_since={ms_dbg})")

        response = request_with_rate_limit_retries(
            "GET",
            f"{self.base_url}/api/v1/pulses/subscribed",
            session=self.session,
            max_rate_limit_retries=5,
            fallback_delay_sec=90.0,
            retry_on_403=False,
            context="OTX",
            params=params,
            timeout=(OTX_CONNECT_TIMEOUT, OTX_REQUEST_TIMEOUT),
            verify=SSL_VERIFY,
        )

        if response.status_code != 200:
            raise requests.exceptions.HTTPError(
                f"OTX API error: {response.status_code} (after rate-limit retries where applicable)"
            )

        data = response.json()
        pulses = data.get("results", []) if isinstance(data, dict) else data

        logger.info(f"[FETCH] OTX: Fetched {len(pulses)} pulses")
        return pulses

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Dict[str, Any]:
        """
        Collect pulses from OTX and optionally push to MISP.

        Args:
            limit: Maximum number of pulses to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back to collect in baseline mode

        Returns:
            Dict with status and counts if push_to_misp=True, else list of processed items
        """
        limit = resolve_collection_limit(limit, "otx", baseline=baseline)

        # Optional source: no OTX key → skip without failing the DAG (same contract as AbuseIPDB / VT)
        if not optional_api_key_effective(self.api_key, OTX_API_KEY_PLACEHOLDERS):
            logger.warning(
                "OTX: No API key — skipping collection (optional source). "
                "Set OTX_API_KEY for AlienVault OTX; https://otx.alienvault.com/"
            )
            if push_to_misp:
                st = make_status(
                    "otx",
                    True,
                    count=0,
                    failed=0,
                    skipped=True,
                    skip_reason="OTX_API_KEY not set (optional — https://otx.alienvault.com/)",
                    skip_reason_class="missing_otx_key",
                )
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            return []

        # Check if service is available before attempting collection
        if not self.check_service_available():
            error_msg = f"OTX service unavailable (circuit breaker: {self.circuit_breaker.state.name})"
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)

        try:
            if baseline:
                # Baseline mode: collect all historical data with pagination.
                # No page-based checkpoint — OTX pagination is unstable across
                # different time windows (baseline_days can be 120, 365, 730).
                # A saved page number from a previous window is meaningless.
                # The incremental cursor (modified_since in "incremental" sub-dict)
                # is separate and unaffected.
                logger.info(f"Baseline mode: Collecting last {baseline_days} days of OTX data...")

                all_pulses = []
                modified_since = (datetime.now(timezone.utc) - timedelta(days=baseline_days)).isoformat()
                page = 1
                max_pages = OTX_BASELINE_MAX_PAGES
                consecutive_empty = 0

                while page <= max_pages and consecutive_empty < 3:
                    pulses = self._fetch_pulses(limit=limit, modified_since=modified_since, page=page)
                    if not pulses:
                        consecutive_empty += 1
                        page += 1
                        if consecutive_empty >= 3:
                            logger.info("   3 consecutive empty pages — stopping baseline fetch")
                            break
                        continue
                    consecutive_empty = 0
                    all_pulses.extend(pulses)
                    logger.info(f"   Page {page}: {len(pulses)} pulses (total: {len(all_pulses)})")
                    page += 1
                    time.sleep(2)  # OTX free tier: 30 req/min → 2 s between page fetches

                pulses = all_pulses
                if not pulses:
                    logger.warning(
                        "OTX baseline returned 0 pulses for %s-day window — verify API key and OTX connectivity",
                        baseline_days,
                    )
                logger.info(f"   Baseline complete: {len(pulses)} total pulses collected")
            else:
                # Incremental: only pulses modified since last successful run (checkpoint + overlap).
                inc = get_source_incremental("otx")
                stored = inc.get("otx_last_pulse_modified")
                overlap = timedelta(seconds=max(0, OTX_INCREMENTAL_OVERLAP_SEC))
                if stored:
                    try:
                        base_dt = datetime.fromisoformat(stored.replace("Z", "+00:00"))
                        # PR-M2 §4-F9: ``stored`` may have been written by an
                        # older checkpoint version that omitted the ``Z``
                        # suffix entirely (just ``"2024-01-15T10:00:00"``).
                        # ``str.replace("Z", "+00:00")`` is a no-op on that
                        # string, so ``fromisoformat`` returns a NAIVE
                        # datetime, and subtracting ``overlap`` (which is a
                        # tz-aware-arithmetic-safe timedelta) silently
                        # produces a naive result that downstream
                        # ``coerce_iso`` would treat differently than a
                        # tz-aware one. Defensive UTC injection ensures
                        # the resume cursor is always tz-aware, matching
                        # docs/TIMESTAMPS.md "Invariant 2".
                        if base_dt.tzinfo is None:
                            base_dt = base_dt.replace(tzinfo=timezone.utc)
                        modified_since = (base_dt - overlap).isoformat()
                    except (ValueError, TypeError):
                        modified_since = (
                            datetime.now(timezone.utc) - timedelta(days=OTX_INCREMENTAL_LOOKBACK_DAYS)
                        ).isoformat()
                else:
                    modified_since = (
                        datetime.now(timezone.utc) - timedelta(days=OTX_INCREMENTAL_LOOKBACK_DAYS)
                    ).isoformat()
                logger.info(
                    "OTX incremental: modified_since=%s (max_pages=%s)",
                    modified_since[:22],
                    OTX_INCREMENTAL_MAX_PAGES,
                )
                all_incr: List[Dict] = []
                page_i = 1
                while page_i <= OTX_INCREMENTAL_MAX_PAGES:
                    page_pulses = self._fetch_pulses(
                        limit=100,
                        modified_since=modified_since,
                        page=page_i,
                    )
                    if not page_pulses:
                        break
                    all_incr.extend(page_pulses)
                    page_i += 1
                    time.sleep(2)
                pulses = all_incr

            # Process pulses
            processed = []
            non_file_hashes = 0

            to_process = pulses if limit is None else pulses[:limit]
            for pulse in to_process:
                # Detect ALL sectors — start with keyword-based detection
                pulse_text = json.dumps(pulse).lower()
                sectors = self.detect_sectors(pulse_text)

                # OTX-native industry_sectors override: if OTX itself classified
                # the pulse into industries, use that as authoritative sector data.
                #
                # PR-N6 hotfix #4 (audit 09, Maintainer #1): the inline
                # industry map moved to ``config.OTX_INDUSTRY_ZONE_ALIASES``
                # so it lives side-by-side with ``VALID_ZONES`` /
                # ``SECTOR_KEYWORDS``. Previously this was a hidden
                # second source of truth containing vocabulary absent
                # from ``SECTOR_KEYWORDS`` ("pharmaceutical", "utilities",
                # "oil", "gas", "insurance") — so vocabulary refinements
                # in ``config.py`` silently diverged from OTX ingestion.
                otx_industries = pulse.get("industries", [])
                if otx_industries:
                    for ind_name in otx_industries:
                        mapped = OTX_INDUSTRY_ZONE_ALIASES.get(str(ind_name).lower().strip())
                        if mapped and mapped not in sectors:
                            sectors.append(mapped)
                    # Remove "global" if we now have specific sectors
                    if len(sectors) > 1 and "global" in sectors:
                        sectors = [s for s in sectors if s != "global"]

                # Pulse-level metadata (available on all items from this pulse)
                pulse_attack_ids = [
                    aid.get("id", aid) if isinstance(aid, dict) else str(aid) for aid in pulse.get("attack_ids", [])
                ]
                pulse_targeted_countries = pulse.get("targeted_countries", [])
                pulse_tags = pulse.get("tags", [])
                pulse_references = pulse.get("references", [])[:10]
                pulse_author = pulse.get("author_name", "")
                pulse_adversary = pulse.get("adversary", "")
                pulse_tlp = pulse.get("TLP", "")
                pulse_description = pulse.get("description", "")

                # PR-M2 §4-F5: read the source's pulse-level timestamps
                # ONCE at the top of the per-pulse block and use them for
                # the per-indicator ``first_seen`` / ``last_seen``
                # propagation further down.
                # Bugbot caught (PR-M2 round 1, LOW): the previous code
                # assigned ``pulse_created = pulse.get("created", "")``
                # for filtering, then later reassigned
                # ``pulse_created = pulse.get("created")`` (None default)
                # for honest-NULL propagation — same name, two semantics,
                # latent breakage if a future edit moved one assignment.
                # Single source of truth eliminates the shadowing risk;
                # downstream honest-NULL gating (``if indicator_first_seen``)
                # treats ``""`` as "absent" too.
                #
                # OTX is intentionally NOT on ``_RELIABLE_FIRST_SEEN_SOURCES``
                # so the read-side ``extract_source_truthful_timestamps``
                # correctly ignores OTX's claim. BUT the MISP attribute
                # itself still carries whatever we put here, so non-EdgeGuard
                # consumers (ResilMesh, SIEM bridges) reading MISP directly
                # will see this value as the source's claim.
                #
                # Honest-NULL pattern (mirrors AbuseIPDB blacklist): omit
                # ``first_seen`` when the source field is absent rather
                # than substituting wall-clock NOW. Per-indicator
                # ``ind.get("created")`` overrides the pulse-level
                # ``pulse.get("created")`` when present (OTX returns
                # per-indicator timestamps for some pulse types).
                # Concept 1 in docs/TIMESTAMPS.md.
                pulse_created = pulse.get("created")  # may be None or "" — honest NULL
                pulse_modified = pulse.get("modified")

                # No age filter on the pulse (2026-10): the request bounds it by ``modified_since``
                # (baseline: ``baseline_days``; incremental: the stored cursor). The former
                # SECTOR_TIME_RANGES filter here compared OTX's zone-less ``created``
                # ("2023-01-25T11:11:02.458000") with a timezone-aware cutoff and swallowed the
                # TypeError, so it had not dropped a pulse since v2026.3.28. Made to work, it would
                # have dropped pulses created more than 24 months ago that are still being updated,
                # new IOCs included.

                # Shared metadata dict for all items from this pulse
                # 2026-10 (regular-update linking): computed once per pulse, stamped on each IOC below.
                pulse_family_names = _pulse_family_names(pulse.get("malware_families", []))
                pulse_actor_names = clean_actor_names(pulse_adversary or "")[:_MAX_PULSE_ADVERSARIES]
                pulse_actor_pairs = _pulse_actor_pairs(pulse_family_names, pulse_actor_names)
                pulse_meta = {
                    "pulse_id": pulse.get("id"),
                    "pulse_name": pulse.get("name", "")[:100],
                    "pulse_tags": pulse_tags[:20],
                    "pulse_references": pulse_references,
                    "pulse_author": pulse_author,
                    "pulse_tlp": pulse_tlp,
                    "attack_ids": pulse_attack_ids,
                    "targeted_countries": pulse_targeted_countries,
                    "otx_industries": otx_industries,
                }
                # Extract indicators - one entry per indicator (zone holds all matched sectors)
                indicators = pulse.get("indicators", [])
                for ind in indicators:
                    if ind.get("type") in _NON_FILE_HASH_TYPES:
                        non_file_hashes += 1
                        continue
                    indicator_type = self.map_indicator_type(ind.get("type"), ind.get("indicator"))
                    indicator_value = ind.get("indicator")
                    indicator_first_seen = ind.get("created") or pulse_created
                    indicator_last_seen = ind.get("modified") or pulse_modified
                    item: Dict[str, Any] = {
                        "indicator_type": indicator_type,
                        "value": indicator_value,
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        "description": ind.get("description", "") or ind.get("title", ""),
                        "indicator_role": ind.get("role", ""),
                        "is_active": ind.get("is_active", True),
                        # 2026-10 (regular-update linking): see _pulse_family_names.
                        "pulse_malware_families": list(pulse_family_names),
                        "pulse_malware_actor_pairs": list(pulse_actor_pairs),
                        **pulse_meta,
                    }
                    if indicator_first_seen:
                        item["first_seen"] = indicator_first_seen
                    if indicator_last_seen:
                        item["last_seen"] = indicator_last_seen
                    processed.append(item)

                # Extract malware families
                # PR-M2 §4-F5 (Bugbot round 3): symmetric honest-NULL
                # propagation. Indicator + CVE branches use
                # ``pulse_created`` / ``pulse_modified`` for first_seen /
                # last_seen; the malware-family branch must follow the
                # same pattern or the per-pulse timestamp contract is
                # broken (some entities from one pulse carry the source's
                # claim, others don't — silently inconsistent).
                malware_families = pulse.get("malware_families", [])
                for mal in malware_families:
                    mal_name = mal if isinstance(mal, str) else mal.get("name", "Unknown")
                    mal_item: Dict[str, Any] = {
                        "type": "malware",
                        "name": mal_name,
                        "malware_types": ["unknown"],
                        "family": mal_name,
                        "description": pulse_description[:1000],
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        # 2026-10: pulse-level ATT&CK ids are a report association,
                        # not MITRE's explicit "uses" relationship — they travel as
                        # ``reported_techniques`` (→ IMPLEMENTS_TECHNIQUE with
                        # match_type ``otx_pulse``), never as ``uses_techniques``.
                        "reported_techniques": pulse_attack_ids,
                        **pulse_meta,
                    }
                    if pulse_created:
                        mal_item["first_seen"] = pulse_created
                    if pulse_modified:
                        mal_item["last_seen"] = pulse_modified
                    processed.append(mal_item)

                # Extract CVE references (no cap — collect all CVEs from pulse)
                # PR-M2 §4-F5: same honest-NULL treatment for CVE entries
                # synthesized from the pulse. OTX's claim about a CVE's
                # first_seen is the pulse's ``created`` timestamp if the
                # API provided it; otherwise we omit the field rather
                # than substituting wall-clock NOW.
                cve_refs = pulse.get("cve_references", [])
                for cve in cve_refs:
                    cve_item: Dict[str, Any] = {
                        "type": "vulnerability",
                        "cve_id": cve.upper() if isinstance(cve, str) else cve.get("cve", "").upper(),
                        "description": f"Referenced in OTX pulse: {pulse.get('name', '')}",
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        "severity": "UNKNOWN",
                        # A pulse reference carries no CVSS (0.0 was tagged cvss:low) and no attack
                        # vector (an invented "NETWORK" was sent until 2026-10).
                        "cvss_score": None,
                        **pulse_meta,
                    }
                    if pulse_created:
                        cve_item["first_seen"] = pulse_created
                    if pulse_modified:
                        cve_item["last_seen"] = pulse_modified
                    processed.append(cve_item)

                # Extract named adversary as a ThreatActor if present.
                # PR-M2 §4-F5 (Bugbot round 3): symmetric honest-NULL
                # propagation — see malware-family branch above for
                # rationale. Same pulse-level timestamps apply.
                # 2026-10: OTX's free-text ``adversary`` is a report field, not a
                # name — pulses ship composites ("apt-c-13, sandworm, frozenbarents",
                # "head mare and twelve") and descriptions ("multiple russian
                # state-backed groups"). ``clean_actor_names`` splits the former into
                # one actor item each and drops the latter, so no ThreatActor node is
                # ever created from a phrase.
                for adversary_name in clean_actor_names(pulse_adversary or ""):
                    actor_item: Dict[str, Any] = {
                        "type": "actor",
                        "name": adversary_name,
                        "description": pulse_description[:1000],
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        # 2026-10: see the malware branch — pulse ids are reported, not MITRE-explicit.
                        "reported_techniques": pulse_attack_ids,
                        "aliases": [],
                        **pulse_meta,
                    }
                    if pulse_created:
                        actor_item["first_seen"] = pulse_created
                    if pulse_modified:
                        actor_item["last_seen"] = pulse_modified
                    processed.append(actor_item)

            # Deduplicate — later pulses fold their pulse id / reported techniques into
            # the kept item (see _dedupe_pulse_items; Bugbot finding on PR #134).
            unique = _dedupe_pulse_items(processed)

            logger.info(f"[OK] OTX: Processed {len(unique)} unique items")
            if non_file_hashes:
                logger.info(
                    "[SKIP] OTX: %d indicators of a non-file hash type (%s) not collected",
                    non_file_hashes,
                    ", ".join(sorted(_NON_FILE_HASH_TYPES)),
                )

            def _advance_otx_incremental_cursor(successful_pulses: Optional[List[Dict]] = None) -> None:
                """Advance cursor to the last successfully processed pulse timestamp.

                Args:
                    successful_pulses: The pulses that were successfully pushed.
                        When None (non-MISP mode or no failures), falls back to
                        the truncated ``to_process`` list — NOT the full fetched
                        ``pulses`` list.

                Production-test audit fix (Bug Hunter HIGH BH-H1, post-PR-C-merge):
                the previous fallback used ``pulses`` (the FULL fetched list)
                rather than ``to_process`` (after the EDGEGUARD_INCREMENTAL_LIMIT
                truncation at line 357 above). When the limit bit (e.g., 250
                modified pulses but limit=200, the default), only the first 200
                were pushed but the cursor advanced to the latest-modified
                timestamp of ALL 250. The 50 truncated pulses were lost
                forever — next run's modified_since filter skipped them
                (silent data loss in normal operation with default settings).
                Fall back to ``to_process`` so the cursor only advances over
                pulses we actually attempted.
                """
                if baseline:
                    return
                source = successful_pulses if successful_pulses is not None else to_process
                if not source:
                    return
                mx = self._max_pulse_modified_iso(source)
                if mx:
                    update_source_incremental("otx", otx_last_pulse_modified=mx)

            # Push to MISP if requested
            if push_to_misp:
                record_collection_success(self.source_name)
                if not unique:
                    self.circuit_breaker.record_success()
                    _advance_otx_incremental_cursor()
                    st = make_status("otx", True, count=0, failed=0)
                    st["circuit_breaker_state"] = self.circuit_breaker.state.name
                    return st

                success, failed = self.misp_writer.push_items(unique)

                if success > 0:
                    logger.info(f"[OK] OTX: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] OTX: Failed to push {failed} items to MISP")

                # Advance cursor only when there were successful items.
                # On partial failure, advance to the last successful pulse
                # so we re-collect only the failed window next time.
                if success > 0:
                    if failed == 0:
                        _advance_otx_incremental_cursor()
                    else:
                        # Partial failure: identify pulses that contributed
                        # the successfully pushed items (first `success` items
                        # are the ones that went through) and advance only
                        # up to their latest timestamp.
                        successful_items = unique[:success]
                        successful_pulse_ids = {it.get("pulse_id") for it in successful_items if it.get("pulse_id")}
                        successful_pulses = [p for p in pulses if p.get("id") in successful_pulse_ids]
                        _advance_otx_incremental_cursor(successful_pulses)

                self.circuit_breaker.record_success()
                st = status_after_misp_push("otx", len(unique), success, failed)
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            else:
                record_collection_success(self.source_name)
                self.circuit_breaker.record_success()
                _advance_otx_incremental_cursor()
                return unique

        # PR-N24 BLOCKER B3 (proactive audit 2026-04-22): on push_to_misp=False,
        # the docstring says "return list of processed items" — but pre-N24
        # all 4 exception handlers returned a status DICT regardless,
        # which the alert-preview / test-harness / baseline-drain caller
        # could not distinguish from a successful empty-list result.
        # Same shape as the PR-N17 NVD bug + PR-N23 CISA fix. Mirroring
        # CISA's resolution (cisa_collector.py:312-355): when
        # push_to_misp=True still return status dict (Airflow contract);
        # when False, re-raise so the caller sees the actual error.
        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"OTX timeout: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"OTX connection error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"OTX: auth/access denied — skipping (optional): {e}")
                self.circuit_breaker.record_success()
                record_collection_success(self.source_name)
                st = make_skipped_optional_source(
                    "otx",
                    skip_reason=str(e),
                    skip_reason_class="otx_auth_denied",
                )
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            error_msg = f"HTTP error: {e}"
            logger.error(f"OTX HTTP error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"OTX collection error: {type(e).__name__}: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Return standardized status dict."""
        result = make_status("otx", success, count=count, failed=failed, error=error)
        result["circuit_breaker_state"] = self.circuit_breaker.state.name
        return result

    def map_indicator_type(self, ind_type: str, value: str = None) -> str:
        """Map OTX indicator types to standard EdgeGuard types"""
        mapping = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "URL": "url",
            "MD5": "hash",
            "SHA1": "hash",
            "SHA256": "hash",
            "SHA384": "hash",
            "SHA512": "hash",
            "EMAIL": "email",
            "FILE_HASH_MD5": "hash",
            "FILE_HASH_SHA1": "hash",
            "FILE_HASH_SHA256": "hash",
            "FileHash-SHA256": "hash",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "Email": "email",
            "email": "email",
            "CVE": "cve",
        }

        # Check type mapping first
        result = mapping.get(ind_type)
        if result:
            return result

        # Fallback: analyze the value itself
        if value:
            val_lower = value.lower()

            # IP address pattern (IPv4) - STRICT check
            parts = value.split(".")
            if len(parts) == 4:
                try:
                    if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        return "ipv4"
                except (ValueError, TypeError):
                    pass

            # Email before domain: "user@host.tld" also contains a dot, and typed as a domain MISP
            # rejects it ("Domain has an invalid format") while answering a batch push with 200.
            if "@" in value and "." in value.split("@")[-1]:
                return "email"

            # Domain patterns
            if "." in val_lower and not val_lower.startswith("http"):
                if not val_lower.isdigit() and len(value) > 4:
                    excluded = ["cve-", "md5", "sha1", "sha256"]
                    if not any(val_lower.startswith(ex) for ex in excluded):
                        return "domain"

            # Email pattern
            if "@" in value and "." in value:
                return "email"
            # Hash patterns
            if len(value) in [32, 40, 64, 128] and all(c in "0123456789abcdefABCDEF" for c in value):
                return "hash"
            # CVE pattern
            if val_lower.startswith("cve-"):
                return "cve"
            # URL pattern
            if val_lower.startswith(("http://", "https://")):
                return "url"

        return "unknown"


def test_otx() -> Dict[str, Any]:
    """Test OTX collection and MISP push"""
    collector = OTXCollector()
    result = collector.collect(limit=500)  # OTX: 30 req/min, safe to fetch 500
    print("\n📥 OTX Test Result:")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    test_otx()
