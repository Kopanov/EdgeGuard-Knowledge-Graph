#!/usr/bin/env python3
"""
EdgeGuard Prototype - CISA KEV Collector
Collects Known Exploited Vulnerabilities from CISA and pushes to MISP

Production-ready features:
- Comprehensive error handling
- Retry logic with exponential backoff
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from baseline_config import resolve_baseline_days

# Shared utilities (rate limiter, retry, HTTP rate-limit retries)
from collectors.collector_utils import (
    RateLimiter,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import KEV_REPLACED_TAG_PREFIXES, MispLookupError, MispTransientError, MISPWriter
from collectors.vulnerability_update import apply_vulnerability_edits, plan_source_updates, push_additions
from config import (
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_text,
    kev_baseline_whole_catalogue,
    kev_max_edits_per_run,
    kev_update_existing,
    resolve_collection_limit,
)
from resilience import get_circuit_breaker, record_collection_failure

# 2026-10: no incremental window. Every run compares the whole catalogue with EdgeGuard's MISP copies
# (``CISACollector._update_misp``); ``EDGEGUARD_CISA_INCREMENTAL_DAYS`` (30) is retired: every revision
# measured between 2026-05-22 and 2026-10-16 hit an entry older than 30 days.

logger = logging.getLogger(__name__)

# Circuit breaker for CISA (CISA is reliable but good to have)
CISA_CIRCUIT_BREAKER = get_circuit_breaker("cisa", failure_threshold=3, recovery_timeout=1800)

CISA_RATE_LIMITER = RateLimiter(min_interval=1.0)  # 1 request per second max

# Configuration constants
CISA_REQUEST_TIMEOUT = 60  # seconds
CISA_CONNECT_TIMEOUT = 15  # seconds
MAX_RETRIES = 5
RETRY_DELAY_BASE = 2  # seconds


class CISACollector:
    """
    CISA Known Exploited Vulnerabilities Collector.

    Production-ready features:
    - Retry logic with exponential backoff
    - Timeout handling
    - Comprehensive error logging
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.tag = SOURCE_TAGS["cisa"]
        self.misp_writer = misp_writer or MISPWriter()
        self.catalog_version: Optional[str] = None  # set by _fetch_kev

    def health_check(self) -> Dict[str, Any]:
        """
        Check CISA KEV feed health.

        Returns:
            Dict with health status
        """
        # Check circuit breaker state
        if not CISA_CIRCUIT_BREAKER.can_execute():
            return {
                "healthy": False,
                "error": "Circuit breaker open",
                "circuit_state": CISA_CIRCUIT_BREAKER.state.name,
            }
        try:
            start_time = time.time()
            response = requests.get(
                self.base_url, timeout=(CISA_CONNECT_TIMEOUT, CISA_REQUEST_TIMEOUT), verify=SSL_VERIFY
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

    def detect_sectors(self, text: str) -> list:
        """Detect ALL sectors from vendor/project/product using common zone detection.

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        return detect_zones_from_text(text)

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_kev(self, limit: Optional[int]) -> List[Dict]:
        """
        Fetch KEV from CISA with retry logic, circuit breaker, and rate limiting.

        Args:
            limit: Not used: the catalogue is one download, and every run takes all of it (2026-10)

        Returns:
            List of vulnerability dicts
        """
        # Check circuit breaker
        if not CISA_CIRCUIT_BREAKER.can_execute():
            logger.warning("CISA circuit breaker open - skipping")
            return []

        # Rate limiting
        CISA_RATE_LIMITER.wait_if_needed()

        logger.info("Fetching KEV from CISA...")

        try:
            response = request_with_rate_limit_retries(
                "GET",
                self.base_url,
                session=None,
                timeout=(CISA_CONNECT_TIMEOUT, CISA_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="CISA",
            )

            if response.status_code != 200:
                raise requests.exceptions.HTTPError(f"CISA API error: {response.status_code}")

            CISA_CIRCUIT_BREAKER.record_success()
        except Exception:
            CISA_CIRCUIT_BREAKER.record_failure()
            raise

        data = response.json()

        # Log catalog-level metadata for operator visibility
        catalog_version = data.get("catalogVersion", "unknown")
        date_released = data.get("dateReleased", "unknown")
        logger.info(f"CISA KEV catalog: version={catalog_version}, dateReleased={date_released}")
        # 2026-10: named in the run's summary line and status (``kev_update.catalogue_version``).
        self.catalog_version = f"{catalog_version} ({date_released})"

        vulnerabilities = data.get("vulnerabilities", [])

        # Sort newest-first by dateAdded so limit/slicing takes the most recent entries
        vulnerabilities.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)

        logger.info(f"[FETCH] CISA KEV: Fetched {len(vulnerabilities)} vulnerabilities (sorted newest-first)")
        return vulnerabilities

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Dict[str, Any]:
        """
        Collect KEV from CISA and keep EdgeGuard's MISP copies in step with the catalogue.

        2026-10: baseline and incremental runs follow one path. Every run downloads the whole
        catalogue (CISA publishes no per-entry modification date) and compares each entry in scope
        with EdgeGuard's stored MISP copies (``_update_misp``): a CVE MISP lacks is added, a stored copy
        that differs is edited in place, so MISP holds CISA's latest statement (a ransomware use that
        became Known, a moved due date, a rewritten description). Before, an incremental run took only
        the entries added within the last 30 days (``EDGEGUARD_CISA_INCREMENTAL_DAYS``, retired) and
        MISPWriter dropped every entry MISP already held, so no revision reached MISP or the graph.

        Scope: the whole catalogue (``EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE``, default true); ``false``
        restores the ``dateAdded`` window of the baseline length (``baseline_days`` in a baseline,
        ``EDGEGUARD_BASELINE_DAYS`` otherwise). Entries are handled newest ``dateAdded`` first, then by
        CVE id.

        Args:
            limit: Explicit per-run limit: cuts the additions and lowers the edit cap
                (``EDGEGUARD_KEV_MAX_EDITS_PER_RUN``); None for none (KEV is in
                ``OWN_RUN_CAP_SOURCES``, so the generic incremental limit does not apply)
            push_to_misp: Whether to compare with MISP and write to it
            baseline: Baseline run (same path; ``baseline_days`` sets the window when the whole
                catalogue is switched off)
            baseline_days: How many days back a baseline reaches when the whole catalogue is off

        Returns:
            With push_to_misp=True a status dict (``st["kev_update"]`` holds the run's counters),
            otherwise the scope's items (cut at ``limit`` when one is given)
        """
        limit = resolve_collection_limit(limit, "cisa", baseline=baseline)

        try:
            if baseline:
                logger.info("📜 Baseline mode: Collecting all CISA KEV data...")
            entries = self._fetch_kev(limit=None)  # the whole catalogue (one download)
            scope = self._scope(entries, baseline, baseline_days)
            items = [self._kev_item(entry) for entry in scope]
            logger.info(f"[OK] CISA KEV: Processed {len(items)} vulnerabilities")

            if not push_to_misp:
                return items if limit is None else items[:limit]
            if not entries:
                # An empty answer (or an open circuit breaker) never means "every entry was removed":
                # nothing is compared and nothing is written.
                logger.warning(
                    "CISA KEV: no catalogue entries were received; nothing was compared with MISP (circuit breaker %s)",
                    CISA_CIRCUIT_BREAKER.state.name,
                )
                st = make_skipped_optional_source(
                    "cisa_kev",
                    skip_reason="CISA KEV: no catalogue entries received; nothing compared with MISP",
                    skip_reason_class="cisa_empty_catalogue",
                )
                st["circuit_breaker_state"] = CISA_CIRCUIT_BREAKER.state.name
                return st
            return self._update_misp(entries, items, limit)

        except requests.exceptions.Timeout as e:
            logger.error(f"CISA KEV timeout: {e}")
            # PR-N23 BLOCKER #4 (proactive audit 2026-04-22): same
            # shape as the PR-N17 NVD silent-window-drop bug, in a
            # different collector.
            # Pre-N23 ``return self._return_status(False, 0, ...) if
            # push_to_misp else []`` returned an EMPTY LIST when
            # ``push_to_misp=False`` (alert-preview / baseline drain-
            # mode / test-harness flows) — indistinguishable from "CISA
            # feed is empty today". Caller cannot tell fetch failure
            # from empty feed → a KEV entry the operator knows was
            # published silently disappears from the output.
            # Fix: when push_to_misp=True we still return a status dict
            # (existing contract — Airflow consumes it); when False we
            # re-raise so the caller sees the actual error.
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise
        except requests.exceptions.ConnectionError as e:
            logger.error(f"CISA KEV connection error: {e}")
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise
        except requests.exceptions.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"CISA KEV: auth/access denied — skipping (optional public feed): {e}")
                # _fetch_kev() records record_failure() before re-raising; treat skip as non-failure.
                CISA_CIRCUIT_BREAKER.record_success()
                st = make_skipped_optional_source(
                    "cisa_kev",
                    skip_reason=str(e),
                    skip_reason_class="cisa_auth_denied",
                )
                st["circuit_breaker_state"] = CISA_CIRCUIT_BREAKER.state.name
                return st
            logger.error(f"CISA KEV HTTP error: {e}")
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise
        except Exception as e:
            logger.error(f"CISA KEV collection error: {type(e).__name__}: {e}")
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise

    def _scope(self, entries: List[Dict], baseline: bool, baseline_days: Optional[int]) -> List[Dict]:
        """The catalogue entries a run compares with MISP, newest ``dateAdded`` first, then by CVE id."""
        total = len(entries)
        if kev_baseline_whole_catalogue():
            # 2026-10: a KEV entry is a CVE known to be exploited, so its age is no reason to leave it
            # out (Log4Shell, added 2021-12, fell outside a 730-day window), and every revision measured
            # between 2026-05-22 and 2026-10-16 hit an entry older than 30 days.
            scope = list(entries)
            logger.info(f"CISA KEV: whole catalogue, processing {total} entries")
        else:
            days = baseline_days if baseline else resolve_baseline_days()
            scope = list(entries)
            if days:
                cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
                scope = [v for v in entries if v.get("dateAdded", "") >= cutoff_date]
            logger.info(
                f"CISA KEV: {total} total, {len(scope)} within the {days}-day dateAdded window "
                "(EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false)"
            )
            if total and not scope:
                logger.warning("CISA KEV: 0 entries in the %s-day window", days)
        ordered = sorted(scope, key=lambda v: str(v.get("cveID") or ""))
        return sorted(ordered, key=lambda v: str(v.get("dateAdded") or ""), reverse=True)

    def _kev_item(self, vuln: Dict) -> Dict[str, Any]:
        """One catalogue entry as an EdgeGuard vulnerability item (the same item for an addition and for
        the comparison with a stored copy)."""
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        short_desc = vuln.get("shortDescription", "")
        required_action = vuln.get("requiredAction", "")
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")
        known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

        # Detect ALL sectors
        sectors = self.detect_sectors(f"{vendor} {product} {short_desc}")

        return {
            "type": "vulnerability",
            "cve_id": cve_id,
            "description": short_desc[:500],
            "zone": sectors,  # zone is now an array
            "tag": self.tag,
            "source": [self.tag],
            # PR (S5) (bugbot MED follow-on): kill the
            # wall-clock fallback for first_seen. CISA's
            # ``dateAdded`` is the source-truthful field — when
            # it's empty we'd rather emit None and let the
            # extractor's MIN logic preserve any prior value
            # than poison Neo4j with a wall-clock NOW that
            # would be misread downstream as "first observed
            # right now". Same pattern as the AbuseIPDB
            # blacklist fix in commit 87d3529.
            # ``last_updated`` is intentionally NOT
            # source-truthful — it's EdgeGuard's local sync
            # wall-clock, which is the correct semantics.
            "first_seen": date_added or None,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "confidence_score": 0.9,  # High confidence - known exploited
            # 2026-10: the catalogue carries no CVSS. The score and severity used to be
            # derived from knownRansomwareCampaignUse (Known 9.0 / CRITICAL, otherwise
            # 7.0 / HIGH) and were stored and exported as if they were CVSS; the CVE's
            # CVSS now comes from NVD only, and ransomware use travels as its own field.
            # Nor does it name an attack vector: the item no longer sends an invented
            # "NETWORK" (the CVE's attack vector comes from its CVSS).
            "severity": "UNKNOWN",
            "cvss_score": None,
            "vendor": vendor,
            "product": product,
            "required_action": required_action,
            "due_date": due_date,
            "known_ransomware_use": known_ransomware,
            "cisa_cwes": vuln.get("cwes", []),
            "cisa_notes": vuln.get("notes", ""),
            # KEV marker round-trip (2026-06): every CVE in this
            # feed IS the KEV list, but only NVD-sourced CVEs used
            # to get a queryable ``cisa_exploit_add`` property (via
            # NVD's cisaExploitAdd enrichment). CVEs known ONLY
            # from this collector reached Neo4j with no KEV marker
            # — 480 such CVEs on the 2026-04 baseline were
            # invisible to the ``ti-cve-kev`` query family. Emit
            # the same four cisa_* fields the NVD path emits;
            # misp_writer embeds them in the META comment and
            # run_misp_to_neo4j rehydrates them onto the CVE node.
            "cisa_exploit_add": date_added or "",
            "cisa_action_due": due_date or "",
            "cisa_required_action": required_action or "",
            "cisa_vulnerability_name": vuln.get("vulnerabilityName", "") or "",
        }

    def _update_misp(self, entries: List[Dict], items: List[Dict[str, Any]], limit: Optional[int]) -> Dict[str, Any]:
        """Compare the scope's items with EdgeGuard's stored MISP copies, add and edit (2026-10).

        - Lists every ``source:CISA-KEV`` vulnerability attribute once
          (``MISPWriter.index_source_attributes``, complete or it fails). A failed listing writes nothing
          and fails the run: a partial one would make stored CVEs look new.
        - Plans each item (``vulnerability_update.plan_source_updates``): only copies in EdgeGuard's own
          events are compared; a CVE MISP holds only in other events is neither added nor edited.
          ``EDGEGUARD_KEV_UPDATE_EXISTING=false`` leaves stored copies as they are. At most
          ``EDGEGUARD_KEV_MAX_EDITS_PER_RUN`` edits; the rest are deferred to the next run.
        - Adds the CVEs MISP lacks (``push_items`` given the listing), then edits the copies that differ
          (``apply_vulnerability_edits``: ``NVD_META``, ``first_seen`` / ``last_seen``; ``severity:``,
          ``cvss:`` and ``ransomware:`` tags replaced, zone, KEV and source tags only added).
        - Counts the CVEs MISP holds in EdgeGuard's events that the catalogue no longer lists; they are
          logged and kept.

        The status counts additions plus attempted edits as the run's items, so a failed edit fails
        the run like a failed addition; a deferred edit is no failure.
        """
        writer = self.misp_writer
        tag_map = getattr(writer, "SOURCE_TAGS", None)
        source_tag = (tag_map.get(self.tag) if isinstance(tag_map, dict) else None) or f"source:{self.tag}"
        edit_cap = kev_max_edits_per_run()
        if limit is not None:
            edit_cap = max(1, min(edit_cap, int(limit)))
        try:
            known = writer.index_source_attributes(source_tag, "vulnerability", keep_meta=True)
        except (MispTransientError, MispLookupError) as e:
            error_msg = (
                f"MISP: the {source_tag} attributes could not be listed ({e}); nothing was written, and the "
                "next run compares the catalogue again"
            )
            logger.error("CISA KEV: %s", error_msg)
            record_collection_failure("cisa", error_msg)
            return self._return_status(False, 0, error_msg)

        plan = plan_source_updates(
            writer,
            items,
            known,
            update_existing=kev_update_existing(),
            max_edits=edit_cap,
            replaced_tag_prefixes=KEV_REPLACED_TAG_PREFIXES,
            max_additions=limit,
        )
        if plan.foreign_only:
            # Also what a MISP answer without ``Event.info`` in its attribute rows would look like.
            logger.warning(
                "CISA KEV: %d CVE(s) are held under %s only in events EdgeGuard did not create (%s); they "
                "are neither added nor edited",
                len(plan.foreign_only),
                source_tag,
                ", ".join(plan.foreign_only[:20]),
            )
        added, add_failed, not_written = push_additions(writer, plan.to_add, source_tag, known)
        outcome = apply_vulnerability_edits(writer, plan.edits, label="KEV")
        not_written.extend(outcome.failed_ids)

        catalogue_ids = {str(entry.get("cveID") or "").strip().upper() for entry in entries}
        not_in_catalogue = sorted(
            cve_id
            for cve_id, copies in known.items()
            if cve_id not in catalogue_ids and any(copy.own_event for copy in copies)
        )
        if not_in_catalogue:
            logger.warning(
                "CISA KEV: %d CVE(s) MISP holds in EdgeGuard events are no longer in the catalogue (%s); "
                "their MISP copies and node fields are kept (a removal is counted, not applied)",
                len(not_in_catalogue),
                ", ".join(not_in_catalogue[:20]),
            )

        # CVEs whose edits were deferred (by the cap, or by a stop rule after part of their copies), once each.
        deferred = list(dict.fromkeys(plan.deferred_ids + outcome.deferred_ids))
        edit_failed = len(outcome.failed_ids)
        failed = add_failed + edit_failed
        if deferred or plan.additions_deferred_ids:
            reasons = list(outcome.stop_reasons)
            if plan.deferred_ids:
                reasons.insert(0, f"edit cap {edit_cap} (EDGEGUARD_KEV_MAX_EDITS_PER_RUN, or the run's limit)")
            if plan.additions_deferred_ids:
                reasons.append(f"the run's limit of {limit} additions")
            logger.info(
                "CISA KEV: %d edit(s) and %d addition(s) left for the next run (%s); the next run compares them again",
                len(deferred),
                len(plan.additions_deferred_ids),
                "; ".join(reasons),
            )
        logger.log(
            logging.WARNING if failed else logging.INFO,
            "CISA KEV: catalogue %s of %d entries, %d in scope; %d added, %d updated, %d unchanged, %d stored "
            "and not updated, %d only in other events, %d deferred, %d failed; %d stored and no longer in the "
            "catalogue",
            getattr(self, "catalog_version", None) or "(version unknown)",
            len(entries),
            len(items),
            added,
            outcome.updated,
            plan.unchanged,
            plan.stored_kept,
            len(plan.foreign_only),
            len(deferred) + len(plan.additions_deferred_ids),
            failed,
            len(not_in_catalogue),
        )
        st = status_after_misp_push(
            "cisa_kev", len(plan.to_add) + outcome.updated + edit_failed, added + outcome.updated, failed
        )
        st["circuit_breaker_state"] = CISA_CIRCUIT_BREAKER.state.name
        st["kev_update"] = {
            "catalogue": len(entries),
            "catalogue_version": getattr(self, "catalog_version", None),
            "scope": len(items),
            "added": added,
            "updated": outcome.updated,
            "unchanged": plan.unchanged,
            "stored_not_updated": plan.stored_kept,
            "foreign_only": len(plan.foreign_only),
            "deferred": len(deferred) + len(plan.additions_deferred_ids),
            "failed": failed,
            "not_written": sorted(set(not_written))[:100],
            "changed_keys": {edit.cve_id: list(edit.changed_keys) for edit in plan.edits[:100]},
            "stored_not_in_catalogue": len(not_in_catalogue),
            "stored_not_in_catalogue_ids": not_in_catalogue[:100],
            "stop_reasons": outcome.stop_reasons,
        }
        return st

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Standard status dict for Airflow when push_to_misp=True."""
        result = make_status("cisa_kev", success, count=count, failed=failed, error=error)
        result["circuit_breaker_state"] = CISA_CIRCUIT_BREAKER.state.name
        return result


def test_cisa() -> Dict[str, Any]:
    """Test CISA KEV collection and MISP push"""
    collector = CISACollector()
    result = collector.collect(limit=500)  # CISA KEV: No rate limit, fetch all
    print("\n📥 CISA KEV Test Result:")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    test_cisa()
