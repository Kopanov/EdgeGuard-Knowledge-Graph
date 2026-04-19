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

# Import MISP writer
from collectors.misp_writer import MISPWriter
from config import (
    OTX_API_KEY,
    OTX_INCREMENTAL_LOOKBACK_DAYS,
    OTX_INCREMENTAL_MAX_PAGES,
    OTX_INCREMENTAL_OVERLAP_SEC,
    SECTOR_TIME_RANGES,
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
                max_pages = 200
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

            # Process pulses with date filtering
            processed = []
            skipped_old = 0

            to_process = pulses if limit is None else pulses[:limit]
            for pulse in to_process:
                # Detect ALL sectors — start with keyword-based detection
                pulse_text = json.dumps(pulse).lower()
                sectors = self.detect_sectors(pulse_text)

                # OTX-native industry_sectors override: if OTX itself classified
                # the pulse into industries, use that as authoritative sector data.
                otx_industries = pulse.get("industries", [])
                if otx_industries:
                    _industry_map = {
                        "healthcare": "healthcare",
                        "health": "healthcare",
                        "medical": "healthcare",
                        "pharmaceutical": "healthcare",
                        "energy": "energy",
                        "utilities": "energy",
                        "oil": "energy",
                        "gas": "energy",
                        "finance": "finance",
                        "banking": "finance",
                        "financial": "finance",
                        "insurance": "finance",
                    }
                    for ind_name in otx_industries:
                        mapped = _industry_map.get(str(ind_name).lower().strip())
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

                # Filter by each sector's date range (use the widest among matched zones)
                pulse_created = pulse.get("created", "")
                if pulse_created:
                    try:
                        pulse_date = datetime.fromisoformat(pulse_created.replace("Z", "+00:00"))
                        months_range = max(SECTOR_TIME_RANGES.get(s, SECTOR_TIME_RANGES["global"]) for s in sectors)
                        cutoff = datetime.now(timezone.utc) - timedelta(days=months_range * 30)

                        if pulse_date < cutoff:
                            skipped_old += 1
                            continue
                    except (ValueError, TypeError):
                        pass

                # Shared metadata dict for all items from this pulse
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
                    indicator_type = self.map_indicator_type(ind.get("type"), ind.get("indicator"))
                    indicator_value = ind.get("indicator")
                    processed.append(
                        {
                            "indicator_type": indicator_type,
                            "value": indicator_value,
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            "first_seen": pulse.get("created", datetime.now(timezone.utc).isoformat()),
                            "last_updated": datetime.now(timezone.utc).isoformat(),
                            "confidence_score": 0.5,
                            "description": ind.get("description", "") or ind.get("title", ""),
                            "indicator_role": ind.get("role", ""),
                            "is_active": ind.get("is_active", True),
                            **pulse_meta,
                        }
                    )

                # Extract malware families
                malware_families = pulse.get("malware_families", [])
                for mal in malware_families:
                    mal_name = mal if isinstance(mal, str) else mal.get("name", "Unknown")
                    processed.append(
                        {
                            "type": "malware",
                            "name": mal_name,
                            "malware_types": ["unknown"],
                            "family": mal_name,
                            "description": pulse_description[:1000],
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            "confidence_score": 0.5,
                            # ATT&CK technique IDs from pulse → uses_techniques on Malware node
                            "uses_techniques": pulse_attack_ids,
                            **pulse_meta,
                        }
                    )

                # Extract CVE references (no cap — collect all CVEs from pulse)
                cve_refs = pulse.get("cve_references", [])
                for cve in cve_refs:
                    processed.append(
                        {
                            "type": "vulnerability",
                            "cve_id": cve.upper() if isinstance(cve, str) else cve.get("cve", "").upper(),
                            "description": f"Referenced in OTX pulse: {pulse.get('name', '')}",
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            "first_seen": pulse.get("created", datetime.now(timezone.utc).isoformat()),
                            "last_updated": datetime.now(timezone.utc).isoformat(),
                            "confidence_score": 0.5,
                            "severity": "UNKNOWN",
                            "cvss_score": 0.0,
                            "attack_vector": "NETWORK",
                            **pulse_meta,
                        }
                    )

                # Extract named adversary as a ThreatActor if present
                if pulse_adversary:
                    processed.append(
                        {
                            "type": "actor",
                            "name": pulse_adversary,
                            "description": pulse_description[:1000],
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            "confidence_score": 0.5,
                            "uses_techniques": pulse_attack_ids,
                            "aliases": [],
                            **pulse_meta,
                        }
                    )

            # Deduplicate
            seen = set()
            unique = []
            for item in processed:
                if "indicator_type" in item and "value" in item:
                    key = f"{item.get('indicator_type')}:{item.get('value')}"
                elif item.get("type") == "malware":
                    key = f"malware:{item.get('name')}"
                elif item.get("type") == "vulnerability":
                    key = f"cve:{item.get('cve_id')}"
                elif item.get("type") == "actor":
                    key = f"actor:{item.get('name')}"
                else:
                    key = str(item)

                if key not in seen and (item.get("value") or item.get("name") or item.get("cve_id")):
                    seen.add(key)
                    unique.append(item)

            logger.info(f"[OK] OTX: Processed {len(unique)} unique items")
            if skipped_old > 0:
                logger.info(f"⏭️ OTX: Skipped {skipped_old} old pulses outside sector time range")

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

        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"OTX timeout: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"OTX connection error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
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
            return self._return_status(False, 0, error_msg)
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"OTX collection error: {type(e).__name__}: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)

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
