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
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

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
from collectors.misp_writer import MISPWriter
from config import SOURCE_TAGS, SSL_VERIFY, detect_zones_from_text, resolve_collection_limit
from resilience import get_circuit_breaker

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
            limit: Maximum number of vulnerabilities to fetch

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
        vulnerabilities = data.get("vulnerabilities", [])

        logger.info(f"[FETCH] CISA KEV: Fetched {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Dict[str, Any]:
        """
        Collect KEV from CISA and optionally push to MISP.

        Args:
            limit: Maximum number of vulnerabilities to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back to collect in baseline mode

        Returns:
            Dict with status and counts if push_to_misp=True, else list of processed items
        """
        limit = resolve_collection_limit(limit, "cisa", baseline=baseline)

        try:
            if baseline:
                # Baseline mode: fetch all (CISA is a bulk download anyway)
                logger.info("📜 Baseline mode: Collecting all CISA KEV data...")
                vulnerabilities = self._fetch_kev(limit=None)  # Fetch all
            else:
                # Normal mode: fetch with limit
                vulnerabilities = self._fetch_kev(limit)

            # Process KEV
            processed = []
            to_process = vulnerabilities if limit is None else vulnerabilities[:limit]
            for vuln in to_process:
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

                # Map ransomware use to severity
                if known_ransomware == "Known":
                    severity = "CRITICAL"
                    cvss_score = 9.0
                elif known_ransomware == "Unknown":
                    severity = "HIGH"
                    cvss_score = 7.0
                else:
                    severity = "MEDIUM"
                    cvss_score = 5.0

                processed.append(
                    {
                        "type": "vulnerability",
                        "cve_id": cve_id,
                        "description": short_desc[:500],
                        "zone": sectors,  # zone is now an array
                        "tag": self.tag,
                        "source": [self.tag],
                        "first_seen": date_added or datetime.now(timezone.utc).isoformat(),
                        "last_updated": datetime.now(timezone.utc).isoformat(),
                        "confidence_score": 0.9,  # High confidence - known exploited
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "attack_vector": "NETWORK",
                        "vendor": vendor,
                        "product": product,
                        "required_action": required_action,
                        "due_date": due_date,
                        "known_ransomware_use": known_ransomware,
                        "cisa_cwes": vuln.get("cwes", []),
                        "cisa_notes": vuln.get("notes", ""),
                    }
                )

            logger.info(f"[OK] CISA KEV: Processed {len(processed)} vulnerabilities")

            # Push to MISP if requested
            if push_to_misp:
                if not processed:
                    return self._return_status(True, 0, failed=0)

                success, failed = self.misp_writer.push_items(processed)

                if success > 0:
                    logger.info(f"[OK] CISA KEV: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] CISA KEV: Failed to push {failed} items to MISP")

                st = status_after_misp_push("cisa_kev", len(processed), success, failed)
                st["circuit_breaker_state"] = CISA_CIRCUIT_BREAKER.state.name
                return st
            else:
                return processed

        except requests.exceptions.Timeout as e:
            logger.error(f"CISA KEV timeout: {e}")
            return self._return_status(False, 0, str(e)) if push_to_misp else []
        except requests.exceptions.ConnectionError as e:
            logger.error(f"CISA KEV connection error: {e}")
            return self._return_status(False, 0, str(e)) if push_to_misp else []
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
            return self._return_status(False, 0, str(e)) if push_to_misp else []
        except Exception as e:
            logger.error(f"CISA KEV collection error: {type(e).__name__}: {e}")
            return self._return_status(False, 0, str(e)) if push_to_misp else []

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
