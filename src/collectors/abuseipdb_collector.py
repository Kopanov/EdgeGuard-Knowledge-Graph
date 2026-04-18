#!/usr/bin/env python3
"""
EdgeGuard - AbuseIPDB Collector
Collects IP reputation data from AbuseIPDB API

API Documentation: https://docs.abuseipdb.com/
Free tier: 1,000 requests/day
Rate limit: 1 request per second recommended
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import requests

from collectors.collector_utils import (
    ABUSEIPDB_API_KEY_PLACEHOLDERS,
    make_skipped_optional_source,
    make_status,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)
from collectors.misp_writer import MISPWriter
from config import SSL_VERIFY, detect_zones_from_text, resolve_collection_limit

logger = logging.getLogger(__name__)


class AbuseIPDBCollector:
    """
    Collects IP reputation and threat intelligence from AbuseIPDB.

    AbuseIPDB is a project dedicated to helping combat the spread of
    hackers, spammers, and abusive activity on the internet.

    Features:
    - Check IP reputation scores
    - Bulk CIDR block checks
    - Rate limiting compliance (1000/day free tier)
    - Automatic MISP integration

    API Key: Get free key at https://www.abuseipdb.com/register
    """

    # API endpoints
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    CHECK_ENDPOINT = f"{BASE_URL}/check"
    CHECK_BLOCK_ENDPOINT = f"{BASE_URL}/check-block"
    BLACKLIST_ENDPOINT = f"{BASE_URL}/blacklist"

    # Rate limiting (free tier)
    REQUESTS_PER_DAY = 1000
    MIN_INTERVAL_SECONDS = 1.0  # 1 request per second to stay safe

    def __init__(self, api_key: Optional[str] = None, misp_writer: Optional[MISPWriter] = None):
        """
        Initialize AbuseIPDB collector.

        Args:
            api_key: AbuseIPDB API key (from https://www.abuseipdb.com/register)
                    Will try ABUSEIPDB_API_KEY environment variable if not provided
            misp_writer: MISPWriter instance for pushing to MISP
        """
        self.api_key = optional_api_key_effective(
            api_key or os.getenv("ABUSEIPDB_API_KEY"),
            ABUSEIPDB_API_KEY_PLACEHOLDERS,
        )
        self.source_name = "abuseipdb"
        self.misp_writer = misp_writer or MISPWriter()
        self._last_http_status: Optional[int] = None

        # Rate limiting state
        self.requests_today = 0
        self.last_request_time = 0.0
        self.daily_reset_time = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({"Key": self.api_key or "", "Accept": "application/json"})

    def _check_rate_limit(self) -> bool:
        """
        Check if we can make another request within rate limits.

        Returns:
            True if request is allowed, False if rate limited
        """
        if not self.api_key:
            # Without API key, we can't make any requests
            return False

        now = datetime.now(timezone.utc)

        # Reset daily counter if it's a new day
        if now.date() > self.daily_reset_time.date():
            self.requests_today = 0
            self.daily_reset_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
            logger.info("AbuseIPDB: Daily request counter reset")

        # Check daily limit
        if self.requests_today >= self.REQUESTS_PER_DAY:
            logger.warning(f"AbuseIPDB: Daily limit ({self.REQUESTS_PER_DAY}) reached")
            return False

        # Enforce minimum interval between requests
        elapsed = time.time() - self.last_request_time
        if elapsed < self.MIN_INTERVAL_SECONDS:
            sleep_time = self.MIN_INTERVAL_SECONDS - elapsed
            logger.debug(f"AbuseIPDB: Rate limiting - sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        return True

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _make_request(self, endpoint: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Make a rate-limited request to AbuseIPDB API.

        Transient network errors (ConnectionError/Timeout/ReadTimeout/
        ChunkedEncodingError) are retried with exponential backoff via the
        decorator — up to 4 total attempts (first + 3 retries) with 5s / 10s /
        20s delays. Before this fix a single connection hiccup (e.g. DNS
        glitch or 60s ISP outage) caused ``collect()`` to return
        ``status=True count=0`` and the day's blacklist was silently lost.

        After all retries are exhausted, the underlying exception propagates
        to ``collect()`` which catches it and returns ``success=False``, so
        Airflow retries the task and Prometheus records the failure.

        Returns:
            Response JSON dict on success, or None for auth/rate-limit
            failures (401/403/429) where retrying won't help.
        """
        if not self._check_rate_limit():
            return None

        # Do NOT wrap in a broad try/except — transient exceptions must
        # propagate to @retry_with_backoff. Only the shape-of-response
        # error branches return None (permanent failures: auth, parse).
        response = request_with_rate_limit_retries(
            "GET",
            endpoint,
            session=self.session,
            params=params,
            timeout=(15, 30),  # tuple: connect=15s, read=30s; prevents hangs on DNS/connect glitches
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=60.0,
            retry_on_403=False,
            context="AbuseIPDB",
        )

        self.last_request_time = time.time()
        self.requests_today += 1
        self._last_http_status = response.status_code

        if response.status_code == 200:
            try:
                return response.json()
            except (ValueError, TypeError):
                logger.error("AbuseIPDB: Malformed JSON in 200 response")
                return None
        elif response.status_code == 429:
            logger.warning("AbuseIPDB: Rate limit exceeded (429) after retries")
            return None
        elif response.status_code == 401:
            logger.error("AbuseIPDB: Authentication failed - check API key")
            return None
        elif response.status_code >= 500:
            # A 5xx that survives the inner ``request_with_rate_limit_retries``
            # budget (4 attempts with exponential backoff) is a real outage —
            # not "no data today". Raise so ``collect()`` reports the task as
            # failed and Airflow retries it, rather than silently returning
            # ``count=0 success=True``. Matches the surface-failure contract
            # of virustotal_collector.py and global_feed_collector.py, which
            # both call ``response.raise_for_status()`` in the equivalent
            # code path.
            logger.warning(f"AbuseIPDB API error: {response.status_code} - {response.text[:200]}")
            raise requests.exceptions.HTTPError(
                f"AbuseIPDB {response.status_code} after inner retries",
                response=response,
            )
        else:
            logger.warning(f"AbuseIPDB API error: {response.status_code} - {response.text[:200]}")
            return None

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
        """
        Check reputation of a single IP address.

        Args:
            ip_address: IP address to check (IPv4 or IPv6)
            max_age_days: Maximum age of reports to include (default 90)

        Returns:
            IP reputation data dict or None on error / network failure.

        ``_make_request`` is now decorated with ``@retry_with_backoff`` and
        propagates ``RequestException`` after retries are exhausted.
        Per-IP enrichment callers still expect ``None`` on error, so we
        catch here and keep the interface backward-compatible. The
        collect() → get_blacklist() path does NOT catch — it wants
        the real failure status so the DAG task fails loudly.
        """
        if not self.api_key:
            logger.warning("AbuseIPDB: No API key configured")
            return None

        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": "true",  # Must be lowercase string; Python True → "True" which the API ignores
        }

        try:
            data = self._make_request(self.CHECK_ENDPOINT, params)
        except requests.exceptions.RequestException as exc:
            logger.warning("AbuseIPDB check_ip(%s) network failure after retries: %s", ip_address, exc)
            return None

        if data and "data" in data:
            return self._format_ip_result(data["data"])
        return None

    def check_cidr_block(self, cidr: str, max_age_days: int = 90) -> List[Dict[str, Any]]:
        """
        Check all IPs in a CIDR block (up to /24 for IPv4, /64 for IPv6).

        This uses the check-block endpoint which is more efficient than
        checking IPs individually.

        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            max_age_days: Maximum age of reports to include

        Returns:
            List of IP reputation data dicts. Returns ``[]`` on network
            failure after retries are exhausted (same backward-compat
            reason as ``check_ip`` above).
        """
        if not self.api_key:
            logger.warning("AbuseIPDB: No API key configured")
            return []

        params = {"network": cidr, "maxAgeInDays": max_age_days}

        try:
            data = self._make_request(self.CHECK_BLOCK_ENDPOINT, params)
        except requests.exceptions.RequestException as exc:
            logger.warning("AbuseIPDB check_cidr_block(%s) network failure after retries: %s", cidr, exc)
            return []

        results = []
        if data and "data" in data:
            for ip_data in data["data"].get("reportedAddress", []):
                formatted = self._format_ip_result(ip_data)
                if formatted:
                    results.append(formatted)

        return results

    def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: Optional[int] = None,
        *,
        baseline: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Get AbuseIPDB blacklist (high-confidence abusive IPs).

        This is the primary feed collection method - gets the most
        actionable malicious IP addresses.

        Args:
            confidence_minimum: Minimum confidence score (25-100)
            limit: Maximum number of IPs to return (uses config if not set)
            baseline: Must match the parent collect() run so unlimited baseline
                does not get replaced by the incremental default here.

        Returns:
            List of indicator dicts ready for MISP
        """
        limit = resolve_collection_limit(limit, "abuseipdb", baseline=baseline)

        if not self.api_key:
            logger.warning("AbuseIPDB: No API key configured - cannot fetch blacklist")
            return []

        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": min(limit, 10000) if limit is not None else 10000,  # API max is 10,000
        }

        self._last_http_status = None
        data = self._make_request(self.BLACKLIST_ENDPOINT, params)

        results = []
        if data and "data" in data:
            for ip_data in data["data"]:
                indicator = self._format_blacklist_result(ip_data)
                if indicator:
                    results.append(indicator)

        logger.info(f"[FETCH] AbuseIPDB: Fetched {len(results)} IPs from blacklist (confidence ≥{confidence_minimum})")
        return results

    def _format_ip_result(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Format single IP check result to EdgeGuard indicator format.

        Args:
            data: Raw AbuseIPDB data dict

        Returns:
            Formatted indicator dict or None
        """
        ip = data.get("ipAddress")
        if not ip:
            return None

        abuse_score = data.get("abuseConfidenceScore", 0)

        # Build metadata text for zone detection
        zone_parts = [
            data.get("isp", ""),
            data.get("countryCode", ""),
            data.get("usageType", ""),
            data.get("domain", ""),
        ]
        zone_text = " ".join(p for p in zone_parts if p)
        zones = detect_zones_from_text(zone_text) if zone_text else ["global"]

        # Aggregate unique abuse category IDs across all reports
        # AbuseIPDB category IDs: 3=Fraud, 4=DDoS, 5=FTP Brute-Force,
        # 11=Email Spam, 14=Port Scan, 15=Hacking, 18=Brute-Force,
        # 19=Bad Web Bot, 20=Exploited Host, 21=Web Spam, 22=SSH, 23=IoT
        all_categories: set[int] = set()
        for report in data.get("reports", [])[:5]:
            for cat_id in report.get("categories", []):
                all_categories.add(cat_id)

        return {
            "indicator_type": "ipv4" if "." in ip else "ipv6",
            "value": ip,
            "zone": zones,
            "tag": "abuseipdb",
            "source": ["abuseipdb"],
            "first_seen": data.get("firstSeen", ""),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "confidence_score": abuse_score / 100.0,
            "abuse_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported": data.get("lastReportedAt", ""),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "hostnames": data.get("hostnames", []),
            "usage_type": data.get("usageType", ""),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "reports": data.get("reports", [])[:5],  # Keep top 5 reports
            "abuse_categories": sorted(all_categories),
        }

    def _format_blacklist_result(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Format blacklist result to EdgeGuard indicator format.

        Args:
            data: Raw AbuseIPDB blacklist data dict

        Returns:
            Formatted indicator dict or None
        """
        ip = data.get("ipAddress")
        if not ip:
            return None

        abuse_score = data.get("abuseConfidenceScore", 0)

        # Build description from available data
        description = f"AbuseIPDB confidence: {abuse_score}%"
        country = data.get("countryCode", "")
        if country:
            description += f", Country: {country}"

        # Build metadata text for zone detection
        zone_parts = [
            data.get("isp", ""),
            country,
            data.get("usageType", ""),
            data.get("domain", ""),
        ]
        zone_text = " ".join(p for p in zone_parts if p)
        zones = detect_zones_from_text(zone_text) if zone_text else ["global"]

        # PR (S5) — Source-Truth Investigator audit: this branch
        # (blacklist endpoint) used to set ``first_seen = lastReportedAt``,
        # which is SEMANTICALLY WRONG — ``lastReportedAt`` is the date of
        # the MOST RECENT report (= last_seen), not the FIRST report.
        # The check endpoint (``_format_check_data`` above) correctly
        # uses ``firstSeen``; the blacklist endpoint doesn't expose that
        # field, so we leave ``first_seen`` UNSET entirely. parse_attribute's
        # source-truthful extractor will then see ``attr.first_seen=None``
        # and skip ``first_seen_at_source`` (NULL = "we don't know when
        # AbuseIPDB first saw this IP via blacklist endpoint" — honest
        # signal).
        #
        # PR (S5) commit X (bugbot HIGH) follow-up: the previous attempt
        # set ``first_seen`` to wall-clock NOW "for back-compat". That was
        # wrong — it leaks through MISPWriter:664 → MISP attribute → the
        # extractor reads it back → AbuseIPDB IS on the reliable allowlist
        # → wall-clock NOW gets stored as first_seen_at_source. Today's
        # date masquerading as world-truth on every blacklist IP.
        # Fix: omit first_seen entirely. Honest NULL > misleading wall-clock.
        last_reported = data.get("lastReportedAt", "")
        return {
            "indicator_type": "ipv4" if "." in ip else "ipv6",
            "value": ip,
            "zone": zones,
            "tag": "abuseipdb",
            "source": ["abuseipdb"],
            # first_seen INTENTIONALLY OMITTED — see comment above.
            "last_seen": last_reported,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "confidence_score": abuse_score / 100.0,
            "abuse_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "country": country,
            "last_reported": data.get("lastReportedAt", ""),
            "description": description,
        }

    def collect(
        self,
        limit: Optional[int] = None,
        push_to_misp: bool = True,
        confidence_minimum: int = 90,
        baseline: bool = False,
        baseline_days: int = 365,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Main collection method - fetches AbuseIPDB blacklist.

        This is the primary entry point for feed collection.

        Args:
            limit: Maximum indicators to collect (uses config if not set)
            push_to_misp: Whether to push to MISP
            confidence_minimum: Minimum confidence score for blacklist (25-100)
            baseline: If True, do not substitute incremental default when limit is None
            baseline_days: Reserved for API consistency with other collectors

        Returns:
            Status dict if ``push_to_misp=True`` (Airflow), else list of indicators.
        """
        limit = resolve_collection_limit(limit, "abuseipdb", baseline=baseline)

        logger.info(f"[NET] AbuseIPDB: Starting collection (limit={limit}, min_confidence={confidence_minimum})")

        if not optional_api_key_effective(self.api_key, ABUSEIPDB_API_KEY_PLACEHOLDERS):
            logger.warning(
                "AbuseIPDB: No API key — skipping collection (optional source). "
                "Set ABUSEIPDB_API_KEY for blacklist feed; https://www.abuseipdb.com/api"
            )
            if push_to_misp:
                return make_status(
                    "abuseipdb",
                    True,
                    count=0,
                    failed=0,
                    skipped=True,
                    skip_reason="ABUSEIPDB_API_KEY not set (optional — https://www.abuseipdb.com/api)",
                    skip_reason_class="missing_abuseipdb_key",
                )
            return []

        # Fetch blacklist. Network exceptions (after @retry_with_backoff in
        # _make_request has exhausted its retries) propagate here — catch
        # them so the collector returns a PROPER failure status instead of
        # silent success. Before this fix, a connection error returned
        # success=True count=0 and Airflow never retried the task.
        try:
            results = self.get_blacklist(confidence_minimum=confidence_minimum, limit=limit, baseline=baseline)
        except requests.exceptions.RequestException as exc:
            logger.error(
                "AbuseIPDB: network failure after retries (%s: %s) — reporting as collector failure",
                type(exc).__name__,
                exc,
            )
            if push_to_misp:
                return self._return_status(False, 0, error=f"{type(exc).__name__}: {exc}", failed=0)
            # Non-MISP caller expects a list; returning an empty list would
            # be indistinguishable from "no data today" so raise instead.
            raise

        if baseline and not results:
            logger.warning("AbuseIPDB baseline returned 0 items — verify API key")

        logger.info(f"[OK] AbuseIPDB: Collection complete - {len(results)} indicators")

        if push_to_misp:
            if not results and self._last_http_status in (401, 403):
                logger.warning("AbuseIPDB: API returned 401/403 — skipping as optional (check ABUSEIPDB_API_KEY)")
                return make_skipped_optional_source(
                    "abuseipdb",
                    skip_reason="AbuseIPDB rejected credentials (401/403)",
                    skip_reason_class="abuseipdb_auth_denied",
                )
            if not results:
                return self._return_status(True, 0, failed=0)
            success, failed = self.misp_writer.push_indicators(results, self.source_name)
            logger.info(f"[PUSH] AbuseIPDB: Pushed {success} to MISP ({failed} failed)")
            return status_after_misp_push("abuseipdb", len(results), success, failed)

        return results

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        return make_status("abuseipdb", success, count=count, failed=failed, error=error)

    def enrich_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich a single IP with AbuseIPDB data (for enrichment use).

        Args:
            ip_address: IP to enrich

        Returns:
            Enriched indicator dict or None
        """
        return self.check_ip(ip_address)

    def get_rate_limit_status(self) -> Dict[str, Any]:
        """
        Get current rate limit status.

        Returns:
            Dict with rate limit information
        """
        return {
            "requests_today": self.requests_today,
            "requests_per_day": self.REQUESTS_PER_DAY,
            "remaining_today": max(0, self.REQUESTS_PER_DAY - self.requests_today),
            "min_interval_seconds": self.MIN_INTERVAL_SECONDS,
            "has_api_key": bool(self.api_key),
        }


def collect_abuseipdb(
    push_to_misp: bool = True, limit: Optional[int] = None, confidence_minimum: int = 90
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Convenience function to collect from AbuseIPDB.

    Args:
        push_to_misp: Whether to push to MISP
        limit: Maximum indicators to collect
        confidence_minimum: Minimum confidence score (25-100)

    Returns:
        Status dict if ``push_to_misp=True``, else list of indicators.
    """
    collector = AbuseIPDBCollector()
    return collector.collect(limit=limit, push_to_misp=push_to_misp, confidence_minimum=confidence_minimum)


def test():
    """Test AbuseIPDB collector"""
    print("=== Testing AbuseIPDB Collector ===")

    collector = AbuseIPDBCollector()

    # Check rate limit status
    status = collector.get_rate_limit_status()
    print(f"Rate limit status: {json.dumps(status, indent=2)}")

    if not collector.api_key:
        print("\n⚠️  No API key configured!")
        print("Set ABUSEIPDB_API_KEY environment variable")
        print("Get free API key at: https://www.abuseipdb.com/register")
        return

    # Test collection
    print("\n=== Testing Blacklist Collection ===")
    data = collector.collect(limit=10, push_to_misp=False, confidence_minimum=90)
    print(f"Collected: {len(data)} indicators")

    if data:
        print("\nSample indicator:")
        print(json.dumps(data[0], indent=2))

    # Test single IP check
    print("\n=== Testing Single IP Check ===")
    test_ip = "8.8.8.8"  # Google's DNS - likely not abusive
    result = collector.check_ip(test_ip)
    if result:
        print(f"IP {test_ip}:")
        print(json.dumps(result, indent=2))
    else:
        print(f"No data for {test_ip} (or rate limited)")


if __name__ == "__main__":
    test()
