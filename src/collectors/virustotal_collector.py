#!/usr/bin/env python3
"""
EdgeGuard - VirusTotal Collector
Collects threat indicators from VirusTotal API

Rate Limits (Free Tier):
- 4 lookups/minute
- 500 lookups/day
- 15,500 lookups/month

Note: For production, get a paid plan at https://www.virustotal.com/gui/join-us
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Union

import requests

from collectors.collector_utils import (
    VIRUSTOTAL_API_KEY_PLACEHOLDERS,
    RateLimiter,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)
from config import (
    DEFAULT_SECTOR,
    SOURCE_TAGS,
    SSL_VERIFY,
    VIRUSTOTAL_API_KEY,
    detect_zones_from_text,
    resolve_collection_limit,
)

logger = logging.getLogger(__name__)


class VirusTotalCollector:
    """Collects indicators from VirusTotal"""

    # Class-level rate limiter (shared across instances)
    _rate_limiter = None

    def __init__(self, misp_writer=None):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.api_key = optional_api_key_effective(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_PLACEHOLDERS)
        self.tag = SOURCE_TAGS.get("virustotal", "virustotal")
        self.misp_writer = misp_writer
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": self.api_key or "", "Accept": "application/json"})
        self.session.verify = SSL_VERIFY

        # Initialize rate limiter
        if VirusTotalCollector._rate_limiter is None:
            VirusTotalCollector._rate_limiter = RateLimiter(requests_per_minute=4)
        self.rate_limiter = VirusTotalCollector._rate_limiter

    def collect(
        self, limit=None, push_to_misp=False, baseline=False, baseline_days=365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Collect from VirusTotal.

        NOTE: VT has rate limits (4 requests/min free tier).
        We collect via:
        1. Intelligence searches (if API key supports)
        2. Daily top threats
        3. Common malware hashes

        For enrichment, use query_domain()/query_hash() instead.

        When ``push_to_misp=True`` (Airflow), returns a status dict after MISP push.
        """
        limit = resolve_collection_limit(limit, "virustotal", baseline=baseline)
        if limit is None:
            limit = 10

        # Optional source: no key → skip Airflow task success + metrics (same contract as AbuseIPDB)
        if not optional_api_key_effective(self.api_key, VIRUSTOTAL_API_KEY_PLACEHOLDERS):
            logger.warning(
                "VirusTotal: No API key — skipping collection (optional source). "
                "Set VIRUSTOTAL_API_KEY when ready; https://www.virustotal.com/gui/join-us"
            )
            if push_to_misp:
                return make_status(
                    "virustotal_enrich",
                    True,
                    count=0,
                    failed=0,
                    skipped=True,
                    skip_reason=("VIRUSTOTAL_API_KEY not set (optional — https://www.virustotal.com/gui/join-us)"),
                    skip_reason_class="missing_virustotal_key",
                )
            return self._collect_demo_data(limit)

        try:
            indicators = self._collect_from_files(limit)
        except requests.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal enrich: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal_enrich",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            logger.error(f"VirusTotal collection error: {e}")
            indicators = self._collect_demo_data(limit)
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
        ) as net_exc:
            # Network outage after @retry_with_backoff exhausted. Do NOT
            # silently fall back to demo data — return a proper failure
            # status so Airflow retries the task and Prometheus records
            # the failure. (Pre-fix behaviour pushed demo data to MISP
            # tagged as real VT enrichment during any outage.)
            logger.error(
                "VirusTotal: network failure after retries (%s: %s) — reporting as collector failure",
                type(net_exc).__name__,
                net_exc,
            )
            if push_to_misp:
                return make_status(
                    "virustotal_enrich",
                    False,
                    count=0,
                    failed=0,
                    error=f"{type(net_exc).__name__}: {net_exc}",
                )
            raise
        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal enrich: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal_enrich",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            logger.error(f"VirusTotal collection error: {e}")
            indicators = self._collect_demo_data(limit)

        if push_to_misp:
            if not self.misp_writer:
                return make_status("virustotal_enrich", False, count=0, error="MISP writer not configured")
            if not indicators:
                return make_status("virustotal_enrich", True, count=0, failed=0)
            success, failed = self.misp_writer.push_indicators(indicators, "virustotal")
            return status_after_misp_push("virustotal_enrich", len(indicators), success, failed)

        return indicators

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _collect_from_files(self, limit):
        """Collect recent malware files from VT.

        Previously this method caught ``Exception`` broadly and returned
        an empty list, which meant the outer ``collect()`` silently fell
        back to DEMO DATA on any network error and pushed fake hashes to
        MISP tagged as real VT intelligence. Now transient network errors
        propagate to ``@retry_with_backoff`` (4 total attempts at 5/10/20s)
        and, on final exhaustion, bubble up to ``collect()`` which routes
        them to a proper failure status instead of the demo fallback.
        """
        indicators = []

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        # Get recent files analyzed by VT. Do NOT catch generic Exception
        # here — let transient network errors reach the retry decorator,
        # and let terminal errors reach collect() for failure reporting.
        response = request_with_rate_limit_retries(
            "GET",
            f"{self.base_url}/files",
            session=self.session,
            params={"limit": min(limit, 10)},  # API has strict limits
            timeout=(15, 30),  # tuple: connect=15s, read=30s
            max_rate_limit_retries=3,
            fallback_delay_sec=60.0,
            retry_on_403=False,
            context="VirusTotal",
        )

        if response.status_code == 200:
            data = response.json()
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                hashes = attrs.get("last_analysis_stats", {})

                # Get the hash with most info
                if attrs.get("sha256"):
                    mal_count = hashes.get("malicious", 0)
                    conf = min(0.5 + (mal_count / 70), 0.95)  # Scale 0.5-0.95

                    zones = self._detect_zones_from_names(attrs)

                    indicators.append(
                        {
                            "indicator_type": "hash",
                            "value": attrs["sha256"],
                            "zone": zones,  # zone is now an array
                            "tag": self.tag,
                            "source": [self.tag],
                            "first_seen": attrs.get("first_submission_date", ""),
                            "last_updated": datetime.now(timezone.utc).isoformat(),
                            "confidence_score": conf,
                        }
                    )
        elif response.status_code in (401, 403):
            # Surface auth errors so the caller can mark the source skipped.
            response.raise_for_status()
        else:
            logger.warning(
                "VT files query returned unexpected status %s — treating as empty",
                response.status_code,
            )

        return indicators[:limit]

    def _detect_zones_from_names(self, attrs):
        """Detect ALL sectors from file names/paths using common zone detection.

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        names = str(attrs.get("meaningful_name", "")) + str(attrs.get("names", ""))
        return detect_zones_from_text(names)

    def _collect_demo_data(self, limit):
        """Return demo data when no API key"""
        # Known malware hashes for testing
        demo_hashes = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty hash (demo)
            "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # Password
        ]

        indicators = []
        for h in demo_hashes[:limit]:
            indicators.append(
                {
                    "indicator_type": "hash",
                    "value": h,
                    "zone": [DEFAULT_SECTOR],  # zone is now an array
                    "tag": self.tag,
                    "source": [self.tag],
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "confidence_score": 0.5,
                }
            )

        logger.info(f"[OK] VirusTotal: Demo mode - {len(indicators)} indicators")
        return indicators

    def query_domain(self, domain):
        """
        ENRICHMENT: Query a domain in VirusTotal
        Returns full analysis data for enrichment
        """
        if not self.api_key:
            logger.warning("No VT API key for enrichment")
            return None

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        try:
            response = request_with_rate_limit_retries(
                "GET",
                f"{self.base_url}/domains/{domain}",
                session=self.session,
                timeout=(15, 30),  # tuple: connect=15s, read=30s — single-value 10s was too tight for DNS glitches
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="VirusTotal",
            )

            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})

                stats = attrs.get("last_analysis_stats", {})
                mal_count = stats.get("malicious", 0)
                conf = min(0.5 + (mal_count / 70), 0.95)

                result = {
                    "indicator_type": "domain",
                    "value": domain,
                    "zone": [DEFAULT_SECTOR],  # zone is now an array
                    "tag": self.tag,
                    "source": [self.tag],
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "confidence_score": conf,
                    # VT-specific data for raw storage
                    "vt_stats": stats,
                    "vt_categories": attrs.get("categories", {}),
                    "vt_last_analysis_date": attrs.get("last_analysis_date"),
                }

                logger.info(f"[OK] VT enrichment: {domain} (conf: {conf})")
                return result

        except Exception as e:
            logger.error(f"VT domain query error: {e}")

        return None

    def query_hash(self, hash_value):
        """
        ENRICHMENT: Query a file hash in VirusTotal
        """
        if not self.api_key:
            return None

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        try:
            response = request_with_rate_limit_retries(
                "GET",
                f"{self.base_url}/files/{hash_value}",
                session=self.session,
                timeout=(15, 30),  # tuple: connect=15s, read=30s — single-value 10s was too tight for DNS glitches
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="VirusTotal",
            )

            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})

                stats = attrs.get("last_analysis_stats", {})
                mal_count = stats.get("malicious", 0)
                conf = min(0.5 + (mal_count / 70), 0.95)

                return {
                    "indicator_type": "hash",
                    "value": hash_value,
                    "zone": [DEFAULT_SECTOR],  # zone is now an array
                    "tag": self.tag,
                    "source": [self.tag],
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "confidence_score": conf,
                    "vt_stats": stats,
                    "vt_names": attrs.get("names", []),
                }

        except Exception as e:
            logger.error(f"VT hash query error: {e}")

        return None

    def query_ip(self, ip):
        """ENRICHMENT: Query an IP in VirusTotal"""
        if not self.api_key:
            return None

        # Rate limit check
        self.rate_limiter.wait_if_needed()

        try:
            response = request_with_rate_limit_retries(
                "GET",
                f"{self.base_url}/ip_addresses/{ip}",
                session=self.session,
                timeout=(15, 30),  # tuple: connect=15s, read=30s — single-value 10s was too tight for DNS glitches
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="VirusTotal",
            )

            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})

                stats = attrs.get("last_analysis_stats", {})
                mal_count = stats.get("malicious", 0)
                conf = min(0.5 + (mal_count / 70), 0.95)

                return {
                    "indicator_type": "ipv4",
                    "value": ip,
                    "zone": [DEFAULT_SECTOR],  # zone is now an array
                    "tag": self.tag,
                    "source": [self.tag],
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "confidence_score": conf,
                    "vt_stats": stats,
                    "vt_country": attrs.get("country"),
                    "vt_asn": attrs.get("asn"),
                }

        except Exception as e:
            logger.error(f"VT IP query error: {e}")

        return None


if __name__ == "__main__":
    collector = VirusTotalCollector()
    results = collector.collect(limit=5)
    print(f"Collected: {len(results)} indicators")
    for r in results[:3]:
        print(f"  - {r['indicator_type']}: {r['value'][:40]}...")
