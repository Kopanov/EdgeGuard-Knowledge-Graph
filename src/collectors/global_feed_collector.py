#!/usr/bin/env python3
"""
EdgeGuard - Global Threat Feed Collectors
Universal feeds that apply to all zones
Sources: ThreatFox, URLhaus, CyberCure
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import csv
import io
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import requests

from collectors.collector_utils import (
    THREATFOX_API_KEY_PLACEHOLDERS,
    RateLimiter,
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
from config import SSL_VERIFY, detect_zones_from_text, resolve_collection_limit
from resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

# Circuit breakers for each feed
THREATFOX_CIRCUIT_BREAKER = get_circuit_breaker("threatfox", failure_threshold=3, recovery_timeout=1800)
URLHAUS_CIRCUIT_BREAKER = get_circuit_breaker("urlhaus", failure_threshold=3, recovery_timeout=1800)
CYBERCURE_CIRCUIT_BREAKER = get_circuit_breaker("cybercure", failure_threshold=3, recovery_timeout=1800)

THREATFOX_RATE_LIMITER = RateLimiter(min_interval=2.0)  # 2 sec between requests
URLHAUS_RATE_LIMITER = RateLimiter(min_interval=1.0)  # 1 req/sec for URLhaus
CYBERCURE_RATE_LIMITER = RateLimiter(min_interval=2.0)  # 2 sec for CyberCure


def get_zones_from_malware(malware_name: str) -> List[str]:
    """
    Determine ALL zones based on malware family name using common zone detection.

    Args:
        malware_name: Name of the malware family

    Returns:
        List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
    """
    return detect_zones_from_text(malware_name or "")


class ThreatFoxCollector:
    """
    Collects IOCs from ThreatFox API - Global threat intelligence feed.

    ThreatFox is a free platform from abuse.ch for sharing IOCs associated
    with malware families. abuse.ch may require a free **THREATFOX_API_KEY**
    (register at https://auth.abuse.ch/). Without a key or on 401/403, the
    collector **skips** so Airflow does not fail the DAG.

    API Documentation: https://threatfox.abuse.ch/api/
    """

    def __init__(self, api_key: Optional[str] = None, misp_writer: MISPWriter = None):
        """
        Initialize ThreatFox collector.

        Args:
            api_key: Optional API key (recommended; may be required by the API)
            misp_writer: MISPWriter instance for pushing to MISP
        """
        # API key can be obtained from https://auth.abuse.ch/ for higher rate limits
        self.api_key = api_key if api_key is not None else os.getenv("THREATFOX_API_KEY")
        self.base_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.source_name = "threatfox"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_iocs(self, days: int) -> dict:
        """POST to ThreatFox API with retry."""
        headers = {}
        if self.api_key and self.api_key != "demo":
            headers["Auth-Key"] = self.api_key
        response = request_with_rate_limit_retries(
            "POST",
            self.base_url,
            session=None,
            json={"query": "get_iocs", "days": days},
            headers=headers if headers else None,
            timeout=30,
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=45.0,
            retry_on_403=False,
            context="ThreatFox",
        )
        if response.status_code != 200:
            response.raise_for_status()
        return response.json()

    def collect(
        self,
        limit: Optional[int] = None,
        push_to_misp: bool = True,
        days: int = 7,
        baseline: bool = False,
        baseline_days: int = 365,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Fetch IOCs from ThreatFox API.

        Args:
            limit: Maximum number of IOCs to collect (uses config if not specified)
            push_to_misp: Whether to push collected IOCs to MISP
            days: Number of days to look back for IOCs (normal mode)
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back in baseline mode

        Returns:
            Status dict if ``push_to_misp=True``, else list of indicators.
        """
        limit = resolve_collection_limit(limit, "threatfox", baseline=baseline)

        # Use more days in baseline mode
        if baseline:
            days = baseline_days

        results = []

        # Check circuit breaker
        if not THREATFOX_CIRCUIT_BREAKER.can_execute():
            logger.warning("ThreatFox circuit breaker open - skipping")
            if push_to_misp:
                return make_status("threatfox", False, count=0, error="Circuit breaker open")
            return results

        # Rate limiting
        THREATFOX_RATE_LIMITER.wait_if_needed()

        # Optional feed: no usable key → skip (same contract as AbuseIPDB / OTX)
        if not optional_api_key_effective(self.api_key, THREATFOX_API_KEY_PLACEHOLDERS):
            logger.warning(
                "ThreatFox: No API key — skipping (optional). Set THREATFOX_API_KEY (free): https://auth.abuse.ch/"
            )
            THREATFOX_CIRCUIT_BREAKER.record_success()
            if push_to_misp:
                return make_skipped_optional_source(
                    "threatfox",
                    skip_reason="THREATFOX_API_KEY not set — https://auth.abuse.ch/",
                    skip_reason_class="missing_threatfox_key",
                )
            return results

        try:
            data = self._fetch_iocs(days)

            if data.get("query_status") != "ok":
                logger.warning(f"ThreatFox query failed: {data.get('query_status')}")
                THREATFOX_CIRCUIT_BREAKER.record_failure()
                if push_to_misp:
                    return make_status(
                        "threatfox",
                        False,
                        count=0,
                        error=f"ThreatFox query_status={data.get('query_status')}",
                    )
                return results

            iocs = data.get("data", [])
            logger.info(f"[FETCH] ThreatFox: Got {len(iocs)} IOCs")

            iocs_to_process = iocs if limit is None else iocs[:limit]
            for ioc in iocs_to_process:
                malware = ioc.get("malware_printable", "")
                # Use detect_zones_from_text for sector detection from malware family
                zones = get_zones_from_malware(malware)

                ioc_type = ioc.get("ioc_type", "")
                ioc_value = ioc.get("ioc", "")

                # Strip port from ip:port values — MISP ip-dst does not accept
                # a port suffix (e.g. "185.220.101.5:8080" → "185.220.101.5").
                if ioc_type == "ip:port" and ":" in ioc_value:
                    ioc_value = ioc_value.rsplit(":", 1)[0]

                # Map ThreatFox IOC types to EdgeGuard types
                indicator_type = self._map_ioc_type(ioc_type)

                if indicator_type != "unknown" and ioc_value:
                    results.append(
                        {
                            "indicator_type": indicator_type,
                            "value": ioc_value,
                            "zone": zones,  # zone is now an array
                            "tag": "threatfox",
                            "source": ["threatfox"],
                            "first_seen": ioc.get("first_seen", ""),
                            "last_seen": ioc.get("last_seen", ""),
                            "last_updated": datetime.now(timezone.utc).isoformat(),
                            "confidence_score": ioc.get("confidence_level", 50) / 100.0,
                            "malware_family": malware,
                            "threat_type": ioc.get("threat_type", ""),
                            "threat_type_desc": ioc.get("threat_type_desc", ""),
                            "ioc_id": ioc.get("id", ""),
                            "malware_alias": ioc.get("malware_alias", ""),
                            "malware_malpedia": ioc.get("malware_malpedia", ""),
                            "reporter": ioc.get("reporter", ""),
                            "reference": ioc.get("reference", ""),
                            "tags": ioc.get("tags") or [],
                        }
                    )

            logger.info(f"[OK] ThreatFox: Processed {len(results)} indicators")
            if not results and optional_api_key_effective(self.api_key, THREATFOX_API_KEY_PLACEHOLDERS):
                logger.warning("ThreatFox returned 0 IOCs despite valid API key — check feed status")

            THREATFOX_CIRCUIT_BREAKER.record_success()
            if push_to_misp:
                if not results:
                    return make_status("threatfox", True, count=0, failed=0)
                success, failed = self.misp_writer.push_indicators(results, self.source_name)
                logger.info(f"[PUSH] ThreatFox: Pushed {success} to MISP ({failed} failed)")
                return status_after_misp_push("threatfox", len(results), success, failed)
            return results

        except requests.exceptions.Timeout:
            logger.error("ThreatFox collection timed out")
            THREATFOX_CIRCUIT_BREAKER.record_failure()
            return make_status("threatfox", False, count=0, error="Timeout") if push_to_misp else results
        except requests.exceptions.RequestException as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"ThreatFox: auth/access denied — skipping (optional): {e}")
                THREATFOX_CIRCUIT_BREAKER.record_success()
                return make_skipped_optional_source(
                    "threatfox",
                    skip_reason=str(e),
                    skip_reason_class="threatfox_auth_denied",
                )
            logger.error(f"ThreatFox request error: {e}")
            THREATFOX_CIRCUIT_BREAKER.record_failure()
            return make_status("threatfox", False, count=0, error=str(e)) if push_to_misp else results
        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"ThreatFox: auth/access denied — skipping (optional): {e}")
                THREATFOX_CIRCUIT_BREAKER.record_success()
                return make_skipped_optional_source(
                    "threatfox",
                    skip_reason=str(e),
                    skip_reason_class="threatfox_auth_denied",
                )
            logger.error(f"ThreatFox collection error: {e}")
            THREATFOX_CIRCUIT_BREAKER.record_failure()
            return make_status("threatfox", False, count=0, error=str(e)) if push_to_misp else results

    def _map_ioc_type(self, ioc_type: str) -> str:
        """
        Map ThreatFox IOC types to EdgeGuard indicator types.

        Args:
            ioc_type: ThreatFox IOC type string

        Returns:
            EdgeGuard indicator type string
        """
        type_mapping = {
            "domain": "domain",
            "ip:port": "ipv4",  # We'll store just the IP part
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "url": "url",
            "md5_hash": "md5",
            "sha1_hash": "sha1",
            "sha256_hash": "sha256",
            "sha3_384_hash": "sha384",
            "sha512_hash": "sha512",
            "ssdeep": "hash",
        }

        # Handle ip:port format specially
        if ioc_type == "ip:port":
            return "ipv4"

        return type_mapping.get(ioc_type, "unknown")

    def query_ioc(self, ioc_value: str) -> Optional[Dict[str, Any]]:
        """
        Query specific IOC details from ThreatFox.

        Args:
            ioc_value: The IOC value to query

        Returns:
            Dictionary with IOC details or None if not found
        """
        try:
            headers = {}
            if self.api_key and self.api_key != "demo":
                headers["Auth-Key"] = self.api_key

            response = requests.post(
                self.base_url,
                json={"query": "search_ioc", "search_term": ioc_value},
                headers=headers if headers else None,
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data.get("data", {})
            return None

        except Exception as e:
            logger.error(f"ThreatFox query error: {e}")
            return None


class URLhausCollector:
    """
    Collects malware URLs from URLhaus - Global malware URL feed.

    URLhaus is a project from abuse.ch to share malicious URLs.
    Public CSV feeds available without authentication.
    """

    def __init__(self, misp_writer: MISPWriter = None):
        """
        Initialize URLhaus collector.

        Args:
            misp_writer: MISPWriter instance for pushing to MISP
        """
        self.urls = [
            # Recent malware URLs (CSV)
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            # Top 1000 malware URLs
            "https://urlhaus.abuse.ch/downloads/csv_top10k/",
        ]
        self.source_name = "urlhaus"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_feed(self, url: str) -> str:
        """Download a URLhaus feed CSV with retry. Matches the CyberCure
        pattern — transient network errors retry 4x with backoff before the
        exception propagates."""
        response = request_with_rate_limit_retries(
            "GET",
            url,
            session=None,
            timeout=(15, 30),  # tuple: connect=15s, read=30s
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="URLhaus",
        )
        response.raise_for_status()
        return response.text

    def collect(
        self, limit: Optional[int] = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Fetch malware URLs from URLhaus CSV feeds.

        Args:
            limit: Maximum number of URLs to collect
            push_to_misp: Whether to push collected URLs to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back in baseline mode

        Returns:
            Status dict if ``push_to_misp=True``, else list of indicators.
        """
        # URLhaus has different feeds - full history, recent, etc.
        # In baseline mode, try to get more feeds
        if baseline:
            logger.info("📜 Baseline mode: Collecting full URLhaus history...")
            # Could add more URLhaus feed types here

        # Check circuit breaker
        if not URLHAUS_CIRCUIT_BREAKER.can_execute():
            logger.warning("URLhaus circuit breaker open - skipping")
            if push_to_misp:
                return make_status("urlhaus", False, count=0, error="Circuit breaker open")
            return []

        limit = resolve_collection_limit(limit, "urlhaus", baseline=baseline)
        results = []
        # Track per-URL failures so we can distinguish "all mirrors failed"
        # (real outage — report FAILURE to Airflow/Prometheus) from "first
        # mirror succeeded, others skipped" (success). Before this change
        # an all-mirrors-down run returned count=0 success=True and was
        # invisible to monitoring.
        mirror_failures = 0
        mirror_success = False

        for url in self.urls:
            # Rate limiting
            URLHAUS_RATE_LIMITER.wait_if_needed()

            try:
                raw_text = self._fetch_feed(url)

                # Parse CSV — filter comment/blank lines BEFORE applying the
                # limit so that the limit refers to actual data rows, not the
                # comment header block (which can be 10-20 lines in URLhaus).
                all_lines = raw_text.strip().split("\n")
                data_lines = [ln for ln in all_lines if ln and not ln.startswith("#")]
                lines_to_process = data_lines if limit is None else data_lines[:limit]

                reader = csv.reader(io.StringIO("\n".join(lines_to_process)))
                for parts in reader:
                    # URLhaus CSV columns:
                    # id(0), dateadded(1), url(2), url_status(3), last_online(4),
                    # threat(5), tags(6), urlhaus_link(7), reporter(8)
                    if len(parts) < 5:
                        continue

                    url_value = parts[2].strip()
                    url_status = parts[3].strip() if len(parts) > 3 else ""
                    last_online = parts[4].strip() if len(parts) > 4 else ""
                    threat = parts[5].strip() if len(parts) > 5 else ""
                    tags = parts[6].strip() if len(parts) > 6 else ""
                    urlhaus_link = parts[7].strip() if len(parts) > 7 else ""
                    reporter = parts[8].strip() if len(parts) > 8 else ""

                    # Determine ALL zones from threat/tags using detect_zones_from_text
                    zones = get_zones_from_malware(threat) if threat else ["global"]
                    if not zones or zones == ["global"]:
                        zones = get_zones_from_malware(tags) if tags else ["global"]

                    if url_value and url_value.startswith("http"):
                        results.append(
                            {
                                "indicator_type": "url",
                                "value": url_value,
                                "zone": zones if zones else ["global"],
                                "tag": "urlhaus",
                                "source": ["urlhaus"],
                                "first_seen": parts[1].strip().strip('"') if len(parts) > 1 else "",
                                "last_updated": datetime.now(timezone.utc).isoformat(),
                                "confidence_score": 0.6,
                                "threat_type": threat,
                                "tags": tags,
                                "url_status": url_status,
                                "last_online": last_online,
                                "reporter": reporter,
                                "reference": urlhaus_link,
                            }
                        )

                logger.info(f"[OK] URLhaus: Collected from {url.split('/')[-2]}")
                URLHAUS_CIRCUIT_BREAKER.record_success()
                mirror_success = True
                break  # Got data, no need to try other URLs

            except Exception as e:
                logger.warning(f"URLhaus {url}: {e}")
                URLHAUS_CIRCUIT_BREAKER.record_failure()
                mirror_failures += 1
                continue

        # Deduplicate by value
        seen = set()
        unique = []
        for r in results:
            if r["value"] not in seen:
                seen.add(r["value"])
                unique.append(r)

        logger.info(f"[OK] URLhaus: {len(unique)} unique URLs")
        if not unique:
            logger.warning("URLhaus returned 0 URLs — check feed availability")

        # If every mirror failed, report collector FAILURE instead of
        # success-with-zero-count. This is the fix for the silent-data-loss
        # pattern where an all-mirrors-down outage showed up as a successful
        # Airflow task with zero indicators and never triggered an alert.
        #
        # For the non-MISP caller (push_to_misp=False), an empty list is
        # indistinguishable from "feed had no data today" — raise instead so
        # the failure is visible to enrichment workflows. Matches the
        # AbuseIPDB pattern in collect().
        if not mirror_success and mirror_failures >= len(self.urls) and self.urls:
            err = f"URLhaus: all {mirror_failures} mirror(s) failed"
            logger.error(err)
            if push_to_misp:
                return make_status("urlhaus", False, count=0, failed=0, error=err)
            raise RuntimeError(err)

        out = unique if limit is None else unique[:limit]
        if push_to_misp:
            if not unique:
                return make_status("urlhaus", True, count=0, failed=0)
            success, failed = self.misp_writer.push_indicators(unique, self.source_name)
            logger.info(f"[PUSH] URLhaus: Pushed {success} to MISP ({failed} failed)")
            return status_after_misp_push("urlhaus", len(unique), success, failed)
        return out


class CyberCureCollector:
    """
    Collects from CyberCure free feeds - Global IOC feed.

    CyberCure provides free CSV feeds of malicious IPs, URLs, and hashes.
    Public feeds available without authentication.

    Status: Limited data quality - may return empty or sparse results.
    """

    def __init__(self, misp_writer: MISPWriter = None):
        """
        Initialize CyberCure collector.

        Args:
            misp_writer: MISPWriter instance for pushing to MISP
        """
        self.feeds = {
            "ip": "https://api.cybercure.ai/feed/get_ips?type=csv",
            "url": "https://api.cybercure.ai/feed/get_url?type=csv",
            "hash": "https://api.cybercure.ai/feed/get_hash?type=csv",
        }
        self.source_name = "cybercure"
        self.misp_writer = misp_writer or MISPWriter()

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_feed(self, url: str) -> str:
        """Download a CyberCure feed CSV with retry."""
        response = request_with_rate_limit_retries(
            "GET",
            url,
            session=None,
            timeout=(15, 30),  # tuple: connect=15s, read=30s
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="CyberCure",
        )
        response.raise_for_status()
        return response.text

    def collect(
        self, limit: Optional[int] = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Fetch from CyberCure feeds.

        Args:
            limit: Maximum number of indicators to collect (split across feed types)
            push_to_misp: Whether to push collected indicators to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back in baseline mode

        Returns:
            Status dict if ``push_to_misp=True``, else list of indicators.
        """
        # CyberCure is a bulk download - baseline doesn't change much
        if baseline:
            logger.info("📜 Baseline mode: Collecting all CyberCure data...")

        # Check circuit breaker
        if not CYBERCURE_CIRCUIT_BREAKER.can_execute():
            logger.warning("CyberCure circuit breaker open - skipping")
            if push_to_misp:
                return make_status("cybercure", False, count=0, error="Circuit breaker open")
            return []

        limit = resolve_collection_limit(limit, "cybercure", baseline=baseline)
        results = []
        # Track per-feed failures so an all-feeds-down outage reports as
        # a collector failure rather than silent-zero-success. Same
        # rationale as URLhaus above.
        feed_failures = 0
        feed_success_count = 0

        for feed_type, url in self.feeds.items():
            # Rate limiting
            CYBERCURE_RATE_LIMITER.wait_if_needed()

            try:
                raw_text = self._fetch_feed(url)

                lines = raw_text.strip().split("\n")

                # Safety check for limit
                # Divide the overall limit across the 3 feed types; None means unlimited.
                batch_limit = max(1, limit // 3) if limit is not None and limit > 0 else None
                lines_iter = lines if batch_limit is None else lines[:batch_limit]
                for line in lines_iter:  # Distribute limit across feed types
                    if not line or line.startswith("#"):
                        continue

                    value = line.strip()
                    if not value:
                        continue

                    # CyberCure feeds provide bare IP/URL/hash lists without metadata
                    # (no ISP, country, description, or tags) — zone detection would
                    # always return ["global"], so we hardcode it to avoid the overhead.
                    if feed_type == "ip":
                        results.append(
                            {
                                "indicator_type": "ipv4",
                                "value": value,
                                "zone": ["global"],
                                "tag": "cybercure",
                                "source": ["cybercure"],
                                "first_seen": datetime.now(timezone.utc).isoformat(),
                                "last_updated": datetime.now(timezone.utc).isoformat(),
                                "confidence_score": 0.5,
                            }
                        )
                    elif feed_type == "url" and value.startswith("http"):
                        results.append(
                            {
                                "indicator_type": "url",
                                "value": value,
                                "zone": ["global"],
                                "tag": "cybercure",
                                "source": ["cybercure"],
                                "first_seen": datetime.now(timezone.utc).isoformat(),
                                "last_updated": datetime.now(timezone.utc).isoformat(),
                                "confidence_score": 0.5,
                            }
                        )
                    elif feed_type == "hash":
                        # Detect hash type by length
                        hash_type = "sha256"
                        if len(value) == 32:
                            hash_type = "md5"
                        elif len(value) == 40:
                            hash_type = "sha1"

                        results.append(
                            {
                                "indicator_type": hash_type,
                                "value": value,
                                "zone": ["global"],
                                "tag": "cybercure",
                                "source": ["cybercure"],
                                "first_seen": datetime.now(timezone.utc).isoformat(),
                                "last_updated": datetime.now(timezone.utc).isoformat(),
                                "confidence_score": 0.5,
                            }
                        )

                CYBERCURE_CIRCUIT_BREAKER.record_success()
                feed_success_count += 1

            except Exception as e:
                logger.warning(f"CyberCure {feed_type}: {e}")
                CYBERCURE_CIRCUIT_BREAKER.record_failure()
                feed_failures += 1
                continue

        logger.info(f"[OK] CyberCure: Collected {len(results)} indicators")
        if not results:
            logger.warning("CyberCure returned 0 indicators — check feed availability")

        # All feeds failed → report collector failure instead of silent
        # zero-count success. Raise for the non-MISP caller so failures
        # are visible to enrichment workflows (same pattern as URLhaus
        # above and AbuseIPDB in its own collect()).
        if feed_success_count == 0 and feed_failures >= len(self.feeds) and self.feeds:
            err = f"CyberCure: all {feed_failures} feed(s) failed"
            logger.error(err)
            if push_to_misp:
                return make_status("cybercure", False, count=0, failed=0, error=err)
            raise RuntimeError(err)

        if push_to_misp:
            if not results:
                return make_status("cybercure", True, count=0, failed=0)
            success, failed = self.misp_writer.push_indicators(results, self.source_name)
            logger.info(f"[PUSH] CyberCure: Pushed {success} to MISP ({failed} failed)")
            return status_after_misp_push("cybercure", len(results), success, failed)

        return results


def collect_all_global_feeds(
    push_to_misp: bool = True, limit_per_source: Optional[int] = None
) -> Dict[str, Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """
    Collect from all global threat feeds.

    Args:
        push_to_misp: Whether to push collected data to MISP
        limit_per_source: Maximum items per source

    Returns:
        Per-source results: status dicts if ``push_to_misp=True``, else indicator lists.
    """
    results = {}

    # ThreatFox
    logger.info("=== Collecting from ThreatFox ===")
    tf = ThreatFoxCollector()
    results["threatfox"] = tf.collect(limit=limit_per_source, push_to_misp=push_to_misp)

    # URLhaus
    logger.info("=== Collecting from URLhaus ===")
    uh = URLhausCollector()
    results["urlhaus"] = uh.collect(limit=limit_per_source, push_to_misp=push_to_misp)

    # CyberCure
    logger.info("=== Collecting from CyberCure ===")
    cc = CyberCureCollector()
    results["cybercure"] = cc.collect(limit=limit_per_source, push_to_misp=push_to_misp)

    def _entry_count(entry: Union[Dict[str, Any], List[Dict[str, Any]]]) -> int:
        if isinstance(entry, dict):
            return int(entry.get("count", 0))
        return len(entry)

    total = sum(_entry_count(v) for v in results.values())
    logger.info(f"=== Global Feeds Complete: {total} total indicators (approx from status counts) ===")

    return results


def test():
    """Test all collectors"""
    print("=== Testing ThreatFox ===")
    tf = ThreatFoxCollector()
    data = tf.collect(limit=50, push_to_misp=False)
    print(f"Collected: {len(data)}")
    if data:
        print(f"Sample: {data[0]}")

    print("\n=== Testing URLhaus ===")
    uh = URLhausCollector()
    data = uh.collect(limit=50, push_to_misp=False)
    print(f"Collected: {len(data)}")
    if data:
        print(f"Sample: {data[0]}")

    print("\n=== Testing CyberCure ===")
    cc = CyberCureCollector()
    data = cc.collect(limit=50, push_to_misp=False)
    print(f"Collected: {len(data)}")
    if data:
        print(f"Sample: {data[0]}")


if __name__ == "__main__":
    test()
