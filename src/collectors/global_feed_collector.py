#!/usr/bin/env python3
"""
EdgeGuard - Global Threat Feed Collectors
Universal feeds that apply to all zones
Sources: ThreatFox, URLhaus
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
    TransientServerError,
    feed_time,
    is_auth_or_access_denied,
    lower_limit,
    make_skipped_optional_source,
    make_status,
    newest_first,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    source_run_cap,
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

THREATFOX_RATE_LIMITER = RateLimiter(min_interval=2.0)  # 2 sec between requests
URLHAUS_RATE_LIMITER = RateLimiter(min_interval=1.0)  # 1 req/sec for URLhaus


def get_zones_from_malware(malware_name: str) -> List[str]:
    """
    Determine ALL zones based on malware family name using common zone detection.

    Args:
        malware_name: Name of the malware family

    Returns:
        List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
    """
    return detect_zones_from_text(malware_name or "")


# MalwareBazaar (abuse.ch) — flag-guarded source added 2026-10 (see MalwareBazaarCollector).
MALWAREBAZAAR_CIRCUIT_BREAKER = get_circuit_breaker("malwarebazaar", failure_threshold=3, recovery_timeout=1800)
MALWAREBAZAAR_RATE_LIMITER = RateLimiter(min_interval=2.0)  # one export download per run; 2 s guard
MALWAREBAZAAR_SOURCE_ID = "malwarebazaar"
# Public "recent" export: samples of the last 48 hours (about 1,000 rows), no API key required.
# The full export (``/export/csv/full/``) is the complete history and is deliberately not used.
MALWAREBAZAAR_EXPORT_URL = "https://bazaar.abuse.ch/export/csv/recent/"
MALWAREBAZAAR_SAMPLE_URL = "https://bazaar.abuse.ch/sample/{sha256}/"
# Column order of the export (verified 2026-10-12); the header is read from the ``#`` comment
# line when present so a reordered export still parses by name.
MALWAREBAZAAR_CSV_COLUMNS = (
    "first_seen_utc",
    "sha256_hash",
    "md5_hash",
    "sha1_hash",
    "reporter",
    "file_name",
    "file_type_guess",
    "mime_type",
    "signature",
    "clamav",
    "vtpercent",
    "imphash",
    "ssdeep",
    "tlsh",
)
_MALWAREBAZAAR_NA = "n/a"
_SHA256_HEX_LEN = 64


class MalwareBazaarTransientError(TransientServerError):
    """HTTP 429 / 5xx from the MalwareBazaar export, or an open circuit breaker.

    Subclasses ``TransientServerError`` so ``retry_with_backoff`` retries it and
    ``run_collector_with_metrics`` classifies it as transient (task skipped with an
    alert, nothing written) instead of failing the DAG task.
    """


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

    @staticmethod
    def max_per_run() -> int:
        """``config.THREATFOX_MAX_PER_RUN`` (default 10,000; ``0`` = no per-run cap)."""
        return source_run_cap("THREATFOX_MAX_PER_RUN", 10000)

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

        # PR-M1 §7-H8: respect the abuse.ch ThreatFox API hard cap.
        # Documented at https://threatfox.abuse.ch/api/ — the ``days``
        # parameter for ``get_iocs`` is ``Min: 1, Max: 7``.  For any
        # historical depth >7 days the documented path is the bulk JSON/
        # CSV export (https://threatfox.abuse.ch/export/), NOT this
        # endpoint.
        #
        # Previous behaviour: ``days = baseline_days`` (typically 365 or
        # 730) was sent verbatim; the API either silently clamped or
        # returned ``query_status`` != ``ok`` for out-of-range values,
        # making baseline runs non-obviously short on data.
        #
        # New behaviour:
        #   * clamp ``days`` to [1, 7] unconditionally (the API ceiling)
        #   * if a baseline with >7d was requested, emit an INFO log
        #     pointing the operator at the documented bulk-export path
        #   * a bulk-import collector for the ThreatFox JSON/CSV export
        #     is planned (see docs/COLLECTORS.md "Planned improvements")
        if baseline:
            days = baseline_days
        days_requested = days
        days = max(1, min(7, int(days)))
        if baseline and days_requested > 7:
            logger.info(
                "ThreatFox: baseline_days=%d clamped to days=%d (abuse.ch API max). "
                "For historical IOCs >7 days use the ThreatFox bulk export: "
                "https://threatfox.abuse.ch/export/ (a bulk-import collector is planned).",
                days_requested,
                days,
            )

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

            # 2026-10: the source's own cap (``EDGEGUARD_THREATFOX_MAX_PER_RUN``) replaces the
            # generic incremental default; a run that reaches it keeps the newest IOCs.
            cap = lower_limit(limit, self.max_per_run())
            iocs_to_process = iocs
            if cap is not None and len(iocs) > cap:
                iocs_to_process = newest_first(iocs, lambda ioc: feed_time(ioc.get("first_seen")))[:cap]
                logger.warning(
                    "ThreatFox: the %d-day window lists %d IOCs, more than this run's cap of %d "
                    "(EDGEGUARD_THREATFOX_MAX_PER_RUN, or a lower EDGEGUARD_MAX_ENTRIES / baseline limit); "
                    "the newest %d by first_seen are kept, %d older ones are not collected by this run",
                    days,
                    len(iocs),
                    cap,
                    cap,
                    len(iocs) - cap,
                )
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

    @staticmethod
    def max_per_run() -> int:
        """``config.URLHAUS_MAX_PER_RUN`` (default 50,000; ``0`` = no per-run cap)."""
        return source_run_cap("URLHAUS_MAX_PER_RUN", 50000)

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_feed(self, url: str) -> str:
        """Download a URLhaus feed CSV with retry. Transient network errors
        retry 4x with backoff before the exception propagates."""
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
        # 2026-10: the source's own cap (``EDGEGUARD_URLHAUS_MAX_PER_RUN``) replaces the generic
        # incremental default; a run that reaches it keeps the newest URLs.
        cap = lower_limit(limit, self.max_per_run())
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
                # cap so that the cap refers to actual data rows, not the
                # comment header block (which can be 10-20 lines in URLhaus).
                all_lines = raw_text.strip().split("\n")
                data_lines = [ln for ln in all_lines if ln and not ln.startswith("#")]
                rows = list(csv.reader(io.StringIO("\n".join(data_lines))))
                listed = len(rows)
                if cap is not None and listed > cap:
                    rows = newest_first(rows, lambda parts: feed_time(parts[1]) if len(parts) > 1 else None)[:cap]
                    logger.warning(
                        "URLhaus: %s lists %d URLs, more than this run's cap of %d "
                        "(EDGEGUARD_URLHAUS_MAX_PER_RUN, or a lower EDGEGUARD_MAX_ENTRIES / baseline limit); "
                        "the newest %d by dateadded are kept, %d older ones are not collected by this run",
                        url.split("/")[-2],
                        listed,
                        cap,
                        cap,
                        listed - cap,
                    )

                for parts in rows:
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
                        # PR (S5) (Logic Tracker MED): also forward
                        # the source's ``last_online`` field as ``last_seen``
                        # so the SOURCED_FROM edge captures URLhaus's own
                        # last-reported claim. Previously ``last_online`` was
                        # parsed and stored on the node only; the source-
                        # truthful extractor never saw it, so the edge's
                        # ``r.source_reported_last_at`` stayed NULL for
                        # every URLhaus IOC. ``last_online`` may be empty
                        # for currently-online URLs; coerce_iso handles
                        # the empty-string case.
                        results.append(
                            {
                                "indicator_type": "url",
                                "value": url_value,
                                "zone": zones if zones else ["global"],
                                "tag": "urlhaus",
                                "source": ["urlhaus"],
                                "first_seen": parts[1].strip().strip('"') if len(parts) > 1 else "",
                                "last_seen": last_online or None,
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


def _malwarebazaar_field(value: Optional[str]) -> str:
    """Strip an export field and map the literal ``n/a`` to an empty string."""
    text = (value or "").strip()
    return "" if text.lower() == _MALWAREBAZAAR_NA else text


def _malwarebazaar_first_seen_iso(value: Optional[str]) -> Optional[str]:
    """``first_seen_utc`` (``YYYY-MM-DD HH:MM:SS``, UTC) → tz-aware ISO-8601; ``None`` when unparseable.

    The export states its timestamps are UTC, so the offset is made explicit here rather
    than left to the reader. An unparseable value is an honest NULL — never wall-clock now.
    """
    text = (value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


class MalwareBazaarCollector:
    """
    Collects malware sample hashes from MalwareBazaar (abuse.ch) — flag-guarded, OFF by default.

    One ``sha256`` indicator per sample from the public **recent** CSV export
    (``MALWAREBAZAAR_EXPORT_URL``: the last 48 hours, about 1,000 samples). The
    export needs no API key; when ``THREATFOX_API_KEY`` (the abuse.ch Auth-Key,
    shared by all abuse.ch platforms) is configured it is sent as ``Auth-Key``.
    The ``signature`` column is the malware family: it becomes ``malware_family``
    on the item, travels to MISP inside the ``TF_META`` comment exactly like the
    ThreatFox family and is rehydrated as ``Indicator.malware_family`` in Neo4j,
    where ``build_relationships`` step 9 links it to ``Malware`` nodes
    (``INDICATES``, ``match_type = malware_family``).

    Baseline and regular runs both read the recent export: the full export is the
    complete history and is far too large for a scheduled task, so the history in
    MISP/Neo4j builds up over successive daily runs.

    Selection: labelled samples (``signature`` other than ``n/a``) are kept before
    unlabelled ones, then the list is cut at ``MALWAREBAZAAR_MAX_PER_RUN``. The generic
    incremental limit (``EDGEGUARD_INCREMENTAL_LIMIT``, 200 by default) does not apply: the
    source is listed in ``config.OWN_RUN_CAP_SOURCES`` because one 48-hour export holds about
    1,000 samples and a daily run cut at 200 would let most of them age out of the window.
    An explicit ``limit`` (baseline smoke-test limit, or the global ``EDGEGUARD_MAX_ENTRIES``
    override) is still honoured when it is lower than the cap.

    Failure contract (optional source): flag off → skipped status
    (``malwarebazaar_disabled_by_flag``) without an HTTP request; HTTP 401/403 →
    skipped (``malwarebazaar_auth_denied``); timeouts, connection errors, HTTP 429
    after the Retry-After retries and 5xx → ``MalwareBazaarTransientError`` propagates
    so ``run_collector_with_metrics`` marks the task skipped with an alert; other HTTP
    errors (for example 404 after an upstream layout change) → ``success=False``.
    Code defects fail loudly.

    Terms: MalwareBazaar data is free of charge for commercial and non-commercial use
    (https://bazaar.abuse.ch/faq/#tos).
    """

    def __init__(self, api_key: Optional[str] = None, misp_writer: MISPWriter = None):
        """
        Initialize MalwareBazaar collector.

        Args:
            api_key: Optional abuse.ch Auth-Key (defaults to ``THREATFOX_API_KEY``; not required)
            misp_writer: MISPWriter instance for pushing to MISP
        """
        self.api_key = api_key if api_key is not None else os.getenv("THREATFOX_API_KEY")
        self.export_url = MALWAREBAZAAR_EXPORT_URL
        self.source_name = MALWAREBAZAAR_SOURCE_ID
        self.misp_writer = misp_writer or MISPWriter()

    # ------------------------------------------------------------------
    # Flags
    # ------------------------------------------------------------------

    @staticmethod
    def is_enabled() -> bool:
        """``config.ENABLE_MALWAREBAZAAR`` (resolved when ``config`` is imported; tests patch the attribute)."""
        import config as _config

        return bool(getattr(_config, "ENABLE_MALWAREBAZAAR", False))

    @staticmethod
    def max_per_run() -> int:
        """``config.MALWAREBAZAAR_MAX_PER_RUN`` clamped at 0 (``0`` = no per-run cap)."""
        import config as _config

        try:
            return max(0, int(getattr(_config, "MALWAREBAZAAR_MAX_PER_RUN", 500)))
        except (TypeError, ValueError):
            return 500

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _headers(self) -> Optional[Dict[str, str]]:
        key = optional_api_key_effective(self.api_key, THREATFOX_API_KEY_PLACEHOLDERS)
        return {"Auth-Key": key} if key else None

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _download_export(self) -> requests.Response:
        """One download with transport-error retry; HTTP 429 / 5xx are retried inside the helper."""
        return request_with_rate_limit_retries(
            "GET",
            self.export_url,
            session=None,
            headers=self._headers(),
            timeout=(15, 60),  # tuple: connect=15s, read=60s (about 450 KB)
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=30.0,
            retry_on_403=False,
            context="MalwareBazaar",
        )

    def _fetch_export(self) -> str:
        """Download the recent export.

        Raises ``MalwareBazaarTransientError`` on 429 after the Retry-After retries and on
        5xx; plain ``requests.exceptions.HTTPError`` on any other non-200 code, so 401/403
        reach the auth-denied skip in ``collect``. The status check sits outside the
        ``retry_with_backoff``-decorated download on purpose: the decorator retries
        ``TransientServerError``, so raising inside it repeated the helper's four attempts
        four times (16 requests; with a ``Retry-After`` of ten minutes on every response
        the sleeps alone exceeded the task's two-hour execution timeout).
        """
        response = self._download_export()
        code = response.status_code
        if code == 200:
            return response.text
        if code == 429 or code >= 500:
            raise MalwareBazaarTransientError(f"MalwareBazaar export HTTP {code}", response=response)
        response.raise_for_status()
        # 3xx (redirects are not followed by the shared helper) or any other non-200 code.
        raise requests.exceptions.HTTPError(f"MalwareBazaar export HTTP {code}", response=response)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_export(raw_text: str) -> List[Dict[str, str]]:
        """Rows of the CSV export as dicts keyed by column name.

        ``#`` comment lines are skipped; the quoted header inside the comment block
        (``# "first_seen_utc","sha256_hash",...`` — recognised by the ``sha256_hash``
        column name) overrides the default column order. Fields are quoted and
        separated by ``, `` (comma + space), hence ``skipinitialspace``. Rows shorter
        than the ``signature`` column are dropped.
        """
        columns = list(MALWAREBAZAAR_CSV_COLUMNS)
        data_lines: List[str] = []
        for line in (raw_text or "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                header = stripped.lstrip("#").strip()
                if header.startswith('"'):
                    names = [c.strip().strip('"') for c in next(csv.reader([header], skipinitialspace=True))]
                    if "sha256_hash" in names:
                        columns = names
                continue
            data_lines.append(stripped)

        min_fields = columns.index("signature") + 1 if "signature" in columns else len(MALWAREBAZAAR_CSV_COLUMNS)
        rows: List[Dict[str, str]] = []
        shifted = 0
        for parts in csv.reader(data_lines, skipinitialspace=True):
            if len(parts) < min_fields:
                continue
            if len(parts) > len(columns):
                # More fields than columns: an unescaped quote or comma inside a field (a file
                # name) split the row, so every later column would be read from the wrong field.
                shifted += 1
                continue
            rows.append({col: (parts[i].strip() if i < len(parts) else "") for i, col in enumerate(columns)})
        if shifted:
            logger.warning(
                "MalwareBazaar: %d row(s) skipped — more fields than the %d export columns (unescaped separator in a field)",
                shifted,
                len(columns),
            )
        return rows

    def build_item(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """One ``sha256`` indicator for an export row; ``None`` when the hash is missing or malformed."""
        sha256 = _malwarebazaar_field(row.get("sha256_hash")).lower()
        if len(sha256) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in sha256):
            return None
        signature = _malwarebazaar_field(row.get("signature"))
        file_type = _malwarebazaar_field(row.get("file_type_guess")).lower()
        zones = get_zones_from_malware(signature) if signature else ["global"]
        return {
            "indicator_type": "sha256",
            "value": sha256,
            "zone": zones if zones else ["global"],  # zone is an array
            "tag": MALWAREBAZAAR_SOURCE_ID,
            "source": [MALWAREBAZAAR_SOURCE_ID],
            # Source-truthful: when MalwareBazaar first saw the sample (UTC). NULL when absent.
            "first_seen": _malwarebazaar_first_seen_iso(row.get("first_seen_utc")),
            "confidence_score": 0.7 if signature else 0.6,
            # Family label ("n/a" → empty). Reaches Neo4j via TF_META like the ThreatFox family.
            "malware_family": signature,
            "md5": _malwarebazaar_field(row.get("md5_hash")).lower(),
            "sha1": _malwarebazaar_field(row.get("sha1_hash")).lower(),
            "file_name": _malwarebazaar_field(row.get("file_name")),
            "file_type": file_type,
            "mime_type": _malwarebazaar_field(row.get("mime_type")),
            "reporter": _malwarebazaar_field(row.get("reporter")),
            # Sample page; also what makes MISPWriter emit the TF_META comment for this item.
            "reference": MALWAREBAZAAR_SAMPLE_URL.format(sha256=sha256),
            # Classification label that survives the MISP round-trip (TF_META.tags → tf_tags).
            "tags": [file_type] if file_type else [],
        }

    @staticmethod
    def select_items(items: List[Dict[str, Any]], limit: Optional[int], cap: int) -> List[Dict[str, Any]]:
        """Labelled samples first (stable order within each group), then cut at ``min(limit, cap)``.

        ``cap`` ≤ 0 means no per-run cap; ``limit`` ``None`` means no regular limit.
        """
        labelled = [item for item in items if item.get("malware_family")]
        unlabelled = [item for item in items if not item.get("malware_family")]
        ordered = labelled + unlabelled
        effective: Optional[int] = cap if cap > 0 else None
        if limit is not None:
            effective = limit if effective is None else min(limit, effective)
        return ordered if effective is None else ordered[:effective]

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(
        self, limit: Optional[int] = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Fetch the recent export and emit one ``sha256`` indicator per sample.

        Args:
            limit: Regular collection limit (``resolve_collection_limit`` semantics)
            push_to_misp: Whether to push collected indicators to MISP
            baseline: Accepted for the shared collector contract; the recent export is read either way
            baseline_days: Not applicable (the export has no date parameter); logged only

        Returns:
            Status dict if ``push_to_misp=True``, else list of indicators.
        """
        if not self.is_enabled():
            logger.info(
                "MalwareBazaar collector disabled by flag (EDGEGUARD_ENABLE_MALWAREBAZAAR is not true) "
                "— skipping, 0 items"
            )
            if push_to_misp:
                return make_skipped_optional_source(
                    MALWAREBAZAAR_SOURCE_ID,
                    skip_reason="disabled by flag EDGEGUARD_ENABLE_MALWAREBAZAAR",
                    skip_reason_class="malwarebazaar_disabled_by_flag",
                )
            return []

        if baseline:
            logger.info(
                "MalwareBazaar baseline: the recent export (last 48 hours) is the only key-free export; "
                "baseline_days=%d is not applicable and the history accumulates over daily runs",
                baseline_days,
            )
        limit = resolve_collection_limit(limit, MALWAREBAZAAR_SOURCE_ID, baseline=baseline)
        cap = self.max_per_run()

        if not MALWAREBAZAAR_CIRCUIT_BREAKER.can_execute():
            logger.warning("MalwareBazaar circuit breaker open - skipping run (transient)")
            raise MalwareBazaarTransientError("MalwareBazaar circuit breaker open — skipping run")

        MALWAREBAZAAR_RATE_LIMITER.wait_if_needed()
        try:
            raw_text = self._fetch_export()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, TransientServerError) as e:
            # Upstream outage / rate limiting → propagate so run_collector_with_metrics
            # classifies it as transient (task skipped + alert, nothing written).
            MALWAREBAZAAR_CIRCUIT_BREAKER.record_failure()
            logger.error(f"MalwareBazaar transient failure: {type(e).__name__}: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            if is_auth_or_access_denied(e):
                logger.warning(f"MalwareBazaar: auth/access denied — skipping (optional): {e}")
                MALWAREBAZAAR_CIRCUIT_BREAKER.record_success()
                if push_to_misp:
                    return make_skipped_optional_source(
                        MALWAREBAZAAR_SOURCE_ID,
                        skip_reason=str(e),
                        skip_reason_class="malwarebazaar_auth_denied",
                    )
                return []
            # Other 4xx / unexpected code: permanent for this URL (layout change) — needs an operator.
            MALWAREBAZAAR_CIRCUIT_BREAKER.record_failure()
            logger.error(f"MalwareBazaar HTTP error: {e}")
            if push_to_misp:
                return make_status(MALWAREBAZAAR_SOURCE_ID, False, count=0, error=str(e))
            raise

        MALWAREBAZAAR_CIRCUIT_BREAKER.record_success()
        rows = self.parse_export(raw_text)

        items: List[Dict[str, Any]] = []
        seen: set = set()
        malformed = 0
        for row in rows:
            item = self.build_item(row)
            if item is None:
                malformed += 1
                continue
            if item["value"] in seen:
                continue
            seen.add(item["value"])
            items.append(item)

        labelled_count = sum(1 for item in items if item["malware_family"])
        selected = self.select_items(items, limit, cap)
        logger.info(
            f"[OK] MalwareBazaar: {len(rows)} rows → {len(items)} samples "
            f"({labelled_count} labelled, {len(items) - labelled_count} unlabelled, {malformed} malformed); "
            f"{len(selected)} selected (limit={limit}, max_per_run={cap})"
        )
        if not items:
            logger.warning("MalwareBazaar returned 0 samples — check feed availability")

        if not push_to_misp:
            return selected
        if not selected:
            return make_status(MALWAREBAZAAR_SOURCE_ID, True, count=0, failed=0)
        success, failed = self.misp_writer.push_indicators(selected, self.source_name)
        logger.info(f"[PUSH] MalwareBazaar: Pushed {success} to MISP ({failed} failed)")
        return status_after_misp_push(MALWAREBAZAAR_SOURCE_ID, len(selected), success, failed)


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


if __name__ == "__main__":
    test()
