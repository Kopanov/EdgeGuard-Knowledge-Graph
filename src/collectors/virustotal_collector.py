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

        # Optional source: no key → skip Airflow task success + metrics (same contract as AbuseIPDB).
        # PR (S5) commit X: the non-Airflow path previously returned
        # ``_collect_demo_data()`` — synthetic hashes tagged ``virustotal``
        # with wall-clock-NOW first_seen. The VT pipeline is a real,
        # production-ready collector (``_collect_from_files`` via the v3
        # Intelligence API); demo mode was a legacy development shortcut
        # from before the real path worked. It served no production
        # purpose and risked poisoning the graph if a dev piped the
        # output through MISPWriter. Deleted — set VIRUSTOTAL_API_KEY to
        # run the real collector; no key means no data (consistent with
        # every other optional-source path).
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
            return []

        try:
            indicators = self._collect_from_files(limit)
        except requests.HTTPError as e:
            # Auth/access denied → optional-source skip (the source is
            # wired but the key is expired or low-tier).
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal enrich: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal_enrich",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            # Any other HTTPError (5xx after retry exhaustion, 4xx that
            # isn't auth) → report as collector failure. Do NOT fall back
            # to demo data — the pre-round-1 behaviour pushed fake hashes
            # to MISP tagged as real VT enrichment on any error.
            logger.error(f"VirusTotal HTTP error: {e}")
            if push_to_misp:
                return make_status(
                    "virustotal_enrich",
                    False,
                    count=0,
                    failed=0,
                    error=f"{type(e).__name__}: {e}",
                )
            raise
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
        ) as net_exc:
            # Network outage after @retry_with_backoff exhausted. Do NOT
            # silently fall back to demo data — return a proper failure
            # status so Airflow retries the task and Prometheus records
            # the failure.
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
            # Any remaining exception (JSONDecodeError on a malformed VT
            # 200 response, KeyError / TypeError on unexpected schema,
            # etc.) — report as a hard collector failure, NOT a fall-back
            # to demo data. Round 1 removed the internal try/except from
            # _collect_from_files without fixing this handler, so parse
            # errors were silently pushing fake hashes to MISP — bugbot
            # caught it on round 3. Auth/access-denied exceptions still
            # route through the optional-source skip path.
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"VirusTotal enrich: auth/access denied — skipping (optional): {e}")
                return make_skipped_optional_source(
                    "virustotal_enrich",
                    skip_reason=str(e),
                    skip_reason_class="virustotal_auth_denied",
                )
            logger.error(
                "VirusTotal collection error (parse/schema/other): %s: %s",
                type(e).__name__,
                e,
            )
            if push_to_misp:
                return make_status(
                    "virustotal_enrich",
                    False,
                    count=0,
                    failed=0,
                    error=f"{type(e).__name__}: {e}",
                )
            raise

        if push_to_misp:
            if not self.misp_writer:
                return make_status("virustotal_enrich", False, count=0, error="MISP writer not configured")
            if not indicators:
                return make_status("virustotal_enrich", True, count=0, failed=0)
            success, failed = self.misp_writer.push_indicators(indicators, "virustotal")
            return status_after_misp_push("virustotal_enrich", len(indicators), success, failed)

        return indicators

    def _collect_from_files(self, limit):
        """Collect recent malware files from VT.

        Previously this method caught ``Exception`` broadly and returned
        an empty list, which meant the outer ``collect()`` silently fell
        back to DEMO DATA on any network error and pushed fake hashes to
        MISP tagged as real VT intelligence. Now transient network errors
        propagate to ``@retry_with_backoff`` (applied on the inner
        ``_fetch_recent_files_raw`` helper, not this method) and, on
        final exhaustion, bubble up to ``collect()`` which routes them
        to a proper failure status instead of the demo fallback.

        Rate limiting is handled HERE, not inside the retried helper,
        because the VT rate limiter is a 4 req/min sliding window —
        retrying inside the rate-limited scope would burn the full
        per-minute quota on a single failing call. Matches the
        URLhaus/CyberCure pattern (rate limiter outside, retry inside).
        """
        indicators = []

        # Rate limit check — outside the retried helper so a single failing
        # call doesn't exhaust the VT 4/minute sliding window on its retries.
        self.rate_limiter.wait_if_needed()

        response = self._fetch_recent_files_raw(limit)

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
        else:
            # Any non-200 that reaches this branch is either a 4xx
            # client error (already surfaced as HTTPError in
            # _fetch_recent_files_raw below) or an unexpected status.
            # Treat it as empty and move on; real 5xx failures are
            # caught by raise_for_status() inside the retried helper
            # so they never reach here.
            logger.warning(
                "VT files query returned unexpected status %s — treating as empty",
                response.status_code,
            )

        return indicators[:limit]

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _fetch_recent_files_raw(self, limit):
        """HTTP fetch for ``/files`` with retry but NO rate limiting.

        Split out of ``_collect_from_files`` so each retry attempt does
        not re-enter ``self.rate_limiter.wait_if_needed()`` — the VT
        free-tier limiter is a 4 req/min sliding window, and a single
        failing call inside the retried scope would have burned the
        whole per-minute quota on its 4 attempts.

        The caller (``_collect_from_files``) handles rate limiting
        once, before this helper runs. Matches the URLhaus/CyberCure
        split in ``global_feed_collector.py``, which includes
        ``response.raise_for_status()`` at the end to surface HTTP
        5xx as exceptions that hit the retry decorator (and, on
        exhaustion, propagate to collect() for proper failure
        reporting — bugbot round 4 caught that this VT helper was
        the only one missing that step and 5xx slipped through
        silently as empty indicators).
        """
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
        # Raise HTTPError on 4xx/5xx so the retry decorator above gets a
        # shot at transient 5xx, and terminal failures propagate to
        # collect() — matches URLhaus/CyberCure. 200 responses pass
        # through unchanged to the caller for normal parsing.
        response.raise_for_status()
        return response

    def _detect_zones_from_names(self, attrs):
        """Detect ALL sectors from file names/paths using common zone detection.

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        names = str(attrs.get("meaningful_name", "")) + str(attrs.get("names", ""))
        return detect_zones_from_text(names)

    # PR (S5) commit X: ``_collect_demo_data`` was deleted. The VT
    # pipeline (``_collect_from_files`` via the v3 Intelligence API) is
    # the real, production collector; the previous demo method returned
    # 3 hardcoded hashes (EICAR + known demo SHAs) tagged ``virustotal``
    # with wall-clock NOW first_seen — a source-truth poisoning risk
    # (the tag is on the reliable allowlist). It was only reachable via
    # direct Python calls with ``push_to_misp=False``; all Airflow +
    # enrichment paths already skipped correctly when the API key was
    # absent. Set ``VIRUSTOTAL_API_KEY`` to run the real collector.

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
