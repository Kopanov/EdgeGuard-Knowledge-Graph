#!/usr/bin/env python3
"""
EdgeGuard Prototype - NVD Collector
Collects CVE records from NVD and pushes to MISP

NVD API use: This product uses data from the NVD API but is not endorsed or certified by the NVD.
See https://nvd.nist.gov/developers/start-here (terms, rate limits, apiKey header).

**NIST constraints (always enforced here):**
- Each GET must use ``pubStartDate`` and ``pubEndDate`` together with span **≤ 120 consecutive
  calendar days** (``NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`` + ``clamp_nvd_published_range`` /
  ``iter_nvd_published_windows``). A 24-month *collection policy* is implemented as **many**
  ≤120-day windows in baseline mode, not one wide request.
- Request spacing: ``batch_sleep`` (~0.7s with API key, ~6.5s without) stays under documented
  public-key vs no-key rate limits; 429/503 use ``request_with_rate_limit_retries``.

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
from typing import Any, Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

# Import baseline checkpoint
from baseline_checkpoint import get_source_checkpoint, update_source_checkpoint

# Shared utilities
from collectors.collector_utils import (
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import MISPWriter
from config import (
    NVD_API_KEY,
    SECTOR_TIME_RANGES,
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_item,
    resolve_collection_limit,
)

# Import resilience utilities
from resilience import check_service_health, get_circuit_breaker, record_collection_failure, record_collection_success

logger = logging.getLogger(__name__)

# Configuration constants
NVD_REQUEST_TIMEOUT = 60  # seconds
NVD_CONNECT_TIMEOUT = 15  # seconds
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# NVD 2.0 API: pubStartDate and pubEndDate must be used together; each range is limited
# to 120 consecutive calendar days per request (NIST documented constraint).
NVD_MAX_PUBLISHED_DATE_RANGE_DAYS = 120


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_nvd_pub_iso(dt: datetime) -> str:
    """Format datetime as NVD published-date filter (UTC, Z suffix)."""
    dt = _ensure_utc(dt)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def clamp_nvd_published_range(
    pub_start: datetime, pub_end: datetime, max_days: int = NVD_MAX_PUBLISHED_DATE_RANGE_DAYS
) -> Tuple[datetime, datetime]:
    """
    NVD requires pubStartDate/pubEndDate together and caps the span (default 120 days).
    Anchor *pub_end* at "now" (or caller-supplied end); if the lookback exceeds *max_days*,
    move *pub_start* forward so the window is exactly at most *max_days*.
    """
    pub_start, pub_end = _ensure_utc(pub_start), _ensure_utc(pub_end)
    if pub_start >= pub_end:
        pub_start = pub_end - timedelta(days=1)
    max_span = timedelta(days=max_days)
    if (pub_end - pub_start) > max_span:
        pub_start = pub_end - max_span
    return pub_start, pub_end


def iter_nvd_published_windows(
    overall_start: datetime, overall_end: datetime, max_days: int = NVD_MAX_PUBLISHED_DATE_RANGE_DAYS
) -> Iterator[Tuple[datetime, datetime]]:
    """
    Cover [overall_start, overall_end] with contiguous windows of at most *max_days* each.
    Yields newest window first (pub_end toward "today"), then older chunks — NVD-compliant.
    """
    overall_start, overall_end = _ensure_utc(overall_start), _ensure_utc(overall_end)
    if overall_start >= overall_end:
        return
    seg_end = overall_end
    while seg_end > overall_start:
        seg_start = max(overall_start, seg_end - timedelta(days=max_days))
        yield (seg_start, seg_end)
        seg_end = seg_start


def configurations_to_zone_text(configurations: Optional[List[Any]]) -> str:
    """
    Flatten NVD CVE ``configurations`` into plain text for sector keyword scoring.

    ``json.dumps`` on the structure hides CPE tokens from ``\\b`` word-boundary patterns;
    we pull ``criteria`` strings plus vendor/product fields from CPE 2.3 URIs.
    """
    if not configurations:
        return ""
    parts: List[str] = []
    for cfg in configurations:
        if not isinstance(cfg, dict):
            continue
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for cpe in node.get("cpeMatch") or []:
                if not isinstance(cpe, dict):
                    continue
                crit = cpe.get("criteria")
                if not crit or not isinstance(crit, str):
                    continue
                parts.append(crit.replace("\\", " "))
                segs = crit.split(":")
                # cpe:2.3:part:vendor:product:version:...
                if len(segs) >= 6 and segs[0] == "cpe" and segs[1] == "2.3":
                    vendor, product = segs[3], segs[4]
                    for token in (vendor, product):
                        if token and token != "*" and token != "-":
                            parts.append(token.replace("_", " ").replace("\\", " "))
    return " ".join(parts)


# Circuit breaker for NVD (singleton)
NVD_CIRCUIT_BREAKER = get_circuit_breaker(
    "nvd",
    failure_threshold=3,
    recovery_timeout=3600,  # 1 hour
)


class NVDCollector:
    """
    NVD (National Vulnerability Database) Collector.

    Production-ready features:
    - Retry logic with exponential backoff
    - Circuit breaker pattern for extended outages
    - Health checks before collection
    - Prometheus metrics integration
    - Timeout handling
    - Comprehensive error logging
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = NVD_API_KEY
        self.tag = SOURCE_TAGS["nvd"]
        self.misp_writer = misp_writer or MISPWriter()
        self.source_name = "nvd"

        # Get circuit breaker for this collector
        self.circuit_breaker = NVD_CIRCUIT_BREAKER

    def health_check(self) -> Dict[str, Any]:
        """
        Check NVD API health.

        Returns:
            Dict with health status
        """
        try:
            start_time = time.time()
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.base_url,
                headers=headers,
                params={"resultsPerPage": 1},
                timeout=(NVD_CONNECT_TIMEOUT, NVD_REQUEST_TIMEOUT),
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
        Check if NVD service is available before collection.
        Uses circuit breaker state if available, otherwise does health check.

        Returns:
            True if service is available, False otherwise
        """
        # First check circuit breaker
        if not self.circuit_breaker.can_execute():
            logger.warning(f"NVD circuit breaker is {self.circuit_breaker.state.name} - skipping collection")
            return False

        # Then do health check
        return check_service_health(self.source_name, self.health_check)

    def detect_sectors(self, description: str, configurations: Optional[List[Any]] = None) -> List[str]:
        """Detect sectors from CVE description and NVD ``configurations`` (CPE criteria)."""
        cpe_text = configurations_to_zone_text(configurations)
        item: Dict[str, Any] = {"description": description or ""}
        if cpe_text.strip():
            item["comment"] = cpe_text
        return detect_zones_from_item(item)

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_cves(self, limit: Optional[int], baseline: bool = False) -> List[Dict]:
        """
        Fetch CVEs from NVD API with retry logic.

        NVD returns CVEs sorted ascending by ``published``; we page from ``startIndex`` toward
        the end of the filtered window to prefer the newest records. Uses ``resultsPerPage`` up
        to 2000 (NIST-recommended maximum per CVE 2.0 request) and increments ``startIndex`` until
        the desired count is reached — see https://nvd.nist.gov/developers/vulnerabilities and
        https://nvd.nist.gov/developers/api-workflows .

        Args:
            limit: Maximum number of CVEs to fetch (None → cap at 2000 newest in window)

        Returns:
            List of vulnerability dicts
        """
        logger.info("Fetching CVEs from NVD...")

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        # NVD requires date pairs together; **every** request span ≤ 120 days (NIST).
        # Incremental mode: use lastModStartDate/lastModEndDate to catch updated CVSS scores.
        # Baseline mode: use pubStartDate/pubEndDate for historical data.
        pub_end = _utc_now()
        _use_mod_dates = not baseline  # incremental uses modification dates
        if _use_mod_dates:
            # Incremental: fetch CVEs modified in the last N days (catches CVSS updates)
            _inc_days = int(os.environ.get("EDGEGUARD_NVD_INCREMENTAL_DAYS", "14"))
            desired_start = pub_end - timedelta(days=_inc_days)
            logger.info(f"NVD incremental: fetching CVEs modified in last {_inc_days} days")
        else:
            # Widest sector window for baseline
            months_range = max(SECTOR_TIME_RANGES.values())
            desired_start = pub_end - timedelta(days=months_range * 30)
        pub_start, pub_end = clamp_nvd_published_range(desired_start, pub_end)
        pub_start_iso = _to_nvd_pub_iso(pub_start)
        pub_end_iso = _to_nvd_pub_iso(pub_end)
        _date_key_start = "lastModStartDate" if _use_mod_dates else "pubStartDate"
        _date_key_end = "lastModEndDate" if _use_mod_dates else "pubEndDate"
        logger.info(
            f"NVD: Fetching CVEs ({_date_key_start}) {pub_start.strftime('%Y-%m-%d')} .. "
            f"{pub_end.strftime('%Y-%m-%d')} (≤{NVD_MAX_PUBLISHED_DATE_RANGE_DAYS}d API window)"
        )

        # Probe total count (NVD returns oldest-first; newest are at highest indices).
        params_count = {
            "resultsPerPage": 1,
            _date_key_start: pub_start_iso,
            _date_key_end: pub_end_iso,
        }
        total_results = 0
        try:
            response = request_with_rate_limit_retries(
                "GET",
                self.base_url,
                session=None,
                headers=headers,
                params=params_count,
                timeout=(NVD_CONNECT_TIMEOUT, NVD_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="NVD",
            )
            if response.status_code != 200:
                raise requests.exceptions.HTTPError(f"NVD API error: {response.status_code}")

            data = response.json()
            total_results = int(data.get("totalResults", 0) or 0)
            logger.info(f"NVD: Total CVEs in window: {total_results}")

        except Exception as e:
            logger.warning(f"Could not get total results: {e}, using default approach")
            total_results = 0

        if total_results <= 0:
            return []

        # How many rows to pull from the *newest* end of the window (published ascending).
        max_newest_cap = 15000
        if limit is not None:
            target_count = min(int(limit), total_results)
        else:
            target_count = min(max_newest_cap, total_results)

        start_index = max(0, total_results - target_count)
        # NIST CVE API: resultsPerPage default/max 2000 — use that for fewer round trips.
        page_cap = 2000
        batch_sleep = 0.7 if self.api_key else 6.5

        accumulated: List[Dict] = []
        idx = start_index
        pages = 0
        while idx < total_results and len(accumulated) < target_count:
            remaining = target_count - len(accumulated)
            results_per_page = min(page_cap, total_results - idx, remaining)
            if results_per_page <= 0:
                break

            params = {
                "resultsPerPage": results_per_page,
                "startIndex": idx,
                _date_key_start: pub_start_iso,
                _date_key_end: pub_end_iso,
            }
            if pages == 0:
                logger.info(
                    f"NVD: Fetching newest CVEs from startIndex {idx} (target {target_count} of {total_results})"
                )

            response = request_with_rate_limit_retries(
                "GET",
                self.base_url,
                session=None,
                headers=headers,
                params=params,
                timeout=(NVD_CONNECT_TIMEOUT, NVD_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="NVD",
            )

            if response.status_code != 200:
                raise requests.exceptions.HTTPError(f"NVD API error: {response.status_code}")

            data = response.json()
            batch = data.get("vulnerabilities", []) or []
            if not batch:
                logger.warning(f"NVD: Empty batch at startIndex {idx}; stopping incremental fetch")
                break

            accumulated.extend(batch)
            idx += len(batch)
            pages += 1

            if len(accumulated) >= target_count:
                break
            if idx < total_results and len(accumulated) < target_count:
                time.sleep(batch_sleep)

        if len(accumulated) > target_count:
            accumulated = accumulated[:target_count]

        logger.info(f"[FETCH] NVD: Fetched {len(accumulated)} recent CVEs ({pages} page(s))")
        return accumulated

    def _fetch_cves_batch(
        self,
        pub_start_iso: Optional[str] = None,
        pub_end_iso: Optional[str] = None,
        start_index: int = 0,
        limit: int = 2000,
    ) -> List[Dict]:
        """
        Fetch a batch of CVEs from NVD API.

        Args:
            pub_start_iso: Publication window start (UTC ISO, NVD format)
            pub_end_iso: Publication window end (UTC ISO); required with pub_start_iso
            start_index: Starting index for pagination
            limit: Number of CVEs to fetch

        Returns:
            List of vulnerability dicts
        """
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        params = {"resultsPerPage": min(limit, 2000), "startIndex": start_index}

        if pub_start_iso or pub_end_iso:
            if not (pub_start_iso and pub_end_iso):
                logger.warning(
                    "NVD: pubStartDate and pubEndDate must be sent together; omitting date filter for this batch."
                )
            else:
                params["pubStartDate"] = pub_start_iso
                params["pubEndDate"] = pub_end_iso

        try:
            response = request_with_rate_limit_retries(
                "GET",
                self.base_url,
                session=None,
                headers=headers,
                params=params,
                timeout=(NVD_CONNECT_TIMEOUT, NVD_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                max_rate_limit_retries=3,
                fallback_delay_sec=60.0,
                retry_on_403=False,
                context="NVD",
            )

            if response.status_code != 200:
                logger.warning(f"NVD API error: {response.status_code} (after rate-limit retries where applicable)")
                return []

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            return vulnerabilities

        except Exception as e:
            logger.warning(f"NVD batch fetch error: {e}")
            return []

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Dict[str, Any]:
        """
        Collect CVEs from NVD and optionally push to MISP.

        Args:
            limit: Maximum number of CVEs to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, collect historical data over ``baseline_days`` using multiple
                NVD requests (each ``pubStartDate``/``pubEndDate`` window ≤ 120 days).
            baseline_days: How many days back to collect in baseline mode

        Returns:
            Dict with status and counts if push_to_misp=True, else list of processed items
        """
        limit = resolve_collection_limit(limit, "nvd", baseline=baseline)

        # Check if service is available before attempting collection
        if not self.check_service_available():
            error_msg = f"NVD service unavailable (circuit breaker: {self.circuit_breaker.state.name})"
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)

        try:
            if baseline:
                logger.info(f"Baseline mode: Collecting NVD CVEs from the last {baseline_days} days...")
                all_cves: List[Dict] = []
                seen_cve_ids: set = set()

                pub_overall_end = _utc_now()
                pub_overall_start = pub_overall_end - timedelta(days=baseline_days)
                windows = list(iter_nvd_published_windows(pub_overall_start, pub_overall_end))
                logger.info(
                    f"  Date filter: {pub_overall_start.strftime('%Y-%m-%d')} .. "
                    f"{pub_overall_end.strftime('%Y-%m-%d')} "
                    f"({len(windows)} API window(s), max {NVD_MAX_PUBLISHED_DATE_RANGE_DAYS}d each)"
                )

                # Rate limit: NVD allows 50 req/30 sec with an API key (~0.6 s/req),
                # or 5 req/30 sec without (~6 s/req).  Sleep conservatively per batch.
                batch_sleep = 0.7 if self.api_key else 6.5
                batch_size = 2000

                checkpoint = get_source_checkpoint("nvd")
                start_wi = 0
                resume_index = 0
                if not checkpoint.get("completed") and checkpoint.get("nvd_window_idx") is not None:
                    start_wi = int(checkpoint["nvd_window_idx"])
                    resume_index = int(checkpoint.get("nvd_start_index", 0))
                    if start_wi >= len(windows):
                        start_wi, resume_index = 0, 0
                    else:
                        logger.info(
                            f"  Resuming baseline at window {start_wi + 1}/{len(windows)}, startIndex={resume_index}"
                        )

                for wi in range(start_wi, len(windows)):
                    w_start, w_end = windows[wi]
                    pub_start_iso = _to_nvd_pub_iso(w_start)
                    pub_end_iso = _to_nvd_pub_iso(w_end)
                    idx = resume_index if wi == start_wi else 0
                    resume_index = 0
                    consecutive_empty = 0

                    while consecutive_empty < 3:
                        cves = self._fetch_cves_batch(
                            pub_start_iso=pub_start_iso,
                            pub_end_iso=pub_end_iso,
                            start_index=idx,
                            limit=batch_size,
                        )
                        if not cves:
                            consecutive_empty += 1
                            if consecutive_empty >= 3:
                                break
                            continue
                        consecutive_empty = 0
                        for v in cves:
                            cve_block = v.get("cve") or {}
                            cid = cve_block.get("id") or ""
                            if cid:
                                if cid in seen_cve_ids:
                                    continue
                                seen_cve_ids.add(cid)
                            all_cves.append(v)
                        logger.info(
                            f"  Window {wi + 1}/{len(windows)} @ startIndex {idx}: {len(cves)} CVEs "
                            f"(unique CVE rows: {len(all_cves)})"
                        )
                        next_idx = idx + len(cves)
                        update_source_checkpoint(
                            "nvd",
                            page=wi * 5000 + (idx // batch_size) + 1,
                            items_collected=len(all_cves),
                            extra={"nvd_window_idx": wi, "nvd_start_index": next_idx},
                        )
                        if len(cves) < batch_size:
                            break
                        idx = next_idx
                        time.sleep(batch_sleep)

                    update_source_checkpoint(
                        "nvd",
                        items_collected=len(all_cves),
                        extra={"nvd_window_idx": wi + 1, "nvd_start_index": 0},
                    )

                vulnerabilities = all_cves if limit is None else all_cves[:limit]
                logger.info(f"  Baseline complete: {len(vulnerabilities)} CVEs collected")
                update_source_checkpoint(
                    "nvd",
                    page=len(windows) * 5000,
                    items_collected=len(vulnerabilities),
                    completed=True,
                )
            else:
                # Normal mode: fetch recent only
                vulnerabilities = self._fetch_cves(limit, baseline=False)

            # Record success in circuit breaker
            self.circuit_breaker.record_success()

            # Process CVEs with date filtering
            processed = []
            skipped_old = 0

            to_process = vulnerabilities if limit is None else vulnerabilities[:limit]
            for vuln in to_process:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Get description
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Get CVSS score
                cvss_score = 0.0
                severity = "UNKNOWN"
                _cvss_vector = ""
                metrics = cve_data.get("metrics", {})

                if metrics.get("cvssMetricV31"):
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    _cvss_vector = cvss_data.get("vectorString", "")
                elif metrics.get("cvssMetricV30"):
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")
                    _cvss_vector = cvss_data.get("vectorString", "")
                elif metrics.get("cvssMetricV2"):
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")

                # Get attack vector and full CVSS component data
                attack_vector = "UNKNOWN"
                cvss_v31_data = {}
                cvss_v30_data = {}
                cvss_v2_data = {}
                result_impacts = []

                # CVSSv4.0 — available from NVD since 2024 (ResilMesh schema: CVSSv40 node + HAS_CVSS_v40 rel)
                cvss_v40_data = None
                if metrics.get("cvssMetricV40"):
                    m40 = metrics["cvssMetricV40"][0]
                    d40 = m40.get("cvssData", {})
                    cvss_v40_data = {
                        "vector_string": d40.get("vectorString", ""),
                        "base_score": d40.get("baseScore", 0.0),
                        "base_severity": d40.get("baseSeverity", ""),
                    }

                if metrics.get("cvssMetricV31"):
                    m31 = metrics["cvssMetricV31"][0]
                    d31 = m31.get("cvssData", {})
                    if "AV:" in d31.get("vectorString", ""):
                        for part in d31["vectorString"].split("/"):
                            if part.startswith("AV:"):
                                attack_vector = part.split(":")[1]
                    # Full v3.1 payload for CVSS sub-node (ResilMesh schema)
                    cvss_v31_data = {
                        "vector_string": d31.get("vectorString", ""),
                        "attack_vector": d31.get("attackVector", ""),
                        "attack_complexity": d31.get("attackComplexity", ""),
                        "privileges_required": d31.get("privilegesRequired", ""),
                        "user_interaction": d31.get("userInteraction", ""),
                        "scope": d31.get("scope", ""),
                        "confidentiality_impact": d31.get("confidentialityImpact", ""),
                        "integrity_impact": d31.get("integrityImpact", ""),
                        "availability_impact": d31.get("availabilityImpact", ""),
                        "base_score": d31.get("baseScore", 0.0),
                        "base_severity": d31.get("baseSeverity", ""),
                        "impact_score": m31.get("impactScore", 0.0),
                        "exploitability_score": m31.get("exploitabilityScore", 0.0),
                    }
                    result_impacts = [
                        d31.get("confidentialityImpact", ""),
                        d31.get("integrityImpact", ""),
                        d31.get("availabilityImpact", ""),
                    ]
                elif metrics.get("cvssMetricV30"):
                    m30 = metrics["cvssMetricV30"][0]
                    d30 = m30.get("cvssData", {})
                    if "AV:" in d30.get("vectorString", ""):
                        for part in d30["vectorString"].split("/"):
                            if part.startswith("AV:"):
                                attack_vector = part.split(":")[1]
                    cvss_v30_data = {
                        "vector_string": d30.get("vectorString", ""),
                        "attack_vector": d30.get("attackVector", ""),
                        "attack_complexity": d30.get("attackComplexity", ""),
                        "privileges_required": d30.get("privilegesRequired", ""),
                        "user_interaction": d30.get("userInteraction", ""),
                        "scope": d30.get("scope", ""),
                        "confidentiality_impact": d30.get("confidentialityImpact", ""),
                        "integrity_impact": d30.get("integrityImpact", ""),
                        "availability_impact": d30.get("availabilityImpact", ""),
                        "base_score": d30.get("baseScore", 0.0),
                        "base_severity": d30.get("baseSeverity", ""),
                        "impact_score": m30.get("impactScore", 0.0),
                        "exploitability_score": m30.get("exploitabilityScore", 0.0),
                    }
                    result_impacts = [
                        d30.get("confidentialityImpact", ""),
                        d30.get("integrityImpact", ""),
                        d30.get("availabilityImpact", ""),
                    ]
                elif metrics.get("cvssMetricV2"):
                    m2 = metrics["cvssMetricV2"][0]
                    d2 = m2.get("cvssData", {})
                    cvss_v2_data = {
                        "vector_string": d2.get("vectorString", ""),
                        "access_vector": d2.get("accessVector", ""),
                        "access_complexity": d2.get("accessComplexity", ""),
                        "authentication": d2.get("authentication", ""),
                        "confidentiality_impact": d2.get("confidentialityImpact", ""),
                        "integrity_impact": d2.get("integrityImpact", ""),
                        "availability_impact": d2.get("availabilityImpact", ""),
                        "base_score": d2.get("baseScore", 0.0),
                        "base_severity": d2.get("baseSeverity", ""),
                        "impact_score": m2.get("impactScore", 0.0),
                        "exploitability_score": m2.get("exploitabilityScore", 0.0),
                        "obtain_all_privilege": m2.get("obtainAllPrivilege", False),
                        "obtain_user_privilege": m2.get("obtainUserPrivilege", False),
                        "obtain_other_privilege": m2.get("obtainOtherPrivilege", False),
                        "user_interaction_required": m2.get("userInteractionRequired", False),
                        "ac_insuf_info": m2.get("acInsufInfo", False),
                    }

                # CWE identifiers (ResilMesh: cwe LIST OF STRING)
                cwe_list = []
                for weakness in cve_data.get("weaknesses", []):
                    for wd in weakness.get("description", []):
                        val = wd.get("value", "")
                        if val and val not in cwe_list:
                            cwe_list.append(val)

                # Reference tags (ResilMesh: ref_tags LIST OF STRING)
                ref_tags_set = set()
                reference_urls = []
                for ref in cve_data.get("references", []):
                    for t in ref.get("tags", []):
                        ref_tags_set.add(t)
                    ref_url = ref.get("url", "")
                    if ref_url:
                        reference_urls.append(ref_url)
                ref_tags = list(ref_tags_set)

                # CISA Known Exploited Vulnerabilities (KEV) fields — strongest
                # signal of active exploitation in the wild.
                cisa_exploit_add = cve_data.get("cisaExploitAdd", "")
                cisa_action_due = cve_data.get("cisaActionDue", "")
                cisa_required_action = cve_data.get("cisaRequiredAction", "")
                cisa_vulnerability_name = cve_data.get("cisaVulnerabilityName", "")

                # Get affected products and CPE types
                configurations = cve_data.get("configurations", [])
                affected_products = []
                cpe_type_set = set()
                version_constraints = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe_match in node.get("cpeMatch", []):
                            criteria = cpe_match.get("criteria", "")
                            if criteria:
                                affected_products.append(criteria)
                                # cpe:2.3:TYPE:... → extract type (a=application, o=os, h=hardware)
                                parts = criteria.split(":")
                                if len(parts) > 2:
                                    cpe_type_set.add(parts[2])
                                # Version range extraction
                                if len(version_constraints) < 10:
                                    version_constraints.append(
                                        {
                                            "cpe": criteria,
                                            "version_start": cpe_match.get("versionStartIncluding", ""),
                                            "version_end": cpe_match.get(
                                                "versionEndExcluding", cpe_match.get("versionEndIncluding", "")
                                            ),
                                            "vulnerable": cpe_match.get("vulnerable", True),
                                        }
                                    )

                # Detect ALL sectors
                sectors = self.detect_sectors(description, configurations)

                # Filter by sector date range: use widest window among matched zones (max).
                # min() + global=12 dropped CVEs tagged only global in the 12–24 month band.
                published_str = cve_data.get("published", "")
                pub_date = None
                if published_str:
                    try:
                        pub_date = datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        pub_date = None

                # Only filter if we have a valid pub_date
                if pub_date is not None:
                    try:
                        months_range = max(SECTOR_TIME_RANGES.get(s, SECTOR_TIME_RANGES["global"]) for s in sectors)
                        cutoff = datetime.now(timezone.utc) - timedelta(days=months_range * 30)

                        if pub_date < cutoff:
                            skipped_old += 1
                            continue
                    except (ValueError, TypeError, AttributeError):
                        pass

                # ResilMesh schema: Vulnerability.status is LIST OF STRING
                vuln_status_raw = cve_data.get("vulnStatus", "")
                vuln_status = ["rejected"] if vuln_status_raw == "Rejected" else ["active"]

                # One entry per CVE — property names aligned to ResilMesh schema
                processed.append(
                    {
                        "type": "vulnerability",
                        "cve_id": cve_id,
                        "description": description[:1000],
                        "status": vuln_status,
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        # ResilMesh-compatible timestamp property names
                        "published": published_str,
                        "last_modified": cve_data.get("lastModified", datetime.now(timezone.utc).isoformat()),
                        # EdgeGuard internal timestamps (kept for backward compat)
                        "first_seen": published_str or datetime.now(timezone.utc).isoformat(),
                        "last_updated": cve_data.get("lastModified", datetime.now(timezone.utc).isoformat()),
                        "confidence_score": 0.9 if cisa_exploit_add else 0.6,
                        "severity": severity.upper(),
                        "cvss_score": cvss_score,
                        "attack_vector": attack_vector,
                        "affected_products": list(set(affected_products))[:10],
                        # ResilMesh-compatible fields
                        "cwe": cwe_list,
                        "ref_tags": ref_tags,
                        "reference_urls": reference_urls[:10],
                        "cpe_type": list(cpe_type_set),
                        "result_impacts": [i for i in result_impacts if i],
                        # Full CVSS payloads for CVSS sub-node creation in Neo4j
                        "cvss_v40_data": cvss_v40_data if cvss_v40_data else None,
                        "cvss_v31_data": cvss_v31_data if cvss_v31_data else None,
                        "cvss_v30_data": cvss_v30_data if cvss_v30_data else None,
                        "cvss_v2_data": cvss_v2_data if cvss_v2_data else None,
                        # CISA KEV — exploitability intelligence
                        "cisa_exploit_add": cisa_exploit_add,
                        "cisa_action_due": cisa_action_due,
                        "cisa_required_action": cisa_required_action,
                        "cisa_vulnerability_name": cisa_vulnerability_name,
                        "version_constraints": version_constraints,
                    }
                )

            logger.info(f"[OK] NVD: Processed {len(processed)} CVEs")
            if skipped_old > 0:
                logger.info(f"⏭️ NVD: Skipped {skipped_old} CVEs outside sector time range")

            # Push to MISP if requested
            if push_to_misp:
                record_collection_success(self.source_name)
                if not processed:
                    st = make_status("nvd", True, count=0, failed=0)
                    st["circuit_breaker_state"] = self.circuit_breaker.state.name
                    return st

                success, failed = self.misp_writer.push_items(processed)

                if success > 0:
                    logger.info(f"[OK] NVD: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] NVD: Failed to push {failed} items to MISP")

                st = status_after_misp_push("nvd", len(processed), success, failed)
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            else:
                record_collection_success(self.source_name)
                return processed

        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"NVD timeout: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"NVD connection error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
        except requests.exceptions.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"NVD: auth/access denied — skipping (optional; check NVD_API_KEY if using one): {e}")
                self.circuit_breaker.record_success()
                st = make_skipped_optional_source(
                    "nvd",
                    skip_reason=str(e),
                    skip_reason_class="nvd_auth_denied",
                )
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            error_msg = f"HTTP error: {e}"
            logger.error(f"NVD HTTP error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"NVD collection error: {type(e).__name__}: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Return standardized status dict."""
        result = make_status("nvd", success, count=count, failed=failed, error=error)
        result["circuit_breaker_state"] = self.circuit_breaker.state.name
        return result


def test_nvd() -> Dict[str, Any]:
    """Test NVD collection and MISP push"""
    collector = NVDCollector()
    result = collector.collect(limit=500)  # Respect NIST rate limits (see batch_sleep in collect)
    print("\n📥 NVD Test Result:")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    test_nvd()
