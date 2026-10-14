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
  ≤120-day windows in baseline mode, not one wide request. ``lastModStartDate`` /
  ``lastModEndDate`` (incremental runs) have the same limit (``iter_nvd_lastmod_spans``).
- Request spacing: ``batch_sleep`` (~0.7s with API key, ~6.5s without) stays under documented
  public-key vs no-key rate limits; 429/503 use ``request_with_rate_limit_retries``.

**Incremental runs (2026-10):** every CVE NVD modified since a stored ``lastModified`` cursor is
read; CVEs MISP does not hold yet are added, and the MISP attribute of a CVE it holds is edited
when NVD's data for it changed (``_collect_incremental``).

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
import math
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

# Import baseline checkpoint
from baseline_checkpoint import (
    get_source_checkpoint,
    get_source_incremental,
    update_source_checkpoint,
    update_source_incremental,
)
from baseline_config import resolve_baseline_days

# Shared utilities
from collectors.collector_utils import (
    TransientServerError,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    status_after_misp_push,
)

# Import MISP writer
from collectors.misp_writer import (
    EDITS_PER_THROTTLE,
    MispLookupError,
    MispTransientError,
    MISPWriter,
    misp_batch_throttle_seconds,
)
from config import (
    NVD_API_KEY,
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_item,
    nvd_baseline_kev_sweep,
    nvd_cursor_overlap_seconds,
    nvd_extra_cve_ids,
    nvd_incremental_days,
    nvd_max_per_run,
    nvd_update_existing,
    resolve_collection_limit,
)
from cvss_selection import select_cvss

# Import resilience utilities
from resilience import check_service_health, get_circuit_breaker, record_collection_failure, record_collection_success
from source_truthful_timestamps import coerce_iso

logger = logging.getLogger(__name__)

# Configuration constants
NVD_REQUEST_TIMEOUT = 60  # seconds
NVD_CONNECT_TIMEOUT = 15  # seconds

# NVD 2.0 API: pubStartDate and pubEndDate must be used together; each range is limited
# to 120 consecutive calendar days per request (NIST documented constraint).
NVD_MAX_PUBLISHED_DATE_RANGE_DAYS = 120

# 2026-10: the baseline's fetch by id (EDGEGUARD_NVD_EXTRA_CVE_IDS) stops after this many failed
# requests in a row — each failure has already spent its rate-limit back-off, so a long list
# during an NVD outage would otherwise hold the baseline (and its lock) for hours.
NVD_EXTRA_MAX_CONSECUTIVE_FAILURES = 3

# 2026-10: incremental runs keep a lastModified cursor in ``checkpoints[nvd].incremental``: the end
# of the last window that was read completely and written to MISP without a failure.
NVD_CURSOR_KEY = "nvd_last_modified_cursor"
# Records per NVD request (the NIST maximum for the CVE API).
NVD_PAGE_SIZE = 2000
# Requests for one page of a lastMod span before an incremental run fails (each request has
# already spent its rate-limit retries).
NVD_INCREMENTAL_PAGE_ATTEMPTS = 3
# A lastMod window that holds more records than one answer is split into time slices of about
# this many records, each read with one request (``NVDCollector._iter_lastmod_slices``).
NVD_SLICE_TARGET = 1500
# A slice narrower than this (in seconds) is paged instead of split further.
NVD_MIN_SLICE_SECONDS = 2


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


def _parse_nvd_time(value: Any) -> Optional[datetime]:
    """A timestamp as an aware UTC datetime, or ``None`` when empty or unparseable.

    NVD sends its timestamps without a zone (``"2021-12-10T10:15:09.143"``, UTC); a stored cursor
    and MISP's ``first_seen`` / ``last_seen`` carry one. ``coerce_iso`` reads both forms.
    """
    iso = coerce_iso(value)
    if not iso:
        return None
    try:
        return _ensure_utc(datetime.fromisoformat(iso))
    except ValueError:
        return None


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _record_last_modified(vuln: Dict) -> datetime:
    """``lastModified`` of an NVD record (the epoch when it has none, so it sorts first)."""
    return _parse_nvd_time((vuln.get("cve") or {}).get("lastModified")) or _EPOCH


def _record_order(vuln: Dict) -> Tuple[datetime, str]:
    """Sort key of an incremental run: modification time, then CVE id."""
    return _record_last_modified(vuln), str((vuln.get("cve") or {}).get("id") or "")


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


def iter_nvd_lastmod_spans(
    start: datetime, end: datetime, max_days: int = NVD_MAX_PUBLISHED_DATE_RANGE_DAYS
) -> List[Tuple[datetime, datetime]]:
    """Cover [start, end] with contiguous spans of at most *max_days*, oldest first.

    ``lastModStartDate`` / ``lastModEndDate`` share the 120-day limit of the publication dates.
    """
    return list(reversed(list(iter_nvd_published_windows(start, end, max_days))))


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


class NvdBatchFetchError(Exception):
    """PR-N17 (2026-04-22 pre-baseline collection audit, BLOCK):
    raised by ``_fetch_cves_batch`` when an HTTP / rate-limit / JSON-
    parse failure occurs AFTER the rate-limit retry layer exhausted.

    The baseline loop MUST catch this and abort the current window
    WITHOUT advancing the checkpoint — distinguishing "NVD returned
    an empty result, this window is done" (legit end-of-window, the
    caller's ``consecutive_empty`` counter handles it) from "fetch
    errored, do not mark the window complete" (data at this startIndex
    never arrived).

    Pre-PR-N17 both cases returned ``[]`` and the baseline advanced
    past unfetched data → silent loss of entire 120-day CVE windows.
    """

    pass


class NvdIncrementalUnavailable(NvdBatchFetchError, TransientServerError):
    """NVD did not serve an incremental run's window after the retries (2026-10).

    Transient (``TransientServerError``): the DAG task is skipped with an alert rather than failing
    as a hard error, and since nothing was written and the cursor stays, the next run reads the
    same changes. A baseline still raises plain ``NvdBatchFetchError``: a partial baseline must fail.
    """


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
        self._api_key_rejected = False  # set by health_check() when NVD answers "Invalid apiKey."
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
        self._api_key_rejected = False
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
                # NVD answers a key it does not know with HTTP 404 and the header
                # ``message: Invalid apiKey.`` — the service is up, the key is wrong.
                message = (response.headers.get("message") or "").strip()[:80]
                self._api_key_rejected = bool(
                    self.api_key and response.status_code == 404 and "apikey" in message.lower()
                )
                return {
                    "healthy": False,
                    "error": f"HTTP {response.status_code}" + (f" ({message})" if message else ""),
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

    @staticmethod
    def _keep_first(records: Dict[str, Dict], batch: List[Dict]) -> None:
        """Add NVD records to *records* by CVE id. A record read twice in one run is the same version
        (a change after the window's end moves it out of the window), so the first copy is kept."""
        for vuln in batch:
            cve_id = ((vuln.get("cve") or {}).get("id") or "").upper()
            if cve_id:
                records.setdefault(cve_id, vuln)

    def _fetch_lastmod_page(self, start_index: int, count: int, lastmod_params: Dict[str, str]) -> Dict[str, Any]:
        """One page of a lastMod span. A page NVD does not serve after its rate-limit retries is
        requested again (``NVD_INCREMENTAL_PAGE_ATTEMPTS`` in all) before the run fails."""
        for attempt in range(1, NVD_INCREMENTAL_PAGE_ATTEMPTS + 1):
            try:
                return self._fetch_cves_page(start_index=start_index, limit=count, extra_params=lastmod_params)
            except NvdBatchFetchError as e:
                if attempt == NVD_INCREMENTAL_PAGE_ATTEMPTS:
                    raise
                logger.warning(
                    "NVD incremental: page at startIndex %d failed (%s) — attempt %d of %d, retrying",
                    start_index,
                    e,
                    attempt,
                    NVD_INCREMENTAL_PAGE_ATTEMPTS,
                )
                time.sleep(30.0 * attempt)
        raise NvdBatchFetchError("unreachable")  # pragma: no cover - the loop returns or raises

    def _read_lastmod_span(
        self, span_start: datetime, span_end: datetime, batch_sleep: float
    ) -> Tuple[List[Dict], bool]:
        """Every record NVD lists as modified in [span_start, span_end] by paging, and whether the
        read is complete. Used only for a slice too narrow to split (``_iter_lastmod_slices``).

        NVD orders the result by publication date and evaluates it again for every page. A record
        modified again after ``span_end`` while the span is paged leaves it, and every record listed
        after it moves down one place, so a plain ``startIndex`` walk skips one record at the next
        page boundary. When ``totalResults`` drops between two pages, the stretch below the current
        index is requested once more. A further drop during that request, or a page that ends
        early, marks the span incomplete; the run then keeps its cursor.
        """
        params = {"lastModStartDate": _to_nvd_pub_iso(span_start), "lastModEndDate": _to_nvd_pub_iso(span_end)}
        records: Dict[str, Dict] = {}
        complete = True
        idx = 0
        total: Optional[int] = None
        while True:
            page = self._fetch_lastmod_page(idx, NVD_PAGE_SIZE, params)
            batch, page_total = page["vulnerabilities"], page["totalResults"]
            if total is not None and page_total < total and idx > 0:
                moved = total - page_total
                if moved > NVD_PAGE_SIZE:
                    complete = False  # more than one request can re-read; the next run reads the span again
                gap_start = max(0, idx - min(moved, NVD_PAGE_SIZE))
                logger.info(
                    "NVD incremental: %d record(s) left the window while it was read — re-reading startIndex %d..%d",
                    moved,
                    gap_start,
                    idx,
                )
                time.sleep(batch_sleep)
                gap = self._fetch_lastmod_page(gap_start, idx - gap_start, params)
                self._keep_first(records, gap["vulnerabilities"])
                if gap["totalResults"] < page_total:
                    complete = False
                    page_total = gap["totalResults"]
            self._keep_first(records, batch)
            idx += len(batch)
            total = page_total
            if not batch:
                if idx < total:
                    complete = False
                break
            if idx >= total:
                break
            time.sleep(batch_sleep)
        return list(records.values()), complete

    def _iter_lastmod_slices(
        self, start: datetime, end: datetime, batch_sleep: float
    ) -> Iterator[Tuple[List[Dict], bool]]:
        """The records NVD lists as modified in [start, end], one time slice at a time, oldest first;
        with each slice, whether its read is complete.

        Each slice is read with one request. NVD evaluates the query again for every request, so
        when a window is paged, a record modified again meanwhile leaves the result and the records
        behind it move down past a page boundary (75 of 19,520 records left a 14-day window while
        it was paged on 2026-10-14). One answer has no page boundary: a record modified again
        during the run only moves after ``end``, and the next run reads it. A window whose
        ``totalResults`` exceeds one answer (``NVD_PAGE_SIZE``) is therefore split by time into
        slices of about ``NVD_SLICE_TARGET`` records; spans never exceed 120 days (NVD's limit for
        ``lastModStartDate`` / ``lastModEndDate`` as for the publication dates). A slice narrower than
        ``NVD_MIN_SLICE_SECONDS`` that still holds more than one answer is paged
        (``_read_lastmod_span``). Adjacent slices share their boundary second, so a record can come
        twice; callers keep the first.
        """
        pending = list(reversed(iter_nvd_lastmod_spans(start, end)))
        requests_made = 0
        while pending:
            slice_start, slice_end = pending.pop()
            if requests_made:
                time.sleep(batch_sleep)
            requests_made += 1
            params = {"lastModStartDate": _to_nvd_pub_iso(slice_start), "lastModEndDate": _to_nvd_pub_iso(slice_end)}
            page = self._fetch_lastmod_page(0, NVD_PAGE_SIZE, params)
            batch, total = page["vulnerabilities"], page["totalResults"]
            if total <= len(batch):
                yield batch, True
                continue
            if len(batch) < NVD_PAGE_SIZE:
                # NVD counted more records than it returned although the answer had room for them.
                # Splitting would not help (an empty answer that counts records would split the slice
                # into thousands of requests); the slice is read as incomplete and the cursor stays.
                logger.warning(
                    "NVD incremental: NVD counted %d records but returned %d for %s .. %s — slice incomplete",
                    total,
                    len(batch),
                    params["lastModStartDate"],
                    params["lastModEndDate"],
                )
                yield batch, False
                continue
            seconds = (slice_end - slice_start).total_seconds()
            parts = min(max(2, math.ceil(total / NVD_SLICE_TARGET)), int(seconds // NVD_MIN_SLICE_SECONDS))
            if parts < 2:
                logger.warning(
                    "NVD incremental: %d records modified within %.0f s (%s) — paging that slice",
                    total,
                    seconds,
                    params["lastModStartDate"],
                )
                time.sleep(batch_sleep)
                requests_made += 1
                yield self._read_lastmod_span(slice_start, slice_end, batch_sleep)
                continue
            step = (slice_end - slice_start) / parts
            bounds = [slice_start + step * i for i in range(parts)] + [slice_end]
            pending.extend(reversed(list(zip(bounds, bounds[1:], strict=False))))

    def _fetch_modified_cves(self, start: datetime, end: datetime) -> Tuple[List[Dict], bool]:
        """Every CVE NVD modified in [start, end], oldest modification first, and whether the read is
        complete (``_iter_lastmod_slices``)."""
        batch_sleep = 0.7 if self.api_key else 6.5
        records: Dict[str, Dict] = {}
        complete = True
        for batch, slice_complete in self._iter_lastmod_slices(start, end, batch_sleep):
            self._keep_first(records, batch)
            complete = complete and slice_complete
        ordered = sorted(records.values(), key=_record_order)
        logger.info(
            "[FETCH] NVD: %d CVE(s) modified %s .. %s%s",
            len(ordered),
            _to_nvd_pub_iso(start),
            _to_nvd_pub_iso(end),
            "" if complete else " (read incomplete)",
        )
        return ordered, complete

    def _fetch_cves_batch(
        self,
        pub_start_iso: Optional[str] = None,
        pub_end_iso: Optional[str] = None,
        start_index: int = 0,
        limit: int = 2000,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> List[Dict]:
        """
        Fetch a batch of CVEs from NVD API.

        ``extra_params`` adds NVD filters that need no date range (2026-10): ``{"hasKev": ""}``
        (every CVE on CISA's KEV list) or ``{"cveId": "CVE-…"}`` (one CVE).

        Args:
            pub_start_iso: Publication window start (UTC ISO, NVD format)
            pub_end_iso: Publication window end (UTC ISO); required with pub_start_iso
            start_index: Starting index for pagination
            limit: Number of CVEs to fetch

        Returns:
            List of vulnerability dicts
        """
        return self._fetch_cves_page(pub_start_iso, pub_end_iso, start_index, limit, extra_params)["vulnerabilities"]

    def _fetch_cves_page(
        self,
        pub_start_iso: Optional[str] = None,
        pub_end_iso: Optional[str] = None,
        start_index: int = 0,
        limit: int = 2000,
        extra_params: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """One NVD response, validated: ``{"vulnerabilities": [...], "totalResults": int}``.

        Same request and error semantics as ``_fetch_cves_batch``, which returns only the list;
        incremental runs also need ``totalResults`` of every page (2026-10, ``_read_lastmod_span``).
        Raises ``NvdBatchFetchError`` when NVD does not answer with a usable page.
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
        if extra_params:
            params.update(extra_params)

        # PR-N17 Fix #1 (BLOCK, 2026-04-22 pre-baseline collection audit):
        # Pre-PR-N17 this method returned ``[]`` on ANY exception, and
        # the baseline caller treated 3 consecutive ``[]`` as "window
        # done" → advanced the checkpoint PAST data that was never
        # fetched. A single DNS flap / NVD 502 cluster / CPU-starved
        # worker silently lost a 120-day window.
        #
        # Fix: distinguish the two failure modes.
        #   - API returned 200 with ``vulnerabilities: []`` → legit empty.
        #     Return ``[]`` (caller may increment consecutive_empty).
        #   - API returned non-200 AFTER rate-limit retries → raise
        #     NvdBatchFetchError so caller aborts the window.
        #   - Exception inside the HTTP call → raise NvdBatchFetchError.
        # The caller MUST catch NvdBatchFetchError and abort the
        # window (not advance checkpoint). See the baseline loop.
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
        except Exception as e:
            # Transient raised after the rate-limit-retry layer exhausted.
            # Propagate so the caller knows NOT to advance checkpoint.
            logger.error("[NVD-BATCH-FETCH-ERROR] exception: %s: %s", type(e).__name__, e)
            raise NvdBatchFetchError(f"NVD fetch exception: {type(e).__name__}: {e}") from e

        if response.status_code != 200:
            # Non-200 post-retry — the window is NOT complete; raise so
            # the caller aborts + preserves checkpoint at the current
            # (wi, idx) instead of advancing past unfetched data.
            logger.error(
                "[NVD-BATCH-FETCH-ERROR] status_code=%d after rate-limit retries",
                response.status_code,
            )
            raise NvdBatchFetchError(f"NVD returned {response.status_code} after retries")

        try:
            data = response.json()
        except Exception as e:
            # Malformed JSON response — could be maintenance page /
            # error HTML / truncated body. Treat as transient (caller
            # aborts window).
            logger.error("[NVD-BATCH-FETCH-ERROR] JSON parse: %s", e)
            raise NvdBatchFetchError(f"NVD response not JSON: {e}") from e

        # PR-N17 follow-up (cursor-bugbot 2026-04-22 #3): NVD can
        # return JSON that's valid but not the expected dict shape
        # (maintenance page returning a JSON string / array / null).
        # Pre-fix, ``data.get("vulnerabilities", [])`` on a non-dict
        # raised AttributeError OUTSIDE the try/except above, bypassing
        # the NvdBatchFetchError abort path — the baseline loop saw
        # a raw AttributeError (not caught by its
        # ``except NvdBatchFetchError``), which then propagated to the
        # outer ``except Exception`` and got converted to a soft
        # status dict. Same "error indistinguishable from success"
        # class that PR-N17 was meant to close.
        #
        # Fix: explicit type check. Raise NvdBatchFetchError so the
        # baseline loop's abort handler fires normally.
        if not isinstance(data, dict):
            logger.error(
                "[NVD-BATCH-FETCH-ERROR] response is valid JSON but not a dict "
                "(got %s) — likely a maintenance page or upstream proxy error",
                type(data).__name__,
            )
            raise NvdBatchFetchError(f"NVD response JSON is {type(data).__name__}, expected dict")

        vulnerabilities = data.get("vulnerabilities", [])
        # Defense-in-depth: confirm ``vulnerabilities`` is a list.
        # A legitimate empty response returns ``[]`` (caller's
        # consecutive_empty counter handles end-of-window). A bad
        # payload with ``vulnerabilities: "some string"`` would
        # otherwise propagate as a non-list into downstream iteration.
        if not isinstance(vulnerabilities, list):
            logger.error(
                "[NVD-BATCH-FETCH-ERROR] ``vulnerabilities`` field is %s, expected list",
                type(vulnerabilities).__name__,
            )
            raise NvdBatchFetchError(
                f"NVD ``vulnerabilities`` field is {type(vulnerabilities).__name__}, expected list"
            )
        try:
            total_results = int(data.get("totalResults", len(vulnerabilities)) or 0)
        except (TypeError, ValueError):
            logger.error(
                "[NVD-BATCH-FETCH-ERROR] ``totalResults`` is %r, expected an integer", data.get("totalResults")
            )
            raise NvdBatchFetchError(f"NVD ``totalResults`` is {data.get('totalResults')!r}, expected an integer")
        return {"vulnerabilities": vulnerabilities, "totalResults": total_results}

    def _fetch_supplementary_cves(self, batch_sleep: float) -> List[Dict]:
        """Baseline records outside the publication windows (2026-10).

        Every CVE on CISA's KEV list (NVD ``hasKev``, about 1,700 records in one or two pages;
        ``EDGEGUARD_NVD_BASELINE_KEV_SWEEP``) and the CVE ids in ``EDGEGUARD_NVD_EXTRA_CVE_IDS``
        (one request each). Known-exploited CVEs stay relevant whatever their age, and CVE
        nodes are what exploitation claims attach to. Supplementary: a failed request is
        logged and skipped, never fails the baseline (the windows are the baseline proper).
        """
        records: List[Dict] = []
        if nvd_baseline_kev_sweep():
            idx = 0
            while True:
                try:
                    batch = self._fetch_cves_batch(start_index=idx, limit=2000, extra_params={"hasKev": ""})
                except NvdBatchFetchError as e:
                    logger.warning("[NVD-KEV-SWEEP] stopped at startIndex %d: %s — KEV records so far kept", idx, e)
                    break
                records.extend(batch)
                if len(batch) < 2000:
                    break
                idx += 2000
                time.sleep(batch_sleep)
            logger.info("  NVD KEV sweep: %d KEV CVE record(s) (any publication date)", len(records))
        extra_ids = nvd_extra_cve_ids()
        fetched_extra = 0
        consecutive_failures = 0
        for position, cve_id in enumerate(extra_ids):
            time.sleep(batch_sleep)
            try:
                batch = self._fetch_cves_batch(limit=1, extra_params={"cveId": cve_id})
            except NvdBatchFetchError as e:
                logger.warning("[NVD-EXTRA-CVE] %s not fetched: %s", cve_id, e)
                consecutive_failures += 1
                # Each failed request has already spent its rate-limit back-off (minutes on
                # 429 / 5xx); during an outage a long list would hold the baseline for hours.
                if consecutive_failures >= NVD_EXTRA_MAX_CONSECUTIVE_FAILURES:
                    logger.error(
                        "[NVD-EXTRA-CVE] %d failures in a row — NVD looks unavailable; "
                        "the remaining %d CVE id(s) are skipped this run",
                        consecutive_failures,
                        len(extra_ids) - position - 1,
                    )
                    break
                continue
            consecutive_failures = 0
            if not batch:
                logger.warning("[NVD-EXTRA-CVE] %s: NVD has no record", cve_id)
                continue
            records.extend(batch)
            fetched_extra += 1
        if extra_ids:
            logger.info("  NVD extra CVE ids: %d of %d fetched", fetched_extra, len(extra_ids))
        return records

    def _incremental_start(self, now: datetime) -> Tuple[datetime, Optional[datetime]]:
        """Where an incremental run starts reading, and the stored cursor (None when there is none).

        With a cursor: the cursor minus ``EDGEGUARD_NVD_CURSOR_OVERLAP_SEC``. Without one (after a
        wipe, or a cursor that is unreadable or later than now): ``EDGEGUARD_NVD_INCREMENTAL_DAYS``
        back from now.
        """
        stored = get_source_incremental("nvd").get(NVD_CURSOR_KEY)
        cursor = _parse_nvd_time(stored) if stored else None
        if stored and cursor is None:
            logger.warning(
                "NVD incremental: stored cursor %r is not a timestamp — reading the default lookback", stored
            )
        if cursor is not None and cursor > now:
            logger.warning("NVD incremental: stored cursor %s is later than now — reading the default lookback", stored)
            cursor = None
        if cursor is None:
            return now - timedelta(days=nvd_incremental_days()), None
        return cursor - timedelta(seconds=nvd_cursor_overlap_seconds()), cursor

    @staticmethod
    def _in_incremental_scope(vuln: Dict, scope_start: datetime, extra_ids: set) -> bool:
        """Whether an incremental run adds a CVE MISP does not hold yet: the scope a baseline collects.

        Published on or after *scope_start* (``EDGEGUARD_BASELINE_DAYS`` back from now), on CISA's
        KEV list (``cisaExploitAdd``), or listed in ``EDGEGUARD_NVD_EXTRA_CVE_IDS``. NVD modifies
        older CVEs as well (1,002 published more than 24 months earlier in the 14 days to
        2026-10-14); outside that scope they are not added. A record without a readable publication
        date is added.
        """
        cve = vuln.get("cve") or {}
        if cve.get("cisaExploitAdd") or str(cve.get("id") or "").upper() in extra_ids:
            return True
        published = _parse_nvd_time(cve.get("published"))
        return published is None or published >= scope_start

    @staticmethod
    def _store_incremental_cursor(at: datetime) -> bool:
        """Store the cursor. A failed checkpoint write is logged, not raised: the next run then reads
        from the previous cursor again, which repeats work and loses nothing."""
        try:
            update_source_incremental("nvd", **{NVD_CURSOR_KEY: _ensure_utc(at).isoformat()})
            return True
        except Exception as e:  # noqa: BLE001 - see docstring
            logger.warning("NVD: could not store the incremental cursor: %s: %s", type(e).__name__, e)
            return False

    def _seed_incremental_cursor(self, at: datetime) -> None:
        """After a clean baseline push: incremental runs start reading at *at*, unless a cursor is stored.

        A fresh baseline follows a wipe, which clears the cursor. An additive baseline on a running
        deployment keeps the stored cursor: a baseline does not edit CVEs MISP already holds, so the
        changes since that cursor still have to be read.
        """
        stored = get_source_incremental("nvd").get(NVD_CURSOR_KEY)
        if stored:
            logger.info("NVD baseline: incremental cursor %s kept", stored)
            return
        if self._store_incremental_cursor(at):
            logger.info("NVD baseline: incremental runs start reading at %s", _ensure_utc(at).isoformat())

    def _collect_incremental(self, limit: Optional[int], push_to_misp: bool) -> Any:
        """Incremental run (2026-10): every CVE NVD modified since the stored cursor.

        - Reads the lastMod window from the cursor (``_incremental_start``) to now, one time slice
          per request (``_iter_lastmod_slices``), oldest first, and handles each slice before the
          next is read, records in order of modification.
        - Lists the CVEs MISP holds under the NVD tag once a record has been read
          (``MISPWriter.index_source_attributes``; a failed listing writes nothing).
        - Adds a CVE MISP does not hold yet when it is in scope (``_in_incremental_scope``).
        - Edits the stored attribute of a CVE MISP holds when NVD's data for it changed
          (``EDGEGUARD_NVD_UPDATE_EXISTING``; ``MISPWriter.plan_vulnerability_update``). The MISP →
          Neo4j sync then rewrites the CVE node.
        - Makes at most ``EDGEGUARD_NVD_MAX_PER_RUN`` MISP writes (``limit``, when set, lowers that
          cap) and stops reading at the record where the cap is reached.
        - Moves the cursor only when the read was complete and every write was confirmed: to the end
          of the window, or to the record at which the cap stopped the run. Additions MISP's
          answers do not confirm are looked up by value (``MISPWriter.existing_values``); a cursor
          that cannot move fails the task and names the CVEs not written.
        - NVD not serving the window raises ``NvdIncrementalUnavailable`` (transient): nothing is
          written and the cursor stays.

        Before, a run took the newest N records by publication date (N = the incremental limit,
        200): 37% of new CVEs were never taken (30-day replay, 2026-10-14), and MISPWriter dropped
        every update to a CVE MISP already held as a duplicate.

        With ``push_to_misp=False`` returns the items of every record read, oldest modification
        first; the cursor stays.
        """
        now = _utc_now()
        start, cursor = self._incremental_start(now)
        window = f"{_to_nvd_pub_iso(start)} .. {_to_nvd_pub_iso(now)}"
        logger.info(
            "NVD incremental: reading CVEs modified %s (%s)",
            window,
            f"cursor {cursor.isoformat()}" if cursor else f"no cursor: last {nvd_incremental_days()} day(s)",
        )
        batch_sleep = 0.7 if self.api_key else 6.5

        if not push_to_misp:
            try:
                records, _complete = self._fetch_modified_cves(start, now)
            except NvdBatchFetchError as e:
                raise NvdIncrementalUnavailable(f"NVD did not serve the window {window}: {e}") from e
            self.circuit_breaker.record_success()
            record_collection_success(self.source_name)
            return [self._vulnerability_item(vuln) for vuln in records]

        source_tag = self.misp_writer.SOURCE_TAGS.get(self.tag, f"source:{self.tag}")
        cap = nvd_max_per_run()
        if limit is not None:
            cap = max(1, min(cap, int(limit)))
        update_existing = nvd_update_existing()
        scope_start = now - timedelta(days=resolve_baseline_days())
        extra_ids = set(nvd_extra_cve_ids())

        known: Optional[Dict[str, List[Any]]] = None  # listed once the first record has been read
        seen: set = set()
        to_add: List[Dict[str, Any]] = []
        edits: List[Tuple[str, Any, Dict[str, Any]]] = []  # (CVE id, stored copy, changes)
        records_read = unchanged = known_kept = out_of_scope = 0
        complete = True
        stopped_at: Optional[datetime] = None
        try:
            for batch, slice_complete in self._iter_lastmod_slices(start, now, batch_sleep):
                complete = complete and slice_complete
                for vuln in sorted(batch, key=_record_order):
                    cve_id = str((vuln.get("cve") or {}).get("id") or "").upper()
                    if not cve_id or cve_id in seen:
                        continue
                    seen.add(cve_id)
                    records_read += 1
                    if known is None:
                        known = self.misp_writer.index_source_attributes(source_tag, "vulnerability")
                    item = self._vulnerability_item(vuln)
                    stored_copies = known.get(cve_id)
                    planned: List[Tuple[Any, Dict[str, Any]]] = []
                    if stored_copies:
                        if not update_existing:
                            known_kept += 1
                            continue
                        planned = self.misp_writer.plan_vulnerability_update(item, stored_copies)
                        if not planned:
                            unchanged += 1
                            continue
                        writes = len(planned)
                    elif self._in_incremental_scope(vuln, scope_start, extra_ids):
                        writes = 1
                    else:
                        out_of_scope += 1
                        continue
                    if (to_add or edits) and len(to_add) + len(edits) + writes > cap:
                        # Never earlier than the window start (a record without ``lastModified`` sorts first).
                        stopped_at = max(_record_last_modified(vuln), start)
                        break
                    if planned:
                        edits.extend((cve_id, stored_copy, changes) for stored_copy, changes in planned)
                    else:
                        to_add.append(item)
                if stopped_at is not None:
                    break
        except NvdBatchFetchError as e:
            raise NvdIncrementalUnavailable(
                f"NVD did not serve the window {window}: {e}; nothing was written and the cursor stays"
            ) from e
        except (MispTransientError, MispLookupError) as e:
            error_msg = (
                f"MISP: the {source_tag} attributes could not be listed ({e}); nothing was written and the "
                "cursor stays, so the next run reads the same changes"
            )
            logger.error("NVD incremental: %s", error_msg)
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)
        self.circuit_breaker.record_success()
        record_collection_success(self.source_name)

        added = add_failed = 0
        not_written: List[str] = []  # CVE ids whose addition or edit MISP did not confirm
        if to_add:
            stats = self.misp_writer.stats if isinstance(getattr(self.misp_writer, "stats", None), dict) else {}
            unconfirmed_before = int(stats.get("attributes_unconfirmed", 0) or 0)
            unverified_before = int(stats.get("batches_unverified", 0) or 0)
            known_keys = {("vulnerability", value) for value in (known or {})}
            added, add_failed = self.misp_writer.push_items(to_add, known_source_keys={source_tag: known_keys})
            unconfirmed = int(stats.get("attributes_unconfirmed", 0) or 0) - unconfirmed_before
            unverified = int(stats.get("batches_unverified", 0) or 0) - unverified_before
            if add_failed or unconfirmed or unverified:
                # MISP's answers did not confirm every addition (a failed batch, attributes missing from
                # the returned event, or an answer without an attribute list, as MISP 2.5 gives when
                # every attribute of a batch on an empty event fails validation): ask MISP by value.
                values = [str(item.get("cve_id") or "").upper() for item in to_add]
                try:
                    present = self.misp_writer.existing_values(source_tag, "vulnerability", values)
                except (MispTransientError, MispLookupError) as e:
                    logger.error("NVD incremental: could not confirm the additions in MISP (%s)", e)
                    present = set()
                missing = [value for value in values if value not in present]
                added, add_failed = len(values) - len(missing), len(missing)
                not_written.extend(missing)
        updated = update_failed = 0
        pause = misp_batch_throttle_seconds()
        for done, (cve_id, stored_copy, changes) in enumerate(edits, 1):
            if self.misp_writer.update_attribute(stored_copy.uuid, changes):
                updated += 1
            else:
                update_failed += 1
                not_written.append(cve_id)
            if pause and done % EDITS_PER_THROTTLE == 0 and done < len(edits):
                # Paced like push_items' batches: EDGEGUARD_MISP_BATCH_THROTTLE_SEC after every 50 edits.
                time.sleep(pause)
        failed = add_failed + update_failed

        new_cursor = stopped_at or now
        cursor_moved = False
        cursor_stuck = ""
        if failed == 0 and complete:
            cursor_moved = self._store_incremental_cursor(new_cursor)
        else:
            reasons = []
            if failed:
                shown = ", ".join(sorted(set(not_written))[:20])
                more = len(set(not_written)) - 20
                reasons.append(
                    f"{failed} MISP write(s) not confirmed ({shown}{f' and {more} more' if more > 0 else ''})"
                )
            if not complete:
                reasons.append("a slice of the window could not be read completely")
            cursor_stuck = (
                f"NVD incremental: {'; '.join(reasons)} — the cursor stays at "
                f"{cursor.isoformat() if cursor else '(none)'} and the next run reads these changes again"
            )
            logger.error(cursor_stuck)
        if stopped_at is not None:
            logger.info(
                "NVD incremental: per-run cap of %d MISP writes reached (EDGEGUARD_NVD_MAX_PER_RUN, or the run's "
                "limit); the next run continues at changes from %s",
                cap,
                stopped_at.isoformat(),
            )
        logger.info(
            "NVD incremental: %d record(s) read; %d added, %d updated, %d unchanged, %d stored and not "
            "updated, %d outside the baseline scope, %d failed; cursor %s",
            records_read,
            added,
            updated,
            unchanged,
            known_kept,
            out_of_scope,
            failed,
            new_cursor.isoformat() if cursor_moved else "unchanged",
        )
        st = status_after_misp_push("nvd", len(to_add) + len(edits), added + updated, failed)
        if cursor_stuck:
            # A cursor that cannot move must be seen: the task fails until the cause is fixed, even
            # when the success rate of the run's writes clears EDGEGUARD_MISP_MIN_SUCCESS_RATE.
            st["success"] = False
            st["error"] = cursor_stuck
        st["circuit_breaker_state"] = self.circuit_breaker.state.name
        st["nvd_incremental"] = {
            "window_start": start.isoformat(),
            "window_end": now.isoformat(),
            "records_read": records_read,
            "read_complete": complete,
            "added": added,
            "updated": updated,
            "unchanged": unchanged,
            "stored_not_updated": known_kept,
            "out_of_scope": out_of_scope,
            "failed": failed,
            "not_written": sorted(set(not_written))[:100],
            "stopped_at_cap": stopped_at is not None,
            "cursor": new_cursor.isoformat() if cursor_moved else (cursor.isoformat() if cursor else None),
        }
        return st

    def _vulnerability_item(self, vuln: Dict) -> Dict[str, Any]:
        """One NVD CVE API 2.0 record (``{"cve": {...}}``) as an EdgeGuard vulnerability item.

        Shared by baseline and incremental runs. The lists built from sets (``ref_tags``,
        ``cpe_type``) are sorted and ``affected_products`` keeps NVD's order (2026-10): an
        incremental run compares the item with the copy MISP holds, and a set's iteration order
        differs between processes, so an unchanged CVE would have looked edited.
        """
        cve_data = vuln.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Get description
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        metrics = cve_data.get("metrics", {})

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
                # NVD API 2.0 puts the CVSS 2 rating on the metric, not in cvssData.
                "base_severity": m2.get("baseSeverity") or d2.get("baseSeverity", ""),
                "impact_score": m2.get("impactScore", 0.0),
                "exploitability_score": m2.get("exploitabilityScore", 0.0),
                "obtain_all_privilege": m2.get("obtainAllPrivilege", False),
                "obtain_user_privilege": m2.get("obtainUserPrivilege", False),
                "obtain_other_privilege": m2.get("obtainOtherPrivilege", False),
                "user_interaction_required": m2.get("userInteractionRequired", False),
                "ac_insuf_info": m2.get("acInsufInfo", False),
            }

        # 2026-10: the record's score is its first CVSS in the order v3.1 → v3.0 → v2 → v4.0
        # (``cvss_selection``); without any CVSS it is None and the severity UNKNOWN. It used
        # to be 0.0, which MISPWriter tagged ``cvss:low`` and the sync read back as 3.0 / LOW.
        cvss_score, severity, _ = select_cvss(
            {
                "cvss_v31_data": cvss_v31_data,
                "cvss_v30_data": cvss_v30_data,
                "cvss_v2_data": cvss_v2_data,
                "cvss_v40_data": cvss_v40_data,
            }
        )

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
        ref_tags = sorted(ref_tags_set)

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

        # No age filter after the fetch (2026-10): what a run collects is decided by its
        # request — a baseline's publication windows of ``baseline_days`` (plus the KEV sweep
        # and named ids, whatever their age), an incremental run's lastMod window and newest-
        # first selection. The former SECTOR_TIME_RANGES filter here compared NVD's zone-less
        # ``published`` ("2021-12-10T10:15:09.143") with a timezone-aware cutoff and swallowed
        # the TypeError, so it had not dropped a record since v2026.3.28. Made to work, it
        # would have cut the oldest hours of every baseline (the cutoff is computed after the
        # windows are fetched), any baseline longer than 24 months, and the KEV sweep's
        # older records.
        published_str = cve_data.get("published", "")

        # ResilMesh schema: Vulnerability.status is LIST OF STRING
        vuln_status_raw = cve_data.get("vulnStatus", "")
        vuln_status = ["rejected"] if vuln_status_raw == "Rejected" else ["active"]

        # PR-M2 §4-F1.5 (defense in depth): canonicalize NVD's
        # naive ISO timestamps at the producer boundary instead
        # of relying on downstream ``coerce_iso`` to fix them.
        # NVD returns ``"2023-05-09T15:15:10.897"`` without a TZ
        # offset; without canonicalization Neo4j's ``datetime()``
        # interprets the naive string as server-local time on
        # non-UTC deployments — silently shifting every NVD
        # CVE timestamp by the local offset. ``coerce_iso`` now
        # injects ``+00:00`` for naive parses (PR-M2 §4-F1) so
        # producer-side wrapping is belt-and-suspenders against
        # any future regression in the chokepoint helper. See
        # docs/TIMESTAMPS.md "Invariant 2".
        #
        # Bugbot round 3 (LOW): no ``or None`` tail — ``coerce_iso``
        # already returns ``None`` for empty / invalid / malformed
        # input per its contract (see source_truthful_timestamps.py).
        # The previous ``coerce_iso(...) or None`` was dead code
        # that misleadingly suggested ``coerce_iso`` could return
        # ``""`` or another falsy non-None value. Removing the
        # tail keeps producer code aligned with the helper's
        # documented contract.
        published_iso = coerce_iso(published_str)
        last_modified_iso = coerce_iso(cve_data.get("lastModified"))

        # One entry per CVE — property names aligned to ResilMesh schema
        return {
            "type": "vulnerability",
            "cve_id": cve_id,
            "description": description[:1000],
            "status": vuln_status,
            "zone": sectors,
            "tag": self.tag,
            "source": [self.tag],
            # PR (S5): source-truthful first/last claim
            # come from NVD's ``published`` and ``lastModified``.
            # Both fields fall back to None (NOT wall-clock NOW)
            # so the SOURCED_FROM edge MIN/MAX CASE logic preserves
            # any prior claim. Same pattern as the CISA + AbuseIPDB
            # wall-clock leak fixes. ``published`` and
            # ``last_modified`` are also kept as ResilMesh-compatible
            # plain string fields on the node for STIX export.
            "published": published_iso,
            "last_modified": last_modified_iso,
            # ``first_seen`` / ``last_seen`` flow into the
            # source-truthful extractor → SOURCED_FROM edge as
            # ``r.source_reported_first_at`` / ``r.source_reported_last_at``.
            "first_seen": published_iso,
            "last_seen": last_modified_iso,
            # PR (S5) (Logic Tracker v3 LOW + Bug
            # Hunter v3 #6): the previously-restored
            # ``"last_updated"`` key was based on a misleading
            # bugbot premise — ``parse_attribute`` reads
            # MISP-side data (``nvd_meta.get("last_modified")``
            # / ``attr.get("timestamp")``), NEVER the
            # collector's item dict. The key has zero
            # consumers. Dropped to keep one source-of-truth
            # per concept (last_seen for the source claim;
            # n.last_updated is set server-side from
            # ``datetime()``).
            "confidence_score": 0.9 if cisa_exploit_add else 0.6,
            "severity": severity.upper(),
            "cvss_score": cvss_score,
            "attack_vector": attack_vector,
            "affected_products": list(dict.fromkeys(affected_products))[:10],
            # ResilMesh-compatible fields
            "cwe": cwe_list,
            "ref_tags": ref_tags,
            "reference_urls": reference_urls[:10],
            "cpe_type": sorted(cpe_type_set),
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
            if self._api_key_rejected:
                error_msg = (
                    "NVD rejected NVD_API_KEY (HTTP 404 Invalid apiKey.) — the service is up, the key is wrong. "
                    "Correct the key, or remove it: NVD also answers without a key, at a lower rate"
                )
                logger.error(error_msg)
            else:
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
                # 2026-10: where the incremental cursor starts after this baseline (see
                # ``_seed_incremental_cursor``): when this collection began or, on a resume,
                # when the interrupted one began, since its records were read then.
                cursor_floor = pub_overall_end
                if not checkpoint.get("completed"):
                    _started = _parse_nvd_time(checkpoint.get("started_at"))
                    if _started is not None and _started < cursor_floor:
                        cursor_floor = _started
                start_wi = 0
                resume_index = 0
                # PR-G1 Bug Hunter audit (HIGH): the old ``page`` formula was
                # ``wi * 5000 + (idx // batch_size) + 1`` with ``batch_size =
                # 2000`` — the hard-coded ``5000`` multiplier made the page
                # counter jump from e.g. ~60 (end of window 0) to 5001
                # (start of window 1), so ``edgeguard baseline status``
                # reported meaningless pages. Replace with a monotonic
                # per-API-call batch counter. ``page`` is display-only —
                # resume uses ``nvd_window_idx`` + ``nvd_start_index`` — so
                # seeding the counter from the checkpoint keeps the display
                # approximately correct across restarts without affecting
                # resume correctness.
                #
                # PR-G1 Bugbot round-1 (Medium): ``update_source_checkpoint``
                # persists the ``page`` kwarg under ``entry["current_page"]``
                # (``baseline_checkpoint.py:135``) — NOT under ``"page"``. The
                # original seed expression ``checkpoint.get("page", 0)`` would
                # always return 0, so the counter never actually recovered on
                # resume. Read ``current_page`` to match the writer, and fall
                # back to ``max(pages)`` for extra robustness if the schema
                # ever diverges.
                #
                # PR-G1 Bugbot round-2 (Low): a fresh baseline run AFTER a
                # previously-completed one must start the counter at 0, not
                # at the prior run's final value. The resume-detection
                # branch below is skipped when ``completed=True``, so we
                # have to reset explicitly here.  The old formula naturally
                # reset because it recomputed from loop variables; the
                # monotonic counter needs the operator-facing invariant
                # made explicit.
                if checkpoint.get("completed"):
                    total_batches_done = 0
                else:
                    total_batches_done = int(
                        checkpoint.get("current_page")
                        or (max(checkpoint.get("pages") or [0]) if checkpoint.get("pages") else 0)
                        or 0
                    )
                if not checkpoint.get("completed") and checkpoint.get("nvd_window_idx") is not None:
                    start_wi = int(checkpoint["nvd_window_idx"])
                    resume_index = int(checkpoint.get("nvd_start_index", 0))
                    if start_wi >= len(windows):
                        start_wi, resume_index = 0, 0
                        total_batches_done = 0
                    else:
                        logger.info(
                            f"  Resuming baseline at window {start_wi + 1}/{len(windows)}, startIndex={resume_index}"
                        )

                # PR-N17 Fix #2 (BLOCK, 2026-04-22): track whether any
                # window aborted due to fetch error so the operator
                # sees "partial" status + the checkpoint is NOT marked
                # ``completed=True`` at the end of the baseline run.
                aborted_windows: list = []

                for wi in range(start_wi, len(windows)):
                    w_start, w_end = windows[wi]
                    pub_start_iso = _to_nvd_pub_iso(w_start)
                    pub_end_iso = _to_nvd_pub_iso(w_end)
                    idx = resume_index if wi == start_wi else 0
                    resume_index = 0
                    consecutive_empty = 0
                    window_aborted = False

                    while consecutive_empty < 3:
                        try:
                            cves = self._fetch_cves_batch(
                                pub_start_iso=pub_start_iso,
                                pub_end_iso=pub_end_iso,
                                start_index=idx,
                                limit=batch_size,
                            )
                        except NvdBatchFetchError as fetch_err:
                            # PR-N17 Fix #1+#2: fetch errored (not a
                            # legit empty response). DO NOT advance
                            # the checkpoint — abort this window and
                            # preserve the current (wi, idx) so resume
                            # picks up where the failure happened.
                            logger.error(
                                "[NVD-WINDOW-ABORT] window %d/%d @ startIndex %d — "
                                "aborting due to fetch error: %s. Checkpoint NOT "
                                "advanced; next baseline run will resume at this "
                                "position. Affected date range: %s to %s.",
                                wi + 1,
                                len(windows),
                                idx,
                                fetch_err,
                                pub_start_iso,
                                pub_end_iso,
                            )
                            record_collection_failure(self.source_name, f"window-abort wi={wi} idx={idx}: {fetch_err}")
                            aborted_windows.append(wi)
                            window_aborted = True
                            # Preserve checkpoint at current (wi, idx) —
                            # explicit write so if the process dies now,
                            # resume is exactly where it aborted.
                            update_source_checkpoint(
                                "nvd",
                                page=total_batches_done,
                                items_collected=len(all_cves),
                                extra={"nvd_window_idx": wi, "nvd_start_index": idx},
                            )
                            break  # stop the inner while loop for this window
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
                        total_batches_done += 1
                        update_source_checkpoint(
                            "nvd",
                            page=total_batches_done,
                            items_collected=len(all_cves),
                            extra={"nvd_window_idx": wi, "nvd_start_index": next_idx},
                        )
                        if len(cves) < batch_size:
                            break
                        idx = next_idx
                        time.sleep(batch_sleep)

                    # PR-N17 Fix #2: only mark this window complete
                    # (advance ``nvd_window_idx`` to wi+1) if the
                    # window actually finished via consecutive-empty.
                    # If it aborted due to fetch error, leave the
                    # checkpoint at (wi, idx) so resume retries.
                    if not window_aborted:
                        update_source_checkpoint(
                            "nvd",
                            items_collected=len(all_cves),
                            extra={"nvd_window_idx": wi + 1, "nvd_start_index": 0},
                        )
                    else:
                        # PR-N17 follow-up (cursor-bugbot 2026-04-22 #1):
                        # break the OUTER for-loop on first abort.
                        # Pre-fix the inner ``break`` only exited the
                        # while loop; the for loop continued with
                        # subsequent windows whose successful batches
                        # called ``update_source_checkpoint`` with
                        # later ``nvd_window_idx`` values, OVERWRITING
                        # the abort checkpoint. Resume then jumped
                        # past the aborted window, losing its data.
                        # Now: stop the for-loop too so the preserved
                        # (wi, idx) checkpoint actually survives.
                        break  # exit outer for-loop on first abort

                # PR-N17 Fix #2 (cursor-bugbot 2026-04-22 #2): if any
                # windows aborted, the baseline is partial — raise
                # NvdBatchFetchError so the Airflow task fails loudly.
                # The raise is OUTSIDE the wrapping try/except (re-
                # raised explicitly below) so it isn't caught by the
                # outer ``except Exception`` and converted to a normal
                # status return — that conversion gave the appearance
                # of a graceful "success: False" response which Airflow
                # treats less aggressively than an explicit raise.
                # Storing the to-raise condition + raising AFTER the
                # try block guarantees the typed exception escapes.
                if aborted_windows:
                    # PR-N17 follow-up (cursor-bugbot 2026-04-22 #2):
                    # raise IMMEDIATELY (not at end of try block) so
                    # the typed exception propagates to the new
                    # ``except NvdBatchFetchError:`` re-raise gate
                    # below. Skips all the post-loop processing
                    # (transform / push / status return) which would
                    # otherwise hide the partial-baseline state.
                    raise NvdBatchFetchError(
                        f"NVD baseline partial: {len(aborted_windows)} window(s) aborted "
                        f"(indices {aborted_windows}). Checkpoint preserved at first abort "
                        f"(per cursor-bugbot 2026-04-22 #1, the outer for-loop now breaks "
                        f"on first abort to prevent later windows from overwriting the "
                        f"checkpoint). Re-run baseline to resume."
                    )

                # PR-M1 §7-H3: defensive guard against a run-level ``limit``
                # leaking from an incremental-style config into the baseline
                # path. The NVD baseline iterates 120-day windows across
                # ``baseline_days`` (default 365, often 730 in production),
                # accumulating potentially millions of CVEs in ``all_cves``.
                # The previous line ``all_cves if limit is None else all_cves[:limit]``
                # would silently truncate the entire accumulation to a
                # small number if an operator had set (e.g.)
                # ``EDGEGUARD_BASELINE_COLLECTION_LIMIT=200`` — we've seen
                # this copy-pasted from incremental configs. In baseline
                # mode the run-level ``limit`` is the wrong ceiling; the
                # correct per-baseline cap is a separate concept.
                #
                # New behaviour: in baseline we IGNORE ``limit`` and return
                # the full windowed collection, emitting a WARNING if a
                # non-None ``limit`` was supplied so the operator can see
                # that their env value had no effect and remove it.
                if limit is not None:
                    logger.warning(
                        "NVD baseline: ignoring run-level limit=%d — it would truncate "
                        "the full %d-day windowed collection of %d CVEs. In baseline mode "
                        "this run-level cap is almost always a copy-paste from an "
                        "incremental config. If you genuinely need a baseline ceiling, "
                        "raise an issue and we'll add EDGEGUARD_NVD_BASELINE_MAX as a "
                        "dedicated knob.",
                        limit,
                        baseline_days,
                        len(all_cves),
                    )
                # 2026-10: KEV CVEs and named CVE ids outside the publication windows (a
                # known-exploited CVE stays relevant whatever its age); records already collected
                # by a window are not duplicated.
                for _rec in self._fetch_supplementary_cves(batch_sleep):
                    _sup_id = (_rec.get("cve") or {}).get("id", "")
                    if not _sup_id:
                        continue
                    if _sup_id not in seen_cve_ids:
                        seen_cve_ids.add(_sup_id)
                        all_cves.append(_rec)
                vulnerabilities = all_cves
                if not vulnerabilities:
                    logger.warning(
                        "NVD baseline returned 0 CVEs for %s-day window — verify API key and connectivity",
                        baseline_days,
                    )
                logger.info(f"  Baseline complete: {len(vulnerabilities)} CVEs collected")
                update_source_checkpoint(
                    "nvd",
                    # PR-G1 Bug Hunter audit (HIGH): was ``len(windows) * 5000``
                    # — a meaningless product of window count and a stale
                    # batch_size constant. Use the actual monotonic
                    # per-API-call batch counter so the final checkpoint
                    # reports the real number of NVD calls made.
                    page=total_batches_done,
                    items_collected=len(vulnerabilities),
                    completed=True,
                )
            else:
                # 2026-10: an incremental run reads every CVE NVD modified since the stored cursor,
                # adds the new ones and edits the MISP copy of the known ones that changed.
                return self._collect_incremental(limit, push_to_misp)

            # Record success in circuit breaker
            self.circuit_breaker.record_success()

            # PR-M1 §7-H3: same defensive stance as the accumulation-side
            # guard above — in baseline mode the run-level ``limit`` is
            # ignored so the windowed collection reaches the processing
            # loop in full. (Incremental runs return above; their limit caps
            # MISP writes per run, see ``_collect_incremental``.)
            to_process = vulnerabilities if (baseline or limit is None) else vulnerabilities[:limit]
            processed = [self._vulnerability_item(vuln) for vuln in to_process]

            logger.info(f"[OK] NVD: Processed {len(processed)} CVEs")

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
                if failed == 0:
                    # The first incremental run after this baseline reads from where it began.
                    self._seed_incremental_cursor(cursor_floor)
                return st
            else:
                record_collection_success(self.source_name)
                return processed

        except NvdBatchFetchError:
            # PR-N17 follow-up (cursor-bugbot 2026-04-22 #2): the
            # baseline-partial raise must escape the outer except
            # chain so Airflow sees an actual exception. Without this
            # explicit re-raise the broader ``except Exception as e:``
            # below catches it, converts to ``return self._return_status(
            # False, 0, error_msg)``, and the task function returns
            # normally. Airflow treats the dict-return as a callable
            # success (the dict's ``success: False`` field IS picked up
            # by ``run_collector_with_metrics`` and converted to
            # ``AirflowException``, but the typed exception is lost).
            # Re-raising preserves the type so downstream alerting +
            # retry logic can distinguish "NVD baseline partial — re-
            # run will resume from preserved checkpoint" from "NVD
            # generic collection failure".
            self.circuit_breaker.record_failure()
            raise
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
            # PR-N24 BLOCKER B3 (proactive audit 2026-04-22): PR-N17 closed
            # the NvdBatchFetchError internal path but left this outer
            # ``except Exception`` as a silent swallower for the
            # ``push_to_misp=False`` branch — caller (baseline-drain /
            # alert-preview) got a status dict indistinguishable from
            # "NVD has no new CVEs today". NVD is the canonical CVE source
            # for the 730-day baseline; a silent outage here is
            # unacceptable. Same fix shape as OTX/MITRE/CISA.
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise

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
