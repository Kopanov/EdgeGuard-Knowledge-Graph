#!/usr/bin/env python3
"""
EdgeGuard - MISP to Neo4j Sync Module

Syncs threat intelligence data from MISP to Neo4j.
This is the second phase of the MISP-as-Source-of-Truth architecture.

Production-ready features:
- Comprehensive error handling with logging
- Connection retry logic with exponential backoff
- Circuit breaker pattern for extended outages
- Health checks for MISP and Neo4j
- Prometheus metrics for alerting
- Batch processing for better performance
- Timeout handling for all API calls
"""

import gc
import json
import logging
import math
import os
import re
import sys
import time
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import urllib3

from actor_name_hygiene import clean_actor_names
from attack_revoked import load_revoked_ids
from attack_software_names import split_attack_software_id
from attack_values import AttackValue, looks_like_attack_value, parse_attack_value
from canonical_threat_actors import (
    CanonicalReference,
    ReferenceUnavailable,
    actor_identities,
    load_canonical_reference,
)

# Import resilience utilities
from collectors.collector_utils import TransientServerError
from config import (
    MISP_API_KEY,
    MISP_URL,
    SECTOR_TIME_RANGES,
    SSL_VERIFY,
    apply_misp_http_host_header,
    get_sector_cutoff_date,
    misp_http_headers_for_pymisp,
)
from cvss_selection import CVSS_VERSIONS, cvss_attack_vector, select_cvss
from indicator_aging import BASIS_MISP_RECORDED, BASIS_SOURCE_DATE
from ioc_normalize import MISP_IP_ATTRIBUTE_TYPES, ip_address_type
from misp_health import MISPHealthCheck
from neo4j_client import (
    _PROP_NAME_RE,
    CURATED_MISSING_SAMPLE,
    CVSS_PAYLOAD_RESERVED_NAMES,
    Neo4jClient,
    clamp_cvss_score,
    normalize_cve_id_for_graph,
    resolve_vulnerability_cve_id,
)
from node_identity import is_placeholder_name
from query_pause import query_pause
from relationship_provenance import CURATED_CLAIM_CONFIDENCE, CURATED_CLAIMS_PREFIX, CURATED_PREDICATES
from resilience import check_service_health, get_circuit_breaker, record_collection_failure, record_collection_success
from sector_evidence import industry_zones as sector_industry_zones
from sector_evidence import link_evidence as sector_link_evidence
from sector_evidence import report_zone_entry as sector_report_zone_entry
from sector_evidence import report_zone_pairs as sector_report_zone_pairs
from sector_evidence import stated_refs as sector_stated_refs
from sector_evidence import stated_zones as sector_stated_zones
from sector_evidence import zone_refs as sector_zone_refs
from source_registry import (
    CURATED_OTHER_LABEL,
    canonical_source_id,
    curated_label_for,
    curated_source_ids,
    format_source_ref,
    is_curated_source,
    misp_tag_to_canonical_map,
)
from source_trust import is_attribute_creator_trusted
from source_truthful_timestamps import coerce_iso as _coerce_to_iso
from source_truthful_timestamps import earliest_allowed_date, extract_source_truthful_timestamps

try:
    from metrics_server import (
        record_misp_fetch_fallback,
        record_pipeline_duration,
        record_sync_event_accounting,
    )

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

    # PR-N31: defensive no-op so call-sites can call unconditionally.
    # Mirrors the pattern used elsewhere when prometheus_client isn't
    # installed (e.g. local pure-unit-test runs without the metrics dep).
    def record_misp_fetch_fallback(branch: str, outcome: str) -> None:  # type: ignore[no-redef]
        return None


# Suppress InsecureRequestWarning only when SSL verification is explicitly
# disabled in config — never globally for the whole process.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuration constants (defined before _pymisp_client_kwargs uses them at call time)
MISP_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
MISP_REQUEST_TIMEOUT = 300  # Read timeout (seconds) — large events (95K+ attrs) need time


class _MispFallbackHardError(Exception):
    """Sentinel: a non-recoverable failure inside the MISP fetch fallback paths.

    PR-N29 (multi-agent audit, 2026-04-24, HIGH-1/2/3): the PyMISP and
    requests-restSearch fallback branches in ``fetch_edgeguard_events``
    discovered three distinct hard-error paths during the audit:

    1. PyMISP returning ``{"errors": ...}`` mid-pagination
    2. PyMISP returning an unexpected payload type mid-pagination
    3. requests-restSearch returning HTTP 5xx mid-pagination
    4. EITHER branch hitting the ``_FALLBACK_MAX_PAGES`` safety cap

    2026-10, same contract for the rest of the event listing:

    5. the primary ``/events/index`` (or ``/events``) listing failing on a
       page after the first with a non-transient error (see
       ``_fetch_edgeguard_events_via_requests_index``)
    6. the restSearch fallback answering a non-JSON page or failing with
       a non-transient error (recorded as ``rest_search`` / ``hard_error``),
       and any other unexpected error while listing (the outer handler of
       ``fetch_edgeguard_events`` used to return the partial list)

    All of them MUST surface to the operator. An earlier PR-N29 fix
    used a bare ``raise RuntimeError(...)`` — but the enclosing
    ``except Exception as e: logger.error(...)`` blocks at lines ~1109
    (PyMISP fallback → swallowed back to requests-restSearch path) and
    ~1201 (outer broad) silently catch ``RuntimeError`` and turn the
    failure into a partial-success "no events found" state, exactly
    the silent-truncation failure mode PR-N29 H3 was meant to close.

    A dedicated sentinel + explicit ``except _MispFallbackHardError:
    raise`` clauses ahead of the broad ``except Exception`` give us a
    clean fast-path to the calling DAG (which has retries=0 on the
    critical chain — see PR-N29 H1) without touching the legitimate
    transient-network catch above.

    The sentinel is intentionally NOT in the ``retry_with_backoff``
    retry set: a 500 mid-pagination is not a transient network issue
    and re-trying immediately would only paper over the underlying
    MISP backend problem.
    """

    pass


def _pymisp_client_kwargs() -> Dict[str, Any]:
    """PyMISP constructor kwargs: SSL verify, HTTP timeouts, optional Host override.

    Without ``timeout``, PyMISP/requests may block indefinitely on a hung MISP server
    (Airflow task stays "running"). Values align with REST fallback below.
    """
    kw: Dict[str, Any] = {
        "ssl": SSL_VERIFY,
        "timeout": (MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
    }
    extra_headers = misp_http_headers_for_pymisp()
    if extra_headers is not None:
        kw["http_headers"] = extra_headers
    return kw


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Retry / circuit breaker (MISP timeouts live above for PyMISP + requests)
MAX_RETRIES = 4
RETRY_DELAY_BASE = 10  # seconds — MISP needs time to free memory under load

# Circuit breakers for MISP and Neo4j
MISP_CIRCUIT_BREAKER = get_circuit_breaker("misp", failure_threshold=3, recovery_timeout=3600)
NEO4J_CIRCUIT_BREAKER = get_circuit_breaker("neo4j", failure_threshold=3, recovery_timeout=3600)

# Chunk size for sync_to_neo4j(): avoids holding huge per-type lists and peaks in driver/heap (OOM).
# Neo4jClient.merge_*_batch still uses its own BATCH_SIZE (default 1000) per Cypher UNWIND.
NEO4J_SYNC_CHUNK_SIZE_DEFAULT = 500  # 500 keeps lock hold time manageable during relationship MERGE — 1000 caused lock contention death spiral on 100K+ attribute events.
# Log a warning when single-pass sync is used with more than this many items (OOM risk).
NEO4J_SYNC_SINGLE_PASS_WARN_THRESHOLD = 2000
NEO4J_SYNC_SINGLE_PASS_STRONG_WARN_THRESHOLD = 5000

# Substring of the event title that marks an EdgeGuard event (titles look like
# ``EdgeGuard-{source}-{date}``), matched case-insensitively by ``_is_edgeguard_index_event``.
# 2026-10: the restSearch fallback sends it as ``eventinfo: "%<needle>%"`` (a LIKE filter on
# ``Event.info``). MISP honours ``eventinfo`` from 2.4.177 on and an older MISP ignores it, so the
# fallback also keeps only the rows ``_is_edgeguard_index_event`` accepts. The ``search`` key used
# before is not a restSearch parameter: MISP dropped it and answered every event of the store.
MISP_EDGEGUARD_DISCOVERY_SEARCH = os.getenv("EDGEGUARD_MISP_EVENT_SEARCH", "EdgeGuard").strip() or "EdgeGuard"

# Lightweight event list (no attribute scan). restSearch without ``metadata`` answers full events with
# all of their attributes and can time out / 500 on very large events (e.g. URLhaus, SSL blacklist).
try:
    MISP_EVENTS_INDEX_PAGE_SIZE = int(os.getenv("EDGEGUARD_MISP_PAGE_SIZE", "500"))
except (ValueError, TypeError):
    MISP_EVENTS_INDEX_PAGE_SIZE = 500
try:
    MISP_EVENTS_INDEX_MAX_PAGES = int(os.getenv("EDGEGUARD_MISP_MAX_PAGES", "100"))
except (ValueError, TypeError):
    MISP_EVENTS_INDEX_MAX_PAGES = 100


# PR (S5) (bugbot LOW): the local ``_coerce_to_iso`` helper was
# deleted; the canonical implementation now lives in
# ``source_truthful_timestamps.coerce_iso`` (imported above as
# ``_coerce_to_iso`` to keep the existing call-site spelling). Single
# source of truth — bug fix in one place propagates to all callers
# (parse_attribute, MISPWriter handoff, alert_processor read-side).


def _is_edgeguard_index_event(ev: Dict[str, Any]) -> bool:
    """Client-side filter for EdgeGuard-created events from ``/events/index`` style payloads."""
    needle = (MISP_EDGEGUARD_DISCOVERY_SEARCH or "").strip()
    info = (ev.get("info") or "").strip()
    if isinstance(info, str) and needle and needle.lower() in info.lower():
        return True
    org = ev.get("org") or ev.get("Org") or {}
    if isinstance(org, dict) and (org.get("name") or "").strip() == "EdgeGuard":
        return True
    return False


def _fallback_search_filters() -> Dict[str, Any]:
    """Filters of the ``fetch_edgeguard_events`` restSearch fallback (PyMISP and requests, 2026-10).

    ``metadata`` asks for event headers only: the caller reads id, info and attribute_count and
    fetches each event's attributes separately, and a page of 500 full events is the whole store
    with every attribute. ``eventinfo`` narrows to EdgeGuard titles on MISP 2.4.177 or later.
    """
    return {"metadata": True, "eventinfo": f"%{MISP_EDGEGUARD_DISCOVERY_SEARCH}%"}


def _edgeguard_fallback_rows(rows: List[Any]) -> List[Any]:
    """Rows of a fallback restSearch page whose event ``_is_edgeguard_index_event`` accepts (2026-10).

    A MISP older than 2.4.177 ignores ``eventinfo`` and answers every event of the store; the index
    path applies the same filter to its rows.
    """
    kept: List[Any] = []
    for row in rows:
        ev = _unwrap_single_misp_event_row(row)
        if ev is not None and _is_edgeguard_index_event(ev):
            kept.append(row)
    return kept


def _event_covers_since(ev: Dict[str, Any], since: Optional[datetime]) -> bool:
    """Incremental sync: keep events modified on/after ``since`` when index exposes a timestamp/date."""
    if since is None:
        return True
    ts = ev.get("timestamp")
    if ts is not None and str(ts).strip() != "":
        try:
            return float(ts) >= since.timestamp()
        except (TypeError, ValueError):
            pass
    date_s = ev.get("date")
    if date_s is not None and str(date_s).strip() != "":
        try:
            if isinstance(date_s, (int, float)):
                return float(date_s) >= since.timestamp()
            ds = str(date_s).strip()[:10]
            if len(ds) >= 10:
                ev_day = datetime.strptime(ds, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                # PR-M2 §4-F7: widen the boundary by 1 day. ``Event.date``
                # is a date-only string (00:00:00 UTC) but ``since`` is a
                # full datetime — typically computed as
                # ``now - timedelta(days=N)`` which lands at e.g. 03:14:22
                # UTC. ``ev_day.date() >= since.date()`` was excluding
                # events on ``since.date()`` whose actual time-of-day was
                # before ``since`` — losing up to 24 h per incremental
                # run at the window floor. Cumulative ~3 h/run × 730 daily
                # runs ≈ 2,190 h of dropped event coverage on a 2-yr
                # baseline. Widening by 1 day errs on the side of
                # inclusion (a few duplicates resolved by MERGE-side
                # dedup) rather than silent loss.
                return ev_day.date() >= (since - timedelta(days=1)).date()
        except (ValueError, TypeError):
            pass
    return True


def _misp_attribute_time(attr: Dict[str, Any]) -> Optional[datetime]:
    """``Attribute.timestamp`` (when MISP recorded the attribute; an edit bumps it) as an aware UTC
    datetime, or None when it is missing or unparsable.

    PyMISP ``to_dict()`` returns datetimes (naive ones are UTC), the raw JSON epoch strings.
    """
    ts = attr.get("timestamp")
    if isinstance(ts, datetime):
        return (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    if ts is None or isinstance(ts, bool):
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _attribute_changed_since(attr: Dict[str, Any], since: datetime) -> bool:
    """Incremental sync: True when the attribute was written to MISP on/after ``since``.

    ``Attribute.timestamp`` is MISP's write-time epoch; an edit bumps it. A missing or
    unparsable timestamp counts as changed, so such rows keep the whole-event behaviour.
    """
    recorded = _misp_attribute_time(attr)
    if recorded is None:
        return True
    return recorded.timestamp() >= since.timestamp()


def _source_last_report_date(attr: Dict[str, Any], event_info: Optional[Dict[str, Any]]) -> Optional[datetime]:
    """The source's own last-report date of one MISP attribute: its native ``last_seen`` (what the
    collector stored as the source's last report, ``MISPWriter``), as an aware UTC datetime.

    None when the attribute has none, when it is unparsable or earlier than
    ``EDGEGUARD_EARLIEST_IOC_DATE`` (a sentinel must not retire an indicator), and when the trust
    check refuses the event's creator (``source_trust``; the source's other dates are refused
    then too). Read for every source, not through the first-seen allowlist: the date only ever
    makes an indicator older than its MISP record time, never newer.
    """
    iso = _coerce_to_iso(attr.get("last_seen"))
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    parsed = (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    if parsed < earliest_allowed_date():
        return None
    if event_info is not None and not is_attribute_creator_trusted(event_info)[0]:
        return None
    return parsed


def misp_report_times(attr: Dict[str, Any], event_info: Optional[Dict[str, Any]] = None) -> Dict[str, Optional[str]]:
    """The report one MISP attribute makes of an indicator (2026-10-16, ``indicator_aging``).

    ``recorded_at`` is T, the attribute's MISP timestamp (UTC). ``reported_at`` is
    ``min(T, coalesce(L, T))`` with L the source's own last-report date
    (``_source_last_report_date``): a date later than T is capped at T. ``reported_basis`` says
    which it is (``source_date`` when L dates the report, ``misp_recorded`` otherwise) and
    ``report_ref`` is the attribute uuid, the record an expert reads in MISP. Without a usable
    timestamp the attribute dates nothing (both times None). Both sync paths (in-memory and
    paged) build their items with ``parse_attribute``, which calls this, so a full sync, an
    incremental one and the paged path carry the same values.
    """
    ref = str(attr.get("uuid") or "").strip() or None
    times: Dict[str, Optional[str]] = {
        "recorded_at": None,
        "reported_at": None,
        "report_ref": ref,
        "reported_basis": None,
    }
    recorded = _misp_attribute_time(attr)
    if recorded is None:
        return times
    times["recorded_at"] = recorded.isoformat()
    source_date = _source_last_report_date(attr, event_info)
    if source_date is not None and source_date <= recorded:
        times["reported_at"] = source_date.isoformat()
        times["reported_basis"] = BASIS_SOURCE_DATE
    else:
        times["reported_at"] = recorded.isoformat()
        times["reported_basis"] = BASIS_MISP_RECORDED
    return times


def _report_key(item: Dict[str, Any]) -> Optional[Tuple[datetime, str, str]]:
    """Sort key of an item's report for ``_dedupe_parsed_items``: the report time, then the
    reference and source (the smaller wins a tie, as in ``indicator_aging._newer_report``)."""
    reported = item.get("reported_at")
    if not reported:
        return None
    try:
        when = datetime.fromisoformat(str(reported).replace("Z", "+00:00"))
    except ValueError:
        return None
    return when, str(item.get("report_ref") or ""), str(item.get("tag") or "")


def _later_iso(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """The later of two ISO-8601 times (either may be None)."""
    if not a or not b:
        return a or b
    try:
        return (
            a
            if datetime.fromisoformat(a.replace("Z", "+00:00")) >= datetime.fromisoformat(b.replace("Z", "+00:00"))
            else b
        )
    except ValueError:
        return a


def _item_report_ids(item: Dict[str, Any]) -> set:
    """Report ids an item belongs to, normalised like ``_build_cross_item_relationships``."""
    ids = set()
    for report_id in [item.get("pulse_id")] + list(item.get("report_ids") or []):
        if isinstance(report_id, str) and report_id.strip():
            ids.add(report_id.strip())
    return ids


def _event_order_key(full_event: Dict[str, Any]) -> Callable[[Dict[str, Any]], int]:
    """Sort key giving a parsed item its attribute's position in *full_event* (2026-10-18).

    An incremental run builds the report-scoped links from the changed items followed by the unchanged
    items of their reports. Sorted by this key they are back in event order, so the per-report caps of
    ``_build_cross_item_relationships`` pick the same items as a full sync, whichever attributes changed.
    An item is found by ``misp_attribute_id`` (the attribute uuid); one not in the event sorts last.
    """
    positions: Dict[str, int] = {}
    for index, attr in enumerate(coerce_misp_attribute_list(full_event.get("Attribute"))):
        attr_uuid = str(attr.get("uuid") or "")
        if attr_uuid:
            positions.setdefault(attr_uuid, index)
    missing = len(positions)
    return lambda item: positions.get(str(item.get("misp_attribute_id") or ""), missing)


# Outcome of the last index listing (read by ``fetch_edgeguard_events`` to record it in the run
# stats): ``truncated`` is True when the listing stopped at ``EDGEGUARD_MISP_MAX_PAGES`` with a
# full last page, i.e. events beyond the cap were not listed.
INDEX_FETCH_STATE: Dict[str, bool] = {"truncated": False}


def _is_misp_index_listing(payload: Any) -> bool:
    """True for the payload shapes ``normalize_misp_event_index_payload`` reads as an event listing.

    2026-10: anything else (for example HTTP 200 with ``{"errors": ...}``) is an error answer, not
    an empty listing; before, it was read as "no events" and the run reported an empty success.
    """
    if isinstance(payload, list):
        return True
    if isinstance(payload, dict):
        return (
            isinstance(payload.get("response"), list)
            or isinstance(payload.get("events"), list)
            or isinstance(payload.get("Event"), dict)
        )
    return False


def _fetch_edgeguard_events_via_requests_index(
    session: requests.Session,
    misp_base: str,
    since: Optional[datetime],
) -> Optional[List[Dict[str, Any]]]:
    """
    Try MISP event index endpoints (paginated). Returns:
      - list (possibly empty) if an index path responded successfully;
      - None if no index URL worked on its first page (caller may fall back to PyMISP/restSearch).

    Raises (2026-10) when a page after the first fails, because the pages read so far are not the
    whole listing: ``requests`` ConnectionError / Timeout / ChunkedEncodingError are re-raised so
    ``fetch_edgeguard_events``'s ``@retry_with_backoff`` re-runs the listing; any other failure (a
    non-200 answer, a non-JSON answer, a payload that is not a listing, another request error)
    raises ``_MispFallbackHardError``. Before, the loop stopped and returned the rows read so far as
    the complete listing, so ``run()`` succeeded and the DAG stamped its cursor past the events
    that were never listed.

    Paging that the server ignores (2026-10): MISP 2.5.45 reads ``limit`` and ``page`` of
    ``/events/index`` only from named parameters (``limit:500/page:2``) or the request body, never
    from the query string, and then answers the whole listing on every page; it narrows by time only
    with a named ``searchtimestamp:`` or a request-body ``timestamp``, while the query-string
    ``timestamp`` and a named ``timestamp:`` are both ignored (measured on the hosted MISP
    2026-10-16). Without a guard, on a MISP with ``MISP_EVENTS_INDEX_PAGE_SIZE`` or more events
    every page would repeat the listing up to the page cap, and each event would be processed once
    per page. The loop therefore de-duplicates rows by event id, stops when a page brings no new id,
    and stops when a page holds more rows than the requested ``limit`` (the server ignored it, so
    that answer is the whole listing).

    PR-K2 §1-2 — server-side ``timestamp`` narrowing:
    when ``since`` is not None, pass ``timestamp = int(since.timestamp())``
    as a query parameter so MISP narrows the result set on the server side
    BEFORE pagination. The prior implementation only filtered client-side
    (``_event_covers_since`` at the post-loop comprehension), which meant
    a re-triggered baseline against a populated MISP would walk up to
    ``MISP_EVENTS_INDEX_MAX_PAGES`` × ``MISP_EVENTS_INDEX_PAGE_SIZE``
    rows of the entire MISP instance (including non-EdgeGuard events
    from federated peers) before any filtering kicked in. On large
    deployments the 100-page cap silently truncated — events past page
    100 never made it to ``full_neo4j_sync``, exactly the
    ``EdgeGuardSyncCoverageGap`` failure mode the alert was built to
    catch (the gap was UPSTREAM of the accounting, so the alert never
    fired).

    The PyMISP and ``/events/restSearch`` fallback paths already use
    this convention (see lines ~977 + ~997). This brings the index
    path into parity. Older MISP versions that ignore the ``timestamp``
    param degrade gracefully — the client-side ``_event_covers_since``
    filter at the post-loop comprehension stays as defense-in-depth.
    2026-10: MISP 2.5.45 ignores this query-string ``timestamp`` (see
    above), so on that version only the client-side filter narrows.
    """
    base = misp_base.rstrip("/")
    INDEX_FETCH_STATE["truncated"] = False
    for path in ("/events/index", "/events"):
        pages: List[Dict[str, Any]] = []
        seen_ids: set = set()
        path_unusable = False
        truncated = False
        for page in range(1, MISP_EVENTS_INDEX_MAX_PAGES + 1):
            try:
                params: dict = {"limit": MISP_EVENTS_INDEX_PAGE_SIZE, "page": page}
                # Server-side narrowing — see docstring above for context.
                if since is not None:
                    params["timestamp"] = int(since.timestamp())
                resp = session.get(
                    f"{base}{path}",
                    params=params,
                    verify=SSL_VERIFY,
                    timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
                )
            except requests.RequestException as exc:
                logger.warning("[FETCH] GET %s page=%s: %s", path, page, exc)
                if page == 1:
                    path_unusable = True
                    break
                # A later page failing leaves the listing incomplete: never hand back the pages read
                # so far as the whole listing. Transient errors re-run the listing (@retry_with_backoff).
                if isinstance(
                    exc,
                    (
                        requests.exceptions.ConnectionError,
                        requests.exceptions.Timeout,
                        requests.exceptions.ChunkedEncodingError,
                    ),
                ):
                    raise
                raise _MispFallbackHardError(f"MISP index {path} page {page}: {exc}") from exc
            failure = None
            payload = None
            if resp.status_code != 200:
                failure = f"HTTP {resp.status_code}"
            else:
                try:
                    payload = resp.json()
                except ValueError:
                    failure = "a non-JSON answer"
            if failure is None and not _is_misp_index_listing(payload):
                # e.g. HTTP 200 with {"errors": ...}: an error object, not an empty listing.
                failure = f"a {type(payload).__name__} that is not an event listing"
            if failure is not None:
                if page == 1:
                    path_unusable = True
                    break
                raise _MispFallbackHardError(
                    f"MISP index {path} answered {failure} on page {page} after {page - 1} good page(s) "
                    f"({len(pages)} rows): the listing is incomplete"
                )
            norm = normalize_misp_event_index_payload(payload)
            if not norm:
                break
            new_rows = []
            for ev in norm:
                eid = ev.get("id")
                if eid is None:
                    # Kept: run() counts a row without an id as a failed event.
                    new_rows.append(ev)
                elif str(eid) not in seen_ids:
                    seen_ids.add(str(eid))
                    new_rows.append(ev)
            if page > 1 and not any(ev.get("id") is not None for ev in new_rows):
                # Only events already listed: the server ignored ``page`` and answered the whole
                # listing again, so the listing is complete.
                break
            pages.extend(new_rows)
            if len(norm) > MISP_EVENTS_INDEX_PAGE_SIZE:
                # More rows than the requested ``limit``: the server ignored it and answered the
                # whole listing, so a next page would only repeat it.
                break
            if len(norm) < MISP_EVENTS_INDEX_PAGE_SIZE:
                break
            if page == MISP_EVENTS_INDEX_MAX_PAGES:
                # The last allowed page was full: the listing most likely continues.
                truncated = True
        if path_unusable:
            continue
        if truncated:
            INDEX_FETCH_STATE["truncated"] = True
            logger.warning(
                "[FETCH] Index %s stopped at the page cap (%d pages × %d rows = %d events): events beyond the cap "
                "were not listed and the run is reported as failed — raise EDGEGUARD_MISP_MAX_PAGES",
                path,
                MISP_EVENTS_INDEX_MAX_PAGES,
                MISP_EVENTS_INDEX_PAGE_SIZE,
                len(pages),
            )
        filtered = [ev for ev in pages if _is_edgeguard_index_event(ev) and _event_covers_since(ev, since)]
        logger.info(
            "[FETCH] Index %s: %s event(s) from API, %s after EdgeGuard filter (since=%s)",
            path,
            len(pages),
            len(filtered),
            since,
        )
        return filtered
    return None


def _warn_neo4j_sync_single_pass(n_items: int, raw_setting: str) -> None:
    """Advise operators that 0/all disables Python-side chunking (expert / debugging only)."""
    if n_items > NEO4J_SYNC_SINGLE_PASS_STRONG_WARN_THRESHOLD:
        logger.warning(
            "EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%r — single-pass MISP→Neo4j sync for %s items "
            "(very high OOM risk on typical Airflow workers; use only with ample RAM or for debugging).",
            raw_setting,
            n_items,
        )
    elif n_items > NEO4J_SYNC_SINGLE_PASS_WARN_THRESHOLD:
        logger.warning(
            "EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%r — single-pass sync for %s items; ensure the worker "
            "has enough memory (default chunking is safer for large backfills).",
            raw_setting,
            n_items,
        )
    else:
        logger.info(
            "EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%r — single-pass sync (%s items; no Python-side chunking).",
            raw_setting,
            n_items,
        )


def _parse_neo4j_sync_chunk_size(raw: Optional[str], n_items: int) -> Tuple[int, str, bool]:
    """
    Parse ``EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`` into an effective chunk size.

    Returns:
        ``(chunk_size, label_for_logs, explicit_single_pass)``.
        ``explicit_single_pass`` is True when the operator set ``0`` or ``all`` (not merely
        "one chunk because item count is small").

    Semantics (documented in README / AIRFLOW_DAGS.md):

    - **Unset / empty:** ``500`` (``NEO4J_SYNC_CHUNK_SIZE_DEFAULT``).
    - **``0`` or ``all``** (case-insensitive, stripped): one Python chunk for the entire sorted
      list — same memory profile as pre-chunking sync (**OOM risk** on large attribute counts).
      For experts, large-RAM workers, or A/B debugging only.
    - **Positive integer:** max items per chunk (``max(1, int)``).
    - **Invalid / negative:** fall back to default with a warning.

    ``Neo4jClient.merge_indicators_batch`` / ``merge_vulnerabilities_batch`` still UNWIND in
    sub-batches regardless of this setting.
    """
    raw_in = (raw or "").strip()
    if not raw_in:
        return NEO4J_SYNC_CHUNK_SIZE_DEFAULT, str(NEO4J_SYNC_CHUNK_SIZE_DEFAULT), False

    lowered = raw_in.lower()
    if lowered == "all" or lowered == "0":
        _warn_neo4j_sync_single_pass(n_items, raw_in)
        return max(1, n_items), raw_in, True

    try:
        v = int(raw_in, 10)
    except ValueError:
        logger.warning(
            "Invalid EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%r — using default %s",
            raw_in,
            NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
        )
        return (
            NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
            f"{raw_in!r} (invalid → {NEO4J_SYNC_CHUNK_SIZE_DEFAULT})",
            False,
        )

    if v == 0:
        _warn_neo4j_sync_single_pass(n_items, raw_in)
        return max(1, n_items), raw_in, True

    if v < 0:
        logger.warning(
            "Invalid EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%r (negative) — using default %s",
            raw_in,
            NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
        )
        return (
            NEO4J_SYNC_CHUNK_SIZE_DEFAULT,
            f"{raw_in!r} (negative → {NEO4J_SYNC_CHUNK_SIZE_DEFAULT})",
            False,
        )

    return max(1, v), raw_in, False


def _item_is_vulnerability_sync_bucket(item: Dict) -> bool:
    """
    True if the item belongs in the vulnerability/CVE merge path (batch or single).

    Avoids treating ``'cve_id' in item`` with a null ``cve_id`` value as a vulnerability (bad bucket).
    """
    if item.get("type") == "vulnerability":
        return True
    cid = item.get("cve_id")
    return cid is not None and bool(str(cid).strip())


_URLHAUS_ENTRY_RE = re.compile(r"urlhaus\.abuse\.ch/url/(\d+)", re.IGNORECASE)

# 2026-10: an attribute comment that is a metadata block — ``NVD_META:``, ``OTX_META:``, ``TF_META:`` or
# any other ``*_META:`` block, ``MITRE_USES_TECHNIQUES:`` and ``MITRE_TACTIC_PHASES:`` (MISPWriter),
# ``CURATED_CLAIMS:`` (the curated-package importer). The block is data for the sync, never text for a
# node; MISPWriter writes an entity's description on the line after a ``MITRE_*`` block's JSON.
_METADATA_COMMENT_RE = re.compile(
    r"^\s*(?P<prefix>[A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|"
    + re.escape(CURATED_CLAIMS_PREFIX.rstrip(":"))
    + r"):"
)

# 2026-10: plain vulnerability comments that say where a CVE was seen, not what it is: the OTX
# collector's pulse reference ("Referenced in OTX pulse: <name>", a ``cve_references`` item) and
# MISPWriter's placeholder for a CVE item without text ("CVE from <source>"). Neither is a description:
# taken as one, OTX's note would describe a CVE that no NVD, KEV or CISA ICS record describes (OTX ranks
# below them, ``description_ranking``, 2026-10-16; until then the first such note to reach a CVE without
# an NVD record stayed there and CISA's KEV text never replaced it). The note stays the comment of the
# MISP attribute, which the node's ``misp_attribute_ids`` name.
# The placeholder names a source id (lowercase, as MISPWriter writes the item's tag), so a text such as
# "CVE from Microsoft" is kept (2026-10, the rule the entity placeholders follow).
_CVE_PROVENANCE_NOTE_RE = re.compile(r"^\s*(?:Referenced in OTX pulse:.*|CVE from [a-z0-9_-]+\s*)$", re.DOTALL)


def _comment_description(raw_comment: Any) -> Optional[str]:
    """The description an attribute comment gives, or None (2026-10).

    A plain comment is the description. A metadata block (``_METADATA_COMMENT_RE``) gives its own
    ``description`` field when its JSON has one, else the text MISPWriter writes after the JSON (the
    entity description that follows a ``MITRE_*`` block), else nothing; its raw text never becomes a
    description. Before 2026-10 the vulnerability branch stored the whole block: a CVE that an OTX pulse
    listed as an indicator showed ``OTX_META:{"attack_ids": [...], ...}`` as its description.
    """
    if not isinstance(raw_comment, str) or not raw_comment.strip():
        return None
    match = _METADATA_COMMENT_RE.match(raw_comment)
    if not match:
        return raw_comment
    rest = raw_comment[match.end() :].lstrip()
    try:
        meta, end = json.JSONDecoder().raw_decode(rest)
    except ValueError:
        logger.debug("Unreadable %s comment — no description taken from it", match.group("prefix"))
        return None
    description = meta.get("description") if isinstance(meta, dict) else None
    if isinstance(description, str) and description.strip():
        return description
    return rest[end:].strip() or None


def _vulnerability_report_ids(raw_comment: Any, ref: str = "") -> Dict[str, Any]:
    """``{"pulse_id", "report_ids"}`` of a vulnerability attribute whose comment is an ``OTX_META`` block
    (2026-10-18), each key only when the block gives it as a non-blank string / a list of them; ``{}``
    for any other comment. An unreadable block names no pulse."""
    if not isinstance(raw_comment, str) or not raw_comment.startswith("OTX_META:"):
        return {}
    try:
        meta = _meta_object(json.loads(raw_comment[len("OTX_META:") :]), "OTX_META", ref)
    except ValueError:
        logger.debug("Unreadable OTX_META comment of vulnerability attribute %s — no pulse taken from it", ref)
        return {}
    out: Dict[str, Any] = {}
    pulse_id = meta.get("pulse_id")
    if isinstance(pulse_id, str) and pulse_id.strip():
        out["pulse_id"] = pulse_id.strip()
    report_ids = [str(x).strip() for x in _meta_list(meta, "report_ids") if str(x).strip()]
    if report_ids:
        out["report_ids"] = report_ids
    return out


def _vulnerability_comment_description(raw_comment: Any) -> Optional[str]:
    """The description a vulnerability attribute's comment gives, or None (2026-10):
    ``_comment_description``, except a note that says where the CVE was seen (``_CVE_PROVENANCE_NOTE_RE``)."""
    description = _comment_description(raw_comment)
    if description is None or _CVE_PROVENANCE_NOTE_RE.match(description):
        return None
    return description


# 2026-10: MISPWriter's comment for a malware, actor, technique, tactic or tool item without text — "Malware
# from <source>", "Threat actor from <source>", "MITRE ATT&CK technique from <source>", "MITRE ATT&CK
# tactic", "MITRE ATT&CK tool: <name>". It names the writer, not the entity; taken as a description it would
# describe a node no other record describes, and keep a lower-ranked source's text off it (the source
# ranking, ``description_ranking``, 2026-10-16; until then any record but MITRE's only filled).
# <source> is the item's tag, a lowercase source id ("alienvault_otx", "mitre_attck", "unknown"), so a
# partner's or a MISP-native text such as "Threat actor from Iran" or "Malware from APT28" stays a description.
_ENTITY_PLACEHOLDER_COMMENT_RE = re.compile(
    r"^\s*(?:(?:Malware|Threat actor|MITRE ATT&CK technique) from [a-z0-9_-]+|MITRE ATT&CK tactic|"
    r"MITRE ATT&CK tool: [^\n]+)\s*$"
)

# 2026-10: a metadata block anywhere in a text. The actor and tool branches find a ``MITRE_USES_TECHNIQUES``
# block anywhere in the comment, ``_comment_description`` only at its start, so a comment with text before
# the block would otherwise hand the block on as part of the description.
_EMBEDDED_METADATA_RE = re.compile(
    r"\b(?:[A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|"
    + re.escape(CURATED_CLAIMS_PREFIX.rstrip(":"))
    + r"):\s*[\[{]"
)

# 2026-10: sources whose malware and actor attributes carry a report's text, not the entity's. Until
# 2026-10 the OTX collector gave every malware family and adversary of a pulse the pulse's description,
# which MISPWriter wrote after the attribute's ``MITRE_USES_TECHNIQUES`` block; MISP keeps those attributes,
# since MISPWriter writes a family or adversary once per source and skips it in later pulses. The OTX
# collector gives such items no description since then.
_REPORT_TEXT_ENTITY_SOURCES = frozenset({"alienvault_otx"})


# 2026-10: the STIX types a Malware, ThreatActor, Technique, Tactic or Tool attribute becomes.
_ENTITY_STIX_TYPES = frozenset({"malware", "intrusion-set", "threat-actor", "tool", "attack-pattern", "x-mitre-tactic"})


def _event_source_id(event_info: Any) -> str:
    """The source id in an EdgeGuard event name (``EdgeGuard-<source>-<date>``), or ``""``."""
    parts = str(event_info or "").split("-")
    return parts[1] if len(parts) >= 3 and parts[0] == "EdgeGuard" else ""


def _filter_entity_stix_description(obj: Dict[str, Any], source_id: str) -> None:
    """In place (2026-10): an entity object's ``description`` follows the rule of the attribute
    parse (``_entity_comment_description``). PyMISP's own conversion copies the attribute comment,
    which may be a metadata block, MISPWriter's placeholder or an OTX pulse's text."""
    if obj.get("type") not in _ENTITY_STIX_TYPES or "description" not in obj:
        return
    text = _entity_comment_description(obj.get("description"), source_id)
    if text:
        obj["description"] = text
    else:
        obj.pop("description", None)


def _entity_comment_description(raw_comment: Any, source_id: str) -> Optional[str]:
    """The description a malware, actor, technique, tactic or tool attribute's comment gives, or None (2026-10).

    ``_comment_description`` (never a metadata block's raw text; the text MISPWriter writes after a
    ``MITRE_*`` block's JSON), except MISPWriter's placeholder for an item without text
    (``_ENTITY_PLACEHOLDER_COMMENT_RE``), a text that still holds a metadata block
    (``_EMBEDDED_METADATA_RE``) and the comment of an attribute from a source in
    ``_REPORT_TEXT_ENTITY_SOURCES`` (OTX: a pulse's description). Before 2026-10 the malware branch
    stored a comment that was only a ``MITRE_USES_TECHNIQUES`` block (an OTX family from a pulse without
    a description) as the Malware description, and the branches that read a block stored the raw comment
    when it did not parse.
    """
    if source_id in _REPORT_TEXT_ENTITY_SOURCES:
        return None
    description = _comment_description(raw_comment)
    if description is None:
        return None
    if _ENTITY_PLACEHOLDER_COMMENT_RE.match(description) or _EMBEDDED_METADATA_RE.search(description):
        return None
    return description


def _item_source_refs(item: Dict, source: str) -> List[str]:
    """The feed's own record ids behind ``item``, each as ``"<source>:<id>"`` (2026-10).

    Covers the feeds that give a record id of their own: the OTX pulse (``pulse_id`` plus
    the other pulses of the run in ``report_ids``), the ThreatFox IOC id, the URLhaus entry,
    the MITRE ATT&CK id and (2026-10-16) the CISA ICS advisories that name the CVE
    (``advisory_ids`` from ``NVD_META``, e.g. ``cisa_ics:ICSA-24-123-01``). Feeds keyed by the
    value itself (NVD and KEV by CVE id, MalwareBazaar and VirusTotal by hash, Feodo Tracker
    and AbuseIPDB by IP, SSL Blacklist by certificate hash) need none: the node is the record.
    """
    record_ids: List[object] = []
    if source == "alienvault_otx":
        record_ids = [item.get("pulse_id")] + list(item.get("report_ids") or [])
    elif source == "threatfox":
        record_ids = [item.get("ioc_id")]
    elif source == "urlhaus":
        match = _URLHAUS_ENTRY_RE.search(str(item.get("reference") or ""))
        record_ids = [match.group(1)] if match else []
    elif source == "mitre_attck":
        record_ids = [item.get("mitre_id")]
    elif source == "cisa_ics":
        record_ids = list(item.get("advisory_ids") or [])
    refs: List[str] = []
    for record_id in record_ids:
        ref = format_source_ref(source, record_id)
        if ref and ref not in refs:
            refs.append(ref)
    return refs


def _item_zone_refs(item: Dict, source: str) -> Dict[str, List[str]]:
    """Zone → the feed's record references behind ``item`` that stated that zone (2026-10-16).

    Only for a feed whose records state zones themselves (``sector_evidence.stated_refs`` keeps the zones
    of the item that are stated). CISA ICS: the CVE item unites the advisories that name the CVE
    (``advisory_zones`` from ``NVD_META``, advisory id → its zones), and each sector cites only the
    advisories that name it. OTX (2026-10-18): the item's pulse (``pulse_id``) for each zone its own
    industries (``otx_industries``) map to, and each later pulse of the run that listed the item for the
    zones its industries state (``report_stated_zones``, ``"<zone>|<pulse id>"``, of the pulses in
    ``report_ids``). A zone no record of the item stated is not in the map: its sector link cites all of the
    item's references (``source_refs``: for OTX every pulse of the item, since EdgeGuard records no
    per-pulse reference for a keyword hit). ``{}`` for every other feed.
    """
    if source == "alienvault_otx":
        out: Dict[str, List[str]] = {}
        own = format_source_ref(source, item.get("pulse_id"))
        if own:
            for zone in sector_industry_zones(item.get("otx_industries")):
                out.setdefault(zone, []).append(own)
        reports = {str(x).strip() for x in (item.get("report_ids") or []) if str(x).strip()}
        for zone, report in sector_report_zone_pairs(item.get("report_stated_zones")):
            ref = format_source_ref(source, report) if report in reports else None
            if ref and ref not in out.get(zone, []):
                out.setdefault(zone, []).append(ref)
        return out
    if source != "cisa_ics":
        return {}
    advisory_zones = item.get("advisory_zones")
    if not isinstance(advisory_zones, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for advisory in sorted(advisory_zones):
        ref = format_source_ref(source, advisory)
        if not ref:
            continue
        for zone in advisory_zones[advisory]:
            out.setdefault(zone, []).append(ref)
    return out


def _tag_sector_evidence(source: Optional[str], sector: str, rel_type: str) -> Tuple[str, float]:
    """``(label, confidence)`` of the row a ``sector:`` / ``target-sector:`` tag gives (2026-10-18).

    EdgeGuard's writers never set such a tag; a partner's attribute may. The tag is no statement EdgeGuard
    tracks, so the row is ``zone_classification`` at the table's confidence (``sector_evidence``), whatever
    the attribute's ``confidence:`` tag says: at that tag's 0.8 a row outweighed a stated link (the batched
    writer keeps the label of the row whose confidence reaches the stored one) and left the link at a
    confidence its label does not give. A ``sector:`` tag of a tracked zone is also one of the item's zones
    (``extract_zones_from_tags``), whose row follows the rule of the item's feed.
    """
    return sector_link_evidence(source, sector, None, rel_type)


def _meta_advisory_zones(meta: Dict[str, Any]) -> Dict[str, List[str]]:
    """``NVD_META.advisory_zones`` (2026-10-16): advisory id → its sorted, lower-case specific zones; ``{}``
    when absent or not a map. A value that is not a list gives the advisory no zone."""
    value = meta.get("advisory_zones")
    if not isinstance(value, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for advisory in sorted(k for k in value if isinstance(k, str) and k.strip()):
        zones = value[advisory]
        listed = _scalar_strings(zones) if isinstance(zones, list) else []
        out[advisory.strip()] = sorted(
            {z.strip().lower() for z in listed if z.strip() and z.strip().lower() != "global"}
        )
    return out


# ---------------------------------------------------------------------------
# Curated packages (2026-10)
# ---------------------------------------------------------------------------
# A curated package is imported once into MISP as its own event (``scripts/
# import_curated_package.py``). Each actor / malware attribute names an existing node and
# carries that node's claims in its comment:
#
#   CURATED_CLAIMS:{"c": [{"p": "uses_technique", "o": "T1566", "src": "coreideas", "id": "<id>"}]}
#
# ``p`` is the predicate, ``o`` the object's key (ATT&CK id, malware name, Tool S-id, CVE id),
# ``src`` the source that asserts the claim (defaults to the package's source) and ``id`` that
# source's record id. Every claim becomes a relationship written with MATCH on both ends: a link
# the claim creates is labelled with the package's curated label (``coreideas_curated``, else
# ``curated_other``) at 0.85; a link that already exists keeps its label and confidence and
# gains the claim's provenance. A curated attribute is not merged as a node (``sync_to_neo4j``
# skips it): a package never creates nodes and never changes the node it names. The item still
# carries no description, types, zones or TLP, so nothing leaks if it ever reached a merge.
_CURATED_MAX_CLAIMS_PER_ATTRIBUTE = 2000
_CURATED_PREDICATES = CURATED_PREDICATES


def _parse_curated_claims(raw_comment: str) -> Optional[List[Dict]]:
    """The claims of a ``CURATED_CLAIMS:`` comment; ``None`` when the comment is not one."""
    text = (raw_comment or "").strip()
    if not text.startswith(CURATED_CLAIMS_PREFIX):
        return None
    rest = text[len(CURATED_CLAIMS_PREFIX) :].lstrip()
    newline = rest.find("\n")
    json_part = rest if newline < 0 else rest[:newline]
    try:
        meta = json.loads(json_part)
    except (ValueError, TypeError):
        logger.warning("Unreadable %s comment — the attribute's claims were not taken", CURATED_CLAIMS_PREFIX)
        return []
    claims = meta.get("c") if isinstance(meta, dict) else None
    if not isinstance(claims, list):
        return []
    if len(claims) > _CURATED_MAX_CLAIMS_PER_ATTRIBUTE:
        logger.warning(
            "%s: %d claims on one attribute, taking the first %d",
            CURATED_CLAIMS_PREFIX,
            len(claims),
            _CURATED_MAX_CLAIMS_PER_ATTRIBUTE,
        )
    return [c for c in claims[:_CURATED_MAX_CLAIMS_PER_ATTRIBUTE] if isinstance(c, dict)]


def _curated_claims_tlp(tags: List[Dict[str, Any]], event_info: Dict, ref: str = "") -> str:
    """The TLP level of a curated attribute's claims (2026-10): its own ``tlp:`` tag, else the event's.

    The importer tags every curated attribute with the package's level; an event imported
    before that carries the level on the event only. With neither, the deployment default
    applies (``_extract_tlp_tag``). The level marks each claim's link (``r.tlp``), so the STIX
    relationship is as restricted as the package.
    """
    return _extract_tlp_tag(list(tags) + normalize_misp_tag_list(event_info.get("Tag", [])), ref)


def _curated_claim_rows(
    claims: List[Dict],
    subject_type: str,
    subject_key: Dict[str, str],
    package_source: str,
    evt_id: str,
    tlp: str = "",
) -> List[Dict]:
    """Relationship rows for one curated subject's claims (see ``CURATED_CLAIMS_PREFIX``).

    ``tlp`` is the package's TLP level (``_curated_claims_tlp``), carried on every row. A technique
    id ATT&CK revoked is translated to its successor (2026-10, ``attack_revoked``) and logged; the
    row keeps the id the claim named in ``cited_ids`` (``r.cited_ids`` on the link).
    """
    label = curated_label_for(package_source)
    revoked = load_revoked_ids()
    rows: List[Dict] = []
    skipped = 0
    unregistered = 0
    translated: List[str] = []
    for claim in claims:
        target = _CURATED_PREDICATES.get(str(claim.get("p") or "").strip().lower(), {}).get(subject_type)
        obj = str(claim.get("o") or "").strip()
        if target is None or not obj:
            skipped += 1
            continue
        rel_type, to_type, key = target
        cited: List[str] = []
        if key == "cve_id":
            obj = normalize_cve_id_for_graph(obj) or ""
        elif key == "mitre_id":
            obj = obj.upper()
            successor = revoked.technique_successor(obj) if to_type == "Technique" else None
            if successor is not None:
                translated.append(f"{obj} -> {successor}")
                cited = [obj]
                obj = successor
        if not obj:
            skipped += 1
            continue
        source = canonical_source_id(claim.get("src")) or package_source
        # 2026-10: only a registered curated source may assert a claim (the importer refuses any
        # other). A claim that still names another source — an event written by hand or by an
        # older importer — is recorded as ``curated_other``, so no outside name reaches
        # ``r.sources``, ``r.source_refs`` or the STIX export.
        if not is_curated_source(source):
            source = CURATED_OTHER_LABEL
            unregistered += 1
        ref = format_source_ref(source, claim.get("id"))
        rows.append(
            {
                "rel_type": rel_type,
                "from_type": subject_type,
                "from_key": dict(subject_key),
                "to_type": to_type,
                "to_key": {key: obj},
                "confidence": CURATED_CLAIM_CONFIDENCE,
                "match_type": label,
                "source": source,
                "source_refs": [ref] if ref else [],
                "misp_event_id": evt_id,
                # exact canonical names on both ends — never alias matching (see the writer)
                "exact_names": True,
                "tlp": tlp or None,
                # 2026-10: the revoked id the claim named, when it was translated (r.cited_ids)
                "cited_ids": cited,
            }
        )
    if skipped:
        logger.info(
            "Curated %s %s: %d claim(s) skipped (unknown predicate for this subject, or no object)",
            subject_type,
            next(iter(subject_key.values()), "?"),
            skipped,
        )
    if translated:
        logger.info(
            "Curated %s %s: %d claim(s) name a technique id ATT&CK revoked, linked to its successor (%s)",
            subject_type,
            next(iter(subject_key.values()), "?"),
            len(translated),
            ", ".join(sorted(set(translated))[:10]),
        )
    if unregistered:
        logger.warning(
            "Curated %s %s: %d claim(s) name a source that is not a registered curated source (%s); recorded as %r",
            subject_type,
            next(iter(subject_key.values()), "?"),
            unregistered,
            ", ".join(curated_source_ids()),
            CURATED_OTHER_LABEL,
        )
    return rows


def _merge_duplicate_report(kept: Dict[str, Any], dup: Dict[str, Any]) -> None:
    """Fold the report of ``dup`` (the same indicator and source as ``kept``) into ``kept``: the
    later report time with its reference and kind (an equal time goes to the smaller reference),
    the later MISP record time, and the higher confidence (2026-10-16)."""
    dup_key, kept_key = _report_key(dup), _report_key(kept)
    if dup_key is not None and (
        kept_key is None or dup_key[0] > kept_key[0] or (dup_key[0] == kept_key[0] and dup_key[1:] < kept_key[1:])
    ):
        for field in ("reported_at", "report_ref", "reported_basis"):
            kept[field] = dup.get(field)
    kept["recorded_at"] = _later_iso(kept.get("recorded_at"), dup.get("recorded_at"))
    dup_conf, kept_conf = dup.get("confidence_score"), kept.get("confidence_score")
    if isinstance(dup_conf, (int, float)) and (not isinstance(kept_conf, (int, float)) or dup_conf > kept_conf):
        kept["confidence_score"] = dup_conf


def _dedupe_parsed_items(items: List[Dict]) -> List[Dict]:
    """
    Deduplicate parsed items within a single MISP event (keys match former global dedupe).

    Used so cross-item relationship building only sees one row per logical entity per event.
    """
    seen = set()
    unique_items: List[Dict] = []
    _kept_by_key: Dict[str, Dict] = {}  # 2026-10: first item per key, to collect extra report ids
    # PR #33 round 13: track drop reasons separately so the Prometheus counter
    # has labelled buckets ("missing_cve_id" vs "missing_key") for alerting.
    _dropped_by_reason: Dict[str, int] = {}
    for item in items:
        tag = item.get("tag", "default")
        if _item_is_vulnerability_sync_bucket(item):
            cid = resolve_vulnerability_cve_id(item)
            if cid:
                key = f"cve:{cid}"  # no tag — CVE merges on cve_id only
            else:
                logger.debug("Dedup: dropping vulnerability with unresolvable CVE ID (tag=%s)", tag)
                _dropped_by_reason["missing_cve_id"] = _dropped_by_reason.get("missing_cve_id", 0) + 1
                continue
        elif item.get("value"):
            # Indicators merge on (indicator_type, value) — no tag
            key = f"{item.get('indicator_type', 'unknown')}:{item['value']}"
        elif item.get("mitre_id"):
            # Techniques, tactics, tools merge on mitre_id — check BEFORE name
            key = f"{item.get('type', 'technique')}:{item['mitre_id']}"
        elif item.get("name"):
            # Actors, malware merge on name only
            key = f"{item['type']}:{item['name']}"
        else:
            logger.debug("Dedup: dropping item with no identifiable key (type=%s, tag=%s)", item.get("type"), tag)
            _dropped_by_reason["missing_key"] = _dropped_by_reason.get("missing_key", 0) + 1
            continue

        if key not in seen:
            seen.add(key)
            unique_items.append(item)
            _kept_by_key[key] = item
        else:
            # 2026-10: the same entity listed in several OTX pulses of one event keeps
            # every report id, so report-scoped linking links it to all of them
            # (``_build_cross_item_relationships`` reads ``pulse_id`` + ``report_ids``).
            kept = _kept_by_key.get(key)
            if kept is not None:
                # the duplicate's own pulse id plus any report ids it already carried
                for rid in [item.get("pulse_id")] + list(item.get("report_ids") or []):
                    if rid and rid != kept.get("pulse_id"):
                        extra = kept.setdefault("report_ids", [])
                        if rid not in extra:
                            extra.append(rid)
                # ... and every feed record id the duplicate carried (``source_refs``)
                for ref in item.get("source_refs") or []:
                    kept_refs = kept.setdefault("source_refs", [])
                    if ref not in kept_refs:
                        kept_refs.append(ref)
                # ... and the pulses among them that name several actors (2026-10), judged with the
                # canonical reference or, without it, by name
                for marks_field in ("several_actor_pulses", "several_actor_pulses_by_name"):
                    for pid in item.get(marks_field) or []:
                        kept_several = kept.setdefault(marks_field, [])
                        if pid not in kept_several:
                            kept_several.append(pid)
                # 2026-10-16 (indicator aging): the latest report of the same source and the highest
                # confidence, whichever duplicate came first, so either order writes the same node
                # (``indicator_aging``). A duplicate of another source is dropped as before.
                if item.get("indicator_type") and kept.get("indicator_type") and item.get("tag") == kept.get("tag"):
                    _merge_duplicate_report(kept, item)
    _dropped = sum(_dropped_by_reason.values())
    _dupes = len(items) - len(unique_items) - _dropped
    if _dropped or _dupes:
        logger.info(
            "Dedup: %s items → %s unique (%s duplicates removed, %s dropped: %s)",
            len(items),
            len(unique_items),
            _dupes,
            _dropped,
            _dropped_by_reason or "{}",
        )
    # PR #33 round 13: emit per-reason drop counter so an operator can graph
    # the silent-skip rate (e.g. spikes in missing_cve_id signal upstream
    # parsing regressions). Wrap in try/except so a metrics outage doesn't
    # break ingest.
    #
    # NB (PR #33 round 15): the import is inline (inside try/except) so the
    # metrics_server module isn't a hard dependency for the ingest path —
    # bugbot's static analysis flagged record_misp_attribute_dropped as
    # "unused" because it doesn't follow inline-import call chains. This is
    # the canonical call site; pinned by
    # test_misp_attributes_dropped_metric_exists_and_is_emitted.
    if _dropped_by_reason:
        try:
            from metrics_server import record_misp_attribute_dropped

            for reason, count in _dropped_by_reason.items():
                record_misp_attribute_dropped(reason, count)
        except Exception:
            logger.debug("Metrics recording for dropped attributes failed", exc_info=True)
    return unique_items


# Max relationship definitions per Neo4j UNWIND batch (see ``Neo4jClient.create_misp_relationships_batch``).
# 500 rows per UNWIND batch — smaller batches reduce lock contention on shared nodes.
_RELATIONSHIP_BATCH_DEFAULT = 500


# Default of ``EDGEGUARD_SYNC_MIN_EVENTS``: a sync window must hold at least one EdgeGuard event.
# Scheduled syncs are at least NEO4J_SYNC_MIN_GAP (24 h) apart and the collectors write to MISP
# every day (OTX every 30 minutes), so an empty window means nothing was collected; as a success
# it would also move the sync cursor past the gap.
_SYNC_MIN_EVENTS_DEFAULT = 1


def _sync_min_events() -> int:
    """Parse ``EDGEGUARD_SYNC_MIN_EVENTS`` (non-negative integer, default 1; 0 disables the guard).

    ``MISPToNeo4jSync.run`` treats a fetch window that returns fewer than N events as a failed
    run instead of an empty success. Unset or empty selects the default; a value that is not a
    non-negative integer is rejected with a WARNING and treated as the default. Read per call so
    Airflow tasks pick up the environment at fork time.
    """
    raw = (os.environ.get("EDGEGUARD_SYNC_MIN_EVENTS") or "").strip()
    if not raw:
        return _SYNC_MIN_EVENTS_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Invalid EDGEGUARD_SYNC_MIN_EVENTS=%r — expected a non-negative integer; using default %d",
            raw,
            _SYNC_MIN_EVENTS_DEFAULT,
        )
        return _SYNC_MIN_EVENTS_DEFAULT
    if value < 0:
        logger.warning("EDGEGUARD_SYNC_MIN_EVENTS=%s is negative; using default %d", value, _SYNC_MIN_EVENTS_DEFAULT)
        return _SYNC_MIN_EVENTS_DEFAULT
    return value


# The feed named in ``r.sources`` on relationships built from items that share the same
# source report (today: the OTX pulse; the evidence label is ``otx_pulse``). Replaces the
# pre-2026-10 whole-event ``misp_cooccurrence`` edges — see
# ``_build_cross_item_relationships``. Until 2026-10 this held the label ``otx_pulse``
# itself, so no relationship named the feed.
_REPORT_SCOPED_SOURCE_ID = "alienvault_otx"

# Cap how many exception-failed events we retry. Beyond this, MISP is almost
# certainly broken and retrying more events just burns wall-clock against the
# Airflow execution_timeout (NVD sync DAG = 2h). The remaining events are
# counted as failed immediately so operators see the real damage.
_MAX_RETRY_FAILED_EVENTS = 20


def _read_max_attr_value_bytes() -> int:
    """Resolve ``EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES`` once at module load.

    PR #40 commit X (bugbot MED): the previous code called
    ``int(os.getenv("EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES", "4096"))`` INSIDE
    ``parse_attribute`` — invoked per attribute, i.e. millions of times per
    baseline run. Trivially cheap per call (low-microsecond) but cumulatively
    measurable, and any malformed env value would re-raise on every row
    instead of failing fast at startup.

    Reading once at import time also gives operators a clear startup error
    if they typo the value, instead of silent per-row spam.
    """
    raw = os.getenv("EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES", "4096").strip()
    try:
        parsed = int(raw)
    except (TypeError, ValueError):
        # Defensive: don't crash sync on a bad env value — fall back to default
        # and log so the operator sees it once.
        logger.warning(
            "EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES=%r is not an integer; using default 4096",
            raw,
        )
        return 4096
    # Clamp to a sane range — operator who sets 0 or negative would refuse all
    # attributes; operator who sets billions defeats the protection. Keep it
    # at "what an actual MISP value could plausibly be".
    if parsed < 64:
        logger.warning(
            "EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES=%d is below 64 (would refuse most legitimate values); using 64 floor",
            parsed,
        )
        return 64
    return parsed


_MAX_ATTR_VALUE_BYTES = _read_max_attr_value_bytes()


class MispTransientServerError(TransientServerError):
    """Raised manually for HTTP 5xx from MISP so @retry_with_backoff can catch
    it selectively. Inherits from ``collector_utils.TransientServerError`` so
    both the local ``retry_with_backoff`` in this module and the shared one
    in ``collector_utils`` (used by ``MISPWriter._push_batch``) retry it.
    Other ``HTTPError`` paths — e.g. 4xx raised via
    ``response.raise_for_status()`` — remain permanent failures."""


def _neo4j_sync_item_sort_rank(item: Dict) -> int:
    """Order items so tactics/techniques/malware/actors land before vulns/indicators when chunking."""
    t = item.get("type", "")
    if t == "tactic":
        return 0
    if t == "technique" or item.get("mitre_id"):
        return 1
    if t == "malware":
        return 2
    if t == "actor":
        return 3
    if _item_is_vulnerability_sync_bucket(item):
        return 4
    if item.get("indicator_type") and item.get("value"):
        return 5
    return 6


def retry_with_backoff(max_retries: int = MAX_RETRIES, base_delay: float = RETRY_DELAY_BASE):
    """Decorator for retry logic with exponential backoff."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):  # +1: first attempt + max_retries retries (matches collector_utils)
                try:
                    return func(*args, **kwargs)
                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ReadTimeout,
                    requests.exceptions.ChunkedEncodingError,
                    # Our own subclass for MISP 5xx. Subclassing HTTPError
                    # means future raise_for_status() calls on 4xx are NOT
                    # accidentally retried — only code that explicitly opts
                    # in by raising MispTransientServerError is retried.
                    MispTransientServerError,
                ) as e:
                    last_exception = e
                    if attempt >= max_retries:
                        break  # exhausted all retries
                    delay = base_delay * (2**attempt)
                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. Retrying in {delay}s..."
                    )
                    time.sleep(delay)
                except Exception as e:
                    # Non-retryable exception
                    logger.error(f"{func.__name__} failed with non-retryable error: {type(e).__name__}: {e}")
                    raise

            logger.error(f"{func.__name__} failed after {max_retries + 1} attempts")
            raise last_exception

        return wrapper

    return decorator


def _unwrap_single_misp_event_row(obj: Any) -> Optional[Dict[str, Any]]:
    """
    MISP REST and PyMISP often wrap events as ``{'Event': {id, info, Attribute, ...}}``.
    The sync and STIX loops expect a **flat** event dict so ``event.get('id')`` works.

    Delegates to ``misp_event_object_to_event_dict`` which is the canonical implementation.
    """
    return misp_event_object_to_event_dict(obj)


def normalize_misp_event_index_payload(raw: Any) -> List[Dict[str, Any]]:
    """
    Turn MISP ``events`` search / ``/events/restSearch`` / ``/events/index`` payloads into a list of flat event dicts.

    Handles:
    - ``[{'Event': {...}}, ...]`` (common)
    - ``{'response': [...]}`` / ``{'events': [...]}`` wrappers
    - single ``{'Event': {...}}`` object
    """
    if raw is None:
        return []
    if isinstance(raw, dict):
        if isinstance(raw.get("response"), list):
            raw = raw["response"]
        elif isinstance(raw.get("events"), list):
            raw = raw["events"]
        elif isinstance(raw.get("Event"), dict):
            raw = [raw]
        else:
            logger.warning(
                "MISP events payload is a dict with unexpected shape (keys: %s) — no events extracted",
                list(raw.keys())[:15],
            )
            return []
    if not isinstance(raw, (list, tuple)):
        logger.warning("MISP events payload type %s — expected list", type(raw).__name__)
        return []
    out: List[Dict[str, Any]] = []
    for i, item in enumerate(raw):
        ev = _unwrap_single_misp_event_row(item)
        if ev is not None:
            out.append(ev)
        else:
            logger.warning(
                "Skipping unparseable MISP event row #%s (type=%s)",
                i,
                type(item).__name__,
            )
    return out


def misp_event_object_to_event_dict(obj: Any) -> Optional[Dict[str, Any]]:
    """
    Normalize a single MISP event from PyMISP or REST ``/events/view`` into a flat Event dict.

    PyMISP ``get_event`` may return a ``MISPEvent`` instance, ``{'Event': {...}}``, or a flat dict.
    Using a non-dict without converting caused ``.get('Attribute')`` failures and empty Neo4j syncs.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        inner = obj.get("Event")
        if isinstance(inner, dict):
            return inner
        if "id" in obj or "info" in obj or "uuid" in obj or "Attribute" in obj:
            return obj
        return None
    to_dict = getattr(obj, "to_dict", None)
    if callable(to_dict):
        try:
            d = to_dict()
            if isinstance(d, dict):
                inner = d.get("Event")
                if isinstance(inner, dict):
                    return inner
                if "id" in d or "info" in d or "uuid" in d or "Attribute" in d:
                    return d
        except Exception as e:
            logger.debug("to_dict() failed on MISP event object (type=%s): %s", type(obj).__name__, e)
    return None


def coerce_misp_attribute_list(attrs: Any) -> List[Dict[str, Any]]:
    """MISP may return one attribute as a dict or many as a list; normalize to a list of dicts."""
    if attrs is None:
        return []
    if isinstance(attrs, dict):
        return [attrs]
    if isinstance(attrs, list):
        return [a for a in attrs if isinstance(a, dict)]
    return []


def normalize_misp_tag_list(tags: Any) -> List[Dict[str, Any]]:
    """
    MISP tags are usually ``[{'name': 'source:otx', ...}, ...]`` but some APIs return
    bare strings or a single dict — normalize so ``tag.get('name')`` is safe everywhere.
    """
    if tags is None:
        return []
    if isinstance(tags, dict):
        return [tags]
    if isinstance(tags, str):
        return [{"name": tags}]
    if not isinstance(tags, list):
        return [{"name": str(tags)}]
    out: List[Dict[str, Any]] = []
    for t in tags:
        if isinstance(t, dict):
            out.append(t)
        elif isinstance(t, str):
            out.append({"name": t})
        else:
            out.append({"name": str(t)})
    return out


def _meta_object(parsed: Any, prefix: str, ref: str = "") -> Dict[str, Any]:
    """A parsed ``<PREFIX>:`` comment as a dict; any other JSON value is treated as absent (2026-10).

    MISPWriter writes a JSON object after the prefix. A comment written by anyone else (a MISP
    user, a federated instance) can hold ``null``, a list, a number or a string there; ``.get``
    on such a value raised ``AttributeError``, which escaped the attribute's parse and failed its
    event, the run and every later incremental run. The attribute is kept without the metadata
    and the attribute's UUID (``ref``) is logged.
    """
    if isinstance(parsed, dict):
        return parsed
    logger.warning(
        "[META] %s comment of attribute %s holds a JSON %s, not an object — the metadata is ignored",
        prefix,
        ref or "?",
        type(parsed).__name__,
    )
    return {}


def _scalar_strings(values: List[Any]) -> List[str]:
    """The strings and numbers of a JSON list, numbers as strings; other elements dropped (2026-10).

    The lists reach node properties (``n.attack_ids``, ``n.targeted_countries``, ``uses_techniques``),
    and Neo4j refuses a property list holding a map, a list, a null or mixed types: the whole
    ``UNWIND`` batch then failed, and with it the run and every later incremental run. The lists
    MISPWriter writes hold strings only and pass unchanged.
    """
    return [
        x if isinstance(x, str) else str(x)
        for x in values
        if isinstance(x, str) or (isinstance(x, (int, float)) and not isinstance(x, bool))
    ]


def _meta_list(meta: Dict[str, Any], key: str) -> List[str]:
    """``meta[key]`` when it is a JSON list, as ``_scalar_strings``; otherwise ``[]`` (2026-10).

    A string such as ``"T1059"`` in a list-valued key is ignored instead of being iterated into
    its characters (``T``, ``1``, ``0``, ``5``, ``9``).
    """
    value = meta.get(key)
    return _scalar_strings(value) if isinstance(value, list) else []


def _meta_report_stated_zones(meta: Dict[str, Any], key: str, report_ids: List[str]) -> List[str]:
    """The ``"<zone>|<pulse id>"`` entries of ``meta[key]`` (``OTX_META.report_stated_zones``,
    ``MITRE_USES_TECHNIQUES.rsz``, 2026-10-18), normalised (``sector_evidence.report_zone_pairs``), of the
    pulses in ``report_ids`` only: a zone never rests on a pulse the item does not name."""
    reports = {str(x).strip() for x in report_ids if str(x).strip()}
    return [
        sector_report_zone_entry(zone, report)
        for zone, report in sector_report_zone_pairs(_meta_list(meta, key))
        if report in reports
    ]


_NEO4J_INT_RANGE = (-(2**63), 2**63 - 1)


# The numeric scores of a CVSS payload (2026-10-17): they must be finite numbers, whatever type the JSON gave.
_CVSS_SCORE_KEYS = frozenset({"base_score", "impact_score", "exploitability_score"})


def _finite_cvss_score(entry: Any) -> Optional[float]:
    """``entry`` as a finite float, or None when it is not a number, or a string that reads as one, or is not finite."""
    if isinstance(entry, bool):
        return None
    try:
        if isinstance(entry, (int, float)):
            number = float(entry)
        elif isinstance(entry, str):
            number = float(entry.strip())
        else:
            return None
    except (ValueError, OverflowError):
        # OverflowError: a JSON integer beyond the float range (json.loads keeps it as an int); it is no
        # usable score, and it must not fail the event's other attributes.
        return None
    return number if math.isfinite(number) else None


def _meta_cvss_payload(meta: Dict[str, Any], key: str, cve_id: str) -> Optional[Dict[str, Any]]:
    """``meta[key]``, a CVSS payload of ``NVD_META`` (``cvss_v31_data`` …), as a CVSS sub-node can hold it;
    None when it is absent or not a JSON object (2026-10).

    ``Neo4jClient._merge_cvss_node`` writes each entry of the payload as a property of the sub-node, so a
    payload that is not an object, a name that is not a property name (letters, digits, underscores) or a
    value that is not a string, a boolean or a number Neo4j can store made that write fail. Since
    ``merge_cve`` counts a failed CVSS sub-write as an error (2026-10), one such attribute would fail every
    sync until its MISP comment is edited. The payload is checked here instead, as ``ssvc`` is: a payload
    that is not an object counts as absent, so the record has no CVSS of that version (an NVD record then
    removes the sub-node only NVD asserted, as a rebuild from the same record gives), and an entry that is
    not a property, or has a name the writer keeps for itself (``CVSS_PAYLOAD_RESERVED_NAMES``: the sub-node's
    ``uuid``, ``timeout`` …), is dropped; both are logged with the CVE. The payloads the collectors write pass
    unchanged.

    A number that is not finite (``Infinity``, ``-Infinity``, ``NaN`` or ``1e309`` in the JSON, which
    ``json.loads`` reads as such floats) is dropped as well, as a missing value (2026-10-17): the sub-node
    would hold it, the GraphQL API cannot return it (a GraphQL ``Float`` is finite) and a JSON export would
    not be valid JSON. A payload left without a base score is malformed and counts as absent, like one that
    is not an object: a sub-node of it would have no score, and an earlier score of the same version would
    stay on the node. An empty object (``{}``, which an NVD record without the version carries) counts as
    absent without a warning, as before.
    """
    value = meta.get(key)
    if value is None:
        return None
    if not isinstance(value, dict):
        logger.warning(
            "[META] NVD_META.%s of %s is a JSON %s, not an object — the CVE is read without it",
            key,
            cve_id,
            type(value).__name__,
        )
        return None
    payload: Dict[str, Any] = {}
    dropped: List[str] = []
    for name, entry in value.items():
        valid_name = (
            isinstance(name, str) and _PROP_NAME_RE.match(name) is not None and name not in CVSS_PAYLOAD_RESERVED_NAMES
        )
        if name in _CVSS_SCORE_KEYS and entry is not None:
            # A score is a finite number (2026-10-17): a string that reads as one ("9.8") becomes that
            # number, and anything else ("1e309", "Infinity", "NaN", "N/A", a boolean) is dropped as a
            # missing value, as a non-finite number is.
            entry = _finite_cvss_score(entry)
            valid_value = entry is not None
        else:
            valid_value = (
                entry is None
                or isinstance(entry, (str, bool))
                or (isinstance(entry, float) and math.isfinite(entry))
                or (isinstance(entry, int) and _NEO4J_INT_RANGE[0] <= entry <= _NEO4J_INT_RANGE[1])
            )
        if valid_name and valid_value:
            payload[name] = entry
        else:
            dropped.append(str(name)[:40])
    if (payload or dropped) and payload.get("base_score") in (None, ""):
        logger.warning(
            "[META] NVD_META.%s of %s has no base score%s — the CVE is read without it",
            key,
            cve_id,
            f" (entries dropped: {', '.join(sorted(dropped))})" if dropped else "",
        )
        return None
    if dropped:
        logger.warning(
            "[META] NVD_META.%s of %s: entries that are not CVSS properties dropped: %s",
            key,
            cve_id,
            ", ".join(sorted(dropped)),
        )
    return payload or None


def _extract_tlp_tag(tags: List[Dict[str, Any]], ref: str = "") -> str:
    """Rehydrate the ``tlp:<level>`` MISP tag (2026-10, fresh-baseline PR).

    MISPWriter stamps one ``tlp:<level>`` tag on every attribute (``_tlp_tag``);
    this is the read half. Returns the lower-case level (``white``, ``green``,
    ``amber``, …). An attribute without a TLP tag gets ``EDGEGUARD_DEFAULT_TLP``,
    the level the writer would have stamped: on 2026-10-12 a host reboot
    interrupted a URLhaus push between the attribute insert and its tags, the
    retry kept the existing attribute untagged, and the node synced with no
    ``tlp`` at all, failing the ``tlp_on_every_node`` acceptance check. The merge
    keeps the most restrictive level, so the default never loosens a stricter
    value already on the node.

    The default is logged with ``ref`` (the attribute's UUID): the node then passes
    ``tlp_on_every_node``, and an attribute whose tags were lost may have come
    from a green or amber OTX pulse.
    """
    for tag in tags:
        name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if isinstance(name, str) and name.lower().startswith("tlp:"):
            level = name[len("tlp:") :].strip().lower()
            if level:
                return level
    from config import EDGEGUARD_DEFAULT_TLP

    logger.warning(
        "[TLP] MISP attribute %s has no tlp: tag (%d other tags); the default level %r applies",
        ref or "<no uuid>",
        len(tags),
        EDGEGUARD_DEFAULT_TLP,
    )
    return EDGEGUARD_DEFAULT_TLP


def _extract_attack_domain_tag(tags: List[Dict[str, Any]]) -> str:
    """Rehydrate the ``attack-domain:<domain>`` MISP tag (2026-10) — ``enterprise`` when absent."""
    for tag in tags:
        name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if isinstance(name, str) and name.lower().startswith("attack-domain:"):
            domain = name[len("attack-domain:") :].strip().lower()
            if domain in ("enterprise", "ics", "mobile"):
                return domain
    return "enterprise"


# 2026-10: written by ``MISPWriter`` (``misp_writer.ATTACK_DEPRECATED_TAG``) on an item ATT&CK
# deprecated (``x_mitre_deprecated``: retired, no successor).
_ATTACK_DEPRECATED_TAG = "attack-status:deprecated"


def _extract_deprecated_tag(tags: List[Dict[str, Any]]) -> bool:
    """True when the attribute carries the ``attack-status:deprecated`` tag (2026-10).

    The item then carries ``deprecated: True`` and the merge sets ``n.deprecated = true`` on
    the node: a deprecated ATT&CK object keeps its node and links, marked so consumers can filter.
    """
    for tag in tags:
        name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if isinstance(name, str) and name.strip().lower() == _ATTACK_DEPRECATED_TAG:
            return True
    return False


def _dedupe_casefold(values: Any) -> List[str]:
    """Non-empty strings, de-duplicated case-insensitively, first-seen order (2026-10)."""
    out: List[str] = []
    seen: set = set()
    for value in values:
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _pair_without_software_id(pair: str) -> str:
    """``"family::adversary"`` or ``"family::adversary::pulse"`` with the family's ATT&CK software id
    suffix removed (2026-10): ``"Cobalt Strike - S0154::apt29::p1"`` → ``"Cobalt Strike::apt29::p1"``.
    A pair without the separator is returned unchanged."""
    family, sep, rest = pair.partition("::")
    if not sep:
        return pair
    return f"{split_attack_software_id(family)[0]}::{rest}"


def _pulse_family_lists(otx_meta: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """``OTX_META.mf`` / ``.pa`` as the indicator's ``pulse_malware_families`` /
    ``pulse_malware_actor_pairs``: stripped, empty entries and pairs without ``::`` dropped; a value
    that is not a JSON list is no list (``_meta_list``).

    2026-10: family names lose an ATT&CK software id suffix (attributes written before carry
    ``"Cobalt Strike - S0154"``), as the Malware node is named, and the lists are de-duplicated
    case-insensitively; build_relationships 9b / 2d strip the suffix too, for indicators already on
    the graph.
    """
    families = _dedupe_casefold(
        split_attack_software_id(str(x))[0] for x in _meta_list(otx_meta, "mf") if str(x).strip()
    )
    pairs = _dedupe_casefold(
        _pair_without_software_id(str(x).strip()) for x in _meta_list(otx_meta, "pa") if "::" in str(x)
    )
    return families, pairs


def _extract_alias_tags(tags: List[Dict[str, Any]]) -> List[str]:
    """Rehydrate ``alias:<name>`` MISP tags into an aliases list.

    The MISP-side carrier is written by MISPWriter for ThreatActor and
    Malware attributes (capped at 20 tags / 100 chars each at write time).
    This is the read half of the alias round-trip (2026-06) — before it
    existed, parse_attribute hardcoded ``aliases: []`` and every
    MISP-sourced actor/malware lost its aliases, disabling the
    alias-matching branches in build_relationships Q2/Q9.

    Entries are NFC-normalized (parity with node_identity name handling —
    build_relationships Q2/Q9 compare via ``toLower(trim(...))`` which does
    NOT unicode-normalize, so a non-NFC alias like NFD "Café" would never
    match an NFC-stored actor name without this). Order-preserving
    case-insensitive dedup. Not otherwise filtered here — merge_actor /
    merge_malware apply the PR-N14 sanitizer (50-item cap, placeholder
    filter, 200-char truncation) downstream, keeping one enforcement point.
    """
    import unicodedata

    aliases: List[str] = []
    seen: set = set()
    for tag in tags:
        tag_name = tag.get("name", "")
        if not isinstance(tag_name, str) or not tag_name.startswith("alias:"):
            continue
        alias = unicodedata.normalize("NFC", tag_name[len("alias:") :]).strip()
        key = alias.lower()
        if alias and key not in seen:
            seen.add(key)
            aliases.append(alias)
    return aliases


# STIX 2.1 Cyber-observable Objects (SCOs) — the spec does not define ``labels`` on these types.
# Manual conversion uses ``x_edgeguard_zones`` for SCOs; PyMISP ``to_stix2()`` output must be patched the same way.
STIX_21_SCO_TYPES: FrozenSet[str] = frozenset(
    {
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
    }
)


def apply_edgeguard_zone_metadata_to_stix_dict(obj_dict: Dict[str, Any], zone_labels: List[str]) -> None:
    """
    In-place: attach EdgeGuard zone hints without violating STIX 2.1.

    - **SCOs** → ``x_edgeguard_zones`` only; any ``labels`` (invalid on SCOs) are removed and
      zone-like entries are migrated into ``x_edgeguard_zones``.
    - **Other types** (SDOs, SROs, etc.) → set ``labels`` only if absent and ``zone_labels`` is non-empty.
    """
    if not obj_dict or not isinstance(obj_dict, dict):
        return
    t = obj_dict.get("type", "")
    zl = list(zone_labels or [])
    if t in STIX_21_SCO_TYPES:
        migrated: List[str] = []
        raw_labels = obj_dict.pop("labels", None)
        if isinstance(raw_labels, list):
            migrated = [x for x in raw_labels if isinstance(x, str) and x.startswith("zone:")]
        have = [x for x in (obj_dict.get("x_edgeguard_zones") or []) if isinstance(x, str)]
        merged = list(dict.fromkeys(have + migrated + zl))
        if merged:
            obj_dict["x_edgeguard_zones"] = merged
        elif "x_edgeguard_zones" in obj_dict and not obj_dict["x_edgeguard_zones"]:
            del obj_dict["x_edgeguard_zones"]
    elif zl and "labels" not in obj_dict:
        obj_dict["labels"] = zl.copy()


class MISPToNeo4jSync:
    """
    Synchronizes threat intelligence from MISP to Neo4j.

    Production-ready features:
    - Comprehensive error handling with proper logging
    - Retry logic with exponential backoff
    - Circuit breaker pattern for extended outages
    - Health checks before sync operations
    - Prometheus metrics for alerting
    - Batch processing for better performance
    - Statistics tracking
    """

    # Source mapping from MISP event/tag names to Neo4j source_ids.
    # Every entry must map to the *actual* originating source, not a proxy.
    # PR (S5) (Logic Tracker MED): the canonical Neo4j source_id
    # MUST match the value the collector emits (config.SOURCE_TAGS).
    # CISA collector emits ``cisa_kev`` (via SOURCE_TAGS["cisa"]) — the
    # mapping target here MUST be ``cisa_kev`` to keep all the per-source
    # node properties (n.tags, n.source) using ONE canonical literal
    # rather than two (``cisa`` vs ``cisa_kev``) that won't dedupe via
    # apoc.coll.toSet. Same for any other source whose collector tag
    # differs from a "human" source label here.
    # Derived from ``source_registry`` (2026-10): this used to be a hand-kept copy, so a
    # source registered there but missing here was silently synced as ``misp``.
    SOURCE_MAPPING = misp_tag_to_canonical_map()

    # MISP attribute type to EdgeGuard type mapping. ``ip-dst`` / ``ip-src`` hold IPv4 and IPv6
    # addresses alike: ``parse_attribute`` decides by the value (``ioc_normalize.ip_address_type``),
    # and the ``ipv4`` here applies only to a value that is not an address.
    TYPE_MAPPING = {
        "ip-dst": "ipv4",
        "ip-src": "ipv4",
        "ipv4": "ipv4",
        "ipv6": "ipv6",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "sha512": "hash",
        # SHA-1 fingerprint of a TLS certificate (SSL Blacklist), not a file hash (2026-10).
        "x509-fingerprint-sha1": "x509-fingerprint-sha1",
        "email-src": "email",
        "email-dst": "email",
        "vulnerability": "cve",
        "filename": "filename",
        "regkey": "registry",
        "mutex": "mutex",
        "yara": "yara",
        "sigma": "sigma",
        "snort": "snort",
        "btc": "bitcoin",
        "text": "unknown",
    }

    def __init__(self, misp_url: str = None, misp_api_key: str = None, neo4j_client: Neo4jClient = None):
        self.misp_url = misp_url or MISP_URL
        self.misp_api_key = misp_api_key or MISP_API_KEY
        # Initialize Neo4j client if not provided
        if neo4j_client is None:
            try:
                from neo4j_client import Neo4jClient

                self.neo4j = Neo4jClient()
                self.neo4j.connect()
            except Exception as e:
                logger.warning(f"Could not initialize Neo4j client: {e}")
                self.neo4j = None
        else:
            self.neo4j = neo4j_client

        # Get circuit breakers
        self.misp_circuit = MISP_CIRCUIT_BREAKER
        self.neo4j_circuit = NEO4J_CIRCUIT_BREAKER

        self.session = requests.Session()
        # Match MISPHealthCheck / PyMISP: honor EDGEGUARD_SSL_VERIFY on every request
        # (explicit verify= on individual calls is redundant but safe; default catches any new code paths).
        self.session.verify = SSL_VERIFY
        # MISP often returns HTML (login redirect) without Accept: application/json on API routes.
        self.session.headers.update(
            {
                "Authorization": self.misp_api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        apply_misp_http_host_header(self.session)

        self.stats = {
            "events_processed": 0,
            "events_failed": 0,
            # Subset of events_failed: the event details could not be fetched from MISP.
            "events_unfetchable": 0,
            "indicators_synced": 0,
            "vulnerabilities_synced": 0,
            "malware_synced": 0,
            "actors_synced": 0,
            "techniques_synced": 0,
            "relationships_created": 0,
            # Relationship rows dropped by permanent Neo4j batch failures
            # (``RelationshipBatchResult.failed``); non-zero fails the run.
            "relationships_failed": 0,
            # 2026-10 (curated packages): claims that found both ends in the graph, and claims whose
            # subject or object is not in it (nothing is written for those; see [CURATED]).
            "curated_claims_attached": 0,
            "curated_claims_unattached": 0,
            # Items no merge path accepts (unknown type, indicator without a value); reported in
            # the run summary, counted neither as successes nor as errors.
            "items_unroutable": 0,
            # 2026-10: OTX pulses naming several actors, whose malware was therefore not attributed
            # to them (``_build_cross_item_relationships``).
            "reports_with_several_actors": 0,
            # 2026-10-20: ``text`` attributes that start like an ATT&CK id but hold no valid one (a value
            # MISP's Import Regexp rules rewrote), skipped with an [ATTACK-VALUE] warning.
            "attack_values_skipped": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
            "circuit_breaker_states": {},
        }
        # Set when ``run()`` returns False so callers (e.g. baseline DAG) can surface a short reason.
        self._last_sync_failure_reason: Optional[str] = None
        self._consecutive_conn_failures: int = 0
        # Incremental window for the per-attribute filter (``_attribute_filter_since``); set by ``run()``.
        self._attr_since: Optional[datetime] = None
        # The canonical threat-actor reference, loaded on first use (``_report_actor_reference``).
        self._actor_reference: Optional[CanonicalReference] = None
        self._actor_reference_loaded = False

    def _report_actor_reference(self) -> Optional[CanonicalReference]:
        """The canonical threat-actor reference that tells how many actors a report names, or
        ``None`` when it is unavailable (logged once): the actors are then told apart by name, so the
        aliases of one actor count as several and their report attributes nothing."""
        if not getattr(self, "_actor_reference_loaded", False):
            self._actor_reference_loaded = True
            self._actor_reference = None
            try:
                self._actor_reference = load_canonical_reference()
            except ReferenceUnavailable as exc:
                logger.warning(
                    "[ATTRIBUTION] canonical reference unavailable (%s): a report's actors are told apart by name",
                    exc,
                )
        return getattr(self, "_actor_reference", None)

    def health_check_misp(self) -> Dict[str, Any]:
        """
        Check MISP health before operations using the shared MISPHealthCheck.

        Returns:
            Dict with health status compatible with resilience.check_service_health
        """
        checker = MISPHealthCheck(url=self.misp_url, api_key=self.misp_api_key, verify_ssl=SSL_VERIFY)
        status = checker.check_health()
        # Sync needs API + DB; workers optional (matches Airflow preflight / healthy_for_collection).
        ok = bool(status.get("healthy_for_collection", False))
        return {
            "healthy": ok,
            "response_time_ms": None,
            "status_code": 200 if ok else None,
            "details": status.to_dict(),
        }

    def health_check_neo4j(self) -> Dict[str, Any]:
        """
        Check Neo4j health before operations.

        Returns:
            Dict with health status
        """
        if not self.neo4j:
            return {"healthy": False, "error": "Neo4j client not initialized"}

        try:
            return self.neo4j.health_check()
        except Exception as e:
            logger.error(f"Neo4j health check failed: {e}")
            return {"healthy": False, "error": str(e)}

    def check_services_available(self) -> Tuple[bool, str]:
        """
        Check if both MISP and Neo4j are available.

        Returns:
            Tuple of (all_available, message)
        """
        # Check MISP circuit breaker and health
        if not self.misp_circuit.can_execute():
            msg = f"MISP circuit breaker is {self.misp_circuit.state.name}"
            logger.warning(msg)
            return False, msg

        misp_health = check_service_health("misp", self.health_check_misp)
        if not misp_health:
            self.misp_circuit.record_failure()
            msg = "MISP health check failed"
            logger.warning(msg)
            return False, msg

        # Check Neo4j circuit breaker and health
        if not self.neo4j_circuit.can_execute():
            msg = f"Neo4j circuit breaker is {self.neo4j_circuit.state.name}"
            logger.warning(msg)
            return False, msg

        neo4j_health = check_service_health("neo4j", self.health_check_neo4j)
        if not neo4j_health:
            self.neo4j_circuit.record_failure()
            msg = "Neo4j health check failed"
            logger.warning(msg)
            return False, msg

        # Both healthy - record success
        self.misp_circuit.record_success()
        self.neo4j_circuit.record_success()

        return True, "All services available"

    def connect(self) -> bool:
        """Connect to both MISP and Neo4j with circuit breaker protection."""
        logger.info("🔌 Starting connection to databases...")

        # Check if services are available
        available, msg = self.check_services_available()
        if not available:
            logger.error(f"[ERR] Service availability check failed: {msg}")
            record_collection_failure("misp_to_neo4j", msg)
            return False

        # Initialize Neo4j if not provided
        if not self.neo4j:
            logger.info("Initializing Neo4j client...")
            self.neo4j = Neo4jClient()

        # Connect to Neo4j
        try:
            neo4j_ok = self.neo4j.connect()
        except Exception as e:
            neo4j_ok = False
            logger.error("[ERR] Neo4j connect raised after retries: %s", e)
        if not neo4j_ok:
            logger.error("[ERR] Failed to connect to Neo4j")
            self.neo4j_circuit.record_failure()
            record_collection_failure("neo4j", "Connection failed")
            return False

        # Run Neo4j health check
        neo4j_health = self.neo4j.health_check()
        logger.info(f"🏥 Neo4j health: {neo4j_health}")

        # Run MISP health check
        misp_health = self.health_check_misp()
        logger.info(f"🏥 MISP health: {misp_health}")

        if not misp_health.get("healthy", False):
            logger.warning(f"[WARN] MISP health check warning: {misp_health.get('error', 'Unknown')}")
            self.misp_circuit.record_failure()

        if not neo4j_health.get("healthy", False):
            logger.warning(f"[WARN] Neo4j health check warning: {neo4j_health.get('error', 'Unknown')}")
            self.neo4j_circuit.record_failure()

        # Ensure schema and sources exist
        logger.info("Setting up Neo4j schema...")
        self.neo4j.create_constraints()
        self.neo4j.create_indexes()
        self.neo4j.ensure_sources()

        logger.info("[OK] Database connections established")

        # Record success
        record_collection_success("misp_to_neo4j")
        return True

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def fetch_edgeguard_events(self, since: datetime = None, sector: str = None) -> List[Dict]:
        """
        Fetch EdgeGuard events from MISP.

        Prefers paginated ``/events/index`` (or ``/events``): lightweight list rows without scanning
        all attributes (avoids restSearch timeouts on huge events). Falls back to PyMISP/restSearch
        if index endpoints are unavailable. 2026-10: the fallback asks for event headers only
        (``metadata``), narrows with ``eventinfo`` and keeps the rows ``_is_edgeguard_index_event``
        accepts (see ``_fallback_search_filters``).

        Args:
            since: Only fetch events modified since this datetime
            sector: Sector to fetch events for (applies sector-specific time ranges)

        Returns:
            List of MISP event dicts

        Raises:
            ``_MispFallbackHardError`` when the listing cannot be completed (2026-10: also a failed
            later index page and any unexpected error, which used to return the partial list), and
            the transient ``requests`` errors once ``@retry_with_backoff`` has used its retries.
        """
        events: List[Any] = []

        try:
            # Apply sector-specific time ranges if sector provided and no explicit since
            if sector and not since:
                since_str = get_sector_cutoff_date(sector)
                since = datetime.strptime(since_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                logger.info(f"Applying {sector} sector time range: fetching events since {since_str}")

            logger.info(f"Fetching EdgeGuard events from MISP (since: {since})...")

            indexed = _fetch_edgeguard_events_via_requests_index(self.session, self.misp_url, since)
            if INDEX_FETCH_STATE.get("truncated"):
                self.stats["events_index_truncated"] = True
            if indexed is not None:
                normalized = normalize_misp_event_index_payload(indexed)
                if normalized:
                    logger.info(f"[FETCH] Normalized {len(normalized)} MISP event(s) for processing")
                elif indexed:
                    logger.warning("[FETCH] Index returned rows but normalized to 0 events — check payload shape")
                return normalized

            # PR-N29 (Holistic H3, pre-baseline audit 2026-04-23): pre-N29
            # this fallback used ``limit: 1000`` with NO pagination. For
            # a 730d baseline against a populated MISP (empirically >1000
            # events in the 2026-04-19 incident), the fallback silently
            # truncated. ``EdgeGuardSyncCoverageGap`` alert compares
            # processed vs ``edgeguard_sync_events_index_total`` which IS
            # the truncated count — so no gap was visible. Fix: paginate
            # both the PyMISP and requests-restSearch branches, matching
            # the 500-per-page cadence of the primary index path.
            logger.warning(
                "[MISP-FETCH-FALLBACK-ACTIVE] Event index unavailable — falling "
                "back to PyMISP / restSearch with pagination. This path is slower "
                "than the index; investigate WHY the index failed. Grep this "
                "token in logs to correlate with other failure modes."
            )

            # Pagination bounds (PR-N29 H3):
            _FALLBACK_PAGE_SIZE = 500  # matches the primary index path cadence
            _FALLBACK_MAX_PAGES = 200  # 100K-event safety cap; raise if needed

            # PR-N31: record fallback-engaged metric. Paired with
            # EdgeGuardMispFetchFallbackActive alert in prometheus/alerts.yml.
            # Counter (not Gauge) so rate() over time answers the operator's
            # question "how often are we falling back?" — not just the most
            # recent run's status.
            record_misp_fetch_fallback("pymisp", "engaged")

            # Fallback: PyMISP restSearch (can be expensive on very large instances).
            try:
                from pymisp import PyMISP

                misp = PyMISP(self.misp_url, self.misp_api_key, **_pymisp_client_kwargs())

                events = []
                for page in range(1, _FALLBACK_MAX_PAGES + 1):
                    search_kwargs: dict = {
                        "limit": _FALLBACK_PAGE_SIZE,
                        "page": page,
                        **_fallback_search_filters(),
                    }
                    if since:
                        search_kwargs["timestamp"] = int(since.timestamp())

                    page_result = misp.search(controller="events", **search_kwargs)
                    if not page_result:
                        break
                    # PR-N29 Bugbot round 2 (2026-04-24, MED): PyMISP can
                    # return a list, ``{"response": [...]}``, or
                    # ``{"errors": ...}`` depending on version + error path.
                    # ``list(dict)`` would yield the dict's KEYS as bare
                    # strings ("response", "errors") — those then go into
                    # ``events`` and downstream normalize drops them all
                    # to zero, with the loop logging "successful pagination."
                    # Mirror the requests-restSearch branch's explicit
                    # unwrap below.
                    if isinstance(page_result, dict):
                        if "errors" in page_result:
                            logger.error(
                                "[MISP-FETCH-FALLBACK] PyMISP page %d returned "
                                "errors payload: %s — aborting fallback (%d good "
                                "pages already collected).",
                                page,
                                page_result.get("errors"),
                                page - 1,
                            )
                            raise _MispFallbackHardError(
                                f"MISP fallback PyMISP errors on page {page}: {page_result.get('errors')}"
                            )
                        page_rows = page_result.get("response") or []
                    elif isinstance(page_result, list):
                        page_rows = page_result
                    else:
                        logger.error(
                            "[MISP-FETCH-FALLBACK] PyMISP page %d returned "
                            "unexpected payload type %s — aborting fallback.",
                            page,
                            type(page_result).__name__,
                        )
                        raise _MispFallbackHardError(
                            f"MISP fallback PyMISP unexpected payload type on page {page}: {type(page_result).__name__}"
                        )
                    if not page_rows:
                        break
                    # 2026-10: keep EdgeGuard events only; the short-page test below counts every row.
                    kept_rows = _edgeguard_fallback_rows(page_rows)
                    events.extend(kept_rows)
                    logger.info(
                        "[MISP-FETCH-FALLBACK] PyMISP page %d returned %d row(s), %d EdgeGuard event(s)",
                        page,
                        len(page_rows),
                        len(kept_rows),
                    )
                    if len(page_rows) < _FALLBACK_PAGE_SIZE:
                        # Short read — we're at the end.
                        break
                else:
                    # PR-N29 (multi-agent audit, 2026-04-24, HIGH-2): hitting the
                    # safety cap means we may have legitimately MORE events in
                    # MISP than the cap allows. Pre-fix this only logged; the
                    # outer ``except Exception`` then silently treated the
                    # truncated list as "all" events. Now raise so the operator
                    # SEES the cap-hit. To intentionally raise the cap, edit
                    # ``_FALLBACK_MAX_PAGES`` in this file.
                    logger.error(
                        "[MISP-FETCH-FALLBACK] PyMISP hit _FALLBACK_MAX_PAGES=%d cap "
                        "(~%d events). If MISP legitimately has more events, "
                        "raise the cap in src/run_misp_to_neo4j.py.",
                        _FALLBACK_MAX_PAGES,
                        _FALLBACK_MAX_PAGES * _FALLBACK_PAGE_SIZE,
                    )
                    raise _MispFallbackHardError(
                        f"MISP fallback PyMISP hit _FALLBACK_MAX_PAGES={_FALLBACK_MAX_PAGES} cap "
                        f"(~{_FALLBACK_MAX_PAGES * _FALLBACK_PAGE_SIZE} events collected). "
                        f"Refusing to treat truncated fallback as complete."
                    )

                if events:
                    logger.info(
                        f"[FETCH] PyMISP pagination returned {len(events)} row(s) total "
                        f"across {page} page(s) (since={since}); normalizing"
                    )
                else:
                    logger.info("No events found in MISP")

            except _MispFallbackHardError:
                # PR-N29 (multi-agent audit, 2026-04-24, HIGH-1): the sentinel
                # raised inside the PyMISP loop above (errors payload, unexpected
                # type, cap-hit) MUST escape this try/except — otherwise the
                # broad ``except Exception`` below treats the hard failure as a
                # transient PyMISP issue and falls through to the
                # requests-restSearch path, masking the real underlying problem
                # and producing a partial-success "no events found" outcome.
                # Re-raising hands control to the outer try/except, which has
                # its own sentinel re-raise that lets the failure surface to
                # the calling DAG (retries=0 on critical chain — see PR-N29 H1).
                # PR-N31: record before re-raising so the operator alert fires
                # on the actual hard-failure event.
                record_misp_fetch_fallback("pymisp", "hard_error")
                raise
            except Exception as e:
                logger.error(f"PyMISP error: {e}, falling back to requests restSearch")
                # PR-N31: PyMISP failed with a non-sentinel exception — counts
                # as fallback-engaged on the requests path now. Pre-fix this
                # path silently fell through; the metric makes the cascade
                # operator-visible.
                record_misp_fetch_fallback("rest_search", "engaged")
                # PR-N29 H3: same pagination for the requests-restSearch path.
                # PR-N31: nested try/except around the loop so a sentinel
                # raised from any of the 4 hard-failure sites below
                # (non-200, errors-payload, unexpected-shape, cap-hit) is
                # attributed to "rest_search/hard_error" before propagating
                # to the outer ``except _MispFallbackHardError`` re-raise.
                # Symmetric with the PyMISP branch's recording above.
                try:
                    events = []
                    for page in range(1, _FALLBACK_MAX_PAGES + 1):
                        rest_body = {
                            "returnFormat": "json",
                            "limit": _FALLBACK_PAGE_SIZE,
                            "page": page,
                            **_fallback_search_filters(),
                        }
                        if since:
                            rest_body["timestamp"] = int(since.timestamp())

                        response = self.session.post(
                            f"{self.misp_url.rstrip('/')}/events/restSearch",
                            json=rest_body,
                            verify=SSL_VERIFY,
                            timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
                        )

                        if response.status_code != 200:
                            # PR-N29 Bugbot round 2 (2026-04-24, MED): pre-fix
                            # this was a silent ``break`` that kept the partial
                            # events list and downstream logged "collected N
                            # rows across M pages" as if successful. A non-200
                            # mid-pagination is a REAL error (3 good pages + a
                            # 500 on page 4 silently dropped 25% of the
                            # baseline). The ``EdgeGuardSyncCoverageGap`` alert
                            # doesn't catch this either because the index path
                            # isn't in play in fallback. Raise so the operator
                            # SEES the failure, can investigate WHY MISP 5xx'd
                            # mid-pagination, and the partial data isn't taken
                            # as ground truth.
                            logger.error(
                                "[MISP-FETCH-FALLBACK] restSearch HTTP %d on page %d "
                                "after %d good pages (%d events collected). NOT silently "
                                "truncating — re-raising so this surfaces as a sync error.",
                                response.status_code,
                                page,
                                page - 1,
                                len(events),
                            )
                            raise _MispFallbackHardError(
                                f"MISP fallback restSearch HTTP {response.status_code} on "
                                f"page {page} after {page - 1} good pages "
                                f"({len(events)} events collected). Investigate MISP backend; "
                                f"do NOT treat partial fallback as complete."
                            )
                        # 2026-10: a non-JSON answer (e.g. a proxy's HTML page with HTTP 200) ended up
                        # in the outer handler, which returned the pages read so far as the listing.
                        try:
                            page_data = response.json()
                        except ValueError as exc:
                            raise _MispFallbackHardError(
                                f"MISP fallback restSearch answered non-JSON on page {page} after {page - 1} "
                                f"good pages ({len(events)} events collected)"
                            ) from exc
                        # PR-N29 (multi-agent audit, 2026-04-24, HIGH-3 / Cross-Checker):
                        # MISP can return HTTP 200 with an ``{"errors": ...}`` body
                        # (e.g. ACL filter matched zero, broken sync user, malformed
                        # query). Pre-fix this silently became ``[]`` via
                        # ``.get("response") or []`` and the loop happily logged
                        # "0 row(s)" → ``break`` → "successful pagination" with
                        # zero events. Mirror the PyMISP branch above: errors is a
                        # hard failure, unexpected payload type is a hard failure,
                        # only list / wrapped-list payloads are accepted.
                        if isinstance(page_data, dict):
                            if "errors" in page_data:
                                logger.error(
                                    "[MISP-FETCH-FALLBACK] restSearch page %d returned "
                                    "errors payload: %s — aborting fallback (%d good "
                                    "pages already collected).",
                                    page,
                                    page_data.get("errors"),
                                    page - 1,
                                )
                                raise _MispFallbackHardError(
                                    f"MISP fallback restSearch errors on page {page}: {page_data.get('errors')}"
                                )
                            page_rows = page_data.get("response") or []
                        elif isinstance(page_data, list):
                            page_rows = page_data
                        else:
                            logger.error(
                                "[MISP-FETCH-FALLBACK] restSearch page %d returned "
                                "unexpected payload type %s — aborting fallback.",
                                page,
                                type(page_data).__name__,
                            )
                            raise _MispFallbackHardError(
                                f"MISP fallback restSearch unexpected payload type on page {page}: {type(page_data).__name__}"
                            )
                        if not page_rows:
                            break
                        # 2026-10: keep EdgeGuard events only; the short-page test below counts every row.
                        kept_rows = _edgeguard_fallback_rows(page_rows)
                        events.extend(kept_rows)
                        logger.info(
                            "[MISP-FETCH-FALLBACK] restSearch page %d returned %d row(s), %d EdgeGuard event(s)",
                            page,
                            len(page_rows),
                            len(kept_rows),
                        )
                        if len(page_rows) < _FALLBACK_PAGE_SIZE:
                            break
                    else:
                        # PR-N29 (multi-agent audit, 2026-04-24, HIGH-2): symmetric
                        # with the PyMISP cap-hit raise above. Hitting the safety
                        # cap means truncated coverage; refuse to treat it as
                        # complete.
                        logger.error(
                            "[MISP-FETCH-FALLBACK] restSearch hit _FALLBACK_MAX_PAGES=%d cap "
                            "(~%d events). If MISP legitimately has more events, "
                            "raise the cap in src/run_misp_to_neo4j.py.",
                            _FALLBACK_MAX_PAGES,
                            _FALLBACK_MAX_PAGES * _FALLBACK_PAGE_SIZE,
                        )
                        raise _MispFallbackHardError(
                            f"MISP fallback restSearch hit _FALLBACK_MAX_PAGES={_FALLBACK_MAX_PAGES} cap "
                            f"(~{_FALLBACK_MAX_PAGES * _FALLBACK_PAGE_SIZE} events collected). "
                            f"Refusing to treat truncated fallback as complete."
                        )
                except _MispFallbackHardError:
                    # PR-N31: symmetric with the PyMISP branch — record before
                    # propagating to the outer ``except _MispFallbackHardError``
                    # re-raise. Without this, restSearch hard errors would be
                    # invisible to Prometheus (only the engaged metric would
                    # increment) and the operator alert couldn't distinguish
                    # "fallback running fine" from "fallback also failing."
                    record_misp_fetch_fallback("rest_search", "hard_error")
                    raise
                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError,
                ):
                    raise  # transient: @retry_with_backoff re-runs the listing
                except Exception as exc:
                    # 2026-10: any other error here (e.g. a request error that is not transient)
                    # leaves the fallback listing as incomplete as an HTTP 5xx does. It reached the
                    # outer handler without ``hard_error`` being recorded, so only the warning
                    # fallback alert fired, not the critical one.
                    record_misp_fetch_fallback("rest_search", "hard_error")
                    raise _MispFallbackHardError(
                        f"MISP fallback restSearch failed on page {page} ({len(events)} events collected): "
                        f"{type(exc).__name__}: {exc}"
                    ) from exc

                # PR-N29: pagination already collected all events; downstream
                # normalization runs on the ``events`` variable. Pre-N29 this
                # block had an ``if response.status_code == 200: events =
                # response.json()`` re-assign on a single-shot response; now
                # redundant because pagination loop already handled it.
                if events:
                    logger.info(
                        "[FETCH] events/restSearch fallback (paginated): collected %d row(s) across %d page(s)",
                        len(events),
                        page,
                    )

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except _MispFallbackHardError:
            # PR-N29 (multi-agent audit, 2026-04-24, HIGH-1): the sentinel
            # marks a non-recoverable failure in the fallback paths
            # (PyMISP errors payload, unexpected payload type, restSearch
            # HTTP 5xx mid-pagination, OR safety-cap hit). Pre-fix the
            # broad ``except Exception`` below caught these as a generic
            # "Error fetching events", logged it, and returned an empty
            # list — the calling DAG's ``EdgeGuardSyncCoverageGap`` alert
            # then compared an empty processed-list to an empty
            # events-index and saw "no gap." Re-raising lets the failure
            # propagate to the DAG (which has retries=0 on the critical
            # chain — see PR-N29 H1) so the operator sees the real error.
            # Intentionally NOT in the @retry_with_backoff retry set:
            # a 500 mid-pagination is not a transient network issue.
            raise
        except Exception as e:
            logger.error(f"Error fetching events: {type(e).__name__}: {e}")
            # 2026-10: a failure after the listing started must not hand back a partial (or empty)
            # list as the complete one: run() would report success and the DAG would stamp last_sync.
            raise _MispFallbackHardError(f"MISP event listing failed: {type(e).__name__}: {e}") from e

        normalized = normalize_misp_event_index_payload(events)
        if normalized:
            logger.info(f"[FETCH] Normalized {len(normalized)} MISP event(s) for processing")
        elif events:
            logger.warning("[FETCH] Had raw MISP payload but normalized to 0 events — check API response shape")
        return normalized

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def fetch_event_details(self, event_id: str) -> Optional[Dict]:
        """
        Fetch full event details including attributes using PyMISP.

        Args:
            event_id: MISP event ID

        Returns:
            Full event dict or None
        """
        try:
            try:
                from pymisp import PyMISP

                misp = PyMISP(self.misp_url, self.misp_api_key, **_pymisp_client_kwargs())
                event = misp.get_event(event_id)

                if event:
                    plain = misp_event_object_to_event_dict(event)
                    if plain is not None:
                        return plain
                    logger.warning(
                        "PyMISP get_event(%r) returned unparsed type %s — falling back to REST /events/view",
                        event_id,
                        type(event).__name__,
                    )
                else:
                    logger.warning(f"Event {event_id} not returned by PyMISP — trying REST /events/view")

            except Exception as e:
                logger.error(f"PyMISP error for event {event_id}: {e}, falling back to requests")

            response = self.session.get(
                f"{self.misp_url}/events/{event_id}",
                verify=SSL_VERIFY,
                timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
            )

            if response.status_code == 200:
                body = response.json()
                plain = misp_event_object_to_event_dict(body)
                if plain is not None:
                    return plain
                if isinstance(body, dict) and body.get("Event"):
                    return body["Event"]
                logger.warning(
                    "REST /events/%s JSON shape unexpected (keys=%s)",
                    event_id,
                    list(body.keys())[:12] if isinstance(body, dict) else type(body).__name__,
                )
                return None

            # 5xx responses are retriable — raise so @retry_with_backoff
            # gets another shot. Silently returning None here used to cause large
            # events (e.g. NVD ~99K CVEs) to be permanently skipped after a single
            # transient MISP 500, leaving the graph missing entire feeds.
            if response.status_code >= 500:
                logger.warning(
                    "MISP returned HTTP %s for event %s — will retry via backoff",
                    response.status_code,
                    event_id,
                )
                raise MispTransientServerError(
                    f"MISP {response.status_code} fetching event {event_id}",
                    response=response,
                )

            # 4xx: permanent failure, don't retry
            logger.error(f"Failed to fetch event {event_id}: HTTP {response.status_code}")
            return None

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
            MispTransientServerError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error fetching event {event_id}: {type(e).__name__}: {e}")
            return None

    # Distinct unmapped ``source:*`` tag names that receive their own
    # Prometheus label value; later names collapse to ``<other>`` so a
    # hostile or misconfigured MISP peer cannot inflate label cardinality.
    _UNMAPPED_SOURCE_TAG_LABEL_CAP = 50

    def extract_source_from_tags(self, tags: List[Dict]) -> str:
        """Extract source_id from MISP tags.

        A ``source:<name>`` tag whose name is not in ``SOURCE_MAPPING`` (for
        example a tag written by a collector that has since been removed
        from the framework) falls back to ``"misp"``. The fallback is
        logged once per distinct name per sync instance and counted in
        ``edgeguard_misp_unmapped_source_tags_total``, so the attribute is
        still ingested while the unmapped provenance stays visible.
        """
        tags = normalize_misp_tag_list(tags)
        for tag in tags:
            tag_name = tag.get("name", "")

            # Check for source tags
            if tag_name.startswith("source:"):
                source_name = tag_name.replace("source:", "")
                mapped = self.SOURCE_MAPPING.get(source_name)
                if mapped is None:
                    self._note_unmapped_source_tag(source_name)
                    return "misp"
                return mapped

            # Check direct mappings
            if tag_name in self.SOURCE_MAPPING:
                return self.SOURCE_MAPPING[tag_name]

        return "misp"

    def _note_unmapped_source_tag(self, source_name: str) -> None:
        """Log (once per distinct name) and count an unmapped ``source:*`` tag.

        The tracking dict is created on first use rather than in ``__init__``
        so instances built without the constructor behave the same way.
        Metric recording is best-effort: a metrics failure must never stop
        the attribute from being ingested.
        """
        name = (source_name or "").strip() or "<empty>"
        seen: Dict[str, str] = self.__dict__.setdefault("_unmapped_source_tags_seen", {})
        label = seen.get(name)
        if label is None:
            label = name if len(seen) < self._UNMAPPED_SOURCE_TAG_LABEL_CAP else "<other>"
            seen[name] = label
            logger.warning(
                "MISP tag %r is not in SOURCE_MAPPING; attributes carrying it are attributed to "
                "source_id='misp' and counted in edgeguard_misp_unmapped_source_tags_total",
                f"source:{name}",
            )
        try:
            from metrics_server import record_misp_unmapped_source_tag

            record_misp_unmapped_source_tag(label)
        except Exception:
            logger.debug("Metrics recording for unmapped source tag failed", exc_info=True)

    def extract_zones_from_tags(self, tags: List[Dict]) -> List[str]:
        """Extract ALL zones/sectors from MISP tags, filtered against the canonical whitelist."""
        from config import VALID_ZONES

        tags = normalize_misp_tag_list(tags)
        zones: set = set()
        for tag in tags:
            tag_name = tag.get("name", "")
            for prefix in ("zone:", "sector:"):
                if tag_name.startswith(prefix):
                    candidate = tag_name[len(prefix) :].strip().lower()
                    if candidate in VALID_ZONES:
                        zones.add(candidate)

        return list(zones) if zones else ["global"]

    def convert_to_stix21(self, misp_event: dict) -> dict:
        """
        Convert MISP event to STIX 2.1 bundle.

        Uses PyMISP's to_stix2() method if available, otherwise
        performs manual conversion to STIX 2.1 format.

        Preserves zone information from event names in STIX labels.

        Args:
            misp_event: MISP event dictionary

        Returns:
            STIX 2.1 bundle as dictionary
        """
        # Extract zone from event name for later use
        event_info = misp_event.get("info", "")
        zone_from_name = self._extract_zone_from_event_name(event_info)

        # Also extract zones from event-level tags
        event_tags = normalize_misp_tag_list(misp_event.get("Tag", []))
        zones_from_tags = self.extract_zones_from_tags(event_tags)

        # Merge both zone sources; prefer specific sectors over generic "global".
        # Previously zone_from_name exclusively overwrote tags, dropping multi-zone data.
        _all_event_zones: set = set()
        if zone_from_name:
            _all_event_zones.add(zone_from_name)
        for _z in zones_from_tags:
            _all_event_zones.add(_z)
        _specific = {_z for _z in _all_event_zones if _z != "global"}
        event_zones = sorted(_specific) if _specific else ["global"]

        # Create zone labels for STIX objects
        zone_labels = [f"zone:{zone}" for zone in event_zones]

        try:
            # Try using PyMISP's built-in STIX 2 conversion if available
            from pymisp import MISPEvent

            event = MISPEvent()
            event.load(misp_event)

            # Check if to_stix2 method exists (newer PyMISP versions)
            if hasattr(event, "to_stix2"):
                stix_objects = event.to_stix2()

                # Build STIX 2.1 bundle
                bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}

                # Convert objects to dictionaries if needed
                for obj in stix_objects:
                    obj_dict = None
                    if hasattr(obj, "serialize"):
                        obj_dict = json.loads(obj.serialize())
                    elif isinstance(obj, dict):
                        obj_dict = obj

                    if obj_dict:
                        apply_edgeguard_zone_metadata_to_stix_dict(obj_dict, zone_labels)
                        _filter_entity_stix_description(obj_dict, _event_source_id(event_info))
                        bundle["objects"].append(obj_dict)

                return bundle

        except ImportError:
            logger.debug("PyMISP not available for STIX conversion, using manual conversion")
        except Exception as e:
            logger.warning(f"PyMISP STIX conversion failed: {e}, falling back to manual conversion")

        # Manual conversion to STIX 2.1
        return self._manual_convert_to_stix21(misp_event)

    def _extract_zone_from_event_name(self, event_info: str) -> Optional[str]:
        """
        Extract zone from MISP event name — always returns None.

        Event names use ``EdgeGuard-{source}-{date}`` (no zone in name).
        Zone data lives exclusively on attribute-level tags (``zone:Finance``).
        This method exists as a no-op stub so call sites don't need changing.
        """
        return None

    def _manual_convert_to_stix21(self, misp_event: dict) -> dict:
        """
        Manually convert MISP event to STIX 2.1 bundle.

        This is a fallback when PyMISP's to_stix2() is not available.
        Preserves zone information from MISP event names.

        PR-M2 §4-F2/F10: previously this method used ``misp_event["date"]``
        (a YYYY-MM-DD string stamped to *today* at MISP-write time, see
        ``misp_writer.py:_get_or_create_event``) as the Report SDO's
        ``created`` / ``modified``. That conflated three concepts:
          * the Report (a new container we're generating now) — should
            be stamped with the current wall-clock per STIX §3.6
          * the Event.date (date-only string; not STIX-valid timestamp)
          * the indicator's source-truthful first-seen (which is what
            consumers actually want to know)

        After PR-M2:
          * Report ``created`` / ``modified`` / ``published`` = NOW (correct
            STIX 2.1 §3.6 semantics — the Report is new)
          * Each contained Indicator/Vulnerability SDO carries its own
            source-truthful timestamps inside (see ``_attribute_to_stix21``
            below)
        See docs/TIMESTAMPS.md "Layer 4 — STIX 2.1 export" for the spec.
        """
        import uuid
        from datetime import datetime, timezone

        event_id = str(misp_event.get("id", uuid.uuid4()))
        event_uuid = misp_event.get("uuid", str(uuid.uuid4()))
        event_info = misp_event.get("info", "MISP Event")
        # PR-M2: Report SDO timestamps are NOW (Report is new, per STIX
        # §3.6). The misp_event["date"] field is irrelevant to the
        # Report's STIX semantics; source-truthful info lives on the
        # contained Indicator SDOs.
        report_now = datetime.now(timezone.utc).isoformat()

        # Extract zone from event name (e.g., "EdgeGuard-FINANCE-alienvault_otx" → "finance")
        zone_from_name = self._extract_zone_from_event_name(event_info)

        # Also extract zones from event-level tags
        event_tags = normalize_misp_tag_list(misp_event.get("Tag", []))
        zones_from_tags = self.extract_zones_from_tags(event_tags)

        # Merge both zone sources; prefer specific sectors over generic "global".
        _all_mz: set = set()
        if zone_from_name:
            _all_mz.add(zone_from_name)
        for _z in zones_from_tags:
            _all_mz.add(_z)
        _specific_mz = {_z for _z in _all_mz if _z != "global"}
        event_zones = sorted(_specific_mz) if _specific_mz else ["global"]

        # Create zone labels for STIX objects
        zone_labels = [f"zone:{zone}" for zone in event_zones]

        # Create STIX 2.1 Report object as the main container
        report_id = f"report--{event_uuid}"

        stix_objects = []
        object_refs = []

        # Create the Report object with zone labels.
        # PR-M2 §4-F2/F10: ``created`` / ``modified`` / ``published`` use
        # the wall-clock NOW because the Report SDO is being generated
        # in this method call. STIX 2.1 §3.6 requires both fields with
        # full timestamp + offset; the previous code passed
        # ``misp_event["date"]`` (date-only YYYY-MM-DD) which was both
        # semantically wrong (consumers reading Report.created inferred
        # the underlying entity's age, not the report's) and STIX-invalid
        # (date-only strings fail strict validators per §3.2).
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": report_now,
            "modified": report_now,
            "published": report_now,
            "name": event_info,
            "description": f"MISP Event {event_id}: {event_info}",
            "report_types": ["threat-report"],
            "object_refs": object_refs,
            "labels": zone_labels.copy(),
        }

        # Process attributes into STIX objects
        for attr in coerce_misp_attribute_list(misp_event.get("Attribute")):
            stix_obj = self._attribute_to_stix21(attr, event_uuid, event_zones)
            if stix_obj:
                stix_objects.append(stix_obj)
                object_refs.append(stix_obj["id"])

        # Add the report to objects
        stix_objects.insert(0, report)

        # Build the bundle
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": stix_objects}

        return bundle

    def _attribute_to_stix21(self, attr: dict, event_uuid: str, event_zones: List[str] = None) -> Optional[dict]:
        """
        Convert a single MISP attribute to STIX 2.1 object.

        Args:
            attr: MISP attribute dictionary
            event_uuid: Parent event UUID
            event_zones: Zones extracted from event name (e.g., ['finance', 'global'])

        Returns:
            STIX 2.1 object dictionary or None

        PR-M2 §4-F3 / spec docs/TIMESTAMPS.md: timestamp handling.

        ``attr["timestamp"]`` is MISP's INTERNAL write-time epoch
        integer (e.g. ``"1716825600"``); it is NOT a source-truthful
        observation timestamp. The previous code used it verbatim as
        STIX ``valid_from`` / ``created`` / ``modified`` — strict STIX
        validators rejected it (raw int as ISO string), and any consumer
        reading the value misinterpreted MISP's write time as the
        source's first observation.

        After PR-M2:
          * ``stix_created_modified`` = NOW (when we generated this STIX
            object) — matches concept 3 / 4 in TIMESTAMPS.md
          * ``stix_valid_from`` follows the 3-step fallback chain from
            docs/TIMESTAMPS.md "valid_from fallback chain":
              (1) MISP-native ``Attribute.first_seen`` (concept 1,
                  source-truthful) — no inferred flag
              (2) MISP ``Attribute.timestamp`` (when MISP first
                  recorded the attribute — analogous to concept 3
                  ``first_imported_at`` for this manual-fallback
                  context) — sets ``x_edgeguard_first_seen_inferred=true``
              (3) wall-clock NOW (defensive last resort) — sets
                  ``x_edgeguard_first_seen_inferred=true``
          * MISP ``Attribute.timestamp`` is also preserved verbatim as
            the custom property ``x_edgeguard_misp_attribute_timestamp``
            for audit / debugging
        """
        import uuid
        from datetime import datetime, timezone

        attr_type = attr.get("type", "")
        # PR-N5 B4 (Bug Hunter F3, audit 09): defensive str-coerce.
        # Downstream this ``value`` hits ``re.match()`` (line ~1595)
        # and is used as the ``value`` field on STIX SCOs (ipv4-addr /
        # domain-name / url / file). An int-typed MISP value would
        # crash ``re.match`` with TypeError and produce schema-invalid
        # STIX bundles.
        #
        # PR-N5 R1 Bugbot LOW (2026-04-21): earlier form
        # ``str(attr.get("value", "") or "")`` had a latent falsy-int
        # bug — ``0 or ""`` evaluates to ``""``, so integer zero values
        # silently became empty strings. Explicit ``is not None`` check
        # handles ``0`` / ``False`` correctly.
        _raw_value = attr.get("value")
        value = str(_raw_value) if _raw_value is not None else ""
        attr_uuid = attr.get("uuid", str(uuid.uuid4()))

        # PR-M2 §4-F3: build the timestamp envelope cleanly, separating
        # the four canonical concepts.
        stix_now = datetime.now(timezone.utc).isoformat()
        # MISP-native first_seen (source-truthful claim, MISP 2.4.120+).
        # Coerced through the canonical helper so naive ISO / epoch int /
        # date-only inputs all normalize to tz-aware UTC ISO.
        attr_first_seen = _coerce_to_iso(attr.get("first_seen"))
        attr_last_seen = _coerce_to_iso(attr.get("last_seen"))
        # MISP-internal write-time epoch (concept 3 analogue for this
        # manual-fallback path: when MISP first recorded the attribute).
        # Better than wall-clock NOW because it preserves at least the
        # MISP-side ingest time when the source didn't expose
        # ``Attribute.first_seen``.
        misp_attr_timestamp = _coerce_to_iso(attr.get("timestamp"))

        # Resolve valid_from per the canonical 3-step fallback chain
        # (TIMESTAMPS.md "valid_from fallback chain"):
        #   (1) source-truthful first_seen   → no inferred flag
        #   (2) MISP attribute timestamp     → x_edgeguard_first_seen_inferred=true
        #   (3) wall-clock NOW (defensive)   → x_edgeguard_first_seen_inferred=true
        # Bugbot caught (PR-M2 round 2, MED): the prior 2-step chain
        # skipped step (2) and went straight to NOW, which conflated
        # "when we generated this STIX object" with "when this entity
        # was first observed". MISP's ``Attribute.timestamp`` is a
        # better intermediate value — it's at least when MISP first
        # ingested this datum, not today's wall-clock.
        if attr_first_seen:
            stix_valid_from = attr_first_seen
            valid_from_inferred = False
        elif misp_attr_timestamp:
            stix_valid_from = misp_attr_timestamp
            valid_from_inferred = True
        else:
            stix_valid_from = stix_now
            valid_from_inferred = True

        # Build the timestamp-envelope helpers that every SDO/SCO branch
        # below applies before returning. Centralizes the spec.
        #
        # STIX 2.1 split (per §3 SDOs vs §6 SCOs):
        #   SDOs (Indicator, Vulnerability, ThreatActor, Malware,
        #     AttackPattern, x-mitre-tactic, Report) require
        #     ``created`` / ``modified`` per §3.1.
        #   SCOs (ipv4-addr, ipv6-addr, domain-name, url, file,
        #     email-addr) do NOT carry ``created`` / ``modified`` —
        #     they're SCOs, not SDOs. Adding the keys would fail
        #     strict STIX 2.1 validation.
        # Custom ``x_edgeguard_*`` properties are allowed on both
        # (STIX 2.1 §3.1 / §6.1 producer custom properties).
        def _x_props(stix_obj: dict) -> dict:
            """Attach the EdgeGuard timestamp custom properties (safe
            for both SDOs and SCOs)."""
            if attr_first_seen:
                stix_obj["x_edgeguard_first_seen_at_source"] = attr_first_seen
            if attr_last_seen:
                stix_obj["x_edgeguard_last_seen_at_source"] = attr_last_seen
            if misp_attr_timestamp:
                stix_obj["x_edgeguard_misp_attribute_timestamp"] = misp_attr_timestamp
            return stix_obj

        def _stamp_sdo(stix_obj: dict) -> dict:
            """SDO timestamp envelope: ``created`` / ``modified`` =
            wall-clock NOW (when this STIX object was generated, per
            STIX §3.1) plus the custom EdgeGuard extensions."""
            stix_obj.setdefault("created", stix_now)
            stix_obj.setdefault("modified", stix_now)
            return _x_props(stix_obj)

        if not value:
            return None

        # Start with zones from event name
        all_zones = set(event_zones) if event_zones else set()

        # Extract zones from attribute tags for STIX labels.
        #
        # PR-N6 hotfix #1 (audit 09, Cross-Checker F1): filter
        # candidates through ``VALID_ZONES`` before accepting them
        # as zones / STIX labels. Pre-fix this manual-STIX fallback
        # path read ``zone:<anything>`` verbatim — including
        # adversarial tags a malicious MISP peer could inject —
        # and emitted them straight into STIX ``labels`` +
        # ``x_edgeguard_zones``. The convert_to_stix21 path above
        # (line ~1218) already went through ``extract_zones_from_tags``
        # which DOES whitelist, so only this attribute-level fallback
        # loop was affected, causing asymmetric behaviour between
        # the pyMISP and manual-fallback conversion paths.
        #
        # PR-N6 hotfix #5 (audit 09, Cross-Checker F4): also accept
        # the ``sector:`` prefix for parity with
        # ``extract_zones_from_tags`` above. Pre-fix only ``zone:``
        # was accepted here, so any MISP feed emitting
        # ``sector:finance`` was silently dropped by the STIX
        # exporter while being picked up by the Neo4j-merge path —
        # same attribute ends up with ``n.zone=["finance"]`` but
        # ``x_edgeguard_zones=[]``.
        from config import VALID_ZONES

        labels = []
        attr_tags = normalize_misp_tag_list(attr.get("Tag", []))
        for tag in attr_tags:
            tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
            for prefix in ("zone:", "sector:"):
                if tag_name.startswith(prefix):
                    zone_name = tag_name[len(prefix) :].strip().lower()
                    if zone_name and zone_name in VALID_ZONES:
                        all_zones.add(zone_name)
                        labels.append(f"zone:{zone_name}")
                    break

        def _with_entity_description(stix_obj: dict) -> dict:
            """2026-10: the description of a threat-actor, malware, attack-pattern, tool or tactic object, as
            the sync takes it (``_entity_comment_description``): never a metadata block's raw text, a
            placeholder or an OTX pulse's text, which these objects carried as the raw comment and a STIX
            import of the bundle (``run_pipeline``) stored on the node. No ``description`` without one."""
            text = _entity_comment_description(attr.get("comment"), self.extract_source_from_tags(attr_tags))
            if text:
                stix_obj["description"] = text
            return stix_obj

        # If no zones found in attribute tags, use event zones
        if not labels and event_zones:
            labels = [f"zone:{zone}" for zone in event_zones]

        # Match parse_attribute: if both global and specific zones appear, drop global
        if all_zones:
            specific_only = {z for z in all_zones if z != "global"}
            if specific_only:
                all_zones = specific_only
            labels = [f"zone:{z}" for z in sorted(all_zones)]

        # Map MISP types to STIX 2.1.
        #
        # STIX 2.1 spec: SCOs (ipv4-addr, ipv6-addr, domain-name, url, file)
        # do NOT support the `labels` property — only SDOs do.
        # Zone membership is stored in the custom `x_edgeguard_zones` property
        # for SCOs to avoid validation errors when feeding a strict STIX parser.
        if attr_type in ["ip-dst", "ip-src", "ipv4", "ipv6"]:
            # 2026-10: the address decides between ``ipv4-addr`` and ``ipv6-addr``; MISP keeps both
            # families under ``ip-dst`` / ``ip-src`` (an IPv6 address used to become ``ipv4-addr``).
            family = ip_address_type(value) or ("ipv6" if attr_type == "ipv6" else "ipv4")
            sco_type = f"{family}-addr"
            stix_obj = {"type": sco_type, "spec_version": "2.1", "id": f"{sco_type}--{attr_uuid}", "value": value}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type == "x509-fingerprint-sha1":
            # 2026-10: the SHA-1 fingerprint of a TLS certificate (SSL Blacklist), not a file hash.
            stix_obj = {
                "type": "x509-certificate",
                "spec_version": "2.1",
                "id": f"x509-certificate--{attr_uuid}",
                "hashes": {"SHA-1": value},
            }
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type in ["domain", "hostname"]:
            stix_obj = {"type": "domain-name", "spec_version": "2.1", "id": f"domain-name--{attr_uuid}", "value": value}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type == "url":
            stix_obj = {"type": "url", "spec_version": "2.1", "id": f"url--{attr_uuid}", "value": value}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type in ["md5", "sha1", "sha256", "sha512"]:
            hashes = {attr_type.upper(): value}
            stix_obj = {"type": "file", "spec_version": "2.1", "id": f"file--{attr_uuid}", "hashes": hashes}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type == "vulnerability":
            # vulnerability is an SDO — `labels` is valid here.
            stix_obj = {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{attr_uuid}",
                "name": value,
            }
            # 2026-10: never a metadata block's raw text (an NVD_META or OTX_META comment) or a note of
            # where the CVE was seen; a STIX import of this bundle (``run_pipeline``) would store it as the
            # CVE description.
            vuln_description = _vulnerability_comment_description(attr.get("comment"))
            if vuln_description:
                stix_obj["description"] = vuln_description
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(stix_obj)

        elif attr_type == "threat-actor":
            stix_obj = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{attr_uuid}",
                "name": value,
                "threat_actor_types": ["hacker"],
            }
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(_with_entity_description(stix_obj))

        elif attr_type == "malware-type":
            # Extract malware family from tags if available
            malware_types = []
            for tag in attr_tags:
                tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
                if tag_name.startswith("malware-type:"):
                    malware_types.append(tag_name.replace("malware-type:", "").strip())

            # 2026-10: named by the base name as ``parse_attribute`` names the node ("Cobalt Strike" for
            # "Cobalt Strike - S0154"), the original kept as an alias. A STIX import of this bundle
            # (``run_pipeline``) made the suffixed name a Malware node beside the ATT&CK one.
            malware_name, attack_software_id = split_attack_software_id(value)
            stix_obj = {
                "type": "malware",
                "spec_version": "2.1",
                "id": f"malware--{attr_uuid}",
                "name": malware_name,
                "is_family": True,
                "malware_types": malware_types if malware_types else ["trojan"],
            }
            if attack_software_id and malware_name != value:
                stix_obj["aliases"] = [value]
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(_with_entity_description(stix_obj))

        elif attr_type == "text":
            # A MITRE technique, tool or tactic: "<id> - <name>" or "<id>: <name>" (``attack_values``;
            # 2026-10-20: the regular expressions used before read only the second form). A value with no
            # valid ATT&CK id, or with no name, converts to nothing.
            attack = parse_attack_value(value)
            if attack is None or not attack.name:
                if attack is None and looks_like_attack_value(value):
                    logger.warning(
                        "[ATTACK-VALUE] MISP text attribute %s: %r starts like an ATT&CK entry but holds no valid "
                        "ATT&CK id; not converted to STIX",
                        attr_uuid,
                        value[:200],
                    )
                return None

            if attack.kind == "technique":
                mitre_id = attack.mitre_id
                technique_name = attack.name

                # Extract platforms from tags
                platforms = []
                for tag in attr_tags:
                    tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
                    if tag_name.startswith("platform:"):
                        platforms.append(tag_name.replace("platform:", "").strip())

                # Build external references for MITRE
                external_refs = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": mitre_id,
                        "url": f"https://attack.mitre.org/techniques/{mitre_id}/",
                    }
                ]

                stix_obj = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": f"attack-pattern--{attr_uuid}",
                    "name": technique_name,
                    "external_references": external_refs,
                }
                if labels:
                    stix_obj["labels"] = labels
                return _stamp_sdo(_with_entity_description(stix_obj))

            # A MITRE tool ("S0002 - Mimikatz")
            #
            # PR-G1 Bug Hunter audit (HIGH): this branch and the tactic branch
            # below had three compounding defects:
            #
            #   1. ``tag`` was an undefined name at this scope — the only
            #      binding was the loop variable ``for tag in attr_tags`` at
            #      line ~1327, which leaks out only if the loop body ran at
            #      least once. Empty ``attr_tags`` → NameError at runtime,
            #      crashing the STIX export for the whole event.
            #   2. The returned dict had no ``id`` field, so the caller's
            #      ``object_refs.append(stix_obj["id"])`` raised KeyError on
            #      every single MITRE tool attribute regardless of tags.
            #   3. Top-level fields ``mitre_id`` / ``zone`` / ``source`` /
            #      ``confidence_score`` are not valid STIX 2.1 SDO fields,
            #      so any downstream STIX parser would reject the bundle.
            #
            # The rewrite mirrors the technique branch above: a proper STIX
            # 2.1 ``tool`` SDO with ``external_references`` carrying the
            # MITRE ATT&CK ID, EdgeGuard-specific metadata under the
            # ``x_edgeguard_*`` prefix per the STIX 2.1 custom-property
            # convention (§3.1.1 of the spec), and ``labels`` populated from
            # the zone extraction already done above (in-scope here).
            if attack.kind == "tool":
                tool_id = attack.mitre_id
                tool_name = attack.name
                raw_comment = attr.get("comment", "") or ""
                uses_techniques = []
                if raw_comment.strip().startswith("MITRE_USES_TECHNIQUES:"):
                    try:
                        rest = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].lstrip()
                        nl = rest.find("\n")
                        json_part = rest if nl < 0 else rest[:nl]
                        parsed = json.loads(json_part)
                        # 2026-10: read as ``parse_attribute`` reads a tool's comment: an object's
                        # "t" list, or the older bare list; any other JSON value is no metadata
                        # (``.get`` on it raised and dropped the whole event from the conversion).
                        if isinstance(parsed, list):
                            uses_techniques = _scalar_strings(parsed)
                        else:
                            meta = _meta_object(parsed, "MITRE_USES_TECHNIQUES", attr_uuid)
                            uses_techniques = _meta_list(meta, "t")
                    except (ValueError, TypeError, json.JSONDecodeError):
                        pass
                external_refs = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tool_id,
                        "url": f"https://attack.mitre.org/software/{tool_id}/",
                    }
                ]
                stix_obj: dict = {
                    "type": "tool",
                    "spec_version": "2.1",
                    "id": f"tool--{attr_uuid}",
                    "name": tool_name,
                    "external_references": external_refs,
                }
                if labels:
                    stix_obj["labels"] = labels
                if uses_techniques:
                    stix_obj["x_edgeguard_uses_techniques"] = uses_techniques
                return _stamp_sdo(_with_entity_description(stix_obj))

            # A MITRE tactic ("TA0001 - Initial Access")
            #
            # PR-G1 Bug Hunter audit (HIGH): same three defects as the tool
            # branch above.
            #
            # PR-G1 Bugbot round-2 (Medium): initial rewrite used
            # ``"type": "attack-pattern"`` for tactics — which turned out
            # to be strictly worse than the prior broken state:
            # ``run_pipeline.py::load_stix21_to_neo4j`` (line ~567) routes
            # ALL ``attack-pattern`` objects to ``merge_technique()`` and
            # handles tactics only under ``"x-mitre-tactic"`` (line ~592).
            # So the "fix" silently created Technique nodes from Tactic
            # data (previously tactics were silently dropped because the
            # non-standard ``"type": "tactic"`` matched no consumer
            # branch). Misclassification beats silent drop.
            #
            # The correct type is MITRE ATT&CK's own custom type
            # ``x-mitre-tactic`` (STIX 2.1 §3.6 custom-object convention),
            # which the consumer already handles correctly. The
            # ``x_edgeguard_mitre_kind`` marker stays as a secondary
            # disambiguator for any code that cares, but the type alone
            # is now authoritative.
            if attack.kind == "tactic":
                tactic_id = attack.mitre_id
                tactic_name = attack.name
                tactic_external_refs = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tactic_id,
                        "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
                    }
                ]
                stix_obj = {
                    "type": "x-mitre-tactic",
                    "spec_version": "2.1",
                    "id": f"x-mitre-tactic--{attr_uuid}",
                    "name": tactic_name,
                    "external_references": tactic_external_refs,
                    "x_edgeguard_mitre_kind": "tactic",
                }
                if labels:
                    stix_obj["labels"] = labels
                return _stamp_sdo(_with_entity_description(stix_obj))

            # Not a MITRE technique/tool/tactic, treat as unknown indicator
            return None

        elif attr_type == "email-src":
            # email-addr is an SCO — use custom property instead of labels
            stix_obj = {"type": "email-addr", "spec_version": "2.1", "id": f"email-addr--{attr_uuid}", "value": value}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        # Default to indicator with pattern
        else:
            pattern = self._value_to_stix_pattern(attr_type, value)
            if pattern:
                # PR-M2 §4-F3: use the canonical four-concept timestamp
                # mapping (TIMESTAMPS.md "Layer 4 — Indicator SDO"):
                #   created   = NOW (when WE generated this SDO)
                #   modified  = NOW (just generated)
                #   valid_from= source-truthful first_seen ?? NOW
                # Pre-PR-M2 used ``attr["timestamp"]`` (raw MISP-internal
                # epoch int) for all three — strict STIX validators
                # rejected the raw epoch as ISO; lenient consumers
                # interpreted MISP's write-time as the source's first
                # observation. Both wrong.
                stix_obj = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{attr_uuid}",
                    "created": stix_now,
                    "modified": stix_now,
                    "name": f"MISP Indicator: {attr_type}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": stix_valid_from,
                }
                # PR-M2 design choice (c): mark inferred valid_from so
                # consumers can filter for source-truthful evidence.
                if valid_from_inferred:
                    stix_obj["x_edgeguard_first_seen_inferred"] = True
                if labels:
                    stix_obj["labels"] = labels
                # _stamp_sdo idempotently fills missing created/modified
                # (already set above) and attaches x_edgeguard_* extensions
                return _stamp_sdo(stix_obj)

        return None

    @staticmethod
    def _escape_stix_value(value: str) -> str:
        """Escape a string for safe embedding in a STIX pattern literal.

        STIX string literals use single-quoted syntax.  Backslash and
        single-quote must be escaped so that attacker-controlled indicator
        values (e.g. URLs, file paths) cannot break out of the literal.
        """
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _value_to_stix_pattern(self, attr_type: str, value: str) -> Optional[str]:
        """
        Convert MISP attribute to STIX pattern.

        Args:
            attr_type: MISP attribute type
            value: Attribute value (escaped before embedding in pattern literal)

        Returns:
            STIX pattern string or None
        """
        safe = self._escape_stix_value(value)
        if attr_type in ["ip-dst", "ip-src", "ipv4", "ipv6"]:
            # 2026-10: the address decides the object type (see ``_attribute_to_stix21``).
            family = ip_address_type(value) or ("ipv6" if attr_type == "ipv6" else "ipv4")
            return f"[{family}-addr:value = '{safe}']"
        elif attr_type in ["domain", "hostname"]:
            return f"[domain-name:value = '{safe}']"
        elif attr_type == "url":
            return f"[url:value = '{safe}']"
        elif attr_type in ["md5", "sha1", "sha256", "sha512"]:
            return f"[file:hashes.'{attr_type.upper()}' = '{safe}']"
        elif attr_type == "email-src":
            return f"[email-addr:value = '{safe}']"
        return None

    def fetch_stix21_from_misp(self, event_id: str) -> dict:
        """
        Fetch STIX 2.1 directly from MISP API.

        The MISP API supports returning events in STIX 2.1 format
        via the /events/{id}/stix2 endpoint.

        Args:
            event_id: MISP event ID

        Returns:
            STIX 2.1 bundle as dictionary
        """
        try:
            response = self.session.get(
                f"{self.misp_url}/events/{event_id}/stix2",
                headers={"Authorization": self.misp_api_key, "Accept": "application/json"},
                verify=SSL_VERIFY,
                timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to fetch STIX 2.1 for event {event_id}: {response.status_code}")
                # Fall back to manual conversion
                event = self.fetch_event_details(event_id)
                if event:
                    return self.convert_to_stix21(event)
                return {"error": f"HTTP {response.status_code}"}

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed fetching STIX 2.1 for event {event_id}: {e}")
            # Fall back to manual conversion
            event = self.fetch_event_details(event_id)
            if event:
                return self.convert_to_stix21(event)
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error fetching STIX 2.1: {e}")
            return {"error": str(e)}

    def _extract_threat_actor_from_tags(self, tags: List[Dict]) -> Optional[str]:
        """Extract threat actor name from MISP tags."""
        tags = normalize_misp_tag_list(tags)
        for tag in tags:
            tag_name = tag.get("name", "")
            if tag_name.startswith("threat-actor:"):
                return tag_name.replace("threat-actor:", "").strip()
            if "misp-galaxy:threat-actor" in tag_name or 'threat-actor="' in tag_name:
                # Handle formats like: misp-galaxy:threat-actor="Wizard Spider"
                if '"' in tag_name:
                    parts = tag_name.split('"')
                    if len(parts) >= 2:
                        return parts[1].strip()
        return None

    def _extract_malware_from_tags(self, tags: List[Dict]) -> List[str]:
        """Extract malware family names from MISP tags.

        2026-10: a galaxy cluster name that carries the ATT&CK software id
        (``misp-galaxy:mitre-malware="Cobalt Strike - S0154"``) names the family without it, so
        the row links the node the family is merged under (``split_attack_software_id``).
        """
        tags = normalize_misp_tag_list(tags)
        malware_list = []
        for tag in tags:
            tag_name = tag.get("name", "")
            if tag_name.startswith("malware-type:"):
                malware_list.append(tag_name.replace("malware-type:", "").strip())
            elif "misp-galaxy:malware" in tag_name or 'malware="' in tag_name:
                # Handle formats like: misp-galaxy:malware="TrickBot"
                if '"' in tag_name:
                    parts = tag_name.split('"')
                    if len(parts) >= 2:
                        malware_list.append(split_attack_software_id(parts[1])[0])
        return malware_list

    def _extract_techniques_from_tags(self, tags: List[Dict]) -> List[Dict]:
        """Extract MITRE technique IDs and names from MISP tags.

        2026-10: an id ATT&CK revoked is translated to its successor (``attack_revoked``), so the
        ``EMPLOYS_TECHNIQUE`` row it becomes lands on the technique that exists; ``name`` stays the
        tag's. Two tags that translate to the same id give one entry. Each entry lists the revoked
        ids its tags named (``cited_ids``, empty when every tag named the id itself); the row
        carries them to ``r.cited_ids`` (explainability).
        """
        techniques = self._extract_technique_tags(tags)
        revoked = load_revoked_ids()
        out: List[Dict] = []
        by_id: Dict[str, Dict] = {}
        for technique in techniques:
            cited = None
            successor = revoked.technique_successor(technique["mitre_id"])
            if successor is not None:
                logger.debug("Technique tag %s is a revoked ATT&CK id; using %s", technique["mitre_id"], successor)
                cited = technique["mitre_id"]
                technique = {**technique, "mitre_id": successor}
            entry = by_id.get(technique["mitre_id"])
            if entry is None:
                entry = {**technique, "cited_ids": []}
                by_id[technique["mitre_id"]] = entry
                out.append(entry)
            if cited is not None and cited not in entry["cited_ids"]:
                entry["cited_ids"].append(cited)
        return out

    def _extract_technique_tags(self, tags: List[Dict]) -> List[Dict]:
        """The technique ids and names the MISP tags name, as written (no translation)."""
        tags = normalize_misp_tag_list(tags)
        techniques = []
        for tag in tags:
            tag_name = tag.get("name", "")
            # Handle various MITRE ATT&CK tag formats
            if "misp-galaxy:mitre-attack-pattern" in tag_name or 'mitre-attack-pattern="' in tag_name:
                # Extract technique ID like T1059 from tag name
                if "T" in tag_name:
                    # Format: misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"
                    if '"' in tag_name:
                        parts = tag_name.split('"')
                        if len(parts) >= 2:
                            content = parts[1]
                            # Try to extract T#### from content
                            import re

                            match = re.search(r"(T\d{4}(?:\.\d{3})?)", content)
                            if match:
                                techniques.append(
                                    {
                                        "mitre_id": match.group(1),
                                        "name": content.split(" - ")[0] if " - " in content else content,
                                    }
                                )
            elif tag_name.startswith("mitre-attack:technique:"):
                # Format: mitre-attack:technique="T1059"
                import re

                match = re.search(r"(T\d{4}(?:\.\d{3})?)", tag_name)
                if match:
                    techniques.append({"mitre_id": match.group(1), "name": ""})
        return techniques

    def _extract_sector_from_tags(self, tags: List[Dict]) -> Optional[str]:
        """Extract target sector from MISP tags."""
        tags = normalize_misp_tag_list(tags)
        for tag in tags:
            tag_name = tag.get("name", "")
            if tag_name.startswith("target-sector:"):
                return tag_name.replace("target-sector:", "").strip().lower()
            elif tag_name.startswith("sector:"):
                return tag_name.replace("sector:", "").strip().lower()
        return None

    def _extract_exploits_cve_from_tags(self, tags: List[Dict]) -> List[str]:
        """Extract CVE IDs that this indicator exploits from MISP tags."""
        tags = normalize_misp_tag_list(tags)
        cves = []
        for tag in tags:
            tag_name = tag.get("name", "")
            if tag_name.startswith("exploits:"):
                cve = tag_name.replace("exploits:", "").strip()
                if cve.upper().startswith("CVE-"):
                    cves.append(cve.upper())
            elif 'cve="CVE-' in tag_name.lower() or "cve:C" in tag_name:
                # Extract CVE from various formats
                import re

                match = re.search(r"(CVE-\d{4}-\d+)", tag_name, re.IGNORECASE)
                if match:
                    cves.append(match.group(1).upper())
        return cves

    # Report-scoped linking (2026-10 fresh-baseline PR). An OTX pulse is the
    # only "report" unit the pipeline currently carries end to end, so these
    # are the only relationship kinds derived from co-membership.
    _REPORT_LINK_CONFIDENCE = 0.6
    _REPORT_LINK_MATCH_TYPE = "otx_pulse"
    _MAX_REPORT_INDICATORS = 2000
    _MAX_REPORT_MALWARE = 50
    # 2026-10-18: the CVEs of one report an indicator is linked to, under the rule of the malware cap.
    _MAX_REPORT_CVES = 50
    _MAX_REPORT_ACTORS = 10

    def _build_cross_item_relationships(self, items: List[Dict], reports: Optional[set] = None) -> List[Dict]:
        """
        Build report-scoped relationships between items from **exactly one** MISP event.

        **Contract (do not violate):** ``items`` must be the parsed rows for a **single**
        ``full_event`` only — e.g. in ``run()``: ``_dedupe_parsed_items(event_items)``
        where ``event_items`` came from that event's attributes only.

        **2026-10 change (fresh-baseline PR, finding F1 of the ResilMesh conformance
        check):** whole-event pairing was removed. EdgeGuard MISP events are
        per-source, per-day buckets (``EdgeGuard-<source>-<date>``), so linking every
        indicator to every malware and every malware to every actor in the same event
        asserted relationships no source had made (e.g. one malware attributed to 152
        actors, median 91). Items are now paired only when they come from the **same
        source report** — today that is the OTX pulse (``item["pulse_id"]``), which the
        OTX collector carries on indicators, malware and actors and the MISP writer
        round-trips. Items without a report id are never paired.

        Relationship kinds produced:
        - Indicator -> INDICATES -> Malware          (same pulse; ``match_type`` ``otx_pulse``, 0.6)
        - Indicator -> INDICATES -> CVE              (same pulse; ``otx_pulse``, 0.6; 2026-10-18): the
          indicator and the CVE are named in the same report, the same evidence as the Malware row. It
          never says that the indicator exploits the CVE (``EXPLOITS`` is the indicator's own CVE tag,
          ``build_relationships`` steps 3a / 3b). The CVE node is matched by ``cve_id``, never created.
        - Malware -> ATTRIBUTED_TO -> ThreatActor    (same pulse, when the actors it names are one actor;
          ``otx_pulse``, 0.6). A pulse that names several actors does not say which malware is whose
          (2026-10): its malware is attributed to none of them. The aliases of one actor count as one
          (``canonical_threat_actors.actor_identities``). The OTX collector judges the pulse's whole
          adversary list and marks such a pulse on its items (``several_actor_pulses``, or
          ``several_actor_pulses_by_name`` when it judged by name without the reference); items
          written without the mark are judged by the actors the event carries.
        - Indicator -> TARGETS -> Sector, Vulnerability -> AFFECTS -> Sector
          (from each item's own ``zone``; unchanged)

        Every row names its feed (``source``) and the feed's record ids (``source_refs``):
        report rows the OTX pulse (``alienvault_otx:<pulse id>``), zone rows the item's own
        feed and record ids.

        No longer produced here: ThreatActor -> EMPLOYS_TECHNIQUE (comes from the node's
        ``uses_techniques`` / ``reported_techniques`` lists in ``build_relationships``),
        Indicator -> EXPLOITS (only the indicator's own ``cve_id`` tag asserts that; see
        ``build_relationships`` Q3).

        Caps per report: ``_MAX_REPORT_INDICATORS`` indicators, ``_MAX_REPORT_MALWARE`` malware,
        ``_MAX_REPORT_CVES`` CVEs and ``_MAX_REPORT_ACTORS`` actors, the first ones in the order of
        ``items``; a cap that applies is logged. The callers pass the items in event order, an
        incremental run too (``_event_order_key``), so a full and an incremental sync pair the same items.

        An incremental run passes ``reports``, the reports of its changed items: only those are grouped.
        The build input holds every item of them (the changed items and the unchanged items that share a
        report with one), but of another report only the items that also belong to one of those, and
        cut at the caps such a partial report could keep an item a full sync does not link.

        Args:
            items: Parsed items for **one** event only.
            reports: The report ids to group (incremental run); None groups every report of ``items``.
                The zone rows are built for every item except those marked ``report_context``
                (unchanged attributes of an incremental run that join only the report-scoped build).

        Returns:
            List of relationship definitions to merge in Neo4j.
        """
        relationships: List[Dict] = []

        # All items in this list share the same MISP event (single-event contract above).
        # Stamp it on every constructed relationship for provenance.
        _evt_id = ""
        for _i in items:
            _eid = _i.get("misp_event_id")
            if _eid:
                _evt_id = str(_eid)
                break

        # Group by source report. Only OTX pulses carry a report id today. An item
        # de-duplicated within the event keeps the other pulses it appeared in under
        # ``report_ids`` (see ``_dedupe_parsed_items``), so it joins every one of them.
        by_report: Dict[str, Dict[str, List[Dict]]] = {}
        for item in items:
            candidate_ids = [item.get("pulse_id")] + list(item.get("report_ids") or [])
            for report_id in candidate_ids:
                if not report_id or not isinstance(report_id, str):
                    continue
                report_id = report_id.strip()
                if not report_id or (reports is not None and report_id not in reports):
                    continue
                bucket = by_report.setdefault(
                    report_id, {"indicators": [], "malware": [], "actors": [], "cves": [], "all": []}
                )
                bucket["all"].append(item)
                if item.get("indicator_type") or item.get("type") == "indicator":
                    if item.get("value"):
                        bucket["indicators"].append(item)
                elif item.get("type") == "malware" and item.get("name"):
                    bucket["malware"].append(item)
                elif item.get("type") == "actor" and item.get("name"):
                    bucket["actors"].append(item)
                elif item.get("type") == "vulnerability":
                    # 2026-10-18: a CVE the report names (an OTX indicator of type CVE or a pulse's
                    # ``cve_references`` item, both a MISP ``vulnerability`` attribute), once per report.
                    cve_id = resolve_vulnerability_cve_id(item)
                    if cve_id and cve_id not in bucket["cves"]:
                        bucket["cves"].append(cve_id)

        for report_id, bucket in by_report.items():
            # The report is the record behind every link of this bucket (``alienvault_otx:<pulse>``).
            _report_ref = format_source_ref(_REPORT_SCOPED_SOURCE_ID, report_id)
            report_refs = [_report_ref] if _report_ref else []
            indicators = bucket["indicators"]
            malware_items = bucket["malware"]
            actors = bucket["actors"]
            if len(indicators) > self._MAX_REPORT_INDICATORS:
                logger.info(
                    "Report %s: capping indicators %s -> %s for report-scoped linking",
                    report_id,
                    len(indicators),
                    self._MAX_REPORT_INDICATORS,
                )
                indicators = indicators[: self._MAX_REPORT_INDICATORS]
            if len(malware_items) > self._MAX_REPORT_MALWARE:
                logger.info(
                    "Report %s: capping malware %s -> %s", report_id, len(malware_items), self._MAX_REPORT_MALWARE
                )
                malware_items = malware_items[: self._MAX_REPORT_MALWARE]
            if len(actors) > self._MAX_REPORT_ACTORS:
                logger.info("Report %s: capping actors %s -> %s", report_id, len(actors), self._MAX_REPORT_ACTORS)
                actors = actors[: self._MAX_REPORT_ACTORS]
            cve_ids = bucket["cves"]
            if len(cve_ids) > self._MAX_REPORT_CVES:
                logger.info("Report %s: capping CVEs %s -> %s", report_id, len(cve_ids), self._MAX_REPORT_CVES)
                cve_ids = cve_ids[: self._MAX_REPORT_CVES]

            # Indicator -> Malware (INDICATES): the pulse lists these IOCs under these
            # malware families.
            for indicator in indicators:
                for malware in malware_items:
                    relationships.append(
                        {
                            "rel_type": "INDICATES",
                            "from_type": "Indicator",
                            "from_key": {
                                "value": indicator.get("value"),
                                "indicator_type": indicator.get("indicator_type", "unknown"),
                            },
                            "to_type": "Malware",
                            "to_key": {"name": malware["name"]},
                            "confidence": self._REPORT_LINK_CONFIDENCE,
                            "match_type": self._REPORT_LINK_MATCH_TYPE,
                            "report_id": report_id,
                            "source": _REPORT_SCOPED_SOURCE_ID,
                            "source_refs": report_refs,
                            "misp_event_id": _evt_id,
                        }
                    )

            # Indicator -> CVE (INDICATES, 2026-10-18): the pulse names these IOCs and these CVEs. The
            # same evidence as the Malware rows above ("named in the same report"); EXPLOITS stays the
            # indicator's own CVE claim.
            for indicator in indicators:
                for cve_id in cve_ids:
                    relationships.append(
                        {
                            "rel_type": "INDICATES",
                            "from_type": "Indicator",
                            "from_key": {
                                "value": indicator.get("value"),
                                "indicator_type": indicator.get("indicator_type", "unknown"),
                            },
                            "to_type": "CVE",
                            "to_key": {"cve_id": cve_id},
                            "confidence": self._REPORT_LINK_CONFIDENCE,
                            "match_type": self._REPORT_LINK_MATCH_TYPE,
                            "report_id": report_id,
                            "source": _REPORT_SCOPED_SOURCE_ID,
                            "source_refs": report_refs,
                            "misp_event_id": _evt_id,
                        }
                    )

            # Malware -> ThreatActor (ATTRIBUTED_TO): the pulse names an adversary for
            # these malware families. Only when the actors it names are one actor (2026-10): a pulse
            # naming several does not say which family is whose (on the hosted graph of 2026-10-15,
            # 515 of 3,727 such links came from 29 pulses naming 2 to 7 actors). The OTX collector
            # decides it on the pulse's whole adversary list and records the pulse in
            # ``several_actor_pulses`` on every item of it: MISP drops an actor or family it already
            # holds, so this event may carry only some of the pulse's actors. For items written before
            # that field existed, the actors of the bucket are judged (all of them, before the cap).
            if malware_items and bucket["actors"]:
                # 2026-10: a mark judged by name (the collector had no canonical reference) counts too.
                several = any(
                    report_id in (item.get("several_actor_pulses") or [])
                    or report_id in (item.get("several_actor_pulses_by_name") or [])
                    for item in bucket["all"]
                )
                if not several:
                    names = [a.get("name") for a in bucket["actors"]]
                    several = len(actor_identities(names, self._report_actor_reference())) > 1
                if several:
                    self.stats["reports_with_several_actors"] += 1
                    logger.info(
                        "[ATTRIBUTION] report %s names several actors: its malware is attributed to none of them",
                        report_id,
                    )
                    actors = []
            for malware in malware_items:
                for actor in actors:
                    relationships.append(
                        {
                            "rel_type": "ATTRIBUTED_TO",
                            "from_type": "Malware",
                            "from_key": {"name": malware["name"]},
                            "to_type": "ThreatActor",
                            "to_key": {"name": actor["name"]},
                            "confidence": self._REPORT_LINK_CONFIDENCE,
                            "match_type": self._REPORT_LINK_MATCH_TYPE,
                            "report_id": report_id,
                            "source": _REPORT_SCOPED_SOURCE_ID,
                            "source_refs": report_refs,
                            "misp_event_id": _evt_id,
                        }
                    )

        # Build sector relationships from zone tags. Canonical edges:
        #   Indicator     → Sector  via TARGETS
        #   Vulnerability → Sector  via AFFECTS  (PR #33 round 12)
        # An unchanged attribute that joins only the report-scoped build (``report_context``, incremental
        # runs) gets none: its sector links were written with its node (``_same_report_context``).
        for item in items:
            if item.get("report_context"):
                continue
            zones = item.get("zone", [])
            if isinstance(zones, str):
                zones = [zones]
            # The zone tag is the item's own: the link names the item's feed and record ids.
            _item_source = canonical_source_id(item.get("tag")) or "misp"
            _item_refs = list(item.get("source_refs") or [])
            # 2026-10-16 (sector evidence): the label and confidence follow from what the feed did,
            # through one table (``sector_evidence``): a sector CISA's ICS advisory states is
            # ``advisory_sector`` at 0.9 on AFFECTS; a sector an OTX pulse's own industries state is
            # ``otx_industries`` at 0.6 on TARGETS (2026-10-18); every other sector is
            # ``zone_classification`` at 0.5. A stated sector cites only the records that stated it
            # (``stated_refs``: of a CISA item, the advisories that name the sector; of an OTX item, the
            # pulses whose industries state it); a sector the item's feed inferred cites all of the item's
            # references. ``build_relationships`` steps 7a-7d compute the same.
            _item_stated = item.get("stated_zones")
            _item_stated_refs = item.get("stated_refs")

            # Map zones to sector names
            for zone in zones:
                if zone and zone != "global":
                    sector_name = zone.lower()
                    item_type = item.get("type", "")

                    # Only MISP vulnerability rows become :Vulnerability AFFECTS (not arbitrary cve_id fields).
                    if item_type == "vulnerability":
                        cve_id = resolve_vulnerability_cve_id(item)
                        if cve_id:
                            _label, _conf = sector_link_evidence(_item_source, sector_name, _item_stated, "AFFECTS")
                            relationships.append(
                                {
                                    "rel_type": "AFFECTS",
                                    "from_type": "Vulnerability",
                                    "from_key": {"cve_id": cve_id},
                                    "to_type": "Sector",
                                    "to_key": {"name": sector_name},
                                    "confidence": _conf,
                                    "match_type": _label,
                                    "source": _item_source,
                                    "source_refs": sector_zone_refs(_item_stated_refs, sector_name, _item_refs),
                                    "misp_event_id": _evt_id,
                                }
                            )
                    elif item.get("indicator_type") or item_type == "indicator":
                        # Indicator → Sector — canonical TARGETS.
                        value = item.get("value")
                        indicator_type = item.get("indicator_type", "unknown")
                        if value:
                            _label, _conf = sector_link_evidence(_item_source, sector_name, _item_stated, "TARGETS")
                            relationships.append(
                                {
                                    "rel_type": "TARGETS",
                                    "from_type": "Indicator",
                                    "from_key": {
                                        "value": value,
                                        "indicator_type": indicator_type,
                                    },
                                    "to_type": "Sector",
                                    "to_key": {"name": sector_name},
                                    "confidence": _conf,
                                    "match_type": _label,
                                    "source": _item_source,
                                    "source_refs": sector_zone_refs(_item_stated_refs, sector_name, _item_refs),
                                    "misp_event_id": _evt_id,
                                }
                            )

        return relationships

    def _with_provenance(self, item: Dict, relationships: List[Dict]) -> Tuple[Dict, List[Dict]]:
        """Stamp the feed and its record ids on ``item`` and on every relationship it asserts (2026-10).

        ``source`` is the attribute's feed (canonical registry id, from its ``source:*`` tag);
        ``source_refs`` are that feed's own record ids (``_item_source_refs``); ``stated_zones``
        (2026-10-16) the zones the feed states itself (``sector_evidence.stated_zones``, from the item's
        zones and, for OTX, its pulse's ``otx_industries`` and the later pulses' ``report_stated_zones``), and
        ``stated_refs`` which of its records stated which of them (``_item_zone_refs``). The writer
        accumulates both on the edge as ``r.sources`` / ``r.source_refs`` and on the
        node's ``SOURCED_FROM`` edge, so every link traces back to the feed record and,
        through ``misp_event_ids``, to the MISP event that carried it.
        """
        source = canonical_source_id(item.get("tag")) or "misp"
        refs = _item_source_refs(item, source)
        if refs:
            item["source_refs"] = refs
        # 2026-10-16 (sector evidence): the zones the feed states itself (CISA ICS: every specific zone
        # of the attribute; OTX, 2026-10-18: those the industries of its pulses map to; an inferring feed:
        # none). The writer keeps them on the node's SOURCED_FROM edge of this feed, and the zone rows of
        # ``_build_cross_item_relationships`` read them.
        stated = sector_stated_zones(
            source, item.get("zone"), item.get("otx_industries"), item.get("report_stated_zones")
        )
        if stated:
            item["stated_zones"] = stated
            # Which record stated which sector (CISA ICS: the advisories that name it; OTX: the pulses whose
            # industries state it), so a sector link cites only those, not every advisory that names the CVE.
            stated_refs = sector_stated_refs(stated, _item_zone_refs(item, source))
            if stated_refs:
                item["stated_refs"] = stated_refs
        for rel in relationships:
            rel.setdefault("source", source)
            if refs:
                rel.setdefault("source_refs", list(refs))
        return item, relationships

    def _skip_unreadable_attack_value(self, value: str, attr_uuid: str, event_info: Dict) -> None:
        """Log and count a ``text`` value that starts like an ATT&CK id but holds no valid one (2026-10-20).

        ``stats["attack_values_skipped"]`` and ``edgeguard_misp_attributes_dropped_total{reason=
        "attack_id_invalid"}`` count them; the run summary repeats the count. The skip does not fail
        the run.
        """
        logger.warning(
            "[ATTACK-VALUE] Skipped MISP text attribute %s (event %s): %r starts like an ATT&CK entry but "
            "holds no valid ATT&CK id (technique T1234 or T1234.123, tactic TA1234, software S1234, then "
            "' - ' or ': ' and the name). A MISP Import Regexp rule may have rewritten it; no node is "
            "created from it.",
            attr_uuid or "?",
            event_info.get("id", "?"),
            value[:200],
        )
        stats = getattr(self, "stats", None)
        if isinstance(stats, dict):
            stats["attack_values_skipped"] = int(stats.get("attack_values_skipped", 0) or 0) + 1
        try:
            from metrics_server import record_misp_attribute_dropped

            record_misp_attribute_dropped("attack_id_invalid")
        except Exception:
            logger.debug("Metrics recording for a skipped ATT&CK value failed", exc_info=True)

    def parse_attribute(self, attr: Dict, event_info: Dict) -> Tuple[Optional[Dict], List[Dict]]:
        """
        Parse a MISP attribute into an EdgeGuard-compatible item.

        Returns:
            Tuple of (item_dict, relationships_list)
            item_dict: The node data to create
            relationships_list: List of relationship definitions to create after node creation
        """
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        tags = normalize_misp_tag_list(attr.get("Tag", []))

        # Reject null/empty/whitespace — do not build nodes or edges on unknown values
        if value is None:
            return None, []
        value = str(value).strip()
        if not value:
            return None, []

        # PR (security A9) — Red Team Tier A: cap inbound attribute value
        # size. Without this, a poisoned/buggy upstream feed (compromised
        # OTX pulse, hostile feed indicator, malformed NVD item)
        # could stuff a 100MB string into one attribute → sync worker
        # OOMs, MISP cache bloats, Neo4j page cache thrashes once stored.
        # 4 KB is generous: longest legitimate MISP value is a SHA-512
        # (128 chars), an IPv6 address (45 chars), or a long URL (~2KB).
        # 4096 chars is well above the 99.9th percentile.
        # Operators with genuine large-value use cases (rare) can override
        # via EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES.
        #
        # PR #40 commit X (bugbot MED): cap is read ONCE at module load
        # (see ``_read_max_attr_value_bytes`` above), not per row. The
        # previous form re-parsed the env var on every call → measurable
        # CPU on million-attribute baselines, plus malformed env values
        # would re-raise per-row instead of failing fast at startup.
        encoded_len = len(value.encode("utf-8"))
        if encoded_len > _MAX_ATTR_VALUE_BYTES:
            logger.warning(
                "Refusing oversized MISP attribute value (%d bytes > cap %d) — "
                "type=%s event=%s. Set EDGEGUARD_MISP_MAX_ATTR_VALUE_BYTES to override.",
                encoded_len,
                _MAX_ATTR_VALUE_BYTES,
                attr_type,
                event_info.get("id", "?"),
            )
            return None, []

        # MISP attribute UUID — stable cross-instance identifier (unlike attr.id which
        # is a per-instance auto-increment). Captured once and threaded into every
        # item dict so Neo4j nodes carry direct traceability back to the originating
        # MISP attribute. Falls back to "" — merge_indicators_batch / merge_node_with_source
        # treat empty as "absent" and skip the array append.
        attr_misp_uuid = str(attr.get("uuid", "") or "")

        # MISP event id — used to stamp provenance on relationships built by this
        # parser so edges carry the originating event back to MISP (mirrors the
        # node-level misp_event_id field). Captured once for use in every
        # relationships.append below.
        _evt_id = str(event_info.get("id", "") or "")

        # 2026-10-20: an ATT&CK technique, tactic or tool is a ``text`` attribute "<id> - <name>" (or the
        # earlier "<id>: <name>"), read by ``attack_values.parse_attack_value``. A value that starts like
        # an ATT&CK id but holds no valid one, such as a value MISP's Import Regexp rules rewrote
        # ("T1059.00%WINDIR%\Command Shell"), is skipped: it made a Technique node with a broken
        # ``mitre_id`` and no name, or an ``unknown`` Indicator.
        attack_value: Optional[AttackValue] = None
        if attr_type == "text" and looks_like_attack_value(value):
            attack_value = parse_attack_value(value)
            if attack_value is None:
                self._skip_unreadable_attack_value(value, attr_misp_uuid, event_info)
                return None, []

        source_id = self.extract_source_from_tags(tags)

        # Zone resolution with priority layers:
        #   1. Attribute has its own specific zone tags → use those exclusively (most precise)
        #   2. No specific attr zone → merge event-level Tag zones + event name
        # Fix: previously event-level Tag zones were never consulted; only event NAME was used.
        _zones_from_attr = self.extract_zones_from_tags(tags)
        _specific_from_attr = [_z for _z in _zones_from_attr if _z != "global"]

        if _specific_from_attr:
            # Attribute carries its own zone — use it exclusively
            zones = sorted(_specific_from_attr)
        else:
            # Supplement from event-level sources
            _az: set = set(_zones_from_attr)
            for _z in self.extract_zones_from_tags(event_info.get("Tag", [])):
                _az.add(_z)
            _zone_from_name = self._extract_zone_from_event_name(event_info.get("info", ""))
            if _zone_from_name:
                _az.add(_zone_from_name)
            _specific_az = {_z for _z in _az if _z != "global"}
            zones = sorted(_specific_az) if _specific_az else ["global"]

        # Parse confidence from tags
        confidence = 0.5
        for tag in tags:
            tag_name = tag.get("name", "")
            if tag_name == "confidence:high":
                confidence = 0.8
            elif tag_name == "confidence:medium":
                confidence = 0.5
            elif tag_name == "confidence:low":
                confidence = 0.3

        # Extract relationship metadata from tags
        relationships = []
        threat_actor = self._extract_threat_actor_from_tags(tags)
        malware_list = self._extract_malware_from_tags(tags)
        techniques = self._extract_techniques_from_tags(tags)
        target_sector = self._extract_sector_from_tags(tags)
        exploits_cves = self._extract_exploits_cve_from_tags(tags)

        # Handle CVE/vulnerability
        if attr_type == "vulnerability":
            cve_id = value.upper()

            # Parse NVD_META JSON from comment (written by MISPWriter for NVD-sourced CVEs).
            # This restores the full CVSS/CWE/ref_tags payload so merge_cve() can create
            # CVSSv4/v3.1/v3.0/v2 sub-nodes without calling NVD again.
            raw_comment = attr.get("comment", "") or ""
            nvd_meta: dict = {}
            if raw_comment.startswith("NVD_META:"):
                try:
                    nvd_meta = json.loads(raw_comment[len("NVD_META:") :])
                except ValueError:
                    logger.warning(f"Failed to parse NVD_META for {cve_id}; reading the CVE without it")
                if not isinstance(nvd_meta, dict):
                    nvd_meta = {}
            # 2026-10: each CVSS payload as a CVSS sub-node can hold it, before anything reads it
            # (``_meta_cvss_payload``): a malformed one would fail the CVE's CVSS sub-write, which counts
            # as an error, on every sync.
            for _cvss in CVSS_VERSIONS:
                if _cvss.payload_key in nvd_meta:
                    nvd_meta[_cvss.payload_key] = _meta_cvss_payload(nvd_meta, _cvss.payload_key, cve_id)

            # 2026-10: score and severity come only from the CVSS payloads in NVD_META, in the
            # order v3.1 → v3.0 → v2 → v4.0 (``cvss_selection.select_cvss``, which applies the
            # PR-N14 clamp). The ``cvss:`` / ``severity:`` tags are not read: MISPWriter tagged an
            # unscored CVE ``cvss:low`` (read back as 3.0 / LOW on 14,451 CVEs of the hosted
            # 730-day baseline), the CISA KEV and ICS records carried values derived from
            # ransomware use or a collector default, and CVSS 3.0 was never read. The CVE node's
            # own values are set by ``Neo4jClient.merge_cve`` from its CVSS sub-nodes; these item
            # values serve the ``:Vulnerability`` paths.
            cvss_score, severity, cvss_version = select_cvss(nvd_meta)
            _rejected_scores = {
                v.payload_key: nvd_meta[v.payload_key].get("base_score")
                for v in CVSS_VERSIONS
                if isinstance(nvd_meta.get(v.payload_key), dict)
                and nvd_meta[v.payload_key].get("base_score") not in (None, "")
                and clamp_cvss_score(nvd_meta[v.payload_key].get("base_score")) is None
            }
            if _rejected_scores:
                # PR-N14: a source claimed a non-finite or out-of-range score (``"1e309"`` from a
                # compromised MISP peer); it is skipped, never stored.
                logger.warning(
                    "CVSS base_score rejected by clamp for %s (%r) — skipped. Compromised feed?",
                    value,
                    _rejected_scores,
                )
            # 2026-10: the attack vector of the CVSS payload that gives the score, in NVD's words, and
            # None without CVSS (``cvss_selection.cvss_attack_vector``). NVD_META's own
            # ``attack_vector`` is not read: copies written before 2026-10 hold a letter of the
            # vector string ("N", "L", "A", "P") or "UNKNOWN" from NVD and an invented "NETWORK"
            # from KEV and ICS, and an attribute without NVD_META (OTX) got "NETWORK".
            attack_vector = cvss_attack_vector(nvd_meta)
            # 2026-10: NVD_META's own ``description``; a comment that is another metadata block gives its
            # own ``description`` field or none, and a note of where the CVE was seen (an OTX pulse
            # reference, MISPWriter's placeholder) gives none (``_vulnerability_comment_description``).
            # The raw block used to become the description (an OTX pulse indicator stored its
            # ``OTX_META`` JSON on the CVE), and an NVD_META without a description, or one that failed to
            # parse, stored itself.
            if nvd_meta:
                _meta_description = nvd_meta.get("description")
                description = (
                    _meta_description if isinstance(_meta_description, str) and _meta_description.strip() else None
                )
            else:
                description = _vulnerability_comment_description(raw_comment)
            # CISA's knownRansomwareCampaignUse: in NVD_META of the KEV collector's records since
            # 2026-10; older KEV attributes carry only the ``ransomware:known`` tag.
            known_ransomware_use = nvd_meta.get("known_ransomware_use") or (
                "Known" if any(t.get("name") == "ransomware:known" for t in tags) else None
            )

            # Vulnerability → Sector — canonical AFFECTS (PR #33 round 12).
            canon_cve = normalize_cve_id_for_graph(cve_id)
            if target_sector and canon_cve:
                # 2026-10-18: a foreign ``sector:`` / ``target-sector:`` tag is no statement EdgeGuard
                # tracks: ``zone_classification`` at the table's confidence (``_tag_sector_evidence``).
                _label, _conf = _tag_sector_evidence(source_id, target_sector, "AFFECTS")
                relationships.append(
                    {
                        "rel_type": "AFFECTS",
                        "from_type": "Vulnerability",
                        "from_key": {"cve_id": canon_cve},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": _conf,
                        "match_type": _label,  # 2026-10 audit: every edge carries an evidence label
                        "misp_event_id": _evt_id,
                    }
                )

            # PR (S5): extract source-truthful first_seen / last_seen via the
            # allowlist + MISP-native + META-fallback resolver. Returns
            # (None, None) for sources not on the reliable allowlist —
            # then n.first_seen_at_source stays NULL ("we don't know"),
            # which the merge MIN-logic handles correctly.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(
                attr, source_id, nvd_meta=nvd_meta, event_info=event_info
            )

            # Single entry with zone as array for cross-zone queries
            item = {
                "type": "vulnerability",
                "cve_id": cve_id,
                "description": description,
                "zone": zones,
                "tag": source_id,
                "source": [source_id],
                # PR (S5) (user-surfaced semantic gap):
                # the legacy ``item["first_seen"]`` field was polluted
                # by MISP event_info.date (= "when EdgeGuard wrote the
                # MISP event"), not "when the source first observed
                # the IOC". For CVE-2013 imported today, it was setting
                # first_seen=2026-04-18 (today's event date) on a
                # 13-year-old vulnerability. Deleted — consumers
                # should read ``first_seen_at_source`` (source-truth,
                # may be NULL) OR ``first_imported_at`` (EdgeGuard
                # sync time, always set) depending on what they
                # actually need. The Cypher ON CREATE SET path
                # stamps first_imported_at = datetime() in neo4j_client.
                "first_seen_at_source": _fs_at_source,
                "last_seen_at_source": _ls_at_source,
                # 2026-10: NVD's own record (an NVD attribute with NVD_META): merge_cve then sets the
                # data only NVD supplies from it even where it is now empty (``_replace_nvd_owned_cve_data``).
                "nvd_record": source_id == "nvd" and bool(nvd_meta),
                "published": nvd_meta.get("published", ""),
                "last_modified": nvd_meta.get("last_modified", ""),
                "confidence_score": confidence,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "known_ransomware_use": known_ransomware_use,
                "attack_vector": attack_vector,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                "tlp": _extract_tlp_tag(tags, attr_misp_uuid),  # 2026-10: tlp:<level> tag → n.tlp
                "relationships": relationships,
                # ResilMesh-compatible fields — populated when NVD_META is present
                "cwe": nvd_meta.get("cwe", []),
                "ref_tags": nvd_meta.get("ref_tags", []),
                "reference_urls": nvd_meta.get("reference_urls", []),
                "cpe_type": nvd_meta.get("cpe_type", []),
                "result_impacts": nvd_meta.get("result_impacts", []),
                "affected_products": nvd_meta.get("affected_products", []),
                # CVSS sub-node payloads — triggers merge_cve() to create CVSS sub-nodes
                "cvss_v40_data": nvd_meta.get("cvss_v40_data"),
                "cvss_v31_data": nvd_meta.get("cvss_v31_data"),
                "cvss_v30_data": nvd_meta.get("cvss_v30_data"),
                "cvss_v2_data": nvd_meta.get("cvss_v2_data"),
                # CISA KEV exploitability intelligence
                "cisa_exploit_add": nvd_meta.get("cisa_exploit_add", ""),
                "cisa_action_due": nvd_meta.get("cisa_action_due", ""),
                "cisa_required_action": nvd_meta.get("cisa_required_action", ""),
                "cisa_vulnerability_name": nvd_meta.get("cisa_vulnerability_name", ""),
                # PR-N13 Fix #3 rehydration: ``version_constraints`` + ``status``
                # mirror of the NVD_META extension in ``misp_writer.py``.
                # ``merge_cve`` in neo4j_client.py already consumes both
                # fields when present (JSON-serialize logic at ~L2389-2431).
                "version_constraints": nvd_meta.get("version_constraints", []),
                "status": nvd_meta.get("status", []),
                # 2026-10: CISA's SSVC decision points from NVD's record; merge_cve sets them from an
                # NVD record only (``nvd_record``), and validates them there.
                "ssvc": nvd_meta.get("ssvc") if isinstance(nvd_meta.get("ssvc"), dict) else None,
            }
            # 2026-10-16: a CISA ICS record's advisory ids, CISA's own sector names (all 16, the three
            # mapped to zones and the others such as Water) and the zones of each advisory, from
            # NVD_META. They reach the node's SOURCED_FROM edge in ``raw_data`` and give the record
            # references ``cisa_ics:<advisory id>`` (``_item_source_refs``), per sector only those of
            # the advisories that name it (``_item_zone_refs``). Only when the record carries them: NVD
            # and KEV items have none.
            for _meta_key in ("advisory_ids", "ics_sectors"):
                _values = _meta_list(nvd_meta, _meta_key)
                if _values:
                    item[_meta_key] = _values
            _advisory_zones = _meta_advisory_zones(nvd_meta)
            if _advisory_zones:
                item["advisory_zones"] = _advisory_zones
            # 2026-10-18: the OTX pulse that names the CVE (``OTX_META.pulse_id`` and the other pulses of the
            # collector run, ``report_ids``): an OTX indicator of type CVE carries the block as every OTX
            # indicator does, and since 2026-10-18 so does a pulse's ``cve_references`` item. The report-scoped
            # build links the pulse's indicators to the CVE (Indicator -> INDICATES -> CVE), and the CVE's
            # record cites the pulse (``source_refs``). A CVE without the block (an older ``cve_references``
            # attribute, "Referenced in OTX pulse: <name>") names no pulse and is linked to no indicator.
            item.update(_vulnerability_report_ids(raw_comment, attr_misp_uuid))
            return self._with_provenance(item, relationships)

        # Handle threat actor
        elif attr_type == "threat-actor":
            actor_name = value

            # 2026-10 defense in depth: the OTX collector now splits composite
            # adversary strings and drops descriptive phrases before MISP, so a
            # composite or generic name reaching this parser is legacy data (or a
            # foreign MISP writer). A phrase must never become a ThreatActor node;
            # a composite is skipped rather than silently reduced to its first name.
            _cleaned_names = clean_actor_names(actor_name)
            _same_name = len(_cleaned_names) == 1 and (
                " ".join(unicodedata.normalize("NFC", _cleaned_names[0]).split()).casefold()
                == " ".join(unicodedata.normalize("NFC", str(actor_name)).split()).casefold()
            )
            if not _same_name:
                logger.info(
                    "Skipping threat-actor attribute %r: %s",
                    actor_name[:80],
                    "generic phrase, not a name" if not _cleaned_names else "composite name — split at collection",
                )
                return None, []

            # Parse uses_techniques from MITRE_USES_TECHNIQUES: comment prefix (same as malware/tool)
            raw_comment = attr.get("comment", "") or ""
            uses_techniques = []
            reported_techniques: List[str] = []
            actor_pulse_id = ""
            actor_report_ids: List[str] = []
            actor_several_actor_pulses: List[str] = []
            actor_several_by_name: List[str] = []
            actor_uses_malware: List[str] = []
            actor_uses_tools: List[str] = []
            actor_otx_industries: List[str] = []
            actor_report_stated_zones: List[str] = []
            # 2026-10: never the block's raw text, a placeholder or an OTX pulse's text
            # (``_entity_comment_description``); the comment used to become the description when the
            # block did not parse.
            actor_description = _entity_comment_description(raw_comment, source_id) or ""
            if "MITRE_USES_TECHNIQUES:" in raw_comment:
                try:
                    uses_json = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].strip()
                    json_part = uses_json.split("\n", 1)[0]
                    parsed = json.loads(json_part)
                    if isinstance(parsed, dict):
                        # 2026-10: list-valued keys accept only lists (``_meta_list``).
                        uses_techniques = _meta_list(parsed, "t")
                        # 2026-10: pulse-level ids ("rt") and the pulse id ("pid")
                        # written by MISPWriter._technique_meta.
                        reported_techniques = [str(x) for x in _meta_list(parsed, "rt")]
                        actor_pulse_id = str(parsed.get("pid") or "").strip()
                        actor_report_ids = [str(x).strip() for x in _meta_list(parsed, "rids") if str(x).strip()]
                        actor_several_actor_pulses = [
                            str(x).strip() for x in _meta_list(parsed, "sap") if str(x).strip()
                        ]
                        actor_several_by_name = [str(x).strip() for x in _meta_list(parsed, "sapn") if str(x).strip()]
                        actor_uses_malware = [str(x).strip() for x in _meta_list(parsed, "m") if str(x).strip()]
                        actor_uses_tools = [str(x).strip() for x in _meta_list(parsed, "s") if str(x).strip()]
                        # 2026-10-18: the OTX pulse's own industries ("ind"), its sector statement
                        # (``sector_evidence.stated_zones``, in ``_with_provenance``).
                        actor_otx_industries = [str(x).strip() for x in _meta_list(parsed, "ind") if str(x).strip()]
                        actor_report_stated_zones = _meta_report_stated_zones(parsed, "rsz", actor_report_ids)
                    elif isinstance(parsed, list):
                        uses_techniques = _scalar_strings(parsed)
                except (ValueError, IndexError):
                    logger.warning(
                        "Unreadable MITRE_USES_TECHNIQUES block for actor %r — no techniques taken", actor_name
                    )

            # 2026-10: a curated package's attribute carries claims, not a profile (see
            # CURATED_CLAIMS_PREFIX); it names the node and must not change it.
            curated_claims = _parse_curated_claims(raw_comment)
            if curated_claims is not None:
                actor_description = ""
                relationships.extend(
                    _curated_claim_rows(
                        curated_claims,
                        "ThreatActor",
                        {"name": actor_name},
                        source_id,
                        _evt_id,
                        tlp=_curated_claims_tlp(tags, event_info, attr_misp_uuid),
                    )
                )

            # Build EMPLOYS_TECHNIQUE relationships to techniques.
            # Attribution edge (who uses the TTP). See 2026-04 refactor note
            # in src/neo4j_client.py create_actor_technique_relationship.
            for technique in techniques:
                relationships.append(
                    {
                        "rel_type": "EMPLOYS_TECHNIQUE",
                        "from_type": "ThreatActor",
                        "from_key": {"name": actor_name},
                        "match_type": "misp_attribute_tag",
                        "to_type": "Technique",
                        "to_key": {"mitre_id": technique["mitre_id"]},
                        "confidence": confidence,
                        "technique_name": technique.get("name", ""),
                        "misp_event_id": _evt_id,
                        # 2026-10: revoked ids the tags named for this technique (r.cited_ids)
                        "cited_ids": technique.get("cited_ids") or [],
                    }
                )

            # Alias round-trip (2026-06): MISPWriter exports actor aliases as
            # ``alias:<name>`` tags, but this parser used to hardcode
            # ``aliases: []`` — every MISP-sourced actor reached Neo4j with
            # zero aliases (0/917 on the 2026-04 baseline), silently disabling
            # the alias-matching branches in build_relationships Q2 and any
            # alias-based lookup ("Cozy Bear" → APT29). Rehydrate here;
            # merge_actor sanitizes downstream (PR-N14: 50-item cap,
            # placeholder filter, 200-char truncation).
            actor_aliases = _extract_alias_tags(tags)

            # PR (S5): source-truthful timestamps when source is on the
            # reliable allowlist (NVD/CISA/MITRE/etc.). Returns (None, None)
            # for unreliable sources so first_seen_at_source stays NULL.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "actor",
                "name": actor_name,
                "aliases": actor_aliases,
                "deprecated": _extract_deprecated_tag(tags),  # 2026-10: ATT&CK x_mitre_deprecated
                "description": actor_description,
                "uses_techniques": uses_techniques,
                "reported_techniques": reported_techniques,
                "pulse_id": actor_pulse_id,
                "report_ids": actor_report_ids,
                "several_actor_pulses": actor_several_actor_pulses,
                "several_actor_pulses_by_name": actor_several_by_name,
                "uses_malware": actor_uses_malware,
                "uses_tools": actor_uses_tools,
                # 2026-10: a curated attribute is not merged as a node (see sync_to_neo4j)
                "curated": curated_claims is not None,
                "zone": [] if curated_claims is not None else zones,
                "tag": source_id,
                "source": [source_id],
                # PR (S5): legacy first_seen removed —
                # was polluted by MISP event_info.date. Read
                # first_seen_at_source (source-truth) OR
                # first_imported_at (DB-local) instead.
                "first_seen_at_source": _fs_at_source,
                "last_seen_at_source": _ls_at_source,
                "confidence_score": confidence,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                # 2026-10: tlp:<level> tag → n.tlp; a curated attribute leaves the node's own TLP
                "tlp": "" if curated_claims is not None else _extract_tlp_tag(tags, attr_misp_uuid),
                "relationships": relationships,
            }
            if actor_otx_industries:
                item["otx_industries"] = actor_otx_industries
            if actor_report_stated_zones:
                item["report_stated_zones"] = actor_report_stated_zones
            return self._with_provenance(item, relationships)

        # Handle malware
        elif attr_type == "malware-type":
            malware_types = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("malware-type:"):
                    malware_types.append(tag_name.replace("malware-type:", ""))

            # 2026-10: a family name that carries its ATT&CK software id ("Cobalt Strike - S0154",
            # the MISP galaxy naming; OTX attributes written before 2026-10, or another writer) is
            # merged under the base name, the node ATT&CK delivered, and kept as an alias below.
            # Merged as given, it became a Malware node of its own beside the ATT&CK one.
            malware_name, _attack_software_id = split_attack_software_id(value)

            raw_comment = attr.get("comment", "") or ""
            uses_techniques: List[str] = []
            reported_techniques: List[str] = []
            malware_pulse_id = ""
            malware_report_ids: List[str] = []
            malware_several_actor_pulses: List[str] = []
            malware_several_by_name: List[str] = []
            malware_otx_industries: List[str] = []
            malware_report_stated_zones: List[str] = []
            # 2026-10: never the block's raw text, a placeholder or an OTX pulse's text
            # (``_entity_comment_description``). The comment used to become the description when it was
            # only the block (``tail or description``: an OTX family from a pulse without a description
            # stored ``MITRE_USES_TECHNIQUES:{...}``) and when the block did not parse.
            description = _entity_comment_description(raw_comment, source_id) or ""
            if raw_comment.strip().startswith("MITRE_USES_TECHNIQUES:"):
                try:
                    rest = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].lstrip()
                    nl = rest.find("\n")
                    json_part = rest if nl < 0 else rest[:nl]
                    # 2026-10: a value other than a JSON object counts as no metadata, and list-valued
                    # keys accept only lists (``{"t": "T1059"}`` gave ['T', '1', '0', '5', '9']).
                    meta = _meta_object(json.loads(json_part), "MITRE_USES_TECHNIQUES", attr_misp_uuid)
                    uses_techniques = [str(x) for x in _meta_list(meta, "t")]
                    # 2026-10: pulse-level ids ("rt") + pulse id ("pid"), see MISPWriter._technique_meta.
                    reported_techniques = [str(x) for x in _meta_list(meta, "rt")]
                    malware_pulse_id = str(meta.get("pid") or "").strip()
                    malware_report_ids = [str(x).strip() for x in _meta_list(meta, "rids") if str(x).strip()]
                    malware_several_actor_pulses = [str(x).strip() for x in _meta_list(meta, "sap") if str(x).strip()]
                    malware_several_by_name = [str(x).strip() for x in _meta_list(meta, "sapn") if str(x).strip()]
                    # 2026-10-18: the OTX pulse's own industries ("ind"), its sector statement.
                    malware_otx_industries = [str(x).strip() for x in _meta_list(meta, "ind") if str(x).strip()]
                    malware_report_stated_zones = _meta_report_stated_zones(meta, "rsz", malware_report_ids)
                except (ValueError, TypeError, json.JSONDecodeError):
                    logger.warning(
                        "Failed to parse MITRE_USES_TECHNIQUES for malware %r; no techniques taken", malware_name
                    )

            # 2026-10: curated package claims (see CURATED_CLAIMS_PREFIX) — the node is named, not changed.
            curated_claims = _parse_curated_claims(raw_comment)
            if curated_claims is not None:
                description = ""
                malware_types = []
                relationships.extend(
                    _curated_claim_rows(
                        curated_claims,
                        "Malware",
                        {"name": malware_name},
                        source_id,
                        _evt_id,
                        tlp=_curated_claims_tlp(tags, event_info, attr_misp_uuid),
                    )
                )

            # Build ATTRIBUTED_TO relationship to threat actor
            if threat_actor:
                relationships.append(
                    {
                        "rel_type": "ATTRIBUTED_TO",
                        "from_type": "Malware",
                        "from_key": {"name": malware_name},
                        "match_type": "misp_attribute_tag",
                        "to_type": "ThreatActor",
                        "to_key": {"name": threat_actor},
                        "confidence": confidence,
                        "misp_event_id": _evt_id,
                    }
                )

            # Alias round-trip (2026-06): same carrier as actors — MISPWriter
            # exports ATT&CK malware aliases (x_mitre_aliases) as ``alias:``
            # tags; rehydrate so build_relationships Q9 INDICATES
            # (i.malware_family ∈ m.aliases) has data. merge_malware
            # sanitizes downstream. (Malware aliases no longer feed actor
            # attribution — the Q2 Branch-3 path was removed as a forgery
            # vector; only the actor's OWN aliases drive ATTRIBUTED_TO.)
            malware_aliases = _extract_alias_tags(tags)
            if _attack_software_id and value.lower() not in {a.lower() for a in malware_aliases}:
                malware_aliases.append(value)

            # PR (S5): source-truthful timestamps via allowlist-gated helper.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "malware",
                "name": malware_name,
                "aliases": malware_aliases,
                "deprecated": _extract_deprecated_tag(tags),  # 2026-10: ATT&CK x_mitre_deprecated
                "malware_types": []
                if curated_claims is not None
                else (malware_types if malware_types else ["unknown"]),
                "family": malware_name,
                "description": description,
                # 2026-10: a curated attribute is not merged as a node (see sync_to_neo4j)
                "curated": curated_claims is not None,
                "zone": [] if curated_claims is not None else zones,  # zone is now an array
                "tag": source_id,
                "source": [source_id],
                # PR (S5): legacy first_seen removed —
                # was polluted by MISP event_info.date. Read
                # first_seen_at_source (source-truth) OR
                # first_imported_at (DB-local) instead.
                "first_seen_at_source": _fs_at_source,
                "last_seen_at_source": _ls_at_source,
                "confidence_score": confidence,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                # 2026-10: tlp:<level> tag → n.tlp; a curated attribute leaves the node's own TLP
                "tlp": "" if curated_claims is not None else _extract_tlp_tag(tags, attr_misp_uuid),
                "uses_techniques": uses_techniques,
                "reported_techniques": reported_techniques,
                "pulse_id": malware_pulse_id,
                "report_ids": malware_report_ids,
                "several_actor_pulses": malware_several_actor_pulses,
                "several_actor_pulses_by_name": malware_several_by_name,
                "relationships": relationships,
            }
            if malware_otx_industries:
                item["otx_industries"] = malware_otx_industries
            if malware_report_stated_zones:
                item["report_stated_zones"] = malware_report_stated_zones
            return self._with_provenance(item, relationships)

        # Handle MITRE technique (text "T1059.001 - PowerShell"; ``attack_values``)
        elif attack_value is not None and attack_value.kind == "technique":
            mitre_id = attack_value.mitre_id
            name = attack_value.name

            # 2026-10: a technique ATT&CK revoked (an id the revoked-id map lists) is not a node any
            # more; the MITRE collector stopped writing it, and an attribute written before that would
            # bring the node back. Links that cite the id land on its successor (build_relationships).
            if load_revoked_ids().technique_successor(mitre_id) is not None:
                logger.debug("Skipping technique attribute %s: a revoked ATT&CK id", mitre_id)
                return None, []

            platforms = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("platform:"):
                    platforms.append(tag_name.replace("platform:", ""))

            # Parse tactic_phases from MITRE_TACTIC_PHASES: comment prefix
            raw_comment = attr.get("comment", "") or ""
            tactic_phases = []
            # 2026-10: never the block's raw text or a placeholder (``_entity_comment_description``); the
            # comment used to become the description when the block did not parse.
            technique_description = _entity_comment_description(raw_comment, source_id) or ""
            if "MITRE_TACTIC_PHASES:" in raw_comment:
                try:
                    phases_json = raw_comment.split("MITRE_TACTIC_PHASES:", 1)[1].strip()
                    json_part = phases_json.split("\n", 1)[0]
                    parsed = json.loads(json_part)
                    # 2026-10: through the META guards of the other blocks. ``{"p": "initial-access"}``
                    # became a string of phases, and a list holding a map, a list or a null reached the
                    # node property, which Neo4j refuses (the whole batch failed). A bare list, which no
                    # writer produces, is still read; only its strings and numbers are kept.
                    if isinstance(parsed, list):
                        tactic_phases = _scalar_strings(parsed)
                    else:
                        tactic_phases = _meta_list(_meta_object(parsed, "MITRE_TACTIC_PHASES", attr_misp_uuid), "p")
                except (ValueError, IndexError):
                    logger.warning("Unreadable MITRE_TACTIC_PHASES block for technique %s — no tactics taken", mitre_id)

            # PR (S5): source-truthful timestamps. Once the MITRE collector
            # commit (8/10) extracts STIX created/modified, these become
            # populated for MITRE entities; until then NULL is the honest
            # answer.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "technique",
                "attack_domain": _extract_attack_domain_tag(tags),  # 2026-10: enterprise | ics
                "deprecated": _extract_deprecated_tag(tags),  # 2026-10: ATT&CK x_mitre_deprecated
                "mitre_id": mitre_id,
                "name": name,
                "description": technique_description,
                "tactic_phases": tactic_phases,
                "zone": zones,
                "tag": source_id,
                "source": [source_id],
                "platforms": platforms,
                # PR (S5): legacy first_seen removed —
                # was polluted by MISP event_info.date. Read
                # first_seen_at_source (source-truth) OR
                # first_imported_at (DB-local) instead.
                "first_seen_at_source": _fs_at_source,
                "last_seen_at_source": _ls_at_source,
                "confidence_score": 0.8,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                "tlp": _extract_tlp_tag(tags, attr_misp_uuid),  # 2026-10: tlp:<level> tag → n.tlp
                "relationships": relationships,
            }
            return self._with_provenance(item, relationships)

        # Handle MITRE tactic (text "TA0001 - Initial Access"; ``attack_values``)
        elif attack_value is not None and attack_value.kind == "tactic":
            mitre_id = attack_value.mitre_id
            name = attack_value.name

            shortname = ""
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("mitre-tactic:"):
                    shortname = tag_name.replace("mitre-tactic:", "")
                    break

            # PR (S5): source-truthful timestamps via allowlist-gated helper.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "tactic",
                "attack_domain": _extract_attack_domain_tag(tags),  # 2026-10: enterprise | ics
                "deprecated": _extract_deprecated_tag(tags),  # 2026-10: ATT&CK x_mitre_deprecated
                "mitre_id": mitre_id,
                "name": name,
                "shortname": shortname,
                # 2026-10: never a placeholder ("MITRE ATT&CK tactic") or a block (``_entity_comment_description``)
                "description": _entity_comment_description(attr.get("comment"), source_id) or "",
                "zone": zones,
                "tag": source_id,
                "source": [source_id],
                # PR (S5): legacy first_seen removed —
                # was polluted by MISP event_info.date. Read
                # first_seen_at_source (source-truth) OR
                # first_imported_at (DB-local) instead.
                "first_seen_at_source": _fs_at_source,
                "last_seen_at_source": _ls_at_source,
                "confidence_score": 0.95,  # MITRE ATT&CK range
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                "tlp": _extract_tlp_tag(tags, attr_misp_uuid),  # 2026-10: tlp:<level> tag → n.tlp
            }
            return self._with_provenance(item, relationships)

        # Handle MITRE tool (text "S0154 - Cobalt Strike"; ``attack_values``)
        elif attack_value is not None and attack_value.kind == "tool":
            mitre_id = attack_value.mitre_id
            name = attack_value.name

            # Extract uses_techniques from MITRE_USES_TECHNIQUES comment
            # Format: "MITRE_USES_TECHNIQUES:{"t":["T1059","T1071"]}\nDescription..."
            uses_techniques = []
            raw_comment = attr.get("comment", "") or ""
            # 2026-10: never the block's raw text or a placeholder ("MITRE ATT&CK tool: <name>",
            # ``_entity_comment_description``); the comment used to become the description when the block
            # did not parse, and the placeholder whenever the tool had no techniques.
            description = _entity_comment_description(raw_comment, source_id) or ""
            if "MITRE_USES_TECHNIQUES:" in raw_comment:
                try:
                    uses_json = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].strip()
                    json_part = uses_json.split("\n", 1)[0]
                    parsed = json.loads(json_part)
                    if isinstance(parsed, dict):
                        uses_techniques = _meta_list(parsed, "t")  # 2026-10: lists only
                    elif isinstance(parsed, list):
                        uses_techniques = _scalar_strings(parsed)
                except (ValueError, IndexError):
                    logger.warning("Unreadable MITRE_USES_TECHNIQUES block for tool %s — no techniques taken", mitre_id)

            tool_types = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("tool-type:"):
                    tool_types.append(tag_name.replace("tool-type:", ""))

            # Build sector-targeting relationship from tag-extracted sector
            if target_sector:
                _label, _conf = _tag_sector_evidence(source_id, target_sector, "TARGETS")
                relationships.append(
                    {
                        "rel_type": "TARGETS",
                        "from_type": "Tool",
                        "from_key": {"mitre_id": mitre_id},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": _conf,
                        "match_type": _label,  # 2026-10 audit: every edge carries an evidence label
                        "misp_event_id": _evt_id,
                    }
                )

            # PR (S5): source-truthful timestamps via allowlist-gated helper.
            _fs_at_source_tool, _ls_at_source_tool = extract_source_truthful_timestamps(
                attr, source_id, event_info=event_info
            )
            item = {
                "type": "tool",
                "mitre_id": mitre_id,
                "name": name,
                "deprecated": _extract_deprecated_tag(tags),  # 2026-10: ATT&CK x_mitre_deprecated
                "description": description,
                "zone": zones,
                "tag": source_id,
                "source": [source_id],
                "tool_types": tool_types,
                "uses_techniques": uses_techniques,
                # PR (S5): legacy first_seen removed (see
                # vulnerability site for the rationale).
                "first_seen_at_source": _fs_at_source_tool,
                "last_seen_at_source": _ls_at_source_tool,
                "confidence_score": 0.9,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                "tlp": _extract_tlp_tag(tags, attr_misp_uuid),  # 2026-10: tlp:<level> tag → n.tlp
            }
            return self._with_provenance(item, relationships)

        # Handle indicators (IP, domain, hash, etc.)
        else:
            indicator_type = self.TYPE_MAPPING.get(attr_type, "unknown")
            if attr_type in MISP_IP_ATTRIBUTE_TYPES:
                # 2026-10: MISP sends IPv4 and IPv6 addresses as ``ip-dst`` / ``ip-src``, so the
                # address decides; before, every IPv6 IOC was stored and exported as ``ipv4``.
                indicator_type = ip_address_type(value) or indicator_type

            # Build INDICATES relationships to malware families
            for malware_name in malware_list:
                relationships.append(
                    {
                        "rel_type": "INDICATES",
                        "from_type": "Indicator",
                        "from_key": {"value": value, "indicator_type": indicator_type},
                        "to_type": "Malware",
                        "to_key": {"name": malware_name},
                        "confidence": confidence,
                        "match_type": "misp_attribute_tag",  # 2026-10 audit: every edge carries an evidence label
                        "misp_event_id": _evt_id,
                    }
                )

            # Build TARGETS relationship to sector
            if target_sector:
                _label, _conf = _tag_sector_evidence(source_id, target_sector, "TARGETS")
                relationships.append(
                    {
                        "rel_type": "TARGETS",
                        "from_type": "Indicator",
                        "from_key": {"value": value, "indicator_type": indicator_type},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": _conf,
                        "match_type": _label,  # 2026-10 audit: every edge carries an evidence label
                        "misp_event_id": _evt_id,
                    }
                )

            # Build EXPLOITS relationships to CVEs (skip null/blank CVE ids)
            for raw_cve in exploits_cves:
                exp_cve = normalize_cve_id_for_graph(raw_cve)
                if not exp_cve:
                    logger.debug(
                        "Skipping malformed CVE reference in EXPLOITS: %s", raw_cve[:50] if raw_cve else "None"
                    )
                    continue
                relationships.append(
                    {
                        "rel_type": "EXPLOITS",
                        "from_type": "Indicator",
                        "from_key": {"value": value, "indicator_type": indicator_type},
                        "to_type": "Vulnerability",
                        "to_key": {"cve_id": exp_cve},
                        "confidence": max(
                            confidence, 0.7
                        ),  # explicit CVE tag match floors at 0.7, respects tag confidence
                        "misp_event_id": _evt_id,
                        "match_type": "cve_tag",  # 2026-10 audit: every edge carries an evidence label
                    }
                )

            # Parse OTX_META or TF_META JSON from comment (written by MISPWriter).
            # Mirrors the NVD_META pattern for vulnerability attributes.
            raw_comment = attr.get("comment", "") or ""
            otx_meta: dict = {}
            tf_meta: dict = {}
            # 2026-10: a value other than a JSON object (``OTX_META:null``, ``TF_META:"s"``) counts as
            # no metadata (``_meta_object``) instead of failing the event on ``.get``.
            if raw_comment.startswith("OTX_META:"):
                try:
                    otx_meta = _meta_object(json.loads(raw_comment[len("OTX_META:") :]), "OTX_META", attr_misp_uuid)
                except ValueError:
                    logger.debug("Failed to parse OTX_META for %s %s", indicator_type, value[:30])
            elif raw_comment.startswith("TF_META:"):
                try:
                    tf_meta = _meta_object(json.loads(raw_comment[len("TF_META:") :]), "TF_META", attr_misp_uuid)
                except ValueError:
                    logger.debug("Failed to parse TF_META for %s %s", indicator_type, value[:30])

            # PR (S5): source-truthful timestamps. The helper consults
            # MISP-native attr.first_seen first (lossless round-trip path
            # populated by MISPWriter:664), then falls back to the
            # source-specific META JSON (TF_META.first_seen for ThreatFox).
            # Returns (None, None) for sources NOT on the reliable
            # allowlist (OTX pulse-created is excluded — it's
            # publish-date, not IOC first-observed).
            _fs_at_source_ind, _ls_at_source_ind = extract_source_truthful_timestamps(
                attr, source_id, tf_meta=tf_meta, event_info=event_info
            )

            item = {
                "indicator_type": indicator_type,
                "value": value,
                "first_seen_at_source": _fs_at_source_ind,
                "last_seen_at_source": _ls_at_source_ind,
                "zone": zones,  # zone is now an array
                "tag": source_id,
                "source": [source_id],
                # PR (S5): legacy first_seen removed (see
                # vulnerability site for the rationale).
                "confidence_score": confidence,
                "pulse_name": otx_meta.get("pulse_name") or tf_meta.get("malware_family") or raw_comment,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
                "tlp": _extract_tlp_tag(tags, attr_misp_uuid),  # 2026-10: tlp:<level> tag → n.tlp
                "relationships": relationships,
                # 2026-10-16: the report this attribute makes (recorded_at, reported_at, report_ref,
                # reported_basis), the time the indicator ages from (``indicator_aging``).
                **misp_report_times(attr, event_info),
            }

            # Enrich indicator with OTX pulse metadata
            if otx_meta:
                # 2026-10: list-valued keys accept only lists (``_meta_list``).
                item["attack_ids"] = _meta_list(otx_meta, "attack_ids")
                item["targeted_countries"] = _meta_list(otx_meta, "targeted_countries")
                item["pulse_tags"] = _meta_list(otx_meta, "pulse_tags")
                item["pulse_references"] = _meta_list(otx_meta, "pulse_references")
                item["pulse_author"] = otx_meta.get("pulse_author", "")
                item["pulse_tlp"] = otx_meta.get("pulse_tlp", "")
                item["otx_industries"] = _meta_list(otx_meta, "otx_industries")
                item["description"] = otx_meta.get("description", "")
                # PR-N10 Fix #3: ``malware_family`` and ``attributed_to``
                # of OTX_META. 2026-10: both are always empty, because the
                # OTX collector puts neither key on an indicator, so an OTX
                # attribute gives the indicator no ``malware_family`` (what
                # Q9 matches); read for compatibility.
                # A pulse's families arrive as OTX_META.mf
                # (``pulse_malware_families``, below), which
                # build_relationships step 9b links.
                item["malware_family"] = otx_meta.get("malware_family", "")
                if isinstance(item["malware_family"], str):  # 2026-10: without an ATT&CK software id suffix
                    item["malware_family"] = split_attack_software_id(item["malware_family"])[0]
                item["attributed_to"] = otx_meta.get("attributed_to", "")
                # PR-N13 Fix #5 rehydration: pull ``pulse_id``,
                # ``indicator_role``, ``is_active`` out of OTX_META now
                # that misp_writer.py serializes them. Pre-PR-N13 all
                # three were dropped on the round-trip; ``indicator_role``
                # in particular is LIVE-WIRED at
                # ``neo4j_client.merge_indicators_batch:~L2169`` which
                # silently received None for every OTX-sourced row.
                item["pulse_id"] = otx_meta.get("pulse_id", "")
                # 2026-10: other pulses of the same run that listed the IOC (OTX_META.report_ids).
                rids = [str(x).strip() for x in _meta_list(otx_meta, "report_ids") if str(x).strip()]
                if rids:
                    item["report_ids"] = rids
                # 2026-10 (regular-update linking): OTX_META.mf / .adv → lists on the indicator
                # (family names without an ATT&CK software id suffix, see _pulse_family_lists).
                _fams, _pairs = _pulse_family_lists(otx_meta)
                if _fams:
                    item["pulse_malware_families"] = _fams
                if _pairs:
                    item["pulse_malware_actor_pairs"] = _pairs
                # 2026-10: the IOC's pulses whose adversaries are several actors (OTX collector). ``sap``
                # is judged with the canonical reference and is stored on the node (step 2d reads it);
                # ``sapn`` is judged by name without it and serves this run's linking only.
                _several = [str(x).strip() for x in _meta_list(otx_meta, "sap") if str(x).strip()]
                if _several:
                    item["several_actor_pulses"] = _several
                _several_by_name = [str(x).strip() for x in _meta_list(otx_meta, "sapn") if str(x).strip()]
                if _several_by_name:
                    item["several_actor_pulses_by_name"] = _several_by_name
                item["indicator_role"] = otx_meta.get("indicator_role", "")
                item["is_active"] = otx_meta.get("is_active", True)
                # 2026-10-18: the zones the industries of the other pulses in ``report_ids`` state (their
                # sector statement, ``sector_evidence.stated_zones``).
                _stated_by_reports = _meta_report_stated_zones(otx_meta, "report_stated_zones", rids)
                if _stated_by_reports:
                    item["report_stated_zones"] = _stated_by_reports

            # Enrich indicator with ThreatFox metadata
            if tf_meta:
                item["malware_malpedia"] = tf_meta.get("malware_malpedia", "")
                item["reference"] = tf_meta.get("reference", "")
                item["tf_tags"] = tf_meta.get("tags", [])
                item["last_seen"] = tf_meta.get("last_seen", "")
                item["threat_type_desc"] = tf_meta.get("threat_type_desc", "")
                item["malware_family"] = tf_meta.get("malware_family", "")
                item["reporter"] = tf_meta.get("reporter", "")
                # PR-N10 Fix #3: mirror OTX_META ``attributed_to`` pull-out.
                item["attributed_to"] = tf_meta.get("attributed_to", "")
                # PR-N13 Fix #4 rehydration: pull ``threat_type``,
                # ``ioc_id``, ``malware_alias`` out of TF_META. Pre-PR-N13
                # all three were dropped on round-trip; losing ``ioc_id``
                # specifically broke cross-day ThreatFox dedup.
                item["threat_type"] = tf_meta.get("threat_type", "")
                item["ioc_id"] = tf_meta.get("ioc_id", "")
                item["malware_alias"] = tf_meta.get("malware_alias", "")
                # 2026-10: optional feed-metadata keys → the Indicator properties of the same
                # name that ``merge_indicators_batch`` writes and the REST / GraphQL APIs expose.
                # Set only when present, so a source that does not report them never overwrites
                # another source's value on the shared node.
                for _opt in ("url_status", "last_online", "threat_label"):
                    _opt_val = tf_meta.get(_opt)
                    if isinstance(_opt_val, str) and _opt_val.strip():
                        item[_opt] = _opt_val.strip()[:200]
                for _opt in ("yara_rules", "sigma_rules"):
                    _opt_list = tf_meta.get(_opt)
                    if isinstance(_opt_list, list):
                        _clean = [str(x).strip()[:200] for x in _opt_list if isinstance(x, str) and x.strip()][:20]
                        if _clean:
                            item[_opt] = _clean

            return self._with_provenance(item, relationships)

    def _sync_to_neo4j_chunk(self, items: List[Dict]) -> Tuple[int, int]:
        """
        Merge one chunk of parsed items to Neo4j (partition by type, same order as before).

        Relationship dicts are *not* aggregated here — the caller already collected them
        during parse; we optionally pop ``relationships`` from items after each chunk in
        ``sync_to_neo4j`` to reduce peak RAM.

        Returns (success, errors). ``errors`` counts only REAL failures (terminal
        Neo4j exceptions, malformed items). PR-N28 (Bravo's 2026-04-23
        post-mortem): PR-N10 placeholder-name rejections (e.g. Malware
        ``name="unknown"``) are graph-safe DEFENSIVE behaviour, NOT real
        errors — they're tracked separately in ``self.stats[
        "placeholder_rejections"]`` and surfaced via the
        ``edgeguard_merge_reject_placeholder_total`` Prometheus counter (with
        a paired ``EdgeGuardMergeRejectPlaceholderSpike`` alert) but they
        no longer increment ``errors`` and therefore don't fail the sync.

        Pre-N28: 4 alienvault_otx placeholder rejections in the
        2026-04-22 21:56 UTC baseline failed the entire ``full_neo4j_sync``
        Airflow task → cascade of ``upstream_failed`` → silent Campaign=0.
        """
        success = 0
        errors = 0
        # PR-N28: tracked alongside ``errors`` but kept separate so the
        # final ``return total_errors == 0`` verdict isn't poisoned by
        # safe rejections.
        if "placeholder_rejections" not in self.stats:
            self.stats["placeholder_rejections"] = 0

        indicators = []
        vulnerabilities = []
        techniques = []
        tactics = []
        malware_items = []
        actors = []
        tools = []

        for item in items:
            item_type = item.get("type", "")

            if _item_is_vulnerability_sync_bucket(item):
                vulnerabilities.append(item)
            elif item_type == "tactic":
                tactics.append(item)
            elif item_type == "tool":
                tools.append(item)
            elif item_type == "technique" or item.get("mitre_id"):
                techniques.append(item)
            elif item_type == "malware":
                malware_items.append(item)
            elif item_type == "actor":
                actors.append(item)
            elif item.get("indicator_type") and item.get("value"):
                indicators.append(item)
            else:
                try:
                    # ``_sync_single_item`` catches its own exceptions (counting them in
                    # ``self.stats["errors"]``) and returns False for an item that no merge
                    # path accepts. Such items (unknown type, indicator without a value) used
                    # to be counted as successes; they are now reported as unroutable in the
                    # run summary. They do not fail the run: one malformed attribute in a
                    # shared MISP event must not turn every scheduled sync red.
                    if self._sync_single_item(item):
                        success += 1
                    else:
                        item_value = (item.get("value") or item.get("name") or "N/A")[:50]
                        logger.warning(
                            "[ITEM-UNROUTABLE] Item not synced (%s, %s): no merge path accepted it",
                            item_type or "unknown",
                            item_value,
                        )
                        self.stats["items_unroutable"] = int(self.stats.get("items_unroutable", 0) or 0) + 1
                except Exception as e:
                    item_type = item.get("type", "unknown")
                    # PR-G1 Bug Hunter audit (HIGH): ``dict.get(k, default)``
                    # returns ``None`` — not the default — when the key exists
                    # with a None value. ``None[:50]`` then raises TypeError
                    # INSIDE the error-recovery path, aborting the whole sync
                    # after most of the work succeeded. Use ``or`` chaining so
                    # a None-valued key falls through to the next fallback.
                    item_value = (item.get("value") or item.get("name") or "N/A")[:50]
                    logger.warning(f"[WARN] Error syncing {item_type} ({item_value}): {type(e).__name__}: {e}")
                    errors += 1

        if indicators:
            logger.info(f"Batch processing {len(indicators)} indicators...")
            by_source = {}
            for ind in indicators:
                src = ind.get("tag", "misp")
                if src not in by_source:
                    by_source[src] = []
                by_source[src].append(ind)

            for source_id, source_indicators in by_source.items():
                try:
                    batch_success, batch_errors = self.neo4j.merge_indicators_batch(
                        source_indicators, source_id=source_id
                    )
                    success += batch_success
                    errors += batch_errors
                    self.stats["indicators_synced"] += batch_success
                    logger.info(f"  ✓ {source_id}: {batch_success} indicators")
                except Exception as e:
                    logger.error(f"Batch indicator sync error for {source_id}: {e}")
                    self.neo4j_circuit.record_failure()
                    errors += len(source_indicators)

        if vulnerabilities:
            logger.info(f"Batch processing {len(vulnerabilities)} vulnerabilities...")

            def _is_rich_cve(v: Dict) -> bool:
                return bool(
                    v.get("cvss_v40_data") or v.get("cvss_v31_data") or v.get("cvss_v30_data") or v.get("cvss_v2_data")
                )

            rich_vulns = [v for v in vulnerabilities if _is_rich_cve(v)]
            plain_vulns = [v for v in vulnerabilities if not _is_rich_cve(v)]

            if rich_vulns:
                logger.info(f"  Processing {len(rich_vulns)} NVD-rich CVEs (with CVSS sub-nodes)...")
                for vuln in rich_vulns:
                    src = vuln.get("tag", "misp")
                    try:
                        # PR-N19 Fix #3 follow-up: pre-PR-N19 this loop
                        # did not check merge_cve's return value —
                        # CVEs that silently failed via return-False
                        # (e.g. unresolvable cve_id) were counted as
                        # success. Mirrors the plain_vulns loop below.
                        if self.neo4j.merge_cve(vuln, source_id=src):
                            success += 1
                            self.stats["vulnerabilities_synced"] += 1
                        else:
                            cve_id = (
                                resolve_vulnerability_cve_id(vuln) or vuln.get("cve_id") or vuln.get("value") or "?"
                            )
                            logger.warning(
                                "[MERGE-RETURNED-FALSE] rich CVE %s source=%s — merge_cve returned False. "
                                "Likely cause: resolve_vulnerability_cve_id returned falsy (missing/empty "
                                "cve_id), or the underlying merge_node_with_source or a CVE sub-write (CVSS "
                                "sub-node, NVD data, CVE score) hit a terminal error.",
                                str(cve_id)[:30],
                                src,
                            )
                            errors += 1
                    except Exception as e:
                        logger.warning(
                            "merge_cve error for %s: %s",
                            resolve_vulnerability_cve_id(vuln) or vuln.get("cve_id"),
                            e,
                        )
                        errors += 1

            if plain_vulns:
                # Plain CVEs (no CVSS sub-nodes) also use merge_cve() to ensure :CVE label
                # consistency. Previously used merge_vulnerabilities_batch() which created
                # :Vulnerability nodes — wrong label for CVEs.
                logger.info(f"  Processing {len(plain_vulns)} plain CVEs (no CVSS sub-nodes)...")
                for vuln in plain_vulns:
                    src = vuln.get("tag", "misp")
                    try:
                        if self.neo4j.merge_cve(vuln, source_id=src):
                            self.stats["vulnerabilities_synced"] += 1
                            success += 1
                        else:
                            # PR-N19 Fix #3 (post-baseline 2026-04-22, from
                            # Bravo's report): identify which CVE failed so
                            # the operator can trace the "N merge/load errors"
                            # summary to specific entities. Pre-PR-N19 the
                            # count was anonymous — the "4 errors" mystery
                            # in Event 3 was exactly this.
                            cve_id = (vuln.get("cve_id") or vuln.get("value") or "?")[:30]
                            logger.warning(
                                "[MERGE-RETURNED-FALSE] plain CVE %s source=%s — merge_cve returned False. "
                                "Likely cause: resolve_vulnerability_cve_id returned falsy, or "
                                "merge_node_with_source or a CVE sub-write (NVD data, CVE score) hit a "
                                "terminal error. See earlier logs.",
                                cve_id,
                                src,
                            )
                            errors += 1
                    except Exception as e:
                        # PR-G1 Bug Hunter audit (HIGH): defensive ``or``
                        # chain — ``get("cve_id", "?")`` returns None (not
                        # "?") when the key exists with a None value, and
                        # ``None[:20]`` would crash the error-recovery path.
                        cve_id = (vuln.get("cve_id") or "?")[:20]
                        logger.warning(f"[WARN] Error syncing plain CVE ({cve_id}): {type(e).__name__}: {e}")
                        errors += 1

        if tactics:
            logger.info(f"Processing {len(tactics)} tactics...")
            for tactic in tactics:
                try:
                    source_id = tactic.get("tag", "misp")
                    if self.neo4j.merge_tactic(tactic, source_id=source_id):
                        self.stats.setdefault("tactics_synced", 0)
                        self.stats["tactics_synced"] += 1
                        success += 1
                    else:
                        # PR-N19 Fix #3: identify the tactic on merge-returned-False.
                        tactic_id = (tactic.get("mitre_id") or tactic.get("name") or "?")[:30]
                        logger.warning(
                            "[MERGE-RETURNED-FALSE] Tactic %s source=%s — merge_tactic returned False. "
                            "Likely cause: missing/empty mitre_id (PR-N13 None-guard), or terminal Neo4j error.",
                            tactic_id,
                            source_id,
                        )
                        errors += 1
                except Exception as e:
                    logger.warning(f"Error syncing tactic: {e}")
                    errors += 1
            logger.info(f"  ✓ {len(tactics)} tactics")

        if techniques:
            logger.info(f"Processing {len(techniques)} techniques...")
            for technique in techniques:
                try:
                    source_id = technique.get("tag", "misp")
                    if self.neo4j.merge_technique(technique, source_id=source_id):
                        self.stats["techniques_synced"] += 1
                        success += 1
                    else:
                        # PR-N19 Fix #3: identify the technique on merge-returned-False.
                        tech_id = (technique.get("mitre_id") or technique.get("name") or "?")[:30]
                        logger.warning(
                            "[MERGE-RETURNED-FALSE] Technique %s source=%s — merge_technique returned False. "
                            "Likely cause: missing/empty mitre_id (PR-N13 None-guard), or terminal Neo4j error.",
                            tech_id,
                            source_id,
                        )
                        errors += 1
                except Exception as e:
                    logger.warning(f"Error syncing technique: {e}")
                    errors += 1
            logger.info(f"  ✓ {len(techniques)} techniques")

        if malware_items:
            logger.info(f"Processing {len(malware_items)} malware...")
            for malware in malware_items:
                try:
                    source_id = malware.get("tag", "misp")
                    raw_name = malware.get("name")
                    # PR-N28 (Bravo's 2026-04-23 post-mortem): PRE-CHECK for
                    # PR-N10 placeholder names so we can DISTINGUISH safe
                    # rejections from real failures. Pre-N28 both paths
                    # incremented ``errors`` and 4 placeholder rejections
                    # could fail the entire baseline sync (cascading to
                    # upstream_failed on every downstream task).
                    if is_placeholder_name(raw_name):
                        m_name = (raw_name or "?")[:30]
                        # Single info-level log at the SYNC boundary; the
                        # underlying merge_malware also logs WARN +
                        # increments the Prometheus counter.
                        logger.info(
                            "[MERGE-PLACEHOLDER-REJECTED] Malware name=%s source=%s — "
                            "PR-N10 defensive reject (graph safe, not a sync error). "
                            "Spike alert: EdgeGuardMergeRejectPlaceholderSpike (>10/15min).",
                            m_name,
                            source_id,
                        )
                        self.stats["placeholder_rejections"] += 1
                        # Still call merge_malware so the metric counter
                        # increments (defense in depth + observability).
                        # PR-N26 multi-agent audit round 2 (Bug Hunter H-2 +
                        # Red Team M3, 2-agent corroboration): this call
                        # MUST be wrapped in its own narrow try/except —
                        # without it, a Neo4j deadlock/transient error on
                        # the placeholder branch would bubble to the outer
                        # ``except Exception as e: errors += 1`` and
                        # re-introduce the exact PR-N28 cascade-fail bug
                        # this branch was meant to prevent. Metric failure
                        # must not poison the sync; log at WARN so the
                        # operator sees it but no error counter increment.
                        try:
                            self.neo4j.merge_malware(malware, source_id=source_id)
                        except Exception as _metric_err:
                            logger.warning(
                                "[MERGE-PLACEHOLDER-METRIC-FAIL] Malware name=%s source=%s: "
                                "%s: %s — observability call failed, NOT counted as sync error.",
                                m_name,
                                source_id,
                                type(_metric_err).__name__,
                                _metric_err,
                            )
                        continue
                    if self.neo4j.merge_malware(malware, source_id=source_id):
                        self.stats["malware_synced"] += 1
                        success += 1
                    else:
                        # PR-N19 Fix #3: identify the malware on merge-returned-False.
                        # PR-N28: this branch now ONLY fires for non-placeholder
                        # returned-False cases (terminal Neo4j errors, malformed
                        # data). Real errors. Increment ``errors`` so the sync
                        # task fails appropriately.
                        m_name = (raw_name or "?")[:30]
                        logger.warning(
                            "[MERGE-RETURNED-FALSE] Malware %s source=%s — merge_malware returned False "
                            "AFTER placeholder pre-check (so this is a TERMINAL error, not a defensive reject). "
                            "Investigate Neo4j logs.",
                            m_name,
                            source_id,
                        )
                        errors += 1
                except Exception as e:
                    logger.warning(f"Error syncing malware: {e}")
                    errors += 1
            logger.info(f"  ✓ {len(malware_items)} malware")

        if actors:
            logger.info(f"Processing {len(actors)} threat actors...")
            for actor in actors:
                try:
                    source_id = actor.get("tag", "misp")
                    raw_name = actor.get("name")
                    # PR-N28: same placeholder pre-check as the malware loop.
                    # ThreatActor placeholders ("unknown", "N/A") were the OTHER
                    # PR-N10 reject site flagged in Bravo's post-mortem.
                    if is_placeholder_name(raw_name):
                        a_name = (raw_name or "?")[:30]
                        logger.info(
                            "[MERGE-PLACEHOLDER-REJECTED] ThreatActor name=%s source=%s — "
                            "PR-N10 defensive reject (graph safe, not a sync error).",
                            a_name,
                            source_id,
                        )
                        self.stats["placeholder_rejections"] += 1
                        # PR-N26 multi-agent audit round 2 Bug Hunter H-2:
                        # same defense-in-depth wrap as the malware loop —
                        # metric-only call must not poison the error counter.
                        try:
                            self.neo4j.merge_actor(actor, source_id=source_id)
                        except Exception as _metric_err:
                            logger.warning(
                                "[MERGE-PLACEHOLDER-METRIC-FAIL] ThreatActor name=%s source=%s: "
                                "%s: %s — observability call failed, NOT counted as sync error.",
                                a_name,
                                source_id,
                                type(_metric_err).__name__,
                                _metric_err,
                            )
                        continue
                    if self.neo4j.merge_actor(actor, source_id=source_id):
                        self.stats["actors_synced"] += 1
                        success += 1
                    else:
                        # PR-N19 Fix #3: identify the actor on merge-returned-False.
                        # PR-N28: terminal-error-only branch (placeholder pre-check
                        # already filtered defensive rejects above).
                        a_name = (raw_name or "?")[:30]
                        logger.warning(
                            "[MERGE-RETURNED-FALSE] ThreatActor %s source=%s — merge_actor returned False "
                            "AFTER placeholder pre-check (TERMINAL error, not a defensive reject).",
                            a_name,
                            source_id,
                        )
                        errors += 1
                except Exception as e:
                    # PR-G1 Bug Hunter audit (HIGH): ``or`` chain guards
                    # against ``actor.get("name")`` returning None on a
                    # present-but-null key — see the companion fix in
                    # ``_sync_single_item`` at ~line 2693.
                    actor_name = (actor.get("name") or "unknown")[:30]
                    logger.warning(f"[WARN] Error syncing actor ({actor_name}): {type(e).__name__}: {e}")
                    errors += 1
            logger.info(f"  ✓ {len(actors)} actors")

        if tools:
            logger.info(f"Processing {len(tools)} tools...")
            for tool in tools:
                try:
                    source_id = tool.get("tag", "misp")
                    if self.neo4j.merge_tool(tool, source_id=source_id):
                        self.stats.setdefault("tools_synced", 0)
                        self.stats["tools_synced"] += 1
                        success += 1
                    else:
                        # PR-N19 Fix #3: identify the tool on merge-returned-False.
                        t_id = (tool.get("mitre_id") or tool.get("name") or "?")[:30]
                        logger.warning(
                            "[MERGE-RETURNED-FALSE] Tool %s source=%s — merge_tool returned False. "
                            "Likely cause: missing/empty mitre_id (PR-N13 None-guard), or terminal Neo4j error.",
                            t_id,
                            source_id,
                        )
                        errors += 1
                except Exception as e:
                    # PR-G1 Bug Hunter audit (HIGH): ``or`` chain guards
                    # against ``tool.get("name")`` returning None on a
                    # present-but-null key — matches the actor / CVE / item
                    # sites above.
                    tool_name = (tool.get("name") or "unknown")[:30]
                    logger.warning(f"[WARN] Error syncing tool ({tool_name}): {type(e).__name__}: {e}")
                    errors += 1
            logger.info(f"  ✓ {len(tools)} tools")

        return success, errors

    def sync_to_neo4j(self, items: List[Dict]) -> Tuple[int, int, List[Dict]]:
        """
        Sync parsed items to Neo4j with chunked processing to limit peak memory (OOM on
        tens of thousands of attributes).

        Items are sorted so tactics/techniques/malware/actors are written before
        vulnerabilities/indicators when split across chunks. Each chunk runs the same
        merge logic as before; ``merge_indicators_batch`` / ``merge_vulnerabilities_batch``
        still UNWIND in sub-batches inside ``Neo4jClient``.

        After each chunk, embedded ``relationships`` lists are removed from item dicts
        (the caller already copied them during parse). The third return value is always
        ``[]`` — use the caller's relationship list for ``_create_relationships``.

        Env:
            EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE: max items per Python-side chunk (default **500**).
            **``0``** or **``all``** (case-insensitive): single pass — all items in one chunk
            (OOM risk on large backfills; see module constants and docs).
            EDGEGUARD_DEBUG_GC: if ``1``/``true``/``yes``, run ``gc.collect()`` after each chunk
            (not recommended in small Airflow workers — can spike RAM).
        """
        if not items:
            # PR #33 round 13: emit a clear log when the sync window is empty.
            # Previously a silent early return — operators couldn't distinguish
            # "MISP returned 0 events" from "sync_to_neo4j was never called".
            logger.info("[NEO4J SYNC] no items received — skipping (empty MISP window or no parsable attributes)")
            return 0, 0, []

        # 2026-10 (curated packages): a curated attribute only names an existing node — it is
        # never merged (MERGE would create the node if the package named one the graph lacks).
        # Its claims are written by the caller as MATCH-only relationships.
        curated = sum(1 for i in items if i.get("curated"))
        if curated:
            items = [i for i in items if not i.get("curated")]
            logger.info("[NEO4J SYNC] %d curated package attribute(s): relationships only, no node merge", curated)
            if not items:
                return 0, 0, []

        indexed = list(enumerate(items))
        indexed.sort(key=lambda iv: (_neo4j_sync_item_sort_rank(iv[1]), iv[0]))
        sorted_items = [iv[1] for iv in indexed]

        n = len(sorted_items)
        raw_env = os.environ.get("EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE", "")
        chunk_size, chunk_label, explicit_single_pass = _parse_neo4j_sync_chunk_size(raw_env, n)

        total_success = 0
        total_errors = 0
        n_chunks = (n + chunk_size - 1) // chunk_size
        mode_note = " — explicit single-pass (0 or all)" if explicit_single_pass else ""
        logger.info(
            "Neo4j sync: %s items in %s chunk(s), up to %s items per chunk (EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE=%s)%s",
            n,
            n_chunks,
            chunk_size,
            chunk_label,
            mode_note,
        )

        for ci, start in enumerate(range(0, n, chunk_size)):
            chunk = sorted_items[start : start + chunk_size]
            logger.info("Neo4j sync chunk %s/%s (%s items)...", ci + 1, n_chunks, len(chunk))
            s, e = self._sync_to_neo4j_chunk(chunk)
            total_success += s
            total_errors += e
            for it in chunk:
                it.pop("relationships", None)
            # Pause between chunks to let Neo4j flush transactions
            # PR #40: env-gated to 0 by default (was hardcoded 3s × ~880 chunks
            # at baseline scale = ~44min of pure idle time per baseline). Set
            # ``EDGEGUARD_QUERY_PAUSE_SECONDS=1`` to re-enable on memory-constrained Neo4j.
            if ci < n_chunks - 1:  # Skip delay after the last chunk
                query_pause()
            # Forced full GC on huge graphs can spike RAM in small workers (OOM/SIGKILL).
            # Opt-in only: EDGEGUARD_DEBUG_GC=1
            if os.environ.get("EDGEGUARD_DEBUG_GC", "").strip().lower() in ("1", "true", "yes"):
                gc.collect()

        return total_success, total_errors, []

    def _sync_single_item(self, item: Dict) -> bool:
        """Sync a single item to Neo4j and create its relationships."""
        item_type = item.get("type", "")
        source_id = item.get("tag", "misp")
        relationships = item.get("relationships", [])

        try:
            if _item_is_vulnerability_sync_bucket(item):
                # Use merge_cve() when rich NVD metadata is present so that
                # CVSS sub-nodes (v4/v3.1/v3.0/v2) are created in the same call.
                if (
                    item.get("cvss_v40_data")
                    or item.get("cvss_v31_data")
                    or item.get("cvss_v30_data")
                    or item.get("cvss_v2_data")
                ):
                    ok = self.neo4j.merge_cve(item, source_id=source_id)
                else:
                    ok = self.neo4j.merge_vulnerability(item, source_id=source_id)
                if ok:
                    self.stats["vulnerabilities_synced"] += 1

            elif item.get("indicator_type") and item.get("value"):
                if self.neo4j.merge_indicator(item, source_id=source_id):
                    self.stats["indicators_synced"] += 1

            elif item_type == "malware":
                if self.neo4j.merge_malware(item, source_id=source_id):
                    self.stats["malware_synced"] += 1

            elif item_type == "actor":
                if self.neo4j.merge_actor(item, source_id=source_id):
                    self.stats["actors_synced"] += 1

            elif item_type == "technique":
                if self.neo4j.merge_technique(item, source_id=source_id):
                    self.stats["techniques_synced"] += 1

            elif item_type == "tactic":
                if self.neo4j.merge_tactic(item, source_id=source_id):
                    self.stats.setdefault("tactics_synced", 0)
                    self.stats["tactics_synced"] += 1
            else:
                return False

            # Now create relationships for this item
            if relationships:
                rels_created = self._create_relationships(relationships, source_id)
                self.stats["relationships_created"] += rels_created

            return True

        except Exception as e:
            logger.warning(f"Error syncing single item: {type(e).__name__}: {e}")
            self.stats["errors"] += 1
            return False

    def _write_cross_item_relationships(self, cross_rels: List[Dict]) -> int:
        """Write the builder's output with honest provenance (2026-10 review fix).

        Every row names its own feed: report-scoped rows (same OTX pulse) carry
        ``source = "alienvault_otx"`` and the pulse as ``source_refs``; the zone-derived
        TARGETS / AFFECTS rows carry the item's own feed, since the zone tag is the item's
        own. ``"misp"`` is only the fallback for a row without a feed.
        """
        if not cross_rels:
            return 0
        return self._create_relationships(cross_rels, "misp")

    def _create_relationships(self, relationships: List[Dict], source_id: str) -> int:
        """
        Create relationships in Neo4j using batched UNWIND (``Neo4jClient.create_misp_relationships_batch``).

        Chunk size: ``EDGEGUARD_REL_BATCH_SIZE`` (default ``_RELATIONSHIP_BATCH_DEFAULT``).
        """
        if not relationships:
            logger.debug("No relationships to create")
            return 0

        if not self.neo4j or not hasattr(self.neo4j, "create_misp_relationships_batch"):
            logger.error("Neo4j client missing create_misp_relationships_batch — cannot create relationships")
            return 0

        raw = os.environ.get("EDGEGUARD_REL_BATCH_SIZE", str(_RELATIONSHIP_BATCH_DEFAULT)).strip()
        try:
            chunk_sz = int(raw) if raw else _RELATIONSHIP_BATCH_DEFAULT
        except ValueError:
            chunk_sz = _RELATIONSHIP_BATCH_DEFAULT
        if chunk_sz < 1:
            chunk_sz = _RELATIONSHIP_BATCH_DEFAULT

        logger.info(
            "Creating %s relationship definitions in Neo4j (batch size %s via UNWIND)...",
            len(relationships),
            chunk_sz,
        )

        created_count = 0
        failed_rows = 0
        curated_sent = curated_matched = 0
        curated_missing: List[str] = []
        total_chunks = (len(relationships) + chunk_sz - 1) // chunk_sz
        for idx, start in enumerate(range(0, len(relationships), chunk_sz)):
            chunk = relationships[start : start + chunk_sz]
            result = self.neo4j.create_misp_relationships_batch(chunk, source_id=source_id)
            created_count += result
            # ``Neo4jClient`` returns a ``RelationshipBatchResult`` whose ``failed`` attribute
            # counts the rows of permanently failed batches. Plain ``int`` results (older
            # clients, test doubles) carry no failure information and are read as zero.
            chunk_failed = getattr(result, "failed", 0)
            if isinstance(chunk_failed, int) and chunk_failed > 0:
                failed_rows += chunk_failed
            # 2026-10 (curated packages): the result counts only the curated claims that found
            # both ends; the writer reports how many it sent and names some missing ends.
            chunk_curated = getattr(result, "curated_sent", 0)
            if isinstance(chunk_curated, int) and chunk_curated > 0:
                curated_sent += chunk_curated
                curated_matched += int(getattr(result, "curated_matched", 0) or 0)
                for name in getattr(result, "curated_missing", ()) or ():
                    if name not in curated_missing and len(curated_missing) < CURATED_MISSING_SAMPLE:
                        curated_missing.append(name)
            if total_chunks > 1 and (idx + 1) % 10 == 0:
                logger.info(
                    "  Relationship batch progress: %s/%s chunks (%s%%), %s created so far",
                    idx + 1,
                    total_chunks,
                    int((idx + 1) / total_chunks * 100),
                    created_count,
                )
            # Pause between chunks to let Neo4j flush transactions (skip after last chunk)
            # PR #40: env-gated via EDGEGUARD_QUERY_PAUSE_SECONDS (default 0).
            if idx < total_chunks - 1:
                query_pause()

        if failed_rows:
            self.stats["relationships_failed"] = int(self.stats.get("relationships_failed", 0) or 0) + failed_rows
            logger.warning(
                "[REL-ROWS-FAILED] %s of %s relationship rows were not written for source %s "
                "(permanent Neo4j batch failures; see the [BATCH-PERMANENT-FAILURE] lines above). "
                "The run will be reported as failed.",
                failed_rows,
                len(relationships),
                source_id,
            )
        if curated_sent:
            self._log_curated_claims(curated_sent, curated_matched, curated_missing)

        return created_count

    def _log_curated_claims(self, sent: int, matched: int, missing: List[str]) -> None:
        """Record and log how many curated claims attached (2026-10).

        A curated claim MATCHes both ends and creates no node, so a claim whose subject or
        object is not in the graph by its exact name or id writes nothing. Such a claim is
        not an error (the package may name entities a later baseline lacks); it is counted
        and logged with a sample of the missing names, never counted as a created link.
        """
        unattached = max(0, sent - matched)
        self.stats["curated_claims_attached"] = int(self.stats.get("curated_claims_attached", 0) or 0) + matched
        self.stats["curated_claims_unattached"] = int(self.stats.get("curated_claims_unattached", 0) or 0) + unattached
        if not unattached:
            logger.info("[CURATED] %d of %d curated claim(s) attached", matched, sent)
            return
        logger.warning(
            "[CURATED] %d of %d curated claim(s) attached; %d did not: subject or object not in the graph "
            "by exact name or id, nothing written for them. Missing (sample): %s",
            matched,
            sent,
            unattached,
            ", ".join(missing) or "(names not available)",
        )

    # Attribute page size for streaming large events (prevents OOM on 100K+ attribute events).
    _ATTR_PAGE_SIZE = 5000

    def _process_single_event(self, event_id: str, event_info: str) -> Tuple[int, int, int]:
        """Process one MISP event: fetch → parse → merge → relationships.

        For events exceeding ``_ATTR_PAGE_SIZE`` attributes, attributes are
        fetched in pages via ``/attributes/restSearch`` and each page is
        synced to Neo4j before the next page is fetched.  This keeps memory
        bounded regardless of event size.

        Returns:
            (parsed_items_count, cross_rels_count, error_count)

        Raises on unrecoverable errors so the caller can catch and continue.
        """
        logger.info(f"Processing event {event_id}: {event_info[:50]}...")

        # First, try to get the event metadata (without full attribute list for large events)
        full_event = self.fetch_event_details(event_id)
        if not full_event:
            # ``fetch_event_details`` returns None only after its retries are exhausted or on
            # a permanent (4xx / unparsable) failure. Count the event as failed so the
            # coverage-gap invariant ``events_index_total == events_processed + events_failed``
            # holds and the error count fails the run instead of reporting a silent skip.
            logger.error(
                "Event %s skipped — event details could not be fetched after retries; counted as failed",
                event_id,
            )
            self.stats["events_failed"] += 1
            self.stats["events_unfetchable"] = int(self.stats.get("events_unfetchable", 0) or 0) + 1
            return 0, 0, 1

        attributes = coerce_misp_attribute_list(full_event.get("Attribute"))
        attr_count = len(attributes)

        # Log MISP Object diagnostic (applies to both normal and paged paths)
        obj_count = len(full_event.get("Object") or [])
        if obj_count and not attributes:
            logger.warning(
                "Event %s has %s MISP Object(s) but no top-level Attribute list — "
                "sync uses flat attributes only; object attributes are not ingested yet",
                event_id,
                obj_count,
            )
        elif obj_count:
            logger.debug(
                "Event %s has %s MISP Object(s); only top-level Attribute rows are synced", event_id, obj_count
            )

        # Incremental run: write only the attributes changed since the window start. The
        # event index keeps whole events modified in the window; right after a baseline that
        # is every baseline event, and re-merging all of them made the "incremental" run as
        # long as a full sync. Unchanged attributes are kept only as report-scoped context.
        context_attrs: List = []
        since = self._attribute_filter_since()
        if since is not None:
            changed: List = []
            for attr in attributes:
                (changed if _attribute_changed_since(attr, since) else context_attrs).append(attr)
            logger.info(
                "Event %s: %s of %s attributes changed since %s",
                event_id,
                len(changed),
                attr_count,
                since.isoformat(),
            )
            if not changed:
                self.stats["events_processed"] += 1
                return 0, 0, 0
            attributes = changed
            attr_count = len(changed)

        # For large events: stream attributes in pages to avoid OOM
        if attr_count > self._ATTR_PAGE_SIZE:
            logger.info(
                "Event %s has %s attributes — streaming in pages of %s to manage memory",
                event_id,
                attr_count,
                self._ATTR_PAGE_SIZE,
            )
            return self._process_large_event_paged(event_id, full_event, attributes, context_attrs)

        # Normal path: process all attributes in memory (small/medium events)
        return self._process_event_attributes(event_id, full_event, attributes, context_attrs)

    def _attribute_filter_since(self) -> Optional[datetime]:
        """Window start for the per-attribute filter, or None for whole-event processing.

        None on a full sync, on a sector sync, and when ``EDGEGUARD_SYNC_ATTRIBUTE_FILTER``
        is false. Limitation: an edit that changes only event-level tags bumps no attribute
        timestamp, so it is not re-synced incrementally; ``NEO4J_FULL_SYNC=true`` covers it.
        """
        since = getattr(self, "_attr_since", None)
        if since is None:
            return None
        if os.getenv("EDGEGUARD_SYNC_ATTRIBUTE_FILTER", "true").strip().lower() in ("0", "false", "no", "off"):
            return None
        return since

    def _same_report_context(self, context_attrs: List, full_event: Dict, report_ids: set) -> List[Dict]:
        """Parse unchanged attributes that share a report (OTX pulse) with a changed item.

        They feed only the report-scoped cross-item build, so a new indicator still links to
        older malware of the same pulse; they are not written to Neo4j again. Each is marked
        ``report_context`` (2026-10-18): the cross-item build writes no link to a Sector for it, since
        its sector links were written with its node, whose ``SOURCED_FROM`` edge records what its feed
        stated; a row from the context alone could carry a label that edge does not record yet (a graph
        kept across a change of the label rules).
        """
        if not context_attrs or not report_ids:
            return []
        context: List[Dict] = []
        for attr in context_attrs:
            item, _rels = self.parse_attribute(attr, full_event)
            if item and _item_report_ids(item) & report_ids:
                item["report_context"] = True
                context.append(item)
        return context

    def _process_event_attributes(
        self, event_id: str, full_event: Dict, attributes: List, context_attrs: Optional[List] = None
    ) -> Tuple[int, int, int]:
        """Process a list of attributes: parse → dedup → sync → relationships.

        ``context_attrs`` (incremental runs) are unchanged attributes of the same event; the
        ones sharing a report with a written item join only the cross-item build.
        """
        event_items: List[Dict] = []
        event_embedded_rels: List[Dict] = []

        for attr in attributes:
            item, rels = self.parse_attribute(attr, full_event)
            if item:
                event_items.append(item)
                if rels:
                    event_embedded_rels.extend(rels)

        if not event_items:
            logger.debug("Event %s: no parsed items, skipping Neo4j writes", event_id)
            # Count empty-but-valid events so the invariant
            # `events_index_total == events_processed + events_failed`
            # holds for the coverage-gap alert.
            self.stats["events_processed"] += 1
            return 0, 0, 0

        unique_event_items = _dedupe_parsed_items(event_items)

        # Type-based sampling inside _build_cross_item_relationships handles O(n²) risk.
        cross_input = unique_event_items
        changed_reports = set().union(*map(_item_report_ids, unique_event_items))
        context = self._same_report_context(context_attrs, full_event, changed_reports)
        cross_reports: Optional[set] = None
        if context:
            cross_input = _dedupe_parsed_items(unique_event_items + context)
            # 2026-10-18: back in event order (the changed items came first) before the per-report caps.
            cross_input.sort(key=_event_order_key(full_event))
            # Only the reports of the changed items, whose items the input holds in full.
            cross_reports = changed_reports
        cross_rels = self._build_cross_item_relationships(cross_input, reports=cross_reports)

        logger.info(
            "Event %s: %s parsed -> %s unique items; %s embedded rel defs; %s cross-item rel defs",
            event_id,
            len(event_items),
            len(unique_event_items),
            len(event_embedded_rels),
            len(cross_rels),
        )

        _s, ev_errors, _u = self.sync_to_neo4j(unique_event_items)
        # Increment events_processed only AFTER sync_to_neo4j returns. If
        # sync_to_neo4j raises, the outer run() loop will append the event
        # to failed_events and count it as events_failed — without this
        # ordering we'd double-count events that fail during sync (both
        # processed and failed), violating the coverage-gap invariant and
        # making `EdgeGuardSyncCoverageGap` fire with a negative value.
        self.stats["events_processed"] += 1

        if event_embedded_rels:
            rels_created = self._create_relationships(event_embedded_rels, "misp")
            self.stats["relationships_created"] += rels_created
        if cross_rels:
            # Every row names its own feed and record ids (``source`` / ``source_refs``):
            # report-scoped rows the OTX pulse, zone rows the item's feed.
            rels_created = self._write_cross_item_relationships(cross_rels)
            self.stats["relationships_created"] += rels_created

        return len(event_items), len(cross_rels), ev_errors

    def _process_large_event_paged(
        self, event_id: str, full_event: Dict, all_attributes: List, context_attrs: Optional[List] = None
    ) -> Tuple[int, int, int]:
        """Process a large event by chunking its attributes into pages.

        Each page of attributes is parsed, synced to Neo4j, and then discarded
        before the next page is loaded.  This keeps peak memory proportional to
        ``_ATTR_PAGE_SIZE`` rather than the full event size.
        """
        import gc

        total_parsed = 0
        total_cross_rels = 0
        total_errors = 0
        page_size = self._ATTR_PAGE_SIZE

        # Lightweight accumulator for cross-item relationship building after all pages.
        # Stores only the fields needed by _build_cross_item_relationships (~100 bytes/item
        # vs ~2KB/item for full parsed items).
        _rel_items: List[Dict] = []
        # 2026-10: ``pulse_id`` / ``report_ids`` are what report-scoped linking groups
        # on, and ``misp_event_id`` is the provenance stamp — without them the
        # large (paged) OTX events, which hold most of the data, produced no links.
        _REL_KEYS = (
            "type",
            "name",
            "mitre_id",
            "tag",
            "indicator_type",
            "value",
            "malware_family",
            "zone",
            "cve_id",
            "pulse_id",
            "report_ids",
            "source_refs",
            "misp_event_id",
            # 2026-10: a pulse naming several actors attributes nothing; the OTX collector's mark
            # is the only record of it once MISP has dropped some of the pulse's actors.
            "several_actor_pulses",
            "several_actor_pulses_by_name",
            # 2026-10-16 (sector evidence): what the feed stated and which record stated it; without them
            # the zone rows of a paged event labelled a CISA statement ``zone_classification`` at 0.5 and
            # cited every advisory, unlike the same attribute in a smaller event.
            "stated_zones",
            "stated_refs",
            # 2026-10-18: an unchanged attribute of an incremental run that joins only the report-scoped
            # build (``_same_report_context``): no sector rows.
            "report_context",
            # 2026-10-18: the attribute's uuid, which gives the item its place in the event (``_event_order_key``).
            "misp_attribute_id",
        )
        total_attrs = len(all_attributes)
        num_pages = (total_attrs + page_size - 1) // page_size

        for page_num in range(num_pages):
            start = page_num * page_size
            end = min(start + page_size, total_attrs)
            page_attrs = all_attributes[start:end]

            logger.info(
                "Event %s: processing page %s/%s (attributes %s-%s of %s)",
                event_id,
                page_num + 1,
                num_pages,
                start + 1,
                end,
                total_attrs,
            )

            page_items: List[Dict] = []
            page_rels: List[Dict] = []

            for attr in page_attrs:
                item, rels = self.parse_attribute(attr, full_event)
                if item:
                    page_items.append(item)
                    if rels:
                        page_rels.extend(rels)

            if page_items:
                unique_items = _dedupe_parsed_items(page_items)
                _s, page_errors, _u = self.sync_to_neo4j(unique_items)
                total_parsed += len(page_items)
                total_errors += page_errors

                # Collect lightweight data for cross-item relationships (built after all pages)
                for _item in unique_items:
                    _rel_items.append({k: _item.get(k) for k in _REL_KEYS if _item.get(k) is not None})

                if page_rels:
                    rels_created = self._create_relationships(page_rels, "misp")
                    self.stats["relationships_created"] += rels_created

                # Release page memory and pause before next page
                # PR #40: env-gated via EDGEGUARD_QUERY_PAUSE_SECONDS (default 0).
                del page_items, unique_items, page_rels
                gc.collect()
                query_pause()  # Let Neo4j flush transactions between pages

            logger.info(
                "Event %s: page %s/%s done — %s items synced so far",
                event_id,
                page_num + 1,
                num_pages,
                total_parsed,
            )

        # Free the full attribute list now that all pages are processed
        del all_attributes
        gc.collect()

        # Incremental run: unchanged items of the same reports join the cross-item build only.
        _changed_reports = set().union(*map(_item_report_ids, _rel_items))
        _context = self._same_report_context(context_attrs, full_event, _changed_reports)
        _cross_reports: Optional[set] = None
        for _item in _context:
            _rel_items.append({k: _item.get(k) for k in _REL_KEYS if _item.get(k) is not None})
        if _context:
            # 2026-10-18: back in event order (the changed items came first) before the per-report caps.
            _rel_items.sort(key=_event_order_key(full_event))
            # Only the reports of the changed items, whose items the input holds in full.
            _cross_reports = _changed_reports
        del _context

        # Build cross-item relationships across ALL pages (now that all nodes are in Neo4j).
        # Uses the lightweight accumulator, not the full parsed items.
        # Type-based sampling inside _build_cross_item_relationships handles O(n²) risk.
        cross_rels = []
        if _rel_items:
            cross_rels = self._build_cross_item_relationships(_rel_items, reports=_cross_reports)
            if cross_rels:
                logger.info(
                    "Event %s: building %s report-scoped relationships from all pages...", event_id, len(cross_rels)
                )
                rels_created = self._write_cross_item_relationships(cross_rels)
                self.stats["relationships_created"] += rels_created
                total_cross_rels += rels_created
            del _rel_items
            gc.collect()

        self.stats["events_processed"] += 1
        logger.info(
            "Event %s: large-event streaming complete — %s total items, %s cross rels, %s errors",
            event_id,
            total_parsed,
            total_cross_rels,
            total_errors,
        )

        return total_parsed, total_cross_rels, total_errors

    def run(self, incremental: bool = True, since: datetime = None, sector: str = None) -> bool:
        """
        Run the full MISP to Neo4j sync with circuit breaker protection.

        Args:
            incremental: If True, only sync events since last run
            since: Specific datetime to sync from (overrides incremental)
            sector: Sector to sync (applies sector-specific time ranges)

        Returns:
            True if successful, False otherwise
        """
        logger.info("=" * 60)
        logger.info("🔄 MISP → Neo4j Sync Started")
        if sector:
            logger.info(f"📍 Sector: {sector}")
        logger.info("=" * 60)

        self._last_sync_failure_reason = None
        self.stats["start_time"] = datetime.now(timezone.utc).isoformat()

        # Determine sync window
        self._attr_since = None
        if since:
            logger.info(f"Syncing events since: {since}")
        elif sector:
            since_str = get_sector_cutoff_date(sector)
            logger.info(f"Sector '{sector}' sync: fetching events since {since_str}")
            since = datetime.strptime(since_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        elif incremental:
            # Fetch window matches sync interval (default 3 days) + 1 day overlap for safety.
            # Overlap is safe: MERGE is idempotent, only new data is added.
            _sync_interval_days = int(os.environ.get("EDGEGUARD_SYNC_INTERVAL_DAYS", "3"))
            _fetch_window_days = _sync_interval_days + 1  # +1 day overlap
            since = datetime.now(timezone.utc) - timedelta(days=_fetch_window_days)
            logger.info(
                f"Incremental sync: events from last {_fetch_window_days} days (interval={_sync_interval_days}d + 1d overlap)"
            )
        else:
            since = None
            logger.info("Full sync: all events")
        if not sector:
            # A sector cutoff is about data age, not write time, so it never filters attributes.
            self._attr_since = since

        # Check service availability before connecting
        available, msg = self.check_services_available()
        if not available:
            self._last_sync_failure_reason = msg
            logger.error(f"Cannot start sync: {msg}")
            self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
            record_collection_failure("misp_to_neo4j", msg)
            return False

        # Connect
        if not self.connect():
            self._last_sync_failure_reason = (
                "connect() failed — check Neo4j from the Airflow worker (NEO4J_URI, NEO4J_PASSWORD, "
                "APOC plugin) and MISP health; see log lines above."
            )
            logger.error("Failed to connect to databases")
            self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
            return False

        # Initialized up-front so the accounting gauges always have a value
        # to read in the finally block — even on early-return or crash
        # paths that exit before sorted_events is built.
        events_index_total = 0

        try:
            # Fetch events from MISP
            events = self.fetch_edgeguard_events(since=since, sector=sector)

            # Exported by the ``finally`` block below on every exit path so the
            # coverage-gap gauges reflect this run even when it stops here.
            events_index_total = len(events)
            self.stats["events_index_total"] = events_index_total

            if not events and self.stats.get("events_index_truncated"):
                # 2026-10: no EdgeGuard event among the rows the cap allowed says nothing about the
                # rows beyond it, so an empty window is not a success here.
                msg = (
                    "MISP event index stopped at the page cap (EDGEGUARD_MISP_MAX_PAGES="
                    f"{MISP_EVENTS_INDEX_MAX_PAGES} x EDGEGUARD_MISP_PAGE_SIZE={MISP_EVENTS_INDEX_PAGE_SIZE}) "
                    "with no EdgeGuard event listed: the listing is incomplete"
                )
                logger.error(msg)
                self._last_sync_failure_reason = msg
                self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
                record_collection_failure("misp_to_neo4j", msg)
                return False

            # EDGEGUARD_SYNC_MIN_EVENTS (default 1): a window returning fewer events is a failed run
            # (ERROR, no success recorded, the state file is not stamped), not an empty success.
            min_events = _sync_min_events()
            if min_events > 0 and events_index_total < min_events:
                msg = (
                    f"MISP returned {events_index_total} event(s) for the sync window but "
                    f"EDGEGUARD_SYNC_MIN_EVENTS={min_events} requires at least {min_events}; "
                    "the run is reported as failed and nothing was processed (since="
                    f"{since.isoformat() if since else 'full'}, sector={sector or 'all'})"
                )
                logger.error(msg)
                self._last_sync_failure_reason = msg
                self.stats["min_events_shortfall"] = True
                self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
                record_collection_failure("misp_to_neo4j", msg)
                # Nothing was attempted: export 0 as the input total so the coverage-gap
                # invariant (``events_index_total == events_processed + events_failed``) holds
                # and ``EdgeGuardSyncCoverageGap`` does not fire on this deliberate abort. The
                # number of events found stays in ``stats["events_index_total"]`` for the summary.
                events_index_total = 0
                return False

            if not events:
                logger.warning(
                    "No events to sync — MISP returned zero events for the window (since=%s, sector=%s). "
                    "The run is reported as successful because EDGEGUARD_SYNC_MIN_EVENTS is 0 (disabled); "
                    "set it to 1 or more to fail on an empty window.",
                    since.isoformat() if since else "full",
                    sector or "all",
                )
                self.stats["zero_events"] = True
                self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
                record_collection_success("misp_to_neo4j")
                return True

            # Per-event pipeline: cross-item links only within the same MISP event (no global O(n²) / false edges).
            total_errors = 0
            total_parsed_items = 0
            total_cross_rels_built = 0

            # Throttle between event fetches — MISP needs time to free memory
            # after serving large events (e.g. 95K-attribute NVD event).
            try:
                event_fetch_throttle = float(os.environ.get("EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC", "2.0"))
            except (ValueError, TypeError):
                event_fetch_throttle = 2.0

            # ── Fault tolerance: max attribute guard ──────────────────
            # Events with huge attribute counts (e.g. 95K NVD) can OOM-kill
            # the worker.  Skip them on first pass, retry at end if possible.
            try:
                max_event_attrs = int(os.environ.get("EDGEGUARD_MAX_EVENT_ATTRIBUTES", "50000"))
            except (ValueError, TypeError):
                max_event_attrs = 50000
            skipped_large: List[Dict] = []
            # Events that raised a transient error on the first pass. They get
            # one retry after the initial sweep finishes — gives MISP time to
            # recover from memory pressure / transient 5xx without losing the
            # entire feed (see event-4 regression: 99K NVD CVEs lost because a
            # single 500 skipped the event permanently).
            failed_events: List[Dict] = []

            # ── Sort events: smallest first ──────────────────────────
            # Process small events (MITRE, CISA) before large ones (NVD, OTX)
            # so critical data always lands even if a large event later fails.
            def _event_sort_key(ev: Dict) -> int:
                """Estimate event size from index metadata (attribute_count or 0)."""
                for key in ("attribute_count", "Attribute_count", "num_attributes"):
                    val = ev.get(key)
                    if val is not None:
                        try:
                            return int(val)
                        except (ValueError, TypeError):
                            pass
                return 0  # unknown size → process first (safe default)

            sorted_events = sorted(events, key=_event_sort_key)
            # ``events_index_total`` (set right after the fetch above) is the total input
            # size used by the coverage-gap alert to catch silently-skipped events (the
            # exact failure mode of the 2026-04-14 NVD regression).

            for ev_idx, event in enumerate(sorted_events):
                event_id = event.get("id")
                event_info = event.get("info", "")

                if event_id is None:
                    # Count as failed so the coverage-gap invariant holds:
                    # events_index_total == events_processed + events_failed.
                    # Otherwise the EdgeGuardSyncCoverageGap Prometheus alert
                    # fires false positives on every baseline run that hits
                    # a malformed MISP index row.
                    logger.warning(
                        "Skipping MISP row with no event id (info=%r) — check index/search response shape",
                        (event_info or "")[:120],
                    )
                    total_errors += 1
                    self.stats["events_failed"] += 1
                    continue

                # Check attribute count from index metadata before fetching
                est_attrs = _event_sort_key(event)
                if max_event_attrs > 0 and est_attrs > max_event_attrs:
                    logger.warning(
                        "Deferring event %s (%s, ~%s attributes) — exceeds "
                        "EDGEGUARD_MAX_EVENT_ATTRIBUTES=%s. Will retry after smaller events.",
                        event_id,
                        (event_info or "")[:60],
                        est_attrs,
                        max_event_attrs,
                    )
                    skipped_large.append(event)
                    continue

                # Pace event fetches (skip before first)
                if ev_idx > 0 and event_fetch_throttle > 0:
                    time.sleep(event_fetch_throttle)

                try:
                    ep, ecr, ee = self._process_single_event(str(event_id), event_info)
                    total_parsed_items += ep
                    total_cross_rels_built += ecr
                    total_errors += ee
                    self._consecutive_conn_failures = 0  # Reset on successful processing
                except Exception as exc:
                    logger.error(
                        "Event %s failed on first pass (%s: %s) — deferring for retry",
                        event_id,
                        type(exc).__name__,
                        str(exc)[:200],
                    )

                    # Queue for retry pass unconditionally. Accounting (total_errors
                    # / events_failed) happens in the retry loop below so we don't
                    # double-count recoveries. If the cap is exceeded, count as
                    # failed immediately — retrying 50+ events against a broken
                    # MISP will blow the Airflow execution_timeout.
                    if len(failed_events) < _MAX_RETRY_FAILED_EVENTS:
                        failed_events.append(event)
                    else:
                        logger.error(
                            "failed_events cap (%s) reached — counting event %s as permanent failure",
                            _MAX_RETRY_FAILED_EVENTS,
                            event_id,
                        )
                        total_errors += 1
                        self.stats["events_failed"] += 1

                    # If this looks like a connection failure, try to reconnect
                    _exc_str = str(exc).lower()
                    if "connection" in _exc_str or "refused" in _exc_str or "unavailable" in _exc_str:
                        consecutive_conn_failures = getattr(self, "_consecutive_conn_failures", 0) + 1
                        self._consecutive_conn_failures = consecutive_conn_failures
                        if consecutive_conn_failures >= 3:
                            logger.error(
                                "3+ consecutive Neo4j connection failures — aborting sync. "
                                "Check: docker compose ps neo4j / docker compose logs neo4j"
                            )
                            # The retry-pass bail-out below will count everything
                            # in failed_events once and only once. 2026-10: the events
                            # this loop never reached are counted here, so the coverage-gap
                            # invariant (index_total == processed + failed) holds; each of
                            # them would have ended as exactly one failure.
                            for _rem in sorted_events[ev_idx + 1 :]:
                                total_errors += 1
                                self.stats["events_failed"] += 1
                            break  # Stop burning through events with a dead Neo4j
                        logger.warning("Attempting Neo4j reconnect after connection failure...")
                        try:
                            self.neo4j.connect()
                            logger.info("Neo4j reconnected successfully")
                        except Exception:
                            logger.error("Neo4j reconnect failed")
                    else:
                        self._consecutive_conn_failures = 0  # Reset on non-connection errors

                    # Free memory after failed event (OOM recovery)
                    import gc

                    gc.collect()
                    continue

            # Retry deferred large events (only if Neo4j is still alive)
            _conn_failures = getattr(self, "_consecutive_conn_failures", 0)
            if skipped_large and _conn_failures >= 3:
                logger.error(
                    "Skipping %s deferred large event(s) — Neo4j connection failed (%s consecutive errors)",
                    len(skipped_large),
                    _conn_failures,
                )
                # Count the abandoned events as failures so operators (and
                # the Prometheus coverage-gap alert) see the real damage.
                # Every other bail-out path in this function increments
                # total_errors + events_failed; this pre-loop one was the
                # outlier that silently dropped the events from accounting.
                for _rem in skipped_large:
                    total_errors += 1
                    self.stats["events_failed"] += 1
                skipped_large = []  # Don't retry with a dead Neo4j

            if skipped_large:
                logger.info(
                    "Retrying %s deferred large event(s) (>%s attributes)...",
                    len(skipped_large),
                    max_event_attrs,
                )
                for retry_idx, event in enumerate(skipped_large):
                    # Mid-loop bail-out: if Neo4j died while we were processing
                    # earlier events, stop burning through remaining ones.
                    # Uses enumerate rather than list.index(event) because
                    # list.index() returns the FIRST equal element — if two
                    # event dicts ever shared identical content (e.g. a MISP
                    # API quirk returning duplicate rows) the slice would
                    # include already-processed events and double-count them.
                    if getattr(self, "_consecutive_conn_failures", 0) >= 3:
                        remaining = len(skipped_large) - retry_idx
                        logger.error(
                            "Neo4j dead mid-retry — counting remaining %s deferred event(s) as failed",
                            remaining,
                        )
                        for _rem in skipped_large[retry_idx:]:
                            total_errors += 1
                            self.stats["events_failed"] += 1
                        break
                    event_id = event.get("id")
                    event_info = event.get("info", "")
                    if event_fetch_throttle > 0:
                        time.sleep(event_fetch_throttle)
                    try:
                        ep, ecr, ee = self._process_single_event(str(event_id), event_info)
                        total_parsed_items += ep
                        total_cross_rels_built += ecr
                        total_errors += ee
                        self._consecutive_conn_failures = 0
                    except Exception as exc:
                        # Defer to the failed_events retry pass below (with
                        # cooldown) instead of burying it here. NVD lives in
                        # skipped_large because it's the largest event — the
                        # whole regression was its single-shot retry, so we
                        # give it the same cooldown+retry as exception-failed
                        # events, subject to the same cap.
                        logger.warning(
                            "Deferred event %s failed on first retry (%s: %s) — re-queueing with cooldown",
                            event_id,
                            type(exc).__name__,
                            str(exc)[:200],
                        )
                        if len(failed_events) < _MAX_RETRY_FAILED_EVENTS:
                            failed_events.append(event)
                        else:
                            logger.error(
                                "failed_events cap (%s) reached — counting deferred event %s as permanent failure",
                                _MAX_RETRY_FAILED_EVENTS,
                                event_id,
                            )
                            total_errors += 1
                            self.stats["events_failed"] += 1
                        # Track Neo4j connection failures across this loop
                        # too. The main event loop above resets the counter
                        # on non-connection errors via an `else:` branch;
                        # mirror that here so a transient MISP 5xx followed
                        # by an unrelated error doesn't leave the counter
                        # stuck and prematurely trigger the 3-strike
                        # Neo4j-dead bail-out.
                        _exc_str = str(exc).lower()
                        if "connection" in _exc_str or "refused" in _exc_str or "unavailable" in _exc_str:
                            self._consecutive_conn_failures = getattr(self, "_consecutive_conn_failures", 0) + 1
                        else:
                            self._consecutive_conn_failures = 0
                        # Free memory after failed large-event fetch (OOM recovery)
                        import gc

                        gc.collect()

            # ── Retry events that raised on the first pass ──────────────
            # Separate from skipped_large: those were deferred *proactively*
            # by size; these are events that hit a transient error (MISP 5xx,
            # timeout, OOM, …). Give each a single second chance before
            # counting it as a permanent failure. Fixes the regression where
            # a single MISP 500 on a large NVD event caused 99K CVEs to be
            # silently dropped from the graph.
            _conn_failures = getattr(self, "_consecutive_conn_failures", 0)
            if failed_events and _conn_failures >= 3:
                logger.error(
                    "Skipping %s event retry(s) — Neo4j connection failed (%s consecutive errors)",
                    len(failed_events),
                    _conn_failures,
                )
                for _ev in failed_events:
                    total_errors += 1
                    self.stats["events_failed"] += 1
                failed_events = []

            if failed_events:
                # Short cooldown before retrying: lets MISP memory settle and
                # any broken connection pools recycle. Reuses the existing
                # batch-throttle knob so ops can tune both together.
                try:
                    retry_cooldown = float(os.environ.get("EDGEGUARD_MISP_RETRY_COOLDOWN_SEC", "15.0"))
                except (ValueError, TypeError):
                    retry_cooldown = 15.0
                if retry_cooldown > 0:
                    logger.info(
                        "Cooling down %.1fs before retrying %s failed event(s)...",
                        retry_cooldown,
                        len(failed_events),
                    )
                    time.sleep(retry_cooldown)

                logger.info(
                    "Retrying %s event(s) that failed on the first pass...",
                    len(failed_events),
                )
                for retry_idx, event in enumerate(failed_events):
                    # Mid-loop bail-out: if a prior retry just killed Neo4j,
                    # stop and count the remaining events without thrashing.
                    if getattr(self, "_consecutive_conn_failures", 0) >= 3:
                        remaining = len(failed_events) - retry_idx
                        logger.error(
                            "Neo4j dead mid-retry — counting remaining %s event(s) as failed",
                            remaining,
                        )
                        for _rem in failed_events[retry_idx:]:
                            total_errors += 1
                            self.stats["events_failed"] += 1
                        break
                    event_id = event.get("id")
                    event_info = event.get("info", "")
                    if event_fetch_throttle > 0:
                        time.sleep(event_fetch_throttle)
                    try:
                        ep, ecr, ee = self._process_single_event(str(event_id), event_info)
                        total_parsed_items += ep
                        total_cross_rels_built += ecr
                        total_errors += ee
                        self._consecutive_conn_failures = 0
                        logger.info("Event %s recovered on retry", event_id)
                    except Exception as exc:
                        logger.error(
                            "Event %s still failed on retry (%s: %s) — skipping until next sync run",
                            event_id,
                            type(exc).__name__,
                            str(exc)[:200],
                        )
                        total_errors += 1
                        self.stats["events_failed"] += 1
                        # Same symmetry as the main and skipped_large loops:
                        # increment on connection errors, reset on everything
                        # else so non-consecutive connection errors don't
                        # accumulate and trigger the 3-strike bail-out.
                        _exc_str = str(exc).lower()
                        if "connection" in _exc_str or "refused" in _exc_str or "unavailable" in _exc_str:
                            self._consecutive_conn_failures = getattr(self, "_consecutive_conn_failures", 0) + 1
                        else:
                            self._consecutive_conn_failures = 0
                        import gc

                        gc.collect()

            logger.info(
                "Sync totals: %s parsed items across events; %s cross-item rel defs built (pre-Neo4j)",
                total_parsed_items,
                total_cross_rels_built,
            )

            # Apply secondary sector labels (:Finance, :Healthcare, etc.) to all
            # nodes that carry a non-'global' zone value.
            labeled = self.neo4j.apply_sector_labels()
            logger.info(f"Applied sector labels to {labeled} nodes")

            # Print summary
            duration = (datetime.now(timezone.utc) - datetime.fromisoformat(self.stats["start_time"])).total_seconds()
            self.stats["end_time"] = datetime.now(timezone.utc).isoformat()

            if _METRICS_AVAILABLE:
                try:
                    record_pipeline_duration("misp_to_neo4j", duration)
                except Exception:
                    logger.debug("Metrics recording failed", exc_info=True)
                # Per-run event accounting is exported from the `finally`
                # block below so it fires on every exit path (happy path,
                # no-events early return, and unhandled exception) — not
                # only on success. Without that, the gauges retain stale
                # values from the previous run on crashes.

            # Update circuit breaker states in stats
            self.stats["circuit_breaker_states"] = {
                "misp": self.misp_circuit.state.name,
                "neo4j": self.neo4j_circuit.state.name,
            }

            logger.info("\n" + "=" * 60)
            logger.info("[OK] MISP → Neo4j Sync Complete")
            logger.info("=" * 60)
            logger.info(f"Duration: {duration:.2f} seconds")
            if self.stats.get("events_index_truncated"):
                logger.warning(
                    "MISP event index was cut at the page cap this run (EDGEGUARD_MISP_MAX_PAGES=%d × "
                    "EDGEGUARD_MISP_PAGE_SIZE=%d): events beyond the cap were not synced",
                    MISP_EVENTS_INDEX_MAX_PAGES,
                    MISP_EVENTS_INDEX_PAGE_SIZE,
                )
            logger.info(f"Events processed: {self.stats['events_processed']}")
            events_failed = self.stats.get("events_failed", 0)
            if events_failed:
                logger.warning(f"Events failed (skipped): {events_failed}")
            logger.info(f"Indicators synced: {self.stats['indicators_synced']}")
            logger.info(f"Vulnerabilities synced: {self.stats['vulnerabilities_synced']}")
            logger.info(f"Malware synced: {self.stats['malware_synced']}")
            logger.info(f"Actors synced: {self.stats['actors_synced']}")
            logger.info(f"Techniques synced: {self.stats['techniques_synced']}")
            logger.info(f"Relationships created: {self.stats['relationships_created']}")
            several_actors = int(self.stats.get("reports_with_several_actors", 0) or 0)
            if several_actors:
                logger.info(
                    "Reports naming several actors, whose malware was attributed to none of them: %d "
                    "(grep '[ATTRIBUTION]')",
                    several_actors,
                )
            curated_attached = int(self.stats.get("curated_claims_attached", 0) or 0)
            curated_unattached = int(self.stats.get("curated_claims_unattached", 0) or 0)
            if curated_attached or curated_unattached:
                logger.info(
                    "Curated package claims: %d attached, %d not attached (subject or object not in the graph; "
                    "grep '[CURATED]' for the missing names)",
                    curated_attached,
                    curated_unattached,
                )
            relationships_failed = int(self.stats.get("relationships_failed", 0) or 0)
            if relationships_failed:
                logger.warning(
                    "Relationships failed (rows not written by permanent batch failures): %d",
                    relationships_failed,
                )
            logger.info(f"Errors: {total_errors}")
            items_unroutable = int(self.stats.get("items_unroutable", 0) or 0)
            if items_unroutable:
                logger.warning(
                    "Items not synced because no merge path accepted them: %d "
                    "(grep '[ITEM-UNROUTABLE]'; counted neither as success nor as error)",
                    items_unroutable,
                )
            # 2026-10-20: ATT&CK values with no valid ATT&CK id (``_skip_unreadable_attack_value``).
            attack_values_skipped = int(self.stats.get("attack_values_skipped", 0) or 0)
            if attack_values_skipped:
                logger.warning(
                    "ATT&CK values skipped because they hold no valid ATT&CK id: %d (grep '[ATTACK-VALUE]'; "
                    "a MISP Import Regexp rule may have rewritten them; not counted as errors)",
                    attack_values_skipped,
                )
            # PR-N28: surface placeholder rejections separately so operators
            # can distinguish "graph corrupted by adversarial input" from
            # "PR-N10 working as intended" at-a-glance. Already counted by
            # ``edgeguard_merge_reject_placeholder_total`` (Prometheus) +
            # alerted by ``EdgeGuardMergeRejectPlaceholderSpike``; this is
            # the inline grep-friendly version.
            placeholder_rejections = int(self.stats.get("placeholder_rejections", 0))
            if placeholder_rejections > 0:
                logger.info(
                    "Placeholder-name rejections (PR-N10 defensive, NOT errors): %d "
                    "— grep '[MERGE-PLACEHOLDER-REJECTED]' for per-entity detail. "
                    "These do NOT fail the sync.",
                    placeholder_rejections,
                )
            logger.info(
                f"Circuit Breaker States: MISP={self.misp_circuit.state.name}, Neo4j={self.neo4j_circuit.state.name}"
            )

            # Verdict: every skipped or failed unit of work (events that could not be
            # fetched or processed, items whose merge failed, relationship rows dropped
            # by permanent batch failures) marks the run as failed. Success is recorded
            # only when nothing was lost. 2026-10: an event listing cut at the page cap lost the
            # events beyond it, so it fails the run too (the DAG then keeps its cursor).
            index_truncated = bool(self.stats.get("events_index_truncated"))
            run_ok = total_errors == 0 and relationships_failed == 0 and not index_truncated
            if run_ok:
                record_collection_success("misp_to_neo4j")
            else:
                reasons = []
                if index_truncated:
                    reasons.append(
                        f"the MISP event index stopped at the page cap (EDGEGUARD_MISP_MAX_PAGES="
                        f"{MISP_EVENTS_INDEX_MAX_PAGES} x EDGEGUARD_MISP_PAGE_SIZE={MISP_EVENTS_INDEX_PAGE_SIZE}): "
                        "events beyond the cap were not synced"
                    )
                events_unfetchable = int(self.stats.get("events_unfetchable", 0) or 0)
                if events_unfetchable:
                    reasons.append(
                        f"{events_unfetchable} event(s) could not be fetched from MISP after retries "
                        "(details request failed; nothing of them was processed)"
                    )
                if events_failed - events_unfetchable > 0:
                    reasons.append(
                        f"{events_failed - events_unfetchable} event(s) failed or were skipped after retries"
                    )
                # Every failed event (unfetchable ones included) counts once in total_errors; the
                # merge/load text applies only to errors from sync_to_neo4j itself. 2026-10: only the
                # unfetchable events were subtracted, so retry-exhausted, bailed-out and id-less events
                # were also reported as merge/load errors.
                merge_errors = max(0, total_errors - events_failed)
                if merge_errors:
                    # PR-N19 Fix #3: point operators at the [MERGE-RETURNED-FALSE]
                    # grep token so the "N errors" summary is traceable to specific
                    # entities. Pre-PR-N19 the message said "see logs above" but no
                    # per-entity log actually existed for return-False cases —
                    # only for thrown exceptions.
                    reasons.append(
                        f"sync_to_neo4j reported {merge_errors} merge/load error(s); "
                        "grep '[MERGE-RETURNED-FALSE]' or '[MERGE-REJECT]' in the logs above for "
                        "per-entity detail (CVE id / Malware name / Actor name / MITRE id)"
                    )
                if relationships_failed:
                    reasons.append(
                        f"{relationships_failed} relationship row(s) were not written "
                        "(permanent Neo4j batch failures; grep '[BATCH-PERMANENT-FAILURE]')"
                    )
                self._last_sync_failure_reason = "; ".join(reasons)
                record_collection_failure("misp_to_neo4j", self._last_sync_failure_reason)

            return run_ok

        except Exception as e:
            self._last_sync_failure_reason = f"{type(e).__name__}: {e}"
            logger.error(f"[ERR] Sync failed with error: {type(e).__name__}: {e}")
            self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
            record_collection_failure("misp_to_neo4j", str(e))

            # Record failure in circuit breakers
            self.misp_circuit.record_failure()
            self.neo4j_circuit.record_failure()

            return False

        finally:
            # Reset per-run accounting gauges on every exit path (happy,
            # no-events early return, unhandled exception). Without this,
            # a run that crashes before the happy-path metrics block would
            # leave the previous run's values in Prometheus, causing
            # `EdgeGuardSyncEventsFailed` to keep firing after a clean
            # rerun or masking a crashing sync entirely.
            if _METRICS_AVAILABLE:
                try:
                    record_sync_event_accounting(
                        events_index_total=int(locals().get("events_index_total", 0) or 0),
                        events_processed=int(self.stats.get("events_processed", 0) or 0),
                        events_failed=int(self.stats.get("events_failed", 0) or 0),
                    )
                except Exception:
                    logger.debug("Sync event accounting export failed", exc_info=True)
            if self.neo4j:
                self.neo4j.close()

    def get_stats(self) -> Dict[str, Any]:
        """Get sync statistics."""
        stats = self.stats.copy()
        stats["circuit_breaker_states"] = {"misp": self.misp_circuit.state.name, "neo4j": self.neo4j_circuit.state.name}
        if self._last_sync_failure_reason:
            stats["last_failure_reason"] = self._last_sync_failure_reason
        return stats


def test_sync():
    """Test MISP to Neo4j sync."""
    sync = MISPToNeo4jSync()

    # Run incremental sync (last 3 days)
    success = sync.run(incremental=True)

    print(f"\nSync {'succeeded' if success else 'failed'}")
    print(f"Stats: {sync.get_stats()}")

    return success


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Sync MISP to Neo4j")
    parser.add_argument("--full", "-f", action="store_true", help="Full sync (all events), default is incremental")
    parser.add_argument(
        "--sector",
        "-s",
        type=str,
        choices=list(SECTOR_TIME_RANGES.keys()),
        help="Sector to sync (applies sector-specific time ranges)",
    )

    args = parser.parse_args()

    sync = MISPToNeo4jSync()
    success = sync.run(incremental=not args.full, sector=args.sector)

    sys.exit(0 if success else 1)
