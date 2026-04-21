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
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import urllib3

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
from misp_health import MISPHealthCheck
from neo4j_client import (
    Neo4jClient,
    normalize_cve_id_for_graph,
    resolve_vulnerability_cve_id,
)
from query_pause import query_pause
from resilience import check_service_health, get_circuit_breaker, record_collection_failure, record_collection_success
from source_truthful_timestamps import coerce_iso as _coerce_to_iso
from source_truthful_timestamps import extract_source_truthful_timestamps

try:
    from metrics_server import record_pipeline_duration, record_sync_event_accounting

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

# Suppress InsecureRequestWarning only when SSL verification is explicitly
# disabled in config — never globally for the whole process.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Configuration constants (defined before _pymisp_client_kwargs uses them at call time)
MISP_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
MISP_REQUEST_TIMEOUT = 300  # Read timeout (seconds) — large events (95K+ attrs) need time


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

# Substring matched against event metadata in MISP restSearch (not exact event title).
# PyMISP/MISP ``eventinfo=`` filtering is unreliable on some 2.4.x builds (e.g. 2.4.123);
# ``search`` maps to the server-side substring / full-text style filter our events need
# (titles look like ``EdgeGuard-{source}-{date}``).
MISP_EDGEGUARD_DISCOVERY_SEARCH = os.getenv("EDGEGUARD_MISP_EVENT_SEARCH", "EdgeGuard").strip() or "EdgeGuard"

# Lightweight event list (no attribute scan). restSearch with ``search=`` can scan all attributes and
# time out / 500 on very large events (e.g. URLhaus, SSL blacklist).
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


def _fetch_edgeguard_events_via_requests_index(
    session: requests.Session,
    misp_base: str,
    since: Optional[datetime],
) -> Optional[List[Dict[str, Any]]]:
    """
    Try MISP event index endpoints (paginated). Returns:
      - list (possibly empty) if an index path responded successfully;
      - None if no index URL worked (caller may fall back to PyMISP/restSearch).

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
    """
    base = misp_base.rstrip("/")
    for path in ("/events/index", "/events"):
        pages: List[Dict[str, Any]] = []
        path_unusable = False
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
                path_unusable = page == 1
                break
            if resp.status_code != 200:
                if page == 1:
                    path_unusable = True
                break
            try:
                payload = resp.json()
            except ValueError:
                path_unusable = page == 1
                break
            norm = normalize_misp_event_index_payload(payload)
            if not norm:
                break
            pages.extend(norm)
            if len(norm) < MISP_EVENTS_INDEX_PAGE_SIZE:
                break
        if path_unusable:
            continue
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


def _dedupe_parsed_items(items: List[Dict]) -> List[Dict]:
    """
    Deduplicate parsed items within a single MISP event (keys match former global dedupe).

    Used so cross-item relationship building only sees one row per logical entity per event.
    """
    seen = set()
    unique_items: List[Dict] = []
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
    SOURCE_MAPPING = {
        "AlienVault-OTX": "alienvault_otx",
        "NVD": "nvd",
        "CISA-KEV": "cisa_kev",
        "MITRE-ATT&CK": "mitre_attck",
        "VirusTotal": "virustotal",
        "AbuseIPDB": "abuseipdb",
        "Feodo-Tracker": "feodo_tracker",
        "SSL-Blacklist": "ssl_blacklist",
        "URLhaus": "urlhaus",
        "CyberCure": "cybercure",
        "ThreatFox": "threatfox",
    }

    # MISP attribute type to EdgeGuard type mapping
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
            "indicators_synced": 0,
            "vulnerabilities_synced": 0,
            "malware_synced": 0,
            "actors_synced": 0,
            "techniques_synced": 0,
            "relationships_created": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
            "circuit_breaker_states": {},
        }
        # Set when ``run()`` returns False so callers (e.g. baseline DAG) can surface a short reason.
        self._last_sync_failure_reason: Optional[str] = None
        self._consecutive_conn_failures: int = 0

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
        if index endpoints are unavailable.

        Args:
            since: Only fetch events modified since this datetime
            sector: Sector to fetch events for (applies sector-specific time ranges)

        Returns:
            List of MISP event dicts
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
            if indexed is not None:
                normalized = normalize_misp_event_index_payload(indexed)
                if normalized:
                    logger.info(f"[FETCH] Normalized {len(normalized)} MISP event(s) for processing")
                elif indexed:
                    logger.warning("[FETCH] Index returned rows but normalized to 0 events — check payload shape")
                return normalized

            logger.warning("[FETCH] Event index unavailable — falling back to PyMISP / restSearch (may be slow)")

            # Fallback: PyMISP restSearch (can be expensive on very large instances).
            try:
                from pymisp import PyMISP

                misp = PyMISP(self.misp_url, self.misp_api_key, **_pymisp_client_kwargs())

                search_kwargs: dict = {"limit": 1000, "search": MISP_EDGEGUARD_DISCOVERY_SEARCH}
                if since:
                    search_kwargs["timestamp"] = int(since.timestamp())

                misp_events = misp.search(controller="events", **search_kwargs)

                if misp_events:
                    events = list(misp_events)
                    logger.info(
                        f"[FETCH] PyMISP returned {len(events)} row(s) (since={since}); normalizing to flat Event dicts"
                    )
                else:
                    logger.info("No events found in MISP")

            except Exception as e:
                logger.error(f"PyMISP error: {e}, falling back to requests restSearch")
                rest_body: dict = {
                    "returnFormat": "json",
                    "limit": 1000,
                    "search": MISP_EDGEGUARD_DISCOVERY_SEARCH,
                }
                if since:
                    rest_body["timestamp"] = int(since.timestamp())

                response = self.session.post(
                    f"{self.misp_url.rstrip('/')}/events/restSearch",
                    json=rest_body,
                    verify=SSL_VERIFY,
                    timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT),
                )

                if response.status_code == 200:
                    events = response.json()
                    logger.info(
                        "[FETCH] events/restSearch fallback: payload type=%s — will normalize",
                        type(events).__name__,
                    )

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ChunkedEncodingError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error fetching events: {type(e).__name__}: {e}")

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

    def extract_source_from_tags(self, tags: List[Dict]) -> str:
        """Extract source_id from MISP tags."""
        tags = normalize_misp_tag_list(tags)
        for tag in tags:
            tag_name = tag.get("name", "")

            # Check for source tags
            if tag_name.startswith("source:"):
                source_name = tag_name.replace("source:", "")
                return self.SOURCE_MAPPING.get(source_name, "misp")

            # Check direct mappings
            if tag_name in self.SOURCE_MAPPING:
                return self.SOURCE_MAPPING[tag_name]

        return "misp"

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

        # Extract zones from attribute tags for STIX labels
        labels = []
        attr_tags = normalize_misp_tag_list(attr.get("Tag", []))
        for tag in attr_tags:
            tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
            if tag_name.startswith("zone:"):
                zone_name = tag_name.replace("zone:", "").lower().strip()
                all_zones.add(zone_name)
                labels.append(f"zone:{zone_name}")

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
        if attr_type in ["ip-dst", "ip-src", "ipv4"]:
            stix_obj = {"type": "ipv4-addr", "spec_version": "2.1", "id": f"ipv4-addr--{attr_uuid}", "value": value}
            if labels:
                stix_obj["x_edgeguard_zones"] = labels
            return _x_props(stix_obj)

        elif attr_type == "ipv6":
            stix_obj = {"type": "ipv6-addr", "spec_version": "2.1", "id": f"ipv6-addr--{attr_uuid}", "value": value}
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
                "description": attr.get("comment", ""),
            }
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(stix_obj)

        elif attr_type == "threat-actor":
            stix_obj = {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": f"threat-actor--{attr_uuid}",
                "name": value,
                "description": attr.get("comment", ""),
                "threat_actor_types": ["hacker"],
            }
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(stix_obj)

        elif attr_type == "malware-type":
            # Extract malware family from tags if available
            malware_types = []
            for tag in attr_tags:
                tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
                if tag_name.startswith("malware-type:"):
                    malware_types.append(tag_name.replace("malware-type:", "").strip())

            stix_obj = {
                "type": "malware",
                "spec_version": "2.1",
                "id": f"malware--{attr_uuid}",
                "name": value,
                "description": attr.get("comment", ""),
                "is_family": True,
                "malware_types": malware_types if malware_types else ["trojan"],
            }
            if labels:
                stix_obj["labels"] = labels
            return _stamp_sdo(stix_obj)

        elif attr_type == "text":
            # Check if this is a MITRE technique (format: "T1234: Name" or starts with T followed by digits)
            import re

            mitre_match = re.match(r"^(T\d{4}(?:\.\d{3})?):\s*(.+)$", value)
            if mitre_match:
                mitre_id = mitre_match.group(1)
                technique_name = mitre_match.group(2).strip()

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
                    "description": attr.get("comment", ""),
                    "external_references": external_refs,
                }
                if labels:
                    stix_obj["labels"] = labels
                return _stamp_sdo(stix_obj)

            # Check if this is a MITRE tool (format: "S0001: Mimikatz")
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
            tool_match = re.match(r"^(S\d{4}):\s*(.+)$", value)
            if tool_match:
                tool_id = tool_match.group(1)
                tool_name = tool_match.group(2).strip()
                raw_comment = attr.get("comment", "") or ""
                uses_techniques = []
                description = raw_comment
                if raw_comment.strip().startswith("MITRE_USES_TECHNIQUES:"):
                    try:
                        rest = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].lstrip()
                        nl = rest.find("\n")
                        json_part = rest if nl < 0 else rest[:nl]
                        tail = (rest[nl + 1 :].strip() if nl >= 0 else "") or ""
                        meta = json.loads(json_part)
                        uses_techniques = [str(x) for x in (meta.get("t") or [])]
                        description = tail or description
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
                    "description": description,
                    "external_references": external_refs,
                }
                if labels:
                    stix_obj["labels"] = labels
                if uses_techniques:
                    stix_obj["x_edgeguard_uses_techniques"] = uses_techniques
                return _stamp_sdo(stix_obj)

            # Check if this is a MITRE tactic (format: "TA0001: Initial Access")
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
            tactic_match = re.match(r"^(TA\d{4}):\s*(.+)$", value)
            if tactic_match:
                tactic_id = tactic_match.group(1)
                tactic_name = tactic_match.group(2).strip()
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
                    "description": attr.get("comment", ""),
                    "external_references": tactic_external_refs,
                    "x_edgeguard_mitre_kind": "tactic",
                }
                if labels:
                    stix_obj["labels"] = labels
                return _stamp_sdo(stix_obj)

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
        if attr_type in ["ip-dst", "ip-src", "ipv4"]:
            return f"[ipv4-addr:value = '{safe}']"
        elif attr_type == "ipv6":
            return f"[ipv6-addr:value = '{safe}']"
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
        """Extract malware family names from MISP tags."""
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
                        malware_list.append(parts[1].strip())
        return malware_list

    def _extract_techniques_from_tags(self, tags: List[Dict]) -> List[Dict]:
        """Extract MITRE technique IDs and names from MISP tags."""
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

    def _build_cross_item_relationships(self, items: List[Dict]) -> List[Dict]:
        """
        Build relationships between items from **exactly one** MISP event.

        **Contract (do not violate):** ``items`` must be the parsed rows for a **single**
        ``full_event`` only — e.g. in ``run()``: ``_dedupe_parsed_items(event_items)``
        where ``event_items`` came from that event's attributes only.

        **Do not** pass a list merged across the whole sync or multiple events. Doing so
        creates **false** co-occurrence edges (entities that never shared an event) and
        **O(n²)** relationship blowups. There is no global/cross-event mode here by design.

        Pairwise logic (indicator × malware, actor × technique, etc.) is intentional **within**
        one event's attribute set.

        Relationship kinds produced:
        - ThreatActor -> EMPLOYS_TECHNIQUE -> Technique
        - Malware -> ATTRIBUTED_TO -> ThreatActor
        - Indicator -> INDICATES -> Malware
        - Indicator/Vulnerability -> TARGETS -> Sector
        - Indicator -> EXPLOITS -> Vulnerability (CVE) (``rel_type`` ``EXPLOITS`` in definitions)

        Args:
            items: Parsed items for **one** event only (typically ``_dedupe_parsed_items`` on that event's list).

        Returns:
            List of relationship definitions to merge in Neo4j for that event's co-occurrence graph.
        """
        relationships = []

        # All items in this list share the same MISP event (single-event contract above).
        # Capture the event id once and stamp it on every constructed relationship so the
        # edge carries provenance back to the originating MISP event. Empty/missing →
        # the merger skips the array append.
        _evt_id = ""
        for _i in items:
            _eid = _i.get("misp_event_id")
            if _eid:
                _evt_id = str(_eid)
                break

        # Group items by type for cross-referencing
        actors = [i for i in items if i.get("type") == "actor"]
        techniques = [i for i in items if i.get("type") == "technique"]
        malware_items = [i for i in items if i.get("type") == "malware"]
        indicators = [i for i in items if i.get("indicator_type") or i.get("type") == "indicator"]

        # Type-based sampling caps to prevent O(n²) blowup on large events.
        # Each cross-product is capped independently; smaller entity types (actors,
        # techniques, malware) keep all items, only indicators are sampled.
        _MAX_ACTORS = 500
        _MAX_TECHNIQUES = 500
        _MAX_MALWARE = 500
        _MAX_INDICATORS = 2000
        _MAX_VULNS = 1000

        sampled = False
        if len(actors) > _MAX_ACTORS:
            logger.info("Sampling actors: %s → %s", len(actors), _MAX_ACTORS)
            actors = actors[:_MAX_ACTORS]
            sampled = True
        if len(techniques) > _MAX_TECHNIQUES:
            logger.info("Sampling techniques: %s → %s", len(techniques), _MAX_TECHNIQUES)
            techniques = techniques[:_MAX_TECHNIQUES]
            sampled = True
        if len(malware_items) > _MAX_MALWARE:
            logger.info("Sampling malware: %s → %s", len(malware_items), _MAX_MALWARE)
            malware_items = malware_items[:_MAX_MALWARE]
            sampled = True
        if len(indicators) > _MAX_INDICATORS:
            logger.info("Sampling indicators: %s → %s", len(indicators), _MAX_INDICATORS)
            indicators = indicators[:_MAX_INDICATORS]
            sampled = True
        if sampled:
            logger.info("Type-based sampling applied to keep cross-products manageable")

        # Collect vulnerabilities for cross-product estimation
        vulnerabilities = [i for i in items if resolve_vulnerability_cve_id(i) is not None]
        if len(vulnerabilities) > _MAX_VULNS:
            logger.info("Sampling vulnerabilities: %s → %s", len(vulnerabilities), _MAX_VULNS)
            vulnerabilities = vulnerabilities[:_MAX_VULNS]

        # Dynamic sampling: estimate cross-product size and reduce caps if needed
        _SAFE_REL_LIMIT = 50000
        estimated_rels = (
            len(actors) * len(techniques)
            + len(malware_items) * len(actors)
            + len(indicators) * len(malware_items)
            + len(indicators) * len(vulnerabilities)
        )
        if estimated_rels > _SAFE_REL_LIMIT and estimated_rels > 0:
            # Use sqrt(factor) because relationships are pairwise products:
            # reducing both sides by sqrt(f) reduces each product by f.
            import math

            factor = math.sqrt(_SAFE_REL_LIMIT / estimated_rels)
            _MAX_INDICATORS = max(100, int(len(indicators) * factor))
            _MAX_MALWARE = max(50, int(len(malware_items) * factor))
            _MAX_VULNS = max(50, int(len(vulnerabilities) * factor))
            _MAX_ACTORS = max(50, int(len(actors) * factor))
            _MAX_TECHNIQUES = max(50, int(len(techniques) * factor))
            # Re-sample with reduced caps
            indicators = indicators[:_MAX_INDICATORS]
            malware_items = malware_items[:_MAX_MALWARE]
            vulnerabilities = vulnerabilities[:_MAX_VULNS]
            actors = actors[:_MAX_ACTORS]
            techniques = techniques[:_MAX_TECHNIQUES]
            new_estimated = (
                len(actors) * len(techniques)
                + len(malware_items) * len(actors)
                + len(indicators) * len(malware_items)
                + len(indicators) * len(vulnerabilities)
            )
            logger.warning(
                "CROSS-ITEM: Estimated %s relationships exceeds %s limit — "
                "dynamically reduced caps (indicators=%s, malware=%s, vulns=%s, actors=%s, techniques=%s) → ~%s rels",
                estimated_rels,
                _SAFE_REL_LIMIT,
                len(indicators),
                len(malware_items),
                len(vulnerabilities),
                len(actors),
                len(techniques),
                new_estimated,
            )
            try:
                from metrics_server import PIPELINE_ERRORS

                PIPELINE_ERRORS.labels(task="cross_item_rels", error_type="dynamic_sampling_triggered", source="").inc()
            except Exception:
                logger.debug("Metrics recording failed", exc_info=True)

        # Build actor -> technique relationships (EMPLOYS_TECHNIQUE).
        # Attribution semantics: "actor uses this TTP". Split from a
        # previously-generic USES in 2026-04 to disambiguate from
        # IMPLEMENTS_TECHNIQUE (Malware/Tool capability).
        for actor in actors:
            for technique in techniques:
                relationships.append(
                    {
                        "rel_type": "EMPLOYS_TECHNIQUE",
                        "from_type": "ThreatActor",
                        "from_key": {"name": actor["name"]},
                        "to_type": "Technique",
                        "to_key": {"mitre_id": technique["mitre_id"]},
                        "confidence": 0.5,
                        "misp_event_id": _evt_id,
                    }
                )

        # Build malware -> actor relationships (ATTRIBUTED_TO)
        # When an event has both malware and actors, attribute malware to actors
        for malware in malware_items:
            for actor in actors:
                relationships.append(
                    {
                        "rel_type": "ATTRIBUTED_TO",
                        "from_type": "Malware",
                        "from_key": {"name": malware["name"]},
                        "to_type": "ThreatActor",
                        "to_key": {"name": actor["name"]},
                        "confidence": 0.5,
                        "misp_event_id": _evt_id,
                    }
                )

        # Build indicator -> malware relationships (INDICATES)
        # Indicators in the same MISP event as a malware entry indicate that malware.
        for indicator in indicators:
            for malware in malware_items:
                indicator_type = indicator.get("indicator_type", "unknown")
                indicator_value = indicator.get("value")
                if indicator_value:
                    relationships.append(
                        {
                            "rel_type": "INDICATES",
                            "from_type": "Indicator",
                            "from_key": {
                                "value": indicator_value,
                                "indicator_type": indicator_type,
                            },
                            "to_type": "Malware",
                            "to_key": {"name": malware["name"]},
                            "confidence": 0.5,
                            "misp_event_id": _evt_id,
                        }
                    )

        # Build indicator -> vulnerability/CVE relationships (EXPLOITS)
        # Indicators in the same MISP event as a CVE are likely exploiting it.
        for indicator in indicators:
            for vuln in vulnerabilities:
                indicator_value = indicator.get("value")
                cve_id = resolve_vulnerability_cve_id(vuln)
                if indicator_value and cve_id:
                    relationships.append(
                        {
                            "rel_type": "EXPLOITS",
                            "from_type": "Indicator",
                            "from_key": {
                                "value": indicator_value,
                                "indicator_type": indicator.get("indicator_type", "unknown"),
                            },
                            "to_type": "Vulnerability",
                            "to_key": {"cve_id": cve_id},
                            "confidence": 0.5,
                            "misp_event_id": _evt_id,
                        }
                    )

        # Build sector relationships from zone tags. Canonical edges:
        #   Indicator     → Sector  via TARGETS
        #   Vulnerability → Sector  via AFFECTS  (PR #33 round 12)
        for item in items:
            zones = item.get("zone", [])
            if isinstance(zones, str):
                zones = [zones]

            # Map zones to sector names
            for zone in zones:
                if zone and zone != "global":
                    sector_name = zone.lower()
                    item_type = item.get("type", "")

                    # Only MISP vulnerability rows become :Vulnerability AFFECTS (not arbitrary cve_id fields).
                    if item_type == "vulnerability":
                        cve_id = resolve_vulnerability_cve_id(item)
                        if cve_id:
                            relationships.append(
                                {
                                    "rel_type": "AFFECTS",
                                    "from_type": "Vulnerability",
                                    "from_key": {"cve_id": cve_id},
                                    "to_type": "Sector",
                                    "to_key": {"name": sector_name},
                                    "confidence": 0.5,
                                    "misp_event_id": _evt_id,
                                }
                            )
                    elif item.get("indicator_type") or item_type == "indicator":
                        # Indicator → Sector — canonical TARGETS.
                        value = item.get("value")
                        indicator_type = item.get("indicator_type", "unknown")
                        if value:
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
                                    "confidence": 0.5,
                                    "misp_event_id": _evt_id,
                                }
                            )

        return relationships

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
        # OTX pulse, hostile CyberCure indicator, malformed NVD item)
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
            severity = "UNKNOWN"
            cvss_score = None  # None = unscored; 0.0 is a valid CVSS score

            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("severity:"):
                    severity = tag_name.replace("severity:", "").upper()
                elif tag_name == "cvss:critical":
                    cvss_score = 9.0
                    severity = "CRITICAL"
                elif tag_name == "cvss:high":
                    cvss_score = 7.5
                    severity = "HIGH"
                elif tag_name == "cvss:medium":
                    cvss_score = 5.5
                    severity = "MEDIUM"
                elif tag_name == "cvss:low":
                    cvss_score = 3.0
                    severity = "LOW"

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
                    logger.warning(f"Failed to parse NVD_META for {cve_id}, falling back to tag-based data")

            # Prefer the precise values stored in NVD_META over tag-derived approximations
            if nvd_meta:
                description = nvd_meta.get("description", raw_comment)
                if nvd_meta.get("attack_vector"):
                    attack_vector = nvd_meta["attack_vector"]
                else:
                    attack_vector = "UNKNOWN"
                # Exact CVSS score from v3.1 or v2 metadata takes priority over tag category
                v31 = nvd_meta.get("cvss_v31_data") or {}
                v2 = nvd_meta.get("cvss_v2_data") or {}
                try:
                    if v31.get("base_score") is not None and v31["base_score"] != "":
                        cvss_score = float(v31["base_score"])
                        severity = (v31.get("base_severity") or severity or "UNKNOWN").upper()
                    elif v2.get("base_score") is not None and v2["base_score"] != "":
                        cvss_score = float(v2["base_score"])
                        severity = (v2.get("base_severity") or severity or "UNKNOWN").upper()
                except (ValueError, TypeError):
                    logger.debug("Non-numeric base_score in NVD_META for %s, using tag-derived score", value)
            else:
                description = raw_comment
                attack_vector = "NETWORK"

            # Vulnerability → Sector — canonical AFFECTS (PR #33 round 12).
            canon_cve = normalize_cve_id_for_graph(cve_id)
            if target_sector and canon_cve:
                relationships.append(
                    {
                        "rel_type": "AFFECTS",
                        "from_type": "Vulnerability",
                        "from_key": {"cve_id": canon_cve},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": confidence,
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
                "published": nvd_meta.get("published", ""),
                "last_modified": nvd_meta.get("last_modified", ""),
                "confidence_score": confidence,
                "severity": severity,
                "cvss_score": cvss_score,
                "attack_vector": attack_vector,
                "misp_event_id": str(event_info.get("id", "")),
                "misp_attribute_id": attr_misp_uuid,
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
            }
            return item, relationships

        # Handle threat actor
        elif attr_type == "threat-actor":
            actor_name = value

            # Parse uses_techniques from MITRE_USES_TECHNIQUES: comment prefix (same as malware/tool)
            raw_comment = attr.get("comment", "") or ""
            uses_techniques = []
            actor_description = raw_comment
            if "MITRE_USES_TECHNIQUES:" in raw_comment:
                try:
                    uses_json = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].strip()
                    if "\n" in uses_json:
                        json_part, actor_description = uses_json.split("\n", 1)
                        actor_description = actor_description.strip()
                    else:
                        json_part = uses_json
                        actor_description = ""
                    parsed = json.loads(json_part)
                    if isinstance(parsed, dict):
                        uses_techniques = parsed.get("t", [])
                    elif isinstance(parsed, list):
                        uses_techniques = parsed
                except (ValueError, IndexError):
                    actor_description = raw_comment

            # Build EMPLOYS_TECHNIQUE relationships to techniques.
            # Attribution edge (who uses the TTP). See 2026-04 refactor note
            # in src/neo4j_client.py create_actor_technique_relationship.
            for technique in techniques:
                relationships.append(
                    {
                        "rel_type": "EMPLOYS_TECHNIQUE",
                        "from_type": "ThreatActor",
                        "from_key": {"name": actor_name},
                        "to_type": "Technique",
                        "to_key": {"mitre_id": technique["mitre_id"]},
                        "confidence": confidence,
                        "technique_name": technique.get("name", ""),
                        "misp_event_id": _evt_id,
                    }
                )

            # PR (S5): source-truthful timestamps when source is on the
            # reliable allowlist (NVD/CISA/MITRE/etc.). Returns (None, None)
            # for unreliable sources so first_seen_at_source stays NULL.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "actor",
                "name": actor_name,
                "aliases": [],
                "description": actor_description,
                "uses_techniques": uses_techniques,
                "zone": zones,
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
                "relationships": relationships,
            }
            return item, relationships

        # Handle malware
        elif attr_type == "malware-type":
            malware_types = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("malware-type:"):
                    malware_types.append(tag_name.replace("malware-type:", ""))

            malware_name = value

            raw_comment = attr.get("comment", "") or ""
            uses_techniques: List[str] = []
            description = raw_comment
            if raw_comment.strip().startswith("MITRE_USES_TECHNIQUES:"):
                try:
                    rest = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].lstrip()
                    nl = rest.find("\n")
                    json_part = rest if nl < 0 else rest[:nl]
                    tail = (rest[nl + 1 :].strip() if nl >= 0 else "") or ""
                    meta = json.loads(json_part)
                    uses_techniques = [str(x) for x in (meta.get("t") or [])]
                    description = tail or description
                except (ValueError, TypeError, json.JSONDecodeError):
                    logger.warning(
                        "Failed to parse MITRE_USES_TECHNIQUES for malware %r; using raw comment as description",
                        malware_name,
                    )

            # Build ATTRIBUTED_TO relationship to threat actor
            if threat_actor:
                relationships.append(
                    {
                        "rel_type": "ATTRIBUTED_TO",
                        "from_type": "Malware",
                        "from_key": {"name": malware_name},
                        "to_type": "ThreatActor",
                        "to_key": {"name": threat_actor},
                        "confidence": confidence,
                        "misp_event_id": _evt_id,
                    }
                )

            # PR (S5): source-truthful timestamps via allowlist-gated helper.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "malware",
                "name": malware_name,
                "malware_types": malware_types if malware_types else ["unknown"],
                "family": value,
                "description": description,
                "zone": zones,  # zone is now an array
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
                "uses_techniques": uses_techniques,
                "relationships": relationships,
            }
            return item, relationships

        # Handle MITRE technique (text format "T1234: Name") — exclude "TA" (tactics, handled below)
        elif attr_type == "text" and len(value) >= 5 and value[0] == "T" and value[1:5].isdigit():
            # MITRE technique format: T followed by 4 digits (T1059, T1059.001)
            parts = value.split(": ", 1)
            mitre_id = parts[0]
            name = parts[1] if len(parts) > 1 else ""

            platforms = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("platform:"):
                    platforms.append(tag_name.replace("platform:", ""))

            # Parse tactic_phases from MITRE_TACTIC_PHASES: comment prefix
            raw_comment = attr.get("comment", "") or ""
            tactic_phases = []
            technique_description = raw_comment
            if "MITRE_TACTIC_PHASES:" in raw_comment:
                try:
                    phases_json = raw_comment.split("MITRE_TACTIC_PHASES:", 1)[1].strip()
                    if "\n" in phases_json:
                        json_part, technique_description = phases_json.split("\n", 1)
                        technique_description = technique_description.strip()
                    else:
                        json_part = phases_json
                        technique_description = ""
                    parsed = json.loads(json_part)
                    if isinstance(parsed, dict):
                        tactic_phases = parsed.get("p", [])
                    elif isinstance(parsed, list):
                        tactic_phases = parsed
                except (ValueError, IndexError):
                    technique_description = raw_comment

            # PR (S5): source-truthful timestamps. Once the MITRE collector
            # commit (8/10) extracts STIX created/modified, these become
            # populated for MITRE entities; until then NULL is the honest
            # answer.
            _fs_at_source, _ls_at_source = extract_source_truthful_timestamps(attr, source_id, event_info=event_info)
            item = {
                "type": "technique",
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
                "relationships": relationships,
            }
            return item, relationships

        # Handle MITRE tactic (text format "TA0001: Name")
        elif attr_type == "text" and len(value) >= 6 and value.startswith("TA") and value[2:6].isdigit():
            # MITRE tactic format: "TA0001: Initial Access" (TA + 4 digits + ": Name")
            parts = value.split(": ", 1)
            mitre_id = parts[0]
            name = parts[1] if len(parts) > 1 else ""

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
                "mitre_id": mitre_id,
                "name": name,
                "shortname": shortname,
                "description": attr.get("comment", ""),
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
            }
            return item, relationships

        # Handle MITRE tool (text format "S0001: Name")
        elif attr_type == "text" and len(value) >= 5 and value[0] == "S" and value[1:5].isdigit():
            # MITRE tool format: "S0154: Cobalt Strike" (S + 4 digits + ": Name")
            parts = value.split(": ", 1)
            mitre_id = parts[0]
            name = parts[1] if len(parts) > 1 else ""

            # Extract uses_techniques from MITRE_USES_TECHNIQUES comment
            # Format: "MITRE_USES_TECHNIQUES:{"t":["T1059","T1071"]}\nDescription..."
            uses_techniques = []
            description = ""
            raw_comment = attr.get("comment", "") or ""
            if "MITRE_USES_TECHNIQUES:" in raw_comment:
                try:
                    uses_json = raw_comment.split("MITRE_USES_TECHNIQUES:", 1)[1].strip()
                    if "\n" in uses_json:
                        json_part, description = uses_json.split("\n", 1)
                        description = description.strip()
                    else:
                        json_part = uses_json
                    parsed = json.loads(json_part)
                    if isinstance(parsed, dict):
                        uses_techniques = parsed.get("t", [])
                    elif isinstance(parsed, list):
                        uses_techniques = parsed
                except (ValueError, IndexError):
                    description = raw_comment
            else:
                description = raw_comment

            tool_types = []
            for tag in tags:
                tag_name = tag.get("name", "")
                if tag_name.startswith("tool-type:"):
                    tool_types.append(tag_name.replace("tool-type:", ""))

            # Build sector-targeting relationship from tag-extracted sector
            if target_sector:
                relationships.append(
                    {
                        "rel_type": "TARGETS",
                        "from_type": "Tool",
                        "from_key": {"mitre_id": mitre_id},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": confidence,
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
            }
            return item, relationships

        # Handle indicators (IP, domain, hash, etc.)
        else:
            indicator_type = self.TYPE_MAPPING.get(attr_type, "unknown")

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
                        "misp_event_id": _evt_id,
                    }
                )

            # Build TARGETS relationship to sector
            if target_sector:
                relationships.append(
                    {
                        "rel_type": "TARGETS",
                        "from_type": "Indicator",
                        "from_key": {"value": value, "indicator_type": indicator_type},
                        "to_type": "Sector",
                        "to_key": {"name": target_sector},
                        "confidence": confidence,
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
                    }
                )

            # Parse OTX_META or TF_META JSON from comment (written by MISPWriter).
            # Mirrors the NVD_META pattern for vulnerability attributes.
            raw_comment = attr.get("comment", "") or ""
            otx_meta: dict = {}
            tf_meta: dict = {}
            if raw_comment.startswith("OTX_META:"):
                try:
                    otx_meta = json.loads(raw_comment[len("OTX_META:") :])
                except ValueError:
                    logger.debug("Failed to parse OTX_META for %s %s", indicator_type, value[:30])
            elif raw_comment.startswith("TF_META:"):
                try:
                    tf_meta = json.loads(raw_comment[len("TF_META:") :])
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
                "relationships": relationships,
            }

            # Enrich indicator with OTX pulse metadata
            if otx_meta:
                item["attack_ids"] = otx_meta.get("attack_ids", [])
                item["targeted_countries"] = otx_meta.get("targeted_countries", [])
                item["pulse_tags"] = otx_meta.get("pulse_tags", [])
                item["pulse_references"] = otx_meta.get("pulse_references", [])
                item["pulse_author"] = otx_meta.get("pulse_author", "")
                item["pulse_tlp"] = otx_meta.get("pulse_tlp", "")
                item["otx_industries"] = otx_meta.get("otx_industries", [])
                item["description"] = otx_meta.get("description", "")

            # Enrich indicator with ThreatFox metadata
            if tf_meta:
                item["malware_malpedia"] = tf_meta.get("malware_malpedia", "")
                item["reference"] = tf_meta.get("reference", "")
                item["tf_tags"] = tf_meta.get("tags", [])
                item["last_seen"] = tf_meta.get("last_seen", "")
                item["threat_type_desc"] = tf_meta.get("threat_type_desc", "")
                item["malware_family"] = tf_meta.get("malware_family", "")
                item["reporter"] = tf_meta.get("reporter", "")

            return item, relationships

    def _sync_to_neo4j_chunk(self, items: List[Dict]) -> Tuple[int, int]:
        """
        Merge one chunk of parsed items to Neo4j (partition by type, same order as before).

        Relationship dicts are *not* aggregated here — the caller already collected them
        during parse; we optionally pop ``relationships`` from items after each chunk in
        ``sync_to_neo4j`` to reduce peak RAM.
        """
        success = 0
        errors = 0

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
                    self._sync_single_item(item)
                    success += 1
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
                        self.neo4j.merge_cve(vuln, source_id=src)
                        success += 1
                        self.stats["vulnerabilities_synced"] += 1
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
                    if self.neo4j.merge_malware(malware, source_id=source_id):
                        self.stats["malware_synced"] += 1
                        success += 1
                    else:
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
                    if self.neo4j.merge_actor(actor, source_id=source_id):
                        self.stats["actors_synced"] += 1
                        success += 1
                    else:
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
        total_chunks = (len(relationships) + chunk_sz - 1) // chunk_sz
        for idx, start in enumerate(range(0, len(relationships), chunk_sz)):
            chunk = relationships[start : start + chunk_sz]
            created_count += self.neo4j.create_misp_relationships_batch(chunk, source_id=source_id)
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

        return created_count

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
            logger.warning(f"Skipping event {event_id} - failed to fetch details")
            return 0, 0, 0

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

        # For large events: stream attributes in pages to avoid OOM
        if attr_count > self._ATTR_PAGE_SIZE:
            logger.info(
                "Event %s has %s attributes — streaming in pages of %s to manage memory",
                event_id,
                attr_count,
                self._ATTR_PAGE_SIZE,
            )
            return self._process_large_event_paged(event_id, full_event, attributes)

        # Normal path: process all attributes in memory (small/medium events)
        return self._process_event_attributes(event_id, full_event, attributes)

    def _process_event_attributes(self, event_id: str, full_event: Dict, attributes: List) -> Tuple[int, int, int]:
        """Process a list of attributes: parse → dedup → sync → relationships."""
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
        cross_rels = self._build_cross_item_relationships(unique_event_items)

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
            # Cross-item (co-occurrence) rels use distinct source_id so calibration
            # job can find and rescore them by MISP event size.
            rels_created = self._create_relationships(cross_rels, "misp_cooccurrence")
            self.stats["relationships_created"] += rels_created

        return len(event_items), len(cross_rels), ev_errors

    def _process_large_event_paged(self, event_id: str, full_event: Dict, all_attributes: List) -> Tuple[int, int, int]:
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
        _REL_KEYS = ("type", "name", "mitre_id", "tag", "indicator_type", "value", "malware_family", "zone", "cve_id")
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

        # Build cross-item relationships across ALL pages (now that all nodes are in Neo4j).
        # Uses the lightweight accumulator, not the full parsed items.
        # Type-based sampling inside _build_cross_item_relationships handles O(n²) risk.
        cross_rels = []
        if _rel_items:
            cross_rels = self._build_cross_item_relationships(_rel_items)
            if cross_rels:
                logger.info(
                    "Event %s: building %s cross-item relationships from all pages...", event_id, len(cross_rels)
                )
                rels_created = self._create_relationships(cross_rels, "misp_cooccurrence")
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

            if not events:
                logger.info("No events to sync")
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
            # Total input size — used by the coverage-gap alert to catch
            # silently-skipped events (the exact failure mode of the
            # 2026-04-14 NVD regression).
            events_index_total = len(sorted_events)

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
                            # in failed_events once and only once. Don't count here.
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
            logger.info(f"Errors: {total_errors}")
            logger.info(
                f"Circuit Breaker States: MISP={self.misp_circuit.state.name}, Neo4j={self.neo4j_circuit.state.name}"
            )

            # Record success
            if total_errors == 0:
                record_collection_success("misp_to_neo4j")

            if total_errors != 0:
                self._last_sync_failure_reason = (
                    f"sync_to_neo4j reported {total_errors} merge/load error(s); see logs above"
                )

            return total_errors == 0

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
