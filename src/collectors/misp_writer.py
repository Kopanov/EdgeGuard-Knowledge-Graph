#!/usr/bin/env python3
"""
EdgeGuard - MISP Writer Module
Pushes indicators to MISP as the single point of truth
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests
import urllib3

import source_registry  # noqa: E402  — single source of truth for source→MISP-tag mapping (chip 5a)
from collectors.collector_utils import TransientServerError, retry_with_backoff
from config import (
    DEFAULT_SECTOR,
    MISP_API_KEY,
    MISP_CROSS_EVENT_DEDUP,
    MISP_PREFETCH_EXISTING_ATTRS,
    MISP_URL,
    SSL_VERIFY,
    apply_misp_http_host_header,
)

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _apply_source_truthful_timestamps(attribute: Dict[str, Any], item: Dict[str, Any]) -> None:
    """Forward the collector's ``first_seen`` / ``last_seen`` (or
    ``last_modified``) into the MISP attribute dict via the MISP
    2.4.120+ native fields.

    PR (S5) (bugbot HIGH): consolidated here to fix the
    bug where only 2 of 7 ``create_*_attribute`` methods honored the
    passthrough. Previously indicators (``87d3529``) and vulnerabilities
    (``ac25b07``) got the fix; malware, threat actors, techniques,
    tactics, and tools silently dropped their source-truthful
    timestamps at the MISPWriter handoff. MITRE is the primary
    affected source — every MITRE ATT&CK SDO carries a canonical
    ``created`` timestamp, which the collector mapped into
    ``item["first_seen"]`` but which was then discarded here.

    PR (S5) (post-merge audit — converged finding from
    bugbot MED / Cross-Checker F5 / Red Team #6 / Bug Hunter #1/#5 /
    Logic Tracker #6): the previous ``isinstance(str)`` gate silently
    dropped THREE real-world scenarios:
    1. VirusTotal's ``first_submission_date`` is an **int** epoch —
       collector passes it straight through, `isinstance(str)` False,
       dropped → entire VT source-truthful path broken.
    2. ``datetime`` objects (from e.g. ``stix2.utils.STIXdatetime`` or
       any future collector using structured parsing) — dropped.
    3. Date-only strings like CISA's ``"2024-03-15"`` — passed the
       string gate but Neo4j's Cypher ``datetime()`` then rejected
       them, crashing the UNWIND batch. The ``coerce_iso`` helper was
       hardened to normalize these to ``"2024-03-15T00:00:00+00:00"``
       on the READ path, but the WRITE path (here) bypassed it.

    Fix: use the canonical ``coerce_iso`` helper from
    ``source_truthful_timestamps``. It handles None, empty string,
    Unix int/float epoch, datetime objects, date-only strings
    (normalized to ISO with UTC midnight), and full ISO — returning
    ``None`` for unparseable / empty inputs. If the result is a
    non-empty string, we set it on the MISP attribute; otherwise the
    field is intentionally omitted (PyMISP rejects empty strings).
    """
    # Lazy import to avoid a potential circular dependency (the
    # source_truthful_timestamps module lives at src/ root; this
    # collector module is under src/collectors/).
    from source_truthful_timestamps import coerce_iso

    first_seen = coerce_iso(item.get("first_seen"))
    # last_modified (NVD / STIX) is accepted as an alias for last_seen.
    last_seen = coerce_iso(item.get("last_seen")) or coerce_iso(item.get("last_modified"))
    if first_seen:
        attribute["first_seen"] = first_seen
    if last_seen:
        attribute["last_seen"] = last_seen


def _resolve_vulnerability_cve_id_for_misp(item: Dict) -> Optional[str]:
    """
    Same rules as ``neo4j_client.resolve_vulnerability_cve_id`` (keep in sync).

    MISP vulnerability attributes often only have ``value`` (CVE id), not ``cve_id``.
    """
    cve_id = item.get("cve_id")
    if cve_id is not None and str(cve_id).strip():
        return str(cve_id).strip().upper()
    if item.get("type") == "vulnerability":
        val = item.get("value")
        if val is not None and str(val).strip():
            return str(val).strip().upper()
    return None


class MispTransientError(TransientServerError):
    """Raised manually for HTTP 5xx from MISP so @retry_with_backoff can catch
    it selectively. Inheriting from ``collector_utils.TransientServerError``
    (a subclass of ``requests.exceptions.HTTPError``) means the shared retry
    decorator in ``collector_utils.py`` retries this class by name, without
    having to widen its catch clause to all ``HTTPError`` values. 4xx errors
    and any other ``HTTPError`` raised by ``response.raise_for_status()``
    stay permanent."""


# Let @retry_with_backoff on _get_or_create_event / _push_batch retry these (must re-raise, not swallow).
# MispTransientError is a TransientServerError subclass, which is also in the
# decorator's catch tuple in collector_utils.retry_with_backoff.
_TRANSIENT_HTTP_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ReadTimeout,
    requests.exceptions.ChunkedEncodingError,
    MispTransientError,
)


def _event_id_and_info_from_restsearch_row(row: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extract (id, info) from one MISP restSearch row (wrapped or flat)."""
    if not isinstance(row, dict):
        return None, None
    ev = row.get("Event")
    if isinstance(ev, dict):
        eid, info = ev.get("id"), ev.get("info")
    else:
        eid, info = row.get("id"), row.get("info")
    if eid is not None:
        eid = str(eid)
    if info is not None:
        info = str(info)
    return eid, info


def _event_id_exact_from_restsearch_rows(rows: List[Any], event_name: str) -> Optional[str]:
    """
    MISP ``restSearch`` ``info`` filter is often a **substring** match. Parallel tier-1 collectors
    share the ``EdgeGuard-GLOBAL-`` prefix; taking ``response[0]`` can attach the wrong feed to
    another source's event. Only accept an **exact** ``Event.info`` match.
    """
    for row in rows:
        eid, info = _event_id_and_info_from_restsearch_row(row)
        if eid and info == event_name:
            return eid
    return None


@contextmanager
def _cross_process_event_creation_lock():
    """
    Serialize MISP event creation across processes (e.g. Airflow LocalExecutor workers).

    Without this, two collectors can both see "no event" and create duplicates — or worse, rely on
    ambiguous restSearch hits. Uses ``fcntl`` (Unix). On platforms without ``fcntl``, the context is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    path = os.environ.get(
        "EDGEGUARD_MISP_EVENT_LOCK_PATH",
        "/tmp/edgeguard_misp_get_or_create_event.lock",
    )
    lock_f = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_f.close()


def sanitize_value(value: str, max_length: int = 255) -> str:
    """Sanitize a threat-intelligence value for safe storage in MISP.

    Removes control characters and null bytes, enforces a maximum length,
    and strips surrounding whitespace.

    HTML-escaping is intentionally NOT applied: it would corrupt indicator
    values that legitimately contain ``&``, ``<``, ``>``, or ``"``
    (e.g. URLs with query strings, file paths, regex patterns).

    Args:
        value:      Input string to sanitize.
        max_length: Maximum allowed byte-length (default 255).

    Returns:
        Sanitized string safe for use in MISP attributes.
    """
    if not value or not isinstance(value, str):
        return ""
    # Remove null bytes and ASCII control characters (0x00–0x1F except tab/newline)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
    value = value.strip()
    if len(value) > max_length:
        value = value[: max_length - 3] + "..."
    return value


def rate_limited(max_per_second: float = 2.0):
    """Rate limiting decorator to avoid overwhelming APIs.

    Args:
        max_per_second: Maximum calls allowed per second
    """
    min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.5
    last_call_time = [0.0]  # Use list for mutable closure

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_call_time[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            result = func(*args, **kwargs)
            last_call_time[0] = time.time()
            return result

        return wrapper

    return decorator


class MISPWriter:
    """
    Writes indicators to MISP as the single point of truth.

    Features:
    - Batch uploads for efficiency
    - Automatic sector-based event organization
    - Deduplication within batches
    - Support for all EdgeGuard indicator types
    """

    # Timeout constants for MISP API calls (defined before use)
    CONNECT_TIMEOUT = 30  # seconds
    READ_TIMEOUT = 300  # seconds — MISP needs time for large events (95K+ attributes)

    # Mapping from EdgeGuard indicator types to MISP attribute types
    TYPE_MAPPING = {
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "ip": "ip-dst",
        "domain": "domain",
        "hostname": "hostname",
        "url": "url",
        "uri": "url",
        "hash": "sha256",  # Default to sha256, can be overridden
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
        "email": "email-src",
        "cve": "vulnerability",
        "filename": "filename",
        "filepath": "filename",
        "mutex": "mutex",
        "registry": "regkey",
        "yara": "yara",
        "sigma": "sigma",
        "snort": "snort",
        "bitcoin": "btc",
        "unknown": "text",
    }

    # Source to MISP tag mapping. Single-source-of-truth derivation from
    # src/source_registry.py (chip 5a) — adding a new source is now a
    # one-line edit there. The derived map covers every alias (so the
    # writer resolves a lookup by either canonical id OR legacy short
    # name to the same MISP tag), which extends the historical key set
    # but does not change behavior for any existing input.
    SOURCE_TAGS = source_registry.source_to_misp_tag_map()

    def __init__(
        self,
        url: str = None,
        api_key: str = None,
        verify_ssl: bool = None,
        liveness_callback: Optional[Callable[[], None]] = None,
    ):
        """
        Initialize MISP writer.

        Args:
            url: MISP instance URL (defaults to config.MISP_URL)
            api_key: MISP API key (defaults to config.MISP_API_KEY)
            verify_ssl: Whether to verify SSL certificates (defaults to config.SSL_VERIFY)
            liveness_callback: PR-F6 (Issue #65) — optional zero-arg callable
                invoked between MISP push batches. Should raise
                ``AbortedByDagFailureException`` (or any exception) to
                signal the collector to abort cleanly. Used for the
                parent-DAG-liveness orphan-process safeguard. ``None``
                (default) preserves legacy behavior — push_items runs
                to completion regardless of parent-DAG state.
        """
        self.url = url or MISP_URL
        self.api_key = api_key or MISP_API_KEY

        # Use config value if not explicitly specified
        if verify_ssl is None:
            self.verify_ssl = SSL_VERIFY
        else:
            self.verify_ssl = verify_ssl

        # Warn if SSL is disabled
        if not self.verify_ssl:
            logger.warning("SSL verification is DISABLED. This is OK for local dev only!")
            logger.warning("For production, set EDGEGUARD_SSL_VERIFY=true or set SSL_VERIFY=True")
        else:
            logger.info("SSL verification is ENABLED")

        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}
        )
        apply_misp_http_host_header(self.session)
        self.stats = {
            "events_created": 0,
            "attributes_added": 0,
            "batches_sent": 0,
            "errors": 0,
            "attrs_skipped_existing": 0,
        }
        # PR-F6 (Issue #65): per-batch parent-DAG liveness callback.
        # ``None`` = no check (legacy / incremental DAGs); a callable
        # = check before each batch. See src/parent_dag_liveness.py.
        self.liveness_callback = liveness_callback

    def _restsearch_events_for_name(self, event_name: str) -> List[Any]:
        """Call ``/events/restSearch``; returns the ``response`` list (may need exact-info filtering)."""
        response = self.session.post(
            f"{self.url}/events/restSearch",
            # ``limit`` > 1: substring ``info`` can return multiple EdgeGuard-* rows; we pick exact match only.
            json={"returnFormat": "json", "info": event_name, "limit": 50},
            verify=self.verify_ssl,
            timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
        )
        if response.status_code != 200:
            logger.warning(
                "MISP restSearch failed for event lookup: HTTP %s — %s",
                response.status_code,
                (response.text or "")[:500],
            )
            return []
        data = response.json()
        return data.get("response") or []

    def _get_existing_source_attribute_keys(self, source_tag: str) -> set:
        """Build a set of (MISP attribute type, value) already pushed under
        ANY MISP event tagged with ``source_tag`` — across all events,
        not just one.

        PR-F7 (Issue #61 quick-fix): the per-event prefetch
        (:meth:`_get_existing_attribute_keys`) misses duplicates across
        different MISP events for the same source. Bravo's 2026-04-19
        incident measured 72,479 CVEs duplicated between event 19
        (``EdgeGuard-nvd-2026-04-19``) and event 20
        (``EdgeGuard-nvd-2026-04-20``) — both runs pushed the same NVD
        baseline window on different UTC days, creating two events with
        the same content.

        Uses MISP's ``attributes/restSearch`` ``tags`` filter — one
        query per source per :meth:`push_items` call (cached by the
        caller). Paginated identically to the per-event variant. Returns
        an empty set when:

          - ``EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`` is disabled
            (master switch — also gates the per-event prefetch)
          - ``EDGEGUARD_MISP_CROSS_EVENT_DEDUP`` is disabled (this
            feature's opt-out)
          - ``source_tag`` is empty (defensive — caller couldn't resolve)
          - The probe fails (any HTTP error / parse error) — degrades
            cleanly to per-event-only dedup; no harm

        Cost: ~30-40 seconds for ~92K NVD attributes paginated 5000/page
        (~19 requests). Amortized over the entire baseline run (one call
        per source per push_items invocation, not per batch).

        See also Issue #61 — the architectural fix is event partitioning
        by attribute date, not push date. This helper is the cheap
        quick-fix until #61 lands.
        """
        if not MISP_PREFETCH_EXISTING_ATTRS:
            return set()
        if not MISP_CROSS_EVENT_DEDUP:
            return set()
        tag = (source_tag or "").strip()
        if not tag:
            return set()
        keys: set = set()
        page = 1
        page_limit = 5000
        max_pages = 200
        while page <= max_pages:
            try:
                response = self.session.post(
                    f"{self.url}/attributes/restSearch",
                    json={
                        "returnFormat": "json",
                        "tags": [tag],
                        "page": page,
                        "limit": page_limit,
                    },
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2),
                )
            except _TRANSIENT_HTTP_ERRORS as ex:
                # PR-F7 Bugbot round-3 / multi-agent audit (Logic Tracker HIGH,
                # Devil's Advocate HIGH, Bug Hunter HIGH): previously this
                # branch re-raised transient errors. That was WRONG —
                # ``push_items`` has no retry decorator around this call,
                # so the exception propagated → collector ``except
                # Exception`` → catastrophic classification → [CRITICAL]
                # HARD-FAILED alert + entire NVD batch (~92K attrs) lost.
                # The docstring promises "degrades cleanly to per-event
                # dedup; no harm" — deliver on that.
                #
                # PR-F7 Bugbot round-4 (Medium on commit 90a0ab5):
                # previous fix was ``return set()`` — which discarded
                # every page already collected. On NVD (~19 pages) a
                # transient blip on page 15 threw away ~70K valid keys
                # → all cross-event dedup lost for the run, most likely
                # to happen exactly when MISP is under load (the
                # scenario this PR targets). Fix: ``break`` preserves
                # the partial keyset (strictly better than empty). The
                # sibling ``_get_existing_attribute_keys`` already uses
                # the same pattern.
                logger.warning(
                    "MISP cross-event prefetch transient error for tag=%s page=%s after %s keys: %s — "
                    "preserving partial keyset, degrading to per-event for remainder "
                    "(PR-F7: fail-OPEN, no collector abort)",
                    tag,
                    page,
                    len(keys),
                    ex,
                )
                break
            except Exception as ex:
                logger.warning(
                    "MISP cross-event prefetch failed for tag=%s page=%s after %s keys: %s — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    tag,
                    page,
                    len(keys),
                    ex,
                )
                break
            if response.status_code != 200:
                # PR-F7 Bugbot round-4: preserve partial keyset (same
                # rationale as the transient-error break above).
                logger.warning(
                    "MISP cross-event prefetch HTTP %s for tag=%s page=%s after %s keys — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    response.status_code,
                    tag,
                    page,
                    len(keys),
                )
                break
            try:
                data = response.json()
            except ValueError:
                logger.warning(
                    "MISP cross-event prefetch non-JSON response for tag=%s page=%s after %s keys — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    tag,
                    page,
                    len(keys),
                )
                break
            resp = data.get("response", data)
            attrs: List = []
            if isinstance(resp, list):
                attrs = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    attrs = raw
                elif isinstance(raw, dict):
                    attrs = [raw]
            for a in attrs:
                if not isinstance(a, dict):
                    continue
                t = a.get("type")
                v = a.get("value")
                if t is not None and v is not None and str(v).strip():
                    keys.add((str(t), str(v)))
            if len(attrs) < page_limit:
                break
            page += 1
        if keys:
            logger.info(
                "MISP cross-event prefetch tag=%s: %s existing keys (will skip duplicates at push time — PR-F7)",
                tag,
                len(keys),
            )
        return keys

    def _get_existing_attribute_keys(self, event_id: str) -> set:
        """
        Build a set of (MISP attribute type, value) already on the event.

        Used to avoid re-posting the same indicator when collectors re-run or incremental
        windows overlap. MISP does not dedupe across different events (e.g. different days).
        """
        if not MISP_PREFETCH_EXISTING_ATTRS:
            return set()
        eid = sanitize_value(str(event_id), max_length=20)
        if not eid:
            return set()
        keys: set = set()
        page = 1
        page_limit = 5000
        max_pages = 200
        while page <= max_pages:
            try:
                response = self.session.post(
                    f"{self.url}/attributes/restSearch",
                    json={
                        "returnFormat": "json",
                        "eventid": eid,
                        "page": page,
                        "limit": page_limit,
                    },
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2),
                )
            except _TRANSIENT_HTTP_ERRORS:
                raise
            except Exception as ex:
                logger.warning("MISP attributes/restSearch failed for event %s page %s: %s", eid, page, ex)
                break
            if response.status_code != 200:
                logger.warning(
                    "MISP attributes/restSearch HTTP %s for event %s — skipping prefetch",
                    response.status_code,
                    eid,
                )
                break
            try:
                data = response.json()
            except ValueError:
                break
            resp = data.get("response", data)
            attrs: List = []
            if isinstance(resp, list):
                attrs = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    attrs = raw
                elif isinstance(raw, dict):
                    attrs = [raw]
            for a in attrs:
                if not isinstance(a, dict):
                    continue
                t = a.get("type")
                v = a.get("value")
                if t is not None and v is not None and str(v).strip():
                    keys.add((str(t), str(v)))
            if len(attrs) < page_limit:
                break
            page += 1
        if keys:
            logger.debug("MISP event %s: prefetched %s existing attribute keys", eid, len(keys))
        return keys

    @retry_with_backoff(max_retries=4, base_delay=10.0)
    def _get_or_create_event(self, source: str, date: str = None, **_kwargs) -> Optional[str]:
        """Get or create a MISP event for a source/date combination.

        Event naming: ``EdgeGuard-{source}-{date}``.  Zone classification lives
        on attribute-level tags (``zone:Finance``, ``zone:Healthcare``), not in
        the event name — a single event can contain multi-zone attributes.

        Uses MISP's ``restSearch`` endpoint, then filters to an **exact** ``Event.info`` match.
        Event **creation** is serialized with a file lock so two processes do not
        create duplicate same-day events after a miss.

        Returns:
            Event ID if successful, None otherwise.
        """
        source = sanitize_value(source, max_length=50)

        date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        event_name = f"EdgeGuard-{source}-{date}"

        try:
            rows = self._restsearch_events_for_name(event_name)
            exact = _event_id_exact_from_restsearch_rows(rows, event_name)
            if exact:
                return exact
        except _TRANSIENT_HTTP_ERRORS:
            raise
        except Exception as e:
            logger.warning(f"Event lookup error: {e}")

        event_data = {
            "Event": {
                "info": event_name,
                "distribution": 1,  # This organization only
                "threat_level_id": 3,  # Low
                "analysis": 0,  # Initial
                "date": date,
                "Attribute": [],
                # Event is an organizational container: ``EdgeGuard-{source}-{date}`` groups by
                # source + day.  Zone classification lives on **attributes** (``zone:…`` tags)
                # so multi-zone items are handled correctly.  Single event tag marks data
                # from this platform for consumers (e.g. ResilMesh).
                "Tag": [{"name": "EdgeGuard"}],
            }
        }

        try:
            with _cross_process_event_creation_lock():
                rows2 = self._restsearch_events_for_name(event_name)
                exact2 = _event_id_exact_from_restsearch_rows(rows2, event_name)
                if exact2:
                    return exact2

                response = self.session.post(
                    f"{self.url}/events",
                    json=event_data,
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
                )

                if response.status_code in (200, 201):
                    result = response.json()
                    ev = result.get("Event") or {}
                    event_id = ev.get("id")
                    created_info = ev.get("info")
                    if created_info and str(created_info) != event_name:
                        logger.error(
                            "MISP created event info mismatch: expected %r got %r (id=%s)",
                            event_name,
                            created_info,
                            event_id,
                        )
                    if event_id:
                        self.stats["events_created"] += 1
                        logger.info(f"Created MISP event: {event_name} (ID: {event_id})")
                        return str(event_id)
                    return None
                logger.error(f"Failed to create event: {response.status_code} - {response.text}")
                self.stats["errors"] += 1
                return None

        except _TRANSIENT_HTTP_ERRORS:
            raise
        except Exception as e:
            logger.error(f"Event creation error: {e}")
            self.stats["errors"] += 1
            return None

    def _get_zones_to_tag(self, item: Dict) -> List[str]:
        """
        Determine which zone tags to apply based on the new equal-importance logic.

        Rules:
        - All detected specific zones (healthcare, energy, finance) are equal - tag ALL
        - Global is special:
          * If specific zones + global detected → tag only specific zones (global is implicit)
          * If ONLY global detected → tag global as primary

        Args:
            item: EdgeGuard item dict with 'zone' key (now an array)

        Returns:
            List of zone names to tag
        """
        # Get zones array (zone is now always an array)
        zones = item.get("zone", ["global"])
        if not isinstance(zones, list):
            zones = [zones] if zones else ["global"]

        # Filter logic:
        # - If 'global' in zones AND other zones exist: exclude 'global' (it's implicit)
        # - If ONLY 'global' in zones: keep 'global'
        # - Otherwise: keep all zones
        specific_zones = [z for z in zones if z and z != "global"]

        if specific_zones:
            # We have specific zones - tag them all equally
            return specific_zones
        else:
            # Only global - tag it (or fallback to default)
            global_zones = [z for z in zones if z]
            return global_zones if global_zones else [DEFAULT_SECTOR]

    def map_indicator_type(self, edgeguard_type: str, value: str = None) -> str:
        """
        Map EdgeGuard indicator type to MISP attribute type.

        Args:
            edgeguard_type: EdgeGuard type string
            value: Optional value for additional type detection

        Returns:
            MISP attribute type string
        """
        # Direct mapping
        if edgeguard_type in self.TYPE_MAPPING:
            return self.TYPE_MAPPING[edgeguard_type]

        # Try to detect from value if type is unknown
        if value:
            val_lower = value.lower()

            # IP address detection
            parts = value.split(".")
            if len(parts) == 4:
                try:
                    if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        return "ip-dst"
                except (ValueError, TypeError):
                    pass

            # Hash detection
            if len(value) in [32, 40, 64, 128] and all(c in "0123456789abcdefABCDEF" for c in value):
                if len(value) == 32:
                    return "md5"
                elif len(value) == 40:
                    return "sha1"
                elif len(value) == 64:
                    return "sha256"
                else:
                    return "sha512"

            # CVE detection
            if val_lower.startswith("cve-"):
                return "vulnerability"

            # URL detection
            if val_lower.startswith(("http://", "https://")):
                return "url"

            # Email detection
            if "@" in value and "." in value:
                return "email-src"

            # Domain detection
            if "." in value and not val_lower.isdigit():
                return "domain"

        return "text"

    def create_attribute(self, indicator: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard indicator.

        Args:
            indicator: EdgeGuard indicator dict with keys like:
                      indicator_type, value, zone, tag, sources, etc.

        Returns:
            MISP attribute dict or None
        """
        ind_type = indicator.get("indicator_type", "unknown")
        value = indicator.get("value")

        if not value:
            return None

        # Sanitize the value
        value = sanitize_value(value, max_length=1024)
        if not value:
            return None

        misp_type = self.map_indicator_type(ind_type, value)

        # Build tags for attribute
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(indicator)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = indicator.get("tag", "unknown")
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Add confidence tag
        confidence = indicator.get("confidence_score", 0.5)
        if confidence >= 0.8:
            tags.append("confidence:high")
        elif confidence >= 0.5:
            tags.append("confidence:medium")
        else:
            tags.append("confidence:low")

        # PR (S5) (bugbot HIGH): the first_seen / last_seen
        # passthrough previously inlined here has been consolidated into
        # the ``_apply_source_truthful_timestamps`` helper below
        # (applied uniformly across all 7 create_*_attribute methods).

        # Encode rich metadata as JSON comment for sources with structured data
        # (same pattern as NVD_META for vulnerabilities).
        has_otx_meta = indicator.get("attack_ids") or indicator.get("targeted_countries")
        has_tf_meta = indicator.get("malware_malpedia") or indicator.get("reference") or indicator.get("tags")

        if has_otx_meta:
            otx_meta = {
                "attack_ids": indicator.get("attack_ids", []),
                "targeted_countries": indicator.get("targeted_countries", []),
                "pulse_tags": indicator.get("pulse_tags", []),
                "pulse_references": indicator.get("pulse_references", []),
                "pulse_author": indicator.get("pulse_author", ""),
                "pulse_tlp": indicator.get("pulse_tlp", ""),
                "otx_industries": indicator.get("otx_industries", []),
                "description": indicator.get("description", ""),
                "pulse_name": indicator.get("pulse_name", ""),
            }
            comment = "OTX_META:" + json.dumps(otx_meta, default=str)
            if len(comment) > 4000:
                original_len = len(comment)
                comment = comment[:4000]
                logger.warning(f"Truncated OTX_META comment for {value}: {original_len} -> 4000 chars")
        elif has_tf_meta:
            tf_meta = {
                "malware_malpedia": indicator.get("malware_malpedia", ""),
                "reference": indicator.get("reference", ""),
                "tags": indicator.get("tags", []),
                "last_seen": indicator.get("last_seen", ""),
                "threat_type_desc": indicator.get("threat_type_desc", ""),
                "malware_family": indicator.get("malware_family", ""),
                "reporter": indicator.get("reporter", ""),
            }
            comment = "TF_META:" + json.dumps(tf_meta, default=str)
            if len(comment) > 4000:
                original_len = len(comment)
                comment = comment[:4000]
                logger.warning(f"Truncated TF_META comment for {value}: {original_len} -> 4000 chars")
        else:
            comment = sanitize_value(indicator.get("pulse_name") or indicator.get("description", ""), max_length=255)

        attribute = {
            "type": misp_type,
            "value": value,
            # No max_length truncation when storing JSON — truncation would break JSON parsing.
            "comment": comment
            if (has_otx_meta or has_tf_meta or comment)
            else f"From {sanitize_value(source, max_length=50)}",
            "to_ids": True,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): consolidated via helper so
        # the passthrough lives in ONE place — previously five of the
        # seven create_*_attribute methods silently dropped these fields.
        _apply_source_truthful_timestamps(attribute, indicator)

        return attribute

    def create_vulnerability_attribute(self, vuln: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard vulnerability.

        Args:
            vuln: EdgeGuard vulnerability dict with keys like:
                  cve_id, description, zone, tag, severity, etc.

        Returns:
            MISP attribute dict or None
        """
        cve_id = vuln.get("cve_id")
        if not cve_id:
            return None

        # Sanitize CVE ID
        cve_id = sanitize_value(cve_id, max_length=50)
        if not cve_id:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(vuln)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(vuln.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Add severity tag
        severity = sanitize_value(vuln.get("severity", "UNKNOWN"), max_length=20)
        if severity:
            tags.append(f"severity:{severity.lower()}")

        # Add CVSS score tag if available
        cvss = vuln.get("cvss_score", 0)
        if cvss >= 9.0:
            tags.append("cvss:critical")
        elif cvss >= 7.0:
            tags.append("cvss:high")
        elif cvss >= 4.0:
            tags.append("cvss:medium")
        else:
            tags.append("cvss:low")

        # Add CISA KEV tag if from CISA source or if NVD entry has CISA KEV data
        if source in ["cisa", "cisa_kev"] or vuln.get("cisa_exploit_add"):
            tags.append("CISA-KEV")

            # Add ransomware tag if applicable
            ransomware = vuln.get("known_ransomware_use", "Unknown")
            if ransomware == "Known":
                tags.append("ransomware:known")

        description = sanitize_value(vuln.get("description", ""), max_length=200)
        vendor = sanitize_value(vuln.get("vendor", ""), max_length=100)
        product = sanitize_value(vuln.get("product", ""), max_length=100)

        # For NVD-sourced CVEs, embed the rich metadata as JSON so the MISP→Neo4j
        # pipeline can reconstruct the full CVE/CVSS graph without calling NVD again.
        # The prefix "NVD_META:" acts as a sentinel for the reader.
        nvd_fields = {
            "published": vuln.get("published", ""),
            "last_modified": vuln.get("last_modified", ""),
            "cwe": vuln.get("cwe", []),
            "ref_tags": vuln.get("ref_tags", []),
            "reference_urls": vuln.get("reference_urls", []),
            "cpe_type": vuln.get("cpe_type", []),
            "result_impacts": vuln.get("result_impacts", []),
            "affected_products": vuln.get("affected_products", []),
            "attack_vector": vuln.get("attack_vector", "UNKNOWN"),
            "cvss_v40_data": vuln.get("cvss_v40_data"),
            "cvss_v31_data": vuln.get("cvss_v31_data"),
            "cvss_v30_data": vuln.get("cvss_v30_data"),
            "cvss_v2_data": vuln.get("cvss_v2_data"),
            "description": vuln.get("description", ""),
            "vendor": vendor,
            "product": product,
            # CISA KEV exploitability intelligence
            "cisa_exploit_add": vuln.get("cisa_exploit_add", ""),
            "cisa_action_due": vuln.get("cisa_action_due", ""),
            "cisa_required_action": vuln.get("cisa_required_action", ""),
            "cisa_vulnerability_name": vuln.get("cisa_vulnerability_name", ""),
        }
        has_nvd_meta = any(
            [
                nvd_fields["published"],
                nvd_fields["cwe"],
                nvd_fields["cvss_v40_data"],
                nvd_fields["cvss_v31_data"],
                nvd_fields["cvss_v30_data"],
                nvd_fields["cvss_v2_data"],
            ]
        )

        if has_nvd_meta:
            import json as _json

            comment = "NVD_META:" + _json.dumps(nvd_fields, default=str)
        else:
            comment_parts = []
            if vendor:
                comment_parts.append(f"Vendor: {vendor}")
            if product:
                comment_parts.append(f"Product: {product}")
            if description:
                comment_parts.append(description)
            comment = " | ".join(comment_parts) if comment_parts else f"CVE from {source}"

        attribute = {
            "type": "vulnerability",
            "value": cve_id.upper(),
            # No max_length truncation when storing JSON — truncation would break JSON parsing.
            "comment": comment if has_nvd_meta else sanitize_value(comment, max_length=500),
            "to_ids": False,  # CVEs don't make good IDS indicators
            "Tag": [{"name": tag} for tag in tags],
        }

        _apply_source_truthful_timestamps(attribute, vuln)
        return attribute

    def create_malware_attribute(self, malware: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard malware entry.

        Args:
            malware: EdgeGuard malware dict with keys like:
                     name, malware_types, family, description, etc.

        Returns:
            MISP attribute dict or None
        """
        name = malware.get("name")
        if not name:
            return None

        # Sanitize the name
        name = sanitize_value(name, max_length=255)
        if not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(malware)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(malware.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Add malware type tags
        malware_types = malware.get("malware_types", [])
        for mtype in malware_types:
            mt = sanitize_value(str(mtype), max_length=50).lower()
            if mt:
                tags.append(f"malware-type:{mt}")

        # Add family tag
        family = sanitize_value(malware.get("family", ""), max_length=100)
        if family and family != name:
            tags.append(f"malware-family:{family}")

        # Add MITRE ATT&CK galaxy tag for malware - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:malware="{name}"')

        description = sanitize_value(malware.get("description", ""), max_length=400)
        uses_techniques = malware.get("uses_techniques") or []

        # Preserve malware→technique IDs through MISP (same idea as NVD_META for CVEs).
        # ``run_misp_to_neo4j.parse_attribute`` reads this prefix into ``uses_techniques`` on Malware nodes.
        if uses_techniques:
            import json as _json

            # Cap list length so comment stays within typical MISP field limits.
            meta = {"t": list(uses_techniques)[:400]}
            comment = "MITRE_USES_TECHNIQUES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"Malware from {source}"
            comment = sanitize_value(comment, max_length=500)

        attribute = {
            "type": "malware-type",
            "value": name,
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): MITRE malware SDOs carry the
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, malware)
        return attribute

    def create_actor_attribute(self, actor: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard threat actor entry.

        Args:
            actor: EdgeGuard actor dict with keys like:
                   name, aliases, description, etc.

        Returns:
            MISP attribute dict or None
        """
        name = actor.get("name")
        if not name:
            return None

        # Sanitize the name
        name = sanitize_value(name, max_length=255)
        if not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(actor)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(actor.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Add alias tags
        aliases = actor.get("aliases", [])
        for alias in aliases[:5]:  # Limit to 5 aliases
            alias_s = sanitize_value(str(alias), max_length=100)
            if alias_s:
                tags.append(f"alias:{alias_s}")

        # Add MITRE threat-actor galaxy tag - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:threat-actor="{name}"')

        description = sanitize_value(actor.get("description", ""), max_length=255)
        uses_techniques = actor.get("uses_techniques") or []

        # Preserve actor→technique IDs through MISP (same pattern as malware/tool).
        # ``run_misp_to_neo4j.parse_attribute`` reads this prefix into ``uses_techniques``.
        if uses_techniques:
            import json as _json

            meta = {"t": list(uses_techniques)[:400]}
            comment = "MITRE_USES_TECHNIQUES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"Threat actor from {source}"

        attribute = {
            "type": "threat-actor",
            "value": name,
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): MITRE intrusion-set SDOs carry
        # the canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, actor)
        return attribute

    def create_technique_attribute(self, technique: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard technique entry.

        Args:
            technique: EdgeGuard technique dict with keys like:
                      mitre_id, name, description, platforms, etc.

        Returns:
            MISP attribute dict or None
        """
        mitre_id = technique.get("mitre_id")
        name = technique.get("name")

        if not mitre_id or not name:
            return None

        # Sanitize inputs
        mitre_id = sanitize_value(mitre_id, max_length=20)
        name = sanitize_value(name, max_length=255)

        if not mitre_id or not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(technique)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(technique.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Add platform tags
        platforms = technique.get("platforms", [])
        for platform in platforms[:3]:  # Limit to 3 platforms
            plat = sanitize_value(str(platform), max_length=50).lower()
            if plat:
                tags.append(f"platform:{plat}")

        # Add MITRE ATT&CK galaxy tags - CRITICAL for STIX conversion
        # This enables PyMISP to recognize and convert to attack-pattern
        tags.append(f'misp-galaxy:mitre-attack-pattern="{name} - {mitre_id}"')
        tags.append(f'mitre-attack:technique="{mitre_id}"')

        description = sanitize_value(technique.get("description", ""), max_length=255)
        tactic_phases = technique.get("tactic_phases") or []

        # Preserve technique→tactic phase mapping through MISP.
        # ``run_misp_to_neo4j.parse_attribute`` reads this prefix into ``tactic_phases``.
        if tactic_phases:
            import json as _json

            meta = {"p": list(tactic_phases)[:20]}
            comment = "MITRE_TACTIC_PHASES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"MITRE ATT&CK technique from {source}"

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): attack-pattern SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, technique)
        return attribute

    def create_tactic_attribute(self, tactic: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from a MITRE ATT&CK tactic (x-mitre-tactic).

        Tactics use the same ``text`` pattern as techniques (``TA0001: Name``) so
        MISP→Neo4j parsing can recognize them. Previously ``push_items`` had no
        branch for ``type: tactic``, so tactics were silently skipped.
        """
        mitre_id = tactic.get("mitre_id")
        name = tactic.get("name")
        if not mitre_id or not name:
            return None

        mitre_id = sanitize_value(str(mitre_id), max_length=20)
        name = sanitize_value(str(name), max_length=255)
        shortname = sanitize_value(str(tactic.get("shortname", "")), max_length=50)
        if not mitre_id or not name:
            return None

        tags = []
        for z in self._get_zones_to_tag(tactic):
            tags.append(f"zone:{z.capitalize()}")

        source = sanitize_value(tactic.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        if shortname:
            tags.append(f"mitre-tactic:{shortname.lower()}")

        description = sanitize_value(str(tactic.get("description", "")), max_length=255)

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
            "comment": description if description else "MITRE ATT&CK tactic",
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }
        # PR (S5) (bugbot HIGH): x-mitre-tactic SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, tactic)
        return attribute

    def create_tool_attribute(self, tool: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from a MITRE ATT&CK tool (Cobalt Strike, Mimikatz, etc.).

        Tools are stored as ``text`` attributes with ``S####: Name`` format,
        following the same pattern as techniques and tactics. The
        ``uses_techniques`` list is preserved via ``MITRE_USES_TECHNIQUES:``
        comment prefix for round-trip through MISP→Neo4j.
        """
        mitre_id = tool.get("mitre_id")
        name = tool.get("name")
        if not mitre_id or not name:
            return None

        mitre_id = sanitize_value(str(mitre_id), max_length=20)
        name = sanitize_value(str(name), max_length=255)
        if not mitre_id or not name:
            return None

        tags = []
        for z in self._get_zones_to_tag(tool):
            tags.append(f"zone:{z.capitalize()}")

        source = sanitize_value(tool.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")

        # Tag as tool type for MISP galaxy compatibility
        tags.append(f'misp-galaxy:tool="{name}"')
        for ttype in tool.get("tool_types", []):
            tt = sanitize_value(str(ttype), max_length=50).lower()
            if tt:
                tags.append(f"tool-type:{tt}")

        description = sanitize_value(str(tool.get("description", "")), max_length=400)
        uses_techniques = tool.get("uses_techniques") or []

        if uses_techniques:
            meta = {"t": list(uses_techniques)[:400]}
            comment = "MITRE_USES_TECHNIQUES:" + json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"MITRE ATT&CK tool: {name}"
            comment = sanitize_value(comment, max_length=500)

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }
        # PR (S5) (bugbot HIGH): MITRE tool SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, tool)
        return attribute

    def push_items(self, items: List[Dict], batch_size: int = 500) -> Tuple[int, int]:
        """
        Push a list of items to MISP in batches.

        Args:
            items: List of EdgeGuard items (indicators, vulnerabilities, etc.)
            batch_size: Number of items per batch. Overridden by
                ``EDGEGUARD_MISP_PUSH_BATCH_SIZE`` env var when set — lets ops
                dial the batch size down without a code change if MISP is
                choking on large pushes (e.g. the 22% HTTP 500 failure rate
                observed on the 730-day NVD baseline).

        Returns:
            Tuple of (successful_count, failed_count)
        """
        if not items:
            return 0, 0

        total_items = len(items)

        # Env override wins over caller default so ops can tune without redeploying.
        _env_batch = os.environ.get("EDGEGUARD_MISP_PUSH_BATCH_SIZE")
        if _env_batch:
            try:
                env_val = int(_env_batch)
                if env_val > 0:
                    batch_size = env_val
            except (ValueError, TypeError):
                logger.warning(
                    "Ignoring invalid EDGEGUARD_MISP_PUSH_BATCH_SIZE=%r; using %d",
                    _env_batch,
                    batch_size,
                )

        # Guard against invalid batch_size (0 would crash range())
        batch_size = max(1, batch_size)

        # Group items by (source, date) — zone lives on attribute tags, not event name
        grouped = {}

        for item in items:
            source = item.get("tag", "unknown")
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            key = (source, date)
            if key not in grouped:
                grouped[key] = []

            # Convert item to MISP attribute
            item_type = item.get("type", "")

            if "indicator_type" in item and "value" in item:
                attr = self.create_attribute(item)
            elif item_type == "vulnerability" or _resolve_vulnerability_cve_id_for_misp(item):
                attr = self.create_vulnerability_attribute(item)
            elif item_type == "malware":
                attr = self.create_malware_attribute(item)
            elif item_type == "actor":
                attr = self.create_actor_attribute(item)
            elif item_type == "technique":
                attr = self.create_technique_attribute(item)
            elif item_type == "tactic":
                attr = self.create_tactic_attribute(item)
            elif item_type == "tool":
                attr = self.create_tool_attribute(item)
            else:
                logger.warning(f"Unknown item type: {item_type}")
                continue

            if attr:
                grouped[key].append(attr)

        # Resolve events + prefetch existing (type, value); build work queue (post-filter batch counts).
        total_success = 0
        total_failed = 0
        processed_batches = 0
        start_time = time.time()
        push_queue: List[Tuple[str, List[Dict]]] = []

        # PR-F7 (Issue #61 quick-fix): cache cross-event prefetch per
        # source so a single push_items call doesn't re-fetch the same
        # tag set N times when grouped has multiple (source, date)
        # entries for the same source. The fetch itself can be 30-40s
        # on a 92K-attr NVD source — caching matters.
        cross_event_cache: Dict[str, set] = {}

        for (source, date), attributes in grouped.items():
            # Deduplicate attributes by value
            seen = set()
            unique_attrs = []
            for attr in attributes:
                key = f"{attr['type']}:{attr['value']}"
                if key not in seen:
                    seen.add(key)
                    unique_attrs.append(attr)

            # Get or create event
            event_id = self._get_or_create_event(source, date)
            if not event_id:
                total_failed += len(unique_attrs)
                continue

            # PR-F7: filter in TWO explicit steps so the skip-count
            # attribution for each layer is exact (not an approximation).
            # Bugbot LOW (commit 2d747e6): the previous diagnostic summed
            # ``cross_event_skipped`` over ``attributes`` (the PRE within-
            # batch-dedup list with its own duplicates) so counts could
            # EXCEED ``skipped_ct`` — producing contradictory log lines
            # like "skipping 5 attributes (~8 caught by PR-F7)".
            #
            # Fix: step 1 filters by per-event keys (existing behavior);
            # step 2 filters the remaining list by cross-event keys. Each
            # step's contribution is exactly the difference in lengths,
            # so the per-event + cross-event counts always add up to
            # ``skipped_ct``.
            per_event_keys = self._get_existing_attribute_keys(event_id)
            # PR-F7 Bugbot round-3 / multi-agent audit (Bug Hunter, Maintainer):
            # cache key is the RESOLVED ``source_tag`` — not the raw ``source``
            # string. Two sources can share a tag via the registry's alias
            # map (e.g. ``cisa`` and ``cisa_kev`` both map to
            # ``source:CISA-KEV``). Keying by raw ``source`` would double-fetch
            # the same tag set; keying by resolved tag collapses aliases into
            # one cache entry, which is what the prefetch cost model expects.
            source_tag = self.SOURCE_TAGS.get(source, f"source:{source}")
            if source_tag not in cross_event_cache:
                cross_event_cache[source_tag] = self._get_existing_source_attribute_keys(source_tag)
            cross_event_keys = cross_event_cache[source_tag]

            before_ct = len(unique_attrs)
            # Step 1 — filter by per-event keys (attrs already in THIS event)
            after_per_event = [a for a in unique_attrs if (a.get("type"), a.get("value")) not in per_event_keys]
            per_event_skipped = before_ct - len(after_per_event)
            # Step 2 — filter the remainder by cross-event keys (attrs in
            # ANY OTHER EdgeGuard event for this source). PR-F7's value is
            # exactly this number: duplicates that the per-event prefetch
            # would have missed.
            unique_attrs = [a for a in after_per_event if (a.get("type"), a.get("value")) not in cross_event_keys]
            cross_event_skipped = len(after_per_event) - len(unique_attrs)
            skipped_ct = per_event_skipped + cross_event_skipped
            if skipped_ct:
                self.stats["attrs_skipped_existing"] += skipped_ct
                # Multi-agent audit (Cross-Checker, Logic Tracker): the
                # "(0 cross-event PR-F7 dedup)" log was ambiguous —
                # operators couldn't tell whether the 0 meant "we checked
                # and found none" (feature working) vs "the feature is
                # disabled/failed" (feature not running). Qualify the
                # log line based on WHY cross_event_keys is empty.
                if not MISP_CROSS_EVENT_DEDUP:
                    cross_event_note = "cross-event DISABLED"
                elif not cross_event_keys:
                    # Empty set with feature enabled — could be genuinely
                    # no cross-event dupes OR prefetch failed and logged
                    # WARN above. The WARN log line is the truth source;
                    # here we just mark "unavailable" so the count 0 is
                    # honest rather than implying "feature ran and found
                    # 0 dupes."
                    cross_event_note = "cross-event unavailable/empty"
                else:
                    cross_event_note = "cross-event PR-F7 active"
                logger.info(
                    "MISP event %s: skipping %s attributes already present (%s per-event + %s cross-event; %s)",
                    event_id,
                    skipped_ct,
                    per_event_skipped,
                    cross_event_skipped,
                    cross_event_note,
                )
            if not unique_attrs:
                continue
            push_queue.append((event_id, unique_attrs))

        total_batches = sum((len(attrs) + batch_size - 1) // batch_size for _, attrs in push_queue)

        if not push_queue and total_items > 0:
            logger.warning(
                "[DEDUP] All %d items were already present in MISP — nothing new to push. "
                "This is normal on re-runs. Use --fresh-baseline to force re-collection.",
                total_items,
            )

        # Throttle delay between batches — gives MISP time to free memory
        # when processing large events (e.g. 95K NVD attributes).
        try:
            batch_throttle = float(os.environ.get("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5.0"))
        except (ValueError, TypeError):
            batch_throttle = 5.0

        for event_id, unique_attrs in push_queue:
            # Send attributes in batches
            for i in range(0, len(unique_attrs), batch_size):
                batch = unique_attrs[i : i + batch_size]

                # Throttle between batches (skip only the very first batch of the first event)
                if (i > 0 or processed_batches > 0) and batch_throttle > 0:
                    time.sleep(batch_throttle)

                # PR-F6 (Issue #65): parent-DAG liveness check BEFORE the
                # next push. If the parent dag_run has been marked failed
                # (e.g., a sibling task failed), the callback raises
                # ``AbortedByDagFailureException`` to exit the collector
                # cleanly between batches — no half-written events. The
                # callback is rate-limited internally (default 60s
                # between actual API probes), so calling it every batch
                # is cheap. ``None`` (the default) preserves legacy
                # behavior — push_items runs to completion regardless.
                # Re-raises ANY exception from the callback so callers
                # can distinguish parent-DAG-died from other failures.
                #
                # ``getattr`` (not ``self.``) is deliberate: existing tests
                # construct MISPWriter via ``__new__`` to bypass __init__
                # for test-isolation reasons (see
                # tests/test_incremental_dedup.py). The new
                # ``liveness_callback`` attribute would otherwise be
                # missing on those instances and crash push_items. The
                # defensive ``getattr`` keeps the legacy test pattern
                # working without requiring every test to opt-in.
                liveness_cb = getattr(self, "liveness_callback", None)
                if liveness_cb is not None:
                    liveness_cb()

                # Progress logging
                processed_batches += 1
                elapsed = time.time() - start_time
                progress_pct = (processed_batches / total_batches * 100) if total_batches > 0 else 0

                # Calculate estimated remaining time
                if processed_batches > 0:
                    avg_time_per_batch = elapsed / processed_batches
                    remaining_batches = total_batches - processed_batches
                    eta_seconds = avg_time_per_batch * remaining_batches
                    eta_str = f"~{int(eta_seconds)}s remaining"
                else:
                    eta_str = "calculating..."

                logger.info(
                    f"[PUSH] Pushing batch {processed_batches}/{total_batches} ({progress_pct:.1f}%) - {elapsed:.1f}s elapsed, {eta_str}"
                )

                # After @retry_with_backoff exhausts its attempts on a
                # persistent 5xx, _push_batch re-raises MispTransientError.
                # Without this try/except the exception would crash out of
                # push_items and skip every remaining batch and event in the
                # push queue — strictly worse than the pre-fix behaviour
                # where 5xx returned (0, len(attributes)) and the loop
                # continued. Count the batch as failed and move on so one
                # bad event doesn't destroy a whole NVD push.
                try:
                    success, failed = self._push_batch(event_id, batch)
                except MispTransientError as exc:
                    logger.error(
                        "Batch %s for event %s failed after retries (%s) — counting batch as failed and continuing",
                        processed_batches,
                        event_id,
                        exc,
                    )
                    success, failed = 0, len(batch)
                    self.stats["errors"] += 1
                total_success += success
                total_failed += failed

        # Final summary
        total_elapsed = time.time() - start_time
        if total_success > 0 or total_failed > 0:
            logger.info(
                f"[OK] MISP push complete: {total_success} succeeded, {total_failed} failed in {total_elapsed:.1f}s"
            )
        elif total_items > 0:
            logger.info(
                f"[SKIP] MISP push: 0 new attributes to push ({total_items} items all deduplicated) in {total_elapsed:.1f}s"
            )
        else:
            logger.info("[OK] MISP push: no items provided")

        return total_success, total_failed

    @retry_with_backoff(max_retries=4, base_delay=10.0)
    @rate_limited(max_per_second=2.0)
    def _push_batch(self, event_id: str, attributes: List[Dict]) -> Tuple[int, int]:
        """
        Push a batch of attributes to a MISP event.

        Args:
            event_id: MISP event ID
            attributes: List of MISP attribute dicts

        Returns:
            Tuple of (successful_count, failed_count)
        """
        # Sanitize event_id first
        event_id = sanitize_value(event_id, max_length=20)
        if not event_id or not attributes:
            return 0, 0

        try:
            # Prepare payload
            payload = {"Attribute": attributes}

            response = self.session.post(
                f"{self.url}/events/{event_id}",
                json=payload,
                verify=self.verify_ssl,
                timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
            )

            if response.status_code == 200:
                result = response.json()
                # MISP returns all attributes in the event, not just the new ones
                # We can only reliably report how many we attempted to add
                # The response doesn't tell us exactly which were new vs existing
                saved = result.get("Event", {}).get("Attribute", [])

                # Count how many attributes we tried to add
                attempted = len(attributes)

                # If the request succeeded, assume all were added (MISP handles deduplication)
                # We can't reliably determine how many were truly new from the response
                success_count = attempted
                failed_count = 0

                self.stats["attributes_added"] += success_count
                self.stats["batches_sent"] += 1

                logger.info(f"[OK] Added {success_count} attributes to event {event_id} (total in event: {len(saved)})")

                return success_count, failed_count
            else:
                # 400 responses usually include a JSON error body — log enough to debug MISP validation.
                detail = (response.text or "")[:4000]
                types_in_batch = [a.get("type") for a in attributes[:30]]
                logger.error(
                    "Failed to add attributes: %s — attribute types (first 30): %s — body (truncated): %s",
                    response.status_code,
                    types_in_batch,
                    detail,
                )
                # 5xx is usually transient (MISP under memory pressure on large
                # NVD events); raise so @retry_with_backoff can give it another
                # shot with exponential delay. Do NOT increment stats["errors"]
                # here — the decorator may succeed on a later attempt, and we
                # don't want to inflate the counter once per retry. The
                # terminal failure path (last raise from the decorator) is
                # handled by the outer caller which counts failed_count.
                if response.status_code >= 500:
                    raise MispTransientError(
                        f"MISP {response.status_code} pushing batch to event {event_id}",
                        response=response,
                    )
                # 4xx: permanent validation failure — count once and return.
                self.stats["errors"] += 1
                return 0, len(attributes)

        except _TRANSIENT_HTTP_ERRORS as e:
            logger.warning(f"MISP batch transient error (will retry): {e}")
            raise
        except Exception as e:
            logger.error(f"Batch push error: {e}")
            self.stats["errors"] += 1
            return 0, len(attributes)

    def push_indicators(self, indicators: List[Dict], source: str, batch_size: int = 500) -> Tuple[int, int]:
        """
        Push indicators to MISP (convenience method).

        Args:
            indicators: List of EdgeGuard indicator dicts
            source: Source name for the indicators
            batch_size: Number of indicators per batch

        Returns:
            Tuple of (successful_count, failed_count)
        """
        # Ensure source tag is set
        for ind in indicators:
            if "tag" not in ind or not ind["tag"]:
                ind["tag"] = source

        return self.push_items(indicators, batch_size)

    def get_stats(self) -> Dict[str, int]:
        """Get writer statistics."""
        return self.stats.copy()

    def reset_stats(self):
        """Reset writer statistics."""
        self.stats = {
            "events_created": 0,
            "attributes_added": 0,
            "batches_sent": 0,
            "errors": 0,
            "attrs_skipped_existing": 0,
        }


def test_misp_writer():
    """Test MISP writer functionality."""
    writer = MISPWriter()

    # Test indicator type mapping
    print("Testing type mapping:")
    print(f"  ipv4 -> {writer.map_indicator_type('ipv4')}")
    print(f"  domain -> {writer.map_indicator_type('domain')}")
    print(f"  hash -> {writer.map_indicator_type('hash')}")

    # Test attribute creation
    print("\nTesting attribute creation:")

    indicator = {
        "indicator_type": "ipv4",
        "value": "192.168.1.1",
        "zone": ["finance"],
        "tag": "otx",
        "confidence_score": 0.8,
        "first_seen": "2024-01-01T00:00:00Z",
        "pulse_name": "Test pulse",
    }

    attr = writer.create_attribute(indicator)
    print(f"  Indicator attribute: {json.dumps(attr, indent=2)}")

    vulnerability = {
        "type": "vulnerability",
        "cve_id": "CVE-2024-1234",
        "description": "Test vulnerability",
        "zone": ["healthcare"],
        "tag": "nvd",
        "severity": "HIGH",
        "cvss_score": 8.5,
    }

    vuln_attr = writer.create_vulnerability_attribute(vulnerability)
    print(f"  Vulnerability attribute: {json.dumps(vuln_attr, indent=2)}")

    print("\nMISP Writer test complete!")


if __name__ == "__main__":
    test_misp_writer()
