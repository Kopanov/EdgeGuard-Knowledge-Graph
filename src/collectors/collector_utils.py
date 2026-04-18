#!/usr/bin/env python3
"""
EdgeGuard - Shared collector utilities.

Provides canonical implementations of patterns that were previously duplicated
across every collector:
  - retry_with_backoff   : decorator for exponential-backoff retries on network errors
  - RateLimiter          : interval-based or sliding-window rate limiter (non-recursive)
  - make_status          : standardised status-dict factory (replaces _return_status copies)
"""

import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from functools import wraps
from typing import Any, Dict, FrozenSet, Optional

import requests

logger = logging.getLogger(__name__)

# Max wait from Retry-After or fallback (avoid blocking the worker for hours)
_MAX_RATE_LIMIT_SLEEP_SEC = 600.0


# ---------------------------------------------------------------------------
# Shared transient-error base class
# ---------------------------------------------------------------------------


class TransientServerError(requests.exceptions.HTTPError):
    """Base class for HTTP 5xx-style errors that callers opt in to retry.

    Callers (e.g. ``MISPWriter._push_batch``, ``fetch_event_details``) subclass
    this and ``raise`` it when an HTTP 5xx response comes back. The
    ``retry_with_backoff`` decorator below catches this base class by name,
    so opting into retry is just "define a subclass of
    ``TransientServerError`` and raise it". Ordinary ``HTTPError`` (including
    any 4xx that might sneak in via ``response.raise_for_status()``) is NOT
    a subclass of this and will not be retried — that way permanent
    validation errors don't spin on the backoff loop.

    Introduced 2026-04 after a regression where ``_push_batch`` raised
    ``requests.exceptions.HTTPError`` directly. The decorator only retried
    connection/timeout errors, so the raised ``HTTPError`` fell through to
    ``except Exception: raise`` and crashed the entire push — strictly worse
    than the pre-fix behaviour where 5xx returned ``(0, len(attributes))``
    and subsequent batches kept going.
    """


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------


def retry_with_backoff(max_retries: int = 3, base_delay: float = 2.0):
    """Decorator for retry logic with exponential backoff.

    Retries on transient network errors
    (ConnectionError, Timeout, ReadTimeout, ChunkedEncodingError) and on
    ``TransientServerError`` subclasses raised by callers that opt in to
    server-error retry (see class docstring above). Any other exception
    propagates immediately without retrying.

    Args:
        max_retries:  Number of retry attempts after the first failure.
        base_delay:   Initial delay in seconds; doubles on each retry.

    Usage::

        @retry_with_backoff(max_retries=3, base_delay=2.0)
        def my_api_call():
            ...
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ReadTimeout,
                    requests.exceptions.ChunkedEncodingError,
                    TransientServerError,
                ) as exc:
                    last_exception = exc
                    if attempt < max_retries:
                        delay = base_delay * (2**attempt)
                        logger.warning(
                            f"{func.__name__} failed "
                            f"(attempt {attempt + 1}/{max_retries + 1}): "
                            f"{exc}. Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(f"{func.__name__} failed after {max_retries + 1} attempts: {exc}")
                except Exception:
                    # Non-retryable — propagate immediately
                    raise

            raise last_exception  # type: ignore[misc]

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# HTTP 429 / 503 (and optional 403) — Retry-After aware retries
# ---------------------------------------------------------------------------


def retry_after_sleep_seconds(response: requests.Response, fallback: float) -> float:
    """
    Parse ``Retry-After`` (seconds or HTTP-date). Returns a bounded wait time in seconds.

    If the header is missing or invalid, returns ``fallback`` capped at 10 minutes.
    """
    raw = response.headers.get("Retry-After")
    if not raw:
        return min(max(fallback, 0.0), _MAX_RATE_LIMIT_SLEEP_SEC)
    raw = raw.strip()
    try:
        sec = float(raw)
        return min(max(sec, 0.0), _MAX_RATE_LIMIT_SLEEP_SEC)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return min(max(fallback, 0.0), _MAX_RATE_LIMIT_SLEEP_SEC)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        wait = (dt - now).total_seconds()
        return min(max(wait, 0.0), _MAX_RATE_LIMIT_SLEEP_SEC)
    except Exception:
        return min(max(fallback, 0.0), _MAX_RATE_LIMIT_SLEEP_SEC)


def request_with_rate_limit_retries(
    method: str,
    url: str,
    *,
    session: Optional[requests.Session] = None,
    max_rate_limit_retries: int = 3,
    fallback_delay_sec: float = 60.0,
    retry_on_403: bool = False,
    context: str = "HTTP",
    **kwargs: Any,
) -> requests.Response:
    """
    Perform an HTTP request and retry on **429**, **502**, **503**, and **504**
    (rate limit / bad gateway / unavailable / gateway timeout).

    After ``max_rate_limit_retries`` failed attempts for those status codes, returns
    the last response so the caller can log and fail or degrade gracefully.

    **403 Forbidden** is usually non-retryable (invalid key, IP block, plan). By
    default we **do not** sleep and retry. Set ``retry_on_403=True`` only if you
    suspect a transient edge/WAF glitch (still uses the same retry budget).

    Args:
        method: ``GET``, ``POST``, etc.
        url: Request URL
        session: Optional ``requests.Session`` (uses ``requests.request`` if None)
        max_rate_limit_retries: Number of **extra** attempts after the first 429/502/503/504
        fallback_delay_sec: Base delay when ``Retry-After`` is absent; also used as
            exponential backoff multiplier index
        retry_on_403: If True, treat 403 like 429 for retry purposes (use sparingly)
        context: Label for log messages (e.g. ``OTX``)
        **kwargs: Passed to ``session.request`` / ``requests.request``

    Returns:
        Final ``requests.Response`` (may still have status != 200).
    """
    # PR (security A8) — Red Team Tier A: default ``allow_redirects=False``
    # for all collector outbound HTTP. Without this, a compromised/hijacked
    # upstream feed (URLhaus, MITRE, NVD, etc.) can redirect a fetch to:
    #   * cloud metadata endpoints (169.254.169.254 → AWS/GCP/Azure creds)
    #   * internal services (127.0.0.1:7474 → Neo4j Browser, 7687 → Bolt)
    #   * .internal hostnames in private VPC ranges
    # The redirected response body lands in MISP and ultimately Neo4j, and
    # may leak via /graph/explore.
    #
    # Caller can override per-call by passing ``allow_redirects=True``
    # explicitly when redirect-following is genuinely needed and the
    # destination is trusted.
    kwargs.setdefault("allow_redirects", False)

    attempts_allowed = max(1, max_rate_limit_retries + 1)
    rate_limit_hits = 0
    attempt = 0
    last_response: Optional[requests.Response] = None

    while attempt < attempts_allowed:
        attempt += 1
        if session is not None:
            last_response = session.request(method.upper(), url, **kwargs)
        else:
            last_response = requests.request(method.upper(), url, **kwargs)

        if last_response.status_code == 200:
            return last_response

        code = last_response.status_code
        retryable = code in (429, 502, 503, 504) or (retry_on_403 and code == 403)

        if not retryable:
            return last_response

        rate_limit_hits += 1
        if rate_limit_hits > max_rate_limit_retries:
            url_dbg = f"{url[:80]}..." if len(url) > 80 else url
            logger.error(
                f"[{context}] HTTP {code} after {max_rate_limit_retries} backoff retries — giving up (url={url_dbg})"
            )
            return last_response

        delay = retry_after_sleep_seconds(
            last_response,
            fallback_delay_sec * (2 ** (rate_limit_hits - 1)),
        )
        logger.warning(
            f"[{context}] HTTP {code} — sleeping {delay:.1f}s then retry ({rate_limit_hits}/{max_rate_limit_retries})"
        )
        time.sleep(delay)

    return last_response  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe (single-process) rate limiter.

    Two operating modes — choose via constructor arguments:

    **Interval mode** (default):
        Enforces a minimum gap of *min_interval* seconds between calls.
        Simple and appropriate for most feeds::

            limiter = RateLimiter(min_interval=1.0)

    **Sliding-window mode**:
        Tracks a rolling 60-second window and blocks when
        *requests_per_minute* has been reached.  Suitable for APIs
        that enforce per-minute quotas (e.g. VirusTotal free tier)::

            limiter = RateLimiter(requests_per_minute=4)

    Note: uses ``time.monotonic()`` for interval mode to avoid wall-clock
    jumps; uses ``datetime.now(timezone.utc)`` for window mode to match timedelta maths.
    The ``wait_if_needed()`` implementation is iterative (not recursive) to
    avoid unbounded call stacks under heavy load.
    """

    def __init__(
        self,
        min_interval: float = 1.0,
        requests_per_minute: Optional[int] = None,
    ):
        self.min_interval = min_interval
        self.requests_per_minute = requests_per_minute
        self._last_call: float = 0.0
        self._window: deque = deque()

    def wait_if_needed(self) -> None:
        """Block until the next call is within the configured rate limit."""
        if self.requests_per_minute is not None:
            self._window_wait()
        else:
            self._interval_wait()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _interval_wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()

    def _window_wait(self) -> None:
        """Iterative sliding-window enforcement (no recursion)."""
        while True:
            now = datetime.now(timezone.utc)
            # Evict requests that have aged out of the 60-second window
            while self._window and now - self._window[0] > timedelta(minutes=1):
                self._window.popleft()

            if len(self._window) < self.requests_per_minute:  # type: ignore[operator]
                # Capacity available — record and return
                self._window.append(now)
                return

            # At capacity — compute exact wait time and sleep once
            wait_seconds = 60.0 - (now - self._window[0]).total_seconds()
            if wait_seconds > 0:
                logger.info(f"Rate limit reached ({self.requests_per_minute} req/min), waiting {wait_seconds:.1f}s...")
                time.sleep(wait_seconds)
            # Loop back to re-evaluate (handles edge cases after sleep)


# ---------------------------------------------------------------------------
# Optional third-party API keys (graceful Airflow skip — see make_status skipped=)
# ---------------------------------------------------------------------------

# Known placeholders from credentials/config.example.yaml — treat as unset
VIRUSTOTAL_API_KEY_PLACEHOLDERS: FrozenSet[str] = frozenset({"YOUR_VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE"})
OTX_API_KEY_PLACEHOLDERS: FrozenSet[str] = frozenset({"YOUR_OTX_API_KEY_HERE"})
ABUSEIPDB_API_KEY_PLACEHOLDERS: FrozenSet[str] = frozenset({"YOUR_ABUSEIPDB_API_KEY_HERE"})
# ThreatFox: literal "demo" is not a real key; abuse.ch may require a registered key for all queries.
THREATFOX_API_KEY_PLACEHOLDERS: FrozenSet[str] = frozenset({"demo", "YOUR_THREATFOX_API_KEY_HERE"})


def optional_api_key_effective(
    value: Optional[str],
    placeholders: FrozenSet[str] = frozenset(),
) -> Optional[str]:
    """Return a stripped API key for HTTP use, or None if unset / whitespace / template placeholder."""
    k = (value or "").strip()
    if not k:
        return None
    if placeholders and k in placeholders:
        return None
    return k


# ---------------------------------------------------------------------------
# Status dict factory
# ---------------------------------------------------------------------------


def make_status(
    source: str,
    success: bool,
    count: int = 0,
    failed: int = 0,
    error: Optional[str] = None,
    *,
    skipped: bool = False,
    skip_reason: Optional[str] = None,
    skip_reason_class: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a standardised collector status dictionary.

    Replaces the ``_return_status`` method that was copy-pasted across six
    collectors with subtle differences.

    Args:
        source:  Collector source name (e.g. ``'mitre'``, ``'cisa_kev'``).
        success: Whether the collection completed successfully.
        count:   Number of items successfully collected/pushed.
        failed:  Number of items that failed to push.
        error:   Optional error message (only included when provided).
        skipped: If True, task should **not** fail Airflow — optional source disabled
                 (e.g. missing API key). Use with ``success=True`` and ``count=0``.
        skip_reason: Human-readable reason for operators (logs / UI).
        skip_reason_class: Short label for metrics (e.g. ``missing_abuseipdb_key``).

    Returns:
        Dict suitable for use as a task return value in Airflow or as a
        pipeline stage status.
    """
    result: Dict[str, Any] = {
        "source": source,
        "success": success,
        "count": count,
        "failed": failed,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if error is not None:
        result["error"] = error
    if skipped:
        result["skipped"] = True
    if skip_reason is not None:
        result["skip_reason"] = skip_reason
    if skip_reason_class is not None:
        result["skip_reason_class"] = skip_reason_class
    return result


def make_skipped_optional_source(
    source: str,
    *,
    skip_reason: str,
    skip_reason_class: str,
) -> Dict[str, Any]:
    """Return ``success=True`` + ``skipped=True`` so Airflow continues (see ``run_collector_with_metrics``)."""
    return make_status(
        source,
        True,
        count=0,
        failed=0,
        skipped=True,
        skip_reason=skip_reason,
        skip_reason_class=skip_reason_class,
    )


def is_auth_or_access_denied(exc: BaseException) -> bool:
    """True if *exc* is HTTP 401/403 or a typical invalid/missing API key rejection."""
    try:
        if isinstance(exc, requests.HTTPError):
            r = exc.response
            if r is not None and getattr(r, "status_code", None) in (401, 403):
                return True
        r = getattr(exc, "response", None)
        if r is not None and getattr(r, "status_code", None) in (401, 403):
            return True
    except Exception:
        pass
    raw = str(exc)
    low = raw.lower()
    if "api error: 401" in low or "api error: 403" in low:
        return True
    if "status code 401" in low or "status code 403" in low:
        return True
    if " 401" in raw or raw.strip().startswith("401"):
        return True
    if " 403" in raw or "forbidden" in low:
        return True
    if "unauthorized" in low:
        return True
    if "invalid" in low and "api key" in low:
        return True
    if "authentication failed" in low:
        return True
    return False


def status_after_misp_push(
    source: str,
    num_items: int,
    push_success_count: int,
    push_failed_count: int,
) -> Dict[str, Any]:
    """Build a standard ``make_status`` dict after ``push_items`` / ``push_indicators``.

    Mirrors MITRE collector semantics: empty batch is success; at least one successful
    MISP write counts as success; all writes failed yields ``success=False`` and an error.
    """
    if num_items == 0:
        return make_status(source, True, count=0, failed=0)
    # All items deduplicated (0 pushed, 0 failed) = success, not failure.
    # This is the normal case on re-runs where MISP already has all items.
    ok = push_success_count > 0 or (push_success_count == 0 and push_failed_count == 0)
    err: Optional[str] = None
    if not ok and push_failed_count:
        err = f"MISP push failed for all or part of batch ({push_failed_count} failures, 0 successes)"
    return make_status(source, ok, count=num_items, failed=push_failed_count, error=err)
