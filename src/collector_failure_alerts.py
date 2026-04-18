"""Shared collector-failure handling — Prometheus + Slack visibility.

Used by BOTH the Airflow DAG path (``dags/edgeguard_pipeline.py:run_collector_with_metrics``)
AND the CLI path (``src/run_pipeline.py``) so a collector failure surfaces
identically regardless of how EdgeGuard was invoked. Vanko's PR-#35
follow-up audit caught that the CLI path had been silently swallowing
collector failures with no metric / no alert — only logs. This module
closes that gap.

Two responsibilities:

1. ``is_transient_external_error(exc)`` — classify whether an exception
   indicates a TRANSIENT external problem (network, upstream provider
   outage, DNS, timeout, HTTP 5xx) vs a CATASTROPHIC bug (TypeError,
   ImportError, programming defect). The Airflow path uses this to
   decide whether to mark the task SUCCESS-with-skipped (transient)
   or FAIL loudly (catastrophic).

2. ``send_slack_alert(message)`` — fire a Slack webhook if configured.
   Identical to the helper that previously lived in
   ``dags/edgeguard_pipeline.py``, now sharable from ``src/``.

Why a separate module: importing from ``dags/`` into ``src/`` is the
wrong dependency direction (DAGs depend on src, not the other way
round). Putting these helpers in ``src/`` lets both paths import
cleanly without a circular import.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


# Exception type names that indicate a TRANSIENT external problem (network,
# upstream provider outage, DNS, timeout) rather than an EdgeGuard bug.
# Names matched against ``type(exc).__name__`` so we don't have to import
# every collector's optional HTTP library — works whether ``requests`` is
# installed or not, and tolerates third-party libraries (``httpx``,
# ``urllib3``, ``aiohttp``) that ship parallel exception hierarchies.
#
# IMPORTANT (PR #35 commit 3, bugbot HIGH): generic ``HTTPError`` and
# ``ClientResponseError`` are DELIBERATELY EXCLUDED. Those classes match
# every 4xx response too — including 401 (expired API key) and 403
# (revoked), which are NOT transient. Marking them transient would
# silently drop "skip" events forever instead of surfacing an auth
# problem. The codebase has ``TransientServerError`` (subclass of
# requests.HTTPError, in src/collectors/collector_utils.py) specifically
# scoped to 5xx; we list THAT instead. For collectors that still raise
# vanilla ``HTTPError``, ``is_transient_external_error`` special-cases
# them by inspecting ``exc.response.status_code`` (5xx only — see below).
_TRANSIENT_EXTERNAL_EXCEPTION_NAMES: frozenset = frozenset(
    {
        # stdlib + requests
        "ConnectionError",
        "ConnectionRefusedError",
        "ConnectionResetError",
        "ConnectionAbortedError",
        "TimeoutError",
        "Timeout",
        "ReadTimeout",
        "ConnectTimeout",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ChunkedEncodingError",
        "ContentDecodingError",
        # The project's 5xx-only HTTPError subclass. Collectors that
        # raise this have already filtered for retry-worthy server errors.
        "TransientServerError",
        # urllib3 / requests adapters
        "MaxRetryError",
        "NewConnectionError",
        "ProtocolError",
        "ProxyError",
        "SSLError",
        # DNS
        "NameResolutionError",
        "gaierror",
        # httpx
        "ConnectError",
        "TransportError",
        "RemoteProtocolError",
        # asyncio / aiohttp
        "ClientConnectorError",
        "ClientConnectionError",
        "ClientOSError",
        "ServerDisconnectedError",
        # boto3-style (in case a collector uses S3-backed feeds later)
        "EndpointConnectionError",
    }
)


def _is_transient_http_5xx(exc: BaseException) -> bool:
    """Special-case for vanilla ``requests.HTTPError`` / aiohttp
    ``ClientResponseError``: only treat as transient if the response
    status is 5xx (server error, retry-worthy). 4xx (client error,
    auth, missing endpoint) is permanent — fail loudly.

    The classes themselves aren't in the transient name-list (see the
    comment on _TRANSIENT_EXTERNAL_EXCEPTION_NAMES), so this check is
    the ONLY way generic HTTPError ends up classified as transient.
    """
    cls_name = type(exc).__name__
    if cls_name not in {"HTTPError", "ClientResponseError"}:
        return False
    # requests.HTTPError stores the response on .response; aiohttp
    # ClientResponseError stores .status directly. Try both.
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if status is None:
        # aiohttp shape
        status = getattr(exc, "status", None)
    if not isinstance(status, int):
        return False
    return 500 <= status < 600


def is_transient_external_error(exc: BaseException | None) -> bool:
    """Return True if *exc* looks like a transient external-service failure.

    Match by class name only (walks the MRO so subclasses match too)
    plus a special-case for HTTP 5xx (where the class name alone —
    ``HTTPError`` or ``ClientResponseError`` — would also match 4xx auth
    failures).

    PR #35 commit 7 (bugbot MED): the cause-chain walk (``__cause__``)
    has been DROPPED. ``raise X from transient_err`` is the recommended
    best-practice pattern for adding context to errors, so wrapped
    exceptions appear in real production code. If we walked ``__cause__``,
    a collector doing ``raise ValueError("bad config") from conn_err``
    would have the ValueError silently classified as transient → real
    bug swallowed.

    The cost (false positives on wrapped real bugs) is greater than the
    benefit (catching wrapped network errors that don't subclass the
    known transient classes). Collectors that need to wrap a transient
    error should make their wrapper inherit from the underlying
    transient class (e.g.
    ``class CyberCureNetworkError(ConnectionError): pass``); the MRO
    walk above will catch it.

    Conservative: when in doubt, return False so the exception re-raises
    and a real bug gets surfaced. Better to fail loudly on a TypeError
    than silently swallow it as "transient."
    """
    if exc is None:
        return False
    # 5xx HTTPError gate: must be checked BEFORE the generic name walk so
    # 4xx HTTPError doesn't accidentally match through some MRO ancestor.
    if _is_transient_http_5xx(exc):
        return True
    # Walk the MRO of exc's class so subclasses match too (e.g. a
    # custom CyberCureRequestTimeout that subclasses TimeoutError).
    for cls in type(exc).__mro__:
        if cls.__name__ in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES:
            return True
    return False


# Slack alerting — opt-in via environment, identical contract to the
# helper that previously lived in dags/edgeguard_pipeline.py.
def _slack_alerts_enabled() -> bool:
    """Slack alerts fire only when explicitly enabled via env var.

    Default OFF so a missing webhook URL doesn't spam-warn on every
    collector failure in dev environments.
    """
    val = os.getenv("EDGEGUARD_ENABLE_SLACK_ALERTS", "").strip().lower()
    return val in {"1", "true", "yes", "on"}


def send_slack_alert(message: str, channel: str | None = None) -> None:
    """Send an alert to Slack if enabled.

    Reads ``SLACK_WEBHOOK_URL`` (or ``AIRFLOW__SLACK__WEBHOOK_URL``) at
    call time so late-bound env-var changes work. Silently returns if
    alerts are disabled or no webhook is configured.
    """
    if not _slack_alerts_enabled():
        return
    try:
        import requests

        webhook_url = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("AIRFLOW__SLACK__WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Slack webhook URL not configured (SLACK_WEBHOOK_URL/AIRFLOW__SLACK__WEBHOOK_URL)")
            return
        payload = {
            "text": f"🚨 *EdgeGuard Alert*\n{message}",
            "username": "EdgeGuard",
            "icon_emoji": ":warning:",
        }
        if channel:
            payload["channel"] = channel
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info("Slack alert sent successfully")
        else:
            logger.warning(f"Failed to send Slack alert: HTTP {response.status_code}")
    except Exception as e:
        # Slack send is best-effort — never let an alerting failure break
        # the caller's exception handler.
        logger.warning(f"Failed to send Slack alert: {e}")


# ---------------------------------------------------------------------------
# Structured failure log — actionable, grep-friendly, dashboard-aligned
# ---------------------------------------------------------------------------


def _extract_http_status(exc: BaseException) -> int | None:
    """Pull the HTTP status code off an HTTP error, if available.

    Handles two common shapes:
      - requests.HTTPError → ``exc.response.status_code``
      - aiohttp.ClientResponseError → ``exc.status``

    Returns None if neither shape applies (e.g. raw ConnectionError,
    timeout — those have no HTTP status).
    """
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return status
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return status
    return None


def _extract_url(exc: BaseException) -> str | None:
    """Pull the URL off an HTTP error, if available.

    Handles:
      - requests.HTTPError → ``exc.response.url``
      - aiohttp.ClientResponseError → ``exc.request_info.url`` or ``exc.url``
      - Fallback: parse ``str(exc)`` for ``"... for url: <URL>"`` (requests'
        default ``HTTPError.__str__`` includes this)
    """
    response = getattr(exc, "response", None)
    url = getattr(response, "url", None)
    if url:
        return str(url)
    request_info = getattr(exc, "request_info", None)
    url = getattr(request_info, "url", None)
    if url:
        return str(url)
    url = getattr(exc, "url", None)
    if url:
        return str(url)
    # Last resort: parse from the str(exc) form. Defensive against malformed
    # input — PR #35 commit 7 (bugbot MED): the previous ``.split()[0]``
    # crashed with IndexError if the message ended with ``" for url: "``
    # followed by whitespace (or nothing). A crash inside the
    # failure-handler would propagate up and FAIL the task — exactly the
    # pipeline-blocking behavior this PR exists to prevent.
    msg = str(exc)
    marker = " for url: "
    idx = msg.find(marker)
    if idx > 0:
        tail = msg[idx + len(marker) :].strip()
        if not tail:
            return None
        parts = tail.split()
        if not parts:
            return None
        return parts[0]
    return None


def _format_failure_log_block(
    source_name: str,
    exc: BaseException,
    *,
    classification: str,
    zone: str = "global",
    duration_s: float | None = None,
) -> str:
    """Build the multi-line structured log block emitted on collector failure.

    Format (3 lines, deterministic, grep-friendly):

        [<source>] <STATUS>  reason=<reason>  exc=<class>  http_status=<int>
                  url=<url>  duration=<s>
        ACTION: <human-readable next step for the operator>
        METRICS: <prometheus metric writes that just fired>

    All fields after ``exc=`` are OPTIONAL — included only when extractable
    from the exception. Operators can grep e.g. ``grep "http_status=503"``
    or ``grep "ACTION: provider-side"`` to find specific failure modes
    across DAG run logs.

    Why a structured block instead of free text:
      - Operator triage: ACTION line tells them WHAT TO DO without reading code
      - Postmortems: METRICS line cross-refs the Prometheus signals
      - Log aggregation (Loki, ELK): key=value parses cleanly into fields
      - Frequent regression: the same fields are present every time, so
        Grafana log panels can extract them with one stable regex
    """
    exc_type = type(exc).__name__
    fields: list = [f"reason={'transient_external_error' if classification == 'transient' else 'catastrophic'}"]
    fields.append(f"exc={exc_type}")
    http_status = _extract_http_status(exc)
    if http_status is not None:
        fields.append(f"http_status={http_status}")
    url = _extract_url(exc)
    if url:
        # Truncate ridiculously long URLs (>200 chars) to keep the log line readable
        fields.append(f"url={url[:200]}")
    if duration_s is not None:
        fields.append(f"duration={duration_s:.2f}s")
    # Always include the (truncated) exception message at the end so the log
    # still tells you WHAT happened even if no HTTP status / URL was extractable.
    exc_msg = str(exc)[:200].replace("\n", " ").replace("\r", " ")
    if exc_msg and exc_msg != exc_type:
        fields.append(f'msg="{exc_msg}"')

    if classification == "transient":
        status_word = "SKIPPED"
        action = (
            "ACTION: provider-side outage or transient network error — pipeline CONTINUED, downstream tasks "
            "will run with whatever data was already in MISP/Neo4j. The next scheduled DAG run will retry "
            "this collector (incremental DAGs run every ~30min/4h/8h/24h depending on tier). For most "
            "feeds, the next run's window overlaps and recovers the missed data automatically (see "
            "docs/AIRFLOW_DAGS.md for per-collector catch-up behavior). If the same source skips for >3 "
            "consecutive runs, treat as a sustained outage: page on-call OR manually re-trigger the DAG "
            "after the provider recovers."
        )
        metrics_summary = (
            "METRICS: edgeguard_collector_skips_total{source="
            + source_name
            + ",reason_class=transient_external_error} +1; "
            "edgeguard_collection_total{source=" + source_name + ",zone=" + zone + ",status=skipped} +1; "
            "edgeguard_source_health{source=" + source_name + ",zone=" + zone + "}=0"
        )
    else:
        status_word = "FAILED"
        action = (
            "ACTION: NOT a transient external error — likely a real bug, config error, or unrecognized "
            "exception type. Task FAILED; downstream baseline tasks (build_relationships, "
            "run_enrichment_jobs) WILL NOT run until the next successful DAG run (NONE_FAILED_MIN_ONE_SUCCESS "
            "trigger rule). See the traceback above this log line. After fixing, re-trigger the DAG. "
            "If you believe this exception class IS a transient external error and should not block, add "
            "its name to _TRANSIENT_EXTERNAL_EXCEPTION_NAMES in src/collector_failure_alerts.py."
        )
        metrics_summary = (
            "METRICS: edgeguard_collection_total{source=" + source_name + ",zone=" + zone + ",status=failed} +1; "
            "edgeguard_pipeline_errors_total{task=collect_"
            + source_name
            + ",error_type="
            + exc_type
            + ",source="
            + source_name
            + "} +1; "
            "edgeguard_source_health{source=" + source_name + ",zone=" + zone + "}=0"
        )

    fields_str = "  ".join(fields)
    return f"[{source_name}] {status_word}  {fields_str}\n{action}\n{metrics_summary}"


# ---------------------------------------------------------------------------
# Convenience: classify + record + alert in one call
# ---------------------------------------------------------------------------


def report_collector_failure(
    source_name: str,
    exc: BaseException,
    *,
    zone: str = "global",
    duration_s: float | None = None,
) -> str:
    """Centralized failure-reporting helper for both DAG and CLI paths.

    Always:
      - Logs a structured 3-line block (status + key=value fields, ACTION,
        METRICS — see ``_format_failure_log_block``) so operators see WHY
        and WHAT TO DO without opening source code
      - Calls ``set_source_health(source, zone, False)`` so the dashboard
        shows degradation
      - Calls ``record_pipeline_error(...)`` for the error-rate metric

    For TRANSIENT errors:
      - Calls ``record_collector_skip(source, "transient_external_error")``
      - Calls ``record_collection(source, zone, 0, "skipped")``
      - Sends a non-blocking Slack alert (if configured)

    For CATASTROPHIC errors:
      - Calls ``record_collection(source, zone, 0, "failed")``
      - Sends a CRITICAL Slack alert (if configured)

    Returns the classification string (``"transient"`` or
    ``"catastrophic"``) so the caller can decide whether to re-raise.

    Importing the ``metrics_server`` helpers happens inside this function
    so callers without the metrics server installed (e.g. a one-off CLI
    invocation in a slim container) don't need to handle ImportError —
    we degrade gracefully here.
    """
    transient = is_transient_external_error(exc)
    classification = "transient" if transient else "catastrophic"
    exc_type = type(exc).__name__
    exc_msg = str(exc)[:200]

    log_block = _format_failure_log_block(
        source_name, exc, classification=classification, zone=zone, duration_s=duration_s
    )

    try:
        from metrics_server import (
            record_collection,
            record_collector_skip,
            record_pipeline_error,
            set_source_health,
        )
    except Exception:
        # Metrics server unavailable — log structured block + bail without dashboards.
        logger.warning("%s\nNOTE: metrics_server import failed — no Prometheus signal emitted.", log_block)
        send_slack_alert(f"Collector {source_name} failed ({classification}, no metrics): {exc_type}: {exc_msg}")
        return classification

    # Best-effort metrics emission — never let a metric failure mask the
    # underlying collector failure.
    def _safe(fn: Any, *args: Any) -> None:
        try:
            fn(*args)
        except Exception as me:
            logger.debug(f"metric emit failed ({fn.__name__}): {me}")

    _safe(set_source_health, source_name, zone, False)
    _safe(record_pipeline_error, f"collect_{source_name}", exc_type, source_name)

    if transient:
        _safe(record_collector_skip, source_name, "transient_external_error")
        _safe(record_collection, source_name, zone, 0, "skipped")
        logger.warning(log_block)
        send_slack_alert(
            f"Collector {source_name} SKIPPED (transient: {exc_type}). "
            f"Pipeline continued. Full triage in Airflow logs (grep '[{source_name}] SKIPPED')."
        )
    else:
        _safe(record_collection, source_name, zone, 0, "failed")
        logger.error(log_block)
        send_slack_alert(
            f"[CRITICAL] Collector {source_name} HARD-FAILED ({exc_type}). "
            f"Downstream tasks blocked. Full triage in Airflow logs (grep '[{source_name}] FAILED')."
        )

    return classification
