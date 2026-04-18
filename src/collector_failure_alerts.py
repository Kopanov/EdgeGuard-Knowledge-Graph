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
        "HTTPError",
        "ChunkedEncodingError",
        "ContentDecodingError",
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
        "ClientResponseError",
        "ServerDisconnectedError",
        # boto3-style (in case a collector uses S3-backed feeds later)
        "EndpointConnectionError",
    }
)


def is_transient_external_error(exc: BaseException | None) -> bool:
    """Return True if *exc* looks like a transient external-service failure.

    Match by class name (and walk the MRO + cause chain) so we don't have
    to import the HTTP library of every collector — works for ``requests``,
    ``httpx``, ``urllib3``, ``aiohttp``, stdlib socket/ssl errors, and
    anything else whose class name matches
    ``_TRANSIENT_EXTERNAL_EXCEPTION_NAMES``.

    Conservative: when in doubt, return False so the exception re-raises
    and a real bug gets surfaced. Better to fail loudly on a TypeError
    than silently swallow it as "transient."
    """
    if exc is None:
        return False
    # Walk the MRO of exc's class so subclasses match too (e.g. a
    # custom CyberCureRequestTimeout that subclasses TimeoutError).
    for cls in type(exc).__mro__:
        if cls.__name__ in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES:
            return True
    # Also walk the cause chain (``raise X from Y`` patterns) — a
    # collector might wrap a network error in a domain-specific exception
    # whose name we don't recognize, but the underlying cause is transient.
    cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    if cause is not None and cause is not exc:
        return is_transient_external_error(cause)
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
# Convenience: classify + record + alert in one call
# ---------------------------------------------------------------------------


def report_collector_failure(
    source_name: str,
    exc: BaseException,
    *,
    zone: str = "global",
) -> str:
    """Centralized failure-reporting helper for both DAG and CLI paths.

    Always:
      - Logs the failure with classification (transient vs catastrophic)
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

    try:
        from metrics_server import (
            record_collection,
            record_collector_skip,
            record_pipeline_error,
            set_source_health,
        )
    except Exception:
        # Metrics server unavailable — log and bail without dashboards.
        logger.warning(
            f"[{source_name}] {classification} failure ({exc_type}: {exc_msg}) "
            "— metrics_server import failed, no Prometheus signal emitted"
        )
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
        logger.warning(
            f"[{source_name}] TRANSIENT external error ({exc_type}: {exc_msg}) — "
            "marking source unhealthy, pipeline continues. "
            "Investigate via edgeguard_collector_skips_total{reason_class='transient_external_error'}"
        )
        send_slack_alert(
            f"Collector {source_name} skipped due to transient external error "
            f"({exc_type}: {exc_msg}); pipeline continues"
        )
    else:
        _safe(record_collection, source_name, zone, 0, "failed")
        logger.error(f"[{source_name}] CATASTROPHIC failure ({exc_type}: {exc_msg}) — see traceback")
        send_slack_alert(f"[CRITICAL] Collector {source_name} hard-failed: {exc_type}: {exc_msg}")

    return classification
