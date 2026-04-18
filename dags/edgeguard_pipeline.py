"""
EdgeGuard Pipeline DAG - Apache Airflow
Comprehensive Threat Intelligence Collection

MISP-as-Source-of-Truth Architecture:
- Task Group 1: Collect sources → Push to MISP (configurable intervals)
- Task Group 2: MISP → Neo4j sync (configurable interval, default 72h)
- MISP preflight (**PythonOperator**) before collector operations

Config:
- MISP_REFRESH_INTERVAL: How often to fetch sources and push to MISP (hours)
- NEO4J_SYNC_INTERVAL: How often to sync MISP to Neo4j (hours)
- EDGEGUARD_COLLECT_SOURCES: Optional comma-separated allowlist of collector names
  (e.g. ``otx,nvd,cisa``). Unset = all collectors run. ``none`` or ``-`` = disable all.
  Skipped collectors return ``skipped`` with ``skip_reason_class=collector_disabled_by_config``.

================================================================================
                           CONFIGURATION FLAGS
================================================================================
Toggle these features by changing True/False:

ENABLE_PROMETHEUS_METRICS: Set to True to export Prometheus metrics
    - Exports: edgeguard_indicators_total, edgeguard_sync_duration_seconds, etc.
    - Default: False

ENABLE_SLACK_ALERTS: Set to True to send alerts to Slack on failure
    - Requires: SLACK_WEBHOOK_URL or AIRFLOW__SLACK__WEBHOOK_URL env var
    - Default: False

ENABLE_METRICS_EXPORT: Legacy flag (use ENABLE_PROMETHEUS_METRICS)

================================================================================
                           COLLECTOR SCHEDULES
================================================================================
This DAG uses optimized schedules for each collector based on rate limits:

HIGH FREQUENCY (Every 30 minutes):
- OTX: AlienVault OTX - High volume active threat feed

MEDIUM FREQUENCY (Every 4 hours):
- CISA: Known Exploited Vulnerabilities catalog
- VirusTotal: 4 req/min limit, 500/day free tier

LOW FREQUENCY (Every 8 hours):
- NVD: National Vulnerability Database updates

DAILY (Once per day):
- MITRE ATT&CK: Framework updates (rarely changes)
- ThreatFox: abuse.ch malware IOC feed
- AbuseIPDB: IP reputation (1,000/day limit)
- URLhaus: Malware distribution sites
- CyberCure: Automated threat feed
- Feodo Tracker: Botnet C2 IPs
- SSLBlacklist: Malicious SSL certificates

SYNC (Every 72 hours / configurable):
- MISP → Neo4j: Full graph synchronization

================================================================================
                           AVAILABLE COLLECTORS
================================================================================
Working Collectors (all integrated into this DAG):

Core Intelligence:
✅ otx_collector.py - AlienVault OTX (30 min)
✅ nvd_collector.py - NVD CVEs (8 hours)
✅ cisa_collector.py - CISA KEV (4 hours)
✅ mitre_collector.py - ATT&CK framework (daily)

VirusTotal:
✅ vt_collector.py - NEW: VirusTotal → MISP (4 hours)
✅ virustotal_collector.py - Enrichment collector (daily)

IP Reputation:
✅ abuseipdb_collector.py - NEW: AbuseIPDB blacklist (daily)

Global Feeds (global_feed_collector.py):
✅ ThreatFox - Malware IOCs (daily)
✅ URLhaus - Malware distribution (daily)
✅ CyberCure - Automated threats (daily)

Finance Sector (finance_feed_collector.py):
✅ Feodo Tracker - Botnet C2 (daily)
✅ SSLBlacklist - Malicious SSL (daily)

Sector-Specific (Placeholders):
📝 energy_feed_collector.py - Energy sector placeholder
📝 healthcare_feed_collector.py - Healthcare sector placeholder

================================================================================
"""

import inspect
import logging
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import pendulum
from airflow import DAG
from airflow.exceptions import AirflowException

# Airflow 3.x: BashOperator / PythonOperator / ShortCircuitOperator moved
# from airflow-core into the ``apache-airflow-providers-standard`` package.
# The provider package is forward-compatible — it works on Airflow 2.x too
# when installed explicitly — so a single import path covers both versions.
# Requires ``apache-airflow-providers-standard>=1.5`` in requirements.txt
# and requirements-airflow-docker.txt.
from airflow.providers.standard.operators.bash import BashOperator
from airflow.providers.standard.operators.python import (
    PythonOperator,
    ShortCircuitOperator,
)

# Airflow 3.x moved TaskGroup and Variable to the Task SDK namespace
# (``airflow.sdk.TaskGroup`` / ``airflow.sdk.Variable``). The old paths
# still work on 3.x as deprecated aliases, and are the ONLY paths that
# exist on Airflow 2.x. Use try/except so DAG parsing works under both
# versions during rollout and rollback. Importing ``Variable`` at module
# scope is safe — only the ``Variable.get()`` / ``Variable.set()`` calls
# hit the metadata DB, and those still happen lazily inside task
# callables.
try:
    from airflow.sdk import TaskGroup  # Airflow 3.x
except ImportError:  # pragma: no cover - 2.x fallback
    from airflow.utils.task_group import TaskGroup  # Airflow 2.x

try:
    from airflow.sdk import Variable  # Airflow 3.x
except ImportError:  # pragma: no cover - 2.x fallback
    from airflow.models import Variable  # Airflow 2.x

from airflow.utils.trigger_rule import TriggerRule

# Fixed start date — must not be dynamic (pendulum.now()) because Airflow
# recomputes it on every scheduler heartbeat which breaks run deduplication
# and causes catchup/backfill instability.
_DAG_START_DATE = pendulum.datetime(2025, 1, 1, tz="UTC")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================================================================================
#  CONFIGURATION FLAGS - Toggle features here
# ================================================================================

# Prometheus metrics export
ENABLE_PROMETHEUS_METRICS = os.getenv("EDGEGUARD_ENABLE_METRICS", "false").lower() == "true"

# Slack alerting on failures (disabled for now)
ENABLE_SLACK_ALERTS = False  # Set to True and configure SLACK_WEBHOOK_URL to enable

# Metrics settings
METRICS_PORT = int(os.getenv("EDGEGUARD_METRICS_PORT", "8001"))
METRICS_HOST = os.getenv("EDGEGUARD_METRICS_HOST", "127.0.0.1")


# Use relative path or environment variable for base directory
BASE_DIR = os.getenv("EDGEGUARD_BASE_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))

from collector_allowlist import is_collector_enabled_by_allowlist

# Import configuration
try:
    from config import MISP_API_KEY, MISP_URL, get_effective_limit, resolve_collection_limit
except (ImportError, RuntimeError) as e:
    logger.warning(f"Could not import config: {e}")
    MISP_URL = os.getenv("MISP_URL", "https://localhost:8443")
    MISP_API_KEY = os.getenv("MISP_API_KEY", "")
    if not MISP_API_KEY:
        raise AirflowException("MISP_API_KEY is required but not set")

    def get_effective_limit(source=None):
        return 100

    def resolve_collection_limit(limit, source=None, baseline=False):
        if limit is not None:
            return limit
        if baseline:
            return None
        return get_effective_limit(source)


# Import resilience utilities for circuit breaker and metrics
try:
    from resilience import (
        CIRCUIT_BREAKER_STATE,
        COLLECTION_FAILURES,
        LAST_SUCCESS,
        SERVICE_UP,
        get_all_circuit_breaker_status,
        record_collection_failure,
        record_collection_success,
        reset_circuit_breaker,
    )
    from resilience import (
        PROMETHEUS_AVAILABLE as RESILIENCE_METRICS_AVAILABLE,
    )
except ImportError:
    RESILIENCE_METRICS_AVAILABLE = False
    logger.warning("resilience module not available - circuit breaker metrics disabled")

# Import metrics server for enhanced metrics
try:
    from metrics_server import (
        get_metrics_server,
        record_collection,
        record_collection_duration,
        record_collector_skip,
        record_dag_run,
        record_misp_push,
        record_neo4j_sync,
        record_pipeline_error,
        record_task_duration,
        set_source_health,
        start_metrics_server,
    )

    METRICS_SERVER_AVAILABLE = True
    logger.info("Metrics server module loaded successfully")
except ImportError as e:
    METRICS_SERVER_AVAILABLE = False
    logger.warning(f"metrics_server module not available: {e}")

# ================================================================================
# METRICS SERVER INITIALIZATION
# ================================================================================

_metrics_server_instance = None
_metrics_server_lock = threading.Lock()


def ensure_metrics_server():
    """
    Ensure the metrics server is running.
    Call this in each task to ensure metrics are exposed.
    """
    global _metrics_server_instance
    if not ENABLE_PROMETHEUS_METRICS or not METRICS_SERVER_AVAILABLE:
        return None

    if _metrics_server_instance is None:
        with _metrics_server_lock:
            if _metrics_server_instance is None:
                try:
                    _metrics_server_instance = start_metrics_server(host=METRICS_HOST, port=METRICS_PORT, threaded=True)
                    logger.info(f"Started metrics server on {METRICS_HOST}:{METRICS_PORT}")
                except Exception as e:
                    logger.warning(f"Failed to start metrics server: {e}")

    return _metrics_server_instance


# ================================================================================
#  PROMETHEUS METRICS - Only initialize if enabled
# ================================================================================

PROMETHEUS_AVAILABLE = False

# When metrics_server IS available (production), import gauges from it to avoid
# duplicate registration.  When NOT available (standalone/dev), define them locally.
if ENABLE_PROMETHEUS_METRICS and METRICS_SERVER_AVAILABLE:
    try:
        from metrics_server import (
            DAG_LAST_SUCCESS,
            DAG_RUN_START,
            INDICATORS_COLLECTED,
            MISP_PUSH_DURATION,
            NEO4J_NODES,
            NEO4J_SYNC_DURATION,
            PIPELINE_ERRORS,
            SOURCE_HEALTH,
        )
        from metrics_server import (
            DAG_RUNS as DAG_RUNS_TOTAL,
        )

        # CIRCUIT_OPEN is not in metrics_server; define locally
        try:
            from prometheus_client import Gauge as _Gauge

            CIRCUIT_OPEN = _Gauge("edgeguard_circuit_open", "Circuit breaker state (1=open, 0=closed)", ["service"])
        except Exception as e:
            CIRCUIT_OPEN = None
            logger.warning(f"Could not create CIRCUIT_OPEN gauge: {e}")

        PROMETHEUS_AVAILABLE = True
        logger.info("Prometheus metrics imported from metrics_server (production mode)")
    except (ImportError, AttributeError) as e:
        logger.warning(f"Could not import metrics from metrics_server: {e}")

if ENABLE_PROMETHEUS_METRICS and not METRICS_SERVER_AVAILABLE and not PROMETHEUS_AVAILABLE:
    try:
        from prometheus_client import Counter, Gauge, Histogram

        PROMETHEUS_AVAILABLE = True

        # Define metrics
        DAG_RUNS_TOTAL = Counter(
            "edgeguard_dag_runs_total", "Total number of DAG runs", ["dag_id", "status", "run_type"]
        )
        INDICATORS_COLLECTED = Counter(
            "edgeguard_indicators_collected_total", "Total indicators collected", ["source", "zone", "status"]
        )
        MISP_PUSH_DURATION = Histogram("edgeguard_misp_push_duration_seconds", "Time spent pushing to MISP", ["source"])
        NEO4J_SYNC_DURATION = Histogram("edgeguard_neo4j_sync_duration_seconds", "Time spent syncing to Neo4j")
        NEO4J_NODES = Gauge("edgeguard_neo4j_nodes", "Number of nodes in Neo4j by label", ["label", "zone"])
        PIPELINE_ERRORS = Counter(
            "edgeguard_pipeline_errors_total", "Total pipeline errors", ["task", "error_type", "source"]
        )
        SOURCE_HEALTH = Gauge("edgeguard_source_health", "Data source health status", ["source", "zone"])

        # Circuit breaker state metrics
        CIRCUIT_OPEN = Gauge("edgeguard_circuit_open", "Circuit breaker state (1=open, 0=closed)", ["service"])
        # Note: edgeguard_last_success_timestamp is already registered by resilience.py
        # (imported above). Do NOT re-register here to avoid duplicate timeseries error.

        # DAG-level stuck-run detection
        DAG_LAST_SUCCESS = Gauge(
            "edgeguard_dag_last_success_timestamp",
            "Unix timestamp of last successful DAG run (0 = never succeeded)",
            ["dag_id"],
        )
        DAG_RUN_START = Gauge(
            "edgeguard_dag_run_start_timestamp",
            "Unix timestamp when the current DAG run started (0 = idle)",
            ["dag_id"],
        )

        logger.info("Prometheus metrics enabled (standalone mode)")
    except ImportError:
        logger.warning("prometheus_client not installed. Install with: pip install prometheus_client")
        ENABLE_PROMETHEUS_METRICS = False


# record_dag_run and set_source_health are only defined locally when metrics_server
# is unavailable; otherwise the imported versions from metrics_server remain active.
if not METRICS_SERVER_AVAILABLE:

    def record_dag_run(dag_id: str, status: str = "success", run_type: str = "scheduled"):
        """Record a DAG run in metrics."""
        if PROMETHEUS_AVAILABLE:
            DAG_RUNS_TOTAL.labels(dag_id=dag_id, status=status, run_type=run_type).inc()


def record_indicators(source: str, zone: str, count: int, status: str = "success"):
    """Record collected indicators."""
    if PROMETHEUS_AVAILABLE:
        INDICATORS_COLLECTED.labels(source=source, zone=zone, status=status).inc(count)


def record_misp_push_duration(source: str, duration: float):
    """Record MISP push duration."""
    if PROMETHEUS_AVAILABLE:
        MISP_PUSH_DURATION.labels(source=source).observe(duration)


def record_neo4j_sync_duration(duration: float):
    """Record Neo4j sync duration."""
    if PROMETHEUS_AVAILABLE:
        NEO4J_SYNC_DURATION.observe(duration)


def record_neo4j_nodes(node_type: str, count: int, zone: str = "all"):
    """Record Neo4j node counts."""
    if PROMETHEUS_AVAILABLE:
        NEO4J_NODES.labels(label=node_type, zone=zone).set(count)


def record_error(task: str, error_type: str, source: str = ""):
    """Record a pipeline error."""
    if PROMETHEUS_AVAILABLE:
        PIPELINE_ERRORS.labels(task=task, error_type=error_type, source=source).inc()


if not METRICS_SERVER_AVAILABLE:

    def set_source_health(source: str, zone: str, healthy: bool):
        """Set source health status."""
        if PROMETHEUS_AVAILABLE:
            SOURCE_HEALTH.labels(source=source, zone=zone).set(1 if healthy else 0)


def set_circuit_state(service: str, is_open: bool):
    """Set circuit breaker state."""
    if PROMETHEUS_AVAILABLE and CIRCUIT_OPEN is not None:
        CIRCUIT_OPEN.labels(service=service).set(1 if is_open else 0)


def set_last_success_timestamp(source: str):
    """Set last successful collection timestamp."""
    if RESILIENCE_METRICS_AVAILABLE:
        LAST_SUCCESS.labels(source=source).set(time.time())


def log_circuit_breaker_status():
    """Log circuit breaker status for all services."""
    if not RESILIENCE_METRICS_AVAILABLE:
        return

    try:
        cb_status = get_all_circuit_breaker_status()
        logger.info("Circuit Breaker Status:")
        for name, status in cb_status.items():
            logger.info(
                f"  {name}: {status['state']} (failures: {status['failure_count']}/{status['failure_threshold']})"
            )
    except Exception as e:
        logger.warning(f"Failed to get circuit breaker status: {e}")


def reset_service_circuit_breaker(source: str):
    """Manually reset a circuit breaker (for admin/ops use)."""
    if RESILIENCE_METRICS_AVAILABLE:
        try:
            reset_circuit_breaker(source)
            logger.info(f"Circuit breaker '{source}' has been reset")
        except Exception as e:
            logger.warning(f"Failed to reset circuit breaker '{source}': {e}")


# ================================================================================
#  SLACK ALERTS - Only initialize if enabled
# ================================================================================


def send_slack_alert(message: str, channel: str = None):
    """Send alert to Slack if enabled."""
    if not ENABLE_SLACK_ALERTS:
        return

    try:
        import requests

        webhook_url = os.getenv("SLACK_WEBHOOK_URL") or os.getenv("AIRFLOW__SLACK__WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Slack webhook URL not configured")
            return

        payload = {"text": f"🚨 *EdgeGuard Alert*\n{message}", "username": "EdgeGuard", "icon_emoji": ":warning:"}
        response = requests.post(webhook_url, json=payload, timeout=10)
        if response.status_code == 200:
            logger.info("Slack alert sent successfully")
        else:
            logger.warning(f"Failed to send Slack alert: {response.status_code}")
    except Exception as e:
        logger.warning(f"Failed to send Slack alert: {e}")


def _on_task_failure(context):
    """Callback on any task failure — logs prominently, updates metrics, sends Slack if enabled."""
    dag_id = context.get("dag").dag_id if context.get("dag") else "unknown"
    task_id = context.get("task_instance").task_id if context.get("task_instance") else "unknown"
    exc = context.get("exception", "")
    logger.error(f"[ALERT] Task FAILED: {dag_id}.{task_id} — {exc}")
    if ENABLE_SLACK_ALERTS:
        send_slack_alert(f"[CRITICAL] Task FAILED: {dag_id}.{task_id} — {exc}")
    if ENABLE_PROMETHEUS_METRICS and PROMETHEUS_AVAILABLE:
        try:
            PIPELINE_ERRORS.labels(task=task_id, error_type="task_failure", source=dag_id).inc()
        except Exception as e:
            logger.warning(f"Failed to record failure metric for {dag_id}.{task_id}: {e}")


def _on_task_success(context):
    """Callback on any task success — updates DAG activity timestamp.

    Sets DAG_LAST_SUCCESS on every task completion so the
    EdgeGuardDAGLastSuccessStale alert can detect DAGs where no task
    has succeeded recently (covers both partial and full failures).
    Also refreshes DAG_RUN_START to show the DAG is actively progressing.
    """
    if not (ENABLE_PROMETHEUS_METRICS and PROMETHEUS_AVAILABLE):
        return
    dag_id = context.get("dag").dag_id if context.get("dag") else "unknown"
    now = time.time()
    try:
        DAG_LAST_SUCCESS.labels(dag_id=dag_id).set(now)
        DAG_RUN_START.labels(dag_id=dag_id).set(now)  # keeps refreshing while DAG is active
    except Exception as e:
        logger.warning(f"Failed to record success metric for {dag_id}: {e}")


# Default arguments
default_args = {
    "owner": "edgeguard",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=5),
    "on_failure_callback": _on_task_failure,
    "on_success_callback": _on_task_success,
}

# ================================================================================
#  MAIN PIPELINE DAG - Runs every 30 minutes (high-frequency collectors)
# ================================================================================


def get_intervals():
    """Get configurable intervals from Airflow variables or use defaults."""
    try:
        # Use positional default (second arg) so the call works on both
        # Airflow 2.x (kwarg is `default_var`) and 3.x (kwarg is `default`).
        # Bugbot caught that the keyword form would raise TypeError on 3.x
        # and silently fall through to the except, disabling all Variable
        # configuration on the upgraded runtime.
        misp_refresh = int(Variable.get("MISP_REFRESH_INTERVAL", 8))
        neo4j_sync = int(Variable.get("NEO4J_SYNC_INTERVAL", 72))
    except (ImportError, ValueError, TypeError) as e:
        logger.warning(f"Failed to get interval variables, using defaults: {e}")
        misp_refresh = 8
        neo4j_sync = 72

    return misp_refresh, neo4j_sync


MISP_REFRESH_INTERVAL, NEO4J_SYNC_INTERVAL = get_intervals()

logger.info("EdgeGuard DAG configured:")
logger.info(f"  MISP Refresh Interval: {MISP_REFRESH_INTERVAL}h")
logger.info(f"  Neo4j Sync Interval: {NEO4J_SYNC_INTERVAL}h")


# MISP preflight (aligned with run_pipeline_misp_spt.check_misp_health)
#
# MISPHealthCheck.check_health() returns MISPHealthCheckResult (dict-like .get / [] / "checks" in result).
# result["healthy"] is API+DB (workers optional). With REQUIRE_WORKERS, preflight also requires workers.
# Set EDGEGUARD_SKIP_MISP_PREFLIGHT=true to bypass preflight (emergency only).


def check_misp_health(require_workers: Optional[bool] = None) -> bool:
    """Return True if MISP is OK for collection (see module docstring)."""
    if require_workers is None:
        require_workers = os.getenv("EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS", "").lower() in (
            "1",
            "true",
            "yes",
        )
    try:
        from misp_health import MISPHealthCheck

        checker = MISPHealthCheck()
        result = checker.check_health()

        logger.info(f"MISP Health Check: {result['status']}")
        if "checks" in result:
            logger.info(f"  API Connectivity: {'OK' if result['checks'].get('api_connectivity') else 'FAIL'}")
            logger.info(f"  Database: {'OK' if result['checks'].get('database') else 'FAIL'}")
            logger.info(f"  Workers: {'OK' if result['checks'].get('worker_status') else 'FAIL'}")

        if require_workers:
            return bool(
                result.get("healthy_for_collection", False) and result.get("checks", {}).get("worker_status", False)
            )
        return bool(result.get("healthy_for_collection", False))
    except (ImportError, AttributeError, KeyError) as e:
        logger.error(f"MISP health check failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in MISP health check: {e}")
        return False


def assert_misp_preflight() -> None:
    """One-shot MISP gate for DAGs: fails fast instead of a PythonSensor waiting minutes."""
    if os.getenv("EDGEGUARD_SKIP_MISP_PREFLIGHT", "").lower() in ("1", "true", "yes"):
        logger.warning(
            "EDGEGUARD_SKIP_MISP_PREFLIGHT is set — skipping MISP preflight (not recommended for production)"
        )
        return
    if not check_misp_health():
        raise AirflowException(
            "MISP preflight failed (API/DB unreachable or unhealthy with current policy). "
            "From Docker, ensure MISP_URL reaches MISP (not host-only localhost). "
            "If workers are down but API/DB are fine, do not set REQUIRE_WORKERS. "
            "Docs: docs/AIRFLOW_DAGS.md, docs/ENVIRONMENTS.md"
        )

    # Warn about version compatibility
    try:
        from misp_health import MISPHealthCheck

        result = MISPHealthCheck().check_health()
        if hasattr(result, "details") and result.details.get("version_compatible") is False:
            issues = result.details.get("issues", [])
            compat_issues = [i for i in issues if "compatible" in i.lower() or "pymisp" in i.lower()]
            if compat_issues:
                logger.warning(f"MISP VERSION WARNING: {compat_issues[0]}")
                logger.warning(
                    "Pipeline may work but Airflow DAG scheduler could hang. "
                    "Consider using 'python3 src/run_pipeline.py' directly."
                )
    except Exception as e:
        logger.debug("Advisory version compatibility check failed: %s", e, exc_info=True)


# ================================================================================
#  COLLECTOR FUNCTIONS WITH METRICS
# ================================================================================


def _method_accepts_kwarg(callable_obj, name: str) -> bool:
    """
    True if ``name`` can be passed to ``callable_obj`` (explicit param or **kwargs).

    Used so baseline DAG does not pass ``baseline`` / ``baseline_days`` into
    ``collect()`` implementations that do not declare them (avoids TypeError).
    """
    try:
        sig = inspect.signature(callable_obj)
    except (TypeError, ValueError):
        return False
    for p in sig.parameters.values():
        if p.name == name:
            return True
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return False


# PR #35 commit 2: ``_is_transient_external_error`` and the transient-name
# frozenset moved to ``src/collector_failure_alerts.py`` so the CLI path
# (``src/run_pipeline.py``) can use the same classifier. The local names
# below are kept as backward-compatible aliases — existing tests + comments
# in this file still reference them.
from collector_failure_alerts import (  # noqa: E402
    _TRANSIENT_EXTERNAL_EXCEPTION_NAMES,
)
from collector_failure_alerts import (
    is_transient_external_error as _is_transient_external_error,
)


def run_collector_with_metrics(
    collector_name: str,
    collector_class,
    writer,
    limit: int = 100,
    baseline: bool = False,
    baseline_days: int = 365,
    **collector_kwargs,
):
    """
    Run a collector with circuit breaker protection and graceful degradation.

    Args:
        collector_name: Name for metrics (e.g., 'otx', 'nvd')
        collector_class: The collector class to instantiate
        writer: MISPWriter instance
        limit: Number of items to collect
        baseline: If True, request baseline mode for collect() when the method accepts it;
            otherwise ``limit`` is pre-resolved with baseline semantics (unlimited vs incremental cap).
        baseline_days: Passed to collect() only when it accepts ``baseline_days`` (with baseline mode).
        **collector_kwargs: Additional arguments passed to the collector constructor only

    Returns:
        Result dict with count and status
    """
    import time

    start_time = time.time()

    # Ensure metrics server is running
    ensure_metrics_server()

    log_circuit_breaker_status()

    task_start = time.time()

    # Baseline mutex: if a CLI baseline run is holding the sentinel lock,
    # skip this scheduled run instead of racing against it for MISP/Neo4j
    # writes. The baseline is treated as authoritative — it's a long,
    # expensive, operator-driven run that shouldn't be undermined by
    # interleaved partial writes from the incremental DAGs.
    try:
        from baseline_lock import baseline_skip_reason

        _baseline_skip = baseline_skip_reason()
    except Exception:
        # If the module can't load for any reason, fail-open (run as
        # before). Import errors must not break the whole DAG.
        logger.debug("baseline_lock import failed — proceeding without baseline mutex", exc_info=True)
        _baseline_skip = None

    if _baseline_skip is not None:
        from collectors.collector_utils import make_skipped_optional_source

        logger.warning("%s: %s", collector_name.upper(), _baseline_skip)
        result = make_skipped_optional_source(
            collector_name,
            skip_reason=_baseline_skip,
            skip_reason_class="baseline_in_progress",
        )
        duration = time.time() - start_time
        record_dag_run("edgeguard_pipeline", "success")
        if METRICS_SERVER_AVAILABLE:
            record_collection(collector_name, "global", 0, "skipped")
            record_collection_duration(collector_name, "global", duration)
            record_collector_skip(collector_name, "baseline_in_progress")
        return result

    if not is_collector_enabled_by_allowlist(collector_name):
        from collectors.collector_utils import make_skipped_optional_source

        result = make_skipped_optional_source(
            collector_name,
            skip_reason="Collector not in EDGEGUARD_COLLECT_SOURCES allowlist (disabled by configuration)",
            skip_reason_class="collector_disabled_by_config",
        )
        duration = time.time() - start_time
        record_dag_run("edgeguard_pipeline", "success")
        if METRICS_SERVER_AVAILABLE:
            record_collection(collector_name, "global", 0, "skipped")
            record_collection_duration(collector_name, "global", duration)
            record_misp_push(collector_name, "global", result.get("event_count", 1), 0, duration)
            record_collector_skip(collector_name, "collector_disabled_by_config")
            task_duration = time.time() - task_start
            record_task_duration(f"collect_{collector_name}", "edgeguard_pipeline", task_duration)
        set_source_health(collector_name, "global", True)
        logger.warning(
            f"{collector_name.upper()} skipped (allowlist) in {duration:.2f}s — "
            f"not listed in EDGEGUARD_COLLECT_SOURCES (task success; downstream continues)"
        )
        return result

    try:
        # Instantiate collector — only constructor-safe kwargs go here.
        # baseline/baseline_days are collect()-level flags, kept separate above.
        collector = collector_class(misp_writer=writer, **collector_kwargs)

        # Run collection — only pass baseline/baseline_days if collect() accepts them (or **kwargs),
        # so third-party or legacy collectors without those parameters do not raise TypeError.
        # If baseline mode is requested but collect() has no ``baseline`` param, resolve ``limit``
        # here so ``limit=None`` still means "no per-item cap" instead of the incremental default.
        collect_kwargs: dict = {"limit": limit, "push_to_misp": True}
        if baseline:
            collect_fn = collector.collect
            if _method_accepts_kwarg(collect_fn, "baseline"):
                collect_kwargs["baseline"] = True
                if _method_accepts_kwarg(collect_fn, "baseline_days"):
                    collect_kwargs["baseline_days"] = baseline_days
            else:
                collect_kwargs["limit"] = resolve_collection_limit(limit, collector_name, baseline=True)
                logger.info(
                    f"{collector_name}: baseline mode — collect() has no 'baseline' parameter; "
                    f"using resolved limit={collect_kwargs['limit']!r} (baseline cap semantics)"
                )
        result = collector.collect(**collect_kwargs)

        # Contract: with push_to_misp=True, collectors must return a status dict (make_status).
        # A list/None used to fall through and become a false Airflow "success" with count 0.
        if not isinstance(result, dict):
            msg = (
                f"{collector_name}: collect() returned {type(result).__name__}, expected a status dict "
                "when push_to_misp=True (see make_status in collector_utils)"
            )
            logger.error(msg)
            record_dag_run("edgeguard_pipeline", "failure")
            if METRICS_SERVER_AVAILABLE:
                record_collection(collector_name, "global", 0, "failed")
            set_source_health(collector_name, "global", False)
            raise AirflowException(msg)

        # Handle result — fail the Airflow task on any explicit collector failure.
        # Many collectors return make_status(..., success=False) without an "error" key
        # (e.g. MITRE when every MISP push fails); the old check required both, so tasks
        # could show "success" in the UI while nothing was ingested.
        if isinstance(result, dict) and result.get("success") is False:
            err = result.get("error") or (
                f"{collector_name}: success=false (failed={result.get('failed', 0)}, "
                f"count={result.get('count', 0)}) — check MISP logs and MISP_URL/API key"
            )
            logger.error(f"{collector_name.upper()} collection failed: {err}")
            record_dag_run("edgeguard_pipeline", "failure")
            if METRICS_SERVER_AVAILABLE:
                record_collection(collector_name, "global", 0, "failed")
            # Always 3-arg: matches metrics_server.set_source_health(source, zone, healthy)
            set_source_health(collector_name, "global", False)
            raise AirflowException(err)

        if isinstance(result, dict):
            # Record success metrics
            duration = time.time() - start_time
            record_misp_push_duration(collector_name, duration)
            record_dag_run("edgeguard_pipeline", "success")

            count = result.get("count", result.get("total", 0))
            zone = result.get("zone", "global")
            if isinstance(zone, list):
                zone = zone[0] if zone else "global"
            record_indicators(collector_name, zone, count)

            skipped = result.get("skipped") is True
            skip_reason = result.get("skip_reason", "optional source skipped")

            set_source_health(collector_name, zone, True)
            if not skipped:
                set_last_success_timestamp(collector_name)

            # Record enhanced metrics — use status=skipped for optional collectors without API keys
            collection_status = "skipped" if skipped else "success"
            if METRICS_SERVER_AVAILABLE:
                record_collection(collector_name, zone, count, collection_status)
                record_collection_duration(collector_name, zone, duration)
                record_misp_push(collector_name, zone, result.get("event_count", 1), count, duration)
                if skipped:
                    record_collector_skip(
                        collector_name,
                        result.get("skip_reason_class", "optional_source"),
                    )

            if skipped:
                logger.warning(
                    f"{collector_name.upper()} skipped in {duration:.2f}s — {skip_reason} "
                    f"(task success; downstream continues)"
                )
            else:
                logger.info(f"{collector_name.upper()} collection completed in {duration:.2f}s")

        # Record task duration
        task_duration = time.time() - task_start
        if METRICS_SERVER_AVAILABLE:
            record_task_duration(f"collect_{collector_name}", "edgeguard_pipeline", task_duration)

        return result

    except AirflowException:
        # Already logged and metrics updated above (collector success=false path).
        raise
    except Exception as e:
        # PR #35: distinguish TRANSIENT external errors (network, upstream
        # 5xx, DNS, SSL handshake, timeout) from CATASTROPHIC bugs
        # (TypeError, ImportError, programming mistakes). The user policy
        # is "if a feed fails for an external reason, log + continue;
        # don't block the whole pipeline." A CyberCure outage on the
        # provider's end shouldn't keep the baseline DAG from running
        # build_relationships + enrichment + completion.
        #
        # Transient errors → log, record metric, send alert, return a
        # "skipped" status with success=True. Airflow task stays GREEN
        # (no upstream_failed propagation), failure remains visible via
        # logs + Prometheus + Slack alert.
        # Catastrophic errors → re-raise as before. A missing module or
        # type error indicates a real bug we want to surface loudly.
        duration = time.time() - start_time
        record_error(collector_name, type(e).__name__)
        if METRICS_SERVER_AVAILABLE:
            record_pipeline_error(f"collect_{collector_name}", type(e).__name__, collector_name)
        set_source_health(collector_name, "global", False)

        # PR #35 commit 6: route through the shared structured-log helper
        # so the operator-facing message is identical to the CLI path
        # (key=value fields + ACTION line + METRICS line). See
        # ``src/collector_failure_alerts.py::_format_failure_log_block``
        # for the format contract.
        from collector_failure_alerts import _format_failure_log_block

        if _is_transient_external_error(e):
            from collectors.collector_utils import make_skipped_optional_source

            record_dag_run("edgeguard_pipeline", "success")
            if METRICS_SERVER_AVAILABLE:
                record_collection(collector_name, "global", 0, "skipped")
                record_collection_duration(collector_name, "global", duration)
                record_collector_skip(collector_name, "transient_external_error")
            log_block = _format_failure_log_block(collector_name, e, classification="transient", duration_s=duration)
            logger.warning(log_block)
            send_slack_alert(
                f"Collector {collector_name} SKIPPED (transient: {type(e).__name__}). "
                f"Pipeline continued. Full triage in Airflow logs (grep '[{collector_name}] SKIPPED')."
            )
            return make_skipped_optional_source(
                collector_name,
                skip_reason=f"transient external error: {type(e).__name__}: {e}",
                skip_reason_class="transient_external_error",
            )

        # Catastrophic — fail loudly.
        record_dag_run("edgeguard_pipeline", "failure")
        if METRICS_SERVER_AVAILABLE:
            record_collection(collector_name, "global", 0, "failed")
        log_block = _format_failure_log_block(collector_name, e, classification="catastrophic", duration_s=duration)
        logger.error(log_block)
        send_slack_alert(
            f"[CRITICAL] Collector {collector_name} HARD-FAILED ({type(e).__name__}). "
            f"Downstream tasks blocked. Full triage in Airflow logs (grep '[{collector_name}] FAILED')."
        )
        raise


# ================================================================================
#  COLLECTOR RUNNER FUNCTIONS
# ================================================================================


def run_otx_collection(**context):
    """Run OTX collector with metrics."""
    from collectors.misp_writer import MISPWriter
    from collectors.otx_collector import OTXCollector

    limit = get_effective_limit("otx")
    return run_collector_with_metrics("otx", OTXCollector, MISPWriter(), limit=limit)


def run_nvd_collection(**context):
    """Run NVD collector with metrics."""
    from collectors.misp_writer import MISPWriter
    from collectors.nvd_collector import NVDCollector

    limit = get_effective_limit("nvd")
    return run_collector_with_metrics("nvd", NVDCollector, MISPWriter(), limit=limit)


def run_cisa_collection(**context):
    """Run CISA collector with metrics."""
    from collectors.cisa_collector import CISACollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("cisa")
    return run_collector_with_metrics("cisa", CISACollector, MISPWriter(), limit=limit)


def run_mitre_collection(**context):
    """Run MITRE collector with metrics."""
    from collectors.misp_writer import MISPWriter
    from collectors.mitre_collector import MITRECollector

    limit = get_effective_limit("mitre")
    return run_collector_with_metrics("mitre", MITRECollector, MISPWriter(), limit=limit)


def run_vt_collection(**context):
    """Run NEW VirusTotal collector (vt_collector.py) with metrics."""
    from collectors.misp_writer import MISPWriter
    from collectors.vt_collector import VTCollector

    limit = get_effective_limit("virustotal")
    return run_collector_with_metrics("virustotal", VTCollector, MISPWriter(), limit=limit)


def run_virustotal_enrichment_collection(**context):
    """Run VirusTotal enrichment collector with metrics."""
    from collectors.misp_writer import MISPWriter
    from collectors.virustotal_collector import VirusTotalCollector

    limit = get_effective_limit("virustotal")
    return run_collector_with_metrics("virustotal_enrich", VirusTotalCollector, MISPWriter(), limit=limit)


def run_abuseipdb_collection(**context):
    """Run AbuseIPDB collector with metrics."""
    from collectors.abuseipdb_collector import AbuseIPDBCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("abuseipdb")
    return run_collector_with_metrics("abuseipdb", AbuseIPDBCollector, MISPWriter(), limit=limit)


def run_threatfox_collection(**context):
    """Run ThreatFox collector with metrics."""
    from collectors.global_feed_collector import ThreatFoxCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("threatfox")
    return run_collector_with_metrics("threatfox", ThreatFoxCollector, MISPWriter(), limit=limit)


def run_urlhaus_collection(**context):
    """Run URLhaus collector with metrics."""
    from collectors.global_feed_collector import URLhausCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("urlhaus")
    return run_collector_with_metrics("urlhaus", URLhausCollector, MISPWriter(), limit=limit)


def run_cybercure_collection(**context):
    """Run CyberCure collector with metrics."""
    from collectors.global_feed_collector import CyberCureCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("cybercure")
    return run_collector_with_metrics("cybercure", CyberCureCollector, MISPWriter(), limit=limit)


def run_feodo_collection(**context):
    """Run Feodo Tracker collector with metrics."""
    from collectors.finance_feed_collector import FeodoCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("feodo")
    return run_collector_with_metrics("feodo", FeodoCollector, MISPWriter(), limit=limit)


def run_sslblacklist_collection(**context):
    """Run SSL Blacklist collector with metrics."""
    from collectors.finance_feed_collector import SSLBlacklistCollector
    from collectors.misp_writer import MISPWriter

    limit = get_effective_limit("sslbl")
    return run_collector_with_metrics("sslbl", SSLBlacklistCollector, MISPWriter(), limit=limit)


def run_energy_placeholder(**context):
    """Placeholder for energy sector collector."""
    logger.info("Energy sector collector - placeholder (no active feeds configured)")
    return {"success": True, "count": 0, "message": "Energy collector placeholder"}


def run_healthcare_placeholder(**context):
    """Placeholder for healthcare sector collector."""
    logger.info("Healthcare sector collector - placeholder (no active feeds configured)")
    return {"success": True, "count": 0, "message": "Healthcare collector placeholder"}


# ================================================================================
#  NEO4J SYNC FUNCTIONS
# ================================================================================


def get_state_file() -> str:
    """Get the state file path with secure permissions.

    Falls back to a 'state/' subdirectory of the project root so the sync
    interval survives server reboots.  Override with EDGEGUARD_STATE_DIR.
    """
    default_state_dir = os.path.join(BASE_DIR, "state")
    state_dir = os.getenv("EDGEGUARD_STATE_DIR", default_state_dir)
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    return os.path.join(state_dir, "edgeguard_last_neo4j_sync.json")


def should_run_neo4j_sync():
    """Determine if Neo4j sync should run based on interval."""
    import json

    # Baseline mutex: the scheduled Neo4j sync must never run concurrently
    # with a CLI baseline. The baseline runs its own MISP->Neo4j sync in
    # the same Python process and a parallel Airflow sync would read
    # MISP mid-push, producing partial data in Neo4j. ShortCircuit skips
    # the whole sync DAG run downstream. Fail-open: if baseline_lock
    # fails to import (e.g. module not on PYTHONPATH during a test),
    # log the error and proceed rather than blocking the sync.
    try:
        from baseline_lock import baseline_skip_reason

        _baseline_skip = baseline_skip_reason()
    except Exception:
        logger.debug("baseline_lock import failed — proceeding without baseline mutex", exc_info=True)
        _baseline_skip = None
    if _baseline_skip is not None:
        logger.warning("Neo4j sync ShortCircuit: %s", _baseline_skip)
        return False

    state_file = get_state_file()

    try:
        interval_hours = int(Variable.get("NEO4J_SYNC_INTERVAL", 72))
    except (ImportError, ValueError, TypeError) as e:
        logger.warning(f"Failed to get NEO4J_SYNC_INTERVAL, using default: {e}")
        interval_hours = 72

    try:
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                state = json.load(f)
                _raw = state.get("last_sync", "2000-01-01T00:00:00+00:00")
                last_sync = datetime.fromisoformat(_raw if "+" in _raw or "Z" in _raw else _raw + "+00:00")

                if datetime.now(timezone.utc) - last_sync < timedelta(hours=interval_hours):
                    logger.info(f"Skipping Neo4j sync - last sync was {last_sync}, interval is {interval_hours}h")
                    return False
    except (json.JSONDecodeError, OSError, ValueError) as e:
        logger.error(f"Corrupted sync state file ({state_file}): {e} — running sync to be safe")

    logger.info(f"Running Neo4j sync - interval {interval_hours}h has passed")
    return True


def run_neo4j_sync():
    """Run the Neo4j sync pipeline."""
    import json

    state_file = get_state_file()

    # Ensure metrics server is running
    ensure_metrics_server()

    try:
        import time

        start_time = time.time()
        task_start = start_time

        from run_misp_to_neo4j import MISPToNeo4jSync

        # Decide full vs incremental sync:
        # 1. First run ever (no state file) → full sync to catch all MISP history (e.g. after baseline)
        # 2. Airflow Variable NEO4J_FULL_SYNC="true" → operator-requested full sync (resets flag after)
        # 3. All other runs → incremental (last 3 days, efficient)
        is_first_run = not os.path.exists(state_file)
        force_full = False
        try:
            force_full = Variable.get("NEO4J_FULL_SYNC", "false").lower() == "true"
            if force_full:
                Variable.set("NEO4J_FULL_SYNC", "false")
                logger.info("NEO4J_FULL_SYNC flag consumed — running full sync")
        except Exception as e:
            logger.debug("Could not read NEO4J_FULL_SYNC Airflow Variable (non-Airflow context): %s", e)

        incremental = not (is_first_run or force_full)

        # Sync conflict guard: after a full/baseline sync, skip the next
        # incremental run to avoid immediately re-processing the same data.
        # Variable is imported at module scope (with 2.x/3.x compat shim).
        if incremental:
            try:
                skip = Variable.get("SKIP_NEXT_NEO4J_SYNC", "false").lower() == "true"
                if skip:
                    Variable.set("SKIP_NEXT_NEO4J_SYNC", "false")
                    logger.info("SKIP_NEXT_NEO4J_SYNC was set — skipping this incremental sync (not a failure)")
                    return  # Task completes as "success" — skip is intentional (post-baseline cooldown)
            except Exception as e:
                logger.debug("Could not check SKIP_NEXT_NEO4J_SYNC Variable: %s", e)

        if is_first_run:
            logger.info("First sync run detected — running full sync to load all MISP history")
        elif not incremental:
            logger.info("Full sync requested via NEO4J_FULL_SYNC variable")
        else:
            logger.info("Running incremental sync (last 3 days)")

        sync = MISPToNeo4jSync()
        success = sync.run(incremental=incremental)

        if success:
            duration = time.time() - start_time
            record_neo4j_sync_duration(duration)

            # Record enhanced metrics
            if METRICS_SERVER_AVAILABLE:
                record_neo4j_sync(
                    node_counts={
                        "Indicator": getattr(sync, "indicator_count", 0),
                        "Threat": getattr(sync, "threat_count", 0),
                        "Sector": getattr(sync, "sector_count", 0),
                        "Country": getattr(sync, "country_count", 0),
                    },
                    duration=duration,
                )
                record_task_duration("run_neo4j_sync", "edgeguard_pipeline", time.time() - task_start)

            # After a full/baseline sync, tell the next incremental run to skip
            # (Variable is imported at module scope).
            if not incremental:
                try:
                    Variable.set("SKIP_NEXT_NEO4J_SYNC", "true")
                    logger.info("Set SKIP_NEXT_NEO4J_SYNC=true after full sync")
                except Exception as e:
                    logger.debug("Could not set SKIP_NEXT_NEO4J_SYNC Variable: %s", e)

            try:
                with open(state_file, "w") as f:
                    json.dump({"last_sync": datetime.now(timezone.utc).isoformat()}, f)
                logger.info("Neo4j sync state persisted to %s", state_file)
            except OSError as e:
                logger.error(
                    "Failed to write sync state file %s: %s — sync succeeded but 'last sync' will show stale",
                    state_file,
                    e,
                )
            logger.info("Neo4j sync completed successfully")
            record_dag_run("edgeguard_pipeline", "success")
        else:
            detail = (
                getattr(sync, "_last_sync_failure_reason", None)
                or "see task log (MISP/Neo4j preflight, APOC, or merge errors)"
            )
            logger.error("Neo4j sync failed — %s", detail)
            record_dag_run("edgeguard_pipeline", "failure")
            if METRICS_SERVER_AVAILABLE:
                record_pipeline_error("neo4j_sync", "SyncFailed", "neo4j")
            raise AirflowException(f"Neo4j sync failed: {detail}")

    except AirflowException:
        raise
    except Exception as e:
        logger.error(f"Neo4j sync error: {e}")
        record_error("neo4j_sync", type(e).__name__)
        if METRICS_SERVER_AVAILABLE:
            record_pipeline_error("neo4j_sync", type(e).__name__, "neo4j")
        raise


# ================================================================================
#  MAIN DAG DEFINITION - High Frequency (Every 30 min, OTX ONLY)
#
#  Only the OTX collector (high_freq_group) runs here.  All other collectors
#  run in dedicated DAGs at their correct rates:
#    edgeguard_medium_freq  → CISA, VirusTotal  (every 4 h)
#    edgeguard_low_freq     → NVD               (every 8 h)
#    edgeguard_daily        → MITRE, AbuseIPDB, ThreatFox, URLhaus,
#                             CyberCure, Feodo, SSLBlacklist  (daily @ 02:00)
#    edgeguard_neo4j_sync   → MISP → Neo4j      (every 3 days @ 03:00)
#
#  Having medium/low/daily task groups inside this DAG caused every API to
#  be called every 30 minutes, immediately exhausting rate limits.
# ================================================================================

dag = DAG(
    "edgeguard_pipeline",
    default_args=default_args,
    description="EdgeGuard High-Frequency Pipeline — OTX only (every 30 min)",
    schedule="*/30 * * * *",
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,  # Prevent pile-up if a run is slow
    dagrun_timeout=timedelta(hours=5, minutes=30),  # Worst-case: 4h25m (OTX retries) + buffer
    tags=["threat-intel", "edgeguard", "misp", "high-frequency"],
)

# Task: Check Docker containers
check_containers = BashOperator(
    task_id="check_containers",
    bash_command="""
        echo "Checking Docker containers..."
        docker ps --filter "name=edgeguard" --filter "name=misp" --format "{{.Names}}: {{.Status}}" 2>/dev/null || echo "Docker check skipped"
        echo "Done checking containers"
    """,
    execution_timeout=timedelta(minutes=5),
    dag=dag,
)

# Task: MISP preflight (PythonOperator — fails in one attempt; no 5–10 min sensor spin)
misp_health_check = PythonOperator(
    task_id="misp_health_check",
    python_callable=assert_misp_preflight,
    execution_timeout=timedelta(minutes=5),
    dag=dag,
)

# ================================================================================
#  TASK GROUP: High Frequency Collectors (Every 30 min — OTX ONLY)
#
#  Medium/low/daily collectors were previously duplicated here, causing them
#  to run every 30 min and blow through API rate limits.  They now live
#  exclusively in their dedicated DAGs (see below).
# ================================================================================

with TaskGroup("high_frequency_collectors", dag=dag) as high_freq_group:
    collect_otx = PythonOperator(
        task_id="collect_otx",
        python_callable=run_otx_collection,
        execution_timeout=timedelta(hours=1),
        dag=dag,
    )

# Task: Log final summary (OTX only)
log_summary = BashOperator(
    task_id="log_summary",
    bash_command="""
        echo "=============================================="
        echo "EdgeGuard High-Freq Run Complete - $(date)"
        echo "  - OTX collection done"
        echo "  (CISA/VT/NVD/daily collectors run in"
        echo "   their own dedicated DAGs)"
        echo "=============================================="
    """,
    execution_timeout=timedelta(minutes=5),
    dag=dag,
)

# ================================================================================
#  TASK DEPENDENCIES (main DAG — OTX pipeline only)
# ================================================================================

check_containers >> misp_health_check >> high_freq_group >> log_summary


# ================================================================================
#  ADDITIONAL DAGS FOR SPECIFIC SCHEDULES
# ================================================================================

# ================================================================================
#  DAG: Medium Frequency (Every 4 hours) - CISA & VirusTotal
# ================================================================================

medium_freq_dag = DAG(
    "edgeguard_medium_freq",
    default_args=default_args,
    description="EdgeGuard Medium Frequency Collectors (CISA, VirusTotal)",
    schedule="0 */4 * * *",  # Every 4 hours
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=5),  # Worst-case: 4h (CISA/VT retries) + buffer
    tags=["threat-intel", "edgeguard", "misp", "medium-frequency"],
)

misp_health_medium = PythonOperator(
    task_id="misp_health_check",
    python_callable=assert_misp_preflight,
    execution_timeout=timedelta(minutes=5),
    dag=medium_freq_dag,
)

collect_cisa_medium = PythonOperator(
    task_id="collect_cisa",
    python_callable=run_cisa_collection,
    execution_timeout=timedelta(hours=1),
    dag=medium_freq_dag,
)

collect_vt_medium = PythonOperator(
    task_id="collect_virustotal",
    python_callable=run_vt_collection,
    execution_timeout=timedelta(hours=1),
    dag=medium_freq_dag,
)

log_medium_summary = BashOperator(
    task_id="log_summary",
    bash_command='echo "Medium Frequency Collectors Complete - $(date)"',
    execution_timeout=timedelta(minutes=5),
    trigger_rule=TriggerRule.ALL_DONE,
    dag=medium_freq_dag,
)

misp_health_medium >> [collect_cisa_medium, collect_vt_medium] >> log_medium_summary


# ================================================================================
#  DAG: Low Frequency (Every 8 hours) - NVD
# ================================================================================

low_freq_dag = DAG(
    "edgeguard_low_freq",
    default_args=default_args,
    description="EdgeGuard Low Frequency Collectors (NVD)",
    schedule="0 */8 * * *",  # Every 8 hours
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=8, minutes=30),  # Worst-case: 7h (NVD retries) + buffer
    tags=["threat-intel", "edgeguard", "misp", "low-frequency"],
)

misp_health_low = PythonOperator(
    task_id="misp_health_check",
    python_callable=assert_misp_preflight,
    execution_timeout=timedelta(minutes=5),
    dag=low_freq_dag,
)

collect_nvd_low = PythonOperator(
    task_id="collect_nvd",
    python_callable=run_nvd_collection,
    execution_timeout=timedelta(hours=2),
    dag=low_freq_dag,
)

log_low_summary = BashOperator(
    task_id="log_summary",
    bash_command='echo "Low Frequency Collectors Complete - $(date)"',
    execution_timeout=timedelta(minutes=5),
    dag=low_freq_dag,
)

misp_health_low >> collect_nvd_low >> log_low_summary


# ================================================================================
#  DAG: Daily Collectors (Once per day)
# ================================================================================

daily_dag = DAG(
    "edgeguard_daily",
    default_args=default_args,
    description="EdgeGuard Daily Collectors (MITRE, AbuseIPDB, ThreatFox, etc.)",
    schedule="0 2 * * *",  # Daily at 2 AM
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=8, minutes=30),  # Worst-case: 7h (7 collectors parallel + retries) + buffer
    tags=["threat-intel", "edgeguard", "misp", "daily"],
)

misp_health_daily = PythonOperator(
    task_id="misp_health_check",
    python_callable=assert_misp_preflight,
    execution_timeout=timedelta(minutes=5),
    dag=daily_dag,
)

collect_mitre_daily = PythonOperator(
    task_id="collect_mitre",
    python_callable=run_mitre_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_abuseipdb_daily = PythonOperator(
    task_id="collect_abuseipdb",
    python_callable=run_abuseipdb_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_threatfox_daily = PythonOperator(
    task_id="collect_threatfox",
    python_callable=run_threatfox_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_urlhaus_daily = PythonOperator(
    task_id="collect_urlhaus",
    python_callable=run_urlhaus_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_cybercure_daily = PythonOperator(
    task_id="collect_cybercure",
    python_callable=run_cybercure_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_feodo_daily = PythonOperator(
    task_id="collect_feodo",
    python_callable=run_feodo_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

collect_sslblacklist_daily = PythonOperator(
    task_id="collect_sslblacklist",
    python_callable=run_sslblacklist_collection,
    execution_timeout=timedelta(hours=2),
    dag=daily_dag,
)

log_daily_summary = BashOperator(
    task_id="log_summary",
    bash_command="""
        echo "Daily Collectors Complete - $(date)"
        echo "  - MITRE ATT&CK"
        echo "  - AbuseIPDB"
        echo "  - ThreatFox"
        echo "  - URLhaus"
        echo "  - CyberCure"
        echo "  - Feodo Tracker"
        echo "  - SSL Blacklist"
    """,
    execution_timeout=timedelta(minutes=5),
    trigger_rule=TriggerRule.ALL_DONE,
    dag=daily_dag,
)

(
    misp_health_daily
    >> [
        collect_mitre_daily,
        collect_abuseipdb_daily,
        collect_threatfox_daily,
        collect_urlhaus_daily,
        collect_cybercure_daily,
        collect_feodo_daily,
        collect_sslblacklist_daily,
    ]
    >> log_daily_summary
)


# ================================================================================
#  DAG: Neo4j Sync (Every 72 hours / configurable)
# ================================================================================

neo4j_sync_dag = DAG(
    "edgeguard_neo4j_sync",
    default_args=default_args,
    description="EdgeGuard MISP to Neo4j Synchronization",
    schedule="0 3 */3 * *",  # Every 3 days at 3 AM
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,
    dagrun_timeout=timedelta(hours=22),  # Worst-case: 18h (full sync + rels + enrich, all with retries)
    tags=["threat-intel", "edgeguard", "neo4j", "sync"],
)

check_neo4j_sync_needed = ShortCircuitOperator(
    task_id="check_sync_needed",
    python_callable=should_run_neo4j_sync,
    execution_timeout=timedelta(minutes=2),
    dag=neo4j_sync_dag,
)


def assert_neo4j_preflight(**kwargs):
    """Verify Neo4j is reachable and healthy before sync."""
    from neo4j_client import Neo4jClient

    client = Neo4jClient()
    try:
        try:
            connected = client.connect()
        except Exception as e:
            raise AirflowException(
                f"Neo4j preflight FAILED — connect raised after retries: {e}. "
                "Check: docker compose ps neo4j / docker compose logs neo4j"
            ) from e
        if not connected:
            raise AirflowException(
                "Neo4j preflight FAILED — cannot connect. Check: docker compose ps neo4j / docker compose logs neo4j"
            )
        try:
            result = client.run("RETURN 1 AS ok")
        except Exception as e:
            raise AirflowException(f"Neo4j connected but health query raised: {e}") from e
        if not result:
            raise AirflowException("Neo4j connected but query returned empty")
        logger.info("Neo4j preflight: connected and healthy")
    finally:
        client.close()


neo4j_preflight_task = PythonOperator(
    task_id="neo4j_health_check",
    python_callable=assert_neo4j_preflight,
    execution_timeout=timedelta(minutes=2),
    dag=neo4j_sync_dag,
)

run_neo4j_sync_task = PythonOperator(
    task_id="run_neo4j_sync",
    python_callable=run_neo4j_sync,
    execution_timeout=timedelta(hours=4),
    dag=neo4j_sync_dag,
)

check_neo4j_quality_task = BashOperator(
    task_id="check_neo4j_quality",
    bash_command="""
        echo "Neo4j Sync Complete - $(date)"
        NEO4J_USER="${NEO4J_USER:-neo4j}"
        NEO4J_PWD="${NEO4J_PASSWORD:-}"
        NEO4J_HTTP="${NEO4J_HTTP:-http://localhost:7474}"
        if [ -n "$NEO4J_PWD" ]; then
            curl -s -u "${NEO4J_USER}:${NEO4J_PWD}" "${NEO4J_HTTP}/db/neo4j/tx/commit" \
                -H "Content-Type: application/json" \
                -d '{"statements": [{"statement": "MATCH (n) WHERE n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR n:ThreatActor OR n:Technique OR n:Tactic OR n:Campaign RETURN labels(n)[0] as type, count(*) as cnt ORDER BY cnt DESC"}]}' 2>/dev/null | \
                python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'{r[\\"row\\"][0]}: {r[\\"row\\"][1]}') for r in d.get('results',[{}])[0].get('data',[])]" || echo "Quality check skipped"
        else
            echo "Quality check skipped (NEO4J_PASSWORD not set)"
        fi
    """,
    execution_timeout=timedelta(minutes=15),
    dag=neo4j_sync_dag,
)

# ================================================================================
#  POST-SYNC ENRICHMENT TASKS — added to the Neo4j sync DAG
#  Runs after every MISP→Neo4j sync to enrich and maintain graph quality.
#
#  Order matters:
#    1. build_relationships  — link IOCs to malware/CVEs (needs fresh data)
#    2. build_campaigns      — materialise Campaign nodes (needs relationships)
#    3. calibrate_confidence — adjust INDICATES scores by event size
#    4. decay_ioc_confidence — retire/reduce stale indicators (idempotent last step)
# ================================================================================


def run_build_relationships(**context):
    """Run build_relationships.py after sync to create/refresh graph links."""
    import subprocess

    result = subprocess.run(
        ["python3", os.path.join(BASE_DIR, "src", "build_relationships.py")],
        capture_output=True,
        text=True,
        timeout=18000,  # 5 hours — aligned with execution_timeout (bumped from 3h
        # after baseline re-runs hit the ceiling on the merged #20/#22/#24 scope)
    )
    if result.returncode != 0:
        logger.error(f"build_relationships failed:\n{result.stderr}")
        raise AirflowException(f"build_relationships.py exited with code {result.returncode}")
    logger.info(result.stdout)


def run_enrichment_jobs(**context):
    """Run IOC decay, Campaign builder, and confidence calibration after sync."""
    from enrichment_jobs import run_all_enrichment_jobs
    from neo4j_client import Neo4jClient

    client = Neo4jClient()
    try:
        client.connect()
        summary = run_all_enrichment_jobs(client)
        logger.info(f"Enrichment summary: {summary}")
    except Exception as e:
        logger.error(f"Enrichment failed: {e}")
        raise AirflowException(f"Enrichment failed: {e}")
    finally:
        client.close()


build_relationships_task = PythonOperator(
    task_id="build_relationships",
    python_callable=run_build_relationships,
    execution_timeout=timedelta(hours=5),
    dag=neo4j_sync_dag,
)

enrichment_task = PythonOperator(
    task_id="run_enrichment_jobs",
    python_callable=run_enrichment_jobs,
    execution_timeout=timedelta(hours=5),
    dag=neo4j_sync_dag,
)

# Updated dependency chain: check interval → Neo4j preflight → sync → build rels → enrich → quality
(
    check_neo4j_sync_needed
    >> neo4j_preflight_task
    >> run_neo4j_sync_task
    >> build_relationships_task
    >> enrichment_task
    >> check_neo4j_quality_task
)


# ================================================================================
#  DAG: Baseline (Manual trigger only — run ONCE before going to production)
#
#  This DAG performs a deep historical collection from all sources using
#  extended lookback windows, followed by a full Neo4j sync and enrichment.
#
#  HOW TO USE:
#    1. Run this DAG once via the Airflow UI (trigger manually)
#    2. It will collect all available history from each source
#    3. After completion, the incremental cron DAGs take over
#
#  DO NOT schedule this DAG — it is intentionally schedule=None (Airflow 3.x API;
#  the 2.x kwarg schedule_interval= was removed in 3.x).
# ================================================================================

baseline_dag = DAG(
    "edgeguard_baseline",
    default_args={**default_args, "retries": 1},  # fewer retries — slow is expected
    description="EdgeGuard Baseline — full historical collection (manual trigger only)",
    schedule=None,  # MANUAL TRIGGER ONLY
    start_date=_DAG_START_DATE,
    catchup=False,
    max_active_runs=1,  # Only one baseline at a time
    dagrun_timeout=timedelta(hours=32),  # Worst-case: 26h (full collection + sync + retries) + buffer
    is_paused_upon_creation=False,  # Must be unpaused so manual triggers execute immediately
    tags=["threat-intel", "edgeguard", "baseline", "manual"],
)


def get_baseline_config(context=None) -> tuple:
    """
    Read baseline collection settings from Airflow Variables, then apply optional
    environment overrides (handy for Docker Compose / .env smoke tests).

    Airflow Variables
    -----------------
    BASELINE_COLLECTION_LIMIT : int  (default 0)
        0 or absent  → None  (unlimited)
        N > 0        → cap at N items per source

    BASELINE_DAYS : int  (default 730)
        History window for NVD, OTX, etc.

    Environment overrides (optional, applied after Variables)
    ---------------------------------------------------------
    EDGEGUARD_BASELINE_DAYS
        If set and non-empty, overrides ``BASELINE_DAYS`` (e.g. ``7`` for a quick test).
    EDGEGUARD_BASELINE_COLLECTION_LIMIT
        If set and non-empty, overrides ``BASELINE_COLLECTION_LIMIT`` (e.g. ``1000``).

    Returns
    -------
    (limit, baseline_days) where limit is None (unlimited) or an int.
    """
    limit = 0
    baseline_days = 730
    try:
        raw = Variable.get("BASELINE_COLLECTION_LIMIT", "0")
        limit = int(raw)
    except Exception as e:
        logger.debug("Could not read BASELINE_COLLECTION_LIMIT Variable: %s", e)
        limit = 0

    try:
        baseline_days = int(Variable.get("BASELINE_DAYS", "730"))
    except Exception as e:
        logger.debug("Could not read BASELINE_DAYS Variable: %s", e)
        baseline_days = 730

    env_limit = os.environ.get("EDGEGUARD_BASELINE_COLLECTION_LIMIT", "").strip()
    if env_limit:
        try:
            limit = int(env_limit)
            logger.info(f"[BASELINE] EDGEGUARD_BASELINE_COLLECTION_LIMIT override → {limit}")
        except ValueError:
            logger.warning(f"[BASELINE] Ignoring invalid EDGEGUARD_BASELINE_COLLECTION_LIMIT={env_limit!r}")

    env_days = os.environ.get("EDGEGUARD_BASELINE_DAYS", "").strip()
    if env_days:
        try:
            baseline_days = int(env_days)
            logger.info(f"[BASELINE] EDGEGUARD_BASELINE_DAYS override → {baseline_days}")
        except ValueError:
            logger.warning(f"[BASELINE] Ignoring invalid EDGEGUARD_BASELINE_DAYS={env_days!r}")

    # DAG trigger conf override (highest priority — from Airflow UI or API)
    if context:
        dag_run = context.get("dag_run")
        dag_conf = getattr(dag_run, "conf", None) or {} if dag_run else {}
        if "baseline_days" in dag_conf:
            try:
                baseline_days = int(dag_conf["baseline_days"])
                logger.info(f"[BASELINE] dag_run.conf override → baseline_days={baseline_days}")
            except (ValueError, TypeError):
                logger.warning(f"[BASELINE] Invalid dag_run.conf baseline_days={dag_conf['baseline_days']!r}")
        if "baseline_collection_limit" in dag_conf:
            try:
                limit = int(dag_conf["baseline_collection_limit"])
                logger.info(f"[BASELINE] dag_run.conf override → limit={limit}")
            except (ValueError, TypeError):
                logger.warning(
                    f"[BASELINE] Invalid dag_run.conf baseline_collection_limit={dag_conf['baseline_collection_limit']!r}"
                )

    # 0 or negative → no cap (pass None to collectors)
    effective_limit = None if limit <= 0 else limit
    logger.info(f"[BASELINE] Config — limit={effective_limit or 'unlimited'}, baseline_days={baseline_days}")
    return effective_limit, baseline_days


def run_baseline_collector(collector_name: str, collector_class, context=None, **kwargs):
    """
    Run a single collector in baseline mode.

    Reads BASELINE_COLLECTION_LIMIT and BASELINE_DAYS from (in priority order):
    1. dag_run.conf (from Airflow UI trigger or API)
    2. Environment variables (EDGEGUARD_BASELINE_DAYS, etc.)
    3. Airflow Variables (BASELINE_DAYS, etc.)
    4. Defaults (730 days, unlimited items)

    Parameters
    ----------
    collector_name  : label for logging / metrics
    collector_class : the collector class to instantiate
    context         : Airflow task context (for dag_run.conf overrides)
    **kwargs        : passed through to the collector constructor
    """
    from collectors.misp_writer import MISPWriter

    limit, baseline_days = get_baseline_config(context=context)
    writer = MISPWriter()
    logger.info(f"[BASELINE] Starting {collector_name} — limit={limit or 'unlimited'}, baseline_days={baseline_days}")

    return run_collector_with_metrics(
        collector_name,
        collector_class,
        writer,
        limit=limit,
        baseline=True,
        baseline_days=baseline_days,
        **kwargs,
    )


def run_baseline_otx(**context):
    from collectors.otx_collector import OTXCollector

    return run_baseline_collector("otx", OTXCollector, context=context)


def run_baseline_nvd(**context):
    from collectors.nvd_collector import NVDCollector

    return run_baseline_collector("nvd", NVDCollector, context=context)


def run_baseline_cisa(**context):
    from collectors.cisa_collector import CISACollector

    return run_baseline_collector("cisa", CISACollector, context=context)


def run_baseline_mitre(**context):
    from collectors.mitre_collector import MITRECollector

    return run_baseline_collector("mitre", MITRECollector, context=context)


def run_baseline_abuseipdb(**context):
    from collectors.abuseipdb_collector import AbuseIPDBCollector

    return run_baseline_collector("abuseipdb", AbuseIPDBCollector, context=context)


def run_baseline_threatfox(**context):
    from collectors.global_feed_collector import ThreatFoxCollector

    return run_baseline_collector("threatfox", ThreatFoxCollector, context=context)


def run_baseline_urlhaus(**context):
    from collectors.global_feed_collector import URLhausCollector

    return run_baseline_collector("urlhaus", URLhausCollector, context=context)


def run_baseline_cybercure(**context):
    from collectors.global_feed_collector import CyberCureCollector

    return run_baseline_collector("cybercure", CyberCureCollector, context=context)


def run_baseline_feodo(**context):
    from collectors.finance_feed_collector import FeodoCollector

    return run_baseline_collector("feodo", FeodoCollector, context=context)


def run_baseline_sslblacklist(**context):
    from collectors.finance_feed_collector import SSLBlacklistCollector

    return run_baseline_collector("sslbl", SSLBlacklistCollector, context=context)


def run_baseline_full_sync(**context):
    """Run a FULL (non-incremental) MISP→Neo4j sync after baseline collection."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    logger.info("[BASELINE] Starting full MISP→Neo4j sync (all history)")
    sync = MISPToNeo4jSync()
    success = sync.run(incremental=False)
    if not success:
        detail = (
            getattr(sync, "_last_sync_failure_reason", None)
            or "see task log (MISP/Neo4j preflight, APOC, or merge errors)"
        )
        raise AirflowException(f"Baseline full MISP→Neo4j sync failed: {detail}")
    logger.info("[BASELINE] Full sync complete")


def run_baseline_enrichment(**context):
    """Run all enrichment jobs after baseline sync."""
    from enrichment_jobs import run_all_enrichment_jobs
    from neo4j_client import Neo4jClient

    client = Neo4jClient()
    try:
        client.connect()
        summary = run_all_enrichment_jobs(client)
        logger.info(f"[BASELINE] Enrichment complete: {summary}")
    except Exception as e:
        logger.error(f"[BASELINE] Enrichment failed: {e}")
        raise AirflowException(f"Baseline enrichment failed: {e}")
    finally:
        client.close()


# ---- Baseline tasks ----

baseline_misp_health = PythonOperator(
    task_id="misp_health_check",
    python_callable=assert_misp_preflight,
    execution_timeout=timedelta(minutes=5),
    dag=baseline_dag,
)


def _baseline_start_summary(**context):
    """Print baseline config at run-time so it shows clearly in the Airflow log.

    Always clears baseline checkpoints (page counters) so collectors start
    from page 1. Incremental state (OTX modified_since cursor, MITRE ETag)
    is preserved by default — pass ``clear_checkpoints: "all"`` in
    dag_run.conf to wipe those too.
    """
    limit, baseline_days = get_baseline_config(context)

    # Clear baseline checkpoints so collectors start fresh (page 1, not stale page 80)
    from baseline_checkpoint import clear_checkpoint

    conf = context.get("dag_run").conf if context.get("dag_run") else {}
    include_incremental = str(conf.get("clear_checkpoints", "")).lower() == "all"
    clear_checkpoint(include_incremental=include_incremental)
    if include_incremental:
        logger.info("[BASELINE] Cleared ALL checkpoints (baseline + incremental state)")
    else:
        logger.info("[BASELINE] Cleared baseline checkpoints (incremental cursors preserved)")

    logger.info("=" * 55)
    logger.info("EdgeGuard BASELINE Collection Started")
    logger.info(f"  Started at    : {datetime.now(timezone.utc).isoformat()} UTC")
    logger.info(f"  Item limit    : {limit or 'UNLIMITED (collecting everything)'}")
    logger.info(f"  History window: {baseline_days} days")
    if baseline_days < 365:
        logger.warning(
            "  WARNING: baseline_days=%s is below recommended 730. "
            "This will collect significantly fewer items. "
            "Check EDGEGUARD_BASELINE_DAYS env var and BASELINE_DAYS Airflow Variable.",
            baseline_days,
        )
    logger.info("")
    logger.info("To change before triggering:")
    logger.info("  Airflow UI → Admin → Variables")
    logger.info("  BASELINE_COLLECTION_LIMIT = 0   (unlimited) or N")
    logger.info("  BASELINE_DAYS             = 730 (2 years, recommended)")
    logger.info("  Or set env on Airflow container (overrides Variables):")
    logger.info("  EDGEGUARD_BASELINE_DAYS=7  EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000")
    logger.info('  To wipe incremental cursors too: {"clear_checkpoints": "all"}')
    logger.info("=" * 55)


baseline_start = PythonOperator(
    task_id="baseline_start",
    python_callable=_baseline_start_summary,
    execution_timeout=timedelta(minutes=2),
    dag=baseline_dag,
)

# Tier 1 — Core intelligence (rate-limited APIs). ALL_DONE: one failure doesn't block others.
with TaskGroup("tier1_core", dag=baseline_dag, default_args={"trigger_rule": TriggerRule.ALL_DONE}) as baseline_tier1:
    bl_otx = PythonOperator(
        task_id="collect_otx",
        python_callable=run_baseline_otx,
        execution_timeout=timedelta(hours=5),
        dag=baseline_dag,
    )
    bl_nvd = PythonOperator(
        task_id="collect_nvd",
        python_callable=run_baseline_nvd,
        execution_timeout=timedelta(hours=5),
        dag=baseline_dag,
    )
    bl_cisa = PythonOperator(
        task_id="collect_cisa",
        python_callable=run_baseline_cisa,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_mitre = PythonOperator(
        task_id="collect_mitre",
        python_callable=run_baseline_mitre,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )

# Tier 2 — Reputation & bulk feeds (parallel after Tier 1).
# ALL_DONE: Tier 1 tasks have no data dependency on each other; OTX (or NVD) failure must not
# skip Tier 2 as upstream_failed (see baseline DAG notes in docs/AIRFLOW_DAGS.md).
with TaskGroup(
    "tier2_feeds",
    dag=baseline_dag,
    default_args={"trigger_rule": TriggerRule.ALL_DONE},
) as baseline_tier2:
    bl_abuseipdb = PythonOperator(
        task_id="collect_abuseipdb",
        python_callable=run_baseline_abuseipdb,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_threatfox = PythonOperator(
        task_id="collect_threatfox",
        python_callable=run_baseline_threatfox,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_urlhaus = PythonOperator(
        task_id="collect_urlhaus",
        python_callable=run_baseline_urlhaus,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_cybercure = PythonOperator(
        task_id="collect_cybercure",
        python_callable=run_baseline_cybercure,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_feodo = PythonOperator(
        task_id="collect_feodo",
        python_callable=run_baseline_feodo,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )
    bl_sslblacklist = PythonOperator(
        task_id="collect_sslblacklist",
        python_callable=run_baseline_sslblacklist,
        execution_timeout=timedelta(hours=2),
        dag=baseline_dag,
    )

baseline_full_sync_task = PythonOperator(
    task_id="full_neo4j_sync",
    python_callable=run_baseline_full_sync,
    execution_timeout=timedelta(hours=6),
    trigger_rule=TriggerRule.ALL_DONE,
    dag=baseline_dag,
)

baseline_build_rels_task = PythonOperator(
    task_id="build_relationships",
    python_callable=run_build_relationships,
    execution_timeout=timedelta(minutes=45),
    # PR #35: NONE_FAILED_MIN_ONE_SUCCESS — run if the upstream
    # full_neo4j_sync didn't crash (success OR skipped, but not failed).
    # Default ALL_SUCCESS would block this task even when the sync
    # succeeded but a sibling collector failed and somehow propagated
    # upstream_failed through the group boundary. NONE_FAILED_MIN_ONE_SUCCESS
    # is the safe choice: still respects real sync failures, but no
    # false-positive blocks from collector glitches.
    trigger_rule=TriggerRule.NONE_FAILED_MIN_ONE_SUCCESS,
    dag=baseline_dag,
)

baseline_enrichment_task = PythonOperator(
    task_id="run_enrichment_jobs",
    python_callable=run_baseline_enrichment,
    execution_timeout=timedelta(hours=5),
    # PR #35: same rationale as build_relationships above.
    trigger_rule=TriggerRule.NONE_FAILED_MIN_ONE_SUCCESS,
    dag=baseline_dag,
)

baseline_complete = BashOperator(
    task_id="baseline_complete",
    bash_command="""
        echo "=========================================="
        echo "EdgeGuard BASELINE Complete!"
        echo "Finished at: $(date)"
        echo ""
        echo "Next steps:"
        echo "  - Incremental cron DAGs are now active"
        echo "  - edgeguard_pipeline    runs every 30min (OTX)"
        echo "  - edgeguard_medium_freq runs every 4h   (CISA, VT)"
        echo "  - edgeguard_low_freq    runs every 8h   (NVD)"
        echo "  - edgeguard_daily       runs at 02:00   (all daily feeds)"
        echo "  - edgeguard_neo4j_sync  runs every 3d   (MISP→Neo4j+Enrich)"
        echo "=========================================="
    """,
    execution_timeout=timedelta(minutes=5),
    # PR #35: ALL_DONE — the "complete" marker should ALWAYS run so the
    # operator gets a clear "baseline finished" signal in the logs even
    # if some upstream task failed. Useful when scrolling through Airflow
    # logs to see "did the run terminate gracefully or hang?"
    trigger_rule=TriggerRule.ALL_DONE,
    dag=baseline_dag,
)

# Dependency chain:
# health → start → tier1 (parallel) → tier2 (parallel) → full_sync → build_rels → enrich → done
(
    baseline_misp_health
    >> baseline_start
    >> baseline_tier1
    >> baseline_tier2
    >> baseline_full_sync_task
    >> baseline_build_rels_task
    >> baseline_enrichment_task
    >> baseline_complete
)
