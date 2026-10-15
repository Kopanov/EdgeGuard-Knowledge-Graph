"""Airflow listener plugin: marks each DAG run in progress for Prometheus (2026-10).

``edgeguard_dag_run_in_progress_start_timestamp{dag_id}`` holds the start time of the DAG's run in
progress and 0 when no run is in progress; ``EdgeGuardDAGRunStuck`` (prometheus/alerts.yml) fires for
a run still marked longer than its ``dagrun_timeout`` plus 15 minutes.

The mark is kept by Airflow's DAG run listener hooks, not by DAG-level or task callbacks:

* the scheduler calls ``on_dag_run_running`` when it starts a run (a cleared run included, with its
  new ``start_date``) and ``on_dag_run_success`` / ``on_dag_run_failed`` when it ends one, also at the
  ``dagrun_timeout``. It calls them in the scheduling loop, in order, so the end of a run is written
  before the next run of the same DAG (``max_active_runs=1``) can start;
* the API server calls ``on_dag_run_success`` / ``on_dag_run_failed`` when a run's state is set by
  hand: "Mark run as failed / success" in the UI, ``PATCH /api/v2/dags/{dag_id}/dagRuns/{run_id}``
  and ``python src/edgeguard.py dag kill``. Airflow runs no DAG-level callback on that path.

The first 2026-10 design cleared the mark from DAG-level success and failure callbacks. Those miss
a manual state change, and the DAG processor runs them asynchronously, so a late callback of one run
could clear the mark of the next. A run that is deleted fires no hook: its mark stays until the DAG's
next run starts (docs/PROMETHEUS_SETUP.md gives the command that clears it at once).

The mark is written only in prometheus_client's multi-process mode (``PROMETHEUS_MULTIPROC_DIR``, set
on the ``airflow`` service by docker-compose.yml, which also mounts this directory as the Airflow
plugins folder): the scheduler and the API server are other processes than the ``metrics`` service
that serves the value, and ``mostrecent`` reports the newest write of any process. A hook never
raises: a metrics failure must not disturb scheduling or a state change.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Optional

from airflow.listeners import hookimpl
from airflow.plugins_manager import AirflowPlugin

logger = logging.getLogger(__name__)

# src/ next to this directory: the repository layout, for an installation without PYTHONPATH=src
# (docker-compose.yml sets PYTHONPATH=/opt/airflow/src, which is the same directory).
_SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def _run_start_gauge() -> Optional[Any]:
    """``metrics_server.DAG_RUN_START``, or None outside the multi-process mode.

    Imported on first use, so loading the plugin costs nothing in a process that never fires a DAG
    run hook (a task process loads plugins too). The gauge object is the one the DAG module imports,
    so a process that has both never registers the series twice.
    """
    if not (os.getenv("PROMETHEUS_MULTIPROC_DIR") or "").strip():
        return None
    if os.path.isdir(_SRC_DIR) and _SRC_DIR not in sys.path:
        sys.path.append(_SRC_DIR)
    from metrics_server import DAG_RUN_START

    return DAG_RUN_START


def _set_mark(dag_run: Any, value: float) -> None:
    dag_id = getattr(dag_run, "dag_id", None) or "unknown"
    try:
        gauge = _run_start_gauge()
        if gauge is not None:
            gauge.labels(dag_id=dag_id).set(value)
    except Exception as e:  # noqa: BLE001 - a listener must never fail the scheduler or the API call
        logger.warning("DAG run in-progress mark of %s not written: %s", dag_id, e)


class DagRunStateListener:
    """The DAG run hooks (pluggy calls the bound methods with ``dag_run`` and ``msg``)."""

    @hookimpl
    def on_dag_run_running(self, dag_run: Any, msg: str) -> None:
        """The run started (or a cleared run restarted): mark it in progress from its start time."""
        started = getattr(dag_run, "start_date", None)
        _set_mark(dag_run, started.timestamp() if started is not None else time.time())

    @hookimpl
    def on_dag_run_success(self, dag_run: Any, msg: str) -> None:
        """The run ended successfully, through the scheduler or a manual state change."""
        _set_mark(dag_run, 0)

    @hookimpl
    def on_dag_run_failed(self, dag_run: Any, msg: str) -> None:
        """The run failed, timed out or was marked failed by hand."""
        _set_mark(dag_run, 0)


class EdgeGuardDagRunStatePlugin(AirflowPlugin):
    """Registers the DAG run hooks with Airflow's listener manager."""

    name = "edgeguard_dag_run_state"
    listeners = [DagRunStateListener()]
