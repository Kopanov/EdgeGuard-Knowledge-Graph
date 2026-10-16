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
next run starts (docs/PROMETHEUS_SETUP.md gives the command that clears it at once). When a run
ends while another run of the same DAG is still running (an older run marked failed by hand), the
mark keeps that run's start time instead of being cleared. The end hooks read the DAG's running runs
in a session of their own: without one, ``DagRun.find()`` used the scheduling loop's session and
stopped the scheduler at the end of every run (see ``_other_running_start``).

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
from airflow.utils.session import create_session

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


def _set_mark(dag_id: str, value: float) -> None:
    try:
        gauge = _run_start_gauge()
        if gauge is not None:
            gauge.labels(dag_id=dag_id).set(value)
    except Exception as e:  # noqa: BLE001 - a listener must never fail the scheduler or the API call
        logger.warning("DAG run in-progress mark of %s not written: %s", dag_id, e)


def _other_running_start(dag_id: Optional[str], own: Optional[str]) -> Optional[float]:
    """The start time of the earliest other run of the same DAG still running, or None (2026-10).

    The run whose end a hook reports need not be the one in progress: marking an older run failed in
    the UI fires the same hook while the current run goes on. Cleared then, the mark would hide that
    run from ``EdgeGuardDAGRunStuck``. Read from Airflow's metadata database; a failed read clears the
    mark, as before.

    The read uses a non-scoped session of its own. Without a session, ``DagRun.find()`` uses
    Airflow's scoped session, which in the scheduler is the scheduling loop's own session. The commit
    that ``create_session()`` attempts on exit is refused there by the scheduler's commit guard
    (``prohibit_commit``: "UNEXPECTED COMMIT"), so the session is rolled back and closed: the
    ``DagRun`` the scheduler is finishing loses its uncommitted end state and is expired and
    detached, and the scheduler's next read of it (``update_state`` reading ``_state``) raises
    ``DetachedInstanceError``, which stops the scheduler. The run stays running across restarts.

    The separate session sees committed state only, which relies on ``max_active_runs=1``: two
    running runs of one DAG never end in one scheduler loop.
    """
    if not dag_id:
        return None
    try:
        from airflow.models.dagrun import DagRun
        from airflow.utils.state import DagRunState

        with create_session(scoped=False) as session:
            runs = DagRun.find(dag_id=dag_id, state=DagRunState.RUNNING, session=session)
            starts = [
                r.start_date.timestamp()
                for r in runs or []
                if getattr(r, "run_id", None) != own and getattr(r, "start_date", None) is not None
            ]
    except Exception as e:  # noqa: BLE001 - a listener must never fail the scheduler or the API call
        logger.warning("Running runs of %s not read; its in-progress mark is cleared: %s", dag_id, e)
        return None
    return min(starts) if starts else None


def _end_mark(dag_run: Any) -> None:
    """A run ended: the mark follows another run of the DAG still running, else it is cleared."""
    dag_id = getattr(dag_run, "dag_id", None)
    other = _other_running_start(dag_id, getattr(dag_run, "run_id", None))
    _set_mark(dag_id or "unknown", other if other is not None else 0)


class DagRunStateListener:
    """The DAG run hooks (pluggy calls the bound methods with ``dag_run`` and ``msg``)."""

    @hookimpl
    def on_dag_run_running(self, dag_run: Any, msg: str) -> None:
        """The run started (or a cleared run restarted): mark it in progress from its start time."""
        started = getattr(dag_run, "start_date", None)
        _set_mark(
            getattr(dag_run, "dag_id", None) or "unknown", started.timestamp() if started is not None else time.time()
        )

    @hookimpl
    def on_dag_run_success(self, dag_run: Any, msg: str) -> None:
        """The run ended successfully, through the scheduler or a manual state change."""
        _end_mark(dag_run)

    @hookimpl
    def on_dag_run_failed(self, dag_run: Any, msg: str) -> None:
        """The run failed, timed out or was marked failed by hand."""
        _end_mark(dag_run)


class EdgeGuardDagRunStatePlugin(AirflowPlugin):
    """Registers the DAG run hooks with Airflow's listener manager."""

    name = "edgeguard_dag_run_state"
    listeners = [DagRunStateListener()]
