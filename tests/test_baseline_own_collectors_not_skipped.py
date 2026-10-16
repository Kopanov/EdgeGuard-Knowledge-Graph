"""The baseline DAG's own collectors must not be skipped by the lock their run holds.

Since the ``edgeguard_baseline`` DAG takes the baseline lock itself (task
``baseline_acquire_lock``), the collector wrapper's "a baseline is running — stand down"
check also saw the sentinel written by the collector's own DAG run. Every collector task of
the baseline returned a green ``baseline_in_progress`` skip in under a second and the run,
which had already wiped the stores in fresh mode, collected nothing.

These tests execute the real DAG callables (``run_baseline_collector`` →
``run_collector_with_metrics``) against a real sentinel file; only the Airflow REST lookup,
the MISP writer and the metrics helpers are replaced.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

import airflow_client
import baseline_lock

RUN = {"dag_id": "edgeguard_baseline", "run_id": "manual__2026-10-13T08:00:00+00:00"}
OTHER_RUN = {"dag_id": "edgeguard_baseline", "run_id": "manual__2026-10-13T09:30:00+00:00"}


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    path = tmp_path / "baseline_in_progress.lock"
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(path))
    monkeypatch.delenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", raising=False)
    return path


@pytest.fixture
def running(monkeypatch):
    """Airflow reports every DAG run as running; the calls are recorded."""
    calls: List[tuple] = []

    def fake_get_dag_run(dag_id, run_id):
        calls.append((dag_id, run_id))
        return {"dag_run_id": run_id, "dag_id": dag_id, "state": "running"}

    monkeypatch.setattr(airflow_client, "get_dag_run", fake_get_dag_run)
    return calls


# ---------------------------------------------------------------------------
# Lock semantics
# ---------------------------------------------------------------------------


def test_own_dag_run_is_not_a_reason_to_skip(lock_path, running) -> None:
    assert baseline_lock.acquire_baseline_lock(holder=RUN) is True
    assert baseline_lock.baseline_skip_reason(own_holder=RUN) is None
    assert running == [], "ownership is read from the sentinel; no Airflow lookup is needed for the own run"


def test_scheduled_dags_and_other_runs_still_skip(lock_path, running) -> None:
    assert baseline_lock.acquire_baseline_lock(holder=RUN) is True
    reason = baseline_lock.baseline_skip_reason()
    assert reason is not None and RUN["run_id"] in reason, "a scheduled DAG passes no identity and stands down"
    assert baseline_lock.baseline_skip_reason(own_holder=OTHER_RUN) is not None, "another baseline run stands down"
    assert baseline_lock.baseline_skip_reason(own_holder={"dag_id": "edgeguard_baseline", "run_id": ""}) is not None
    assert baseline_lock.baseline_skip_reason(own_holder={"dag_id": "", "run_id": RUN["run_id"]}) is not None
    assert (
        baseline_lock.baseline_skip_reason(own_holder={"dag_id": "edgeguard_daily", "run_id": RUN["run_id"]})
        is not None
    )


def test_a_process_held_lock_is_never_own_for_a_dag_task(lock_path) -> None:
    assert baseline_lock.acquire_baseline_lock() is True, "in-process baseline (run_pipeline --baseline)"
    try:
        assert baseline_lock.baseline_skip_reason(own_holder=RUN) is not None
    finally:
        baseline_lock.release_baseline_lock()


def test_no_lock_means_no_skip_with_or_without_identity(lock_path) -> None:
    assert baseline_lock.baseline_skip_reason() is None
    assert baseline_lock.baseline_skip_reason(own_holder=RUN) is None


@pytest.mark.parametrize(
    "data, holder, expected",
    [
        ({"holder": "airflow_dag_run", **RUN}, RUN, True),
        ({"holder": "airflow_dag_run", **RUN}, OTHER_RUN, False),
        ({"holder": "airflow_dag_run", **RUN}, None, False),
        ({"holder": "airflow_dag_run", **RUN}, {}, False),
        ({"holder": "process", "pid": 1, **RUN}, RUN, False),
        (None, RUN, False),
        (
            {"holder": "airflow_dag_run", "dag_id": "edgeguard_baseline", "run_id": ""},
            {"dag_id": "edgeguard_baseline", "run_id": ""},
            False,
        ),
    ],
)
def test_is_own_dag_run_sentinel(data, holder, expected) -> None:
    assert baseline_lock.is_own_dag_run_sentinel(data, holder) is expected


# ---------------------------------------------------------------------------
# The real DAG callables
# ---------------------------------------------------------------------------


def _import_dag_module():
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            or key.startswith("airflow")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    dags = os.path.join(os.path.dirname(__file__), "..", "dags")
    if dags not in sys.path:
        sys.path.insert(0, dags)
    return importlib.import_module("edgeguard_pipeline")


class _Collector:
    """Stands in for a feed collector; records that it was built and how ``collect`` was called."""

    built: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []

    def __init__(self, misp_writer=None, **kwargs):
        type(self).built.append({"writer": misp_writer, **kwargs})

    def collect(self, limit=None, push_to_misp=True, baseline=False, baseline_days=365):
        type(self).calls.append(
            {"limit": limit, "push_to_misp": push_to_misp, "baseline": baseline, "baseline_days": baseline_days}
        )
        return {"source": "urlhaus", "success": True, "count": 7, "failed": 0}


@pytest.fixture
def dag(monkeypatch):
    try:
        ep = _import_dag_module()
    except Exception:
        pytest.skip("Airflow not installed in this test env")
    # The DAG module (re-imported above) binds the real modules; point the fake REST client at the one it uses.
    _Collector.built = []
    _Collector.calls = []
    patches = [
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _name: True),
        patch.object(ep, "get_baseline_config", lambda context=None: (None, 730)),
        patch.object(ep, "send_slack_alert", MagicMock()),
        patch.object(ep, "set_source_health", MagicMock()),
        patch.object(ep, "set_last_success_timestamp", MagicMock()),
        patch.object(ep, "record_dag_run", MagicMock()),
        patch.object(ep, "record_collection", MagicMock()),
        patch.object(ep, "record_collection_duration", MagicMock()),
        patch.object(ep, "record_collector_skip", MagicMock()),
        patch.object(ep, "record_indicators", MagicMock()),
        patch.object(ep, "record_misp_push", MagicMock()),
        patch.object(ep, "record_misp_push_duration", MagicMock()),
        patch.object(ep, "record_task_duration", MagicMock()),
        patch("collectors.misp_writer.MISPWriter", MagicMock()),
        patch("parent_dag_liveness.make_liveness_callback", lambda *_a, **_k: None),
    ]
    for p in patches:
        p.start()
    yield ep
    for p in reversed(patches):
        p.stop()


def _context(run: Dict[str, str]) -> Dict[str, Any]:
    return {
        "dag_run": SimpleNamespace(run_id=run["run_id"], dag_id=run["dag_id"], conf={}),
        "dag": SimpleNamespace(dag_id=run["dag_id"]),
    }


def test_baseline_collector_runs_while_its_own_dag_run_holds_the_lock(dag, lock_path, running) -> None:
    """The regression: acquire the lock as the DAG does, then run a collector of the same run."""
    dag._baseline_acquire_lock(**_context(RUN))
    assert lock_path.exists()

    result = dag.run_baseline_collector("urlhaus", _Collector, context=_context(RUN))

    assert len(_Collector.built) == 1, "the collector was instantiated"
    assert _Collector.calls == [{"limit": None, "push_to_misp": True, "baseline": True, "baseline_days": 730}]
    assert result["success"] is True and result["count"] == 7 and not result.get("skipped")


def test_baseline_collector_of_another_run_stands_down(dag, lock_path, running, caplog) -> None:
    dag._baseline_acquire_lock(**_context(RUN))
    with caplog.at_level("ERROR"):
        result = dag.run_baseline_collector("urlhaus", _Collector, context=_context(OTHER_RUN))
    assert _Collector.built == [] and _Collector.calls == []
    assert result.get("skipped") is True and result["skip_reason_class"] == "baseline_in_progress"
    assert any("NOT collected" in r.getMessage() and "another run" in r.getMessage() for r in caplog.records)


def test_scheduled_collector_still_stands_down_during_a_baseline(dag, lock_path, running) -> None:
    dag._baseline_acquire_lock(**_context(RUN))
    result = dag.run_collector_with_metrics("urlhaus", _Collector, MagicMock(), limit=50)
    assert _Collector.built == []
    assert result.get("skipped") is True and result["skip_reason_class"] == "baseline_in_progress"


def test_every_baseline_collector_callable_passes_its_run_context(dag, lock_path, running, monkeypatch) -> None:
    """All baseline collector tasks must reach the wrapper with the identity of their DAG run."""
    # 2026-10-16: the run holds its lock, as every baseline run does before its collectors; without
    # one they refuse (``_require_baseline_lock``).
    dag._baseline_acquire_lock(**_context(RUN))
    seen: List[Dict[str, Any]] = []

    def spy(collector_name, collector_class, writer, **kwargs):
        seen.append(
            {"name": collector_name, "holder": kwargs.get("baseline_holder"), "baseline": kwargs.get("baseline")}
        )
        return {"source": collector_name, "success": True, "count": 0, "failed": 0}

    monkeypatch.setattr(dag, "run_collector_with_metrics", spy)
    import config

    monkeypatch.setattr(config, "ENABLE_CISA_ICS", True)
    monkeypatch.setattr(config, "ENABLE_MALWAREBAZAAR", True, raising=False)
    callables = sorted(
        name
        for name in dir(dag)
        if name.startswith("run_baseline_")
        and name not in {"run_baseline_collector", "run_baseline_full_sync", "run_baseline_enrichment"}
    )
    assert len(callables) >= 10, callables
    for name in callables:
        getattr(dag, name)(**_context(RUN))
    assert len(seen) == len(callables), "every baseline collector callable goes through run_collector_with_metrics"
    assert all(s["baseline"] is True and s["holder"] == RUN for s in seen), seen


def test_acquire_fails_before_the_destructive_step_if_the_own_run_would_be_skipped(
    dag, lock_path, running, monkeypatch
) -> None:
    """Self-check: if the own-run exemption did not hold, the run must stop before ``baseline_clean``."""
    from airflow.exceptions import AirflowException

    monkeypatch.setattr(baseline_lock, "is_own_dag_run_sentinel", lambda _data, _holder: False)
    with pytest.raises(AirflowException, match="would skip this run's own collectors"):
        dag._baseline_acquire_lock(**_context(RUN))
