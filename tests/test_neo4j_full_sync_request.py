"""A requested full MISP → Neo4j sync survives a failed attempt (2026-10).

``run_neo4j_sync`` read the Airflow Variable ``NEO4J_FULL_SYNC`` and reset it to ``false`` before
``sync.run()``. When that attempt failed (or hit the task's execution timeout), Airflow retried
the task (``retries=2``); the retry found the flag cleared, ran incrementally, stamped the state
file, and the repair the operator asked for was silently incomplete. The flag is now cleared only
after a successful full sync. Because it then persists until a full sync succeeds, the task's
limit is 8 h (was 4 h; a full sync of a 730-day MISP takes about 6 h), the DAG run's limit covers
every task failing on all attempts, and the last failed attempt alerts that incremental syncs are
suspended while the flag stays set. The 8 h limit is the default of ``EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS``.

The DAG module is imported as Airflow would import it; the Variable store and
``MISPToNeo4jSync`` are stand-ins.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, "dags")

DAG_PATH = "dags/edgeguard_pipeline.py"


def _load_dag_module(skip_if_not_importable=True):
    # Purge the Airflow stubs other tests leave in ``sys.modules`` (``test_graphql_api.py`` registers
    # MagicMock placeholders for ``airflow.*`` and ``opentelemetry.*``), so the real Airflow is imported.
    for key in list(sys.modules):
        if key.startswith("airflow") or key == "opentelemetry" or key.startswith("opentelemetry."):
            del sys.modules[key]
    spec = importlib.util.spec_from_file_location("_dag_module_full_sync_request_test", DAG_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # pragma: no cover - environment-dependent
        # Skip only where Airflow is not installed: with Airflow present an import error is a
        # failure, so a stub left by another test cannot turn every DAG test here into a skip.
        if not skip_if_not_importable or importlib.util.find_spec("airflow") is not None:
            raise
        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module


@pytest.fixture(scope="module")
def dag_module():
    return _load_dag_module()


class _Variables:
    """Airflow Variable stand-in backed by a dict; ``fail_set`` makes writes raise."""

    store: dict = {}
    fail_set = False

    @classmethod
    def get(cls, key, default=None):
        return cls.store.get(key, default)

    @classmethod
    def set(cls, key, value):
        if cls.fail_set:
            raise RuntimeError("Airflow metadata database unavailable")
        cls.store[key] = value


class _ScriptedSync:
    """``MISPToNeo4jSync`` stand-in: one entry of ``outcomes`` per attempt (True, False or an exception)."""

    outcomes: list = []
    calls: list = []

    def __init__(self):
        self._last_sync_failure_reason = "scripted failure"

    def run(self, incremental=True, since=None, sector=None):
        _ScriptedSync.calls.append({"incremental": incremental, "since": since})
        outcome = _ScriptedSync.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture()
def env(tmp_path, monkeypatch, dag_module):
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_file = state_dir / "edgeguard_last_neo4j_sync.json"
    previous = datetime.now(timezone.utc) - timedelta(days=3)
    state_file.write_text(json.dumps({"last_sync": previous.isoformat()}))
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(state_dir))
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(tmp_path / "no_such.lock"))
    _Variables.store = {"NEO4J_FULL_SYNC": "true"}
    _Variables.fail_set = False
    monkeypatch.setattr(dag_module, "Variable", _Variables)
    fake = ModuleType("run_misp_to_neo4j")
    fake.MISPToNeo4jSync = _ScriptedSync
    monkeypatch.setitem(sys.modules, "run_misp_to_neo4j", fake)
    _ScriptedSync.calls = []
    monkeypatch.setattr(dag_module, "ensure_metrics_server", lambda: None)
    monkeypatch.setattr(dag_module, "record_neo4j_sync_duration", lambda *_a, **_k: None)
    monkeypatch.setattr(dag_module, "record_dag_run", lambda *_a, **_k: None)
    monkeypatch.setattr(dag_module, "record_error", lambda *_a, **_k: None)
    monkeypatch.setattr(dag_module, "METRICS_SERVER_AVAILABLE", False)
    return SimpleNamespace(state_file=state_file, previous=previous)


def _attempt(dag_module, n):
    return dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=n))


def _stamp(state_file):
    return datetime.fromisoformat(json.loads(state_file.read_text())["last_sync"])


@pytest.mark.parametrize(
    "first_failure",
    [False, TimeoutError("MISP event fetch timed out")],
    ids=["sync-reports-failure", "sync-raises"],
)
def test_a_failed_attempt_keeps_the_request_and_the_retry_runs_in_full(dag_module, env, first_failure):
    _ScriptedSync.outcomes = [first_failure, True]

    with pytest.raises((dag_module.AirflowException, TimeoutError)):
        _attempt(dag_module, 1)
    assert _Variables.store["NEO4J_FULL_SYNC"] == "true", "a failed attempt must leave the request in place"
    assert _stamp(env.state_file) == env.previous, "a failed attempt must not stamp the state file"

    _attempt(dag_module, 2)
    assert [c["incremental"] for c in _ScriptedSync.calls] == [False, False], "the retry is a full sync too"
    assert _ScriptedSync.calls[1]["since"] is None, "a full sync reads every event, no window"
    assert _Variables.store["NEO4J_FULL_SYNC"] == "false", "cleared once the full sync succeeded"
    assert _stamp(env.state_file) > env.previous


def test_the_next_run_after_a_successful_full_sync_is_incremental(dag_module, env):
    _ScriptedSync.outcomes = [True, True]
    _attempt(dag_module, 1)
    _attempt(dag_module, 1)
    assert [c["incremental"] for c in _ScriptedSync.calls] == [False, True]


def test_the_log_states_the_mode_and_why(dag_module, env, caplog):
    _ScriptedSync.outcomes = [True, True]
    with caplog.at_level(logging.INFO):
        _attempt(dag_module, 3)
    assert any(
        "Sync mode: FULL — requested by the Airflow Variable NEO4J_FULL_SYNC=true" in r.message
        and "(attempt 3)" in r.message
        for r in caplog.records
    )
    caplog.clear()
    with caplog.at_level(logging.INFO):
        _attempt(dag_module, 1)
    assert any("Sync mode: incremental" in r.message for r in caplog.records)


def test_the_log_states_the_task_limit_of_the_attempt(dag_module, env, caplog):
    _ScriptedSync.outcomes = [True, True, True]
    task = SimpleNamespace(execution_timeout=timedelta(hours=14))
    with caplog.at_level(logging.INFO):
        dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=2), task=task)
    assert any(
        r.getMessage().startswith("Sync mode: FULL") and r.getMessage().endswith("(attempt 2), task limit 14 h")
        for r in caplog.records
    )
    caplog.clear()
    with caplog.at_level(logging.INFO):
        _attempt(dag_module, 1)
    modes = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Sync mode:")]
    assert modes == ["Sync mode: incremental — state file present and NEO4J_FULL_SYNC not set (attempt 1)"]
    caplog.clear()
    with caplog.at_level(logging.INFO):
        dag_module.run_neo4j_sync(ti=SimpleNamespace(try_number=1), task=task)
    modes = [r.getMessage() for r in caplog.records if r.getMessage().startswith("Sync mode:")]
    assert modes and modes[0].startswith("Sync mode: incremental") and modes[0].endswith("(attempt 1), task limit 14 h")


def test_a_variable_write_failure_after_success_does_not_fail_the_task(dag_module, env, caplog):
    _ScriptedSync.outcomes = [True]
    _Variables.fail_set = True
    with caplog.at_level(logging.WARNING):
        _attempt(dag_module, 1)
    assert _Variables.store["NEO4J_FULL_SYNC"] == "true"
    assert any("Could not clear the Airflow Variable NEO4J_FULL_SYNC" in r.message for r in caplog.records)


def test_an_incremental_run_never_touches_the_flag(dag_module, env):
    _Variables.store = {}
    _ScriptedSync.outcomes = [True]
    _attempt(dag_module, 1)
    assert _ScriptedSync.calls[0]["incremental"] is True
    assert "NEO4J_FULL_SYNC" not in _Variables.store


def test_the_sync_task_limit_leaves_margin_above_the_full_sync_estimate(dag_module):
    """About 6 h for a full sync of a 730-day MISP (the baseline task's limit). A requested full sync
    keeps its flag until it succeeds, so a limit at the estimate could fail every attempt of every run."""
    assert dag_module.run_neo4j_sync_task.execution_timeout == timedelta(hours=8)
    assert dag_module.run_neo4j_sync_task.execution_timeout > dag_module.baseline_full_sync_task.execution_timeout


_INVALID = "(expected whole hours from 1 to 22) — using 8"
_ABOVE_CAP = "is above 22 — using 22 (three attempts must end inside the 68 h dagrun_timeout)"


@pytest.mark.parametrize(
    "value, hours, warning",
    [
        (None, 8, None),
        ("14", 14, None),
        (" 12 ", 12, None),
        ("", 8, None),
        ("22", 22, None),
        ("0", 8, _INVALID),
        ("-3", 8, _INVALID),
        ("abc", 8, _INVALID),
        ("1.5", 8, _INVALID),
        ("23", 22, _ABOVE_CAP),
        (str(24 * 10**9), 22, _ABOVE_CAP),
    ],
    ids=["unset", "set", "padded", "empty", "cap", "zero", "negative", "text", "fraction", "above-cap", "huge"],
)
def test_the_sync_task_limit_follows_the_env_knob(dag_module, monkeypatch, caplog, value, hours, warning):
    """EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS: a remote Neo4j can need more than 8 h; an invalid value uses 8
    and one above the 22 h cap uses 22, both with a warning."""
    if value is None:
        monkeypatch.delenv("EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS", value)
    with caplog.at_level(logging.WARNING):
        assert dag_module._neo4j_sync_timeout_hours() == hours
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS" in r.getMessage()
    ]
    if warning is None:
        assert warnings == []
    else:
        assert len(warnings) == 1 and warning in warnings[0] and repr(value) in warnings[0]


@pytest.mark.parametrize(
    "value, hours",
    [("14", 14), (None, 8), ("30", 22), (str(24 * 10**9), 22)],
    ids=["set", "unset", "above-cap", "huge"],
)
def test_the_dag_file_sets_the_sync_task_limit_from_the_env_knob(dag_module, monkeypatch, value, hours):
    """The variable is read when the DAG file is parsed: the task's execution_timeout is what Airflow enforces.
    ``dag_module`` skips where the DAG file is not importable; here a failing import (an ``OverflowError``
    from ``timedelta`` for a huge value) fails the test."""
    if value is None:
        monkeypatch.delenv("EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS", raising=False)
    else:
        monkeypatch.setenv("EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS", value)
    module = _load_dag_module(skip_if_not_importable=False)
    assert module.run_neo4j_sync_task.execution_timeout == timedelta(hours=hours)
    if value is None:
        assert module._NEO4J_SYNC_TIMEOUT_DEFAULT_HOURS == 8


def test_the_cap_keeps_three_sync_attempts_and_the_skip_guard_inside_the_limits(dag_module):
    """22 h: the largest whole number of hours with which every attempt of run_neo4j_sync, after the
    worst case of the two tasks before it, ends inside the DAG run's limit, and the previous sync's
    latest start leaves the next 72 h run more than the 24 h skip guard."""
    dag = dag_module.neo4j_sync_dag
    sync = dag.get_task("run_neo4j_sync")

    def worst(task):
        return task.execution_timeout * (1 + task.retries) + task.retry_delay * task.retries

    before = worst(dag.get_task("check_sync_needed")) + worst(dag.get_task("neo4j_health_check"))

    def all_attempts_end_inside_the_run(limit):
        return before + limit * (1 + sync.retries) + sync.retry_delay * sync.retries < dag.dagrun_timeout

    cap = timedelta(hours=dag_module._NEO4J_SYNC_TIMEOUT_MAX_HOURS)
    assert all_attempts_end_inside_the_run(cap)
    assert not all_attempts_end_inside_the_run(cap + timedelta(hours=1)), "the largest such whole hour"
    latest_start = before + (cap + sync.retry_delay) * sync.retries
    assert dag_module.NEO4J_SYNC_EVERY - latest_start > dag_module.NEO4J_SYNC_MIN_GAP


def test_the_dag_run_limit_covers_every_task_failing_on_all_attempts(dag_module):
    """The method docs/AIRFLOW_DAGS.md states for every DAG: execution_timeout × (1 + retries) +
    retries × retry_delay, summed over the sequential chain, plus 20%."""
    dag = dag_module.neo4j_sync_dag
    assert all(len(task.downstream_list) <= 1 for task in dag.tasks), "one sequential chain"
    worst = sum(
        (task.execution_timeout * (1 + task.retries) + task.retry_delay * task.retries for task in dag.tasks),
        timedelta(0),
    )
    assert dag.dagrun_timeout >= worst * 1.2


def _failure_context(dag_module):
    return {
        "dag": dag_module.neo4j_sync_dag,
        "task_instance": SimpleNamespace(task_id="run_neo4j_sync"),
        "exception": "Neo4j sync failed: scripted failure",
    }


def test_the_last_failed_attempt_alerts_while_the_request_is_pending(dag_module, env, monkeypatch, caplog):
    common = MagicMock()
    errors = MagicMock()
    monkeypatch.setattr(dag_module, "_on_task_failure", common)
    monkeypatch.setattr(dag_module, "ENABLE_PROMETHEUS_METRICS", True)
    monkeypatch.setattr(dag_module, "PROMETHEUS_AVAILABLE", True)
    monkeypatch.setattr(dag_module, "PIPELINE_ERRORS", errors, raising=False)
    callbacks = dag_module.run_neo4j_sync_task.on_failure_callback
    assert dag_module._on_neo4j_sync_failure in (callbacks if isinstance(callbacks, list) else [callbacks])

    with caplog.at_level(logging.ERROR):
        dag_module._on_neo4j_sync_failure(_failure_context(dag_module))
    common.assert_called_once()
    assert any(
        r.levelno == logging.ERROR
        and "NEO4J_FULL_SYNC is still true" in r.message
        and "no incremental sync runs" in r.message
        and "airflow variables set NEO4J_FULL_SYNC false" in r.message
        for r in caplog.records
    )
    errors.labels.assert_called_once_with(
        task="run_neo4j_sync", error_type="full_sync_request_pending", source="edgeguard_neo4j_sync"
    )

    caplog.clear()
    errors.reset_mock()
    _Variables.store = {"NEO4J_FULL_SYNC": "false"}
    with caplog.at_level(logging.ERROR):
        dag_module._on_neo4j_sync_failure(_failure_context(dag_module))
    assert not any("NEO4J_FULL_SYNC is still true" in r.message for r in caplog.records)
    errors.labels.assert_not_called()
