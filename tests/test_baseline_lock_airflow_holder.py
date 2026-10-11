"""Baseline lock held by the ``edgeguard_baseline`` DAG run (Issue #57).

The task process that writes the sentinel exits while the DAG run continues for hours, so the
holder's liveness is the DAG-run state read through the Airflow REST API, with the sentinel age
as fallback. These tests pin that contract, the DAG wiring, and the documentation.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import airflow_client
import baseline_lock

_ROOT = Path(__file__).resolve().parents[1]
HOLDER = {"dag_id": "edgeguard_baseline", "run_id": "manual__2026-10-11T20:00:00+00:00"}


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    path = tmp_path / "baseline_in_progress.lock"
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(path))
    monkeypatch.delenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", raising=False)
    return path


@pytest.fixture
def run_state(monkeypatch):
    """Fake Airflow REST client: ``state`` None means the API is unavailable."""
    box: dict = {"state": None, "calls": []}

    def fake_get_dag_run(dag_id, run_id):
        box["calls"].append((dag_id, run_id))
        if box["state"] is None:
            return {"error": "Cannot connect to Airflow at http://localhost:8082."}
        return {"dag_run_id": run_id, "dag_id": dag_id, "state": box["state"]}

    monkeypatch.setattr(airflow_client, "get_dag_run", fake_get_dag_run)
    return box


def _rewrite(lock_path: Path, **fields) -> None:
    data = json.loads(lock_path.read_text())
    data.update(fields)
    lock_path.write_text(json.dumps(data))


class TestAirflowRunHolder:
    def test_acquire_records_the_dag_run_and_the_skip_reason_names_it(self, lock_path, run_state):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER) is True
        data = json.loads(lock_path.read_text())
        assert data["holder"] == "airflow_dag_run"
        assert data["dag_id"] == HOLDER["dag_id"] and data["run_id"] == HOLDER["run_id"]
        assert baseline_lock.is_baseline_running()["run_id"] == HOLDER["run_id"]
        reason = baseline_lock.baseline_skip_reason()
        assert HOLDER["run_id"] in reason and "skipping scheduled collector run" in reason

    def test_holder_without_identifiers_is_refused(self, lock_path):
        assert baseline_lock.acquire_baseline_lock(holder={"dag_id": "edgeguard_baseline"}) is False
        assert not lock_path.exists()

    def test_pid_liveness_is_not_used_for_a_dag_run(self, lock_path, run_state):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        _rewrite(lock_path, pid=-1)  # a process holder with this pid would be pruned as dead
        assert baseline_lock.is_baseline_running() is not None
        assert run_state["calls"][-1] == (HOLDER["dag_id"], HOLDER["run_id"])

    def test_successful_run_state_prunes_the_sentinel(self, lock_path, run_state, caplog):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        run_state["state"] = "success"
        with caplog.at_level(logging.WARNING, logger="baseline_lock"):
            assert baseline_lock.is_baseline_running() is None
        assert not lock_path.exists()
        assert any("is success" in r.message for r in caplog.records)

    def test_failed_run_keeps_the_lock_until_the_age_cap(self, lock_path, run_state):
        """A failed baseline is resumed by clearing the failed task; the resumed run must stay under the mutex."""
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        run_state["state"] = "failed"
        assert baseline_lock.is_baseline_running() is not None
        assert lock_path.exists()
        _rewrite(lock_path, started_at=(datetime.now(timezone.utc) - timedelta(hours=49)).isoformat())
        assert baseline_lock.is_baseline_running() is None
        assert not lock_path.exists()

    def test_acquire_is_idempotent_for_the_same_run(self, lock_path, run_state, caplog):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER) is True
        with caplog.at_level(logging.INFO, logger="baseline_lock"):
            assert baseline_lock.acquire_baseline_lock(holder=HOLDER) is True
        assert any("already held by this DAG run" in r.message for r in caplog.records)
        assert (
            baseline_lock.acquire_baseline_lock(holder={"dag_id": HOLDER["dag_id"], "run_id": "manual__other"}) is False
        )
        assert json.loads(lock_path.read_text())["run_id"] == HOLDER["run_id"]

    def test_api_unavailable_trusts_a_fresh_sentinel_and_reaps_an_old_one(self, lock_path, run_state):
        run_state["state"] = None
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        assert baseline_lock.is_baseline_running() is not None
        _rewrite(lock_path, started_at=(datetime.now(timezone.utc) - timedelta(hours=49)).isoformat())
        assert baseline_lock.is_baseline_running() is None
        assert not lock_path.exists()

    def test_age_cap_is_configurable(self, lock_path, run_state, monkeypatch):
        run_state["state"] = None
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        _rewrite(lock_path, started_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat())
        assert baseline_lock.is_baseline_running() is not None
        monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", "3600")
        assert baseline_lock.is_baseline_running() is None

    def test_a_live_dag_run_blocks_an_in_process_baseline(self, lock_path, run_state):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        assert baseline_lock.acquire_baseline_lock() is False

    def test_release_requires_the_same_run(self, lock_path, run_state):
        run_state["state"] = "running"
        assert baseline_lock.acquire_baseline_lock(holder=HOLDER)
        baseline_lock.release_baseline_lock()  # an in-process caller must not remove a DAG-run lock
        assert lock_path.exists()
        baseline_lock.release_baseline_lock(holder={"dag_id": HOLDER["dag_id"], "run_id": "manual__other"})
        assert lock_path.exists()
        baseline_lock.release_baseline_lock(holder=HOLDER)
        assert not lock_path.exists()

    def test_a_dag_run_cannot_release_a_process_sentinel(self, lock_path):
        assert baseline_lock.acquire_baseline_lock()
        baseline_lock.release_baseline_lock(holder=HOLDER)
        assert lock_path.exists()
        baseline_lock.release_baseline_lock()
        assert not lock_path.exists()

    def test_process_sentinel_contract_unchanged(self, lock_path):
        assert baseline_lock.acquire_baseline_lock()
        data = json.loads(lock_path.read_text())
        assert "holder" not in data and data["pid"] == os.getpid()
        assert "pid=" in baseline_lock.baseline_skip_reason()
        baseline_lock.release_baseline_lock()
        assert not lock_path.exists()


class _AirflowException(Exception):
    pass


def _dag_lock_callables() -> dict:
    """The lock callables of the baseline DAG, executed without importing Airflow."""
    src = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
    start = src.index("def _baseline_run_holder(context) -> dict:")
    end = src.index("baseline_acquire_lock_task = PythonOperator(")
    ns: dict = {"logger": logging.getLogger("dag-lock-test"), "AirflowException": _AirflowException}
    exec(compile(src[start:end], "dag_lock_callables", "exec"), ns)
    return ns


class _Run:
    def __init__(self, run_id: str):
        self.dag_id = "edgeguard_baseline"
        self.run_id = run_id


class TestDagWiring:
    @pytest.fixture(scope="class")
    def dag_src(self) -> str:
        return (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()

    def test_lock_tasks_exist_and_bracket_the_destructive_step(self, dag_src):
        assert 'task_id="baseline_acquire_lock"' in dag_src and 'task_id="baseline_release_lock"' in dag_src
        chain = dag_src[dag_src.index("(\n    baseline_misp_health\n") :]
        assert (
            chain.index(">> baseline_acquire_lock_task")
            < chain.index(">> baseline_clean_task")
            < chain.index(">> baseline_start")
        )
        assert "baseline_complete >> baseline_release_lock_task" in dag_src

    def test_release_task_runs_only_after_a_successful_chain(self, dag_src):
        """A failed run keeps the lock so that clearing the failed task resumes under the mutex."""
        block = dag_src[dag_src.index("baseline_release_lock_task = PythonOperator(") :]
        block = block[: block.index("\n)\n")]
        assert "trigger_rule=TriggerRule.ALL_SUCCESS" in block
        assert "ALL_DONE" not in block

    def test_acquire_callable_takes_the_lock_and_refuses_a_second_run(self, lock_path, run_state):
        ns = _dag_lock_callables()
        run_state["state"] = "running"
        ns["_baseline_acquire_lock"](dag_run=_Run("manual__first"))
        assert json.loads(lock_path.read_text())["run_id"] == "manual__first"
        ns["_baseline_acquire_lock"](dag_run=_Run("manual__first"))  # retry of the task: idempotent
        with pytest.raises(_AirflowException, match="Another baseline holds"):
            ns["_baseline_acquire_lock"](dag_run=_Run("manual__second"))
        ns["_baseline_release_lock"](dag_run=_Run("manual__second"))
        assert lock_path.exists(), "a different run must not release the lock"
        ns["_baseline_release_lock"](dag_run=_Run("manual__first"))
        assert not lock_path.exists()

    def test_acquire_callable_requires_a_run_id(self, lock_path):
        ns = _dag_lock_callables()
        with pytest.raises(_AirflowException, match="run_id"):
            ns["_baseline_acquire_lock"](dag_run=None)
        assert not lock_path.exists()

    def test_release_callable_never_raises(self, lock_path, monkeypatch):
        ns = _dag_lock_callables()
        monkeypatch.setattr(
            baseline_lock, "release_baseline_lock", lambda **_k: (_ for _ in ()).throw(RuntimeError("disk"))
        )
        ns["_baseline_release_lock"](dag_run=_Run("manual__first"))


class TestDocumentation:
    def test_docs_no_longer_claim_the_dag_holds_no_lock(self):
        readme = (_ROOT / "README.md").read_text()
        runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
        assert "does **not** acquire the `baseline_lock` sentinel" not in readme
        assert "the baseline DAG holds no" not in readme
        assert "NOT written by the baseline DAG" not in runbook
        assert "Until Issue #57 lands" not in readme and "Until Issue #57 lands" not in runbook
        assert "baseline_acquire_lock" in readme and "baseline_acquire_lock" in runbook

    def test_preflight_treats_an_unpaused_dag_as_a_warning(self):
        script = (_ROOT / "scripts" / "preflight_baseline.sh").read_text()
        assert 'fail "DAG $dag is NOT paused' not in script
        assert 'warn "DAG $dag is not paused' in script
