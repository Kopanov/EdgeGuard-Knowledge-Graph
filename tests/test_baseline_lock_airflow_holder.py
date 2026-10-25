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


class TestPreflightRunningRuns:
    """Check [5] of preflight_baseline.sh (2026-10-25): pausing stops new tasks and retries only, so a
    task that is already running (a ``run_neo4j_sync`` attempt up to EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS)
    keeps writing into a store the fresh baseline wipes. The check fails while one of the five
    scheduled DAGs has a running run and warns when the runs cannot be read."""

    # The fake ``docker``: every DAG is paused; list-runs answers per DAG. edgeguard_neo4j_sync has
    # one running run (after a log line), edgeguard_pipeline answers as ``-o plain`` would with no
    # run, edgeguard_low_freq fails, the other two have none.
    _DOCKER = r"""#!/bin/sh
echo "$*" >> calls.txt
case "$7 $8" in
  "details "*) echo "is_paused | True"; exit 0 ;;
  "list-runs edgeguard_neo4j_sync")
    echo "[2026-10-25T05:00:00.000+0000] {dagbag.py:588} INFO - Filling up the DagBag"
    echo '[{"dag_id": "edgeguard_neo4j_sync", "run_id": "scheduled__2026-10-25T03:00:00+00:00", "state": "running"}]'
    exit 0 ;;
  "list-runs edgeguard_pipeline") echo "No data found"; exit 0 ;;
  "list-runs edgeguard_low_freq") echo "Connection refused" >&2; exit 1 ;;
  "list-runs "*) echo "[]"; exit 0 ;;
esac
exit 2
"""

    _DAGS = (
        "edgeguard_daily",
        "edgeguard_medium_freq",
        "edgeguard_pipeline",
        "edgeguard_low_freq",
        "edgeguard_neo4j_sync",
    )

    def _run_check(self, tmp_path, launch_path="dag"):
        import subprocess

        script = (_ROOT / "scripts" / "preflight_baseline.sh").read_text()
        block = script[script.index('hdr "[4][5]') : script.index("# [6] Airflow worker RAM")]
        block = block[: block.rindex("fi\n") + 3]
        docker = tmp_path / "docker"
        docker.write_text(self._DOCKER)
        docker.chmod(0o755)
        harness = (
            f"set -uo pipefail\nLAUNCH_PATH={launch_path}\n"
            'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n' + block
        )
        env = {"PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}"}
        done = subprocess.run(
            ["bash", "-c", harness], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
        )
        assert done.returncode == 0, done.stderr
        return done.stdout.splitlines(), (tmp_path / "calls.txt").read_text().splitlines()

    def test_a_running_run_fails_and_an_unreadable_answer_warns(self, tmp_path):
        out, calls = self._run_check(tmp_path)
        by_dag: dict = {}
        for line in out:
            dag = next(d for d in self._DAGS if f" {d} " in f" {line} ")
            by_dag.setdefault(dag, []).append(line.split("|", 1)[0])
        assert by_dag == {
            "edgeguard_daily": ["PASS", "PASS"],
            "edgeguard_medium_freq": ["PASS", "PASS"],
            "edgeguard_pipeline": ["PASS", "WARN"],
            "edgeguard_low_freq": ["PASS", "WARN"],
            "edgeguard_neo4j_sync": ["PASS", "FAIL"],
        }, out
        (failure,) = [line for line in out if line.startswith("FAIL|")]
        assert "edgeguard_neo4j_sync has 1 running run(s)" in failure
        assert "EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS" in failure
        assert "PASS|DAG edgeguard_daily has no running run" in out
        for dag in self._DAGS:
            assert f"compose exec -T airflow airflow dags list-runs {dag} --state running -o json" in calls

    def test_the_cli_launch_path_checks_running_runs_too(self, tmp_path):
        # The in-process baseline wipes as well, and a task already running keeps writing whatever the path.
        out, calls = self._run_check(tmp_path, launch_path="cli")
        assert not [c for c in calls if " details " in f" {c} "], "the CLI path does not read the pause state"
        for dag in self._DAGS:
            assert f"compose exec -T airflow airflow dags list-runs {dag} --state running -o json" in calls
        (failure,) = [line for line in out if line.startswith("FAIL|")]
        assert "edgeguard_neo4j_sync has 1 running run(s)" in failure
        assert "PASS|DAG edgeguard_daily has no running run" in out

    def test_the_docs_no_longer_say_pausing_stops_a_running_write(self):
        runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
        checklist = (_ROOT / "docs" / "BASELINE_LAUNCH_CHECKLIST.md").read_text()
        for name, text in (("RUNBOOK.md", runbook), ("BASELINE_LAUNCH_CHECKLIST.md", checklist)):
            main = text.split("\n## History", 1)[0]
            assert "mid-write" not in main and "finishes its write" not in main, name
            assert "airflow dags list-runs" in main and "--state running -o json" in main, name
        protocol = runbook.split("## Baseline-day protocol", 1)[1].split("\n---", 1)[0]
        assert "Pausing them stops new tasks and retries only" in protocol
        assert 'airflow dags list-runs "$dag" --state running -o json' in protocol
