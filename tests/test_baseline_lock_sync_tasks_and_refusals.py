"""The baseline lock in the sync DAG's later tasks and around ``baseline_clean``'s refusals (2026-10-16).

1. ``edgeguard_neo4j_sync`` checked the baseline lock only in its first task, ``check_sync_needed``.
   ``run_neo4j_sync`` (and its retries), ``build_relationships`` and ``run_enrichment_jobs`` start
   minutes to hours later and wrote to Neo4j even when a baseline had taken the lock in between
   (during its wipe or its collection). Each now skips at its start while another run holds the
   lock; the baseline DAG's own ``build_relationships`` (the same callable) still runs under the
   lock of its run.
2. ``baseline_clean`` refuses before the wipe on a ``fresh_baseline`` typo, an invalid
   ``wipe_scope`` or the backup gate. The run had taken the lock in ``baseline_acquire_lock`` and,
   failed, kept it until the 48 h age cap: the corrected trigger the error message asks for was
   refused, and every scheduled collector and the sync stood down meanwhile, although nothing was
   wiped. A refusal now releases the lock; ``baseline_clean`` (cleared after an environment fix)
   takes it again before the wipe and ``baseline_start`` before the collectors, which also covers
   a ``baseline_clean`` marked success by hand.

The DAG module is imported as Airflow imports it, and the lock is a real sentinel file; only the
Airflow REST lookup of the run state, the sync, the subprocess, the enrichment and the wipe are
replaced.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

import airflow_client
import baseline_lock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "dags") not in sys.path:
    sys.path.insert(0, str(_ROOT / "dags"))

BASELINE_A = {"dag_id": "edgeguard_baseline", "run_id": "manual__2026-10-16T08:00:00+00:00"}
BASELINE_B = {"dag_id": "edgeguard_baseline", "run_id": "manual__2026-10-16T08:10:00+00:00"}
SYNC_RUN = {"dag_id": "edgeguard_neo4j_sync", "run_id": "scheduled__2026-10-16T03:00:00+00:00"}


def _load_dag_module():
    spec = importlib.util.spec_from_file_location(
        "_dag_module_baseline_lock_sync_tasks_test", _ROOT / "dags" / "edgeguard_pipeline.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module


@pytest.fixture(scope="module")
def dag():
    return _load_dag_module()


def _context(run: dict, conf: dict | None = None) -> dict:
    return {
        "dag_run": SimpleNamespace(run_id=run["run_id"], dag_id=run["dag_id"], conf=conf or {}),
        "dag": SimpleNamespace(dag_id=run["dag_id"]),
    }


@pytest.fixture
def lock(tmp_path, monkeypatch):
    """A real sentinel path; Airflow reports each DAG run as ``states[run_id]`` (default running)."""
    path = tmp_path / "baseline_in_progress.lock"
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(path))
    monkeypatch.delenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", raising=False)
    states: dict = {}

    def fake_get_dag_run(dag_id, run_id):
        return {"dag_id": dag_id, "dag_run_id": run_id, "state": states.get(run_id, "running")}

    monkeypatch.setattr(airflow_client, "get_dag_run", fake_get_dag_run)
    return SimpleNamespace(path=path, states=states)


def _holder_on_disk(path: Path):
    return json.loads(path.read_text())["run_id"] if path.exists() else None


# ---------------------------------------------------------------------------
# 1. The sync DAG's tasks after check_sync_needed
# ---------------------------------------------------------------------------


class _Variables:
    store: dict = {}

    @classmethod
    def get(cls, key, default=None):
        return cls.store.get(key, default)

    @classmethod
    def set(cls, key, value):
        cls.store[key] = value


@pytest.fixture
def sync_tasks(dag, lock, tmp_path, monkeypatch):
    """The three tasks with recording stand-ins for the work they start."""
    ran: list = []
    state_dir = tmp_path / "state"
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(state_dir))
    _Variables.store = {"NEO4J_FULL_SYNC": "true"}
    monkeypatch.setattr(dag, "Variable", _Variables)
    for name in ("ensure_metrics_server", "record_dag_run", "record_error", "record_neo4j_node_counts"):
        monkeypatch.setattr(dag, name, lambda *_a, **_k: None)
    monkeypatch.setattr(dag, "_record_successful_sync_metrics", lambda *_a, **_k: None)
    monkeypatch.setattr(dag, "METRICS_SERVER_AVAILABLE", False)

    class _Sync:
        _last_sync_failure_reason = None

        def run(self, incremental=True, since=None, sector=None):
            ran.append("run_neo4j_sync")
            return True

    fake_sync = ModuleType("run_misp_to_neo4j")
    fake_sync.MISPToNeo4jSync = _Sync
    monkeypatch.setitem(sys.modules, "run_misp_to_neo4j", fake_sync)

    def _stream(cmd, **_kwargs):
        ran.append("build_relationships")
        return 0, []

    fake_stream = ModuleType("subprocess_streaming")
    fake_stream.SubprocessStreamTimeout = TimeoutError
    fake_stream.run_with_streaming_output = _stream
    monkeypatch.setitem(sys.modules, "subprocess_streaming", fake_stream)

    fake_enrichment = ModuleType("enrichment_jobs")
    fake_enrichment.run_all_enrichment_jobs = lambda _client: ran.append("run_enrichment_jobs") or {}
    monkeypatch.setitem(sys.modules, "enrichment_jobs", fake_enrichment)
    fake_client = ModuleType("neo4j_client")
    fake_client.Neo4jClient = MagicMock
    monkeypatch.setitem(sys.modules, "neo4j_client", fake_client)

    tasks = (dag.run_neo4j_sync, dag.run_build_relationships, dag.run_enrichment_jobs)
    return SimpleNamespace(ran=ran, tasks=tasks, state_file=state_dir / "edgeguard_last_neo4j_sync.json")


def test_sync_dag_tasks_skip_while_a_baseline_holds_the_lock(dag, lock, sync_tasks):
    """The regression: the baseline takes the lock after ``check_sync_needed`` passed."""
    assert baseline_lock.acquire_baseline_lock(holder=BASELINE_A)

    for task in sync_tasks.tasks:
        with pytest.raises(dag.AirflowSkipException, match=re.escape(BASELINE_A["run_id"])):
            task(**_context(SYNC_RUN))

    assert sync_tasks.ran == [], f"ran while a baseline held the lock: {sync_tasks.ran}"
    assert not sync_tasks.state_file.exists(), "a skipped sync stamps no state file"
    assert _Variables.store["NEO4J_FULL_SYNC"] == "true", "a skipped sync leaves the full-sync request set"

    # The same tasks run once the lock is released (the stand-ins above are reached).
    baseline_lock.release_baseline_lock(holder=BASELINE_A)
    for task in sync_tasks.tasks:
        task(**_context(SYNC_RUN))
    assert sync_tasks.ran == ["run_neo4j_sync", "build_relationships", "run_enrichment_jobs"]
    assert sync_tasks.state_file.exists() and _Variables.store["NEO4J_FULL_SYNC"] == "false"


def test_a_process_held_lock_skips_the_sync_tasks_too(dag, lock, sync_tasks):
    """The in-process baseline (``run_pipeline --baseline``) is never the task's own run."""
    assert baseline_lock.acquire_baseline_lock()
    try:
        with pytest.raises(dag.AirflowSkipException):
            dag.run_enrichment_jobs(**_context(SYNC_RUN))
    finally:
        baseline_lock.release_baseline_lock()
    assert sync_tasks.ran == []


def test_the_baseline_runs_own_build_relationships_still_runs(dag, lock, sync_tasks):
    """``build_relationships`` of the baseline DAG is the same callable; the lock of its own run is no reason to skip."""
    assert baseline_lock.acquire_baseline_lock(holder=BASELINE_A)

    assert dag.run_build_relationships(**_context(BASELINE_A)) == {"built": True, "returncode": 0}
    assert sync_tasks.ran == ["build_relationships"]

    with pytest.raises(dag.AirflowSkipException):
        dag.run_build_relationships(**_context(BASELINE_B))
    assert sync_tasks.ran == ["build_relationships"], "another baseline run's task still stands down"


# ---------------------------------------------------------------------------
# 2. baseline_clean's refusals before the wipe
# ---------------------------------------------------------------------------


@pytest.fixture
def clean(lock, monkeypatch):
    """The real ``baseline_clean`` module with the backup gate, the probe and the wipe replaced."""
    import baseline_clean

    box = SimpleNamespace(gate_error=None, wipes=[], wipe_error=None)
    monkeypatch.setattr(baseline_clean, "check_recent_backup_timestamp", lambda: box.gate_error)
    monkeypatch.setattr(
        baseline_clean,
        "probe_baseline_state",
        lambda client=None: baseline_clean.BaselineState(
            neo4j_count=350_000, neo4j_ok=True, misp_count=8_000, misp_ok=True, checkpoint_count=3, checkpoint_ok=True
        ),
    )

    def reset_baseline_data(**kwargs):
        if box.wipe_error is not None:
            raise box.wipe_error
        box.wipes.append({"holder": _holder_on_disk(lock.path), **kwargs})
        return SimpleNamespace(
            before=SimpleNamespace(neo4j_count=350_000, misp_count=8_000, checkpoint_count=3), duration_seconds=0.1
        )

    monkeypatch.setattr(baseline_clean, "reset_baseline_data", reset_baseline_data)
    box.module = baseline_clean
    return box


REFUSALS = [
    pytest.param(
        {"fresh": True, "baseline_days": 730}, None, "did you mean 'fresh_baseline'", id="fresh_baseline-typo"
    ),
    pytest.param({"fresh_baseline": True, "wipe_scope": "edgegaurd"}, None, "wipe_scope must be", id="wipe_scope"),
    pytest.param(
        {"fresh_baseline": True}, "EDGEGUARD_LAST_BACKUP_AT is not set", "BASELINE_CLEAN refused", id="backup-gate"
    ),
]


@pytest.mark.parametrize("conf, gate_error, refusal", REFUSALS)
def test_a_refusal_before_the_wipe_releases_the_lock(dag, lock, clean, conf, gate_error, refusal):
    """The regression: nothing was wiped, yet the failed run kept the lock for up to 48 h."""
    clean.gate_error = gate_error
    dag._baseline_acquire_lock(**_context(BASELINE_A, conf))

    with pytest.raises(dag.AirflowException, match=refusal) as refused:
        dag._baseline_clean(**_context(BASELINE_A, conf))
    assert "Nothing was wiped and this run released the baseline lock" in str(refused.value)
    lock.states[BASELINE_A["run_id"]] = "failed"

    assert clean.wipes == []
    assert not lock.path.exists()
    assert baseline_lock.baseline_skip_reason() is None, "the scheduled DAGs do not stand down"
    # The corrected trigger (a new run) takes the lock.
    dag._baseline_acquire_lock(**_context(BASELINE_B, {"fresh_baseline": True, "skip_backup_check": True}))
    assert _holder_on_disk(lock.path) == BASELINE_B["run_id"]


def test_baseline_clean_cleared_after_an_environment_fix_wipes_under_the_lock(dag, lock, clean):
    conf = {"fresh_baseline": True}
    clean.gate_error = "EDGEGUARD_LAST_BACKUP_AT is not set"
    dag._baseline_acquire_lock(**_context(BASELINE_A, conf))
    with pytest.raises(dag.AirflowException, match="BASELINE_CLEAN refused"):
        dag._baseline_clean(**_context(BASELINE_A, conf))
    assert not lock.path.exists()

    clean.gate_error = None  # the backup is recorded and the container recreated; baseline_clean is cleared
    dag._baseline_clean(**_context(BASELINE_A, conf))
    assert clean.wipes == [{"holder": BASELINE_A["run_id"], "wipe_scope": "edgeguard"}]


def test_baseline_clean_does_not_wipe_while_another_run_holds_the_lock(dag, lock, clean):
    """A cleared ``baseline_clean`` of a run whose lock was released must not wipe under another baseline."""
    dag._baseline_acquire_lock(**_context(BASELINE_B, {"fresh_baseline": True}))
    with pytest.raises(dag.AirflowException, match="another baseline holds the baseline lock"):
        dag._baseline_clean(**_context(BASELINE_A, {"fresh_baseline": True}))
    assert clean.wipes == []
    assert _holder_on_disk(lock.path) == BASELINE_B["run_id"]


def test_a_failed_wipe_keeps_the_lock(dag, lock, clean):
    """Only the refusals before the wipe release the lock; a failed wipe is resumed under it."""
    clean.wipe_error = clean.module.BaselineCleanError("verify poll timed out")
    dag._baseline_acquire_lock(**_context(BASELINE_A, {"fresh_baseline": True}))
    with pytest.raises(dag.AirflowException, match="BASELINE_CLEAN failed") as failed:
        dag._baseline_clean(**_context(BASELINE_A, {"fresh_baseline": True}))
    assert "released the baseline lock" not in str(failed.value)
    assert _holder_on_disk(lock.path) == BASELINE_A["run_id"]


def test_baseline_start_takes_the_lock_again_after_a_refusal(dag, lock, clean, monkeypatch):
    """``baseline_clean`` marked success by hand after a refusal: the collectors must not start without the lock."""
    monkeypatch.setattr(dag, "get_baseline_config", lambda context=None: (0, 730))
    conf = {"fresh_baseline": True}
    clean.gate_error = "EDGEGUARD_LAST_BACKUP_AT is not set"
    dag._baseline_acquire_lock(**_context(BASELINE_A, conf))
    with pytest.raises(dag.AirflowException, match="BASELINE_CLEAN refused"):
        dag._baseline_clean(**_context(BASELINE_A, conf))
    assert not lock.path.exists()

    marker = dag._baseline_start_summary(**_context(BASELINE_A, conf))
    assert marker["started"] is True
    assert _holder_on_disk(lock.path) == BASELINE_A["run_id"]
    # Idempotent while the run holds the lock (the additive path, or a cleared baseline_start).
    assert dag._baseline_start_summary(**_context(BASELINE_A, {}))["started"] is True


def test_baseline_start_refuses_while_another_run_holds_the_lock(dag, lock, monkeypatch):
    monkeypatch.setattr(dag, "get_baseline_config", lambda context=None: (0, 730))
    dag._baseline_acquire_lock(**_context(BASELINE_B, {}))
    with pytest.raises(dag.AirflowException, match="baseline_start: another baseline holds the baseline lock"):
        dag._baseline_start_summary(**_context(BASELINE_A, {}))
    assert _holder_on_disk(lock.path) == BASELINE_B["run_id"]


def test_the_suite_keeps_the_lock_sentinel_outside_the_checkout():
    """``tests/conftest.py`` points the lock at a temporary path: a test calling ``baseline_start`` with a
    ``MagicMock`` DAG run would otherwise write ``checkpoints/baseline_in_progress.lock`` in the checkout."""
    path = Path(baseline_lock.baseline_lock_path()).resolve()
    assert not path.is_relative_to(_ROOT.resolve()), path
