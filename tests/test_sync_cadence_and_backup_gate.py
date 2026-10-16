"""2026-06 ops-hardening bundle — sync cadence + DAG backup gate + drift pins.

Pins the four fixes shipped together after the 2026-06-11 production-readiness
audit (multi-agent, adversarially challenged):

1. **Deterministic every-other-run sync skip.** ``edgeguard_neo4j_sync``'s
   cron (``0 3 */3 * *``) fires exactly 72h apart, but ``last_sync`` was
   stamped at sync COMPLETION — so at the next fire ``elapsed`` was always
   ``72h − sync_duration < 72h`` and the ShortCircuit skipped every other
   scheduled run. Effective cadence 144h against a fixed 96h (3d+1d overlap)
   incremental fetch window = ~48h of MISP events silently dropped per cycle.
   Fix: stamp the sync START time + subtract a tolerance
   (``EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN``, default 60) in
   ``should_run_neo4j_sync``, and derive the incremental ``since`` from the
   state file (minus ``EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS``, default 1 h,
   at least 60 s, at most 720 h; 2026-10, was 1 day) so coverage survives
   skips/pauses/outages.
   2026-10: the DAG runs every 72 h (``NEO4J_SYNC_EVERY``, a timedelta
   schedule) and the guard skips a run only when the last sync started less
   than 24 h ago (``NEO4J_SYNC_MIN_GAP``): the tolerance and the
   ``NEO4J_SYNC_INTERVAL`` Variable are no longer read.

2. **Backup gate on the DAG wipe path.** The PR-F2 backup-timestamp gate ran
   only inside ``edgeguard fresh-baseline`` (CLI). A UI/API trigger with
   ``{"fresh_baseline": true}`` bypassed it entirely. Fix: shared
   ``baseline_clean.check_recent_backup_timestamp`` enforced by
   ``_enforce_dag_backup_gate`` inside ``_baseline_clean``, honoring
   ``backup_check_passed_cli`` (CLI already gated) and ``skip_backup_check``
   (audited bypass), with PR-F3 clean-install auto-skip parity.

3. **preflight_baseline.sh compose drift.** The script targeted a nonexistent
   ``airflow-worker`` service / ``edgeguard-airflow-worker`` container and
   probed a lock path (``/tmp/edgeguard/baseline_lock.sentinel``) that appears
   nowhere in the code — checks [5], [6], and [8] could never do their job.
   (PR-N35 fixed the prose in RUNBOOK.md but not the executable.)

4. **Slack alert flag.** ``EDGEGUARD_ENABLE_SLACK_ALERTS`` has been documented
   in .env.example since PR #35, but the DAG hardcoded
   ``ENABLE_SLACK_ALERTS = False`` and silently ignored it.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import time as _time
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, "dags")

DAG_PATH = "dags/edgeguard_pipeline.py"
PREFLIGHT_PATH = "scripts/preflight_baseline.sh"
CLI_PATH = "src/edgeguard.py"


def _read(path: str) -> str:
    with open(path) as fh:
        return fh.read()


def _load_dag_module():
    """Load the DAG file as an isolated module (same pattern as
    test_pr_f5_dag_conf_validation.py). Skips when Airflow isn't available."""
    spec = importlib.util.spec_from_file_location("_dag_module_cadence_test", DAG_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as e:  # pragma: no cover - environment-dependent
        pytest.skip(f"DAG module not importable in this environment: {e}")
    return module


@pytest.fixture(scope="module")
def dag_module():
    return _load_dag_module()


class _StubVariable:
    """Airflow Variable stand-in: get() returns the caller's default."""

    @staticmethod
    def get(key, default=None):
        return default

    @staticmethod
    def set(key, value):
        return None


@pytest.fixture()
def isolated_state(tmp_path, monkeypatch, dag_module):
    """Fresh state dir + no baseline lock + stubbed Airflow Variable."""
    state_dir = tmp_path / "state"
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(state_dir))
    # Point the baseline-lock probe at a path that cannot exist so the
    # mutex short-circuit inside should_run_neo4j_sync never triggers.
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(tmp_path / "no_such.lock"))
    monkeypatch.setattr(dag_module, "Variable", _StubVariable)
    return state_dir


def _write_state(state_dir, last_sync: datetime) -> str:
    state_dir.mkdir(mode=0o700, exist_ok=True)
    state_file = state_dir / "edgeguard_last_neo4j_sync.json"
    state_file.write_text(json.dumps({"last_sync": last_sync.isoformat()}))
    return str(state_file)


# ---------------------------------------------------------------------------
# Fix 1a — should_run_neo4j_sync guard (the deterministic-skip regression; 24 h since 2026-10)
# ---------------------------------------------------------------------------


class TestShouldRunNeo4jSyncCadence:
    def test_runs_when_elapsed_is_interval_minus_drift(self, dag_module, isolated_state):
        """THE 2026-06 regression: a run is due 72h after the previous one, but the
        stamp lags it by preflight+startup drift. Pre-fix this skipped
        (71.5h < 72h) — every other scheduled sync died deterministically."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=71, minutes=30))
        assert dag_module.should_run_neo4j_sync() is True

    def test_runs_after_a_sync_that_started_on_its_third_attempt(self, dag_module, isolated_state):
        """2026-10: the previous sync may start 16 h 42 min after its run was due (two failed 8 h attempts,
        two retry delays, the attempts of the two tasks before it), so the next run sees 55 h 18 min. The
        former 71 h guard skipped it, and the sync after it came 144 h after the previous run."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=55, minutes=18))
        assert dag_module.should_run_neo4j_sync() is True

    def test_skips_a_run_within_24_hours_of_the_last_sync_start(self, dag_module, isolated_state):
        """A run right after a baseline's full sync or a forced sync (both stamp the state file) is
        skipped; from 24 h on it syncs (the next scheduled sync is then at most 96 h after it)."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=23, minutes=59))
        assert dag_module.should_run_neo4j_sync() is False
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=24, minutes=1))
        assert dag_module.should_run_neo4j_sync() is True

    def test_the_former_settings_are_not_read(self, dag_module, isolated_state, monkeypatch):
        """``NEO4J_SYNC_INTERVAL`` (Airflow Variable) and ``EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN`` set the
        former guard; the bound is now fixed (the alert thresholds are derived from it)."""

        class _Interval(_StubVariable):
            @staticmethod
            def get(key, default=None):
                return "144" if key == "NEO4J_SYNC_INTERVAL" else default

        monkeypatch.setattr(dag_module, "Variable", _Interval)
        monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN", "0")
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=30))
        assert dag_module.should_run_neo4j_sync() is True
        assert dag_module.NEO4J_SYNC_MIN_GAP == timedelta(hours=24)
        assert dag_module.NEO4J_SYNC_EVERY == timedelta(days=3)

    def test_runs_when_no_state_file(self, dag_module, isolated_state):
        assert dag_module.should_run_neo4j_sync() is True


# ---------------------------------------------------------------------------
# Fix 1b — run_neo4j_sync stamps START time and derives `since` from state
# ---------------------------------------------------------------------------


class _FakeSync:
    """Captures run() kwargs; sleeps so a completion-time stamp would be
    measurably later than the start-time stamp the fix requires."""

    captured: dict = {}
    init_args: tuple | None = None

    def __init__(self, *args, **kwargs):
        self._last_sync_failure_reason = None
        _FakeSync.init_args = (args, kwargs)

    def run(self, incremental=True, since=None, sector=None):
        _FakeSync.captured = {
            "incremental": incremental,
            "since": since,
            "entered_at": datetime.now(timezone.utc),
        }
        _time.sleep(1.5)
        return True


@pytest.fixture()
def fake_sync_module(monkeypatch):
    fake = ModuleType("run_misp_to_neo4j")
    fake.MISPToNeo4jSync = _FakeSync
    monkeypatch.setitem(sys.modules, "run_misp_to_neo4j", fake)
    _FakeSync.captured = {}
    return fake


class TestRunNeo4jSyncWindowAndStamp:
    def _run(self, dag_module, monkeypatch):
        monkeypatch.setattr(dag_module, "ensure_metrics_server", lambda: None)
        monkeypatch.setattr(dag_module, "record_neo4j_sync_duration", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "record_dag_run", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "METRICS_SERVER_AVAILABLE", False)
        dag_module.run_neo4j_sync()

    def test_since_derived_from_state_file_with_overlap(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch
    ):
        last_sync = datetime.now(timezone.utc) - timedelta(hours=200)  # paused-DAG scenario
        _write_state(isolated_state, last_sync)

        self._run(dag_module, monkeypatch)

        captured = _FakeSync.captured
        assert captured["incremental"] is True
        assert captured["since"] is not None, (
            "run_neo4j_sync must derive `since` from the state file so the fetch "
            "window covers everything since the last successful sync — the fixed "
            "3d+1d window silently drops the excess after skips/pauses/outages"
        )
        assert captured["since"] == last_sync - timedelta(hours=1), "window must be last_sync − 1h default overlap"

    def test_overlap_env_override(self, dag_module, isolated_state, fake_sync_module, monkeypatch):
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", "6")

        self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(hours=6)

    @pytest.mark.parametrize("raw", ["abc", "-2", "nan", "inf"])
    def test_invalid_overlap_env_falls_back_to_default(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog, raw
    ):
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", raw)

        with caplog.at_level(logging.WARNING):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(hours=1)
        assert any(
            "Invalid EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS" in r.getMessage() and raw in r.getMessage()
            for r in caplog.records
        )

    @pytest.mark.parametrize("raw", ["", "   "])
    def test_empty_overlap_env_is_silent_default(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog, raw
    ):
        """Set but empty (a deployment outside docker-compose.yml, which itself sets ``1``)
        behaves like unset: the 1 h default, without an invalid-value warning on every run."""
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", raw)

        with caplog.at_level(logging.WARNING):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(hours=1)
        assert not any("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS" in r.getMessage() for r in caplog.records), (
            "an empty value must not emit a spurious invalid-value warning"
        )

    @pytest.mark.parametrize("raw", ["721", "2e7", "1e400"])
    def test_overlap_above_bound_warns_and_does_not_fail_the_run(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog, raw
    ):
        """A huge value (2e7 h) used to raise OverflowError on ``last_sync − overlap`` and
        fail every run; above 720 h it is invalid, logged and replaced by the default."""
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", raw)

        with caplog.at_level(logging.WARNING):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(hours=1)
        assert any(
            "Invalid EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS" in r.getMessage() and raw in r.getMessage()
            for r in caplog.records
        )

    def test_overlap_at_bound_is_used(self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog):
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", "720")

        with caplog.at_level(logging.INFO):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(hours=720)
        # The log states whole seconds, not exponent form ("2.592e+06 s").
        assert any("− 2592000 s overlap" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("raw", ["0", "0.0", "-0", "0.01", "1e-9"])
    def test_overlap_below_floor_is_raised_to_60_seconds(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog, raw
    ):
        """0 (or anything under 60 s) removed the margin: MISP timestamps are whole seconds, so
        an attribute stamped in the second the previous sync started was never read."""
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", raw)

        with caplog.at_level(logging.WARNING):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(seconds=60)
        assert any("below the minimum of 60 s" in r.getMessage() for r in caplog.records)

    def test_overlap_of_exactly_60_seconds_is_kept_without_warning(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch, caplog
    ):
        last_sync = datetime.now(timezone.utc) - timedelta(hours=10)
        _write_state(isolated_state, last_sync)
        monkeypatch.setenv("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS", str(1 / 60))

        with caplog.at_level(logging.WARNING):
            self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["since"] == last_sync - timedelta(seconds=60)
        assert not any("EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS" in r.getMessage() for r in caplog.records)

    def test_state_date_at_datetime_minimum_falls_back_to_fixed_window(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch
    ):
        """``last_sync − overlap`` below ``datetime.min`` raises OverflowError; the run falls
        back to the fixed window like any unreadable state file instead of failing."""
        _write_state(isolated_state, datetime(1, 1, 1, 0, 30, tzinfo=timezone.utc))

        self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["incremental"] is True
        assert _FakeSync.captured["since"] is None

    def test_state_file_stamped_with_start_time_not_completion(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch
    ):
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=200))
        t_before = datetime.now(timezone.utc)

        self._run(dag_module, monkeypatch)

        state_file = isolated_state / "edgeguard_last_neo4j_sync.json"
        stamped = datetime.fromisoformat(json.loads(state_file.read_text())["last_sync"])
        entered = _FakeSync.captured["entered_at"]
        assert stamped >= t_before - timedelta(seconds=1)
        # The fake sync sleeps 1.5s after being entered; a completion-time
        # stamp would land ≥ entered_at + 1.5s. Start-time stamps land before
        # run() was even entered.
        assert stamped <= entered + timedelta(seconds=0.25), (
            f"state file must record the sync START time (deterministic-skip fix); "
            f"got {stamped.isoformat()} vs run() entry {entered.isoformat()} — "
            "a completion-time stamp re-introduces the every-other-run skip"
        )

    def test_the_sync_and_the_job_of_a_run_are_given_no_time(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch
    ):
        """2026-10-16: the indicator aging is evaluated at the database's current time, lifted to a
        node's ``aging_evaluated_at`` (``indicator_aging``), so the DAG passes no time of the run: the
        sync is built without one and the enrichment runner gets the client only, for a newer run and
        an older run cleared after it alike, and no Airflow Variable is read or set for the aging."""
        monkeypatch.setattr(dag_module, "ensure_metrics_server", lambda: None)
        monkeypatch.setattr(dag_module, "record_neo4j_sync_duration", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "record_dag_run", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "METRICS_SERVER_AVAILABLE", False)
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: True)
        keys: list = []

        class _Variable(_StubVariable):
            @staticmethod
            def get(key, default=None):
                keys.append(key)
                return default

            @staticmethod
            def set(key, value):
                keys.append(key)

        monkeypatch.setattr(dag_module, "Variable", _Variable)
        jobs: list = []

        def run_all_enrichment_jobs(*args, **kwargs):
            jobs.append((args, kwargs))
            return {}

        class _Client:
            def connect(self):
                return True

            def close(self):
                return None

        monkeypatch.setitem(
            sys.modules, "enrichment_jobs", SimpleNamespace(run_all_enrichment_jobs=run_all_enrichment_jobs)
        )
        monkeypatch.setitem(sys.modules, "neo4j_client", SimpleNamespace(Neo4jClient=_Client))

        # A newer run, then an older run cleared and re-run.
        for due in (
            datetime(2026, 10, 16, 3, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 10, 3, 0, tzinfo=timezone.utc),
        ):
            _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=200))
            _FakeSync.init_args = None
            dag_module.run_neo4j_sync(data_interval_end=due)
            dag_module.run_enrichment_jobs(data_interval_end=due)
            assert _FakeSync.init_args == ((), {}), due
            (args, kwargs) = jobs[-1]
            assert len(args) == 1 and isinstance(args[0], _Client) and kwargs == {}, due
        assert not [k for k in keys if "AGING" in str(k).upper()], keys

    def test_corrupt_state_file_falls_back_to_fixed_window(
        self, dag_module, isolated_state, fake_sync_module, monkeypatch
    ):
        isolated_state.mkdir(mode=0o700, exist_ok=True)
        (isolated_state / "edgeguard_last_neo4j_sync.json").write_text("{not json")

        self._run(dag_module, monkeypatch)

        assert _FakeSync.captured["incremental"] is True
        assert _FakeSync.captured["since"] is None, (
            "unreadable state file must fall back to the fixed EDGEGUARD_SYNC_INTERVAL_DAYS window (since=None)"
        )


# ---------------------------------------------------------------------------
# Fix 1c — manual ``force_sync`` past the guards; no SKIP_NEXT after a full sync
# ---------------------------------------------------------------------------


class _RecordingVariable:
    """Airflow Variable stand-in backed by a dict."""

    store: dict = {}

    @classmethod
    def get(cls, key, default=None):
        return cls.store.get(key, default)

    @classmethod
    def set(cls, key, value):
        cls.store[key] = value


def _forced(value=True):
    return {"dag_run": SimpleNamespace(conf={"force_sync": value})}


class TestForceSyncAndSkipNext:
    @pytest.fixture()
    def variables(self, dag_module, isolated_state, monkeypatch):
        _RecordingVariable.store = {}
        monkeypatch.setattr(dag_module, "Variable", _RecordingVariable)
        return _RecordingVariable.store

    def _run(self, dag_module, monkeypatch, **context):
        monkeypatch.setattr(dag_module, "ensure_metrics_server", lambda: None)
        monkeypatch.setattr(dag_module, "record_neo4j_sync_duration", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "record_dag_run", lambda *_a, **_k: None)
        monkeypatch.setattr(dag_module, "METRICS_SERVER_AVAILABLE", False)
        dag_module.run_neo4j_sync(**context)

    def test_force_sync_bypasses_the_interval(self, dag_module, isolated_state, variables):
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=1))
        assert dag_module.should_run_neo4j_sync() is False
        assert dag_module.should_run_neo4j_sync(**_forced()) is True
        assert dag_module.should_run_neo4j_sync(**_forced("false")) is False
        assert dag_module.should_run_neo4j_sync(dag_run=SimpleNamespace(conf=None)) is False

    def test_force_sync_ignores_and_keeps_skip_next(
        self, dag_module, isolated_state, variables, fake_sync_module, monkeypatch
    ):
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=1))
        variables["SKIP_NEXT_NEO4J_SYNC"] = "true"
        self._run(dag_module, monkeypatch, **_forced())
        assert _FakeSync.captured["incremental"] is True, "forced run must sync"
        assert variables["SKIP_NEXT_NEO4J_SYNC"] == "true", "forced run must not consume the operator flag"

    def test_skip_next_is_still_consumed_without_force(
        self, dag_module, isolated_state, variables, fake_sync_module, monkeypatch
    ):
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=1))
        variables["SKIP_NEXT_NEO4J_SYNC"] = "true"
        self._run(dag_module, monkeypatch)
        assert _FakeSync.captured == {}, "flagged run must skip the sync"
        assert variables["SKIP_NEXT_NEO4J_SYNC"] == "false"

    def test_full_sync_no_longer_sets_skip_next(
        self, dag_module, isolated_state, variables, fake_sync_module, monkeypatch
    ):
        # No state file → first run → full sync.
        self._run(dag_module, monkeypatch)
        assert _FakeSync.captured["incremental"] is False
        assert "SKIP_NEXT_NEO4J_SYNC" not in variables, (
            "incremental runs write only changed attributes now, so the post-full-sync skip only delays data"
        )


# ---------------------------------------------------------------------------
# Fix 2 — backup gate enforced on the DAG wipe path
# ---------------------------------------------------------------------------


# Import the REAL BaselineState up front: the fake probe below must return
# genuine instances so the gate's attribute access is exercised against the
# actual dataclass interface. (Review round 1 caught the first version of
# this fixture returning a SimpleNamespace with an invented attribute —
# which masked an AttributeError in the gate while all tests stayed green.)
from baseline_clean import BaselineState  # noqa: E402  (after sys.path setup)


def _real_state(
    *,
    reachable: bool,
    neo4j_count: int,
    misp_count: int,
    checkpoint_count: int = 0,
    checkpoint_ok: bool | None = None,
) -> BaselineState:
    return BaselineState(
        neo4j_count=neo4j_count,
        neo4j_ok=reachable,
        misp_count=misp_count,
        misp_ok=reachable,
        checkpoint_count=checkpoint_count,
        checkpoint_ok=reachable if checkpoint_ok is None else checkpoint_ok,
    )


@pytest.fixture()
def fake_baseline_clean(monkeypatch):
    """Inject a fake `baseline_clean` module so the gate's lazy imports hit
    controllable stubs (and the real wipe can never run from a test). The
    probe returns REAL BaselineState instances — see note above."""
    fake = ModuleType("baseline_clean")
    calls = SimpleNamespace(
        reset_called=False,
        gate_error=None,
        probe_state=_real_state(reachable=True, neo4j_count=350_000, misp_count=8_000),
        probe_raises=False,
    )

    def check_recent_backup_timestamp():
        return calls.gate_error

    def probe_baseline_state(client=None):
        if calls.probe_raises:
            raise RuntimeError("probe blew up")
        return calls.probe_state

    class BaselineCleanError(RuntimeError):
        pass

    def reset_baseline_data(**kwargs):
        calls.reset_called = True
        calls.reset_kwargs = kwargs
        return SimpleNamespace(
            before=SimpleNamespace(neo4j_count=1, misp_count=2, checkpoint_count=3),
            duration_seconds=0.1,
        )

    fake.check_recent_backup_timestamp = check_recent_backup_timestamp
    fake.probe_baseline_state = probe_baseline_state
    fake.BaselineCleanError = BaselineCleanError
    fake.reset_baseline_data = reset_baseline_data
    monkeypatch.setitem(sys.modules, "baseline_clean", fake)
    return calls


def _run_baseline_clean(dag_module, conf):
    context = {"dag_run": SimpleNamespace(conf=conf)}
    return dag_module._baseline_clean(**context)


class TestDagBackupGate:
    GATE_FAIL_MSG = "EDGEGUARD_LAST_BACKUP_AT is not set"

    def test_fresh_baseline_without_backup_refuses(self, dag_module, fake_baseline_clean):
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        with pytest.raises(Exception, match="BASELINE_CLEAN refused"):
            _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is False, (
            "the destructive wipe MUST NOT run when the backup gate refuses — "
            "this is the exact UI/API bypass the 2026-06 fix closes"
        )

    def test_fresh_baseline_with_recent_backup_proceeds(self, dag_module, fake_baseline_clean):
        fake_baseline_clean.gate_error = None  # gate passes
        _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is True

    def test_cli_flag_skips_in_container_recheck(self, dag_module, fake_baseline_clean, caplog):
        """`edgeguard fresh-baseline` runs the gate on the HOST (where
        EDGEGUARD_LAST_BACKUP_AT lives) before triggering — the container
        env may lack the var, so the DAG must honor the CLI's attestation.
        The attestation is unverifiable (a bare conf key, replayable from
        any past dag_run), so it must be logged at WARNING for audit parity
        with skip_backup_check."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        with caplog.at_level(logging.WARNING):
            _run_baseline_clean(dag_module, {"fresh_baseline": True, "backup_check_passed_cli": True})
        assert fake_baseline_clean.reset_called is True
        assert any("backup_check_passed_cli" in r.message and r.levelno >= logging.WARNING for r in caplog.records), (
            "the unverifiable CLI attestation must be WARNING-visible to log-level-based audit review"
        )

    def test_explicit_skip_conf_bypasses(self, dag_module, fake_baseline_clean, caplog):
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        with caplog.at_level(logging.WARNING):
            _run_baseline_clean(dag_module, {"fresh_baseline": True, "skip_backup_check": True})
        assert fake_baseline_clean.reset_called is True
        assert any("BACKUP GATE BYPASSED" in r.message for r in caplog.records), (
            "the bypass must be loudly logged — it is an audited operator decision"
        )

    def test_clean_install_autoskips_gate(self, dag_module, fake_baseline_clean):
        """PR-F3 parity: empty + reachable stores → nothing to lose → no
        backup required (first-time setup must not be blocked). Uses a REAL
        BaselineState so the gate's attribute access is interface-checked."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        fake_baseline_clean.probe_state = _real_state(reachable=True, neo4j_count=0, misp_count=0)
        _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is True

    def test_clean_install_ignores_leftover_checkpoints(self, dag_module, fake_baseline_clean):
        """CLI parity detail (PR-F3): checkpoint files are cursor state, not
        user data — leftovers on an emptied graph must still auto-skip."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        fake_baseline_clean.probe_state = _real_state(reachable=True, neo4j_count=0, misp_count=0, checkpoint_count=7)
        _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is True

    def test_failed_checkpoint_probe_blocks_autoskip(self, dag_module, fake_baseline_clean):
        """Bugbot (PR #125): the checkpoint COUNT is ignored, but a FAILED
        checkpoint probe must still block the auto-skip — the CLI path
        refuses on any failed probe via all_reachable, and the DAG gate
        claims parity with it. Empty-but-unprobeable ≠ clean install."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        fake_baseline_clean.probe_state = _real_state(reachable=True, neo4j_count=0, misp_count=0, checkpoint_ok=False)
        with pytest.raises(Exception, match="BASELINE_CLEAN refused"):
            _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is False

    def test_unreachable_stores_are_not_clean_install(self, dag_module, fake_baseline_clean):
        """probe_baseline_state reports unreachable stores via ok-flags with
        count=0 (it does NOT raise) — zero-counts with dead probes must
        enforce the gate, not auto-skip (fail-closed)."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        fake_baseline_clean.probe_state = _real_state(reachable=False, neo4j_count=0, misp_count=0)
        with pytest.raises(Exception, match="BASELINE_CLEAN refused"):
            _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is False

    def test_probe_failure_fails_closed(self, dag_module, fake_baseline_clean):
        """A raising probe is NOT a clean install — the gate must still run."""
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        fake_baseline_clean.probe_raises = True
        with pytest.raises(Exception, match="BASELINE_CLEAN refused"):
            _run_baseline_clean(dag_module, {"fresh_baseline": True})
        assert fake_baseline_clean.reset_called is False

    def test_gate_uses_only_real_baselinestate_attributes(self, dag_module):
        """Interface pin: every attribute _enforce_dag_backup_gate reads off
        the probe result must exist on the REAL BaselineState dataclass.
        Guards against the exact drift review round 1 caught (the gate read
        an invented `is_clean_install` that only the test stub defined)."""
        import inspect

        gate_src = inspect.getsource(dag_module._enforce_dag_backup_gate)
        import re

        accessed = set(re.findall(r"\bstate\.([A-Za-z_][A-Za-z0-9_]*)", gate_src))
        assert accessed, "expected the gate to read probe-state attributes"
        real_attrs = {f.name for f in __import__("dataclasses").fields(BaselineState)} | {
            name for name, val in vars(BaselineState).items() if isinstance(val, property)
        }
        missing = accessed - real_attrs
        assert not missing, f"gate reads attributes missing from the real BaselineState: {sorted(missing)}"

    def test_additive_mode_never_touches_gate(self, dag_module, fake_baseline_clean):
        fake_baseline_clean.gate_error = self.GATE_FAIL_MSG
        _run_baseline_clean(dag_module, {})  # no fresh_baseline → additive no-op
        assert fake_baseline_clean.reset_called is False

    def test_new_conf_keys_are_known_to_validator(self, dag_module):
        """The CLI now sends backup_check_passed_cli — the PR-F5 typo
        validator must not WARN on it (or on the documented bypass key)."""
        assert "backup_check_passed_cli" in dag_module._KNOWN_BASELINE_CONF_KEYS
        assert "skip_backup_check" in dag_module._KNOWN_BASELINE_CONF_KEYS


class TestSharedGateFunction:
    """baseline_clean.check_recent_backup_timestamp — the shared (real)
    implementation, plus the edgeguard.py delegation wrapper."""

    @pytest.fixture()
    def real_baseline_clean(self):
        import baseline_clean

        return baseline_clean

    def test_unset_env_fails(self, real_baseline_clean, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        assert real_baseline_clean.check_recent_backup_timestamp() is not None

    def test_fresh_iso_z_passes(self, real_baseline_clean, monkeypatch):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", now)
        assert real_baseline_clean.check_recent_backup_timestamp() is None

    def test_epoch_seconds_pass(self, real_baseline_clean, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", str(int(_time.time()) - 3600))
        assert real_baseline_clean.check_recent_backup_timestamp() is None

    def test_stale_backup_fails(self, real_baseline_clean, monkeypatch):
        stale = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", stale)
        msg = real_baseline_clean.check_recent_backup_timestamp()
        assert msg is not None and "old" in msg

    def test_future_timestamp_fails(self, real_baseline_clean, monkeypatch):
        future = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", future)
        msg = real_baseline_clean.check_recent_backup_timestamp()
        assert msg is not None and "future" in msg

    def test_garbage_fails(self, real_baseline_clean, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", "last tuesday")
        assert real_baseline_clean.check_recent_backup_timestamp() is not None

    def test_max_age_override(self, real_baseline_clean, monkeypatch):
        two_days_ago = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", two_days_ago)
        monkeypatch.setenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", "24")
        assert real_baseline_clean.check_recent_backup_timestamp() is not None
        monkeypatch.setenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", "72")
        assert real_baseline_clean.check_recent_backup_timestamp() is None

    def test_edgeguard_wrapper_delegates(self, monkeypatch):
        """PR-F2's established import path keeps working (test_pr_f3 et al.)."""
        import edgeguard

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", now)
        assert edgeguard._check_recent_backup_timestamp() is None
        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        assert edgeguard._check_recent_backup_timestamp() is not None


# ---------------------------------------------------------------------------
# Source pins — wiring + drift (style of test_pr_f5 / test_pr_n31)
# ---------------------------------------------------------------------------


class TestSourcePins:
    def test_baseline_clean_calls_backup_gate(self):
        src = _read(DAG_PATH)
        idx = src.find("def _baseline_clean(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx : end if end > 0 else len(src)]
        assert "_enforce_dag_backup_gate(" in body, (
            "_baseline_clean must enforce the backup gate before the destructive "
            "wipe — UI/API triggers used to bypass the CLI-only PR-F2 gate"
        )

    def test_cli_passes_attestation_flag(self):
        src = _read(CLI_PATH)
        assert '_conf["backup_check_passed_cli"] = True' in src, (
            "edgeguard fresh-baseline must attest its client-side gate run in the "
            "DAG conf, or the in-container re-check breaks the CLI flow (the "
            "container env may lack EDGEGUARD_LAST_BACKUP_AT)"
        )
        assert '_conf["skip_backup_check"] = True' in src, (
            "a CLI --skip-backup-check bypass must propagate AS the bypass key "
            "(WARNING-logged by the DAG), never as a false 'gate passed' attestation"
        )

    def test_slack_flag_reads_env(self):
        src = _read(DAG_PATH)
        assert "ENABLE_SLACK_ALERTS = False" not in src, (
            "ENABLE_SLACK_ALERTS must not be hardcoded False — "
            ".env.example has documented EDGEGUARD_ENABLE_SLACK_ALERTS since PR #35"
        )
        assert 'os.getenv("EDGEGUARD_ENABLE_SLACK_ALERTS"' in src

    def test_sync_state_stamps_start_time(self):
        src = _read(DAG_PATH)
        assert '"last_sync": sync_started_at.isoformat()' in src, (
            "run_neo4j_sync must stamp the sync START time — a completion-time "
            "stamp re-introduces the deterministic every-other-run skip"
        )

    def test_preflight_targets_real_compose_names(self):
        src = _read(PREFLIGHT_PATH)
        assert "airflow-worker" not in src, (
            "preflight must not reference the nonexistent `airflow-worker` service "
            "(real service: `airflow`, container: `edgeguard_airflow` — PR-N35 "
            "fixed RUNBOOK.md; this pins the executable)"
        )
        assert "edgeguard_airflow" in src
        assert "docker compose exec -T airflow airflow dags details" in src

    def test_preflight_checks_real_lock_path(self):
        src = _read(PREFLIGHT_PATH)
        assert "/tmp/edgeguard/baseline_lock.sentinel" not in src, (
            "preflight probed a lock path that appears nowhere in the code — "
            "the real sentinel is checkpoints/baseline_in_progress.lock (src/baseline_lock.py)"
        )
        assert "baseline_in_progress.lock" in src
        assert "EDGEGUARD_BASELINE_LOCK_PATH" in src, "preflight must honor the lock-path override env var"

    def test_compose_publishes_metrics_port_loopback(self):
        src = _read("docker-compose.yml")
        assert '"127.0.0.1:8001:8001"' in src, (
            "the loopback 8001 mapping gives host access to the metrics service "
            "(Prometheus scrapes metrics:8001 over edgeguard_net since 2026-10)"
        )
        assert 'EDGEGUARD_METRICS_HOST: "127.0.0.1"' not in src, (
            "the metrics host must be parameterized (a hardcoded container-loopback "
            "literal is unreachable by any scraper and not overridable from .env)"
        )

    def test_compose_passes_backup_gate_env(self):
        src = _read("docker-compose.yml")
        assert "EDGEGUARD_LAST_BACKUP_AT" in src, (
            "the airflow container needs EDGEGUARD_LAST_BACKUP_AT for the DAG-side "
            "backup gate to be satisfiable on UI/API triggers"
        )

    def test_env_example_says_the_tolerance_knob_is_no_longer_read(self):
        # 2026-10: the sync guard is a fixed 24 h; the knob is gone from compose and documented as unread.
        src = _read(".env.example")
        assert "EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN and the Airflow Variable" in src
        assert "# EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN=" not in src
        assert "EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN" not in _read("docker-compose.yml")

    def test_dag_module_emits_no_syntax_warning(self):
        """The bash_command comment used to contain a literal backslash-space
        escape inside a non-raw triple-quoted string — SyntaxWarning today,
        hard SyntaxError in a future CPython (would break DAG parsing)."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            with open(DAG_PATH) as fh:
                compile(fh.read(), DAG_PATH, "exec")
