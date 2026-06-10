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
   state file (+1d overlap) so coverage survives skips/pauses/outages.

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
# Fix 1a — should_run_neo4j_sync tolerance (the deterministic-skip regression)
# ---------------------------------------------------------------------------


class TestShouldRunNeo4jSyncCadence:
    def test_runs_when_elapsed_is_interval_minus_drift(self, dag_module, isolated_state):
        """THE regression: cron fires 72h after the previous fire, but the
        stamp lags the fire by preflight+startup drift. Pre-fix this skipped
        (71.5h < 72h) — every other scheduled sync died deterministically."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=71, minutes=30))
        assert dag_module.should_run_neo4j_sync() is True

    def test_skips_well_within_interval(self, dag_module, isolated_state):
        """A genuinely-early fire (e.g. the 24h month-boundary gap of a
        ``*/3`` day-of-month cron) must still be suppressed."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=24))
        assert dag_module.should_run_neo4j_sync() is False

    def test_skips_just_inside_tolerance_boundary(self, dag_module, isolated_state):
        """Elapsed clearly below interval−tolerance (60min default) → skip."""
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=69))
        assert dag_module.should_run_neo4j_sync() is False

    def test_tolerance_env_override(self, dag_module, isolated_state, monkeypatch):
        """A widened tolerance window admits an earlier elapsed."""
        monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN", "300")
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=68))
        assert dag_module.should_run_neo4j_sync() is True

    def test_tolerance_clamped_to_half_interval(self, dag_module, isolated_state, monkeypatch):
        """An absurd tolerance (e.g. 1 week) must not disable the skip check
        entirely — clamp at interval/2 (36h for the 72h default)."""
        monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN", str(7 * 24 * 60))
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=12))
        assert dag_module.should_run_neo4j_sync() is False

    def test_invalid_tolerance_falls_back_to_default(self, dag_module, isolated_state, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN", "not-a-number")
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=71, minutes=30))
        assert dag_module.should_run_neo4j_sync() is True

    def test_empty_string_tolerance_is_silent_default(self, dag_module, isolated_state, monkeypatch, caplog):
        """docker-compose passes `${EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN:-}`
        through, so an unconfigured deployment sees the var SET but EMPTY.
        That must behave exactly like unset (60min default) WITHOUT logging
        the 'invalid config' warning on every scheduled check."""
        monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN", "")
        _write_state(isolated_state, datetime.now(timezone.utc) - timedelta(hours=71, minutes=30))
        with caplog.at_level(logging.WARNING):
            assert dag_module.should_run_neo4j_sync() is True
        assert not any("EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN" in r.message for r in caplog.records), (
            "set-but-empty (the stock compose deployment) must not emit a spurious invalid-config warning"
        )

    def test_runs_when_no_state_file(self, dag_module, isolated_state):
        assert dag_module.should_run_neo4j_sync() is True


# ---------------------------------------------------------------------------
# Fix 1b — run_neo4j_sync stamps START time and derives `since` from state
# ---------------------------------------------------------------------------


class _FakeSync:
    """Captures run() kwargs; sleeps so a completion-time stamp would be
    measurably later than the start-time stamp the fix requires."""

    captured: dict = {}

    def __init__(self):
        self._last_sync_failure_reason = None

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
        assert captured["since"] == last_sync - timedelta(days=1), "window must be last_sync − 1d overlap"

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
# Fix 2 — backup gate enforced on the DAG wipe path
# ---------------------------------------------------------------------------


# Import the REAL BaselineState up front: the fake probe below must return
# genuine instances so the gate's attribute access is exercised against the
# actual dataclass interface. (Review round 1 caught the first version of
# this fixture returning a SimpleNamespace with an invented attribute —
# which masked an AttributeError in the gate while all tests stayed green.)
from baseline_clean import BaselineState  # noqa: E402  (after sys.path setup)


def _real_state(*, reachable: bool, neo4j_count: int, misp_count: int, checkpoint_count: int = 0) -> BaselineState:
    return BaselineState(
        neo4j_count=neo4j_count,
        neo4j_ok=reachable,
        misp_count=misp_count,
        misp_ok=reachable,
        checkpoint_count=checkpoint_count,
        checkpoint_ok=reachable,
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

    def reset_baseline_data():
        calls.reset_called = True
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
            "without the 8001 mapping, prometheus.yml's host.docker.internal:8001 "
            "scrape target can never connect — all alert rules stay inert"
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

    def test_env_example_documents_tolerance_knob(self):
        src = _read(".env.example")
        assert "EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN" in src

    def test_dag_module_emits_no_syntax_warning(self):
        """The bash_command comment used to contain a literal backslash-space
        escape inside a non-raw triple-quoted string — SyntaxWarning today,
        hard SyntaxError in a future CPython (would break DAG parsing)."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            with open(DAG_PATH) as fh:
                compile(fh.read(), DAG_PATH, "exec")
