"""
Regression tests for PR-F2 — most-critical audit fixes.

Two ship-blocking findings from the 8-agent production-readiness audit:

  - **Bug Hunter HIGH BH-H2 + BH2-HIGH** (corroborated by 2 independent
    Bug Hunter agents): the baseline sentinel lock was only acquired by
    the legacy CLI-runs-baseline-in-process path. PR-C made operators
    trigger via Airflow, at which point NO task in the DAG acquired the
    lock — scheduled incremental DAGs ran in parallel with the multi-hour
    baseline, racing MISP writes and Neo4j MERGEs. Fix: add
    ``baseline_lock_task`` (after misp_health, before clean) and
    ``baseline_unlock_task`` (after baseline_complete, ``ALL_DONE``).

  - **Devil's Advocate #1 + Prod Readiness BLOCK 1.1** (corroborated):
    ``edgeguard fresh-baseline`` shipped without any documented backup
    procedure or backup-timestamp gate. Fix: refuse to run unless
    ``EDGEGUARD_LAST_BACKUP_AT`` records a backup within
    ``EDGEGUARD_BACKUP_MAX_AGE_HOURS`` (default 24h). ``--skip-backup-check``
    is the dev/test escape hatch.

Naming convention: per the global Skill recommendation, future test additions
should adopt ``test_<module>_<aspect>.py``. The ``test_pr_f2_*`` name is
kept here only because this file pins multiple unrelated audit-fix contracts.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Bug Hunter HIGH BH-H2 + BH2-HIGH — baseline DAG sentinel lock
# ---------------------------------------------------------------------------


class TestBaselineDagAcquireSentinelLock:
    """The DAG must acquire the lock before destructive ops + release it
    after baseline_complete (with ``trigger_rule=ALL_DONE`` so it fires
    even on failure). Without this, scheduled incremental DAGs race the
    baseline — exactly the bug PR-A's lock work was meant to prevent."""

    def _read_dag_source(self) -> str:
        with open("dags/edgeguard_pipeline.py") as fh:
            return fh.read()

    def test_dag_defines_baseline_lock_task(self):
        src = self._read_dag_source()
        assert 'task_id="baseline_lock"' in src, "expected baseline_lock PythonOperator"
        assert "baseline_lock_task = PythonOperator(" in src
        assert "python_callable=_baseline_lock" in src

    def test_dag_defines_baseline_unlock_task_with_all_done_trigger(self):
        src = self._read_dag_source()
        assert 'task_id="baseline_unlock"' in src, "expected baseline_unlock PythonOperator"
        # Find the unlock-task block and assert ALL_DONE trigger inside it
        idx = src.find("baseline_unlock_task = PythonOperator(")
        assert idx > 0
        # Walk to matching close-paren via depth-tracking
        depth = 0
        end = idx
        for i in range(idx, len(src)):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = src[idx:end]
        assert "trigger_rule=TriggerRule.ALL_DONE" in block, (
            "unlock MUST be ALL_DONE so it fires even when upstream tasks failed"
        )

    def test_lock_task_calls_acquire_baseline_lock(self):
        src = self._read_dag_source()
        idx = src.find("def _baseline_lock(")
        assert idx > 0
        end = src.find("\ndef ", idx + 10)
        body = src[idx:end]
        assert "from baseline_lock import acquire_baseline_lock" in body
        assert "acquire_baseline_lock()" in body
        assert "AirflowException" in body, "must fail-fast when another baseline holds the lock"

    def test_unlock_task_calls_release_baseline_lock_safely(self):
        src = self._read_dag_source()
        idx = src.find("def _baseline_unlock(")
        assert idx > 0
        end = src.find("\nbaseline_lock_task", idx)
        body = src[idx:end]
        assert "from baseline_lock import release_baseline_lock" in body
        assert "release_baseline_lock(expected_pid=" in body, (
            "must pass expected_pid (from XCom) so the PID-check in release_baseline_lock "
            "passes across worker boundaries — Bugbot HIGH on commit 3122821"
        )
        # Must NOT raise on release failure — would otherwise block re-runs
        assert "except Exception" in body or "try:" in body, "release must be exception-safe"

    def test_lock_task_pushes_pid_to_xcom_for_unlock(self):
        """Bugbot HIGH on commit 3122821: ``_baseline_lock`` and
        ``_baseline_unlock`` run in DIFFERENT Airflow worker processes
        with DIFFERENT PIDs. The unlock task's PID can't match the
        sentinel's recorded PID, so ``release_baseline_lock()`` always
        no-op'd — lock persisted forever, blocking all future baselines.
        Fix: lock task pushes its PID via XCom; unlock task pulls it and
        passes via ``expected_pid=`` to bypass the same-process check
        while preserving safety (unlock must know the right PID)."""
        src = self._read_dag_source()
        idx = src.find("def _baseline_lock(")
        assert idx > 0
        end = src.find("\ndef _baseline_unlock(", idx)
        body = src[idx:end]
        assert 'xcom_push(key="baseline_lock_pid"' in body, "lock task must push its PID via XCom for the unlock task"
        # And unlock must pull it
        idx = src.find("def _baseline_unlock(")
        end = src.find("\nbaseline_lock_task", idx)
        body = src[idx:end]
        assert 'xcom_pull(task_ids="baseline_lock", key="baseline_lock_pid"' in body, (
            "unlock task must pull the lock-PID from XCom"
        )

    def test_release_baseline_lock_accepts_expected_pid_parameter(self):
        """The helper must accept ``expected_pid`` so the cross-process
        case (Airflow workers) works. Default None preserves legacy
        single-process semantics."""
        import inspect

        from baseline_lock import release_baseline_lock

        sig = inspect.signature(release_baseline_lock)
        assert "expected_pid" in sig.parameters, "release_baseline_lock must accept expected_pid parameter"
        # Default must be None so legacy callers keep working
        assert sig.parameters["expected_pid"].default is None

    def test_release_baseline_lock_uses_expected_pid_when_provided(self, tmp_path, monkeypatch):
        """Behavioural test: write a sentinel with PID X, call release
        from a process with PID Y, pass expected_pid=X — release MUST
        succeed."""
        import json

        from baseline_lock import release_baseline_lock

        # Point baseline_lock at a tmp dir
        sentinel_path = tmp_path / "baseline_in_progress.lock"
        monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(sentinel_path))

        # Write a sentinel with a fake PID (simulating "lock task wrote it")
        fake_lock_pid = 99999  # arbitrary, NOT our PID
        sentinel_path.write_text(
            json.dumps({"pid": fake_lock_pid, "host": "test", "started_at": "2026-04-19T00:00:00Z"})
        )
        assert sentinel_path.exists()

        # Call release WITHOUT expected_pid — should NOT delete (PID mismatch)
        release_baseline_lock()
        assert sentinel_path.exists(), "release without expected_pid should refuse to delete (PID mismatch)"

        # Call release WITH expected_pid=99999 — MUST delete
        release_baseline_lock(expected_pid=fake_lock_pid)
        assert not sentinel_path.exists(), "release with expected_pid matching the sentinel MUST delete the lock file"

    def test_release_baseline_lock_refuses_wrong_expected_pid(self, tmp_path, monkeypatch):
        """Safety: passing a wrong ``expected_pid`` must NOT delete the
        lock — the safety property (don't delete someone else's lock)
        is preserved across processes."""
        import json

        from baseline_lock import release_baseline_lock

        sentinel_path = tmp_path / "baseline_in_progress.lock"
        monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(sentinel_path))

        sentinel_path.write_text(json.dumps({"pid": 12345, "host": "test", "started_at": "2026-04-19T00:00:00Z"}))
        # Pass the WRONG expected PID
        release_baseline_lock(expected_pid=99999)
        assert sentinel_path.exists(), "wrong expected_pid must still refuse to delete"

    def test_dag_dependency_chain_includes_lock_before_clean_and_unlock_last(self):
        """The dependency chain MUST place lock BEFORE the destructive
        clean and unlock AFTER baseline_complete."""
        src = self._read_dag_source()
        # Find the chain definition
        idx = src.find("baseline_misp_health\n    >> baseline_lock_task")
        assert idx > 0, "expected baseline_misp_health → baseline_lock_task"
        # Verify unlock comes after baseline_complete
        chain_end_idx = src.find(">> baseline_unlock_task")
        complete_idx = src.find(">> baseline_complete")
        assert chain_end_idx > complete_idx > 0, "baseline_unlock_task must come after baseline_complete"

    def test_lock_task_has_retries_zero(self):
        """No retry on lock — if acquire fails, another baseline is
        genuinely running; retry won't help, just delays the operator's
        'this conflict needs attention' signal."""
        src = self._read_dag_source()
        idx = src.find("baseline_lock_task = PythonOperator(")
        depth = 0
        end = idx
        for i in range(idx, len(src)):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = src[idx:end]
        assert "retries=0" in block

    def test_unlock_task_has_retries_zero(self):
        """release_baseline_lock has internal PID-check that makes it
        idempotent; transient exceptions are logged and skipped, not retried."""
        src = self._read_dag_source()
        idx = src.find("baseline_unlock_task = PythonOperator(")
        depth = 0
        end = idx
        for i in range(idx, len(src)):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = src[idx:end]
        assert "retries=0" in block


# ---------------------------------------------------------------------------
# Devil's Advocate #1 + Prod Readiness BLOCK 1.1 — backup-timestamp gate
# ---------------------------------------------------------------------------


class TestBackupTimestampGate:
    """``_check_recent_backup_timestamp()`` returns None on success, error
    string on failure. Tests cover format parsing + age math + edge cases."""

    def test_gate_fails_when_env_var_unset(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        result = _check_recent_backup_timestamp()
        assert result is not None, "expected gate to fail (return error string) when unset"
        assert "EDGEGUARD_LAST_BACKUP_AT is not set" in result

    def test_gate_passes_with_recent_iso_z_timestamp(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        # 1h ago — well within the 24h default window
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", recent)
        result = _check_recent_backup_timestamp()
        assert result is None, f"gate should pass for 1h-old backup; got: {result!r}"

    def test_gate_fails_for_stale_backup(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        # 25h ago — outside the 24h default window
        stale = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", stale)
        result = _check_recent_backup_timestamp()
        assert result is not None
        assert "is 25" in result and "h old" in result, f"expected age in error: {result!r}"
        assert "max allowed: 24" in result

    def test_gate_respects_max_age_hours_override(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        # 5h-old backup; default 24h window passes; tighten to 4h, fails
        ts_5h = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", ts_5h)

        monkeypatch.setenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", "24")
        assert _check_recent_backup_timestamp() is None, "5h within 24h should pass"

        monkeypatch.setenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", "4")
        result = _check_recent_backup_timestamp()
        assert result is not None and "max allowed: 4" in result

    def test_gate_accepts_iso_with_explicit_offset(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", recent)
        assert _check_recent_backup_timestamp() is None

    def test_gate_accepts_unix_epoch(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        recent_epoch = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", str(recent_epoch))
        assert _check_recent_backup_timestamp() is None

    def test_gate_fails_on_unparseable_timestamp(self, monkeypatch):
        from edgeguard import _check_recent_backup_timestamp

        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", "not-a-timestamp")
        result = _check_recent_backup_timestamp()
        assert result is not None
        assert "not parseable" in result
        assert "ISO 8601" in result

    def test_gate_fails_on_future_timestamp(self, monkeypatch):
        """Timestamps in the future indicate a configuration error
        (system clock skew, wrong env var) — refuse rather than risk
        accepting an indefinitely-stale backup as 'recent'."""
        from edgeguard import _check_recent_backup_timestamp

        future = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", future)
        result = _check_recent_backup_timestamp()
        assert result is not None
        assert "in the future" in result

    def test_gate_treats_naive_datetime_as_utc(self, monkeypatch):
        """Operators may forget the trailing Z; assume UTC + still check
        the age (don't return a parse error for a missing timezone)."""
        from edgeguard import _check_recent_backup_timestamp

        recent_naive = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", recent_naive)
        assert _check_recent_backup_timestamp() is None


# ---------------------------------------------------------------------------
# CLI integration — fresh-baseline accepts --skip-backup-check
# ---------------------------------------------------------------------------


class TestFreshBaselineSkipBackupCheckFlag:
    """``edgeguard fresh-baseline --skip-backup-check`` must bypass the
    gate (with WARNING log) for dev/test contexts."""

    def test_argparse_includes_skip_backup_check_flag(self):
        """Parse fresh-baseline subcommand args; verify --skip-backup-check
        flag is registered."""
        # Source-pin: the flag MUST be registered on the fresh_baseline_p
        # subparser. Walking the source is the lightest-weight check that
        # doesn't require importing the entire CLI.
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find("fresh_baseline_p = subparsers.add_parser(")
        assert idx > 0
        end = src.find("\n    # Preflight", idx)
        block = src[idx:end]
        assert '"--skip-backup-check"' in block, "expected --skip-backup-check flag on fresh-baseline"

    def test_cmd_fresh_baseline_checks_skip_flag_attribute(self):
        """The command must read ``args.skip_backup_check`` to determine
        whether to invoke the gate."""
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find("def cmd_fresh_baseline(")
        assert idx > 0
        end = src.find("\ndef cmd_baseline(", idx)
        body = src[idx:end]
        assert 'getattr(args, "skip_backup_check", False)' in body, (
            "must check skip_backup_check arg before invoking the gate"
        )
        assert "_check_recent_backup_timestamp" in body, "must invoke the gate function when not skipped"


# ---------------------------------------------------------------------------
# docs/BACKUP.md exists + is referenced from README
# ---------------------------------------------------------------------------


class TestBackupDocsExist:
    """``docs/BACKUP.md`` is the operator pre-requisite document for
    fresh-baseline. README must reference it from the In-Progress section."""

    def test_backup_md_exists_and_documents_required_procedures(self):
        with open("docs/BACKUP.md") as fh:
            content = fh.read()
        # Required sections / commands
        assert "neo4j-admin database dump" in content, "Neo4j backup command required"
        assert "EDGEGUARD_LAST_BACKUP_AT" in content, "must document the env var"
        assert "EDGEGUARD_BACKUP_MAX_AGE_HOURS" in content, "must document the override"
        assert "--skip-backup-check" in content, "must document the bypass flag"
        # Restore procedure must include a worked example
        assert "Restore procedure" in content
        assert "Worked example" in content

    def test_readme_references_backup_md(self):
        """README's In-Progress section must link BACKUP.md so operators
        find it from the entry-point doc."""
        with open("README.md") as fh:
            content = fh.read()
        assert "docs/BACKUP.md" in content, "README must link to docs/BACKUP.md"

    def test_env_example_documents_last_backup_at(self):
        with open(".env.example") as fh:
            content = fh.read()
        assert "EDGEGUARD_LAST_BACKUP_AT" in content
        assert "docs/BACKUP.md" in content, ".env.example must reference the backup docs"
