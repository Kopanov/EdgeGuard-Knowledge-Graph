"""
Regression tests for PR-F2 — backup-timestamp gate + BACKUP.md procedure.

PR-F2 was originally scoped to ship two ship-blocking fixes from the 8-agent
production-readiness audit. The first (BH-H2: Airflow-side baseline lock)
was de-scoped after Bugbot caught two HIGH-severity flaws across consecutive
review rounds — both rooted in the same architectural mismatch (the legacy
PID-based primitive doesn't work in Airflow's multi-process model). Per the
global ``pr-bot-review`` Skill stop-and-ask rule, the lock-task pair was
reverted; the proper Airflow-aware lock primitive is tracked in Issue #57.

What this file pins:

  - **Devil's Advocate #1 + Prod Readiness BLOCK 1.1** (corroborated):
    ``edgeguard fresh-baseline`` shipped without any documented backup
    procedure or backup-timestamp gate. Fix: refuse to run unless
    ``EDGEGUARD_LAST_BACKUP_AT`` records a backup within
    ``EDGEGUARD_BACKUP_MAX_AGE_HOURS`` (default 240h = 10 days).
    ``--skip-backup-check`` is the dev/test escape hatch.

Naming convention: per the global Skill recommendation, future test additions
should adopt ``test_<module>_<aspect>.py``. The ``test_pr_f2_*`` name is
kept here only because this file pins multiple unrelated audit-fix contracts.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "src")


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

        # 250h ago — outside the 240h default window (10 days)
        stale = (datetime.now(timezone.utc) - timedelta(hours=250)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", stale)
        # Make sure no test-level override is leaking
        monkeypatch.delenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", raising=False)
        result = _check_recent_backup_timestamp()
        assert result is not None
        assert "is 250" in result and "h old" in result, f"expected age in error: {result!r}"
        assert "max allowed: 240" in result, f"expected default 240h in error: {result!r}"

    def test_gate_default_window_is_240_hours(self, monkeypatch):
        """Bumping the default to 240h (10 days) is the operator-preferred
        cadence — take a backup once per ~10 days. Tighten via env var
        for production-strict-RPO."""
        from edgeguard import _check_recent_backup_timestamp

        # 200h-old backup, no override → must pass under 240h default
        ts_200h = (datetime.now(timezone.utc) - timedelta(hours=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", ts_200h)
        monkeypatch.delenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", raising=False)
        assert _check_recent_backup_timestamp() is None, "200h within 240h default should pass"

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

    def test_gate_logs_freshness_state_on_pass(self, monkeypatch, caplog):
        """When the gate accepts, an INFO log line must surface the
        backup age + max window + remaining time so operators can see
        WHY the gate accepted (and how much window is left). Useful for
        debugging 'why isn't fresh-baseline running' (when stale) and
        'how many days until I need to backup again' (when passing)."""
        import logging

        from edgeguard import _check_recent_backup_timestamp

        # 6h-old backup, default 240h window
        recent = (datetime.now(timezone.utc) - timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", recent)
        monkeypatch.delenv("EDGEGUARD_BACKUP_MAX_AGE_HOURS", raising=False)

        with caplog.at_level(logging.INFO, logger="edgeguard"):
            result = _check_recent_backup_timestamp()
        assert result is None
        # The freshness-info log MUST be present
        msg = " ".join(rec.message for rec in caplog.records)
        assert "Backup-timestamp gate passed" in msg
        assert "6.0h old" in msg or "6.1h old" in msg, f"expected age in log: {msg!r}"
        assert "max 240" in msg
        assert "remaining" in msg

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
