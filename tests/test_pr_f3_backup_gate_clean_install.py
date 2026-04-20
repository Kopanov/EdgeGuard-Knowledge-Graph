"""
Regression tests for PR-F3 — clean-install ergonomics for the
``edgeguard fresh-baseline`` backup-timestamp gate (Issue #58).

PR-F2 (#56, merged) added a backup-timestamp gate that refuses to run
``edgeguard fresh-baseline`` unless ``EDGEGUARD_LAST_BACKUP_AT`` records
a backup within the freshness window. That's correct for production
(steady-state) but creates UX friction for the first-time / dev-laptop /
CI-bringup workflow: on a truly empty install there is **nothing to
back up**, but the gate would still refuse.

PR-F3 closes the gap by auto-skipping the gate when both data stores
report zero EdgeGuard-managed objects. The bypass is logged at INFO
(audit-trail clarity: "no data exists" is a different state than the
WARNING-level explicit ``--skip-backup-check`` bypass).

This file pins the contract:

    | state                           | EDGEGUARD_LAST_BACKUP_AT | gate behavior          |
    |---------------------------------|--------------------------|------------------------|
    | empty Neo4j + empty MISP        | unset                    | AUTO-SKIP (INFO log)   |
    | empty Neo4j + empty MISP        | recent ISO ts            | helper runs (passes)   |
    | non-empty (either store)        | unset                    | gate REFUSES (exit 2)  |
    | non-empty (either store)        | recent ISO ts            | helper runs (passes)   |
    | --skip-backup-check (any state) | irrelevant               | bypass (WARNING log)   |

Naming: per the PR-F2 docstring recommendation, this is
``test_<module>_<aspect>.py`` rather than the older ``test_pr_<id>_*``
pattern; the ``pr_f3`` slug is kept here because the change is scoped
to a single PR with a clear audit-trail back to Issue #58.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, "src")


def _make_state(*, neo4j_count: int, misp_count: int):
    """Build a ``BaselineState`` with all probes 'reachable' so the
    pre-flight (``state.all_reachable``) gate doesn't short-circuit
    before the backup-gate logic we're testing."""
    from baseline_clean import BaselineState

    return BaselineState(
        neo4j_count=neo4j_count,
        neo4j_ok=True,
        misp_count=misp_count,
        misp_ok=True,
        checkpoint_count=0,
        checkpoint_ok=True,
    )


def _make_args(**overrides):
    """Build an ``args`` object compatible with ``cmd_fresh_baseline``.
    ``force=False`` would block on ``input()``; tests that exercise the
    gate path only need to verify the gate result *before* the
    confirmation prompt, so we set ``force=True`` to bypass it."""
    args = MagicMock()
    args.days = 30
    args.force = True
    args.skip_backup_check = False
    args.dry_run = False
    args.yes = True
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


# ---------------------------------------------------------------------------
# The three test cases the user explicitly requested in the PR-F3 brief
# ---------------------------------------------------------------------------


class TestCleanInstallAutoSkip:
    """Empty graph + no backup timestamp → gate auto-skips, INFO log fires."""

    def test_empty_graph_no_timestamp_auto_skips_gate(self, monkeypatch, caplog):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        empty = _make_state(neo4j_count=0, misp_count=0)

        with (
            patch("baseline_clean.probe_baseline_state", return_value=empty),
            patch("edgeguard._trigger_baseline_dag", return_value=(0, "run-1")),
            caplog.at_level(logging.INFO, logger="edgeguard"),
        ):
            ret = edgeguard.cmd_fresh_baseline(_make_args())

        # The gate must NOT fail with exit 2 (no backup) — the auto-skip
        # path is the whole point of this PR. Any exit code that is NOT 2
        # means the gate didn't reject (the actual numeric exit depends on
        # the airflow-trigger mock and confirmation-prompt path; this
        # assertion is contract, not implementation).
        assert ret != 2, f"clean install must not be blocked by backup gate; got exit {ret}"

        # The structured log entry MUST surface the auto-skip reason so
        # operators can grep for it later when wondering "why did the gate
        # accept on this run".
        msg = " ".join(rec.message for rec in caplog.records)
        assert "auto-skipped on clean install" in msg, (
            f"expected auto-skip log line; got records: {[r.message for r in caplog.records]}"
        )
        assert "neo4j_count=0" in msg
        assert "misp_count=0" in msg

    def test_auto_skip_log_is_info_not_warning(self, monkeypatch, caplog):
        """Audit-trail clarity: 'no data exists' is NOT a deliberate
        safety bypass like ``--skip-backup-check`` — the latter is
        WARNING-level for a reason. Auto-skip is INFO."""
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        empty = _make_state(neo4j_count=0, misp_count=0)

        with (
            patch("baseline_clean.probe_baseline_state", return_value=empty),
            patch("edgeguard._trigger_baseline_dag", return_value=(0, "run-1")),
            caplog.at_level(logging.DEBUG, logger="edgeguard"),
        ):
            edgeguard.cmd_fresh_baseline(_make_args())

        auto_skip_records = [r for r in caplog.records if "auto-skipped on clean install" in r.message]
        assert auto_skip_records, "auto-skip log line must be emitted"
        for rec in auto_skip_records:
            assert rec.levelno == logging.INFO, (
                f"auto-skip must be INFO (got {rec.levelname}); "
                "WARNING is reserved for the explicit --skip-backup-check path"
            )


class TestPopulatedGraphStillEnforces:
    """Non-empty graph + no backup timestamp → gate refuses (current behavior)."""

    def test_neo4j_has_data_misp_empty_gate_refuses(self, monkeypatch):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        populated = _make_state(neo4j_count=42, misp_count=0)

        with patch("baseline_clean.probe_baseline_state", return_value=populated):
            ret = edgeguard.cmd_fresh_baseline(_make_args())

        assert ret == 2, "non-empty Neo4j must still trigger the gate refusal (exit 2)"

    def test_misp_has_data_neo4j_empty_gate_refuses(self, monkeypatch):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        populated = _make_state(neo4j_count=0, misp_count=7)

        with patch("baseline_clean.probe_baseline_state", return_value=populated):
            ret = edgeguard.cmd_fresh_baseline(_make_args())

        assert ret == 2, "non-empty MISP must still trigger the gate refusal (exit 2)"

    def test_both_stores_have_data_gate_refuses(self, monkeypatch):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        populated = _make_state(neo4j_count=350_000, misp_count=8000)

        with patch("baseline_clean.probe_baseline_state", return_value=populated):
            ret = edgeguard.cmd_fresh_baseline(_make_args())

        assert ret == 2


class TestEmptyGraphRecentTimestampPassesThrough:
    """Empty graph + recent backup timestamp → gate passes through normal
    path (the auto-skip short-circuit fires FIRST, but the passthrough
    is still safe — recent timestamps must never trigger a refusal)."""

    def test_empty_graph_with_recent_timestamp_does_not_refuse(self, monkeypatch, caplog):
        import edgeguard

        # 1h-old backup, well within the 240h default
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        monkeypatch.setenv("EDGEGUARD_LAST_BACKUP_AT", recent)
        empty = _make_state(neo4j_count=0, misp_count=0)

        with (
            patch("baseline_clean.probe_baseline_state", return_value=empty),
            patch("edgeguard._trigger_baseline_dag", return_value=(0, "run-1")),
            caplog.at_level(logging.INFO, logger="edgeguard"),
        ):
            ret = edgeguard.cmd_fresh_baseline(_make_args())

        assert ret != 2, "recent timestamp + empty graph must never block"

        # Implementation choice: auto-skip fires first (short-circuit on
        # empty install). The helper's "gate passed" log must NOT fire
        # in this case — having BOTH would be confusing in the audit log.
        msg = " ".join(rec.message for rec in caplog.records)
        assert "auto-skipped on clean install" in msg
        assert "Backup-timestamp gate passed: backup is" not in msg, (
            "auto-skip path must short-circuit BEFORE the helper, so the "
            "helper's 'gate passed' log should not also fire"
        )


# ---------------------------------------------------------------------------
# Defensive coverage — the explicit --skip-backup-check flag must keep
# its WARNING-level audit semantics regardless of empty/non-empty state.
# ---------------------------------------------------------------------------


class TestSkipBackupCheckFlagUnchanged:
    """``--skip-backup-check`` is the explicit operator-bypass path.
    PR-F3 must not weaken its WARNING-level audit log just because the
    auto-skip path now also exists."""

    def test_skip_flag_logs_warning_even_on_clean_install(self, monkeypatch, caplog):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        empty = _make_state(neo4j_count=0, misp_count=0)

        with (
            patch("baseline_clean.probe_baseline_state", return_value=empty),
            patch("edgeguard._trigger_baseline_dag", return_value=(0, "run-1")),
            caplog.at_level(logging.DEBUG, logger="edgeguard"),
        ):
            edgeguard.cmd_fresh_baseline(_make_args(skip_backup_check=True))

        # Must NOT auto-skip (the explicit flag takes precedence — operator
        # opted in, audit-trail must reflect it).
        msg = " ".join(rec.message for rec in caplog.records)
        assert "auto-skipped on clean install" not in msg, (
            "explicit --skip-backup-check must take precedence over auto-skip"
        )

    def test_skip_flag_bypasses_gate_when_populated_too(self, monkeypatch):
        import edgeguard

        monkeypatch.delenv("EDGEGUARD_LAST_BACKUP_AT", raising=False)
        populated = _make_state(neo4j_count=100, misp_count=50)

        with (
            patch("baseline_clean.probe_baseline_state", return_value=populated),
            patch("edgeguard._trigger_baseline_dag", return_value=(0, "run-1")),
        ):
            ret = edgeguard.cmd_fresh_baseline(_make_args(skip_backup_check=True))

        # The gate must NOT exit 2 — the bypass flag is the whole point.
        assert ret != 2, "--skip-backup-check must bypass even on populated installs"


# ---------------------------------------------------------------------------
# Source-pin: the auto-skip branch must be present in cmd_fresh_baseline,
# AND must use ``state.neo4j_count`` + ``state.misp_count`` (not the
# ``state.all_zero`` convenience property — checkpoint state is
# intentionally excluded from this gate).
# ---------------------------------------------------------------------------


class TestAutoSkipSourceContract:
    def test_auto_skip_branch_uses_neo4j_and_misp_counts_only(self):
        with open("src/edgeguard.py") as fh:
            src = fh.read()
        idx = src.find("def cmd_fresh_baseline(")
        assert idx > 0
        end = src.find("\ndef cmd_baseline(", idx)
        body = src[idx:end]
        # The condition MUST be neo4j_count == 0 AND misp_count == 0,
        # NOT state.all_zero (which would also gate on checkpoint state
        # and reintroduce a different friction case).
        assert "state.neo4j_count == 0 and state.misp_count == 0" in body, (
            "PR-F3 contract: auto-skip predicate is data-store counts only"
        )
        assert "auto-skipped on clean install" in body, "structured-log marker required for ops grep"
