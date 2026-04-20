"""
PR-K1 — Baseline resume robustness regression suite.

Fixes three flow-audit findings that collectively break the
restart-without-data-loss story for a 730-day baseline:

  * §2-3 — Corrupt checkpoint recovery: the on-disk JSON getting
    truncated by a power-loss / SIGKILL would silently wipe all
    per-source baseline progress on next load. Fix: preserve the
    corrupt bytes as ``baseline_checkpoint.json.corrupt.{timestamp}``
    and escalate log level to ERROR.

  * §2-1 — ``save_checkpoint`` exception handling: the function
    swallowed every write error with a WARN log, letting an
    ENOSPC / permission failure during a 730-day run silently
    desync the in-memory counter from the on-disk state. Fix:
    re-raise so callers (and their Prometheus error accounting)
    can handle it.

  * §1-8 — Additive-baseline checkpoint preservation: the DAG's
    ``_baseline_start_summary`` task unconditionally called
    ``clear_checkpoint()`` on every baseline run, including
    additive ones — killing the resume path that the rest of the
    checkpoint machinery was built to support. Fix:
    ``_baseline_start_summary`` no longer touches checkpoint state;
    the fresh-baseline path still wipes via the separate
    ``_baseline_clean`` task.

**Intentionally scoped out of PR-K1:** §2-8 (fresh-baseline →
incremental cursor handoff) needs a design decision about what
cursor value to set at baseline completion and breaks an existing
pin-test that encodes the ``true clean slate`` operator invariant.
The §1-8 fix above ALREADY closes the ADDITIVE-baseline half of
§2-8 by preserving cursors on additive runs; the remaining
fresh-baseline-only handoff is deferred to a dedicated PR.

Each fix has behavioural tests that prove the bug is closed, plus
source-pin tests that guard against silent regressions.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_checkpoint_dir(tmp_path, monkeypatch):
    """Redirect ``baseline_checkpoint`` state into a per-test directory.

    The module captures the checkpoint path at import time via
    ``EDGEGUARD_CHECKPOINT_DIR``. To mutate that, we set the env var
    + reload the module; we restore afterwards so other tests see the
    normal project-default path.

    The path-traversal guard requires the dir to be INSIDE the project
    root, so we use ``tmp_path / "inside_repo"`` placed as a child of
    the repo. Safer: we use a repo-child dir and clean up.
    """
    safe_dir = REPO_ROOT / ".pytest_k1_checkpoint_tmp"
    safe_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("EDGEGUARD_CHECKPOINT_DIR", str(safe_dir))

    import baseline_checkpoint

    importlib.reload(baseline_checkpoint)

    yield safe_dir, baseline_checkpoint

    # Cleanup
    for entry in safe_dir.iterdir():
        try:
            entry.unlink()
        except OSError:
            pass
    if safe_dir.exists() and not any(safe_dir.iterdir()):
        safe_dir.rmdir()
    # Restore module to normal state
    monkeypatch.delenv("EDGEGUARD_CHECKPOINT_DIR", raising=False)
    importlib.reload(baseline_checkpoint)


# ===========================================================================
# §2-3 — Corrupt checkpoint recovery
# ===========================================================================


class TestCorruptCheckpointRecovery:
    """A corrupt checkpoint JSON MUST be preserved as evidence
    before ``load_checkpoint`` returns ``{}``. The file rename is
    the forensic artifact the operator needs to recover from the
    class of bug where a truncated write wiped two years of
    baseline progress on the next resume."""

    def test_corrupt_file_preserved_as_timestamped_backup(self, isolated_checkpoint_dir, caplog):
        """Write a corrupt JSON, call load_checkpoint, assert:
        (a) function returns ``{}`` (existing contract preserved),
        (b) corrupt file is gone from the checkpoint path,
        (c) a ``baseline_checkpoint.json.corrupt.*`` sibling exists
            with the original corrupt bytes intact,
        (d) the log event is at ERROR level."""
        import logging

        safe_dir, bc = isolated_checkpoint_dir
        corrupt_bytes = b'{"nvd": {"page": 42, "current_page"'  # truncated mid-field
        bc.CHECKPOINT_FILE.write_bytes(corrupt_bytes)

        caplog.set_level(logging.ERROR, logger="baseline_checkpoint")
        result = bc.load_checkpoint()

        assert result == {}, "load_checkpoint must still return empty dict on parse failure"
        assert not bc.CHECKPOINT_FILE.exists(), "corrupt file must be moved out of the way"

        # Find the preserved backup
        backups = list(safe_dir.glob("baseline_checkpoint.json.corrupt.*"))
        assert len(backups) == 1, f"expected exactly one .corrupt.* backup; got {backups}"
        assert backups[0].read_bytes() == corrupt_bytes, "backup bytes must match the original corrupt file"

        # Log must be ERROR level with CORRUPT marker for alert rules
        assert any(rec.levelno == logging.ERROR and "CORRUPT CHECKPOINT" in rec.message for rec in caplog.records), (
            f"expected ERROR log; got {[(r.levelname, r.message) for r in caplog.records]}"
        )

    def test_returns_empty_dict_when_rename_fails(self, isolated_checkpoint_dir, monkeypatch, caplog):
        """If the rename itself fails (e.g. read-only filesystem),
        load_checkpoint still returns {} — the primary bug (silent
        fresh start with no preservation) is logged, and we don't
        crash because the backup couldn't be taken."""
        import logging
        from pathlib import Path as _Path

        _, bc = isolated_checkpoint_dir
        bc.CHECKPOINT_FILE.write_bytes(b"{not valid json")

        # Force rename to fail
        original_rename = _Path.rename

        def failing_rename(self, target):  # type: ignore[no-redef]
            raise OSError("read-only filesystem (simulated)")

        monkeypatch.setattr(_Path, "rename", failing_rename)

        caplog.set_level(logging.ERROR, logger="baseline_checkpoint")
        try:
            result = bc.load_checkpoint()
        finally:
            monkeypatch.setattr(_Path, "rename", original_rename)

        assert result == {}
        # Log must mention the rename failure so operators understand why
        # no backup was stashed.
        assert any("could not preserve" in rec.message for rec in caplog.records)

    def test_valid_checkpoint_still_loads_normally(self, isolated_checkpoint_dir):
        """Sanity: the new defensive path must not regress the happy path."""
        _, bc = isolated_checkpoint_dir
        bc.save_checkpoint({"nvd": {"current_page": 42, "items_collected": 100}})

        result = bc.load_checkpoint()
        assert result == {"nvd": {"current_page": 42, "items_collected": 100}}

    def test_source_pins_corrupt_rename_logic(self):
        """Guard against a future "cleanup" that removes the rename
        step. The rename behavior must stay in ``load_checkpoint``."""
        source = (SRC / "baseline_checkpoint.py").read_text()
        assert "corrupt." in source.lower(), "load_checkpoint must preserve corrupt files with a .corrupt.* suffix"
        assert "CORRUPT CHECKPOINT" in source, "the ERROR log marker must stay for alert rules"
        # Explicit: the old silent-warn pattern must not return.
        assert "starting fresh." not in source, (
            "the old silent-fresh-start warning pattern must not return — PR-K1 §2-3 escalated it to ERROR "
            "+ forensic backup"
        )


# ===========================================================================
# §2-1 — save_checkpoint re-raises on write failure
# ===========================================================================


class TestSaveCheckpointReRaises:
    """Write failures MUST propagate out of ``save_checkpoint`` so the
    caller (and its downstream error accounting) can react. The prior
    silent-WARN behavior let a 730-day baseline silently desync
    in-memory progress from on-disk state — PR-K1 §2-1."""

    def test_save_failure_propagates_oserror(self, isolated_checkpoint_dir, monkeypatch):
        """Simulate a disk-full / permission failure during ``_atomic_write``:
        the exception must reach the caller, not be swallowed."""
        _, bc = isolated_checkpoint_dir

        def failing_atomic_write(path, data):  # type: ignore[no-redef]
            raise OSError(28, "No space left on device (simulated)")

        monkeypatch.setattr(bc, "_atomic_write", failing_atomic_write)

        with pytest.raises(OSError) as exc_info:
            bc.save_checkpoint({"nvd": {"current_page": 42}})
        assert "No space left on device" in str(exc_info.value)

    def test_save_failure_logs_at_error_level(self, isolated_checkpoint_dir, monkeypatch, caplog):
        """The write failure must appear in logs at ERROR level with
        the ``CHECKPOINT WRITE FAILED`` marker so alert rules and
        operator dashboards can surface it immediately."""
        import logging

        _, bc = isolated_checkpoint_dir

        def failing_atomic_write(path, data):  # type: ignore[no-redef]
            raise PermissionError("denied (simulated)")

        monkeypatch.setattr(bc, "_atomic_write", failing_atomic_write)

        caplog.set_level(logging.ERROR, logger="baseline_checkpoint")
        with pytest.raises(PermissionError):
            bc.save_checkpoint({"nvd": {}})

        assert any(
            rec.levelno == logging.ERROR and "CHECKPOINT WRITE FAILED" in rec.message for rec in caplog.records
        ), f"ERROR log missing; got {[(r.levelname, r.message) for r in caplog.records]}"

    def test_update_source_checkpoint_also_raises(self, isolated_checkpoint_dir, monkeypatch):
        """Downstream contract: ``update_source_checkpoint`` delegates
        to ``save_checkpoint``, so it must also raise on write
        failure. NVD collector's outer try/except then records a
        collection failure and returns a failed-status response,
        which is the exact behavior §2-1 wants."""
        _, bc = isolated_checkpoint_dir

        def failing_atomic_write(path, data):  # type: ignore[no-redef]
            raise OSError("disk error (simulated)")

        monkeypatch.setattr(bc, "_atomic_write", failing_atomic_write)

        with pytest.raises(OSError):
            bc.update_source_checkpoint("nvd", page=1, items_collected=10)

    def test_fcntl_lock_released_on_save_exception(self, isolated_checkpoint_dir, monkeypatch):
        """Critical: the fcntl lock inside update_source_checkpoint
        MUST be released even when save_checkpoint raises. The
        ``with open(...)`` context manager closes the fd, which
        releases the advisory lock automatically — but a regression
        that restructures the code could break this. Verify by
        calling update_source_checkpoint twice: first with failing
        save, then with normal save. The second call must succeed
        (proves the lock from the first call was released)."""
        _, bc = isolated_checkpoint_dir

        call_count = {"n": 0}
        original_atomic_write = bc._atomic_write

        def conditionally_failing(path, data):  # type: ignore[no-redef]
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise OSError("simulated first-call failure")
            return original_atomic_write(path, data)

        monkeypatch.setattr(bc, "_atomic_write", conditionally_failing)

        with pytest.raises(OSError):
            bc.update_source_checkpoint("nvd", page=1)

        # Second call must not deadlock (lock was released on the
        # exception path) and must succeed.
        bc.update_source_checkpoint("nvd", page=2)
        result = bc.get_source_checkpoint("nvd")
        assert result.get("current_page") == 2

    def test_source_pins_no_silent_warn(self):
        """The old silent-WARN pattern must not return."""
        source = (SRC / "baseline_checkpoint.py").read_text()
        # Strip comments (docstrings / explanation) so cautionary
        # mentions in documentation don't trigger.
        # The actual code must use ``logger.error`` + ``raise``, not
        # ``logger.warning`` followed by quiet return.
        assert "CHECKPOINT WRITE FAILED" in source
        # The old behavior: ``logger.warning("Could not save checkpoint...``.
        # Must be gone. Strip docstrings first.
        # Simplest check: look for the specific old log string literal.
        assert 'logger.warning("Could not save checkpoint' not in source, (
            "the old silent-WARN save pattern must not return — PR-K1 §2-1 escalated to ERROR + re-raise"
        )


# ===========================================================================
# §1-8 — Additive baselines preserve checkpoints
# ===========================================================================


class TestAdditiveBaselinePreservesCheckpoints:
    """``_baseline_start_summary`` must NOT wipe checkpoints on
    additive baseline runs. The old code unconditionally cleared
    — defeating the resume path that the whole checkpoint machinery
    was built to provide."""

    @pytest.fixture(scope="class")
    def dag_source(self) -> str:
        return (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()

    def test_baseline_start_summary_does_not_call_clear_checkpoint(self, dag_source: str) -> None:
        """Source-pin: the ``_baseline_start_summary`` body must not
        import or call ``clear_checkpoint``. The fresh-baseline path
        clears via ``_baseline_clean`` (a separate task); this task
        has no business wiping on additive runs."""
        # Extract the _baseline_start_summary function body
        start = dag_source.find("def _baseline_start_summary")
        assert start > 0, "_baseline_start_summary function not found"
        # End at the next top-level def or the EdgeGuard BASELINE marker
        # (the log line that leads the config printout).
        end_marker_1 = dag_source.find("\ndef ", start + 1)
        end_marker_2 = dag_source.find("\n# ", start + 1)
        end = min(e for e in (end_marker_1, end_marker_2, len(dag_source)) if e > start)
        body = dag_source[start:end]

        # The active-code region (strip comments) must not call
        # ``clear_checkpoint(``. We strip comment lines so the
        # explanatory docstring/comments that MENTION what was
        # removed don't trigger the pin.
        code_only = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))
        assert "clear_checkpoint(" not in code_only, (
            "_baseline_start_summary MUST NOT call clear_checkpoint() — "
            "additive baselines preserve checkpoints for resume (PR-K1 §1-8). "
            "The fresh-baseline path clears via _baseline_clean task instead."
        )
        # And the import should also be gone (tidy).
        assert "from baseline_checkpoint import clear_checkpoint" not in code_only, (
            "_baseline_start_summary no longer needs clear_checkpoint imported"
        )

    def test_baseline_start_summary_preserves_for_additive_runs(self, dag_source: str) -> None:
        """The log message MUST state that additive baselines preserve
        checkpoints — this is the operator-facing signal that resume
        works."""
        assert "Additive baseline: preserving checkpoints" in dag_source, (
            "the additive-baseline log line must say 'preserving checkpoints' so operators know the resume path is live"
        )

    def test_baseline_start_summary_documents_fresh_baseline_path(self, dag_source: str) -> None:
        """The log message MUST tell operators how to wipe if they
        actually wanted a fresh baseline — surface the
        ``fresh_baseline: true`` conf trigger."""
        # Extract just the _baseline_start_summary function
        start = dag_source.find("def _baseline_start_summary")
        end_marker_1 = dag_source.find("\ndef ", start + 1)
        end_marker_2 = dag_source.find("\n# ", start + 1)
        end = min(e for e in (end_marker_1, end_marker_2, len(dag_source)) if e > start)
        body = dag_source[start:end]
        # Log message mentions the fresh-baseline conf hint.
        assert "fresh_baseline" in body, (
            "_baseline_start_summary must reference the fresh_baseline conf so "
            "operators know how to opt into wipe behavior"
        )

    def test_baseline_start_uses_shared_is_truthy_helper(self, dag_source: str) -> None:
        """PR-K1 Bugbot round-1 (Medium): the truthy-check for
        ``fresh_baseline`` MUST go through ``_is_truthy_conf_value``
        (not an inline ``str(...).lower() in (...)`` check) so it
        mirrors ``_baseline_clean``'s parse exactly.

        PR-F8 extracted the helper SPECIFICALLY to prevent this drift:
        operator passes ``{"fresh_baseline": "on"}`` →
        ``_baseline_clean`` wipes correctly (helper accepts "on") but
        inline check in ``_baseline_start_summary`` didn't → operator
        sees misleading "preserving checkpoints" log. Silent operator
        confusion."""
        start = dag_source.find("def _baseline_start_summary")
        end_marker_1 = dag_source.find("\ndef ", start + 1)
        end_marker_2 = dag_source.find("\n# ", start + 1)
        end = min(e for e in (end_marker_1, end_marker_2, len(dag_source)) if e > start)
        body = dag_source[start:end]
        code_only = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))

        # Must use the shared helper
        assert "_is_truthy_conf_value(" in code_only, (
            "fresh_baseline truthy-check must use the shared _is_truthy_conf_value helper "
            "(extracted in PR-F8 to prevent drift between _baseline_clean and _baseline_start_summary)"
        )
        # And must NOT re-introduce the inline pattern
        assert 'str(conf.get("fresh_baseline", "")).lower() in' not in code_only, (
            "the inline truthy parse must not return — PR-K1 Bugbot round-1 Medium "
            "caught the exact drift PR-F8 was designed to prevent"
        )


class TestSaveCheckpointLogIncludesExceptionMessage:
    """PR-K1 Bugbot round-1 (Low): the CHECKPOINT WRITE FAILED error
    log MUST include ``str(e)`` (the actual exception message) along
    with ``type(e).__name__``. Otherwise operators can't distinguish
    ENOSPC from permission-denied from the alert alone."""

    def test_log_includes_exception_message_not_just_type(self, isolated_checkpoint_dir, monkeypatch, caplog):
        """Trigger a failure with a distinctive message and verify
        both the exception type AND the exception message appear in
        the ERROR log output."""
        import logging

        _, bc = isolated_checkpoint_dir

        def failing_atomic_write(path, data):  # type: ignore[no-redef]
            raise OSError(28, "No space left on device — distinctive marker")

        monkeypatch.setattr(bc, "_atomic_write", failing_atomic_write)

        caplog.set_level(logging.ERROR, logger="baseline_checkpoint")
        with pytest.raises(OSError):
            bc.save_checkpoint({"nvd": {}})

        error_logs = [rec.message for rec in caplog.records if rec.levelno == logging.ERROR]
        # Exception message (not just type name) must be in the log.
        assert any("No space left on device" in msg for msg in error_logs), (
            f"operator-facing error log must include the exception message, not just the type. Got: {error_logs}"
        )
        # Type name should still be there too (both, not either/or).
        assert any("OSError" in msg for msg in error_logs)


class TestNoStaleClearCheckpointsReferences:
    """PR-K1 Bugbot round-2 (Medium): when §1-8 removed the only
    consumer of the ``clear_checkpoints`` conf key from
    ``_baseline_start_summary``, three stale references survived:

    1. ``_KNOWN_BASELINE_CONF_KEYS`` still listed it, so passing
       it would silently pass conf-validation (no "did you mean?"
       warning).
    2. The ``_baseline_start_summary`` log told operators to pass
       it for "wipe incremental cursors too" — pure no-op, would
       mislead operators into thinking cursors were wiped.
    3. The docstring claimed it "flows through baseline_clean.py
       with its own opt-in" — but ``_wipe_checkpoints()`` always
       wipes everything unconditionally; no opt-in exists.

    Pin all three against regression."""

    @pytest.fixture(scope="class")
    def dag_source(self) -> str:
        return (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()

    def test_clear_checkpoints_not_in_known_baseline_conf_keys(self, dag_source: str) -> None:
        """The ``clear_checkpoints`` key MUST be absent from the
        allowlist. Otherwise an operator passing it gets no warning
        and silently believes it took effect."""
        # Find the _KNOWN_BASELINE_CONF_KEYS frozenset literal block.
        idx = dag_source.find("_KNOWN_BASELINE_CONF_KEYS = frozenset(")
        assert idx > 0, "_KNOWN_BASELINE_CONF_KEYS not found"
        # End at the closing of the literal.
        end = dag_source.find(")", idx + len("_KNOWN_BASELINE_CONF_KEYS = frozenset("))
        assert end > idx
        block = dag_source[idx:end]
        # Strip the explanatory comment block (which may legitimately
        # mention "clear_checkpoints" as the removed key).
        active_lines = [
            line for line in block.splitlines() if not line.lstrip().startswith("#") and "clear_checkpoints" in line
        ]
        assert active_lines == [], (
            f"clear_checkpoints must not appear as an active set member; "
            f"found: {active_lines}. PR-K1 Bugbot round-2 caught this drift "
            f"after §1-8 removed the consumer."
        )

    def test_baseline_start_summary_log_does_not_advertise_clear_checkpoints(self, dag_source: str) -> None:
        """The operator-facing log MUST NOT tell operators to pass
        the now-dead ``clear_checkpoints`` conf key. The mention IS
        allowed in comments (explaining what was removed), but not
        as live ``logger.info(...)`` text."""
        # Locate _baseline_start_summary body
        start = dag_source.find("def _baseline_start_summary")
        end = dag_source.find("\ndef ", start + 1)
        body = dag_source[start:end]
        # Strip comments/docstrings — same code-only view as Bugbot is
        # complaining about.
        in_doc = False
        doc_q = ""
        live_lines = []
        for line in body.splitlines():
            s = line.lstrip()
            if in_doc:
                if doc_q in s:
                    in_doc = False
                    doc_q = ""
                continue
            for q in ('"""', "'''"):
                if s.startswith(q):
                    rest = s[len(q) :]
                    if q in rest:
                        break  # single-line, skip
                    in_doc = True
                    doc_q = q
                    break
            if in_doc or s.startswith("#"):
                continue
            live_lines.append(line)
        live_code = "\n".join(live_lines)
        assert '"clear_checkpoints"' not in live_code, (
            "live (non-comment, non-docstring) code in _baseline_start_summary "
            "must not advertise the clear_checkpoints conf key — it's a no-op "
            "since PR-K1 §1-8."
        )

    def test_baseline_start_summary_advertises_fresh_baseline_instead(self, dag_source: str) -> None:
        """The replacement: operators are pointed at
        ``fresh_baseline: 'true'`` which IS still consumed (by
        ``_baseline_clean``)."""
        start = dag_source.find("def _baseline_start_summary")
        end = dag_source.find("\ndef ", start + 1)
        body = dag_source[start:end]
        # The operator-facing instruction line must mention
        # fresh_baseline as the actual lever.
        assert "fresh_baseline" in body, (
            "_baseline_start_summary must point operators at the fresh_baseline conf key as the "
            "actual control for wiping data — that's the key still consumed by _baseline_clean."
        )
