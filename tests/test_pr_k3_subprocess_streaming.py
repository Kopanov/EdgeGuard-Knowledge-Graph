"""
PR-K3 §1-4 — bounded-memory subprocess streaming for build_relationships.

Regression coverage for ``src/subprocess_streaming.py`` and the two
call sites that use it (DAG ``run_build_relationships`` + CLI
``run_pipeline.py`` Step 5b).

## The bug

Both call sites used
``subprocess.run(..., capture_output=True, timeout=18000)``. On a
344K-node graph with 12 APOC link queries, the child emits tens of
MB of progress logs over a 5-hour run. ``capture_output=True``
buffers the ENTIRE child stdout + stderr in the parent's memory
until the child exits — real OOM risk on 8 GB Airflow workers,
especially when ``NEO4J_TX_MEMORY_MAX`` is also bumped to 8 g.

## The fix

Replace with a streaming helper that:

- Spawns the child with ``stdout=PIPE, stderr=STDOUT, bufsize=1``
  (line-buffered, merged streams)
- Drains output line-by-line in a daemon thread, logging each line
  at INFO and appending to a bounded ``deque(maxlen=200)`` for
  error-context
- Waits for exit with the same 5h deadline
- On timeout: sends ``SIGTERM``, waits 30s, escalates to ``SIGKILL``
- Returns ``(returncode, tail_lines_list)``

Memory cap: ~40 KB (200 lines × ~200 bytes/line average) vs. the
unbounded buffer.

## Tests

Behavioural (using a small Python subprocess as a stand-in for
``build_relationships.py``):
- Streaming: lines are logged as they arrive, not buffered
- Success path: returncode=0 returned, tail populated
- Failure path: non-zero returncode returned, tail has last N lines
- Timeout: SubprocessStreamTimeout raised after SIGTERM/SIGKILL
  escalation

Source-pins (guard against a future refactor reverting to
capture_output=True):
- DAG ``run_build_relationships`` uses the helper, not subprocess.run
- CLI Step 5b uses the helper, not subprocess.run
- Helper's tail buffer is bounded (``deque(maxlen=...)``)
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# Behavioural tests — the streaming helper
# ===========================================================================


class TestStreamingHelperBehavior:
    """Drive the helper with small Python subprocesses that emit
    deterministic output. We don't need the real
    ``build_relationships.py`` — we need to verify the helper itself."""

    def test_streams_lines_to_logger_as_they_arrive(self, caplog):
        """The whole point of PR-K3: lines from the child must reach
        the parent logger incrementally, not be buffered until the
        child exits. Use a child that sleeps BETWEEN prints so we
        can verify lines arrive out-of-order with the helper's
        wait() — the reader thread must be draining in parallel."""
        from subprocess_streaming import run_with_streaming_output

        caplog.set_level(logging.INFO)
        child_logger = logging.getLogger("test_streaming")

        # Child prints 3 lines with small delays in between. flush=True
        # on each print + python -u for line-buffering means they hit
        # the parent's pipe immediately.
        child_code = "import sys, time\nfor i in range(3):\n    print(f'line-{i}', flush=True)\n    time.sleep(0.05)\n"
        start = time.monotonic()
        returncode, tail = run_with_streaming_output(
            [sys.executable, "-u", "-c", child_code],
            timeout=10.0,
            child_logger=child_logger,
            line_prefix="[child] ",
        )
        elapsed = time.monotonic() - start

        assert returncode == 0
        assert tail == ["line-0", "line-1", "line-2"]
        # Sanity: the run took at least the cumulative sleep time,
        # proving we actually waited for the child (not a fast-path
        # that collected stdout buffered).
        assert elapsed >= 0.15, f"expected >=0.15s for 3× 50ms sleeps, got {elapsed}"

        # Every line must appear in caplog with the prefix.
        streamed = [rec.message for rec in caplog.records if "[child]" in rec.message]
        assert any("line-0" in m for m in streamed)
        assert any("line-1" in m for m in streamed)
        assert any("line-2" in m for m in streamed)

    def test_success_path_returns_zero_and_tail(self):
        """Clean exit with output → ``(0, tail_lines)``."""
        from subprocess_streaming import run_with_streaming_output

        child_logger = logging.getLogger("test_streaming_success")
        returncode, tail = run_with_streaming_output(
            [sys.executable, "-c", "print('ok')"],
            timeout=10.0,
            child_logger=child_logger,
        )
        assert returncode == 0
        assert tail == ["ok"]

    def test_failure_path_returns_non_zero_and_tail(self):
        """Non-zero exit → ``(returncode, tail)`` (no exception)."""
        from subprocess_streaming import run_with_streaming_output

        child_logger = logging.getLogger("test_streaming_failure")
        returncode, tail = run_with_streaming_output(
            [sys.executable, "-c", "import sys; print('bye'); sys.exit(7)"],
            timeout=10.0,
            child_logger=child_logger,
        )
        assert returncode == 7
        assert tail == ["bye"]

    def test_tail_buffer_is_bounded(self):
        """The retained-line deque MUST be capped at ``tail_lines``.
        Proves the PR-K3 memory-cap guarantee."""
        from subprocess_streaming import run_with_streaming_output

        child_logger = logging.getLogger("test_streaming_bounded")
        # Child prints 500 lines; ask helper to retain only 50.
        child_code = "for i in range(500):\n    print(f'line-{i}')\n"
        returncode, tail = run_with_streaming_output(
            [sys.executable, "-u", "-c", child_code],
            timeout=15.0,
            child_logger=child_logger,
            tail_lines=50,
        )
        assert returncode == 0
        assert len(tail) == 50, f"tail must be capped at tail_lines=50; got {len(tail)}"
        # And it must be the LAST 50 (not the first 50).
        assert tail[0] == "line-450"
        assert tail[-1] == "line-499"

    def test_timeout_sends_sigterm_then_raises(self, caplog):
        """A child that exceeds the deadline gets SIGTERM'd; if it
        exits within the grace window the helper raises
        ``SubprocessStreamTimeout``. We use a child that handles
        SIGTERM politely so the SIGKILL escalation path is NOT
        exercised here (separate test for that)."""
        from subprocess_streaming import (
            SubprocessStreamTimeout,
            run_with_streaming_output,
        )

        caplog.set_level(logging.INFO)
        child_logger = logging.getLogger("test_streaming_timeout")

        # Child sleeps longer than our deadline but handles SIGTERM
        # cleanly (the default: ``signal.SIGTERM`` → KeyboardInterrupt-
        # like termination in Python, non-zero exit).
        child_code = "import time\ntime.sleep(10)\n"
        start = time.monotonic()
        with pytest.raises(SubprocessStreamTimeout) as exc_info:
            run_with_streaming_output(
                [sys.executable, "-u", "-c", child_code],
                timeout=0.5,  # very short deadline
                child_logger=child_logger,
            )
        elapsed = time.monotonic() - start

        assert "exceeded timeout" in str(exc_info.value)
        # Helper should have escalated quickly — deadline 0.5s + some
        # buffer for process cleanup. Allow generous upper bound to
        # avoid flakes on slow CI.
        assert elapsed < 5.0, f"timeout escalation took too long: {elapsed}s"
        # The SIGTERM log should have fired.
        assert any("sending SIGTERM" in rec.message for rec in caplog.records), (
            f"expected 'sending SIGTERM' log; got {[r.message for r in caplog.records]}"
        )


# ===========================================================================
# Source-pins — guard against refactor reverting to capture_output=True
# ===========================================================================


class TestSourcePinsCaptureOutputGone:
    """Neither of the two call sites may re-introduce
    ``capture_output=True`` on the 18000-second deadline. That's the
    exact pattern PR-K3 replaced because it buffers 5 hours of stdout
    in parent memory."""

    @staticmethod
    def _strip_docstrings_and_comments(source: str) -> str:
        """Remove ``# ...`` line-comments AND triple-quoted docstrings
        so source-pins don't false-positive on prose that explains
        what was removed. We're not parsing Python syntax; a simple
        state-machine over line-by-line text is enough for the
        narrow 'code-only' view we need.

        PR-K3 Bugbot round-1 (Low): previously the single-line
        docstring branch only ``break``ed the inner ``for`` loop but
        never set a skip flag — control fell through to
        ``out.append(raw)`` and the line was included anyway.
        An explicit ``skip_this_line`` flag makes the intent match
        the behaviour."""
        out = []
        in_doc = False
        doc_quote: str = ""
        for raw in source.splitlines():
            stripped = raw.lstrip()
            if in_doc:
                if doc_quote in stripped:
                    in_doc = False
                    doc_quote = ""
                continue
            # Detect triple-quoted docstring start (either """ or ''')
            skip_this_line = False
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # Single-line docstring ("""...""") — skip the line.
                    # Multi-line — enter doc mode, skip subsequent lines
                    # until the closing quote.
                    rest = stripped[len(quote) :]
                    if quote in rest:
                        skip_this_line = True
                    else:
                        in_doc = True
                        doc_quote = quote
                    break
            if skip_this_line or in_doc:
                continue
            if stripped.startswith("#"):
                continue
            out.append(raw)
        return "\n".join(out)

    def test_dag_run_build_relationships_uses_helper(self):
        """DAG site: ``run_build_relationships`` MUST call the
        streaming helper, NOT ``subprocess.run(capture_output=True)``."""
        dag_src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        start = dag_src.find("def run_build_relationships")
        assert start > 0
        end = dag_src.find("\ndef ", start + 1)
        body = dag_src[start:end]
        code_only = self._strip_docstrings_and_comments(body)

        # New code path must use the helper.
        assert "run_with_streaming_output(" in code_only, (
            "PR-K3: run_build_relationships must call run_with_streaming_output"
        )
        # Old bad pattern — the specific call that buffered 5h of
        # stdout in parent memory. If `subprocess.run(` appears in
        # live code of this function body, something regressed.
        assert "subprocess.run(" not in code_only, (
            "PR-K3: run_build_relationships must not revert to subprocess.run(...) — "
            "that's the 5h-memory-buffer pattern the PR closed"
        )
        # The SubprocessStreamTimeout branch must be present so timeouts are handled.
        assert "SubprocessStreamTimeout" in code_only

    def test_cli_step_5b_uses_helper(self):
        """CLI site: ``run_pipeline.py`` Step 5b MUST call the
        streaming helper."""
        cli_src = (REPO_ROOT / "src" / "run_pipeline.py").read_text()
        # Locate Step 5b — uniquely identified by the log marker.
        marker = "Step 5b: build_relationships"
        idx = cli_src.find(marker)
        assert idx > 0, "could not find Step 5b marker in run_pipeline.py"
        # Grab the next ~120 lines of context.
        block = cli_src[idx : idx + 6000]
        code_only = self._strip_docstrings_and_comments(block)

        assert "run_with_streaming_output(" in code_only, "PR-K3: Step 5b must call run_with_streaming_output"
        assert "subprocess.run(" not in code_only, "PR-K3: Step 5b must not revert to subprocess.run(...)"
        # Degraded-mode log must still be there — CLI divergence from DAG preserved.
        assert "DEGRADED MODE" in code_only

    def test_helper_uses_bounded_deque(self):
        """The helper's tail buffer MUST be a bounded ``deque(maxlen=...)``
        — otherwise the memory-cap guarantee of PR-K3 evaporates."""
        helper_src = (SRC / "subprocess_streaming.py").read_text()
        code_only = "\n".join(line for line in helper_src.splitlines() if not line.lstrip().startswith("#"))
        assert "deque(maxlen=" in code_only, (
            "subprocess_streaming.py tail buffer must use deque(maxlen=...) to cap memory"
        )

    def test_helper_escalates_sigterm_to_sigkill(self):
        """Source-pin the SIGTERM → 30s grace → SIGKILL escalation
        so a future refactor can't silently remove the graceful-abort
        window (APOC needs time to roll back transactions on SIGTERM)."""
        helper_src = (SRC / "subprocess_streaming.py").read_text()
        code_only = "\n".join(line for line in helper_src.splitlines() if not line.lstrip().startswith("#"))
        assert "proc.terminate()" in code_only, "helper must send SIGTERM first"
        assert "proc.kill()" in code_only, "helper must escalate to SIGKILL after grace window"
        assert "SIGTERM_GRACE_SECONDS" in code_only, "helper must use the documented grace constant"


# ===========================================================================
# Default tail-lines cap + env-var override
# ===========================================================================


class TestDefaultTailLinesIsGenerous:
    """PR-K3 bumped the default from 200 to 2000 lines after operator
    concern that 200 was too few for common APOC failure modes.
    Verify the generous default AND the env-var override path so
    operators can tune per-deployment if needed."""

    def test_default_is_at_least_2000_lines(self):
        """The default retained-tail cap MUST be at least 2000 lines.
        200 was operator-diagnostic-tight for APOC nested-exception
        chains; 2000 gives 10x context at ~400KB memory (0.005% of
        an 8GB worker)."""
        # Import fresh so we don't pick up a prior test's env override.
        import importlib

        import subprocess_streaming

        importlib.reload(subprocess_streaming)
        assert subprocess_streaming.DEFAULT_TAIL_LINES >= 2000, (
            f"DEFAULT_TAIL_LINES must be >= 2000 for operator-facing "
            f"diagnostic context; got {subprocess_streaming.DEFAULT_TAIL_LINES}"
        )

    def test_env_var_override_honored(self, monkeypatch):
        """Operators can raise the tail-line cap via
        ``EDGEGUARD_SUBPROCESS_TAIL_LINES`` without a code change.
        Useful for debugging a particularly verbose failure class."""
        import importlib

        monkeypatch.setenv("EDGEGUARD_SUBPROCESS_TAIL_LINES", "7777")
        import subprocess_streaming

        importlib.reload(subprocess_streaming)
        assert subprocess_streaming.DEFAULT_TAIL_LINES == 7777

    def test_env_var_invalid_falls_back_to_default(self, monkeypatch, caplog):
        """Non-integer env var MUST fall back to the hard-coded default
        with a clear warning, not crash the import."""
        import importlib
        import logging

        caplog.set_level(logging.WARNING, logger="subprocess_streaming")
        monkeypatch.setenv("EDGEGUARD_SUBPROCESS_TAIL_LINES", "not-an-int")
        import subprocess_streaming

        importlib.reload(subprocess_streaming)
        assert subprocess_streaming.DEFAULT_TAIL_LINES == 2000
        assert any("not an integer" in rec.message for rec in caplog.records)

    def test_env_var_non_positive_falls_back_to_default(self, monkeypatch, caplog):
        """Zero or negative env var must also fall back — not clamp
        to 0 (which would disable tail retention entirely)."""
        import importlib
        import logging

        caplog.set_level(logging.WARNING, logger="subprocess_streaming")
        monkeypatch.setenv("EDGEGUARD_SUBPROCESS_TAIL_LINES", "0")
        import subprocess_streaming

        importlib.reload(subprocess_streaming)
        assert subprocess_streaming.DEFAULT_TAIL_LINES == 2000
        assert any("must be > 0" in rec.message for rec in caplog.records)


# ===========================================================================
# Bugbot round-1 follow-up findings (Medium + 2 Low)
# ===========================================================================


class TestImportOutsideTryBlock:
    """PR-K3 Bugbot round-1 (Medium): ``from subprocess_streaming
    import ...`` MUST be OUTSIDE the ``try`` block in ``run_pipeline.py``
    Step 5b. If the import is inside ``try`` and fails, the
    ``except SubprocessStreamTimeout as e:`` clause references an
    un-imported name → NameError propagates PAST the
    ``except Exception`` fallback, breaking the CLI's degraded-mode
    guarantee.

    The DAG site already had it outside; this pin enforces parity."""

    def test_subprocess_streaming_imported_outside_try(self):
        """The import must precede the ``try:`` block, not be inside it."""
        cli_src = (REPO_ROOT / "src" / "run_pipeline.py").read_text()
        marker = "Step 5b: build_relationships"
        idx = cli_src.find(marker)
        assert idx > 0
        block = cli_src[idx : idx + 6000]

        # Find the import statement
        import_line = "from subprocess_streaming import"
        import_idx = block.find(import_line)
        assert import_idx > 0, f"could not find {import_line!r} in Step 5b region"

        # Find the first try: block AFTER the marker
        try_idx = block.find("try:", 0)
        assert try_idx > 0, "could not find try block in Step 5b region"

        # The import MUST come before the try, not inside it.
        assert import_idx < try_idx, (
            "PR-K3 Bugbot round-1 (Medium): subprocess_streaming import must be "
            "OUTSIDE the try block. If the import fails inside try, NameError on "
            "the except clause bypasses the degraded-mode handler."
        )


class TestTimeoutMessageReflectsActualEscalation:
    """PR-K3 Bugbot round-1 (Low): ``SubprocessStreamTimeout`` message
    MUST distinguish between (a) child exited cleanly after SIGTERM
    within grace window and (b) child required SIGKILL escalation.
    Operators eyeballing the AirflowException need the right signal
    for whether to investigate APOC transaction integrity."""

    def test_clean_sigterm_message_does_not_claim_sigkill(self, caplog):
        """A child that handles SIGTERM cleanly within the grace
        window MUST get a message that says ``no SIGKILL`` — NOT a
        message that claims SIGKILL was sent."""
        import logging

        from subprocess_streaming import (
            SubprocessStreamTimeout,
            run_with_streaming_output,
        )

        caplog.set_level(logging.INFO)
        child_logger = logging.getLogger("test_clean_sigterm_msg")

        # Child that handles SIGTERM by exiting cleanly (Python's
        # default behavior: SIGTERM → KeyboardInterrupt-like).
        child_code = "import time\ntime.sleep(10)\n"
        with pytest.raises(SubprocessStreamTimeout) as exc_info:
            run_with_streaming_output(
                [sys.executable, "-u", "-c", child_code],
                timeout=0.3,
                child_logger=child_logger,
            )

        msg = str(exc_info.value)
        # The cleaner outcome — child exited within grace window — must NOT
        # claim SIGKILL was sent.
        assert "no SIGKILL" in msg, (
            f"timeout message must reflect that SIGKILL was NOT sent when child "
            f"exited cleanly within grace window; got: {msg!r}"
        )
        # The misleading old message format must not return.
        assert "→ SIGKILL" not in msg, (
            f"timeout message must not unconditionally claim SIGKILL when SIGTERM succeeded; got: {msg!r}"
        )

    def test_timeout_message_distinguishes_sigterm_vs_sigkill_paths(self):
        """Source-pin: the helper MUST track whether ``proc.kill()``
        actually fired and emit different messages for the two cases.
        Guards against a future refactor reverting to the unconditional-
        SIGKILL message."""
        helper_src = (SRC / "subprocess_streaming.py").read_text()
        # The two distinct messages must exist
        assert "no SIGKILL" in helper_src, "helper must emit a 'no SIGKILL' message when SIGTERM alone was sufficient"
        # And the SIGKILL escalation message must remain for the actual escalation path
        assert "→ SIGKILL" in helper_src
        # A boolean tracking flag must be set inside the SIGKILL branch
        assert "sigkill_sent" in helper_src, (
            "helper must track whether SIGKILL was actually sent, not just always claim it was"
        )


class TestStripDocstringsHandlesSingleLine:
    """PR-K3 Bugbot round-1 (Low): the test-helper
    ``_strip_docstrings_and_comments`` MUST actually skip single-line
    docstrings (e.g. ``\"\"\"text\"\"\"`` on one line). Previously the
    inner ``break`` exited the for loop without setting any skip
    flag, so the line was appended to the output anyway."""

    def test_single_line_docstring_is_actually_stripped(self):
        # Construct source with a single-line docstring that mentions
        # a forbidden pattern; if the stripper doesn't actually skip
        # it, our other source-pin tests would false-positive.
        from tests.test_pr_k3_subprocess_streaming import TestSourcePinsCaptureOutputGone

        source_with_singleline_doc = (
            'def some_func():\n    """This docstring mentions subprocess.run but is only prose."""\n    return 42\n'
        )
        stripped = TestSourcePinsCaptureOutputGone._strip_docstrings_and_comments(source_with_singleline_doc)
        assert "subprocess.run" not in stripped, (
            "single-line docstring must be skipped; if it leaks through, source-pin tests could false-positive on prose"
        )

    def test_multi_line_docstring_still_stripped(self):
        """Sanity: the multi-line case the helper handled correctly
        before MUST still work."""
        from tests.test_pr_k3_subprocess_streaming import TestSourcePinsCaptureOutputGone

        source_with_multiline_doc = (
            "def some_func():\n"
            '    """\n'
            "    This multi-line docstring also mentions subprocess.run.\n"
            '    """\n'
            "    return 42\n"
        )
        stripped = TestSourcePinsCaptureOutputGone._strip_docstrings_and_comments(source_with_multiline_doc)
        assert "subprocess.run" not in stripped

    def test_actual_code_lines_kept(self):
        """Non-docstring, non-comment code MUST still appear in the
        stripped output — otherwise the source-pin tests can't see
        anything."""
        from tests.test_pr_k3_subprocess_streaming import TestSourcePinsCaptureOutputGone

        source = '"""Module docstring"""\n# A line comment\nx = 1\ny = subprocess.run(cmd)\n'
        stripped = TestSourcePinsCaptureOutputGone._strip_docstrings_and_comments(source)
        # Real code must survive
        assert "x = 1" in stripped
        assert "subprocess.run(cmd)" in stripped
        # Module docstring + comment must be gone
        assert "Module docstring" not in stripped
        assert "A line comment" not in stripped
