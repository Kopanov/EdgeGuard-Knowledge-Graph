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
        narrow 'code-only' view we need."""
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
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # Single-line docstring ("""...""") — also skip
                    rest = stripped[len(quote) :]
                    if quote in rest:
                        break  # single-line, skip this line and move on
                    in_doc = True
                    doc_quote = quote
                    break
            if in_doc:
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
