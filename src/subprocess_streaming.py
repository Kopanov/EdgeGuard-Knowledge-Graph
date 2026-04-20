"""
Bounded-memory subprocess runner for long-lived child processes.

PR-K3 §1-4 — addresses the flow-audit finding that
``subprocess.run(..., capture_output=True, timeout=18000)`` was
being used for ``build_relationships.py`` in both the Airflow DAG
and the CLI baseline path. ``capture_output=True`` buffers the
ENTIRE child stdout + stderr in the parent's memory until the child
exits — on a 5-hour APOC-heavy run against a 344K-node graph, the
buffer grows to tens of megabytes of log text and adds real OOM
risk on the 8GB Airflow worker (especially when
``NEO4J_TX_MEMORY_MAX`` is also bumped).

The helper in this module replaces ``capture_output=True`` with a
streaming read: a daemon thread drains the child's merged
stdout/stderr line-by-line into the parent's logger, the main
thread waits for exit with a deadline, and on timeout the helper
sends ``SIGTERM``, grants a 30s grace window, then escalates to
``SIGKILL``. A bounded ``deque`` retains the last N lines for
error-context logging on failure — no unbounded buffer.

## Why a separate module (not inlined)

PR-L's regression tests (``tests/test_tier1_sequential_robustness.py``)
source-pin that ``src/run_pipeline.py`` has no ``threading.Thread``
— part of the tier-1 sequential-execution robustness guarantee.
Putting the reader thread in a dedicated module keeps that pin
happy: the CLI's ``run_pipeline.py`` only *calls* the helper, never
spawns raw threads itself.

## Scope

Designed specifically for ``build_relationships.py``-shaped children:
- Long-running (minutes to hours)
- Emit progress logs frequently (so line-by-line streaming is useful)
- Single-threaded reader suffices (no multiplexing needed)
- Timeout is a hard deadline (SIGTERM → 30s grace → SIGKILL)

Callers who need different semantics (short-running, binary output,
multiplexed stderr) should continue using ``subprocess.run`` directly.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from collections import deque
from typing import List, Sequence, Tuple

# Default: keep the last 2000 lines of child output for error-context
# logging if the child exits non-zero.  At ~200 bytes/line average this
# caps memory at ~400 KB — still negligible on an 8 GB Airflow worker
# (0.005% of RAM), vs. the unbounded buffer the ``capture_output``
# path accumulated over 5-hour runs.
#
# Why 2000 (not 200): a Python stack trace is 10-30 lines, but an APOC
# nested-exception chain can run 50-100 lines, a multi-query cascade
# failure easily 200+, and a Neo4j transaction retry storm with nested
# error details 100-200.  200 lines was operator-diagnostic-tight even
# for common failure classes.  2000 gives 10x the context at the same
# trivial memory footprint.
#
# **Operator override:** ``EDGEGUARD_SUBPROCESS_TAIL_LINES`` env var
# lets operators tune without a code change — e.g. raise to 20000
# (~4 MB) for a particularly gnarly diagnosis session, or drop to
# 500 on memory-constrained workers.  Non-integer or <=0 values fall
# back to the 2000-line default with a warning log.
_DEFAULT_TAIL_LINES_CONST = 2000


def _resolve_default_tail_lines() -> int:
    """Resolve ``DEFAULT_TAIL_LINES`` from the env var with a safe
    fallback. Called once at module load."""
    raw = os.getenv("EDGEGUARD_SUBPROCESS_TAIL_LINES", "").strip()
    if not raw:
        return _DEFAULT_TAIL_LINES_CONST
    try:
        value = int(raw)
    except ValueError:
        logging.getLogger(__name__).warning(
            "EDGEGUARD_SUBPROCESS_TAIL_LINES=%r is not an integer; using default=%d.",
            raw,
            _DEFAULT_TAIL_LINES_CONST,
        )
        return _DEFAULT_TAIL_LINES_CONST
    if value <= 0:
        logging.getLogger(__name__).warning(
            "EDGEGUARD_SUBPROCESS_TAIL_LINES=%d must be > 0; using default=%d.",
            value,
            _DEFAULT_TAIL_LINES_CONST,
        )
        return _DEFAULT_TAIL_LINES_CONST
    return value


DEFAULT_TAIL_LINES = _resolve_default_tail_lines()

# Grace window between SIGTERM and SIGKILL when a child exceeds its
# deadline. 30 seconds matches the sysadmin-folk-wisdom default (long
# enough for the child to flush buffers + cleanly abort APOC
# transactions; short enough that operators aren't waiting forever).
SIGTERM_GRACE_SECONDS = 30


class SubprocessStreamTimeout(Exception):
    """Raised when the child did not exit within the deadline.

    Distinct from ``subprocess.TimeoutExpired`` so callers can react
    specifically to the streaming-helper's timeout + escalation
    behavior (SIGTERM-then-SIGKILL) without catching broader
    ``subprocess`` errors."""


def _drain_output(
    proc: subprocess.Popen,
    tail_buf: deque,
    child_logger: logging.Logger,
    line_prefix: str,
) -> None:
    """Read child stdout line-by-line (merged stderr), log each at INFO,
    retain last N in the bounded deque.

    Runs in a daemon thread so the main thread can continue waiting
    on the child's exit while output streams in parallel. ``bufsize=1``
    on the ``Popen`` (text mode + line-buffered) ensures
    ``readline()`` returns as soon as the child emits a newline.
    """
    try:
        assert proc.stdout is not None, "caller must have set stdout=PIPE"
        for raw in iter(proc.stdout.readline, ""):
            line = raw.rstrip()
            if not line:
                continue
            child_logger.info("%s%s", line_prefix, line)
            tail_buf.append(line)
    finally:
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except (ValueError, OSError) as exc:
            # Expected: stdout already closed by subprocess module on
            # process exit (``ValueError: I/O operation on closed file``)
            # or pipe already torn down (``OSError``). Log at DEBUG so
            # operators who need traceability still see it but normal
            # runs don't get noise.
            #
            # PR-K3 Bugbot round-2 (Low): the prior ``except Exception: pass``
            # violated the project's bare-except-with-pass review rule.
            # Narrowing + DEBUG log preserves the close-is-harmless
            # invariant while meeting the audit contract.
            logging.getLogger(__name__).debug("stdout close on exiting child: %s", exc, exc_info=True)


def run_with_streaming_output(
    cmd: Sequence[str],
    timeout: float,
    child_logger: logging.Logger,
    *,
    tail_lines: int = DEFAULT_TAIL_LINES,
    line_prefix: str = "[child] ",
) -> Tuple[int, List[str]]:
    """Run ``cmd`` as a subprocess, stream its output to
    ``child_logger``, and return ``(returncode, tail_lines_list)``.

    - ``cmd``: argv list passed to ``subprocess.Popen``.
    - ``timeout``: hard deadline in seconds. On exceed, the child
      receives ``SIGTERM``, then after
      :data:`SIGTERM_GRACE_SECONDS` escalates to ``SIGKILL``. The
      helper then raises :class:`SubprocessStreamTimeout` so the
      caller can distinguish this from a clean non-zero exit.
    - ``child_logger``: every line emitted by the child is logged at
      INFO level. Pass the caller's module logger so Airflow's
      task-log routing works naturally.
    - ``tail_lines``: bound on the retained-line buffer for
      error-context. Capped even on successful runs — caller can
      decide whether to surface the tail (typically only on
      non-zero exit).
    - ``line_prefix``: tag prepended to every logged line so
      operators can distinguish child output from parent context.

    Returns ``(returncode, tail)`` where ``tail`` is a list of the
    last ``tail_lines`` lines (order preserved, oldest→newest).

    Raises :class:`SubprocessStreamTimeout` on deadline exceed
    (after the SIGTERM/SIGKILL escalation). Any other
    ``subprocess``-layer exception propagates unchanged so the
    caller can handle (missing binary, EACCES, etc.) with existing
    logic.
    """
    tail_buf: deque = deque(maxlen=max(1, tail_lines))

    # ``bufsize=1`` + ``text=True`` gives line-buffered UTF-8
    # readline(); ``errors="replace"`` keeps a child that emits
    # invalid bytes (e.g. an APOC exception that logs a raw
    # un-escaped byte) from crashing the reader thread.
    proc = subprocess.Popen(  # noqa: S603 — argv list, not shell=True
        list(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        errors="replace",
    )

    reader = threading.Thread(
        target=_drain_output,
        args=(proc, tail_buf, child_logger, line_prefix),
        daemon=True,
        name=f"stream-reader-pid{proc.pid}",
    )
    reader.start()

    start = time.monotonic()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        child_logger.error(
            "%schild exceeded timeout=%ss (elapsed=%.1fs); sending SIGTERM",
            line_prefix,
            timeout,
            elapsed,
        )
        proc.terminate()
        # PR-K3 Bugbot round-1 (Low): track whether SIGKILL actually
        # fired so the exception message reflects reality. Previously
        # the message unconditionally said ``SIGTERM + grace → SIGKILL``
        # even when SIGTERM alone succeeded within the grace window,
        # which in an APOC-heavy workload could trigger unnecessary
        # data-integrity investigations (SIGTERM → clean rollback;
        # SIGKILL → transactions may be interrupted mid-commit). The
        # distinction matters to operators.
        sigkill_sent = False
        try:
            proc.wait(timeout=SIGTERM_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            child_logger.error(
                "%sSIGTERM did not exit in %ds; escalating to SIGKILL",
                line_prefix,
                SIGTERM_GRACE_SECONDS,
            )
            proc.kill()
            sigkill_sent = True
            # SIGKILL cannot be caught; wait() returns promptly.
            proc.wait()
        reader.join(timeout=5)
        if sigkill_sent:
            msg = (
                f"child exceeded timeout={timeout}s (elapsed={elapsed:.1f}s); "
                f"SIGTERM + {SIGTERM_GRACE_SECONDS}s grace → SIGKILL "
                f"(child did not exit within grace; transactions may be interrupted)"
            )
        else:
            msg = (
                f"child exceeded timeout={timeout}s (elapsed={elapsed:.1f}s); "
                f"exited cleanly after SIGTERM within {SIGTERM_GRACE_SECONDS}s grace "
                f"(no SIGKILL)"
            )
        raise SubprocessStreamTimeout(msg) from None

    # Clean exit: drain the reader and return.
    reader.join(timeout=5)
    return proc.returncode, list(tail_buf)
