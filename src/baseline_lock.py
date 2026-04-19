"""
EdgeGuard baseline lock — cross-process mutex between CLI baseline runs
and scheduled Airflow collector DAG tasks.

Problem this solves
-------------------

Before this module existed, there was no serialization between a CLI
baseline run (`python run_pipeline.py --baseline`) and the regularly
scheduled Airflow collector DAGs (edgeguard_pipeline, edgeguard_daily,
edgeguard_low_freq, etc.). Both could target MISP and Neo4j at the same
time, racing on MISP event writes and Neo4j MERGE operations.

Existing locks did not cover this:
- `checkpoints/pipeline.lock` (set in run_pipeline.py) only prevents
  concurrent CLI invocations.
- `max_active_runs=1` on each DAG only prevents overlap *within* that DAG.

Neither knew about the other.

Design
------

A sentinel file at `checkpoints/baseline_in_progress.lock` that CLI
baseline runs write on entry and remove on exit. Every scheduled DAG
collector task checks the sentinel before doing work and short-circuits
(returns a skipped status) if a baseline is holding it.

The sentinel stores `{"pid": int, "started_at": ISO-8601, "host": str}`
so stale entries (process died without cleanup) can be pruned safely by
checking whether the PID is still alive on the same host. Cross-host
stale detection uses a configurable max-age (default 24h).

Why not Airflow pools / ExternalTaskSensor
------------------------------------------

Airflow pools require API plumbing from the CLI side to take the slot,
which is more invasive. ExternalTaskSensor only works if the baseline
also runs inside Airflow. The sentinel file is the cheapest approach
that handles both the CLI→Airflow and Airflow→Airflow directions, and
it matches the existing `pipeline.lock` idiom.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Max age before a sentinel is considered stale on cross-host setups.
# PID-check covers local same-host stale detection; this catches the case
# where the process holding the lock crashed on a different host.
_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 24 * 3600


def _repo_root() -> str:
    """Repo root — src/../ — without depending on any other module."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def baseline_lock_path() -> str:
    """Absolute path to the sentinel file. Matches the `checkpoints/` dir
    convention already used by `pipeline.lock` and baseline checkpoints."""
    override = os.environ.get("EDGEGUARD_BASELINE_LOCK_PATH")
    if override:
        return override
    return os.path.join(_repo_root(), "checkpoints", "baseline_in_progress.lock")


def _read_sentinel(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # PID exists but owned by another user — treat as alive.
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def _max_age_sec() -> float:
    raw = os.environ.get("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC")
    if not raw:
        return float(_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT)
    try:
        return max(1.0, float(raw))
    except (TypeError, ValueError):
        return float(_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT)


def is_baseline_running() -> Optional[Dict[str, Any]]:
    """
    Return the sentinel dict if a baseline is currently holding the lock,
    else None. Transparently prunes stale sentinels (dead PID on same host,
    or exceeded max-age on any host).

    Callers: treat a non-None return as "do not run, baseline has priority".
    """
    path = baseline_lock_path()
    data = _read_sentinel(path)
    if data is None:
        return None

    # Validate fields — tolerate missing/garbled state by treating as stale.
    pid = data.get("pid")
    host = data.get("host", "")
    started_at = data.get("started_at", "")
    try:
        pid_int = int(pid) if pid is not None else 0
    except (TypeError, ValueError):
        pid_int = 0

    # Same-host liveness check: if the sentinel was written by this host
    # we can ask the kernel directly whether the PID is still alive.
    # A live same-host PID is authoritative — do NOT fall through to the
    # cross-host age check, or a baseline running longer than
    # EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC (default 24h) would have its
    # sentinel pruned out from under a still-running process and re-open
    # the exact race the mutex is designed to prevent.
    local_host = socket.gethostname()
    if host == local_host:
        if not _pid_alive(pid_int):
            logger.warning(
                "Stale baseline lock (PID %s on this host is gone) — removing %s",
                pid_int,
                path,
            )
            _safe_remove(path)
            return None
        return data  # live same-host PID — authoritative, skip age check

    # Age check — ONLY for cross-host sentinels, where we can't verify the
    # PID from here. If a baseline ran on another host and crashed without
    # cleaning up, this reaps the sentinel after the configured max age.
    try:
        started_dt = datetime.fromisoformat(started_at)
        age_sec = (datetime.now(timezone.utc) - started_dt).total_seconds()
    except (TypeError, ValueError):
        age_sec = float("inf")

    if age_sec > _max_age_sec():
        logger.warning(
            "Stale baseline lock (age %.0fs > max %.0fs) — removing %s",
            age_sec,
            _max_age_sec(),
            path,
        )
        _safe_remove(path)
        return None

    return data


def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning("Failed to remove baseline lock %s: %s", path, exc)


# How long a sentinel must be unchanged before we'll treat "empty or
# unparseable content" as crash debris vs. an active-write-in-progress
# by a competitor. 5 minutes is MASSIVELY conservative — a legitimate
# ``os.open(O_EXCL)`` → ``os.write`` window is sub-millisecond — but it
# eliminates the window where Process B could mistake Process A's
# mid-write empty file for a crash artifact and unlink it.
#
# See ``_is_corrupt_sentinel`` docstring for the race scenario.
_CRASH_RECOVERY_AGE_SECS = 300


def _is_corrupt_sentinel(path: str) -> bool:
    """Return True iff the sentinel file at ``path`` is BOTH:
      * empty or contains unparseable-as-dict content, AND
      * older than ``_CRASH_RECOVERY_AGE_SECS`` (mtime check).

    The mtime check is CRITICAL for correctness (PR #38 bugbot HIGH).
    Without it, this recovery path re-introduces the TOCTOU race that
    atomic ``O_EXCL`` was added to eliminate:

      Process A: os.open(O_EXCL) → succeeds, fd held
      Process B: os.open(O_EXCL) → FileExistsError
      Process B: reads file → empty (A hasn't written yet!)
      Process B: _is_corrupt_sentinel → True (WITHOUT age check)
      Process B: unlinks file → succeeds
      Process A: writes to orphaned inode → succeeds
      Process A: returns True  ┐
      Process B: os.open(O_EXCL) → succeeds on the re-created file
      Process B: returns True  ┘  BOTH hold the "lock" — bug returns.

    With the age check, Process B sees file is fresh (mtime seconds ago,
    not minutes) and refuses rather than unlinking. Only genuinely stale
    crash debris (5+ minutes old, empty) gets auto-recovered.

    Distinct from the empty-string check in ``is_baseline_running``
    because that one returns None on the SAME condition (interpretation:
    "no live lock"); this one explicitly says "this file is junk AND old
    enough to be safely unlinked".

    Returns False if the file is missing, too young for the age check,
    or parses as a valid JSON dict (a real live lock — we must NOT
    delete it).
    """
    try:
        stat = os.stat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return False

    age_secs = time.time() - stat.st_mtime
    if age_secs < _CRASH_RECOVERY_AGE_SECS:
        # File is fresh — might be a competitor's mid-write O_EXCL. Refuse
        # to interpret as crash debris regardless of content.
        return False

    try:
        with open(path) as f:
            content = f.read().strip()
    except FileNotFoundError:
        return False
    except OSError:
        # Can't read at all — leave it alone; caller will see FileExistsError again.
        return False
    if not content:
        return True
    try:
        parsed = json.loads(content)
    except (ValueError, TypeError):
        return True
    # Valid JSON but not a dict → also corrupt
    return not isinstance(parsed, dict)


def acquire_baseline_lock() -> bool:
    """
    Write the sentinel file. Returns True on success, False if another
    live baseline already holds the lock (caller should not proceed).

    The caller is responsible for calling `release_baseline_lock()` on
    exit — both success and failure paths. `_run_pipeline_inner` wraps
    this in a try/finally alongside the existing pipeline.lock cleanup.

    PR #38 (Bug Hunter Tier S S2): the sentinel acquisition is now
    ATOMIC via ``os.open(path, O_CREAT|O_EXCL|O_WRONLY)``. The previous
    pattern — ``is_baseline_running()`` (read sentinel) THEN
    ``os.replace(tmp, path)`` — was non-atomic: two concurrent
    baselines could both see ``existing is None``, both write to their
    own tmp file, both rename in (last writer wins), and both proceed
    thinking they hold the lock. ``release_baseline_lock`` then
    erroneously deleted the winner's sentinel via the loser's
    PID-mismatch check. Net: both baselines ran unguarded against
    scheduled DAGs — the exact race the lock was meant to prevent.

    ``O_EXCL`` is POSIX-defined as atomic create-or-fail: if the
    sentinel already exists, ``os.open`` raises ``FileExistsError`` AND
    does not touch the existing file. No window for a racing process.
    Stale-sentinel pruning (the dead-PID + age-based logic in
    ``is_baseline_running``) still runs before the atomic acquisition;
    if THAT detects a stale lock it unlinks first, then we attempt the
    atomic create.
    """
    path = baseline_lock_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Stale-pruning: ``is_baseline_running`` will unlink an obviously-stale
    # sentinel (dead PID, too old) and return None. If it returns a payload,
    # there's a live baseline.
    existing = is_baseline_running()
    if existing is not None:
        logger.error(
            "Refusing to start baseline: another baseline is already running "
            "(pid=%s host=%s started_at=%s). "
            "If this is stale, delete %s and retry.",
            existing.get("pid"),
            existing.get("host"),
            existing.get("started_at"),
            path,
        )
        return False

    payload = {
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "monotonic_started": time.monotonic(),
    }
    serialized = json.dumps(payload).encode("utf-8")

    # Atomic create-or-fail. If FileExistsError fires, a competitor slipped
    # in between our ``is_baseline_running`` check and this ``os.open`` —
    # OR a previous process was killed AFTER O_EXCL created the sentinel
    # but BEFORE os.write completed (SIGKILL, power loss). In the latter
    # case, the file exists but is empty/corrupt — ``is_baseline_running``
    # returns None (its JSON parse fails silently), the dead-PID/age
    # pruning never fires, and we'd be permanently locked out until
    # someone manually deletes the sentinel.
    #
    # PR #38 commit X (bugbot MED): on FileExistsError, do a SECOND
    # corrupt-sentinel probe — try to read+parse the file. If it's
    # genuinely unparseable (zero-byte, truncated JSON), unlink it and
    # retry the atomic create exactly once. The old ``os.replace``
    # pattern tolerated this case by silently overwriting; with O_EXCL
    # we have to handle it explicitly.
    def _attempt_atomic_create() -> int:
        """Single atomic create attempt; returns fd on success, raises
        OSError (including FileExistsError) on failure. Caller MUST handle
        the exception — there is no None return path."""
        return os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)

    try:
        fd = _attempt_atomic_create()
    except FileExistsError:
        # Probe whether the existing sentinel is empty/corrupt — if so, treat
        # as a crash-during-write artifact and retry once.
        if _is_corrupt_sentinel(path):
            logger.warning(
                "Detected empty/corrupt baseline-lock sentinel at %s — "
                "likely a crash during write; unlinking + retrying once.",
                path,
            )
            try:
                os.unlink(path)
            except OSError as unlink_exc:
                logger.error(
                    "Failed to unlink corrupt baseline-lock sentinel at %s: %s",
                    path,
                    unlink_exc,
                )
                return False
            try:
                fd = _attempt_atomic_create()
            except OSError as retry_exc:
                logger.error(
                    "Failed to acquire baseline lock at %s after corrupt-sentinel cleanup: %s",
                    path,
                    retry_exc,
                )
                return False
        else:
            logger.error(
                "Refusing to start baseline: lost the lock-acquisition race "
                "to another baseline that started in the gap between the "
                "stale-pruning check and the atomic create. Path: %s",
                path,
            )
            return False
    except OSError as exc:
        logger.error("Failed to acquire baseline lock at %s: %s", path, exc)
        return False

    # PR #38 commit X (bugbot MED): close the fd EXACTLY ONCE. The
    # previous structure had close inside both the except branch AND
    # the finally, racing to double-close → EBADF on the second close
    # (silently swallowed, but ugly). The cleaner pattern: close in
    # finally only; on write failure, the finally still runs, then
    # we unlink the partial sentinel AFTER the close completes.
    write_failed = False
    try:
        os.write(fd, serialized)
    except OSError as exc:
        logger.error("Failed to write baseline-lock payload to %s: %s", path, exc)
        write_failed = True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    if write_failed:
        # Roll back the empty/partial sentinel so the next attempt isn't blocked.
        try:
            os.unlink(path)
        except OSError:
            pass
        return False

    logger.info(
        "Acquired baseline lock at %s (pid=%s host=%s)",
        path,
        payload["pid"],
        payload["host"],
    )
    return True


def release_baseline_lock(expected_pid: Optional[int] = None) -> None:
    """Remove the sentinel. Safe to call even if never acquired (idempotent).

    Args:
        expected_pid: PID that wrote the sentinel. ``None`` (default) means
            "use ``os.getpid()``" — the legacy single-process semantics
            where the same Python process acquires + releases. Pass an
            explicit value when the acquire and release happen in
            **different processes** (e.g. Airflow worker tasks: the
            ``baseline_lock`` task writes its PID to the sentinel; the
            ``baseline_unlock`` task — possibly in a different worker
            with a different PID — must pass that recorded PID via XCom
            so the safety check passes).

    PR-F2 audit fix (Bugbot HIGH on commit 3122821): the previous
    implementation always compared against ``os.getpid()``. In Airflow
    deployments where ``_baseline_lock`` and ``_baseline_unlock`` run in
    different worker processes, the unlock task's PID never matched the
    sentinel's recorded PID → ``release_baseline_lock`` always no-op'd
    and silently logged "released sentinel" while the lock persisted
    forever — blocking all future baselines + scheduled DAGs.

    The safety property (can't delete someone else's lock) is preserved:
    callers must pass the PID they recorded at acquire-time. A caller
    that passes a wrong PID still gets refused.
    """
    path = baseline_lock_path()
    # Only remove if the sentinel belongs to the expected process — prevents
    # a crash-and-restart race where we'd delete someone else's lock.
    data = _read_sentinel(path)
    if data is None:
        return
    try:
        pid_val = int(data.get("pid", 0))
    except (TypeError, ValueError):
        pid_val = 0
    check_against = expected_pid if expected_pid is not None else os.getpid()
    if pid_val != check_against:
        logger.warning(
            "Not removing baseline lock: sentinel pid=%s != expected pid=%s (current pid=%s)",
            pid_val,
            check_against,
            os.getpid(),
        )
        return
    _safe_remove(path)
    logger.info("Released baseline lock at %s (held by pid=%s)", path, pid_val)


def baseline_skip_reason() -> Optional[str]:
    """
    Human-readable reason for an Airflow task to skip if a baseline is
    running. Returns None if no baseline is holding the lock.
    """
    data = is_baseline_running()
    if data is None:
        return None
    return (
        f"EdgeGuard baseline is running (pid={data.get('pid')}, "
        f"host={data.get('host')}, started_at={data.get('started_at')}) — "
        "skipping scheduled collector run to avoid racing MISP/Neo4j writes"
    )
