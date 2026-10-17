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

Holders (2026-10, Issue #57)
----------------------------

The sentinel records who holds it:

* ``process`` (default, legacy) — the in-process CLI baseline
  (``python src/run_pipeline.py --baseline``). Liveness is the PID on the
  same host, then the age cap on other hosts.
* ``airflow_dag_run`` — the ``edgeguard_baseline`` DAG (task
  ``baseline_acquire_lock``). The task process that writes the sentinel
  exits seconds later while the DAG run continues for hours, so PID
  liveness is meaningless here; the run state from the Airflow REST API
  (``airflow_client.get_dag_run``) is authoritative when available, and the
  sentinel is otherwise trusted until it is older than
  ``EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`` (default 48 h, above the DAG's
  32 h ``dagrun_timeout``). ``baseline_release_lock`` removes it after a
  successful run. A ``failed`` run keeps the sentinel (clearing the failed
  task resumes the same run, which must stay under the mutex) until the age
  cap; a ``success`` state prunes it. Exception (2026-10-16): a refusal of
  ``baseline_clean`` before the wipe (conf typo, ``wipe_scope``, backup gate)
  releases it, and ``baseline_clean`` and ``baseline_start`` take it again
  when they run; the collectors refuse while no baseline holds it, and the
  full sync, the baseline's ``build_relationships`` and its enrichment
  refuse unless the sentinel names their own DAG run
  (``is_own_dag_run_sentinel``). Acquiring again for the same run id is
  idempotent (task retries, manual re-runs).

  The collector tasks of that same DAG run pass their run identity to
  ``baseline_skip_reason(own_holder=...)`` and are not skipped by the sentinel
  their own run holds; a sentinel of another run or of an in-process baseline
  still skips them. Since 2026-10-16 the baseline's ``build_relationships``
  passes its run identity as well, and the writing tasks of the scheduled
  sync DAG (``run_neo4j_sync``, ``build_relationships``,
  ``run_enrichment_jobs``) call ``baseline_skip_reason`` at their start, not
  only ``check_sync_needed``. ``baseline_acquire_lock`` checks this before the
  destructive step and fails the run if the own collectors would be skipped.

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
#
# PR-N29 (Holistic M3, pre-baseline audit 2026-04-23): bumped 24h → 48h.
# Rationale: the baseline DAG's ``dagrun_timeout`` is 32h (see
# ``dags/edgeguard_pipeline.py:baseline_dag`` — ~26h realistic + 6h
# headroom). Cross-host deployments (k8s / multi-host docker-compose)
# where a different host writes the sentinel than reads it would have
# the lock reaped 8h before the baseline finishes under the old 24h
# default. Same-host deployments (the recommended CLI launch path per
# preflight script) are unaffected — PID liveness check bypasses this
# age cap. 48h gives 16h buffer above the dagrun_timeout ceiling.
_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 48 * 3600

# Sentinel holder kinds (``holder`` key; absent means ``process``).
HOLDER_PROCESS = "process"
HOLDER_AIRFLOW_DAG_RUN = "airflow_dag_run"
# DAG-run states in which the holder is alive.
_ACTIVE_RUN_STATES = frozenset({"queued", "running"})
# DAG-run state after which the sentinel is pruned. ``failed`` is deliberately absent: a failed
# baseline run is resumed by clearing the failed task (the checkpoint design of the DAG), and the
# resumed run must still hold the lock; its sentinel is kept until the age cap instead.
_FINISHED_RUN_STATES = frozenset({"success"})


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


def _sentinel_age_sec(data: Dict[str, Any]) -> float:
    """Seconds since ``started_at``; infinity when the timestamp is unusable."""
    try:
        started_dt = datetime.fromisoformat(str(data.get("started_at", "")))
        return (datetime.now(timezone.utc) - started_dt).total_seconds()
    except (TypeError, ValueError):
        return float("inf")


def sentinel_holder(data: Dict[str, Any]) -> str:
    """``process`` or ``airflow_dag_run``."""
    return str(data.get("holder") or HOLDER_PROCESS)


def describe_holder(data: Dict[str, Any]) -> str:
    """Operator-facing description of who holds the sentinel."""
    if sentinel_holder(data) == HOLDER_AIRFLOW_DAG_RUN:
        return f"Airflow DAG run {data.get('dag_id')}/{data.get('run_id')} (started_at={data.get('started_at')})"
    return f"pid={data.get('pid')} host={data.get('host')} started_at={data.get('started_at')}"


def _airflow_run_state(dag_id: str, run_id: str) -> Optional[str]:
    """State of a DAG run through the Airflow REST client, or None when it cannot be determined."""
    if not dag_id or not run_id:
        return None
    try:
        import airflow_client
    except Exception:
        return None
    try:
        result = airflow_client.get_dag_run(dag_id, run_id)
    except Exception:
        return None
    if not isinstance(result, dict) or "error" in result:
        return None
    state = result.get("state")
    return str(state) if state else None


def _airflow_sentinel_if_live(path: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Liveness of a sentinel written by the ``edgeguard_baseline`` DAG.

    The run state from the Airflow REST API is authoritative when available. Without it the
    sentinel is trusted until it is older than ``EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC``.
    """
    dag_id = str(data.get("dag_id") or "")
    run_id = str(data.get("run_id") or "")
    state = _airflow_run_state(dag_id, run_id)
    if state in _ACTIVE_RUN_STATES:
        return data
    if state in _FINISHED_RUN_STATES:
        logger.warning(
            "Stale baseline lock (DAG run %s/%s is %s) — removing %s",
            dag_id,
            run_id,
            state,
            path,
        )
        _safe_remove(path)
        return None
    # ``failed`` (resumable by clearing the failed task) or the run state is not available:
    # trust the sentinel until the age cap.
    age_sec = _sentinel_age_sec(data)
    if age_sec > _max_age_sec():
        logger.warning(
            "Stale baseline lock (DAG run %s/%s, state %s, age %.0fs > max %.0fs) — removing %s",
            dag_id,
            run_id,
            state or "not available",
            age_sec,
            _max_age_sec(),
            path,
        )
        _safe_remove(path)
        return None
    return data


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

    if sentinel_holder(data) == HOLDER_AIRFLOW_DAG_RUN:
        return _airflow_sentinel_if_live(path, data)

    # Validate fields — tolerate missing/garbled state by treating as stale.
    pid = data.get("pid")
    host = data.get("host", "")
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
    age_sec = _sentinel_age_sec(data)

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


def acquire_baseline_lock(holder: Optional[Dict[str, Any]] = None) -> bool:
    """
    Write the sentinel file. Returns True on success, False if another
    live baseline already holds the lock (caller should not proceed).

    ``holder`` is None for the in-process CLI baseline (PID-based liveness) or
    ``{"dag_id": ..., "run_id": ...}`` for the ``edgeguard_baseline`` DAG, whose
    liveness is the DAG-run state (see the module docstring).

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
        if (
            holder is not None
            and sentinel_holder(existing) == HOLDER_AIRFLOW_DAG_RUN
            and str(existing.get("run_id") or "") == str(holder.get("run_id") or "")
        ):
            # Idempotent for the owning run: a retry or manual re-run of the acquiring task.
            logger.info("Baseline lock at %s is already held by this DAG run (%s)", path, describe_holder(existing))
            return True
        logger.error(
            "Refusing to start baseline: another baseline is already running (%s). If this is stale, delete %s and retry.",
            describe_holder(existing),
            path,
        )
        return False

    payload: Dict[str, Any] = {
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "monotonic_started": time.monotonic(),
    }
    if holder is not None:
        dag_id = str(holder.get("dag_id") or "")
        run_id = str(holder.get("run_id") or "")
        if not dag_id or not run_id:
            logger.error("Refusing to acquire the baseline lock for a DAG run without dag_id/run_id: %r", holder)
            return False
        payload.update({"holder": HOLDER_AIRFLOW_DAG_RUN, "dag_id": dag_id, "run_id": run_id})
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

    logger.info("Acquired baseline lock at %s (%s)", path, describe_holder(payload))
    return True


def release_baseline_lock(holder: Optional[Dict[str, Any]] = None) -> None:
    """Remove the sentinel. Safe to call even if never acquired (idempotent).

    A sentinel held by a DAG run is removed only when ``holder`` names the same ``run_id``;
    a process sentinel only by the process that wrote it.
    """
    path = baseline_lock_path()
    # Only remove if the sentinel belongs to this process — prevents a
    # crash-and-restart race where we'd delete someone else's lock.
    data = _read_sentinel(path)
    if data is None:
        return
    if sentinel_holder(data) == HOLDER_AIRFLOW_DAG_RUN:
        requested = str((holder or {}).get("run_id") or "")
        if not requested or requested != str(data.get("run_id") or ""):
            logger.warning(
                "Not removing baseline lock: held by %s, release requested by %s",
                describe_holder(data),
                f"DAG run {holder.get('dag_id')}/{requested}" if holder else f"pid={os.getpid()}",
            )
            return
        _safe_remove(path)
        logger.info("Released baseline lock at %s (%s)", path, describe_holder(data))
        return
    if holder is not None:
        logger.warning(
            "Not removing baseline lock: held by %s, release requested by DAG run %s/%s",
            describe_holder(data),
            holder.get("dag_id"),
            holder.get("run_id"),
        )
        return
    try:
        pid_val = int(data.get("pid", 0))
    except (TypeError, ValueError):
        pid_val = 0
    if pid_val != os.getpid():
        logger.warning(
            "Not removing baseline lock: sentinel pid=%s != current pid=%s",
            pid_val,
            os.getpid(),
        )
        return
    _safe_remove(path)
    logger.info("Released baseline lock at %s", path)


def is_own_dag_run_sentinel(data: Optional[Dict[str, Any]], own_holder: Optional[Dict[str, Any]]) -> bool:
    """True when the sentinel *data* is held by the Airflow DAG run that *own_holder* names.

    Both ``dag_id`` and ``run_id`` must be present and equal. A process-held sentinel
    (``run_pipeline --baseline``) is never "own" for a DAG task.
    """
    if not data or not own_holder or sentinel_holder(data) != HOLDER_AIRFLOW_DAG_RUN:
        return False
    run_id = str(own_holder.get("run_id") or "")
    dag_id = str(own_holder.get("dag_id") or "")
    return (
        bool(run_id and dag_id) and run_id == str(data.get("run_id") or "") and dag_id == str(data.get("dag_id") or "")
    )


def baseline_skip_reason(own_holder: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Human-readable reason for an Airflow task to skip if a baseline is
    running. Returns None if no baseline is holding the lock.

    ``own_holder`` (``{"dag_id", "run_id"}``) is passed by the tasks of the
    ``edgeguard_baseline`` DAG itself: the sentinel their own run wrote in
    ``baseline_acquire_lock`` must not make them skip. Without it every collector
    of the baseline would stand down for "the baseline in progress" — its own —
    and the run would collect nothing. A sentinel held by another DAG run or by
    an in-process baseline still returns a reason. Scheduled DAGs pass nothing.
    """
    if own_holder and is_own_dag_run_sentinel(_read_sentinel(baseline_lock_path()), own_holder):
        return None
    data = is_baseline_running()
    if data is None:
        return None
    return (
        f"EdgeGuard baseline is running ({describe_holder(data)}) — "
        "skipping scheduled collector run to avoid racing MISP/Neo4j writes"
    )
