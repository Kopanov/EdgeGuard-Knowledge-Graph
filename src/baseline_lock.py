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


def acquire_baseline_lock() -> bool:
    """
    Write the sentinel file. Returns True on success, False if another
    live baseline already holds the lock (caller should not proceed).

    The caller is responsible for calling `release_baseline_lock()` on
    exit — both success and failure paths. `_run_pipeline_inner` wraps
    this in a try/finally alongside the existing pipeline.lock cleanup.
    """
    path = baseline_lock_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)

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
    try:
        # Atomic-ish write: write to tmp then rename so a reader never sees
        # a half-written JSON blob.
        tmp_path = f"{path}.tmp.{os.getpid()}"
        with open(tmp_path, "w") as f:
            json.dump(payload, f)
        os.replace(tmp_path, path)
    except OSError as exc:
        logger.error("Failed to acquire baseline lock at %s: %s", path, exc)
        return False

    logger.info(
        "Acquired baseline lock at %s (pid=%s host=%s)",
        path,
        payload["pid"],
        payload["host"],
    )
    return True


def release_baseline_lock() -> None:
    """Remove the sentinel. Safe to call even if never acquired (idempotent)."""
    path = baseline_lock_path()
    # Only remove if the sentinel belongs to this process — prevents a
    # crash-and-restart race where we'd delete someone else's lock.
    data = _read_sentinel(path)
    if data is None:
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
