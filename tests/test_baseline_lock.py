"""Unit tests for src/baseline_lock.py.

Covers the three load-bearing behaviors of the cross-process mutex
between CLI baseline runs and scheduled Airflow DAGs:

1. Acquire / release lifecycle — both the write and the idempotent
   release path.
2. Stale-lock detection — a same-host PID that is no longer alive must
   be pruned. This is the security-critical path; if it breaks, a
   crashed baseline leaves a permanent lock and every scheduled
   collector skips forever.
3. Same-host liveness takes precedence over age — a long-running
   baseline (>24h) must not be pruned out from under a still-alive
   PID. Before the round-1 bugbot fix on PR #23 the age check ran
   unconditionally and re-opened the exact race the mutex prevents.

Tests use a per-test temporary lock path via the
EDGEGUARD_BASELINE_LOCK_PATH env var so they don't touch the real
`checkpoints/` directory.
"""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timedelta, timezone

import pytest

import baseline_lock


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    """Point baseline_lock at a throwaway path for this test only."""
    path = tmp_path / "baseline_in_progress.lock"
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(path))
    # Also clear any stale max-age override so tests are deterministic
    monkeypatch.delenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", raising=False)
    return path


def test_acquire_release_roundtrip(lock_path):
    """Happy path: acquire, observe, release, gone."""
    assert not lock_path.exists()
    assert baseline_lock.acquire_baseline_lock() is True
    assert lock_path.exists()

    data = baseline_lock.is_baseline_running()
    assert data is not None
    assert int(data["pid"]) == os.getpid()
    assert data["host"] == socket.gethostname()

    baseline_lock.release_baseline_lock()
    assert not lock_path.exists()
    assert baseline_lock.is_baseline_running() is None


def test_double_acquire_is_rejected(lock_path):
    """A second acquire while the first is still live must fail."""
    assert baseline_lock.acquire_baseline_lock() is True
    try:
        # Same process, same PID — is_baseline_running returns the live
        # sentinel, and acquire_baseline_lock short-circuits.
        assert baseline_lock.acquire_baseline_lock() is False
    finally:
        baseline_lock.release_baseline_lock()


def test_stale_sentinel_with_dead_pid_is_pruned(lock_path):
    """A same-host sentinel pointing at a PID that no longer exists
    must be cleared on the next is_baseline_running() call. PID 1 is
    always alive on POSIX, so we use a PID that can't exist (very
    high number well past any plausible live process)."""
    sentinel = {
        "pid": 2**30,  # effectively guaranteed dead
        "host": socket.gethostname(),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    lock_path.write_text(json.dumps(sentinel))
    assert lock_path.exists()

    assert baseline_lock.is_baseline_running() is None
    assert not lock_path.exists(), "stale sentinel should have been removed"


def test_same_host_alive_pid_is_not_aged_out(lock_path, monkeypatch):
    """Regression test for a round-1 bugbot finding on PR #23: a
    long-running baseline whose sentinel is older than
    EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC must NOT be pruned if the
    same-host PID is still alive. The age check is for cross-host
    stale detection only."""
    # Make the max age very small so the sentinel looks ancient.
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", "1")

    ancient = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    sentinel = {
        "pid": os.getpid(),  # definitely alive — it's us
        "host": socket.gethostname(),
        "started_at": ancient,
    }
    lock_path.write_text(json.dumps(sentinel))

    result = baseline_lock.is_baseline_running()
    assert result is not None, "live same-host PID must survive the age check"
    assert int(result["pid"]) == os.getpid()
    assert lock_path.exists(), "sentinel must not be removed"


def test_cross_host_age_check_prunes_old_sentinel(lock_path, monkeypatch):
    """The age check is load-bearing for cross-host clusters: if the
    baseline crashed on another host we can't kill -0 its PID from
    here, so we fall back to a configurable max age."""
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC", "1")

    old = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    sentinel = {
        "pid": 1,  # real pid on a different host — not locally verifiable
        "host": "definitely-not-this-host-" + socket.gethostname() + "-xyz",
        "started_at": old,
    }
    lock_path.write_text(json.dumps(sentinel))

    assert baseline_lock.is_baseline_running() is None
    assert not lock_path.exists(), "stale cross-host sentinel should be removed"


def test_release_is_idempotent_when_no_sentinel(lock_path):
    """Calling release when no lock is held must be a no-op, not an
    exception — the `finally` block in the baseline pipeline runs
    unconditionally."""
    assert not lock_path.exists()
    baseline_lock.release_baseline_lock()  # must not raise


def test_release_refuses_to_delete_foreign_sentinel(lock_path):
    """Crash-restart race: a new baseline process must not delete a
    sentinel owned by a different PID. Otherwise a fresh crashed-and-
    restarted baseline could wipe a still-running one on the same host."""
    foreign_sentinel = {
        "pid": os.getpid() + 1,  # not us
        "host": socket.gethostname(),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    lock_path.write_text(json.dumps(foreign_sentinel))

    baseline_lock.release_baseline_lock()
    assert lock_path.exists(), "must refuse to remove another process's lock"


def test_baseline_skip_reason_matches_running_state(lock_path):
    """The human-readable skip reason used by DAG collector tasks."""
    assert baseline_lock.baseline_skip_reason() is None

    assert baseline_lock.acquire_baseline_lock() is True
    try:
        reason = baseline_lock.baseline_skip_reason()
        assert reason is not None
        assert "baseline is running" in reason
        assert str(os.getpid()) in reason
    finally:
        baseline_lock.release_baseline_lock()

    assert baseline_lock.baseline_skip_reason() is None
