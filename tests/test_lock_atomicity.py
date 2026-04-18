"""PR #38 regression pins for the lock-atomicity TOCTOU fixes.

Bug Hunter (proactive audit) Tier S S2 surfaced two TOCTOU bugs that
let concurrent baselines both acquire the same "lock":

1. ``src/run_pipeline.py:905`` — pipeline.lock used
   ``os.path.exists(lock_path)`` then ``with open(lock_path, "w")``.
   Non-atomic: two CLI invocations both find no lock and both write
   their PID, last writer wins.

2. ``src/baseline_lock.py:193-218`` — sentinel acquisition used
   ``is_baseline_running()`` then ``os.replace(tmp, path)``.
   Non-atomic: two concurrent baselines both see ``existing is None``,
   both rename their tmp file in (last writer wins), both proceed.

Fix: both sites now use ``os.open(path, O_CREAT|O_EXCL|O_WRONLY)``,
which is POSIX-defined as atomic create-or-fail. Concurrent attempts
either succeed exactly once or fail with ``FileExistsError``.

Tests below pin the contract structurally (source-grep for the new
flag combo) AND behaviorally (concurrent acquisition simulation
where only one should win).
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import List

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Structural pins — source-grep that the atomic flags are present
# ---------------------------------------------------------------------------


def test_run_pipeline_uses_o_excl_for_lock_file_acquisition():
    """Pin the contract: the pipeline.lock acquisition MUST use
    ``O_CREAT | O_EXCL`` so concurrent CLI invocations atomically
    serialize on the lock. If a future refactor removes O_EXCL the
    TOCTOU bug returns silently (no test caught it before).
    """
    path = os.path.join(_SRC, "run_pipeline.py")
    with open(path) as fh:
        src = fh.read()
    # Find the lock-acquisition function-local helper
    assert "_try_atomic_lock_acquire" in src, (
        "run_pipeline.py must define _try_atomic_lock_acquire; "
        "if this assertion fails, lock acquisition is no longer atomic"
    )
    # And it must use O_EXCL
    assert "O_EXCL" in src, (
        "run_pipeline.py lock acquisition MUST use os.open(..., O_CREAT|O_EXCL|O_WRONLY) — "
        "that's the only POSIX-atomic create-or-fail primitive. "
        "TOCTOU race returns if anyone removes the flag."
    )


def test_baseline_lock_uses_o_excl_for_sentinel_acquisition():
    """Same contract for the baseline-lock sentinel."""
    path = os.path.join(_SRC, "baseline_lock.py")
    with open(path) as fh:
        src = fh.read()
    assert "O_EXCL" in src, (
        "baseline_lock.py acquire_baseline_lock MUST use os.open(..., O_CREAT|O_EXCL|O_WRONLY); "
        "without it, two concurrent baselines can both acquire the sentinel"
    )
    # And it must NOT use the old non-atomic os.replace pattern as the primary acquisition
    # (the file may still be referenced in comments documenting the historical bug; that's OK)
    code_lines = [line for line in src.splitlines() if not line.lstrip().startswith("#")]
    code_only = "\n".join(code_lines)
    # The acquire function specifically must not use os.replace anymore for the sentinel.
    # PR #38 commit X (bugbot LOW): use ``>= 0`` not ``> 0`` — find() returns
    # -1 when not found and 0 when at the start of the string. The previous
    # ``> 0`` would silently skip the assertion if the function happened to
    # be at index 0 (after comment-stripping, that's actually possible if
    # there are no comments above the def).
    acquire_start = code_only.find("def acquire_baseline_lock")
    assert acquire_start >= 0, "could not locate acquire_baseline_lock in baseline_lock.py source"
    # Find end of function — next top-level def
    next_def = code_only.find("\ndef ", acquire_start + 1)
    acquire_body = code_only[acquire_start:next_def] if next_def >= 0 else code_only[acquire_start:]
    assert "os.replace(tmp_path, path)" not in acquire_body, (
        "acquire_baseline_lock must no longer use the os.replace(tmp, path) pattern — "
        "that was the non-atomic acquisition that PR #38 replaced"
    )


# ---------------------------------------------------------------------------
# Behavioral pin — concurrent acquisition: only one winner
# ---------------------------------------------------------------------------


def test_acquire_baseline_lock_is_atomic_under_concurrent_attempts(tmp_path, monkeypatch):
    """Two threads both call acquire_baseline_lock simultaneously.
    Exactly ONE must succeed; the other must return False.

    Note on what this test does + does NOT prove
    --------------------------------------------
    PROVES: the FIXED code correctly serializes concurrent attempts
    via O_EXCL — exactly one winner, deterministically.

    Does NOT (reliably) prove that the OLD code was broken — the
    TOCTOU window in the pre-fix ``is_baseline_running()`` →
    ``os.replace(tmp, path)`` pattern is real but small enough that
    two threads typically don't hit it under benign scheduling. The
    structural-pin test
    ``test_baseline_lock_uses_o_excl_for_sentinel_acquisition``
    above is the actual regression-prevention mechanism: it source-
    greps for ``O_EXCL`` and fails loudly if the atomic flag is ever
    removed. This behavioral test complements it by exercising the
    real concurrency path.
    """
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    results: List[bool] = []
    barrier = threading.Barrier(parties=2)

    def attempt() -> None:
        # Sync both threads to maximize the race window
        barrier.wait()
        results.append(baseline_lock.acquire_baseline_lock())

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    # PR #38 commit X (bugbot LOW): assert BOTH threads completed before
    # counting successes. Thread exceptions don't propagate to the main
    # thread — they print to stderr and the thread silently dies. Without
    # this length check, a thread that crashed instead of returning False
    # would skip ``results.append(...)`` and leave ``results`` with one
    # entry; if THAT entry is True the success count still equals 1 and
    # the test falsely passes.
    assert len(results) == 2, (
        f"Both threads must have completed and recorded a result; got {len(results)} results. "
        f"A missing result means a thread crashed silently — investigate stderr."
    )
    successes = sum(1 for r in results if r is True)
    assert successes == 1, (
        f"Exactly ONE thread must acquire the baseline lock; got {successes} successes. "
        f"If this fails, the TOCTOU race lets concurrent baselines proceed."
    )


def test_acquire_baseline_lock_then_retry_returns_false(tmp_path, monkeypatch):
    """After one process acquires the lock, a second attempt MUST return
    False (the live-lock case). Independent of the concurrent-race
    test — this is the simpler ordering."""
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    assert baseline_lock.acquire_baseline_lock() is True
    # Second attempt: ours is the "competitor" — should fail.
    # is_baseline_running will see our own pid as alive.
    assert baseline_lock.acquire_baseline_lock() is False
    # Cleanup: release so other tests don't see a stale sentinel
    baseline_lock.release_baseline_lock()


def _backdate_mtime(path: str, seconds_ago: int = 600) -> None:
    """Set the file's mtime to N seconds ago. Used to simulate a stale
    crash-debris sentinel that's old enough for the auto-recovery path
    to engage (PR #38 commit X added a 5-minute mtime guard to prevent
    the TOCTOU race where Process B unlinks Process A's mid-write file)."""
    target_ts = time.time() - seconds_ago
    os.utime(path, (target_ts, target_ts))


def test_acquire_baseline_lock_recovers_from_aged_corrupt_sentinel(tmp_path, monkeypatch):
    """PR #38 commit X regression pin.

    Background: with O_EXCL atomic create-or-fail, a process killed
    AFTER ``os.open`` creates the sentinel but BEFORE ``os.write``
    completes leaves an empty/corrupt file behind.

    Fix: after FileExistsError, probe via ``_is_corrupt_sentinel``;
    if it's empty/junk AND OLDER THAN 5 MINUTES, unlink + retry. The
    age check is critical for correctness — see the
    ``_is_corrupt_sentinel`` docstring for the TOCTOU race scenario
    that hits without it (bugbot HIGH).
    """
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    # Simulate a STALE crash artifact: empty file, mtime 10 minutes ago
    with open(sentinel_path, "w") as fh:
        fh.write("")
    _backdate_mtime(sentinel_path, seconds_ago=600)

    assert baseline_lock.acquire_baseline_lock() is True, (
        "Aged empty sentinel (crash debris > 5min old) must be auto-recovered"
    )
    baseline_lock.release_baseline_lock()


def test_acquire_baseline_lock_recovers_from_aged_truncated_json_sentinel(tmp_path, monkeypatch):
    """Same recovery path for truncated/malformed JSON, BUT only when aged."""
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    with open(sentinel_path, "w") as fh:
        fh.write('{"pid": 12345, "host":')  # truncated mid-JSON
    _backdate_mtime(sentinel_path, seconds_ago=600)

    assert baseline_lock.acquire_baseline_lock() is True
    baseline_lock.release_baseline_lock()


def test_acquire_baseline_lock_REFUSES_fresh_empty_sentinel(tmp_path, monkeypatch):
    """PR #38 commit X (bugbot HIGH) regression pin — the critical
    NEGATIVE case for the TOCTOU race fix.

    Without the age guard, a competitor's mid-write empty file (just
    after their O_EXCL succeeded, just before their os.write completes)
    would be misclassified as crash debris by THIS process and unlinked.
    Both processes would end up "holding" the lock — re-introducing
    the very bug PR #38 fixed.

    The age guard requires the empty file to be 5+ minutes old before
    auto-recovery engages. A fresh empty file (likely active competitor)
    must REFUSE.
    """
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    # Fresh empty sentinel (mtime = now) — simulates a competitor who
    # just did O_EXCL and hasn't yet written their PID.
    with open(sentinel_path, "w") as fh:
        fh.write("")

    assert baseline_lock.acquire_baseline_lock() is False, (
        "A FRESH empty sentinel must NOT be auto-recovered — it might be a "
        "competitor's mid-write O_EXCL. If this regresses, the TOCTOU race returns."
    )
    # Sentinel still exists (we did not unlink it)
    assert os.path.exists(sentinel_path), "fresh sentinel must NOT be unlinked"


def test_acquire_baseline_lock_does_NOT_unlink_valid_sentinel(tmp_path, monkeypatch):
    """Negative pin: a VALID JSON sentinel from a real live lock must NOT
    be auto-unlinked. ``_is_corrupt_sentinel`` must return False on
    well-formed JSON dicts so the recovery path can't trash a legitimate
    lock from another process."""
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    # PR #38 commit X (bugbot LOW): use a DYNAMIC ``started_at`` instead
    # of a hardcoded date. The original hardcoded
    # ``"2026-04-18T12:00:00+00:00"`` would have made this test pass
    # today but FAIL after that timestamp aged past
    # ``BASELINE_MAX_CROSS_HOST_AGE_HOURS`` (default 24h) — at which
    # point ``is_baseline_running`` would prune the sentinel as stale,
    # ``acquire_baseline_lock`` would succeed, and the assertion would
    # flip. Using ``datetime.now(timezone.utc)`` keeps the started_at
    # anchored to "now" relative to test execution.
    import json as _json
    from datetime import datetime as _dt
    from datetime import timezone as _tz

    payload = {
        "pid": os.getpid(),
        "host": "competitor.example",
        "started_at": _dt.now(_tz.utc).isoformat(),
        "monotonic_started": 0.0,
    }
    with open(sentinel_path, "w") as fh:
        _json.dump(payload, fh)

    # is_baseline_running returns the payload (live lock detected); acquire
    # must REFUSE.
    assert baseline_lock.acquire_baseline_lock() is False, (
        "A valid JSON sentinel from a live process must NOT be auto-recovered as 'corrupt'"
    )
    # And the sentinel must still exist
    assert os.path.exists(sentinel_path), "valid sentinel must not be unlinked by recovery path"


def test_acquire_baseline_lock_handles_filewrite_failure_cleanly(tmp_path, monkeypatch):
    """If os.write fails between O_EXCL acquire and write completion,
    the partial sentinel must be cleaned up so the next attempt isn't
    permanently blocked. Pins the rollback path."""
    import baseline_lock

    sentinel_path = str(tmp_path / "baseline.lock")
    monkeypatch.setattr(baseline_lock, "baseline_lock_path", lambda: sentinel_path)

    # Patch os.write to raise OSError on the first call
    original_write = os.write
    call_count = {"n": 0}

    def bomb_first_write(fd: int, data: bytes) -> int:
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise OSError("simulated disk full")
        return original_write(fd, data)

    monkeypatch.setattr(baseline_lock.os, "write", bomb_first_write)

    # First attempt: write fails, sentinel must be rolled back
    assert baseline_lock.acquire_baseline_lock() is False
    assert not os.path.exists(sentinel_path), "partial sentinel must be cleaned up after write failure"

    # Second attempt with normal write: must succeed (sentinel was cleaned)
    assert baseline_lock.acquire_baseline_lock() is True
    baseline_lock.release_baseline_lock()


# ---------------------------------------------------------------------------
# Documentation pin — ensure the bug-fix narrative is captured
# ---------------------------------------------------------------------------


def test_baseline_lock_docstring_documents_pr38_atomicity_fix():
    """Make sure future maintainers see the rationale for the O_EXCL
    pattern in the function docstring. Without this trace, someone
    "simplifying" the code can re-introduce the TOCTOU bug."""
    import baseline_lock

    doc = baseline_lock.acquire_baseline_lock.__doc__ or ""
    assert "PR #38" in doc, (
        "acquire_baseline_lock docstring must reference PR #38 as the source of "
        "the atomicity fix so future refactors don't accidentally undo it"
    )
    assert "O_EXCL" in doc, "docstring must explain the O_EXCL atomic-create-or-fail mechanism"
