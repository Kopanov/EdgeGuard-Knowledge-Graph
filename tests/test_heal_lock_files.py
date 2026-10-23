"""``edgeguard heal`` removes only the EdgeGuard lock files that no process holds.

The event-creation lock of the MISP writer is an flock-style file: its presence means nothing, a
process holds it with ``fcntl.flock``. Removing it while a collector holds it lets the next collector
create and lock a new file under the same name, so two collectors create the same day's MISP event at
once. Heal therefore removes the file only while it holds the lock itself, and a collector that was
already waiting on the removed file takes the lock again on the file the name now points to.

The presence-based locks (``checkpoints/pipeline.lock`` and the baseline lock) are reported, never
removed, and heal touches no other ``*.lock`` file. The tests use real files, a second process and
threads that hold the lock through ``MISPWriter``'s own context manager.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import baseline_lock  # noqa: E402
import collectors.misp_writer as mw  # noqa: E402
import edgeguard  # noqa: E402

EVENT_LOCK_NAME = "edgeguard_misp_get_or_create_event.lock"
WAIT_SEC = 10.0

_HOLDER_SCRIPT = """
import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_CREAT | os.O_RDWR, 0o644)
fcntl.flock(fd, fcntl.LOCK_EX)
print("locked", flush=True)
sys.stdin.read()
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolate every lock location in ``tmp_path``: repository root, temporary directory, lock paths."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "checkpoints").mkdir()
    temp = tmp_path / "temp"
    temp.mkdir()
    event_lock = temp / EVENT_LOCK_NAME
    monkeypatch.setattr(edgeguard, "SCRIPT_DIR", str(root / "src"))
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(event_lock))
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(root / "checkpoints" / "baseline_in_progress.lock"))
    return {"root": root, "temp": temp, "event_lock": event_lock}


def _paths(entries):
    return [path for path, _detail in entries]


def _hold_in_thread(entered: threading.Event, release: threading.Event) -> threading.Thread:
    def run():
        with mw._cross_process_event_creation_lock():
            entered.set()
            release.wait(WAIT_SEC)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert entered.wait(WAIT_SEC)
    return thread


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


# --------------------------------------------------------------------------- the flock-style event lock


def test_heal_keeps_the_event_lock_another_process_holds(env):
    lock = env["event_lock"]
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLDER_SCRIPT, str(lock)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "locked"
        report = edgeguard.clear_lock_files()
        assert lock.exists()
        assert _paths(report["held"]) == [str(lock)]
        assert report["removed"] == []
    finally:
        holder.stdin.close()
        holder.wait(WAIT_SEC)
    # The holder has exited, so the kernel released its lock: the file is free now and goes.
    report = edgeguard.clear_lock_files()
    assert not lock.exists()
    assert _paths(report["removed"]) == [str(lock)]
    assert report["held"] == []


def test_heal_keeps_the_event_lock_a_collector_holds(env):
    lock = env["event_lock"]
    entered, release = threading.Event(), threading.Event()
    thread = _hold_in_thread(entered, release)
    try:
        report = edgeguard.clear_lock_files()
        assert lock.exists()
        assert _paths(report["held"]) == [str(lock)]
    finally:
        release.set()
        thread.join(WAIT_SEC)
    assert _paths(edgeguard.clear_lock_files()["removed"]) == [str(lock)]
    assert not lock.exists()


def test_heal_removes_the_event_lock_no_process_holds(env):
    lock = env["event_lock"]
    lock.touch()
    report = edgeguard.clear_lock_files()
    assert not lock.exists()
    assert _paths(report["removed"]) == [str(lock)]
    assert report["held"] == [] and report["kept"] == []


def test_heal_finds_the_event_lock_at_its_configured_path(env, tmp_path, monkeypatch):
    # The lock lives where EDGEGUARD_MISP_EVENT_LOCK_PATH says, whatever its name.
    lock = tmp_path / "elsewhere" / "event.lock"
    lock.parent.mkdir()
    lock.touch()
    monkeypatch.setenv("EDGEGUARD_MISP_EVENT_LOCK_PATH", str(lock))
    assert _paths(edgeguard.clear_lock_files()["removed"]) == [str(lock)]
    assert not lock.exists()


def test_a_collector_waiting_on_the_removed_file_takes_the_lock_again(env, monkeypatch):
    """A collector that opened the file before heal removed it must not run beside a new holder.

    Heal holds the lock while it removes the file. A collector that opened the file before the
    removal gets that lock once heal lets go, on a file no longer reachable by name, while a collector
    that started after the removal created and locked a new file under the same name.
    """
    lock = env["event_lock"]
    lock.touch()
    inside = []
    overlap = []
    guard = threading.Lock()
    waiter_entered, waiter_release = threading.Event(), threading.Event()
    late_entered, late_release = threading.Event(), threading.Event()

    def collector(entered: threading.Event, release: threading.Event):
        with mw._cross_process_event_creation_lock():
            with guard:
                inside.append(threading.current_thread().name)
                overlap.append(len(inside))
            entered.set()
            release.wait(WAIT_SEC)
            with guard:
                inside.remove(threading.current_thread().name)

    def fds_on(inode) -> int:
        count = 0
        for name in os.listdir("/dev/fd"):
            try:
                st = os.fstat(int(name))
            except (OSError, ValueError):
                continue
            if (st.st_dev, st.st_ino) == inode:
                count += 1
        return count

    real_remove, real_unlink = os.remove, os.unlink
    threads = {}

    def remove_with_waiter(path, *args, **kwargs):
        if os.fspath(path) != str(lock):
            return real_unlink(path, *args, **kwargs)
        st = os.stat(path)
        inode = (st.st_dev, st.st_ino)
        before = fds_on(inode)
        threads["waiter"] = threading.Thread(
            target=collector, args=(waiter_entered, waiter_release), name="waiter", daemon=True
        )
        threads["waiter"].start()
        deadline = time.monotonic() + WAIT_SEC
        while fds_on(inode) <= before:  # the waiter has the file open
            assert time.monotonic() < deadline, "the waiting collector never opened the lock file"
            time.sleep(0.01)
        real_unlink(path, *args, **kwargs)
        threads["late"] = threading.Thread(
            target=collector, args=(late_entered, late_release), name="late", daemon=True
        )
        threads["late"].start()
        assert late_entered.wait(WAIT_SEC), "the collector started after the removal never got the lock"

    monkeypatch.setattr(os, "remove", remove_with_waiter)
    monkeypatch.setattr(os, "unlink", remove_with_waiter)
    try:
        report = edgeguard.clear_lock_files()
    finally:
        monkeypatch.setattr(os, "remove", real_remove)
        monkeypatch.setattr(os, "unlink", real_unlink)

    time.sleep(0.3)  # heal has let go: the waiter would be inside by now if it took the old file
    with guard:
        assert inside == ["late"]
    late_release.set()
    assert waiter_entered.wait(WAIT_SEC), "the waiting collector never got the lock"
    waiter_release.set()
    for thread in threads.values():
        thread.join(WAIT_SEC)
    assert max(overlap) == 1
    assert lock.exists()
    assert _paths(report["removed"]) == [str(lock)]


# --------------------------------------------------------------------------- other files


def test_heal_leaves_lock_files_that_are_not_edgeguard_locks(env):
    root, temp = env["root"], env["temp"]
    others = [root / "poetry.lock", root / "uv.lock", temp / "edgeguard_other.lock", root / "checkpoints" / "x.lock"]
    for path in others:
        path.write_text("keep")
    report = edgeguard.clear_lock_files()
    assert all(path.read_text() == "keep" for path in others)
    assert report == {"removed": [], "held": [], "kept": []}


def test_heal_reports_and_keeps_the_baseline_lock_of_a_dag_run(env):
    run_id = "manual__2026-10-23T08:00:00+00:00"
    assert baseline_lock.acquire_baseline_lock({"dag_id": "edgeguard_baseline", "run_id": run_id})
    path = baseline_lock.baseline_lock_path()
    report = edgeguard.clear_lock_files()
    assert os.path.exists(path)
    assert _paths(report["kept"]) == [path]
    assert run_id in report["kept"][0][1]


def test_heal_keeps_a_baseline_lock_whose_process_is_gone(env):
    # The baseline lock's own liveness check would prune this sentinel; heal leaves that to it.
    path = baseline_lock.baseline_lock_path()
    pid = _dead_pid()
    sentinel = {"pid": pid, "host": socket.gethostname(), "started_at": datetime.now(timezone.utc).isoformat()}
    with open(path, "w") as fh:
        json.dump(sentinel, fh)
    report = edgeguard.clear_lock_files()
    assert json.loads(open(path).read()) == sentinel
    assert _paths(report["kept"]) == [path]
    assert f"pid={pid}" in report["kept"][0][1]


def test_heal_reports_an_unreadable_baseline_lock(env):
    path = baseline_lock.baseline_lock_path()
    with open(path, "w") as fh:
        fh.write("")
    report = edgeguard.clear_lock_files()
    assert os.path.exists(path)
    assert _paths(report["kept"]) == [path]
    assert "unreadable" in report["kept"][0][1]


def test_heal_reports_and_keeps_the_pipeline_lock(env):
    path = env["root"] / "checkpoints" / "pipeline.lock"
    pid = _dead_pid()
    path.write_text(str(pid))
    report = edgeguard.clear_lock_files()
    assert path.read_text() == str(pid)
    assert _paths(report["kept"]) == [str(path)]
    assert f"PID {pid}" in report["kept"][0][1]


# --------------------------------------------------------------------------- the heal command


def _heal(monkeypatch, env, capsys) -> str:
    monkeypatch.setattr(edgeguard, "reset_circuit_breakers", lambda: (True, "No circuit breakers to reset"))
    monkeypatch.setattr(edgeguard, "retry_pending_collections", lambda: (True, "No DAG triggered"))
    monkeypatch.setattr(
        edgeguard, "get_circuit_breaker_state_file", lambda: str(env["root"] / "dags" / "circuit_breaker_state.json")
    )
    capsys.readouterr()
    assert edgeguard.cmd_heal(argparse.Namespace()) == 0
    return capsys.readouterr().out


def test_cmd_heal_prints_the_held_lock_it_kept_and_the_free_lock_it_removed(env, monkeypatch, capsys):
    lock = env["event_lock"]
    entered, release = threading.Event(), threading.Event()
    thread = _hold_in_thread(entered, release)
    try:
        out = _heal(monkeypatch, env, capsys)
    finally:
        release.set()
        thread.join(WAIT_SEC)
    assert lock.exists()
    assert f"Kept {lock}" in out
    assert "Removed" not in out

    out = _heal(monkeypatch, env, capsys)
    assert not lock.exists()
    assert f"Removed {lock}" in out
    assert "lock file" in out.split("Heal Complete")[1]


def test_cmd_heal_prints_the_presence_locks_it_kept(env, monkeypatch, capsys):
    pipeline = env["root"] / "checkpoints" / "pipeline.lock"
    pipeline.write_text("12345")
    assert baseline_lock.acquire_baseline_lock({"dag_id": "edgeguard_baseline", "run_id": "manual__r1"})
    out = _heal(monkeypatch, env, capsys)
    assert f"Kept {pipeline}" in out
    assert f"Kept {baseline_lock.baseline_lock_path()}" in out
    assert pipeline.exists() and os.path.exists(baseline_lock.baseline_lock_path())


def test_cmd_heal_without_lock_files(env, monkeypatch, capsys):
    out = _heal(monkeypatch, env, capsys)
    assert "No lock files found" in out
