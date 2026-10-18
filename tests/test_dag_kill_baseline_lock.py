"""``edgeguard dag kill`` releases the baseline lock that a killed baseline run holds.

A ``failed`` run keeps its sentinel until the 48 h age cap, so that clearing a failed task resumes
the run under the mutex. A run the operator killed is not resumed that way, and while its sentinel
stays every collector and sync skips for the baseline it names. ``dag kill`` therefore removes a
sentinel naming a run it killed; a later resume clears ``baseline_start``, which takes the lock
again. A sentinel of another run, or of a run whose kill failed, is left alone.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import baseline_lock  # noqa: E402
import edgeguard  # noqa: E402

KILLED = "manual__2026-10-17T13:03:20+00:00"


@pytest.fixture
def lock_path(tmp_path, monkeypatch):
    path = tmp_path / "baseline_in_progress.lock"
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(path))
    return path


def _hold(path, run_id):
    assert baseline_lock.acquire_baseline_lock({"dag_id": "edgeguard_baseline", "run_id": run_id})
    assert json.loads(path.read_text())["run_id"] == run_id


def _kill(monkeypatch, runs, patch_error=None):
    client = types.SimpleNamespace(
        airflow_health=lambda: {"status": "healthy"},
        list_all_active_dag_runs=lambda dag_ids: runs,
        patch_dag_run_state=lambda dag_id, run_id, state: {"error": patch_error} if patch_error else {"state": state},
    )
    monkeypatch.setitem(sys.modules, "airflow_client", client)
    return edgeguard.cmd_dag_kill(argparse.Namespace(dag_id=None, dry_run=False, force=True))


def _run(dag_id, run_id):
    return {"dag_id": dag_id, "dag_run_id": run_id, "state": "running", "start_date": "2026-10-17T13:03:20"}


def test_killing_the_baseline_run_releases_its_lock(lock_path, monkeypatch):
    _hold(lock_path, KILLED)
    assert _kill(monkeypatch, [_run("edgeguard_baseline", KILLED)]) == 0
    assert not lock_path.exists()


def test_a_lock_of_another_baseline_run_stays(lock_path, monkeypatch):
    _hold(lock_path, "manual__other")
    assert _kill(monkeypatch, [_run("edgeguard_baseline", KILLED)]) == 0
    assert json.loads(lock_path.read_text())["run_id"] == "manual__other"


def test_a_failed_kill_keeps_the_lock(lock_path, monkeypatch):
    _hold(lock_path, KILLED)
    _kill(monkeypatch, [_run("edgeguard_baseline", KILLED)], patch_error="HTTP 500")
    assert lock_path.exists()


def test_killing_another_dag_with_the_same_run_id_keeps_the_lock(lock_path, monkeypatch):
    _hold(lock_path, KILLED)
    _kill(monkeypatch, [_run("edgeguard_neo4j_sync", KILLED)])
    assert lock_path.exists()
