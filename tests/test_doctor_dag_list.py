"""``edgeguard doctor`` lists the paused and active EdgeGuard DAGs through ``airflow_client``.

Since 2026-10 the DAG list calls ``airflow_client.get_registered_dags`` (``/api/v2`` with a JWT
on Airflow 3). An error answer is a warning when ``AIRFLOW_API_PASSWORD`` is set and is reported
as skipped when it is not; an exception from the client is reported as a failed check. These
tests run ``cmd_doctor`` with every other check stubbed and read what it prints.
"""

from __future__ import annotations

import argparse
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import edgeguard  # noqa: E402

_ENV_UNSET = (
    "AIRFLOW_API_PASSWORD",
    "NATS_URL",
    "EDGEGUARD_BASELINE_DAYS",
    "AIRFLOW_MEMORY_LIMIT",
    "NEO4J_HEAP_MAX",
    "NEO4J_PAGECACHE",
    "NEO4J_CONTAINER_MEMORY_LIMIT",
)


@pytest.fixture
def run_doctor(monkeypatch, capsys):
    """Return a function that runs ``cmd_doctor`` with ``get_registered_dags`` replaced."""
    for name in _ENV_UNSET:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(edgeguard, "test_misp_connection", lambda: (False, "MISP stub"))
    monkeypatch.setattr(edgeguard, "test_neo4j_connection", lambda: (False, "Neo4j stub"))
    monkeypatch.setattr(edgeguard, "_doctor_airflow_reachable", lambda *a, **k: True)
    monkeypatch.setattr(edgeguard, "validate_api_keys", lambda: (True, "keys stub"))
    monkeypatch.setattr(edgeguard, "check_disk_space", lambda: (True, "disk stub"))
    monkeypatch.setattr(edgeguard, "check_last_sync", lambda: (True, "sync stub"))
    monkeypatch.setattr(edgeguard, "load_sources", lambda: {})
    monkeypatch.setattr(edgeguard, "DEFAULT_SOURCES", {}, raising=False)
    monkeypatch.setitem(
        sys.modules,
        "version_compatibility",
        types.SimpleNamespace(compare_pinned_vs_running=lambda **kw: []),
    )

    def _run(get_registered_dags, password=None):
        if password is not None:
            monkeypatch.setenv("AIRFLOW_API_PASSWORD", password)
        # cmd_doctor imports airflow_client at call time; other tests replace that module in
        # sys.modules, so the fake goes there rather than onto one module object.
        monkeypatch.setitem(
            sys.modules, "airflow_client", types.SimpleNamespace(get_registered_dags=get_registered_dags)
        )
        edgeguard.cmd_doctor(argparse.Namespace(memory=False))
        return capsys.readouterr().out.splitlines()

    return _run


def _line(lines, text):
    found = [ln for ln in lines if text in ln]
    assert found, f"no output line contains {text!r}"
    return found[0]


def test_paused_and_active_dags_are_listed(run_doctor):
    dags = [
        {"dag_id": "edgeguard_daily", "is_paused": True},
        {"dag_id": "edgeguard_neo4j_sync", "is_paused": False},
        {"dag_id": "other_dag", "is_paused": True},
    ]
    lines = run_doctor(lambda: dags)
    paused = _line(lines, "Paused DAGs:")
    active = _line(lines, "Active DAGs:")
    assert "⚠" in paused and "edgeguard_daily" in paused and "other_dag" not in paused
    assert "✓" in active and "edgeguard_neo4j_sync" in active
    assert not any("No EdgeGuard DAGs found" in ln for ln in lines)


def test_empty_list_warns_that_no_edgeguard_dag_is_registered(run_doctor):
    lines = run_doctor(lambda: [])
    assert "⚠" in _line(lines, "No EdgeGuard DAGs found")
    assert not any("Paused DAGs:" in ln or "Active DAGs:" in ln for ln in lines)


def test_error_answer_warns_when_a_password_is_set(run_doctor):
    lines = run_doctor(lambda: [{"error": "HTTP 401"}], password="secret")
    line = _line(lines, "Could not list Airflow DAGs: HTTP 401")
    assert "⚠" in line
    assert not any("DAG state check skipped" in ln for ln in lines)


def test_error_answer_is_skipped_without_a_password(run_doctor):
    lines = run_doctor(lambda: [{"error": "no credentials"}])
    line = _line(lines, "DAG state check skipped: no credentials")
    assert "ℹ" in line
    assert not any("Could not list Airflow DAGs" in ln for ln in lines)


def test_client_exception_is_reported_as_failed_check(run_doctor):
    def _raise():
        raise RuntimeError("boom")

    lines = run_doctor(_raise)
    assert "ℹ" in _line(lines, "DAG state check failed: boom")
