"""``edgeguard doctor`` checks Airflow through the version-aware health call.

Airflow 3 serves the health check at ``/api/v2/monitor/health`` and answers 404 on the Airflow 2
path ``/health``. Doctor probed ``/health`` directly, so on Airflow 3.3 it always printed
"Airflow webserver not reachable" while ``edgeguard dag status`` reached the same Airflow.

The endpoint answers HTTP 200 also when the scheduler is unhealthy (``airflow standalone`` keeps its
API server up), so the helper retries once on an unhealthy scheduler too (right after a restart the
API server answers before the new scheduler's first heartbeat) and returns the last answer.
"""

from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import airflow_client  # noqa: E402
import edgeguard  # noqa: E402

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
HEALTHY = json.loads((_FIXTURES / "airflow_health_healthy_2026_11_01.json").read_text())
UNHEALTHY = json.loads((_FIXTURES / "airflow_health_unhealthy_2026_11_01.json").read_text())


def _health(monkeypatch, fn):
    # The helper imports airflow_client at call time; other tests replace that module in
    # sys.modules, so install the fake there rather than patching one module object.
    monkeypatch.setitem(
        sys.modules,
        "airflow_client",
        types.SimpleNamespace(airflow_health=fn, component_health=airflow_client.component_health),
    )


def test_healthy_answer_is_returned(monkeypatch):
    calls = []
    _health(monkeypatch, lambda: calls.append(1) or HEALTHY)
    assert edgeguard._doctor_airflow_health(retry_delay=0) == HEALTHY
    assert len(calls) == 1


def test_error_twice_is_unreachable(monkeypatch):
    calls = []
    _health(monkeypatch, lambda: calls.append(1) or {"error": "404"})
    assert edgeguard._doctor_airflow_health(retry_delay=0) is None
    assert len(calls) == 2


def test_recovers_on_retry(monkeypatch):
    answers = iter([{"error": "starting"}, HEALTHY])
    _health(monkeypatch, lambda: next(answers))
    assert edgeguard._doctor_airflow_health(retry_delay=0) == HEALTHY


def test_unhealthy_scheduler_is_retried_and_returned(monkeypatch):
    """Reachable but with a dead scheduler: one retry, then the answer itself (not None)."""
    calls = []
    _health(monkeypatch, lambda: calls.append(1) or UNHEALTHY)
    assert edgeguard._doctor_airflow_health(retry_delay=0) == UNHEALTHY
    assert len(calls) == 2


def test_scheduler_that_comes_back_on_retry_is_healthy(monkeypatch):
    answers = iter([UNHEALTHY, HEALTHY])
    _health(monkeypatch, lambda: next(answers))
    assert edgeguard._doctor_airflow_health(retry_delay=0) == HEALTHY
