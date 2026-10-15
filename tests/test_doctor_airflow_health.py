"""``edgeguard doctor`` checks Airflow through the version-aware health call.

Airflow 3 serves the health check at ``/api/v2/monitor/health`` and answers 404 on the Airflow 2
path ``/health``. Doctor probed ``/health`` directly, so on Airflow 3.3 it always printed
"Airflow webserver not reachable" while ``edgeguard dag status`` reached the same Airflow.
"""

from __future__ import annotations

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import edgeguard  # noqa: E402


def _health(monkeypatch, fn):
    # The helper imports airflow_client at call time; other tests replace that module in
    # sys.modules, so install the fake there rather than patching one module object.
    monkeypatch.setitem(sys.modules, "airflow_client", types.SimpleNamespace(airflow_health=fn))


def test_healthy_answer_counts_as_reachable(monkeypatch):
    _health(monkeypatch, lambda: {"scheduler": {"status": "healthy"}})
    assert edgeguard._doctor_airflow_reachable(retry_delay=0) is True


def test_error_twice_is_unreachable(monkeypatch):
    calls = []
    _health(monkeypatch, lambda: calls.append(1) or {"error": "404"})
    assert edgeguard._doctor_airflow_reachable(retry_delay=0) is False
    assert len(calls) == 2


def test_recovers_on_retry(monkeypatch):
    answers = iter([{"error": "starting"}, {"scheduler": {"status": "healthy"}}])
    _health(monkeypatch, lambda: next(answers))
    assert edgeguard._doctor_airflow_reachable(retry_delay=0) is True
