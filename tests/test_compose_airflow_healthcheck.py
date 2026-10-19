"""The airflow healthcheck probes an endpoint Airflow 3 serves, on the port the API server listens on.

Airflow 3 has no ``/health``: the probe got 404, curl exited 22 on every try, and the service was
``unhealthy`` for its whole life on the plain compose file.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]


def _airflow() -> dict:
    return yaml.safe_load((_ROOT / "docker-compose.yml").read_text())["services"]["airflow"]


def test_healthcheck_uses_the_airflow_3_monitor_endpoint():
    probe = " ".join(_airflow()["healthcheck"]["test"])
    assert "/api/v2/monitor/health" in probe
    assert not probe.rstrip().endswith(":8082/health")


def test_healthcheck_port_is_the_api_server_port():
    service = _airflow()
    port = str(service["environment"]["AIRFLOW__API__PORT"])
    assert f"localhost:{port}/" in " ".join(service["healthcheck"]["test"])
