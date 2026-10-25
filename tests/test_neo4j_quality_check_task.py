"""``check_neo4j_quality`` reads through ``Neo4jClient`` (``NEO4J_URI``), like the sync tasks.

It was a curl to ``NEO4J_HTTP`` that printed nothing and exited 0 when that address was not the
synced instance (2026-10-25: ``NEO4J_URI`` pointed at a remote Neo4j through a bolt bridge).
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from datetime import timedelta

import pytest

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")


def _import_dag_module():
    """Purge Airflow stubs other tests leave in ``sys.modules``, then import the real DAG file."""
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            or key.startswith("airflow")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    if _DAGS not in sys.path:
        sys.path.insert(0, _DAGS)
    return importlib.import_module("edgeguard_pipeline")


@pytest.fixture
def dag_module():
    try:
        return _import_dag_module()
    except Exception:
        pytest.skip("Airflow not installed in this test env")


class _FakeClient:
    instances: list = []
    connect_result: object = True
    connect_error: Exception | None = None
    run_error: Exception | None = None
    rows: list = []

    def __init__(self):
        self.queries = []
        self.closed = False
        _FakeClient.instances.append(self)

    def connect(self):
        if _FakeClient.connect_error:
            raise _FakeClient.connect_error
        return _FakeClient.connect_result

    def run(self, query, parameters=None, timeout=None):
        self.queries.append(query)
        if _FakeClient.run_error:
            raise _FakeClient.run_error
        return _FakeClient.rows

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_client(monkeypatch):
    import neo4j_client

    _FakeClient.instances = []
    _FakeClient.connect_result = True
    _FakeClient.connect_error = None
    _FakeClient.run_error = None
    _FakeClient.rows = []
    monkeypatch.setattr(neo4j_client, "Neo4jClient", _FakeClient)
    return _FakeClient


def test_task_is_python_operator_with_unchanged_wiring(dag_module):
    task = dag_module.check_neo4j_quality_task
    assert isinstance(task, dag_module.PythonOperator)
    assert task.task_id == "check_neo4j_quality"
    assert task.execution_timeout == timedelta(minutes=15)
    assert task.dag is dag_module.neo4j_sync_dag
    assert task.python_callable is dag_module.check_neo4j_quality
    assert task.upstream_task_ids == {dag_module.enrichment_task.task_id}
    assert not task.downstream_task_ids


def test_counts_are_logged_per_label(dag_module, fake_client, caplog):
    fake_client.rows = [{"type": "Indicator", "cnt": 12}, {"type": "CVE", "cnt": 3}]
    with caplog.at_level(logging.INFO):
        dag_module.check_neo4j_quality()
    assert "Indicator: 12" in caplog.text
    assert "CVE: 3" in caplog.text
    (client,) = fake_client.instances
    assert client.closed
    for label in ("Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique", "Tactic", "Campaign"):
        assert f"n:{label}" in client.queries[0]


def test_connect_false_raises(dag_module, fake_client):
    fake_client.connect_result = False
    with pytest.raises(dag_module.AirflowException, match="cannot connect"):
        dag_module.check_neo4j_quality()
    assert fake_client.instances[0].closed


def test_connect_error_raises(dag_module, fake_client):
    fake_client.connect_error = RuntimeError("bolt down")
    with pytest.raises(dag_module.AirflowException, match="bolt down"):
        dag_module.check_neo4j_quality()
    assert fake_client.instances[0].closed


def test_query_error_raises(dag_module, fake_client):
    fake_client.run_error = RuntimeError("boom")
    with pytest.raises(dag_module.AirflowException, match="boom"):
        dag_module.check_neo4j_quality()
    assert fake_client.instances[0].closed
