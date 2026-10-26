"""``check_neo4j_quality`` reads through ``Neo4jClient`` (``NEO4J_URI``), like the sync tasks.

It was a curl to ``NEO4J_HTTP`` that printed nothing and exited 0 when that address was not the
synced instance (2026-10-25: ``NEO4J_URI`` pointed at a remote Neo4j through a bolt bridge). The
counts come from ``Neo4jClient.count_nodes_by_label``, which raises on any failure; ``Neo4jClient.run``
returns [] on a terminal error (a Cypher syntax error, a non-retryable ``DatabaseError``).
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
import sys
from datetime import timedelta
from unittest.mock import MagicMock

import pytest
from stub_cleanup import clear_graphql_api_magicmock_stubs, dag_module_import

# The driver's real ``DatabaseError``: MagicMock placeholders for ``neo4j`` are removed when another test
# module has left them in ``sys.modules`` (as in ``tests/test_export_paths.py``).
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j" or k.startswith("neo4j.")):
    clear_graphql_api_magicmock_stubs()

from neo4j.exceptions import DatabaseError  # noqa: E402

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
_LABELS = ("Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique", "Tactic", "Campaign")


def _import_dag_module():
    """Purge Airflow from ``sys.modules``, then import the real DAG file against a fresh import of it."""
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            # airflow itself, not sibling modules such as ``airflow_client`` that other test modules
            # patch by object identity
            or key == "airflow"
            or key.startswith("airflow.")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    if _DAGS not in sys.path:
        sys.path.insert(0, _DAGS)
    return importlib.import_module("edgeguard_pipeline")


@pytest.fixture
def dag_module():
    with dag_module_import():
        return _import_dag_module()


class _FakeClient:
    instances: list = []
    connect_result: object = True
    connect_error: Exception | None = None
    count_error: Exception | None = None
    counts: dict = {}

    def __init__(self):
        self.count_calls = []
        self.run_calls = []
        self.closed = False
        _FakeClient.instances.append(self)

    def connect(self):
        if _FakeClient.connect_error:
            raise _FakeClient.connect_error
        return _FakeClient.connect_result

    def count_nodes_by_label(self, labels):
        self.count_calls.append(tuple(labels))
        if _FakeClient.count_error:
            raise _FakeClient.count_error
        return dict(_FakeClient.counts)

    def run(self, query, parameters=None, timeout=None):
        # Neo4jClient.run's answer to a terminal error: an empty list, no exception.
        self.run_calls.append(query)
        return []

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def fake_client(monkeypatch):
    import neo4j_client

    _FakeClient.instances = []
    _FakeClient.connect_result = True
    _FakeClient.connect_error = None
    _FakeClient.count_error = None
    _FakeClient.counts = {}
    monkeypatch.setattr(neo4j_client, "Neo4jClient", _FakeClient)
    return _FakeClient


def _messages(caplog):
    return [record.getMessage() for record in caplog.records]


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
    fake_client.counts = {label: index + 1 for index, label in enumerate(_LABELS)}
    with caplog.at_level(logging.INFO):
        dag_module.check_neo4j_quality()
    messages = _messages(caplog)
    assert any(message.startswith("Neo4j sync complete - ") for message in messages)
    for index, label in enumerate(_LABELS):
        assert f"{label}: {index + 1}" in messages
    (client,) = fake_client.instances
    assert client.count_calls == [_LABELS]
    assert client.run_calls == []
    assert client.closed


def test_label_without_nodes_is_logged_as_zero(dag_module, fake_client, caplog):
    fake_client.counts = {label: 0 if label == "Campaign" else 7 for label in _LABELS}
    with caplog.at_level(logging.INFO):
        dag_module.check_neo4j_quality()
    messages = _messages(caplog)
    assert "Campaign: 0" in messages
    assert "Indicator: 7" in messages


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


def test_count_query_error_raises(dag_module, fake_client):
    fake_client.count_error = RuntimeError("boom")
    with pytest.raises(dag_module.AirflowException, match="node count query raised: boom"):
        dag_module.check_neo4j_quality()
    assert fake_client.instances[0].closed


def test_terminal_database_error_fails_the_task(dag_module, fake_client):
    """A non-retryable ``DatabaseError`` (which ``Neo4jClient.run`` turns into []) fails the task."""
    error = DatabaseError("Neo.DatabaseError.Schema.ConstraintCreationFailed: constraint could not be created")
    fake_client.count_error = error
    with pytest.raises(dag_module.AirflowException, match="node count query raised") as raised:
        dag_module.check_neo4j_quality()
    assert raised.value.__cause__ is error
    (client,) = fake_client.instances
    assert client.run_calls == []
    assert client.closed


def test_quality_check_does_not_shell_out(dag_module):
    source = inspect.getsource(dag_module.check_neo4j_quality)
    for marker in ("subprocess", "curl", "os.system", "bash_command"):
        assert marker not in source, f"check_neo4j_quality must not shell out ({marker!r} found)"
