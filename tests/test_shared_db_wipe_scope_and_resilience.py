"""Follow-up fixes of the 2026-10 production-readiness check (code and logic items still open after
the Tier 2 pull requests):

* the fresh-baseline wipe deletes only EdgeGuard-managed nodes unless ``wipe_scope`` is ``all``
  (shared-database contract) — DAG conf key and CLI flag;
* REST ``/health`` answers 503 while degraded and the request guard retries the Neo4j connection;
* the NATS client reconnects without an attempt limit and logs state changes;
* the Neo4j health probe honours its timeout (the executor no longer waits for a hung thread);
* the creator-rejection counter accepts only registered source identifiers as label values.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import baseline_clean
import health_check
import metrics_server
import query_api

_ROOT = Path(__file__).resolve().parents[1]


def _real_nats_client():
    """Import ``nats_client`` against the real ``nats`` package.

    Other test modules register ``MagicMock`` placeholders for ``nats`` in ``sys.modules``; a
    placeholder is not a package, so ``from nats.aio.client import ...`` fails at import time.
    """
    for key in list(sys.modules):
        if key == "nats_client" or key == "nats" or key.startswith("nats."):
            if key == "nats_client" or isinstance(sys.modules[key], MagicMock):
                del sys.modules[key]
    pytest.importorskip("nats.aio.client")
    import nats_client

    return nats_client


class TestWipeScopeWiring:
    def test_reset_baseline_data_defaults_to_the_edgeguard_scope(self):
        sig = inspect.signature(baseline_clean.reset_baseline_data)
        assert sig.parameters["wipe_scope"].default == baseline_clean.WIPE_SCOPE_EDGEGUARD == "edgeguard"
        assert baseline_clean.VALID_WIPE_SCOPES == {"edgeguard", "all"}

    def test_dag_passes_the_conf_scope_and_accepts_the_key(self):
        dag = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        assert "reset_baseline_data(wipe_scope=wipe_scope)" in dag
        assert "reset_baseline_data()" not in dag, "the unscoped call would wipe partner data"
        keys_block = dag[dag.index("_KNOWN_BASELINE_CONF_KEYS = frozenset(") :]
        keys_block = keys_block[: keys_block.index("\n)\n")]
        assert '"wipe_scope"' in keys_block
        assert "wipe_scope must be 'edgeguard' or 'all'" in dag

    def test_cli_flag_sets_the_conf_only_when_requested(self):
        cli = (_ROOT / "src" / "edgeguard.py").read_text()
        assert '"--wipe-all"' in cli
        assert '_conf["wipe_scope"] = "all"' in cli
        # The default conf carries no scope key: the DAG default (edgeguard) applies.
        assert '_conf: dict = {"fresh_baseline": True, "baseline_days": days}' in cli
        assert "Neo4j scope: EdgeGuard-managed nodes only" in cli

    def test_documentation_states_the_default_scope(self):
        for rel in ("README.md", "docs/AIRFLOW_DAGS.md", "docs/RESILMESH_INTEROPERABILITY.md"):
            text = (_ROOT / rel).read_text()
            assert "EdgeGuard-managed nodes" in text and ("--wipe-all" in text or "wipe_scope" in text), rel
        assert "the wipe deletes every node" not in (_ROOT / "src" / "baseline_clean.py").read_text()


class _Client:
    def __init__(self, connected: bool, healthy: bool = True, connect_result: bool = True):
        self._connected = connected
        self._healthy = healthy
        self._connect_result = connect_result
        self.connect_calls = 0

    def is_connected(self) -> bool:
        return self._connected

    def health_check(self) -> dict:
        return {"healthy": self._healthy}

    def connect(self) -> bool:
        self.connect_calls += 1
        if self._connect_result:
            self._connected = True
        return self._connect_result


class TestRestHealthAndReconnect:
    @pytest.fixture(autouse=True)
    def _reset_guard(self, monkeypatch):
        monkeypatch.setattr(query_api, "_last_reconnect_attempt", float("-inf"))
        monkeypatch.setattr(query_api, "_API_KEY", None)

    def test_health_is_503_while_degraded_and_200_when_healthy(self, monkeypatch):
        monkeypatch.setattr(query_api, "neo4j_client", _Client(connected=True, healthy=False))
        resp = TestClient(query_api.app).get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded" and resp.json()["neo4j_connected"] is False
        monkeypatch.setattr(query_api, "neo4j_client", _Client(connected=True, healthy=True))
        resp = TestClient(query_api.app).get("/health")
        assert resp.status_code == 200 and resp.json()["status"] == "ok"

    def test_health_is_503_without_a_client(self, monkeypatch):
        monkeypatch.setattr(query_api, "neo4j_client", None)
        assert TestClient(query_api.app).get("/health").status_code == 503

    def test_guard_reconnects_once_then_rate_limits(self, monkeypatch):
        client = _Client(connected=False, connect_result=False)
        monkeypatch.setattr(query_api, "neo4j_client", client)
        with pytest.raises(query_api.HTTPException) as exc:
            query_api._require_neo4j()
        assert exc.value.status_code == 503 and client.connect_calls == 1
        with pytest.raises(query_api.HTTPException):
            query_api._require_neo4j()
        assert client.connect_calls == 1, "a second attempt within the interval must not hit the driver"
        monkeypatch.setattr(query_api, "_last_reconnect_attempt", float("-inf"))
        client._connect_result = True
        query_api._require_neo4j()  # reconnect succeeds: no exception
        assert client.connect_calls == 2 and client.is_connected()

    def test_guard_is_a_no_op_when_connected_and_503_without_a_client(self, monkeypatch):
        client = _Client(connected=True)
        monkeypatch.setattr(query_api, "neo4j_client", client)
        query_api._require_neo4j()
        assert client.connect_calls == 0
        monkeypatch.setattr(query_api, "neo4j_client", None)
        with pytest.raises(query_api.HTTPException):
            query_api._require_neo4j()

    def test_every_data_route_uses_the_guard(self):
        src = (_ROOT / "src" / "query_api.py").read_text()
        assert "if not neo4j_client or not neo4j_client.is_connected():" not in src
        assert src.count("_require_neo4j()") >= 10

    def test_request_through_the_guard_reconnects(self, monkeypatch):
        """A route call after a failed startup connection succeeds once the database is back."""
        session = MagicMock()
        session.run.return_value = []
        client = _Client(connected=False, connect_result=True)
        client.driver = MagicMock()
        client.driver.session.return_value.__enter__.return_value = session
        client.driver.session.return_value.__exit__.return_value = False
        monkeypatch.setattr(query_api, "neo4j_client", client)
        resp = TestClient(query_api.app).post("/search/indicator", json={"value": "1.2.3.4"})
        assert resp.status_code != 503 and client.connect_calls == 1


class TestNatsReconnectPolicy:
    def test_connect_requests_unbounded_reconnects_with_callbacks(self, monkeypatch):
        nats_client = _real_nats_client()
        captured: dict = {}

        async def fake_connect(**kwargs):
            captured.update(kwargs)
            return MagicMock(connected_url="nats://edge:4222")

        monkeypatch.setattr(nats_client.nats, "connect", fake_connect)
        client = nats_client.NATSClient(["nats://edge:4222"], use_tls=False)
        assert asyncio.run(client.connect()) is True
        assert captured["max_reconnect_attempts"] == -1
        assert captured["reconnect_time_wait"] == 5
        for name in ("disconnected_cb", "reconnected_cb", "error_cb", "closed_cb"):
            assert asyncio.iscoroutinefunction(captured[name]), name

    def test_callbacks_log_state_changes(self, caplog):
        nats_client = _real_nats_client()
        client = nats_client.NATSClient(["nats://edge:4222"], use_tls=False)
        client.nc = MagicMock(connected_url="nats://edge:4222")
        with caplog.at_level(logging.INFO, logger="nats_client"):
            asyncio.run(client._on_disconnected())
            asyncio.run(client._on_reconnected())
            asyncio.run(client._on_error(RuntimeError("slow consumer")))
            asyncio.run(client._on_closed())
        messages = [r.getMessage() for r in caplog.records]
        assert any("Disconnected" in m for m in messages)
        assert any("Reconnected to nats://edge:4222" in m for m in messages)
        assert any("slow consumer" in m for m in messages)
        assert any("Connection closed" in m for m in messages)


class TestHealthProbeTimeout:
    def test_hung_probe_returns_at_the_deadline(self, monkeypatch):
        release = threading.Event()

        class _HangingClient:
            def __init__(self, **_kw):
                pass

            def connect(self):
                release.wait(5)  # simulates a driver that does not answer
                return False

        monkeypatch.setattr(health_check, "Neo4jClient", _HangingClient)
        monkeypatch.setattr(health_check, "NEO4J_HEALTH_TIMEOUT_SEC", 0.3)
        started = time.monotonic()
        try:
            result = health_check.health_check_neo4j(neo4j_uri="bolt://x", neo4j_user="u", neo4j_password="p")
        finally:
            release.set()
        elapsed = time.monotonic() - started
        assert result["healthy"] is False and "timed out" in result["error"]
        assert elapsed < 2.0, f"the caller waited {elapsed:.1f}s for a hung probe; the timeout was 0.3s"


class TestRejectionCounterLabel:
    def _value(self, source: str, reason: str) -> float:
        return metrics_server.SOURCE_TRUTHFUL_CREATOR_REJECTED.labels(source_id=source, reason=reason)._value.get()

    def test_registered_source_keeps_its_canonical_id(self):
        before = self._value("nvd", "creator_org_not_allowlisted")
        metrics_server.record_source_truthful_creator_rejected("NVD", "creator_org_not_allowlisted")
        assert self._value("nvd", "creator_org_not_allowlisted") == before + 1

    def test_unregistered_source_collapses_to_other(self):
        before = self._value("<other>", "creator_org_not_allowlisted")
        metrics_server.record_source_truthful_creator_rejected(
            "attacker-controlled-" + "x" * 40, "creator_org_not_allowlisted"
        )
        assert self._value("<other>", "creator_org_not_allowlisted") == before + 1
        assert not any(
            re.match(r"attacker-controlled", key[0]) for key in metrics_server.SOURCE_TRUTHFUL_CREATOR_REJECTED._metrics
        )

    def test_missing_source_is_unknown(self):
        before = self._value("<unknown>", "creator_org_missing")
        metrics_server.record_source_truthful_creator_rejected(None, "creator_org_missing")
        assert self._value("<unknown>", "creator_org_missing") == before + 1
