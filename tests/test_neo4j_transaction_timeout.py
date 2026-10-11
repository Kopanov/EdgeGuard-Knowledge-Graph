"""Real Neo4j transaction timeouts (2026-10 production-readiness check, blocker B2).

The neo4j 5 driver merges unknown ``session.run`` keywords into the Cypher parameters, so the
``timeout=`` every caller passes used to enforce nothing. ``Neo4jClient.connect`` now wraps the
driver in ``_TimeoutDriver``; its sessions turn ``timeout=`` into ``neo4j.Query(text, timeout=…)``,
which the server honours as a transaction timeout. No call site changed.
"""

from __future__ import annotations

import inspect
import os
import sys
from unittest.mock import MagicMock

from neo4j import Query

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
if "neo4j_client" in sys.modules and not hasattr(sys.modules["neo4j_client"], "__file__"):
    del sys.modules["neo4j_client"]
import neo4j_client as nc  # noqa: E402


class _RecordingSession:
    def __init__(self):
        self.calls = []
        self.entered = self.exited = False

    def run(self, query, parameters=None, **kwargs):
        self.calls.append((query, parameters, kwargs))
        result = MagicMock()
        result.single.return_value = {"test": 1}
        return result

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, *exc):
        self.exited = True
        return False

    def close(self):
        pass


class _RecordingDriver:
    def __init__(self):
        self.session_kwargs = []
        self.closed = False
        self.sessions = []

    def session(self, **kwargs):
        self.session_kwargs.append(kwargs)
        s = _RecordingSession()
        self.sessions.append(s)
        return s

    def verify_connectivity(self):
        return None

    def close(self):
        self.closed = True


class TestSessionProxy:
    def test_timeout_keyword_becomes_a_query_timeout(self):
        inner = _RecordingSession()
        nc._TimeoutSession(inner).run("RETURN $x AS x", x=1, timeout=30)
        query, parameters, kwargs = inner.calls[0]
        assert isinstance(query, Query) and query.text == "RETURN $x AS x" and query.timeout == 30.0
        assert parameters is None and kwargs == {"x": 1}, "timeout must not reach the Cypher parameters"

    def test_without_timeout_the_statement_passes_through_unchanged(self):
        inner = _RecordingSession()
        nc._TimeoutSession(inner).run("RETURN 1", {"a": 2}, b=3)
        query, parameters, kwargs = inner.calls[0]
        assert query == "RETURN 1" and parameters == {"a": 2} and kwargs == {"b": 3}

    def test_existing_query_objects_are_not_rewrapped(self):
        inner = _RecordingSession()
        q = Query("RETURN 1", timeout=5)
        nc._TimeoutSession(inner).run(q, timeout=99)
        assert inner.calls[0][0] is q

    def test_context_manager_and_delegation(self):
        inner = _RecordingSession()
        with nc._TimeoutSession(inner) as s:
            assert s.run("RETURN 1", timeout=1) is not None
            assert s.close.__self__ is inner  # attribute delegation
        assert inner.entered and inner.exited


class TestSessionProxyYieldingAnotherObject:
    def test_run_goes_to_the_object_the_context_manager_yields(self):
        """Mirrors the repository's mock style: ``__enter__`` yields a different object than the
        manager itself; ``run`` must reach that object and ``__exit__`` must go to the manager."""
        yielded = _RecordingSession()
        manager = MagicMock()
        manager.__enter__ = lambda s: yielded
        manager.__exit__ = MagicMock(return_value=False)
        with nc._TimeoutSession(manager) as s:
            s.run("RETURN 1", timeout=7)
        assert isinstance(yielded.calls[0][0], Query) and yielded.calls[0][0].timeout == 7.0
        manager.__exit__.assert_called_once()


class TestDriverProxy:
    def test_sessions_are_wrapped_and_kwargs_forwarded(self):
        raw = _RecordingDriver()
        driver = nc._TimeoutDriver(raw)
        with driver.session(default_access_mode="READ") as s:
            assert isinstance(s, nc._TimeoutSession)
            s.run("MATCH (n) RETURN count(n)", timeout=120)
        assert raw.session_kwargs == [{"default_access_mode": "READ"}]
        assert isinstance(raw.sessions[0].calls[0][0], Query)
        driver.close()
        assert raw.closed and driver.verify_connectivity() is None


class TestClientWiring:
    def test_connect_wraps_the_driver(self, monkeypatch):
        raw = _RecordingDriver()
        monkeypatch.setattr(nc.GraphDatabase, "driver", lambda *a, **k: raw)
        client = nc.Neo4jClient.__new__(nc.Neo4jClient)
        client.uri, client.user, client.password = "bolt://x:7687", "neo4j", "pw"
        client.driver = None
        client._connection_healthy = False
        assert client.connect() is True
        assert isinstance(client.driver, nc._TimeoutDriver)
        verify_query = raw.sessions[0].calls[0][0]
        assert isinstance(verify_query, Query) and verify_query.text == "RETURN 1 as test" and verify_query.timeout > 0

    def test_connect_source_pins_the_wrapper(self):
        assert "_TimeoutDriver(" in inspect.getsource(inspect.unwrap(nc.Neo4jClient.connect))
