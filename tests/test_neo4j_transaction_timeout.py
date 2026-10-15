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

import pytest

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


# --------------------------------------------------------------------------- a timeout is logged (2026-10)
class _TimedOut(Exception):
    code = "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration"


class _SyntaxError(Exception):
    code = "Neo.ClientError.Statement.SyntaxError"


class _RaisingResult:
    def __init__(self, exc):
        self.exc = exc

    def single(self):
        raise self.exc

    def __iter__(self):
        raise self.exc


class _SessionWith:
    def __init__(self, result, close_error=None):
        self.result = result
        self.close_error = close_error

    def run(self, query, parameters=None, **kwargs):
        return self.result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self.close_error is not None:
            raise self.close_error
        return None


def _timeout_lines(caplog):
    return [r.getMessage() for r in caplog.records if "[NEO4J-TIMEOUT]" in r.getMessage()]


class TestTimeoutIsLogged:
    def test_a_timeout_raised_while_reading_names_the_statement_and_its_limit(self, caplog):
        session = nc._TimeoutSession(_SessionWith(_RaisingResult(_TimedOut("terminated"))))
        result = session.run("MATCH (n)\n   RETURN count(n) AS c", timeout=1200)
        with pytest.raises(_TimedOut):
            result.single()
        (line,) = _timeout_lines(caplog)
        assert "1200 s" in line and "MATCH (n) RETURN count(n) AS c" in line

    def test_a_timeout_raised_while_iterating_is_logged(self, caplog):
        session = nc._TimeoutSession(_SessionWith(_RaisingResult(_TimedOut("terminated"))))
        with pytest.raises(_TimedOut):
            list(session.run("MATCH (n) RETURN n", timeout=60))
        assert len(_timeout_lines(caplog)) == 1

    def test_a_timeout_surfacing_when_the_session_closes_is_logged(self, caplog):
        inner = _SessionWith(object(), close_error=_TimedOut("terminated"))
        with pytest.raises(_TimedOut):
            with nc._TimeoutSession(inner) as s:
                s.run("CALL apoc.periodic.iterate('x', 'y', {})", timeout=300)
        (line,) = _timeout_lines(caplog)
        assert "300 s" in line and "apoc.periodic.iterate" in line

    def test_other_errors_are_not_reported_as_timeouts(self, caplog):
        session = nc._TimeoutSession(_SessionWith(_RaisingResult(_SyntaxError("bad"))))
        with pytest.raises(_SyntaxError):
            session.run("MATCH (n RETURN n", timeout=60).single()
        assert _timeout_lines(caplog) == []

    def test_one_timeout_is_logged_once(self, caplog):
        exc = _TimedOut("terminated")
        nc._log_if_timed_out(exc, 60.0, "MATCH (n) RETURN n")
        nc._log_if_timed_out(exc, 60.0, "MATCH (n) RETURN n")
        assert len(_timeout_lines(caplog)) == 1

    def test_without_a_timeout_the_result_is_returned_unchanged(self):
        result = object()
        assert nc._TimeoutSession(_SessionWith(result)).run("RETURN 1") is result

    def test_the_message_names_the_limit_that_applied(self, caplog):
        nc._log_if_timed_out(_TimedOut("a"), float(nc.NEO4J_READ_TIMEOUT), "MATCH (a) RETURN a")
        nc._log_if_timed_out(_TimedOut("b"), float(nc._REL_QUERY_TIMEOUT), "UNWIND $rows AS row MERGE (x)")
        nc._log_if_timed_out(_TimedOut("c"), 300.0, "MATCH (s) RETURN s")
        pipeline, batch, api = _timeout_lines(caplog)
        assert "EDGEGUARD_NEO4J_READ_TIMEOUT" in pipeline
        assert "_REL_QUERY_TIMEOUT" in batch and "EDGEGUARD_NEO4J_READ_TIMEOUT" not in batch
        assert "REST and STIX" in api and "EDGEGUARD_NEO4J_READ_TIMEOUT" not in api

    def test_a_timeout_raised_by_the_next_run_is_logged_against_the_previous_statement(self, caplog):
        class _UnreadThenTimeout:
            def __init__(self):
                self.calls = 0

            def run(self, query, parameters=None, **kwargs):
                self.calls += 1
                if self.calls == 2:  # the driver reads the first, unread result here
                    raise _TimedOut("terminated")
                return object()

        session = nc._TimeoutSession(_UnreadThenTimeout())
        session.run("UNWIND $rows AS row MERGE (a)-[r:USES]->(b)", timeout=600)
        with pytest.raises(_TimedOut):
            session.run("MATCH (n) RETURN count(n)", timeout=3600)
        (line,) = _timeout_lines(caplog)
        assert "600 s" in line and "UNWIND $rows AS row MERGE" in line and "count(n)" not in line
