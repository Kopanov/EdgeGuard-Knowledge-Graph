"""
PR-N15 — pre-baseline recovery hardening.

Two must-fix-before-baseline findings from the 7-agent audit's
Recovery-Audit + Cypher-Correctness passes. Both are silent-data-loss
vectors that will fire during a 730-day baseline and were rated BLOCK
in the post-audit triage.

## Fix #1 — ``.run()`` swallowed ``DatabaseError``-wrapped deadlocks

``src/neo4j_client.py:705-754`` — Neo4j wraps some deadlocks /
lock-acquisition timeouts as ``Neo.DatabaseError.Statement.ExecutionFailed``
rather than surfacing them as ``neo4j.exceptions.TransientError`` in
the Python driver. The ``retry_with_backoff`` decorator only retried
on ``TransientError``; the ``except DatabaseError`` handler in
``run()`` returned ``[]`` and the caller saw "0 rows, success".

Same class as the PR-N7 ``<> ''`` silent-zero-edge bug — different
layer, same failure mode. At 730d scale with concurrent
``build_relationships`` + ``enrichment_jobs`` writers, this was
guaranteed to fire.

Fix: new ``_is_retryable_neo4j_error(exc)`` classifier that inspects
``exc.code`` for Neo4j transient codes (``Neo.TransientError.*``,
``Transaction.DeadlockDetected``, ``LockAcquisitionTimeout``,
``General.DatabaseUnavailable``, ``Cluster.NotALeader``). Extended
``retry_with_backoff`` + ``run()`` ``except DatabaseError`` handler to
re-raise retryable subclasses + return ``[]`` only for truly terminal
errors (schema / constraint / syntax).

## Fix #2 — ``merge_indicators_batch`` / ``merge_vulnerabilities_batch`` lost entire batch

``src/neo4j_client.py:2255-2287`` + ``:2465-2488`` — bare
``except Exception: error_count += len(batch)`` with no retry. A 5-
second Neo4j GC pause mid-NVD-sync dropped 1000 CVEs per batch. Over
a 730d baseline with ~30 sync cycles, thousands of nodes silently
lost. No counter, no alert, just one WARN log line per batch.

Fix: new ``_execute_batch_with_retry(driver, query, ...)`` helper
that (a) retries on ``_is_retryable_neo4j_error`` with exponential
backoff (2s → 4s → 8s, 3 retries), (b) runs ``_record_batch_counters``
(PR-N9 B6 silent-write detector) on success, (c) emits
``edgeguard_neo4j_batch_permanent_failure_total{label, source,
reason}`` on permanent failure so operators can alert on silent data
loss.

Both ``merge_indicators_batch`` and ``merge_vulnerabilities_batch``
now use the helper. The outer ``except Exception`` is kept as a
last-resort invariant (one bad batch must not crash the whole sync)
but now ALSO emits the permanent-failure counter so the operator
sees it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n15")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n15")


# ===========================================================================
# Fix #1 — ``_is_retryable_neo4j_error`` classifier
# ===========================================================================


class TestFix1RetryableClassifier:
    def test_classifier_exists(self):
        from neo4j_client import _is_retryable_neo4j_error  # noqa: F401

    def test_transient_error_is_retryable(self):
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        # Construct a bare TransientError — the driver's usual
        # ServiceUnavailable inherits from the same parent tree.
        exc = neo4j_exc.TransientError("deadlock")
        assert _is_retryable_neo4j_error(exc) is True

    def test_service_unavailable_is_retryable(self):
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.ServiceUnavailable("leader gone")
        assert _is_retryable_neo4j_error(exc) is True

    def test_connection_error_is_retryable(self):
        from neo4j_client import _is_retryable_neo4j_error

        assert _is_retryable_neo4j_error(ConnectionError("socket reset")) is True
        assert _is_retryable_neo4j_error(TimeoutError("timed out")) is True

    def test_database_error_with_transient_code_is_retryable(self):
        """THE PRIMARY PR-N15 FIX: a DatabaseError whose ``.code``
        contains ``Neo.TransientError`` must classify as retryable."""
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.DatabaseError("statement execution failed")
        exc.code = "Neo.TransientError.Transaction.DeadlockDetected"
        assert _is_retryable_neo4j_error(exc) is True, (
            "regression: DatabaseError wrapping a Neo.TransientError.* "
            "code MUST classify as retryable — this was the PR-N7-class "
            "silent-zero-edge bug"
        )

    def test_database_error_with_lock_timeout_is_retryable(self):
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.DatabaseError("lock timeout")
        exc.code = "Neo.ClientError.Transaction.LockAcquisitionTimeout"
        assert _is_retryable_neo4j_error(exc) is True

    def test_cluster_failover_is_retryable(self):
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.DatabaseError("not a leader")
        exc.code = "Neo.ClientError.Cluster.NotALeader"
        assert _is_retryable_neo4j_error(exc) is True

    def test_cypher_syntax_error_is_not_retryable(self):
        """Terminal errors (schema / syntax / constraint) must NOT
        retry — they'll never succeed."""
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.CypherSyntaxError("bad syntax")
        assert _is_retryable_neo4j_error(exc) is False

    def test_database_error_without_code_is_not_retryable(self):
        """Defensive: if .code is missing, classify as terminal. A
        false-terminal is safer than a false-retryable (infinite retry
        on a bug)."""
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _is_retryable_neo4j_error

        exc = neo4j_exc.DatabaseError("unknown")
        # no .code set
        assert _is_retryable_neo4j_error(exc) is False

    def test_generic_exception_is_not_retryable(self):
        from neo4j_client import _is_retryable_neo4j_error

        assert _is_retryable_neo4j_error(ValueError("nope")) is False
        assert _is_retryable_neo4j_error(RuntimeError("nope")) is False


# ===========================================================================
# Fix #1 — ``.run()`` re-raises retryable DatabaseError
# ===========================================================================


class TestFix1RunReRaisesRetryableDbError:
    def _client(self, session_mock):
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session_mock
        driver.session.return_value.__exit__.return_value = False
        c.driver = driver
        return c

    def test_run_raises_retryable_database_error_through_decorator(self):
        """When session.run raises a DatabaseError with a retryable
        code, ``.run()`` must re-raise so the ``@retry_with_backoff``
        decorator retries. Pre-PR-N15 it returned ``[]`` (silent)."""
        from neo4j import exceptions as neo4j_exc

        # Session.run raises a retryable-coded DatabaseError on every call.
        exc = neo4j_exc.DatabaseError("deadlock")
        exc.code = "Neo.TransientError.Transaction.DeadlockDetected"
        session = MagicMock()
        session.run.side_effect = exc

        client = self._client(session)
        # The decorator retries (max_retries=3) + re-raises on exhaustion.
        # We expect the final raise to surface to the test caller — NOT
        # a silent empty-list return.
        with pytest.raises(neo4j_exc.DatabaseError):
            client.run("MATCH (n) RETURN n")
        # session.run called (1 attempt + 3 retries) = 4 times.
        assert session.run.call_count == 4

    def test_run_returns_empty_on_terminal_database_error(self):
        """A DatabaseError without a retryable code still returns []
        (preserves PR-N15-pre-existing behaviour for truly terminal
        errors — no regression)."""
        from neo4j import exceptions as neo4j_exc

        exc = neo4j_exc.DatabaseError("schema drift")
        # No retryable code — no .code set, or a constraint-class code.
        exc.code = "Neo.ClientError.Schema.ConstraintValidationFailed"
        session = MagicMock()
        session.run.side_effect = exc

        client = self._client(session)
        # Should NOT retry + should NOT raise to caller — return [].
        result = client.run("MATCH (n) RETURN n")
        assert result == []
        # Only ONE attempt (no retry on terminal).
        assert session.run.call_count == 1


# ===========================================================================
# Fix #2 + #3 — ``_execute_batch_with_retry`` helper
# ===========================================================================


class TestFix2_3BatchRetryHelper:
    def test_helper_exists(self):
        from neo4j_client import (
            _emit_batch_permanent_failure,  # noqa: F401
            _execute_batch_with_retry,  # noqa: F401
        )

    def test_success_path_returns_ok_and_runs_counter_inspection(self):
        """Happy path: session.run succeeds on first try, returns
        (True, batch_len), and _record_batch_counters is invoked."""
        from neo4j_client import _execute_batch_with_retry

        session = MagicMock()
        result_mock = MagicMock()
        consumed = MagicMock()
        consumed.nodes_created = 10
        consumed.properties_set = 20
        result_mock.consume.return_value.counters = consumed
        session.run.return_value = result_mock
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = False

        ok, rows = _execute_batch_with_retry(
            driver,
            "UNWIND $batch AS item MERGE (n:Indicator {value: item.value}) RETURN n",
            label="Indicator",
            source_id="otx",
            batch_len=100,
            query_kwargs={"batch": [{"value": "x"}]},
        )
        assert ok is True
        assert rows == 100
        # Counter inspection happened (consume() called).
        result_mock.consume.assert_called_once()

    def test_transient_error_retries_with_backoff(self, monkeypatch):
        """On a transient error (TransientError raised first 2 times,
        succeeds 3rd), helper must retry, not give up after the first."""
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _execute_batch_with_retry

        # Skip the sleep delays for fast tests.
        monkeypatch.setattr("neo4j_client.time.sleep", lambda *_args, **_kwargs: None)

        result_mock = MagicMock()
        consumed = MagicMock()
        consumed.nodes_created = 1
        consumed.properties_set = 1
        result_mock.consume.return_value.counters = consumed

        # First two calls raise, third succeeds.
        session = MagicMock()
        session.run.side_effect = [
            neo4j_exc.TransientError("deadlock 1"),
            neo4j_exc.TransientError("deadlock 2"),
            result_mock,
        ]
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = False

        ok, rows = _execute_batch_with_retry(
            driver,
            "UNWIND $batch AS item MERGE (n:Indicator {value: item.value}) RETURN n",
            label="Indicator",
            source_id="otx",
            batch_len=50,
            query_kwargs={"batch": [{"value": "x"}]},
        )
        assert ok is True
        assert rows == 50
        # 3 attempts total (2 failures + success)
        assert session.run.call_count == 3

    def test_permanent_failure_after_retry_exhaustion(self, monkeypatch, caplog):
        """After max_retries transient errors, helper returns (False,
        batch_len) + emits permanent-failure counter + ERROR log."""
        import logging

        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _execute_batch_with_retry

        monkeypatch.setattr("neo4j_client.time.sleep", lambda *_args, **_kwargs: None)

        session = MagicMock()
        session.run.side_effect = neo4j_exc.TransientError("persistent deadlock")
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = False

        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            ok, rows = _execute_batch_with_retry(
                driver,
                "UNWIND $batch AS item MERGE (n) RETURN n",
                label="Indicator",
                source_id="otx",
                batch_len=1000,
                query_kwargs={"batch": []},
                max_retries=2,  # tight budget for test
            )
        assert ok is False
        assert rows == 1000
        # 1 initial + 2 retries = 3 attempts
        assert session.run.call_count == 3
        # Permanent-failure log line fires (reason is on the counter
        # label, not in the log message — that's what the counter test
        # covers).
        assert any("[BATCH-PERMANENT-FAILURE]" in r.message for r in caplog.records)
        # Must indicate the retry path (message mentions "retries" /
        # "after N retries").
        assert any("[BATCH-PERMANENT-FAILURE]" in r.message and "retries" in r.message for r in caplog.records)

    def test_non_retryable_error_fails_fast_no_retry(self, monkeypatch, caplog):
        """A CypherSyntaxError or ConstraintValidationError must
        NOT retry — that would be a waste."""
        import logging

        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _execute_batch_with_retry

        monkeypatch.setattr("neo4j_client.time.sleep", lambda *_args, **_kwargs: None)

        session = MagicMock()
        session.run.side_effect = neo4j_exc.CypherSyntaxError("bad query")
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = False

        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            ok, rows = _execute_batch_with_retry(
                driver,
                "invalid cypher",
                label="Indicator",
                source_id="otx",
                batch_len=100,
                query_kwargs={"batch": []},
            )
        assert ok is False
        assert rows == 100
        # Only ONE attempt — must not retry terminal.
        assert session.run.call_count == 1
        # Permanent-failure log line fires, naming the exception class.
        assert any(
            "[BATCH-PERMANENT-FAILURE]" in r.message and "CypherSyntaxError" in r.message for r in caplog.records
        )
        # The non-retryable path also mentions the word "non-retryable"
        # in the log line so operators can distinguish from retry-exhausted.
        assert any("[BATCH-PERMANENT-FAILURE]" in r.message and "non-retryable" in r.message for r in caplog.records)

    def test_database_error_wrapping_deadlock_retries(self, monkeypatch):
        """The PR-N15 BLOCK fix core: a DatabaseError with a retryable
        ``.code`` must retry (was silent-pass-through before)."""
        from neo4j import exceptions as neo4j_exc
        from neo4j_client import _execute_batch_with_retry

        monkeypatch.setattr("neo4j_client.time.sleep", lambda *_args, **_kwargs: None)

        # Build a DatabaseError with a retryable code.
        wrapped = neo4j_exc.DatabaseError("execution failed wrapping deadlock")
        wrapped.code = "Neo.TransientError.Transaction.DeadlockDetected"

        # Fail twice then succeed.
        result_mock = MagicMock()
        consumed = MagicMock()
        consumed.nodes_created = 1
        consumed.properties_set = 1
        result_mock.consume.return_value.counters = consumed

        session = MagicMock()
        session.run.side_effect = [wrapped, wrapped, result_mock]
        driver = MagicMock()
        driver.session.return_value.__enter__.return_value = session
        driver.session.return_value.__exit__.return_value = False

        ok, _ = _execute_batch_with_retry(
            driver,
            "UNWIND $batch AS item MERGE (n) RETURN n",
            label="Indicator",
            source_id="otx",
            batch_len=100,
            query_kwargs={"batch": []},
        )
        assert ok is True
        assert session.run.call_count == 3


# ===========================================================================
# Fix #2 — merge_indicators_batch uses the helper
# ===========================================================================


def _extract_function_body(src: str, def_name: str) -> str:
    """Return the body of a top-level or method `def` up to the next
    `def ` at the same indentation (or EOF). Handles the fact that
    merge_indicators_batch is huge (>16K chars, bigger than a fixed
    window)."""
    start = src.find(def_name)
    assert start != -1, f"{def_name!r} not found"
    # Detect leading indent (spaces before "def").
    line_start = src.rfind("\n", 0, start) + 1
    indent = src[line_start:start]
    # Find next "def " at SAME indent (and not immediately).
    marker = f"\n{indent}def "
    end = src.find(marker, start + len(def_name))
    if end == -1:
        # Try class-scope end (next def at module level).
        end = src.find("\nclass ", start + len(def_name))
    if end == -1:
        end = len(src)
    return src[start:end]


class TestFix2MergeIndicatorsBatchUsesHelper:
    def test_batch_uses_execute_batch_with_retry(self):
        """Regression pin: ``merge_indicators_batch`` must call
        ``_execute_batch_with_retry`` (not the old bare session.run
        pattern)."""
        src = (SRC / "neo4j_client.py").read_text()
        block = _extract_function_body(src, "def merge_indicators_batch")
        assert "_execute_batch_with_retry" in block, "merge_indicators_batch must use the retry helper"
        assert 'label="Indicator"' in block

    def test_batch_no_longer_has_bare_except_without_counter(self):
        """Regression pin: the outer except must emit the permanent-
        failure counter, not silently log and increment error_count."""
        src = (SRC / "neo4j_client.py").read_text()
        block = _extract_function_body(src, "def merge_indicators_batch")
        if "error_count += len(batch)" in block:
            assert '_emit_batch_permanent_failure(label="Indicator"' in block, (
                "outer except for merge_indicators_batch must emit permanent-failure counter"
            )


# ===========================================================================
# Fix #3 — merge_vulnerabilities_batch uses the helper
# ===========================================================================


class TestFix3MergeVulnerabilitiesBatchUsesHelper:
    def test_batch_uses_execute_batch_with_retry(self):
        src = (SRC / "neo4j_client.py").read_text()
        block = _extract_function_body(src, "def merge_vulnerabilities_batch")
        assert "_execute_batch_with_retry" in block, "merge_vulnerabilities_batch must use the retry helper"
        assert 'label="Vulnerability"' in block

    def test_outer_except_emits_counter(self):
        src = (SRC / "neo4j_client.py").read_text()
        block = _extract_function_body(src, "def merge_vulnerabilities_batch")
        if "error_count += len(batch)" in block:
            assert '_emit_batch_permanent_failure(label="Vulnerability"' in block


# ===========================================================================
# Metrics counter declaration
# ===========================================================================


class TestPermanentFailureCounterDeclared:
    def test_counter_exists_in_metrics_server(self):
        src = (SRC / "metrics_server.py").read_text()
        assert "NEO4J_BATCH_PERMANENT_FAILURES" in src
        assert '"edgeguard_neo4j_batch_permanent_failure_total"' in src
        # Bounded labels only — label, source, reason
        # (no event_id / uuid / attribute_id / … unbounded axes)
        idx = src.find("NEO4J_BATCH_PERMANENT_FAILURES = Counter(")
        assert idx != -1
        block = src[idx : idx + 2000]
        assert '["label", "source", "reason"]' in block

    def test_counter_imported_with_graceful_fallback(self):
        """Same PR-N9/PR-N10 pattern: None-fallback on ImportError."""
        src = (SRC / "neo4j_client.py").read_text()
        assert "NEO4J_BATCH_PERMANENT_FAILURES as _NEO4J_BATCH_PERMANENT_FAILURES" in src
        assert "_NEO4J_BATCH_PERMANENT_FAILURES = None" in src  # fallback


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports_and_exports(self):
        from neo4j_client import (  # noqa: F401
            _emit_batch_permanent_failure,
            _execute_batch_with_retry,
            _is_retryable_neo4j_error,
        )

    def test_metrics_server_imports(self):
        from metrics_server import NEO4J_BATCH_PERMANENT_FAILURES  # noqa: F401
