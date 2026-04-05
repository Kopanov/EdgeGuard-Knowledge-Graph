"""
Tests for the batching logic in build_relationships.py.

Verifies that _safe_run_batched correctly constructs apoc.periodic.iterate
Cypher, handles success/partial-failure/error cases, and that all 11 queries
in build_relationships() use the batched path with inter-query pauses.
"""

import inspect
import logging
import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Drop stale cached modules so we always get fresh imports
for _mod in ("build_relationships", "neo4j_client"):
    if _mod in sys.modules:
        del sys.modules[_mod]

import build_relationships  # noqa: E402
from build_relationships import _safe_run_batched  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_client():
    """Return a MagicMock that acts as a Neo4jClient for _safe_run_batched."""
    client = MagicMock()
    return client


# ===========================================================================
# 1. _safe_run_batched constructs correct apoc.periodic.iterate Cypher
# ===========================================================================


class TestBatchedCypherConstruction:
    """Verify the Cypher string passed to client.run()."""

    def test_contains_apoc_periodic_iterate(self):
        client = _mock_client()
        client.run.return_value = [{"count": 10, "batches": 1, "errorMessages": []}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key")
        query = client.run.call_args[0][0]
        assert "CALL apoc.periodic.iterate" in query

    def test_contains_batch_size_1000(self):
        client = _mock_client()
        client.run.return_value = [{"count": 10, "batches": 1, "errorMessages": []}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key")
        query = client.run.call_args[0][0]
        assert "batchSize: 1000" in query

    def test_contains_parallel_false(self):
        client = _mock_client()
        client.run.return_value = [{"count": 10, "batches": 1, "errorMessages": []}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key")
        query = client.run.call_args[0][0]
        assert "parallel: false" in query

    def test_custom_batch_size(self):
        client = _mock_client()
        client.run.return_value = [{"count": 10, "batches": 1, "errorMessages": []}]
        stats = {}
        _safe_run_batched(
            client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key", batch_size=500
        )
        query = client.run.call_args[0][0]
        assert "batchSize: 500" in query


# ===========================================================================
# 2. _safe_run_batched handles successful result
# ===========================================================================


class TestBatchedSuccess:
    """Verify stats and return value on a clean run."""

    def test_returns_true(self):
        client = _mock_client()
        client.run.return_value = [{"count": 100, "batches": 5, "errorMessages": []}]
        stats = {}
        result = _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "ok_key")
        assert result is True

    def test_stats_updated(self):
        client = _mock_client()
        client.run.return_value = [{"count": 100, "batches": 5, "errorMessages": []}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "ok_key")
        assert stats["ok_key"] == 100

    def test_empty_result(self):
        client = _mock_client()
        client.run.return_value = []
        stats = {}
        result = _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "empty_key")
        assert result is True
        assert stats["empty_key"] == 0


# ===========================================================================
# 3. _safe_run_batched handles partial failure
# ===========================================================================


class TestBatchedPartialFailure:
    """Verify behaviour when apoc.periodic.iterate reports errorMessages."""

    def test_returns_true_on_partial(self):
        client = _mock_client()
        client.run.return_value = [{"count": 80, "batches": 5, "errorMessages": ["some error"]}]
        stats = {}
        result = _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "partial_key")
        assert result is True

    def test_stats_updated_on_partial(self):
        client = _mock_client()
        client.run.return_value = [{"count": 80, "batches": 5, "errorMessages": ["some error"]}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "partial_key")
        assert stats["partial_key"] == 80

    def test_warning_logged_on_partial(self, caplog):
        client = _mock_client()
        client.run.return_value = [{"count": 80, "batches": 5, "errorMessages": ["some error"]}]
        stats = {}
        with caplog.at_level(logging.WARNING):
            _safe_run_batched(client, "test-label", "MATCH (n) RETURN n", "SET n.x = 1", stats, "partial_key")
        assert any("PARTIAL" in rec.message and "test-label" in rec.message for rec in caplog.records)


# ===========================================================================
# 4. _safe_run_batched handles complete failure (exception)
# ===========================================================================


class TestBatchedCompleteFailure:
    """Verify behaviour when client.run() raises an exception."""

    def test_returns_false(self):
        client = _mock_client()
        client.run.side_effect = Exception("Neo4j OOM")
        stats = {}
        result = _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "fail_key")
        assert result is False

    def test_stats_set_to_zero(self):
        client = _mock_client()
        client.run.side_effect = Exception("Neo4j OOM")
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "fail_key")
        assert stats["fail_key"] == 0


# ===========================================================================
# 5. All 11 queries use _safe_run_batched (not _safe_run)
# ===========================================================================


class TestAllQueriesUseBatched:
    """Ensure build_relationships() calls _safe_run_batched for every query."""

    def test_no_safe_run_calls_in_build_relationships(self):
        """The body of build_relationships() must not call _safe_run (un-batched)."""
        source = inspect.getsource(build_relationships.build_relationships)
        # Remove the function definition line itself and any comments/strings mentioning _safe_run
        # We specifically look for calls: _safe_run( but not _safe_run_batched(
        import re

        # Find all _safe_run( calls that are NOT _safe_run_batched(
        unbatched_calls = re.findall(r"(?<!_batched)\b_safe_run\s*\(", source)
        # Also filter out the function definition itself
        # _safe_run is only defined at module level, not inside build_relationships,
        # so any match here is an actual call
        assert len(unbatched_calls) == 0, (
            f"Found {len(unbatched_calls)} un-batched _safe_run() call(s) in build_relationships(). "
            "All queries should use _safe_run_batched()."
        )

    def test_safe_run_batched_called_for_all_queries(self):
        """Count _safe_run_batched calls — should be at least 10 (queries 1-10)."""
        source = inspect.getsource(build_relationships.build_relationships)
        import re

        batched_calls = re.findall(r"_safe_run_batched\s*\(", source)
        assert len(batched_calls) >= 10, (
            f"Expected at least 10 _safe_run_batched() calls, found {len(batched_calls)}"
        )


# ===========================================================================
# 6. Inter-query pauses exist
# ===========================================================================


class TestInterQueryPauses:
    """Verify that time.sleep(_INTER_QUERY_PAUSE) is called between queries."""

    def test_sleep_calls_in_source(self):
        """The source of build_relationships() must contain time.sleep(_INTER_QUERY_PAUSE)."""
        source = inspect.getsource(build_relationships.build_relationships)
        assert "time.sleep(_INTER_QUERY_PAUSE)" in source, (
            "build_relationships() must call time.sleep(_INTER_QUERY_PAUSE) between queries"
        )

    def test_inter_query_pause_value(self):
        """_INTER_QUERY_PAUSE should be a positive number."""
        assert build_relationships._INTER_QUERY_PAUSE > 0
