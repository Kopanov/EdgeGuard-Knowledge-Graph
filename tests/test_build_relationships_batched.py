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
from unittest.mock import MagicMock

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

    def test_contains_batch_size_5000(self):
        client = _mock_client()
        client.run.return_value = [{"count": 10, "batches": 1, "errorMessages": []}]
        stats = {}
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key")
        query = client.run.call_args[0][0]
        assert "batchSize: 5000" in query

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
        _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "test_key", batch_size=500)
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

    def test_returns_false_on_partial(self):
        """PR #33 round 13: errorMessages > 0 now flips the return value to
        False so the caller's failures counter reflects partial APOC errors.
        Prior to round 13 this returned True (silent partial-failure)."""
        client = _mock_client()
        client.run.return_value = [{"count": 80, "batches": 5, "errorMessages": ["some error"]}]
        stats = {}
        result = _safe_run_batched(client, "test", "MATCH (n) RETURN n", "SET n.x = 1", stats, "partial_key")
        assert result is False, (
            "round 13: partial APOC errorMessages must flip return value to False — previously returned True silently"
        )

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
        assert len(batched_calls) >= 10, f"Expected at least 10 _safe_run_batched() calls, found {len(batched_calls)}"


# ===========================================================================
# 6. Inter-query pauses exist
# ===========================================================================


class TestInterQueryPauses:
    """Verify that env-gated query_pause() is called between queries.

    PR #40 (Performance Auditor Tier S S10): the previous hardcoded
    ``_INTER_QUERY_PAUSE = 3`` constant burned ~36 seconds per
    build_relationships run × multiple runs/day. Replaced with
    ``query_pause()`` which reads ``EDGEGUARD_QUERY_PAUSE_SECONDS``
    (default 0). The pacing call SITES are still required (so
    operators on memory-constrained Neo4j can opt back in via the
    env var) — what's removed is the hardcoded value.
    """

    def test_query_pause_calls_in_source(self):
        """The source of build_relationships() must contain ``query_pause()``
        between queries — operators need the call sites present so the
        env-gated pause becomes possible to enable. Pre-PR-#40 the
        equivalent assertion was ``time.sleep(_INTER_QUERY_PAUSE)``."""
        source = inspect.getsource(build_relationships.build_relationships)
        assert "query_pause()" in source, (
            "build_relationships() must call query_pause() between queries — "
            "the env-gated replacement for the old hardcoded time.sleep(_INTER_QUERY_PAUSE)"
        )
        # Negative pin: the old hardcoded pattern must NOT come back.
        assert "time.sleep(_INTER_QUERY_PAUSE)" not in source, (
            "PR #40 removed _INTER_QUERY_PAUSE — if this regresses, the audit "
            "finding (30min-3h idle per baseline) returns silently"
        )

    def test_inter_query_pause_constant_removed(self):
        """``_INTER_QUERY_PAUSE`` is GONE — the env var supersedes it."""
        assert not hasattr(build_relationships, "_INTER_QUERY_PAUSE"), (
            "_INTER_QUERY_PAUSE constant must be removed — env-gating via "
            "EDGEGUARD_QUERY_PAUSE_SECONDS is the new contract"
        )
