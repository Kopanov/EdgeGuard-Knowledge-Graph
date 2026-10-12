"""
apoc.periodic.iterate failure detection in _safe_run_batched.

Field observation (local 800-day baseline, 2026-09-16): one OTX day-event held
115,654 Indicators and 3,196 Malware, so the whole-event Indicator → Malware
co-occurrence step (since removed upstream) targeted ~370M INDICATES edges and
exhausted a 2 GB Neo4j heap.
``apoc.periodic.iterate`` returned a row with empty ``errorMessages``, so
``_safe_run_batched`` logged ``[OK]`` and ``build_relationships`` reported
``failures=0/12``.

Pinned here: ``_safe_run_batched`` treats every failure column APOC reports
(``failedBatches``, ``failedOperations``, ``wasTerminated``, ``batch.errors``,
``operations.errors``) as a failure, not only ``errorMessages``, logs
relationships actually created, and forwards ``params`` to the iterate config.
(The Q4 co-occurrence query itself was removed upstream in 2026-10; the
per-event bound that used to live here is gone with it.)
"""

import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

for _mod in ("build_relationships", "neo4j_client"):
    if _mod in sys.modules:
        del sys.modules[_mod]

import build_relationships  # noqa: E402
from build_relationships import _safe_run_batched  # noqa: E402


def _clean_row(**overrides):
    row = {
        "count": 3905,
        "batches": 1,
        "errorMessages": {},
        "failedBatches": 0,
        "failedOperations": 0,
        "wasTerminated": False,
        "batch": {"total": 1, "committed": 1, "failed": 0, "errors": {}},
        "operations": {"total": 3905, "committed": 3905, "failed": 0, "errors": {}},
        "updateStatistics": {"relationshipsCreated": 12},
    }
    row.update(overrides)
    return row


def _run(row, caplog=None, **kwargs):
    client = MagicMock()
    client.run.return_value = [row]
    stats = {}
    result = _safe_run_batched(client, "q-label", "MATCH (n) RETURN n", "SET n.x = 1", stats, "k", **kwargs)
    return result, client, stats


# ===========================================================================
# (c) _safe_run_batched detects every APOC failure signal
# ===========================================================================


class TestApocFailureColumns:
    def test_query_yields_failure_and_update_columns(self):
        _, client, _ = _run(_clean_row())
        query = client.run.call_args[0][0]
        for column in (
            "failedBatches",
            "failedOperations",
            "wasTerminated",
            "batch",
            "operations",
            "updateStatistics",
        ):
            assert column in query, f"YIELD/RETURN must include {column}"

    def test_clean_row_returns_true(self):
        result, _, stats = _run(_clean_row())
        assert result is True
        assert stats["k"] == 3905

    @pytest.mark.parametrize(
        "overrides",
        [
            {"errorMessages": {"/ by zero": 3}},
            {"failedBatches": 1},
            {"failedOperations": 3905},
            {"wasTerminated": True},
            {"batch": {"total": 1, "committed": 0, "failed": 1, "errors": {"java.lang.OutOfMemoryError": 1}}},
            {"operations": {"total": 3905, "committed": 0, "failed": 0, "errors": {"boom": 1}}},
        ],
        ids=["errorMessages", "failedBatches", "failedOperations", "wasTerminated", "batch.errors", "operations.errors"],
    )
    def test_any_failure_signal_returns_false(self, overrides):
        result, _, _ = _run(_clean_row(**overrides))
        assert result is False, f"{overrides} must fail the step, not log [OK]"

    def test_failure_signal_logs_partial_not_ok(self, caplog):
        with caplog.at_level(logging.INFO):
            _run(_clean_row(failedBatches=1))
        messages = [rec.message for rec in caplog.records]
        assert any("[PARTIAL]" in m and "q-label" in m for m in messages)
        assert not any("[OK]" in m for m in messages)
        partial = next(m for m in messages if "[PARTIAL]" in m)
        assert "relationships reported 12 (may include rolled-back batches)" in partial
        assert "relationships created" not in partial

    def test_error_messages_map_logs_partial(self, caplog):
        """errorMessages is a map {message: count}, not a list. Before this fix the
        [PARTIAL] log line sliced it (``errors[:3]``) and raised
        ``KeyError: slice(None, 3, None)``, so any batch error took the exception
        path: no [PARTIAL] line, no partial-batch metric. Row observed on the local
        stack 2026-10-12 for an inner query ``RETURN 1/0`` over 3 batches."""
        with caplog.at_level(logging.INFO):
            result, _, _ = _run(_clean_row(errorMessages={"/ by zero": 3}, failedBatches=3, failedOperations=3))
        assert result is False
        messages = [rec.message for rec in caplog.records]
        assert not any("[FAIL]" in m for m in messages), messages
        partial = next(m for m in messages if "[PARTIAL]" in m)
        assert "errorMessages={'/ by zero': 3}" in partial

    def test_heap_oom_row_from_enigma_fails(self):
        """Row shape observed on the local stack 2026-09-17 when the co-occurrence step exhausted the heap
        and the JVM survived: errorMessages empty, failure only in
        failedBatches and batch.errors."""
        row = _clean_row(
            failedBatches=1,
            batch={
                "total": 1,
                "committed": 0,
                "failed": 1,
                "errors": {"java.lang.OutOfMemoryError: Java heap space": 1},
            },
            updateStatistics={"relationshipsCreated": 1040886},
        )
        result, _, _ = _run(row)
        assert result is False

    def test_failure_signal_fires_partial_metric(self, monkeypatch):
        recorder = MagicMock()
        fake_metrics = MagicMock(record_apoc_batch_partial=recorder)
        monkeypatch.setattr(build_relationships, "_METRICS_AVAILABLE", True)
        monkeypatch.setitem(sys.modules, "metrics_server", fake_metrics)
        _run(_clean_row(wasTerminated=True))
        recorder.assert_called_once_with(step="k")

    def test_empty_result_logs_fail_not_ok(self, caplog):
        client = MagicMock()
        client.run.return_value = []
        with caplog.at_level(logging.INFO):
            result = _safe_run_batched(client, "q-label", "MATCH (n) RETURN n", "SET n.x = 1", {}, "k")
        messages = [rec.message for rec in caplog.records]
        assert result is False
        assert any("[FAIL]" in m and "q-label" in m for m in messages)
        assert not any("[OK]" in m for m in messages)

    def test_legacy_row_without_new_columns_still_succeeds(self):
        result, _, _ = _run({"count": 10, "batches": 1, "errorMessages": []})
        assert result is True

    def test_ok_log_reports_relationships_created(self, caplog):
        with caplog.at_level(logging.INFO):
            _run(_clean_row())
        ok = [rec.message for rec in caplog.records if "[OK]" in rec.message]
        assert ok, "clean run must log [OK]"
        assert "relationships created 12" in ok[0]
        assert "outer rows 3905" in ok[0]


class TestIterateParams:
    def test_params_are_passed_to_iterate_config_and_driver(self):
        _, client, _ = _run(_clean_row(), params={"q4_skip_event_ids": ["10"]})
        query = client.run.call_args[0][0]
        assert "params: $iterate_params" in query
        assert client.run.call_args[0][1] == {"iterate_params": {"q4_skip_event_ids": ["10"]}}

    def test_no_params_keeps_driver_call_unchanged(self):
        _, client, _ = _run(_clean_row())
        assert len(client.run.call_args[0]) == 1
        assert "params:" not in client.run.call_args[0][0]


# ===========================================================================
# (a) _safe_run_batched forwards params to apoc.periodic.iterate
# ===========================================================================
