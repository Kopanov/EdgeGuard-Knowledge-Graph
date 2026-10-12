"""Guards found missing by the 2026-10-12 fresh-baseline smoke run.

1. The ``edgeguard_baseline`` DAG holds the baseline lock for its whole run, so its own
   collector tasks must not skip under it. Before the fix every tier task returned a
   "skipped optional source" result and ended ``success`` having collected nothing.
2. A failed ``baseline_clean`` must stop the chain. The tier groups and ``full_neo4j_sync``
   run with ``trigger_rule=ALL_DONE`` (per-source resilience), which also fires on
   ``upstream_failed``; ``baseline_start`` now publishes an XCom marker and the collectors
   and the full sync refuse to run without it.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
for _p in (_DAGS, _SRC):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _import_dag_module():
    for key in list(sys.modules):
        # Purge airflow itself, not sibling modules such as ``airflow_client`` that other
        # test modules patch by object identity.
        if key in ("edgeguard_pipeline", "airflow", "opentelemetry") or key.startswith(("airflow.", "opentelemetry.")):
            del sys.modules[key]
    import importlib

    try:
        return importlib.import_module("edgeguard_pipeline")
    except Exception:
        pytest.skip("Airflow not installed in this test env")


class _Collector:
    def __init__(self, *_a, **_kw):
        pass

    def collect(self, *_a, **_kw):
        return {"success": True, "count": 1}


def _patched(ep, lock_reason):
    return (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", lambda *_a, **_kw: None),
        patch.object(ep, "set_source_health", MagicMock()),
        patch.object(ep, "record_dag_run", MagicMock()),
        patch.object(ep, "record_collection", MagicMock()),
        patch.object(ep, "record_collection_duration", MagicMock()),
        patch.object(ep, "record_collector_skip", MagicMock()),
        patch.object(ep, "record_pipeline_error", MagicMock()),
        patch.object(ep, "record_error", MagicMock()),
        patch("baseline_lock.baseline_skip_reason", lambda: lock_reason, create=True),
    )


class TestOwnLockDoesNotSkipTheBaselineCollectors:
    LOCK = "EdgeGuard baseline is running (Airflow DAG run edgeguard_baseline/manual__x) — skipping"

    def test_scheduled_run_still_yields_to_the_lock(self):
        ep = _import_dag_module()
        patches = _patched(ep, self.LOCK)
        for p in patches:
            p.start()
        try:
            result = ep.run_collector_with_metrics("cisa", _Collector, MagicMock(), limit=10)
        finally:
            for p in patches:
                p.stop()
        assert result.get("skipped") is True
        assert result.get("skip_reason_class") == "baseline_in_progress"

    def test_baseline_run_collects_under_its_own_lock(self):
        ep = _import_dag_module()
        patches = _patched(ep, self.LOCK)
        for p in patches:
            p.start()
        try:
            result = ep.run_collector_with_metrics(
                "cisa", _Collector, MagicMock(), limit=0, baseline=True, baseline_days=7
            )
        finally:
            for p in patches:
                p.stop()
        assert result.get("skipped") is not True, result
        assert result.get("skip_reason_class") != "baseline_in_progress", result


class TestChainStopsAfterAFailedClean:
    def _context(self, marker):
        ti = MagicMock()
        ti.xcom_pull.return_value = marker
        return {"ti": ti, "dag_run": MagicMock(conf={})}

    def test_guard_raises_without_the_marker(self):
        ep = _import_dag_module()
        with pytest.raises(ep.AirflowException, match=r"baseline_start did not succeed"):
            ep._require_baseline_start(self._context(None), "cisa")

    def test_guard_passes_with_the_marker_and_without_a_task_instance(self):
        ep = _import_dag_module()
        ep._require_baseline_start(self._context({"started": True}), "cisa")
        ep._require_baseline_start(None, "cisa")
        ep._require_baseline_start({}, "cisa")

    def test_baseline_start_publishes_the_marker(self):
        ep = _import_dag_module()
        with patch.object(ep, "get_baseline_config", lambda context=None: (0, 7)):
            marker = ep._baseline_start_summary(dag_run=MagicMock(conf={"fresh_baseline": True}))
        assert marker == {"started": True, "limit": 0, "baseline_days": 7, "fresh_baseline": True}

    def test_collector_and_full_sync_refuse_without_the_marker(self):
        ep = _import_dag_module()
        ctx = self._context(None)
        with pytest.raises(ep.AirflowException, match=r"\[BASELINE\] cisa: baseline_start did not succeed"):
            ep.run_baseline_collector("cisa", _Collector, context=ctx)
        with pytest.raises(ep.AirflowException, match=r"\[BASELINE\] full_neo4j_sync: baseline_start did not succeed"):
            ep.run_baseline_full_sync(**ctx)
