"""Guards found missing by the 2026-10-12 fresh-baseline smoke run.

The own-lock skip found by the same run is fixed upstream (#169, ``baseline_holder``) and
tested there. Kept here:

1. A failed ``baseline_clean`` must stop the chain. The tier groups and ``full_neo4j_sync``
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


class TestPostcheckFailsWithoutTheChainMarkers:
    """Airflow 3: ``ti.get_dagrun()`` does not exist, so the postcheck reads the XCom markers."""

    def _ti(self, markers):
        ti = MagicMock(spec=["xcom_pull"])  # no get_dagrun, like RuntimeTaskInstance
        ti.xcom_pull.side_effect = lambda task_ids=None, **_kw: markers.get(task_ids)
        return ti

    def test_missing_enrichment_marker_fails_the_task(self):
        ep = _import_dag_module()
        ti = self._ti({"full_neo4j_sync": {"synced": True}, "build_relationships": {"built": True}})
        with pytest.raises(ep.AirflowException, match=r"\['run_enrichment_jobs'\] did not succeed"):
            ep.assert_baseline_postconditions(task_instance=ti)

    def test_chain_tasks_return_their_markers(self):
        ep = _import_dag_module()
        with patch("subprocess_streaming.run_with_streaming_output", return_value=(0, [])):
            assert ep.run_build_relationships() == {"built": True, "returncode": 0}
        sync = MagicMock()
        sync.run.return_value = True
        with patch("run_misp_to_neo4j.MISPToNeo4jSync", return_value=sync):
            assert ep.run_baseline_full_sync(ti=self._ti({"baseline_start": {"started": True}})) == {"synced": True}
        with (
            patch("neo4j_client.Neo4jClient", return_value=MagicMock()),
            patch("enrichment_jobs.run_all_enrichment_jobs", return_value={}),
        ):
            assert ep.run_baseline_enrichment() == {"enriched": True}
