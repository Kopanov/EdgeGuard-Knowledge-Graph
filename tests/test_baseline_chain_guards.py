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
        with patch("run_misp_to_neo4j.MISPToNeo4jSync", return_value=sync) as sync_class:
            assert ep.run_baseline_full_sync(ti=self._ti({"baseline_start": {"started": True}})) == {"synced": True}
        # 2026-10-16: no time of the run reaches the sync or the aging job; both age at the database's
        # current time (``indicator_aging``).
        sync_class.assert_called_once_with()
        client = MagicMock()
        with (
            patch("neo4j_client.Neo4jClient", return_value=client),
            patch("enrichment_jobs.run_all_enrichment_jobs", return_value={}) as run_all,
        ):
            assert ep.run_baseline_enrichment() == {"enriched": True}
        run_all.assert_called_once_with(client)


class TestLiveTaskStatesDecide:
    """Airflow 3 reports the chain's task states; they decide before the XCom markers (2026-10).

    Clearing a task leaves its XComs until it runs again (the Task SDK deletes them at the start of
    the task's next run), so a marker can outlive the success it records.
    """

    RUN = "manual__2026-10-15T08:00:00+00:00"

    def _ti(self, states, xcom=None):
        ti = MagicMock()
        ti.dag_id = "edgeguard_baseline"
        ti.run_id = self.RUN
        ti.get_task_states.return_value = {self.RUN: states}
        ti.xcom_pull.return_value = xcom
        del ti.get_dagrun  # like RuntimeTaskInstance
        return ti

    def test_a_stale_marker_does_not_pass_after_a_failed_clean(self):
        # baseline_clean was cleared and failed again: baseline_start is upstream_failed but keeps
        # the XCom of its earlier success.
        ep = _import_dag_module()
        ti = self._ti({"baseline_start": "upstream_failed"}, xcom={"started": True})
        with pytest.raises(ep.AirflowException, match=r"cisa: baseline_start is upstream_failed in this run"):
            ep._require_baseline_start({"ti": ti}, "cisa")
        with pytest.raises(ep.AirflowException, match=r"full_neo4j_sync: baseline_start is upstream_failed"):
            ep.run_baseline_full_sync(ti=ti)

    def test_a_start_marked_success_passes_without_a_marker(self):
        ep = _import_dag_module()
        ti = self._ti({"baseline_start": "success"}, xcom=None)
        ep._require_baseline_start({"ti": ti}, "cisa")
        ti.get_task_states.assert_called_once_with(
            dag_id="edgeguard_baseline", task_ids=["baseline_start"], run_ids=[self.RUN]
        )

    def test_a_cleared_start_has_no_state_and_refuses(self):
        ep = _import_dag_module()
        with pytest.raises(ep.AirflowException, match=r"baseline_start is not run in this run"):
            ep._require_baseline_start({"ti": self._ti({"baseline_start": None}, xcom={"started": True})}, "nvd")

    def test_an_unavailable_api_falls_back_to_the_marker(self):
        ep = _import_dag_module()
        ti = self._ti({}, xcom={"started": True})
        ti.get_task_states.side_effect = RuntimeError("supervisor gone")
        ep._require_baseline_start({"ti": ti}, "cisa")
        ti.xcom_pull.return_value = None
        with pytest.raises(ep.AirflowException, match=r"no XCom marker"):
            ep._require_baseline_start({"ti": ti}, "cisa")

    def test_postcheck_fails_on_a_chain_task_that_did_not_succeed_despite_its_marker(self):
        ep = _import_dag_module()
        states = {"full_neo4j_sync": "success", "build_relationships": "success", "run_enrichment_jobs": "failed"}
        ti = self._ti(states, xcom={"stale": True})
        with pytest.raises(ep.AirflowException, match=r"did not succeed: \{'run_enrichment_jobs': 'failed'\}"):
            ep.assert_baseline_postconditions(task_instance=ti)

    def test_postcheck_reads_the_chain_states_of_this_run(self):
        ep = _import_dag_module()
        states = {task: "success" for task in ep._BASELINE_CRITICAL_CHAIN}
        ti = self._ti(states, xcom=None)
        with patch("neo4j_client.Neo4jClient", side_effect=RuntimeError("past the chain check")):
            with pytest.raises(RuntimeError, match="past the chain check"):
                ep.assert_baseline_postconditions(task_instance=ti)
        ti.xcom_pull.assert_not_called()


class TestPostcheckCampaignInvariant:
    """INV-1 (2026-10-16): the qualifying actors are those ``build_campaign_nodes`` builds a campaign
    for, by the builder's own definition (``campaign_evidence``): an ATTRIBUTED_TO or a USES_MALWARE
    link to a malware an active indicator INDICATES. The inline query read ATTRIBUTED_TO only, so a
    graph whose campaigns rest on USES_MALWARE alone passed the invariant with no campaign."""

    RUN = "manual__2026-10-16T08:00:00+00:00"

    def _ti(self, ep):
        ti = MagicMock()
        ti.dag_id = "edgeguard_baseline"
        ti.run_id = self.RUN
        ti.get_task_states.return_value = {self.RUN: {task: "success" for task in ep._BASELINE_CRITICAL_CHAIN}}
        del ti.get_dagrun  # like RuntimeTaskInstance
        return ti

    def _run(self, ep, qualifying, campaigns):
        import campaign_evidence

        queries = []

        def run(query, **_kw):
            queries.append(query)
            result = MagicMock()
            if query == campaign_evidence.QUALIFYING_ACTORS_QUERY:
                result.single.return_value = {"qualifying_actors": qualifying}
            elif "(c:Campaign)" in query:
                result.single.return_value = {"campaigns": campaigns}
            else:
                result.single.return_value = {"n": 10}
            return result

        session = MagicMock()
        session.__enter__.return_value = session
        session.__exit__.return_value = None
        session.run.side_effect = run
        client = MagicMock()
        client.driver.session.return_value = session
        with patch("neo4j_client.Neo4jClient", return_value=client):
            try:
                ep.assert_baseline_postconditions(task_instance=self._ti(ep))
                return queries, None
            except ep.AirflowException as exc:
                return queries, exc

    def test_qualifying_actors_without_campaigns_fail_the_run(self):
        import campaign_evidence

        ep = _import_dag_module()
        queries, exc = self._run(ep, qualifying=3, campaigns=0)
        assert queries[0] == campaign_evidence.QUALIFYING_ACTORS_QUERY
        assert "(a)-[:USES_MALWARE]->(:Malware)<-[:INDICATES]-(i:Indicator)" in queries[0]
        # INV-1 is the one violation (Indicator and Source counts are non-zero).
        assert exc is not None and "(1 violations)" in str(exc)

    def test_campaigns_for_the_qualifying_actors_pass(self):
        ep = _import_dag_module()
        _queries, exc = self._run(ep, qualifying=3, campaigns=3)
        assert exc is None


def test_the_clean_step_outlasts_two_large_event_deletes():
    # Each MISP delete may wait EDGEGUARD_MISP_DELETE_TIMEOUT_SEC (900 s); the OTX and NVD events of a
    # 730-day baseline are the large ones.
    from datetime import timedelta

    ep = _import_dag_module()
    assert ep.baseline_clean_task.execution_timeout >= timedelta(minutes=60)


def test_a_refusal_fails_the_task_without_its_retry():
    """A retry would refuse again: the guards raise AirflowFailException (no retry)."""
    ep = _import_dag_module()
    stale = MagicMock()
    stale.dag_id, stale.run_id = "edgeguard_baseline", "manual__1"
    stale.get_task_states.return_value = {"manual__1": {"baseline_start": "upstream_failed"}}
    with pytest.raises(ep.AirflowFailException):
        ep._require_baseline_start({"ti": stale}, "cisa")
    no_states = MagicMock(spec=["xcom_pull"])
    no_states.xcom_pull.return_value = None
    with pytest.raises(ep.AirflowFailException):
        ep._require_baseline_start({"ti": no_states}, "cisa")
