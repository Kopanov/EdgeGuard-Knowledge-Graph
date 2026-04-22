"""
PR-N21 — enrichment_jobs robustness for the next 730-day baseline.

Root-caused via 4-agent audit on 2026-04-22 of the Campaign = 0 outcome
in cloud Neo4j after a "successful" baseline. Three problems found:

1. **Silent-failure swallowers** in all 4 enrichment jobs
   (``decay_ioc_confidence``, ``build_campaign_nodes``,
   ``calibrate_cooccurrence_confidence``, ``bridge_vulnerability_cve``).
   The pre-N21 ``except Exception: logger.error(...)`` (no raise) ate
   real Cypher errors (timeouts, schema drift, OOM) and let each job
   return zero results. Airflow saw a clean dict and marked the task
   SUCCESS — no traceback, no alert. The 2026-04-22 cloud baseline
   showed ``Campaign = 0`` despite 156 qualifying ThreatActors with
   incoming Malware ATTRIBUTED_TO edges; expected output was ~156
   Campaigns.

2. **Un-batched cartesian** in ``link_indicators`` (the most likely
   cause of the underlying raise). At 730-day scale,
   ``MATCH (c:Campaign) MATCH (a:ThreatActor)<-[:ATTRIBUTED_TO]-(m:Malware)
   <-[:INDICATES]-(i:Indicator)`` materialized millions of intermediate
   rows in a single Neo4j transaction → timeout / OOM. Now wrapped in
   ``apoc.periodic.iterate`` with batchSize=25 (one Campaign per
   batch).

3. **No baseline post-check** to catch ``Campaign = 0 / ATTRIBUTED_TO > 0``
   asymmetry. Added ``baseline_postcheck`` task to the
   ``edgeguard_baseline`` DAG that fails the run with an actionable
   message if any invariant is violated.

These three changes together mean that the NEXT baseline either:
  (a) succeeds and produces Campaigns proportional to qualifying
      ThreatActors (currently ~156 in cloud), OR
  (b) fails loudly with a real traceback the operator can act on.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DAGS = REPO_ROOT / "dags"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n21")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n21")


# ===========================================================================
# Fix #1-#4 — the four swallowers must re-raise
# ===========================================================================


def _function_body(src: str, fn_name: str) -> str:
    """Return the AST-unparsed body of a top-level function."""
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return ast.unparse(node)
    raise AssertionError(f"function {fn_name} not found in source")


class TestFix1234SwallowersReraise:
    """Each of the 4 enrichment jobs must re-raise on outer except instead of
    silently returning zero results. Pin via AST-walk of each function."""

    def _src(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def _outer_except_reraises(self, fn_name: str) -> bool:
        """True iff the function has at least one ``except Exception`` handler
        whose body contains a bare ``raise``."""
        tree = ast.parse(self._src())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                for inner in ast.walk(node):
                    if isinstance(inner, ast.ExceptHandler):
                        # Must catch Exception (not a narrower class)
                        is_broad = (
                            isinstance(inner.type, ast.Name) and inner.type.id == "Exception"
                        ) or inner.type is None
                        if not is_broad:
                            continue
                        # Look for a bare ``raise`` in the handler body
                        for stmt in ast.walk(ast.Module(body=inner.body, type_ignores=[])):
                            if isinstance(stmt, ast.Raise) and stmt.exc is None:
                                return True
                return False
        raise AssertionError(f"function {fn_name} not found")

    def test_decay_ioc_confidence_reraises(self):
        assert self._outer_except_reraises("decay_ioc_confidence"), (
            "decay_ioc_confidence must ``raise`` after logging in its outer "
            "except Exception handler. Pre-PR-N21 it silently returned zero "
            "results, hiding real Cypher errors from Airflow."
        )

    def test_build_campaign_nodes_reraises(self):
        """The 2026-04-22 Campaign = 0 culprit. The exception-swallower at
        line ~548 was the smoking gun."""
        assert self._outer_except_reraises("build_campaign_nodes"), (
            "build_campaign_nodes must ``raise`` after logging in its outer "
            "except Exception handler. The pre-N21 swallower returned "
            "{campaigns_created: 0, links_created: 0} on any error, "
            "producing the silent Campaign = 0 outcome in the cloud baseline."
        )

    def test_calibrate_cooccurrence_confidence_reraises(self):
        assert self._outer_except_reraises("calibrate_cooccurrence_confidence"), (
            "calibrate_cooccurrence_confidence must ``raise`` after logging "
            "in its outer except. Per-tier inner exceptions still log+continue "
            "(by design) — only the WHOLE-SESSION outer except re-raises."
        )

    def test_bridge_vulnerability_cve_reraises(self):
        assert self._outer_except_reraises("bridge_vulnerability_cve"), (
            "bridge_vulnerability_cve must ``raise`` after logging. "
            "Pre-N21 it downgraded to WARNING and bumped results['errors'], "
            "but no caller ever read results['errors'] — effectively "
            "invisible to Airflow."
        )


# ===========================================================================
# Fix #5 — link_indicators wrapped in apoc.periodic.iterate
# ===========================================================================


class TestFix5LinkIndicatorsBatched:
    """The cartesian explosion in build_campaign_nodes link_indicators
    must be wrapped in apoc.periodic.iterate at baseline scale."""

    def _campaigns_body(self) -> str:
        return _function_body((SRC / "enrichment_jobs.py").read_text(), "build_campaign_nodes")

    def test_link_indicators_uses_apoc_periodic_iterate(self):
        body = self._campaigns_body()
        # The Cypher fragment must reference apoc.periodic.iterate. Pre-N21
        # was a single ``MATCH (c:Campaign) MATCH (a)<-...-(i)`` materialized
        # in one TX.
        assert "apoc.periodic.iterate" in body, (
            "link_indicators must be wrapped in apoc.periodic.iterate so the "
            "Campaign × Malware × Indicator cartesian doesn't materialize in "
            "one TX. Pre-N21 produced 0.5–3M intermediate rows at baseline "
            "scale → likely cause of the 2026-04-22 timeout that the "
            "swallower hid."
        )

    def test_link_indicators_outer_iterates_campaigns(self):
        """The outer query of apoc.periodic.iterate must be ``MATCH (c:Campaign)``
        — one batch per Campaign, not one batch per Indicator."""
        body = self._campaigns_body()
        assert '"MATCH (c:Campaign) RETURN c"' in body or "MATCH (c:Campaign) RETURN c" in body, (
            "apoc.periodic.iterate outer must iterate Campaigns (the small "
            "side, ~156 rows in cloud) not Indicators (146K)."
        )

    def test_link_indicators_batch_size_bounded(self):
        body = self._campaigns_body()
        # batchSize must be present and reasonable (not 0, not 100000+).
        # Anything in [1, 500] is fine; we pin only that batchSize is set.
        assert "batchSize" in body, "apoc.periodic.iterate must specify batchSize to bound TX size"

    def test_link_indicators_propagates_apoc_errors(self):
        """If any per-batch fails, the result's errorMessages map must cause
        a hard raise — otherwise apoc.periodic.iterate just returns
        a dict with errors and we'd be back to silent partial-loss."""
        body = self._campaigns_body()
        assert "errorMessages" in body, "post-call must inspect errorMessages"
        assert "raise" in body, "any non-empty errorMessages must raise"


# ===========================================================================
# Fix #6 — baseline_postcheck task added to edgeguard_baseline DAG
# ===========================================================================


class TestFix6BaselinePostcheck:
    """The baseline_postcheck task must exist, be wired between enrichment
    and baseline_complete, and check the Campaign = 0 invariant."""

    def _dag_src(self) -> str:
        return (DAGS / "edgeguard_pipeline.py").read_text()

    def test_postcheck_callable_exists(self):
        src = self._dag_src()
        assert "def assert_baseline_postconditions" in src, (
            "DAG module must define assert_baseline_postconditions callable"
        )

    def test_postcheck_task_wired_into_dag(self):
        src = self._dag_src()
        # PythonOperator with task_id="baseline_postcheck"
        assert 'task_id="baseline_postcheck"' in src, (
            "baseline_postcheck PythonOperator must be defined in baseline_dag"
        )
        # Must be in the chain BEFORE baseline_complete
        assert ">> baseline_postcheck_task" in src, "baseline_postcheck_task must appear in the >> chain"
        assert ">> baseline_complete" in src, "baseline_complete still in chain"
        # Order check: postcheck must precede complete in the chain
        chain_start = src.find(">> baseline_postcheck_task")
        complete_pos = src.find(">> baseline_complete", chain_start)
        assert chain_start != -1 and complete_pos > chain_start, (
            "baseline_postcheck_task must come BEFORE baseline_complete in the chain"
        )

    def test_postcheck_runs_after_enrichment(self):
        src = self._dag_src()
        # baseline_enrichment_task must immediately precede baseline_postcheck_task
        # in the chain (so the postcheck runs only if enrichment succeeded).
        idx_enrich = src.find(">> baseline_enrichment_task")
        idx_post = src.find(">> baseline_postcheck_task", idx_enrich)
        assert idx_enrich != -1 and idx_post > idx_enrich, (
            "baseline_postcheck_task must come AFTER baseline_enrichment_task"
        )

    def test_postcheck_checks_campaign_invariant(self):
        """INV-1 must be implemented: ATTRIBUTED_TO > 0 AND Campaign = 0
        is a hard failure."""
        src = self._dag_src()
        # The Cypher in the postcheck callable must reference both Campaign
        # and ATTRIBUTED_TO — otherwise it's not actually checking the
        # invariant the 2026-04-22 incident exposed.
        post_body = _function_body(src, "assert_baseline_postconditions")
        assert "ATTRIBUTED_TO" in post_body, "INV-1 must check ATTRIBUTED_TO edges"
        assert ":Campaign" in post_body, "INV-1 must check Campaign nodes"
        # Must raise AirflowException on violation (not just log)
        assert "AirflowException" in post_body, "violations must raise AirflowException so DAG marks FAILED"

    def test_postcheck_strict_trigger_rule(self):
        """The postcheck task must have ALL_SUCCESS trigger_rule — running
        it when enrichment failed would just produce a misleading second
        error."""
        src = self._dag_src()
        # Find the baseline_postcheck_task PythonOperator block
        anchor = src.find('task_id="baseline_postcheck"')
        assert anchor != -1
        # Search forward for trigger_rule within the next ~500 chars (block size)
        block = src[anchor : anchor + 600]
        assert "TriggerRule.ALL_SUCCESS" in block, "baseline_postcheck must use ALL_SUCCESS trigger_rule"


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_enrichment_jobs_imports(self):
        import enrichment_jobs  # noqa: F401

    def test_dag_module_parses(self):
        """DAG module must remain Python-syntax-valid after the
        baseline_postcheck addition."""
        src = (DAGS / "edgeguard_pipeline.py").read_text()
        # Just parse — full Airflow DagBag verification lives in CI's
        # preflight script.
        ast.parse(src)
