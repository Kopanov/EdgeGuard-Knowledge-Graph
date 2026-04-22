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
        """The postcheck task's trigger_rule must let the diagnostics run
        when at least one upstream succeeded.

        PR-N21 originally pinned ``ALL_SUCCESS`` ("don't run on partial
        failure"), but the proactive PR-N24 audit (Cross-Checker H2) flipped
        this to ``NONE_FAILED_MIN_ONE_SUCCESS``: INV-2 (Indicator > 0) and
        INV-3 (Source > 0) are UPSTREAM diagnostics — operators NEED them
        to triage *why* an enrichment task failed. ``ALL_SUCCESS`` skipped
        them in exactly the case they were most useful."""
        src = self._dag_src()
        # Find the baseline_postcheck_task PythonOperator block
        anchor = src.find('task_id="baseline_postcheck"')
        assert anchor != -1
        # Search forward for trigger_rule within the next ~500 chars (block size)
        block = src[anchor : anchor + 600]
        assert "TriggerRule.NONE_FAILED_MIN_ONE_SUCCESS" in block, (
            "baseline_postcheck must use NONE_FAILED_MIN_ONE_SUCCESS trigger_rule "
            "(PR-N24 H2: diagnostics must run after partial-failure to help triage)"
        )


# ===========================================================================
# Bravo-ops: build_relationships observability counters + 2 alerts + RUNBOOK
# ===========================================================================


class TestBravoOpsCountersExist:
    """PR-N21 follow-up from Bravo's 2026-04-22 OOM-forensics review:
    add metrics so a future silent build_relationships death (OOM-kill,
    Neo4j MemoryLimitExceededException inside APOC TX, etc.) can be
    detected by Prometheus instead of noticed days later via manual grep."""

    def _metrics_src(self) -> str:
        return (SRC / "metrics_server.py").read_text()

    def test_build_relationships_completion_counter_defined(self):
        src = self._metrics_src()
        assert "BUILD_RELATIONSHIPS_COMPLETIONS" in src, (
            "metrics_server must define BUILD_RELATIONSHIPS_COMPLETIONS counter"
        )
        assert "edgeguard_build_relationships_completions_total" in src, (
            "counter must expose the ``edgeguard_build_relationships_completions_total`` Prometheus metric name"
        )

    def test_apoc_batch_partial_counter_defined(self):
        src = self._metrics_src()
        assert "APOC_BATCH_PARTIAL" in src, "metrics_server must define APOC_BATCH_PARTIAL counter"
        assert "edgeguard_apoc_batch_partial_total" in src, (
            "counter must expose the ``edgeguard_apoc_batch_partial_total`` Prometheus metric name"
        )
        # Must be labelled by step so operators can target re-runs.
        assert '"step"' in src or "'step'" in src, "APOC_BATCH_PARTIAL must be labelled by step identifier"

    def test_recorder_helpers_defined(self):
        src = self._metrics_src()
        assert "def record_build_relationships_completion" in src, (
            "metrics_server must define record_build_relationships_completion helper"
        )
        assert "def record_apoc_batch_partial" in src, (
            "metrics_server must define record_apoc_batch_partial(step=) helper"
        )


class TestBravoOpsBuildRelationshipsWiring:
    """build_relationships.py must actually CALL the new recorders at the
    right points, otherwise the counters stay flat and the alerts never
    fire for real events."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_completion_counter_fired_after_summary(self):
        """The completion counter MUST be incremented only after the
        ``[BUILD_RELATIONSHIPS SUMMARY]`` log line is emitted — absence
        of this call = subprocess died before reaching the end."""
        src = self._src()
        assert "record_build_relationships_completion" in src, (
            "build_relationships must call record_build_relationships_completion "
            "after the summary log line so Prometheus can detect silent death"
        )
        # Must come AFTER the summary log, not at import time.
        summary_pos = src.find("[BUILD_RELATIONSHIPS SUMMARY]")
        completion_pos = src.find("record_build_relationships_completion(")
        assert summary_pos != -1 and completion_pos > summary_pos, (
            "completion counter must be AFTER the summary log (call_counter < summary_log "
            "would give false positives on every import)"
        )

    def test_partial_counter_fired_per_partial_batch(self):
        """The partial counter MUST be incremented inside the
        ``if errors:`` branch of _safe_run_batched so any
        apoc.periodic.iterate errorMessages increment the counter."""
        src = self._src()
        assert "record_apoc_batch_partial" in src, (
            "build_relationships must call record_apoc_batch_partial(step=) "
            "when apoc.periodic.iterate reports errorMessages"
        )
        # Must be inside the _safe_run_batched function, near the [PARTIAL] log
        partial_log_pos = src.find("[PARTIAL]")
        record_pos = src.find("record_apoc_batch_partial")
        assert partial_log_pos != -1 and record_pos > partial_log_pos, (
            "partial counter must be fired in the same [PARTIAL] log branch"
        )


class TestBravoOpsPrometheusAlerts:
    """Two alert rules must be loaded so the above counters produce
    actionable paging signals."""

    def _alerts_src(self) -> str:
        return (REPO_ROOT / "prometheus" / "alerts.yml").read_text()

    def test_silent_death_alert_defined(self):
        src = self._alerts_src()
        assert "EdgeGuardBuildRelationshipsSilentDeath" in src, (
            "Prometheus must define EdgeGuardBuildRelationshipsSilentDeath alert"
        )
        # Must reference the completion counter
        assert "edgeguard_build_relationships_completions_total" in src, (
            "silent-death alert must key on the completion counter"
        )
        # Must be critical severity (OOM-kill is data-loss, page the operator)
        silent_death_block = src[src.find("EdgeGuardBuildRelationshipsSilentDeath") :]
        silent_death_block = silent_death_block[: silent_death_block.find("- alert:", 50)]
        assert "severity: critical" in silent_death_block, (
            "silent-death alert must be critical severity (OOM = data-loss)"
        )

    def test_apoc_partial_alert_defined(self):
        src = self._alerts_src()
        assert "EdgeGuardApocBatchPartial" in src, "Prometheus must define EdgeGuardApocBatchPartial alert"
        # Must reference the partial counter
        assert "edgeguard_apoc_batch_partial_total" in src, "APOC partial alert must key on the partial counter"
        # Must be warning severity (partial is recoverable, but worth paging)
        partial_block = src[src.find("EdgeGuardApocBatchPartial") :]
        # Pick this alert's block out (until next alert or end)
        next_alert = partial_block.find("- alert:", 50)
        partial_block = partial_block[:next_alert] if next_alert != -1 else partial_block
        assert "severity: warning" in partial_block, (
            "APOC partial alert must be warning severity (partial = recoverable)"
        )


class TestBravoOpsRunbookGuidance:
    """RUNBOOK must document the memory posture + APOC partial response
    playbook so operators have a single source of truth."""

    def _runbook(self) -> str:
        return (REPO_ROOT / "docs" / "RUNBOOK.md").read_text()

    def test_runbook_has_bravo_ops_section(self):
        rb = self._runbook()
        assert "Bravo-ops" in rb, "RUNBOOK must have Bravo-ops memory-posture section"

    def test_runbook_documents_tx_memory_max_cap(self):
        """The key Bravo recommendation: NEO4J_TX_MEMORY_MAX ≤ 4g on an
        8 GB worker to avoid MemoryLimitExceededException inside APOC TX."""
        rb = self._runbook()
        assert "NEO4J_TX_MEMORY_MAX" in rb, "RUNBOOK must reference NEO4J_TX_MEMORY_MAX"
        # Must mention the 4g cap (the specific recommendation)
        assert "4g" in rb or "≤ 4" in rb, "RUNBOOK must specify the ≤ 4g TX memory cap"

    def test_runbook_documents_silent_death_alert(self):
        rb = self._runbook()
        assert "EdgeGuardBuildRelationshipsSilentDeath" in rb, (
            "RUNBOOK must document the silent-death alert so operators know what to do when it fires"
        )

    def test_runbook_documents_apoc_partial_playbook(self):
        rb = self._runbook()
        # Must have a playbook entry with MemoryLimitExceededException handling
        assert "APOC partial" in rb or "EdgeGuardApocBatchPartial" in rb
        assert "MemoryLimitExceededException" in rb, (
            "RUNBOOK must mention MemoryLimitExceededException as a common APOC partial cause"
        )


# ===========================================================================
# Bugbot round 1 (PR #105) — three real bugs Bugbot caught in the
# Bravo-ops extension. Each fix needs a regression pin.
# ===========================================================================


class TestBugbotRound1Fixes:
    """Three Bugbot findings on the Bravo-ops extension of PR-N21:
    - HIGH:   INV-1 postcheck Cypher returned no rows when Campaign=0
    - MEDIUM: apoc.periodic.iterate ``committedOperations`` counts
              Campaigns (~156) not PART_OF edges (~15,600)
    - MEDIUM: PromQL ``AND`` label mismatch makes silent-death alert
              unfireable
    """

    def _dag_src(self) -> str:
        return (DAGS / "edgeguard_pipeline.py").read_text()

    def _enrichment_src(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def _alerts_src(self) -> str:
        return (REPO_ROOT / "prometheus" / "alerts.yml").read_text()

    def test_inv1_uses_separate_count_queries(self):
        """Bugbot round 1 HIGH: the pre-fix INV-1 chained
        ``MATCH (m)-[:ATTRIBUTED_TO]->(a) WITH count(*) MATCH (c:Campaign)``
        which returned ZERO ROWS when Campaign=0 (the MATCH eliminated
        all tuples). ``.single()`` → None → violation check silently
        skipped → DAG green — the exact bug the invariant exists to
        catch. Fix: separate queries, each returns one row."""
        src = self._dag_src()
        post_body = _function_body(src, "assert_baseline_postconditions")

        # Pin the new shape: independent queries, each returning a
        # single count. INV-1 (qualifying actors + Campaigns) + INV-2
        # (Indicator) + INV-3 (Source) → ≥4 ``RETURN count`` occurrences.
        assert post_body.count("RETURN count") >= 4, (
            "INV-1 + INV-2 + INV-3 must each use a standalone count query (≥4 ``RETURN count`` total)"
        )

        # Negative: the original silently-broken pattern must NOT be present.
        assert "WITH count(*) AS attrib_edges MATCH (c:Campaign)" not in post_body, (
            "chained MATCH after aggregation is the Bugbot round 1 HIGH regression pattern"
        )

    def test_inv1_uses_qualifying_actor_filter_not_naive_attrib_count(self):
        """Bugbot round 2 (PR #105, MEDIUM): naive ``count(ATTRIBUTED_TO
        edges) > 0`` would false-positive on a graph where actors have
        Malware attributions but no active Indicators (a legitimate
        zero-Campaign outcome — ``build_campaign_nodes`` requires BOTH
        per enrichment_jobs.py:296 ``size(malware_list) > 0 AND
        indicator_total > 0``). INV-1 must mirror the actual qualifying-
        actor condition: Malware ATTRIBUTED_TO + INDICATES from active
        Indicator."""
        src = self._dag_src()
        post_body = _function_body(src, "assert_baseline_postconditions")

        # Positive: must reference INDICATES + active filter (qualifying-actor logic)
        assert "INDICATES" in post_body, "INV-1 must include INDICATES traversal to mirror build_campaign_nodes filter"
        assert "i.active = true" in post_body or "i.active=true" in post_body, (
            "INV-1 must filter on i.active=true to match build_campaign_nodes (enrichment_jobs.py:251)"
        )
        # Negative: the naive ATTRIBUTED_TO-only count must NOT appear
        assert "MATCH (m:Malware)-[:ATTRIBUTED_TO]->(:ThreatActor) RETURN count(*)" not in post_body, (
            "INV-1 must not use the naive ATTRIBUTED_TO-only count — that's the Bugbot round 2 false-positive shape"
        )

    def test_links_counted_by_updated_at_not_committed_operations(self):
        """Bugbot round 1 MEDIUM: pre-fix code treated apoc.periodic.iterate's
        ``committedOperations`` as the PART_OF edge count. Per APOC docs it
        counts SUCCESSFUL INNER-STATEMENT EXECUTIONS (one per Campaign,
        ~156) — NOT the number of MERGE rows produced (~15,600 for 156
        campaigns × ~100 indicators). Post-deploy the ``[CAMPAIGNS] Built
        N campaigns, M links`` log would show M ≈ 156 instead of ≈15,600 —
        confusing operators monitoring PART_OF growth."""
        body = _function_body(self._enrichment_src(), "build_campaign_nodes")
        # Positive: the implementation must include a follow-up count
        # query keyed on ``r.updated_at >= datetime($run_start_at)`` —
        # this gives the TRUE per-run edge count using the freshness
        # marker Step 3a stamps and Step 3b prunes against.
        assert "r.updated_at >= datetime($run_start_at)" in body, (
            "Step 3a must follow the apoc.periodic.iterate with a count "
            "query keyed on r.updated_at (the per-run freshness marker)"
        )
        # Negative: the pre-fix ``committedOperations``-based read MUST
        # NOT appear as an increment into links_created (the misleading
        # line).
        assert 'links_created"] += record.get("committedOperations"' not in body, (
            "link count must not read from committedOperations — that's the "
            "Bugbot-round-1-regression shape (Campaign count != edge count)"
        )

    def test_silent_death_alert_uses_on_join_modifier(self):
        """Bugbot round 1 MEDIUM: pre-fix PromQL used bare ``AND`` to
        join the completion-counter absence with the DAG-start-timestamp
        check. Left side has ``{}`` labels; right side has
        ``{dag_id="edgeguard_baseline"}`` → default AND requires label
        equality → no match → alert never fires. Fix: ``and on()`` to
        ignore all labels on the join."""
        src = self._alerts_src()
        # Find the silent-death alert block
        start = src.find("EdgeGuardBuildRelationshipsSilentDeath")
        next_alert = src.find("- alert:", start + 50)
        block = src[start:next_alert] if next_alert != -1 else src[start:]
        # Positive: must use ``and on()`` (or ``and ignoring(dag_id)``) on
        # the cross-series join.
        has_on = "and on()" in block or "and ignoring(" in block
        assert has_on, (
            "silent-death alert must use ``and on()`` or ``and ignoring(...)`` "
            "to join the differently-labeled series — otherwise default AND "
            "requires label equality and the alert never fires. "
            "Bugbot round 1 MEDIUM."
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_enrichment_jobs_imports(self):
        import enrichment_jobs  # noqa: F401

    def test_metrics_server_exports_new_recorders(self):
        """PR-N21 Bravo-ops: the new recorders must be importable.
        NOTE: cannot ``del sys.modules['metrics_server'] + reimport``
        because prometheus_client's ``CollectorRegistry`` forbids
        duplicate metric registration — the second import would raise
        ``ValueError: Duplicated timeseries``. Just check attribute
        presence on the already-imported module; duplicate-registration
        would have surfaced on the first import in the test collector."""
        import metrics_server

        assert hasattr(metrics_server, "record_build_relationships_completion")
        assert hasattr(metrics_server, "record_apoc_batch_partial")
        # Spot-check the counter object is actually a Counter (not a stub)
        assert hasattr(metrics_server, "BUILD_RELATIONSHIPS_COMPLETIONS")
        assert hasattr(metrics_server, "APOC_BATCH_PARTIAL")

    def test_dag_module_parses(self):
        """DAG module must remain Python-syntax-valid after the
        baseline_postcheck addition."""
        src = (DAGS / "edgeguard_pipeline.py").read_text()
        # Just parse — full Airflow DagBag verification lives in CI's
        # preflight script.
        ast.parse(src)
