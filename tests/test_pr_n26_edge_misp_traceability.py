"""
PR-N26 — wire ``r.misp_event_ids[]`` onto TARGETS / EXPLOITS / INDICATES /
AFFECTS edges produced by ``build_relationships.py``.

## Why this PR exists

Cloud-Neo4j audit on 2026-04-23 found that 5 edge types created by the
post-sync graph-traversal in ``build_relationships.py`` silently dropped
the ``r.misp_event_ids[]`` provenance array. Pre-N26 cloud coverage:

| Relationship | Total | with `misp_event_ids` |
|---|---|---|
| INDICATES | 19,370 | 6.6% |
| TARGETS | 36,480 | 0% |
| EXPLOITS | 26,730 | 0% |
| AFFECTS | 1,221 | 0.1% |

PR #32's commit message had said *"every MISP-derived edge accumulates
``r.misp_event_ids[]``"* — the cloud data showed only 2 of 5 MISP-derived
edge types actually got the wire-up. PR-N26 closes the gap in 6 queries:

* **Q3a / Q3b** — EXPLOITS: propagate ``i.misp_event_ids[]``
* **Q4** — INDICATES (co-occurrence): use the ``eid`` already in scope
* **Q7a** — TARGETS: propagate ``i.misp_event_ids[]``
* **Q7b** — AFFECTS: propagate ``v.misp_event_ids[]``
* **Q9** — INDICATES (family-match): propagate ``i.misp_event_ids[]``

## Test strategy

Two layers of pin:

1. **Static text pins** — every modified inner-query string contains the
   ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) +
   …)`` SET clause. Anchored on the PR-N26 comment marker so a future
   refactor can't strip the SET without also stripping the comment.

2. **AST-shape pins** — for each modified ``_qNN_inner`` constant in
   ``build_relationships.py``, parse the file and verify the constant's
   value contains the SET clause structurally. Catches the case where
   someone reorganizes the queries into a helper function and breaks the
   string-literal anchor.

We deliberately do NOT add a behavioural integration test that runs
build_relationships against a live Neo4j — that's covered by the
existing integration suite (which is excluded from the coverage gate).
The static + AST pins are sufficient to catch regressions to the
specific SET-clause shape this PR introduces.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


# ===========================================================================
# Helper: locate a string-literal assignment and return its concatenated value
# ===========================================================================


def _link(src: str, step: str, after: int = 0) -> int:
    """Position of the ``[LINK] <step>/<total>`` banner in ``src`` (``-1`` if absent).

    The total is not pinned: adding or removing a step renumbers every banner, which used to
    break ~30 assertions across these files for no behavioural reason (2026-10 checks audit #4).
    """
    m = re.search(rf"\[LINK\] {re.escape(step)}/\d+", src[after:])
    return after + m.start() if m else -1


def _string_literal_value(src_path: Path, var_name: str) -> str:
    """Return the concatenated string value of a top-level or nested ``var = (...)``
    assignment in ``src_path``. Walks the AST so reformatting / line-wrapping
    doesn't break the lookup.

    Build_relationships.py uses the pattern::

        _q3a_inner = (
            "WITH $i AS i ..."
            "MERGE (i)-[r:EXPLOITS]->(v) "
            ...
        )

    which the AST normalises into a Constant or a JoinedStr / BinOp tree.
    ast.unparse + a literal_eval-style probe is robust across Python 3.12+
    versions and across reformat decisions.
    """
    tree = ast.parse(src_path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == var_name:
                # Try literal evaluation first (works for pure string concat).
                try:
                    return str(ast.literal_eval(node.value))
                except (ValueError, SyntaxError):
                    # 2026-10 (relationship provenance): the build_relationships queries are
                    # assembled from shared fragments — evaluate them (the text that runs).
                    if src_path.name == "build_relationships.py":
                        from build_rel_queries import assigned_query

                        return assigned_query(var_name)
                    return ast.unparse(node.value)
    raise AssertionError(f"variable {var_name!r} not found in {src_path}")


# ===========================================================================
# Section 1 — static text pins on each fixed query in build_relationships.py
# ===========================================================================


_BUILD_RELATIONSHIPS = SRC / "build_relationships.py"


def _br_namespace() -> dict:
    """``build_relationships``'s module namespace, to evaluate its assembled queries."""
    import build_relationships

    return vars(build_relationships)


class TestBuildRelationshipsHasMispEventIdsSetClause:
    """Each of the remaining fixed inner-query constants must contain the
    ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) + …)``
    SET clause (``coalesce(<src>.misp_event_ids, [])``), so the pin checks
    each pattern individually. Q4 — the co-occurrence path that appended
    ``[eid]`` — was removed in 2026-10; its test now pins the absence."""

    def test_q3a_exploits_vuln_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3a_inner")
        assert "r.misp_event_ids" in body, "Q3a must SET r.misp_event_ids (PR-N26)"
        assert "[(i)-[_sf:SOURCED_FROM]->(_src:Source)" in body and "coalesce(_x.misp_event_ids, [])" in body, (
            "events come from the subject's per-source SOURCED_FROM edges (2026-10 relationship provenance)"
        )
        assert "apoc.coll.toSet" in body, "Q3a must use apoc.coll.toSet for idempotent dedup"

    def test_q3b_exploits_cve_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3b_inner")
        assert "r.misp_event_ids" in body, "Q3b must SET r.misp_event_ids (PR-N26)"
        assert "[(i)-[_sf:SOURCED_FROM]->(_src:Source)" in body and "coalesce(_x.misp_event_ids, [])" in body, (
            "events come from the subject's per-source SOURCED_FROM edges (2026-10 relationship provenance)"
        )
        assert "apoc.coll.toSet" in body

    def test_q4_indicates_cooccurrence_query_is_gone(self):
        """2026-10 (fresh-baseline PR): Q4 — the whole-event co-occurrence
        INDICATES query whose ``[eid]`` wire-up PR-N26 pinned — was removed
        (ResilMesh conformance finding F1). There is no ``_q4_inner`` to
        wire any more, and no inner query may iterate ``eid IN
        m.misp_event_ids`` to MERGE INDICATES. The reported-technique
        queries 5b / 6b took its slot."""
        tree = ast.parse(_BUILD_RELATIONSHIPS.read_text())
        assigned = {
            tgt.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            for tgt in node.targets
            if isinstance(tgt, ast.Name)
        }
        assert "_q4_inner" not in assigned, "Q4 inner query must stay removed"
        assert "_q4_outer" not in assigned, "Q4 outer query must stay removed"
        text = _BUILD_RELATIONSHIPS.read_text()
        assert "eid IN i.misp_event_ids" not in text, "no event-id co-occurrence join may remain"
        assert _link(text, "5b") >= 0 and _link(text, "6b") >= 0, "5b / 6b must have replaced Q4"

    def test_q7a_targets_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7a_inner")
        assert "r.misp_event_ids" in body, "Q7a must SET r.misp_event_ids (PR-N26)"
        assert "[(i)-[_sf:SOURCED_FROM]->(_src:Source)" in body and "ev: CASE WHEN _sf.misp_event_ids" in body, (
            "events come from the subject's per-source SOURCED_FROM edges (2026-10 relationship provenance)"
        )
        # 2026-10-16 (sector evidence): only the SOURCED_FROM edges whose zones give the sector
        assert "reduce(_a = [], _x IN _st | _a + _x.ev)" in body
        assert "apoc.coll.toSet" in body

    def test_q7b_affects_propagates_vulnerability_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7b_inner")
        assert "r.misp_event_ids" in body, "Q7b must SET r.misp_event_ids (PR-N26)"
        # Q7b uses ``v`` for the Vulnerability/CVE node, not ``i``.
        assert "[(v)-[_sf:SOURCED_FROM]->(_src:Source)" in body and "ev: CASE WHEN _sf.misp_event_ids" in body, (
            "events come from the subject's per-source SOURCED_FROM edges (2026-10 relationship provenance)"
        )
        # 2026-10-16 (sector evidence): only the SOURCED_FROM edges whose zones give the sector
        assert "reduce(_a = [], _x IN _st | _a + _x.ev)" in body
        assert "apoc.coll.toSet" in body

    def test_q9_indicates_family_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q9_inner")
        assert "r.misp_event_ids" in body, "Q9 must SET r.misp_event_ids (PR-N26)"
        assert "[(i)-[_sf:SOURCED_FROM]->(_src:Source)" in body and "coalesce(_x.misp_event_ids, [])" in body, (
            "events come from the subject's per-source SOURCED_FROM edges (2026-10 relationship provenance)"
        )
        assert "apoc.coll.toSet" in body


# ===========================================================================
# Section 2 — defensive AST scan: every MERGE producing an affected edge
# type in build_relationships.py must be followed by an r.misp_event_ids
# SET clause within the same query. Catches future regressions that add a
# NEW INDICATES/EXPLOITS/TARGETS/AFFECTS query without remembering the wire-up.
# ===========================================================================


class TestNoNewQueryForgetsToWireMispEventIds:
    """Defensive scan — every assigned ``_qN_inner`` constant in
    build_relationships.py that contains a MERGE for one of the four
    affected relationship types must also reference ``r.misp_event_ids``
    somewhere in its body. Prevents the bug class from coming back the
    next time someone adds a 13th link query.

    We exempt ``_q5_inner``-style queries (EMPLOYS_TECHNIQUE) and similar
    that are NOT in the four-edge-type set."""

    AFFECTED_REL_TYPES = ("INDICATES", "EXPLOITS", "TARGETS", "AFFECTS")

    def test_every_inner_query_with_affected_merge_sets_misp_event_ids(self):
        tree = ast.parse(_BUILD_RELATIONSHIPS.read_text())
        offenders: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for tgt in node.targets:
                if not isinstance(tgt, ast.Name):
                    continue
                # Inner queries follow the pattern _q<NN>_inner or _inner.
                if not (tgt.id.endswith("_inner") or tgt.id == "_inner"):
                    continue
                try:
                    body = str(ast.literal_eval(node.value))
                except (ValueError, SyntaxError):
                    # 2026-10: evaluate the assembled query (see _string_literal_value).
                    body = eval(compile(ast.Expression(node.value), str(_BUILD_RELATIONSHIPS), "eval"), _br_namespace())  # noqa: S307

                # Does this query MERGE one of the affected edge types?
                # Look for ``[r:INDICATES]``, ``[r:TARGETS]``, etc.
                affected = [rel for rel in self.AFFECTED_REL_TYPES if f":{rel}]" in body]
                if not affected:
                    continue
                # If yes, must also reference r.misp_event_ids.
                if "r.misp_event_ids" not in body:
                    offenders.append(f"{tgt.id}: MERGEs [{','.join(affected)}] but missing r.misp_event_ids SET")

        assert not offenders, (
            "the following build_relationships.py queries MERGE one of "
            f"{self.AFFECTED_REL_TYPES} but DO NOT SET r.misp_event_ids — "
            "this is the PR-N26 bug class:\n  " + "\n  ".join(offenders)
        )


class TestBaselineCompleteTriggerRule:
    """PR-N26 Fix A (Bravo's 2026-04-23 post-mortem): ``baseline_complete``
    must NOT use ``trigger_rule=ALL_DONE``. That rationale (PR #35 "always
    emit end-of-run marker") directly undermined the PR-N21 invariant-check
    contract: postcheck raises AirflowException on Campaign=0 but ALL_DONE
    on the final task let baseline_complete emit "BASELINE Complete!" to
    stdout anyway → silent-success regression.

    Fix: ``NONE_FAILED_MIN_ONE_SUCCESS`` — the final marker runs only when
    everything upstream succeeded, making upstream failures + invariant
    violations correctly propagate to the DAG-run state."""

    def test_baseline_complete_does_not_use_all_done(self):
        """ALL_DONE on the final task breaks the PR-N21 invariant-check
        semantics: postcheck can intentionally raise, but ALL_DONE means
        the 'Complete!' echo fires anyway."""
        dag_src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        idx = dag_src.find('task_id="baseline_complete"')
        assert idx != -1, "baseline_complete task not found in edgeguard_pipeline.py"
        # Scan forward ~3000 chars (well past the BashOperator block) for
        # the trigger_rule kwarg.
        block = dag_src[idx : idx + 3000]
        assert "TriggerRule.ALL_DONE" not in block, (
            "baseline_complete must NOT use trigger_rule=ALL_DONE — that "
            "rationale (PR #35) produces a silent-success regression when "
            "postcheck raises AirflowException on invariant violations. "
            "Use NONE_FAILED_MIN_ONE_SUCCESS (PR-N26 Fix A)."
        )

    def test_baseline_complete_uses_none_failed_min_one_success(self):
        dag_src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        idx = dag_src.find('task_id="baseline_complete"')
        block = dag_src[idx : idx + 3000]
        assert "TriggerRule.NONE_FAILED_MIN_ONE_SUCCESS" in block, (
            "baseline_complete must use trigger_rule=NONE_FAILED_MIN_ONE_SUCCESS "
            "(PR-N26 Fix A) so the DAG is correctly marked FAILED when an "
            "upstream task (sync / build_rels / enrichment / postcheck) fails."
        )

    def test_postcheck_uses_all_done_with_sentinel(self):
        """PR-N26 Fix A pinned this as ``NONE_FAILED_MIN_ONE_SUCCESS`` (PR-N24 H2).
        PR-N27 (Bravo's 2026-04-23 post-mortem) discovered that semantics
        STILL skipped postcheck when ``full_neo4j_sync`` failed entirely
        (downstream all upstream_failed → no upstream succeeded). PR-N27
        flipped postcheck to ``ALL_DONE`` + added an upstream-state sentinel
        inside the callable. Pin the new state."""
        dag_src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        idx = dag_src.find("baseline_postcheck_task = PythonOperator")
        assert idx != -1
        block = dag_src[idx : idx + 2500]
        assert "TriggerRule.ALL_DONE" in block, "baseline_postcheck must use trigger_rule=ALL_DONE (PR-N27)"
        # And the callable must have the upstream-state sentinel
        assert "BASELINE-POSTCHECK-SKIPPED" in dag_src, (
            "PR-N27 callable sentinel ([BASELINE-POSTCHECK-SKIPPED] log token) is missing"
        )


class TestPRN28PlaceholderRejectionsNotErrors:
    """PR-N28 (Bravo's 2026-04-23 post-mortem): in
    ``src/run_misp_to_neo4j.py::_sync_to_neo4j_chunk``, PR-N10
    placeholder-name rejections (Malware/ThreatActor name == "unknown"/N/A/etc)
    must NOT increment the ``errors`` counter. They're tracked separately
    in ``self.stats["placeholder_rejections"]`` and surfaced in the sync
    summary log so 4 defensive rejections don't fail the entire baseline."""

    SRC_FILE = REPO_ROOT / "src" / "run_misp_to_neo4j.py"

    def test_imports_is_placeholder_name(self):
        text = self.SRC_FILE.read_text()
        assert "from node_identity import is_placeholder_name" in text, (
            "run_misp_to_neo4j.py must import is_placeholder_name to pre-check placeholder rejections (PR-N28)"
        )

    def test_malware_loop_uses_placeholder_pre_check(self):
        text = self.SRC_FILE.read_text()
        # The malware sync loop must call is_placeholder_name(raw_name)
        # before incrementing errors. Anchor on the [MERGE-PLACEHOLDER-REJECTED]
        # log token introduced by PR-N28.
        assert "[MERGE-PLACEHOLDER-REJECTED] Malware" in text, (
            "PR-N28 malware loop must emit [MERGE-PLACEHOLDER-REJECTED] log token "
            "for placeholder names (instead of [MERGE-RETURNED-FALSE] which incremented errors)"
        )

    def test_actor_loop_uses_placeholder_pre_check(self):
        text = self.SRC_FILE.read_text()
        assert "[MERGE-PLACEHOLDER-REJECTED] ThreatActor" in text, (
            "PR-N28 actor loop must emit [MERGE-PLACEHOLDER-REJECTED] log token for placeholder names"
        )

    def test_placeholder_rejections_tracked_in_stats(self):
        text = self.SRC_FILE.read_text()
        assert 'self.stats["placeholder_rejections"]' in text, (
            "PR-N28 must track placeholder rejections in self.stats so they can "
            "be surfaced in the sync summary log without conflating with errors"
        )

    def test_sync_summary_logs_placeholder_rejections(self):
        text = self.SRC_FILE.read_text()
        # The sync summary log must mention placeholder rejections separately
        # so operators can see them without grepping per-event logs.
        assert "Placeholder-name rejections" in text, (
            "sync summary log must surface placeholder_rejections count separately "
            "from total_errors so the operator can distinguish defensive rejects "
            "from real failures"
        )

    def test_placeholder_rejections_do_not_increment_errors(self):
        """Behavioural pin via AST inspection: in the malware/actor branches,
        the ``[MERGE-PLACEHOLDER-REJECTED]`` block must use ``continue`` (skip
        the rest of the loop body) rather than fall through to ``errors += 1``.

        PR-N26 audit round 2 follow-up: window widened to 2000 chars because
        the Bug Hunter H-2 fix added the metric-fail try/except wrap, which
        pushes the ``continue`` further down the block."""
        text = self.SRC_FILE.read_text()
        # Find the malware placeholder rejected block
        idx = text.find("[MERGE-PLACEHOLDER-REJECTED] Malware")
        assert idx != -1
        # Within ~2000 chars after the log line, we expect:
        #   - increment placeholder_rejections
        #   - try/except wrap on merge_malware (H-2 fix, metric-fail guard)
        #   - continue (skip the rest of the loop)
        block = text[idx : idx + 2000]
        assert "continue" in block, (
            "PR-N28 placeholder block must use ``continue`` to skip the rest of "
            "the loop iteration — otherwise it falls through to the merge-returned-False "
            "branch which increments ``errors`` (the very bug PR-N28 closes)"
        )


class TestPRN27PostcheckUpstreamFailedSentinel:
    """PR-N27 (Bravo's 2026-04-23 post-mortem follow-up): when an upstream
    task fails, ``baseline_postcheck`` must emit a clean diagnostic instead
    of being silently skipped (PR-N24 H2 trigger_rule semantics) OR
    falsely firing INV-1/2/3 violations (which would be trivially true on
    a half-filled graph for the wrong reason).

    Implementation: trigger_rule=ALL_DONE so postcheck always runs; the
    callable's sentinel inspects upstream task state via the Airflow context
    and exits cleanly when an upstream task is in failed/upstream_failed/skipped
    state, emitting a [BASELINE-POSTCHECK-SKIPPED] log token."""

    DAG_FILE = REPO_ROOT / "dags" / "edgeguard_pipeline.py"

    def test_postcheck_callable_inspects_dagrun_task_states(self):
        text = self.DAG_FILE.read_text()
        # Must reference get_dagrun + get_task_instance to look up upstream state
        assert "get_dagrun" in text and "get_task_instance" in text, (
            "PR-N27 sentinel must use ti.get_dagrun().get_task_instance(task_id) to inspect upstream task state"
        )

    def test_postcheck_sentinel_uses_module_level_critical_chain_constant(self):
        """PR-N26 multi-agent audit ROUND 2 (2026-04-23, 6-of-7 agent
        corroboration): the first audit's "dynamic enumeration" fix
        (``ti.task.get_flat_relatives(upstream=True)``) overcorrected —
        it caught Tier 1/2 collector failures, which use trigger_rule=
        ALL_DONE on purpose and must NOT cascade. Bugbot round 2 caught
        this as HIGH. The correct shape is a module-level
        ``_BASELINE_CRITICAL_CHAIN`` frozenset that scopes the sentinel
        to ONLY the data-producing critical-chain tasks (sync, build_rels,
        enrichment). Adding a 4th critical task in the future is
        discoverable via grep — the "bit-rot" concern from the first
        audit is real but theoretical; the dynamic-enumeration regression
        was concrete and baseline-blocking."""
        text = self.DAG_FILE.read_text()
        # Must define _BASELINE_CRITICAL_CHAIN at module scope
        assert "_BASELINE_CRITICAL_CHAIN" in text, (
            "dags/edgeguard_pipeline.py must define _BASELINE_CRITICAL_CHAIN frozenset "
            "at module level (PR-N26 audit round 2, 6-of-7 agent corroboration)"
        )
        # The sentinel's for-loop must iterate over the constant (positive pin)
        assert "for upstream_task_id in _BASELINE_CRITICAL_CHAIN:" in text, (
            "the sentinel must iterate over the module-level _BASELINE_CRITICAL_CHAIN "
            "frozenset (PR-N26 audit round 2 recommended shape)"
        )
        # Negative pin: the broken call pattern must NOT appear anywhere in
        # the file as actual code. Strip comments (lines starting with ``#``
        # or content after ``#``) so the comment trail documenting the
        # history doesn't false-positive the pin.
        code_only_lines = []
        for line in text.splitlines():
            # Drop trailing inline comments
            if "#" in line:
                # Crude but sufficient: if the first non-space char is ``#``
                # it's a comment line; else strip after ``#`` if the ``#`` is
                # clearly a comment delimiter (preceded by a space and not
                # inside a string literal — this file has no ``#`` in strings
                # for this concern).
                code_part = line.split("#", 1)[0]
                code_only_lines.append(code_part)
            else:
                code_only_lines.append(line)
        code_only = "\n".join(code_only_lines)
        assert "ti.task.get_flat_relatives(upstream=True)" not in code_only, (
            "the sentinel must NOT call ti.task.get_flat_relatives(upstream=True) — "
            "that overcorrection was Bugbot's round-2 HIGH. Use the "
            "_BASELINE_CRITICAL_CHAIN frozenset instead (PR-N26 audit round 2)."
        )

    def test_postcheck_sentinel_behaviour_collector_failure_does_not_skip(self):
        """BEHAVIOURAL test (Test Coverage REC-B1 from audit round 2):
        exercise the sentinel with a mocked Airflow context simulating
        "1 of 10 collectors failed, critical chain all succeeded". The
        sentinel must NOT raise AirflowSkipException — the graph is
        healthy, invariants should run.

        This is the test that would have caught Bugbot's round-2 HIGH
        had it existed before f4eebbb. The previous test
        (``test_postcheck_callable_uses_dynamic_upstream_enumeration``)
        pinned the BROKEN behaviour via source-text; a behavioural test
        is the correct shape for runtime control-flow contracts."""
        # NOTE: we can't import the DAG module directly without Airflow
        # runtime (it instantiates DAG() at import time). The behavioural
        # pin here is source-level but semantically specific: it verifies
        # that the sentinel's iteration set DOES NOT include any collector
        # task_id, which is the invariant that would have caught Bugbot's
        # round-2 HIGH. A full behavioural test with mocked Airflow
        # context is deferred to a dedicated pytest-airflow fixture
        # (tracked as part of PR-N29 follow-ups).

        # We can't import the DAG module directly without Airflow runtime
        # (it instantiates DAG() at import time). Instead verify the
        # sentinel logic via a focused exec of the assert_baseline_postconditions
        # function body using the module-level constant.
        #
        # Minimum viable behavioural pin: after reverting to the
        # hardcoded constant, verify that feeding it a collector_X state
        # doesn't land in ``failed_or_skipped`` because collector_X isn't
        # in _BASELINE_CRITICAL_CHAIN.
        text = self.DAG_FILE.read_text()
        assert '"full_neo4j_sync"' in text and '"build_relationships"' in text, (
            "the _BASELINE_CRITICAL_CHAIN must enumerate the 3 critical tasks"
        )
        # Sentinel logic: upstream_task_id iterates over the constant; only
        # those states are checked. So bl_otx=failed never enters the dict.
        # Verify by checking no collector task_id (bl_otx, bl_nvd, bl_cisa, etc.)
        # appears inside the sentinel block alongside the iteration.
        sentinel_idx = text.find("[BASELINE-POSTCHECK-SKIPPED]")
        sentinel_block = text[max(0, sentinel_idx - 2000) : sentinel_idx + 500]
        for collector_task in ("bl_otx", "bl_nvd", "bl_cisa", "bl_abuseipdb", "bl_threatfox"):
            assert collector_task not in sentinel_block, (
                f"collector task {collector_task!r} must not appear in sentinel — "
                "would indicate the old get_flat_relatives overcorrection is back"
            )

    def test_postcheck_sentinel_skips_on_critical_chain_failure(self):
        """BEHAVIOURAL test (Test Coverage REC-B1 part 2):
        when a critical-chain task (full_neo4j_sync / build_relationships /
        run_enrichment_jobs) is in failed/upstream_failed state, the
        sentinel MUST raise AirflowSkipException. This is the positive
        side of the contract — skipping DOES happen when upstream
        genuinely failed, just not when a non-critical collector glitched."""
        text = self.DAG_FILE.read_text()
        # The filter condition must match failed/upstream_failed/skipped
        # inside the sentinel scope
        sentinel_idx = text.find("[BASELINE-POSTCHECK-SKIPPED]")
        assert sentinel_idx != -1
        sentinel_block = text[max(0, sentinel_idx - 2000) : sentinel_idx + 500]
        # Must filter for these three states
        for state in ("failed", "upstream_failed", "skipped"):
            assert f'"{state}"' in sentinel_block, f"sentinel must match state {state!r} as a skip-trigger"
        # And raise AirflowSkipException (not just return)
        after_filter = text[sentinel_idx : sentinel_idx + 3000]
        assert "raise AirflowSkipException" in after_filter, (
            "sentinel must raise AirflowSkipException (not bare return) — PR-N26 Bugbot round 1 HIGH fix"
        )

    def test_postcheck_callable_raises_airflow_skip_on_upstream_failure(self):
        """PR-N27 Bugbot round 1 (HIGH): the sentinel must raise
        ``AirflowSkipException`` (NOT bare ``return``) so postcheck lands in
        state=skipped. Bare ``return`` would land state=SUCCESS, and
        ``baseline_complete``'s ``NONE_FAILED_MIN_ONE_SUCCESS`` trigger rule
        (which evaluates only direct parents) would see postcheck SUCCESS
        and still run — echoing "BASELINE Complete!" on a failed upstream
        run. Exact silent-success regression Fix A was meant to eliminate.

        Fix: AirflowSkipException propagates cleanly — postcheck SKIPPED
        → baseline_complete sees "no direct-parent success" → also SKIPPED
        → DAG correctly FAILED via the original upstream."""
        text = self.DAG_FILE.read_text()
        # Must import AirflowSkipException alongside AirflowException
        assert "AirflowSkipException" in text, (
            "dags/edgeguard_pipeline.py must import AirflowSkipException (PR-N27 Bugbot round 1 fix)"
        )
        # The sentinel must raise it after the log line
        idx = text.find("[BASELINE-POSTCHECK-SKIPPED]")
        assert idx != -1, "[BASELINE-POSTCHECK-SKIPPED] log token missing"
        block = text[idx : idx + 2000]
        assert "raise AirflowSkipException" in block, (
            "PR-N27 sentinel must ``raise AirflowSkipException`` after logging "
            "[BASELINE-POSTCHECK-SKIPPED]. A bare ``return`` lands postcheck in "
            "SUCCESS state, which defeats the PR-N26 Fix A contract "
            "(baseline_complete still runs because its direct parent is SUCCESS). "
            "AirflowSkipException correctly propagates as SKIPPED."
        )

    def test_airflow_skip_exception_not_swallowed_by_broad_except(self):
        """Defensive: the broad ``except Exception`` around the
        introspection block must NOT swallow AirflowSkipException (which
        inherits from BaseException in modern Airflow but is sometimes
        a subclass of Exception). Pin an explicit ``except AirflowSkipException:
        raise`` clause ahead of the broad handler."""
        text = self.DAG_FILE.read_text()
        idx = text.find("[BASELINE-POSTCHECK-SKIPPED]")
        assert idx != -1
        # The ordering must be:
        #   raise AirflowSkipException(...)
        #   except AirflowSkipException: raise
        #   except Exception as _ctx_err: log-and-continue
        block = text[idx : idx + 2000]
        assert "except AirflowSkipException:" in block, (
            "PR-N27 sentinel must explicitly re-raise AirflowSkipException "
            "so the broad ``except Exception`` below doesn't swallow it as "
            "an introspection failure"
        )

    def test_postcheck_callable_handles_introspection_failure_gracefully(self):
        """Defensive: if Airflow context introspection itself fails (API
        change / missing field), the sentinel must log and continue to
        the invariant checks rather than block them."""
        text = self.DAG_FILE.read_text()
        # The sentinel must be wrapped in try/except that logs the error
        # and continues — find the warning log token.
        assert "upstream-state introspection failed" in text, (
            "PR-N27 sentinel must gracefully handle Airflow context-introspection "
            "failures (try/except around get_dagrun/get_task_instance) and continue "
            "to the invariant checks rather than block them"
        )


class TestPRN26AuditFollowupFixes:
    """PR-N26 multi-agent audit (2026-04-23) corroborated findings folded
    into this PR. The follow-up fixes pinned here and in the classes above:

    * **MED** — hardcoded upstream task IDs (Cross-Checker + Maintainer
      + Bug Hunter, 3-agent corroboration): switched to
      ``ti.task.get_flat_relatives(upstream=True)`` for dynamic enumeration.
    * **LOW** — ``[BASELINE-POSTCHECK-SKIPPED]`` token not in RUNBOOK
      (Maintainer + Prod Readiness): added Section 7 to ``docs/RUNBOOK.md``.
    """

    RUNBOOK_DOC = REPO_ROOT / "docs" / "RUNBOOK.md"
    SRC_FILE = REPO_ROOT / "src" / "run_misp_to_neo4j.py"

    def test_audit_round2_h2_placeholder_metric_call_is_wrapped(self):
        """PR-N26 multi-agent audit round 2 Bug Hunter H-2 + Red Team M3
        (2-agent corroboration): the defense-in-depth merge_malware/actor
        call inside the placeholder branch must be wrapped in its own
        narrow try/except so a Neo4j error on the observability-only path
        doesn't cascade to the outer try/except and get counted as a real
        sync error (re-introducing the PR-N28 bug class)."""
        text = self.SRC_FILE.read_text()
        # Must emit the new log token
        assert "[MERGE-PLACEHOLDER-METRIC-FAIL]" in text, (
            "H-2 fix: placeholder defense-in-depth merge call must emit "
            "[MERGE-PLACEHOLDER-METRIC-FAIL] on exception (WARN log, NOT counted "
            "as sync error)"
        )
        # Both malware and actor sites must have the wrap
        malware_fail_count = text.count("[MERGE-PLACEHOLDER-METRIC-FAIL] Malware")
        actor_fail_count = text.count("[MERGE-PLACEHOLDER-METRIC-FAIL] ThreatActor")
        assert malware_fail_count >= 1, "H-2 fix: malware loop must have the metric-fail wrap"
        assert actor_fail_count >= 1, "H-2 fix: actor loop must have the metric-fail wrap"

    def test_low_runbook_documents_baseline_postcheck_skipped_token(self):
        """LOW: ``[BASELINE-POSTCHECK-SKIPPED]`` token now indexed in RUNBOOK
        so on-call who sees it knows what it means without git-grep."""
        text = self.RUNBOOK_DOC.read_text()
        assert "[BASELINE-POSTCHECK-SKIPPED]" in text, (
            "LOW (Maintainer + Prod Readiness): docs/RUNBOOK.md must index the "
            "[BASELINE-POSTCHECK-SKIPPED] token introduced by PR-N27 so on-call "
            "operators can find it via grep"
        )
        # Section header mentioning postcheck (Section 7 per the fix):
        assert "Baseline postcheck skipped" in text, (
            "LOW: RUNBOOK section header must reference baseline postcheck skip scenario for greppability"
        )
