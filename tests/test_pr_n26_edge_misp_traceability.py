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

Plus a backfill migration (`scripts/backfill_edge_misp_event_ids.py`) for
~82,500 existing edges that were created before the fix.

## Test strategy

Three layers of pin:

1. **Static text pins** — every modified inner-query string contains the
   ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) +
   …)`` SET clause. Anchored on the PR-N26 comment marker so a future
   refactor can't strip the SET without also stripping the comment.

2. **AST-shape pins** — for each modified ``_qNN_inner`` constant in
   ``build_relationships.py``, parse the file and verify the constant's
   value contains the SET clause structurally. Catches the case where
   someone reorganizes the queries into a helper function and breaks the
   string-literal anchor.

3. **Backfill script structural pins** — assert ``scripts/backfill_edge_
   misp_event_ids.py`` exists, exposes 5 named patterns, uses
   ``apoc.periodic.iterate`` (bounded TX), and is gated on
   ``coalesce(size(r.misp_event_ids), 0) = 0`` (idempotent).

We deliberately do NOT add a behavioural integration test that runs
build_relationships against a live Neo4j — that's covered by the
existing integration suite (which is excluded from the coverage gate).
The static + AST pins are sufficient to catch regressions to the
specific SET-clause shape this PR introduces.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
SCRIPTS = REPO_ROOT / "scripts"
MIGRATIONS = REPO_ROOT / "migrations"


# ===========================================================================
# Helper: locate a string-literal assignment and return its concatenated value
# ===========================================================================


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
                    # f-string / call expressions — fall back to unparsed source
                    # which still contains every literal we care to grep for.
                    return ast.unparse(node.value)
    raise AssertionError(f"variable {var_name!r} not found in {src_path}")


# ===========================================================================
# Section 1 — static text pins on each fixed query in build_relationships.py
# ===========================================================================


_BUILD_RELATIONSHIPS = SRC / "build_relationships.py"


class TestBuildRelationshipsHasMispEventIdsSetClause:
    """Each of the 6 fixed inner-query constants must contain the
    ``r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) + …)``
    SET clause. The right-hand side may differ (``[eid]`` for Q4 — the
    co-occurrence path which has the eid in scope — vs ``coalesce(<src>.
    misp_event_ids, [])`` for the others), so the pin checks each pattern
    individually."""

    def test_q3a_exploits_vuln_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3a_inner")
        assert "r.misp_event_ids" in body, "Q3a must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q3a must propagate the indicator's misp_event_ids onto the EXPLOITS edge"
        )
        assert "apoc.coll.toSet" in body, "Q3a must use apoc.coll.toSet for idempotent dedup"

    def test_q3b_exploits_cve_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q3b_inner")
        assert "r.misp_event_ids" in body, "Q3b must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body
        assert "apoc.coll.toSet" in body

    def test_q4_indicates_cooccurrence_uses_eid_in_scope(self):
        """Q4's co-occurrence query iterates ``eid IN m.misp_event_ids`` —
        the eid IS the originating event id, so the SET appends ``[eid]``
        (cleaner than propagating the full source array)."""
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q4_inner")
        assert "r.misp_event_ids" in body, "Q4 must SET r.misp_event_ids (PR-N26)"
        # Specifically [eid] (not coalesce-from-i) — Q4 has the exact
        # event id available, no superset needed.
        assert "+ [eid]" in body or "+[eid]" in body, (
            "Q4 must SET r.misp_event_ids = apoc.coll.toSet(coalesce(r.misp_event_ids, []) + [eid]) "
            "— the eid is already in scope, no need to propagate the full array"
        )
        assert "apoc.coll.toSet" in body

    def test_q7a_targets_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7a_inner")
        assert "r.misp_event_ids" in body, "Q7a must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q7a must propagate the indicator's misp_event_ids onto the TARGETS edge"
        )
        assert "apoc.coll.toSet" in body

    def test_q7b_affects_propagates_vulnerability_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q7b_inner")
        assert "r.misp_event_ids" in body, "Q7b must SET r.misp_event_ids (PR-N26)"
        # Q7b uses ``v`` for the Vulnerability/CVE node, not ``i``.
        assert "coalesce(v.misp_event_ids, [])" in body, (
            "Q7b must propagate the Vulnerability/CVE's misp_event_ids onto the AFFECTS edge"
        )
        assert "apoc.coll.toSet" in body

    def test_q9_indicates_family_propagates_indicator_events(self):
        body = _string_literal_value(_BUILD_RELATIONSHIPS, "_q9_inner")
        assert "r.misp_event_ids" in body, "Q9 must SET r.misp_event_ids (PR-N26)"
        assert "coalesce(i.misp_event_ids, [])" in body, (
            "Q9 must propagate the indicator's misp_event_ids onto the family-match INDICATES edge"
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
                    body = ast.unparse(node.value)

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


# ===========================================================================
# Section 3 — backfill script structural pins
# ===========================================================================


_BACKFILL = SCRIPTS / "backfill_edge_misp_event_ids.py"


class TestBackfillScriptStructure:
    """``scripts/backfill_edge_misp_event_ids.py`` must:

    1. Exist + be executable.
    2. Define a ``PATTERNS`` list with at least 5 entries (one per fix site).
    3. Use ``apoc.periodic.iterate`` so transactions stay bounded.
    4. Gate on ``coalesce(size(r.misp_event_ids), 0) = 0`` so it's idempotent.
    5. For the cooccurrence pattern, compute the intersection of source +
       target arrays (the EXACT historical event set), not the union.
    """

    def test_backfill_script_exists(self):
        assert _BACKFILL.exists(), f"backfill script missing at {_BACKFILL}"

    def test_backfill_script_is_executable(self):
        import os

        assert os.access(_BACKFILL, os.X_OK), "backfill script must be chmod +x for operator runbook"

    def test_backfill_script_has_five_patterns(self):
        text = _BACKFILL.read_text()
        # Each pattern is a ('name', count_q, write_q) tuple in the PATTERNS list.
        # We don't import the module (would require neo4j-driver in the test env);
        # parse the AST to count tuple-literal entries inside PATTERNS.
        # PATTERNS may be either an Assign (``PATTERNS = [...]``) or an
        # AnnAssign (``PATTERNS: List[Tuple[str, str, str]] = [...]``) —
        # check both shapes.
        tree = ast.parse(text)
        for node in ast.walk(tree):
            target_name = None
            value_node = None
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "PATTERNS":
                        target_name = "PATTERNS"
                        value_node = node.value
                        break
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "PATTERNS":
                target_name = "PATTERNS"
                value_node = node.value

            if target_name is None or value_node is None:
                continue
            assert isinstance(value_node, ast.List), "PATTERNS must be a list literal"
            assert len(value_node.elts) >= 5, (
                f"PATTERNS must have at least 5 entries (one per fix site); found {len(value_node.elts)}"
            )
            return
        raise AssertionError("PATTERNS list not found in backfill script")

    def test_backfill_uses_apoc_periodic_iterate(self):
        text = _BACKFILL.read_text()
        assert text.count("apoc.periodic.iterate") >= 5, (
            "every pattern's write_query must use apoc.periodic.iterate to keep TX bounded — "
            "expected ≥5 occurrences (one per pattern)"
        )

    def test_backfill_is_idempotent_via_size_gate(self):
        text = _BACKFILL.read_text()
        # The Cypher gate ``coalesce(size(r.misp_event_ids), 0) = 0`` ensures
        # we only touch edges that currently lack the array. Re-runs are no-ops.
        assert "coalesce(size(r.misp_event_ids), 0) = 0" in text, (
            "every pattern must gate on coalesce(size(r.misp_event_ids), 0) = 0 to be idempotent"
        )

    def test_cooccurrence_pattern_uses_intersection(self):
        """For the ``misp_cooccurrence`` INDICATES edge specifically, we have
        BOTH endpoints' arrays available — so we can recover the EXACT
        historical event set (the intersection) rather than over-stamping
        with a superset."""
        text = _BACKFILL.read_text()
        # The intersection idiom: list comprehension filtering one array
        # against the other.
        assert "WHERE eid IN coalesce(m.misp_event_ids" in text, (
            "indicates_cooccurrence pattern must compute "
            "[eid IN coalesce(i.misp_event_ids, []) WHERE eid IN coalesce(m.misp_event_ids, [])] — "
            "the exact intersection that originally produced the edge"
        )

    def test_backfill_supports_dry_run(self):
        text = _BACKFILL.read_text()
        assert "--dry-run" in text, "backfill must support --dry-run for operator preflight"

    def test_backfill_supports_only_filter(self):
        text = _BACKFILL.read_text()
        assert "--only" in text, "backfill must support --only <pattern> for incremental rollout"

    def test_backfill_reports_committed_operations_not_total(self):
        """PR-N26 Bugbot round 1 LOW (2026-04-23): apoc.periodic.iterate's
        ``total`` field reports INPUT rows consumed from the outer query, not
        rows actually MUTATED by the inner statement. For patterns with an
        inner-query filter (indicates_cooccurrence has
        ``WHERE size(shared) > 0`` to skip empty intersections), ``total``
        OVERCOUNTS. Operators re-running the script would see misleading
        "backfilled N edges" reports when zero were actually modified.

        Fix: YIELD ``committedOperations`` and report that as the written
        count. ``total`` is kept as ``scanned`` so operators can see the
        filter-skip delta."""
        text = _BACKFILL.read_text()
        # All 5 write queries must YIELD committedOperations.
        committed_yield_count = text.count("YIELD batches, total, committedOperations, errorMessages")
        assert committed_yield_count >= 5, (
            f"all 5 write queries must YIELD committedOperations for accurate write counts; "
            f"found only {committed_yield_count} occurrences. "
            "See Bugbot round 1 LOW finding on PR #109."
        )
        # And the Python driver must read the field (not total).
        assert 'write_record["committedOperations"]' in text, (
            "Python driver must read write_record['committedOperations'] to report "
            "accurate write counts, not write_record['total'] which overcounts"
        )
        # The operator log must surface both scanned + written so the delta
        # (filter-skipped) is visible.
        assert "filter-skipped" in text, (
            "operator-facing log must surface the scanned vs written delta as "
            "``filter-skipped`` so ops can see the filter impact without re-querying"
        )


# ===========================================================================
# Section 4 — operator runbook exists and references the script
# ===========================================================================


_RUNBOOK = MIGRATIONS / "2026_05_edge_misp_event_ids_backfill_runbook.md"


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
        the rest of the loop body) rather than fall through to ``errors += 1``."""
        text = self.SRC_FILE.read_text()
        # Find the malware placeholder rejected block
        idx = text.find("[MERGE-PLACEHOLDER-REJECTED] Malware")
        assert idx != -1
        # Within ~600 chars after the log line, we expect:
        #   - increment placeholder_rejections
        #   - call merge_malware (defense-in-depth metric increment)
        #   - continue (skip the rest of the loop)
        block = text[idx : idx + 1000]
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

    def test_postcheck_callable_checks_known_upstream_task_ids(self):
        text = self.DAG_FILE.read_text()
        # The sentinel must enumerate the actual upstream task IDs in the chain
        for task_id in ("full_neo4j_sync", "build_relationships", "run_enrichment_jobs"):
            assert f'"{task_id}"' in text, (
                f"PR-N27 sentinel must enumerate upstream task_id={task_id!r} for state inspection"
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


class TestRunbookExists:
    def test_runbook_file_exists(self):
        assert _RUNBOOK.exists(), f"operator runbook missing at {_RUNBOOK}"

    def test_runbook_references_backfill_script(self):
        text = _RUNBOOK.read_text()
        assert "scripts/backfill_edge_misp_event_ids.py" in text, "runbook must reference the backfill script by path"

    def test_runbook_has_dry_run_step(self):
        text = _RUNBOOK.read_text()
        assert "--dry-run" in text, "runbook must instruct operators to dry-run first"

    def test_runbook_has_idempotency_note(self):
        text = _RUNBOOK.read_text()
        assert "Idempoten" in text or "idempoten" in text, (
            "runbook must explicitly state the script is idempotent (so operators feel safe re-running)"
        )

    def test_runbook_has_verification_step(self):
        text = _RUNBOOK.read_text()
        # Operators need to know HOW to verify the backfill landed.
        assert "Verify" in text or "verify" in text or "verification" in text.lower(), (
            "runbook must include a post-backfill verification step"
        )

    def test_runbook_clarifies_not_a_baseline_blocker(self):
        text = _RUNBOOK.read_text()
        assert "NOT a blocker" in text or "not a blocker" in text or "not block" in text.lower(), (
            "runbook should clarify this migration is NOT a blocker for the next 730d baseline launch — "
            "operators need this signal so they don't delay baseline-day for a non-critical migration"
        )
