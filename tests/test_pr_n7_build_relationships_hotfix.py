"""
PR-N7 — build_relationships hotfix.

Triggered by on-call report from Bravo Vanko on 2026-04-21: the
730-day baseline pipeline deadlocked for 5+ hours on
``build_relationships.py`` step 4 with no progress logs. Root-cause
investigation found THREE distinct bugs at three layers:

  #1 [HIGH / silent-data-loss] The ``<> ''`` pattern in 4 outer
    queries (steps 2, 3a, 3b, 9) broke the apoc.periodic.iterate
    single-quote wrapper. Rendered Cypher:

        CALL apoc.periodic.iterate('... <> '' RETURN i', '...', ...)
                                                ^^ closes the wrapper string
                                                   RETURN i is un-delimited

    Steps failed with "Invalid input '' RETURN i'" → caught by
    ``_safe_run_batched`` try/except → logged at ERROR → pipeline
    continued with ``stats[key]=0``. Net: zero ATTRIBUTED_TO edges,
    zero Indicator→Vulnerability edges, zero Indicator→CVE edges,
    zero Indicator→Malware-family edges on EVERY baseline run.

  #2 [HIGH / scale] Step 4 (Indicator → Malware co-occurrence)
    iterated from the 144K-Indicator side. With no array index on
    ``Malware.misp_event_ids`` (Neo4j CE doesn't support array
    element indexes), each (indicator, event_id) pair scanned all
    3,384 Malware nodes → ~1.7B comparisons → 5+ hour stall.

  #3 [MED / ops] ``_safe_run_batched`` emitted no mid-flight
    progress logs. A multi-hour apoc.periodic.iterate call produced
    zero output between its start and completion → operators could
    not distinguish "still running" from "hung/dead".

## Fixes

  #1 Replace ``x IS NOT NULL AND x <> ''`` with ``x IS NOT NULL AND
     size(x) > 0`` at all 4 sites. Same semantics for string fields,
     no single-quote conflict.

  #1b Add a module-load regression guard
     (``_assert_no_unsafe_empty_string_literal_in_outer_queries``)
     that AST-walks the module's own source and raises at import
     time if any ``*_outer`` / ``*_inner`` variable contains
     ``<> ''``. Prevents a future maintainer from silently
     re-introducing the bug.

  #2 Reverse step 4's join direction: outer = Malware (3.4K), inner
     = Indicator scan per event_id. 43× fewer apoc outer iterations
     = 43× fewer batch-transaction commits. MERGE semantics make
     the reversed edge set identical.

  #3 Pre-log outer row count + start log + elapsed-time in the
     completion log. Operators now see "N outer rows, ~M batches"
     before the step starts + "in X.Ys" after, so multi-hour runs
     are distinguishable from hangs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n7")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n7")


# ===========================================================================
# Fix #1 — quote-escape bug eliminated at all 4 outer query sites
# ===========================================================================


class TestFix1QuoteEscapeBugEliminated:
    """Pre-fix 4 outer queries (steps 2, 3a, 3b, 9) contained
    ``<> ''`` which broke the apoc wrapper. Post-fix all use
    ``size(x) > 0``."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_step2_malware_threatactor_no_unsafe_literal(self):
        """Step 2: Malware → ThreatActor ATTRIBUTED_TO. Outer query
        must not contain ``<> ''`` anywhere.

        PR-N10 refactored ``_outer`` to a multi-line tuple-of-strings
        shape (to accommodate the placeholder NOT IN filter inline
        with the OR branches). AST-extract the full resolved string
        rather than the source-file line."""
        import ast

        src = self._src()
        # Scan a window around step 2 to find the _outer assignment.
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        assert step2_idx != -1 and step3_idx != -1
        # Parse the full module so AST walker covers all assignments.
        tree = ast.parse(src)
        outer_value = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "_outer":
                        # Collect all string Constant values from the RHS
                        parts: list = []
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                                parts.append(sub.value)
                        candidate = "".join(parts)
                        # Is this the step-2 _outer? Step 2 MATCH is (m:Malware).
                        if "MATCH (m:Malware)" in candidate and "m.attributed_to" in candidate:
                            outer_value = candidate
                            break
                if outer_value:
                    break

        assert outer_value is not None, "could not locate step-2 _outer via AST"
        assert "<> ''" not in outer_value, f"Step 2 outer still has unsafe `<> ''`: {outer_value}"
        assert "size(m.attributed_to) > 0" in outer_value or "size(trim(m.attributed_to)) > 0" in outer_value, (
            "Step 2 must use a size()-based length check (PR-N8 R1 hardened "
            "to size(trim(...))); PR-N10 kept this shape."
        )

    def test_step3a_3b_cve_no_unsafe_literal(self):
        """Steps 3a and 3b: Indicator → Vulnerability/CVE. Both
        outer queries + skip queries must avoid ``<> ''``."""
        src = self._src()
        # Specifically look for the patterns expected in the fixed form
        assert "i.cve_id IS NOT NULL AND size(i.cve_id) > 0" in src, "Step 3a/3b outer must use size(i.cve_id) > 0"
        # And the bad form must not appear in any executable query literal
        # (checked structurally in the next test too)

    def test_step9_malware_family_no_unsafe_literal(self):
        """Step 9: Indicator → Malware (malware_family match). Outer
        query must use size() check.

        PR-N8 R1 hardened outer to ``size(trim(...))``. PR-N10 split
        the outer into a multi-line tuple for the placeholder NOT IN
        filter. We check the concatenated parts contain the size-check
        pattern; the PR-N7 test's primary concern (no `<> ''`) is
        separately pinned by ``test_no_unsafe_literal_in_any_outer_
        or_inner_query_string`` which AST-walks the full module."""
        src = self._src()
        # Concatenate adjacent quoted string fragments so the multi-line
        # tuple form (``_q9_outer = ("a " "b " "c")``) matches the same
        # substring as the pre-PR-N10 single-line form.
        # Easiest: just check both the OLD single-line form and a more
        # flexible check on the AST-walked Q9 outer string.
        import ast

        tree = ast.parse(src)
        q9_outer_value = None
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "_q9_outer":
                        parts = [
                            sub.value
                            for sub in ast.walk(node.value)
                            if isinstance(sub, ast.Constant) and isinstance(sub.value, str)
                        ]
                        q9_outer_value = "".join(parts)
                        break
        assert q9_outer_value is not None, "_q9_outer not found"
        # Accept either the pre-PR-N8-R1 size(x) or the post-R1 size(trim(x))
        assert "i.malware_family IS NOT NULL" in q9_outer_value and (
            "size(i.malware_family) > 0" in q9_outer_value or "size(trim(i.malware_family)) > 0" in q9_outer_value
        ), f"Q9 outer must use a size()-based length check; got: {q9_outer_value!r}"

    def test_no_unsafe_literal_in_any_outer_or_inner_query_string(self):
        """AST-walk: verify NO ``<> ''`` appears in any string literal
        assigned to a variable named with 'outer' or 'inner'."""
        import ast

        src = self._src()
        tree = ast.parse(src)
        findings: list = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                target_names = [
                    t.id
                    for t in node.targets
                    if isinstance(t, ast.Name) and ("outer" in t.id.lower() or "inner" in t.id.lower())
                ]
                if not target_names:
                    continue
                for const_node in ast.walk(node.value):
                    if isinstance(const_node, ast.Constant) and isinstance(const_node.value, str):
                        if "<> ''" in const_node.value:
                            findings.append((target_names[0], node.lineno))

        assert not findings, (
            f"PR-N7 fix #1 regression: found `<> ''` in outer/inner query "
            f"variables: {findings}. This breaks apoc.periodic.iterate's "
            f"single-quote wrapper. Use `size(x) > 0` instead."
        )


# ===========================================================================
# Fix #1b — module-load regression guard
# ===========================================================================


class TestFix1bModuleLoadRegressionGuard:
    """The ``_assert_no_unsafe_empty_string_literal_in_outer_queries``
    guard must fire at import time if any ``_outer``/``_inner`` string
    contains the dangerous pattern."""

    def test_guard_function_exists(self):
        src = (SRC / "build_relationships.py").read_text()
        assert "def _assert_no_unsafe_empty_string_literal_in_outer_queries" in src, (
            "PR-N7 guard function must be defined in build_relationships.py"
        )

    def test_guard_called_at_module_load(self):
        """The guard must actually be INVOKED at module top-level,
        not just defined. Otherwise it's a dead function."""
        src = (SRC / "build_relationships.py").read_text()
        # Find an invocation of the guard function that's NOT inside
        # another def (i.e. at module top level).
        import ast

        tree = ast.parse(src)
        found_top_level_call = False
        for node in tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                if (
                    isinstance(node.value.func, ast.Name)
                    and node.value.func.id == "_assert_no_unsafe_empty_string_literal_in_outer_queries"
                ):
                    found_top_level_call = True
                    break
        assert found_top_level_call, (
            "PR-N7: guard function must be CALLED at module top level, "
            "not just defined. Otherwise regressions won't trip CI."
        )

    def test_guard_raises_on_synthetic_bad_pattern(self, monkeypatch, tmp_path):
        """Behavioural: synthesize a mini module with the bad pattern
        in an outer/inner variable and verify the guard logic raises.

        We can't easily monkey-patch the real module's source (it's
        already imported cleanly), so we replicate the AST-walking logic
        inline to prove the detection is correct."""
        import ast

        bad_src = """
_q_outer = "MATCH (i) WHERE i.x <> '' RETURN i"
_q_inner = "WITH $i AS i RETURN i"
"""
        tree = ast.parse(bad_src)
        findings: list = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                target_names = [
                    t.id
                    for t in node.targets
                    if isinstance(t, ast.Name) and ("outer" in t.id.lower() or "inner" in t.id.lower())
                ]
                if not target_names:
                    continue
                for const_node in ast.walk(node.value):
                    if isinstance(const_node, ast.Constant) and isinstance(const_node.value, str):
                        if "<> ''" in const_node.value:
                            findings.append(target_names[0])

        assert "_q_outer" in findings, "guard logic must detect <> '' in an _outer string literal"
        assert "_q_inner" not in findings, "_q_inner without the pattern must not be flagged"


# ===========================================================================
# Fix #2 — step 4 join reversal (Malware is outer, Indicator is inner)
# ===========================================================================


class TestFix2Step4JoinReversal:
    """Step 4 now iterates from the small side (Malware, ~3.4K)
    instead of the large side (Indicator, ~144K). 43× fewer apoc
    outer iterations."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_step4_outer_is_malware_not_indicator(self):
        """Outer MATCH must select Malware, not Indicator. Find the
        step-4 outer assignment by the label banner."""
        src = self._src()
        step4_idx = src.find("[LINK] 4/12 Indicator → Malware (co-occurrence")
        assert step4_idx != -1
        # Following _q4_outer assignment
        outer_idx = src.find("_q4_outer =", step4_idx)
        assert outer_idx != -1
        line = src[outer_idx : src.find("\n", outer_idx)]
        # Must match Malware, not Indicator
        assert "MATCH (m:Malware)" in line, f"Step 4 outer must be Malware; got: {line}"
        assert "MATCH (i:Indicator)" not in line, f"Step 4 outer must NOT be Indicator (pre-fix form); got: {line}"

    def test_step4_inner_matches_indicator(self):
        """Inner MATCH must select Indicator (the other side of the
        join). Use AST walking to extract the actual string value of
        ``_q4_inner`` — source-text regex misses because the tuple
        contains parentheses inside comments."""
        import ast

        src = self._src()
        tree = ast.parse(src)
        q4_inner_value = self._extract_string_constant(tree, "_q4_inner")
        assert q4_inner_value is not None, "could not locate _q4_inner assignment"
        assert "MATCH (i:Indicator)" in q4_inner_value, (
            f"Step 4 inner must scan Indicator; got: {q4_inner_value[:200]!r}"
        )
        assert "eid IN i.misp_event_ids" in q4_inner_value, (
            "Step 4 inner must filter by event-id membership on Indicator side"
        )

    def test_step4_merge_edge_direction_unchanged(self):
        """MERGE direction must still be (i)-[:INDICATES]->(m) — the
        reversal is only in which side is the apoc outer driver, NOT
        in the edge semantics."""
        import ast

        src = self._src()
        tree = ast.parse(src)
        q4_inner_value = self._extract_string_constant(tree, "_q4_inner")
        assert q4_inner_value is not None
        assert "MERGE (i)-[r:INDICATES]->(m)" in q4_inner_value, (
            "edge direction must remain i→m (INDICATES); join reversal is "
            "about outer driver only, not semantic direction"
        )

    @staticmethod
    def _extract_string_constant(tree, var_name: str):
        """Walk AST, find ``<var_name> = ...`` and return the resolved
        string value if the RHS is a tuple/Str of string literals."""
        import ast

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        # RHS can be a Constant, a Tuple of Constants,
                        # or an expr that concatenates strings. Walk
                        # all descendants and concatenate constant strs.
                        parts = []
                        for sub in ast.walk(node.value):
                            if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                                parts.append(sub.value)
                        return "".join(parts) if parts else None
        return None


# ===========================================================================
# Fix #3 — heartbeat / progress logging
# ===========================================================================


class TestFix3ProgressLogging:
    """_safe_run_batched must pre-log outer count + start + end+elapsed."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_pre_count_query_runs_before_apoc(self):
        """A preamble COUNT(*) of the outer query must run before the
        main apoc.periodic.iterate so operators see the scale."""
        src = self._src()
        fn_idx = src.find("def _safe_run_batched(")
        assert fn_idx != -1
        # Find the apoc CALL. The preamble (outer_count + log) must appear before it.
        body_end = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : body_end if body_end != -1 else len(src)]
        apoc_idx = body.find("CALL apoc.periodic.iterate")
        count_idx = body.find("CALL {{ {outer_query} }} RETURN count(*)")
        # Actually the f-string uses f"CALL {{ {outer_query} }} ...", check literal
        assert "CALL {{ {outer_query} }} RETURN count(*)" in body, (
            "preamble COUNT query must use `CALL {{ ... }} RETURN count(*)` form"
        )
        # Count query must appear before the main apoc call
        count_idx = body.find("CALL {{ {outer_query} }}")
        apoc_idx = body.find("CALL apoc.periodic.iterate")
        assert 0 < count_idx < apoc_idx, "preamble count must appear before main apoc call"

    def test_start_log_emitted(self):
        """A "starting apoc.periodic.iterate" log must fire before the
        apoc call so operators see the boundary."""
        src = self._src()
        assert "starting apoc.periodic.iterate" in src, "PR-N7 fix #3: start-log must be present"

    def test_elapsed_time_in_completion_log(self):
        """Success + partial + 0-match log lines must include elapsed
        time so operators can compare against wall-clock."""
        src = self._src()
        # These three log sites all need the elapsed field
        assert "elapsed {_elapsed:.1f}s" in src, "completion logs must include elapsed time"
        # Specifically check in all three branches (OK / PARTIAL / 0 no-matches)
        # by checking 3+ occurrences
        occurrences = src.count("elapsed {_elapsed:.1f}s") + src.count("elapsed %.1fs")
        assert occurrences >= 3, (
            f"elapsed-time pattern should appear in all 3 result branches "
            f"(OK / PARTIAL / 0-matches) + the FAIL branch; "
            f"got {occurrences} occurrences"
        )


# ===========================================================================
# Cross-cutting — module imports cleanly with all 4 fixes applied
# ===========================================================================


class TestModuleImportsCleanly:
    """The module must import without the regression guard firing."""

    def test_module_imports_without_error(self):
        """If the guard finds any lingering `<> ''`, import raises."""
        # If import succeeds, the guard passed on current source.
        import build_relationships  # noqa: F401

    def test_build_relationships_function_exists(self):
        """Sanity: top-level API is still present."""
        import build_relationships

        assert hasattr(build_relationships, "build_relationships")
        assert callable(build_relationships.build_relationships)
