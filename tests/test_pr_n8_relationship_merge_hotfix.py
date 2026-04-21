"""
PR-N8 — relationship/merge hotfix bundle.

Four findings from the 5-agent audit of `build_relationships` + merge
logic (run 2026-04-21 after PR-N7 merged). All four are Tier-B or above
with cross-agent corroboration:

  #1 [BLOCK-MERGE] Q9 in ``build_relationships.py`` re-inflates
     calibrator-demoted INDICATES edges every run. The calibrator
     demotes 0.8 → 0.30 for bulk-dump events; Q9's unconditional
     ``SET r.confidence_score = CASE WHEN 0.8 > r.confidence_score
     THEN 0.8 …`` reverses that on the very next build_relationships
     run. The flap has been happening nightly since the calibrator
     shipped.

  #2 [HIGH] REFERS_TO / RUNS / PART_OF(malware) edges have no
     ``created_at`` / ``updated_at``. Cloud delta-sync + STIX
     incremental export filter by ``r.updated_at >= cutoff`` — these
     three edge classes are invisible to delta consumers.

  #3 [HIGH] ``_safe_run_batched`` blanket ``except Exception``
     swallows Neo4j transient errors (ServiceUnavailable,
     TransientError) instead of re-raising for retry. A 30-sec
     Neo4j restart mid-pipeline silently zeros a step.

  #4 [HIGH] Canonicalization parity: ``m.name`` is NFC+strip+lower'd
     at ingest via ``canonicalize_merge_key`` but ``i.malware_family``
     / ``m.attributed_to`` are stored raw. Same-semantic strings
     silently miss the match (e.g. "Emotet " vs "emotet"). Fix
     applies ``trim() + toLower()`` to both sides at the Cypher
     comparison.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n8")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n8")


# ===========================================================================
# Fix #1 — Q9 calibrator-respect guard (BLOCK-MERGE)
# ===========================================================================


class TestFix1Q9CalibratorRespect:
    """Pre-fix Q9 re-inflated calibrator-demoted confidence on every
    run. Post-fix the CASE gates on ``r.calibrated_at IS NOT NULL``
    to respect the calibrator's stamp."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_q9_has_calibrated_at_guard(self):
        """The Q9 inner CASE must include ``WHEN r.calibrated_at IS
        NOT NULL THEN r.confidence_score`` as its FIRST branch so it
        short-circuits before the 0.8 floor."""
        src = self._src()
        # Find the Q9 inner block and verify the guard is present
        q9_idx = src.find("_q9_inner")
        assert q9_idx != -1, "Q9 inner query must exist"
        next_assignment = src.find("_q9_skip", q9_idx)
        block = src[q9_idx : next_assignment if next_assignment != -1 else q9_idx + 3000]
        assert "r.calibrated_at IS NOT NULL" in block, (
            "Fix #1 regression: Q9 must guard on r.calibrated_at IS NOT NULL to respect the calibrator's demotion"
        )
        # Must appear BEFORE the 0.8 floor — extract the CASE body
        case_start = block.find("SET r.confidence_score = CASE")
        case_end = block.find("END", case_start)
        assert case_start != -1 and case_end > case_start
        case_body = block[case_start:case_end]
        # calibrated_at guard must come before the 0.8 floor
        cal_idx = case_body.find("calibrated_at IS NOT NULL")
        floor_idx = case_body.find("0.8 > r.confidence_score")
        assert cal_idx != -1 and floor_idx != -1 and cal_idx < floor_idx, (
            "Fix #1 regression: calibrated_at guard must come BEFORE the "
            "0.8 floor clause (CASE evaluates top-down, first-match-wins)"
        )

    def test_q9_case_branches_semantics(self):
        """Walk the CASE semantics:
        - calibrated_at NOT NULL → keep existing (calibrator wins)
        - confidence_score NULL or 0.8 > it → set 0.8 (fresh-edge floor)
        - else → keep existing (no regression from higher existing)
        """
        src = self._src()
        q9_idx = src.find("_q9_inner")
        next_assignment = src.find("_q9_skip", q9_idx)
        block = src[q9_idx : next_assignment if next_assignment != -1 else q9_idx + 3000]
        # Extract the CASE body
        case_body = block[block.find("SET r.confidence_score = CASE") : block.find("END", block.find("CASE"))]
        # All three branches must be present
        assert "r.calibrated_at IS NOT NULL THEN r.confidence_score" in case_body
        assert "r.confidence_score IS NULL OR 0.8 > r.confidence_score THEN 0.8" in case_body
        assert "ELSE r.confidence_score" in case_body


# ===========================================================================
# Fix #2 — REFERS_TO / RUNS / PART_OF(malware) timestamp stamping (HIGH)
# ===========================================================================


class TestFix2EnrichmentEdgeTimestamps:
    """Enrichment edges (RUNS, PART_OF malware, REFERS_TO both directions)
    must stamp ``created_at`` on first merge + ``updated_at`` on every
    re-merge so they're visible to cloud delta-sync + STIX incremental."""

    def _src(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_runs_edge_stamps_both_timestamps(self):
        """Campaign RUNS (ThreatActor→Campaign) edge must stamp both
        created_at and updated_at in build_campaign_nodes."""
        src = self._src()
        # Find the RUNS MERGE block; scan until the RETURN to capture
        # full MERGE + ON CREATE + SET clauses.
        idx = src.find("MERGE (a)-[r_runs:RUNS]")
        assert idx != -1
        end = src.find("RETURN count(DISTINCT c)", idx)
        assert end != -1, "could not find end of RUNS MERGE block"
        block = src[idx:end]
        assert "r_runs.created_at = datetime()" in block, "RUNS ON CREATE must stamp created_at"
        assert "r_runs.updated_at = datetime()" in block, "RUNS SET must stamp updated_at"

    def test_part_of_malware_stamps_both_timestamps(self):
        """PART_OF (Malware→Campaign) edge in the link_malware Cypher
        must stamp created_at + updated_at."""
        src = self._src()
        idx = src.find("link_malware = ")
        assert idx != -1
        # Find the triple-quote block
        block_end = src.find('"""', idx + 20)
        block_end = src.find('"""', block_end + 3)
        block = src[idx : block_end + 3]
        assert "r.created_at = datetime()" in block, "PART_OF(malware) ON CREATE must stamp created_at"
        assert "r.updated_at = datetime()" in block, "PART_OF(malware) SET must stamp updated_at"

    def test_refers_to_stamps_both_timestamps_both_directions(self):
        """bridge_vulnerability_cve creates REFERS_TO in BOTH directions
        (Vuln→CVE and CVE→Vuln). Both must stamp timestamps."""
        src = self._src()
        # Find the bridge_vulnerability_cve query
        idx = src.find("def bridge_vulnerability_cve")
        assert idx != -1
        # Next def
        next_def = src.find("\ndef ", idx + 10)
        block = src[idx : next_def if next_def != -1 else len(src)]
        # Both r1 (Vuln→CVE) and r2 (CVE→Vuln) must have timestamps
        assert "r1.created_at = datetime()" in block, "REFERS_TO Vuln→CVE must stamp created_at"
        assert "r1.updated_at = datetime()" in block, "REFERS_TO Vuln→CVE must stamp updated_at"
        assert "r2.created_at = datetime()" in block, "REFERS_TO CVE→Vuln must stamp created_at"
        assert "r2.updated_at = datetime()" in block, "REFERS_TO CVE→Vuln must stamp updated_at"


# ===========================================================================
# Fix #3 — narrow _safe_run_batched exception catch (HIGH)
# ===========================================================================


class TestFix3NarrowExceptionCatch:
    """``_safe_run_batched`` must re-raise Neo4j transient errors so
    the caller (or retry decorator) can retry. Non-transient errors
    (syntax, constraint) still caught-and-continue."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_transient_exception_classes_named(self):
        """The three Neo4j transient classes must be listed."""
        src = self._src()
        for cls_name in ("ServiceUnavailable", "SessionExpired", "TransientError"):
            assert cls_name in src, f"Fix #3: transient class {cls_name!r} must be named in the exception guard"

    def test_transient_raise_branch_exists(self):
        """The raise-on-transient branch must exist in the except block."""
        src = self._src()
        # Find _safe_run_batched's except
        fn_idx = src.find("def _safe_run_batched(")
        assert fn_idx != -1
        next_def = src.find("\ndef ", fn_idx + 1)
        body = src[fn_idx : next_def if next_def != -1 else len(src)]
        assert "isinstance(e, _transient_classes)" in body, "Fix #3: must isinstance-check against transient classes"
        # Must have a bare `raise` — using a sentinel that's less likely to false-match
        assert "            raise\n" in body, "Fix #3: must have a bare `raise` to propagate transients"

    def test_behaviour_transient_exception_reraised(self):
        """Given a mocked client.run that raises ServiceUnavailable,
        _safe_run_batched must re-raise (not silently count+continue)."""
        import importlib

        if "build_relationships" in sys.modules:
            del sys.modules["build_relationships"]
        build_relationships = importlib.import_module("build_relationships")

        try:
            from neo4j import exceptions as _neo4j_exc
        except ImportError:
            import pytest

            pytest.skip("neo4j package not available; transient-class test requires it")

        client = MagicMock()
        # Pre-count call succeeds with 0 (no rows to count). Main apoc call raises transient.
        client.run.side_effect = [
            [{"c": 0}],  # pre-count
            _neo4j_exc.ServiceUnavailable("simulated 30s restart"),  # main apoc
        ]
        stats: dict = {}
        import pytest

        with pytest.raises(_neo4j_exc.ServiceUnavailable):
            build_relationships._safe_run_batched(
                client,
                "TEST",
                "MATCH (n) RETURN n",
                "SET n.x = 1",
                stats,
                "k",
            )

    def test_behaviour_non_transient_caught_and_continued(self):
        """Non-transient ``ValueError`` (stand-in for ClientError/
        SyntaxError) must be caught+logged+returns False, NOT raised."""
        import importlib

        if "build_relationships" in sys.modules:
            del sys.modules["build_relationships"]
        build_relationships = importlib.import_module("build_relationships")

        client = MagicMock()
        client.run.side_effect = [
            [{"c": 0}],  # pre-count
            ValueError("simulated syntax error"),  # main apoc (not a transient)
        ]
        stats: dict = {}
        result = build_relationships._safe_run_batched(
            client,
            "TEST",
            "MATCH (n) RETURN n",
            "SET n.x = 1",
            stats,
            "k",
        )
        assert result is False, "non-transient error must return False (not raise)"
        assert stats["k"] == 0


# ===========================================================================
# Fix #4 — Canonicalization parity (HIGH)
# ===========================================================================


class TestFix4CanonicalizationParity:
    """Q2 (Malware→ThreatActor) and Q9 (Indicator→Malware family)
    must apply ``trim() + toLower()`` on BOTH sides of every string
    comparison so ingest-time canonicalization (PR #37) doesn't miss."""

    def _src(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_q9_inner_uses_trim_and_lower_on_both_sides(self):
        src = self._src()
        q9_idx = src.find("_q9_inner")
        next_assignment = src.find("_q9_skip", q9_idx)
        block = src[q9_idx:next_assignment]
        # Both m.name and i.malware_family sides must go through trim()+toLower()
        assert "toLower(trim(m.name))" in block, "Q9 m.name side must use trim()+toLower()"
        assert "toLower(trim(i.malware_family))" in block, "Q9 i.malware_family side must use trim()+toLower()"

    def test_q9_skip_uses_trim_and_lower_on_both_sides(self):
        """Skip-query must use the same normalization so orphan count
        matches actual match behaviour."""
        src = self._src()
        q9_skip_idx = src.find("_q9_skip")
        next_assignment = src.find("if not _safe_run_batched", q9_skip_idx)
        block = src[q9_skip_idx:next_assignment]
        assert "toLower(trim(m.name))" in block, "Q9 skip m.name must use trim()+toLower()"
        assert "toLower(trim(i.malware_family))" in block, "Q9 skip i.malware_family must use trim()+toLower()"

    def test_q2_uses_trim_and_lower_on_both_sides(self):
        """Q2 Malware.attributed_to vs ThreatActor.name comparison
        must also use trim()+toLower().

        Post-Bugbot-R1 (2026-04-21): the coalesce-to-empty-string
        wrapper has been removed; the bare ``trim(m.attributed_to)``
        form is now the correct shape (NULL propagates as falsy)."""
        src = self._src()
        # Find the step 2 block
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        assert step2_idx != -1
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        block = src[step2_idx:step3_idx]
        # Post-R1 form: no coalesce wrapper around the field
        assert "toLower(trim(m.attributed_to))" in block, "Q2 m.attributed_to side must use trim()+toLower()"
        assert "toLower(trim(a.name))" in block, "Q2 a.name side must use trim()+toLower()"

    def test_r1_no_coalesce_to_empty_string_in_q2_or_q9_comparisons(self):
        """Bugbot PR-N8 R1 LOW (2026-04-21): ``coalesce(m.family, '')``
        and ``coalesce(m.attributed_to, "")`` in the WHERE comparison
        broke NULL propagation. Post-R1 fix: drop the coalesce, rely
        on Cypher's native ``trim(NULL) → NULL → comparison NULL →
        falsy`` semantic.

        This test AST-walks Q2 and Q9 string literals and fails if any
        contains ``coalesce(m.family`` or ``coalesce(m.attributed_to``
        (with an empty-string default). The breadcrumb comments that
        describe the old idiom are NOT caught because they're in
        source comments, not in string literals."""
        import ast

        src = self._src()
        tree = ast.parse(src)

        findings: list = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                target_names = [
                    t.id
                    for t in node.targets
                    if isinstance(t, ast.Name) and (t.id in ("_outer", "_inner", "_q9_outer", "_q9_inner", "_q9_skip"))
                ]
                if not target_names:
                    continue
                for const_node in ast.walk(node.value):
                    if isinstance(const_node, ast.Constant) and isinstance(const_node.value, str):
                        s = const_node.value
                        # Detect the bad patterns: coalesce(<field>, '') or coalesce(<field>, "")
                        if "coalesce(m.family, '')" in s or 'coalesce(m.family, "")' in s:
                            findings.append((target_names[0], "coalesce(m.family, <empty>)"))
                        if "coalesce(m.attributed_to, '')" in s or 'coalesce(m.attributed_to, "")' in s:
                            findings.append((target_names[0], "coalesce(m.attributed_to, <empty>)"))

        assert not findings, (
            f"Bugbot PR-N8 R1 regression: found coalesce-to-empty-string in "
            f"Q2/Q9 query strings: {findings}. This breaks NULL propagation — "
            f"drop the coalesce and let trim(NULL) propagate as falsy."
        )

    def test_r1_outer_filters_reject_whitespace_only_values(self):
        """Bugbot PR-N8 R1 LOW: outer filters must use ``size(trim(x))
        > 0`` (not just ``size(x) > 0``) so whitespace-only values
        (e.g. ``"   "``) are rejected before reaching the comparison.
        Belt-and-suspenders against the same bug class the coalesce
        removal prevents."""
        src = self._src()
        # Q2 outer
        step2_idx = src.find("[LINK] 2/12 Malware → ThreatActor")
        step3_idx = src.find("[LINK] 3a/12", step2_idx)
        q2_block = src[step2_idx:step3_idx]
        assert "size(trim(m.attributed_to)) > 0" in q2_block, (
            "Q2 outer must filter with size(trim(m.attributed_to)) > 0"
        )

        # Q9 outer + skip
        q9_start = src.find("[LINK] 9/12")
        q10_start = src.find("[LINK] 10/12")
        q9_block = src[q9_start:q10_start]
        # Q9 outer and skip both need the hardened form
        assert q9_block.count("size(trim(i.malware_family)) > 0") >= 2, (
            "Q9 outer AND skip-query must both filter with size(trim(i.malware_family)) > 0"
        )

    def test_no_bare_tolower_on_attributed_to_or_malware_family_in_match_clauses(self):
        """Regression pin: bare ``toLower(m.attributed_to)`` (without
        trim()) must NOT appear in the Q2 or Q9 inner/skip blocks."""
        src = self._src()
        # Restrict search to the Q2/Q9 blocks
        step2_idx = src.find("[LINK] 2/12")
        step3_idx = src.find("[LINK] 3a/12")
        step9_start = src.find("[LINK] 9/12")
        step10_idx = src.find("[LINK] 10/12")

        q2_block = src[step2_idx:step3_idx]
        q9_block = src[step9_start:step10_idx]

        for block, name in [(q2_block, "Q2"), (q9_block, "Q9")]:
            # The bare form with no trim() is what we want to prevent
            # (``toLower(m.attributed_to)`` or ``toLower(i.malware_family)``
            # directly, not through a trim wrapper).
            assert "toLower(m.attributed_to)" not in block, (
                f"{name} regression: bare toLower(m.attributed_to) must not return — wrap in trim()"
            )
            # Note: toLower(i.malware_family) appears inside the list-
            # comprehension `[x IN coalesce(...) | toLower(trim(x))]` where
            # x is the list element, not `i.malware_family` directly. The
            # outer comparison must use trim(). Check for the exact bad form:
            assert "toLower(i.malware_family)" not in block.replace("toLower(trim(i.malware_family))", ""), (
                f"{name} regression: bare toLower(i.malware_family) must not return — wrap in trim()"
            )


# ===========================================================================
# Cross-cutting: module imports cleanly
# ===========================================================================


class TestModuleImportsCleanly:
    def test_build_relationships_imports(self):
        import build_relationships  # noqa: F401

    def test_enrichment_jobs_imports(self):
        import enrichment_jobs  # noqa: F401
