"""
PR-M3c — §8-RI-S3-Q9: Co-occurrence ``r.source_ids`` accumulation.

## The bug

``src/build_relationships.py`` Q4 (Indicator→Malware co-occurrence)
stamps ``r.source_id = "misp_cooccurrence"`` on the INDICATES edge.
Q9 (malware_family match) later MERGEs the SAME edge and OVERWRITES
``r.source_id = "malware_family_match"`` — the last-writer-wins scalar
hides the co-occurrence provenance.  The calibrator
(``calibrate_cooccurrence_confidence``) filters on
``r.source_id IN ["misp_cooccurrence", "misp_correlation"]`` and
silently MISSES these edges, leaving them at 0.8 confidence instead of
the bulk-dump tier's 0.30-0.50.  Estimated 30-50% of INDICATES edges
on a 730-day baseline are affected.

## The fix

1. Every MERGE site that sets ``r.source_id = "<X>"`` ALSO sets
   ``r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["<X>"])``
   so every tag that has ever applied to the edge is preserved.
2. Calibrator filter becomes
   ``(r.source_ids IS NOT NULL AND any(s IN r.source_ids WHERE s IN [...]))
   OR r.source_id IN [...]`` — array match for post-fix edges; scalar
   fallback for pre-fix/legacy edges.
3. Scalar ``r.source_id`` writes kept for backwards compat with any
   legacy reader.

## Test strategy

Source-pin the fix sites (Q3a/Q3b/Q4/Q9 + calibrator small-event path +
calibrator apoc.periodic.iterate large-event path) so any future
regression that reintroduces the scalar-only filter or drops the
``r.source_ids`` accumulation fails loudly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# build_relationships.py — every source_id write site accumulates source_ids
# ===========================================================================


class TestBuildRelationshipsAccumulatesSourceIds:
    """Every MERGE site that sets ``r.source_id = "<X>"`` MUST also set
    ``r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["<X>"])``
    so the SAME edge MERGEd by a later query (the bug: Q9 overwriting Q4's
    scalar) cannot erase earlier provenance."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "build_relationships.py").read_text()

    def test_q3a_exploits_vuln_accumulates_cve_tag_match(self, source: str) -> None:
        """Q3a Indicator→Vulnerability EXPLOITS must accumulate
        ``"cve_tag_match"`` into ``r.source_ids``."""
        assert "_q3a_inner" in source
        q3a_idx = source.find("_q3a_inner")
        block = source[q3a_idx : q3a_idx + 1500]
        assert 'r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["cve_tag_match"])' in block, (
            "Q3a must accumulate cve_tag_match into r.source_ids (set-valued provenance)"
        )

    def test_q3b_exploits_cve_accumulates_cve_tag_match(self, source: str) -> None:
        """Q3b Indicator→CVE EXPLOITS must accumulate
        ``"cve_tag_match"`` into ``r.source_ids``."""
        assert "_q3b_inner" in source
        q3b_idx = source.find("_q3b_inner")
        block = source[q3b_idx : q3b_idx + 1500]
        assert 'r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["cve_tag_match"])' in block, (
            "Q3b must accumulate cve_tag_match into r.source_ids (set-valued provenance)"
        )

    def test_q4_cooccurrence_accumulates_misp_cooccurrence(self, source: str) -> None:
        """Q4 (the PRE-OVERWRITE site) must accumulate
        ``"misp_cooccurrence"`` into ``r.source_ids`` so Q9's later MERGE
        on the same edge cannot erase the co-occurrence tag."""
        assert "_q4_inner" in source
        q4_idx = source.find("_q4_inner")
        block = source[q4_idx : q4_idx + 2500]
        assert 'r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["misp_cooccurrence"])' in block, (
            "Q4 MUST accumulate misp_cooccurrence into r.source_ids — without "
            "this, Q9's later MERGE on the same edge hides the co-occurrence "
            "tag from the calibrator filter and ~30-50% of INDICATES edges "
            "on a 730d baseline stay at inflated 0.8 confidence."
        )

    def test_q9_malware_family_accumulates_malware_family_match(self, source: str) -> None:
        """Q9 (the OVERWRITE site — the bug origin) must accumulate
        ``"malware_family_match"`` into ``r.source_ids`` rather than
        ONLY writing the scalar ``r.source_id``."""
        assert "_q9_inner" in source
        q9_idx = source.find("_q9_inner")
        block = source[q9_idx : q9_idx + 2500]
        assert 'r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["malware_family_match"])' in block, (
            "Q9 MUST accumulate malware_family_match into r.source_ids. "
            "The scalar r.source_id write is kept (last-writer-wins legacy), "
            "but the set-valued r.source_ids is what the calibrator now uses."
        )

    def test_q4_and_q9_both_set_scalar_source_id_too(self, source: str) -> None:
        """Backwards compat: scalar ``r.source_id`` writes MUST remain on
        both Q4 and Q9 so legacy readers (and the calibrator's fallback
        branch) still work for edges stamped before the array rollout."""
        assert "_q4_inner" in source and "_q9_inner" in source
        q4_idx = source.find("_q4_inner")
        q4_block = source[q4_idx : q4_idx + 2500]
        assert 'r.source_id = "misp_cooccurrence"' in q4_block, (
            "Q4 MUST still set scalar r.source_id (legacy/fallback compat)"
        )
        q9_idx = source.find("_q9_inner")
        q9_block = source[q9_idx : q9_idx + 2500]
        assert 'r.source_id = "malware_family_match"' in q9_block, (
            "Q9 MUST still set scalar r.source_id (legacy/fallback compat)"
        )


# ===========================================================================
# enrichment_jobs.py — calibrator filter matches on source_ids with fallback
# ===========================================================================


class TestCalibratorFiltersOnSourceIdsArray:
    """The calibrator (``calibrate_cooccurrence_confidence``) MUST filter
    on ``r.source_ids`` (array) with a fallback to ``r.source_id`` (scalar,
    legacy edges) — NOT on the scalar alone."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_small_event_path_uses_source_ids_array(self, source: str) -> None:
        """The small-event ``update_cypher`` inside the tier loop must
        filter on ``any(s IN r.source_ids WHERE s IN [...])`` (with the
        NULL-safe guard) and fall back to the scalar for legacy edges."""
        start = source.find("def calibrate_cooccurrence_confidence")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert "update_cypher = " in body
        uc_idx = body.find("update_cypher = ")
        # Triple-quoted block <1500 chars
        block = body[uc_idx : uc_idx + 1500]
        # Must have the array match (with NULL guard) for post-fix edges
        assert "r.source_ids IS NOT NULL" in block, (
            "calibrator small-event path must guard r.source_ids IS NOT NULL before any()"
        )
        assert 'any(s IN r.source_ids WHERE s IN ["misp_cooccurrence", "misp_correlation"])' in block, (
            "calibrator small-event path must match on any(s IN r.source_ids WHERE s IN [...])"
        )
        # Must have scalar fallback for legacy edges
        assert 'r.source_id IN ["misp_cooccurrence", "misp_correlation"]' in block, (
            "calibrator must retain scalar r.source_id branch as a fallback for legacy edges"
        )

    def test_large_event_path_uses_source_ids_array(self, source: str) -> None:
        """The ``apoc.periodic.iterate`` batch for large (>1000-indicator)
        events must apply the same array-or-scalar filter inside the
        OUTER matcher."""
        start = source.find("def calibrate_cooccurrence_confidence")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert "large_batch_query = " in body, "large-event apoc.periodic.iterate query must exist"
        lbq_idx = body.find("large_batch_query = ")
        # Python-string-concat block <1500 chars
        block = body[lbq_idx : lbq_idx + 1500]
        # Array-match branch
        assert "r.source_ids IS NOT NULL" in block, (
            "calibrator large-event path must guard r.source_ids IS NOT NULL before any()"
        )
        assert 'any(s IN r.source_ids WHERE s IN ["misp_cooccurrence", "misp_correlation"])' in block, (
            "calibrator large-event path must match on any(s IN r.source_ids WHERE s IN [...])"
        )
        # Scalar fallback
        assert 'r.source_id IN ["misp_cooccurrence", "misp_correlation"]' in block, (
            "calibrator large-event path must retain scalar r.source_id branch (legacy fallback)"
        )


# ===========================================================================
# Negative pin — the pre-fix form (scalar-only filter) must not reappear
# ===========================================================================


class TestCalibratorScalarOnlyFilterIsGone:
    """Regression pin: a calibrator filter of ``WHERE r.source_id IN [...]``
    ALONE (no array branch, no OR) is the pre-fix form that silently
    exempts Q9-overwritten edges from calibration.  This test catches a
    future refactor that accidentally drops the array check."""

    def test_no_active_scalar_only_filter_line(self) -> None:
        """Scan the calibrator's source for any active (non-comment)
        line that matches ``WHERE r.source_id IN [...]`` WITHOUT an
        accompanying ``r.source_ids`` array match on the same line or
        the surrounding boolean expression.  If found, the pre-fix
        scalar-only filter has regressed."""
        source = (SRC / "enrichment_jobs.py").read_text()
        start = source.find("def calibrate_cooccurrence_confidence")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        # Heuristic: look for ``WHERE r.source_id IN`` (capital WHERE,
        # active Cypher) that does NOT appear next to ``source_ids``
        # in a small window.  Active cypher lines are NOT inside Python
        # ``#`` comments.
        for i, line in enumerate(body.splitlines()):
            stripped = line.lstrip()
            # Skip Python comment lines
            if stripped.startswith("#"):
                continue
            # The pre-fix scalar-only form would be a standalone
            # ``WHERE r.source_id IN [...]`` with NO array branch.
            # After PR-M3c, every such line is preceded/followed by a
            # ``r.source_ids`` match in the same boolean expression.
            if "WHERE r.source_id IN" in line and "source_ids" not in line:
                # Check the preceding line for an OR-continuation that
                # contains ``source_ids`` (spans two lines in the
                # update_cypher block).
                prev = body.splitlines()[i - 1] if i > 0 else ""
                if "source_ids" not in prev:
                    raise AssertionError(
                        f"Regression: scalar-only ``WHERE r.source_id IN [...]`` filter at "
                        f"line {i + 1}: {line.strip()!r}. "
                        f"This is the pre-fix form — it silently exempts Q9-overwritten "
                        f"edges from calibration. The array branch "
                        f"(``r.source_ids IS NOT NULL AND any(s IN r.source_ids ...)``) "
                        f"must accompany it."
                    )
