"""
PR-M3d — Campaign PART_OF determinism + c.zone stability.

Closes TWO findings that share a root cause (non-deterministic
``collect(DISTINCT i)[0..100]``):

## §8-RI-S3-Camp (CRITICAL) — Campaign PART_OF monotonic growth

``build_campaign_nodes`` Step 3 used ``collect(i)[0..100]`` returning
the first 100 indicators in Neo4j's internal (non-deterministic)
iteration order.  Combined with MERGE's no-delete semantic, PART_OF
edges accumulated across runs: run N attached {i1..i100}, run N+1
attached {i17..i116}, old 16 kept their edges forever.  After 730
daily enrichment runs, a ThreatActor with 10k active indicators had
EVERY single one wired via PART_OF — defeating the 100-cap.

## §5-MD-C2 (CRITICAL) — c.zone flapping

Same root cause. Step 1 computed ``c.zone`` from
``collect(DISTINCT i)[0..100]`` → non-deterministic subset of zones.
``c.zone`` flipped between ``["healthcare"]`` on run 1 and
``["healthcare","energy"]`` on run 2 for the same Campaign.

## Fix

Three-part:
1. **Step 1:** compute ``all_zones`` from the FULL active-indicator
   set (no ``[0..100]`` slice).  Deterministic + semantically correct.
2. **Step 3a:** add ``ORDER BY i.first_imported_at DESC, i.value ASC``
   before ``collect(i)[0..100]`` so top-100 is stable across runs.
   Stamp ``r.updated_at = datetime()`` on every MERGE (freshness
   marker for pruning).
3. **Step 3b (NEW):** delete PART_OF edges whose ``r.updated_at``
   predates the run's start (``$run_start_at``) — they're the
   displaced-from-top-100 residue.  ``$run_start_at`` captured in
   Python at function start.

## Test strategy

Source-pin the three fix sites + behavioral test with mocked Neo4j
driver for the prune step's `$run_start_at` param.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# §5-MD-C2 — c.zone computed from full set, not sample
# ===========================================================================


class TestCampaignZoneComputedFromFullSet:
    """``c.zone`` MUST be computed by reducing over the FULL active-
    indicator set, not over a non-deterministic 100-sample."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_step1_uses_all_indicators_for_zone_reduction(self, source: str) -> None:
        """Step 1's MERGE block must compute zones from
        ``reduce(z=[], ind IN all_indicators | ...)`` — iterating the
        full active set — not from ``indicator_sample[0..100]``."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]

        # The reduce over all_indicators must be present
        assert "reduce(z=[], ind IN all_indicators | z + coalesce(ind.zone, []))" in body, (
            "PR-M3d §5-MD-C2: c.zone must be computed by reducing over "
            "``all_indicators`` (the FULL active set), not over a 100-sample. "
            "The old ``indicator_sample[0..100]`` path was non-deterministic."
        )

    def test_step1_old_indicator_sample_slice_is_gone(self, source: str) -> None:
        """The ``collect(DISTINCT i)[0..100] AS indicator_sample`` pattern
        (non-deterministic 100-sample in Step 1) must be absent from the
        active Cypher. Comments explaining what was removed are fine."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        # Strip comment-only Cypher lines (// ...) and Python comments (#)
        # before checking.  Simple heuristic: active Cypher lines contain
        # the pattern and are NOT inside a # comment.
        active_lines = [
            line for line in body.splitlines() if not line.lstrip().startswith("#") and "//" not in line.strip()[:3]
        ]
        active = "\n".join(active_lines)
        assert "collect(DISTINCT i)[0..100] AS indicator_sample" not in active, (
            "old Step 1 indicator_sample slice must not return as active Cypher"
        )


# ===========================================================================
# §8-RI-S3-Camp — PART_OF edges deterministic + pruned
# ===========================================================================


class TestPartOfEdgesDeterministic:
    """Step 3a MUST order indicators deterministically before the
    ``[0..100]`` slice so the same graph state always produces the
    same top-100."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "enrichment_jobs.py").read_text()

    def test_step3_has_order_by_before_collect(self, source: str) -> None:
        """The ``ORDER BY i.first_imported_at DESC, i.value ASC``
        clause MUST appear between the WHERE filter and the
        ``collect(i)[0..100]`` slice."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        # Look for link_indicators query
        assert "link_indicators = " in body
        li_start = body.find("link_indicators = ")
        li_end = body.find('"""', li_start + 20)  # end of triple-quoted block
        # Skip the opening triple-quote to find the real end
        li_end = body.find('"""', li_end + 3)
        link_block = body[li_start:li_end]
        assert "ORDER BY i.first_imported_at DESC, i.value ASC" in link_block, (
            "Step 3 must sort deterministically before the 100-slice"
        )
        # Ensure the ORDER BY comes BEFORE the collect
        order_idx = link_block.find("ORDER BY i.first_imported_at")
        collect_idx = link_block.find("collect(i)[0..100]")
        assert order_idx < collect_idx, "ORDER BY must precede collect(i)[0..100]"

    def test_step3a_stamps_r_updated_at(self, source: str) -> None:
        """Every PART_OF MERGE MUST stamp ``r.updated_at = datetime()``
        so Step 3b can use it as the freshness marker."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        li_idx = body.find("link_indicators = ")
        # The link_indicators query block extends roughly 2KB.
        link_block = body[li_idx : li_idx + 2000]
        assert "r.updated_at = datetime()" in link_block, (
            "Step 3a MERGE must stamp r.updated_at so Step 3b can prune stale edges"
        )

    def test_step3b_prune_query_exists(self, source: str) -> None:
        """Step 3b MUST delete PART_OF edges whose ``r.updated_at``
        predates ``$run_start_at`` (or is NULL for pre-fix edges)."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert "prune_indicators = " in body, "Step 3b prune query must be defined"
        pi_idx = body.find("prune_indicators = ")
        prune_block = body[pi_idx : pi_idx + 1000]
        # WHERE clause with the freshness marker check
        assert "r.updated_at IS NULL OR r.updated_at < $run_start_at" in prune_block, (
            "prune must gate on r.updated_at < $run_start_at (with NULL-tolerant branch for pre-fix edges)"
        )
        # DELETE keyword
        assert "DELETE r" in prune_block

    def test_function_captures_run_start_at(self, source: str) -> None:
        """The Python function MUST capture ``run_start_at`` before
        any Cypher executes so the prune query can filter edges
        stamped DURING the run from edges stamped BEFORE."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert "run_start_at = datetime.now(timezone.utc).isoformat()" in body, (
            "run_start_at must be captured with datetime.now(timezone.utc) for UTC+ISO-8601 format"
        )
        # Must pass to prune query
        assert "run_start_at=run_start_at" in body, "prune query must receive run_start_at parameter"

    def test_results_includes_links_pruned(self, source: str) -> None:
        """Operator-facing: the results dict should report prune count
        alongside links_created so a 730d baseline can see both."""
        start = source.find("def build_campaign_nodes")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert 'results["links_pruned"]' in body


# ===========================================================================
# Behavioral test: prune query receives correct params
# ===========================================================================


class TestPruneQueryReceivesRunStartAt:
    """Mocked-driver behavioral test: assert that the prune query is
    called with ``run_start_at`` as an ISO string in UTC."""

    def test_prune_query_called_with_run_start_at(self, monkeypatch):
        """Drive ``build_campaign_nodes`` with a mocked driver and
        verify the prune query's params include ``run_start_at`` in
        ISO-8601 UTC format."""
        import enrichment_jobs

        # Mock session + driver
        queries_captured: list = []

        def capture_run(query, **kwargs):
            queries_captured.append((query, kwargs))
            result = MagicMock()
            # Return a row with 0 for every aggregate
            result.single.return_value = {
                "backfilled": 0,
                "links": 0,
                "pruned": 5,  # non-zero so the "pruned X" log fires
                "count": 0,
                "campaigns": 0,
            }
            # For queries that return iterable results (qualifying_actors_query)
            result.__iter__ = lambda s: iter([])
            return result

        session = MagicMock()
        session.run = capture_run
        session.__enter__ = lambda s: s
        session.__exit__ = lambda *a: False

        fake_client = MagicMock()
        fake_client.driver = MagicMock()
        fake_client.driver.session.return_value = session

        # Also mock query_pause so it's a no-op
        monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)

        enrichment_jobs.build_campaign_nodes(fake_client)

        # Find the prune query in captured calls
        prune_calls = [
            (query, kwargs) for query, kwargs in queries_captured if "DELETE r" in query and "PART_OF" in query
        ]
        assert prune_calls, (
            f"expected a prune query (MATCH PART_OF + DELETE r); got queries: {[q[:80] for q, _ in queries_captured]}"
        )

        _, prune_kwargs = prune_calls[0]
        assert "run_start_at" in prune_kwargs, (
            f"prune query must receive run_start_at kwarg; got {list(prune_kwargs.keys())}"
        )
        run_start_at = prune_kwargs["run_start_at"]
        assert isinstance(run_start_at, str)
        # ISO-8601 UTC format
        assert "+00:00" in run_start_at or run_start_at.endswith("Z"), (
            f"run_start_at must be ISO with UTC offset; got {run_start_at!r}"
        )
