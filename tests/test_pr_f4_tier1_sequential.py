"""
Regression tests for PR-F4 — tier1_core baseline collectors are sequential.

Background
----------

The 2026-04-19 overnight 730-day baseline run (manual run started
~22:47 UTC) lost ~14.7% of NVD attributes (13,620 of 92,620) to MISP
HTTP 500 errors. Bravo's investigation traced the failure to PHP-FPM
worker exhaustion in MISP's ``AppModel.php`` under concurrent-write
load when all four tier-1 collectors hammered MISP simultaneously.

PR-F4 sequences the four tier-1 collectors (CISA → MITRE → OTX → NVD)
inside the ``tier1_core`` TaskGroup so MISP only ever sees one
heavy-write source at a time. Order rationale: small collectors first
(CISA ~14s, MITRE ~28s) so a chain-wide failure surfaces in <1 minute
rather than after sinking ~3-5 hours into OTX or NVD.

What this DOES NOT fix
----------------------

The per-event-grows-with-size cost on a single oversized MISP event.
``edit-event`` loads the entire event for dedup; cost grows linearly
with existing attribute count. That's an architectural fix tracked
separately — event partitioning by date range so no single event
exceeds ~20K attributes.

What these tests pin
--------------------

  - The four tier-1 task IDs still exist (``collect_cisa``,
    ``collect_mitre``, ``collect_otx``, ``collect_nvd``)
  - The dependency edges are present in the SOURCE in the right order
  - Tier-2 stays parallel (no edges added between tier-2 tasks)
  - The DAG-level dependency-chain comment + module docstring still
    reference the new ordering (so future readers don't re-introduce
    the parallel pattern by accident)

These tests are SOURCE-PINS rather than runtime-loaded DAG inspections
on purpose — the runtime path requires importing Airflow at test time,
which is heavier than necessary to pin a one-line dependency contract.
The matching ``test_baseline_dag_timeouts.py`` already does the same
pattern for execution_timeout assertions.
"""

from __future__ import annotations

import re

DAG_PATH = "dags/edgeguard_pipeline.py"


def _read_dag_source() -> str:
    with open(DAG_PATH) as fh:
        return fh.read()


def _tier1_block(src: str) -> str:
    """Extract just the ``tier1_core`` TaskGroup body (from the
    ``with TaskGroup(...)`` line to the next blank line followed by
    a top-level ``# Tier 2`` comment)."""
    start = src.find('with TaskGroup("tier1_core"')
    assert start > 0, "tier1_core TaskGroup not found in DAG source"
    end = src.find("# Tier 2", start)
    assert end > start, "could not find tier2 boundary after tier1_core"
    return src[start:end]


# ---------------------------------------------------------------------------
# Sequential dependency chain inside tier1_core
# ---------------------------------------------------------------------------


class TestTier1SequentialChain:
    def test_all_four_tier1_collectors_still_defined(self):
        """The four collector task IDs MUST still exist — the change
        is only in their dependency edges, not their identities."""
        block = _tier1_block(_read_dag_source())
        for task_id in ("collect_cisa", "collect_mitre", "collect_otx", "collect_nvd"):
            assert f'task_id="{task_id}"' in block, f"tier1_core lost the {task_id} task"

    def test_sequential_chain_present_in_source(self):
        """The dependency chain ``cisa >> mitre >> otx >> nvd`` (in that
        exact order) MUST be present inside the tier1_core TaskGroup.

        We accept either the compact one-liner or a multi-line variant
        with extra whitespace — the contract is the directional ordering.
        """
        block = _tier1_block(_read_dag_source())
        # Normalize whitespace so the regex matches both the one-liner
        # and any future multi-line variants.
        normalized = re.sub(r"\s+", " ", block)
        assert re.search(
            r"bl_cisa\s*>>\s*bl_mitre\s*>>\s*bl_otx\s*>>\s*bl_nvd",
            normalized,
        ), "PR-F4 contract: tier1 collectors must be chained cisa >> mitre >> otx >> nvd inside tier1_core"

    def test_no_unintended_parallel_chains_remain(self):
        """Defensive: no ``[bl_otx, bl_nvd, ...]`` list-form parallel
        spec should be left over (would create a hidden parallel edge
        that contradicts the sequential chain)."""
        block = _tier1_block(_read_dag_source())
        # Look for any list-of-bl_* expression that would represent
        # parallel scheduling (e.g. ``[bl_otx, bl_nvd] >> ...`` or
        # ``... >> [bl_otx, bl_nvd]``)
        list_form = re.findall(r"\[\s*bl_(?:otx|nvd|cisa|mitre)[^\]]*\]", block)
        assert not list_form, (
            f"found leftover parallel-list form for tier1 collectors: {list_form!r} — "
            "PR-F4 requires the chain form (cisa >> mitre >> otx >> nvd)"
        )


# ---------------------------------------------------------------------------
# Tier 2 stays parallel (defensive — make sure we didn't accidentally
# serialize tier2 too)
# ---------------------------------------------------------------------------


class TestTier2StaysParallel:
    """Bravo's analysis: tier2 feeds (~6 collectors, each <5K attrs) are
    individually tiny and don't trigger the oversized-event failure mode.
    Their parallel write pressure on MISP is negligible. Keep them parallel."""

    def test_no_sequential_chain_among_tier2_tasks(self):
        src = _read_dag_source()
        start = src.find('with TaskGroup(\n    "tier2_feeds"')
        if start < 0:
            # Tolerate the one-line variant
            start = src.find('with TaskGroup("tier2_feeds"')
        assert start > 0, "tier2_feeds TaskGroup not found"
        end = src.find("baseline_full_sync_task", start)
        assert end > start
        block = src[start:end]
        # The 6 tier2 task IDs MUST exist.
        for task_id in (
            "collect_abuseipdb",
            "collect_threatfox",
            "collect_urlhaus",
            "collect_cybercure",
            "collect_feodo",
            "collect_sslblacklist",
        ):
            assert f'task_id="{task_id}"' in block, f"tier2_feeds lost {task_id}"
        # No ``bl_<tier2> >> bl_<tier2>`` chain edges expected.
        normalized = re.sub(r"\s+", " ", block)
        chain = re.search(
            r"bl_(?:abuseipdb|threatfox|urlhaus|cybercure|feodo|sslblacklist)"
            r"\s*>>\s*"
            r"bl_(?:abuseipdb|threatfox|urlhaus|cybercure|feodo|sslblacklist)",
            normalized,
        )
        assert chain is None, (
            f"tier2 feeds should remain parallel; found a sequential edge: {chain.group(0)!r}. "
            "PR-F4 sequenced tier1 only — tier2 stays parallel per the design."
        )


# ---------------------------------------------------------------------------
# Comment + docstring traceability — keep the rationale discoverable so
# the next maintainer doesn't re-introduce parallel scheduling thinking
# "why isn't this parallel?"
# ---------------------------------------------------------------------------


class TestRationaleIsDiscoverable:
    def test_dependency_chain_comment_mentions_pr_f4(self):
        """The top-of-DAG dependency-chain comment must mention PR-F4
        and the new ordering so the next reader doesn't have to git-blame."""
        src = _read_dag_source()
        # The comment block above the final ``baseline_misp_health >> ...``
        # chain must reference PR-F4 and the sequential ordering.
        idx = src.find("# Dependency chain")
        assert idx > 0
        end = src.find("(", idx + len("# Dependency chain"))
        # The PR reference + ordering note are within ~6 comment lines
        # of the start of the dependency-chain block.
        snippet = src[idx : idx + 600]
        assert "PR-F4" in snippet, "dependency-chain comment must reference PR-F4"
        assert "sequential" in snippet.lower() or "serial" in snippet.lower(), (
            "dependency-chain comment must call out the sequential ordering"
        )

    def test_tier1_taskgroup_comment_explains_why(self):
        """The TaskGroup itself must carry a comment explaining the
        14.7% NVD-loss observation, so future readers see WHY the
        sequencing exists before they consider 'optimizing' it back
        to parallel."""
        src = _read_dag_source()
        block_idx = src.find('with TaskGroup("tier1_core"')
        assert block_idx > 0
        # Look at the ~2KB block ABOVE the TaskGroup line (inline comment)
        preceding = src[max(0, block_idx - 2500) : block_idx]
        assert "PR-F4" in preceding, "tier1_core needs a PR-F4 comment block above it"
        # The rationale should mention the actual incident metric so
        # future readers understand the cost of regressing this.
        assert "14.7" in preceding or "13,620" in preceding or "MISP" in preceding, (
            "tier1_core comment must reference the underlying MISP-write-pressure "
            "incident (the 14.7% NVD loss / PHP-FPM worker exhaustion)"
        )
