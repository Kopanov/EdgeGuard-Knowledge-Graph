"""
PR-L — tier-1 sequential-execution robustness regression suite.

Builds on ``tests/test_pr_f4_tier1_sequential.py`` (which pins the
baseline DAG's ``bl_cisa >> bl_mitre >> bl_otx >> bl_nvd`` chain and
the ``ALL_DONE`` trigger-rule rationale). This file pins the **broader
invariants** that must ALSO hold for the tier-1 serial mitigation to
actually protect MISP from PHP-FPM exhaustion during a 730-day
baseline:

1. **CLI baseline path (`run_pipeline.py --baseline`) stays sequential.**
   The baseline CLI uses a plain Python ``for`` loop over collectors;
   no ``ThreadPool`` / ``asyncio.gather`` / ``concurrent.futures``
   that could re-parallelize writes to MISP.

2. **`MISPWriter.push_items` has zero internal concurrency primitives.**
   All write-path fan-out is nested synchronous loops with an explicit
   inter-batch throttle. A future refactor that adds a ``ThreadPool``
   here would silently reintroduce the 4-way concurrent MISP writes
   that caused 14.7% NVD loss on 2026-04-19.

3. **Incremental DAGs do NOT run multiple tier-1 collectors in
   parallel.** ``edgeguard_daily`` and ``edgeguard_medium_freq``
   currently DO (``MITRE`` alongside 6 tier-2 in parallel; ``CISA``
   alongside ``VT`` in parallel). Those paths fire during a 730-day
   baseline and reintroduce the concurrency pattern PR-F4 was supposed
   to eliminate. The tests covering this gap are marked
   ``@pytest.mark.xfail`` with a clear reason + follow-up reference,
   so CI stays green AND the test suite documents the gap. When the
   gap is closed, the xfails auto-promote to xpass and CI surfaces
   that the fix has landed — time to flip the marker off.

4. **`baseline_lock` sentinel coverage under the DAG path.** CLI
   ``--baseline`` acquires the sentinel (``run_pipeline.py:1077``);
   the DAG-triggered baseline does NOT (de-scoped to Issue #57 per
   ``dags/edgeguard_pipeline.py:2656-2679``). Incremental DAGs check
   ``baseline_skip_reason()`` which reads a sentinel nothing writes
   on the DAG path → they do NOT skip during a DAG-triggered 730-day
   baseline. Marked ``@pytest.mark.xfail`` with the Issue #57 pointer.

The goal: invariants we VERIFIED hold must stay holding; invariants
we VERIFIED don't hold are documented with an explicit xfail so the
test suite is the source of truth for "what's robust and what isn't."

See ``docs/flow_audits/`` for the full audit findings that motivated
these invariants.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DAG_PATH = REPO_ROOT / "dags" / "edgeguard_pipeline.py"
CLI_PATH = REPO_ROOT / "src" / "run_pipeline.py"
MISP_WRITER_PATH = REPO_ROOT / "src" / "collectors" / "misp_writer.py"


def _read(path: Path) -> str:
    return path.read_text()


# ---------------------------------------------------------------------------
# 1. CLI baseline path stays sequential (no ThreadPool / asyncio concurrency)
# ---------------------------------------------------------------------------


class TestCliBaselineLoopStaysSequential:
    """``run_pipeline.py`` drives the CLI ``--baseline`` path. The
    collector iteration MUST stay a plain synchronous ``for`` loop
    so a CLI-run 730-day baseline can't re-introduce concurrent
    MISP writes.

    A future "optimization" that adds ``concurrent.futures.ThreadPoolExecutor``
    or ``asyncio.gather`` to speed up the collector dispatch would
    silently recreate the 2026-04-19 failure mode. These tests pin
    against that class of regression."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return _read(CLI_PATH)

    def test_run_pipeline_has_no_threadpool_executor(self, source: str) -> None:
        """``ThreadPoolExecutor`` / ``ProcessPoolExecutor`` / bare
        ``Thread`` imports would indicate a future refactor has
        added concurrency to the baseline path."""
        # Strip comments so a cautionary mention in a docstring doesn't
        # trigger the pin. We only reject ACTIVE use.
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        assert "ThreadPoolExecutor" not in code, (
            "run_pipeline.py must not use ThreadPoolExecutor — the baseline CLI "
            "path MUST stay single-threaded to preserve PR-F4's MISP concurrency "
            "guarantee (cuts 4 concurrent writers to 1)."
        )
        assert "ProcessPoolExecutor" not in code
        assert "concurrent.futures" not in code

    def test_run_pipeline_has_no_asyncio_gather(self, source: str) -> None:
        """``asyncio.gather`` / ``asyncio.TaskGroup`` would spawn
        concurrent awaitables; pin against their introduction."""
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        assert "asyncio.gather" not in code
        assert "asyncio.TaskGroup" not in code

    def test_run_pipeline_has_no_bare_threading_thread(self, source: str) -> None:
        """Raw ``Thread(target=...)`` would also break the guarantee."""
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        # Match ``threading.Thread(`` and ``from threading import Thread``.
        assert "threading.Thread" not in code, "run_pipeline.py must not spawn raw threads for collector dispatch"
        assert not re.search(r"\bfrom\s+threading\s+import\s+Thread\b", code)

    def test_baseline_acquires_lock_sentinel(self, source: str) -> None:
        """The CLI path ``--baseline`` MUST call ``acquire_baseline_lock()``
        before running collectors. This is the sentinel that incremental
        DAGs check via ``baseline_skip_reason()``. Without it, scheduled
        incrementals race the baseline — same failure mode as the DAG
        path gap (see Issue #57)."""
        assert "acquire_baseline_lock" in source, (
            "run_pipeline.py --baseline must acquire the baseline_lock "
            "sentinel so incremental DAGs correctly skip via "
            "baseline_skip_reason()"
        )
        # And the release call must be present too.
        assert "release_baseline_lock" in source


# ---------------------------------------------------------------------------
# 2. MISPWriter.push_items has no internal concurrency
# ---------------------------------------------------------------------------


class TestPushItemsHasNoInternalConcurrency:
    """The MISP write fan-out in ``push_items`` is the exact code path
    PR-F4 sequenced. Internal re-parallelism here would defeat the
    entire mitigation — the TaskGroup chain would schedule one
    collector at a time, but that one collector would then fan out
    concurrent writes internally, reproducing the original failure.
    """

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return _read(MISP_WRITER_PATH)

    def test_push_items_has_no_threadpool(self, source: str) -> None:
        """No concurrent-execution primitive may appear in the MISP
        write module."""
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        for forbidden in (
            "ThreadPoolExecutor",
            "ProcessPoolExecutor",
            "concurrent.futures",
            "asyncio.gather",
            "asyncio.TaskGroup",
            "threading.Thread",
        ):
            assert forbidden not in code, (
                f"misp_writer.py must not introduce {forbidden} — doing so would "
                "reintroduce concurrent MISP writes and defeat PR-F4's tier-1 "
                "sequential mitigation."
            )

    def test_push_items_retains_inter_batch_throttle(self, source: str) -> None:
        """The ``EDGEGUARD_MISP_BATCH_THROTTLE_SEC`` sleep between
        batches MUST remain — it's the second layer of MISP protection
        (first layer = tier-1 serial, second layer = per-batch pause)."""
        assert "EDGEGUARD_MISP_BATCH_THROTTLE_SEC" in source, "the inter-batch throttle env var must stay in place"


# ---------------------------------------------------------------------------
# 3. Baseline DAG sentinel gap — documented via xfail
# ---------------------------------------------------------------------------


class TestBaselineLockSentinelCoverage:
    """The CLI ``--baseline`` path acquires the sentinel. The DAG
    ``edgeguard_baseline`` path does NOT (de-scoped in PR-F2 for the
    architectural reasons Issue #57 documents). Incremental DAGs
    check ``baseline_skip_reason()`` → they're skipped during CLI
    baselines but NOT during DAG baselines.

    Tests that currently hold are asserted normally. The known gap
    is marked xfail with a clear pointer to Issue #57 — when that
    lands, this xfail flips to xpass and CI tells us to remove the
    marker.
    """

    @pytest.fixture(scope="class")
    def dag_source(self) -> str:
        return _read(DAG_PATH)

    def test_incremental_dags_check_baseline_skip_reason(self, dag_source: str) -> None:
        """Every incremental DAG task body MUST call
        ``baseline_skip_reason()`` so the sentinel coverage has a
        reader. This is what makes the CLI-path sentinel acquisition
        effective in the first place.

        The function itself is defined in ``src/baseline_lock.py``;
        the DAG imports + calls it. Verify the USAGE in the DAG,
        and verify the DEFINITION lives in the expected module."""
        assert "baseline_skip_reason" in dag_source, (
            "at least one DAG task must read baseline_skip_reason() "
            "for the CLI-path sentinel mechanism to actually skip "
            "incrementals"
        )
        # Verify the function is defined in the canonical location so
        # the import resolves correctly. `baseline_skip_reason` lives
        # in `src/baseline_lock.py`.
        lock_module = REPO_ROOT / "src" / "baseline_lock.py"
        assert lock_module.exists(), "src/baseline_lock.py must exist"
        lock_src = lock_module.read_text()
        assert "def baseline_skip_reason" in lock_src, (
            "baseline_skip_reason must remain defined in src/baseline_lock.py"
        )

    @pytest.mark.xfail(
        reason=(
            "Issue #57: DAG-triggered baseline does NOT acquire baseline_lock "
            "sentinel (the Airflow-side lock-task pair was de-scoped in PR-F2 "
            "after Bugbot caught two architectural flaws in the PID-based "
            "primitive). Known gap — during a DAG-triggered 730-day baseline, "
            "incremental DAGs do NOT skip. Interim mitigation: use CLI "
            "`python src/run_pipeline.py --baseline` OR pre-pause the "
            "scheduled incremental DAGs in Airflow. See "
            "dags/edgeguard_pipeline.py:2656-2679 for the de-scope note."
        ),
        strict=True,
    )
    def test_baseline_dag_acquires_sentinel(self, dag_source: str) -> None:
        """When Issue #57 lands, the ``edgeguard_baseline`` DAG will
        have a task that calls ``acquire_baseline_lock()``. Until
        then this is a known gap; test xfails. When it flips to
        xpass, remove the marker.

        Comment-stripping is critical: the DAG currently has a
        comment block that literally includes the string
        ``acquire_baseline_lock()`` while explaining what was
        de-scoped. We must check ONLY live code, not prose."""
        # Scope: ONLY the edgeguard_baseline DAG body.
        baseline_idx = dag_source.find('DAG(\n    "edgeguard_baseline"')
        if baseline_idx < 0:
            baseline_idx = dag_source.find('DAG("edgeguard_baseline"')
        assert baseline_idx > 0, "edgeguard_baseline DAG declaration not found"
        tail = dag_source[baseline_idx:]
        # Strip comment lines so the de-scope note doesn't satisfy the
        # check. The code must have an ACTIVE call to acquire_baseline_lock().
        code_only = "\n".join(line for line in tail.splitlines() if not line.lstrip().startswith("#"))
        assert "acquire_baseline_lock()" in code_only, (
            "Issue #57 fix: the baseline DAG should have a task calling "
            "acquire_baseline_lock() so incremental DAGs skip correctly "
            "during a DAG-triggered 730-day baseline. Comment-only "
            "mentions don't count — need an actual call."
        )


# ---------------------------------------------------------------------------
# 4. Incremental DAGs don't run tier-1 collectors in parallel — xfail
#    documents the current gap
# ---------------------------------------------------------------------------


class TestIncrementalDagsNoTier1Parallel:
    """PR-F4 sequentialized tier-1 INSIDE the baseline DAG. But other
    DAGs still run tier-1 collectors. Verification found two gaps:

    - ``edgeguard_daily`` fans MITRE + 6 tier-2 as 7 parallel branches
      (dags/edgeguard_pipeline.py:1557-1569). MITRE is tier-1.
    - ``edgeguard_medium_freq`` runs CISA + VT in 2 parallel branches
      (line 1425). CISA is tier-1.

    Both fire during a 26-hour 730-day baseline. The current test
    xfails on these; when the gaps are closed (either by sequencing
    them or pre-pausing them operationally), the xfail flips to xpass.

    Tier-1 task IDs (per PR-F4): ``collect_cisa``, ``collect_mitre``,
    ``collect_otx``, ``collect_nvd``.
    """

    @pytest.fixture(scope="class")
    def dag_source(self) -> str:
        return _read(DAG_PATH)

    def test_baseline_dag_tier1_is_serial(self, dag_source: str) -> None:
        """Sanity: the existing baseline-DAG test already covers this,
        but we re-assert here under the robustness-suite framing.

        PR-L Bugbot round-1 (Low): the boundary marker ``# Tier 2``
        MUST exist — if it's removed or renamed, ``find`` returns
        ``-1`` and the regex matches anywhere downstream, making
        the test pass vacuously. The boundary assertion mirrors the
        pattern used in ``test_pr_f4_tier1_sequential.py``."""
        # Find the tier1_core block.
        start = dag_source.find('with TaskGroup("tier1_core"')
        assert start > 0, "tier1_core TaskGroup not found in DAG source"
        end = dag_source.find("# Tier 2", start)
        assert end > start, (
            "could not find '# Tier 2' boundary after tier1_core — without "
            "a valid end boundary, the regex below would match anywhere in "
            "the rest of the file and pass vacuously"
        )
        block = dag_source[start:end]
        normalized = re.sub(r"\s+", " ", block)
        assert re.search(
            r"bl_cisa\s*>>\s*bl_mitre\s*>>\s*bl_otx\s*>>\s*bl_nvd",
            normalized,
        ), "baseline DAG tier1_core must stay cisa >> mitre >> otx >> nvd (PR-F4)"

    @pytest.mark.xfail(
        reason=(
            "edgeguard_daily fans MITRE + 6 tier-2 collectors as 7 parallel "
            "branches (dags/edgeguard_pipeline.py:1557-1569). MITRE is a "
            "tier-1 collector per PR-F4. During a 730-day baseline, this "
            "daily DAG fires ~1x and reintroduces 7-way concurrent MISP "
            "writes — the same pattern that caused 14.7% NVD loss on "
            "2026-04-19. When this gap is closed (sequencing MITRE "
            "ahead of the tier-2 parallel OR pre-pausing the daily DAG), "
            "the test will xpass. See docs/flow_audits/01_baseline_sequence.md "
            "for the broader context."
        ),
        strict=True,
    )
    def test_edgeguard_daily_does_not_run_mitre_parallel_to_tier2(self, dag_source: str) -> None:
        """``edgeguard_daily`` MUST NOT schedule ``collect_mitre`` as a
        sibling of the tier-2 parallel fan-out."""
        # Find the edgeguard_daily DAG body.
        daily_idx = dag_source.find('DAG(\n    "edgeguard_daily"')
        if daily_idx < 0:
            daily_idx = dag_source.find('DAG("edgeguard_daily"')
        assert daily_idx > 0, "edgeguard_daily DAG not found"
        # Next DAG boundary or end-of-file.
        next_dag = dag_source.find("DAG(", daily_idx + 1)
        if next_dag < 0:
            next_dag = len(dag_source)
        body = dag_source[daily_idx:next_dag]
        # Look for a parallel-list-form expression that includes
        # collect_mitre alongside any tier-2 task.
        tier2_task_ids = {
            "collect_abuseipdb",
            "collect_threatfox",
            "collect_urlhaus",
            "collect_cybercure",
            "collect_feodo",
            "collect_sslblacklist",
        }
        # Any ``[..., daily_mitre_task_var, ...]`` list that also
        # contains a tier-2 task variable indicates parallel tier-1+2.
        # Strategy: find any list containing multiple task-variable-like
        # identifiers and check if it mixes a mitre-ish name with a
        # tier-2-ish name.
        list_exprs = re.findall(r"\[([^\]]+)\]", body)
        for expr in list_exprs:
            has_mitre = "mitre" in expr.lower()
            has_tier2 = any(t.replace("collect_", "") in expr.lower() for t in tier2_task_ids)
            assert not (has_mitre and has_tier2), (
                f"edgeguard_daily has a parallel list mixing MITRE with tier-2: {expr!r}"
            )

    @pytest.mark.xfail(
        reason=(
            "edgeguard_medium_freq runs CISA + VirusTotal in 2-way parallel "
            "(dags/edgeguard_pipeline.py:1425). CISA is a tier-1 collector. "
            "Every 4h this reintroduces 2-way concurrent MISP writes. "
            "Lower volume than the daily-DAG gap but still against PR-F4's "
            "'one-writer' intent. When CISA is sequenced ahead of VT (or "
            "the DAG is paused during baselines), this test xpasses. "
            "See docs/flow_audits/01_baseline_sequence.md."
        ),
        strict=True,
    )
    def test_edgeguard_medium_freq_does_not_parallel_cisa_and_vt(self, dag_source: str) -> None:
        """``edgeguard_medium_freq`` MUST NOT schedule ``collect_cisa``
        (or ``collect_cisa_medium``) in parallel with ``collect_vt``
        (or ``collect_vt_medium``)."""
        medium_idx = dag_source.find('DAG(\n    "edgeguard_medium_freq"')
        if medium_idx < 0:
            medium_idx = dag_source.find('DAG("edgeguard_medium_freq"')
        assert medium_idx > 0, "edgeguard_medium_freq DAG not found"
        next_dag = dag_source.find("DAG(", medium_idx + 1)
        if next_dag < 0:
            next_dag = len(dag_source)
        body = dag_source[medium_idx:next_dag]
        # Find any list expression with cisa + vt in it.
        list_exprs = re.findall(r"\[([^\]]+)\]", body)
        for expr in list_exprs:
            lower = expr.lower()
            if "cisa" in lower and "vt" in lower:
                raise AssertionError(
                    f"edgeguard_medium_freq runs CISA and VT in parallel: {expr!r} — "
                    "both are MISP writers; CISA is tier-1; this contradicts PR-F4's "
                    "'one writer to MISP at a time' intent."
                )


# ---------------------------------------------------------------------------
# 5. Documentation cross-reference
# ---------------------------------------------------------------------------


class TestDocumentationCrossReference:
    """Meta-test: the operator-facing docs must mention how to safely
    run a 730-day baseline given the known gaps. If the docs drift,
    operators won't know whether to use CLI or pre-pause DAGs."""

    def test_flow_audit_index_lists_tier1_findings(self) -> None:
        """The flow-audit index must call out the incremental-DAG
        parallel-tier-1 gap so operators see it alongside the other
        baseline risks."""
        index_path = REPO_ROOT / "docs" / "flow_audits" / "README.md"
        if not index_path.exists():
            pytest.skip("flow audit index not yet present; will land with PR-K")
        content = index_path.read_text()
        # It should mention the lock-missing issue (§1-1) by either Issue
        # number or by the finding ID.
        assert "#57" in content or "§1-1" in content, (
            "flow audit index should reference Issue #57 or finding §1-1 so operators see the baseline-lock gap"
        )
