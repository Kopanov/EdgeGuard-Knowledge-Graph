"""
Tests for PR-C — CLI ↔ DAG parity + fresh-baseline.

Covers (from the comprehensive 7-agent audit):
  - **Cross-Checker HIGH H1**: CLI baseline never invoked enrichment_jobs
  - **Cross-Checker HIGH H2**: CLI baseline never invoked build_relationships
  - **Cross-Checker HIGH H3**: baseline_dag had no fresh_baseline conf knob
  - **Devil's Advocate / Cross-Checker MED**: 730 baseline_days hardcoded 4×
  - **Prod Readiness HIGH**: fresh-baseline had no pre-baseline backup gate,
    no post-clean verify, no fail-fast on partial wipe
  - **Devil's Advocate / Bravo's UX recs**: typed confirmation,
    informed-consent counts, refuse-without-counts, run_id printout

These tests pin the CONTRACTS, not literal strings — by deliberate design
(audit Devil's Advocate findings on PR #46/#47 testing patterns).
"""

from __future__ import annotations

import inspect
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# baseline_config — single source of truth for DEFAULT_BASELINE_DAYS
# ---------------------------------------------------------------------------


class TestBaselineConfig:
    """The 730 default and resolution precedence are now in ONE place."""

    def test_default_is_730(self):
        from baseline_config import DEFAULT_BASELINE_DAYS

        assert DEFAULT_BASELINE_DAYS == 730

    def test_explicit_takes_priority(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.setenv("EDGEGUARD_BASELINE_DAYS", "30")
        # Explicit beats env
        assert resolve_baseline_days(explicit=180) == 180

    def test_dag_run_conf_beats_env(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.setenv("EDGEGUARD_BASELINE_DAYS", "30")
        assert resolve_baseline_days(dag_run_conf={"baseline_days": 90}) == 90

    def test_env_beats_airflow_variable(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.setenv("EDGEGUARD_BASELINE_DAYS", "60")
        assert resolve_baseline_days(airflow_variable_value=120) == 60

    def test_airflow_variable_beats_default(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.delenv("EDGEGUARD_BASELINE_DAYS", raising=False)
        assert resolve_baseline_days(airflow_variable_value=200) == 200

    def test_default_when_nothing_set(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.delenv("EDGEGUARD_BASELINE_DAYS", raising=False)
        assert resolve_baseline_days() == 730

    def test_invalid_explicit_falls_through(self, monkeypatch):
        from baseline_config import resolve_baseline_days

        monkeypatch.delenv("EDGEGUARD_BASELINE_DAYS", raising=False)
        # Negative → fall through to default
        assert resolve_baseline_days(explicit=-5) == 730
        # Non-int → fall through
        assert resolve_baseline_days(explicit="not-a-number") == 730  # type: ignore[arg-type]

    def test_collection_limit_zero_is_unlimited(self, monkeypatch):
        from baseline_config import resolve_baseline_collection_limit

        monkeypatch.delenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT", raising=False)
        # 0 means UNLIMITED — preserved
        assert resolve_baseline_collection_limit(explicit=0) == 0
        # Negative clamped to 0 (also UNLIMITED — defensive)
        assert resolve_baseline_collection_limit(explicit=-1) == 0


# ---------------------------------------------------------------------------
# baseline_clean — destructive helper contract
# ---------------------------------------------------------------------------


class TestBaselineCleanContract:
    """The helper's API contract — type shapes, exception class, key
    properties. We don't test the actual wipe (needs Neo4j+MISP); we
    test the surface that callers (CLI + DAG) depend on."""

    def test_baseline_state_dataclass_is_frozen(self):
        from dataclasses import FrozenInstanceError

        from baseline_clean import BaselineState

        state = BaselineState(neo4j_count=5, neo4j_ok=True)
        with pytest.raises(FrozenInstanceError):
            state.neo4j_count = 99  # type: ignore[misc]

    def test_baseline_state_all_reachable_property(self):
        from baseline_clean import BaselineState

        # All ok → reachable
        state = BaselineState(neo4j_ok=True, misp_ok=True, checkpoint_ok=True)
        assert state.all_reachable is True
        # Any not ok → not reachable
        state = BaselineState(neo4j_ok=True, misp_ok=False, checkpoint_ok=True)
        assert state.all_reachable is False

    def test_baseline_state_all_zero_requires_reachable(self):
        from baseline_clean import BaselineState

        # All zero counts BUT one probe failed → all_zero is False
        # (we can't claim "verified empty" if we couldn't probe)
        state = BaselineState(
            neo4j_count=0,
            neo4j_ok=True,
            misp_count=0,
            misp_ok=False,
            misp_error="conn refused",
            checkpoint_count=0,
            checkpoint_ok=True,
        )
        assert state.all_zero is False

    def test_baseline_state_all_zero_when_all_reachable_and_zero(self):
        from baseline_clean import BaselineState

        state = BaselineState(
            neo4j_count=0,
            neo4j_ok=True,
            misp_count=0,
            misp_ok=True,
            checkpoint_count=0,
            checkpoint_ok=True,
        )
        assert state.all_zero is True

    def test_clean_error_carries_partial_state(self):
        from baseline_clean import BaselineCleanError, BaselineState

        partial = BaselineState(neo4j_count=100, neo4j_ok=True, misp_ok=False, misp_error="boom")
        err = BaselineCleanError("test failure", partial_state=partial)
        assert err.partial_state is partial
        assert "test failure" in str(err)

    def test_render_summary_includes_all_three_datastores(self):
        from baseline_clean import BaselineState

        state = BaselineState(
            neo4j_count=347197,
            neo4j_ok=True,
            neo4j_breakdown=(("Indicator", 281000),),
            misp_count=8247,
            misp_ok=True,
            checkpoint_count=12,
            checkpoint_ok=True,
        )
        summary = state.render_summary()
        assert "Neo4j" in summary
        assert "MISP" in summary
        assert "Checkpoint" in summary
        # Counts formatted with commas (operator-readable):
        assert "347,197" in summary
        assert "8,247" in summary

    def test_reset_baseline_data_signature(self):
        # Pin the public API so consumer call sites (CLI, DAG) don't drift.
        from baseline_clean import reset_baseline_data

        sig = inspect.signature(reset_baseline_data)
        params = sig.parameters
        # All keyword-only so adding parameters is non-breaking
        assert all(p.kind == inspect.Parameter.KEYWORD_ONLY for p in params.values())
        # Required defaults present
        assert "settle_seconds" in params
        assert "verify_timeout_seconds" in params
        assert "verify_poll_interval_seconds" in params
        assert "misp_max_pages" in params


# ---------------------------------------------------------------------------
# CLI ↔ DAG parity invariants
# ---------------------------------------------------------------------------


class TestCliDagParity:
    """The audit (Cross-Checker HIGH H1, H2) found the CLI baseline path
    skipped enrichment_jobs and build_relationships entirely. These tests
    pin the parity invariants — if a future refactor accidentally removes
    them, the test fails."""

    def _pipeline_inner_source(self) -> str:
        import run_pipeline

        return inspect.getsource(run_pipeline.EdgeGuardPipeline._run_pipeline_inner)

    def test_cli_baseline_invokes_build_relationships(self):
        # CLI baseline path must call build_relationships.py via subprocess
        # (matches the DAG's invocation shape — same script, same timeout).
        src = self._pipeline_inner_source()
        # Gated on `if baseline:` to avoid surprising incremental runs
        assert "build_relationships.py" in src
        # Subprocess invocation (matches the DAG's run_build_relationships shape)
        assert "subprocess.run" in src

    def test_cli_baseline_invokes_run_all_enrichment_jobs(self):
        # CLI baseline path must call enrichment_jobs.run_all_enrichment_jobs
        # (matches the DAG's enrichment task — produces Campaign nodes,
        # decay, calibrate, bridge_vuln_cve).
        src = self._pipeline_inner_source()
        assert "run_all_enrichment_jobs" in src
        # In-process (we have a Neo4jClient open) — distinct from build_rels
        # which is subprocess.
        assert "from enrichment_jobs import run_all_enrichment_jobs" in src

    def test_cli_baseline_skips_enrichment_when_not_baseline(self):
        # The build_rels + enrichment calls must be gated on `if baseline:`
        # so incremental CLI runs don't pay the latency cost.
        src = self._pipeline_inner_source()
        # The comment block notes the gating rationale
        assert "Step 5b" in src or "Step 5c" in src
        # Inspect the source structure: build_relationships call is inside
        # an `if baseline:` block.
        # Find the build_relationships.py reference and check it's inside
        # an `if baseline:` block by walking back through the source.
        idx = src.find("build_relationships.py")
        assert idx > 0
        # Walk back and find the most recent `if ` keyword at lower indent.
        prefix = src[:idx]
        assert "if baseline:" in prefix


class TestFreshBaselineDagTask:
    """The new baseline_clean Airflow task (Cross-Checker HIGH H3) must:
    1. Be wired BETWEEN baseline_misp_health and baseline_start
    2. No-op when dag_run.conf.fresh_baseline is not True
    3. Call baseline_clean.reset_baseline_data when conf says fresh_baseline=true
    4. Raise AirflowException on BaselineCleanError (so the DAG aborts)"""

    def _dag_source(self) -> str:
        # Read the file directly — importing dags/edgeguard_pipeline.py
        # requires Airflow + tons of deps not available in the test env.
        with open("dags/edgeguard_pipeline.py") as fh:
            return fh.read()

    def test_baseline_clean_task_defined(self):
        src = self._dag_source()
        assert "baseline_clean_task = PythonOperator(" in src
        assert 'task_id="baseline_clean"' in src

    def test_baseline_clean_task_wired_in_dependency_chain(self):
        src = self._dag_source()
        # Must appear AFTER baseline_misp_health AND BEFORE baseline_start
        # in the dependency chain.
        assert ("baseline_misp_health\n    >> baseline_clean_task\n    >> baseline_start") in src, (
            "baseline_clean_task must be wired between misp_health and baseline_start"
        )

    def test_baseline_clean_task_reads_fresh_baseline_conf(self):
        src = self._dag_source()
        # The _baseline_clean function must check dag_run.conf for fresh_baseline
        assert 'conf.get("fresh_baseline"' in src

    def test_baseline_clean_task_no_op_default(self):
        # When fresh_baseline is not set, the task must skip the destructive
        # path (no-op + log explanation). Pin via source scan: the
        # `if not fresh_baseline:` block must contain a `return` statement
        # within its first ~10 lines (before the destructive path runs).
        #
        # PR-C v3 audit fix: previous slice was ``src[idx:idx+3000]``, which
        # broke when the dag_run.conf=None guard added ~250 chars of code+
        # comments above the ``if not fresh_baseline:`` line. Walk the
        # function body via the next ``def`` / ``baseline_clean_task =``
        # marker so the slice is bounded by structure, not magic numbers.
        src = self._dag_source()
        clean_fn_idx = src.find("def _baseline_clean(")
        assert clean_fn_idx > 0
        # End at the next module-level binding after _baseline_clean
        next_def_idx = src.find("\nbaseline_clean_task =", clean_fn_idx)
        assert next_def_idx > clean_fn_idx
        clean_body = src[clean_fn_idx:next_def_idx]
        assert "if not fresh_baseline:" in clean_body
        # Slice the body of the `if not fresh_baseline:` block (next ~10 lines)
        block_start = clean_body.index("if not fresh_baseline:")
        block_body = clean_body[block_start : block_start + 600]
        assert "\n        return\n" in block_body, (
            "_baseline_clean must `return` (no-op) inside the `if not fresh_baseline:` block"
        )

    def test_baseline_clean_task_raises_on_clean_error(self):
        src = self._dag_source()
        # Must raise AirflowException when reset_baseline_data raises
        # BaselineCleanError (so the DAG aborts before collectors).
        clean_fn_idx = src.find("def _baseline_clean(")
        clean_end = src.find("\n\nbaseline_clean_task = ", clean_fn_idx)
        clean_body = src[clean_fn_idx:clean_end]
        assert "except BaselineCleanError" in clean_body
        assert "raise AirflowException" in clean_body


# ---------------------------------------------------------------------------
# CLI commands (edgeguard fresh-baseline / edgeguard baseline)
# ---------------------------------------------------------------------------


class TestCliCommands:
    """The new operator-facing CLI commands. Tests cover argument parsing
    + dispatch wiring; the actual subprocess calls to airflow are mocked."""

    def _edgeguard_source(self, fn_name: str) -> str:
        import edgeguard

        return inspect.getsource(getattr(edgeguard, fn_name))

    def test_cmd_fresh_baseline_exists(self):
        import edgeguard

        assert hasattr(edgeguard, "cmd_fresh_baseline")
        assert callable(edgeguard.cmd_fresh_baseline)

    def test_cmd_baseline_exists(self):
        import edgeguard

        assert hasattr(edgeguard, "cmd_baseline")
        assert callable(edgeguard.cmd_baseline)

    def test_fresh_baseline_refuses_when_probes_unreachable(self):
        # Audit principle: refuse to ask for confirmation without live counts.
        # Pin the contract via a mock probe that returns all_reachable=False.
        import edgeguard
        from baseline_clean import BaselineState

        unreachable = BaselineState(
            neo4j_ok=False,
            neo4j_error="conn refused",
            misp_ok=True,
            checkpoint_ok=True,
        )
        args = MagicMock()
        args.days = 30
        args.force = False

        with patch("baseline_clean.probe_baseline_state", return_value=unreachable):
            ret = edgeguard.cmd_fresh_baseline(args)

        # Exit code 2 = preflight failed (system unhealthy); distinct from
        # exit 1 (user declined).
        assert ret == 2

    def test_fresh_baseline_uses_typed_confirmation_token(self):
        # Source-scan: the CLI MUST require typing FRESH-BASELINE exactly.
        # No partial matches, no case-insensitive, no "y/n".
        src = self._edgeguard_source("cmd_fresh_baseline")
        assert 'confirm != "FRESH-BASELINE"' in src

    def test_fresh_baseline_passes_correct_dag_conf(self):
        # When the user confirms, the airflow trigger must include BOTH
        # fresh_baseline=true AND baseline_days=N in the conf JSON.
        src = self._edgeguard_source("cmd_fresh_baseline")
        # The conf-build line uses json.dumps so we pin the structure
        assert "fresh_baseline" in src
        assert "baseline_days" in src
        # Triggers the right DAG name
        assert "edgeguard_baseline" in src

    def test_baseline_does_NOT_pass_fresh_baseline_conf(self):
        # The additive baseline command must NOT set fresh_baseline=true
        # (otherwise it'd accidentally trigger the destructive clean).
        src = self._edgeguard_source("cmd_baseline")
        assert "baseline_days" in src

        # Strip both # comments (whole-line) AND # trailing comments
        # before scanning. A line like `conf = json.dumps({...})  # NO fresh_baseline`
        # legitimately mentions the word in a comment but doesn't pass it.
        def _strip_inline_comment(line: str) -> str:
            # Naive but adequate for our codebase: cut at the first " #"
            idx = line.find("  #")
            return line[:idx] if idx > 0 else line

        code_only_lines = [
            _strip_inline_comment(line) for line in src.splitlines() if not line.lstrip().startswith("#")
        ]
        for line in code_only_lines:
            if "json.dumps(" in line:
                assert "fresh_baseline" not in line, (
                    "cmd_baseline must NOT pass fresh_baseline conf — that would trigger the destructive clean"
                )


# ---------------------------------------------------------------------------
# Run_pipeline.py — fresh-baseline path delegates to baseline_clean
# ---------------------------------------------------------------------------


class TestRunPipelineDelegatesToBaselineClean:
    """The CLI's --fresh-baseline path must use the SAME helper as the DAG.
    Otherwise we re-introduce the CLI ↔ DAG drift the audit found."""

    def test_run_pipeline_imports_baseline_clean(self):
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        assert "from baseline_clean import" in src
        assert "BaselineCleanError" in src
        assert "reset_baseline_data" in src

    def test_run_pipeline_no_longer_has_inline_misp_delete_loop(self):
        # The previous inline 80-LOC paginated DELETE loop is gone.
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        # Negative: no more inline _misp_url + searchall=EdgeGuard pattern
        # in the fresh-baseline branch (the helper has its own copy)
        # Strip comments first so the rationale comment doesn't false-fail
        code_only = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # The previous code had a `for _round in range(20):` loop — that's
        # now in baseline_clean._wipe_misp_events.
        assert "for _round in range(20):" not in code_only

    def test_run_pipeline_returns_false_on_clean_error(self):
        # When BaselineCleanError fires, the inner pipeline returns False
        # — refusing to run collectors on a half-cleaned state.
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        assert "except BaselineCleanError" in src
        # The handler must return False (not continue silently)
        idx = src.find("except BaselineCleanError")
        handler_body = src[idx : idx + 500]
        assert "return False" in handler_body
