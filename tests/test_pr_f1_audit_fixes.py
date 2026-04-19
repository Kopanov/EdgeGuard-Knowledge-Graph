"""
Regression tests for PR-F1 — easy + fast audit fixes.

Each fix below was a real finding from the post-PR-merge production-readiness
audit (8 agents, 2026-04-19 evening). PR-F1 lands the mechanical fixes; this
test file pins the contracts.

Coverage:
  - **Bug Hunter HIGH BH-H1** — OTX cursor advance over truncated pulse set
    (silent data loss when EDGEGUARD_INCREMENTAL_LIMIT bites)
  - **Bug Hunter HIGH BH2-HIGH** — EDGEGUARD_CHECKPOINT_DIR path-traversal
    guard was a substring-prefix check, not a directory-prefix check
  - **Prod Readiness BLOCK 1.3** — verify_timeout_seconds default 60s would
    fail on 350K+ node baselines (~70s+ for clear_all + APOC + commit)
  - **Devil's Advocate + Maintainer corroborated** — `_build_relationships_degraded`
    ghost attribute removed (no production reader)

The naming convention follows the global Skill recommendation: function-named,
not PR-numbered. Future test additions should adopt
``test_<module>_<aspect>.py`` as 92% of the test dir already does.
The ``test_pr_f1_*`` name is kept here ONLY because this file pins multiple
unrelated audit-fix contracts; it'll get split when next touched.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Bug Hunter HIGH BH-H1 — OTX cursor advance fallback
# ---------------------------------------------------------------------------


class TestOtxCursorAdvanceUsesProcessedSet:
    """``_advance_otx_incremental_cursor`` must fall back to the truncated
    ``to_process`` list when ``successful_pulses`` is None — not the FULL
    fetched ``pulses`` list. The previous bug advanced the cursor past
    the latest-modified timestamp of pulses we never actually processed,
    silently losing them on the next incremental run."""

    def test_otx_collector_source_uses_to_process_not_pulses(self):
        """Source-pin (acknowledged trade-off): the closure can't be
        unit-tested without instantiating the entire collector + mocking
        OTX HTTP. Pin the actual line that addresses the bug.

        If a future refactor renames `to_process` or changes the closure
        shape, this test fires. The literal-pin is justified because
        the bug is silent data loss in the most-common operational mode."""
        with open("src/collectors/otx_collector.py") as fh:
            src = fh.read()

        # Strip comment lines so the explanatory comment doesn't false-pass
        code_only = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))

        # Negative — the buggy fallback must not be in code
        assert "source = successful_pulses if successful_pulses is not None else pulses" not in code_only, (
            "BH-H1: cursor advance must use `to_process` (truncated set), not full `pulses`"
        )
        # Positive — the fixed fallback must be present
        assert "source = successful_pulses if successful_pulses is not None else to_process" in code_only, (
            "expected `else to_process` fallback (the truncated set after EDGEGUARD_INCREMENTAL_LIMIT)"
        )


# ---------------------------------------------------------------------------
# Bug Hunter HIGH BH2-HIGH — EDGEGUARD_CHECKPOINT_DIR path-traversal guard
# ---------------------------------------------------------------------------


class TestCheckpointDirPathTraversalGuard:
    """The guard must use ``Path.is_relative_to`` (directory-prefix check),
    not ``str.startswith`` (substring-prefix check). Otherwise
    ``EDGEGUARD_CHECKPOINT_DIR=/opt/edgeguard-evil`` passes when project
    root is ``/opt/edgeguard``."""

    def test_path_traversal_evil_prefix_directory_rejected(self, tmp_path, monkeypatch):
        """Concrete reproducer: a sibling directory whose prefix matches
        the project root must NOT pass the guard. Tests the CURRENT logic
        by simulating with synthetic project root + candidate dirs."""
        project_root = tmp_path / "edgeguard"
        project_root.mkdir()
        evil_sibling = tmp_path / "edgeguard-evil"
        evil_sibling.mkdir()

        # The buggy str.startswith check would PASS this:
        assert str(evil_sibling).startswith(str(project_root)) is True, "buggy check passes evil sibling"

        # The fixed Path.is_relative_to check must REJECT it:
        assert evil_sibling.is_relative_to(project_root) is False, "fixed check rejects evil sibling"

    def test_path_traversal_legitimate_subdir_accepted(self, tmp_path):
        """A genuine subdirectory of the project root must still pass."""
        project_root = tmp_path / "edgeguard"
        project_root.mkdir()
        legit_subdir = project_root / "checkpoints"
        legit_subdir.mkdir()

        assert legit_subdir.is_relative_to(project_root) is True

    def test_baseline_checkpoint_module_uses_is_relative_to(self):
        """Source-pin: the actual fix must be present in the module."""
        with open("src/baseline_checkpoint.py") as fh:
            src = fh.read()

        # Strip comment lines so the rationale comment doesn't false-pass
        code_only = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))

        # Negative — the buggy substring-prefix check must be absent from code
        assert "str(_candidate).startswith(str(_PROJECT_ROOT))" not in code_only, (
            "BH2-HIGH: must use Path.is_relative_to, not str.startswith"
        )
        # Positive — the fixed check must be present
        assert "_candidate.is_relative_to(_PROJECT_ROOT)" in code_only, (
            "expected directory-prefix check via Path.is_relative_to"
        )


# ---------------------------------------------------------------------------
# Prod Readiness BLOCK 1.3 — verify_timeout_seconds derived from neo4j_count
# ---------------------------------------------------------------------------


class TestVerifyTimeoutDerivedFromCount:
    """``reset_baseline_data(verify_timeout_seconds=None)`` (the default)
    must derive the timeout from ``before.neo4j_count`` rather than use
    a static 60s. Math: ``max(60, neo4j_count / 5000)``."""

    def test_derivation_math_floor_60_seconds(self):
        """For small graphs (< 300K nodes), the 60s floor applies."""
        # Direct math test (the formula is in the function body, but
        # we can at least verify the math the doc promises)
        for count in [0, 100, 10_000, 100_000, 299_999]:
            derived = max(60.0, count / 5000.0)
            assert derived == 60.0, f"count={count} should yield 60s floor, got {derived}"

    def test_derivation_math_scales_linearly_above_floor(self):
        """For 350K+ node graphs, the derived timeout exceeds 60s."""
        derived_350k = max(60.0, 350_000 / 5000.0)
        assert derived_350k == 70.0, "350K → 70s"

        derived_1m = max(60.0, 1_000_000 / 5000.0)
        assert derived_1m == 200.0, "1M → 200s"

        derived_500k = max(60.0, 500_000 / 5000.0)
        assert derived_500k == 100.0, "500K → 100s"

    def test_reset_baseline_data_signature_accepts_optional_verify_timeout(self):
        """The signature must allow None to trigger derivation."""
        import inspect

        from baseline_clean import reset_baseline_data

        sig = inspect.signature(reset_baseline_data)
        param = sig.parameters["verify_timeout_seconds"]
        # Default must be None so caller-omits → derivation applies
        assert param.default is None, "expected default=None to trigger derivation"

    def test_baseline_clean_module_contains_derivation_logic(self):
        """Source-pin: the derivation block must be present in the function."""
        with open("src/baseline_clean.py") as fh:
            src = fh.read()
        # Strip comment lines so the explanatory comment doesn't false-pass
        code_only = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        # Both halves of the derivation pattern must be present in code
        assert "if verify_timeout_seconds is None:" in code_only
        assert "max(60.0, before.neo4j_count / 5000.0)" in code_only


# ---------------------------------------------------------------------------
# Devil's Advocate + Maintainer corroborated — _build_relationships_degraded removed
# ---------------------------------------------------------------------------


class TestBuildRelationshipsDegradedAttributeRemoved:
    """``self._build_relationships_degraded`` was a write-only attribute
    with zero production readers (only test framework grep referenced it).
    The PR-F1 fix replaces it with a structured log line carrying
    ``extra={"degraded": True, "step": "build_relationships"}`` — cloud-
    portable, zero-additional-state."""

    def test_attribute_no_longer_referenced_anywhere_in_src(self):
        """Repo-wide grep: the attribute name must not appear in src/ code
        (rationale comments are OK)."""
        # Walk src/ and check for any non-comment reference
        offenders = []
        for path in Path("src").rglob("*.py"):
            with open(path) as fh:
                lines = fh.readlines()
            for i, line in enumerate(lines, start=1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                if "_build_relationships_degraded" in line:
                    offenders.append(f"{path}:{i}: {line.rstrip()}")
        assert offenders == [], "ghost attribute should be removed from src/; references found:\n" + "\n".join(
            offenders
        )

    def test_run_pipeline_uses_structured_log_extra(self):
        """The replacement is a structured log with ``extra={'degraded': True}``."""
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        # The ``extra={"degraded": True, "step": "build_relationships"}`` keyword
        # must be present in the build_relationships failure log calls
        assert 'extra={"degraded": True, "step": "build_relationships"}' in src, (
            "expected structured log marker on build_relationships failure path"
        )


# ---------------------------------------------------------------------------
# Prod Readiness LOW 1.8 — install.sh auto-gens AIRFLOW secrets
# ---------------------------------------------------------------------------


class TestInstallShAutoGensAirflowSecrets:
    """install.sh must auto-generate ``AIRFLOW_API_AUTH_JWT_SECRET`` and
    ``AIRFLOW_FERNET_KEY`` on first .env creation, mirroring the existing
    EDGEGUARD_API_KEY + GRAFANA_ADMIN_PASSWORD pattern."""

    def test_install_sh_generates_jwt_secret_on_empty_value(self):
        with open("install.sh") as fh:
            src = fh.read()
        # Detection grep + generator + awk replace
        assert "AIRFLOW_API_AUTH_JWT_SECRET=$" in src, "expected detection of empty AIRFLOW_API_AUTH_JWT_SECRET"
        assert "secrets.token_urlsafe(64)" in src, "expected python3 fallback generator (urlsafe_64) for JWT"
        assert "AIRFLOW_API_AUTH_JWT_SECRET=" in src

    def test_install_sh_generates_fernet_key(self):
        with open("install.sh") as fh:
            src = fh.read()
        assert "AIRFLOW_FERNET_KEY=$" in src, "expected detection of empty AIRFLOW_FERNET_KEY"
        # Must use the canonical Fernet generator OR openssl-base64
        assert "Fernet.generate_key" in src, "expected canonical Fernet generator path"

    def test_env_example_documents_airflow_fernet_key(self):
        """The .env.example must document AIRFLOW_FERNET_KEY (mirror the
        existing JWT_SECRET docstring)."""
        with open(".env.example") as fh:
            content = fh.read()
        assert "AIRFLOW_FERNET_KEY" in content
        assert "Fernet.generate_key" in content, "expected the canonical generator command in .env.example"
