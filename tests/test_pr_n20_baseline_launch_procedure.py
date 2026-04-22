"""
PR-N20 — 730-day baseline launch procedure + follow-ups.

After PR-N19 merged, a 3-agent readiness audit surfaced three actionable
items that needed to ship before launching the 730-day baseline:

1. **Launch-path documentation gap.** Three xfails in
   ``tests/test_tier1_sequential_robustness.py`` pin Issue #57 — the
   Airflow DAG baseline path does NOT call ``acquire_baseline_lock()``.
   Over the ~26h baseline, the 4 scheduled incremental DAGs race the
   baseline for MISP + Neo4j writes, reproducing the 2026-04-19
   MISP-PHP-FPM exhaustion + 14.7% NVD loss. ``docs/RUNBOOK.md`` didn't
   surface the workaround. Fix: add a dedicated "Baseline launch path"
   section with explicit CLI vs DAG+pause procedures.

2. **Preflight script missing.** Operators had no single command to
   verify env vars + Neo4j + MISP reachability + DAG pause state + RAM
   + alerts + sentinel cleanup + kill-switch defaults before kicking
   off the 26h run. Fix: add ``scripts/preflight_baseline.sh``.

3. **``merge_vulnerability`` single-row path symmetry gap.** PR-N19
   Fix #1 fixed the MISP-sourced CVE date-drop, but the NVD-sourced
   ``merge_vulnerability`` single-row path (used by the alert pipeline
   and ``_sync_single_item`` fallback) still dropped ``published`` /
   ``last_modified``. Same bug shape as the one PR-N19 closed for
   ``merge_cve``. Fix: symmetric promotion in ``merge_vulnerability``.

Additionally: add a MISP-retrieval-paths section to the RUNBOOK
answering the operator question "how do I use a Neo4j node to fetch
the raw MISP data?" (`n.misp_attribute_ids[]` → MISP API).
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
DOCS = REPO_ROOT / "docs"
SCRIPTS = REPO_ROOT / "scripts"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n20")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n20")


# ===========================================================================
# Fix #1 — RUNBOOK has the launch-path section (CLI vs DAG+pause)
# ===========================================================================


class TestFix1RunbookLaunchPath:
    def _runbook(self) -> str:
        return (DOCS / "RUNBOOK.md").read_text()

    def test_runbook_has_baseline_launch_path_section(self):
        """Pin that the CLI-vs-DAG decision is surfaced in the RUNBOOK,
        not only in docs/flow_audits/ where an operator might miss it."""
        rb = self._runbook()
        assert "Baseline launch path" in rb, (
            "RUNBOOK must surface the baseline launch-path decision (CLI vs DAG+pause). "
            "Issue #57 / docs/flow_audits/01_baseline_sequence.md Finding 1."
        )

    def test_runbook_documents_cli_launch_option(self):
        rb = self._runbook()
        # CLI path takes the in-process baseline_lock; every scheduled DAG
        # then self-skips via baseline_skip_reason(). Pin the recommended
        # command shape.
        assert "python -m edgeguard baseline" in rb, (
            "RUNBOOK must document the CLI launch command (recommended path). "
            "It takes the in-process baseline_lock (src/run_pipeline.py:1093)."
        )

    def test_runbook_documents_dag_pause_option(self):
        rb = self._runbook()
        # DAG path requires pre-pausing 4 incremental DAGs for the ~26h window.
        for dag in [
            "edgeguard_daily",
            "edgeguard_medium_freq",
            "edgeguard_pipeline",
            "edgeguard_low_freq",
        ]:
            assert dag in rb, f"RUNBOOK must name {dag} in the DAG-pause procedure"
        assert "airflow dags pause" in rb, "RUNBOOK must show the `airflow dags pause` command"
        assert "airflow dags unpause" in rb, "RUNBOOK must show how to restore after baseline completes"

    def test_runbook_cross_references_issue_57(self):
        rb = self._runbook()
        # Cross-reference so ops readers can find the root-cause audit.
        assert "Issue #57" in rb or "01_baseline_sequence.md" in rb, (
            "RUNBOOK must cross-reference the root-cause audit for the launch-path constraint"
        )

    def test_runbook_references_preflight_script(self):
        rb = self._runbook()
        assert "preflight_baseline.sh" in rb, (
            "RUNBOOK must reference the preflight script so operators know there's a one-shot check"
        )


# ===========================================================================
# Fix #2 — preflight_baseline.sh exists + has the expected check matrix
# ===========================================================================


class TestFix2PreflightScript:
    def _script(self) -> str:
        return (SCRIPTS / "preflight_baseline.sh").read_text()

    def test_preflight_script_exists(self):
        path = SCRIPTS / "preflight_baseline.sh"
        assert path.exists(), "scripts/preflight_baseline.sh must exist"
        # Must be executable — operators run it directly.
        assert os.access(path, os.X_OK), "preflight_baseline.sh must be executable (chmod +x)"

    def test_preflight_covers_required_env_vars(self):
        src = self._script()
        for var in ["NEO4J_PASSWORD", "MISP_API_KEY", "MISP_URL"]:
            assert var in src, f"preflight must check that {var} is set"

    def test_preflight_checks_neo4j_reachability(self):
        src = self._script()
        assert "Neo4j" in src and ("cypher-shell" in src or "bolt://" in src), (
            "preflight must verify Neo4j is reachable"
        )

    def test_preflight_checks_misp_reachability(self):
        src = self._script()
        assert ("/servers/getVersion" in src or "MISP" in src) and "curl" in src, (
            "preflight must hit a MISP API endpoint to verify auth works"
        )

    def test_preflight_checks_dag_pause_on_dag_launch_path(self):
        src = self._script()
        # The DAG path is the one that NEEDS the pause-check. Confirm the
        # script knows how to verify each of the 4 incrementals.
        for dag in [
            "edgeguard_daily",
            "edgeguard_medium_freq",
            "edgeguard_pipeline",
            "edgeguard_low_freq",
        ]:
            assert dag in src, f"preflight must verify {dag} pause-state on --launch-path=dag"

    def test_preflight_checks_prometheus_alerts(self):
        src = self._script()
        assert "promtool" in src or "alerts.yml" in src, (
            "preflight must verify Prometheus alert rules parse (promtool check rules)"
        )

    def test_preflight_exits_nonzero_on_failure(self):
        src = self._script()
        assert "exit 1" in src, "preflight must exit 1 when any hard-fail check fails"
        assert "exit 0" in src, "preflight must exit 0 on all-green"

    def test_preflight_env_var_loop_reports_value_length_not_name_length(self):
        """Bugbot round 1 (PR #104, Medium severity): the env-var loop used
        ``${#var}`` which measures the length of the variable NAME
        ("NEO4J_PASSWORD" = 14 chars), not the indirectly-referenced VALUE.
        The printed copy said "value not echoed" so the reported count
        had to correspond to the value; a 40-char API key printed "12
        chars" misleading operators about credential state.

        Pin: the env-var loop MUST (a) capture the indirect value into a
        local like ``var_value="${!var:-}"``, and (b) measure
        ``${#var_value}``. Regression-guard against a literal ``${#var}``
        re-appearing inside that loop."""
        src = self._script()
        # Isolate the env-var loop so we don't false-fail on similar
        # constructs elsewhere in the script (if any are added later).
        # Rough anchor: the loop starts after the "[1] required env vars" header.
        loop_start = src.find("for var in NEO4J_PASSWORD MISP_API_KEY MISP_URL")
        assert loop_start != -1, "env-var loop anchor missing"
        loop_end = src.find("done", loop_start)
        assert loop_end != -1, "env-var loop terminator missing"
        loop_body = src[loop_start:loop_end]

        # Positive: the loop must capture the indirect reference into a
        # local variable (any name is fine as long as it's used below).
        assert '"${!var' in loop_body, (
            'env-var loop must capture the indirect reference (``"${!var..}"``) into a local before measuring length'
        )
        # Negative: ``${#var}`` (measuring the name) must NOT appear inside
        # the loop body. This is the exact Bugbot-flagged regression shape.
        assert "${#var}" not in loop_body, (
            "env-var loop reports ${#var} (length of NAME, always 8/12/14) instead of the VALUE length. "
            'Capture ``var_value="${!var:-}"`` first, then measure ``${#var_value}``. '
            "Bugbot round 1, PR #104, Medium severity."
        )
        # Positive: the correct form (value-length) must appear.
        assert "${#var_value}" in loop_body or "${#value}" in loop_body, (
            "env-var loop must report the VALUE length (e.g. ``${#var_value}``) after capturing the indirect reference"
        )


# ===========================================================================
# Fix #3 — merge_vulnerability promotes published + last_modified (symmetry
# with post-PR-N19 merge_cve)
# ===========================================================================


class TestFix3MergeVulnerabilitySymmetry:
    def test_merge_vulnerability_extra_props_includes_published(self):
        """AST pin: merge_vulnerability must conditionally add 'published'
        to extra_props — same shape as PR-N19 Fix #1 on merge_cve."""
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_vulnerability":
                        body = ast.unparse(node)
                        assert 'extra_props["published"]' in body or "extra_props['published']" in body, (
                            "merge_vulnerability must promote data['published'] to extra_props "
                            "(PR-N20 follow-up to PR-N19 Fix #1; single-row NVD path was dropping it)"
                        )
                        return
        raise AssertionError("merge_vulnerability not found")

    def test_merge_vulnerability_extra_props_includes_last_modified(self):
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_vulnerability":
                        body = ast.unparse(node)
                        assert 'extra_props["last_modified"]' in body or "extra_props['last_modified']" in body, (
                            "merge_vulnerability must promote data['last_modified'] to extra_props (PR-N20 follow-up to PR-N19 Fix #1)"
                        )
                        return
        raise AssertionError("merge_vulnerability not found")

    def test_merge_vulnerability_behavior_promotes_both_fields(self):
        """Behavioral pin: invoke merge_vulnerability with data containing
        published + last_modified; confirm both reach extra_props via the
        merge_node_with_source mock (same shape as PR-N19 Fix #1's test)."""
        from neo4j_client import Neo4jClient

        c = Neo4jClient.__new__(Neo4jClient)
        c.driver = MagicMock()
        c.merge_node_with_source = MagicMock(return_value=True)

        data = {
            "cve_id": "CVE-2024-12345",
            "description": "Symmetry test",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "published": "2024-02-14T12:00:00.000",
            "last_modified": "2024-03-01T08:30:00.000",
        }
        assert c.merge_vulnerability(data) is True
        call_kwargs = c.merge_node_with_source.call_args.kwargs
        extra_props = call_kwargs.get("extra_props", {})
        assert extra_props.get("published") == "2024-02-14T12:00:00.000", (
            f"merge_vulnerability must pass published to extra_props; got {extra_props.get('published')!r}"
        )
        assert extra_props.get("last_modified") == "2024-03-01T08:30:00.000"


# ===========================================================================
# Fix #4 — RUNBOOK documents how to retrieve raw MISP data from a Neo4j node
# ===========================================================================


class TestFix4RunbookMispRetrievalPaths:
    def _runbook(self) -> str:
        return (DOCS / "RUNBOOK.md").read_text()

    def test_runbook_documents_misp_retrieval_section(self):
        rb = self._runbook()
        assert "Retrieving raw MISP data from a Neo4j node" in rb, (
            "RUNBOOK must document the three MISP-retrieval paths (attribute UUID, event ID, raw JSON on edge)"
        )

    def test_runbook_clarifies_node_uuid_is_not_misp_link(self):
        """The user's audit question conflated n.uuid (deterministic UUIDv5
        for cross-environment identity) with the MISP back-pointer
        (misp_attribute_ids[]). Pin the clarifying paragraph."""
        rb = self._runbook()
        assert "n.uuid" in rb and "deterministic" in rb.lower() and "NOT" in rb, (
            "RUNBOOK must clarify that n.uuid is a deterministic UUIDv5 for cross-env identity, "
            "NOT a foreign key into MISP"
        )

    def test_runbook_documents_all_three_retrieval_paths(self):
        rb = self._runbook()
        assert "misp_attribute_ids" in rb, "Path 1 — MISP attribute UUID"
        assert "misp_event_ids" in rb, "Path 2 — MISP event ID"
        assert "SOURCED_FROM" in rb and "raw_data" in rb, "Path 3 — raw JSON on SOURCED_FROM edge"

    def test_runbook_documents_misp_api_fetch_shape(self):
        rb = self._runbook()
        # Operator needs to know the HTTP endpoint + header shape.
        assert "/attributes/" in rb, "RUNBOOK must show the MISP /attributes/<uuid> endpoint"
        assert "/events/" in rb, "RUNBOOK must show the MISP /events/<id> endpoint"
        assert "Authorization" in rb, "RUNBOOK must show the Authorization header for MISP API"


# ===========================================================================
# Fix #5 — README.md surfaces the launch procedure for colleagues
# ===========================================================================


class TestFix5ReadmeLaunchProcedure:
    """Colleagues new to the project read the README first, not RUNBOOK.
    Pin that the baseline-launch options + the MISP retrieval paths live
    at the README level so they can't get lost in deep docs."""

    def _readme(self) -> str:
        return (REPO_ROOT / "README.md").read_text()

    def test_readme_has_baseline_launch_section(self):
        rd = self._readme()
        assert "Running the 730-day baseline" in rd, (
            "README must have a top-level 'Running the 730-day baseline' section "
            "so colleagues see the launch-path decision without hunting through docs/"
        )

    def test_readme_documents_cli_and_dag_options(self):
        rd = self._readme()
        # Both options must be visible; colleague should be able to pick
        # without having to open RUNBOOK.md first.
        assert "Option A" in rd and "Option B" in rd, "README must show both launch options (CLI + DAG)"
        assert "python -m edgeguard baseline" in rd, "README must show the CLI launch command"
        assert "airflow dags pause" in rd, "README must show the DAG pause command"

    def test_readme_references_preflight_script(self):
        rd = self._readme()
        assert "preflight_baseline.sh" in rd, (
            "README must point to scripts/preflight_baseline.sh as the pre-kickoff check"
        )

    def test_readme_explains_issue_57_rationale(self):
        """The 'why' matters as much as the 'what' — colleagues need to
        understand the 2026-04-19 incident shape to make the right
        launch-path choice."""
        rd = self._readme()
        assert "Issue #57" in rd, "README must cross-reference Issue #57 (DB-backed mutex)"
        assert "2026-04-19" in rd or "14.7%" in rd, (
            "README must explain the historical incident that motivates the launch-path decision"
        )

    def test_readme_documents_misp_retrieval_paths(self):
        rd = self._readme()
        assert "misp_attribute_ids" in rd, "README must show Path 1 (attribute UUID)"
        assert "misp_event_ids" in rd, "README must show Path 2 (event ID)"
        assert "SOURCED_FROM" in rd and "raw_data" in rd, "README must show Path 3 (raw JSON on edge)"

    def test_readme_clarifies_node_uuid_is_not_misp_link(self):
        """The user's original question conflated n.uuid with the MISP
        back-pointer. Pin the clarifying note at the README level."""
        rd = self._readme()
        assert "n.uuid" in rd and "NOT" in rd, (
            "README must clarify n.uuid is a deterministic UUIDv5 for cross-env identity, NOT a foreign key into MISP"
        )

    def test_airflow_section_warns_about_launch_path(self):
        """The existing 'Airflow DAG-based workflow' section must point
        readers at the launch-path decision before they hit the
        `airflow dags trigger edgeguard_baseline` button."""
        rd = self._readme()
        # Look for a warning in the Airflow section that references the
        # new launch-path decision section.
        assert "Running the 730-day baseline" in rd and "IMPORTANT" in rd, (
            "Existing Airflow DAG section must warn readers to consult the baseline launch procedure before triggering"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_neo4j_client_imports(self):
        import neo4j_client  # noqa: F401
