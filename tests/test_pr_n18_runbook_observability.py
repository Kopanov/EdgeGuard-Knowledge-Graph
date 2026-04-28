"""
PR-N18 — overnight RUNBOOK drift + observability close-out.

Cross-check Agent B's RUNBOOK audit (2026-04-22) found 4 BLOCK + 4
HIGH operator-facing drift items. This PR closes all of them + lands
the promised Prometheus counter + alert that PR-N11 deferred.

## Part A — --bootstrap-sources CLI

The RUNBOOK's Neo4j-ineffective-batch remediation referenced
``python -m src.neo4j_client --bootstrap-sources`` — but pre-PR-N18
the CLI had no argparse and that flag did nothing. PR-N18 adds the
flag + a proper ``_cli_bootstrap_sources()`` helper that runs
``create_constraints`` + ``create_indexes`` + ``ensure_sources``.

## Part B — RUNBOOK drift fixed

Rewrote ``docs/RUNBOOK.md`` with:
- Verified log prefixes (``[honest-NULL]`` not ``EDGE-GUARD-NULL-VIOLATION``;
  ``[MERGE-INEFFECTIVE]``, ``[BATCH-PERMANENT-FAILURE]``, ``[MERGE-REJECT]`` —
  all grep-friendly)
- Real log paths (``/opt/airflow/logs/**/*.log``, not ``/var/log/airflow/*.log``)
- Real docker-compose container names (`edgeguard-neo4j`, `edgeguard-misp`,
  `edgeguard-airflow-worker`, not kubectl pod refs)
- Expanded kill-switch table to 3 entries (added ``EDGEGUARD_EARLIEST_IOC_DATE``,
  which is semantically a PR-N14 kill-switch even though framed as a floor)
- Alert severity table mapped to paging priority
- Top-6 failure modes (was top-5; added PR-N15 batch-permanent-failure)
- Post-run validation queries extended for PR-N14/N15/N16 regression checks

## Part C — placeholder-reject Prometheus counter + wire

PR-N11 promised ``edgeguard_merge_reject_placeholder_total`` but
deferred it to "PR-N12 follow-up" — which never landed. PR-N18 ships
the counter + wires it in ``merge_malware`` / ``merge_actor`` next
to the existing ``[MERGE-REJECT]`` WARN logs. None-guarded per PR-N5 R1.

## Part D — Prometheus alerts

Two new alerts in ``edgeguard_pipeline_observability`` group:
- ``EdgeGuardNeo4jBatchPermanentFailure`` (critical) — pages on the
  PR-N15 counter. Was promised but not wired in alerts.yml.
- ``EdgeGuardMergeRejectPlaceholderSpike`` (warning) — pages when a
  collector emits >10 placeholder-name MERGE attempts per 15min
  (adversarial / feed regression signal).

## Part E — in-tree TODO markers

Two deferred items now have inline TODOs so they survive team rotation:
1. ``src/build_relationships.py`` Q2 branch 3 — aliases attribution
   hijack (Red-Team BLOCK #19, deferred pending allowlist/corroboration
   design).
2. ``src/neo4j_client.py`` ``retry_with_backoff`` decorator — full
   ``execute_write`` migration (40 call sites) for atomicity, deferred
   post-baseline.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n18")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n18")


def _load_alerts() -> dict:
    return yaml.safe_load((REPO_ROOT / "prometheus" / "alerts.yml").read_text())


def _find_rule(alert_name: str) -> dict:
    alerts = _load_alerts()
    for group in alerts["groups"]:
        for rule in group.get("rules", []):
            if rule.get("alert") == alert_name:
                return rule
    raise AssertionError(f"alert {alert_name!r} not found")


# ===========================================================================
# Part A — --bootstrap-sources CLI
# ===========================================================================


class TestPartABootstrapSourcesCli:
    def test_cli_helper_exists(self):
        """``_cli_bootstrap_sources`` must be a module-level function."""
        from neo4j_client import _cli_bootstrap_sources

        assert callable(_cli_bootstrap_sources)

    def test_main_block_supports_bootstrap_sources_flag(self):
        """AST pin: ``if __name__ == '__main__':`` must include an
        argparse ``--bootstrap-sources`` flag."""
        src = (SRC / "neo4j_client.py").read_text()
        assert 'parser.add_argument(\n        "--bootstrap-sources"' in src, (
            "--bootstrap-sources flag must be wired in __main__"
        )
        assert "args.bootstrap_sources" in src, "argparse dest must be checked in __main__"


# ===========================================================================
# Part B — RUNBOOK drift fixed
# ===========================================================================


class TestPartBRunbookDriftFixed:
    def _runbook(self) -> str:
        return (REPO_ROOT / "docs" / "RUNBOOK.md").read_text()

    def test_fabricated_grep_strings_are_gone(self):
        """``EDGE-GUARD-NULL-VIOLATION`` was a fabricated grep string
        (actual log prefix is ``[honest-NULL]``)."""
        runbook = self._runbook()
        assert "EDGE-GUARD-NULL-VIOLATION" not in runbook, "regression: fabricated grep string reintroduced"
        assert "[honest-NULL]" in runbook, "actual log prefix must be documented"

    def test_fabricated_replay_cli_is_gone(self):
        """``python -m src.collectors.misp_writer --replay-failed`` was
        fabricated — there is no replay mechanism."""
        runbook = self._runbook()
        assert "--replay-failed" not in runbook, "regression: fabricated replay CLI reintroduced"

    def test_bootstrap_sources_command_documented(self):
        runbook = self._runbook()
        assert "--bootstrap-sources" in runbook, "bootstrap-sources CLI (added in Part A) must be in RUNBOOK"

    def test_real_log_paths_used(self):
        """``/var/log/airflow/*.log`` was wrong. The RUNBOOK should use
        either ``/opt/airflow/logs/**/*.log`` (filesystem path on the
        worker container) OR ``docker logs edgeguard_airflow``
        (which is what we actually use — cleaner for docker-compose).

        PR-N35 docs audit (2026-04-28): updated container name from
        ``edgeguard-airflow-worker`` (hyphen, never existed in compose)
        to ``edgeguard_airflow`` (the actual `container_name:` per
        ``docker-compose.yml:204``)."""
        runbook = self._runbook()
        assert "/var/log/airflow" not in runbook, "regression: wrong log path reintroduced"
        # Must have at least one of the valid log-access patterns.
        uses_docker_logs = "docker logs edgeguard_airflow" in runbook
        uses_filesystem = "/opt/airflow/logs" in runbook
        assert uses_docker_logs or uses_filesystem, (
            "RUNBOOK must document a valid log-access method "
            "(docker logs edgeguard_airflow or /opt/airflow/logs)"
        )

    def test_docker_compose_container_names_used(self):
        """RUNBOOK mixed `kubectl` (not applicable to docker-compose
        deployment) and `docker`. Should be consistent.

        PR-N35 docs audit (2026-04-28): updated to the ACTUAL container
        names from ``docker-compose.yml`` (with underscores). MISP is
        explicitly NOT in the compose stack — there is no
        ``edgeguard_misp`` container; MISP is deployed separately and
        accessed via ``MISP_URL``."""
        runbook = self._runbook()
        # Mention the real compose container names.
        assert "edgeguard_neo4j" in runbook
        assert "edgeguard_airflow" in runbook
        # MISP is NOT in this compose; the runbook explicitly notes that.
        assert "MISP is NOT in this compose stack" in runbook or "MISP is NOT in the compose" in runbook, (
            "RUNBOOK must explicitly note that MISP is NOT a compose service"
        )

    def test_kill_switch_table_has_three_entries(self):
        """Pre-PR-N18 only 2 kill-switches were documented. PR-N14
        added a third (EDGEGUARD_EARLIEST_IOC_DATE) that was missing
        from the table."""
        runbook = self._runbook()
        assert "EDGEGUARD_RESPECT_CALIBRATOR" in runbook
        assert "EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION" in runbook
        assert "EDGEGUARD_EARLIEST_IOC_DATE" in runbook, "PR-N14 earliest-date env var must be in kill-switch table"

    def test_top_6_failure_modes_present(self):
        """Pre-PR-N18 had Top-5. Adding PR-N15 batch-permanent-failure
        makes 6."""
        runbook = self._runbook()
        for mode in [
            "MISP batch permanent failure",
            "MISP sustained backoff",
            "Honest-NULL violation",
            "Neo4j ineffective-batch",
            "Neo4j batch PERMANENT failure",
            "Placeholder-name MERGE spike",
        ]:
            assert mode in runbook, f"Top-6 failure mode missing: {mode!r}"

    def test_post_run_validation_queries_include_pr_n14_checks(self):
        """Post-run validation should check PR-N14 clamp regression."""
        runbook = self._runbook()
        assert "cvss_score > 10" in runbook, "CVSS range check should be part of post-run validation (PR-N14 Fix #1)"
        assert "confidence_score > 1" in runbook, "confidence range check (PR-N14 Fix #2)"


# ===========================================================================
# Part C — placeholder-reject counter declared + wired
# ===========================================================================


class TestPartCPlaceholderRejectCounter:
    def test_counter_declared_in_metrics_server(self):
        src = (SRC / "metrics_server.py").read_text()
        assert "MERGE_REJECT_PLACEHOLDER = Counter(" in src
        assert '"edgeguard_merge_reject_placeholder_total"' in src
        # Bounded labels only — label (Malware/ThreatActor), source.
        idx = src.find("MERGE_REJECT_PLACEHOLDER = Counter(")
        block = src[idx : idx + 1500]
        assert '["label", "source"]' in block, "counter labels must be bounded (label + source; no event_id / uuid)"

    def test_counter_imported_with_graceful_fallback(self):
        src = (SRC / "neo4j_client.py").read_text()
        assert "MERGE_REJECT_PLACEHOLDER as _MERGE_REJECT_PLACEHOLDER" in src
        # None-fallback on ImportError (PR-N9/N10 pattern).
        assert "_MERGE_REJECT_PLACEHOLDER = None" in src

    def test_merge_malware_emits_counter_on_reject(self):
        """AST pin: merge_malware's placeholder-reject branch must
        increment the counter before returning False. ``ast.unparse``
        normalizes string literals to single-quotes, so accept either
        quote style."""
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_malware":
                        body = ast.unparse(node)
                        assert "_MERGE_REJECT_PLACEHOLDER" in body, (
                            "merge_malware must emit MERGE_REJECT_PLACEHOLDER counter"
                        )
                        assert "label='Malware'" in body or 'label="Malware"' in body, "counter label must be Malware"
                        return
        raise AssertionError("merge_malware not found")

    def test_merge_actor_emits_counter_on_reject(self):
        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for cls in ast.walk(tree):
            if isinstance(cls, ast.ClassDef):
                for node in cls.body:
                    if isinstance(node, ast.FunctionDef) and node.name == "merge_actor":
                        body = ast.unparse(node)
                        assert "_MERGE_REJECT_PLACEHOLDER" in body
                        assert "label='ThreatActor'" in body or 'label="ThreatActor"' in body
                        return
        raise AssertionError("merge_actor not found")


# ===========================================================================
# Part D — Prometheus alerts
# ===========================================================================


class TestPartDPrometheusAlerts:
    def test_batch_permanent_failure_alert_exists(self):
        rule = _find_rule("EdgeGuardNeo4jBatchPermanentFailure")
        assert rule["labels"]["severity"] == "critical"
        assert "edgeguard_neo4j_batch_permanent_failure_total" in rule["expr"]
        # Bounded labels only in the group_by.
        assert "reason" in rule["expr"]

    def test_placeholder_reject_spike_alert_exists(self):
        rule = _find_rule("EdgeGuardMergeRejectPlaceholderSpike")
        assert rule["labels"]["severity"] == "warning"
        # Uses increase() not rate() (per-window threshold, not per-second)
        assert "increase(edgeguard_merge_reject_placeholder_total" in rule["expr"]
        # Threshold > 10 per 15min
        assert "> 10" in rule["expr"]

    def test_no_orphan_alert_references_in_alerts_yml(self):
        """PR-N12 test_every_alert_references_existing_metric caught
        the placeholder-counter gap. Re-verify after PR-N18 — every
        alert must reference a metric that exists."""
        import re

        metrics_src = (SRC / "metrics_server.py").read_text()
        alerts = _load_alerts()
        for group in alerts["groups"]:
            for rule in group.get("rules", []):
                if "alert" not in rule:
                    continue
                expr = rule["expr"]
                counter_names = re.findall(r"edgeguard_\w+_total", expr)
                for counter in counter_names:
                    assert counter in metrics_src, f"alert {rule['alert']!r} references undeclared counter {counter!r}"


# ===========================================================================
# Part E — in-tree TODO markers for deferred items
# ===========================================================================


class TestPartEDeferredItemsHaveInTreeTodos:
    def test_aliases_hijack_todo_in_q2_branch_3(self):
        """Red-Team BLOCK #19 (aliases attribution hijack) was deferred
        to post-baseline. The Q2 branch-3 Cypher must have an inline
        TODO so the deferral survives team rotation."""
        src = (SRC / "build_relationships.py").read_text()
        # Find Q2 branch 3 area — match the toLower(trim(a.name))
        # IN [x IN coalesce(m.aliases ...] pattern.
        idx = src.find("toLower(trim(a.name)) IN [x IN coalesce(m.aliases")
        assert idx != -1, "Q2 branch 3 not found at expected location"
        # Search upward for the TODO.
        block = src[max(0, idx - 2000) : idx + 500]
        assert "TODO" in block and "Red-Team" in block, (
            "aliases attribution hijack (BLOCK #19) must have an inline "
            "TODO marker near Q2 branch 3 so deferral survives rotation"
        )

    def test_execute_write_migration_todo_in_retry_decorator(self):
        """The ``execute_write`` migration was flagged as deferred
        by the coverage audit. Must have an inline TODO in the
        retry decorator docstring."""
        src = (SRC / "neo4j_client.py").read_text()
        idx = src.find("def retry_with_backoff(")
        assert idx != -1
        block = src[idx : idx + 3000]
        assert "execute_write" in block and "TODO" in block, (
            "execute_write migration deferral must have an inline TODO in retry_with_backoff docstring"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_metrics_server_exports_new_counter(self):
        from metrics_server import MERGE_REJECT_PLACEHOLDER  # noqa: F401

    def test_neo4j_client_imports_with_new_counter(self):
        import neo4j_client  # noqa: F401

    def test_cli_helper_is_exported(self):
        from neo4j_client import _cli_bootstrap_sources  # noqa: F401

    def test_alerts_yaml_valid(self):
        _load_alerts()  # raises on invalid YAML
