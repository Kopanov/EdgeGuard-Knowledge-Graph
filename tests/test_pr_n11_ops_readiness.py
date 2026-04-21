"""
PR-N11 — ops-readiness bundle.

Pre-PR-N11 gaps flagged by the 7-agent pre-baseline audit
Prod-Readiness pass:

1. PR-N4/N5/N9 metrics exist but no Prometheus alert fires. Counters
   were visible in Grafana but not actionable — on-call would not be
   paged on silent data loss or sustained MISP backoff. PR-N11 adds a
   new ``edgeguard_pipeline_observability`` rule group in
   ``prometheus/alerts.yml`` with 4 rules (placeholder-reject alert
   deferred to PR-N12 — see below).

2. No kill-switch for PR-N9 B6 ``_record_batch_counters``. If the
   counter inspection itself turned out to have a bug mid-baseline
   (driver API drift, double-consume), on-call had no way to disable
   it without a code revert. PR-N11 adds
   ``EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION`` env kill-switch.

3. No on-call runbook — the five failure modes observed during the
   pre-PR-N7 730d baseline had no documented remediation. PR-N11 ships
   ``docs/RUNBOOK.md`` v0 covering top-5 modes + kill-switch reference.

Note: the PR-N10 placeholder-reject alert
(``edgeguard_merge_reject_placeholder_total``) requires a Prometheus
counter that isn't wired yet. That alert + its counter land atomically
in PR-N12. This test suite intentionally verifies the alert is NOT
present in PR-N11 so the deferral is explicit.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n11")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n11")


# ===========================================================================
# Fix #1 — Prometheus alert rules wired for PR-N4 / PR-N5 / PR-N9 metrics
# ===========================================================================


class TestFix1AlertRulesWired:
    """Alert rule group ``edgeguard_pipeline_observability`` must exist
    in ``prometheus/alerts.yml`` with 4 rules, each expr referencing a
    metric that actually exists in ``src/metrics_server.py``."""

    def _rules(self) -> dict:
        alerts_yaml = (REPO_ROOT / "prometheus" / "alerts.yml").read_text()
        parsed = yaml.safe_load(alerts_yaml)
        for group in parsed["groups"]:
            if group["name"] == "edgeguard_pipeline_observability":
                return group
        raise AssertionError("edgeguard_pipeline_observability group missing from alerts.yml")

    def test_rule_group_exists(self):
        group = self._rules()
        assert group["name"] == "edgeguard_pipeline_observability"
        assert "rules" in group

    def test_four_rules_present(self):
        """Placeholder-reject alert deferred to PR-N12 so exactly 4 rules."""
        group = self._rules()
        names = {rule["alert"] for rule in group["rules"]}
        assert names == {
            "EdgeGuardMispBatchPermanentFailure",
            "EdgeGuardMispSustainedBackoff",
            "EdgeGuardMispHonestNullViolation",
            "EdgeGuardNeo4jIneffectiveBatch",
        }, f"unexpected rule set: {names}"

    def test_placeholder_alert_deferred_not_present(self):
        """PR-N12 follow-up adds this; must not be in PR-N11 without
        the counter wire."""
        group = self._rules()
        names = {rule["alert"] for rule in group["rules"]}
        assert "EdgeGuardMergeRejectPlaceholder" not in names, (
            "Placeholder-reject alert requires edgeguard_merge_reject_placeholder_total "
            "counter (not wired yet); must not ship in PR-N11"
        )

    def test_every_alert_references_existing_metric(self):
        """Each alert's expr must reference a counter defined in
        metrics_server.py. Prevents shipping alerts against counters
        that don't exist — a Prom-side silence."""
        metrics_src = (SRC / "metrics_server.py").read_text()
        group = self._rules()
        for rule in group["rules"]:
            expr = rule["expr"]
            # Extract the counter name (anything ending in _total inside rate())
            import re

            counter_names = re.findall(r"edgeguard_\w+_total", expr)
            assert counter_names, f"alert {rule['alert']!r} expr references no counter: {expr}"
            for counter in counter_names:
                assert counter in metrics_src, (
                    f"alert {rule['alert']!r} references counter {counter!r} "
                    f"that is not defined in src/metrics_server.py"
                )

    def test_every_alert_has_bounded_labels(self):
        """Per Prometheus guidance, alert expr should group by
        bounded-cardinality labels (source, label), not high-cardinality
        ones (user_id, event_id, etc.). Regression pin."""
        group = self._rules()
        forbidden = {"event_id", "user_id", "indicator_id", "attribute_id", "uuid", "trace_id"}
        for rule in group["rules"]:
            expr = rule["expr"]
            for label in forbidden:
                assert label not in expr, (
                    f"alert {rule['alert']!r} groups by forbidden high-cardinality label {label!r}"
                )

    def test_absolute_count_thresholds_use_increase_not_rate(self):
        """Cursor-bugbot 2026-04-21 (HIGH x2): a threshold expressed as
        an absolute count over a window (e.g. ">1/15min", ">100/hr")
        must use ``increase()``, not ``rate()``. ``rate()`` returns the
        per-SECOND average, so ``rate(...[15m]) > 1`` means >1/sec =
        >900/15min, 900x the intended threshold.

        The two alerts whose annotations document a per-window
        threshold (sustained-backoff > 1/15min, honest-NULL > 100/hr)
        must both use ``increase()``. The two that use ``rate(...) > 0``
        are fine — a non-zero per-second rate IS a non-zero count.
        """
        group = self._rules()
        # Map: alert name → expected functor.
        expected_functor = {
            "EdgeGuardMispBatchPermanentFailure": "rate",  # > 0 is fine
            "EdgeGuardMispSustainedBackoff": "increase",  # > 1/15min
            "EdgeGuardMispHonestNullViolation": "increase",  # > 100/hr
            "EdgeGuardNeo4jIneffectiveBatch": "rate",  # > 0 is fine
        }
        for rule in group["rules"]:
            name = rule["alert"]
            expected = expected_functor.get(name)
            if expected is None:
                continue
            expr = rule["expr"]
            # The functor must appear immediately before the counter
            # name inside parentheses, e.g. "increase(edgeguard_..."
            expected_pattern = f"{expected}(edgeguard_"
            assert expected_pattern in expr, (
                f"alert {name!r} must use {expected}() (not the other functor) — expr={expr!r}"
            )
            # And must NOT use the wrong functor with a counter.
            other = "rate" if expected == "increase" else "increase"
            wrong_pattern = f"{other}(edgeguard_"
            assert wrong_pattern not in expr, (
                f"alert {name!r} uses {other}() on the counter but should use {expected}() — "
                f"likely per-second vs per-window confusion"
            )


# ===========================================================================
# Fix #2 — EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION kill-switch
# ===========================================================================


class TestFix2CounterInspectionKillSwitch:
    """PR-N9 B6 ``_record_batch_counters`` honors
    ``EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION``."""

    def test_helper_reads_env_var(self):
        """Function body must check the env var before touching the
        result object. AST-level pin so a future refactor doesn't drop
        the check."""
        import ast

        src = (SRC / "neo4j_client.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_record_batch_counters":
                body_src = ast.unparse(node)
                assert "EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION" in body_src, (
                    "_record_batch_counters must check the disable env var"
                )
                return
        raise AssertionError("_record_batch_counters not found in neo4j_client.py")

    def test_module_load_logs_once_when_kill_switch_active(self, monkeypatch, caplog):
        """Cursor-bugbot 2026-04-21 Medium: the docstring promises a
        module-load WARN log when the kill-switch is active. Without it,
        an on-call operator who flips the switch has no log confirmation
        the flag took effect. The helper
        ``_log_merge_counter_inspection_kill_switch_once`` emits a
        single WARNING containing ``[KILL-SWITCH-ACTIVE]``."""
        import logging

        import neo4j_client

        monkeypatch.setenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", "1")
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            # Call the helper directly; importlib.reload would re-import
            # the whole module (slow + has side effects). The helper is
            # the unit under test, and it's called unconditionally at
            # module import, so invoking it mirrors the import-time path.
            neo4j_client._log_merge_counter_inspection_kill_switch_once()
        assert any("[KILL-SWITCH-ACTIVE]" in r.message for r in caplog.records), (
            "kill-switch activation must emit the [KILL-SWITCH-ACTIVE] WARN"
        )
        assert any("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION" in r.message for r in caplog.records), (
            "log line must name the env var so operators can grep for it"
        )

    def test_module_load_silent_when_kill_switch_unset(self, monkeypatch, caplog):
        """Default (kill-switch OFF) must NOT log — otherwise every
        process-start WARNs, polluting the log."""
        import logging

        import neo4j_client

        monkeypatch.delenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", raising=False)
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            neo4j_client._log_merge_counter_inspection_kill_switch_once()
        assert not any("[KILL-SWITCH-ACTIVE]" in r.message for r in caplog.records), (
            "must not emit WARN when kill-switch is inactive"
        )

    def test_kill_switch_short_circuits(self, monkeypatch):
        """Setting the env var to 1/true/yes/on makes the helper return
        without touching result.consume()."""
        # Build a MagicMock that would raise if touched
        from unittest.mock import MagicMock

        from neo4j_client import _record_batch_counters

        for enable_val in ("1", "true", "yes", "on", "TRUE", "On"):
            monkeypatch.setenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", enable_val)
            bomb = MagicMock()
            bomb.consume.side_effect = RuntimeError(
                "kill-switch failed: helper should have no-op'd before touching result"
            )
            # Must not raise
            _record_batch_counters(label="Indicator", source_id="otx", batch_len=10, result=bomb)
            bomb.consume.assert_not_called()

    def test_default_keeps_inspection_active(self, monkeypatch):
        """Unset or empty-value env → helper proceeds as normal."""
        from unittest.mock import MagicMock

        from neo4j_client import _record_batch_counters

        monkeypatch.delenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", raising=False)

        # result.consume() must be called. Build a mock that returns a
        # counters namespace with the expected attrs.
        counters_mock = MagicMock()
        counters_mock.nodes_created = 5
        counters_mock.nodes_deleted = 0
        counters_mock.relationships_created = 0
        counters_mock.relationships_deleted = 0
        counters_mock.properties_set = 10
        result_mock = MagicMock()
        result_mock.consume.return_value.counters = counters_mock

        _record_batch_counters(label="Indicator", source_id="otx", batch_len=10, result=result_mock)
        result_mock.consume.assert_called_once()


# ===========================================================================
# Fix #3 — docs/RUNBOOK.md v0
# ===========================================================================


class TestFix3RunbookShipped:
    """``docs/RUNBOOK.md`` exists and covers the minimum set of topics
    on-call needs during a baseline run."""

    def _runbook(self) -> str:
        path = REPO_ROOT / "docs" / "RUNBOOK.md"
        assert path.exists(), "docs/RUNBOOK.md must exist for on-call"
        return path.read_text()

    def test_runbook_covers_top_5_failure_modes(self):
        runbook = self._runbook()
        required_topics = [
            "MISP batch permanent failure",
            "MISP sustained backoff",
            "Honest-NULL violation",
            "ineffective-batch",
            "Placeholder",
        ]
        for topic in required_topics:
            assert topic.lower() in runbook.lower(), f"RUNBOOK missing top-5 topic: {topic!r}"

    def test_runbook_documents_kill_switches(self):
        runbook = self._runbook()
        assert "EDGEGUARD_RESPECT_CALIBRATOR" in runbook
        assert "EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION" in runbook

    def test_runbook_has_baseline_day_protocol(self):
        runbook = self._runbook()
        assert "baseline" in runbook.lower()
        assert "7-day" in runbook or "7 day" in runbook.lower(), "RUNBOOK must reference the 7-day smoke recommendation"
