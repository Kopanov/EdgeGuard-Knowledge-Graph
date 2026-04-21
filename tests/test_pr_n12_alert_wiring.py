"""
PR-N12 — pre-baseline alert-wiring bundle.

Five BLOCK-severity findings from the pre-baseline 7-agent audit's
Observability pass. Each was silently dead (alert never fires) and
would have left on-call blind during the 730-day baseline.

## Fix #1 — ``EdgeGuardNeo4jSyncStale`` nonsensical expr

Prior expr ``time() - (edgeguard_neo4j_sync_duration_seconds_count > 0)
> 259200`` subtracted a Histogram ``_count`` (int like 42) from current
time, producing either a permanently-firing or permanently-silent alert
depending on eval semantics. Either way it carried no signal.

Fix: new dedicated ``NEO4J_SYNC_LAST_SUCCESS`` gauge
(``edgeguard_neo4j_sync_last_success_timestamp``) stamped at the end
of every successful sync via ``record_neo4j_sync()``. Alert now reads
``time() - edgeguard_neo4j_sync_last_success_timestamp > 259200 and
<gauge> > 0``.

## Fix #2 — ``EdgeGuardContainerRestartLoop`` nonexistent metric

Prior expr referenced ``container_restart_count{...}`` which cAdvisor
does NOT export (that name is from kubelet). Alert was silently inert.

Fix: use cAdvisor's ``container_start_time_seconds`` with
``changes()`` over a window, OR kubelet's
``kube_pod_container_status_restarts_total`` if a kubelet scrape is
present. Both covered via PromQL ``or``; harmless when one of the two
scrape jobs isn't configured.

## Fix #3 — ``EdgeGuardCollectionHighFailureRate`` NaN denominator

Prior denominator ``rate(collected) > 0`` DROPPED the series when rate
was zero — producing no-result (undefined ratio) exactly when the
collector had stopped producing anything, which is the scenario the
alert is meant to catch.

Fix: denominator = ``rate(collected) + rate(failed)`` (total attempts),
``clamp_min(..., 0.001)`` to avoid 0/0, plus an explicit
``rate(failed) > 0`` guard so a collector doing nothing at all doesn't
trigger a meaningless alert (covered by EdgeGuardNoIndicatorsCollected).

## Fix #4 — Collector staleness coverage audit (regression pin only)

The audit claimed ``edgeguard_last_success_timestamp`` was set for only
3 of 11 collectors. The claim was WRONG — the central dispatcher at
``dags/edgeguard_pipeline.py:755`` calls
``set_last_success_timestamp(collector_name)`` on every successful
collection, covering ALL registered collectors. This test pins the
dispatcher wiring so a future refactor that drops the call surfaces
immediately (preventing the audit's hypothetical from becoming real).

## Fix #5 — ``EdgeGuardNoIndicatorsCollected`` label mismatch + hard-coded allow-list

Two bugs in the prior expr:
- LHS ``sum by (source)`` dropped the ``zone`` label while RHS
  ``edgeguard_source_health`` kept it → PromQL ``and`` found no match
  → alert was silent.
- Hard-coded regex ``source=~"otx|nvd|cisa|abuseipdb"`` silently
  excluded every new source (ThreatFox, URLhaus, CyberCure, Feodo,
  SSLBL, MITRE, MISP federated, …).

Fix: collapse both sides via ``and on (source)``; drop the allow-list.
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

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n12")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n12")


def _load_alerts() -> dict:
    alerts_yaml = (REPO_ROOT / "prometheus" / "alerts.yml").read_text()
    return yaml.safe_load(alerts_yaml)


def _find_rule(alert_name: str) -> dict:
    alerts = _load_alerts()
    for group in alerts["groups"]:
        for rule in group.get("rules", []):
            if rule.get("alert") == alert_name:
                return rule
    raise AssertionError(f"alert {alert_name!r} not found in prometheus/alerts.yml")


# ===========================================================================
# Fix #1 — EdgeGuardNeo4jSyncStale fixed + dedicated gauge
# ===========================================================================


class TestFix1NeoSyncStale:
    def test_new_gauge_declared_in_metrics_server(self):
        """NEO4J_SYNC_LAST_SUCCESS must be a Gauge exporting
        ``edgeguard_neo4j_sync_last_success_timestamp``."""
        src = (SRC / "metrics_server.py").read_text()
        assert "NEO4J_SYNC_LAST_SUCCESS" in src, "gauge variable missing"
        assert '"edgeguard_neo4j_sync_last_success_timestamp"' in src, "prometheus metric name missing"
        # Must be a Gauge — not a Counter (Counters don't support .set)
        assert "NEO4J_SYNC_LAST_SUCCESS = Gauge(" in src

    def test_record_neo4j_sync_stamps_gauge(self):
        """On every successful sync, ``record_neo4j_sync`` must stamp
        the gauge with current wall-clock. Pin via AST so a refactor
        that drops the call surfaces."""
        import ast

        src = (SRC / "metrics_server.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "record_neo4j_sync":
                body_src = ast.unparse(node)
                assert "NEO4J_SYNC_LAST_SUCCESS.set(" in body_src, (
                    "record_neo4j_sync must stamp NEO4J_SYNC_LAST_SUCCESS"
                )
                return
        raise AssertionError("record_neo4j_sync function not found")

    def test_alert_uses_new_gauge_not_histogram_count(self):
        """Regression pin: the prior expr subtracted
        ``edgeguard_neo4j_sync_duration_seconds_count`` (a histogram
        count int) from ``time()``. Must not happen again."""
        rule = _find_rule("EdgeGuardNeo4jSyncStale")
        expr = rule["expr"]
        assert "edgeguard_neo4j_sync_last_success_timestamp" in expr, "must use the new last-success timestamp gauge"
        assert "edgeguard_neo4j_sync_duration_seconds_count" not in expr, (
            "regression: must NOT subtract histogram _count from time()"
        )
        # Must also guard against `> 0` so fresh instances (gauge = 0)
        # don't trigger spurious alerts before the first sync.
        assert "> 0" in expr, "must guard against gauge == 0 (pre-first-sync)"


# ===========================================================================
# Fix #2 — ContainerRestartLoop uses a metric that actually exists
# ===========================================================================


class TestFix2ContainerRestartLoopMetric:
    def test_alert_no_longer_uses_nonexistent_metric(self):
        rule = _find_rule("EdgeGuardContainerRestartLoop")
        expr = rule["expr"]
        assert "container_restart_count" not in expr, "regression: container_restart_count is NOT exported by cAdvisor"

    def test_alert_uses_cadvisor_or_kubelet_metric(self):
        """Accept either cAdvisor's ``container_start_time_seconds``
        (via ``changes()``) or kubelet's
        ``kube_pod_container_status_restarts_total`` (via
        ``increase()``). Deployment may have either or both."""
        rule = _find_rule("EdgeGuardContainerRestartLoop")
        expr = rule["expr"]
        uses_cadvisor = "container_start_time_seconds" in expr
        uses_kubelet = "kube_pod_container_status_restarts_total" in expr
        assert uses_cadvisor or uses_kubelet, "must reference a metric that a real Prometheus target exports"

    def test_kubelet_branch_normalizes_container_label_to_name(self):
        """Cursor-bugbot 2026-04-21 Low: cAdvisor labels the container as
        `name`; kubelet labels it as `container`. If the kubelet branch
        fires without a label rewrite, the annotation renders
        `{{ $labels.name }}` as empty string. `label_replace` must copy
        the kubelet `container` into `name` so both branches populate
        the annotation uniformly."""
        rule = _find_rule("EdgeGuardContainerRestartLoop")
        expr = rule["expr"]
        # The kubelet branch must be wrapped in label_replace that
        # copies `container` into `name`.
        if "kube_pod_container_status_restarts_total" in expr:
            assert "label_replace(" in expr, (
                "kubelet branch needs label_replace to normalize `container` → `name` "
                "so the annotation `{{ $labels.name }}` isn't empty"
            )
            assert '"name"' in expr and '"container"' in expr, "label_replace must target `name` from `container`"


# ===========================================================================
# Fix #3 — CollectionHighFailureRate denominator is NaN-safe
# ===========================================================================


class TestFix3CollectionHighFailureRateDenominator:
    def test_denominator_cannot_be_undefined_when_collector_silent(self):
        """Prior expr used ``rate(collected) > 0`` as denominator, which
        drops the series when the rate is zero — producing a
        NO-RESULT vector exactly when the collector has stopped. The
        fix puts total ATTEMPTS in the denominator (collected + failed)
        with ``clamp_min`` to avoid division-by-zero."""
        rule = _find_rule("EdgeGuardCollectionHighFailureRate")
        expr = rule["expr"]
        # Must use clamp_min or explicit > 0 denominator guard
        assert "clamp_min(" in expr, "denominator must use clamp_min to handle zero-rate case; got {expr!r}"
        # Total attempts in denominator = collected + failed
        assert "rate(edgeguard_indicators_collected_total" in expr
        assert "rate(edgeguard_collection_failures_total" in expr

    def test_denominator_does_not_use_zero_filter_pattern(self):
        """The `> 0` filter on the denominator is the specific bug —
        ensure it's not back in any form."""
        rule = _find_rule("EdgeGuardCollectionHighFailureRate")
        expr = rule["expr"]
        # The `> 0` filter on `rate(collected)` as denominator was the bug.
        # The fix uses clamp_min instead. The expr may still have `> 0`
        # for the guard on failures > 0 — that's fine.
        # Count occurrences — at most one (for the failures > 0 guard).
        import re

        zero_filters = re.findall(r"rate\([^)]+\)\s*>\s*0", expr)
        assert len(zero_filters) <= 1, (
            f"too many `rate(...) > 0` filters ({len(zero_filters)}); the denominator-filter bug may be back"
        )


# ===========================================================================
# Fix #4 — Collector staleness dispatcher coverage (regression pin)
# ===========================================================================


class TestFix4DispatcherCoversAllCollectors:
    """The central dispatcher at ``dags/edgeguard_pipeline.py``
    ``run_collector_with_metrics`` calls ``set_last_success_timestamp``
    on every successful collection. This writes the
    ``edgeguard_last_success_timestamp`` gauge the
    ``EdgeGuardCollectionStale`` alert depends on. Pin the wiring."""

    def test_dispatcher_calls_set_last_success_timestamp(self):
        """AST pin: `set_last_success_timestamp(collector_name)` must
        appear inside `run_collector_with_metrics` (the central
        dispatcher)."""
        import ast

        src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "run_collector_with_metrics":
                body_src = ast.unparse(node)
                assert "set_last_success_timestamp(" in body_src, (
                    "central dispatcher must stamp the last-success gauge on "
                    "every successful collector run — regression would break "
                    "EdgeGuardCollectionStale alert for all collectors"
                )
                return
        raise AssertionError("run_collector_with_metrics not found in dags/edgeguard_pipeline.py")

    def test_set_last_success_timestamp_writes_the_expected_gauge(self):
        """The function must write to the ``LAST_SUCCESS`` gauge
        (exported as ``edgeguard_last_success_timestamp``) — the same
        gauge the ``EdgeGuardCollectionStale`` alert watches."""
        import ast

        src = (REPO_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "set_last_success_timestamp":
                body_src = ast.unparse(node)
                assert "LAST_SUCCESS.labels" in body_src, "must write to the LAST_SUCCESS gauge"
                assert ".set(time.time())" in body_src, "must stamp wall-clock seconds"
                return
        raise AssertionError("set_last_success_timestamp not found")

    def test_collection_stale_alert_watches_the_same_metric(self):
        """Close the loop: the alert reads the metric the dispatcher
        writes."""
        rule = _find_rule("EdgeGuardCollectionStale")
        expr = rule["expr"]
        assert "edgeguard_last_success_timestamp" in expr, "alert must read the gauge the dispatcher writes"


# ===========================================================================
# Fix #5 — NoIndicatorsCollected label set matches + no hard-coded allow-list
# ===========================================================================


class TestFix5NoIndicatorsCollectedLabelMatch:
    def test_label_sets_match_on_source(self):
        """The two halves of the ``and`` must join on ``source`` via
        ``on (source)`` — otherwise the different label sets on LHS
        (source) vs RHS (source, zone) produce no matches."""
        rule = _find_rule("EdgeGuardNoIndicatorsCollected")
        expr = rule["expr"]
        assert "on (source)" in expr, (
            "the vector `and` must explicitly join on `source` — without this, label-set mismatch silences the alert"
        )

    def test_no_hard_coded_source_allowlist(self):
        """The prior expr hard-coded
        ``source=~"otx|nvd|cisa|abuseipdb"``, silently excluding every
        new collector. Drop the allow-list; let ``source_health`` scope
        to pipeline-known sources."""
        rule = _find_rule("EdgeGuardNoIndicatorsCollected")
        expr = rule["expr"]
        assert 'source=~"otx|nvd|cisa|abuseipdb"' not in expr, (
            "hard-coded source allow-list re-introduced; would silently "
            "exclude ThreatFox, URLhaus, CyberCure, Feodo, SSLBL, MITRE, …"
        )

    def test_both_sides_reduced_to_source_only(self):
        """LHS and RHS both aggregate by `source` so `and on (source)`
        has matching label sets. RHS uses `max by (source)` (not `sum`)
        to correctly handle multi-zone healthy sources — see
        test_source_health_uses_max_not_sum below."""
        rule = _find_rule("EdgeGuardNoIndicatorsCollected")
        expr = rule["expr"]
        assert "sum by (source)" in expr, "LHS must sum indicator rates by source"
        assert "max by (source)" in expr, "RHS must max source_health by source"

    def test_source_health_uses_max_not_sum(self):
        """Cursor-bugbot 2026-04-21 Medium: `sum by (source)
        (edgeguard_source_health) == 1` silently fails when a source
        is emitted in multiple zones (e.g. OTX healthy in both `global`
        and `healthcare` → sum == 2, not 1). That reintroduces the same
        silent-alert class Fix #5 was meant to eliminate. `max by
        (source) == 1` correctly captures "healthy in ANY zone"."""
        rule = _find_rule("EdgeGuardNoIndicatorsCollected")
        expr = rule["expr"]
        assert "max by (source) (edgeguard_source_health)" in expr, (
            "edgeguard_source_health must be aggregated with max by (source), "
            "not sum — sum == 1 fails on multi-zone healthy sources"
        )
        assert "sum by (source) (edgeguard_source_health)" not in expr, (
            "regression: sum by (source) on source_health reintroduces the multi-zone silent-alert bug"
        )


# ===========================================================================
# Alerts file overall sanity
# ===========================================================================


class TestAlertsFileSanity:
    def test_alerts_yaml_is_valid(self):
        """The edits must leave the file as valid YAML + a valid
        Prometheus rules document (groups → rules → alert/expr/for)."""
        alerts = _load_alerts()
        assert "groups" in alerts
        for group in alerts["groups"]:
            assert "name" in group
            assert "rules" in group
            for rule in group["rules"]:
                assert "alert" in rule or "record" in rule, f"every rule must have `alert` or `record`: {rule}"
                if "alert" in rule:
                    assert "expr" in rule
                    assert "labels" in rule
                    assert "severity" in rule["labels"]

    def test_all_five_fixed_alerts_still_present(self):
        """Regression: the 5 alerts PR-N12 fixed must still exist after
        any future edits."""
        for alert_name in [
            "EdgeGuardNeo4jSyncStale",
            "EdgeGuardContainerRestartLoop",
            "EdgeGuardCollectionHighFailureRate",
            "EdgeGuardCollectionStale",
            "EdgeGuardNoIndicatorsCollected",
        ]:
            _find_rule(alert_name)  # raises if missing
