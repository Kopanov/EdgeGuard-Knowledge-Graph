#!/usr/bin/env python3
"""
EdgeGuard Prometheus Metrics Server

Exposes Prometheus metrics for EdgeGuard threat intelligence pipeline.
Can run as standalone server or embedded thread.

Metrics exposed:
- edgeguard_indicators_collected_total - Total indicators collected by source/zone
- edgeguard_collection_failures_total - Collection failures by source
- edgeguard_collection_duration_seconds - Collection duration histogram
- edgeguard_misp_events_total - MISP events by source
- edgeguard_misp_attributes_total - MISP attributes by type
- edgeguard_neo4j_nodes - Neo4j node counts by label
- edgeguard_neo4j_relationships - Neo4j relationship counts
- edgeguard_neo4j_sync_duration_seconds - Neo4j sync duration
- edgeguard_circuit_breaker_state - Circuit breaker state (0=closed, 1=half-open, 2=open)
- edgeguard_service_up - Service health (1=up, 0=down)
- edgeguard_last_success_timestamp - Unix timestamp of last successful collection
- edgeguard_pipeline_duration_seconds - Total pipeline duration
- edgeguard_dag_runs_total - DAG run counter by status
- edgeguard_source_truthful_claim_accepted_total - Source-truthful timestamp claim accepted (per source + field)
- edgeguard_source_truthful_claim_dropped_total - Source-truthful timestamp claim dropped (per source + reason + field)
- edgeguard_source_truthful_coerce_rejected_total - coerce_iso input rejected (per failure-mode reason)
- edgeguard_source_truthful_future_clamp_total - Future-dated timestamp clamped to now()
- edgeguard_source_truthful_creator_rejected_total - Tag-impersonation rejection (per source + reason; chip 5e)
"""

import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Dict, Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Prometheus client
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    raise ImportError("prometheus_client not installed. Run: pip install prometheus_client")

# Import existing metrics from resilience module
from resilience import PROMETHEUS_AVAILABLE as RESILIENCE_PROMETHEUS_AVAILABLE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ================================================================================
# METRICS REGISTRY - EdgeGuard Metrics
# ================================================================================

# Use the default registry to include resilience.py metrics
registry = REGISTRY

# Application info
APP_INFO = Info("edgeguard", "EdgeGuard application information")

# Collection metrics
INDICATORS_COLLECTED = Counter(
    "edgeguard_indicators_collected_total", "Total indicators collected", ["source", "zone", "status"]
)

COLLECTOR_SKIPS = Counter(
    "edgeguard_collector_skips_total",
    "Collector skipped (optional source, e.g. missing API key) — task still succeeded",
    ["source", "reason_class"],
)

COLLECTION_DURATION = Histogram(
    "edgeguard_collection_duration_seconds",
    "Time spent collecting indicators",
    ["source", "zone"],
    buckets=[0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
)

# MISP metrics
MISP_EVENTS = Counter("edgeguard_misp_events_total", "Total MISP events created", ["source", "zone"])

MISP_ATTRIBUTES = Counter("edgeguard_misp_attributes_total", "Total MISP attributes created", ["type", "source"])

# PR #33 round 13: dropped-attribute counter for the dedup pre-stage. Surfaces
# silent-skip rate: any spike in a particular reason class (missing_cve_id,
# missing_key) is a data-quality signal worth alerting on.
MISP_ATTRIBUTES_DROPPED = Counter(
    "edgeguard_misp_attributes_dropped_total",
    "MISP attributes dropped during dedup/parse — by reason",
    ["reason"],
)

# PR #34 round 18: counter for unmapped MISP attribute types. Each MISP
# attribute type that EdgeGuard's mapping doesn't recognize falls into the
# "unknown" bucket; this counter surfaces the type-name distribution so an
# operator can see when MISP adds a new type and EdgeGuard's mapping needs
# to catch up.
MISP_UNMAPPED_ATTRIBUTE_TYPES = Counter(
    "edgeguard_misp_unmapped_attribute_types_total",
    "MISP attribute types not in EdgeGuard's mapping — by type name",
    ["attr_type"],
)

# Chip 5e — defense-in-depth against MISP tag impersonation. Counter
# fires when ``extract_source_truthful_timestamps`` drops a claim
# because the parent event's creator org is NOT on the EdgeGuard
# trust allowlist (env vars EDGEGUARD_TRUSTED_MISP_ORG_UUIDS /
# EDGEGUARD_TRUSTED_MISP_ORG_NAMES). A non-zero rate is the operator
# signal for an active impersonation attempt OR a misconfigured
# allowlist (e.g. operator forgot to add the EdgeGuard collector
# org's UUID after a MISP migration).
SOURCE_TRUTHFUL_CREATOR_REJECTED = Counter(
    "edgeguard_source_truthful_creator_rejected_total",
    "Source-truthful claim rejected because the parent MISP event's "
    "creator org is not on the EdgeGuard trust allowlist (chip 5e). "
    "Reason label is bounded — see source_trust.py for the enum.",
    ["source_id", "reason"],
    # reason ∈ {creator_org_not_allowlisted, creator_org_missing}.
    # The other source_trust reasons (trust_check_disabled,
    # creator_org_in_uuid_allowlist, creator_org_in_name_allowlist)
    # are NOT rejection reasons and therefore never appear here.
)

MISP_PUSH_DURATION = Histogram(
    "edgeguard_misp_push_duration_seconds",
    "Time spent pushing to MISP",
    ["source"],
    buckets=[0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
)

# PR-N4: permanent batch failure after exhausting MISPWriter's
# @retry_with_backoff(max_retries=4) on 5xx. The on-call report from
# Bravo Vanko on 2026-04-21 had 7 OTX + 16 NVD batches × 500 attrs ≈
# 11,500 attrs silently dropped during a 730-day baseline; Bravo had
# to hand-count from the logs because no metric existed. A non-zero
# rate is the operator signal that MISP backend is undersized for the
# current event size — see docs/MISP_TUNING.md for the tuning playbook.
#
# PR-N4 round 2 (Maintainer Dev #4, Bug Hunter #4): label set is
# ``["source"]`` only. ``event_id`` was dropped because each MISP run
# creates a new event (date-stamped name like ``EdgeGuard-otx-2026-04-21``),
# which would balloon the time-series cardinality by ~365/year per source
# (12 sources × 365 days = ~4.4K series/year just from this metric).
# The actionable signal for operators is "is source X dropping batches?",
# which ``source`` alone provides; the specific event_id is recoverable
# from logs.
MISP_PUSH_PERMANENT_FAILURES = Counter(
    "edgeguard_misp_push_permanent_failure_total",
    "MISP batch pushes that failed permanently after retry exhaustion. "
    "Each increment = one batch (typically 500 attributes) lost. "
    "See docs/MISP_TUNING.md for ops tuning playbook.",
    ["source"],
)

# PR-N4: adaptive backoff trigger — fires when the writer enters
# extended-pause mode after N consecutive 5xx failures. Lets operators
# distinguish "occasional flap MISP is recovering from" from "MISP is
# sustained-degraded and we're throttling ourselves down."
MISP_PUSH_BACKOFF_TRIGGERED = Counter(
    "edgeguard_misp_push_backoff_triggered_total",
    "Number of times MISPWriter entered extended-cooldown mode after "
    "N consecutive HTTP 5xx batch failures (default N=3, see "
    "EDGEGUARD_MISP_BACKOFF_THRESHOLD).",
    ["source"],
)

# PR-N5 C7: honest-NULL invariant violation counter. Fires when
# MISPWriter's runtime validator spots an incoming item whose
# ``first_seen`` / ``last_seen`` is suspiciously close to wall-clock
# NOW (default ±5 min heuristic in ``_validate_honest_null``) —
# a strong signal that a collector is manufacturing NOW() substitutes
# instead of honoring the PR-M2 honest-NULL contract. Source-only
# label keeps cardinality bounded (same reasoning as PR-N4 round 2:
# ``event_id`` would explode time-series count).
MISP_HONEST_NULL_VIOLATIONS = Counter(
    "edgeguard_misp_honest_null_violation_total",
    "Count of MISPWriter items flagged as violating the honest-NULL "
    "invariant (first_seen / last_seen within ±5 min of wall-clock NOW, "
    "a strong proxy for 'collector manufactured a NOW substitute instead "
    "of passing NULL through'). Non-zero rate on a source indicates the "
    "collector needs auditing.",
    ["source", "field"],
)

MISP_HEALTH = Gauge("edgeguard_misp_health", "MISP health status (1=healthy, 0=unhealthy)", ["check_type"])

# Neo4j metrics
NEO4J_NODES = Gauge("edgeguard_neo4j_nodes", "Number of nodes in Neo4j by label", ["label", "zone"])

NEO4J_RELATIONSHIPS = Gauge("edgeguard_neo4j_relationships", "Number of relationships in Neo4j by type", ["rel_type"])

NEO4J_SYNC_DURATION = Histogram(
    "edgeguard_neo4j_sync_duration_seconds",
    "Time spent syncing MISP to Neo4j",
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)

# PR-N12 (pre-baseline audit Fix #1, 2026-04-21): dedicated gauge for the
# last successful MISP→Neo4j sync wall-clock. Pre-PR-N12 the
# EdgeGuardNeo4jSyncStale alert used the nonsensical expression
# ``time() - (edgeguard_neo4j_sync_duration_seconds_count > 0) > 259200``
# which subtracted a histogram COUNT (e.g. 42) from current time; the
# alert was permanently firing or permanently silent depending on eval
# semantics. Either way it carried no signal. This gauge is written on
# every successful sync completion and read by the alert as
# ``time() - edgeguard_neo4j_sync_last_success_timestamp > 259200``.
NEO4J_SYNC_LAST_SUCCESS = Gauge(
    "edgeguard_neo4j_sync_last_success_timestamp",
    "Unix timestamp (seconds) of the last successful MISP→Neo4j sync "
    "completion. Used by EdgeGuardNeo4jSyncStale alert. Set on every "
    "successful run of MISPToNeo4jSync.run() after counters are flushed.",
)

# Distribution of accumulator-list sizes on Neo4j nodes/relationships.
# Sampled periodically (NOT per-write) — see ``record_neo4j_list_dedup_size``
# in this module and the ``scrape_list_dedup_sizes`` helper in neo4j_client.
#
# Why we measure: the apoc.coll.toSet → native-Cypher migration plan
# includes Phase 3, which flips ``_dedup_concat_clause`` internals from
# ``apoc.coll.toSet(...)`` to a native ``CASE WHEN $x IN coalesce(...)``
# pattern. The pure-``reduce()`` alternative is O(n²) — at p99=500 list
# size on a 350K-relationship build_relationships pass that adds ~22 min
# (per the prod-readiness audit). To know whether we can ship Phase 3
# safely we need the live distribution: if our actual p99 is 20, the
# perf concern is moot; if it's 500+, we must use the O(n) CASE form
# (which is exact only for append-of-one — most callsites — but breaks
# subtly for two-list merges).
#
# Buckets are tuned for the threat-intel list shapes:
#   1, 5, 10 — typical n.source / r.sources
#   25, 50   — typical n.tags / n.misp_event_ids on cold indicators
#   100, 250 — hot indicators across many MISP events
#   500, 1000, 2500 — worst-case OTX hot-IPs across the 2-year baseline
NEO4J_LIST_DEDUP_SIZE = Histogram(
    "edgeguard_neo4j_list_dedup_size",
    "Sampled distribution of list sizes on dedup-accumulator properties "
    "(n.source, n.misp_event_ids, r.sources, r.misp_event_ids, etc). "
    "Periodic sample, not per-write. Used to size the eventual native-Cypher "
    "replacement for apoc.coll.toSet (see neo4j_client._dedup_concat_clause).",
    ["label_or_type", "prop"],
    buckets=[1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500],
)

# Per-run sync accounting. Gauges (not counters) so they reset each run
# and alerts can fire on the CURRENT run's damage, not cumulative history.
# Added after the 2026-04-14 NVD regression where a single MISP 500 dropped
# ~99K CVEs silently: events_failed stayed 0 because the accounting bug
# never recorded the skipped event, so no alert fired. Exporting these
# three invariants (processed + failed + index_total) lets a coverage-gap
# alert catch that exact silent-skip pattern.
SYNC_EVENTS_PROCESSED = Gauge(
    "edgeguard_sync_events_processed",
    "Events successfully processed in the most recent MISP->Neo4j sync run",
)

SYNC_EVENTS_FAILED = Gauge(
    "edgeguard_sync_events_failed",
    "Events that failed in the most recent MISP->Neo4j sync run (after all retries)",
)

SYNC_EVENTS_INDEX_TOTAL = Gauge(
    "edgeguard_sync_events_index_total",
    "Total events returned by MISP events index for the most recent sync run",
)

# PR-I (2026-04-20 multi-agent audit Red Team #4): MISP tag-impersonation
# defense can be configured OFF (both allowlists empty). Prior to PR-I,
# that state was signalled only by a startup log line that fired ONLY in
# prod/staging — which silently accepted the default dev env.  This
# gauge mirrors the defense's configured state at metrics-server boot:
#
#   value 0 → defense ENABLED (at least one allowlist populated)
#   value 1 → defense DISABLED (all source-truthful claims accepted)
#
# Suggested alert rule (see docs/PROMETHEUS_SETUP.md):
#
#   ALERT EdgeGuardMispTagImpersonationDefenseDisabled
#     IF edgeguard_misp_tag_impersonation_defense_disabled == 1
#     FOR 5m
#     LABELS { severity="warning" }
#
# Labelless by design: alert rules care about "is it on?", not
# "what kind of allowlist?". If operators later need config-audit
# gauges (count of trusted uuids / names, per-env breakdown), those
# land as separate metrics — one gauge per question.
MISP_TAG_IMPERSONATION_DEFENSE_DISABLED = Gauge(
    "edgeguard_misp_tag_impersonation_defense_disabled",
    "MISP tag-impersonation defense: 1 = disabled (all source claims accepted "
    "without creator-org verification), 0 = enabled. Set EDGEGUARD_TRUSTED_MISP_ORG_UUIDS "
    "and/or EDGEGUARD_TRUSTED_MISP_ORG_NAMES to enable. See docs/SECURITY_ROADMAP.md.",
)


def _initialize_misp_defense_gauge() -> None:
    """Populate the MISP_TAG_IMPERSONATION_DEFENSE_DISABLED gauge from
    source_trust's current state. Called once at module load.

    The gauge reflects env-var state AT METRICS-SERVER BOOT; an operator
    who changes the env vars must restart the metrics-server process
    for the gauge to update. This matches the semantics of every other
    config-derived gauge in this file (e.g. NEO4J_POOL_SIZE, which is
    also read-once-at-boot). Documented in docs/SECURITY_ROADMAP.md.
    """
    try:
        from source_trust import is_trust_check_configured
    except ImportError:  # pragma: no cover — defensive; source_trust is always present
        # source_trust module not available in the environment metrics
        # is running in — safer to report ``disabled`` so operators
        # notice that something is off than to stay silent.
        MISP_TAG_IMPERSONATION_DEFENSE_DISABLED.set(1)
        return
    MISP_TAG_IMPERSONATION_DEFENSE_DISABLED.set(0 if is_trust_check_configured() else 1)


_initialize_misp_defense_gauge()

NEO4J_QUERIES = Counter("edgeguard_neo4j_queries_total", "Total Neo4j queries executed", ["query_type", "status"])

NEO4J_QUERY_DURATION = Histogram(
    "edgeguard_neo4j_query_duration_seconds",
    "Time spent on Neo4j queries",
    ["query_type"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
)

# PR-N9 B6 (audit 09 Prod Readiness #2): ineffective-batch counter —
# fires when ``merge_indicators_batch`` / ``merge_vulnerabilities_batch``
# runs a non-empty batch that produces ZERO counter-visible writes
# (no nodes_created, nodes_updated, properties_set, rels_created or
# rels_updated). The typical silent-failure causes are:
#
#  * Source node missing (the SOURCED_FROM MATCH inside the UNWIND
#    returns zero rows; the per-row edge MERGE never runs)
#  * Constraint violation on the primary MERGE key (write rejected
#    silently; caller still returns ``len(batch)`` as success_count)
#  * Schema mismatch or broken Cypher
#
# Labels are bounded: ``label`` is one of the static node labels
# (Indicator / Vulnerability / …), ``source`` is the per-source
# identifier (otx / nvd / misp / …). No unbounded cardinality axes.
# Alerting: ``rate(edgeguard_neo4j_merge_ineffective_batch_total[5m])
# > 0`` for 5 min → write path is silently dropping edges.
NEO4J_MERGE_INEFFECTIVE_BATCH = Counter(
    "edgeguard_neo4j_merge_ineffective_batch_total",
    "Non-empty Neo4j MERGE batches that produced ZERO counter-visible "
    "writes (no nodes / rels / properties touched). Indicates silent-"
    "write failure — missing prerequisite Source, constraint violation, "
    "or schema drift. Non-zero rate is an operator-actionable signal.",
    ["label", "source"],
)

# PR-N15 (2026-04-21 pre-baseline audit Fix #2 + #3): permanent-failure
# counter for ``merge_indicators_batch`` / ``merge_vulnerabilities_batch``
# batches that either (a) raised a non-retryable exception or (b)
# exhausted the retry budget on transient errors. Pre-PR-N15 these
# counted as anonymous error_count + one WARN log line — no metric,
# so Prometheus alerting was blind to silent data loss.
#
# Over a 730d baseline with ~30 sync cycles, a 5-second Neo4j GC pause
# mid-NVD-sync dropped 1000 CVEs per batch: thousands of nodes silently
# lost without any operator signal beyond post-hoc log greps. This
# counter makes that failure mode alertable.
#
# Labels are bounded: ``label`` is a static node label (Indicator /
# Vulnerability), ``source`` is the per-source identifier (otx / nvd
# / …), ``reason`` is the enum {``non_retryable``, ``retries_exhausted``}.
# Alerting (intended in a follow-up alert PR):
# ``rate(edgeguard_neo4j_batch_permanent_failure_total[5m]) > 0`` for
# 5 min = silent-data-loss in progress — pause ingest + investigate.
NEO4J_BATCH_PERMANENT_FAILURES = Counter(
    "edgeguard_neo4j_batch_permanent_failure_total",
    "Neo4j MERGE batches that failed permanently after retry exhaustion "
    "(retries_exhausted) or non-retryable exception (non_retryable). "
    "Each increment = one batch (up to BATCH_SIZE items) lost. "
    "See docs/RUNBOOK.md § Neo4j silent-write failures.",
    ["label", "source", "reason"],
)

# Pipeline metrics
PIPELINE_DURATION = Histogram(
    "edgeguard_pipeline_duration_seconds",
    "Total pipeline execution time",
    ["pipeline_type"],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)

PIPELINE_ERRORS = Counter("edgeguard_pipeline_errors_total", "Total pipeline errors", ["task", "error_type", "source"])

PIPELINE_STAGES = Gauge("edgeguard_pipeline_stage", "Current pipeline stage (1=running, 0=idle)", ["stage"])

# DAG/Airflow metrics
DAG_RUNS = Counter("edgeguard_dag_runs_total", "Total DAG runs", ["dag_id", "status", "run_type"])

# Stuck-run detection: set to time.time() on success, alert if stale
DAG_LAST_SUCCESS = Gauge(
    "edgeguard_dag_last_success_timestamp",
    "Unix timestamp of last successful DAG run (0 = never succeeded)",
    ["dag_id"],
)

DAG_RUN_START = Gauge(
    "edgeguard_dag_run_start_timestamp",
    "Unix timestamp when the current DAG run started (0 = idle)",
    ["dag_id"],
)

DAG_RUN_DURATION = Histogram(
    "edgeguard_dag_run_duration_seconds",
    "DAG run duration",
    ["dag_id"],
    buckets=[30.0, 60.0, 120.0, 300.0, 600.0, 1200.0],
)

TASK_DURATION = Histogram(
    "edgeguard_task_duration_seconds",
    "Individual task duration",
    ["task_id", "dag_id"],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
)

# Data source health
SOURCE_HEALTH = Gauge(
    "edgeguard_source_health", "Data source health status (1=healthy, 0=unhealthy)", ["source", "zone"]
)

SOURCE_LATENCY = Histogram(
    "edgeguard_source_latency_seconds",
    "Data source response latency",
    ["source"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

# Processing metrics
INDICATORS_PROCESSED = Counter(
    "edgeguard_indicators_processed_total",
    "Total indicators processed (enriched, transformed)",
    ["operation", "status"],
)

ENRICHMENT_DURATION = Histogram(
    "edgeguard_enrichment_duration_seconds",
    "Time spent enriching indicators",
    ["enricher_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

# ================================================================================
# Source-truthful timestamp pipeline (PR #41 follow-up)
# ================================================================================
# Counters that surface how the per-source first_seen / last_seen pipeline
# (src/source_truthful_timestamps.py) is performing in production. Without
# them an operator has no visibility into:
#  - which sources actually supply the values vs. emit honest-NULL
#  - the failure-mode distribution of coerce_iso (sentinel epochs vs.
#    malformed strings vs. overflow)
#  - upstream feed bugs producing future-dated timestamps
# Cardinality budget: ~16 sources × {first_seen, last_seen, both} × small
# reason set ≈ low hundreds of cells; well within Prometheus comfort.

SOURCE_TRUTHFUL_CLAIM_ACCEPTED = Counter(
    "edgeguard_source_truthful_claim_accepted_total",
    "Source-truthful timestamp claim accepted onto the SOURCED_FROM edge — by source + field. "
    "Incremented exactly once per (extract call, field) when the final post-Layer-2 value is non-NULL.",
    ["source_id", "field"],  # field ∈ {first_seen, last_seen}
)

SOURCE_TRUTHFUL_CLAIM_DROPPED = Counter(
    "edgeguard_source_truthful_claim_dropped_total",
    "Source-truthful timestamp claim dropped — by source + reason + field. "
    "honest-NULL drops (source on the allowlist but supplied no value) ARE counted here under "
    "reason=no_data_from_source — operators looking at total_dropped should expect a non-zero baseline.",
    ["source_id", "reason", "field"],
    # reason ∈ {
    #   "source_not_in_allowlist",  # caller's source not on the reliable list (Layer 1 filter)
    #   "no_data_from_source",      # source on the list but Layer 1 + Layer 2 both empty (honest-NULL)
    # }
    # field: first_seen / last_seen — "both" is used for the single
    # source_not_in_allowlist emit (we never even attempt per-field).
)

SOURCE_TRUTHFUL_COERCE_REJECTED = Counter(
    "edgeguard_source_truthful_coerce_rejected_total",
    "coerce_iso input rejected — by failure-mode reason. No source_id label: coerce_iso is a "
    "pure utility called from many sites (STIX exporter, alert processor, etc.) without source context.",
    ["reason"],
    # reason ∈ {
    #   "sentinel_epoch",    # int/float ≤ 0 or > epoch ceil
    #   "malformed_string",  # non-ISO / invalid calendar / non-ASCII / parse failure
    #   "overflow",          # OverflowError / OSError from datetime.fromtimestamp
    # }
)

SOURCE_TRUTHFUL_FUTURE_CLAMP = Counter(
    "edgeguard_source_truthful_future_clamp_total",
    "Future-dated timestamp clamped to now() — likely upstream feed bug or operator clock drift. "
    "The corresponding WARNING log carries the original value for triage.",
    [],
)

# Set application info
APP_INFO.info(
    {"version": os.getenv("EDGEGUARD_VERSION", "1.0.0"), "environment": os.getenv("EDGEGUARD_ENV", "development")}
)

# ================================================================================
# HELPER FUNCTIONS
# ================================================================================


def record_collection(source: str, zone: str, count: int, status: str = "success"):
    """Record indicator collection."""
    INDICATORS_COLLECTED.labels(source=source, zone=zone, status=status).inc(count)


def record_collector_skip(source: str, reason_class: str = "missing_api_key"):
    """Record that an optional collector was skipped (e.g. no API key)."""
    safe = (reason_class or "unknown").replace('"', "")[:80]
    COLLECTOR_SKIPS.labels(source=source, reason_class=safe).inc()


def record_collection_duration(source: str, zone: str, duration: float):
    """Record collection duration."""
    COLLECTION_DURATION.labels(source=source, zone=zone).observe(duration)


def record_misp_push(source: str, zone: str, event_count: int, attr_count: int, duration: float):
    """Record MISP push metrics."""
    MISP_EVENTS.labels(source=source, zone=zone).inc(event_count)
    MISP_PUSH_DURATION.labels(source=source).observe(duration)


def record_misp_attribute(indicator_type: str, source: str):
    """Record MISP attribute creation."""
    MISP_ATTRIBUTES.labels(type=indicator_type, source=source).inc()


def record_misp_attribute_dropped(reason: str, count: int = 1):
    """Record an attribute dropped during dedup/parse — see MISP_ATTRIBUTES_DROPPED."""
    safe = (reason or "unknown").replace('"', "")[:80]
    MISP_ATTRIBUTES_DROPPED.labels(reason=safe).inc(count)


# ----------------------------------------------------------------------------
# Source-truthful timestamp pipeline helpers (see SOURCE_TRUTHFUL_* counters)
# ----------------------------------------------------------------------------
# These are imported defensively from src/source_truthful_timestamps.py so
# they tolerate import failures (tests that don't bring up prometheus_client,
# etc.). The counters themselves are always-on once this module imports.

# Allowlist used to keep the source_id label cardinality bounded. Anything
# outside the list collapses to "<other>" so a malformed / surprise tag
# can't blow up Prometheus storage.
#
# Composition is two-part:
#   1. RELIABLE — every entry in
#      ``source_truthful_timestamps._RELIABLE_FIRST_SEEN_SOURCES``
#      (mirrored byte-for-byte; see test
#      ``test_source_label_allowlist_mirrors_reliable_first_seen_sources``
#      that pins parity).
#   2. REJECTED-ON-PURPOSE — relays we deliberately exclude from the
#      reliable allowlist but still want metric visibility for so
#      operators can SEE the rejection rate as signal, not silence.
#
# PR #42 audit M1 (Cross-Checker): the previous hand-maintained
# allowlist drifted from ``_RELIABLE_FIRST_SEEN_SOURCES`` — it
# included ``sslbl`` even though no source emits that tag (the
# canonical SSL-Blacklist tags are ``ssl_blacklist`` /
# ``abusech_ssl``). Drift was silent: the sslbl cell was dead and a
# future source added to the reliable allowlist would have collapsed
# into ``<other>`` until somebody remembered to update both files.
_REJECTED_ON_PURPOSE_SOURCES: frozenset[str] = frozenset(
    {
        "otx",
        "alienvault_otx",
        "cybercure",
        "misp",
    }
)


def _build_source_label_allowlist() -> frozenset[str]:
    """Compose the metrics allowlist from the source-truthful module.

    Lazy + late-bound so the import order (``metrics_server`` ←
    ``source_truthful_timestamps``) doesn't form a cycle: the
    source-truthful module imports ``record_*`` functions from us,
    so we cannot import ``_RELIABLE_FIRST_SEEN_SOURCES`` at
    module-load time. By the time any caller hits
    ``_safe_source_label``, the source-truthful module is already
    fully imported (the call only fires from inside its
    ``extract_source_truthful_timestamps`` body).
    """
    try:
        from source_truthful_timestamps import _RELIABLE_FIRST_SEEN_SOURCES
    except ImportError:  # pragma: no cover — defensive
        return _REJECTED_ON_PURPOSE_SOURCES
    return frozenset(_RELIABLE_FIRST_SEEN_SOURCES) | _REJECTED_ON_PURPOSE_SOURCES


# Module-level cache: built lazily on first call. ``None`` sentinel
# means "not yet initialized"; ``frozenset()`` would be the empty
# allowlist which is a different state (every source → ``<other>``).
#
# CRITICAL: this MUST be lazy. ``source_truthful_timestamps`` imports
# the ``record_*`` helpers from this module. If we eagerly build the
# allowlist at import time, Python's circular-import handling returns
# a half-initialized ``metrics_server`` to ``source_truthful_timestamps``
# — its defensive ``try/except ImportError`` catches the missing
# names and silently installs no-op shims. The metrics never fire.
# Lazy build avoids that: by the time ``_source_label_allowlist`` is
# called from inside ``_safe_source_label``, both modules are fully
# loaded and the import succeeds.
_SOURCE_LABEL_ALLOWLIST_CACHE: frozenset[str] | None = None


def _source_label_allowlist() -> frozenset[str]:
    """Return the cached allowlist; build on first call."""
    global _SOURCE_LABEL_ALLOWLIST_CACHE
    if _SOURCE_LABEL_ALLOWLIST_CACHE is None:
        _SOURCE_LABEL_ALLOWLIST_CACHE = _build_source_label_allowlist()
    return _SOURCE_LABEL_ALLOWLIST_CACHE


def _safe_source_label(source_id: str | None) -> str:
    """Coerce a source_id to a bounded-cardinality Prometheus label.

    ``None`` / empty → ``"<unknown>"``; anything outside the allowlist →
    ``"<other>"``. Caps Prometheus storage at ~20 source labels rather
    than allowing an unbounded set of malformed / spoofed tags.
    """
    if not source_id:
        return "<unknown>"
    norm = source_id.strip().lower()
    if not norm:
        return "<unknown>"
    # Use the lazy lookup so a hypothetical late binding of
    # source_truthful_timestamps still resolves correctly. Falls back
    # to the eagerly-built constant if the module-level cache has
    # already settled.
    return norm if norm in _source_label_allowlist() else "<other>"


# PR #42 audit M2 (Bug Hunter): bounded enums for ``reason`` labels on
# the source-truthful counters. Without these, a future caller could
# pass an unbounded string and blow up Prometheus cardinality —
# Prometheus stores ONE time series per unique label combination, so
# even one ``reason=<random uuid>`` per call would O(N) explode the
# memory footprint over time. PR #42 audit M3 (Logic Tracker): the
# ``field`` label gets the same treatment for the same reason, plus
# the historical ``"both"`` value was dropped when source_not_in_allowlist
# switched to per-field emit (see source_truthful_timestamps.py).
_VALID_DROP_REASONS: frozenset[str] = frozenset({"source_not_in_allowlist", "no_data_from_source"})
_VALID_COERCE_REASONS: frozenset[str] = frozenset({"sentinel_epoch", "malformed_string", "overflow"})
_VALID_FIELD_LABELS: frozenset[str] = frozenset({"first_seen", "last_seen"})


def _safe_enum_label(value: str | None, valid: frozenset[str]) -> str:
    """Clamp a label value to a known enum; unknown → ``<other>``.

    Empty / None → ``<unknown>`` (operator-distinguishable from
    ``<other>``: the former is missing data, the latter is an
    out-of-band reason value worth investigating).
    """
    if not value:
        return "<unknown>"
    norm = value.strip().lower()[:80].replace('"', "")
    if not norm:
        return "<unknown>"
    return norm if norm in valid else "<other>"


def record_source_truthful_claim_accepted(source_id: str | None, field: str) -> None:
    """Record a source-truthful claim that survived the full pipeline.

    Called from ``extract_source_truthful_timestamps`` exactly once per
    (call, field) when the final post-Layer-2 value is non-NULL.
    """
    SOURCE_TRUTHFUL_CLAIM_ACCEPTED.labels(
        source_id=_safe_source_label(source_id),
        field=_safe_enum_label(field, _VALID_FIELD_LABELS),
    ).inc()


def record_source_truthful_claim_dropped(source_id: str | None, reason: str, field: str) -> None:
    """Record a source-truthful claim that did NOT make it onto the edge.

    Called from ``extract_source_truthful_timestamps`` for two distinct
    reasons (source_not_in_allowlist / no_data_from_source). Honest-NULL
    drops are counted here under ``no_data_from_source`` — operators
    monitoring this counter should expect a non-zero baseline.
    """
    SOURCE_TRUTHFUL_CLAIM_DROPPED.labels(
        source_id=_safe_source_label(source_id),
        reason=_safe_enum_label(reason, _VALID_DROP_REASONS),
        field=_safe_enum_label(field, _VALID_FIELD_LABELS),
    ).inc()


def record_source_truthful_coerce_rejected(reason: str) -> None:
    """Record a coerce_iso input that the input-hardening layer refused.

    Called from inside ``coerce_iso`` itself — pure utility, no source
    context available. The reason label IS bounded
    (sentinel_epoch / malformed_string / overflow); see the counter
    definition for the full enum.
    """
    SOURCE_TRUTHFUL_COERCE_REJECTED.labels(
        reason=_safe_enum_label(reason, _VALID_COERCE_REASONS),
    ).inc()


def record_source_truthful_future_clamp() -> None:
    """Record one future-dated timestamp clamp (likely feed bug / clock drift).

    The accompanying WARNING log carries the original value for triage.
    """
    SOURCE_TRUTHFUL_FUTURE_CLAMP.inc()


def record_source_truthful_creator_rejected(source_id: str | None, reason: str) -> None:
    """Record a source-truthful claim rejected by the chip 5e creator-org check.

    Wired from ``source_truthful_timestamps.extract_source_truthful_timestamps``
    when the parent event's creator org fails the EdgeGuard trust
    allowlist. Operators MUST alert on a non-zero rate for any
    allowlisted source — that signal is either an active spoofing
    attempt OR a misconfigured allowlist (e.g. forgot to register a
    new EdgeGuard collector org's UUID after a MISP migration).

    PR #44 audit M6 (Maintainer Dev): clamp ``reason`` to the bounded
    rejection enum from ``source_trust``. Unknown reason values
    collapse to ``<other>`` rather than create new Prometheus cells —
    catches a future TRUST_REASON_* rename that forgets to update
    this counter's label semantics.
    """
    # Lazy import to avoid the module-load circular (source_trust
    # itself does NOT depend on metrics_server, but keeping the
    # import lazy is defensive against future changes).
    try:
        from source_trust import TRUST_REASON_CREATOR_MISSING, TRUST_REASON_NOT_ALLOWLISTED

        valid_rejection_reasons = frozenset({TRUST_REASON_NOT_ALLOWLISTED, TRUST_REASON_CREATOR_MISSING})
    except ImportError:  # pragma: no cover — defensive
        valid_rejection_reasons = frozenset({"creator_org_not_allowlisted", "creator_org_missing"})

    safe_source = (source_id or "<unknown>").strip().lower()[:80] or "<unknown>"
    norm_reason = (reason or "").strip().lower()[:80].replace('"', "")
    safe_reason = norm_reason if norm_reason in valid_rejection_reasons else "<other>"
    SOURCE_TRUTHFUL_CREATOR_REJECTED.labels(source_id=safe_source, reason=safe_reason).inc()


def record_misp_unmapped_attribute_type(attr_type: str, count: int = 1):
    """Record a MISP attribute type that EdgeGuard's mapping doesn't recognize.

    See MISP_UNMAPPED_ATTRIBUTE_TYPES — surfaces silent fall-through to the
    'unknown' bucket so operators see when MISP adds a new type.
    """
    safe = (attr_type or "<empty>").replace('"', "")[:80]
    MISP_UNMAPPED_ATTRIBUTE_TYPES.labels(attr_type=safe).inc(count)


def record_neo4j_sync(node_counts: Dict[str, int], duration: float):
    """Record Neo4j sync metrics.

    PR-N12 (2026-04-21): also stamp ``NEO4J_SYNC_LAST_SUCCESS`` with
    the current wall-clock so ``EdgeGuardNeo4jSyncStale`` has a real
    signal to alert on. Called at the END of a sync, so a crashed
    sync does NOT update the gauge (which is exactly the behaviour the
    staleness alert needs)."""
    NEO4J_SYNC_DURATION.observe(duration)
    NEO4J_SYNC_LAST_SUCCESS.set(time.time())
    for label, count in node_counts.items():
        zone = "unknown"
        if ":" in label:
            label, zone = label.split(":", 1)
        NEO4J_NODES.labels(label=label, zone=zone).set(count)


def record_sync_event_accounting(
    events_index_total: int,
    events_processed: int,
    events_failed: int,
) -> None:
    """Export the per-run event accounting so alerts can catch silent skips.

    The invariant ``events_index_total == events_processed + events_failed``
    is what would have caught the 2026-04-14 NVD regression (event 4 was
    neither processed nor failed — it was silently dropped, and the counter
    gap stayed hidden because nothing exported the numbers).
    """
    SYNC_EVENTS_INDEX_TOTAL.set(max(events_index_total, 0))
    SYNC_EVENTS_PROCESSED.set(max(events_processed, 0))
    SYNC_EVENTS_FAILED.set(max(events_failed, 0))


def record_neo4j_relationships(rel_counts: Dict[str, int]):
    """Record Neo4j relationship counts."""
    for rel_type, count in rel_counts.items():
        NEO4J_RELATIONSHIPS.labels(rel_type=rel_type).set(count)


def record_neo4j_list_dedup_size(label_or_type: str, prop: str, size: int) -> None:
    """Observe one sample of a dedup-accumulator list size.

    See ``NEO4J_LIST_DEDUP_SIZE`` for rationale. ``label_or_type`` is the
    node label (``"Indicator"``) or relationship type (``"INDICATES"``)
    that owns the property; both are normalized to bounded short strings
    to keep Prometheus cardinality finite. ``prop`` is the property name
    (``"misp_event_ids"``, ``"sources"``, etc).

    Negative or non-int sizes are silently dropped — the scrape helper
    in neo4j_client filters NULLs upstream, so a non-int here would be a
    programming error rather than data quality.
    """
    if not isinstance(size, int) or size < 0:
        return
    safe_lt = (label_or_type or "<unknown>").strip()[:80] or "<unknown>"
    safe_prop = (prop or "<unknown>").strip()[:80] or "<unknown>"
    NEO4J_LIST_DEDUP_SIZE.labels(label_or_type=safe_lt, prop=safe_prop).observe(size)


def record_pipeline_duration(pipeline_type: str, duration: float):
    """Record pipeline execution duration."""
    PIPELINE_DURATION.labels(pipeline_type=pipeline_type).observe(duration)


def record_pipeline_error(task: str, error_type: str, source: str = "unknown"):
    """Record pipeline error."""
    PIPELINE_ERRORS.labels(task=task, error_type=error_type, source=source).inc()


def record_dag_run(dag_id: str, status: str, run_type: str = "scheduled"):
    """Record DAG run."""
    DAG_RUNS.labels(dag_id=dag_id, status=status, run_type=run_type).inc()


def record_task_duration(task_id: str, dag_id: str, duration: float):
    """Record task execution duration."""
    TASK_DURATION.labels(task_id=task_id, dag_id=dag_id).observe(duration)


def set_source_health(source: str, zone: str, healthy: bool):
    """Set source health status."""
    SOURCE_HEALTH.labels(source=source, zone=zone).set(1 if healthy else 0)


def record_source_latency(source: str, latency: float):
    """Record source response latency."""
    SOURCE_LATENCY.labels(source=source).observe(latency)


def set_misp_health(api_healthy: bool, db_healthy: bool, workers_healthy: bool):
    """Set MISP health status."""
    MISP_HEALTH.labels(check_type="api").set(1 if api_healthy else 0)
    MISP_HEALTH.labels(check_type="database").set(1 if db_healthy else 0)
    MISP_HEALTH.labels(check_type="workers").set(1 if workers_healthy else 0)


def set_pipeline_stage(stage: str, running: bool):
    """Set pipeline stage status."""
    PIPELINE_STAGES.labels(stage=stage).set(1 if running else 0)


def record_indicators_processed(operation: str, count: int, status: str = "success"):
    """Record processed indicators."""
    INDICATORS_PROCESSED.labels(operation=operation, status=status).inc(count)


def record_enrichment_duration(enricher_type: str, duration: float):
    """Record enrichment duration."""
    ENRICHMENT_DURATION.labels(enricher_type=enricher_type).observe(duration)


def get_all_metrics() -> bytes:
    """Get all metrics in Prometheus format."""
    return generate_latest(registry)


# ================================================================================
# HTTP SERVER
# ================================================================================


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    allow_reuse_address = True
    daemon_threads = True


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Prometheus metrics."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        logger.debug(f"{self.address_string()} - {format % args}")

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(get_all_metrics())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            health_status = {
                "status": "healthy",
                "timestamp": time.time(),
                "metrics_enabled": True,
                "resilience_metrics": RESILIENCE_PROMETHEUS_AVAILABLE,
            }
            self.wfile.write(json.dumps(health_status).encode())
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <head><title>EdgeGuard Metrics</title></head>
                <body>
                <h1>EdgeGuard Prometheus Metrics</h1>
                <p><a href="/metrics">Metrics</a></p>
                <p><a href="/health">Health Check</a></p>
                </body>
                </html>
            """)
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests."""
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


# ================================================================================
# SERVER CLASSES
# ================================================================================


class MetricsServer:
    """
    Standalone Prometheus metrics server for EdgeGuard.

    Usage:
        # Standalone mode
        server = MetricsServer(port=8001)
        server.start()

        # Embedded mode (as thread)
        server = MetricsServer(port=8001)
        server.start_threaded()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8001):
        self.host = host
        self.port = port
        self.server: Optional[ThreadedHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the metrics server (blocking)."""
        try:
            self.server = ThreadedHTTPServer((self.host, self.port), MetricsHandler)
        except OSError as e:
            logger.error(f"Cannot start metrics server on {self.host}:{self.port}: {e}")
            logger.error("Port may be in use. Pipeline will continue without metrics.")
            return
        self._running = True
        logger.info(f"Prometheus metrics server starting on http://{self.host}:{self.port}")
        logger.info(f"  - Metrics: http://{self.host}:{self.port}/metrics")
        logger.info(f"  - Health:  http://{self.host}:{self.port}/health")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down metrics server...")
            self.stop()

    def start_threaded(self) -> threading.Thread:
        """Start the metrics server in a separate thread (non-blocking)."""
        try:
            self.server = ThreadedHTTPServer((self.host, self.port), MetricsHandler)
        except OSError as e:
            logger.error(f"Cannot start metrics server on {self.host}:{self.port}: {e}")
            logger.error("Port may be in use. Pipeline will continue without metrics.")
            return None
        self._running = True

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        logger.info(f"Prometheus metrics server started in thread on http://{self.host}:{self.port}")
        logger.info(f"  - Metrics: http://{self.host}:{self.port}/metrics")
        logger.info(f"  - Health:  http://{self.host}:{self.port}/health")

        return self.thread

    def stop(self):
        """Stop the metrics server."""
        self._running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Metrics server stopped")

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


# ================================================================================
# SINGLETON INSTANCE
# ================================================================================

_server_instance: Optional[MetricsServer] = None


def get_metrics_server(host: str = None, port: int = None) -> MetricsServer:
    """
    Get or create the singleton metrics server instance.

    Usage:
        server = get_metrics_server(port=8001)
        server.start_threaded()  # Start in background thread
    """
    global _server_instance

    if _server_instance is None:
        host = host or os.getenv("EDGEGUARD_METRICS_HOST", "127.0.0.1")
        if port is None:
            try:
                port = int(os.getenv("EDGEGUARD_METRICS_PORT", "8001"))
            except (ValueError, TypeError):
                port = 8001
        _server_instance = MetricsServer(host=host, port=port)

    return _server_instance


def start_metrics_server(host: str = None, port: int = None, threaded: bool = True) -> Optional[MetricsServer]:
    """
    Convenience function to start the metrics server.

    Args:
        host: Bind host (default: 127.0.0.1)
        port: Bind port (default: 8001)
        threaded: If True, start in background thread; if False, block

    Returns:
        MetricsServer instance if threaded, None if blocking
    """
    server = get_metrics_server(host, port)

    if threaded:
        server.start_threaded()
        return server
    else:
        server.start()
        return None


# ================================================================================
# MAIN
# ================================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="EdgeGuard Prometheus Metrics Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Bind port (default: 8001)")
    parser.add_argument("--test-metrics", action="store_true", help="Generate test metrics")

    args = parser.parse_args()

    # Generate test metrics if requested
    if args.test_metrics:
        logger.info("Generating test metrics...")

        # Simulate some data
        for source in ["otx", "nvd", "cisa", "misp", "abuseipdb"]:
            record_collection(source, "global", 100, "success")
            record_collection(source, "global", 5, "failed")
            set_source_health(source, "global", True)
            record_collection_duration(source, "global", 5.0)
            record_misp_push(source, "global", 10, 100, 2.0)

        # Neo4j metrics
        record_neo4j_sync({"Indicator": 5000, "Threat": 500, "Sector": 10, "Country": 200}, 30.0)

        # Circuit breaker metrics (through resilience module)
        from resilience import CIRCUIT_BREAKER_STATE

        CIRCUIT_BREAKER_STATE.labels(service="otx").set(0)
        CIRCUIT_BREAKER_STATE.labels(service="nvd").set(0)

        logger.info("Test metrics generated")

    # Start server (blocking mode)
    logger.info("Starting EdgeGuard Metrics Server...")
    server = MetricsServer(host=args.host, port=args.port)
    server.start()
