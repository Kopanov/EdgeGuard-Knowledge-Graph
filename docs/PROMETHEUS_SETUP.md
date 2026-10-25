# EdgeGuard Prometheus + Grafana Monitoring Setup

This guide covers the complete setup of Prometheus and Grafana monitoring for the EdgeGuard threat intelligence pipeline.

## Overview

The monitoring stack includes:
- **Prometheus** - Metrics collection and alerting
- **Grafana** - Visualization dashboards
- **Node Exporter** - Host system metrics (Linux only)
- **cAdvisor** - Container metrics (Linux only)
- **AlertManager** - Alert routing (optional)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EdgeGuard Monitoring Stack                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │
│  │   Airflow    │───▶│   Metrics    │───▶│  Prometheus  │              │
│  │     DAGs     │    │   Server     │    │   (9090)     │              │
│  └──────────────┘    │   (:8001)    │    └──────┬───────┘              │
│  ┌──────────────┐    └──────────────┘           │                       │
│  │  Collectors  │───────────────────────────────┤                       │
│  │  (resilience │         Scrapes /metrics      │                       │
│  │    metrics)  │                               ▼                       │
│  └──────────────┘                      ┌──────────────┐                │
│                                        │    Grafana   │                │
│                                        │   (3000)     │                │
│                                        └──────────────┘                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Start the Metrics Server

The metrics server exposes all Prometheus metrics on port **8001** (port 8000 is reserved for the FastAPI query API).

**Option A: Standalone (bare-metal, with `PROMETHEUS_MULTIPROC_DIR`)**

Set `PROMETHEUS_MULTIPROC_DIR` to a directory shared by every Airflow task process and by this
server; `python src/metrics_server.py` or `python -m src.metrics_exporter` then serves the
aggregate. Without it, the server exposes only its own process and none of the pipeline's
metrics, because each Airflow task process keeps its metrics in its own memory (Method 0 below).

```bash
# From the EdgeGuard directory
python src/metrics_server.py --port 8001

# Or with test metrics: only without PROMETHEUS_MULTIPROC_DIR, since with it the fake values
# are written to the shared directory and served as real ones
python src/metrics_server.py --port 8001 --test-metrics
```

**Option B: Docker Compose (the default)**

The `metrics` compose service serves the aggregate of every Airflow task process on
`127.0.0.1:8001` from the shared `PROMETHEUS_MULTIPROC_DIR` (Method 0 below). Nothing has to be
triggered.

**Option C: Via Dedicated Airflow DAG (bare-metal installs without `PROMETHEUS_MULTIPROC_DIR`)**

The metrics server runs as a long-lived task in the `edgeguard_metrics_server` DAG; in the Compose
deployment this DAG exits immediately because the multi-process mode is active. This avoids side effects during DAG parsing — never start the HTTP server at module level. Without `PROMETHEUS_MULTIPROC_DIR` the task serves only its own process's registry, so it exposes none of the pipeline's metrics (see *Methods 1 and 2* below).

```bash
# Trigger the metrics server DAG
airflow dags trigger edgeguard_metrics_server
```

> **Important:** Do not call `start_http_server()` at DAG module level. Airflow re-parses DAG files frequently, which would attempt to bind the port repeatedly. Always start the metrics server inside a task function.

### 2. Start Prometheus + Grafana

Start the monitoring stack together with the application stack, as one Compose project:

```bash
# Start the monitoring stack (both files in one command), with make or with Compose directly
make monitoring
# or
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d

# With host monitoring (Linux only)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml --profile host-monitoring up -d

# With alerts enabled (Alertmanager, see "Alertmanager notifications" below)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml --profile alerts up -d
```

Prometheus is attached to the application network `edgeguard_net` and scrapes the `metrics` service
by name (`metrics:8001`). The network is declared only in `docker-compose.yml`, so the monitoring
file on its own (`docker compose -f docker-compose.monitoring.yml up -d`) is rejected by Compose
before any container starts: the service "prometheus" refers to the undefined network
`edgeguard_net`. The Compose deployment does not scrape `host.docker.internal:8001`, because on
Linux that name resolves to the docker0 bridge address while the metrics port is published on
`127.0.0.1` only, so such a scrape is refused everywhere but on Docker Desktop. The `127.0.0.1:8001`
publish is for local access (`curl http://localhost:8001/metrics`).

### 3. Access the Dashboards

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (default login: admin / set via `GRAFANA_ADMIN_PASSWORD`)
- **Metrics Endpoint**: http://localhost:8001/metrics

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `EDGEGUARD_METRICS_PORT` | Metrics server port | `8001` |
| `EDGEGUARD_METRICS_HOST` | Metrics server bind host | `127.0.0.1` |
| `EDGEGUARD_ENABLE_METRICS` | Enables Prometheus metrics in the DAG on a single-process install. Ignored when `PROMETHEUS_MULTIPROC_DIR` is set (the Compose deployment), where metrics are always on | `false` |
| `EDGEGUARD_VERSION` | App version label | `1.0.0` |
| `EDGEGUARD_ENV` | Environment label | `development` |
| `GRAFANA_ADMIN_USER` | Grafana admin username | `admin` |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin password | **required** — no default in production |
| `GRAFANA_ROOT_URL` | Grafana root URL | `http://localhost:3000` |

### Prometheus Configuration

Edit `prometheus/prometheus.yml` to customize scrape targets:

```yaml
scrape_configs:
  - job_name: 'edgeguard'
    static_configs:
      - targets: ['metrics:8001']   # the `metrics` compose service, over edgeguard_net
    metrics_path: /metrics
    scrape_interval: 30s
```

Bare-metal install (metrics server on the host, Prometheus in Docker): replace the target with
`host.docker.internal:8001`. On Linux, bind the metrics server to an address the docker0 bridge
reaches (`EDGEGUARD_METRICS_HOST`); a `127.0.0.1` bind is not reachable from a container there.

### Grafana Dashboards

The EdgeGuard dashboard is automatically provisioned at:
- **Dashboards** → **EdgeGuard** → **EdgeGuard Overview**

To import manually:
1. Go to **Dashboards** → **Import**
2. Upload `grafana/dashboards/edgeguard-overview.json`
3. Select the Prometheus datasource

## Available Metrics

### Collection Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_indicators_collected_total` | Counter | `source`, `zone`, `status` | Total indicators collected. One increment per collector run. `status`: `success`, `not_modified` (HTTP 304), `skipped`, `failed` |
| `edgeguard_collector_last_run_outcome` | Gauge | `source`, `outcome` | Outcome of the source's most recent run, `1` for that outcome and `0` for the others: `collected`, `empty` (success, nothing collected), `not_modified` (HTTP 304), `skipped`, `failed` |
| `edgeguard_collection_failures_total` | Counter | `source` | Collection failures |
| `edgeguard_collection_duration_seconds` | Histogram | `source`, `zone` | Collection time |
| `edgeguard_last_success_timestamp` | Gauge | `source` | Last successful collection; also `source="misp_to_neo4j"`, stamped by the MISP→Neo4j sync |
| `edgeguard_collector_skips_total` | Counter | `source`, `reason_class` | A collector run that was skipped and succeeded: a missing key (`missing_*_key`), a provider that refused access (`*_auth_denied`), `baseline_in_progress`, `collector_disabled_by_config`, `transient_external_error`, … (read by `EdgeGuardSourceAccessDenied`) |
| `edgeguard_source_health` | Gauge | `source`, `zone` | `1` after a collector run that did not fail, `0` after a failed run or a transient-error skip (read by `EdgeGuardNoIndicatorsCollected` and `EdgeGuardSourceUnhealthy`) |

### MISP Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_misp_events_total` | Counter | `source`, `zone` | The collector result's `event_count` (1 when the result has none; no collector sets it), added after every collector run that did not fail, skipped and not-modified runs included (not after a skip while a baseline holds the baseline lock or a transient-error skip). It counts collector runs, not MISP events created |
| `edgeguard_misp_attributes_total` | Counter | `type`, `source` | Defined, but written by no code path (always absent) |
| `edgeguard_misp_push_duration_seconds` | Histogram | `source` | MISP push time |
| `edgeguard_misp_health` | Gauge | `check_type` | MISP health status |
| `edgeguard_misp_push_permanent_failure_total` | Counter | `source` | MISP batch pushes that failed after the retries; each one is a lost batch (read by `EdgeGuardMispBatchPermanentFailure`) |
| `edgeguard_misp_push_backoff_triggered_total` | Counter | `source` | Times `MISPWriter` entered its extended cooldown after consecutive HTTP 5xx batch failures (`EDGEGUARD_MISP_BACKOFF_THRESHOLD`; read by `EdgeGuardMispSustainedBackoff`) |
| `edgeguard_misp_honest_null_violation_total` | Counter | `source`, `field` | Items whose `first_seen` / `last_seen` lies within 5 minutes of the current time, a sign that the collector substituted the current time for a missing value (read by `EdgeGuardMispHonestNullViolation`) |
| `edgeguard_misp_fetch_fallback_active_total` | Counter | `branch`, `outcome` | The sync's event listing fell back to PyMISP or restSearch (`branch` = `pymisp` / `rest_search`; `outcome` = `engaged` / `hard_error`; read by `EdgeGuardMispFetchFallbackActive` and `EdgeGuardMispFetchFallbackHardError`) |
| `edgeguard_misp_event_attributes_truncated_total` | Counter | `source` | Events `MISPCollector.collect` (CLI pipeline `src/run_pipeline.py`) sliced to 500 attributes (read by `EdgeGuardMispEventAttributesTruncated`) |
| `edgeguard_misp_attributes_dropped_total` | Counter | `reason` | MISP attributes the sync dropped while parsing or de-duplicating them, by reason: `missing_cve_id`, `missing_key`, `attack_id_invalid` (a `text` value that starts like an ATT&CK id but holds no valid one, such as a value a MISP Import Regexp rule rewrote; logged as `[ATTACK-VALUE]`) (no alert) |
| `edgeguard_misp_unmapped_attribute_types_total` | Counter | `attr_type` | MISP attribute types outside EdgeGuard's mapping (no alert) |
| `edgeguard_misp_unmapped_source_tags_total` | Counter | `source_tag` | MISP `source:*` tags outside EdgeGuard's source mapping (no alert) |

### Neo4j Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_neo4j_nodes` | Gauge | `label`, `zone` | Node count of each label EdgeGuard writes, with `zone="all"`, read from the graph by one read-only query (`Neo4jClient.count_nodes_by_label`) after every successful scheduled sync, after the enrichment of the sync DAG, and after the baseline's enrichment (not after its full sync: before the enrichment a fresh baseline has no Campaign nodes). A label without nodes is recorded as `0`. A failed count logs a warning and keeps the previous values. The per-label panels read `zone="all"` only |
| `edgeguard_neo4j_relationships` | Gauge | `rel_type` | Counts `build_relationships` reported in its last completed run, one per step key (e.g. `in_tactic`, `attributed_to`; also `multi_zone_indicators` and the `attributed_to_several_actor_pulses_removed` / `_trimmed` counts). Not a total of the graph's relationships per Neo4j type |
| `edgeguard_neo4j_sync_duration_seconds` | Histogram | - | Neo4j sync duration (one observation per sync) |
| `edgeguard_neo4j_sync_last_success_timestamp` | Gauge | - | End of the last successful MISP→Neo4j sync, scheduled or baseline (`EdgeGuardNeo4jSyncStale`) |
| `edgeguard_neo4j_queries_total` | Counter | `query_type`, `status` | Query count |
| `edgeguard_neo4j_query_duration_seconds` | Histogram | `query_type` | Neo4j query time (read by `EdgeGuardNeo4jQuerySlow`) |
| `edgeguard_neo4j_merge_ineffective_batch_total` | Counter | `label`, `source` | Non-empty MERGE batches that wrote nothing Neo4j counts (read by `EdgeGuardNeo4jIneffectiveBatch`) |
| `edgeguard_neo4j_batch_permanent_failure_total` | Counter | `label`, `source`, `reason` | MERGE batches lost after the retries (`retries_exhausted`) or to an error that is not retried (`non_retryable`) (read by `EdgeGuardNeo4jBatchPermanentFailure`) |
| `edgeguard_merge_reject_placeholder_total` | Counter | `label`, `source` | Malware or ThreatActor MERGEs refused because the name is a placeholder (`unknown`, `N/A`, …) (read by `EdgeGuardMergeRejectPlaceholderSpike`) |
| `edgeguard_build_relationships_last_completion_timestamp` | Gauge | - | Time of the last `build_relationships` run that reached its summary line (read by `EdgeGuardBuildRelationshipsSilentDeath`) |
| `edgeguard_build_relationships_completions_total` | Counter | - | `build_relationships` runs that reached their summary line (no alert) |
| `edgeguard_apoc_batch_partial_total` | Counter | `step` | `apoc.periodic.iterate` batches of a `build_relationships` step that reported errors (read by `EdgeGuardApocBatchPartial`) |
| `edgeguard_destructive_ops_total` | Counter | `operation`, `target` | Destructive operations on a store (node deletes, wipes, the CVSS duplicate removal) (no alert) |

### Circuit Breaker Metrics (from resilience.py)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_circuit_breaker_state` | Gauge | `service` | 0=closed, 1=half-open, 2=open |
| `edgeguard_consecutive_failures` | Gauge | `service` | Failure count |
| `edgeguard_service_up` | Gauge | `service` | 1=up, 0=down |
| `edgeguard_health_check_duration_seconds` | Histogram | `service` | Health check latency |

### Pipeline Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_pipeline_duration_seconds` | Histogram | `pipeline_type` | Total pipeline time |
| `edgeguard_pipeline_errors_total` | Counter | `task`, `error_type`, `source` | Error count |
| `edgeguard_dag_runs_total` | Counter | `dag_id`, `status`, `run_type` | Outcomes of collector task attempts and of `run_neo4j_sync`, not of DAG runs: one increment when a collector attempt ends (`failure` when it fails, `success` otherwise, a transient-error skip and a skip while a baseline holds the lock included) and one when `run_neo4j_sync` completes (`success`) or the sync reports failure (`failure`; an attempt that ends in another exception, and a baseline collector refused by the chain's checks, record nothing). `dag_id` is always `edgeguard_pipeline` and `run_type` always `scheduled`, whatever DAG ran the task |
| `edgeguard_dag_run_duration_seconds` | Histogram | `dag_id` | Defined, but written by no code path (always absent) |
| `edgeguard_dag_run_in_progress_start_timestamp` | Gauge | `dag_id` | Start time of the DAG run in progress, `0` when no run is in progress. Written by the Airflow listener plugin `plugins/edgeguard_dag_run_state.py` (see [DAG run in progress](#dag-run-in-progress)): the scheduler sets the run's start when it starts a run, and sets `0` (or the start of the DAG's other run still in progress) when it ends one (also at the `dagrun_timeout`); the API server does the same when a run is marked failed or successful by hand |
| `edgeguard_dag_last_success_timestamp` | Gauge | `dag_id` | Time of the last successful task of the DAG |
| `edgeguard_task_duration_seconds` | Histogram | `task_id`, `dag_id` | Duration of collector tasks and of `run_neo4j_sync`, recorded with `dag_id="edgeguard_pipeline"` whatever DAG ran the task (no alert) |

### MISP Sync Event Accounting

These gauges enforce the invariant `events_index_total == events_processed + events_failed`
for every sync run — the `EdgeGuardSyncCoverageGap` alert fires when it breaks.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_sync_events_index_total` | Gauge | - | Events returned from the MISP index on the last sync |
| `edgeguard_sync_events_processed` | Gauge | - | Events whose `sync_to_neo4j` completed successfully |
| `edgeguard_sync_events_failed` | Gauge | - | Events that failed permanently (first pass + retry pass + cap exhaustion) |

### Source-truthful Timestamp Pipeline

These counters observe the source-truthful first_seen / last_seen edge
architecture: they show which sources supply per-source timestamp claims
and which emit honest-NULL, and the failure-mode distribution of the
input-hardening layer (`coerce_iso`).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_source_truthful_claim_accepted_total` | Counter | `source_id`, `field` | Per-source claim survived all layers and lands on `r.source_reported_first_at` / `r.source_reported_last_at`. `field ∈ {first_seen, last_seen}`. |
| `edgeguard_source_truthful_claim_dropped_total` | Counter | `source_id`, `reason`, `field` | Per-source claim did NOT make it onto the edge. `reason ∈ {source_not_in_allowlist, no_data_from_source, last_seen_before_first_seen}`. The last one is emitted (field `last_seen`) when a source's last_seen precedes its first_seen: the last_seen claim is dropped and first_seen is kept. `field ∈ {first_seen, last_seen}` — the first two reasons emit per-field (the relay-rejection drop and the honest-NULL drop appear in the same per-field denominator, so the operator query below is correct). Honest-NULL drops (source on the allowlist but supplied no value) ARE counted under `no_data_from_source` — non-zero baseline expected. |
| `edgeguard_source_truthful_coerce_rejected_total` | Counter | `reason` | `coerce_iso` input rejected. `reason ∈ {sentinel_epoch, malformed_string, overflow}`. No `source_id` label — `coerce_iso` is a pure utility called from many sites without source context. |
| `edgeguard_source_truthful_future_clamp_total` | Counter | - | Future-dated timestamp clamped to `now()`. Likely upstream feed bug or operator clock drift. The accompanying WARNING log carries the original value. |

**Cardinality control:** the `source_id` label is bounded by an
allowlist (~20 values: every reliable source plus a few intentionally-
rejected relays the operator wants visibility into). Anything outside
the allowlist collapses to `<other>`; `None` / empty collapses to
`<unknown>`. This caps storage at low hundreds of cells and prevents
a malformed or spoofed source tag from blowing up Prometheus.

**Operator queries:**

```promql
# Per-source acceptance rate (1.0 = source always supplies first_seen).
# Includes ALL drops in the denominator — both honest-NULL
# (no_data_from_source) and unreliable-source filter
# (source_not_in_allowlist) — so the rate reflects the full
# pipeline, not just the post-allowlist-filter slice.
rate(edgeguard_source_truthful_claim_accepted_total{field="first_seen"}[5m])
  /
(
    rate(edgeguard_source_truthful_claim_accepted_total{field="first_seen"}[5m])
  + sum without (reason) (
        rate(edgeguard_source_truthful_claim_dropped_total{field="first_seen"}[5m])
    )
)

# Relay-rejection visibility — count of unreliable-source drops per source
sum by (source_id) (
    rate(edgeguard_source_truthful_claim_dropped_total{reason="source_not_in_allowlist"}[5m])
)

# coerce_iso failure-mode distribution (spot a misbehaving collector)
sum by (reason) (rate(edgeguard_source_truthful_coerce_rejected_total[5m]))

# Spike alert: future-clamp rate > 1/min (likely upstream clock drift)
rate(edgeguard_source_truthful_future_clamp_total[5m]) > 1 / 60
```

### Source-truthful tag-impersonation defense

The tag-impersonation defense is defense-in-depth for the source-truthful timestamp pipeline. When `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` is configured, EdgeGuard verifies the parent event's creator org against the allowlist before honoring a source-truthful claim. Rejections fire this counter:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_source_truthful_creator_rejected_total` | Counter | `source_id`, `reason` | Source-truthful claim refused because the parent MISP event's creator org failed the EdgeGuard trust allowlist. `reason ∈ {creator_org_not_allowlisted, creator_org_missing}`. |

**Operator alerts:**

```promql
# Spoofing-attempt detector — non-zero rate for any allowlisted source
# is either an active impersonation OR an allowlist misconfiguration
# (e.g. operator forgot to register a new EdgeGuard collector org's
# UUID after a MISP migration).
sum by (source_id, reason) (
    rate(edgeguard_source_truthful_creator_rejected_total[5m])
) > 0

# Distinguish "we couldn't verify" (creator_org_missing — likely an
# event from an old MISP version) from "we verified and rejected"
# (creator_org_not_allowlisted — likely a spoofing attempt).
sum by (reason) (
    increase(edgeguard_source_truthful_creator_rejected_total[1h])
)
```

**When neither allowlist env var is configured (the default), the trust check is bypassed, every source-truthful claim is accepted, and this counter never increments.**

### Defense-disabled state gauge

This gauge makes the "defense configured off" state observable to alert rules, not only to the startup log. See [`SECURITY_ROADMAP.md`](SECURITY_ROADMAP.md) for the full threat-model background and the Tier 3 fail-closed plan.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_misp_tag_impersonation_defense_disabled` | Gauge | — | `1` when both allowlist env vars are empty (defense BYPASSED, all source-truthful claims accepted); `0` when at least one allowlist is populated (defense ACTIVE). Every process that imports `metrics_server` sets it from that process's environment when it loads the module. In the Compose deployment that is every Airflow process (the `metrics` service does not import it), and the newest write is served. After changing `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` in `.env`, recreate the airflow service (`docker compose up -d airflow`); the gauge changes with the next task that runs. Restarting the `metrics` service has no effect. On a single-process install, restart the metrics server. |

**Suggested alert rule:**

```yaml
- alert: EdgeGuardMispTagImpersonationDefenseDisabled
  expr: edgeguard_misp_tag_impersonation_defense_disabled == 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: MISP tag-impersonation defense is disabled
    description: |
      EdgeGuard is accepting source-truthful claims from MISP attributes
      without verifying the creator organization. Configure
      EDGEGUARD_TRUSTED_MISP_ORG_UUIDS and/or
      EDGEGUARD_TRUSTED_MISP_ORG_NAMES to enable the defense, then
      recreate the airflow service (docker compose up -d airflow; on a
      single-process install, restart the metrics server). See
      docs/SECURITY_ROADMAP.md.
```

This alert is a **backstop** for the startup `WARNING` log that fires on every process boot when the defense is disabled; it catches deployments whose log aggregator filters or suppresses that log.

## Using Metrics in Code

### Recording Collection

```python
from metrics_server import (
    record_collection,
    record_collection_duration,
    set_source_health
)

# Record successful collection
record_collection(
    source='otx',
    zone='global',
    count=100,
    status='success'
)

# Record duration
record_collection_duration('otx', 'global', 5.5)

# Set source health
set_source_health('otx', 'global', healthy=True)
```

### Recording MISP Push

```python
from metrics_server import record_misp_push

record_misp_push(
    source='nvd',
    zone='global',
    event_count=5,
    attr_count=50,  # accepted, not recorded
    duration=2.5
)
```

`record_misp_push` adds `event_count` to `edgeguard_misp_events_total` and observes `duration` in
`edgeguard_misp_push_duration_seconds`; it does not record `attr_count`.

### Recording Neo4j Sync

```python
from metrics_server import record_neo4j_sync

# Duration histogram and the last-success stamp read by EdgeGuardNeo4jSyncStale
record_neo4j_sync(node_counts={}, duration=30.0)
```

The DAG records both through `_record_successful_sync_metrics(duration)` after the scheduled sync and
after the baseline's full sync. Its `record_neo4j_node_counts()` reads the node count of every label
from the graph and sets `edgeguard_neo4j_nodes{label, zone="all"}`: after the scheduled sync, after the
sync DAG's enrichment, and for the baseline only after its enrichment, when the graph is complete.

### Recording Pipeline Errors

```python
from metrics_server import record_pipeline_error

try:
    run_collector()
except Exception as e:
    record_pipeline_error(
        task='collect_otx',
        error_type=type(e).__name__,
        source='otx'
    )
```

## Airflow Integration

### Method 0: Multi-process exposure (Docker Compose, the default)

Airflow's LocalExecutor runs every task in its own process, and a process's metrics registry lives
in that process's memory. So that the pipeline's counters and gauges reach Prometheus, the compose
deployment runs `prometheus_client` in its multi-process mode:

- `PROMETHEUS_MULTIPROC_DIR=/opt/airflow/metrics_multiproc` is set on the `airflow` service; every
  task process writes its metric values to memory-mapped files in that shared volume.
- The `metrics` service (`src/metrics_exporter.py`, same image) aggregates those files with
  `MultiProcessCollector` and serves `/metrics` on port 8001. Prometheus scrapes it as `metrics:8001`
  over `edgeguard_net`; the `127.0.0.1:8001` host publish is for local access. Task
  processes start no HTTP server in this mode; the `edgeguard_metrics_server` DAG exits
  immediately with a log line.
- Gauges are declared with `multiprocess_mode="mostrecent"`: one series per label set, carrying
  the newest value written by any process. Counters, histograms and summaries are summed across
  processes, including processes that have exited.
- Compaction: `compact_multiproc_dir()` merges the files of exited processes into one file per
  type (`counter_merged.db`, `gauge_mostrecent_merged.db`, …) and deletes the originals. Tasks call
  it opportunistically from `ensure_metrics_server()` once more than 400 files exist; it is
  lock-guarded and must run inside the Airflow container (same PID namespace).
- Not exported in this mode: the `edgeguard_info` `Info` metric (unsupported by multi-process
  mode); every other metric is exported.

Methods 1 and 2 below describe the single-process server. Without `PROMETHEUS_MULTIPROC_DIR`,
neither exposes the pipeline's metrics: the server, in the metrics-DAG task or started by
`ensure_metrics_server()` in the first task process that binds the port, serves only its own
process's registry, and Method 2's server lives only as long as that task process. On a bare-metal
install, set `PROMETHEUS_MULTIPROC_DIR` and run the standalone server (Option A).

If the directory cannot be created or written (for example a volume mounted with the wrong ownership), the process logs an ERROR, removes `PROMETHEUS_MULTIPROC_DIR` from its own environment and keeps in-process metrics, so DAG parsing and task imports never fail because of metrics. The image creates `/opt/airflow/metrics_multiproc` owned by the `airflow` user so the named volume inherits writable ownership on first mount.

### DAG run in progress

`edgeguard_dag_run_in_progress_start_timestamp{dag_id}` (read by `EdgeGuardDAGRunStuck`) is written
by the Airflow listener plugin `plugins/edgeguard_dag_run_state.py`, not by the DAG code.
`docker-compose.yml` mounts `./plugins` at `/opt/airflow/plugins` and sets
`AIRFLOW__CORE__PLUGINS_FOLDER` to it; `docker compose exec airflow airflow plugins` lists
`edgeguard_dag_run_state` when it is loaded.

| Hook | Called by | Value |
|------|-----------|-------|
| `on_dag_run_running` | the scheduler, when it starts a run (a cleared run included) | the run's `start_date` |
| `on_dag_run_success` / `on_dag_run_failed` | the scheduler, when it ends a run (also at the `dagrun_timeout`) | `0`, or the start time of another run of the DAG still running (read from the metadata database in a session of its own) |
| `on_dag_run_success` / `on_dag_run_failed` | the API server, when a run is marked successful or failed by hand: UI "Mark run as …", `PATCH /api/v2/dags/{dag_id}/dagRuns/{run_id}`, `python src/edgeguard.py dag kill` | `0`, or the start time of another run of the DAG still running (read from the metadata database in a session of its own) |

The scheduler calls its hooks in the scheduling loop, in order, so a run's end is written before the
next run of the same DAG starts. The end hooks read the DAG's running runs in a session of their own,
because with the scheduler's session they would stop the scheduler at the end of every run. The mark is
written by listener hooks, not by DAG-level success and failure callbacks, because Airflow 3 runs
none of those callbacks when a run's state is set through the UI or the API, and the DAG processor
runs them asynchronously, so a late callback could clear the mark of the next run.

The hooks write only in the multi-process mode (`PROMETHEUS_MULTIPROC_DIR`): the scheduler and the
API server are not the process that serves `/metrics`. While a listener plugin is loaded, Airflow
refuses a DAG with a deferrable task that sets `end_from_trigger=True`; no EdgeGuard task does.

A run **deleted** while in progress fires no hook; its mark stays until the DAG's next run starts.
To clear it at once (here for the baseline):

```bash
docker compose exec airflow python -c \
  "from metrics_server import DAG_RUN_START; DAG_RUN_START.labels(dag_id='edgeguard_baseline').set(0)"
```

### Method 1: Separate Metrics DAG

Create a dedicated DAG that runs the metrics server:

```python
# dags/edgeguard_metrics.py
from airflow import DAG

# Airflow 3.x: PythonOperator is provided by apache-airflow-providers-standard.
from airflow.providers.standard.operators.python import PythonOperator
from datetime import datetime

from metrics_server import start_metrics_server

def run_metrics_server():
    """Run the metrics server (blocking)."""
    server = start_metrics_server(threaded=False)

with DAG(
    'edgeguard_metrics',
    schedule=None,  # Airflow 3 takes `schedule`, not `schedule_interval`
    start_date=datetime(2024, 1, 1),
    catchup=False,
) as dag:
    
    metrics_task = PythonOperator(
        task_id='metrics_server',
        python_callable=run_metrics_server,
    )
```

### Method 2: Embedded via `ensure_metrics_server()` helper

The main pipeline DAG (`edgeguard_pipeline.py`) provides an `ensure_metrics_server()` helper that starts the server lazily within a task — never at module parse time:

```python
def ensure_metrics_server():
    """Start metrics server inside a task, not at DAG parse time."""
    global _metrics_server_instance
    if _metrics_server_instance is None:
        from metrics_server import start_metrics_server
        _metrics_server_instance = start_metrics_server(threaded=True)
    return _metrics_server_instance
```

> **Never** call `start_http_server()` at the module level of a DAG file. DAG files are parsed every 30 seconds by the Airflow scheduler, which would repeatedly attempt to bind the metrics port.

## Alerting

### Built-in Alert Rules

`prometheus/alerts.yml` is the canonical source of truth; it
defines **39 alert rules** and 3 recording rules in nine groups
(`edgeguard_collection`, `edgeguard_circuit_breaker`, `edgeguard_health`,
`edgeguard_pipeline`, `edgeguard_containers`, `edgeguard_sync_integrity`,
`edgeguard_neo4j`, `edgeguard_host_disk`,
`edgeguard_pipeline_observability`). The
table below highlights the **operator-relevant** subset; for the full
list (including the disk, inode and `build_relationships` alerts), grep
`prometheus/alerts.yml` directly. Preflight (`scripts/preflight_baseline.sh`
`[7]`) enforces a floor of `≥ 11` rules.

| Alert | Condition | Severity |
|-------|-----------|----------|
| `EdgeGuardCollectionHighFailureRate` | >20% failure rate | warning |
| `EdgeGuardCollectionStale` | No success for longer than twice the collector's cadence (OTX 2 h; CISA, VirusTotal 9 h; NVD 17 h; daily sources 26 h; `misp_to_neo4j`, the MISP→Neo4j sync, 98 h: the longest gap between two sync starts, 96 h after a baseline's or a forced sync, plus the attempts of the tasks before the sync — recording rule `edgeguard:collector_max_stale_seconds`) | critical |
| `EdgeGuardNoIndicatorsCollected` | No indicator from a healthy source in 26 hours. A source whose last run was `not_modified` (HTTP 304, MITRE's unchanged bundle) or `skipped` (no API key, not in `EDGEGUARD_COLLECT_SOURCES`, a baseline in progress, a transient error) is left out (`edgeguard_collector_last_run_outcome`); a source whose last run succeeded and collected nothing still fires | warning |
| `EdgeGuardSourceAccessDenied` | A collector was skipped with `reason_class=*_auth_denied` in the last 25 hours: the provider refuses the request (rejected or revoked API key, blocked client). The task is green and nothing is collected; check with `python src/source_key_check.py` | warning |
| `EdgeGuardCircuitBreakerOpen` | Circuit open | critical |
| `EdgeGuardServiceDown` | Health check fail | critical |
| `EdgeGuardDAGRunFailures` | More than 3 failed collector or sync task attempts in one hour, across all DAGs (all counted under `dag_id="edgeguard_pipeline"`, see `edgeguard_dag_runs_total`) | warning |
| `EdgeGuardDAGRunStuck` | A DAG run marked in progress longer than its `dagrun_timeout` plus 15 minutes (`edgeguard:dag_run_max_seconds`; pipeline 5 h 45 min, medium 5 h 15 min, low and daily 8 h 45 min, Neo4j sync 68 h 15 min, baseline 32 h 15 min). The scheduler fails a run at its timeout and its listener hook clears the mark; a run marked failed or successful by hand (UI, `PATCH dagRuns`, `edgeguard dag kill`) is cleared by the API server's hook. When the run that ends is not the DAG's run in progress (an older run marked failed by hand), the mark keeps the start of the run still running. The alert therefore means a run the scheduler did not end, a run deleted while in progress, or a listener plugin that is not loaded (see [DAG run in progress](#dag-run-in-progress)) | critical |
| `EdgeGuardDAGLastSuccessStale` | No successful task for longer than one schedule interval plus the DAG's `dagrun_timeout` (`edgeguard:dag_max_success_gap_seconds`: `edgeguard_pipeline` 6 h, `edgeguard_medium_freq` 9 h, `edgeguard_low_freq` 16 h 30 min). The limits are per DAG because a single 6 h limit would fire about 1.5 h of every 8 h for `edgeguard_low_freq`. `edgeguard_daily` has `EdgeGuardDailyDAGStale` (25 h) | warning |
| `EdgeGuardNeo4jSyncStale` | No MISP→Neo4j sync (scheduled or baseline) completed in 122 hours: the longest gap between two sync starts plus the longest run of the next sync. `edgeguard_neo4j_sync` runs every 72 h and skips a run within 24 h of the last sync start, so scheduled syncs start 72 h apart and the first one after a baseline's or a forced sync starts less than 96 h after it; the next sync can then take 32 min of `check_sync_needed` / `neo4j_health_check` attempts and three attempts of `run_neo4j_sync` at its default 8-hour limit (`EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`) with two 5-minute retry delays (120 h 42 min in all). With a limit of N hours the threshold needs 439200 + 10800 × (N − 8) seconds; otherwise expect the warning during a retried sync | warning |
| `EdgeGuardNeo4jFullSyncRequestPending` | A requested full MISP→Neo4j sync (Airflow Variable `NEO4J_FULL_SYNC=true`) failed on its last attempt in the last 3 days: `edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}` rose, or appeared for the first time. The Variable stays set, so every scheduled run is a full sync again and no incremental sync runs until one succeeds. The alert clears 3 days after the last failure, also when the request was resolved earlier (silence it then); see [RUNBOOK.md](RUNBOOK.md), "Requesting a full MISP → Neo4j sync" | warning |
| `EdgeGuardContainerRestartLoop` | >3 container restarts in 1 hour (requires cAdvisor) | critical |
| `EdgeGuardSyncEventsFailed` | Any MISP event in the last sync landed in `events_failed` | critical |
| `EdgeGuardSyncCoverageGap` | `events_index_total ≠ events_processed + events_failed` — silent skip detected | critical |
| `EdgeGuardNeo4jLabelDropBig` | Per-label node count dropped >50% against the same label a day earlier (`offset 1d`); fed by the node counts recorded after every sync (the Grafana panel "Neo4j Node Count Change (24 h) by Label" shows the same comparison) | critical |
| `EdgeGuardMispBatchPermanentFailure` | MISP push 5xx exhausted retries | critical |
| `EdgeGuardMispSustainedBackoff` | MISP push backoff fired >1× in 15m | warning |
| `EdgeGuardMispEventAttributesTruncated` | `MISPCollector.collect` (the CLI pipeline `src/run_pipeline.py`, not the Airflow sync) sliced an event to `MAX_ATTRIBUTES_PER_EVENT` (500) attributes, and the rest of the event is lost. The sync's deferral of events above `EDGEGUARD_MAX_EVENT_ATTRIBUTES` does not fire it | warning |
| `EdgeGuardBuildRelationshipsSilentDeath` | A MISP→Neo4j sync completed between 15 h 25 min and 36 h ago (`edgeguard_neo4j_sync_last_success_timestamp`) and no build_relationships completion has been stamped since (`edgeguard_build_relationships_last_completion_timestamp`). build_relationships runs after the sync in both the scheduled sync DAG and the baseline; every attempt is limited to 5 h and the scheduled DAG retries twice, 5 min apart, so the rule waits until every attempt has ended (15 h 10 min) plus 15 min. The sync DAG's build_relationships skips while a baseline holds the baseline lock, so a sync that started before the lock is followed by no completion: the rule is silent while an `edgeguard_baseline` run is in progress (`edgeguard_dag_run_in_progress_start_timestamp{dag_id="edgeguard_baseline"} > 0`) and fires after a baseline that ended before its own full sync and build_relationships | critical |
| `EdgeGuardApocBatchPartial` | apoc.periodic.iterate reported per-row errors | warning |
| `EdgeGuardMispFetchFallbackActive` | `sum by (branch) (rate(...{outcome="engaged"}[10m])) > 0` for 10m. Sustained engagement of the PyMISP / requests-restSearch fallback signals the primary `/events/index` is broken. | warning |
| `EdgeGuardMispFetchFallbackHardError` | `sum by (branch) (rate(...{outcome="hard_error"}[5m])) > 0` for 1m. A fallback branch (PyMISP or restSearch) raised the `_MispFallbackHardError` sentinel in `src/run_misp_to_neo4j.py` (errors payload, unexpected shape, non-200 mid-pagination, or cap hit). The baseline's `full_neo4j_sync` has no retry, so its run has failed; the scheduled `run_neo4j_sync` is retried twice, 5 minutes apart. The primary `/events/index` listing raises the same sentinel on a failed later page or a non-listing answer, and a listing cut at the page cap fails the run; these failures do not increment the counter and show only as a failed `run_neo4j_sync` (and, if they persist, as `EdgeGuardNeo4jSyncStale`). | critical |

What the sync-integrity, build_relationships and MISP-fallback alerts catch:
- **`SyncEventsFailed` / `SyncCoverageGap` / `Neo4jLabelDropBig`** — catch MISP events the MISP→Neo4j sync skips silently, and large drops in a label's node count.
- **`BuildRelationshipsSilentDeath` / `ApocBatchPartial`** — surface a `build_relationships` run that dies silently after the sync, and APOC partial-batch responses.
- **`MispEventAttributesTruncated`** — surfaces events the CLI pipeline's `MISPCollector` sliced to 500 attributes.
- **`MispFetchFallbackActive` / `MispFetchFallbackHardError`** — see § "MISP fetch fallback" in [`docs/RUNBOOK.md`](RUNBOOK.md) § 8 for triage.

The invariant the `EdgeGuardSyncCoverageGap` alert guards is set by `record_sync_event_accounting` (`src/metrics_server.py`), which `MISPToNeo4jSync.run` calls on every exit path (see *MISP Sync Event Accounting* above).

### Alertmanager notifications

`prometheus/alertmanager.yml` loads without any secret. The Slack incoming-webhook URL is read from
a file when a Slack notification is sent (`slack_api_url_file: /etc/alertmanager/secrets/slack_api_url`);
every Slack receiver (`critical`, `team-platform`) inherits it. The configuration carries no inline
URL because Alertmanager v0.28 refuses an empty `slack_api_url: ''` at startup (unsupported scheme)
and restarts in a loop under the `alerts` profile.

To deliver to Slack:

```bash
# One line: the incoming-webhook URL. prometheus/secrets/ is ignored by git except its .gitignore.
printf '%s\n' 'https://hooks.slack.com/services/…' > prometheus/secrets/slack_api_url
# The Alertmanager image runs as uid 65534 (nobody); the file must be readable by it. chmod first:
# after the chown only root may change the mode.
chmod 0400 prometheus/secrets/slack_api_url && sudo chown 65534 prometheus/secrets/slack_api_url
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml --profile alerts up -d alertmanager
```

`docker-compose.monitoring.yml` mounts `./prometheus/secrets` read-only at
`/etc/alertmanager/secrets`. Without the file Alertmanager starts and serves its UI and API; each
Slack delivery fails and is logged, and the other receivers are unaffected. The e-mail receivers
(`smtp_smarthost: localhost:587`, `*@edgeguard.local`) and the PagerDuty key
(`${EDGEGUARD_PAGERDUTY_INTEGRATION_KEY}`, refused by `scripts/preflight_baseline.sh` check [7b]
until it is rendered) are placeholders to replace for a deployment.

### Reloading Prometheus after editing `alerts.yml`

Prometheus loads alert rules at startup. After you edit `prometheus/alerts.yml`:

```bash
# Validate the rules first (syntax + expression). Both files: the prometheus service is defined in
# docker-compose.monitoring.yml only.
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml exec prometheus \
  promtool check rules /etc/prometheus/alerts.yml

# Hot-reload without restarting Prometheus (requires --web.enable-lifecycle).
curl -X POST http://localhost:9090/-/reload
```

If `--web.enable-lifecycle` is not set, restart the container:
`docker compose -f docker-compose.yml -f docker-compose.monitoring.yml restart prometheus`.

### Custom Alerts

Add custom alerts to `prometheus/alerts.yml`:

```yaml
groups:
  - name: custom
    rules:
      - alert: MyCustomAlert
        expr: edgeguard_indicators_collected_total > 1000000
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "Milestone reached"
```

## Troubleshooting

### Metrics Not Appearing

1. Check metrics server is running:
   ```bash
   curl http://localhost:8001/health
   curl http://localhost:8001/metrics
   ```

2. Check Prometheus targets:
   - Open http://localhost:9090/targets
   - Ensure `edgeguard` target is UP

3. Check Prometheus can reach the server:
   ```bash
   docker exec edgeguard_prometheus wget -qO- http://metrics:8001/metrics | head
   ```
   A `bad address 'metrics'` answer means Prometheus is not attached to `edgeguard_net`: start the
   monitoring stack with both compose files (`make monitoring`).

### Grafana Dashboard Not Loading

1. Check Grafana logs:
   ```bash
   docker logs edgeguard_grafana
   ```

2. Verify dashboard provisioning:
   ```bash
   docker exec edgeguard_grafana ls -la /var/lib/grafana/dashboards/
   ```

3. Manually import the dashboard if needed

### High Memory Usage

Resource limits are pre-configured in `docker-compose.monitoring.yml`:

| Service | Memory Limit |
|---------|-------------|
| Prometheus | 1 GB |
| Grafana | 512 MB |
| Alertmanager | 256 MB |

To further reduce usage:

1. Reduce Prometheus retention:
   ```yaml
   # In docker-compose.monitoring.yml
   command:
     - '--storage.tsdb.retention.time=7d'  # the file sets 15d
   ```

2. Increase scrape intervals:
   ```yaml
   scrape_interval: 60s  # prometheus/prometheus.yml sets 30s
   ```

## Maintenance

### Backup Grafana Dashboards

```bash
# Export dashboard
# with GRAFANA_ADMIN_PASSWORD (and GRAFANA_ADMIN_USER, if set) exported from .env
curl -u "${GRAFANA_ADMIN_USER:-admin}:${GRAFANA_ADMIN_PASSWORD}" http://localhost:3000/api/dashboards/uid/edgeguard-overview > backup-dashboard.json
```

### Upgrade

```bash
# Pull the monitoring images
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml pull prometheus grafana alertmanager

# Recreate containers
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

### Cleanup

The monitoring services share the Compose project of the application stack, so name them:
`down` on the two files would also stop Neo4j, Airflow and the APIs, and `down -v` would delete their
volumes.

```bash
# Stop and remove the monitoring services only
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml rm -s -f prometheus grafana alertmanager node-exporter cadvisor

# Remove the monitoring volumes (WARNING: deletes the Prometheus history and the Grafana state)
docker volume ls --filter name=prometheus_data --filter name=grafana_data --filter name=alertmanager_data
docker volume rm <project>_prometheus_data <project>_grafana_data <project>_alertmanager_data
```

## Security Considerations

1. **Change default passwords** in production
2. **Use HTTPS** for external access
3. **Limit network access** to metrics endpoints
4. **Enable authentication** on metrics server if exposed externally
5. **Review alert rules** to prevent alert fatigue

## Reference

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [PromQL Query Guide](https://prometheus.io/docs/prometheus/latest/querying/basics/)

---

_Last updated: 2026-10-25_

## History

- 2026-10-25 — `EdgeGuardNeo4jSyncStale`: the 8-hour limit of the three `run_neo4j_sync` attempts is the default (`EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`); the row gives the threshold a larger limit needs.
- 2026-10-20 — `edgeguard_misp_attributes_dropped_total` lists its reasons, with `attack_id_invalid` for ATT&CK values without a valid ATT&CK id.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text restated as a guide to current behaviour; change history moved to this section and the leftover metric series of earlier versions to the appendix.
- 2026-10-17 — Metric descriptions follow the code: `edgeguard_dag_runs_total` counts collector and sync task attempts under `dag_id="edgeguard_pipeline"`, `edgeguard_misp_events_total` counts collector runs, `edgeguard_misp_attributes_total` and `edgeguard_dag_run_duration_seconds` are written by no code path, `edgeguard_neo4j_relationships` holds the counts of the last `build_relationships` run, and the `last_seen_before_first_seen` drop reason is listed.
- 2026-10-17 — The metrics read by alert rules are listed with the rule that reads each (39 alert rules and 3 recording rules in nine groups, preflight check `[7]`); `EdgeGuardSyncEventsFailed` is critical, `EdgeGuardMispEventAttributesTruncated` fires for the CLI pipeline only, and failures of the primary MISP listing do not increment the fallback counter.
- 2026-10-17 — `EDGEGUARD_ENABLE_METRICS` is ignored with `PROMETHEUS_MULTIPROC_DIR`, a metrics server without that directory exposes none of the pipeline's metrics, the defense-disabled gauge is set by every Airflow process, and the Grafana backup command reads the password from the environment.
- 2026-10-16 — `EdgeGuardBuildRelationshipsSilentDeath` is silent while a baseline run is in progress, because the sync DAG's build_relationships skips while a baseline holds the baseline lock; the primary `/events/index` listing fails the sync on a failed later page, a non-listing answer or the page cap.
- 2026-10-16 — The end hooks of the DAG run listener read the DAG's running runs in a session of their own, because with the scheduler's session they stopped the scheduler at the end of every run.
- 2026-10-16 — `EdgeGuardNeo4jSyncStale` lowered from 145 h to 122 h and the `misp_to_neo4j` staleness set to 98 h, derived from the 72-hour sync schedule and its 24-hour skip guard; the former cron `0 3 */3 * *` with a 71 h guard left 96 h gaps at most month ends, 120 h after 28 February of a leap year and up to 143 h after a baseline.
- 2026-10-16 — `EdgeGuardNeo4jFullSyncRequestPending` added to the alert table; it clears 3 days after the last failure.
- 2026-10-15 — The DAG run in progress is marked by the listener plugin `plugins/edgeguard_dag_run_state.py` (scheduler and API server hooks, with a command to clear the mark of a deleted run), replacing DAG-level callbacks that Airflow 3 does not run for a run marked by hand and runs asynchronously; the mark of a run still in progress is kept when another run of the DAG ends.
- 2026-10-15 — `edgeguard_dag_run_in_progress_start_timestamp` replaced `edgeguard_dag_run_start_timestamp`, which was refreshed on every task success and never cleared, and `EdgeGuardDAGRunStuck` received per-DAG limits; before, it fired from one hour after a run until the DAG's next run (permanently after the baseline).
- 2026-10-15 — `EdgeGuardBuildRelationshipsSilentDeath` compares the last successful sync with the new gauge `edgeguard_build_relationships_last_completion_timestamp`, because the former rule (no completion in 6 h while a baseline task succeeded) fired through every collection phase of a baseline.
- 2026-10-15 — `EdgeGuardNeo4jSyncStale` set to 145 h and the Neo4j sync limit of `EdgeGuardDAGRunStuck` to 68 h 15 min, following the sync DAG's 68 h `dagrun_timeout` and the sync task's 8 h limit with two retries.
- 2026-10-15 — The monitoring stack runs in the Compose project of the application and Prometheus scrapes `metrics:8001` over `edgeguard_net`, because the former target `host.docker.internal:8001` was refused on Linux; upgrade, cleanup, promtool and restart commands use both compose files.
- 2026-10-15 — Alertmanager reads the Slack URL from `prometheus/secrets/slack_api_url` (`chmod` before `chown`), because the former `slack_api_url: ''` made Alertmanager v0.28 refuse its configuration and restart in a loop.
- 2026-10-15 — `edgeguard_neo4j_nodes` is read from the graph after every sync and enrichment, with 0 for a label without nodes (before, every sync set four labels to 0 under `zone="unknown"`); collection counts and sync durations are recorded once per run (the Compose deployment had counted every collection twice).
- 2026-10-15 — `edgeguard_collector_last_run_outcome` added; `EdgeGuardNoIndicatorsCollected` leaves out not-modified and skipped runs, `EdgeGuardDAGLastSuccessStale` uses per-DAG limits, and `misp_to_neo4j` joined the staleness map.
- 2026-10-11 — Multi-process metrics exposure: Airflow task processes write to `PROMETHEUS_MULTIPROC_DIR` and the `metrics` service serves the aggregate, because each task process had kept a private registry and the pipeline's metrics never reached Prometheus.
- 2026-04-26 — Alert table limited to the operator-relevant subset with `prometheus/alerts.yml` as the canonical source; it documents the sync-integrity alerts and event-accounting gauges (added after a single MISP 5xx lost about 99K NVD CVEs from the graph), the build_relationships and APOC alerts, the attribute-truncation alert and the two MISP fetch fallback alerts with their counter.
- 2026-04-20 — Gauge `edgeguard_misp_tag_impersonation_defense_disabled` added, so that alert rules see a disabled tag-impersonation defense and not only the startup log.
- 2026-04-19 — Counters of the source-truthful timestamp pipeline (accepted, dropped, coerce-rejected and future-clamped claims) and of the MISP tag-impersonation defense (`edgeguard_source_truthful_creator_rejected_total`) added.
- 2026-03-24 — The metrics server listens on port 8001 (8000 is the REST API); `prometheus/prometheus.yml` scraped it at `host.docker.internal:8001`.
