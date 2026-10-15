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

**Option A: Standalone (Recommended for production)**

```bash
# From the EdgeGuard directory
python src/metrics_server.py --port 8001

# Or with test metrics
python src/metrics_server.py --port 8001 --test-metrics
```

**Option B: Docker Compose (default since 2026-10)**

The `metrics` compose service serves the aggregate of every Airflow task process on
`127.0.0.1:8001` from the shared `PROMETHEUS_MULTIPROC_DIR` (Method 0 below). Nothing has to be
triggered.

**Option C: Via Dedicated Airflow DAG (bare-metal installs without `PROMETHEUS_MULTIPROC_DIR`)**

The metrics server runs as a long-lived task in the `edgeguard_metrics_server` DAG; in the Compose
deployment this DAG exits immediately because the multi-process mode is active. This avoids side effects during DAG parsing — never start the HTTP server at module level.

```bash
# Trigger the metrics server DAG
airflow dags trigger edgeguard_metrics_server
```

> **Important:** Do not call `start_http_server()` at DAG module level. Airflow re-parses DAG files frequently, which would attempt to bind the port repeatedly. Always start the metrics server inside a task function.

### 2. Start Prometheus + Grafana

Start the monitoring stack together with the application stack, as one Compose project (2026-10):

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
`edgeguard_net`. Before 2026-10 Prometheus scraped `host.docker.internal:8001`; on Linux that name
resolves to the docker0 bridge address while the metrics port is published on `127.0.0.1` only, so
the scrape was refused everywhere but on Docker Desktop. The `127.0.0.1:8001` publish remains for
local access (`curl http://localhost:8001/metrics`).

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
| `EDGEGUARD_ENABLE_METRICS` | Enable Prometheus metrics in DAG | `false` |
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
| `edgeguard_indicators_collected_total` | Counter | `source`, `zone`, `status` | Total indicators collected. One increment per collector run (2026-10; before, the compose deployment added every count twice). `status`: `success`, `not_modified` (HTTP 304), `skipped`, `failed` |
| `edgeguard_collector_last_run_outcome` | Gauge | `source`, `outcome` | 2026-10: outcome of the source's most recent run, `1` for that outcome and `0` for the others: `collected`, `empty` (success, nothing collected), `not_modified` (HTTP 304), `skipped`, `failed` |
| `edgeguard_collection_failures_total` | Counter | `source` | Collection failures |
| `edgeguard_collection_duration_seconds` | Histogram | `source`, `zone` | Collection time |
| `edgeguard_last_success_timestamp` | Gauge | `source` | Last successful collection; also `source="misp_to_neo4j"`, stamped by the MISP→Neo4j sync |

### MISP Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_misp_events_total` | Counter | `source`, `zone` | MISP events created |
| `edgeguard_misp_attributes_total` | Counter | `type`, `source` | MISP attributes created |
| `edgeguard_misp_push_duration_seconds` | Histogram | `source` | MISP push time |
| `edgeguard_misp_health` | Gauge | `check_type` | MISP health status |

### Neo4j Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_neo4j_nodes` | Gauge | `label`, `zone` | Node count of each label EdgeGuard writes, with `zone="all"`, read from the graph by one read-only query (`Neo4jClient.count_nodes_by_label`) after every successful scheduled sync, after the enrichment of the sync DAG, and after the baseline's enrichment (not after its full sync: before the enrichment a fresh baseline has no Campaign nodes). A label without nodes is recorded as `0`. A failed count logs a warning and keeps the previous values. Before 2026-10 every sync set four labels to 0 under `zone="unknown"`; those series stay at 0 in the metrics directory until the `metrics_multiproc` volume is recreated, and the per-label panels read `zone="all"` only |
| `edgeguard_neo4j_relationships` | Gauge | `rel_type` | Relationship counts |
| `edgeguard_neo4j_sync_duration_seconds` | Histogram | - | Neo4j sync duration (one observation per sync since 2026-10) |
| `edgeguard_neo4j_sync_last_success_timestamp` | Gauge | - | End of the last successful MISP→Neo4j sync, scheduled or baseline (`EdgeGuardNeo4jSyncStale`) |
| `edgeguard_neo4j_queries_total` | Counter | `query_type`, `status` | Query count |

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
| `edgeguard_dag_runs_total` | Counter | `dag_id`, `status`, `run_type` | DAG run count |
| `edgeguard_dag_run_duration_seconds` | Histogram | `dag_id` | DAG run duration |
| `edgeguard_dag_run_in_progress_start_timestamp` | Gauge | `dag_id` | 2026-10: start time of the DAG run in progress, `0` when no run is in progress. Written by the Airflow listener plugin `plugins/edgeguard_dag_run_state.py` (see [DAG run in progress](#dag-run-in-progress)): the scheduler sets the run's start when it starts a run, and sets `0` when it ends one (also at the `dagrun_timeout`); the API server sets `0` when a run is marked failed or successful by hand. It replaces `edgeguard_dag_run_start_timestamp`, which was refreshed on every task success and never cleared; values the former series left in the metrics directory are read by no rule |
| `edgeguard_dag_last_success_timestamp` | Gauge | `dag_id` | Time of the last successful task of the DAG |

### MISP Sync Event Accounting

Added in 2026-04 after the NVD silent-skip regression (see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)).
These gauges enforce the invariant `events_index_total == events_processed + events_failed`
for every sync run — the `EdgeGuardSyncCoverageGap` alert fires when it breaks.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_sync_events_index_total` | Gauge | - | Events returned from the MISP index on the last sync |
| `edgeguard_sync_events_processed` | Gauge | - | Events whose `sync_to_neo4j` completed successfully |
| `edgeguard_sync_events_failed` | Gauge | - | Events that failed permanently (first pass + retry pass + cap exhaustion) |

### Source-truthful Timestamp Pipeline

Added in 2026-04 (PR #41 follow-up — closes the observability gap that
shipped with the source-truthful first_seen / last_seen edge architecture).
Without these, an operator has zero signal on which sources actually
supply per-source timestamp claims vs. emit honest-NULL, and zero signal
on the failure-mode distribution of the input-hardening layer
(`coerce_iso`).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_source_truthful_claim_accepted_total` | Counter | `source_id`, `field` | Per-source claim survived all layers and lands on `r.source_reported_first_at` / `r.source_reported_last_at`. `field ∈ {first_seen, last_seen}`. |
| `edgeguard_source_truthful_claim_dropped_total` | Counter | `source_id`, `reason`, `field` | Per-source claim did NOT make it onto the edge. `reason ∈ {source_not_in_allowlist, no_data_from_source}`. `field ∈ {first_seen, last_seen}` — both reasons emit per-field (the relay-rejection drop and the honest-NULL drop appear in the same per-field denominator, so the operator query below is correct). Honest-NULL drops (source on the allowlist but supplied no value) ARE counted under `no_data_from_source` — non-zero baseline expected. |
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

### Source-truthful tag-impersonation defense (chip 5e)

Added in 2026-04 as defense-in-depth for the source-truthful timestamp pipeline (PR #41). When `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` is configured, EdgeGuard verifies the parent event's creator org against the allowlist before honoring a source-truthful claim. Rejections fire this counter:

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

**When neither allowlist env var is configured (the default), the trust check is BYPASSED and this counter never increments.** Pre-release / dev environments see no behavior change.

### Defense-disabled state gauge (PR-I, 2026-04)

Added to make the "defense configured OFF" state observable to alert rules, not just to the startup log. See [`SECURITY_ROADMAP.md`](SECURITY_ROADMAP.md) for the full threat-model background and the Tier 3 fail-closed plan.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `edgeguard_misp_tag_impersonation_defense_disabled` | Gauge | — | `1` when both allowlist env vars are empty (defense BYPASSED, all source-truthful claims accepted); `0` when at least one allowlist is populated (defense ACTIVE). Read once at metrics-server boot; operators must restart the metrics server to pick up an env-var change. |

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
      restart the metrics server. See docs/SECURITY_ROADMAP.md.
```

This alert is a **backstop** for the startup `WARNING` log that fires on every process boot when the defense is disabled — catches cases where operators have filtered / suppressed the log aggregator.

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
    attr_count=50,
    duration=2.5
)
```

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

### Method 0: Multi-process exposure (Docker Compose — the default since 2026-10)

Airflow's LocalExecutor runs every task in its own process. Before 2026-10 each task process
kept a private metrics registry (and tried to start its own HTTP server), so pipeline counters
and gauges never reached Prometheus. The compose deployment now runs `prometheus_client` in its
multi-process mode:

- `PROMETHEUS_MULTIPROC_DIR=/opt/airflow/metrics_multiproc` is set on the `airflow` service; every
  task process writes its metric values to memory-mapped files in that shared volume.
- The `metrics` service (`src/metrics_exporter.py`, same image) aggregates those files with
  `MultiProcessCollector` and serves `/metrics` on port 8001. Prometheus scrapes it as `metrics:8001`
  over `edgeguard_net` (2026-10); the `127.0.0.1:8001` host publish is for local access. Task
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
  mode); everything else is unchanged.

Methods 1 and 2 below describe the single-process server and apply to bare-metal installs without
`PROMETHEUS_MULTIPROC_DIR`.

If the directory cannot be created or written (for example a volume mounted with the wrong ownership), the process logs an ERROR, removes `PROMETHEUS_MULTIPROC_DIR` from its own environment and keeps in-process metrics, so DAG parsing and task imports never fail because of metrics. The image creates `/opt/airflow/metrics_multiproc` owned by the `airflow` user so the named volume inherits writable ownership on first mount.

### DAG run in progress

`edgeguard_dag_run_in_progress_start_timestamp{dag_id}` (read by `EdgeGuardDAGRunStuck`) is written
by the Airflow listener plugin `plugins/edgeguard_dag_run_state.py` (2026-10), not by the DAG code.
`docker-compose.yml` mounts `./plugins` at `/opt/airflow/plugins` and sets
`AIRFLOW__CORE__PLUGINS_FOLDER` to it; `docker compose exec airflow airflow plugins` lists
`edgeguard_dag_run_state` when it is loaded.

| Hook | Called by | Value |
|------|-----------|-------|
| `on_dag_run_running` | the scheduler, when it starts a run (a cleared run included) | the run's `start_date` |
| `on_dag_run_success` / `on_dag_run_failed` | the scheduler, when it ends a run (also at the `dagrun_timeout`) | `0` |
| `on_dag_run_success` / `on_dag_run_failed` | the API server, when a run is marked successful or failed by hand: UI "Mark run as …", `PATCH /api/v2/dags/{dag_id}/dagRuns/{run_id}`, `python src/edgeguard.py dag kill` | `0` |

The scheduler calls its hooks in the scheduling loop, in order, so a run's end is written before the
next run of the same DAG starts. The first 2026-10 version used DAG-level success and failure
callbacks: Airflow 3 runs none of them when a run's state is set through the UI or the API, and the
DAG processor runs them asynchronously, so a late callback could clear the mark of the next run.

The hooks write only in the multi-process mode (`PROMETHEUS_MULTIPROC_DIR`): the scheduler and the
API server are not the process that serves `/metrics`. While a listener plugin is loaded, Airflow
refuses a DAG with a deferrable task that sets `end_from_trigger=True`; no EdgeGuard task does.

A run **deleted** while in progress fires no hook; its mark stays until the DAG's next run starts.
To clear it at once (here for the baseline):

```bash
docker compose exec airflow python -c \
  "from metrics_server import DAG_RUN_START; DAG_RUN_START.labels(dag_id='edgeguard_baseline').set(0)"
```

### Method 1: Separate Metrics DAG (Recommended)

Create a dedicated DAG that runs the metrics server:

```python
# dags/edgeguard_metrics.py
from airflow import DAG

# Airflow 3.x: PythonOperator moved to apache-airflow-providers-standard.
from airflow.providers.standard.operators.python import PythonOperator
from datetime import datetime

from metrics_server import start_metrics_server

def run_metrics_server():
    """Run the metrics server (blocking)."""
    server = start_metrics_server(threaded=False)

with DAG(
    'edgeguard_metrics',
    schedule=None,  # Airflow 3: `schedule` replaces `schedule_interval`
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

`prometheus/alerts.yml` is the canonical source of truth — at HEAD it
defines **30+ alert rules** across multiple groups (collection, circuit
breaker, health, pipeline, MISP-push, Neo4j, MISP-fetch-fallback). The
table below highlights the **operator-relevant** subset; for the full
list (including the disk, inode and `build_relationships` alerts), grep
`prometheus/alerts.yml` directly. Preflight (`scripts/preflight_baseline.sh`
`[11]`) enforces a floor of `≥ 11` rules.

| Alert | Condition | Severity |
|-------|-----------|----------|
| `EdgeGuardCollectionHighFailureRate` | >20% failure rate | warning |
| `EdgeGuardCollectionStale` | No success for longer than twice the collector's cadence (OTX 2 h; CISA, VirusTotal 9 h; NVD 17 h; daily sources 26 h; `misp_to_neo4j`, the MISP→Neo4j sync, 145 h since 2026-10 — recording rule `edgeguard:collector_max_stale_seconds`) | critical |
| `EdgeGuardNoIndicatorsCollected` | No indicator from a healthy source in 26 hours. Since 2026-10 a source whose last run was `not_modified` (HTTP 304, MITRE's unchanged bundle) or `skipped` (no API key, not in `EDGEGUARD_COLLECT_SOURCES`, a baseline in progress, a transient error) is left out (`edgeguard_collector_last_run_outcome`); a source whose last run succeeded and collected nothing still fires | warning |
| `EdgeGuardSourceAccessDenied` | A collector was skipped with `reason_class=*_auth_denied` in the last 25 hours: the provider refuses the request (rejected or revoked API key, blocked client). The task is green and nothing is collected; check with `python src/source_key_check.py` | warning |
| `EdgeGuardCircuitBreakerOpen` | Circuit open | critical |
| `EdgeGuardServiceDown` | Health check fail | critical |
| `EdgeGuardDAGRunFailures` | >3 failures/hour | warning |
| `EdgeGuardDAGRunStuck` | A DAG run marked in progress longer than its `dagrun_timeout` plus 15 minutes (`edgeguard:dag_run_max_seconds`; pipeline 5 h 45 min, medium 5 h 15 min, low and daily 8 h 45 min, Neo4j sync 22 h 15 min, baseline 32 h 15 min). The scheduler fails a run at its timeout and its listener hook clears the mark; a run marked failed or successful by hand (UI, `PATCH dagRuns`, `edgeguard dag kill`) is cleared by the API server's hook. The alert therefore means a run the scheduler did not end, a run deleted while in progress, or a listener plugin that is not loaded (see [DAG run in progress](#dag-run-in-progress)). Before 2026-10 it fired from one hour after a run until the DAG's next run (permanently after the baseline) | critical |
| `EdgeGuardDAGLastSuccessStale` | No successful task for longer than one schedule interval plus the DAG's `dagrun_timeout` (`edgeguard:dag_max_success_gap_seconds`: `edgeguard_pipeline` 6 h, `edgeguard_medium_freq` 9 h, `edgeguard_low_freq` 16 h 30 min). The single 6 h limit fired about 1.5 h of every 8 h for `edgeguard_low_freq`. `edgeguard_daily` has `EdgeGuardDailyDAGStale` (25 h) | warning |
| `EdgeGuardNeo4jSyncStale` | No MISP→Neo4j sync (scheduled or baseline) completed in 145 hours: the longest gap between two sync starts plus the sync task's longest run (three 8-hour attempts). The cron `0 3 */3 * *` with its 71 h guard skips the fire after the 31st and after 28 February (96 h gaps; 120 h after 28 February of a leap year), and a baseline sync can leave 143 h until the next scheduled sync; the former 72 h limit fired about 23 h at most month ends | warning |
| `EdgeGuardContainerRestartLoop` | >3 container restarts in 1 hour (requires cAdvisor) | critical |
| `EdgeGuardSyncEventsFailed` | Any MISP event in the last sync landed in `events_failed` | warning |
| `EdgeGuardSyncCoverageGap` | `events_index_total ≠ events_processed + events_failed` — silent skip detected | critical |
| `EdgeGuardNeo4jLabelDropBig` | Per-label node count dropped >50% against the same label a day earlier (`offset 1d`); fed by the node counts recorded after every sync since 2026-10 (the Grafana panel "Neo4j Node Count Change (24 h) by Label" shows the same comparison) | critical |
| `EdgeGuardMispBatchPermanentFailure` | MISP push 5xx exhausted retries | critical |
| `EdgeGuardMispSustainedBackoff` | MISP push backoff fired >1× in 15m | warning |
| `EdgeGuardMispEventAttributesTruncated` | PR-N24 H3 — event attribute count exceeded `MAX_EVENT_ATTRIBUTES`; deferred to end of sync | warning |
| `EdgeGuardBuildRelationshipsSilentDeath` | PR-N21 — a MISP→Neo4j sync completed between 15 h 25 min and 36 h ago (`edgeguard_neo4j_sync_last_success_timestamp`) and no build_relationships completion has been stamped since (`edgeguard_build_relationships_last_completion_timestamp`, 2026-10). build_relationships runs directly after the sync in both the scheduled sync DAG and the baseline; every attempt is limited to 5 h and the scheduled DAG retries twice, 5 min apart, so the rule waits until every attempt has ended (15 h 10 min) plus 15 min; the former rule (no completion in 6 h while a baseline task succeeded) also fired through every collection phase of a baseline | critical |
| `EdgeGuardApocBatchPartial` | PR-N21 — apoc.periodic.iterate reported per-row errors | warning |
| **`EdgeGuardMispFetchFallbackActive`** | **PR-N31** — `sum by (branch) (rate(...{outcome="engaged"}[10m])) > 0` for 10m. Sustained engagement of the PyMISP / requests-restSearch fallback signals the primary `/events/index` is broken. | warning |
| **`EdgeGuardMispFetchFallbackHardError`** | **PR-N31** — `sum by (branch) (rate(...{outcome="hard_error"}[5m])) > 0` for 1m. The `_MispFallbackHardError` sentinel raised in `src/run_misp_to_neo4j.py` (errors-payload, unexpected-shape, non-200 mid-pagination, or cap-hit). The dagrun has already failed (PR-N29 H1: `retries=0` on critical chain). | **critical** |

The 2026-04 train added several alert classes:
- **`SyncEventsFailed` / `SyncCoverageGap` / `Neo4jLabelDropBig`** (PR-N18) — catch silent-skip regressions where a single MISP 5xx lost ~99K NVD CVEs from the graph.
- **`BuildRelationshipsSilentDeath` / `ApocBatchPartial`** (PR-N21) — surface the `build_relationships` post-sync silent-death and APOC partial-batch responses.
- **`MispEventAttributesTruncated`** (PR-N24 H3) — surfaces the deferred-large-event signal.
- **`MispFetchFallbackActive` / `MispFetchFallbackHardError`** (PR-N31) — see § "MISP fetch fallback" in [`docs/RUNBOOK.md`](RUNBOOK.md) § 8 for triage.

See [docs/AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) § sync-event accounting for the invariant the `EdgeGuardSyncCoverageGap` alert guards.

### Alertmanager notifications

`prometheus/alertmanager.yml` loads without any secret (2026-10). Before, `slack_api_url: ''` made
Alertmanager v0.28 refuse its configuration at startup (unsupported scheme) and restart in a loop
under the `alerts` profile. The Slack incoming-webhook URL is now read from a file when a Slack
notification is sent (`slack_api_url_file: /etc/alertmanager/secrets/slack_api_url`); every Slack
receiver (`critical`, `team-platform`) inherits it.

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
until it is rendered) are still placeholders to replace for a deployment.

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
     - '--storage.tsdb.retention.time=7d'  # Reduce from 15d
   ```

2. Increase scrape intervals:
   ```yaml
   scrape_interval: 60s  # Increase from 30s
   ```

## Maintenance

### Backup Grafana Dashboards

```bash
# Export dashboard
curl -u admin:edgeguard http://localhost:3000/api/dashboards/uid/edgeguard-overview > backup-dashboard.json
```

### Upgrade

```bash
# Pull the monitoring images
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml pull prometheus grafana alertmanager

# Recreate containers
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

### Cleanup

The monitoring services share the Compose project of the application stack (2026-10), so name them:
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

_Last updated: 2026-10-15 — `EdgeGuardNeo4jSyncStale` at 145 h and the `edgeguard_neo4j_sync` run limit in `EdgeGuardDAGRunStuck` follow the sync DAG's 68 h `dagrun_timeout` and the sync task's 8 h limit with two retries. Same day: `EdgeGuardBuildRelationshipsSilentDeath` compares the last successful sync with the last build_relationships completion (new gauge `edgeguard_build_relationships_last_completion_timestamp`), so it no longer fires during a baseline's collection phase or while a build_relationships retry may still complete. Same day: DAG run in progress marked by the listener plugin `plugins/edgeguard_dag_run_state.py` (scheduler and API server hooks; a run marked failed by hand is cleared; command to clear the mark of a deleted run); node counts after the enrichment (baseline: only then) and a label without nodes recorded as 0; `EdgeGuardBuildRelationshipsSilentDeath` reads the latest successful baseline task; promtool and restart commands with both compose files; `chmod` before `chown` for the Slack secret. Same day: monitoring signals: Prometheus scrapes `metrics:8001` over `edgeguard_net` and the monitoring stack starts together with `docker-compose.yml` (upgrade and cleanup commands adjusted); Alertmanager reads the Slack URL from `prometheus/secrets/slack_api_url`; `edgeguard_neo4j_nodes` read from the graph after every sync; `edgeguard_dag_run_in_progress_start_timestamp` and `edgeguard_collector_last_run_outcome`; per-DAG limits for `EdgeGuardDAGRunStuck` and `EdgeGuardDAGLastSuccessStale`, `EdgeGuardNoIndicatorsCollected` without 304 and skipped runs, `misp_to_neo4j` in the staleness map, `EdgeGuardNeo4jSyncStale` at 144 h. Same day: wording only: the PR-N21 alerts are cited by PR number, without personal names. Prior: 2026-04-26 — PR-N33 docs audit: replaced the "11-row" alert table snapshot with a "operator-relevant subset" table + pointer to `prometheus/alerts.yml` as canonical source (30+ rules at HEAD); added the two PR-N31 fallback alerts + several other 2026-04 additions; reframed "the last three" narrative paragraph as a per-PR-train summary. Added `edgeguard_misp_fetch_fallback_active_total` Counter (labels: `branch`, `outcome`) to the implicit metrics inventory.

Prior: 2026-04-19 chips 5b + 5e added five new source-truthful counters: `edgeguard_source_truthful_claim_accepted_total` / `_dropped_total` / `_coerce_rejected_total` / `_future_clamp_total` (PR #42, observability for the per-source first_seen / last_seen pipeline shipped in PR #41) plus `edgeguard_source_truthful_creator_rejected_total` (PR #44, fires when the MISP tag-impersonation defense refuses a source-truthful claim). 2026-03-24: repo **`prometheus/prometheus.yml`** scrapes EdgeGuard metrics at **`host.docker.internal:8001`** (not 8000 REST). Metrics server default port **8001**._
