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

**Option B: Via Dedicated Airflow DAG (Recommended for Airflow deployments)**

The metrics server runs as a long-lived task in the `edgeguard_metrics_server` DAG. This avoids side effects during DAG parsing — never start the HTTP server at module level.

```bash
# Trigger the metrics server DAG
airflow dags trigger edgeguard_metrics_server
```

> **Important:** Do not call `start_http_server()` at DAG module level. Airflow re-parses DAG files frequently, which would attempt to bind the port repeatedly. Always start the metrics server inside a task function.

### 2. Start Prometheus + Grafana

```bash
# Start the monitoring stack
docker-compose -f docker-compose.monitoring.yml up -d

# With host monitoring (Linux only)
docker-compose -f docker-compose.monitoring.yml --profile host-monitoring up -d

# With alerts enabled
docker-compose -f docker-compose.monitoring.yml --profile alerts up -d
```

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
      - targets: ['host.docker.internal:8001']
    metrics_path: /metrics
    scrape_interval: 30s
```

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
| `edgeguard_indicators_collected_total` | Counter | `source`, `zone`, `status` | Total indicators collected |
| `edgeguard_collection_failures_total` | Counter | `source` | Collection failures |
| `edgeguard_collection_duration_seconds` | Histogram | `source`, `zone` | Collection time |
| `edgeguard_last_success_timestamp` | Gauge | `source` | Last successful collection |

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
| `edgeguard_neo4j_nodes` | Gauge | `label`, `zone` | Node counts by label |
| `edgeguard_neo4j_relationships` | Gauge | `rel_type` | Relationship counts |
| `edgeguard_neo4j_sync_duration_seconds` | Histogram | - | Neo4j sync duration |
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

record_neo4j_sync(
    node_counts={
        'Indicator': 5000,
        'Threat': 500,
        'Sector': 10
    },
    duration=30.0
)
```

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
    schedule_interval=None,  # Run continuously
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

The following alerts are pre-configured in `prometheus/alerts.yml`:

| Alert | Condition | Severity |
|-------|-----------|----------|
| `EdgeGuardCollectionHighFailureRate` | >20% failure rate | warning |
| `EdgeGuardCollectionStale` | No success in >1 hour | critical |
| `EdgeGuardCircuitBreakerOpen` | Circuit open | critical |
| `EdgeGuardServiceDown` | Health check fail | critical |
| `EdgeGuardDAGRunFailures` | >3 failures/hour | warning |
| `EdgeGuardDAGRunStuck` | DAG run running >1 hour without completing | critical |
| `EdgeGuardDAGLastSuccessStale` | No successful DAG run in >6 hours | warning |
| `EdgeGuardContainerRestartLoop` | >3 container restarts in 1 hour (requires cAdvisor) | critical |
| `EdgeGuardSyncEventsFailed` | Any MISP event in the last sync landed in `events_failed` | warning |
| `EdgeGuardSyncCoverageGap` | `events_index_total ≠ events_processed + events_failed` — silent skip detected | critical |
| `EdgeGuardNeo4jLabelDropBig` | Per-label node count dropped >50% vs previous scrape | critical |

The last three were added in 2026-04 to catch the silent-skip regression where a single MISP 5xx lost ~99K NVD CVEs from the graph. See [docs/AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) § sync-event accounting for the invariant the `EdgeGuardSyncCoverageGap` alert guards.

### Reloading Prometheus after editing `alerts.yml`

Prometheus loads alert rules at startup. After you edit `prometheus/alerts.yml`:

```bash
# Validate the rules first (syntax + expression).
docker compose exec prometheus promtool check rules /etc/prometheus/alerts.yml

# Hot-reload without restarting Prometheus (requires --web.enable-lifecycle).
curl -X POST http://localhost:9090/-/reload
```

If `--web.enable-lifecycle` is not set, restart the container: `docker compose restart prometheus`.

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
   docker exec edgeguard_prometheus wget -qO- host.docker.internal:8001/metrics
   ```

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
# Pull latest images
docker-compose -f docker-compose.monitoring.yml pull

# Recreate containers
docker-compose -f docker-compose.monitoring.yml up -d
```

### Cleanup

```bash
# Stop all monitoring services
docker-compose -f docker-compose.monitoring.yml down

# Remove volumes (WARNING: deletes all data)
docker-compose -f docker-compose.monitoring.yml down -v
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

_Last updated: 2026-04-19 — chips 5b + 5e added five new source-truthful counters: `edgeguard_source_truthful_claim_accepted_total` / `_dropped_total` / `_coerce_rejected_total` / `_future_clamp_total` (PR #42, observability for the per-source first_seen / last_seen pipeline shipped in PR #41) plus `edgeguard_source_truthful_creator_rejected_total` (PR #44, fires when the MISP tag-impersonation defense refuses a source-truthful claim). Prior pass 2026-03-24: repo **`prometheus/prometheus.yml`** scrapes EdgeGuard metrics at **`host.docker.internal:8001`** (not 8000 REST). Metrics server default port **8001**._
