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
| `EDGEGUARD_METRICS_HOST` | Metrics server bind host | `0.0.0.0` |
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
from airflow.operators.python import PythonOperator
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

_Last updated: 2026-03-24 — repo **`prometheus/prometheus.yml`** scrapes EdgeGuard metrics at **`host.docker.internal:8001`** (not 8000 REST). Metrics server default port **8001**._
