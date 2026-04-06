# EdgeGuard Airflow DAGs (operations guide)

**Last Updated:** 2026-03-29
**Purpose:** Automated ETL pipeline for threat intelligence collection and synchronization.  
**DAG Python files:** repository `dags/` directory.

**Where you are in the docs:** Step **2** of the operator path — read after **[SETUP_GUIDE.md](SETUP_GUIDE.md)**. **Next →** **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for a safe first **`edgeguard_baseline`**. Full order: [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) § *Recommended reading order*.

---

## Overview

EdgeGuard uses Apache Airflow to orchestrate the automated collection of threat intelligence from multiple sources, pushing to MISP, and syncing to Neo4j.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EdgeGuard Pipeline                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐   │
│  │   Sources    │ -> │     MISP     │ -> │   Neo4j      │ -> │  NATS   │   │
│  │ (feeds — see │    │ (Central Hub)│    │ (Knowledge   │    │ (Alerts)│   │
│  │ DATA_SOURCES)│    │              │    │   Graph)     │    │         │   │
│  └──────────────┘    └──────────────┘    └──────────────┘    └─────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Airflow orchestrates:
  1. External Collectors → MISP (scheduled by source)
  2. MISP → Neo4j sync (periodic)
  3. Alert generation via NATS
```

---

## DAG Structure

EdgeGuard defines **6** primary DAGs in `dags/edgeguard_pipeline.py` (baseline + five scheduled pipelines). **Optional** Prometheus metrics DAGs live in `dags/edgeguard_metrics_server.py`: **`edgeguard_metrics_server`** / **`edgeguard_metrics_server_scheduled`** (blocking metrics HTTP task only) and **`edgeguard_metrics_helpers`** (manual **generate_test_metrics** → **health_check**, run after the server is up).

### DAGs Overview (edgeguard_pipeline.py)

| DAG Name | Schedule | Purpose | Sources |
|----------|----------|---------|---------|
| `edgeguard_baseline` | Manual | One-time deep historical load | Tiered collectors → full MISP→Neo4j + enrichment |
| `edgeguard_pipeline` | Every 30 min | High-frequency updates | AlienVault OTX |
| `edgeguard_medium_freq` | Every 4 hours | Medium-frequency sources | CISA KEV, VirusTotal |
| `edgeguard_low_freq` | Every 8 hours | Low-frequency sources | NVD |
| `edgeguard_daily` | Daily at 2 AM | Daily feeds | MITRE, ThreatFox, AbuseIPDB, URLhaus, CyberCure, Feodo, SSLBlacklist |
| `edgeguard_neo4j_sync` | `0 3 */3 * *` (every 3 days at 03:00) | MISP → Neo4j sync + `build_relationships` + `run_enrichment_jobs` | All sources |

**Concurrency and timeout guards (all 6 DAGs):**

| DAG | `max_active_runs` | `dagrun_timeout` | Notes |
|-----|-------------------|------------------|-------|
| `edgeguard_pipeline` | 1 | 5h 30m | Covers OTX with full retry chain |
| `edgeguard_medium_freq` | 1 | 5h | CISA + VT parallel with retries |
| `edgeguard_low_freq` | 1 | 8h 30m | NVD with full retry chain |
| `edgeguard_daily` | 1 | 8h 30m | 7 parallel collectors with retries |
| `edgeguard_neo4j_sync` | 1 | 22h | Full sync + relationships + enrichment |
| `edgeguard_baseline` | 1 | 32h | Full historical collection + sync |

`max_active_runs=1` prevents run pile-up when a run is slow. `dagrun_timeout` is wall-clock time from DAG run start — if the entire run (including retries) exceeds this, Airflow marks it as failed. These are calculated as worst-case: `execution_timeout x (1 + retries) + retries x retry_delay` summed across the sequential task chain, with a 20% buffer.

**Callbacks:** All DAGs inherit `on_failure_callback` (logs `[ALERT]`, sends Slack if enabled, increments Prometheus error counter) and `on_success_callback` (updates `edgeguard_dag_last_success_timestamp` gauge for stuck-run detection).

**Baseline note:** `edgeguard_baseline` uses `is_paused_upon_creation=False` so manual triggers execute immediately without needing to unpause first.

**Metrics (optional):** `edgeguard_metrics_server` (+ `…_scheduled`) and **`edgeguard_metrics_helpers`** in `dags/edgeguard_metrics_server.py` — default scrape URL `http://127.0.0.1:8001/metrics` (`EDGEGUARD_METRICS_HOST` / `EDGEGUARD_METRICS_PORT`).

**Note:** “Items/Run” figures below are **order-of-magnitude defaults**; effective limits come from `get_effective_limit()` (`EDGEGUARD_INCREMENTAL_LIMIT`, `EDGEGUARD_MAX_ENTRIES`, baseline Airflow Variables).

---

## Source Schedules

### By Frequency

#### High Frequency (Every 30 minutes)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| AlienVault OTX | `edgeguard_pipeline` | 30 req/min | 50 pulses |

#### Medium Frequency (Every 4 hours)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| CISA KEV | `edgeguard_medium_freq` | No limit | 500 CVEs |
| VirusTotal | `edgeguard_medium_freq` | 4 req/min | 10-20 IOCs |

#### Low Frequency (Every 8 hours)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| NVD | `edgeguard_low_freq` | 50 req/30sec (with key) | Up to configured limit (paginated, ≤2000 CVEs/request) |

#### Daily (Once per day)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| MITRE ATT&CK | `edgeguard_daily` | No limit | 500 items |
| ThreatFox | `edgeguard_daily` | No limit | 100 IOCs |
| AbuseIPDB | `edgeguard_daily` | 1000/day | 100 IPs |
| URLhaus | `edgeguard_daily` | No limit | 100 URLs |
| CyberCure | `edgeguard_daily` | No limit | 50 IOCs |
| Feodo Tracker | `edgeguard_daily` | No limit | 10 IPs |
| SSL Blacklist | `edgeguard_daily` | No limit | 100 certs |

---

## All Collectors

### Working Collectors (Pushing to MISP)

| Collector | Class | Source File | Zone Detection |
|-----------|-------|-------------|----------------|
| AlienVault OTX | `OTXCollector` | `otx_collector.py` | Keyword-based |
| NVD | `NVDCollector` | `nvd_collector.py` | `detect_zones_from_item()` + CVE description + flattened CPE criteria (`configurations_to_zone_text`) |
| CISA KEV | `CISACollector` | `cisa_collector.py` | Keyword-based |
| MITRE ATT&CK | `MITRECollector` | `mitre_collector.py` | N/A (TTPs) |
| VirusTotal | `VTCollector` | `vt_collector.py` | Scheduled on `edgeguard_medium_freq` (`virustotal_collector.py` / `VirusTotalCollector` exists for optional enrichment — not on a default DAG) |
| AbuseIPDB | `AbuseIPDBCollector` | `abuseipdb_collector.py` | Confidence-based |
| ThreatFox | `ThreatFoxCollector` | `global_feed_collector.py` | Malware family |
| URLhaus | `URLhausCollector` | `global_feed_collector.py` | Tags |
| CyberCure | `CyberCureCollector` | `global_feed_collector.py` | Keyword-based |
| Feodo | `FeodoCollector` | `finance_feed_collector.py` | Hardcoded Finance |
| SSL Blacklist | `SSLBlacklistCollector` | `finance_feed_collector.py` | Malware family |

### Placeholder Collectors (Not Yet Active)

| Collector | Source File | Notes |
|-----------|-------------|-------|
| Energy | `energy_feed_collector.py` | Needs ENTSO-E/EU-CERT membership |
| Healthcare | `healthcare_feed_collector.py` | Needs H-ISAC/EHFC membership |

---

## MISP Tagging

### Event level (new events from `MISPWriter`)

| Tag | Role |
|-----|------|
| **`EdgeGuard`** | Platform provenance (e.g. ResilMesh / EdgeGuard pipeline). **Only** event-level tag added on create. |

**`Event.info`** uses **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`). Zone classification lives on attribute-level tags (`zone:Finance`, `zone:Healthcare`), not in the event name. A single event can contain multi-zone attributes.

**Legacy:** Older events may still carry `sector:…`, `source:…`, or TLP on the event; sync and parsers still understand them. New writes follow the model above — see [MISP_SOURCES.md](MISP_SOURCES.md).

### Attribute level (all pushed indicators/objects)

**Source tags** (per attribute):

| Source | MISP Tag |
|--------|----------|
| AlienVault OTX | `source:AlienVault-OTX` |
| NVD | `source:NVD` |
| CISA KEV | `source:CISA-KEV` |
| MITRE ATT&CK | `source:MITRE-ATT&CK` |
| VirusTotal | `source:VirusTotal` |
| AbuseIPDB | `source:AbuseIPDB` |
| ThreatFox | `source:ThreatFox` |
| URLhaus | `source:URLhaus` |
| CyberCure | `source:CyberCure` |
| Feodo Tracker | `source:Feodo-Tracker` |
| SSL Blacklist | `source:SSL-Blacklist` |

**Zone tags** (per attribute — source of truth for classification): `zone:Global`, `zone:Healthcare`, `zone:Energy`, `zone:Finance` (capitalization as written by `MISPWriter`), plus confidence tags. **`MISPWriter._get_zones_to_tag`** drops redundant `global` when any specific zone is present.

---

## Neo4j Sync

### Schedule
- **Frequency:** Every 3 days
- **Process:** MISP → Neo4j using MERGE (upsert)

### Airflow task: `run_neo4j_sync` (`edgeguard_neo4j_sync` DAG)

1. **`check_sync_needed`** (`ShortCircuitOperator`) — if the last successful sync (state file under `EDGEGUARD_STATE_DIR` / `dags/`) is newer than **`NEO4J_SYNC_INTERVAL`** hours (Airflow Variable, default 72), it **short-circuits** and **skips** `run_neo4j_sync` and **all downstream tasks** (`build_relationships`, `run_enrichment_jobs`, …). So a “green” DAG run can mean **sync did not run** (skipped).
2. **`run_neo4j_sync`** — imports **`MISPToNeo4jSync`**, chooses **full** vs **incremental** sync (first-ever run or Airflow Variable **`NEO4J_FULL_SYNC=true`** → full; otherwise incremental, default window last 3 days), calls **`sync.run()`**, then on success updates the state file and metrics.
   - **OOM on very large attribute sets:** `sync_to_neo4j()` merges in **Python-side chunks** (default **1000** items per chunk, 3s pause between chunks). Events with **>5000 attributes** are automatically **streamed in pages** of 5000 with `gc.collect()` between pages. Set **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** lower on the Airflow worker if the process is still killed. Default **`AIRFLOW_MEMORY_LIMIT`** is **12g** (100K+ attribute events need 8-12GB for PyMISP JSON parsing).
3. **Downstream** — `build_relationships` materializes cross-node edges (e.g. **`USES`** ThreatActor→Technique and **Malware→Technique** from MITRE **`uses_techniques`**, **`INDICATES`** from MISP co-occurrence, …); `run_enrichment_jobs` runs decay/campaign/bridge jobs. Both can succeed with little effect if the sync wrote no nodes.

MISP search/index responses are normalized in code (see **`normalize_misp_event_index_payload`** in [`run_misp_to_neo4j.py`](../src/run_misp_to_neo4j.py)): each row must become a **flat** event dict with **`id`**, not only `{'Event': {...}}`.

### Node Types
| Node Label | Count (approx) | Key Properties |
|------------|----------------|----------------|
| Indicator | ~8,000 | value, type, source, zone |
| Vulnerability | ~500 | cve_id, severity, cvss_score |
| ThreatActor | ~100 | name, aliases, description |
| Technique | ~300 | mitre_id, name, description |
| Malware | ~100 | name, family, type |
| Source | 13 | source_id, name |

### Deduplication
Neo4j uses unique constraints:
- `Indicator`: value + source
- `Vulnerability`: cve_id + source
- `ThreatActor`: name + source
- `Technique`: mitre_id + source
- `Malware`: name + source

**Running again does NOT create duplicates** — MERGE updates existing nodes.

**MISP vs Neo4j:** The graph deduplication above is **independent** of MISP. The same logical IOC may still appear on **more than one** EdgeGuard MISP event (e.g. different dates); **`MISPWriter`** prefetch + source cursors reduce **re-pushes** to the **current** target event — see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*.

---

## Features

### Built-in Features
- ✅ Circuit breaker for failed collectors
- ✅ Prometheus metrics export (via dedicated `edgeguard_metrics_server` DAG on port 8001)
- ✅ Slack alerts (optional)
- ✅ MISP **preflight** task (`misp_health_check` — fast `PythonOperator`, API+DB gate; see troubleshooting)
- ✅ Container health verification
- ✅ Rate limit awareness (each source group has its own DAG schedule)
- ✅ Incremental sync support
- ✅ Error handling and retry logic (`retries=2`, `retry_delay=5min`; baseline: `retries=1`)
- ✅ Execution timeouts on all tasks (prevents hung workers)
- ✅ `dagrun_timeout` on all DAGs (prevents entire DAG runs from hanging indefinitely)
- ✅ `max_active_runs=1` on all DAGs (prevents concurrent run pile-up)
- ✅ `on_failure_callback` / `on_success_callback` for alerting and metrics
- ✅ `ShortCircuitOperator` gates the Neo4j sync (skips when nothing new; error-tolerant on corrupted state file)
- ✅ Pipeline lock file (`checkpoints/pipeline.lock`) for CLI runs to prevent concurrent `run_pipeline.py` invocations
- ✅ `--fresh-baseline` performs a true clean slate: clears Neo4j graph data + MISP EdgeGuard events + checkpoints, then re-collects from scratch. Incremental cursor state is preserved so scheduled runs resume correctly after the baseline.
- ✅ MISP dedup logging: `[DEDUP]` when all items already exist, `[SKIP]` when nothing new to push

### Metrics Exported
```
edgeguard_indicators_collected_total{source, zone}
edgeguard_sync_duration_seconds{operation}
edgeguard_dag_runs_total{status, dag_id}
```

---

## Running DAGs

### Manual Run
```bash
# Start Airflow
airflow webserver -p 8080
airflow scheduler

# Trigger specific DAG
airflow dags trigger edgeguard_pipeline
airflow dags trigger edgeguard_daily
```

### Check Status
```bash
# List all DAGs
airflow dags list | grep edgeguard

# Show DAG tasks
airflow tasks list edgeguard_pipeline

# Show DAG runs
airflow dags list-runs -d edgeguard_pipeline
```

### EdgeGuard CLI (recommended — wraps Airflow REST API)

```bash
# See all DAG run states (color-coded)
python src/edgeguard.py dag status

# See only running/queued runs
python src/edgeguard.py dag status --state running

# Force-fail stuck DAG runs (preserves checkpoints + incremental state)
python src/edgeguard.py dag kill

# Kill a specific DAG only
python src/edgeguard.py dag kill --dag-id edgeguard_baseline

# Check data counts (by zone, by source, MISP breakdown)
python src/edgeguard.py stats --full

# Check baseline checkpoint progress
python src/edgeguard.py checkpoint status

# Pre-run readiness check (env vars, APIs, Neo4j, MISP, Airflow, disk)
python src/edgeguard.py preflight
```

### View Logs
```bash
airflow logs <task_id> <dag_run_id>
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| DAG runs stuck in "queued" | Check if DAG is paused: `edgeguard dag status`. Kill stuck runs: `edgeguard dag kill` |
| Collectors failing repeatedly | Reset circuit breakers + retry: `edgeguard heal` |
| Need a completely fresh start | `python src/run_pipeline.py --baseline --fresh-baseline --baseline-days N` (clears Neo4j + MISP + checkpoints) |
| Airflow not reachable | `edgeguard doctor` retries after 10s; check container: `docker compose ps airflow` |
| Pipeline already running (lock error) | Wait for it to finish, or delete `checkpoints/pipeline.lock` if stale |
| Need to clear just Neo4j or MISP | `edgeguard clear neo4j` / `edgeguard clear misp` / `edgeguard clear all` |
| OOM on large MISP events (100K+ attrs) | Events >5000 attributes are automatically streamed in pages. Increase `AIRFLOW_MEMORY_LIMIT` in `.env` if still failing |

---

## Environment Variables

```bash
# MISP
export MISP_URL="https://localhost:8443"
export MISP_API_KEY="your-misp-api-key"

# Neo4j (from **inside** Docker Compose services use bolt://neo4j:7687 — see docker-compose.yml x-common-env)
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-password"

# API Keys
export OTX_API_KEY="your-otx-key"
export NVD_API_KEY="your-nvd-key"
export VIRUSTOTAL_API_KEY="your-vt-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export THREATFOX_API_KEY="your-threatfox-key"

# Airflow
export AIRFLOW__CORE__EXECUTOR=LocalExecutor
export EDGEGUARD_BASE_DIR="/path/to/EdgeGuard-Knowledge-Graph"

# Monitoring
export EDGEGUARD_ENABLE_METRICS=true     # Enable Prometheus metrics
export EDGEGUARD_METRICS_PORT=8001       # Must not conflict with FastAPI (8000)
```

---

## Troubleshooting

### DAG run stuck in **queued** (scheduler “running” but nothing executes)

**Typical causes:** Airflow cannot reach its **metadata database**, migrations did not complete, or the scheduler process is unhealthy.

**EdgeGuard Docker Compose:** `docker-compose.yml` uses **PostgreSQL** (`airflow_postgres`) for metadata. Ensure Postgres is healthy, then restart:

```bash
docker compose ps
docker compose logs airflow_postgres
docker compose logs airflow
docker compose down && docker compose up -d
```

On first start, grab the Airflow UI bootstrap credentials from `docker compose logs airflow`.

**Bare-metal / pip Airflow:** set **`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`** to **PostgreSQL** or **MySQL** (see [Apache Airflow database docs](https://airflow.apache.org/docs/apache-airflow/stable/howto/set-up-database.html)). Keep **`AIRFLOW__CORE__EXECUTOR`** aligned with your deployment (e.g. `LocalExecutor` with a proper metadata backend).

**Scaling:** for multi-worker production layouts, prefer the [official Airflow compose](https://airflow.apache.org/docs/apache-airflow/stable/howto/docker-compose/index.html) or your platform’s chart — still with Postgres/MySQL metadata.

### `misp_health_check` blocked the DAG for many minutes (sensor timeout)

**What changed:** DAGs used a **`PythonSensor`** that re-poked until MISP returned “fully healthy” (including workers). Many MISP instances have **workers down** while **API + DB** are fine. The old sensor treated that as not ready and blocked until **timeout**.

**Current behavior:**

- **`misp_health_check`** is a **`PythonOperator`** that runs **once** per DAG run and **fails fast** (typical runtime: a few HTTP calls, &lt; ~1–2 minutes) instead of waiting 5–10+ minutes.
- Pass criteria use **`MISPHealthCheck.check_health()`** → **`healthy_for_collection`** (same as **`healthy`** for API+DB; workers optional). With **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`**, preflight also requires **`checks["worker_status"]`**. Return type is **`MISPHealthCheckResult`** in **`src/misp_health.py`** (dict-like: **`[]`**, **`.get()`**, **`in`** for field names). Same policy as **`run_pipeline_misp_spt.check_misp_health()`**.

**Env vars (Airflow worker/scheduler environment):**

| Variable | Effect |
|----------|--------|
| *(default)* | Require **API + DB** only for preflight success. |
| `EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true` | Require workers as well (stricter; same as old “all green” behavior). |
| `EDGEGUARD_SKIP_MISP_PREFLIGHT=true` | **Skip** the check entirely — emergency / debugging only; not recommended in production. |

If preflight still fails, fix **reachability** from the Airflow container to **`MISP_URL`** (see `docs/ENVIRONMENTS.md` — `localhost` inside Docker is usually wrong).

**Docker + Apache + `EDGEGUARD_MISP_HTTP_HOST` (common pitfall):**

- **`MISP_URL`** must be a hostname the **Airflow worker** resolves to the MISP container (e.g. Compose service name), not `https://localhost/...` unless MISP really listens there **inside the worker’s network namespace**.
- If Apache issues **absolute redirects** to `https://localhost/...`, the **requests** client may follow them and connect to **localhost on the Airflow container** (wrong service). Fix **Apache** (relative redirects, correct internal URL, or `ServerName` aligned with how clients connect) — that is **infrastructure**, not EdgeGuard.
- **`EDGEGUARD_MISP_HTTP_HOST`** sets the HTTP `Host` header when the TLS/SNI name must differ from the URL host (vhost). If you need `Host: localhost` for SSL but redirects break cross-container access, you must fix **redirect targets** in Apache; there is no safe “header only” workaround for bad `Location:` URLs.
- On **MISP 2.4.124**, `/servers/healthCheck` may be **missing (404)** or **redirect to login (302)**. EdgeGuard’s API probe uses **`allow_redirects=False`** on that URL and then tries **`/servers/getWorkers`** and **`/events/index`** so preflight matches what works with the API key.

**Self-signed MISP HTTPS (`certificate verify failed`):** EdgeGuard defaults to **verifying** TLS (**`EDGEGUARD_SSL_VERIFY`** defaults to **`true`**). For a **dev/lab** MISP with a self-signed cert, set **`EDGEGUARD_SSL_VERIFY=false`** on the **Airflow worker and scheduler** (same as other MISP env vars), then restart/recreate containers. Prefer installing your CA in the image over disabling verify in production. The env name **`SSL_CERT_VERIFY`** is **not** read; optional alias: **`SSL_VERIFY=false`** only if **`EDGEGUARD_SSL_VERIFY`** is unset or empty.

### MISP → Neo4j sync logs **“No events”** while MISP has EdgeGuard events

**Causes to check:**

1. **Stale code:** Older builds used **`eventinfo`** or heavy **`restSearch`** only. Current **`fetch_edgeguard_events()`** uses **`GET /events/index`** (then **`/events`**) with **client-side** filter: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) **or** **`org.name`** is **`EdgeGuard`**. If the index fails, it falls back to PyMISP **`restSearch`** with **`search`**.

2. **JSON vs HTML:** The sync **`requests.Session`** sends **`Accept: application/json`** (and **`Authorization`**) so MISP returns JSON, not a login HTML page.

3. **Wrong substring / org:** Set **`EDGEGUARD_MISP_EVENT_SEARCH`** if titles don’t contain the default substring, or ensure publishing org name matches the filter if you rely on **`EdgeGuard`** org.

4. **Incremental window:** Incremental sync only keeps events whose **`timestamp`** / **`date`** (when present) is on/after the **`since`** window; baseline **`full_neo4j_sync`** uses **`incremental=False`** and loads all matching index rows (subject to index pagination caps).

### Airflow container: **neo4j** / **pymisp** missing after recreate

**Do not** rely on **`pip install`** inside a running `apache/airflow` container — packages are lost when the container is recreated.

**Compose fix:** the **`airflow`** service is built from **`Dockerfile.airflow`**, which installs **`requirements-airflow-docker.txt`**. After changing that file or Python deps, rebuild:

```bash
docker compose build airflow && docker compose up -d airflow
```

**`PYTHONPATH` and mounted `src/`:** Compose sets **`PYTHONPATH=/opt/airflow/src`** so imports like **`config`**, **`neo4j_client`**, **`misp_health`** resolve from the read-only **`./src:/opt/airflow/src`** mount. If you still see **`ModuleNotFoundError`**, confirm you recreated the stack after pulling **`docker-compose.yml`**, and that **`Dockerfile.airflow`** was rebuilt (custom image, not plain `apache/airflow`).

**`Dockerfile.airflow` + `tini`:** The custom image uses **`tini`** as PID 1 and **`CMD ["airflow", "standalone"]`**. Do **not** set **`command: standalone`** in Compose — that overrides **`CMD`** and can break the process list (e.g. **`tini -- standalone`** instead of **`tini -- airflow standalone`**). Rebuild after **`Dockerfile.airflow`** changes.

### `edgeguard_baseline` — Tier1 MITRE / NVD failures, “zombie” tasks, long runs

**Symptoms:** `tier1_core.collect_mitre` or `collect_nvd` fails after **up_for_retry**, or NVD runs a long time then is marked **zombie** / killed.

**Tier2 / `full_neo4j_sync` vs Tier1 failures:** **`tier2_feeds`** tasks use **`TriggerRule.ALL_DONE`** on Tier1 upstreams, so a failed **`collect_otx`** (or another Tier1 task) no longer leaves Tier2 as **`upstream_failed`**. **`full_neo4j_sync`** uses **`ALL_DONE`** after Tier2 so MISP→Neo4j still runs when some bulk collectors fail — Neo4j reflects whatever landed in MISP.

**How to trace**

| What | Where to look |
|------|----------------|
| **Root error** | Airflow UI → DAG `edgeguard_baseline` → failed task → **Log** (search: `MISP`, `HTTP`, `Timeout`, `Failed to push`, `MITRE`, `NVD`, `AirflowException`). |
| **MISP-side** | MISP server logs / web UI (auth errors, validation, rate limits, disk). Airflow must reach **`MISP_URL`** from **inside** the Airflow container. |
| **Config used** | Task **`baseline_start`** log prints **`BASELINE_DAYS`** and **`BASELINE_COLLECTION_LIMIT`** (Airflow **Admin → Variables**). |

**MITRE (`collect_mitre`)**

- Downloads a large STIX bundle (~80 MB) from GitHub, parses JSON, then **`misp_writer.push_items`** for thousands of objects. Failures are often **MISP timeouts**, **SSL**, **auth**, or **payload validation** — the task log and MISP logs together confirm it.
- **Scheduled (non-baseline) runs:** when **`EDGEGUARD_MITRE_CONDITIONAL_GET`** is enabled, the collector uses **`If-None-Match`**; **HTTP 304** skips download/parse/push if the bundle is unchanged. **Baseline** still fetches the full bundle.
- **`run_collector_with_metrics`** raises **`AirflowException`** if the collector returns **`success: false`** (including “all pushes failed”), so the UI should show a clear failure after deploy.
- If **`metrics_server`** is enabled, **`set_source_health(source, zone, healthy)`** requires **three** arguments. Older call sites used **`(name, False)`**, which raised **`TypeError: ... missing ... 'healthy'`** *before* **`AirflowException`** — fixed in `edgeguard_pipeline.py` (always pass zone, e.g. **`"global"`**).

**`up_for_retry`:** With **`retries: 1`** on baseline Tier1 tasks, a first failure can show as **up_for_retry** until the retry is consumed; the final state should be **failed** or **success**, not stuck indefinitely.

**NVD (`collect_nvd`) — baseline**

- With **`BASELINE_DAYS`** set to **90** (or **730**), NVD walks many **120-day** API windows and **pages** (0.7 s between pages with an API key). Then it **processes** all CVEs and **pushes** to MISP in bulk — this can take **hours**.
- **`execution_timeout`** for baseline NVD is **3 hours** in `dags/edgeguard_pipeline.py`. If you need more wall-clock time, increase that timeout (and ensure the scheduler/worker is not restarted mid-run).
- A **“zombie”** message usually means the scheduler lost the task heartbeat (scheduler/worker restart, heavy CPU blocking, OOM, or platform kill) — check **`docker compose logs airflow`**, host **memory**, and whether the task process was killed. It is **not** always the same as hitting `execution_timeout`.

**Smoke test (recommended before a full baseline)**

See **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for copy-paste **`.env`** examples (`EDGEGUARD_BASELINE_DAYS=7`, `EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000`) and restart steps. For a printable runtime checklist (Docker + `airflow dags trigger`), see [`scripts/runtime_smoke_checklist.sh`](../scripts/runtime_smoke_checklist.sh).

Or use Airflow **Variables** only: `BASELINE_DAYS` = **`7`**, `BASELINE_COLLECTION_LIMIT` = **`500`** or **`1000`**.

After Tier1 succeeds, remove env overrides or restore Variables for production.

**NVD resume:** Baseline NVD writes checkpoints under **`get_source_checkpoint("nvd")`** — a new run can resume windows; see `src/collectors/nvd_collector.py` and `baseline_checkpoint` usage.

### DAG Not Running
1. Check Airflow scheduler is running: `airflow scheduler`
2. Verify DAG file is in `$AIRFLOW_HOME/dags/`
3. **CI / local parse check:** from repo root run [`scripts/preflight_ci.sh`](../scripts/preflight_ci.sh) (`compileall`, `pytest`, Airflow `DagBag` load with `NEO4J_PASSWORD` set). Airflow 2.11+ has no `airflow dags validate` subcommand; use `airflow dags list-import-errors` after `airflow db init` if you use the full CLI.

### Collector Failures
1. Check API key configuration
2. Verify network connectivity to source
3. Check rate limits: `airflow logs <task_id>`

**Optional API keys (skip without failing the DAG):** If an optional key is unset, the corresponding task **succeeds** with a **warning** log, **`skipped: true`** in the return payload, Prometheus counter **`edgeguard_collector_skips_total`** (label `reason_class=...`), and **`edgeguard_indicators_collected_total{status="skipped"}`** (count 0). Supported optional sources:

| Env var | `reason_class` (metrics label) |
|---------|--------------------------------|
| **`ABUSEIPDB_API_KEY`** | `missing_abuseipdb_key` (also **`abuseipdb_auth_denied`** on HTTP 401/403) |
| **`OTX_API_KEY`** | `missing_otx_key` (also **`otx_auth_denied`** on 401/403) |
| **`VIRUSTOTAL_API_KEY`** | `missing_virustotal_key` (also **`virustotal_auth_denied`** on 401/403) |
| **`THREATFOX_API_KEY`** | `missing_threatfox_key` (also **`threatfox_auth_denied`** on 401/403) |

Add keys when you want those feeds. Values that are **empty**, **whitespace-only**, or YAML **placeholders** from `credentials/config.example.yaml` are treated as unset. **ThreatFox** requires a free key from **https://auth.abuse.ch/** — without it the task **skips** (success) so the baseline DAG can continue.

**Other optional HTTP feeds** (no API key today, but if the upstream returns **401/403**, the task **skips** instead of failing): **NVD** (`nvd_auth_denied`), **CISA KEV** (`cisa_auth_denied`), **MITRE** (`mitre_auth_denied`, e.g. GitHub), **Feodo** (`feodo_auth_denied`), **SSL Blacklist** (`sslbl_auth_denied`). **URLhaus** / **CyberCure** usually return empty success if downloads fail; they are public CSV endpoints.

**Collector allowlist (`EDGEGUARD_COLLECT_SOURCES`):** Optional comma-separated list of which collectors may run (e.g. `otx,nvd,cisa,mitre`). **Unset or empty** → all collectors run (subject to optional-key skips above). **`none`**, **`-`**, or **`0`** alone → no external collectors run; each collection task **succeeds** with **`skipped: true`** and **`skip_reason_class=collector_disabled_by_config`**. Unknown names are **logged and ignored**; if no valid names remain, behavior matches **unset** (fail-open). Applies to **Airflow** (`run_collector_with_metrics`) and **CLI** [`run_pipeline.py`](../src/run_pipeline.py) Step 2 (same canonical source keys as scheduled tasks, including both `virustotal` and `virustotal_enrich`). Implementation: [`src/collector_allowlist.py`](../src/collector_allowlist.py).

### MISP → Neo4j Sync Issues

**Limits (don’t confuse these):** Baseline **`BASELINE_COLLECTION_LIMIT`** caps **external collectors** (OTX, NVD, …), **not** how many MISP events the sync reads. The sync discovers events via **paginated `/events/index`**. **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **1000**) controls **Neo4j merge RAM** (parsed items per Python chunk, 3s pause between chunks), **not** MISP fetch size. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

0. **Sync fails almost immediately (baseline `full_neo4j_sync` or `run_neo4j_sync`):** The script does **not** call EdgeGuard REST/GraphQL — look at **MISP + Neo4j only**. Open the task log and search for **`Cannot start sync`**, **`MISP health check failed`**, **`Neo4j health check failed`**, **`No driver initialized`**, **`APOC`**, or **`circuit breaker`**. Typical fixes: **`NEO4J_URI` / `NEO4J_PASSWORD`** correct **from inside the Airflow worker** (e.g. `bolt://neo4j:7687`, not host-only `localhost` if Neo4j is another container), **APOC** installed and allowed (see `docker-compose` / Neo4j docs), **`MISP_URL`** reachable from the worker, and **`EDGEGUARD_MISP_HTTP_HOST`** if Apache vhost name ≠ URL hostname. Failed tasks now raise **`AirflowException`** with a short **reason** suffix when available.
1. Verify Neo4j is running: `neo4j status`
2. Check MISP is accessible
3. Review sync logs for constraint violations
4. **“Tasks succeeded but Neo4j is empty”**
   - **`check_sync_needed` skipped the run:** confirm whether `run_neo4j_sync` is **skipped** (grey) vs **success** (green). If skipped, shorten the interval, delete the state file (see crontab/README notes), or trigger a one-off full sync via **`NEO4J_FULL_SYNC`**.
   - **Sync ran but ingested 0 items:** In logs, look for **`Processing event None`** or **`Parsed 0 items`**. That usually meant the MISP API returned rows as **`{'Event': {...}}`** while the loop expected a flat dict — fixed by normalizing in **`fetch_edgeguard_events`** (current code). Also check **incremental window**: default is **last 3 days**; older EdgeGuard events need a **full** sync or a wider window.
5. **PyMISP vs REST:** If PyMISP errors and the code falls back to **`/events/index`**, the JSON shape may be a **`response`** / **`events`** wrapper; that is handled when building the normalized list.
6. **Event view shape:** `get_event` / `/events/view` may return a **PyMISP object** or **`{'Event': ...}`**; the sync normalizes to a flat dict before reading **`Attribute`**. REST is always tried if PyMISP returns an unparsed type.
7. **MISP Objects vs flat attributes:** Ingestion uses the event’s top-level **`Attribute`** list. Events that store IOCs only inside **`Object`** (object templates) may log a warning and sync **zero** attributes until object expansion is implemented.
8. **OOM / worker killed during Neo4j insert:** The sync merges in **Python-side chunks** (default **1000** items, 3s pause). Events with **>5000 attributes** are streamed in pages of 5000. Default **`AIRFLOW_MEMORY_LIMIT`** is **12g** (100K+ attr events need 8-12GB). Lower **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** if still OOM.
9. **Cross-item relationships are per MISP event:** The sync builds co-occurrence edges (actor↔technique, indicator↔malware, etc.) **within each event** only, then writes nodes and edges for that event before moving on. This avoids false links and runaway **O(n²)** work across the whole run.
10. **Relationship batching:** **`EDGEGUARD_REL_BATCH_SIZE`** (default **2000**) controls how many relationship definitions are sent per **`create_misp_relationships_batch`** UNWIND round-trip.
11. **Task success vs Airflow “failed” / SIGKILL:** If the graph is updated but the task is red, read **[HEARTBEAT.md](HEARTBEAT.md)** — **`local_task_job_heartbeat_sec`**, **`scheduler_zombie_task_threshold`**, **`zombie_detection_interval`**, and **OOM (-9)** are common causes separate from application exceptions. Compose defaults are documented there.

---

## File Structure

```
EdgeGuard-Knowledge-Graph/
├── dags/
│   ├── edgeguard_pipeline.py        # Collection DAGs (high/medium/low/daily + baseline)
│   └── edgeguard_metrics_server.py  # Dedicated metrics server DAG
├── src/
│   ├── collector_allowlist.py      # EDGEGUARD_COLLECT_SOURCES (parse-time safe for DagBag)
│   ├── collectors/               # All collectors
│   │   ├── otx_collector.py
│   │   ├── nvd_collector.py
│   │   ├── cisa_collector.py
│   │   ├── mitre_collector.py
│   │   ├── vt_collector.py
│   │   ├── abuseipdb_collector.py
│   │   ├── global_feed_collector.py
│   │   ├── finance_feed_collector.py
│   │   └── misp_writer.py
│   ├── run_pipeline.py           # Manual pipeline run
│   └── run_misp_to_neo4j.py      # Manual sync
└── docs/
    └── AIRFLOW_DAGS.md           # This guide (CLI, env, troubleshooting)
```

---

## Quick Reference

| Action | Command |
|--------|---------|
| List DAGs | `airflow dags list \| grep edgeguard` |
| Trigger pipeline | `airflow dags trigger edgeguard_pipeline` |
| Sync to Neo4j | `airflow dags trigger edgeguard_neo4j_sync` |
| Check status | `airflow dags list-runs -d edgeguard_pipeline` |
| View logs | `airflow logs <task_id> <run_id>` |
