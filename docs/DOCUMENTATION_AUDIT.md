# Documentation ↔ codebase audit index

**Purpose:** (1) **Traceability** for papers/reviews — each table row ties a doc to code/config. (2) **Navigation** — what to read in order and what overlaps.

---

**Convention — status:**
- **Verified** — Reviewed against code/config on last audit date; known drift fixed in the same pass.
- **Narrative** — Mostly process/architecture prose; few machine-verifiable claims.

**Last full pass:** 2026-03-24 — **MISP event discovery** = **`/events/index`** pagination + client filter + **`Accept: application/json`** on sync session; **`restSearch`** fallback; **`misp_health`** **`healthy`** = API+DB (workers optional; **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS`** for strict); **Airflow** **`AIRFLOW_MEMORY_LIMIT`** (default **4g**), scheduler zombie/heartbeat env vars; **Prometheus** scrape **8001**; **api/graphql** **`Dockerfile`** **`chown /app/src`**. Prior **2026-03-21** pass: per-event MISP→Neo4j, **`EDGEGUARD_REL_BATCH_SIZE`**, **HEARTBEAT.md**, SSL env aliases, etc.

---

## Navigating overlapping topics

| If you need… | Start here | Avoid duplicating in… |
|--------------|------------|------------------------|
| **Integration contract** (who owns which nodes, ISIM, `edgeguard_managed`) | [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) | Long prose in README — link instead |
| **Platform / NATS diagram** (how alerts flow) | [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) | Keep one diagram authoritative |
| **CSV / Malware→Technique `USES`** vs ResilMesh files | [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Cross-link only |
| **MISP feeds + discovery + troubleshooting** | [MISP_SOURCES.md](MISP_SOURCES.md) | AIRFLOW_DAGS — keep only task-level troubleshooting |
| **Which limit is which (500 vs baseline caps)** | [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) | README duplicates the short table only |

---

## Root

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [README.md](../README.md) | Quick start, **upgrade**, ports, DAG overview, MISP index discovery + env, **`AIRFLOW_MEMORY_LIMIT`**, **HEARTBEAT.md**, **collection/sync limits** | `install.sh`, `docker-compose.yml`, `Dockerfile`, `Dockerfile.airflow`, `dags/edgeguard_pipeline.py`, `src/config.py`, `src/run_misp_to_neo4j.py`, `src/misp_health.py`, `docs/COLLECTION_AND_SYNC_LIMITS.md`, `docs/HEARTBEAT.md` | Verified (2026-03-24) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR checklist, local CI parity, **Python 3.12+**, generated Airflow files | `.github/workflows/ci.yml`, `Makefile`, `.gitignore`, `pyproject.toml`, `tests/test_*cli*` | Verified (2026-03-24) |

---

## Core architecture & data

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline diagrams, **per-event MISP→Neo4j**, index discovery + restSearch fallback, cross-item edges, **`EDGEGUARD_REL_BATCH_SIZE`**, zone scoring; pointer to **collector → MISP** dedup | `dags/edgeguard_pipeline.py`, `src/config.py`, `src/collectors/*`, `src/run_misp_to_neo4j.py`, `src/neo4j_client.py`, `src/run_pipeline.py` | Verified (2026-03-24) |
| [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) | Baseline vs incremental vs MISP **index** vs **restSearch** fallback vs Neo4j chunk vs rel batch vs `MISPCollector`; **MISP prefetch** + **OTX/MITRE** incremental env rows | `src/config.py`, `src/run_misp_to_neo4j.py`, `src/neo4j_client.py`, `src/collectors/misp_collector.py`, `src/collectors/misp_writer.py`, `dags/edgeguard_pipeline.py`, `src/run_pipeline.py`, `src/baseline_checkpoint.py` | Verified (2026-03-24) |
| [DATA_SOURCES.md](DATA_SOURCES.md) | 13 source slots, per-source notes (overview counts illustrative) | `src/collectors/*`, DAG callables | Verified (2026-03-21) |
| [DATA_SOURCES_RATE_LIMITS.md](DATA_SOURCES_RATE_LIMITS.md) | API rate limits | Vendor docs + collector code | Verified |
| [COLLECTORS.md](COLLECTORS.md) | Per-collector reference; **§ Duplicate avoidance** (MISP prefetch, OTX cursor, MITRE 304); **§ MISP Collector** = optional path vs **`run_misp_to_neo4j`** (index discovery + per-event parse) | `src/collectors/*.py`, `dags/edgeguard_pipeline.py`, `src/run_misp_to_neo4j.py`, `src/baseline_checkpoint.py` | Verified (2026-03-24) |

---

## Airflow

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) | CLI, env, MISP preflight + sync troubleshooting, **HEARTBEAT.md**; Neo4j MERGE vs MISP duplicate semantics; MITRE **304** on scheduled runs | `dags/*.py`, `docker-compose.yml`, `src/run_misp_to_neo4j.py`, `src/misp_health.py`, `src/neo4j_client.py` | Verified (2026-03-24) |

---

## Graph & schema

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md) | Nodes, relationships, MISP→Neo4j **per-event** + chunking + **`EDGEGUARD_REL_BATCH_SIZE`** | `src/neo4j_client.py`, `src/build_relationships.py`, `src/run_misp_to_neo4j.py` | Verified (2026-03-21) |
| [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Property specs | `src/neo4j_client.py`, `src/graphql_schema.py` | Verified |
| [NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md) | Example Cypher | Neo4j label/property usage in code | Verified |

---

## Operations & security

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | **Onboarding:** Compose vs venv, **`x-common-env`**, **`AIRFLOW_MEMORY_LIMIT`**, MISP networking, APOC, troubleshooting (PermissionError, SIGKILL, zombies) | `install.sh`, `docker-compose.yml`, `Dockerfile`, `Dockerfile.airflow`, `.env.example`, `src/health_check.py`, `src/config.py` | Verified (2026-03-24) |
| [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) | **Workstation / high-RAM:** **`NEO4J_HEAP_*` / `NEO4J_PAGECACHE` / `NEO4J_CONTAINER_MEMORY_LIMIT`**, clean slate (`compose down -v`), `host.docker.internal` vs MISP container URL, MISP `docker run` caveats; **Airflow** image **Python 3.12** | `docker-compose.yml`, `.env.example`, `Dockerfile.airflow`, `docs/MISP_SOURCES.md` | Verified (2026-03-24) |
| [ENVIRONMENTS.md](ENVIRONMENTS.md) | **`EDGEGUARD_ENV`**, **Python 3.12+**, conda | `src/config.py`, `pyproject.toml` | Verified (2026-03-24) |
| [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md) | Credential handling | `.env.example`, `src/config.py` | Verified |
| [API_KEYS_SETUP.md](API_KEYS_SETUP.md) | Obtaining API keys | Collector `config` imports | Narrative + Verified |
| [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md) | Metrics stack; scrape **8001** (`prometheus/prometheus.yml`) | `docker-compose.monitoring.yml`, `prometheus/prometheus.yml`, `src/metrics_server.py`, `dags/edgeguard_metrics_server.py` | Verified (2026-03-24) |
| [RESILIENCE_CONFIG.md](RESILIENCE_CONFIG.md) | Circuit breakers | `src/resilience.py`, `src/metrics_server.py` | Verified |
| [HEARTBEAT.md](HEARTBEAT.md) | Scheduler zombie/heartbeat/**`zombie_detection_interval`**; **`AIRFLOW_MEMORY_LIMIT`**; OOM/SIGKILL vs zombies | `docker-compose.yml` (`AIRFLOW__SCHEDULER__*`, `AIRFLOW_MEMORY_LIMIT`), `docs/AIRFLOW_DAGS.md`, `docs/SETUP_GUIDE.md` | Verified (2026-03-24) |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Checklist | Cross-doc + compose | Verified |

---

## ResilMesh integration

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) | Integration contract: **`REFERS_TO`** Vuln↔CVE, **`EXPLOITS`/`INDICATES`** per **`build_relationships.py`**, no **`MAPS_TO`**, TLP on MISP tags, cross-layer gaps | `enrichment_jobs.py`, `build_relationships.py`, `neo4j_client.py`, `misp_writer.py` | Verified (2026-03-21) |
| [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) | NATS diagram, `Neo4jClient` mapping table (verify methods exist) | `nats_client.py`, `alert_processor.py`, `neo4j_client.py` | Verified (2026-03-21) |
| [RESILMESH_INTEGRATION_TESTING.md](RESILMESH_INTEGRATION_TESTING.md) | Push/pull testing; **`test_resilmesh_schema.py`** (no planned-only bridge methods) | `tests/test_resilmesh_schema.py`, `src/run_pipeline.py` | Verified (2026-03-28) |

---

## Supporting

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [METHODOLOGY.md](METHODOLOGY.md) | Sector classification | `src/config.py` (`SECTOR_KEYWORDS`, scoring) | Verified |
| [MISP_SOURCES.md](MISP_SOURCES.md) | MISP SSoT; **event** tag **`EdgeGuard`** only (sector/source/`zone:` on **attributes**); **index + filter** discovery; **`restSearch`** fallback; **collector → MISP** duplicate avoidance (prefetch + cursors); per-event sync; troubleshooting | `misp_writer.py`, `run_misp_to_neo4j.py`, `misp_health.py`, `neo4j_client.py`, `config.py` (`ZONE_*_THRESHOLD`, dedup env vars) | Verified (2026-03-24) |
| [DATA_QUALITY.md](DATA_QUALITY.md) | Quality practices, MISP→Neo4j per-event + chunking + rel batch | `neo4j_client.py` (`SOURCED_FROM`), `enrichment_jobs.py`, `run_misp_to_neo4j.py` | Verified (2026-03-21) |
| [VERSIONING.md](VERSIONING.md) | CalVer policy (`YYYY.M.D`) | `pyproject.toml`, `edgeguard version` | Verified (2026-03-20) |
| [DEMO.md](DEMO.md) | Mock publisher | `demo/mock_resilmesh_publisher.py` | Verified |
| [sources/README.md](sources/README.md) | Source doc index | — | Narrative |
| [sources/MISP/SETUP.md](sources/MISP/SETUP.md) | MISP setup | MISP product | Narrative |

---

## How to cite code in a paper

Use paths under the repo root, e.g. `dags/edgeguard_pipeline.py` (DAG schedules), `src/config.py` (`get_effective_limit`, `SECTOR_TIME_RANGES`), `src/collectors/nvd_collector.py` (NVD 120-day published-date windows).

---

_Last updated: 2026-04-06_
