# EdgeGuard Production Readiness Assessment

**Before a deployment test:** run the ordered gates in [**Deployment readiness checklist**](DEPLOYMENT_READINESS_CHECKLIST.md) (logic + wiring). Automate Layer 1 with `./scripts/deployment_wiring_check.sh` or `make deploy-check`; set `EDGEGUARD_DEPLOY_CHECK_LIVE=1` for live health checks.

**Local verification:** in a Python **3.12** venv with `requirements-dev.txt`, run `./scripts/preflight_ci.sh` and **`make ci`** (ruff, ruff format, mypy, pytest with coverage), **`make deploy-check`** (static Layer 1), and **`airflow db migrate`** on an ephemeral `AIRFLOW_HOME` followed by **`airflow dags list-import-errors`** (with `MISP_API_KEY` / `MISP_URL` set; it must report no import errors). **Docker image builds** and **live** `health_check.py` / API curls need the host that has Docker and a running stack: run them there before production.

---

## Overall Status: GREEN — READY FOR PRODUCTION TEST

The core pipeline is functional, well-documented, and CI-verified. All CI jobs pass (lint, type-check, unit tests, security scan, Docker build). The main remaining work is Phase 3 (Query Engine) and ResilMesh integration.

---

## Component Readiness

### ✅ COMPLETE - Production Ready

| Component | Status | Notes |
|-----------|--------|-------|
| **Knowledge Graph Schema** | ✅ Ready | Full node/relationship design, UNIQUE constraints |
| **MISP Integration** | ✅ Ready | Writer with sanitization, retry, rate limiting |
| **Airflow DAGs** | ✅ Ready | **6** DAGs; `max_active_runs=1` + `dagrun_timeout` on all; `on_failure_callback`/`on_success_callback`; baseline `is_paused_upon_creation=False`; `ShortCircuitOperator` on Neo4j sync |
| **Data Collectors** | ✅ Ready | 10 active collectors by default (12 with the flag-guarded CISA ICS and MalwareBazaar) → MISP → Neo4j |
| **Neo4j Client** | ✅ Ready | Constraints, indexes, batch ops, sector labels applied |
| **Health Checks** | ✅ Ready | MISP preflight task (`misp_health_check`, PythonOperator) + Docker service healthchecks |
| **Documentation** | ✅ Ready | 20+ documents that describe the current code |
| **Production CLI** | ✅ Ready | 15 top-level commands, among them `preflight`, `stats --full`, `dag status/kill`, `checkpoint status/clear`, `doctor`, `heal`, `validate`, `monitor` |
| **Security Hardening** | ✅ Ready | Input sanitization, injection guards, SSL, rate limiting |
| **Monitoring/Metrics** | ⚠️ Partially | Metrics of every Airflow task process are served by the `metrics` compose service on **8001** (loopback publish for local access; Prometheus scrapes `metrics:8001` over `edgeguard_net`); alert rules evaluate in Prometheus; Alertmanager loads without secrets and delivers to Slack once `prometheus/secrets/slack_api_url` is provided; **the e-mail and PagerDuty receivers are placeholders** (no notification is delivered until a webhook, mailbox or rendered key is configured); Grafana dashboard. |
| **CI/CD Pipeline** | ✅ Ready | GitHub Actions: lint, type-check, unit tests, Docker build, security scan |
| **Automated Code Review** | ✅ Ready | Automated review on every pull request, with project-specific review rules |

### ⏳ NOT STARTED - Future Phases

| Component | Status | Notes |
|-----------|--------|-------|
| **Query Engine** | ⏳ Not Started | Phase 3 - LLM integration |
| **ResilMesh Integration** | ⏳ Partial | GraphQL (port 4001), schema alignment — see `docs/RESILMESH_*.md`; full NATS/TLP/RBAC varies by deployment |

---

## Security and code-quality controls

| Area | Control |
|------|---------|
| Input sanitization | `sanitize_value()` in `src/collectors/misp_writer.py` |
| Retry and rate limiting | `retry_with_backoff()` decorator and `RateLimiter` class in `src/collectors/collector_utils.py`; `rate_limited()` decorator in `src/collectors/misp_writer.py` |
| TLS verification | In code, `config.SSL_VERIFY` defaults to **on**; set **`EDGEGUARD_SSL_VERIFY=false`** for dev self-signed MISP (or **`SSL_VERIFY=false`** only if `EDGEGUARD_SSL_VERIFY` is unset). **`SSL_CERT_VERIFY`** is not read. |
| MISP preflight | `misp_health.py`: **`healthy`** = API + DB (workers optional); stricter preflight via **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS`** |
| Graph keys | UNIQUE constraints per node label, among them `Indicator` (`indicator_type`, `value`) and `Vulnerability` (`cve_id`), created by `src/neo4j_client.py` |
| Provenance timestamps | `SOURCED_FROM.imported_at` is set on create only (`ON CREATE SET`, `src/neo4j_client.py`) |
| Malware → technique edges | **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** built only from explicit MITRE STIX **`uses`** rows: `uses_techniques` on **`Malware`** (collector → `MITRE_USES_TECHNIQUES:` in MISP → `run_misp_to_neo4j` → `merge_malware`) + `build_relationships.py` exact `mitre_id` match (same pattern as **ThreatActor**). No `CONTAINS` inference, no fuzzy matching — see [KNOWLEDGE_GRAPH.md § Technique edges](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-report) |
| Feed values | ThreatFox `ip:port` values are reduced to the IP before the MISP push (MISP `ip-dst` takes no port; `src/collectors/global_feed_collector.py`) |
| Sector detection | zones are detected from `SECTOR_KEYWORDS` in `src/config.py` |
| Airflow task limits | `execution_timeout` on every task; `max_active_runs=1` and `dagrun_timeout` on every DAG |
| Metrics port | **8001** (the REST API holds 8000); the metrics switch is `EDGEGUARD_ENABLE_METRICS`, which matters only for the in-process server of a bare-metal single-process install |
| Logging | collectors use the `logging` module and configure no module-level `logging.basicConfig` |
| Sync state file | the state directory (`EDGEGUARD_STATE_DIR`, default `state/` under the project root) is created with mode 0o700 |
| Dependencies | every package in `requirements.txt` is pinned (`~=`, or a bounded range for `fastapi`) |
| Dependency scan | `pip-audit -r requirements.txt` is a blocking CI check, without an ignore list |
| Monitoring containers | Memory limits 1 GB Prometheus, 512 MB Grafana, 256 MB Alertmanager; healthchecks with `start_period` on every healthchecked service of `docker-compose.yml` and `docker-compose.monitoring.yml`, node-exporter, cAdvisor and Alertmanager included |

---

## Testing Status

| Test Suite | Result | Date | Notes |
|------------|--------|------|-------|
| Manual: Neo4j connectivity | ✅ Pass | 2026-03-05 | — |
| Manual: MISP health check | ✅ Pass | 2026-03-05 | — |
| Manual: Phase 1 (Sources → MISP) | ✅ Pass | 2026-03-05 | — |
| Manual: Phase 2 (MISP → Neo4j) | ✅ Pass | 2026-03-05 | — |
| Manual: Relationship creation | ✅ Pass | 2026-03-05 | — |
| **CI: Ruff lint (50 source files)** | ✅ Pass | 2026-03-17 | GitHub Actions |
| **CI: Mypy type-check** | ✅ Pass | 2026-03-17 | GitHub Actions |
| **CI: Unit tests (1814+ tests)** | ✅ Pass | 2026-04-25 | ≥30% coverage gate (`--cov-fail-under=30` in `.github/workflows/ci.yml` and `make test`) |
| **CI: Docker image build** | ✅ Pass | 2026-04-25 | Non-root user, no secrets baked in |
| **CI: pip-audit security scan** | ✅ Pass | 2026-04-25 | Blocking check, no ignore list |

---

## Documentation Checklist

| Document | Status | Location |
|----------|--------|----------|
| Architecture Overview | ✅ | `docs/ARCHITECTURE.md` |
| ResilMesh Integration Architecture | ✅ | `docs/RESILMESH_INTEGRATION_GUIDE.md` |
| Knowledge Graph Schema | ✅ | `docs/KNOWLEDGE_GRAPH.md` |
| Technical Spec | ✅ | `docs/TECHNICAL_SPEC.md` |
| Data Sources Reference | ✅ | `docs/DATA_SOURCES.md` |
| API Rate Limits | ✅ | `docs/DATA_SOURCES_RATE_LIMITS.md` |
| MISP Source Config | ✅ | `docs/MISP_SOURCES.md` |
| Methodology | ✅ | `docs/METHODOLOGY.md` |
| Airflow DAG Design | ✅ | `docs/AIRFLOW_DAG_DESIGN.md` |
| Airflow DAG operations | ✅ | `docs/AIRFLOW_DAGS.md` |
| Prometheus Setup | ✅ | `docs/PROMETHEUS_SETUP.md` |
| Resilience Config | ✅ | `docs/RESILIENCE_CONFIG.md` |
| Setup Guide | ✅ | `docs/SETUP_GUIDE.md` |
| API Keys Setup | ✅ | `docs/API_KEYS_SETUP.md` |
| Secrets Management | ✅ | `docs/SECRETS_MANAGEMENT.md` |

---

## What's Needed for Production

### Deployment Checklist

| Step | Command / Action | Status |
|------|-----------------|--------|
| Copy `.env.example` → `.env` and fill values | `cp .env.example .env` | Required |
| Set `NEO4J_PASSWORD`, `MISP_URL`, `MISP_API_KEY`, `EDGEGUARD_API_KEY` | Edit `.env` | Required |
| Copy `credentials/config.example.yaml` → `credentials/config.yaml` | `cp credentials/config.example.yaml credentials/config.yaml` | Required |
| Set `ssl_verify: true` in `config.yaml` | Edit file | Required for production |
| Fill optional API keys | `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `THREATFOX_API_KEY`, … in `.env` | Optional |
| Large MISP→Neo4j backfill / OOM on sync | Set **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default `500`; try `250` if still OOM). **`0`** / **`all`** = single pass (OOM risk — not recommended for huge backfills); see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) | If needed |
| Start full stack (Neo4j + Airflow + Postgres + REST + GraphQL) | `docker compose up -d` (root compose). **MISP is NOT in this compose** — run/connect to a separate MISP deployment via `MISP_URL`. | Required |
| Run **launch-day pre-flight** | `EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh --launch-path=dag` — see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) | Before first baseline |
| Run baseline (first run) | Trigger Airflow DAG `edgeguard_baseline` (Airflow UI or `airflow dags trigger edgeguard_baseline`) — see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) | First run |
| Start monitoring stack | `make monitoring` (= `docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d`; both files, one Compose project) | Recommended |

**Docker Compose (full stack):** root `docker-compose.yml` runs Airflow with **PostgreSQL** metadata (`airflow_postgres`). See `docs/AIRFLOW_DAGS.md` if DAG runs appear stuck.

### Future Enhancements

| Item | Priority | Effort |
|------|----------|--------|
| Increase test coverage beyond the 30% gate (unit tests per collector as they stabilise) | Medium | Ongoing |
| Query Engine (LLM) | Low | 1-2 weeks |
| ResilMesh Integration (NATS, TLP, RBAC) | Low | 1-2 weeks |
| Premium feeds (VT, AbuseIPDB) | Low | Ongoing |

---

## Quick Start

```bash
# 1. Configure credentials
cp .env.example .env
cp credentials/config.example.yaml credentials/config.yaml
# Edit both files — fill in MISP_URL, MISP_API_KEY, NEO4J_PASSWORD, EDGEGUARD_API_KEY, API keys

# 2. Start the EdgeGuard stack (Neo4j + Airflow + Postgres + REST + GraphQL).
#    MISP is NOT in this compose — point MISP_URL at a separate MISP deployment.
docker compose up -d

# 3. Run the launch-day pre-flight (catches missing creds, broken APOC,
#    stale baseline_lock, missing baseline hardening invariants — see [11] in
#    docs/BASELINE_LAUNCH_CHECKLIST.md)
EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh --launch-path=dag

# 4. Trigger the baseline DAG (first run). Wraps full_neo4j_sync +
#    build_relationships + run_enrichment_jobs — see AIRFLOW_DAGS.md.
airflow dags trigger edgeguard_baseline

# 5. Start monitoring (both files: Prometheus joins edgeguard_net to scrape metrics:8001)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

Airflow runs as `airflow standalone` inside the compose stack (Airflow 3.x).
Airflow 3 has no `airflow webserver` command (its web UI is served by
`airflow api-server`), and EdgeGuard does not run either command separately.

---

## Conclusion

**The project is production-ready for its core function** (threat intel ingestion → MISP → Neo4j).

All 5 CI checks pass cleanly. The security and code-quality controls above cover security, architecture, data quality, Airflow DAG design, dependency management, and monitoring.

**What's left:**
- Phase 3: Query Engine (LLM integration)
- ResilMesh Integration (NATS, TLP, RBAC)

For the **launch-day pre-flight pass** that the operator must walk through before triggering a 730-day baseline, see [`BASELINE_LAUNCH_CHECKLIST.md`](BASELINE_LAUNCH_CHECKLIST.md). It complements this doc — `PRODUCTION_READINESS.md` is the broader pre-deploy posture; `BASELINE_LAUNCH_CHECKLIST.md` is the focused operator pass right before kickoff. Cross-link in [`DEPLOYMENT_READINESS_CHECKLIST.md`](DEPLOYMENT_READINESS_CHECKLIST.md) for the full deployment workflow.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Restated as a guide to the current state: the dated fix history condensed here, the controls it established listed as current controls, the coverage gate located in CI and `make test`.
- 2026-10-17 — 15 top-level CLI commands (it said 16); the launch-day pre-flight runs with `--launch-path=dag`; the MISP health check is the `misp_health_check` PythonOperator (the sensor was replaced); the documentation table names `docs/AIRFLOW_DAG_DESIGN.md` and `docs/AIRFLOW_DAGS.md`; the collector count names the two flag-guarded collectors.
- 2026-10-15 — Monitoring stack started with both compose files so that Prometheus scrapes `metrics:8001` over `edgeguard_net`; Alertmanager loads without secrets and delivers to Slack through `prometheus/secrets/slack_api_url`; automated code review described without naming the tool.
- 2026-04-28 — MISP stated as outside the EdgeGuard compose stack (the full-stack step had named it), with a `MISP_URL` note in the Quick Start.
- 2026-04-26 — Obsolete `src/neo4j/docker-compose.yml`, `--baseline` flag and `airflow webserver` commands replaced; the "Upgrade to Airflow 3.x" item removed.
- 2026-04-15 — Airflow upgraded from 2.11.x to 3.2.0, resolving the 16 Airflow 2.11 CVEs deferred on 2026-03-17 (CVE-2026-27205 in flask, CVE-2025-32962/58065 in flask-appbuilder, CVE-2025-66236 in airflow had fix versions only in the 3.x line); the generic malware→technique `USES` edge specialised into `IMPLEMENTS_TECHNIQUE`.
- 2026-04-06 — Collector deduplication environment variables documented.
- 2026-03-24 — Local verification passed (`preflight_ci.sh`, `make ci`, `make deploy-check`, `airflow db migrate` and `airflow dags list-import-errors`); Docker image builds and live checks were not run in that environment.
- 2026-03-17 — Security review, Phase 6 (CI/CD and monitoring): the `pip-audit` step made blocking (it had `|| true`), memory limits and healthchecks for the monitoring containers, `EDGEGUARD_ENABLE_PROMETHEUS` / `EDGEGUARD_ENABLE_METRICS` standardised to `EDGEGUARD_ENABLE_METRICS`; the Airflow 2.11.x CVEs and the test coverage of 14% deferred.
- 2026-03-10 — Phase 5 (dependencies and configuration): `stix2` added, `OTXv2` instead of `otx-api`, all packages pinned, unified defaults with sector time ranges in `config.py` and `ssl_verify` true everywhere, zones built from `SECTOR_KEYWORDS`, module-level `logging.basicConfig` removed, `clear_neo4j.py` scoped to EdgeGuard nodes, MISP `healthy` = API + DB, AbuseIPDB flag sent as a string, no `labels` on STIX SCOs, one `SOURCE_MAPPING` entry per source, `SOURCED_FROM.imported_at` set on create only, labels on all graph traversal patterns, `start_period` on Docker healthchecks.
- 2026-03-10 — Phase 4 (Airflow DAGs): sources split into DAGs by update cadence, named callables instead of lambdas, `check_sync_needed` as `ShortCircuitOperator`, Grafana histogram queries with the `le` label, Prometheus server started inside the task instead of at parse time, `execution_timeout` on every task, metrics port moved from 8000 to 8001.
- 2026-03-09 — Phase 3 (Neo4j and graph integrity): UNIQUE constraints for `Indicator` and `Vulnerability`, sector labels applied on every node write, source provenance appended with `COALESCE`, a duplicate `_create_relationships` call removed, malware→technique edges built from explicit MITRE `uses` rows instead of the fuzzy `CAN_USE` attempts.
- 2026-03-09 — Phase 2 (architecture and data pipeline): one reused `PyMISP` object with batch GETs, ThreatFox port suffix stripped before the MISP push, SSL Blacklist config key `sslbl`, URLhaus filter applied before the limit, shared helpers centralised in `collector_utils.py`, MISP event lookup paginated, MITRE relationship cap raised to cover the full ATT&CK graph.
- 2026-03-06 — Phase 1 (security hardening): `sanitize_value()`, centralised `retry_with_backoff()` and `RateLimiter`, specific exception handling, `logging` instead of print statements, state file through `tempfile` with mode 0o700, Airflow Variables for paths, SSL verification on by default.
- 2026-03-05 — Manual tests of Neo4j connectivity, MISP health, sources → MISP, MISP → Neo4j and relationship creation passed.
