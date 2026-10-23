# EdgeGuard Production Readiness Assessment

**Before a deployment test:** run the ordered gates in [**Deployment readiness checklist**](DEPLOYMENT_READINESS_CHECKLIST.md) (logic + wiring). `./scripts/deployment_wiring_check.sh` and `make deploy-check` run `scripts/preflight_ci.sh` first, which stops at its DAG parse step on Airflow 3.3 (`DagBag` has no `include_examples` argument there), so their live checks (`EDGEGUARD_DEPLOY_CHECK_LIVE=1`) are not reached ([CLI.md § Operator scripts](CLI.md#operator-scripts)).

**Local verification:** in a Python **3.12** venv with `requirements-dev.txt`, run **`make ci`** (ruff, ruff format, mypy, pytest with coverage), and **`airflow db migrate`** on an ephemeral `AIRFLOW_HOME` followed by **`airflow dags list-import-errors`** (with `MISP_API_KEY` / `MISP_URL` set; it must report no import errors), which checks the DAG parse that `preflight_ci.sh` cannot run on Airflow 3.3. **Docker image builds** and **live** `health_check.py` / API curls need the host that has Docker and a running stack: run them there before production.

---

## Overall Status: GREEN — READY FOR PRODUCTION TEST

The core pipeline is functional, well-documented, and CI-verified. All CI jobs pass (lint, type-check, unit tests, security scan, Docker build). Planned work is listed in [ROADMAP.md](ROADMAP.md).

---

## Component Readiness

### Implemented

| Component | Status | Notes |
|---|---|---|
| Docker Compose stack | Ready | Started by `./install.sh`; MISP is external |
| Data collectors | Ready | 10 sources by default, 3 opt-in, FIRST EPSS |
| MISP integration | Ready | Sanitised writes, retries, adaptive batches |
| MISP → Neo4j sync | Ready | Paged event listing, chunked writes |
| Knowledge graph schema | Ready | Constraints, provenance on every source-built link |
| Post-sync enrichment | Ready | Six jobs after every sync and baseline |
| Airflow DAGs | Ready | Baseline and five scheduled DAGs |
| Baseline safety | Ready | Baseline lock, backup gate, audit trail |
| REST API | Ready | Queries, STIX 2.1 and Wazuh CDB exports |
| GraphQL API | Ready | Port 4001, query depth and alias limits |
| Security hardening | Ready | API keys, loopback ports, injection guards, TLS |
| Health checks | Ready | MISP preflight task, service healthchecks |
| CLI | Ready | 15 top-level commands |
| Monitoring and metrics | Partial | Alert delivery needs a configured channel |
| Documentation | Ready | Guides and references under `docs/` |
| CI/CD pipeline | Ready | Lint, types, tests, image scans, pip-audit |
| Automated code review | Ready | Pull-request review with project rules |

- **Docker Compose stack.** One host runs Neo4j with APOC, Airflow with its PostgreSQL, the `metrics` service and the REST and GraphQL APIs, every port published on 127.0.0.1; `./install.sh` generates the secrets and starts it.
- **Data collectors.** OTX, NVD, CISA KEV, MITRE ATT&CK, VirusTotal (lookups of hashes already in MISP), AbuseIPDB, ThreatFox, URLhaus, Feodo Tracker and SSL Blacklist write to MISP; CISA ICS, ATT&CK for ICS and MalwareBazaar are off by default; FIRST EPSS scores go to the `CVE` nodes directly. Curated packages are imported through MISP.
- **MISP integration.** MISP is the single source of truth for collected data; `OTX_META` / `TF_META` / `NVD_META` comment blocks and `alias:<name>` tags carry metadata and aliases to Neo4j.
- **Knowledge graph schema.** Single-key `MERGE` deduplication across sources; every relationship built from the sources names its sources, their record ids and the MISP events (`sources[]`, `source_refs[]`, `misp_event_ids[]`), and the linking ones carry `match_type` and a confidence. The shared-database contract marks nodes EdgeGuard creates with `edgeguard_managed` and partner nodes it writes to with `edgeguard_enriched`; `CVE` and its CVSS sub-nodes follow the ResilMesh data model, and partner-owned labels get no UNIQUE constraint.
- **Post-sync enrichment.** Vulnerability–CVE bridge, actor alias merge, Malware ATT&CK-id twin merge, indicator aging, campaigns and FIRST EPSS ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)).
- **Airflow DAGs.** `max_active_runs=1` and a `dagrun_timeout` on the baseline and the five scheduled DAGs (the metrics DAGs of `dags/edgeguard_metrics_server.py` have no `dagrun_timeout`), `execution_timeout` on every task, failure and success callbacks; the baseline DAG is created unpaused, the five scheduled DAGs paused. The sync runs every 72 hours.
- **Baseline safety.** The baseline DAG holds the baseline lock for the whole run, so the scheduled DAGs skip; a destructive baseline passes the backup gate, and its Neo4j wipe, like those of `edgeguard clear` and `scripts/clear_neo4j.py`, is recorded in `logs/destructive_ops.jsonl` and the counter `edgeguard_destructive_ops_total` ([BACKUP.md](BACKUP.md)).
- **REST and GraphQL APIs.** `X-API-Key` authentication (required in production), rate limits, a request-body cap and `GET /health` with HTTP 503 while Neo4j is degraded. STIX 2.1 bundles are deterministic and parse under strict `stix2.parse` ([RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md)); the Graph Explorer reads `GET /graph/explore` ([GRAPH_EXPLORER.md](GRAPH_EXPLORER.md)).
- **Monitoring and metrics.** The metrics of every Airflow task process are served by the `metrics` service on 8001 (Prometheus scrapes `metrics:8001` over `edgeguard_net`); the alert rules evaluate in Prometheus and a Grafana dashboard is provisioned. Once `prometheus/secrets/slack_api_url` is provided, Slack receives the critical and the collector alerts; the circuit-breaker alerts go to PagerDuty and every other alert to the default e-mail receiver, both placeholders, so those alerts are delivered only after a mailbox or a rendered key is configured ([PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#alertmanager-notifications)).
- **Automated code review.** Pull requests are reviewed automatically against project rules kept in the repository.
- **Resilience.** Circuit breakers guard the feed fetches and the sync's MISP and Neo4j connection checks; VirusTotal, AbuseIPDB, FIRST EPSS and the collectors' MISP writes have none ([RESILIENCE_CONFIG.md](RESILIENCE_CONFIG.md)). Timestamps are timezone-aware UTC throughout ([TIMESTAMPS.md](TIMESTAMPS.md)).
- **CLI.** `preflight`, `doctor`, `stats`, `dag`, `checkpoint`, the baseline triggers, `clear` and the install commands ([CLI.md](CLI.md)).
- **CI/CD pipeline.** Ruff, Mypy, unit tests with a 30% coverage floor, the Neo4j integration tests, both Docker image builds with Trivy scans, and `pip-audit`.

### Planned work

Planned work is listed in [ROADMAP.md](ROADMAP.md).

---

## Security and code-quality controls

| Area | Control |
|------|---------|
| Input sanitization | `sanitize_value()` in the MISP writer |
| Retry and rate limiting | Shared retry and rate-limit helpers |
| TLS verification | On by default |
| MISP preflight | API and database checked before collection |
| Graph keys | UNIQUE constraint per node label |
| Provenance timestamps | `imported_at` set on create only |
| Malware → technique edges | Explicit ATT&CK `uses` rows only |
| Feed values | ThreatFox `ip:port` reduced to the IP |
| Sector detection | `SECTOR_KEYWORDS` in `src/config.py` |
| Airflow task limits | Timeouts per task and per DAG run |
| Metrics port | 8001 |
| Logging | `logging` module, no `basicConfig` |
| Sync state file | State directory with mode 0o700 |
| Dependencies | Every package pinned |
| Dependency scan | Blocking `pip-audit` in CI |
| Monitoring containers | Memory limits and healthchecks |

- **Input sanitization:** `sanitize_value()` in `src/collectors/misp_writer.py`.
- **Retry and rate limiting:** the `retry_with_backoff()` decorator and the `RateLimiter` class in `src/collectors/collector_utils.py`, and the `rate_limited()` decorator in `src/collectors/misp_writer.py`.
- **TLS verification:** `config.SSL_VERIFY` defaults to on; set `EDGEGUARD_SSL_VERIFY=false` for a development MISP with a self-signed certificate (or `SSL_VERIFY=false`, read only when `EDGEGUARD_SSL_VERIFY` is unset). `SSL_CERT_VERIFY` is not read ([CONFIGURATION.md § TLS and trust](CONFIGURATION.md#tls-and-trust)).
- **MISP preflight:** in `src/misp_health.py`, `healthy` means the API and the database answer (workers optional); `EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true` also requires the workers.
- **Graph keys:** `src/neo4j_client.py` creates a UNIQUE constraint per node label, among them `Indicator` (`indicator_type`, `value`) and `Vulnerability` (`cve_id`).
- **Provenance timestamps:** `SOURCED_FROM.imported_at` is set with `ON CREATE SET` only.
- **Malware → technique edges:** `(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)` is built only from explicit ATT&CK STIX `uses` rows: the collector writes `MITRE_USES_TECHNIQUES:` into MISP, the sync sets `uses_techniques` on the `Malware` node, and `src/build_relationships.py` matches the exact `mitre_id`, as for `ThreatActor`; there is no `CONTAINS` inference and no fuzzy matching ([KNOWLEDGE_GRAPH.md § Technique edges](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-report)).
- **Feed values:** ThreatFox `ip:port` values are reduced to the IP before the MISP push, because MISP `ip-dst` takes no port (`src/collectors/global_feed_collector.py`).
- **Airflow task limits:** `execution_timeout` on every task; `max_active_runs=1` and `dagrun_timeout` on the baseline and the five scheduled DAGs.
- **Metrics port:** 8001 (the REST API holds 8000); `EDGEGUARD_ENABLE_METRICS` matters only for the in-process server of a bare-metal single-process install.
- **Logging:** the collectors use the `logging` module and configure no module-level `logging.basicConfig`.
- **Sync state file:** the state directory (`EDGEGUARD_STATE_DIR`, default `state/` under the project root) is created with mode 0o700.
- **Dependencies:** every package in `requirements.txt` is pinned (`~=`, or a bounded range for `fastapi`); `pip-audit -r requirements.txt` is a blocking CI check without an ignore list.
- **Monitoring containers:** memory limits of 1 GB for Prometheus, 512 MB for Grafana and 256 MB for Alertmanager; healthchecks with `start_period` on every healthchecked service of `docker-compose.yml` and `docker-compose.monitoring.yml`, node-exporter, cAdvisor and Alertmanager included.

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
| **CI: Unit tests (1814+ tests)** | ✅ Pass | 2026-04-25 | 30% coverage gate in CI and `make test` |
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

| Step | When |
|------|------|
| Create `.env` from `.env.example` | Required |
| Set the MISP, Neo4j and API keys | Required |
| Add the optional source keys | Optional |
| Start the stack (MISP is external) | Required |
| Lower the sync chunk size | On a sync OOM |
| Run the launch-day preflight | Before the first baseline |
| Trigger the baseline | First run |
| Start the monitoring stack | Recommended |

The commands are in the [Quick Start](#quick-start) below.

- **Settings.** `./install.sh` creates `.env` and generates the secrets; set `MISP_URL`, `MISP_API_KEY` and, where it does not generate them, `NEO4J_PASSWORD` and `EDGEGUARD_API_KEY`. The optional source keys are `OTX_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `THREATFOX_API_KEY` and `NVD_API_KEY` ([CONFIGURATION.md](CONFIGURATION.md)).
- **Stack.** The root `docker-compose.yml` runs Neo4j, Airflow with its PostgreSQL metadata database (`airflow_postgres`), the metrics service and the REST and GraphQL APIs. MISP is not part of it: point `MISP_URL` at a separate MISP deployment. See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) if DAG runs appear stuck.
- **Sync chunk size.** On a large MISP → Neo4j backfill that runs out of memory, lower `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` (default `500`, try `250`); `0` or `all` is a single pass with a high risk of running out of memory ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)).
- **Preflight and baseline.** The launch-day preflight and its checks: [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md); the baseline DAG and its run configuration: [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md).
- **Monitoring.** `make monitoring` starts Prometheus and Grafana with both Compose files in one Compose project.

---

## Quick Start

```bash
# 1. Configure credentials (./install.sh does this and generates the secrets)
cp .env.example .env
# Edit .env — fill in MISP_URL, MISP_API_KEY, NEO4J_PASSWORD, EDGEGUARD_API_KEY, source API keys

# 2. Start the EdgeGuard stack (Neo4j + Airflow + Postgres + REST + GraphQL).
#    MISP is NOT in this compose — point MISP_URL at a separate MISP deployment.
docker compose up -d

# 3. Run the launch-day pre-flight (catches missing creds, broken APOC,
#    stale baseline_lock, missing baseline hardening invariants — see [11] in
#    docs/BASELINE_LAUNCH_CHECKLIST.md); the script reads the exported settings
#    Checks [10]-[12] use the repository's .venv (./install.sh --python); check [7b]
#    fails until prometheus/alertmanager.yml holds a real PagerDuty key or no PagerDuty receiver.
set -a; . ./.env; set +a
EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh --launch-path=dag

# 4. Trigger the baseline DAG (first run). Wraps full_neo4j_sync +
#    build_relationships + run_enrichment_jobs — see AIRFLOW_DAGS.md.
docker compose exec airflow airflow dags trigger edgeguard_baseline

# 5. Start monitoring (both files: Prometheus joins edgeguard_net to scrape metrics:8001)
docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d
```

Airflow runs as `airflow standalone` inside the compose stack (Airflow 3.x).
Airflow 3 has no `airflow webserver` command (its web UI is served by
`airflow api-server`), and EdgeGuard does not run either command separately.

---

## Conclusion

**The core function (threat intel ingestion → MISP → Neo4j) is ready for a production test.**

All 5 CI checks pass cleanly. The security and code-quality controls above cover security, architecture, data quality, Airflow DAG design, dependency management, and monitoring.

Planned work: [ROADMAP.md](ROADMAP.md).

For the **launch-day pre-flight pass** that the operator must walk through before triggering a 730-day baseline, see [`BASELINE_LAUNCH_CHECKLIST.md`](BASELINE_LAUNCH_CHECKLIST.md). It complements this doc — `PRODUCTION_READINESS.md` is the broader pre-deploy posture; `BASELINE_LAUNCH_CHECKLIST.md` is the focused operator pass right before kickoff. Cross-link in [`DEPLOYMENT_READINESS_CHECKLIST.md`](DEPLOYMENT_READINESS_CHECKLIST.md) for the full deployment workflow.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The baseline-safety control names the Neo4j wipe of `scripts/clear_neo4j.py` among those the destructive-operations trail records.
- 2026-10-23 — The component table takes the README's lists of available and implemented capabilities, de-duplicated, with the details below it: the collectors counted as 10 by default and 3 opt-in, the scheduled DAGs created paused, the circuit breakers limited to the feed fetches and the sync's checks; the deployment steps no longer require `credentials/config.yaml`, which the Docker path does not read, and trigger the baseline in the `airflow` container; the future-phase and enhancement tables and the "what's left" list are replaced by a pointer to ROADMAP.md, the list of planned work, and the conclusion says "ready for a production test" as the status does; `max_active_runs=1` and `dagrun_timeout` are named for the baseline and the five scheduled DAGs (the metrics DAGs have no timeout), automated review is not claimed for every pull request, the alert routing names the alerts that reach Slack, `preflight_ci.sh` and `make deploy-check` are stated to stop at the DAG parse on Airflow 3.3, and the controls and deployment tables keep short cells with the detail in lists below them.
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
