# EdgeGuard Production Readiness Assessment

**Date:** 2026-03-24  
**Last security review:** 2026-03-17  

**Before a deployment test:** run the ordered gates in [**Deployment readiness checklist**](DEPLOYMENT_READINESS_CHECKLIST.md) (logic + wiring). Automate Layer 1 with `./scripts/deployment_wiring_check.sh` or `make deploy-check`; set `EDGEGUARD_DEPLOY_CHECK_LIVE=1` for live health checks.

**Last local verification (2026-03-24):** Python **3.12** venv with `requirements-dev.txt`; `./scripts/preflight_ci.sh` and **`make ci`** (ruff, ruff format, mypy, pytest with coverage) passed; **`make deploy-check`** (static Layer 1) passed; **`airflow db migrate`** on an ephemeral `AIRFLOW_HOME` then **`airflow dags list-import-errors`** reported no import errors (with `MISP_API_KEY` / `MISP_URL` set). **Docker image builds** and **live** `health_check.py` / API curls were not run in that environment—run on the host that has Docker and a running stack before production.

---

## Overall Status: GREEN — READY FOR PRODUCTION TEST

The core pipeline is functional, well-documented, and CI-verified. All CI jobs pass (lint, type-check, unit tests, security scan, Docker build). Bugbot is active on every PR. The main remaining work is Phase 3 (Query Engine) and ResilMesh integration.

---

## Component Readiness

### ✅ COMPLETE - Production Ready

| Component | Status | Notes |
|-----------|--------|-------|
| **Knowledge Graph Schema** | ✅ Ready | Full node/relationship design, UNIQUE constraints |
| **MISP Integration** | ✅ Ready | Writer with sanitization, retry, rate limiting |
| **Airflow DAGs** | ✅ Ready | **6** DAGs; `max_active_runs=1` + `dagrun_timeout` on all; `on_failure_callback`/`on_success_callback`; baseline `is_paused_upon_creation=False`; `ShortCircuitOperator` on Neo4j sync |
| **Data Collectors** | ✅ Ready | 11 active collectors → MISP → Neo4j |
| **Neo4j Client** | ✅ Ready | Constraints, indexes, batch ops, sector labels applied |
| **Health Checks** | ✅ Ready | MISP health sensor + Docker service healthchecks |
| **Documentation** | ✅ Ready | 20+ docs updated to match current code |
| **Production CLI** | ✅ Ready | 16 commands: `preflight`, `stats --full`, `dag status/kill`, `checkpoint status/clear`, `doctor`, `heal`, `validate`, `monitor` |
| **Security Hardening** | ✅ Ready | Input sanitization, injection guards, SSL, rate limiting |
| **Monitoring/Metrics** | ✅ Ready | Prometheus on **8001** (loopback); Alertmanager enabled; alerts: `EdgeGuardDAGRunStuck`, `EdgeGuardDAGLastSuccessStale` + 12 others; Grafana dashboard |
| **CI/CD Pipeline** | ✅ Ready | GitHub Actions: lint, type-check, unit tests, Docker build, security scan |
| **Automated Code Review** | ✅ Ready | Bugbot active on every PR with comprehensive rules |

### ⏳ NOT STARTED - Future Phases

| Component | Status | Notes |
|-----------|--------|-------|
| **Query Engine** | ⏳ Not Started | Phase 3 - LLM integration |
| **ResilMesh Integration** | ⏳ Partial | GraphQL (port 4001), schema alignment — see `docs/RESILMESH_*.md`; full NATS/TLP/RBAC varies by deployment |

---

## Security & Code Quality — Full Fix History

### ✅ Phase 1 — Security Hardening (2026-03-06)

| Issue | Fix Applied |
|-------|-------------|
| Input injection | `sanitize_value()` in `collector_utils.py` |
| No retry logic | `retry_with_backoff()` decorator (centralised in `collector_utils.py`) |
| No rate limiting | `RateLimiter` class + `rate_limited()` decorator (centralised) |
| Bare except clauses | Specific exception handling throughout |
| Print statements | Proper `logging` module |
| State file in /tmp | `tempfile` with `mode 0o700` |
| Hardcoded paths | Airflow Variables support |
| SSL verification off | In code, `config.SSL_VERIFY` defaults to **on**; set **`EDGEGUARD_SSL_VERIFY=false`** for dev self-signed MISP (or **`SSL_VERIFY=false`** only if `EDGEGUARD_SSL_VERIFY` is unset). **`SSL_CERT_VERIFY`** is not read. |

### ✅ Phase 2 — Architecture & Data Pipeline (2026-03-09)

| Issue | Fix Applied |
|-------|-------------|
| N+1 HTTP requests in MISP collector | Single reused `PyMISP` object; batch GETs |
| ThreatFox stores IP:port as `ip-dst` | Port suffix stripped before MISP push |
| SSLBlacklist used wrong config key | Fixed key from `feodo` → `sslbl` |
| URLhaus limit applied before comment filter | Filter first, then apply limit |
| DRY violations across 5+ collectors | Centralised into `collector_utils.py` |
| MISP event lookup capped at 100 | Increased; pagination added |
| MITRE relationships capped at 1,500 | Cap raised to cover full ATT&CK graph |

### ✅ Phase 3 — Neo4j / Graph Integrity (2026-03-09)

| Issue | Fix Applied |
|-------|-------------|
| Missing UNIQUE constraints for `Indicator` and `Vulnerability` | Added in `neo4j_client.py` |
| Sector labels never applied | `apply_sector_label()` called on every node write |
| Source provenance overwritten on update | `COALESCE` used to append; not replace |
| Duplicate `_create_relationships` calls | Removed double-call in `run()` |
| Malware→Technique edges missing / bogus `CAN_USE` attempts | **Replaced** fuzzy / broken `CAN_USE` with **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** built only from explicit MITRE STIX **`uses`** rows: `uses_techniques` on **`Malware`** (collector → `MITRE_USES_TECHNIQUES:` in MISP → `run_misp_to_neo4j` → `merge_malware`) + `build_relationships.py` exact `mitre_id` match (same pattern as **ThreatActor**). No `CONTAINS` inference. *(Originally shipped as a generic `USES` edge; specialized into `IMPLEMENTS_TECHNIQUE` in 2026-04 — see `docs/KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation`.)* |

### ✅ Phase 4 — Airflow DAGs (2026-03-10)

| Issue | Fix Applied |
|-------|-------------|
| All sources ran every 30 min (rate-limit violation) | Split into **6** DAGs in `edgeguard_pipeline.py` by update cadence (+ baseline manual DAG) |
| Lambda `python_callable` (PicklingError) | Replaced with named function references |
| `check_sync_needed` never gated execution | Changed to `ShortCircuitOperator` |
| Grafana histogram queries missing `le` label | Fixed PromQL; `{le="..."}` label added |
| Prometheus server started at DAG parse time | Moved inside task; never at module level |
| Tasks with no execution timeout | `execution_timeout` added to every task |
| Metrics server on port 8000 (conflicts with FastAPI) | Default changed to 8001 |

### ✅ Phase 5 — Dependencies & Configuration (2026-03-10)

| Issue | Fix Applied |
|-------|-------------|
| `stix2` missing from `requirements.txt` | Added with version pin |
| Wrong PyPI package `otx-api` | Corrected to `OTXv2` |
| No version pinning | All packages pinned with `~=X.Y` or `>=X.Y.Z` |
| Conflicting defaults between config files | Unified; canonical sector time ranges set in `config.py` |
| `detect_zones_from_item` hardcoded sectors | Dynamically built from `SECTOR_KEYWORDS` |
| `ssl_verify` defaults inconsistent across 3 files | Unified to `True` everywhere |
| `logging.basicConfig` at module level in every collector | Removed; application-level config used |
| `clear_neo4j.py` deletes ALL nodes (not scoped) | Scoped to EdgeGuard nodes only |
| `misp_health.py` | **`healthy`** = API+DB (workers optional); stricter preflight via **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS`** |
| `AbuseIPDBCollector` sent Python `True` not `"true"` | Fixed to string |
| STIX 2.1 `labels` on SCOs (violates spec) | Removed `labels` from SCO objects |
| `SOURCE_MAPPING` assigned 5 sources to `abuseipdb` | Each source has its own entry |
| `SOURCED_FROM.imported_at` overwritten on every import | Changed to `ON CREATE SET` |
| `MATCH (n)` full-graph scan | Added label on all graph traversal patterns |
| No `start_period` on Docker healthchecks | Added to all services |

### ✅ Phase 6 — CI/CD & Monitoring (2026-03-17) — Bugbot findings

| Issue | Fix Applied |
|-------|-------------|
| `pip-audit` step had `\|\| true` (never failed CI) | Removed; now a blocking check |
| ~~16 Airflow 2.11.x CVEs~~ | **Resolved 2026-04-15:** upgraded to Airflow 3.2.0. CVE-2026-27205 (flask), CVE-2025-32962/58065 (flask-appbuilder) and CVE-2025-66236 (airflow) all had fix versions only in the 3.x line. See [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md#airflow-2-to-3-upgrade) for migration notes. |
| Missing memory limits on monitoring containers | 1 GB Prometheus, 512 MB Grafana, 256 MB Alertmanager |
| No healthchecks on node-exporter, cAdvisor, Alertmanager | Added to `docker-compose.monitoring.yml` |
| `EDGEGUARD_ENABLE_PROMETHEUS` / `EDGEGUARD_ENABLE_METRICS` naming conflict | Standardised to `EDGEGUARD_ENABLE_METRICS` everywhere |

### ⚠️ Remaining / Deferred

| Issue | Reason | Recommendation |
|-------|--------|----------------|
| ~~Airflow 2.11.x CVEs (16 known)~~ | ~~Fix requires Airflow 3.x (breaking upgrade)~~ | **Done 2026-04-15:** upgraded to 3.2.0, see AIRFLOW_DAGS.md. |
| Test coverage at 14% | Legacy codebase; integration tests complex to mock | Add unit tests per collector as they stabilise |

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
| **CI: Unit tests (16 tests)** | ✅ Pass | 2026-03-17 | 14% coverage, threshold 10% |
| **CI: Docker image build** | ✅ Pass | 2026-03-17 | Non-root user, no secrets baked in |
| **CI: pip-audit security scan** | ✅ Pass | 2026-03-17 | 16 Airflow CVEs explicitly documented and ignored |

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
| Airflow DAG Design | ✅ | `docs/AIRFLOW_DAGS.md` |
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
| Start Neo4j | `docker-compose -f src/neo4j/docker-compose.yml up -d` | Required |
| Run baseline | `python3 src/edgeguard.py --baseline` | First run |
| Start monitoring stack | `docker-compose -f docker-compose.monitoring.yml up -d` | Recommended |
| Start Airflow | `airflow webserver & airflow scheduler` | For automated collection |

**Docker Compose (full stack):** root `docker-compose.yml` runs Airflow with **PostgreSQL** metadata (`airflow_postgres`). See `docs/AIRFLOW_DAGS.md` if DAG runs appear stuck.

### Future Enhancements

| Item | Priority | Effort |
|------|----------|--------|
| Increase test coverage beyond 14% | Medium | Ongoing |
| Upgrade to Airflow 3.x (fixes all 2.11.x CVEs) | Medium | 1-2 weeks |
| Query Engine (LLM) | Low | 1-2 weeks |
| ResilMesh Integration | Low | 1-2 weeks |
| Premium feeds (VT, AbuseIPDB) | Low | Ongoing |

---

## Quick Start

```bash
# 1. Configure credentials
cp .env.example .env
cp credentials/config.example.yaml credentials/config.yaml
# Edit both files — fill in MISP_URL, MISP_API_KEY, NEO4J_PASSWORD, API keys

# 2. Start Neo4j
docker-compose -f src/neo4j/docker-compose.yml up -d

# 3. Build the baseline (first run)
python3 src/edgeguard.py --baseline

# 4. Start monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# 5. (Optional) Start Airflow for automated recurring collection
airflow webserver --port 8082 &
airflow scheduler &
```

---

## Conclusion

**The project is production-ready for its core function** (threat intel ingestion → MISP → Neo4j).

All 5 CI checks pass cleanly. The codebase has been through 6 rounds of systematic fixes covering security, architecture, data quality, Airflow DAG design, dependency management, and monitoring. Bugbot is active and watching every PR.

**What's left:**
- Phase 3: Query Engine (LLM integration)
- ResilMesh Integration (NATS, TLP, RBAC)
- Upgrade to Airflow 3.x to resolve the 16 known 2.11.x CVEs

---

*Last updated: 2026-04-06 — aligned with collector dedup env vars, Python 3.12 / `Dockerfile.airflow` docs; prior: 2026-03-17 CI/checklist.*
