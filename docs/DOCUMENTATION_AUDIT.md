# Documentation ↔ codebase audit index

**Purpose:** (1) **Traceability** for papers/reviews — each table row ties a doc to code/config. (2) **Navigation** — what to read in order and what overlaps.

---

**Convention — status:**
- **Verified** — Reviewed against code/config on last audit date; known drift fixed in the same pass.
- **Narrative** — Mostly process/architecture prose; few machine-verifiable claims.

**Last full pass:** 2026-03-24 — **MISP event discovery** = **`/events/index`** pagination + client filter + **`Accept: application/json`** on sync session; **`restSearch`** fallback; **`misp_health`** **`healthy`** = API+DB (workers optional; **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS`** for strict); **Airflow** **`AIRFLOW_MEMORY_LIMIT`** (default **4g**), scheduler zombie/heartbeat env vars; **Prometheus** scrape **8001**; **api/graphql** **`Dockerfile`** **`chown /app/src`**. Prior **2026-03-21** pass: per-event MISP→Neo4j, **`EDGEGUARD_REL_BATCH_SIZE`**, **HEARTBEAT.md**, SSL env aliases, etc.

**Targeted pass 2026-04-16 — MISP attribute UUID + edge provenance** (PR #32, branch `fix/misp-attribute-uuid-traceability`): forward fix in `src/run_misp_to_neo4j.py` (`parse_attribute` now stamps `misp_attribute_id = attr.uuid` on all 7 item types) and `src/collectors/misp_collector.py` (aligned to `attr.uuid`). New `Indicator.misp_attribute_id` index. New `r.misp_event_ids[]` on every relationship MERGEd by `create_misp_relationships_batch`. Latent scalar→array bugs fixed in `mark_inactive_nodes`, `calibrate_cooccurrence_confidence`, `build_relationships.py` INDICATES co-occurrence, and `run_pipeline.py` co-occurrence. New STIX exporter custom properties `x_edgeguard_misp_event_ids` / `x_edgeguard_misp_attribute_ids` via `_attach_misp_provenance` (mirrors `_attach_zones`). Backfill migration was deleted in the pre-release cleanup pass (no production graph to migrate; a fresh baseline rerun is the canonical heal path). Docs touched: ARCHITECTURE.md, KNOWLEDGE_GRAPH.md, TECHNICAL_SPEC.md, MIGRATIONS.md, AIRFLOW_DAG_DESIGN.md, STIX21_EXPORTER_PROPOSAL.md, RESILMESH_INTEROPERABILITY.md, RESILMESH_QUICKSTART_STIX.md, this file.

**Targeted pass 2026-04-16 — per-node UUID + edge endpoint UUIDs** (PR #33, branch `feat/node-uuid-and-edge-endpoints`, stacked on PR #32): new `src/node_identity.py` module — deterministic `uuid5(namespace, canonical(label, natural_key))` shared with the STIX exporter so the UUID portion of a STIX SDO id equals the corresponding Neo4j `n.uuid` for the same logical entity (Indicator / Malware / ThreatActor / Technique / Vulnerability / CVE / Sector / Campaign — Tool documented exception). Wired into every node MERGE in `src/neo4j_client.py` (`merge_node_with_source`, `merge_indicators_batch`, `merge_vulnerabilities_batch`, `merge_cve`, `_merge_cvss_node`, `ensure_sources`, Sector auto-creation in MISP rel batch + sector helpers). Edge `r.src_uuid`/`r.trg_uuid` stamped by every Cypher template in `create_misp_relationships_batch` (11 templates), `_upsert_sourced_relationship`, the 12 `build_relationships.py` link queries, and `enrichment_jobs.bridge_vulnerability_cve`. New per-label `<label>_uuid` indexes in `create_indexes`. New `uuid` field on every GraphQL node type + resolver pass-through. Backfill script was deleted in the pre-release cleanup pass (no production graph to migrate; a fresh baseline rerun stamps every uuid at write time). New `docs/CLOUD_SYNC.md` describing the local→cloud delta-sync recipe. Docs touched: ARCHITECTURE.md, KNOWLEDGE_GRAPH.md, TECHNICAL_SPEC.md, MIGRATIONS.md, RESILMESH_INTEROPERABILITY.md, CLOUD_SYNC.md (new), this file. Topology mergers (IP/Host/Device/Subnet/NetworkService/SoftwareVersion/Application/Role) and Campaign uuid stamping landed in subsequent rounds within the same PR series; only the ResilMesh-owned labels (Component/Mission/OrganizationUnit/MissionDependency/Node) remain outside `_NATURAL_KEYS` because they are owned by ResilMesh, not EdgeGuard.

---

## Navigating overlapping topics

| If you need… | Start here | Avoid duplicating in… |
|--------------|------------|------------------------|
| **Integration contract** (who owns which nodes, ISIM, `edgeguard_managed`) | [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) | Long prose in README — link instead |
| **Platform / NATS diagram** (how alerts flow) | [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) | Keep one diagram authoritative |
| **CSV / Malware→Technique `IMPLEMENTS_TECHNIQUE`** (previously generic `USES`, split in 2026-04) | [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) + [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation) | Cross-link only |
| **MISP feeds + discovery + troubleshooting** | [MISP_SOURCES.md](MISP_SOURCES.md) | AIRFLOW_DAGS — keep only task-level troubleshooting |
| **Which limit is which (500 vs baseline caps)** | [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) | README duplicates the short table only |

---

## Root

| Document | Topic | Verified against | Status |
|----------|--------|------------------|--------|
| [README.md](../README.md) | Quick start, **upgrade**, ports, DAG overview, MISP index discovery + env, **`AIRFLOW_MEMORY_LIMIT`**, **HEARTBEAT.md**, **collection/sync limits** | `install.sh`, `docker-compose.yml`, `Dockerfile`, `Dockerfile.airflow`, `dags/edgeguard_pipeline.py`, `src/config.py`, `src/run_misp_to_neo4j.py`, `src/misp_health.py`, `docs/COLLECTION_AND_SYNC_LIMITS.md`, `docs/HEARTBEAT.md` | Verified (2026-04-26) |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | PR checklist, local CI parity, **Python 3.12+**, generated Airflow files | `.github/workflows/ci.yml`, `Makefile`, `.gitignore`, `pyproject.toml`, `tests/test_*cli*` | Verified (2026-04-26) — root copy is canonical; `docs/CONTRIBUTING.md` is a stale duplicate slated for stub-replacement |

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
| [TIMESTAMPS.md](TIMESTAMPS.md) | Source-truthful first/last-seen architecture; honest-NULL contract; PR-S5/PR-M2 | `src/source_truthful_timestamps.py`, `src/collectors/*` | Verified (2026-04-15) |
| [RUNBOOK.md](RUNBOOK.md) | Operator response playbook — **Top 8 failure modes** including PR-N31 § 8 (`_MispFallbackHardError`); kill-switches; baseline launch path | `prometheus/alerts.yml`, `dags/edgeguard_pipeline.py`, `src/run_misp_to_neo4j.py` | Verified (2026-04-26) |
| [BACKUP.md](BACKUP.md) | Self-hosted + Aura backup procedure; PR-F2 backup-timestamp gate; restore worked example | `dags/`, `docs/RUNBOOK.md` | Verified (2026-04-15) |
| [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) | **PR-N32:** 6-section pre-launch operator pass — preflight, smoke, Alertmanager wiring, MISP scale, RAM/disk, unicode-bypass audit | `scripts/preflight_baseline.sh`, `scripts/audit_legacy_unicode_bypass_nodes.py`, `prometheus/alerts.yml`, `src/run_misp_to_neo4j.py` | Verified (2026-04-26) |
| [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) | 7-day mini-baseline procedure (DAG vs CLI vs Variables) | `dags/edgeguard_pipeline.py` (`edgeguard_baseline`), `src/config.py` (`EDGEGUARD_BASELINE_DAYS`, `EDGEGUARD_BASELINE_COLLECTION_LIMIT`) | Verified (2026-04-15) |
| [MEMORY_TUNING.md](MEMORY_TUNING.md) | Per-component memory recommendations; `edgeguard doctor --memory` output | `docker-compose.yml`, `src/edgeguard.py` | Verified (2026-04-06) |
| [MISP_TUNING.md](MISP_TUNING.md) | MISP PHP/MySQL settings for large baselines; adaptive scaling tiers | `src/run_misp_to_neo4j.py`, `src/collectors/misp_writer.py` | Verified (2026-04-15) |
| [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md) | Mermaid diagrams of pipeline + retry/fallback flows | `dags/edgeguard_pipeline.py`, `src/run_misp_to_neo4j.py` | Needs refresh (2026-04-06) — diagrams predate PR-N29 fallback hardening |
| [ARCHITECTURE_FLOW.md](ARCHITECTURE_FLOW.md) | Roadmap for diagram/integrity-test pins (`tests/test_architecture_flow_pins.py` planned) | (planned) | Roadmap — pin-test not yet implemented |
| [CLOUD_SYNC.md](CLOUD_SYNC.md) | Cross-environment sync via `n.uuid` + `r.src_uuid` / `r.trg_uuid`; cloud Neo4j replay recipe | `src/node_identity.py`, `src/neo4j_client.py`, `src/build_relationships.py`, `src/enrichment_jobs.py`, `src/stix_exporter.py` | Verified (2026-04-26) |
| [DEPLOYMENT_READINESS_CHECKLIST.md](DEPLOYMENT_READINESS_CHECKLIST.md) | Broad pre-deploy posture; complement to `BASELINE_LAUNCH_CHECKLIST.md` (focused launch-day pre-flight) | `pyproject.toml`, `docker-compose.yml`, `scripts/preflight_baseline.sh` | Verified (2026-04-26) |
| [GRAPH_EXPLORER.md](GRAPH_EXPLORER.md) | Per-zone Neo4j Browser views; API enum (`attacks` / `actors` / `indicators` / `vulnerabilities`) | `src/query_api.py` | Verified (2026-04-26) |
| [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md) | STIX 2.1 quickstart (`/stix-flow` endpoint, content-deterministic bundle id) | `src/stix_exporter.py`, `src/query_api.py` | Verified (2026-04-26) |
| [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md) | Tiered security roadmap (NFKC + zero-width strip in PR-N29 L1 / PR-N31; trust-boundary defenses) | `src/node_identity.py`, `src/source_trust.py` | Verified (2026-04-26) |
| [STIX21_EXPORTER_PROPOSAL.md](STIX21_EXPORTER_PROPOSAL.md) | STIX 2.1 exporter design + namespace parity + content-deterministic bundles | `src/stix_exporter.py`, `src/node_identity.py` | Verified (2026-04-26) |
| [AIRFLOW_DAG_DESIGN.md](AIRFLOW_DAG_DESIGN.md) | DAG-design rationale (tier1/2/3, baseline carve-out for `retries=0`) | `dags/edgeguard_pipeline.py` | Verified (2026-04-26) |
| [ADDING_A_NODE_LABEL.md](ADDING_A_NODE_LABEL.md) | Recipe for adding a new label (6 touchpoints + Unicode-safe natural keys) | `src/neo4j_client.py`, `src/node_identity.py` | Verified (2026-04-26) |
| [MIGRATIONS.md](MIGRATIONS.md) | Operator runbooks + PR-N22 / N26 / N32 backfill / audit scripts under `scripts/` | `scripts/`, `migrations/` | Verified (2026-04-26) |

---

## How to cite code in a paper

Use paths under the repo root, e.g. `dags/edgeguard_pipeline.py` (DAG schedules), `src/config.py` (`get_effective_limit`, `SECTOR_TIME_RANGES`), `src/collectors/nvd_collector.py` (NVD 120-day published-date windows).

---

_Last updated: 2026-04-26 — PR-N33 docs audit (6-agent fan-out)._

The PR-N26 → PR-N32 train added significant capabilities that earlier
versions of this index did not cover. Added rows for: TIMESTAMPS,
RUNBOOK, BACKUP, BASELINE_LAUNCH_CHECKLIST (PR-N32), BASELINE_SMOKE_TEST,
MEMORY_TUNING, MISP_TUNING, ARCHITECTURE_DIAGRAMS, ARCHITECTURE_FLOW,
CLOUD_SYNC, DEPLOYMENT_READINESS_CHECKLIST, GRAPH_EXPLORER,
RESILMESH_QUICKSTART_STIX, SECURITY_ROADMAP, STIX21_EXPORTER_PROPOSAL,
AIRFLOW_DAG_DESIGN, ADDING_A_NODE_LABEL, MIGRATIONS.

Per-PR narrative for the train (cross-doc summary):

* **PR-N26 (#109, 2026-04-23):** wired `r.misp_event_ids[]` provenance
  onto edges from `build_relationships.py` (4 edge types: INDICATES,
  EXPLOITS, TARGETS, AFFECTS). Backfill via
  `scripts/backfill_edge_misp_event_ids.py` + the 2026_05 runbook.
* **PR-N29 (#110, 2026-04-24):** pre-baseline hardening + multi-agent
  audit findings — `_MispFallbackHardError` sentinel exception in
  `src/run_misp_to_neo4j.py`; paginated MISP fetch fallback
  (`_FALLBACK_PAGE_SIZE=500`, `_FALLBACK_MAX_PAGES=200`); DAG
  `retries=0` on critical chain (4 baseline tasks); baseline_lock
  max-age 24h → 48h; NFKC + 17-char unicode strip in
  `is_placeholder_name`.
* **PR-N30 (#111, 2026-04-24):** post-PR-#109 audit follow-ups —
  `--dry-run` opens session in READ_ACCESS mode; uniform
  `[0..200]`-cap on edge `misp_event_ids[]`.
* **PR-N31 (#112, 2026-04-25):** observability + invariants —
  `MISP_FETCH_FALLBACK_ACTIVE` Counter (labels: `branch`, `outcome`),
  2 Prometheus alerts (`EdgeGuardMispFetchFallbackActive` warning,
  `EdgeGuardMispFetchFallbackHardError` critical), `[11] PR-N29
  invariants` section in `scripts/preflight_baseline.sh`, RUNBOOK § 8
  operator triage tree, alert-count floor bumped 9 → 11.
* **PR-N32 (#113, 2026-04-25):** read-only audit script
  (`scripts/audit_legacy_unicode_bypass_nodes.py`) + the
  `BASELINE_LAUNCH_CHECKLIST.md` operator pre-launch pass.
* **PR-N33 (this audit, 2026-04-26):** 6-agent docs audit; ~30
  drift findings fixed across the doc corpus; this index expanded
  to cover all 46 docs in `docs/` plus the 2 root-level docs.

Prior: 2026-04-18 PR #41 cleanup pass — historical PR #32 "Backfill
migration" reference marked as deleted; PR #33 deferred items closed.
