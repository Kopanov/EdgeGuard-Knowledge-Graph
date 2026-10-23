# EdgeGuard documentation

Every document of the repository, by topic. The [README](../README.md) at the repository root is the product overview: install, configuration, the 730-day baseline and the interfaces. New operators read [SETUP_GUIDE.md](SETUP_GUIDE.md), then [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), then [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md).

---

## Getting started

| Document | Description |
|---|---|
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | Install with Docker Compose or a Python venv; `.env`; MISP and Neo4j connectivity |
| [API_KEYS_SETUP.md](API_KEYS_SETUP.md) | How to obtain the MISP key and each source's API key |
| [ENVIRONMENTS.md](ENVIRONMENTS.md) | `EDGEGUARD_ENV`, conda and venv, edge devices, service addresses |
| [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) | High-RAM workstations, Neo4j memory profiles, clean slate, image rebuilds |
| [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) | A short first baseline (7 days, small limits) |

## Configuration and commands

| Document | Description |
|---|---|
| [CONFIGURATION.md](CONFIGURATION.md) | Every setting by area, with its default |
| [CLI.md](CLI.md) | The `edgeguard` commands, `make` targets, installer options and scripts |
| [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) | Which limit applies at which stage: baseline, incremental, sync, chunking |
| [MEMORY_TUNING.md](MEMORY_TUNING.md) | Neo4j, Airflow, MISP and host memory; `edgeguard doctor --memory` |
| [MISP_TUNING.md](MISP_TUNING.md) | MISP PHP and MySQL settings for large events; adaptive push scaling |
| [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md) | Credential handling and key rotation |
| [VERSIONING.md](VERSIONING.md) | Calendar versions (`YYYY.M.D`) |

## Operations

| Document | Description |
|---|---|
| [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) | The DAGs, their tasks and run configuration, troubleshooting |
| [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) | Preflight checks, launch, monitoring and acceptance of a 730-day baseline |
| [RUNBOOK.md](RUNBOOK.md) | On-call runbook: alerts, failure modes, kill switches, baseline-day protocol |
| [BACKUP.md](BACKUP.md) | Backup and restore of Neo4j and MISP; the backup gate |
| [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md) | Prometheus, Grafana and Alertmanager; metrics and alert rules |
| [HEARTBEAT.md](HEARTBEAT.md) | Airflow heartbeats, failed-but-finished tasks, memory kills |
| [MISP_SOURCES.md](MISP_SOURCES.md) | How collectors stage data in MISP and how the sync reads it back |
| [MIGRATIONS.md](MIGRATIONS.md) | Neo4j schema changes: pause the scheduled DAGs, wipe, rebaseline, verify |
| [RESILIENCE_CONFIG.md](RESILIENCE_CONFIG.md) | Circuit breakers: where they are used, thresholds, recovery timeouts, metrics |
| [DEPLOYMENT_READINESS_CHECKLIST.md](DEPLOYMENT_READINESS_CHECKLIST.md) | Ordered deployment gates (`make deploy-check`) |
| [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) | Component readiness and the controls in place |
| [CLOUD_SYNC.md](CLOUD_SYNC.md) | Tracking a graph across environments; reproducibility and transfer |

## Data and graph reference

| Document | Description |
|---|---|
| [DATA_SOURCES.md](DATA_SOURCES.md) | Source inventory (collectors, opt-in feeds, placeholders, FIRST EPSS): classification, volume |
| [COLLECTORS.md](COLLECTORS.md) | Per-collector behaviour, sector detection, limits, example output |
| [DATA_SOURCES_RATE_LIMITS.md](DATA_SOURCES_RATE_LIMITS.md) | Source API rate limits and endpoints |
| [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md) | Graph schema: nodes, relationships, provenance, aging, sectors |
| [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) | Cypher specification of nodes, relationships, constraints; API endpoints |
| [TIMESTAMPS.md](TIMESTAMPS.md) | The timestamp model, from the source to the STIX export |
| [DATA_QUALITY.md](DATA_QUALITY.md) | Deterministic merges and exact matching rules |
| [METHODOLOGY.md](METHODOLOGY.md) | Collection, sector classification and linking methods |
| [NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md) | Cypher examples for Neo4j Browser |
| [ADDING_A_NODE_LABEL.md](ADDING_A_NODE_LABEL.md) | Checklist for introducing a new node label |

## Architecture and design

| Document | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Pipeline data flow, sector detection, chunking, module map |
| [ARCHITECTURE_DIAGRAMS.md](ARCHITECTURE_DIAGRAMS.md) | Mermaid diagrams: system, pipeline, schema, DAGs, retries, memory guards |
| [ARCHITECTURE_FLOW.md](ARCHITECTURE_FLOW.md) | Scope of the end-to-end flow diagrams and the documentation pin test |
| [AIRFLOW_DAG_DESIGN.md](AIRFLOW_DAG_DESIGN.md) | Why the DAGs are split as they are; schedules and task design |
| [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md) | MISP trust-boundary defences and their threat model |

## ResilMesh integration

| Document | Description |
|---|---|
| [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) | Integration contract: what EdgeGuard produces and ResilMesh consumes |
| [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) | NATS messaging, the shared Neo4j, alert enrichment |
| [RESILMESH_INTEGRATION_TESTING.md](RESILMESH_INTEGRATION_TESTING.md) | Integration verification and test procedures |
| [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md) | STIX 2.1 export guide: discovery, bundles, smoke script, design decisions |

## Tools and demos

| Document | Description |
|---|---|
| [GRAPH_EXPLORER.md](GRAPH_EXPLORER.md) | The browser graph explorer (`visualization.html`): views, API, extending |
| [DEMO.md](DEMO.md) | Alert enrichment demo and workflow demonstration checks |
| [sources/README.md](sources/README.md) | Notes on running MISP next to EdgeGuard, with a reference Compose file |

`visualization.html` (the Graph Explorer), `demo.html` and `architecture_presentation.html` are pages to open in a browser, served from a local web server.

## Project

| Document | Description |
|---|---|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Pull-request checklist, CI, documentation convention |
| [ROADMAP.md](ROADMAP.md) | Planned work, its dependencies and the issues that track it |
| [CONTRIBUTING.md (docs stub)](CONTRIBUTING.md) | Pointer to the root guide |

## Historical records

These record a past state and are not maintained; each opens with a pointer to the current document.

| Document | Description |
|---|---|
| [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) | Traceability tables of the documentation audits |
| [flow_audits/README.md](flow_audits/README.md) | Flow audits of April 2026 and their findings |

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — Created as the full documentation index, taken from the README's documentation section and completed with the documents it did not list (RUNBOOK, BACKUP, MEMORY_TUNING, MISP_TUNING, BASELINE_LAUNCH_CHECKLIST, TIMESTAMPS, SECURITY_ROADMAP, CLOUD_SYNC, AIRFLOW_DAG_DESIGN, ARCHITECTURE_FLOW, ADDING_A_NODE_LABEL, CONFIGURATION, CLI, ROADMAP); the SETUP_GUIDE, MIGRATIONS, RESILIENCE_CONFIG and DATA_SOURCES descriptions state what those documents cover.
