# EdgeGuard Architecture Flow Diagrams

End-to-end system flows rendered as Mermaid diagrams, ordered to
de-risk the **730-day baseline production-test**.

> **Status:** the eight diagrams below are planned; each section states the
> scope, the files covered and the failure modes the diagram illuminates.
> `tests/test_architecture_flow_pins.py` validates four kinds of concrete
> reference in a doc — `EDGEGUARD_*` env vars, container names in `docker`
> commands, `src/*.py` file paths, and the removed command forms
> `python -m edgeguard baseline` / `python -m src.neo4j_client` (removed forms
> may appear only where a line calls them removed or wrong) — against `src/`,
> `dags/`, `scripts/`, `tests/`, `.env.example`, and `docker-compose.yml` /
> `docker-compose.monitoring.yml`. It does not check `edgeguard` subcommands
> or function and class names.
> CI fails on broken doc references. A symbol named in a doc that does not
> exist in code requires either (a) fixing the doc, (b) adding the symbol
> to code, or (c) explicitly allowlisting it in the test with a clear reason.

---

## Why this document exists

EdgeGuard's data path is 12 collectors (10 always on, MalwareBazaar and
CISA ICS flag-guarded) → MISP → Neo4j → STIX/GraphQL/REST, with
deterministic merge, zone detection, cross-event dedup, creator-org trust
checks, and resumable checkpoints along the way.
Any single file shows a fragment. This document shows the whole.

**The motivating use case:** the 2-year historical baseline
(`edgeguard baseline --days 730`) is EdgeGuard's most stressful
production scenario. It takes hours-to-days, gets interrupted mid-run,
exercises every checkpoint path, hits every rate limit, and
concurrently runs against scheduled incremental DAGs that keep firing.
Failures of error-handler recovery paths, checkpoint key mismatches,
cross-event dedup cache-key drift and STIX emitter–consumer desync all
surface disproportionately on long runs. A bird's-eye view makes those
cross-component contracts visible.

**Use case 2 — automated review.** An automated reviewer of a change
starts with no model of the system. A diagram in Markdown is the
densest way to give it the model it needs to judge the change.

**Use case 3 — onboarding & external integration.** ResilMesh
integrators, new contributors, and operators asking "where does my
IOC live after it's ingested?" get a two-minute answer instead of a
two-hour read.

### What this document does NOT do

- **It does not replace code.** When in doubt, the code is the source of truth.
- **It does not auto-detect bugs.** It helps humans (and LLMs) notice them by making cross-component contracts visible.
- **It is not UML.** UML over-fits on OO structure; EdgeGuard is data-flow-heavy, so Mermaid `flowchart` / `sequenceDiagram` / `stateDiagram-v2` are the right tools.

---

## How to keep these diagrams honest

Diagrams rot. Every diagram in this file:

1. **References real symbols.** Function names, class names, env vars, and file paths appear as plain text labels. `src/*.py` file paths, env vars and container names in `docker` commands are checked by `tests/test_architecture_flow_pins.py` — if a referenced one vanishes, the test fails and forces an update here; the test also fails on the removed `python -m` command forms, and function names, class names and `edgeguard` subcommands are not pinned.
2. **Lives close to the code.** Modules whose behavior a diagram describes get a link to the corresponding section from their top-of-file docstring; these cross-references are part of each tier's work (see [Work plan](#work-plan)).
3. **States its scope.** Each diagram section declares which files it covers and which failure modes it illuminates.
4. **Changes with the flow.** A change to the flow updates its diagram in the same pull request; a change that removes a referenced `src/*.py` file, env var or a container name used in a `docker` command fails the pin-test.

---

## Table of contents (ordered by 730-day-baseline production-test risk)

| # | Diagram | Status | Tier | De-risks |
|---|---------|--------|------|----------|
| 1 | [Baseline sequence — full end-to-end](#1-baseline-sequence) | 🚧 Planned | **1** | Whole-run orchestration; where each safeguard lives |
| 2 | [Checkpoint state machine](#2-checkpoint-state-machine) | 🚧 Planned | **1** | Resume correctness (writer/reader key agreement, counter reset on completion) |
| 3 | [Collector → MISP → Neo4j data flow](#3-collector--misp--neo4j-data-flow) | 🚧 Planned | **1** | Dedup at scale; zone detection; rate-limit + retry paths; MISP trust check placement |
| 4 | [Incremental sync sequence](#4-incremental-sync-sequence) | 📋 Planned | 2 | Concurrent-with-baseline scenarios; baseline-lock race |
| 5 | [Deployment topology](#5-deployment-topology) | 📋 Planned | 2 | Operator orientation; which process owns which metric |
| 6 | [MISP ↔ Neo4j traceability](#6-misp--neo4j-traceability) | 📋 Planned | 3 | Back-pointer validation; audit trail of any ingested fact |
| 7 | [STIX export + ResilMesh integration surface](#7-stix-export--resilmesh-integration-surface) | 📋 Planned | 3 | External contract; xAI / LLM consumer plug-in |
| 8 | [Zone detection flow](#8-zone-detection-flow) | 📋 Planned | 3 | Sector classification correctness |

### Tier rationale

**Tier 1 — production-test-critical.** Written first, ahead of the next 2-year baseline. These three diagrams collectively illuminate the failure modes of long-running EdgeGuard baselines: memory, checkpoint resume, race conditions, dedup correctness, rate limits, transaction boundaries.

**Tier 2 — production-ready-useful.** Follows Tier 1. Incremental sync is distinct from the baseline but runs concurrently with it (the baseline-lock race); deployment topology answers operator questions.

**Tier 3 — integration / completeness.** Lower urgency for the internal production-test itself but critical for ResilMesh integration and for completeness. Follows once Tier 2 is stable.

---

## Work plan

Each tier lands complete, with CI-validated symbol pins for the diagrams it contains.

### Tier 1 (production-test-critical)

Target: complete before the next 730-day baseline.

- [ ] §1 Baseline sequence diagram (Mermaid `sequenceDiagram`)
- [ ] §2 Checkpoint state machine (Mermaid `stateDiagram-v2`)
- [ ] §3 Collector → MISP → Neo4j flow (Mermaid `flowchart`)
- [x] `tests/test_architecture_flow_pins.py` — env vars, container names, `src/*.py` paths and the removed `python -m` command forms (function symbols and `edgeguard` subcommands not pinned)
- [ ] Docstring cross-references in `src/run_misp_to_neo4j.py`, `src/collectors/misp_writer.py`, `src/baseline_checkpoint.py`, `src/collectors/nvd_collector.py`

### Tier 2 (production-ready-useful)

- [ ] §4 Incremental sync sequence (Mermaid `sequenceDiagram`)
- [ ] §5 Deployment topology (Mermaid `flowchart`)
- [ ] Extend `test_architecture_flow_pins.py` to cover §4-§5
- [ ] Docstring cross-references in `dags/edgeguard_pipeline.py`, `docker-compose.yml`

### Tier 3 (integration / completeness)

- [ ] §6 MISP ↔ Neo4j traceability (Mermaid `flowchart`)
- [ ] §7 STIX export + ResilMesh surface (Mermaid `sequenceDiagram` + component callout)
- [ ] §8 Zone detection flow (Mermaid `flowchart`)
- [ ] Extend `test_architecture_flow_pins.py` to cover §6-§8
- [ ] Docstring cross-references in `src/stix_exporter.py`, `src/graphql_api.py`, `src/config.py` (zone detection)

---

## 1. Baseline sequence

> 🚧 **To be written.** Tier 1. Highest-leverage diagram.

**Scope:** The full `edgeguard baseline --days N` run, from CLI entry point through collector sequencing, MISP writes, Neo4j merge, relationship building, and enrichment. Covers both `baseline` (additive) and `fresh-baseline` (destructive with backup gate).

**Files covered:**
- `src/edgeguard.py` (CLI entry points `cmd_baseline`, `cmd_fresh_baseline`)
- `src/run_pipeline.py` (orchestration)
- `src/collectors/*_collector.py` (12 collectors — tier-1/2/3 sequencing)
- `src/collectors/misp_writer.py` (write-side)
- `src/run_misp_to_neo4j.py` (sync to Neo4j)
- `src/build_relationships.py` (post-sync edges)
- `src/enrichment_jobs.py` (bridges, campaigns, decay)
- `src/baseline_checkpoint.py` (progress tracking)
- `src/baseline_lock.py` (sentinel file)

**Failure modes illuminated:**
- OOM on large MISP events
- Partial-sync with collector exception mid-tier
- `fresh_baseline` destructive-op gating (backup timestamp, dev-config refusal)
- Neo4j circuit-breaker tripping mid-sync
- Rate-limit exhaustion on NVD / OTX
- Where the MISP tag-impersonation trust check fires

**Cross-reference targets:** tier sequencing; parent-DAG liveness; cross-event dedup; error-recovery paths; the defense-state gauge read.

---

## 2. Checkpoint state machine

> 🚧 **To be written.** Tier 1. Resume is where writer/reader key mismatches and stale counters arise; diagramming it makes such bugs visible.

**Scope:** State transitions for `baseline_checkpoint.py` — how `entry["current_page"]`, `entry["pages"]`, `entry["completed"]`, and source-specific fields (`nvd_window_idx`, `nvd_start_index`) evolve across: fresh start → in-progress → interrupted → resumed → completed → fresh-re-run.

**Files covered:**
- `src/baseline_checkpoint.py`
- `src/collectors/nvd_collector.py` (primary consumer with resume semantics)
- `src/collectors/misp_writer.py` (checkpoint writes on push)

**Failure modes illuminated:**
- Key mismatch between writer and reader (`page` vs `current_page`)
- Stale counter carrying across completed runs (`total_batches_done` not reset when `completed=True`)
- Resume-index off-by-one on window boundaries
- Concurrent-writer corruption (the advisory lock at `_checkpoint_lock_path()`)
- Path-traversal guard for `EDGEGUARD_CHECKPOINT_DIR`

**Cross-reference targets:** the checkpoint resume tests, e.g. `test_seed_recovers_persisted_page_end_to_end`.

---

## 3. Collector → MISP → Neo4j data flow

> 🚧 **To be written.** Tier 1. Covers the highest-traffic path; answers ~40% of "why does my data look like this?" questions.

**Scope:** A single IOC's journey from collector output (dict with `indicator_type` + `value` + zone hints) through `MISPWriter.push_items` (dedup, tag resolution, event creation) through `MISPToNeo4jSync.sync_to_neo4j` (Python chunks: `Neo4jClient.merge_indicators_batch` for indicators, `merge_cve` for CVEs, the per-label merges for ATT&CK entities, malware and actors, `_sync_single_item` for any other item) to the final `:Indicator` / `:CVE` / `:Malware` node with `SOURCED_FROM` edges.

**Files covered:**
- `src/collectors/collector_utils.py` (shared validation)
- `src/collectors/misp_writer.py` (write-side: event dedup, attribute dedup, cross-event dedup prefetch)
- `src/run_misp_to_neo4j.py` (read-side: `_attribute_to_stix21`, `sync_to_neo4j`, per-type batches)
- `src/neo4j_client.py` (Cypher MERGE with natural-key UNIQUE constraints)
- `src/source_trust.py` (creator-org allowlist check, fires here)
- `src/config.py` (`detect_zones_from_item`, `detect_zones_from_text`)
- `src/source_registry.py` (source ↔ tag resolution)

**Failure modes illuminated:**
- Cross-event dedup cache-key desync
- Source-tag alias resolution
- Dedup prefetch pagination bounds
- Zone detection precedence (text vs explicit tag vs event `x_edgeguard_zones`)
- SOURCED_FROM edge creation semantics (source-truthful provenance)
- MISP tag-impersonation defense firing point (and its gauge)
- Rate-limit retry placement (collector vs MISP writer vs both)
- Natural-key UNIQUE constraint per label

**Cross-reference targets:** cross-event dedup; source-truthful pipeline; trust check; observability; natural-key constraints.

---

## 4. Incremental sync sequence

> 📋 **To be written.** Tier 2.

**Scope:** The four incremental collector DAGs (`edgeguard_pipeline` OTX every 30 min, `edgeguard_medium_freq` CISA + VirusTotal every 4 h, `edgeguard_low_freq` NVD every 8 h, `edgeguard_daily` 02:00 UTC) and `edgeguard_neo4j_sync` (every 72 h; its incremental window starts 1 h before the last sync's start, `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`) — how each one picks collectors, skips already-known events, and interacts (or should not interact) with an in-progress baseline.

**Files covered:**
- `dags/edgeguard_pipeline.py`
- `src/parent_dag_liveness.py` (orphan-process safeguard)
- `src/baseline_lock.py` (sentinel, read-path)
- `src/collectors/misp_writer.py` (`push_items` with `cross_event_cache`)

**Failure modes illuminated:**
- Baseline-lock race
- Parent-DAG orphan processes
- A mistyped `fresh_baseline` DAG-conf key
- Stale event-index pagination on MISP
- Timezone drift on the sync window overlap

---

## 5. Deployment topology

> 📋 **To be written.** Tier 2.

**Scope:** Local Docker Compose vs planned cloud (Aura Neo4j + cloud MISP + K8s) vs hybrid. Which process owns which port, which volume, which metric.

**Files covered:**
- `docker-compose.yml` + `docker-compose.override.yml`
- `Dockerfile`
- `prometheus.yml`, `grafana/*`
- `src/metrics_server.py` (port 8001)
- `src/query_api.py` (port 8000)
- `src/graphql_api.py` (port 4001)

**Failure modes illuminated:**
- Prometheus scrape path: `metrics:8001` over `edgeguard_net`, because `host.docker.internal` reaches the loopback-only publish on Docker Desktop but not on Linux
- MISP API TLS vs plain-HTTP config drift
- Airflow `postgres` metadata vs SQLite default
- Which restart policy maps to which SLO

---

## 6. MISP ↔ Neo4j traceability

> 📋 **To be written.** Tier 3.

**Scope:** The back-pointers — every Neo4j Indicator carries its originating MISP attribute UUID, every MISP-derived edge accumulates `r.misp_event_ids[]`, and STIX bundles carry `x_edgeguard_misp_*_ids`. This diagram shows the round-trip: from an edge in Neo4j, how do you retrieve the source MISP event + attribute?

**Files covered:**
- `src/run_misp_to_neo4j.py` (attribute-id + event-id propagation)
- `src/neo4j_client.py` (`misp_event_ids` accumulation on `SOURCED_FROM`)
- `src/stix_exporter.py` (`x_edgeguard_misp_*_ids` in STIX SDOs)
- `src/node_identity.py` (deterministic node `uuid` and edge `src_uuid` / `trg_uuid`)

---

## 7. STIX export + ResilMesh integration surface

> 📋 **To be written.** Tier 3.

**Scope:** How a query through GraphQL or REST turns into a STIX 2.1 bundle, what extensions EdgeGuard emits (`x_edgeguard_*`), and where ResilMesh consumers plug in.

**Files covered:**
- `src/stix_exporter.py` (`_deterministic_id` namespace, SDO construction)
- `src/graphql_api.py` (Strawberry schema, port 4001)
- `src/query_api.py` (FastAPI REST, port 8000)
- `docs/RESILMESH_INTEROPERABILITY.md` (the ResilMesh-side contract)

---

## 8. Zone detection flow

> 📋 **To be written.** Tier 3.

**Scope:** `detect_zones_from_text` weighted keyword scoring; zone precedence (explicit tag > item hint > text score); multi-zone attribution; the "if global + specific present, drop global" rule.

**Files covered:**
- `src/config.py` (`SECTOR_KEYWORDS`, `detect_zones_from_text`, `detect_zones_from_item`)
- `src/collectors/*` (per-collector zone-hint injection)
- `src/run_misp_to_neo4j.py` (zone extraction from attribute tags in `_attribute_to_stix21`)

---

## Appendix A — Diagram conventions

- **Colors:** use Mermaid's built-in classDef. EdgeGuard convention:
  - Process boxes → default
  - External systems (MISP, Neo4j, NATS) → `classDef external fill:#eef,stroke:#446`
  - Error / retry paths → `classDef error fill:#fee,stroke:#844`
  - Security-critical paths → `classDef sec fill:#efe,stroke:#484`
- **Symbol references:** fence function names in backticks, file paths in backticks with forward slashes.
- **Cross-links:** `[label](#section-anchor)` within this file; `[label](../file.md#anchor)` across files.

## Appendix B — Self-validation

`tests/test_architecture_flow_pins.py` checks env vars, container names, `src/*.py` file paths and the removed `python -m` command forms; it does not check `edgeguard` subcommands. Symbol pinning is planned:

1. Parse this file for backticked tokens matching symbol patterns (`_[a-z_]+`, `[A-Z][a-zA-Z]+`, `[A-Z_]{3,}`).
2. For each token, grep `src/` for a definition (`def X`, `class X`, `X =`, `X:` env var).
3. Fail with a clear message naming the unresolved symbol if the grep returns nothing.
4. Skip Mermaid keywords (`participant`, `activate`, etc.), Prometheus metric names (handled by separate test), and words in prose text (detected by being outside backticks or outside diagram code fences).

This keeps the cost of lying in a diagram at exactly "CI fails," which is the only cost that changes behavior.

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — The pin-test is described as it runs: env vars, container names in `docker` commands, `src/*.py` paths and the removed `python -m` command forms; `edgeguard` subcommands are not checked.
- 2026-10-17 — Rewritten as a guide to the current state: change notes and the delivery history of the plan moved to this history.
- 2026-10-17 — Corrected against the code: 12 collectors (2 flag-guarded); § 3 names `sync_to_neo4j` and the merges it calls (`_sync_bulk` does not exist); § 4 the real DAG schedules and the sync's 1 h window overlap; the pin-test does not check function names.
- 2026-10-15 — Deployment topology: the Prometheus scrape path is `metrics:8001` over `edgeguard_net` (`host.docker.internal` did not reach the loopback-only publish on Linux).
- 2026-04-28 — `tests/test_architecture_flow_pins.py` added (env vars, the removed `python -m` command forms, container names, `src/*.py` file paths); its first run found four doc references with no counterpart in code, among them a README baseline command block that was out of date.
- 2026-04-20 — Document created: the diagram plan ordered by baseline risk, a skeleton section per diagram, and the README roadmap entry.
