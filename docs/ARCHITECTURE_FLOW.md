# EdgeGuard Architecture Flow Diagrams

End-to-end system flows rendered as Mermaid diagrams, ordered to
de-risk the **730-day baseline production-test**. Every symbol name,
env var, and file path referenced in a diagram is validated against
`src/` by `tests/test_architecture_flow_pins.py` — diagrams cannot
silently drift from the code.

---

## Why this document exists

EdgeGuard's data path is 11 collectors → MISP → Neo4j → STIX/GraphQL/
REST, with deterministic merge, zone detection, cross-event dedup,
creator-org trust checks, and resumable checkpoints along the way.
Any single file shows a fragment. This document shows the whole.

**The motivating use case:** the 2-year historical baseline
(`edgeguard baseline --days 730`) is EdgeGuard's most stressful
production scenario. It takes hours-to-days, gets interrupted mid-run,
exercises every checkpoint path, hits every rate limit, and
concurrently runs against scheduled incremental DAGs that keep firing.
The bugs PR-F through PR-I fixed — NoneType slicing in error handlers
that killed recovery paths; checkpoint key mismatches; cross-event
dedup cache-key drift; STIX emitter-consumer desync — all surface
disproportionately on long runs. A bird's-eye view makes those
cross-component contracts visible.

**Use case 2 — audit agents.** When spawning a Claude agent to review
a change, the agent starts with no model of the system. A diagram in
markdown is the densest way to give the agent the model it needs to
make good judgment calls.

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

1. **References real symbols.** Function names, class names, env vars, and file paths appear as plain text labels. `tests/test_architecture_flow_pins.py` greps these against `src/` — if a referenced symbol vanishes, the test fails and forces an update here.
2. **Lives close to the code.** Modules whose behavior a diagram describes get a link to the corresponding section from their top-of-file docstring (e.g. `src/run_misp_to_neo4j.py` points at §1).
3. **States its scope.** Each diagram section declares which files it covers and which failure modes it illuminates.
4. **Gets updated in the same PR that changes the flow.** A PR that changes the flow but not the diagram will be failed by the pin-test.

---

## Table of contents (ordered by 730-day-baseline production-test risk)

| # | Diagram | Status | Tier | De-risks |
|---|---------|--------|------|----------|
| 1 | [Baseline sequence — full end-to-end](#1-baseline-sequence) | 🚧 PR-J1 | **1** | Whole-run orchestration; where each audit fix lives |
| 2 | [Checkpoint state machine](#2-checkpoint-state-machine) | 🚧 PR-J1 | **1** | Resume correctness (PR-G1 round-1 + round-2 both bit here) |
| 3 | [Collector → MISP → Neo4j data flow](#3-collector--misp--neo4j-data-flow) | 🚧 PR-J1 | **1** | Dedup at scale; zone detection; rate-limit + retry paths; MISP trust check placement |
| 4 | [Incremental sync sequence](#4-incremental-sync-sequence) | 📋 PR-J2 | 2 | Concurrent-with-baseline scenarios; Issue #57 lock-race context |
| 5 | [Deployment topology](#5-deployment-topology) | 📋 PR-J2 | 2 | Operator orientation; which process owns which metric |
| 6 | [MISP ↔ Neo4j traceability](#6-misp--neo4j-traceability) | 📋 PR-J3 | 3 | PR #32 back-pointer validation; audit-trail on any ingested fact |
| 7 | [STIX export + ResilMesh integration surface](#7-stix-export--resilmesh-integration-surface) | 📋 PR-J3 | 3 | External contract; xAI / LLM consumer plug-in |
| 8 | [Zone detection flow](#8-zone-detection-flow) | 📋 PR-J3 | 3 | Sector classification correctness |

### Tier rationale

**Tier 1 — production-test-critical.** Must land before running the 2-year baseline. These three diagrams collectively illuminate every failure mode that has historically bitten long-running EdgeGuard baselines: memory, checkpoint resume, race conditions, dedup correctness, rate limits, transaction boundaries.

**Tier 2 — production-ready-useful.** Lands soon after Tier 1. Incremental sync is distinct from baseline but runs concurrently with it (the whole Issue #57 lock-race picture); deployment topology unblocks operator questions.

**Tier 3 — integration / completeness.** Lower urgency for the internal production-test itself but critical for ResilMesh integration and for completeness. Lands after Tier 2 proves stable.

---

## Execution plan — three PRs

Each PR lands a complete tier, with CI-validated symbol pins for the diagrams it contains.

### PR-J (this PR)

- [x] Roadmap update in `README.md` (G2 + H + Tier 3 + this document)
- [x] This file — skeleton with the reordered plan + empty sections for each diagram
- [x] No diagrams yet; no pin-test infrastructure yet
- [x] Commit message documents the prioritization rationale

### PR-J1 — Tier 1 (production-test-critical)

Target: complete before the next 730-day baseline attempt.

- [ ] §1 Baseline sequence diagram (Mermaid `sequenceDiagram`)
- [ ] §2 Checkpoint state machine (Mermaid `stateDiagram-v2`)
- [ ] §3 Collector → MISP → Neo4j flow (Mermaid `flowchart`)
- [ ] `tests/test_architecture_flow_pins.py` — grep-tests for every symbol named in §1-§3
- [ ] Docstring cross-references in `src/run_misp_to_neo4j.py`, `src/collectors/misp_writer.py`, `src/baseline_checkpoint.py`, `src/collectors/nvd_collector.py`

### PR-J2 — Tier 2 (production-ready-useful)

- [ ] §4 Incremental sync sequence (Mermaid `sequenceDiagram`)
- [ ] §5 Deployment topology (Mermaid `flowchart`)
- [ ] Extend `test_architecture_flow_pins.py` to cover §4-§5
- [ ] Docstring cross-references in `dags/edgeguard_pipeline.py`, `docker-compose.yml`

### PR-J3 — Tier 3 (integration / completeness)

- [ ] §6 MISP ↔ Neo4j traceability (Mermaid `flowchart`)
- [ ] §7 STIX export + ResilMesh surface (Mermaid `sequenceDiagram` + component callout)
- [ ] §8 Zone detection flow (Mermaid `flowchart`)
- [ ] Extend `test_architecture_flow_pins.py` to cover §6-§8
- [ ] Docstring cross-references in `src/stix_exporter.py`, `src/graphql_api.py`, `src/config.py` (zone detection)

---

## 1. Baseline sequence

> 🚧 **PR-J1 — to be written.** Tier 1. Highest-leverage diagram.

**Scope:** The full `edgeguard baseline --days N` run, from CLI entry point through collector sequencing, MISP writes, Neo4j merge, relationship building, and enrichment. Covers both `baseline` (additive) and `fresh-baseline` (destructive with backup gate).

**Files covered:**
- `src/edgeguard.py` (CLI entry points `cmd_baseline`, `cmd_fresh_baseline`)
- `src/run_pipeline.py` (orchestration)
- `src/collectors/*_collector.py` (11 collectors — tier-1/2/3 sequencing per PR-F4)
- `src/collectors/misp_writer.py` (write-side)
- `src/run_misp_to_neo4j.py` (sync to Neo4j)
- `src/build_relationships.py` (post-sync edges)
- `src/enrichment_jobs.py` (bridges, campaigns, decay)
- `src/baseline_checkpoint.py` (progress tracking)
- `src/baseline_lock.py` (sentinel file)

**Failure modes illuminated:**
- OOM on large MISP events (queued PR-G2 lives here)
- Partial-sync with collector exception mid-tier
- `fresh_baseline` destructive-op gating (backup timestamp, dev-config refusal)
- Neo4j circuit-breaker tripping mid-sync
- Rate-limit exhaustion on NVD / OTX
- Where the MISP tag-impersonation trust check fires (PR #44 + PR-I)

**Cross-reference targets:** PR-F4 tier sequencing; PR-F6 parent-DAG liveness; PR-F7 cross-event dedup; PR-G1 error-recovery paths; PR-I defense-state gauge read.

---

## 2. Checkpoint state machine

> 🚧 **PR-J1 — to be written.** Tier 1. The exact place PR-G1 round-1 + round-2 bit; diagramming this makes similar bugs visible.

**Scope:** State transitions for `baseline_checkpoint.py` — how `entry["current_page"]`, `entry["pages"]`, `entry["completed"]`, and source-specific fields (`nvd_window_idx`, `nvd_start_index`) evolve across: fresh start → in-progress → interrupted → resumed → completed → fresh-re-run.

**Files covered:**
- `src/baseline_checkpoint.py`
- `src/collectors/nvd_collector.py` (primary consumer with resume semantics)
- `src/collectors/misp_writer.py` (checkpoint writes on push)

**Failure modes illuminated:**
- Key mismatch between writer and reader (PR-G1 round-1: `page` vs `current_page`)
- Stale counter carrying across completed runs (PR-G1 round-2: `total_batches_done` not reset when `completed=True`)
- Resume-index off-by-one on window boundaries
- Concurrent-writer corruption (the advisory lock at `_checkpoint_lock_path()`)
- Path-traversal guard for `EDGEGUARD_CHECKPOINT_DIR`

**Cross-reference targets:** PR-G1 round-1 + round-2 fixes; `test_seed_recovers_persisted_page_end_to_end`.

---

## 3. Collector → MISP → Neo4j data flow

> 🚧 **PR-J1 — to be written.** Tier 1. Covers the highest-traffic path; answers ~40% of "why does my data look like this?" questions.

**Scope:** A single IOC's journey from collector output (dict with `indicator_type` + `value` + zone hints) through `MISPWriter.push_items` (dedup, tag resolution, event creation) through `MISPToNeo4jSync._sync_single_item` / `_sync_bulk` (batch merge) to the final `:Indicator` / `:CVE` / `:Malware` node with `SOURCED_FROM` edges.

**Files covered:**
- `src/collectors/collector_utils.py` (shared validation)
- `src/collectors/misp_writer.py` (write-side: event dedup, attribute dedup, cross-event dedup prefetch)
- `src/run_misp_to_neo4j.py` (read-side: `_attribute_to_stix21`, `sync_to_neo4j`, per-type batches)
- `src/neo4j_client.py` (Cypher MERGE with natural-key UNIQUE constraints)
- `src/source_trust.py` (creator-org allowlist check, fires here)
- `src/config.py` (`detect_zones_from_item`, `detect_zones_from_text`)
- `src/source_registry.py` (source ↔ tag resolution)

**Failure modes illuminated:**
- Cross-event dedup cache-key desync (PR-F7 was here)
- Source-tag alias resolution (PR-F7 round-3 fix)
- Dedup prefetch pagination bounds (PR-F7 Bugbot LOW)
- Zone detection precedence (text vs explicit tag vs event `x_edgeguard_zones`)
- SOURCED_FROM edge creation semantics (PR #41 source-truthful architecture)
- MISP tag-impersonation defense firing point (PR #44 Chip 5e / PR-I gauge)
- Rate-limit retry placement (collector vs MISP writer vs both)
- Natural-key UNIQUE constraint per label (PR-F9 fix #3 corrected the doc)

**Cross-reference targets:** PR-F7 cross-event dedup; PR #41 source-truthful pipeline; PR #44 trust check; PR-I observability; PR-F9 fix #3 docs correction.

---

## 4. Incremental sync sequence

> 📋 **PR-J2 — to be written.** Tier 2.

**Scope:** The four incremental DAGs (`edgeguard_medium_freq` 30min, `edgeguard_pipeline` 4h, `edgeguard_low_freq` 8h, `edgeguard_daily`) — how each one picks collectors, handles the 2-3 day re-read window, skips already-known events, and interacts (or should not interact) with an in-progress baseline.

**Files covered:**
- `dags/edgeguard_pipeline.py`
- `src/parent_dag_liveness.py` (PR-F6 orphan-process safeguard)
- `src/baseline_lock.py` (sentinel, read-path)
- `src/collectors/misp_writer.py` (`push_items` with `cross_event_cache`)

**Failure modes illuminated:**
- Baseline-lock race (Issue #57)
- Parent-DAG orphan processes (PR-F6)
- `fresh_baseline` DAG-conf typo that reached production (PR-F5 + PR-F8)
- Stale event-index pagination on MISP
- Timezone drift on the 2-3 day window

---

## 5. Deployment topology

> 📋 **PR-J2 — to be written.** Tier 2.

**Scope:** Local Docker Compose vs planned cloud (Aura Neo4j + cloud MISP + K8s) vs hybrid. Which process owns which port, which volume, which metric.

**Files covered:**
- `docker-compose.yml` + `docker-compose.override.yml`
- `Dockerfile`
- `prometheus.yml`, `grafana/*`
- `src/metrics_server.py` (port 8001)
- `src/query_api.py` (port 8000)
- `src/graphql_api.py` (port 4001)

**Failure modes illuminated:**
- `host.docker.internal` scrape path on Mac vs Linux
- MISP API TLS vs plain-HTTP config drift
- Airflow `postgres` metadata vs SQLite default (PR #45)
- Which restart policy maps to which SLO

---

## 6. MISP ↔ Neo4j traceability

> 📋 **PR-J3 — to be written.** Tier 3.

**Scope:** PR #32's back-pointer work — every Neo4j Indicator carries its originating MISP attribute UUID, every MISP-derived edge accumulates `r.misp_event_ids[]`, and STIX bundles carry `x_edgeguard_misp_*_ids`. This diagram shows the round-trip: from an edge in Neo4j, how do you retrieve the source MISP event + attribute?

**Files covered:**
- `src/run_misp_to_neo4j.py` (attribute-id + event-id propagation)
- `src/neo4j_client.py` (`misp_event_ids` accumulation on `SOURCED_FROM`)
- `src/stix_exporter.py` (`x_edgeguard_misp_*_ids` in STIX SDOs)
- Planned PR #33 UUID work (`src/node_identity.py`) if merged before this diagram lands

---

## 7. STIX export + ResilMesh integration surface

> 📋 **PR-J3 — to be written.** Tier 3.

**Scope:** How a query through GraphQL or REST turns into a STIX 2.1 bundle, what extensions EdgeGuard emits (`x_edgeguard_*`), and where ResilMesh consumers plug in.

**Files covered:**
- `src/stix_exporter.py` (`_deterministic_id` namespace, SDO construction)
- `src/graphql_api.py` (Strawberry schema, port 4001)
- `src/query_api.py` (FastAPI REST, port 8000)
- Planned `docs/RESILMESH_INTEROPERABILITY.md` updates post-PR #33

---

## 8. Zone detection flow

> 📋 **PR-J3 — to be written.** Tier 3.

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

## Appendix B — Self-validation (lands with PR-J1)

`tests/test_architecture_flow_pins.py` (to be created) will:

1. Parse this file for backticked tokens matching symbol patterns (`_[a-z_]+`, `[A-Z][a-zA-Z]+`, `[A-Z_]{3,}`).
2. For each token, grep `src/` for a definition (`def X`, `class X`, `X =`, `X:` env var).
3. Fail with a clear message naming the unresolved symbol if the grep returns nothing.
4. Skip Mermaid keywords (`participant`, `activate`, etc.), Prometheus metric names (handled by separate test), and words in prose text (detected by being outside backticks or outside diagram code fences).

This keeps the cost of lying in a diagram at exactly "CI fails," which is the only cost that changes behavior.
