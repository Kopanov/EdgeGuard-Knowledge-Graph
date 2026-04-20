# Flow Audits — Consolidated Findings Index

This directory holds multi-agent audit reports that drive the bug-fix
work on the main pipeline. Organized for **730-day baseline
production-test readiness** — what bites a 2-year historical run.

## Audit passes

### Pass 1 — Tier-1 critical flows (2026-04-20 morning)

Output: 37 findings. Driven fixes in PR-F9, PR-G1, PR-I, PR-J, PR-K1, PR-K2, PR-K3 (merged or in flight).

| # | Flow | File | Findings |
|---|------|------|----------|
| 01 | Baseline sequence | [`01_baseline_sequence.md`](01_baseline_sequence.md) | 11 |
| 02 | Checkpoint state machine | [`02_checkpoint_state_machine.md`](02_checkpoint_state_machine.md) | 13 |
| 03 | Collector → MISP → Neo4j | [`03_collector_misp_neo4j.md`](03_collector_misp_neo4j.md) | 13 |

### Pass 2 — Comprehensive production-test audit (2026-04-20 afternoon)

**Trigger:** operator pivoted from reactive Bugbot-fix cycles to proactive comprehensive auditing. 5 parallel agents audited specific 730d concerns. **~60 findings.**

| # | Focus | File | Findings |
|---|-------|------|----------|
| 04 | Timestamps / dates end-to-end | [`04_timestamps_dates.md`](04_timestamps_dates.md) | 11 (5 HIGH) |
| 05 | Neo4j merge determinism | [`05_merge_determinism.md`](05_merge_determinism.md) | 10+ (2 CRITICAL, 3 HIGH) |
| 06 | MISP aggregation + dedup | [`06_misp_aggregation.md`](06_misp_aggregation.md) | 9 (4 HIGH, 5 MEDIUM) |
| 07 | Per-collector baseline correctness | [`07_collector_baseline.md`](07_collector_baseline.md) | 19 (8 HIGH, 10 MED, 6 LOW) |
| 08 | Relationship / edge integrity | [`08_relationship_integrity.md`](08_relationship_integrity.md) | 10+ (2 CRITICAL, 4 HIGH) |

---

## Tier A — 730-DAY BASELINE BLOCKERS (FIX BEFORE PRODUCTION RUN)

**~17 findings.** Each either silently loses data, corrupts historical dates, or produces non-deterministic graphs. Every one has a clear production path that triggers it during a real 730d run.

> **Note on Issue #57 (baseline lock, finding §1-1 from Pass-1 audit):** the Airflow-aware baseline-lock architectural gap was identified in Pass 1 (tracked separately as [Issue #57](../../issues/57) — not a patch, needs design spike). Interim mitigation during 730d production-test: use CLI `python src/run_pipeline.py --baseline` (in-process lock acquisition works) OR pre-pause scheduled incremental DAGs in Airflow for the baseline window.

### A1. Silent data loss (operator sees "success", graph is empty or wrong)

| ID | File:line | Sev | What breaks | Fix strategy |
|----|-----------|-----|-------------|--------------|
| **CB-H3** | `src/collectors/nvd_collector.py:618` | HIGH | NVD baseline truncates output to `EDGEGUARD_INCREMENTAL_LIMIT` if env set → 99%+ silent data loss | Gate on `baseline=True`; use separate `BASELINE_NVD_MAX` |
| **CB-H1** | `src/collectors/otx_collector.py:291` | HIGH | OTX baseline hard-capped at `max_pages=200 × limit=50 = 10k` pulses; typical 2y = 15-30k | Raise `max_pages` via env, decouple from incremental limit |
| **CB-H6** | `src/collectors/vt_collector.py:588` | HIGH | VT baseline forces `limit=20` when None → 20 items for a 730d run | Gate on `baseline=True` for baseline ceiling |
| **CB-H7** | `src/collectors/energy_feed_collector.py:100` (+ healthcare) | HIGH | Sector placeholders have no `baseline` kwarg → silent no-op | `make_skipped_optional_source(..., skip_reason_class="placeholder")` |
| **CB-H8** | `src/collectors/global_feed_collector.py:99,137` | HIGH | ThreatFox `days=730` silently clamped by abuse.ch API to 7/30 max | Loop 30d windows OR check `query_status=illegal_days` |
| **MA-H3** | `src/collectors/misp_writer.py:548-552` | HIGH | Per-event attribute prefetch re-raises transient MISP errors → one flake aborts whole collector baseline | Apply PR-F7's `break`+preserve-partial pattern |

### A2. Date/timestamp corruption (2 years of data with wrong dates)

| ID | File:line | Sev | What breaks | Fix strategy |
|----|-----------|-----|-------------|--------------|
| **TS-F1** | `src/source_truthful_timestamps.py:436-449` | HIGH | NVD `published` strings TZ-less → Neo4j parses as server-local, not UTC. Non-UTC server = 2y of CVEs offset by server tz | Apply `tzinfo=timezone.utc` in full-string branch of `coerce_iso` |
| **TS-F2** | `src/collectors/misp_writer.py:1386` | HIGH | `push_items` buckets by wall-clock `now()`, ignores item's own date → 13-year-old CVE lands in "today's" MISP event | Bucket by `_coerce_item_date(item)` with fallback |
| **TS-F4** | `src/collectors/vt_collector.py:404,523` | HIGH | VT's `datetime.now()` fallback for missing `first_submission_date` leaks wall-clock into `r.source_reported_first_at` (VT IS on reliable allowlist) | Omit `first_seen` when source provides no value (honest-NULL) |
| **TS-F5** | `src/collectors/otx_collector.py:440,482` | HIGH | OTX `datetime.now()` fallback for missing `pulse.created` → today's date in MISP `first_seen` | Use `None` fallback |
| **TS-F3** | `src/run_misp_to_neo4j.py:1316` | HIGH | Manual STIX fallback uses raw MISP Unix epoch int as `created`/`valid_from` | Route through `coerce_iso` |

### A3. Merge / relationship determinism (same input → different graph)

| ID | File:line | Sev | What breaks | Fix strategy |
|----|-----------|-----|-------------|--------------|
| **MD-C1** | `src/neo4j_client.py:2488,2501,2541,2597,3051,3065,3099,3106` | **CRITICAL** | Relationship MATCH uses raw indicator value; MERGE canonicalizes to lowercase → edges SILENTLY DROPPED for uppercase/mixed-case hashes from MISP | Canonicalize in dispatch before MATCH (one place) |
| **RI-S4-Decay** | `src/enrichment_jobs.py:92-103` | **CRITICAL** | `decay_ioc_confidence` multi-decays nodes every Airflow run → confidence converges to 0.10 floor in ~7 runs | Add `last_decayed_tier` gate OR recompute from `base_confidence` |
| **RI-S3-Q9** | `src/build_relationships.py:440` | HIGH | Query #9 overwrites `r.source_id` of co-occurrence edges → calibrator filter misses them → ~30-50% INDICATES edges with inflated 0.8 | Accumulate `r.source_ids` as array; calibrator uses ANY() |
| **RI-S3-Camp** | `src/enrichment_jobs.py:324-335` | HIGH | `build_campaign_nodes` uses `collect(i)[0..100]` non-deterministic; PART_OF edges grow monotonically, 100-cap meaningless | Drop cap OR explicit delete-outside-top-N |

### A4. Scale / aggregation resilience

| ID | File:line | Sev | What breaks | Fix strategy |
|----|-----------|-----|-------------|--------------|
| **MA-H2** | `src/collectors/misp_writer.py::push_items` | HIGH | No large-event split; events >~20k attrs make MISP edit-event time out | Split overflow into `-part2` event before writes to part1 |

---

## Tier B — Production readiness (silent-degradation, not catastrophic)

**~25 findings.** Covered in detail reports. Examples:

- **TS-F6** — `SECTOR_TIME_RANGES` `months × 30` approximation drops 10 days on 2y lookback
- **MA-H4** — `restSearch limit=50` can miss exact match past row 49 (latent bomb)
- **MD-H1** — `create_misp_relationships_batch` sets `r.confidence_score = row.confidence` flat overwrite, not MAX
- **MD-H2** — `merge_node_with_source` scalar `extra_props` last-writer-wins for `cvss_score`, `severity`
- **CB-H4** — CISA silently drops entries with empty `dateAdded` (string-compare)
- **CB-H5** — OTX baseline truncates by pulse count, not item count
- **TS-F7** — `_event_covers_since` compares dates not datetimes → 3-hour boundary loss per incremental run
- **MA-M1/M2** — `_push_batch` retry can duplicate; tag rejection silently drops batch
- **RI-S3-BridgeProvenance** — REFERS_TO edges lack `r.updated_at`, invisible to CLOUD_SYNC delta
- Several more

---

## Tier C — Hygiene / observability

**~20 findings.** Best-effort, not bug-fixes. Deferred until Tier A + B stable.

---

## Proposed execution (Tier A only)

Operator direction: **stop adding improvements, focus on fixing bugs in the main pipeline.**

| PR | Scope | Touches | Est size |
|----|-------|---------|----------|
| **PR-M1** Collector silent-data-loss | CB-H1, H3, H6, H7, H8 | 5 collectors | ~150 LOC + tests |
| **PR-M2** Timestamp/date corruption | TS-F1-F5 | `source_truthful_timestamps.py`, `misp_writer.py`, `run_misp_to_neo4j.py`, VT, OTX | ~100 LOC + tests |
| **PR-M3a** Merge determinism — indicator canonicalization | MD-C1 | `neo4j_client.py` relationship dispatches | ~40 LOC + tests |
| **PR-M3b** Decay idempotency | RI-S4-Decay | `enrichment_jobs.py` | ~30 LOC + tests |
| **PR-M3c** Co-occurrence source_id accumulation | RI-S3-Q9 | `build_relationships.py` + calibrator | ~30 LOC + tests |
| **PR-M3d** Campaign PART_OF determinism | RI-S3-Camp | `enrichment_jobs.py` | ~40 LOC + tests |
| **PR-M4** MISP aggregation resilience | MA-H2, H3 | `misp_writer.py` | ~80 LOC + tests |

Bundling option: M3a-d could be one PR if no conflicts (all touch different sites). Keeping separate for cleaner review.

**After Tier A lands:** run 730d baseline as a real production test. Tier B and C land after that proves stable.

---

## What's NOT in this audit

Deliberately out of scope for this pass; separate audit tracks:

- Full STIX 2.1 export correctness (partial coverage via timestamps audit only)
- ResilMesh integration surface
- Security / trust-boundary (PR-I Tier 2 shipped; Tier 3 fail-closed tracked separately)
- Observability + alerting (queued PR-H)

These get audited after the main pipeline is bug-fixed and the 730d run exposes what remains.
