# Flow Audit §8 — Post-sync Relationship Construction

**Date:** 2026-04-20 afternoon
**Scope:** `src/build_relationships.py` (12 link queries), `src/enrichment_jobs.py`, `src/neo4j_client.py` relationship helpers
**Goal:** Graph-integrity bugs — wrong direction, duplicate edges, missing provenance, non-idempotent enrichment

---

## S4 (CRITICAL) — `decay_ioc_confidence` is non-idempotent; multi-decays stale nodes on every run

**File:** `src/enrichment_jobs.py:92-103`

Decay query **multiplies `n.confidence_score` every time it runs** as long as `n.last_updated` stays in the same tier window. No "already-decayed" flag; `n.last_updated` NOT refreshed by decay. On 730-day baseline with daily enrichment, a 180-365-day-stale node has been in that tier for ~100 runs → `confidence × 0.70^100` ≈ 0, floored to 0.10 within a handful of runs. **Every indicator in 180-365-day bucket converges to 0.10 floor within ~7 enrichment runs** — losing all discriminatory power.

**730d impact:** With Airflow's daily enrichment, ~350k Indicators enter 90-180 and 180-365 tiers; every one drops to floor within a week. Confidence ranking across indicators becomes meaningless; RAG/xAI ranks 100-day-old IP at 0.10 the same as 13-month-old one.

**Fix:** Add `SET n.last_decayed_tier = $tier` + gate on `AND (n.last_decayed_tier IS NULL OR n.last_decayed_tier <> $tier)`. OR better: compute confidence as deterministic function of age on read (not mutate in place). OR store `n.base_confidence` separately, recompute from it.

**Regression test:** Run `decay_ioc_confidence` 5× on indicator with `last_updated = now() - 120 days`; assert `n.confidence_score == base × 0.85` once, not `base × 0.85^5`.

---

## S4 (CRITICAL) — `calibrate_cooccurrence_confidence` clobbers decay (resolved today), decay runs AFTER calibrate

**File:** `src/enrichment_jobs.py:468-469, 506-513, 656-665`

Today the runner order is bridge → campaigns → calibrate → decay (line 656-665). Calibrator writes flat overwrite to *edges*; decay acts on *nodes* — so no double-penalize today. But:

1. Calibrator **overwrites `r.confidence_score` every run** with fixed tier value (0.50, 0.45, …), regardless of whether previous run already calibrated. Idempotent on edges but erases any manual/external adjustment silently.
2. Calibrator writes `r.confidence_score = $conf, r.calibrated_at = datetime()` unconditionally — edges previously at 0.9 (e.g. `malware_family_match` from `build_relationships.py:440` CASE `WHEN > r.confidence_score`) demoted to 0.50 IF calibrator targets them via `r.source_id`.

Today saved by q9 overwriting `r.source_id = "malware_family_match"` → calibrator filter `r.source_id IN ["misp_cooccurrence", "misp_correlation"]` misses. But that's lucky, not correct (see S3-Q9).

**Fix:** Calibrate guards: `WHERE r.calibrated_at IS NULL OR r.calibrated_at < r.updated_at`. Write to separate `r.adjusted_confidence` rather than clobbering `r.confidence_score`.

---

## S3 — Query #9 (malware_family INDICATES) corrupts `r.source_id` of co-occurrence edges

**File:** `src/build_relationships.py:440`

`MERGE (i)-[r:INDICATES]->(m) ... SET r.source_id = "malware_family_match", ...` — when INDICATES already exists from query #4 (co-occurrence, `r.source_id = "misp_cooccurrence"`), #9's MERGE matches it and **overwrites `r.source_id`**. Hides co-occurrence provenance. Calibrator then filters on `source_id IN ["misp_cooccurrence", "misp_correlation"]` (enrichment_jobs.py:467) — silently **exempts this edge from calibration** → confidence stays at 0.8 even though it came from 96k-indicator bulk dump.

**730d impact:** Any indicator with `malware_family` tag AND co-occurred with that malware (common — both set by MISP attribute) keeps inflated 0.8. Estimated 30-50% of INDICATES edges in a 2-year baseline.

**Fix:** Accumulate: `r.source_ids = apoc.coll.toSet(coalesce(r.source_ids, []) + ["malware_family_match"])`. Calibrator: `ANY(s IN r.source_ids WHERE s IN [...])`.

---

## S3 — Query #4 cross-product fan-out inflates reported count 3-10×

**File:** `src/build_relationships.py:258-279`

Inner joins indicator × malware over `eid IN m.misp_event_ids`. Single bulk-feed event with 5000 indicators × 3 malware = 15000 edges — fine (MERGE dedupes). Subtle: `UNWIND eids AS eid` followed by MATCH, indicator sharing 5 events with malware runs 5× per (i, m) inside single batch. MERGE dedupes → OK. But `r.updated_at` re-stamped 5× per batch, APOC `total` multiplied by 5 — reported count inflated. Cosmetic but confusing.

**Fix:** `WITH DISTINCT i, m` before MERGE; report `count(DISTINCT id(r))`.

---

## S3 — `bridge_vulnerability_cve` REFERS_TO lacks source/provenance/updated_at

**File:** `src/enrichment_jobs.py:583`

REFERS_TO stamped only with `r.src_uuid`, `r.trg_uuid`. No `r.created_at`, `r.updated_at`, `r.source_id`, `r.edgeguard_managed`:
1. **CLOUD_SYNC delta extraction** filtering `r.updated_at >= ...` **silently excludes REFERS_TO** — invisible to cloud sync and Grafana recent-edges panels
2. Operators can't tell when bridge ran
3. No `edgeguard_managed = true` → cleanup queries filtering on flag miss these edges

**Fix:** Add `ON CREATE SET r.created_at = datetime(), r.edgeguard_managed = true SET r.updated_at = datetime(), r.source_id = "bridge_vulnerability_cve"`.

---

## S3 — `build_campaign_nodes` Step 3: `collect(i)[0..100]` non-deterministic + monotonic growth

**File:** `src/enrichment_jobs.py:324-335`

`collect(i)[0..100]` returns first 100 in Neo4j internal ordering (not stable). Run #1 attaches {i1..i100} via PART_OF; run #2 attaches {i17..i116} (different 100). New 16 get edges, old 16 **keep edges from run #1 forever** (MERGE without DELETE never removes). Campaign's "sample" grows monotonically.

After 730 daily runs, ThreatActor with 10 000 active indicators has **every single one** wired via PART_OF — defeating the point of 100-cap.

**Fix:** Either (a) drop the cap entirely (consistent semantics), OR (b) MERGE with explicit ORDER BY and DELETE edges outside current top 100. Current design is neither.

---

## S3 — `build_campaign_nodes` Step 4 reactivation logic wrong

**File:** `src/enrichment_jobs.py:342-367`

Step 4 sets `c.active = false` when all PART_OF indicators retired. But PART_OF edges were created in Step 3 with the non-deterministic 100-cap — if sampled 100 include 1 still-active, campaign stays active even when other 9900 retired.

**Fix:** Step 4 queries directly via `(a:ThreatActor)<-[:ATTRIBUTED_TO]-(:Malware)<-[:INDICATES]-(i:Indicator)`, not via PART_OF sample.

---

## S2 — `clear_all` batch DELETE + partial wipe hazard

**File:** `src/neo4j_client.py:648-657`

10k-node batches. Mid-way failure retried via `@retry_with_backoff` with stale `node_count`. External SIGTERM leaves half-wiped graph; subsequent baseline double-populates.

**Fix:** Two-phase commit: mark all with `n.to_delete = true`, then batch-delete resumably. Or drop database + recreate.

---

## S2 — `create_indicator_vulnerability_relationship` creates edges to BOTH Vulnerability AND CVE for same CVE

**File:** `src/neo4j_client.py:2486-2515`

Creates `(i)-[:INDICATES]->(v:Vulnerability)` AND `(i)-[:INDICATES]->(c:CVE)` if both exist. After `bridge_vulnerability_cve` creates `(v)-[:REFERS_TO]->(c)`, indicator's relationship is **triply represented**:
- `Indicator → Vulnerability → CVE` (via REFERS_TO)
- `Indicator → CVE` (direct)
- `Indicator → Vulnerability` (direct)

STIX export / RAG walking any INDICATES double-counts. Also: edge label is `INDICATES` here but `build_relationships.py` 3a/3b uses `EXPLOITS` — same semantic under **two different edge types** depending on code path.

**Fix:** Unify edge type. Spec says `EXPLOITS` for indicator→CVE. Pick one.

---

## S2 — `build_relationships.py` queries 1-12 are sequential; partial commits leak

**File:** `src/build_relationships.py:178-532`

Each query own `apoc.periodic.iterate` transaction. If #5 fails, #1-4 committed, #6-12 proceed. Returns `failures == 0` with PARTIAL log. Graph queryable in half-built state. Airflow retry re-runs all 12 (safe via MERGE) but no "all-or-nothing" mode.

**Fix:** `--atomic` flag wraps in outer session.begin_transaction() (may exceed tx limit on 350k/700k). Alternative: Prometheus counter `edgeguard_build_rel_partial_total` + Grafana alert.

---

## S2 — Zone on edges is missing

**Files:** all `create_*_relationship` + 12 queries in `build_relationships.py`

No edge carries `r.zone`. Every edge has `r.src_uuid`/`r.trg_uuid` but zone is node-only. Today zone-filtered GraphQL reads from node — fine. If callers ever switch to edge-scoped zone filtering (sensible for multi-zone indicators), nothing's there. Not a bug today, but a footgun — audit prompt mentions `zones` parameters on helpers that don't exist.

**Fix (preventive):** Document that zone lives on endpoint nodes only.

---

## S1 — Minor polish items

- **L1.** `_upsert_sourced_relationship` doesn't `ON CREATE SET r.updated_at` (line 1417-1422) — but general SET block (line 1425) runs after ON CREATE → `r.updated_at` IS set on first insert. False alarm.
- **L2.** `calibrate_cooccurrence_confidence` Step 1 UNWIND NULL rows: filter applied AFTER UNWIND; collapses correctly. OK.

---

## What's handled well

- **Queries #1, #2, #3a, #3b, #5, #6, #8, #10 in `build_relationships.py`** — exact-match natural keys, carry `r.confidence_score`, `r.match_type`, `r.created_at`/`r.updated_at`, `r.src_uuid`/`r.trg_uuid`. Idempotent.
- **Sector uuid stamping via Python-precomputed CASE** (`_SECTOR_UUIDS`) — deterministic, cross-environment.
- **`_upsert_sourced_relationship` MIN/MAX CASE** — defensive NULL handling, correctly nested.
- **Array accumulation via `_dedup_concat_clause`** — `apoc.coll.toSet(coalesce(..., []) + new)` used consistently across 11 batch-rel templates.
- **`_safe_run_batched` skip_query design** (PR #34 round 20) — detects orphan input rows.
- **TARGETS vs AFFECTS split** (PR #33 round 11) — canonical schema separation enforced in both `build_relationships.py` 7a/7b AND batch dispatch.
- **Campaign uuid precomputation + TOCTOU guard** (enrichment_jobs.py:197-200) — refuses to MERGE Campaigns without precomputed uuid.
- **Campaign `c.first_seen` / `c.last_seen` MIN/MAX** — defensive NULL handling, symmetric.
- **`parallel: false` on every `apoc.periodic.iterate`** — no ordering races.
- **`canonicalize_merge_key` in batch + single-item MERGE** (PR #37) — remaining gap in post-sync relationship MATCHes (§5 C1).
- **`edgeguard_managed=true` stamped on every MERGE** including Sector auto-creates.
- **`mark_inactive_nodes`** — re-activation + deactivation symmetric.

Determinism story is solid for nodes; main gaps are **indicator-value canonicalization split (§5 C1)**, **decay multi-decay (S4)**, and **campaign PART_OF monotonic growth (S3)**.
