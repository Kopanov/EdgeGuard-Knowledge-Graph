# Flow Audit §5 — Neo4j Merge Determinism

**Date:** 2026-04-20 afternoon
**Scope:** Every Cypher MERGE + relationship creation helper
**Goal:** Same inputs → same graph, regardless of retry, concurrent DAGs, collector order

---

## CRITICAL — C1. Raw indicator `value` used in every post-sync relationship MATCH — drops edges silently

**Files:** `src/neo4j_client.py:2488, 2501, 2541, 2597, 3051, 3065, 3099, 3106` (`create_indicator_vulnerability_relationship`, `create_indicator_malware_relationship`, `create_indicator_sector_relationship`; `q_ind_mal` / `q_tgt_ind` / `q_expl_vuln` / `q_expl_cve` in `create_misp_relationships_batch`); callers at `src/run_misp_to_neo4j.py:2600, 2614, 2634`.

`merge_indicators_batch` (line 1988) canonicalizes `value` via `canonicalize_merge_key` before MERGE — e.g. `"DEADBEEF..."` stored as `"deadbeef..."` for hash/ipv4/domain/hostname types. But every post-sync relationship query MATCHes `(i:Indicator {value: $value})` with the **raw, un-canonicalized** value threaded from the MISP parser (`str(value).strip()` only, no `.lower()`). For an SHA256 or JA3 that MISP reports uppercase: batch creates Indicator at `deadbeef...`, `create_misp_relationships_batch` looks up `DEADBEEF...` → zero rows → edge silently not created. `_dropped_rels` counter does NOT catch this (only counts missing endpoints before the query ran).

**730d impact:** Non-deterministic — across 11 collectors an SHA256 from CyberCure (uppercase) vs AbuseIPDB (lowercase) produces the same node but *different* edge sets depending on which collector emitted the relationship. Same inputs → different graph. For a 2-year baseline with 350k+ nodes, every hash-typed INDICATES/EXPLOITS relationship is exposed.

**Fix:** Apply `canonicalize_merge_key("Indicator", {...})` at the producer (`parse_attribute`) OR inside `create_misp_relationships_batch`'s row dispatch (before appending). Cheaper in one place: normalize in the dispatch. Same fix needed in the three single-item `create_*_relationship` helpers.

**Regression test:** Feed `{indicator_type:"sha256", value:"DEADBEEF...", misp_event_id:"7"}` to `merge_indicators_batch`, then a relationship row with same MixedCase value; assert one `INDICATES` edge exists.

---

## CRITICAL — C2. `build_campaign_nodes`: `collect(DISTINCT i)[0..100]` is order-non-deterministic → `c.zone` flaps across runs

**File:** `src/enrichment_jobs.py:233, 274`

Neo4j's `collect()` does NOT guarantee ordering. `collect(DISTINCT i)[0..100] AS indicator_sample` picks a different 100 of N matching Indicators on every run. Then `c.zone = all_zones` (line 274) **unconditionally overwrites** with the union over that non-deterministic 100-sample. For a Campaign with 500 associated indicators in multiple zones, `c.zone` can be `["healthcare"]` on one run and `["healthcare","energy"]` on the next.

Only `c.zone` is affected (first_seen/last_seen aggregate over ALL matching `i`). But `c.zone` is load-bearing for dashboard filters.

**730d impact:** For every large campaign, `c.zone` rewrites to a random subset on each enrichment run. Dashboards filtering `WHERE 'healthcare' IN c.zone` see campaign flicker in/out.

**Fix:** Either drop the sample (compute from all indicators via `reduce(...)`) OR MIN/MAX guard: `c.zone = apoc.coll.toSet(coalesce(c.zone, []) + all_zones)`. Latter matches accumulation contract.

**Regression test:** Insert 150 Indicators across three zones; run `build_campaign_nodes` twice; assert `c.zone` set-equal across both runs.

---

## HIGH — H1. `_set_clause` writes `r.confidence_score = row.confidence` unconditionally → last-writer-wins

**File:** `src/neo4j_client.py:2985` (and lines 2396, 2446, 2493, 2506, 2547, 2602, 2666 for hard-coded constants)

`create_misp_relationships_batch` is the UNWIND-based helper used by every edge in `run_misp_to_neo4j.py`. Shared `_set_clause` writes `r.confidence_score = row.confidence` with no MAX-guard. `build_relationships.py:440` (`indicates_family`) uses MAX-guarded CASE; `create_indicator_malware_relationship` hard-codes 0.6. Same (i, m) pair gets whichever ran last.

**730d impact:** Under concurrent DAGs (30min OTX + 8h NVD + 4h CISA during baseline) edge confidences oscillate. "INDICATES with confidence > 0.7" result differs hour-to-hour.

**Fix:** Replace every scalar with MAX-guarded CASE. Pattern exists in `merge_indicators_batch` line 2075 — promote to shared helper.

**Regression test:** Call `create_misp_relationships_batch` twice with confidence=0.4 then 0.9; then once with 0.5. Final `r.confidence_score == 0.9`.

---

## HIGH — H2. `merge_node_with_source` scalar `extra_props` last-writer-wins

**File:** `src/neo4j_client.py:1220` — `query += f", n.{prop_name} = ${prop_name}"`

NVD's `cvss_score=7.5` overwritten by later CISA import with `cvss_score=7.3`. Python-side `if prop_value is not None` filter helps only when the later caller omits the field.

**730d impact:** Two same-CVE syncs (NVD 7.5 → secondary 7.3) flip the graph score per-hour. Operationally confusing.

**Fix:** Route scientific fields (cvss_score, severity) through MAX or source-precedence map. Narrative fields (`description`): pick longest or pin to highest-trust source.

---

## HIGH — H3. `canonicalize_merge_key` does NOT lowercase `Indicator.value` for URL/email/filename types

**File:** `src/node_identity.py:460-465`

Intentional per the comment (URL path case-sensitive) — but MISP data arrives mixed-case. `HTTP://Example.COM/Path` from one collector + `http://example.com/Path` from another → treated as different nodes. Combined with C1, post-sync relationship MATCH won't find the right node.

**730d impact:** URL-type indicators split into 2-3 nodes per logical URL across collectors.

**Fix:** Product decision — extend canonicalization to lowercase host-part of URLs, OR split `host`/`path` pair with lowercase on host only.

---

## MEDIUM — M1. Silent edge orphaning on `_upsert_sourced_relationship` failure

**File:** `src/neo4j_client.py:1475-1477` vs `1302-1310`

If node MERGE succeeds but downstream `_upsert_sourced_relationship` raises non-transient error, the function catches it, logs warning, returns False. Node committed; caller sees False and treats item as failed. Orphan Indicator persists with no `SOURCED_FROM` edge. Next run fixes it but intermediate state is inconsistent.

**Fix:** Run node MERGE + edge MERGE in one session transaction.

---

## MEDIUM — M2. `merge_indicators_batch` per-BATCH_SIZE partial failure

**File:** `src/neo4j_client.py:2138-2140`

Outer `for i in range(0, len(items), BATCH_SIZE)` catches per-batch exceptions and continues. Batches 1-4 commit, batch 5 fails, batches 6-20 continue. Retrying adds 1-4 and 6-20 again (idempotent via MERGE — OK for graph). But `r.updated_at = datetime()` on re-run batches is LATER than single-pass — affects `CLOUD_SYNC` delta extraction contract filtered on `r.updated_at >= T`.

**Fix:** Log batch-5 failure with context for operator re-run OR promote to managed-retry transaction.

---

## MEDIUM — M3. Scalar `indicator_role`, `url_status`, `last_online`, `threat_label` use `coalesce(item.X, n.X)`

**File:** `src/neo4j_client.py:2089-2095`

"If incoming non-null, overwrite; else keep." For indicator switching between dropper/c2 labels across sources, final value = whichever source fired last.

**Fix:** If union: accumulate via `apoc.coll.toSet`. If single label: pin to highest-trust source.

---

## MEDIUM — M4. `build_relationships.py` q4: `[0..200]` slice order-dep on `misp_event_ids[]` insertion order

**File:** `src/build_relationships.py:261`

`apoc.coll.toSet` preserves insertion order; parallel incremental DAGs append in non-deterministic order. 200-cap truncates potentially-valuable subset.

**Fix:** Sort before slicing: `WITH i, apoc.coll.sort(i.misp_event_ids) AS eids_sorted, eids_sorted[0..200] AS eids`.

---

## MEDIUM — M5. `create_malware_actor_relationship` fires Cartesian join on aliases

**File:** `src/neo4j_client.py:2440-2442`

Alias-based `WHERE (m.name = $name OR $name IN coalesce(m.aliases, []))` — single name matching 3 Malware + 2 ThreatActor → 6 edges. Same pattern in `create_misp_relationships_batch` q_attr.

**Fix:** `WITH m, a LIMIT 1` after MATCHes, OR require exact name match (drop alias fallback in batch path).

---

## LOW — L1. `calibrate_cooccurrence_confidence` writes `r.confidence_score = $conf` unconditionally

**File:** `src/enrichment_jobs.py:468, 512`

Erases any prior MAX-guarded value from `build_relationships` q9. Today gated by `WHERE r.source_id IN [...]`, so narrow path — but if the q9 fix (RI-S3-Q9) overwrites `r.source_id`, this exemption disappears.

---

## What's handled well

1. **Deterministic node uuids** (`compute_node_uuid`) — UUIDv5 over canonical (label, key); same input → same uuid everywhere. `ON CREATE SET n.uuid` + `coalesce(n.uuid, ...)` defensively. PR #33 round 21 TOCTOU guard is right.
2. **Array accumulation via `_dedup_concat_clause`** — all 47+ sites use `apoc.coll.toSet(coalesce(prop, []) + addition)`. Zone/source/tags/misp_event_ids union correctly.
3. **`confidence_score` on nodes is MAX-guarded** — merge_indicators_batch (line 2075), merge_vulnerabilities_batch (2271), merge_node_with_source (1147). Reproducible.
4. **`n.first_imported_at` set only `ON CREATE`** — never overwritten. Immutability honored.
5. **`source_reported_first_at` / `source_reported_last_at` edge MIN/MAX** — correct nested-CASE with NULL-short-circuit. PR (S5) was clean.
6. **`parallel: false` on every `apoc.periodic.iterate`** — no intra-batch ordering races.
7. **`canonicalize_merge_key` applied in batch and single-item MERGE paths** (PR #37) — remaining gap is post-sync relationship MATCHes (C1).
8. **`edgeguard_managed=true` stamped on every MERGE** including Sector auto-creates.
9. **`VALID_ZONES` + `_SECTOR_UUIDS` derivation is sorted** — stable across Python runs.
10. **`skip_query` pattern** on batched rel queries — counts orphans directly, no false positives.

The determinism story is in good shape for **nodes**; main gap is indicator-value canonicalization split between MERGE and MATCH (C1), scalar edge-property races (H1, H2), and campaign PART_OF non-determinism (C2).
