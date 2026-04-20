# Flow Audit §3 — Collector → MISP → Neo4j

**Date:** 2026-04-20
**Commit audited:** `8e39f88`
**Scope:** A single IOC's journey from collector through MISPWriter, through MISP-read, through trust check, through sync, to Neo4j node + SOURCED_FROM edge
**Method:** Walk one IPv4 from OTX collector end-to-end; at each seam verify contract correctness; then enumerate all attribute types and verify round-trip
**Goal:** Find residual bugs + contract mismatches in the highest-traffic flow

---

## A. Dedup cache key — residual desync risk

**File:** `src/collectors/misp_writer.py:1385, 1467`
**Class:** Cross-component contract (subtle)

`push_items` groups by `source = item.get("tag", "unknown")` (line 1385), then later keys cross-event prefetch cache by `source_tag = self.SOURCE_TAGS.get(source, f"source:{source}")` (line 1467). PR-F7 fixed the cache lookup — but items are grouped by RAW `source`, so two canonical sources that resolve to the SAME MISP tag never collide into one group.

Today benign because `source_to_misp_tag_map()` returns a different `source:...` tag for every canonical source. If two sources ever share a misp_tag (e.g. future "nvd_nightly" aliased into NVD), grouping-by-tag bypasses PR-F7 consolidation → re-hits MISP twice per same-tag source. Low-probability today.

**Also:** `source_to_misp_tag_map()` is FULL alias-expanded (`source_registry.py:645-662`) — includes both `"cisa"` AND `"cisa_kev"` → same `"source:CISA-KEV"`. `MISPWriter.SOURCE_TAGS` knows both spellings. `config.SOURCE_TAGS` is the legacy subset. If a collector emits raw `self.tag = "cisa"` (shortname), both maps resolve via different paths — defensively correct but worth a test pin.

**Proposed fix:** Group on `SOURCE_TAGS.get(source, source)` directly so both layers share one key.
**Regression test:** Two sources aliased to same misp_tag; verify single cache hit, single MISP prefetch.

---

## B/C. Zone precedence — multi-zone IS preserved end-to-end; one edge

**File:** `src/collectors/misp_writer.py:676, 694-709` + `src/run_misp_to_neo4j.py:2104-2122`
**Class:** Multi-zone attribution

`_get_zones_to_tag()` honors collector's `zone` array verbatim. **No text-based re-detection in writer.** Precedence: collector decides → MISPWriter tags → parse_attribute re-reads tags. But writer and reader implement DIFFERENT multi-zone rules:

- **Writer** (line 701-709): if specific zones present, drop global entirely, emit each specific zone
- **Reader** (line 2110): extract zones from attr tags; if ANY specific zone found, use ONLY attr tags

Edge case: writer emits `zone:Global` only (collector said `["global"]`) → reader returns `["global"]`. Correct. Writer would never emit `zone:Global` + `zone:Finance` (rule forbids) but if it did, reader would ignore global and return `["finance"]` — still correct. Multi-zone (`healthcare` + `energy` for hospital/grid breach) preserved end-to-end. **OK.**

Subtler: `_get_zones_to_tag` falls back to `[DEFAULT_SECTOR]` if zones empty. Collector `zone=[]` → writer stamps `zone:Global`. Fine. `zone=None` → coerced to `["global"]` at line 694. Fine.

**Verdict:** Works correctly but the writer/reader have different zone-resolution code paths. A shared helper `resolve_zones_from_tags(tags)` would prevent future drift.

---

## D. Trust check timing — EdgeGuard self-laundering + stale-UUID silent failure

**File:** `src/source_trust.py:323-379`, called from `src/source_truthful_timestamps.py:627`
**Class:** Security / trust-boundary

Critical operational gotcha: trust check runs on READ, not write. EdgeGuard's own collector writes land in MISP events whose `Orgc.uuid` is the EdgeGuard collector user's org. When those attributes are read back by sync, **`is_attribute_creator_trusted` is checked against EdgeGuard's OWN Orgc** — so EdgeGuard must allowlist itself or every source-truthful timestamp gets dropped.

If Orgc UUID rotates (MISP user re-created, allowlist not updated), every SOURCED_FROM edge silently gets NULL `source_reported_first_at` from that point. `source_truthful_creator_rejected_total` catches it, but operator alert rule isn't documented as mandatory.

**Impact on 730d baseline:** In prod/staging with misconfigured allowlist, fresh-baseline "completes successfully" but Neo4j silently loses all source-truthful timestamps.
**Proposed fix:** Boot-time warning escalates to ERROR when `EDGEGUARD_ENV=prod` AND Orgc rotation detected (self-check: MISP `/users/view/me` returns Orgc not in allowlist → refuse to start). This extends Tier 3 MISP defense plan.

*Related to §1 Finding 7 — treat these as one operator-facing issue.*

---

## E. Trust check + honest-NULL in sync_to_neo4j — working correctly

**File:** `src/run_misp_to_neo4j.py:2113-2118` + `src/neo4j_client.py` (merge_indicators_batch)
**Class:** Verification

Flow is correct: `extract_source_truthful_timestamps` returns `(None, None)` on rejection → `parse_attribute` stamps `item["first_seen_at_source"] = None` → `merge_indicators_batch` passes NULL → Cypher ON CREATE sets NULL → IOC STILL ingested, SOURCED_FROM edge created, `r.imported_at = datetime()` stamped, `r.source_reported_first_at` stays NULL. Matches honest-NULL doctrine. ✅

UPDATE path: `CASE WHEN item.first_seen_at_source IS NULL THEN r.source_reported_first_at ELSE ... END` — NULL reject PRESERVES any pre-existing trusted value. Correct.

---

## F. STIX-export vs Cypher-sync path emits DIFFERENT IOC counts — real bug

**File:** `src/run_misp_to_neo4j.py:1408-1562` (`_attribute_to_stix21`) vs `2040+` (`parse_attribute`)
**Class:** Cross-component contract

These are parallel readers of MISP attributes. They diverge on several edge cases. See the **Attribute-Type Round-Trip Table** below.

**Three desync rows:**

1. **`email-dst`** — STIX export wraps as indicator pattern; sync treats identically to email-src. Minor.
2. **`text` branches** — STIX emits nothing for non-MITRE text; sync creates an `unknown` Indicator. Silent.
3. **`filename`/`regkey`/`mutex`/`yara`/`sigma`/`snort`/`btc`** — sync stores as Indicators; STIX export drops them entirely. **Operators reading via `/stix21` get fewer IOCs than via `/graphql`.**

**Impact:** ResilMesh export fidelity degrades silently. Not a 730d-stability issue but a data-surface issue.
**Proposed fix:** Shared dispatch helper `attr_type_to_dispatch(attr_type, value)` → one source of truth for "what type is this?", consumed by both `_attribute_to_stix21` and `parse_attribute`. Or at minimum: document the known desyncs in `docs/RESILMESH_INTEROPERABILITY.md`.

---

## G. Partial-batch-failure accounting inconsistent across buckets

**File:** `src/run_misp_to_neo4j.py:2775-2900, src/neo4j_client.py:2138`
**Class:** Error-recovery accounting

`_sync_to_neo4j_chunk` batches ONLY indicators. Malware/actors/tools/tactics/techniques/CVEs iterate per-item. One bad malware fails just that malware. One bad indicator in sub-batch fails the WHOLE sub-batch (BATCH_SIZE items lost).

**Proposed fix:** Add metric `edgeguard_sync_partial_batch_failures_total{bucket=...}` so operators see "lost 500 indicators to one bad row" case.

---

## H. Rate-limit × retry composition — real risk of 45-attempt explosion per IOC

**File:** `src/collectors/misp_writer.py:588, 1619` + collector + Neo4j layers
**Class:** Retry composition (same class as §1 Finding 6 but deeper analysis)

`_push_batch` has `@retry_with_backoff(max_retries=4, base_delay=10.0)` STACKED ABOVE `@rate_limited(max_per_second=2.0)`. Decorator order: `rate_limited` innermost → every retry re-enters rate-limiter's sleep.

Collector → MISPWriter → Neo4j stacks:
- Collector: `retry_with_backoff(3)` around fetch
- MISPWriter: `retry_with_backoff(4)` around push
- Neo4j: `retry_with_backoff(3)` around merge

Worst case 3 × 5 × 3 = **45 attempts per IOC**. Empirically rare (failures uncorrelated across layers), but if MISP goes into multi-minute brownout, retry cost explodes into hours with no surface signal except slowness.

**Proposed fix:** Global retry budget per request chain; jittered backoff; centralized retry metric.

---

## I. `_sync_single_item` fallthrough has no Prometheus counter

**File:** `src/run_misp_to_neo4j.py:2749`
**Class:** Observability gap

Items not matching any bucket fall through to `_sync_single_item`. Today, parse_attribute sets one of the matchable fields, so fallthrough is unreachable via the main path. But any third-party code path (ad-hoc tests, manual ingests) can reach it. **No Prometheus counter** on fallthrough — if a new attribute type starts silently missing routing, only shows in error log.

**Proposed fix:** Add `sync_fallthrough_total{item_type=...}` counter.

---

## J. SOURCED_FROM edge provenance — TWO gaps

**File:** `src/neo4j_client.py` (merge_indicators_batch at lines 1400+)
**Class:** Data-model completeness

Edge carries: `imported_at`, `updated_at`, `confidence`, `source`, `edgeguard_managed`, `src_uuid`, `trg_uuid`, `source_reported_first_at`, `source_reported_last_at`, `raw_data`.

**Gap 1:** `misp_event_ids[]` accumulation lives on the NODE, not the edge. Can't query "which MISP events did NVD specifically report this IOC in" because node accumulates union across all sources.

**Gap 2:** `raw_data` set only on CREATE (line 2100), never on UPDATE. Frozen at first-sighting per edge. If NVD re-reports with newer CVSS, edge's `raw_data` stays old. Node scalars update, edge audit-trail doesn't.

**Proposed fix:** Move `misp_event_ids` to edge (list union on MERGE). Decide + document whether `raw_data` freeze is intentional.

---

## K/L. Rate-limit retry multiplication, source registry alias resolution — verified correct-with-caveat

Alias resolution: ALL key derivations share `_REGISTRY` (source_registry.py). Alias collision guard at import (line 455). MISPWriter's `f"source:{source}"` fallback is a divergent cache key for un-registered tags — correct behavior but bypasses `source_to_misp_tag_map` if a mis-typed alias is used. Edge case triggered only by new-source rollout bugs.

---

## M. Neo4j MERGE+SET under concurrent writers — mostly safe, one TOCTOU

**File:** `src/neo4j_client.py:1248, 2072+`
**Class:** Concurrent MERGE semantics

`MERGE (n:Indicator {indicator_type, value})` then `SET n.confidence_score = CASE ... END`. Two concurrent writers: Neo4j write-lock serializes. MIN/MAX safe. `n.zone` uses `apoc.coll.toSet` → safe.

But `confidence_score` CASE is **last-write-wins under tied values** — slightly-lower-confidence late arriver no-ops. AUDIT log at line 1248 ("AUDIT: Skipping lower-confidence update") runs as SEPARATE query BEFORE merge → under concurrency, audit decision can be inconsistent with final write (TOCTOU). Benign for logging; would be real if code acted on the check.

---

## What's handled well

- **PR-F7 partial-keyset break semantics** (misp_writer.py:457, 467, 479, 488) — transient errors degrade to partial cross-event dedup, not full drop. Log explicit.
- **Cross-process file lock on event creation** (`_cross_process_event_creation_lock`, line 164) — prevents Airflow LocalExecutor race on `EdgeGuard-{source}-{date}` creation
- **Honest-NULL across the seam** — `first_seen_at_source=None` flows cleanly through batch Cypher; MIN CASE preserves prior legitimate values
- **Defensive source_id pre-validation** (neo4j_client.py:1938, 2176) — refuses heterogeneous batches, prevents silent orphan nodes
- **Canonical merge-key coercion** (line 1988) — lowercased IPs/hashes/domains prevent case-mismatch double-node bug
- **`_event_id_exact_from_restsearch_rows`** (line 150) — substring `info:` filter match could grab wrong event; exact filter guards
- **UUID allowlist validation** (source_trust.py:136) — misconfigured non-UUID entries dropped with WARN, not treated as matches
- **Retry subclassing** — `MispTransientError` inherits `TransientServerError` inherits `HTTPError`; decorator retries 5xx but not 4xx
- **Parent-DAG liveness callback** (line 1560) — orphan collector detection between batches
- **Attribute size cap** (line 2077) — rejects >4KB MISP values with configurable override

---

## Attribute-type round-trip table

| MISP attr `type` | STIX-export branch | `parse_attribute` item type | `_sync_chunk` bucket | Neo4j merge method | Flag |
|---|---|---|---|---|---|
| `ip-dst`/`ip-src`/`ipv4` | `ipv4-addr` SCO | `indicator_type="ipv4"` | indicators | `merge_indicators_batch` | OK |
| `ipv6` | `ipv6-addr` SCO | `indicator_type="ipv6"` | indicators | `merge_indicators_batch` | OK |
| `domain`/`hostname` | `domain-name` SCO | `indicator_type="domain"` | indicators | `merge_indicators_batch` | OK |
| `url` | `url` SCO | `indicator_type="url"` | indicators | `merge_indicators_batch` | OK |
| `md5`/`sha1`/`sha256`/`sha512` | `file` SCO with `hashes` | `indicator_type="hash"` | indicators | `merge_indicators_batch` | OK |
| `email-src` | `email-addr` SCO | `indicator_type="email"` | indicators | `merge_indicators_batch` | OK |
| `email-dst` | **no branch** → indicator pattern default | `indicator_type="email"` | indicators | `merge_indicators_batch` | **Minor desync** |
| `vulnerability` | `vulnerability` SDO | `type="vulnerability"` | vulnerabilities | `merge_cve` | OK |
| `threat-actor` | `threat-actor` SDO | `type="actor"` | actors | `merge_actor` | OK |
| `malware-type` | `malware` SDO | `type="malware"` | malware_items | `merge_malware` | OK |
| `text` (T####) | `attack-pattern` SDO | `type="technique"` | techniques | `merge_technique` | OK |
| `text` (S####) | `tool` SDO | `type="tool"` | tools | `merge_tool` | OK |
| `text` (TA####) | `x-mitre-tactic` (PR-G1 fix) | `type="tactic"` | tactics | `merge_tactic` | OK |
| `text` (other) | returns None | else → indicator `type="unknown"` | indicators | `merge_indicators_batch` | **DESYNC** — STIX drops, sync creates silent unknown |
| `filename`/`regkey`/`mutex`/`yara`/`sigma`/`snort`/`btc` | `_value_to_stix_pattern` returns None → **drops** | `indicator_type=<mapped>` | indicators | `merge_indicators_batch` | **DESYNC** — sync stores, STIX drops. `/stix21` consumers get fewer IOCs than `/graphql` |

**Three desync rows.** The `text`-fallthrough and `filename/...` rows affect ResilMesh export fidelity.
