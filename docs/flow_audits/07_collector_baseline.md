# Flow Audit §7 — Per-collector Baseline Correctness

**Date:** 2026-04-20 afternoon
**Scope:** Each of 12 collectors + 4 sector feeds on baseline=True path
**Goal:** 730-day baseline completes without silent data loss

---

## HIGH — H1. OTX baseline: `max_pages=200` silently caps at ~10k pulses

**File:** `src/collectors/otx_collector.py:291`

`_fetch_pulses(limit=limit)` sends global incremental cap as OTX `limit=` per page. Combined with `max_pages = 200` hardcoded (line 291), total possible = `limit_param * 200`. Default `resolve_collection_limit` returns `None` in baseline → `_fetch_pulses` substitutes `params["limit"] = limit or 50` (line 204) → baseline fetches **at most 200 × 50 = 10 000 pulses**. OTX typically 20-40 pulses/day × 730 = 15-30k. Anything past ~10k silently dropped.

**Fix:** Per-page `limit=50` hard, `max_pages = int(os.getenv("EDGEGUARD_OTX_BASELINE_MAX_PAGES", "2000"))`, drop `limit` kwarg from `_fetch_pulses` in baseline.

---

## HIGH — H2. OTX baseline has zero checkpoint resume

**File:** `src/collectors/otx_collector.py:280-307`

Comment: "No page-based checkpoint — OTX pagination is unstable across different time windows." True, but 730d run is ~30-40 min; crash at page 180/200 restarts at page 1.

**Fix:** Store `(baseline_modified_since, last_completed_page)` in `baseline_otx_*` sub-key; resume iff window matches. Minimally: log operator-visible "starting from scratch" warning.

---

## HIGH — H3. NVD incremental-limit leaks into baseline — 99% silent data loss

**File:** `src/collectors/nvd_collector.py:618`

After baseline window loop accumulates `all_cves`, line 618 does `vulnerabilities = all_cves if limit is None else all_cves[:limit]`. If operator sets `EDGEGUARD_BASELINE_COLLECTION_LIMIT=200` (copy-paste from incremental), baseline collects millions across 12 windows then **truncates to 200**. Collector "succeeded", MISP gets 200 CVEs, ≥99% silently discarded.

**Fix:** In baseline branch, honor separate `BASELINE_NVD_MAX` env but NEVER inherit incremental limit — if present, warn loudly.

**Regression test:** `EDGEGUARD_BASELINE_COLLECTION_LIMIT=200` + baseline=True + 10k mocked CVEs → assert returned count is 10k OR warning emitted.

---

## HIGH — H4. CISA baseline_days filter used as string compare

**File:** `src/collectors/cisa_collector.py:210-211`

`cutoff_date = ... .strftime("%Y-%m-%d")`; `v.get("dateAdded", "") >= cutoff_date`. If KEV entry has `"dateAdded": ""`, `"" >= "2024-04-20"` is False → entry silently dropped. Missing/malformed `dateAdded` → **silently lost, not logged**.

**Fix:** try/except ISO parse + bucket `skipped_malformed_date` counter logged at end.

---

## HIGH — H5. OTX baseline `limit` truncation before dedup

**File:** `src/collectors/otx_collector.py:357`

After fetching, `to_process = pulses if limit is None else pulses[:limit]`. Each pulse emits many items (indicators + CVEs + malware + actor). Truncating PULSES to `limit` means one limit-pulse may emit 100 items while 10 high-value following pulses are dropped.

**Fix:** In baseline mode, raise loud warning if `limit` not None; only truncate `processed` by item-count.

---

## HIGH — H6. VT `collect()` in baseline forces `limit = 20`

**File:** `src/collectors/vt_collector.py:588` (+ `virustotal_collector.py:86`)

`if limit is None: limit = 20`. When baseline passes `limit=None, baseline=True`, default truncates to 20 items → `min(limit // 2, 10)` = 10 files + 10 URLs. 730d VT baseline retrieves **20 indicators total**, regardless of days.

**Fix:** Baseline mode uses separate ceiling `EDGEGUARD_VT_BASELINE_MAX=2000` OR document VT is enrichment-only.

---

## HIGH — H7. Energy + Healthcare feeds in baseline are silent no-ops

**File:** `src/collectors/energy_feed_collector.py:100`, `healthcare_feed_collector.py` similar

`collect()` signature `(limit=None, push_to_misp=True)` — **no `baseline` / `baseline_days` kwargs**. `run_pipeline.py:1320` inspects signatures, falls to else branch at 1334, calls `collector.collect(limit=effective_limit)`. Baseline logs "collected 0 items" and operator never knows it was a placeholder.

**Fix:** Placeholders return `make_skipped_optional_source("energy_placeholder", skip_reason="not_implemented", skip_reason_class="placeholder")` so they appear on skip dashboard, not zero-count.

---

## HIGH — H8. ThreatFox baseline: `days` param has undocumented cap

**File:** `src/collectors/global_feed_collector.py:99, 137`

Baseline sends `{"query": "get_iocs", "days": 730}`. abuse.ch docs: public endpoint accepts `days` up to 7 (free) / 30 (registered). 730 either returns max window or `query_status=illegal_days`. Collector handles `query_status != "ok"` as failure (line 168), but IF abuse.ch silently clamps, baseline reports `success=True count=<30d>` — operators don't realize they got 30 days instead of 730.

**Fix:** Iterate 30d windows via `search_ioc` endpoint OR warn that ThreatFox baseline is capped at API max.

---

## MEDIUM — M1. Wall-clock `last_updated` in collectors

Multiple files: `otx_collector.py:441,483`; `abuseipdb_collector.py:361,438`; `global_feed_collector.py:466,655,668,688`; `finance_feed_collector.py:125,239`

Every indicator sets `"last_updated": datetime.now(timezone.utc).isoformat()`. Push-time wall-clock is local sync metadata, not `last_seen_at_source`. Plausibly misread downstream by `parse_attribute`.

**Fix:** Rename key to `synced_at` OR drop entirely if MISP push already timestamps.

---

## MEDIUM — M2. Feodo / SSLBL / URLhaus — limit applied before filtering invalid rows

**Files:** `finance_feed_collector.py:93`, `global_feed_collector.py:423`

`for i, line in enumerate(lines[1:]): if limit is not None and i >= limit: break`. First N malformed rows → collector processes 0 items. Fix: increment `i` only on successful parse.

---

## MEDIUM — M3. CyberCure has no intra-run dedup

**File:** `src/collectors/global_feed_collector.py:692`

Same IP may appear in both ip and hash feeds with different `indicator_type` but identical `value`. MISP upsert handles it, but dedup metric wrong.

**Fix:** Add `seen` set keyed on `(indicator_type, value)`.

---

## MEDIUM — M4. NVD `_fetch_cves` incremental-mode silent 120-day cap

**File:** `src/collectors/nvd_collector.py:292-295`

`max(SECTOR_TIME_RANGES.values())` then `clamp_nvd_published_range` silently caps at 120d without iterating prior windows. Incremental runs with 24-month desired window get 120 days. Not baseline, but trap.

**Fix:** Document prominently.

---

## MEDIUM — M5. MITRE ETag reuse in baseline mode

**File:** `src/collectors/mitre_collector.py:142`

Baseline ignores ETag, but WRITES `new_etag` (line 509, 519). Crashed baseline with etag written but items not pushed → next incremental gets 304, sees no new data.

**Fix:** Only write ETag when `push_items` returned `success > 0 and failed == 0` in baseline.

---

## MEDIUM — M6. Retry budget multiplication

All collectors: `retry_with_backoff(max_retries=3)` + `request_with_rate_limit_retries(max_rate_limit_retries=3, fallback_delay_sec=60.0)`. Inner up to 420s, outer ×4 → **28 min worst case per HTTP call**. One MISP outage eats hours.

**Fix:** Cap total wall-time budget per call via `deadline_seconds`.

---

## MEDIUM — M7. Circuit-breaker `failure_threshold=3` too strict for 730d

NVD CB opens on 3 consecutive failures during ~40-min baseline, aborts entire 730d run, `recovery_timeout=3600` blocks retry for an hour.

**Fix:** For baseline, bypass CB OR higher threshold OR re-close on partial-batch success (NVD already does at line 641).

---

## MEDIUM — M8. NVD baseline — resume dedup doesn't persist `seen_cve_ids`

**File:** `src/collectors/nvd_collector.py:499, 555-557`

Fresh in-memory set per `collect()` invocation. Crash at window 7/12 resumes with empty set — boundary CVEs re-emitted. MISP dedup saves correctness but inflates `success`/`failed` counts and network cost.

**Fix:** Persist `seen_cve_ids` to checkpoint as list.

---

## MEDIUM — M9. OTX `successful_pulse_ids` lookup is O(N*M)

**File:** `src/collectors/otx_collector.py:592`

`[p for p in pulses if p.get("id") in successful_pulse_ids]` on 10k pulses × 50k items = millions of comparisons. Not correctness, performance.

**Fix:** Pre-index `pulses` by id.

---

## MEDIUM — M10. `misp_collector.py` has no `baseline` parameter

**File:** `src/collectors/misp_collector.py:144`

`def collect(self, limit=None):` — no baseline. Falls into incremental branch regardless of `--baseline`. Meta-MISP 730d baseline silently wrong.

**Fix:** Add `baseline, baseline_days` kwargs + propagate via `?from=<date>`.

---

## LOW — Hygiene

- **L1.** `requests.Session` leaks on exception — otx/misp/vt/abuseipdb/virustotal collectors. Fix: context manager or finally-close.
- **L2.** `MITRE_MAX_RELATIONSHIPS` reads env at import time, runtime changes ignored.
- **L3.** Feodo CSV parser `split('","')` fragile.
- **L4.** SSLBL CSV no column contract check.
- **L5.** OTX `pulse_tags[:20]` truncation at emission time — zone-relevant tags lost.
- **L6.** CISA + Feodo + SSLBL don't emit `items_skipped` in status.

---

## What's handled well

- **NVD post-PR-G1 checkpoint/resume** — atomic advisory-locked writes, monotonic batch counter, `nvd_window_idx` + `nvd_start_index` survive crashes correctly
- **NVD 120-day window iteration** (`iter_nvd_published_windows`) — provably correct, walks newest-first, inclusive bounds
- **Rate-limit adaptation with/without API key** — `batch_sleep = 0.7 if api_key else 6.5` matches NIST spec
- **Optional-source skip semantics** — `make_skipped_optional_source` + `run_collector_with_metrics` consistently avoid failing DAG on missing keys
- **URLhaus all-mirrors-down detection** — silent-zero-count → explicit FAILURE
- **Corrupt-checkpoint forensic backup** — `load_checkpoint` preserves as `.corrupt.<ts>`
- **OTX incremental cursor advancement** — `to_process` vs `pulses` fix at line 555 closes incremental-limit data-loss
- **Redirect-follow disabled by default** — prevents SSRF via redirect abuse

**Top priority before real 730d run: H1, H3, H6, H7, H8** — all cause silent >90% data loss.
