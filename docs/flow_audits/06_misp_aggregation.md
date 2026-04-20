# Flow Audit §6 — MISP Aggregation + Attribute Dedup

**Date:** 2026-04-20 afternoon
**Scope:** `src/collectors/misp_writer.py`, `src/run_misp_to_neo4j.py` index-side fetch, `src/source_registry.py`, `src/config.py` SOURCE_TAGS
**Goal:** At 730d scale (~500K-1M attrs over ~50-200 events), no duplicates, no silent truncation, no partial-failure aborts

---

## HIGH — H1. `push_items` groups items on wall-clock `now()`, ignoring item date

**File:** `src/collectors/misp_writer.py:1384-1390`

```python
for item in items:
    source = item.get("tag", "unknown")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = (source, date)
```

`date` is re-computed per iteration but is always `now().date()` — item's `first_seen` / `published` / `date` is **never consulted**. Consequences:

1. **Event-name collision on day-rollover mid-push.** Baseline at 23:58 UTC shards items into `EdgeGuard-nvd-2026-04-19` then `EdgeGuard-nvd-2026-04-20`. Cross-event cache is keyed by resolved source_tag and dedupes across them, BUT the cache was prefetched *before* the push — items moved to the new event after midnight were NOT in prefetch → duplicate attributes split across two events.
2. **Baseline rerun next day** creates event #2 for same logical content. Cross-event dedup saves you *if* prefetch succeeded (H3 below otherwise).
3. **Issue #61's architectural note** "partition by attribute date, not push date" is acknowledged in docstrings — no code path honors `item["first_seen"]` for bucketing. This is the root cause of the NVD event-19/event-20 72k duplication PR-F7 papers over.

**Fix:** Bucket by item's own date: `date = _coerce_item_date(item) or datetime.now(timezone.utc).strftime("%Y-%m-%d")`. Hoist `datetime.now(...)` out of per-item loop.

**Regression test:** Feed items with `first_seen` spanning 3 days → assert exactly 3 `(source, date)` groups; pre-midnight → post-midnight wall-clock advance does NOT create second event.

---

## HIGH — H2. Large-event split is never performed by the writer

**File:** `src/collectors/misp_writer.py:1344-1617`

`EDGEGUARD_MAX_EVENT_ATTRIBUTES` is only consulted on the READ side (`run_misp_to_neo4j.py:3405`) to defer oversize events on sync. **`push_items` has no split-off logic**: NVD pushing ~95k attrs to one event just piles them on. MISP's per-event edit handler chokes (observed 22% HTTP 500 on 730d NVD baseline). `@retry_with_backoff` retries the same overloaded event forever until terminal failure.

730d impact: once an event crosses ~20k mark, every subsequent batch's `attributes/restSearch` (per-event prefetch) paginates through a larger set — O(N²) degrade.

**Fix:** After `_get_or_create_event`, if `len(per_event_keys) + len(unique_attrs) > MAX_EVENT_ATTRIBUTES`, allocate suffixed event name (`EdgeGuard-nvd-2026-04-19-part2`) and migrate overflow. **Atomic:** create overflow event BEFORE writes to part1, so crash leaves complete part1 + empty part2 (recoverable), not overflowing part1 with lost items.

**Regression test:** Monkeypatch `_get_existing_attribute_keys` returns 19_999 keys; push 500 new → assert second event created with exactly the overflow.

---

## HIGH — H3. Cross-event dedup is fail-open (PR-F7) but per-event prefetch is NOT

**File:** `src/collectors/misp_writer.py:548-552`

```python
except _TRANSIENT_HTTP_ERRORS:
    raise
except Exception as ex:
    logger.warning("MISP attributes/restSearch failed for event %s page %s: %s", ...)
    break
```

Sibling cross-event prefetch (line 427-457) was hardened in PR-F7 rounds 3-4 to fail-open on transient errors (break instead of raise). Per-event prefetch **still re-raises** transient errors. `_get_existing_attribute_keys` has no retry decorator; `push_items` has no try/except at line 1459. Transient ReadTimeout on page 12 of a 20-page NVD prefetch propagates → crashes `push_items` → aborts entire source push.

730d impact: NVD's ~19-page prefetch encounters ~1 flake per full run under MISP memory pressure. Single flake bombs entire NVD collector — exactly the failure mode PR-F7 round-3 fixed for cross-event but never backported here.

**Fix:** Apply identical partial-keyset preservation pattern from `_get_existing_source_attribute_keys`. Treat transient + permanent symmetrically on break.

**Regression test:** MISP mock raising `ConnectionError` on page 5; assert caller sees keys from pages 1-4 and continues push (currently unhandled exception propagates).

---

## HIGH — H4. `restSearch` for event discovery has `limit: 50`, no pagination — exact-match hit can be past page 1

**File:** `src/collectors/misp_writer.py:349-366`

`json={"returnFormat": "json", "info": event_name, "limit": 50}` — substring-match restSearch can return many rows with `info` containing that string. If operator appends `-backup`/`-retry` suffixes (or MISP fulltext treats `-` as word break), exact-match row could be past index 49. `_event_id_exact_from_restsearch_rows` iterates rows given — no "fetch next page" loop. Miss → create duplicate event.

**Fix:** Paginate until exact hit found or exhausted, OR switch to exact-match endpoint (`eventinfo` with quoted strings on newer MISPs).

**Regression test:** Mock returns 50 near-miss rows page 1 + exact match page 2; assert found without duplicate.

---

## MEDIUM — M1. `_push_batch` retry can duplicate attributes in a large event

**File:** `src/collectors/misp_writer.py:1619-1702`

`@retry_with_backoff(max_retries=4, base_delay=10.0)` retries on 5xx. Scenario: batch POSTed, MISP writes ~400, handler crashes → 500. Retry #2 POSTs same 500. MISP's server-side dedup handles most collisions for `cve_id`, but **techniques/tactics/tools** (`value=f"{mitre_id}: {name}"`) differ if name changed between runs. More acute: `text` attrs with different comments after retry — side-by-side copies.

**Fix:** Before retry, call `_get_existing_attribute_keys(event_id)` and filter. Or cap `max_retries=2`.

---

## MEDIUM — M2. Tag attachment is one-shot — rejected tag drops whole batch silently

**File:** `src/collectors/misp_writer.py:1639-1646`

Attrs include `Tag` inline. MISP rejects entire batch with 400 on malformed tag. Line 1692 treats 4xx as permanent `errors += 1; return 0, len(attributes)` — the whole batch is counted failed but **no diagnostic names the offending tag**. Silent tag loss (some MISP patches strip unknown tags + accept attribute) destroys zone classification for that batch.

**Fix:** On 400 with tag-error body, retry batch once without offending tag OR per-attribute. Minimally: log body explicitly for `"Tag name ... does not exist"` patterns + Prometheus counter.

---

## MEDIUM — M3. `config.SOURCE_TAGS` legacy 7-key subset vs full alias-expanded map — grouping / tag can drift

**File:** `src/config.py:716` vs `src/collectors/misp_writer.py:292`

Legacy subset = 7 keys; writer full map = all aliases. Collector setting `item["tag"] = "feodo"` (alias, not in legacy subset):
- Grouping: `source = "feodo"` → bucket `("feodo", date)`
- Cache key: `SOURCE_TAGS.get("feodo", ...)` → `"source:Feodo-Tracker"` (works in writer)
- But upstream collector init doing `self.tag = SOURCE_TAGS["feodo"]` (legacy) raises KeyError → some collectors emit `tag="feodo"`, others `tag="feodo_tracker"` → two different `(source, date)` buckets → two different MISP events for same content.

**Fix:** Canonicalize `item["tag"]` at top of `push_items` via `source_registry.get_source(tag).canonical_id or tag`.

---

## MEDIUM — M4. Event-discovery pagination cap interacts with shared MISP instances

**File:** `src/run_misp_to_neo4j.py:119-125`

`500 × 100 = 50_000` events max. 2y × 365 × 12 sources ≈ 8_760 — fits. But index is ordered by MISP default (usually `id DESC`). Shared MISP with non-EdgeGuard events (ResilMesh partners) → EdgeGuard events interspersed. "50k" is total index rows, not EdgeGuard rows. Can trivially exhaust cap, silent EdgeGuard-tail truncation.

**Fix:** Use `events/restSearch` with `tags: ["EdgeGuard"]` server-side filter OR raise cap OR sanity-check: if `len(pages) == MAX × PAGE_SIZE`, WARN likely truncated.

---

## MEDIUM — M5. `coerce_iso` / `sanitize_value` truncates large rule bodies at 1024 bytes

**File:** `src/collectors/misp_writer.py:786`

`value = sanitize_value(value, max_length=1024)` — URL or YARA body > 1024 truncated to `...`-suffix prefix. 730d scale OTX pulses carry multi-kB snort/yara bodies. Truncated YARA is worse than no YARA (unparseable, won't dedup next sync's untruncated variant).

**Fix:** Route `yara` / `sigma` / `snort` through `comment` field (4000 char tolerance) + keep `value` as content-hash. Or raise `max_length` for rule types.

---

## LOW — L1. `_cross_process_event_creation_lock` shared global path

**File:** `src/collectors/misp_writer.py:177-181`

`/tmp/edgeguard_misp_get_or_create_event.lock` serializes every event-create globally across every source. Baseline (single-process) fine; 6 parallel Airflow DAGs = global bottleneck. Throughput tax, not correctness.

---

## LOW — L2. Rate-limiter + retry amplification

`_push_batch` decorated `@retry_with_backoff` → `@rate_limited(max_per_second=2.0)`. Each retry re-enters rate limiter. Under sustained 500s, effective push rate collapses to ~1/min.

---

## What's handled well

- **PR-F7 cross-event prefetch partial-keyset preservation** — transient + permanent both `break` and preserve. Round-4 solid.
- **PR-F7 cache-key resolution via resolved `source_tag`** — collapses alias-duplicates (cisa/cisa_kev) into one cache entry.
- **PR-F7 two-step dedup accounting** — per-event and cross-event skip counts attributable; old "counts exceed skipped_ct" gone.
- **PR-K2 `since` filter in `_event_covers_since`** — honors `timestamp` then `date`, permissive on missing fields.
- **Exact-info filter `_event_id_exact_from_restsearch_rows`** — `==` is strict (no startswith/contains).
- **Double-check pattern inside the lock** (line 635-639) — re-queries after acquiring, avoiding TOCTOU.
- **`source_registry.py` alias-collision validation at import time** — `_validate_no_alias_collisions()` catches at load.
- **`@retry_with_backoff` on `MispTransientError` subclass only** — permanent 4xx doesn't spin retries.
- **`_push_batch` failure isolation** — one bad event no longer aborts entire push queue.
