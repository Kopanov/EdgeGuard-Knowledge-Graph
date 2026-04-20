# Flow Audit §4 — Timestamps & Date-Handling End-to-End

**Date:** 2026-04-20 afternoon
**Scope:** Every timestamp / date field from collector source → MISP attribute → Neo4j property → STIX export
**Goal:** Find every date-handling bug that would corrupt historical data during a 730-day baseline run

---

## FINDING 1 [HIGH] — NVD `published` timestamps are naive (no TZ) → Neo4j reads them as server-local, not UTC

**File:** `src/source_truthful_timestamps.py:436-449` (consumer), `src/collectors/nvd_collector.py:877,882` (producer)
**Class:** A (timezone loss), B (format drift)

NVD API 2.0 returns `published` and `lastModified` as ISO-8601 strings **without** offset/Z suffix, e.g. `"2023-05-09T15:15:10.897"`. `coerce_iso`'s full-string branch at line 436-449 validates via `datetime.fromisoformat()` but only appends `T00:00:00+00:00` in the **10-char date-only** branch (line 435). For full NVD strings it returns `s` unchanged — TZ-less. That string is then passed to Neo4j's Cypher `datetime($...)`, which parses TZ-less input as **LocalDateTime** in the server's timezone, not UTC. When the DB server is not UTC, every NVD `source_reported_first_at` on the 2-year baseline is shifted by the server-local offset.

**730d impact:** Every CVE ingested via NVD during the 730-day window has its published-date shifted by the Neo4j server's local UTC offset (e.g. 5h off in an `America/New_York` deployment). MIN/MAX comparisons against tz-aware ThreatFox/CISA claims sort wrong.

**Fix:** In `coerce_iso`'s full-string branch, after `fromisoformat(normalized)`, if `parsed.tzinfo is None`, return `parsed.replace(tzinfo=timezone.utc).isoformat()` instead of the raw string — analogous to what `_stix_ts` already does (lines 145-147).

**Regression test:** Feed `"2023-05-09T15:15:10.897"` through `coerce_iso`, assert the return ends in `+00:00` or `Z`.

---

## FINDING 2 [HIGH] — MISP `Event.date` is stamped "today", not the attribute's first-seen

**File:** `src/collectors/misp_writer.py:1386`, `src/collectors/misp_writer.py:605`
**Class:** G (Event.date vs Attribute.timestamp)

In `push_items`, every item is grouped by `date = datetime.now(timezone.utc).strftime("%Y-%m-%d")` and `_get_or_create_event` uses this for the MISP event's `date` field. So a CVE-2013 indicator ingested during a 730-day baseline sits inside a MISP event named `EdgeGuard-nvd-2026-04-20` with `Event.date = 2026-04-20`. The **manual STIX fallback** then reads `event_date = misp_event.get("date", ...)` and uses it as `created` / `modified` on STIX Report objects. Consumers see today's date for 13-year-old CVEs.

**730d impact:** Every STIX Report produced via the manual-fallback path reports today as creation date for 2 years of historical indicators — corrupting the timeline ResilMesh consumers cache.

**Fix:** Derive `date` from `item.get("first_seen")` before falling back to today. In `_manual_convert_to_stix21` normalize `event_date` through `_stix_ts`.

**Regression test:** Push an item with `first_seen="2013-05-01T00:00:00Z"`; assert MISP event's `date == "2013-05-01"` and STIX Report `created` is in 2013.

---

## FINDING 3 [HIGH] — STIX manual-fallback uses raw MISP `Attribute.timestamp` (Unix epoch int) as ISO string

**File:** `src/run_misp_to_neo4j.py:1316`, used at `1592-1597`
**Class:** B (format drift), F (downstream crash)

`_attribute_to_stix21` does `timestamp = attr.get("timestamp", datetime.now(timezone.utc).isoformat())` and uses that value verbatim as STIX 2.1 `created`, `modified`, `valid_from`. MISP's `Attribute.timestamp` is a **Unix epoch integer** (`"1716825600"`), not ISO-8601. Strict STIX validator rejects; lenient accepts nonsense. Absent → `datetime.now()` → today's wall-clock for historical indicators.

**730d impact:** Every STIX indicator via manual-fallback carries either raw epoch (validator rejects) or today's wall-clock (valid_from=today for 2-year-old indicators).

**Fix:** Run `attr.get("timestamp")` through `coerce_iso()` (handles int epoch → ISO): `_coerce_iso(attr.get("first_seen")) or _coerce_iso(attr.get("timestamp")) or now_iso`.

**Regression test:** Feed `{"timestamp": 1716825600}` to `_attribute_to_stix21`; assert `valid_from == "2024-05-27T16:00:00+00:00"`, not raw int.

---

## FINDING 4 [HIGH] — VirusTotal collector leaks wall-clock NOW into reliable-source first_seen

**File:** `src/collectors/vt_collector.py:404-409` and `523-528`
**Class:** D (NULL vs "now" ambiguity), E (MIN-pollution)

`first_seen_ts = attrs.get("first_submission_date", 0)` followed by `if first_seen_ts` means absent-or-zero produces `first_seen = datetime.now(timezone.utc).isoformat()`. VirusTotal **is on `_RELIABLE_FIRST_SEEN_SOURCES`**, so MISP's `first_seen` is trusted and flows into `r.source_reported_first_at`. MIN-CASE pins today's wall-clock as "VT first saw this" forever.

**730d impact:** Every VT record missing `first_submission_date` gets "first seen=today" for the entire baseline run — permanently anchoring `MIN(r.source_reported_first_at)` at baseline day 1.

**Fix:** Mirror AbuseIPDB blacklist pattern — omit `first_seen` when absent instead of wall-clock-NOW fallback.

**Regression test:** Process VT row with `first_submission_date=0`; assert returned item has no `first_seen`, and `extract_source_truthful_timestamps` returns `(None, None)`.

---

## FINDING 5 [HIGH] — OTX pulse `created` passed as `first_seen` with wall-clock NOW fallback

**File:** `src/collectors/otx_collector.py:440,482`; `src/collectors/misp_writer.py:87-91`
**Class:** D, E

OTX emits `"first_seen": pulse.get("created", datetime.now(timezone.utc).isoformat())`. `_apply_source_truthful_timestamps` forwards `first_seen` unconditionally — does not check `is_reliable_first_seen_source`. OTX is correctly excluded on READ side today, but: (a) if operator adds OTX to allowlist, wall-clock-NOW immediately poisons every IOC missing `pulse.created`; (b) MISP attribute already carries the lie — any non-EdgeGuard consumer reads wall-clock "first_seen" as truth.

**730d impact:** Any MISP consumer other than EdgeGuard's sync (ResilMesh, SIEM bridge) reads today's date as first-seen for 2y of OTX-relayed IOCs.

**Fix:** Drop `datetime.now(...)` fallback — use `pulse.get("created") or None`, let `coerce_iso` turn None into skip.

**Regression test:** Ingest OTX pulse with no `created` field; assert MISP attribute has no `first_seen` key.

---

## FINDING 6 [MEDIUM] — `SECTOR_TIME_RANGES` windowing uses `months * 30` days — 10-day drift over 24 months

**File:** `src/config.py:90`; `src/collectors/nvd_collector.py:847`; `src/collectors/otx_collector.py:407`
**Class:** C (windowing off-by-one)

`cutoff = datetime.now(tz.utc) - timedelta(days=months * 30)`. For `months=24`, cutoff is 720 days back; true 2-year semantics want 730 or 731. On a 730-day baseline, NVD/OTX per-item sector filter drops CVEs published in the 10-day shoulder at oldest end.

**Fix:** Change `SECTOR_TIME_RANGES` semantics to `_days` and store `730`; or compute `timedelta(days=int(months * 30.437))`.

---

## FINDING 7 [MEDIUM] — `_event_covers_since` compares `Event.date` as `date` (not datetime) — drops 3 hours at window boundary

**File:** `src/run_misp_to_neo4j.py:165-166`
**Class:** C (off-by-one)

Comparing dates instead of datetimes means events on `since.date()` are included regardless of partial-day. But parent call `since = now - timedelta(days=N)` at 03:00 UTC → `since.date() == (now - N).date()`, losing 3 hours at window floor per incremental run. Cumulative 2280 hours over 730d.

**Fix:** Widen boundary by 1 day: `ev_day.date() >= (since - timedelta(days=1)).date()`.

---

## FINDING 8 [MEDIUM] — `_clamp_future_to_now` defaults unparseable strings to pass-through

**File:** `src/source_truthful_timestamps.py:294-318`
**Class:** B, F

If `coerce_iso`'s output is still naive (Finding 1 unfixed), `_clamp_future_to_now` applies `replace(tzinfo=timezone.utc)` — inconsistent with whatever Neo4j does downstream (server-local). Silent inconsistency between clamp path and Cypher parse.

**Fix:** Fix Finding 1; clamp path then has no naive case.

---

## FINDING 9 [MEDIUM] — OTX incremental resume reuses last-modified without tz-safety

**File:** `src/collectors/otx_collector.py:321-332`
**Class:** C, E

`base_dt = datetime.fromisoformat(stored.replace("Z", "+00:00"))` succeeds even if `stored` is naive; subtracting `timedelta(seconds=OVERLAP)` from naive vs tz-aware drifts silently across checkpoint writer/reader versions.

**Fix:** `if base_dt.tzinfo is None: base_dt = base_dt.replace(tzinfo=timezone.utc)`.

---

## FINDING 10 [LOW] — Manual STIX uses YYYY-MM-DD `Event.date` as STIX `created`/`modified` — not a valid STIX timestamp

**File:** `src/run_misp_to_neo4j.py:1242,1274-1275`
**Class:** B, J (precision loss)

STIX 2.1 §3.2 requires timestamp with time + Z-suffix. MISP `Event.date` is date-only. Strict validators reject; mixed formats confuse chronological sort.

**Fix:** Wrap through `_stix_ts(coerce_iso(event_date))`.

---

## FINDING 11 [LOW] — `parse_attribute` computes `last_updated` from MISP epoch but Cypher never reads it

**File:** `src/run_misp_to_neo4j.py:2247,2338,2405,2469,2508,2583,2681`
**Class:** J (dead plumbing masking a future bug)

Every parse_attribute branch stuffs `"last_updated": _coerce_to_iso(attr.get("timestamp"))`. But `merge_indicators_batch` sets `n.last_updated = datetime()` server-side unconditionally — never reading `item.last_updated`. Dead key. Latent trap if a future reader adds `SET n.last_updated = $last_updated` thinking it's pre-computed correctly.

**Fix:** Delete the dead key.

---

## What's handled well

1. **`datetime.now()` discipline** — every call site passes `timezone.utc`; no `utcnow()`, no naive `now()`
2. **Server-side node timestamps** — `n.first_imported_at = datetime()` (ON CREATE) and `n.last_updated = datetime()` (every MERGE) via Cypher's server-side function. Single clock source
3. **Edge MIN/MAX CASE semantics with NULL-guards** (`neo4j_client.py:2103-2124, 2296-2317`) — correct handling of all four cases: both-null, either-null, regression, first-write
4. **NVD 120-day window iterator** correctly walks newest-first, clamps at `now`, never exceeds NIST limit
5. **`coerce_iso` sentinel rejection** — rejects epoch-0, negatives, overflow
6. **`_stix_ts` non-UTC offset normalization** — parses and re-emits as Z form
7. **STIX custom-property envelope** — uniformly attaches `x_edgeguard_first_seen_at_source` / `x_edgeguard_first_imported_at` across all SDO types
8. **AbuseIPDB blacklist honest-NULL** — reference pattern (lines 410-428)
9. **`extract_source_truthful_timestamps` allowlist gate** — OTX / CyberCure / plain MISP correctly rejected on READ side
