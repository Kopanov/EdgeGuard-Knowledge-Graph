# Collection & sync limits — what applies when

Several numbers (**200**, **500**) appear across EdgeGuard docs and code. They control **different stages** of the pipeline and are **not interchangeable**. Use this page to avoid mixing up “baseline cap per source” with “Neo4j merge chunk size” or “MISP event search page size”.

---

## Quick reference

| What | Where it applies | What is limited | How to change |
|------|------------------|-----------------|---------------|
| **`BASELINE_COLLECTION_LIMIT`** (+ **`EDGEGUARD_BASELINE_COLLECTION_LIMIT`** env override) | **`edgeguard_baseline` DAG**, **`run_pipeline.py` step 2** (external collectors only) | Maximum **items per source per run** for each **external** feed (OTX, NVD, CISA, MITRE, ThreatFox, …). **`0`** = unlimited. | Airflow **Admin → Variables**, or `.env` override on the worker |
| **`BASELINE_DAYS`** (+ **`EDGEGUARD_BASELINE_DAYS`**) | Same baseline paths | How far back **time-based** sources (e.g. NVD, OTX) look | Same as above |
| **`EDGEGUARD_INCREMENTAL_LIMIT`** (+ **`EDGEGUARD_MAX_ENTRIES`**) | Scheduled collector DAGs (`edgeguard_pipeline`, medium/low/daily, …) | Max **items per source per cron run** for external collectors. **`0`** = unlimited. The sources with their own per-run rule are listed below the table. | Environment on Airflow worker; not forwarded by `docker-compose.yml` (below) |
| **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** | **`run_misp_to_neo4j.sync_to_neo4j()`** (MISP → Neo4j) | Max **parsed graph items** merged **per Python chunk** into Neo4j (controls **worker RAM** during write). Default **`500`**. **`0`** / **`all`** = single pass (OOM risk). | Environment on Airflow worker |
| **`EDGEGUARD_REL_BATCH_SIZE`** | **`run_misp_to_neo4j._create_relationships()`** → **`Neo4jClient.create_misp_relationships_batch()`** | Max **relationship definitions** per Neo4j **UNWIND** batch. Default **`500`**. | Environment on Airflow worker |
| **MISP "EdgeGuard" event discovery** | **`run_misp_to_neo4j.fetch_edgeguard_events()`** | **Primary:** paginated **`GET /events/index`** (then **`/events`**) — lightweight rows **without** scanning all attributes (avoids **`restSearch`** timeouts on huge events). MISP 2.5.45 ignores **`limit`**, **`page`** and **`timestamp`** in the query string and answers the whole listing on every page; the listing de-duplicates rows by event id and stops at the first page with more rows than **`limit`** or with no new event id, so each event is processed once (without this, from 500 events on, each event would be processed once per page, up to the 100-page cap). A page after the first that fails ends the run: a timeout or a dropped connection re-runs the listing (4 retries) and then fails it with the `requests` error; any other failure raises `_MispFallbackHardError`. That MISP narrows by time only with a named **`searchtimestamp:`** or a request-body **`timestamp`** (a named **`timestamp:`** is ignored too), so the window is applied client-side. **Client-side filter:** **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) **or** **`org.name`** is **`EdgeGuard`**. Incremental runs also filter by **`timestamp`** / **`date`** when present. **Fallback:** PyMISP / **`POST /events/restSearch`** for event headers only (**`metadata`**), filtered with **`eventinfo`** `%<EDGEGUARD_MISP_EVENT_SEARCH>%` (MISP 2.4.177 or later; an older MISP answers every event) and then by the same client-side filter + **paginated** `_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200` (= 100K events safety cap). Cap-hit raises `_MispFallbackHardError` rather than silently truncating; so do a non-JSON page, a request error that is not a timeout or a dropped connection (recorded as `rest_search` / `hard_error`) and any other error while listing. Primary index env knobs: **`EDGEGUARD_MISP_PAGE_SIZE`** (default **500**), **`EDGEGUARD_MISP_MAX_PAGES`** (default **100**); a listing that stops at the cap fails the run, so the DAG keeps its cursor. | Code in **`src/run_misp_to_neo4j.py`** |
| **`MISPCollector`** (`src/collectors/misp_collector.py`) | Library code: no DAG or CLI step runs it (the baseline DAG does not use it, and `run_pipeline` step 2 excludes it, `k != "misp"`) | If invoked elsewhere: `GET /events?limit=` uses **`min(3 × resolved_limit, 2000)`** when limit is positive, else **`2000`**; max **`500`** attributes processed **per event**. Uses **`resolve_collection_limit(..., baseline=False)`** — it does **not** read **`BASELINE_COLLECTION_LIMIT`**. | Code constants + incremental / passed `limit` |
| **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** | **`MISPWriter`** (`src/collectors/misp_writer.py`) before **`push_items`** | If **true**, paginated **`POST …/attributes/restSearch`** on the **target** event builds a set of existing **`(type, value)`**; matching items are skipped (stat **`attrs_skipped_existing`**). | `.env` / worker env |
| **`EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`**, **`EDGEGUARD_MISP_REFRESH_MAX_PER_RUN`**, **`EDGEGUARD_MISP_REFRESH_MAX_SECONDS`** | **`MISPWriter.push_items()`** — indicators a collector run reports again that MISP already holds for their source | A stored copy (in an EdgeGuard event) that MISP last wrote more than the interval ago (default **30** days; **`0`** = off) gets one attribute edit that keeps the source's dates and makes MISP stamp it anew, so the incremental sync reads it again; at most **2,000** edits (**`0`** = no cap) and **600** s (**`0`** = no limit) per run, stopping after 5 failed edits in a row, the longest unwritten first (stats **`attributes_refreshed`** / **`attributes_refresh_failed`** / **`attributes_refresh_deferred`**). Feodo Tracker and SSL Blacklist report their whole list per run, AbuseIPDB at most 10,000 blacklist addresses, which AbuseIPDB chooses. See [COLLECTORS.md](COLLECTORS.md#re-reported-indicators). | `.env` (forwarded by `docker-compose.yml`) / worker env |
| **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**, **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**, **`EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES`** | **`otx_collector`** on **scheduled** (non-baseline) runs | **`modified_since`** window, overlap with last cursor, and max API pages; state in **`checkpoints[otx]["incremental"]`** (same JSON as baseline checkpoints). | `.env` / worker env |
| **`EDGEGUARD_MITRE_CONDITIONAL_GET`** | **`mitre_collector`** on **scheduled** (non-baseline) runs | **ETag** / **If-None-Match** on the STIX URL; **304** skips work. **Baseline** ignores this for a full refresh. | `.env` / worker env |
| **`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`** | **`MISPWriter.push_items()`** — between batches (500 attributes; on events with 50,000+ / 100,000+ attributes the batch shrinks to 100 / 50 and the pause is at least 15 / 30 s). Attribute edits — after every 50 edits of the NVD incremental run, the CISA KEV update path and the refresh of re-reported indicators | Pause in seconds between batch POSTs to MISP. Prevents memory exhaustion on large events (e.g. 95K NVD attributes). Default **`5.0`**. `0` removes the pause, except the 15 / 30 s floors on large events (not recommended). | `.env` / worker env |
| **`EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC`** | **`run_misp_to_neo4j.sync()`** — between fetching consecutive MISP events | Pause in seconds between `get_event()` calls. Gives MISP time to free memory after serving large events. Default **`2.0`**. | `.env` / worker env |
| **`EDGEGUARD_MAX_EVENT_ATTRIBUTES`** | **`run_misp_to_neo4j.run()`** — event processing loop | Events exceeding this attribute count (from MISP index metadata) are **deferred** to the end of the sync. Smaller events process first so critical data (MITRE, CISA) always lands before a large event can OOM-kill the worker. Default **`50000`**. **`0`** = disable guard (process all events in sort order). | `.env` / worker env |

**Sources with their own per-run rule.** `EDGEGUARD_INCREMENTAL_LIMIT` does not apply to them; `EDGEGUARD_MAX_ENTRIES` does, when it is lower.

- NVD: `EDGEGUARD_NVD_MAX_PER_RUN` (5,000).
- MalwareBazaar: `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500).
- ThreatFox and URLhaus: `EDGEGUARD_THREATFOX_MAX_PER_RUN` (10,000) and `EDGEGUARD_URLHAUS_MAX_PER_RUN` (50,000).
- Feodo Tracker and SSL Blacklist: `EDGEGUARD_FEODO_MAX_PER_RUN` (15,000) and `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000).
- AbuseIPDB: `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000), the request limit of its one blacklist request per run.
- CISA KEV: the whole catalogue every run; entries are added without a cap, and at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) stored copies are edited.
- CISA ICS: the advisories changed since its cursor, at most `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200) advisory files.
- MITRE ATT&CK: the whole bundle when it changed, with no item cap.

VirusTotal stays within `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` (60) lookups per run, below the 200, so in effect `EDGEGUARD_INCREMENTAL_LIMIT` cuts OTX. `docker-compose.yml` forwards the eight source caps above (the seven `*_MAX_PER_RUN` caps and `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN`) and `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`, but not `EDGEGUARD_INCREMENTAL_LIMIT` or `EDGEGUARD_MAX_ENTRIES`, so on that deployment `.env` does not change the two generic limits.

---

## Mental model: three separate pipelines

1. **Collectors → MISP**  
   External sources push into MISP. Caps = **baseline** or **incremental** limits above.

2. **MISP → Neo4j sync** (`run_misp_to_neo4j`, Airflow **`run_neo4j_sync`** / **`full_neo4j_sync`**)  
   Reads events from MISP and merges into Neo4j. **Baseline item caps do not configure this step.**  
   Event **discovery** uses the **index + client filter** path first (see table above); **restSearch** is fallback only.  
   **Per event:** parse → dedupe within the event → **cross-item relationships** (same-event only) → merge nodes → create edges. On an **incremental** sync only the attributes whose MISP `timestamp` falls inside the window are written (**`EDGEGUARD_SYNC_ATTRIBUTE_FILTER`**, default `true`); unchanged items of the same OTX pulse join only the report-scoped link build, and an event without a changed attribute makes no Neo4j call. Report-scoped links take at most 2,000 indicators, 50 malware, 50 CVEs and 10 actors per OTX pulse, the first in event order (full and incremental syncs alike; an incremental sync rebuilds the links of the pulses of its changed items only).  
   **Chunk size** for Neo4j **node** writes is **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **500** items; no pause between chunks unless `EDGEGUARD_QUERY_PAUSE_SECONDS` is set — default 0, at most 60; not forwarded by `docker-compose.yml`). **Relationship** batches use **`EDGEGUARD_REL_BATCH_SIZE`** (default **500** definitions).
   **Large events** (>5000 attributes): processed in **pages** of 5000 via `_process_large_event_paged()` — each page is parsed, synced to Neo4j, and released before the next page loads (`gc.collect()` between pages, plus the `EDGEGUARD_QUERY_PAUSE_SECONDS` pause, default 0). After all pages complete, cross-item relationships (Malware→Actor, Indicator→Malware, Indicator→CVE etc.) are built using a lightweight accumulator (~100 bytes/item) that collects only relationship-relevant fields from each page. Keeps peak RAM bounded while preserving full relationship coverage.

3. **Optional `MISPCollector`**  
   Alternate path to pull from MISP’s **`/events`** API with its **own** caps (**2000** index ceiling, etc.). **Not** the same as (2) and **not** wired into baseline collection.

---

## Common misconceptions

- **“I set `BASELINE_COLLECTION_LIMIT=1000`, so MISP→Neo4j only loads 1000 things.”**  
   **No.** Baseline limit caps **per-source collector** pushes (OTX, NVD, …). Sync discovers events via **paginated index** (then optional **paginated restSearch** fallback — `_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200`, raises `_MispFallbackHardError` on cap-hit) — unrelated to baseline Variables.

- **”Neo4j sync chunk 500 means only 500 events.”**  
  **No.** Chunking limits **parsed items** (indicators, techniques, …) per merge batch, not “number of MISP events” in one go.

- **“MISP collector’s 2000 applies during baseline.”**  
  **Baseline DAG does not run `MISPCollector`.** The **2000** cap is only relevant if something explicitly runs that collector.

---

## Related documentation

- [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) — env examples for **`EDGEGUARD_BASELINE_*`**
- [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — § *MISP → Neo4j Sync Issues*, chunking / OOM
- [ARCHITECTURE.md](ARCHITECTURE.md) — baseline vs incremental limits
- [COLLECTORS.md](COLLECTORS.md) — § *Duplicate avoidance* (MISP prefetch, OTX/MITRE cursors)
- [DATA_SOURCES_RATE_LIMITS.md](DATA_SOURCES_RATE_LIMITS.md) — **API** rate limits (different from item caps)
- `src/config.py` — `get_effective_limit`, `resolve_collection_limit`, `baseline_collection_limit_from_env`

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — MITRE ATT&CK listed among the sources with their own per-run rule (the whole changed bundle), and VirusTotal's lookup cap named, so `EDGEGUARD_INCREMENTAL_LIMIT` in effect cuts OTX; `MISPCollector` is run by no DAG or CLI step; `docker-compose.yml` forwards eight source caps, `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` among them (the page said seven), and the per-source rules moved from the table into a list below it.
- 2026-10-19 — Report-scoped links: a 50-CVE cap per pulse beside the existing caps (2,000 indicators, 50 malware, 10 actors); an incremental sync takes the first items in event order (it put the changed items first) and rebuilds only the pulses of its changed items (it also rebuilt other pulses of the unchanged items).
- 2026-10-17 — CISA ICS and CISA KEV listed among the sources with their own per-run rule (CISA ICS at most `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` advisory files, so `EDGEGUARD_INCREMENTAL_LIMIT` does not cut its scheduled runs; KEV the whole catalogue with at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` edits); `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` also paces the KEV edits and the refresh of re-reported indicators; no pause between Neo4j sync chunks or large-event pages unless `EDGEGUARD_QUERY_PAUSE_SECONDS` is set (the page said 3 s); main text limited to current behaviour, with the change history in this section.
- 2026-10-16 — Event discovery lists each event once on a MISP that ignores the query-string `limit` / `page` (MISP 2.5.45); an incomplete listing (a failed later index page, a listing cut at `EDGEGUARD_MISP_MAX_PAGES`, a non-JSON fallback page, a fallback request error that is not transient, any other listing error) fails the run, where the rows read so far had been taken as the whole listing.
- 2026-10-16 — The restSearch fallback asks for event headers only, filtered with `eventinfo` and the client-side filter (it sent `search`, which is not a restSearch parameter).
- 2026-10-16 — Per-run caps of Feodo Tracker, SSL Blacklist and AbuseIPDB, so the refresh reaches every entry they report (only their first `EDGEGUARD_INCREMENTAL_LIMIT` entries had been reported and refreshed).
- 2026-10-15 — ThreatFox and URLhaus per-run caps; `docker-compose.yml` does not forward the two generic limits; refresh of re-reported indicators added; incremental syncs write only the attributes changed in the window (`EDGEGUARD_SYNC_ATTRIBUTE_FILTER`).
- 2026-10-14 — NVD and MalwareBazaar apply their own per-run caps instead of `EDGEGUARD_INCREMENTAL_LIMIT`.
- 2026-04-26 — The restSearch fallback documented as paginated (`_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200`, `_MispFallbackHardError` at the cap), where a single `limit: 1000` request without pagination had risked silent data loss on a populated MISP; `EDGEGUARD_MISP_PAGE_SIZE` / `EDGEGUARD_MISP_MAX_PAGES` named; an unverified 3-second pause between chunks removed.
- 2026-04-06 — Neo4j sync chunk size (1000) and the pause between chunks (3 s) updated to the code values of the time.
