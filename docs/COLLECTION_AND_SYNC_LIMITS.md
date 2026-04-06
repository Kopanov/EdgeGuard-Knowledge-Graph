# Collection & sync limits — what applies when

Several numbers (**200**, **1000**, **2000**) appear across EdgeGuard docs and code. They control **different stages** of the pipeline and are **not interchangeable**. Use this page to avoid mixing up “baseline cap per source” with “Neo4j merge chunk size” or “MISP event search page size”.

---

## Quick reference

| What | Where it applies | What is limited | How to change |
|------|------------------|-----------------|---------------|
| **`BASELINE_COLLECTION_LIMIT`** (+ **`EDGEGUARD_BASELINE_COLLECTION_LIMIT`** env override) | **`edgeguard_baseline` DAG**, **`run_pipeline.py` step 2** (external collectors only) | Maximum **items per source per run** for each **external** feed (OTX, NVD, CISA, MITRE, ThreatFox, …). **`0`** = unlimited. | Airflow **Admin → Variables**, or `.env` override on the worker |
| **`BASELINE_DAYS`** (+ **`EDGEGUARD_BASELINE_DAYS`**) | Same baseline paths | How far back **time-based** sources (e.g. NVD, OTX) look | Same as above |
| **`EDGEGUARD_INCREMENTAL_LIMIT`** (+ **`EDGEGUARD_MAX_ENTRIES`**) | Scheduled collector DAGs (`edgeguard_pipeline`, medium/low/daily, …) | Max **items per source per cron run** for external collectors. **`0`** = unlimited. | Environment on Airflow worker |
| **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** | **`run_misp_to_neo4j.sync_to_neo4j()`** (MISP → Neo4j) | Max **parsed graph items** merged **per Python chunk** into Neo4j (controls **worker RAM** during write). Default **`1000`**. **`0`** / **`all`** = single pass (OOM risk). 3-second pause between chunks. | Environment on Airflow worker |
| **`EDGEGUARD_REL_BATCH_SIZE`** | **`run_misp_to_neo4j._create_relationships()`** → **`Neo4jClient.create_misp_relationships_batch()`** | Max **relationship definitions** per Neo4j **UNWIND** batch. Default **`2000`**. | Environment on Airflow worker |
| **MISP “EdgeGuard” event discovery** | **`run_misp_to_neo4j.fetch_edgeguard_events()`** | **Primary:** paginated **`GET /events/index`** (then **`/events`**) — lightweight rows **without** scanning all attributes (avoids **`restSearch`** timeouts on huge events). **Client-side filter:** **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) **or** **`org.name`** is **`EdgeGuard`**. Incremental runs also filter by **`timestamp`** / **`date`** when present. **Fallback:** PyMISP / **`POST /events/restSearch`** with **`search`** + **`limit: 1000`** if index endpoints fail. Constants: **`MISP_EVENTS_INDEX_PAGE_SIZE`** (500), **`MISP_EVENTS_INDEX_MAX_PAGES`** (100). | Code in **`src/run_misp_to_neo4j.py`** |
| **`MISPCollector`** (`src/collectors/misp_collector.py`) | **Not** used by the baseline DAG; **excluded** from `run_pipeline` step 2 (`k != "misp"`) | If invoked elsewhere: `GET /events?limit=` uses **`min(3 × resolved_limit, 2000)`** when limit is positive, else **`2000`**; max **`500`** attributes processed **per event**. Uses **`resolve_collection_limit(..., baseline=False)`** — it does **not** read **`BASELINE_COLLECTION_LIMIT`**. | Code constants + incremental / passed `limit` |
| **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** | **`MISPWriter`** (`src/collectors/misp_writer.py`) before **`push_items`** | If **true**, paginated **`POST …/attributes/restSearch`** on the **target** event builds a set of existing **`(type, value)`**; matching items are skipped (stat **`attrs_skipped_existing`**). | `.env` / worker env |
| **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**, **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**, **`EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES`** | **`otx_collector`** on **scheduled** (non-baseline) runs | **`modified_since`** window, overlap with last cursor, and max API pages; state in **`checkpoints[otx]["incremental"]`** (same JSON as baseline checkpoints). | `.env` / worker env |
| **`EDGEGUARD_MITRE_CONDITIONAL_GET`** | **`mitre_collector`** on **scheduled** (non-baseline) runs | **ETag** / **If-None-Match** on the STIX URL; **304** skips work. **Baseline** ignores this for a full refresh. | `.env` / worker env |
| **`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`** | **`MISPWriter.push_items()`** — between each batch of 500 attributes | Pause in seconds between batch POSTs to MISP. Prevents memory exhaustion on large events (e.g. 95K NVD attributes). Default **`5.0`**. Set to `0` to disable (not recommended). | `.env` / worker env |
| **`EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC`** | **`run_misp_to_neo4j.sync()`** — between fetching consecutive MISP events | Pause in seconds between `get_event()` calls. Gives MISP time to free memory after serving large events. Default **`2.0`**. | `.env` / worker env |
| **`EDGEGUARD_MAX_EVENT_ATTRIBUTES`** | **`run_misp_to_neo4j.run()`** — event processing loop | Events exceeding this attribute count (from MISP index metadata) are **deferred** to the end of the sync. Smaller events process first so critical data (MITRE, CISA) always lands before a large event can OOM-kill the worker. Default **`50000`**. **`0`** = disable guard (process all events in sort order). | `.env` / worker env |

---

## Mental model: three separate pipelines

1. **Collectors → MISP**  
   External sources push into MISP. Caps = **baseline** or **incremental** limits above.

2. **MISP → Neo4j sync** (`run_misp_to_neo4j`, Airflow **`run_neo4j_sync`** / **`full_neo4j_sync`**)  
   Reads events from MISP and merges into Neo4j. **Baseline item caps do not configure this step.**  
   Event **discovery** uses the **index + client filter** path first (see table above); **restSearch** is fallback only.  
   **Per event:** parse → dedupe within the event → **cross-item relationships** (same-event only) → merge nodes → create edges.  
   **Chunk size** for Neo4j **node** writes is **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **1000** items, 3s pause between chunks). **Relationship** batches use **`EDGEGUARD_REL_BATCH_SIZE`** (default **2000** definitions).
   **Large events** (>5000 attributes): processed in **pages** of 5000 via `_process_large_event_paged()` — each page is parsed, synced to Neo4j, and released before the next page loads (3s pause + `gc.collect()` between pages). After all pages complete, cross-item relationships (Actor→Technique, Malware→Actor, Indicator→Malware etc.) are built using a lightweight accumulator (~100 bytes/item) that collects only relationship-relevant fields from each page. Keeps peak RAM bounded while preserving full relationship coverage.

3. **Optional `MISPCollector`**  
   Legacy / alternate path to pull from MISP’s **`/events`** API with its **own** caps (**2000** index ceiling, etc.). **Not** the same as (2) and **not** wired into baseline collection.

---

## Common misconceptions

- **“I set `BASELINE_COLLECTION_LIMIT=1000`, so MISP→Neo4j only loads 1000 things.”**  
   **No.** Baseline limit caps **per-source collector** pushes (OTX, NVD, …). Sync discovers events via **paginated index** (then optional **restSearch** fallback with **`limit: 1000`**) — unrelated to baseline Variables.

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

_Last updated: 2026-03-28 — Added MISP batch throttle and event fetch throttle env vars for memory-constrained hosts._
