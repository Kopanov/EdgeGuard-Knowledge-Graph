# EdgeGuard - Airflow DAG Architecture

For **Airflow CLI commands**, environment variables, and operational troubleshooting, see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md).

## Pipeline Overview

EdgeGuard runs **6 specialized DAGs** — each source group has its own schedule to respect rate limits and update cadences. The baseline DAG is triggered manually once before production.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        EdgeGuard Pipeline Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_baseline  (MANUAL TRIGGER ONLY — run once)               │    │
│  │  misp_health → source_key_check → baseline_acquire_lock              │    │
│  │    → baseline_clean (wipe only for fresh_baseline) → baseline_start  │    │
│  │    → tier1 cisa → mitre → otx → nvd  (SEQUENTIAL)                    │    │
│  │    → tier2 [abuseipdb, threatfox, urlhaus, feodo, sslbl,             │    │
│  │             cisa_ics*, malwarebazaar*]                               │    │
│  │             (collector pool: at most EDGEGUARD_COLLECTOR_POOL_SLOTS  │    │
│  │              at once, default 4)                                     │    │
│  │    → full_neo4j_sync → build_relationships                           │    │
│  │    → run_enrichment_jobs → baseline_postcheck → baseline_complete    │    │
│  │    → baseline_release_lock        (* flag-guarded, off by default)   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_pipeline  (every 30 min)                                  │    │
│  │  check_containers → misp_health → [collect_otx] → log_summary        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_medium_freq  (every 4 hours)                              │    │
│  │  misp_health → [collect_cisa, collect_virustotal] → log_summary      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_low_freq  (every 8 hours)                                 │    │
│  │  misp_health → [collect_nvd] → log_summary                           │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_daily  (daily at 2 AM)                                    │    │
│  │  misp_health → [mitre, cisa_ics*, abuseipdb, threatfox, urlhaus,     │    │
│  │                 feodo, sslblacklist, malwarebazaar*] → log_summary   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_neo4j_sync  (every 72 hours)                              │    │
│  │  check_sync_needed → neo4j_health_check → run_neo4j_sync             │    │
│  │    → build_relationships → run_enrichment_jobs                       │    │
│  │    → check_neo4j_quality                                             │    │
│  │  (ShortCircuitOperator skips the chain within 24 h of the last sync  │    │
│  │   start or while a baseline holds the baseline lock; the writing     │    │
│  │   tasks check the lock again when they start)                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  All collectors → MISP (single source of truth) → Neo4j Knowledge Graph     │
│                   → Post-sync enrichment (relationships, aging, campaigns)   │
│                                                                              │
│  Every collect_* task of every DAG takes a slot of the Airflow pool          │
│  edgeguard_collectors: at most EDGEGUARD_COLLECTOR_POOL_SLOTS (default 4)    │
│  collectors run at once                                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## DAG Structure

### DAGs and their tasks

| DAG | Schedule | Tasks |
|-----|----------|-------|
| `edgeguard_baseline` | **None (manual only)** | `misp_health_check` → `source_key_check` → `baseline_acquire_lock` → `baseline_clean` (gated on `dag_run.conf={"fresh_baseline": true}`) → `baseline_start` → `tier1_core` (TaskGroup) → `tier2_feeds` (TaskGroup) → `full_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `baseline_postcheck` → `baseline_complete` → `baseline_release_lock`. **Top-level task IDs do NOT carry a `baseline_` prefix.** **The four critical-chain tasks (`baseline_clean`, `full_neo4j_sync`, `build_relationships`, `run_enrichment_jobs`) override `retries=0`**, as does `source_key_check` — see [`AIRFLOW_DAGS.md § Built-in Features`](AIRFLOW_DAGS.md). The baseline DAG has only 2 TaskGroups (`tier1_core`, `tier2_feeds`); there is no `tier3_low_freq` here — the daily-tier collectors live in the *incremental* `edgeguard_daily` DAG. |
| `edgeguard_pipeline` | Every 30 min | `check_containers` → `misp_health_check` → `high_frequency_collectors.collect_otx` → `log_summary` |
| `edgeguard_medium_freq` | Every 4 hours | `misp_health_check` → `collect_cisa`, `collect_virustotal` → `log_summary` |
| `edgeguard_low_freq` | Every 8 hours | `misp_health_check` → `collect_nvd` → `log_summary` |
| `edgeguard_daily` | Daily 2 AM | `misp_health_check` → 8 collectors on the shared collector pool (no order among them; at most `EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4, run at once; `collect_cisa_ics` and `collect_malwarebazaar` skip while their flags are off) → `log_summary` |
| `edgeguard_neo4j_sync` | Every 72 hours (`timedelta(days=3)`) | `check_sync_needed` → `neo4j_health_check` → `run_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `check_neo4j_quality` |

### Execution Timeouts

All tasks have explicit `execution_timeout` values to prevent hung workers from holding Airflow slots indefinitely:

| Task type | Timeout |
|-----------|---------|
| Fast collectors (OTX, CISA, VirusTotal) | 1 hour |
| Slow collectors (MITRE, AbuseIPDB, ThreatFox, etc.) | 2 hours |
| Baseline collectors OTX / NVD (unlimited)            | 5 hours each |
| Baseline collectors CISA / MITRE / Tier 2 feeds      | 2 hours each |
| Baseline wipe (`baseline_clean`) | 60 minutes |
| Neo4j sync (`run_neo4j_sync`; incremental, or full on the first run and on `NEO4J_FULL_SYNC=true`) | 8 hours (a full sync of a 730-day MISP takes about 6 hours, the baseline full sync's limit; plus a third, because a requested full sync stands until it succeeds) |
| Neo4j full sync (baseline) | 6 hours |
| build_relationships | 5 hours |
| run_enrichment_jobs | 5 hours |
| Neo4j quality check | 15 minutes |
| Baseline postcheck (`baseline_postcheck`) | 10 minutes |
| Health, key and lock checks (`check_containers`, `misp_health_check`, `check_sync_needed`, `neo4j_health_check`, `source_key_check`, `baseline_acquire_lock`, `baseline_release_lock`, `baseline_start`) | 2–5 minutes |
| Log/summary tasks | 2–5 minutes |
| Metrics server task | 24 hours (long-lived) |

### Tier 1 collectors — sequential

The four tier-1 baseline collectors run **sequentially** inside the
`tier1_core` TaskGroup, in the order **`cisa → mitre → otx → nvd`**,
because all four writing to MISP at once exhaust MISP's PHP-FPM workers:
`AppModel.php` "Cannot use a scalar value as an array" warnings cascade
into 5xx responses on edit-event calls, and the attributes of those calls
are lost. On the overnight 730-day baseline run of 2026-04-19, with the
four collectors in parallel, MISP HTTP 500 errors lost 13,620 of 92,620
NVD attributes (about 14.7%).

**Order rationale:** the order is mostly aesthetic — small-first
(CISA ~14s, MITRE ~28s) reads more naturally in the Airflow grid view.
It does **not** give automatic fast-fail: the TaskGroup keeps
`trigger_rule = ALL_DONE` so a
single-source API flake doesn't cascade-skip the rest of tier-1 — losing
1/4 of a baseline is much better than losing all of it. The real value
of the sequential order is **halved MISP write concurrency**, which is independent of
the collector ordering.

**Trade-off:** total tier-1 wall time is
`cisa + mitre + otx + nvd ≈ 8h` instead of `max(otx, nvd) ≈ 5h` for
parallel collectors. The ~3h cost buys halved MISP write
concurrency without any MISP server changes.

**What this does not address:** the per-event-grows-with-size cost on a
single oversized event (MISP `edit-event` loads the entire event for
dedup; cost grows linearly with existing attribute count). Partitioning
events by date range, so that no single event exceeds ~20K attributes,
is not implemented.

**Tier 2 has no order, and the collector pool bounds it** —
the tier-2 feeds are individually small and don't trigger the
oversized-event failure mode, so `tier2_feeds` puts no edges between
them. Their load is not negligible, though: all 7 at once grow the MISP
php-fpm workers past the MISP container's memory limit (HTTP 502), and a
daily catch-up run together with OTX, VirusTotal and NVD reaches the
`airflow` container's memory limit (tasks killed). Every
collector, here and in the other DAGs, therefore takes a slot of the Airflow pool
`edgeguard_collectors`, so at most `EDGEGUARD_COLLECTOR_POOL_SLOTS`
(default 4) collectors run at once across all DAGs; tier 1 runs one
collector at a time, so it holds one slot. The pool and resizing are described in
[AIRFLOW_DAGS.md § Collector pool: setup and resizing](AIRFLOW_DAGS.md#collector-pool-setup-and-resizing).

### Parent-DAG liveness check

Every baseline collector (tier 1 and tier 2, through
`run_baseline_collector`) installs a **parent-DAG liveness
callback** that polls the Airflow REST API between MISP push batches
and exits cleanly if the parent `dag_run` is no longer in `running`
or `queued` state. This closes the **orphan-collector-process gap**.

**Why it is needed:** when a DAG run is marked `failed` (because *another*
task in the same run failed), Airflow does NOT auto-kill in-flight
tasks of that run. The collector keeps running in its worker
subprocess until it finishes naturally or hits its 5h timeout, and can
push attributes to MISP after the next run's `baseline_clean` has wiped
it.

**How it works:** between MISP push batches (already throttled 5s by
`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`), the collector calls a callback
that probes the Airflow REST API (rate-limited to one probe per
60s). If the parent `dag_run` is in any terminal state, the callback
raises `AbortedByDagFailureException` — the **current batch finishes**
its write to MISP cleanly, the **next batch never starts**.

**Trade-offs:**
- Clean exit between batches → no half-written MISP events
- Fail-OPEN → transient Airflow API blip doesn't false-kill the collector
- Per-collector opt-in via `EDGEGUARD_PARENT_DAG_LIVENESS_CHECK` (default `true` for baseline)
- Low overhead (~1 small HTTP call per minute)
- Limitation: up to 60s lag between DAG-marked-failed and collector-noticing (configurable via `EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC`)

**Operator visibility:** when the safeguard fires, you'll see this in the collector log:

```
WARNING [PARENT_DAG_DEAD] dag_run=edgeguard_baseline/manual__2026-04-19T22:46:59
        observed state='failed' — aborting collector cleanly. Orphan-process
        safeguard (PR-F6) prevented late writes to MISP/Neo4j.
```

Grep `PARENT_DAG_DEAD` in your DAG logs to find every aborted-by-parent-failure
event. If you see it firing on healthy runs, your Airflow API is unreachable
from the collector worker (check `AIRFLOW_WEBSERVER_URL` env).

**What this does not do:** the safeguard runs collector-side, so it
can't help if the collector itself is wedged (e.g., blocked in a
syscall, in a non-MISP loop). For those cases, the per-task
`execution_timeout` is the backstop. Combine the two
for defense-in-depth.

See [`src/parent_dag_liveness.py`](../src/parent_dag_liveness.py) for
the full module documentation.

---

## Baseline DAG — How to Use

The `edgeguard_baseline` DAG performs a deep historical collection from all sources and builds the full knowledge graph from scratch. Run it **once** before activating the incremental cron DAGs.

### Step 1 — Configure via Airflow Variables (optional)

Go to **Airflow UI → Admin → Variables** and set:

| Variable | Default | Description |
|----------|---------|-------------|
| `BASELINE_COLLECTION_LIMIT` | `0` | Items per source. `0` = unlimited (recommended). Set to e.g. `200` for a test run. |
| `BASELINE_DAYS` | `730` | Days of history to request from NVD and OTX. `365` = 1 year, `730` = 2 years, `1460` = 4 years. |

### Step 2 — Trigger manually

Airflow UI → DAGs → `edgeguard_baseline` → Trigger DAG (▶). Without a conf the run is additive; trigger with the conf `{"fresh_baseline": true}`, or run `edgeguard fresh-baseline --days N`, to wipe first ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md#edgeguard_baseline-task-chain--additive-vs-destructive)).

### Step 3 — After completion

Unpause the scheduled DAGs (`edgeguard_pipeline`, `edgeguard_medium_freq`, etc.) if you paused them before the launch ([BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md)). They skip while the baseline holds the baseline lock, which the run releases when it succeeds; a failed run keeps it until it is resumed and succeeds or the sentinel reaches the 48 h age cap (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`).

### Baseline collection behaviour

| Source | Baseline mode | Note |
|--------|--------------|------|
| NVD | `baseline=True` — date-range paged, up to `BASELINE_DAYS` back; then the records of every KEV CVE and of `EDGEGUARD_NVD_EXTRA_CVE_IDS`, whatever their age | Resumes from checkpoint on restart |
| OTX | `baseline=True` — date-range paged, up to `BASELINE_DAYS` back | Resumes from checkpoint on restart |
| CISA / MITRE | Full catalog fetch | Already returns complete list |
| ThreatFox / URLhaus / Feodo / etc. | Full current feed (ThreatFox: last 7 days, at most `EDGEGUARD_THREATFOX_MAX_PER_RUN`; URLhaus: `csv_recent`, at most `EDGEGUARD_URLHAUS_MAX_PER_RUN`; Feodo Tracker: the complete C2 history, at most `EDGEGUARD_FEODO_MAX_PER_RUN`; SSL Blacklist: the whole blacklist, at most `EDGEGUARD_SSLBL_MAX_PER_RUN`; AbuseIPDB: one blacklist request of at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` addresses) | Flat feeds, no history API |

---

## Incremental Collection Limit

Regular cron DAGs (every 30 min / 4 h / 8 h / daily) read what changed since each collector's cursor or its feed's current window ([README § Two operating modes](../README.md)); a per-source item cap keeps each run fast and prevents accidental re-ingestion of bulk historical data.

### Configuration

Set `EDGEGUARD_INCREMENTAL_LIMIT` in the environment of the Airflow worker. `src/config.py` reads the process environment, not `.env`, and `docker-compose.yml` does not forward `EDGEGUARD_INCREMENTAL_LIMIT` or `EDGEGUARD_MAX_ENTRIES`, so on the Compose deployment a value in `.env` does not reach the container: add the variable to the `airflow` service's `environment` (or to `x-common-env`) to change it there. The per-source caps below (`EDGEGUARD_NVD_MAX_PER_RUN`, `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN`, `EDGEGUARD_THREATFOX_MAX_PER_RUN`, `EDGEGUARD_URLHAUS_MAX_PER_RUN`, `EDGEGUARD_FEODO_MAX_PER_RUN`, `EDGEGUARD_SSLBL_MAX_PER_RUN`, `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN`) are forwarded, so `.env` sets them.

```bash
# Default — 200 items per source per cron run
EDGEGUARD_INCREMENTAL_LIMIT=200

# Larger window for high-volume sources
EDGEGUARD_INCREMENTAL_LIMIT=500

# No item cap — only each collector's cursor or feed window applies (use with caution)
EDGEGUARD_INCREMENTAL_LIMIT=0
```

This is a **per-source** limit. NVD, MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker, SSL Blacklist, AbuseIPDB, CISA KEV and CISA ICS do not use it: each applies its own per-run cap. CISA KEV compares its whole catalogue with MISP in every run and caps only its edits (`EDGEGUARD_KEV_MAX_EDITS_PER_RUN` 500). CISA ICS reads the advisories changed since its cursor up to `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200) files, because a cut at 200 (advisory, CVE) items would stop inside the window, and an advisory naming 200 or more CVEs would hold its cursor for good, every run green. ThreatFox and URLhaus read a 7-day and a 30-day window of about 1,100 new entries per day each, of which a cut at 200 would lose about 80%. Feodo Tracker, SSL Blacklist and AbuseIPDB publish lists of thousands of entries, and a cut at 200 would leave the stored copies of the others unreported, so they would age while still listed. AbuseIPDB makes one blacklist request per run: its cap is that request's `limit`, at most 10,000 on the free plan. The other collectors in the incremental DAGs take at most 200 items each per run (plus optional separate VirusTotal enrichment runs if enabled).

### Priority order in `get_effective_limit()`

```
1. NO_LIMIT_SOURCES (per-source bypass in config.py)   → None (unlimited)
2. EDGEGUARD_MAX_ENTRIES ≠ 0 (hard global override)    → that value
3. OWN_RUN_CAP_SOURCES (nvd, malwarebazaar,            → None here; the collector applies
   threatfox, urlhaus, feodo, sslbl,                     its own cap (EDGEGUARD_NVD_MAX_PER_RUN,
   abuseipdb, cisa / cisa_kev, cisa_ics)                 EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN,
                                                         EDGEGUARD_THREATFOX_MAX_PER_RUN 10000,
                                                         EDGEGUARD_URLHAUS_MAX_PER_RUN 50000,
                                                         EDGEGUARD_FEODO_MAX_PER_RUN 15000,
                                                         EDGEGUARD_SSLBL_MAX_PER_RUN 20000,
                                                         EDGEGUARD_ABUSEIPDB_MAX_PER_RUN 10000,
                                                         EDGEGUARD_KEV_MAX_EDITS_PER_RUN 500,
                                                         EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN
                                                         1200)
4. EDGEGUARD_INCREMENTAL_LIMIT > 0 (default: 200)      → 200
5. EDGEGUARD_INCREMENTAL_LIMIT = 0                     → None (unlimited)
```

### Baseline vs Incremental — quick reference

| | Baseline | Incremental |
|--|----------|-------------|
| Item cap | `BASELINE_COLLECTION_LIMIT` (Airflow Variable, default unlimited) | `EDGEGUARD_INCREMENTAL_LIMIT` (env var, default 200/source); NVD, MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker, SSL Blacklist, AbuseIPDB and CISA ICS use their own per-run caps, and CISA KEV compares its whole catalogue (edits capped by `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`) |
| Lookback | `BASELINE_DAYS` (Airflow Variable, default 730 days) | From each collector's cursor (NVD, OTX, CISA ICS) or its feed's current window (ThreatFox: 7 days; URLhaus: `csv_recent`; Feodo Tracker: the servers active in the last 30 days); CISA KEV and MITRE ATT&CK read the whole catalogue (see [Incremental Collection Limit](#incremental-collection-limit)) |
| Trigger | Manual (once before production) | Automatic (cron schedules) |
| Scope | Full historical load | New / updated data only |

---

## Post-Sync Enrichment Jobs

After every MISP→Neo4j sync (`edgeguard_neo4j_sync`) the following jobs run automatically in sequence.

**Worker memory:** The sync task calls `run_misp_to_neo4j.sync_to_neo4j()`, which chunks merges by **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **500**). **`0`** or **`all`** = single Python-side pass (**OOM risk** on huge backfills). See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) and [README.md](../README.md).

### 1. build_relationships

Runs `src/build_relationships.py` to create or refresh all cross-source graph relationships:

| Relationship | Method | Confidence / properties |
|-------------|--------|-------------------------|
| `(Indicator)-[:INDICATES]->(Malware)` | Same OTX pulse (`pulse_id`) in the MISP→Neo4j sync (`match_type='otx_pulse'`, the pulse in `r.source_refs[]`), or `malware_family` name match in `build_relationships.py` Q9; there is no whole-event `misp_event_ids[]` co-occurrence query | **0.6** (`otx_pulse`) / **0.8** (`malware_family`) |
| `(Indicator)-[:EXPLOITS]->(CVE\|Vulnerability)` | Indicator `cve_id` matches node `cve_id` | **1.0**, `match_type='cve_tag'` (not bulk-calibrated like co-occurrence) |
| `(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)` | `t.mitre_id IN a.uses_techniques` — **explicit STIX from MITRE bundle** (Q5); also `a.reported_techniques` from OTX pulse `attack_ids` (Q5b) | **0.95** (`match_type='mitre_explicit'`) / **0.6** (`match_type='otx_pulse'`) |
| `(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)` | `t.mitre_id IN m.uses_techniques` — **same STIX `uses` rows** (malware → attack-pattern) | **0.95** (`match_type='mitre_explicit'`) |
| `(Tool)-[:IMPLEMENTS_TECHNIQUE]->(Technique)` | `t.mitre_id IN tool.uses_techniques` — **same STIX `uses` rows** (tool → attack-pattern) | **0.95** (`match_type='mitre_explicit'`) |
| `(Technique)-[:IN_TACTIC]->(Tactic)` | MITRE ATT&CK taxonomy | **1.0** |
| `(Technique)-[:SUBTECHNIQUE_OF]->(Technique)` | MITRE dotted id `T1021.006` → `T1021` (Q1b) | **1.0** (`match_type='mitre_explicit'`) |
| `(ThreatActor)-[:USES_MALWARE]->(Malware)` | `m.name IN a.uses_malware` (MITRE STIX `uses` group → malware; Q2b) | **0.95** (`mitre_explicit`) |
| `(ThreatActor)-[:USES_TOOL]->(Tool)` | `t.mitre_id IN a.uses_tools` (MITRE STIX `uses` group → tool; Q2c) | **0.95** (`mitre_explicit`) |

**Note on Actor/Malware/Tool → Technique:** All three are sourced from **explicit** STIX **`relationship_type: uses`** objects in the MITRE ATT&CK bundle — **not** from fuzzy text matching and **not** from actor/technique MISP co-occurrence (which is always empty). The MITRE collector populates **`uses_techniques`** on actors directly from the bundle; for **malware** and **tool**, the same list is embedded in MISP as **`MITRE_USES_TECHNIQUES:{...}`** on the attribute comment so `run_misp_to_neo4j` can restore **`uses_techniques`** on **`Malware`** / **`Tool`** nodes. `build_relationships.py` uses `WHERE t.mitre_id IN coalesce(node.uses_techniques, [])` per label and emits the specialized edge type matching the source label.

> **Technique edge types:** attribution (actor/campaign → technique) is
> `EMPLOYS_TECHNIQUE` and capability (malware/tool → technique) is
> `IMPLEMENTS_TECHNIQUE`, rather than one generic `USES`, for Cypher
> clarity and LLM/GraphRAG retrieval. Both edges collapse back to STIX 2.1
> `relationship_type: "uses"` on export. See
> [`docs/KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation)
> for the semantic rationale.

### 2. run_enrichment_jobs

Runs `src/enrichment_jobs.py` — **seven** jobs in sequence (`run_all_enrichment_jobs`):

1. **Vulnerability↔CVE bridge** (`bridge_vulnerability_cve` — `REFERS_TO`)
1b. **Actor alias merge** (`merge_alias_duplicate_actors` — folds non-MITRE actors named by an alias of exactly one MITRE actor, or resolved by the canonical threat-actor reference to another actor on the graph, into that node; `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE`, `EDGEGUARD_CANONICAL_THREAT_ACTORS`)
1c. **Malware ATT&CK-id twin merge** (`merge_malware_attack_twins` — folds a non-MITRE `Malware` node named after an ATT&CK software id, `cobalt strike - s0154` from OTX's MISP-galaxy naming, into the MITRE `Malware` node of that id or, when its id cannot be read, of that base name, or, for software without one (an ATT&CK tool), into the `Malware` node of its base name; a twin with neither is left and counted; same merge as 1b; `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE`; see [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Malware named after an ATT&CK software id")
2. **Indicator aging** (`decay_ioc_confidence`: the one aging rule for every `Indicator`, evaluated at the database's current time, as in every Indicator write, or at a node's `aging_evaluated_at` when that is later (the time at which its aging values were last written; no task passes a time of the run, so a re-run of an older run, or a baseline overlapping a scheduled sync, evaluates at the time it runs and moves no node backwards; [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md#airflow-task-run_neo4j_sync-edgeguard_neo4j_sync-dag), *Indicator aging time*); writes only the nodes whose values change, so a run right after it writes nothing unless a node reached a tier day; runs before the campaign builder, which links active indicators only)
3. **Campaign nodes** (`build_campaign_nodes`)
4. **Co-occurrence calibration** (`calibrate_cooccurrence_confidence`; a no-op on a fresh baseline, since no `misp_cooccurrence` edges are written)
5. **FIRST EPSS** (`enrich_cve_epss` in `src/cve_feed_enrichment.py` — the day's EPSS score and percentile on the `CVE` nodes that exist, removed from those that left the feed; `EDGEGUARD_ENABLE_EPSS`, default on; a feed outage is logged and skipped, never fails the task; the one source written to Neo4j without MISP, see [DATA_SOURCES.md § 8b](DATA_SOURCES.md)). CISA's SSVC decision points need no job: they come with the NVD records through the sync.

#### Indicator aging

Threat intelligence has a shelf life. Every `Indicator`, whoever supplied it, ages from its latest report (`last_reported_at`: the source's own `last_seen` capped at the MISP timestamp; `first_imported_at` when no report dated it), never from `last_updated` ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging)). No other label ages.

| Days since the latest report | Effect on the Indicator |
|--------------------------|---------------------|
| below 90 | `confidence_score = source_confidence` |
| from 90 | × 0.85 |
| from 180 | × 0.70 |
| from 365 | × 0.55 |
| from 730 | `active = false`, `retired_by = 'decay'`, `retired_at` = basis + 730 days (retired, not deleted) |
| Any | Minimum floor: 0.10 |

The value is recomputed from `source_confidence` each time, so a missed or repeated run gives the same graph; a newer report reactivates a node in the sync's write, and a manual decommission is kept. `active` comes from this rule only. Retired nodes remain in the graph for historical queries — they are never deleted. Settings: `EDGEGUARD_AGING_TIER_DAYS`, `EDGEGUARD_AGING_FACTORS`, `EDGEGUARD_AGING_RETIRE_DAYS`.

#### Campaign Node Builder

Materialises `Campaign` nodes from the existing graph structure. A Campaign is created for each `ThreatActor` that has at least one malware attributed to it (`ATTRIBUTED_TO`) or used by it (`USES_MALWARE`: MITRE's explicit `uses`, curated-package claims), and an active indicator of such a malware (`src/campaign_evidence.py`; the baseline postcheck's INV-1 counts the qualifying actors by the same definition).

```
ThreatActor <-[:ATTRIBUTED_TO]- Malware <-[:INDICATES]- Indicator
ThreatActor  -[:USES_MALWARE]-> Malware <-[:INDICATES]- Indicator
    ↓                              ↓                       ↓
 [:RUNS]→ Campaign ←── [:PART_OF_CAMPAIGN] ←── [:PART_OF_CAMPAIGN]
```

Every campaign link carries `match_type = 'campaign_grouping'`, the confidence of the links it rests on and their relationship types (`evidence_types`). A campaign whose actor has neither link left (or whose actor name no longer exists after the actor alias merge) is deleted with its links in the same run; one with evidence whose indicators all expired stays, `active = false`. Its `uuid` comes from the actor's name, so a campaign built again keeps it.

Campaign properties: `name`, `actor_name`, `first_seen`, `last_seen`, `zone`, `indicator_count`, `malware_count`.

#### Co-occurrence Confidence Calibration

Adjusts **INDICATES** and **EXPLOITS** edge confidence **when** `r.match_type IN ('misp_cooccurrence', 'misp_correlation')`, using the number of indicators in the same MISP event. No producer writes such edges (the sync links report-scoped, `match_type='otx_pulse'`), so the pass is a no-op on a fresh baseline. Other edges, curated-package claims included, are untouched. (CVE-tag `EXPLOITS` edges carry `match_type='cve_tag'` and are not tuned by this pass.)

## Data Quality Targets

| Metric | Target | Implementation |
|--------|--------|----------------|
| Schema Compliance | >95% | Required fields validation |
| Deduplication | >90% | Entity resolution matching |
| Provenance Scoring | Multi-source | +1 per source corroboration |
| PII-Free | 100% | Automated PII scanning |

## Deduplication Methodology: MERGE Strategy

### The Problem
Duplicates arrive at different times — threat intelligence is asynchronous!
- NVD reports a CVE on Tuesday
- MISP reports that same CVE on Thursday

### The Solution: Neo4j MERGE
Instead of `CREATE`, use `MERGE` to dynamically handle duplicates:

```python
# Instead of CREATE (creates duplicates):
CREATE (v:Vulnerability {cve_id: 'CVE-2024-1234'})

# Use MERGE (creates OR updates):
MERGE (v:Vulnerability {cve_id: 'CVE-2024-1234'})
SET 
    v.description = '...',
    v.cvss_score = 8.5,
    v.updated_at = timestamp()
```

### Provenance Metadata Tracking

Every merge records the source and confidence:

```cypher
MERGE (v:Vulnerability {cve_id: 'CVE-2024-1234'})
SET 
    v.description = '...',
    v.updated_at = timestamp(),
    // Provenance: track sources
    v.sources = COALESCE(v.sources, []) + 'NVD',
    // Confidence: +1 per source
    v.confidence_score = CASE 
        WHEN 'NVD' IN v.sources AND 'MISP' IN v.sources THEN 0.8
        WHEN 'NVD' IN v.sources THEN 0.6
        ELSE 0.4
    END
```

### Confidence Score Logic

The Cypher above and the multi-source example below illustrate the MERGE pattern; their confidence values are illustrative, not implemented. EdgeGuard adds no bonus per corroborating source and none for freshness. In the code, a node other than an `Indicator` keeps the highest `confidence_score` any source reported for it, and an `Indicator`'s `confidence_score` is its `source_confidence` (the highest confidence a source gave) × the aging factor, at least 0.10 (see [Indicator aging](#indicator-aging)).

### Provenance Tracking Properties

Under the **source-truthful architecture** (see
[`migrations/2026_04_first_seen_at_source.md`](../migrations/2026_04_first_seen_at_source.md)),
**node-level timestamps are DB-local only** — per-source observation
claims live on the `SOURCED_FROM` edge so multi-source IOCs preserve
full provenance. Nodes carry no `n.first_seen` field.

| Property | Where | Type | Description |
|----------|-------|------|-------------|
| `sources` | node | List[String] | All sources that reported this entity |
| `first_imported_at` | node | Timestamp | When EdgeGuard first imported the node (ON CREATE only — never overwritten) |
| `last_updated` | node | Timestamp | DB-local refresh timestamp (set on every MERGE) |
| `confidence_score` | node | Float | 0.0 - 1.0: the highest confidence a source reported; on an `Indicator`, `source_confidence` × the aging factor, at least 0.10 |
| `validation_status` | node | String | verified, pending, disputed |
| `imported_at` | edge `SOURCED_FROM` | Timestamp | Per-source DB-local import time |
| `updated_at` | edge `SOURCED_FROM` | Timestamp | Per-source DB-local refresh time |
| `source_reported_first_at` | edge `SOURCED_FROM` | Timestamp / NULL | MIN-CASE of source's claimed first observation; NULL when source did not report (honest-NULL principle) |
| `source_reported_last_at` | edge `SOURCED_FROM` | Timestamp / NULL | MAX-CASE of source's claimed last observation; NULL when source did not report |

### Example: Multi-Source CVE

```cypher
// Day 1: NVD reports CVE-2024-1234
MERGE (v:Vulnerability {cve_id: 'CVE-2024-1234'})
ON CREATE SET v.first_imported_at = datetime()
SET v.sources           = ['NVD'],
    v.confidence_score  = 0.5,
    v.last_updated      = datetime()
// ... and the SOURCED_FROM edge carries the per-source NVD timestamps.

// Day 3: MISP reports same CVE
MERGE (v:Vulnerability {cve_id: 'CVE-2024-1234'})
SET v.sources          = ['NVD', 'MISP'],
    v.confidence_score = 0.7,  // Boosted!
    v.last_updated     = datetime()
// `first_imported_at` is NEVER overwritten (ON CREATE only); MISP's
// per-source claims land on a NEW SOURCED_FROM edge, leaving NVD's
// provenance intact.

// Day 5: CISA KEV reports it (known exploited)
MERGE (v:Vulnerability {cve_id: 'CVE-2024-1234'})
SET 
    v.sources = ['NVD', 'MISP', 'CISA_KEV'],
    v.confidence_score = 0.9,  // High confidence!
    v.known_exploited = true,
    v.last_updated = timestamp()
```

## Quality Scoring Logic

No base-plus-bonus confidence formula is implemented. How `confidence_score` is set: [Confidence Score Logic](#confidence-score-logic) above.

## Airflow Setup Requirements

**Docker Compose (`docker-compose.yml`):** the **`airflow`** service is **built** from **`Dockerfile.airflow`**, which installs **`requirements-airflow-docker.txt`** (e.g. **`neo4j`**, **`pymisp`**, **`apache-airflow-providers-standard`**) on top of **`apache/airflow:3.3.2-python3.12`**. After dependency changes, run **`docker compose build airflow`**. The service uses **`LocalExecutor`** with **PostgreSQL** (`airflow_postgres`) for metadata. Optional credentials: `AIRFLOW_POSTGRES_*` in `.env`. If runs stall, see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) troubleshooting.

```bash
# Install Airflow + PostgreSQL driver (matches docker-compose metadata backend)
pip install "apache-airflow[postgres]~=3.3" "apache-airflow-providers-standard~=1.5"
# or from repo root:
# pip install ".[airflow]"

# Or use Astro CLI (recommended for local dev)
brew install astro
```

## DAG File Location

```
EdgeGuard-Knowledge-Graph/
├── dags/
│   ├── edgeguard_pipeline.py      # 6 DAGs: baseline + high/med/low/daily + neo4j_sync
│   └── edgeguard_metrics_server.py # Dedicated metrics server DAG
├── src/
│   └── collectors/                 # Collector modules (one per source)
└── logs/                           # Pipeline logs
```

### Key DAG Design Points
- Each source group runs at its own cadence to respect API rate limits, rather than one DAG for all sources.
- **`edgeguard_neo4j_sync`** runs every 72 hours (a timedelta schedule) and uses a `ShortCircuitOperator`
  (`check_sync_needed` / `should_run_neo4j_sync`) that skips the chain when the last sync started less than 24 hours ago
  (after a baseline's or a forced sync) and while a baseline holds the baseline lock; a regular run is never skipped by the
  24 h guard. `run_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` check the lock again at
  their start and skip while a baseline holds it ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md#neo4j-sync)).
- All `python_callable` values are direct function references (no lambdas) — lambda functions
  cannot be serialized by Airflow's DAG serialization (on 2.x and 3.x alike) and cause `PicklingError` on workers.
- Every task has an `execution_timeout` — see table above.
- Every `collect_*` task of every DAG runs in the Airflow pool `edgeguard_collectors`, which bounds how many collectors run at once (`EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4); see [AIRFLOW_DAGS.md § Collector pool: setup and resizing](AIRFLOW_DAGS.md#collector-pool-setup-and-resizing).
- The Prometheus metrics server runs in `edgeguard_metrics_server.py`, not at DAG module level.

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-18 — Baseline vs Incremental table: the incremental lookback is each collector's cursor or its feed's current window, not 72 hours.
- 2026-10-17 — Rewritten as a guide to the current system: change history moved to this section, co-occurrence calibration details to the appendix.
- 2026-10-17 — CISA ICS uses its own per-run cap (`EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN`, `cisa_ics` in `OWN_RUN_CAP_SOURCES`); the incremental collectors read from their cursor or feed window (the text said the last 2–3 days without an item cap); the sync's ShortCircuit also skips while a baseline holds the lock and the writing tasks check it again; `source_key_check` has `retries=0`; every baseline collector installs the liveness callback; the confidence formulas are marked illustrative.
- 2026-10-16 — CISA KEV, Feodo Tracker, SSL Blacklist and AbuseIPDB are in `OWN_RUN_CAP_SOURCES`; every `collect_*` task takes a slot of the collector pool `edgeguard_collectors`, because all 7 tier-2 feeds at once grew the MISP php-fpm workers past the MISP container's memory limit and a daily catch-up run with OTX, VirusTotal and NVD reached the `airflow` container's memory limit; `edgeguard_neo4j_sync` runs every 72 hours with a 24-hour skip guard.
- 2026-10-16 — Indicator aging: one rule for every Indicator from its latest report, evaluated at the database's current time and run before the campaign builder; `mark_inactive_nodes` (no caller) removed, because it set `active` on Indicators and Vulnerabilities from MISP event listing, a second lifecycle rule beside the aging rule on a label that does not age.
- 2026-10-16 — Campaign builder: a campaign rests on `ATTRIBUTED_TO` or `USES_MALWARE`, its links name their evidence types, and a campaign without evidence is deleted (it was kept, inactive).
- 2026-10-15 — ThreatFox and URLhaus use their own per-run caps; a value of `EDGEGUARD_INCREMENTAL_LIMIT` in `.env` does not reach the Compose deployment; `run_neo4j_sync` timeout 8 hours (was 4); `baseline_clean` timeout 60 minutes (was 20); the enrichment gained the Malware ATT&CK-id twin merge and FIRST EPSS; the calibration filter is `r.match_type` (it named the dropped `r.source_id` / `r.source_ids`) and its large-event batch binds `rid` as a variable (the `$rid` parameter failed every batch); the NVD baseline names the KEV sweep and the named CVE ids.
- 2026-10-14 — Every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]`; `source_id`, `source_ids` and `report_ids` dropped from relationships.
- 2026-10-10 — The whole-event Indicator → Malware co-occurrence query was removed: `INDICATES` comes from the same OTX pulse and the family match; actor techniques also come from OTX pulse `attack_ids`; `SUBTECHNIQUE_OF`, `USES_MALWARE` and `USES_TOOL` edges; the actor alias merge (`merge_alias_duplicate_actors`) joins the enrichment jobs.
- 2026-04-28 — Baseline task chain corrected: task IDs carry no `baseline_` prefix, there is no `tier3_low_freq` group, `tier2_extended` is `tier2_feeds`, and `baseline_postcheck` is in the chain.
- 2026-04-23 — The four baseline critical-chain tasks have `retries=0`.
- 2026-04-20 — Tier-1 baseline collectors run sequentially after the 2026-04-19 baseline lost about 14.7% of NVD attributes; parent-DAG liveness check after a failed baseline run's `collect_nvd` subprocess stayed alive 12+ hours and pushed 78,313 attributes to MISP after the next run's `baseline_clean` had wiped it (Event 19, 72,479 duplicated CVEs).
- 2026-04-18 — Source-truthful provenance: per-source timestamps on `SOURCED_FROM`, `n.first_seen` retired; Airflow 2 to 3 upgrade.
- 2026-04-17 — The INDICATES co-occurrence query became array-only (`misp_event_ids[]`, the scalar `misp_event_id` dropped).
- 2026-04-15 — Baseline OTX/NVD, `build_relationships` and `run_enrichment_jobs` timeouts raised from 3 h to 5 h after baseline re-runs hit the 3 h limit; technique edges split from a single `USES` into `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE`.
