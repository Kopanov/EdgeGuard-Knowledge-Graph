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
│  │  misp_health → baseline_start                                        │    │
│  │    → tier1 cisa → mitre → otx → nvd  (SEQUENTIAL, PR-F4)             │    │
│  │    → tier2 [abuseipdb, threatfox, urlhaus, cybercure,                │    │
│  │             feodo, sslbl] (parallel)                                 │    │
│  │    → full_neo4j_sync → build_relationships                           │    │
│  │    → run_enrichment_jobs → baseline_complete                         │    │
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
│  │  misp_health → [mitre, abuseipdb, threatfox, urlhaus,                │    │
│  │               cybercure, feodo, sslblacklist] → log_summary          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  edgeguard_neo4j_sync  (every 3 days at 3 AM)                        │    │
│  │  check_sync_needed → run_neo4j_sync                                  │    │
│  │    → build_relationships → run_enrichment_jobs                       │    │
│  │    → check_neo4j_quality                                             │    │
│  │  (ShortCircuitOperator skips entire chain when nothing new)          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  All collectors → MISP (single source of truth) → Neo4j Knowledge Graph     │
│                   → Post-sync enrichment (relationships, campaigns, decay)   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## DAG Structure

### DAGs and their tasks

| DAG | Schedule | Tasks |
|-----|----------|-------|
| `edgeguard_baseline` | **None (manual only)** | `misp_health_check` → `baseline_start` → `tier1_core` (TaskGroup) → `tier2_feeds` (TaskGroup) → `full_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `baseline_complete` |
| `edgeguard_pipeline` | Every 30 min | `check_containers` → `misp_health_check` → `high_frequency_collectors.collect_otx` → `log_summary` |
| `edgeguard_medium_freq` | Every 4 hours | `misp_health_check` → `collect_cisa`, `collect_virustotal` → `log_summary` |
| `edgeguard_low_freq` | Every 8 hours | `misp_health_check` → `collect_nvd` → `log_summary` |
| `edgeguard_daily` | Daily 2 AM | `misp_health_check` → 7 collectors (parallel) → `log_summary` |
| `edgeguard_neo4j_sync` | Every 3 days 3 AM | `check_sync_needed` → `run_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `check_neo4j_quality` |

### Execution Timeouts

All tasks have explicit `execution_timeout` values to prevent hung workers from holding Airflow slots indefinitely:

| Task type | Timeout |
|-----------|---------|
| Fast collectors (OTX, CISA, VirusTotal) | 1 hour |
| Slow collectors (MITRE, AbuseIPDB, ThreatFox, etc.) | 2 hours |
| Baseline collectors OTX / NVD (unlimited)            | 5 hours each |
| Baseline collectors CISA / MITRE / Tier 2 feeds      | 2 hours each |
| Neo4j sync (incremental) | 4 hours |
| Neo4j full sync (baseline) | 6 hours |
| build_relationships | 5 hours |
| run_enrichment_jobs | 5 hours |
| Neo4j quality check | 15 minutes |
| Log/summary tasks | 2–5 minutes |
| Metrics server task | 24 hours (long-lived) |

_Baseline OTX/NVD, `build_relationships`, and `run_enrichment_jobs` were
bumped from 3h → 5h in 2026-04 after baseline re-runs on the merged
#20/#22/#24 scope repeatedly hit the 3h ceiling._

### Tier 1 collectors — sequential (PR-F4, 2026-04-20)

The four tier-1 baseline collectors run **sequentially** inside the
`tier1_core` TaskGroup, in the order **`cisa → mitre → otx → nvd`**. They
were originally parallel; the change was made after the 2026-04-19
overnight 730-day baseline run lost ~14.7% of NVD attributes (13,620 of
92,620) to MISP HTTP 500 errors caused by PHP-FPM worker exhaustion when
all four collectors hammered MISP simultaneously (`AppModel.php`
"Cannot use a scalar value as an array" warnings cascading into 5xx
responses on edit-event calls).

**Order rationale:** the order is mostly aesthetic — small-first
(CISA ~14s, MITRE ~28s) reads more naturally in the Airflow grid view.
It does **not** give automatic fast-fail: the TaskGroup keeps its
`trigger_rule = ALL_DONE` (preserved from the parallel design) so a
single-source API flake doesn't cascade-skip the rest of tier-1 — losing
1/4 of a baseline is much better than losing all of it. The real value
of PR-F4 is **halved MISP write concurrency**, which is independent of
the collector ordering.

**Trade-off:** total tier-1 wall time grows from `max(otx, nvd) ≈ 5h` to
`cisa + mitre + otx + nvd ≈ 8h`. The ~3h cost buys halved MISP write
concurrency without any MISP server changes.

**What this DOES NOT fix:** the per-event-grows-with-size cost on a
single oversized event (MISP `edit-event` loads the entire event for
dedup; cost grows linearly with existing attribute count). That's an
architectural fix tracked separately — see [Issue #61](../../issues/61)
for event partitioning by date range so no single event exceeds
~20K attributes.

**Tier 2 stays parallel** — the 6 reputation feeds are individually tiny
(<5K attrs each), don't trigger the oversized-event failure mode, and
their parallel write pressure on MISP is negligible compared to OTX/NVD.

### Parent-DAG liveness check (PR-F6, Issue #65, 2026-04-20)

The four tier-1 baseline collectors install a **parent-DAG liveness
callback** that polls the Airflow REST API between MISP push batches
and exits cleanly if the parent `dag_run` is no longer in `running`
or `queued` state. This closes the **orphan-collector-process gap**
that produced Event 19 + 72,479-CVE duplication on 2026-04-19:

> A failed `edgeguard_baseline` DAG run kept its `collect_nvd` Python
> subprocess alive for 12+ hours after Airflow marked the run failed.
> The orphan eventually pushed 78,313 attributes to MISP **after** the
> next manual run's `baseline_clean` had already wiped MISP.

**Root cause**: when a DAG run is marked `failed` (because *another*
task in the same run failed), Airflow does NOT auto-kill in-flight
tasks of that run. The collector keeps running in its worker
subprocess until it finishes naturally or hits its 5h timeout.

**The fix**: between MISP push batches (already throttled 5s by
`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`), the collector calls a callback
that probes the Airflow REST API (rate-limited to one probe per
60s). If the parent `dag_run` is in any terminal state, the callback
raises `AbortedByDagFailureException` — the **current batch finishes**
its write to MISP cleanly, the **next batch never starts**.

**Trade-offs**:
- ✅ Clean exit between batches → no half-written MISP events
- ✅ Fail-OPEN → transient Airflow API blip doesn't false-kill the collector
- ✅ Per-collector opt-in via `EDGEGUARD_PARENT_DAG_LIVENESS_CHECK` (default `true` for baseline)
- ✅ Low overhead (~1 small HTTP call per minute)
- ⚠️ Up to 60s lag between DAG-marked-failed and collector-noticing (configurable via `EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC`)

**Operator visibility**: when the safeguard fires, you'll see this in the collector log:

```
WARNING [PARENT_DAG_DEAD] dag_run=edgeguard_baseline/manual__2026-04-19T22:46:59
        observed state='failed' — aborting collector cleanly. Orphan-process
        safeguard (PR-F6) prevented late writes to MISP/Neo4j.
```

Grep `PARENT_DAG_DEAD` in your DAG logs to find every aborted-by-parent-failure
event. If you see it firing on healthy runs, your Airflow API is unreachable
from the collector worker (check `AIRFLOW_WEBSERVER_URL` env).

**What this DOES NOT do**: the safeguard runs collector-side, so it
can't help if the collector itself is wedged (e.g., blocked in a
syscall, in a non-MISP loop). For those cases, the existing
`execution_timeout` per task remains the backstop. Combine the two
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

Airflow UI → DAGs → `edgeguard_baseline` → Trigger DAG (▶)

### Step 3 — After completion

The incremental DAGs (`edgeguard_pipeline`, `edgeguard_medium_freq`, etc.) are already scheduled and will start maintaining the graph automatically. No further action needed.

### Baseline collection behaviour

| Source | Baseline mode | Note |
|--------|--------------|------|
| NVD | `baseline=True` — date-range paged, up to `BASELINE_DAYS` back | Resumes from checkpoint on restart |
| OTX | `baseline=True` — date-range paged, up to `BASELINE_DAYS` back | Resumes from checkpoint on restart |
| CISA / MITRE | Full catalog fetch | Already returns complete list |
| ThreatFox / URLhaus / Feodo / etc. | Full current feed | Flat feeds, no history API |

---

## Incremental Collection Limit

Regular cron DAGs (every 30 min / 4 h / 8 h / daily) scan only the **last 2-3 days** of new data. A per-source item cap keeps each run fast and prevents accidental re-ingestion of bulk historical data.

### Configuration

Set `EDGEGUARD_INCREMENTAL_LIMIT` in `.env` (or docker-compose environment):

```bash
# Default — 200 items per source per cron run
EDGEGUARD_INCREMENTAL_LIMIT=200

# Larger window for high-volume sources
EDGEGUARD_INCREMENTAL_LIMIT=500

# No item cap — only the 72-hour time window applies (use with caution)
EDGEGUARD_INCREMENTAL_LIMIT=0
```

This is a **per-source** limit. With **11** active external collectors in the incremental DAGs at the default of 200, a full cycle collects at most **~2,200 items** (plus optional separate VirusTotal enrichment runs if enabled).

### Priority order in `get_effective_limit()`

```
1. NO_LIMIT_SOURCES (per-source bypass in config.py)   → None (unlimited)
2. EDGEGUARD_MAX_ENTRIES ≠ 0 (hard global override)    → that value
3. EDGEGUARD_INCREMENTAL_LIMIT > 0 (default: 200)      → 200
4. EDGEGUARD_INCREMENTAL_LIMIT = 0                     → None (unlimited)
```

### Baseline vs Incremental — quick reference

| | Baseline | Incremental |
|--|----------|-------------|
| Item cap | `BASELINE_COLLECTION_LIMIT` (Airflow Variable, default unlimited) | `EDGEGUARD_INCREMENTAL_LIMIT` (env var, default 200/source) |
| Lookback | `BASELINE_DAYS` (Airflow Variable, default 730 days) | Last 72 hours |
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
| `(Indicator)-[:INDICATES]->(Malware)` | Shared MISP event id from `misp_event_ids[]` (co-occurrence) in `build_relationships.py` | Initial **0.5**, `match_type='misp_cooccurrence'`, `source_id='misp_cooccurrence'`; then **0.30–0.50** via `calibrate_cooccurrence_confidence()` from event size (co-occurrence ceiling: 0.50) |
| `(Indicator)-[:EXPLOITS]->(CVE\|Vulnerability)` | Indicator `cve_id` matches node `cve_id` | **1.0**, `match_type='cve_tag'`, `source_id='cve_tag_match'` (not bulk-calibrated like co-occurrence) |
| `(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)` | `t.mitre_id IN a.uses_techniques` — **explicit STIX from MITRE bundle** | **0.95** (`match_type='mitre_explicit'`) |
| `(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)` | `t.mitre_id IN m.uses_techniques` — **same STIX `uses` rows** (malware → attack-pattern) | **0.95** (`match_type='mitre_explicit'`) |
| `(Tool)-[:IMPLEMENTS_TECHNIQUE]->(Technique)` | `t.mitre_id IN tool.uses_techniques` — **same STIX `uses` rows** (tool → attack-pattern) | **0.95** (`match_type='mitre_explicit'`) |
| `(Technique)-[:IN_TACTIC]->(Tactic)` | MITRE ATT&CK taxonomy | **1.0** |

**Note on Actor/Malware/Tool → Technique:** All three are sourced from **explicit** STIX **`relationship_type: uses`** objects in the MITRE ATT&CK bundle — **not** from fuzzy text matching and **not** from actor/technique MISP co-occurrence (which is always empty). The MITRE collector populates **`uses_techniques`** on actors directly from the bundle; for **malware** and **tool**, the same list is embedded in MISP as **`MITRE_USES_TECHNIQUES:{...}`** on the attribute comment so `run_misp_to_neo4j` can restore **`uses_techniques`** on **`Malware`** / **`Tool`** nodes. `build_relationships.py` uses `WHERE t.mitre_id IN coalesce(node.uses_techniques, [])` per label and emits the specialized edge type matching the source label.

> **2026-04 refactor note:** Prior to April 2026 all three edges were a single generic `USES`. They were split into `EMPLOYS_TECHNIQUE` (attribution — actor/campaign) and `IMPLEMENTS_TECHNIQUE` (capability — malware/tool) to improve Cypher clarity and LLM/GraphRAG retrieval. Both edges collapse back to STIX 2.1 `relationship_type: "uses"` on export. *Pre-release framework — no migration script is shipped; a fresh baseline rerun writes the specialized edge types directly.* See [`docs/KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation) for the semantic rationale.

> **PR #33 round 10 — array-only INDICATES co-occurrence:** the legacy
> first-seen scalar `misp_event_id` was dropped pre-release. The Indicator
> → Malware co-occurrence query is now array-only on both ends — outer
> filter selects Indicators with a non-empty `misp_event_ids[]`; inner
> Malware match uses `eid IN m.misp_event_ids` for IN-membership. Mirrored
> in `src/run_pipeline.py` for the optional CLI path.

### 2. run_enrichment_jobs

Runs `src/enrichment_jobs.py` — **four** jobs in sequence (`run_all_enrichment_jobs`):

1. **Vulnerability↔CVE bridge** (`bridge_vulnerability_cve` — `REFERS_TO`)
2. **Campaign nodes** (`build_campaign_nodes`)
3. **Co-occurrence calibration** (`calibrate_cooccurrence_confidence`)
4. **IOC confidence decay** (`decay_ioc_confidence` — idempotent last step)

#### IOC Confidence Decay

Threat intelligence has a shelf life. Indicators not updated recently lose confidence automatically.

| Days since `last_updated` | Effect on Indicator |
|--------------------------|---------------------|
| < 90 days | No change |
| 90–180 days | confidence × 0.85 (−15%) |
| 180–365 days | confidence × 0.70 (−30%) |
| > 365 days | `active = false` (retired, not deleted) |
| Any | Minimum floor: 0.10 |

Retired nodes remain in the graph for historical queries — they are never deleted.

#### Campaign Node Builder

Materialises `Campaign` nodes from the existing graph structure. A Campaign is created for each `ThreatActor` that has at least one attributed malware and at least one related indicator.

```
ThreatActor -[:ATTRIBUTED_TO]<- Malware -[:INDICATES]<- Indicator
    ↓                                ↓                       ↓
 [:RUNS]→ Campaign ←───────── [:PART_OF] ←──────── [:PART_OF]
```

Campaign properties: `name`, `actor_name`, `first_seen`, `last_seen`, `zone`, `indicator_count`, `malware_count`.

#### Co-occurrence Confidence Calibration

Adjusts **INDICATES** and **EXPLOITS** edge confidence **when** `r.source_id IN ('misp_cooccurrence', 'misp_correlation')`, using the number of indicators in the same MISP event. (CVE-tag `EXPLOITS` edges use `source_id='cve_tag_match'` and are not tuned by this pass.)

| Event size (indicators in same event) | Confidence set to |
|--------------------------------------|-------------------|
| ≤ 10 (tight incident report) | 0.50 |
| 11–20 (small report) | 0.45 |
| 21–100 (medium feed) | 0.40 |
| 101–500 (large feed) | 0.35 |
| > 500 (bulk dump, e.g. Feodo) | 0.30 |

Only edges with `source_id IN ['misp_cooccurrence', 'misp_correlation']` are modified. Manually curated edges are untouched.

> **Multi-event event sizing (array-only):** the event-size pre-compute
> UNWINDs `misp_event_ids[]` and counts distinct Indicators per event id,
> so multi-event Indicators contribute to the size of every event they
> appear in. The matcher and the large-event `apoc.periodic.iterate`
> path use the same array IN-membership semantics; the large-event path
> uses APOC's `params:` config so the event id is bound (no f-string
> interpolation).

> **Multi-event re-activation in `mark_inactive_nodes`:** a node is
> active if ANY event in its `misp_event_ids[]` array is currently
> active (`any(eid IN n.misp_event_ids WHERE eid IN $active_ids)`).
> Both Indicators and Vulnerabilities have re-activation (any) AND
> deactivation (none) gates. `retired_at` (manual decommission) wins
> over the auto-active reset.

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

```
Confidence Score = Base + Source Bonus + Freshness Bonus

Where:
- Base Score = 0.4 (default for single source)
- Source Bonus = +0.2 per corroborating source
- Freshness Bonus = +0.1 if updated < 24h ago
- Max Score = 1.0
- Min Score = 0.1
```

### Provenance Tracking Properties

Per the **PR #41 source-truthful architecture** (see
[`migrations/2026_04_first_seen_at_source.md`](../migrations/2026_04_first_seen_at_source.md)),
**node-level timestamps are DB-local only** — per-source observation
claims live on the `SOURCED_FROM` edge so multi-source IOCs preserve
full provenance. The legacy `n.first_seen` field has been retired.

| Property | Where | Type | Description |
|----------|-------|------|-------------|
| `sources` | node | List[String] | All sources that reported this entity |
| `first_imported_at` | node | Timestamp | When EdgeGuard first imported the node (ON CREATE only — never overwritten) |
| `last_updated` | node | Timestamp | DB-local refresh timestamp (set on every MERGE) |
| `confidence_score` | node | Float | 0.1 - 1.0 (corroboration-based) |
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

```
Confidence Score = Base Score + Source Bonus - Penalty

Where:
- Base Score = 0.5 (default)
- Source Bonus = +0.1 per corroborating source
- Penalty = -0.2 for single-source unverified
- Max Score = 1.0
- Min Score = 0.1
```

## Airflow Setup Requirements

**Docker Compose (`docker-compose.yml`):** the **`airflow`** service is **built** from **`Dockerfile.airflow`**, which installs **`requirements-airflow-docker.txt`** (e.g. **`neo4j`**, **`pymisp`**, **`apache-airflow-providers-standard`**) on top of **`apache/airflow:3.2.0-python3.12`**. After dependency changes, run **`docker compose build airflow`**. The service uses **`LocalExecutor`** with **PostgreSQL** (`airflow_postgres`) for metadata. Optional credentials: `AIRFLOW_POSTGRES_*` in `.env`. If runs stall, see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) troubleshooting; for operators upgrading from an existing 2.11 deployment see [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md#airflow-2-to-3-upgrade).

```bash
# Install Airflow + PostgreSQL driver (matches docker-compose metadata backend)
pip install "apache-airflow[postgres]~=3.2" "apache-airflow-providers-standard~=1.5"
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
- Each source group runs at its own cadence to respect API rate limits — no more one-DAG-for-all.
- **`edgeguard_neo4j_sync`** uses a `ShortCircuitOperator` (`check_sync_needed` / `should_run_neo4j_sync`) so the
  heavy sync is skipped when nothing new is available in MISP.
- All `python_callable` values are direct function references (no lambdas) — lambda functions
  cannot be serialized by Airflow 2.x DAG serialization and cause `PicklingError` on workers.
- Every task has an `execution_timeout` — see table above.
- The Prometheus metrics server runs in `edgeguard_metrics_server.py`, not at DAG module level.


---

_Last updated: 2026-04-18 — PR #41 cleanup pass updated the 2026-04 USES→specialized-edge refactor note to reflect pre-release posture (no migration script ships; a fresh baseline rerun writes the specialized edge types). `Dockerfile.airflow` base **`apache/airflow:3.2.0-python3.12`** (Python 3.12), upgraded from 2.11.2 in the April 2026 Airflow 2→3 upgrade — see [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md#airflow-2-to-3-upgrade) for the operational rollout._
