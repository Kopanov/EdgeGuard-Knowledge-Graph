# EdgeGuard Architecture

## Overview

EdgeGuard is a **Graph-Augmented xAI Threat Intelligence System** for edge infrastructure — a collaboration between **IICT-BAS + Ratio1**, financed by **ResilMesh**.

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    EXTERNAL SOURCES                         │
│  (OTX, NVD, CISA, MITRE, VirusTotal, Feodo, URLhaus...)    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              COLLECTORS (per source)                       │
│  • Fetch data from 11 active sources (+ 2 sector placeholders) │
│  • Detect zone(s) using detect_zones_from_text()          │
│  • Return indicators with zone: ['healthcare', 'finance'] │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     MISP (hub)                             │
│  • Receives all data from collectors                      │
│  • Tags with source (e.g., "source:AlienVault-OTX", "source:NVD") │
│  • Tags with zone(s): "zone:Finance", "zone:Healthcare"  │
│    - ALL detected specific zones get tagged equally       │
│    - Events organized by zone in MISP                     │
│  • Stores everything (single source of truth)             │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│   MISP → Neo4j (Airflow: MISPToNeo4jSync.run)              │
│  • Fetches EdgeGuard events (``/events/index`` + filter; restSearch fallback) │
│  • Loads full event JSON → parse_attribute() per flat row   │
│  • MERGE nodes + relationships (not a STIX bundle load)     │
│  • MISP ``Object`` / nested attrs: not ingested yet (flat   │
│    ``Attribute`` list only) — see run_misp_to_neo4j logs    │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                     Neo4j                                  │
│  • Indicator, CVE, Malware, ThreatActor, Technique, …     │
│  • ``zone`` and ``source`` as arrays on nodes               │
│  • Cross-item relationships after per-event parse           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              POST-SYNC (edgeguard_neo4j_sync + baseline)   │
│  1. build_relationships.py —                                │
│     Actor → Technique (EMPLOYS_TECHNIQUE, MITRE explicit),  │
│     Malware/Tool → Technique (IMPLEMENTS_TECHNIQUE, MITRE), │
│     Indicator → Technique (USES_TECHNIQUE, OTX attack_ids), │
│     IOC↔malware/CVE,                                        │
│     malware_family name match → Malware (INDICATES, 0.8),   │
│     co-occurrence INDICATES, sector edges                   │
│  2. enrichment_jobs — campaigns (RUNS/PART_OF),            │
│     confidence calibration, IOC decay (order inside module) │
└─────────────────────────────────────────────────────────────┘
```

### Pipeline flow (what actually runs where)

**Airflow (default production path)** — `dags/edgeguard_pipeline.py` calls `MISPToNeo4jSync().run()`:

```
Collectors → MISP → [per MISP event] parse_attribute() → dedupe → cross-item edges (same event only)
              → sync_to_neo4j() (Python chunks) → create_misp_relationships_batch() (UNWIND batches) → Neo4j
```

No STIX bundle is materialized on this path: each MISP attribute is parsed into EdgeGuard item dicts. **Cross-item** relationships (e.g. co-occurrence-style edges produced during sync) are built from **one event’s item list only** — do not pass a global multi-event list into `_build_cross_item_relationships` (see `run_misp_to_neo4j.py` docstring). **Node** merges use Python-side chunks (`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`); **relationship** writes use **`EDGEGUARD_REL_BATCH_SIZE`** (default **500** definitions per UNWIND). Optional **`EDGEGUARD_DEBUG_GC`** enables `gc.collect()` after each node chunk (diagnostics; can hurt RAM on small workers).

**CLI / `run_pipeline.py` (optional)** — with `use_stix_flow=True` (default for **`python src/run_pipeline.py`** step 3 when STIX is available):

```
MISP → convert_to_stix21() / PyMISP to_stix2 → load_stix21_to_neo4j() → Neo4j
```

STIX is also used for **export** (`--stix`, `export_to_stix21`) and lives in **`MISPToNeo4jSync.convert_to_stix21`** / **`fetch_stix21_from_misp`** for tooling — those helpers are **not** invoked by **`MISPToNeo4jSync.run()`** used from Airflow.

**After sync** — DAG **`edgeguard_neo4j_sync`** runs **`build_relationships.py`**, then **`enrichment_jobs.run_all_enrichment_jobs`** (bridge, campaigns, calibration, decay). Baseline DAG runs the same pattern after **`full_neo4j_sync`**.

---

## Zone Detection

### Keywords and zone scoring
Sector keywords live in **`config.py`** as **`SECTOR_KEYWORDS`**. Matching is **not** a simple “any keyword hits” boolean — production code uses:

- **`detect_zones_from_text(text, default_zone=..., context=...)`** — weighted scores per sector, **negative keyword** exclusions, compiled regex patterns (**`_SECTOR_PATTERNS`**), and **`ZONE_DETECT_THRESHOLD`** (default **1.5**, env **`EDGEGUARD_ZONE_DETECT_THRESHOLD`**). Context weights: `name`/`alias`/`title` **3.0**, `description` **2.0**, `body` **1.5**, `tag` **1.0** — see `config.py`.
- **`detect_zones_from_item(item)`** — combines multiple fields with **`ZONE_ITEM_COMBINED_THRESHOLD`** (default **1.5**, env **`EDGEGUARD_ZONE_ITEM_THRESHOLD`**). **NVD** uses this with **`description`** + **`comment`** filled from **`configurations_to_zone_text()`** (CPE criteria + vendor/product tokens), not `json.dumps` of the raw JSON.

Collectors pass contextual text into these helpers; items carry **`zone`** as a **list** (e.g. `['finance', 'healthcare']` or `['global']`).

**Do not** copy simplified pseudo-code from older docs — **`src/config.py`** is the source of truth.

### MISP → Neo4j Zone Resolution (Priority Layers)

When attributes are read from MISP and written to Neo4j, zone resolution follows a three-layer priority model implemented in `run_misp_to_neo4j.py`:

```
Priority 1: Attribute-level zone tags  (most precise — exclusive if specific)
Priority 2: Event-level zone/sector tags + zone from Event.info  (merged; "global" dropped if any specific exists)
Priority 3: "global"  (fallback only)
```

**MISP events created by `MISPWriter`** use **`EdgeGuard-{source}-{date}`** as the event name, with the **`EdgeGuard`** tag at event level. **Zone classification** lives exclusively on **attribute-level tags** (`zone:Finance`, `zone:Healthcare`) — a single event can contain multi-zone attributes. Attribute `zone:` tags are the primary classification signal for Neo4j sync.

**Collectors → MISP:** Optional **per-event attribute prefetch** and **source-specific** incremental cursors reduce duplicate writes when event names rotate by date — see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*.

Merging rule — never drop zones from any source:
```python
# Collect from all sources, prefer specific over global
all_zones = set(event_tag_zones) | {zone_from_event_name}
specific  = {z for z in all_zones if z != "global"}
result    = sorted(specific) if specific else ["global"]
```

This prevents two confirmed bugs from the 2026-03 debug audit:
- **H1** (zone combination): event name `FINANCE` + tag `zone:healthcare` → `['finance', 'healthcare']`
- **H3** (fallback override): no attribute zone, event has `zone:healthcare` tag, event name `GLOBAL` → `['healthcare']`

All zone values are validated against `VALID_ZONES` in `config.py` before any write.

### MISP → Neo4j sync chunking (worker memory)

`sync_to_neo4j()` merges parsed items in **Python-side chunks** to limit RAM on huge attribute counts. Env **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**: default **`500`**; **`0`** or **`all`** (case-insensitive) forces a **single pass** (legacy memory profile, **OOM risk** on tens of thousands of items — expert/debug only). `Neo4jClient.merge_*_batch` still UNWINDs in sub-batches. Relationship creation uses **`EDGEGUARD_REL_BATCH_SIZE`** and **`Neo4jClient.create_misp_relationships_batch`** (per-query error handling; partial success possible — see module docstring). See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [HEARTBEAT.md](HEARTBEAT.md) for worker OOM vs Airflow “task failed” symptoms.

### ThreatActor / Malware / Tool → Technique Relationship Sources

**`(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)`**, **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`**, and **`(Tool)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** are built from the **explicit STIX `uses` relationship objects** in the MITRE ATT&CK bundle — **not** from substring / `CONTAINS` matching and **not** from cross-event co-occurrence (which yields 0 for actor/technique pairs).

> **History:** Prior to 2026-04 all three were a single generic `USES` edge. The split was made to distinguish **attribution** (actor employs a TTP) from **capability** (malware/tool implements a TTP), which matters for both Cypher query clarity and GraphRAG retrieval. *Pre-release framework — no migration script is shipped; a fresh baseline rerun writes the specialized edge types directly.* The property name **`uses_techniques`** on nodes is a STIX-side serialization field and was intentionally left unchanged.

The MITRE collector populates **`uses_techniques: [T1059, ...]`** on each **ThreatActor**, **Malware**, and **Tool** item; malware IDs round-trip through MISP via the **`MITRE_USES_TECHNIQUES:`** attribute comment (same idea as **`NVD_META:`** for CVEs). `build_relationships.py` matches `WHERE t.mitre_id IN coalesce(node.uses_techniques, [])` per label, writing the appropriate specialized edge type. Edge confidence **`0.95`**, **`match_type = 'mitre_explicit'`**.

---

See [DATA_SOURCES.md](DATA_SOURCES.md) for the complete source inventory.

---

## MISP Zone Tagging (Equal Importance Logic)

### MISPWriter Helper: `_get_zones_to_tag()`

The `MISPWriter` class includes a `_get_zones_to_tag()` helper that implements equal-importance zone tagging:

```python
def _get_zones_to_tag(self, item: Dict) -> List[str]:
    """
    Determine which zone tags to apply based on equal-importance logic.
    
    Rules:
    - All detected specific zones (healthcare, energy, finance) are equal - tag ALL
    - Global is special:
      * If specific zones + global detected → tag only specific zones (global is implicit)
      * If ONLY global detected → tag global as primary
    
    Returns:
        List of zone names to tag
    """
    # Get zones from zone array property
    zones = item.get('zone', [DEFAULT_SECTOR])
    if not isinstance(zones, list):
        zones = [zones] if zones else [DEFAULT_SECTOR]
    
    # Filter logic:
    # - If 'global' in zones AND other zones exist: exclude 'global' (it's implicit)
    # - If ONLY 'global' in zones: keep 'global'
    # - Otherwise: keep all zones
    specific_zones = [z for z in zones if z and z != 'global']
    
    if specific_zones:
        # We have specific zones - tag them all equally
        return specific_zones
    else:
        # Only global - tag it
        return [z for z in zones if z] or [DEFAULT_SECTOR]
```

### Tagging Rules

| Scenario | Example `zone` | Tags Applied |
|----------|----------------|--------------|
| Single specific zone | `['finance']` | `zone:Finance` |
| Multiple specific zones | `['finance', 'healthcare']` | `zone:Finance`, `zone:Healthcare` |
| Specific + global | `['finance', 'global']` | `zone:Finance` (global implicit) |
| Only global | `['global']` | `zone:Global` |

### MISP Tags Applied

When data is pushed to MISP, it gets tagged with:

| Tag Category | Example | Description |
|--------------|---------|-------------|
| Zone | `zone:Finance` | All detected zones (equal importance) |
| Source | `source:AlienVault-OTX` | Original data source |
| Confidence | `confidence:high` | Based on confidence_score |
| Severity | `severity:HIGH` | For vulnerabilities |
| CVSS | `cvss:critical` | CVSS score category |
| Malware Family | `malware-family:emotet` | For malware indicators |

---

## Neo4j Schema

### Nodes
- **Indicator** - IP, domain, hash, URL
- **Vulnerability** - CVE
- **Malware** - Malware families
- **ThreatActor** - Threat actors
- **Technique** - MITRE techniques
- **Source** - Data sources

### Properties
```python
# Indicator node — zone is ALWAYS a list, never a single string
{
    'value': '192.168.1.1',
    'indicator_type': 'ipv4',
    'zone': ['finance', 'healthcare'],  # Array — no separate 'zones' property
    'tag': 'alienvault_otx',            # Source tag (part of UNIQUE constraint)
    'source': ['alienvault_otx'],       # On Neo4j node: property name is ``source`` (list); merged via apoc.coll.toSet
    'confidence_score': 0.8,
}
# Per-source raw payload and merge metadata also live on ``SOURCED_FROM`` edges.
# See KNOWLEDGE_GRAPH.md → SOURCED_FROM and neo4j_client.merge_node_with_source.
```

### Relationships

| Relationship | From → To | How it is created |
|---|---|---|
| `SOURCED_FROM` | Node → Source | Every merge; carries `raw_data`, `confidence`, `imported_at`, `updated_at`, `source_reported_first_at`, `source_reported_last_at`, `src_uuid`, `trg_uuid`, `edgeguard_managed`. **One edge per (entity, source) pair** — multi-source IOCs preserve full per-source provenance. See [KNOWLEDGE_GRAPH.md → SOURCED_FROM edge schema](KNOWLEDGE_GRAPH.md#sourced_from-edge-schema). |
| `EMPLOYS_TECHNIQUE` | ThreatActor / Campaign → Technique | Attribution — MITRE STIX **`uses`** → `uses_techniques` on actor → `build_relationships.py`. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Malware / Tool → Technique | Capability — MITRE STIX **`uses`** → `uses_techniques` on malware/tool (MISP **`MITRE_USES_TECHNIQUES:`** round-trip for malware) → `build_relationships.py`. *(Split from a generic `USES` in 2026-04.)* |
| `USES_TECHNIQUE` | Indicator → Technique | Observation — OTX `attack_ids` on indicator → `build_relationships.py` (confidence 0.85). |
| `ATTRIBUTED_TO` | Malware → ThreatActor | MITRE / MISP event data |
| `INDICATES` | Indicator → Malware | MISP event co-occurrence (`misp_event_ids[]` array IN-membership match) |
| `EXPLOITS` | Indicator → CVE/Vulnerability | Indicator tagged with matching `cve_id` |
| `IN_TACTIC` | Technique → Tactic | MITRE ATT&CK tactic phases |
| `TARGETS` | Indicator → Sector | Node `zone` list → `build_relationships.py` |
| `AFFECTS` | Vulnerability/CVE → Sector | Node `zone` list → `build_relationships.py` |
| `RUNS` | ThreatActor → Campaign | Built by `enrichment_jobs.build_campaign_nodes()` |
| `PART_OF` | Malware / Indicator → Campaign | Built by `enrichment_jobs.build_campaign_nodes()` |

All relationship `sources` arrays are accumulated as sets — no duplicates on re-sync.
`imported_at` is set once on first creation (`ON CREATE SET`) and never overwritten.

**Source-truthful timestamps on `SOURCED_FROM` edges (PR S5, 2026-04;
PR-M2 hardening, 2026-04):**
The two new edge properties `r.source_reported_first_at` /
`r.source_reported_last_at` carry the per-source first/last claim
("NVD says it published 2013-01-15", "AbuseIPDB says it first reported
2024-01-15"). Updated via MIN/MAX CASE with NULL short-circuit so
stale imports cannot regress earlier claims. Node-level
`n.first_imported_at` (ON CREATE SET only) and `n.last_updated`
(refreshed every MERGE) carry only DB-local truths — they cannot be
misread as real-world claims. STIX export aggregates MIN across all
edges for `valid_from`; when no source claim exists, `valid_from`
falls back to `first_imported_at` and the SDO is stamped with
`x_edgeguard_first_seen_inferred=true` so consumers can filter for
source-truthful evidence (PR-M2 design choice). The complete
**timestamp semantic model** is documented in
[`docs/TIMESTAMPS.md`](TIMESTAMPS.md) — invariants (honest-NULL +
tz-aware UTC), per-collector source-field mapping, STIX 2.1 export
contract for Indicator vs. Vulnerability vs. Report SDOs, and the
backwards-compatibility plan for pre-PR-M2 data.

**MISP traceability on edges (PR-N26, 2026-04-23):** the four edge types
MERGEd by `build_relationships.py` from the MISP path —
`INDICATES` (Indicator → Malware, both co-occurrence + family-match
patterns), `EXPLOITS` (Indicator → CVE / Vulnerability), `TARGETS`
(Indicator → Sector), and `AFFECTS` (Vulnerability → Sector) — accumulate
`r.misp_event_ids[]` via `apoc.coll.toSet`, same shape as the node-level
array. The `apoc.coll.toSet(coalesce + CASE)` write pattern is idempotent
on re-sync. The `_misp_event_id` scalar field was deleted in PR-N17 —
all readers now use list-membership predicates (`eid IN
n.misp_event_ids`).

Edges built BEFORE PR-N26 have no array set; backfill via
[`scripts/backfill_edge_misp_event_ids.py`](../scripts/backfill_edge_misp_event_ids.py)
+ the [`migrations/2026_05_edge_misp_event_ids_backfill_runbook.md`](../migrations/2026_05_edge_misp_event_ids_backfill_runbook.md)
runbook. The other edge types created via
`Neo4jClient.create_misp_relationships_batch` (`EMPLOYS_TECHNIQUE`,
`IMPLEMENTS_TECHNIQUE`, `ATTRIBUTED_TO`) do **not** carry
`r.misp_event_ids[]` today — those edges are derived from STIX
relationships and the provenance flows through the endpoint nodes.

Per-attribute IDs are deliberately **not** stored on edges (cardinality
blowup for marginal benefit) — attribute UUIDs live on the Indicator
node only as `i.misp_attribute_ids[]`.

**MISP traceability on Indicator nodes:** `i.misp_attribute_ids[]` holds the
originating MISP attribute UUIDs — the stable cross-instance identifiers
from `attr.uuid`. The forward fix is in
[run_misp_to_neo4j.py `parse_attribute`](../src/run_misp_to_neo4j.py).

**Array-only provenance (PR #33 round 10):** every MISP-derived consumer
(`mark_inactive_nodes`, `calibrate_cooccurrence_confidence`, the INDICATES
co-occurrence query in `build_relationships.py` and `run_pipeline.py`,
STIX export) reads only `misp_event_ids[]` / `misp_attribute_ids[]`. The
legacy first-seen scalars `misp_event_id` / `misp_attribute_id` were
removed pre-release — multi-event nodes are tracked via the array's full
list of contributing events with `any(eid IN n.misp_event_ids WHERE eid IN
$active_ids)` semantics.

**Cross-environment traceability (2026-04, PR #33):** every node carries a
deterministic `n.uuid` = `uuid5(namespace, canonical(label, natural_key))`
and every MISP-derived edge carries `r.src_uuid` / `r.trg_uuid`. Same input
→ same uuid on every Neo4j instance, so:

- A delta-sync push to a cloud Neo4j MERGEs nodes by uuid (no natural-key
  resolution); edges re-attach via `MATCH (a {uuid: $src_uuid})` /
  `MATCH (b {uuid: $trg_uuid})`.
- Edge documents are self-describing for LLM/RAG consumers — `src_uuid` /
  `trg_uuid` resolve back to nodes lazily.
- The UUID portion of a STIX SDO id (from `src/stix_exporter.py
  _deterministic_id`) **equals** the corresponding Neo4j `n.uuid` for
  Indicator, Malware, ThreatActor (→ STIX intrusion-set), Technique
  (→ STIX attack-pattern), Vulnerability, CVE, Sector, Campaign. Tool is
  the one documented exception — see [CLOUD_SYNC.md](CLOUD_SYNC.md).

The implementation lives in [src/node_identity.py](../src/node_identity.py)
and is wired into every node MERGE in `Neo4jClient` plus the 12 link
queries in `build_relationships.py`. *Pre-release framework — no backfill
script ships; a fresh baseline rerun stamps every uuid at write time. See
[MIGRATIONS.md](MIGRATIONS.md) for the heal-by-rebaseline contract.*

---

## Data Sources (13 Total)

> **Single source of truth — `src/source_registry.py`.** Adding a new
> data source is a one-line `Source(...)` entry there. Five legacy
> registries (`neo4j_client.SOURCES`, `edgeguard.DEFAULT_SOURCES`,
> `config.SOURCE_TAGS`, `source_truthful_timestamps._RELIABLE_FIRST_SEEN_SOURCES`,
> `MISPWriter.SOURCE_TAGS`) all derive from it; before the chip-5a
> refactor each was hand-maintained and forgetting any one produced
> a different silent-failure mode (see the module docstring for the
> full failure-mode catalog).

| Code | Full Name | Type | Collector Module |
|------|-----------|------|------------------|
| alienvault_otx | AlienVault OTX | Threat Intel | otx_collector.py |
| nvd | NVD | Vulnerability DB | nvd_collector.py |
| cisa | CISA KEV | Advisory | cisa_collector.py |
| mitre_attck | MITRE ATT&CK | Framework | mitre_collector.py |
| virustotal | VirusTotal | Threat Intel | `vt_collector.py` (scheduled); `virustotal_collector.py` (enrichment task) |
| abuseipdb | AbuseIPDB | IP Reputation | abuseipdb_collector.py |
| feodo_tracker | Feodo Tracker | Threat Intel | finance_feed_collector.py |
| ssl_blacklist | SSL Blacklist | Threat Intel | finance_feed_collector.py |
| urlhaus | URLhaus | Threat Intel | global_feed_collector.py |
| cybercure | CyberCure | Threat Intel | global_feed_collector.py |
| threatfox | ThreatFox | Threat Intel | global_feed_collector.py |
| healthcare | Healthcare Feeds | Threat Intel | healthcare_feed_collector.py (placeholder) |
| energy | Energy Feeds | Threat Intel | energy_feed_collector.py (placeholder) |

---

## Limit Logic

See [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) for detailed limit reference.

---

## Key Files

| File | Purpose |
|------|---------|
| `src/config.py` | Configuration, zone detection functions |
| `src/collectors/misp_writer.py` | MISP tagging with `_get_zones_to_tag()` |
| `src/collectors/otx_collector.py` | AlienVault OTX collector |
| `src/collectors/nvd_collector.py` | NVD CVE collector |
| `src/collectors/cisa_collector.py` | CISA KEV collector |
| `src/collectors/mitre_collector.py` | MITRE ATT&CK collector |
| `src/collectors/vt_collector.py` | VirusTotal — primary `VTCollector` used by medium-freq DAG |
| `src/collectors/virustotal_collector.py` | VirusTotal — `VirusTotalCollector` enrichment DAG path |
| `src/collectors/finance_feed_collector.py` | Feodo, SSL Blacklist collectors |
| `src/collectors/global_feed_collector.py` | URLhaus, CyberCure, ThreatFox collectors |
| `src/collectors/healthcare_feed_collector.py` | Healthcare placeholder |
| `src/collectors/energy_feed_collector.py` | Energy placeholder |
| `src/collectors/misp_collector.py` | Fetch/normalize events from MISP API (ingest) — **not** used in default baseline collector tier |
| `src/run_misp_to_neo4j.py` | **Airflow MISP→Neo4j**: `fetch_edgeguard_events`, `parse_attribute`, `sync_to_neo4j`, optional STIX helpers for CLI/export |
| `src/run_pipeline.py` | CLI orchestration; optional **STIX flow** to Neo4j; collector steps to MISP |
| `src/enrichment_jobs.py` | Post-sync enrichment: Vulnerability↔CVE `REFERS_TO` bridge, campaigns, co-occurrence calibration, IOC decay |
| `src/build_relationships.py` | Graph relationship builder (exact / MITRE-ID / scoped co-occurrence — **no `CONTAINS`**) |
| `dags/edgeguard_pipeline.py` | Six primary DAGs (collection + baseline + sync + enrichment tasks) |
| `dags/edgeguard_metrics_server.py` | Optional long-running Prometheus metrics DAG(s) |
| `src/query_api.py` | FastAPI REST API — threat queries, indicator search, zone filtering (port 8000) |
| `src/graphql_api.py` | **GraphQL API** — Strawberry/FastAPI endpoint on port 4001, mirroring ISIM GraphQL |
| `src/graphql_schema.py` | Strawberry type definitions for all node types (CVE, Vulnerability, Indicator, etc.) |

---

## GraphQL API (Port 4001)

EdgeGuard exposes a GraphQL endpoint that mirrors the ISIM GraphQL convention used by ResilMesh (port 4001), making it queryable in exactly the same way as ISIM.

### Endpoint

```
POST http://localhost:4001/graphql     # queries and mutations
GET  http://localhost:4001/graphql     # GraphiQL only if EDGEGUARD_GRAPHQL_PLAYGROUND=true (default false — see README)
GET  http://localhost:4001/health      # liveness: HTTP 200 if Neo4j ping+APOC OK, else 503 (REST /health on :8000 always 200 with body flags — see README)
```

### Example queries

```graphql
# Fetch a CVE with linked CVSS sub-nodes (v4 / v3.1 / v3.0 / v2 — whichever exist)
# baseScore / baseSeverity fall back from linked CVSS when the CVE node has no score
query {
  cve(cveId: "CVE-2024-12345") {
    cveId description published baseScore baseSeverity
    cvssV40 { baseScore baseSeverity vectorString }
    cvssV31 { baseScore vectorString attackVector }
    cvssV30 { baseScore vectorString attackVector }
    cvssV2  { baseScore accessVector }
  }
}

# List critical vulnerabilities in the healthcare sector
query {
  vulnerabilities(filter: { zone: "healthcare", minCvss: 9.0, limit: 20 }) {
    cveId description status severity cvssScore
  }
}

# List active indicators with confidence > 0.7
query {
  indicators(filter: { zone: "energy", activeOnly: true, minConfidence: 0.7 }) {
    value indicatorType confidenceScore source
  }
}

# Threat actors, malware, techniques, tactics, campaigns all available
query {
  threatActors { name sophistication primaryMotivation }
  campaigns     { name zone confidenceScore firstSeen }
}
```

### Types exposed

| GraphQL Type | Shared with ISIM | Status |
|---|---|---|
| `CVE` | ✅ queryable via ISIM today | Fully aligned |
| `Vulnerability` | ✅ queryable via ISIM today | Fully aligned |
| `CVSSv2`, `CVSSv31`, `CVSSv40` | ✅ ISIM schema | Fully aligned |
| `Indicator` | ❌ EdgeGuard extension | Planned ISIM schema extension |
| `ThreatActor` | ❌ EdgeGuard extension | Planned ISIM schema extension |
| `Malware` | ❌ EdgeGuard extension | Planned ISIM schema extension |
| `Technique`, `Tactic` | ❌ EdgeGuard extension | Planned ISIM schema extension |
| `Campaign` | ❌ EdgeGuard extension | Planned ISIM schema extension |

See [`RESILMESH_INTEROPERABILITY.md` §8.4](RESILMESH_INTEROPERABILITY.md) for the proposed ISIM schema extension that would make Indicator/ThreatActor/Malware/Technique/Campaign queryable from ResilMesh directly.

---

## See Also

- [COLLECTORS.md](COLLECTORS.md) — Per-collector documentation with examples
- [README.md](../README.md) — Project overview and quick start
- [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md) — Full node/relationship schema and Cypher examples
- [RESILMESH_INTEGRATION_GUIDE.md](RESILMESH_INTEGRATION_GUIDE.md) — How EdgeGuard connects to ResilMesh/CRUSOE via NATS
- [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — Airflow CLI, env vars, troubleshooting
- [HEARTBEAT.md](HEARTBEAT.md) — Heartbeats, zombies, SIGKILL/OOM vs successful graph writes
- [DATA_SOURCES_RATE_LIMITS.md](DATA_SOURCES_RATE_LIMITS.md) — API rate limits and cost reference
- [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) — Doc ↔ code traceability + reading order


---

_Last updated: 2026-04-28 — PR-N36 Tier-2 deep verification: re-verified — no factual drift. The 13-source inventory matches `src/collectors/` (incl. healthcare/energy placeholders). `EDGEGUARD_REL_BATCH_SIZE` default 500 matches `_RELATIONSHIP_BATCH_DEFAULT` in `src/run_misp_to_neo4j.py:484`; `EDGEGUARD_DEBUG_GC` exists at line 3723. `create_misp_relationships_batch` and the per-edge-type provenance scoping all match code. Prior: 2026-04-26 PR-N33 docs audit (corrected PR-N26 edge scope); 2026-04-18 chip 5a + PR #41 cleanup._
