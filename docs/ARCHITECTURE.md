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
│  • Fetch data from 10 active sources (+ 2 sector placeholders) │
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
│  • Report-scoped relationships (same OTX pulse) per event  │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              POST-SYNC (edgeguard_neo4j_sync + baseline)   │
│  1. build_relationships.py —                                │
│     Actor → Technique (EMPLOYS_TECHNIQUE, MITRE explicit),  │
│     Malware/Tool → Technique (IMPLEMENTS_TECHNIQUE, MITRE), │
│     Indicator → Technique (USES_TECHNIQUE, OTX attack_ids), │
│     Actor/Malware → Technique from OTX pulse ids            │
│     (EMPLOYS/IMPLEMENTS_TECHNIQUE, otx_pulse 0.6),          │
│     malware_family name match → Malware (INDICATES, 0.8),   │
│     CVE-tag EXPLOITS, sector edges — no event co-occurrence │
│  2. enrichment_jobs — campaigns (RUNS/PART_OF_CAMPAIGN),   │
│     confidence calibration, IOC decay (order inside module) │
└─────────────────────────────────────────────────────────────┘
```

### Pipeline flow (what actually runs where)

**Airflow (default production path)** — `dags/edgeguard_pipeline.py` calls `MISPToNeo4jSync().run()`:

```
Collectors → MISP → [per MISP event] parse_attribute() → dedupe → cross-item edges (same event only)
              → sync_to_neo4j() (Python chunks) → create_misp_relationships_batch() (UNWIND batches) → Neo4j
```

No STIX bundle is materialized on this path: each MISP attribute is parsed into EdgeGuard item dicts. **Report-scoped** relationships produced during sync (2026-10) are built from **one event’s item list only**, and inside it only between items that share the same OTX `pulse_id`: `Indicator → INDICATES → Malware` and `Malware → ATTRIBUTED_TO → ThreatActor`, `match_type='otx_pulse'`, confidence 0.6, `r.sources = ['alienvault_otx']`, the pulse in `r.source_refs[]` (`alienvault_otx:<pulse id>`). Items without a pulse id are never paired, and nothing is paired across the whole per-source, per-day event any more (see the `_build_cross_item_relationships` docstring in `run_misp_to_neo4j.py`). **Node** merges use Python-side chunks (`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`); **relationship** writes use **`EDGEGUARD_REL_BATCH_SIZE`** (default **500** definitions per UNWIND). Optional **`EDGEGUARD_DEBUG_GC`** enables `gc.collect()` after each node chunk (diagnostics; can hurt RAM on small workers).

**CLI / `run_pipeline.py` (optional)** — with `use_stix_flow=True` (default for **`python src/run_pipeline.py`** step 3 when STIX is available):

```
MISP → convert_to_stix21() / PyMISP to_stix2 → load_stix21_to_neo4j() → Neo4j
```

STIX is also used for **export** (`--stix`, `export_to_stix21`) and lives in **`MISPToNeo4jSync.convert_to_stix21`** / **`fetch_stix21_from_misp`** for tooling — those helpers are **not** invoked by **`MISPToNeo4jSync.run()`** used from Airflow.

**After sync** — DAG **`edgeguard_neo4j_sync`** runs **`build_relationships.py`**, then **`enrichment_jobs.run_all_enrichment_jobs`** (bridge, actor alias merge, campaigns, calibration, decay, FIRST EPSS). Baseline DAG runs the same pattern after **`full_neo4j_sync`**.

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

The MITRE collector populates **`uses_techniques: [T1059, ...]`** on each **ThreatActor**, **Malware**, and **Tool** item; malware IDs round-trip through MISP via the **`MITRE_USES_TECHNIQUES:`** attribute comment (same idea as **`NVD_META:`** for CVEs). **2026-10:** the OTX collector puts a pulse's `attack_ids` on its malware/actor items as **`reported_techniques`** (JSON key `rt`, with the pulse id as `pid`) — never as `uses_techniques` — so pulse-level associations become `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` edges with `match_type='otx_pulse'` (0.6) instead of being mislabelled `mitre_explicit`. `build_relationships.py` matches `WHERE t.mitre_id IN coalesce(node.uses_techniques, [])` per label, writing the appropriate specialized edge type. Edge confidence **`0.95`**, **`match_type = 'mitre_explicit'`**.

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
| TLP | `tlp:white` | 2026-10: on every attribute — the source's own level (OTX `pulse_tlp`) or `EDGEGUARD_DEFAULT_TLP` |
| Severity | `severity:high` | For vulnerabilities; `severity:unknown` when the CVE has no CVSS |
| CVSS | `cvss:critical` | Rating of the CVE's CVSS score (`none`, `low`, `medium`, `high`, `critical`), from its first CVSS in the order v3.1 → v3.0 → v2 → v4.0. No tag when the CVE has no CVSS (2026-10: unscored CVEs used to be tagged `cvss:low`). The sync takes the score itself from NVD_META, never from this tag |
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
| `SOURCED_FROM` | Node → Source | Every merge; carries `raw_data`, `confidence`, `imported_at`, `updated_at`, `source_reported_first_at`, `source_reported_last_at`, `src_uuid`, `trg_uuid`, `edgeguard_managed`, and (2026-10) that source's `misp_event_ids[]` and `source_refs[]`, which the links derived after the sync copy. **One edge per (entity, source) pair** — multi-source IOCs preserve full per-source provenance. See [KNOWLEDGE_GRAPH.md → SOURCED_FROM edge schema](KNOWLEDGE_GRAPH.md#sourced_from-edge-schema). |
| `EMPLOYS_TECHNIQUE` | ThreatActor / Campaign → Technique | Attribution — MITRE STIX **`uses`** → `uses_techniques` on actor (`match_type='mitre_explicit'`, 0.95); OTX pulse `attack_ids` → `reported_techniques` (`match_type='otx_pulse'`, 0.6, 2026-10) → `build_relationships.py`; a curated package's claim, written by the sync (2026-10): the package's curated label and 0.85 on a link it creates, only its provenance on an existing link. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Malware / Tool → Technique | Capability — MITRE STIX **`uses`** → `uses_techniques` (`mitre_explicit`, 0.95); OTX pulse ids → `reported_techniques` (`otx_pulse`, 0.6, 2026-10); a malware's curated-package claim as for `EMPLOYS_TECHNIQUE` (2026-10). MISP round-trip via **`MITRE_USES_TECHNIQUES:`** (`t` / `rt` / `pid`) → `build_relationships.py`. *(Split from a generic `USES` in 2026-04.)* |
| `USES_TECHNIQUE` | Indicator → Technique | Observation — OTX `attack_ids` on indicator → `build_relationships.py` (confidence 0.85). |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `build_relationships.py` exact match on the malware's own `attributed_to` claim against the actor's `name` OR the actor's `aliases` (`match_type='exact'`, 1.0; the "Cozy Bear → APT29" path), plus — 2026-10 — same-OTX-pulse links from the sync (`match_type='otx_pulse'`, 0.6). Whole-event co-occurrence attribution removed 2026-10. Actor/malware `aliases` survive the MISP round-trip via `alias:` tags (2026-06). |
| `INDICATES` | Indicator → Malware | Same-OTX-pulse link from the sync (`match_type='otx_pulse'`, 0.6, 2026-10) and source-asserted `malware_family` match (`build_relationships.py` Q9, 0.8). The whole-event `misp_event_ids[]` co-occurrence query was removed in 2026-10. |
| `EXPLOITS` | Indicator → CVE/Vulnerability; ThreatActor / Malware → CVE | Indicator tagged with matching `cve_id` (`match_type='cve_tag'`, 1.0). Not derived from event co-membership since 2026-10. Actor and malware links (2026-10) come only from curated packages (the package's curated label, 0.85, on the link a claim creates; MATCH on existing nodes; `r.tlp` = the package's TLP level). |
| `IN_TACTIC` | Technique → Tactic | MITRE ATT&CK tactic phases |
| `SUBTECHNIQUE_OF` | Technique → Technique | Sub-technique → parent technique (MITRE dotted id; 2026-10) |
| `USES_MALWARE` | ThreatActor → Malware | MITRE explicit group → malware `uses` (2026-10, R6); also a curated package's claim (curated label and 0.85 on a link it creates) |
| `USES_TOOL` | ThreatActor → Tool | MITRE explicit group → tool `uses` (2026-10, R6); also a curated package's claim (curated label and 0.85 on a link it creates) |
| `TARGETS` | Indicator / ThreatActor / Malware → Sector | Node `zone` list → the sync (indicators) and `build_relationships.py` (`zone_classification`, 0.5; actor and malware edges since 2026-10; never to `global`) |
| `AFFECTS` | Vulnerability/CVE → Sector | Node `zone` list → the sync and `build_relationships.py` (`zone_classification`, 0.5) |
| `RUNS` | ThreatActor → Campaign | Built by `enrichment_jobs.build_campaign_nodes()` |
| `PART_OF_CAMPAIGN` | Malware / Indicator → Campaign | Built by `enrichment_jobs.build_campaign_nodes()` (named `PART_OF` until 2026-10; `PART_OF` is ResilMesh's asset hierarchy) |

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
`INDICATES` (Indicator → Malware, both report-scoped + family-match
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
runbook (those four types only). **Since 2026-10 every relationship built
from the sources carries `r.misp_event_ids[]`**, together with `r.sources[]`
(who asserts it) and `r.source_refs[]` (the sources' own record ids): the
sync writes the three lists from the MISP attribute, and the links derived
afterwards (`build_relationships.py`, the campaign and Vulnerability↔CVE
links of `enrichment_jobs.py`) copy them from the subject node's
per-source `SOURCED_FROM` edge or inherit them from the links they are
built on (`src/relationship_provenance.py`; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md),
"Relationship provenance").

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
| cisa_kev | CISA KEV | Advisory | cisa_collector.py |
| mitre_attck | MITRE ATT&CK | Framework | mitre_collector.py |
| virustotal | VirusTotal | Threat Intel | `vt_collector.py` (scheduled); `virustotal_collector.py` (enrichment task) |
| abuseipdb | AbuseIPDB | IP Reputation | abuseipdb_collector.py |
| feodo_tracker | Feodo Tracker | Threat Intel | finance_feed_collector.py |
| ssl_blacklist | SSL Blacklist | Threat Intel | finance_feed_collector.py |
| urlhaus | URLhaus | Threat Intel | global_feed_collector.py |
| threatfox | ThreatFox | Threat Intel | global_feed_collector.py |
| malwarebazaar | MalwareBazaar | Threat Intel | global_feed_collector.py (flag-guarded, `EDGEGUARD_ENABLE_MALWAREBAZAAR`) |
| cisa_ics | CISA ICS Advisories | Advisory | cisa_ics_collector.py (flag-guarded, `EDGEGUARD_ENABLE_CISA_ICS`) |
| healthcare | Healthcare Feeds | Threat Intel | healthcare_feed_collector.py (placeholder) |
| energy | Energy Feeds | Threat Intel | energy_feed_collector.py (placeholder) |

The registry also holds the MISP hub (`misp`, the fallback for an attribute without a known source tag) and, since 2026-10, two curated sources with no collector: `coreideas` (Core Ideas) and `misp_galaxy`. Their packages are imported once into MISP with `scripts/import_curated_package.py`, and the sync writes their claims as relationships of existing types without creating nodes ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Curated packages").

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
| `src/collectors/global_feed_collector.py` | URLhaus, ThreatFox, MalwareBazaar collectors |
| `src/collectors/cisa_ics_collector.py` | CISA ICS advisories (CSAF 2.0), flag-guarded |
| `src/collectors/virustotal_budget.py` | VirusTotal free-tier daily ledger (budget, per-run cap, lookup memory) |
| `src/source_key_check.py` | Live check of the source API keys (preflight, baseline task `source_key_check`) |
| `src/collectors/healthcare_feed_collector.py` | Healthcare placeholder |
| `src/collectors/energy_feed_collector.py` | Energy placeholder |
| `src/collectors/misp_collector.py` | Fetch/normalize events from MISP API (ingest) — **not** used in default baseline collector tier |
| `src/run_misp_to_neo4j.py` | **Airflow MISP→Neo4j**: `fetch_edgeguard_events`, `parse_attribute`, `sync_to_neo4j`, optional STIX helpers for CLI/export |
| `src/run_pipeline.py` | CLI orchestration; optional **STIX flow** to Neo4j; collector steps to MISP |
| `src/enrichment_jobs.py` | Post-sync enrichment: Vulnerability↔CVE `REFERS_TO` bridge, actor alias merge, campaigns, co-occurrence calibration, IOC decay, FIRST EPSS |
| `src/cve_feed_enrichment.py` | FIRST EPSS on existing `CVE` nodes (2026-10): bounded download, parse, batched `SET`, removal for CVEs that left the feed; the one source written to Neo4j without MISP |
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
GET  http://localhost:4001/health      # liveness: HTTP 200 if Neo4j ping+APOC OK, else 503 (REST /health on :8000 behaves the same — see README)
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

# List critical vulnerabilities in the healthcare sector (the CVE nodes, highest score first)
query {
  vulnerabilities(filter: { zone: "healthcare", minCvss: 9.0, limit: 20 }) {
    cveId description status severity cvssScore cvssVersion published tlp
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

Every type that maps an EdgeGuard node carries `tlp`, the node's TLP level (null when it has none; 2026-10). `vulnerabilities` returns the `Vulnerability` type built from the `CVE` nodes the sync writes (2026-10: it read the `Vulnerability` label, which the sync does not write, and returned an empty list); `cvssScore` is null for a CVE without CVSS, named by `cvssVersion` otherwise. An `indicators` filter on `md5` / `sha1` / `sha256` / `sha512` selects the stored `hash` indicators of that digest length.

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

_Last updated: 2026-10-15 — GraphQL: `vulnerabilities` reads the `CVE` nodes, every node type carries `tlp`, digest-type indicator filters; the REST `/health` note says 503 while degraded. Same day: post-sync enrichment adds FIRST EPSS (`src/cve_feed_enrichment.py`). Same day: relationship table: per-source `misp_event_ids[]` / `source_refs[]` on `SOURCED_FROM`, curated-package claims on the technique, `USES_MALWARE` / `USES_TOOL` and `EXPLOITS` rows, `TARGETS` from actors and malware; the edge-traceability paragraph no longer says the technique and attribution edges lack `r.misp_event_ids[]`; the curated sources and the `misp` hub named under the source inventory; after #193: a curated claim sets its label and confidence only on a link it creates, and actor / malware `EXPLOITS` carry the package's TLP. Prior: 2026-10-14 — MISP tag table: `cvss:` only for a CVE with a CVSS score (`cvss:none` for 0.0), `severity:unknown` without; relationship provenance: every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]` (who asserts it, the sources' record ids, the MISP events); `source_id`, `source_ids` and `report_ids` were dropped from relationships. Prior: 2026-06-11 — PR #126: ATTRIBUTED_TO row now documents the alias round-trip (actor/malware aliases survive the MISP round-trip via `alias:` tags) and the removal of the alias attribution-forgery branch (Q2 Branch 3). Prior: 2026-04-28 — PR-N36 Tier-2 deep verification: re-verified — no factual drift. The 13-source inventory matches `src/collectors/` (incl. healthcare/energy placeholders). `EDGEGUARD_REL_BATCH_SIZE` default 500 matches `_RELATIONSHIP_BATCH_DEFAULT` in `src/run_misp_to_neo4j.py:484`; `EDGEGUARD_DEBUG_GC` exists at line 3723. `create_misp_relationships_batch` and the per-edge-type provenance scoping all match code. Prior: 2026-04-26 PR-N33 docs audit (corrected PR-N26 edge scope); 2026-04-18 chip 5a + PR #41 cleanup._