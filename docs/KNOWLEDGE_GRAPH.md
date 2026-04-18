# EdgeGuard Knowledge Graph Schema

> **Node/relationship property reference:** See [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) for complete Cypher schemas and property types.

## Overview

The EdgeGuard knowledge graph is designed to be **backward compatible with ResilMesh/CRUSOE** while extending it with sector-aware threat intelligence.

---

## Sector Architecture

EdgeGuard partitions the knowledge graph by **three sectors** plus a **central OSINT backbone**:

```
 Healthcare (:Zone)  |  Energy (:Zone)  |  Finance (:Zone)   ← 10K-100K nodes each
─────────────────────┴──────────────────┴────────────────────
          Central OSINT Backbone (:Global)
       (Generic threats, Windows zero-days, general IOCs)
```

---

## Node Types (ResilMesh Compatible + EdgeGuard Extensions)

### ResilMesh Core Layers

| Layer | Nodes |
|-------|-------|
| Threat | `Vulnerability`, `CVE` |
| Host | `Host`, `SoftwareVersion`, `NetworkService` |
| Network | `Node`, `IP`, `DomainName`, `Subnet` |
| Flow | `Flow` |

### EdgeGuard Threat Layer Extensions

| Node | Description |
|------|-------------|
| `ThreatActor` | APT groups, threat actors |
| `Malware` | Malware families, trojans, ransomware |
| `Tool` | MITRE ATT&CK tools (Mimikatz, Cobalt Strike, etc.) |
| `Technique` | MITRE ATT&CK techniques (T1566, T1059, etc.) |
| `Tactic` | MITRE ATT&CK tactics (Initial Access, Execution, etc.) |
| `Campaign` | Named campaigns (auto-built from graph, see below) |
| `Indicator` | IOCs: IPs, domains, URLs, hashes |

---

## Relationship Types

| Relationship | From → To | Source / Confidence |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | ThreatActor → Technique | **Attribution.** MITRE STIX explicit `uses` relationship (confidence 0.95) *(split from a generic `USES` in 2026-04)* |
| `IMPLEMENTS_TECHNIQUE` | Malware → Technique | **Capability.** MITRE STIX explicit `uses` relationship via `uses_techniques` (confidence 0.95) *(split from a generic `USES` in 2026-04)* |
| `IMPLEMENTS_TECHNIQUE` | Tool → Technique | **Capability.** MITRE STIX explicit `uses` relationship (confidence 0.95) *(split from a generic `USES` in 2026-04)* |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `build_relationships.py` name matching |
| `INDICATES` | Indicator → Malware | MISP event co-occurrence (confidence 0.5) **and** malware_family name match from ThreatFox/VT (confidence 0.8) |
| `EXPLOITS` | Indicator → Vulnerability/CVE | CVE tag exact match (confidence 1.0) |
| `REFERS_TO` | Vulnerability ↔ CVE | `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor → Campaign | `build_campaign_nodes()` |
| `PART_OF` | Malware, Indicator → Campaign | `build_campaign_nodes()` |
| `INVOLVES` | Alert → Indicator | `neo4j_client` |
| `USES_TECHNIQUE` | Indicator → Technique | OTX pulse `attack_ids` exact MITRE ID match (confidence 0.85) |
| `AFFECTS` | Vulnerability/CVE → Sector | Zone list unwind (confidence 1.0) |
| `IN_TACTIC` | Technique → Tactic | Kill-chain phase exact match (confidence 1.0) |
| `HAS_CVSS_v2/v30/v31/v40` | CVE ↔ CVSS sub-nodes | Bidirectional (ResilMesh schema) |
| `REFERS_TO` | CVE ↔ Vulnerability | Bidirectional bridge by cve_id (`enrichment_jobs.bridge_vulnerability_cve`) |
| `SOURCED_FROM` | Node → Source | **Per-source provenance edge.** ONE edge per (entity, source) pair (multi-source IOCs preserve full provenance). See [SOURCED_FROM edge schema](#sourced_from-edge-schema) below for the full property contract. |

### SOURCED_FROM edge schema

Every threat-intel node (Indicator, Vulnerability, Malware, ThreatActor, Technique, Tactic, Tool) carries one `(:Node)-[r:SOURCED_FROM]->(:Source)` edge per reporting source. The edge holds both DB-local facts (when EdgeGuard saw this source report this entity) AND the source's own claim (when the source itself says it first/last recorded the entity). Per-source attribution preserves full provenance for multi-source IOCs.

| Property | Semantic | Type | Write rule | Source |
|---|---|---|---|---|
| `r.imported_at` | When EdgeGuard FIRST saw THIS source report this entity | DateTime | `ON CREATE SET = datetime()` (set once per edge, never overwritten) | DB-local |
| `r.updated_at` | When EdgeGuard LAST saw this source report it | DateTime | `SET = datetime()` on every MERGE (always current) | DB-local |
| `r.source_reported_first_at` | Source's own claim about when it first recorded the entity (NVD `published`, CISA `dateAdded`, MITRE `created`, ThreatFox `first_seen`, AbuseIPDB `firstSeen`, etc.) | Optional DateTime | MIN CASE with NULL short-circuit: earliest claim wins; stale imports cannot regress | Source claim |
| `r.source_reported_last_at` | Source's own claim about when it last recorded the entity | Optional DateTime | MAX CASE with NULL short-circuit: latest claim wins | Source claim |
| `r.confidence` | Per-source confidence score for THIS observation | Float | `SET = $confidence` every MERGE | Per-collector |
| `r.source` | Source identifier (string copy of source_id; redundant with `s.source_id` but cached on edge for performance) | String | `SET = $source_id` every MERGE | Per-collector |
| `r.raw_data` | Full source-specific payload as JSON (audit trail for one (entity, source) observation) | String (JSON) | `ON CREATE SET = $raw_data` (rarely overwritten — set once unless a re-sync explicitly rewrites) | Per-collector |
| `r.src_uuid` | Indicator/CVE/Malware/etc. node UUID (cached on edge for serialized-edge consumers — RAG / xAI use cases) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.trg_uuid` | Source node UUID (cached on edge, same rationale as `src_uuid`) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.edgeguard_managed` | Always `true` for edges EdgeGuard owns; allows STIX export to filter against ResilMesh-owned data | Boolean | `SET = true` every MERGE | DB-local |

**Why per-source on edges, not aggregates on nodes?** A single Indicator may be reported by multiple sources (NVD + AbuseIPDB + ThreatFox), each with its own claim. Aggregating to a node-level value via MIN/MAX would destroy the per-source detail. Queries that want a single canonical value compute `MIN(r.source_reported_first_at)` / `MAX(r.source_reported_last_at)` across edges on read (STIX `valid_from`, alert enrichment, campaign aggregate all do this). Read-side aggregation is cheap (~9 edges max per indicator); write-side per-source isolation prevents cross-source contention.

**Honest naming.** `source_reported_first_at` makes explicit "what the source claims to have first recorded", NOT "first observed in the wild". Sources record catalog dates: NVD's `published` is when NVD published the CVE record (after the vuln was actively exploited); MITRE's `created` is when MITRE added the SDO to its TAXII store; etc.

**MIN/MAX merge semantics handle every realistic ordering scenario** — see `src/source_truthful_timestamps.py` module docstring or `migrations/2026_04_first_seen_at_source.md` for the full scenario walkthrough (baseline + incremental + out-of-order + stale-import + multi-source).

### Technique edges: attribution vs capability vs observation

Prior to 2026-04 the three X→Technique edges were a single generic `USES` relationship. They have since been split into specialized types so Cypher queries and LLM/GraphRAG retrieval can distinguish **who does it** from **what the code can do** from **what an indicator observes**:

| Specialized type | Source | Semantic |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | `ThreatActor` (or `Campaign`) | Attribution — e.g. *"APT28 employs T1059"* |
| `IMPLEMENTS_TECHNIQUE` | `Malware` or `Tool` | Capability — e.g. *"Mimikatz implements T1059"* |
| `USES_TECHNIQUE` | `Indicator` | Observation — e.g. *"this IOC was observed executing T1059"* (from OTX `attack_ids`) |

When emitting STIX 2.1, all three collapse back to the standard `relationship_type: "uses"` predicate with the source/target types providing the same disambiguation — see `docs/STIX21_EXPORTER_PROPOSAL.md` (planned). *Pre-release framework — no migration script is shipped; a fresh baseline rerun writes the specialized edge types directly.*

---

## Sector Labeling

During ETL, nodes are labeled by sector. The `zone` property is always a list:

```cypher
(:Indicator :Finance {value: 'evil.com', zone: ['finance']})
(:Vulnerability :Energy {cve_id: 'CVE-2024-1234', zone: ['energy']})
(:Host :Healthcare {hostname: 'hospital.cardiology.server', zone: ['healthcare']})
(:Vulnerability :Global {cve_id: 'CVE-2024-9999', zone: ['global']})
```

### Multi-Zone Support

EdgeGuard supports **cross-zone threats** — threats that apply to multiple sectors.
The `zone` property is **always a list** (never a single string). There is no separate
`zones` property; all zone membership is stored in the single `zone` array.

```cypher
// Energy company compromised → affects Finance (payments)
// Creates ONE node with BOTH zones in a single array:
(:Indicator {
    value: 'evil-energy.com',
    zone: ['energy', 'finance']   // All applicable zones — always a list
})
```

#### Zone Logic

| Scenario | `zone` (array) |
|----------|----------------|
| Energy-specific threat | `['energy']` |
| Finance-specific threat | `['finance']` |
| Generic threat | `['global']` |
| Energy → Finance crossover | `['energy', 'finance']` |
| Healthcare ransomware (affects all) | `['healthcare', 'global']` |

#### Querying Cross-Zone Threats

```cypher
// Find all threats affecting BOTH energy AND finance
MATCH (i:Indicator)
WHERE 'energy' IN i.zone AND 'finance' IN i.zone
RETURN i.value, i.zone

// Find all threats affecting ANY of specific zones
MATCH (i:Indicator)
WHERE ANY(z IN ['energy', 'finance'] WHERE z IN i.zone)
RETURN i.value, i.zone
```

---

## Neo4j 5 Constraints & Indexes

### UNIQUE Constraints (Composite Keys)

```cypher
// Single-key UNIQUE — zone is metadata, not part of deduplication key
CREATE CONSTRAINT vulnerability_key IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE;

// Composite UNIQUE on (indicator_type, value) — same IOC merges across sources
CREATE CONSTRAINT indicator_key IF NOT EXISTS
FOR (i:Indicator) REQUIRE (i.indicator_type, i.value) IS UNIQUE;

// Note: no Host constraint exists in the current codebase.
// The example below is a ResilMesh-shaped illustration for a full CRUSOE graph:
// CREATE CONSTRAINT host_key IF NOT EXISTS
// FOR (h:Host) REQUIRE (h.hostname) IS UNIQUE;
```

**Note:** Zone is treated as metadata/metadata, not as part of the deduplication key. This allows the same indicator/vulnerability to exist in multiple zones while being stored as a single node in Neo4j.

### Indexes

```cypher
// Core lookups
CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value);
CREATE INDEX indicator_type IF NOT EXISTS FOR (i:Indicator) ON (i.indicator_type);
CREATE INDEX indicator_source IF NOT EXISTS FOR (i:Indicator) ON (i.source);
CREATE INDEX indicator_zone IF NOT EXISTS FOR (i:Indicator) ON (i.zone);
CREATE INDEX malware_name IF NOT EXISTS FOR (m:Malware) ON (m.name);
CREATE INDEX actor_name IF NOT EXISTS FOR (a:ThreatActor) ON (a.name);
CREATE INDEX technique_mitre IF NOT EXISTS FOR (t:Technique) ON (t.mitre_id);

// Original source tracking
CREATE INDEX indicator_original_source IF NOT EXISTS FOR (i:Indicator) ON (i.original_source);
CREATE INDEX vulnerability_original_source IF NOT EXISTS FOR (v:Vulnerability) ON (v.original_source);

// Active/inactive tracking
CREATE INDEX indicator_active IF NOT EXISTS FOR (i:Indicator) ON (i.active);
CREATE INDEX vulnerability_active IF NOT EXISTS FOR (v:Vulnerability) ON (v.active);
// PR #33 round 10: legacy-scalar misp_event_id / misp_attribute_id indexes
// removed. All readers query the misp_event_ids[] / misp_attribute_ids[]
// arrays via list-membership predicates.

// Per-node deterministic UUID indexes — added 2026-04 (PR #33) for cross-
// environment delta-sync (cloud MERGEs by uuid) and self-describing edge
// serialization (xAI / RAG consumers resolve r.src_uuid / r.trg_uuid by uuid).
// One per documented node label — see src/node_identity.py for the canonical
// natural-key map.
CREATE INDEX indicator_uuid IF NOT EXISTS FOR (i:Indicator) ON (i.uuid);
CREATE INDEX vulnerability_uuid IF NOT EXISTS FOR (v:Vulnerability) ON (v.uuid);
CREATE INDEX cve_uuid IF NOT EXISTS FOR (c:CVE) ON (c.uuid);
CREATE INDEX malware_uuid IF NOT EXISTS FOR (m:Malware) ON (m.uuid);
CREATE INDEX actor_uuid IF NOT EXISTS FOR (a:ThreatActor) ON (a.uuid);
CREATE INDEX technique_uuid IF NOT EXISTS FOR (t:Technique) ON (t.uuid);
// (… one per documented label — see src/neo4j_client.py create_indexes for the full list.)

// Tactic / technique navigation
CREATE INDEX tactic_shortname IF NOT EXISTS FOR (t:Tactic) ON (t.shortname);
CREATE INDEX technique_tactic_phases IF NOT EXISTS FOR (t:Technique) ON (t.tactic_phases);

// CVSS sub-node lookups
CREATE INDEX cvssv31_cve_id IF NOT EXISTS FOR (n:CVSSv31) ON (n.cve_id);
CREATE INDEX cvssv30_cve_id IF NOT EXISTS FOR (n:CVSSv30) ON (n.cve_id);
CREATE INDEX cvssv2_cve_id IF NOT EXISTS FOR (n:CVSSv2) ON (n.cve_id);
CREATE INDEX cvssv40_cve_id IF NOT EXISTS FOR (n:CVSSv40) ON (n.cve_id);

// Campaign enrichment
CREATE INDEX campaign_actor_name IF NOT EXISTS FOR (c:Campaign) ON (c.actor_name);
CREATE INDEX campaign_zone IF NOT EXISTS FOR (c:Campaign) ON (c.zone);
```

---

## MISP Integration

**Data split:** Sources --> MISP (raw + full history) --> Neo4j (metadata + relationships for fast queries). Neo4j nodes carry `misp_event_ids[]` for tracing back to every MISP event that has observed them. **Indicator** nodes additionally carry `misp_attribute_ids[]` — the MISP **attribute UUIDs** (`attr.uuid`), which are the *stable cross-instance identifiers*. The legacy numeric `attr.id` was deliberately not chosen because it is per-instance auto-increment and not portable across MISP instances or restores. With `misp_attribute_ids[]` populated you can resolve a Neo4j Indicator directly back to its MISP attributes without joining via event id. Edges built from the MISP path carry `r.misp_event_ids[]` for per-edge provenance.

### Sync throughput (Airflow worker memory)

MISP→Neo4j ingestion (`run_misp_to_neo4j.py`) processes **one MISP event at a time**: parse attributes → dedupe within the event → build **cross-item** edges **for that event only** (no cross-event co-occurrence on this path) → merge nodes in **Python-side chunks** (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**, default **`500`**) → flush relationships in **UNWIND batches** (**`EDGEGUARD_REL_BATCH_SIZE`**, default **`500`**). **`0`** or **`all`** on chunk size disables Python node chunking (**OOM risk** on huge attribute counts). See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

### Querying Full History

To get full history from MISP for an indicator:

```cypher
-- Get MISP event IDs from Neo4j (every event that has observed this indicator)
MATCH (i:Indicator {value: '1.2.3.4'})
RETURN i.value, i.misp_event_ids, i.source

-- Then query MISP API for full event history:
-- GET /api/attributes/restSearch/json?value=1.2.3.4
```

---

## Zone Detection Methodology

### Three-Source Zone Resolution (MISP → Neo4j pipeline)

When `run_misp_to_neo4j.py` resolves the zone for an attribute, it applies a strict **priority ladder** across three sources:

| Priority | Source | Logic |
|----------|--------|-------|
| 1 (highest) | Attribute-level tags | If the attribute itself carries specific `zone:*` tags, use those exclusively |
| 2 | Event-level tags | If attribute has no specific zone, check `zone:*` / `sector:*` tags from the parent event. Event names (`EdgeGuard-{source}-{date}`) do not contain zone information — zone lives exclusively on attribute tags. |
| 3 (fallback) | `global` | Only if neither of the above produces a specific sector |

**Merging logic (event name + event tags):**

```python
# If multiple sources provide zones, ALL specific sectors are merged.
# "global" is only kept when no specific sectors exist from any source.
all_zones = set(zones_from_event_tags)
if zone_from_event_name:
    all_zones.add(zone_from_event_name)
specific = {z for z in all_zones if z != "global"}
event_zones = sorted(specific) if specific else ["global"]
```

This merging logic prevents two confirmed bugs:
- **H1**: event name `FINANCE` + tag `zone:healthcare` → correctly produces `['finance', 'healthcare']`
- **H3**: attribute with no zone tag, event `Tag: [{name:"zone:healthcare"}]`, event name `GLOBAL` → correctly produces `['healthcare']`

All resolved zone values are validated against `VALID_ZONES = frozenset({"global", "healthcare", "energy", "finance"})` before storage.

---

### Conservative Keyword-Based Detection

EdgeGuard uses a **weighted scoring system** to detect sectors from threat data, designed to avoid false positives:

#### Scoring Weights by Context

| Context | Weight (`detect_zones_from_text`) | Example |
|---------|-----------------------------------|---------|
| `name` / `alias` / `title` | 3.0 | Primary identity, CVE title |
| `description` | 2.0 | Long-form CVE / feed description |
| `body` (default) | 1.5 | Generic body text when context unspecified |
| `tag` | 1.0 | Concatenated tag strings |

**`detect_zones_from_item`:** For each text field it calls **`detect_zones_from_text`** with the matching context; for every sector returned that is **not** `global`, it adds a **fixed** bump to **`combined_scores`** (**+3.0** name fields, **+2.5** title/info, **+1.5** description/comment/detail, **+0.5** tags). Those bumps are **not** the same numbers as the per-snippet weights above — see **`config.py`**.

#### Detection Rules

1. **Per-field threshold** (`ZONE_DETECT_THRESHOLD`, default **1.5**): minimum weighted score in `detect_zones_from_text` for a sector to count in that field. Override with **`EDGEGUARD_ZONE_DETECT_THRESHOLD`**.
2. **Multi-field aggregation** (`detect_zones_from_item`): uses **`ZONE_ITEM_COMBINED_THRESHOLD`** (default **1.5**, env **`EDGEGUARD_ZONE_ITEM_THRESHOLD`**). **NVD** passes `description` + a **`comment`** string built from flattened **CPE criteria** (`configurations_to_zone_text` in `nvd_collector.py`), not raw `json.dumps` of configurations.
3. **Relative filtering**: sectors must be within **50%** of the max combined score (see `config.py`).
4. **Negative keywords**: explicit exclusions (“not healthcare”, …) drop that sector for the snippet.
5. **Clean keywords**: no malware family names as sector keywords — link via relationships.

#### Sector Keywords (representative; full list in `config.py` → `SECTOR_KEYWORDS`)

- **Healthcare**: hospital, patient, dicom, hl7, fhir, medical device, emr, ehr, hipaa, …
- **Energy**: scada, modbus, opc ua, ics, plc, power grid, substation, industrial control, …
- **Finance**: banking trojan, payment processing, core banking, fintech, kyc, aml, …

#### Example Behavior

| Input | Detection | Result |
|-------|-----------|--------|
| "Generic phishing IP list" | No sector keywords | `global` |
| "TrickBot banking trojan" | "banking trojan" in description | `finance` |
| "Nuclear SCADA system" | "nuclear", "scada" in title | `energy` |
| "LockBit ransomware" | No strong sector keywords | `global` |
| "Healthcare ransomware attack" | "healthcare" in description | `healthcare` |
| One “hospital” in CVE description | Single keyword at body weight ≥ threshold | `healthcare` (after threshold 1.5 default) |

#### Why Conservative?

- Malware families (LockBit, Conti, TrickBot) target multiple sectors
- They should be linked via relationships, not keyword tags
- This prevents 57% of threats being tagged as "all sectors"
- Better for accurate sector-specific alerting

---

### Best Practices

1. **Latest data in Neo4j** - For fast graph queries
2. **Full history in MISP** - For audit, changes over time
3. **Query both** - Get metadata from Neo4j, details from MISP

---

## Example Queries

> **Scope:** The first queries use labels and properties written by **EdgeGuard’s default MISP→Neo4j pipeline** (`neo4j_client`, `build_relationships`). Patterns involving `Host`, `SoftwareVersion`, `IP`, `DomainName`, or sector **secondary labels** are **ResilMesh-shaped illustrations** — they are valid Cypher for a full CRUSOE graph but may not return rows until those node types are populated by your deployment.

### Healthcare-related CVEs / vulnerabilities (zone property)

```cypher
MATCH (v:Vulnerability)
WHERE 'healthcare' IN coalesce(v.zone, []) AND coalesce(v.cvss_score, 0) >= 7.0
RETURN v.cve_id, v.description, v.cvss_score
ORDER BY v.cvss_score DESC
```

### Alert enrichment: trace indicator to actor

```cypher
MATCH (ind:Indicator {indicator_type: 'ipv4', value: '192.168.1.100'})-[:INDICATES]->(m:Malware)
MATCH (m)-[:ATTRIBUTED_TO]->(ta:ThreatActor)
MATCH (ta)-[:EMPLOYS_TECHNIQUE]->(tech:Technique)
OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tactic:Tactic)
RETURN ind.value, m.name, ta.name, collect(DISTINCT tech.name) AS techniques, collect(DISTINCT tactic.name) AS tactics
```

### Cross-zone: critical vulnerabilities (`zone` list contains `global`)

```cypher
MATCH (v:Vulnerability)
WHERE 'global' IN coalesce(v.zone, []) AND coalesce(v.cvss_score, 0) >= 9.0
RETURN v.cve_id, v.description, v.first_seen
ORDER BY v.first_seen DESC
```

### Query all indicators in a Campaign

```cypher
MATCH (a:ThreatActor)-[:RUNS]->(c:Campaign)<-[:PART_OF]-(i:Indicator)
WHERE a.name = 'APT28'
  AND i.active = true
RETURN c.name, c.first_seen, c.last_seen, i.value, i.indicator_type, i.confidence_score
ORDER BY i.confidence_score DESC
```

### Find active vs retired IOCs for a threat actor

```cypher
MATCH (a:ThreatActor {name: 'Lazarus Group'})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
RETURN i.value, i.indicator_type, i.confidence_score,
       i.active, i.last_updated,
       CASE WHEN i.active = false THEN 'RETIRED' ELSE 'ACTIVE' END AS status
ORDER BY i.last_updated DESC
```

---

_Last updated: 2026-04-17_
