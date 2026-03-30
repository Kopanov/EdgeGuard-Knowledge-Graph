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
| `USES` | ThreatActor → Technique | MITRE STIX explicit `uses` relationship (confidence 0.95) |
| `USES` | Malware → Technique | MITRE STIX explicit `uses` relationship via `uses_techniques` (confidence 0.95) |
| `USES` | Tool → Technique | MITRE STIX explicit `uses` relationship (confidence 0.95) |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `build_relationships.py` name matching |
| `INDICATES` | Indicator → Malware | MISP event co-occurrence (confidence 0.5) **and** malware_family name match from ThreatFox/VT (confidence 0.8) |
| `EXPLOITS` | Indicator → Vulnerability/CVE | CVE tag exact match (confidence 1.0) |
| `REFERS_TO` | Vulnerability ↔ CVE | `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor → Campaign | `build_campaign_nodes()` |
| `PART_OF` | Malware, Indicator → Campaign | `build_campaign_nodes()` |
| `INVOLVES` | Alert → Indicator | `neo4j_client` |
| `USES_TECHNIQUE` | Indicator → Technique | OTX pulse `attack_ids` exact MITRE ID match (confidence 0.85) |
| `IS_SAME_AS` | Malware → Malware | Cross-source name/alias exact match for deduplication (confidence 0.9) |
| `AFFECTS` | Vulnerability/CVE → Sector | Zone list unwind (confidence 1.0) |
| `IN_TACTIC` | Technique → Tactic | Kill-chain phase exact match (confidence 1.0) |
| `HAS_CVSS_v2/v30/v31/v40` | CVE ↔ CVSS sub-nodes | Bidirectional (ResilMesh schema) |
| `REFERS_TO` | CVE ↔ Vulnerability | Bidirectional bridge by cve_id (`enrichment_jobs.bridge_vulnerability_cve`) |

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
// UNIQUE on (cve_id, tag) - zone is metadata, not part of deduplication key
CREATE CONSTRAINT vulnerability_key IF NOT EXISTS 
FOR (v:Vulnerability) REQUIRE (v.cve_id, v.tag) IS UNIQUE;

// UNIQUE on (indicator_type, value, tag) - tag scopes the dedup key per source tag
CREATE CONSTRAINT indicator_key IF NOT EXISTS 
FOR (i:Indicator) REQUIRE (i.indicator_type, i.value, i.tag) IS UNIQUE;

// UNIQUE on (hostname, tag) - zone is metadata
CREATE CONSTRAINT host_key IF NOT EXISTS 
FOR (h:Host) REQUIRE (h.hostname, h.tag) IS UNIQUE;
```

**Note:** Zone is treated as metadata/metadata, not as part of the deduplication key. This allows the same indicator/vulnerability to exist in multiple zones while being stored as a single node in Neo4j.

### Indexes

```cypher
// Sector filtering
CREATE INDEX zone_healthcare IF NOT EXISTS FOR (n) ON (n.zone) WHERE n:Healthcare;
CREATE INDEX zone_energy IF NOT EXISTS FOR (n) ON (n.zone) WHERE n:Energy;
CREATE INDEX zone_finance IF NOT EXISTS FOR (n) ON (n.zone) WHERE n:Finance;

// Performance
CREATE INDEX vulnerability_cve_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value);
CREATE INDEX host_hostname IF NOT EXISTS FOR (h:Host) ON (h.hostname);
```

---

## MISP Integration

**Data split:** Sources --> MISP (raw + full history) --> Neo4j (metadata + relationships for fast queries). Neo4j nodes carry `misp_event_id` for tracing back to MISP.

### Sync throughput (Airflow worker memory)

MISP→Neo4j ingestion (`run_misp_to_neo4j.py`) processes **one MISP event at a time**: parse attributes → dedupe within the event → build **cross-item** edges **for that event only** (no cross-event co-occurrence on this path) → merge nodes in **Python-side chunks** (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**, default **`500`**) → flush relationships in **UNWIND batches** (**`EDGEGUARD_REL_BATCH_SIZE`**, default **`2000`**). **`0`** or **`all`** on chunk size disables Python node chunking (**OOM risk** on huge attribute counts). See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

### Querying Full History

To get full history from MISP for an indicator:

```cypher
-- Get MISP event ID from Neo4j
MATCH (i:Indicator {value: '1.2.3.4'})
RETURN i.value, i.misp_event_id, i.sources

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
MATCH (ta)-[:USES]->(tech:Technique)
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

_Last updated: 2026-03-28_
