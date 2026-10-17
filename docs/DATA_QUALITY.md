# EdgeGuard Data Quality Strategy

> **Confidence scores per relationship type:** See [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) § EdgeGuard ThreatIntel Relationships.

## Overview

When merging threat intelligence from multiple sources, quality management is critical. This document outlines our approach.

**Canonical doc for the “deterministic workflow”:** how we **upsert** into Neo4j (**`MERGE`** + composite keys), preserve **provenance**, and why we prefer **exact** matching over **fuzzy** text/graph inference for production relationships (fewer **false-positive** links — see § fixes below). High-level pipeline placement: **[ARCHITECTURE.md](ARCHITECTURE.md)**; schema detail: **[KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)**.

**Code reference:** `src/neo4j_client.py` implements `MERGE` semantics, `Source` nodes, and **`SOURCED_FROM`** edges with per-source metadata — see `merge_node_with_source` (the canonical entry point post-PR-S5/PR-M2; the older `merge_indicator` / per-label helpers all funnel through it).

**MISP→Neo4j ingest path:** **Per MISP event** — dedupe within the event, same-event cross-item edges, then batched UNWIND node merges plus optional Python-side chunking via **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **500**; **`0`** / **`all`** = single pass, OOM risk). Relationship writes are batched separately (**`EDGEGUARD_REL_BATCH_SIZE`**). Does not change merge semantics — only peak RAM / transaction size. See [README.md](../README.md) and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

## Merge Strategy

### Current Logic (post-PR-S5/PR-M2 SOURCED_FROM model)

Per-source provenance is **NOT** stored on the node itself — it lives on
`(Node)-[r:SOURCED_FROM]->(Source)` edges, with the Source's
`source_id` (`'nvd'`, `'alienvault_otx'`, `'mitre_attck'`, …) plus per-source
metadata (`confidence`, `source_reported_first_at` / `source_reported_last_at`,
`raw_data`, `misp_event_ids`, `source_refs`, `zones`). The node's
`n.source` field is an accumulated list (`apoc.coll.toSet`) for
fast dashboard rollups, and `n.tags` accumulates each write's source tag
(legacy). **The canonical write path is `Neo4jClient.merge_node_with_source`,
which writes the node and then its SOURCED_FROM edge, in two statements.**

```cypher
// Schema (illustrative — actual write is via merge_node_with_source):
//
//   MERGE (n:Indicator {indicator_type: $type, value: $value})
//     ON CREATE SET n.first_imported_at = datetime()
//   SET n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_id),
//       n.last_updated = datetime()
//   // n.confidence_score: max-wins for non-Indicator labels; for an Indicator
//   // max(0.10, round(source_confidence × aging factor, 2)) (src/indicator_aging.py)
//
//   MATCH (n:Indicator {indicator_type: $type, value: $value})
//   MATCH (s:Source {source_id: $source_id})  // e.g. 'nvd', 'alienvault_otx', 'mitre_attck'
//   MERGE (n)-[r:SOURCED_FROM]->(s)
//     ON CREATE SET r.imported_at = datetime(), r.raw_data = $raw
//   SET r.confidence = $confidence,
//       r.source_reported_first_at = <MIN CASE>,  // earliest claim wins
//       r.source_reported_last_at = <MAX CASE>    // latest claim wins
```

### Unique Key
**Unique key is `(indicator_type, value)`** — same IOC from different sources merges into a single node. Source provenance is tracked via the **`SOURCED_FROM`** edge (canonical, with per-source metadata), accumulated `source` array (rollup), and `tags` array (legacy).

## Exact Matching Rules (March 2026)

### Fix 1: Zone Array Handling in Stats
**Problem**: When zone is stored as an array (e.g., `['healthcare', 'global']`), the stats query counted nodes multiple times.

**Solution**: Updated `get_stats()` in `neo4j_client.py` to use `UNWIND`:
```cypher
// Before (broken)
MATCH (n) WHERE n.zone IS NOT NULL
RETURN n.zone as zone, count(n) as count

// After (fixed)
MATCH (n) WHERE n.zone IS NOT NULL
UNWIND n.zone AS z
RETURN z as zone, count(DISTINCT n) as count
```

### Fix 2: Relationship Building with Exact Matching
**Problem**: `build_relationships.py` used fuzzy `CONTAINS` matching which created false positives (e.g., "APT" matched "AP").

**Solution**: Changed to exact matching with confidence scoring:
```cypher
// Before (false positives)
WHERE m.attributed_to CONTAINS a.name

// After (exact match)
WHERE m.attributed_to = a.name OR a.name = m.attributed_to
```

**Confidence scoring** (current evidence labels, `r.match_type`; no partial or fuzzy matching exists):
| Evidence label | Confidence | Basis |
|----------------|------------|-------|
| `exact` | 1.0 | The malware's `attributed_to` equals an actor's name or alias (Q2, `ATTRIBUTED_TO`) |
| `cve_tag` | 1.0 | A CVE tag on the indicator (`EXPLOITS`) |
| `kill_chain_phase` | 1.0 | The technique's tactic phase equals the tactic's short name (`IN_TACTIC`) |
| `mitre_explicit` | 0.95 (1.0 on `SUBTECHNIQUE_OF`) | MITRE ATT&CK's explicit `uses` relationship, or the dotted sub-technique id |
| `advisory_sector` | 0.9 | CISA's ICS advisory states the sector (`AFFECTS`) |
| `otx_attack_ids` | 0.85 | An ATT&CK id an OTX pulse lists for the indicator (`USES_TECHNIQUE`) |
| `malware_family` | 0.8 | The family label a source gives the indicator (`INDICATES`) |
| `otx_pulse` | 0.6 | Named in the same OTX pulse |
| `zone_classification` | 0.5 | EdgeGuard's sector inference (`AFFECTS`, `TARGETS`) |

The full table, with the curated, campaign and MISP-attribute-tag labels: [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#evidence-labels-report-provenance-tlp-2026-10) and `docs/RESILMESH_INTEROPERABILITY.md` §3.2.2.

**Malware ↔ Technique:** A previous **`CAN_USE`** / description-based approach was **not** used — it risked the same class of false links. **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** is created from **MITRE STIX `uses`** relationships, stored as **`uses_techniques`** (with MISP **`MITRE_USES_TECHNIQUES:`** round-trip), matching **`Technique.mitre_id`** exactly in `build_relationships.py` (`mitre_explicit`, 0.95); since 2026-10 also from the ATT&CK ids an OTX pulse lists (`reported_techniques`, step 6b, `otx_pulse`, 0.6) and from curated-package claims (0.85), each by exact id. *(Prior to 2026-04 this edge was a generic `USES`; it was renamed to `IMPLEMENTS_TECHNIQUE` to distinguish malware/tool capability from actor attribution — see [`KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation).)*

### Fix 3: Audit Logging for Confidence Skips
**Problem**: When lower-confidence source data was ignored, no audit trail existed.

**Solution**: Added logging in `merge_node_with_source()`. Today's message (2026-10-16; it read "AUDIT: Skipping lower-confidence update …" before):
```python
logger.info(f"AUDIT: Keeping the higher confidence of {label}({key_str}): "
            f"existing={existing_conf} (source={existing_src}), new={confidence} (source={source_id})")
```
A non-Indicator node keeps the higher confidence (max-wins). For an Indicator the existing value is `source_confidence`, the highest confidence a source gave, and its `confidence_score` follows the aging rule (`src/indicator_aging.py`).

### Fix 4: Enhanced Relationship Stats
Now reports average confidence per relationship type:
```python
# Output:
# ATTRIBUTED_TO: 15 (avg confidence: 1.00)
# EMPLOYS_TECHNIQUE: 27 (avg confidence: 0.95)
# IMPLEMENTS_TECHNIQUE: 15 (avg confidence: 0.95)
```

---

## Best Practices

### Do's ✅
- Use exact matching for production relationships
- Keep raw data on edges for audit trails
- Log confidence skips for debugging
- Use zone arrays for multi-sector indicators

### Don'ts ❌
- Don't use `CONTAINS` for production matching
- Don't overwrite higher-confidence with lower-confidence without audit
- Don't assume zone is a single string (it's an array)


---

_Last updated: 2026-10-17 — "Current Logic" matches `merge_node_with_source` (`first_imported_at`; the `SOURCED_FROM` edge's `imported_at`, `source_reported_first_at` / `source_reported_last_at`; source id `alienvault_otx`; max-wins or aging-rule confidence; node and edge in two statements); the confidence table lists the current evidence labels (no partial or fuzzy match exists); Fix 3 shows the current audit message; `IMPLEMENTS_TECHNIQUE` also comes from OTX pulses and curated claims since 2026-10. Prior: 2026-04-28 — PR-N36 Tier-2 deep verification: re-verified — no factual drift. The historical Fix 1-4 narrative describes past code states accurately; the SOURCED_FROM-edge "Current Logic" matches `Neo4jClient.merge_node_with_source` at HEAD. Prior: 2026-04-26 PR-N33 docs audit (replaced pre-SOURCED_FROM Cypher); 2026-03-28._
