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
`source_id` (`'nvd'`, `'otx'`, `'mitre_attck'`, …) plus per-source
metadata (confidence, first_seen / last_seen, tags). The node's
`n.source` field is an accumulated list (`apoc.coll.toSet`) for
fast dashboard rollups, but **the canonical write path is via
`Neo4jClient.merge_node_with_source` which writes both the node and
the SOURCED_FROM edge in the same transaction**.

```cypher
// Schema (illustrative — actual write is via merge_node_with_source):
//
//   MERGE (n:Indicator {indicator_type: $type, value: $value})
//     ON CREATE SET n.first_seen_at = datetime()
//   MERGE (s:Source {source_id: $source_id})
//   MERGE (n)-[r:SOURCED_FROM]->(s)
//     ON CREATE SET r.first_seen = $first_seen, r.confidence = $confidence
//     ON MATCH  SET r.last_seen  = $last_seen
//   SET n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_id)
//   SET n.confidence_score = CASE WHEN ... END  // composite across edges
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

**Confidence Scoring**:
| Match Type | Confidence | Description |
|------------|------------|-------------|
| Exact | 1.0 | Direct property match |
| Partial | 0.6 | One field contains another |
| Fuzzy | 0.3 | Loose matching (deprecated) |

**Malware ↔ Technique:** A previous **`CAN_USE`** / description-based approach was **not** used — it risked the same class of false links. **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** is created only from **MITRE STIX `uses`** relationships, stored as **`uses_techniques`** (with MISP **`MITRE_USES_TECHNIQUES:`** round-trip), matching **`Technique.mitre_id`** exactly in `build_relationships.py`. *(Prior to 2026-04 this edge was a generic `USES`; it was renamed to `IMPLEMENTS_TECHNIQUE` to distinguish malware/tool capability from actor attribution — see [`KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-observation).)*

### Fix 3: Audit Logging for Confidence Skips
**Problem**: When lower-confidence source data was ignored, no audit trail existed.

**Solution**: Added logging in `merge_node_with_source()`:
```python
logger.info(f"AUDIT: Skipping lower-confidence update for {label}({key}): "
          f"existing={0.8} (source=nvd), new={0.5} (source=otx)")
```

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

_Last updated: 2026-04-26 — PR-N33 docs audit: replaced pre-SOURCED_FROM "Current Logic" Cypher (which set `n.source` directly) with the post-PR-S5/PR-M2 SOURCED_FROM-edge model; updated `merge_indicator` reference to canonical `merge_node_with_source` entry point. Prior: 2026-03-28._
