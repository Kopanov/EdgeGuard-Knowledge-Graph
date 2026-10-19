# EdgeGuard Data Quality Strategy

> **Confidence scores per relationship type:** See [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) § EdgeGuard ThreatIntel Relationships.

## Overview

When merging threat intelligence from multiple sources, quality management is critical. This document outlines our approach.

**Canonical doc for the “deterministic workflow”:** how we **upsert** into Neo4j (**`MERGE`** + composite keys), preserve **provenance**, and why we prefer **exact** matching over **fuzzy** text/graph inference for production relationships (fewer **false-positive** links — see [Exact matching rules](#exact-matching-rules) below). High-level pipeline placement: **[ARCHITECTURE.md](ARCHITECTURE.md)**; schema detail: **[KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md)**.

**Code reference:** `src/neo4j_client.py` implements `MERGE` semantics, `Source` nodes, and **`SOURCED_FROM`** edges with per-source metadata — see `merge_node_with_source` (the canonical entry point; the per-label helpers such as `merge_indicator` funnel through it).

**MISP→Neo4j ingest path:** **Per MISP event** — dedupe within the event, same-event cross-item edges, then batched UNWIND node merges plus optional Python-side chunking via **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **500**; **`0`** / **`all`** = single pass, OOM risk). Relationship writes are batched separately (**`EDGEGUARD_REL_BATCH_SIZE`**). Does not change merge semantics — only peak RAM / transaction size. See [README.md](../README.md) and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

## Merge Strategy

### Merge logic: the SOURCED_FROM model

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

## Exact Matching Rules

### Zone counts in the statistics

`zone` is a list (e.g. `['healthcare', 'energy']`), so `get_stats()` in `neo4j_client.py` unwinds it and counts each node once per zone:

```cypher
MATCH (n) WHERE n.zone IS NOT NULL
UNWIND n.zone AS z
RETURN z as zone, count(DISTINCT n) as count
```

### Relationship building with exact matching

`build_relationships.py` matches names exactly, never with a substring test such as `CONTAINS`, because a substring match creates false positives (e.g. "APT" would match "AP"). The attribution step compares the malware's own `attributed_to` claim with the actor's name and aliases:

```cypher
// Exact match (simplified: Q2 compares trimmed, lower-cased values and also matches a.aliases)
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
| `malware_family` | 0.8 | The family label a source gives the indicator (`INDICATES`) |
| `otx_pulse` | 0.6 | Named in the same OTX pulse (`INDICATES` to Malware and to CVE, `ATTRIBUTED_TO`, and the techniques a pulse lists for its actors and malware); on Indicator → CVE it says "named in the same report", never that the indicator exploits the CVE (`cve_tag`) |
| `otx_attack_ids` | 0.6 | An ATT&CK id the indicator's OTX pulse lists (`USES_TECHNIQUE`); a report-level association like `otx_pulse`, with a label of its own |
| `zone_classification` | 0.5 | EdgeGuard's sector inference (`AFFECTS`, `TARGETS`) |

The full table, with the curated, campaign and MISP-attribute-tag labels: [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#evidence-labels-report-provenance-tlp) and `docs/RESILMESH_INTEROPERABILITY.md` §3.2.2.

**Malware ↔ Technique:** No description-based inference (such as a **`CAN_USE`** relationship) is used, because it risks the same class of false links. **`(Malware)-[:IMPLEMENTS_TECHNIQUE]->(Technique)`** is created from **MITRE STIX `uses`** relationships, stored as **`uses_techniques`** (with MISP **`MITRE_USES_TECHNIQUES:`** round-trip), matching **`Technique.mitre_id`** exactly in `build_relationships.py` (`mitre_explicit`, 0.95); also from the ATT&CK ids an OTX pulse lists (`reported_techniques`, step 6b, `otx_pulse`, 0.6) and from curated-package claims (0.85), each by exact id. `IMPLEMENTS_TECHNIQUE` (malware/tool capability) is distinct from actor attribution (`EMPLOYS_TECHNIQUE`) — see [`KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md#technique-edges-attribution-vs-capability-vs-report).

### Audit logging for kept confidences

When an incoming confidence is lower than the stored one, `merge_node_with_source()` logs the decision as an audit trail:
```python
logger.info(f"AUDIT: Keeping the higher confidence of {label}({key_str}): "
            f"existing={existing_conf} (source={existing_src}), new={confidence} (source={source_id})")
```
A non-Indicator node keeps the higher confidence (max-wins). For an Indicator the existing value is `source_confidence`, the highest confidence a source gave, and its `confidence_score` follows the aging rule (`src/indicator_aging.py`).

### Relationship statistics

At the end of a run, `build_relationships.py` reports the count and the average confidence per relationship type:
```python
# Output:
# ATTRIBUTED_TO: 15 (avg confidence: 1.00)
# EMPLOYS_TECHNIQUE: 27 (avg confidence: 0.95)
# IMPLEMENTS_TECHNIQUE: 15 (avg confidence: 0.95)
```

---

## Best Practices

### Do
- Use exact matching for production relationships
- Keep raw data on edges for audit trails
- Log confidence skips for debugging
- Use zone arrays for multi-sector indicators

### Do not
- Don't use `CONTAINS` for production matching
- Don't overwrite higher-confidence with lower-confidence without audit
- Don't assume zone is a single string (it's an array)

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — `otx_pulse` also labels `INDICATES` from an indicator to a CVE named in the same OTX pulse.
- 2026-10-18 — `otx_attack_ids` (`USES_TECHNIQUE` from an OTX pulse's ATT&CK ids) is 0.6, the confidence of every other link from those ids (it was 0.85).
- 2026-10-17 — Main text restated as a guide to current behaviour: the fixes of 2026-03 are described as the rules they established, and change history moved to this section.
- 2026-10-17 — The merge logic matches `merge_node_with_source` (`first_imported_at`; the `SOURCED_FROM` edge's `imported_at` and source-reported times; source id `alienvault_otx`; max-wins or aging-rule confidence; node and edge in two statements); the confidence table lists the current evidence labels; the audit message reads "Keeping the higher confidence" (it read "Skipping lower-confidence update"); `IMPLEMENTS_TECHNIQUE` also comes from OTX pulses and curated claims.
- 2026-04-26 — The merge logic describes the `SOURCED_FROM` model instead of node-level provenance.
- 2026-04-15 — The generic `USES` edge from malware or a tool to a technique became `IMPLEMENTS_TECHNIQUE`, distinct from actor attribution (`EMPLOYS_TECHNIQUE`).
- 2026-03-28 — Exact matching rules: `get_stats()` counts zone lists with `UNWIND` (the grouped query had counted nodes several times), relationship building uses exact matches instead of `CONTAINS`, confidence skips are logged, and relationship statistics report the average confidence.
