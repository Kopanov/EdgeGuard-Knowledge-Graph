# Neo4j sample queries (EdgeGuard)

Run these in Neo4j Browser (e.g. `http://localhost:7474`).

---

## Basic Stats

### Count all nodes by type
```cypher
MATCH (n) 
RETURN labels(n)[0] as type, count(n) as count
ORDER BY count DESC
```

### Count by zone
```cypher
MATCH (n) 
WHERE n.zone IS NOT NULL
RETURN n.zone as zone, count(n) as count
ORDER BY count DESC
```

---

## Vulnerabilities

### Find critical vulnerabilities
```cypher
MATCH (v:Vulnerability)
WHERE v.cvss_score >= 9.0
RETURN v.cve_id, v.cvss_score, v.severity, v.zone
ORDER BY v.cvss_score DESC
LIMIT 20
```

### Find healthcare-tagged vulnerabilities
Sectors are stored on the **`zone`** property (list of strings) at MERGE time. After the post-sync `apply_sector_labels()` call (see `src/neo4j_client.py:1580`), nodes ALSO get secondary labels (e.g. `:Vulnerability :Healthcare`). For portable queries — pre or post `apply_sector_labels` — use the `zone` property:

```cypher
MATCH (v:Vulnerability)
WHERE 'healthcare' IN coalesce(v.zone, [])
RETURN v.cve_id, v.cvss_score, v.description
LIMIT 20
```

---

## Indicators

### Find suspicious IPs
```cypher
MATCH (i:Indicator {indicator_type: 'ipv4'})
WHERE i.confidence_score > 0.5
RETURN i.value, i.confidence_score, i.zone
LIMIT 20
```

### Find malicious domains
```cypher
MATCH (i:Indicator {indicator_type: 'domain'})
RETURN i.value, i.confidence_score, i.zone
LIMIT 20
```

---

## Threat Actors

### List all threat actors
```cypher
MATCH (a:ThreatActor)
RETURN a.name, a.aliases, a.confidence_score
LIMIT 20
```

---

## Techniques

### Find techniques by tactic phase
```cypher
// PR-N33 docs audit (2026-04-26): the previous `WHERE 'Windows' IN t.platforms`
// query was broken — `merge_technique` in src/neo4j_client.py never sets
// `t.platforms` (only `tactic_phases`, `detection`, `is_subtechnique`,
// `name`, `description` are written), so the query silently returned
// zero rows. Use `tactic_phases` instead, which IS populated:
MATCH (t:Technique)
WHERE 'lateral-movement' IN t.tactic_phases
RETURN t.mitre_id, t.name
LIMIT 20
```

---

## Malware & MITRE techniques

### Malware with explicit IMPLEMENTS_TECHNIQUE → Technique (MITRE STIX)
Requires **`uses_techniques`** on **`Malware`** (from MITRE collector + MISP **`MITRE_USES_TECHNIQUES:`** + sync) and **`build_relationships.py`**.

```cypher
MATCH (m:Malware)-[r:IMPLEMENTS_TECHNIQUE]->(t:Technique)
RETURN m.name, t.mitre_id, t.name, r.confidence_score
LIMIT 25
```

> **History:** Prior to 2026-04 this edge was a generic `USES`. It was renamed to `IMPLEMENTS_TECHNIQUE` to distinguish malware/tool capability from actor attribution (`EMPLOYS_TECHNIQUE`). Both collapse back to STIX 2.1 `relationship_type: "uses"` on export. To query all three specialized types at once:
>
> ```cypher
> MATCH (n)-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
> RETURN labels(n)[0] AS source_label, n.name AS source_name,
>        type(r) AS rel_type, t.mitre_id, t.name, r.confidence_score
> LIMIT 50
> ```

---

## Alert Enrichment Example

### Trace indicator → malware → threat actor (attribution chain)
```cypher
MATCH (i:Indicator)-[:INDICATES]->(m:Malware)
MATCH (m)-[:ATTRIBUTED_TO]->(a:ThreatActor)
RETURN i.value AS indicator, m.name AS malware, a.name AS actor
LIMIT 10
```

---

## Edge provenance (PR-N26 — `r.misp_event_ids[]`)

PR-N26 wired `r.misp_event_ids[]` onto edges from `build_relationships.py`
for 4 edge types: `INDICATES`, `EXPLOITS`, `TARGETS`, `AFFECTS`.

### Indicators with their MISP-event provenance edges

```cypher
MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
WHERE size(coalesce(r.misp_event_ids, [])) > 0
RETURN i.value, i.indicator_type, m.name,
       r.misp_event_ids[0..5] AS misp_events_first5,
       size(r.misp_event_ids) AS misp_event_count
ORDER BY misp_event_count DESC
LIMIT 25
```

### Find INDICATES edges that share MISP events with a known indicator

```cypher
// Use case: pivoting from one IoC to others co-mentioned in the same MISP event(s)
MATCH (a:Indicator {value: $known_value})-[ra:INDICATES]->(:Malware)
WITH ra.misp_event_ids AS shared_events
MATCH (b:Indicator)-[rb:INDICATES]->(m:Malware)
WHERE any(eid IN rb.misp_event_ids WHERE eid IN shared_events)
RETURN b.value, m.name, rb.misp_event_ids
LIMIT 50
```

### Backfill candidates — edges WITHOUT misp_event_ids

```cypher
// Run before scripts/backfill_edge_misp_event_ids.py to estimate scope.
// Pre-PR-N26 edges have no array; post-PR-N26 edges always do.
MATCH ()-[r]->()
WHERE type(r) IN ['INDICATES', 'EXPLOITS', 'TARGETS', 'AFFECTS']
  AND (r.misp_event_ids IS NULL OR size(r.misp_event_ids) = 0)
RETURN type(r) AS edge_type, count(r) AS gap
```

---

_Last updated: 2026-04-28 — PR-N36 Tier-2 deep verification: corrected the "stored on `zone` property, not as extra labels" claim — sectors are stored on BOTH (`zone` property at MERGE time, plus secondary labels like `:Healthcare` after `apply_sector_labels()` runs post-sync). Recommend `zone` property for portable queries that work pre or post the label-apply step. Prior: 2026-04-26 PR-N33 docs audit (replaced broken `t.platforms` query with `t.tactic_phases`; added Edge provenance section)._

*Save queries to test the prototype*
