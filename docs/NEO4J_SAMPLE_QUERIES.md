# Neo4j sample queries (EdgeGuard)

Run these in Neo4j Browser (e.g. `http://localhost:7474`).

> This is an illustrative operator cookbook. The full **test-pinned analyst
> query catalog** (19 GraphRAG shapes: IOC triage, sector relevance, CVE/KEV
> prioritization, ATT&CK hunting, actor investigation) lives in
> `tests/test_cypher_query_catalog.py::_TI_GRAPHRAG` and runs against the
> live graph via `scripts/run_cypher_catalog_http.py`.

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

> **Label note (verified 2026-05-25 against the live graph):** the MISP→Neo4j sync routes every CVE through `merge_cve()` → the **`:CVE`** label (`src/run_misp_to_neo4j.py:3415`). The older **`:Vulnerability`** label is legacy and is **empty** on current baselines (the production snapshot held 99,757 `:CVE` and 0 `:Vulnerability`), so query `:CVE`. If a graph may still hold legacy nodes, use the portable form `MATCH (v) WHERE v:CVE OR v:Vulnerability`.

> **Scores (2026-10):** `c.cvss_score` / `c.severity` are the base score and rating of the CVE's first CVSS in the order v3.1 → v3.0 → v2 → v4.0, and `c.cvss_version` names the version. A CVE without any CVSS (rejected, or awaiting NVD analysis without a CNA score) has a null score and severity `UNKNOWN`. Graphs built before 2026-10 show such CVEs as 3.0 / LOW.
>
> **Attack vector (2026-10):** `c.attack_vector` is the attack vector of the same CVSS, in NVD's words — `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` — and null without CVSS. Graphs built before 2026-10 mix the vector-string letters (`N`, `L`, `A`, `P`) with the words and `UNKNOWN`, so `c.attack_vector = 'NETWORK'` there misses most network-exploitable CVEs (3,305 matches on the hosted graph of 2026-10-15; 100,779 after a re-merge).

### Network-exploitable CVEs
```cypher
MATCH (c:CVE)
WHERE c.attack_vector = 'NETWORK' AND c.cvss_score >= 7.0
RETURN c.cve_id, c.cvss_score, c.cvss_version, c.attack_vector
ORDER BY c.cvss_score DESC
LIMIT 20
```

### Find critical CVEs
```cypher
MATCH (c:CVE)
WHERE c.cvss_score >= 9.0
RETURN c.cve_id, c.cvss_score, c.cvss_version, c.severity, c.zone
ORDER BY c.cvss_score DESC
LIMIT 20
```

### CVEs without a CVSS 3.x / 2 score
```cypher
MATCH (c:CVE)
WHERE c.cvss_score IS NULL OR c.cvss_version = '4.0'
RETURN coalesce(c.cvss_version, 'none') AS cvss, c.severity, count(*) AS cves
ORDER BY cves DESC
```

### Find healthcare-tagged CVEs
Sectors are stored on the **`zone`** property (list of strings) at MERGE time. After the post-sync `apply_sector_labels()` call (see `src/neo4j_client.py:1580`), nodes ALSO get secondary labels (e.g. `:CVE :Healthcare`). For portable queries — pre or post `apply_sector_labels` — use the `zone` property:

```cypher
MATCH (c:CVE)
WHERE 'healthcare' IN coalesce(c.zone, [])
RETURN c.cve_id, c.cvss_score, c.description
LIMIT 20
```

### Find actively exploited CVEs (CISA KEV)
`cisa_exploit_add` (date added to the CISA Known Exploited Vulnerabilities
list) is range-indexed (PR #126). On pre-June-2026 baselines only
NVD-enriched CVEs carry it; after a fresh baseline CISA-only CVEs do too.

```cypher
MATCH (c:CVE)
WHERE c.cisa_exploit_add IS NOT NULL
RETURN c.cve_id, c.cisa_exploit_add, c.cisa_vulnerability_name, c.cvss_score
ORDER BY c.cisa_exploit_add DESC
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

### Resolve an actor by name OR alias ("Cozy Bear" → APT29)
`aliases` is populated by the PR #126 alias round-trip — on baselines from
before June 2026 the property is empty (0/917 actors), so this query only
resolves canonical names there. `a.name` is stored lowercase; aliases keep
display case.

```cypher
WITH 'Cozy Bear' AS name
MATCH (a:ThreatActor)
WHERE a.name = toLower(trim(name))
   OR any(x IN coalesce(a.aliases, []) WHERE toLower(trim(x)) = toLower(trim(name)))
RETURN a.name, a.aliases, a.zone
LIMIT 5
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

## Edge provenance (`r.misp_event_ids[]`, `r.sources[]`, `r.source_refs[]`)

PR-N26 wired `r.misp_event_ids[]` onto edges from `build_relationships.py`
for 4 edge types: `INDICATES`, `EXPLOITS`, `TARGETS`, `AFFECTS`. Since
2026-10 every relationship built from the sources carries it, together with
`r.sources[]` and `r.source_refs[]` (see "Who asserts a link" below).

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
// Use case: pivoting from one IoC to others pushed in the same MISP event(s).
// EdgeGuard's MISP events are per-source, per-day buckets (EdgeGuard-{source}-{date}),
// so a shared event means "same source, same day", not "same report".
MATCH (a:Indicator {value: $known_value})-[ra:INDICATES]->(:Malware)
WITH ra.misp_event_ids AS shared_events
MATCH (b:Indicator)-[rb:INDICATES]->(m:Malware)
WHERE any(eid IN rb.misp_event_ids WHERE eid IN shared_events)
RETURN b.value, m.name, rb.misp_event_ids
LIMIT 50
```

```cypher
// Report-level pivot (2026-10): other IoCs whose INDICATES link cites the same source
// record, e.g. the same OTX pulse ("alienvault_otx:<pulse id>" in r.source_refs).
MATCH (a:Indicator {value: $known_value})-[ra:INDICATES]->(:Malware)
UNWIND coalesce(ra.source_refs, []) AS ref
MATCH (b:Indicator)-[rb:INDICATES]->(m:Malware)
WHERE b <> a AND ref IN coalesce(rb.source_refs, [])
RETURN ref, b.value, m.name
LIMIT 50
```

### Who asserts a link, and where is the record (2026-10)

Every relationship built from the sources carries `r.sources[]` (who asserts it), `r.source_refs[]`
(the sources' own record ids, `"<source>:<id>"`) and `r.misp_event_ids[]`
(`docs/KNOWLEDGE_GRAPH.md`, "Relationship provenance").

```cypher
// The evidence behind one actor's techniques, strongest first
MATCH (a:ThreatActor {name: $actor})-[r:EMPLOYS_TECHNIQUE]->(t:Technique)
RETURN t.mitre_id, t.name, r.match_type, r.confidence_score,
       r.sources, r.source_refs[0..5] AS records, r.misp_event_ids[0..5] AS misp_events
ORDER BY r.confidence_score DESC, size(r.sources) DESC
LIMIT 50
```

```cypher
// Corroboration: links that two or more independent sources state
MATCH (x)-[r]->(y)
WHERE size(coalesce(r.sources, [])) >= 2
RETURN type(r) AS rel, r.sources AS sources, count(*) AS links
ORDER BY links DESC
LIMIT 25
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

_Last updated: 2026-10-15 — attack-vector note (`c.attack_vector` from the CVSS that gives the score, NVD's words, null without CVSS) and the network-exploitable CVE sample; edge-provenance section: `r.misp_event_ids[]` is on every relationship built from the sources (no longer only the four PR-N26 types); the MISP-event pivot states that events are per-source, per-day buckets, and a report-level pivot on `r.source_refs[]` was added. Prior: 2026-10-14 — score note (`cvss_version`; unscored CVEs have a null score, not 3.0 / LOW) and the sample for CVEs without a CVSS 3.x / 2 score; added the relationship-provenance samples (`r.sources[]`, `r.source_refs[]`). Prior: 2026-06-12 — added the CISA-KEV sample (`cisa_exploit_add`, range-indexed since PR #126), the alias-aware actor-resolve sample, and the header pointer to the test-pinned `_TI_GRAPHRAG` catalog (19 analyst-question shapes). Prior: 2026-05-25 — Cypher-catalog verification against the live graph: switched the Vulnerabilities sample queries from the legacy `:Vulnerability` label (empty on current baselines) to `:CVE` (the label the sync actually writes) and added the label note in the Vulnerabilities section. Prior: 2026-04-28 — PR-N36 Tier-2 deep verification: corrected the "stored on `zone` property, not as extra labels" claim — sectors are stored on BOTH (`zone` property at MERGE time, plus secondary labels like `:Healthcare` after `apply_sector_labels()` runs post-sync). Recommend `zone` property for portable queries that work pre or post the label-apply step. Prior: 2026-04-26 PR-N33 docs audit (replaced broken `t.platforms` query with `t.tactic_phases`; added Edge provenance section)._

*Save queries to test the prototype*
