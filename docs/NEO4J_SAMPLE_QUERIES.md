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

`zone` is a list (for example `['healthcare', 'energy']`), so the query unwinds it and counts each node once per zone, as `get_stats()` does ([DATA_QUALITY.md](DATA_QUALITY.md#zone-counts-in-the-statistics)):

```cypher
MATCH (n)
WHERE n.zone IS NOT NULL
UNWIND n.zone AS zone
RETURN zone, count(DISTINCT n) AS count
ORDER BY count DESC
```

---

## Vulnerabilities

> **Label note:** the MISP→Neo4j sync routes every CVE through `merge_cve()` → the **`:CVE`** label (`MISPToNeo4jSync._sync_to_neo4j_chunk` in `src/run_misp_to_neo4j.py`: CVEs with and without CVSS sub-nodes alike). The **`:Vulnerability`** label is **empty** on current baselines (the production snapshot of 2026-05-25 held 99,757 `:CVE` and 0 `:Vulnerability`), so query `:CVE`. If a graph may hold `:Vulnerability` nodes, use the portable form `MATCH (v) WHERE v:CVE OR v:Vulnerability`.

> **Scores:** `c.cvss_score` / `c.severity` are the base score and rating of the CVE's first CVSS in the order v3.1 → v3.0 → v2 → v4.0, and `c.cvss_version` names the version. A CVE without any CVSS (rejected, or awaiting NVD analysis without a CNA score) has a null score and severity `UNKNOWN`.
>
> **Attack vector:** `c.attack_vector` is the attack vector of the same CVSS, in NVD's words — `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` — and null without CVSS.

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
Sectors are stored on the **`zone`** property (list of strings) at MERGE time. After the post-sync `apply_sector_labels()` call (`Neo4jClient.apply_sector_labels` in `src/neo4j_client.py`, run at the end of every sync; `global` is never a label), nodes ALSO get secondary labels (e.g. `:CVE :Healthcare`). For portable queries — pre or post `apply_sector_labels` — use the `zone` property:

```cypher
MATCH (c:CVE)
WHERE 'healthcare' IN coalesce(c.zone, [])
RETURN c.cve_id, c.cvss_score, c.description
LIMIT 20
```

### Find actively exploited CVEs (CISA KEV)
`cisa_exploit_add` (date added to the CISA Known Exploited Vulnerabilities
list) is range-indexed. Both NVD-enriched and CISA-only CVEs carry it.

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
`aliases` is populated by the alias round trip (MISP `alias:` tags). `a.name`
is stored lowercase; aliases keep display case.

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
// `merge_technique` in src/neo4j_client.py writes `tactic_phases`, `detection`,
// `is_subtechnique` (from the dotted id), `attack_domain`, `deprecated`, `name`,
// `description` and `description_source`; it sets no `t.platforms`, so a filter
// on platforms returns zero rows. Filter on `tactic_phases`, which is populated:
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
WHERE r.match_type = 'mitre_explicit'
RETURN m.name, t.mitre_id, t.name, r.match_type, r.confidence_score
LIMIT 25
```

Drop the `WHERE` to also see the OTX-reported links (`otx_pulse`, 0.6, step 6b) and the curated ones (0.85).

`IMPLEMENTS_TECHNIQUE` (malware/tool capability) is distinct from `EMPLOYS_TECHNIQUE` (actor attribution); both become STIX 2.1 `relationship_type: "uses"` on export. To query all three specialized technique types at once:

```cypher
MATCH (n)-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
RETURN labels(n)[0] AS source_label, n.name AS source_name,
       type(r) AS rel_type, t.mitre_id, t.name, r.confidence_score
LIMIT 50
```

---

## Alert Enrichment Example

### Trace indicator → malware → threat actor (attribution chain)
```cypher
MATCH (i:Indicator)-[:INDICATES]->(m:Malware)
MATCH (m)-[:ATTRIBUTED_TO]->(a:ThreatActor)
RETURN i.value AS indicator, m.name AS malware, a.name AS actor
LIMIT 10
```

### CVEs named in the same OTX report as an indicator
```cypher
// INDICATES to a CVE says only that one OTX pulse names both (r.source_refs names the pulse);
// the indicator's own claim to exploit a CVE is EXPLOITS (cve_tag).
MATCH (i:Indicator {value: $value})-[r:INDICATES]->(c:CVE)
WHERE r.match_type = 'otx_pulse'
RETURN c.cve_id AS cve, c.cvss_score AS cvss, c.severity AS severity, r.source_refs AS reports
ORDER BY cve
```

---

## Edge provenance (`r.misp_event_ids[]`, `r.sources[]`, `r.source_refs[]`)

Every relationship built from the sources carries `r.misp_event_ids[]`,
together with `r.sources[]` and `r.source_refs[]` (see "Who asserts a link"
below).

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
// Report-level pivot: other IoCs whose INDICATES link cites the same source
// record, e.g. the same OTX pulse ("alienvault_otx:<pulse id>" in r.source_refs).
MATCH (a:Indicator {value: $known_value})-[ra:INDICATES]->(:Malware)
UNWIND coalesce(ra.source_refs, []) AS ref
MATCH (b:Indicator)-[rb:INDICATES]->(m:Malware)
WHERE b <> a AND ref IN coalesce(rb.source_refs, [])
RETURN ref, b.value, m.name
LIMIT 50
```

### Who asserts a link, and where is the record

Every relationship built from the sources carries `r.sources[]` (who asserts it), `r.source_refs[]`
(the sources' own record ids, `"<source>:<id>"`) and `r.misp_event_ids[]`
(`docs/KNOWLEDGE_GRAPH.md`, "Relationship provenance"). On a link to a `Sector` they name only
the feeds that gave that sector.

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

### Measuring CISA ICS and ATT&CK for ICS

**CISA ICS.** A sector CISA's ICS advisory states is a statement of where the affected product is
**deployed**: the CVE's `AFFECTS` link to the sector carries `match_type = 'advisory_sector'` (0.9), and
the `SOURCED_FROM` edge of the CVE to `cisa_ics` lists it in `stated_zones`; the link cites in `r.source_refs`
only the advisories whose sector note names that sector (the edge's `stated_refs`, `"<zone>|cisa_ics:<id>"`),
not every advisory that names the CVE. It is never a `TARGETS`
link, so it never answers "who targets energy". A sector EdgeGuard infers from text (NVD, KEV, OTX) is
`zone_classification` (0.5): **a query that filters sector links on `match_type = 'zone_classification'`
alone misses CISA's statements**; filter on `type(r)` instead, or on both labels.

```cypher
// What CISA ICS states, per sector: by CISA alone, or also inferred by another feed
MATCH (:CVE)-[r:AFFECTS]->(s:Sector)
WHERE r.match_type = 'advisory_sector'
RETURN s.name AS sector, count(*) AS stated,
       sum(CASE WHEN r.sources = ['cisa_ics'] THEN 1 ELSE 0 END) AS cisa_only,
       sum(CASE WHEN size(r.sources) > 1 THEN 1 ELSE 0 END) AS also_inferred
ORDER BY sector
```

```cypher
// The same through the per-source zones, with the advisories, which advisory names which sector,
// and CISA's own sector names
MATCH (c:CVE)-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'})
WITH c, sf, apoc.convert.fromJsonMap(sf.raw_data) AS rec
RETURN c.cve_id, sf.stated_zones AS stated_sectors, sf.source_refs AS advisories,
       sf.stated_refs AS advisories_per_sector, rec.ics_sectors AS cisa_sector_names
LIMIT 25
```

```cypher
// The CISA ICS advisories a sector link cites (only those that name the sector)
MATCH (c:CVE)-[r:AFFECTS]->(s:Sector)
WHERE r.match_type = 'advisory_sector'
RETURN c.cve_id, s.name AS sector, [x IN r.source_refs WHERE x STARTS WITH 'cisa_ics:'] AS advisories
LIMIT 25
```

```cypher
// CISA ICS CVEs whose advisory names no tracked sector (Water, Critical Manufacturing, ...)
MATCH (c:CVE)-[sf:SOURCED_FROM]->(:Source {source_id: 'cisa_ics'})
WHERE sf.zones = ['global']
RETURN count(c) AS cisa_cves_without_a_tracked_sector
```

```cypher
// Every sector link by kind of evidence (both labels; never filter on one alone)
MATCH (n)-[r:AFFECTS|TARGETS]->(s:Sector)
RETURN type(r) AS rel, labels(n)[0] AS label, s.name AS sector, r.match_type AS evidence, count(*) AS links
ORDER BY rel, label, sector, evidence
```

**ATT&CK for ICS.** Only `Technique` and `Tactic` nodes carry `attack_domain`; a group or software item in
both ATT&CK bundles keeps the Enterprise item, and no `ThreatActor`, `Malware` or `Tool` node carries a
domain. Measure ICS through the links into ICS techniques (`IMPLEMENTS_TECHNIQUE`, `EMPLOYS_TECHNIQUE`,
`SUBTECHNIQUE_OF`) and `IN_TACTIC` from an ICS technique to an ICS tactic:

```cypher
// Links into ATT&CK for ICS techniques, by relationship type and start label
MATCH (n)-[r]->(t:Technique {attack_domain: 'ics'})
RETURN type(r) AS rel, labels(n)[0] AS label, count(*) AS links, count(DISTINCT n) AS nodes
ORDER BY links DESC
```

```cypher
// ICS techniques in ICS tactics (IN_TACTIC runs from a technique to a tactic, never into a technique)
MATCH (t:Technique {attack_domain: 'ics'})-[:IN_TACTIC]->(tc:Tactic {attack_domain: 'ics'})
RETURN tc.name AS tactic, count(t) AS ics_techniques
ORDER BY ics_techniques DESC
```

```cypher
// The malware and actors with ATT&CK for ICS techniques
MATCH (n)-[:IMPLEMENTS_TECHNIQUE|EMPLOYS_TECHNIQUE]->(t:Technique {attack_domain: 'ics'})
RETURN labels(n)[0] AS label, n.name AS name, collect(DISTINCT t.mitre_id) AS ics_techniques
ORDER BY size(ics_techniques) DESC
LIMIT 25
```

---

*Save queries to test the prototype*

_Last updated: 2026-10-18_

## History

- 2026-10-18 — Sample query: the CVEs named in the same OTX report as an indicator (`INDICATES` to a `CVE`).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-18 — *Count by zone* unwinds the `zone` list and counts each node once per zone.
- 2026-10-17 — Main text restated as a guide to current behaviour; change history moved to this section and queries for graphs built by earlier versions to the appendix.
- 2026-10-17 — The `IMPLEMENTS_TECHNIQUE` sample filters on `mitre_explicit`, because OTX-reported and curated links share the type; code references name functions instead of line numbers; the properties `merge_technique` writes are listed.
- 2026-10-16 — "Measuring CISA ICS and ATT&CK for ICS": CISA's sector statements (`advisory_sector` on `AFFECTS`, `SOURCED_FROM.stated_zones`, the advisories a sector link cites) and ATT&CK for ICS through the links into ICS techniques; a link to a `Sector` names only the feeds that gave the sector.
- 2026-10-15 — Attack-vector note and the network-exploitable CVE sample; `r.misp_event_ids[]` on every relationship built from the sources; the MISP-event pivot states that events are per-source, per-day buckets, and a report-level pivot on `r.source_refs[]` was added.
- 2026-10-14 — Score note (`cvss_version`; unscored CVEs have a null score, not 3.0 / LOW), the sample for CVEs without a CVSS 3.x / 2 score, and the relationship-provenance samples (`r.sources[]`, `r.source_refs[]`).
- 2026-06-12 — CISA-KEV sample (`cisa_exploit_add`, range-indexed), the alias-aware actor-resolve sample, and the pointer to the test-pinned `_TI_GRAPHRAG` catalog.
- 2026-05-25 — The Vulnerabilities samples query the `:CVE` label the sync writes instead of the empty `:Vulnerability` label, verified against the live graph.
- 2026-04-28 — Sectors are stored both on the `zone` property and as secondary labels after `apply_sector_labels()`; the `zone` property is recommended for portable queries.
- 2026-04-26 — The technique sample filters on `t.tactic_phases` instead of the never-written `t.platforms`; the edge-provenance section was added.
- 2026-04-15 — The generic `USES` edge to a technique became `IMPLEMENTS_TECHNIQUE` for malware and tools, distinct from `EMPLOYS_TECHNIQUE` for actors.
- 2026-03-28 — First version of the sample queries.
