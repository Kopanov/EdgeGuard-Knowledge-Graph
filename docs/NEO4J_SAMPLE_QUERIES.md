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
Sectors are stored on the **`zone`** property (list of strings), not as extra labels — see `neo4j_client.merge_vulnerability` / ResilMesh schema.

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

### Find techniques by platform
```cypher
MATCH (t:Technique)
WHERE 'Windows' IN t.platforms
RETURN t.mitre_id, t.name
LIMIT 20
```

---

## Malware & MITRE techniques

### Malware with explicit USES → Technique (MITRE STIX)
Requires **`uses_techniques`** on **`Malware`** (from MITRE collector + MISP **`MITRE_USES_TECHNIQUES:`** + sync) and **`build_relationships.py`**.

```cypher
MATCH (m:Malware)-[r:USES]->(t:Technique)
RETURN m.name, t.mitre_id, t.name, r.confidence_score
LIMIT 25
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

---

*Save queries to test the prototype*
