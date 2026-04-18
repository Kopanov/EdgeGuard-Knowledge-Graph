# EdgeGuard Technical Specification

## For ResilMesh Engineers

---

## Neo4j Connection

```
URI:     bolt://localhost:7687
Browser: http://localhost:7474
Auth:    Configured via environment variables
```

---

## Complete Node Schema

### EdgeGuard ThreatIntel Nodes

#### Vulnerability
```cypher
(:Vulnerability {
  cve_id: STRING,           // CVE identifier (e.g., "CVE-2023-1234")
  cvss_score: FLOAT,        // CVSS score (0-10)
  severity: STRING,         // Critical/High/Medium/Low
  attack_vector: STRING,    // Network/Adjacent/Local/Physical
  description: STRING,      // Vulnerability description (up to 1000 chars)
  zone: LIST,               // Zone(s): ['finance'], ['energy', 'global'] — always a list
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  sources: LIST,            // Accumulated source list (deduped)
  confidence_score: FLOAT,  // 0.0-1.0 (0.9 for CISA KEV entries)
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME,   // Last update
  active: BOOLEAN,          // Active in MISP
  // NVD-enriched fields
  cwe: LIST,                // CWE identifiers (e.g., ['CWE-787'])
  ref_tags: LIST,           // Reference tags (Vendor Advisory, Patch, etc.)
  cpe_type: LIST,           // CPE types (a=application, o=os, h=hardware)
  result_impacts: LIST,     // CIA impact strings
  affected_products: LIST,  // CPE URIs (up to 10)
  // CISA KEV fields (present when CVE is actively exploited)
  cisa_exploit_add: STRING,        // Date added to CISA KEV
  cisa_action_due: STRING,         // Federal remediation deadline
  cisa_required_action: STRING,    // Required mitigation action
  cisa_vulnerability_name: STRING  // CISA-assigned vulnerability name
})
// Source provenance is on the SOURCED_FROM relationship, not a node property.
// CVSS sub-nodes (CVSSv40, CVSSv31, CVSSv30, CVSSv2) linked via HAS_CVSS_* relationships.
```

#### Indicator (IOC)
```cypher
(:Indicator {
  indicator_type: STRING,   // ipv4, ipv6, domain, sha256, md5, url
  value: STRING,            // The indicator value
  zone: LIST,               // Zone(s): ['finance'] — always a list, never a string
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  sources: LIST,            // Accumulated source list (deduped)
  confidence_score: FLOAT,  // 0.0-1.0
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME,   // Last update
  misp_event_ids: LIST,     // Accumulated MISP event ids (set, deduped)
  misp_attribute_ids: LIST, // Accumulated MISP attribute UUIDs (stable cross-instance, from attr.uuid; set, deduped)
  uuid: STRING,             // 2026-04 (PR #33): deterministic uuid5(namespace, canonical(label, natural_key))
                            //                   — same value on local + cloud Neo4j; equals the UUID portion of the
                            //                   corresponding STIX SDO id. See src/node_identity.py.
  // OTX enrichment fields
  attack_ids: LIST,              // MITRE ATT&CK technique IDs from OTX pulse
  targeted_countries: LIST,      // ISO country codes from OTX pulse
  // ThreatFox enrichment fields
  malware_family: STRING,        // Associated malware family name
  malware_malpedia: STRING,      // Malpedia URL for the malware family
  reference: STRING,             // Source URL (ThreatFox IOC page, etc.)
  reporter: STRING,              // Who reported the IOC
  // AbuseIPDB enrichment fields
  domain: STRING,                // Reverse DNS domain
  hostnames: LIST,               // Associated hostnames
  // VT enrichment fields
  yara_rules: LIST,                  // Crowdsourced YARA rule names
  sigma_rules: LIST,                 // Sigma detection rule titles
  // AbuseIPDB enrichment
  abuse_categories: LIST,            // Abuse category IDs
  // OTX enrichment
  indicator_role: STRING             // Role classification (C2, Dropper, etc.)
})
// Source provenance is on the SOURCED_FROM relationship, not a node property.
```

#### Malware
```cypher
(:Malware {
  name: STRING,             // Malware name
  malware_types: LIST,      // Types (trojan, ransomware, etc.)
  family: STRING,           // Malware family
  description: STRING,      // Description
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  sources: LIST,            // Accumulated source list (deduped)
  uses_techniques: LIST,    // Optional MITRE IDs from STIX malware→technique **uses** (MISP **MITRE_USES_TECHNIQUES:**)
  confidence_score: FLOAT,  // 0.0-1.0
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME,   // Last update
  misp_event_ids: LIST      // Accumulated MISP event ids (set, deduped)
})
```

#### ThreatActor
```cypher
(:ThreatActor {
  name: STRING,             // Actor name
  aliases: LIST,            // Known aliases
  description: STRING,      // Description
  sources: LIST,            // Data sources
  uses_techniques: LIST,    // MITRE IDs from STIX actor **uses** technique; drives (Actor)-[:EMPLOYS_TECHNIQUE]->(Technique) edges in build_relationships.py. Property name retained as-is (STIX-side contract).
  confidence_score: FLOAT,  // 0.0-1.0
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Technique (MITRE ATT&CK)
```cypher
(:Technique {
  mitre_id: STRING,         // T#### or T####.###
  name: STRING,             // Technique name
  description: STRING,      // Description
  platforms: LIST,          // Target platforms
  sources: LIST,            // Data sources
  confidence_score: FLOAT,  // 0.0-1.0
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Tool (MITRE ATT&CK)
```cypher
(:Tool {
  mitre_id: STRING,         // Tool ID (S0001)
  name: STRING,             // Tool name
  description: STRING,      // Description
  tag: STRING,              // Source tag
  tool_types: LIST,         // Classification labels
  uses_techniques: LIST,    // MITRE IDs from STIX uses relationships
  zone: LIST,               // Detected zones
  sources: LIST,            // Accumulated sources
  confidence_score: FLOAT   // 0.0-1.0
})
```

#### Alert
```cypher
(:Alert {
  alert_id: STRING,         // Unique alert ID
  source: STRING,           // Alert source (wazuh, suricata)
  zone: LIST,               // Zone(s) — always a list, like all other node types
  timestamp: DATETIME,      // Alert timestamp
  severity: INTEGER,        // 0-10 severity
  description: STRING,      // Alert description
  indicator: STRING,        // Related indicator
  indicator_type: STRING,   // Type of indicator
  malware: STRING,          // Related malware
  cve: STRING,              // Related CVE
  enriched: BOOLEAN,        // Enrichment status
  enrichment_latency_ms: FLOAT,
  received_at: DATETIME,    // When received
  last_updated: DATETIME    // Last update
})
```

---

### ResilMesh Topology Nodes

#### IP
```cypher
(:IP {
  address: STRING,          // IP address
  status: STRING,           // active/inactive
  version: INTEGER,         // 4 or 6
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Host
```cypher
(:Host {
  hostname: STRING,         // Hostname
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Device
```cypher
(:Device {
  device_id: STRING,        // Device identifier
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Node (Topology)
```cypher
(:Node {
  node_id: STRING,          // Node identifier
  degree_centrality: FLOAT, // Graph metric
  pagerank_centrality: FLOAT, // Graph metric
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Subnet
```cypher
(:Subnet {
  range: STRING,            // CIDR range (e.g., "192.168.1.0/24")
  note: STRING,             // Optional note
  version: INTEGER,         // 4 or 6
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### SoftwareVersion
```cypher
(:SoftwareVersion {
  version: STRING,          // Version string
  cve_timestamp: STRING,    // CVE data timestamp
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### NetworkService
```cypher
(:NetworkService {
  port: INTEGER,            // Port number
  protocol: STRING,         // tcp/udp/icmp
  service: STRING,          // Service name (http, ssh, etc.)
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Application
```cypher
(:Application {
  name: STRING,             // Application name
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### User (ResilMesh)
```cypher
(:User {
  username: STRING,         // Username
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Role
```cypher
(:Role {
  role_name: STRING,        // Role name
  permission: STRING,       // Permission level
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Component
```cypher
(:Component {
  name: STRING,             // Component name
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### Mission
```cypher
(:Mission {
  name: STRING,             // Mission name
  description: STRING,      // Mission description
  structure: STRING,        // Structure info
  criticality: INTEGER,     // Criticality level
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### OrganizationUnit
```cypher
(:OrganizationUnit {
  name: STRING,             // Unit name
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### MissionDependency
```cypher
(:MissionDependency {
  dependency_id: STRING,    // Dependency identifier
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

---

### ResilMesh CVE/CVSS Nodes

#### CVE (ResilMesh Detailed)
```cypher
(:CVE {
  cve_id: STRING,           // CVE identifier
  description: STRING,      // Description
  published: STRING,        // Publication date
  last_modified: STRING,    // Last modified date
  cpe_type: LIST,           // CPE types
  result_impacts: LIST,     // Impact results
  ref_tags: LIST,           // Reference tags
  cwe: LIST,                // CWE identifiers
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

#### CVSSv2
```cypher
(:CVSSv2 {
  vector_string: STRING,           // CVSS vector
  base_score: FLOAT,               // Base score
  base_severity: STRING,           // Severity
  access_vector: STRING,           // AV component
  access_complexity: STRING,       // AC component
  authentication: STRING,          // Au component
  confidentiality_impact: STRING,  // C component
  integrity_impact: STRING,        // I component
  availability_impact: STRING,     // A component
  impact_score: FLOAT,             // Impact subscore
  exploitability_score: FLOAT,     // Exploitability subscore
  ac_insuf_info: BOOLEAN,          // Additional flags
  obtain_user_privilege: BOOLEAN,
  obtain_other_privilege: BOOLEAN,
  obtain_all_privilege: BOOLEAN,
  user_interaction_required: BOOLEAN,
  tag: STRING,                     // Data provenance tag
  first_seen: DATETIME,            // First observed
  last_updated: DATETIME           // Last update
})
```

#### CVSSv30
```cypher
(:CVSSv30 {
  vector_string: STRING,           // CVSS vector
  base_score: FLOAT,               // Base score
  base_severity: STRING,           // Severity
  attack_vector: STRING,           // AV component
  attack_complexity: STRING,       // AC component
  privileges_required: STRING,     // PR component
  user_interaction: STRING,        // UI component
  scope: STRING,                   // S component
  confidentiality_impact: STRING,  // C component
  integrity_impact: STRING,        // I component
  availability_impact: STRING,     // A component
  impact_score: FLOAT,             // Impact subscore
  exploitability_score: FLOAT,     // Exploitability subscore
  tag: STRING,                     // Data provenance tag
  first_seen: DATETIME,            // First observed
  last_updated: DATETIME           // Last update
})
```

#### CVSSv31
```cypher
(:CVSSv31 {
  vector_string: STRING,           // CVSS vector
  base_score: FLOAT,               // Base score
  base_severity: STRING,           // Severity
  attack_vector: STRING,           // AV component
  attack_complexity: STRING,       // AC component
  privileges_required: STRING,     // PR component
  user_interaction: STRING,        // UI component
  scope: STRING,                   // S component
  confidentiality_impact: STRING,  // C component
  integrity_impact: STRING,        // I component
  availability_impact: STRING,     // A component
  impact_score: FLOAT,             // Impact subscore
  exploitability_score: FLOAT,     // Exploitability subscore
  tag: STRING,                     // Data provenance tag
  first_seen: DATETIME,            // First observed
  last_updated: DATETIME           // Last update
})
```

#### CVSSv40
```cypher
(:CVSSv40 {
  vector_string: STRING,           // CVSS vector
  base_score: FLOAT,               // Base score
  base_severity: STRING,           // Severity
  tag: STRING,                     // Data provenance tag
  first_seen: DATETIME,            // First observed
  last_updated: DATETIME           // Last update
})
```

#### Vulnerability (ResilMesh)
```cypher
(:Vulnerability {
  vuln_id: STRING,          // Vulnerability ID
  description: STRING,      // Description
  status: LIST,             // Status flags
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed
  last_updated: DATETIME    // Last update
})
```

---

## Complete Relationship Schema

### EdgeGuard ThreatIntel Relationships

| Relationship | From | To | Properties |
|--------------|------|-----|------------|
| `EMPLOYS_TECHNIQUE` | ThreatActor / Campaign | Technique | **Attribution.** `confidence_score` (~0.95), `match_type='mitre_explicit'`, … (`build_relationships.py`, `uses_techniques` on actor). *Split from a generic `USES` in 2026-04 — pre-release framework, no migration script shipped; a fresh baseline rerun writes the specialized edge type directly.* |
| `IMPLEMENTS_TECHNIQUE` | Malware / Tool | Technique | **Capability.** Same properties as `EMPLOYS_TECHNIQUE`; same MITRE STIX **`uses`** source via `node.uses_techniques` (`build_relationships.py`). Split from a generic `USES` in 2026-04. |
| `ATTRIBUTED_TO` | Malware | ThreatActor | `confidence_score`, `match_type`, `created_at` (`build_relationships.py`) |
| `INDICATES` | Indicator | Malware | Initial `confidence_score` 0.5, `match_type='misp_cooccurrence'`, `source_id='misp_cooccurrence'`; **also** `malware_family` name match from ThreatFox/VT (`confidence_score` 0.8); calibrated by `enrichment_jobs.calibrate_cooccurrence_confidence` |
| `EXPLOITS` | Indicator | `Vulnerability` or `CVE` | `confidence_score` 1.0, `match_type='cve_tag'`, `source_id='cve_tag_match'` |
| `USES_TECHNIQUE` | Indicator | Technique | OTX pulse `attack_ids` exact MITRE ID match (`confidence_score` 0.85) |
| `REFERS_TO` | `Vulnerability` | `CVE` (and reverse) | Created by `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor | Campaign | `build_campaign_nodes()` |
| `PART_OF` | Malware, Indicator | Campaign | `build_campaign_nodes()` |
| `INVOLVES` | Alert | Indicator | `created_at`, `source` (`neo4j_client`) |

### ResilMesh Topology Relationships

| Relationship | From | To | Properties |
|--------------|------|-----|------------|
| `ON` | SoftwareVersion | Host | created_at |
| `TO` | Role | Device | created_at |
| `ASSIGNED_TO` | Role | User | created_at |
| `HAS_IDENTITY` | Device | Host | created_at |
| `HAS_IDENTITY` | Host | Device | created_at |
| `IS_A` | Node | Host | created_at |
| `IS_A` | Host | Node | created_at |
| `HAS_ASSIGNED` | IP | Node | created_at |
| `HAS_ASSIGNED` | Node | IP | created_at |
| `PART_OF` | IP | Subnet | created_at |
| `PART_OF` | Subnet | Subnet | created_at |
| `PART_OF` | Subnet | OrganizationUnit | created_at |
| `PART_OF` | OrganizationUnit | OrganizationUnit | created_at |
| `FOR` | Mission | OrganizationUnit | created_at |
| `SUPPORTS` | Mission | Component | created_at |
| `PROVIDED_BY` | Component | Host | created_at |
| `FROM` | Component | MissionDependency | created_at |
| `TO` | Component | MissionDependency | created_at |
| `IS_CONNECTED_TO` | Node | Node | start, end, created_at |
| `ON` | NetworkService | Host | status, created_at |
| `HAS_IDENTITY` | Component | Application | created_at |
| `HAS_IDENTITY` | Application | Component | created_at |
| `IN` | SoftwareVersion | Vulnerability | created_at |
| `REFERS_TO` | Vulnerability | CVE | created_at |
| `REFERS_TO` | CVE | Vulnerability | created_at |
| `HAS_CVSS_v2` | CVE | CVSSv2 | created_at |
| `HAS_CVSS_v30` | CVE | CVSSv30 | created_at |
| `HAS_CVSS_v31` | CVE | CVSSv31 | created_at |
| `HAS_CVSS_v40` | CVE | CVSSv40 | created_at |

### Bridge Relationships (EdgeGuard ↔ ResilMesh)

| Relationship | From | To | Properties |
|--------------|------|-----|------------|
| `RESOLVES_TO` | Indicator | IP | created_at, source, confidence_score |
| `MAPS_TO` | Vulnerability | CVE | created_at, source, confidence_score |
| `TARGETS` | Malware | Host | created_at, source, confidence_score |

---

## Constraints

### UNIQUE Constraints (30 total)

```cypher
// EdgeGuard constraints (15) — tag removed; entities merge across sources
CREATE CONSTRAINT source_key FOR (s:Source) REQUIRE (s.source_id) IS UNIQUE;
CREATE CONSTRAINT cve_key FOR (c:CVE) REQUIRE (c.cve_id) IS UNIQUE;
CREATE CONSTRAINT vulnerability_key FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE;
CREATE CONSTRAINT indicator_key FOR (i:Indicator) REQUIRE (i.indicator_type, i.value) IS UNIQUE;
CREATE CONSTRAINT malware_key FOR (m:Malware) REQUIRE (m.name) IS UNIQUE;
CREATE CONSTRAINT actor_key FOR (a:ThreatActor) REQUIRE (a.name) IS UNIQUE;
CREATE CONSTRAINT technique_key FOR (t:Technique) REQUIRE (t.mitre_id) IS UNIQUE;
CREATE CONSTRAINT tactic_key FOR (t:Tactic) REQUIRE (t.mitre_id) IS UNIQUE;
CREATE CONSTRAINT tool_key FOR (t:Tool) REQUIRE (t.mitre_id) IS UNIQUE;
CREATE CONSTRAINT sector_key FOR (s:Sector) REQUIRE (s.name) IS UNIQUE;
CREATE CONSTRAINT campaign_key FOR (c:Campaign) REQUIRE (c.name) IS UNIQUE;
// CVSS sub-nodes — one per CVE (scores are properties of the vuln, not the source)
CREATE CONSTRAINT cvssv2_key FOR (n:CVSSv2) REQUIRE (n.cve_id) IS UNIQUE;
CREATE CONSTRAINT cvssv30_key FOR (n:CVSSv30) REQUIRE (n.cve_id) IS UNIQUE;
CREATE CONSTRAINT cvssv31_key FOR (n:CVSSv31) REQUIRE (n.cve_id) IS UNIQUE;
CREATE CONSTRAINT cvssv40_key FOR (n:CVSSv40) REQUIRE (n.cve_id) IS UNIQUE;

// ResilMesh topology constraints (15)
CREATE CONSTRAINT ip_key FOR (ip:IP) REQUIRE (ip.address, ip.tag) IS UNIQUE;
CREATE CONSTRAINT host_key FOR (h:Host) REQUIRE (h.hostname, h.tag) IS UNIQUE;
CREATE CONSTRAINT device_key FOR (d:Device) REQUIRE (d.device_id, d.tag) IS UNIQUE;
CREATE CONSTRAINT subnet_key FOR (s:Subnet) REQUIRE (s.range, s.tag) IS UNIQUE;
CREATE CONSTRAINT node_key FOR (n:Node) REQUIRE (n.node_id, n.tag) IS UNIQUE;
CREATE CONSTRAINT softwareversion_key FOR (sv:SoftwareVersion) REQUIRE (sv.version, sv.tag) IS UNIQUE;
CREATE CONSTRAINT application_key FOR (app:Application) REQUIRE (app.name, app.tag) IS UNIQUE;
CREATE CONSTRAINT networkservice_key FOR (ns:NetworkService) REQUIRE (ns.port, ns.protocol, ns.tag) IS UNIQUE;
CREATE CONSTRAINT resilmesh_cve_key FOR (c:CVE) REQUIRE (c.cve_id, c.tag) IS UNIQUE;
CREATE CONSTRAINT user_key FOR (u:User) REQUIRE (u.username, u.tag) IS UNIQUE;
CREATE CONSTRAINT role_key FOR (r:Role) REQUIRE (r.role_name, r.tag) IS UNIQUE;
CREATE CONSTRAINT component_key FOR (c:Component) REQUIRE (c.name, c.tag) IS UNIQUE;
CREATE CONSTRAINT mission_key FOR (m:Mission) REQUIRE (m.name, m.tag) IS UNIQUE;
CREATE CONSTRAINT organizationunit_key FOR (ou:OrganizationUnit) REQUIRE (ou.name, ou.tag) IS UNIQUE;
CREATE CONSTRAINT resilmesh_vulnerability_key FOR (v:Vulnerability) REQUIRE (v.vuln_id, v.tag) IS UNIQUE;
```

---

## Indexes

### Performance Indexes (43 total)

```cypher
// EdgeGuard indexes (28)
CREATE INDEX source_id_idx FOR (s:Source) ON (s.source_id);
CREATE INDEX vulnerability_cve FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX indicator_value FOR (i:Indicator) ON (i.value);
CREATE INDEX indicator_type FOR (i:Indicator) ON (i.indicator_type);
CREATE INDEX indicator_source FOR (i:Indicator) ON (i.source);
CREATE INDEX indicator_zone FOR (i:Indicator) ON (i.zone);
CREATE INDEX malware_name FOR (m:Malware) ON (m.name);
CREATE INDEX actor_name FOR (a:ThreatActor) ON (a.name);
CREATE INDEX technique_mitre FOR (t:Technique) ON (t.mitre_id);
// PR #34 round 18: indicator_original_source / vulnerability_original_source
// indexes removed — the n.original_source property had zero readers.
CREATE INDEX indicator_active FOR (i:Indicator) ON (i.active);
CREATE INDEX vulnerability_active FOR (v:Vulnerability) ON (v.active);
// PR #33 round 10: legacy-scalar indexes (indicator/vulnerability/malware/
// actor _misp_event_id and indicator_misp_attribute_id) removed. All readers
// now match against misp_event_ids[] / misp_attribute_ids[] via list-membership
// predicates (`eid IN n.misp_event_ids`).
CREATE INDEX tactic_shortname FOR (t:Tactic) ON (t.shortname);
CREATE INDEX technique_tactic_phases FOR (t:Technique) ON (t.tactic_phases);
CREATE INDEX cvssv31_cve_id FOR (n:CVSSv31) ON (n.cve_id);
CREATE INDEX cvssv30_cve_id FOR (n:CVSSv30) ON (n.cve_id);
CREATE INDEX cvssv2_cve_id FOR (n:CVSSv2) ON (n.cve_id);
CREATE INDEX cvssv40_cve_id FOR (n:CVSSv40) ON (n.cve_id);
CREATE INDEX campaign_actor_name FOR (c:Campaign) ON (c.actor_name);
CREATE INDEX campaign_zone FOR (c:Campaign) ON (c.zone);
CREATE INDEX indicator_last_updated FOR (i:Indicator) ON (i.last_updated);
CREATE INDEX vulnerability_last_updated FOR (v:Vulnerability) ON (v.last_updated);
CREATE INDEX cve_cve_id FOR (c:CVE) ON (c.cve_id);

// ResilMesh indexes (15)
CREATE INDEX ip_address FOR (ip:IP) ON (ip.address);
CREATE INDEX ip_status FOR (ip:IP) ON (ip.status);
CREATE INDEX host_hostname FOR (h:Host) ON (h.hostname);
CREATE INDEX subnet_range FOR (s:Subnet) ON (s.range);
CREATE INDEX node_centrality FOR (n:Node) ON (n.degree_centrality);
CREATE INDEX softwareversion_version FOR (sv:SoftwareVersion) ON (sv.version);
CREATE INDEX application_name FOR (app:Application) ON (app.name);
CREATE INDEX networkservice_port FOR (ns:NetworkService) ON (ns.port);
CREATE INDEX resilmesh_cve_id FOR (c:CVE) ON (c.cve_id);
CREATE INDEX resilmesh_cve_published FOR (c:CVE) ON (c.published);
CREATE INDEX cvss_base_score FOR (cv:CVSSv2|CVSSv30|CVSSv31|CVSSv40) ON (cv.base_score);
CREATE INDEX user_username FOR (u:User) ON (u.username);
CREATE INDEX mission_name FOR (m:Mission) ON (m.name);
CREATE INDEX mission_criticality FOR (m:Mission) ON (m.criticality);
CREATE INDEX organizationunit_name FOR (ou:OrganizationUnit) ON (ou.name);
```

---

## API Endpoints

### FastAPI Query Engine

| Method | Path | Description | Parameters |
|--------|------|-------------|------------|
| GET | `/health` | Health check — **HTTP 200** always; JSON includes `status` (`ok`/`degraded`), `neo4j_connected` (from `Neo4jClient.health_check()`: ping + APOC). | - |
| POST | `/query` | Natural language query | query, zone, limit |
| POST | `/search/indicator` | Search by indicator | value, type |
| GET | `/zone/{zone}` | Get threats by zone | zone, limit, active_only |
| GET | `/indicators` | List indicators | skip, limit, zone |
| GET | `/vulnerabilities` | List CVEs | skip, limit, severity |
| GET | `/stats` | Graph statistics | - |
| POST | `/enrich` | Enrich alert | alert_data |

**GraphQL service (default port 4001):** `GET /health` returns **HTTP 200** when Neo4j `health_check()` passes, else **503** — see [README.md](../README.md) § *HTTP APIs*.

### Example Queries

#### Enrich Alert
```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-001",
    "zone": "healthcare",
    "threat": {
      "indicator": "192.168.1.100",
      "type": "ip"
    }
  }'
```

#### Natural Language Query
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{
    "query": "Find malware targeting energy sector",
    "zone": "energy",
    "limit": 10
  }'
```

#### Get Zone Threats
```bash
curl "http://localhost:8000/zone/healthcare?limit=20&active_only=true"
```

---

## NATS Topics

### Subscribe (EdgeGuard ← ResilMesh)

| Topic | Description |
|-------|-------------|
| `resilmesh.alerts.zone.healthcare` | Healthcare alerts |
| `resilmesh.alerts.zone.energy` | Energy sector alerts |
| `resilmesh.alerts.zone.finance` | Finance sector alerts |
| `resilmesh.alerts.zone.global` | Global alerts |
| `resilmesh.threats.zone.{zone}` | Zone-specific threat intel |
| `resilmesh.cve.kev` | Known Exploited Vulnerabilities |

### Publish (EdgeGuard → ResilMesh)

| Topic | Description |
|-------|-------------|
| `resilmesh.enriched.alerts` | Enriched alert responses |
| `resilmesh.threats.cross_zone` | Cross-zone threat alerts |

---

## Alert Format

### Input (ResilMesh → EdgeGuard)

```json
{
  "alert_id": "wazuh-001",
  "source": "wazuh",
  "zone": "healthcare",
  "timestamp": "2026-03-07T10:30:00Z",
  "tags": ["healthcare", "finance"],
  "threat": {
    "indicator": "192.168.1.100",
    "type": "ip",
    "malware": "TrickBot",
    "cve": "CVE-2021-43297",
    "description": "Suspected TrickBot C2 communication",
    "severity": 9,
    "source_ip": "192.168.1.100",
    "dest_ip": "185.220.101.45",
    "hostname": "hospital-server-01",
    "user": "admin",
    "device_type": "MRI Scanner",
    "protocol": "IEC61850"
  }
}
```

### Output (EdgeGuard → ResilMesh)

```json
{
  "alert_id": "wazuh-001",
  "enriched": true,
  "edgeguard_version": "2026.3.21",
  "latency_ms": 120,
  "enrichment": {
    "indicator": {
      "value": "192.168.1.100",
      "type": "ipv4",
      "confidence_score": 0.8
    },
    "malware": [{
      "name": "TrickBot",
      "family": "TrickBot",
      "types": ["trojan", "banking_trojan"]
    }],
    "threat_actors": [{
      "name": "Wizard Spider",
      "aliases": ["IRON LIBERTY", "TEMP.MixMaster"]
    }],
    "techniques": [{
      "mitre_id": "T1021.002",
      "name": "Remote Services: SMB/Windows Admin Shares",
      "tactic": "Lateral Movement"
    }],
    "cves": [{
      "cve_id": "CVE-2021-43297",
      "cvss_score": 9.8,
      "severity": "Critical",
      "description": "Apache Log4j2 JNDI features..."
    }],
    "network_context": {
      "resolved_ip": "192.168.1.100",
      "targeted_hosts": ["hospital-server-01"]
    },
    "affected_zones": ["healthcare", "finance"],
    "confidence": 0.85
  }
}
```

---

## Performance SLAs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Graph query latency (median) | <100-150ms | Neo4j query log |
| End-to-end p95 response | ≤2.0 seconds | API response time |
| Alert enrichment latency | <200ms | Enrichment pipeline |
| Cross-zone threat query | <300ms | Multi-zone queries |
| Node creation | <50ms | Individual MERGE |
| Relationship creation | <30ms | Individual MERGE |

---

## Type Mapping

### Indicator Type Normalization

| ResilMesh Type | EdgeGuard Type | Detection |
|----------------|----------------|-----------|
| `ip` | `ipv4` or `ipv6` | Regex pattern match |
| `ipv4` | `ipv4` | Direct mapping |
| `ipv6` | `ipv6` | Direct mapping |
| `domain` | `domain` | Direct mapping |
| `file_hash` | `sha256` or `md5` | Length detection (64=sha256, 32=md5) |
| `sha256` | `sha256` | Direct mapping |
| `md5` | `md5` | Direct mapping |
| `url` | `url` | Direct mapping |
| `email` | `email` | Direct mapping |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | - | Neo4j password |
| `NATS_SERVERS` | `nats://localhost:4222` | NATS server URLs |
| `NATS_TLS_CERT` | - | TLS certificate path |
| `NATS_TLS_KEY` | - | TLS key path |
| `MISP_URL` | - | MISP instance URL |
| `MISP_API_KEY` | - | MISP API key |
| `EDGEGUARD_MISP_HTTP_HOST` | (unset) | Optional HTTP `Host` when URL hostname ≠ Apache `ServerName` (e.g. Docker DNS `misp_misp_1` vs vhost `misp-edgeguard`). See [MISP_SOURCES.md](MISP_SOURCES.md). |
| `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` | `500` | MISP→Neo4j (`run_misp_to_neo4j`): max **parsed items** per **Python** merge chunk (RAM). **`0`** or **`all`** = single pass (OOM risk). **Not** the MISP event search page size — see [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md). |
| `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS` | `true` | **`MISPWriter`**: before push, prefetch existing **`(type, value)`** on the **target** MISP event and skip duplicates. |
| `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` | `3` | **OTX** scheduled runs: initial **`modified_since`** lookback when no incremental cursor. |
| `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC` | `300` | **OTX**: overlap added to last cursor time (clock skew / API timing). |
| `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` | `25` | **OTX**: max API pages per scheduled run. |
| `EDGEGUARD_MITRE_CONDITIONAL_GET` | `true` | **MITRE** scheduled runs: **`If-None-Match`** / **ETag**; **304** skips download. Baseline still fetches full bundle. |
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Pause (seconds) between each batch of 500 attributes pushed to MISP. Prevents memory exhaustion on large events. |
| `EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC` | `2.0` | Pause (seconds) between fetching consecutive MISP events during sync. |
| `EDGEGUARD_MAX_EVENT_ATTRIBUTES` | `50000` | Events exceeding this attribute count are deferred to end of sync (small events first). `0` = disable. |
| `LOG_LEVEL` | `INFO` | Logging level |

**Collection vs sync limits (baseline caps, incremental caps, MISP prefetch, OTX/MITRE incremental env, MISP search `1000`, Neo4j chunk `500`, `MISPCollector` internals):** [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

---

*Technical Specification Version: 2.0*
*For ResilMesh Engineers*

---

_Last updated: 2026-04-17_
