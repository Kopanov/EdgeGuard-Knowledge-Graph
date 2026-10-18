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
  // Score: base score / rating of the CVE's first CVSS in the order v3.1 → v3.0 → v2 → v4.0.
  // On :CVE nodes merge_cve sets all three from the CVSS sub-nodes; no CVSS → cvss_score and
  // cvss_version null, severity UNKNOWN (never a 0.0 placeholder, a cvss: tag band or a KEV/ICS default).
  cvss_score: FLOAT,        // CVSS base score (0-10), null without CVSS
  cvss_version: STRING,     // "3.1", "3.0", "2.0" or "4.0" — which CVSS cvss_score is
  severity: STRING,         // NONE/LOW/MEDIUM/HIGH/CRITICAL, UNKNOWN without CVSS
  // Attack vector: that of the CVSS which gives cvss_score, in NVD's words; null without
  // CVSS. On :CVE nodes merge_cve sets it with the score from the CVSS sub-nodes (CVSS 3.x
  // attack_vector, CVSS 2 access_vector, the AV metric of a CVSS 4.0 vector_string); never the
  // vector-string letter (N/L/A/P), UNKNOWN or a KEV/OTX default.
  attack_vector: STRING,    // NETWORK / ADJACENT_NETWORK / LOCAL / PHYSICAL, null without CVSS
  // published / last_modified where a record carries them: set by NVD's record; a KEV,
  // CISA ICS or OTX record, a STIX import or a partner write fills them only where the node has none.
  // description: the text of the highest-ranked source, NVD > CISA KEV > CISA ICS > any
  // other source, named in description_source (src/description_ranking.py). A MISP metadata block
  // (OTX_META:{...}, NVD_META:{...}) and an OTX pulse reference ("Referenced in OTX pulse: <name>")
  // are never a description.
  description: STRING,      // Vulnerability description (up to 1000 chars)
  description_source: STRING, // The source of description ("nvd", "cisa_kev", ...)
  zone: LIST,               // Zone(s): ['finance'], ['energy', 'global'] — always a list
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
  confidence_score: FLOAT,  // 0.0-1.0; not a KEV marker: the MISP sync stores 0.5 for every CVE (CVE attributes
                            // carry no confidence tag; the highest value written is kept). Select KEV entries
                            // with cisa_exploit_add IS NOT NULL
  first_imported_at: DATETIME, // When EdgeGuard first stored the node (DB-local; the source's own claim is on SOURCED_FROM)
  last_updated: DATETIME,   // Last update
  active: BOOLEAN,          // true when EdgeGuard creates the node; a CVE never ages
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
  cisa_vulnerability_name: STRING, // CISA-assigned vulnerability name
  known_ransomware_use: STRING,    // CISA knownRansomwareCampaignUse: "Known" / "Unknown" (KEV records)
  // FIRST EPSS (enrich_cve_epss, after every Neo4j sync and the baseline)
  epss_score: FLOAT,               // probability of exploitation in the next 30 days, 0-1
  epss_percentile: FLOAT,          // 0-1
  epss_score_date: STRING,         // date of the EPSS file, e.g. "2026-10-11T12:00:25Z"
  epss_model_version: STRING,      // e.g. "v2026.06.15"
  epss_updated_at: DATETIME,       // time of the write
  // CISA's SSVC decision points from NVD's record (removed when the record has none)
  ssvc_exploitation: STRING,       // none / poc / active
  ssvc_automatable: STRING,        // yes / no
  ssvc_technical_impact: STRING,   // partial / total
  ssvc_version: STRING,            // SSVC version, e.g. "2.0.3"
  ssvc_timestamp: STRING           // time of CISA's decision
})
// Source provenance is on the SOURCED_FROM relationship, not a node property.
// CVSS sub-nodes (CVSSv40, CVSSv31, CVSSv30, CVSSv2) linked via HAS_CVSS_* relationships.
```

#### Indicator (IOC)
```cypher
(:Indicator {
  indicator_type: STRING,   // ipv4, ipv6, domain, url, email, hash (file digests), x509-fingerprint-sha1
                            // (TLS certificate fingerprint), filename, … — the sync's TYPE_MAPPING
  value: STRING,            // The indicator value
  zone: LIST,               // Zone(s): ['finance'] — always a list, never a string
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
  confidence_score: FLOAT,  // 0.0-1.0; max(0.10, round(source_confidence * aging_factor, 2))
  first_imported_at: DATETIME, // When EdgeGuard first stored the node (DB-local; the source's own claim is on SOURCED_FROM)
  last_updated: DATETIME,   // Last database write (not read for aging or ordering)
  // Indicator aging (src/indicator_aging.py): one rule for every Indicator, whoever supplied it.
  last_reported_at: DATETIME,   // Latest report of any source: min(MISP timestamp, source last_seen); forward only
  last_reported_source: STRING, // The source of that report
  last_reported_ref: STRING,    // The MISP attribute uuid of that report
  last_reported_basis: STRING,  // source_date / misp_recorded: the kind of date of that report; forward only
  last_recorded_at: DATETIME,   // Latest MISP timestamp of a report; forward only
  source_confidence: FLOAT,     // Highest confidence a source gave (incoming values only)
  aging_basis: STRING,          // last_reported_basis, or first_imported without a report: what the age counts from (set by the rule)
  aging_tier: INTEGER,          // 0 below 90 days, 1 from 90, 2 from 180, 3 from 365 (EDGEGUARD_AGING_TIER_DAYS)
  aging_factor: FLOAT,          // 1.0 / 0.85 / 0.70 / 0.55 (EDGEGUARD_AGING_FACTORS)
  aging_since: DATETIME,        // When the current aging state began (basis + tier start, or + 730 days once retired)
  aging_evaluated_at: DATETIME, // When the aging values were last written (a write, or a job run that changed them); the rule runs at the database's time, lifted to it
  active: BOOLEAN,              // false from 730 days without a report (EDGEGUARD_AGING_RETIRE_DAYS) or by hand
  retired_at: DATETIME,         // decay: basis + 730 days; a manual decommission keeps its own
  retired_by: STRING,           // 'decay', or another value / none for a manual decommission
  misp_event_ids: LIST,     // Accumulated MISP event ids (set, deduped)
  misp_attribute_ids: LIST, // Accumulated MISP attribute UUIDs (stable cross-instance, from attr.uuid; set, deduped)
  uuid: STRING,             // Deterministic uuid5(namespace, canonical(label, natural_key))
                            // — same value on local + cloud Neo4j; equals the UUID portion of the
                            // corresponding STIX SDO id. See src/node_identity.py.
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
  threat_label: STRING,              // VirusTotal popular_threat_classification.suggested_threat_label
  // URLhaus / Feodo Tracker fields (carried in the TF_META comment)
  url_status: STRING,                // URLhaus online / offline status
  last_online: STRING,               // URLhaus and Feodo: last date the source saw it online
  // OTX report-scoped linking (names reported by the same pulse; build_relationships steps 2d and 9b)
  pulse_malware_families: LIST,      // malware families named by the OTX pulse(s) that listed the IOC, without an ATT&CK software id suffix
  pulse_malware_actor_pairs: LIST,   // "family::adversary::pulse" pairs named by the same pulse, the family without the suffix
  several_actor_pulses: LIST,        // The OTX pulses that listed the IOC and that the OTX collector judged, with the canonical threat-actor reference, to name several actors (OTX_META.sap; a judgement by name without it, OTX_META.sapn, is not stored); step 2d links no pair of them and removes the same-pulse links resting only on them
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
  name: STRING,             // Malware name, without an ATT&CK software id suffix ("Cobalt Strike - S0154" -> "cobalt strike")
  aliases: LIST,            // Other names, including a source's suffixed name ("Cobalt Strike - S0154")
  merged_from: LIST,        // ATT&CK-id twins the enrichment job merge_malware_attack_twins folded in (steps 9b / 2d resolve these names to this node)
  malware_types: LIST,      // Types (trojan, ransomware, etc.)
  family: STRING,           // Malware family
  description: STRING,      // Ranked text: MITRE ATT&CK > a curated source > any other source
  description_source: STRING, // The source of description ("mitre_attck", ...)
  tag: STRING,              // Source tag (provenance — NOT part of UNIQUE constraint)
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
  uses_techniques: LIST,    // Optional MITRE IDs from STIX malware→technique **uses** (MISP **MITRE_USES_TECHNIQUES:**)
  confidence_score: FLOAT,  // 0.0-1.0
  first_imported_at: DATETIME, // When EdgeGuard first stored the node (DB-local; the source's own claim is on SOURCED_FROM)
  last_updated: DATETIME,   // Last update
  misp_event_ids: LIST      // Accumulated MISP event ids (set, deduped)
})
```

#### ThreatActor
```cypher
(:ThreatActor {
  name: STRING,             // Actor name
  aliases: LIST,            // Known aliases
  description: STRING,      // Ranked text: MITRE ATT&CK > a curated source > any other source
  description_source: STRING, // The source of description ("mitre_attck", ...)
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
  uses_techniques: LIST,    // MITRE IDs from STIX actor **uses** technique; drives (Actor)-[:EMPLOYS_TECHNIQUE]->(Technique) edges in build_relationships.py. Property name retained as-is (STIX-side contract).
  confidence_score: FLOAT,  // 0.0-1.0
  first_imported_at: DATETIME, // When EdgeGuard first stored the node (DB-local; the source's own claim is on SOURCED_FROM)
  last_updated: DATETIME    // Last update
})
```

#### Technique (MITRE ATT&CK)
```cypher
(:Technique {
  mitre_id: STRING,         // T#### or T####.###
  name: STRING,             // Technique name
  description: STRING,      // Ranked text: MITRE ATT&CK > a curated source > any other source
  description_source: STRING, // The source of description
  platforms: LIST,          // Target platforms
  is_subtechnique: BOOLEAN, // true when mitre_id is dotted (T####.###), whatever the record says
  tactic_phases: LIST,      // Kill-chain phase shortnames (IN_TACTIC)
  attack_domain: STRING,    // enterprise / ics / mobile (default enterprise)
  detection: STRING,        // ATT&CK detection text
  deprecated: BOOLEAN,      // Set when ATT&CK deprecated the object (never cleared)
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
  confidence_score: FLOAT,  // 0.0-1.0
  first_imported_at: DATETIME, // When EdgeGuard first stored the node (DB-local; the source's own claim is on SOURCED_FROM)
  last_updated: DATETIME    // Last update
})
```

#### Tactic (MITRE ATT&CK)
```cypher
(:Tactic {
  mitre_id: STRING,         // TA####
  name: STRING,             // Tactic name
  shortname: STRING,        // Kill-chain phase name (e.g. "initial-access"), matched by Technique.tactic_phases
  attack_domain: STRING,    // enterprise / ics / mobile (default enterprise)
  description: STRING,      // Ranked text, as on Technique
  description_source: STRING,
  deprecated: BOOLEAN       // Set when ATT&CK deprecated the object
})
```

#### Campaign (built by enrichment)
```cypher
(:Campaign {
  name: STRING,             // "<actor name> Campaign"
  actor_name: STRING,       // The ThreatActor it groups
  indicator_count: INTEGER, // Active indicators at the last run
  malware_count: INTEGER,   // Member malware at the last run
  first_seen: DATETIME,     // Earliest indicator observation; never moves later
  last_seen: DATETIME,      // Latest indicator observation; never moves earlier
  zone: LIST,               // Union of the indicators' zones
  active: BOOLEAN           // false once no indicator linked to it is active
})
// build_campaign_nodes in src/enrichment_jobs.py; what a campaign rests on: src/campaign_evidence.py
```

#### Sector
```cypher
(:Sector {
  name: STRING              // Sector name: healthcare / energy / finance
})
```

#### Tool (MITRE ATT&CK)
```cypher
(:Tool {
  mitre_id: STRING,         // Tool ID (S0001)
  name: STRING,             // Tool name
  description: STRING,      // Ranked text: MITRE ATT&CK > a curated source > any other source
  description_source: STRING, // The source of description ("mitre_attck", ...)
  tag: STRING,              // Source tag
  tool_types: LIST,         // Classification labels
  uses_techniques: LIST,    // MITRE IDs from STIX uses relationships
  zone: LIST,               // Detected zones
  source: LIST,             // Canonical source ids, accumulated (deduped); relationships carry r.sources
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
  description: STRING,      // Description; the ranked text, NVD > CISA KEV > CISA ICS > any other source
  description_source: STRING, // EdgeGuard extension: the source of description
  published: STRING,        // Publication date; NVD's record sets it, any other record only fills it
  last_modified: STRING,    // Last modified date; same rule
  // NVD's record also sets cwe, ref_tags, cpe_type, result_impacts, reference_urls and
  // affected_products; any other record only fills them. A CVSS sub-node NVD has asserted keeps NVD's
  // values (a CISA ICS payload only fills missing properties) until an NVD record without that version.
  // cisa_exploit_add, cisa_action_due, cisa_required_action and cisa_vulnerability_name are set by a
  // CISA KEV record and only filled by any other (NVD's copy included), in either order of the sync.
  cpe_type: LIST,           // CPE types
  result_impacts: LIST,     // Impact results
  ref_tags: LIST,           // Reference tags
  cwe: LIST,                // CWE identifiers
  // EdgeGuard additions, set by merge_cve from the CVSS sub-nodes: cvss_score,
  // cvss_version, severity, and attack_vector (NVD's word for the attack vector of the CVSS that
  // gives the score; null without CVSS). See :Vulnerability above for their rules.
  attack_vector: STRING,    // NETWORK / ADJACENT_NETWORK / LOCAL / PHYSICAL, null without CVSS
  cvss_score: FLOAT,        // null without CVSS
  cvss_version: STRING,     // "3.1", "3.0", "2.0" or "4.0"; null without CVSS
  severity: STRING,         // rating of that score; UNKNOWN without CVSS
  // Further EdgeGuard properties written by merge_cve (the MISP → Neo4j sync path):
  status: LIST,             // NVD record status, ["active"] or ["rejected"]
  reference_urls: LIST,     // NVD reference URLs
  affected_products: LIST,  // CPE URIs (up to 10)
  known_ransomware_use: STRING, // CISA KEV knownRansomwareCampaignUse, "Known" / "Unknown"
  epss_score: FLOAT,        // and epss_percentile, epss_score_date, epss_model_version, epss_updated_at (FIRST EPSS; see Vulnerability above)
  ssvc_exploitation: STRING, // and ssvc_automatable, ssvc_technical_impact, ssvc_version, ssvc_timestamp (CISA's SSVC from NVD's record)
  cisa_exploit_add: STRING, // and the other CISA KEV fields (see Vulnerability above); zone, source and tlp as on every EdgeGuard node
  tag: STRING,              // Data provenance tag
  first_seen: DATETIME,     // First observed (merge_resilmesh_cve); the MISP sync path writes first_imported_at
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
| `EMPLOYS_TECHNIQUE` | ThreatActor / Campaign | Technique | **Attribution.** `confidence_score` + `match_type` per evidence: `mitre_explicit` (0.95, `uses_techniques`) or `otx_pulse` (0.6, `reported_techniques`); curated-package claims: see below the table; `created_at`, `updated_at`, `edgeguard_managed`, `src_uuid`, `trg_uuid` (`build_relationships.py` Q5/Q5b). |
| `IMPLEMENTS_TECHNIQUE` | Malware / Tool | Technique | **Capability.** Same properties as `EMPLOYS_TECHNIQUE`; `mitre_explicit` (0.95) via `uses_techniques`, `otx_pulse` (0.6) via `reported_techniques` (`build_relationships.py` Q6/Q6b/Q10); curated-package claims: see below the table. |
| `ATTRIBUTED_TO` | Malware | ThreatActor | `match_type='exact'` (1.0, Q2) or `match_type='otx_pulse'` (0.6, sync path and Q2d, the pulse in `source_refs[]`; only from a pulse whose actors are one actor); `created_at`/`imported_at`, `updated_at`, `edgeguard_managed`, `src_uuid`, `trg_uuid` |
| `INDICATES` | Indicator | Malware | `match_type='otx_pulse'` (0.6, same OTX pulse, sync path) **or** `match_type='malware_family'` (0.8, Q9; `sources[]` names the indicator's feeds that carry family labels); `edgeguard_managed`. No code path writes the `misp_cooccurrence` level (0.5) |
| `EXPLOITS` | Indicator | `Vulnerability` or `CVE` | `confidence_score` 1.0, `match_type='cve_tag'` |
| `EXPLOITS` | ThreatActor / Malware | `CVE` | Curated packages only: `match_type` = the package's curated label (`coreideas_curated` / `curated_other`), `confidence_score` 0.85 (both written when the claim creates the link), `tlp` = the package's TLP level |
| `USES_TECHNIQUE` | Indicator | Technique | OTX pulse `attack_ids` exact MITRE ID match (`confidence_score` 0.85) |
| `REFERS_TO` | `Vulnerability` | `CVE` (and reverse) | Created by `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor | Campaign | `build_campaign_nodes()`; `match_type='campaign_grouping'`; rests on the actor's `ATTRIBUTED_TO` and `USES_MALWARE` links to malware (`evidence_types`); a campaign whose actor has neither link left is deleted with its links |
| `PART_OF_CAMPAIGN` | Malware, Indicator | Campaign | `build_campaign_nodes()`; a malware with either link to the campaign's actor is a member, an indicator joins through `INDICATES` to a member (`evidence_types`) |
| `USES_MALWARE` | ThreatActor | Malware | `match_type='mitre_explicit'` (0.95, MITRE group → software `uses`, `build_relationships.py` Q2b); curated-package claims: see below the table |
| `USES_TOOL` | ThreatActor | Tool | As `USES_MALWARE` (Q2c; a curated claim names the tool by its ATT&CK id) |
| `SUBTECHNIQUE_OF` | Technique | Technique | `match_type='mitre_explicit'`, 1.0 (Q1b, from the dotted ATT&CK id) |
| `IN_TACTIC` | Technique | Tactic | `match_type='kill_chain_phase'`, 1.0 (Q1; both ends in the same `attack_domain`) |
| `TARGETS` | Indicator, ThreatActor, Malware | Sector | `match_type='zone_classification'`, 0.5 (sync and Q7a / Q7c / Q7d; never to `global`); `r.sources` names only the feeds whose `SOURCED_FROM.zones` give the sector |
| `AFFECTS` | Vulnerability / CVE | Sector | `match_type='advisory_sector'`, 0.9, where CISA's ICS advisory states the sector (the product is deployed in it), else `zone_classification`, 0.5 (sync and Q7b, one label table, `src/sector_evidence.py`; never to `global`); `r.sources` names only the feeds that gave the sector |
| `SOURCED_FROM` | any EdgeGuard node | Source | Per-source provenance: `raw_data`, `imported_at`, `updated_at`, `confidence`, `source`, `source_reported_first_at`, `source_reported_last_at`, `src_uuid`, `trg_uuid`, `edgeguard_managed`, that source's `misp_event_ids[]` and `source_refs[]`, `zones`, `stated_zones` and `stated_refs` (what a link to a `Sector` reads), and on an Indicator's edge `last_recorded_at`, `last_reported_at`, `last_reported_source` and `last_reported_ref` (indicator aging) — see `docs/KNOWLEDGE_GRAPH.md` "SOURCED_FROM edge schema" |
| `INVOLVES` | Alert | Indicator | `created_at`, `updated_at`, `source` (`'resilmesh'`) (`neo4j_client` alert path) |

Every relationship in this table except `SOURCED_FROM` and `INVOLVES` also carries `sources[]`, `source_refs[]` and `misp_event_ids[]` (who asserts it, the sources' record ids, the MISP events; see `docs/KNOWLEDGE_GRAPH.md` "Relationship provenance"). Relationships carry no `source_id`, `source_ids` or `report_ids` property; `Source.source_id` is the key of the `Source` node.

Curated packages also add claims to `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`, `USES_MALWARE` and `USES_TOOL`. A claim sets `match_type` (the package's curated label) and `confidence_score` 0.85 only on a link it creates; on a link that already exists it adds its provenance and leaves the label and confidence as they are. Every link a claim touches carries the package's TLP level in `tlp` (see `docs/KNOWLEDGE_GRAPH.md`, "Curated packages").

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
| `HAS_CVSS_v2` / `HAS_CVSS_v30` / `HAS_CVSS_v31` / `HAS_CVSS_v40` | CVE, and CVSSv2 / CVSSv30 / CVSSv31 / CVSSv40 | CVSSv2 / CVSSv30 / CVSSv31 / CVSSv40, and CVE (both directions, as in the ResilMesh model) | src_uuid, trg_uuid, edgeguard_managed, sources, misp_event_ids |

### Bridge Relationships (EdgeGuard ↔ ResilMesh)

| Relationship | From | To | Properties |
|--------------|------|-----|------------|
| `RESOLVES_TO` | Indicator | IP | created_at, source, confidence_score |
| `MAPS_TO` | Vulnerability | CVE | created_at, source, confidence_score |
| `TARGETS` | Malware | Host | created_at, source, confidence_score |

These three bridges are planned; no pipeline path writes them today. The Vulnerability ↔ CVE link EdgeGuard writes is `REFERS_TO`, and the planned Indicator → IP bridge is named `INDICATOR_RESOLVES_TO` (see [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 3.2).

---

## Constraints

### UNIQUE Constraints (19 — see `Neo4jClient.create_constraints` in `src/neo4j_client.py` for the canonical list)

> **Note:** no constraint includes `tag`: provenance lives on `SOURCED_FROM`
> edges, so an entity merges across sources on its natural key alone. The
> constraints below mirror the live Cypher in `Neo4jClient.create_constraints`
> (`src/neo4j_client.py`). **Single source of truth** is the source file;
> this block is a snapshot and may drift between releases.

```cypher
// EdgeGuard constraints — single-key (no tag); entities merge across sources
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

// ResilMesh topology — only the keys that are unique in CRUSOE's own model as well.
// Device, NetworkService, SoftwareVersion, Application, Role and User are deliberately NOT
// constrained: their keys recur legitimately in the partner's data (the same software version
// per product, the same port/protocol per host), so DDL on those labels belongs to ResilMesh.
CREATE CONSTRAINT ip_key FOR (n:IP) REQUIRE (n.address) IS UNIQUE;
CREATE CONSTRAINT host_key FOR (n:Host) REQUIRE (n.hostname) IS UNIQUE;
CREATE CONSTRAINT subnet_key FOR (n:Subnet) REQUIRE (n.range) IS UNIQUE;
// Alert: alert_id is the idempotency key of the alerts EdgeGuard's own processor writes
CREATE CONSTRAINT alert_key FOR (n:Alert) REQUIRE (n.alert_id) IS UNIQUE;
```

---

## Indexes

### Performance Indexes (snapshot — see `Neo4jClient.create_indexes` in `src/neo4j_client.py` for the canonical list)

```cypher
// EdgeGuard indexes (24 shown — query-performance subset; the per-node
// uuid indexes and delta-sync timestamp indexes are omitted here. The
// canonical list is Neo4jClient.create_indexes: 46 EdgeGuard statements.)
CREATE INDEX source_id_idx FOR (s:Source) ON (s.source_id);
CREATE INDEX vulnerability_cve FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX indicator_value FOR (i:Indicator) ON (i.value);
CREATE INDEX indicator_type FOR (i:Indicator) ON (i.indicator_type);
CREATE INDEX indicator_source FOR (i:Indicator) ON (i.source);
CREATE INDEX indicator_zone FOR (i:Indicator) ON (i.zone);
CREATE INDEX malware_name FOR (m:Malware) ON (m.name);
CREATE INDEX actor_name FOR (a:ThreatActor) ON (a.name);
CREATE INDEX technique_mitre FOR (t:Technique) ON (t.mitre_id);
CREATE INDEX indicator_active FOR (i:Indicator) ON (i.active);
CREATE INDEX vulnerability_active FOR (v:Vulnerability) ON (v.active);
// No index on a scalar MISP id: readers match against misp_event_ids[] /
// misp_attribute_ids[] via list-membership predicates (`eid IN n.misp_event_ids`).
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
// GraphRAG retrieval shapes: CVSS range scans
// (cvss_score >= $min) + KEV filters (cisa_exploit_add IS NOT NULL / >= $since)
CREATE INDEX cve_cvss_score FOR (c:CVE) ON (c.cvss_score);
CREATE INDEX cve_cisa_exploit_add FOR (c:CVE) ON (c.cisa_exploit_add);

// ResilMesh topology indexes are ResilMesh's own DDL. On those labels EdgeGuard creates only the
// uuid indexes (IP, Host, Device, Subnet, NetworkService, SoftwareVersion, Application, Role, User)
// — see Neo4jClient.create_indexes.
```

---

## API Endpoints

### FastAPI Query Engine

All data endpoints require the `X-API-Key` header (`_verify_api_key`,
constant-time compare) and are rate-limited (shared read limit;
`POST /admin/query` has its own stricter admin limit and additionally
requires `X-Admin-Token`). `GET /health` is public. The interactive
documentation routes (`/docs`, `/redoc`, `/openapi.json`) are served
without a key only when `EDGEGUARD_ENV` names a non-production
environment; in production they require the key. The routes are those of
`src/query_api.py`; alert *enrichment* is **not** a REST
endpoint; it is NATS-based via `src/alert_processor.py` (see *NATS
Topics* below).

| Method | Path | Description | Parameters |
|--------|------|-------------|------------|
| GET | `/health` | Health check — **HTTP 200** when Neo4j is healthy, **HTTP 503** while degraded (no client, a reconnect in progress, or a failed `Neo4jClient.health_check()`: ping + APOC); the JSON body in both cases holds `status` (`ok`/`degraded`), `neo4j_connected` and `version`. | - |
| POST | `/query` | Natural-language threat query | `query`, `zone`, `limit`, `return_cypher` (body) |
| POST | `/search/indicator` | Search a single indicator. Input is canonicalized via `ioc_normalize.canonicalize_lookup` (refang, NFC, case-fold, type resolution) before querying — see *Type Mapping* below. `related` lists the related nodes' properties in a stable order — Malware, ThreatActor and CVE / Vulnerability before Technique, Campaign, Sector and other labels, at most 10 per kind — and `relationships` (same order) the relationship type, direction (`outgoing` = indicator → node) and labels of each. When one value is stored under several types, the indicator of the resolved type answers (the `indicator_type` given, mapped to the graph type — `md5` → `hash` — or the type inferred from the value), otherwise the lowest type; `related` and `relationships` are that indicator's alone. | `value`, `indicator_type`, `zone` (body) |
| GET | `/zone/{zone}` | Threats for a zone/sector, newest first by one clock for every label: `coalesce(last_reported_at, first_imported_at, created_at)`, an indicator's latest report, otherwise when the node entered the graph (a campaign's `created_at`); nodes without a time last, ties by `uuid`. `last_updated`, which every sync and campaign rebuild moves, is not read | `zone` (path), `limit`, `severity` |
| GET | `/indicators` | List indicators with filters; `indicator_type` `md5` / `sha1` / `sha256` / `sha512` selects the stored `hash` indicators whose value is a hexadecimal string of that digest's length (32 / 40 / 64 / 128), `hash` every file digest | `indicator_type`, `zone`, `source`, `limit`, `offset` |
| GET | `/vulnerabilities` | List CVEs | `severity`, `zone`, `limit` |
| GET | `/graph/explore` | Cytoscape.js-formatted graph data for the interactive Graph Explorer (4 views; the default `attacks` view is `(Indicator)-[:INDICATES]->(Malware)`, edges in graph direction — see [GRAPH_EXPLORER.md](GRAPH_EXPLORER.md)) | `view`, `zone`, `limit` |
| GET | `/stix/types` | Discovery — list supported STIX export object types; each `returns` names the graph relationships the export walks at `depth=2`, and `relationship_mappings` lists the STIX relationship each graph relationship becomes, from the exporter's own table | - |
| GET | `/stix/export/{object_type}/{identifier}` | STIX 2.1 bundle centred on a threat-intel object; CVE / technique / indicator identifiers are normalized before lookup; actor lookup is case-insensitive and alias-aware. Every related-node collection is bounded by `limit` (default 100, maximum 500, `422` outside `[1, 500]`; deterministic `ORDER BY` before truncation). Bundles carry the EdgeGuard producer `identity` (`created_by_ref`), the `extension-definition` declaring the `x_edgeguard_*` top-level properties, and the STIX 2.1 TLP `marking-definition` objects referenced by `object_marking_refs` (from `n.tlp`); the bundle parses under strict `stix2.parse`. Every graph relationship with a STIX form is exported, curated-package claims included, and each SRO carries its provenance (`confidence`, `external_references` from `source_refs`, `x_edgeguard_match_type`, `x_edgeguard_sources`, `x_edgeguard_source_refs`, `x_edgeguard_misp_event_ids`). Bundles declare extension definition 1.7.0, which declares, besides the relationship provenance: NVD's record status `x_edgeguard_status` on `vulnerability`; the explainability properties `x_edgeguard_cited_ids` (SROs) and `x_edgeguard_merged_from` (`intrusion-set`); FIRST EPSS and CISA's SSVC on `vulnerability`; `x_edgeguard_evidence_types` on the SROs of campaign links; `x_edgeguard_description_source` on SDOs with a description; and the aging of an indicator (`x_edgeguard_last_reported_at`, `x_edgeguard_last_reported_source`, `x_edgeguard_last_reported_ref`, `x_edgeguard_source_confidence`, `x_edgeguard_aging_basis`, `x_edgeguard_aging_tier`, `x_edgeguard_active`, `x_edgeguard_retired_by`; an indicator's `modified` is the latest of `created`, `last_recorded_at` and `aging_since`) — see [RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md) | `object_type`, `identifier` (path), `depth`, `limit` |
| GET | `/actors/{name}/summary` | SOC-analyst actor summary: profile + attributed malware (`malware`, up to 10), the malware the actor uses (`malware_used`, `USES_MALWARE`, up to 10, sorted; listed because a campaign rests on either link), employed techniques (up to 15) and the campaigns the actor runs (up to 5), each with its total count. Alias-aware, case-insensitive; deterministic canonical-name-over-alias resolution. | `name` (path) |
| GET | `/export/wazuh/cdb` | Sector IOC/CVE intelligence as a **Wazuh CDB list** (text/plain `key:value` lines; active entries only; url/ipv6 keys skipped — CDB keys cannot contain `:`). At most 50,000 entries, newest first (entries without the time last), ties by key, so the cap keeps the most recent entries: indicators by their latest report (`coalesce(last_reported_at, first_imported_at)`), CVEs by `last_updated`; `X-EdgeGuard-Truncated: true` (and a log warning) says the list was cut. `X-EdgeGuard-Entries` / `X-EdgeGuard-Skipped` count the lines written and skipped. The `indicator_type` filter follows `/indicators` (md5 / sha1 / sha256 / sha512 → `hash` of that length). | `list` (`indicators`\|`cves`), `zone`, `indicator_type`, `min_confidence` |
| POST | `/admin/query` | Raw read-only Cypher (admin-gated: `X-Admin-Token` + admin rate limit; write keywords rejected, read-only session) | `cypher`, `parameters` (body; at most 20 parameters) |

**GraphQL service (default port 4001):** `GET /health` returns **HTTP 200** when Neo4j `health_check()` passes, else **503** — see [README.md](../README.md) § *HTTP APIs*.

### Example Queries

#### Search Indicator
```bash
# Defanged/mixed-case paste is fine — the value is canonicalized
# (refang + NFC + case-fold) to the graph's merge key before lookup.
curl -X POST http://localhost:8000/search/indicator \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $EDGEGUARD_API_KEY" \
  -d '{
    "value": "hxxp://evil[.]com/payload",
    "indicator_type": "url"
  }'
```

#### Natural Language Query
```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $EDGEGUARD_API_KEY" \
  -d '{
    "query": "Find malware targeting energy sector",
    "zone": "energy",
    "limit": 10
  }'
```

#### Get Zone Threats
```bash
curl -H "X-API-Key: $EDGEGUARD_API_KEY" \
  "http://localhost:8000/zone/healthcare?limit=20"
```

> Alert enrichment has no REST endpoint — ResilMesh alerts arrive on the
> NATS subjects below and `src/alert_processor.py` enriches them against the graph.
> **Publishing the enriched response back is not wired:** the handler
> returns the response to its caller and the only `publish` in the code is the
> `NATSClient.publish` method itself. Subject, response schema and delivery guarantees
> are pending agreement with ResilMesh — see
> [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) § 8.6.

---

## NATS Topics

### Subscribe (EdgeGuard ← ResilMesh)

| Topic | Description | Status |
|-------|-------------|------------------|
| `resilmesh.alerts.zone.*` (`healthcare`, `energy`, `finance`, `global`) | Zone alerts → `alert_processor.handle_resilmesh_alert` | **Implemented** as a wildcard subscription. No deployable consumer service yet (no compose service, DAG task or CLI command); `demo/alert_enrichment_demo.py` runs the enrichment read-only against the configured Neo4j, without NATS ([DEMO.md](DEMO.md)). |
| `resilmesh.threats.zone.{zone}` | Zone-specific threat intel | Planned — nothing subscribes or publishes |
| `resilmesh.cve.kev` | Known Exploited Vulnerabilities | Planned — nothing subscribes or publishes |

### Publish (EdgeGuard → ResilMesh)

| Topic | Description | Status |
|-------|-------------|------------------|
| `resilmesh.enriched.alerts` | Enriched alert responses | Planned — the response is built but not published (see the note above) |
| `resilmesh.threats.cross_zone` | Cross-zone threat alerts | Planned — no code path |

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

The response is the `EnrichedAlert` dataclass of `src/alert_processor.py` serialised with
`to_dict()`. Publishing it back to NATS is not implemented yet (the processor returns it to its
caller). The schema, with placeholders in angle brackets (the list entries are objects,
as the code builds them):

```json
{
  "alert_id": "wazuh-001",
  "enriched": true,
  "edgeguard_version": "<CalVer from pyproject.toml>",
  "latency_ms": "<milliseconds>",
  "query_metadata": {
    "indicator_found": "<true | false>",
    "malware_found": "<true | false>",
    "actor_found": "<true | false>",
    "techniques_found": "<count>",
    "cves_found": "<count>",
    "assets_found": 0,
    "users_found": 0
  },
  "enrichment": {
    "indicator": "<canonical indicator value>",
    "indicator_type": "<graph type: ipv4, ipv6, domain, url, hash, ...>",
    "known_malware": [{"name": "<malware>", "family": "<family or null>", "malware_types": ["<type>"], "description": "<text or null>"}],
    "threat_actors": [{"name": "<actor>", "aliases": ["<alias>"], "description": "<text or null>"}],
    "techniques": [{"mitre_id": "<T####>", "name": "<technique>", "description": "<text or null>"}],
    "cves": [{"cve_id": "<CVE id>", "cvss_score": "<score or null>", "severity": "<severity or null>"}],
    "assets": [],
    "users": [],
    "confidence": "<the indicator's confidence_score>",
    "first_seen": "<earliest first seen a source reports, else the first import>",
    "last_updated": "<latest last seen a source reports, else the last update>",
    "sectors_affected": ["<zone>"],
    "cross_zone_detected": "<true when more than one zone>",
    "recommendations": ["<generated from the fields above>"]
  },
  "original_alert": { "...": "copy of the incoming alert" }
}
```

What the enrichment reads: `(Indicator)-[:INDICATES]->(Malware)`, `(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`,
`(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)` and `(Indicator)-[:EXPLOITS]->` a `CVE` or
`Vulnerability` node. `cves` has one entry per CVE id, its score and
severity taken as a pair from one node: the `CVE` node's (a null score with severity `UNKNOWN` when
the CVE has no CVSS), or the `Vulnerability` node's when no `CVE` node of that id states them. A
CVE the alert names is listed with `"source": "alert"`, a malware the alert names with the
description `From alert (not in graph)`. `assets` and `users` stay empty: no code path writes
`(Alert)-[:TARGETS]->(Asset)` or `(Alert)-[:INVOLVES_USER]->(User)`. A failed enrichment query is
reported in `query_metadata.error`; `process_alert` keeps `enriched: true` then, while the read-only
`enrich_alert_read_only` of the demo answers `enriched: false` ([DEMO.md](DEMO.md)).

---

## Performance targets

The values below are design targets. None of them is measured in production today: the API
exposes no latency histogram, the alert enrichment path has no deployed consumer, and no load
test has been run against the edge deployment. They
are the acceptance thresholds for a future measurement, not guarantees.

| Metric | Target | Measurement (planned) |
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

| Input type (ResilMesh alert or MISP attribute) | EdgeGuard Type | Detection |
|----------------|----------------|-----------|
| `ip` | `ipv4` or `ipv6` | The address, parsed with Python's `ipaddress` |
| `ip-src`, `ip-dst` (MISP) | `ipv4` or `ipv6` | The address decides (`ioc_normalize.ip_address_type`; CIDR blocks and `address\|port` values included), because MISP has one type for both families; a value that is not an address stays `ipv4` |
| `ipv4` | `ipv4` | Direct mapping |
| `ipv6` | `ipv6` | Direct mapping |
| `domain`, `hostname` | `domain` | Direct mapping |
| `file_hash`, `md5`, `sha1`, `sha256`, `sha512` | `hash` | Direct mapping: one type for every file digest |
| `x509-fingerprint-sha1` (MISP) | `x509-fingerprint-sha1` | Direct mapping: the SHA-1 fingerprint of a TLS certificate (SSL Blacklist), not a file hash |
| `url` | `url` | Direct mapping |
| `email`, `email-src`, `email-dst` | `email` | Direct mapping |

**Read-side lookup canonicalization:** the table above
describes the *write* side. Every read entrypoint that
resolves analyst/sensor input against the graph — REST
`POST /search/indicator`, the STIX export
(`/stix/export/{object_type}/{identifier}`), and NATS alert enrichment —
first passes the input through `src/ioc_normalize.py::canonicalize_lookup`:
defang reversal (`hxxp://` → `http://`, `1.2.3[.]4` → `1.2.3.4`), Unicode
NFC, case-folding to the write-side merge key, and full write-side
`TYPE_MAPPING` parity (e.g. `hostname` → `domain`, `btc` → `bitcoin`, MISP
`text` → `unknown`; blank/`unknown` types are shape-inferred). This
guarantees a lookup keys the same `(indicator_type, value)` node the MISP
sync MERGEd; a parity test pins the read- and write-side vocabularies
together so they cannot drift.

**Indicator-type filters:** the `indicator_type` filters of
`GET /indicators`, `GET /export/wazuh/cdb` and the GraphQL `indicators`
query accept `md5` / `sha1` / `sha256` / `sha512` and select the `hash`
nodes whose value is a hexadecimal string of that digest's length (32 /
40 / 64 / 128; `ioc_normalize.indicator_type_filter`), because the sync
stores every file digest as `hash`. `hash` selects every file digest; any
other type is compared as given.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | - | Neo4j password |
| `NATS_SERVERS` | - | Documented NATS server URLs. No code path reads this variable today: `NATSClient` receives its server list from its caller and no consumer service is deployed (see *NATS Topics*). |
| `MISP_URL` | `https://localhost:8443` | MISP instance URL |
| `MISP_API_KEY` | - | MISP API key |
| `EDGEGUARD_MISP_HTTP_HOST` | (unset) | Optional HTTP `Host` when URL hostname ≠ Apache `ServerName` (e.g. Docker DNS `misp_misp_1` vs vhost `misp-edgeguard`). See [MISP_SOURCES.md](MISP_SOURCES.md). |
| `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` | `500` | MISP→Neo4j (`run_misp_to_neo4j`): max **parsed items** per **Python** merge chunk (RAM). **`0`** or **`all`** = single pass (OOM risk). **Not** the MISP event search page size — see [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md). |
| `EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS` | `true` | **`MISPWriter`**: before push, prefetch existing **`(type, value)`** on the **target** MISP event and skip duplicates. |
| `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` | `3` | **OTX** scheduled runs: initial **`modified_since`** lookback when no incremental cursor. |
| `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC` | `300` | **OTX**: subtracted from the stored cursor when querying `modified_since` (clock skew / API timing). |
| `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` | `25` | **OTX**: max API pages per scheduled run. |
| `EDGEGUARD_MITRE_CONDITIONAL_GET` | `true` | **MITRE** scheduled runs: **`If-None-Match`** / **ETag**; **304** skips download. Baseline still fetches full bundle. |
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Pause (seconds) between each batch of 500 attributes pushed to MISP, and after every 50 attribute edits (NVD incremental updates, CISA KEV in-place edits, re-reported-indicator refreshes). Prevents memory exhaustion on large events. |
| `EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC` | `2.0` | Pause (seconds) between fetching consecutive MISP events during sync. |
| `EDGEGUARD_MAX_EVENT_ATTRIBUTES` | `50000` | Events exceeding this attribute count are deferred to end of sync (small events first). `0` = disable. |
| `EDGEGUARD_MISP_PAGE_SIZE` | `500` | MISP `/events/index` page size used by the **primary** index path in `run_misp_to_neo4j._fetch_edgeguard_events_via_requests_index`. |
| `EDGEGUARD_MISP_MAX_PAGES` | `100` | MISP `/events/index` page cap on the primary index path. A listing that reaches the cap with a full last page fails the sync run (events beyond the cap were not listed; the DAG keeps its cursor), also when no EdgeGuard event was listed; raise it when the index for the window can exceed `EDGEGUARD_MISP_MAX_PAGES` × `EDGEGUARD_MISP_PAGE_SIZE` rows (50,000 by default). A page that fails after the first raises `_MispFallbackHardError`. |
| `EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` | `172800` (48h) | Cross-host stale-lock TTL for the `baseline_lock` sentinel; 48h gives a 16h buffer above the baseline's 32h `dagrun_timeout`. See `src/baseline_lock.py`. |
| `EDGEGUARD_API_KEY` | - | Shared secret for the REST and GraphQL data endpoints (`X-API-Key`); required when `EDGEGUARD_ENV` is production (unset or empty counts as production). |
| `EDGEGUARD_ENV` | - (production) | Environment name; `dev`, `development`, `local`, `staging`, `test` are non-production. Forwarded to every container by `docker-compose.yml`. |
| `EDGEGUARD_API_HOST` / `EDGEGUARD_API_PORT` / `EDGEGUARD_API_WORKERS` | `127.0.0.1` / `8000` / `1` | REST bind address, port and worker count (compose: `0.0.0.0`, 8000 published on loopback, 2 workers). |
| `EDGEGUARD_GRAPHQL_HOST` / `EDGEGUARD_GRAPHQL_PORT` / `EDGEGUARD_GRAPHQL_WORKERS` / `EDGEGUARD_GRAPHQL_PLAYGROUND` / `EDGEGUARD_GRAPHQL_MAX_DEPTH` | `127.0.0.1` / `4001` / `1` / `false` / code default | GraphQL bind, port, workers, interactive explorer, query depth cap. |
| `EDGEGUARD_CORS_ORIGINS` | `http://localhost,http://localhost:3000` | CORS allowlist of both APIs (comma-separated). |
| `EDGEGUARD_MAX_BODY_BYTES` | `1048576` | Request body cap of both APIs. |
| `EDGEGUARD_ALLOW_UNAUTH` | - | Last-resort opt-in to start an API without a key on a non-loopback bind (documented in `.env.example`). |
| `EDGEGUARD_ENABLE_ADMIN_QUERY` / `EDGEGUARD_ADMIN_TOKEN` | `false` / - | Raw Cypher route `POST /admin/query` and its token. |
| `LOG_LEVEL` | `INFO` | Logging level |

**Internal constants (no env override today; tune by editing `src/run_misp_to_neo4j.py` or `src/collectors/misp_writer.py`):**

| Constant | Value | Where | Why |
|----------|-------|-------|-----|
| `_FALLBACK_PAGE_SIZE` | `500` | `fetch_edgeguard_events` | PyMISP / requests-restSearch fallback per-page batch; the fallback asks for event headers only (`metadata`) with `eventinfo` `%EdgeGuard%` and keeps EdgeGuard rows client-side |
| `_FALLBACK_MAX_PAGES` | `200` | `fetch_edgeguard_events` | 100K-event safety cap on fallback. Hitting it raises `_MispFallbackHardError`. |
| `EVENT_LOOKUP_PAGE_SIZE` | `500` | `MISPWriter._restsearch_events_for_name` | Event headers per page of the writer's event lookup (`eventinfo` exact name + `metadata`) |
| `EVENT_LOOKUP_MAX_PAGES` | `40` | `MISPWriter._restsearch_events_for_name` | Pages the lookup reads on a MISP older than 2.4.177, which ignores `eventinfo`; reaching the cap fails the lookup and creates no event |

**Collection vs sync limits (baseline caps, incremental caps, MISP prefetch, OTX/MITRE incremental env, MISP restSearch fallback `500` per page, Neo4j chunk `500`, `MISPCollector` internals):** [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

---

*Technical Specification Version: 2.0*
*For ResilMesh Engineers*

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — The `INDICATES` row no longer names the removed co-occurrence calibration job.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Rewritten as a guide to current behaviour: change notes moved to this history, the handling of data from earlier versions to the appendix.
- 2026-10-17 — Corrected against the code: a CVE's `confidence_score` is 0.5 from the MISP sync and does not mark KEV entries; NVD and CISA KEV ownership of CVE properties; Technique fields and the Tactic, Campaign and Sector schemas; the `SOURCED_FROM` properties; `HAS_CVSS_v*` in both directions; 19 UNIQUE constraints; the uuid indexes EdgeGuard creates on ResilMesh labels instead of ResilMesh indexes no code creates; `EDGEGUARD_MISP_MAX_PAGES` (a listing that reaches the cap fails the sync run), `EDGEGUARD_MISP_BATCH_THROTTLE_SEC`, `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC` and the `MISP_URL` default.
- 2026-10-16 — Links to a `Sector` name only the feeds that gave the sector; `AFFECTS` is `advisory_sector` (0.9) where CISA's ICS advisory states the sector.
- 2026-10-16 — One indicator aging rule for every Indicator: the report and aging properties on `Indicator` (`last_reported_*`, `last_recorded_at`, `source_confidence`, `aging_*`, `active`, `retired_*`), evaluated at the database's time and never moved backwards; `CVE.active` set on create only; `/zone/{zone}` and the Wazuh CDB list ordered by the latest report (they read `last_updated`); STIX extension definition 1.7.0.
- 2026-10-16 — Descriptions of CVE, Vulnerability, Malware, ThreatActor, Tool and Technique chosen by a fixed source ranking and named in `description_source`; STIX extension definition 1.6.0.
- 2026-10-16 — Campaigns rest on `ATTRIBUTED_TO` or `USES_MALWARE` (`evidence_types`; a campaign without evidence is deleted); the actor summary returns `malware_used`; STIX extension definition 1.5.0.
- 2026-10-16 — Alert enrichment reads `(Indicator)-[:EXPLOITS]->` a `CVE` or `Vulnerability` node (it read `INDICATES` to a `Vulnerability`, which nothing writes, and listed only a CVE the alert named); the Output sample shows the objects the code builds (it showed plain strings); the read-only demo replaced the removed mock.
- 2026-10-16 — `Indicator.several_actor_pulses`; the writer's event lookup constants; the restSearch fallback asks for EdgeGuard event headers only, 500 per page (the doc named a single 1000-event search).
- 2026-10-15 — Malware named without the ATT&CK software id suffix, with `aliases` and `merged_from` (twin merge); MITRE's record sets the Malware, ThreatActor and Tool descriptions, NVD's record the CVE description, `published` and `last_modified`; an OTX pulse reference is never a CVE description.
- 2026-10-15 — Same-pulse `ATTRIBUTED_TO` only from a pulse whose actors are one actor; `pulse_malware_actor_pairs` carry the pulse (`family::adversary::pulse`).
- 2026-10-15 — API table matched to the code: REST `/health` answers 503 while degraded; the actor summary returns campaigns (it said indicators); the `/admin/query` body is `cypher` with `parameters`; `/search/indicator` answers with the resolved type's indicator and only its neighbours, in a stable order with `relationships`; md5 / sha1 / sha256 / sha512 filters select `hash` indicators by length (they never matched); the Wazuh CDB export keeps the newest entries under its cap and reports a cut list (it kept the alphabetically first keys); `/stix/types` lists `relationship_mappings`; the Graph Explorer's default view is `(Indicator)-[:INDICATES]->(Malware)`.
- 2026-10-15 — STIX export of every graph relationship with a STIX form, each SRO with its provenance (extension definition 1.1.0), then NVD's record status (1.2.0), `x_edgeguard_cited_ids` / `x_edgeguard_merged_from` (1.3.0), and FIRST EPSS with CISA's SSVC (1.4.0).
- 2026-10-15 — CVE properties `epss_*` and `ssvc_*`; `attack_vector` in NVD's words from the CVSS that gives the score (it was the vector letter, `UNKNOWN` or a KEV/OTX default); MISP `ip-src` / `ip-dst` resolve to `ipv4` or `ipv6` (IPv6 addresses were stored as `ipv4`); SSL Blacklist fingerprints typed `x509-fingerprint-sha1` (they were file hashes); relationship table completed; the three bridge relationships marked planned.
- 2026-10-14 — CVE score from the first CVSS (v3.1 → v3.0 → v2 → v4.0) with `cvss_version`, a null score and severity `UNKNOWN` without CVSS; `known_ransomware_use`.
- 2026-10-14 — Every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]`, and `source_id`, `source_ids` and `report_ids` were dropped from relationships; campaign membership renamed from `PART_OF` to `PART_OF_CAMPAIGN`; curated packages add claims to existing links.
- 2026-10-13 — VirusTotal `threat_label` and the URLhaus / Feodo Tracker fields `url_status` / `last_online` reach the graph.
- 2026-10-11 — Shared-database contract: EdgeGuard creates no UNIQUE constraint on the ResilMesh labels `Device`, `NetworkService`, `SoftwareVersion`, `Application`, `Role` and `User` (earlier builds did).
- 2026-10-11 — The interactive API documentation routes require the key in production.
- 2026-10-10 — Report-scoped linking: same-pulse `INDICATES` / `ATTRIBUTED_TO` (`otx_pulse`) replaced whole-event co-occurrence, so the `misp_cooccurrence` level is no longer written; OTX pulse techniques as `reported_techniques`; `SUBTECHNIQUE_OF`, `USES_MALWARE` / `USES_TOOL` and `TARGETS` from actors and malware added.
- 2026-06-12 — `GET /export/wazuh/cdb` added, the first Wazuh integration deliverable.
- 2026-06-11 — API Endpoints table rewritten against the routes of `src/query_api.py` (no `GET /stats` or `POST /enrich`; alert enrichment is NATS-based); the `cve_cvss_score` and `cve_cisa_exploit_add` indexes for GraphRAG retrieval; read-side lookup canonicalization (`ioc_normalize.canonicalize_lookup`).
- 2026-04-26 — Constraints corrected: no constraint includes `tag` (provenance lives on `SOURCED_FROM` edges); env settings and edge names corrected.
- 2026-04-24 — `EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` default raised from 24 h to 48 h; the restSearch fallback pages 500 events per page and raises `_MispFallbackHardError` at its page cap.
- 2026-04-17 — The `indicator_original_source` / `vulnerability_original_source` indexes removed (the property had no readers); the indexes on scalar MISP ids removed in favour of `misp_event_ids[]` / `misp_attribute_ids[]`.
- 2026-04-16 — Deterministic node `uuid` (`src/node_identity.py`).
- 2026-04-15 — The generic `USES` technique edge split into `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE`.
- 2026-03-28 — First version.
