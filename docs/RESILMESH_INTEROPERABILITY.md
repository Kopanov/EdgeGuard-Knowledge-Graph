# EdgeGuard ↔ ResilMesh Interoperability Guide

**Last updated: 2026-04-17**
**Document type:** Integration contract — shared reference between EdgeGuard (IICT-BAS + Ratio1) and ResilMesh  
**Purpose:** Defines exactly what EdgeGuard produces, what it relies on ResilMesh to provide, and what neither system covers today.

---

## 1. Role Division

EdgeGuard and ResilMesh are **complementary, not overlapping**. Each system owns a distinct layer:

| Layer | Owner | What it contains |
|-------|-------|-----------------|
| **Network Topology** | ResilMesh | Hosts, Devices, IPs, Subnets, Network Services, Connections |
| **Identity & Access** | ResilMesh | Users, Roles, Organizational Units |
| **Mission Model** | ResilMesh | Missions, Components, MissionDependencies, Applications |
| **Incident Management** | ResilMesh | SecurityEvents, Incidents, DetectionSystems, Responses |
| **Threat Intelligence** | EdgeGuard | CVEs, Vulnerabilities, Indicators, Malware, ThreatActors, Techniques, Tactics |
| **Sector Enrichment** | EdgeGuard | Zone classification, TLP tagging, sector-specific threat feeds |
| **Graph Enrichment** | EdgeGuard | Relationships linking threat intel to ResilMesh topology nodes |

The integration point is the **shared Neo4j database**: ResilMesh writes the infrastructure graph; EdgeGuard writes the threat intelligence graph on top of it and creates bridge relationships between the two.

---

## 2. Data Flow

```
External Threat Sources (OTX, NVD, CISA, MITRE, VirusTotal, Feodo, URLhaus...)
        │
        ▼
EdgeGuard Collectors  →  MISP (single source of truth)  →  Neo4j (graph)
                          (Airflow sync: MISP attributes → parse → merge;
                           not a STIX bundle on that path — see ARCHITECTURE.md)
                                                               │
                          ResilMesh (Wazuh, Suricata, Nmap)  ─┤
                                (writes topology layer)        │
                                                               ▼
                                                    Shared Neo4j Database
                                                  ┌─────────────────────┐
                                                  │  ResilMesh Layer     │
                                                  │  Host, IP, Device..  │
                                                  ├─────────────────────┤
                                                  │  Bridge Rels         │
                                                  │  REFERS_TO, MAPS_TO  │
                                                  ├─────────────────────┤
                                                  │  EdgeGuard Layer     │
                                                  │  CVE, Indicator,     │
                                                  │  Malware, Actor...   │
                                                  └─────────────────────┘
                                                          │
                                                          ▼
                                             Alert Enrichment via NATS
                                          (ResilMesh alert + EdgeGuard context)
```

---

## 3. What EdgeGuard Provides to ResilMesh

### 3.1 Node Types Produced by EdgeGuard

All EdgeGuard nodes are **ResilMesh-schema compatible** where they overlap.

#### Threat Intelligence Layer (EdgeGuard-native)

| Node Label | Key Properties | Source |
|------------|---------------|--------|
| `Indicator` | `value`, `indicator_type`, `zone[]`, `confidence_score`, `first_seen`, `last_updated`, `misp_event_ids[]`, `misp_attribute_ids[]`, **`uuid`** (deterministic, equal to the UUID portion of the STIX SDO id), … | OTX, ThreatFox, URLhaus, AbuseIPDB, VirusTotal, CyberCure, Feodo, SSLBlacklist |
| `Vulnerability` | `cve_id`, `severity`, `cvss_score`, `attack_vector`, `zone[]`, `published`, `last_modified` | NVD, CISA KEV, OTX |
| `CVE` | `cve_id`, `description`, `published`, `last_modified`, `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]` | NVD |
| `CVSSv31` | `vector_string`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score` | NVD (via CVE node) |
| `CVSSv2` | `vector_string`, `base_score`, `base_severity`, `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score`, `obtain_all_privilege`, `obtain_user_privilege`, `ac_insuf_info` | NVD (via CVE node) |
| `ThreatActor` | `name`, `aliases[]`, `description`, `zone[]` | MITRE ATT&CK, OTX |
| `Malware` | `name`, `malware_types[]`, `aliases[]`, `zone[]`, `uses_techniques[]` (MITRE explicit **`uses`**, optional) | MITRE ATT&CK, OTX, ThreatFox |
| `Technique` | `mitre_id`, `name`, `description`, `tactic_phases[]`, `zone[]` | MITRE ATT&CK |
| `Tactic` | `mitre_id`, `name`, `shortname` | MITRE ATT&CK |
| `Source` | `source_id`, `name` | Internal registry |

#### ResilMesh Topology Layer (schema-compatible stubs)

EdgeGuard creates these nodes only when enriching an inbound alert — not during scheduled collection. They are written to be fully compatible with ResilMesh's schema.

| Node Label | When created | Properties aligned to ResilMesh |
|------------|-------------|----------------------------------|
| `IP` | On alert ingestion from ResilMesh | `address`, `version`, `tag[]`, `status` |
| `Host` | On alert ingestion | `hostname` |
| `SoftwareVersion` | When a CVE affects a known product | `version`, `cve_timestamp` |

### 3.2 Relationships Produced by EdgeGuard

#### Internal threat intel relationships

| Relationship | From → To | Description |
|---|---|---|
| `SOURCED_FROM` | Any node → `Source` | **Per-source provenance** — one edge per (entity, source) pair. Carries `raw_data`, `imported_at` (immutable), `updated_at`, `confidence`, plus per-source claim properties **`source_reported_first_at`** (MIN-guarded) and **`source_reported_last_at`** (MAX-guarded) — what the source itself says about when it first/last recorded the entity. STIX export aggregates `MIN(r.source_reported_first_at)` across all edges to populate `Indicator.valid_from`. See [`docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`](KNOWLEDGE_GRAPH.md#sourced_from-edge-schema) for the full property contract. |
| `EMPLOYS_TECHNIQUE` | `ThreatActor` / `Campaign` → `Technique` | **Attribution.** Actor employs a MITRE technique (explicit STIX **`uses`** → `uses_techniques` on actor). *Split from a generic `USES` in 2026-04 — see below.* |
| `IMPLEMENTS_TECHNIQUE` | `Malware` / `Tool` → `Technique` | **Capability.** Malware or tool implements a MITRE technique (same STIX **`uses`** → `uses_techniques` on the source node; MISP **`MITRE_USES_TECHNIQUES:`** round-trip for Malware). *Split from a generic `USES` in 2026-04 — see below.* |
| `USES_TECHNIQUE` | `Indicator` → `Technique` | **Observation.** OTX `attack_ids` on indicator → `Technique.mitre_id` (`build_relationships.py`, conf 0.85). Unchanged by the 2026-04 refactor. |
| `ATTRIBUTED_TO` | `Malware` → `ThreatActor` | Malware linked to an actor (`build_relationships.py`) |
| `EXPLOITS` | `Indicator` → `Vulnerability` / `CVE` | Same `cve_id` on indicator and vuln/CVE node (`build_relationships.py`) |
| `INDICATES` | `Indicator` → `Malware` | MISP co-occurrence — array-only on both ends (`eid IN n.misp_event_ids` for both Indicator and Malware; legacy scalar dropped PR #33 round 10) or `malware_family` name match (ThreatFox/VT, conf 0.8) — **`build_relationships.py`** |
| `TARGETS` | `Indicator` → `Sector` | From `zone[]` on indicators (`build_relationships.py`) |
| `AFFECTS` | `Vulnerability` / `CVE` → `Sector` | From `zone[]` on vuln/CVE nodes (`build_relationships.py`) |
| `IN_TACTIC` | `Technique` → `Tactic` | MITRE kill-chain phase match (`build_relationships.py`) |

#### ResilMesh-compatible relationships

These match the ResilMesh schema exactly and allow cross-layer graph traversal:

| Relationship | From → To | Description |
|---|---|---|
| `HAS_CVSS_v31` | `CVE` ↔ `CVSSv31` | Bidirectional (matches ResilMesh pattern) |
| `HAS_CVSS_v30` | `CVE` ↔ `CVSSv30` | Bidirectional |
| `HAS_CVSS_v40` | `CVE` ↔ `CVSSv40` | Bidirectional |
| `HAS_CVSS_v2` | `CVE` ↔ `CVSSv2` | Bidirectional |
| `REFERS_TO` | `Vulnerability` ↔ `CVE` | Bidirectional link bridging EdgeGuard `Vulnerability` and `CVE` nodes — created by the post-sync enrichment job (`bridge_vulnerability_cve` in `enrichment_jobs.py`) |
| `IN` | `SoftwareVersion` → `Vulnerability` | Software affected by vulnerability |
| `ON` | `SoftwareVersion` → `Host` | Software installed on host |

#### Cross-layer bridges (threat intel ↔ topology) — gaps

Vulnerability↔CVE bridging is already listed above (**`REFERS_TO`**, enrichment job). ResilMesh docs sometimes call that link **`MAPS_TO`** — **EdgeGuard does not write `MAPS_TO`** today; query **`REFERS_TO`** instead.

| Relationship | From → To | Status |
|---|---|---|
| `TARGETS` | `Malware` → `Host` | ⚠️ Not implemented in scheduled pipeline |
| `INDICATOR_RESOLVES_TO` | `Indicator` → `IP` | ⚠️ Planned — **not** in `neo4j_client.py` (no `create_indicator_resolves_to_ip`) |

> **Note on naming:** ISIM uses `(IP)-[:RESOLVES_TO]->(DomainName)` for DNS. EdgeGuard’s planned Indicator→IP bridge is **`INDICATOR_RESOLVES_TO`** to avoid colliding with that semantics.

> **`Neo4jClient` helpers:** `create_indicator_vulnerability_relationship()` creates **`INDICATES`** to `Vulnerability`/`CVE` when called from custom code; the **Airflow `build_relationships`** pass uses **`EXPLOITS`** for CVE equality and **`INDICATES`** only for **Indicator→Malware**. Describe **production** output using **`build_relationships.py`**.

#### 3.2.1 Specialized technique relationships (2026-04 refactor)

Prior to 2026-04 every X→Technique edge was a single generic `USES`. That single type conflated three semantically distinct claims and hurt both Cypher query clarity and LLM/GraphRAG retrieval quality. It has been split into three specialized types that ResilMesh consumers should read going forward:

| New rel type | From → To | Semantic | Previously |
|---|---|---|---|
| `EMPLOYS_TECHNIQUE` | `ThreatActor` / `Campaign` → `Technique` | **Attribution** — *who* is observed using this TTP | `USES` |
| `IMPLEMENTS_TECHNIQUE` | `Malware` / `Tool` → `Technique` | **Capability** — *what* the code or tool can do | `USES` |
| `USES_TECHNIQUE` | `Indicator` → `Technique` | **Observation** — artifact observed tied to a TTP | (unchanged — already specialized) |

**STIX 2.1 mapping (for partners building STIX retrieval against our Neo4j):** All three graph types collapse back to the single STIX `relationship_type: "uses"` predicate. STIX disambiguates via the `source_ref` object type, exactly the pattern MITRE's own ATT&CK STIX bundles use. No information is lost on export; the graph simply makes the distinction explicit one layer earlier so graph-native consumers and GraphRAG prompts can see it directly.

```text
Graph                                                  → STIX 2.1 SRO
(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)        → relationship { source_ref: intrusion-set, relationship_type: "uses", target_ref: attack-pattern }
(Malware)    -[:IMPLEMENTS_TECHNIQUE]->(Technique)     → relationship { source_ref: malware,        relationship_type: "uses", target_ref: attack-pattern }
(Tool)       -[:IMPLEMENTS_TECHNIQUE]->(Technique)     → relationship { source_ref: tool,           relationship_type: "uses", target_ref: attack-pattern }
(Indicator)  -[:USES_TECHNIQUE]->(Technique)           → relationship { source_ref: indicator,      relationship_type: "indicates", target_ref: attack-pattern }
```

**Backward compatibility during rollout:** `create_misp_relationships_batch` in `src/neo4j_client.py` still accepts `rel_type="USES"` when `to_type="Technique"` and routes it to the correct specialized type based on `from_type`. Partners with code that emits the legacy value will keep working.

**Migration:** *Pre-release framework — no production graph exists, so no migration script is shipped.* The first baseline run already writes the specialized edge types (`EMPLOYS_TECHNIQUE` for actor/campaign, `IMPLEMENTS_TECHNIQUE` for malware/tool); a fresh baseline rerun heals any dev/test graph that still carries the legacy generic `USES` edges.

**What to update in your code:**

```cypher
// Before (still works due to backward-compat read path, but write path is deprecated):
MATCH (a:ThreatActor)-[:USES]->(t:Technique) RETURN a, t

// After (recommended — reads both attribution and capability explicitly):
MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN a, t
MATCH (m:Malware)-[:IMPLEMENTS_TECHNIQUE]->(t:Technique)  RETURN m, t

// If you want both specialized types in one query:
MATCH (n)-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
RETURN n, type(r) AS rel, t
```

### 3.3 Sector/zone and TLP

- **`zone`** — `LIST[STRING]` on merged threat-intel nodes (`global`, `healthcare`, `energy`, `finance`, …), populated from classification + MISP→Neo4j resolution (attribute-level `zone:` tags prioritized over event name / legacy event tags). Enables sector-scoped queries.
- **TLP** — **Current `MISPWriter`:** new events are tagged only with **`EdgeGuard`**; TLP is **not** added at event level by default. **Neo4j nodes are not guaranteed to have a `tlp` property** on every label after sync; do not rely on `n.tlp` in Cypher unless you add a separate projection step. Older MISP events may still carry historical TLP/sector event tags.

**Historical collection windows (hard limits):**

| Sector | Lookback | Rationale |
|--------|----------|-----------|
| `global` | 24 months | Aligned with sector feeds (`SECTOR_TIME_RANGES` in `config.py`); avoids dropping NVD/OTX items tagged only `global` in the 12–24 month band |
| `healthcare` | 24 months | Sector threats persist longer |
| `energy` | 24 months | ICS/SCADA vulnerabilities lag in patching |
| `finance` | 24 months | Regulatory and fraud patterns |

### 3.4 Node Identity Marking (`edgeguard_managed`)

Every node written by EdgeGuard carries a constant property:

```
edgeguard_managed = true
```

This follows the same principle as Kubernetes' `app.kubernetes.io/managed-by: helm` label — when multiple systems share the same database, each system marks what it owns. Without this, a consumer querying the shared Neo4j has no reliable way to distinguish EdgeGuard-written nodes from ResilMesh-written nodes of the same label (e.g., both may write `CVE` or `Vulnerability` nodes).

**Why this is a best practice in multi-system shared databases:**
- Label-based filtering (`WHERE n:CVE`) is ambiguous if two systems can write the same label
- Property-based ownership marker is explicit, self-documenting, and retroactively applies on next sync
- Allows ResilMesh, PPCTI, and THF to query EdgeGuard data cleanly without hardcoding label lists

**Useful filter queries:**

```cypher
// All EdgeGuard-managed nodes by type
MATCH (n) WHERE n.edgeguard_managed = true
RETURN labels(n)[0] AS type, count(*) AS cnt ORDER BY cnt DESC

// EdgeGuard nodes in the energy sector, updated in last 7 days
MATCH (n) WHERE n.edgeguard_managed = true
  AND 'energy' IN n.zone
  AND n.last_updated > datetime() - duration('P7D')
RETURN labels(n)[0] AS type, n.zone, count(*) AS cnt
```

The `source` and `tag` properties provide finer-grained **intelligence-source-level** provenance (which external feed provided the data), while `edgeguard_managed` provides **system-level** ownership (EdgeGuard wrote this).

---

## 4. What EdgeGuard Does NOT Provide

These nodes and relationships exist in the ResilMesh data model but are **outside EdgeGuard's scope by design**. EdgeGuard has no collectors for this data and should not attempt to populate it.

### 4.1 Infrastructure Layer — ResilMesh's Responsibility

| Node | Why not EdgeGuard's job |
|------|------------------------|
| `Device` | Physical/logical device inventory — populated by ResilMesh network scanners (Nmap, Zeek) |
| `User` | Identity data — populated by ResilMesh from AD/LDAP or network observation |
| `Role` | Access control model — populated by ResilMesh |
| `Component` | Mission components — populated by ResilMesh asset management |
| `Mission` | Organizational mission model — populated by ResilMesh |
| `OrganizationUnit` | Org structure — populated by ResilMesh |
| `MissionDependency` | Dependency graph — populated by ResilMesh |
| `Application` | Application inventory — populated by ResilMesh |
| `Node` (graph topology) | Network topology node with centrality scores — populated by ResilMesh |
| `Subnet` | Network segmentation — populated by ResilMesh network discovery |

### 4.2 Incident Management Layer — ResilMesh's Responsibility

| Node | Why not EdgeGuard's job |
|------|------------------------|
| `SecurityEvent` | Runtime detection events from Wazuh/Suricata — ResilMesh's domain |
| `Incident` | Incident lifecycle management — ResilMesh's domain |
| `DetectionSystem` | Wazuh, Suricata, Zeek instances — ResilMesh's domain |
| `Response` | Incident response tracking — ResilMesh's domain |
| `Data in Transit / Use / Rest` | Data flow classification — ResilMesh's domain |

### 4.3 Relationships ResilMesh Owns

These relationship types should only be written by ResilMesh's own pipeline:

`IS_A`, `HAS_IDENTITY`, `PART_OF` (IP→Subnet, Subnet→OrgUnit), `FOR` (Mission→OrgUnit), `SUPPORTS` (Mission↔Component), `PROVIDED_BY` (Component→Host), `IS_CONNECTED_TO` (Node↔Node with `{start, end}`), `TO`/`FROM` (MissionDependency), `RAISES` (DetectionSystem→SecurityEvent), `RELATES_TO` (SecurityEvent→Incident).

### 4.4 Planned: SoftwareVersion Bridge ⚠️ Work in Progress

> **Status: Not yet implemented.** This section documents the planned design.

The ResilMesh schema defines the chain:

```
(CVE)-[:IN]-(Vulnerability)-[:IN]->(SoftwareVersion)-[:ON]->(Host)
```

This chain enables the query: *"Which of our hosts is vulnerable to this CVE?"* — the most operationally valuable query in attack surface management. Currently EdgeGuard writes `CVE` and `Vulnerability` nodes but does **not** create `SoftwareVersion` nodes or the `IN`/`ON` relationships linking them to `Host`.

**What's needed to implement this:**

1. **CPE-to-SoftwareVersion mapping** — NVD CVE records include CPE strings (e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`). These need to be parsed and matched against the `SoftwareVersion.version` values that ResilMesh writes from its Nmap/scanner inventory.

2. **New enrichment job** — A `bridge_cve_to_softwareversion()` job in `enrichment_jobs.py` that:
   ```cypher
   MATCH (cve:CVE), (sv:SoftwareVersion)
   WHERE cve.cpe_type IS NOT NULL
     AND any(cpe IN cve.cpe_type WHERE sv.version CONTAINS cpe)
   MERGE (cve)-[:IN]->(sv)
   ```
   The CPE matching logic is non-trivial (version ranges, wildcards) and requires a dedicated parser.

3. **ResilMesh must write SoftwareVersion nodes first** — EdgeGuard cannot create this bridge until ResilMesh's network scanner has populated `SoftwareVersion` and `Host` nodes in the shared Neo4j. This is a coordination dependency.

**Why this matters:**

Once implemented, the full attack surface query becomes:
```cypher
MATCH (cve:CVE {cve_id: 'CVE-2021-44228'})  // Log4Shell
     -[:IN]->(sv:SoftwareVersion)
     -[:ON]->(host:Host)
     <-[:PROVIDED_BY]-(comp:Component)
     <-[:SUPPORTS]-(mission:Mission)
RETURN host.hostname, comp.name, mission.name, mission.criticality
ORDER BY mission.criticality DESC
```
This answers: *"Log4Shell affects which of our hosts, and what missions depend on those hosts?"*

---

## 5. Property Alignment — ResilMesh Schema vs EdgeGuard Output

### CVE Node

| Property | ResilMesh type | EdgeGuard output | Status |
|----------|---------------|------------------|--------|
| `cve_id` | STRING | ✅ `cve_id` | Aligned |
| `description` | STRING | ✅ `description` (500 chars) | Aligned |
| `published` | STRING | ✅ `published` (ISO 8601) | Aligned |
| `last_modified` | STRING | ✅ `last_modified` (ISO 8601) | Aligned |
| `cwe` | LIST OF STRING | ✅ `cwe` (e.g. `["CWE-89"]`) | Aligned |
| `ref_tags` | LIST OF STRING | ✅ `ref_tags` (e.g. `["Vendor Advisory"]`) | Aligned |
| `cpe_type` | LIST OF STRING | ✅ `cpe_type` (e.g. `["a", "o"]`) | Aligned |
| `result_impacts` | LIST OF STRING | ✅ `result_impacts` (CIA values) | Aligned |

### CVSSv31 Node

| Property | ResilMesh type | EdgeGuard output | Status |
|----------|---------------|------------------|--------|
| `vector_string` | STRING | ✅ | Aligned |
| `attack_vector` | STRING | ✅ | Aligned |
| `attack_complexity` | STRING | ✅ | Aligned |
| `privileges_required` | STRING | ✅ | Aligned |
| `user_interaction` | STRING | ✅ | Aligned |
| `scope` | STRING | ✅ | Aligned |
| `confidentiality_impact` | STRING | ✅ | Aligned |
| `integrity_impact` | STRING | ✅ | Aligned |
| `availability_impact` | STRING | ✅ | Aligned |
| `base_score` | FLOAT | ✅ | Aligned |
| `base_severity` | STRING | ✅ | Aligned |
| `impact_score` | FLOAT | ✅ | Aligned |
| `exploitability_score` | FLOAT | ✅ | Aligned |

### CVSSv2 Node

| Property | ResilMesh type | EdgeGuard output | Status |
|----------|---------------|------------------|--------|
| `vector_string` | STRING | ✅ | Aligned |
| `access_vector` | STRING | ✅ | Aligned |
| `access_complexity` | STRING | ✅ | Aligned |
| `authentication` | STRING | ✅ | Aligned |
| `confidentiality_impact` | STRING | ✅ | Aligned |
| `integrity_impact` | STRING | ✅ | Aligned |
| `availability_impact` | STRING | ✅ | Aligned |
| `base_score` | FLOAT | ✅ | Aligned |
| `base_severity` | STRING | ✅ | Aligned |
| `impact_score` | FLOAT | ✅ | Aligned |
| `exploitability_score` | FLOAT | ✅ | Aligned |
| `obtain_all_privilege` | BOOLEAN | ✅ | Aligned |
| `obtain_user_privilege` | BOOLEAN | ✅ | Aligned |
| `obtain_other_privilege` | BOOLEAN | ✅ | Aligned |
| `user_interaction_required` | BOOLEAN | ✅ | Aligned |
| `ac_insuf_info` | BOOLEAN | ✅ | Aligned |

### IP Node (ResilMesh vs EdgeGuard)

| Property | ResilMesh type | EdgeGuard output | Status |
|----------|---------------|------------------|--------|
| `address` | STRING | ✅ | Aligned |
| `version` | INTEGER | ✅ (4 or 6) | Aligned |
| `tag` | LIST OF STRING | ✅ | Aligned |
| `status` | STRING | ⚠️ Only set on alert enrichment, not during collection | Partial |

---

## 6. What ResilMesh Needs to Do for Full Integration

For the complete cross-layer graph traversal to work, ResilMesh must:

1. **Write topology nodes first** — `Host`, `IP`, `Subnet`, `Device`, `Node`, `Component`, `Mission` must exist in the shared Neo4j before EdgeGuard bridge relationships can be created.

2. **Use the same property names** as EdgeGuard expects for bridge relationships:
   - `IP.address` (EdgeGuard matches on this for `INDICATOR_RESOLVES_TO`)
   - `Host.hostname` (EdgeGuard matches on this for `TARGETS`)

3. **Use the same Neo4j instance** — EdgeGuard and ResilMesh must point to the same database for the shared graph to work. Connection is configured via `NEO4J_URI` in `.env`.

4. **Not overwrite EdgeGuard nodes** — ResilMesh should not create `CVE`, `Vulnerability`, `Indicator`, `Malware`, `ThreatActor`, `Technique`, or `Tactic` nodes. These are EdgeGuard's responsibility.

---

## 7. Downstream ResilMesh Services that Consume EdgeGuard Data

The ResilMesh platform exposes several services that directly consume or benefit from EdgeGuard's enriched graph. These are not integration requirements but are useful to understand as the deployment matures.

| Service | Port | How EdgeGuard feeds it |
|---------|------|------------------------|
| **PPCTI Frontend** (Privacy-Preserving CTI) | 3100 | EdgeGuard is the primary intelligence source. The PPCTI UI visualises threat intel from the shared Neo4j. |
| **IOB STIX** (Indicator of Behavior) | 3400 | Processes STIX-format IoB. EdgeGuard's STIX exports (`run_pipeline.py`) can feed IOB directly. |
| **THF** (Threat Hunting Framework) | 8030 / 8501 | Uses Anthropic Claude Sonnet for LLM-assisted threat hunting. EdgeGuard's enriched graph — ThreatActors linked to Techniques, Indicators linked to CVEs — is the ideal context injection for THF queries. |
| **Shuffle** (SOAR) | 3443 | Playbook automation. High-confidence, critical-sector indicators from EdgeGuard can trigger automated response playbooks. |
| **Wazuh SIEM** | 4433 | Wazuh detects events; EdgeGuard enriches them with CVE/IoC context via the NATS alert bridge. |

### Deployment note — Port Allocation & Intentional Separation

EdgeGuard runs on its **own dedicated edge server**, not on the ResilMesh host. The two systems share only the **Neo4j database** (via the Bolt port, 7687) and the **NATS message bus**. All other EdgeGuard services are network-isolated.

Despite running on separate hardware, we intentionally choose ports that do not collide with any known ResilMesh service port. This is a defensive practice: if future deployments co-locate EdgeGuard closer to the ResilMesh stack, or if a developer runs both on the same machine for testing, there are no silent bind conflicts.

| EdgeGuard Service | Our Port | Rationale |
|---|---|---|
| REST Query API | **8000** | Standard FastAPI default; no ResilMesh service uses it |
| GraphQL API | **4001** | Mirrors the ISIM GraphQL port — intentional alignment so ResilMesh can treat EdgeGuard as an additional ISIM-compatible data source |
| Airflow webserver | **8082** | Default (8080) collides with ResilMesh **Temporal** — explicitly overridden via `AIRFLOW__WEBSERVER__WEB_SERVER_PORT=8082` |
| Airflow metadata DB (PostgreSQL) | *(internal only)* | Docker Compose service **`airflow_postgres`** — not published on the host; backs **`LocalExecutor`** scheduler/UI state. |
| Prometheus metrics | **8001** (loopback only) | No ResilMesh service on this port; bound to `127.0.0.1` by default so it is not reachable from other hosts |
| Neo4j Browser | **7474** | Shared database — same host/port as ResilMesh's Neo4j instance |
| Neo4j Bolt | **7687** | Shared database — same host/port as ResilMesh's Neo4j instance |

**Known ResilMesh ports we intentionally avoid:**

| ResilMesh Service | Port |
|---|---|
| Temporal (workflow orchestration) | 8080 |
| PPCTI Frontend | 3100 |
| IOB STIX | 3400 |
| iSIM GraphQL | 4001 *(we mirror, not collide — separate host)* |
| iSIM REST (Django) | 8000 *(separate host — no collision in practice)* |
| THF API / Streamlit | 8030 / 8501 |
| Shuffle SOAR | 3443 |
| Wazuh SIEM | 4433 |
| MISP | 10443 |

(See `.env.example` for all annotated variables and the `docker-compose.yml` for how each service port is configured.)

---

## 8. Authorization — Who Can Access EdgeGuard Data ⚠️ Work in Progress

> **Status: Partially implemented.** Neo4j authentication is in place. Role-based access control and the preferred read interface are not yet configured. This section records what needs to be done.

### 8.1 Current State

Neo4j is protected by username/password authentication (`NEO4J_USER` / `NEO4J_PASSWORD` from `.env`). The Bolt port (7687) is restricted to `my_ips` at the AWS Security Group level — it is never publicly exposed.

However, **there is currently no role separation**. Any service with the Neo4j credentials has full read *and* write access to the shared database. EdgeGuard and ResilMesh both run on the same host and both use the same database user.

### 8.2 Preferred Access Method — iSIM GraphQL

> **ResilMesh recommendation:** use GraphQL (or REST, but REST is limited) instead of direct database access. Direct Bolt connections are not the intended integration path for external consumers.

ResilMesh exposes two query interfaces:
- **GraphQL** — iSIM, port 4001 — **preferred**
- **REST** — iSIM Django API, port 8000 — available but limited

**Why GraphQL is preferred for this use case:**

| Factor | GraphQL | REST |
|---|---|---|
| Data model fit | Native match — maps directly to graph nodes and edges | Impedance mismatch — flat resources don't represent traversals cleanly |
| Query flexibility | Consumer specifies exactly which fields to return | Fixed response shape per endpoint |
| Multi-hop traversals | Single query traverses CVE → CVSS → Vulnerability → SoftwareVersion → Host | Requires multiple sequential API calls |
| Schema documentation | Introspection built-in | Requires separate OpenAPI/Swagger spec |

**ISIM GraphQL is available at:** `http://<host>:4001/graphql`

**EdgeGuard GraphQL** (`src/graphql_api.py`, Strawberry + FastAPI) also listens on **4001** by default (`EDGEGUARD_GRAPHQL_PORT`). **Auth:** when `EDGEGUARD_API_KEY` is set in the environment, requests must include header **`X-Api-Key`**. **GraphiQL** is off unless `EDGEGUARD_GRAPHQL_PLAYGROUND=true`. **Rate limiting:** default **120 requests/minute** per IP (`slowapi`). **Health:** `GET /health` — **HTTP 200** only when Neo4j is healthy (ping + APOC); **503** otherwise. (REST API on port 8000 always returns **200** with `neo4j_connected` in JSON — see [README.md](../README.md) § *HTTP APIs*.)

**Real example from ISIM README** — query an IP address and trace to its missions:
```graphql
query IPaddresses {
  ips {
    address
    subnets {
      range
      contacts { name }
    }
    domain_names { domain_name }
    nodes {
      host {
        components {
          missions { name }
        }
      }
    }
  }
}
```

**Vulnerability + CVE query via ISIM GraphQL** (EdgeGuard data is directly queryable here):
```graphql
query VulnerableHosts {
  vulnerabilities {
    description
    status
    cve {
      cve_id
      description
      cvss_v31 { base_score base_severity attack_vector }
    }
    software_versions {
      version
      hosts { hostname }
    }
  }
}
```

> The ISIM GraphQL schema includes `CVE`, `Vulnerability`, `CVSSv31`, `CVSSv2`, `CVSSv30`, `CVSSv40`, `SoftwareVersion`, `Host`, `IP`, `Subnet` and all topology types. EdgeGuard's `CVE` and `Vulnerability` nodes are written in full compliance with this schema and are queryable via ISIM GraphQL as-is.

### 8.3 ISIM GraphQL Schema Coverage for EdgeGuard Data

| EdgeGuard node type | In ISIM GraphQL schema | Queryable via iSIM? |
|---|---|---|
| `CVE` | ✅ Yes — `type CVE` with full CVSS relationships | ✅ Yes |
| `Vulnerability` | ✅ Yes — `type Vulnerability` with `→CVE`, `→SoftwareVersion` | ✅ Yes |
| `CVSSv31` / `CVSSv30` / `CVSSv2` / `CVSSv40` | ✅ Yes — full property coverage | ✅ Yes (when NVD/MISP→Neo4j supplies metrics) |
| `Indicator` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `ThreatActor` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Malware` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Technique` / `Tactic` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Campaign` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |

**Impact:** EdgeGuard's MITRE ATT&CK and threat actor data cannot currently be queried through ISIM GraphQL. Querying those types requires either direct Neo4j Bolt access or an extension to the ISIM schema. See section 8.5.

### 8.4 ISIM Schema Extension — EdgeGuard Threat Intelligence Types ⚠️ Work in Progress

> **ResilMesh status:** ISIM currently covers assets and their vulnerabilities. Threat intelligence events, alerts, and ATT&CK data are not yet modelled in ISIM, but the data model is architected for this extension. ResilMesh is open to co-developing this layer.

The path to making EdgeGuard's full threat intelligence graph (ATT&CK techniques, indicators, threat actors, MISP events) queryable via ISIM GraphQL is to **extend the ISIM schema** — a co-development effort between EdgeGuard and ResilMesh.

**Proposed new types for the ISIM GraphQL schema:**

```graphql
type Indicator {
  value: String!
  indicator_type: String!
  zone: [String!]!
  confidence_score: Float
  tlp: String
  first_seen: String
  last_updated: String
  edgeguard_managed: Boolean
  vulnerabilities: [Vulnerability!]! @relationship(type: "INDICATES", direction: OUT)
}

type ThreatActor {
  name: String!
  aliases: [String]
  zone: [String!]!
  edgeguard_managed: Boolean
  techniques: [Technique!]! @relationship(type: "EMPLOYS_TECHNIQUE", direction: OUT)
  malware: [Malware!]! @relationship(type: "ATTRIBUTED_TO", direction: IN)
}

type Technique {
  mitre_id: String!
  name: String!
  tactic_phases: [String]
  edgeguard_managed: Boolean
  tactic: [Tactic!]! @relationship(type: "IN_TACTIC", direction: OUT)
}
```

- [ ] Coordinate with ResilMesh team to add EdgeGuard threat intelligence types to the ISIM GraphQL schema
- [ ] Reference ISIM GitHub: [resilmesh2/ISIM](https://github.com/resilmesh2/ISIM) — schema is in `isim_graphql/src/schema.graphql`

### 8.5 Planned Access Control Options

| Option | Effort | Protection | Recommended for |
|---|---|---|---|
| **iSIM GraphQL** (port 4001) — route CVE/Vulnerability queries through iSIM today | Low — works now for CVE/Vuln data | Strong — no direct database exposure | **All production CVE/Vuln integrations** |
| **Extend ISIM schema** — add Indicator/ThreatActor/Technique types (ResilMesh team can assist) | Medium — schema PR to ISIM repo | Strong — full threat intel queryable via API | **Full threat intelligence access** |
| **Neo4j Enterprise roles** — `resilmesh_read` user for direct Bolt access | Low if license available | Strong — database-enforced | If direct Bolt access is operationally required |

### 8.6 What Needs to Be Done

- [x] Confirm GraphQL is the preferred interface — ✅ confirmed per ResilMesh documentation and ISIM README
- [x] Confirm EdgeGuard CVE/Vulnerability schema alignment with ISIM — ✅ fully aligned
- [ ] Coordinate with ResilMesh team on ISIM schema extension for Indicator/ThreatActor/Technique/Tactic/Campaign
- [ ] Once schema is extended: test EdgeGuard data is queryable via `http://<host>:4001/graphql`
- [ ] Ensure metrics endpoint (`/metrics`, port 8001) stays on loopback — already defaulted in `.env.example`
- [ ] Update `docs/ARCHITECTURE.md` with final access method once ISIM extension is agreed

---

## 9. CVSS sub-nodes (v4.0 / v3.1 / v3.0 / v2)

EdgeGuard creates `CVSSv40`, `CVSSv31`, `CVSSv30`, and `CVSSv2` nodes from NVD metrics when present (`nvd_collector.py`), persists them in MISP via `NVD_META` (`misp_writer.py`), and merges them in Neo4j via `Neo4jClient.merge_cve()` → `_merge_cvss_node()`. CVSS v4.0 appears only for a subset of CVEs in NVD; v3.0 is used when v3.1 is absent.

---

## 10. Example: End-to-End Query Across Both Layers

### 10.1 Via ISIM GraphQL — works today (CVE + topology layer)

EdgeGuard's CVE/Vulnerability data is already in the ISIM schema and queryable now:

```graphql
# Which hosts are running software affected by a high-severity CVE?
query HighSeverityVulnerableHosts {
  vulnerabilities {
    description
    status
    cve {
      cve_id
      cvss_v31 {
        base_score
        base_severity
        attack_vector
      }
    }
    software_versions {
      version
      hosts {
        hostname
        components {
          missions {
            name
            criticality
          }
        }
      }
    }
  }
}
```

This query is **fully supported today** — it traverses `Vulnerability → CVE → CVSSv31` (EdgeGuard data) and `Vulnerability → SoftwareVersion → Host → Component → Mission` (ResilMesh topology data). The SoftwareVersion bridge (section 4.4) must be implemented first for the full chain.

### 10.2 Via Direct Neo4j Bolt — full threat intelligence (pending ISIM schema extension)

Once the ISIM GraphQL schema is extended (or via direct Bolt access), this query links a detected IP through EdgeGuard's full threat intelligence graph:

```cypher
// Starting from a ResilMesh IP under scrutiny → trace to CVE → malware → ATT&CK techniques
MATCH (ip:IP {address: '203.0.113.42'})
OPTIONAL MATCH (ind:Indicator)-[:INDICATOR_RESOLVES_TO]->(ip)   // planned EdgeGuard bridge
OPTIONAL MATCH (ind)-[:INDICATES|EXPLOITS]->(v:Vulnerability)
OPTIONAL MATCH (v)-[:REFERS_TO]->(cve:CVE)-[:HAS_CVSS_v31]->(cvss:CVSSv31)
OPTIONAL MATCH (ind)-[:ATTRIBUTED_TO]->(m:Malware)<-[:ATTRIBUTED_TO]-(ta:ThreatActor)
OPTIONAL MATCH (ta)-[:EMPLOYS_TECHNIQUE]->(tech:Technique)-[:IN_TACTIC]->(tactic:Tactic)
OPTIONAL MATCH (ip)<-[:HAS_ASSIGNED]-(n:Node)-[:IS_A]->(h:Host)
RETURN
  ip.address                      AS ip,
  ind.value                       AS indicator,
  v.cve_id                        AS cve,
  cvss.base_score                 AS cvss_score,
  cvss.base_severity              AS severity,
  m.name                          AS malware,
  ta.name                         AS threat_actor,
  collect(DISTINCT tech.mitre_id) AS techniques,
  h.hostname                      AS targeted_host
```

> `INDICATOR_RESOLVES_TO` replaces the previously documented `RESOLVES_TO` to avoid semantic collision with ISIM's `(IP)-[:RESOLVES_TO]->(DomainName)` relationship.

---

## 11. Related Documents

| Document | Content |
|----------|---------|
| [`docs/RESILMESH_INTEGRATION_GUIDE.md`](RESILMESH_INTEGRATION_GUIDE.md) | Full alert enrichment flow, NATS integration, performance SLAs, deployment |
| [`docs/KNOWLEDGE_GRAPH.md`](KNOWLEDGE_GRAPH.md) | Complete EdgeGuard Neo4j schema — all nodes, properties, constraints, indexes |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | EdgeGuard pipeline overview and data flow |
| [`COLLECTORS.md`](COLLECTORS.md) | Per-collector documentation with MISP output format |
| [`docs/DATA_SOURCES.md`](DATA_SOURCES.md) | All threat intelligence sources and what they provide |
| [`docs/DATA_SOURCES_RATE_LIMITS.md`](DATA_SOURCES_RATE_LIMITS.md) | API rate limits and quotas |
