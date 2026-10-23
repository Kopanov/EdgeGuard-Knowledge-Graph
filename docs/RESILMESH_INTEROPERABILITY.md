# EdgeGuard ↔ ResilMesh Interoperability Guide

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
| **Threat Intelligence** | EdgeGuard | CVEs (+ CVSS), Indicators, Malware, ThreatActors, Techniques, Tactics, Tools, Campaigns |
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
                                                  │  REFERS_TO           │
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
| `Indicator` | `value`, `indicator_type`, `zone[]`, `confidence_score`, `first_imported_at` (DB-local; the source's own claim lives on `SOURCED_FROM.source_reported_first_at`), `last_updated`, `misp_event_ids[]`, `misp_attribute_ids[]`, `pulse_id` (OTX report), `attack_ids[]` (pulse-level), `tlp`, **`uuid`** (deterministic, equal to the UUID portion of the STIX SDO id); the aging (§3.4): `last_reported_at`, `last_reported_source`, `last_reported_ref` (MISP attribute uuid), `last_reported_basis` (`source_date` / `misp_recorded`: the kind of date of the latest report; `aging_basis` is derived from it), `last_recorded_at`, `source_confidence`, `aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `aging_evaluated_at` (the time at which the aging values were last written: by a write, or by a job run that changed them; a job run that changes nothing leaves it unchanged), `active`, `retired_at`, `retired_by`, … | OTX, ThreatFox, URLhaus, MalwareBazaar (when `EDGEGUARD_ENABLE_MALWAREBAZAAR` is on), AbuseIPDB, VirusTotal, Feodo, SSLBlacklist; ResilMesh alerts (`source = resilmesh`) |
| `Vulnerability` | `cve_id`, `severity`, `cvss_score`, `attack_vector`, `zone[]`, `published`, `last_modified` | **Not written by the scheduled pipeline** (none on the live graph of 2026-10-11): NVD data lands as `CVE` + `CVSSv*` via `merge_cve`; `merge_vulnerabilities_batch` only serves MISP `vulnerability` objects. In CRUSOE's model `Vulnerability` is the scanner's finding — see §6. |
| `CVE` | `cve_id`, `description` (the text of the highest-ranked source, NVD > CISA KEV > CISA ICS > any other source, named in the EdgeGuard extension `description_source`; neither a MISP metadata block such as `OTX_META:{...}` nor an OTX pulse reference is ever a description), `published`, `last_modified` (from NVD's record; a KEV, CISA ICS or OTX record, a STIX import or a partner write fills them only where the node has none), `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]`; EdgeGuard extensions: `cvss_score` / `severity` / `cvss_version` / `attack_vector` (from the CVE's first CVSS sub-node in the order v3.1 → v3.0 → v2 → v4.0; a CVE without any CVSS has a null score, version and attack vector and severity `UNKNOWN`), `status[]` (NVD's record status), `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` (set by CISA KEV's record, and only filled by NVD's copy or any other record; every KEV run compares the whole catalogue, so CISA's revisions reach the node), `known_ransomware_use` (KEV; no score is derived from it), `epss_score` / `epss_percentile` / `epss_score_date` / `epss_model_version` (FIRST EPSS, written by the post-sync job on the CVE nodes that exist, partner-created ones included, which then carry `edgeguard_enriched`), `ssvc_exploitation` / `ssvc_automatable` / `ssvc_technical_impact` / `ssvc_version` / `ssvc_timestamp` (CISA's SSVC decision from NVD's record) | NVD; CISA KEV, CISA ICS and OTX records merge into the same node; FIRST EPSS |
| `CVSSv31` | `vector_string`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score` (none from CISA ICS) | NVD (via CVE node); CISA ICS where NVD has not asserted the node (NVD's values hold a node both assert) |
| `CVSSv2` | `vector_string`, `base_score`, `base_severity`, `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score`, `obtain_all_privilege`, `obtain_user_privilege`, `ac_insuf_info` | NVD (via CVE node) |
| `ThreatActor` | `name` (cleaned: no composites, no descriptive phrases, no country or state names; an OTX adversary the same pulse lists as a malware family only when the canonical threat-actor reference knows it, `docs/KNOWLEDGE_GRAPH.md` "Threat-actor names"), `aliases[]`, `description` (the text of the highest-ranked source, MITRE ATT&CK > a curated source > any other source, named in `description_source`, so ATT&CK's text where ATT&CK describes the actor; none on an actor only OTX names, since an OTX pulse's text describes the report), `zone[]`, `uses_techniques[]` (MITRE explicit **`uses`**), `reported_techniques[]` (OTX pulse-level), `pulse_ids[]`, `merged_from[]` (the names of the actor nodes the alias merge folded into it; STIX `x_edgeguard_merged_from`), `tlp` | MITRE ATT&CK, OTX (duplicates under an alias of a MITRE actor are merged into the MITRE node post-sync) |
| `Malware` | `name` (the family name without an ATT&CK software id suffix: OTX's `"Cobalt Strike - S0154"` is the ATT&CK node `cobalt strike`, the original in `aliases[]`), `malware_types[]`, `aliases[]`, `description` (as on `ThreatActor`), `zone[]`, `uses_techniques[]` (MITRE explicit **`uses`**, optional), `reported_techniques[]` (OTX pulse-level), `pulse_ids[]`, `merged_from[]` (the ATT&CK-id twins folded into the node), `tlp` | MITRE ATT&CK, OTX, ThreatFox |
| `Technique` | `mitre_id`, `name`, `description` (as on `ThreatActor`, with `description_source`), `tactic_phases[]`, `attack_domain` (`enterprise` \| `ics`), `is_subtechnique` (true for a dotted ATT&CK id), `zone[]`, `tlp` | MITRE ATT&CK Enterprise; ATT&CK for ICS when `EDGEGUARD_ENABLE_MITRE_ICS` is on |
| `Tactic` | `mitre_id`, `name`, `shortname`, `description` (ATT&CK's text, as on `ThreatActor`, with `description_source`), `attack_domain` | MITRE ATT&CK (Enterprise; ICS when enabled — 9 of 12 ICS short names equal Enterprise ones, so `IN_TACTIC` is matched within the domain) |
| `Source` | `source_id`, `name` | Internal registry |
| `Tool` | `mitre_id` (ATT&CK S-id), `name`, `description` (ATT&CK's text, as on `ThreatActor`, with `description_source`), `uses_techniques[]`, `zone[]`, `tlp` | MITRE ATT&CK software (tools) |
| `Campaign` | `name`, `actor_name`, `aliases[]`, `tags[]`, `indicator_count`, `malware_count`, `first_seen`, `last_seen`, `active`, `zone[]`, `tlp` (the most restrictive level of the links it rests on; none when none has one) | Derived — `enrichment_jobs.build_campaign_nodes`, one per actor with a malware attributed to it (`ATTRIBUTED_TO`) or used by it (`USES_MALWARE`), and an active indicator of such a malware. A campaign whose actor has neither link left, or whose actor name does not exist, is deleted with its links; one with evidence whose indicators expired stays, `active = false`. The `uuid` comes from the actor's name, so a campaign built again keeps it |
| `Sector` | `name` (`energy`, `finance`, `healthcare`, `global`) | Derived from `zone[]` by the sync and `build_relationships.py` Q7a–d |
| `CVSSv30`, `CVSSv40` | per-version score fields, same pattern as `CVSSv31` | NVD; bidirectional `HAS_CVSS_v30` / `HAS_CVSS_v40` |
| `Alert` | `alert_id`, `source`, `zone[]`, `timestamp`, `severity`, `indicator`, `indicator_type`, `malware`, `cve`, `enriched`, `received_at` | EdgeGuard's alert processor, from inbound NATS alerts only (none on a baseline). Not in CRUSOE's model, which has `SecurityEvent` — label ownership to agree with ResilMesh |

**Secondary sector labels:** nodes classified into a sector also carry `:Energy` / `:Finance` / `:Healthcare` as additional labels (applied by the sync after each run; on the live graph of 2026-10-11, 7,364 nodes carried `:Energy`). They are a convenience for label-based filtering — the authoritative sector relation is `TARGETS` / `AFFECTS` → `Sector`.

#### ResilMesh Topology Layer (schema-compatible helpers)

EdgeGuard has schema-compatible `merge_*` helpers for these labels, but **no pipeline path writes them today** — nothing calls `merge_ip` / `merge_host`; the alert processor writes `Alert`, the `Indicator` and `INVOLVES`. The indicator's link to its sector is written later, from its `zone[]`, by `build_relationships.py` Q7a. When a path does write them, §3.4 applies: a node EdgeGuard creates gets `edgeguard_managed`, a partner-created one `edgeguard_enriched`.

| Node Label | When created | Properties aligned to ResilMesh |
|------------|-------------|----------------------------------|
| `IP` | helper only (`merge_ip`) | `address`, `version`, `tag[]`, `status` |
| `Host` | helper only (`merge_host`) | `hostname` |
| `SoftwareVersion` | helper only (`merge_softwareversion`); see §4.4 | `version`, `cve_timestamp` |

### 3.2 Relationships Produced by EdgeGuard

#### Internal threat intel relationships

| Relationship | From → To | Description |
|---|---|---|
| `SOURCED_FROM` | Any node → `Source` | **Per-source provenance** — one edge per (entity, source) pair. Carries `raw_data` (the record that created the edge; on a `CVE` the MISP → Neo4j sync writes, the source's latest record, replaced on every write), `imported_at` (immutable), `updated_at`, `confidence`, plus per-source claim properties **`source_reported_first_at`** (MIN-guarded) and **`source_reported_last_at`** (MAX-guarded) — what the source itself says about when it first/last recorded the entity. The edge also accumulates, for its source, the MISP events that carried the entity (`misp_event_ids[]`) and the source's own record ids (`source_refs[]`). STIX export aggregates `MIN(r.source_reported_first_at)` across all edges to populate `Indicator.valid_from`. On an Indicator's edge, the source's latest report, forward only: `last_reported_at`, `last_reported_ref`, `last_reported_source`, `last_recorded_at`. On every edge, the zones this source's records gave the entity (`zones[]`, `global` dropped once a sector is present, sorted), the part of them the source stated itself (`stated_zones[]`: CISA ICS, and OTX for the sectors a pulse's own industries name; written when not empty) and which of the source's records stated which sector (`stated_refs[]`, `"<zone>\|<source ref>"`, e.g. `healthcare\|cisa_ics:ICSMA-26-283-01`): a link to a `Sector` names only the feeds that gave its sector and cites only the records that gave it. See [`docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`](KNOWLEDGE_GRAPH.md#sourced_from-edge-schema) for the full property contract. |
| `EMPLOYS_TECHNIQUE` | `ThreatActor` / `Campaign` → `Technique` | **Attribution.** Actor employs a MITRE technique. Evidence levels, told apart by `r.match_type` (§3.2.2): `mitre_explicit` (0.95, from MITRE's STIX **`uses`** → `uses_techniques`), `otx_pulse` (0.6, from an OTX pulse's `attack_ids` → `reported_techniques`) and, on a link a curated package's claim creates, the package's curated label (0.85; a claim on an existing link adds only its provenance, §3.2.2). One of the three technique relationship types, §3.2.1. |
| `IMPLEMENTS_TECHNIQUE` | `Malware` / `Tool` → `Technique` | **Capability.** Malware or tool implements a MITRE technique. Same evidence levels as `EMPLOYS_TECHNIQUE`: `mitre_explicit` (0.95), for malware named in an OTX pulse `otx_pulse` (0.6), and, on a link a curated package's claim creates, the package's curated label (0.85). MISP round-trip via the **`MITRE_USES_TECHNIQUES:`** comment (`t` = explicit, `rt` = reported, `pid` = pulse id). One of the three technique relationship types, §3.2.1. |
| `USES_TECHNIQUE` | `Indicator` → `Technique` | **Report.** The OTX report the indicator came from lists the technique: the pulse's `attack_ids`, inherited by every indicator of the pulse → `Technique.mitre_id` (`build_relationships.py`, `otx_attack_ids`, conf 0.6). It does not say the indicator executed the technique; phrase answers as "the report this indicator came from lists T1059". |
| `ATTRIBUTED_TO` | `Malware` → `ThreatActor` | Malware linked to an actor. Either the malware's own `attributed_to` claim matched exactly to the actor's name or alias (`match_type = "exact"`, 1.0, `build_relationships.py` Q2), or malware and actor named in the **same OTX pulse** (`match_type = "otx_pulse"`, 0.6, the pulse in `r.source_refs[]` as `alienvault_otx:<pulse id>`, written by the MISP→Neo4j sync). Only from a pulse whose actors are one actor: a pulse naming several actors does not say which malware is whose, so it attributes nothing; the aliases of one actor count as one (canonical threat-actor reference), decided by the OTX collector on the pulse's whole adversary list. `build_relationships` step 2d removes an attribution that rests only on such pulses (unless another feed asserts it) and drops such pulses from the provenance of the other attributions. No attribution comes from whole-MISP-event co-occurrence. |
| `EXPLOITS` | `Indicator` → `Vulnerability` / `CVE` | Only from the indicator's own `cve_id` tag (`match_type = "cve_tag"`; 1.0 from `build_relationships.py` Q3, or the attribute's own confidence (≥ 0.7) when the sync created the edge first from the `exploits:` tag). Never produced from event co-membership or from a shared report, because an IP or hash listed next to a CVE does not exploit it (an indicator and a CVE named in the same OTX pulse are `INDICATES`, below). No collector writes such a tag. Edge carries `r.misp_event_ids[]`. |
| `EXPLOITS` | `ThreatActor` / `Malware` → `CVE` | A curated package's claim that an actor or malware exploits a CVE (`match_type` = the package's curated label, 0.85; see the evidence table below). Completes the join from ResilMesh's `Host ← ON ← SoftwareVersion ← IN ← Vulnerability → REFERS_TO → CVE` to the threats that exploit the CVE. |
| `INDICATES` | `Indicator` → `Malware` | Two evidence levels (§3.2.2): a source-asserted `malware_family` on the indicator matched to the malware name/alias (`match_type = "malware_family"`, 0.8, ThreatFox, MalwareBazaar or Feodo Tracker; `r.sources[]` names OTX on such a link only when a pulse that listed the indicator names the family by the malware's name (or a name folded into it, `merged_from`), since OTX records carry no family label), or indicator and malware listed in the **same OTX pulse** (`match_type = "otx_pulse"`, 0.6, the pulse in `r.source_refs[]`). No link comes from whole-MISP-event co-occurrence. Edge carries `r.misp_event_ids[]`. |
| `INDICATES` | `Indicator` → `CVE` | The indicator and the CVE are named in the **same OTX pulse** (`match_type = "otx_pulse"`, 0.6), written by the MISP→Neo4j sync's report-scoped build: `r.sources = ["alienvault_otx"]`, the pulse in `r.source_refs[]` (`alienvault_otx:<pulse id>`), the MISP event in `r.misp_event_ids[]`. It says "named in the same report", the evidence of the same-pulse `INDICATES` to `Malware`, never that the indicator exploits the CVE (`EXPLOITS`). The `CVE` node is matched by `cve_id`, never created by the link; at most 50 CVEs and 2,000 indicators of one pulse are paired. It joins ResilMesh's `Host ← ON ← SoftwareVersion ← IN ← Vulnerability → REFERS_TO → CVE` to the indicators a report names with the CVE: `… → CVE ← INDICATES ← Indicator` (§10.3). |
| `TARGETS` | `Indicator` → `Sector`; `ThreatActor` → `Sector`, `Malware` → `Sector` | "Reported in connection with attacks on this sector." From `zone[]` on the node — indicators: written by the sync (`r.sources` names the indicator's own source) and by `build_relationships.py` Q7a; actors and malware: Q7c / Q7d. `global` is never an edge target, so an actor never "targets global". `r.sources` / `r.source_refs` / `r.misp_event_ids` name only the feeds whose `SOURCED_FROM.zones` give the sector, and the label and confidence follow §3.2.2: `match_type='otx_industries'` at 0.6 when an OTX pulse's own `industries` name the sector (the report's author states that its campaign targets it; `r.source_refs` names the pulses whose industries name it), otherwise `match_type='zone_classification'` at 0.5 (an inference, never 1.0; the pulse's keyword hits included); a CISA deployment statement never labels `TARGETS`. A query that filters on `match_type = 'zone_classification'` alone misses OTX's statements. The edge carries `r.misp_event_ids[]`. |
| `AFFECTS` | `Vulnerability` / `CVE` → `Sector` | "The vulnerable product is used in this sector." From `zone[]` on vuln/CVE nodes — sync (`r.sources` names the record's own source) and `build_relationships.py` Q7b; `global` never an edge target. The link names only the feeds whose `SOURCED_FROM.zones` give the sector, and its label follows §3.2.2: `advisory_sector` at 0.9 when CISA's ICS advisory states the sector (where the product is deployed; `r.source_refs` names the advisories whose sector note names that sector, `cisa_ics:ICSA-…`, not every advisory of the CVE), otherwise `zone_classification` at 0.5 (also for a CVE an OTX pulse names: a targeted industry says nothing about where a product is deployed). A query that filters on `match_type = 'zone_classification'` alone misses CISA's statements. The edge carries `r.misp_event_ids[]`. |
| `IN_TACTIC` | `Technique` → `Tactic` | MITRE kill-chain phase match (`build_relationships.py`) |
| `SUBTECHNIQUE_OF` | `Technique` → `Technique` | Sub-technique → parent technique, from MITRE's dotted id (`T1021.006` → `T1021`; the same claim as the STIX `subtechnique-of` relationship). `build_relationships.py` Q1b, `match_type='mitre_explicit'`, 1.0, same `attack_domain` on both ends. 493 edges on the graph of 2026-09. |
| `USES_MALWARE` | `ThreatActor` → `Malware` | MITRE's explicit STIX `uses` relationship from a group to malware, carried on the actor as `uses_malware[]` and written by `build_relationships.py` Q2b (`match_type='mitre_explicit'`, 0.95; canonical lower-case **name** match only — never `aliases`, which are rehydrated from untrusted MISP tags). The precise form of what the legacy CLI path infers as `ATTRIBUTED_TO` (`mitre_derived`). A curated package's claim (exact canonical malware name) creates the link with the package's curated label and 0.85, or adds its provenance to an existing one. Campaign evidence like `ATTRIBUTED_TO`: an actor with such a link has a campaign, and the malware is a member. |
| `USES_TOOL` | `ThreatActor` → `Tool` | Same source for tools (`uses_tools[]` = ATT&CK S-ids), Q2c; curated-package claims (the tool's ATT&CK id) as for `USES_MALWARE`. |
| `RUNS` | `ThreatActor` → `Campaign` | Actor runs the campaign materialised for it by `enrichment_jobs.build_campaign_nodes` (one `Campaign` per actor with a malware attributed to it or used by it). Removed when it comes from an actor that is not the campaign's or has neither link left; a campaign whose actor has neither link left is deleted with its links. `r.evidence_types` names the types of the links it rests on (`ATTRIBUTED_TO`, `USES_MALWARE`). |
| `PART_OF_CAMPAIGN` | `Malware` → `Campaign`; `Indicator` → `Campaign` | Membership of the actor's malware (attributed to it or used by it) and of the indicators that indicate it (the 100 newest active ones, each once); the indicator edge is pruned when the indicator is retired, and the malware edge when the malware has neither link (`ATTRIBUTED_TO`, `USES_MALWARE`) to the campaign's actor. Campaign links (`RUNS`, `PART_OF_CAMPAIGN`) carry the provenance of the links they currently rest on, replaced on every run, and the relationship types of those links in `r.evidence_types` (`INDICATES` too on an indicator's link). |
| `INVOLVES` | `Alert` → `Indicator` | Written by the alert processor for inbound NATS alerts; carries the ownership marker (`created_at` once, `updated_at` per delivery). |

**STIX 2.1 bundle coverage (`/stix/export/*`):** every SRO uses the `relationship_type` the STIX 2.1 relationship summary table permits for its (source, target) pair. `INDICATES` (Indicator → Malware) and `USES_TECHNIQUE` (Indicator → Technique) are `indicates`; `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` are `uses`; `ATTRIBUTED_TO` (Malware → ThreatActor) is exported in the direction the table defines, `intrusion-set` **`uses`** `malware` (the MITRE ATT&CK form these edges derive from); `RUNS` (ThreatActor → Campaign) is `campaign` **`attributed-to`** `intrusion-set`; `EXPLOITS` (Indicator → CVE), `INDICATES` (Indicator → CVE, named in the same OTX report), `Indicator → Sector TARGETS` and `CVE → Sector AFFECTS` have no table-defined pair and are `related-to` (both links of one indicator and CVE are one SRO, whose provenance merges them and whose `x_edgeguard_match_type` names the stronger link's label). Sector `identity` objects carry `industry-sector-ov` values (`finance` → `financial-services`; `global` has none). Every SDO carries `object_marking_refs` from `n.tlp` (STIX 2.1 TLP marking definitions; `clear` → WHITE, `amber+strict` → RED, unrecognised → AMBER, absent → the deployment default `EDGEGUARD_DEFAULT_TLP`) and SROs carry the most restrictive marking of their endpoints and of the relationship's own `r.tlp` (curated-package links carry the package's level, and the campaigns and campaign links built on them carry the most restrictive level of the links they rest on); `created_by_ref` on every object points to the EdgeGuard producer `identity`, which carries the exporter provenance, and the `x_edgeguard_*` properties are declared by an `extension-definition` (`toplevel-property-extension`) so the bundle parses under strict `stix2.parse`. Every `created` / `modified` comes from the graph, never from the clock, so re-exporting the same graph gives a byte-identical bundle ([RESILMESH_QUICKSTART_STIX.md § 8](RESILMESH_QUICKSTART_STIX.md#8-design-decisions)). Each related-node collection is bounded by `?limit=` (default 100, maximum 500). **Every relationship with a STIX form is exported**, curated-package claims included: `USES_MALWARE` / `USES_TOOL` (`intrusion-set` `uses` `malware` / `tool`), `SUBTECHNIQUE_OF` (`subtechnique-of`, MITRE ATT&CK's own type), `EXPLOITS` from `Malware` (`malware` `exploits` `vulnerability`) and from `ThreatActor` (`intrusion-set` `targets` `vulnerability`), `ThreatActor → Sector TARGETS` (`intrusion-set targets identity`), and an indicator's `PART_OF_CAMPAIGN` (`indicator indicates campaign`). `relationship_mappings` also lists `malware targets identity` and `campaign uses malware`, but there is no malware or campaign export, so no bundle carries those links today. **Every SRO carries the provenance of its graph relationship:** `confidence` (0–100 from `confidence_score`), `external_references` built from `source_refs` (a link where the source record has a public page: OTX pulse, ThreatFox IOC, URLhaus entry, ATT&CK object), and the extension properties `x_edgeguard_match_type`, `x_edgeguard_sources`, `x_edgeguard_source_refs`, `x_edgeguard_misp_event_ids` (extension definition 1.1.0). Not SROs: `IN_TACTIC` (a kill-chain phase on the `attack-pattern`), `SOURCED_FROM` (node provenance, carried as properties), `REFERS_TO` (twin nodes share one `vulnerability`), `HAS_CVSS_*` (properties of the `vulnerability`) and `INVOLVES`. **A `vulnerability` carries NVD's record status** as `x_edgeguard_status` (`["rejected"]` / `["active"]`, extension definition 1.2.0). **Explainability (extension definition 1.3.0):** a link to a technique that a source cited by an id ATT&CK has since revoked carries `x_edgeguard_cited_ids` (the ids cited), and an `intrusion-set` the actor alias merge folded other actor nodes into carries `x_edgeguard_merged_from` (their names). **A `vulnerability` carries FIRST EPSS and CISA's SSVC decision** (extension definition 1.4.0): `x_edgeguard_epss_score`, `x_edgeguard_epss_percentile`, `x_edgeguard_epss_score_date`, `x_edgeguard_epss_model_version`, `x_edgeguard_ssvc_exploitation`, `x_edgeguard_ssvc_automatable`, `x_edgeguard_ssvc_technical_impact`, `x_edgeguard_ssvc_version`, `x_edgeguard_ssvc_timestamp`. **The SRO of a campaign link (`RUNS`, `PART_OF_CAMPAIGN`) names the relationship types it rests on** as `x_edgeguard_evidence_types` (extension definition 1.5.0).

#### ResilMesh-compatible relationships

These match the ResilMesh schema exactly and allow cross-layer graph traversal:

| Relationship | From → To | Description |
|---|---|---|
| `HAS_CVSS_v31` | `CVE` ↔ `CVSSv31` | Bidirectional (matches ResilMesh pattern) |
| `HAS_CVSS_v30` | `CVE` ↔ `CVSSv30` | Bidirectional |
| `HAS_CVSS_v40` | `CVE` ↔ `CVSSv40` | Bidirectional |
| `HAS_CVSS_v2` | `CVE` ↔ `CVSSv2` | Bidirectional |
| `REFERS_TO` | `Vulnerability` ↔ `CVE` | ResilMesh's edge in CRUSOE's model (the scanner links its finding to the CVE). EdgeGuard's post-sync job `bridge_vulnerability_cve` MERGEs it in both directions for any `Vulnerability` node carrying `cve_id` — none exists today: EdgeGuard writes `CVE`, not `Vulnerability` (no `REFERS_TO` on the live graph of 2026-10-11). |
| `IN` | `Vulnerability` → `SoftwareVersion` | Vulnerable software, as ISIM traverses it (`vulnerabilities { software_versions }`) — ResilMesh-defined; EdgeGuard has helpers for both directions but no pipeline path writes it (see §4.4) |
| `ON` | `SoftwareVersion` → `Host` | Software installed on host — ResilMesh-defined; EdgeGuard has helper code but no pipeline path writes it |

#### Cross-layer bridges (threat intel ↔ topology) — gaps

Vulnerability↔CVE bridging is already listed above (**`REFERS_TO`**, enrichment job). ResilMesh docs sometimes call that link **`MAPS_TO`** — **EdgeGuard does not write `MAPS_TO`** today; query **`REFERS_TO`** instead.

| Relationship | From → To | Status |
|---|---|---|
| `TARGETS` | `Malware` → `Host` | Not written |
| `INDICATOR_RESOLVES_TO` | `Indicator` → `IP` | Not written; no helper in `neo4j_client.py` |

Both links are planned work ([ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration)).

> **Note on naming:** ISIM uses `(IP)-[:RESOLVES_TO]->(DomainName)` for DNS. The name of an EdgeGuard Indicator→IP link is **`INDICATOR_RESOLVES_TO`**, which avoids colliding with that semantics.

> **`Neo4jClient` helpers:** `create_indicator_vulnerability_relationship()` creates **`INDICATES`** to `Vulnerability`/`CVE` without an evidence label (0.5) when called from custom code; no pipeline path calls it. In production, **`EXPLOITS`** links an indicator to the CVE its own CVE tag names (`build_relationships.py`), and **`INDICATES`** links an indicator to a `Malware` (family label or same OTX pulse) or to a `CVE` named in the same OTX pulse (the sync, `create_misp_relationships_batch`, `otx_pulse`).

#### 3.2.1 Specialized technique relationships

Every relationship from a `ThreatActor`, `Campaign`, `Malware`, `Tool` or `Indicator` to a `Technique` has one of three specialized types. Each type carries one distinct claim, which keeps Cypher queries clear and LLM/GraphRAG retrieval precise; ResilMesh consumers read these types:

| Rel type | From → To | Semantic |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | `ThreatActor` / `Campaign` → `Technique` | **Attribution** — *who* is observed using this TTP |
| `IMPLEMENTS_TECHNIQUE` | `Malware` / `Tool` → `Technique` | **Capability** — *what* the code or tool can do |
| `USES_TECHNIQUE` | `Indicator` → `Technique` | **Report** — the indicator's OTX report lists this TTP (not an observation of the indicator using it) |

**STIX 2.1 mapping (for partners building STIX retrieval against our Neo4j):** `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE` collapse back to the single STIX `relationship_type: "uses"`; STIX tells them apart by the `source_ref` object type, as MITRE's ATT&CK bundles do. `USES_TECHNIQUE` (indicator source) is exported as `indicates`, the only relationship STIX 2.1 defines for `indicator` → `attack-pattern`. No information is lost on export; the graph simply makes the distinction explicit one layer earlier so graph-native consumers and GraphRAG prompts can see it directly.

```text
Graph                                                  → STIX 2.1 SRO
(ThreatActor)-[:EMPLOYS_TECHNIQUE]->(Technique)        → relationship { source_ref: intrusion-set, relationship_type: "uses", target_ref: attack-pattern }
(Malware)    -[:IMPLEMENTS_TECHNIQUE]->(Technique)     → relationship { source_ref: malware,        relationship_type: "uses", target_ref: attack-pattern }
(Tool)       -[:IMPLEMENTS_TECHNIQUE]->(Technique)     → relationship { source_ref: tool,           relationship_type: "uses", target_ref: attack-pattern }
(Indicator)  -[:USES_TECHNIQUE]->(Technique)           → relationship { source_ref: indicator,      relationship_type: "indicates", target_ref: attack-pattern }
```

**No generic `USES`:** no relationship of type `USES` points to a `Technique`. `create_misp_relationships_batch` in `src/neo4j_client.py` does not accept `rel_type="USES"` with `to_type="Technique"`: such a row matches none of the specialized buckets and is silently dropped, and no caller in `src/`, `dags/` or `tests/` emits it. Partner code must emit the specialized types; check your call sites. The alert-enrichment query reads `EMPLOYS_TECHNIQUE` only. The baseline writes the specialized types (`EMPLOYS_TECHNIQUE` for actor/campaign, `IMPLEMENTS_TECHNIQUE` for malware/tool).

**Querying:**

```cypher
// Attribution (actor) and capability (malware):
MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN a, t
MATCH (m:Malware)-[:IMPLEMENTS_TECHNIQUE]->(t:Technique)  RETURN m, t

// All three specialized types in one query:
MATCH (n)-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
RETURN n, type(r) AS rel, t
```

### 3.2.2 Evidence labels on relationships

Every relationship that encodes a claim between threat-intelligence entities states what kind of evidence
produced it, in `r.match_type`, with a confidence that follows from the evidence. (Structural edges —
`SOURCED_FROM`, `HAS_CVSS_*`, `REFERS_TO` — carry none; their meaning is fixed. The campaign links carry `campaign_grouping`.) Consumers (and the text-to-Cypher model) can therefore filter
by evidence; the relationship names are the ResilMesh and STIX-derived ones.

| `r.match_type` | Meaning | Confidence | Produced by |
|---|---|---|---|
| `mitre_explicit` | MITRE ATT&CK's own assertion: the STIX `uses` relationship, or the sub-technique hierarchy encoded in MITRE's dotted ids (`T1021.006` → `T1021`, equivalent to its STIX `subtechnique-of`) | 0.95 (`uses`) / 1.0 (`SUBTECHNIQUE_OF`) | `build_relationships.py` Q5/Q6/Q10 from `uses_techniques` (MITRE collector only); Q1b `SUBTECHNIQUE_OF`; Q2b/Q2c `USES_MALWARE` / `USES_TOOL` from `uses_malware` / `uses_tools` |
| `otx_pulse` | The entity was named in the same AlienVault OTX pulse (one report) | 0.6 | MISP→Neo4j sync (`INDICATES` to `Malware` and to `CVE`, `ATTRIBUTED_TO`, same-run pairs); `build_relationships.py` Q5b/Q6b from `reported_techniques`; **Q9b/Q2d (regular updates)** from the families / adversaries each pulse stamps on its indicators (`Indicator.pulse_malware_families`, and `"family::adversary::pulse"` pairs of the same pulse in `.pulse_malware_actor_pairs` — never a cross product of two lists) — so IOCs of a later pulse naming an already-known family still link, although the family attribute itself is a MISP cross-event duplicate. `ATTRIBUTED_TO` only from a pulse whose actors are one actor (aliases of one actor count as one). ON CREATE only: never downgrades `malware_family` (0.8), `exact` (1.0) or `mitre_explicit` |
| `exact` | The malware's own `attributed_to` claim equals an actor name/alias | 1.0 | `build_relationships.py` Q2 |
| `malware_family` | The indicator's source-asserted family equals a malware name/alias | 0.8 | `build_relationships.py` Q9 |
| `cve_tag` | The indicator's own CVE tag | 1.0 | `build_relationships.py` Q3a/Q3b |
| `otx_attack_ids` | Pulse-level ATT&CK ids inherited by every indicator in the pulse | 0.6 (the confidence of `otx_pulse`, which the same ids give the pulse's actors and families) | `build_relationships.py` Q8 (`USES_TECHNIQUE`; pulse-level). ON CREATE only |
| `kill_chain_phase` | ATT&CK tactic phase on the technique | 1.0 | `build_relationships.py` Q1 (`IN_TACTIC`) |
| `campaign_grouping` | EdgeGuard's grouping of one actor's malware (attributed to it, `ATTRIBUTED_TO`, or used by it, `USES_MALWARE`) and those malware's active indicators into a campaign — derived, not a source's claim; `r.evidence_types` names the relationship types it rests on; its `sources` and `source_refs` are those of the links it rests on, sorted, and its `misp_event_ids` the 200 newest of theirs by MISP event id, so they do not depend on the order in which those links were created | the evidence it rests on: `RUNS` the actor's strongest link to a malware; malware `PART_OF_CAMPAIGN` its strongest link to the actor; indicator `PART_OF_CAMPAIGN` its best path, `INDICATES` then `ATTRIBUTED_TO` or `USES_MALWARE`, each path as strong as its weaker link | `enrichment_jobs.build_campaign_nodes` (`RUNS`, `PART_OF_CAMPAIGN`), recomputed on every run |
| `zone_classification` | EdgeGuard's own sector classification of the node (keywords in NVD descriptions and CPE vendors / products, KEV vendor and product, OTX pulse text, a feed's malware family; on `AFFECTS` also the sectors an OTX pulse's industries name for a CVE it lists) and a foreign MISP zone tag — an inference, so it never carries 1.0; `global` ("no sector") is never linked | 0.5 (sync and Q7a–Q7d) | `TARGETS` (Indicator, ThreatActor, Malware → Sector), `AFFECTS` (CVE → Sector); the link names only the feeds that gave the sector |
| `otx_industries` | The OTX pulse classifies itself into industries (its `industries` field): the report's author states that the campaign it describes **targets** the sector. Only the sectors those industries map to (`config.OTX_INDUSTRY_ZONE_ALIASES`) are stated; the sectors keyword detection finds in the pulse text stay `zone_classification`. A targeting statement, never a deployment one; one link per node and sector, so where another record infers the sector the link carries this label and names both feeds, and the statement is on the `alienvault_otx` `SOURCED_FROM` edge (`stated_zones`). Every pulse of the collection run that lists the item counts, whichever listed it first; MISP keeps the attribute written first, so a pulse of a later run that lists the same item adds no statement | 0.6 (sync and Q7a / Q7c / Q7d, from one table, `src/sector_evidence.py`; must stay above 0.5) | `TARGETS` (Indicator, ThreatActor, Malware → Sector) only, from `alienvault_otx`; `r.source_refs` `alienvault_otx:<pulse id>` of the pulses whose industries name that sector (`SOURCED_FROM.stated_refs`); a CVE the pulse names keeps `zone_classification` on `AFFECTS` |
| `advisory_sector` | CISA's ICS advisory names the sector in its "Critical infrastructure sectors" note: the affected product is **deployed** in it. A deployment statement, never a targeting claim; one link per CVE and sector, so where NVD or OTX also infers the sector the link carries this label and names both feeds, and who stated it is on the `cisa_ics` `SOURCED_FROM` edge (`stated_zones`) | 0.9 (sync and Q7b, from one table, `src/sector_evidence.py`; must stay above 0.5) | `AFFECTS` (CVE → Sector) only, from `cisa_ics`; `r.source_refs` `cisa_ics:<advisory id>` of the advisories that name that sector only (a CVE named by an ICS advisory for Energy and a medical advisory for Healthcare cites the first on its energy link and the second on its healthcare link; `SOURCED_FROM.stated_refs`), exported to STIX with the cisa.gov page |
| `mitre_derived` | Malware attributed to an actor because MITRE's STIX says the actor **uses** that malware (inference, not an explicit `attributed-to`) | 0.7 | Legacy in-process path only (`run_pipeline.py` → `Neo4jClient.create_malware_actor_relationship`); the DAG path does not write it |
| `stix_relationship` | An explicit STIX relationship object (`attributed-to`) in a bundle imported by the in-process loader | 0.7 | Legacy in-process path only (`run_pipeline.load_stix21_to_neo4j` → `Neo4jClient.create_malware_actor_relationship`); the DAG path does not write it |
| `misp_attribute_tag` | A tag on the MISP attribute itself: an ATT&CK technique tag (`misp-galaxy:mitre-attack-pattern="… - T####"`, `mitre-attack:technique:`), a threat-actor tag (`threat-actor:`, `misp-galaxy:threat-actor="…"`) or a malware tag (`malware-type:`, `misp-galaxy:malware="…"`); an `exploits:` tag gives `EXPLOITS` with `cve_tag` | from the attribute's `confidence:` tag: 0.8 high, 0.5 medium, 0.3 low (0.5 without one) | MISP→Neo4j sync: attribute-embedded `EMPLOYS_TECHNIQUE`, `ATTRIBUTED_TO` and `INDICATES` (indicator → a malware family named in the attribute's tags); embedded `EXPLOITS` keeps `cve_tag` |
| `coreideas_curated` / `curated_other` | A link created by a claim of a curated package imported once into MISP (`scripts/import_curated_package.py`): `coreideas_curated` for the registered curated source `coreideas`, `curated_other` for a registered curated source without a label of its own (`misp_galaxy`). A claim on a link that already exists leaves that link's label and confidence and adds its provenance. `r.sources` names the source of each claim, a registered curated source only (any other is recorded as `curated_other`); `r.tlp` carries the package's TLP level | 0.85 | MISP→Neo4j sync: `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`, `USES_MALWARE`, `USES_TOOL`, `EXPLOITS` (actor / malware → CVE); MATCH on existing nodes only |

**Precedence:** an edge's label and confidence only ever move towards stronger evidence. On a link to a `Sector` the confidence is the value the label table gives the label (`src/sector_evidence.py`), whichever writer runs: `build_relationships` Q7a–Q7d keep a stored stronger label of the table and a label outside it, and give a link without a label the computed one. The MISP→Neo4j sync keeps the higher `confidence_score` and the label that came with it (a later `otx_pulse` 0.6 row never overwrites an `exact` 1.0 or `mitre_explicit` 0.95 edge); `build_relationships` re-asserts explicit labels on every run and writes report-scoped labels on creation only. A curated-package claim never changes an existing edge's label or confidence (an `otx_pulse` 0.6 edge stays `otx_pulse`): it writes its label and 0.85 only on an edge it creates, and on an existing edge adds its provenance. To leave the curated layer out of a dataset, filter on `r.sources`, not on `r.match_type` (`docs/KNOWLEDGE_GRAPH.md`, "Curated packages").

Every edge EdgeGuard builds from the sources also says who asserts it: `r.sources[]` (canonical
source ids such as `mitre_attck`, `alienvault_otx`, `threatfox`, `nvd`), `r.source_refs[]` (the sources' own
record ids, e.g. `alienvault_otx:<pulse id>`, `threatfox:<IOC id>`, `mitre_attck:G0016`) and
`r.misp_event_ids[]`, so a consumer can go from the edge to the MISP event and to the report that asserted it
(`docs/KNOWLEDGE_GRAPH.md`, "Relationship provenance"). Items without a report id are never paired.
No edge EdgeGuard writes carries the label `misp_cooccurrence`.

### 3.2.x STIX 2.1 timestamp semantics

The full timestamp model is documented in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md). For consumers, the upshot is:

| STIX field | Meaning in EdgeGuard bundles |
|---|---|
| `created` | When the SDO was created in EdgeGuard's graph (our import time, the node's `first_imported_at`), for every SDO type including `vulnerability`. NVD's publication date of a CVE is `x_edgeguard_published`. |
| `modified` | When EdgeGuard last refreshed its record. An indicator's: the latest of `created`, `last_recorded_at` (the latest MISP record of a report) and `aging_since` (when its aging state last changed), never earlier than `created` and unmoved by a re-sync of the same data |
| `valid_from` (Indicator only) | The source's first-observation claim if available; falls back to EdgeGuard's import time and sets `x_edgeguard_first_seen_inferred=true` so consumers can filter for source-truthful evidence |
| `x_edgeguard_first_seen_at_source` | Verbatim source claim (concept 1). Absent if no source provided one |
| `x_edgeguard_last_seen_at_source` | Verbatim source claim (concept 2). Absent if no source provided one |
| `x_edgeguard_first_imported_at` | EdgeGuard's import wall-clock (concept 3) |
| `x_edgeguard_last_updated` | EdgeGuard's last-touch wall-clock (concept 4); not on an indicator, whose `modified` does not follow it |
| `x_edgeguard_first_seen_inferred` | `true` iff `valid_from` came from the fallback chain. Use this to filter for source-truthful indicators only when building correlation pipelines |
| `x_edgeguard_description_source` | The source whose text the SDO's `description` is (`nvd`, `cisa_kev`, `mitre_attck`, …; extension definition 1.6.0). Absent when the SDO has no description |
| `x_edgeguard_last_reported_at`, `x_edgeguard_last_reported_source`, `x_edgeguard_last_reported_ref` | Indicators (extension definition 1.7.0): the latest report of any source — its time (`min(T, coalesce(L, T))`, the source's `last_seen` capped at the MISP timestamp), the source, and the MISP attribute uuid that holds it ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging)) |
| `x_edgeguard_source_confidence`, `x_edgeguard_aging_basis`, `x_edgeguard_aging_tier`, `x_edgeguard_active`, `x_edgeguard_retired_by` | Indicators (extension definition 1.7.0): the highest confidence a source gave, what the age counts from (`source_date`, `misp_recorded`, `first_imported`), the tier reached (0 below 90 days, 1 from 90, 2 from 180, 3 from 365), whether it is active, and who retired it (`decay` from 730 days without a report, or a manual decommission) |

The `x_edgeguard_*` properties are top-level extension properties: each object that carries them declares the EdgeGuard `extension-definition` in its `extensions` map (`extension_type: "toplevel-property-extension"`), and the definition object — listing every property name — is included in every bundle. Strict parsers (`stix2.parse` with `allow_custom=False`) accept the bundle without configuration.

**Worked example.** A ThreatFox IP indicator that ThreatFox first reported on 2025-11-03 and last reported on 2026-10-01, first imported by EdgeGuard on 2026-04-21, appears as:

```jsonc
{
  "type": "indicator",
  "valid_from": "2025-11-03T00:00:00Z",          // source-truthful (the earliest first report of its sources)
  "created":    "2026-04-21T08:00:00.000Z",      // EdgeGuard import time
  "modified":   "2026-10-02T06:10:00.000Z",      // latest MISP record of a report or aging change, not the last database write
  "x_edgeguard_first_seen_at_source": "2025-11-03T00:00:00+00:00",
  "x_edgeguard_last_seen_at_source":  "2026-10-01T18:42:00+00:00",
  "x_edgeguard_first_imported_at":    "2026-04-21T08:00:00+00:00",
  "x_edgeguard_last_reported_at":     "2026-10-01T18:42:00+00:00",
  "x_edgeguard_last_reported_source": "threatfox",
  "x_edgeguard_aging_tier": 0,
  "x_edgeguard_active": true
  // x_edgeguard_first_seen_inferred ABSENT — we have a real source claim
}
```

A consumer reading this sees that the source first reported the indicator in 2025 and last reported it on 2026-10-01, and that EdgeGuard first imported it on 2026-04-21.

### 3.3 Sector/zone and TLP

- **`zone`** — `LIST[STRING]` on merged threat-intel nodes (`global`, `healthcare`, `energy`, `finance`, …), populated from classification + MISP→Neo4j resolution (attribute-level `zone:` tags prioritized over event name / legacy event tags). Enables sector-scoped queries. What a sector rests on is on the link to the `Sector` node (§3.2.2): `zone_classification` (EdgeGuard's inference), `otx_industries` (an OTX pulse's own industries, `TARGETS`) or `advisory_sector` (CISA's ICS advisory, `AFFECTS`).
- **TLP** — `MISPWriter` stamps one **`tlp:<level>`** tag on **every attribute** (`_tlp_tag`): the source's own level when it states one (OTX `pulse_tlp`; when several pulses of one collector run list the same entity, the most restrictive of their levels), otherwise `EDGEGUARD_DEFAULT_TLP` (`white` — every current source is an open feed). The MISP→Neo4j sync rehydrates it as **`n.tlp`** on every EdgeGuard node label, keeping the **most restrictive** level a source ever stated for the node (`red` > `amber+strict` > `amber` > `green` > `white`/`clear`), so `WHERE n.tlp IN ['white','clear','green']` is a valid filter. The actor alias merge keeps that rule: the canonical node takes the most restrictive level of the nodes folded into it, and a collapsed relationship the most restrictive `r.tlp` of the relationships it replaces; so does the Malware ATT&CK-id twin merge, which runs the same statements. A campaign and its `RUNS` / `PART_OF_CAMPAIGN` links take the most restrictive `tlp` of the links they rest on (`build_campaign_nodes`, recomputed on every run). An attribute that reaches the sync without a `tlp:` tag (for example after an interrupted push) is given `EDGEGUARD_DEFAULT_TLP`, and the sync logs its UUID (`[TLP]` warning), since its source may have stated a stricter level. At event level, events carry only the `EdgeGuard` tag.

**Historical collection window:** the same for every sector. How far back a baseline reaches is set per source: NVD and OTX by `baseline_days` (default 730 days = 24 months; `BASELINE_DAYS` / `--days`) in the request, CISA ICS by `baseline_days` on the advisories it downloads, CISA KEV and the NVD records of KEV CVEs whatever their age, the other sources by what their API offers ([DATA_SOURCES.md](DATA_SOURCES.md)). No collector filters by sector or on `SECTOR_TIME_RANGES`. `SECTOR_TIME_RANGES` in `config.py` (24 months for every sector) only sets the start date of `run_misp_to_neo4j --sector` (the current time minus 24 months); that option does not filter events by sector.

### 3.4 Node Identity Marking (`edgeguard_managed`, `edgeguard_enriched`)

The marker also bounds EdgeGuard's destructive operations: `edgeguard fresh-baseline` and the `baseline_clean` DAG step delete only `edgeguard_managed` nodes by default (`clear_edgeguard_managed`); deleting every node requires the explicit `--wipe-all` flag / `wipe_scope: "all"`.

Every node EdgeGuard **creates** carries a constant property:

```
edgeguard_managed = true
```

**Shared-database contract:** the marker is stamped on the MERGE *create* path only. When EdgeGuard writes onto a node another system created first — a CRUSOE scanner's `CVE` / `Vulnerability`, ResilMesh topology such as `Host` / `IP` — the node keeps its owner and receives `edgeguard_enriched = true` instead, so both sides can see which partner-owned nodes carry EdgeGuard properties. Consequences:

- `edgeguard clear neo4j --edgeguard-only` deletes nodes with `edgeguard_managed = true` and leaves enriched nodes in place, EdgeGuard's properties on them included.
- The REST / GraphQL APIs and the STIX 2.1 exporter expose nodes EdgeGuard created **or** enriched: `(n.edgeguard_managed = true OR n.edgeguard_enriched = true)`.
- EdgeGuard declares UNIQUE constraints on its own labels (`Indicator`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Campaign`, `Sector`, `Source`, `Alert`) and on the shared vulnerability labels: `CVE.cve_id`, `Vulnerability.cve_id`, and `cve_id` on `CVSSv2` / `CVSSv30` / `CVSSv31` / `CVSSv40`. A partner `Vulnerability` that carries `cve_id` must therefore be one node per CVE; findings without `cve_id` are not constrained. It also constrains `IP.address`, `Host.hostname` and `Subnet.range` (unique in CRUSOE's model too). It does **not** constrain `Device`, `NetworkService`, `SoftwareVersion`, `Application`, `Role` or `User` — DDL on those labels belongs to ResilMesh.
- CVSS de-duplication (run with constraint creation) only touches EdgeGuard-created nodes with a non-null `cve_id`.
- `Alert` nodes and `INVOLVES` edges written by EdgeGuard's alert processor carry the marker like everything else; `Alert.zone` is a list.

The marker is also on **every relationship EdgeGuard writes** (`SOURCED_FROM`, every `build_relationships.py` edge, the batched MISP edges, `HAS_CVSS_*`, `REFERS_TO`, `RUNS`, `PART_OF_CAMPAIGN`) and on the `Campaign` and `Source` nodes. `edgeguard clear neo4j --edgeguard-only` deletes the nodes with `edgeguard_managed = true` and every relationship attached to them, including a relationship a partner drew to such a node. Relationships EdgeGuard wrote between two nodes it did not create are kept, for example `REFERS_TO` between a partner's `Vulnerability` and `CVE`, or `HAS_CVSS_*` between a partner's `CVE` and CVSS node. List them with `MATCH (a)-[r]->(b) WHERE r.edgeguard_managed = true AND coalesce(a.edgeguard_managed, false) <> true AND coalesce(b.edgeguard_managed, false) <> true RETURN type(r), count(r)`. Use this mode on a database shared with ResilMesh, after checking that no partner relationship is attached to an EdgeGuard node: `MATCH (n)-[r]-() WHERE n.edgeguard_managed = true AND coalesce(r.edgeguard_managed, false) <> true RETURN type(r), count(DISTINCT r)`. Relationship *names* EdgeGuard shares with ResilMesh (`REFERS_TO`, `HAS_CVSS_*`; campaign membership is `PART_OF_CAMPAIGN`, so `PART_OF` is ResilMesh's alone) must never be selected by type alone on a shared database; scope by the marker and by EdgeGuard labels.

This follows the same principle as Kubernetes' `app.kubernetes.io/managed-by: helm` label — when multiple systems share the same database, each system marks what it owns. Without this, a consumer querying the shared Neo4j has no reliable way to distinguish EdgeGuard-written nodes from ResilMesh-written nodes of the same label (e.g., both may write `CVE` or `Vulnerability` nodes).

**Why this is a best practice in multi-system shared databases:**
- Label-based filtering (`WHERE n:CVE`) is ambiguous if two systems can write the same label
- Property-based ownership marker is explicit and self-documenting
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

// Partner-created nodes EdgeGuard has written to (shared database)
MATCH (n) WHERE n.edgeguard_enriched = true
RETURN labels(n)[0] AS type, count(*) AS cnt ORDER BY cnt DESC
```

The `source` and `tag` properties provide finer-grained **intelligence-source-level** provenance (which external feed provided the data), while `edgeguard_managed` provides **system-level** ownership (EdgeGuard wrote this).

**Identity and lifecycle notes:**

- `uuid` is deterministic from the natural key, and `CVE` and `Vulnerability` with the same `cve_id` share **one** uuid — look-ups by uuid must be label-scoped (`MATCH (n:CVE {uuid: $u})`, never `MATCH (n {uuid: $u})`).
- **Aging by kind of fact.** What ages depends on the kind of fact, not on who supplied it or who created the node. Every `Indicator` ages by one rule, whichever source reported it and whether EdgeGuard created it (`edgeguard_managed`) or wrote onto a partner's node (`edgeguard_enriched`; no aging statement reads either marker): from the latest report of any source (the source's own last-report date capped at the MISP record time), the confidence falls to ×0.85 / ×0.70 / ×0.55 of the source's from 90 / 180 / 365 days and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days; a newer report reactivates it, a manual decommission is never overridden. `CVE`, the CVSS nodes, `Vulnerability`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Sector`, `Source` and `Alert` never age by time. **Nodes of the labels that do not age keep their own lifecycle:** on those labels EdgeGuard sets `active = true` only when it creates the node, and writes no `active`, `retired_*` or aging property when it matches one. A CASM `CVE` / `CVSSv*` node or an ISIM asset therefore never receives an EdgeGuard lifecycle property. A partner's `Indicator` node that EdgeGuard writes to (a sync record or an alert) is aged like every other indicator (`confidence_score`, `active`, `retired_*`, `aging_*`). EdgeGuard never writes ResilMesh's asset or scan-finding labels (`IP`, `Host`, `SoftwareVersion`, the scanner's `Vulnerability` …), which age on ResilMesh's own clock (rescans moving `start` / `end`, `rediscovered`, finding statuses). See [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging).
- Constraints: EdgeGuard declares UNIQUE keys for its own labels plus `CVE.cve_id`, `Vulnerability.cve_id`, `cve_id` on `CVSSv2` / `CVSSv30` / `CVSSv31` / `CVSSv40`, `IP.address`, `Host.hostname`, `Subnet.range` and `Alert.alert_id`; the full list is in [TECHNICAL_SPEC.md § Constraints](TECHNICAL_SPEC.md#constraints).

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

### 4.4 SoftwareVersion bridge

The ResilMesh schema defines the chain:

```
(CVE)<-[:REFERS_TO]-(Vulnerability)-[:IN]->(SoftwareVersion)-[:ON]->(Host)
```

This chain answers *"Which of our hosts is vulnerable to this CVE?"*, the central query of attack surface management. EdgeGuard writes `CVE` (and `CVSSv*`) nodes only; `Vulnerability`, `SoftwareVersion`, `Host` and the `IN` / `ON` relationships are ResilMesh's scanner data, and EdgeGuard's post-sync job writes `REFERS_TO` for every `Vulnerability` that carries a `cve_id`. For each CVE the NVD collector stores up to ten CPE match strings (`affected_products`), their CPE parts (`cpe_type`) and up to ten version ranges (`version_constraints`); no job maps them to `SoftwareVersion` nodes. What the bridge needs is listed in [ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration).

With ResilMesh's chain in the shared graph, the attack surface query is:
```cypher
MATCH (cve:CVE {cve_id: 'CVE-2021-44228'})  // Log4Shell
     <-[:REFERS_TO]-(:Vulnerability)-[:IN]->(sv:SoftwareVersion)
     -[:ON]->(host:Host)
     <-[:PROVIDED_BY]-(comp:Component)
     <-[:SUPPORTS]-(mission:Mission)
RETURN host.hostname, comp.name, mission.name, mission.criticality
ORDER BY mission.criticality DESC
```
This answers: *"Log4Shell affects which of our hosts, and what missions depend on those hosts?"* It returns rows once ResilMesh has written the `Vulnerability`, `SoftwareVersion`, `Host`, `Component` and `Mission` nodes and their links.

---

## 5. Property Alignment — ResilMesh Schema vs EdgeGuard Output

### CVE Node

| Property | ResilMesh type | EdgeGuard output | Status |
|----------|---------------|------------------|--------|
| `cve_id` | STRING | ✅ `cve_id` | Aligned |
| `description` | STRING | ✅ `description` (NVD's text, at most 1,000 characters, when NVD has a record of the CVE; otherwise the next source in the ranking: CISA KEV's text, at most 500 characters, then CISA ICS's, at most 1,000) | Aligned |
| `description_source` | — | ✅ `description_source`, the source of `description` (`nvd`, `cisa_kev`, `cisa_ics`, …) | EdgeGuard extension |
| `published` | STRING | ✅ `published` (ISO 8601), NVD's date when NVD has a record of the CVE | Aligned |
| `last_modified` | STRING | ✅ `last_modified` (ISO 8601), NVD's date when NVD has a record of the CVE | Aligned |
| `cwe` | LIST OF STRING | ✅ `cwe` (e.g. `["CWE-89"]`) | Aligned |
| `ref_tags` | LIST OF STRING | ✅ `ref_tags` (e.g. `["Vendor Advisory"]`) | Aligned |
| `cpe_type` | LIST OF STRING | ✅ `cpe_type` (e.g. `["a", "o"]`) | Aligned |
| `result_impacts` | LIST OF STRING | ✅ `result_impacts` (CIA values) | Aligned |
| `status` | — (on `Vulnerability`: LIST OF STRING) | ✅ `status` (`["active"]` / `["rejected"]`, NVD's record status) | EdgeGuard extension |
| `attack_vector` | — (on `CVSSv31`: `attack_vector`, on `CVSSv2`: `access_vector`) | ✅ `attack_vector` (`NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL`, null without CVSS) | EdgeGuard extension |

> **`published`, `last_modified`** are set by NVD's record and only filled, where the node has none, by a record from any other source (CISA KEV, CISA ICS, OTX, a STIX import, `merge_resilmesh_cve`); a write without them leaves them in place. Of the other records only CISA ICS gives dates (the advisory's release dates), from one attribute per CVE in MISP. **`description`** follows a fixed source ranking, NVD > CISA KEV > CISA ICS > any other source (inside "any other source" the higher registry reliability, then the source id; an unregistered source such as a STIX import or `merge_resilmesh_cve`, named `resilmesh`, below every registered one), and `description_source` names the source of the text: a record sets it when its source ranks at least as high as the stored text's source, so the same source's revised record replaces its own text and the result does not depend on the order in which the records are merged. Neither a MISP metadata block such as `OTX_META:{...}` nor an OTX pulse reference is ever a description, so a CVE that only OTX and the KEV name shows CISA's KEV text. `merge_resilmesh_cve` keeps `cwe`, `ref_tags`, `cpe_type` and `result_impacts` when a call does not carry them. In the STIX flow of the `run_pipeline.py` CLI (always on in that CLI; the Airflow DAGs do not use it) a `vulnerability` object carries the source of its event, so the description is the one the attribute flow gives; the dates come from the attribute flow only. Every source's own text stays in MISP, reached from the node's `SOURCED_FROM` edges ([RUNBOOK.md § Retrieving raw MISP data from a Neo4j node](RUNBOOK.md#retrieving-raw-misp-data-from-a-neo4j-node)).
>
> **`cwe`, `ref_tags`, `cpe_type` and `result_impacts`** (plus `reference_urls`, `affected_products`) are written on the `CVE` node by `merge_cve` whenever NVD provides them, so a ResilMesh consumer reads them as `c.cwe` and so on, not only inside `SOURCED_FROM.raw_data`. NVD's record sets them and a record from any other source (only CISA ICS gives them: product names, the advisory's URL, CISA's CWE) fills them only where the node has none. The exception is `merge_resilmesh_cve`: a call that carries `cwe`, `ref_tags`, `cpe_type` or `result_impacts` overwrites NVD's lists until NVD's next record. Among the feed records, a CVE NVD describes therefore shows NVD's lists whatever their order.
>
> **CVSS sub-nodes.** NVD and CISA ICS write the same `CVSSv31` / `CVSSv30` node of a CVE. Once NVD has asserted it (`'nvd'` in `sources` of the CVE's `HAS_CVSS_*` edge to it), the node holds NVD's values and a CISA ICS record only fills a property it lacks; the CVE's `cvss_score`, `severity` and `attack_vector` follow. When NVD's record drops that version, a sub-node EdgeGuard created that only NVD asserted is deleted. On a sub-node another feed also asserted, NVD leaves `sources` (and its event's `misp_event_ids`) of both edges, and that feed's next record sets its values again. A partner-created sub-node is never deleted. On a CVE EdgeGuard created whose only source is NVD, NVD's record also replaces `cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls` and `affected_products`, and an empty list removes the property. NVD's record sets or removes the SSVC properties on any CVE. A node only CISA ICS asserted holds CISA's values without `impact_score` and `exploitability_score`, which a CSAF advisory does not give (null through GraphQL).
>
> **`attack_vector`** is the attack vector of the CVSS that gives the CVE's score (`cvss_score`, `cvss_version`: the first CVSS in the order v3.1 → v3.0 → v2 → v4.0), in NVD's words, and null without CVSS. `merge_cve` sets it from the CVSS sub-nodes after every merge (`CVSSv31` / `CVSSv30` `attack_vector`, `CVSSv2` `access_vector`, the `AV` metric of a `CVSSv40` `vector_string`), so the order in which records are merged does not decide it. Each NVD record carries every CVSS version NVD supplies, so a CVE can have a `CVSSv31` and a `CVSSv2` sub-node at once.

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
| `status` | STRING | ⚠️ Written only by the `merge_ip` helper, which no pipeline or alert path calls (§3.1) | Not written |

---

## 6. What ResilMesh Needs to Do for Full Integration

For the complete cross-layer graph traversal to work, ResilMesh must:

1. **Write topology nodes first** — `Host`, `IP`, `Subnet`, `Device`, `Node`, `Component`, `Mission` must exist in the shared Neo4j before EdgeGuard bridge relationships can be created.

2. **Use the keys of the topology nodes** that a link from EdgeGuard's nodes would match on (no such link is written yet, [ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration)):
   - `IP.address` for `INDICATOR_RESOLVES_TO`
   - `Host.hostname` for `(Malware)-[:TARGETS]->(Host)`

3. **Use the same Neo4j instance** — EdgeGuard and ResilMesh must point to the same database for the shared graph to work. Connection is configured via `NEO4J_URI` in `.env`.

4. **Shared labels are safe to write** — ResilMesh's scanner may create `CVE` and `Vulnerability` nodes, as its model does: EdgeGuard MERGEs on `cve_id`, enriches the existing node (`edgeguard_enriched = true`) and never deletes a node it did not create. `Vulnerability`, `REFERS_TO`, `IN` and `ON` are ResilMesh's to write (key `REFERS_TO` on `cve_id`, EdgeGuard's property name; EdgeGuard's UNIQUE constraint on `Vulnerability.cve_id` allows one `Vulnerability` per `cve_id`, §3.4). `Indicator`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Campaign`, `Sector` and `Source` are EdgeGuard's vocabulary — a partner node under those labels is enriched, not claimed, but its properties are not guaranteed to follow EdgeGuard's conventions.

---

## 7. Downstream ResilMesh Services that Consume EdgeGuard Data

The ResilMesh platform exposes several services that directly consume or benefit from EdgeGuard's enriched graph. These are not integration requirements but are useful to understand as the deployment matures.

| Service | Port | How EdgeGuard feeds it |
|---------|------|------------------------|
| **PPCTI Frontend** (Privacy-Preserving CTI) | 3100 | EdgeGuard is the primary intelligence source. The PPCTI UI visualises threat intel from the shared Neo4j. |
| **IOB STIX** (Indicator of Behavior) | 3400 | Processes STIX-format IoB produced inside ResilMesh; it does not ingest bundles from outside producers. EdgeGuard's outward STIX surface is `GET /stix/export/{object_type}/{identifier}` ([RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md)), for consumers that pull STIX. |
| **THF** (Threat Hunting Framework) | 8030 / 8501 | Threat hunting assisted by a large language model. EdgeGuard's enriched graph — ThreatActors linked to Techniques, Indicators linked to CVEs — is the ideal context injection for THF queries. |
| **Shuffle** (SOAR) | 3443 | Playbook automation. High-confidence, critical-sector indicators from EdgeGuard can trigger automated response playbooks. |
| **Wazuh SIEM** | 4433 | Two directions: (1) **EdgeGuard exports CTI to Wazuh** — `GET /export/wazuh/cdb` serves sector-specific IOC/CVE intelligence as Wazuh CDB lists (`key:value` lines, active entries only, `list=indicators\|cves`, zone/type/confidence filters) for use in Wazuh rules via `<list lookup="match_key">`; url/ipv6 keys are skipped (CDB keys cannot contain `:`) — match those via the enrichment path instead. A list holds at most 50,000 entries. Indicators with the latest report come first (`coalesce(last_reported_at, first_imported_at)`); CVEs are ordered by their last write (`last_updated`), newest first. `X-EdgeGuard-Truncated: true` says the list was cut. (2) Wazuh detects events; EdgeGuard enriches them with CVE/IoC context via the NATS alert bridge (later phase). |

### Deployment note — Port Allocation & Intentional Separation

EdgeGuard runs on its **own dedicated edge server**, not on the ResilMesh host. The two systems share only the **Neo4j database** (via the Bolt port, 7687) and the **NATS message bus**. All other EdgeGuard services are network-isolated.

Despite running on separate hardware, we intentionally choose ports that do not collide with any known ResilMesh service port. This is a defensive practice: if future deployments co-locate EdgeGuard closer to the ResilMesh stack, or if a developer runs both on the same machine for testing, there are no silent bind conflicts.

| EdgeGuard Service | Our Port | Rationale |
|---|---|---|
| REST Query API | **8000** | Standard FastAPI default; no ResilMesh service uses it |
| GraphQL API | **4001** | Mirrors the ISIM GraphQL port — intentional alignment so ResilMesh can treat EdgeGuard as an additional ISIM-compatible data source. On EdgeGuard's own host; when co-located with iSIM, change `EDGEGUARD_GRAPHQL_PORT` |
| Airflow API server (UI) | **8082** | Default (8080) collides with ResilMesh **Temporal**; explicitly overridden via `AIRFLOW__API__PORT=8082` (with `AIRFLOW__API__BASE_URL=http://localhost:8082`). The legacy `AIRFLOW__WEBSERVER__WEB_SERVER_PORT`, which docker-compose also sets, has no effect on Airflow 3. |
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

## 8. Authorization — Who Can Access EdgeGuard Data

Neo4j authenticates every client, and every client uses the same Neo4j user. This section describes the access paths and their protection; role separation and the ISIM schema extension are planned work ([ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration)).

### 8.1 Current State

Neo4j is protected by username/password authentication (`NEO4J_USER` / `NEO4J_PASSWORD` from `.env`). Docker Compose publishes the Bolt port (7687) on host loopback (127.0.0.1) only; a client on another host needs a network path that the deployment provides.

However, **there is currently no role separation**. Any service with the Neo4j credentials has full read *and* write access to the shared database. EdgeGuard, on its own edge server (§7), and ResilMesh use the same database user.

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

**EdgeGuard GraphQL** (`src/graphql_api.py`, Strawberry + FastAPI) also listens on **4001** by default (`EDGEGUARD_GRAPHQL_PORT`). **Auth:** when `EDGEGUARD_API_KEY` is set in the environment, requests must include header **`X-Api-Key`**. **GraphiQL** is off unless `EDGEGUARD_GRAPHQL_PLAYGROUND=true`. **Rate limiting:** **120 requests/minute** per client address by default (`slowapi`), set with `EDGEGUARD_RATE_LIMIT_GRAPHQL` (for example `600/minute`); behind a reverse proxy every client shares the proxy's address and so one limit, so raise it before an integration. **Health:** `GET /health` — **HTTP 200** only when Neo4j is healthy (ping + APOC); **503** otherwise. (The REST API on port 8000 answers the same way: **200** while healthy, **503** while degraded, with `status` and `neo4j_connected` in the JSON body — see [TECHNICAL_SPEC.md § API Endpoints](TECHNICAL_SPEC.md#api-endpoints).)

**Shape of EdgeGuard's GraphQL:** field names are camelCase (Strawberry's default — `cveId`, `cvssV31`, `lastUpdated`), the schema is flat apart from a CVE's CVSS sub-objects (`cvssV40`, `cvssV31`, `cvssV30`, `cvssV2`, read through `HAS_CVSS_*`): node types have scalar and list fields and no other relationship-traversal fields yet, and no SDL file is committed; introspection is disabled in prod. The ISIM examples in this section are snake_case with traversal. "ISIM-compatible" today means the **data model** matches (labels, keys, property names) — not that the two GraphQL schemas are interchangeable. Aligning case and traversal needs ISIM's real SDL ([ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration)). `Indicator` carries MISP back-links: `mispEventUrls` (the whole source event) and `mispAttributeUrls` (`<MISP_URL>/attributes/view/<uuid>`, the one MISP attribute behind the indicator; a client with a MISP key receives it as JSON). Every node type carries `tlp` (the node's TLP level, §3.3; null when it has none), and `vulnerabilities` lists the `CVE` nodes EdgeGuard created or enriched.

**SOC-analyst REST endpoints (port 8000):** `GET /actors/{name}/summary` resolves a threat actor by canonical name **or alias** (case-insensitive; `resolved_by` reports which) and returns an aggregated profile — attributed malware, the malware the actor uses (`malware_used`, `USES_MALWARE`; a campaign rests on either link, so a campaign of an actor with only `USES_MALWARE` links names its malware there), employed techniques, campaigns, with counts — backing analyst "tell me about this actor" queries. Analyst-supplied IOC/CVE/technique inputs at the REST and GraphQL boundaries are refanged + canonicalized to graph form via `src/ioc_normalize.py` (write-side parity), so defanged paste (`1.2.3[.]4`, `hxxp://`), uppercase hashes, and en-dash CVE ids resolve to the stored nodes.

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

**Vulnerability + CVE query via ISIM GraphQL** (EdgeGuard's `CVE` data is queryable here through the `Vulnerability` nodes ResilMesh writes):
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

> The ISIM GraphQL schema includes `CVE`, `Vulnerability`, `CVSSv31`, `CVSSv2`, `CVSSv30`, `CVSSv40`, `SoftwareVersion`, `Host`, `IP`, `Subnet` and all topology types. EdgeGuard's `CVE` nodes are written in full compliance with this schema and are queryable via ISIM GraphQL as-is. The scheduled pipeline writes no `Vulnerability` nodes (§3.1): the `vulnerabilities` query above returns the `Vulnerability` nodes ResilMesh writes (the scanner's findings) with the `CVE` each one refers to (EdgeGuard's node where EdgeGuard holds that CVE id).

### 8.3 ISIM GraphQL Schema Coverage for EdgeGuard Data

| EdgeGuard node type | In ISIM GraphQL schema | Queryable via iSIM? |
|---|---|---|
| `CVE` | ✅ Yes — `type CVE` with full CVSS relationships | ✅ Yes |
| `Vulnerability` | ✅ Yes — `type Vulnerability` with `→CVE`, `→SoftwareVersion` | ✅ Yes, the nodes ResilMesh writes; the scheduled pipeline writes none (§3.1) |
| `CVSSv31` / `CVSSv30` / `CVSSv2` / `CVSSv40` | ✅ Yes — full property coverage | ✅ Yes (when NVD/MISP→Neo4j supplies metrics) |
| `Indicator` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `ThreatActor` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Malware` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Technique` / `Tactic` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |
| `Campaign` | ❌ Not in ISIM schema | ❌ Not via ISIM GraphQL |

**Impact:** EdgeGuard's MITRE ATT&CK and threat actor data cannot currently be queried through ISIM GraphQL. Querying those types requires EdgeGuard's own GraphQL or REST API, direct Neo4j Bolt access, or an extension to the ISIM schema (§ 8.4, § 8.5).

### 8.4 ISIM Schema Extension — EdgeGuard Threat Intelligence Types

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
  first_imported_at: String
  last_updated: String
  edgeguard_managed: Boolean
  cves: [CVE!]! @relationship(type: "EXPLOITS", direction: OUT)
  # CVEs named in the same OTX report as the indicator (INDICATES to a CVE node, match_type otx_pulse)
  same_report_cves: [CVE!]! @relationship(type: "INDICATES", direction: OUT)
  malware: [Malware!]! @relationship(type: "INDICATES", direction: OUT)
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

ISIM's schema is `isim_graphql/src/schema.graphql` in [resilmesh2/ISIM](https://github.com/resilmesh2/ISIM). The extension is planned work agreed with ResilMesh ([ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration)).

### 8.5 Access paths

| Path | Data | Protection |
|---|---|---|
| ISIM GraphQL | CVE and Vulnerability | No direct database access |
| EdgeGuard GraphQL and REST | Every EdgeGuard type | API key, rate limits |
| Direct Neo4j Bolt | The whole graph | One shared user, read and write |

- **ISIM GraphQL** is ResilMesh's interface and the preferred one for CVE and `Vulnerability` data, whose schema EdgeGuard follows (§ 8.2, § 8.3).
- **EdgeGuard's GraphQL (4001) and REST (8000) APIs** serve the threat-intelligence types in EdgeGuard's own schema, with the `X-API-Key` header; Docker Compose publishes them on host loopback, so access from another host goes through a TLS reverse proxy the deployment provides.
- **Direct Bolt** gives full read and write access with the shared `NEO4J_USER`; the Community edition that `docker-compose.yml` runs has no role-based access control.

### 8.6 Planned work

The ISIM schema extension, Neo4j role separation, the NATS response to an enriched alert and the links to the topology layer are listed in [ROADMAP.md § ResilMesh integration](ROADMAP.md#resilmesh-integration).

---

## 9. CVSS sub-nodes (v4.0 / v3.1 / v3.0 / v2)

EdgeGuard creates `CVSSv40`, `CVSSv31`, `CVSSv30` and `CVSSv2` nodes from NVD metrics when present (`nvd_collector.py`), and `CVSSv31` / `CVSSv30` nodes from CISA ICS advisories (`cisa_ics_collector.py`; where both assert a node, NVD's values hold, §5). It persists them in MISP via `NVD_META` (`misp_writer.py`), and merges them in Neo4j via `Neo4jClient.merge_cve()` → `_merge_cvss_node()`. CVSS v4.0 appears only for a subset of CVEs in NVD. **Node score:** after every merge, `merge_cve` sets the `CVE` node's `cvss_score`, `severity`, `cvss_version` and `attack_vector` from its first CVSS sub-node in the order v3.1 → v3.0 → v2 → v4.0 (`src/cvss_selection.py`), so the result does not depend on which source's record was merged last; a CVE without any CVSS sub-node has a null score and severity `UNKNOWN`. No score is derived from a `cvss:` tag, a 0.0 placeholder, CISA KEV ransomware use or a collector default. Both `HAS_CVSS_*` edges name the source that delivered the score (`r.sources`) and the MISP event (`r.misp_event_ids`).

---

## 10. Example: End-to-End Query Across Both Layers

### 10.1 Via ISIM GraphQL — once ResilMesh has written `Vulnerability` / `SoftwareVersion` (CVE + topology layer)

EdgeGuard supplies the `CVE` + `CVSSv*` half of this query; the `Vulnerability → SoftwareVersion → Host` half is ResilMesh's scanner data (0 `Vulnerability` nodes live on 2026-10-11, so the query returns nothing yet):

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

This query is supported by the shared model — it traverses `Vulnerability → CVE → CVSSv31` (EdgeGuard data) and `Vulnerability → SoftwareVersion → Host → Component → Mission` (ResilMesh topology data). The SoftwareVersion bridge (section 4.4) must be implemented first for the full chain.

### 10.2 Via Direct Neo4j Bolt — full threat intelligence (pending ISIM schema extension)

Once the ISIM GraphQL schema is extended (or via direct Bolt access), this query links a detected IP through EdgeGuard's full threat intelligence graph:

```cypher
// Starting from a ResilMesh IP under scrutiny → trace to CVE → malware → ATT&CK techniques
MATCH (ip:IP {address: '203.0.113.42'})
OPTIONAL MATCH (ind:Indicator)-[:INDICATOR_RESOLVES_TO]->(ip)   // planned EdgeGuard bridge
OPTIONAL MATCH (ind)-[:EXPLOITS]->(cve:CVE)
OPTIONAL MATCH (ind)-[rc:INDICATES]->(rcve:CVE) WHERE rc.match_type = 'otx_pulse'
OPTIONAL MATCH (ind)-[:INDICATES]->(m:Malware)-[:ATTRIBUTED_TO]->(ta:ThreatActor)
OPTIONAL MATCH (ta)-[:EMPLOYS_TECHNIQUE]->(tech:Technique)-[:IN_TACTIC]->(tactic:Tactic)
OPTIONAL MATCH (ip)<-[:HAS_ASSIGNED]-(n:Node)-[:IS_A]->(h:Host)
RETURN
  ip.address                      AS ip,
  ind.value                       AS indicator,
  cve.cve_id                      AS exploited_cve,
  cve.cvss_score                  AS cvss_score,
  cve.severity                    AS severity,
  collect(DISTINCT rcve.cve_id)   AS cves_named_in_the_same_otx_report,
  m.name                          AS malware,
  ta.name                         AS threat_actor,
  collect(DISTINCT tech.mitre_id) AS techniques,
  h.hostname                      AS targeted_host
```

The EdgeGuard hops follow the relationships the pipeline writes: an indicator `INDICATES` a `CVE` named in the same OTX
report (`match_type` `otx_pulse`; returned in `cves_named_in_the_same_otx_report`, never as exploited) and `INDICATES` a
malware, and the malware is `ATTRIBUTED_TO` an actor. `EXPLOITS` from an indicator comes only from the indicator's own CVE
tag (and reaches the `Vulnerability` of that id, where one exists), which no collector writes, so `exploited_cve` and its
score are null on a graph the collectors built. The score and severity are the `CVE` node's own (§9: from its first CVSS,
null / `UNKNOWN` without one).

> The planned bridge is named `INDICATOR_RESOLVES_TO`, not `RESOLVES_TO`, to avoid a semantic collision with ISIM's `(IP)-[:RESOLVES_TO]->(DomainName)` relationship.

### 10.3 Via Direct Neo4j Bolt — from a host's vulnerable software to the indicators of the CVE's reports

ResilMesh writes `Host ← ON ← SoftwareVersion ← IN ← Vulnerability → REFERS_TO → CVE`; EdgeGuard links the `CVE` to the
indicators an OTX report names with it (`INDICATES`, `otx_pulse`). The query returns, per host and CVE, the active
indicators to look for in the host's traffic and the reports that name them (it returns rows once ResilMesh has written
`Vulnerability` and `SoftwareVersion` nodes):

```cypher
MATCH (h:Host)<-[:ON]-(:SoftwareVersion)<-[:IN]-(:Vulnerability)-[:REFERS_TO]->(c:CVE)
MATCH (c)<-[r:INDICATES]-(ind:Indicator)
WHERE r.match_type = 'otx_pulse' AND ind.active = true
RETURN h.hostname AS host, c.cve_id AS cve,
       collect(DISTINCT ind.value)[..20] AS indicators,
       apoc.coll.toSet(apoc.coll.flatten(collect(r.source_refs))) AS reports
```

`INDICATES` here means only that one report names the indicator and the CVE; an indicator's own claim to exploit the CVE is
`EXPLOITS` (`cve_tag`), which no collector writes today.

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
| [`docs/BASELINE_LAUNCH_CHECKLIST.md`](BASELINE_LAUNCH_CHECKLIST.md) | The six-item pre-launch operator pass that must be walked through before triggering a 730d baseline (preflight, smoke, Alertmanager wiring, MISP scale, RAM/disk, fresh-baseline deploy and re-feed) |
| [`docs/RUNBOOK.md`](RUNBOOK.md) § 8 | Operator triage tree for `_MispFallbackHardError` (the fallback's 4 hard-failure modes: errors-payload, unexpected-shape, non-200 and cap-hit; and a failed or incomplete primary event listing) |

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The STIX flow of the `run_pipeline.py` CLI is always on there (the page called it opt-in); the health reference points to TECHNICAL_SPEC.md, which replaced the README's health table; the planned SoftwareVersion bridge (§ 4.4), the access-control options (§ 8.5) and the to-do list (§ 8.6) give way to the current state and a pointer to ROADMAP.md, which lists the planned work, with the topology links of § 3.2; § 8.1 states the loopback publication of the Bolt port (it named a hosted firewall rule the repository does not hold).
- 2026-10-22 — The STIX coverage paragraph is written for any registered curated source.
- 2026-10-21 — A campaign and its `RUNS` / `PART_OF_CAMPAIGN` links carry the most restrictive TLP of the links they rest on (`build_campaign_nodes`): a campaign built on a curated-package claim was exported at the deployment default (TLP:WHITE) while its links named the package's source, claim ids and MISP event.
- 2026-10-19 — `USES_TECHNIQUE` (Indicator → Technique) is described as what it is: the OTX report the indicator came from lists the technique, not an observation that the indicator executed it.
- 2026-10-18 — `INDICATES` from an `Indicator` to a `CVE` named in the same OTX pulse (`otx_pulse`, 0.6), exported to STIX as `related-to`; the §10.2 query returns those CVEs in a column of their own (it followed only `EXPLOITS`, which no collector writes), and §10.3 joins a host's vulnerable software to the indicators of the CVE's reports.
- 2026-10-18 — The GraphQL rate limit is a setting (`EDGEGUARD_RATE_LIMIT_GRAPHQL`, default 120/minute); a reverse proxy makes every client share one limit.
- 2026-10-18 — `otx_industries` (0.6, `TARGETS` only): an OTX pulse's own industries state the sectors its campaign targets (they were `zone_classification`).
- 2026-10-18 — `ThreatActor.name`: no country or state names; an OTX adversary the same pulse lists as a malware family only when the canonical threat-actor reference knows the actor.
- 2026-10-18 — `otx_attack_ids` (`USES_TECHNIQUE` from an OTX pulse's ATT&CK ids, Q8) is 0.6, the confidence of `otx_pulse` from the same ids (it was 0.85).
- 2026-10-18 — STIX bundle coverage: times from the graph (byte-identical re-exports); an indicator no longer carries `x_edgeguard_last_updated`. § 7: IOB STIX does not ingest bundles from outside producers; EdgeGuard's outward STIX surface is `GET /stix/export` (the table had pointed to the `run_pipeline.py` file export, since removed).
- 2026-10-18 — The launch checklist row counts six items: its unicode-bypass audit item was removed.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-18 — §8.2 and §8.3: EdgeGuard's `CVE` nodes are queryable through ISIM GraphQL; the `Vulnerability` nodes there are ResilMesh's, since the scheduled pipeline writes none (§3.1).
- 2026-10-17 — Rewritten as a guide to current behaviour, with history and kept-graph procedures at the end, and checked against the code: `Vulnerability` and `MAPS_TO` are not EdgeGuard output, `Technique.is_subtechnique` is true for a dotted id (every sync wrote false before), `--edgeguard-only` keeps EdgeGuard relationships between partner nodes, UNIQUE constraints cover the shared vulnerability labels, and the `misp_attribute_tag` row names the tags the sync reads.
- 2026-10-16 — Sector links name only the feeds whose `SOURCED_FROM.zones` give the sector (they named every feed of the node: on that day's graph 2,639 of 6,506 `AFFECTS` links named a feed that never gave their sector), and a sector CISA's ICS advisory states is `advisory_sector` at 0.9 on `AFFECTS` only.
- 2026-10-16 — Every indicator ages by one rule, from the latest report of any source (STIX extension definition 1.7.0), and its STIX `modified` follows its reports and aging instead of the last database write.
- 2026-10-16 — Descriptions follow a fixed source ranking named in `description_source` (extension definition 1.6.0); before, the record merged last set a `Technique` description and a CVE without an NVD record kept the first record's text.
- 2026-10-16 — NVD's record sets a CVE's list properties and the CVSS sub-nodes it asserts and CISA ICS only fills them; before, the record merged last set the whole sub-node and CISA ICS wrote 0.0 sub-scores.
- 2026-10-16 — Campaigns rest on `ATTRIBUTED_TO` or `USES_MALWARE`, name that evidence in `r.evidence_types` (extension definition 1.5.0) and are deleted with their links when it is gone (they retired before; the graph of 2026-10-11 held 202 campaigns, built from `ATTRIBUTED_TO` only); campaign provenance is sorted and keeps the 200 newest MISP event ids.
- 2026-10-16 — A `malware_family` `INDICATES` link names OTX only when a pulse names the family; the actor summary returns `malware_used`; the §10.2 sample query follows the relationships the pipeline writes (it read `INDICATES` to a `Vulnerability` and `ATTRIBUTED_TO` from the indicator, which nothing writes).
- 2026-10-15 — A CVE's `description`, `published` and `last_modified` come from NVD's record and other sources only fill them (the record merged last set them: an OTX pulse's raw `OTX_META:{...}` JSON or "Referenced in OTX pulse: <name>", CISA's short KEV description, an ICS advisory's dates); `ThreatActor`, `Malware`, `Tool` and `Tactic` descriptions are ATT&CK's text.
- 2026-10-15 — `CVE.attack_vector` comes from the CVSS that gives the score and NVD records carry every CVSS version; NVD's record status is exported as `x_edgeguard_status` (extension definition 1.2.0; a rejected CVE exported like an active one before).
- 2026-10-15 — `ATTRIBUTED_TO` from an OTX pulse only when its actors are one actor; Malware named without the ATT&CK software id suffix, with a twin merge; the actor alias and Malware twin merges, and an entity several pulses of one run list, take the most restrictive TLP.
- 2026-10-15 — FIRST EPSS and CISA SSVC on `CVE` (extension definition 1.4.0), explainability properties (1.3.0) and the `campaign_grouping` label; REST `/health` answers 503 while degraded (the note said HTTP 200 in every state); GraphQL `tlp` on every node type and `vulnerabilities` reads `CVE` (it read `Vulnerability` and returned an empty list); the Wazuh CDB list keeps the newest 50,000 entries.
- 2026-10-15 — Same-pulse links name the pulse in `r.source_refs[]` (`r.report_ids[]` dropped), sync-written sector links name the node's own source (no `source_id='misp'`), curated-package claims documented, and the CVE node score comes from its CVSS sub-nodes only.
- 2026-10-15 — The NVD/OTX sector time-range filter removed (it compared zone-less source timestamps with a timezone-aware cutoff and had not dropped a record since v2026.3.28).
- 2026-10-14 — Relationship provenance (`sources[]`, `source_refs[]`, `misp_event_ids[]`) on every edge.
- 2026-10-14 — Campaign membership as `PART_OF_CAMPAIGN`; KEV CVEs collected whatever their age.
- 2026-10-11 — Shared-database contract: `edgeguard_managed` on create only, `edgeguard_enriched` on partner nodes EdgeGuard writes to, no UNIQUE constraints on partner labels; every section restated as what is written, exported and queryable.
- 2026-10-10 — Relationships come only from items of the same source report, with an evidence label (`match_type`) and confidence, instead of whole-MISP-event co-occurrence (which had attributed one malware to up to 152 actors and made 96% of all `INDICATES` on the 2026-09 baseline); OTX pulse-level ATT&CK ids are `reported_techniques`; the ResilMesh CVE list properties are on the `CVE` node (on the 2026-09 baseline 0 of 139,410 CVE nodes carried `cwe`); `edgeguard_managed` on every edge and on `Campaign` / `Source`; `tlp:<level>` on every MISP attribute.
- 2026-10-10 — `SUBTECHNIQUE_OF`, `USES_MALWARE` and `USES_TOOL`; actor and malware `TARGETS`.
- 2026-10 — Sector link confidence 0.5 (Q7 wrote 1.0).
- 2026-06-12 — Wazuh integration phase 1: `GET /export/wazuh/cdb` serves sector IOC/CVE intelligence as Wazuh CDB lists (export lists first, by team decision of 2026-06).
- 2026-06-11 — SOC-analyst endpoint `GET /actors/{name}/summary` with alias-aware actor resolution, and read-side IOC/CVE input normalization (`src/ioc_normalize.py`).
- 2026-04-26 — `INDICATES`, `EXPLOITS`, `TARGETS` and `AFFECTS` documented with edge-level `r.misp_event_ids[]`.
- 2026-04-24 — Names padded with zero-width, bidi-control or variation-selector characters rejected as placeholders.
- 2026-04-18 — Aligned with the source-truthful timestamp model.
- 2026-04 — The generic `USES` to `Technique` split into `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE` (`USES_TECHNIQUE` kept) for clearer queries and GraphRAG retrieval; the `USES` compatibility shim and the `[:EMPLOYS_TECHNIQUE|USES]` alternation of the alert query removed.
