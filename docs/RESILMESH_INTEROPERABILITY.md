# EdgeGuard ↔ ResilMesh Interoperability Guide

**Last updated: 2026-10-16** — §3.1 `CVSSv31` row, §5 notes under "CVE Node": NVD's record sets a CVE's `cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls` and `affected_products` and any other record only fills them; a CVSS sub-node NVD has asserted holds NVD's values (a CISA ICS record only fills a property it lacks), in either order; a node only CISA ICS asserted has no `impact_score` / `exploitability_score` (it had 0.0). Same day: §3.2 `INDICATES` row: a `malware_family` link names ThreatFox, MalwareBazaar and Feodo Tracker in `r.sources[]`, no longer OTX, whose records carry no family label (OTX is named when a pulse that listed the indicator names the family by the malware's name or a name folded into it). Same day: sector evidence (§3.2 `TARGETS` / `AFFECTS` rows, the `SOURCED_FROM` row, §3.2.2): a link to a `Sector` names only the feeds whose `SOURCED_FROM.zones` give its sector (`zones[]` / `stated_zones[]` / `stated_refs[]` on every `SOURCED_FROM` edge); a sector CISA's ICS advisory states is `advisory_sector` at 0.9 on `AFFECTS` only ("the product is deployed in this sector", never `TARGETS`), with the advisories whose sector note names that sector in `r.source_refs` (not every advisory of the CVE); `zone_classification` no longer lists the CISA sector; the confidence of a sector link follows its label. Same day: the `Indicator` row names `aging_evaluated_at`, the time at which the aging values were last written. Same day: the `Indicator` row names `last_reported_basis` (the kind of date of the latest report, from which `aging_basis` is derived). Same day: §8: the actor summary returns the malware the actor uses (`malware_used`); §3.2.2 `campaign_grouping`: the provenance lists of a campaign link are sorted and its `misp_event_ids` are the 200 newest by MISP event id, independent of the order its links were created in; §3.2.x `modified` of an indicator on a graph kept through the aging rollout: re-ingest the full bundle once. Same day: aging by kind of fact (§3.4 lifecycle note, the `Indicator` and `SOURCED_FROM` rows, §3.2.x `modified` and the `x_edgeguard_*` aging properties of extension definition 1.7.0): every Indicator ages by one rule whoever supplied it or created it, from the latest report of any source; no other label ages; partner nodes keep their own lifecycle and get no EdgeGuard lifecycle property. Same day: descriptions follow a fixed source ranking with `description_source` (§3.1 `CVE`, `ThreatActor`, `Malware`, `Technique`, `Tactic`, `Tool` rows; §5 `description`, `description_source` and the note on `description`, `published`, `last_modified`): CVE NVD > CISA KEV > CISA ICS > any other source, the other labels MITRE ATT&CK > a curated source > any other source; a description written before counts as the top source's; the dates stay NVD's (others fill); STIX `x_edgeguard_description_source` (extension definition 1.6.0). Same day: campaigns rest on `ATTRIBUTED_TO` or `USES_MALWARE` (§3.1 `Campaign`, the `USES_MALWARE`, `RUNS` and `PART_OF_CAMPAIGN` rows, `campaign_grouping` in §3.2.2): either link gives the actor a campaign and makes the malware a member, campaign links name the relationship types they rest on (`r.evidence_types`; `x_edgeguard_evidence_types` on their SROs, extension definition 1.5.0), and a campaign without evidence is deleted with its links. Same day: §10.2: the sample query follows the relationships the pipeline writes (`(Indicator)-[:EXPLOITS]->(CVE)`, `(Indicator)-[:INDICATES]->(Malware)-[:ATTRIBUTED_TO]->(ThreatActor)`; it read `INDICATES` to a `Vulnerability` and `ATTRIBUTED_TO` from the indicator, which nothing writes) and returns the `CVE` node's score and severity. Prior: 2026-10-15 — §3.1: `Tactic` carries `description`, ATT&CK's text. Same day: §3.1: `ThreatActor`, `Malware` and `Tool` `description` is ATT&CK's text, set by MITRE's record and only filled by any other source; none on an entity only OTX names. Same day: TLP: an entity several OTX pulses of one collector run list is pushed with the most restrictive of their levels. Same day: `ATTRIBUTED_TO` from an OTX pulse only when the pulse's actors are one actor (§3.2, §3.2.2); campaign membership and the provenance of campaign links follow attribution. Same day: §3.1 `Malware`: named without an ATT&CK software id suffix (`"Cobalt Strike - S0154"` → `cobalt strike`), `merged_from[]` from the Malware twin merge; §3.3: the twin merge keeps the most restrictive TLP. Same day: §3.1 and §5: an OTX pulse reference is never a CVE description; §5: a CVE without an NVD record keeps the first record's values against later revisions, `merge_resilmesh_cve` keeps the lists a call omits, the STIX flow only fills. Same day: §3.1 and §5: `CVE.description`, `published` and `last_modified` from NVD's record, only filled by any other source; a MISP metadata block is never a description. Same day: §8.2: the REST `/health` answers 503 while degraded (the note documented HTTP 200 in every state); EdgeGuard GraphQL carries `tlp` on every node type and `vulnerabilities` reads the `CVE` nodes; §7 Wazuh row: the CDB list keeps the newest 50,000 entries and reports a cut list in `X-EdgeGuard-Truncated`. Same day: §3.3: the actor alias merge keeps the most restrictive TLP. Same day: FIRST EPSS and CISA's SSVC decision points on `CVE` (§3.1) and on the STIX `vulnerability` (extension definition 1.4.0). Same day: campaign links state their evidence, `campaign_grouping` (§3.2.2). Same day: explainability: `x_edgeguard_cited_ids` on SROs and `x_edgeguard_merged_from` on intrusion-sets (STIX extension definition 1.3.0). Same day: `CVE.attack_vector` from the CVSS that gives the score, in NVD's words, null without CVSS (§5); NVD records carry every CVSS version; STIX `x_edgeguard_status` (§3.2); §3.2: same-pulse `ATTRIBUTED_TO` / `INDICATES` name the pulse in `r.source_refs[]` (the dropped `r.report_ids[]` no longer exists), sync-written `TARGETS` / `AFFECTS` name the node's own source in `r.sources` (no `source_id='misp'`), curated-package claims on the technique and `USES_MALWARE` / `USES_TOOL` rows, per-source `misp_event_ids[]` / `source_refs[]` on `SOURCED_FROM`; §3.1 CVE score, `status` and KEV properties; §3.3 default TLP for an untagged attribute; §9 the CVE node score rule; §7 THF described without naming its model vendor. Prior: 2026-10-14 — relationship provenance on every edge (`sources[]`, `source_refs[]`, `misp_event_ids[]`, §3.2.2). Prior: 2026-10-11 — shared-database contract (PR #147: `edgeguard_managed` on create only, `edgeguard_enriched` on partner nodes EdgeGuard writes to, no UNIQUE constraints on partner labels) and the documentation review that followed the 2026-10-10 readiness check — §3.1, §3.2, §3.4, §4.4, §6, §8.2 and §10.1 now state what is written, exported and queryable today. Prior (2026-10-10) — fresh-baseline PR (ResilMesh conformance check of 2026-10-09): relationships are no longer derived from whole-MISP-event co-occurrence — only items from the same source report (OTX pulse) are linked, under the same relationship names, with an explicit evidence label (`match_type`) and confidence (§3.2.2); OTX pulse-level ATT&CK ids are `reported_techniques` (`match_type = "otx_pulse"`), never `mitre_explicit`; the four ResilMesh CVE list properties are on the `CVE` node (§5); every EdgeGuard edge and the Campaign/Source nodes carry `edgeguard_managed` (§3.4); `tlp:<level>` on every MISP attribute → `n.tlp` (§3.3). Prior: 2026-06-12 — Wazuh integration phase 1: documented `GET /export/wazuh/cdb` (sector IOC/CVE intelligence as Wazuh CDB lists — export-lists-first per the 2026-06 team decision). Prior: 2026-06-11 — PR #126: documented the SOC-analyst REST endpoint `GET /actors/{name}/summary` (alias-aware actor resolution) and the read-side IOC/CVE input normalization layer (`src/ioc_normalize.py`). Prior: 2026-04-26 PR-N33 docs audit: explicitly noted that the 4 PR-N26 edge types (`INDICATES`, `EXPLOITS`, `TARGETS`, `AFFECTS`) carry `r.misp_event_ids[]` for edge-level provenance (not just node-level). Prior: 2026-04-18 PR #41 cleanup pass.
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
| `Indicator` | `value`, `indicator_type`, `zone[]`, `confidence_score`, `first_imported_at` (DB-local; the source's own claim lives on `SOURCED_FROM.source_reported_first_at`), `last_updated`, `misp_event_ids[]`, `misp_attribute_ids[]`, `pulse_id` (OTX report), `attack_ids[]` (pulse-level), `tlp` (2026-10), **`uuid`** (deterministic, equal to the UUID portion of the STIX SDO id); the aging (2026-10-16, §3.4): `last_reported_at`, `last_reported_source`, `last_reported_ref` (MISP attribute uuid), `last_reported_basis` (`source_date` / `misp_recorded`: the kind of date of the latest report; `aging_basis` is derived from it), `last_recorded_at`, `source_confidence`, `aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `aging_evaluated_at` (the time at which the aging values were last written: by a write, or by a job run that changed them; a job run that changes nothing leaves it unchanged), `active`, `retired_at`, `retired_by`, … | OTX, ThreatFox, URLhaus, AbuseIPDB, VirusTotal, Feodo, SSLBlacklist |
| `Vulnerability` | `cve_id`, `severity`, `cvss_score`, `attack_vector`, `zone[]`, `published`, `last_modified` | **Not written by the scheduled pipeline** (0 live, 2026-10-11): NVD data lands as `CVE` + `CVSSv*` via `merge_cve`; `merge_vulnerabilities_batch` only serves MISP `vulnerability` objects. In CRUSOE's model `Vulnerability` is the scanner's finding — see §6. |
| `CVE` | `cve_id`, `description` (2026-10-16: the text of the highest-ranked source, NVD > CISA KEV > CISA ICS > any other source, named in the EdgeGuard extension `description_source`; neither a MISP metadata block such as `OTX_META:{...}` nor an OTX pulse reference is ever a description), `published`, `last_modified` (2026-10: from NVD's record; a KEV, CISA ICS or OTX record, a STIX import or a partner write fills them only where the node has none), `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]`; EdgeGuard extensions: `cvss_score` / `severity` / `cvss_version` / `attack_vector` (2026-10: from the CVE's first CVSS sub-node in the order v3.1 → v3.0 → v2 → v4.0; a CVE without any CVSS has a null score, version and attack vector and severity `UNKNOWN`), `status[]` (NVD's record status, 2026-10), `cisa_exploit_add` and the other KEV fields, `known_ransomware_use` (KEV, 2026-10; no score is derived from it), `epss_score` / `epss_percentile` / `epss_score_date` / `epss_model_version` (FIRST EPSS, 2026-10, written by the post-sync job on the CVE nodes that exist, partner-created ones included, which then carry `edgeguard_enriched`), `ssvc_exploitation` / `ssvc_automatable` / `ssvc_technical_impact` / `ssvc_version` / `ssvc_timestamp` (CISA's SSVC decision from NVD's record, 2026-10) | NVD; CISA KEV, CISA ICS and OTX records merge into the same node; FIRST EPSS |
| `CVSSv31` | `vector_string`, `base_score`, `base_severity`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score` (none from CISA ICS, 2026-10-16) | NVD (via CVE node); CISA ICS where NVD has not asserted the node (2026-10-16: NVD's values hold a node both assert) |
| `CVSSv2` | `vector_string`, `base_score`, `base_severity`, `access_vector`, `access_complexity`, `authentication`, `confidentiality_impact`, `integrity_impact`, `availability_impact`, `impact_score`, `exploitability_score`, `obtain_all_privilege`, `obtain_user_privilege`, `ac_insuf_info` | NVD (via CVE node) |
| `ThreatActor` | `name` (cleaned: no composites, no descriptive phrases — 2026-10), `aliases[]`, `description` (ATT&CK's text where ATT&CK describes the actor; 2026-10-16: the text of the highest-ranked source, MITRE ATT&CK > a curated source > any other source, named in `description_source`; none on an actor only OTX names, since an OTX pulse's text describes the report), `zone[]`, `uses_techniques[]` (MITRE explicit **`uses`**), `reported_techniques[]` (OTX pulse-level, 2026-10), `pulse_ids[]` (2026-10), `tlp` | MITRE ATT&CK, OTX (duplicates under an alias of a MITRE actor are merged into the MITRE node post-sync) |
| `Malware` | `name` (the family name without an ATT&CK software id suffix: OTX's `"Cobalt Strike - S0154"` is the ATT&CK node `cobalt strike`, the original in `aliases[]`, 2026-10), `malware_types[]`, `aliases[]`, `description` (2026-10: as on `ThreatActor`), `zone[]`, `uses_techniques[]` (MITRE explicit **`uses`**, optional), `reported_techniques[]` (OTX pulse-level, 2026-10), `pulse_ids[]` (2026-10), `merged_from[]` (the ATT&CK-id twins folded into the node, 2026-10), `tlp` | MITRE ATT&CK, OTX, ThreatFox |
| `Technique` | `mitre_id`, `name`, `description` (2026-10-16: as on `ThreatActor`, with `description_source`; until then the record merged last set it), `tactic_phases[]`, `attack_domain` (`enterprise` \| `ics`, 2026-10), `zone[]`, `tlp` | MITRE ATT&CK Enterprise; ATT&CK for ICS when `EDGEGUARD_ENABLE_MITRE_ICS` is on |
| `Tactic` | `mitre_id`, `name`, `shortname`, `description` (2026-10: ATT&CK's text; none when synced from a MISP kept from before 2026-10, which holds a placeholder there; 2026-10-16: as on `ThreatActor`, with `description_source`), `attack_domain` (2026-10) | MITRE ATT&CK (Enterprise; ICS when enabled — 9 of 12 ICS short names equal Enterprise ones, so `IN_TACTIC` is matched within the domain) |
| `Source` | `source_id`, `name` | Internal registry |
| `Tool` | `mitre_id` (ATT&CK S-id), `name`, `description` (ATT&CK's text, 2026-10; 2026-10-16: as on `ThreatActor`, with `description_source`), `uses_techniques[]`, `zone[]`, `tlp` | MITRE ATT&CK software (tools) |
| `Campaign` | `name`, `actor_name`, `aliases[]`, `tags[]`, `indicator_count`, `malware_count`, `first_seen`, `last_seen`, `active`, `zone[]` | Derived — `enrichment_jobs.build_campaign_nodes`, one per actor with a malware attributed to it (`ATTRIBUTED_TO`) or (2026-10-16) used by it (`USES_MALWARE`), and an active indicator of such a malware (202 live, 2026-10-11, from `ATTRIBUTED_TO` only). A campaign whose actor has neither link left, or whose actor name no longer exists, is deleted with its links (2026-10-16); one with evidence whose indicators expired stays, `active = false`. The `uuid` comes from the actor's name, so a campaign built again keeps it |
| `Sector` | `name` (`energy`, `finance`, `healthcare`, `global`) | Derived from `zone[]` by the sync and `build_relationships.py` Q7a–d |
| `CVSSv30`, `CVSSv40` | per-version score fields, same pattern as `CVSSv31` | NVD; bidirectional `HAS_CVSS_v30` / `HAS_CVSS_v40` |
| `Alert` | `alert_id`, `source`, `zone[]`, `timestamp`, `severity`, `indicator`, `indicator_type`, `malware`, `cve`, `enriched`, `received_at` | EdgeGuard's alert processor, from inbound NATS alerts only (none on a baseline). Not in CRUSOE's model, which has `SecurityEvent` — label ownership to agree with ResilMesh |

**Secondary sector labels:** nodes classified into a sector also carry `:Energy` / `:Finance` / `:Healthcare` as additional labels (applied by the sync after each run; 7,364 `:Energy` nodes live on 2026-10-11). They are a convenience for label-based filtering — the authoritative sector relation is `TARGETS` / `AFFECTS` → `Sector`.

#### ResilMesh Topology Layer (schema-compatible helpers)

EdgeGuard has schema-compatible `merge_*` helpers for these labels, but **no pipeline path writes them today** — nothing calls `merge_ip` / `merge_host`; the alert processor writes `Alert`, the `Indicator`, `INVOLVES` and the indicator's sector link. When a path does write them, §3.4 applies: a node EdgeGuard creates gets `edgeguard_managed`, a partner-created one `edgeguard_enriched`.

| Node Label | When created | Properties aligned to ResilMesh |
|------------|-------------|----------------------------------|
| `IP` | helper only (`merge_ip`) | `address`, `version`, `tag[]`, `status` |
| `Host` | helper only (`merge_host`) | `hostname` |
| `SoftwareVersion` | helper only (`merge_softwareversion`); see §4.4 | `version`, `cve_timestamp` |

### 3.2 Relationships Produced by EdgeGuard

#### Internal threat intel relationships

| Relationship | From → To | Description |
|---|---|---|
| `SOURCED_FROM` | Any node → `Source` | **Per-source provenance** — one edge per (entity, source) pair. Carries `raw_data`, `imported_at` (immutable), `updated_at`, `confidence`, plus per-source claim properties **`source_reported_first_at`** (MIN-guarded) and **`source_reported_last_at`** (MAX-guarded) — what the source itself says about when it first/last recorded the entity. Since 2026-10 the edge also accumulates, for its source, the MISP events that carried the entity (`misp_event_ids[]`) and the source's own record ids (`source_refs[]`). STIX export aggregates `MIN(r.source_reported_first_at)` across all edges to populate `Indicator.valid_from`. On an Indicator's edge (2026-10-16) the source's latest report, forward only: `last_reported_at`, `last_reported_ref`, `last_reported_source`, `last_recorded_at`. On every edge (2026-10-16) the zones this source's records gave the entity (`zones[]`, `global` dropped once a sector is present, sorted) the part of them the source stated itself (`stated_zones[]`, today CISA ICS only, written when not empty) and which of the source's records stated which sector (`stated_refs[]`, `"<zone>\|<source ref>"`, e.g. `healthcare\|cisa_ics:ICSMA-26-283-01`): a link to a `Sector` names only the feeds that gave its sector and cites only the records that gave it. See [`docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`](KNOWLEDGE_GRAPH.md#sourced_from-edge-schema) for the full property contract. |
| `EMPLOYS_TECHNIQUE` | `ThreatActor` / `Campaign` → `Technique` | **Attribution.** Actor employs a MITRE technique. Evidence levels, told apart by `r.match_type` (§3.2.2): `mitre_explicit` (0.95, from MITRE's STIX **`uses`** → `uses_techniques`), `otx_pulse` (0.6, from an OTX pulse's `attack_ids` → `reported_techniques`, 2026-10) and, on a link a curated package's claim creates, the package's curated label (0.85, 2026-10; a claim on an existing link adds only its provenance, §3.2.2). *Split from a generic `USES` in 2026-04 — see below.* |
| `IMPLEMENTS_TECHNIQUE` | `Malware` / `Tool` → `Technique` | **Capability.** Malware or tool implements a MITRE technique. Same evidence levels as `EMPLOYS_TECHNIQUE`: `mitre_explicit` (0.95), for malware named in an OTX pulse `otx_pulse` (0.6, 2026-10), and, on a link a curated package's claim creates, the package's curated label (0.85, 2026-10). MISP round-trip via the **`MITRE_USES_TECHNIQUES:`** comment (`t` = explicit, `rt` = reported, `pid` = pulse id). *Split from a generic `USES` in 2026-04 — see below.* |
| `USES_TECHNIQUE` | `Indicator` → `Technique` | **Observation.** OTX `attack_ids` on indicator → `Technique.mitre_id` (`build_relationships.py`, conf 0.85). Unchanged by the 2026-04 refactor. |
| `ATTRIBUTED_TO` | `Malware` → `ThreatActor` | Malware linked to an actor. Either the malware's own `attributed_to` claim matched exactly to the actor's name or alias (`match_type = "exact"`, 1.0, `build_relationships.py` Q2), or — 2026-10 — malware and actor named in the **same OTX pulse** (`match_type = "otx_pulse"`, 0.6, the pulse in `r.source_refs[]` as `alienvault_otx:<pulse id>`, written by the MISP→Neo4j sync). Only from a pulse whose actors are one actor (2026-10-15): a pulse naming several actors does not say which malware is whose, so it attributes nothing; the aliases of one actor count as one (canonical threat-actor reference), decided by the OTX collector on the pulse's whole adversary list. `build_relationships` step 2d removes the attributions an earlier run made from such pulses (unless another feed asserts them) and drops such pulses from the provenance of the others. Whole-event co-occurrence attribution was removed (it had attributed one malware to up to 152 actors). |
| `EXPLOITS` | `Indicator` → `Vulnerability` / `CVE` | Only from the indicator's own `cve_id` tag (`match_type = "cve_tag"`; 1.0 from `build_relationships.py` Q3, or the attribute's own confidence (≥ 0.7) when the sync created the edge first from the `exploits:` tag). 2026-10: no longer produced from event co-membership (an IP or hash listed next to a CVE does not exploit it). Edge carries `r.misp_event_ids[]`. |
| `EXPLOITS` | `ThreatActor` / `Malware` → `CVE` | **2026-10.** A curated package's claim that an actor or malware exploits a CVE (`match_type` = the package's curated label, 0.85; see the evidence table below). Completes the join from ResilMesh's `Host ← ON ← SoftwareVersion ← IN ← Vulnerability → REFERS_TO → CVE` to the threats that exploit the CVE. |
| `INDICATES` | `Indicator` → `Malware` | Two evidence levels (§3.2.2): a source-asserted `malware_family` on the indicator matched to the malware name/alias (`match_type = "malware_family"`, 0.8, ThreatFox, MalwareBazaar or Feodo Tracker; 2026-10: `r.sources[]` no longer names OTX on such a link unless a pulse that listed the indicator names the family by the malware's name (or a name folded into it, `merged_from`), since OTX records carry no family label), or — 2026-10 — indicator and malware listed in the **same OTX pulse** (`match_type = "otx_pulse"`, 0.6, the pulse in `r.source_refs[]`). Whole-event co-occurrence (`misp_cooccurrence`, 0.5, 96% of all INDICATES on the 2026-09 baseline) was removed. Edge carries `r.misp_event_ids[]`. |
| `TARGETS` | `Indicator` → `Sector`; **`ThreatActor` → `Sector`, `Malware` → `Sector` (2026-10)** | "Reported in connection with attacks on this sector." From `zone[]` on the node — indicators: written by the sync (`r.sources` names the indicator's own source, 2026-10) and by `build_relationships.py` Q7a; actors and malware: Q7c / Q7d. `global` is never an edge target, so an actor never "targets global". Since 2026-10-16 `r.sources` / `r.source_refs` / `r.misp_event_ids` name only the feeds whose `SOURCED_FROM.zones` give the sector (before, every feed of the node), and the label and confidence follow §3.2.2: `match_type='zone_classification'` at 0.5 (an inference, never 1.0); a CISA deployment statement never labels `TARGETS`. **PR-N26:** edge carries `r.misp_event_ids[]`. |
| `AFFECTS` | `Vulnerability` / `CVE` → `Sector` | "The vulnerable product is used in this sector." From `zone[]` on vuln/CVE nodes — sync (`r.sources` names the record's own source, 2026-10) and `build_relationships.py` Q7b; `global` never an edge target. Since 2026-10-16 the link names only the feeds whose `SOURCED_FROM.zones` give the sector (on the graph of 2026-10-16, 2,639 of 6,506 AFFECTS links named a feed that never gave their sector), and its label follows §3.2.2: `advisory_sector` at 0.9 when CISA's ICS advisory states the sector (where the product is deployed; `r.source_refs` names the advisories whose sector note names that sector, `cisa_ics:ICSA-…`, not every advisory of the CVE), otherwise `zone_classification` at 0.5. A query that filters on `match_type = 'zone_classification'` alone misses CISA's statements. **PR-N26:** edge carries `r.misp_event_ids[]`. |
| `IN_TACTIC` | `Technique` → `Tactic` | MITRE kill-chain phase match (`build_relationships.py`) |
| `SUBTECHNIQUE_OF` | `Technique` → `Technique` | **2026-10 (R6).** Sub-technique → parent technique, from MITRE's dotted id (`T1021.006` → `T1021`; the same claim as the STIX `subtechnique-of` relationship). `build_relationships.py` Q1b, `match_type='mitre_explicit'`, 1.0, same `attack_domain` on both ends. 493 edges on the September graph. |
| `USES_MALWARE` | `ThreatActor` → `Malware` | **2026-10 (R6).** MITRE's explicit STIX `uses` relationship from a group to malware, carried on the actor as `uses_malware[]` and written by `build_relationships.py` Q2b (`match_type='mitre_explicit'`, 0.95; canonical lower-case **name** match only — never `aliases`, which are rehydrated from untrusted MISP tags). The precise form of what the legacy CLI path inferred as `ATTRIBUTED_TO` (`mitre_derived`). A curated package's claim (exact canonical malware name) creates the link with the package's curated label and 0.85, or adds its provenance to an existing one (2026-10). Campaign evidence like `ATTRIBUTED_TO` (2026-10-16): an actor with such a link has a campaign, and the malware is a member. |
| `USES_TOOL` | `ThreatActor` → `Tool` | **2026-10 (R6).** Same source for tools (`uses_tools[]` = ATT&CK S-ids), Q2c; curated-package claims (the tool's ATT&CK id) as for `USES_MALWARE`. |
| `RUNS` | `ThreatActor` → `Campaign` | Actor runs the campaign materialised for it by `enrichment_jobs.build_campaign_nodes` (one `Campaign` per actor with a malware attributed to it or, since 2026-10-16, used by it). Removed when it comes from an actor that is not the campaign's or has neither link left; a campaign whose actor has neither link left is deleted with its links (2026-10-16; before, the campaign retired). `r.evidence_types` names the types of the links it rests on (`ATTRIBUTED_TO`, `USES_MALWARE`; 2026-10-16). |
| `PART_OF_CAMPAIGN` | `Malware` → `Campaign`; `Indicator` → `Campaign` | Membership of the actor's malware (attributed to it or, since 2026-10-16, used by it) and of the indicators that indicate it (the 100 newest active ones, each once); the indicator edge is pruned when the indicator is retired, and the malware edge when the malware has neither link to the campaign's actor (2026-10-15, `USES_MALWARE` since 2026-10-16). Campaign links (`RUNS`, `PART_OF_CAMPAIGN`) carry the provenance of the links they currently rest on, replaced on every run, and the relationship types of those links in `r.evidence_types` (2026-10-16; `INDICATES` too on an indicator's link). |
| `INVOLVES` | `Alert` → `Indicator` | Written by the alert processor for inbound NATS alerts; carries the ownership marker since 2026-10 (`created_at` once, `updated_at` per delivery). |

**STIX 2.1 bundle coverage (`/stix/export/*`, 2026-10):** every SRO uses the `relationship_type` the STIX 2.1 relationship summary table permits for its (source, target) pair. `INDICATES` (Indicator → Malware) and `USES_TECHNIQUE` (Indicator → Technique) are `indicates`; `EMPLOYS_TECHNIQUE` / `IMPLEMENTS_TECHNIQUE` are `uses`; `ATTRIBUTED_TO` (Malware → ThreatActor) is exported in the direction the table defines, `intrusion-set` **`uses`** `malware` (the MITRE ATT&CK form these edges derive from); `RUNS` (ThreatActor → Campaign) is `campaign` **`attributed-to`** `intrusion-set`; `EXPLOITS` (Indicator → CVE), `Indicator → Sector TARGETS` and `CVE → Sector AFFECTS` have no table-defined pair and are `related-to`. Sector `identity` objects carry `industry-sector-ov` values (`finance` → `financial-services`; `global` has none). Every SDO carries `object_marking_refs` from `n.tlp` (STIX 2.1 TLP marking definitions; `clear` → WHITE, `amber+strict` → RED, unrecognised → AMBER, absent → the deployment default `EDGEGUARD_DEFAULT_TLP`) and SROs carry the most restrictive marking of their endpoints and of the relationship's own `r.tlp` (curated-package links carry the package's level, 2026-10); `created_by_ref` on every object points to the EdgeGuard producer `identity`, which carries the exporter provenance, and the `x_edgeguard_*` properties are declared by an `extension-definition` (`toplevel-property-extension`) so the bundle parses under strict `stix2.parse`. Each related-node collection is bounded by `?limit=` (default 100, maximum 500). **2026-10: every relationship with a STIX form is exported**, curated-package claims (Core Ideas) included: `USES_MALWARE` / `USES_TOOL` (`intrusion-set` `uses` `malware` / `tool`), `SUBTECHNIQUE_OF` (`subtechnique-of`, MITRE ATT&CK's own type), `EXPLOITS` from `Malware` (`malware` `exploits` `vulnerability`) and from `ThreatActor` (`intrusion-set` `targets` `vulnerability`), `ThreatActor` / `Malware → Sector TARGETS` (`targets`), and `PART_OF_CAMPAIGN` (`campaign` `uses` `malware`; `indicator` `indicates` `campaign`). **Every SRO carries the provenance of its graph relationship:** `confidence` (0–100 from `confidence_score`), `external_references` built from `source_refs` (a link where the source record has a public page: OTX pulse, ThreatFox IOC, URLhaus entry, ATT&CK object), and the extension properties `x_edgeguard_match_type`, `x_edgeguard_sources`, `x_edgeguard_source_refs`, `x_edgeguard_misp_event_ids` (extension definition 1.1.0). Still not SROs: `IN_TACTIC` (a kill-chain phase on the `attack-pattern`), `SOURCED_FROM` (node provenance, carried as properties), `REFERS_TO` (twin nodes share one `vulnerability`), `HAS_CVSS_*` (properties of the `vulnerability`) and `INVOLVES`. **A `vulnerability` carries NVD's record status** as `x_edgeguard_status` (`["rejected"]` / `["active"]`, extension definition 1.2.0, 2026-10-15); before, a rejected CVE exported like an active one. **Explainability (extension definition 1.3.0, 2026-10-15):** a link to a technique that a source cited by an id ATT&CK has since revoked carries `x_edgeguard_cited_ids` (the ids cited), and an `intrusion-set` the actor alias merge folded other actor nodes into carries `x_edgeguard_merged_from` (their names). **A `vulnerability` carries FIRST EPSS and CISA's SSVC decision** (extension definition 1.4.0, 2026-10-15): `x_edgeguard_epss_score`, `x_edgeguard_epss_percentile`, `x_edgeguard_epss_score_date`, `x_edgeguard_epss_model_version`, `x_edgeguard_ssvc_exploitation`, `x_edgeguard_ssvc_automatable`, `x_edgeguard_ssvc_technical_impact`, `x_edgeguard_ssvc_version`, `x_edgeguard_ssvc_timestamp`. **The SRO of a campaign link (`RUNS`, `PART_OF_CAMPAIGN`) names the relationship types it rests on** as `x_edgeguard_evidence_types` (extension definition 1.5.0, 2026-10-16).

#### ResilMesh-compatible relationships

These match the ResilMesh schema exactly and allow cross-layer graph traversal:

| Relationship | From → To | Description |
|---|---|---|
| `HAS_CVSS_v31` | `CVE` ↔ `CVSSv31` | Bidirectional (matches ResilMesh pattern) |
| `HAS_CVSS_v30` | `CVE` ↔ `CVSSv30` | Bidirectional |
| `HAS_CVSS_v40` | `CVE` ↔ `CVSSv40` | Bidirectional |
| `HAS_CVSS_v2` | `CVE` ↔ `CVSSv2` | Bidirectional |
| `REFERS_TO` | `Vulnerability` ↔ `CVE` | ResilMesh's edge in CRUSOE's model (the scanner links its finding to the CVE). EdgeGuard's post-sync job `bridge_vulnerability_cve` MERGEs it in both directions for any `Vulnerability` node carrying `cve_id` — none exists today: EdgeGuard writes `CVE`, not `Vulnerability` (0 `REFERS_TO` live, 2026-10-11). |
| `IN` | `Vulnerability` → `SoftwareVersion` | Vulnerable software, as ISIM traverses it (`vulnerabilities { software_versions }`) — ResilMesh-defined; EdgeGuard has helpers for both directions but no pipeline path writes it (see §4.4) |
| `ON` | `SoftwareVersion` → `Host` | Software installed on host — ResilMesh-defined; EdgeGuard has helper code but no pipeline path writes it |

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

**Backward compatibility:** **Removed in PR-N1 (2026-04).** Earlier
versions of `create_misp_relationships_batch` in `src/neo4j_client.py`
accepted `rel_type="USES"` when `to_type="Technique"` and routed it to
the specialized type based on `from_type`. That shim is gone — verified
no caller anywhere in `src/`, `dags/`, or `tests/` emits
`rel_type="USES"`. Any partner code still emitting the legacy value
will be silently dropped (the row never matches any of the specialized
buckets), so check your call sites before upgrading. Same goes for
read paths — the alternation `[:EMPLOYS_TECHNIQUE|USES]` was removed
from the alert-enrichment query in PR-N1.

**Migration:** *Pre-release framework — no production graph exists, so
no migration script is shipped.* The first baseline run already writes
the specialized edge types (`EMPLOYS_TECHNIQUE` for actor/campaign,
`IMPLEMENTS_TECHNIQUE` for malware/tool); a fresh baseline rerun heals
any dev/test graph that still carries the legacy generic `USES` edges.

**What to update in your code:**

```cypher
// Before (no longer supported as of PR-N1):
MATCH (a:ThreatActor)-[:USES]->(t:Technique) RETURN a, t

// After (specialized — reads attribution OR capability OR observation):
MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN a, t
MATCH (m:Malware)-[:IMPLEMENTS_TECHNIQUE]->(t:Technique)  RETURN m, t

// If you want all three specialized types in one query:
MATCH (n)-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE]->(t:Technique)
RETURN n, type(r) AS rel, t
```

### 3.2.2 Evidence labels on relationships (2026-10)

Every relationship that encodes a claim between threat-intelligence entities states what kind of evidence
produced it, in `r.match_type`, with a confidence that follows from the evidence. (Structural edges —
`SOURCED_FROM`, `HAS_CVSS_*`, `REFERS_TO` — carry none; their meaning is fixed. The campaign links carry `campaign_grouping` since 2026-10-15.) Consumers (and the text-to-Cypher model) can therefore filter
by evidence without renaming anything — the ResilMesh and STIX-derived relationship names are unchanged.

| `r.match_type` | Meaning | Confidence | Produced by |
|---|---|---|---|
| `mitre_explicit` | MITRE ATT&CK's own assertion: the STIX `uses` relationship, or the sub-technique hierarchy encoded in MITRE's dotted ids (`T1021.006` → `T1021`, equivalent to its STIX `subtechnique-of`) | 0.95 (`uses`) / 1.0 (`SUBTECHNIQUE_OF`) | `build_relationships.py` Q5/Q6/Q10 from `uses_techniques` (MITRE collector only); Q1b `SUBTECHNIQUE_OF`; Q2b/Q2c `USES_MALWARE` / `USES_TOOL` from `uses_malware` / `uses_tools` |
| `otx_pulse` | The entity was named in the same AlienVault OTX pulse (one report) | 0.6 | MISP→Neo4j sync (`INDICATES`, `ATTRIBUTED_TO`, same-run pairs); `build_relationships.py` Q5b/Q6b from `reported_techniques`; **Q9b/Q2d (2026-10, regular updates)** from the families / adversaries each pulse stamps on its indicators (`Indicator.pulse_malware_families`, and `"family::adversary::pulse"` pairs of the same pulse in `.pulse_malware_actor_pairs` — never a cross product of two lists) — so IOCs of a later pulse naming an already-known family still link, although the family attribute itself is a MISP cross-event duplicate. `ATTRIBUTED_TO` only from a pulse whose actors are one actor (2026-10-15; aliases of one actor count as one). ON CREATE only: never downgrades `malware_family` (0.8), `exact` (1.0) or `mitre_explicit` |
| `exact` | The malware's own `attributed_to` claim equals an actor name/alias | 1.0 | `build_relationships.py` Q2 |
| `malware_family` | The indicator's source-asserted family equals a malware name/alias | 0.8 | `build_relationships.py` Q9 |
| `cve_tag` | The indicator's own CVE tag | 1.0 | `build_relationships.py` Q3a/Q3b |
| `otx_attack_ids` | Pulse-level ATT&CK ids inherited by every indicator in the pulse | 0.85 | `build_relationships.py` Q8 (`USES_TECHNIQUE`; unchanged, documented as pulse-level) |
| `kill_chain_phase` | ATT&CK tactic phase on the technique | 1.0 | `build_relationships.py` Q1 (`IN_TACTIC`) |
| `campaign_grouping` | EdgeGuard's grouping of one actor's malware (attributed to it, `ATTRIBUTED_TO`, or, since 2026-10-16, used by it, `USES_MALWARE`) and those malware's active indicators into a campaign (2026-10-15) — derived, not a source's claim; `r.evidence_types` names the relationship types it rests on (2026-10-16); its `sources` and `source_refs` are those of the links it rests on, sorted, and its `misp_event_ids` the 200 newest of theirs by MISP event id, so they do not depend on the order in which those links were created (2026-10-16) | the evidence it rests on: `RUNS` the actor's strongest link to a malware; malware `PART_OF_CAMPAIGN` its strongest link to the actor; indicator `PART_OF_CAMPAIGN` its best path, `INDICATES` then `ATTRIBUTED_TO` or `USES_MALWARE`, each path as strong as its weaker link | `enrichment_jobs.build_campaign_nodes` (`RUNS`, `PART_OF_CAMPAIGN`), recomputed on every run |
| `zone_classification` | EdgeGuard's own sector classification of the node (keywords in NVD descriptions and CPE vendors / products, KEV vendor and product, OTX pulse text and industries, a feed's malware family) and a foreign MISP zone tag — an inference, so it never carries 1.0; `global` ("no sector") is never linked | 0.5 (sync and Q7a–Q7d; aligned in the 2026-10 audit, Q7 wrote 1.0 before) | `TARGETS` (Indicator, ThreatActor, Malware → Sector), `AFFECTS` (CVE → Sector); the link names only the feeds that gave the sector (2026-10-16) |
| `advisory_sector` | CISA's ICS advisory names the sector in its "Critical infrastructure sectors" note: the affected product is **deployed** in it (2026-10-16). A deployment statement, never a targeting claim; one link per CVE and sector, so where NVD or OTX also infers the sector the link carries this label and names both feeds, and who stated it is on the `cisa_ics` `SOURCED_FROM` edge (`stated_zones`) | 0.9 (sync and Q7b, from one table, `src/sector_evidence.py`; must stay above 0.5) | `AFFECTS` (CVE → Sector) only, from `cisa_ics`; `r.source_refs` `cisa_ics:<advisory id>` of the advisories that name that sector only (a CVE named by an ICS advisory for Energy and a medical advisory for Healthcare cites the first on its energy link and the second on its healthcare link; `SOURCED_FROM.stated_refs`), exported to STIX with the cisa.gov page |
| `mitre_derived` | Malware attributed to an actor because MITRE's STIX says the actor **uses** that malware (inference, not an explicit `attributed-to`) | 0.7 | Legacy in-process path only (`run_pipeline.py` → `Neo4jClient.create_malware_actor_relationship`); the DAG path does not write it |
| `stix_relationship` | An explicit STIX relationship object (`attributed-to`) in a bundle imported by the in-process loader | 0.7 | Legacy in-process path only (`run_pipeline.load_stix21_to_neo4j` → `Neo4jClient.create_malware_actor_relationship`); the DAG path does not write it |
| `misp_attribute_tag` | A tag on the MISP attribute itself (`mitre-attack:technique=`, `threat_actor=`, `exploits:`) | per attribute confidence (≥ 0.7) | MISP→Neo4j sync: attribute-embedded `EMPLOYS_TECHNIQUE`, `ATTRIBUTED_TO`; embedded `EXPLOITS` keeps `cve_tag` |
| `coreideas_curated` / `curated_other` | A link created by a claim of a curated package imported once into MISP (`scripts/import_curated_package.py`): `coreideas_curated` for the registered curated source `coreideas`, `curated_other` for a registered curated source without a label of its own (`misp_galaxy`). A claim on a link that already exists leaves that link's label and confidence and adds its provenance. `r.sources` names the source of each claim, a registered curated source only (any other is recorded as `curated_other`); `r.tlp` carries the package's TLP level | 0.85 | MISP→Neo4j sync: `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`, `USES_MALWARE`, `USES_TOOL`, `EXPLOITS` (actor / malware → CVE); MATCH on existing nodes only |

**Precedence (2026-10):** an edge's label and confidence only ever move towards stronger evidence. On a link to a `Sector` (2026-10-16) the confidence is the value the label table gives the label (`src/sector_evidence.py`), whichever writer runs: `build_relationships` Q7a–Q7d keep a stored stronger label of the table and a label outside it, give a link without a label the computed one, and bring an old `zone_classification` link at 1.0 back to 0.5. The MISP→Neo4j sync keeps the higher `confidence_score` and the label that came with it (a later `otx_pulse` 0.6 row never overwrites an `exact` 1.0 or `mitre_explicit` 0.95 edge); `build_relationships` re-asserts explicit labels on every run and writes report-scoped labels on creation only. A curated-package claim never changes an existing edge's label or confidence (an `otx_pulse` 0.6 edge stays `otx_pulse`): it writes its label and 0.85 only on an edge it creates, and on an existing edge adds its provenance. To leave the curated layer out of a dataset, filter on `r.sources`, not on `r.match_type` (`docs/KNOWLEDGE_GRAPH.md`, "Curated packages").

Every edge EdgeGuard builds from the sources also says who asserts it (2026-10): `r.sources[]` (canonical
source ids such as `mitre_attck`, `alienvault_otx`, `threatfox`, `nvd`), `r.source_refs[]` (the sources' own
record ids, e.g. `alienvault_otx:<pulse id>`, `threatfox:<IOC id>`, `mitre_attck:G0016`) and
`r.misp_event_ids[]`, so a consumer can go from the edge to the MISP event and to the report that asserted it
(`docs/KNOWLEDGE_GRAPH.md`, "Relationship provenance"). Items without a report id are never paired.
`misp_cooccurrence` no longer appears on any edge written by this version; `calibrate_cooccurrence_confidence`
is kept for graphs that still hold such edges and is a no-op on a fresh baseline.

### 3.2.x STIX 2.1 timestamp semantics (PR-M2)

The full timestamp model is documented in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md). For consumers, the upshot is:

| STIX field | Meaning in EdgeGuard bundles |
|---|---|
| `created` | When the SDO was created in EdgeGuard's graph (= our import time). For Vulnerability SDOs specifically, this is NIST's `published` since the SDO represents the CVE itself. |
| `modified` | When EdgeGuard last refreshed its record. An indicator's (2026-10-16): the latest of `created`, `last_recorded_at` (the latest MISP record of a report) and `aging_since` (when its aging state last changed), never earlier than `created` and unmoved by a re-sync of the same data; on a graph kept through that change it can be earlier than the `modified` an earlier export gave (it was the last database write), so a consumer re-ingests the full bundle once after the rollout |
| `valid_from` (Indicator only) | The source's first-observation claim if available; falls back to EdgeGuard's import time and sets `x_edgeguard_first_seen_inferred=true` so consumers can filter for source-truthful evidence |
| `x_edgeguard_first_seen_at_source` | Verbatim source claim (concept 1). Absent if no source provided one |
| `x_edgeguard_last_seen_at_source` | Verbatim source claim (concept 2). Absent if no source provided one |
| `x_edgeguard_first_imported_at` | EdgeGuard's import wall-clock (concept 3) |
| `x_edgeguard_last_updated` | EdgeGuard's last-touch wall-clock (concept 4) |
| `x_edgeguard_first_seen_inferred` | `true` iff `valid_from` came from the fallback chain. Use this to filter for source-truthful indicators only when building correlation pipelines |
| `x_edgeguard_description_source` | The source whose text the SDO's `description` is (`nvd`, `cisa_kev`, `mitre_attck`, …; 2026-10-16, extension definition 1.6.0). Absent when the SDO has no description or the node was written before 2026-10-16 |
| `x_edgeguard_last_reported_at`, `x_edgeguard_last_reported_source`, `x_edgeguard_last_reported_ref` | Indicators (2026-10-16, extension definition 1.7.0): the latest report of any source — its time (`min(T, coalesce(L, T))`, the source's `last_seen` capped at the MISP timestamp), the source, and the MISP attribute uuid that holds it ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging-2026-10-16)) |
| `x_edgeguard_source_confidence`, `x_edgeguard_aging_basis`, `x_edgeguard_aging_tier`, `x_edgeguard_active`, `x_edgeguard_retired_by` | Indicators (2026-10-16, extension definition 1.7.0): the highest confidence a source gave (a node written before 2026-10-16: its `confidence_score`), what the age counts from (`source_date`, `misp_recorded`, `first_imported`), the tier reached (0 below 90 days, 1 from 90, 2 from 180, 3 from 365), whether it is active, and who retired it (`decay` from 730 days without a report, or a manual decommission) |

The `x_edgeguard_*` properties are top-level extension properties: each object that carries them declares the EdgeGuard `extension-definition` in its `extensions` map (`extension_type: "toplevel-property-extension"`), and the definition object — listing every property name — is included in every bundle. Strict parsers (`stix2.parse` with `allow_custom=False`) accept the bundle without configuration.

**Worked example.** A CVE-2013 indicator ingested today appears as:

```jsonc
{
  "type": "indicator",
  "valid_from": "2013-05-29T00:00:00+00:00",          // source-truthful (NVD published)
  "created":    "2026-04-21T08:00:00+00:00",          // EdgeGuard import time
  "modified":   "2026-04-21T08:15:00+00:00",          // last refresh
  "x_edgeguard_first_seen_at_source": "2013-05-29T00:00:00+00:00",
  "x_edgeguard_last_seen_at_source":  "2024-03-15T18:42:00+00:00",
  "x_edgeguard_first_imported_at":    "2026-04-21T08:00:00+00:00",
  "x_edgeguard_last_updated":         "2026-04-21T08:15:00+00:00"
  // x_edgeguard_first_seen_inferred ABSENT — we have a real source claim
}
```

A consumer reading this gets a clear picture: the underlying CVE was published in 2013, was last updated by NIST in 2024, and EdgeGuard learned about it on 2026-04-21.

### 3.3 Sector/zone and TLP

- **`zone`** — `LIST[STRING]` on merged threat-intel nodes (`global`, `healthcare`, `energy`, `finance`, …), populated from classification + MISP→Neo4j resolution (attribute-level `zone:` tags prioritized over event name / legacy event tags). Enables sector-scoped queries.
- **TLP** (2026-10) — `MISPWriter` stamps one **`tlp:<level>`** tag on **every attribute** (`_tlp_tag`): the source's own level when it states one (OTX `pulse_tlp`; when several pulses of one collector run list the same entity, the most restrictive of their levels, 2026-10), otherwise `EDGEGUARD_DEFAULT_TLP` (`white` — every current source is an open feed). The MISP→Neo4j sync rehydrates it as **`n.tlp`** on every EdgeGuard node label, keeping the **most restrictive** level a source ever stated for the node (`red` > `amber+strict` > `amber` > `green` > `white`/`clear`), so `WHERE n.tlp IN ['white','clear','green']` is a valid filter. The actor alias merge keeps that rule (2026-10-15): the canonical node takes the most restrictive level of the nodes folded into it, and a collapsed relationship the most restrictive `r.tlp` of the relationships it replaces; so does the Malware ATT&CK-id twin merge, which runs the same statements (2026-10-15). An attribute that reaches the sync without a `tlp:` tag (for example after an interrupted push) is given `EDGEGUARD_DEFAULT_TLP`, and the sync logs its UUID (`[TLP]` warning), since its source may have stated a stricter level. Events are still tagged only with `EdgeGuard` at event level.

**Historical collection window:** the same for every sector. How far back a baseline reaches is set per source: NVD and OTX by `baseline_days` (default 730 days = 24 months; `BASELINE_DAYS` / `--days`) in the request, CISA ICS by `baseline_days` on the advisories it downloads, CISA KEV and the NVD records of KEV CVEs whatever their age (2026-10), the other sources by what their API offers ([DATA_SOURCES.md](DATA_SOURCES.md)). No collector filters by sector or on `SECTOR_TIME_RANGES` (2026-10): the former NVD/OTX sector time-range filter compared the sources' zone-less timestamps with a timezone-aware cutoff, had not dropped a record since v2026.3.28, and was removed. `SECTOR_TIME_RANGES` in `config.py` (24 months for every sector) now only sets the start date of `run_misp_to_neo4j --sector` (now − 24 months); that option does not filter events by sector.

### 3.4 Node Identity Marking (`edgeguard_managed`, `edgeguard_enriched`)

The marker also bounds EdgeGuard's destructive operations: `edgeguard fresh-baseline` and the `baseline_clean` DAG step delete only `edgeguard_managed` nodes by default (`clear_edgeguard_managed`); deleting every node requires the explicit `--wipe-all` flag / `wipe_scope: "all"` (2026-10).

Every node EdgeGuard **creates** carries a constant property:

```
edgeguard_managed = true
```

**2026-10 (shared-database contract):** the marker is stamped on the MERGE *create* path only. When EdgeGuard writes onto a node another system created first — a CRUSOE scanner's `CVE` / `Vulnerability`, ResilMesh topology such as `Host` / `IP` — the node keeps its owner and receives `edgeguard_enriched = true` instead, so both sides can see which partner-owned nodes carry EdgeGuard properties. Consequences:

- `edgeguard clear neo4j --edgeguard-only` deletes nodes with `edgeguard_managed = true` and leaves enriched nodes in place, EdgeGuard's properties on them included.
- The REST / GraphQL APIs and the STIX 2.1 exporter expose nodes EdgeGuard created **or** enriched: `(n.edgeguard_managed = true OR n.edgeguard_enriched = true)`.
- EdgeGuard declares UNIQUE constraints on its own labels and on `IP.address`, `Host.hostname`, `Subnet.range` (unique in CRUSOE's model too). It does **not** constrain `Device`, `NetworkService`, `SoftwareVersion`, `Application`, `Role` or `User` — DDL on those labels belongs to ResilMesh — and drops any such constraint an older build created.
- CVSS de-duplication (run with constraint creation) only touches EdgeGuard-created nodes with a non-null `cve_id`.
- `Alert` nodes and `INVOLVES` edges written by EdgeGuard's alert processor carry the marker like everything else; `Alert.zone` is a list.

**2026-10:** the marker is also on **every relationship EdgeGuard writes** (`SOURCED_FROM`, every `build_relationships.py` edge, the batched MISP edges, `HAS_CVSS_*`, `REFERS_TO`, `RUNS`, `PART_OF_CAMPAIGN`) and on the `Campaign` and `Source` nodes that previously lacked it. `edgeguard clear neo4j --edgeguard-only` deletes exactly this set and nothing else — the mode to use on a database shared with ResilMesh. Relationship *names* EdgeGuard shares with ResilMesh (`REFERS_TO`, `HAS_CVSS_*`; campaign membership is `PART_OF_CAMPAIGN` since 2026-10, so `PART_OF` is ResilMesh's alone) must never be selected by type alone on a shared database; scope by the marker and by EdgeGuard labels.

This follows the same principle as Kubernetes' `app.kubernetes.io/managed-by: helm` label — when multiple systems share the same database, each system marks what it owns. Without this, a consumer querying the shared Neo4j has no reliable way to distinguish EdgeGuard-written nodes from ResilMesh-written nodes of the same label (e.g., both may write `CVE` or `Vulnerability` nodes).

**Why this is a best practice in multi-system shared databases:**
- Label-based filtering (`WHERE n:CVE`) is ambiguous if two systems can write the same label
- Property-based ownership marker is explicit and self-documenting; a node from before the marker existed is treated as not EdgeGuard-created — it receives `edgeguard_enriched` on the next sync and stays visible to the APIs
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

**Identity and lifecycle notes (2026-10):**

- `uuid` is deterministic from the natural key, and `CVE` and `Vulnerability` with the same `cve_id` share **one** uuid — look-ups by uuid must be label-scoped (`MATCH (n:CVE {uuid: $u})`, never `MATCH (n {uuid: $u})`).
- **Aging by kind of fact (2026-10-16).** What ages depends on the kind of fact, not on who supplied it or who created the node. Every `Indicator` ages by one rule, whichever source reported it and whether EdgeGuard created it (`edgeguard_managed`) or wrote onto a partner's node (`edgeguard_enriched`; no aging statement reads either marker): from the latest report of any source (the source's own last-report date capped at the MISP record time), the confidence falls to ×0.85 / ×0.70 / ×0.55 of the source's from 90 / 180 / 365 days and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days; a newer report reactivates it, a manual decommission is never overridden. `CVE`, the CVSS nodes, `Vulnerability`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Sector`, `Source` and `Alert` never age by time. **Partner nodes keep their own lifecycle:** EdgeGuard sets `active = true` only on nodes it creates and writes no `active`, `retired_*` or aging property when it matches a node, so a CASM `CVE` / `CVSSv*` node or an ISIM asset never receives an EdgeGuard lifecycle property, and EdgeGuard never writes ResilMesh's asset or scan-finding labels (`IP`, `Host`, `SoftwareVersion`, the scanner's `Vulnerability` …), which age on ResilMesh's own clock (rescans moving `start` / `end`, `rediscovered`, finding statuses). See [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging-2026-10-16).
- Constraints: EdgeGuard declares UNIQUE keys for its own labels plus `IP.address`, `Host.hostname`, `Subnet.range` and `Alert.alert_id`; the full list is in [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) (§ Neo4j constraints).

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
(CVE)<-[:REFERS_TO]-(Vulnerability)-[:IN]->(SoftwareVersion)-[:ON]->(Host)
```

This chain enables the query: *"Which of our hosts is vulnerable to this CVE?"* — the most operationally valuable query in attack surface management. Currently EdgeGuard writes `CVE` (+ `CVSSv*`) nodes only; `Vulnerability`, `SoftwareVersion`, `Host` and the `REFERS_TO` / `IN` / `ON` relationships are ResilMesh's scanner data (0 `Vulnerability` nodes live on 2026-10-11).

**What's needed to implement this:**

1. **CPE-to-SoftwareVersion mapping** — NVD CVE records include CPE strings (e.g. `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*`). These need to be parsed and matched against the `SoftwareVersion.version` values that ResilMesh writes from its Nmap/scanner inventory.

2. **New enrichment job** — A `bridge_cve_to_softwareversion()` job in `enrichment_jobs.py` that:
   ```cypher
   MATCH (cve:CVE), (sv:SoftwareVersion)
   WHERE cve.cpe_type IS NOT NULL
     AND any(cpe IN cve.cpe_type WHERE sv.version CONTAINS cpe)
   // via ResilMesh's Vulnerability node: (cve)<-[:REFERS_TO]-(v)-[:IN]->(sv)
   MERGE (v:Vulnerability {cve_id: cve.cve_id})-[:IN]->(sv)
   MERGE (v)-[:REFERS_TO]->(cve)
   ```
   The CPE matching logic is non-trivial (version ranges, wildcards) and requires a dedicated parser.

3. **ResilMesh must write SoftwareVersion nodes first** — EdgeGuard cannot create this bridge until ResilMesh's network scanner has populated `SoftwareVersion` and `Host` nodes in the shared Neo4j. This is a coordination dependency.

**Why this matters:**

Once implemented, the full attack surface query becomes:
```cypher
MATCH (cve:CVE {cve_id: 'CVE-2021-44228'})  // Log4Shell
     <-[:REFERS_TO]-(:Vulnerability)-[:IN]->(sv:SoftwareVersion)
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
| `description` | STRING | ✅ `description` (500 chars), NVD's text when NVD has a record of the CVE, else the next source in the ranking (2026-10-16) | Aligned |
| `description_source` | — | ✅ `description_source`, the source of `description` (`nvd`, `cisa_kev`, `cisa_ics`, …; null on a node written before 2026-10-16) | EdgeGuard extension (2026-10-16) |
| `published` | STRING | ✅ `published` (ISO 8601), NVD's date when NVD has a record of the CVE | Aligned |
| `last_modified` | STRING | ✅ `last_modified` (ISO 8601), NVD's date when NVD has a record of the CVE | Aligned |
| `cwe` | LIST OF STRING | ✅ `cwe` (e.g. `["CWE-89"]`) | Aligned |
| `ref_tags` | LIST OF STRING | ✅ `ref_tags` (e.g. `["Vendor Advisory"]`) | Aligned |
| `cpe_type` | LIST OF STRING | ✅ `cpe_type` (e.g. `["a", "o"]`) | Aligned |
| `result_impacts` | LIST OF STRING | ✅ `result_impacts` (CIA values) | Aligned |
| `status` | — (on `Vulnerability`: LIST OF STRING) | ✅ `status` (`["active"]` / `["rejected"]`, NVD's record status) | EdgeGuard extension (2026-10) |
| `attack_vector` | — (on `CVSSv31`: `attack_vector`, on `CVSSv2`: `access_vector`) | ✅ `attack_vector` (`NETWORK` / `ADJACENT_NETWORK` / `LOCAL` / `PHYSICAL`, null without CVSS) | EdgeGuard extension (2026-10) |

> **`published`, `last_modified` (2026-10)** are set by NVD's record and only filled, where the node has none, by a record from any other source (CISA KEV, CISA ICS, OTX, a STIX import, `merge_resilmesh_cve`); a write without them no longer removes them. Of the other records only CISA ICS gives dates (the advisory's release dates), from one attribute per CVE in MISP. **`description` (2026-10-16)** follows a fixed source ranking, NVD > CISA KEV > CISA ICS > any other source (inside "any other source" the higher registry reliability, then the source id; an unregistered source such as a STIX import or `merge_resilmesh_cve`, named `resilmesh`, below every registered one), and `description_source` names the source of the text: a record sets it when its source ranks at least as high as the stored text's source, so the same source's revised record replaces its own text and the result does not depend on the order in which the records are merged. A description written before 2026-10-16 has no `description_source` and counts as NVD's: only NVD's record replaces it ([RUNBOOK.md](RUNBOOK.md#repairing-cve-descriptions-and-dates-2026-10) repairs a kept graph). Until 2026-10 the record merged last set all three: a CVE that an OTX pulse listed as an indicator carried the raw `OTX_META:{...}` JSON of the pulse as its description, an OTX pulse reference "Referenced in OTX pulse: <name>", a KEV record CISA's short description and a CISA ICS record the advisory's dates; from 2026-10 to 2026-10-16 any record but NVD's only filled them, so a CVE without an NVD record kept the text of the first record to arrive. An OTX pulse reference gives no description, so a CVE that only OTX and the KEV name shows CISA's KEV text. `merge_resilmesh_cve` keeps `cwe`, `ref_tags`, `cpe_type` and `result_impacts` when a call does not carry them. In the opt-in STIX flow (`run_pipeline --stix-flow`) a `vulnerability` object carries the source of its event, so the description is the one the attribute flow gives; the dates come from the attribute flow only. Every source's own text stays in MISP, reached from the node's `SOURCED_FROM` edges ([RUNBOOK.md § Retrieving raw MISP data from a Neo4j node](RUNBOOK.md#retrieving-raw-misp-data-from-a-neo4j-node)).
>
> **2026-10:** `cwe`, `ref_tags`, `cpe_type` and `result_impacts` (plus `reference_urls`, `affected_products`) are written on the `CVE` node by `merge_cve` whenever NVD provides them. On the 2026-09 baseline they existed only inside `SOURCED_FROM.raw_data` (0 of 139,410 CVE nodes carried `c.cwe`), so a ResilMesh consumer reading `c.cwe` got nothing; the conformance check of 2026-10-09 caught it. Since 2026-10-16 NVD's record sets them and a record from any other source (only CISA ICS gives them: product names, the advisory's URL, CISA's CWE) fills them only where the node has none, so a CVE NVD describes shows NVD's lists whatever the order of the records; until then the record merged last set them.
>
> **CVSS sub-nodes (2026-10-16).** NVD and CISA ICS write the same `CVSSv31` / `CVSSv30` node of a CVE. Once NVD has asserted it (`'nvd'` in `sources` of the CVE's `HAS_CVSS_*` edge to it), the node holds NVD's values and a CISA ICS record only fills a property it lacks; the CVE's `cvss_score`, `severity` and `attack_vector` follow. A node only CISA ICS asserted holds CISA's values without `impact_score` and `exploitability_score`, which a CSAF advisory does not give (null through GraphQL). Until 2026-10-16 the record merged last set the whole node, and CISA ICS's carried 0.0 for both sub-scores; a graph built before then keeps those 0.0 values until the planned wipe and new baseline.
>
> **`attack_vector` (2026-10)** is the attack vector of the CVSS that gives the CVE's score (`cvss_score`, `cvss_version`: the first CVSS in the order v3.1 → v3.0 → v2 → v4.0), in NVD's words, and null without CVSS. `merge_cve` sets it from the CVSS sub-nodes after every merge (`CVSSv31` / `CVSSv30` `attack_vector`, `CVSSv2` `access_vector`, the `AV` metric of a `CVSSv40` `vector_string`), so the record merged last no longer decides it. Graphs built before 2026-10 mix NVD's vector-string letters (`N`, `L`, `A`, `P`), NVD's words and an invented `UNKNOWN`, and KEV and OTX records wrote `NETWORK`: on the hosted graph of 2026-10-15, 147 CVEs showed `NETWORK` against a `LOCAL`, `ADJACENT_NETWORK` or `PHYSICAL` CVSS 3.1, and `attack_vector = 'NETWORK'` matched 3,305 CVEs where a re-merge gives 100,779. Each NVD record now carries every CVSS version NVD supplies, so a CVE can have a `CVSSv31` and a `CVSSv2` sub-node at once.

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

4. **Shared labels are safe to write (2026-10)** — ResilMesh's scanner may create `CVE` and `Vulnerability` nodes, as its model does: EdgeGuard MERGEs on `cve_id`, enriches the existing node (`edgeguard_enriched = true`) and never deletes a node it did not create. `Vulnerability`, `REFERS_TO`, `IN` and `ON` are ResilMesh's to write (key `REFERS_TO` on `cve_id`, EdgeGuard's property name). `Indicator`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Campaign`, `Sector` and `Source` are EdgeGuard's vocabulary — a partner node under those labels is enriched, not claimed, but its properties are not guaranteed to follow EdgeGuard's conventions.

---

## 7. Downstream ResilMesh Services that Consume EdgeGuard Data

The ResilMesh platform exposes several services that directly consume or benefit from EdgeGuard's enriched graph. These are not integration requirements but are useful to understand as the deployment matures.

| Service | Port | How EdgeGuard feeds it |
|---------|------|------------------------|
| **PPCTI Frontend** (Privacy-Preserving CTI) | 3100 | EdgeGuard is the primary intelligence source. The PPCTI UI visualises threat intel from the shared Neo4j. |
| **IOB STIX** (Indicator of Behavior) | 3400 | Processes STIX-format IoB. EdgeGuard's STIX exports (`run_pipeline.py`) can feed IOB directly. |
| **THF** (Threat Hunting Framework) | 8030 / 8501 | Threat hunting assisted by a large language model. EdgeGuard's enriched graph — ThreatActors linked to Techniques, Indicators linked to CVEs — is the ideal context injection for THF queries. |
| **Shuffle** (SOAR) | 3443 | Playbook automation. High-confidence, critical-sector indicators from EdgeGuard can trigger automated response playbooks. |
| **Wazuh SIEM** | 4433 | Two directions (2026-06 team decision): (1) **EdgeGuard exports CTI to Wazuh** — `GET /export/wazuh/cdb` serves sector-specific IOC/CVE intelligence as Wazuh CDB lists (`key:value` lines, active entries only, `list=indicators\|cves`, zone/type/confidence filters) for use in Wazuh rules via `<list lookup="match_key">`; url/ipv6 keys are skipped (CDB keys cannot contain `:`) — match those via the enrichment path instead. A list holds at most 50,000 entries, the most recently updated first; `X-EdgeGuard-Truncated: true` says it was cut (2026-10). (2) Wazuh detects events; EdgeGuard enriches them with CVE/IoC context via the NATS alert bridge (later phase). |

### Deployment note — Port Allocation & Intentional Separation

EdgeGuard runs on its **own dedicated edge server**, not on the ResilMesh host. The two systems share only the **Neo4j database** (via the Bolt port, 7687) and the **NATS message bus**. All other EdgeGuard services are network-isolated.

Despite running on separate hardware, we intentionally choose ports that do not collide with any known ResilMesh service port. This is a defensive practice: if future deployments co-locate EdgeGuard closer to the ResilMesh stack, or if a developer runs both on the same machine for testing, there are no silent bind conflicts.

| EdgeGuard Service | Our Port | Rationale |
|---|---|---|
| REST Query API | **8000** | Standard FastAPI default; no ResilMesh service uses it |
| GraphQL API | **4001** | Mirrors the ISIM GraphQL port — intentional alignment so ResilMesh can treat EdgeGuard as an additional ISIM-compatible data source. On EdgeGuard's own host; when co-located with iSIM, change `EDGEGUARD_GRAPHQL_PORT` |
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

**EdgeGuard GraphQL** (`src/graphql_api.py`, Strawberry + FastAPI) also listens on **4001** by default (`EDGEGUARD_GRAPHQL_PORT`). **Auth:** when `EDGEGUARD_API_KEY` is set in the environment, requests must include header **`X-Api-Key`**. **GraphiQL** is off unless `EDGEGUARD_GRAPHQL_PLAYGROUND=true`. **Rate limiting:** default **120 requests/minute** per IP (`slowapi`). **Health:** `GET /health` — **HTTP 200** only when Neo4j is healthy (ping + APOC); **503** otherwise. (The REST API on port 8000 answers the same way: **200** while healthy, **503** while degraded, with `status` and `neo4j_connected` in the JSON body — see [README.md](../README.md) § *HTTP APIs*.)

**Shape of EdgeGuard's GraphQL (2026-10):** field names are camelCase (Strawberry's default — `cveId`, `cvssV31`, `lastUpdated`), the schema is flat (node types with scalar and list fields, no relationship-traversal fields yet) and no SDL file is committed; introspection is disabled in prod. The ISIM examples in this section are snake_case with traversal. "ISIM-compatible" today means the **data model** matches (labels, keys, property names) — not that the two GraphQL schemas are interchangeable. Aligning case and traversal needs ISIM's real SDL (§8.6). `Indicator` carries MISP back-links: `mispEventUrls` (the whole source event) and, since 2026-10, `mispAttributeUrls` (`<MISP_URL>/attributes/view/<uuid>`, the one MISP attribute behind the indicator; a client with a MISP key receives it as JSON). Since 2026-10 every node type carries `tlp` (the node's TLP level, §3.3; null when it has none), and `vulnerabilities` lists the `CVE` nodes EdgeGuard created or enriched (it read the `Vulnerability` label, which the sync does not write, and returned an empty list).

**SOC-analyst REST endpoints (port 8000):** `GET /actors/{name}/summary` (2026-06) resolves a threat actor by canonical name **or alias** (case-insensitive; `resolved_by` reports which) and returns an aggregated profile — attributed malware, the malware the actor uses (`malware_used`, `USES_MALWARE`; 2026-10-16: a campaign rests on either link, so a campaign of an actor with only `USES_MALWARE` links names its malware there), employed techniques, campaigns, with counts — backing analyst "tell me about this actor" queries. Analyst-supplied IOC/CVE/technique inputs at the REST and GraphQL boundaries are refanged + canonicalized to graph form via `src/ioc_normalize.py` (write-side parity), so defanged paste (`1.2.3[.]4`, `hxxp://`), uppercase hashes, and en-dash CVE ids resolve to the stored nodes.

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

EdgeGuard creates `CVSSv40`, `CVSSv31`, `CVSSv30`, and `CVSSv2` nodes from NVD metrics when present (`nvd_collector.py`), persists them in MISP via `NVD_META` (`misp_writer.py`), and merges them in Neo4j via `Neo4jClient.merge_cve()` → `_merge_cvss_node()`. CVSS v4.0 appears only for a subset of CVEs in NVD. **Node score (2026-10):** after every merge, `merge_cve` sets the `CVE` node's `cvss_score`, `severity`, `cvss_version` and `attack_vector` from its first CVSS sub-node in the order v3.1 → v3.0 → v2 → v4.0 (`src/cvss_selection.py`), so the result does not depend on which source's record was merged last; a CVE without any CVSS sub-node has a null score and severity `UNKNOWN`. No score is derived from a `cvss:` tag, a 0.0 placeholder, CISA KEV ransomware use or a collector default. Both `HAS_CVSS_*` edges name the source that delivered the score (`r.sources`) and the MISP event (`r.misp_event_ids`).

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
OPTIONAL MATCH (ind)-[:INDICATES]->(m:Malware)-[:ATTRIBUTED_TO]->(ta:ThreatActor)
OPTIONAL MATCH (ta)-[:EMPLOYS_TECHNIQUE]->(tech:Technique)-[:IN_TACTIC]->(tactic:Tactic)
OPTIONAL MATCH (ip)<-[:HAS_ASSIGNED]-(n:Node)-[:IS_A]->(h:Host)
RETURN
  ip.address                      AS ip,
  ind.value                       AS indicator,
  cve.cve_id                      AS cve,
  cve.cvss_score                  AS cvss_score,
  cve.severity                    AS severity,
  m.name                          AS malware,
  ta.name                         AS threat_actor,
  collect(DISTINCT tech.mitre_id) AS techniques,
  h.hostname                      AS targeted_host
```

The EdgeGuard hops follow the relationships the pipeline writes (2026-10; the sample read
`INDICATES` to a `Vulnerability` and `(Indicator)-[:ATTRIBUTED_TO]->(Malware)<-[:ATTRIBUTED_TO]-(ThreatActor)`,
which nothing writes): an indicator `EXPLOITS` the `CVE` its CVE tag names (and the `Vulnerability`
of that id, where one exists), `INDICATES` a malware, and the malware is `ATTRIBUTED_TO` an actor.
The score and severity are the `CVE` node's own (§9: from its first CVSS, null / `UNKNOWN` without
one).

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
| [`docs/BASELINE_LAUNCH_CHECKLIST.md`](BASELINE_LAUNCH_CHECKLIST.md) | **PR-N32:** the 6-section pre-launch operator pass that must be walked through before triggering a 730d baseline (preflight, smoke, Alertmanager wiring, MISP scale, RAM/disk, unicode-bypass audit) |
| [`docs/RUNBOOK.md`](RUNBOOK.md) § 8 | **PR-N31:** operator triage tree for `_MispFallbackHardError` (4 hard-failure modes: errors-payload, unexpected-shape, non-200, cap-hit) |
| [`scripts/audit_legacy_unicode_bypass_nodes.py`](../scripts/audit_legacy_unicode_bypass_nodes.py) | **PR-N32:** read-only audit of legacy `Malware`/`ThreatActor`/`Tool` nodes with zero-width / bidi-control / variation-selector chars in their `name` (created BEFORE the PR-N29 L1 placeholder filter landed) |

