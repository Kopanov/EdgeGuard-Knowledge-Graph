# EdgeGuard Knowledge Graph Schema

> **Node/relationship property reference:** See [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) for complete Cypher schemas and property types.

## Overview

The EdgeGuard knowledge graph is designed to be **backward compatible with ResilMesh/CRUSOE** while extending it with sector-aware threat intelligence.

---

## Sector Architecture

EdgeGuard partitions the knowledge graph by **three sectors** plus a **central OSINT backbone**:

```
 Healthcare (:Healthcare)  |  Energy (:Energy)  |  Finance (:Finance)   ← 10K-100K nodes each
───────────────────────────┴────────────────────┴──────────────────────
       Central OSINT Backbone (zone ['global'], no sector label)
       (Generic threats, Windows zero-days, general IOCs)
```

---

## Node Types (ResilMesh Compatible + EdgeGuard Extensions)

### ResilMesh Core Layers

| Layer | Nodes |
|-------|-------|
| Threat | `Vulnerability`, `CVE` |
| Host | `Host`, `SoftwareVersion`, `NetworkService` |
| Network | `Node`, `IP`, `DomainName`, `Subnet` |
| Flow | `Flow` |

### EdgeGuard Threat Layer Extensions

| Node | Description |
|------|-------------|
| `ThreatActor` | APT groups, threat actors. Named only by a name: no composite, description or country name, and no adversary name that the same OTX pulse also lists as its malware family, unless the canonical reference knows the actor (see [Threat-actor names](#threat-actor-names)). A group ATT&CK revoked (UNC2452, APT34, …) is not a node; its name and aliases are aliases of the group that replaced it (see [Revoked and deprecated ATT&CK objects](#revoked-and-deprecated-attck-objects)). `description`: ATT&CK's text, none on an actor only OTX names |
| `Malware` | Malware families, trojans, ransomware. Named by the family name without an ATT&CK software id suffix: OTX's `"Cobalt Strike - S0154"` is the ATT&CK node `cobalt strike` (see [Malware named after an ATT&CK software id](#malware-named-after-an-attck-software-id)). `description`: ATT&CK's text, none on a family only OTX names |
| `Tool` | MITRE ATT&CK tools (Mimikatz, Cobalt Strike, etc.). `description`: ATT&CK's text |
| `Technique` | MITRE ATT&CK techniques (T1566, T1059, etc.). A technique ATT&CK revoked is not a node, and a feed's link to its id lands on its successor; a deprecated one stays, with `deprecated = true`. `is_subtechnique` is true for a dotted id (T1059.001) and false otherwise, read from the id because the MISP round trip carries no flag |
| `Tactic` | MITRE ATT&CK tactics (Initial Access, Execution, etc.). `description`: ATT&CK's text |
| `Campaign` | EdgeGuard's grouping of one threat actor's malware and those malware's active indicators, built by the enrichment job `build_campaign_nodes`, one per actor (`"<actor> Campaign"`). It rests on the links between the actor and a malware: the malware is attributed to the actor (`ATTRIBUTED_TO`) or the actor uses it (`USES_MALWARE`: MITRE's explicit `uses`, curated-package claims); `src/campaign_evidence.py` holds the definition. An actor with either link and an active indicator of such a malware gets a campaign. A campaign EdgeGuard created whose actor has neither link left, or whose actor the actor alias merge folded into another (no actor of its name remains), is deleted with its links in the same run; on a `Campaign` node a partner created, only EdgeGuard's links are removed; one with evidence whose indicators all expired stays, `active = false`. Its `uuid` is computed from the actor's name, so a campaign built again keeps it |
| `Indicator` | IOCs: IP addresses, domains, URLs, file hashes, TLS certificate fingerprints, … — keyed by `(indicator_type, value)`; `indicator_type` is `ipv4` / `ipv6` (MISP `ip-src` / `ip-dst` are resolved by the address), `domain`, `url`, `email`, `hash` (every file digest), `x509-fingerprint-sha1` (SSL Blacklist), `filename`, … as mapped by the sync's `TYPE_MAPPING`. The one label that ages, whoever supplied it (see [Indicator aging](#indicator-aging)): `last_reported_at`, `last_reported_source`, `last_reported_ref`, `last_reported_basis`, `last_recorded_at`, `source_confidence`, `aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `aging_evaluated_at`, `active`, `retired_at`, `retired_by` |

---

## Relationship Types

| Relationship | From → To | Source / Confidence |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | ThreatActor → Technique | **Attribution.** `match_type='mitre_explicit'` (0.95) from MITRE STIX `uses` → `uses_techniques`; `match_type='otx_pulse'` (0.6) from OTX pulse `attack_ids` → `reported_techniques`. Q5 runs before Q5b so a pair MITRE asserts keeps the explicit stamp. `match_type='misp_attribute_tag'` (attribute tag, sync): an ATT&CK technique tag on the actor's MISP attribute, at the attribute's confidence (see "Evidence labels"). |
| `IMPLEMENTS_TECHNIQUE` | Malware → Technique | **Capability.** `match_type='mitre_explicit'` (0.95) via `uses_techniques`; `match_type='otx_pulse'` (0.6) via `reported_techniques`. |
| `IMPLEMENTS_TECHNIQUE` | Tool → Technique | **Capability.** MITRE STIX explicit `uses` relationship (confidence 0.95) |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `match_type='exact'` (1.0): the malware's own `m.attributed_to` claim matched exactly against `a.name` OR `a.aliases` (the "Cozy Bear → APT29" path; `build_relationships.py` Q2). The `aliases` of `ThreatActor` and `Malware` nodes survive the MISP round trip as `alias:` tags; ATT&CK's malware aliases come from `x_mitre_aliases`. `match_type='otx_pulse'` (0.6): malware and actor named in the same OTX pulse, written by the MISP→Neo4j sync; the pulse is in `r.source_refs[]` (`alienvault_otx:<pulse id>`). Only from a pulse whose actors are one actor: a pulse naming several actors does not say which malware is whose, so it attributes nothing; the aliases of one actor count as one (canonical threat-actor reference). The OTX collector decides it on the pulse's whole adversary list (MISP holds each actor once, so a later event may carry only some of a pulse's actors) and marks the pulse's items (`several_actor_pulses`); the mark accumulates on the indicators (`i.several_actor_pulses[]`), and step 2d takes as naming several actors both the pulses whose actor nodes are several actors and the pulses marked there, as the collector judged them with the canonical reference (the actor nodes miss a pulse edited to name several actors after its pairs were written; its mark reaches the indicators through the pulse's new IOCs, and the MISP writer adds no mark to a stored copy, because MISP keeps what the sources said, so a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit to be closed by a per-pulse MISP record; a mark judged by name without the reference serves the sync's own run and is not stored). `build_relationships` step 2d links the pairs the indicators carry (`family::adversary::pulse`) to the adversary or its canonical actor, removes the attributions an earlier run made from such pulses (unless another feed asserts them) and drops such pulses from the provenance of the others. `match_type='misp_attribute_tag'` (attribute tag, sync): a threat-actor tag on the malware's MISP attribute, at the attribute's confidence (see "Evidence labels"). No attribution is derived from co-occurrence in a whole MISP event. |
| `INDICATES` | Indicator → Malware | `match_type='malware_family'` (0.8): source-asserted family name match (ThreatFox, MalwareBazaar or Feodo Tracker, Q9; VirusTotal and OTX send no family label, and OTX is not named in `r.sources` of a Q9 link) **and** `match_type='otx_pulse'` (0.6): same-run pairing by the sync, and — for regular updates — Q9b from the families the pulse stamps on each indicator (`pulse_malware_families`, looked up by the name as given and without an ATT&CK software id suffix, each through the node the twin merge folded that name into); indicator and malware listed in the same OTX pulse (sync path). `match_type='misp_attribute_tag'` (attribute tag, sync): a `malware-type:` or malware galaxy tag on the indicator's MISP attribute, at the attribute's confidence (see "Evidence labels"). No link is derived from co-occurrence in a whole MISP event. |
| `INDICATES` | Indicator → CVE | `match_type='otx_pulse'` (0.6): the indicator and the CVE are named in the same OTX pulse (the CVE as an OTX indicator of type CVE or as one of the pulse's `cve_references`), written by the MISP→Neo4j sync's report-scoped build with the same provenance as the same-pulse `INDICATES` to Malware: `r.sources = ["alienvault_otx"]`, the pulse in `r.source_refs[]` (`alienvault_otx:<pulse id>`), the MISP event in `r.misp_event_ids[]`. The link says "named in the same report", not that the indicator exploits the CVE (that is `EXPLOITS`, the indicator's own CVE tag). The `CVE` node is matched by `cve_id` and never created by the link. At most 50 CVEs and 2,000 indicators of one pulse are paired: the first ones in the event's attribute order, so a full and an incremental sync pair the same ones. Limit: the pair is built from the items of one MISP event; an indicator or CVE MISP already holds from an earlier pulse is not pushed again with a later pulse, so the later pulse links it to nothing. |
| `EXPLOITS` | Indicator → Vulnerability/CVE; ThreatActor / Malware → CVE | Indicator: CVE tag on the indicator, exact match (`match_type='cve_tag'`, 1.0); never produced from event co-membership, and never from a shared report (an indicator and a CVE named in the same OTX pulse are `INDICATES`, row above); no collector writes such a tag. ThreatActor / Malware → CVE: a curated package's claim (`match_type` = the package's curated label, 0.85) — the link that joins EdgeGuard's threat side to the CVE node ResilMesh's `Vulnerability → REFERS_TO → CVE` path ends on. |
| `REFERS_TO` | Vulnerability ↔ CVE | Bidirectional bridge by `cve_id` (`enrichment_jobs.bridge_vulnerability_cve`); both directions carry the vulnerability record's provenance |
| `RUNS` | ThreatActor → Campaign | `build_campaign_nodes()`; `campaign_grouping`, the confidence of the actor's strongest link to a malware (`ATTRIBUTED_TO` or `USES_MALWARE`); `r.evidence_types[]` names the types of those links; recomputed on every run from the actor's current links, and removed when it comes from an actor that is not the campaign's or has neither link (a campaign whose actor has none left is deleted) |
| `PART_OF_CAMPAIGN` | Malware, Indicator → Campaign | `build_campaign_nodes()`; a malware is a member while it is attributed to the campaign's actor or used by it (`USES_MALWARE`), an indicator while it `INDICATES` a member (the 100 newest active ones, each once); `campaign_grouping`, the confidence of the malware's strongest link to the actor (malware) or of the indicator's best path, `INDICATES` then `ATTRIBUTED_TO` or `USES_MALWARE`, each path as strong as its weaker link (indicator); `r.evidence_types[]` names the relationship types it rests on, e.g. `["ATTRIBUTED_TO", "USES_MALWARE"]` on a malware, `["INDICATES", "USES_MALWARE"]` on an indicator (not `PART_OF`, because ResilMesh uses `PART_OF` for its asset hierarchy, and one name must have one meaning in the shared database) |
| `INVOLVES` | Alert → Indicator | `neo4j_client` alert path (`alert_processor`, NATS) — not part of the collector pipeline; excluded from the acceptance script's policed types |
| `USES_TECHNIQUE` | Indicator → Technique | "The OTX report this indicator came from lists this technique" (not that the indicator executed it). OTX pulse `attack_ids` exact MITRE ID match (`match_type='otx_attack_ids'`, 0.6: the ids are the pulse's, so the link has the confidence of every other link from them); an id ATT&CK revoked matches its successor |
| `AFFECTS` | Vulnerability/CVE → Sector | "The vulnerable product is used in this sector." Zone list unwind, per sector only the feeds whose `SOURCED_FROM.zones` give it; `advisory_sector`, 0.9, where CISA's ICS advisory states the sector (deployed in it), else `zone_classification`, 0.5 (inferred sector; an OTX pulse's industries never label AFFECTS: a targeted industry says nothing about where a product is deployed); `global` never linked |
| `TARGETS` | Indicator / ThreatActor / Malware → Sector | "Reported in connection with attacks on this sector." Zone list unwind, per sector only the feeds that gave it; `otx_industries`, 0.6, where an OTX pulse's own `industries` name the sector (the report's author states that its campaign targets it), else `zone_classification`, 0.5 (inferred sector, the pulse's keyword hits included; a CISA deployment statement never labels TARGETS); `global` never linked |
| `IN_TACTIC` | Technique → Tactic | Kill-chain phase exact match (confidence 1.0) |
| `SUBTECHNIQUE_OF` | Technique → Technique | Sub-technique → parent from MITRE's dotted id (`T1021.006` → `T1021`); `mitre_explicit`, 1.0 |
| `USES_MALWARE` | ThreatActor → Malware | MITRE's explicit group → malware `uses`; `mitre_explicit`, 0.95; curated-package claims, 0.85. Campaign evidence like `ATTRIBUTED_TO` |
| `USES_TOOL` | ThreatActor → Tool | MITRE's explicit group → tool `uses`; `mitre_explicit`, 0.95 |
| `HAS_CVSS_v2/v30/v31/v40` | CVE ↔ CVSS sub-nodes | Bidirectional (ResilMesh schema; `_merge_cvss_node` writes both directions) |
| `SOURCED_FROM` | Node → Source | **Per-source provenance edge.** ONE edge per (entity, source) pair (multi-source IOCs preserve full provenance). See [SOURCED_FROM edge schema](#sourced_from-edge-schema) below for the full property contract. |

`src/build_relationships.py` builds the derived links in 20 steps, each logged as `[LINK] <step>/20`: 1 `IN_TACTIC`, 1b `SUBTECHNIQUE_OF`, 2 `ATTRIBUTED_TO` (exact name match), 2b `USES_MALWARE`, 2c `USES_TOOL`, 2d `ATTRIBUTED_TO` (same OTX pulse), 3a / 3b `EXPLOITS` (Indicator → Vulnerability / CVE), 5 / 5b `EMPLOYS_TECHNIQUE` (ATT&CK / source report), 6 / 6b `IMPLEMENTS_TECHNIQUE` from Malware (ATT&CK / source report), 7a–7d the links to a `Sector` (Indicator `TARGETS`, Vulnerability/CVE `AFFECTS`, ThreatActor `TARGETS`, Malware `TARGETS`), 8 `USES_TECHNIQUE`, 9 / 9b `INDICATES` (family label / same OTX pulse) and 10 `IMPLEMENTS_TECHNIQUE` from Tool. The queries named Q2, Q5, Q5b, Q9 and Q9b in this document are the steps of those numbers.

### SOURCED_FROM edge schema

Every threat-intel node (Indicator, CVE, Vulnerability, Malware, ThreatActor, Technique, Tactic, Tool) carries one `(:Node)-[r:SOURCED_FROM]->(:Source)` edge per reporting source. The edge holds both DB-local facts (when EdgeGuard saw this source report this entity) AND the source's own claim (when the source itself says it first/last recorded the entity). Per-source attribution preserves full provenance for multi-source IOCs.

| Property | Semantic | Type | Write rule | Source |
|---|---|---|---|---|
| `r.imported_at` | When EdgeGuard FIRST saw THIS source report this entity | DateTime | `ON CREATE SET = datetime()` (set once per edge, never overwritten) | DB-local |
| `r.updated_at` | When EdgeGuard LAST saw this source report it | DateTime | `SET = datetime()` on every MERGE (always current) | DB-local |
| `r.source_reported_first_at` | Source's own claim about when it first recorded the entity (NVD `published`, CISA `dateAdded`, MITRE `created`, ThreatFox `first_seen`, AbuseIPDB `firstSeen`, etc.) | Optional DateTime | MIN CASE with NULL short-circuit: earliest claim wins; stale imports cannot regress | Source claim |
| `r.source_reported_last_at` | Source's own claim about when it last recorded the entity | Optional DateTime | MAX CASE with NULL short-circuit: latest claim wins | Source claim |
| `r.confidence` | Per-source confidence score for THIS observation | Float | `SET = $confidence` every MERGE | Per-collector |
| `r.source` | Source identifier (string copy of source_id; redundant with `s.source_id` but cached on edge for performance) | String | `SET = $source_id` every MERGE | Per-collector |
| `r.misp_event_ids` | The MISP events in which THIS source carried the entity | List of strings | Accumulated (deduplicated) on every MERGE; never replaced | MISP |
| `r.source_refs` | THIS source's own record ids for the entity, `"<source>:<id>"` (OTX pulse, ThreatFox IOC id, URLhaus entry, ATT&CK id; the CISA ICS advisories that name the CVE, `cisa_ics:ICSA-…`). Links derived after the sync copy these two lists from the subject node's edge (see "Relationship provenance" below) | List of strings | Accumulated (deduplicated) on every MERGE; never replaced | Per-collector |
| `r.zones` | The zones THIS source's records gave the entity. The node's `zone` is the union over its sources; `build_relationships` steps 7a–7d name on a link to a `Sector` only the feeds whose `zones` contain that sector | List of strings | Accumulated on every MERGE with the node's rule: `global` dropped once a sector is present, sorted | MISP zone tags of the source's attribute |
| `r.stated_zones` | The part of `zones` THIS source stated itself rather than EdgeGuard inferring it (`src/sector_evidence.py`): for `cisa_ics`, every sector its advisories name (an `AFFECTS` link to it carries `advisory_sector`); for `alienvault_otx`, the sectors the pulses' own `industries` map to (`config.OTX_INDUSTRY_ZONE_ALIASES`; a `TARGETS` link to it carries `otx_industries`), not the sectors keyword detection found in the pulse text; for every other source, none | List of strings, absent when empty | Accumulated (sorted set) when the record states a zone | Source statement |
| `r.stated_refs` | Which of THIS source's records stated which of `stated_zones`, as `"<zone>\|<source ref>"`: for `cisa_ics`, the advisories whose sector note names each sector (`healthcare\|cisa_ics:ICSMA-26-283-01`); for `alienvault_otx`, the pulses whose industries name it (`energy\|alienvault_otx:<pulse id>`). A link to a `Sector` cites only the records recorded for its sector; an edge without an entry for the sector (a sector the source inferred, or an inferring source) gives all of its `source_refs` | List of strings, absent when empty | Accumulated (sorted set) when the record states a zone | `NVD_META.advisory_zones`; the OTX item's `pulse_id` with its `otx_industries`, and its `report_stated_zones` |
| `r.raw_data` | Full source-specific payload as JSON (audit trail for one (entity, source) observation) | String (JSON) | `ON CREATE SET = $raw_data`; on a `CVE` also `SET` on every write from a MISP attribute, so the edge holds the source's latest record (a KEV or NVD copy edited in MISP reaches it at the next sync); on other labels, and against the reduced record of the opt-in STIX import (`run_pipeline --stix-flow`, written under the MISP event's source id), the record that created the edge | Per-collector |
| `r.src_uuid` | Indicator/CVE/Malware/etc. node UUID (cached on edge for serialized-edge consumers — RAG / xAI use cases) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.trg_uuid` | Source node UUID (cached on edge, same rationale as `src_uuid`) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.edgeguard_managed` | Always `true` for edges EdgeGuard owns; allows STIX export to filter against ResilMesh-owned data | Boolean | `SET = true` every MERGE | DB-local |
| `r.last_reported_at`, `r.last_reported_ref`, `r.last_reported_source` | Indicator edges: THIS source's latest report of the indicator, `min(T, coalesce(L, T))` (T the MISP attribute timestamp, L the source's `last_seen`), the MISP attribute uuid of that report and the source id ([Indicator aging](#indicator-aging)) | Optional DateTime, strings | Forward only: set when the report is newer (an equal time with a smaller uuid takes the reference) | MISP / source claim |
| `r.last_recorded_at` | Indicator edges: the latest MISP timestamp of THIS source's attributes for the indicator | Optional DateTime | MAX CASE with NULL short-circuit | MISP |

**Why per-source on edges, not aggregates on nodes?** A single Indicator may be reported by multiple sources (NVD + AbuseIPDB + ThreatFox), each with its own claim. Aggregating to a node-level value via MIN/MAX would destroy the per-source detail. Queries that want a single canonical value compute `MIN(r.source_reported_first_at)` / `MAX(r.source_reported_last_at)` across edges on read (STIX `valid_from`, alert enrichment, campaign aggregate all do this). Read-side aggregation is cheap (~9 edges max per indicator); write-side per-source isolation prevents cross-source contention.

**Honest naming.** `source_reported_first_at` makes explicit "what the source claims to have first recorded", NOT "first observed in the wild". Sources record catalog dates: NVD's `published` is when NVD published the CVE record (after the vuln was actively exploited); MITRE's `created` is when MITRE added the SDO to its TAXII store; etc.

**MIN/MAX merge semantics handle every realistic ordering scenario** — see `src/source_truthful_timestamps.py` module docstring or `migrations/2026_04_first_seen_at_source.md` for the full scenario walkthrough (baseline + incremental + out-of-order + stale-import + multi-source).

**Timestamp invariants.** Every value flowing into `r.source_reported_first_at` / `r.source_reported_last_at` is **either NULL or tz-aware ISO-8601 UTC**. Mixing naive and aware values would corrupt the MIN/MAX comparison since Neo4j parses naive ISO strings as **server-local** time. The canonicalization chokepoint is `coerce_iso()` in `src/source_truthful_timestamps.py`. Producers MUST emit honest NULL when the source field is absent — never wall-clock NOW. The complete semantic model is documented in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md).

### Relationship provenance: who asserts a link

Every relationship EdgeGuard builds from the threat-intelligence sources carries three lists. Each write adds to them and never replaces them, so no source can erase another's claim, and a link can be traced from Neo4j to the MISP event and to the source's own record. The contract and the shared Cypher fragments live in `src/relationship_provenance.py`.

| Property | Meaning | Example |
|---|---|---|
| `r.sources[]` | The sources that assert the link: canonical ids from `src/source_registry.py` (`alienvault_otx`, `mitre_attck`, `nvd`, `cisa_kev`, `threatfox`, `urlhaus`, `malwarebazaar`, `feodo_tracker`, `ssl_blacklist`, `virustotal`, `abuseipdb`, `cisa_ics`, `misp`, and the curated sources `coreideas`, `misp_galaxy`). An unregistered name is kept as given, except on a curated claim: only a registered curated source may assert one, any other is recorded as `curated_other`. | `["mitre_attck", "alienvault_otx"]` |
| `r.source_refs[]` | The sources' own record ids, `"<source>:<id>"`, for sources that have one: the OTX pulse, the ThreatFox IOC id, the URLhaus entry, the ATT&CK id. Sources keyed by the value itself (NVD and KEV by CVE id, MalwareBazaar and VirusTotal by hash, Feodo Tracker and AbuseIPDB by IP, SSL Blacklist by certificate fingerprint) need none: the node is the record. | `["mitre_attck:G0016", "alienvault_otx:5f3c…"]` |
| `r.misp_event_ids[]` | The MISP events that carried the link. The list accumulates: a link the sync writes adds its event; a link derived after the sync (`build_relationships`, the Vulnerability↔CVE bridge) adds at most 200 per write (on a link to a `Sector`, the 200 newest by MISP event id of the feeds that gave the sector). On a campaign link, whose lists are replaced on every run, the 200 newest by MISP event id, with `r.sources[]` and `r.source_refs[]` sorted, so the same MISP data gives the same lists whatever the order in which the links it rests on were created. | `["137", "141"]` |

**Links to a Sector.** A node's `zone` is the union of the zones its sources gave, so a link to one of them names only the sources that gave that sector: `build_relationships` steps 7a–7d read the node's `SOURCED_FROM` edges whose `zones` contain the sector (`relationship_provenance.zone_prov_with`) and take `r.sources`, `r.source_refs` and `r.misp_event_ids` from them alone (the events by the fixed sorted rule); of an edge that records its references per sector (`stated_refs`: CISA ICS, and OTX for the sectors a pulse's industries state) only the references of that sector, so a CVE that an ICS advisory names for Energy and a medical advisory for Healthcare cites the first on its energy link and the second on its healthcare link, as the sync's rows do, and a sector OTX pulses' industries state cites those pulses (a sector inferred from a pulse's text cites every pulse on the edge). A `SOURCED_FROM` edge without `zones`, and a feed of the node without a `SOURCED_FROM` edge (the alert path), count as giving every zone of the node. A node sector no feed gave is not linked; the step counts it (`[SKIP]`) and the acceptance check `node_sectors_without_a_feed` reports it. The label is the strongest statement label among the feeds that stated the sector, else `zone_classification`, and the confidence is the value the label table gives it (`src/sector_evidence.py`): the sync and the step agree, and a stored stronger label and a label outside the table (a curated or partner label) are kept. A link the sync or a step labels with a stronger label than the stored one takes it (the batched writer keeps the label of the row whose confidence reaches the stored one), so a link one record states and another infers carries the statement whatever the order of the writes. The OTX pulse's industries reach the sync on the indicator (`OTX_META.otx_industries`) and on the malware family and adversary (`MITRE_USES_TECHNIQUES.ind`), and the sectors the later pulses of the run that listed the same item state travel with it (`OTX_META.report_stated_zones`, `MITRE_USES_TECHNIQUES.rsz`), so within a run the statement does not depend on which pulse listed the item first. MISP keeps the attribute written first, so a node's OTX statement is that of the pulses of the run that wrote its attribute: a pulse of a later run that lists the item adds neither its id nor its statement. The actor alias merge and the Malware twin merge combine `zones`, `stated_zones` and `stated_refs` of two folded edges to one source and keep them sorted lists, and parallel links collapse with the strongest label.

`r.match_type` is the kind of evidence (next section); several sources can share one kind (ThreatFox, MalwareBazaar and Feodo Tracker all give the indicator's family label, `malware_family`), and the strongest evidence keeps the label and the confidence. A `malware_family` link names only the indicator's feeds that give the label (ThreatFox, MalwareBazaar, Feodo Tracker; `FAMILY_LABEL_FEEDS` in `src/relationship_provenance.py`), or every feed of the indicator when none of its feeds is one of them (a family set by another writer); OTX is added to it, with the indicator's OTX pulses and MISP events, when a pulse that listed the indicator names the family by the `Malware` node's name, by that name with an ATT&CK software id, or by a name the twin merge folded into the node (`merged_from`; step 9b, which looks families up as the `INDICATES` row says), not when it names it only by another alias of the node, which Q9 matches. Links the sync writes directly get the three lists from the MISP attribute; links derived afterwards (`build_relationships.py`, campaign and Vulnerability↔CVE links in `enrichment_jobs.py`) copy them from the subject node's per-source `SOURCED_FROM` edge, which carries the same `misp_event_ids[]` and `source_refs[]` for that source, or inherit them from the links they are built on (campaign links replace theirs on every run with the provenance of the links they currently rest on — the `ATTRIBUTED_TO` and `USES_MALWARE` links, and the indicator's `INDICATES` links, named in `r.evidence_types[]` — so they name no evidence `build_relationships` step 2d removed or trimmed). Corroboration is countable: `size(r.sources) >= 2` means independent sources state the link.

**Explainability: what the source said, where the graph says something else.** Two cases make the graph name a target differently from the source, and both are recorded, so a reader can tell what was claimed from what EdgeGuard derived:

| Property | Meaning | Example |
|---|---|---|
| `r.cited_ids[]` | On a technique link (`USES_TECHNIQUE`, `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`): the ATT&CK ids the sources cited that ATT&CK has since revoked into the link's technique (see "Revoked and deprecated ATT&CK objects"). Accumulated, de-duplicated; absent when every source cited the technique's own id. Written by `build_relationships` (steps 5, 5b, 6, 6b, 8, 10), by the sync for MISP technique tags, and for curated claims. | An OTX pulse cited `T1562` (Impair Defenses), which ATT&CK revoked into `T1685`: the link to `T1685` carries `["T1562"]` |
| `r.evidence_types[]` | On a campaign link (`RUNS`, `PART_OF_CAMPAIGN`): the relationship types of the links it rests on, sorted: `ATTRIBUTED_TO` and `USES_MALWARE` between the actor and a malware, and `INDICATES` on an indicator's link. Recomputed on every run with the link's confidence and provenance. | `["ATTRIBUTED_TO", "USES_MALWARE"]` on the `RUNS` of an actor with both kinds of link |
| `n.merged_from[]` | On a `ThreatActor`: the names of the duplicate nodes the actor alias merge folded into this one; on a `Malware` node: the names of the ATT&CK-id twins the twin merge folded into it, which steps 9b / 2d resolve to this node. Unlike `aliases`, which also hold every source's aliases, it names only the merges, so a wrong merge can be traced and undone. Accumulated across merges. | `clop` carries `["cl0p"]`; `cobalt strike` carries `["cobalt strike - s0154"]` |

Together with `r.sources[]` and `r.source_refs[]`, a link reads in full: "the OTX pulse 5f3c… cited T1562, which ATT&CK revoked into T1685". The STIX export carries both (`x_edgeguard_cited_ids` on SROs, `x_edgeguard_merged_from` on intrusion-sets; extension definition 1.3.0), and the evidence types of campaign links (`x_edgeguard_evidence_types`; extension definition 1.5.0).

### Curated packages

A curated package is a set of claims about entities already in the graph (actor uses technique / malware / tool, malware implements technique, actor or malware exploits CVE), imported once into MISP as its own EdgeGuard event with `scripts/import_curated_package.py` (validate, then `--push`; see the script's docstring for the JSON format). Each `threat-actor` / `malware-type` attribute names an existing node by its canonical name and carries the node's claims in a `CURATED_CLAIMS:` comment. The MISP→Neo4j sync turns every claim into a relationship of an existing type (`EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`, `USES_MALWARE`, `USES_TOOL`, `EXPLOITS`), MATCHing both ends by exact canonical name or id. A curated attribute is not merged as a node at all: a package never creates nodes and never changes the node it names; its provenance lives on the relationships. Labels and provenance:

- **Label and confidence on the links a claim creates only.** A link the claim creates gets the package source's curated label from the source registry (`coreideas` → `coreideas_curated`; `curated_other` for a curated source without a label of its own, e.g. `misp_galaxy`) and confidence 0.85. A link that already exists keeps its `match_type` and `confidence_score` (an `otx_pulse` link stays `otx_pulse` at 0.6, a `mitre_explicit` link stays `mitre_explicit`); the claim adds its source to `r.sources`, its record id to `r.source_refs` and the package's event to `r.misp_event_ids`. `match_type` therefore shows which links a package created, not every link it asserts.
- `r.sources` = the source that asserts each claim (a package may carry claims from several sources, e.g. `misp_galaxy`), `r.source_refs` = that source's record id. Only registered curated sources (`source_type="curated"` in `src/source_registry.py`: `coreideas`, `misp_galaxy`) may assert a claim: the importer rejects a claim from any other source, and the sync records one that still arrives as `curated_other`.
- `r.tlp` = the package's TLP level (required by the importer and tagged on every attribute), on every link a claim touches, most restrictive wins. Only curated links carry `r.tlp`. The STIX export marks each relationship with the most restrictive of its endpoints' markings and `r.tlp`.
- A claim attaches only when both ends exist by exact name or id. The sync counts the claims that did not attach (`curated_claims_unattached` in the sync stats), logs them with a sample of the missing names (`[CURATED]` lines) and never counts them as created relationships.
- **Leaving the layer out of a shared dataset:** select by `r.sources`, not by `r.match_type`. Keep the links with at least one non-curated source, `any(s IN r.sources WHERE NOT s IN ['coreideas', 'misp_galaxy', 'curated_other'])`, and drop the curated entries from their `sources` / `source_refs` and their `tlp`: a link a package did not create keeps its own label, so `match_type` does not show that a curated source also asserts it.
- Removing the layer from a live graph: `docs/RUNBOOK.md`, "Importing a curated package".

### Threat-actor names

A `ThreatActor` node is created only from a name. OTX's free-text `adversary` field and hand-typed MISP threat-actor attributes also carry lists, descriptions and places, so names pass two rules before a node is written:

- **Name hygiene** (`src/actor_name_hygiene.py`, `clean_actor_names`; the OTX collector, the MISP→Neo4j sync, and the reference builder for synonyms). A composite is split (`"apt-c-13, sandworm, frozenbarents"`, `"head mare and twelve"`), a trailing parenthetical is dropped (`"kimsuky (apt43)"` → `kimsuky`) or, behind a country, kept as the name (`"north korea (apt37)"` → `apt37`), and a name is dropped when it is a description (`"multiple russian state-backed groups"`, `"russia-nexus apt"`, `"unknown"`) or, as the whole name, a country or state or a nationality adjective (`COUNTRY_AND_STATE_NAMES`: the ISO 3166 short names, state forms such as `dprk`, `prc`, `usa`, `u.s.`, `russian federation`, `people's republic of china`, and territories such as `taiwan`, `gaza`, `crimea`, `kosovo`; `NATIONALITY_ADJECTIVES`: `russian`, `north korean`, `iranian`), compared without case, apostrophes, dots or hyphens (`u.s.`, `n. korea`, `north-korea`, `peoples republic of china`; `"korea, north"` is one name). A country names where an actor is said to be from, not which actor: `"APT37, North Korea"` is the one actor `apt37`. A name that contains a country stays a name (`cyber army of russia reborn`, `anonymous sudan`). The sync skips a threat-actor attribute whose name is not a single clean name. No entry of the country, state or nationality lists is a name the canonical threat-actor reference resolves. A test checks every key and synonym of the reference and pins the five that the description rules already judge generic: `hacking team` (rule (b4) reads both words as descriptors, so an adversary or attribute named `Hacking Team` creates no node) and placeholder records such as `unnamed actor`; a list change that makes another reference name generic fails it.
- **An adversary the same pulse lists as a malware family** (OTX collector). It is an actor only when the canonical threat-actor reference resolves it: `kimsuky`, `akira`, `qilin` or `medusa` stay actors; `lumma stealer`, `asyncrat`, `agent tesla` or `lockbit` are not actors from that pulse and remain the pulse's `Malware` node. Names are compared by actor key, the family also without its ATT&CK software id or a trailing parenthetical (`"Lumma Stealer (LummaC2)"`). A name the reference lists as ambiguous or never_merge (`winnti`, `golden chickens`, `lumma stealer`) does not resolve and counts as unknown. On the graph of 2026-10-18, 181 of 859 actor names were also malware names, 34 of them known to the reference. A name that only another pulse lists as a family stays an actor. Without the reference the name is kept.

Both act before the collector decides whether the pulse names one actor or several ([`ATTRIBUTED_TO`](#relationship-types) above), so a country or a family named in the adversary field does not make a pulse name several actors. An actor the second rule leaves out because the reference lacks it is added through the reference's overrides file (`src/reference/canonical_threat_actor_overrides.json`, a `merge` decision; `docs/RUNBOOK.md`, "Canonical threat-actor reference"). The name hygiene does not read the reference: an actor whose whole name is a country or state is kept only by taking that name out of `COUNTRY_AND_STATE_NAMES`.

### Actor alias merge and canonical threat actors

One actor reaches the graph under several names (`lazarus` from OTX, `lazarus group` from ATT&CK), so its evidence splits across `ThreatActor` nodes. The enrichment job `merge_alias_duplicate_actors` folds the duplicates into one node after every sync, before the Campaign builder. Two rules propose a (canonical, duplicate) pair:

- **ATT&CK aliases.** A node that is not MITRE-sourced and whose name is an alias (`c.aliases`) of exactly one MITRE-sourced node; a name that is an alias of several is skipped.
- **The canonical threat-actor reference.** `src/reference/canonical_threat_actors.json` is built by `scripts/build_canonical_threat_actors.py` from the ATT&CK groups and the public MISP threat-actor galaxies (CC0), plus reviewed decisions, and is versioned by date. It gives every name it knows one place: the key of one canonical actor (for an ATT&CK group, the name EdgeGuard writes for it), a synonym of one actor, or `ambiguous` (several actors, or a reviewed never_merge). A node that is not MITRE-sourced and whose name resolves to another canonical key that is a node on the graph is a duplicate of it (`cl0p` → `clop`, `sandworm` → `sandworm team`). Ambiguous and never_merge names are never resolved.

A MITRE-sourced node is never a duplicate, and two ATT&CK groups are never merged. ATT&CK groups that ATT&CK revoked into another stay as their own nodes; the reference resolves their names to the successor. A node the two rules give different canonicals, and a node that would be both a canonical and a duplicate in the same run, are skipped and counted (`skipped_conflict`, `skipped_chain`).

The reference also checks the ATT&CK-alias pairs. A canonical's `aliases` hold ATT&CK's aliases and every name merged into it earlier, so the ATT&CK rule alone would keep folding a name a reviewer has since marked never_merge. A pair whose duplicate the reference marks ambiguous or never_merge is skipped (`skipped_blocked`), and a pair whose duplicate it gives to another actor, or keeps as an actor of its own, is a conflict. A name the reference does not list is left to the ATT&CK rule.

A merge adds the duplicate's name to the canonical's `aliases` and to `merged_from` (only the names this job folded in), moves all of its relationships to the canonical (`apoc.refactor.mergeNodes`: scalars keep the canonical's value, lists are combined; `tlp` is first set to the most restrictive level of the canonical and its duplicates, so a merge never loosens it), re-stamps their `src_uuid` / `trg_uuid` with the canonical's uuid, and removes the duplicate node. Parallel relationships (same type, same other node, same direction) collapse into one: it keeps the union of their `sources`, `source_refs`, `misp_event_ids` and `cited_ids`, and the strongest evidence's `match_type` and `confidence_score` (on a tie the alphabetically first label), the rule every writer follows, and the most restrictive `r.tlp` of the group (curated-package links carry one). APOC stores two equal merged values as one string (two OTX names of one actor both hold `source = ["alienvault_otx"]`); the merge wraps every list property of the node, and the provenance lists of its edges, back into lists. The Campaign builder then rebuilds the canonical's campaign and deletes the duplicate's, because no actor of its name remains. When the reference file is missing, unreadable or inconsistent, or its data cannot be applied to the graph's names, the job logs one warning (`canonical reference unavailable`) and merges by ATT&CK aliases alone. `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false` makes the job a dry run that logs the pairs, the reference pairs included, and merges nothing; `EDGEGUARD_CANONICAL_THREAT_ACTORS` overrides the reference path. Each batch of pairs (`apoc.refactor.mergeNodes`, the uuid re-stamps and the list normalisation) is one transaction: a failed batch is rolled back whole, logged and counted (`errors`), and its pairs merge on the next run. The Malware twin merge runs the same batches.

### Malware named after an ATT&CK software id

OTX names malware families as the MISP ATT&CK galaxy names its clusters, with the ATT&CK software id as a suffix: `"Cobalt Strike - S0154"`, `"njRAT - S0385"`. Kept as given, such a name would become a `Malware` node of its own (`cobalt strike - s0154`) beside the node ATT&CK delivers (`cobalt strike`), and the family's indicators would split between the two. EdgeGuard therefore names a family by its base name at ingest, looks families up under both names, and folds such twins into one node.

- **Ingest.** One helper, `split_attack_software_id` (`src/attack_software_names.py`), turns a name ending in `<whitespace>-<whitespace>S####` (case and extra whitespace ignored) into its base name and the id. The OTX collector names the malware item, its `family`, the indicators' `pulse_malware_families` and the family side of `pulse_malware_actor_pairs` by the base name and keeps the original string in the item's `aliases`. The sync does the same for every `malware-type` attribute (an attribute of another writer; the original string joins `aliases`), for the malware names of MISP galaxy tags (`misp-galaxy:mitre-malware="Cobalt Strike - S0154"`), and for `OTX_META.mf`, `.pa` and `.malware_family`; so does the command-line MISP reader (`misp_collector`), and the sync's own STIX conversion of a `malware-type` attribute, used when PyMISP's conversion is not available (the original string as the STIX object's `aliases`).
- **Lookup under both names.** `build_relationships` steps 9b (`INDICATES`) and 2d (`ATTRIBUTED_TO`) look a family up by its name as given and without the id (`apoc.text.replace` with the pattern as a query parameter), so an indicator that lists `Cobalt Strike - S0154` links the ATT&CK node; until the twin is folded it links both. Each of the two names is first replaced by the node the twin merge folded a node of that name into (`$folded_families`, read once per run from the `merged_from` lists of the `Malware` nodes; an entry that carries an id also stands for its base name; a name that leads to two nodes, or that is an ATT&CK node's own name, is left as it is). A folded node is gone, and a later pulse that names its family is a MISP cross-event duplicate that creates no new node: once `agenttesla` (alias `AgentTesla - S0331`) is folded into the ATT&CK node `agent tesla`, the indicators of a pulse naming `AgentTesla` link `agent tesla`. `merged_from` is written only by the merge jobs, so, unlike `aliases`, no source can redirect a family. The acceptance check `pulse_indicates_complete` looks families up the same way.
- **Folding twins.** The enrichment job `merge_malware_attack_twins` runs after the actor alias merge and before the Campaign builder. A `Malware` node that is not MITRE-sourced and whose name, or an alias of its own name, ends with an ATT&CK software id folds into the MITRE-sourced `Malware` node of that id. The MITRE node carries no `mitre_id`: its id is read from the record MITRE delivered, the `raw_data` of its `SOURCED_FROM` edge to the ATT&CK source, whose description opens with a link to the software (`[Cobalt Strike](https://attack.mitre.org/software/S0154)`), as the canonical threat-actor reference reads group ids. When that id cannot be read, the MITRE node of the same base name is the target; a name whose id contradicts the twin's is not. A revoked software id is translated to its successor first (`Darkmoon - S0209` → PoisonIvy). A twin whose id and base name lead to more than one MITRE node is skipped on every run (`skipped_ambiguous`) and needs a decision by hand. Software without a MITRE `Malware` node has no ATT&CK target: ATT&CK tools such as Mimikatz `S0002` are `Tool` nodes, never merge targets. Such a twin (`mimikatz - s0002`) folds into the non-MITRE `Malware` node of its base name (`mimikatz`, which a pulse creates, since the collectors name a family by its base name) when that node states no other ATT&CK id (`base_name_targets`; twins of one base name that state different ids fold nowhere), because steps 9b / 2d would otherwise link the indicators that list the family with its id to both nodes. A twin with neither target is left as it is and counted (`no_target`) until a pulse creates the node of its base name.
- **The merge** is the actor alias merge's (same statements, built for the `Malware` label): the twin's name joins the target's `aliases` and `merged_from`, `tlp` becomes the most restrictive level of the two, all relationships move to the target (parallel ones collapse with the union of their provenance lists and the strongest evidence), their `src_uuid` / `trg_uuid` are re-stamped, every list property stays a list (`malware_types` is combined as well), and the target keeps its name and uuid. The statement re-checks each target at merge time: a MITRE-sourced node, or a node of a twin's base name the plan chose, into which only a twin named `<its name> - s####` folds. Batched, idempotent; `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE=false` makes it a dry run that logs the pairs (`[MALWARE-TWIN-MERGE]` log lines).
- **Acceptance.** `scripts/verify_fresh_baseline.py` fails `malware_attack_twins_folded` when a twin the job folds (into a MITRE node or into the node of its base name), or one it cannot decide, is still a node; twins without a target are reported.

### Evidence labels, report provenance, TLP

- `r.match_type` states the evidence behind every edge (`mitre_explicit`, `otx_pulse`, `exact`, `malware_family`, `cve_tag`, `otx_attack_ids`, `kill_chain_phase`, `campaign_grouping` for the campaign links EdgeGuard derives, `misp_attribute_tag` (a tag on the MISP attribute itself: an ATT&CK technique tag, a threat-actor tag, or a `malware-type:` or malware galaxy tag; the sync writes it on `EMPLOYS_TECHNIQUE`, `ATTRIBUTED_TO` and `INDICATES` at the attribute's confidence: `confidence:high` 0.8, `confidence:medium` 0.5, `confidence:low` 0.3, default 0.5), for curated packages `coreideas_curated` / `curated_other`, and on links to a `Sector` `zone_classification` (EdgeGuard's inference, 0.5), `otx_industries` (an OTX pulse's own industries state that its campaign targets the sector, 0.6, `TARGETS` only) or `advisory_sector` (CISA's ICS advisory states that the product is deployed in the sector, 0.9, `AFFECTS` only)) — see `docs/RESILMESH_INTEROPERABILITY.md` §3.2.2 for the table with confidences. A query that filters sector links on `match_type = 'zone_classification'` alone misses CISA's and OTX's statements.
- `r.source_refs[]` holds the OTX pulse (`alienvault_otx:<pulse id>`) on report-scoped edges; `n.pulse_ids[]` on `Malware` / `ThreatActor` nodes: the OTX pulse whose attribute created the entity in MISP, plus the other pulses of that collector run that named it (the attribute is written once, so later pulses are not added; they link through `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`); `n.reported_techniques[]` next to `n.uses_techniques[]` (pulse-level vs MITRE-explicit ATT&CK ids).
- `n.tlp` on every EdgeGuard node (from the `tlp:<level>` MISP tag; default `white`). `r.tlp` on curated-package links only: the package's level (see "Curated packages").
- `n.attack_domain` (`enterprise` | `ics`) on `Technique` and `Tactic` (from the `attack-domain:<domain>` MISP tag); `IN_TACTIC` is created only within the same domain. ATT&CK for ICS is ingested when `EDGEGUARD_ENABLE_MITRE_ICS=true` (97 techniques T08xx, 12 tactics TA0100–TA0111, shared groups/malware keep one node with unioned technique lists). `ThreatActor`, `Malware` and `Tool` carry no `attack_domain` (a group or software item in both ATT&CK bundles keeps the Enterprise item), so measure ATT&CK for ICS through the links into ICS techniques (`IMPLEMENTS_TECHNIQUE` / `EMPLOYS_TECHNIQUE` / `SUBTECHNIQUE_OF` to a `Technique {attack_domain: 'ics'}`) and `IN_TACTIC` from an ICS technique to an ICS tactic ([NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md), "Measuring CISA ICS and ATT&CK for ICS").
- `edgeguard_managed = true` on every EdgeGuard edge and on every node EdgeGuard **creates** (stamped on the MERGE create path only; a node a partner created first that EdgeGuard writes to gets `edgeguard_enriched = true` instead) — so `edgeguard clear neo4j --edgeguard-only` removes exactly the nodes EdgeGuard created from a shared database, and the APIs / STIX export expose nodes it created or enriched.
- `CVE` nodes carry `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]`, `reference_urls[]`, `affected_products[]` from NVD (ResilMesh CVE properties), and `status[]`: NVD's record status, `["active"]` or `["rejected"]`, replaced when NVD changes it. When an NVD record is merged into a node EdgeGuard created (`edgeguard_managed`) whose only source is NVD, the six lists are set from it even when empty; on a node with another source (CISA ICS, KEV, OTX) an empty NVD list leaves the property as it is. A record from any other source fills a list only where the node has none; of the other records only CISA ICS gives them, from one attribute per CVE in MISP, so the lists do not depend on the order of the records. A partner write through `merge_resilmesh_cve` is the exception: it sets `cwe`, `ref_tags`, `cpe_type` and `result_impacts` when the call carries them, until NVD's next record ([RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) §5). The trade-off: a revised CISA ICS record does not update the lists of a CVE only CISA ICS names, so its `result_impacts` can then differ from the C/I/A of its CVSS sub-node, which follows the revised record (MISPWriter keeps the first CISA ICS record of a CVE, so no revision reaches the graph).
- **CVSS sub-nodes of a `CVE`.** An NVD record carries every CVSS version NVD supplies. NVD and CISA ICS write the same CVSS sub-node of a CVE and version: once NVD has asserted it (`'nvd'` in `sources` of the CVE's `HAS_CVSS_*` edge to it), it holds NVD's payload and a CISA ICS payload only fills a property it lacks, so the sub-node and the CVE's score are NVD's in either order; a sub-node only CISA ICS asserted follows CISA ICS's record. `sources` and `misp_event_ids` of the edge name every feed and event; the sub-node's `tag` stays that of the first writer. A CVSS sub-node of a version NVD's record drops is removed if NVD alone asserted it, before the node's score is derived from its CVSS sub-nodes; on a sub-node CISA ICS also asserted, NVD leaves `sources` and the record's event leaves `misp_event_ids` of both edges, so CISA ICS's next record sets its values there again (until then it keeps NVD's values; the impact and exploitability sub-scores, which CSAF does not give, keep NVD's on a graph that is not rebuilt). A CISA ICS payload has no `impact_score` or `exploitability_score` (a CSAF advisory gives none). At the sync, a CVSS score in `NVD_META` (`base_score`, `impact_score`, `exploitability_score`) that does not read as a finite number is dropped (a string such as `"9.8"` becomes that number), and a payload left without a base score counts as absent. A failed CVSS sub-node, NVD-data or score write makes `merge_cve` return False, and the sync counts the CVE as an error.
- `CVE.attack_vector` is the attack vector of the CVSS that gives the score (`cvss_score`, `cvss_version`: the first CVSS in the order v3.1 → v3.0 → v2 → v4.0 whose sub-node's `base_score` is a number in [0, 10]), in NVD's words — `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` — and null without CVSS. `merge_cve` sets it with the score from the CVSS sub-nodes (CVSS 3.x `attack_vector`, CVSS 2 `access_vector`, the `AV` metric of a CVSS 4.0 `vector_string`), whatever record arrives last; no record's own value is written.
- `CVE.epss_score` / `epss_percentile`: FIRST EPSS, the probability of exploitation in the next 30 days and its percentile, with `epss_score_date`, `epss_model_version` and `epss_updated_at`; set by the post-sync job `enrich_cve_epss` on the `CVE` nodes that exist and removed from a CVE that left the feed (the one source written to Neo4j without MISP, [DATA_SOURCES.md § 8b](DATA_SOURCES.md)).
- `CVE.ssvc_exploitation` (`none` / `poc` / `active`), `ssvc_automatable` (`yes` / `no`), `ssvc_technical_impact` (`partial` / `total`), with `ssvc_version` and `ssvc_timestamp`: CISA's SSVC decision, as NVD relays it in the CVE record; set from NVD's record only and removed when the record has none.
- `CVE.published` and `last_modified`: NVD's record (an NVD attribute with `NVD_META`, `nvd_record`) sets them; a record from any other source — CISA KEV, CISA ICS, an OTX pulse, a STIX import, a partner write through `merge_resilmesh_cve` — fills them only where the node has none (an empty string counts as none). Of the other records only CISA ICS gives dates (the advisory's release dates, not the CVE's), from one attribute per CVE in MISP, so they stay outside the description's ranking. `CVE.description` and `description_source`: the source ranking NVD > CISA KEV > CISA ICS > any other source ("Descriptions and their source" below). For a CVE, the sync never takes a comment that is a metadata block (`NVD_META:`, `OTX_META:`, `TF_META:` or any other `*_META:`) as the description, only the block's own `description` field, and never a comment that only says where the CVE was seen: the pulse reference "Referenced in OTX pulse: <name>" (the comment of a `cve_references` attribute written without an `OTX_META` block) and MISPWriter's placeholder "CVE from <source>" give no description, so CISA's KEV text describes a CVE that only OTX and the KEV name. `:Vulnerability` follows the same rules (`merge_vulnerability`, `merge_vulnerabilities_batch`). In the opt-in STIX flow (`run_pipeline --stix-flow`, MISP → STIX → Neo4j) a `vulnerability` object carries the source of its event (`x_edgeguard_source`), so the description is the one the attribute flow gives; the dates come only from the attribute flow.
- `CVE.cisa_exploit_add`, `cisa_action_due`, `cisa_required_action` and `cisa_vulnerability_name`: the CISA KEV record owns them. A KEV record (source `cisa_kev`) sets them when it carries a value; any other record, NVD's included (NVD copies the four from its own KEV enrichment), only fills them where the node has none (an empty string counts as none), whatever the order of the records in the sync, because NVD's MISP copy can hold an older value: NVD did not move `lastModified` when CISA moved the due date of CVE-2022-0995 on 2026-10-08, so NVD's copy kept the old date. `known_ransomware_use` comes from KEV records only and is replaced by each. Every KEV run edits the stored MISP copy of an entry CISA revised ([COLLECTORS.md § 3](COLLECTORS.md#revisions-every-run-compares-the-catalogue-with-misp)), and the incremental sync carries it to these properties and to the `SOURCED_FROM` edge's `raw_data`. What does not follow a revision: with `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false`, an entry outside the window (the KEV collector neither adds nor edits it, and where NVD's record alone gives the four fields it only fills them); an entry CISA removes from the catalogue keeps its properties (counted and logged by the collector only), the zones EdgeGuard detected in an entry accumulate on the node and on the edge (`zone`, `r.zones`) like every source's, and a revised KEV description shows on the node only where NVD gave none (the ranking below).
- `Malware.description`, `ThreatActor.description` and `Tool.description`: ATT&CK's text wherever ATT&CK describes the entity. These descriptions, and those of `Technique` and `Tactic`, follow the source ranking MITRE ATT&CK > a curated source > any other source, with `description_source` ("Descriptions and their source" below): the record MITRE delivered (source `mitre_attck`: the MITRE collector's MISP attributes, and in the opt-in STIX flow the objects of a MITRE event) ranks first, so ATT&CK's text stays whatever the order in which the records are merged. The MITRE collector gives tactics ATT&CK's description. The OTX collector gives its malware-family and adversary items no description: a pulse's description describes the report, not the family or actor. A family or actor only OTX names therefore shows no description; the pulse that first named it (and the other pulses of that collector run that named it) are in `n.pulse_ids[]`, since its MISP attribute is written once, and later pulses link to it through `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`. The sync takes no description from an OTX malware or actor attribute, from a metadata block (`MITRE_USES_TECHNIQUES:{...}` or any other, also one that does not parse or follows other text; only the text MISPWriter writes after a block's JSON), or from MISPWriter's placeholder for an item without text ("Malware from <source>", "Threat actor from <source>", "MITRE ATT&CK tool: <name>", and for techniques and tactics "MITRE ATT&CK technique from <source>", "MITRE ATT&CK tactic"); the STIX objects of the STIX flow follow the same rule.

### Descriptions and their source

A `CVE`, `Vulnerability`, `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node keeps one description: the text of the highest-ranked source whose record gave one (`src/description_ranking.py`). `n.description_source` names that source by its canonical id (`nvd`, `cisa_kev`, `mitre_attck`, …).

| Nodes | Ranking, highest first |
|---|---|
| `CVE`, `Vulnerability` | NVD, CISA KEV, CISA ICS, then every other source |
| `Malware`, `ThreatActor`, `Tool`, `Technique`, `Tactic` | MITRE ATT&CK, the curated sources (Core Ideas, then MISP Galaxy), then every other source |

- **The rule.** A record sets the description, with its source, when its source ranks at least as high as the source of the stored text: the same source's revised record replaces its own text, a lower-ranked source never replaces a higher-ranked one, and any record fills an empty description (null or `''`). A record without text changes nothing. Neo4j decides once per write, before it sets both properties (`DescriptionRanking.set_cypher`).
- **No ties.** Inside a group of several sources (the curated sources, every other source) the source with the higher registry `reliability` ranks higher, then the one whose id sorts first; a source the registry does not know (`stix_import`, `resilmesh` for a ResilMesh-native write through `merge_resilmesh_cve` / `merge_resilmesh_vulnerability`, the source name of an external STIX bundle) ranks below every registered one, two such sources by id. So no two sources share a rank, and the order of arrival cannot decide.
- **Order of arrival.** MISP holds one attribute per source per CVE or entity: MISPWriter skips an attribute whose type and value its source already holds in any event (cross-event deduplication), and NVD's update and every CISA KEV run edit their stored copies in place. Each source gives one text, so the node shows the highest-ranked text whatever the order of the events, in a full and an incremental sync and in the attribute and the STIX flow alike. Where MISP holds two attributes of one source for one node (the cross-event check switched off or its prefetch failed, both logged; a technique, tactic or tool ATT&CK renamed, whose attribute value carries the name), the one merged last is kept.
- **Merged nodes.** The actor alias merge and the Malware ATT&CK-id twin merge keep the description, with its source, that the ranking keeps among the nodes they fold together (equal ranks: the canonical node's).
- **Where it is exposed.** REST (`/vulnerabilities`, `/actors/{name}/summary`, the Graph Explorer's vulnerability view, which shows of a CVE's twin nodes, `:CVE` and `:Vulnerability`, the description the ranking keeps; at an equal rank the twin that names a source, since a record of that source replaces a text without one, then the source id), GraphQL (`descriptionSource` on `CVE`, `Vulnerability`, `ThreatActor`, `Malware`, `Technique`, `Tactic`, `Tool`) and the STIX export (`x_edgeguard_description_source` on an SDO with a description, extension definition 1.6.0).
- **Every source's text.** The node's `SOURCED_FROM` edge to each source names the MISP events that hold that source's attribute (`r.misp_event_ids[]`) and the source's own record ids (`r.source_refs[]`); the attribute's comment holds the source's text ([RUNBOOK.md § Retrieving raw MISP data from a Neo4j node](RUNBOOK.md#retrieving-raw-misp-data-from-a-neo4j-node)).

### Revoked and deprecated ATT&CK objects

ATT&CK keeps old objects in its STIX bundle. A **revoked** object (`revoked: true`) was replaced: a `revoked-by` relationship names its successor (`T1086` PowerShell → `T1059.001`, group `UNC2452` → `APT29`). A **deprecated** object (`x_mitre_deprecated: true`) was retired without a successor.

- **Revoked objects are not nodes.** The MITRE collector skips revoked objects of every type; they become neither nodes nor relationship endpoints. A revoked group's or software's name and aliases are added to its successor's `aliases`, so a lookup by the old name and the actor alias merge (`enrichment_jobs.merge_alias_duplicate_actors`) reach the successor: an OTX actor named `unc2452` is folded into `apt29`. One exception: a revoked technique the map below does not list yet is kept, with an `[ATTACK-REVOKED]` warning, until the map is rebuilt; feeds cite techniques by id and only the map translates them, so skipping it would lose those links.
- **A revoked technique id a feed names lands on the successor.** OTX pulses keep citing replaced ids. Where a Technique is matched by an id a feed names, the id is translated first: the technique steps of `build_relationships.py` (`coalesce($revoked[toString(tid)], tid)` before each `MATCH (t:Technique {mitre_id: …})` and in their orphan counts), the technique ids of MISP `misp-galaxy:mitre-attack-pattern` tags in the sync, curated-package claims, the STIX import of the command-line pipeline (`run_pipeline.py`), and the STIX export (`GET /stix/export/technique/<id>`), which answers a revoked id with its successor's bundle. The sub-technique step (`SUBTECHNIQUE_OF`) is not translated: ATT&CK never revokes the parent of a live sub-technique. The sync and the command-line pipeline's MISP reader and STIX import also skip a technique whose id the map lists, so a revoked technique held in MISP never becomes a node. Node properties keep the ids as the source gave them (`attack_ids`, `reported_techniques`, `uses_techniques`); only the link goes to the successor, and it records the ids the sources cited in `r.cited_ids` ("Relationship provenance").
- **Deprecated objects stay, marked.** A deprecated technique, tactic, group, malware or tool keeps its node and its links and carries `n.deprecated = true` (from the `attack-status:deprecated` MISP tag the writer sets). Filter them with `WHERE coalesce(n.deprecated, false) = false`. The flag is set, never cleared by another source.
- **The map.** `src/reference/attack_revoked_ids.json` lists every revoked technique (`T…`), group (`G…`) and software (`S…`) id with its successor and both names (version 2026.10.15: 210 techniques, 6 groups, 2 software; a chain A → B → C is resolved to C). It is built from the MITRE galaxies of MISP by `scripts/build_attack_revoked_ids.py`, carries the CalVer `version`, the inputs with their SHA-256 and the MISP galaxy (CC0) and MITRE notices, and is rebuilt at each ATT&CK release (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map"). It is read once per process (`src/attack_revoked.py`); a missing or invalid file logs one warning (`[ATT&CK] revoked-id map … not used`) and nothing is translated.
- **Acceptance.** `scripts/verify_fresh_baseline.py` fails when a Technique node carries an id the map lists (`no_revoked_attack_techniques`), a ThreatActor node from MITRE is a revoked group (`no_revoked_attack_groups`) or a Malware / Tool node from MITRE is revoked software (`no_revoked_attack_software`), and warns when an actor from another source still bears a revoked group's name (`revoked_group_names_folded`: the alias merge did not fold it).

### Indicator aging

Aging depends on the kind of fact, not on who supplied it or who created the node (`src/indicator_aging.py`, the single definition of the rule).

- **What ages.** Every `Indicator`, whatever source reported it and whether EdgeGuard created the node (`edgeguard_managed`) or wrote onto a node another system created (`edgeguard_enriched`); no aging statement reads either marker. `CVE`, the CVSS nodes, `Vulnerability`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Sector`, `Source` and `Alert` never age by time: EdgeGuard sets `active = true` when it creates such a node and writes no `active`, `retired_*` or aging property when it matches one, so a node another system created (a CASM CVE or CVSS node, an ISIM asset) keeps its own lifecycle. The rules that are not about time stay: a deprecated ATT&CK object keeps `deprecated = true` and a revoked one is no node ([above](#revoked-and-deprecated-attck-objects)), a `Campaign` follows its indicators (inactive when none is active), and a manual decommission is kept.
- **The basis.** One MISP report of an indicator has two times: T, the attribute's MISP timestamp (when MISP recorded it, UTC), and L, the source's own last-report date the collector stored in the attribute's `last_seen` ([COLLECTORS.md](COLLECTORS.md#the-source-date-an-indicator-ages-from) lists it per source). The report time is `min(T, coalesce(L, T))`: L dates the report when it is no later than T, a later L is capped at T, a source without a date gives T. The node keeps, forward only, the latest report of any source: `last_reported_at`, `last_reported_source`, `last_reported_ref` (the MISP attribute uuid, the record an expert opens in MISP to read the source's full text) and the kind of date in `last_reported_basis` (`source_date` or `misp_recorded`); and the latest MISP record time, `last_recorded_at`. A report with an older or equal time changes none of them; an equal time with a smaller attribute uuid takes the reference, so the order of arrival does not matter. The indicator's `SOURCED_FROM` edge keeps the same values for that one source. An indicator no MISP report dated ages from `first_imported_at` (set once, when EdgeGuard creates the node), `aging_basis = 'first_imported'`. `last_updated` stays the last database write and is read neither for aging nor for ordering.
- **The rule.** The age is the number of whole days from the basis to the evaluation time. `confidence_score = max(0.10, round(source_confidence × factor, 2))` with the factor 1.00 below 90 days, 0.85 from 90, 0.70 from 180 and 0.55 from 365. From 730 days the indicator is retired: `active = false`, `retired_by = 'decay'`, `retired_at` = basis + 730 days. Below 730 days `active = true` and a decay retirement is cleared; a manual decommission (`retired_at` with another `retired_by`, or none) is kept. `source_confidence` is the highest confidence a source gave (incoming values only, never an aged one), and the value is recomputed from it, never multiplied step by step, so a missed or repeated run gives the same result. `EDGEGUARD_AGING_TIER_DAYS` (`90,180,365`), `EDGEGUARD_AGING_FACTORS` (`0.85,0.70,0.55`) and `EDGEGUARD_AGING_RETIRE_DAYS` (`730`) set the tiers, validated (strictly ascending days, one factor per tier day in (0, 1], retirement above the last tier day).
- **Each node says why.** `aging_basis` (the kind of the latest report, `last_reported_basis`, or `first_imported`; the rule derives it from the stored report like the other aging properties), `aging_tier` (0 below the first tier day, then 1, 2, 3), `aging_factor`, `aging_since`, when the current state began: the basis plus the first day of the tier, or plus 730 days once retired, and `aging_evaluated_at`, the time at which the node's aging values were last written: by a write, or by a job run that changed them; a job run that changes nothing leaves it unchanged (below).
- **When it is applied.** Every Indicator write applies the rule (the sync's batch and single-item paths, the alert path, the STIX import, the VirusTotal re-enrichment) in a `SET` clause of its own after the clause that records the report and `source_confidence` (`indicator_aging.aging_set_clause`), so it reads the report of the same write whatever order Neo4j applies the items of one clause in, and a newer report reactivates a node in that write. The alert path applies it in a second statement of its transaction, after the statement that merges the node: in one statement the planner reads the node's basis with the `MERGE`, before the `SET` takes the node's write lock. **The time of an evaluation.** Every evaluation, a write or the job, applies the rule at the database's current time (`datetime()`, read when its statement starts), lifted to the node's `aging_evaluated_at` when that is later (`indicator_aging.evaluated_at_expr`), and stores that time whenever it writes the aging properties. No DAG run passes a time and no clock is shared between runs: real time only moves forward, so a cleared or re-run task, a baseline overlapping a scheduled sync and a command-line run evaluate at the time they run, and a write of a newer report evaluates that report at the time its statement started. For one basis every aging value changes in one direction only as the time grows (the tier and `aging_since` only grow, the confidence only falls, a retired node stays retired); the lift keeps a node from moving backwards where the clocks of two evaluations do not follow their order (two overlapping transactions, a clock set back on the database server), so no retired indicator comes back, no tier falls and no `aging_since` or STIX `modified` moves back. One case leaves a node behind the latest evaluation for a while, without moving it backwards: the job selects the nodes to change without a lock, and a job run that changes none of a node's values neither locks it nor stores a time on it, so a write whose statement started before that job evaluated the node, and which commits a newer report after it, evaluates the report at its own statement's start, earlier than the job's time; the node holds the state of the new report at that time until the next write or job evaluates it at its own time. The gap lasts as long as that write's statement ran, lock waits included (the batch write locks all its rows with the `MERGE` before it sets any property). Two evaluations of one node never interleave: the batch and single-item writes set properties of the node in the clause before the rule, which holds the node's write lock until the write commits, so the rule reads the node under that lock; the alert path's second statement reads the node under the lock its first statement took; the job locks each node it is about to change (`apoc.lock.nodes`) and evaluates it again under the lock. The enrichment job `decay_ioc_confidence` recomputes the rule for every Indicator in `apoc.periodic.iterate` batches (each at the database's time when its transaction starts), writes a node when any of its aging properties (`aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `confidence_score`, `active`, `retired_at`, `retired_by`) differs from what the rule gives, so a stale value is corrected and a run in which no aging changes writes nothing (a later `aging_evaluated_at` alone is no change), runs before the campaign builder, and logs the Indicators per tier, retired and by basis, and those with neither time (left untouched; expected 0).
- **The same graph from the same data.** A full sync, an incremental one, the in-memory and the paged paths, any order of arrival and any number of re-syncs give the same aging properties. Duplicates of an indicator in one MISP event keep the latest report of the source and its highest confidence, whichever comes first.
- **Known limits.** The alert path (`create_indicator_from_alert`; no subscriber is deployed) and the command-line writers (the STIX import, the VirusTotal re-enrichment) record no report: a node they create ages from `first_imported_at`, an existing node keeps its basis. What an alert's time means for aging, and whether an alert is independent evidence or a match of a list EdgeGuard exported to Wazuh, is to be designed with the ResilMesh alert integration. ResilMesh's own MISP events stay outside the sync.
- **Where it is exposed.** REST (the node's properties; `/indicators` and the Wazuh CDB indicator list newest first by `coalesce(last_reported_at, first_imported_at)`; `/zone/{zone}` every label it lists by one clock, `coalesce(last_reported_at, first_imported_at, created_at)`: an indicator's latest report, otherwise when the node entered the graph, a campaign's `created_at`; none of these moves when a sync or the campaign builder rewrites a node, whereas ordering the other labels by `last_updated` would put every node just rewritten above an indicator reported in the latest run), GraphQL (`lastReportedAt`, `lastReportedSource`, `lastReportedRef`, `lastRecordedAt`, `sourceConfidence`, `agingBasis`, `agingTier`, `agingFactor`, `agingSince`, `agingEvaluatedAt`, `active`, `retiredBy`, `retiredAt` on `Indicator`) and the STIX export (`x_edgeguard_last_reported_at`, `x_edgeguard_last_reported_source`, `x_edgeguard_last_reported_ref`, `x_edgeguard_source_confidence`, `x_edgeguard_aging_basis`, `x_edgeguard_aging_tier`, `x_edgeguard_active`, `x_edgeguard_retired_by` on indicators, extension definition 1.7.0; an indicator's `modified` is the latest of `created`, `last_recorded_at` and `aging_since`). A retired indicator drops out of the GraphQL `indicators` default list, the Wazuh CDB export and campaigns; it is never deleted.

### Technique edges: attribution vs capability vs report

The three X→Technique edges are specialized types, so Cypher queries and LLM/GraphRAG retrieval can distinguish **who does it** from **what the code can do** from **what the report an indicator came from lists**:

| Specialized type | Source | Semantic |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | `ThreatActor` (or `Campaign`) | Attribution — e.g. *"APT28 employs T1059"* |
| `IMPLEMENTS_TECHNIQUE` | `Malware` or `Tool` | Capability — e.g. *"Mimikatz implements T1059"* |
| `USES_TECHNIQUE` | `Indicator` | Report — e.g. *"the OTX report this indicator came from lists T1059"*: the pulse's `attack_ids`, inherited by every indicator of the pulse. It does not say the indicator executed the technique |

When emitting STIX 2.1, `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE` become `relationship_type: "uses"` and `USES_TECHNIQUE` becomes `"indicates"` (indicator indicates attack-pattern); the source and target types give the same disambiguation. See `src/stix_exporter.py` (`_SRO_BY_EDGE`) and `GET /stix/types` (`relationship_mappings`).

---

## Sector Labeling

After every sync, nodes are labeled by sector. The `zone` property is always a list:

```cypher
(:Indicator :Finance {value: 'evil.com', zone: ['finance']})
(:Vulnerability :Energy {cve_id: 'CVE-2024-1234', zone: ['energy']})
(:Malware :Healthcare {name: 'medusalocker', zone: ['healthcare']})
(:Vulnerability {cve_id: 'CVE-2024-9999', zone: ['global']})   // no :Global label: global is never applied as a label
```

`apply_sector_labels` (`Neo4jClient.apply_sector_labels`, run at the end of every sync) adds one secondary label per sector in `zone` (`healthcare` → `:Healthcare`), to the threat-intel labels only (Indicator, CVE, Vulnerability, Malware, ThreatActor, Technique, Tactic, Tool, Campaign, Source); `global` is never a label. Links to the sector itself go to `(:Sector {name})`.

### Multi-Zone Support

EdgeGuard supports **cross-zone threats** — threats that apply to multiple sectors.
The `zone` property is **always a list** (never a single string). There is no separate
`zones` property on the node; all of its zone membership is stored in the single `zone` array
(each `SOURCED_FROM` edge also carries `r.zones`: the zones that one source gave the node).

```cypher
// Energy company compromised → affects Finance (payments)
// Creates ONE node with BOTH zones in a single array:
(:Indicator {
    value: 'evil-energy.com',
    zone: ['energy', 'finance']   // All applicable zones — always a list
})
```

#### Zone Logic

| Scenario | `zone` (array) |
|----------|----------------|
| Energy-specific threat | `['energy']` |
| Finance-specific threat | `['finance']` |
| Generic threat | `['global']` |
| Energy → Finance crossover | `['energy', 'finance']` |
| Threat reported for every sector | `['energy', 'finance', 'healthcare']` |

`global` means "no sector": it is dropped as soon as any source gives a sector (`_zone_override_global_clause`), so a list never holds `global` next to a sector.

#### Querying Cross-Zone Threats

```cypher
// Find all threats affecting BOTH energy AND finance
MATCH (i:Indicator)
WHERE 'energy' IN i.zone AND 'finance' IN i.zone
RETURN i.value, i.zone;

// Find all threats affecting ANY of specific zones
MATCH (i:Indicator)
WHERE ANY(z IN ['energy', 'finance'] WHERE z IN i.zone)
RETURN i.value, i.zone
```

---

## Neo4j Constraints & Indexes

### UNIQUE Constraints (Composite Keys)

```cypher
// Single-key UNIQUE — zone is metadata, not part of deduplication key
CREATE CONSTRAINT vulnerability_key IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE;

// Composite UNIQUE on (indicator_type, value) — same IOC merges across sources
CREATE CONSTRAINT indicator_key IF NOT EXISTS
FOR (i:Indicator) REQUIRE (i.indicator_type, i.value) IS UNIQUE;

// Also created by Neo4jClient.create_constraints: cve_key, source_key,
// malware_key / actor_key (name), technique_key / tactic_key / tool_key (mitre_id),
// sector_key, cvssv2/30/31/40_key (cve_id), campaign_key, ip_key (IP.address),
// host_key (Host.hostname), subnet_key (Subnet.range), alert_key.
// Device, NetworkService, SoftwareVersion, Application, Role and User get no
// constraint (SHARED_LABELS_WITHOUT_UNIQUE_CONSTRAINT).
```

**Note:** Zone is treated as metadata, not as part of the deduplication key. This allows the same indicator/vulnerability to exist in multiple zones while being stored as a single node in Neo4j.

### Indexes

```cypher
// Core lookups
CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id);
CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value);
CREATE INDEX indicator_type IF NOT EXISTS FOR (i:Indicator) ON (i.indicator_type);
CREATE INDEX indicator_source IF NOT EXISTS FOR (i:Indicator) ON (i.source);
CREATE INDEX indicator_zone IF NOT EXISTS FOR (i:Indicator) ON (i.zone);
CREATE INDEX malware_name IF NOT EXISTS FOR (m:Malware) ON (m.name);
CREATE INDEX actor_name IF NOT EXISTS FOR (a:ThreatActor) ON (a.name);
CREATE INDEX technique_mitre IF NOT EXISTS FOR (t:Technique) ON (t.mitre_id);

// CVE prioritization range scans (GraphRAG): CVSS-threshold
// filters and the CISA-KEV (cisa_exploit_add IS NOT NULL) query family.
CREATE INDEX cve_cvss_score IF NOT EXISTS FOR (c:CVE) ON (c.cvss_score);
CREATE INDEX cve_cisa_exploit_add IF NOT EXISTS FOR (c:CVE) ON (c.cisa_exploit_add);

// Aging and recency: the time an indicator ages from, and the aging job's per-tier counts
CREATE INDEX indicator_last_reported_at IF NOT EXISTS FOR (i:Indicator) ON (i.last_reported_at);
CREATE INDEX indicator_aging_tier IF NOT EXISTS FOR (i:Indicator) ON (i.aging_tier);
CREATE INDEX indicator_first_imported_at IF NOT EXISTS FOR (i:Indicator) ON (i.first_imported_at);
// (… see src/neo4j_client.py create_indexes for the full list.)

// Active/inactive tracking
CREATE INDEX indicator_active IF NOT EXISTS FOR (i:Indicator) ON (i.active);
CREATE INDEX vulnerability_active IF NOT EXISTS FOR (v:Vulnerability) ON (v.active);
// No index on a scalar misp_event_id / misp_attribute_id: all readers query the
// misp_event_ids[] / misp_attribute_ids[] arrays via list-membership predicates.

// Per-node deterministic UUID indexes, for cross-environment delta-sync
// (cloud MERGEs by uuid) and self-describing edge serialization (xAI / RAG
// consumers resolve r.src_uuid / r.trg_uuid by uuid).
// One per documented node label — see src/node_identity.py for the canonical
// natural-key map.
CREATE INDEX indicator_uuid IF NOT EXISTS FOR (i:Indicator) ON (i.uuid);
CREATE INDEX vulnerability_uuid IF NOT EXISTS FOR (v:Vulnerability) ON (v.uuid);
CREATE INDEX cve_uuid IF NOT EXISTS FOR (c:CVE) ON (c.uuid);
CREATE INDEX malware_uuid IF NOT EXISTS FOR (m:Malware) ON (m.uuid);
CREATE INDEX actor_uuid IF NOT EXISTS FOR (a:ThreatActor) ON (a.uuid);
CREATE INDEX technique_uuid IF NOT EXISTS FOR (t:Technique) ON (t.uuid);
// (… one per documented label — see src/neo4j_client.py create_indexes for the full list.)

// Tactic / technique navigation
CREATE INDEX tactic_shortname IF NOT EXISTS FOR (t:Tactic) ON (t.shortname);
CREATE INDEX technique_tactic_phases IF NOT EXISTS FOR (t:Technique) ON (t.tactic_phases);

// CVSS sub-node lookups
CREATE INDEX cvssv31_cve_id IF NOT EXISTS FOR (n:CVSSv31) ON (n.cve_id);
CREATE INDEX cvssv30_cve_id IF NOT EXISTS FOR (n:CVSSv30) ON (n.cve_id);
CREATE INDEX cvssv2_cve_id IF NOT EXISTS FOR (n:CVSSv2) ON (n.cve_id);
CREATE INDEX cvssv40_cve_id IF NOT EXISTS FOR (n:CVSSv40) ON (n.cve_id);

// Campaign enrichment
CREATE INDEX campaign_actor_name IF NOT EXISTS FOR (c:Campaign) ON (c.actor_name);
CREATE INDEX campaign_zone IF NOT EXISTS FOR (c:Campaign) ON (c.zone);
```

---

## MISP Integration

**Data split:** Sources --> MISP (raw + full history) --> Neo4j (metadata + relationships for fast queries). Neo4j nodes carry `misp_event_ids[]` for tracing back to every MISP event that has observed them. **Indicator** nodes additionally carry `misp_attribute_ids[]` — the MISP **attribute UUIDs** (`attr.uuid`), which are the *stable cross-instance identifiers*. The numeric `attr.id` is not used, because it is a per-instance auto-increment and not portable across MISP instances or restores. With `misp_attribute_ids[]` populated you can resolve a Neo4j Indicator directly back to its MISP attributes without joining via event id. **Relationships:** every relationship built from the sources carries `r.misp_event_ids[]`, together with `r.sources[]` and `r.source_refs[]` (see "Relationship provenance" above).

### Sync throughput (Airflow worker memory)

MISP→Neo4j ingestion (`run_misp_to_neo4j.py`) processes **one MISP event at a time**: parse attributes → dedupe within the event → build **report-scoped** edges (only items that share the same OTX `pulse_id` are paired — `INDICATES` to Malware and to CVE and `ATTRIBUTED_TO` with `match_type='otx_pulse'`, `ATTRIBUTED_TO` only when the pulse's actors are one actor; items are never paired for sharing a MISP event) → merge nodes in **Python-side chunks** (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**, default **`500`**) → flush relationships in **UNWIND batches** (**`EDGEGUARD_REL_BATCH_SIZE`**, default **`500`**). **`0`** or **`all`** on chunk size disables Python node chunking (**OOM risk** on huge attribute counts). On an incremental sync only the attributes whose MISP `timestamp` falls inside the window are written (`EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` processes whole events); unchanged items of the same OTX pulse (indicators, malware, actors and CVEs) take part only in the report-scoped link build, which groups only the pulses of the changed items (the run holds all of their items) and takes the items in event order, so the per-pulse caps pick the items a full sync picks. See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

### Querying Full History

To get full history from MISP for an indicator:

```cypher
// Get MISP event IDs from Neo4j (every event that has observed this indicator)
MATCH (i:Indicator {value: '1.2.3.4'})
RETURN i.value, i.misp_event_ids, i.source

// Then query MISP API for full event history:
// GET /api/attributes/restSearch/json?value=1.2.3.4
```

---

## Zone Detection Methodology

### Three-Source Zone Resolution (MISP → Neo4j pipeline)

When `run_misp_to_neo4j.py` resolves the zone for an attribute, it applies a strict **priority ladder** across three sources:

| Priority | Source | Logic |
|----------|--------|-------|
| 1 (highest) | Attribute-level tags | If the attribute itself carries specific `zone:*` tags, use those exclusively |
| 2 | Event-level tags | If attribute has no specific zone, check `zone:*` / `sector:*` tags from the parent event. Event names (`EdgeGuard-{source}-{date}`) do not contain zone information — zone lives exclusively on attribute tags. |
| 3 (fallback) | `global` | Only if neither of the above produces a specific sector |

**Merging logic (event name + event tags):**

```python
# If multiple sources provide zones, ALL specific sectors are merged.
# "global" is only kept when no specific sectors exist from any source.
all_zones = set(zones_from_event_tags)
if zone_from_event_name:
    all_zones.add(zone_from_event_name)
specific = {z for z in all_zones if z != "global"}
event_zones = sorted(specific) if specific else ["global"]
```

Examples of what this merging logic produces:
- Event tags `zone:finance` + `zone:healthcare` → `['finance', 'healthcare']`, and `zone:global` + `zone:healthcare` → `['healthcare']` (event names carry no zone: `_extract_zone_from_event_name` returns None)
- Attribute with no zone tag, event `Tag: [{name:"zone:healthcare"}]`, event name `GLOBAL` → `['healthcare']`

All resolved zone values are validated against `VALID_ZONES = frozenset({"global", "healthcare", "energy", "finance"})` before storage.

---

### Conservative Keyword-Based Detection

EdgeGuard uses a **weighted scoring system** to detect sectors from threat data, designed to avoid false positives:

#### Scoring Weights by Context

| Context | Weight (`detect_zones_from_text`) | Example |
|---------|-----------------------------------|---------|
| `name` / `alias` / `title` | 3.0 | Primary identity, CVE title |
| `description` | 2.0 | Long-form CVE / feed description |
| `body` (default) | 1.5 | Generic body text when context unspecified |
| `tag` | 1.0 | Concatenated tag strings |

**`detect_zones_from_item`:** For each text field it calls **`detect_zones_from_text`** with the matching context; for every sector returned that is **not** `global`, it adds a **fixed** bump to **`combined_scores`** (**+3.0** name fields, **+2.5** title/info, **+1.5** description/comment/detail, **+0.5** tags). Those bumps are **not** the same numbers as the per-snippet weights above — see **`config.py`**.

#### Detection Rules

1. **Per-field threshold** (`ZONE_DETECT_THRESHOLD`, default **1.5**): minimum weighted score in `detect_zones_from_text` for a sector to count in that field. Override with **`EDGEGUARD_ZONE_DETECT_THRESHOLD`**.
2. **Multi-field aggregation** (`detect_zones_from_item`): uses **`ZONE_ITEM_COMBINED_THRESHOLD`** (default **1.5**, env **`EDGEGUARD_ZONE_ITEM_THRESHOLD`**). **NVD** passes `description` + a **`comment`** string built from flattened **CPE criteria** (`configurations_to_zone_text` in `nvd_collector.py`), not raw `json.dumps` of configurations.
3. **Relative filtering**: sectors must be within **50%** of the max combined score (see `config.py`).
4. **Negative keywords**: explicit exclusions (“not healthcare”, …) drop that sector for the snippet; `detect_zones_from_item` also drops it for the whole item when any scanned field holds one.
5. **Clean keywords**: no malware family names as sector keywords — link via relationships.

#### Sector Keywords (representative; full list in `config.py` → `SECTOR_KEYWORDS`)

- **Healthcare**: hospital, patient, dicom, hl7, fhir, medical device, emr, ehr, hipaa, …
- **Energy**: scada, modbus, opc ua, ics, plc, power grid, substation, industrial control, …
- **Finance**: banking trojan, payment processing, core banking, fintech, kyc, aml, …

#### Example Behavior

| Input | Detection | Result |
|-------|-----------|--------|
| "Generic phishing IP list" | No sector keywords | `global` |
| "TrickBot banking trojan" | "banking trojan" in description | `finance` |
| "Nuclear SCADA system" | "nuclear", "scada" in title | `energy` |
| "LockBit ransomware" | No strong sector keywords | `global` |
| "Healthcare ransomware attack" | "healthcare" in description | `healthcare` |
| One “hospital” in CVE description | Single keyword at body weight ≥ threshold | `healthcare` (after threshold 1.5 default) |

#### Why Conservative?

- Malware families (LockBit, Conti, TrickBot) target multiple sectors
- They should be linked via relationships, not keyword tags
- This prevents 57% of threats being tagged as "all sectors"
- Better for accurate sector-specific alerting

---

### Best Practices

1. **Latest data in Neo4j** - For fast graph queries
2. **Full history in MISP** - For audit, changes over time
3. **Query both** - Get metadata from Neo4j, details from MISP

---

## Example Queries

> **Scope:** The first queries use labels and properties written by **EdgeGuard’s default MISP→Neo4j pipeline** (`neo4j_client`, `build_relationships`). Patterns involving `Host`, `SoftwareVersion`, `IP` or `DomainName` are **ResilMesh-shaped illustrations** — they are valid Cypher for a full CRUSOE graph but may not return rows until those node types are populated by your deployment. The sector secondary labels (`:Finance`, `:Healthcare`, `:Energy`) are applied by EdgeGuard at the end of every sync ([Sector Labeling](#sector-labeling)).

### Healthcare-related CVEs (zone property)

The sync writes CVEs under the **`:CVE`** label (`:Vulnerability` is empty on current
baselines — see NEO4J_SAMPLE_QUERIES.md). Use the portable form if a graph may
hold `:Vulnerability` nodes: `MATCH (v) WHERE v:CVE OR v:Vulnerability`.

```cypher
MATCH (c:CVE)
WHERE 'healthcare' IN coalesce(c.zone, []) AND coalesce(c.cvss_score, 0) >= 7.0
RETURN c.cve_id, c.description, c.cvss_score
ORDER BY c.cvss_score DESC
```

### Alert enrichment: trace indicator to actor

```cypher
MATCH (ind:Indicator {indicator_type: 'ipv4', value: '192.168.1.100'})-[:INDICATES]->(m:Malware)
MATCH (m)-[:ATTRIBUTED_TO]->(ta:ThreatActor)
MATCH (ta)-[:EMPLOYS_TECHNIQUE]->(tech:Technique)
OPTIONAL MATCH (tech)-[:IN_TACTIC]->(tactic:Tactic)
RETURN ind.value, m.name, ta.name, collect(DISTINCT tech.name) AS techniques, collect(DISTINCT tactic.name) AS tactics
```

### CVEs named in the same OTX report as an indicator

`EXPLOITS` is the indicator's own CVE claim; `INDICATES` to a `CVE` says only that one OTX pulse names both
(`r.source_refs` names the pulse).

```cypher
MATCH (i:Indicator {value: '203.0.113.17'})-[r:INDICATES]->(c:CVE)
WHERE r.match_type = 'otx_pulse'
RETURN c.cve_id, c.cvss_score, c.severity, r.source_refs AS reports
ORDER BY c.cve_id
```

### Cross-zone: critical CVEs (`zone` list contains `global`)

```cypher
MATCH (c:CVE)
WHERE 'global' IN coalesce(c.zone, []) AND coalesce(c.cvss_score, 0) >= 9.0
RETURN c.cve_id, c.description, c.cvss_score
ORDER BY c.cvss_score DESC
```

### Query all indicators in a Campaign

Actor and malware names are stored lower-case (aliases keep display case).

```cypher
MATCH (a:ThreatActor)-[:RUNS]->(c:Campaign)<-[:PART_OF_CAMPAIGN]-(i:Indicator)
WHERE a.name = 'apt28'
  AND i.active = true
RETURN c.name, c.first_seen, c.last_seen, i.value, i.indicator_type, i.confidence_score
ORDER BY i.confidence_score DESC
```

### Find active vs retired IOCs for a threat actor

_Lifecycle: one rule for every Indicator ([Indicator aging](#indicator-aging)): the confidence follows the age since the latest report of any source (×0.85 from 90 days, ×0.70 from 180, ×0.55 from 365) and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days; a newer report reactivates it in the same write, a re-sync of the same data changes nothing. Only a manual decommission — `retired_at` without the `decay` tag — survives a newer report. Edge confidence written by the sync never decreases: the label follows the stronger evidence._

_Re-reported indicators: the incremental sync reads only MISP attributes whose timestamp moved, and a collector does not push an indicator its source already holds in MISP, so without a refresh an IOC a feed keeps listing would never be written again and would decay while still listed. When a collector run reports an indicator again and MISP last wrote the stored copy (its timestamp) more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30, well inside the first aging tier at 90 days), the collector edits that copy; MISP stamps it anew and the next incremental sync merges the node again. The indicator ages from the source's own date capped at that timestamp, so the edit makes it younger only when the source's `last_seen` moved, or, for a source without a date (SSL Blacklist, MalwareBazaar), to the time of the edit; an indicator re-reported within the interval keeps its older date until the interval has passed. The edit keeps the source's dates: `last_seen` changes only when the source claims a later one, so `SOURCED_FROM.source_reported_last_at` moves only then, and `source_reported_first_at` and `first_imported_at` do not move. Decay therefore still applies to an indicator no collector run reports any more, and also to one a source lists but a run does not report. Feodo Tracker and SSL Blacklist report the whole list a run reads, up to `EDGEGUARD_FEODO_MAX_PER_RUN` and `EDGEGUARD_SSLBL_MAX_PER_RUN` (a Feodo Tracker daily run reads the 30-day list, so the history a baseline loaded is not reported again); the AbuseIPDB blacklist reports at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses per run, the most one request returns on the free plan, and AbuseIPDB chooses which, so a listed address outside that answer still ages. A run refreshes at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` (2,000) copies. Further limits: an existing IOC listed by a new OTX pulse does not receive that pulse's families, adversaries, report id or TLP, and an IOC a source lists for less than the interval (ThreatFox re-lists each IOC for 7 days) is not refreshed by that listing ([COLLECTORS.md](COLLECTORS.md#re-reported-indicators))._

```cypher
MATCH (a:ThreatActor {name: 'lazarus group'})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
RETURN i.value, i.indicator_type, i.confidence_score, i.source_confidence,
       i.active, i.retired_by, i.aging_tier, i.aging_basis,
       i.last_reported_at, i.last_reported_source, i.last_reported_ref,
       CASE WHEN i.active = false THEN 'RETIRED' ELSE 'ACTIVE' END AS status
ORDER BY coalesce(i.last_reported_at, i.first_imported_at) DESC
```

---

_Last updated: 2026-10-19_

## History

- 2026-10-19 — `USES_TECHNIQUE` (Indicator → Technique) is described as what it is: the OTX report the indicator came from lists the technique, not an observation that the indicator executed it.
- 2026-10-18 — `INDICATES` from an Indicator to a `CVE` named in the same OTX pulse (`otx_pulse`, 0.6), written by the sync's report-scoped build; a CVE item of a pulse joins its report (`OTX_META.pulse_id`), and a pulse's `cve_references` item reaches MISP with an `OTX_META` block naming the pulse; the per-pulse caps take the first items in event order in an incremental sync too, which groups only the pulses of its changed items (it put the changed items first and also grouped the other pulses of the unchanged items, so over several runs a pulse could be linked to more than 50 malware families or 2,000 indicators).
- 2026-10-18 — Threat-actor names: country and state names and nationality adjectives are never actor names (`"north korea (apt37)"` is `apt37`), and an OTX adversary the same pulse lists as a malware family is an actor only when the canonical threat-actor reference resolves it.
- 2026-10-18 — An OTX pulse's own `industries` are a statement: `TARGETS` links to the sectors they map to carry `otx_industries` (0.6; they were `zone_classification`), recorded on the OTX `SOURCED_FROM` edge (`stated_zones`, `stated_refs`), also for the later pulses of a run that list the same item (`report_stated_zones`); a foreign `sector:` tag row follows the label table; an unchanged attribute that joins an incremental run's report-scoped build writes no sector link (it wrote its zone rows again).
- 2026-10-18 — `USES_TECHNIQUE` from an OTX pulse's ATT&CK ids (`otx_attack_ids`, step 8) is created at 0.6, the confidence of every other link from those ids (it was 0.85).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text restated as a guide to current behaviour; change history moved to this section and data written by earlier versions to the appendix; the `build_relationships` step numbers and the alias round trip are stated in the relationship table's notes.
- 2026-10-17 — Corrected against the code: the `misp_attribute_tag` evidence label, `USES_TECHNIQUE` exported as STIX `indicates`, the constraint and index lists, sector labels (never `:Global`, no `global` next to a sector), item-level negative keywords, lower-case actor names in the examples and the zone examples.
- 2026-10-17 — A CVSS edge written before it carried `sources` takes its feed from the sub-node's `tag`, `NVD_META` scores that are not finite numbers are dropped, a failed CVE sub-write makes `merge_cve` return False, and a partner write through `merge_resilmesh_cve` sets four CVE list properties.
- 2026-10-16 — NVD's record holds a CVE's CVSS sub-nodes and list properties and every other record only fills them, whatever the order of the records (the record merged last had won); a CISA ICS CVSS payload carries no impact or exploitability sub-score (the collector had sent 0.0).
- 2026-10-16 — The CISA KEV record owns the four `cisa_*` fields (the record merged last had set them, so NVD's older copy could write back an outdated due date), and revised KEV entries reach MISP and the graph through in-place edits.
- 2026-10-16 — `Technique.is_subtechnique` follows the dotted ATT&CK id (every sync had written false), and a `malware_family` link names only the feeds that give a family label (OTX had been named too).
- 2026-10-16 — Links to a `Sector` name only the feeds that gave that sector and cite only their records (`zones`, `stated_zones`, `stated_refs`), CISA ICS sector statements carry `advisory_sector` (0.9), and the unconditional confidence reset to 0.5 was removed.
- 2026-10-16 — One indicator aging rule from the latest report of any source, evaluated at the database's time and never backwards, replacing aging of `Indicator` and `Vulnerability` from `last_updated`, which every write reset and which made the 730-day baseline's two-year-old IOCs look new.
- 2026-10-16 — Descriptions follow a per-label source ranking recorded in `description_source`, replacing the rules under which NVD's or MITRE's record set the text and every other record only filled it.
- 2026-10-16 — Campaigns also rest on `USES_MALWARE`, name their evidence in `r.evidence_types[]`, keep capped and sorted provenance lists, and are deleted when their evidence is gone (they had been kept inactive); the alias merge runs each batch of pairs in one transaction.
- 2026-10-16 — `ATTRIBUTED_TO` from a pulse: step 2d also treats pulses the OTX collector marked on indicators as naming several actors; the sync's own STIX conversion names a malware by its base name.
- 2026-10-15 — `Malware`, `ThreatActor` and `Tool` descriptions come from ATT&CK and never from an OTX pulse, a metadata block or a placeholder (the record merged last had set them); tactics carry ATT&CK's description.
- 2026-10-15 — Malware names lose the ATT&CK software id suffix at ingest, families are looked up under both names, and `merge_malware_attack_twins` folds the twins into one node.
- 2026-10-15 — Revoked ATT&CK objects are no longer nodes and revoked technique ids land on their successor, deprecated ones carry `deprecated = true`; the actor alias merge uses the canonical threat-actor reference; `r.cited_ids[]` and `n.merged_from[]` record what the source said.
- 2026-10-15 — CVE nodes: `attack_vector` from the scoring CVSS in NVD's words, every CVSS version NVD supplies (one version had been kept, so an update removed the older sub-node), FIRST EPSS and CISA SSVC properties, and descriptions and dates set by NVD's record.
- 2026-10-15 — `ATTRIBUTED_TO` from an OTX pulse only when the pulse's actors are one actor; campaign links carry `campaign_grouping` (they had carried no evidence label); the alias merge keeps the most restrictive TLP; re-reported indicators are refreshed in MISP after 30 days (Feodo Tracker, SSL Blacklist and AbuseIPDB had reported only their first 200 entries per daily run).
- 2026-10-15 — IPv6 indicators are `ipv6` (they were `ipv4`) and SSL Blacklist fingerprints `x509-fingerprint-sha1` (they were `hash`); the incremental sync writes only changed attributes.
- 2026-10-14 — Every relationship names its sources, their records and the MISP events (`sources[]`, `source_refs[]`, `misp_event_ids[]`), replacing `source_id`, `source_ids` and `report_ids`; curated packages; campaign membership renamed from `PART_OF` to `PART_OF_CAMPAIGN`, leaving `PART_OF` to ResilMesh.
- 2026-10-11 — Shared-database contract: `edgeguard_managed` is stamped on the create path only, `edgeguard_enriched` marks nodes a partner created, and partner-owned labels get no UNIQUE constraint.
- 2026-10-10 — Report-scoped linking replaced whole-event co-occurrence (the co-occurrence query Q4, 0.5, was removed; `INDICATES` and `ATTRIBUTED_TO` only within one OTX pulse; Q5b / Q6b from `reported_techniques`); evidence labels, CVE list properties, `tlp`, `SUBTECHNIQUE_OF`, `USES_MALWARE` / `USES_TOOL`, and ThreatActor / Malware → Sector `TARGETS` links.
- 2026-06-11 — Alias round trip (`aliases` through MISP `alias:` tags, ATT&CK malware aliases from `x_mitre_aliases`) and the `cve_cvss_score` / `cve_cisa_exploit_add` range indexes.
- 2026-04-23 — `r.misp_event_ids[]` written on `INDICATES`, `EXPLOITS`, `TARGETS` and `AFFECTS` by `build_relationships.py`.
- 2026-04-21 — Timestamp semantic model: source-reported times are NULL or tz-aware UTC, canonicalised by `coerce_iso()`.
- 2026-04-18 — Edge-based, source-truthful provenance on `SOURCED_FROM` edges; migration and backfill scripts replaced by a fresh baseline.
- 2026-04-17 — Scalar MISP provenance fields and their indexes dropped in favour of the `misp_event_ids[]` / `misp_attribute_ids[]` arrays.
- 2026-04-16 — Deterministic per-node UUIDs and edge endpoint UUIDs, with one uuid index per label.
- 2026-04-15 — The generic `USES` relationship to a technique split into `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE` and `USES_TECHNIQUE`.
- 2026-03-28 — First version of the knowledge graph schema.
