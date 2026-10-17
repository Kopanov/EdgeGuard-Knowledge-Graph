# EdgeGuard Knowledge Graph Schema

> **Node/relationship property reference:** See [TECHNICAL_SPEC.md](TECHNICAL_SPEC.md) for complete Cypher schemas and property types.

## Overview

The EdgeGuard knowledge graph is designed to be **backward compatible with ResilMesh/CRUSOE** while extending it with sector-aware threat intelligence.

---

## Sector Architecture

EdgeGuard partitions the knowledge graph by **three sectors** plus a **central OSINT backbone**:

```
 Healthcare (:Zone)  |  Energy (:Zone)  |  Finance (:Zone)   ← 10K-100K nodes each
─────────────────────┴──────────────────┴────────────────────
          Central OSINT Backbone (:Global)
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
| `ThreatActor` | APT groups, threat actors. A group ATT&CK revoked (UNC2452, APT34, …) is not a node; its name and aliases are aliases of the group that replaced it (2026-10, see [Revoked and deprecated ATT&CK objects](#revoked-and-deprecated-attck-objects-2026-10)). `description`: ATT&CK's text, none on an actor only OTX names (2026-10) |
| `Malware` | Malware families, trojans, ransomware. Named by the family name without an ATT&CK software id suffix: OTX's `"Cobalt Strike - S0154"` is the ATT&CK node `cobalt strike` (2026-10, see [Malware named after an ATT&CK software id](#malware-named-after-an-attck-software-id-2026-10)). `description`: ATT&CK's text, none on a family only OTX names (2026-10) |
| `Tool` | MITRE ATT&CK tools (Mimikatz, Cobalt Strike, etc.). `description`: ATT&CK's text (2026-10) |
| `Technique` | MITRE ATT&CK techniques (T1566, T1059, etc.). A technique ATT&CK revoked is not a node, and a feed's link to its id lands on its successor; a deprecated one stays, with `deprecated = true` (2026-10). `is_subtechnique` is true for a dotted id (T1059.001) and false otherwise (2026-10; until then every sync wrote false, the MISP round trip carrying no flag) |
| `Tactic` | MITRE ATT&CK tactics (Initial Access, Execution, etc.). `description`: ATT&CK's text (2026-10; none when the graph is synced from a MISP kept from before 2026-10, whose tactic attributes hold MISPWriter's placeholder) |
| `Campaign` | EdgeGuard's grouping of one threat actor's malware and those malware's active indicators, built by the enrichment job `build_campaign_nodes`, one per actor (`"<actor> Campaign"`). It rests on the links between the actor and a malware: the malware is attributed to the actor (`ATTRIBUTED_TO`) or (2026-10-16) the actor uses it (`USES_MALWARE`: MITRE's explicit `uses`, curated-package claims); `src/campaign_evidence.py` holds the definition. An actor with either link and an active indicator of such a malware gets a campaign. A campaign whose actor has neither link left, or whose actor name no longer exists (the actor alias merge folded it), is deleted with its links in the same run (2026-10-16; it was kept, inactive, before); one with evidence whose indicators all expired stays, `active = false`. Its `uuid` is computed from the actor's name, so a campaign built again keeps it |
| `Indicator` | IOCs: IP addresses, domains, URLs, file hashes, TLS certificate fingerprints, … — keyed by `(indicator_type, value)`; `indicator_type` is `ipv4` / `ipv6` (MISP `ip-src` / `ip-dst` are resolved by the address), `domain`, `url`, `email`, `hash` (every file digest), `x509-fingerprint-sha1` (SSL Blacklist), `filename`, … as mapped by the sync's `TYPE_MAPPING`. The one label that ages, whoever supplied it (2026-10-16, see [Indicator aging](#indicator-aging-2026-10-16)): `last_reported_at`, `last_reported_source`, `last_reported_ref`, `last_reported_basis`, `last_recorded_at`, `source_confidence`, `aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `aging_evaluated_at`, `active`, `retired_at`, `retired_by` |

---

## Relationship Types

| Relationship | From → To | Source / Confidence |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | ThreatActor → Technique | **Attribution.** `match_type='mitre_explicit'` (0.95) from MITRE STIX `uses` → `uses_techniques`; `match_type='otx_pulse'` (0.6, 2026-10) from OTX pulse `attack_ids` → `reported_techniques`. Q5 runs before Q5b so a pair MITRE asserts keeps the explicit stamp. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Malware → Technique | **Capability.** `match_type='mitre_explicit'` (0.95) via `uses_techniques`; `match_type='otx_pulse'` (0.6, 2026-10) via `reported_techniques`. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Tool → Technique | **Capability.** MITRE STIX explicit `uses` relationship (confidence 0.95) *(split from a generic `USES` in 2026-04)* |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `match_type='exact'` (1.0): the malware's own `m.attributed_to` claim matched exactly against `a.name` OR `a.aliases` (the "Cozy Bear → APT29" path; `build_relationships.py` Q2). `match_type='otx_pulse'` (0.6, 2026-10): malware and actor named in the same OTX pulse, written by the MISP→Neo4j sync; the pulse is in `r.source_refs[]` (`alienvault_otx:<pulse id>`). Only from a pulse whose actors are one actor (2026-10-15): a pulse naming several actors does not say which malware is whose, so it attributes nothing; the aliases of one actor count as one (canonical threat-actor reference). The OTX collector decides it on the pulse's whole adversary list (MISP holds each actor once, so a later event may carry only some of a pulse's actors) and marks the pulse's items (`several_actor_pulses`); the mark accumulates on the indicators (`i.several_actor_pulses[]`, 2026-10-16), and step 2d takes as naming several actors both the pulses whose actor nodes are several actors and the pulses marked there, as the collector judged them with the canonical reference (the actor nodes miss a pulse edited to name several actors after its pairs were written; its mark reaches the indicators through the pulse's new IOCs, and the MISP writer adds no mark to a stored copy (2026-10: MISP keeps what the sources said), so a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit to be closed by a per-pulse MISP record; a mark judged by name without the reference serves the sync's own run and is not stored). `build_relationships` step 2d links the pairs the indicators carry (`family::adversary::pulse`) to the adversary or its canonical actor, removes the attributions an earlier run made from such pulses (unless another feed asserts them) and drops such pulses from the provenance of the others. Whole-event co-occurrence attribution was removed in 2026-10 (fresh-baseline PR). |
| `INDICATES` | Indicator → Malware | `match_type='malware_family'` (0.8): source-asserted family name match (ThreatFox, MalwareBazaar or Feodo Tracker, Q9; VirusTotal and OTX send no family label, and since 2026-10 OTX is no longer named in `r.sources` of a Q9 link) **and** `match_type='otx_pulse'` (0.6, 2026-10): same-run pairing by the sync, and — for regular updates — Q9b from the families the pulse stamps on each indicator (`pulse_malware_families`, looked up by the name as given and without an ATT&CK software id suffix, each through the node the twin merge folded that name into); indicator and malware listed in the same OTX pulse (sync path). The whole-event co-occurrence query (old Q4, 0.5) was removed in 2026-10. |
| `EXPLOITS` | Indicator → Vulnerability/CVE; ThreatActor / Malware → CVE | Indicator: CVE tag on the indicator, exact match (`match_type='cve_tag'`, 1.0); not produced from event co-membership since 2026-10. ThreatActor / Malware → CVE (2026-10): a curated package's claim (`match_type` = the package's curated label, 0.85) — the link that joins EdgeGuard's threat side to the CVE node ResilMesh's `Vulnerability → REFERS_TO → CVE` path ends on. |
| `REFERS_TO` | Vulnerability ↔ CVE | `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor → Campaign | `build_campaign_nodes()`; `campaign_grouping`, the confidence of the actor's strongest link to a malware (2026-10-15; `ATTRIBUTED_TO` or, since 2026-10-16, `USES_MALWARE`); `r.evidence_types[]` names the types of those links (2026-10-16); recomputed on every run from the actor's current links, and removed when it comes from an actor that is not the campaign's or has neither link (a campaign whose actor has none left is deleted, 2026-10-16) |
| `PART_OF_CAMPAIGN` | Malware, Indicator → Campaign | `build_campaign_nodes()`; a malware is a member while it is attributed to the campaign's actor (2026-10-15) or (2026-10-16) used by it (`USES_MALWARE`), an indicator while it `INDICATES` a member (the 100 newest active ones, each once); `campaign_grouping`, the confidence of the malware's strongest link to the actor (malware) or of the indicator's best path, `INDICATES` then `ATTRIBUTED_TO` or `USES_MALWARE`, each path as strong as its weaker link (indicator; 2026-10-15); `r.evidence_types[]` names the relationship types it rests on, e.g. `["ATTRIBUTED_TO", "USES_MALWARE"]` on a malware, `["INDICATES", "USES_MALWARE"]` on an indicator (2026-10-16) (named `PART_OF` until 2026-10: ResilMesh uses `PART_OF` for its asset hierarchy, and one name must have one meaning in the shared database) |
| `INVOLVES` | Alert → Indicator | `neo4j_client` alert path (`alert_processor`, NATS) — not part of the collector pipeline; excluded from the acceptance script's policed types |
| `USES_TECHNIQUE` | Indicator → Technique | OTX pulse `attack_ids` exact MITRE ID match (confidence 0.85); an id ATT&CK revoked matches its successor (2026-10) |
| `AFFECTS` | Vulnerability/CVE → Sector | "The vulnerable product is used in this sector." Zone list unwind, per sector only the feeds whose `SOURCED_FROM.zones` give it (2026-10-16); `advisory_sector`, 0.9, where CISA's ICS advisory states the sector (deployed in it), else `zone_classification`, 0.5 (inferred sector); `global` never linked — 2026-10 audit |
| `TARGETS` | Indicator / ThreatActor / Malware → Sector | "Reported in connection with attacks on this sector." Zone list unwind, per sector only the feeds that gave it (2026-10-16); `zone_classification`, 0.5 (a CISA deployment statement never labels TARGETS); actor and malware edges added 2026-10 (sector focus); `global` never linked |
| `IN_TACTIC` | Technique → Tactic | Kill-chain phase exact match (confidence 1.0) |
| `SUBTECHNIQUE_OF` | Technique → Technique | Sub-technique → parent from MITRE's dotted id (`T1021.006` → `T1021`); `mitre_explicit`, 1.0 (2026-10) |
| `USES_MALWARE` | ThreatActor → Malware | MITRE's explicit group → malware `uses`; `mitre_explicit`, 0.95 (2026-10, R6); curated-package claims, 0.85. Campaign evidence like `ATTRIBUTED_TO` (2026-10-16) |
| `USES_TOOL` | ThreatActor → Tool | MITRE's explicit group → tool `uses`; `mitre_explicit`, 0.95 (2026-10, R6) |
| `HAS_CVSS_v2/v30/v31/v40` | CVE ↔ CVSS sub-nodes | Bidirectional (ResilMesh schema) |
| `REFERS_TO` | CVE ↔ Vulnerability | Bidirectional bridge by cve_id (`enrichment_jobs.bridge_vulnerability_cve`) |
| `SOURCED_FROM` | Node → Source | **Per-source provenance edge.** ONE edge per (entity, source) pair (multi-source IOCs preserve full provenance). See [SOURCED_FROM edge schema](#sourced_from-edge-schema) below for the full property contract. |

### SOURCED_FROM edge schema

Every threat-intel node (Indicator, Vulnerability, Malware, ThreatActor, Technique, Tactic, Tool) carries one `(:Node)-[r:SOURCED_FROM]->(:Source)` edge per reporting source. The edge holds both DB-local facts (when EdgeGuard saw this source report this entity) AND the source's own claim (when the source itself says it first/last recorded the entity). Per-source attribution preserves full provenance for multi-source IOCs.

| Property | Semantic | Type | Write rule | Source |
|---|---|---|---|---|
| `r.imported_at` | When EdgeGuard FIRST saw THIS source report this entity | DateTime | `ON CREATE SET = datetime()` (set once per edge, never overwritten) | DB-local |
| `r.updated_at` | When EdgeGuard LAST saw this source report it | DateTime | `SET = datetime()` on every MERGE (always current) | DB-local |
| `r.source_reported_first_at` | Source's own claim about when it first recorded the entity (NVD `published`, CISA `dateAdded`, MITRE `created`, ThreatFox `first_seen`, AbuseIPDB `firstSeen`, etc.) | Optional DateTime | MIN CASE with NULL short-circuit: earliest claim wins; stale imports cannot regress | Source claim |
| `r.source_reported_last_at` | Source's own claim about when it last recorded the entity | Optional DateTime | MAX CASE with NULL short-circuit: latest claim wins | Source claim |
| `r.confidence` | Per-source confidence score for THIS observation | Float | `SET = $confidence` every MERGE | Per-collector |
| `r.source` | Source identifier (string copy of source_id; redundant with `s.source_id` but cached on edge for performance) | String | `SET = $source_id` every MERGE | Per-collector |
| `r.misp_event_ids` | The MISP events in which THIS source carried the entity (2026-10) | List of strings | Accumulated (deduplicated) on every MERGE; never replaced | MISP |
| `r.source_refs` | THIS source's own record ids for the entity, `"<source>:<id>"` (OTX pulse, ThreatFox IOC id, URLhaus entry, ATT&CK id; 2026-10; the CISA ICS advisories that name the CVE, `cisa_ics:ICSA-…`, 2026-10-16). Links derived after the sync copy these two lists from the subject node's edge (see "Relationship provenance" below) | List of strings | Accumulated (deduplicated) on every MERGE; never replaced | Per-collector |
| `r.zones` | The zones THIS source's records gave the entity (2026-10-16). The node's `zone` is the union over its sources; `build_relationships` steps 7a–7d name on a link to a `Sector` only the feeds whose `zones` contain that sector | List of strings | Accumulated on every MERGE with the node's rule: `global` dropped once a sector is present, sorted | MISP zone tags of the source's attribute |
| `r.stated_zones` | The part of `zones` THIS source stated itself rather than EdgeGuard inferring it (2026-10-16): for `cisa_ics`, every sector its advisories name (`src/sector_evidence.py`); for every other source, none. A link to such a sector carries `advisory_sector` | List of strings, absent when empty | Accumulated (sorted set) when the record states a zone | Source statement |
| `r.stated_refs` | Which of THIS source's records stated which of `stated_zones`, as `"<zone>\|<source ref>"` (2026-10-16): for `cisa_ics`, the advisories whose sector note names each sector (`healthcare\|cisa_ics:ICSMA-26-283-01`). A link to a `Sector` cites only the records recorded for its sector; an edge without an entry for the sector (an inferring source, or an edge written before) gives all of its `source_refs` | List of strings, absent when empty | Accumulated (sorted set) when the record states a zone | `NVD_META.advisory_zones` |
| `r.raw_data` | Full source-specific payload as JSON (audit trail for one (entity, source) observation) | String (JSON) | `ON CREATE SET = $raw_data`; on a `CVE` also `SET` on every write from a MISP attribute (2026-10), so the edge holds the source's latest record (a KEV or NVD copy edited in MISP reaches it at the next sync); on other labels, and against the reduced record of the opt-in STIX import (`run_pipeline --stix-flow`, written under the MISP event's source id), the record that created the edge | Per-collector |
| `r.src_uuid` | Indicator/CVE/Malware/etc. node UUID (cached on edge for serialized-edge consumers — RAG / xAI use cases) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.trg_uuid` | Source node UUID (cached on edge, same rationale as `src_uuid`) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.edgeguard_managed` | Always `true` for edges EdgeGuard owns; allows STIX export to filter against ResilMesh-owned data | Boolean | `SET = true` every MERGE | DB-local |
| `r.last_reported_at`, `r.last_reported_ref`, `r.last_reported_source` | Indicator edges (2026-10-16): THIS source's latest report of the indicator, `min(T, coalesce(L, T))` (T the MISP attribute timestamp, L the source's `last_seen`), the MISP attribute uuid of that report and the source id ([Indicator aging](#indicator-aging-2026-10-16)) | Optional DateTime, strings | Forward only: set when the report is newer (an equal time with a smaller uuid takes the reference) | MISP / source claim |
| `r.last_recorded_at` | Indicator edges (2026-10-16): the latest MISP timestamp of THIS source's attributes for the indicator | Optional DateTime | MAX CASE with NULL short-circuit | MISP |

**Why per-source on edges, not aggregates on nodes?** A single Indicator may be reported by multiple sources (NVD + AbuseIPDB + ThreatFox), each with its own claim. Aggregating to a node-level value via MIN/MAX would destroy the per-source detail. Queries that want a single canonical value compute `MIN(r.source_reported_first_at)` / `MAX(r.source_reported_last_at)` across edges on read (STIX `valid_from`, alert enrichment, campaign aggregate all do this). Read-side aggregation is cheap (~9 edges max per indicator); write-side per-source isolation prevents cross-source contention.

**Honest naming.** `source_reported_first_at` makes explicit "what the source claims to have first recorded", NOT "first observed in the wild". Sources record catalog dates: NVD's `published` is when NVD published the CVE record (after the vuln was actively exploited); MITRE's `created` is when MITRE added the SDO to its TAXII store; etc.

**MIN/MAX merge semantics handle every realistic ordering scenario** — see `src/source_truthful_timestamps.py` module docstring or `migrations/2026_04_first_seen_at_source.md` for the full scenario walkthrough (baseline + incremental + out-of-order + stale-import + multi-source).

**Timestamp invariants.** Every value flowing into `r.source_reported_first_at` / `r.source_reported_last_at` is **either NULL or tz-aware ISO-8601 UTC** (PR-M2 §4-F1). Mixing naive and aware values would corrupt the MIN/MAX comparison since Neo4j parses naive ISO strings as **server-local** time. The canonicalization chokepoint is `coerce_iso()` in `src/source_truthful_timestamps.py`. Producers MUST emit honest NULL when the source field is absent — never wall-clock NOW (PR-M2 §4-F4 / F5). The complete semantic model is documented in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md).

### Relationship provenance: who asserts a link (2026-10)

Every relationship EdgeGuard builds from the threat-intelligence sources carries three lists. Each write adds to them and never replaces them, so no source can erase another's claim, and a link can be traced from Neo4j to the MISP event and to the source's own record. The contract and the shared Cypher fragments live in `src/relationship_provenance.py`.

| Property | Meaning | Example |
|---|---|---|
| `r.sources[]` | The sources that assert the link: canonical ids from `src/source_registry.py` (`alienvault_otx`, `mitre_attck`, `nvd`, `cisa_kev`, `threatfox`, `urlhaus`, `malwarebazaar`, `feodo_tracker`, `ssl_blacklist`, `virustotal`, `abuseipdb`, `cisa_ics`, `misp`, and the curated sources `coreideas`, `misp_galaxy`). An unregistered name is kept as given, except on a curated claim: only a registered curated source may assert one, any other is recorded as `curated_other` (2026-10). | `["mitre_attck", "alienvault_otx"]` |
| `r.source_refs[]` | The sources' own record ids, `"<source>:<id>"`, for sources that have one: the OTX pulse, the ThreatFox IOC id, the URLhaus entry, the ATT&CK id. Sources keyed by the value itself (NVD and KEV by CVE id, MalwareBazaar and VirusTotal by hash, Feodo Tracker and AbuseIPDB by IP, SSL Blacklist by certificate fingerprint) need none: the node is the record. | `["mitre_attck:G0016", "alienvault_otx:5f3c…"]` |
| `r.misp_event_ids[]` | The MISP events that carried the link (capped at 200 per edge). On a campaign link (2026-10-16) the 200 newest by MISP event id, with `r.sources[]` and `r.source_refs[]` sorted, so the same MISP data gives the same lists whatever the order in which the links it rests on were created. | `["137", "141"]` |

**Links to a Sector (2026-10-16).** A node's `zone` is the union of the zones its sources gave, so a link to one of them names only the sources that gave that sector: `build_relationships` steps 7a–7d read the node's `SOURCED_FROM` edges whose `zones` contain the sector (`relationship_provenance.zone_prov_with`) and take `r.sources`, `r.source_refs` and `r.misp_event_ids` from them alone (the events by the fixed sorted rule); of an edge that records its references per sector (`stated_refs`, CISA ICS) only the references of that sector, so a CVE that an ICS advisory names for Energy and a medical advisory for Healthcare cites the first on its energy link and the second on its healthcare link, as the sync's rows do. Before, every link took every feed of the node: on the graph of 2026-10-16, 2,639 of the 6,506 `AFFECTS` links named a feed that never gave their sector, among them 420 NVD or OTX guesses that named `cisa_ics`. Legacy rule, so a graph written before behaves as it did: a `SOURCED_FROM` edge without `zones`, and a feed of the node without a `SOURCED_FROM` edge (the alert path), count as giving every zone of the node. A node sector no feed gave is not linked; the step counts it (`[SKIP]`) and the acceptance check `node_sectors_without_a_feed` reports it. The label is the strongest statement label among the feeds that stated the sector, else `zone_classification`, and the confidence is the value the label table gives it (`src/sector_evidence.py`): the sync and the step agree, a stored stronger label and a label outside the table (a curated or partner label) are kept, and the unconditional reset to 0.5 is gone. The actor alias merge and the Malware twin merge combine `zones`, `stated_zones` and `stated_refs` of two folded edges to one source and keep them sorted lists. A graph built before 2026-10-16 keeps the extra entries in `r.sources` until the next baseline (provenance only accumulates).

`r.match_type` stays the kind of evidence (next section); several sources can share one kind (ThreatFox, MalwareBazaar and Feodo Tracker all give the indicator's family label, `malware_family`), and the strongest evidence keeps the label and the confidence. A `malware_family` link names only the indicator's feeds that give the label (2026-10: OTX was named as well, though its records carry no `malware_family`); OTX is added to it, with the indicator's OTX pulses and MISP events, when a pulse that listed the indicator names the family by the `Malware` node's name, by that name with an ATT&CK software id, or by a name the twin merge folded into the node (`merged_from`; step 9b, which looks families up as the `INDICATES` row says), not when it names it only by another alias of the node, which Q9 matches. Links the sync writes directly get the three lists from the MISP attribute; links derived afterwards (`build_relationships.py`, campaign and Vulnerability↔CVE links in `enrichment_jobs.py`) copy them from the subject node's per-source `SOURCED_FROM` edge, which carries the same `misp_event_ids[]` and `source_refs[]` for that source, or inherit them from the links they are built on (campaign links replace theirs on every run with the provenance of the links they currently rest on, 2026-10-15, so they name no evidence `build_relationships` step 2d removed or trimmed; since 2026-10-16 those are the `ATTRIBUTED_TO` and `USES_MALWARE` links, and the indicator's `INDICATES` links, named in `r.evidence_types[]`). Corroboration is countable: `size(r.sources) >= 2` means independent sources state the link. Until 2026-10 relationships carried a single `r.source_id` (last writer wins; it held evidence names such as `otx_pulse`, `malware_family_match`, `cve_tag_match` or the hub `misp`), a set `r.source_ids` of such names and OTX-only `r.report_ids[]`; all three were dropped.

**Explainability: what the source said, where the graph says something else (2026-10).** Two cases make the graph name a target differently from the source, and both are recorded, so a reader can tell what was claimed from what EdgeGuard derived:

| Property | Meaning | Example |
|---|---|---|
| `r.cited_ids[]` | On a technique link (`USES_TECHNIQUE`, `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`): the ATT&CK ids the sources cited that ATT&CK has since revoked into the link's technique (see "Revoked and deprecated ATT&CK objects"). Accumulated, de-duplicated; absent when every source cited the technique's own id. Written by `build_relationships` (steps 5, 5b, 6, 6b, 8, 10), by the sync for MISP technique tags, and for curated claims. | An OTX pulse cited `T1562` (Impair Defenses), which ATT&CK revoked into `T1685`: the link to `T1685` carries `["T1562"]` |
| `r.evidence_types[]` | On a campaign link (`RUNS`, `PART_OF_CAMPAIGN`, 2026-10-16): the relationship types of the links it rests on, sorted: `ATTRIBUTED_TO` and `USES_MALWARE` between the actor and a malware, and `INDICATES` on an indicator's link. Recomputed on every run with the link's confidence and provenance. | `["ATTRIBUTED_TO", "USES_MALWARE"]` on the `RUNS` of an actor with both kinds of link |
| `n.merged_from[]` | On a `ThreatActor`: the names of the duplicate nodes the actor alias merge folded into this one; on a `Malware` node (2026-10): the names of the ATT&CK-id twins the twin merge folded into it, which steps 9b / 2d resolve to this node. Unlike `aliases`, which also hold every source's aliases, it names only the merges, so a wrong merge can be traced and undone. Accumulated across merges. | `clop` carries `["cl0p"]`; `cobalt strike` carries `["cobalt strike - s0154"]` |

Together with `r.sources[]` and `r.source_refs[]`, a link reads in full: "the OTX pulse 5f3c… cited T1562, which ATT&CK revoked into T1685". The STIX export carries both (`x_edgeguard_cited_ids` on SROs, `x_edgeguard_merged_from` on intrusion-sets; extension definition 1.3.0), and the evidence types of campaign links (`x_edgeguard_evidence_types`; 1.5.0, 2026-10-16).

### Curated packages (2026-10)

A curated package is a set of claims about entities already in the graph (actor uses technique / malware / tool, malware implements technique, actor or malware exploits CVE), imported once into MISP as its own EdgeGuard event with `scripts/import_curated_package.py` (validate, then `--push`; see the script's docstring for the JSON format). Each `threat-actor` / `malware-type` attribute names an existing node by its canonical name and carries the node's claims in a `CURATED_CLAIMS:` comment. The MISP→Neo4j sync turns every claim into a relationship of an existing type (`EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`, `USES_MALWARE`, `USES_TOOL`, `EXPLOITS`), MATCHing both ends by exact canonical name or id. A curated attribute is not merged as a node at all: a package never creates nodes and never changes the node it names; its provenance lives on the relationships. Labels and provenance:

- **Label and confidence on the links a claim creates only.** A link the claim creates gets the package source's curated label from the source registry (`coreideas` → `coreideas_curated`; `curated_other` for a curated source without a label of its own, e.g. `misp_galaxy`) and confidence 0.85. A link that already exists keeps its `match_type` and `confidence_score` (an `otx_pulse` link stays `otx_pulse` at 0.6, a `mitre_explicit` link stays `mitre_explicit`); the claim adds its source to `r.sources`, its record id to `r.source_refs` and the package's event to `r.misp_event_ids`. `match_type` therefore shows which links a package created, not every link it asserts.
- `r.sources` = the source that asserts each claim (a package may carry claims from several sources, e.g. `misp_galaxy`), `r.source_refs` = that source's record id. Only registered curated sources (`source_type="curated"` in `src/source_registry.py`: `coreideas`, `misp_galaxy`) may assert a claim: the importer rejects a claim from any other source, and the sync records one that still arrives as `curated_other`.
- `r.tlp` = the package's TLP level (required by the importer and tagged on every attribute), on every link a claim touches, most restrictive wins. Only curated links carry `r.tlp`. The STIX export marks each relationship with the most restrictive of its endpoints' markings and `r.tlp`.
- A claim attaches only when both ends exist by exact name or id. The sync counts the claims that did not attach (`curated_claims_unattached` in the sync stats), logs them with a sample of the missing names (`[CURATED]` lines) and never counts them as created relationships.
- **Leaving the layer out of a shared dataset:** select by `r.sources`, not by `r.match_type`. Keep the links with at least one non-curated source, `any(s IN r.sources WHERE NOT s IN ['coreideas', 'misp_galaxy', 'curated_other'])`, and drop the curated entries from their `sources` / `source_refs` and their `tlp`: a link a package did not create keeps its own label, so `match_type` does not show that a curated source also asserts it.
- Removing the layer from a live graph: `docs/RUNBOOK.md`, "Importing a curated package".

### Actor alias merge and canonical threat actors (2026-10)

One actor reaches the graph under several names (`lazarus` from OTX, `lazarus group` from ATT&CK), so its evidence splits across `ThreatActor` nodes. The enrichment job `merge_alias_duplicate_actors` folds the duplicates into one node after every sync, before the Campaign builder. Two rules propose a (canonical, duplicate) pair:

- **ATT&CK aliases.** A node that is not MITRE-sourced and whose name is an alias (`c.aliases`) of exactly one MITRE-sourced node; a name that is an alias of several is skipped.
- **The canonical threat-actor reference.** `src/reference/canonical_threat_actors.json` is built by `scripts/build_canonical_threat_actors.py` from the ATT&CK groups and the public MISP threat-actor galaxies (CC0), plus reviewed decisions, and is versioned by date. It gives every name it knows one place: the key of one canonical actor (for an ATT&CK group, the name EdgeGuard writes for it), a synonym of one actor, or `ambiguous` (several actors, or a reviewed never_merge). A node that is not MITRE-sourced and whose name resolves to another canonical key that is a node on the graph is a duplicate of it (`cl0p` → `clop`, `sandworm` → `sandworm team`). Ambiguous and never_merge names are never resolved.

A MITRE-sourced node is never a duplicate, and two ATT&CK groups are never merged. ATT&CK groups that ATT&CK revoked into another stay as their own nodes; the reference resolves their names to the successor. A node the two rules give different canonicals, and a node that would be both a canonical and a duplicate in the same run, are skipped and counted (`skipped_conflict`, `skipped_chain`).

The reference also checks the ATT&CK-alias pairs. A canonical's `aliases` hold ATT&CK's aliases and every name merged into it earlier, so the ATT&CK rule alone would keep folding a name a reviewer has since marked never_merge. A pair whose duplicate the reference marks ambiguous or never_merge is skipped (`skipped_blocked`), and a pair whose duplicate it gives to another actor, or keeps as an actor of its own, is a conflict. A name the reference does not list is left to the ATT&CK rule.

A merge adds the duplicate's name to the canonical's `aliases` and to `merged_from` (only the names this job folded in), moves all of its relationships to the canonical (`apoc.refactor.mergeNodes`: scalars keep the canonical's value, lists are combined; `tlp` is first set to the most restrictive level of the canonical and its duplicates, so a merge never loosens it, 2026-10-15), re-stamps their `src_uuid` / `trg_uuid` with the canonical's uuid, and removes the duplicate node. Parallel relationships (same type, same other node, same direction) collapse into one: it keeps the union of their `sources`, `source_refs`, `misp_event_ids` and `cited_ids`, and the strongest evidence's `match_type` and `confidence_score` (on a tie the alphabetically first label), the rule every writer follows, and the most restrictive `r.tlp` of the group (curated-package links carry one). APOC stores two equal merged values as one string (two OTX names of one actor both hold `source = ["alienvault_otx"]`); the merge wraps every list property of the node, and the provenance lists of its edges, back into lists. The Campaign builder then rebuilds the canonical's campaign and deletes the duplicate's: no actor of its name remains (2026-10-16; it was kept, inactive, before). When the reference file is missing, unreadable or inconsistent, or its data cannot be applied to the graph's names, the job logs one warning (`canonical reference unavailable`) and merges by ATT&CK aliases alone. `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false` makes the job a dry run that logs the pairs, the reference pairs included, and merges nothing; `EDGEGUARD_CANONICAL_THREAT_ACTORS` overrides the reference path.

### Malware named after an ATT&CK software id (2026-10)

OTX names malware families as the MISP ATT&CK galaxy names its clusters, with the ATT&CK software id as a suffix: `"Cobalt Strike - S0154"`, `"njRAT - S0385"`. Until 2026-10 the OTX collector passed such names through, the MISP→Neo4j sync and `merge_malware` kept them (lower-cased), and each became a `Malware` node of its own (`cobalt strike - s0154`) beside the node ATT&CK delivered (`cobalt strike`). The family's indicators split between the two: on the graph of 2026-10-14, 136 such twins held 16,005 `INDICATES` links, and a query on the ATT&CK Cobalt Strike node found 55 indicators instead of about 2,078.

- **Ingest.** One helper, `split_attack_software_id` (`src/attack_software_names.py`), turns a name ending in `<whitespace>-<whitespace>S####` (case and extra whitespace ignored) into its base name and the id. The OTX collector names the malware item, its `family`, the indicators' `pulse_malware_families` and the family side of `pulse_malware_actor_pairs` by the base name and keeps the original string in the item's `aliases`. The sync does the same for every `malware-type` attribute (attributes written before 2026-10, or by another writer; the original string joins `aliases`), for the malware names of MISP galaxy tags (`misp-galaxy:mitre-malware="Cobalt Strike - S0154"`), and for `OTX_META.mf`, `.pa` and `.malware_family`; so does the command-line MISP reader (`misp_collector`), and (2026-10-16) the sync's own STIX conversion of a `malware-type` attribute, used when PyMISP's conversion is not available (the original string as the STIX object's `aliases`).
- **Links from indicators written before, and from later pulses.** `build_relationships` steps 9b (`INDICATES`) and 2d (`ATTRIBUTED_TO`) look a family up by its name as given and without the id (`apoc.text.replace` with the pattern as a query parameter), so an indicator that still lists `Cobalt Strike - S0154` links the ATT&CK node; until the twin is folded it links both. Each of the two names is first replaced by the node the twin merge folded a node of that name into (`$folded_families`, read once per run from the `merged_from` lists of the `Malware` nodes; an entry that carries an id also stands for its base name; a name that leads to two nodes, or that is an ATT&CK node's own name, is left as it is). A folded node is gone, and a later pulse that names its family is a MISP cross-event duplicate that creates no new node: once `agenttesla` (alias `AgentTesla - S0331`) is folded into the ATT&CK node `agent tesla`, the indicators of a pulse naming `AgentTesla` link `agent tesla`. `merged_from` is written only by the merge jobs, so, unlike `aliases`, no source can redirect a family. The acceptance check `pulse_indicates_complete` looks families up the same way.
- **Folding existing twins (no new baseline needed).** The enrichment job `merge_malware_attack_twins` runs after the actor alias merge and before the Campaign builder. A `Malware` node that is not MITRE-sourced and whose name, or an alias of its own name, ends with an ATT&CK software id folds into the MITRE-sourced `Malware` node of that id. The MITRE node carries no `mitre_id`: its id is read from the record MITRE delivered, the `raw_data` of its `SOURCED_FROM` edge to the ATT&CK source, whose description opens with a link to the software (`[Cobalt Strike](https://attack.mitre.org/software/S0154)`), as the canonical threat-actor reference reads group ids. When that id cannot be read, the MITRE node of the same base name is the target; a name whose id contradicts the twin's is not. A revoked software id is translated to its successor first (`Darkmoon - S0209` → PoisonIvy). A twin whose id and base name lead to more than one MITRE node is skipped on every run (`skipped_ambiguous`) and needs a decision by hand. Software without a MITRE `Malware` node has no ATT&CK target: ATT&CK tools such as Mimikatz `S0002` are `Tool` nodes, never merge targets. Since the collectors name a family by its base name, a later pulse creates the node `mimikatz` beside the twin `mimikatz - s0002`, and steps 9b / 2d would link every indicator written before to both; such a twin therefore folds into the non-MITRE `Malware` node of its base name when that node states no other ATT&CK id (`base_name_targets`; twins of one base name that state different ids fold nowhere). A twin with neither target is left as it is and counted (`no_target`) until a pulse creates the node of its base name.
- **The merge** is the actor alias merge's (same statements, built for the `Malware` label): the twin's name joins the target's `aliases` and `merged_from`, `tlp` becomes the most restrictive level of the two, all relationships move to the target (parallel ones collapse with the union of their provenance lists and the strongest evidence), their `src_uuid` / `trg_uuid` are re-stamped, every list property stays a list (`malware_types` is combined as well), and the target keeps its name and uuid. The statement re-checks each target at merge time: a MITRE-sourced node, or a node of a twin's base name the plan chose, into which only a twin named `<its name> - s####` folds. Batched, idempotent; `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE=false` makes it a dry run that logs the pairs (`[MALWARE-TWIN-MERGE]` log lines).
- **Acceptance.** `scripts/verify_fresh_baseline.py` fails `malware_attack_twins_folded` when a twin the job folds (into a MITRE node or into the node of its base name), or one it cannot decide, is still a node; twins without a target are reported.

### Evidence labels, report provenance, TLP (2026-10)

- `r.match_type` states the evidence behind every edge (`mitre_explicit`, `otx_pulse`, `exact`, `malware_family`, `cve_tag`, `otx_attack_ids`, `kill_chain_phase`, `campaign_grouping` for the campaign links EdgeGuard derives (2026-10-15; until then they carried none), for curated packages `coreideas_curated` / `curated_other`, and on links to a `Sector` `zone_classification` (EdgeGuard's inference, 0.5) or `advisory_sector` (CISA's ICS advisory states that the product is deployed in the sector, 0.9, `AFFECTS` only, 2026-10-16)) — see `docs/RESILMESH_INTEROPERABILITY.md` §3.2.2 for the table with confidences. A query that filters sector links on `match_type = 'zone_classification'` alone misses CISA's statements.
- `r.source_refs[]` holds the OTX pulse (`alienvault_otx:<pulse id>`) on report-scoped edges; `n.pulse_ids[]` on `Malware` / `ThreatActor` nodes (every pulse that named them); `n.reported_techniques[]` next to `n.uses_techniques[]` (pulse-level vs MITRE-explicit ATT&CK ids).
- `n.tlp` on every EdgeGuard node (from the `tlp:<level>` MISP tag; default `white`). `r.tlp` on curated-package links only: the package's level (see "Curated packages").
- `n.attack_domain` (`enterprise` | `ics`) on `Technique` and `Tactic` (from the `attack-domain:<domain>` MISP tag); `IN_TACTIC` is created only within the same domain. ATT&CK for ICS is ingested when `EDGEGUARD_ENABLE_MITRE_ICS=true` (97 techniques T08xx, 12 tactics TA0100–TA0111, shared groups/malware keep one node with unioned technique lists). `ThreatActor`, `Malware` and `Tool` carry no `attack_domain` (a group or software item in both ATT&CK bundles keeps the Enterprise item), so measure ATT&CK for ICS through the links into ICS techniques (`IMPLEMENTS_TECHNIQUE` / `EMPLOYS_TECHNIQUE` / `SUBTECHNIQUE_OF` to a `Technique {attack_domain: 'ics'}`) and `IN_TACTIC` from an ICS technique to an ICS tactic ([NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md), "Measuring CISA ICS and ATT&CK for ICS").
- `edgeguard_managed = true` on every EdgeGuard edge and on every node EdgeGuard **creates** (stamped on the MERGE create path only since 2026-10; a node a partner created first that EdgeGuard writes to gets `edgeguard_enriched = true` instead) — so `edgeguard clear neo4j --edgeguard-only` removes exactly the nodes EdgeGuard created from a shared database, and the APIs / STIX export expose nodes it created or enriched.
- `CVE` nodes carry `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]`, `reference_urls[]`, `affected_products[]` from NVD (ResilMesh CVE properties), and `status[]` (2026-10): NVD's record status, `["active"]` or `["rejected"]`, replaced when NVD changes it. A node written before 2026-10 gets it at its next write; a full sync writes it on every NVD CVE. When an NVD record is merged into a node whose only source is NVD, the six lists are set from it even when empty; on a node with another source (CISA ICS, KEV, OTX) an empty NVD list leaves the property as it is. A CVSS sub-node of a version the record no longer has is removed if NVD alone asserted it, before the node's score is derived from its CVSS sub-nodes. An NVD record carries every CVSS version NVD supplies (2026-10; before, only one of 3.1, 3.0 and 2, so an update removed the sub-node of an older version when NVD added a newer one).
- `CVE.attack_vector` (2026-10) is the attack vector of the CVSS that gives the score (`cvss_score`, `cvss_version`: the first CVSS in the order v3.1 → v3.0 → v2 → v4.0), in NVD's words — `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` — and null without CVSS. `merge_cve` sets it with the score from the CVSS sub-nodes (CVSS 3.x `attack_vector`, CVSS 2 `access_vector`, the `AV` metric of a CVSS 4.0 `vector_string`), whatever record arrives last; no record's own value is written. Graphs built before 2026-10 mix the letters of the vector strings (`N`, `L`, `A`, `P`), NVD's words and an invented `UNKNOWN` (the KEV and OTX records sent `NETWORK`): on the hosted graph of 2026-10-15, `attack_vector = 'NETWORK'` matched 3,305 CVEs, and a re-merge of every CVE gives 100,779.
- `CVE.epss_score` / `epss_percentile` (2026-10): FIRST EPSS, the probability of exploitation in the next 30 days and its percentile, with `epss_score_date`, `epss_model_version` and `epss_updated_at`; set by the post-sync job `enrich_cve_epss` on the `CVE` nodes that exist and removed from a CVE that left the feed (the one source written to Neo4j without MISP, [DATA_SOURCES.md § 8b](DATA_SOURCES.md)).
- `CVE.ssvc_exploitation` (`none` / `poc` / `active`), `ssvc_automatable` (`yes` / `no`), `ssvc_technical_impact` (`partial` / `total`), with `ssvc_version` and `ssvc_timestamp` (2026-10): CISA's SSVC decision, as NVD relays it in the CVE record; set from NVD's record only and removed when the record has none.
- `CVE.published` and `last_modified` (2026-10): NVD's record (an NVD attribute with `NVD_META`, `nvd_record`) sets them; a record from any other source — CISA KEV, CISA ICS, an OTX pulse, a STIX import, a partner write through `merge_resilmesh_cve` — fills them only where the node has none (an empty string counts as none). Of the other records only CISA ICS gives dates (the advisory's release dates, not the CVE's), from one attribute per CVE in MISP, so they stay outside the description's ranking. `CVE.description` and `description_source` (2026-10-16): the source ranking NVD > CISA KEV > CISA ICS > any other source ("Descriptions and their source" below); until then NVD's record set the description and any other record only filled it, so a CVE without an NVD record kept the text of the first record to arrive. For a CVE, the sync never takes a comment that is a metadata block (`NVD_META:`, `OTX_META:`, `TF_META:` or any other `*_META:`) as the description, only the block's own `description` field, and never a comment that only says where the CVE was seen: the OTX collector's pulse reference "Referenced in OTX pulse: <name>" (a `cve_references` item) and MISPWriter's placeholder "CVE from <source>" give no description, so CISA's KEV text describes a CVE that only OTX and the KEV name. Until 2026-10 the record merged last set all three: a CVE an OTX pulse listed as an indicator showed the pulse's raw `OTX_META` JSON, a pulse reference "Referenced in OTX pulse: <name>", a KEV record CISA's short description and a CISA ICS record the advisory's dates, depending on the order of the events in the sync. `:Vulnerability` follows the same rules (`merge_vulnerability`, `merge_vulnerabilities_batch`). In the opt-in STIX flow (`run_pipeline --stix-flow`, MISP → STIX → Neo4j) a `vulnerability` object carries the source of its event (`x_edgeguard_source`), so the description is the one the attribute flow gives (until 2026-10-16 every object, NVD's included, only filled it); the dates come only from the attribute flow. An existing graph is repaired by one full sync after cleanup statements ([RUNBOOK.md § Repairing CVE descriptions and dates](RUNBOOK.md#repairing-cve-descriptions-and-dates-2026-10)).
- `CVE.cisa_exploit_add`, `cisa_action_due`, `cisa_required_action` and `cisa_vulnerability_name` (2026-10): the CISA KEV record owns them. A KEV record (source `cisa_kev`) sets them when it carries a value; any other record, NVD's included (NVD copies the four from its own KEV enrichment), only fills them where the node has none (an empty string counts as none), whatever the order of the records in the sync. Until then the record merged last set them, and NVD's MISP copy can hold an older value: NVD did not move `lastModified` when CISA moved the due date of CVE-2022-0995 (2026-10-08), so NVD's copy kept the old date and a sync that read it after the KEV record wrote it back. `known_ransomware_use` comes from KEV records only and is replaced by each. Since 2026-10 every KEV run edits the stored MISP copy of an entry CISA revised ([COLLECTORS.md § 3](COLLECTORS.md#revisions-every-run-compares-the-catalogue-with-misp-2026-10)), and the incremental sync carries it to these properties and to the `SOURCED_FROM` edge's `raw_data`. What does not follow a revision: with `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false`, an entry outside the window (the KEV collector neither adds nor edits it, and where NVD's record alone gives the four fields it only fills them); an entry CISA removes from the catalogue keeps its properties (counted and logged by the collector only), the zones EdgeGuard detected in an entry accumulate on the node and on the edge (`zone`, `r.zones`) like every source's, and a revised KEV description shows on the node only where NVD gave none (the ranking below).
- `Malware.description`, `ThreatActor.description` and `Tool.description` (2026-10): ATT&CK's text wherever ATT&CK describes the entity. Since 2026-10-16 these descriptions, and those of `Technique` and `Tactic`, follow the source ranking MITRE ATT&CK > a curated source > any other source, with `description_source` ("Descriptions and their source" below): the record MITRE delivered (source `mitre_attck`: the MITRE collector's MISP attributes, and in the opt-in STIX flow the objects of a MITRE event) ranks first, so ATT&CK's text stays whatever the order in which the records are merged; until then any other record only filled an empty description (a `Technique` or `Tactic` took any record's). The OTX collector gives its malware-family and adversary items no description: a pulse's description describes the report, not the family or actor. A family or actor only OTX names therefore shows no description; the pulse that first named it (and the other pulses of that collector run that named it) are in `n.pulse_ids[]`, since its MISP attribute is written once, and later pulses link to it through `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`. The sync takes no description from an OTX malware or actor attribute (MISP keeps the attributes written before 2026-10, which carry a pulse's text after their block), from a metadata block (`MITRE_USES_TECHNIQUES:{...}` or any other, also one that does not parse or follows other text; only the text MISPWriter writes after a block's JSON), or from MISPWriter's placeholder for an item without text ("Malware from <source>", "Threat actor from <source>", "MITRE ATT&CK tool: <name>", and for techniques and tactics "MITRE ATT&CK technique from <source>", "MITRE ATT&CK tactic"); the STIX objects of the STIX flow follow the same rule. Until 2026-10 the record merged last set the description: ATT&CK's text of Cobalt Strike or APT29 gave way to an OTX pulse's description, a family from a pulse without a description stored the raw `MITRE_USES_TECHNIQUES:{"rt":[...],"pid":"..."}` block, and every `Tactic` showed "MITRE ATT&CK tactic" (the MITRE collector now gives tactics ATT&CK's description). An existing graph is repaired by one full sync after cleanup statements ([RUNBOOK.md § Repairing Malware, ThreatActor and Tool descriptions](RUNBOOK.md#repairing-malware-threatactor-and-tool-descriptions-2026-10)).

### Descriptions and their source (2026-10-16)

A `CVE`, `Vulnerability`, `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node keeps one description: the text of the highest-ranked source whose record gave one (`src/description_ranking.py`). `n.description_source` names that source by its canonical id (`nvd`, `cisa_kev`, `mitre_attck`, …).

| Nodes | Ranking, highest first |
|---|---|
| `CVE`, `Vulnerability` | NVD, CISA KEV, CISA ICS, then every other source |
| `Malware`, `ThreatActor`, `Tool`, `Technique`, `Tactic` | MITRE ATT&CK, the curated sources (Core Ideas, then MISP Galaxy), then every other source |

- **The rule.** A record sets the description, with its source, when its source ranks at least as high as the source of the stored text: the same source's revised record replaces its own text, a lower-ranked source never replaces a higher-ranked one, and any record fills an empty description (null or `''`). A record without text changes nothing. Neo4j decides once per write, before it sets both properties (`DescriptionRanking.set_cypher`).
- **No ties.** Inside a group of several sources (the curated sources, every other source) the source with the higher registry `reliability` ranks higher, then the one whose id sorts first; a source the registry does not know (`stix_import`, `resilmesh` for a ResilMesh-native write through `merge_resilmesh_cve` / `merge_resilmesh_vulnerability`, the source name of an external STIX bundle) ranks below every registered one, two such sources by id. So no two sources share a rank, and the order of arrival cannot decide.
- **Order of arrival.** MISP holds one attribute per source per CVE or entity: MISPWriter skips an attribute whose type and value its source already holds in any event (cross-event deduplication), and NVD's update edits NVD's stored copies in place. Each source gives one text, so the node shows the highest-ranked text whatever the order of the events, in a full and an incremental sync and in the attribute and the STIX flow alike. Where MISP holds two attributes of one source for one node (the cross-event check switched off or its prefetch failed, both logged; a technique, tactic or tool ATT&CK renamed, whose attribute value carries the name), the one merged last is kept.
- **Nodes written before 2026-10-16** have a description but no `description_source`. Their text counts as the top source's: only NVD's record (CVE, Vulnerability) or MITRE's (the other labels) replaces it, and any other record fills only an empty description. The repair sections of [RUNBOOK.md](RUNBOOK.md#repairing-cve-descriptions-and-dates-2026-10) remove those descriptions on the nodes EdgeGuard created before one full sync writes them again, each with its source.
- **Merged nodes.** The actor alias merge and the Malware ATT&CK-id twin merge keep the description, with its source, that the ranking keeps among the nodes they fold together (equal ranks: the canonical node's).
- **Where it is exposed.** REST (`/vulnerabilities`, `/actors/{name}/summary`, the Graph Explorer's vulnerability view, which shows of a CVE's twin nodes, `:CVE` and `:Vulnerability`, the description the ranking keeps; at an equal rank the twin that names a source, since a record of that source replaces a text without one, then the source id), GraphQL (`descriptionSource` on `CVE`, `Vulnerability`, `ThreatActor`, `Malware`, `Technique`, `Tactic`, `Tool`) and the STIX export (`x_edgeguard_description_source` on an SDO with a description, extension definition 1.6.0).
- **Every source's text.** The node's `SOURCED_FROM` edge to each source names the MISP events that hold that source's attribute (`r.misp_event_ids[]`) and the source's own record ids (`r.source_refs[]`); the attribute's comment holds the source's text ([RUNBOOK.md § Retrieving raw MISP data from a Neo4j node](RUNBOOK.md#retrieving-raw-misp-data-from-a-neo4j-node)).

### Revoked and deprecated ATT&CK objects (2026-10)

ATT&CK keeps old objects in its STIX bundle. A **revoked** object (`revoked: true`) was replaced: a `revoked-by` relationship names its successor (`T1086` PowerShell → `T1059.001`, group `UNC2452` → `APT29`). A **deprecated** object (`x_mitre_deprecated: true`) was retired without a successor. Before 2026-10 both became ordinary nodes: on the hosted graph of 2026-10-15, 158 of 982 Technique nodes and 6 ThreatActor nodes were revoked objects (`apt34`, `charming kitten`, `unc2452`, `monsoon`, `dragonfly 2.0`, `stolen pencil`, next to their successors `oilrig`, `magic hound`, `apt29`, `patchwork`, `dragonfly`, `kimsuky`), and deprecated objects were not marked (12 Technique nodes said so only in their description).

- **Revoked objects are not nodes.** The MITRE collector skips revoked objects of every type; they become neither nodes nor relationship endpoints. A revoked group's or software's name and aliases are added to its successor's `aliases`, so a lookup by the old name and the actor alias merge (`enrichment_jobs.merge_alias_duplicate_actors`) reach the successor: an OTX actor named `unc2452` is folded into `apt29`. One exception: a revoked technique the map below does not list yet is kept, with an `[ATTACK-REVOKED]` warning, until the map is rebuilt; feeds cite techniques by id and only the map translates them, so skipping it would lose those links.
- **A revoked technique id a feed names lands on the successor.** OTX pulses keep citing replaced ids. Where a Technique is matched by an id a feed names, the id is translated first: the technique steps of `build_relationships.py` (`coalesce($revoked[toString(tid)], tid)` before each `MATCH (t:Technique {mitre_id: …})` and in their orphan counts), the technique ids of MISP `misp-galaxy:mitre-attack-pattern` tags in the sync, curated-package claims, the STIX import of the command-line pipeline (`run_pipeline.py`), and the STIX export (`GET /stix/export/technique/<id>`), which answers a revoked id with its successor's bundle. The sub-technique step (`SUBTECHNIQUE_OF`) is not translated: ATT&CK never revokes the parent of a live sub-technique. The sync and the command-line pipeline's MISP reader and STIX import also skip a technique whose id the map lists, so data written before 2026-10 does not bring the node back. Node properties keep the ids as the source gave them (`attack_ids`, `reported_techniques`, `uses_techniques`); only the link goes to the successor, and it records the ids the sources cited in `r.cited_ids` ("Relationship provenance"). Measured on the hosted graph of 2026-10-15: of the 24,452 links into revoked techniques, 24,440 come from feed ids (`USES_TECHNIQUE` 22,278, `IMPLEMENTS_TECHNIQUE` 1,772, `EMPLOYS_TECHNIQUE` 390) and land on 37 successors: 1,371 of them are already there, the rest become 22,572 new links (a source that cited two revoked ids of one successor gets one link); the other 12 are `SUBTECHNIQUE_OF` links of revoked sub-techniques and go with them.
- **Deprecated objects stay, marked.** A deprecated technique, tactic, group, malware or tool keeps its node and its links and carries `n.deprecated = true` (from the `attack-status:deprecated` MISP tag the writer sets). Filter them with `WHERE coalesce(n.deprecated, false) = false`. The flag is set, never cleared by another source.
- **The map.** `src/reference/attack_revoked_ids.json` lists every revoked technique (`T…`), group (`G…`) and software (`S…`) id with its successor and both names (version 2026.10.15: 210 techniques, 6 groups, 2 software; a chain A → B → C is resolved to C). It is built from the MITRE galaxies of MISP by `scripts/build_attack_revoked_ids.py`, carries the CalVer `version`, the inputs with their SHA-256 and the MISP galaxy (CC0) and MITRE notices, and is rebuilt at each ATT&CK release (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map"). It is read once per process (`src/attack_revoked.py`); a missing or invalid file logs one warning (`[ATT&CK] revoked-id map … not used`) and nothing is translated.
- **Acceptance.** `scripts/verify_fresh_baseline.py` fails when a Technique node carries an id the map lists (`no_revoked_attack_techniques`), a ThreatActor node from MITRE is a revoked group (`no_revoked_attack_groups`) or a Malware / Tool node from MITRE is revoked software (`no_revoked_attack_software`), and warns when an actor from another source still bears a revoked group's name (`revoked_group_names_folded`: the alias merge did not fold it).

### Indicator aging (2026-10-16)

Aging depends on the kind of fact, not on who supplied it or who created the node (`src/indicator_aging.py`, the single definition of the rule).

- **What ages.** Every `Indicator`, whatever source reported it and whether EdgeGuard created the node (`edgeguard_managed`) or wrote onto a node another system created (`edgeguard_enriched`); no aging statement reads either marker. `CVE`, the CVSS nodes, `Vulnerability`, `Malware`, `ThreatActor`, `Technique`, `Tactic`, `Tool`, `Sector`, `Source` and `Alert` never age by time: EdgeGuard sets `active = true` when it creates such a node and writes no `active`, `retired_*` or aging property when it matches one, so a node another system created (a CASM CVE or CVSS node, an ISIM asset) keeps its own lifecycle. The rules that are not about time stay: a deprecated ATT&CK object keeps `deprecated = true` and a revoked one is no node ([above](#revoked-and-deprecated-attck-objects-2026-10)), a `Campaign` follows its indicators (inactive when none is active), and a manual decommission is kept. Before 2026-10-16 the job aged `Indicator` and `Vulnerability` from `last_updated` (the last database write), every node write reactivated a decay-retired node and restored its confidence by max-wins, so a full sync undid the aging, and the 730-day baseline made two-year-old IOCs look new.
- **The basis.** One MISP report of an indicator has two times: T, the attribute's MISP timestamp (when MISP recorded it, UTC), and L, the source's own last-report date the collector stored in the attribute's `last_seen` ([COLLECTORS.md](COLLECTORS.md#the-source-date-an-indicator-ages-from-2026-10-16) lists it per source). The report time is `min(T, coalesce(L, T))`: L dates the report when it is no later than T, a later L is capped at T, a source without a date gives T. The node keeps, forward only, the latest report of any source: `last_reported_at`, `last_reported_source`, `last_reported_ref` (the MISP attribute uuid, the record an expert opens in MISP to read the source's full text) and the kind of date in `last_reported_basis` (`source_date` or `misp_recorded`); and the latest MISP record time, `last_recorded_at`. A report with an older or equal time changes none of them; an equal time with a smaller attribute uuid takes the reference, so the order of arrival does not matter. The indicator's `SOURCED_FROM` edge keeps the same values for that one source. An indicator no MISP report dated ages from `first_imported_at` (set once, when EdgeGuard creates the node), `aging_basis = 'first_imported'`. `last_updated` stays the last database write and is read neither for aging nor for ordering.
- **The rule.** The age is the number of whole days from the basis to the evaluation time. `confidence_score = max(0.10, round(source_confidence × factor, 2))` with the factor 1.00 below 90 days, 0.85 from 90, 0.70 from 180 and 0.55 from 365. From 730 days the indicator is retired: `active = false`, `retired_by = 'decay'`, `retired_at` = basis + 730 days. Below 730 days `active = true` and a decay retirement is cleared; a manual decommission (`retired_at` with another `retired_by`, or none) is kept. `source_confidence` is the highest confidence a source gave (incoming values only, never an aged one), and the value is recomputed from it, never multiplied step by step, so a missed or repeated run gives the same result. `EDGEGUARD_AGING_TIER_DAYS` (`90,180,365`), `EDGEGUARD_AGING_FACTORS` (`0.85,0.70,0.55`) and `EDGEGUARD_AGING_RETIRE_DAYS` (`730`) set the tiers, validated (strictly ascending days, one factor per tier day in (0, 1], retirement above the last tier day).
- **Each node says why.** `aging_basis` (the kind of the latest report, `last_reported_basis`, or `first_imported`; the rule derives it from the stored report like the other aging properties), `aging_tier` (0 below the first tier day, then 1, 2, 3), `aging_factor`, `aging_since`, when the current state began: the basis plus the first day of the tier, or plus 730 days once retired, and `aging_evaluated_at`, the time at which the node's aging values were last written: by a write, or by a job run that changed them; a job run that changes nothing leaves it unchanged (2026-10-16, below).
- **When it is applied.** Every Indicator write applies the rule (the sync's batch and single-item paths, the alert path, the STIX import, the VirusTotal re-enrichment) in a `SET` clause of its own after the clause that records the report and `source_confidence` (`indicator_aging.aging_set_clause`), so it reads the report of the same write whatever order Neo4j applies the items of one clause in, and a newer report reactivates a node in that write. The alert path applies it in a second statement of its transaction, after the statement that merges the node (2026-10-16): in one statement the planner reads the node's basis with the `MERGE`, before the `SET` takes the node's write lock. **The time of an evaluation (2026-10-16).** Every evaluation, a write or the job, applies the rule at the database's current time (`datetime()`, read when its statement starts), lifted to the node's `aging_evaluated_at` when that is later (`indicator_aging.evaluated_at_expr`), and stores that time whenever it writes the aging properties. No DAG run passes a time and no clock is shared between runs: real time only moves forward, so a cleared or re-run task, a baseline overlapping a scheduled sync and a command-line run evaluate at the time they run, and a write of a newer report evaluates that report at the time its statement started. For one basis every aging value changes in one direction only as the time grows (the tier and `aging_since` only grow, the confidence only falls, a retired node stays retired); the lift keeps a node from moving backwards where the clocks of two evaluations do not follow their order (two overlapping transactions, a clock set back on the database server), so no retired indicator comes back, no tier falls and no `aging_since` or STIX `modified` moves back. One case leaves a node behind the latest evaluation for a while, without moving it backwards: the job selects the nodes to change without a lock, and a job run that changes none of a node's values neither locks it nor stores a time on it, so a write whose statement started before that job evaluated the node, and which commits a newer report after it, evaluates the report at its own statement's start, earlier than the job's time; the node holds the state of the new report at that time until the next write or job evaluates it at its own time. The gap lasts as long as that write's statement ran, lock waits included (the batch write locks all its rows with the `MERGE` before it sets any property). Two evaluations of one node never interleave: the batch and single-item writes set properties of the node in the clause before the rule, which holds the node's write lock until the write commits, so the rule reads the node under that lock; the alert path's second statement reads the node under the lock its first statement took; the job locks each node it is about to change (`apoc.lock.nodes`) and evaluates it again under the lock. The enrichment job `decay_ioc_confidence` recomputes the rule for every Indicator in `apoc.periodic.iterate` batches (each at the database's time when its transaction starts), writes a node when any of its aging properties (`aging_basis`, `aging_tier`, `aging_factor`, `aging_since`, `confidence_score`, `active`, `retired_at`, `retired_by`) differs from what the rule gives, so a stale value is corrected and a run in which no aging changes writes nothing (a later `aging_evaluated_at` alone is no change; a node evaluated before the property existed is written once to store it), runs before the campaign builder, and logs the Indicators per tier, retired and by basis, and those with neither time (left untouched; expected 0).
- **The same graph from the same data.** A full sync, an incremental one, the in-memory and the paged paths, any order of arrival and any number of re-syncs give the same aging properties. Duplicates of an indicator in one MISP event keep the latest report of the source and its highest confidence, whichever comes first.
- **Nodes written before 2026-10-16** have no `source_confidence`. Until their next write the job keeps their `confidence_score` (it may carry the old decay, so it is neither aged again nor copied into `source_confidence`), and the readers show `coalesce(source_confidence, confidence_score)`. `last_decayed_tier` and `last_decayed_at` are no longer written or read. After deployment one full sync writes the new properties ([RUNBOOK.md](RUNBOOK.md#indicator-aging-rollout-2026-10-16)).
- **Known limits.** The alert path (`create_indicator_from_alert`; no subscriber is deployed) and the command-line writers (the STIX import, the VirusTotal re-enrichment) record no report: a node they create ages from `first_imported_at`, an existing node keeps its basis. What an alert's time means for aging, and whether an alert is independent evidence or a match of a list EdgeGuard exported to Wazuh, is to be designed with the ResilMesh alert integration. ResilMesh's own MISP events stay outside the sync.
- **Where it is exposed.** REST (the node's properties; `/indicators` and the Wazuh CDB indicator list newest first by `coalesce(last_reported_at, first_imported_at)`; `/zone/{zone}` every label it lists by one clock, `coalesce(last_reported_at, first_imported_at, created_at)`: an indicator's latest report, otherwise when the node entered the graph, a campaign's `created_at`; none of these moves when a sync or the campaign builder rewrites a node, whereas ordering the other labels by `last_updated` put every node just rewritten above an indicator reported in the latest run), GraphQL (`lastReportedAt`, `lastReportedSource`, `lastReportedRef`, `lastRecordedAt`, `sourceConfidence`, `agingBasis`, `agingTier`, `agingFactor`, `agingSince`, `agingEvaluatedAt`, `active`, `retiredBy`, `retiredAt` on `Indicator`) and the STIX export (`x_edgeguard_last_reported_at`, `x_edgeguard_last_reported_source`, `x_edgeguard_last_reported_ref`, `x_edgeguard_source_confidence`, `x_edgeguard_aging_basis`, `x_edgeguard_aging_tier`, `x_edgeguard_active`, `x_edgeguard_retired_by` on indicators, extension definition 1.7.0; an indicator's `modified` is the latest of `created`, `last_recorded_at` and `aging_since`). A retired indicator drops out of the GraphQL `indicators` default list, the Wazuh CDB export and campaigns; it is never deleted.

### Technique edges: attribution vs capability vs observation

Prior to 2026-04 the three X→Technique edges were a single generic `USES` relationship. They have since been split into specialized types so Cypher queries and LLM/GraphRAG retrieval can distinguish **who does it** from **what the code can do** from **what an indicator observes**:

| Specialized type | Source | Semantic |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | `ThreatActor` (or `Campaign`) | Attribution — e.g. *"APT28 employs T1059"* |
| `IMPLEMENTS_TECHNIQUE` | `Malware` or `Tool` | Capability — e.g. *"Mimikatz implements T1059"* |
| `USES_TECHNIQUE` | `Indicator` | Observation — e.g. *"this IOC was observed executing T1059"* (from OTX `attack_ids`) |

When emitting STIX 2.1, all three collapse back to the standard `relationship_type: "uses"` predicate with the source/target types providing the same disambiguation — see `docs/STIX21_EXPORTER_PROPOSAL.md` (planned). *Pre-release framework — no migration script is shipped; a fresh baseline rerun writes the specialized edge types directly.*

---

## Sector Labeling

During ETL, nodes are labeled by sector. The `zone` property is always a list:

```cypher
(:Indicator :Finance {value: 'evil.com', zone: ['finance']})
(:Vulnerability :Energy {cve_id: 'CVE-2024-1234', zone: ['energy']})
(:Host :Healthcare {hostname: 'hospital.cardiology.server', zone: ['healthcare']})
(:Vulnerability :Global {cve_id: 'CVE-2024-9999', zone: ['global']})
```

### Multi-Zone Support

EdgeGuard supports **cross-zone threats** — threats that apply to multiple sectors.
The `zone` property is **always a list** (never a single string). There is no separate
`zones` property; all zone membership is stored in the single `zone` array.

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
| Healthcare ransomware (affects all) | `['healthcare', 'global']` |

#### Querying Cross-Zone Threats

```cypher
// Find all threats affecting BOTH energy AND finance
MATCH (i:Indicator)
WHERE 'energy' IN i.zone AND 'finance' IN i.zone
RETURN i.value, i.zone

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

// Note: no Host constraint exists in the current codebase.
// The example below is a ResilMesh-shaped illustration for a full CRUSOE graph:
// CREATE CONSTRAINT host_key IF NOT EXISTS
// FOR (h:Host) REQUIRE (h.hostname) IS UNIQUE;
```

**Note:** Zone is treated as metadata/metadata, not as part of the deduplication key. This allows the same indicator/vulnerability to exist in multiple zones while being stored as a single node in Neo4j.

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

// CVE prioritization range scans (2026-06, GraphRAG): CVSS-threshold
// filters and the CISA-KEV (cisa_exploit_add IS NOT NULL) query family.
CREATE INDEX cve_cvss_score IF NOT EXISTS FOR (c:CVE) ON (c.cvss_score);
CREATE INDEX cve_cisa_exploit_add IF NOT EXISTS FOR (c:CVE) ON (c.cisa_exploit_add);

// Original source tracking
CREATE INDEX indicator_original_source IF NOT EXISTS FOR (i:Indicator) ON (i.original_source);
CREATE INDEX vulnerability_original_source IF NOT EXISTS FOR (v:Vulnerability) ON (v.original_source);

// Active/inactive tracking
CREATE INDEX indicator_active IF NOT EXISTS FOR (i:Indicator) ON (i.active);
CREATE INDEX vulnerability_active IF NOT EXISTS FOR (v:Vulnerability) ON (v.active);
// PR #33 round 10: legacy-scalar misp_event_id / misp_attribute_id indexes
// removed. All readers query the misp_event_ids[] / misp_attribute_ids[]
// arrays via list-membership predicates.

// Per-node deterministic UUID indexes — added 2026-04 (PR #33) for cross-
// environment delta-sync (cloud MERGEs by uuid) and self-describing edge
// serialization (xAI / RAG consumers resolve r.src_uuid / r.trg_uuid by uuid).
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

**Data split:** Sources --> MISP (raw + full history) --> Neo4j (metadata + relationships for fast queries). Neo4j nodes carry `misp_event_ids[]` for tracing back to every MISP event that has observed them. **Indicator** nodes additionally carry `misp_attribute_ids[]` — the MISP **attribute UUIDs** (`attr.uuid`), which are the *stable cross-instance identifiers*. The legacy numeric `attr.id` was deliberately not chosen because it is per-instance auto-increment and not portable across MISP instances or restores. With `misp_attribute_ids[]` populated you can resolve a Neo4j Indicator directly back to its MISP attributes without joining via event id. **Relationships (2026-10):** every relationship built from the sources carries `r.misp_event_ids[]`, together with `r.sources[]` and `r.source_refs[]` (see "Relationship provenance" above). From PR-N26 (2026-04-23) until then, only the four `build_relationships.py` edge types `INDICATES`, `EXPLOITS`, `TARGETS` and `AFFECTS` carried the list; `scripts/backfill_edge_misp_event_ids.py` backfills those four types on graphs created before PR-N26.

### Sync throughput (Airflow worker memory)

MISP→Neo4j ingestion (`run_misp_to_neo4j.py`) processes **one MISP event at a time**: parse attributes → dedupe within the event → build **report-scoped** edges (2026-10: only items that share the same OTX `pulse_id` are paired — `INDICATES` and `ATTRIBUTED_TO` with `match_type='otx_pulse'`, `ATTRIBUTED_TO` only when the pulse's actors are one actor; whole-event pairing is gone) → merge nodes in **Python-side chunks** (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**, default **`500`**) → flush relationships in **UNWIND batches** (**`EDGEGUARD_REL_BATCH_SIZE`**, default **`500`**). **`0`** or **`all`** on chunk size disables Python node chunking (**OOM risk** on huge attribute counts). On an incremental sync only the attributes whose MISP `timestamp` falls inside the window are written (2026-10; `EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` restores whole-event processing); unchanged items of the same OTX pulse take part only in the report-scoped link build. See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

### Querying Full History

To get full history from MISP for an indicator:

```cypher
-- Get MISP event IDs from Neo4j (every event that has observed this indicator)
MATCH (i:Indicator {value: '1.2.3.4'})
RETURN i.value, i.misp_event_ids, i.source

-- Then query MISP API for full event history:
-- GET /api/attributes/restSearch/json?value=1.2.3.4
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

This merging logic prevents two confirmed bugs:
- **H1**: event name `FINANCE` + tag `zone:healthcare` → correctly produces `['finance', 'healthcare']`
- **H3**: attribute with no zone tag, event `Tag: [{name:"zone:healthcare"}]`, event name `GLOBAL` → correctly produces `['healthcare']`

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
4. **Negative keywords**: explicit exclusions (“not healthcare”, …) drop that sector for the snippet.
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

> **Scope:** The first queries use labels and properties written by **EdgeGuard’s default MISP→Neo4j pipeline** (`neo4j_client`, `build_relationships`). Patterns involving `Host`, `SoftwareVersion`, `IP`, `DomainName`, or sector **secondary labels** are **ResilMesh-shaped illustrations** — they are valid Cypher for a full CRUSOE graph but may not return rows until those node types are populated by your deployment.

### Healthcare-related CVEs (zone property)

The sync writes CVEs under the **`:CVE`** label (`:Vulnerability` is legacy and empty on
current baselines — see NEO4J_SAMPLE_QUERIES.md). Use the portable form if a graph may
still hold legacy nodes: `MATCH (v) WHERE v:CVE OR v:Vulnerability`.

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

### Cross-zone: critical CVEs (`zone` list contains `global`)

```cypher
MATCH (c:CVE)
WHERE 'global' IN coalesce(c.zone, []) AND coalesce(c.cvss_score, 0) >= 9.0
RETURN c.cve_id, c.description, c.cvss_score
ORDER BY c.cvss_score DESC
```

### Query all indicators in a Campaign

```cypher
MATCH (a:ThreatActor)-[:RUNS]->(c:Campaign)<-[:PART_OF_CAMPAIGN]-(i:Indicator)
WHERE a.name = 'APT28'
  AND i.active = true
RETURN c.name, c.first_seen, c.last_seen, i.value, i.indicator_type, i.confidence_score
ORDER BY i.confidence_score DESC
```

### Find active vs retired IOCs for a threat actor

_Lifecycle (2026-10-16): one rule for every Indicator ([Indicator aging](#indicator-aging-2026-10-16)): the confidence follows the age since the latest report of any source (×0.85 from 90 days, ×0.70 from 180, ×0.55 from 365) and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days; a newer report reactivates it in the same write, a re-sync of the same data changes nothing. Only a manual decommission — `retired_at` without the `decay` tag — survives a newer report. Edge confidence written by the sync never decreases: the label follows the stronger evidence._

_Re-reported indicators (2026-10): the incremental sync reads only MISP attributes whose timestamp moved, and a collector does not push an indicator its source already holds in MISP, so until 2026-10 an IOC a feed kept listing was never written again and decayed while still listed. When a collector run reports an indicator again and MISP last wrote the stored copy (its timestamp) more than `EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS` ago (default 30, well inside the first aging tier at 90 days), the collector edits that copy; MISP stamps it anew and the next incremental sync merges the node again. Since 2026-10-16 the indicator ages from the source's own date capped at that timestamp, so the edit makes it younger only when the source's `last_seen` moved, or, for a source without a date (SSL Blacklist, MalwareBazaar), to the time of the edit; an indicator re-reported within the interval keeps its older date until the interval has passed. The edit keeps the source's dates: `last_seen` changes only when the source claims a later one, so `SOURCED_FROM.source_reported_last_at` moves only then, and `source_reported_first_at` and `first_imported_at` do not move. Decay therefore still applies to an indicator no collector run reports any more, and also to one a source lists but a run does not report. Since 2026-10 Feodo Tracker and SSL Blacklist report the whole list a run reads, up to `EDGEGUARD_FEODO_MAX_PER_RUN` and `EDGEGUARD_SSLBL_MAX_PER_RUN` (a Feodo Tracker daily run reads the 30-day list, so the history a baseline loaded is not reported again); the AbuseIPDB blacklist reports at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses per run, the most one request returns on the free plan, and AbuseIPDB chooses which, so a listed address outside that answer still ages. Until 2026-10 the three reported only their first `EDGEGUARD_INCREMENTAL_LIMIT` (200) entries per daily run. A run refreshes at most `EDGEGUARD_MISP_REFRESH_MAX_PER_RUN` (2,000) copies. Further limits: an existing IOC listed by a new OTX pulse still does not receive that pulse's families, adversaries, report id or TLP, and an IOC a source lists for less than the interval (ThreatFox re-lists each IOC for 7 days) is not refreshed by that listing ([COLLECTORS.md](COLLECTORS.md#re-reported-indicators-2026-10))._

```cypher
MATCH (a:ThreatActor {name: 'Lazarus Group'})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
RETURN i.value, i.indicator_type, i.confidence_score, i.source_confidence,
       i.active, i.retired_by, i.aging_tier, i.aging_basis,
       i.last_reported_at, i.last_reported_source, i.last_reported_ref,
       CASE WHEN i.active = false THEN 'RETIRED' ELSE 'ACTIVE' END AS status
ORDER BY coalesce(i.last_reported_at, i.first_imported_at) DESC
```

---

_Last updated: 2026-10-16 — CVE KEV fields: a CISA KEV record sets `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action` and `cisa_vulnerability_name`, any other record (NVD's included) only fills them, in either order of the sync; KEV revisions reach the node through the edited MISP copy, removals and detected zones do not; `SOURCED_FROM.raw_data` of a CVE is replaced on every write from a MISP attribute (the source's latest record), other labels and the STIX import's reduced record keep the record that created the edge; with `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false` an entry outside the window does not follow revisions. Same day: `INDICATES` (`malware_family`, Q9) and relationship provenance: the link names only ThreatFox, MalwareBazaar and Feodo Tracker among the indicator's feeds, no longer OTX, whose records carry no family label; OTX's credit on such a link comes from step 9b (a pulse naming the family by the node's name, that name with an ATT&CK software id or a name folded into the node, not by another alias); `Technique.is_subtechnique` from the dotted id. Same day: sector evidence: the edge table's `AFFECTS` / `TARGETS` rows, the `SOURCED_FROM` edge's `zones`, `stated_zones` and `stated_refs` and the CISA ICS `source_refs`, "Links to a Sector" under relationship provenance (a link names only the feeds that gave its sector and cites only the records that gave it; legacy rule; confidence from the label table), `advisory_sector` among the evidence labels, and measuring ATT&CK for ICS through the links into ICS techniques and `IN_TACTIC` from an ICS technique to an ICS tactic (`IN_TACTIC` never ends at a technique). Same day: indicator aging, *When it is applied*: a write of a newer report evaluates it at the time its statement started; the one case that leaves a node behind the latest evaluation for a while without moving it backwards (a write whose statement started before an aging job that changed nothing on the node, committing a newer report after it) and that the next write or job evaluates it at its own time. Same day: indicator aging: every evaluation, a write or the job, applies the rule at the database's current time, lifted to the node's `aging_evaluated_at` when that is later, and stores that time with the aging properties; no DAG run passes a time; `aging_evaluated_at` is the time at which the node's aging values were last written (a job run that changes nothing leaves it unchanged) and is listed in the `Indicator` row; the job locks each node it changes (`apoc.lock.nodes`) before it reads it; the alert path applies the rule in a second statement of its transaction; GraphQL `agingEvaluatedAt` on `Indicator`. Same day: indicator aging: every write applies the rule in a `SET` clause of its own after the one recording the report and `source_confidence`; the report records its kind in `last_reported_basis` and the rule derives `aging_basis` from it, and the job writes a node when any aging property differs, so a stale `aging_basis` is corrected; `/zone/{zone}` orders every label by one clock, `coalesce(last_reported_at, first_imported_at, created_at)`, no longer the other labels by `last_updated`; the Graph Explorer prefers, at an equal rank, the twin description that names a source. Same day: `r.misp_event_ids[]` of a campaign link: the 200 newest by MISP event id, `sources[]` / `source_refs[]` sorted; the indicators in `/zone/{zone}` are ordered by their latest report, the other labels by `last_updated`; the Graph Explorer shows the twin description the ranking keeps; the re-reported note states the per-run caps of Feodo Tracker, SSL Blacklist and AbuseIPDB (AbuseIPDB at most 10,000 addresses per run, chosen by AbuseIPDB). Same day: `ATTRIBUTED_TO`: the MISP writer adds no several-actor mark to a stored copy (MISP keeps what the sources said); a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit to be closed by a per-pulse MISP record. Same day: new section "Indicator aging": one rule for every Indicator whoever supplied it (no aging statement reads `edgeguard_managed` / `edgeguard_enriched`), from the latest report of any source (`min(T, coalesce(L, T))`: the source's `last_seen` capped at the MISP timestamp), kept forward only on the node and its `SOURCED_FROM` edge (`last_reported_at`, `last_reported_source`, `last_reported_ref`, `last_recorded_at`), `first_imported_at` when no report dated it; confidence `max(0.10, round(source_confidence × factor, 2))` with ×0.85 / ×0.70 / ×0.55 from 90 / 180 / 365 days, retirement from 730 days, a newer report reactivating in the same write, a manual decommission kept; `aging_basis`, `aging_tier`, `aging_factor`, `aging_since` on each node; no other label ages and none gets a lifecycle property on MATCH; the `Indicator` row, the `SOURCED_FROM` schema, the lifecycle and re-reported notes and the example query (ordered by the report time, not `last_updated`) say so. Same day: new section "Descriptions and their source": a CVE or Vulnerability description follows the source ranking NVD > CISA KEV > CISA ICS > any other source, a Malware, ThreatActor, Tool, Technique or Tactic description MITRE ATT&CK > a curated source > any other source, the node names the source in `description_source`, ties broken by registry reliability and id, descriptions written before count as the top source's, merged nodes keep the ranked pair, and where every source's text is; the `CVE` dates and the entity description bullets say what stays (NVD sets the dates, others fill) and what changed. Same day: campaigns: an actor that uses a malware (`USES_MALWARE`) has a campaign as one a malware is attributed to (`ATTRIBUTED_TO`), and either link makes a malware a member (`src/campaign_evidence.py`); campaign links name the relationship types they rest on (`r.evidence_types[]`); a campaign without evidence (its actor has neither link left, or no actor of its name remains) is deleted with its links, one with evidence whose indicators expired stays inactive; an indicator's link reads the indicator's best path through either link, and the sample is the 100 newest indicators, each once (the `Campaign`, `RUNS`, `PART_OF_CAMPAIGN`, `USES_MALWARE` rows, the alias merge and the provenance section say so). Same day: `ATTRIBUTED_TO` (same pulse): step 2d also takes the pulses the OTX collector marked on indicators (`i.several_actor_pulses[]`, judged with the canonical reference, also on IOCs MISP already holds) as naming several actors; the sync's own STIX conversion names a malware by the base name. Prior: 2026-10-15 — `Tactic.description` (ATT&CK's text) in the node table; an OTX-only family or actor keeps in `pulse_ids[]` the pulse that first named it and the other pulses of that run, not every pulse. Same day: `Malware`, `ThreatActor` and `Tool` descriptions: MITRE's record sets them, any other only fills them; OTX gives families and adversaries no description (a pulse's text is the report's); the sync takes none from an OTX malware or actor attribute, a metadata block or MISPWriter's placeholder, and tactics carry ATT&CK's description. Same day: re-reported indicators: the collector edits the stored MISP copy of an indicator a run reports again once MISP last wrote it more than 30 days ago, keeping the source's dates, so the sync merges the node again before decay retires it; the limits (Feodo Tracker, SSL Blacklist and AbuseIPDB report only their first 200 entries per daily run, at most 2,000 refreshes per run, no families, report id or TLP from a later OTX pulse). Same day: `ATTRIBUTED_TO` from an OTX pulse only when the pulse's actors are one actor (step 2d removes and trims the older attributions); campaign malware membership and the provenance of campaign links follow attribution. Same day: new section "Malware named after an ATT&CK software id": family names lose the `- S####` suffix of the MISP galaxy naming at ingest (OTX collector, sync, MISP galaxy tags), steps 9b / 2d look a family up with and without it, each through the names the twin merge folded (`merged_from`), and the enrichment job `merge_malware_attack_twins` folds the twins of a graph built before into the ATT&CK node, or, for software without one, into the node of the base name (`n.merged_from[]` on `Malware`); the `Malware`, `INDICATES` and `n.merged_from[]` rows say so. Same day: `CVE.description`: an OTX pulse reference and the placeholder "CVE from <source>" are no description; the metadata-block rule is stated for CVEs; a CVE without an NVD record keeps the first record's values against later revisions; the STIX flow only fills. Same day: `CVE.description`, `published` and `last_modified` set by NVD's record and only filled by any other; a metadata block is never a description. Same day: the actor alias merge keeps the most restrictive TLP of the nodes it folds together, and of the relationships it collapses. Same day: `CVE` properties from FIRST EPSS (`epss_*`) and CISA's SSVC decision points (`ssvc_*`, from NVD's record). Same day: campaign links (`RUNS`, `PART_OF_CAMPAIGN`) state their evidence, `campaign_grouping`, with the confidence of the links they rest on. Same day: explainability: `r.cited_ids[]` on technique links a revoked ATT&CK id led to, and `n.merged_from[]` on actors the alias merge folded others into ("Relationship provenance"); relationships the alias merge collapses keep every provenance list and the strongest evidence. Same day: new section "Actor alias merge and canonical threat actors": the canonical threat-actor reference (`src/reference/canonical_threat_actors.json`) is the merge's second rule next to the ATT&CK aliases and checks the ATT&CK-alias pairs (blocked names, conflicts), with conflict and chain skips, list properties kept as lists, and a fallback; new section "Revoked and deprecated ATT&CK objects": revoked objects are no nodes, a revoked technique id a feed names lands on its successor (not in the sub-technique step), deprecated objects carry `n.deprecated`, the revoked-id map and the acceptance checks; the `ThreatActor`, `Technique` and `USES_TECHNIQUE` rows say so. Same day: `CVE.attack_vector` comes from the CVSS that gives the score, in NVD's words, null without CVSS; NVD records carry every CVSS version NVD supplies; `Indicator` types: IPv6 addresses from MISP `ip-src` / `ip-dst` are `ipv6` (were `ipv4`); SSL Blacklist fingerprints are `x509-fingerprint-sha1` (were `hash`); `SOURCED_FROM` schema lists the per-source `misp_event_ids[]` and `source_refs[]`; MISP Integration states that every relationship built from the sources carries `misp_event_ids[]` (no longer only the four PR-N26 types); the incremental sync writes only changed attributes; the `malware_family` match names the sources that give a family label (VirusTotal gives none). Prior: 2026-10-14 — relationship provenance: every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]` (who asserts it, the sources' record ids, the MISP events); `source_id`, `source_ids` and `report_ids` were dropped from relationships. Prior: 2026-10-10 — fresh-baseline PR: report-scoped linking replaces whole-event co-occurrence (`INDICATES` / `ATTRIBUTED_TO` only within one OTX pulse, `match_type='otx_pulse'`, 0.6); old Q4 removed; Q5b/Q6b from `reported_techniques`; `mitre_explicit` reserved for the MITRE collector; CVE list properties promoted; `tlp` and the ownership marker on every node and edge. Prior: 2026-06-11 — PR #126: documented the alias round-trip (ThreatActor/Malware `aliases` survive the MISP round-trip via `alias:` tags; ATT&CK malware aliases from `x_mitre_aliases`) on the ATTRIBUTED_TO matching note, and added the cve_cvss_score + cve_cisa_exploit_add range indexes. Prior: 2026-04-28 — PR-N36 Tier-2 deep verification:_
- _Verified all confidence values match `src/build_relationships.py` (step numbers as of 2026-04-28 — the pipeline has 20 steps since 2026-10: Q4 removed, 5b/6b added, 7c/7d ThreatActor/Malware → Sector added, 1b SUBTECHNIQUE_OF added, 2b/2c USES_MALWARE/USES_TOOL added):
  EMPLOYS_TECHNIQUE = 0.95 (step 5/20), IMPLEMENTS_TECHNIQUE = 0.95
  (steps 6/20 and 10/20), USES_TECHNIQUE = 0.85 (8/20 — OTX
  attack_ids), INDICATES family-match = 0.8 (9/20), INDICATES same-pulse = 0.6 (9b/20),
  ATTRIBUTED_TO same-pulse = 0.6 (2d/20); the co-occurrence
  INDICATES step was removed in 2026-10 (report-scoped linking replaces it)._
- _Verified relationships exist in code: `RUNS` and `PART_OF_CAMPAIGN` in
  `src/enrichment_jobs.py:184-186` (build_campaign_nodes); `INVOLVES`
  in `src/neo4j_client.py:6142`; `HAS_CVSS_v2/v30/v31/v40`
  bidirectional in `src/neo4j_client.py:2470` (\_merge_cvss_node
  writes BOTH `(cve)-[r1]->(cvss)` AND `(cvss)-[r2]->(cve)`)._
- _Verified SOURCED_FROM property names + sector dual-labeling
  pattern (`apply_sector_labels` at `src/neo4j_client.py:1582`)._
- _No drift found. Footer refresh._

_Prior: 2026-04-26 PR-N33 docs audit (enumerated PR-N26's 4 wired
edge types for `r.misp_event_ids[]`); 2026-04-18 PR #41 cleanup pass._
