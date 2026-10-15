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
| `ThreatActor` | APT groups, threat actors. A group ATT&CK revoked (UNC2452, APT34, …) is not a node; its name and aliases are aliases of the group that replaced it (2026-10, see [Revoked and deprecated ATT&CK objects](#revoked-and-deprecated-attck-objects-2026-10)) |
| `Malware` | Malware families, trojans, ransomware |
| `Tool` | MITRE ATT&CK tools (Mimikatz, Cobalt Strike, etc.) |
| `Technique` | MITRE ATT&CK techniques (T1566, T1059, etc.). A technique ATT&CK revoked is not a node, and a feed's link to its id lands on its successor; a deprecated one stays, with `deprecated = true` (2026-10) |
| `Tactic` | MITRE ATT&CK tactics (Initial Access, Execution, etc.) |
| `Campaign` | Named campaigns (auto-built from graph, see below) |
| `Indicator` | IOCs: IP addresses, domains, URLs, file hashes, TLS certificate fingerprints, … — keyed by `(indicator_type, value)`; `indicator_type` is `ipv4` / `ipv6` (MISP `ip-src` / `ip-dst` are resolved by the address), `domain`, `url`, `email`, `hash` (every file digest), `x509-fingerprint-sha1` (SSL Blacklist), `filename`, … as mapped by the sync's `TYPE_MAPPING` |

---

## Relationship Types

| Relationship | From → To | Source / Confidence |
|---|---|---|
| `EMPLOYS_TECHNIQUE` | ThreatActor → Technique | **Attribution.** `match_type='mitre_explicit'` (0.95) from MITRE STIX `uses` → `uses_techniques`; `match_type='otx_pulse'` (0.6, 2026-10) from OTX pulse `attack_ids` → `reported_techniques`. Q5 runs before Q5b so a pair MITRE asserts keeps the explicit stamp. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Malware → Technique | **Capability.** `match_type='mitre_explicit'` (0.95) via `uses_techniques`; `match_type='otx_pulse'` (0.6, 2026-10) via `reported_techniques`. *(Split from a generic `USES` in 2026-04.)* |
| `IMPLEMENTS_TECHNIQUE` | Tool → Technique | **Capability.** MITRE STIX explicit `uses` relationship (confidence 0.95) *(split from a generic `USES` in 2026-04)* |
| `ATTRIBUTED_TO` | Malware → ThreatActor | `match_type='exact'` (1.0): the malware's own `m.attributed_to` claim matched exactly against `a.name` OR `a.aliases` (the "Cozy Bear → APT29" path; `build_relationships.py` Q2). `match_type='otx_pulse'` (0.6, 2026-10): malware and actor named in the same OTX pulse, written by the MISP→Neo4j sync; the pulse is in `r.source_refs[]` (`alienvault_otx:<pulse id>`). Whole-event co-occurrence attribution was removed in 2026-10 (fresh-baseline PR). |
| `INDICATES` | Indicator → Malware | `match_type='malware_family'` (0.8): source-asserted family name match (ThreatFox, MalwareBazaar, Feodo Tracker or OTX, Q9; VirusTotal sends no family label) **and** `match_type='otx_pulse'` (0.6, 2026-10): same-run pairing by the sync, and — for regular updates — Q9b from the families the pulse stamps on each indicator (`pulse_malware_families`); indicator and malware listed in the same OTX pulse (sync path). The whole-event co-occurrence query (old Q4, 0.5) was removed in 2026-10. |
| `EXPLOITS` | Indicator → Vulnerability/CVE; ThreatActor / Malware → CVE | Indicator: CVE tag on the indicator, exact match (`match_type='cve_tag'`, 1.0); not produced from event co-membership since 2026-10. ThreatActor / Malware → CVE (2026-10): a curated package's claim (`match_type` = the package's curated label, 0.85) — the link that joins EdgeGuard's threat side to the CVE node ResilMesh's `Vulnerability → REFERS_TO → CVE` path ends on. |
| `REFERS_TO` | Vulnerability ↔ CVE | `bridge_vulnerability_cve()` |
| `RUNS` | ThreatActor → Campaign | `build_campaign_nodes()`; `campaign_grouping`, the actor's strongest `ATTRIBUTED_TO` confidence (2026-10-15) |
| `PART_OF_CAMPAIGN` | Malware, Indicator → Campaign | `build_campaign_nodes()`; `campaign_grouping`, the confidence of the `ATTRIBUTED_TO` link (malware) or of the indicator's best `INDICATES` → `ATTRIBUTED_TO` path, each path as strong as its weaker link (indicator; 2026-10-15) (named `PART_OF` until 2026-10: ResilMesh uses `PART_OF` for its asset hierarchy, and one name must have one meaning in the shared database) |
| `INVOLVES` | Alert → Indicator | `neo4j_client` alert path (`alert_processor`, NATS) — not part of the collector pipeline; excluded from the acceptance script's policed types |
| `USES_TECHNIQUE` | Indicator → Technique | OTX pulse `attack_ids` exact MITRE ID match (confidence 0.85); an id ATT&CK revoked matches its successor (2026-10) |
| `AFFECTS` | Vulnerability/CVE → Sector | Zone list unwind; `zone_classification`, 0.5 (inferred sector; `global` never linked — 2026-10 audit) |
| `TARGETS` | Indicator / ThreatActor / Malware → Sector | Zone list unwind; `zone_classification`, 0.5; actor and malware edges added 2026-10 (sector focus); `global` never linked |
| `IN_TACTIC` | Technique → Tactic | Kill-chain phase exact match (confidence 1.0) |
| `SUBTECHNIQUE_OF` | Technique → Technique | Sub-technique → parent from MITRE's dotted id (`T1021.006` → `T1021`); `mitre_explicit`, 1.0 (2026-10) |
| `USES_MALWARE` | ThreatActor → Malware | MITRE's explicit group → malware `uses`; `mitre_explicit`, 0.95 (2026-10, R6) |
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
| `r.source_refs` | THIS source's own record ids for the entity, `"<source>:<id>"` (OTX pulse, ThreatFox IOC id, URLhaus entry, ATT&CK id; 2026-10). Links derived after the sync copy these two lists from the subject node's edge (see "Relationship provenance" below) | List of strings | Accumulated (deduplicated) on every MERGE; never replaced | Per-collector |
| `r.raw_data` | Full source-specific payload as JSON (audit trail for one (entity, source) observation) | String (JSON) | `ON CREATE SET = $raw_data` (rarely overwritten — set once unless a re-sync explicitly rewrites) | Per-collector |
| `r.src_uuid` | Indicator/CVE/Malware/etc. node UUID (cached on edge for serialized-edge consumers — RAG / xAI use cases) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.trg_uuid` | Source node UUID (cached on edge, same rationale as `src_uuid`) | String (UUID) | `ON CREATE` + coalesce | Computed |
| `r.edgeguard_managed` | Always `true` for edges EdgeGuard owns; allows STIX export to filter against ResilMesh-owned data | Boolean | `SET = true` every MERGE | DB-local |

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
| `r.misp_event_ids[]` | The MISP events that carried the link (capped at 200 per edge). | `["137", "141"]` |

`r.match_type` stays the kind of evidence (next section); several sources can share one kind (ThreatFox, MalwareBazaar, Feodo Tracker and OTX all give the indicator's family label, `malware_family`), and the strongest evidence keeps the label and the confidence. Links the sync writes directly get the three lists from the MISP attribute; links derived afterwards (`build_relationships.py`, campaign and Vulnerability↔CVE links in `enrichment_jobs.py`) copy them from the subject node's per-source `SOURCED_FROM` edge, which carries the same `misp_event_ids[]` and `source_refs[]` for that source, or inherit them from the links they are built on. Corroboration is countable: `size(r.sources) >= 2` means independent sources state the link. Until 2026-10 relationships carried a single `r.source_id` (last writer wins; it held evidence names such as `otx_pulse`, `malware_family_match`, `cve_tag_match` or the hub `misp`), a set `r.source_ids` of such names and OTX-only `r.report_ids[]`; all three were dropped.

**Explainability: what the source said, where the graph says something else (2026-10).** Two cases make the graph name a target differently from the source, and both are recorded, so a reader can tell what was claimed from what EdgeGuard derived:

| Property | Meaning | Example |
|---|---|---|
| `r.cited_ids[]` | On a technique link (`USES_TECHNIQUE`, `EMPLOYS_TECHNIQUE`, `IMPLEMENTS_TECHNIQUE`): the ATT&CK ids the sources cited that ATT&CK has since revoked into the link's technique (see "Revoked and deprecated ATT&CK objects"). Accumulated, de-duplicated; absent when every source cited the technique's own id. Written by `build_relationships` (steps 5, 5b, 6, 6b, 8, 10), by the sync for MISP technique tags, and for curated claims. | An OTX pulse cited `T1562` (Impair Defenses), which ATT&CK revoked into `T1685`: the link to `T1685` carries `["T1562"]` |
| `n.merged_from[]` | On a `ThreatActor`: the names of the duplicate nodes the actor alias merge folded into this one. Unlike `aliases`, which also hold every source's aliases, it names only the merges, so a wrong merge can be traced and undone. Accumulated across merges. | `clop` carries `["cl0p"]` |

Together with `r.sources[]` and `r.source_refs[]`, a link reads in full: "the OTX pulse 5f3c… cited T1562, which ATT&CK revoked into T1685". The STIX export carries both (`x_edgeguard_cited_ids` on SROs, `x_edgeguard_merged_from` on intrusion-sets; extension definition 1.3.0).

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

A merge adds the duplicate's name to the canonical's `aliases` and to `merged_from` (only the names this job folded in), moves all of its relationships to the canonical (`apoc.refactor.mergeNodes`: scalars keep the canonical's value, lists are combined), re-stamps their `src_uuid` / `trg_uuid` with the canonical's uuid, and removes the duplicate node. Parallel relationships (same type, same other node, same direction) collapse into one: it keeps the union of their `sources`, `source_refs`, `misp_event_ids` and `cited_ids`, and the strongest evidence's `match_type` and `confidence_score` (on a tie the alphabetically first label), the rule every writer follows. APOC stores two equal merged values as one string (two OTX names of one actor both hold `source = ["alienvault_otx"]`); the merge wraps every list property of the node, and the provenance lists of its edges, back into lists. The Campaign builder then rebuilds the canonical's campaign and retires the duplicate's. When the reference file is missing, unreadable or inconsistent, or its data cannot be applied to the graph's names, the job logs one warning (`canonical reference unavailable`) and merges by ATT&CK aliases alone. `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false` makes the job a dry run that logs the pairs, the reference pairs included, and merges nothing; `EDGEGUARD_CANONICAL_THREAT_ACTORS` overrides the reference path.

### Evidence labels, report provenance, TLP (2026-10)

- `r.match_type` states the evidence behind every edge (`mitre_explicit`, `otx_pulse`, `exact`, `malware_family`, `cve_tag`, `otx_attack_ids`, `kill_chain_phase`, `campaign_grouping` for the campaign links EdgeGuard derives (2026-10-15; until then they carried none), and for curated packages `coreideas_curated` / `curated_other`) — see `docs/RESILMESH_INTEROPERABILITY.md` §3.2.2 for the table with confidences.
- `r.source_refs[]` holds the OTX pulse (`alienvault_otx:<pulse id>`) on report-scoped edges; `n.pulse_ids[]` on `Malware` / `ThreatActor` nodes (every pulse that named them); `n.reported_techniques[]` next to `n.uses_techniques[]` (pulse-level vs MITRE-explicit ATT&CK ids).
- `n.tlp` on every EdgeGuard node (from the `tlp:<level>` MISP tag; default `white`). `r.tlp` on curated-package links only: the package's level (see "Curated packages").
- `n.attack_domain` (`enterprise` | `ics`) on `Technique` and `Tactic` (from the `attack-domain:<domain>` MISP tag); `IN_TACTIC` is created only within the same domain. ATT&CK for ICS is ingested when `EDGEGUARD_ENABLE_MITRE_ICS=true` (97 techniques T08xx, 12 tactics TA0100–TA0111, shared groups/malware keep one node with unioned technique lists).
- `edgeguard_managed = true` on every EdgeGuard edge and on every node EdgeGuard **creates** (stamped on the MERGE create path only since 2026-10; a node a partner created first that EdgeGuard writes to gets `edgeguard_enriched = true` instead) — so `edgeguard clear neo4j --edgeguard-only` removes exactly the nodes EdgeGuard created from a shared database, and the APIs / STIX export expose nodes it created or enriched.
- `CVE` nodes carry `cwe[]`, `ref_tags[]`, `cpe_type[]`, `result_impacts[]`, `reference_urls[]`, `affected_products[]` from NVD (ResilMesh CVE properties), and `status[]` (2026-10): NVD's record status, `["active"]` or `["rejected"]`, replaced when NVD changes it. A node written before 2026-10 gets it at its next write; a full sync writes it on every NVD CVE. When an NVD record is merged into a node whose only source is NVD, the six lists are set from it even when empty; on a node with another source (CISA ICS, KEV, OTX) an empty NVD list leaves the property as it is. A CVSS sub-node of a version the record no longer has is removed if NVD alone asserted it, before the node's score is derived from its CVSS sub-nodes. An NVD record carries every CVSS version NVD supplies (2026-10; before, only one of 3.1, 3.0 and 2, so an update removed the sub-node of an older version when NVD added a newer one).
- `CVE.attack_vector` (2026-10) is the attack vector of the CVSS that gives the score (`cvss_score`, `cvss_version`: the first CVSS in the order v3.1 → v3.0 → v2 → v4.0), in NVD's words — `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL` — and null without CVSS. `merge_cve` sets it with the score from the CVSS sub-nodes (CVSS 3.x `attack_vector`, CVSS 2 `access_vector`, the `AV` metric of a CVSS 4.0 `vector_string`), whatever record arrives last; no record's own value is written. Graphs built before 2026-10 mix the letters of the vector strings (`N`, `L`, `A`, `P`), NVD's words and an invented `UNKNOWN` (the KEV and OTX records sent `NETWORK`): on the hosted graph of 2026-10-15, `attack_vector = 'NETWORK'` matched 3,305 CVEs, and a re-merge of every CVE gives 100,779.

### Revoked and deprecated ATT&CK objects (2026-10)

ATT&CK keeps old objects in its STIX bundle. A **revoked** object (`revoked: true`) was replaced: a `revoked-by` relationship names its successor (`T1086` PowerShell → `T1059.001`, group `UNC2452` → `APT29`). A **deprecated** object (`x_mitre_deprecated: true`) was retired without a successor. Before 2026-10 both became ordinary nodes: on the hosted graph of 2026-10-15, 158 of 982 Technique nodes and 6 ThreatActor nodes were revoked objects (`apt34`, `charming kitten`, `unc2452`, `monsoon`, `dragonfly 2.0`, `stolen pencil`, next to their successors `oilrig`, `magic hound`, `apt29`, `patchwork`, `dragonfly`, `kimsuky`), and deprecated objects were not marked (12 Technique nodes said so only in their description).

- **Revoked objects are not nodes.** The MITRE collector skips revoked objects of every type; they become neither nodes nor relationship endpoints. A revoked group's or software's name and aliases are added to its successor's `aliases`, so a lookup by the old name and the actor alias merge (`enrichment_jobs.merge_alias_duplicate_actors`) reach the successor: an OTX actor named `unc2452` is folded into `apt29`. One exception: a revoked technique the map below does not list yet is kept, with an `[ATTACK-REVOKED]` warning, until the map is rebuilt; feeds cite techniques by id and only the map translates them, so skipping it would lose those links.
- **A revoked technique id a feed names lands on the successor.** OTX pulses keep citing replaced ids. Where a Technique is matched by an id a feed names, the id is translated first: the technique steps of `build_relationships.py` (`coalesce($revoked[toString(tid)], tid)` before each `MATCH (t:Technique {mitre_id: …})` and in their orphan counts), the technique ids of MISP `misp-galaxy:mitre-attack-pattern` tags in the sync, curated-package claims, the STIX import of the command-line pipeline (`run_pipeline.py`), and the STIX export (`GET /stix/export/technique/<id>`), which answers a revoked id with its successor's bundle. The sub-technique step (`SUBTECHNIQUE_OF`) is not translated: ATT&CK never revokes the parent of a live sub-technique. The sync and the command-line pipeline's MISP reader and STIX import also skip a technique whose id the map lists, so data written before 2026-10 does not bring the node back. Node properties keep the ids as the source gave them (`attack_ids`, `reported_techniques`, `uses_techniques`); only the link goes to the successor, and it records the ids the sources cited in `r.cited_ids` ("Relationship provenance"). Measured on the hosted graph of 2026-10-15: of the 24,452 links into revoked techniques, 24,440 come from feed ids (`USES_TECHNIQUE` 22,278, `IMPLEMENTS_TECHNIQUE` 1,772, `EMPLOYS_TECHNIQUE` 390) and land on 37 successors: 1,371 of them are already there, the rest become 22,572 new links (a source that cited two revoked ids of one successor gets one link); the other 12 are `SUBTECHNIQUE_OF` links of revoked sub-techniques and go with them.
- **Deprecated objects stay, marked.** A deprecated technique, tactic, group, malware or tool keeps its node and its links and carries `n.deprecated = true` (from the `attack-status:deprecated` MISP tag the writer sets). Filter them with `WHERE coalesce(n.deprecated, false) = false`. The flag is set, never cleared by another source.
- **The map.** `src/reference/attack_revoked_ids.json` lists every revoked technique (`T…`), group (`G…`) and software (`S…`) id with its successor and both names (version 2026.10.15: 210 techniques, 6 groups, 2 software; a chain A → B → C is resolved to C). It is built from the MITRE galaxies of MISP by `scripts/build_attack_revoked_ids.py`, carries the CalVer `version`, the inputs with their SHA-256 and the MISP galaxy (CC0) and MITRE notices, and is rebuilt at each ATT&CK release (`docs/RUNBOOK.md`, "Rebuilding the ATT&CK revoked-id map"). It is read once per process (`src/attack_revoked.py`); a missing or invalid file logs one warning (`[ATT&CK] revoked-id map … not used`) and nothing is translated.
- **Acceptance.** `scripts/verify_fresh_baseline.py` fails when a Technique node carries an id the map lists (`no_revoked_attack_techniques`), a ThreatActor node from MITRE is a revoked group (`no_revoked_attack_groups`) or a Malware / Tool node from MITRE is revoked software (`no_revoked_attack_software`), and warns when an actor from another source still bears a revoked group's name (`revoked_group_names_folded`: the alias merge did not fold it).

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

MISP→Neo4j ingestion (`run_misp_to_neo4j.py`) processes **one MISP event at a time**: parse attributes → dedupe within the event → build **report-scoped** edges (2026-10: only items that share the same OTX `pulse_id` are paired — `INDICATES` and `ATTRIBUTED_TO` with `match_type='otx_pulse'`; whole-event pairing is gone) → merge nodes in **Python-side chunks** (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**, default **`500`**) → flush relationships in **UNWIND batches** (**`EDGEGUARD_REL_BATCH_SIZE`**, default **`500`**). **`0`** or **`all`** on chunk size disables Python node chunking (**OOM risk** on huge attribute counts). On an incremental sync only the attributes whose MISP `timestamp` falls inside the window are written (2026-10; `EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` restores whole-event processing); unchanged items of the same OTX pulse take part only in the report-scoped link build. See [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), and [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

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

_Lifecycle (2026-10): `decay_ioc_confidence` lowers `confidence_score` after 90 and 180 days without a sighting and sets `active = false`, `retired_at`, `retired_by = 'decay'` after 365; any later write of the same node (incremental sync, alert) reactivates it and resets the decay tier. Only a manual decommission — `retired_at` without the `decay` tag — survives a re-observation. Edge confidence written by the sync never decreases: the label follows the stronger evidence._

```cypher
MATCH (a:ThreatActor {name: 'Lazarus Group'})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
RETURN i.value, i.indicator_type, i.confidence_score,
       i.active, i.last_updated,
       CASE WHEN i.active = false THEN 'RETIRED' ELSE 'ACTIVE' END AS status
ORDER BY i.last_updated DESC
```

---

_Last updated: 2026-10-15 — campaign links (`RUNS`, `PART_OF_CAMPAIGN`) state their evidence, `campaign_grouping`, with the confidence of the links they rest on. Same day: explainability: `r.cited_ids[]` on technique links a revoked ATT&CK id led to, and `n.merged_from[]` on actors the alias merge folded others into ("Relationship provenance"); relationships the alias merge collapses keep every provenance list and the strongest evidence. Same day: new section "Actor alias merge and canonical threat actors": the canonical threat-actor reference (`src/reference/canonical_threat_actors.json`) is the merge's second rule next to the ATT&CK aliases and checks the ATT&CK-alias pairs (blocked names, conflicts), with conflict and chain skips, list properties kept as lists, and a fallback; new section "Revoked and deprecated ATT&CK objects": revoked objects are no nodes, a revoked technique id a feed names lands on its successor (not in the sub-technique step), deprecated objects carry `n.deprecated`, the revoked-id map and the acceptance checks; the `ThreatActor`, `Technique` and `USES_TECHNIQUE` rows say so. Same day: `CVE.attack_vector` comes from the CVSS that gives the score, in NVD's words, null without CVSS; NVD records carry every CVSS version NVD supplies; `Indicator` types: IPv6 addresses from MISP `ip-src` / `ip-dst` are `ipv6` (were `ipv4`); SSL Blacklist fingerprints are `x509-fingerprint-sha1` (were `hash`); `SOURCED_FROM` schema lists the per-source `misp_event_ids[]` and `source_refs[]`; MISP Integration states that every relationship built from the sources carries `misp_event_ids[]` (no longer only the four PR-N26 types); the incremental sync writes only changed attributes; the `malware_family` match names the sources that give a family label (VirusTotal gives none). Prior: 2026-10-14 — relationship provenance: every relationship built from the sources carries `sources[]`, `source_refs[]` and `misp_event_ids[]` (who asserts it, the sources' record ids, the MISP events); `source_id`, `source_ids` and `report_ids` were dropped from relationships. Prior: 2026-10-10 — fresh-baseline PR: report-scoped linking replaces whole-event co-occurrence (`INDICATES` / `ATTRIBUTED_TO` only within one OTX pulse, `match_type='otx_pulse'`, 0.6); old Q4 removed; Q5b/Q6b from `reported_techniques`; `mitre_explicit` reserved for the MITRE collector; CVE list properties promoted; `tlp` and the ownership marker on every node and edge. Prior: 2026-06-11 — PR #126: documented the alias round-trip (ThreatActor/Malware `aliases` survive the MISP round-trip via `alias:` tags; ATT&CK malware aliases from `x_mitre_aliases`) on the ATTRIBUTED_TO matching note, and added the cve_cvss_score + cve_cisa_exploit_add range indexes. Prior: 2026-04-28 — PR-N36 Tier-2 deep verification:_
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
