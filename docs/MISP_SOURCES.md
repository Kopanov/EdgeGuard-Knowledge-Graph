# MISP OSINT sources

This page describes how collectors stage data in MISP and how the sync reads it back. Related code: `src/collectors/misp_writer.py`, `src/run_misp_to_neo4j.py` (index discovery and the **`Accept`** header), `src/misp_health.py`, `src/neo4j_client.py` and `dags/edgeguard_pipeline.py`, plus the collector duplicate-avoidance settings in **`src/config.py`**.

---

## Architecture: MISP as single source of truth

```
External sources → Collectors → MISP → run_misp_to_neo4j (Airflow) → Neo4j
```

External feeds (OTX, NVD, CISA, MITRE, VirusTotal, abuse.ch, …) push into **MISP** first via **`MISPWriter`**. The knowledge graph is filled from MISP primarily by **`run_misp_to_neo4j`** in Airflow. **`MISPCollector`** (`src/collectors/misp_collector.py`) is a **separate** optional reader of MISP that no DAG or `run_pipeline.py` runs ([COLLECTORS.md § 11](COLLECTORS.md#11-misp-collector)).

This is the product path, **collectors → MISP → Neo4j** (see **[ARCHITECTURE.md](ARCHITECTURE.md)**); deployments do not bypass MISP.

### How EdgeGuard events are found for sync

Collectors create/update MISP events whose **`Event.info`** looks like **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`); once that event holds `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` attributes (default 20000), the source's attributes of that day go on to **`EdgeGuard-{source}-{date}-part2`**, **`-part3`**, ..., except a group with an attribute that names an OTX report ([COLLECTION_AND_SYNC_LIMITS.md § MISP event parts](COLLECTION_AND_SYNC_LIMITS.md#misp-event-parts)). The event carries a single tag **`EdgeGuard`** (it marks the events EdgeGuard wrote). The events are created with distribution **1** (MISP's "This community only": every organisation on this MISP instance can read them) and EdgeGuard does not publish them, so MISP server synchronisation and feeds do not forward them: MISP is the single store every collector writes to and the graph is built from, not a sharing channel. **Zone and source classification** lives on **attribute-level tags** (`zone:Finance`, `zone:Healthcare`, `source:NVD`, confidence, etc.) — a single event can contain multi-zone attributes. **`MISPWriter._get_or_create_event`** looks the event up with **`POST /events/restSearch`** `{"eventinfo": <name>, "metadata": true, "limit": 500, "page": n}` (event headers only, an exact `Event.info` match), keeps only a row whose `info` equals the name exactly, and serializes event creation with a cross-process file lock — see `src/collectors/misp_writer.py`. MISP honours `eventinfo` from 2.4.177 on, so the first page holds the event; an older MISP ignores the filter and answers the events of the whole store, so the lookup reads further pages until the name or a short page, up to 40 pages (`EVENT_LOOKUP_MAX_PAGES`). Reaching that cap fails the lookup and creates no event, as any failed lookup does. Later parts are looked up the same way, one exact name per part until the first missing one, only when the first part is full, the push does not fit it, or the cross-event listing is incomplete (dedup off, or a listing that stopped early), since the duplicate check then lists every other part of the day; a lookup that fails creates no part in that push, and a new part is created through the same locked path right before its first batch. The sync finds the parts like every EdgeGuard event and processes each as its own event; it and `edgeguard stats --misp` take the source from the second `-` field of the name, so a part counts under its source.

### Collector → MISP duplicate avoidance

**Daily `Event.info`** (`…-{date}`) means MISP does **not** globally dedupe the same IOC across different EdgeGuard events. **`MISPWriter`** can **prefetch** existing **`(type, value)`** on the **target** event (the first part of the day with room; paginated **`POST …/attributes/restSearch`**) and skip redundant adds when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is enabled, and lists the source's attributes across every MISP event that carries the source tag (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**). A complete cross-event listing also covers the other parts of the day (without one, the push lists them) and is checked before the day's event is looked up, so a re-run MISP already holds entirely creates no event; nor does a group whose items all fail conversion. Such items (an unknown item type, an empty value) are reported by a `[CONVERT]` log line and count as failed pushes only when they are all or at least half of a source's items in the push, and `[DEDUP] All N items were already present` is logged only when nothing failed or was dropped. **OTX**, **NVD** and **CISA ICS** keep **incremental cursors** and **MITRE** uses **conditional HTTP**, so fewer items reach the push path. **CISA KEV** compares the whole catalogue with its stored copies. Full behavior and defaults: [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance* and [CONFIGURATION.md](CONFIGURATION.md#collection-limits-and-the-misp-push).

**`fetch_edgeguard_events()`** first uses paginated **`/events/index`** (or **`/events`**) for a lightweight event list (no attribute scan), then filters client-side: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) or **`org.name`** is **`EdgeGuard`**. That avoids **`restSearch`** timeouts on instances with very large events (e.g. URLhaus / SSL blacklist attribute counts). If the index is unavailable, it falls back to **paginated** PyMISP / **`restSearch`** for event headers only (`metadata`), filtered with `eventinfo` `%<EDGEGUARD_MISP_EVENT_SEARCH>%` (MISP 2.4.177 or later; an older MISP answers every event) and then by the same client-side filter as the index (`_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200` = a 100K-event safety cap; reaching the cap raises `_MispFallbackHardError` rather than truncating silently — see [`RUNBOOK.md`](RUNBOOK.md) § 8 for the operator triage tree). The fallback path emits the `[MISP-FETCH-FALLBACK-ACTIVE]` log token and increments the `edgeguard_misp_fetch_fallback_active_total{branch,outcome}` Counter, which fires the `EdgeGuardMispFetchFallbackActive` (warning) and `EdgeGuardMispFetchFallbackHardError` (critical) Prometheus alerts. If sync logs **"No events"** but the UI shows EdgeGuard events, confirm deployed code matches the repo and see **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *MISP → Neo4j sync logs "No events"*.

**Limits:** Baseline **`BASELINE_COLLECTION_LIMIT`** caps **external** collectors only — not the MISP→Neo4j event search page size or Neo4j merge chunking. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

**Source labeling (Neo4j):** `source` reflects the **original** feed (e.g. `alienvault_otx`, `nvd`, `mitre_attck`). MISP is the staging hub, not labeled as `misp_*` for that provenance.

**Neo4j sync semantics:** `run_misp_to_neo4j` walks discovered events **one at a time**. Parsed items from an event are **deduped within that event**; **cross-item** graph edges created during sync are scoped to **that event’s** item list (not a global list across all events). Node merges use **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**; relationship flushes use **`EDGEGUARD_REL_BATCH_SIZE`**. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)** and **`run_misp_to_neo4j._build_cross_item_relationships`** docstring.

---

## Source catalog

Canonical list: **[DATA_SOURCES.md](DATA_SOURCES.md)** (**15** sources: **11** active, **2** placeholders, **1** flag-guarded collector that is off by default (MalwareBazaar), and the FIRST EPSS post-sync enrichment, which writes to Neo4j without MISP). The table below is the same inventory in compact form.

| Source | Type | Status | Pushes to MISP | Notes |
|--------|------|--------|----------------|--------|
| AlienVault OTX | API | Active | Yes | Primary volume for many deployments |
| NVD | API | Active | Yes | CVEs |
| CISA KEV | API | Active | Yes | Known exploited vulns |
| MITRE ATT&CK | API | Active | Yes | STIX / TTPs |
| VirusTotal | API | Active | Yes | Optional key |
| AbuseIPDB | API | Active | Yes | Optional key |
| ThreatFox | API | Active | Yes | Abuse.ch key |
| URLhaus | CSV export | Active | Yes | Abuse.ch key |
| Feodo Tracker | CSV | Active | Yes | Botnet C&C (keyword detector: Global in practice) |
| SSL Blacklist | CSV | Active | Yes | |
| Energy sector | — | Placeholder | No | Needs membership / feed |
| Healthcare sector | — | Placeholder | No | Needs membership / feed |
| CISA ICS Advisories | CSAF JSON (GitHub raw) | Active (`EDGEGUARD_ENABLE_CISA_ICS`, on; `false` turns it off) | Yes | CVE ↔ sector as CISA states it |
| MalwareBazaar | CSV export | Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, off) | Yes | sha256 + family label; abuse.ch key |
| FIRST EPSS | gzip CSV | Post-sync enrichment (`EDGEGUARD_ENABLE_EPSS`, on) | No (writes to Neo4j) | Exploit-prediction score on existing CVE nodes |

**Optional `MISPCollector`:** pulls from MISP **`/events`** with **its own** limits; no DAG or `run_pipeline.py` runs it. It is not counted among the DATA_SOURCES.md sources.

**Sector mix in your graph:** Depends on feeds, classifier, and time range. Use Neo4j (`MATCH (n) RETURN labels(n), count(*)`) or the MISP UI — **do not** rely on static percentage tables.

---

## Active collectors (code ↔ source)

| Collector module | Source | Pushes to MISP |
|------------------|--------|----------------|
| `OTXCollector` | AlienVault OTX | Yes |
| `NVDCollector` | NVD | Yes |
| `CISACollector` | CISA KEV | Yes |
| `MITRECollector` | MITRE ATT&CK | Yes |
| `VTCollector` | VirusTotal | Yes |
| `AbuseIPDBCollector` | AbuseIPDB | Yes |
| `ThreatFoxCollector`, `URLhausCollector` | abuse.ch | Yes |
| `FeodoCollector`, `SSLBlacklistCollector` | Feodo / SSLBL CSV | Yes |
| `CISAICSCollector` | CISA ICS Advisories (on by default) | Yes |
| `MalwareBazaarCollector` | MalwareBazaar (flag-guarded) | Yes |
| `EnergyCollector`, `HealthcareCollector` | Placeholders | No |

---

## Recommended MISP feeds (finance-oriented examples)

| Feed | URL | Format | Notes |
|------|-----|--------|--------|
| Feodo Tracker | `feodotracker.abuse.ch` | CSV | Banking trojans |
| SSL Blacklist | `sslbl.abuse.ch` | CSV | Stealers |
| MalwareBazaar | `bazaar.abuse.ch` | MISP | |
| URLhaus | `urlhaus.abuse.ch` | CSV/API | |

### Tier 2 — API keys (Abuse.ch)

1. Register at https://auth.abuse.ch/  
2. Use keys in env / collector config as documented in **[API_KEYS_SETUP.md](API_KEYS_SETUP.md)** and **`global_feed_collector.py`**.

### Tier 3 — ISAC / membership feeds

FS-ISAC, Health-ISAC, etc.: no collector; ingest via MISP or future connectors. CISA ICS advisories have the `cisa_ics` collector, on by default.

### Tier 4 — Extra OSINT (ideas)

| Source | Notes |
|--------|--------|
| DigitalSide | Daily IOC feeds |
| Emerging Threats | Snort rules |
| Bambenek, Phishtank | CSV / URL lists |

---

## Attribute types and values

`MISPWriter` writes one attribute per item:

| Item | MISP type | Value |
|------|-----------|-------|
| Indicator | by indicator type (`ip-dst`, `domain`, `hostname`, `url`, `md5` … `sha512`, `x509-fingerprint-sha1`, `email-src`, …); `text` when neither the type nor the value's shape gives one | the value as the source gives it |
| CVE | `vulnerability` | the CVE id, upper-case |
| Threat actor | `threat-actor` | the name |
| Malware | `malware-type` | the name |
| ATT&CK technique (Enterprise and ICS) | `text` | the id, ` - ` and the name: `T1059.003 - Windows Command Shell`, `T0807 - Command-Line Interface` |
| ATT&CK tactic (Enterprise and ICS) | `text` | `TA0002 - Execution`, `TA0104 - Execution` |
| ATT&CK tool | `text` | `S0005 - Windows Credential Editor` |

**MISP Import Regexp.** MISP applies its Import Regexp rules (*Input Filters → Import Regexp*) to the value of every attribute it stores; the comment and the tags are not rewritten. A fresh MISP database holds the default rules, which normalise Windows paths: those for Windows, Program Files, ProgramData, Documents and Settings and Users begin with any character, a colon and any character (`/.:.Windows./i` → `%WINDIR%\`), so MISP stores the file-name indicator `C:\Windows\System32\evil.exe` as `%WINDIR%\System32\evil.exe`. The ATT&CK values carry no colon for this reason: written as `<id>: <name>`, `T1059.003: Windows Command Shell` would be stored as `T1059.00%WINDIR%\Command Shell`, without its id and name, and so would every ATT&CK entry named "Windows …". They are the only values EdgeGuard composes; every other value is a source's (an indicator, a name, a CVE id) and is stored as MISP's rules leave it.

**How the sync reads an ATT&CK value.** `run_misp_to_neo4j` (the node parse) reads a `text` value with `attack_values.parse_attack_value` (`src/attack_values.py`): the id (`T1234` or `T1234.123` for a technique, `TA1234` for a tactic, `S1234` for a tool), then ` - ` or `: `, then the name. A value that starts like an ATT&CK id (`T`, `TA` or `S`, three digits, then a fourth digit or `%`) but holds no valid one, such as a value a MISP rule rewrote, creates no node: the sync logs an `[ATTACK-VALUE]` warning naming the attribute and the value, counts it in the run summary and in `edgeguard_misp_attributes_dropped_total{reason="attack_id_invalid"}`, and goes on (the run does not fail). Any other `text` value is an `Indicator` of type `unknown`.

**ATT&CK text and tags.** The comment of an ATT&CK attribute holds ATT&CK's whole description, with its markup, after the `MITRE_*` block or as the whole comment (up to 8,000 characters; ATT&CK's longest has 4,668); the sync caps the node's copy at 500 characters. Techniques, malware and tools carry every ATT&CK platform as a `platform:` tag, sent in ATT&CK's casing; MISP resolves a tag name without regard to case and keeps the casing of a tag it already holds, and a tag outlives the events that used it, so on a MISP that already holds a `platform:` tag in another casing (`platform:windows`) the attribute comes back with that tag, and the sync maps each platform value back to ATT&CK's spelling (`attack_platforms`); groups, malware and tools carry an `attack-domain:` tag per ATT&CK domain, their `alias:` tags and ATT&CK's own galaxy cluster tag (`"<name> - <ATT&CK id>"`: `misp-galaxy:mitre-intrusion-set` for groups; `mitre-software` for malware and tools when the MISP has that galaxy enabled, which MISPWriter reads once per writer from `GET /galaxies/index`, else `mitre-malware` / `mitre-tool`) beside the community one, so MISP attaches ATT&CK's card. The tags and their counts: [COLLECTORS.md § MITRE, MISP tags](COLLECTORS.md#misp-tags). MITRE's terms and notice for the ATT&CK text EdgeGuard copies are given in [DATA_SOURCES.md § 5](DATA_SOURCES.md#5-mitre-attck).

---

## Metadata Comment Prefixes

Collectors embed structured metadata as JSON in MISP attribute comments using these prefixes:

| Prefix | Source | Fields |
|--------|--------|--------|
| `OTX_META:` | AlienVault OTX | attack_ids, targeted_countries, pulse_tags, pulse_references, pulse_author, pulse_tlp, otx_industries (the pulse's own industries: the sync takes the sectors they map to as the pulse's statement, `otx_industries` on `TARGETS`), pulse_name, indicator_role, is_active, the indicator's own description (not the pulse's); the pulses that listed the IOC (`pulse_id`, `report_ids`), the sectors the industries of the later pulses (`report_ids`) state (`report_stated_zones`, `"<zone>\|<pulse id>"`), their families (`mf`), their `family::adversary::pulse` pairs (`pa`, the first pair of each family and adversary before the later pulses' pairs) and those of them naming several actors (`sap`, judged with the canonical threat-actor reference and stored on `Indicator.several_actor_pulses`; `sapn`, judged by name without it, used by the sync's run only); on a CVE an OTX pulse names (`vulnerability`, from the pulse's `cve_references`): `pulse_id`, `report_ids`, `pulse_name`, no description; the sync groups the CVE into its pulse from it. The pulse's text (`pulse_name`, `pulse_tags`, `pulse_references`, `targeted_countries`) is written only for a pulse that states white, clear or green; for an amber, amber+strict or red pulse, or one without a known TLP, these keys are written empty (a CVE's block has no `pulse_name`) and the text stays in the pulse's report record ([Report records](#report-records-event-reports)); `pulse_id`, `report_ids` and `pulse_tlp` are written whatever the level (`misp_writer.pulse_copies_allowed`). The pulse's lists (attack_ids, targeted_countries, pulse_tags, pulse_references, otx_industries) hold its items as its report record holds them, in the pulse's order, without blank items (`report_records.otx_pulse_list`) |
| `TF_META:` | ThreatFox, URLhaus, Feodo Tracker, SSL Blacklist, AbuseIPDB, MalwareBazaar, VirusTotal | malware_malpedia, reference, tags, last_seen, threat_type_desc, malware_family, reporter, attributed_to, threat_type, ioc_id, malware_alias; only when the item carries them: url_status, last_online, threat_label, yara_rules, sigma_rules, and the list-source fields as the source gives them: `ports` (integers) and `families` (ThreatFox, Feodo Tracker), `ioc_ids`, `threat_types` and `confidence_level` (ThreatFox's own 0-100 integer, the highest of the records merged into the value when it was first written; apart from the edge's `confidence` and the node's `source_confidence`), `c2_status` (Feodo Tracker), `listing_reason` (verbatim) and `listing_family` (SSL Blacklist; the list's own label, never a category word), `abuse_confidence_score` and `ip_country_code` (AbuseIPDB; the address's country, never a targeted country), `file_name`, `file_md5`, `file_sha1`, `file_type` (MalwareBazaar, VirusTotal), `threat_category`, `meaningful_name`, `file_size`, `detection_malicious`, `detection_total` (VirusTotal); `as_of`, the time the comment was written, when it holds a value that changes at the source (url_status, last_online, c2_status, the AbuseIPDB score, the VirusTotal counts): MISP keeps the first report's values for the life of the attribute, and the merged lists (`ports`, `ioc_ids`, `families`, `threat_types`) hold the records of the run that first wrote the value |
| `MITRE_USES_TECHNIQUES:` | MITRE ATT&CK; AlienVault OTX (malware families, adversaries) | The ATT&CK id of a MITRE group or malware (`aid`, `G####` / `S####`; the sync takes it from an ATT&CK attribute only, as `mitre_id` and the `mitre_attck:<id>` reference), technique IDs from STIX uses relationships (`t`), an OTX pulse's ATT&CK ids and pulse id (`rt`, `pid`), the pulse's own industries (`ind`, at most 20, read as `OTX_META.otx_industries` is) and the sectors the industries of the other pulses of the run (`rids`) state (`rsz`, as `OTX_META.report_stated_zones`); ATT&CK's whole description of the entity (up to 8,000 characters) follows on the next line. The block is never a description, and the sync takes no description from an OTX attribute |
| `NVD_META:` | NVD, CISA KEV, CISA ICS | `published`, `last_modified`, the source's whole `description`, `vendor`, `product`, the CVSS payloads (`cvss_v40_data`, `cvss_v31_data`, `cvss_v30_data`, `cvss_v2_data`) and `attack_vector`, `cwe`, `ref_tags`, `reference_urls`, `cpe_type`, `result_impacts`, `affected_products`, `version_constraints`, `status`, `ssvc`; NVD: `nvd_vuln_status`, `references`, `affected`, `cvss_scorers`; KEV: the four cisa_* fields, known_ransomware_use, `cisa_notes`, `cisa_cwes`, `cisa_forensic_triage`; NVD and KEV: `cwe_names`, `cwe_names_version`; CISA ICS: advisory_ids, advisory_zones, ics_sectors, and as `description` the advisory id and title and the vulnerability's whole note (on the advisories of 2024-2026 the longest note has 4,102 characters, the longest description (advisory id, title and note) 4,142 characters, and the longest CISA ICS comment 6,275 bytes, within the byte budget) ([below](#nvd_meta-cve-records)) |
| `MITRE_TACTIC_PHASES:` | MITRE ATT&CK techniques | `p`: the technique's tactic phases (at most 20); ATT&CK's whole description (up to 8,000 characters) follows on the next line |

These are parsed by `run_misp_to_neo4j.py` during the MISP→Neo4j sync to populate enrichment fields on Neo4j nodes (the `TF_META` list-source fields from `ports` on and the `NVD_META` keys of the table [below](#nvd_meta-cve-records) are kept in MISP and not read by the sync; a metadata block is never copied whole into the graph, the edge's `raw_data.pulse_name` takes a plain comment only). Maximum comment length: 4000 characters for `OTX_META` and `TF_META`; a `MITRE_*` comment holds its block and up to 8,000 characters of ATT&CK's text after it (the column holds 64 KB); `NVD_META` has its own budget ([below](#nvd_meta-cve-records)). A longer `OTX_META` or `TF_META` block is shortened with a warning, never cut mid-token, so the JSON always parses: lists first, in a fixed order, then long strings, then optional keys. In `TF_META` the feed's `tags` are shortened before the list-source lists (`ports`, `threat_types`, `families`, then `ioc_ids`, which takes back first what fits), and the long strings in the order `reference`, `file_name`, `meaningful_name`, `listing_reason`; the scalar keys and integers are never shortened. These records fit unshortened (`tests/test_list_source_fields.py`): the recorded ones (every form of SSL Blacklist reason, the longest included; the Feodo Tracker address with the most ports, 11; one ThreatFox and one MalwareBazaar record per family label stored on the test graph; a MalwareBazaar export row with its file fields) and constructed ones (ThreatFox `get_iocs` records with ports and `confidence_level`, a VirusTotal object, an AbuseIPDB blacklist entry, a MalwareBazaar file name of 255 characters, the usual file-system limit). The MalwareBazaar records stored on the test graph carry no file fields, so the size of real file names is unmeasured; a file name longer than about 3,500 characters is shortened after the lists. A constructed block at the sources' bounds shrinks in the order above. On the same records an SSL Blacklist comment is 327 to 410 characters and an AbuseIPDB blacklist comment about 330 (most of it the shared keys, written also when empty); the list-source fields with `as_of` take 103 to 154 characters of a Feodo Tracker comment and 80 to 89 of a ThreatFox comment, and 103 to 160 when the value carries ports and `confidence_level`, and `as_of` takes 38 characters of a URLhaus comment. `OTX_META.report_stated_zones` is shortened first (it lists the first pulse of each sector before the others) and `pa` before `report_ids` and `mf`, both from the end (the later pulses' entries first); `report_stated_zones` keeps only the entries of pulses still in `report_ids`; `sap` and `sapn` keep the marks of the pulses still in `pulse_id` + `report_ids` (a mark goes with its pulse's id; the sync stores every `sap` entry on the indicator, so a dropped mark is lost on that IOC and travels on the pulse's other IOCs), and each shortened list keeps the longest part that fits. The MISP writer never edits a stored `OTX_META` comment: the several-actor mark is EdgeGuard's judgement and goes only into the attributes it pushes, so a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked (a known limit; the pulse's report record holds its adversaries as edited, and the sync does not read the records yet).

### `NVD_META` (CVE records)

The comment of a CVE attribute an NVD, CISA KEV or CISA ICS record gives. MISP holds the source's whole text: `description` is NVD's description (up to the 4,096 characters of the CVE record format), CISA KEV's short description, or for CISA ICS the advisory id and title with the vulnerability's whole note, without characters outside the Basic Multilingual Plane; `vendor` and `product` (CISA KEV's `vendorProject` and `product`, a CISA ICS advisory's first vendor and product) are whole as well; the sync caps what the graph holds ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#descriptions-and-their-source)). The keys below are written only when the record carries a value, and the sync reads none of them yet:

| Key | Source | Value |
|---|---|---|
| `nvd_vuln_status` | NVD | `vulnStatus` as NVD writes it (`Analyzed`, `Awaiting Analysis`, `Deferred` ...), at most 32 characters |
| `references` | NVD | `[{"url", "tags"}]`: every reference, each URL once with the tags of every source that listed it, in NVD's order; `tags` is left out when no source tagged the URL; a URL over 2,048 characters is left out, never cut |
| `affected` | NVD | `[{"vendor", "product"}]`: the CNA's own pairs (the `affected` entry whose `source` is the record's `sourceIdentifier`), each once, at most 20; `n/a`, `Unknown`, `*` and `-` count as no name, so a pair may hold one of the two; an entry that names its product only by its package (`collectionURL` + `packageName`) keeps the package name as `product` |
| `cvss_scorers` | NVD | `{"cvss_v31_data": {"scored_by", "score_type"}, ...}`: the `source` (`nvd@nist.gov`, a CNA's address or UUID) and `type` (`Primary` or `Secondary`, NVD's label as given: `scored_by`, not `score_type`, names the scorer) of the metric each CVSS payload was read from |
| `cwe_names`, `cwe_names_version` | NVD, CISA KEV | `"CWE-<id>: <name>"` for each CWE id of the record (`cwe`; KEV: `cisa_cwes`) the pinned MITRE CWE list names, and the list's CWE version ([COLLECTORS.md](COLLECTORS.md#cwe-names)) |
| `cisa_notes` | CISA KEV | `notes`, whole |
| `cisa_cwes` | CISA KEV | `cwes`, CISA's own CWE ids |
| `cisa_forensic_triage` | CISA KEV | `forensicTriage`, `Yes` when BOD 26-04 requires forensic triage, else `No` |

**Byte budget.** The comment holds at most 32,768 bytes (`misp_writer.NVD_META_BUDGET_BYTES`), half of the comment column (`attributes.comment`, taken as MySQL `TEXT`, 65,535 bytes; a longer comment is refused under strict SQL or cut, and a cut comment's JSON no longer parses, so the sync would read the CVE without its `NVD_META`). The JSON is written with ASCII escapes, so its bytes are its characters. Every record of NVD's KEV page fits whole (1,769 records on 2026-11-07: median about 4,800 bytes, the largest 26,598, CVE-2023-44487; CVE-2014-6271, with the most references, 341 of 171 URLs, 24,053). Over the budget (`_fit_nvd_meta`), whole entries are dropped, as few as make the comment fit, never a part of a URL or name, and the JSON stays intact:

1. `references`: those without a tag first, then those whose tags hold none of `Exploit`, `Patch`, `Vendor Advisory` and `Mitigation`, then the others, each kind from the end;
2. `affected`, from the end;
3. `version_constraints`, from the end;
4. `cwe_names`, from the end (`cwe_names_version` goes with the last).

Only when these lists are gone and the comment is still over its budget (no real record comes near) are `description` and `cisa_notes` cut at a word end and then the other keys dropped, the largest first, keeping the record's dates, scores, status and KEV date; that is logged as an ERROR. A shrink is logged as a WARNING naming the CVE, the sizes and the counts dropped, never the content.

**Stored copies.** The NVD and KEV update paths compare `NVD_META` by digest, so a copy written without a new key differs from the record wherever the record carries it, and is edited once (KEV: at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` per run; NVD: when NVD sends the record again).

---

## Report records (Event Reports)

A report record holds what one source record says, as the source says it: an AlienVault OTX pulse (graph label `ThreatReport`) or a CISA ICS CSAF advisory (graph label `VulnerabilityAdvisory`). MISP keeps one Event Report per record. `src/report_records.py` defines the record; `MISPWriter.push_reports` (`src/collectors/misp_writer.py`) writes it. The OTX collector writes one record per pulse, after the pulse's items, and keeps the records whose push failed on `report_pending` ([COLLECTORS.md § Report records](COLLECTORS.md#report-records)). The CISA ICS collector writes one record per advisory, after the CVE items (an item batch's answer carries every report of the event) and also for an advisory without a CVE, and keeps the records whose push failed on `report_pending` ([COLLECTORS.md § 12](COLLECTORS.md#advisory-report-records)). The sync does not read the records yet: it reads the events that hold them, the `-reports` companion event without attributes included, as any EdgeGuard event, and ignores their reports.

**Record (schema `edgeguard.report.v1`).** Common fields: `source` (`alienvault_otx`, `cisa_ics`), `record_id`, `record_ref` (the exact `source_refs` string, `alienvault_otx:<pulse id>` or `cisa_ics:<tracking id>`), `url`, `title`, `description`, `published`, `last_modified` (ISO 8601 in UTC), `revision`, `tlp`.

| Source | Fields |
|---|---|
| OTX pulse | `author`, `industries`, `targeted_countries`, `tags`, `references`, `adversary`, `malware_families`, `attack_ids`, `cve_ids` (the values of the pulse's CVE indicators), `indicators` (`[MISP type, value]` pairs, exactly those the push sends for the pulse's items: a defanged value refanged as MISP refangs it on save, a URL the pulse lists again with another case of its scheme or host once, in the first spelling; at most `EDGEGUARD_REPORT_MAX_INDICATORS`, default 2000, the first in (type, value) order), `indicator_count` (the exact number of those pairs) |
| CISA ICS advisory | `publisher`, `kind` (ICSA, ICSMA), `csaf_url`, `vendors`, `products`, `deployment_sectors`, `deployment_countries` (the names the document notes list, the countries note split at its commas and at `and`), `vendor_headquarters` (the note's text), `cve_ids`, `version` (`tracking.version` as given; `revision` is the number of `tracking.revision_history` entries), `vulnerabilities` (per CVE: `cve_id`, `summary` (the vulnerability's note, whole: of category `summary`, else `description`, else a `details` note that holds no score), `remediations` with CSAF `category` and `details`, `affected_products` (from `product_status`, resolved through the product tree), `cwes` with `id` and `name`) |

- **Source facts only.** Zones, canonical actors and country codes are not in the record; the sync derives them from the raw fields, so a change of the derivation rules never rewrites MISP.
- **Normalisation.** Characters MISP cannot store are removed: those outside the Basic Multilingual Plane, lone surrogates and NUL. An indicator whose value needs such a character is left out, because the writer never stores it. Lists are de-duplicated and sorted. A missing scalar is `null` and a missing list is empty.
- **Caps.** The meta block has safety caps above the real records: a list item over its length cap is left out, never cut, a text over its cap is cut at a word end, and a list over its item cap keeps its first items in sort order (`list_cuts` names such a list; the CISA ICS collector logs it at WARNING `[REPORTS]`). The CISA ICS caps and the most the 1,389 advisories of 2024-2026 give: 500 remediations per CVE (85, ICSA-26-113-03), 5,000 affected products per CVE (644, ICSA-24-235-03), 2,000 products per advisory (497, ICSA-24-193-05), 5,000 CVEs (486, ICSA-25-226-07), a vulnerability summary of 20,000 characters (3,998 as the record holds it, 4,102 with the source's CRLF line ends), remediation details of 8,000 characters (3,705), a product name of 300 characters (219). The caps of the graph are applied by the sync.
- **Digest.** `digest` is the SHA-256 of the canonical JSON (sorted keys, ASCII, no spaces) of the record's source facts, the description included. The same pulse read from the subscribed list (`tlp`) and by id (`TLP`) gives the same record and digest.

**Content.** The Event Report's content is, in this order:

1. the description, in a code fence longer than any run of backticks it holds;
2. the heading `## EdgeGuard record`;
3. the sentinel line `<!-- edgeguard:report-meta v1 -->`;
4. exactly one fenced `json` block, to the end of the content.

The block holds every field but the description, the `digest`, and a `self_digest`: the SHA-256 of the canonical JSON of the block without it. A reader (`parse_content`):

- takes the **last** sentinel, which must be followed by that one block and nothing else, so a sentinel or a block inside the description cannot stand for the record;
- accepts the block only in its normal form, with schema v1 and a matching self-digest;
- returns the description as stored. A description edited in MISP still reads; `digest_matches` tells whether the block's digest covers it;
- ignores text MISP puts before the description's fence.

**uuid, name, tags, distribution.**

- **uuid**: `node_identity.compute_node_uuid(<label>, {"record_ref": ...})`. Both labels map to the STIX type `report`, so the uuid depends on `record_ref` alone. It is the report's uuid in MISP, the node's `uuid` and the uuid of the STIX `report--<uuid>`. Pinned: `alienvault_otx:6abf0b86fb14812f2dc84fb2` is `41646198-5449-5283-bf27-6f3813e5f708`, and `cisa_ics:ICSA-26-281-01` is `17ff328c-07c3-5786-9cac-e09357433faa`.
- **Name**: the title, cut at a word end to at most 255 characters (`EventReport.name` is varchar(255); 256 characters answer HTTP 500).
- **Tags on the add**: `EdgeGuard`, the source tag and `tlp:<level>`. A record without a known level counts as amber.
- **Distribution**: 0 ("Your organisation only") for amber, amber+strict and red; 5 ("Inherit event") otherwise. The events themselves have distribution 1.

**Event.** A record goes to the source's day event, `EdgeGuard-<source>-<date>`, which is looked up or created through the same locked path as for attributes. When that event holds more attributes than `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` (default 20000; `0` = never), new records go to `EdgeGuard-<source>-<date>-reports` instead: the OTX baseline's day event holds about 150,000 attributes, and every attribute push to an event and every view of it carries all of its reports in full. A revised record is edited where MISP holds it.

**The writer's flow per record.**

1. **Add.** `POST /eventReports/add/<event id>` with uuid, name, content, distribution and tags. The add counts only when MISP's answer shows `EventReport` with:
   - the uuid sent;
   - the SHA-256 of the content sent;
   - the name sent;
   - `deleted` false.

   A database without strict SQL mode cuts a value silently, so the content is compared after every add.
2. **Any HTTP 403: view the uuid.** `GET /eventReports/view/<lower-case uuid>` (an upper-case uuid answers 404). Then:
   - **Foreign report.** The report sits in an event whose `info` does not match `^EdgeGuard-<source>-\d{4}-\d{2}-\d{2}(-part\d+|-reports)?$`, or whose creator organisation is not the writer key's (`GET /users/view/me`). This is a permanent failure, logged as `[REPORT-UUID-FOREIGN]`; the record is not written and not retried.
   - **Deleted in MISP.** The report is soft-deleted (a soft-deleted uuid still blocks an add). The deletion is respected: no restore, no edit (`reports_deleted_in_misp`).
   - **Unchanged.** The stored block's `digest` equals the record's, or its `last_modified` is later than the record's. The report is left as it is (`reports_unchanged`).
   - **Otherwise: edit.** `POST /eventReports/edit/<uuid>` with name, content and distribution, checked as the add. MISP applies only these fields, in the report's own event, and keeps uuid and id. A failed edit answers HTTP 200 `[]`.
3. **TLP change.** After an edit that changes the record's TLP: `removeTag` of the old `tlp:` tag, then `addTag` of the new one. Both go by tag id (MISP reads `tlp:white` in a path as a named parameter), and each answer must say `saved` true (a failure answers HTTP 200 `{"saved": false}`). The `addTag` is sent whatever the `removeTag` answered. An old tag that is not on the report counts as removed: MISP answers its `removeTag` HTTP 200 `{"saved": false, "errors": "Invalid event-report - tag combination."}` (MISP source), as after an earlier change whose `addTag` failed, an add that dropped a missing tag, or an edit with a `perm_sync_authoritative` key. So does an old tag this MISP does not hold. A failure counts in `report_tag_drift` and does not fail the record: the reader takes the TLP from the block and the distribution follows the edit.

Reports never travel inside `POST /events/<id>`: there MISP 2.5.50 silently ignores the uuid of another event's report, and 2.5.45 moves the report into the edited event. The report requests are not wrapped in the writer's retry decorator:

- an HTTP 4xx is never tried again;
- an HTTP 5xx, a timeout or a connection error is tried once more;
- after 5 records in a row failed that way, the rest of the push is skipped; a record with any other outcome starts the count again.

Pacing and limits:

- `EDGEGUARD_MISP_REPORT_THROTTLE_SEC` (default 0.1) is the pause between records.
- The parent-DAG liveness callback runs before each record.
- No record starts after the push's deadline. For a writer given its task's end (`task_ends_at`: the baseline's, and the scheduled OTX and CISA ICS runs'), no record and no report request starts later than 10 minutes before that end, so the collector can save `report_pending` before Airflow kills the task. A request in flight keeps its timeouts (30 s to connect, 300 s to read), which fit in those 10 minutes. A request not sent then counts as no answer, and one not tried again keeps its first answer.
- The push stops before the next record once MISP has kept failing for `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC` (the baseline's writer: `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`, at most until 10 minutes before its task's end): the time from the start of the first record that failed on HTTP 5xx or no answer, until a record ends otherwise.
- The records not tried are listed as skipped.

The logs carry uuid, `record_ref`, lengths and SHA-256 only, never content or MISP's answers. MISP's own logs are not covered by this rule: MISP logs every Event Report change in full, an add with the whole content and an edit with the old and the new content, amber and red text included, whatever the report's distribution. MISP's site administrators can read these entries ([RUNBOOK.md](RUNBOOK.md#report-text-in-misps-logs)). The writer's item bookkeeping (`last_push_*`) is not touched.

**Outcome of a push.** The writer returns counts: `reports_added`, `reports_updated`, `reports_unchanged`, `reports_deleted_in_misp`, `reports_failed` (with `reports_foreign`), `reports_skipped` and `report_tag_drift`. It also returns the lists `settled`, `failed` (with the reason, and whether the failure is permanent) and `skipped`.

**`report_pending`.** Per source, `report_records.note_report_push` keeps the records whose push failed, or that a push did not try, in the incremental state of the source's collector: `report_pending` beside the `otx` or `cisa_ics` cursor. Each entry holds `record_ref`, `first_failed_at`, `attempts`, `last_tried_at` and `last_reason`, and, while the collector cannot fetch the source record, `first_fetch_failed_at` and `last_fetch_failed_at` (`fetch_failed`; no try: `attempts` and `last_tried_at` stay). `pending_record_refs` orders the list by the later of `last_tried_at` and `last_fetch_failed_at`, neither first; a read of the source record (`fetched`) or a try ends the fetch failures.

- The list is apart from the OTX item retry list, and kept on baselines and scheduled runs alike.
- A push that settles a record takes it off; a permanent failure is never added.
- A record still failing `EDGEGUARD_REPORT_PENDING_MAX_DAYS` (default 7) after its first failure is given up by the next push that tries it, with an ERROR `[REPORT-GAVE-UP]`. So is a record whose source record has failed to be fetched for more than that many days, the last of those fetches past the record's deadline.
- Gauges: `edgeguard_report_pending_records` and `edgeguard_report_pending_oldest_failure_timestamp_seconds`; counter: `edgeguard_report_pending_given_up_total`.
- The fresh baseline's wipe clears the list with MISP, which frees every report uuid.

**Read-only preflight.** `MISPWriter.report_preflight()` checks the writer key and writes nothing:

- its role has `perm_tagger`, without which MISP drops every report tag;
- its role lacks `perm_sync_authoritative`, with which every report edit strips the report's tags;
- every tag the writer sets exists (`POST /tags/search/x/1`), or the role has `perm_tag_editor`, without which MISP drops a missing tag instead of creating it.

It returns the problems found and logs `[REPORT-PREFLIGHT]`. No task runs it: the operator runs it before a baseline ([RUNBOOK.md § Before a 730d baseline run](RUNBOOK.md#before-a-730d-baseline-run)).

**MISP versions.** The report and tag requests and their answers above were measured on MISP 2.5.50 on 2026-11-07 with a site-admin key. The effects of the writer key's role (`perm_tagger`, `perm_tag_editor`, `perm_sync_authoritative`), the creator-organisation check, the shape of the `GET /users/view/me` answer and the answer to a `removeTag` of a tag that is not on the report come from the MISP and PyMISP source, not from a measurement. A read-only check with the writer key settles them, and its recording then replaces the constructed fixture. The source of 2.5.45 behaves the same on the report and tag requests the writer sends; it differs on the event-edit path, which the writer does not use.

---

## Classification (sector)

| Approach | Status |
|----------|--------|
| Keyword (`SECTOR_KEYWORDS` in `config.py`) | Default |
| Malware family → sector through graph relationships (no family keywords) | Active |
| LLM / hybrid | Not in default path |

---

## MISP API (reference)

- Base: `https://<host>/` (your **`MISP_URL`**)  
- Auth: header **`Authorization: <api_key>`**  
- Format: JSON  

---

## Troubleshooting (Airflow + Docker + MITRE)

### MISP not reachable from Airflow (`Name or service not known`)

EdgeGuard **`docker-compose.yml`** does **not** start MISP. **`MISP_URL`** must resolve **inside** the Airflow container (not `localhost` on the host). The compose default **`https://misp.local`** is often wrong in-container unless you inject that name via **extra_hosts** / custom DNS. If MISP runs in another compose project, attach both stacks to a **shared Docker network** and set **`MISP_URL`** to that service’s resolvable name (e.g. default Compose pattern **`https://misp_misp_1:443`** when the other project directory is `misp` — your project/service names may differ). See **[ENVIRONMENTS.md](ENVIRONMENTS.md)** and **`.env.example`**.

### Wrong vhost / empty response (`EDGEGUARD_MISP_HTTP_HOST`)

If Apache **`ServerName`** differs from the URL host, set **`EDGEGUARD_MISP_HTTP_HOST`** (no scheme). Applied to `requests` and PyMISP in **`run_misp_to_neo4j`**.

### Self-signed MISP / **`certificate verify failed`** (preflight, sync, collectors)

EdgeGuard verifies HTTPS by default. For **dev/lab** MISP with a self-signed cert, set **`EDGEGUARD_SSL_VERIFY=false`** on every runtime that calls MISP (**Airflow worker + scheduler**, API containers, etc.). Optional alias: **`SSL_VERIFY=false`** only when **`EDGEGUARD_SSL_VERIFY`** is unset or blank. Only `false`, `0`, `no` or `off` (any case) turns verification off; any other value keeps it on and is logged as a warning ([CONFIGURATION.md § TLS and trust](CONFIGURATION.md#tls-and-trust)). **`SSL_CERT_VERIFY`** has no effect. See **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *misp_health_check* (self-signed + Apache redirect notes).

### MITRE collector: HTTP **400** on attribute add

Usually **MITRE-specific** types/tags vs MISP policy. Read the full MISP error body in logs; allow types like **`threat-actor`**, **`malware-type`**, **`text`** in MISP settings if restricted.

---

_Last updated: 2026-11-08_

## History

- 2026-11-08 — ATT&CK attributes: malware and tools carry the `mitre-software` galaxy cluster tag when the MISP has that galaxy enabled (`mitre-malware` / `mitre-tool` otherwise); MISP keeps a platform tag's casing across event wipes.
- 2026-11-08 — OTX report records list exactly the `[MISP type, value]` pairs the push sends: a defanged value refanged as MISP refangs it (the record named the value as the pulse gave it), a URL repeated with another case of its scheme or host once (`indicator_count` counted it twice). `OTX_META` lists hold no blank item (`[""]` was copied as given).
- 2026-11-08 — CISA ICS Advisories is active by default (`EDGEGUARD_ENABLE_CISA_ICS` defaults to `true`; `false` turns it off): 11 active sources, 1 flag-guarded. Read-only preflight: it logs `[REPORT-PREFLIGHT]`, and the operator runs it before a baseline (the RUNBOOK gives the command).
- 2026-11-07 — `NVD_META`: the source's whole description (the NVD and KEV collectors cut it at 1,000 and 500 characters); new keys `nvd_vuln_status`, `references`, `affected`, `cvss_scorers`, `cwe_names`, `cwe_names_version`, `cisa_notes`, `cisa_cwes` and `cisa_forensic_triage`; a byte budget of 32,768 with a shrink order (it had no bound); `vendor` and `product` whole (cut at 100 characters with `...`); `affected` keeps a package-only entry's package name as `product`.
- 2026-11-07 — The CISA ICS collector writes a report record per advisory, after the CVE items (an item batch's answer carries every report of the event), also for an advisory without a CVE, and keeps the records whose push failed on `report_pending`. The ICS record: `revision` is the number of revision-history entries and `version` is `tracking.version` as given (`revision` had been `tracking.version` when it was a whole number, with the count in `revision_count`); a vulnerability entry carries its `cwes` (`id`, `name`), and its `summary` falls back to a `details` note that holds no score; the countries note is split at its commas and at `and`. The list caps are 500 remediations and 5,000 affected products per CVE and 2,000 products per advisory: the caps of 50 remediations and 500 affected products had cut ICSA-26-113-03 and ICSA-24-235-03, and the cap of 500 products cut none; a list a cap cuts is named in `list_cuts` and logged. A CISA ICS `NVD_META.description` holds the vulnerability's whole note.
- 2026-11-07 — ATT&CK attributes: the comment holds ATT&CK's whole description (up to 8,000 characters; the writer cut it at 255 or 400 characters); every platform is a tag sent in ATT&CK's casing, which the sync reads in ATT&CK's spelling whatever casing MISP holds the tag in; groups, malware and tools carry `attack-domain:` tags, tools `alias:` tags, and groups, malware and tools ATT&CK's own galaxy cluster tag; the 4,000-character comment limit names the blocks it applies to.
- 2026-11-07 — The OTX collector writes a report record per pulse. `report_pending` notes the failed fetches of a source record (`first_fetch_failed_at`, `last_fetch_failed_at`): no try, but they order the list and give up a record whose source keeps failing. `OTX_META` carries the pulse's text (name, tags, references, targeted countries) only for a white, clear or green pulse; for an amber or red pulse, or one without a known TLP, the keys are written empty and the text stays in the pulse's report record.
- 2026-11-07 — `TF_META`: SSL Blacklist and AbuseIPDB write it (SSL Blacklist wrote "From ssl_blacklist", AbuseIPDB a prose comment); the list-source fields, `as_of` for values that change at the source, their place in the shrink order, the records that fit unshortened and the comment size per source.
- 2026-11-07 — Report records: one MISP Event Report per OTX pulse and CISA ICS advisory (schema `edgeguard.report.v1`, content, digest, uuid, tags, distribution, the writer's flow and its failure answers, its limits (deadline, task end, failing-time cap), the `report_pending` list, the read-only preflight, MISP's own logs of report text, what was measured and what comes from the MISP source). No collector writes records yet.
- 2026-11-02 — `MISPCollector`: no DAG or `run_pipeline.py` runs it (the text named the collector step of the retired in-process baseline). How the sync reads an ATT&CK value: the node parse only (the text also named a STIX conversion that no pipeline step calls).
- 2026-11-02 — Event names and lookups: the readers of an event part's source no longer list the STIX flow of `run_pipeline.py`, which is removed (`run_pipeline.py` runs the collectors into MISP only).
- 2026-11-01 — `MITRE_USES_TECHNIQUES.aid`: the ATT&CK id of a MITRE group or malware.
- 2026-10-25 — Event names and lookups: a source/date event continues in `-part2`, `-part3`, ... past `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` (default 20000) attributes, except a group with OTX report ids; later parts are looked up by exact name until the first missing one, the duplicate check covers every part of the day, and readers count a part under its source.
- 2026-10-25 — Source table: URLhaus and MalwareBazaar need the abuse.ch key (`THREATFOX_API_KEY`); URLhaus is read as a CSV export.
- 2026-10-23 — Self-signed MISP: only `false`, `0`, `no` or `off` turns TLS verification off; any other value of `EDGEGUARD_SSL_VERIFY` keeps it on with a warning.
- 2026-10-23 — The settings reference points to CONFIGURATION.md, which holds the README's settings tables.
- 2026-10-20 — ATT&CK techniques, tactics and tools are written as `<id> - <name>`, which MISP's default Import Regexp rules leave unchanged (as `<id>: <name>`, the rules rewrote the nine entries named "Windows …" on the run of 2026-10-20); the sync reads both forms and skips a value with no valid ATT&CK id with an `[ATTACK-VALUE]` warning; new section on the attribute types and values.
- 2026-10-19 — MISPWriter writes an `OTX_META` block (`pulse_id`, `report_ids`, `pulse_name`) on a CVE an OTX pulse names (it wrote a plain comment), from which the sync groups the CVE into its pulse; the `OTX_META` row lists it.
- 2026-10-18 — `MITRE_USES_TECHNIQUES.ind`: an OTX family's and adversary's pulse industries; `OTX_META.report_stated_zones` / `MITRE_USES_TECHNIQUES.rsz`: the sectors the later pulses of the run state.
- 2026-10-18 — The events' MISP distribution stated as it is: 1 ("This community only", every organisation on the instance), unpublished, so neither server synchronisation nor feeds forward them; MISP is the single store the collectors write to and the graph is built from (the writer's code comment had said "This organization only"); the `EdgeGuard` tag marks the events EdgeGuard wrote.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text restated as a guide to current behaviour; the change history moved to this section, the historical note on early prototypes that skipped MISP folded into the architecture section as the product path, and data written by earlier versions moved to the appendix.
- 2026-10-17 — Source catalog of 15 sources as in DATA_SOURCES.md, with the flag-guarded CISA ICS Advisories and MalwareBazaar collectors (Tier 3 had said CISA ICS had no collector) and the FIRST EPSS enrichment; no malware family maps to a sector by keyword; the metadata prefixes list the keys as written, `MITRE_TACTIC_PHASES` included; the cross-event listing covers every event carrying the source tag, and NVD and CISA ICS keep cursors too.
- 2026-10-16 — Duplicate avoidance: a complete cross-event listing is checked before the day's event is looked up, so an entirely held re-run or a group whose items all fail conversion creates no event, and items that fail conversion are logged as `[CONVERT]` and count as failed only when they are all or at least half of a source's items.
- 2026-10-16 — The writer's event lookup sends `eventinfo` with `metadata` and pages up to 40 × 500 event headers on a MISP older than 2.4.177; it had sent `info`, which is not a restSearch parameter, without `metadata`, so MISP answered the first 50 events of the store with all of their attributes (about 1 GB per lookup on the 730-day baseline) and a store of more than 50 events would have had a duplicate same-day event created; the sync's `restSearch` fallback likewise asks for EdgeGuard event headers with `eventinfo` instead of the `search` key, which had returned every event with all of its attributes.
- 2026-10-16 — `OTX_META` within its 4000 characters: the first pair of each family and adversary first, `pa` shortened before `report_ids` and `mf`, `sap` / `sapn` kept to the pulses still listed, each shortened list as long as fits; an IOC that many pulses listed had kept few report ids and families (with 120 pulses naming several actors and 10 naming one, 1 of 129 report ids and 1 of 8 families); `sapn` added; the writer does not edit a stored `OTX_META` comment to add a several-actor mark.
- 2026-10-15 — `OTX_META` carries the indicator's own description, not the pulse's; `MITRE_USES_TECHNIQUES` is written for OTX families and adversaries too, the text after it is ATT&CK's description, and neither the block nor an OTX attribute's text is a description.
- 2026-04-26 — The sync's `restSearch` fallback is paginated with a safety cap that raises `_MispFallbackHardError`, and its use is counted and alerted (`[MISP-FETCH-FALLBACK-ACTIVE]`, two Prometheus alerts).
- 2026-03-28 — First version (v2026.3.28), reviewed on 2026-03-24 against the writer, the sync (index discovery, `Accept` header), the health check, the Neo4j client and the pipeline DAG.
