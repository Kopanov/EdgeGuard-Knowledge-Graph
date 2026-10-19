# MISP OSINT sources

This page describes how collectors stage data in MISP and how the sync reads it back. Related code: `src/collectors/misp_writer.py`, `src/run_misp_to_neo4j.py` (index discovery and the **`Accept`** header), `src/misp_health.py`, `src/neo4j_client.py` and `dags/edgeguard_pipeline.py`, plus the collector duplicate-avoidance settings in **`src/config.py`**.

---

## Architecture: MISP as single source of truth

```
External sources → Collectors → MISP → run_misp_to_neo4j (Airflow) → Neo4j
```

External feeds (OTX, NVD, CISA, MITRE, VirusTotal, abuse.ch, …) push into **MISP** first via **`MISPWriter`**. The knowledge graph is filled from MISP primarily by **`run_misp_to_neo4j`** in Airflow. **`MISPCollector`** (`src/collectors/misp_collector.py`) is a **separate** optional path and is **not** used in the default baseline collector step.

This is the product path, **collectors → MISP → Neo4j** (see **[ARCHITECTURE.md](ARCHITECTURE.md)**); deployments do not bypass MISP.

### How EdgeGuard events are found for sync

Collectors create/update MISP events whose **`Event.info`** looks like **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`). The event carries a single tag **`EdgeGuard`** (it marks the events EdgeGuard wrote). The events are created with distribution **1** (MISP's "This community only": every organisation on this MISP instance can read them) and EdgeGuard does not publish them, so MISP server synchronisation and feeds do not forward them: MISP is the single store every collector writes to and the graph is built from, not a sharing channel. **Zone and source classification** lives on **attribute-level tags** (`zone:Finance`, `zone:Healthcare`, `source:NVD`, confidence, etc.) — a single event can contain multi-zone attributes. **`MISPWriter._get_or_create_event`** looks the event up with **`POST /events/restSearch`** `{"eventinfo": <name>, "metadata": true, "limit": 500, "page": n}` (event headers only, an exact `Event.info` match), keeps only a row whose `info` equals the name exactly, and serializes event creation with a cross-process file lock — see `src/collectors/misp_writer.py`. MISP honours `eventinfo` from 2.4.177 on, so the first page holds the event; an older MISP ignores the filter and answers the events of the whole store, so the lookup reads further pages until the name or a short page, up to 40 pages (`EVENT_LOOKUP_MAX_PAGES`). Reaching that cap fails the lookup and creates no event, as any failed lookup does.

### Collector → MISP duplicate avoidance

**Daily `Event.info`** (`…-{date}`) means MISP does **not** globally dedupe the same IOC across different EdgeGuard events. **`MISPWriter`** can **prefetch** existing **`(type, value)`** on the **target** event (paginated **`POST …/attributes/restSearch`**) and skip redundant adds when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is enabled, and lists the source's attributes across every MISP event that carries the source tag (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**). A complete cross-event listing is checked before the day's event is looked up, so a re-run MISP already holds entirely creates no `EdgeGuard-{source}-{date}` event; nor does a group whose items all fail conversion. Such items (an unknown item type, an empty value) are reported by a `[CONVERT]` log line and count as failed pushes only when they are all or at least half of a source's items in the push, and `[DEDUP] All N items were already present` is logged only when nothing failed or was dropped. **OTX**, **NVD** and **CISA ICS** keep **incremental cursors** and **MITRE** uses **conditional HTTP**, so fewer items reach the push path. **CISA KEV** compares the whole catalogue with its stored copies. Full behavior and defaults: [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance* and [README.md](../README.md) (environment table).

**`fetch_edgeguard_events()`** first uses paginated **`/events/index`** (or **`/events`**) for a lightweight event list (no attribute scan), then filters client-side: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) or **`org.name`** is **`EdgeGuard`**. That avoids **`restSearch`** timeouts on instances with very large events (e.g. URLhaus / SSL blacklist attribute counts). If the index is unavailable, it falls back to **paginated** PyMISP / **`restSearch`** for event headers only (`metadata`), filtered with `eventinfo` `%<EDGEGUARD_MISP_EVENT_SEARCH>%` (MISP 2.4.177 or later; an older MISP answers every event) and then by the same client-side filter as the index (`_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200` = a 100K-event safety cap; reaching the cap raises `_MispFallbackHardError` rather than truncating silently — see [`RUNBOOK.md`](RUNBOOK.md) § 8 for the operator triage tree). The fallback path emits the `[MISP-FETCH-FALLBACK-ACTIVE]` log token and increments the `edgeguard_misp_fetch_fallback_active_total{branch,outcome}` Counter, which fires the `EdgeGuardMispFetchFallbackActive` (warning) and `EdgeGuardMispFetchFallbackHardError` (critical) Prometheus alerts. If sync logs **"No events"** but the UI shows EdgeGuard events, confirm deployed code matches the repo and see **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *MISP → Neo4j sync logs "No events"*.

**Limits:** Baseline **`BASELINE_COLLECTION_LIMIT`** caps **external** collectors only — not the MISP→Neo4j event search page size or Neo4j merge chunking. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

**Source labeling (Neo4j):** `source` reflects the **original** feed (e.g. `alienvault_otx`, `nvd`, `mitre_attck`). MISP is the staging hub, not labeled as `misp_*` for that provenance.

**Neo4j sync semantics:** `run_misp_to_neo4j` walks discovered events **one at a time**. Parsed items from an event are **deduped within that event**; **cross-item** graph edges created during sync are scoped to **that event’s** item list (not a global list across all events). Node merges use **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**; relationship flushes use **`EDGEGUARD_REL_BATCH_SIZE`**. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)** and **`run_misp_to_neo4j._build_cross_item_relationships`** docstring.

---

## Source catalog

Canonical list: **[DATA_SOURCES.md](DATA_SOURCES.md)** (**15** sources: **10** active, **2** placeholders, **2** flag-guarded collectors that are off by default (CISA ICS Advisories and MalwareBazaar), and the FIRST EPSS post-sync enrichment, which writes to Neo4j without MISP). The table below is the same inventory in compact form.

| Source | Type | Status | Pushes to MISP | Notes |
|--------|------|--------|----------------|--------|
| AlienVault OTX | API | Active | Yes | Primary volume for many deployments |
| NVD | API | Active | Yes | CVEs |
| CISA KEV | API | Active | Yes | Known exploited vulns |
| MITRE ATT&CK | API | Active | Yes | STIX / TTPs |
| VirusTotal | API | Active | Yes | Optional key |
| AbuseIPDB | API | Active | Yes | Optional key |
| ThreatFox | API | Active | Yes | Abuse.ch key |
| URLhaus | API | Active | Yes | |
| Feodo Tracker | CSV | Active | Yes | Botnet C&C (keyword detector: Global in practice) |
| SSL Blacklist | CSV | Active | Yes | |
| Energy sector | — | Placeholder | No | Needs membership / feed |
| Healthcare sector | — | Placeholder | No | Needs membership / feed |
| CISA ICS Advisories | CSAF JSON (GitHub raw) | Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, off) | Yes | CVE ↔ sector as CISA states it |
| MalwareBazaar | CSV export | Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, off) | Yes | sha256 + family label |
| FIRST EPSS | gzip CSV | Post-sync enrichment (`EDGEGUARD_ENABLE_EPSS`, on) | No (writes to Neo4j) | Exploit-prediction score on existing CVE nodes |

**Optional `MISPCollector`:** pulls from MISP **`/events`** with **its own** limits; **not** wired into default baseline collector step 2. It is not counted among the DATA_SOURCES.md sources.

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
| `CISAICSCollector` | CISA ICS Advisories (flag-guarded) | Yes |
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

FS-ISAC, Health-ISAC, etc.: no collector; ingest via MISP or future connectors. CISA ICS advisories have the flag-guarded `cisa_ics` collector.

### Tier 4 — Extra OSINT (ideas)

| Source | Notes |
|--------|--------|
| DigitalSide | Daily IOC feeds |
| Emerging Threats | Snort rules |
| Bambenek, Phishtank | CSV / URL lists |

---

## Metadata Comment Prefixes

Collectors embed structured metadata as JSON in MISP attribute comments using these prefixes:

| Prefix | Source | Fields |
|--------|--------|--------|
| `OTX_META:` | AlienVault OTX | attack_ids, targeted_countries, pulse_tags, pulse_references, pulse_author, pulse_tlp, otx_industries (the pulse's own industries: the sync takes the sectors they map to as the pulse's statement, `otx_industries` on `TARGETS`), pulse_name, indicator_role, is_active, the indicator's own description (not the pulse's); the pulses that listed the IOC (`pulse_id`, `report_ids`), the sectors the industries of the later pulses (`report_ids`) state (`report_stated_zones`, `"<zone>|<pulse id>"`), their families (`mf`), their `family::adversary::pulse` pairs (`pa`, the first pair of each family and adversary before the later pulses' pairs) and those of them naming several actors (`sap`, judged with the canonical threat-actor reference and stored on `Indicator.several_actor_pulses`; `sapn`, judged by name without it, used by the sync's run only); on a CVE an OTX pulse names (`vulnerability`, from the pulse's `cve_references`): `pulse_id`, `report_ids`, `pulse_name`, no description; the sync groups the CVE into its pulse from it |
| `TF_META:` | ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, VirusTotal | malware_malpedia, reference, tags, last_seen, threat_type_desc, malware_family, reporter, attributed_to, threat_type, ioc_id, malware_alias; url_status, last_online, threat_label, yara_rules and sigma_rules only when the item carries them |
| `MITRE_USES_TECHNIQUES:` | MITRE ATT&CK; AlienVault OTX (malware families, adversaries) | Technique IDs from STIX uses relationships (`t`), an OTX pulse's ATT&CK ids and pulse id (`rt`, `pid`), the pulse's own industries (`ind`, at most 20, read as `OTX_META.otx_industries` is) and the sectors the industries of the other pulses of the run (`rids`) state (`rsz`, as `OTX_META.report_stated_zones`); ATT&CK's description of the entity follows on the next line. The block is never a description, and the sync takes no description from an OTX attribute |
| `NVD_META:` | NVD, CISA KEV, CISA ICS | CVSS payloads, CWE, references, affected products, status, `ssvc`; KEV: the four cisa_* fields and known_ransomware_use; CISA ICS: advisory_ids, advisory_zones, ics_sectors |
| `MITRE_TACTIC_PHASES:` | MITRE ATT&CK techniques | `p`: the technique's tactic phases (at most 20); ATT&CK's description follows on the next line |

These are parsed by `run_misp_to_neo4j.py` during the MISP→Neo4j sync to populate enrichment fields on Neo4j nodes. Maximum comment length: 4000 characters. A longer `OTX_META` or `TF_META` block is shortened with a warning, never cut mid-token, so the JSON always parses: lists first, in a fixed order, then long strings, then optional keys. `OTX_META.report_stated_zones` is shortened first (it lists the first pulse of each sector before the others) and `pa` before `report_ids` and `mf`, both from the end (the later pulses' entries first); `report_stated_zones` keeps only the entries of pulses still in `report_ids`; `sap` and `sapn` keep the marks of the pulses still in `pulse_id` + `report_ids` (a mark goes with its pulse's id; the sync stores every `sap` entry on the indicator, so a dropped mark is lost on that IOC and travels on the pulse's other IOCs), and each shortened list keeps the longest part that fits. The MISP writer never edits a stored `OTX_META` comment: the several-actor mark is EdgeGuard's judgement and goes only into the attributes it pushes, so a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked (a known limit, to be closed by a per-pulse MISP record).

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

EdgeGuard verifies HTTPS by default. For **dev/lab** MISP with a self-signed cert, set **`EDGEGUARD_SSL_VERIFY=false`** on every runtime that calls MISP (**Airflow worker + scheduler**, API containers, etc.). Optional alias: **`SSL_VERIFY=false`** only when **`EDGEGUARD_SSL_VERIFY`** is unset or empty. **`SSL_CERT_VERIFY`** has no effect. See **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *misp_health_check* (self-signed + Apache redirect notes).

### MITRE collector: HTTP **400** on attribute add

Usually **MITRE-specific** types/tags vs MISP policy. Read the full MISP error body in logs; allow types like **`threat-actor`**, **`malware-type`**, **`text`** in MISP settings if restricted.

---

_Last updated: 2026-10-19_

## History

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
