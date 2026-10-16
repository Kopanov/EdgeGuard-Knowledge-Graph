# MISP OSINT sources

**Last reviewed:** 2026-03-24 — aligned with `src/collectors/misp_writer.py`, `src/run_misp_to_neo4j.py` (index discovery + **`Accept`** header), `src/misp_health.py`, `src/neo4j_client.py`, and `dags/edgeguard_pipeline.py` (plus collector duplicate-avoidance env vars in **`src/config.py`**).

---

## Architecture: MISP as single source of truth

```
External sources → Collectors → MISP → run_misp_to_neo4j (Airflow) → Neo4j
```

External feeds (OTX, NVD, CISA, MITRE, VirusTotal, abuse.ch, …) push into **MISP** first via **`MISPWriter`**. The knowledge graph is filled from MISP primarily by **`run_misp_to_neo4j`** in Airflow. **`MISPCollector`** (`src/collectors/misp_collector.py`) is a **separate** optional path and is **not** used in the default baseline collector step.

### How EdgeGuard events are found for sync

Collectors create/update MISP events whose **`Event.info`** looks like **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`). The event carries a single tag **`EdgeGuard`** (platform provenance for downstream systems such as ResilMesh). **Zone and source classification** lives on **attribute-level tags** (`zone:Finance`, `zone:Healthcare`, `source:NVD`, confidence, etc.) — a single event can contain multi-zone attributes. **`MISPWriter._get_or_create_event`** looks the event up with **`POST /events/restSearch`** `{"eventinfo": <name>, "metadata": true, "limit": 500, "page": n}` (event headers only, an exact `Event.info` match), keeps only a row whose `info` equals the name exactly, and serializes event creation with a cross-process file lock — see `src/collectors/misp_writer.py`. MISP honours `eventinfo` from 2.4.177 on, so the first page holds the event; an older MISP ignores the filter and answers the events of the whole store, so the lookup reads further pages until the name or a short page, up to 40 pages (`EVENT_LOOKUP_MAX_PAGES`). Reaching that cap fails the lookup and creates no event, as any failed lookup does. (2026-10: the lookup sent `info`, which is not a restSearch parameter, without `metadata`: MISP answered the first 50 events of the store with all of their attributes, about 1 GB per lookup on the 730-day baseline, and a store of more than 50 events would have had a duplicate same-day event created.)

### Collector → MISP duplicate avoidance

**Daily `Event.info`** (`…-{date}`) means MISP does **not** globally dedupe the same IOC across different EdgeGuard events. **`MISPWriter`** can **prefetch** existing **`(type, value)`** on the **target** event (paginated **`POST …/attributes/restSearch`**) and skip redundant adds when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is enabled, and lists the source's attributes across every EdgeGuard event (**`EDGEGUARD_MISP_CROSS_EVENT_DEDUP`**). Since 2026-10-16 a complete cross-event listing is checked before the day's event is looked up, so a re-run MISP already holds entirely creates no `EdgeGuard-{source}-{date}` event; nor does a group whose items all fail conversion. Such items (an unknown item type, an empty value) are reported by a `[CONVERT]` log line and count as failed pushes only when they are all or at least half of a source's items in the push, and `[DEDUP] All N items were already present` is logged only when nothing failed or was dropped. **OTX** and **MITRE** also use **incremental cursors** / **conditional HTTP** so fewer items reach the push path. Full behavior and defaults: [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance* and [README.md](../README.md) (environment table).

**`fetch_edgeguard_events()`** first uses paginated **`/events/index`** (or **`/events`**) for a lightweight event list (no attribute scan), then filters client-side: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) or **`org.name`** is **`EdgeGuard`**. That avoids **`restSearch`** timeouts on instances with very large events (e.g. URLhaus / SSL blacklist attribute counts). If the index is unavailable, it falls back to **paginated** PyMISP / **`restSearch`** for event headers only (`metadata`), filtered with `eventinfo` `%<EDGEGUARD_MISP_EVENT_SEARCH>%` (MISP 2.4.177 or later; an older MISP answers every event) and then by the same client-side filter as the index (2026-10; the `search` key sent before is not a restSearch parameter, so every event of the store came back with all of its attributes) (PR-N29 H3: `_FALLBACK_PAGE_SIZE=500` × `_FALLBACK_MAX_PAGES=200` = 100K-event safety cap; cap-hit raises `_MispFallbackHardError` rather than silently truncating — see [`RUNBOOK.md`](RUNBOOK.md) § 8 for the operator triage tree). The fallback path emits the `[MISP-FETCH-FALLBACK-ACTIVE]` log token and increments the `edgeguard_misp_fetch_fallback_active_total{branch,outcome}` Counter (PR-N31), which fires the `EdgeGuardMispFetchFallbackActive` (warning) and `EdgeGuardMispFetchFallbackHardError` (critical) Prometheus alerts. If sync logs **"No events"** but the UI shows EdgeGuard events, confirm deployed code matches the repo and see **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *MISP → Neo4j sync logs "No events"*.

**Limits:** Baseline **`BASELINE_COLLECTION_LIMIT`** caps **external** collectors only — not the MISP→Neo4j event search page size or Neo4j merge chunking. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

**Source labeling (Neo4j):** `source` reflects the **original** feed (e.g. `alienvault_otx`, `nvd`, `mitre_attck`). MISP is the staging hub, not labeled as `misp_*` for that provenance.

**Neo4j sync semantics:** `run_misp_to_neo4j` walks discovered events **one at a time**. Parsed items from an event are **deduped within that event**; **cross-item** graph edges created during sync are scoped to **that event’s** item list (not a global list across all events). Node merges use **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**; relationship flushes use **`EDGEGUARD_REL_BATCH_SIZE`**. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)** and **`run_misp_to_neo4j._build_cross_item_relationships`** docstring.

---

## Source catalog (13 slots)

Canonical list: **[DATA_SOURCES.md](DATA_SOURCES.md)** (**13** rows: **11** active + **2** placeholders). The table below is the same inventory in compact form.

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
| Feodo Tracker | CSV | Active | Yes | Finance-heavy families |
| SSL Blacklist | CSV | Active | Yes | |
| Energy sector | — | Placeholder | No | Needs membership / feed |
| Healthcare sector | — | Placeholder | No | Needs membership / feed |

**Optional `MISPCollector`:** pulls from MISP **`/events`** with **its own** limits; **not** wired into default baseline collector step 2. This is **not** counted as one of the **12** DATA_SOURCES slots.

**Sector mix in your graph:** Depends on feeds, classifier, and time range. Use Neo4j (`MATCH (n) RETURN labels(n), count(*)`) or the MISP UI — **do not** rely on static percentage tables in old docs.

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

FS-ISAC, Health-ISAC, CISA ICS, etc. — out of scope for default collectors; ingest via MISP or future connectors.

### Tier 4 — Extra OSINT (ideas)

| Source | Notes |
|--------|--------|
| DigitalSide | Daily IOC feeds |
| Emerging Threats | Snort rules (typo in some old lists: *threats*) |
| Bambenek, Phishtank | CSV / URL lists |

---

## Metadata Comment Prefixes

Collectors embed structured metadata as JSON in MISP attribute comments using these prefixes:

| Prefix | Source | Fields |
|--------|--------|--------|
| `OTX_META:` | AlienVault OTX | attack_ids, targeted_countries, tags, references, author_name, adversary, TLP, industries, the indicator's own description (not the pulse's); the pulses that listed the IOC (`pulse_id`, `report_ids`), their families (`mf`), their `family::adversary::pulse` pairs (`pa`, the first pair of each family and adversary before the later pulses' pairs) and those of them naming several actors (`sap`, judged with the canonical threat-actor reference and stored on `Indicator.several_actor_pulses`; `sapn`, judged by name without it, used by the sync's run only) |
| `TF_META:` | ThreatFox | malware_malpedia, reference, reporter, tags, threat_type_desc, last_seen, confidence_level |
| `MITRE_USES_TECHNIQUES:` | MITRE ATT&CK; AlienVault OTX (malware families, adversaries) | Technique IDs from STIX uses relationships (`t`), an OTX pulse's ATT&CK ids and pulse id (`rt`, `pid`); ATT&CK's description of the entity follows on the next line. The block is never a description (2026-10), and the sync takes no description from an OTX attribute: one written before 2026-10 carries the pulse's description there |
| `NVD_META:` | NVD | CVSS data, CWE, references, affected products |

These are parsed by `run_misp_to_neo4j.py` during the MISP→Neo4j sync to populate enrichment fields on Neo4j nodes. Maximum comment length: 4000 characters. A longer `OTX_META` or `TF_META` block is shortened with a warning, never cut mid-token, so the JSON always parses: lists first, in a fixed order, then long strings, then optional keys. Since 2026-10 `OTX_META.pa` is shortened before `report_ids` and `mf`, from the end (the later pulses' pairs first), `sap` and `sapn` keep the marks of the pulses still in `pulse_id` + `report_ids` (a mark goes with its pulse's id; the sync stores every `sap` entry on the indicator, so a dropped mark is lost on that IOC and travels on the pulse's other IOCs), and each shortened list keeps the longest part that fits. The MISP writer never edits a stored `OTX_META` comment (2026-10): the several-actor mark is EdgeGuard's judgement and goes only into the attributes it pushes, so a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked (a known limit, to be closed by a per-pulse MISP record). Before, an IOC that many pulses list kept few of its report ids and families: 120 pulses naming several actors and 10 naming one kept 1 of 129 report ids and 1 of 8 families.

---

## Classification (sector)

| Approach | Status |
|----------|--------|
| Keyword (`SECTOR_KEYWORDS` in `config.py`) | Default |
| Malware-family hints (Feodo, SSLBL, …) | Active |
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

## Historical note: “direct collectors only”

Early prototypes discussed skipping MISP. **Current product path** is **collectors → MISP → Neo4j** (see **[ARCHITECTURE.md](ARCHITECTURE.md)**). Do not use this page to justify bypassing MISP in new deployments.

---

_Last updated: 2026-10-16 — *Collector → MISP duplicate avoidance*: items that fail conversion count as failed pushes only when they are all or at least half of a source's items in the push; fewer are only reported (`[CONVERT]`). Same day: *Collector → MISP duplicate avoidance*: a complete cross-event listing is checked before the day's event is looked up, so a re-run MISP already holds entirely, or a group whose items all fail conversion, creates no `EdgeGuard-{source}-{date}` event; items that fail conversion are logged as `[CONVERT]`. Same day: the writer's event lookup sends `eventinfo` (exact name) with `metadata` and pages up to 40 × 500 event headers on a MISP older than 2.4.177; the sync's `restSearch` fallback asks for event headers with `eventinfo` `%EdgeGuard%` and keeps EdgeGuard rows client-side (`info` and `search` are not restSearch parameters). Same day: the MISP writer never edits a stored `OTX_META` comment: the several-actor mark goes only into the attributes it pushes (a known limit for a pulse edited to name several actors whose IOCs MISP already holds). Same day: `OTX_META` within its 4000 characters: the first pair of each family and adversary before the later pulses' pairs, `pa` shortened before `report_ids` and `mf`, `sap` / `sapn` kept to the pulses still listed, each shortened list as long as fits; `sapn` (a mark judged without the canonical reference); the writer adds a mark to stored copies of held IOCs. Prior: 2026-10-15 — Metadata Comment Prefixes: `OTX_META` carries the indicator's own description, not the pulse's; `MITRE_USES_TECHNIQUES` is written for OTX families and adversaries too, the text after it is ATT&CK's description, and neither the block nor an OTX attribute's text is a description. Prior: 2026-04-26 — PR-N33 docs audit: documented PR-N29 fallback hardening (paginated restSearch + `_MispFallbackHardError` sentinel + safety cap) and PR-N31 observability (Counter + 2 Prometheus alerts). Prior: 2026-03-28._
