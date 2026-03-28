# MISP OSINT sources

**Last reviewed:** 2026-03-24 — aligned with `src/collectors/misp_writer.py`, `src/run_misp_to_neo4j.py` (index discovery + **`Accept`** header), `src/misp_health.py`, `src/neo4j_client.py`, and `dags/edgeguard_pipeline.py` (plus collector duplicate-avoidance env vars in **`src/config.py`**).

---

## Architecture: MISP as single source of truth

```
External sources → Collectors → MISP → run_misp_to_neo4j (Airflow) → Neo4j
```

External feeds (OTX, NVD, CISA, MITRE, VirusTotal, abuse.ch, …) push into **MISP** first via **`MISPWriter`**. The knowledge graph is filled from MISP primarily by **`run_misp_to_neo4j`** in Airflow. **`MISPCollector`** (`src/collectors/misp_collector.py`) is a **separate** optional path and is **not** used in the default baseline collector step.

### How EdgeGuard events are found for sync

Collectors create/update MISP events whose **`Event.info`** looks like **`EdgeGuard-{SECTOR}-{source}-{date}`**. The event carries a single tag **`EdgeGuard`** (platform provenance for downstream systems such as ResilMesh). **Sector/source/TLP context** is on **attributes** (`zone:…`, `source:…`, confidence, etc.); the `SECTOR` token in the event name is the **grouping key** for MISP event routing, not a duplicate event-level sector tag. **`MISPWriter._get_or_create_event`** filters **`restSearch`** hits to an **exact** `info` string match (MISP’s `info` parameter is often substring-based; parallel Tier1 collectors share the `EdgeGuard-GLOBAL-` prefix) and serializes event creation with a cross-process file lock — see `src/collectors/misp_writer.py`.

### Collector → MISP duplicate avoidance

**Daily `Event.info`** (`…-{date}`) means MISP does **not** globally dedupe the same IOC across different EdgeGuard events. **`MISPWriter`** can **prefetch** existing **`(type, value)`** on the **target** event (paginated **`POST …/attributes/restSearch`**) and skip redundant adds when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is enabled. **OTX** and **MITRE** also use **incremental cursors** / **conditional HTTP** so fewer items reach the push path. Full behavior and defaults: [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance* and [README.md](../README.md) (environment table).

**`fetch_edgeguard_events()`** first uses paginated **`/events/index`** (or **`/events`**) for a lightweight event list (no attribute scan), then filters client-side: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) or **`org.name`** is **`EdgeGuard`**. That avoids **`restSearch`** timeouts on instances with very large events (e.g. URLhaus / SSL blacklist attribute counts). If the index is unavailable, it falls back to PyMISP **`restSearch`** with the same substring. If sync logs **“No events”** but the UI shows EdgeGuard events, confirm deployed code matches the repo and see **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)** § *MISP → Neo4j sync logs “No events”*.

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
| CyberCure | API | Active | Yes | |
| Energy sector | — | Placeholder | No | Needs membership / feed |
| Healthcare sector | — | Placeholder | No | Needs membership / feed |

**Optional `MISPCollector`:** pulls from MISP **`/events`** with **its own** limits; **not** wired into default baseline collector step 2. This is **not** counted as one of the **13** DATA_SOURCES slots.

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
| `ThreatFoxCollector`, `URLhausCollector`, `CyberCureCollector` | abuse.ch / CyberCure | Yes |
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
| `OTX_META:` | AlienVault OTX | attack_ids, targeted_countries, tags, references, author_name, adversary, TLP, industries, pulse_description |
| `TF_META:` | ThreatFox | malware_malpedia, reference, reporter, tags, threat_type_desc, last_seen, confidence_level |
| `MITRE_USES_TECHNIQUES:` | MITRE ATT&CK | Technique IDs from STIX uses relationships |
| `NVD_META:` | NVD | CVSS data, CWE, references, affected products |

These are parsed by `run_misp_to_neo4j.py` during the MISP→Neo4j sync to populate enrichment fields on Neo4j nodes. Maximum comment length: 4000 chars (truncated with warning if exceeded).

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

_Last updated: 2026-03-28_
