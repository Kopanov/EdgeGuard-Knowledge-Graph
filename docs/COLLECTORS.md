# EdgeGuard Collectors Documentation

This document details all data collectors in EdgeGuard, including their sources, zone detection methods, and output formats.

---

## Table of Contents

1. [Overview](#overview)
2. [OTX Collector](#1-otx-collector)
3. [NVD Collector](#2-nvd-collector)
4. [CISA Collector](#3-cisa-collector)
5. [MITRE Collector](#4-mitre-collector)
6. [AbuseIPDB Collector](#5-abuseipdb-collector)
7. [VirusTotal](#6-virustotal-lookup-enrichment)
8. [Finance Feed Collector](#7-finance-feed-collector)
9. [Global Feed Collector](#8-global-feed-collector)
10. [Healthcare Feed Collector](#9-healthcare-feed-collector)
11. [Energy Feed Collector](#10-energy-feed-collector)
12. [MISP Collector](#11-misp-collector)
13. [CISA ICS Advisories Collector](#12-cisa-ics-advisories-collector)

---

## Overview

### Zone Detection Method (Conservative)

Collectors use **`detect_zones_from_text()`** and **`detect_zones_from_item()`** from **`config.py`** (see source for exact weights).

EdgeGuard uses a **weighted scoring system** to limit false positives:

- **`ZONE_DETECT_THRESHOLD`** (default **1.5**, **`EDGEGUARD_ZONE_DETECT_THRESHOLD`**) — applied inside **`detect_zones_from_text`** per snippet (so a single strong keyword at `body` weight **1.5** can qualify).
- **`ZONE_ITEM_COMBINED_THRESHOLD`** (default **1.5**, **`EDGEGUARD_ZONE_ITEM_THRESHOLD`**) — applied in **`detect_zones_from_item`** after multi-field accumulation.
- Context weights in **`detect_zones_from_text`**: `name` / `alias` / `title` **3.0**, `description` **2.0**, `body` **1.5**, `tag` **1.0**.
- **NVD** (`nvd_collector.py`): builds an item with **`description`** + **`comment`** = flattened CPE text from **`configurations_to_zone_text()`** (criteria URIs + vendor/product tokens), then calls **`detect_zones_from_item`**.

```python
# Authoritative implementation — always read config.py
# detect_zones_from_text(...)  -> per-field threshold ZONE_DETECT_THRESHOLD
# detect_zones_from_item(...)   -> combined threshold ZONE_ITEM_COMBINED_THRESHOLD
```

### Duplicate avoidance (MISP + incremental runs)

- **`MISPWriter.push_items`**: when **`EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`** is true (default), loads existing **`(type, value)`** on the target event via **`/attributes/restSearch`** and skips attributes already present — covers same-day reruns and overlapping incremental windows. MISP still does not dedupe **across** different daily events; reducing **incoming** volume is the job of collector cursors below.
- **OTX** (non-baseline): stores **`otx_last_pulse_modified`** in **`checkpoints/baseline_checkpoint.json`** under **`[source].incremental`** (`get_source_incremental("otx")`). Each run fetches pulses with **`modified_since`** = last cursor minus **`EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`**. First run with no cursor uses **`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`**. Cursor advances only after a **clean** MISP push (**`failed == 0`**) or when there is nothing to push.
- **MITRE** (non-baseline): stores **`mitre_bundle_etag`**; sends **`If-None-Match`** to GitHub. **HTTP 304** skips download, parse, and MISP push. **Baseline** runs always fetch the full bundle. ETag is saved only after **`failed == 0`** on MISP push (or immediately when **`push_to_misp`** is false).

#### Detection Rules
1. **Thresholds**: Defaults **1.5** for both per-field and combined-item scoring (overridable via env — see **`.env.example`**).
2. **Relative filtering**: In **`detect_zones_from_item`**, sectors must be within **50%** of the max combined score.
3. **Negative keywords**: e.g. “not healthcare”, “except bank” exclude that sector for the analyzed text.
4. **Clean keywords**: malware family names are not sector keywords — link via graph relationships.

### Common Output Fields

All collectors return items with these common fields:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Item type: `indicator`, `vulnerability`, `malware`, `actor`, `technique` |
| `zone` | list | **All matching zones as array** (e.g., `['finance', 'healthcare']`) |
| `tag` | string | Source tag for MISP |
| `sources` | list | List of source identifiers |
| `confidence_score` | float | 0.0-1.0 confidence rating |
| `first_seen` | tz-aware ISO-8601, **OPTIONAL** | Source's claim about when it first observed this entity (concept 1 in [`docs/TIMESTAMPS.md`](TIMESTAMPS.md)). **Omit when source field is absent — never substitute wall-clock NOW** (PR-M2 §4-F4 / F5). |
| `last_seen` | tz-aware ISO-8601, **OPTIONAL** | Source's claim about when it last updated this entity (concept 2). Same omit-when-absent rule. |

**Note:** The `zone` property is always an array. The old `zones` property has been removed.

**Removed in PR-M2:** the `last_updated` key on collector items (Finding 11). It was a dead key — Cypher MERGE sets `n.last_updated = datetime()` server-side and never reads the collector-supplied value. Concepts 3 (`first_imported_at`) and 4 (`last_updated`) are EdgeGuard-internal and always set server-side; collectors must NOT emit them.

**Honest-NULL invariant.** If a collector's source doesn't expose a first/last-seen field, OMIT the key from the item dict — do not substitute `datetime.now()`. The downstream MIN/MAX CASE on the `SOURCED_FROM` edge preserves any prior real claim from another source. The reference pattern is `src/collectors/abuseipdb_collector.py` (blacklist endpoint omits `first_seen` because the API doesn't expose it). See [`docs/TIMESTAMPS.md`](TIMESTAMPS.md) for the full semantic model.

---

## 1. OTX Collector

**File:** `src/collectors/otx_collector.py`

### What It Does
Collects threat intelligence pulses from AlienVault OTX, including:
- Indicators (IPs, domains, hashes, URLs) with per-indicator description
- Malware families with the pulse's ATT&CK technique IDs as `reported_techniques` (2026-10: pulse-level association, written to MISP as `MITRE_USES_TECHNIQUES:{"rt":[…],"pid":"<pulse id>","rids":[…]}` — `rids` lists the other pulses of the same run that named the entity (the collector's dedup folds them in instead of dropping them; indicators carry the same list as `OTX_META.report_ids`); on MITRE actors the block also carries `m` (malware names) and `s` (tool S-ids) from the group → software `uses` relationships (R6: `USES_MALWARE` / `USES_TOOL`) and linked downstream as `IMPLEMENTS_TECHNIQUE` with `match_type='otx_pulse'`, 0.6 — never as `uses_techniques` / `mitre_explicit`)
- CVE references (all CVEs per pulse, no cap)
- **Pulse metadata:** `attack_ids` (MITRE ATT&CK), `industries` (authoritative sector classification), `targeted_countries`, `tags`, `references`, `author_name`, `adversary`, `TLP`
- **Pulse families / adversaries on every indicator (2026-10):** each IOC item carries `pulse_malware_families` (the pulse's `malware_families`, cleaned, ≤ 20) and `pulse_malware_actor_pairs` (`"family::adversary"` for the pulse's families × its `adversary` names through `clean_actor_names`, ≤ 50 — the pair encoding keeps the same-pulse guarantee when several pulses' lists are unioned on one IOC); they travel as `OTX_META.mf` / `.pa`, accumulate on `Indicator.pulse_malware_families` / `.pulse_malware_actor_pairs`, and `build_relationships` Q9b / Q2d link them (`otx_pulse`, 0.6). This is what keeps report-scoped linking working on regular updates: the family / actor attribute itself is a MISP cross-event duplicate after the first pulse and is never re-pushed. `OTX_META` is now written for every pulse indicator (before: only when the pulse had `attack_ids` or `targeted_countries`).
- Named adversaries are automatically extracted as ThreatActor items

### Source
- **URL:** `https://otx.alienvault.com/api/v1/pulses/subscribed`
- **API Key:** Required (free)
- **Rate Limits:** ~30 requests/minute (free tier, 2s between requests)

### Zone Detection
```python
def detect_sectors(self, text: str) -> List[str]:
    """Detect ALL sectors from pulse text using word boundary matching."""
    import re
    text_lower = text.lower()
    matched_sectors = set()
    
    for sector, keywords in SECTOR_KEYWORDS.items():
        for keyword in keywords:
            pattern = r'\b' + re.escape(keyword) + r'\b'
            if re.search(pattern, text_lower):
                matched_sectors.add(sector)
    
    return list(matched_sectors) if matched_sectors else ['global']
```

### Example Output

```python
# Indicator
{
    'indicator_type': 'ipv4',
    'value': '192.168.1.100',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.5,
    'description': 'C2 beacon indicator',
    'pulse_id': '5f3a2b...',
    'pulse_name': 'Emotet Banking Trojan IOCs',
    'attack_ids': ['T1059', 'T1071'],        # MITRE ATT&CK from pulse
    'targeted_countries': ['US', 'DE'],       # OTX geo targeting
    'pulse_tags': ['emotet', 'banking'],      # Pulse labels
    'pulse_references': ['https://...'],      # Source URLs
    'pulse_author': 'AlienVault',
    'pulse_tlp': 'white',
    'otx_industries': ['finance'],            # OTX-native sector classification
}

# Malware (with ATT&CK technique IDs)
{
    'type': 'malware',
    'name': 'Emotet',
    'malware_types': ['unknown'],
    'family': 'Emotet',
    'description': 'Banking trojan targeting financial institutions...',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],  # ATT&CK from pulse attack_ids (2026-10: reported, not MITRE-explicit)
    'pulse_id': '6aa4409a4290cc035d81500c',   # source report id → report-scoped INDICATES / ATTRIBUTED_TO
    'pulse_id': '5f3a2b...',
    'pulse_name': 'Emotet Banking Trojan IOCs',
}

# CVE Reference (no cap — all CVEs from pulse)
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'Referenced in OTX pulse: Emotet Banking Trojan IOCs',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'first_seen': '2024-01-15T10:30:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.5,
    'severity': 'UNKNOWN',
    'cvss_score': 0.0,
    'attack_vector': 'NETWORK',
}

# Threat Actor (auto-extracted from pulse adversary field — 2026-10: the free-text
# adversary goes through actor_name_hygiene.clean_actor_names: "apt-c-13, sandworm"
# → two actor items, "multiple russian state-backed groups" → none)
{
    'type': 'actor',
    'name': 'TA542',
    'description': 'Emotet distribution group...',
    'zone': ['finance'],
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'confidence_score': 0.5,
    'reported_techniques': ['T1059', 'T1071'],  # 2026-10
    'aliases': [],
}
```

---

## 2. NVD Collector

**File:** `src/collectors/nvd_collector.py`

### What It Does
Collects CVE records from the National Vulnerability Database, including:
- CVE IDs and descriptions (up to 1000 chars)
- CVSS scores (v4.0, v3.1, v3.0, v2) with full component data
- Affected products (CPE matching)
- Attack vectors
- CWE identifiers
- Reference URLs and tags (advisory/patch links)
- **CISA KEV fields** — `cisa_exploit_add`, `cisa_action_due`, `cisa_required_action`, `cisa_vulnerability_name` (strongest signal of active exploitation; auto-boosts confidence to 0.9)

**NIST notice:** This product uses data from the NVD API but is not endorsed or certified by the NVD ([Start Here](https://nvd.nist.gov/developers/start-here)).

### Source
- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **API Key:** Optional (strongly recommended — higher throughput). Sent as HTTP header `apiKey` with the key value (per [NVD Developers — Start Here](https://nvd.nist.gov/developers/start-here)).
- **Rate Limits (NIST):** With key **50** requests / 30 seconds; without key **5** requests / 30 seconds. NIST recommends ~**6 seconds** between requests during bulk sync; this collector uses ~**0.7s** between paginated baseline/incremental pages when a key is set (still under the rolling cap) and ~**6.5s** without a key.

### Published-date API rules (implementation)
NVD 2.0 requires **`pubStartDate` and `pubEndDate` together**; each window **≤ 120 days**. The collector uses **`NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`**, **`clamp_nvd_published_range()`**, and for baseline **`iter_nvd_published_windows()`** — see `src/collectors/nvd_collector.py`.

**Incremental runs** use the same published window, probe **`totalResults`**, then page with **`resultsPerPage`** up to **2000** and **`startIndex`** from the newest slice of the result set (CVE list is **published-ascending** per [CVE API](https://nvd.nist.gov/developers/vulnerabilities)). Ongoing syncs can also use **`lastModStartDate` / `lastModEndDate`** (≤120 days); that pattern is not implemented here — new and updated CVEs in the chosen published window are still returned when NVD updates records within that window.

### Zone detection (implementation)

**`detect_sectors(description, configurations)`** builds `{"description": …, "comment": …}` where **`comment`** is plain text from **`configurations_to_zone_text()`** (CPE **`criteria`** strings plus vendor/product tokens from CPE 2.3 URIs). It calls **`detect_zones_from_item()`** — not `json.dumps` on the raw JSON (that broke word-boundary keyword matches).

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2024-1234',
    'description': 'SQL injection vulnerability in hospital management system...',
    'zone': ['healthcare'],  # Array of all matching zones
    'tag': 'nvd',
    'sources': ['nvd'],
    'first_seen': '2024-01-10T00:00:00Z',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.9,  # 0.9 when on CISA KEV, 0.6 otherwise
    'severity': 'HIGH',
    'cvss_score': 8.5,
    'attack_vector': 'NETWORK',
    'affected_products': ['cpe:2.3:a:hospital_mgmt:system:1.0:*:*:*:*:*:*:*'],
    'reference_urls': ['https://vendor.example.com/advisory/2024-001'],
    'cisa_exploit_add': '2024-01-12',       # date added to CISA KEV
    'cisa_action_due': '2024-02-02',        # federal remediation deadline
    'cisa_required_action': 'Apply update per vendor instructions.',
    'cisa_vulnerability_name': 'Hospital Mgmt SQL Injection',
}
```

---

## 3. CISA Collector

**File:** `src/collectors/cisa_collector.py`

### What It Does
Collects Known Exploited Vulnerabilities (KEV) from CISA, including:
- CVE IDs with exploitation confirmation
- Vendor and product information
- Required actions and due dates
- Known ransomware campaign use

### Source
- **URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **API Key:** Not required
- **Update Frequency:** Daily

### Zone Detection
```python
def detect_sectors(self, text: str) -> list:
    """Detect ALL sectors from vendor/project/product."""
    return detect_zones_from_text(text)
```

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2023-1234',
    'description': 'Remote code execution in power grid management software...',
    'zone': ['energy', 'finance'],  # Array of all matching zones
    'tag': 'cisa_kev',
    'sources': ['cisa_kev'],
    'first_seen': '2024-01-15',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.9,  # High confidence - confirmed exploited
    'severity': 'CRITICAL',
    'cvss_score': 9.0,
    'attack_vector': 'NETWORK',
    'vendor': 'SCADA Systems Inc',
    'product': 'Grid Manager Pro',
    'required_action': 'Apply patch by due date',
    'due_date': '2024-02-01',
    'known_ransomware_use': 'Known'
}
# Note: severity and cvss_score are derived from the CISA KEV `knownRansomwareCampaignUse`
# field (Known=CRITICAL/9.0, Unknown=HIGH/7.0), not from NVD CVSS data. For actual CVSS
# scores, cross-reference with the NVD collector via CVE ID.
```

---

## 4. MITRE Collector

**File:** `src/collectors/mitre_collector.py`

### What It Does
Collects threat intelligence from MITRE ATT&CK framework, including:
- Attack techniques (T###)
- Threat actors (intrusion sets)
- Malware families
- Relationships (uses, attributed-to, subtechnique-of) — STIX **`uses`** populates **`uses_techniques`** on **actors** and **malware** for **`build_relationships.py`** (malware round-trips via MISP **`MITRE_USES_TECHNIQUES:`**)

### Source
- **URL:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- **ATT&CK for ICS (2026-10, `EDGEGUARD_ENABLE_MITRE_ICS=true`, default off):** `ics-attack/ics-attack.json` from the same repository (`MITRE_ICS_ATTACK_URL` to override) is fetched after the Enterprise bundle and parsed with the same code (`_parse_bundle`, kill-chain name `mitre-ics-attack`). 97 techniques (T08xx), 12 tactics (TA0100–TA0111, 9 short names identical to Enterprise), 14 groups, 23 malware. Every item carries `attack_domain` (`enterprise` | `ics`); groups/malware present in both bundles are emitted once with `uses_techniques` unioned. An ICS fetch/parse failure is logged, counted (`pipeline_errors_total{task=collect_mitre_ics}`) and never affects the Enterprise items; the MITRE circuit breaker is not tripped. No ETag for ICS: on an Enterprise HTTP 304 the ICS bundle is skipped (baseline runs ignore ETag). ICS items are **not** auto-zoned `energy` (`x_mitre_sectors` / assets unused — follow-up).
- **API Key:** Not required
- **Format:** STIX 2.1 bundle

### Zone Detection
```python
def detect_sectors(self, text):
    """Detect ALL sectors from technique/actor description."""
    return detect_zones_from_text(text)
```

### Example Output

```python
# Technique
{
    'type': 'technique',
    'mitre_id': 'T1566.001',
    'name': 'Spearphishing Attachment',
    'description': 'Adversaries may send spearphishing emails with malicious attachments...',
    'zone': ['global'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'sources': ['mitre_attck'],
    'platforms': ['Windows', 'macOS', 'Linux'],
    'data_sources': ['Application Log', 'File', 'Network Traffic'],
    'confidence_score': 0.8
}

# Threat Actor
{
    'type': 'actor',
    'name': 'APT29',
    'aliases': ['Cozy Bear', 'The Dukes', 'PowerDuke'],
    'description': 'APT29 is a threat group that has been attributed to the Russian government...',
    'zone': ['healthcare', 'finance'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'sources': ['mitre_attck'],
    'confidence_score': 0.7,
    'uses_techniques': ['T1566', 'T1059'],  # From STIX actor→technique **uses** (example)
}

# Malware
{
    'type': 'malware',
    'name': 'Conti',
    'malware_types': ['Ransomware'],
    'family': 'Conti',
    'description': 'Conti is a ransomware family that has been used in attacks against healthcare...',
    'zone': ['healthcare', 'finance', 'energy'],  # Array of all matching zones
    'tag': 'mitre_attck',
    'sources': ['mitre_attck'],
    'confidence_score': 0.7,
    'uses_techniques': ['T1486', 'T1490'],  # From STIX malware→technique **uses** (example)
}

# Tool (from MITRE ATT&CK)
{
    'type': 'tool',
    'mitre_id': 'S0002',
    'name': 'Mimikatz',
    'description': 'Credential dumping tool...',
    'zone': ['global'],
    'tag': 'mitre_attck',
    'sources': ['mitre_attck'],
    'tool_types': ['credential-theft'],
    'confidence_score': 0.95,
    'uses_techniques': ['T1003.001', 'T1078'],
}
```

---

## 5. AbuseIPDB Collector

**File:** `src/collectors/abuseipdb_collector.py`  
**Class:** `AbuseIPDBCollector`  
**DAG:** `edgeguard_daily` (`collect_abuseipdb`)

### What It Does
Fetches IP reputation / blacklist data from the AbuseIPDB API v2 and pushes indicators to MISP, including:
- Abuse confidence score, total reports, and unique reporter count (`num_distinct_users`)
- Reverse DNS (`domain`), associated `hostnames`
- ISP, country code, usage type
- Tor exit node and whitelist flags
- Top 5 report objects per IP

### Source
- **Base URL:** `https://api.abuseipdb.com/api/v2`
- **API Key:** Required — `ABUSEIPDB_API_KEY`
- **Rate limits:** Free tier ~1,000 checks/day; collector enforces ~1 request/second (`MIN_INTERVAL_SECONDS`)

### Zone detection
Typically **`global`** or derived from feed context — see `collect()` implementation for scoring → zone mapping.

---

## 6. VirusTotal (lookup enrichment)

**File:** `src/collectors/vt_collector.py` (`VTCollector`)  
**DAG:** `edgeguard_medium_freq` (every 4 hours) — task id `collect_virustotal` → `run_vt_collection`. Not part of the baseline DAG.

### What It Does
The public (free) VirusTotal API v3 offers **single-object lookups only** (`GET /files/{hash}`); feed and Intelligence-search endpoints need a premium licence and return nothing on a free key. The collector therefore does not act as a feed. Each run:

1. lists SHA-256 attributes in MISP that no `source:VirusTotal` attribute covers yet (`attributes/restSearch`, type `sha256`, attribute timestamp within `EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS`, default 30 days) — hashes pushed by ThreatFox, MalwareBazaar, OTX and other sources;
2. looks each hash up within the per-run cap and the daily budget (below);
3. pushes the enriched items to MISP under `source:VirusTotal`. The MISP→Neo4j sync merges them into the **same** Indicator node: a second `SOURCED_FROM` edge, VirusTotal confidence (`last_analysis_stats`), threat label, file names (zone detection) and the first-submission date (source-truthful `first_seen`).

Hashes are looked up **once**: the ledger remembers every lookup, including hashes unknown to VirusTotal (HTTP 404), so no lookup is repeated across runs.

### Free-tier safety (never blocks the workflow)

| Limit | Enforcement |
|-------|-------------|
| 4 lookups/min | `RateLimiter(requests_per_minute=4)` in-process |
| 500 lookups/day | Ledger `virustotal_daily_budget.json` in the state directory (`./state` bind mount): `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` (default **400**) per UTC day, `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` (default **60**) per run — six runs a day stay below the budget |
| HTTP 429 | The day is marked exhausted in the ledger; the run stops and pushes what it has |
| Budget exhausted | Task returns `skipped=True`, `skip_reason_class="virustotal_daily_budget"` (`virustotal_rate_limited` when VirusTotal answered 429 before any lookup succeeded); the Airflow task stays green and downstream continues |
| MISP candidate listing fails | `skip_reason_class="virustotal_candidates_unavailable"` |
| API key missing / rejected | `missing_virustotal_key` / `virustotal_auth_denied` |

Every quota message is logged with the prefix **`[VT-QUOTA]`** (budget state at the start of the run, exhaustion events, run summary with lookups / enriched / unknown / errors), so `grep VT-QUOTA` on the task log shows what happened. The task result carries `vt_lookups`, `vt_enriched`, `vt_unknown`, `vt_lookup_errors`, `vt_stopped`, `vt_budget_used`, `vt_budget_remaining`.

Growth: at the defaults, up to 360 hashes per day gain VirusTotal corroboration; a ThreatFox-sized backlog (~16,000 hashes) is covered in about six weeks. A premium key raises the budget knobs; the collector logic does not change.

### Zone Detection
```python
def _detect_zones_from_attributes(self, attrs):
    """Detect ALL sectors from file names, tags, sandbox verdicts and the popular threat label."""
    ...
    return detect_zones_from_text(combined_text)
```

### Example Output

```python
# Hash enrichment (from GET /files/{sha256})
{
    'indicator_type': 'hash',
    'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'zone': ['finance'],                 # from file names / tags / sandbox verdicts
    'tag': 'virustotal',
    'source': ['virustotal'],
    'first_seen': '2024-01-01T00:00:00+00:00',   # first_submission_date (source-truthful)
    'confidence_score': 0.85,           # from last_analysis_stats
    'md5': '...', 'sha1': '...', 'sha256': '...',
    'file_type': 'Win32 EXE', 'file_size': 123456,
    'vt_reputation': -12, 'vt_names': ['invoice.exe'],
    'threat_label': 'trojan.emotet/heodo', 'threat_category': 'trojan',
    'yara_rules': [...], 'sigma_rules': [...], 'sandbox_verdicts': {...}
}
```

### `virustotal_collector.py` (`VirusTotalCollector`) — not scheduled
`src/collectors/virustotal_collector.py` is an older module (`run_virustotal_enrichment_collection` in the DAG file, `virustotal_enrich` in `run_pipeline`) that lists `/files` — a premium endpoint — and offers `query_domain` / `query_hash` / `query_ip` helpers. No DAG schedules it; it shares the key and the 4/min limiter but not the daily ledger. Use `VTCollector` for production runs.

---

## 7. Finance Feed Collector

**File:** `src/collectors/finance_feed_collector.py`

### What It Does
Collects finance-specific threat feeds from abuse.ch, including:
- **Feodo Tracker:** Banking trojan C&C server IPs
- **SSL Blacklist:** Malicious SSL certificate fingerprints

### Sources
- **Feodo (regular runs):** `https://feodotracker.abuse.ch/downloads/ipblocklist.csv` — C2 servers active in the last 30 days
- **Feodo (baseline runs):** `https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv` — the complete C2 history (same columns); a fresh baseline seeds the history once, the daily task then adds what is currently active
- **SSL Blacklist:** `https://sslbl.abuse.ch/blacklist/sslblacklist.csv`
- **API Key:** Not required

### Zone Detection
Both collectors use `detect_zones_from_text()` on malware names and listing reasons:

```python
# Feodo Collector
zones = detect_zones_from_text(malware.lower())

# SSL Blacklist Collector
zones = detect_zones_from_text(reason)
```

### Example Output

```python
# Feodo Indicator (Banking Trojan C&C)
{
    'indicator_type': 'ipv4',
    'value': '185.220.101.42',
    'zone': ['finance', 'healthcare'],  # Emotet targets both - array only
    'tag': 'feodo_tracker',
    'sources': ['feodo_tracker'],
    'first_seen': '2024-01-10',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.7,
    'malware_family': 'emotet',
    'port': '443',
    'status': 'online'
}

# SSL Blacklist Indicator
{
    'indicator_type': 'hash',
    'value': 'a1b2c3d4e5f6...',
    'zone': ['finance'],  # Array of all matching zones
    'tag': 'ssl_blacklist',
    'sources': ['ssl_blacklist'],
    'first_seen': '2024-01-10',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.6,
    'listing_reason': 'dridex'
}
```

---

## 8. Global Feed Collector

**File:** `src/collectors/global_feed_collector.py`

### What It Does
Collects universal threat feeds that apply to all zones, including:
- **ThreatFox:** IOCs with malware family context
- **URLhaus:** Malware distribution URLs

### Configuration
- **ThreatFox** requires **`THREATFOX_API_KEY`** in the same environment as the collector (Airflow worker / `.env`). Get a free key from [auth.abuse.ch](https://auth.abuse.ch/). Without it, the task **skips** or returns **401 Unauthorized** if the API is called without credentials.

### Sources
- **ThreatFox:** `https://threatfox-api.abuse.ch/api/v1/`
- **URLhaus:** `https://urlhaus.abuse.ch/downloads/csv_recent/`

### Zone Detection

```python
def get_zones_from_malware(malware_name):
    """Determine ALL zones based on malware family name."""
    return detect_zones_from_text(malware_name or "")

# ThreatFox uses malware family
zones = get_zones_from_malware(malware)

# URLhaus uses threat tags
zones = get_zones_from_malware(threat) or get_zones_from_malware(tags)
```

### Example Output

```python
# ThreatFox Indicator
{
    'indicator_type': 'domain',
    'value': 'malware-c2.example.com',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'threatfox',
    'sources': ['threatfox'],
    'first_seen': '2024-01-14T10:00:00Z',
    'last_seen': '2024-01-15T08:00:00Z',     # Most recent observation
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.75,
    'malware_family': 'emotet',
    'threat_type': 'botnet_cc',
    'threat_type_desc': 'Botnet Command&Control server',
    'malware_malpedia': 'https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet',
    'reference': 'https://threatfox.abuse.ch/ioc/12345/',
    'tags': ['emotet', 'epoch4', 'tier1'],    # IOC classification labels
}

# URLhaus Indicator
{
    'indicator_type': 'url',
    'value': 'http://evil-site.com/malware.exe',
    'zone': ['healthcare'],  # Array of all matching zones
    'tag': 'urlhaus',
    'sources': ['urlhaus'],
    'first_seen': '2024-01-14',
    # 'last_updated' REMOVED in PR-M2 — set server-side by Cypher MERGE; collectors must NOT emit.
    'confidence_score': 0.6,
    'threat_type': 'malware_download',
    'tags': 'exe,windows'
}
```

---

## 9. Healthcare Feed Collector

**File:** `src/collectors/healthcare_feed_collector.py`

### What It Does
Placeholder for healthcare-specific threat feed collection.

### Decision (2026-10)
No healthcare member-only feed collector is planned: HC3 and Health-ISAC (H-ISAC) require memberships that are not budgeted. Public healthcare advisories are covered by the CISA KEV and CISA ICS Advisories collectors. The placeholder stays so the slot is visible on the skip dashboard.

### Current State
Returns `skipped=True` (`skip_reason_class="placeholder"`); no feed is wired.

### Example Output
```python
# Placeholder - no active output yet
{
    'source': 'healthcare_placeholder',
    'success': True,
    'count': 0,
    'timestamp': '2024-01-15T12:00:00Z'
}
```

---

## 10. Energy Feed Collector

**File:** `src/collectors/energy_feed_collector.py`

### What It Does
Placeholder for energy/ICS-specific threat feed collection.

### Decision (2026-10)
No energy member-only feed collector is planned: EE-ISAC (European Energy ISAC) membership is not budgeted. CISA ICS-CERT energy sector advisories are collected by the flag-guarded CISA ICS Advisories collector (`cisa_ics`); MITRE ATT&CK for ICS is available through the MITRE collector flag. The placeholder stays so the slot is visible on the skip dashboard.

### Current State
Returns `skipped=True` (`skip_reason_class="placeholder"`); no feed is wired.

### Example Output
```python
# Placeholder - no active output yet
{
    'source': 'energy_placeholder',
    'success': True,
    'count': 0,
    'timestamp': '2024-01-15T12:00:00Z'
}
```

---

## 11. MISP Collector

**File:** `src/collectors/misp_collector.py`

### What It Does
Pulls data from local MISP instance for **optional** Neo4j-oriented ingest (legacy / alternate path), including:
- Indicators (all types)
- Vulnerabilities (CVEs)
- Malware families
- Threat actors
- MITRE techniques
- Relationships

**Note:** **Production Airflow** does **not** use this module for graph fill. Scheduled **MISP → Neo4j** is **`run_misp_to_neo4j`**: **attribute parse** → **per-event** dedupe and same-event cross-item edges → chunked node merges (**`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**) → batched relationship writes (**`EDGEGUARD_REL_BATCH_SIZE`**). A separate **CLI** path can use STIX helpers (`run_pipeline` / `MISPToNeo4jSync` STIX methods) — see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

**Limits & wiring:** This module is **not** run by the **`edgeguard_baseline`** DAG or by **`run_pipeline` step 2** (external collectors only). **`run_misp_to_neo4j`** discovers events via **paginated `/events/index`** (+ client filter) with **`restSearch` fallback** (`limit: 1000`) — see **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**. This collector uses **`resolve_collection_limit(..., baseline=False)`** and caps **`/events`** fetch at **`min(3×limit, 2000)`** or **2000**, plus **500** attributes per event.

### Source
- **URL:** Configured MISP instance (`MISP_URL`)
- **API Key:** Required (`MISP_API_KEY`)

### Zone Detection
```python
def detect_sectors(self, text):
    """Detect ALL sectors from text (tags, description)."""
    return detect_zones_from_text(text)
```

### Source Tag Mapping
```python
SOURCE_TAG_MAPPING = {
    'AlienVault-OTX': 'alienvault_otx',
    'NVD': 'nvd',
    'CISA-KEV': 'cisa_kev',
    'MITRE-ATT&CK': 'mitre_attck',
    'VirusTotal': 'virustotal',
    'AbuseIPDB': 'abuseipdb',
    'Feodo-Tracker': 'feodo',
    'SSL-Blacklist': 'sslbl',
    'URLhaus': 'urlhaus',
    'ThreatFox': 'threatfox'
}
```

### Example Output

```python
# Indicator from MISP
{
    'type': 'indicator',
    'value': '192.168.1.100',
    'indicator_type': 'ipv4',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'source': 'alienvault_otx',
    'original_source': 'alienvault_otx',
    'event_id': '1234',
    'tags': ['zone:Finance', 'zone:Healthcare', 'source:AlienVault-OTX']
}

# Vulnerability from MISP
{
    'type': 'vulnerability',
    'value': 'CVE-2024-1234',
    'zone': ['healthcare'],  # Array of all matching zones
    'source': 'nvd',
    'original_source': 'nvd',
    'severity': 'HIGH',
    'cvss_score': 8.5
}
```

---

## 12. CISA ICS Advisories Collector

**File:** `src/collectors/cisa_ics_collector.py` — **flag-guarded, OFF by default** (`EDGEGUARD_ENABLE_CISA_ICS=true` to enable). Added 2026-10.

### What It Does
Collects CISA ICS-CERT advisories (`ICSA-*`) and ICS medical advisories (`ICSMA-*`) published as **CSAF 2.0** JSON files in the public `cisagov/CSAF` GitHub repository and emits **one `vulnerability` item per (advisory, CVE)**. The point of this collector is the **source-asserted critical-infrastructure sector**: every advisory carries a `"Critical infrastructure sectors"` note written by CISA (e.g. `"Critical Manufacturing, Energy, Information Technology"`). The keyword sector detector (`detect_zones_from_text`) is **deliberately not applied** to these items.

### Source
- **Base URL:** `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`EDGEGUARD_CISA_ICS_BASE_URL`)
- **Listing files:** `index.txt` (all advisories as `YYYY/<file>.json`, ~3,960 entries 2010–2026, newest first) and `changes.csv` (`"YYYY/<file>.json","<ISO timestamp>"`, no header, newest first)
- **Per advisory:** `document.tracking.{id,initial_release_date,current_release_date}`, `document.title`, `document.notes[]`, `document.references[]` (`category: self` → cisa.gov URL), `product_tree.branches[]` (vendor → product_name), `vulnerabilities[]` (`cve`, `cwe`, `notes`, `scores[].cvss_v3`)
- **API Key:** Not required · **Licence:** TLP:WHITE ("Disclosure is not limited")
- **Mode selection:** baseline → `index.txt` filtered to the years inside `baseline_days` and pre-filtered on the day-of-year encoded in the file name (`icsa-26-281-01` → 2026-10-08, with a 45-day margin), fetched newest-first, then filtered by `initial_release_date >= cutoff`; incremental → `changes.csv` rows newer than the stored cursor (`checkpoints/baseline_checkpoint.json` → `cisa_ics.incremental.cisa_ics_last_change_ts`, minus a 24 h overlap; first run uses `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS`, default 30). The cursor advances **only after a clean MISP push** (`failed == 0`), like the OTX/MITRE cursors.

### Zone Mapping (source-asserted, fixed table)

| CISA sector (from the advisory note) | EdgeGuard zone |
|---|---|
| `Energy` | `energy` |
| `Healthcare and Public Health` | `healthcare` |
| `Financial Services` | `finance` |
| any other sector (Critical Manufacturing, Water, Communications, …) | contributes nothing |
| nothing mapped | `['global']` |

The raw sector list is kept on the item as `ics_sectors`; every emitted zone is validated against `config.VALID_ZONES`.

### Example Output

```python
{
    'type': 'vulnerability',
    'cve_id': 'CVE-2026-32645',
    'description': 'ICSA-26-281-01: Red Lion Controls N-Tron 700 Series — Default factory credentials ...',
    'zone': ['energy'],                      # from "Critical Manufacturing, Energy, Information Technology"
    'ics_sectors': ['Commercial Facilities', 'Communications', 'Critical Manufacturing', 'Energy', 'Information Technology'],
    'advisory_id': 'ICSA-26-281-01',
    'tag': 'cisa_ics',
    'source': ['cisa_ics'],
    'confidence_score': 0.9,                  # authoritative government advisory
    'published': '2026-10-08T06:00:00+00:00',     # initial_release_date
    'last_modified': '2026-10-08T06:00:00+00:00', # current_release_date
    'first_seen': '2026-10-08T06:00:00+00:00',    # source-truthful (same two dates)
    'last_seen': '2026-10-08T06:00:00+00:00',
    'severity': 'MEDIUM', 'cvss_score': 6.0, 'attack_vector': 'LOCAL',
    'cvss_v31_data': {'vector_string': 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N', 'base_score': 6.0, ...},
    'cvss_v30_data': None,
    'cwe': ['CWE-798'],
    'vendor': 'Red Lion Controls', 'product': '700 Series',
    'affected_products': ['Red Lion Controls 700 Series'],
    'reference_urls': ['https://www.cisa.gov/news-events/ics-advisories/icsa-26-281-01'],
    'ref_tags': [], 'cpe_type': [], 'result_impacts': ['HIGH', 'HIGH', 'NONE'],
}
# No CVSS block in the advisory → KEV-consistent defaults: severity HIGH, cvss_score 7.0, attack_vector NETWORK.
# Dates absent → the four timestamp keys are omitted (honest-NULL), never wall-clock.
# MISP: tagged source:CISA-ICS + zone:<Zone>; NOT tagged CISA-KEV. Same CVE in two advisories → MISP dedups the
# second attribute (type, value); the first advisory's metadata wins.
```

### Flags & knobs (`src/config.py`, section "CISA ICS advisories collector (2026-10)")

| Env var | Default | Meaning |
|---|---|---|
| `EDGEGUARD_ENABLE_CISA_ICS` | `false` | Master switch. Off → the daily task and `collect()` log "disabled by flag" and return a skipped status (success, 0 items) **without any HTTP request** |
| `EDGEGUARD_CISA_ICS_BASE_URL` | GitHub raw `OT/white/` folder | Where `index.txt`, `changes.csv` and the advisory files live |
| `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` | `1200` | Hard cap on advisory files fetched per run (a 24-month baseline is ~900) |
| `EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES` | `50` | Baseline-only sanity floor (see below) |
| `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` | `30` | Lookback for the first incremental run (no cursor yet) |

### Safety behaviour
- **Isolated:** own circuit breaker (`cisa_ics`, 3 failures → open 30 min), own `RateLimiter` (≤ 4 req/s, sequential fetches), `retry_with_backoff` (3 retries) + `request_with_rate_limit_retries` (429/5xx backoff). Shares only the generic helpers with the KEV collector.
- **Per-file failures never abort the run:** a file that is not a JSON object with `document` + `vulnerabilities`, a JSON decode error, or a per-file 404 is counted in the status `stats` (`malformed`, `fetch_failed`, `skipped_vulns`, …) and skipped. Ten **consecutive** fetch failures (or the breaker opening mid-run) abort as a transient error **before** anything is pushed.
- **Baseline sanity floor:** when at least `CISA_ICS_MIN_EXPECTED_ADVISORIES` advisories were attempted but fewer parsed, or the index lists nothing in the window, the collector logs an error, increments `pipeline_errors_total{task="collect_cisa_ics"}` and raises `CISAICSBaselineFloorError` (a `TransientServerError` subclass) → `run_collector_with_metrics` marks the task **skipped + Slack alert** instead of writing a thin dataset. Not evaluated when fewer than the floor were attempted (small `collection_limit` smoke runs).
- **Upstream outage** (timeout / connection error / 5xx on the index) propagates as transient → skip + alert. A 4xx on `index.txt`/`changes.csv` (layout change) returns `success=False` so the task goes red for an operator. Code defects re-raise (DAG catastrophic branch).
- `health_check()` GETs `index.txt` and returns the same `{healthy, response_time_ms, ...}` shape as the other collectors.

---

## Collector Summary Table

| Collector | Sources | Status | Zone Detection |
|-----------|---------|--------|----------------|
| OTX | AlienVault OTX | ✅ Active | `detect_sectors()` → list |
| NVD | NVD | ✅ Active | `detect_sectors()` → `detect_zones_from_item` + CPE flattening → list |
| CISA | CISA KEV | ✅ Active | `detect_zones_from_text()` → list |
| MITRE | MITRE ATT&CK | ✅ Active | `detect_zones_from_text()` → list |
| AbuseIPDB | AbuseIPDB API | ✅ Active | See `AbuseIPDBCollector` |
| VirusTotal | VirusTotal API v3 lookups (free tier) | ✅ Active | `VTCollector` (`vt_collector.py`): enrichment of MISP hashes within a daily budget; `VirusTotalCollector` (`virustotal_collector.py`) is not scheduled |
| Finance Feed | Feodo, SSLBL | ✅ Active | `detect_zones_from_text()` → list |
| Global Feed | URLhaus, ThreatFox | ✅ Active | `detect_zones_from_text()` → list |
| Healthcare | — (HC3 / Health-ISAC not planned, decision 2026-10) | ⏳ Placeholder | - |
| Energy | — (EE-ISAC not planned, decision 2026-10; ICS-CERT via `cisa_ics`) | ⏳ Placeholder | - |
| MISP | Local MISP | ✅ Active | `detect_sectors()` → list |
| CISA ICS | cisagov/CSAF (ICS-CERT advisories) | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, default off) | Source-asserted sector → fixed table (`map_sectors_to_zones()`), no keyword detector |

---

## Baseline collection limits — current & planned

This table captures **what each collector actually pulls on a 730-day
baseline today**, the **upstream API constraint** driving that choice,
and any **planned follow-up work**. Operators running long baselines
should expect the numbers in the "Current ceiling" column as the hard
upper bound for a single baseline run.

| Collector | Current ceiling | Upstream API constraint | Notes & planned follow-ups |
|-----------|-----------------|-------------------------|----------------------------|
| **NVD** | Full windowed collection (no artificial run-level cap on baseline) | `resultsPerPage <= 2000`; `pubStartDate..pubEndDate` must span `<= 120` days per request | Already iterates 120-day windows via `iter_nvd_published_windows`. PR-M1 adds a defensive WARNING + ignore if an incremental-style `limit` env is present in baseline (prevents ~99% silent truncation) |
| **OTX** | `max_pages = 200` × `50/page` ≈ 10k pulses (~7 min runtime, 2 s between pages) | No publicly documented pulse cap; effective throttle ≈ 30 req/min on the free tier | Current settings produce **~100k nodes + relationships** on a 730-day run. Raising `max_pages` is a future knob (likely an env var) for operators with a paid tier and very active subscriptions |
| **CISA KEV** | Full KEV snapshot per run | Public JSON, no auth, no rate limit | No change planned |
| **MITRE ATT&CK** | Full STIX 2.1 bundle per run | Public GitHub raw file, no rate limit | No change planned |
| **MISP (local)** | Full MISP server content matching the filter | Bounded by local MISP; no external quota | No change planned |
| **AbuseIPDB** | As per `ABUSEIPDB_*` limits | Public API daily checks quota (1k free) | No change planned |
| **VirusTotal** | `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` lookups per run (default 60), `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` per UTC day (default 400); not in the baseline DAG | Free tier: **4 req/min**, **500 req/day**; lookups only (`GET /files/{hash}`), no feed or search endpoints | Enrichment of hashes already in MISP (see [§ 6](#6-virustotal-lookup-enrichment)); the ledger in `./state` carries the daily counter across runs and remembers looked-up hashes. A premium key raises the two knobs |
| **Finance (Feodo / SSLBL)** | Feodo: full C2 history on baselines (`ipblocklist_aggressive.csv`), 30-day list on regular runs; SSLBL: full feed | Public CSV/text feeds, no rate limit | No change planned |
| **Global (URLhaus / ThreatFox)** | **ThreatFox: last 7 days via API** (clamped in PR-M1); URLhaus full feeds | **abuse.ch ThreatFox:** `get_iocs` `days` param `Min 1, Max 7` per [abuse.ch docs](https://threatfox.abuse.ch/api/); historical >7d is the documented **JSON/CSV bulk export** (`https://threatfox.abuse.ch/export/`), NOT this endpoint | **Planned:** bulk-import collector that ingests the ThreatFox JSON/CSV export for true historical depth beyond 7 days |
| **Energy (sector)** | Placeholder (returns `skipped=True`, `skip_reason_class="placeholder"`) | — | No member-only feed (EE-ISAC) is planned (decision 2026-10). Surfaces on the skip dashboard as a placeholder (not silent zero-count) since PR-M1. **Since 2026-10 the ICS-CERT part is a real collector:** [CISA ICS Advisories](#12-cisa-ics-advisories-collector) (`cisa_ics`, flag-guarded by `EDGEGUARD_ENABLE_CISA_ICS`, default off) feeds `energy` / `healthcare` / `finance` from CISA's own sector assertion |
| **CISA ICS Advisories** | `min(index entries in window, CISA_ICS_MAX_ADVISORIES_PER_RUN=1200)` advisory files (~900 on a 730-day run), one item per CVE | Public GitHub raw files, no auth; polite sequential fetch ≤ 4 req/s | Flag-guarded, default **off**. Baseline sanity floor `CISA_ICS_MIN_EXPECTED_ADVISORIES=50` → transient skip + alert instead of a thin dataset |
| **Healthcare (sector)** | Placeholder (returns `skipped=True`, `skip_reason_class="placeholder"`) | — | No member-only feed (HC3, Health-ISAC) is planned (decision 2026-10). Same skip-dashboard behaviour as Energy |

### Planned improvements (future PRs)

- **ThreatFox bulk-import collector** for historical IOCs >7 days (reads the abuse.ch JSON/CSV export, pushes to MISP with a dedicated `Source(source_id="threatfox_bulk")`)
- **VT Premium API path** for operators with licensed service steps (unlocks bulk Intelligence search beyond the 500/day free-tier cap)
- **OTX max-pages env knob** (`EDGEGUARD_OTX_BASELINE_MAX_PAGES`) for paid-tier operators with very active pulse subscriptions

---

## Testing Collectors

Each collector can be tested individually:

```bash
cd EdgeGuard-Knowledge-Graph/src   # or your clone path

python -m collectors.otx_collector
python -m collectors.nvd_collector
python -m collectors.cisa_collector
python -m collectors.mitre_collector
python -m collectors.abuseipdb_collector
python -m collectors.vt_collector
python -m collectors.virustotal_collector
python -m collectors.finance_feed_collector
python -m collectors.global_feed_collector
python -m collectors.healthcare_feed_collector
python -m collectors.energy_feed_collector
```


---

## Adding a new reliable source — checklist

When adding a new collector that has a **canonical first-reported / last-reported timestamp** that should flow into the source-truthful timestamp pipeline (PR S5, 2026-04 — see `docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`), follow this **5-step checklist**:

> **Chip 5a (PR follow-up) consolidated steps 1–4** of the legacy
> 8-step checklist into a single declarative edit in
> `src/source_registry.py`. The five legacy registries
> (`_RELIABLE_FIRST_SEEN_SOURCES`, `SOURCE_TAGS`, `SOURCES`,
> `MISPWriter.SOURCE_TAGS`, `DEFAULT_SOURCES`) are now derived from
> the registry, so adding a `Source(...)` entry there propagates to
> all five simultaneously. The propagation is pinned by
> `tests/test_source_registry.py::test_adding_a_new_source_propagates_to_all_five_derivations`.

### 1. Add a `Source(...)` entry to `src/source_registry.py`

Append one record to the `_REGISTRY` tuple. Required fields:
``canonical_id``, ``display_name``, ``source_type``, ``reliability``,
``misp_tag``, ``reliable_first_seen``. Optional but recommended:
``aliases`` (covers historical short-names so collector lookups by
either spelling resolve identically), ``cli_id`` / ``api_key_env`` /
``rate_limit`` / ``cli_default_enabled`` / ``cli_description`` (the
``edgeguard sources`` CLI listing), ``cli_display_name`` (only needed
when the CLI label differs from the Neo4j ``Source.name`` — currently
only NVD).

The ``reliable_first_seen`` flag controls whether the source's
first/last_seen claims land on the ``SOURCED_FROM`` edge. ``False``
for sources whose first_seen field means something other than "first
observed in the wild" (OTX pulse-publish-date, MISP pipeline
metadata).

### 2. Have the collector emit `item["first_seen"]` (and `item["last_seen"]` if available)

In your new `collectors/<name>_collector.py`, populate the source-truthful timestamps directly from upstream:

```python
processed.append({
    "type": "indicator",  # or vulnerability, malware, etc.
    "value": <value>,
    "tag": "your_source_tag",
    "source": ["your_source_tag"],
    # PR (S5): source-truthful timestamps. NULL is honest — do NOT
    # fall back to wall-clock NOW. The source-truthful extractor will
    # return None for missing values, and the SOURCED_FROM edge MIN/MAX
    # CASE preserves any prior value.
    "first_seen": upstream_data.get("first_reported_at") or None,
    "last_seen":  upstream_data.get("last_reported_at")  or None,
    # ...
})
```

### 3. Verify MISPWriter passthrough fires for your entity type

The `_apply_source_truthful_timestamps` helper in `src/collectors/misp_writer.py` is called from all 7 `create_*_attribute` methods (indicator, vulnerability, malware, actor, technique, tactic, tool) AS THE LAST STATEMENT before `return attribute`. If you add a NEW entity type, you must add the helper call to its `create_*_attribute` method too — the bugbot fix in commit `9a414ac` had to do exactly this for 5 entity types after they were missed. The helper uses `coerce_iso` to accept int epochs, datetime objects, and date-only strings.

### 4. Add Layer-2 META JSON parser if your source ships structured metadata

If your source ships a structured-metadata JSON blob (like NVD_META, TF_META, CISA_META) that needs to round-trip through the MISP attribute comment field, add a Layer-2 fallback branch in `src/source_truthful_timestamps.py::extract_source_truthful_timestamps`. Most sources only need Layer-1 (MISP-native attribute fields).

### 5. Update `tests/test_source_reported_timestamps.py`

Add your tag to the static enumeration in `test_collector_emitted_tags_match_allowlist` so the test catches future tag drift.

### Verification

After adding a new source, run:

```bash
.venv/bin/python -m pytest tests/test_source_reported_timestamps.py -v
```

The full suite should pass. If any test fails, the new source isn't wired through correctly — the assertion message names the exact symbol you missed.

For an end-to-end smoke test:

```cypher
MATCH (n)-[r:SOURCED_FROM]->(:Source {source_id: "your_source_tag"})
RETURN n.uuid,
       r.source_reported_first_at,
       r.source_reported_last_at,
       r.imported_at,
       r.updated_at
LIMIT 10;
```

Should show populated source-reported timestamps if your upstream provides them.

---

_Last updated: 2026-04-26 — PR-N33 docs audit: removed all 11 occurrences of the dead `last_updated` key from per-collector example dicts (the doc itself says at L71 "PR-M2 removed `last_updated` from collector emit"; the example dicts were stale and contradicted the rule). Replaced with explanatory comments referencing PR-M2. Prior: 2026-04-18 chip 5a refactor._
