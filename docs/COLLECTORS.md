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
7. [VirusTotal](#6-virustotal-two-modules)
8. [Finance Feed Collector](#7-finance-feed-collector)
9. [Global Feed Collector](#8-global-feed-collector)
10. [Healthcare Feed Collector](#9-healthcare-feed-collector)
11. [Energy Feed Collector](#10-energy-feed-collector)
12. [MISP Collector](#11-misp-collector)

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
| `first_seen` | string | ISO timestamp |
| `last_updated` | string | ISO timestamp |

**Note:** The `zone` property is always an array. The old `zones` property has been removed.

---

## 1. OTX Collector

**File:** `src/collectors/otx_collector.py`

### What It Does
Collects threat intelligence pulses from AlienVault OTX, including:
- Indicators (IPs, domains, hashes, URLs) with per-indicator description
- Malware families with ATT&CK technique IDs (`uses_techniques`)
- CVE references (all CVEs per pulse, no cap)
- **Pulse metadata:** `attack_ids` (MITRE ATT&CK), `industries` (authoritative sector classification), `targeted_countries`, `tags`, `references`, `author_name`, `adversary`, `TLP`
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
    'last_updated': '2024-01-15T12:00:00Z',
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
    'uses_techniques': ['T1059', 'T1071'],  # ATT&CK from pulse attack_ids
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
    'last_updated': '2024-01-15T12:00:00Z',
    'confidence_score': 0.5,
    'severity': 'UNKNOWN',
    'cvss_score': 0.0,
    'attack_vector': 'NETWORK',
}

# Threat Actor (auto-extracted from pulse adversary field)
{
    'type': 'actor',
    'name': 'TA542',
    'description': 'Emotet distribution group...',
    'zone': ['finance'],
    'tag': 'alienvault_otx',
    'sources': ['alienvault_otx'],
    'confidence_score': 0.5,
    'uses_techniques': ['T1059', 'T1071'],
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
    'last_updated': '2024-01-15T00:00:00Z',
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
    'last_updated': '2024-01-15T12:00:00Z',
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

## 6. VirusTotal (two modules)

Airflow **`edgeguard_medium_freq`** runs **`VTCollector`** from **`src/collectors/vt_collector.py`** (`run_vt_collection`). The file `dags/edgeguard_pipeline.py` also defines **`run_virustotal_enrichment_collection`** using **`VirusTotalCollector`**, but that callable is **not wired to a DAG** in the default repository layout — add a `PythonOperator` if you want it on a schedule. **`VIRUSTOTAL_API_KEY`** is **optional** for Airflow: if unset, whitespace-only, or a YAML template value (`YOUR_VT_API_KEY`, `YOUR_VIRUSTOTAL_API_KEY_HERE`), the task **succeeds** with **`skipped: true`** and skip metrics (see **`docs/AIRFLOW_DAGS.md`**).


### 6a. `virustotal_collector.py` (`VirusTotalCollector`)

**File:** `src/collectors/virustotal_collector.py`

### What It Does
Collects threat intelligence from VirusTotal, including:
- File hash analysis
- Domain reputation
- IP reputation
- Real-time and enrichment queries

### Source
- **URL:** `https://www.virustotal.com/api/v3`
- **API Key:** Optional for scheduled Airflow runs (missing / placeholder → `skipped`; required for real VT API data)
- **Rate Limits:** 4 requests/min, 500/day (free tier)

### Zone Detection
```python
def _detect_zones_from_names(self, attrs):
    """Detect ALL sectors from file names/paths."""
    names = str(attrs.get('meaningful_name', '')) + str(attrs.get('names', ''))
    return detect_zones_from_text(names)
```

### Example Output

```python
# Hash Indicator (from file collection)
{
    'indicator_type': 'hash',
    'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'zone': ['finance', 'healthcare'],  # Array of all matching zones
    'tag': 'virustotal',
    'sources': ['virustotal'],
    'first_seen': '2024-01-01T00:00:00Z',
    'last_updated': '2024-01-15T12:00:00Z',
    'confidence_score': 0.85  # Based on malicious scan count
}

# Domain Enrichment (from query_domain)
{
    'indicator_type': 'domain',
    'value': 'evil-bank-phish.com',
    'zone': ['global'],  # Array of all matching zones
    'tag': 'virustotal',
    'sources': ['virustotal'],
    'last_updated': '2024-01-15T12:00:00Z',
    'confidence_score': 0.95,
    'vt_reputation': 0,
    'vt_last_analysis_stats': {'malicious': 65, 'suspicious': 5, 'harmless': 0}
}
```

### 6b. `vt_collector.py` (`VTCollector`)

**File:** `src/collectors/vt_collector.py`  
**DAG:** `edgeguard_medium_freq` — task id `collect_virustotal` → `run_vt_collection`.  
Pulls VirusTotal v3 intelligence and normalises items for `MISPWriter` (see class docstring for rate-limit notes).

---

## 7. Finance Feed Collector

**File:** `src/collectors/finance_feed_collector.py`

### What It Does
Collects finance-specific threat feeds from abuse.ch, including:
- **Feodo Tracker:** Banking trojan C&C server IPs
- **SSL Blacklist:** Malicious SSL certificate fingerprints

### Sources
- **Feodo:** `https://feodotracker.abuse.ch/downloads/ipblocklist.csv`
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
    'last_updated': '2024-01-15T12:00:00Z',
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
    'last_updated': '2024-01-15T12:00:00Z',
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
- **CyberCure:** IP, URL, and hash feeds

### Configuration
- **ThreatFox** requires **`THREATFOX_API_KEY`** in the same environment as the collector (Airflow worker / `.env`). Get a free key from [auth.abuse.ch](https://auth.abuse.ch/). Without it, the task **skips** or returns **401 Unauthorized** if the API is called without credentials.

### Sources
- **ThreatFox:** `https://threatfox-api.abuse.ch/api/v1/`
- **URLhaus:** `https://urlhaus.abuse.ch/downloads/csv_recent/`
- **CyberCure:**
  - IPs: `https://api.cybercure.ai/feed/get_ips?type=csv`
  - URLs: `https://api.cybercure.ai/feed/get_url?type=csv`
  - Hashes: `https://api.cybercure.ai/feed/get_hash?type=csv`

### Zone Detection

```python
def get_zones_from_malware(malware_name):
    """Determine ALL zones based on malware family name."""
    return detect_zones_from_text(malware_name or "")

# ThreatFox uses malware family
zones = get_zones_from_malware(malware)

# URLhaus uses threat tags
zones = get_zones_from_malware(threat) or get_zones_from_malware(tags)

# CyberCure defaults to global
zones = ['global']
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
    'last_updated': '2024-01-15T12:00:00Z',
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
    'last_updated': '2024-01-15T12:00:00Z',
    'confidence_score': 0.6,
    'threat_type': 'malware_download',
    'tags': 'exe,windows'
}

# CyberCure Indicator
{
    'indicator_type': 'ipv4',
    'value': '192.0.2.100',
    'zone': ['global'],  # Array of all matching zones
    'tag': 'cybercure',
    'sources': ['cybercure'],
    'first_seen': '2024-01-15T12:00:00Z',
    'last_updated': '2024-01-15T12:00:00Z',
    'confidence_score': 0.5
}
```

---

## 9. Healthcare Feed Collector

**File:** `src/collectors/healthcare_feed_collector.py`

### What It Does
Placeholder for healthcare-specific threat feed collection.

### Future Implementation
- HC3 (HHS Cybersecurity) alerts integration
- FDA medical device vulnerability feeds
- H-ISAC threat feeds (requires membership)
- Healthcare-targeting ransomware tracking

### Current State
Returns empty list until actual feeds are implemented.

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

### Future Implementation
- E-ISAC threat feeds (requires membership)
- CISA ICS-CERT energy sector advisories
- OT/ICS vulnerability databases (Claroty, Dragos, Mandiant)
- Energy-targeting APT tracking (Industroyer, TRITON, Havex)

### Current State
Returns empty list until actual feeds are implemented.

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
    'CyberCure': 'cybercure',
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

## Collector Summary Table

| Collector | Sources | Status | Zone Detection |
|-----------|---------|--------|----------------|
| OTX | AlienVault OTX | ✅ Active | `detect_sectors()` → list |
| NVD | NVD | ✅ Active | `detect_sectors()` → `detect_zones_from_item` + CPE flattening → list |
| CISA | CISA KEV | ✅ Active | `detect_zones_from_text()` → list |
| MITRE | MITRE ATT&CK | ✅ Active | `detect_zones_from_text()` → list |
| AbuseIPDB | AbuseIPDB API | ✅ Active | See `AbuseIPDBCollector` |
| VirusTotal | VirusTotal API | ✅ Active | `VTCollector` (`vt_collector.py`); `VirusTotalCollector` (`virustotal_collector.py`) |
| Finance Feed | Feodo, SSLBL | ✅ Active | `detect_zones_from_text()` → list |
| Global Feed | URLhaus, CyberCure, ThreatFox | ✅ Active | `detect_zones_from_text()` → list |
| Healthcare | HC3, FDA, H-ISAC | ⏳ Placeholder | - |
| Energy | E-ISAC, ICS-CERT | ⏳ Placeholder | - |
| MISP | Local MISP | ✅ Active | `detect_sectors()` → list |

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

When adding a 10th+ collector that has a **canonical first-reported / last-reported timestamp** that should flow into the source-truthful timestamp pipeline (PR S5, 2026-04 — see `docs/KNOWLEDGE_GRAPH.md#sourced_from-edge-schema`), follow this 5-step checklist:

### 1. Add to `_RELIABLE_FIRST_SEEN_SOURCES` allowlist

In `src/source_truthful_timestamps.py`, add your source's tag(s) to the `_RELIABLE_FIRST_SEEN_SOURCES` frozenset. Include both the canonical name AND any aliases (e.g. `"feodo"` + `"feodo_tracker"`) — the allowlist must accept whatever string the collector writes to `item["tag"]`.

### 2. Add to `SOURCE_MAPPING` in `run_misp_to_neo4j.py`

In `src/run_misp_to_neo4j.py::SOURCE_MAPPING`, map the human label (e.g. `"My-New-Source"`) to the canonical tag. Tag MUST match what the collector emits; the static test `test_collector_emitted_tags_match_allowlist` will fail otherwise.

### 3. Add to `SOURCE_TAGS` in `config.py`

In `src/config.py::SOURCE_TAGS`, add the human-readable label → tag mapping. This is what MISPWriter uses to tag attributes and what `extract_source_from_tags` reads back.

### 4. Have the collector emit `item["first_seen"]` (and `item["last_seen"]` if available)

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

The `_apply_source_truthful_timestamps` helper in `src/collectors/misp_writer.py` calls `coerce_iso` to handle int epochs, datetime objects, and date-only strings — so any of these formats are accepted.

### 5. Update `tests/test_first_seen_at_source.py`

Add your tag to the static enumeration in `test_collector_emitted_tags_match_allowlist` so the test catches future tag drift.

### Verification

After adding a new source, run:

```bash
.venv/bin/python -m pytest tests/test_first_seen_at_source.py -v
```

All 38 tests should pass. If any fail, the new source isn't wired through correctly.

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

_Last updated: 2026-04-18_
