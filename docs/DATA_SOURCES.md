# EdgeGuard Data Sources - Complete Reference

**Last Updated:** 2026-03-21  
**Total Sources:** 13 (11 active + 2 placeholders) — canonical inventory; cross-check `src/collectors/` and `docs/DOCUMENTATION_AUDIT.md`.

**Counts in the overview table** (`~8,000`, `TBD`, etc.) are **illustrative** snapshots, not continuously validated — use your MISP/Neo4j deployment for real numbers.

---

## Source Overview

| # | Source | Items | Sector Classification | Purpose | Status |
|---|--------|-------|---------------------|---------|--------|
| 1 | AlienVault OTX | ~8,000 | ✅ Auto-tagged | Primary IOC source | ✅ Active |
| 2 | NVD | ~500 | ✅ Auto-tagged | CVE database | ✅ Active |
| 3 | CISA KEV | ~500 | ✅ Auto-tagged | Known exploits | ✅ Active |
| 4 | MITRE ATT&CK | ~300 | N/A | TTPs & relationships | ✅ Active |
| 5 | VirusTotal | TBD | ✅ Auto-tagged | File/URL analysis | ✅ Active |
| 6 | ThreatFox | TBD | ✅ Auto-tagged | Malware IOCs | ✅ Active |
| 7 | AbuseIPDB | TBD | ✅ Auto-tagged | IP reputation | ✅ Active |
| 8 | URLhaus | ~500 | ✅ Auto-tagged | Malware URLs | ✅ Active |
| 9 | Feodo Tracker | TBD | ✅ Finance | Banking trojan C&C | ✅ Active |
| 10 | SSL Blacklist | ~500 | ✅ Finance | Malware SSL certs | ✅ Active |
| 11 | CyberCure | TBD | ✅ Auto-tagged | Automated threats | ✅ Active |
| 12 | Energy Sector | - | - | Placeholder | ❌ Placeholder |
| 13 | Healthcare Sector | - | - | Placeholder | ❌ Placeholder |

**Note:** Energy and Healthcare collectors are placeholders requiring ISAC membership (ENTSO-E, H-ISAC/EHFC).

---

## Source Details

### 1. AlienVault OTX
**Items:** 6,953 | **Zone (Sector) Distribution:** Healthcare 62%, Energy 30%, Global 6%, Finance 2%

| Attribute | Value |
|-----------|-------|
| URL | https://otx.alienvault.com/api/v1/pulses/subscribed |
| Format | JSON API |
| Auth | API Key required |
| Update | On-demand (50 pulses per run) |
| Classification | ✅ Keyword-based on pulse tags/name |

**What we get:**
- IPs, domains, URLs, hashes
- Malware family names
- CVE references
- Pulse descriptions

**How classified:**
- Pulse tags searched for keywords (hospital, scada, bank, etc.)
- Word boundary matching prevents false positives

---

### 2. SSL Blacklist (abuse.ch)
**Items:** 500 | **Zone Distribution:** Global 72%, Finance 28%

| Attribute | Value |
|-----------|-------|
| URL | https://sslbl.abuse.ch/blacklist/sslblacklist.csv |
| Format | CSV |
| Auth | None (public) |
| Update | Daily |
| Classification | ✅ Malware family → Finance mapping |

**What we get:**
- SSL certificate SHA1 fingerprints
- Malware family name (Vidar, RedLine, etc.)
- Listing reason

**How classified:**
- Malware family names mapped to finance sector
- e.g., "Vidar C&C" → finance

---

### 3. URLhaus
**Items:** 491 | **Zone Distribution:** Global 100%

| Attribute | Value |
|-----------|-------|
| URL | https://urlhaus.abuse.ch/downloads/csv_recent/ |
| Format | CSV |
| Auth | None (public) |
| Update | Daily |
| Classification | ✅ `detect_zones_from_text()` on threat names and tags |

**What we get:**
- Malware distribution URLs
- Threat type (malware_download, etc.)
- Tags

**How classified:**
- `detect_zones_from_text()` is called on threat names and tags to determine zone

---

### 4. CISA KEV (Known Exploited Vulnerabilities)
**Items:** 500 | **Zone Distribution:** Global 46%, Healthcare 29%, Energy 16%, Finance 10%

| Attribute | Value |
|-----------|-------|
| URL | https://www.cisa.gov/known-exploited-vulnerabilities-catalog/json |
| Format | JSON |
| Auth | None (public) |
| Update | Daily |
| Classification | ⚠️ CVE descriptions searched |

**What we get:**
- CVE IDs
- Vendor/product names
- Description
- Date added to KEV

**How classified:**
- Description text searched for sector keywords

---

### 5. MITRE ATT&CK
**Items:** 500 | **Zone:** N/A (techniques/actors)

| Attribute | Value |
|-----------|-------|
| URL | https://attack.mitre.org/resources/working-attack-files/ |
| Format | STIX 2.1 JSON |
| Auth | None (public) |
| Update | Periodic |
| Classification | ❌ N/A - provides relationships |

**What we get:**
- Techniques (300)
- Threat Actors (100)
- Malware (100)
- **Relationships** (1,459 USES links)

**How classified:**
- N/A - these are TTP entities, not sector-specific

---

### 6. NVD (National Vulnerability Database)
**Items:** 100 | **Zone Distribution:** Global 76%, Finance 10%, Energy 7%, Healthcare 7%

| Attribute | Value |
|-----------|-------|
| URL | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| Format | JSON API |
| Auth | API Key (free) |
| Update | On-demand |
| Classification | ⚠️ Description searched |

**API constraints (collector behavior):** NVD CVE 2.0 requires **`pubStartDate` and `pubEndDate` together** when filtering by published date. Each request is limited to **at most 120 consecutive days**. The collector anchors the window on **now (UTC)** and applies sector/baseline lookback; if the implied range is longer than 120 days, **normal (incremental) fetch** clamps to the last **120 days** of that lookback, then **pages** with **`resultsPerPage` ≤ 2000** and **`startIndex`** from the newest slice of the result set (see [CVE API](https://nvd.nist.gov/developers/vulnerabilities), [workflows](https://nvd.nist.gov/developers/api-workflows)). **Baseline** mode **splits** `[now − baseline_days, now]` into multiple ≤120-day windows. **NIST attribution:** This product uses data from the NVD API but is not endorsed or certified by the NVD.

**What we get:**
- CVE IDs
- Descriptions
- CVSS scores (including v4 when present)
- Attack vectors

---

### 7. MISP
**Items:** 4 | **Zone:** Healthcare 100%

| Attribute | Value |
|-----------|-------|
| URL | https://localhost:8443/api/events |
| Format | JSON API |
| Auth | API Key |
| Update | Manual |
| Classification | ✅ Keyword-based |

**Status:** Minimal data - only test event

---

### 8. Feodo Tracker
**Items:** 3 | **Zone:** Finance 100%

| Attribute | Value |
|-----------|-------|
| URL | https://feodotracker.abuse.ch/downloads/ipblocklist.csv |
| Format | CSV |
| Auth | None (public) |
| Update | Daily |
| Classification | ✅ Hardcoded as Finance |

**What we get:**
- C&C server IPs
- Malware family (Emotet, QakBot, etc.)
- Status (online/offline)

---

## Classification Methods

### Method 1: Keyword Matching
Used for: OTX, MISP, CISA KEV, NVD

```python
# Example: "hospital" → healthcare
# Word boundary prevents "his" matching in "hospital"
"hospital patient data" → healthcare ✓
"hospital information system" → healthcare ✓
```

### Method 2: Malware Family Mapping
Used for: Feodo, SSL Blacklist

```python
MALWARE_FAMILIES = {
    'finance': ['emotet', 'dridex', 'qakbot', 'vidar', 'redline', ...],
    'healthcare': ['ransomware', 'lockbit', ...],
    'energy': ['industroyer', 'triton', ...]
}
```

### Method 3: Hardcoded
Used for: Feodo Tracker (always finance)

---

## Issues & Fixes Needed

| Issue | Impact | Fix |
|-------|--------|-----|
| ~~URLhaus not classified~~ | ~~491 items → global~~ | Fixed — `detect_zones_from_text()` applied on threat names/tags |
| Finance still low (4%) | Demo imbalance | Get ThreatFox API, FS-ISAC |
| MITRE has no zone | 500 items unclassified | N/A - TTP data |
| MISP has only 4 items | Minimal data | Add real events or remove |

---

## For Prep Meeting Discussion

1. **Architecture:** MISP vs Direct Collectors - which approach?
2. **Finance gap:** Public feeds limited - discuss FS-ISAC membership
3. **URLhaus classification:** Should we parse tags for classification?
4. **Data quality:** How to validate/verify IOCs?


---

_Last updated: 2026-03-28_
