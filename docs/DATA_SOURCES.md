# EdgeGuard Data Sources - Complete Reference

**Last Updated:** 2026-10-12 (MalwareBazaar row 14 added)  
**Total Sources:** 14 (10 active + 2 placeholders + 2 flag-guarded, off by default) — canonical inventory; cross-check `src/collectors/` and `docs/DOCUMENTATION_AUDIT.md`.

**Counts in the overview table** (`~8,000`, `TBD`, etc.) are **illustrative** snapshots, not continuously validated — use your MISP/Neo4j deployment for real numbers.

---

## Source Overview

| # | Source | Items | Sector Classification | Purpose | Status |
|---|--------|-------|---------------------|---------|--------|
| 1 | AlienVault OTX | ~8,000 | ✅ Auto-tagged | Primary IOC source | ✅ Active |
| 2 | NVD | ~500 | ✅ Auto-tagged | CVE database | ✅ Active |
| 3 | CISA KEV | ~500 | ✅ Auto-tagged | Known exploits | ✅ Active |
| 4 | MITRE ATT&CK | ~300 | N/A | TTPs & relationships | ✅ Active |
| 5 | VirusTotal | grows by ≤ 400 lookups/day (free-tier budget) | ✅ Auto-tagged | Enrichment of hashes already in MISP (lookups, not a feed) | ✅ Active |
| 6 | ThreatFox | TBD | ✅ Auto-tagged | Malware IOCs | ✅ Active |
| 7 | AbuseIPDB | TBD | ✅ Auto-tagged | IP reputation | ✅ Active |
| 8 | URLhaus | ~500 | ✅ Auto-tagged | Malware URLs | ✅ Active |
| 9 | Feodo Tracker | TBD | ✅ Finance | Banking trojan C&C | ✅ Active |
| 10 | SSL Blacklist | ~500 | ✅ Finance | Malware SSL certs | ✅ Active |
| 11 | Energy Sector | - | - | Placeholder | ❌ Placeholder |
| 12 | Healthcare Sector | - | - | Placeholder | ❌ Placeholder |
| 13 | CISA ICS Advisories | ~900 advisories / 730 days (1–7 CVEs each) | ✅ **Source-asserted** (CISA sector note → Energy / Healthcare / Finance) | ICS-CERT advisories, CVE ↔ critical-infrastructure sector | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, default off) — added 2026-10 |
| 14 | MalwareBazaar | ~1,000 samples per export (last 48 h; 1,027 on 2026-10-12, 762 with a family label), ≤ 500 pushed per run | ✅ Auto-tagged (`detect_zones_from_text()` on the family label) | Malware sample hashes (sha256) with the family label → `INDICATES` edges to `Malware` nodes | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, default off) — added 2026-10 |

**Note:** Energy and Healthcare collectors are placeholders requiring ISAC membership (ENTSO-E, H-ISAC/EHFC). CISA ICS Advisories (row 13) is a real, flag-guarded collector that covers the ICS-CERT part of the energy/healthcare picture without any membership.

## Removed sources

| Source | Removed | Reason |
|--------|---------|--------|
| CyberCure | 2026-10 | The feed API (`api.cybercure.ai`) answered HTTP 520 on every endpoint as of 2026-10-12; the service offers no paid or authenticated tier to fall back to; the collector produced zero events on the production instance and skipped silently on every run. MISP attributes still tagged `source:CyberCure` are ingested by the sync under `source_id = misp`; each such tag name is logged once and counted in `edgeguard_misp_unmapped_source_tags_total`. |

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
| URL | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (per `src/collectors/cisa_collector.py:70`) |
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

### 4b. CISA ICS Advisories (CSAF 2.0) — flag-guarded, added 2026-10
**Items:** one `vulnerability` per (advisory, CVE); ~900 advisories on a 730-day baseline | **Zone:** source-asserted by CISA, not keyword-detected

| Attribute | Value |
|-----------|-------|
| URL | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`index.txt`, `changes.csv`, `<year>/<advisory>.json`) — per `src/collectors/cisa_ics_collector.py` |
| Format | CSAF 2.0 JSON, one file per advisory (`ICSA-*`, `ICSMA-*`) |
| Auth | None (public GitHub raw); TLP:WHITE |
| Update | Daily (`edgeguard_daily` → `collect_cisa_ics`), only when `EDGEGUARD_ENABLE_CISA_ICS=true` |
| Classification | ✅ Fixed table on the advisory's `"Critical infrastructure sectors"` note: `Energy → energy`, `Healthcare and Public Health → healthcare`, `Financial Services → finance`; anything else → `global` |

**What we get:**
- CVE IDs with CWE, CVSS v3.x score/vector (→ `CVSSv31`/`CVSSv30` sub-nodes), vulnerability summary
- Advisory id, title, cisa.gov URL, vendor and affected products
- `initial_release_date` / `current_release_date` as source-truthful `first_seen` / `last_seen`
- Raw CISA sector list (`ics_sectors`) in addition to the mapped zone

**How classified:**
- Sector names come from CISA's own note in the advisory; the keyword detector is not used

**Safety:** own circuit breaker + rate limiter, per-file failures counted and skipped, baseline sanity floor (`EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES`, default 50) raises a transient error → task skipped + alert rather than a thin dataset. See [COLLECTORS.md §12](COLLECTORS.md#12-cisa-ics-advisories-collector).

---

### 4c. MalwareBazaar (abuse.ch) — flag-guarded, added 2026-10
**Items:** one `sha256` indicator per sample; the recent export holds the samples of the last 48 hours (1,027 rows on 2026-10-12: 458 Mirai, 265 without a label) and at most `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500) are pushed per run | **Zone:** `detect_zones_from_text()` on the family label (`global` when the label is `n/a`)

| Attribute | Value |
|-----------|-------|
| URL | `https://bazaar.abuse.ch/export/csv/recent/` — per `src/collectors/global_feed_collector.py` (`MalwareBazaarCollector`). The full export (`/export/csv/full/`) is the complete history and is not used |
| Format | CSV with `#` comment lines; columns `first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh` |
| Auth | None required; a configured `THREATFOX_API_KEY` (the abuse.ch Auth-Key) is sent as `Auth-Key` |
| Update | Daily (`edgeguard_daily` → `collect_malwarebazaar`) and baseline tier 2, only when `EDGEGUARD_ENABLE_MALWAREBAZAAR=true`; both read the recent export, so the history builds up over the daily runs |
| Classification | ✅ `detect_zones_from_text()` on `signature` |
| Terms | Free of charge for commercial and non-commercial use (https://bazaar.abuse.ch/faq/#tos) |

**What we get:**
- sha256 (the indicator), md5 and sha1 of the sample
- Family label (`signature`, "n/a" when unknown) → `malware_family` → `Indicator → Malware` `INDICATES` edges (`match_type = malware_family`), the same path as the ThreatFox family
- File name, file type guess, MIME type, reporter, sample page URL
- `first_seen_utc` as source-truthful `first_seen` (tz-aware UTC)

**Selection:** labelled samples are kept before unlabelled ones, then the list is cut at the per-run cap (and at the regular collection limit when that is lower).

**Safety:** own circuit breaker + rate limiter; flag off → skipped status without an HTTP request; 401/403 → skipped (`malwarebazaar_auth_denied`); 429 after the Retry-After retries, 5xx and timeouts → transient error → task skipped + alert. See [COLLECTORS.md §13](COLLECTORS.md#13-malwarebazaar-collector).

---

### 5. MITRE ATT&CK
**Items:** 500 | **Zone:** N/A (techniques/actors)

| Attribute | Value |
|-----------|-------|
| URL | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` (per `src/collectors/mitre_collector.py`); with `EDGEGUARD_ENABLE_MITRE_ICS=true` (2026-10, default off) also `ics-attack/ics-attack.json` — ATT&CK for ICS (97 techniques T08xx, 12 tactics, 14 groups, 23 malware), items stamped `attack_domain: ics`, ICS fetch failure isolated from the Enterprise ingest |
| Format | STIX 2.1 JSON |
| Auth | None (public) |
| Update | Periodic |
| Classification | ❌ N/A - provides relationships |

**What we get:**
- Techniques (300)
- Threat Actors (100)
- Malware (100)
- **Relationships** — 1,459 TTP edges split into `EMPLOYS_TECHNIQUE` (Actor→Technique, attribution) and `IMPLEMENTS_TECHNIQUE` (Malware/Tool→Technique, capability). Prior to 2026-04 these were a single generic `USES` edge.

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
**Items:** 30-day list: a handful of active C2s; complete history (baseline): several thousand rows | **Zone:** Finance 100%

| Attribute | Value |
|-----------|-------|
| URL | `ipblocklist.csv` (C2s active in the last 30 days — regular runs); `ipblocklist_aggressive.csv` (complete history — baseline runs) |
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

_Last updated: 2026-04-26 — PR-N33 docs audit: corrected wrong CISA KEV URL (was a non-existent human page; actual is `feeds/known_exploited_vulnerabilities.json`); corrected MITRE ATT&CK URL (was a non-existent human page; actual is the legacy `mitre/cti` raw GitHub URL the collector hits at HEAD). Prior: 2026-03-28._
