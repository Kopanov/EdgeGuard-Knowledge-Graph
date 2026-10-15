# EdgeGuard Data Sources - Complete Reference

**Last Updated:** 2026-10-15 (FIRST EPSS row 15 added; CISA's SSVC decision points come with the NVD records, row 2; measured volumes of the first 730-day baseline; MalwareBazaar row 14 added 2026-10-12)  
**Total Sources:** 15 (10 active + 2 placeholders + 2 flag-guarded, off by default + 1 post-sync enrichment feed, on by default) — canonical inventory; cross-check `src/collectors/` and `docs/DOCUMENTATION_AUDIT.md`.

**Counts in the overview table** (`~8,000`, `TBD`, etc.) are **illustrative** snapshots, not continuously validated — use your MISP/Neo4j deployment for real numbers.

---

## Source Overview

| # | Source | Items | Sector Classification | Purpose | Status |
|---|--------|-------|---------------------|---------|--------|
| 1 | AlienVault OTX | ~8,000 | ✅ Auto-tagged | Primary IOC source | ✅ Active |
| 2 | NVD | ~500 | ✅ Auto-tagged | CVE database; carries CISA's SSVC decision points (2026-10) | ✅ Active |
| 3 | CISA KEV | ~500 | ✅ Auto-tagged | Known exploits | ✅ Active |
| 4 | MITRE ATT&CK | ~300 | N/A | TTPs & relationships | ✅ Active |
| 5 | VirusTotal | grows by ≤ 400 lookups/day (free-tier budget) | ✅ Auto-tagged | Enrichment of hashes already in MISP (lookups, not a feed) | ✅ Active |
| 6 | ThreatFox | TBD | ✅ Auto-tagged | Malware IOCs | ✅ Active |
| 7 | AbuseIPDB | TBD | ✅ Auto-tagged | IP reputation | ✅ Active |
| 8 | URLhaus | ~500 | ✅ Auto-tagged | Malware URLs | ✅ Active |
| 9 | Feodo Tracker | 7,607 servers on a baseline (complete history; feed not updated by abuse.ch since 2026-03-04) | ✅ Auto-tagged (keyword detector; Global in practice) | Botnet C&C IPs with malware family | ✅ Active |
| 10 | SSL Blacklist | ~11,000 (10,964 on 2026-10-12) | ✅ Auto-tagged (keyword detector; Global in practice) | Malware SSL certs | ✅ Active |
| 11 | Energy Sector | - | - | Placeholder | ❌ Placeholder |
| 12 | Healthcare Sector | - | - | Placeholder | ❌ Placeholder |
| 13 | CISA ICS Advisories | ~900 advisories / 730 days (1–7 CVEs each) | ✅ **Source-asserted** (CISA sector note → Energy / Healthcare / Finance) | ICS-CERT advisories, CVE ↔ critical-infrastructure sector | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, default off) — added 2026-10 |
| 14 | MalwareBazaar | ~1,000 samples per export (last 48 h; 1,027 on 2026-10-12, 762 with a family label), ≤ 500 pushed per run | ✅ Auto-tagged (`detect_zones_from_text()` on the family label) | Malware sample hashes (sha256) with the family label → `INDICATES` edges to `Malware` nodes | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, default off) — added 2026-10 |
| 15 | FIRST EPSS | ~385,000 scores / day (only existing CVEs updated) | N/A | Exploit-prediction score and percentile per CVE; the one source written to Neo4j without MISP (§ 8b) | 🚩 Post-sync enrichment (`EDGEGUARD_ENABLE_EPSS`, default on) — added 2026-10 |

**Note:** Energy and Healthcare collectors are placeholders. Member-only ISAC feeds (EE-ISAC, Health-ISAC, HC3) are not planned and no membership is budgeted (decision 2026-10). CISA ICS Advisories (row 13) is a real, flag-guarded collector that covers the ICS-CERT part of the energy/healthcare picture without any membership.

**Measured on the hosted instance after the first 730-day baseline (13–14 October 2026), MISP attributes per source:** AlienVault OTX 149,270; NVD 139,862; URLhaus 34,003; SSL Blacklist 10,967; AbuseIPDB 10,000; Feodo Tracker 7,607; ThreatFox 7,398 (the API serves at most 7 days); MITRE ATT&CK 1,892; CISA KEV 547; 361,546 in total. VirusTotal, MalwareBazaar and CISA ICS were not part of that run. The Items column above lists the earlier per-run estimates.

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
- SSL certificate SHA1 fingerprints, stored as MISP `x509-fingerprint-sha1` attributes and `x509-fingerprint-sha1` Indicators (2026-10; they were typed as file `sha1` hashes before)
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
- Known ransomware campaign use (`known_ransomware_use` on the `CVE` node; 2026-10: no CVSS score is derived from it — the catalogue carries none, and the node's score comes from its CVSS sub-nodes)

**How classified:**
- Description text searched for sector keywords

**Baseline scope (2026-10):** a baseline takes the **whole catalogue** (about 1,500 entries), not only the entries added within the baseline window: a KEV entry is a CVE known to be exploited, so its age is no reason to leave it out (Log4Shell, added 2021-12, fell outside a 730-day window). `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false` restores the `dateAdded` window. Incremental runs keep their `EDGEGUARD_CISA_INCREMENTAL_DAYS` window.

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

**API constraints (collector behavior):** NVD CVE 2.0 requires **`pubStartDate` and `pubEndDate` together** when filtering by published date. Each request is limited to **at most 120 consecutive days**. The collector anchors the window on **now (UTC)**. **Incremental** runs (2026-10) read every CVE modified since a stored cursor (**`lastModStartDate` / `lastModEndDate`**, read in time slices of at most 120 days, one answer of up to 2,000 records each; without a cursor the last `EDGEGUARD_NVD_INCREMENTAL_DAYS` days, default 14). They add the CVEs MISP does not hold yet when these lie in the baseline's scope (published within `EDGEGUARD_BASELINE_DAYS`, on KEV, or named in `EDGEGUARD_NVD_EXTRA_CVE_IDS`), and they edit the MISP attribute of a CVE MISP holds when NVD's data for it changed. NVD's later analysis (CVSS, CPE, CWE, description, KEV fields) and rejections reach the graph, including data NVD withdrew (list values on CVE nodes whose only source is NVD, and CVSS sub-nodes only NVD asserted). Each request reads one time slice, so records NVD changes during the read are not skipped. A run makes at most `EDGEGUARD_NVD_MAX_PER_RUN` (5,000) MISP writes ([COLLECTORS.md § 2](COLLECTORS.md)) (see [CVE API](https://nvd.nist.gov/developers/vulnerabilities), [workflows](https://nvd.nist.gov/developers/api-workflows)). **Baseline** mode **splits** `[now − baseline_days, now]` into multiple ≤120-day publication windows. No age filter is applied after the fetch (2026-10; the former sector time-range check had not fired on NVD's zone-less timestamps since v2026.3.28 and was removed). **Known-exploited CVEs outside the windows (2026-10):** after the windows, a baseline also fetches the NVD record of every CVE on CISA's KEV list (`hasKev`, about 1,700 records in one page; `EDGEGUARD_NVD_BASELINE_KEV_SWEEP`, default on) and of the CVE ids listed in `EDGEGUARD_NVD_EXTRA_CVE_IDS` (one request each), whatever their publication date. A failed supplementary request is logged and skipped, never fails the baseline. **NIST attribution:** This product uses data from the NVD API but is not endorsed or certified by the NVD.

**What we get:**
- CVE IDs
- Descriptions
- CVSS scores (including v4 when present); 2026-10: a CVE's `cvss_score` / `severity` come from its first CVSS in the order v3.1 → v3.0 → v2 → v4.0 (`cvss_version` names it), and a CVE without any CVSS has no score and severity `UNKNOWN`
- Attack vectors
- NVD's record status (`status`, `["active"]` or `["rejected"]`, 2026-10)
- CISA's SSVC decision points (2026-10), which NVD relays from the CISA-ADP container of the CVE record (`metrics.ssvcV203`; CISA's Vulnrichment program): `ssvc_exploitation` (`none` / `poc` / `active`), `ssvc_automatable` (`yes` / `no`), `ssvc_technical_impact` (`partial` / `total`), with `ssvc_version` and `ssvc_timestamp` (the time of CISA's decision). They travel through MISP in `NVD_META` like the rest of the record and are set on the `CVE` node from NVD's record only; a decision CISA withdraws is removed. Compared on 2026-10-15 with the values read from CISA's Vulnrichment repository for 24 CVEs (4 records of `tests/fixtures/nvd_incremental_2026_10_14.json` and a random sample of 20 CVEs of the hosted graph): NVD had a decision for every one, the decision points were the same on all 24, and the timestamp on 22 (on the other 2, NVD gives the day only)

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
**Items:** complete history (baseline): 7,980 rows merged to 7,607 servers, last seen online mostly in 2021–2023; 30-day list: 5 rows. Both downloads were last updated by abuse.ch on 2026-03-04 (checked 2026-10-12), so daily runs add nothing at present | **Zone:** Global (keyword detector on the family name; no family is hard-coded to a sector)

| Attribute | Value |
|-----------|-------|
| URL | `ipblocklist.csv` (C2s active in the last 30 days — regular runs); `ipblocklist_aggressive.csv` (complete history — baseline runs) |
| Format | CSV |
| Auth | None (public) |
| Update | Daily |
| Classification | Keyword detector on the malware family name (Global in practice) |

**What we get:**
- C&C server IPs
- Malware family (QakBot, BumbleBee, TrickBot, Emotet, Dridex, Pikabot) — carried to MISP and Neo4j, where it links the indicator to the `Malware` node (`INDICATES`)
- Last-online date as `Indicator.last_online` and as the source-reported last-seen time; ports and status kept with the source record. Servers not seen online in the last 30 days are published at low confidence with the MISP detection flag cleared (see docs/COLLECTORS.md § 7)

---

### 8b. FIRST EPSS (Exploit Prediction Scoring System) — post-sync enrichment, added 2026-10
**Items:** ~385,000 rows per daily file; only `CVE` nodes already in the graph are updated | **Zone:** n/a (CVE properties, not new nodes)

| Attribute | Value |
|-----------|-------|
| URL | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (the address FIRST documents; it redirects to the day's file; override `EPSS_URL`) — per `src/cve_feed_enrichment.py` |
| Format | gzip CSV, first line `#model_version:...,score_date:...`, header `cve,epss,percentile` (~2.7 MB) |
| Auth | None (public) |
| Update | FIRST publishes a file every day. The enrichment job `enrich_cve_epss` reads the current file after every Neo4j sync (`edgeguard_neo4j_sync`, every 72 hours by default, `NEO4J_SYNC_INTERVAL`) and after the baseline, when `EDGEGUARD_ENABLE_EPSS=true` (default). The download is bounded by `EPSS_MAX_BYTES` (64 MiB) and `EPSS_DOWNLOAD_DEADLINE_SEC` (300 s) |
| Classification | n/a |

**What we get:**
- `CVE.epss_score` (probability of exploitation in the next 30 days, 0-1) and `CVE.epss_percentile`
- `CVE.epss_score_date` and `CVE.epss_model_version` (from the file's first line; a file without a score date is not used), `CVE.epss_updated_at` (the time of the write)

**How written:** only on `CVE` nodes that exist (`MATCH`, never `MERGE`); a node a partner created gets the shared-database marker `edgeguard_enriched` ([RESILMESH_INTEROPERABILITY.md § 3.4](RESILMESH_INTEROPERABILITY.md)). Once the whole file is written, a CVE whose EPSS is from an earlier file has left the feed (NVD rejected it, for example) and loses its EPSS properties; a run that matched fewer CVE nodes than half of those already scored does not clear, so neither a short file nor ids that no longer match (a changed format) wipe the scores. A feed failure (HTTP error, timeout, deadline, size cap, bad payload) is logged at ERROR and the job returns `skipped`: it never fails the DAG task. A database failure raises, before anything is cleared; the next run writes the whole file again.

**Why not through MISP:** EPSS is the one source EdgeGuard writes straight to Neo4j. It is a new score for every published CVE every day (about 385,000 rows), a measurement of the CVE rather than threat intelligence about it, and MISP would only hold a copy of it. No node or relationship is created, so there is no relationship provenance to record; the score date and model version on every scored node say which file the value came from.

**How classified:** n/a — no sector logic; properties only.

**Terms:** FIRST publishes the scores daily, free of charge and without registration; its EPSS pages state no licence or attribution requirement (checked 2026-10-15). The scores are generated by Empirical Security for FIRST.

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

### Method 2: Malware family through graph relationships (not keywords)
Used for: ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar

No malware family is mapped to a sector by name, and no source is hard-coded to a sector: the keyword list deliberately excludes family names. A family reaches a sector through the graph (`Indicator -INDICATES-> Malware`, and the sectors of the campaigns and actors that use that malware). Feodo Tracker and SSL Blacklist rows are therefore tagged Global at collection time (measured 2026-10-12: all 7,980 Feodo rows and all 10,964 SSL Blacklist rows).

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

_Last updated: 2026-10-15 — FIRST EPSS (row 15, § 8b: cadence, writes and clearing, why it bypasses MISP, terms, the address FIRST documents); CISA's SSVC decision points with the NVD records (row 2, § 6). Same day: SSL Blacklist fingerprints are stored as `x509-fingerprint-sha1` (TLS certificate fingerprints), not as file hashes; CISA KEV: ransomware use without a derived score; NVD: CVE score rule and record status. Prior: 2026-10-14 — KEV whole catalogue in baseline mode and the NVD KEV sweep / `EDGEGUARD_NVD_EXTRA_CVE_IDS`; the sector time-range filter removed; NVD incremental runs by lastModified cursor. Prior: 2026-04-26 — PR-N33 docs audit: corrected wrong CISA KEV URL (was a non-existent human page; actual is `feeds/known_exploited_vulnerabilities.json`); corrected MITRE ATT&CK URL (was a non-existent human page; actual is the legacy `mitre/cti` raw GitHub URL the collector hits at HEAD). Prior: 2026-03-28._
