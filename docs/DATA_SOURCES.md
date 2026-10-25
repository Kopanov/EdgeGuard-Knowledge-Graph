# EdgeGuard Data Sources - Complete Reference

**Total Sources:** 15 (10 active + 2 placeholders + 2 flag-guarded, off by default + 1 post-sync enrichment feed, on by default) — canonical inventory; cross-check `src/collectors/`.

**Counts in the overview table** (`~8,000`, `TBD`, etc.) are **illustrative** snapshots, not continuously validated — use your MISP/Neo4j deployment for real numbers.

---

## Source Overview

| # | Source | Items | Sector Classification | Purpose | Status |
|---|--------|-------|---------------------|---------|--------|
| 1 | AlienVault OTX | ~8,000 | ✅ Auto-tagged | Primary IOC source | ✅ Active |
| 2 | NVD | ~500 | ✅ Auto-tagged | CVE database; carries CISA's SSVC decision points | ✅ Active |
| 3 | CISA KEV | ~500 | ✅ Auto-tagged | Known exploits | ✅ Active |
| 4 | MITRE ATT&CK | ~300 | N/A | TTPs & relationships | ✅ Active |
| 5 | VirusTotal | grows by ≤ 400 lookups/day (free-tier budget) | ✅ Auto-tagged | Enrichment of hashes already in MISP (lookups, not a feed) | ✅ Active |
| 6 | ThreatFox | the IOCs of the last 7 days (7,398 on the 730-day baseline; about 1,100 new per day), ≤ 10,000 per run | ✅ Auto-tagged | Malware IOCs | ✅ Active |
| 7 | AbuseIPDB | the blacklist: at most one request per run of at most 10,000 addresses (the free plan's maximum per request; 10,000 on the 730-day baseline); 5 blacklist requests per UTC day on the free plan: an answer is reused for the rest of its UTC day, and a 429 fails the task ([COLLECTORS.md § 5](COLLECTORS.md#5-abuseipdb-collector)) | ✅ Auto-tagged | IP reputation | ✅ Active |
| 8 | URLhaus | the `recent.csv` export (about 63,000 URLs on 2026-10-24; about 1,130 new per day), ≤ 100,000 per run; abuse.ch Auth-Key required | ✅ Auto-tagged | Malware URLs | ✅ Active |
| 9 | Feodo Tracker | 7,607 servers on a baseline (complete history; abuse.ch last updated the feed on 2026-03-04), ≤ 15,000 per run | ✅ Auto-tagged (keyword detector; Global in practice) | Botnet C&C IPs with malware family | ✅ Active |
| 10 | SSL Blacklist | ~11,000 (10,964 on 2026-10-12), the whole list per run, ≤ 20,000 | ✅ Auto-tagged (keyword detector; Global in practice) | Malware SSL certs | ✅ Active |
| 11 | Energy Sector | - | - | Placeholder | ❌ Placeholder |
| 12 | Healthcare Sector | - | - | Placeholder | ❌ Placeholder |
| 13 | CISA ICS Advisories | ~900 advisories / 730 days (1–7 CVEs each) | ✅ **Source-asserted** (CISA sector note → Energy / Healthcare / Finance) | ICS-CERT advisories, CVE ↔ critical-infrastructure sector | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_CISA_ICS`, default off) |
| 14 | MalwareBazaar | ~830–1,000 samples per export (last 48 h; 1,027 on 2026-10-12, 762 with a family label; about 830 on 2026-10-24), ≤ 500 pushed per run; abuse.ch Auth-Key required | ✅ Auto-tagged (`detect_zones_from_text()` on the family label) | Malware sample hashes (sha256) with the family label → `INDICATES` edges to `Malware` nodes | 🚩 Flag-guarded (`EDGEGUARD_ENABLE_MALWAREBAZAAR`, default off) |
| 15 | FIRST EPSS | ~385,000 scores / day (only existing CVEs updated) | N/A | Exploit-prediction score and percentile per CVE; the one source written to Neo4j without MISP (§ 8b) | 🚩 Post-sync enrichment (`EDGEGUARD_ENABLE_EPSS`, default on) |

**Note:** Energy and Healthcare collectors are placeholders. Member-only ISAC feeds (EE-ISAC, Health-ISAC) are not planned and no membership is budgeted, and HC3, a public source of the US Department of Health and Human Services, is not collected. No DAG task calls the two placeholder modules. CISA ICS Advisories (row 13) is a real, flag-guarded collector that covers the ICS-CERT part of the energy/healthcare picture without any membership.

**Measured on the hosted instance after the first 730-day baseline (13–14 October 2026), MISP attributes per source:** AlienVault OTX 149,270; NVD 139,862; URLhaus 34,003; SSL Blacklist 10,967; AbuseIPDB 10,000; Feodo Tracker 7,607; ThreatFox 7,398 (the API serves at most 7 days); MITRE ATT&CK 1,892; CISA KEV 547; 361,546 in total. VirusTotal, MalwareBazaar and CISA ICS were not part of that run. The Items column above gives per-run estimates.

---

## Source Details

### 1. AlienVault OTX
**Items:** 6,953 | **Zone (Sector) Distribution:** Healthcare 62%, Energy 30%, Global 6%, Finance 2%

| Attribute | Value |
|-----------|-------|
| URL | https://otx.alienvault.com/api/v1/pulses/subscribed |
| Format | JSON API |
| Auth | API Key required |
| Update | Every 30 minutes (`edgeguard_pipeline` → `collect_otx`): pulses modified since the stored cursor (`otx_last_pulse_modified` minus `EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`, 300 s; without a cursor the last `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`, 3), in pages of 100 up to `EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES` (25), with at most `EDGEGUARD_INCREMENTAL_LIMIT` (200) pulses processed per run. A baseline reads pages of 50 pulses (the baseline limit when one is set) up to `EDGEGUARD_OTX_BASELINE_MAX_PAGES` (200) |
| Classification | ✅ Keyword-based on the whole pulse (name, tags, description, indicators), plus OTX's own `industries` |

**What we get:**
- IPs, domains, URLs, hashes
- Malware family names
- CVE references
- Adversary names (no pulse descriptions: a pulse's description, which describes the report, is stored on no item, and the families and adversaries it names carry none; it is used for sector classification)

**How classified:**
- The whole pulse — name, tags, description, indicators — searched for keywords (hospital, scada, bank, etc.); the sectors found apply to every item of the pulse
- OTX's own `industries` classification added to them (the whole name, case ignored: Energy, Utilities, Oil, Gas, Petroleum → `energy`; Finance, Financial, Financial Services, Banking, Insurance, Investment, Investments → `finance`; Healthcare, Health, Medical, Pharmaceutical, Pharmaceuticals, Pharmacy → `healthcare`; `config.OTX_INDUSTRY_ZONE_ALIASES`; Government, Transportation and the other industries map to no sector). These are the report's statement of the sectors its campaign targets: an indicator's, actor's or malware's `TARGETS` link to such a sector carries `otx_industries` (0.6), a sector only the keywords found `zone_classification` (0.5)
- Word boundary matching prevents false positives

---

### 2. SSL Blacklist (abuse.ch)
**Items:** the whole blacklist (10,964 rows on 2026-10-12), at most `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000) per run | **Zone Distribution:** Global (all 10,964 rows on 2026-10-12, see Method 2 below)

| Attribute | Value |
|-----------|-------|
| URL | https://sslbl.abuse.ch/blacklist/sslblacklist.csv |
| Format | CSV |
| Auth | None (public) |
| Update | Daily |
| Classification | Keyword detector on the listing reason (Global in practice; no malware family is mapped to a sector) |

**What we get:**
- SSL certificate SHA1 fingerprints, stored as MISP `x509-fingerprint-sha1` attributes and `x509-fingerprint-sha1` Indicators
- Listing reason (for example `Dridex C&C`), used only for sector detection. It is not written to MISP, and no malware family is emitted

**How classified:**
- Keyword detector on the listing reason; no malware family is mapped to a sector by name (Method 2 below), so the rows are tagged Global

**Per-run cap:** each run, daily or baseline, reads the whole blacklist, because the stored copy of a certificate a run leaves out is not refreshed and ages while the list still names it. The cap `EDGEGUARD_SSLBL_MAX_PER_RUN` (default 20,000, about twice the list) covers the whole list; a run whose list is longer keeps the newest by `Listingdate` and logs a warning ([COLLECTORS.md § 7](COLLECTORS.md#7-finance-feed-collector)).

---

### 3. URLhaus
**Items:** the URLs of the `recent.csv` export (about 63,000 on 2026-10-24, about 1,130 new per day), at most `EDGEGUARD_URLHAUS_MAX_PER_RUN` (100,000) per run | **Zone Distribution:** Global 100%

| Attribute | Value |
|-----------|-------|
| URL | `https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv` |
| Format | CSV |
| Auth | The abuse.ch Auth-Key (`THREATFOX_API_KEY`, https://auth.abuse.ch/) in the URL path; without it the task is skipped (`missing_abusech_key`), HTTP 401/403 → skipped (`urlhaus_auth_denied`). The key is redacted in every log line and error, the HTTP library's DEBUG records included |
| Update | Daily |
| Classification | ✅ `detect_zones_from_text()` on threat names and tags |

**Per-run cap:** the daily run reads the whole export, so that no URL leaves the window uncollected. The cap `EDGEGUARD_URLHAUS_MAX_PER_RUN` (default 100,000) covers the export (about 63,000 URLs on 2026-10-24) with headroom; a run that reaches it keeps the newest URLs by `dateadded` and logs a warning. ThreatFox (the IOCs of the last 7 days, the most `get_iocs` serves; 7,398 on the same baseline) has the same rule with `EDGEGUARD_THREATFOX_MAX_PER_RUN` (default 10,000), newest by `first_seen` ([COLLECTORS.md § 8](COLLECTORS.md#8-global-feed-collector)).

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
| URL | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (per `src/collectors/cisa_collector.py:81`) |
| Format | JSON |
| Auth | None (public) |
| Update | Every 4 hours (`edgeguard_medium_freq` → `collect_cisa`) and baseline |
| Classification | Keyword detector on vendor, product and short description |

**What we get:**
- CVE IDs
- Vendor/product names
- Description
- Date added to KEV
- Known ransomware campaign use (`known_ransomware_use` on the `CVE` node; no CVSS score is derived from it — the catalogue carries none, and the node's score comes from its CVSS sub-nodes)

**How classified:**
- Vendor, product and short description searched for sector keywords

**Scope:** every run, the baseline and the run every 4 hours, takes the **whole catalogue** (1,748 entries on 2026-10-16), not only the entries added within a window: a KEV entry is a CVE known to be exploited, so its age is no reason to leave it out (Log4Shell, added to the catalogue in 2021-12, lies outside a 730-day window). `EDGEGUARD_KEV_BASELINE_WHOLE_CATALOGUE=false` applies the `dateAdded` window of the baseline length instead; an entry outside it is then neither added nor edited, so it follows no revision, and where NVD's record (the NVD KEV sweep) alone gives its KEV fields, that record only fills them on the `CVE` node. `EDGEGUARD_CISA_INCREMENTAL_DAYS` is not read.

**Revisions:** CISA revises entries in place (26 ransomware uses Unknown → Known, a moved due date and an extended description between 2026-05-22 and 2026-10-16, all on entries older than 30 days) and publishes no per-entry modification date. Every run therefore compares each catalogue entry with EdgeGuard's stored MISP copy: a CVE MISP lacks is added, a copy that differs is edited in place (its `NVD_META` and tags, `ransomware:known` included), so MISP holds CISA's latest statement and the sync carries it to the `CVE` node, whose four KEV fields the KEV record owns. At most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) edits per run, the rest on the next run; `EDGEGUARD_KEV_UPDATE_EXISTING=false` adds new entries only. An entry removed from the catalogue is counted and logged, not removed. `notes`, `cwes` and `forensicTriage` are not stored in MISP (`cwes` and `notes` are read onto the item but not written to `NVD_META`). Details: [COLLECTORS.md § 3](COLLECTORS.md#revisions-every-run-compares-the-catalogue-with-misp).

---

### 4b. CISA ICS Advisories (CSAF 2.0) — flag-guarded
**Items:** one `vulnerability` per CVE (the advisories that name one CVE are merged into one item); ~900 advisories on a 730-day baseline | **Zone:** source-asserted by CISA, not keyword-detected

| Attribute | Value |
|-----------|-------|
| URL | `https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/` (`index.txt`, `changes.csv`, `<year>/<advisory>.json`) — per `src/collectors/cisa_ics_collector.py` |
| Format | CSAF 2.0 JSON, one file per advisory (`ICSA-*`, `ICSMA-*`) |
| Auth | None (public GitHub raw); TLP:WHITE |
| Update | Daily (`edgeguard_daily` → `collect_cisa_ics`) and baseline tier 2, only when `EDGEGUARD_ENABLE_CISA_ICS=true` |
| Classification | ✅ Fixed table on the advisory's `"Critical infrastructure sectors"` note: `Energy → energy`, `Healthcare and Public Health → healthcare`, `Financial Services → finance`; other sectors contribute nothing; `global` only when no sector maps |

**What we get:**
- CVE IDs with CWE, CVSS v3.x score/vector (→ `CVSSv31`/`CVSSv30` sub-nodes), vulnerability summary. A CSAF score block has no impact or exploitability sub-score, so the sub-node gets none. On a CVE NVD also describes, NVD's values hold: a sub-node NVD has asserted and NVD's lists (CWE, references, products) are only filled by CISA's record where they lack a value, whatever the order of the sync. When NVD's record drops a CVSS version CISA also gives, CISA's next record sets that sub-node's values again
- Advisory id, title, cisa.gov URL, vendor and affected products
- `initial_release_date` / `current_release_date` as source-truthful `first_seen` / `last_seen`
- The ids of every advisory that names the CVE (`advisory_ids`), CISA's own sector names (`ics_sectors`, all of CISA's sectors, not only the three mapped to zones, e.g. `Water and Wastewater Systems`) and the zones of each advisory (`advisory_zones`). MISPWriter carries the three in the attribute's `NVD_META` comment (CISA ICS records only), and the sync keeps them in the `raw_data` of the CVE's `SOURCED_FROM` edge to `cisa_ics`; each advisory becomes a record reference `cisa_ics:<advisory id>` (`r.source_refs`), which the STIX export links to its cisa.gov page. A sector link cites only the advisories whose sector note names that sector (the edge's `stated_refs`), not every advisory that names the CVE

**How classified:**
- Sector names come from CISA's own note in the advisory; the keyword detector is not used
- The sector says where the affected product is **deployed**, not who is targeted. On the graph it is a statement of CISA: the CVE's `AFFECTS` link to the sector carries the evidence label `advisory_sector` at confidence 0.9 (never a `TARGETS` link), while a sector EdgeGuard infers from text stays `zone_classification` at 0.5 (`src/sector_evidence.py`). The field is often broad: in the 2026-10-16 graph, 946 of the 955 CVEs CISA placed in finance also named energy and healthcare
- A CVE named by several advisories carries the union of their sectors, ids and references; its text, CVSS and products come from the newest advisory, so the result does not depend on the order of the advisories

**Per-run cap:** a daily run reads the advisories changed since its cursor (minus 24 h), oldest first, up to `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200) advisory files. `EDGEGUARD_INCREMENTAL_LIMIT` does not apply, because a limit counted in (advisory, CVE) items would stop a run inside an advisory that names more CVEs than the limit (350–378 on three advisories of the 2026-10-16 baseline): the cursor would stay at that advisory, and newer advisories would never reach MISP.

**Safety:** own circuit breaker + rate limiter, per-file failures counted and skipped, baseline sanity floor (`EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES`, default 50) raises a transient error → task skipped + alert rather than a thin dataset. See [COLLECTORS.md §12](COLLECTORS.md#12-cisa-ics-advisories-collector).

---

### 4c. MalwareBazaar (abuse.ch) — flag-guarded
**Items:** one `sha256` indicator per sample; the recent export holds the samples of the last 48 hours (1,027 rows on 2026-10-12: 458 Mirai, 265 without a label; about 830 on 2026-10-24) and at most `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500) are pushed per run | **Zone:** `detect_zones_from_text()` on the family label (`global` when the label is `n/a`)

| Attribute | Value |
|-----------|-------|
| URL | `https://mb-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv` — per `src/collectors/global_feed_collector.py` (`MalwareBazaarCollector`). The full export (`/export/csv/full/`) is the complete history and is not used |
| Format | CSV with `#` comment lines; columns `first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, file_name, file_type_guess, mime_type, signature, clamav, vtpercent, imphash, ssdeep, tlsh` |
| Auth | The abuse.ch Auth-Key (`THREATFOX_API_KEY`) in the URL path, required (without it the task is skipped, `missing_abusech_key`); redacted in every log line and error, the HTTP library's DEBUG records included |
| Update | Daily (`edgeguard_daily` → `collect_malwarebazaar`) and baseline tier 2, only when `EDGEGUARD_ENABLE_MALWAREBAZAAR=true`; both read the recent export, so the history builds up over the daily runs |
| Classification | ✅ `detect_zones_from_text()` on `signature` |
| Terms | Free of charge for commercial and non-commercial use (https://bazaar.abuse.ch/faq/#tos) |

**What we get:**
- sha256 (the indicator), md5 and sha1 of the sample
- Family label (`signature`, "n/a" when unknown) → `malware_family` → `Indicator → Malware` `INDICATES` edges (`match_type = malware_family`), the same path as the ThreatFox family
- File name, file type guess, MIME type, reporter, sample page URL
- `first_seen_utc` as source-truthful `first_seen` (tz-aware UTC)

**Selection:** labelled samples are kept before unlabelled ones, then the list is cut at the per-run cap (and at the regular collection limit when that is lower).

**Safety:** own circuit breaker + rate limiter; flag off or no `THREATFOX_API_KEY` → skipped status without an HTTP request; 401/403 → skipped (`malwarebazaar_auth_denied`); 429 after the Retry-After retries, 5xx and timeouts → transient error → task skipped + alert. See [COLLECTORS.md §13](COLLECTORS.md#13-malwarebazaar-collector).

---

### 5. MITRE ATT&CK
**Items:** 500 | **Zone:** N/A (techniques/actors)

| Attribute | Value |
|-----------|-------|
| URL | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` (per `src/collectors/mitre_collector.py`); with `EDGEGUARD_ENABLE_MITRE_ICS=true` (default off) also `ics-attack/ics-attack.json` — ATT&CK for ICS (97 techniques T08xx, 12 tactics, 14 groups, 23 malware), items stamped `attack_domain: ics`, ICS fetch failure isolated from the Enterprise ingest |
| Format | STIX 2.1 JSON |
| Auth | None (public) |
| Update | Periodic |
| Classification | ❌ N/A - provides relationships |

**What we get:**
- Techniques (300)
- Threat Actors (100)
- Malware (100)
- **Relationships** — 1,459 TTP edges, typed `EMPLOYS_TECHNIQUE` (Actor→Technique, attribution) or `IMPLEMENTS_TECHNIQUE` (Malware/Tool→Technique, capability)

**How classified:**
- N/A - these are TTP entities, not sector-specific

---

### 6. NVD (National Vulnerability Database)
**Items:** 100 | **Zone Distribution:** Global 76%, Finance 10%, Energy 7%, Healthcare 7%

| Attribute | Value |
|-----------|-------|
| URL | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| Format | JSON API |
| Auth | API key optional (free; without it requests are paced 6.5 s apart) |
| Update | Every 8 hours (`edgeguard_low_freq` → `collect_nvd`) and baseline |
| Classification | Keyword detector on the description and the CPE vendor/product text (`detect_zones_from_item`) |

**API constraints (collector behavior):** NVD CVE 2.0 requires **`pubStartDate` and `pubEndDate` together** when filtering by published date. Each request is limited to **at most 120 consecutive days**. The collector anchors the window on **now (UTC)**. **Incremental** runs read every CVE modified since a stored cursor (**`lastModStartDate` / `lastModEndDate`**, read in time slices of at most 120 days, one answer of up to 2,000 records each; without a cursor the last `EDGEGUARD_NVD_INCREMENTAL_DAYS` days, default 14). They add the CVEs MISP does not hold yet when these lie in the baseline's scope (published within `EDGEGUARD_BASELINE_DAYS`, on KEV, or named in `EDGEGUARD_NVD_EXTRA_CVE_IDS`), and they edit the MISP attribute of a CVE MISP holds when NVD's data for it changed. NVD's later analysis (CVSS, CPE, CWE, description, KEV fields) and rejections reach the graph, including data NVD withdrew (list values on CVE nodes whose only source is NVD, and CVSS sub-nodes only NVD asserted). Each request reads one time slice, so records NVD changes during the read are not skipped. A run makes at most `EDGEGUARD_NVD_MAX_PER_RUN` (5,000) MISP writes ([COLLECTORS.md § 2](COLLECTORS.md)) (see [CVE API](https://nvd.nist.gov/developers/vulnerabilities), [workflows](https://nvd.nist.gov/developers/api-workflows)). **Baseline** mode **splits** `[now − baseline_days, now]` into multiple ≤120-day publication windows. No age filter is applied after the fetch. **Known-exploited CVEs outside the windows:** after the windows, a baseline also fetches the NVD record of every CVE on CISA's KEV list (`hasKev`, about 1,700 records in one page; `EDGEGUARD_NVD_BASELINE_KEV_SWEEP`, default on) and of the CVE ids listed in `EDGEGUARD_NVD_EXTRA_CVE_IDS` (one request each), whatever their publication date. A failed supplementary request is logged and skipped, never fails the baseline. **NIST attribution:** This product uses data from the NVD API but is not endorsed or certified by the NVD.

**What we get:**
- CVE IDs
- Descriptions
- CVSS scores (including v4 when present); a CVE's `cvss_score` / `severity` come from its first CVSS in the order v3.1 → v3.0 → v2 → v4.0 (`cvss_version` names it), and a CVE without any CVSS has no score and severity `UNKNOWN`
- Attack vectors
- NVD's record status (`status`, `["active"]` or `["rejected"]`)
- CISA's SSVC decision points, which NVD relays from the CISA-ADP container of the CVE record (`metrics.ssvcV203`; CISA's Vulnrichment program): `ssvc_exploitation` (`none` / `poc` / `active`), `ssvc_automatable` (`yes` / `no`), `ssvc_technical_impact` (`partial` / `total`), with `ssvc_version` and `ssvc_timestamp` (the time of CISA's decision). They travel through MISP in `NVD_META` like the rest of the record and are set on the `CVE` node from NVD's record only; a decision CISA withdraws is removed. Compared on 2026-10-15 with the values read from CISA's Vulnrichment repository for 24 CVEs (4 records of `tests/fixtures/nvd_incremental_2026_10_14.json` and a random sample of 20 CVEs of the hosted graph): NVD had a decision for every one, the decision points were the same on all 24, and the timestamp on 22 (on the other 2, NVD gives the day only)

---

### 7. MISP (the staging hub, not a source)
MISP is the staging hub every collector pushes into (361,546 attributes after the first 730-day baseline, see above), not a source. `MISPCollector` is an optional path that no DAG runs ([COLLECTORS.md § 11](COLLECTORS.md#11-misp-collector)).

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

**Per-run cap:** a run reports every server of the list it reads (the 30-day list daily, the complete history on a baseline), up to `EDGEGUARD_FEODO_MAX_PER_RUN` (default 15,000 servers, about twice the history). A run whose list is longer keeps the servers seen online most recently and logs a warning.

---

### 8b. FIRST EPSS (Exploit Prediction Scoring System) — post-sync enrichment
**Items:** ~385,000 rows per daily file; only `CVE` nodes already in the graph are updated | **Zone:** n/a (CVE properties, not new nodes)

| Attribute | Value |
|-----------|-------|
| URL | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (the address FIRST documents; it redirects to the day's file; override `EPSS_URL`) — per `src/cve_feed_enrichment.py` |
| Format | gzip CSV, first line `#model_version:...,score_date:...`, header `cve,epss,percentile` (~2.7 MB) |
| Auth | None (public) |
| Update | FIRST publishes a file every day. The enrichment job `enrich_cve_epss` reads the current file after every Neo4j sync (`edgeguard_neo4j_sync`, every 72 hours) and after the baseline, when `EDGEGUARD_ENABLE_EPSS=true` (default). The download is bounded by `EPSS_MAX_BYTES` (64 MiB) and `EPSS_DOWNLOAD_DEADLINE_SEC` (300 s) |
| Classification | n/a |

**What we get:**
- `CVE.epss_score` (probability of exploitation in the next 30 days, 0-1) and `CVE.epss_percentile`
- `CVE.epss_score_date` and `CVE.epss_model_version` (from the file's first line; a file without a score date is not used), `CVE.epss_updated_at` (the time of the write)

**How written:** only on `CVE` nodes that exist (`MATCH`, never `MERGE`); a node a partner created gets the shared-database marker `edgeguard_enriched` ([RESILMESH_INTEROPERABILITY.md § 3.4](RESILMESH_INTEROPERABILITY.md)). Once the whole file is written, a CVE whose EPSS is from an earlier file has left the feed (NVD rejected it, for example) and loses its EPSS properties; a run that matched fewer CVE nodes than half of those already scored does not clear, so neither a short file nor ids that fail to match after a format change wipe the scores. A feed failure (HTTP error, timeout, deadline, size cap, bad payload) is logged at ERROR and the job returns `skipped`: it never fails the DAG task. A database failure raises, before anything is cleared; the next run writes the whole file again.

**Why not through MISP:** EPSS is the one source EdgeGuard writes straight to Neo4j. It is a new score for every published CVE every day (about 385,000 rows), a measurement of the CVE rather than threat intelligence about it, and MISP would only hold a copy of it. No node or relationship is created, so there is no relationship provenance to record; the score date and model version on every scored node say which file the value came from.

**How classified:** n/a — no sector logic; properties only.

**Terms:** FIRST publishes the scores daily, free of charge and without registration; its EPSS pages state no licence or attribution requirement (checked 2026-10-15). The scores are generated by Empirical Security for FIRST.

---

### 9. AbuseIPDB
**Items:** the addresses of the blacklist (`abuseConfidenceScore` ≥ 90 requested), at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) per run; the 730-day baseline of 2026-10-13 received 10,000 | **Zone:** keyword detector on the fields the answer carries (country code; ISP, usage type and domain when present)

| Attribute | Value |
|-----------|-------|
| URL | `https://api.abuseipdb.com/api/v2/blacklist` (per `src/collectors/abuseipdb_collector.py`) |
| Format | JSON API |
| Auth | API key (`ABUSEIPDB_API_KEY`; optional source, skipped without it) |
| Update | Daily (`edgeguard_daily` → `collect_abuseipdb`) and baseline tier 2 |
| Classification | ✅ `detect_zones_from_text()` on country code, ISP, usage type and domain |

**What we get:**
- IP addresses with AbuseIPDB's confidence score (`confidence_score` = score / 100), country and `lastReportedAt` (the source-reported last-seen time; the endpoint gives no first-seen date)

**Plan limits and the per-run cap:** the collector makes at most one blacklist request per run: the daily run at most one, a baseline at most one more, and none when a run reuses the answer fetched earlier on the same UTC day (the free plan allows 5 blacklist requests per UTC day; the daily and the baseline runs share one cache key, [COLLECTORS.md § 5](COLLECTORS.md#5-abuseipdb-collector), "Blacklist quota and cached answer"). The cap `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (default 10,000), not `EDGEGUARD_INCREMENTAL_LIMIT`, is that request's `limit`, because the stored copy of an address a run leaves out is not refreshed and ages while the blacklist still lists it; the cap changes the size of the answer, not the number of requests. 10,000 is the most one request returns on the free plan (`AbuseIPDBCollector.BLACKLIST_MAX_PER_REQUEST`), so a larger value has no effect until that ceiling is raised for a plan that returns more. AbuseIPDB chooses which addresses fill the request; an answer longer than the request keeps the addresses reported most recently. The live source key check uses the `check` endpoint (1,000 a day on the free plan), not the blacklist ([COLLECTORS.md § 5](COLLECTORS.md#5-abuseipdb-collector)).

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

_Last updated: 2026-10-25_

## History

- 2026-10-25 — URLhaus and MalwareBazaar read the abuse.ch v2 `recent.csv` exports with the Auth-Key (`THREATFOX_API_KEY`) in the URL path, because the keyless downloads (`downloads/csv_recent/`, `csv_top10k/`, `/export/csv/recent/`) answer HTTP 410 since 2026-10; the URLhaus export listed about 63,000 URLs on 2026-10-24 (the keyless 30-day file 34,003 on 2026-10-13), and `EDGEGUARD_URLHAUS_MAX_PER_RUN` is 100,000 (was 50,000), so the cap covers it again.
- 2026-10-23 — HC3 named as a public source that is not collected, not as a member-only feed; no DAG task calls the placeholder modules.
- 2026-10-18 — OTX: the sectors the pulse's own industries name are its statement (`otx_industries` on `TARGETS`); Financial Services, Investment(s), Pharmaceuticals, Pharmacy and Petroleum map to a sector.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — CISA ICS daily runs bounded by `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1,200 advisory files) instead of `EDGEGUARD_INCREMENTAL_LIMIT`, whose 200 (advisory, CVE) items stopped a run inside a large advisory and held the cursor there.
- 2026-10-17 — Sections aligned with the code: OTX every 30 minutes from a stored cursor with its page limits (it said on demand, 50 pulses per run); SSL Blacklist classified by the listing reason, which does not reach MISP; CISA KEV every 4 hours, with `notes` and `cwes` not stored in MISP; NVD key optional, every 8 hours, CPE text searched; MISP described as the staging hub; main text limited to current behaviour, with the change history (the 2026-03 notes included) in this section and data written by earlier versions in the appendix.
- 2026-10-16 — CISA ICS: one item per CVE with the newest advisory's text (the first item pushed won); advisory ids, CISA's sector names and per-advisory zones carried to the graph (the documented `ics_sectors` had never left the collector); sector links as `advisory_sector` statements at 0.9; no impact or exploitability sub-score (the collector sent 0.0); NVD's CVSS sub-nodes and lists hold whatever the sync order (the record merged last won).
- 2026-10-16 — CISA KEV: every run takes the whole catalogue (1,748 entries) and edits revised entries in place; `EDGEGUARD_CISA_INCREMENTAL_DAYS` (a 30-day window for incremental runs) retired.
- 2026-10-16 — Per-run caps for SSL Blacklist (20,000), Feodo Tracker (15,000) and AbuseIPDB (10,000; one blacklist request per run, reused within its UTC day; a 429 fails the task); their daily runs had been cut at `EDGEGUARD_INCREMENTAL_LIMIT` (200), so the stored copies of unreported entries aged while the lists named them.
- 2026-10-15 — ThreatFox and URLhaus read their whole window per run (caps 10,000 and 50,000); the daily cut at 200 had left about 80% of each day's URLhaus URLs uncollected.
- 2026-10-15 — FIRST EPSS enrichment (row 15, § 8b) and CISA's SSVC decision points from the NVD records added; OTX pulse descriptions no longer given to the pulse's families and adversaries; SSL Blacklist fingerprints stored as `x509-fingerprint-sha1` (they were file `sha1` hashes); no CVSS score derived from KEV ransomware use; NVD score rule and record status; measured volumes of the first 730-day baseline.
- 2026-10-14 — CISA KEV whole catalogue in baseline mode, the NVD KEV sweep and `EDGEGUARD_NVD_EXTRA_CVE_IDS`; NVD incremental runs by lastModified cursor; the sector time-range check removed (it had not fired on NVD's zone-less timestamps since v2026.3.28).
- 2026-10-12 — MalwareBazaar added as a flag-guarded source; CyberCure removed (its feed API answered HTTP 520 on every endpoint, it offers no paid or authenticated tier, and the collector produced zero events on the production instance, skipping silently on every run); member-only ISAC feeds not planned.
- 2026-10-10 — CISA ICS Advisories and ATT&CK for ICS added, both flag-guarded and off by default.
- 2026-04-26 — CISA KEV and MITRE ATT&CK URLs corrected to the files the collectors fetch (both pointed at non-existent pages).
- 2026-04-15 — MITRE TTP edges typed `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE`, replacing one generic `USES` edge.
- 2026-03-28 — State recorded at the time: finance coverage low (4%; a ThreatFox API key and FS-ISAC proposed), URLhaus classified by `detect_zones_from_text()`, MITRE data without zone, MISP as a source holding 4 items; open questions on MISP versus direct collectors, FS-ISAC membership, URLhaus tag parsing and IOC validation.
