# EdgeGuard Data Sources - API Documentation & Rate Limits

**Purpose:** Complete reference for setting up a new EdgeGuard instance. For integration behaviour (e.g. NVD published-date windows), see [`DATA_SOURCES.md`](DATA_SOURCES.md).

---

## Quick Reference Table

| Source | API Required | Rate Limit | Cost | Data Format |
|--------|-------------|------------|------|-------------|
| AlienVault OTX | ✅ Yes | 30 requests/min (free) | Free | JSON |
| NVD | Optional (free; recommended) | 50 requests/30 sec with a key, 5 without | Free | JSON |
| CISA KEV | ❌ No | No limit (JSON download) | Free | JSON |
| MITRE ATT&CK | ❌ No | No limit (STIX download) | Free | STIX 2.1 |
| VirusTotal | ✅ Yes | 4 requests/min, 500/day (free) | Free tier used; paid plans from $50/month | JSON |
| AbuseIPDB | ✅ Yes | 1,000 `check` requests/day, 5 `blacklist` requests per UTC day (free) | $50+/month | JSON |
| URLhaus | ✅ Yes (abuse.ch Auth-Key) | No limit (CSV) | Free | CSV |
| Feodo Tracker | ❌ No | No limit (CSV) | Free | CSV |
| SSL Blacklist | ❌ No | No limit (CSV) | Free | CSV |
| MalwareBazaar (flag-guarded) | ✅ Yes (abuse.ch Auth-Key, export) | One export download per run (about 450 KB) | Free | CSV |
| CISA ICS advisories (flag-guarded) | ❌ No | GitHub raw files (`cisagov/CSAF`) | Free | CSAF 2.0 JSON |
| ThreatFox | ✅ Yes | Varies by key | Free tier | JSON |
| MISP | ✅ Yes | Varies (self-hosted) | Free (self-hosted) | JSON |

---

## Detailed Source Documentation

### 1. AlienVault OTX (LevelBlue OTX)

**Website:** https://otx.alienvault.com  
**Documentation:** https://otx.alienvault.com/api

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Free account required |
| **Rate Limit (Free)** | 30 requests/minute |
| **Rate Limit (Enterprise)** | Custom, higher limits |
| **Data Provided** | IPs, domains, URLs, hashes, malware families, CVEs |
| **Update Frequency** | Real-time (pulses) |

**Getting an API key:**
1. Create account at https://otx.alienvault.com
2. Go to Settings → API Key
3. Copy your OTX API key

**Pricing:**
- Free tier: 30 requests/min, 10,000 pulses/day
- Enterprise: Contact sales (custom pricing)

---

### 2. NVD (National Vulnerability Database)

**Website:** https://nvd.nist.gov  
**Documentation:** https://nvd.nist.gov/developers/vulnerabilities

| Aspect | Details |
|--------|---------|
| **API Required** | Optional (free API key recommended; without one the collector paces requests 6.5 s apart) |
| **Registration** | Free registration, only to obtain a key |
| **Rate Limit (No Key)** | 5 requests/30 seconds |
| **Rate Limit (With Key)** | 50 requests/30 seconds |
| **Data Provided** | CVE records, CVSS scores, CPEs |
| **Update Frequency** | Daily (new CVEs) |

**Getting an API key:**
1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Wait for approval (usually automatic)
3. Use key in the **`apiKey`** request header (NVD 2.0; value is case-sensitive)

**Pricing:** Free

**Collector note (EdgeGuard):** CVE 2.0 requests that filter by **published** date must send **`pubStartDate` and `pubEndDate` together**; NIST limits each range to **120 consecutive days**. Implementation: `src/collectors/nvd_collector.py` (`NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`, `clamp_nvd_published_range`, `iter_nvd_published_windows` for baseline).

---

### 3. CISA KEV (Known Exploited Vulnerabilities)

**Website:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog  
**Data Feed:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (the file `src/collectors/cisa_collector.py:81` fetches; the `/json` address under the catalogue page does not resolve).

| Aspect | Details |
|--------|---------|
| **API Required** | No |
| **Registration** | Not required |
| **Rate Limit** | None (direct download) |
| **Data Provided** | CVE IDs, vendor/product, description, known exploitation |
| **Update Frequency** | Daily |

**Note:** CISA website may have downtime during federal funding lapses. Consider caching the JSON file locally.

**Pricing:** Free

---

### 4. MITRE ATT&CK

**Website:** https://attack.mitre.org  
**Data Repository:** https://github.com/mitre/cti

| Aspect | Details |
|--------|---------|
| **API Required** | No |
| **Registration** | Not required |
| **Rate Limit** | None (GitHub download) |
| **Data Provided** | Techniques, tactics, threat actors, malware, relationships |
| **Format** | STIX 2.1 |
| **Update Frequency** | Quarterly releases |

**Data Download (ground truth — `MITRECollector.attack_url` in `src/collectors/mitre_collector.py`; with `EDGEGUARD_ENABLE_MITRE_ICS=true` (default off) also the ATT&CK for ICS bundle `https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json`, `MITRE_ICS_ATTACK_URL` in `src/config.py`, overridable):**
- **Used:** `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` — the STIX 2.0/2.1 enterprise bundle from MITRE's `mitre/cti` repo.
- **Not used:** https://github.com/mitre-attack/attack-stix-data, MITRE's newer canonical STIX 2.1 dataset. A migration to it is planned; the collector does not read it.

**Pricing:** Free

---

### 5. VirusTotal

**Website:** https://www.virustotal.com  
**Documentation:** https://developers.virustotal.com/reference

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Free account required |
| **Rate Limit (Free)** | 4 requests/minute, 500 requests/day; lookups only (no feed or search endpoints) |
| **Rate Limit (Lite)** | 60 requests/minute |
| **Rate Limit (Basic)** | 120 requests/minute |
| **Data Provided** | File hashes, URLs, IPs, domains, malware analysis |
| **Update Frequency** | Real-time |

**Getting an API key:**
1. Create account at https://www.virustotal.com
2. Go to Settings → API Key
3. Copy your API key

**Pricing:**
- **Free:** 4 requests/min, limited lookups
- **Lite:** $50/month, 60 requests/min
- **Basic:** $200/month, 120 requests/min, 1M queries/month
- **Enterprise:** Custom pricing, unlimited

**EdgeGuard usage (free tier):** `VTCollector` enriches SHA-256 hashes already in MISP with `GET /files/{hash}` — `EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN` (default 60) per run and `EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET` (default 400) per UTC day, tracked in a ledger in the state directory. Quota events are logged with the prefix `[VT-QUOTA]`; an exhausted budget or an HTTP 429 skips the task instead of failing it. See docs/COLLECTORS.md § 6.

---

### 6. AbuseIPDB

**Website:** https://www.abuseipdb.com  
**Documentation:** https://docs.abuseipdb.com/

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Free account required |
| **Rate Limit (Free)** | 1,000 `check` requests and 5 `blacklist` requests per UTC day |
| **Rate Limit (Paid)** | 300,000+ requests/day |
| **Data Provided** | IP reputation, abuse reports, confidence score |
| **Update Frequency** | Real-time reports |

**Getting an API key:**
1. Create account at https://www.abuseipdb.com/register
2. Go to API Key section
3. Free tier provides 1,000 `check` lookups and 5 `blacklist` downloads per UTC day

**Pricing:**
- **Free:** 1,000 lookups/day, 5 blacklist downloads/day
- **Starter:** $50/month, 10,000 lookups/day
- **Professional:** $150/month, 100,000 lookups/day
- **Enterprise:** Custom, 300,000+ lookups/day

**EdgeGuard usage (free tier):** `collect_abuseipdb` (daily DAG and baseline) downloads the blacklist with `GET /blacklist`; the source key check uses `GET /check` and spends no blacklist request. A blacklist answer of HTTP 429 means the day's 5 blacklist requests are spent: the request returns at once, without the rate-limit backoff, and the task fails. A fetched, non-empty answer is kept in `<EDGEGUARD_STATE_DIR or ./state>/abuseipdb_blacklist_cache.json`, and a run that asks for the same parameters reuses it without a request while it was fetched on the current UTC day and is at most `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` (default 20) old; `0` turns the cache off. See docs/COLLECTORS.md § 5 and docs/RUNBOOK.md, "AbuseIPDB daily blacklist quota".

---

### 7. URLhaus

**Website:** https://urlhaus.abuse.ch  
**Documentation:** https://urlhaus.abuse.ch/api/

| Aspect | Details |
|--------|---------|
| **API Required** | No (CSV download) |
| **Registration** | Not required |
| **Rate Limit** | None (CSV download) |
| **Data Provided** | Malware URLs, tags, threat types |
| **Format** | CSV |
| **Update Frequency** | Hourly |

**Download URLs:**
- Recent (2026-10, Auth-Key in the path; the old `downloads/csv_recent/` answers HTTP 410): https://urlhaus-api.abuse.ch/v2/files/exports/<AUTH-KEY>/recent.csv
- Full: https://urlhaus.abuse.ch/downloads/csv_all/ (not used)
- API: https://urlhaus.abuse.ch/api/

**Pricing:** Free

---

### 8. Feodo Tracker

**Website:** https://feodotracker.abuse.ch  
**Documentation:** https://feodotracker.abuse.ch/api/

| Aspect | Details |
|--------|---------|
| **API Required** | No (CSV download) |
| **Registration** | Not required |
| **Rate Limit** | None (CSV download) |
| **Data Provided** | Banking trojan C&C IPs, malware family |
| **Format** | CSV |
| **Update Frequency** | Daily by design; abuse.ch last updated the feed on 2026-03-04 |

**Download URLs:**
- IP blocklist (last 30 days, regular runs): https://feodotracker.abuse.ch/downloads/ipblocklist.csv
- Aggressive IP blocklist (complete history, baseline runs): https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv — 7,980 rows (7,607 distinct servers) on 2026-10-12; the feed header says it was last updated on 2026-03-04. abuse.ch advises against blocking on this list (false positives); EdgeGuard loads it as history: servers not seen online in the last 30 days get low confidence and no MISP detection flag.
- JSON: https://feodotracker.abuse.ch/api/v1/feodotracker/ipblocklist

**Pricing:** Free

---

### 9. SSL Blacklist (abuse.ch)

**Website:** https://sslbl.abuse.ch  
**Documentation:** https://sslbl.abuse.ch/documentation/

| Aspect | Details |
|--------|---------|
| **API Required** | No (CSV download) |
| **Registration** | Not required |
| **Rate Limit** | None (CSV download) |
| **Data Provided** | SSL certificate SHA1 fingerprints, malware family |
| **Format** | CSV |
| **Update Frequency** | Daily |

**Download URL:** https://sslbl.abuse.ch/blacklist/sslblacklist.csv

**Pricing:** Free

---

### 10. MISP (Self-Hosted)

**Website:** https://www.misp-project.org  
**GitHub:** https://github.com/MISP/MISP

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Self-hosted (your instance) |
| **Rate Limit** | Configurable |
| **Data Provided** | Any threat intel you feed it |
| **Format** | JSON (MISP format) |
| **Update Frequency** | Based on your collectors |

**Installation:**
- Docker: https://github.com/coolacid/docker-misp
- Manual: https://www.misp-project.org/install/

**Pricing:**
- **Software:** Free (open source)
- **Hosting:** Your infrastructure costs
- **MISP VM:** Free appliance available

---

## Setup Checklist for New Instance

### API Keys (free tier; OTX, VirusTotal, AbuseIPDB and ThreatFox are skipped without their key, NVD runs slower without one)

| Source | Environment variable | Signup URL |
|--------|----------------------|------------|
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com |
| NVD | `NVD_API_KEY` | https://nvd.nist.gov/developers |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com |
| ThreatFox (also used by URLhaus and MalwareBazaar) | `THREATFOX_API_KEY` | https://auth.abuse.ch/ |

### Optional (Recommended for Production)

| Source | Purpose | Cost |
|--------|---------|------|
| VirusTotal Basic | Better rate limits | $200/month |
| AbuseIPDB Professional | More lookups | $150/month |
| FS-ISAC | Financial sector intel | Membership required |
| Flashpoint | Threat intelligence | Enterprise pricing |

### Environment Variables to Set

```bash
# Core API Keys
export MISP_URL="https://your-misp-instance:8443"
export MISP_API_KEY="your-misp-api-key"

# Source API Keys
export OTX_API_KEY="your-otx-key"
export NVD_API_KEY="your-nvd-key"
export VIRUSTOTAL_API_KEY="your-virustotal-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export THREATFOX_API_KEY="your-abuse-ch-auth-key"

# Neo4j
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-neo4j-password"

# Airflow (optional)
export AIRFLOW__CORE__EXECUTOR=LocalExecutor
export EDGEGUARD_BASE_DIR="/path/to/EdgeGuard"
# Metadata DB: use PostgreSQL or MySQL for Airflow state (repo Compose: service `airflow_postgres`).
# Example bare-metal: AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=postgresql+psycopg2://user:pass@host:5432/airflow
# See docs/AIRFLOW_DAGS.md and https://airflow.apache.org/docs/apache-airflow/stable/howto/set-up-database.html
```

---

## Rate Limit Recommendations

For production use, implement these delays:

| Source | Recommended Delay | Reason |
|--------|-------------------|--------|
| AlienVault OTX | 2 seconds/request | 30 req/min limit |
| NVD | ~0.6–1s between paginated requests with key; ~6.5s without | 50 req/30sec with key; 5 without ([NVD Start Here](https://nvd.nist.gov/developers/start-here)) |
| VirusTotal (free) | 15 seconds/request | 4 req/min limit |
| VirusTotal (paid) | 0.5 seconds/request | Higher limits |
| AbuseIPDB (free) | 90 seconds/request | 1000/day `check` limit; the blacklist allows 5 requests per UTC day, and EdgeGuard reuses a fetched answer within that day (§ 6) |
| MISP | 1 second/request | Depends on server |

---

## Notes

1. **CISA KEV** - Sometimes unavailable during US government funding gaps
2. **abuse.ch feeds** - Block automated access; use their recommended download intervals (daily/hourly)
3. **MISP** - Can run locally or use misp-project.org's community instance (limited)
4. **Stagger requests** - Use Airflow's scheduling to avoid hitting rate limits

---

## Alternative/Premium Sources (Not Yet Integrated)

| Source | Type | Cost | Notes |
|--------|------|------|-------|
| **FS-ISAC** | Financial sector | Membership | Best for finance IOCs |
| **Mandiant Advantage** | Threat intel | Enterprise | Industry standard |
| **Flashpoint** | Threat intel | Enterprise | Dark web intelligence |
| **DomainTools** | WHOIS/ DNS | $300+/month | Infrastructure |
| **GreyNoise** | Internet scan | $200+/month | Background noise |
| **Shodan** | IoT search | $50+/month | Attack surface |


---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — The NVD key is optional (5 requests per 30 s without it; the page said required); the KEV feed listed as a JSON download; the MITRE download named as `MITRECollector.attack_url`, plus the ATT&CK for ICS bundle with `EDGEGUARD_ENABLE_MITRE_ICS=true`; the setup checklist adds `THREATFOX_API_KEY`, names the environment variables and marks every source key optional; main text limited to current behaviour, with the change history in this section.
- 2026-10-16 — AbuseIPDB: the free plan's 5 `blacklist` requests per UTC day besides the 1,000 `check` requests; a blacklist 429 fails `collect_abuseipdb` at once (the task had stayed green with a count of 0); a fetched, non-empty answer is reused on the same UTC day within `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS`; the collector line that names the KEV feed URL cited.
- 2026-10-15 — One entry removed from the alternative and premium sources.
- 2026-04-26 — The CISA KEV feed URL corrected (the page named the non-existent `/known-exploited-vulnerabilities-catalog/json` address); the MITRE ATT&CK labels corrected to the `mitre/cti` bundle the collector reads, with `attack-stix-data` as a planned migration.
- 2026-03-27 — Reference of source APIs, rate limits and the setup checklist.
