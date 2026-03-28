# EdgeGuard Data Sources - API Documentation & Rate Limits

**Last Updated:** 2026-03-27  
**Purpose:** Complete reference for setting up a new EdgeGuard instance. For integration behaviour (e.g. NVD published-date windows), see [`DATA_SOURCES.md`](DATA_SOURCES.md).

---

## Quick Reference Table

| Source | API Required | Rate Limit | Cost | Data Format |
|--------|-------------|------------|------|-------------|
| AlienVault OTX | ✅ Yes | 30 requests/min (free) | Free | JSON |
| NVD | ✅ Yes (free) | 50 requests/30 sec (with key) | Free | JSON |
| CISA KEV | ❌ No | No limit (CSV download) | Free | JSON |
| MITRE ATT&CK | ❌ No | No limit (STIX download) | Free | STIX 2.0/2.1 |
| VirusTotal | ✅ Yes | 4 requests/min (free) | $200+/month | JSON |
| AbuseIPDB | ✅ Yes | 1,000 requests/day (free) | $50+/month | JSON |
| URLhaus | ❌ No | No limit (CSV) | Free | CSV |
| Feodo Tracker | ❌ No | No limit (CSV) | Free | CSV |
| SSL Blacklist | ❌ No | No limit (CSV) | Free | CSV |
| CyberCure | ❌ No | No limit (public feed) | Free | Mixed |
| ThreatFox | ✅ Yes | Varies by key | Free tier | JSON |
| MISP | ✅ Yes | Varies (self-hosted) | Free (self-hosted) | JSON |

---

## Detailed Source Documentation

### 1. AlienVault OTX (Now LevelBlue OTX)

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

**API Key获取:**
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
| **API Required** | Yes (free API key recommended) |
| **Registration** | Free registration required |
| **Rate Limit (No Key)** | 5 requests/30 seconds |
| **Rate Limit (With Key)** | 50 requests/30 seconds |
| **Data Provided** | CVE records, CVSS scores, CPEs |
| **Update Frequency** | Daily (new CVEs) |

**API Key获取:**
1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Wait for approval (usually automatic)
3. Use key in the **`apiKey`** request header (NVD 2.0; value is case-sensitive)

**Pricing:** Free

**Collector note (EdgeGuard):** CVE 2.0 requests that filter by **published** date must send **`pubStartDate` and `pubEndDate` together**; NIST limits each range to **120 consecutive days**. Implementation: `src/collectors/nvd_collector.py` (`NVD_MAX_PUBLISHED_DATE_RANGE_DAYS`, `clamp_nvd_published_range`, `iter_nvd_published_windows` for baseline).

---

### 3. CISA KEV (Known Exploited Vulnerabilities)

**Website:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog  
**Data Feed:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog/json

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
| **Format** | STIX 2.0 / STIX 2.1 |
| **Update Frequency** | Quarterly releases |

**Data Download:**
- Full dataset: https://github.com/mitre/cti (STIX 2.0)
- Better formatted: https://github.com/mitre-attack/attack-stix-data (STIX 2.1)

**Pricing:** Free

---

### 5. VirusTotal

**Website:** https://www.virustotal.com  
**Documentation:** https://developers.virustotal.com/reference

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Free account required |
| **Rate Limit (Free)** | 4 requests/minute |
| **Rate Limit (Lite)** | 60 requests/minute |
| **Rate Limit (Basic)** | 120 requests/minute |
| **Data Provided** | File hashes, URLs, IPs, domains, malware analysis |
| **Update Frequency** | Real-time |

**API Key获取:**
1. Create account at https://www.virustotal.com
2. Go to Settings → API Key
3. Copy your API key

**Pricing:**
- **Free:** 4 requests/min, limited lookups
- **Lite:** $50/month, 60 requests/min
- **Basic:** $200/month, 120 requests/min, 1M queries/month
- **Enterprise:** Custom pricing, unlimited

---

### 6. AbuseIPDB

**Website:** https://www.abuseipdb.com  
**Documentation:** https://docs.abuseipdb.com/

| Aspect | Details |
|--------|---------|
| **API Required** | Yes |
| **Registration** | Free account required |
| **Rate Limit (Free)** | 1,000 requests/day |
| **Rate Limit (Paid)** | 300,000+ requests/day |
| **Data Provided** | IP reputation, abuse reports, confidence score |
| **Update Frequency** | Real-time reports |

**API Key获取:**
1. Create account at https://www.abuseipdb.com/register
2. Go to API Key section
3. Free tier provides 1,000 lookups/day

**Pricing:**
- **Free:** 1,000 lookups/day
- **Starter:** $50/month, 10,000 lookups/day
- **Professional:** $150/month, 100,000 lookups/day
- **Enterprise:** Custom, 300,000+ lookups/day

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
- Recent: https://urlhaus.abuse.ch/downloads/csv_recent/
- Full: https://urlhaus.abuse.ch/downloads/csv_all/
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
| **Update Frequency** | Daily |

**Download URLs:**
- IP blocklist: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
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

### Required API Keys (Free Tier)

| Source | Key Name in config.py | Signup URL |
|--------|----------------------|------------|
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com |
| NVD | `NVD_API_KEY` | https://nvd.nist.gov/developers |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com |

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
| AbuseIPDB (free) | 90 seconds/request | 1000/day limit |
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
| **Recorded Future** | Threat intel | Enterprise | Large coverage |
| **Flashpoint** | Threat intel | Enterprise | Dark web intelligence |
| **DomainTools** | WHOIS/ DNS | $300+/month | Infrastructure |
| **GreyNoise** | Internet scan | $200+/month | Background noise |
| **Shodan** | IoT search | $50+/month | Attack surface |


---

_Last updated: 2026-03-27_
