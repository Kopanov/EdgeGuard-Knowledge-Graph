# Credentials Setup Guide

This guide explains how to obtain API keys for all the threat intelligence sources used by EdgeGuard.

---

## Getting API Keys

### MISP

1. Log in to your MISP instance at `https://your-misp-server`
2. Navigate to: **Administration > Users**
3. Select your user account, then click **Authentication Keys**
4. Click **Create new key**
5. Copy the key (it will only be shown once!)
6. Save it securely in your environment:
   ```bash
   export MISP_API_KEY="your-api-key-here"
   ```

---

### AlienVault OTX

1. Register for a free account at [https://otx.alienvault.com](https://otx.alienvault.com)
2. Log in and go to **Settings** (click your profile icon)
3. Select **API Key** from the menu
4. Copy your API key
5. Set it in your environment:
   ```bash
   export OTX_API_KEY="your-otx-key-here"
   ```

---

### NVD (National Vulnerability Database)

1. Go to [https://nvd.nist.gov/developers](https://nvd.nist.gov/developers)
2. Click **Request an API Key**
3. Fill in the registration form
4. Wait for approval (usually automatic within minutes)
5. Copy your API key from the confirmation email
6. Set it in your environment:
   ```bash
   export NVD_API_KEY="your-nvd-key-here"
   ```

---

### VirusTotal

1. Create an account at [https://www.virustotal.com](https://www.virustotal.com)
2. Go to your profile settings
3. Navigate to **API Key**
4. Copy your API key
5. Set it in your environment:
   ```bash
   export VIRUSTOTAL_API_KEY="your-key-here"
   ```

**Note:** Free tier has rate limits of 4 lookups/minute, 500/day. Rate limiting is hardcoded at 4 req/min in the collector.

---

## Neo4j Remote Connection

For connecting to a remote Neo4j server instead of localhost:

### Option 1: Environment Variables (Recommended)

```bash
# Set these before running EdgeGuard
export NEO4J_URI="bolt://your-neo4j-server.com:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-secure-password"
export NEO4J_DATABASE="neo4j"  # Optional — explicit database name (multi-DB has been default since Neo4j 4.x)
```

### Option 2: Connection Types

| Type | URI Format | Use Case |
|------|------------|----------|
| Local | `bolt://localhost:7687` | Default local development |
| Remote (TCP) | `bolt://hostname:7687` | Single remote server, no TLS |
| Remote (TLS, system CA) | `bolt+s://hostname:7687` | Single remote server with strict TLS |
| Remote (TLS, self-signed) | `bolt+ssc://hostname:7687` | Single remote server with self-signed cert |
| Cluster (auto-routing) | `neo4j://hostname:7687` (or `neo4j+s://` for TLS) | Neo4j 5.x cluster — replaces the deprecated `bolt+routing://` scheme (removed in driver 5.x; this repo pins `neo4j~=5.27`). |

### Option 3: Docker Compose

If using Docker Compose for Neo4j:

```yaml
services:
  neo4j:
    # Track the production pin in the repo's top-level docker-compose.yml.
    # Project moved to Neo4j CalVer in 2025; current pin: 2026.03.1-community.
    image: neo4j:2026.03.1-community
    environment:
      - NEO4J_AUTH=neo4j/your-secure-password
    ports:
      - "7687:7687"
      - "7474:7474"
```

---

## Environment Variable Summary

| Variable | Description | Default |
|----------|-------------|---------|
| `MISP_URL` | MISP server URL | *(required, no default — Compose example: `https://misp.local`)* |
| `MISP_API_KEY` | MISP API authentication | *(required)* |
| `EDGEGUARD_API_KEY` | EdgeGuard REST API auth (production-required; `EDGEGUARD_ALLOW_UNAUTH=true` only for local dev) | *(required in production)* |
| `OTX_API_KEY` | AlienVault OTX API key | *(optional)* |
| `NVD_API_KEY` | NVD API key | *(optional)* |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key (used by `src/collectors/abuseipdb_collector.py`) | *(optional)* |
| `THREATFOX_API_KEY` | ThreatFox API key (used by `src/collectors/global_feed_collector.py`) | *(optional)* |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | *(optional)* |
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | *(required, no default)* |
| `NEO4J_DATABASE` | Neo4j database name | `neo4j` |
| `EDGEGUARD_SSL_VERIFY` | Enable SSL verification for HTTPS (MISP, collectors). Fallback: `SSL_VERIFY` if unset/empty. Not used: `SSL_CERT_VERIFY`. | `true` |

---

## Security Best Practices

1. **Never commit API keys to version control**
   - Use environment variables or `.env` files
   - Add `credentials/` to `.gitignore`

2. **Use different keys for different environments**
   - Development: Limited-scope test keys
   - Production: Dedicated production keys

3. **Rotate keys regularly**
   - Set calendar reminders for key rotation
   - Revoke old keys promptly

4. **Restrict key permissions when possible**
   - MISP: Use read-only keys for collection
   - OTX: Free tier is sufficient for most use cases

5. **Enable SSL in production**
   ```bash
   export EDGEGUARD_SSL_VERIFY=true
   ```


---

_Last updated: 2026-04-26 — PR-N33 docs audit: replaced deprecated `bolt+routing://` with `neo4j://` cluster URI scheme (driver 5.x); fixed `MISP_URL` "default" claim (it's required, no built-in default); added `EDGEGUARD_API_KEY`, `ABUSEIPDB_API_KEY`, `THREATFOX_API_KEY`, `VIRUSTOTAL_API_KEY` to the env-var summary; added `bolt+s://` / `bolt+ssc://` rows for TLS variants. Prior: 2026-03-17._
