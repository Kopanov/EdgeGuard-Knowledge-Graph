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
| Remote | `bolt://hostname:7687` | Single remote server |
| Cluster | `bolt+routing://hostname:7687` | Neo4j Causal Cluster |

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
| `MISP_URL` | MISP server URL | `https://localhost:8443` |
| `MISP_API_KEY` | MISP API authentication | *(required)* |
| `OTX_API_KEY` | AlienVault OTX API key | *(optional)* |
| `NVD_API_KEY` | NVD API key | *(optional)* |
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

_Last updated: 2026-03-17_
