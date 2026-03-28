## How to Use API Keys Securely in EdgeGuard

This guide explains how to configure API keys and credentials for EdgeGuard **without ever hard-coding secrets** in the codebase.

---

### 1. General principles

- **No secrets in code**: All API keys and passwords are loaded from **environment variables** or a local, git‑ignored credentials file.
- **Different values per environment**:
  - Development: low‑privilege, test keys.
  - Production: dedicated keys with minimal required scopes.
- **Rotate regularly**: Plan periodic key rotation and remove old keys.

---

### 2. Core environment variables

Set these before running any EdgeGuard components:

```bash
# MISP
export MISP_URL="https://your-misp-server:8443"
export MISP_API_KEY="your-misp-api-key"          # REQUIRED

# Neo4j
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-strong-password"     # REQUIRED, no default
export NEO4J_DATABASE="neo4j"                    # Optional, Neo4j 5+

# SSL / TLS
export EDGEGUARD_SSL_VERIFY=true                 # default; set false ONLY for local self-signed dev
```

**Important:**

- `MISP_API_KEY` and `NEO4J_PASSWORD` are **required**; EdgeGuard will fail fast if they are missing.
- `EDGEGUARD_SSL_VERIFY` defaults to `true` in code to ensure secure production behavior.
- If `EDGEGUARD_SSL_VERIFY` is unset or empty, `SSL_VERIFY` is read the same way (`true`/`false`). `SSL_CERT_VERIFY` is **not** read — use `EDGEGUARD_SSL_VERIFY` (see `src/config.py`, `.env.example`).

You can store these in a `.env` file and load it via a process manager (systemd, Docker, etc.) but **never commit `.env` to git**.

---

### 3. Source‑specific API keys

Some collectors use additional external feeds. Configure them via environment variables:

```bash
# AlienVault OTX (optional but recommended if using OTX collector)
export OTX_API_KEY="your-otx-key"

# NVD
export NVD_API_KEY="your-nvd-key"

# VirusTotal
export VIRUSTOTAL_API_KEY="your-virustotal-key"
```

For VirusTotal you can optionally also use `credentials/api_keys.yaml` (git‑ignored by default) with:

```yaml
VIRUSTOTAL_API_KEY=your-virustotal-key
VIRUSTOTAL_RATE_LIMIT=4
```

The code prefers environment variables where present; the YAML file is a local convenience only.

---

### 4. API keys in development scripts

Some helper scripts (e.g. `run_with_env.sh`, `hourly_status.sh`, `setup.py`) are intended for **local development** and may show example `export` lines. To use them safely:

- Replace any example values with your own keys **locally**.
- Do **not** commit real keys to these files.
- Prefer referencing a `.env` or system environment instead of embedding values directly.

Before committing, always run a quick search for obvious secrets:

```bash
rg "API_KEY|PASSWORD|SECRET" .
```

---

### 5. Admin API security

The `/admin/query` endpoint in `query_api.py` is disabled by default. To enable it safely:

```bash
export EDGEGUARD_ENABLE_ADMIN_QUERY=true
export EDGEGUARD_ADMIN_TOKEN="a-long-random-admin-token"
```

Then, when calling the endpoint, pass:

```http
X-Admin-Token: a-long-random-admin-token
```

**Recommendations:**

- Only enable this endpoint in **trusted internal environments**.
- Protect it with network controls (VPN, firewall) and a strong token.

---

### 6. Summary checklist

- [ ] No API keys or passwords committed to git.
- [ ] `MISP_API_KEY` and `NEO4J_PASSWORD` set via environment.
- [ ] `EDGEGUARD_SSL_VERIFY=true` in production.
- [ ] Optional keys (`OTX_API_KEY`, `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`) configured if corresponding collectors are enabled.
- [ ] `/admin/query` enabled only when needed and protected with `EDGEGUARD_ADMIN_TOKEN` + network controls.



---

_Last updated: 2026-03-17_
