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
export NEO4J_DATABASE="neo4j"                    # Optional — explicit database name (multi-DB default since Neo4j 4.x)

# SSL / TLS
export EDGEGUARD_SSL_VERIFY=true                 # default; set false ONLY for local self-signed dev
```

**Important:**

- `MISP_API_KEY` and `NEO4J_PASSWORD` are **required**; EdgeGuard will fail fast if they are missing.
- `EDGEGUARD_SSL_VERIFY` defaults to `true` in code to ensure secure production behavior.
- `true`, `1`, `yes` and `on` verify, `false`, `0`, `no` and `off` do not (any case; spaces, tabs and line breaks around the value are ignored); any other value, a non-breaking space around it included, keeps verification on and is logged as a warning. If `EDGEGUARD_SSL_VERIFY` is unset or blank, `SSL_VERIFY` is read by the same rule. `SSL_CERT_VERIFY` is **not** read — use `EDGEGUARD_SSL_VERIFY` (see `src/tls_verify.py`, `.env.example`).

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

For VirusTotal you can optionally also use `credentials/api_keys.yaml` (git‑ignored by default). Despite the extension the file is not parsed as YAML: `src/config.py` reads it line by line and accepts only lines that start with `VIRUSTOTAL_API_KEY=` or `VIRUSTOTAL_RATE_LIMIT=`, and only when `VIRUSTOTAL_API_KEY` is not set in the environment. A YAML-style `KEY: value` line is ignored, so such a file yields no key.

```
VIRUSTOTAL_API_KEY=your-virustotal-key
VIRUSTOTAL_RATE_LIMIT=4
```

The environment variable wins when present; the file is a local convenience only.

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

### 5.1 API + Airflow + monitoring secrets (production-required)

Beyond the data-source API keys above, production deployments need
several **infrastructure** secrets — all listed in `.env.example`:

| Secret | Purpose |
|---|---|
| `EDGEGUARD_API_KEY` | EdgeGuard REST and GraphQL API auth (FastAPI on `:8000` and `:4001`). Required in production, i.e. whenever `EDGEGUARD_ENV` is not `dev` / `development` / `local` / `staging` / `test` (unset counts as production), whatever `EDGEGUARD_ALLOW_UNAUTH` says. In those non-production envs it may be empty only with a loopback bind or `EDGEGUARD_ALLOW_UNAUTH=1`. |
| `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `EDGEGUARD_TRUSTED_MISP_ORG_NAMES` | Source-truthful timestamp creator-org allow-list (defends against MISP tag impersonation; see [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md)). |
| `AIRFLOW_API_AUTH_JWT_SECRET` | Airflow 3.x JWT signing key (`[api_auth] jwt_secret`, passed as `AIRFLOW__API_AUTH__JWT_SECRET`), shared by the scheduler and the API server. The option exists from Airflow 3 on; the Airflow 2.x `[webserver] secret_key` maps to `[api] secret_key`, not to this one. |
| `AIRFLOW_FERNET_KEY` | Airflow Fernet encryption for Variables / Connections. |
| `GRAFANA_ADMIN_PASSWORD` | Grafana admin login (default user is admin). |
| `PROMETHEUS_ADMIN_PASSWORD` | Placeholder only — nothing in the repository reads it (Prometheus basic auth needs your own web-config or proxy). |
| `EDGEGUARD_ADMIN_TOKEN` | `/admin/query` endpoint auth (when `EDGEGUARD_ENABLE_ADMIN_QUERY=true`). |

Generate strong values for all of these except the `PROMETHEUS_ADMIN_PASSWORD` placeholder — none have safe defaults. The `.env.example` file shows the variable names + recommended generation recipes (e.g. `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` for `AIRFLOW_FERNET_KEY`).

---

### 6. Summary checklist

- [ ] No API keys or passwords committed to git.
- [ ] `MISP_API_KEY` and `NEO4J_PASSWORD` set via environment.
- [ ] `EDGEGUARD_API_KEY`, `AIRFLOW_API_AUTH_JWT_SECRET`, `AIRFLOW_FERNET_KEY`, `GRAFANA_ADMIN_PASSWORD` set via environment (production).
- [ ] `EDGEGUARD_SSL_VERIFY=true` in production.
- [ ] Optional keys (`OTX_API_KEY`, `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `THREATFOX_API_KEY`) configured if corresponding collectors are enabled.
- [ ] `/admin/query` enabled only when needed and protected with `EDGEGUARD_ADMIN_TOKEN` + network controls.
- [ ] `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` / `_NAMES` populated for the MISP source-truthful timestamp defense.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — `EDGEGUARD_SSL_VERIFY` / `SSL_VERIFY`: the recognised values (`true`/`1`/`yes`/`on`, `false`/`0`/`no`/`off`, with only ASCII whitespace around the value ignored); any other value keeps TLS verification on with a warning.
- 2026-10-17 — Corrected the `credentials/api_keys.yaml` format (`KEY=value` lines, read only when `VIRUSTOTAL_API_KEY` is not set in the environment), the production rule for `EDGEGUARD_API_KEY`, the Airflow 3 option behind `AIRFLOW_API_AUTH_JWT_SECRET` and the unread `PROMETHEUS_ADMIN_PASSWORD`; the main text describes current behavior only and the change history is kept here.
- 2026-04-26 — Added § 5.1 on the API, Airflow and monitoring secrets required in production (including the creator-org allow-list of the MISP tag-impersonation defense) and aligned the § 6 checklist; the `credentials/api_keys.yaml` example was rewritten as a YAML mapping, which the 2026-10-17 entry reverts.
- 2026-03-17 — Earlier revision of the guide; no change details recorded.
