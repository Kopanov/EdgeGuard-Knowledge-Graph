# EdgeGuard Environments and Recommended Setup

EdgeGuard is designed to run in multiple environments (local dev, staging, production, edge devices). This document explains how to use the `EDGEGUARD_ENV` flag and how to set up a clean Python/conda environment for best practice deployments.

---

## 1. Environment flag: `EDGEGUARD_ENV`

`EDGEGUARD_ENV` decides whether the REST and GraphQL APIs run in production mode:

```bash
export EDGEGUARD_ENV="dev"   # non-production labels: dev, development, local, staging, test
```

- The check is fail-closed (`config.is_production_env()`): only `dev`, `development`, `local`, `staging` and `test` are non-production. Unset or empty is treated as **production**, and so is every other value — `stage`, `prod` and `edge` included.
- In production the REST and GraphQL APIs refuse to start without `EDGEGUARD_API_KEY`, whatever `EDGEGUARD_ALLOW_UNAUTH` says; `/docs` and `/redoc` are off, `/openapi.json` is served to key holders only, and GraphQL introspection is blocked. In non-production an API without a key starts only on a loopback bind, or with `EDGEGUARD_ALLOW_UNAUTH=1`.
- `config.EDGEGUARD_ENV` (default `dev`, printed below) is only a label for logs; the security gate does not use that default.

**Suggested values:**

- `dev` – local development on your laptop.
- `staging` – staging/pre‑production environment (not `stage`, which counts as production).
- `prod` – production deployment.

An edge device / gateway deployment runs as production unless it is given one of the non-production labels.

You can see the current label in Python via:

```python
# Requires src/ on PYTHONPATH (the editable `pip install -e .` does this;
# alternately: PYTHONPATH=src python -c "from config import EDGEGUARD_ENV; print(EDGEGUARD_ENV)").
from config import EDGEGUARD_ENV
print(EDGEGUARD_ENV)
```

---

## 2. Recommended Python / conda environment

To keep dependencies clean and reproducible, use a dedicated environment per project/deployment.

**Version:** EdgeGuard requires **Python 3.12+** (`requires-python` in `pyproject.toml`, CI, and `Dockerfile`). Apache Airflow **3.3** supports Python 3.10–3.14 upstream; this repository standardizes on 3.12 for a single supported interpreter line.

**Pinned component versions** (explicit and verifiable at runtime):

| Component | Pinned in | Recommended | Verified by |
|---|---|---|---|
| Neo4j server | `docker-compose.yml` `neo4j:` image | `2026.03.x-community` (CalVer) | `edgeguard doctor` |
| Neo4j Python driver | `requirements.txt`, `requirements-airflow-docker.txt` | `~=5.27` (5.x driver is wire-compat with 2026.x server per [Neo4j compat matrix](https://neo4j.com/developer/kb/neo4j-supported-versions/)) | `edgeguard doctor` |
| Apache Airflow | `Dockerfile.airflow` `FROM apache/airflow:` | `3.3.2-python3.12` | `edgeguard doctor` |
| PyMISP | `requirements.txt`, `requirements-airflow-docker.txt` | `~=2.4` | `edgeguard doctor` |
| MISP server | (operator-controlled deploy) | `2.4.x` | `edgeguard doctor` |
| CA bundle `certifi` | `requirements.txt`, `requirements-airflow-docker.txt`, `pyproject.toml`, `Dockerfile.airflow` | `>=2026.10.19` (earlier releases bundle emSign roots whose intermediate CA keys were compromised, GHSA-6q48-6c7w-9gw2) | `tests/test_pre_refeed_audit.py::test_every_dependency_list_sets_the_certifi_floor`; CI image scan (Trivy) |
| `pip`, `uv` in the Airflow image | `Dockerfile.airflow` (upgraded on top of the base; the base's `prek` hook runner is removed) | `pip>=26.2.2` (it vendors certifi 2026.10.19, GHSA-6q48-6c7w-9gw2), `uv>=0.13.4` (its bundled CA store, GHSA-hq85-5cpj-mr62) | CI image scan (Trivy) |

The single source of truth for the comparison logic is `src/version_compatibility.py::RECOMMENDED_VERSIONS`. `edgeguard doctor` and `edgeguard validate` capture the actual running versions and warn on drift. A regression test (`tests/test_version_compatibility.py::test_recommended_*_matches_*_pin`) fails CI when a pin file and the recommended-versions table disagree. The last two rows are not in `RECOMMENDED_VERSIONS`: their test and the CI image scan check them.

### 2.1 Create a conda environment (recommended)

```bash
# Create a new environment for EdgeGuard
conda create -n edgeguard_env python=3.12

# Activate it
conda activate edgeguard_env
```

Then install EdgeGuard with the extras you need:

```bash
# From the project root
pip install .[api,monitoring]

# If you also want Airflow integration:
pip install .[api,monitoring,airflow]
```

This keeps your EdgeGuard dependencies isolated from your system Python and other projects.

### 2.2 Using virtualenv instead of conda

If you prefer `venv`:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install .[api,monitoring]
```

---

## 3. Putting it all together for an "edge" deployment

On an edge device / gateway, a typical setup looks like this:

```bash
# 1. Create and activate an isolated environment
conda create -n edgeguard_env python=3.12
conda activate edgeguard_env

# 2. Install EdgeGuard with only the features you need
pip install .[api,monitoring]

# 3. Set environment flags and credentials
#    (an unrecognised label such as "edge" counts as production: the APIs need EDGEGUARD_API_KEY)
export EDGEGUARD_ENV="edge"
export EDGEGUARD_API_KEY="$(openssl rand -hex 32)"
export MISP_URL="https://your-misp-server:8443"
export MISP_API_KEY="your-misp-api-key"
export NEO4J_URI="bolt://your-neo4j-server:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-strong-password"
export EDGEGUARD_SSL_VERIFY=true

# 4. Start the API / pipeline as needed
python src/query_api.py   # via uvicorn in production
python src/run_pipeline.py --stix-flow
```

For production, you would typically run these via a process manager (systemd, Docker, Kubernetes) and inject the environment variables there instead of exporting them manually.

---

## 4. Service connectivity — Docker, Kubernetes, VMs, or bare metal

EdgeGuard does **not** require Docker. The same Python code paths read **`NEO4J_URI`**, **`MISP_URL`**, **`NEO4J_USER`**, **`NEO4J_PASSWORD`**, **`NEO4J_DATABASE`**, and **`EDGEGUARD_SSL_VERIFY`** (for HTTPS/MISP and outbound collectors). Point those at whatever hostnames your deployment uses.

| Topology | Typical `NEO4J_URI` | Typical `MISP_URL` | Note |
|----------|--------------------|--------------------|------|
| All-in-one Docker Compose | `bolt://neo4j:7687` (service DNS) | `https://misp` or external URL from `.env` | Compose sets `x-common-env`; override for external MISP. |
| App on host, DB in Docker | `bolt://localhost:7687` (published port) | `https://localhost:8443` | Match published ports. |
| Kubernetes | `bolt://neo4j.namespace.svc:7687` or `neo4j+s://…` | `https://misp.example.internal` | Use **stable DNS** for the pod’s network view. |
| Managed Neo4j (Aura, etc.) | `neo4j+s://xxxx.databases.neo4j.io` | (unchanged) | Use the URI the provider gives; the official driver accepts `neo4j+s` / `bolt+s`. |
| Split data plane | Any reachable Bolt host | Any reachable HTTPS MISP | Each EdgeGuard process must reach MISP and Neo4j from **its own** network namespace. |

**Robustness**

- **No hardcoded Docker hostnames** in `src/` for Neo4j/MISP — defaults are `localhost` for dev only; production should always set env vars.
- **TLS for MISP/feeds**: controlled by **`EDGEGUARD_SSL_VERIFY`** (keep `true` in production). Fallback: **`SSL_VERIFY`** if `EDGEGUARD_SSL_VERIFY` is unset/empty. **`SSL_CERT_VERIFY`** is not used.
- **Neo4j multi-database**: **`NEO4J_DATABASE`**.
- **Neo4j APOC**: required for sync regardless of Docker — install/allow APOC on whatever runs Neo4j (see `docs/SETUP_GUIDE.md`).

**Gaps / things operators must handle**

1. **Reachability**: If Airflow runs in Docker but MISP is on the host, `https://localhost:8443` from *inside* the container is wrong — use the host gateway, ingress URL, or service name your platform documents.
2. **Neo4j custom CA / mTLS**: The client uses `GraphDatabase.driver(self.uri, auth=…)` without extra SSL config. Standard `neo4j+s://` with a **public** CA works; **private CAs** may require JVM/Python trust store configuration on the host; there are no env flags for explicit trust material.
3. **NATS**: The `NATSClient` helper exists for ResilMesh-style messaging; callers pass server URLs in code. No single **`NATS_SERVERS`** env var is wired through all entrypoints, so treat NATS as integration-specific.
4. **Airflow**: DAG tasks use the same env as the Airflow worker/scheduler container; ensure **`MISP_URL` / `NEO4J_*`** are set there, not only on your laptop shell. With **EdgeGuard `docker-compose.yml`**, Airflow’s metadata DB is **PostgreSQL** (`airflow_postgres`); override defaults via **`AIRFLOW_POSTGRES_*`** in `.env` if needed. **`EDGEGUARD_SSL_VERIFY`** is passed via **`x-common-env`** so Airflow, API, and GraphQL all see the same value; if it were missing from the Airflow service, `config.SSL_VERIFY` would default to **`true`** even when `.env` had `false` for other tooling.
5. **MISP→Neo4j sync RAM**: The sync uses **Python-side chunked merges** (default **500** items per chunk via **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**). Inter-batch throttling is the separate **`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`** (default **5.0s**) on the MISP-push side; there is no inter-chunk pause on the Neo4j-merge side. Large events are deferred end-of-sync at **`EDGEGUARD_MAX_EVENT_ATTRIBUTES`** (default **50000**). With Docker Compose, the **airflow** service has a **memory limit** (**`AIRFLOW_MEMORY_LIMIT`**, default **12g** in `docker-compose.yml`). Events with 100K+ attributes require **8-12GB** due to PyMISP loading the full event JSON. Lower to 4g only for small test deployments. **`0`** or **`all`** for chunk size forces a **single pass** (OOM risk).

---

## 5. MISP sync tuning + baseline mutex

These four env vars are optional — the code uses the defaults below —
but operators tuning a slow MISP host or running parallel baselines
should know them. All four are in `.env.example`.

| Env var | Default | Purpose |
|---|---|---|
| `EDGEGUARD_MISP_PUSH_BATCH_SIZE` | `500` | Attributes per MISP push batch (`MISPWriter.push_items` default; the adaptive scaling lowers it on large events). Lower on memory-constrained MISP hosts that answer HTTP 500 on large batches. |
| `EDGEGUARD_MISP_RETRY_COOLDOWN_SEC` | `15.0` | Seconds between failed-event retry passes. Gives MISP time to recover from transient 5xx. |
| `EDGEGUARD_BASELINE_LOCK_PATH` | `checkpoints/baseline_in_progress.lock` | Sentinel held by a running baseline: the `edgeguard_baseline` DAG run (from `baseline_acquire_lock`; `edgeguard baseline` triggers that DAG) or an in-process `run_pipeline.py --baseline`. While another run holds it, the scheduled collectors and the sync DAG's `run_neo4j_sync` / `build_relationships` / `run_enrichment_jobs` skip. |
| `EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` | `172800` (48 h, above the baseline DAG's 32 h `dagrun_timeout`) | Max age before a stale lock is auto-cleared (e.g. after a crash on a different host — the PID-liveness check only works on the same host). |

See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) for the wider set of Airflow-related
variables, and [MIGRATIONS.md](MIGRATIONS.md) for the operator runbook that
references the baseline lock.

## 6. Summary checklist

- [ ] `EDGEGUARD_ENV` set appropriately (`dev`, `staging`, `prod`; unset = production).
- [ ] Dedicated Python/conda environment created for EdgeGuard.
- [ ] Dependencies installed via `pip install .[...]` with the right extras for your use case.
- [ ] All credentials provided via environment variables (no secrets in code).
- [ ] From each runtime (host, container, K8s pod), `MISP_URL` and `NEO4J_URI` resolve and are reachable; Neo4j has **APOC** loaded (`python src/health_check.py`).

---

_Last updated: 2026-10-22_

## History

- 2026-10-22 — Pinned versions list the CA bundle `certifi` (`>=2026.10.19`) and the Airflow image's `pip` and `uv`, upgraded past the emSign CA advisories.
- 2026-10-17 — Main text describes current behaviour only; version history moved here; heading levels start at the title.
- 2026-10-17 — Corrected against the code: `EDGEGUARD_ENV` is the fail-closed production gate (`config.is_production_env`: unset, empty, `stage`, `edge` and any value outside dev / development / local / staging / test are production, so the APIs require `EDGEGUARD_API_KEY`); the edge recipe sets the key; suggested values `dev` / `staging` / `prod`; MISP push batch default 500; the baseline lock is held by the `edgeguard_baseline` DAG run (or `run_pipeline.py --baseline`) and makes the scheduled collectors and sync writes skip, max age 172800 s (48 h); Airflow 3.3.2.
- 2026-10 — Airflow image 3.2.0 → 3.3.2 (security update).
- 2026-04-26 — `from config import …` requires `src/` on `PYTHONPATH` (or an editable install); removed an unverified inter-chunk pause from the `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` description.
- 2026-04-15 — MISP sync tuning and baseline mutex env vars documented.
- 2026-04 — Airflow upgraded from 2.11 to 3.2; Neo4j server from 5.26.x to the 2026.03 CalVer line.
