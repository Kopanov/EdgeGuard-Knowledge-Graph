## EdgeGuard Environments and Recommended Setup

EdgeGuard is designed to run in multiple environments (local dev, staging, production, edge devices). This document explains how to use the `EDGEGUARD_ENV` flag and how to set up a clean Python/conda environment for best practice deployments.

---

### 1. Environment flag: `EDGEGUARD_ENV`

EdgeGuard reads a simple environment flag:

```bash
export EDGEGUARD_ENV="dev"   # or "stage", "prod", "edge", etc.
```

- Default is `dev` if not set.
- Used to:
  - Make logs and monitoring easier to interpret.
  - Allow future environment‑specific behavior (e.g. different intervals or feature toggles) without changing code.

**Suggested values:**

- `dev`  – local development on your laptop.
- `stage` – staging/pre‑production environment.
- `prod` – production deployment.
- `edge` – edge device / gateway deployments (limited resources, closer to the sensors).

You can see the current environment in Python via:

```python
# Requires src/ on PYTHONPATH (the editable `pip install -e .` does this;
# alternately: PYTHONPATH=src python -c "from config import EDGEGUARD_ENV; print(EDGEGUARD_ENV)").
from config import EDGEGUARD_ENV
print(EDGEGUARD_ENV)
```

---

### 2. Recommended Python / conda environment

To keep dependencies clean and reproducible, use a dedicated environment per project/deployment.

**Version:** EdgeGuard requires **Python 3.12+** (`requires-python` in `pyproject.toml`, CI, and `Dockerfile`). Apache Airflow **3.2** (upgraded from 2.11 in April 2026 — see [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md)) supports Python 3.10–3.14 upstream; this repository standardizes on 3.12 for a single supported interpreter line.

**Pinned component versions** (PR #36 — Vanko's request to make these explicit and verifiable at runtime):

| Component | Pinned in | Recommended | Verified by |
|---|---|---|---|
| Neo4j server | `docker-compose.yml` `neo4j:` image | `2026.03.x-community` (CalVer; was 5.26.x before April 2026) | `edgeguard doctor` |
| Neo4j Python driver | `requirements.txt`, `requirements-airflow-docker.txt` | `~=5.27` (5.x driver is wire-compat with 2026.x server per [Neo4j compat matrix](https://neo4j.com/developer/kb/neo4j-supported-versions/)) | `edgeguard doctor` |
| Apache Airflow | `Dockerfile.airflow` `FROM apache/airflow:` | `3.2.0-python3.12` | `edgeguard doctor` |
| PyMISP | `requirements.txt`, `requirements-airflow-docker.txt` | `~=2.4` | `edgeguard doctor` |
| MISP server | (operator-controlled deploy) | `2.4.x` | `edgeguard doctor` |

The single source of truth for the comparison logic is `src/version_compatibility.py::RECOMMENDED_VERSIONS`. `edgeguard doctor` and `edgeguard validate` capture the actual running versions and warn on drift. A regression test (`tests/test_version_compatibility.py::test_recommended_*_matches_*_pin`) fails CI if anyone bumps a pin file without updating the recommended-versions table.

#### 2.1 Create a conda environment (recommended)

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

#### 2.2 Using virtualenv instead of conda

If you prefer `venv`:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install --upgrade pip
pip install .[api,monitoring]
```

---

### 3. Putting it all together for an "edge" deployment

On an edge device / gateway, a typical setup looks like this:

```bash
# 1. Create and activate an isolated environment
conda create -n edgeguard_env python=3.12
conda activate edgeguard_env

# 2. Install EdgeGuard with only the features you need
pip install .[api,monitoring]

# 3. Set environment flags and credentials
export EDGEGUARD_ENV="edge"
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

### 4. Service connectivity — Docker, Kubernetes, VMs, or bare metal

EdgeGuard does **not** require Docker. The same Python code paths read **`NEO4J_URI`**, **`MISP_URL`**, **`NEO4J_USER`**, **`NEO4J_PASSWORD`**, **`NEO4J_DATABASE`**, and **`EDGEGUARD_SSL_VERIFY`** (for HTTPS/MISP and outbound collectors). Point those at whatever hostnames your deployment uses.

| Topology | Typical `NEO4J_URI` | Typical `MISP_URL` | Note |
|----------|--------------------|--------------------|------|
| All-in-one Docker Compose | `bolt://neo4j:7687` (service DNS) | `https://misp` or external URL from `.env` | Compose sets `x-common-env`; override for external MISP. |
| App on host, DB in Docker | `bolt://localhost:7687` (published port) | `https://localhost:8443` | Match published ports. |
| Kubernetes | `bolt://neo4j.namespace.svc:7687` or `neo4j+s://…` | `https://misp.example.internal` | Use **stable DNS** for the pod’s network view. |
| Managed Neo4j (Aura, etc.) | `neo4j+s://xxxx.databases.neo4j.io` | (unchanged) | Use the URI the provider gives; the official driver accepts `neo4j+s` / `bolt+s`. |
| Split data plane | Any reachable Bolt host | Any reachable HTTPS MISP | Each EdgeGuard process must reach MISP and Neo4j from **its own** network namespace. |

**Robustness today**

- **No hardcoded Docker hostnames** in `src/` for Neo4j/MISP — defaults are `localhost` for dev only; production should always set env vars.
- **TLS for MISP/feeds**: controlled by **`EDGEGUARD_SSL_VERIFY`** (keep `true` in production). Fallback: **`SSL_VERIFY`** if `EDGEGUARD_SSL_VERIFY` is unset/empty. **`SSL_CERT_VERIFY`** is not used.
- **Neo4j multi-database**: **`NEO4J_DATABASE`**.
- **Neo4j APOC**: required for sync regardless of Docker — install/allow APOC on whatever runs Neo4j (see `docs/SETUP_GUIDE.md`).

**Gaps / things operators must handle**

1. **Reachability**: If Airflow runs in Docker but MISP is on the host, `https://localhost:8443` from *inside* the container is wrong — use the host gateway, ingress URL, or service name your platform documents.
2. **Neo4j custom CA / mTLS**: The client uses `GraphDatabase.driver(self.uri, auth=…)` without extra SSL config. Standard `neo4j+s://` with a **public** CA works; **private CAs** may require JVM/Python trust store configuration on the host or future support for explicit trust material (not yet first-class env flags).
3. **NATS**: The `NATSClient` helper exists for ResilMesh-style messaging; callers today pass server URLs in code. There is no single **`NATS_SERVERS`** env var wired through all entrypoints yet — treat NATS as integration-specific until standardized.
4. **Airflow**: DAG tasks use the same env as the Airflow worker/scheduler container; ensure **`MISP_URL` / `NEO4J_*`** are set there, not only on your laptop shell. With **EdgeGuard `docker-compose.yml`**, Airflow’s metadata DB is **PostgreSQL** (`airflow_postgres`); override defaults via **`AIRFLOW_POSTGRES_*`** in `.env` if needed. **`EDGEGUARD_SSL_VERIFY`** is passed via **`x-common-env`** so Airflow, API, and GraphQL all see the same value; if it were missing from the Airflow service, `config.SSL_VERIFY` would default to **`true`** even when `.env` had `false` for other tooling.
5. **MISP→Neo4j sync RAM**: The sync uses **Python-side chunked merges** (default **500** items per chunk via **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`**). Inter-batch throttling is the separate **`EDGEGUARD_MISP_BATCH_THROTTLE_SEC`** (default **5.0s**) on the MISP-push side; there is no inter-chunk pause on the Neo4j-merge side. Large events are deferred end-of-sync at **`EDGEGUARD_MAX_EVENT_ATTRIBUTES`** (default **50000**). With Docker Compose, the **airflow** service has a **memory limit** (**`AIRFLOW_MEMORY_LIMIT`**, default **12g** in `docker-compose.yml`). Events with 100K+ attributes require **8-12GB** due to PyMISP loading the full event JSON. Lower to 4g only for small test deployments. **`0`** or **`all`** for chunk size forces a **single pass** (OOM risk).

---

### 5. MISP sync tuning + baseline mutex (added 2026-04)

These four env vars were introduced with PRs #20, #23, and #28. They are
off-by-default — the code uses sensible fallbacks — but operators tuning
a slow MISP host or running parallel baselines should know they exist.
All four are also in `.env.example`.

| Env var | Default | Purpose |
|---|---|---|
| `EDGEGUARD_MISP_PUSH_BATCH_SIZE` | `1000` | Attributes per MISP POST. Lower on memory-constrained MISP hosts that 500 on large batches. |
| `EDGEGUARD_MISP_RETRY_COOLDOWN_SEC` | `15.0` | Seconds between failed-event retry passes. Gives MISP time to recover from transient 5xx. |
| `EDGEGUARD_BASELINE_LOCK_PATH` | `checkpoints/baseline_in_progress.lock` | Cross-process sentinel that blocks a manual `edgeguard baseline` run from racing the scheduled incremental DAG. |
| `EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` | `86400` (24h) | Max age before a stale lock is auto-cleared (e.g. after a crash on a different host — the PID-liveness check only works on the same host). |

See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) for the wider set of Airflow-related
variables introduced with the 3.2 upgrade, and [MIGRATIONS.md](MIGRATIONS.md)
for the operator runbook that references the baseline lock.

### 6. Summary checklist

- [ ] `EDGEGUARD_ENV` set appropriately (`dev`, `stage`, `prod`, `edge`, …).
- [ ] Dedicated Python/conda environment created for EdgeGuard.
- [ ] Dependencies installed via `pip install .[...]` with the right extras for your use case.
- [ ] All credentials provided via environment variables (no secrets in code).
- [ ] From each runtime (host, container, K8s pod), `MISP_URL` and `NEO4J_URI` resolve and are reachable; Neo4j has **APOC** loaded (`python src/health_check.py`).

---

_Last updated: 2026-04-26 — PR-N33 docs audit: clarified `from config import …` requires `src/` on PYTHONPATH (or editable install); removed unverified "3s pause between chunks" claim from `EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE` description (the only documented inter-batch throttle is `EDGEGUARD_MISP_BATCH_THROTTLE_SEC=5.0` on the MISP-push side). Prior: 2026-04-15 MISP sync tuning + baseline mutex env vars._
