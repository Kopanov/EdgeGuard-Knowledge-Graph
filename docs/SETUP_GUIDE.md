# EdgeGuard setup guide (for new operators)

This document is for people **setting up EdgeGuard for the first time** without prior project context. It explains **what** gets installed, **how** pieces connect, and **in which order** to run things.

---

## Start here — then read these next (operator path)

**You are reading step 1.** Follow this order so install, orchestration, and first pipeline run stay coherent:

| Step | Document | What you get |
|------|-----------|----------------|
| **1** | **This guide** ([SETUP_GUIDE.md](SETUP_GUIDE.md)) | Install Compose or venv, `.env`, MISP/Neo4j connectivity, health checks, first UI URLs |
| **2** | [**AIRFLOW_DAGS.md**](AIRFLOW_DAGS.md) | DAG names, CLI, **`docker compose restart airflow`**, import errors, task troubleshooting, MISP→Neo4j issues |
| **3** | [**BASELINE_SMOKE_TEST.md**](BASELINE_SMOKE_TEST.md) | Safe first **`edgeguard_baseline`** / variable tuning (short window, limits) before a multi-hour full load |

**After step 3**, open other docs **only when you need them** (avoid reading everything up front):

| Need | Read |
|------|------|
| “What do **200 / 500** mean?” | [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md) |
| **Large-RAM workstation**, Neo4j heap/pagecache via `.env`, clean slate volumes, MISP `docker run` caveats | [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) |
| MISP Docker networking, **`EDGEGUARD_MISP_HTTP_HOST`**, sync discovery | [MISP_SOURCES.md](MISP_SOURCES.md) |
| Full pipeline / file map | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Per-feed keys & behavior | [DATA_SOURCES.md](DATA_SOURCES.md), [COLLECTORS.md](COLLECTORS.md), [API_KEYS_SETUP.md](API_KEYS_SETUP.md) |
| ResilMesh shared Neo4j / ISIM | [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) |

Full doc map: [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md).

**One-page skim before step 1:** [README.md](../README.md) (quick start, ports, env table).

---

## 1. What you are deploying

EdgeGuard is a **pipeline**, not a single binary:

| Piece | Role |
|--------|------|
| **Collectors** (Python in `src/collectors/`) | Pull threat intel from feeds → push into **MISP** |
| **MISP** (your instance) | **Not** started by this repo — you provide URL + API key. Single staging area for normalized events |
| **Airflow** (optional but recommended) | Runs DAGs on a schedule: collectors → later **MISP → Neo4j** sync, enrichment |
| **Neo4j** | Knowledge graph (Indicators, CVEs, MITRE objects, …). Compose includes Neo4j; you can use an external cluster instead |
| **REST / GraphQL APIs** | Query the graph (ports **8000** / **4001** in Compose) |

**Typical data path:** `Feeds → MISP → Neo4j → APIs` (see [ARCHITECTURE.md](ARCHITECTURE.md)).

---

## 2. Choose an install path

| Path | Best for | You manage |
|------|-----------|------------|
| **A. Docker Compose (recommended)** | Production-like dev, demos, shared Neo4j + Airflow + APIs | Docker, `.env`, external MISP |
| **B. Python / venv only** | Lightweight dev, no Docker | Your own Neo4j + MISP URLs, optional local Airflow |

The repo **`install.sh`** defaults to **path A** when Docker Compose v2 is available.

---

## 3. Path A — Docker Compose (step by step)

### 3.1 Prerequisites on the host

- **Docker** + **Docker Compose v2** (`docker compose`, not legacy `docker-compose` only)
- **Git** (or a release tarball — see § 7)
- A running **MISP** instance (URL + auth key your org provides)
- ~**8 GB+ RAM** recommended if you run baseline collection + MISP→Neo4j sync (tune Neo4j/Airflow limits in `docker-compose.yml` if needed)

For a **large Neo4j heap**, clean-slate volume resets, and MISP-on-Docker-desktop patterns, use [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) alongside this section.

### 3.2 Get the code and create `.env`

```bash
git clone https://github.com/Kopanov/EdgeGuard-Knowledge-Graph.git
cd EdgeGuard-Knowledge-Graph
cp .env.example .env
```

Edit **`.env`** before or right after the first start. **Inside Docker**, services talk to Neo4j as **`bolt://neo4j:7687`** — that is already set in **`docker-compose.yml`** via `x-common-env`; your **`.env`** should still define **`NEO4J_PASSWORD`** (and any other secrets) — Compose substitutes them into the stack.

### 3.3 Minimum variables to set (Compose)

| Variable | Why |
|----------|-----|
| **`NEO4J_PASSWORD`** | Required — Neo4j auth (no insecure default in Compose) |
| **`MISP_URL`** | Full base URL of your MISP (e.g. `https://misp.company.internal`) |
| **`MISP_API_KEY`** | MISP auth key (same as in MISP UI → automation) |
| **`EDGEGUARD_API_KEY`** | Set a **strong random** value for the EdgeGuard REST API (Compose expects it for the `api` / `graphql` services) |

**Strongly recommended:**

| Variable | When |
|----------|------|
| **`AIRFLOW_FERNET_KEY`** | Before relying on Airflow Connections / encrypted fields. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| **`AIRFLOW_POSTGRES_PASSWORD`** | Non-default password for metadata DB in production (must stay URL-safe for the SQLAlchemy URI — avoid `@`, `#`, `/`, `?` in the password) |
| **`EDGEGUARD_SSL_VERIFY=false`** | Only if MISP uses a **private CA** / self-signed cert **and** you accept the risk in dev. **`SSL_VERIFY=false`** works only as a **fallback** when **`EDGEGUARD_SSL_VERIFY`** is unset/empty. **`SSL_CERT_VERIFY`** is ignored by EdgeGuard. |

**MISP in Docker on another compose network?**  
Airflow and collectors resolve **`MISP_URL`** from **inside** containers. `localhost` on the host ≠ MISP inside another stack. Use a **shared Docker network** or hostname both stacks know. Details: [MISP_SOURCES.md](MISP_SOURCES.md) § *MISP not reachable*, [ENVIRONMENTS.md](ENVIRONMENTS.md).

**Apache vhost / `Host` header:** If MISP only answers for a specific name, set **`EDGEGUARD_MISP_HTTP_HOST`** (no `https://`).

**MISP event vs attribute tags:** EdgeGuard events use **`EdgeGuard-{source}-{date}`** as the event name (e.g., `EdgeGuard-nvd-2026-03-29`). The event carries the **`EdgeGuard`** tag at event level. **Zone and source classification** lives on **attribute-level tags** (`zone:Finance`, `source:NVD`) — a single event can contain multi-zone attributes. See [MISP_SOURCES.md](MISP_SOURCES.md). Sector keyword scoring thresholds: **`EDGEGUARD_ZONE_DETECT_THRESHOLD`** / **`EDGEGUARD_ZONE_ITEM_THRESHOLD`** in **`.env.example`**.

### 3.4 Build and start

From the repo root:

```bash
./install.sh
```

This will:

1. Create **`.env`** from **`.env.example`** if missing  
2. **`docker compose build`** (API image + **Airflow image** from **`Dockerfile.airflow`**)  
3. **`docker compose up -d`**

If you change **`requirements-airflow-docker.txt`** or **`Dockerfile.airflow`**, rebuild Airflow:

```bash
docker compose build airflow && docker compose up -d airflow
```

After **any** change to **`.env`**, restart services that read it (at least **Airflow**, often **api** + **graphql**):

```bash
docker compose up -d --force-recreate api graphql airflow
# or simply:
docker compose restart airflow api graphql
```

### 3.5 URLs to open (default ports)

| Service | URL |
|---------|-----|
| Neo4j Browser | http://localhost:7474 |
| Airflow UI | http://localhost:8082 |
| REST API health | http://localhost:8000/health |
| GraphQL | http://localhost:4001/graphql |

First Airflow login: check **`docker compose logs airflow`** for the generated admin password (standalone image).

### 3.6 Verify connectivity

With **`.env` loaded** in your shell (or `export` vars manually):

```bash
cd EdgeGuard-Knowledge-Graph
set -a && source .env && set +a   # bash/zsh
python src/health_check.py
```

You want **MISP** and **Neo4j** checks to pass. If MISP fails with SSL errors, align **`EDGEGUARD_SSL_VERIFY`** with your cert policy and restart services.

Optional: **`edgeguard doctor`** / **`edgeguard validate`** after `pip install -e ".[api]"` or from a venv that has the project on `PYTHONPATH` (see § 4).

### 3.7 Run the pipeline in Airflow (first time)

1. In the Airflow UI: **DAGs** → ensure **no import errors** (see also: `docker compose exec airflow airflow dags list-import-errors`).  
2. Run **`misp_health_check`** path: open DAG **`edgeguard_pipeline`** (or baseline) and confirm the **preflight** task succeeds — proves Airflow can reach **MISP** (**API + DB**; workers optional unless **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`**).  
3. For a **full historical load** (long-running): trigger **`edgeguard_baseline`** once. For a **smaller test**, see [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) (`EDGEGUARD_BASELINE_DAYS`, limits, restart Airflow).  
4. **MISP → Neo4j:** tasks like **`full_neo4j_sync`** / **`run_neo4j_sync`** need **Neo4j APOC** (enabled in Compose Neo4j service). If sync logs **“No events”** but MISP has `EdgeGuard-…` events, confirm deployed **`src/run_misp_to_neo4j.py`** matches the repo (discovery: **`/events/index`** + client filter; **`Accept: application/json`** on the sync session; **`restSearch`** only as fallback). See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) and [MISP_SOURCES.md](MISP_SOURCES.md).

**Schedules and task IDs:** [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md).

---

## 4. Path B — Python / venv (no Docker)

Requires **Python 3.12+** (same as `pyproject.toml` and GitHub Actions). Apache Airflow 3.2 supports **3.10–3.14** upstream; this repo tests on **3.12** only. Airflow was bumped from 2.11 to 3.2 in April 2026 — see [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md#airflow-2-to-3-upgrade) if you are migrating an existing install.

For developers or minimal setups:

```bash
cd EdgeGuard-Knowledge-Graph
./install.sh --python          # creates .venv, pip installs project + deps
# or: make install-py
cp .env.example .env           # if not already present
# Edit .env: NEO4J_URI, NEO4J_PASSWORD, MISP_*, keys
set -a && source .env && set +a
python src/health_check.py
```

**Neo4j:** Use **`bolt://localhost:7687`** (or your server) in **`.env`**. Install **APOC** on that Neo4j — required for sync (see below).

**Airflow (optional):** Install **`apache-airflow[postgres]~=2.11`**, configure **`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`**, copy **`dags/`** into **`$AIRFLOW_HOME/dags`**, mount or copy **`src/`** so DAGs can import collectors. This is more manual; prefer Compose for orchestration.

**CLI:** `python src/run_pipeline.py --baseline` or `edgeguard` after editable install.

---

## 5. Neo4j + APOC (required for MISP → Neo4j)

Sync code uses APOC (`apoc.coll.toSet`, etc.). Without APOC, merges fail.

- **Compose:** `NEO4J_PLUGINS` and allowlisting are already set on the **`neo4j`** service.  
- **External Neo4j:** Install a matching APOC build and allowlist procedures per [Neo4j APOC docs](https://neo4j.com/labs/apoc/).

**Quick check** in Neo4j Browser: `RETURN apoc.coll.toSet([1,1,2]) AS x;`

---

## 6. Configuration: what actually matters

**Primary source of truth for running code:** **environment variables** loaded into the process — see **`src/config.py`** and **`.env.example`**. Docker Compose injects these into **api**, **graphql**, **airflow**, etc.

**Compose-specific (see `docker-compose.yml` header and service blocks):**

- **`x-common-env`:** includes **`NEO4J_URI=bolt://neo4j:7687`**, **`MISP_URL`** (override in **`.env`** if **`misp.local`** doesn’t resolve in containers), collector keys, sync tuning vars.
- **`airflow` service:** **`AIRFLOW_MEMORY_LIMIT`** (default **4g**) — raise if **`full_neo4j_sync`** gets **SIGKILL (-9)**; scheduler tuning **`AIRFLOW__SCHEDULER__SCHEDULER_ZOMBIE_TASK_THRESHOLD`**, **`LOCAL_TASK_JOB_HEARTBEAT_SEC`**, **`ZOMBIE_DETECTION_INTERVAL`** (defaults documented in [HEARTBEAT.md](HEARTBEAT.md)).
- **`api` / `graphql` images:** **`Dockerfile`** runs as **`edgeguard`** and **`chown`s `/app/src`** so Uvicorn can read modules (see troubleshooting table §9).

**Optional YAML / wizard:**

- **`python src/setup.py`** — may create **`credentials/config.yaml`**; useful for experiments, **not** required for the standard Docker path if **`.env`** is complete.  
- **`credentials/config.example.yaml`** — legacy / optional; Airflow DAGs and collectors in production are driven by **env** + Airflow Variables (**`BASELINE_*`**, etc.).

**Do not** assume any legacy config module alone drives Airflow — match what **`dags/edgeguard_pipeline.py`** imports (**`config`** from **`src`** with env).

---

## 7. Updates (git pull or tarball)

With git:

```bash
./install.sh --update              # pull + rebuild / refresh (auto Docker vs pip)
# or: make update
```

Without git (tarball): replace files manually, then **`docker compose build && docker compose up -d`** (or **`./install.sh --python`**).

---

## 8. Operational commands (cheat sheet)

```bash
docker compose ps
docker compose logs -f airflow
docker compose logs -f neo4j
docker compose down
docker compose up -d
```

**Neo4j check helper:** `src/check_neo4j.sh` expects Docker container **`edgeguard_neo4j`** and reads **`NEO4J_PASSWORD`** from **`.env`** in the repo root (or your environment). Prefer **`python src/health_check.py`** for a full MISP+Neo4j check.

---

## 9. Troubleshooting (quick)

| Symptom | What to check |
|---------|----------------|
| Compose fails on **`NEO4J_PASSWORD is required`** | Set **`NEO4J_PASSWORD`** in **`.env`** |
| Airflow tasks: **MISP connection** / DNS errors | **`MISP_URL`** must resolve **inside** the Airflow container (compose default **`misp.local`** often fails); use the MISP service URL on a **shared Docker network** — see **`.env.example`** / **[MISP_SOURCES.md](MISP_SOURCES.md)** |
| **NVD / long task or sync marked zombie** | **`docker-compose.yml`** sets **`SCHEDULER_ZOMBIE_TASK_THRESHOLD`** (default **3600**), **`LOCAL_TASK_JOB_HEARTBEAT_SEC`** (**30**), **`ZOMBIE_DETECTION_INTERVAL`** (**60**) on **airflow** — recreate container after pull; see **[HEARTBEAT.md](HEARTBEAT.md)** |
| **SSL certificate verify failed** (MISP) | Corporate CA → trust store; dev self-signed → **`EDGEGUARD_SSL_VERIFY=false`** + restart |
| Sync **0 events** | MISP has `EdgeGuard-…` event titles? Current **`run_misp_to_neo4j.py`**? **`EDGEGUARD_MISP_EVENT_SEARCH`** |
| **`Unknown function 'apoc.coll.toSet'`** | Enable APOC on Neo4j |
| **`ModuleNotFoundError: neo4j` / `pymisp` in Airflow** | Rebuild Airflow image: **`docker compose build airflow`** — deps come from **`Dockerfile.airflow`**, not manual pip in the container |
| **API / GraphQL crash loop:** **`PermissionError: ... '/app/src/query_api.py'`** (or **`graphql_api.py`**) | Image runs as **`edgeguard` (uid 1001)**; **`COPY src/`** was root-owned with tight modes (**600**). Rebuild **`edgeguard-kg`** from current **`Dockerfile`** (includes **`chown -R edgeguard:edgeguard /app/src`**) — **`docker compose build api graphql --no-cache`** |
| **`full_neo4j_sync` / MISP→Neo4j exits -9 (SIGKILL)** mid-run | Usually **container memory**, not a Python traceback: host can have free RAM while **Docker’s cgroup** limit is hit. Check **`docker inspect edgeguard_airflow --format '{{.State.OOMKilled}}'`** and **`docker stats`**. Compose defaults **`AIRFLOW_MEMORY_LIMIT=4g`** for **airflow**; raise in **`.env`** or lower **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** / **`EDGEGUARD_REL_BATCH_SIZE`**. On **Docker Desktop**, raise the **VM memory** cap too. See **[HEARTBEAT.md](HEARTBEAT.md)**. |

More: [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) troubleshooting, [COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md).

---

## 10. Security notes

- Never commit **`.env`** or real **`credentials/config.yaml`**.  
- Use strong **`NEO4J_PASSWORD`**, **`EDGEGUARD_API_KEY`**, **`AIRFLOW_POSTGRES_PASSWORD`**.  
- Keep **`EDGEGUARD_SSL_VERIFY=true`** in production where possible.

---

## 11. Next steps after a green health check

Follow the **same operator path** as at the top of this guide:

1. **Step 2 —** Open [**AIRFLOW_DAGS.md**](AIRFLOW_DAGS.md): confirm **`list-import-errors`** is clean, understand which DAG to trigger, preflight / worker env.  
2. **Step 3 —** Open [**BASELINE_SMOKE_TEST.md**](BASELINE_SMOKE_TEST.md): configure a **small** baseline (or use Airflow Variables + optional `EDGEGUARD_BASELINE_*` env), then trigger **`edgeguard_baseline`** or incremental DAGs as documented.  
3. **Verify data:** MISP events titled **`EdgeGuard-…`**, Neo4j sample queries — [**NEO4J_SAMPLE_QUERIES.md**](NEO4J_SAMPLE_QUERIES.md).  
4. **If limits confuse you:** [**COLLECTION_AND_SYNC_LIMITS.md**](COLLECTION_AND_SYNC_LIMITS.md).  
5. **ResilMesh / shared DB:** [**RESILMESH_INTEROPERABILITY.md**](RESILMESH_INTEROPERABILITY.md).

---

_Last updated: 2026-04-06 — Compose **`x-common-env`** / **`AIRFLOW_MEMORY_LIMIT`** / scheduler tuning; MISP preflight + index-based sync discovery; troubleshooting (zombie, SIGKILL, PermissionError)._
