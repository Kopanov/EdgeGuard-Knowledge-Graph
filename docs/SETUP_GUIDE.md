# EdgeGuard setup guide (for new operators)

This document is for people **setting up EdgeGuard for the first time** without prior project context. It explains **what** gets installed, **how** pieces connect, and **in which order** to run things.

---

## Start here — then read these next (operator path)

**You are reading step 1.** Follow this order so install, orchestration, and first pipeline run stay coherent:

| Step | Document | What you get |
|------|-----------|----------------|
| **1** | **This guide** ([SETUP_GUIDE.md](SETUP_GUIDE.md)) | Install Compose or venv, `.env`, MISP/Neo4j connectivity, health checks, first UI URLs |
| **2** | [**AIRFLOW_DAGS.md**](AIRFLOW_DAGS.md) | DAG names, CLI, **`docker compose up -d airflow`** after a `.env` change, import errors, task troubleshooting, MISP→Neo4j issues |
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

Full doc map: [docs/README.md](README.md). Every setting: [CONFIGURATION.md](CONFIGURATION.md); every command: [CLI.md](CLI.md).

**One-page skim before step 1:** [README.md](../README.md) (quick start, ports, the 730-day baseline).

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
- **Tiny dev / smoke test:** ~**8 GB+ RAM** is enough.
- **Full 730d baseline** (the baseline loaded on 2026-10-16 has about 550K nodes and 2.7M relationships): Neo4j alone wants **12 GB heap + 8 GB pagecache** under load (8 GB transaction limit, ~25 GB typical RSS, 32 GB container limit — the baseline-capable profile of [`DOCKER_SETUP_GUIDE.md`](DOCKER_SETUP_GUIDE.md)). With the Airflow limit of **12 GB** (`AIRFLOW_MEMORY_LIMIT=12g`), its Postgres' 2 GB and the API and GraphQL services' 512 MB each, the container limits add up to about **47 GB**, so plan **~48 GB host RAM** (more if MISP or the monitoring stack runs on the same host). On a smaller host, use DOCKER_SETUP_GUIDE's smaller option (8 GB heap, ~21 GB typical RSS, 28 GB container limit). See [`DOCKER_SETUP_GUIDE.md`](DOCKER_SETUP_GUIDE.md) "Recommended Neo4j memory profiles" + [`MEMORY_TUNING.md`](MEMORY_TUNING.md).

For a **large Neo4j heap**, clean-slate volume resets, and MISP-on-Docker-desktop patterns, use [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) alongside this section.

### 3.2 Get the code and create `.env`

```bash
git clone https://github.com/Kopanov/EdgeGuard-Knowledge-Graph.git
cd EdgeGuard-Knowledge-Graph
cp .env.example .env && chmod 600 .env
```

**`./install.sh`** (§ 3.4) generates **`EDGEGUARD_API_KEY`**, **`AIRFLOW_API_AUTH_JWT_SECRET`** and **`AIRFLOW_FERNET_KEY`** whenever one of them is blank, so a copy like the one above gets them on its first run. It never replaces a value set on any line of **`.env`** (also one above the template's commented line) or a variable exported in the shell, which Compose prefers to **`.env`**; when a later blank line overrides a value set earlier (Compose uses the last assignment), it says so and leaves **`.env`** as it is. It generates **`GRAFANA_ADMIN_PASSWORD`** (used by `docker-compose.monitoring.yml`) only when it creates **`.env`** itself. **`.env`** keeps its mode: after writing a secret, the installer warns when other users can read the file (`chmod 600 .env`). Without the installer, set these yourself together with the variables of § 3.3.

Edit **`.env`** before the first start: Neo4j takes its password from **`NEO4J_PASSWORD`** on the first start only (while its data volume is empty), and a later change in **`.env`** does not change it. On the Docker path, **`./install.sh`** replaces the template value **`changeme`** with a generated password while neither the Neo4j data volume nor the `edgeguard_neo4j` container exists. It keeps the value and prints a warning once one of them exists, when Docker cannot tell, or when **`NEO4J_PASSWORD`** is exported in the shell. **Inside Docker**, services talk to Neo4j as **`bolt://neo4j:7687`** — that is already set in **`docker-compose.yml`** via `x-common-env`; your **`.env`** should still define **`NEO4J_PASSWORD`** (and any other secrets) — Compose substitutes them into the stack.

### 3.3 Minimum variables to set (Compose)

| Variable | Why |
|----------|-----|
| **`NEO4J_PASSWORD`** | Required — Neo4j auth (no insecure default in Compose) |
| **`MISP_URL`** | Full base URL of your MISP (e.g. `https://misp.company.internal`) |
| **`MISP_API_KEY`** | MISP auth key (same as in MISP UI → automation) |
| **`EDGEGUARD_API_KEY`** | Set a **strong random** value for the EdgeGuard REST API (Compose expects it for the `api` / `graphql` services) |
| **`AIRFLOW_API_AUTH_JWT_SECRET`** | Required. One stable JWT signing secret for the Airflow scheduler and API server (`python3 -c "import secrets; print(secrets.token_urlsafe(64))"`); when it is empty the Airflow API server fails to start (`ValueError: The value api_auth/jwt_secret must be set!`) |

**Strongly recommended:**

| Variable | When |
|----------|------|
| **`AIRFLOW_FERNET_KEY`** | Before relying on Airflow Connections / encrypted fields. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| **`AIRFLOW_POSTGRES_PASSWORD`** | Non-default password for metadata DB in production (must stay URL-safe for the SQLAlchemy URI — avoid `@`, `#`, `/`, `?` in the password) |
| **`EDGEGUARD_SSL_VERIFY=false`** | Only if MISP uses a **private CA** / self-signed cert **and** you accept the risk in dev. **`SSL_VERIFY=false`** works only as a **fallback** when **`EDGEGUARD_SSL_VERIFY`** is unset/empty. **`SSL_CERT_VERIFY`** is ignored by EdgeGuard. On the Compose stack **`EDGEGUARD_SSL_VERIFY`** is always set (default `true`), so only **`EDGEGUARD_SSL_VERIFY`** takes effect there. |

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

1. Create **`.env`** from **`.env.example`** (mode 600) if it is missing and generate **`GRAFANA_ADMIN_PASSWORD`** in that case; generate a blank **`EDGEGUARD_API_KEY`**, **`AIRFLOW_API_AUTH_JWT_SECRET`** or **`AIRFLOW_FERNET_KEY`** in every case, unless **`.env`** sets a value on another line or the variable is exported in the shell (**`.env`** is rewritten in place, so a symlinked **`.env`** stays a symlink and keeps its mode); on the Docker path, replace **`NEO4J_PASSWORD=changeme`** before Neo4j's first start  
2. **`docker compose build`** (API image + **Airflow image** from **`Dockerfile.airflow`**)  
3. **`docker compose up -d`**
4. Wait up to **`EDGEGUARD_INSTALL_WAIT_SEC`** seconds (default 300) for the services and name any that are not healthy, with a pointer to **`docker compose logs`** (a one-shot service that exited with an error is listed with its exit code; when **`docker compose ps`** fails, the health is reported as not checked). It does not wait for `api` and `graphql` while **`MISP_API_KEY`** is a placeholder (empty, `your-misp-api-key-here`, `changeme` or `YOUR_API_KEY_HERE`): they do not start until **`MISP_URL`** and **`MISP_API_KEY`** are set in **`.env`** (then run **`docker compose up -d`**), and the installer says so. Services that are still not healthy after the wait leave the exit status at 0 (after a first install **`.env`** usually still needs editing); when **`docker compose up -d`** fails, the installer checks the services once, prints the summary and exits with that command's status

When **`install.sh`** creates **`.env`**, it starts the stack in the same run with the template MISP values: **`api`** and **`graphql`** refuse the placeholder **`MISP_API_KEY`** and restart until **`MISP_URL`** and **`MISP_API_KEY`** are set. Set them (§ 3.2, § 3.3) and run **`docker compose up -d`**.

If you change **`requirements-airflow-docker.txt`** or **`Dockerfile.airflow`**, rebuild Airflow:

```bash
docker compose build airflow && docker compose up -d airflow
```

After **any** change to **`.env`**, restart services that read it (at least **Airflow**, often **api** + **graphql**):

```bash
docker compose up -d --force-recreate api graphql airflow
# (`docker compose restart` is NOT enough after a .env change — it keeps the old values)
```

### 3.5 URLs to open (default ports)

| Service | URL |
|---------|-----|
| Neo4j Browser | http://localhost:7474 |
| Airflow UI | http://localhost:8082 |
| REST API health | http://localhost:8000/health |
| GraphQL | http://localhost:4001/graphql |

First Airflow login: user **`admin`**. The password is printed in **`docker compose logs airflow`** on the first start only. Afterwards: **`docker exec edgeguard_airflow cat /opt/airflow/simple_auth_manager_passwords.json.generated`** (the file is in the persistent `airflow_db` volume).

### 3.6 Verify connectivity

With **`.env` loaded** in your shell (or `export` vars manually):

```bash
cd EdgeGuard-Knowledge-Graph
set -a && source .env && set +a   # bash/zsh
export NEO4J_URI=bolt://localhost:7687   # .env names the Compose service, which resolves only inside the Compose network
python src/health_check.py
```

You want **MISP** and **Neo4j** checks to pass. **`MISP_URL`** must also be reachable from the host for this check (a name that resolves only inside the Docker network fails here). If MISP fails with SSL errors, align **`EDGEGUARD_SSL_VERIFY`** with your cert policy and restart services.

The same applies to the `edgeguard` CLI on the host. Its Airflow commands (`dag`, and the DAG list of `preflight` and `doctor`) also need **`AIRFLOW_API_PASSWORD`**: inside the `airflow` container the CLI reads the password file the Simple auth manager generates, while on the host `preflight` warns "Could not query DAG list" without it. `doctor`'s NATS and memory-setting lines read variables Compose does not forward to `airflow`, so check those from the host. Without a host Python environment, run the CLI in the container instead: `docker compose exec airflow python /opt/airflow/src/edgeguard.py preflight` ([CLI.md](CLI.md)).

Optional: **`edgeguard doctor`** / **`edgeguard validate`** after `pip install -e ".[api]"` or from a venv that has the project on `PYTHONPATH` (see § 4).

### 3.7 Run the pipeline in Airflow (first time)

1. In the Airflow UI: **DAGs** → ensure **no import errors** (see also: `docker compose exec airflow airflow dags list-import-errors`).  
2. Run **`misp_health_check`** path: open DAG **`edgeguard_pipeline`** (or baseline) and confirm the **`misp_health_check`** task succeeds (the baseline DAG also runs **`source_key_check`**) — proves Airflow can reach **MISP** (**API + DB**; workers optional unless **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`**).  
3. For a **full historical load** (long-running): trigger **`edgeguard_baseline`** once. For a **smaller test**, see [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) (`EDGEGUARD_BASELINE_DAYS`, limits, restart Airflow).  
4. **MISP → Neo4j:** tasks like **`full_neo4j_sync`** / **`run_neo4j_sync`** need **Neo4j APOC** (enabled in Compose Neo4j service). If sync logs **“No events”** but MISP has `EdgeGuard-…` events, confirm deployed **`src/run_misp_to_neo4j.py`** matches the repo (discovery: **`/events/index`** + client filter; **`Accept: application/json`** on the sync session; **`restSearch`** only as fallback). See [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) and [MISP_SOURCES.md](MISP_SOURCES.md).

**Schedules and task IDs:** [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md).

---

## 4. Path B — Python / venv (no Docker)

Requires **Python 3.12+** (same as `pyproject.toml` and GitHub Actions). Apache Airflow 3.3 supports **3.10–3.14** upstream; this repo tests on **3.12** only.

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

**Airflow (optional):** Install the Airflow extra: **`pip install -e '.[airflow]'`** (`apache-airflow[postgres]~=3.3` + `apache-airflow-providers-standard~=1.5`; the Compose image is `apache/airflow:3.3.2-python3.12`). Configure **`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`**. Point **`AIRFLOW__CORE__DAGS_FOLDER`** at the repository's **`dags/`** and **`AIRFLOW__CORE__PLUGINS_FOLDER`** at **`plugins/`** (the DAG-run listener `edgeguard_dag_run_state.py`) instead of copying them. The DAG then imports **`src/`** from the repository (`EDGEGUARD_BASE_DIR`, default the parent of the DAG folder), and **`./install.sh --update`** updates what Airflow runs. If you copy instead, re-copy **`dags/`**, **`src/`** and **`plugins/`** after every update. After **`airflow db migrate`** and before unpausing the DAGs, create the collector pool once: **`airflow pools set edgeguard_collectors 4 "Collector tasks of all DAGs"`** (every collector task of every DAG runs in this pool, which bounds how many collectors run at once; without it the collector tasks are never scheduled — see [AIRFLOW_DAGS.md § Collector pool: setup and resizing](AIRFLOW_DAGS.md#collector-pool-setup-and-resizing)). Compose creates it on every start of the **`airflow`** service. The Compose stack runs `airflow standalone` (Airflow 3.x), which runs the scheduler, the API server, the DAG processor and the triggerer in one process; Airflow 3 has no `airflow webserver` command, and EdgeGuard does not start a separate `airflow api-server` service. This venv path is more manual; prefer Compose for orchestration.

**CLI:** `python src/run_pipeline.py --baseline` or `edgeguard` after editable install. For 730d baseline launches see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md).

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
- **`airflow` service:** **`AIRFLOW_MEMORY_LIMIT`** (default **12g**, the `airflow` service's `deploy.resources.limits.memory` in `docker-compose.yml`) — raise if **`full_neo4j_sync`** gets **SIGKILL (-9)**. Scheduler tuning: `docker-compose.yml` sets the Airflow 3 options **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT`** (3600 s; Airflow default 300 s) and **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT_DETECTION_INTERVAL`** (60 s; Airflow default 10 s), both overridable in `.env`. Airflow 3 ignores the Airflow 2 names (**`SCHEDULER_ZOMBIE_TASK_THRESHOLD`**, **`LOCAL_TASK_JOB_HEARTBEAT_SEC`**, **`ZOMBIE_DETECTION_INTERVAL`**), which it renamed without an alias (see [HEARTBEAT.md](HEARTBEAT.md)).
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

On the venv path, **`--update`** pulls and re-installs the package; Airflow runs the new code only when its DAG and plugin folders point at the repository (§ 4), otherwise re-copy **`dags/`**, **`src/`** and **`plugins/`**.

On a Compose stack, **`--update`** writes the pulled commit into **`.env`** as **`EDGEGUARD_GIT_SHA`** (**`scripts/record_deployed_commit.sh`**) before it rebuilds; both `/health` responses report it as `git_sha`. Run the update only when no **`edgeguard_baseline`** run is in progress: it recreates the containers, which kills the running tasks, and if the rebuild fails after the pull, the old container keeps running and re-parses the new **`./dags`**.

Without git (tarball): replace files manually, record the release's commit with **`scripts/record_deployed_commit.sh <commit>`** (when it is unknown, delete the `EDGEGUARD_GIT_SHA=` line of `.env`, so `/health` reports `null` instead of an earlier commit), then **`docker compose build && docker compose up -d --force-recreate`**, which rebuilds every image (the `api` and `graphql` images contain `src/`) and recreates every container (or **`./install.sh --python`**).

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

The `edgeguard` commands, the `make` targets and the operator scripts: [CLI.md](CLI.md).

---

## 9. Troubleshooting (quick)

| Symptom | What to check |
|---------|----------------|
| Compose fails on **`NEO4J_PASSWORD is required`** | Set **`NEO4J_PASSWORD`** in **`.env`** |
| Airflow tasks: **MISP connection** / DNS errors | **`MISP_URL`** must resolve **inside** the Airflow container (compose default **`misp.local`** often fails); use the MISP service URL on a **shared Docker network** — see **`.env.example`** / **[MISP_SOURCES.md](MISP_SOURCES.md)** |
| **Long task or sync failed for missing heartbeats** | The scheduler fails a task whose last heartbeat is older than **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT`** (Airflow default **300 s**; **`docker-compose.yml`** sets **3600 s**). Check the value with `docker compose exec airflow airflow config get-value scheduler task_instance_heartbeat_timeout`; after a change in `.env`, recreate the container with `docker compose up -d airflow`. See **[HEARTBEAT.md](HEARTBEAT.md)** |
| **SSL certificate verify failed** (MISP) | `requests` and PyMISP trust the `certifi` bundle only, not the system store: corporate CA → a bundle named by **`REQUESTS_CA_BUNDLE`** (pip install; `docker-compose.yml` does not forward it); dev self-signed → **`EDGEGUARD_SSL_VERIFY=false`** + restart |
| Sync **0 events** | MISP has `EdgeGuard-…` event titles? Deployed **`run_misp_to_neo4j.py`** matches the repo? **`EDGEGUARD_MISP_EVENT_SEARCH`** |
| **`Unknown function 'apoc.coll.toSet'`** | Enable APOC on Neo4j |
| **`ModuleNotFoundError: neo4j` / `pymisp` in Airflow** | Rebuild Airflow image: **`docker compose build airflow`** — deps come from **`Dockerfile.airflow`**, not manual pip in the container |
| **API / GraphQL crash loop:** **`PermissionError: ... '/app/src/query_api.py'`** (or **`graphql_api.py`**) | Image runs as **`edgeguard` (uid 1001)** and cannot read files that **`COPY src/`** leaves root-owned with tight modes (**600**). The repository's **`Dockerfile`** runs **`chown -R edgeguard:edgeguard /app/src`**; rebuild **`edgeguard-kg`** from it without cache — **`docker compose build api graphql --no-cache`** |
| **`full_neo4j_sync` / MISP→Neo4j exits -9 (SIGKILL)** mid-run | Usually **container memory**, not a Python traceback: host can have free RAM while **Docker's cgroup** limit is hit. Check **`docker inspect edgeguard_airflow --format '{{.State.OOMKilled}}'`** and **`docker stats`**. Compose defaults **`AIRFLOW_MEMORY_LIMIT=12g`** for **airflow** (the `airflow` service's `deploy.resources.limits.memory` in `docker-compose.yml`); raise in **`.env`** or lower **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** / **`EDGEGUARD_REL_BATCH_SIZE`**. On **Docker Desktop**, raise the **VM memory** cap too. See **[HEARTBEAT.md](HEARTBEAT.md)**. |

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

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The documentation map is docs/README.md, with links to CONFIGURATION.md and CLI.md; § 3.6 names the Airflow API password a host shell needs, which the README carried.
- 2026-10-22 — `certificate verify failed` (MISP): `requests` and PyMISP trust the `certifi` bundle only; a corporate CA goes into a bundle named by `REQUESTS_CA_BUNDLE`.
- 2026-10-19 — `install.sh` waits for the services after `docker compose up -d` and names those that are not healthy instead of always reporting success; it recognises the `MISP_API_KEY` placeholders, and after a failed `docker compose up -d` prints the summary and keeps that command's exit status.
- 2026-10-19 — `install.sh` generates a blank `EDGEGUARD_API_KEY`, `AIRFLOW_API_AUTH_JWT_SECRET` or `AIRFLOW_FERNET_KEY` on every run (a `.env` prepared before the first run kept them blank and the stack did not start), rewrites `.env` in place so a symlinked `.env` stays a symlink, creates it with mode 600 (also `make .env`), and replaces `NEO4J_PASSWORD=changeme` before Neo4j's first start (the first start locked the template password in, and the documented edit afterwards left the stack waiting on an unhealthy Neo4j). A value set on any line of `.env` or exported in the shell (also `NEO4J_PASSWORD`) is never replaced; the Neo4j check also treats an existing `edgeguard_neo4j` container as started and reads the project name without python3; `EDGEGUARD_ENV` is compared without regard to case, as in `is_production_env`; generated secrets reach awk through the environment, not its command line; the installer warns when other users can read `.env`; the commented template lines are matched with `grep -E`, because BSD grep (macOS) never matched the earlier pattern.
- 2026-10-18 — The tarball update recreates every container (`docker compose up -d --force-recreate`) after rebuilding every image; the deployed commit is recorded in `.env` as `EDGEGUARD_GIT_SHA` (`./install.sh --update` runs `scripts/record_deployed_commit.sh`; a tarball deploy passes the commit to it).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text describes current behaviour only; upgrade steps for kept installs moved to the appendix.
- 2026-10-17 — An empty `AIRFLOW_API_AUTH_JWT_SECRET` stops the API server from starting; the reading-order table names `docker compose up -d airflow` after a `.env` change.
- 2026-10-17 — Corrected against the code: `install.sh` generates the four secrets only when it creates `.env`; `AIRFLOW_API_AUTH_JWT_SECRET` among the minimum variables; host RAM for a 730-day baseline from the container limits (about 47 GB, plan ~48 GB); `pip install -e '.[airflow]'`; venv path points the DAG and plugin folders at the repository; host health check sets `NEO4J_URI=bolt://localhost:7687`; first Airflow login and the `misp_health_check` / `source_key_check` task names; `EDGEGUARD_SSL_VERIFY` always set on Compose; symbol pointers instead of compose line numbers.
- 2026-10-16 — Collector pool `edgeguard_collectors`: created before unpausing the DAGs on the venv path and on every start by Compose; create it before the first update to the pool code, and update a Compose stack only when no baseline runs.
- 2026-10 — `docker-compose.yml` sets the Airflow 3 heartbeat-timeout names (Airflow 3 ignored the Airflow 2 names it set before); Airflow upgraded from 3.2 to 3.3.2.
- 2026-04-26 — Venv Airflow install corrected to Airflow 3; `AIRFLOW_MEMORY_LIMIT` default 12g; RAM split into tiny dev and full baseline; links to `BASELINE_LAUNCH_CHECKLIST.md` and `MEMORY_TUNING.md`.
- 2026-04-15 — Airflow upgraded from 2.11 to 3.2 to resolve 16 open 2.11.x CVEs.
- 2026-04-06 — Compose `x-common-env` and scheduler tuning documented.
