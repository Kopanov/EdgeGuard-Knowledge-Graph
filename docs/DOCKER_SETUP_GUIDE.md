# Docker workstation setup (high-RAM / clean slate)

This guide is an **operator checklist** for running the full EdgeGuard Compose stack on a **powerful workstation** (large Neo4j heap, optional external MISP). It complements the main path in [SETUP_GUIDE.md](SETUP_GUIDE.md); read that first for concepts and ports.

**Related:** [MISP_SOURCES.md](MISP_SOURCES.md) (how `MISP_URL` and `EDGEGUARD_MISP_HTTP_HOST` interact), [HEARTBEAT.md](HEARTBEAT.md) / [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) (scheduler tuning, OOM).

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose v2) with enough **RAM allocated to the Docker VM** for Neo4j + Airflow + anything else you run.
- **Disk:** tens of GB free for images and volumes (Neo4j grows with data).
- **RAM:** there is no single magic number. If you give Neo4j a **12g heap and 8g pagecache** (the baseline-capable profile below: ~25g typical RSS in a **32g** container), the container limits of Neo4j (32g), Airflow (12g), its Postgres (2g) and the API and GraphQL services (512m each) add up to about **47g**: plan about **48g** for the host (and Docker VM), more if MISP runs on the same host. Smaller hosts should use smaller `NEO4J_*` values (see "If your host has < 32g RAM" below) or accept slower baselines.
- **Airflow image:** the repo’s **`Dockerfile.airflow`** extends **`apache/airflow:3.3.2-python3.12`** (see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)) — task code runs on **Python 3.12**. After changing the base tag, rebuild the **`edgeguard-airflow`** image (see [SETUP_GUIDE.md](SETUP_GUIDE.md)).

**Security:** put real passwords and API keys only in **`.env`** (never committed). Copy from [`.env.example`](../.env.example). Do not paste production secrets into chat or docs.

---

## 1. `.env` (project root)

Required and optional variables are documented in `.env.example`. For a **large Neo4j** stack, set **both** the JVM settings (via env vars consumed by Compose) and a matching container memory cap:

```bash
# Required — use your own secrets
NEO4J_PASSWORD=changeme
NEO4J_URI=bolt://neo4j:7687
MISP_URL=https://your-misp-hostname:443
MISP_API_KEY=your-misp-api-key-here

# Large Neo4j — RECOMMENDED for baseline-capable workstation (730-day
# historical window; the baseline loaded on 2026-10-16 has ~550K nodes,
# ~2.7M relationships).
#
# Memory math — IMPORTANT: tx_memory sets dbms.memory.transaction.total.max,
# the memory ALL running transactions together may use (heap + off-heap
# combined). It is a limit, NOT a separate region. So actual peak RSS:
#   12g heap (committed at startup, INITIAL=MAX)
# +  8g pagecache (committed at startup, off-heap)
# +  ~3-5g JVM/Bolt/threads/transaction off-heap
# = ~23-25g typical peak; ~28g extreme.
# container_limit=32g gives ~7g headroom — comfortable, no OOM risk.
#
# HEAP_INITIAL is EQUAL to HEAP_MAX per Neo4j Operations Manual ("set
# initial and max to the same value to avoid GC pauses caused by heap
# resizing"), so the heap does not resize mid-run.
# tx_memory 8g: build_relationships exceeds 4g on a populated graph
# (MemoryLimitExceededException on a 344K-node graph). Container 32g:
# 22g is too small for the working set.
NEO4J_HEAP_INITIAL=12g
NEO4J_HEAP_MAX=12g
NEO4J_PAGECACHE=8g
NEO4J_TX_MEMORY_MAX=8g              # dbms.memory.transaction.total.max: all running transactions together (a limit, not additive to heap)
NEO4J_CONTAINER_MEMORY_LIMIT=32g

# Baseline DAG (optional env overrides — see BASELINE_SMOKE_TEST.md)
EDGEGUARD_BASELINE_DAYS=730
EDGEGUARD_BASELINE_COLLECTION_LIMIT=0

# MISP TLS / vhost quirks (see MISP_SOURCES.md)
# EDGEGUARD_MISP_HTTP_HOST=localhost
# EDGEGUARD_SSL_VERIFY=false

# Airflow scheduler — long tasks (task heartbeat timeout). docker-compose.yml passes the
# Airflow 3 options to the airflow service, so they can be overridden here:
# AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT=3600 (Airflow default 300 s) and
# AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT_DETECTION_INTERVAL=60 (Airflow default 10).
# Airflow 3 ignores the Airflow 2 names (SCHEDULER_ZOMBIE_TASK_THRESHOLD,
# LOCAL_TASK_JOB_HEARTBEAT_SEC, ZOMBIE_DETECTION_INTERVAL), which it renamed without an alias.
# No Airflow 3.3.2 code reads task_instance_heartbeat_sec, the successor of
# LOCAL_TASK_JOB_HEARTBEAT_SEC, so compose does not set it. See HEARTBEAT.md.

# Airflow memory: default 12g for production (100K+ attribute events need 8-12GB).
# Lower to 4g only for small test deployments.
# AIRFLOW_MEMORY_LIMIT=12g
```

**Note:** A variable named `NEO4J_MEMORY` is **not** read by this repository. Use **`NEO4J_HEAP_MAX`**, **`NEO4J_PAGECACHE`**, and **`NEO4J_CONTAINER_MEMORY_LIMIT`** as above.

**`MISP_URL` from Compose services:**

- If MISP runs **in another container on the same Docker network**, prefer **`https://<container_name>:443`** (or the service DNS name Compose gives you), not a host-only name. Example pattern: `https://misp_misp_1:443` — **your** name may differ; use `docker network inspect …` if unsure.
- **`https://host.docker.internal:8443`** can work on **Docker Desktop** when MISP publishes **host port 8443 → container 443**, so EdgeGuard containers talk to the host-published port. Behavior on plain **Linux** Docker may differ; verify connectivity from inside the `airflow` container (`curl -vk …`).

---

## 2. Optional: relax Compose memory limits

`docker-compose.yml` sets **cgroup memory limits** on Neo4j and Airflow. Limits prevent one service from starving others but can trigger **OOM kills** if set too low.

- You can **raise** limits via `.env` (`NEO4J_CONTAINER_MEMORY_LIMIT`, `AIRFLOW_MEMORY_LIMIT`) without editing YAML.
- **Commenting out** entire `deploy.resources.limits` blocks (if you choose to edit YAML) removes caps — the JVM can still be bounded by **`NEO4J_HEAP_MAX`** / **`NEO4J_PAGECACHE`**, but the container may use more RSS and **swap/thrash** on an undersized host. That is a tradeoff, not a free win.

On some setups, Compose **ignores** `deploy` unless you use Swarm or a compatible backend; still treat documented limits as the intended contract for local dev.

### Recommended Neo4j memory profiles

> **Memory math note** (subtle but load-bearing): `NEO4J_TX_MEMORY_MAX` sets `dbms.memory.transaction.total.max`: the memory all running transactions together may use (heap + off-heap combined). It is a limit, NOT a separate memory region added on top. A per-transaction limit would be `db.memory.transaction.max`, which this stack does not set. Transactions using up to the 8g limit pull from the already-committed 12g heap; they do NOT add to the heap+pagecache budget. The "Working-set" column below reflects this: it's `heap + pagecache + off-heap-overhead`, not `heap + pagecache + tx_max`.

| Profile | Heap initial | Heap max | Pagecache | TX max | Container | Typical RSS peak | Headroom | Use case |
|---------|-------------|----------|-----------|--------|-----------|------------------|----------|----------|
| **Tiny dev** (compose defaults) | 512m | 2g | 1g | 4g | 8g | ~3g | 5g | Smoke tests, an empty container. Container default is **8g** (`${NEO4J_CONTAINER_MEMORY_LIMIT:-8g}`, the `neo4j` service's `deploy.resources.limits.memory` in `docker-compose.yml`). |
| **Mid box** | 4g | 4g | 4g | 4g | 16g | ~10g | 6g | Single-source incremental syncs |
| **Baseline-capable** (recommended; set these five in `.env` — `.env.example` lists them commented out, so without them the compose defaults of the Tiny dev row apply) | **12g** | 12g | 8g | 8g | **32g** | ~25g | 7g | Full 730-day baseline (~550K nodes on the baseline of 2026-10-16) |

Where the "Typical RSS peak" comes from for the baseline-capable profile:

```
   12g heap (committed at startup, INITIAL=MAX)
+   8g pagecache (committed at startup, off-heap)
+   1g JVM overhead (metaspace, code cache)
+ 0.5g Bolt protocol buffers
+ 0.5g thread stacks (under heavy concurrency)
+ 1-3g transaction off-heap (heavy build_relationships batches)
+ Lucene mmap (kernel pagecache, NOT counted in process RSS)
= ~23-25g typical, ~28g extreme
```

The 32g cgroup limit gives ~7g headroom over typical peak — well above Neo4j's own production-safe formula (`heap + pagecache + 2g JVM + 2g OS + ~2g for Bolt/threads/Lucene = ~28g`).

**Why the Baseline-capable values** (measured on `edgeguard_baseline` runs):

- `NEO4J_TX_MEMORY_MAX=8g`: with `4g`, `build_relationships` against a 344K-node graph exceeds the limit — Neo4j logs `MemoryLimitExceededException` and the subprocess hangs until the Airflow task timeout fires.
- `NEO4J_CONTAINER_MEMORY_LIMIT=32g`: typical RSS during a baseline (~25g) exceeds a 22g cgroup limit, an immediate OOM risk; 32g leaves ~7g headroom over the typical peak.
- `NEO4J_HEAP_INITIAL=12g` (= MAX): a smaller initial heap (4g with `HEAP_MAX=12g`) causes multiple stop-the-world JVM heap resizes during a baseline run as the heap grows to 12g. Neo4j's own [Operations Manual](https://neo4j.com/docs/operations-manual/current/performance/memory-configuration/) recommends: *"set the initial heap size and the maximum heap size to the same value to avoid GC pauses caused by heap resizing."*

**If your host has < 32g RAM** for the Neo4j container alone, drop the working set. Lossless options:
- `NEO4J_HEAP_INITIAL=NEO4J_HEAP_MAX=8g` + everything else the same → ~21g typical RSS, fits comfortably in a 28g container. Slightly worse query performance under heavy concurrent load, no OOM.
- Or `NEO4J_PAGECACHE=4g` → ~21g typical RSS, fits a 28g container. Pagecache helps repeat-query latency but is already 16× the typical graph size (~500MB raw); reducing it slows index-heavy scans but is acceptable on small test graphs.
- Going below `NEO4J_TX_MEMORY_MAX=8g` is NOT recommended — that total transaction-memory limit is what `build_relationships` needs for the `apoc.periodic.iterate` batches over a populated graph (4g is exceeded).
- Going below `NEO4J_HEAP_INITIAL=NEO4J_HEAP_MAX` (e.g. initial=4g, max=8g) is operational-debt-only — under steady load, the heap will quickly grow to max anyway, but you'll pay multiple GC pauses to get there. Prefer setting both to the same value.

---

## 3. Clean slate (volumes and state)

**Prefer** removing project volumes through Compose so names stay correct:

```bash
docker compose down -v
```

That drops named volumes declared in this compose file (`neo4j_data`, Airflow logs/db/postgres, etc.).

`docker compose down -v` does not touch the bind-mounted `./state` and `./checkpoints` directories (sync watermark, VirusTotal budget ledger, collector cursors, baseline lock). For a clean slate, also remove their contents while the stack is down: `rm -rf ./state/* ./checkpoints/*`. On Linux the files belong to the container user (uid 50000), so use `sudo`. Removing the VirusTotal ledger also resets the count of the day's VirusTotal lookups.

If you remove volumes **by name manually**, the prefix is **the Compose project name** (usually the **directory name** of the project). Commands such as `docker volume rm edgeguard-knowledge-graph_neo4j_data` only work when the project name matches. List what you have:

```bash
docker volume ls | grep -E 'neo4j|airflow'
```

**This repo stores Neo4j data in a named volume**, not a `neo4j_data/` folder in the repo root. A bare `rm -rf neo4j_data` is **unnecessary** for the default Compose path and can confuse operators who expect bind mounts.

---

## 4. Start the stack

```bash
scripts/record_deployed_commit.sh       # the deployed commit into .env (EDGEGUARD_GIT_SHA, reported by /health)
docker compose build                    # every image: Airflow and edgeguard-kg (api, graphql)
docker compose up -d --force-recreate
```

`scripts/record_deployed_commit.sh` writes the checked-out commit into `.env` as `EDGEGUARD_GIT_SHA` (on a release tarball, pass the commit: `scripts/record_deployed_commit.sh <commit>`). `docker compose build` builds the Airflow image and the `edgeguard-kg` image, into which `api` and `graphql` copy `src/` at build time; rebuilding only the Airflow image leaves REST, GraphQL and STIX on the old code. The `airflow` service creates the Airflow pool `edgeguard_collectors` on every start (every collector task runs in it); `docker compose logs airflow | grep 'collector pool'` shows `[edgeguard] collector pool edgeguard_collectors set to <n> slots` once it is set.

**Updating a running stack:** `./dags` is re-parsed live, but the pool is only created when the `airflow` container is recreated. (1) Pull; (2) only when no baseline is running (a recreate kills running tasks), run the three commands above: they rebuild every image and recreate every container, `metrics` included; (3) check the pool with `docker exec edgeguard_airflow airflow pools list`; (4) check the running commit: `curl -s http://127.0.0.1:8000/health | jq -r .git_sha` and `curl -s http://127.0.0.1:4001/health | jq -r .git_sha` print the commit `scripts/record_deployed_commit.sh` wrote. The value stays in `.env`, so a later `docker compose` command from any shell sees it unchanged and recreates no container because of it. Compose forwards `EDGEGUARD_GIT_SHA` to `api` and `graphql` only, so a changed value never recreates `airflow`. Do not export it in the shell: Compose prefers a shell value to `.env`, and a `docker compose up -d` from a shell with a different value recreates `api` and `graphql`.

Wait for healthchecks (often **~60s** for Neo4j/Airflow), then:

```bash
docker compose ps
```

---

## 5. MISP (you provide the instance)

EdgeGuard **does not** ship MISP in its main `docker-compose.yml`. You must run MISP (or point `MISP_URL` at an existing instance) yourself.

Any **`docker run …`** recipe is **image-specific**. In particular:

- **`MYSQL_HOST=localhost`** only works if **MySQL actually listens inside that same container** (all-in-one image). If MySQL is a **separate** container, the host must be the **service name** on the shared network (for example `db` or `mysql`), not `localhost`.
- Attach MISP to the **same user-defined bridge network** as EdgeGuard if you want **`MISP_URL=https://misp_container:443`**. The network name is typically **`<project_directory>_edgeguard_net`** — confirm with `docker network ls` and `docker inspect`.

After MISP is up, validate from the Airflow container (adjust URL):

```bash
docker compose exec airflow sh -c 'curl -vk "$MISP_URL" -o /dev/null'   # uses the container's MISP_URL
```

### MISP performance tuning (large baselines)

During baseline collection, MISP can receive **tens of thousands** of attributes in a single event (e.g. NVD pushes ~95K CVEs into one event). Under default Apache settings, this causes **memory exhaustion and timeouts** because each `POST /attributes/add` request spawns a PHP process that loads the full event context.

**1. Reduce Apache `MaxRequestWorkers`** (critical on hosts with ≤ 32 GB RAM):

```bash
# Inside the MISP container:
# Edit /etc/apache2/mods-enabled/mpm_prefork.conf
MaxRequestWorkers 25          # default 150 — far too many for large events
MaxConnectionsPerChild 500    # recycle workers to free leaked memory
```

Then restart Apache inside the container:

```bash
docker exec -it <misp_container> apachectl graceful
```

**Why:** Each Apache child handling a large event can consume 1–2 GB of RAM as CakePHP loads the full event context and all related models. With `MaxRequestWorkers 150`, the server can spawn 150 such processes simultaneously. At 25, peak concurrent RAM is capped at ~25–50 GB instead of ~150–300 GB.

**2. EdgeGuard pipeline throttling** (already configured in code):

The pipeline includes built-in throttling to pace writes to MISP:

| Env var | Default | Effect |
|---------|---------|--------|
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Seconds to pause between MISP push batches (500 attributes by default, fewer on very large events) and after every 50 attribute edits (NVD incremental updates, CISA KEV revisions, refreshes of re-reported indicators). Prevents rapid-fire POSTs from overwhelming Apache. |
| `EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC` | `2.0` | Seconds to pause between fetching consecutive MISP events during sync. Gives MISP time to free memory after serving large events. |
| `EDGEGUARD_MAX_EVENT_ATTRIBUTES` | `50000` | Events exceeding this attribute count are deferred to the end of sync. Smaller events (MITRE, CISA) process first so critical data lands even if a large event OOM-kills the worker. |

On **memory-constrained hosts** (≤ 16 GB for MISP), increase these:

```bash
# In .env
EDGEGUARD_MISP_BATCH_THROTTLE_SEC=10
EDGEGUARD_MISP_EVENT_FETCH_THROTTLE_SEC=5
```

**3. PHP `memory_limit` inside the container** (critical — distinct from Docker `mem_limit`):

Docker's `mem_limit: 8g` sets the *container* ceiling — Docker kills the container if total RSS exceeds 8 GB. But PHP has its own `memory_limit` in `php.ini`, defaulting to **2 GB** on the `coolacid/misp-docker` image. When MISP's `JSONConverterTool.php` loads a 95K-attribute event, it can exceed 2 GB of PHP heap *before Docker notices*, and PHP kills the process internally with `Fatal Error: Allowed memory size exhausted`.

Fix: the `docs/sources/MISP/docker-compose.yml` mounts `php-overrides.ini` at `/etc/php/7.4/fpm/conf.d/99-edgeguard.ini`, which sets `memory_limit = 8G` to match the container ceiling. That path matches `coolacid/misp-docker` (debian:bullseye-slim base, PHP 7.4 + php-fpm) — the conf.d location PHP scans on Debian-based images is `/etc/php/<version>/<sapi>/conf.d/`, NOT the `/usr/local/etc/php/conf.d/` used by the official `php:*` images.

If your MISP image ships a different PHP version (e.g. a future coolacid release on PHP 8.x), update the mount path in `docker-compose.yml` to match. **Always verify the override actually took effect:**

```bash
# 1. Find the PHP version your MISP image uses:
docker exec misp_misp_1 php -v
# 2. Verify the override loaded:
docker exec misp_misp_1 php -i | grep memory_limit
# Should show: memory_limit => 8G => 8G
# 3. If it still shows 2G, find the actual conf.d path PHP scans:
docker exec misp_misp_1 php -i | grep "Scan this dir"
# Then update the mount target in docker-compose.yml accordingly.
```

**4. Retry backoff:** MISP-facing operations use `retry_with_backoff(max_retries=4, base_delay=10.0)` — retries at **10s → 20s → 40s → 80s**. This gives MISP time to recover from memory pressure between retries. Read timeouts are set to **300s** (5 minutes) to accommodate large event processing.

**5. Signs of MISP memory pressure:**
- `ReadTimeout` or `ConnectionError` in pipeline logs
- MISP circuit breaker of the MISP → Neo4j sync opening: 3 consecutive recorded failures (failed MISP health checks or failed sync runs) in the same process, after which it stays open for an hour
- MISP container OOM-killed (check `docker inspect <container> | grep OOMKilled`)
- `dmesg | grep -i oom` on the host showing MISP processes killed

**6. Collector concurrency:** all collector tasks share the Airflow pool `edgeguard_collectors` (`EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4). Lower it if MISP workers still get killed (HTTP 502). After changing the value in `.env`, run `docker compose up -d airflow`, which recreates the container; `docker compose restart airflow` keeps the old value.

---

## 6. Checklist of common setup ideas

| Idea | Verdict |
|------|--------|
| Large Neo4j heap + pagecache for heavy baselines | **Reasonable** on a big machine if **Docker VM RAM** and **`NEO4J_CONTAINER_MEMORY_LIMIT`** stay above JVM + cache + overhead. |
| `NEO4J_MEMORY=12g` in `.env` | **Not used** by this repo — use **`NEO4J_HEAP_MAX`** / **`NEO4J_PAGECACHE`** / **`NEO4J_CONTAINER_MEMORY_LIMIT`** (wired in `docker-compose.yml`). |
| Commenting out memory limits | **Optional tradeoff** — avoids cgroup OOM from a low cap; does not remove JVM limits; can hide host RAM pressure. |
| Fixed volume names in `docker volume rm` | **Fragile** — depends on Compose **project name**; prefer **`docker compose down -v`**. |
| `rm -rf neo4j_data` | **Misaligned** with default **named volume** layout in this repo. |
| `MISP_URL=https://host.docker.internal:8443` | **Can work** on Docker Desktop with **published port 8443**; prefer **container DNS** when MISP is on **`edgeguard_net`**. |
| `docker run … harvarditsecurity/misp` with `MYSQL_HOST=localhost` | **Verify against that image’s documentation** — often wrong if MySQL is external. |

---

## 7. Where to go next

| Step | Document |
|------|-----------|
| First-time concepts and health URLs | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| DAG names, restart, task failures | [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) |
| Safe first baseline | [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) |
| Every setting | [CONFIGURATION.md](CONFIGURATION.md) |
| Full doc index | [docs/README.md](README.md) |

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — § 7 points to CONFIGURATION.md and to the documentation index docs/README.md, which replaced the README's documentation section.
- 2026-10-18 — § 4 builds every image and recreates every container (`docker compose build`, then `docker compose up -d --force-recreate`; the start command built only the Airflow image) and records the deployed commit in `.env` (`scripts/record_deployed_commit.sh` writes `EDGEGUARD_GIT_SHA`, which both `/health` responses report as `git_sha`).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Main text describes current behaviour only; the collector pool upgrade for a running stack moved to the appendix; § 6 renamed to "Checklist of common setup ideas".
- 2026-10-17 — Corrected against the code: `NEO4J_TX_MEMORY_MAX` sets `dbms.memory.transaction.total.max` (all running transactions together); Tiny dev TX max 4g; the baseline-capable values are commented out in `.env.example` and must be set in `.env`; host RAM from the container limits (about 47g, plan 48g); `docker compose down -v` keeps `./state` and `./checkpoints`; the update rebuilds every image; the MISP check uses the container's `MISP_URL`; the batch throttle also paces KEV revisions and indicator refreshes; the MISP circuit breaker opens after 3 recorded failures; node count of the 2026-10-16 baseline.
- 2026-10-16 — Collector pool `edgeguard_collectors`: created by the `airflow` service on every start; upgrade order for a running stack (pool before the pull, recreate only when no baseline runs); resizing by `docker compose up -d airflow`.
- 2026-10 — The compose file passes the Airflow 3 heartbeat-timeout names (Airflow 3 ignored the Airflow 2 names it passed before); Airflow image 3.2.0 → 3.3.2 to clear base-image CVEs.
- 2026-04-26 — Tiny dev container default corrected from 4g to 8g (the compose default).
- 2026-04-19 — Recommended Neo4j memory profiles added after an overnight baseline exceeded the limits: `NEO4J_TX_MEMORY_MAX` 4g → 8g, `NEO4J_HEAP_INITIAL` 4g → 12g (= MAX), `NEO4J_CONTAINER_MEMORY_LIMIT` 22g → 32g; the Airflow task timeout of that run (45 min) was too short.
- 2026-04 — Airflow image upgraded from 2.11.x to 3.2 (Airflow 2 → 3 migration).
