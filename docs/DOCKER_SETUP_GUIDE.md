# Docker workstation setup (high-RAM / clean slate)

This guide is an **operator checklist** for running the full EdgeGuard Compose stack on a **powerful workstation** (large Neo4j heap, optional external MISP). It complements the main path in [SETUP_GUIDE.md](SETUP_GUIDE.md); read that first for concepts and ports.

**Related:** [MISP_SOURCES.md](MISP_SOURCES.md) (how `MISP_URL` and `EDGEGUARD_MISP_HTTP_HOST` interact), [HEARTBEAT.md](HEARTBEAT.md) / [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) (scheduler tuning, OOM).

---

## Prerequisites

- **Docker Desktop** (or Docker Engine + Compose v2) with enough **RAM allocated to the Docker VM** for Neo4j + Airflow + anything else you run.
- **Disk:** tens of GB free for images and volumes (Neo4j grows with data).
- **RAM:** there is no single magic number. If you give Neo4j a **12g heap and 8g pagecache**, the host (and Docker VM) needs **well above 20g** just for that service, plus Airflow, Postgres, APIs, and optional MISP. A **32g** workstation is a reasonable target for that class of tuning; smaller hosts should use smaller `NEO4J_*` values or accept slower baselines.
- **Airflow image:** the repo’s **`Dockerfile.airflow`** extends **`apache/airflow:3.2.0-python3.12`** (upgraded from 2.11.x in the April 2026 Airflow 2→3 migration; see [AIRFLOW_DAGS.md § Airflow 2 to 3 upgrade](AIRFLOW_DAGS.md)) — task code runs on **Python 3.12**. After changing the base tag, rebuild the **`edgeguard-airflow`** image (see [SETUP_GUIDE.md](SETUP_GUIDE.md)).

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
# historical window, ~350K nodes, ~600K edges).
#
# Memory math — IMPORTANT: tx_memory is a CAP on transaction allocations
# (heap + off-heap combined), NOT a separate region. So actual peak RSS:
#   12g heap (committed at startup, INITIAL=MAX)
# +  8g pagecache (committed at startup, off-heap)
# +  ~3-5g JVM/Bolt/threads/transaction off-heap
# = ~23-25g typical peak; ~28g extreme.
# container_limit=32g gives ~7g headroom — comfortable, no OOM risk.
#
# HEAP_INITIAL is EQUAL to HEAP_MAX per Neo4j Operations Manual ("set
# initial and max to the same value to avoid GC pauses caused by heap
# resizing").
# 2026-04-19 (Vanko's overnight regression): bumped tx_memory 4g→8g
# (was hitting MemoryLimitExceededException during build_relationships
# on a 344K-node graph), container 22g→32g (was undersized at 22g for
# even the working set), and heap_initial 4g→12g (= MAX; no mid-run
# heap resizing).
NEO4J_HEAP_INITIAL=12g
NEO4J_HEAP_MAX=12g
NEO4J_PAGECACHE=8g
NEO4J_TX_MEMORY_MAX=8g              # Per-transaction CAP (heap+off-heap combined; not additive to heap)
NEO4J_CONTAINER_MEMORY_LIMIT=32g

# Baseline DAG (optional env overrides — see BASELINE_SMOKE_TEST.md)
EDGEGUARD_BASELINE_DAYS=730
EDGEGUARD_BASELINE_COLLECTION_LIMIT=0

# MISP TLS / vhost quirks (see MISP_SOURCES.md)
# EDGEGUARD_MISP_HTTP_HOST=localhost
# EDGEGUARD_SSL_VERIFY=false

# Airflow scheduler — long tasks (defaults already set in docker-compose.yml; override if needed)
# AIRFLOW__SCHEDULER__SCHEDULER_ZOMBIE_TASK_THRESHOLD=3600
# AIRFLOW__SCHEDULER__LOCAL_TASK_JOB_HEARTBEAT_SEC=30

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

> **Memory math note** (subtle but load-bearing): `NEO4J_TX_MEMORY_MAX` is a **CAP** on what a single transaction can allocate (heap + off-heap combined), NOT a separate memory region added on top. A heavy transaction allocating up to its 8g cap pulls from the already-committed 12g heap; it does NOT add to the heap+pagecache budget. The "Working-set" column below reflects this: it's `heap + pagecache + off-heap-overhead`, not `heap + pagecache + tx_max`.

| Profile | Heap initial | Heap max | Pagecache | TX max | Container | Typical RSS peak | Headroom | Use case |
|---------|-------------|----------|-----------|--------|-----------|------------------|----------|----------|
| **Tiny dev** (compose defaults) | 512m | 2g | 1g | 8g | 8g | ~3g | 5g | Smoke tests, an empty container. Container default is **8g** per `docker-compose.yml:121` (`${NEO4J_CONTAINER_MEMORY_LIMIT:-8g}`) after the PR-A bump from 4g. |
| **Mid box** | 4g | 4g | 4g | 4g | 16g | ~10g | 6g | Single-source incremental syncs |
| **Baseline-capable** (recommended; `.env.example` has these uncommented as the default) | **12g** | 12g | 8g | 8g | **32g** | ~25g | 7g | Full 730-day baseline + 350K-node graph |

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

**The Baseline-capable profile is what landed after the 2026-04-19 overnight regression** (Vanko's run of `edgeguard_baseline`):

- Old `NEO4J_TX_MEMORY_MAX=4g` was hit during `build_relationships` against a 344K-node graph — Neo4j logged `MemoryLimitExceededException` and the subprocess got stuck before Airflow's (separately-too-short) 45min timeout fired. Bumped to `8g`.
- Old `NEO4J_CONTAINER_MEMORY_LIMIT=22g` was undersized: typical RSS during baseline (~25g) exceeded the cgroup limit, immediate OOM risk. Bumped to `32g` for ~7g headroom over typical peak.
- Old `NEO4J_HEAP_INITIAL=4g` (with `HEAP_MAX=12g`) caused multiple stop-the-world JVM heap resizes during a baseline run as the heap grew from 4g to 12g. Bumped to `12g` (= MAX) per Neo4j's own [Operations Manual](https://neo4j.com/docs/operations-manual/current/performance/memory-configuration/) recommendation: *"set the initial heap size and the maximum heap size to the same value to avoid GC pauses caused by heap resizing."*

**If your host has < 32g RAM** for the Neo4j container alone, drop the working set. Lossless options:
- `NEO4J_HEAP_INITIAL=NEO4J_HEAP_MAX=8g` + everything else the same → ~21g typical RSS, fits comfortably in a 28g container. Slightly worse query performance under heavy concurrent load, no OOM.
- Or `NEO4J_PAGECACHE=4g` → ~21g typical RSS, fits a 28g container. Pagecache helps repeat-query latency but is already 16× the typical graph size (~500MB raw); reducing it slows index-heavy scans but is acceptable on small test graphs.
- Going below `NEO4J_TX_MEMORY_MAX=8g` is NOT recommended — that's the cap the 2026-04-19 baseline hit and is what `build_relationships` needs for the `apoc.periodic.iterate` batches over a populated graph.
- Going below `NEO4J_HEAP_INITIAL=NEO4J_HEAP_MAX` (e.g. initial=4g, max=8g) is operational-debt-only — under steady load, the heap will quickly grow to max anyway, but you'll pay multiple GC pauses to get there. Prefer setting both to the same value.

---

## 3. Clean slate (volumes and state)

**Prefer** removing project volumes through Compose so names stay correct:

```bash
docker compose down -v
```

That drops named volumes declared in this compose file (`neo4j_data`, Airflow logs/db/postgres, etc.).

If you remove volumes **by name manually**, the prefix is **the Compose project name** (usually the **directory name** of the project). A colleague’s commands like `docker volume rm edgeguard-knowledge-graph_neo4j_data` only work when the project name matches. List what you have:

```bash
docker volume ls | grep -E 'neo4j|airflow'
```

**This repo stores Neo4j data in a named volume**, not a `neo4j_data/` folder in the repo root. A bare `rm -rf neo4j_data` is **unnecessary** for the default Compose path and can confuse operators who expect bind mounts.

---

## 4. Start the stack

```bash
docker compose build airflow   # after clone or Python dep changes
docker compose up -d
```

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
docker compose exec airflow curl -vk “$MISP_URL” -o /dev/null
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
| `EDGEGUARD_MISP_BATCH_THROTTLE_SEC` | `5.0` | Seconds to pause between each batch of 500 attributes pushed to MISP. Prevents rapid-fire POSTs from overwhelming Apache. |
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
- Circuit breaker opening after 4 failed retries
- MISP container OOM-killed (check `docker inspect <container> | grep OOMKilled`)
- `dmesg | grep -i oom` on the host showing MISP processes killed

---

## 6. Sanity check: is the colleague checklist “correct”?

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
| Full doc index | [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) |

---

_Last updated: 2026-04-26 — PR-N33 docs audit: corrected "Tiny dev" container default 4g → 8g (matches `docker-compose.yml:121` `${NEO4J_CONTAINER_MEMORY_LIMIT:-8g}`).

Prior: 2026-04-19 — added Recommended Neo4j memory profiles table (Tiny dev / Mid box / Baseline-capable) after the 2026-04-19 overnight baseline regression. Baseline-capable profile bumped per Vanko's findings: `NEO4J_TX_MEMORY_MAX` 4g→8g, `NEO4J_HEAP_INITIAL` 4g→12g (= MAX per Neo4j Operations Manual; eliminates GC pauses from resizing), `NEO4J_CONTAINER_MEMORY_LIMIT` 22g→32g (adequate headroom over ~25g typical RSS peak). Memory-math note clarifies that `tx_memory` is a CAP on transaction allocations, not additive to heap+pagecache._
