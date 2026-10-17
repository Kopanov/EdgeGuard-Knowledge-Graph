# Memory & Sizing — EdgeGuard Knowledge Graph

> **Status:** production-ready. This is the operator reference for the
> `edgeguard doctor --memory` diagnostic and for the "what should this be
> set to?" questions of the EdgeGuard stack.

## Quick reference — recommended values

| Setting | Minimum | Recommended | Where to set |
|---|---|---|---|
| Neo4j heap (`NEO4J_HEAP_MAX` → `NEO4J_server_memory_heap_max__size`) | 4G | 8G | `.env` (`NEO4J_HEAP_MAX`) |
| Neo4j page cache (`NEO4J_PAGECACHE` → `NEO4J_server_memory_pagecache_size`) | 2G | 4G | `.env` (`NEO4J_PAGECACHE`) |
| Neo4j tx memory (`NEO4J_TX_MEMORY_MAX` → `NEO4J_dbms_memory_transaction_total_max`) | 4G | 8G | `.env` (`NEO4J_TX_MEMORY_MAX`) |
| MISP PHP `memory_limit` | 2048M | 4096M | MISP container (see [MISP_TUNING.md](MISP_TUNING.md)) |
| MISP PHP `max_execution_time` | 300 | 600+ | `php.ini` inside MISP container |
| Host RAM | 8G | 40G (about 48G for a 730-day baseline) | Hypervisor / host OS |

Run `edgeguard doctor --memory` to see your **actual** values vs these
recommendations side-by-side, with verdicts (`✓ ok` / `⚠ low` /
`✗ too low` / `? unknown`). The doctor applies the Minimum and
Recommended values of the three Neo4j rows; for host RAM it applies 8G
and 16G, and 16G is enough only for small test runs (see "Host RAM"
below). A 730-day baseline uses larger Neo4j values: heap 12G, page
cache 8G and transaction memory 8G in a 32G container (the
baseline-capable profile of [DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md),
listed commented out in `.env.example`).

## Why these numbers

The values come from failures observed under baseline load, not from
generic recommendations. Each subsection states the failure the
threshold prevents.

### Neo4j heap — 8G recommended

The 730-day baseline loaded on 2026-10-16 has about 550K nodes and 2.7M
relationships. Memory pressure shows up at:

- **Build-relationships subprocess** — runs 20 linking steps, most of
  them batched with `apoc.periodic.iterate`. At <4G heap, the batch
  transactions spill to disk + slow to a crawl.
- **`full_neo4j_sync` task** — reads ~all MISP attributes in 500-item
  chunks; per-chunk commit needs ~200MB working memory at peak graph
  density.

Symptom of under-provisioning: `OutOfMemoryError` in the Neo4j log,
build_relationships task killed by Airflow at the 5h timeout.

### Neo4j page cache — 4G recommended

Page cache caches the on-disk Neo4j store files (nodes, relationships,
properties). With 4G page cache and the 350K-node graph of April 2026,
~95% of common read queries were served from cache; below 2G, every read
hits disk and GraphQL/REST query latency spikes 10-50x.

### Neo4j tx memory — 8G recommended

`NEO4J_dbms_memory_transaction_total_max` (`.env`: `NEO4J_TX_MEMORY_MAX`)
is the per-instance cap on concurrent transaction memory. The
recommendation is 8G (the compose default is 4g), because a single batch
transaction inside `apoc.periodic.iterate` can exceed a 4G cap; that
crashes the entire build-relationships subprocess and leaves the graph
half-linked.

**Symptom to grep for:** `MemoryLimitExceededException` in the Neo4j
container log (`docker compose logs neo4j | grep MemoryLimitExceeded`).
If you see it, the cap was reached — either bump tx_memory or reduce
the per-batch size in `apoc.periodic.iterate` calls (less common; the
batch size is tuned to the recommended 8G).

### MISP PHP `memory_limit` — 4096M recommended (2048M on a 4-6 GB MISP host)

Each `edit-event` call loads the whole event for de-duplication, so
PHP-FPM workers run out of memory in `AppModel.php` once an event grows
large; the collector receives HTTP 500. On the 730-day baseline of
2026-04-19, run overnight with the default 512M `memory_limit`, this
happened once the NVD event grew past ~75K attributes, and ~14.7% of the
NVD attributes (13,620 of 92,620) were lost to MISP HTTP 500 errors.

Tier-1 collectors run sequentially, which halves the concurrent-write
pressure, but the per-event size cost is still load-dependent.
[MISP_TUNING.md](MISP_TUNING.md), the authoritative MISP tuning
reference, sets `memory_limit = 4096M` (2048M on a 4-6 GB MISP
host); the 512M default runs out of memory on events above 50K
attributes.

### MISP PHP `max_execution_time` — 600+ recommended

Large `edit-event` calls under load take 5-10 minutes. With the
default 300 s, PHP-FPM workers abort mid-write, which the collector
sees as HTTP 500. 600 s gives MISP enough headroom for the worst-case
write path.

### Host RAM — 40G recommended

The EdgeGuard compose stack alone has memory limits of about 23 GB with
its defaults (Neo4j container 8g, Airflow 12g, its Postgres 2g, API and
GraphQL 512m each). With the Neo4j values recommended here (20g
container, see below) the limits come to about 35 GB (plan 40 GB), and
with the 730-day profile (32g container) to about 47 GB. A baseline needs
Airflow's 8-12 GB for large MISP events ([HEARTBEAT.md](HEARTBEAT.md)).
MISP is not part of EdgeGuard's compose stack; on the same host it
needs at least 8 GB more ([MISP_TUNING.md](MISP_TUNING.md)). 16 GB is
enough only for small test runs with lowered limits; plan about 48 GB
for a 730-day baseline ([SETUP_GUIDE.md](SETUP_GUIDE.md) § 3.1). When
the services together need more than the host has, the OOM killer
eventually picks one of Neo4j or MISP and you get cascading failures
across the stack.

`docker-compose.yml` defaults are heap 2g, page cache 1g, transaction
total 4g and a container limit of 8g (`NEO4J_CONTAINER_MEMORY_LIMIT`).
Heap and page cache are below the minimums above, and `edgeguard doctor
--memory` reports them as too low (tx memory as low) until `.env` sets
larger values.

## How to set these values

### Neo4j (Docker Compose, the default)

Add to `.env` using the **operator-facing wrapper variables** (what
`docker-compose.yml` reads and forwards to Neo4j's internal config keys):

```bash
NEO4J_HEAP_MAX=8g
NEO4J_PAGECACHE=4g
NEO4J_TX_MEMORY_MAX=8g
NEO4J_CONTAINER_MEMORY_LIMIT=20g
```

The container limit must exceed heap + page cache + the JVM's off-heap
memory (about 3-5 GB under baseline load, per the memory math in
[DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md)). With 8g heap and 4g
page cache, 20g leaves headroom; the 8g compose default is too small
for these values. For a 730-day baseline, use the baseline-capable
profile (listed commented out in `.env.example`):

```bash
NEO4J_HEAP_INITIAL=12g
NEO4J_HEAP_MAX=12g
NEO4J_PAGECACHE=8g
NEO4J_TX_MEMORY_MAX=8g
NEO4J_CONTAINER_MEMORY_LIMIT=32g
```

Then recreate the Neo4j container:

```bash
docker compose up -d neo4j
```

`up -d` recreates the container with the new environment. `docker
compose restart neo4j` keeps the old values, because the environment is
fixed when the container is created.

### A note on env-var names

Neo4j's Docker image maps environment variables to internal config keys
by a specific convention:

  - `__` (double underscore) → literal underscore in the config key
  - `_` (single underscore) → dot separator
  - So `NEO4J_server_memory_heap_max__size` → `server.memory.heap.max_size`

Our `docker-compose.yml` sets **`NEO4J_server_memory_heap_max__size`**
(double underscore before `size`), **`NEO4J_server_memory_pagecache_size`**
(single underscore — `pagecache` is one word in the config key), and
**`NEO4J_dbms_memory_transaction_total_max`** (`dbms.` prefix, NOT
`server.`, per Neo4j 5.x's split between `dbms.*` and `server.*`
namespaces).

**Operators should set the short wrapper variables above in `.env`**;
compose substitutes them into the Neo4j-internal names at container
startup. `edgeguard doctor --memory` accepts either form when probing,
so it works both from the host shell and from inside the container.

### MISP PHP settings

MISP is not part of EdgeGuard's `docker-compose.yml`
([MISP_TUNING.md](MISP_TUNING.md), "Where MISP runs"). Run these
commands in your MISP deployment's compose directory, or use
`docker exec <misp-container>`. [MISP_TUNING.md](MISP_TUNING.md) is the
authoritative MISP tuning reference (PHP paths per image, MySQL
settings, host capacity).

The harvarditsecurity/misp image ships with conservative defaults.
Override by editing `php.ini` inside the container:

```bash
docker compose exec misp bash -c '
  sed -i "s/memory_limit = .*/memory_limit = 4096M/" /etc/php/*/apache2/php.ini
  sed -i "s/max_execution_time = .*/max_execution_time = 600/" /etc/php/*/apache2/php.ini
'
docker compose restart misp
```

These values reset on container rebuild; for a permanent fix, mount a
custom `php.ini` via the compose file:

```yaml
# your MISP deployment's compose file — under its misp service
volumes:
  - ./misp-php.ini:/etc/php/8.2/apache2/conf.d/zz-edgeguard.ini:ro
```

with `misp-php.ini` containing:

```ini
memory_limit = 4096M        ; 2048M on a 4-6 GB MISP host
max_execution_time = 600
```

## Verifying your settings

```bash
edgeguard doctor --memory
```

Sample output:

```
Memory & sizing check

  Setting                              Current     Min     Rec  Verdict
  --------------------------------    ----------  ------  ------  -------
  Neo4j heap                                8.0G    4G      8G    ✓ ok
  Neo4j page cache                          2.0G    2G      4G    ⚠ low
                                    → Caches Neo4j store files; 4G recommended, 8G for a 730-day baseline (baseline-capable profile)
                                    → set NEO4J_PAGECACHE in .env (or NEO4J_server_memory_pagecache_size directly on the neo4j service)
  Neo4j tx memory                           8.0G    4G      8G    ✓ ok

  Host RAM                                 16.0G    8G     16G    ✓ ok

ℹ MISP PHP settings (memory_limit, max_execution_time) are NOT auto-probed yet.
ℹ Manual check: ``docker compose exec misp php -r 'echo ini_get("memory_limit");'``
ℹ Recommended values + rationale: see docs/MEMORY_TUNING.md
```

## What the probe does not cover

The probe is intentionally minimal — it covers the settings most often
implicated in production-readiness incidents. The following are
documented above but **not auto-probed**:

- MISP PHP `memory_limit` / `max_execution_time` (manual check via
  `docker compose exec misp php -r ...` in your MISP deployment's
  compose directory)
- Airflow worker memory + concurrency settings
- Neo4j JVM GC settings (rarely need tuning; defaults work for our
  graph size)
- Per-collector working-set memory (rarely the bottleneck — collectors
  stream and don't accumulate)

A request to add one of these to the probe goes into an issue that
references this document.

## Cross-references

- [`edgeguard doctor --memory`](../src/edgeguard.py) — the diagnostic command
- [`docs/AIRFLOW_DAGS.md`](AIRFLOW_DAGS.md) — operational guide
- [`docs/AIRFLOW_DAG_DESIGN.md`](AIRFLOW_DAG_DESIGN.md) — pipeline architecture
- [`docs/BACKUP.md`](BACKUP.md) — backup & recovery (companion ops doc)
- [`docs/MISP_TUNING.md`](MISP_TUNING.md) — MISP tuning (authoritative for the MISP PHP and MySQL settings)

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Main text restated as a guide to current behaviour; change history moved to this section.
- 2026-10-17 — The sample doctor output gives the doctor's page-cache rationale (4G recommended, 8G for a 730-day baseline).
- 2026-10-17 — Quick reference names the Neo4j env vars (`NEO4J_server_memory_heap_max__size`, `NEO4J_dbms_memory_transaction_total_max`) set through the `.env` wrapper names, and states the compose defaults (heap 2g, page cache 1g, tx 4g, container 8g) in place of a commented preset that does not exist.
- 2026-10-17 — The `.env` recipe sets `NEO4J_CONTAINER_MEMORY_LIMIT` and adds the 730-day profile, and recreates the container with `docker compose up -d neo4j`, because `restart` keeps the old environment.
- 2026-10-17 — Host RAM derived from the compose memory limits (40G, about 48G for a 730-day baseline); MISP `memory_limit` 4096M as in MISP_TUNING.md, with the MISP commands run in the MISP deployment, not in EdgeGuard's compose project.
- 2026-10-17 — build_relationships described as 20 linking steps with `apoc.periodic.iterate`, the graph size taken from the 730-day baseline of 2026-10-16, and the doctor hint line shown as printed.
- 2026-04-20 — `edgeguard doctor --memory` probes the Neo4j-internal env-var names that `docker-compose.yml` sets as well as the `.env` wrapper names (`NEO4J_HEAP_MAX`, `NEO4J_PAGECACHE`, `NEO4J_TX_MEMORY_MAX`); the `.env` recipe uses the wrapper names, and the mapping convention (`__` for a literal underscore, `dbms.` vs `server.` namespaces) is explained here (PR-F8).
- 2026-04-20 — Document created for the `edgeguard doctor --memory` diagnostic (PR-F5); the MISP PHP thresholds come from the 2026-04-19 baseline incident analysed in PR-F4 (#60), which also made the tier-1 collectors sequential, and MISP event partitioning, the architectural fix for the per-event size problem, is tracked in issue #61; the Neo4j transaction-memory recommendation of 8G (raised from 4G after the 2026-04-18 `build_relationships` failure, in which one batch transaction exceeded the 4G cap and left the graph half-linked) dates from the same version.
