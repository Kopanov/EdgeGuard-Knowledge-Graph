# Memory & Sizing — EdgeGuard Knowledge Graph

> **Status: ✅ Production-ready.** This is the operator reference for the
> `edgeguard doctor --memory` diagnostic (PR-F5) and the underlying
> "what should this be set to?" questions for the EdgeGuard stack.

## Quick reference — recommended values

| Setting | Minimum | Recommended | Where to set |
|---|---|---|---|
| Neo4j heap (`NEO4J_server_memory_heap_max_size`) | 4G | 8G | `.env` / `docker-compose.yml` |
| Neo4j page cache (`NEO4J_server_memory_pagecache_size`) | 2G | 4G | `.env` / `docker-compose.yml` |
| Neo4j tx memory (`NEO4J_server_memory_transaction_total_max`) | 4G | 8G | `.env` / `docker-compose.yml` |
| MISP PHP `memory_limit` | 512M | 1G+ | `php.ini` inside MISP container |
| MISP PHP `max_execution_time` | 300 | 600+ | `php.ini` inside MISP container |
| Host RAM | 8G | 16G+ | Hypervisor / host OS |

Run `edgeguard doctor --memory` to see your **actual** values vs these
recommendations side-by-side, with verdicts (`✓ ok` / `⚠ low` /
`✗ too low` / `? unknown`).

## Why these numbers

The values come from **real production-readiness incidents**, not
hand-wavy generic recommendations. Each row links back to the
incident that established the threshold.

### Neo4j heap — 8G recommended

The 730-day baseline produces ~350K nodes + ~700K relationships. Memory
pressure shows up at:

- **Build-relationships subprocess** — runs 12 Cypher MERGE queries with
  `apoc.periodic.commit` batching. At <4G heap, the batch transactions
  spill to disk + slow to a crawl.
- **`full_neo4j_sync` task** — reads ~all MISP attributes in 500-item
  chunks; per-chunk commit needs ~200MB working memory at peak graph
  density.

Symptom of under-provisioning: `OutOfMemoryError` in the Neo4j log,
build_relationships task killed by Airflow at the 5h timeout.

### Neo4j page cache — 4G recommended

Page cache caches the on-disk Neo4j store files (nodes, relationships,
properties). With 4G page cache and a 350K-node graph, ~95% of common
read queries are served from cache; below 2G, every read hits disk and
GraphQL/REST query latency spikes 10-50x.

### Neo4j tx memory — 8G recommended

`NEO4J_server_memory_transaction_total_max` is the per-instance cap on
concurrent transaction memory. Bumped from 4G → 8G after the 2026-04-18
`build_relationships` failure: a single batch transaction inside
`apoc.periodic.commit` exceeded the 4G cap and crashed the entire
build-relationships subprocess, leaving the graph half-linked.

**Symptom to grep for:** `MemoryLimitExceededException` in the Neo4j
container log (`docker compose logs neo4j | grep MemoryLimitExceeded`).
If you see it, the cap was reached — either bump tx_memory or reduce
the per-batch size in `apoc.periodic.commit` calls (less common; the
batch size is tuned to the recommended 8G already).

### MISP PHP `memory_limit` — 1G+ recommended

Established by **PR-F4 (#60)**: the 2026-04-19 overnight 730-day
baseline ran with default 512M `memory_limit` and lost ~14.7% of NVD
attributes (13,620 of 92,620) to MISP HTTP 500 errors. Bravo's
investigation traced the 5xx to PHP-FPM worker exhaustion in
`AppModel.php` when the NVD event grew past ~75K attributes — each
`edit-event` call had to load the whole event for dedup, blowing through
512M.

Tier-1 collectors are now sequential (PR-F4) which halves the
concurrent-write pressure, but the per-event size cost is still
load-dependent and benefits from ≥1G memory_limit.

### MISP PHP `max_execution_time` — 600+ recommended

Same incident: large `edit-event` calls under load take 5-10 minutes.
Default 300 s caused PHP-FPM workers to abort mid-write, surfacing as
HTTP 500 to the collector. 600 s gives MISP enough headroom for the
worst-case write path.

### Host RAM — 16G recommended

Running the full self-hosted stack (Neo4j 8G + MISP 4G + Airflow 2G +
host OS overhead) needs **at least 14G effective**, so 16G physical RAM
is the practical floor. Below 16G, the OOM killer eventually picks one
of Neo4j or MISP and you get cascading failures across the stack.

For dev/test rigs with 8-16G, you can reduce Neo4j heap to 4G and
page cache to 2G — see `docker-compose.yml` for the lower-resource
preset (commented).

## How to set these values

### Neo4j (Docker Compose, the default)

Add to `.env` using the **operator-facing wrapper variables** (what
`docker-compose.yml` reads and forwards to Neo4j's internal config keys):

```bash
NEO4J_HEAP_MAX=8g
NEO4J_PAGECACHE=4g
NEO4J_TX_MEMORY_MAX=8g
```

Then restart the Neo4j container:

```bash
docker compose restart neo4j
```

The values are read at container startup; they cannot be changed at
runtime.

### A note on env-var names (Cross-Checker audit HIGH — fixed in PR-F8)

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

The harvarditsecurity/misp image ships with conservative defaults.
Override by editing `php.ini` inside the container:

```bash
docker compose exec misp bash -c '
  sed -i "s/memory_limit = .*/memory_limit = 1G/" /etc/php/*/apache2/php.ini
  sed -i "s/max_execution_time = .*/max_execution_time = 600/" /etc/php/*/apache2/php.ini
'
docker compose restart misp
```

These values reset on container rebuild; for a permanent fix, mount a
custom `php.ini` via the compose file:

```yaml
# docker-compose.yml — under misp service
volumes:
  - ./misp-php.ini:/etc/php/8.2/apache2/conf.d/zz-edgeguard.ini:ro
```

with `misp-php.ini` containing:

```ini
memory_limit = 1G
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
                                    → Caches Neo4j store files; 4G recommended for 350K-node graph
                                    → set NEO4J_server_memory_pagecache_size in .env / docker-compose.yml
  Neo4j tx memory                           8.0G    4G      8G    ✓ ok

  Host RAM                                 16.0G    8G     16G    ✓ ok

ℹ MISP PHP settings (memory_limit, max_execution_time) are NOT auto-probed yet.
ℹ Manual check: ``docker compose exec misp php -r 'echo ini_get("memory_limit");'``
ℹ Recommended values + rationale: see docs/MEMORY_TUNING.md
```

## What's NOT covered yet

The probe is intentionally minimal — it covers the settings most often
implicated in production-readiness incidents. The following are
documented above but **not auto-probed**:

- MISP PHP `memory_limit` / `max_execution_time` (manual check via
  `docker compose exec misp php -r ...`)
- Airflow worker memory + concurrency settings
- Neo4j JVM GC settings (rarely need tuning; defaults work for our
  graph size)
- Per-collector working-set memory (rarely the bottleneck — collectors
  stream and don't accumulate)

If you'd like one of these added to the probe, file a follow-up issue
referencing this doc.

## Cross-references

- [`edgeguard doctor --memory`](../src/edgeguard.py) — the diagnostic command
- [`docs/AIRFLOW_DAGS.md`](AIRFLOW_DAGS.md) — operational guide
- [`docs/AIRFLOW_DAG_DESIGN.md`](AIRFLOW_DAG_DESIGN.md) — pipeline architecture
- [`docs/BACKUP.md`](BACKUP.md) — backup & recovery (companion ops doc)
- [PR #60 (PR-F4)](../../pull/60) — incident establishing MISP PHP
  recommendation thresholds
- [Issue #61](../../issues/61) — MISP event partitioning (related
  architectural fix for the per-event size problem)
