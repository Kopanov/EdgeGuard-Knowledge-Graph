# Neo4j Schema Migrations

> **Pre-release status (PR #41 cleanup pass):** the project is on a fresh-start
> path. There is no production graph anywhere; every dev/test environment
> reaches a correct schema by running a fresh baseline against the current
> code (`edgeguard baseline` or the equivalent DAG run). For that reason,
> **no Cypher migration scripts and no Python backfill scripts are shipped
> with this repository.** Each forward-fix lives at the write-time MERGE
> sites in `src/neo4j_client.py`, `src/build_relationships.py`, and
> `src/enrichment_jobs.py`; a fresh baseline rerun is the canonical heal
> path for every schema change in the project so far.

---

## Why no migration directory?

EdgeGuard is in pre-release. Several earlier passes accumulated single-purpose
backfill / heal Cypher scripts (per-source first/last-seen splits, MISP
attribute UUID stamping, zone scalar→list conversion, USES→specialized
edge rewrites, n.uuid stamping). Every one of those scripts was written
to migrate a graph that nobody actually has — the only graphs in
existence are local dev / test instances that can be wiped and rebuilt
in under an hour from the collectors.

Keeping migration scripts around in that posture had three real costs:

1. **Maintenance drag** — any code change that affects a node MERGE has to
   keep the corresponding backfill script in sync, or readers get
   diverging stories about how the graph reaches its target shape.
2. **Misleading docs** — operators reading "run this migration before
   deploying X" assumed there was an upgrade path, when in fact the
   correct path was always "just rebaseline".
3. **Orphan-property fabrication risk** — backfills that copy values
   between nodes and edges (e.g. the deleted
   `_backfill_edges_from_orphan_props.cypher`) actively introduced
   uniform fabricated provenance, defeating the source-truth invariant
   they were meant to support.

The `migrations/` directory now holds **operator runbooks only** — narrative
documents describing what changed and how to verify it post-baseline. There
are no `.cypher` files and no Python migration scripts.

---

## Current operator runbooks

| Runbook | Topic |
|---------|-------|
| [migrations/2026_04_first_seen_at_source.md](../migrations/2026_04_first_seen_at_source.md) | Source-truthful first-seen / last-seen architecture (PR #41). Edge-based per-source provenance, honest-NULL principle, baseline verification queries. |

Add a new runbook here when a future schema change needs operator-facing
guidance beyond "rerun the baseline".

---

## Heal path for a misshapen dev / test graph

If a dev / test environment somehow drifts from the documented schema
(case-duplicate nodes, missing uuids, zone scalars instead of lists,
generic `USES` edges instead of the specialized triple, etc.), the
canonical fix is:

```bash
# 1. Pause ingest DAGs
# Airflow UI → Pause: edgeguard_pipeline, edgeguard_baseline

# 2. Wipe the graph (dev/test only — never production)
python scripts/clear_neo4j.py --yes

# 3. Rebuild from the collectors
edgeguard baseline   # or: trigger the edgeguard_baseline DAG

# 4. Verify the post-baseline schema with the queries in the
#    relevant runbook (see table above).
```

This works because every MERGE site in the codebase already writes the
target schema correctly on first contact — the heal path is "let the
forward-fix run from a clean slate".

---

_Last updated: 2026-04-18 — PR #41 cleanup pass. Migration / backfill
scripts deleted; runbooks-only directory._
