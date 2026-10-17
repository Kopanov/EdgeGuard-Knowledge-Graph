# Neo4j Schema Migrations

> **Pre-release status:** the project's heal path is "rebaseline against
> the current code" — every dev/test environment reaches a correct schema
> by running a fresh baseline. Each schema rule lives at the write-time
> MERGE sites in `src/neo4j_client.py`, `src/build_relationships.py`, and
> `src/enrichment_jobs.py`.
>
> The read-only fresh-baseline acceptance check
> `scripts/verify_fresh_baseline.py` is described under § "Operator scripts
> in `scripts/`" below. Fix-up and audit scripts for graphs written by
> earlier versions that **cannot** be wiped (cloud Neo4j Aura snapshots,
> partner deployments, etc.) are listed in the
> [appendix](#appendix-data-written-by-earlier-versions). None are
> auto-run by CI or DAGs. (`scripts/` holds other operator tools as well,
> e.g. `import_curated_package.py`, `build_canonical_threat_actors.py`,
> `build_attack_revoked_ids.py`, `clear_neo4j.py`, `clear_misp.py`.)

---

## Why no migration directory?

EdgeGuard keeps no single-purpose backfill / heal Cypher scripts. Every
node and relationship MERGE writes the target schema on first contact,
and a fresh baseline rebuilds a graph from the collectors. Migration
scripts in that posture have three real costs:

1. **Maintenance drag** — any code change that affects a node MERGE has to
   keep the corresponding backfill script in sync, or readers get
   diverging stories about how the graph reaches its target shape.
2. **Misleading docs** — "run this migration before deploying X" suggests
   an upgrade path, when the correct path is a fresh baseline.
3. **Orphan-property fabrication risk** — backfills that copy values
   between nodes and edges introduce uniform fabricated provenance,
   defeating the source-truth invariant they are meant to support.

The `migrations/` directory holds **operator runbooks** only — narrative
documents describing a change to the stored data and how to verify it.
There are no `.cypher` files. Operator-only Python scripts live in
`scripts/` (see § "Operator scripts in `scripts/`" below and the
[appendix](#appendix-data-written-by-earlier-versions)).

---

## Operator scripts in `scripts/`

These are **operator-only**: not auto-run by CI / DAGs, never invoked from
the pipeline.

| Script | Mode | What it does |
|--------|------|--------------|
| [`scripts/verify_fresh_baseline.py`](../scripts/verify_fresh_baseline.py) | **Read-only** (HTTP Query API v2) | Fresh-baseline acceptance check: provenance properties, campaign and sector evidence, CVE scores, revoked ATT&CK ids, the ResilMesh-facing schema (see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) § Fresh-baseline acceptance). Reads `NEO4J_HTTP_URL` (or `NEO4J_HTTP`), not `NEO4J_URI`; without either it checks the hosted instance `https://neo4j.edgeguard.org`, so point it at your graph. |

The fix-up and audit scripts for graphs written by earlier versions are
listed in the [appendix](#appendix-data-written-by-earlier-versions).

---

## Heal path for a misshapen dev / test graph

If a dev / test environment somehow drifts from the documented schema
(case-duplicate nodes, missing uuids, zone scalars instead of lists,
generic `USES` edges instead of the specialized triple, etc.), the
canonical fix is:

```bash
# 1. Pause the scheduled ingest and sync DAGs
# Airflow UI → Pause: edgeguard_pipeline, edgeguard_medium_freq, edgeguard_low_freq,
#   edgeguard_daily, edgeguard_neo4j_sync
# Leave edgeguard_baseline unpaused: a run triggered on a paused DAG stays queued.
# While the baseline runs, its lock keeps the scheduled DAGs from writing.

# 2. Wipe the graph (dev/test only — never production): deletes the nodes of the
#    EdgeGuard labels (add --full-wipe for every node) and clears the collector checkpoints
python scripts/clear_neo4j.py --force

# 3. Rebuild from the collectors
edgeguard baseline   # or: trigger the edgeguard_baseline DAG

# 4. Verify: read-only acceptance check (without NEO4J_HTTP_URL it checks the
#    hosted instance), plus the verification queries of the runbooks in the appendix
NEO4J_HTTP_URL=http://localhost:7474 python scripts/verify_fresh_baseline.py
```

This works because every MERGE site in the codebase writes the target
schema correctly on first contact — the heal path is "let the write path
run from a clean slate".

---

## Appendix: data written by earlier versions

The main text assumes a fresh baseline. The runbooks and scripts below
matter only for a graph kept across an upgrade that cannot be wiped
(cloud Aura snapshot, partner deployment). The scripts are operator-only,
never run by CI or a DAG, and read `NEO4J_URI` / `NEO4J_PASSWORD` /
`NEO4J_USER` from the environment.

**Runbooks in `migrations/`** (historical records of the change they
describe):

| Runbook | Topic |
|---------|-------|
| [migrations/2026_04_first_seen_at_source.md](../migrations/2026_04_first_seen_at_source.md) | Node-level `first_seen_at_source` / `last_seen_at_source` replaced by per-source claims on `SOURCED_FROM` edges (edge-based provenance, honest-NULL principle, verification queries). No backfill: an edge stays NULL until a source claim arrives. The current model is described in [TIMESTAMPS.md](TIMESTAMPS.md). |
| [migrations/2026_05_edge_misp_event_ids_backfill_runbook.md](../migrations/2026_05_edge_misp_event_ids_backfill_runbook.md) | Backfill `r.misp_event_ids[]` on INDICATES / EXPLOITS / TARGETS / AFFECTS edges written before `build_relationships.py` stamped the array. Pairs with `scripts/backfill_edge_misp_event_ids.py`. |

**Scripts in `scripts/`:**

| Script | Mode | What it does |
|--------|------|--------------|
| [`scripts/backfill_edge_misp_event_ids.py`](../scripts/backfill_edge_misp_event_ids.py) | `--dry-run` (READ_ACCESS) / commit (WRITE) | Propagates `misp_event_ids[]` from endpoint nodes onto INDICATES/EXPLOITS/TARGETS/AFFECTS edges. Idempotent (skips edges that already have the array). Uses `apoc.periodic.iterate` for batched commits; reports `committedOperations` (real writes) vs `total` (input rows scanned). Pairs with the 2026_05 runbook above. |
| [`scripts/backfill_cve_dates_from_nvd_meta.py`](../scripts/backfill_cve_dates_from_nvd_meta.py) | `--dry-run` / commit | Historical CVE `published` / `last_modified` dates from NVD JSON feeds, for graphs whose CVE nodes were written before the source-truthful timestamps. |
| [`scripts/audit_legacy_unicode_bypass_nodes.py`](../scripts/audit_legacy_unicode_bypass_nodes.py) | **Read-only** (READ_ACCESS at session level) | Counts `Malware` / `ThreatActor` / `Tool` nodes whose `name` contains a zero-width / bidi-control / variation-selector char from the canonical `_ZERO_WIDTH_AND_BIDI_CHARS` list (nodes written before the placeholder-name check stripped these characters; see [SECURITY_ROADMAP.md](SECURITY_ROADMAP.md)). Never writes. Output recommends one of: close as no-op (0 hits), one-shot Cypher (1–10 hits), full migration (>10 hits). Run before a 730d baseline launch — see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) item `[6]`. |

A schema change that needs operator-facing guidance beyond "rerun the
baseline" gets a runbook in `migrations/` and a row in the runbook table
above.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — The heal path pauses the five scheduled DAGs and leaves `edgeguard_baseline` unpaused (its lock holds the scheduled writers off), wipes with `scripts/clear_neo4j.py --force` (the script has no `--yes`), and verifies with the read-only `scripts/verify_fresh_baseline.py`; the main text describes current behavior only, and the runbooks and the fix-up and audit scripts for earlier-version graphs moved to the appendix.
- 2026-04-26 — Retracted the claim that no Python backfill scripts ship, listed the three operator scripts in `scripts/`, and added the 2026_05 edge `misp_event_ids` backfill runbook to the runbook table.
- 2026-04-25 — Added the read-only audit `scripts/audit_legacy_unicode_bypass_nodes.py` for nodes written before the zero-width / bidi-control strip.
- 2026-04-24 — Added `scripts/backfill_edge_misp_event_ids.py` and the 2026_05 runbook for edges written before `build_relationships.py` stamped `r.misp_event_ids[]`; its `--dry-run` opens the session in READ_ACCESS mode.
- 2026-04-22 — Added `scripts/backfill_cve_dates_from_nvd_meta.py` for historical CVE dates.
- 2026-04-18 — Deleted the single-purpose backfill / heal Cypher scripts (per-source first/last-seen splits, MISP attribute UUID stamping, zone scalar→list conversion, USES→specialized edge rewrites, `n.uuid` stamping, `_backfill_edges_from_orphan_props.cypher`), because the only graphs were dev/test instances that a fresh baseline rebuilds in under an hour, and every MERGE change had to be mirrored in them.
