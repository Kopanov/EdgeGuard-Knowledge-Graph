# Neo4j Schema Migrations

> **Pre-release status:** the project's heal path is "rebaseline against
> the current code" — after larger changes MISP and Neo4j are wiped and a
> fresh baseline is run, so the graph reaches the correct schema from the
> collectors. Each schema rule lives at the write-time MERGE sites in
> `src/neo4j_client.py`, `src/build_relationships.py`, and
> `src/enrichment_jobs.py`.
>
> The read-only fresh-baseline acceptance check
> `scripts/verify_fresh_baseline.py` is described under § "Operator scripts
> in `scripts/`" below; it is not auto-run by CI or DAGs. (`scripts/` holds
> other operator tools as well, e.g. `import_curated_package.py`,
> `build_canonical_threat_actors.py`, `build_attack_revoked_ids.py`,
> `clear_neo4j.py`, `clear_misp.py`.)

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

The `migrations/` directory holds only narrative records of earlier
changes to the stored data; they are not maintained, and there are no
`.cypher` files. Operator-only Python scripts live in `scripts/` (see
§ "Operator scripts in `scripts/`" below).

---

## Operator scripts in `scripts/`

These are **operator-only**: not auto-run by CI / DAGs, never invoked from
the pipeline.

| Script | Mode | What it does |
|--------|------|--------------|
| [`scripts/verify_fresh_baseline.py`](../scripts/verify_fresh_baseline.py) | **Read-only** (HTTP Query API v2) | Fresh-baseline acceptance check: provenance properties, campaign and sector evidence, CVE scores, revoked ATT&CK ids, the ResilMesh-facing schema (see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) § Fresh-baseline acceptance). Reads `NEO4J_HTTP_URL` (or `NEO4J_HTTP`), not `NEO4J_URI`; without either it checks the Compose Neo4j at `http://127.0.0.1:7474`. |

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

# 2. Wipe the graph (dev/test only — never production): deletes the nodes EdgeGuard
#    created (edgeguard_managed = true; --full-wipe deletes every node after a typed
#    confirmation) and clears the collector checkpoints
python scripts/clear_neo4j.py --force

# 3. Rebuild from the collectors
edgeguard baseline   # or: trigger the edgeguard_baseline DAG

# 4. Verify: read-only acceptance check of the Compose Neo4j at http://127.0.0.1:7474
#    (set NEO4J_HTTP_URL for another instance)
python scripts/verify_fresh_baseline.py
```

This works because every MERGE site in the codebase writes the target
schema correctly on first contact — the heal path is "let the write path
run from a clean slate".

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — `scripts/verify_fresh_baseline.py` checks the Compose Neo4j at `http://127.0.0.1:7474` when neither `NEO4J_HTTP_URL` nor `NEO4J_HTTP` is set (it checked a built-in remote instance); the heal path's verify step runs without `NEO4J_HTTP_URL`.
- 2026-10-23 — The heal path states that `scripts/clear_neo4j.py --force` deletes the nodes EdgeGuard created (`edgeguard_managed = true`) and that `--full-wipe` asks for a typed confirmation.
- 2026-10-18 — Removed `scripts/backfill_cve_dates_from_nvd_meta.py`, `scripts/backfill_edge_misp_event_ids.py` with its runbook in `migrations/`, and the read-only audit `scripts/audit_legacy_unicode_bypass_nodes.py`: they repaired or inspected data written by earlier versions, which a fresh baseline rebuilds.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — The heal path pauses the five scheduled DAGs and leaves `edgeguard_baseline` unpaused (its lock holds the scheduled writers off), wipes with `scripts/clear_neo4j.py --force` (the script has no `--yes`), and verifies with the read-only `scripts/verify_fresh_baseline.py`; the main text describes current behavior only, and the runbooks and the fix-up and audit scripts for earlier-version graphs moved to the appendix.
- 2026-04-26 — Retracted the claim that no Python backfill scripts ship, listed the three operator scripts in `scripts/`, and added the 2026_05 edge `misp_event_ids` backfill runbook to the runbook table.
- 2026-04-25 — Added the read-only audit `scripts/audit_legacy_unicode_bypass_nodes.py` for nodes written before the zero-width / bidi-control strip.
- 2026-04-24 — Added `scripts/backfill_edge_misp_event_ids.py` and the 2026_05 runbook for edges written before `build_relationships.py` stamped `r.misp_event_ids[]`; its `--dry-run` opens the session in READ_ACCESS mode.
- 2026-04-22 — Added `scripts/backfill_cve_dates_from_nvd_meta.py` for historical CVE dates.
- 2026-04-18 — Deleted the single-purpose backfill / heal Cypher scripts (per-source first/last-seen splits, MISP attribute UUID stamping, zone scalar→list conversion, USES→specialized edge rewrites, `n.uuid` stamping, `_backfill_edges_from_orphan_props.cypher`), because the only graphs were dev/test instances that a fresh baseline rebuilds in under an hour, and every MERGE change had to be mirrored in them.
- 2026-04-18 — Per-source timestamps moved from the nodes (`first_seen_at_source` / `last_seen_at_source`) to the `SOURCED_FROM` edges (`source_reported_first_at` / `source_reported_last_at`), without a backfill; the record of that change is [`migrations/2026_04_first_seen_at_source.md`](../migrations/2026_04_first_seen_at_source.md), and [TIMESTAMPS.md](TIMESTAMPS.md) describes the current model.
