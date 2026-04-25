# Neo4j Schema Migrations

> **Pre-release status:** the project's primary heal path is still "rebaseline
> against the current code" — every dev/test environment reaches a correct
> schema by running a fresh baseline. Each forward-fix lives at the write-time
> MERGE sites in `src/neo4j_client.py`, `src/build_relationships.py`, and
> `src/enrichment_jobs.py`.
>
> **However**, three operator-only Python scripts under `scripts/` exist for
> graphs that **cannot** be wiped (cloud Neo4j Aura snapshots, partner
> deployments, etc.) — see § "Operator scripts in `scripts/`" below. None
> are auto-run by CI or DAGs.

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

The `migrations/` directory holds **operator runbooks** — narrative
documents describing what changed and how to verify it post-baseline. There
are no `.cypher` files. Operator-only Python scripts live in `scripts/`
(see § "Operator scripts in `scripts/`" below).

---

## Current operator runbooks

| Runbook | Topic |
|---------|-------|
| [migrations/2026_04_first_seen_at_source.md](../migrations/2026_04_first_seen_at_source.md) | Source-truthful first-seen / last-seen architecture (PR #41). Edge-based per-source provenance, honest-NULL principle, baseline verification queries. |
| [migrations/2026_05_edge_misp_event_ids_backfill_runbook.md](../migrations/2026_05_edge_misp_event_ids_backfill_runbook.md) | PR-N26 — backfill `r.misp_event_ids[]` on legacy INDICATES / EXPLOITS / TARGETS / AFFECTS edges in graphs that pre-date PR-N26 wiring (`build_relationships.py`). Pairs with `scripts/backfill_edge_misp_event_ids.py` (operator-only; `--dry-run` opens session in READ_ACCESS — see PR-N30). |

Add a new runbook here when a future schema change needs operator-facing
guidance beyond "rerun the baseline".

---

## Operator scripts in `scripts/`

These are **operator-only**: not auto-run by CI / DAGs, never invoked from
the pipeline. Operators reach for them when a graph that **cannot** be
wiped (cloud Aura snapshot, partner deployment) needs a one-shot fix-up
or audit. All read `NEO4J_URI` / `NEO4J_PASSWORD` / `NEO4J_USER` from env.

| Script | Mode | What it does |
|--------|------|--------------|
| [`scripts/backfill_edge_misp_event_ids.py`](../scripts/backfill_edge_misp_event_ids.py) | `--dry-run` (READ_ACCESS) / commit (WRITE) | PR-N26 backfill — propagates `misp_event_ids[]` from endpoint nodes onto INDICATES/EXPLOITS/TARGETS/AFFECTS edges. Idempotent (skips edges that already have the array). Uses `apoc.periodic.iterate` for batched commits; reports `committedOperations` (real writes) vs `total` (input rows scanned). Pairs with the 2026_05 runbook above. |
| [`scripts/backfill_cve_dates_from_nvd_meta.py`](../scripts/backfill_cve_dates_from_nvd_meta.py) | `--dry-run` / commit | PR-N22 backfill — historical CVE `published` / `last_modified` dates from NVD JSON feeds. For graphs where the CVE nodes were created before the source-truthful timestamp work landed (PR-S5 / PR-M2). |
| [`scripts/audit_legacy_unicode_bypass_nodes.py`](../scripts/audit_legacy_unicode_bypass_nodes.py) | **Read-only** (READ_ACCESS at session level) | PR-N32 audit — counts `Malware` / `ThreatActor` / `Tool` nodes whose `name` contains a zero-width / bidi-control / variation-selector char from the canonical `_ZERO_WIDTH_AND_BIDI_CHARS` list. Never writes. Output recommends one of: close as no-op (0 hits), one-shot Cypher (1–10 hits), full migration PR (>10 hits). Run before a 730d baseline launch — see [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) item `[6]`. |

The legacy "no Python migration scripts shipped" claim was retracted in
PR-N33 (2026-04-26) — these three scripts have all shipped under PR-N22
through PR-N32 and are now first-class operator tools.

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

_Last updated: 2026-04-26 — PR-N33 docs audit: retracted the "no Python
backfill scripts shipped" claim (3 scripts now live in `scripts/`); added
the 2026_05 PR-N26 edge-misp-event-ids backfill runbook + cross-links to
all three operator scripts (PR-N22 / PR-N26 / PR-N32). Prior: 2026-04-18
PR #41 cleanup pass._
