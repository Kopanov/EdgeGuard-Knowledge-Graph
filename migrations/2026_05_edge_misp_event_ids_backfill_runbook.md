# Migration: PR-N26 — Backfill `r.misp_event_ids[]` on TARGETS / EXPLOITS / INDICATES / AFFECTS edges

**Status:** Operator action — runbook only. NOT auto-run by CI / DAGs.

**Prerequisites:** PR-N26 code merged. APOC plugin loaded on target Neo4j.

**Estimated runtime:** 5-15 min on a 360K-node / 600K-edge graph (cloud snapshot from 2026-04-23). Pure Cypher, no MISP API calls — fast.

---

## What this migration does

Cloud-Neo4j audit on 2026-04-23 found that 5 edge types created by the post-sync graph-traversal in `src/build_relationships.py` silently dropped the `r.misp_event_ids[]` provenance array. PR-N26 fixed the forward write path; this migration backfills existing edges that were created before PR-N26 landed.

**Pre-N26 cloud coverage** (`bolt+s://neo4j-bolt.edgeguard.org:443`):

| Relationship | Total edges | with `misp_event_ids` | Gap |
|---|---|---|---|
| INDICATES | 19,370 | 6.6% (1,280) | ~18,090 |
| TARGETS | 36,480 | 0% | 36,480 |
| EXPLOITS | 26,730 | 0% | 26,730 |
| AFFECTS | 1,221 | 0.1% (1) | ~1,220 |

Total: ~82,500 edges to backfill in the cloud snapshot. Local Neo4j almost certainly has the same gap.

The script is **pure Cypher** — no MISP API needed. It walks the existing graph and propagates the originating node's `misp_event_ids[]` onto edges that lack them. For INDICATES edges with `r.match_type = 'misp_cooccurrence'`, it computes the **intersection** of source and target node arrays (the exact set of events that produced the edge). For all other patterns, it propagates the source endpoint's full array (a superset of the true provenance — acceptable for traceability).

---

## When to run

- **After** PR-N26 merges to `main`.
- **Before** any consumer relies on edge-level MISP traceability for backwards lookups (e.g. ResilMesh STIX export, RAG retrieval that joins on `r.misp_event_ids`).
- **Either before or after** the next 730-day baseline — order doesn't matter (idempotent), but running it first means baseline-day operators see consistent edge-level provenance throughout.

**This is NOT a blocker for the next 730d baseline launch.** Node-level traceability (`Indicator.misp_event_ids[]`, `Malware.misp_event_ids[]`, etc.) already works correctly — only edge-level backwards lookups are degraded by the gap.

---

## Pre-flight checks

```bash
# 1. Confirm APOC is loaded on the target Neo4j
echo "RETURN apoc.version();" | cypher-shell -a "$NEO4J_URI" -u neo4j

# 2. Sample the gap (sanity-check the script will find work to do)
cypher-shell -a "$NEO4J_URI" -u neo4j <<'EOF'
MATCH ()-[r:INDICATES|EXPLOITS|TARGETS|AFFECTS]->()
WHERE coalesce(size(r.misp_event_ids), 0) = 0
RETURN type(r) AS rel_type, count(r) AS gap
ORDER BY gap DESC;
EOF

# 3. Snapshot the current state (so you can compare post-backfill)
cypher-shell -a "$NEO4J_URI" -u neo4j <<'EOF' > pre_n26_state.txt
MATCH ()-[r]->() RETURN type(r) AS rel_type, count(r) AS total,
  sum(CASE WHEN coalesce(size(r.misp_event_ids), 0) > 0 THEN 1 ELSE 0 END) AS with_array
ORDER BY total DESC;
EOF
```

---

## Run the backfill

### Step 1 — Dry-run (no writes)

```bash
export NEO4J_URI="bolt+s://neo4j-bolt.edgeguard.org:443"
export NEO4J_PASSWORD="<cloud-password>"

./scripts/backfill_edge_misp_event_ids.py --dry-run
```

Expected output: per-pattern gap counts. If totals match the cloud snapshot above (~82K), proceed.

### Step 2 — Execute

```bash
./scripts/backfill_edge_misp_event_ids.py
```

Expected runtime: 5-15 min. Output should look like:

```
[backfill-edge-misp] [indicates_cooccurrence] gap = 18090 edges
[backfill-edge-misp] [indicates_cooccurrence] backfilled 18090 edges across 9 batches (errors=0)
[backfill-edge-misp] [indicates_family_match] gap = 0 edges
[backfill-edge-misp] [indicates_family_match] nothing to do
[backfill-edge-misp] [exploits] gap = 26730 edges
[backfill-edge-misp] [exploits] backfilled 26730 edges across 14 batches (errors=0)
[backfill-edge-misp] [targets_indicator_to_sector] gap = 36480 edges
[backfill-edge-misp] [targets_indicator_to_sector] backfilled 36480 edges across 19 batches (errors=0)
[backfill-edge-misp] [affects_vuln_to_sector] gap = 1220 edges
[backfill-edge-misp] [affects_vuln_to_sector] backfilled 1220 edges across 1 batches (errors=0)
[backfill-edge-misp] Summary: gap=82520, backfilled=82520, errors=0 (dry_run=False)
```

### Step 3 — Verify

```bash
cypher-shell -a "$NEO4J_URI" -u neo4j <<'EOF'
MATCH ()-[r]->()
WHERE type(r) IN ['TARGETS', 'EXPLOITS', 'INDICATES', 'AFFECTS']
WITH type(r) AS rel_type, count(r) AS total,
     sum(CASE WHEN coalesce(size(r.misp_event_ids), 0) > 0 THEN 1 ELSE 0 END) AS with_array
RETURN rel_type, total, with_array,
       round(toFloat(with_array) / total * 100, 1) AS pct
ORDER BY total DESC;
EOF
```

**Expected post-backfill coverage: ≥95% on all 4 edge types.** The remaining ≤5% are edges where the source node's `misp_event_ids[]` is also empty (pre-existing non-MISP-derived edges, mostly from MITRE / NVD direct paths) — those don't have any MISP event to propagate.

---

## Idempotency

Safe to re-run. The Cypher gate `coalesce(size(r.misp_event_ids), 0) = 0` skips edges that already have the array set. If a baseline runs concurrently and populates the array via the PR-N26 forward path, this script respects that and skips.

## Resumability

The script processes patterns sequentially. If it crashes mid-way (e.g. Neo4j OOM), re-run — already-completed patterns will report `gap = 0` and skip cleanly. Each pattern uses `apoc.periodic.iterate` so individual transactions are bounded by `--batch-size` (default 2000 edges/tx).

If a single pattern errors with non-empty `errorMessages`, lower the batch size:

```bash
./scripts/backfill_edge_misp_event_ids.py --only indicates_cooccurrence --batch-size 500
```

## Rollback

Not required — this is a pure additive write (sets a property that was previously NULL). To reverse, you would need to remove the array, which would re-introduce the bug — don't.

If for some reason you need to inspect the pre-backfill state, the snapshot from `pre_n26_state.txt` (Step 0 in pre-flight) gives you the counts.

## Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `apoc.periodic.iterate not found` | APOC plugin not loaded | Install APOC, restart Neo4j |
| `MemoryLimitExceededException` in mid-batch | Some indicators have very wide `misp_event_ids[]` (100+ entries) → joined product exceeds 4GB tx memory | Lower `--batch-size` to 500 or 200 |
| `Connection refused` | Wrong `NEO4J_URI` or Neo4j down | Verify URI + service status |
| `Authentication failed` | Wrong `NEO4J_PASSWORD` | Re-export the correct password |
| Backfill reports `gap = 0` immediately | Already backfilled (re-run after success) | No action — confirms idempotency works |
| `errors > 0` in summary | Per-batch errors during apoc.periodic.iterate | Re-run with smaller `--batch-size`; check Neo4j logs |

## Cross-references

- Forward write path (the actual code fix): `src/build_relationships.py` Q3a/Q3b/Q4/Q7a/Q7b/Q9
- Sister backfill: `scripts/backfill_cve_dates_from_nvd_meta.py` (PR-N22)
- Original audit query that surfaced the gap: cloud-Neo4j Browser session 2026-04-23
- Architecture context: `docs/ARCHITECTURE_FLOW.md` § "Cross-system traceability"
