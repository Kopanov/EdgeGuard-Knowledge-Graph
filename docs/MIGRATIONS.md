# Neo4j Schema Migrations

Hand-applied operational migrations that evolve the EdgeGuard graph schema in
place. They are **not** auto-applied by any pipeline run — an operator must
execute them once against a running Neo4j after the corresponding code has been
deployed.

> **Pre-release status (PR #33 round 12):** the project is on a fresh-start
> path. Two earlier Cypher migrations were deleted because they only applied
> to data that no longer exists (legacy `misp_attribute_id` scalar; legacy
> `USES→Technique` edges). Only the n.uuid backfill remains, and it is only
> needed if you started Neo4j on an older code build before deploying PR #33.

---

## Migration index

| Migration | Applied | Purpose |
|-----------|---------|---------|
| [scripts/backfill_node_uuids.py](../scripts/backfill_node_uuids.py) | _pending_ | Stamp deterministic `n.uuid` on every existing node and `r.src_uuid` / `r.trg_uuid` on every existing edge. Python script (UUIDv5 can't be computed in Cypher). Idempotent + resumable. Required before delta-sync to cloud Neo4j; see [CLOUD_SYNC.md](CLOUD_SYNC.md). |

Update the **Applied** column with a date once the migration runs in
production — that's the single source of truth for whether it still needs
to be applied to a new environment.

---

## Generic runbook (applies to every migration above)

### 1. Pre-flight

```bash
# From the repo root, verify target Neo4j matches the graph you mean to migrate.
echo "$NEO4J_URI  $NEO4J_USER"
```

Activate the project venv with `NEO4J_*` env vars set, then run the dry-run
mode (each migration script supports `--dry-run`):

```bash
python scripts/backfill_node_uuids.py --dry-run
```

Save the output — you'll compare against post-flight numbers.

### 2. Back up the graph

Migrations write in place. There is **no automatic rollback**. Before any
production run:

```bash
# Inside the Neo4j container
docker compose exec neo4j neo4j-admin database dump neo4j \
    --to-path=/backups --overwrite-destination
docker compose cp neo4j:/backups/neo4j.dump ./backups/pre-$(date +%F).dump
```

If something goes wrong, restore with `neo4j-admin database load` after
stopping Neo4j. Keep the dump until you've verified the post-flight counts.

### 3. Pause ingest

Stop the DAGs that write to Neo4j so the migration runs against a stable graph:

```bash
# Airflow UI → Pause: edgeguard_pipeline, edgeguard_baseline
# OR: edgeguard doctor --pause-dags   (if the helper is available)
```

Wait for any in-flight task to finish (`edgeguard doctor` or check the Airflow
UI). A concurrent sync writing nodes mid-migration will produce a few rows
the migration won't see — harmless on idempotent migrations, but you'll want
to re-run once afterward.

### 4. Resume ingest

Unpause the DAGs after post-flight passes. The next scheduled run uses the
post-migration schema.

---

## n.uuid + edge endpoint uuids backfill

**When to use:** if the Neo4j has any nodes/edges that were created BEFORE
PR #33 landed. Forward fix only stamps NEW MERGEs — pre-existing rows need
the one-time backfill before delta-sync to cloud Neo4j becomes safe.

**What it does:**

1. For each label in `node_identity._NATURAL_KEYS` (Indicator, Vulnerability,
   CVE, Malware, ThreatActor, Technique, Tactic, Tool, Sector, Source,
   Campaign, CVSSv2/v30/v31/v40, IP, Host, Device, Subnet, NetworkService,
   SoftwareVersion, Application, Role): read every node with NULL `uuid`,
   compute the deterministic UUIDv5 in Python via
   `node_identity.compute_node_uuid`, write back via UNWIND.
2. For each documented edge type (INDICATES, EXPLOITS, EMPLOYS_TECHNIQUE,
   ATTRIBUTED_TO, TARGETS, AFFECTS, IN_TACTIC, USES_TECHNIQUE,
   IMPLEMENTS_TECHNIQUE, REFERS_TO, RUNS, PART_OF, SOURCED_FROM,
   HAS_CVSS_v*, plus the topology edges): stamp `r.src_uuid` and
   `r.trg_uuid` from the connected nodes' `n.uuid` via
   `apoc.periodic.iterate` (cross-transaction-safe id()-based rebinding).

**Why a Python script (not pure Cypher):** UUIDv5 cannot be computed inside
Cypher — APOC has only random `apoc.create.uuid` (v4). The same Python
canonicalization must run in every environment to produce the same uuid.

**Execute:**

```bash
python scripts/backfill_node_uuids.py
# OR per-label / smaller batches:
python scripts/backfill_node_uuids.py --labels Indicator,Vulnerability --batch-size 500
# OR nodes-only first to validate, then edges:
python scripts/backfill_node_uuids.py --nodes-only
python scripts/backfill_node_uuids.py --edges-only
```

The script is **idempotent** (skips already-stamped nodes/edges) and
**resumable** (per-batch progress; a crash mid-run leaves a consistent
partial state and the next run picks up).

**Post-flight:**

```cypher
// Every documented label must have 100% coverage:
MATCH (n) WHERE n.uuid IS NULL RETURN labels(n)[0] AS label, count(n) AS missing;
// Expected: empty result for documented labels (Indicator, Malware, …).

// Every documented edge type must have both endpoint uuids stamped:
MATCH ()-[r]->() WHERE r.src_uuid IS NULL OR r.trg_uuid IS NULL
RETURN type(r) AS rel_type, count(r) AS missing;
// Expected: empty for documented edges.
```

**Caveats:**

- ResilMesh-owned labels (`User`, `Node`, `Component`, `Mission`,
  `OrganizationUnit`, `MissionDependency`) are NOT in
  `node_identity._NATURAL_KEYS` — the script logs and skips them.
  Documented as a deferred follow-up.
- `Tool` is in the natural-key map but its STIX SDO id uses `name` while
  Neo4j's UNIQUE constraint is on `mitre_id`. The Tool n.uuid is stable
  cross-environment but does NOT have UUID parity with the corresponding
  STIX `tool--<uuid>` SDO id.

---

## Rollback / cleanup recipes

The PR is backward-compatible (old code that doesn't read `n.uuid` /
`r.src_uuid` / `r.trg_uuid` ignores the new fields), so a code revert is
safe and requires no graph modification. The recipes below are for
**emergency cleanup** — only run if you genuinely need to remove the
fields (e.g. preparing to migrate to a new uuid namespace, or wiping
test data).

### Recipe R1 — drop all uuid fields

**IRREVERSIBLE without re-running the backfill.** Removes the deterministic
identifier from every node and every edge. Cloud sync stops working until
the backfill is re-run.

```cypher
// Drop the uuid property on every node and every edge.
MATCH (n) WHERE n.uuid IS NOT NULL SET n.uuid = null;
MATCH ()-[r]->() WHERE r.src_uuid IS NOT NULL SET r.src_uuid = null;
MATCH ()-[r]->() WHERE r.trg_uuid IS NOT NULL SET r.trg_uuid = null;
```

### Recipe R2 — drop the uuid indexes

The 43 uuid indexes (one per label) sit empty after Recipe R1 — drop them
to reclaim storage:

```cypher
// List every uuid index, then drop one by one.
SHOW INDEXES YIELD name WHERE name ENDS WITH '_uuid';
// → 43 names: indicator_uuid, vulnerability_uuid, ..., user_uuid, alert_uuid

// For each:
DROP INDEX indicator_uuid IF EXISTS;
DROP INDEX vulnerability_uuid IF EXISTS;
// (... repeat for all 43 — see Neo4jClient.create_indexes for the full list)
```

### Recipe R3 — re-stamp uuids after a canonicalization change

The standard backfill (`scripts/backfill_node_uuids.py`) is **idempotent**:
it skips nodes whose uuid is already set. If you've changed
`node_identity.canonicalize_field_value` (e.g. added a new normalization)
and want to re-stamp existing nodes, you must clear the uuid first:

```bash
# Step 1: clear uuids (Recipe R1, scoped to the affected label)
cypher-shell -u neo4j -p $NEO4J_PASSWORD <<EOF
MATCH (n:Indicator) SET n.uuid = null;
MATCH ()-[r]->() WHERE startNode(r):Indicator OR endNode(r):Indicator
SET r.src_uuid = null, r.trg_uuid = null;
EOF

# Step 2: re-run the backfill — picks up the cleared uuids.
python scripts/backfill_node_uuids.py --labels Indicator
```

**WARNING**: re-stamping invalidates every cloud-side reference to those
uuids. Coordinate with cloud Neo4j operators before running.

### Recipe R4 — partial restart of the backfill

If the backfill crashed halfway, just re-run it. Already-stamped nodes
are skipped (the `WHERE n.uuid IS NULL` filter — pinned by
`tests/test_round26_invariants.py::test_backfill_node_query_only_targets_null_uuid`).

```bash
python scripts/backfill_node_uuids.py
```

---

_Last updated: 2026-04-17_
