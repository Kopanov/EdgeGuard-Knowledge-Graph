# Neo4j Schema Migrations

Hand-applied Cypher migrations that evolve the EdgeGuard graph schema in place.
They are **not** auto-applied by any pipeline run — an operator must execute
them against a running Neo4j once, after the corresponding code has been
deployed.

Migrations live in [`migrations/`](../migrations/) and are named
`YYYY_MM_<slug>.cypher`. Each file is **idempotent**: re-running it against an
already-migrated graph matches 0 rows and leaves the graph unchanged.

---

## How to run a migration

All migrations assume:

- Neo4j is reachable from wherever you run `cypher-shell` (laptop, Airflow
  worker, or the Neo4j container itself).
- APOC is installed (`CALL apoc.help("periodic")` returns rows). The 2026-04
  migration falls back to a non-APOC variant for small graphs — see the file
  comments.

### 1. Pre-flight

```bash
# From the repo root, verify target Neo4j and credentials match the graph you mean to migrate.
echo "$NEO4J_URI  $NEO4J_USER"

# Snapshot edge counts that the migration will touch. Save the output.
cypher-shell -a "$NEO4J_URI" -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
  "MATCH ()-[r:USES]->(t:Technique) RETURN count(r) AS before_count;"
```

Record `before_count` — the post-flight sum must match it.

### 2. Back up the graph

Migrations rewrite edges in place. There is **no automatic rollback**. Before
running any migration against production:

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
UI). A concurrent sync writing the old rel type will produce a few edges the
migration won't see — harmless, but you'll want to re-run the migration once
more afterward.

### 4. Execute

```bash
cypher-shell -a "$NEO4J_URI" -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" \
    -f migrations/2026_04_specialize_uses_technique.cypher
```

`apoc.periodic.iterate` prints one row per block with
`batches`, `total`, `committedOperations`, `failedOperations`. All blocks
should report `failedOperations: 0`.

### 5. Post-flight

```bash
# Must be 0 — all USES→Technique edges rewritten.
cypher-shell ... "MATCH ()-[r:USES]->(t:Technique) RETURN count(r) AS remaining_uses;"

# These should sum to before_count (± any Campaign→Technique edges).
cypher-shell ... "
MATCH (a:ThreatActor)-[r:EMPLOYS_TECHNIQUE]->(:Technique)   RETURN count(r) AS actor_employs;
MATCH (c:Campaign)-[r:EMPLOYS_TECHNIQUE]->(:Technique)      RETURN count(r) AS campaign_employs;
MATCH (m:Malware)-[r:IMPLEMENTS_TECHNIQUE]->(:Technique)    RETURN count(r) AS malware_implements;
MATCH (tool:Tool)-[r:IMPLEMENTS_TECHNIQUE]->(:Technique)    RETURN count(r) AS tool_implements;
"
```

### 6. Resume ingest

Unpause the DAGs. The first scheduled run will MERGE directly into the new
rel types — the Python code has already been switched over in
[src/build_relationships.py](../src/build_relationships.py) and
[src/neo4j_client.py](../src/neo4j_client.py).

---

## Rollback

Migrations are forward-only. If you need to reverse `2026_04_specialize_uses_technique.cypher`:

1. **Preferred:** restore the dump taken in step 2 above.
2. **Manual reverse migration** (graph is small, no dump available):

    ```cypher
    CALL apoc.periodic.iterate(
      "MATCH (a:ThreatActor)-[r:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN a, r, t",
      "MERGE (a)-[r2:USES]->(t) SET r2 += properties(r) DELETE r",
      {batchSize: 1000, parallel: false}
    );
    CALL apoc.periodic.iterate(
      "MATCH (c:Campaign)-[r:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN c, r, t",
      "MERGE (c)-[r2:USES]->(t) SET r2 += properties(r) DELETE r",
      {batchSize: 1000, parallel: false}
    );
    CALL apoc.periodic.iterate(
      "MATCH (m:Malware)-[r:IMPLEMENTS_TECHNIQUE]->(t:Technique) RETURN m, r, t",
      "MERGE (m)-[r2:USES]->(t) SET r2 += properties(r) DELETE r",
      {batchSize: 1000, parallel: false}
    );
    CALL apoc.periodic.iterate(
      "MATCH (tool:Tool)-[r:IMPLEMENTS_TECHNIQUE]->(t:Technique) RETURN tool, r, t",
      "MERGE (tool)-[r2:USES]->(t) SET r2 += properties(r) DELETE r",
      {batchSize: 1000, parallel: false}
    );
    ```

    Note: after a manual reverse you must also redeploy a code build from
    before the 2026-04 specialization, otherwise the next sync will re-write
    the new rel types and undo the reverse.

---

## Migration index

| File | Applied | Purpose |
|------|---------|---------|
| [2026_04_specialize_uses_technique.cypher](../migrations/2026_04_specialize_uses_technique.cypher) | _pending_ | Split generic `USES→Technique` into `EMPLOYS_TECHNIQUE` (attribution) and `IMPLEMENTS_TECHNIQUE` (capability). Run once after deploying the PR that merged the specialization. |
| [scripts/backfill_node_uuids.py](../scripts/backfill_node_uuids.py) | _pending_ | Stamp deterministic `n.uuid` on every existing node and `r.src_uuid` / `r.trg_uuid` on every existing edge. Python script (UUIDv5 can't be computed in Cypher). Idempotent + resumable. Required before delta-sync to cloud Neo4j; see [CLOUD_SYNC.md](CLOUD_SYNC.md). |

> **PR #33 round 10:** the legacy `Indicator.misp_attribute_id` backfill
> migration was removed from this index — the project is pre-release and
> the canonical provenance now lives in `misp_attribute_ids[]`. New
> ingests populate the array directly; no backfill is needed for a fresh
> Neo4j.

Update the **Applied** column with a date once a migration has been run in
production — that's the single source of truth for whether the migration
still needs to be applied to a new environment.

---

<!-- PR #33 round 10: Pass-B runbook removed — the legacy
     misp_attribute_id backfill migration that it served was deleted
     pre-release. Fresh ingests populate misp_attribute_ids[] directly.
-->

---

## n.uuid + edge endpoint uuids backfill (2026-04)

**When to use:** After deploying the PR that adds `n.uuid` and
`r.src_uuid`/`r.trg_uuid` SET clauses (PR #33). The forward fix only stamps
new MERGEs — every existing node + edge needs a one-time backfill before
delta-sync to cloud Neo4j (see [CLOUD_SYNC.md](CLOUD_SYNC.md)) becomes safe.

**What it does:**

1. For each documented node label (Indicator, Vulnerability, CVE, Malware,
   ThreatActor, Technique, Tactic, Tool, Sector, Source, Campaign, CVSSv*):
   read every node with NULL `uuid`, compute the deterministic UUIDv5 in
   Python via `node_identity.compute_node_uuid`, write back via UNWIND.
2. For each documented edge type (INDICATES, EXPLOITS, EMPLOYS_TECHNIQUE,
   ATTRIBUTED_TO, TARGETS, AFFECTS, IN_TACTIC, USES_TECHNIQUE,
   IMPLEMENTS_TECHNIQUE, REFERS_TO, RUNS, PART_OF, SOURCED_FROM, HAS_CVSS_v*):
   stamp `r.src_uuid` and `r.trg_uuid` from the connected nodes' `n.uuid`
   via `apoc.periodic.iterate`.

**Why a Python script (not pure Cypher):** UUIDv5 cannot be computed inside
Cypher — APOC has only random `apoc.create.uuid` (v4). Same canonicalization
must run in every environment to produce the same uuid.

**Pre-flight:**

```bash
# Activate the project venv with NEO4J_* env vars set
python scripts/backfill_node_uuids.py --dry-run
# Logs counts per label + per edge type. No writes.
```

**Backup before running** (per the Backup section above) — backfill is
forward-only.

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
**resumable** (per-batch progress; a crash mid-run leaves a consistent partial
state and the next run picks up).

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

- Topology / ResilMesh-owned labels (`Component`, `Mission`,
  `OrganizationUnit`, `MissionDependency`, `Node`) are NOT in
  `node_identity._NATURAL_KEYS` yet — the script logs and skips them.
  Documented as a deferred follow-up.
- `Tool` is in the natural-key map but its STIX SDO id uses `name` while
  Neo4j's UNIQUE constraint is on `mitre_id`. The Tool n.uuid is stable
  cross-environment but does NOT have UUID parity with the corresponding
  STIX `tool--<uuid>` SDO id.
