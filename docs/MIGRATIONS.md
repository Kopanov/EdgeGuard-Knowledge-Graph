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

Update the **Applied** column with a date once a migration has been run in
production — that's the single source of truth for whether the migration
still needs to be applied to a new environment.
