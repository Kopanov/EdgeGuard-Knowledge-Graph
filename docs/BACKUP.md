# Backup & Recovery — EdgeGuard Knowledge Graph

> **Status:** production-ready. This procedure is the operator prerequisite
> for `edgeguard fresh-baseline` (the destructive command). Without an
> up-to-date `EDGEGUARD_LAST_BACKUP_AT` timestamp, the CLI refuses to run
> (the backup-timestamp gate). **The `baseline_clean` DAG task enforces the
> same gate** for Airflow UI/API triggers with `{"fresh_baseline": true}`.
> The DAG-side gate reads `EDGEGUARD_LAST_BACKUP_AT` from the **airflow
> container environment** (passed through by docker-compose), auto-skips on
> a clean install (Neo4j and MISP reachable and empty), and accepts an
> explicit `{"skip_backup_check": true}` conf bypass (logged at WARNING; the
> counterpart of the CLI `--skip-backup-check` flag).

## Why this exists

`edgeguard fresh-baseline` permanently deletes:

- All EdgeGuard nodes + edges in Neo4j (about 550K nodes / 2.7M
  relationships on the 730-day baseline loaded on 2026-10-16)
- All EdgeGuard-tagged events in MISP (~8K events on a real-world deployment)
- All collector checkpoints (per-source incremental cursors)

**There is no built-in undo.** A single command can wipe hours of historical
threat-intel collection. This document is the recovery story.

## Quick reference

```bash
# 1. Take a backup BEFORE running fresh-baseline.
#    Neo4j: offline dump (Community Edition); needs the ./backups/neo4j mount
#    described in "Self-hosted Neo4j" below.
docker compose stop airflow api graphql neo4j
docker compose run --rm neo4j neo4j-admin database dump neo4j --to-path=/backups --overwrite-destination=true
docker compose start neo4j airflow api graphql
#    MISP: dump its MySQL database where MISP runs, outside EdgeGuard's
#    compose project (container name of the reference compose in
#    docs/sources/MISP/; adapt it to your deployment — see "MISP backup").
docker exec misp_db_1 sh -c 'mysqldump -u misp -p"$MYSQL_PASSWORD" misp' > backups/misp-$(date +%F).sql

# 2. Update the freshness timestamp the gate checks.
#    `up -d` (RECREATE), not `restart` — compose interpolates .env into the
#    container environment at CREATE time only; a plain restart keeps the
#    stale value and the DAG-side gate would still refuse.
#    The host CLI reads its own environment, not .env, hence the export.
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "EDGEGUARD_LAST_BACKUP_AT=$TS" >> .env
export EDGEGUARD_LAST_BACKUP_AT=$TS
docker compose up -d api graphql airflow

# 3. NOW you can run the destructive command
edgeguard fresh-baseline --days 730
```

## The backup-timestamp gate

`edgeguard fresh-baseline` reads `EDGEGUARD_LAST_BACKUP_AT` from the
environment. The gate accepts:

- ISO 8601 with `Z` suffix (recommended): `2026-04-19T14:30:00Z`
- ISO 8601 with explicit offset: `2026-04-19T14:30:00+00:00`
- Unix epoch seconds: `1745074200`

The default freshness window is **240 hours (10 days)**. This reflects the
typical operator cadence: take a backup once per ~10 days, then `fresh-baseline`
can be re-triggered freely within that window without re-backing-up. Override
with:

```bash
EDGEGUARD_BACKUP_MAX_AGE_HOURS=24    # strict-RPO: daily backup posture (production)
EDGEGUARD_BACKUP_MAX_AGE_HOURS=4     # very strict: 4-hour RPO
EDGEGUARD_BACKUP_MAX_AGE_HOURS=720   # very loose: 30-day window (dev only)
```

**Trade-off note for 240h default:** a `fresh-baseline` triggered on day 10
of the window with NO interim backup, if it fails, would require restoring
to a 10-day-old state + losing 10 days of incremental ingest. If losing 10
days of incremental work would be unacceptable for your environment, tighten
the window. The strict-RPO production posture is `EDGEGUARD_BACKUP_MAX_AGE_HOURS=24`.

**Operator visibility:** when the gate accepts, both the structured log AND a
brief stdout line confirm the freshness state — operators see e.g.
`Backup-timestamp gate passed: backup is 6.2h old (max 240.0h via
EDGEGUARD_BACKUP_MAX_AGE_HOURS; 233.8h remaining before next backup required)`.
Useful when wondering "why isn't fresh-baseline running" (gate failure messages
also explicitly state the max + the actual age).

Bypass for dev/test scenarios where data loss is acceptable:

```bash
edgeguard fresh-baseline --skip-backup-check    # logs WARNING; not for prod
```

The gate logs the bypass at WARNING level so audit-trail readers can see
when production safety was disabled.

### Auto-skip on clean installs

The gate also auto-skips when **both data stores are empty** (Neo4j
EdgeGuard nodes = 0 AND MISP EdgeGuard events = 0). This covers the
first-time / dev-laptop / CI-bringup workflow: there is nothing to back
up on a fresh install, so requiring `EDGEGUARD_LAST_BACKUP_AT` for the
very first `fresh-baseline` would be friction-without-safety.

The auto-skip is logged at **INFO** (not WARNING):

```
INFO  edgeguard: Backup-timestamp gate auto-skipped on clean install
      (neo4j_count=0, misp_count=0); EDGEGUARD_LAST_BACKUP_AT not required.
```

This is deliberately distinct from the WARNING-level `--skip-backup-check`
audit log: "no data exists" is a different state than "operator chose to
disable safety". As soon as either store has any EdgeGuard-managed data,
the gate enforces normally on the next `fresh-baseline` run — the auto-skip
is a one-time bootstrap, not an ongoing posture.

Checkpoint state is **intentionally excluded** from the auto-skip
predicate: a leftover `checkpoints/baseline_checkpoint.json` from a prior
run on an emptied graph is exactly the case the auto-skip allows without
ceremony, and per-collector cursor state is not user-meaningful data.

## Backup procedures by deployment shape

### Self-hosted Neo4j (Docker Compose, the default)

`neo4j-admin database dump` produces a single `.dump` file. On Neo4j
Community Edition (the `neo4j:2026.03.1-community` image of
`docker-compose.yml`) it refuses a database that is in use, and Community
has no `STOP DATABASE`, so the dump runs while the Neo4j server is stopped.

**Required once — a backup mount.** `docker-compose.yml` mounts only
`/data`, `/logs` and `/plugins` on the `neo4j` service. Add a host
directory as `/backups` to its volumes, so that the dump outlives the
container that writes it and the restore below can read it:

```yaml
# docker-compose.yml — add to the neo4j service's volumes
volumes:
  - ./backups/neo4j:/backups
```

The host directory must be writable by the container's `neo4j` user
(uid 7474), e.g. `mkdir -p backups/neo4j && sudo chown 7474:7474 backups/neo4j`.
The MISP dumps and checkpoint copies of this document go to `backups/`
itself, which stays writable by your own user.

```bash
# Stop the writers and Neo4j, dump offline, start again
docker compose stop airflow api graphql neo4j
docker compose run --rm neo4j neo4j-admin database dump neo4j \
    --to-path=/backups \
    --overwrite-destination=true
docker compose start neo4j airflow api graphql

# Verify the dump exists + has a sane size
ls -lh backups/neo4j/neo4j.dump
# Expected: 100MB-2GB depending on graph size
```

**Dump file location:** `./backups/neo4j/neo4j.dump` on the host filesystem —
copy/sync to durable storage (S3, BorgBackup, etc.) per your retention
policy.

### Cloud Neo4j (Aura)

Aura ships with built-in scheduled snapshots; the operator backup procedure
is to **trigger a snapshot via the Aura console (or REST API) and record
the snapshot ID** as the recovery anchor. Snapshots are typically available
within 1-2 minutes.

```bash
# Trigger snapshot via Aura REST API (requires AURA_API_TOKEN)
curl -X POST "https://api.neo4j.io/v1/instances/$INSTANCE_ID/snapshots" \
    -H "Authorization: Bearer $AURA_API_TOKEN"
```

Record the returned `snapshot_id` somewhere durable; it's the recovery
anchor for `restore` operations.

### MISP backup

MISP stores events in a MySQL database + raw JSON exports. Either is sufficient
for restoration. MISP is not part of EdgeGuard's `docker-compose.yml`, so run
these commands where MISP runs, against its own containers.

**Option A — MySQL dump (canonical):** run the dump where MISP's MySQL runs.
For the reference compose in `docs/sources/MISP/` (MySQL in the separate
`misp_db` service, container `misp_db_1`, user and database `misp`):

```bash
docker exec misp_db_1 sh -c 'mysqldump -u misp -p"$MYSQL_PASSWORD" misp' > backups/misp-$(date +%F).sql
```

Adapt the container name to your MISP deployment; all-in-one images run
MySQL in the MISP container itself. The single quotes make
`$MYSQL_PASSWORD` expand inside the container, not in the host shell.

**Option B — MISP CakePHP event export (MISP-aware):**

```bash
docker exec <misp-container> /var/www/MISP/app/Console/cake admin event export json /backups/misp-events.json
```

The export file is written inside the MISP container.

Option B is preferred when restoring to a different MISP instance (handles
MISP version drift); Option A is faster for same-instance restore.

## Restore procedure

### Worked example: fresh-baseline failed at 14:05 UTC

**Scenario:** Operator triggered `edgeguard fresh-baseline` at 14:00 UTC.
Task `baseline_clean` succeeded (Neo4j wiped, MISP cleared, checkpoints
cleared) at 14:01. Task `full_neo4j_sync` failed at 14:05 with a MISP
rate-limit error. The graph is now empty; the operator needs to restore
to the 13:55 state (last backup taken at 13:50).

**Step 1 — Stop dependent services to prevent writes during restore:**

```bash
docker compose stop airflow api graphql
```

**Step 2 — Restore Neo4j from the dump:**

```bash
# Stop neo4j to release the DB lock
docker compose stop neo4j

# Restore (overwrites current data; reads ./backups/neo4j/neo4j.dump through the mount above)
docker compose run --rm neo4j neo4j-admin database load neo4j \
    --from-path=/backups \
    --overwrite-destination=true

# Restart
docker compose start neo4j
```

**Step 3 — Restore MISP events:**

```bash
# Reference compose in docs/sources/MISP/; adapt the container name to your MISP deployment
docker exec -i misp_db_1 sh -c 'mysql -u misp -p"$MYSQL_PASSWORD" misp' < backups/misp-2026-04-19.sql
```

**Step 4 — Reset incremental checkpoints to pre-baseline state:**

If you took a backup of `checkpoints/baseline_checkpoint.json` (recommended
when running fresh-baseline against a graph with prior incremental work):

```bash
cp backups/baseline_checkpoint-2026-04-19.json checkpoints/baseline_checkpoint.json
```

If no checkpoint backup exists, the next incremental run will re-collect
each source's incremental window (OTX 3 days, NVD 14 days, CISA ICS 30
days, ThreatFox 7 days, URLhaus its `recent.csv` export; CISA KEV reads the
whole catalogue every run).

**Step 5 — Restart and verify:**

```bash
docker compose start airflow api graphql
edgeguard doctor    # verify all services connect
edgeguard --help    # sanity check
```

The graph reflects the 13:50 state. Investigate the MISP rate-limit of
the 14:05 failure, fix the root cause, then take a fresh backup and
retry.

## Expected restore times

| Graph size | Neo4j dump | Neo4j restore | MISP dump | MISP restore |
|---|---|---|---|---|
| 50K nodes (dev) | ~30s | ~1 min | ~10s | ~30s |
| 350K nodes (April 2026 baseline) | ~3 min | ~5-10 min | ~2 min | ~5 min |
| 1M nodes (extreme) | ~10 min | ~30-60 min | ~10 min | ~20 min |

Times are SSDs on a workstation; spinning disk + cloud storage adds 2-5×.

## Audit trail and what this procedure does not cover

Destructive operations leave an audit trail: `src/destructive_ops_audit.py`
appends one JSONL line per Neo4j wipe, CVSS de-duplication and removal of
`Source` nodes keyed by a registry alias that have no relationship
(`ensure_sources`, operation `source_alias_cleanup`) to
`EDGEGUARD_DESTRUCTIVE_OPS_AUDIT_PATH` (default `logs/destructive_ops.jsonl`).
The Neo4j wipes are those of the fresh baseline, of `edgeguard clear neo4j`
and of `scripts/clear_neo4j.py`. Each line names the operation, the store,
the selection (`scope`), the number of nodes deleted (`affected`) and the
process that ran the delete (`actor`: operating-system user, host, program).
A Neo4j wipe that fails after deleting something also writes a line: `affected`
and `details.relationships_deleted` count what it deleted before the failure,
`details.outcome` is `failed` and `details.error` names the error. The graph
client retries a wipe after a transient Neo4j error, and each attempt writes
its own line, so the lines of one run add up to what it deleted.
For the `baseline_clean` DAG task that process is the Airflow worker, so the
line does not say who triggered the run or with which run conf.

Not covered:

- **Automated pre-flight backup hook** — option to take the snapshot AS
  part of `fresh-baseline` rather than as a manual prerequisite
- **Backup-validation script** — verify the dump is restorable without
  actually restoring (parse + size + checksum sanity)

This manual procedure is the supported path. Operators who run
`fresh-baseline` regularly should script the backup steps + timestamp
update into a wrapper.

## Cross-references

- [docs/AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — `edgeguard_baseline` task chain (additive vs destructive modes)
- [docs/DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) — Neo4j memory + storage sizing (relevant for dump sizing)
- [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md) — component readiness and the controls in place

---

_Last updated: 2026-10-25_

## History

- 2026-10-25 — Audit trail: `ensure_sources` writes a line when it deletes `Source` nodes keyed by a registry alias that have no relationship (`source_alias_cleanup`).
- 2026-10-25 — URLhaus re-reads its abuse.ch `recent.csv` export (the keyless 30-day download answers HTTP 410 since 2026-10).
- 2026-10-23 — A Neo4j wipe that fails part-way writes an audit line with what it deleted (`details.outcome = "failed"`), one per attempt when the graph client retries; before, only a wipe that completed wrote a line, and a retried wipe recorded only the nodes of its last attempt.
- 2026-10-23 — Each audit line names the process that ran the delete (`actor`); the wipes of `edgeguard clear neo4j` and `scripts/clear_neo4j.py` are listed with that of the fresh baseline.
- 2026-10-23 — The readiness cross-reference points to PRODUCTION_READINESS.md; the README section it named was removed.
- 2026-10-17 — Main text restated as a guide to current behaviour; change history moved to this section.
- 2026-10-17 — The 350K-node row of the restore times names the April 2026 baseline on which they were measured.
- 2026-10-17 — The Neo4j dump runs offline, because Community Edition refuses to dump a database in use, and needs a backup mount (`./backups/neo4j:/backups`) on the `neo4j` service, which `docker-compose.yml` does not have.
- 2026-10-17 — The MISP dump and restore run in MISP's own containers (MySQL in `misp_db_1` in the reference compose), not through EdgeGuard's compose project; the quick reference exports `EDGEGUARD_LAST_BACKUP_AT` to the host shell, because the CLI reads its own environment, not `.env`.
- 2026-10-17 — Airflow task ids `baseline_clean` / `full_neo4j_sync`, the incremental window of each source, the node count of the 730-day baseline of 2026-10-16 and the destructive-operations audit trail documented; the open items (automated pre-flight backup hook, backup validation) are listed under *Not covered*.
- 2026-06-11 — The `baseline_clean` DAG task enforces the backup-timestamp gate for UI/API triggers with `{"fresh_baseline": true}`, which had bypassed it; the quick reference recreates the containers with `docker compose up -d`, because `restart` does not re-read `.env` interpolations.
- 2026-04-20 — The gate auto-skips on a clean install where both stores are empty.
- 2026-04-20 — Document created with the backup-timestamp gate of `edgeguard fresh-baseline`.
