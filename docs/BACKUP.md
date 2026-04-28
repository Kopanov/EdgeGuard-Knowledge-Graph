# Backup & Recovery — EdgeGuard Knowledge Graph

> **Status: ✅ Production-ready.** This procedure is the operator pre-requisite
> for `edgeguard fresh-baseline` (the destructive command). Without an
> up-to-date `EDGEGUARD_LAST_BACKUP_AT` timestamp, the CLI refuses to run
> (PR-F2 backup-timestamp gate).

## Why this exists

`edgeguard fresh-baseline` permanently deletes:

- All EdgeGuard nodes + edges in Neo4j (~350K nodes / ~700K edges on a
  730-day baseline)
- All EdgeGuard-tagged events in MISP (~8K events on a real-world deployment)
- All collector checkpoints (per-source incremental cursors)

**There is no built-in undo.** A single command can wipe hours of historical
threat-intel collection. This document is the recovery story.

## Quick reference

```bash
# 1. Take a backup BEFORE running fresh-baseline
docker compose exec neo4j neo4j-admin database dump neo4j --to-path=/backups
docker compose exec misp /var/www/MISP/app/Console/cake admin event export json /backups/misp-events.json

# 2. Update the freshness timestamp the CLI gate checks
echo "EDGEGUARD_LAST_BACKUP_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> .env
docker compose restart api graphql airflow

# 3. NOW you can run the destructive command
edgeguard fresh-baseline --days 730
```

## The backup-timestamp gate (PR-F2)

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

### Auto-skip on clean installs (PR-F3, Issue #58)

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
run on a now-emptied graph is exactly the case we want to allow without
ceremony, and per-collector cursor state is not user-meaningful data.

## Backup procedures by deployment shape

### Self-hosted Neo4j (Docker Compose, the default)

The `neo4j-admin database dump` tool is the canonical online-backup utility
for Neo4j Community Edition. It pauses writes briefly during the dump
(usually < 1 second on a 350K-node graph) and produces a single `.dump` file.

```bash
# Create backups dir + dump
docker compose exec neo4j mkdir -p /backups
docker compose exec neo4j neo4j-admin database dump neo4j \
    --to-path=/backups \
    --overwrite-destination=true

# Verify the dump exists + has a sane size
docker compose exec neo4j ls -lh /backups/neo4j.dump
# Expected: 100MB-2GB depending on graph size
```

**Dump file location:** `/backups/neo4j.dump` inside the `neo4j` container.
For host-side persistence, mount a volume:

```yaml
# docker-compose.yml — add to neo4j service
volumes:
  - ./backups:/backups
```

Then `./backups/neo4j.dump` is on the host filesystem — copy/sync to
durable storage (S3, BorgBackup, etc.) per your retention policy.

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
for restoration:

**Option A — MySQL dump (canonical):**

```bash
docker compose exec misp mysqldump -u misp -p$MYSQL_PASSWORD misp > backups/misp-$(date +%F).sql
```

**Option B — MISP CakePHP event export (MISP-aware):**

```bash
docker compose exec misp /var/www/MISP/app/Console/cake admin event export json /backups/misp-events.json
```

Option B is preferred when restoring to a different MISP instance (handles
MISP version drift); Option A is faster for same-instance restore.

## Restore procedure

### Worked example: fresh-baseline failed at 14:05 UTC

**Scenario:** Operator triggered `edgeguard fresh-baseline` at 14:00 UTC.
`baseline_clean_task` succeeded (Neo4j wiped, MISP cleared, checkpoints
cleared) at 14:01. `baseline_full_sync_task` failed at 14:05 with a MISP
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

# Restore (overwrites current data)
docker compose run --rm neo4j neo4j-admin database load neo4j \
    --from-path=/backups \
    --overwrite-destination=true

# Restart
docker compose start neo4j
```

**Step 3 — Restore MISP events:**

```bash
docker compose exec misp mysql -u misp -p$MYSQL_PASSWORD misp < backups/misp-2026-04-19.sql
```

**Step 4 — Reset incremental checkpoints to pre-baseline state:**

If you took a backup of `checkpoints/baseline_checkpoint.json` (recommended
when running fresh-baseline against a graph with prior incremental work):

```bash
cp backups/baseline_checkpoint-2026-04-19.json checkpoints/baseline_checkpoint.json
```

If no checkpoint backup exists, the next incremental run will re-collect
the source's full lookback window (typically 3 days per
`EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS`).

**Step 5 — Restart and verify:**

```bash
docker compose start airflow api graphql
edgeguard doctor    # verify all services connect
edgeguard --help    # sanity check
```

The graph should reflect the 13:50 state. The 14:05 failure is now
recoverable; investigate the MISP rate-limit, fix the root cause, then
take a fresh backup + retry.

## Expected restore times

| Graph size | Neo4j dump | Neo4j restore | MISP dump | MISP restore |
|---|---|---|---|---|
| 50K nodes (dev) | ~30s | ~1 min | ~10s | ~30s |
| 350K nodes (production baseline) | ~3 min | ~5-10 min | ~2 min | ~5 min |
| 1M nodes (extreme) | ~10 min | ~30-60 min | ~10 min | ~20 min |

Times are SSDs on a workstation; spinning disk + cloud storage adds 2-5×.

## What's NOT in this procedure (yet)

These are tracked in [Issue #53 (PR-E backlog)](../../issues/53):

- **Audit-trail JSONL** for destructive operations — the operator who
  triggered `fresh-baseline` + when + with what conf
- **Automated pre-flight backup hook** — option to take the snapshot AS
  part of `fresh-baseline` rather than as a manual prerequisite
- **Backup-validation script** — verify the dump is restorable without
  actually restoring (parse + size + checksum sanity)

For now, this manual procedure is the supported path. Operators who run
`fresh-baseline` regularly should script the backup steps + timestamp
update into a wrapper.

## Cross-references

- [docs/AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — `edgeguard_baseline` task chain (additive vs destructive modes)
- [docs/DOCKER_SETUP_GUIDE.md](DOCKER_SETUP_GUIDE.md) — Neo4j memory + storage sizing (relevant for dump sizing)
- [Issue #53](../../issues/53) — operational hardening backlog (audit trail, automated backup hook)
- [README.md § Roadmap & Status](../README.md#-roadmap--status) — current production-ready vs in-progress scope

---

_Last updated: 2026-04-28 — PR-N35 Tier-1 docs audit: verified — no factual drift. All commands (`docker compose exec neo4j neo4j-admin database dump …`) match the live `docker-compose.yml` `neo4j:` service; `EDGEGUARD_BACKUP_MAX_AGE_HOURS` env var exists and is read at `src/edgeguard.py:2341` (default 240h). Footer added as part of the audit trail._
