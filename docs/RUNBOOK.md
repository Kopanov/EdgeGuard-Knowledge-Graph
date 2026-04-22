# EdgeGuard On-Call Runbook

**Audience:** on-call operator responding to an alert or incident during
a baseline or incremental sync.

**Scope:** failure modes observed during pre-PR-N7 730d baselines +
kill-switches added in PR-N10 through PR-N18 to let on-call revert
a specific PR-Nx semantic change without a code revert.

**Deployment assumption:** this RUNBOOK targets the shipped `docker-compose.yml`
topology (services: `edgeguard-neo4j`, `edgeguard-misp`, `edgeguard-airflow-*`).
Kubernetes deployments should substitute `kubectl` for `docker` below.

---

## Quick reference — kill-switches

Each kill-switch is a process environment variable read at request time
(not module import), so toggling requires a task restart, not a redeploy.

| Env var | Default | When to set | What it reverts |
|---|---|---|---|
| `EDGEGUARD_RESPECT_CALIBRATOR` | unset (guard active) | Calibrator demotions causing false negatives after PR-N10; operator wants pre-N10 overwrite behaviour | `_confidence_respect_calibrator` emits bare literal (pre-PR-N10), not CASE guard |
| `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` | unset (inspection active) | Result-counter inspection itself throwing (driver API drift, double-consume) — mid-baseline | `_record_batch_counters` short-circuits to no-op (pre-PR-N9 B6). Emits a `[KILL-SWITCH-ACTIVE]` WARN at module import when set so on-call can confirm the flag took effect via `docker logs edgeguard-airflow-worker 2>&1 \| grep -m1 '\[KILL-SWITCH-ACTIVE\]'`. |
| `EDGEGUARD_EARLIEST_IOC_DATE` | `1995-01-01` | Importing pre-1995 corpora; seeing ingest silently drop historical IOCs with a `before earliest-allowed` WARN | Loosens the `_clamp_future_to_now` earliest-date floor. Accepts ISO date (e.g. `1970-01-01`). Invalid values fall back to default with a WARN. |

Set via task env (one-off):

```bash
# Docker Compose deployment — pass through the airflow worker env
EDGEGUARD_RESPECT_CALIBRATOR=0 docker compose exec airflow-worker \
  airflow tasks run edgeguard_incremental sync …
```

or persistent in `.env` at repo root (same env is read by all services
via docker-compose `env_file`):

```
EDGEGUARD_RESPECT_CALIBRATOR=0
EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1
EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01
```

Restart the affected service (`docker compose restart airflow-worker`) for
the change to take effect. Revert by unsetting + restarting.

---

## Prometheus alert → paging severity

| Alert | Severity | Metric / threshold |
|---|---|---|
| `EdgeGuardMispBatchPermanentFailure` | critical | `rate(edgeguard_misp_push_permanent_failure_total[5m]) > 0` for 5m |
| `EdgeGuardMispSustainedBackoff` | warning | `increase(edgeguard_misp_push_backoff_triggered_total[15m]) > 1` for 15m |
| `EdgeGuardMispHonestNullViolation` | warning | `increase(edgeguard_misp_honest_null_violation_total[1h]) > 100` for 1h |
| `EdgeGuardNeo4jIneffectiveBatch` | critical | `rate(edgeguard_neo4j_merge_ineffective_batch_total[5m]) > 0` for 5m |
| `EdgeGuardNeo4jBatchPermanentFailure` | critical | `rate(edgeguard_neo4j_batch_permanent_failure_total[5m]) > 0` for 5m |
| `EdgeGuardMergeRejectPlaceholderSpike` | warning | `increase(edgeguard_merge_reject_placeholder_total[15m]) > 10` for 15m |

Verify alerts load cleanly on baseline day:

```bash
promtool check rules prometheus/alerts.yml
```

---

## Top 6 failure modes

Each entry: symptom → detection signal → remediation.

### 1. MISP batch permanent failure (5xx exhaustion)

- **Symptom.** One or more 500-attribute batches lost; post-baseline
  `MATCH (i:Indicator {source: 'otx'}) RETURN count(i)` is lower than
  `edgeguard_indicators_collected_total{source="otx"}` counter value.
- **Prom alert.** `EdgeGuardMispBatchPermanentFailure` — critical.
- **Log probe.** `docker logs edgeguard-airflow-worker 2>&1 | grep "\[MISP-PUSH-FAILURE\]" | tail -20`
- **Root cause.** MISPWriter's `@retry_with_backoff(max_retries=4)` gave
  up after four attempts. Typical triggers: MISP PHP memory_limit below
  event-size threshold, MySQL `innodb_buffer_pool_size` too small for
  working set, MISP worker OOM.
- **Remediation.**
  1. Check MISP container memory: `docker stats edgeguard-misp --no-stream`
  2. Check MISP logs for OOM/segfault:
     `docker logs edgeguard-misp 2>&1 | grep -iE "out of memory|segfault|killed"`
  3. Tune per `docs/MISP_TUNING.md § TL;DR — Apply these on the MISP container`
  4. No scripted batch-replay exists. Re-triggering the source collector DAG
     re-harvests from upstream and dedups against existing MISP events:
     `docker compose exec airflow-worker airflow dags trigger edgeguard_daily`

### 2. MISP sustained backoff (flap vs overload)

- **Symptom.** Ingest stalling in 5-minute waves; nightly incremental
  runs exceeding 1-hour SLO.
- **Prom alert.** `EdgeGuardMispSustainedBackoff` — warning.
- **Log probe.** `docker logs edgeguard-airflow-worker 2>&1 | grep "\[MISP-BACKOFF\]" | tail -20`
- **Root cause.** MISP backend is sustained-degraded (not a transient
  flap — the adaptive backoff distinguishes them).
- **Remediation.** Same as (1) — this is usually the early-warning
  before (1) fires.

### 3. Honest-NULL violation (collector forging timestamps)

- **Symptom.** Calibrator decay runs attribute staleness from
  `first_seen`, but the data comes out obviously wrong — everything
  looks ~1 day old regardless of actual source age.
- **Prom alert.** `EdgeGuardMispHonestNullViolation` — warning (fires
  when a specific (source, field) pair exceeds 100 violations/hour).
- **Log probe.**
  ```bash
  docker logs edgeguard-airflow-worker 2>&1 | grep "\[honest-NULL\]" | tail -50
  ```
  (the log prefix is literally `[honest-NULL]` per
  `src/collectors/misp_writer.py:143`)
- **Root cause.** PR-N5 C7 validator caught a collector calling
  `datetime.now()` as a fallback when the source feed was silent on a
  timestamp. The violation log line names the source + field.
- **Remediation.**
  1. Identify the (source, field) pair from the log lines or from
     `edgeguard_misp_honest_null_violation_total{source=...,field=...}`
  2. Audit the named collector's extraction path for
     `datetime.now()` / `datetime.utcnow()` fallbacks.
  3. Remove the fallback — pass `None` through (honest-NULL).
  4. Ship fix via hotfix PR; do NOT disable the validator.

### 4. Neo4j ineffective-batch (silent write failure)

- **Symptom.** Incremental sync task reports success, but post-run
  `MATCH (n:Label) RETURN count(n)` shows no growth for that label.
- **Prom alert.** `EdgeGuardNeo4jIneffectiveBatch` — critical.
- **Log probe.** `docker logs edgeguard-airflow-worker 2>&1 | grep "\[MERGE-INEFFECTIVE\]" | tail -20`
- **Root cause.** Three common triggers:
  1. Source node missing (the SOURCED_FROM MATCH returns zero rows; the
     per-row edge MERGE silently never runs).
  2. Constraint violation on primary MERGE key.
  3. Schema drift (new MISP attribute type, stale Cypher).
- **Remediation.**
  1. Confirm Source node exists:
     ```bash
     docker compose exec neo4j cypher-shell \
       "MATCH (s:Source {source_id: '<source>'}) RETURN s"
     ```
     If empty, re-run `ensure_sources()` via the standalone CLI:
     ```bash
     docker compose exec airflow-worker python -m src.neo4j_client --bootstrap-sources
     ```
     (flag added in PR-N18; if using an older image, the equivalent Python:
     `python -c "from neo4j_client import Neo4jClient; c=Neo4jClient(); c.connect(); c.create_constraints(); c.create_indexes(); c.ensure_sources(); c.close()"`)
  2. Tail Neo4j log for constraint violations:
     `docker logs edgeguard-neo4j 2>&1 | grep -i constraint | tail -20`
  3. For schema drift: diff the failing Cypher against
     `src/neo4j_client.py` MERGE site; add the missing property coalesce.

### 5. Neo4j batch PERMANENT failure (PR-N15 retry exhaustion)

- **Symptom.** A MERGE batch gave up after exponential-backoff retries
  or hit a non-retryable exception. Up to 1000 rows per batch silently
  lost UNTIL the operator alert fires.
- **Prom alert.** `EdgeGuardNeo4jBatchPermanentFailure` — critical. Fires
  within 5m of the first occurrence; label includes `reason` = `retries_exhausted`
  or `non_retryable`.
- **Log probe.**
  ```bash
  docker logs edgeguard-airflow-worker 2>&1 | grep "\[BATCH-PERMANENT-FAILURE\]" | tail -20
  docker logs edgeguard-airflow-worker 2>&1 | grep "\[BATCH-RETRY\]" | tail -20  # see retry attempts preceding
  ```
- **Root cause by reason label.**
  - `retries_exhausted` → Neo4j overloaded. Three retries (2s→4s→8s) didn't recover. GC pause, lock contention, cluster failover.
  - `non_retryable` → schema / constraint / syntax error. Won't be fixed by retrying.
- **Remediation.**
  1. If `retries_exhausted`: pause the DAG, let Neo4j recover, manually
     re-trigger the sync task once load drops. Consider scaling Neo4j
     heap (`NEO4J_dbms_memory_heap_max__size`) and `innodb_buffer_pool_size`
     on MISP's MySQL.
  2. If `non_retryable`: check Neo4j logs for the actual error:
     `docker logs edgeguard-neo4j --tail=200 | grep -iE "error|exception"`.
     This is a code bug — file an issue + hotfix PR.

### 6. Placeholder-name MERGE spike (feed regression or attack)

- **Symptom.** Growing volume of `[MERGE-REJECT]` WARN log lines;
  Malware / ThreatActor node count flatlined despite sync activity.
- **Prom alert.** `EdgeGuardMergeRejectPlaceholderSpike` — warning
  (fires when `increase(edgeguard_merge_reject_placeholder_total[15m]) > 10` per (label, source)).
- **Log probe.**
  ```bash
  docker logs edgeguard-airflow-worker 2>&1 | grep "\[MERGE-REJECT\]" | \
    awk '{print $NF}' | sort | uniq -c | sort -rn | head
  ```
- **Root cause.** A collector is emitting Malware / ThreatActor nodes
  with placeholder names (`unknown`, `N/A`, `generic`, `malware`, `apt`,
  `trojan`, …). Feed regression (upstream schema change) or, in the
  worst case, an adversary injecting malicious `Malware{name:"unknown"}`
  nodes to cause false-attribution storms via Q9 edges. See
  `src/node_identity.py:_REJECTED_PLACEHOLDER_NAMES` for the full
  blocklist.
- **Remediation.**
  1. Identify the offending collector from the `source` label on the
     alert / the log line source=... field.
  2. If feed regression: file an issue against the feed upstream;
     extend the collector's normalization to skip placeholder names
     before they reach `merge_malware()`.
  3. If suspected injection: freeze the source, audit that MISP event's
     attributes, purge pre-PR-N10 garbage nodes (if any) with:
     ```cypher
     MATCH (m:Malware)-[r]->()
     WHERE toLower(trim(m.name)) IN ['unknown','n/a','generic','apt','malware']
     DETACH DELETE m
     ```
  4. PR-N10's merge-time reject already blocked actual new writes —
     the graph is safe. Focus on WHY the collector started emitting.

---

## Baseline-day protocol

### Before a 730d baseline run

1. **Smoke test.** Run a 7-day window first (`baseline=True, baseline_days=7`
   in the baseline DAG config). Success criteria: no ERROR lines, all
   6 pre-baseline alerts green, spot-check 10 random Indicators via
   Neo4j Browser or `graphql_api`.
2. **Prometheus rules loaded.** Verify the `edgeguard_pipeline_observability`
   rule group has all 6 alerts (4 from PR-N11/N12 + 2 added in PR-N18):
   ```bash
   promtool check rules prometheus/alerts.yml
   curl -s localhost:9090/api/v1/rules | \
     jq '.data.groups[] | select(.name=="edgeguard_pipeline_observability") | .rules[].name'
   ```
3. **Alert paging destinations confirmed.** Test that each alert
   actually reaches the on-call pager/inbox. Manual metric injection:
   `curl -X POST localhost:9091/metrics/job/manual -d 'edgeguard_neo4j_batch_permanent_failure_total{label="test",source="test",reason="test"} 1'`
4. **Worker RAM sized.** NVD baseline holds ~1-2 GB of CVE dicts in
   memory (HIGH gap tracked for follow-up). Ensure `airflow-worker`
   container has ≥ 4 GB RAM: `docker inspect edgeguard-airflow-worker | grep -i mem`.
5. **Kill-switches staged.** Decide in advance what signal would make
   you set each:
   - `EDGEGUARD_RESPECT_CALIBRATOR=0` → if edges flap confidence 0.3 ↔ 0.8 nightly (PR-N10 Fix #2 regression signal).
   - `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1` → if `_record_batch_counters` raises persistently in logs.
   - `EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01` → if ingesting historical corpora and seeing `before earliest-allowed` WARNs.

### During the run

- Monitor the 6 `edgeguard_pipeline_observability` alerts continuously.
- Any **critical** alert → pause the DAG, triage, then resume. Do NOT let
  it continue silently.
- Any **warning** alert → investigate, continue unless you see compounding.
- Heartbeat log: `docker logs edgeguard-airflow-worker 2>&1 --follow | grep -vE 'DEBUG|INFO'`

### After the run

Run these post-run validation queries (each via
`docker compose exec neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD`):

```cypher
// 1. Pre-PR-N10 calibrator flap leftover — expect ~0.
MATCH ()-[r]->()
WHERE r.calibrated_at IS NOT NULL AND r.confidence_score > 0.5
RETURN count(r) AS post_fix_candidates;

// 2. Orphan Indicators (PR-N9 B6 silent-write signal) — expect 0.
MATCH (i:Indicator)
WHERE NOT EXISTS { (i)-[:SOURCED_FROM]->(:Source) }
RETURN count(i) AS orphans;

// 3. Post-PR-N14 clamp regression check — expect 0.
MATCH (n)
WHERE n.cvss_score > 10 OR n.cvss_score < 0
RETURN count(n) AS cvss_out_of_range;
MATCH ()-[r]->()
WHERE r.confidence_score > 1 OR r.confidence_score < 0
RETURN count(r) AS confidence_out_of_range;

// 4. Post-PR-N16 aliases type integrity — expect 0.
MATCH (n) WHERE n.aliases IS NOT NULL
AND NOT (n.aliases IS :: LIST<ANY>)
RETURN count(n) AS aliases_scalar_corruption;

// 5. Node count by label — diff vs. expected baseline scale.
CALL db.labels() YIELD label
CALL { WITH label MATCH (n) WHERE label IN labels(n) RETURN count(n) AS c }
RETURN label, c ORDER BY c DESC;
```

Any non-zero on #1–#4 = regression; file issue.

---

## See also

- `docs/MISP_TUNING.md` — backend tuning for failure modes 1-2
- `docs/KNOWLEDGE_GRAPH.md` — schema reference
- `docs/VERSIONING.md` — CalVer release cadence
- `prometheus/alerts.yml` — alert rule source of truth
- `src/neo4j_client.py:_record_batch_counters` — ineffective-batch detector (PR-N9 B6)
- `src/neo4j_client.py:_confidence_respect_calibrator` — calibrator-respect helper (PR-N10)
- `src/neo4j_client.py:_execute_batch_with_retry` — batch retry helper (PR-N15)
- `src/neo4j_client.py:_is_retryable_neo4j_error` — exception classifier (PR-N15)
- `src/collectors/nvd_collector.py:NvdBatchFetchError` — NVD silent-window-drop guard (PR-N17)
- `src/node_identity.py:_REJECTED_PLACEHOLDER_NAMES` — placeholder blocklist (PR-N10 + PR-N10-followup)
