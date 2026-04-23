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
| `EdgeGuardBuildRelationshipsSilentDeath` | critical | `absent(build_rels_completions) or rate == 0` for 6h after baseline start (PR-N21 Bravo-ops) |
| `EdgeGuardApocBatchPartial` | warning | `increase(edgeguard_apoc_batch_partial_total[15m]) > 0` (PR-N21 Bravo-ops) |

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

- **Symptom.** Growing volume of `[MERGE-REJECT]` WARN log lines OR
  `[MERGE-PLACEHOLDER-REJECTED]` INFO log lines (the latter is the
  PR-N28 sync-loop equivalent: per-event placeholder rejections that
  are counted but no longer crash the sync — graph is SAFE);
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

### 7. Baseline postcheck skipped due to upstream failure (PR-N27)

- **Symptom.** Airflow `baseline_postcheck` task log contains a
  `[BASELINE-POSTCHECK-SKIPPED]` ERROR line; postcheck task state =
  `skipped` instead of `success` / `failed`.
- **What it means.** An upstream task in the baseline chain
  (`full_neo4j_sync`, `build_relationships`, or `run_enrichment_jobs`)
  failed (or itself was upstream_failed / skipped). The PR-N27 sentinel
  in `assert_baseline_postconditions` detected this state and raised
  `AirflowSkipException` — INTENTIONALLY abstaining from running
  invariants because they would trivially violate (Campaign=0,
  Indicator=0, Source=0) for upstream reasons, NOT a real data-integrity
  breach. The DAG is correctly marked FAILED via the original upstream
  task state; `baseline_complete` is also skipped so the operator
  doesn't see "BASELINE Complete!" on a failed run.
- **What it does NOT mean.** It does NOT mean an invariant violation.
  Don't investigate INV-1/2/3 (Campaign=0 etc.) as the root cause.
- **Triage.**
  1. Read the upstream-state table in the same log line:
     `State table: {'full_neo4j_sync': 'failed', 'build_relationships':
     'upstream_failed', ...}` — the FAILED entry is the actual cause.
  2. Pull that task's log and triage from there.
  3. If `full_neo4j_sync` failed with placeholder-rejection errors
     (4-ish errors, all alienvault_otx-flavoured): pre-PR-N28 bug —
     verify PR-N28 is deployed; placeholder rejections should now
     surface as `[MERGE-PLACEHOLDER-REJECTED]` INFO logs and NOT crash
     the sync.
- **No alert needed.** The DAG-level FAILED state is already alerted
  via `EdgeGuardDAGRunFailures`; `[BASELINE-POSTCHECK-SKIPPED]` is
  documentation, not a separate-page-worthy event.

---

## Bravo-ops: memory posture for the next baseline

After the 2026-04-04 baseline was OOM-killed (exit 137) during
`build_relationships`, and the 2026-04-22 baseline silently returned
`Campaign = 0` due to a downstream enrichment swallower (now fixed in
PR-N21), these are the memory settings and alerts that should guard
the next 26h baseline run:

### Memory ceilings (reconcile BEFORE kickoff)

On an 8 GB Airflow worker with Neo4j co-hosted (typical EdgeGuard
dev/staging topology):

| Knob | Value | Why |
|---|---|---|
| `AIRFLOW_MEMORY_LIMIT` | `12g` | Allow headroom above the ~8 GB working set that MISP-to-Neo4j sync consumes on 100K+ event baselines |
| `NEO4J_HEAP_MAX` | `8g` | Matches `NEO4J_HEAP_INITIAL`; avoids GC pauses from heap resize mid-APOC |
| `NEO4J_TX_MEMORY_MAX` | **`≤ 4g`** | **Critical.** Per-TX cap. Above 4g you risk Neo4j `MemoryLimitExceededException` inside a single APOC `periodic.iterate` batch → partial data loss (`[PARTIAL]` log + `EdgeGuardApocBatchPartial` alert). Cap it. |
| `NEO4J_PAGECACHE` | `4g` | Enough for 350K-node working set without eating heap |

Worker resident set: baseline should peak around 6 GB. **If
`docker stats edgeguard-airflow-worker` shows RSS > 6 GB before the
baseline even kicks off, raise `AIRFLOW_MEMORY_LIMIT` first or the
baseline will OOM mid-run.**

### Two Bravo-ops Prometheus alerts (added in PR-N21)

Both fire on the new counters `build_relationships` now emits:

| Alert | Fires when | Severity | What to do |
|---|---|---|---|
| `EdgeGuardBuildRelationshipsSilentDeath` | `edgeguard_build_relationships_completions_total` hasn't incremented for 6h while a baseline DAG started in the last 8h | critical | subprocess died silently (exit 137 OOM, SIGKILL, TX memory exhausted). Check docker stats + Neo4j logs for `MemoryLimit`. Raise memory ceilings, re-trigger. |
| `EdgeGuardApocBatchPartial` | any `apoc.periodic.iterate` in build_relationships returned non-empty `errorMessages` in last 15m | warning | partial data loss in that step. Grep `[PARTIAL]` in worker logs for the step identifier and error detail; re-run that single step or accept partial and move on. |

Verify both load cleanly on baseline day:

```bash
promtool check rules prometheus/alerts.yml
curl -s localhost:9090/api/v1/rules | \
  jq '.data.groups[] | select(.name=="edgeguard_pipeline_observability") | .rules[].name' | \
  grep -E 'BuildRelationshipsSilentDeath|ApocBatchPartial'
```

### APOC partial-batch response playbook

When `EdgeGuardApocBatchPartial` fires:

1. Find the step and first few error messages:
   ```bash
   docker logs edgeguard-airflow-worker 2>&1 | grep -E '\[PARTIAL\]' | tail -5
   ```
2. Classify the root cause from the logged `errorMessages`:
   - `MemoryLimitExceededException` → Neo4j TX memory cap hit. Lower batch size for that step, OR raise `NEO4J_TX_MEMORY_MAX` (but watch the ceiling — above 4g on 8 GB worker and you're eating worker RSS).
   - `DeadlockDetected` → transient, re-run the step.
   - Schema / constraint error → code bug, file an issue, do NOT re-run blindly.
3. Option A — re-trigger the whole `edgeguard_baseline` DAG from `build_relationships` task in Airflow UI (Graph view → click `build_relationships` → "Clear" → confirm). It re-runs all 12 sub-steps, but the early-step MERGEs are idempotent so only the failed step's edges are re-created. There is currently NO per-step CLI flag — `src/build_relationships.py` runs all 12 steps as a single Python program. (See Issue #58 for the planned `--step N` CLI; until then, full-task re-run is the supported path.)
4. Option B — if partial data is acceptable for the demo window, leave it. The next incremental sync will fill in most missed edges. Flag for follow-up.

### Post-run summary grep

A successful baseline should always emit this line:

```bash
docker logs edgeguard-airflow-worker 2>&1 | grep -E '\[BUILD_RELATIONSHIPS SUMMARY\]'
# expected: total_edges=N failures=0/12 per_query=[...]
```

Absence of this line = silent subprocess death (the exact scenario the
`EdgeGuardBuildRelationshipsSilentDeath` alert guards against).

---

## Baseline-day protocol

### ⚠️ Baseline launch path — PICK ONE (CLI or DAG+pause)

The 730-day baseline runs for ~26h. Over that window, the 4 scheduled
incremental DAGs will try to write to MISP + Neo4j in parallel with the
baseline unless you stop them. This is Issue #57 (documented in
`docs/flow_audits/01_baseline_sequence.md` Finding 1) and was the
underlying cause of the 2026-04-19 MISP-PHP-FPM exhaustion + 14.7%
NVD loss. Three regression xfails pin this contract in
`tests/test_tier1_sequential_robustness.py` — they stay failing until
Issue #57 ships a DB-backed mutex.

**Until Issue #57 lands, pick one of the two safe launch paths below.**

#### Option A — CLI (recommended)

The CLI path acquires an in-process `baseline_lock` sentinel
(`src/run_pipeline.py:1093`) that makes every `baseline_skip_reason()`
check on the scheduled DAGs return a reason — they self-skip.

```bash
docker compose exec -T airflow-worker \
  python -m edgeguard baseline --days 730
```

Or for the fresh-baseline shape (wipes existing Neo4j data first):

```bash
docker compose exec -T airflow-worker \
  python -m edgeguard fresh-baseline --days 730
```

Confirm the lock sentinel is present during tier-1:

```bash
docker compose exec airflow-worker ls /tmp/edgeguard/baseline_lock.sentinel
# expect: /tmp/edgeguard/baseline_lock.sentinel  (file present while baseline runs)
```

#### Option B — DAG + pre-pause the 4 incremental schedulers

If you must use the Airflow UI trigger, pause the 4 scheduled DAGs
first so they cannot fire during the ~26h window:

```bash
docker compose exec airflow-worker airflow dags pause edgeguard_daily
docker compose exec airflow-worker airflow dags pause edgeguard_medium_freq
docker compose exec airflow-worker airflow dags pause edgeguard_pipeline
docker compose exec airflow-worker airflow dags pause edgeguard_low_freq

# trigger the baseline
docker compose exec airflow-worker airflow dags trigger edgeguard_baseline

# AFTER baseline + enrichment complete (watch the baseline_complete task):
docker compose exec airflow-worker airflow dags unpause edgeguard_daily
docker compose exec airflow-worker airflow dags unpause edgeguard_medium_freq
docker compose exec airflow-worker airflow dags unpause edgeguard_pipeline
docker compose exec airflow-worker airflow dags unpause edgeguard_low_freq
```

Alternatively, run the preflight helper which verifies the 4 DAGs are
paused AND the MISP/Neo4j endpoints respond AND env-var prerequisites
are satisfied before returning exit 0:

```bash
./scripts/preflight_baseline.sh
```

Exit non-zero = do NOT launch. Exit zero + green summary = safe to trigger.

#### Why not both CLI + DAG?

CLI delegates to the DAG via `_trigger_baseline_dag` in recent releases
(`src/edgeguard.py:2377`) but takes the in-process lock FIRST. If you
trigger the DAG directly without pausing, nothing takes the lock →
incrementals race.

---

### Before a 730d baseline run

1. **Launch path decided.** Per the section above (CLI vs DAG+pause).
2. **Preflight green.** `./scripts/preflight_baseline.sh` returns exit 0.
3. **Smoke test.** Run a 7-day window first (`baseline=True, baseline_days=7`
   in the baseline DAG config). Success criteria: no ERROR lines, all
   6 pre-baseline alerts green, spot-check 10 random Indicators via
   Neo4j Browser or `graphql_api`.
4. **Prometheus rules loaded.** Verify the `edgeguard_pipeline_observability`
   rule group has all 8 alerts (4 from PR-N11/N12 + 2 added in PR-N18 +
   2 Bravo-ops added in PR-N21):
   ```bash
   promtool check rules prometheus/alerts.yml
   curl -s localhost:9090/api/v1/rules | \
     jq '.data.groups[] | select(.name=="edgeguard_pipeline_observability") | .rules[].name'
   ```
5. **Alert paging destinations confirmed.** Test that each alert
   actually reaches the on-call pager/inbox. Manual metric injection:
   `curl -X POST localhost:9091/metrics/job/manual -d 'edgeguard_neo4j_batch_permanent_failure_total{label="test",source="test",reason="test"} 1'`
6. **Worker RAM sized.** NVD baseline holds ~1-2 GB of CVE dicts in
   memory (HIGH gap tracked for follow-up). Ensure `airflow-worker`
   container has ≥ 4 GB RAM: `docker inspect edgeguard-airflow-worker | grep -i mem`.
7. **Kill-switches staged.** Decide in advance what signal would make
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

## Retrieving raw MISP data from a Neo4j node

Three complementary retrieval paths exist for every MISP-sourced node
(Indicator, CVE, Vulnerability, Malware, ThreatActor, Technique,
Tactic, Tool). Use whichever fits your consumer.

### ⚠️ `n.uuid` is NOT the MISP link

`n.uuid` is a **deterministic UUIDv5** computed from `(label, natural_key)`
(`src/node_identity.py:compute_node_uuid`). It's stable across
environments (local vs cloud Neo4j produce the same `n.uuid` for the
same logical entity) and has **STIX parity** (the UUID portion of a
STIX SDO id equals `n.uuid`). It is NOT a foreign key into MISP.

### Path 1 — MISP attribute UUID (most granular)

Every MISP-sourced node carries `n.misp_attribute_ids[]` — the real
MISP attribute UUID(s) captured at ingest
(`src/run_misp_to_neo4j.py:2311`).

```cypher
MATCH (i:Indicator) WHERE i.value = '203.0.113.5'
RETURN i.misp_attribute_ids;
// returns e.g. ['5f8d-abcd-...', '61b2-efgh-...']
```

Fetch raw attribute JSON from MISP:

```bash
curl -H "Authorization: $MISP_API_KEY" \
     -H "Accept: application/json" \
     "$MISP_URL/attributes/5f8d-abcd-..."
```

### Path 2 — MISP event ID (coarser, per-event context)

`n.misp_event_ids[]` carries stringified MISP event IDs.

```cypher
MATCH (i:Indicator) WHERE i.value = '203.0.113.5'
RETURN i.misp_event_ids;
// returns e.g. ['12345', '12678']

MATCH ()-[r:INDICATES]->(:Malware {name: 'Cobalt Strike'})
RETURN r.misp_event_ids LIMIT 10;
```

Fetch the event (contains all related attributes):

```bash
curl -H "Authorization: $MISP_API_KEY" \
     "$MISP_URL/events/12345"
```

### Path 3 — Raw MISP JSON on SOURCED_FROM edge (no network call)

Every per-source ingest carries the raw MISP attribute JSON pickled
into `r.raw_data` on the `SOURCED_FROM` edge
(`src/neo4j_client.py:_upsert_sourced_relationship`). Useful when you
need the original payload without a round-trip to MISP.

```cypher
MATCH (i:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'otx'})
WHERE i.value = '203.0.113.5'
RETURN r.raw_data LIMIT 1;
```

### Coverage

| Node label | Attribute UUID | Event IDs | Raw JSON on edge |
|---|:-:|:-:|:-:|
| Indicator | ✅ | ✅ | ✅ |
| CVE / Vulnerability | ✅ | ✅ | ✅ |
| Malware | ✅ | ✅ | ✅ |
| ThreatActor | ✅ | ✅ | ✅ |
| Technique / Tactic / Tool | ✅ | ✅ | ✅ |
| Campaign | via inbound edges only | via inbound edges only | — |
| Sector | — (fixed vocab) | — | — |

---

## PR-N22: backfill historical CVE `published` / `last_modified`

### When to run

PR-N19 Fix #1 closed the MISP-sourced `merge_cve` path that was silently
dropping `published` / `last_modified` before 2026-04-22. The write path
is fixed in code, but any CVE ingested before PR-N19 deployed has NULL
date fields in Neo4j. Run this script when:

- You want to demo/export graph data with proper CVE timelines
- You don't have 26h for a fresh full baseline
- You want to preserve existing edge counts / confidence scores (a
  backfill is non-destructive; a re-baseline would rebuild everything)

### How to run

Safe + idempotent. Dry-run first, then execute:

```bash
# 1. Dry-run — logs what WOULD change, writes nothing
./scripts/backfill_cve_dates_from_nvd_meta.py --dry-run

# 2. Real run against cloud Neo4j (env vars set)
export NEO4J_URI="bolt+s://neo4j-bolt.edgeguard.org:443"
export NEO4J_PASSWORD="<cloud-password>"
export MISP_URL="https://misp.edgeguard.org"
export MISP_API_KEY="<key>"
export EDGEGUARD_SSL_VERIFY=true
./scripts/backfill_cve_dates_from_nvd_meta.py --batch-size 100 --rate-limit 10
```

Expected duration: ~1-2 hours for a ~100K-CVE graph at 10 MISP req/s.
Lower `--rate-limit 5` during business hours if MISP is user-facing.

### Verify success

After the script completes:

```cypher
// Expect: very small number (maybe 0) — only CVEs with no NVD_META in MISP
MATCH (c:CVE)
WHERE c.published IS NULL AND size(coalesce(c.misp_attribute_ids,[])) > 0
RETURN count(c) AS still_null;

// Spot-check: top 5 most-connected CVEs should now have dates
MATCH (c:CVE)
WHERE c.published IS NOT NULL
RETURN c.cve_id, c.published, c.last_modified
ORDER BY c.cvss_score DESC LIMIT 5;
```

### Idempotency guarantee

The script's `SET c.published = coalesce(c.published, $pub)` pattern
means re-runs are safe:

- If a baseline ran between script invocations and populated the field,
  the script respects the baseline value (coalesce prefers the existing
  non-NULL).
- If the script crashes mid-run, just re-invoke — it picks up where it
  left off (the `WHERE c.published IS NULL` filter skips already-done).
- Running dry-run → real-run → re-run all produce the same final state.

### Known edge cases

- **CVEs without NVD_META in MISP**: ~0.1-0.5% of CVEs (older events
  with corrupted comment fields). These stay NULL; no data corruption.
- **Rate-limit too aggressive**: if MISP returns 429, lower
  `--rate-limit`. Default 10 req/s is conservative.
- **Neo4j transient errors mid-write**: script logs + increments the
  `errors` counter but continues. Exit code 1 if any error occurred.

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
- `scripts/backfill_cve_dates_from_nvd_meta.py` — historical CVE date backfill migration (PR-N22)
