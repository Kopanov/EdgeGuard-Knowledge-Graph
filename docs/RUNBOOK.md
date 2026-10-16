# EdgeGuard On-Call Runbook

**Audience:** on-call operator responding to an alert or incident during
a baseline or incremental sync.

**Scope:** failure modes observed during pre-PR-N7 730d baselines +
kill-switches added in PR-N10 through PR-N18 to let on-call revert
a specific PR-Nx semantic change without a code revert.

**Deployment assumption:** this RUNBOOK targets the shipped `docker-compose.yml`
topology. Container names (per `container_name:` in compose):

| Service in compose | Container name |
|---|---|
| `neo4j` | `edgeguard_neo4j` |
| `airflow` | `edgeguard_airflow` (single Airflow standalone container — webserver + scheduler + worker bundled per Airflow 3.x) |
| `airflow_postgres` | `edgeguard_airflow_postgres` |
| `api` | `edgeguard_api` |
| `graphql` | `edgeguard_graphql` |

**MISP is NOT in this compose stack** — it's deployed separately and accessed
via `MISP_URL` (typically a sibling container or external host). MISP-side
operations below assume `docker logs <misp-container>` against your MISP
deployment, not a service in this compose file.

Kubernetes deployments should substitute `kubectl` for `docker` below.

---

## Quick reference — kill-switches

Each kill-switch is a process environment variable read at request time
(not module import), so toggling requires a task restart, not a redeploy.

| Env var | Default | When to set | What it reverts |
|---|---|---|---|
| `EDGEGUARD_RESPECT_CALIBRATOR` | unset (guard active) | Calibrator demotions causing false negatives after PR-N10; operator wants pre-N10 overwrite behaviour | `_confidence_respect_calibrator` emits bare literal (pre-PR-N10), not CASE guard |
| `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` | unset (inspection active) | Result-counter inspection itself throwing (driver API drift, double-consume) — mid-baseline | `_record_batch_counters` short-circuits to no-op (pre-PR-N9 B6). Emits a `[KILL-SWITCH-ACTIVE]` WARN at module import when set so on-call can confirm the flag took effect via `docker logs edgeguard_airflow 2>&1 \| grep -m1 '\[KILL-SWITCH-ACTIVE\]'`. |
| `EDGEGUARD_EARLIEST_IOC_DATE` | `1995-01-01` | Importing pre-1995 corpora; seeing ingest silently drop historical IOCs with a `before earliest-allowed` WARN | Loosens the `_clamp_future_to_now` earliest-date floor. Accepts ISO date (e.g. `1970-01-01`). Invalid values fall back to default with a WARN. |

Set via task env (one-off):

```bash
# Docker Compose deployment — pass through the airflow worker env
EDGEGUARD_RESPECT_CALIBRATOR=0 docker compose exec airflow \
  airflow tasks run edgeguard_pipeline collect_otx …
```

or persistent in `.env` at repo root (same env is read by all services
via docker-compose `env_file`):

```
EDGEGUARD_RESPECT_CALIBRATOR=0
EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1
EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01
```

Recreate the affected service (`docker compose up -d airflow` — `restart` does not re-read `.env`) for
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
| `EdgeGuardBuildRelationshipsSilentDeath` | critical | a sync completed 15 h 25 min to 36 h ago (every build_relationships attempt has ended) and no build_relationships completion stamped since (PR-N21; 2026-10 the two timestamps) |
| `EdgeGuardApocBatchPartial` | warning | `increase(edgeguard_apoc_batch_partial_total[15m]) > 0` (PR-N21) |
| `EdgeGuardMispFetchFallbackActive` | warning | `sum by (branch) (rate(edgeguard_misp_fetch_fallback_active_total{outcome="engaged"}[10m])) > 0` for 10m (PR-N31 — sustained fallback engagement signals primary `/events/index` is broken) |
| `EdgeGuardMispFetchFallbackHardError` | **critical** | `sum by (branch) (rate(edgeguard_misp_fetch_fallback_active_total{outcome="hard_error"}[5m])) > 0` for 1m (PR-N31 — `_MispFallbackHardError` sentinel raised; baseline run already failed since `retries=0` on critical chain) |
| `EdgeGuardNeo4jSyncStale` | warning | `time() - edgeguard_neo4j_sync_last_success_timestamp > 439200` (122 h) for 1h (2026-10, was 145 h): no MISP→Neo4j sync, scheduled or baseline, completed within the longest gap the 72-hour schedule leaves plus the next sync's longest run; see "MISP → Neo4j sync schedule" |
| `EdgeGuardNeo4jFullSyncRequestPending` | warning | `edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}` rose in the last 3 days, or appeared for the first time (2026-10): a requested full sync (`NEO4J_FULL_SYNC=true`) failed on its last attempt and the request stands, so no incremental sync runs; it clears 3 days after the last failure, also when the request was resolved earlier (silence it then); see "Requesting a full MISP → Neo4j sync" |
| `EdgeGuardSourceAccessDenied` | warning | `edgeguard_collector_skips_total{reason_class=~".+_auth_denied"}` rose in the last 25 h, or appeared for the first time (2026-10). The provider refuses the source's requests (HTTP 401/403) and the task stays green while nothing is collected: run `python src/source_key_check.py`, renew the key, or check whether the provider blocks this host |

Verify alerts load cleanly on baseline day:

```bash
promtool check rules prometheus/alerts.yml
```

---

## Top 8 failure modes

Each entry: symptom → detection signal → remediation.

### 1. MISP batch permanent failure (5xx exhaustion)

- **Symptom.** One or more 500-attribute batches lost; post-baseline
  `MATCH (i:Indicator) WHERE 'alienvault_otx' IN i.source RETURN count(i)` is lower than
  `edgeguard_indicators_collected_total{source="otx"}` counter value.
- **Prom alert.** `EdgeGuardMispBatchPermanentFailure` — critical.
- **Log probe.** `docker logs edgeguard_airflow 2>&1 | grep "\[MISP-PUSH-FAILURE\]" | tail -20`
- **Root cause.** MISPWriter's `@retry_with_backoff(max_retries=4)` gave
  up after four attempts. Typical triggers: MISP PHP memory_limit below
  event-size threshold, MySQL `innodb_buffer_pool_size` too small for
  working set, MISP worker OOM.
- **Remediation.**
  1. Check MISP container memory: `docker stats <your-misp-container> --no-stream`
  2. Check MISP logs for OOM/segfault:
     `docker logs <your-misp-container> 2>&1 | grep -iE "out of memory|segfault|killed"`
  3. Tune per `docs/MISP_TUNING.md § TL;DR — Apply these on the MISP container`
  4. No scripted batch-replay exists. Re-triggering the source collector DAG
     re-harvests from upstream and dedups against existing MISP events:
     `docker compose exec airflow airflow dags trigger edgeguard_daily`

### 2. MISP sustained backoff (flap vs overload)

- **Symptom.** Ingest stalling in 5-minute waves; nightly incremental
  runs exceeding 1-hour SLO.
- **Prom alert.** `EdgeGuardMispSustainedBackoff` — warning.
- **Log probe.** `docker logs edgeguard_airflow 2>&1 | grep "\[MISP-BACKOFF\]" | tail -20`
- **Root cause.** MISP backend is sustained-degraded (not a transient
  flap — the adaptive backoff distinguishes them).
- **Remediation.** Same as (1) — this is usually the early-warning
  before (1) fires.

### 3. Honest-NULL violation (collector forging timestamps)

- **Symptom.** The indicator aging dates a report by the source's
  `last_seen` (capped at the MISP timestamp, 2026-10-16); a collector
  that stores the run's time there makes every indicator look newly
  reported — everything looks ~1 day old regardless of actual source
  age (`aging_basis = 'source_date'`, tier 0).
- **Prom alert.** `EdgeGuardMispHonestNullViolation` — warning (fires
  when a specific (source, field) pair exceeds 100 violations/hour).
- **Log probe.**
  ```bash
  docker logs edgeguard_airflow 2>&1 | grep "\[honest-NULL\]" | tail -50
  ```
  (the log prefix is literally `[honest-NULL]` — search
  `src/collectors/misp_writer.py` for `[honest-NULL]` to find the
  emit site; line numbers drift, the prefix doesn't.)
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
- **Log probe.** `docker logs edgeguard_airflow 2>&1 | grep "\[MERGE-INEFFECTIVE\]" | tail -20`
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
     docker compose exec airflow python src/neo4j_client.py --bootstrap-sources
     ```
     (the `--bootstrap-sources` flag was added in PR-N18 — runs
     `ensure_sources() + create_constraints() + create_indexes()` as a
     one-shot. Note the invocation is `python src/neo4j_client.py …`,
     not `python -m src.neo4j_client …` — the latter requires an
     `src/__init__.py` that doesn't exist at HEAD.)
  2. Tail Neo4j log for constraint violations:
     `docker logs edgeguard_neo4j 2>&1 | grep -i constraint | tail -20`
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
  docker logs edgeguard_airflow 2>&1 | grep "\[BATCH-PERMANENT-FAILURE\]" | tail -20
  docker logs edgeguard_airflow 2>&1 | grep "\[BATCH-RETRY\]" | tail -20  # see retry attempts preceding
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
     `docker logs edgeguard_neo4j --tail=200 | grep -iE "error|exception"`.
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
  docker logs edgeguard_airflow 2>&1 | grep "\[MERGE-REJECT\]" | \
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

### 7. Baseline chain stopped after a failed step; postcheck (PR-N27, 2026-10)

**7a. Collectors and `full_neo4j_sync` refuse to run (2026-10).**

- **Symptom.** The `tier1_core` / `tier2_feeds` collector tasks (a
  flag-guarded source that is switched off still skips) and
  `full_neo4j_sync` fail at start, without their retry, with `[BASELINE] <step>: baseline_start
  is <state> in this run — refusing to run after a failed baseline_clean /
  baseline_start` (or `... did not succeed (no XCom marker) ...`).
- **What it means.** `baseline_clean` or `baseline_start` did not succeed
  in this DAG run. The tier groups and `full_neo4j_sync` keep
  `trigger_rule=ALL_DONE`, so that one failed source does not stop the
  others; that rule also fires after an upstream failure, and before
  2026-10 every collector and the full sync then ran on an un-wiped store.
  The guard reads the task states of this run from Airflow 3; only where
  Airflow reports none (Airflow 2, or a failed call) does it read the XCom
  marker that `baseline_start` returns on success. A marker left by an
  earlier success therefore does not count, and a `baseline_start` marked
  success by hand does.
- **Triage.** Read the `baseline_clean` log. The clean step's time limit is
  60 minutes (`execution_timeout`, 2026-10). It deletes Neo4j relationships
  in batches of 50,000 before the node batches (a single node batch holding
  hub nodes ran a 2 GB heap out of memory), and it waits up to
  `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` (default 900 s) for each MISP event
  delete, because MISP deletes an event's attributes inside the request
  (the OTX and NVD events of a 730-day baseline hold about 150,000
  attributes each).
  Fix the cause, then clear `baseline_clean` together with its downstream
  tasks (it has `retries=0`); the run resumes under the baseline lock it
  still holds.
  A refusal before the wipe (`[BASELINE_CONF]` typo of `fresh_baseline`,
  invalid `wipe_scope`, `BASELINE_CLEAN refused` by the backup gate) wipes
  nothing and releases the lock (2026-10-16), so the corrected trigger is
  not refused by it: trigger the baseline again with the corrected conf, or,
  after an environment fix (`EDGEGUARD_LAST_BACKUP_AT` set and the container
  recreated), clear `baseline_clean`, which takes the lock again before the
  wipe. Clear it rather than marking it success: a `baseline_clean` marked
  success skips the wipe. `baseline_start` takes the lock again in either
  case, so the collectors and `full_neo4j_sync` do not start without it.

**7b. Postcheck on Airflow 3 (the shipped image).**

- **Symptom.** `baseline_postcheck` fails with `[BASELINE-POSTCHECK]
  upstream task(s) did not succeed: {...}` (or `... (no XCom marker)`),
  after a warning that the upstream-state introspection failed.
- **What it means.** Airflow 3's task instance has no `get_dagrun()`, so
  the PR-N27 path below does not run. The postcheck reads the states of
  `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` in this
  run, or, where Airflow reports none, the XCom markers they return on
  success, and fails when one did not succeed. It fails rather than skips
  because Airflow derives the run state from the leaf tasks and a skipped
  leaf counts as success; before 2026-10 such a run could end `success`
  with `run_enrichment_jobs` failed. Triage the task named in the message.

**7c. Baseline postcheck skipped due to upstream failure — Airflow 2 only, not supported (PR-N27).**

- **Applies to.** Only an Airflow 2 deployment, whose task instance has
  `get_dagrun()`. EdgeGuard runs on Airflow 3 (`requirements.txt` pins
  `apache-airflow~=3.3`; the image, `Dockerfile.airflow`, runs 3.3.2), where
  this path cannot run: the postcheck fails the run as described in 7b.
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
  breach. The skip propagates to `baseline_complete` and to
  `baseline_release_lock`, the run's only leaf task; Airflow derives the
  run state from the leaf tasks and counts a skipped leaf as success, so
  the run ends `success`, not `failed` (corrected 2026-10-16; 7b states the
  same rule). The run is not counted as failed (`EdgeGuardDAGRunFailures`
  does not see it), and the baseline lock is pruned once its liveness check
  reads the run state `success`. On this path the run state does not show the failure; the
  postcheck log does.
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

### 8. MISP fetch fallback (`_MispFallbackHardError`) — PR-N29 / PR-N31

- **Symptom (alert path).** `EdgeGuardMispFetchFallbackHardError`
  fires (severity=critical), OR `EdgeGuardMispFetchFallbackActive`
  fires for >10 minutes (severity=warning), OR
  `MISPToNeo4jSync.run()` traceback shows
  `_MispFallbackHardError: MISP fallback ... on page N`.
- **Symptom (log path).** Grep `[MISP-FETCH-FALLBACK-ACTIVE]` —
  emitted when the primary `/events/index` path errors and the
  PyMISP / requests-restSearch fallback engages. Grep
  `[MISP-FETCH-FALLBACK]` for per-page activity / per-failure
  detail (the sentinel raise's log line is here).
- **What it means.** EdgeGuard's primary MISP `/events/index` path
  failed (auth, 5xx, schema drift, broken sync user). The fallback
  paginated through PyMISP / `restSearch` BUT hit one of four
  hard-failure modes:
  1. **errors-payload mid-pagination** — MISP returned HTTP 200 with
     `{"errors": ...}` (typical: ACL filter matched zero, broken
     sync user, malformed query).
  2. **unexpected payload type** — MISP returned a non-list, non-
     dict-with-response payload (typical: server-side schema bug or
     proxy injecting an HTML error page).
  3. **non-200 mid-pagination** — `response.status_code != 200` on
     a page after the first (typical: MISP-PHP-FPM exhaustion partway
     through a 50-page walk).
  4. **safety-cap hit** — fallback paginated through
     `_FALLBACK_MAX_PAGES = 200` (~100K events) without hitting a
     short-read terminator. MISP legitimately has more events than
     the cap allows.
- **What it does NOT mean.** It does NOT mean the data was silently
  truncated — that's exactly the failure mode the sentinel exists
  to prevent. The Airflow task is FAILED (PR-N29 H1: critical-chain
  tasks have `retries=0`), no partial baseline was committed.
- **Triage.**
  1. Identify which branch raised — the alert label `branch` is
     `pymisp` or `rest_search`. Pipeline log line will reference the
     same. PyMISP-only failures often indicate library/version
     incompatibility; `rest_search` failures are pure HTTP/payload.
  2. Pull the surrounding `[MISP-FETCH-FALLBACK]` log lines for
     the page number + good-pages count + raw error payload.
  3. **For mode (1) errors-payload:** check MISP user permissions,
     ACL config, `EDGEGUARD_MISP_EVENT_SEARCH` env var (defaults to
     "EdgeGuard" — empty string would match nothing).
  4. **For mode (2) unexpected payload:** check upstream proxy
     (Cloudflare / nginx) is not interposing an HTML error page on
     5xx. Test directly: `curl -s -H "Authorization: $MISP_API_KEY"
     "$MISP_URL/events/restSearch" -d '{"limit":1,"metadata":true}' -H "Content-Type:
     application/json" | head`.
  5. **For mode (3) non-200 mid-pagination:** investigate MISP
     backend health (PHP-FPM workers, MariaDB connection pool,
     OOM). The 2026-04-19 incident was MISP-PHP-FPM exhaustion;
     scale workers + reduce `EDGEGUARD_MISP_PAGE_SIZE` (default 500
     → try 250).
  6. **For mode (4) safety-cap hit:** if MISP legitimately has >100K
     EdgeGuard events (on a MISP older than 2.4.177, >100K events of any
     kind: it ignores the fallback's `eventinfo` filter, and the
     EdgeGuard rows are then picked client-side), raise `_FALLBACK_MAX_PAGES` in
     `src/run_misp_to_neo4j.py` and redeploy. Otherwise (probably a
     loop bug or a misconfigured `EDGEGUARD_MISP_EVENT_SEARCH`),
     fix the root cause.
- **Re-run.** After remediation, re-trigger the failed DAG run.
  PR-N29 H1 set `retries=0` on the critical chain — there is no
  auto-retry. The dagrun MUST be manually re-triggered to run.
- **Why the sentinel exists.** Pre-PR-N29 the fallback silently
  truncated at `limit=1000` with no pagination; the
  `EdgeGuardSyncCoverageGap` alert compared a truncated processed-
  count to a truncated index-total and saw "no gap." PR-N29 added
  pagination + the sentinel; PR-N31 added the operator-visible
  Prometheus counter. See PR #110 (PR-N29) and PR-N31 (this PR) for
  the audit history.

---

## Neo4j statement timeouts (`[NEO4J-TIMEOUT]`, 2026-10)

- **What applies.** Every pipeline statement carries a transaction timeout that the Neo4j server enforces. The limits are protection against a statement that hangs, set loose so that a slow statement on a large graph does not reach them:
  - `EDGEGUARD_NEO4J_READ_TIMEOUT` (default 3600 s) for the sync, relationship-build, enrichment and wipe statements;
  - 600 s for the relationship batch writes (a batch takes seconds; deadlocks are reported at once and retried);
  - 300 s for the REST API and STIX export queries.

  A driver opened directly by a CLI command or a script carries none.
- **Symptom.** A task fails with `[NEO4J-TIMEOUT] the server aborted a statement at its N s transaction timeout: <statement>`.
- **Log probe.**
  ```bash
  docker logs edgeguard_airflow 2>&1 | grep "\[NEO4J-TIMEOUT\]" | tail -20
  ```
- **Remediation.**
  - **The statement is expected to run longer on a large graph** (a baseline build step or an enrichment job): raise `EDGEGUARD_NEO4J_READ_TIMEOUT` in `.env`, recreate the Airflow containers and clear the failed task.
  - **The statement stalls without progress:** this points to lock contention or memory pressure; see § 5 above and the memory posture below.

## MISP → Neo4j sync schedule (2026-10)

- **When it runs.** `edgeguard_neo4j_sync` runs every 72 hours, a fixed interval (`schedule=timedelta(days=3)`; until 2026-10 the cron `0 3 */3 * *`, whose runs were 24 h apart at month ends). A run is due 72 h after the previous scheduled run; a manual run does not move the schedule. A run that fell due while the DAG was paused or Airflow was down starts once when it resumes, and the next one is due 72 h after it. The Airflow UI shows the next run under *Next Run*.
- **The 24-hour guard.** `check_sync_needed` skips a run when the last successful sync started less than 24 hours ago (the state file `state/edgeguard_last_neo4j_sync.json`): that happens only after a baseline's full sync or a `force_sync` run, which stamp the file. A skipped run is green, with `run_neo4j_sync` and everything after it skipped, and logs `Skipping Neo4j sync - the last sync started at …`. A regular run is never skipped: even a sync that started on its third attempt (16 h 42 min after its run was due) leaves 55 h until the next.
- **After a baseline.** When `edgeguard_neo4j_sync` is unpaused after the baseline (Baseline-day protocol, Option A) and a run is due, it starts at once and is skipped by the guard if the baseline's full sync started less than 24 hours before; the first scheduled sync then starts at most 96 hours after the baseline's full sync started. It reads the attributes changed since the incremental window overlap before that start (`EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h; one day until 2026-10), which includes what the baseline collected in that overlap. To sync sooner, trigger a forced run: `docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`.
- **`EdgeGuardNeo4jSyncStale`** (warning) fires when no sync, scheduled or baseline, has completed in 122 hours: the longest gap between two sync starts (96 h after a baseline's or a forced sync) plus the longest run of the next sync (32 min of `check_sync_needed` / `neo4j_health_check` attempts, three 8-hour attempts of `run_neo4j_sync` and two 5-minute retry delays), with about an hour for the scheduler (`prometheus/alerts.yml`). `EdgeGuardCollectionStale{source="misp_to_neo4j"}` fires at 98 hours without a sync connecting. When either fires: check that the DAG is not paused (`airflow dags list | grep edgeguard_neo4j_sync`), that the scheduler runs, and the log of the last `run_neo4j_sync` attempt; a baseline holding its lock also skips the sync (`Neo4j sync ShortCircuit: EdgeGuard baseline is running`).
- **Settings no longer read.** The Airflow Variable `NEO4J_SYNC_INTERVAL` and `EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN` set the former 71-hour guard and are ignored; the interval and the guard are fixed in `dags/edgeguard_pipeline.py` (`NEO4J_SYNC_EVERY`, `NEO4J_SYNC_MIN_GAP`), because the alert thresholds are derived from them.

## Requesting a full MISP → Neo4j sync (`NEO4J_FULL_SYNC`, 2026-10)

- **When.** An incremental sync writes only the attributes whose MISP `timestamp` moved, so a change that touches no attribute (event-level tags), a Neo4j restored from a dump older than MISP, or a curated layer removed by hand needs a full sync.
- **How.** Set the Airflow Variable and let the next scheduled run pick it up, or trigger one now:
  ```bash
  docker compose exec airflow airflow variables set NEO4J_FULL_SYNC true
  docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
  ```
  `force_sync` only bypasses the 24-hour skip guard; without the Variable the triggered run is incremental.
- **What the log shows.** `run_neo4j_sync` states the mode, the reason and the attempt at the start: `Sync mode: FULL — requested by the Airflow Variable NEO4J_FULL_SYNC=true … (attempt N)`.
- **Failure and retry.** The Variable is cleared only after the full sync succeeded (`NEO4J_FULL_SYNC cleared after the requested full sync succeeded`). A failed or timed-out attempt leaves it set, and the retries (`retries=2`) run in full again. Before 2026-10 it was cleared before the sync started, so a failed attempt retried as an incremental run and the repair was silently incomplete: after such a failure on an older deployment, check the Variable and set it again. If clearing the Variable fails after a successful sync, a warning names it and the next scheduled run is a full sync again; set it to `false` by hand to avoid that.
- **While the request stands, no incremental sync runs.** Every scheduled run is a full sync until one succeeds. A request that cannot succeed (a full sync longer than the task's limit, or one that reports a single merge or fetch error) therefore fails all three attempts of every run, about a day each time, skips `build_relationships` and `run_enrichment_jobs` (decay included), and keeps new MISP data out of Neo4j. After the last failed attempt the task's failure callback logs `[ALERT] NEO4J_FULL_SYNC is still true after the requested full sync failed on its last attempt …` at ERROR, sends it to Slack when enabled and counts `edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}`, which the Prometheus alert `EdgeGuardNeo4jFullSyncRequestPending` (warning, 2026-10) reads: it fires when the counter rose in the last 3 days, or appeared for the first time, so each failed run of a request that keeps failing is reported again. It follows the counter, not the Variable: it clears 3 days after the last failure, and keeps firing until then after the request was cleared or a later run succeeded, so silence it once the request is resolved (Recovery, below).
- **Recovery.** Find the cause in the `run_neo4j_sync` log of the failed attempts (timeout, `_last_sync_failure_reason`) and fix it, then let the next run repeat the full sync. To resume incremental syncs first, clear the request; the repair it asked for is then not done:
  ```bash
  docker compose exec airflow airflow variables set NEO4J_FULL_SYNC false
  ```
- **Duration.** A full sync of a 730-day MISP takes about 6 hours (the baseline DAG's `full_neo4j_sync` limit). The task's limit is 8 hours (2026-10; it was 4 hours): the estimate plus a third, because a limit at the estimate could fail every attempt of a request that now stands until it succeeds. The DAG run's limit of 68 hours covers every task of the chain failing on all three attempts, plus 20%, as for the other DAGs.

## AbuseIPDB daily blacklist quota (429, 2026-10)

- **Symptom.** `collect_abuseipdb` is red in `edgeguard_daily` or `edgeguard_baseline`. The task log shows `AbuseIPDB: daily blacklist quota exhausted (429) — no cached blacklist available`, and the task's error reads `HTTPError: AbuseIPDB daily blacklist quota exhausted (429)`. The task failure signals (Slack, `edgeguard_pipeline_errors_total`, source health) fire as for any failed collector.
- **Cause.** The free plan allows 5 `GET /blacklist` requests per UTC day, counted per key: every blacklist request made with the same key that day counts, from this deployment or elsewhere. The source key check uses the `check` endpoint and spends none. Before 2026-10 such a 429 produced an empty list, the task stayed green with a count of 0, and that day's blacklist was lost without a signal.
- **What the task does.** The blacklist request returns the 429 at once, without the rate-limit backoff (up to 3 × 10 minutes before 2026-10); 502, 503 and 504 are still retried. The task's own retries (2 in the daily DAG, 1 in the baseline DAG, 5 minutes apart) send one request each and get the 429 again, because the quota is spent until 00:00 UTC; the task therefore ends red within minutes. Nothing is pushed to MISP. The rest of the run continues: the tier-2 group and `full_neo4j_sync` of the baseline and `log_summary` of the daily DAG use `ALL_DONE`, the baseline postcheck checks only the critical chain, and the baseline lock is released.
- **Remediation.** After 00:00 UTC, clear only the failed `collect_abuseipdb` task instance, without its downstream tasks (Airflow UI: the task in that DAG run → Clear, with downstream and upstream not selected); in the baseline run, clearing downstream tasks would repeat the full sync and the build steps. The cleared task sends one new request, or none when a run with the same parameters fetched an answer earlier that UTC day (by default the daily and the baseline runs share one cache key; see "The cached answer"). In the daily DAG clearing is optional: the next scheduled run (02:00 UTC) sends its own request (or, when the task was cleared after 00:00 UTC and succeeded, reuses that answer; see "The cached answer"), and the blacklist is a current list rather than a history, so the failed run's addresses that are still listed come with it. For a baseline, the data reaches MISP when the cleared task succeeds and Neo4j at the next `edgeguard_neo4j_sync` run, because the baseline's full sync has already run; to move it into Neo4j at once, trigger a sync:
  ```bash
  docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
  ```
- **The cached answer.** A successful, non-empty answer is written to `state/abuseipdb_blacklist_cache.json` (`/opt/airflow/state` in the container; the directory named by `EDGEGUARD_STATE_DIR` when it is set) with its request parameters and fetch time. A run reuses it and sends no request when it asks for the same parameters (`confidenceMinimum`, `limit`), the file was written on the current UTC day and it is at most `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` old (default 20; `0` turns the cache off). This covers the task's own retries after a MISP push failure, a cleared task, and a baseline or daily run with the same parameters on the same UTC day. The task log then shows `AbuseIPDB: reusing the blacklist fetched <time> (<age>h old, same UTC quota day, …)`. The daily and the baseline runs share one cache key: with the default settings both ask for `{confidenceMinimum: 90, limit: 10000}` (`limit` is `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN`, the same in both DAGs since 2026-10), so a baseline whose `collect_abuseipdb` runs later on the UTC day of a daily run, within the maximum age, reuses that run's answer and sends no request, and the daily run reuses a baseline's answer fetched after 00:00 UTC that day. Only a lower `limit` gives a run its own request: `EDGEGUARD_MAX_ENTRIES` below 10,000 (daily runs) or a baseline `BASELINE_COLLECTION_LIMIT` below 10,000. An answer from an earlier UTC day is never reused, so the 02:00 UTC daily run never works from the previous day's answer; it reuses one only when a run with the same parameters fetched it after 00:00 UTC that day (for example a failed daily task cleared after midnight, as under Remediation), and otherwise sends a request. A run with other parameters sends its own request and replaces the file (it holds the latest answer only). An empty answer is not kept.
- **Forcing a fresh request.** Delete the file, and the next run or cleared task sends a request (one of the day's 5):
  ```bash
  docker compose exec airflow rm -f /opt/airflow/state/abuseipdb_blacklist_cache.json
  ```
  To turn the cache off, set `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS=0` in `.env` and recreate the Airflow containers.
- **One state directory.** The cache assumes that every task process reads the same state directory, as on the Compose deployment (one Airflow container with the LocalExecutor and the `./state` bind mount, § "Shared state directories"). Workers on separate hosts without a shared directory each miss the cache: no data is lost, but a retry spends another request.

## Bravo-ops: memory posture for the next baseline

After the 2026-04-04 baseline was OOM-killed (exit 137) during
`build_relationships`, and the 2026-04-22 baseline silently returned
`Campaign = 0` due to a downstream enrichment swallower (now fixed in
PR-N21), these are the memory settings and alerts that should guard
the next 32h baseline run (per `dagrun_timeout` in the baseline DAG):

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
`docker stats edgeguard_airflow` shows RSS > 6 GB before the
baseline even kicks off, raise `AIRFLOW_MEMORY_LIMIT` first or the
baseline will OOM mid-run.**

### Two `build_relationships` Prometheus alerts (added in PR-N21)

Both fire on the new counters `build_relationships` now emits:

| Alert | Fires when | Severity | What to do |
|---|---|---|---|
| `EdgeGuardBuildRelationshipsSilentDeath` | a MISP→Neo4j sync completed between 15 h 25 min and 36 h ago (`edgeguard_neo4j_sync_last_success_timestamp`) and `edgeguard_build_relationships_last_completion_timestamp` is older (2026-10; build_relationships follows the sync directly; 5 h per attempt, two retries in the scheduled DAG) | critical | subprocess died silently (exit 137 OOM, SIGKILL, TX memory exhausted). Check docker stats + Neo4j logs for `MemoryLimit`. Raise memory ceilings, re-trigger. |
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
   docker logs edgeguard_airflow 2>&1 | grep -E '\[PARTIAL\]' | tail -5
   ```
2. Classify the root cause from the logged `errorMessages`:
   - `MemoryLimitExceededException` → Neo4j TX memory cap hit. Lower batch size for that step, OR raise `NEO4J_TX_MEMORY_MAX` (but watch the ceiling — above 4g on 8 GB worker and you're eating worker RSS).
   - `DeadlockDetected` → transient, re-run the step.
   - Schema / constraint error → code bug, file an issue, do NOT re-run blindly.
3. Option A — re-trigger the whole `edgeguard_baseline` DAG from `build_relationships` task in Airflow UI (Graph view → click `build_relationships` → "Clear" → confirm). It re-runs all 20 sub-steps, but the early-step MERGEs are idempotent so only the failed step's edges are re-created. There is currently NO per-step CLI flag — `src/build_relationships.py` runs all 20 steps as a single Python program. (See Issue #58 for the planned `--step N` CLI; until then, full-task re-run is the supported path.)
4. Option B — if partial data is acceptable for the demo window, leave it. The next incremental sync will fill in most missed edges. Flag for follow-up.

### Post-run summary grep

A successful baseline should always emit this line:

```bash
docker logs edgeguard_airflow 2>&1 | grep -E '\[BUILD_RELATIONSHIPS SUMMARY\]'
# expected: total_edges=N failures=0/20 per_query=[...]
```

Absence of this line = silent subprocess death (the exact scenario the
`EdgeGuardBuildRelationshipsSilentDeath` alert guards against).

Every collector run also emits one grep-able push summary (Issue #62,
2026-06):

```bash
docker logs edgeguard_airflow 2>&1 | grep "COLLECTOR_SUMMARY"
# expected per source: COLLECTOR_SUMMARY source=nvd items=N pushed=S failed=F \
#                      attempted=A success_rate=R min_success_rate=T
```

A `success_rate` below `EDGEGUARD_MISP_MIN_SUCCESS_RATE` (default **0.95**,
`0` disables) now marks the collector run **failed** — the Airflow task goes
RED with the rate in the error instead of the pre-2026-06 behavior where one
successful attribute out of 92k made the run green (how the 2026-04-19
baseline silently lost 14.7% of NVD attributes). Rate is computed over
**attempted** pushes only — deduplicated re-runs are unaffected. Remediation
for a tripped gate = failure mode 1 above (MISP batch permanent failure);
the re-trigger is dedup-safe. Since 2026-10-16 the writer logs the items no
MISP attribute could be built from (an unknown item type, an empty value, CVE
id, name or ATT&CK id), which MISP never saw, in one `[CONVERT] N item(s)
could not be converted …` line per push: per source, how many of its items,
the reasons and whether they count as failed. They count as failed only when
they are all or at least half of a source's items in the push
(`CONVERT_FAILED_MIN_SHARE` in `src/collectors/misp_writer.py`), and the error
then names both causes. A red task whose `[CONVERT]` line is an ERROR, with
`item(s), counted as failed` for a source, means that source's payload
stopped converting: the fix is in the collector or the source's payload, not
in MISP, and a re-trigger fails the same way. The exception is a line that
reads `1 of 1` or `1 of 2` for the source: one bad record in a small window,
which clears once a window holds three or more of the source's items. A
`[CONVERT]` WARNING (every source `item(s), not counted as failed`) is a few
bad records; the run goes on, the source's cursor is not held by these items,
and the line repeats while the source keeps sending them. The line names each
source by its tag (`alienvault_otx`, `threatfox`, …).

---

## Shared state directories

`./state` and `./checkpoints` are bind-mounted into the Airflow container (`/opt/airflow/state`, `/opt/airflow/checkpoints`), so `edgeguard doctor`, `monitor`, `stats` and `checkpoint status` on the host read the files the DAGs wrote (sync state, collector checkpoints, `baseline_in_progress.lock`). The `airflow-init` service creates the directories owned by uid 50000 before Airflow starts. On a deployment created before these mounts it first copies the existing state file and checkpoints from the `airflow_db` volume into the host directories (no overwrite; the process-held lock files `baseline_in_progress.lock` and `pipeline.lock` are not copied), so the sync watermark and resume points are kept. Host-side deletes (`edgeguard checkpoint clear`, removing a stale sentinel) go through `docker compose exec airflow …` unless the host user owns the directories.

## Baseline-day protocol

### ⚠️ Baseline launch path — PICK ONE (CLI or DAG+pause)

The 730-day baseline runs for ~32h (matches the baseline DAG's
`dagrun_timeout`). Over that window the 5 scheduled DAGs check the
`checkpoints/baseline_in_progress.lock` sentinel at task start and skip
while the `edgeguard_baseline` DAG holds it (`baseline_acquire_lock`,
taken before the destructive `baseline_clean` step; released by
`baseline_release_lock` after a successful run). In `edgeguard_neo4j_sync`
every task that writes checks it, not only the first task
`check_sync_needed`: `run_neo4j_sync` (and its retries), `build_relationships`
and `run_enrichment_jobs` skip at their start too (2026-10-16). The
baseline's own collector tasks and its `build_relationships` are not skipped
by the lock of their own run; a log line
`[BASELINE] <SOURCE> NOT collected — the baseline lock is held by another
run` means a second baseline was started. A failed run keeps the
lock so that clearing the failed task resumes under the mutex, except
after a refusal of `baseline_clean` before the wipe, which releases it
(2026-10-16; § 7a); an
abandoned run's sentinel is reaped at the age cap, or remove it by hand:
`docker compose exec airflow rm /opt/airflow/checkpoints/baseline_in_progress.lock`.
This is Issue #57 (root cause
in `docs/flow_audits/01_baseline_sequence.md` Finding 1, the 2026-04-19
MISP-PHP-FPM exhaustion + 14.7% NVD loss), closed in 2026-10. The
holder's liveness is the DAG-run state read through the Airflow REST
API, with the sentinel age as fallback (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`,
default 48 h). `tests/test_tier1_sequential_robustness.py` pins the
DAG-side acquisition. A scheduled task that is already running when the
lock is taken completes its current write, so pausing the scheduled DAGs
before a destructive `fresh-baseline` remains recommended.

**Pick one of the two launch paths below.**

> **2026-10:** the `baseline_in_progress.lock` sentinel is written by the
> baseline DAG itself (`baseline_acquire_lock`) and by the legacy
> in-process `python src/run_pipeline.py --baseline` path. The
> `edgeguard baseline` / `edgeguard fresh-baseline` wrappers trigger the
> DAG and add safety UX; they do not pause anything.

#### Option A — DAG trigger, optionally pre-pausing the 5 scheduled DAGs (recommended)

Whether you trigger via the Airflow UI, the API, or the CLI wrappers,
the baseline DAG holds the lock and the scheduled DAGs skip at task
start. Pausing them first guarantees that none is mid-write when the
lock is taken (recommended before a destructive fresh-baseline; this
includes `edgeguard_neo4j_sync` — a full MISP→Neo4j sync firing
mid-baseline is the same concurrent-writer hazard):

```bash
docker compose exec airflow airflow dags pause edgeguard_daily
docker compose exec airflow airflow dags pause edgeguard_medium_freq
docker compose exec airflow airflow dags pause edgeguard_pipeline
docker compose exec airflow airflow dags pause edgeguard_low_freq
docker compose exec airflow airflow dags pause edgeguard_neo4j_sync

# trigger the baseline
docker compose exec airflow airflow dags trigger edgeguard_baseline

# AFTER baseline + enrichment complete (watch the baseline_complete task).
# edgeguard_neo4j_sync: a run that fell due while paused starts at once and is skipped
# within 24 h of the baseline's full sync; the next sync follows within 96 h of it
# ("MISP → Neo4j sync schedule").
docker compose exec airflow airflow dags unpause edgeguard_daily
docker compose exec airflow airflow dags unpause edgeguard_medium_freq
docker compose exec airflow airflow dags unpause edgeguard_pipeline
docker compose exec airflow airflow dags unpause edgeguard_low_freq
docker compose exec airflow airflow dags unpause edgeguard_neo4j_sync
```

Alternatively, run the preflight helper which verifies the 5 DAGs are
paused AND the MISP/Neo4j endpoints respond AND env-var prerequisites
are satisfied before returning exit 0:

```bash
./scripts/preflight_baseline.sh --launch-path=dag
```

Exit non-zero = do NOT launch. Exit zero + green summary = safe to trigger.

#### What about the CLI commands?

`edgeguard baseline --days N` (additive) and `edgeguard fresh-baseline`
(destructive — typed confirmation + backup-timestamp gate) trigger the
same `edgeguard_baseline` DAG; they add safety UX, not a mutex of their
own. The `baseline_in_progress.lock` sentinel is held by the DAG
(`baseline_acquire_lock`) and by the legacy in-process
`python src/run_pipeline.py --baseline` run (Issue #57).

---

### Before a 730d baseline run

1. **Launch path decided.** Per Option A above — trigger the
   `edgeguard_baseline` DAG (`airflow dags trigger edgeguard_baseline`, the
   Airflow UI, or the `edgeguard baseline` / `edgeguard fresh-baseline`
   wrappers, which trigger the same DAG), preferably after pausing the 5
   scheduled DAGs.
2. **Preflight green.** `./scripts/preflight_baseline.sh` returns exit 0.
   Check `[12]` asks every provider whether it accepts the configured API
   key; a rejected key means that source is skipped for the whole baseline
   (a rejected NVD key stops it). The baseline DAG repeats the check in its
   `source_key_check` task, before the lock and the wipe.
3. **Smoke test.** Run a 7-day window first (`baseline=True, baseline_days=7`
   in the baseline DAG config). Success criteria: no ERROR lines, all
   6 pre-baseline alerts green, spot-check 10 random Indicators via
   Neo4j Browser or `graphql_api`.
4. **Prometheus rules loaded.** Verify the `edgeguard_pipeline_observability`
   rule group has at least 11 alerts (4 from PR-N11/N12 + 2 added in PR-N18 +
   2 `build_relationships` alerts added in PR-N21 + 2 MISP-fetch-fallback added in PR-N31 +
   1 PR-N24 H3 placeholder-pager). The full `prometheus/alerts.yml` has more
   rules than this — `[11] PR-N29 invariants` in `scripts/preflight_baseline.sh`
   enforces a floor of `≥ 11` against the canonical YAML.:
   ```bash
   promtool check rules prometheus/alerts.yml
   curl -s localhost:9090/api/v1/rules | \
     jq '.data.groups[] | select(.name=="edgeguard_pipeline_observability") | .rules[].name'
   ```
5. **Alert paging destinations confirmed.** Test that each alert
   actually reaches the on-call pager/inbox. Manual metric injection:
   `curl -X POST localhost:9091/metrics/job/manual -d 'edgeguard_neo4j_batch_permanent_failure_total{label="test",source="test",reason="test"} 1'`
6. **Worker RAM sized.** NVD baseline holds ~1-2 GB of CVE dicts in
   memory (HIGH gap tracked for follow-up). Ensure the `airflow`
   container has ≥ 4 GB RAM: `docker inspect edgeguard_airflow | grep -i mem`.
7. **Kill-switches staged.** Decide in advance what signal would make
   you set each:
   - `EDGEGUARD_RESPECT_CALIBRATOR=0` → if edges flap confidence 0.3 ↔ 0.8 nightly (PR-N10 Fix #2 regression signal).
   - `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1` → if `_record_batch_counters` raises persistently in logs.
   - `EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01` → if ingesting historical corpora and seeing `before earliest-allowed` WARNs.

### During the run

- Monitor the `edgeguard_pipeline_observability` rule group continuously
  (≥ 11 alerts at HEAD; floor enforced by preflight `[11]` — see PR-N31).
  The two PR-N31 fallback alerts (`EdgeGuardMispFetchFallbackActive`,
  `EdgeGuardMispFetchFallbackHardError`) should be SILENT for the entire
  run if everything is healthy.
- Any **critical** alert → pause the DAG, triage, then resume. Do NOT let
  it continue silently.
- Any **warning** alert → investigate, continue unless you see compounding.
- Heartbeat log: `docker logs edgeguard_airflow 2>&1 --follow | grep -vE 'DEBUG|INFO'`

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

Then run the acceptance script, `python scripts/verify_fresh_baseline.py`
([BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) § "Fresh-baseline
acceptance"). Since 2026-10 it also fails when a relationship built from the
sources names no source (`relationships_name_their_source`) or when a
provenance list is stored as a plain string (`provenance_lists_are_lists`).

Since 2026-10-16 it also checks the sector evidence and two properties of the 2026-10-16 writers:

| Check | Fails when | Not judged |
|---|---|---|
| `sector_links_name_only_feeds_that_gave_the_sector` | a link to a `Sector` names a feed whose `SOURCED_FROM.zones` do not hold that sector | no `SOURCED_FROM` edge has `zones` (a graph built before) |
| `advisory_sector_only_where_cisa_stated` | `advisory_sector` sits on anything but an `AFFECTS` link from a CVE to a sector the `cisa_ics` edge lists in `stated_zones` | no link carries the label |
| `cisa_stated_sectors_linked_as_advisory_sector` | a sector CISA stated is not linked as `advisory_sector`; with `--require-cisa-ics`, also when no sector is stated although the `cisa_ics` edges carry `zones` | no stated sector, when `--require-cisa-ics` is not given, no `cisa_ics` edge carries `zones` (a graph built before, or kept and not re-read since) or `--legacy-graph` is given |
| `sector_links_cite_only_records_that_gave_the_sector` | a sector link cites a CISA ICS advisory whose sector note does not name its sector (the `cisa_ics` edge records the advisories per sector in `stated_refs`) | no `SOURCED_FROM` edge has `stated_refs` |
| `sector_confidence_follows_label` | a sector link's confidence is not the label table's value (`src/sector_evidence.py`; a label outside the table is not judged) | no sector link |
| `descriptions_name_their_source` | a node with a ranked description (CVE, Vulnerability, Malware, ThreatActor, Tool, Technique, Tactic) has no `description_source` | `--legacy-graph`, or no description |
| `indicators_have_aging_basis` | an Indicator has no `aging_basis` or no `source_confidence` | `--legacy-graph`, or no Indicator |

It also reports, without judging, the sector links by type, start label, sector and label
(`sector_evidence_breakdown`), what CISA ICS adds per sector (`cisa_ics_contribution`: stated, by CISA
alone, also inferred, and the CISA records whose advisory named no tracked sector) and the node sectors no
feed gave and the nodes holding `global` next to a sector (`node_sectors_without_a_feed`). Run it with
`--legacy-graph` on a graph built before 2026-10-16: the description-source and aging checks fail there by
construction (no writer before set those properties), and with `--require-cisa-ics` no CISA ICS record can
have stated a sector (`cisa_stated_sectors_linked_as_advisory_sector` is then reported, not judged; it is
not judged either while no `cisa_ics` edge carries `zones`). After the 730-day baseline with
`EDGEGUARD_ENABLE_CISA_ICS=true`, run it with `--require-cisa-ics`.

**Measuring CISA ICS and ATT&CK for ICS.** Count CISA's sector statements by label (`advisory_sector` on
`AFFECTS`) or through the `cisa_ics` `SOURCED_FROM` edge's `stated_zones`; count ATT&CK for ICS through
the links into `Technique {attack_domain: 'ics'}` (actors and software carry no domain). The queries are in
[NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md), "Measuring CISA ICS and ATT&CK for ICS". On a graph
built before 2026-10-16 a sector link names every feed of the node: count CISA there through MISP (the
`source:CISA-ICS` attributes and their `zone:*` tags) or `SOURCED_FROM.raw_data`, not `r.sources`. Those
extra entries stay on a kept graph (provenance only accumulates) until a wipe and a new baseline.

---

## Importing a curated package (2026-10)

A curated package (JSON, e.g. `2026-10-20_EdgeGuard_CoreIdeas_package.json`) adds claims about existing actors and malware as one MISP event; the next MISP→Neo4j sync turns them into relationships (see `docs/KNOWLEDGE_GRAPH.md`, "Curated packages"). Import it after the baseline, since its claims attach only to nodes that exist.

```bash
python scripts/import_curated_package.py PACKAGE.json                 # validate: summary, warnings, errors
python scripts/import_curated_package.py PACKAGE.json --check-graph   # + per predicate, claims that would not attach
python scripts/import_curated_package.py PACKAGE.json --push          # create the MISP event (MISP_URL / MISP_API_KEY)
```

The validation refuses the package (errors block `--push`) when its `source` is not a registered curated source (`coreideas`, `misp_galaxy`; `source_type="curated"` in `src/source_registry.py`) or when it has no `tlp`. It rejects a single claim — listed as a warning, counted under `claims_skipped_by_reason` in the summary, never written to MISP — when the claim's source is not a registered curated source, its object id is malformed (technique `T1234` / `T1234.123`, tool `S1234`, CVE `CVE-YYYY-NNNN`), its predicate does not fit its subject, or it has no object. The package's TLP level is tagged on the event and on every attribute; it marks each claim's link (`r.tlp`) and the STIX relationship exported from it.

`--check-graph` only reads Neo4j (`NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD`, optionally `NEO4J_DATABASE`). For each predicate it reports how many valid claims find both ends by the exact name or id the sync matches on, how many lack their subject or their object, and a sample of the missing names, so the package can be aligned with the graph before `--push`.

The event is unpublished and visible to the creating organisation only. A fresh baseline removes it with the other EdgeGuard events: import it again afterwards.

**After the sync.** A claim attaches only when both its subject and its object exist by exact canonical name or id. A link the claim creates gets the package's curated label (`coreideas_curated`) at 0.85; a link that already exists keeps its label and confidence and gains the claim's provenance. Each write logs `[CURATED] <attached> of <sent> curated claim(s) attached` (WARNING, with a sample of the missing names, when some did not attach), and the run summary adds `Curated package claims: <n> attached, <m> not attached`. Claims that did not attach are not errors and are not counted as relationships created.

**Removing the layer without a re-feed.** Delete the package's event in MISP, then run on Neo4j (replace `<event id>` with the package's MISP event id, printed by `--push`):

```cypher
// 1. The links the package created: they carry its curated label.
MATCH ()-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_MALWARE|USES_TOOL|EXPLOITS]->()
WHERE r.match_type IN ['coreideas_curated', 'curated_other']
DELETE r;

// 2. Its entries on the links it did not create (those keep another source's label).
MATCH ()-[r:EMPLOYS_TECHNIQUE|IMPLEMENTS_TECHNIQUE|USES_MALWARE|USES_TOOL|EXPLOITS]->()
WHERE any(s IN coalesce(r.sources, []) WHERE s IN ['coreideas', 'misp_galaxy', 'curated_other'])
SET r.sources = [s IN r.sources WHERE NOT s IN ['coreideas', 'misp_galaxy', 'curated_other']],
    r.source_refs = [x IN coalesce(r.source_refs, [])
                     WHERE NOT split(x, ':')[0] IN ['coreideas', 'misp_galaxy', 'curated_other']],
    r.misp_event_ids = [e IN coalesce(r.misp_event_ids, []) WHERE e <> '<event id>']
REMOVE r.tlp;
```

Only curated claims set `r.tlp`, so step 2 removes it. A link the package created and another source asserted afterwards (an OTX pulse naming the same technique, say) still carries the curated label and is deleted in step 1; the relationship build and a full sync (`NEO4J_FULL_SYNC=true`) recreate it from that source's data. To remove one package of several, delete its event, remove the layer as above and run a full sync, which writes the remaining packages' claims again. To leave the layer out of a shared dataset without removing it, filter on `r.sources`, not on `r.match_type` (`docs/KNOWLEDGE_GRAPH.md`, "Curated packages").

A claim may name a technique id ATT&CK revoked (`T1086`): the validation accepts it, lists it under `revoked_technique_ids` with its successor and warns, the claim goes to MISP as written, and the sync links it to the successor (see "Rebuilding the ATT&CK revoked-id map" below).

In Neo4j the claims are relationships like any other: the API routes that traverse relationships (for example `GET /actors/{name}/summary` and `/graph/explore`) and the STIX bundles expose them (2026-10: a STIX relationship names the curated source in `x_edgeguard_sources` and is marked with at least the package's TLP level; `x_edgeguard_match_type` shows the curated label only on a link the package created). No export filter by source exists, so import a package only on an instance whose API consumers may receive its claims.

## Canonical threat-actor reference (2026-10)

The actor alias merge (`merge_alias_duplicate_actors`) reads `src/reference/canonical_threat_actors.json`. At each run it logs `[ACTOR-ALIAS-MERGE] canonical reference <version>: <n> actors`. The warning `canonical reference unavailable (<reason>); merging by MITRE aliases only` means the file is missing, unreadable, larger than 16 MB, of another `schema_version` or inconsistent, or that its data could not be applied to the graph's names. The merge then runs on ATT&CK aliases alone; restore the file (or `EDGEGUARD_CANONICAL_THREAT_ACTORS`) and the next run uses it again.

The job's other warnings name pairs it did not merge:

- `(ambiguous)`: the name is an ATT&CK alias of several groups;
- `(conflict)`: the ATT&CK aliases and the reference name different canonical actors, or the reference keeps the name as an actor of its own;
- `(blocked)`: the name is an ATT&CK alias of a group, but the reference marks it ambiguous or never_merge;
- `(chain)`: the node is also a canonical in the same run.

The final line, `[ACTOR-ALIAS-MERGE] complete — …`, counts each kind.

A conflict or a blocked pair after an ATT&CK release usually means the reference predates the release: rebuild it (below).

**Attribution from a source report (2026-10).** The OTX collector, the MISP→Neo4j sync, `build_relationships` step 2d and the acceptance check `attribution_from_single_actor_reports` read the same reference to decide whether a pulse's actors are one actor. Without it the collector, the sync and step 2d each log `[ATTRIBUTION] canonical reference unavailable (<reason>)` once (the acceptance check reports it in its detail), and they behave as follows: the collector and the sync count every name as an actor, so the aliases of one actor count as several and the pulse attributes nothing (since 2026-10-16 the collector writes such a pulse into `several_actor_pulses_by_name`, `OTX_META.sapn` / `MITRE_USES_TECHNIQUES.sapn`, which the sync uses for its own run and never stores on a node; the pulse's pairs come when it is collected again with the reference, as new IOCs carry them); step 2d links only the pairs whose pulse it can tell names one actor by name (the aliases of one actor count as several, and a name the alias merge folded away finds no node) and removes nothing; the acceptance check is informational. The sync logs `[ATTRIBUTION] report <pulse> names several actors: its malware is attributed to none of them` for each such pulse and counts them in its summary. Step 2d and the acceptance check also take the pulses the collector marked on indicators (`Indicator.several_actor_pulses`, 2026-10-16) as naming several actors, as the collector judged them with the reference, whether or not step 2d has it; step 2d logs `[ATTRIBUTION] N pulse(s) name several actors (M marked on K indicator(s) by the OTX collector)`, and a failed read of either source skips the step and fails the run. A pulse edited to name several actors after MISP stored its IOCs gets its mark only through its new IOCs: the MISP writer adds no mark to a stored copy (2026-10: MISP keeps what the sources said; the `[MARK]` comment edits were removed), so a pulse whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit to be closed by a per-pulse MISP record. A mark on a node is never cleared by a later run. Should one be wrong (written by an earlier release from a judgement by name), remove the pulse ids from the nodes, then run step 2d again; the stored copies in MISP still carry the mark, so a full sync brings it back until they are corrected too:

```cypher
// $pulses: the OTX pulse ids to unmark
MATCH (i:Indicator) WHERE any(p IN coalesce(i.several_actor_pulses, []) WHERE p IN $pulses)
SET i.several_actor_pulses = [p IN i.several_actor_pulses WHERE NOT p IN $pulses]
```

**Rebuilding.** The inputs are:

- the threat-actor entities export of the MISP galaxies;
- the raw mitre-intrusion-set galaxy dump it was built from (ATT&CK revocations);
- an export of the graph's `ThreatActor` nodes, which is read-only and is kept outside the repository. Its ATT&CK-sourced nodes are the ATT&CK version EdgeGuard loaded. Their aliases are read from the record MITRE delivered (the node's `SOURCED_FROM` edge to the ATT&CK source), not from the node: the node's `aliases` also hold every name the merge folded in, which are no ATT&CK claims. An export made before 2026-10-15 lacks these aliases and is refused;
- `src/reference/canonical_threat_actor_overrides.json`.

```bash
python scripts/build_canonical_threat_actors.py --export-graph-actors /tmp/graph_threat_actors.json
python scripts/build_canonical_threat_actors.py --galaxy galaxy_threat_actors_<date>.json \
    --attack-galaxy-raw misp_galaxy_mitre-intrusion-set_<date>.json \
    --graph-actors /tmp/graph_threat_actors.json --unresolved-out /tmp/unresolved_actors.json
```

The version defaults to the build date. The same inputs and version give a byte-identical file. Review the printed report before committing:

- the revoked folds and the ATT&CK groups anchored from the loaded version;
- the 360net-threat-actor records left out because they join no ATT&CK actor;
- the duplicate groups the merge would fold, and the ATT&CK aliases the reference resolves elsewhere (the merge skips those pairs as conflicts or blocked);
- the spelling variants, the spellings of one name that two actors held (made ambiguous), and the suffix-rule short forms, including those another actor held by a galaxy synonym;
- every override decision with its effect.

Add or change decisions only in the overrides file, with a reason, a date and `"status": "proposed"` until reviewed. A rebuild keeps them. `tests/test_canonical_threat_actors.py` fails when the overrides file changed after the last build.

**At each ATT&CK release.** After the MITRE collector has loaded the new release, export the graph again and rebuild. In the report's canonical-key check, every ATT&CK node must be either a canonical key or a revoked group that resolves to its successor. Then look at:

- groups the new release renamed, which take the loaded name;
- new groups, anchored by name;
- ATT&CK aliases that now resolve elsewhere.

When the release revokes groups, take a new MISP galaxy dump as well, so that the revocations are folded.

## Rebuilding the ATT&CK revoked-id map (2026-10)

`src/reference/attack_revoked_ids.json` maps every revoked ATT&CK technique, group and software id to its successor. The MITRE collector skips revoked objects; the feeds still cite their ids, and `build_relationships`, the sync (MISP technique tags and curated claims) and the STIX export translate a revoked technique id with this map (`docs/KNOWLEDGE_GRAPH.md`, "Revoked and deprecated ATT&CK objects"). ATT&CK revokes objects in every release. When the map is older than the bundle the collector reads, the collector keeps each revoked technique the map does not list and logs `[ATTACK-REVOKED] N technique(s) the bundle revokes are not in the revoked-id map (<ids>); kept, so the links that cite them are not lost`. Those links stay on the old ids until the map is rebuilt; the next run then skips the techniques and links their ids to the successors.

**When.** At each ATT&CK release (twice a year, usually April and October; the release notes list the revoked objects), after MISP's galaxies carry that release.

**How.**

1. Update the galaxies on the MISP instance (Administration → Galaxies → Update all galaxies, or `POST /galaxies/update`) and check that the `mitre-attack-pattern` galaxy version moved.
2. Capture the answer of `POST /galaxy_clusters/restSearch` for each of `mitre-attack-pattern`, `mitre-intrusion-set`, `mitre-malware`, `mitre-tool` (and `mitre-ics-groups` / `mitre-ics-software`) into one folder, as `misp_galaxy_<galaxy>_<YYYYMMDD>.json`: `{"captured_at", "request": {"galaxy": {...}, "misp_version"}, "payload": {"response": [...]}}`. The 2026.10.15 map was built from the open-data captures of 2026-10-13. A folder inside a `restricted` tree is refused.
3. Build, with the date of the build as the version:

   ```bash
   python scripts/build_attack_revoked_ids.py RAW_DIR --version 2026.10.15
   ```

   It prints the counts and every id it left out (`excluded`: a looping `revoked-by` chain, a successor missing from the inputs or of another kind, an id that a cluster that is not revoked also carries). An excluded id is not translated; look it up in the ATT&CK release notes before committing.
4. Review the diff of the file (new entries, changed successors), run `pytest tests/test_attack_revoked_map.py tests/test_attack_revoked_translation.py`, and commit the file with the script's output in the message.

**Taking effect.** Each process reads the map once: `build_relationships`, the sync and the collectors are separate runs and pick up the new file at their next run; restart the API service (`edgeguard_api`) for the STIX export. Links that were not built while an id was untranslated are built by the next `build_relationships` run.

**When the map is missing or unreadable.** Every reader logs once `[ATT&CK] revoked-id map <path> not used (<reason>): revoked ATT&CK ids are not translated in this run` and carries on with the ids as given; no run fails. The MITRE collector then keeps every revoked technique (`[ATTACK-REVOKED]`), as before 2026-10. The acceptance script fails its three revoked-object checks (`no_revoked_attack_techniques`, `no_revoked_attack_groups`, `no_revoked_attack_software`) with the same reason.

**Checking a graph.** `python scripts/verify_fresh_baseline.py` fails when a Technique node carries an id the map lists, a ThreatActor node from MITRE is a revoked group, or a Malware / Tool node from MITRE is revoked software, and warns (`revoked_group_names_folded`) when an actor from another source still bears a revoked group's name: the actor alias merge (enrichment, `[ACTOR-ALIAS-MERGE]` lines) folds such a node into the successor, whose aliases carry the name. On a graph built before 2026-10 both checks fail (2026-10-15: 158 Technique nodes, 6 ThreatActor nodes). MISP keeps the attributes of revoked objects pushed before 2026-10, and a full sync turns them into nodes again; the writer does not re-tag attributes that already exist, so older deprecated objects lack the `attack-status:deprecated` tag. The change takes full effect after a wipe and a new baseline.

## Malware ATT&CK-id twin merge (2026-10)

OTX names malware families as the MISP ATT&CK galaxy does (`"Cobalt Strike - S0154"`). Before 2026-10 every such name became a `Malware` node of its own beside the ATT&CK node, and the family's indicators split between the two (136 twins, 16,005 `INDICATES` links on the graph of 2026-10-14). The collectors and the sync now name the node by the base name; the enrichment job `merge_malware_attack_twins` folds the twins a graph already holds into the ATT&CK node (for software without a MITRE `Malware` node, into the node of the base name once one exists), so a graph built before needs no new baseline: the next `run_enrichment_jobs` repairs it (`docs/KNOWLEDGE_GRAPH.md`, "Malware named after an ATT&CK software id").

**What it logs.** `[MALWARE-TWIN-MERGE] batch i/n: merged … duplicate(s) into … target Malware node(s)` per batch and a final `[MALWARE-TWIN-MERGE] complete — candidates=… merged=… base_name_targets=… no_target=… skipped_ambiguous=… errors=… restamped_edges=…`. Most twins whose ATT&CK id no MITRE `Malware` node has are ATT&CK tools (Mimikatz `S0002`), which are `Tool` nodes and never merge targets. Once a later pulse has created the node of the base name (`mimikatz`, named so by the collector since 2026-10), such a twin folds into it, so indicators written before do not link two nodes; `base_name_targets` counts these, with a sample in the log. `no_target` counts the twins with neither target; they stay as they are, with a sample in the log. A `(ambiguous)` warning names a twin whose id and base name lead to more than one MITRE node (its id to one and its base name to another, or two MITRE nodes of one id): the job skips it on every run, so decide by hand which node it is. `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE=false` turns the job into a dry run that logs the pairs (`DRY RUN … Sample (target node, twin)`).

**Checking a graph.** `python scripts/verify_fresh_baseline.py` fails `malware_attack_twins_folded` while a twin the job folds, or an ambiguous one, is still a node, and lists the twins without a target; it applies the job's own rule, so its figures are exact. A quick, approximate count on the graph (read-only; names only, with single spaces around the hyphen, so twins that state their id only through an alias, or with other whitespace, are not counted):

```cypher
MATCH (m:Malware)
WHERE NOT 'mitre_attck' IN coalesce(m.source, []) AND m.name =~ '(?i).* - s[0-9]{4}'
RETURN count(m) AS twins, collect(m.name)[..20] AS sample
```

After the job, the twins that remain are the `no_target` ones and the ambiguous ones (a `(ambiguous)` warning each), and those of a batch that failed (`errors`, logged); the count above therefore need not match the `no_target` figure. The folded names are on the node they were folded into (`n.merged_from`, and in `n.aliases`), and `build_relationships` steps 9b / 2d resolve the names in `n.merged_from` to that node: a later pulse that names a folded family (a MISP cross-event duplicate, so no new node) still links its indicators.

## Indicator aging rollout (2026-10-16)

Every `Indicator` ages by one rule, whoever supplied it ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging-2026-10-16)): from the latest report of any source (the source's own `last_seen` capped at the MISP timestamp; `first_imported_at` when no report dated it), the confidence is ×0.85 / ×0.70 / ×0.55 of the source's from 90 / 180 / 365 days, and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days. No other label ages.

- **After deployment.** Each Indicator gets the new properties (`last_reported_at`, `source_confidence`, `aging_*`, …) at its next write. One full sync writes them on every Indicator ([Requesting a full MISP → Neo4j sync](#requesting-a-full-misp--neo4j-sync-neo4j_full_sync-2026-10)); its writes and the same run's `run_enrichment_jobs` evaluate the rule at the database's current time (or a node's later `aging_evaluated_at`, below); a node written before has no `aging_evaluated_at` until its next write, or until the first aging job writes it once on every Indicator with a time. This is safe on a graph built before: the report times come from MISP and only move forward, and until a node is written again the job ages it from `first_imported_at` and keeps its `confidence_score`. STIX consumers of a kept graph re-ingest the full bundle once after the rollout: an indicator's `modified` was its last database write (`last_updated`) and is now the latest of `created`, its latest MISP record and the time its aging state last changed, which can be earlier than the `modified` a consumer already holds, so a consumer that keeps the version with the highest `modified` would ignore the new versions, the retirements of old indicators among them. A wipe and a new baseline avoid this: every `created`, and so every `modified`, is then later than any earlier export. A deployment before the running baseline syncs to Neo4j needs nothing more: the baseline's own full sync writes them. Before either, check that the MISP the sync reads keeps the timestamps MISP gave the attributes when they were collected: a copy that re-stamps them makes every undated indicator look new, so wipe MISP and Neo4j together.
- **Measure before confirming the 730 days.** Per source: the Indicators per tier, those retired, the shares by basis (a source date, the MISP time, the import time) and those with no time at all (expected 0). A baseline loads some indicators already retired, Feodo Tracker's history entries whose `last_online` is more than 730 days old among them; how many is what this measures. Read-only:
  ```cypher
  MATCH (i:Indicator)
  RETURN coalesce(i.last_reported_source, '(no report)') AS source, i.aging_basis AS basis, i.aging_tier AS tier,
         sum(CASE WHEN i.retired_by = 'decay' THEN 1 ELSE 0 END) AS retired, count(*) AS indicators
  ORDER BY source, basis, tier
  ```
  ```cypher
  MATCH (i:Indicator) WHERE i.last_reported_at IS NULL AND i.first_imported_at IS NULL
  RETURN count(i) AS no_time
  ```
- **What the job logs.** `[AGING] at the database's current time: N Indicator(s) changed; tier 0 (from 0 d, x1.00): …, tier 3 (from 365 d, x0.55): …; retired (from 730 d): …`, then `[AGING] by basis: first_imported=…, misp_recorded=…, source_date=…`, and a warning when Indicators have neither `last_reported_at` nor `first_imported_at` (left untouched). The job writes only the nodes whose values change: a second run right after the first logs 0 changed, unless a node reached a tier day in between. The enrichment summary line's `decay=` is that number.
- **Clearing a failed enrichment task or sync (the aging time, 2026-10-16).** Nothing needs to be checked first. Every evaluation, a write or the aging job, applies the rule at the database's current time, lifted to the node's `aging_evaluated_at` (the time at which its aging values were last written) when that is later; no DAG run passes a time. A cleared `run_enrichment_jobs` or sync therefore evaluates at the time it runs, no earlier than the node's stored time, and moves nothing backwards: no retired indicator becomes active again, no tier falls, no `aging_since` or STIX `modified` moves back. The same holds for a baseline that overlaps a scheduled sync, in either order, and the aging job locks each node it changes before it reads it, so a write that commits before the job takes that lock is what the job evaluates. One case leaves a node behind the latest evaluation for a while, without moving it backwards: the database reads the time once per statement, when it starts, and an aging job that changes nothing on a node neither locks it nor stores a time, so a write whose statement started before such a job and which commits a newer report after it evaluates that report at its statement's start, earlier than the job's time. The next write or aging job evaluates the node at its own time; the gap lasts as long as that write's statement ran, lock waits included. To see the time of a node: `MATCH (n:Indicator {value: $v}) RETURN n.aging_evaluated_at, n.aging_tier, n.active`; a job run that changes nothing leaves `aging_evaluated_at` as it was. A stored time later than the database's current time holds the node at that time's state until the clock passes it: a database clock set back keeps the later states this way, and only a hand-made call of `decay_ioc_confidence` with a future `as_of` (a parameter for tests) can store a time in the future.
- **Changing the rule.** `EDGEGUARD_AGING_TIER_DAYS` (`90,180,365`), `EDGEGUARD_AGING_FACTORS` (`0.85,0.70,0.55`) and `EDGEGUARD_AGING_RETIRE_DAYS` (`730`), forwarded by `docker-compose.yml`. A value that fails validation (days not strictly ascending, a factor outside (0, 1], one factor per tier day, retirement not above the last tier day) stops the sync's indicator writes and the job with an error naming the variable. The next `run_enrichment_jobs` recomputes every Indicator under a new setting; no full sync is needed, the values are recomputed from `source_confidence` and the basis.
- **Re-reported indicators.** The collectors' refresh of a stored copy (`EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`, [COLLECTORS.md](COLLECTORS.md#re-reported-indicators-2026-10)) makes an indicator younger only when the source's `last_seen` moved, or, for a source without a date, to the time of the edit; one re-reported within the 30-day interval keeps its older date until the interval has passed (the first tier starts at 90 days).
- **Known limit.** The alert path (no subscriber is deployed) and the command-line writers (STIX import, VirusTotal re-enrichment) record no report: what they create ages from `first_imported_at`. The alert's time is to be designed with the ResilMesh alert integration.

## Repairing CVE descriptions and dates (2026-10)

Since 2026-10 a CVE's `published` and `last_modified` come from NVD's record: a record from any other source (CISA KEV, CISA ICS, an OTX pulse, a STIX import, a partner write) fills them only where the node has none. Since 2026-10-16 its `description` follows a fixed source ranking, NVD > CISA KEV > CISA ICS > any other source, and the node names the source of its text in `description_source` ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"): a record sets the description when its source ranks at least as high as the source of the stored text, so the result does not depend on the order in which the sync merges the records. A description without `description_source`, written before 2026-10-16, counts as NVD's: only NVD's record replaces it, and any other record fills only an empty description. For a CVE, the sync never takes as its description a comment that is a metadata block (`OTX_META:{...}`, `NVD_META:{...}` or any other `*_META:`; only the block's own `description` field) or a comment that only says where the CVE was seen (the OTX collector's "Referenced in OTX pulse: <name>", MISPWriter's placeholder "CVE from <source>") ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Evidence labels, report provenance, TLP"). A graph built before 2026-10 keeps what the record merged last wrote. On the CVEs several feeds name, which are the ones a demonstration shows, that is often the raw `OTX_META` JSON of an OTX pulse indicator, "Referenced in OTX pulse: <name>", CISA's short KEV text or a CISA ICS advisory's dates instead of NVD's.

A wipe and a new baseline need none of this. A graph that is kept is repaired once, after the deploy, in this order (each Cypher statement via `docker compose exec neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD`). The full sync of step 4 also completes [Repairing Malware, ThreatActor and Tool descriptions](#repairing-malware-threatactor-and-tool-descriptions-2026-10): when both are needed, run that section's steps 1–5 as well before it, and one full sync serves both.

1. **Count** the nodes whose description is a metadata block, an OTX pulse reference or the placeholder (read-only):

   ```cypher
   MATCH (c)
   WHERE (c:CVE OR c:Vulnerability)
     AND (c.description =~ '(?s)\\s*([A-Z][A-Z0-9_]*_META|Referenced in OTX pulse):.*'
       OR ((c.edgeguard_managed = true OR c.edgeguard_enriched = true)
           AND c.description =~ '\\s*CVE from [a-z0-9_-]+\\s*'))
   RETURN labels(c)[0] AS label, count(c) AS nodes;
   ```

2. **Remove those descriptions.** Such a description names no source, so it counts as NVD's: the full sync in step 4 replaces it on every CVE that NVD has a record of, but on any other CVE a stored block or pulse reference would stay and CISA's KEV text could not replace it (on the hosted MISP of 2026-10-14, CVE-2015-5477 had only an OTX and a KEV attribute). The statement also removes a `description_source`, so a node never names the source of a text it no longer holds:

   ```cypher
   MATCH (c)
   WHERE (c:CVE OR c:Vulnerability)
     AND (c.description =~ '(?s)\\s*([A-Z][A-Z0-9_]*_META|Referenced in OTX pulse):.*'
       OR ((c.edgeguard_managed = true OR c.edgeguard_enriched = true)
           AND c.description =~ '\\s*CVE from [a-z0-9_-]+\\s*'))
   REMOVE c.description, c.description_source;
   ```

3. **Remove the other descriptions that name no source** (2026-10-16), on the nodes EdgeGuard created. They count as NVD's too, so on a CVE without NVD's record the full sync would keep the text of the record merged first before 2026-10-16 (a CISA ICS advisory's text where the KEV ranks higher). The full sync writes them again from MISP, each with its source; a node a partner created keeps its text:

   ```cypher
   MATCH (c)
   WHERE (c:CVE OR c:Vulnerability)
     AND c.edgeguard_managed = true
     AND c.description IS NOT NULL
     AND c.description_source IS NULL
   REMOVE c.description;
   ```

4. **One full MISP → Neo4j sync.** An incremental run does not repair the graph: it writes only the attributes changed since the last sync.

   ```bash
   docker compose exec airflow airflow variables set NEO4J_FULL_SYNC true
   docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
   ```

   `run_neo4j_sync` runs a full sync and clears the Variable once it succeeded ("Requesting a full MISP → Neo4j sync"); `force_sync` bypasses `check_sync_needed` ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), `edgeguard_neo4j_sync`). Every CVE takes the text of the highest-ranked record MISP holds for it, with its `description_source` (NVD's record; without one the KEV's, then CISA ICS's, then another source's, such as an `OTX_META` block's own `description` field), and every NVD attribute sets its CVE's dates again; a CVE that only OTX names keeps no description. The run re-merges every attribute in MISP and takes about as long as the full sync of a baseline.

5. **Check.** Step 1 returns no rows, no CVE EdgeGuard created holds a description without its source, and a CVE that NVD, OTX and the KEV all name shows NVD's text and dates:

   ```cypher
   MATCH (c)
   WHERE (c:CVE OR c:Vulnerability)
     AND c.edgeguard_managed = true
     AND c.description IS NOT NULL
     AND c.description_source IS NULL
   RETURN labels(c)[0] AS label, count(c) AS without_source;
   // no rows

   MATCH (c:CVE {cve_id: 'CVE-2025-21042'})
   RETURN c.description, c.description_source, c.published, c.last_modified;
   // NVD's record (as stored in MISP on 2026-10-14): "Out-of-bounds write in libimagecodec.quram.so prior
   // to SMR Apr-2025 Release 1 allows remote attackers to execute arbitrary code.", description_source "nvd",
   // published 2025-09-12T08:15:44.743000+00:00 (a later NVD update moves last_modified)
   ```

A CVE without an NVD record shows the KEV's text when the KEV lists it, else CISA ICS's, else another source's, whatever the order of the events. The KEV and CISA ICS texts are those of the first record MISP stored: only NVD edits its stored copies (`MISPWriter.plan_vulnerability_update`), and MISPWriter skips a KEV or CISA ICS attribute its source already holds, so a revised KEV entry or ICS advisory reaches neither MISP nor the graph (the graph-side rule, under which a source's revised record replaces its own text, is in [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"). Its dates are the CISA ICS record's (the advisory's release dates), the only other record in MISP that gives dates: MISP holds one CISA ICS attribute per CVE, from the first advisory that named it (MISPWriter skips the CVE in later advisories), so the dates do not depend on the order either. They stay outside the ranking, since they are the advisory's dates rather than the CVE's, and NVD's record replaces them.

## Repairing Malware, ThreatActor and Tool descriptions (2026-10)

Since 2026-10 a `Malware`, `ThreatActor` or `Tool` description is ATT&CK's wherever MITRE ATT&CK describes the entity. Since 2026-10-16 the description of these nodes, and of `Technique` and `Tactic` nodes, follows a fixed source ranking, MITRE ATT&CK > a curated source (Core Ideas, then MISP Galaxy) > any other source, and the node names the source of its text in `description_source` ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"): a record sets the description when its source ranks at least as high as the source of the stored text. Until then the record MITRE delivered set it and a record from any other source only filled an empty one, so on a node MITRE does not describe the first source to arrive kept its text, and a `Technique` or `Tactic` took the text of the record merged last. A description without `description_source`, written before 2026-10-16, counts as MITRE's: only MITRE's record replaces it, and any other record fills only an empty description. The OTX collector gives its malware-family and adversary items no description (the pulse's text describes the report, not the family or actor), and the sync takes no description from an OTX malware or actor attribute, from a metadata block (`MITRE_USES_TECHNIQUES:{...}` or any other; also a block that does not parse or follows other text) or from MISPWriter's placeholder for an item without text ("Malware from <source>", "Threat actor from <source>", "MITRE ATT&CK tool: <name>", "MITRE ATT&CK technique from <source>", "MITRE ATT&CK tactic") ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Evidence labels, report provenance, TLP"). A graph built before 2026-10 keeps what the record merged last wrote: on an entity MITRE and OTX both name (Cobalt Strike, APT29, the actors and families a demonstration shows) often the description of an OTX pulse, on an OTX family from a pulse without a description the raw `MITRE_USES_TECHNIQUES:{"rt":[...],"pid":"..."}` block, and on every `Tactic` node the placeholder "MITRE ATT&CK tactic".

**What repairs it.** The MITRE collector's next run does not. An unchanged ATT&CK release is not even downloaded (the bundle's ETag answers 304), and a new one adds only attributes MISP does not hold yet: MISPWriter skips every attribute its source already has in MISP ([COLLECTORS.md](COLLECTORS.md), "Duplicate avoidance"), so the existing MITRE attributes do not change and the incremental sync, which writes changed attributes only, does not re-read them. One full MISP → Neo4j sync does: it re-reads every MITRE attribute, whose comment holds ATT&CK's text after the block, and sets that text with `description_source` `mitre_attck` on every node MITRE describes, whatever OTX wrote there. On a node MITRE does not describe, a stored text that names no source counts as MITRE's and stays, so the text OTX left there, a block or placeholder stored anywhere, and every other description without a source on a node EdgeGuard created are removed first. A wipe and a new baseline need none of this.

A graph that is kept is repaired once, after the deploy, in this order (each Cypher statement via `docker compose exec neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD`). The full sync of step 6 also completes [Repairing CVE descriptions and dates](#repairing-cve-descriptions-and-dates-2026-10): when both are needed, run that section's steps 1–3 as well before it, and one full sync serves both.

1. **Count** the descriptions that are a metadata block, hold one, or are a placeholder (read-only):

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor OR n:Tool OR n:Technique OR n:Tactic)
     AND (n.description =~ '(?s)\\s*([A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|CURATED_CLAIMS):.*'
       OR n.description =~ '(?s).*\\b([A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|CURATED_CLAIMS):\\s*[\\[{].*'
       OR ((n.edgeguard_managed = true OR n.edgeguard_enriched = true)
           AND n.description =~ '\\s*((Malware|Threat actor|MITRE ATT&CK technique) from [a-z0-9_-]+|MITRE ATT&CK tactic|MITRE ATT&CK tool: [^\\n]+)\\s*'))
   RETURN labels(n)[0] AS label, count(n) AS nodes;
   ```

2. **Remove those descriptions**, with any `description_source`. The full sync sets ATT&CK's text again on every node MITRE describes. A placeholder is removed only from a node EdgeGuard created or wrote to (`edgeguard_managed`, `edgeguard_enriched`; a graph built before 2026-10 stamped `edgeguard_managed` on every node EdgeGuard wrote), and only with a source id after "from" (lowercase, as MISPWriter writes the item's tag), so a partner's or a MISP-native text such as "Threat actor from Iran" stays:

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor OR n:Tool OR n:Technique OR n:Tactic)
     AND (n.description =~ '(?s)\\s*([A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|CURATED_CLAIMS):.*'
       OR n.description =~ '(?s).*\\b([A-Z][A-Z0-9_]*_META|MITRE_USES_TECHNIQUES|MITRE_TACTIC_PHASES|CURATED_CLAIMS):\\s*[\\[{].*'
       OR ((n.edgeguard_managed = true OR n.edgeguard_enriched = true)
           AND n.description =~ '\\s*((Malware|Threat actor|MITRE ATT&CK technique) from [a-z0-9_-]+|MITRE ATT&CK tactic|MITRE ATT&CK tool: [^\\n]+)\\s*'))
   REMOVE n.description, n.description_source;
   ```

3. **Count** the families and actors OTX names and MITRE does not that carry a description (read-only). On a graph built before 2026-10 that description is, almost always, the description of the first OTX pulse that named the entity:

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor)
     AND n.edgeguard_managed = true
     AND n.description IS NOT NULL
     AND 'alienvault_otx' IN n.source
     AND NOT 'mitre_attck' IN n.source
   RETURN labels(n)[0] AS label, count(n) AS nodes;
   ```

4. **Remove those descriptions.** Decision (2026-10): an entity only OTX describes shows no description, as it does on a new baseline, rather than a report's text that names no source, counts as MITRE's and could only be replaced by a record of MITRE's. The full sync fills the description again where an attribute of another source than OTX carries text (a MISP attribute of another feed), with that source. Only nodes EdgeGuard created (`edgeguard_managed`) are touched, so a partner's own text stays:

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor)
     AND n.edgeguard_managed = true
     AND n.description IS NOT NULL
     AND 'alienvault_otx' IN n.source
     AND NOT 'mitre_attck' IN n.source
   REMOVE n.description, n.description_source;
   ```

5. **Remove the other descriptions that name no source** (2026-10-16), on the nodes EdgeGuard created. They count as MITRE's, so the full sync would keep them on a node MITRE does not describe (a MISP-native text where a curated package ranks higher) and on a `Technique` or `Tactic` whose last record before 2026-10-16 was not MITRE's. The full sync writes them again from MISP, each with its source:

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor OR n:Tool OR n:Technique OR n:Tactic)
     AND n.edgeguard_managed = true
     AND n.description IS NOT NULL
     AND n.description_source IS NULL
   REMOVE n.description;
   ```

6. **One full MISP → Neo4j sync**, as in [Repairing CVE descriptions and dates](#repairing-cve-descriptions-and-dates-2026-10), step 4:

   ```bash
   docker compose exec airflow airflow variables set NEO4J_FULL_SYNC true
   docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
   ```

7. **Check.** Steps 1 and 3 return no rows (step 3 may list a node another source than OTX described), no node EdgeGuard created holds a description without its source, and an entity MITRE and OTX both name shows ATT&CK's text:

   ```cypher
   MATCH (n)
   WHERE (n:Malware OR n:ThreatActor OR n:Tool OR n:Technique OR n:Tactic)
     AND n.edgeguard_managed = true
     AND n.description IS NOT NULL
     AND n.description_source IS NULL
   RETURN labels(n)[0] AS label, count(n) AS without_source;
   // no rows

   MATCH (n:ThreatActor {name: 'apt29'}) RETURN n.description, n.description_source, n.source;
   // ATT&CK's text, beginning "[APT29](https://attack.mitre.org/groups/G0016)", description_source "mitre_attck"
   MATCH (n:Malware {name: 'cobalt strike'}) RETURN n.description, n.description_source, n.source;
   // ATT&CK's text, beginning "[Cobalt Strike](https://attack.mitre.org/software/S0154)", description_source "mitre_attck"
   ```

A `Tactic` node has no description after step 2 until MISP holds the tactic's ATT&CK text: the MITRE collector gives tactics their description since 2026-10, but MISPWriter writes it only into an attribute MISP does not hold yet, so on a MISP that is kept the tactics show none until the next baseline. A MISP attribute an OTX run wrote before 2026-10 keeps the pulse's text after its block; the sync ignores it.

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
(written by `parse_attribute` in `src/run_misp_to_neo4j.py` — search
for `misp_attribute_id` to find the emit sites).

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
MATCH (i:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'})
WHERE i.value = '203.0.113.5'
RETURN r.raw_data, r.misp_event_ids, r.source_refs LIMIT 1;
```

### Whose text a description is, and every source's text (2026-10-16)

A `CVE`, `Vulnerability`, `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node holds one description: the text of the highest-ranked source whose record gave one (CVE and Vulnerability: NVD > CISA KEV > CISA ICS > any other source; the other labels: MITRE ATT&CK > a curated source > any other source; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"). `n.description_source` names that source; it is null on a node without a description and on one written before 2026-10-16. Every source that named the node has its own `SOURCED_FROM` edge, with the MISP events that hold its attribute and its own record ids:

```cypher
MATCH (c:CVE {cve_id: 'CVE-2025-21042'})-[r:SOURCED_FROM]->(s:Source)
RETURN s.source_id AS source, s.source_id = c.description_source AS gave_the_description,
       r.misp_event_ids AS misp_events, r.source_refs AS record_ids
ORDER BY gave_the_description DESC, source;
```

Each source's text is the comment of its attribute in those events (`n.misp_attribute_ids[]` lists the attributes of every source, and each attribute's `source:` tag names its source). One source's attribute, by value and source tag:

```bash
curl -s -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
     -d '{"returnFormat": "json", "type": "vulnerability", "value": "CVE-2025-21042", "tags": ["source:CISA-KEV"]}' \
     "$MISP_URL/attributes/restSearch"
```

For a CVE the comment is the record's `NVD_META:{...}` block, whose `description` field is the source's text (NVD, CISA KEV, CISA ICS), or a plain text; for a `Malware` (`malware-type`), `ThreatActor` (`threat-actor`), `Tool`, `Technique` or `Tactic` (`text`) attribute it is the text MISPWriter wrote after the `MITRE_*` block's line. The node holds the text as MISP holds it (MISPWriter cuts an entity's description to the length [COLLECTORS.md](COLLECTORS.md) gives per kind); the source's own record is named in `r.source_refs[]` where the feed has record ids (`mitre_attck:G0016`). The `source:` tag of each source is its `misp_tag` in `src/source_registry.py` (`source:NVD`, `source:CISA-KEV`, `source:CISA-ICS`, `source:AlienVault-OTX`, `source:MITRE-ATT&CK`, …). A description whose source is not a MISP source (`resilmesh` for a ResilMesh-native write, `stix_import` or another name an external STIX bundle gave) is not in MISP.

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
- You don't have 32h for a fresh full baseline
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
- `scripts/backfill_edge_misp_event_ids.py` — edge `r.misp_event_ids[]` backfill (PR-N26; pairs with `migrations/2026_05_edge_misp_event_ids_backfill_runbook.md`)
- `scripts/audit_legacy_unicode_bypass_nodes.py` — read-only audit of legacy unicode-bypass nodes (PR-N32; surface for `BASELINE_LAUNCH_CHECKLIST.md` item `[6]`)
- `src/run_misp_to_neo4j.py:_MispFallbackHardError` — sentinel exception raised by the paginated MISP fetch fallback on any of 4 hard-failure modes (errors-payload, unexpected-shape, non-200, cap-hit; PR-N29 audit HIGH-1/2/3 + PR-N31 metric/alert wiring; see § 8 above)

---

_Last updated: 2026-10-16 — baseline lock: in `edgeguard_neo4j_sync`, `run_neo4j_sync` (and its retries), `build_relationships` and `run_enrichment_jobs` skip at their start while a baseline holds the lock, not only `check_sync_needed` (*Baseline launch path*); a refusal of `baseline_clean` before the wipe (`fresh_baseline` typo, invalid `wipe_scope`, backup gate) releases the lock, and `baseline_clean` (cleared) and `baseline_start` take it again before the run goes on (§ 7a); § 7c (the Airflow 2 postcheck skip) states that the run then ends `success`, not `failed`, and that the path does not run on the supported Airflow 3. Same day: *Post-run summary grep* (`COLLECTOR_SUMMARY`): the items no MISP attribute could be built from count among the push failures only when they are all or at least half of a source's items in the push (a payload that stopped converting, fixed in the collector or the source's payload); fewer are reported by the `[CONVERT]` WARNING and neither fail the run nor hold its cursor; how to tell the two `[CONVERT]` lines apart. Same day: *Post-run summary grep*: the `[CONVERT]` line of the MISP writer, per source, for the items no MISP attribute could be built from, which MISP never saw. Same day: after a baseline, the acceptance script's sector-evidence checks (a sector link names only the feeds that gave the sector and cites only the CISA ICS advisories that name it; `advisory_sector` only on AFFECTS where CISA stated it, and on every sector CISA stated, which `--require-cisa-ics` requires once the `cisa_ics` edges carry `zones` and not with `--legacy-graph`; confidence follows the label), its description-source and aging checks with `--legacy-graph` for an older graph, its reports, and how to measure CISA ICS and ATT&CK for ICS. Same day: *MISP → Neo4j sync schedule*, after a baseline: the first scheduled sync reads the attributes changed since the incremental window overlap before the baseline's full sync started (`EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h; it said one day). Same day: "AbuseIPDB daily blacklist quota": the daily and the baseline runs share one cache key (`{confidenceMinimum: 90, limit: 10000}` with the default settings), so on a day with both the run that collects second reuses the first one's answer within the maximum age, and a lower `EDGEGUARD_MAX_ENTRIES` or baseline `BASELINE_COLLECTION_LIMIT` gives a run its own request; a cleared task sends no request when such an answer exists. Same day: new section "AbuseIPDB daily blacklist quota (429, 2026-10)": a red `collect_abuseipdb` with "daily blacklist quota exhausted (429)" means the 5 blacklist requests of the UTC day are spent and the task's retries get the 429 again (no rate-limit backoff for that request); clear only that task after 00:00 UTC, and for a baseline the data reaches Neo4j at the next sync; the cache file `state/abuseipdb_blacklist_cache.json`, which runs reuse it (same parameters, same UTC day, at most `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` old), how to force a fresh request, and the one shared state directory it assumes. Same day: "AbuseIPDB daily blacklist quota": the 02:00 UTC daily run reuses an answer that a run with its parameters fetched after 00:00 UTC that day (a failed daily task cleared after midnight), and otherwise sends a request; an answer from an earlier UTC day is never reused. Same day: fallback triage: the `restSearch` probe asks for event headers only (`metadata`), and the safety cap on a MISP older than 2.4.177 counts events of any kind. Same day: indicator aging rollout, *Clearing a failed enrichment task or sync*: a cleared task evaluates no earlier than the node's stored time; a write that commits before the job locks a node is what the job evaluates; the one case that leaves a node behind the latest evaluation for a while (a write whose statement started before an aging job that changed nothing, committing a newer report after it) until the next write or job. Same day: indicator aging rollout: the aging runs at the database's current time, lifted to a node's `aging_evaluated_at` (the time at which its aging values were last written) when that is later, and no DAG run passes a time, so a cleared task, an older run or a baseline overlapping a scheduled sync evaluates at the time it runs and never moves a node's aging backwards; the first aging job after the deployment writes `aging_evaluated_at` once on every Indicator with a time that no write has stored it on; what the job logs. Same day: indicator aging rollout: STIX consumers of a kept graph re-ingest the full bundle once (an indicator's `modified` can move back); CVE descriptions: the KEV and CISA ICS texts are those of the first record MISP stored (only NVD edits its stored copies). Same day: new section "MISP → Neo4j sync schedule": every 72 hours, the 24-hour skip guard, the first sync after a baseline (within 96 hours of its full sync), `EdgeGuardNeo4jSyncStale` (122 h, also in the alert table) and the settings no longer read; `force_sync` bypasses the 24-hour guard. Same day: attribution: the MISP writer adds no several-actor mark to a stored copy; a pulse edited to name several actors whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit. Same day: new section "Indicator aging rollout": after deployment one full sync writes the new aging properties on every Indicator, then the per-source measurement (per tier, retired, by basis, no time) before the 730 days are confirmed; what the job logs; changing the rule (`EDGEGUARD_AGING_*`); the refresh of re-reported indicators and the known limit of the alert and command-line writers. Same day: "Repairing CVE descriptions and dates" and "Repairing Malware, ThreatActor and Tool descriptions": the description follows a fixed source ranking with `description_source` (CVE: NVD > CISA KEV > CISA ICS > any other source; entity, Technique and Tactic: MITRE ATT&CK > a curated source > any other source), a description without a source counts as the top source's, the cleanup statements also remove `description_source`, a new step removes the other descriptions without a source on nodes EdgeGuard created before the full sync, and the checks read `description_source`; a CVE without an NVD record shows the KEV's text over CISA ICS's whatever the order, and keeps CISA ICS's dates; new subsection "Whose text a description is, and every source's text" under "Retrieving raw MISP data from a Neo4j node". Same day: `EdgeGuardNeo4jFullSyncRequestPending` (a requested full sync that failed on its last attempt; it clears 3 days after the last failure) in "Requesting a full MISP → Neo4j sync" and the paging table; the CVE description repair names the shared full sync with the entity description repair, as that section does; step 2d and the acceptance check read the pulses marked on indicators, the MISP writer marks stored copies of held IOCs (`[MARK]`), a mark judged without the reference is not stored, and a repair for a wrong mark. Prior: 2026-10-15 — `EdgeGuardBuildRelationshipsSilentDeath` compares the last successful sync with the last build_relationships completion (new gauge `edgeguard_build_relationships_last_completion_timestamp`), so it no longer fires during a baseline's collection phase or while a build_relationships retry may still complete. Same day: `EdgeGuardBuildRelationshipsSilentDeath` described by the series it reads (the latest successful baseline task). Same day: "Repairing CVE descriptions and dates", steps 1–2: the placeholder "CVE from <source>" is matched only with a lowercase source id and removed only from a node EdgeGuard created or wrote to, as for the entity placeholders. Same day: "Repairing Malware, ThreatActor and Tool descriptions", steps 1–2: a placeholder is matched only with a lowercase source id after "from" and removed only from a node EdgeGuard created or wrote to (`edgeguard_managed`, `edgeguard_enriched`), so a partner's text such as "Threat actor from Iran" stays. Same day: new section "Repairing Malware, ThreatActor and Tool descriptions": MITRE's record sets the description and other sources only fill it; the MITRE collector's next run repairs nothing (ETag 304, existing attributes skipped), one full sync does after removing descriptions that are metadata blocks or placeholders and the OTX pulse text on nodes MITRE does not describe (decision: such nodes show none); Tactic nodes keep none on a kept MISP. Same day: new section "Requesting a full MISP → Neo4j sync": `NEO4J_FULL_SYNC` is cleared only after the full sync succeeded, the mode line in the task log, that no incremental sync runs while the request stands, the alert after the last failed attempt and the recovery step, the 8-hour task limit and the 68-hour DAG run limit. Same day: "Canonical threat-actor reference": what each component reading it does without it ([ATTRIBUTION] warnings). Same day: new section "Malware ATT&CK-id twin merge": what the job logs (including the twins that fold into the node of their base name and the ambiguous ones it skips), the dry run, the acceptance check, an approximate count query and what remains after the job. Same day: "Repairing CVE descriptions and dates": an OTX pulse reference and the placeholder "CVE from <source>" are no CVE description, and steps 1–2 also remove them; the metadata-block rule is stated for CVEs; a CVE without an NVD record keeps the first record's text and dates when that source revises its record. Same day: new section "Repairing CVE descriptions and dates": a CVE's description and dates come from NVD's record (other records only fill them); a kept graph is repaired by removing descriptions that are metadata blocks, then one full sync (`NEO4J_FULL_SYNC`, `force_sync`). Same day: new section "Canonical threat-actor reference": what the merge logs (including the pairs it skips as ambiguous, conflict, blocked or chain), rebuilding the reference (the ATT&CK aliases come from the record MITRE delivered), and the check at each ATT&CK release; "Rebuilding the ATT&CK revoked-id map" (when and how to rebuild `src/reference/attack_revoked_ids.json`, what happens without it, the acceptance checks for revoked objects) and the curated validation's report of revoked technique ids. Same day: failure mode 7 covers the 2026-10 baseline chain guards (collectors and `full_neo4j_sync` refuse after a failed `baseline_clean` / `baseline_start`, judged by the task states of the run), the clean step's 60-minute limit, batched relationship deletion and `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC`, and the postcheck that fails on Airflow 3 (the PR-N27 skip applies on Airflow 2 only); "Before a 730d baseline run" names the five scheduled DAGs and the CLI wrappers; the acceptance script's provenance checks after the run; curated packages are exposed by the APIs and the STIX export; OTX Cypher examples use the canonical source id `alienvault_otx`; `build_relationships` has 20 steps; the PR-N21 alerts are cited by PR number (the memory-posture heading keeps its title, which an alert annotation and a test cite); after #189: a refused chain task fails without its retry; after #193: the curated exposure paragraph names the TLP marking of exported curated links and that the curated label marks only the links a package created. Prior: 2026-10-14 — "Importing a curated package". Prior: 2026-06-12 — Issue #62 silent-loss gate: documented the COLLECTOR_SUMMARY grep + EDGEGUARD_MISP_MIN_SUCCESS_RATE fail policy in § Post-run summary grep (partial MISP push loss below 0.95 now fails the task RED). Prior: 2026-06-11 — PR #125 docs correction (supersedes the PR-N35 note in § Baseline launch path): edgeguard baseline/fresh-baseline DO exist (PR-C wrappers, no mutex); the lock sentinel is written only by the legacy in-process CLI path, not the DAG; pause procedure extended to all 5 scheduled DAGs incl. edgeguard_neo4j_sync. Prior: 2026-04-28 — PR-N35 Tier-1 + PR-N36 follow-up:_
- _**Container/service names** (BLOCK, PR-N35):_ replaced `edgeguard-airflow-worker` (doesn't exist) with `edgeguard_airflow` (single Airflow standalone container, per `docker-compose.yml:204`) across 15+ command examples; `edgeguard-neo4j` → `edgeguard_neo4j`; `edgeguard-misp` → `<your-misp-container>` (MISP is NOT in the compose stack); `docker compose exec airflow-worker` → `docker compose exec airflow`. Added an explicit container-name table to the deployment-assumption block at the top.
- _**Baseline launch path** (BLOCK, PR-N35):_ removed the entire Option A "CLI baseline" path (`python -m edgeguard baseline --days 730` / `fresh-baseline`) — those subcommands do NOT exist in `src/edgeguard.py` (verified via `grep "add_parser"`). Promoted the DAG+pause path to Option A. Added a callout explaining the historical CLI path was never shipped at HEAD.
- _**`--bootstrap-sources` invocation form** (BLOCK, PR-N35):_ flag DOES exist (PR-N18) but `python -m src.neo4j_client …` doesn't work (no `src/__init__.py`). Fixed to `python src/neo4j_client.py --bootstrap-sources`._
- _**Stale line-number references** (MED, PR-N36):_ replaced `src/collectors/misp_writer.py:143` and `src/run_misp_to_neo4j.py:2311` with grep-target descriptions (line numbers drift constantly; symbol/prefix references survive)._

_Prior: 2026-04-26 PR-N33 docs audit (added the two PR-N31 fallback alerts to the paging-severity table; bumped "8 alerts" → "≥ 11"; reconciled "26h baseline" → "32h"; added cross-refs to PR-N26 / PR-N32 scripts and `_MispFallbackHardError`)._
