# EdgeGuard On-Call Runbook

**Audience:** on-call operator responding to an alert or incident during
a baseline or incremental sync.

**Scope:** the failure modes of the 730-day baseline and the incremental
syncs, the kill-switches that let on-call revert a specific behaviour
without a code change, the baseline-day protocol, and the operating
procedures of the sync, the sources and the reference data.

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

Each kill-switch is read at call time (not at module import), so a new
value takes effect once the Airflow container is recreated with it; no
code change or image rebuild is needed.

| Env var | Default | When to set | What it reverts |
|---|---|---|---|
| `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` | unset (inspection active) | Result-counter inspection itself throwing (driver API drift, double-consume) — mid-baseline | `_record_batch_counters` short-circuits to a no-op: only the zero-write check stops; the batch's result is still read, so a server error in the batch is still retried and counted. Emits a `[KILL-SWITCH-ACTIVE]` WARN at module import when set so on-call can confirm the flag took effect via `docker logs edgeguard_airflow 2>&1 \| grep -m1 '\[KILL-SWITCH-ACTIVE\]'`. |
| `EDGEGUARD_EARLIEST_IOC_DATE` | `1995-01-01` | Importing pre-1995 corpora; seeing ingest silently drop historical IOCs with a `before earliest-allowed` WARN | Loosens the `_clamp_future_to_now` earliest-date floor. Accepts ISO date (e.g. `1970-01-01`). Invalid values fall back to default with a WARN. It also bounds the source date that dates an indicator for aging (`misp_report_times`). With a lower floor, older `last_seen` dates count, and those indicators may be retired (730 days). |

Set for one run (one-off):

```bash
# Docker Compose deployment: one sync run in the container with the variable set
# (a real sync, run in-process; Airflow records no task state)
docker compose exec -e EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1 airflow \
  airflow tasks test edgeguard_neo4j_sync run_neo4j_sync
```

Airflow 3 has no `airflow tasks run`. A kill switch for the scheduled runs
goes in `.env`, and the airflow container must be recreated (below).

Or persistent in `.env` at repo root (compose interpolates it into the
airflow service's environment; there is no `env_file`):

```
EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1
EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01
```

Recreate the affected service (`docker compose up -d airflow` — `restart` does not re-read `.env`) for
the change to take effect. Revert by unsetting the variable and recreating the service the same way.

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
| `EdgeGuardBuildRelationshipsSilentDeath` | critical | a sync completed 15 h 25 min to 36 h ago (every build_relationships attempt has ended) and no build_relationships completion stamped since, while no baseline run is in progress |
| `EdgeGuardApocBatchPartial` | warning | `increase(edgeguard_apoc_batch_partial_total[15m]) > 0` |
| `EdgeGuardMispFetchFallbackActive` | warning | `sum by (branch) (rate(edgeguard_misp_fetch_fallback_active_total{outcome="engaged"}[10m])) > 0` for 10m (sustained fallback engagement signals that the primary `/events/index` is broken) |
| `EdgeGuardMispFetchFallbackHardError` | **critical** | `sum by (branch) (rate(edgeguard_misp_fetch_fallback_active_total{outcome="hard_error"}[5m])) > 0` for 1m (the `_MispFallbackHardError` sentinel was raised; the sync task fails: the baseline's `full_neo4j_sync` at once (`retries=0`), the scheduled `run_neo4j_sync` after its retries) |
| `EdgeGuardNeo4jSyncStale` | warning | `time() - edgeguard_neo4j_sync_last_success_timestamp > 439200` (122 h) for 1h: no MISP→Neo4j sync, scheduled or baseline, completed within the longest gap the 72-hour schedule leaves plus the next sync's longest run; see "MISP → Neo4j sync schedule" |
| `EdgeGuardNeo4jFullSyncRequestPending` | warning | `edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}` rose in the last 3 days, or appeared for the first time: a requested full sync (`NEO4J_FULL_SYNC=true`) failed on its last attempt and the request stands, so no incremental sync runs; it clears 3 days after the last failure, also when the request was resolved earlier (silence it then); see "Requesting a full MISP → Neo4j sync" |
| `EdgeGuardSourceAccessDenied` | warning | `edgeguard_collector_skips_total{reason_class=~".+_auth_denied"}` rose in the last 25 h, or appeared for the first time. The provider refuses the source's requests (HTTP 401/403) and the task stays green while nothing is collected: run `python src/source_key_check.py`, renew the key, or check whether the provider blocks this host |

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
- **Log probe.** `docker logs edgeguard_airflow 2>&1 | grep -E 'failed after retries .* counting batch as failed' | tail -20`
- **Root cause.** MISPWriter's `@retry_with_backoff(max_retries=4)` gave
  up after five attempts (the first and four retries). Typical triggers: MISP PHP memory_limit below
  event-size threshold, MySQL `innodb_buffer_pool_size` too small for
  working set, MISP worker OOM.
- **Remediation.**
  1. Check MISP container memory: `docker stats <your-misp-container> --no-stream`
  2. Check MISP logs for OOM/segfault:
     `docker logs <your-misp-container> 2>&1 | grep -iE "out of memory|segfault|killed"`
  3. Tune per `docs/MISP_TUNING.md § TL;DR — Apply these on the MISP container`
  4. No scripted batch-replay exists. For a scheduled run, trigger the DAG
     that runs the source: OTX `edgeguard_pipeline`; CISA and VirusTotal
     `edgeguard_medium_freq`; NVD `edgeguard_low_freq`; MITRE, CISA ICS,
     AbuseIPDB, ThreatFox, URLhaus, Feodo, SSL Blacklist and MalwareBazaar
     `edgeguard_daily` (for example
     `docker compose exec airflow airflow dags trigger edgeguard_daily`).
     MISP de-duplicates what it already holds. A scheduled DAG collects only
     its incremental window, not a baseline's days. For a baseline, clear the
     collector task in the baseline run, without downstream tasks. If the run
     has ended `success` and released the lock, clear `baseline_start` first
     and the collector after it has succeeded (§ 7a). The data then reaches
     Neo4j at the next sync, or at once with
     `docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`.

### 2. MISP sustained backoff (flap vs overload)

- **Symptom.** Ingest stalling in 5-minute waves; incremental runs
  taking longer than usual (`EdgeGuardPipelineDurationHigh`).
- **Prom alert.** `EdgeGuardMispSustainedBackoff` — warning.
- **Log probe.** `docker logs edgeguard_airflow 2>&1 | grep -E '\[PUSH\] [0-9]+ consecutive 5xx failures' | tail -20`
- **Root cause.** MISP backend is sustained-degraded (not a transient
  flap — the adaptive backoff distinguishes them).
- **Remediation.** Same as (1) — this is usually the early-warning
  before (1) fires.

### 3. Honest-NULL violation (collector forging timestamps)

- **Symptom.** The indicator aging dates a report by the source's
  `last_seen` (capped at the MISP timestamp); a collector
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
- **Root cause.** The honest-NULL validator caught a collector calling
  `datetime.now()` as a fallback when the source feed was silent on a
  timestamp. The violation log line names the source + field.
- **Remediation.**
  1. Identify the (source, field) pair from the log lines or from
     `edgeguard_misp_honest_null_violation_total{source=...,field=...}`
  2. Inspect the named collector's extraction path for
     `datetime.now()` / `datetime.utcnow()` fallbacks.
  3. Remove the fallback — pass `None` through (honest-NULL).
  4. Ship the fix as a hotfix; do NOT disable the validator.

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
     (`--bootstrap-sources` runs
     `ensure_sources() + create_constraints() + create_indexes()` as a
     one-shot. The invocation is `python src/neo4j_client.py …`,
     not `python -m src.neo4j_client …`, because the module form needs an
     `src/__init__.py`, which does not exist in the repository.)
  2. Tail Neo4j log for constraint violations:
     `docker logs edgeguard_neo4j 2>&1 | grep -i constraint | tail -20`
  3. For schema drift: diff the failing Cypher against
     `src/neo4j_client.py` MERGE site; add the missing property coalesce.

### 5. Neo4j batch PERMANENT failure (retry exhaustion)

- **Symptom.** A MERGE batch gave up after exponential-backoff retries
  or hit a non-retryable exception. Up to 1000 rows of the batch are not
  written, and the sync task fails with the count in its reason
  (relationship rows: `[BATCH-PERMANENT-FAILURE]`; nodes: merge/load
  errors). The alert fires within 5 minutes.
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
- **What reaches this path.** Also an error the server reports while it executes or
  commits a batch (deadlock, lock or transaction timeout, constraint violation, a value it cannot
  convert), which arrives with the statement's result. The batch MERGEs, the single-item merges, each
  relationship group of the sync (`MISP relationship batch <group>`) and the other writes read
  their result where their retry and error handling see it: a deadlock is retried, a terminal error
  is counted or returned to the caller. The lines that name such a failure:
  - `[BATCH-PERMANENT-FAILURE]`: the batch (label, source, rows) or relationship group and the
    server's error.
  - `[MERGE-RETURNED-FALSE]`: the sync's line naming the entity (CVE id, MITRE id, Malware, actor or
    tool name) whose single-item merge failed with a terminal error. The client's line before it gives
    the server's error and names the node and source: `merge_node_with_source FAILED` when the node
    MERGE failed, `SOURCED_FROM relationship error (terminal)` when its source link failed (a source
    timestamp the server cannot convert, for one).
  - `merge_node_with_source failed after 4 attempts`: a retryable error (a deadlock, a lost
    connection) that persisted through the retries; the sync then logs an `Error syncing ...` WARNING
    and counts the entity as an error.
  - The CVE sub-writes (the CVSS sub-nodes, the NVD-owned data, the CVE score, which
    `merge_cve` runs after the node MERGE) follow the same rule. A terminal error logs `Failed to merge
    <label> for CVE <id> (terminal)`, `Failed to replace the NVD data of CVE <id> (terminal)` or `Failed
    to set the CVSS score of CVE <id> (terminal)` at ERROR with the server's error; the other sub-writes
    still run (the score is derived last from the sub-nodes there are), `merge_cve` returns False and
    the sync logs `[MERGE-RETURNED-FALSE]` for the CVE and counts it as an error. A retryable error is
    retried; one that persists logs `_merge_cvss_node failed after 4 attempts` (or
    `_replace_nvd_owned_cve_data`, `_set_cve_score_from_cvss`), and the sync logs `merge_cve error for
    <id>` (a CVE with CVSS) or `Error syncing plain CVE` and counts it as an error.
    A malformed CVSS payload in an attribute's `NVD_META` is not a write error: the sync checks each
    payload when it reads the attribute, reads one that is not a JSON object as absent and drops an
    entry that is not a property (a map or list value, a name with other characters than letters,
    digits and underscores, a number that is not finite: `Infinity`, `-Infinity`, `NaN` or `1e309`
    in the JSON), reads a payload left without a base score as absent, and logs
    `[META] NVD_META.<payload> of <CVE> ...` at WARNING; the CVE counts as synced. Correct the
    attribute's comment in MISP if the payload should be there.
- **Remediation.**
  1. If `retries_exhausted`: pause the DAG, let Neo4j recover, manually
     re-trigger the sync task once load drops. Consider raising the Neo4j
     heap (`NEO4J_HEAP_MAX` in `.env`, which compose passes as
     `NEO4J_server_memory_heap_max__size`; recreate the neo4j service) and
     `innodb_buffer_pool_size` on MISP's MySQL.
  2. If `non_retryable`: check Neo4j logs for the actual error:
     `docker logs edgeguard_neo4j --tail=200 | grep -iE "error|exception"`.
     This is a code bug: file an issue and ship a hotfix.

### 6. Placeholder-name MERGE spike (feed regression or attack)

- **Symptom.** Growing volume of `[MERGE-REJECT]` WARN log lines OR
  `[MERGE-PLACEHOLDER-REJECTED]` INFO log lines (the latter is the
  sync loop's equivalent: per-event placeholder rejections that
  are counted and do not fail the sync — the graph is SAFE);
  Malware / ThreatActor node count flatlined despite sync activity.
- **Prom alert.** `EdgeGuardMergeRejectPlaceholderSpike` — warning
  (fires when `increase(edgeguard_merge_reject_placeholder_total[15m]) > 10` per (label, source)).
- **Log probe.**
  ```bash
  docker logs edgeguard_airflow 2>&1 | grep "\[MERGE-REJECT\]" | \
    sed -nE 's/.*\[MERGE-REJECT\] (Malware|ThreatActor) .*Source=([A-Za-z0-9_-]+).*/\1 \2/p' | \
    sort | uniq -c | sort -rn | head
  ```
  (counts per label and source, as the alert does; the Indicator and
  `mitre_id` rejects carry no source and are not counted).
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
  3. If suspected injection: freeze the source and inspect that MISP
     event's attributes.
  4. The merge-time reject blocks the new writes — the graph is safe.
     Focus on WHY the collector started emitting.

### 7. Baseline chain stopped after a failed step; postcheck

**7a. Collectors, `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` refuse to run.**

- **Symptom.** The `tier1_core` / `tier2_feeds` collector tasks (a
  flag-guarded source that is switched off still skips) and
  `full_neo4j_sync` fail at start, without their retry, with `[BASELINE] <step>: baseline_start
  is <state> in this run — refusing to run after a failed baseline_clean /
  baseline_start` (or `... did not succeed (no XCom marker) ...`), or with
  `... no baseline holds the baseline lock ...` (the collectors and the three
  writers), or `... is held by <holder>, not by this run ...` (the three
  writers only: `full_neo4j_sync`, `build_relationships` and
  `run_enrichment_jobs`; the collectors stand down instead and succeed).
- **What it means.** `baseline_clean` or `baseline_start` did not succeed
  in this DAG run. The tier groups and `full_neo4j_sync` keep
  `trigger_rule=ALL_DONE`, so that one failed source does not stop the
  others; that rule also fires after an upstream failure, so without the
  guard every collector and the full sync would run on an un-wiped store.
  The guard reads the task states of this run from Airflow 3; only where
  Airflow reports none (Airflow 2, or a failed call) does it read the XCom
  marker that `baseline_start` returns on success. A marker left by an
  earlier success therefore does not count, and a `baseline_start` marked
  success by hand does.
- **Triage.** Read the `baseline_clean` log. The clean step's time limit is
  60 minutes (`execution_timeout`). It deletes Neo4j relationships
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
  nothing and releases the lock, so the corrected trigger is
  not refused by it: trigger the baseline again with the corrected conf, or,
  after an environment fix (`EDGEGUARD_LAST_BACKUP_AT` set and the container
  recreated), clear `baseline_clean`, which takes the lock again before the
  wipe. Clear it rather than marking it success: a `baseline_clean` marked
  success skips the wipe. `baseline_start` takes the lock again in either
  case. A `baseline_start` marked success by hand takes nothing: the
  collectors, `full_neo4j_sync`, `build_relationships` and
  `run_enrichment_jobs` then refuse with `no baseline holds the baseline
  lock`; clear `baseline_start`, which takes it, then those tasks. While
  another baseline holds the lock (another DAG run, or
  `run_pipeline --baseline`), the collectors of this run stand down
  (`[BASELINE] <SOURCE> NOT collected — the baseline lock is held by another
  run`; the task succeeds), but `full_neo4j_sync`, `build_relationships` and
  `run_enrichment_jobs` run whatever the collectors' outcome, so they refuse
  unless the lock names this run: `the baseline lock (...) is held by
  <holder>, not by this run (...)`, so that `full_neo4j_sync` does not write
  a full MISP → Neo4j sync during the other baseline's wipe or refill. Let
  that baseline finish (remove the sentinel only if it is
  stale); to go on with this run, clear `baseline_start`, then those tasks.

**7b. Postcheck on Airflow 3 (the shipped image).**

- **Symptom.** `baseline_postcheck` fails with `[BASELINE-POSTCHECK]
  upstream task(s) did not succeed: {...}` (or `... (no XCom marker)`),
  after a warning that the upstream-state introspection failed.
- **What it means.** Airflow 3's task instance has no `get_dagrun()`, so
  the skip path of 7c does not run. The postcheck reads the states of
  `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` in this
  run, or, where Airflow reports none, the XCom markers they return on
  success, and fails when one did not succeed. It fails rather than skips
  because Airflow derives the run state from the leaf tasks and a skipped
  leaf counts as success, so a skipped postcheck would let such a run end
  `success` with `run_enrichment_jobs` failed. Triage the task named in the message.

**7c. Baseline postcheck skipped due to upstream failure — Airflow 2 only, not supported.**

- **Applies to.** Only an Airflow 2 deployment, whose task instance has
  `get_dagrun()`. EdgeGuard runs on Airflow 3 (`requirements.txt` pins
  `apache-airflow~=3.3`; the image, `Dockerfile.airflow`, runs 3.3.2), where
  this path cannot run: the postcheck fails the run as described in 7b.
- **Symptom.** Airflow `baseline_postcheck` task log contains a
  `[BASELINE-POSTCHECK-SKIPPED]` ERROR line; postcheck task state =
  `skipped` instead of `success` / `failed`.
- **What it means.** An upstream task in the baseline chain
  (`full_neo4j_sync`, `build_relationships`, or `run_enrichment_jobs`)
  failed (or itself was upstream_failed / skipped). The sentinel
  in `assert_baseline_postconditions` detected this state and raised
  `AirflowSkipException` — INTENTIONALLY abstaining from running
  invariants because they would trivially violate (Campaign=0,
  Indicator=0, Source=0) for upstream reasons, NOT a real data-integrity
  breach. The skip propagates to `baseline_complete` and to
  `baseline_release_lock`, the run's only leaf task; Airflow derives the
  run state from the leaf tasks and counts a skipped leaf as success, so
  the run ends `success`, not `failed` (7b states the
  same rule). No alert reports it: `EdgeGuardDAGRunFailures` counts
  failures of the scheduled collector and sync tasks only, never a baseline
  run, on Airflow 3 as well. The baseline lock is pruned once its liveness
  check reads the run state `success`. On this path the run state does not
  show the failure; the postcheck log does.
- **What it does NOT mean.** It does NOT mean an invariant violation.
  Don't investigate INV-1/2/3 (Campaign=0 etc.) as the root cause.
- **Triage.**
  1. Read the upstream-state table in the same log line:
     `State table: {'full_neo4j_sync': 'failed', 'build_relationships':
     'upstream_failed', ...}` — the FAILED entry is the actual cause.
  2. Pull that task's log and triage from there.
  3. Placeholder rejections do not fail `full_neo4j_sync`: they surface as
     `[MERGE-PLACEHOLDER-REJECTED]` INFO lines (§ 6).

### 8. MISP fetch fallback (`_MispFallbackHardError`)

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
     proxy injecting an HTML error page). A `restSearch` page that is
     not JSON at all raises `restSearch answered non-JSON on page N`.
  3. **non-200 mid-pagination** — `response.status_code != 200` on
     a page after the first (typical: MISP-PHP-FPM exhaustion partway
     through a 50-page walk). A `restSearch` request that fails with
     an error other than a timeout or a dropped connection (for
     example a redirect loop) counts the same way and raises
     `MISP fallback restSearch failed on page N (M events collected):
     <error>`. A timeout or a dropped connection re-runs the
     listing four times first and then fails the task with the
     `requests` error, without `hard_error`.
  4. **safety-cap hit** — fallback paginated through
     `_FALLBACK_MAX_PAGES = 200` (~100K events) without hitting a
     short-read terminator. MISP legitimately has more events than
     the cap allows.
- **What it does NOT mean.** It does NOT mean the data was silently
  truncated — that's exactly the failure mode the sentinel exists
  to prevent. The Airflow task is FAILED (the baseline's `full_neo4j_sync`
  has `retries=0`; the scheduled `run_neo4j_sync` fails after its two
  retries), no partial baseline was committed.
- **Triage.**
  1. Identify which branch raised — the alert label `branch` is
     `pymisp` or `rest_search`. Pipeline log line will reference the
     same. PyMISP-only failures often indicate library/version
     incompatibility; `rest_search` failures are pure HTTP/payload.
  2. Pull the surrounding `[MISP-FETCH-FALLBACK]` log lines for
     the page number + good-pages count + raw error payload.
  3. **For mode (1) errors-payload:** check MISP user permissions,
     ACL config, `EDGEGUARD_MISP_EVENT_SEARCH` env var (default
     "EdgeGuard", also used when the value is empty; a value that matches
     no EdgeGuard event title makes the fallback list nothing).
  4. **For mode (2) unexpected payload:** check upstream proxy
     (Cloudflare / nginx) is not interposing an HTML error page on
     5xx. Test directly: `curl -s -H "Authorization: $MISP_API_KEY"
     "$MISP_URL/events/restSearch" -d '{"limit":1,"metadata":true}' -H "Content-Type:
     application/json" | head`.
  5. **For mode (3) non-200 mid-pagination:** investigate MISP
     backend health (PHP-FPM workers, MariaDB connection pool,
     OOM). MISP-PHP-FPM exhaustion caused it on the baseline of
     2026-04-19; scale workers. `EDGEGUARD_MISP_PAGE_SIZE` (default 500) sizes only
     the primary `/events/index` pages; the fallback pages are fixed at
     500 (`_FALLBACK_PAGE_SIZE`). When you lower it, raise
     `EDGEGUARD_MISP_MAX_PAGES` so that the product still exceeds the
     number of MISP events.
  6. **For mode (4) safety-cap hit:** if MISP legitimately has >100K
     EdgeGuard events (on a MISP older than 2.4.177, >100K events of any
     kind: it ignores the fallback's `eventinfo` filter, and the
     EdgeGuard rows are then picked client-side), raise `_FALLBACK_MAX_PAGES` in
     `src/run_misp_to_neo4j.py` and redeploy. Otherwise (probably a
     loop bug or a misconfigured `EDGEGUARD_MISP_EVENT_SEARCH`),
     fix the root cause.
- **Re-run.** In `edgeguard_neo4j_sync`, Airflow retries
  `run_neo4j_sync` itself (`retries=2`). After the last attempt, fix the
  cause and let the next scheduled run sync, or trigger
  `docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`.
  In the baseline, `full_neo4j_sync` has `retries=0` and must be
  manually re-run: clear it with its downstream tasks in the same DAG
  run, which still holds the baseline lock (after the 48 h age cap,
  first clear `baseline_start` without its downstream tasks, § 7a). Do
  not trigger a new baseline run: its `baseline_acquire_lock` refuses
  while the failed run's sentinel stands, and a new `fresh_baseline` run
  would wipe again.
- **The primary listing fails the same way.** These
  messages come from the `/events/index` (or `/events`) listing or
  from outside the fallback branches, so no fallback alert fires; the
  sync task fails, keeps the state file (`last_sync`), and Airflow
  retries `run_neo4j_sync` (`full_neo4j_sync` has no retry). Grep
  `MISP index /events` for the first two:
  - `MISP index /events/index answered HTTP 5xx | a non-JSON answer |
    a dict that is not an event listing on page N after N-1 good
    page(s) (M rows): the listing is incomplete` — a page after the
    first failed. Triage as for mode (3).
  - `MISP index /events/index page N: <requests error>` — a page
    after the first failed with a request error that is not a
    timeout or a dropped connection (for example a redirect loop). A
    timeout or a dropped connection on such a page re-runs the
    listing four times first, then fails the task with the
    `requests` error itself (for example `ReadTimeout: …`).
  - `MISP event listing failed: <error>` — an unexpected error
    outside the index pages and the fallback branches (for example in
    the code that reads the listing). A request error inside the
    `restSearch` fallback is mode (3) above.
  - `MISP event index stopped at the page cap
    (EDGEGUARD_MISP_MAX_PAGES=… x EDGEGUARD_MISP_PAGE_SIZE=…)` — the
    listing filled every page up to the cap, so events beyond it
    were not listed (the reason ends `events beyond the cap were not
    synced`, or `with no EdgeGuard event listed: the listing is
    incomplete` when none of the listed rows was an EdgeGuard event).
    Raise `EDGEGUARD_MISP_MAX_PAGES` on the Airflow worker and clear
    the task. A MISP that ignores the query-string `limit` / `page`
    (MISP 2.5.45 answers the whole listing on every page) does not
    reach the cap: the listing stops at the first page with more rows
    than `limit` or with no new event id.
- **Why the sentinel exists.** A fallback that returned the rows read so
  far would truncate the listing silently, and the
  `EdgeGuardSyncCoverageGap` alert would compare a truncated processed
  count with a truncated index total and see no gap. The fallback
  therefore paginates and raises the sentinel on a hard failure, and the
  Prometheus counter `edgeguard_misp_fetch_fallback_active_total` makes
  each engagement and hard error visible to the operator.

---

## Neo4j statement timeouts (`[NEO4J-TIMEOUT]`)

- **What applies.** Every pipeline statement carries a transaction timeout that the Neo4j server enforces. The limits are protection against a statement that hangs, set loose so that a slow statement on a large graph does not reach them:
  - `EDGEGUARD_NEO4J_READ_TIMEOUT` (default 3600 s) for the sync, relationship-build, enrichment and wipe statements;
  - 600 s for the relationship batch writes (a batch takes seconds; deadlocks are reported at once and retried);
  - 300 s for the REST API and STIX export queries.

  A driver opened directly by a CLI command or a script carries none.

  The actor alias merge and the Malware twin merge run each batch (the merge, the two uuid re-stamps and the list normalisation) in one transaction, so `EDGEGUARD_NEO4J_READ_TIMEOUT` limits the four statements together; at that limit the batch rolls back whole and the `[NEO4J-TIMEOUT]` line names it (`[ACTOR-ALIAS-MERGE] merge batch i/n …` or `[MALWARE-TWIN-MERGE] merge batch i/n …`).
- **Symptom.** A task fails with `[NEO4J-TIMEOUT] the server aborted a statement at its N s transaction timeout: <statement>`.
- **Log probe.**
  ```bash
  docker logs edgeguard_airflow 2>&1 | grep "\[NEO4J-TIMEOUT\]" | tail -20
  ```
- **Remediation.**
  - **The statement is expected to run longer on a large graph** (a baseline build step or an enrichment job): raise `EDGEGUARD_NEO4J_READ_TIMEOUT` in `.env`, recreate the Airflow containers and clear the failed task.
  - **The statement stalls without progress:** this points to lock contention or memory pressure; see § 5 above and the memory posture below.

## MISP → Neo4j sync schedule

- **When it runs.** `edgeguard_neo4j_sync` runs every 72 hours, a fixed interval (`schedule=timedelta(days=3)`). A run is due 72 h after the previous scheduled run; a manual run does not move the schedule. A run that fell due while the DAG was paused or Airflow was down starts once when it resumes, and the next one is due 72 h after it. The Airflow UI shows the next run under *Next Run*.
- **The 24-hour guard.** `check_sync_needed` skips a run when the last successful sync started less than 24 hours ago (the state file `state/edgeguard_last_neo4j_sync.json`): that happens only after a baseline's full sync or a `force_sync` run, which stamp the file. A skipped run is green, with `run_neo4j_sync` and everything after it skipped, and logs `Skipping Neo4j sync - the last sync started at …`. A regular run is never skipped: even a sync that started on its third attempt (16 h 42 min after its run was due) leaves 55 h until the next.
- **After a baseline.** When `edgeguard_neo4j_sync` is unpaused after the baseline (Baseline-day protocol, Option A) and a run is due, it starts at once and is skipped by the guard if the baseline's full sync started less than 24 hours before; the first scheduled sync then starts at most 96 hours after the baseline's full sync started. It reads the attributes changed since the incremental window overlap before that start (`EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h), which includes what the baseline collected in that overlap. To sync sooner, trigger a forced run: `docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`.
- **`EdgeGuardNeo4jSyncStale`** (warning) fires when no sync, scheduled or baseline, has completed in 122 hours: the longest gap between two sync starts (96 h after a baseline's or a forced sync) plus the longest run of the next sync (32 min of `check_sync_needed` / `neo4j_health_check` attempts, three 8-hour attempts of `run_neo4j_sync` and two 5-minute retry delays), with about an hour for the scheduler (`prometheus/alerts.yml`). `EdgeGuardCollectionStale{source="misp_to_neo4j"}` fires at 98 hours without a sync connecting. When either fires: check that the DAG is not paused (`airflow dags list | grep edgeguard_neo4j_sync`), that the scheduler runs, and the log of the last `run_neo4j_sync` attempt; a baseline holding its lock also skips the sync (`Neo4j sync ShortCircuit: EdgeGuard baseline is running`).
- **Fixed settings.** The interval and the guard are fixed in `dags/edgeguard_pipeline.py` (`NEO4J_SYNC_EVERY`, `NEO4J_SYNC_MIN_GAP`), because the alert thresholds are derived from them. The Airflow Variable `NEO4J_SYNC_INTERVAL` and `EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN` are not read.

## Requesting a full MISP → Neo4j sync (`NEO4J_FULL_SYNC`)

- **When.** An incremental sync writes only the attributes whose MISP `timestamp` moved, so a change that touches no attribute (event-level tags), a Neo4j restored from a dump older than MISP, or a curated layer removed by hand needs a full sync.
- **How.** Set the Airflow Variable and let the next scheduled run pick it up, or trigger one now:
  ```bash
  docker compose exec airflow airflow variables set NEO4J_FULL_SYNC true
  docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
  ```
  `force_sync` only bypasses the 24-hour skip guard; without the Variable the triggered run is incremental.
- **What the log shows.** `run_neo4j_sync` states the mode, the reason and the attempt at the start: `Sync mode: FULL — requested by the Airflow Variable NEO4J_FULL_SYNC=true … (attempt N)`.
- **Failure and retry.** The Variable is cleared only after the full sync succeeded (`NEO4J_FULL_SYNC cleared after the requested full sync succeeded`). A failed or timed-out attempt leaves it set, and the retries (`retries=2`) run in full again. If clearing the Variable fails after a successful sync, a warning names it and the next scheduled run is a full sync again; set it to `false` by hand to avoid that.
- **While the request stands, no incremental sync runs.** Every scheduled run is a full sync until one succeeds. A request that cannot succeed (a full sync longer than the task's limit, or one that reports a single merge or fetch error) therefore fails all three attempts of every run, about a day each time, skips `build_relationships` and `run_enrichment_jobs` (decay included), and keeps new MISP data out of Neo4j. After the last failed attempt the task's failure callback logs `[ALERT] NEO4J_FULL_SYNC is still true after the requested full sync failed on its last attempt …` at ERROR, sends it to Slack when enabled and counts `edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}`, which the Prometheus alert `EdgeGuardNeo4jFullSyncRequestPending` (warning) reads: it fires when the counter rose in the last 3 days, or appeared for the first time, so each failed run of a request that keeps failing is reported again. It follows the counter, not the Variable: it clears 3 days after the last failure, and keeps firing until then after the request was cleared or a later run succeeded, so silence it once the request is resolved (Recovery, below).
- **Recovery.** Find the cause in the `run_neo4j_sync` log of the failed attempts (timeout, `_last_sync_failure_reason`) and fix it, then let the next run repeat the full sync. To resume incremental syncs first, clear the request; the repair it asked for is then not done:
  ```bash
  docker compose exec airflow airflow variables set NEO4J_FULL_SYNC false
  ```
- **Duration.** A full sync of a 730-day MISP takes about 6 hours (the baseline DAG's `full_neo4j_sync` limit). The task's limit is 8 hours: the estimate plus a third, because a limit at the estimate could fail every attempt of a request, and a request stands until it succeeds. The DAG run's limit of 68 hours covers every task of the chain failing on all three attempts, plus 20%, as for the other DAGs.

## AbuseIPDB daily blacklist quota (429)

- **Symptom.** `collect_abuseipdb` is red in `edgeguard_daily` or `edgeguard_baseline`. The task log shows `AbuseIPDB: daily blacklist quota exhausted (429) — no cached blacklist available`, and the task's error reads `HTTPError: AbuseIPDB daily blacklist quota exhausted (429)`. The task failure signals (Slack, `edgeguard_pipeline_errors_total`, source health) fire as for any failed collector.
- **Cause.** The free plan allows 5 `GET /blacklist` requests per UTC day, counted per key: every blacklist request made with the same key that day counts, from this deployment or elsewhere. The source key check uses the `check` endpoint and spends none.
- **What the task does.** The blacklist request returns the 429 at once, without the rate-limit backoff; 502, 503 and 504 are still retried. The task's own retries (2 in the daily DAG, 1 in the baseline DAG, 5 minutes apart) send one request each and get the 429 again, because the quota is spent until 00:00 UTC; the task therefore ends red within minutes, so a spent quota is never reported as an empty list. Nothing is pushed to MISP. The rest of the run continues: the tier-2 group and `full_neo4j_sync` of the baseline and `log_summary` of the daily DAG use `ALL_DONE`, the baseline postcheck checks only the critical chain, and the baseline lock is released.
- **Remediation.** After 00:00 UTC, clear only the failed `collect_abuseipdb` task instance, without its downstream tasks (Airflow UI: the task in that DAG run → Clear, with downstream and upstream not selected); in the baseline run, clearing downstream tasks would repeat the full sync and the build steps. Once the baseline run has ended `success`, `baseline_release_lock` has removed the lock, and a cleared collector refuses with `no baseline holds the baseline lock` (§ 7a). In that case, first clear `baseline_start` without downstream tasks; it takes the lock again for this run. Once it has succeeded, clear `collect_abuseipdb`. A collector cleared at the same time as `baseline_start` refuses while `baseline_start` is not yet `success`. When the run is `success` again, the lock's liveness check prunes the sentinel. If it is still there, remove it (`docker compose exec airflow rm /opt/airflow/checkpoints/baseline_in_progress.lock`), because every scheduled DAG skips while it stands. While the baseline run still holds the lock (it is in progress, or it failed and kept the lock), clearing `collect_abuseipdb` alone is enough. The cleared task sends one new request, or none when a run with the same parameters fetched an answer earlier that UTC day (by default the daily and the baseline runs share one cache key; see "The cached answer"). In the daily DAG clearing is optional: the next scheduled run (02:00 UTC) sends its own request (or, when the task was cleared after 00:00 UTC and succeeded, reuses that answer; see "The cached answer"), and the blacklist is a current list rather than a history, so the failed run's addresses that are still listed come with it. For a baseline, the data reaches MISP when the cleared task succeeds and Neo4j at the next `edgeguard_neo4j_sync` run, because the baseline's full sync has already run; to move it into Neo4j at once, trigger a sync:
  ```bash
  docker compose exec airflow airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'
  ```
- **The cached answer.** A successful, non-empty answer is written to `state/abuseipdb_blacklist_cache.json` (`/opt/airflow/state` in the container; the directory named by `EDGEGUARD_STATE_DIR` when it is set) with its request parameters and fetch time. A run reuses it and sends no request when it asks for the same parameters (`confidenceMinimum`, `limit`), the file was written on the current UTC day and it is at most `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS` old (default 20; `0` turns the cache off). This covers the task's own retries after a MISP push failure, a cleared task, and a baseline or daily run with the same parameters on the same UTC day. The task log then shows `AbuseIPDB: reusing the blacklist fetched <time> (<age>h old, same UTC quota day, …)`. The daily and the baseline runs share one cache key: with the default settings both ask for `{confidenceMinimum: 90, limit: 10000}` (`limit` is `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN`, the same in both DAGs), so a baseline whose `collect_abuseipdb` runs later on the UTC day of a daily run, within the maximum age, reuses that run's answer and sends no request, and the daily run reuses a baseline's answer fetched after 00:00 UTC that day. Only a lower `limit` gives a run its own request: `EDGEGUARD_MAX_ENTRIES` below 10,000 (daily runs) or a baseline `BASELINE_COLLECTION_LIMIT` below 10,000. An answer from an earlier UTC day is never reused, so the 02:00 UTC daily run never works from the previous day's answer; it reuses one only when a run with the same parameters fetched it after 00:00 UTC that day (for example a failed daily task cleared after midnight, as under Remediation), and otherwise sends a request. A run with other parameters sends its own request and replaces the file (it holds the latest answer only). An empty answer is not kept.
- **Forcing a fresh request.** Delete the file, and the next run or cleared task sends a request (one of the day's 5):
  ```bash
  docker compose exec airflow rm -f /opt/airflow/state/abuseipdb_blacklist_cache.json
  ```
  To turn the cache off, set `EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS=0` in `.env` and recreate the Airflow containers.
- **One state directory.** The cache assumes that every task process reads the same state directory, as on the Compose deployment (one Airflow container with the LocalExecutor and the `./state` bind mount, § "Shared state directories"). Workers on separate hosts without a shared directory each miss the cache: no data is lost, but a retry spends another request.

## CISA KEV revisions

Every `collect_cisa` run (`edgeguard_medium_freq`, every 4 hours, and the baseline) compares the whole KEV catalogue with EdgeGuard's `source:CISA-KEV` copies in MISP: a CVE MISP lacks is added, a copy of an entry CISA revised (ransomware use, due date, required action, name, description) is edited in place, at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) per run ([COLLECTORS.md § 3](COLLECTORS.md#revisions-every-run-compares-the-catalogue-with-misp)). The incremental MISP → Neo4j sync then re-reads the edited attributes. To spread the edits over more runs, lower `EDGEGUARD_KEV_MAX_EDITS_PER_RUN`; `EDGEGUARD_KEV_UPDATE_EXISTING=false` stops editing (new entries are still added).

- **What the logs show.** One summary line per run:
  ```bash
  docker logs edgeguard_airflow 2>&1 | grep -E 'CISA KEV: catalogue|\[KEV-UPDATE\]|CISA KEV: .*(only in events|no longer in the catalogue|could not be listed|left for the next run)'
  # CISA KEV: catalogue 2026.10.16 (2026-10-16T17:15:48.8752Z) of 1748 entries, 1748 in scope; 9 added, 2 updated,
  #   1737 unchanged, 0 stored and not updated, 0 only in other events, 0 deferred, 0 failed; 0 stored and no longer in the catalogue
  # [KEV-UPDATE] CVE-2026-63077 attribute <uuid> event <id>: known_ransomware_use; tags +ransomware:known
  ```
  - `[KEV-UPDATE] … MISP did not confirm the edit (planned: …)` (WARNING), next to the writer's `[UPDATE-FAILED]` or `[UNCONFIRMED-EDIT]` line for the same attribute: the edit counts as failed, the run fails when its writes fall below `EDGEGUARD_MISP_MIN_SUCCESS_RATE`, and the next run plans the edit again.
  - `… left for the next run (edit cap 500 …)`: the cap or a stop rule (`EDGEGUARD_MISP_REFRESH_MAX_SECONDS` spent, 5 failed edits in a row) deferred edits; not a failure.
  - `… only in events EdgeGuard did not create (…)` (WARNING): those CVEs are neither added nor edited. When its count is close to the catalogue size, MISP's attribute listing does not return each row's `Event` (`info`), and no copy is edited; check the MISP version before anything else.
  - `… no longer in the catalogue (…)` (WARNING): CISA removed entries; their MISP copies and node fields are kept.
  - `MISP: the source:CISA-KEV attributes could not be listed (…)` (ERROR): nothing was written and the task fails; the next run compares again.
  - The task's return value holds `kev_update` (`added`, `updated`, `unchanged`, `deferred`, `failed`, `not_written`, `changed_keys`, `foreign_only`, `stored_not_in_catalogue`, `stop_reasons`); Airflow shows it as the task's XCom `return_value`.
- **Acceptance after a wipe and a new baseline.** The first `collect_cisa` run after the baseline logs `0 updated`, `unchanged` close to the catalogue size, `0 only in other events` and `0 failed`.
- **Live check after deploy (once).** That an edit moves the MISP event's timestamp, which the incremental sync selects events by, rests on MISP 2.5's code, not on a test against MISP. Check it on the first edit: the first natural revision (about 5 a month).
  1. Take a CVE from a `[KEV-UPDATE]` line and the time of that line.
  2. MISP holds the new copy, and its event's timestamp is not earlier than the edit:
     ```bash
     curl -s -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" -H "Content-Type: application/json" \
          -d '{"returnFormat": "json", "type": "vulnerability", "value": "CVE-2026-63077", "tags": ["source:CISA-KEV"], "includeAllTags": true}' \
          "$MISP_URL/attributes/restSearch" | jq '.response.Attribute[] | {uuid, event_id, timestamp, tags: [.Tag[].name]}'
     curl -s -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" "$MISP_URL/events/view/<event_id>" | jq '.Event | {id, info, timestamp}'
     ```
     Both timestamps are epoch seconds after the edit's time. An event timestamp before it means MISP did not move it: the sync would miss every KEV and NVD edit, so stop and report it.
  3. After the next incremental sync (`edgeguard_neo4j_sync`), the node and its KEV edge hold the new record:
     ```cypher
     MATCH (c:CVE {cve_id: 'CVE-2026-63077'})-[r:SOURCED_FROM]->(:Source {source_id: 'cisa_kev'})
     RETURN c.known_ransomware_use, c.cisa_action_due, c.last_updated, r.updated_at, r.raw_data;
     ```

## Bravo-ops: memory posture for the next baseline

The memory settings and alerts below guard a 32-hour baseline run (the
baseline DAG's `dagrun_timeout`) against an out-of-memory kill (exit 137)
of `build_relationships` and against a `build_relationships` subprocess
that dies silently.

### Memory ceilings (reconcile BEFORE kickoff)

For the 730-day baseline ([MEMORY_TUNING.md § 730-day baseline profile](MEMORY_TUNING.md#730-day-baseline-profile)):

| Knob | Value | Why |
|---|---|---|
| `AIRFLOW_MEMORY_LIMIT` | `12g` | Allow headroom above the ~8 GB working set that MISP-to-Neo4j sync consumes on 100K+ event baselines |
| `NEO4J_HEAP_MAX` | `12g` (= `NEO4J_HEAP_INITIAL`) | Heap for the 730-day graph and build_relationships; INITIAL = MAX avoids resize pauses |
| `NEO4J_TX_MEMORY_MAX` | `8g` | Cap of all running transactions together (`dbms.memory.transaction.total.max`, not a per-transaction limit). At 4g build_relationships hit `MemoryLimitExceededException` on the baseline of 2026-04-19; do not go below 8g for a baseline (docs/DOCKER_SETUP_GUIDE.md). The compose default is 4g, so set it in `.env`. |
| `NEO4J_PAGECACHE` | `8g` | Off-heap store cache |
| `NEO4J_CONTAINER_MEMORY_LIMIT` | `32g` | Above heap + pagecache + ~5g overhead |

Worker resident set: baseline should peak around 6 GB. **If
`docker stats edgeguard_airflow` shows RSS > 6 GB before the
baseline even kicks off, raise `AIRFLOW_MEMORY_LIMIT` first or the
baseline will OOM mid-run.**

### Two `build_relationships` Prometheus alerts

Both read counters that `build_relationships` emits:

| Alert | Fires when | Severity | What to do |
|---|---|---|---|
| `EdgeGuardBuildRelationshipsSilentDeath` | a MISP→Neo4j sync completed between 15 h 25 min and 36 h ago (`edgeguard_neo4j_sync_last_success_timestamp`) and `edgeguard_build_relationships_last_completion_timestamp` is older, while no `edgeguard_baseline` run is in progress (build_relationships runs after the sync; 5 h per attempt, two retries in the scheduled DAG) | critical | subprocess died silently (exit 137 OOM, SIGKILL, TX memory exhausted). Check docker stats + Neo4j logs for `MemoryLimit`. Raise memory ceilings, re-trigger. First check the sync DAG run's `build_relationships`: it skips while a baseline holds the baseline lock (log line `build_relationships skipped: EdgeGuard baseline is running`, state `skipped`), and a sync that started before the lock is then followed by no completion. The rule is silent while the baseline runs and fires after a baseline that ended before its own full sync and build_relationships (a failed run); nothing died, and the next build_relationships that completes builds the relationships. |
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
   - `MemoryLimitExceededException` → Neo4j TX memory cap hit. Raise `NEO4J_TX_MEMORY_MAX` (8g is the baseline value) and keep `NEO4J_CONTAINER_MEMORY_LIMIT` above heap + pagecache + overhead, or lower the batch size of that step.
   - `DeadlockDetected` → transient, re-run the step.
   - Schema / constraint error → code bug, file an issue, do NOT re-run blindly.
3. Option A — re-trigger the whole `edgeguard_baseline` DAG from `build_relationships` task in Airflow UI (Graph view → click `build_relationships` → "Clear" → confirm). It re-runs all 20 sub-steps, but the early-step MERGEs are idempotent so only the failed step's edges are re-created. There is no per-step CLI flag: `src/build_relationships.py` runs all 20 steps as a single Python program, so the full-task re-run is the supported path.
4. Option B — accept the partial step. In the baseline run, mark `build_relationships` as success (Airflow UI: the task → Mark state as → success). Then clear `run_enrichment_jobs` with its downstream tasks. The failed run still holds the baseline lock, so the enrichment, the postcheck and `baseline_release_lock` run. A cleared `run_enrichment_jobs` alone turns `upstream_failed` again while `build_relationships` is failed. If the failed run is left as it is, it keeps the baseline lock for up to 48 h (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`), and every scheduled DAG skips meanwhile, the MISP → Neo4j sync included. The edges of the failed step are created by the next `build_relationships` that completes. Flag for follow-up.

### Post-run summary grep

A successful baseline should always emit this line:

```bash
docker logs edgeguard_airflow 2>&1 | grep -E '\[BUILD_RELATIONSHIPS SUMMARY\]'
# expected: total_edges=N failures=0/20 per_query=[...]
```

Absence of this line = silent subprocess death (the exact scenario the
`EdgeGuardBuildRelationshipsSilentDeath` alert guards against).

Every collector run also emits one grep-able push summary:

```bash
docker logs edgeguard_airflow 2>&1 | grep "COLLECTOR_SUMMARY"
# expected per source: COLLECTOR_SUMMARY source=nvd items=N pushed=S failed=F \
#                      attempted=A success_rate=R min_success_rate=T
```

A `success_rate` below `EDGEGUARD_MISP_MIN_SUCCESS_RATE` (default **0.95**,
`0` disables) marks the collector run **failed** — the Airflow task goes
RED with the rate in the error, so a run in which, say, one attribute out of
92,000 reached MISP is never green. Rate is computed over
**attempted** pushes only — deduplicated re-runs are unaffected. Remediation
for a tripped gate = failure mode 1 above (MISP batch permanent failure);
the re-trigger is dedup-safe. The writer logs the items no
MISP attribute could be built from (an unknown item type, an empty value, CVE
id, name or ATT&CK id), which MISP never saw, in one `[CONVERT] N item(s)
could not be converted …` line per push: per source, how many of its items,
the reasons and whether they count as failed. They count as failed only when
they are all or at least half of a source's items in the push
(`CONVERT_FAILED_MIN_SHARE` in `src/collectors/misp_writer.py`), and the error
then names both causes. A red task whose `[CONVERT]` line is an ERROR, with
`item(s), counted as failed` for a source, means that source's payload
stopped converting: the fix is in the collector or the source's payload, not
in MISP, and a re-trigger fails the same way. OTX keeps its cursor below the
pulses of these items (`last_push_unstored_items`), so its runs read
them again once the collector is fixed. The exception is a line that
reads `1 of 1` or `1 of 2` for the source: one bad record in a small window,
which clears once a window holds three or more of the source's items. A
`[CONVERT]` WARNING (every source `item(s), not counted as failed`) is a few
bad records; the run goes on, the source's cursor is not held by these items,
and the line repeats while the source keeps sending them. The line names each
source by its tag (`alienvault_otx`, `threatfox`, …).

---

## Shared state directories

`./state` and `./checkpoints` are bind-mounted into the Airflow container (`/opt/airflow/state`, `/opt/airflow/checkpoints`), so `edgeguard doctor`, `monitor`, `stats` and `checkpoint status` on the host read the files the DAGs wrote (sync state, collector checkpoints, `baseline_in_progress.lock`). The `airflow-init` service creates the directories owned by uid 50000 before Airflow starts. Host-side deletes (`edgeguard checkpoint clear`, removing a stale sentinel) go through `docker compose exec airflow …` unless the host user owns the directories.

## Baseline-day protocol

### ⚠️ Baseline launch path and the baseline lock

The 730-day baseline runs for ~32h (matches the baseline DAG's
`dagrun_timeout`). Over that window the 5 scheduled DAGs check the
`checkpoints/baseline_in_progress.lock` sentinel at task start and skip
while the `edgeguard_baseline` DAG holds it (`baseline_acquire_lock`,
taken before the destructive `baseline_clean` step; released by
`baseline_release_lock` after a successful run); a collector task skipped
this way succeeds with `skipped: true` (a green task, reason
`baseline_in_progress`). In `edgeguard_neo4j_sync`
every task that writes checks it, not only the first task
`check_sync_needed`: `run_neo4j_sync` (and its retries), `build_relationships`
and `run_enrichment_jobs` skip at their start too. The
baseline's own collector tasks and its `build_relationships` are not skipped
by the lock of their own run; a log line
`[BASELINE] <SOURCE> NOT collected — the baseline lock is held by another
run` means a second baseline was started. A failed run keeps the
lock so that clearing the failed task resumes under the mutex, except
after a refusal of `baseline_clean` before the wipe (a misspelt
`fresh_baseline` key, an invalid `wipe_scope`, the backup gate), which
releases it so that the corrected trigger is not refused (§ 7a). The
sentinel is reaped once the holder's run state is `success`; an
abandoned run's sentinel is reaped at the age cap, or remove it by hand:
`docker compose exec airflow rm /opt/airflow/checkpoints/baseline_in_progress.lock`.
A collector, `full_neo4j_sync`, `build_relationships` or
`run_enrichment_jobs` of a run that no longer holds the lock (released,
reaped or removed) refuses while no baseline holds it, with `no baseline
holds the baseline lock`; clear `baseline_start` first, which takes it again.
While another baseline holds it, the collectors of that run
stand down and `full_neo4j_sync`, `build_relationships` and
`run_enrichment_jobs` refuse with `is held by <holder>, not by this run`
(§ 7a). The lock keeps the scheduled DAGs from writing to MISP during a
baseline, because concurrent writers exhaust MISP's PHP-FPM workers (the
baseline of 2026-04-19 lost 14.7% of its NVD attributes that way). The
holder's liveness is the DAG-run state read through the Airflow REST
API, with the sentinel age as fallback (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`,
default 48 h). `tests/test_tier1_sequential_robustness.py` pins the
DAG-side acquisition. A scheduled task that is already running when the
lock is taken completes its current write, so pausing the scheduled DAGs
before a destructive `fresh-baseline` remains recommended.

**Every launch path takes the lock:** the DAG, whether it is triggered from
the Airflow UI, the API or the CLI wrappers, and the in-process
`python src/run_pipeline.py --baseline`. Pausing the scheduled DAGs first
only guarantees that none of them is mid-write when the lock is taken.

> **Note:** the `baseline_in_progress.lock` sentinel is written by the
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
# additive (no wipe):
docker compose exec airflow airflow dags trigger edgeguard_baseline
# wipe + new baseline (needs EDGEGUARD_LAST_BACKUP_AT set in .env and the container
# recreated, unless Neo4j and MISP are empty; or use `edgeguard fresh-baseline`):
docker compose exec airflow airflow dags trigger edgeguard_baseline --conf '{"fresh_baseline": true}'

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

Alternatively, run the preflight helper. It checks that the MISP and
Neo4j endpoints respond and that the env-var prerequisites are met, and
it reports the pause state of the 5 DAGs. A DAG that is unpaused, or
whose state cannot be queried, is only a warning, so exit 0 does not
mean they are paused. With `--strict` (or `EDGEGUARD_PREFLIGHT_STRICT=1`),
every warning is a failure:

```bash
./scripts/preflight_baseline.sh --launch-path=dag --strict
```

Exit non-zero = do NOT launch. Exit zero + green summary = safe to trigger.

#### What about the CLI commands?

`edgeguard baseline --days N` (additive) and `edgeguard fresh-baseline`
(destructive — typed confirmation + backup-timestamp gate) trigger the
same `edgeguard_baseline` DAG; they add safety UX, not a mutex of their
own. The `baseline_in_progress.lock` sentinel is held by the DAG
(`baseline_acquire_lock`) and by the legacy in-process
`python src/run_pipeline.py --baseline` run.

---

### Before a 730d baseline run

1. **Launch path decided.** Per Option A above — trigger the
   `edgeguard_baseline` DAG (`airflow dags trigger edgeguard_baseline`, the
   Airflow UI, or the `edgeguard baseline` / `edgeguard fresh-baseline`
   wrappers, which trigger the same DAG), preferably after pausing the 5
   scheduled DAGs.
2. **Preflight green.** `./scripts/preflight_baseline.sh --launch-path=dag` returns exit 0
   (add `--strict` to make an unpaused DAG, like every other warning, a failure).
   Check `[12]` asks every provider whether it accepts the configured API
   key; a rejected key means that source is skipped for the whole baseline
   (a rejected NVD key stops it). The baseline DAG repeats the check in its
   `source_key_check` task, before the lock and the wipe.
3. **Smoke test.** Run a 7-day window first:
   `docker compose exec airflow airflow dags trigger edgeguard_baseline --conf '{"baseline_days": 7}'`
   (add `"fresh_baseline": true` for a wiped store). Success criteria: no ERROR lines, all
   6 pre-baseline alerts green, spot-check 10 random Indicators via
   Neo4j Browser or `graphql_api`.
4. **Prometheus rules loaded.** Verify that the `edgeguard_pipeline_observability`
   group lists its 9 rules: the MISP batch, backoff and honest-NULL alerts, the
   Neo4j ineffective-batch and permanent-failure alerts, the placeholder,
   event-truncation, build_relationships silent-death and APOC-partial alerts.
   Also verify that `edgeguard_sync_integrity` lists the two MISP fetch fallback
   alerts. Check `[7]` of `scripts/preflight_baseline.sh` requires at least 11
   alert rules in the whole `prometheus/alerts.yml`:
   ```bash
   promtool check rules prometheus/alerts.yml
   curl -s localhost:9090/api/v1/rules | \
     jq '.data.groups[] | select(.name=="edgeguard_pipeline_observability" or .name=="edgeguard_sync_integrity") | .rules[].name'
   ```
5. **Alert paging destinations confirmed.** Test that each alert
   actually reaches the on-call pager/inbox. Send a test alert straight to
   Alertmanager (started with `--profile alerts`):
   `curl -X POST localhost:9093/api/v2/alerts -H 'Content-Type: application/json' -d '[{"labels":{"alertname":"EdgeGuardPagingTest","severity":"critical"}}]'`
6. **Worker RAM sized.** NVD baseline holds ~1-2 GB of CVE dicts in
   memory (a known limit). Ensure the `airflow`
   container has ≥ 4 GB RAM: `docker inspect edgeguard_airflow | grep -i mem`.
7. **Kill-switches staged.** Decide in advance what signal would make
   you set each:
   - `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1` → if `_record_batch_counters` raises persistently in logs.
   - `EDGEGUARD_EARLIEST_IOC_DATE=1970-01-01` → if ingesting historical corpora and seeing `before earliest-allowed` WARNs.
8. **Collector pool present.** `docker compose exec airflow airflow pools list`
   lists `edgeguard_collectors` with the configured slots
   (`EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4).
   `docker compose logs airflow | grep 'collector pool'` shows
   `[edgeguard] collector pool edgeguard_collectors set to <n> slots`. Without
   the pool, no collector task is scheduled
   ([AIRFLOW_DAGS.md § Collector pool: setup and resizing](AIRFLOW_DAGS.md#collector-pool-setup-and-resizing)).

### During the run

- Monitor the `edgeguard_pipeline_observability` and `edgeguard_sync_integrity`
  rule groups continuously. The two MISP fetch fallback alerts (in
  `edgeguard_sync_integrity`: `EdgeGuardMispFetchFallbackActive`,
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
// 1. Orphan Indicators (silent-write signal) — expect 0.
MATCH (i:Indicator)
WHERE NOT EXISTS { (i)-[:SOURCED_FROM]->(:Source) }
RETURN count(i) AS orphans;

// 2. Clamp check: CVSS and confidence values out of range — expect 0.
MATCH (n)
WHERE n.cvss_score > 10 OR n.cvss_score < 0
RETURN count(n) AS cvss_out_of_range;
MATCH ()-[r]->()
WHERE r.confidence_score > 1 OR r.confidence_score < 0
RETURN count(r) AS confidence_out_of_range;

// 3. Aliases type integrity — expect 0.
MATCH (n) WHERE n.aliases IS NOT NULL
AND NOT (n.aliases IS :: LIST<ANY>)
RETURN count(n) AS aliases_scalar_corruption;

// 4. Node count by label — diff vs. expected baseline scale.
CALL db.labels() YIELD label
CALL { WITH label MATCH (n) WHERE label IN labels(n) RETURN count(n) AS c }
RETURN label, c ORDER BY c DESC;
```

Any non-zero on #1–#3 = regression; file issue.

Then run the acceptance script, `python scripts/verify_fresh_baseline.py`
([BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md) § "Fresh-baseline
acceptance"). It reads the Compose Neo4j at `http://127.0.0.1:7474` with
`NEO4J_USER` and `NEO4J_PASSWORD`; for another instance set `NEO4J_HTTP_URL`
(or `NEO4J_HTTP`) to its HTTP address
([CONFIGURATION.md](CONFIGURATION.md#neo4j-connection-and-memory)). Among its
checks, it fails when a relationship built from the sources names no source
(`relationships_name_their_source`) or when a provenance list is stored as a
plain string (`provenance_lists_are_lists`).

It also checks the sector evidence, the description sources and the indicator aging properties:

| Check | Fails when | Not judged |
|---|---|---|
| `sector_links_name_only_feeds_that_gave_the_sector` | a link to a `Sector` names a feed whose `SOURCED_FROM.zones` do not hold that sector | no `SOURCED_FROM` edge has `zones` (a graph written by an earlier version) |
| `advisory_sector_only_where_cisa_stated` | `advisory_sector` sits on anything but an `AFFECTS` link from a CVE to a sector the `cisa_ics` edge lists in `stated_zones` | no link carries the label |
| `cisa_stated_sectors_linked_as_advisory_sector` | a sector CISA stated is not linked as `advisory_sector`; with `--require-cisa-ics`, also when no sector is stated although the `cisa_ics` edges carry `zones` | no stated sector, when `--require-cisa-ics` is not given or no `cisa_ics` edge carries `zones` (a graph written by an earlier version, or kept and not re-read since) |
| `sector_links_cite_only_records_that_gave_the_sector` | a sector link cites a CISA ICS advisory whose sector note does not name its sector (the `cisa_ics` edge records the advisories per sector in `stated_refs`) | no `cisa_ics` edge has `stated_refs` (judged only for the feeds whose records state every zone they give: an OTX record also gives zones by keyword, for which it records no reference) |
| `otx_industries_only_where_otx_stated` | `otx_industries` sits on anything but a `TARGETS` link from an Indicator, ThreatActor or Malware to a sector the `alienvault_otx` edge lists in `stated_zones` (an `AFFECTS` link with it fails; `examples`), or such a link cites none of the pulses the edge records for its sector in `stated_refs` (`citing_examples`) | no link carries the label |
| `otx_stated_sectors_linked_as_otx_industries` | a sector an OTX record stated (the `alienvault_otx` edge's `stated_zones` on an Indicator, ThreatActor or Malware) has no `TARGETS` link, or one labelled `zone_classification` (a label outside the table is not judged); with `--require-otx-industries`, also when no sector is stated although the `alienvault_otx` edges give a sector (`otx_records_with_a_sector`) | no OTX record states a sector, when `--require-otx-industries` is not given or no `alienvault_otx` edge gives a sector (a graph synced by an earlier version) |
| `sector_confidence_follows_label` | a sector link's confidence is not the label table's value (`src/sector_evidence.py`; a label outside the table is not judged) | no sector link |
| `descriptions_name_their_source` | a node with a ranked description (CVE, Vulnerability, Malware, ThreatActor, Tool, Technique, Tactic) has no `description_source` | no description |
| `indicators_have_aging_basis` | an Indicator has no `aging_basis` or no `source_confidence` | no Indicator |

It also reports, without judging, the sector links by type and label (`sector_links_by_evidence_label`)
and by type, start label, sector and label (`sector_evidence_breakdown`), what CISA ICS adds per sector (`cisa_ics_contribution`: stated, by CISA
alone, also inferred, and the CISA records whose advisory named no tracked sector) and the node sectors no
feed gave and the nodes holding `global` next to a sector (`node_sectors_without_a_feed`). After the
730-day baseline with `EDGEGUARD_ENABLE_CISA_ICS=true`, run it with `--require-cisa-ics`, and after a
baseline that collected OTX with `--require-otx-industries` (a run that lost the pulses' industries on the
way to the sync otherwise looks like a graph without OTX statements, which the OTX checks do not judge).

**Measuring CISA ICS and ATT&CK for ICS.** Count CISA's sector statements by label (`advisory_sector` on
`AFFECTS`) or through the `cisa_ics` `SOURCED_FROM` edge's `stated_zones`; count ATT&CK for ICS through
the links into `Technique {attack_domain: 'ics'}` (actors and software carry no domain). The queries are in
[NEO4J_SAMPLE_QUERIES.md](NEO4J_SAMPLE_QUERIES.md), "Measuring CISA ICS and ATT&CK for ICS".

---

## Importing a curated package

A curated package (JSON, e.g. `YYYY-MM-DD_EdgeGuard_curated_package.json`) adds claims about existing actors and malware as one MISP event; the next MISP→Neo4j sync turns them into relationships (see `docs/KNOWLEDGE_GRAPH.md`, "Curated packages"). Import it after the baseline, since its claims attach only to nodes that exist.

```bash
python scripts/import_curated_package.py PACKAGE.json                 # validate: summary, warnings, errors
python scripts/import_curated_package.py PACKAGE.json --check-graph   # + per predicate, claims that would not attach
python scripts/import_curated_package.py PACKAGE.json --push          # create the MISP event (MISP_URL / MISP_API_KEY)
```

The validation refuses the package (errors block `--push`) when its `source` is not a registered curated source (`source_type="curated"` in `src/source_registry.py`) or when it has no `tlp`. It rejects a single claim — listed as a warning, counted under `claims_skipped_by_reason` in the summary, never written to MISP — when the claim's source is not a registered curated source, its object id is malformed (technique `T1234` / `T1234.123`, tool `S1234`, CVE `CVE-YYYY-NNNN`), its predicate does not fit its subject, or it has no object. The package's TLP level is tagged on the event and on every attribute; it marks each claim's link (`r.tlp`) and the STIX relationship exported from it.

`--check-graph` only reads Neo4j (`NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD`, optionally `NEO4J_DATABASE`). For each predicate it reports how many valid claims find both ends by the exact name or id the sync matches on, how many lack their subject or their object, and a sample of the missing names, so the package can be aligned with the graph before `--push`.

The event is unpublished and visible to the creating organisation only. A fresh baseline removes it with the other EdgeGuard events: import it again afterwards.

**After the sync.** A claim attaches only when both its subject and its object exist by exact canonical name or id. A link the claim creates gets the package's curated label (`curated_other` for a source without one) at 0.85; a link that already exists keeps its label and confidence and gains the claim's provenance. Each write logs `[CURATED] <attached> of <sent> curated claim(s) attached` (WARNING, with a sample of the missing names, when some did not attach), and the run summary adds `Curated package claims: <n> attached, <m> not attached`. Claims that did not attach are not errors and are not counted as relationships created.

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

Only curated claims set `r.tlp` on these five types, so step 2 removes it. Then run the enrichment jobs: `build_campaign_nodes` rebuilds the campaign links from the links that remain (provenance, confidence, evidence types and `tlp`; an indicator's link from its remaining paths to the actor) and each campaign's `tlp`, so a campaign built on a claim loses the package's events and level, and a campaign whose actor has no link left is deleted. A link the package created and another source asserted afterwards (an OTX pulse naming the same technique, say) still carries the curated label and is deleted in step 1; the relationship build and a full sync (`NEO4J_FULL_SYNC=true`) recreate it from that source's data. To remove one package of several, delete its event, remove the layer as above and run a full sync, which writes the remaining packages' claims again. To leave the layer out of a shared dataset without removing it, filter on `r.sources`, not on `r.match_type` (`docs/KNOWLEDGE_GRAPH.md`, "Curated packages").

A claim may name a technique id ATT&CK revoked (`T1086`): the validation accepts it, lists it under `revoked_technique_ids` with its successor and warns, the claim goes to MISP as written, and the sync links it to the successor (see "Rebuilding the ATT&CK revoked-id map" below).

In Neo4j the claims are relationships like any other: the API routes that traverse relationships (for example `GET /actors/{name}/summary` and `/graph/explore`) and the STIX bundles expose them (a STIX relationship names the curated source in `x_edgeguard_sources` and is marked with at least the package's TLP level; `x_edgeguard_match_type` shows the curated label only on a link the package created). No export filter by source exists, so import a package only on an instance whose API consumers may receive its claims.

## Canonical threat-actor reference

The actor alias merge (`merge_alias_duplicate_actors`) reads `src/reference/canonical_threat_actors.json`. The committed reference is version `2026.10.22`: 1,166 actors (191 ATT&CK groups; 37 created by override decisions), 4,484 synonyms and 80 ambiguous names. At each run it logs `[ACTOR-ALIAS-MERGE] canonical reference <version>: <n> actors`. The warning `canonical reference unavailable (<reason>); merging by MITRE aliases only` means the file is missing, unreadable, larger than 16 MB, of another `schema_version` or inconsistent, or that its data could not be applied to the graph's names. The merge then runs on ATT&CK aliases alone; restore the file (or `EDGEGUARD_CANONICAL_THREAT_ACTORS`) and the next run uses it again.

The job's other warnings name pairs it did not merge:

- `(ambiguous)`: the name is an ATT&CK alias of several groups;
- `(conflict)`: the ATT&CK aliases and the reference name different canonical actors, or the reference keeps the name as an actor of its own;
- `(blocked)`: the name is an ATT&CK alias of a group, but the reference marks it ambiguous or never_merge;
- `(chain)`: the node is also a canonical in the same run.

The final line, `[ACTOR-ALIAS-MERGE] complete — …`, counts each kind.

Each batch of pairs is one transaction: a line `batch i/n FAILED (k pairs rolled back)` means that none of its pairs merged, `errors` counts the batch, and the next run merges its pairs again. The Malware twin merge runs its batches the same way.

A conflict or a blocked pair after an ATT&CK release usually means the reference predates the release: rebuild it (below).

**Attribution from a source report.** The OTX collector, the MISP→Neo4j sync, `build_relationships` step 2d and the acceptance check `attribution_from_single_actor_reports` read the same reference to decide whether a pulse's actors are one actor. Without it the collector, the sync and step 2d each log `[ATTRIBUTION] canonical reference unavailable (<reason>)` once (the acceptance check reports it in its detail), and they behave as follows: the collector and the sync count every name as an actor, so the aliases of one actor count as several and the pulse attributes nothing (the collector writes such a pulse into `several_actor_pulses_by_name`, `OTX_META.sapn` / `MITRE_USES_TECHNIQUES.sapn`, which the sync uses for its own run and never stores on a node; the pulse's pairs come when it is collected again with the reference, as new IOCs carry them); step 2d links only the pairs whose pulse it can tell names one actor by name (the aliases of one actor count as several, and a name the alias merge folded away finds no node) and removes nothing; the acceptance check is informational. The sync logs `[ATTRIBUTION] report <pulse> names several actors: its malware is attributed to none of them` for each such pulse and counts them in its summary. Step 2d and the acceptance check also take the pulses the collector marked on indicators (`Indicator.several_actor_pulses`) as naming several actors, as the collector judged them with the reference, whether or not step 2d has it; step 2d logs `[ATTRIBUTION] N pulse(s) name several actors (M marked on K indicator(s) by the OTX collector)`, and a failed read of either source skips the step and fails the run. A pulse edited to name several actors after MISP stored its IOCs gets its mark only through its new IOCs: the MISP writer adds no mark to a stored copy (MISP keeps what the sources said), so a pulse whose IOCs MISP already holds and which brings no new IOC is not marked, a known limit to be closed by a per-pulse MISP record. A mark on a node is never cleared by a later run.

**Adversary names that are also the pulse's malware family.** The OTX collector also reads the reference to decide whether an adversary name the same pulse lists as a malware family is an actor: only when the reference resolves it (`Kimsuky`, `Akira`); otherwise (`Lumma Stealer`, `AsyncRAT`) the name is not taken as an actor and stays the pulse's malware item. A name the reference lists as ambiguous or never_merge does not resolve, so it counts as unknown here: `winnti` (ambiguous between `apt41` and `winnti group`), `golden chickens`, `lumma stealer`. The run logs `[ACTOR-NAMES] OTX: N distinct adversary name(s) in M pulse(s), which the same pulse lists as a malware family and the canonical threat-actor reference does not know, not taken as actors (they stay malware): <names>`, with every distinct name, alphabetically. When a listed name is a real actor, add it to the overrides file and rebuild (below): a `merge` decision into a key no actor has creates that actor, and a `merge` into an actor's key gives that actor a name the reference lists as ambiguous; a name marked never_merge (`lumma stealer`) needs its never_merge decision removed as well, since never_merge is applied after merge. Without the reference the collector keeps such names as actors; its one `[ATTRIBUTION] canonical reference unavailable` warning says so.

**Groups named after a country.** Country and state names and nationality adjectives are never actor names, with or without the reference (`actor_name_hygiene`, `docs/KNOWLEDGE_GRAPH.md` "Threat-actor names"), and no name is taken out of the hygiene's lists for an actor. A group whose common name is a country (the Cuba ransomware operation) is written under a qualified name that passes the hygiene (`Cuba Ransomware Gang`). That name counts as itself until the reference gives it to an actor, through a galaxy synonym or a `merge` decision in the overrides file (rebuild, below); the decision states the evidence that the galaxies name that actor as the group. `Cuba Ransomware Gang` has no decision and counts as itself: the ransomware galaxy's Cuba entry cites reports on UNC2596, a Storm-0671 synonym, and on Tropical Scorpius, which the reference lists as ambiguous between Storm-0671 and Void Rabisu, and the threat-actor galaxy records that Void Rabisu uses Cuba ransomware; no galaxy names one actor as its operator. A bare country name in an OTX adversary field is dropped, and the collector logs the distinct names it dropped this way once per run: `[ACTOR-NAMES] OTX: N distinct country, state or nationality name(s) in M pulse(s), dropped from the adversary field by the actor-name hygiene (never actor names; a group named after a country needs a qualified name): <name> (<k> pulse(s): <ids>); …`, alphabetically, with up to three pulse ids per name. A fragment that yields a name is not listed (`North Korea (APT37)` is `APT37`); a country followed by a parenthetical that yields no name is (`Cuba (Ransomware)` lists `cuba`). When a listed name is a group's own name, the listed OTX pulses name no actor for it: EdgeGuard does not rename an OTX adversary, and the hygiene drops the name before the reference is read. The group's qualified name reaches the graph only from a source in which a curator writes it (an entity of a curated package, [Importing a curated package](#importing-a-curated-package), or a hand-typed MISP threat-actor attribute), and a `merge` decision on that qualified name, when the galaxies name its actor, gives it to that actor for those sources only.

**Ransomware operations named after their ransomware.** An OTX report often names such an operation as the adversary and its ransomware as the family (`Rhysida`, `BlackSuit`, `Trigona`). The reference holds 33 of them in version `2026.10.22`: 29 as actors of their own (status `proposed`), each through a `merge` into its own key and a `canonical_name` for its display name, and 4 as names of their operator, each through a `merge` into the operator's key (`Qilin`, with its earlier name `Agenda`, status `accepted`; the others `proposed`). A name the `[ACTOR-NAMES]` malware-family line lists (adversary names the same pulse lists as a malware family) is added as an actor of its own when all three checks hold, and its decision states the evidence:

- the MISP ransomware galaxy lists the name: as written, without a trailing `ransomware`, with or without a trailing `group` or `team`, ignoring spaces, hyphens, dots and underscores, or as a malpedia synonym of an entry it lists (`global group`: malpedia `Global`, synonym `GLOBAL GROUP`);
- no MISP galaxy names an actor the reference holds as its developer or operator. A group the galaxies describe as deploying several ransomware brands, as an affiliate or a distributor, is not the operator (Storm-0501 and `Embargo`, Larva-26002 and `Trigona`, UNC2447 and `HelloKitty`), and neither is the actor whose ransomware code an operation took (the leaked LockBit 3.0 builder for `Brain Cipher`, a DragonForce build for `DEVMAN`, INC Ransom's source code for `Lynx`). Operation and actor names are searched in the galaxy texts in every spelling (`Hello Kitty`, `INC ransomware`), and the decision names each actor of the reference that the galaxies link to the operation in these ways;
- the galaxies give the name to no stealer, loader, RAT, botnet, banking trojan or backdoor, also with the type word added (`Anubis`, `Kraken`, `Osiris`, `Chaos`; `Nitrogen` and `Morpheus`: malpedia `Nitrogen Loader`, `Morpheus Loader`).

A name that fails only the second check is merged into the key of the actor the galaxies name as its developer or operator, so it counts as that actor and the actor alias merge folds its node into the operator's node when the graph holds one: `Conti` into Wizard Spider (the ransomware galaxy: developed by the TrickBot group; the threat-actor galaxy: Wizard Spider operates the TrickBot malware; ATT&CK: Wizard Spider uses Conti), `LockBit` into BITWISE SPIDER (the threat-actor galaxy: BITWISE SPIDER uses LockBit, estimated as likely, and its leak site posts the victims of LockBit 2.0), `Nefilim` into GOLD MANSARD (the threat-actor galaxy: Nefilim followed GOLD MANSARD's Nemty, without an affiliate model; it names TRAVELING SPIDER as the developer of Nemty, not of Nefilim), `Qilin` and `Agenda` into Water Galura (ATT&CK: Water Galura (G1050) are the operators of the Qilin Ransomware-as-a-Service; Agenda is an ATT&CK alias of Qilin (S1242) and its earlier name; Moonstone Sleet only uses Qilin). A name that fails the first or third check stays malware only.

**Rebuilding.** The inputs are:

- the threat-actor entities export of the MISP galaxies;
- the raw mitre-intrusion-set galaxy dump it was built from (ATT&CK revocations);
- an export of the graph's `ThreatActor` nodes, which is read-only and is kept outside the repository. Its ATT&CK-sourced nodes are the ATT&CK version EdgeGuard loaded. Their aliases are read from the record MITRE delivered (the node's `SOURCED_FROM` edge to the ATT&CK source), not from the node: the node's `aliases` also hold every name the merge folded in, which are no ATT&CK claims. An export that lacks these aliases is refused;
- `src/reference/canonical_threat_actor_overrides.json`.

The export reads the graph over the HTTP API like the acceptance script: the Compose Neo4j at `http://127.0.0.1:7474`, or the instance `NEO4J_HTTP_URL` (or `NEO4J_HTTP`) names, with `NEO4J_USER` and `NEO4J_PASSWORD`.

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
- the spelling variants, the spellings of one name that two actors held (made ambiguous), and the suffix-rule short forms, including those another actor held by a galaxy synonym. A record joined by a spacing variant stays listed when a never_merge with that actor keeps its names away (`'Cold River' -> star blizzard`): the decision takes the names, and the record stays among the actor's `records`;
- every override decision with its effect.

Add or change decisions only in the overrides file, with a reason, a date and `"status": "proposed"` until reviewed. A rebuild keeps them. `tests/test_canonical_threat_actors.py` fails when the overrides file changed after the last build.

**At each ATT&CK release.** A scheduled MITRE run adds the release's new techniques, groups and software, and a renamed object as a new MISP attribute under its new name; an object MISP already holds keeps its stored description, relationships and deprecation (MISPWriter skips it), which reach the graph with the next fresh baseline. After the release is loaded, export the graph again and rebuild. In the report's canonical-key check, every ATT&CK node must be either a canonical key or a revoked group that resolves to its successor. Then look at:

- groups the new release renamed, which take the loaded name;
- new groups, anchored by name;
- ATT&CK aliases that now resolve elsewhere.

When the release revokes groups, take a new MISP galaxy dump as well, so that the revocations are folded.

## Rebuilding the ATT&CK revoked-id map

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

**When the map is missing or unreadable.** Every reader logs once `[ATT&CK] revoked-id map <path> not used (<reason>): revoked ATT&CK ids are not translated in this run` and carries on with the ids as given; no run fails. The MITRE collector then keeps every revoked technique (`[ATTACK-REVOKED]`). The acceptance script fails its three revoked-object checks (`no_revoked_attack_techniques`, `no_revoked_attack_groups`, `no_revoked_attack_software`) with the same reason.

**Checking a graph.** `python scripts/verify_fresh_baseline.py` fails when a Technique node carries an id the map lists, a ThreatActor node from MITRE is a revoked group, or a Malware / Tool node from MITRE is revoked software, and warns (`revoked_group_names_folded`) when an actor from another source still bears a revoked group's name: the actor alias merge (enrichment, `[ACTOR-ALIAS-MERGE]` lines) folds such a node into the successor, whose aliases carry the name.

## Malware ATT&CK-id twin merge

OTX names malware families as the MISP ATT&CK galaxy does (`"Cobalt Strike - S0154"`). The collectors and the sync name the node by the base name, so that a family's indicators do not split between two nodes. The enrichment job `merge_malware_attack_twins` folds the twins a graph holds into the ATT&CK node (for software without a MITRE `Malware` node, into the node of the base name once one exists) at each `run_enrichment_jobs` (`docs/KNOWLEDGE_GRAPH.md`, "Malware named after an ATT&CK software id").

**What it logs.** `[MALWARE-TWIN-MERGE] batch i/n: merged … duplicate(s) into … target Malware node(s)` per batch and a final `[MALWARE-TWIN-MERGE] complete — candidates=… merged=… base_name_targets=… no_target=… skipped_ambiguous=… errors=… restamped_edges=…`. Most twins whose ATT&CK id no MITRE `Malware` node has are ATT&CK tools (Mimikatz `S0002`), which are `Tool` nodes and never merge targets. Once a later pulse has created the node of the base name (`mimikatz`, as the collector names it), such a twin folds into it, so indicators written before do not link two nodes; `base_name_targets` counts these, with a sample in the log. `no_target` counts the twins with neither target; they stay as they are, with a sample in the log. A `(ambiguous)` warning names a twin whose id and base name lead to more than one MITRE node (its id to one and its base name to another, or two MITRE nodes of one id): the job skips it on every run, so decide by hand which node it is. `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE=false` turns the job into a dry run that logs the pairs (`DRY RUN … Sample (target node, twin)`). A `batch i/n FAILED (k pairs rolled back)` line is a batch that changed nothing; its twins fold on the next run (one transaction per batch, as in the actor alias merge).

**Checking a graph.** `python scripts/verify_fresh_baseline.py` fails `malware_attack_twins_folded` while a twin the job folds, or an ambiguous one, is still a node, and lists the twins without a target; it applies the job's own rule, so its figures are exact. A quick, approximate count on the graph (read-only; names only, with single spaces around the hyphen, so twins that state their id only through an alias, or with other whitespace, are not counted):

```cypher
MATCH (m:Malware)
WHERE NOT 'mitre_attck' IN coalesce(m.source, []) AND m.name =~ '(?i).* - s[0-9]{4}'
RETURN count(m) AS twins, collect(m.name)[..20] AS sample
```

After the job, the twins that remain are the `no_target` ones and the ambiguous ones (a `(ambiguous)` warning each), and those of a batch that failed (`errors`, logged); the count above therefore need not match the `no_target` figure. The folded names are on the node they were folded into (`n.merged_from`, and in `n.aliases`), and `build_relationships` steps 9b / 2d resolve the names in `n.merged_from` to that node: a later pulse that names a folded family (a MISP cross-event duplicate, so no new node) still links its indicators.

## Indicator aging

Every `Indicator` ages by one rule, whoever supplied it ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging)): from the latest report of any source (the source's own `last_seen` capped at the MISP timestamp; `first_imported_at` when no report dated it), the confidence is ×0.85 / ×0.70 / ×0.55 of the source's from 90 / 180 / 365 days, and the indicator is retired (`active = false`, `retired_by = 'decay'`) from 730 days. No other label ages. The sync's indicator writes and the aging job of `run_enrichment_jobs` evaluate the rule.

- **MISP timestamps.** The MISP the sync reads must keep the timestamps MISP gave the attributes when they were collected: a copy that re-stamps them makes every undated indicator look new, so wipe MISP and Neo4j together.
- **STIX `modified`.** An indicator's STIX `modified` is the latest of `created`, its latest MISP record and the time its aging state last changed.
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
- **Clearing a failed enrichment task or sync (the aging time).** Nothing needs to be checked first. Every evaluation, a write or the aging job, applies the rule at the database's current time, lifted to the node's `aging_evaluated_at` (the time at which its aging values were last written) when that is later; no DAG run passes a time. A cleared `run_enrichment_jobs` or sync therefore evaluates at the time it runs, no earlier than the node's stored time, and moves nothing backwards: no retired indicator becomes active again, no tier falls, no `aging_since` or STIX `modified` moves back. The same holds for a baseline that overlaps a scheduled sync, in either order, and the aging job locks each node it changes before it reads it, so a write that commits before the job takes that lock is what the job evaluates. One case leaves a node behind the latest evaluation for a while, without moving it backwards: the database reads the time once per statement, when it starts, and an aging job that changes nothing on a node neither locks it nor stores a time, so a write whose statement started before such a job and which commits a newer report after it evaluates that report at its statement's start, earlier than the job's time. The next write or aging job evaluates the node at its own time; the gap lasts as long as that write's statement ran, lock waits included. To see the time of a node: `MATCH (n:Indicator {value: $v}) RETURN n.aging_evaluated_at, n.aging_tier, n.active`; a job run that changes nothing leaves `aging_evaluated_at` as it was. A stored time later than the database's current time holds the node at that time's state until the clock passes it: a database clock set back keeps the later states this way, and only a hand-made call of `decay_ioc_confidence` with a future `as_of` (a parameter for tests) can store a time in the future.
- **Changing the rule.** `EDGEGUARD_AGING_TIER_DAYS` (`90,180,365`), `EDGEGUARD_AGING_FACTORS` (`0.85,0.70,0.55`) and `EDGEGUARD_AGING_RETIRE_DAYS` (`730`), forwarded by `docker-compose.yml`. A value that fails validation (days not strictly ascending, a factor outside (0, 1], one factor per tier day, retirement not above the last tier day) stops the sync's indicator writes and the job with an error naming the variable. The next `run_enrichment_jobs` recomputes every Indicator under a new setting; no full sync is needed, the values are recomputed from `source_confidence` and the basis.
- **Re-reported indicators.** The collectors' refresh of a stored copy (`EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`, [COLLECTORS.md](COLLECTORS.md#re-reported-indicators)) makes an indicator younger only when the source's `last_seen` moved, or, for a source without a date, to the time of the edit; one re-reported within the 30-day interval keeps its older date until the interval has passed (the first tier starts at 90 days).
- **Known limit.** The alert path (no subscriber is deployed) and the command-line writers (STIX import, VirusTotal re-enrichment) record no report: what they create ages from `first_imported_at`. The alert's time is to be designed with the ResilMesh alert integration.

## Descriptions and dates of CVEs and entities

A `CVE`, `Vulnerability`, `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node holds one description, chosen by a fixed source ranking, and names the source of its text in `description_source` ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"). A record sets the description when its source ranks at least as high as the source of the stored text, so the result does not depend on the order in which the sync merges the records. A stored description without `description_source` counts as the top-ranked source's (NVD for a CVE or Vulnerability, MITRE ATT&CK for the other labels): only that source's record replaces it, and any other record fills only an empty description.

**CVE and Vulnerability.**

- **Ranking.** NVD > CISA KEV > CISA ICS > any other source. A CVE without an NVD record shows the KEV's text when the KEV lists it, else CISA ICS's, else another source's, whatever the order of the events.
- **Revised records.** The KEV text is the catalogue's latest: every KEV run edits the stored copy of an entry CISA revised ([CISA KEV revisions](#cisa-kev-revisions)), and the sync's rule, under which a source's revised record replaces its own text, carries it to the node. The CISA ICS text is that of the first record MISP stored: MISPWriter skips a CISA ICS attribute its source already holds, so a revised ICS advisory reaches neither MISP nor the graph.
- **What is no description.** For a CVE, the sync never takes as its description a comment that is a metadata block (`OTX_META:{...}`, `NVD_META:{...}` or any other `*_META:`; only the block's own `description` field) or a comment that only says where the CVE was seen (the pulse reference "Referenced in OTX pulse: <name>", the comment of a `cve_references` attribute written without an `OTX_META` block; MISPWriter's placeholder "CVE from <source>") ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Evidence labels, report provenance, TLP").
- **Dates.** A CVE's `published` and `last_modified` come from NVD's record: a record from any other source (CISA KEV, CISA ICS, an OTX pulse, a STIX import, a partner write) fills them only where the node has none. Without an NVD record the dates are the CISA ICS record's (the advisory's release dates), the only other record in MISP that gives dates: MISP holds one CISA ICS attribute per CVE, from the first advisory that named it (MISPWriter skips the CVE in later advisories), so the dates do not depend on the order either. They stay outside the ranking, since they are the advisory's dates rather than the CVE's, and NVD's record replaces them.
- **CVSS sub-nodes and list properties.** NVD's record also comes first for a CVE's CVSS sub-nodes and its lists (`cwe`, `ref_tags`, `cpe_type`, `result_impacts`, `reference_urls`, `affected_products`): a sub-node NVD has asserted keeps NVD's payload and a CISA ICS payload only fills a property it lacks, and NVD's record sets the lists while any other record only fills a list the node does not have ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), the `CVE` properties). The CISA ICS collector sends no impact and exploitability sub-scores, which a CSAF advisory does not give. When NVD's record drops a CVSS version CISA ICS also gives, NVD leaves `sources` and its event leaves `misp_event_ids` of that sub-node's edges, and CISA ICS's next record (at the latest the next full sync) sets its values and the CVE's score; until then the sub-node keeps NVD's values, and its impact and exploitability sub-scores, which CSAF does not give, keep NVD's on a graph that is kept.

**Malware, ThreatActor, Tool, Technique and Tactic.**

- **Ranking.** MITRE ATT&CK > a curated source (Core Ideas, then MISP Galaxy) > any other source, so a `Malware`, `ThreatActor` or `Tool` description is ATT&CK's wherever MITRE ATT&CK describes the entity.
- **What is no description.** The OTX collector gives its malware-family and adversary items no description (the pulse's text describes the report, not the family or actor), so an entity only OTX describes shows none. The sync takes no description from an OTX malware or actor attribute, from a metadata block (`MITRE_USES_TECHNIQUES:{...}` or any other; also a block that does not parse or follows other text) or from MISPWriter's placeholder for an item without text ("Malware from <source>", "Threat actor from <source>", "MITRE ATT&CK tool: <name>", "MITRE ATT&CK technique from <source>", "MITRE ATT&CK tactic") ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Evidence labels, report provenance, TLP").
- **Where the text comes from.** A MITRE attribute's comment holds ATT&CK's text after the block. The MITRE collector gives tactics their description. MISPWriter skips every attribute its source already has in MISP ([COLLECTORS.md](COLLECTORS.md), "Duplicate avoidance"), and an unchanged ATT&CK release is not downloaded (the bundle's ETag answers 304).

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

MATCH ()-[r:INDICATES]->(:Malware {name: 'cobalt strike'})
RETURN r.misp_event_ids LIMIT 10;
```

Fetch the event (contains all related attributes):

```bash
curl -H "Authorization: $MISP_API_KEY" \
     "$MISP_URL/events/12345"
```

### Path 3 — Parsed source record on the SOURCED_FROM edge (no network call)

Every per-source ingest stores the record EdgeGuard parsed from the MISP
attribute (its properties minus the node's key, as a JSON string) in
`r.raw_data` on the `SOURCED_FROM` edge
(`src/neo4j_client.py:_upsert_sourced_relationship`). Useful when you
need the source's record without a round-trip to MISP. On a `CVE` the
edge holds the source's latest record, replaced on every write from a MISP
attribute; on other labels, the record that created the edge. The
STIX import of the `run_pipeline.py` CLI (always on there; the Airflow DAGs
do not use it) writes a reduced record under the MISP event's source id only
when it creates the edge, never over the record the sync wrote.

```cypher
MATCH (i:Indicator)-[r:SOURCED_FROM]->(:Source {source_id: 'alienvault_otx'})
WHERE i.value = '203.0.113.5'
RETURN r.raw_data, r.misp_event_ids, r.source_refs LIMIT 1;
```

### Who asserts a link, what the source said, and an indicator's age

| Question | Field | Where to read it |
|---|---|---|
| Who asserts a relationship | `r.sources[]`, `r.source_refs[]`, `r.misp_event_ids[]` | Every relationship built from the sources |
| What the source cited | `r.cited_ids[]`, `n.merged_from[]`, `r.evidence_types[]` | Technique links, merged nodes, campaign links |
| Why an indicator has its age | `n.last_reported_at`, `n.last_reported_ref`, `n.aging_basis` | `Indicator` nodes |
| Ready-made MISP links | `mispAttributeUrls[]`, `mispEventUrls[]` | GraphQL `Indicator` |

- `r.sources[]` names the asserting sources (`mitre_attck`, `alienvault_otx`, `threatfox`, …), `r.source_refs[]` their own record ids (`alienvault_otx:<pulse id>`, `threatfox:<IOC id>`, `mitre_attck:G0016`) and `r.misp_event_ids[]` the MISP events ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Relationship provenance").
- `r.cited_ids[]` holds the ATT&CK ids a source cited before ATT&CK revoked them into the link's technique (`["T1562"]` on a link to `T1685`); `n.merged_from[]` the duplicate actor nodes folded into a canonical one (`["cl0p"]` on `clop`) or the ATT&CK-id twins folded into a malware node (`["cobalt strike - s0154"]` on `cobalt strike`); `r.evidence_types[]` the relationship types a campaign link rests on (`["ATTRIBUTED_TO", "USES_MALWARE"]`).
- An indicator ages from its latest report: `n.last_reported_at`, `n.last_reported_source` and `n.last_reported_ref`, the MISP attribute uuid of that report (`GET /attributes/<uuid>` shows the source's record and its `last_seen`). `n.last_reported_basis` (`source_date` or `misp_recorded`) gives the kind of date and derives `n.aging_basis`; `n.aging_tier`, `n.source_confidence` and `n.aging_evaluated_at`, the time the aging values were last written, complete the record ([KNOWLEDGE_GRAPH.md § Indicator aging](KNOWLEDGE_GRAPH.md#indicator-aging)). REST, GraphQL (`lastReportedRef` …) and STIX (`x_edgeguard_last_reported_ref` …) expose the same fields.
- `<MISP_URL>/attributes/view/<uuid>` names the one attribute behind the indicator, and `<MISP_URL>/events/view/<id>` opens the whole source event (100,000 or more attributes for OTX or NVD). A client sending a MISP API key gets the attribute as JSON; a browser needs a MISP login. The links are built from the API container's `MISP_URL`, so that address must be one the reader can reach; they are null when it is unset.

### Whose text a description is, and every source's text

A `CVE`, `Vulnerability`, `Malware`, `ThreatActor`, `Tool`, `Technique` or `Tactic` node holds one description: the text of the highest-ranked source whose record gave one (CVE and Vulnerability: NVD > CISA KEV > CISA ICS > any other source; the other labels: MITRE ATT&CK > a curated source > any other source; [KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Descriptions and their source"). `n.description_source` names that source; it is null on a node without a description and on a description written by an earlier version. Every source that named the node has its own `SOURCED_FROM` edge, with the MISP events that hold its attribute and its own record ids:

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

## See also

- `docs/MISP_TUNING.md` — backend tuning for failure modes 1-2
- `docs/KNOWLEDGE_GRAPH.md` — schema reference
- `docs/VERSIONING.md` — CalVer release cadence
- `prometheus/alerts.yml` — alert rule source of truth
- `src/neo4j_client.py:_record_batch_counters` — ineffective-batch detector
- `src/neo4j_client.py:_execute_batch_with_retry` — batch retry helper
- `src/neo4j_client.py:_is_retryable_neo4j_error` — exception classifier
- `src/collectors/nvd_collector.py:NvdBatchFetchError` — NVD silent-window-drop guard
- `src/node_identity.py:_REJECTED_PLACEHOLDER_NAMES` — placeholder blocklist
- `src/run_misp_to_neo4j.py:_MispFallbackHardError` — sentinel exception raised by the paginated MISP fetch fallback on any of 4 hard-failure modes (errors-payload, unexpected-shape, non-200, cap-hit; see § 8 above) and by the primary event listing (a failed later index page, any other listing error)

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The acceptance script and the graph export of the threat-actor rebuild read the Compose Neo4j at `http://127.0.0.1:7474` unless `NEO4J_HTTP_URL` (or `NEO4J_HTTP`) names another instance; they no longer fall back to a built-in remote address.
- 2026-10-23 — The baseline launch path section is titled for the lock that every launch path takes (it offered a choice of paths); it names the green `skipped: true` collector task, the refusals that release the lock and its reaping. Raw MISP data: a section on who asserts a link, what the source cited, an indicator's age and the GraphQL MISP links, which the README carried. The STIX import of `run_pipeline.py` is always on in that CLI; the memory pointer names MEMORY_TUNING.md; the MISP backoff symptom no longer cites a one-hour service-level objective, which is defined nowhere.
- 2026-10-22 — "Importing a curated package" is written for any registered curated source; the removal queries keep the registered sources and labels.
- 2026-10-22 — Canonical threat-actor reference: version `2026.10.22` and its counts (merges of spelling variants and designations, `Qilin` and `Agenda` into Water Galura, the never_merge of `Cold River` with Star Blizzard); a group named after a country is written under a qualified name, which counts as itself until the reference gives it to an actor, and a bare country name, also one followed by a parenthetical that yields no name, is dropped and listed by the new `[ACTOR-NAMES]` country line of the OTX collector, whose pulses name no actor for it; a never_merge with an actor leaves the record joined.
- 2026-10-21 — A campaign and its `RUNS` / `PART_OF_CAMPAIGN` links carry the most restrictive TLP of the links they rest on (`build_campaign_nodes`): a campaign built on a curated-package claim was exported at the deployment default (TLP:WHITE) while its links named the package's source, claim ids and MISP event. Removing the curated layer is followed by an enrichment run, which rebuilds the campaign links and levels.
- 2026-10-20 — Canonical threat-actor reference: the committed version and its counts, and the review of a ransomware operation named after its own ransomware before it is added as an actor (listed by the MISP ransomware galaxy, no actor the reference holds named as its developer or operator, not also a stealer, loader, RAT, botnet, banking trojan or backdoor), and the merge of an operation into the key of the actor the galaxies name as its operator (`Conti`, `LockBit`, `Nefilim`).
- 2026-10-19 — The pulse reference "Referenced in OTX pulse: <name>" that gives a CVE no description is named as the comment of a `cve_references` attribute written without an `OTX_META` block.
- 2026-10-18 — Acceptance: `otx_industries_only_where_otx_stated`, `otx_stated_sectors_linked_as_otx_industries` (`--require-otx-industries`) and the report `sector_links_by_evidence_label`; the per-sector reference check judges CISA ICS only.
- 2026-10-18 — Canonical threat-actor reference: the OTX collector also reads it to decide whether an adversary the pulse lists as a malware family is an actor (an ambiguous or never_merge name counts as unknown; `[ACTOR-NAMES]` log line with every distinct name; kept without the reference), and how to add an actor the reference lacks.
- 2026-10-18 — "At each ATT&CK release": a scheduled run adds the release's new and renamed objects; changes to objects already in MISP arrive with the next fresh baseline.
- 2026-10-18 — The acceptance script has no `--legacy-graph` option, so the description-source and aging checks are judged whenever the graph holds such nodes; the unicode-bypass audit script was removed. The kill switch `EDGEGUARD_RESPECT_CALIBRATOR`, the relationship-write guard it controlled and the post-run query for calibrated edges were removed with the co-occurrence calibration job, which was the only writer of `r.calibrated_at`.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Restructured as a guide to current behaviour: the change history moved to this section and the repairs of data written by earlier versions to the appendix.
- 2026-10-17 — Post-run summary grep: OTX keeps its cursor below the pulses of the items a systemic conversion drop leaves unstored, so they are read again once the collector is fixed.
- 2026-10-17 — Failure mode 5: the CVE sub-writes (CVSS sub-nodes, NVD-owned data, CVE score) retry a retryable error and make `merge_cve` return False on a terminal one, so the sync counts the CVE as an error where it had logged a WARNING and counted it as synced.
- 2026-10-17 — Kill-switches and failure modes corrected against the code: a new value needs a recreated container, a one-off run uses `airflow tasks test` (Airflow 3 has no `tasks run`), the calibrator switch affects only the sync's relationship writes, the log probes grep lines that are logged, MISP pushes make five attempts, and a failed baseline `full_neo4j_sync` is re-run by clearing it in its own run.
- 2026-10-17 — Memory posture gives the 730-day values (heap 12g, transaction cap 8g, page cache 8g, container 32g); it had advised a transaction cap of at most 4g, at which build_relationships ran out of transaction memory.
- 2026-10-17 — Baseline-day protocol: the destructive trigger conf, the preflight's pause-state warning and `--strict`, the `baseline_days` smoke-test key, the rule counts, the Alertmanager paging test and the collector-pool item; APOC partial Option B and the AbuseIPDB lock re-take after a successful run.
- 2026-10-16 — Every Neo4j write reads its result where its retry and error handling see a server error, where such an error had been logged only as a driver WARNING, the rows counted as written and a relationship group's error charged to the next group; `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` stops only the zero-write check.
- 2026-10-16 — The primary MISP event listing and the `restSearch` fallback fail the sync task on a failed later page, a listing cut at the page cap, a non-JSON page or any other listing error, where the sync had gone on with the rows read so far and stamped the state file.
- 2026-10-16 — Baseline lock: the sync DAG's writing tasks skip while a baseline holds it, a refusal of `baseline_clean` before the wipe releases it, and the collectors and the three writers refuse without it, the writers also while another baseline holds it (`full_neo4j_sync` had written a full sync during another baseline's wipe or refill).
- 2026-10-16 — Failure mode 7c corrected: a skipped Airflow 2 postcheck lets the run end `success`, not `failed`, and no alert reports it; `EdgeGuardBuildRelationshipsSilentDeath` is silent while a baseline runs.
- 2026-10-16 — The actor alias merge and the Malware twin merge run each batch in one transaction, where a failed batch had kept its merge and moved relationships could keep the folded node's uuid in `src_uuid` / `trg_uuid`.
- 2026-10-16 — Descriptions follow a fixed source ranking with `description_source`, and NVD's record comes first for a CVE's CVSS sub-nodes and lists, where the record merged last had set them; the repairs remove descriptions without a source before the full sync.
- 2026-10-16 — CISA KEV revisions: every `collect_cisa` run compares the whole catalogue with MISP and edits the copies of revised entries, which had reached neither MISP nor the graph; a CVE's `SOURCED_FROM.raw_data` holds the source's latest record, which the STIX import never replaces.
- 2026-10-16 — Indicator aging: one rule for every Indicator, evaluated at the database's current time and never moved backwards, with the rollout, the measurement, the job's log lines and the settings.
- 2026-10-16 — An indicator's STIX `modified` is the latest of `created`, its latest MISP record and the time its aging state last changed, where it had been the time of its last database write (`last_updated`).
- 2026-10-16 — The acceptance script checks the sector evidence, the description sources and the aging properties, with `--legacy-graph` and `--require-cisa-ics`.
- 2026-10-16 — The MISP writer reports the items it cannot convert in a `[CONVERT]` line and counts them as failed only when they are at least half of a source's items.
- 2026-10-16 — AbuseIPDB: a quota 429 fails the task at once, where it had produced an empty list and a green task after up to 3 × 10 minutes of backoff, and a cached blacklist shared by the daily and baseline runs is reused within its UTC day.
- 2026-10-16 — MISP → Neo4j sync schedule: every 72 hours (the cron `0 3 */3 * *` had run 24 h apart at month ends), a 24-hour skip guard in place of the 71-hour guard of `NEO4J_SYNC_INTERVAL` and `EDGEGUARD_SYNC_INTERVAL_TOLERANCE_MIN`, `EdgeGuardNeo4jSyncStale` at 122 h (was 145 h) and an incremental window overlap of 1 h (was one day).
- 2026-10-16 — `EdgeGuardNeo4jFullSyncRequestPending` reports a requested full sync that failed on its last attempt.
- 2026-10-16 — Attribution: the MISP writer adds no several-actor mark to a stored copy (the `[MARK]` comment edits were removed), and step 2d and the acceptance check read the marks on indicators.
- 2026-10-16 — Fallback triage: the `restSearch` probe asks for event headers only, and the safety cap on a MISP older than 2.4.177 counts events of any kind.
- 2026-10-15 — `EdgeGuardBuildRelationshipsSilentDeath` compares the last successful sync with the last build_relationships completion, so it does not fire during a baseline's collection phase or while a retry may still complete.
- 2026-10-15 — New sections on requesting a full sync (`NEO4J_FULL_SYNC` is cleared only after success, where a failed attempt had retried as an incremental run; task limit 8 h, was 4 h) and on Neo4j statement timeouts.
- 2026-10-15 — New sections on the canonical threat-actor reference (an export of the graph's actors without the aliases MITRE delivered is refused), the ATT&CK revoked-id map and the Malware ATT&CK-id twin merge, where OTX's `"Name - S0154"` malware names had become nodes of their own.
- 2026-10-15 — New repair sections for CVE descriptions and dates and for Malware, ThreatActor and Tool descriptions, which the record merged last had written.
- 2026-10-15 — Failure mode 7: the collectors and `full_neo4j_sync` refuse after a failed `baseline_clean` / `baseline_start`, where they had run on an un-wiped store; the clean step's 60-minute limit and batched relationship deletion; the postcheck fails on Airflow 3.
- 2026-10-15 — Curated packages are exposed by the API and the STIX export with the package's TLP marking; OTX examples use the source id `alienvault_otx`; `build_relationships` has 20 steps.
- 2026-10-14 — New section on importing a curated package.
- 2026-10-12 — The baseline DAG holds the baseline lock for the whole run (`baseline_acquire_lock`), so the scheduled DAGs skip during any baseline (root cause in `docs/flow_audits/01_baseline_sequence.md`, Finding 1); state and checkpoints are bind-mounted to the host.
- 2026-06-12 — A collector run whose MISP push success rate falls below `EDGEGUARD_MISP_MIN_SUCCESS_RATE` fails; one successful attribute out of 92,000 had made a run green, which is how the 2026-04-19 baseline lost 14.7% of its NVD attributes.
- 2026-06-11 — The `edgeguard baseline` / `fresh-baseline` wrappers trigger the baseline DAG without a mutex of their own, and the pause procedure covers all five scheduled DAGs including `edgeguard_neo4j_sync`.
- 2026-04-28 — Container names follow `docker-compose.yml` and MISP is outside the stack; the CLI baseline path `python -m edgeguard baseline --days 730` was removed because the subcommand did not exist then; `--bootstrap-sources` runs as `python src/neo4j_client.py`; line-number references became grep targets.
- 2026-04-26 — The paging table lists the two MISP fetch fallback alerts, the rule count reads at least 11 and the baseline window 32 h.
- 2026-04-25 — Failure mode 8 documents the `_MispFallbackHardError` triage and the fallback counter and alerts.
- 2026-04-24 — The MISP fetch fallback paginates and raises `_MispFallbackHardError` where it had truncated silently at `limit=1000`; failure mode 7 documents the `[BASELINE-POSTCHECK-SKIPPED]` postcheck skip; placeholder rejections in the sync loop are counted and do not fail the sync.
- 2026-04-22 — The build_relationships counters, the two alerts and the memory posture follow the 2026-04-04 baseline, OOM-killed during build_relationships, and the 2026-04-22 baseline, which returned Campaign = 0 through a swallowed enrichment error; the APOC partial-batch recovery is a full-task re-run because no per-step `--step N` flag exists.
- 2026-04-22 — The CVE date backfill script for CVEs whose dates the MISP-sourced `merge_cve` path had dropped before that path was fixed.
- 2026-04-22 — The runbook was rewritten against the code (real log prefixes and paths, `--bootstrap-sources`, three kill-switches, the Prometheus alert → paging severity table), with the baseline launch path and the raw-MISP retrieval paths.
- 2026-04-21 — First version: the top five failure modes, two kill-switches and the baseline-day protocol.
