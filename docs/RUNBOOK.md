# EdgeGuard On-Call Runbook

**Audience:** on-call operator responding to an alert or incident during
a baseline or incremental sync.

**Scope:** the five failure modes observed during pre-PR-N7 730d baselines
+ the kill-switches added in PR-N11 to let on-call revert a specific PR-Nx
semantic change without a code revert.

---

## Quick reference — kill-switches

Each kill-switch is a process environment variable read at request time
(not module import), so toggling requires a task restart, not a redeploy.

| Env var | Default | When to set | What it reverts |
|---|---|---|---|
| `EDGEGUARD_RESPECT_CALIBRATOR` | unset (guard active) | Calibrator demotions causing false negatives after PR-N10; operator wants pre-N10 overwrite behaviour | `_confidence_respect_calibrator` emits bare literal (pre-PR-N10), not CASE guard |
| `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` | unset (inspection active) | Result-counter inspection itself throwing (driver API drift, double-consume) — mid-baseline | `_record_batch_counters` short-circuits to no-op (pre-PR-N9 B6) |

Set via task env (one-off):

```bash
EDGEGUARD_RESPECT_CALIBRATOR=0 airflow tasks run edgeguard_incremental sync …
```

or in the Airflow connection / .env (persistent):

```
EDGEGUARD_RESPECT_CALIBRATOR=0
EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION=1
```

Restart the affected DAG / worker for the change to take effect. Revert
by unsetting and restarting.

---

## Top 5 failure modes

Each entry: symptom → detection signal → remediation → runbook link.

### 1. MISP batch permanent failure (5xx exhaustion)

- **Symptom.** One or more 500-attribute batches lost; post-baseline
  `MATCH (i:Indicator {source: 'otx'}) RETURN count(i)` is lower than
  `edgeguard_indicators_collected_total{source="otx"}` counter value.
- **Prom alert.** `EdgeGuardMispBatchPermanentFailure` — fires when
  `rate(edgeguard_misp_push_permanent_failure_total[5m]) > 0` for 5m.
- **Root cause.** MISPWriter's `@retry_with_backoff(max_retries=4)` gave
  up after four attempts. Typical triggers: MISP PHP memory_limit below
  event-size threshold, MySQL `innodb_buffer_pool_size` too small for
  working set, MISP worker OOM.
- **Remediation.**
  1. `kubectl logs <misp-pod> --tail=500 | grep -i "out of memory\|segfault"`
  2. Check `/proc/meminfo` on the MISP host.
  3. Tune per `docs/MISP_TUNING.md` § PHP & MySQL.
  4. Retry the specific batch via `python -m src.collectors.misp_writer
     --replay-failed --since <timestamp>`.

### 2. MISP sustained backoff (flap vs overload)

- **Symptom.** Ingest stalling in 5-minute waves; nightly incremental
  runs exceeding 1-hour SLO.
- **Prom alert.** `EdgeGuardMispSustainedBackoff` — fires when extended
  cooldown triggers more than once per 15 min.
- **Root cause.** MISP backend is sustained-degraded (not a transient
  flap — the adaptive backoff distinguishes them).
- **Remediation.** Same as (1) — this is usually the early-warning
  before (1) fires.

### 3. Honest-NULL violation (collector forging timestamps)

- **Symptom.** Calibrator decay runs attribute staleness from
  `first_seen`, but the data comes out obviously wrong — everything
  looks ~1 day old regardless of actual source age.
- **Prom alert.** `EdgeGuardMispHonestNullViolation` — fires when a
  specific (source, field) pair exceeds 100 violations/hour.
- **Root cause.** PR-N5 C7 validator caught a collector calling
  `datetime.now()` as a fallback when the source feed was silent on a
  timestamp. The violation log line names the collector.
- **Remediation.**
  1. `grep EDGE-GUARD-NULL-VIOLATION /var/log/airflow/*.log | tail -50`
  2. Audit the named collector's extraction path.
  3. Remove the `datetime.now()` fallback — pass `None` through.
  4. Ship fix via a hotfix PR; do NOT disable the validator.

### 4. Neo4j ineffective-batch (silent write failure)

- **Symptom.** Incremental sync task reports success, but post-run
  `MATCH (n:Label) RETURN count(n)` shows no growth for that label.
- **Prom alert.** `EdgeGuardNeo4jIneffectiveBatch` — fires when a
  non-empty batch produces ZERO counter-visible writes.
- **Root cause.** Three common triggers:
  1. Source node missing (the SOURCED_FROM MATCH returns zero rows; the
     per-row edge MERGE silently never runs).
  2. Constraint violation on primary MERGE key.
  3. Schema drift (new MISP attribute type, stale Cypher).
- **Remediation.**
  1. `MATCH (s:Source {source_id: '<source>'}) RETURN s` — if empty,
     re-run `ensure_sources()` via
     `python -m src.neo4j_client --bootstrap-sources`.
  2. Tail Neo4j log for constraint violations:
     `docker logs edgeguard-neo4j 2>&1 | grep -i constraint | tail -20`.
  3. For schema drift: diff the failing Cypher against
     `src/neo4j_client.py` MERGE site; add the missing property coalesce.

### 5. Placeholder-name MERGE spike (feed regression or attack)

- **Symptom.** Growing volume of `MERGE-REJECT: placeholder name` WARN
  log lines; Malware / ThreatActor node count flatlined despite sync
  activity.
- **Detection.** `grep MERGE-REJECT /var/log/airflow/*.log | sort | uniq -c | sort -rn | head`.
  (A Prometheus counter + alert for this lands in PR-N12.)
- **Root cause.** A collector is emitting Malware / ThreatActor nodes
  with placeholder names (`unknown`, `N/A`, `generic`, …). Feed
  regression (upstream schema change) or, in the worst case, an
  adversary injecting malicious `Malware{name: "unknown"}` nodes to
  cause false-attribution storms via Q9 edges.
- **Remediation.**
  1. Identify the offending collector from the log lines' source tag.
  2. If feed regression: file an issue against the feed upstream;
     extend the collector's normalization to skip placeholder names
     before they reach `merge_malware()`.
  3. If suspected injection: freeze the source, audit that MISP event's
     attributes, purge with
     `MATCH (m:Malware)-[r]->() WHERE m.name IN ['unknown','N/A','generic'] DELETE r, m`.
  4. PR-N10's merge-time reject already blocked the actual writes —
     the graph is safe. Focus on finding WHY the collector started
     emitting them.

---

## Baseline-day protocol

Before a 730d baseline run:

1. **Smoke test.** Run a 7-day window first (baseline=7 instead of 730).
   Success criteria: no ERROR lines, metrics look sane, spot-check 10
   random Indicators via Neo4j Browser.
2. **Prometheus dashboard.** Verify
   `edgeguard_pipeline_observability` rule group is loaded
   (`promtool check rules prometheus/alerts.yml`).
3. **Kill-switches staged.** Decide in advance — what signal would make
   you set `EDGEGUARD_RESPECT_CALIBRATOR=0`? Write it down before the
   run starts so you're not making the call in an outage.

During the run:

- Monitor the 4 `edgeguard_pipeline_observability` alerts every hour.
- Any BLOCK alert (batch permanent failure, ineffective batch) → pause
  the DAG, triage, then resume. Do NOT let it continue silently.

After the run:

- Diff `count(*)` of each node label vs. previous baseline.
- Diff `MATCH ()-[r]->() WHERE r.calibrated_at IS NOT NULL AND
  r.confidence_score > 0.5 RETURN count(r)` — expect ~0 (calibrator-
  demoted edges that still read as high-confidence = PR-N10 Fix #2
  regression).

---

## See also

- `docs/MISP_TUNING.md` — backend tuning for failure modes 1-2
- `docs/KNOWLEDGE_GRAPH.md` — schema reference
- `docs/VERSIONING.md` — CalVer release cadence
- `prometheus/alerts.yml` — alert rule source of truth
- `src/neo4j_client.py:_record_batch_counters` — ineffective-batch detector (PR-N9 B6)
- `src/neo4j_client.py:_confidence_respect_calibrator` — calibrator-respect helper (PR-N10)
