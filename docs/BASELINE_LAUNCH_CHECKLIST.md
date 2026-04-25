# 730-day baseline — launch-day checklist

**Purpose:** the single doc the operator walks through immediately
before triggering a 730-day MISP→Neo4j baseline. Every item maps to a
concrete failure mode that has either bitten us in a prior run or that
the audit cycle (PR-N26 / N29 / N30 / N31) explicitly built defenses
against.

**This is not a substitute for** [`docs/RUNBOOK.md`](RUNBOOK.md) — that
remains the comprehensive operator reference. This file is a **pre-flight
checklist**: 30 minutes of structured verification before pulling the
trigger on a 32-hour irreversible-mid-run process.

**Pass/fail interpretation:** every item either ✅ passes or 🛑 blocks
the launch. There is no soft-warn tier here — soft warns belong in
`scripts/preflight_baseline.sh` (they fire there, you decide whether to
override). When this file says "block", it means stop and escalate.

---

## How to use this doc

Run the items **in order**. Each section has:

* **What** — the one-line action
* **Command** — exactly what to run
* **Pass criteria** — what success looks like
* **If it fails** — the specific remediation pointer (RUNBOOK section,
  follow-up PR, or "stop and ask")

The whole thing should take 30 minutes if you've launched a baseline
before, 60 minutes the first time. Budget 2 hours total so you don't
short-cut on a discovery.

---

## Pre-launch checklist

### [1] Live preflight run — `scripts/preflight_baseline.sh`

**What:** run the 11-check preflight in strict mode against the actual
prod environment. This is the single most important check — it
exercises every PR-N29 invariant (sentinel class, retries=0, lock
max-age, alert wiring) in addition to the original 8 sanity checks.

**Command:**

```bash
EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh
```

**Pass criteria:** exit code 0, all 11 checks green. Specifically:

* `[1] required env vars present` — NEO4J_PASSWORD, MISP_API_KEY, MISP_URL
* `[2] Neo4j reachable + APOC + indexes`
* `[3] MISP API reachable + auth valid`
* `[4] launch-path decision confirmed` (CLI vs DAG+pause)
* `[5] IF DAG path: 4 incremental DAGs PAUSED` (Issue #57)
* `[6] Airflow worker RAM ≥ 4 GB`
* `[7] Prometheus alerts.yml parses + ≥ 11 rules loaded`
* `[8] no stale baseline_lock sentinel`
* `[9..10]` (existing checks)
* `[11] PR-N29 invariants` — sentinel class, retries=0, 48h lock
  max-age, fallback metric wiring

**If it fails:** the failing check tells you the exact remediation. Do
**NOT** override `STRICT=1` to skip a fail — every fail in this script
is a real risk that has either bitten us in production or was
explicitly designed to catch a bypass attempt.

---

### [2] 7-day smoke baseline on the post-PR-N31 codebase

**What:** confirm the new `_MispFallbackHardError` sentinel + counter +
alert wiring work end-to-end against a live MISP. The unit tests pin
the contract, but only a live run proves the fallback metric actually
emits and Alertmanager actually routes the alert.

**Command:** see [`docs/BASELINE_SMOKE_TEST.md`](BASELINE_SMOKE_TEST.md)
for the full procedure. Short form:

```bash
# .env additions
EDGEGUARD_BASELINE_DAYS=7
EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000

# trigger via Airflow
airflow dags trigger edgeguard_baseline
```

**Pass criteria:**

* Smoke baseline completes without raising `_MispFallbackHardError`
* Prometheus shows `edgeguard_misp_fetch_fallback_active_total` exists
  as a series (even if value=0 — proves the counter is registered)
* Post-run, the 7-day graph has the expected node + relationship counts
  for the smoke window

**If the smoke ran AT LEAST 7 days ago against a different commit:**
re-run it. PR-N31's metric wiring is too new to trust without a fresh
smoke against the post-PR-N31 codebase.

**If it fails:** the smoke run failure mode itself is the diagnostic.
Map to RUNBOOK § "Top 8 failure modes":

| Smoke failure | RUNBOOK section |
|---|---|
| MISP 5xx exhaustion | § 1 |
| Neo4j ineffective batch | § 4 |
| `_MispFallbackHardError` raised | § 8 (newly added in PR-N29/N31) |
| Placeholder MERGE spike | § 6 |

---

### [3] Alertmanager receiver wired for `severity=critical, component=sync`

**What:** confirm the new
`EdgeGuardMispFetchFallbackHardError` (critical severity, component=sync)
actually reaches a human pager / Slack / email channel. The alert rule
is wired in `prometheus/alerts.yml` — but if Alertmanager routing has
no receiver matching those labels, the alert fires into the void.

**Command:**

```bash
# Replace <amtool-config> with your Alertmanager config path or URL
amtool config routes test --tree --config.file=<amtool-config> \
    severity=critical component=sync
```

**Pass criteria:** the output names a receiver (Slack channel, PagerDuty
service, email address — whatever your routing tree resolves to). NOT
just `default-receiver` if your default is "/dev/null" — verify the
specific matcher landed.

**If it fails:** Alertmanager routing config needs a receiver block for
`{severity=critical, component=sync}`. This is operator-side config;
no code change. Mirror whatever pattern you use for the existing
`EdgeGuardCircuitBreakerOpen` alert (same severity / component=circuit-breaker).

---

### [4] MISP event count vs `_FALLBACK_MAX_PAGES = 200` cap

**What:** check whether the populated MISP has more EdgeGuard events
than the fallback safety cap can paginate. The cap is 200 pages × 500
events = 100,000 events. If MISP legitimately has more, the fallback
will raise `_MispFallbackHardError` mid-baseline (PR-N29 made this
visible — but it still needs the cap raised in advance, not at
hour 18 of a 32-hour run).

**Command:**

```bash
curl -s -H "Authorization: $MISP_API_KEY" \
     -H "Accept: application/json" \
     "$MISP_URL/events/index" \
  | jq 'if type=="array" then length else (.response | length) end'
```

(rough scale; the actual fallback walks `/events/restSearch` with
``search=EdgeGuard``, so the number above is an upper bound)

**Pass criteria:** event count < 100,000.

**If event count ≥ 100,000:**

1. Edit `src/run_misp_to_neo4j.py` — bump `_FALLBACK_MAX_PAGES`
   to a value ≥ `ceil(actual_count / 500) * 1.2` (20% headroom).
2. **Important:** this only matters if the primary `/events/index`
   path is broken (PR-N29 made the index path the default). The
   fallback only engages if the index errors. So this is
   defense-in-depth — consider also fixing why the index errors.
3. Re-run preflight (`[1]` above) to confirm nothing else regressed.

---

### [5] Disk + RAM headroom for projected scale

**What:** confirm the host has enough Neo4j data-disk space + heap RAM
for the expected end state. Pre-2-year historical: documented at
~350,000 nodes / ~700,000 relationships. OOM at hour 26 of a 32-hour
dagrun is the worst failure mode — recovery requires the procedure
in [`docs/BACKUP.md`](BACKUP.md) § "Restore procedure" and 6+ hours of
operator time.

**Command (Docker Compose):**

```bash
# Disk: where the Neo4j volume lives
docker volume inspect edgeguard-knowledge-graph_neo4j_data \
  | jq -r '.[0].Mountpoint' | xargs df -h

# RAM: Neo4j heap config
docker compose exec neo4j neo4j-admin server memory-recommendation
```

**Pass criteria:**

* Free disk ≥ 50 GB on the Neo4j data volume (current footprint ×4 for
  WAL + index rebuilds during heavy MERGE)
* `dbms.memory.heap.max_size` ≥ 8 GB (4 GB minimum, 8 GB recommended
  for 350k-node baseline; 16 GB if you can spare)
* `dbms.memory.pagecache.size` ≥ 4 GB

**If it fails:** stop. There is no graceful recovery from mid-baseline
OOM. Either:

* Add disk / increase heap, then re-run this check
* Reduce baseline scope (`EDGEGUARD_BASELINE_DAYS=365` for a 1-year
  baseline as a fallback), and run that one first while procurement
  catches up

---

### [6] PR-N32 unicode-bypass audit

**What:** check whether legacy `Malware`/`ThreatActor`/`Tool` nodes
exist with zero-width / bidi-control chars in their names — created
BEFORE the PR-N29 L1 placeholder filter landed. Read-only audit; no
mutation.

**Command:**

```bash
./scripts/audit_legacy_unicode_bypass_nodes.py
```

**Pass criteria:** total suspicious count = 0 OR ≤ 10 with operator
spot-check OK.

**If audit returns ≥ 1 suspicious node:**

| Count    | Action                                                                 |
|----------|------------------------------------------------------------------------|
| 0        | ✅ pass — close PR-N32 as a no-op                                      |
| 1–10     | One-shot Cypher per node (rename / re-merge / delete); no PR needed   |
| > 10     | 🛑 build a proper PR-N32 migration BEFORE the baseline. The baseline doesn't fix legacy data. |

The audit script's recommendation block tells you which bucket you're
in and what to do.

---

## Launch decision

If all 6 items pass, you are cleared to run `edgeguard_baseline`. Pick
your launch path per RUNBOOK § "Baseline launch path":

* **Option A (recommended):** CLI invocation — see RUNBOOK § "Option A"
* **Option B:** DAG + pre-pause the 4 incremental schedulers — see
  RUNBOOK § "Option B"

**Do not pick both.** The DAG and CLI paths share the `baseline_lock`
sentinel; concurrent invocation will (correctly) fail-fast with
`BaselineAlreadyRunning`, but it's a confusing state to debug.

---

## During the run

* Watch the `EdgeGuardMispFetchFallbackActive` (warning) and
  `EdgeGuardMispFetchFallbackHardError` (critical) alerts. Both are
  PR-N31; both should be SILENT for the entire run if everything is
  healthy.
* Watch `edgeguard_pipeline_duration_seconds` for the 3 critical-chain
  tasks (`full_neo4j_sync`, `build_relationships`, `run_enrichment_jobs`).
  Each should complete within its expected envelope (RUNBOOK has the
  envelopes).
* The `EdgeGuardSyncCoverageGap` alert is what catches silent
  truncation between MISP attribute count and processed count.

## After the run

Follow [`docs/RUNBOOK.md`](RUNBOOK.md) § "After the run" — postcheck
queries, sector-stats reconciliation, alert mute window cleanup.

---

## Cross-references

* [`docs/RUNBOOK.md`](RUNBOOK.md) — comprehensive operator reference
* [`docs/BACKUP.md`](BACKUP.md) — backup + restore procedure
* [`docs/BASELINE_SMOKE_TEST.md`](BASELINE_SMOKE_TEST.md) — 7-day smoke
* [`scripts/preflight_baseline.sh`](../scripts/preflight_baseline.sh) — automated readiness check
* [`scripts/audit_legacy_unicode_bypass_nodes.py`](../scripts/audit_legacy_unicode_bypass_nodes.py) — PR-N32 audit
* [`prometheus/alerts.yml`](../prometheus/alerts.yml) — alert rule definitions

---

_Last updated: 2026-04-25 — added in PR-N32 alongside the legacy unicode-bypass audit script._
