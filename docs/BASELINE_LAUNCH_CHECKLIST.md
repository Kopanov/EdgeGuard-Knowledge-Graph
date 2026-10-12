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
* `[4] launch-path decision confirmed` (the `edgeguard baseline`/`fresh-baseline` CLI wrappers trigger the same DAG — see RUNBOOK § "Baseline launch path"; `--launch-path=cli` refers only to the legacy in-process `run_pipeline.py --baseline` path)
* `[5] IF DAG path: 5 scheduled DAGs PAUSED` (Issue #57 — required to prevent the incremental collectors AND `edgeguard_neo4j_sync` racing the baseline)
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

**If the most recent smoke is older than 7 days OR ran against a
commit before PR-N31 / PR-N32 landed:** re-run it. PR-N31's metric
wiring + PR-N32's audit script are too new to trust without a fresh
smoke against the post-PR-N32 codebase.

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

### [7] 2026-10 fresh-baseline PR: MISP import rule + flags

**What:** the 2026-10 PRs (#136–#140: evidence labels, report-scoped linking, CVE
properties, TLP, ownership marker, sector targeting, `SUBTECHNIQUE_OF`,
`USES_MALWARE` / `USES_TOOL`, pulse-scoped INDICATES / ATTRIBUTED_TO on regular updates, 20 `build_relationships` steps) only materialize on a
fresh re-feed — **and only if the hosted pipeline runs that code**. Before clearing:

0. **Deploy `main` first.** The wipe rebuilds the graph with whatever is checked out,
   so a re-feed on the old checkout produces a graph identical to the one being
   replaced. On the hosted pipeline: `git status` clean and `git diff origin/main`
   empty (commit or drop any local change first), then `git pull` to the PR #140
   merge (`ca9cdae`) or later. The Airflow base moved to
   `apache/airflow:3.3.2-python3.12` in the same train, so back up the Airflow
   metadata DB and rebuild the image — `docker compose build airflow && docker
   compose up -d --force-recreate airflow` — following
   [AIRFLOW_DAGS.md § 3.2 → 3.3.2](AIRFLOW_DAGS.md#32--332-october-2026).
   `edgeguard version` must print `2026.10.10` (or later) and `edgeguard doctor` must
   report Airflow `3.3.x` with no drift warning; the DAG list must load with zero parse
   errors.
1. **MISP Import Regexp.** In the MISP UI open *Input Filters → Import Regexp*
   and remove (or fix) the rule that rewrites `: Windows ` to `%WINDIR%\`. On the
   2026-09 baseline it mangled 12 ATT&CK entries (`T1047: Windows Management
   Instrumentation` became `T104%WINDIR%\Management Instrumentation`), so T1047,
   T1021.006, T1543.003, T1222.001, T1546.003 and tool S0005 never reached Neo4j.
   The acceptance script checks for them after the run.
2. **Flags.** Decide `EDGEGUARD_ENABLE_MITRE_ICS` and `EDGEGUARD_ENABLE_CISA_ICS`
   (both default `false`). Recommended: run the baseline with both **off**, run
   `scripts/verify_fresh_baseline.py`, then enable them one at a time (step 6).
   On the Compose deployment the flags live in `.env` and reach the `airflow`
   container only through the `x-common-env` block of `docker-compose.yml` (added
   October 2026 — a checkout older than that silently ignores them); after changing
   `.env` run `docker compose up -d airflow`. `EDGEGUARD_DEFAULT_TLP` (`white`) and
   `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE` (`true`) keep their defaults.
3. **Snapshot first.** Take a `neo4j-admin database dump` and a MISP export of the
   old instance before `edgeguard clear` — it is the "before" record for the
   quality numbers and the graph the v0.10 model was benchmarked on.
   Record the backup time in `EDGEGUARD_LAST_BACKUP_AT` — `fresh-baseline` and the
   `baseline_clean` task refuse to run without a backup inside
   `EDGEGUARD_BACKUP_MAX_AGE_HOURS` (default 240 h).
4. **One command for the re-feed.** `edgeguard fresh-baseline --days 730` deletes the
   EdgeGuard-managed Neo4j nodes (the default since 2026-10-12; `--wipe-all` deletes every node)
   and the EdgeGuard MISP events (typed confirmation, blast-radius display, backup-timestamp gate).
   For the October 2026 re-feed pass `--wipe-all`: the hosted database holds no partner-written
   nodes (verified 2026-10-10 and again 2026-10-12 — the 221 unmarked nodes are EdgeGuard's own
   pre-marker Campaign and Source nodes), and those would otherwise survive the scoped wipe and
   fail the `ownership_marker_on_nodes` acceptance check. On a database ResilMesh has started writing to, use the
   edgeguard-only sequence instead: `edgeguard clear neo4j --edgeguard-only`,
   `edgeguard clear misp`, `edgeguard checkpoint clear --include-incremental`, then the
   additive `edgeguard baseline --days 730`. `--edgeguard-only` deletes only the nodes
   EdgeGuard created; nodes a partner created first stay, marked `edgeguard_enriched = true`
   where EdgeGuard wrote to them (2026-10). Unmarked leftovers from before the marker existed
   (`MATCH (c:Campaign) WHERE c.edgeguard_managed IS NULL AND c.edgeguard_enriched IS NULL DETACH DELETE c`)
   must be deleted by hand first or `ownership_marker_on_nodes` fails. The first sync of this
   build also drops the six UNIQUE constraints EdgeGuard used to hold on partner labels
   (`device_key`, `networkservice_key`, `softwareversion_key`, `application_key`, `role_key`,
   `user_key`) — no manual DDL needed. The gate
   and triggers the `edgeguard_baseline` DAG with `fresh_baseline=true`; the DAG
   chain then runs `build_relationships` and the enrichment jobs itself. When it
   finishes, run `python scripts/verify_fresh_baseline.py` (needs `NEO4J_HTTP_URL` or
   `NEO4J_HTTP`, `NEO4J_USER`, `NEO4J_PASSWORD` of the instance under test in the
   environment) — every mandatory check must pass before the instance is handed to the
   partners or the demo. `uses_malware_complete` / `uses_tool_complete` are mandatory as soon
   as a MITRE actor exists (2026-10 audit): zero claims then means the `m` / `s` lists were
   lost in transit, not "collector not run yet".
   The baseline DAG holds the baseline lock for the whole run (Issue #57, 2026-10); pausing the
   scheduled DAGs before triggering remains the recommended extra step for a destructive run
   ([RUNBOOK § Baseline day protocol](RUNBOOK.md#baseline-day-protocol)).
5. **Hand back.** Return the acceptance JSON
   (`python scripts/verify_fresh_baseline.py --json > baseline_acceptance.json`),
   the two snapshot paths and the `edgeguard_baseline` DAG run id. The informational
   checks `uses_malware_complete` / `uses_tool_complete` become real once the MITRE
   collector of this build has run. Three relationship types exist for the first time
   after this re-feed — `SUBTECHNIQUE_OF`, `USES_MALWARE`, `USES_TOOL` (definitions in
   [RESILMESH_INTEROPERABILITY.md § 3.2](RESILMESH_INTEROPERABILITY.md)) — and
   `TARGETS` now also runs from actors and malware to sectors, so the Cypher model's
   training set needs examples for them.
6. **Enable the ICS sources one at a time** (each followed by the acceptance script
   with `--require-cisa-ics` / `--require-ics`):
   - `EDGEGUARD_ENABLE_CISA_ICS=true`, `docker compose up -d airflow`, then one **additive**
     `edgeguard baseline --days 730` (same DAG, no wipe). The daily task alone would load
     only the last `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` (30) days of advisories.
   - `EDGEGUARD_ENABLE_MITRE_ICS=true`, `docker compose up -d airflow`, then either the same
     additive baseline or `MITRE_FORCE_REFETCH=true` for one daily run — the daily MITRE
     task skips both bundles while the Enterprise bundle's ETag is unchanged.

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

If the items above pass, you are cleared to run `edgeguard_baseline`.
Every launch flow goes through the DAG — `edgeguard baseline` /
`edgeguard fresh-baseline` are wrappers that trigger it (PR-C,
2026-04-19); they add confirmation + backup-gate UX, **not** a mutex.
See RUNBOOK § "Baseline launch path" for the full procedure:

1. Pause the 5 scheduled DAGs (`edgeguard_daily`, `edgeguard_medium_freq`,
   `edgeguard_pipeline`, `edgeguard_low_freq`, `edgeguard_neo4j_sync`)
   so they don't race the baseline.
2. `airflow dags trigger edgeguard_baseline`
3. Watch the `baseline_complete` task. After it completes, unpause
   the 5 scheduled DAGs.

**Docs correction (2026-06):** the `baseline_in_progress.lock` sentinel
at `checkpoints/baseline_in_progress.lock` (per `src/baseline_lock.py`)
is **NOT** written by the baseline DAG (the DAG-side lock tasks were
de-scoped in PR-F2; Issue #57) — only the legacy in-process
`python src/run_pipeline.py --baseline` path writes it. For DAG-launched
baselines the manual pause above is therefore the ONLY mutex, not
defense-in-depth. Issue #57 tracks the DB-backed mutex that will
replace the manual-pause step.

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

### Fresh-baseline acceptance (2026-10 PR)

The 2026-10 changes (report-scoped linking, evidence labels, CVE properties,
TLP, ownership marker, optional ICS sources) only materialize on a fresh
re-feed. After `build_relationships` and the enrichment jobs have run, execute
the read-only acceptance script against the new graph and keep its JSON with
the baseline record:

```bash
python scripts/verify_fresh_baseline.py --json > baseline_acceptance.json
```

It exits non-zero when any of these fail:

| Check | Expected |
|---|---|
| Edges with `source_id = 'misp_cooccurrence'` | 0 |
| `match_type = 'mitre_explicit'` edges whose source node has no MITRE source | 0 |
| `ATTRIBUTED_TO` edges without a `match_type` | 0; median actors per malware in single digits |
| NVD-sourced `CVE` nodes carrying `cwe` / `ref_tags` / `cpe_type` / `result_impacts` | judged only on CVEs published > 45 days ago (NVD assigns reference tags and CPE configurations during analysis, weeks after publication — day-old CVEs have neither); thresholds 50 / 20 / 20 / 50 %; measured 2026-10-10 on the 730-day event: 93 / 57 / 58 / 91 %. Informational when fewer than 100 analysed CVEs are present (short smoke baselines) |
| `T1047`, `T1021.006`, `T1543.003`, `T1222.001`, `T1546.003`, Tool `S0005` | present (requires the MISP Import Regexp fix before re-import) |
| `ThreatActor` names containing `,` or ` and ` | 0 |
| `tlp` property | on every EdgeGuard node |
| `edgeguard_managed` | on every node EdgeGuard created and every EdgeGuard edge; a node a partner created first that EdgeGuard wrote to carries `edgeguard_enriched = true` instead |
| ICS (when `EDGEGUARD_ENABLE_MITRE_ICS`) | techniques with `attack_domain = 'ics'` link only to ICS tactics |
| CISA ICS (when `EDGEGUARD_ENABLE_CISA_ICS`) | `Source {source_id: 'cisa_ics'}` present with `SOURCED_FROM` edges |
| Sub-technique hierarchy (`subtechnique_of_complete`) | every dotted-id `Technique` whose parent exists has a `SUBTECHNIQUE_OF` edge to it (493 on the September graph; 0 missing) |
| Group → software (`uses_malware_complete`, `uses_tool_complete`) | every MITRE `uses_malware` / `uses_tools` claim whose target node exists has its edge (informational until the MITRE collector of the R6 build has run) |
| Sector coverage (`sector_coverage`, informational) | `ThreatActor` / `Malware` → `Sector` `TARGETS` present for finance, energy, healthcare (2026-10: ~200/100/100 actors and ~750/400/320 malware on the September graph); energy CVEs well above the 234 of the keyword-only vocabulary |
| ResilMesh conformance | relationship names and directions unchanged; `HAS_CVSS_*` bidirectional |

### GraphRAG readiness verification (post-#126)

Several PR #126 fixes change what is *written*, so they only materialize
on a fresh baseline — and several analyst-facing query shapes depend on
`build_relationships.py` having run after the sync. Verify in this order
(all read-only; Neo4j Browser or the HTTP runner):

1. **Aliases populated** — the alias round-trip fix. The pre-June
   snapshot had **0/917** actors with aliases, which silently disabled
   alias-based attribution and lookups ("Cozy Bear" → APT29):
   ```cypher
   MATCH (a:ThreatActor) WHERE size(coalesce(a.aliases, [])) > 0
   RETURN count(a)  // expect hundreds, not 0
   ```
2. **KEV markers populated** — CISA-only CVEs (~480 on the old
   snapshot) previously got no `cisa_exploit_add` property:
   ```cypher
   MATCH (c:CVE) WHERE c.cisa_exploit_add IS NOT NULL RETURN count(c)
   ```
3. **`build_relationships.py` ran** — `IMPLEMENTS_TECHNIQUE`,
   `USES_TECHNIQUE`, and `IN_TACTIC` edges come ONLY from this job
   (deliberately deferred out of the sync). All three edge types were
   entirely absent from the pre-June snapshot because the job never ran:
   ```cypher
   MATCH ()-[r:IMPLEMENTS_TECHNIQUE|USES_TECHNIQUE|IN_TACTIC]->()
   RETURN type(r) AS rel, count(r)  // all three must be non-zero
   ```
4. **Expected-empty is not a bug** — `Campaign` nodes are materialized
   by `enrichment_jobs.py`, not the sync; campaign queries return 0 rows
   until that job runs.

The full analyst-question catalog (19 test-pinned shapes) lives in
`tests/test_cypher_query_catalog.py::_TI_GRAPHRAG`, runnable against the
live graph via [`scripts/run_cypher_catalog_http.py`](../scripts/run_cypher_catalog_http.py).

---

## Cross-references

* [`docs/RUNBOOK.md`](RUNBOOK.md) — comprehensive operator reference
* [`docs/BACKUP.md`](BACKUP.md) — backup + restore procedure
* [`docs/BASELINE_SMOKE_TEST.md`](BASELINE_SMOKE_TEST.md) — 7-day smoke
* [`scripts/preflight_baseline.sh`](../scripts/preflight_baseline.sh) — automated readiness check
* [`scripts/audit_legacy_unicode_bypass_nodes.py`](../scripts/audit_legacy_unicode_bypass_nodes.py) — PR-N32 audit
* [`prometheus/alerts.yml`](../prometheus/alerts.yml) — alert rule definitions

---

_Last updated: 2026-10-10 (later) — § [7] step 2/6: flags reach the airflow container only via compose `x-common-env` (added), additive baseline after enabling CISA ICS, `MITRE_FORCE_REFETCH` for ICS. Earlier the same day — § [7]: deploy `main` (`ca9cdae`, Airflow 3.3.2 image rebuild) before the wipe, backup-gate env, DAG pause pointer, hand-back step with the three new relationship types. Prior: 2026-06-12 — added "GraphRAG readiness verification" to § After the run: post-baseline checks for the PR #126 write-side fixes (aliases, KEV markers) + the build_relationships edge types absent from the pre-June snapshot. Prior: 2026-06-11 — PR #125 docs correction: the lock sentinel is NOT written by the baseline DAG (PR-F2 de-scope, Issue #57) — manual pausing is the ONLY mutex on the DAG path, and the pause list now covers all 5 scheduled DAGs (added edgeguard_neo4j_sync); CLI wrappers exist (PR-C) but trigger the same DAG. Prior: 2026-04-28 — PR-N35 Tier-1 + PR-N36 follow-up:_
- _Item `[4]` description (PR-N35): "CLI vs DAG+pause" → "DAG-only at HEAD" (the
  CLI baseline subcommand referenced in older RUNBOOK versions doesn't
  exist in `src/edgeguard.py` — verified by `grep "add_parser"`)._
- _"Launch decision" section (PR-N35): removed Option A "CLI invocation" reference,
  rewrote as DAG-only 3-step procedure with explicit sentinel + Issue
  #57 cross-link._
- _Item `[2]` smoke-rerun wording (PR-N36): "AT LEAST 7 days ago against a
  different commit" → "older than 7 days OR ran against a commit before
  PR-N31 / PR-N32 landed" (cleaner OR-condition rather than the awkward
  AT-LEAST phrasing)._

_Prior: 2026-04-25 — added in PR-N32 alongside the legacy unicode-bypass audit script._
