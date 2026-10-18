# 730-day baseline — launch-day checklist

**Purpose:** the single document the operator walks through immediately
before triggering a 730-day MISP→Neo4j baseline. Every item maps to a
concrete failure mode of a baseline run.

**This is not a substitute for** [`docs/RUNBOOK.md`](RUNBOOK.md) — that
remains the comprehensive operator reference. This file is a **pre-flight
checklist**: 30 minutes of structured verification before pulling the
trigger on a 32-hour process that cannot be undone mid-run.

**Pass/fail interpretation:** every item either ✅ passes or 🛑 blocks
the launch. There is no soft-warn tier here — soft warns belong in
`scripts/preflight_baseline.sh` (they fire there, and the operator decides
whether to override). When this file says "block", it means stop and escalate.

The checklist assumes a fresh baseline built by the deployed code: § [6]
clears the EdgeGuard data in MISP and Neo4j before the baseline runs.

---

## How to use this doc

Run the items **in order**. Each section has:

* **What** — the one-line action
* **Command** — exactly what to run
* **Pass criteria** — what success looks like
* **If it fails** — the specific remediation pointer (RUNBOOK section,
  follow-up PR, or "stop and ask")

The whole pass takes about 30 minutes for an operator who has launched a
baseline before and 60 minutes the first time. Budget 2 hours in total so
that a discovery is not short-cut.

---

## Pre-launch checklist

### [1] Live preflight run — `scripts/preflight_baseline.sh`

**What:** run the 12-check preflight in strict mode against the actual
production environment. This is the single most important check: besides
the environment and connectivity checks, it verifies the baseline hardening
invariants (fallback sentinel class, retries=0, lock max-age, alert wiring).

**Command:**

```bash
EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh --launch-path=dag
```

**Pass criteria:** exit code 0, all 12 checks green. Without
`--launch-path=dag` the script assumes the in-process CLI path, warns (which
fails under STRICT=1) and skips check [5]. Specifically:

* `[1] required env vars present` — NEO4J_PASSWORD, MISP_API_KEY, MISP_URL
* `[2] Neo4j reachable + APOC + indexes` — through `docker compose exec neo4j cypher-shell` when the Compose neo4j service runs, else `cypher-shell -a $NEO4J_URL` (default bolt://localhost:7687; the script reads NEO4J_URL, not NEO4J_URI, and logs in as user `neo4j`)
* `[3] MISP API reachable + auth valid`
* `[4] launch-path decision confirmed` (the `edgeguard baseline`/`fresh-baseline` CLI wrappers trigger the same DAG — see RUNBOOK § "Baseline launch path"; `--launch-path=cli` refers only to the in-process `run_pipeline.py --baseline` path)
* `[5] IF DAG path: 5 scheduled DAGs PAUSED` (an unpaused DAG is a warning, a failure under STRICT=1: the baseline lock makes scheduled tasks skip at start, and pausing guarantees that none is mid-write)
* `[6] Airflow worker RAM ≥ 4 GB`
* `[7] Prometheus alerts.yml parses + ≥ 11 rules loaded`
* `[7b] alertmanager.yml has no placeholder / un-rendered ${...} pager key`
* `[8] no stale baseline_lock sentinel`
* `[9] kill-switch env vars` — `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION`
  unset (a warning when it is set)
* `[10] test suite syntax check` — `pytest --collect-only` collects the
  suite cleanly (a warning when `.venv/bin/pytest` is missing)
* `[11] baseline hardening invariants` — sentinel class, retries=0, 48h lock
  max-age, fallback metric wiring
* `[12] source API keys` — each configured key (OTX, NVD, VirusTotal,
  ThreatFox, AbuseIPDB) is accepted by its provider. A rejected key is
  a warning (the source would be skipped for the whole baseline), a
  rejected NVD key is a failure (the NVD task would fail after the
  wipe). A source without a key is listed as information: decide
  before the launch whether the baseline should run without it

**If it fails:** the failing check names the exact remediation. Do
**NOT** override `STRICT=1` to skip a fail — every fail in this script
marks either a failure mode seen in production or an attempt to bypass a
safeguard.

---

### [2] 7-day smoke baseline

**What:** confirm that the `_MispFallbackHardError` sentinel, the fallback
counter and the alert wiring work end-to-end against a live MISP. The unit
tests pin the contract, but only a live run proves that the fallback metric
is emitted and that Alertmanager routes the alert.

**Command:** see [`docs/BASELINE_SMOKE_TEST.md`](BASELINE_SMOKE_TEST.md)
for the full procedure. Short form:

```bash
# .env additions
EDGEGUARD_BASELINE_DAYS=7
EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000

docker compose up -d airflow   # not restart: picks up the .env values

# trigger via Airflow
airflow dags trigger edgeguard_baseline
```

**Pass criteria:**

* Smoke baseline completes without raising `_MispFallbackHardError`
* `edgeguard_misp_fetch_fallback_active_total` has no series unless the
  fallback engaged (a labelled counter without pre-initialised label
  sets), so on a healthy smoke run
  `sum(edgeguard_misp_fetch_fallback_active_total{outcome="hard_error"})`
  returns no data or 0. To prove the alert wiring, check that
  `EdgeGuardMispFetchFallbackHardError` is loaded (Prometheus /rules) and
  routed (item [3]).
* Post-run, the 7-day graph has the expected node + relationship counts
  for the smoke window

**If the most recent smoke run is older than 7 days:** re-run it. The
fallback metric and the alert wiring are proven only by a live smoke run.

**If it fails:** the smoke run failure mode itself is the diagnostic.
Map to RUNBOOK § "Top 8 failure modes":

| Smoke failure | RUNBOOK section |
|---|---|
| MISP 5xx exhaustion | § 1 |
| Neo4j ineffective batch | § 4 |
| `_MispFallbackHardError` raised | § 8 |
| Placeholder MERGE spike | § 6 |

---

### [3] Alertmanager receiver wired for `severity=critical, component=sync`

**What:** confirm that
`EdgeGuardMispFetchFallbackHardError` (critical severity, component=sync)
reaches a human pager / Slack / email channel. The alert rule is wired in
`prometheus/alerts.yml` — but if Alertmanager routing has no receiver
matching those labels, the alert fires into the void.

**Command:**

```bash
# Replace <amtool-config> with your Alertmanager config path or URL
amtool config routes test --tree --config.file=<amtool-config> \
    severity=critical component=sync
```

**Pass criteria:** the output names a receiver (Slack channel, PagerDuty
service, email address — whatever the routing tree resolves to). NOT
just `default-receiver` if the default is "/dev/null" — verify that the
specific matcher landed.

**If it fails:** Alertmanager routing config needs a receiver block for
`{severity=critical, component=sync}`. This is operator-side config;
no code change. Mirror the pattern used for the existing
`EdgeGuardCircuitBreakerOpen` alert (same severity / component=circuit-breaker).

---

### [4] MISP event count vs the index page cap and `_FALLBACK_MAX_PAGES = 200`

**What:** check whether the populated MISP has more events than the
primary index listing (below) or the fallback safety cap can paginate.
The fallback cap is 200 pages × 500 events = 100,000 events. If MISP
legitimately holds more, the fallback raises `_MispFallbackHardError`
mid-baseline; the cap has to be raised in advance, not at hour 18 of a
32-hour run.

**Command:**

```bash
curl -s -H "Authorization: $MISP_API_KEY" \
     -H "Accept: application/json" \
     "$MISP_URL/events/index" \
  | jq 'if type=="array" then length else (.response | length) end'
```

(rough scale; the actual fallback walks `/events/restSearch` for event
headers with ``eventinfo=%EdgeGuard%``, so on MISP 2.4.177 or later the
number above is an upper bound; an older MISP ignores that filter and the
fallback walks every event, i.e. the number above)

The primary `/events/index` listing stops at `EDGEGUARD_MISP_MAX_PAGES` ×
`EDGEGUARD_MISP_PAGE_SIZE` (100 × 500 = 50,000 listed events, counted before
the EdgeGuard filter), and a listing cut at that cap fails the sync. On a
MISP that honours paging, set `EDGEGUARD_MISP_MAX_PAGES` ≥
`ceil(count / 500) × 1.2` in `.env` (forwarded by docker-compose.yml) when the
count is ≥ 50,000. A MISP that ignores the query-string paging (2.5.45)
returns the whole listing on page 1.

**Pass criteria:** event count < 50,000 (index cap) and < 100,000 (fallback
cap), or both caps raised.

**If event count ≥ 100,000:**

1. Edit `src/run_misp_to_neo4j.py` — bump `_FALLBACK_MAX_PAGES`
   to a value ≥ `ceil(actual_count / 500) * 1.2` (20% headroom).
2. **Important:** this only matters if the primary `/events/index`
   path is broken. The index path is the default, and the fallback
   engages only when the index errors, so this is defense-in-depth —
   consider also fixing why the index errors.
3. Re-run preflight (`[1]` above) to confirm nothing else regressed.

---

### [5] Disk + RAM headroom for projected scale

**What:** confirm the host has enough Neo4j data-disk space + heap RAM
for the expected end state. Expected end state of a 730-day baseline
(measured on the hosted baseline loaded 2026-10-16): ~553,000 nodes /
~2.7M relationships. OOM at hour 26 of a 32-hour dagrun is the worst
failure mode — recovery requires the procedure in
[`docs/BACKUP.md`](BACKUP.md) § "Restore procedure" and 6+ hours of
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
* Heap (`NEO4J_HEAP_MAX`, passed as `server.memory.heap.max_size`)
  ≥ 12 GB and page cache (`NEO4J_PAGECACHE`, `server.memory.pagecache.size`)
  ≥ 8 GB for a ~2.7M-relationship baseline (README § Recommended Memory
  Settings); on a host with less than 32 GB for the Neo4j container,
  docs/DOCKER_SETUP_GUIDE.md allows an 8 GB heap or a 4 GB page cache
* `NEO4J_TX_MEMORY_MAX` ≥ 8 GB (the compose default is 4 GB, at which
  `build_relationships` runs out of transaction memory on a 730-day
  baseline)

**If it fails:** stop. There is no graceful recovery from mid-baseline
OOM. Either:

* Add disk / increase heap, then re-run this check
* Reduce baseline scope (`EDGEGUARD_BASELINE_DAYS=365` for a 1-year
  baseline as a fallback), and run that one first while procurement
  catches up

---

### [6] Fresh baseline: deploy, MISP import rule, flags, re-feed

**What:** the graph is built by whatever code is deployed, and part of its
contract (evidence labels, report-scoped linking, CVE properties, TLP,
ownership marker, sector targeting, `SUBTECHNIQUE_OF`, `USES_MALWARE` /
`USES_TOOL`, pulse-scoped INDICATES / ATTRIBUTED_TO on regular updates, 20
`build_relationships` steps) is complete only on a fresh re-feed. Before
clearing:

0. **Deploy `main` first.** The wipe rebuilds the graph with whatever is checked out,
   so a re-feed on an outdated checkout reproduces the graph being replaced. On the
   hosted pipeline: `git status` clean and `git diff origin/main` empty (commit or drop
   any local change first), then `git pull`. `scripts/verify_fresh_baseline.py` is
   written for a `main` at or after eef87be that also holds the CVE NVD-precedence
   change: that code holds the relationship, CVE, indicator-type, description and
   curated-package behaviour the re-feed must run with (step 5).
   After the pull, record the deployed commit, rebuild every image and recreate every
   container:
   ```bash
   scripts/record_deployed_commit.sh      # writes EDGEGUARD_GIT_SHA=<commit> into .env
   docker compose build && docker compose up -d --force-recreate
   ```
   The `api` and `graphql` images contain `src/` (the `Dockerfile` copies it at build
   time), so rebuilding only the Airflow image (built on `apache/airflow:3.3.2-python3.12`)
   would leave REST, GraphQL and STIX serving the old code. `EDGEGUARD_GIT_SHA` stays in
   `.env`, so every later `docker compose` command, from any shell, sees the same value
   and recreates no container because of it. Do not export it in the shell: Compose
   prefers a shell value to `.env`, and a `docker compose up -d` from a shell with a
   different value recreates `airflow`, which kills a running baseline, and restarts
   `api` and `graphql`. After the recreate,
   `curl -s http://127.0.0.1:8000/health | jq -r .git_sha` and
   `curl -s http://127.0.0.1:4001/health | jq -r .git_sha` must both print the pulled commit.
   Every collector task runs in the Airflow pool
   `edgeguard_collectors`, and while the pool does not exist the collectors of new runs
   are never scheduled, without an alert. The `airflow` service sets the pool on every
   start: after the recreate, `docker exec edgeguard_airflow airflow pools list` must
   list it with the slots of `EDGEGUARD_COLLECTOR_POOL_SLOTS` (default 4); see
   [AIRFLOW_DAGS.md § Collector pool: setup and resizing](AIRFLOW_DAGS.md#collector-pool-setup-and-resizing).
   The CalVer printed by `edgeguard version` (`2026.10.10`) does not identify these
   commits, so check the commit, not the version:
   `git merge-base --is-ancestor eef87be HEAD && echo ok` must print `ok`, and so must
   `test -f tests/test_cve_nvd_precedence.py && echo ok` (the CVE NVD-precedence change). `edgeguard version` also prints the git
   short SHA of the checkout.
   `edgeguard doctor` must report Airflow `3.3.x` with no drift warning; the DAG list must
   load with zero parse errors.
1. **MISP Import Regexp.** In the MISP UI open *Input Filters → Import Regexp*
   and remove (or fix) the rule that rewrites `: Windows ` to `%WINDIR%\`. On the
   2026-09 baseline it mangled 12 ATT&CK entries (`T1047: Windows Management
   Instrumentation` became `T104%WINDIR%\Management Instrumentation`), so T1047,
   T1021.006, T1543.003, T1222.001, T1546.003 and tool S0005 never reached Neo4j.
   The acceptance script checks for them after the run.
2. **Flags.** Decide `EDGEGUARD_ENABLE_MITRE_ICS`, `EDGEGUARD_ENABLE_CISA_ICS` and
   `EDGEGUARD_ENABLE_MALWAREBAZAAR` (all default `false`). Recommended: run the baseline
   with all three **off**, run `scripts/verify_fresh_baseline.py`, then enable them one at
   a time (step 6).
   On the Compose deployment the flags live in `.env` and reach the `airflow`
   container only through the `x-common-env` block of `docker-compose.yml`; after
   changing `.env` run `docker compose up -d airflow`. `EDGEGUARD_DEFAULT_TLP` (`white`),
   `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE` (`true`) and `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE`
   (`true`) keep their defaults.
3. **Snapshot first.** Take a `neo4j-admin database dump` and a MISP export of the
   existing instance before `edgeguard clear` — it is the "before" record for the
   quality numbers and the graph of the v0.10 model benchmark.
   Record the backup time in `EDGEGUARD_LAST_BACKUP_AT` — `fresh-baseline` and the
   `baseline_clean` task refuse to run without a backup inside
   `EDGEGUARD_BACKUP_MAX_AGE_HOURS` (default 240 h).
4. **One command for the re-feed.** `edgeguard fresh-baseline --days 730` deletes the
   EdgeGuard-managed Neo4j nodes (the default; `--wipe-all` deletes every node)
   and the EdgeGuard MISP events (typed confirmation, blast-radius display, backup-timestamp gate).
   On a database without partner-written nodes pass `--wipe-all` (the hosted database holds
   none, verified 2026-10-12): it deletes every node, including any node without the ownership
   marker.
   On a database ResilMesh has started writing to, use the edgeguard-only sequence instead:
   `edgeguard clear neo4j --edgeguard-only`, `edgeguard clear misp`,
   `edgeguard checkpoint clear --include-incremental`, then the additive
   `edgeguard baseline --days 730`. `--edgeguard-only` deletes only the nodes EdgeGuard
   created; nodes a partner created first stay, marked `edgeguard_enriched = true` where
   EdgeGuard wrote to them. The command then runs the backup gate
   and triggers the `edgeguard_baseline` DAG with `fresh_baseline=true`; the DAG
   chain then runs `build_relationships` and the enrichment jobs itself. When it
   finishes, run `python scripts/verify_fresh_baseline.py` (needs `NEO4J_HTTP_URL` or
   `NEO4J_HTTP`, `NEO4J_USER`, `NEO4J_PASSWORD` of the instance under test in the
   environment) — every mandatory check must pass before the instance is handed to the
   partners or the demo. `uses_malware_complete` / `uses_tool_complete` are mandatory as soon
   as a MITRE actor exists: zero claims then means the `m` / `s` lists were lost in transit,
   not "collector not run yet".
   The baseline DAG holds the baseline lock for the whole run; pausing the scheduled DAGs
   before triggering is the recommended extra step for a destructive run
   ([RUNBOOK § Baseline day protocol](RUNBOOK.md#baseline-day-protocol)).
   The `baseline_clean` step may take up to 60 minutes on a 730-day store: it deletes Neo4j
   relationships in batches before the nodes, and each MISP event delete may wait up to
   `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` (default 900 s; forwarded by `docker-compose.yml`, and
   used by `edgeguard clear misp` too). If the clean fails, the collectors and `full_neo4j_sync` refuse to run
   instead of writing into a half-wiped store ([RUNBOOK § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck)).
5. **Hand back.** Return the acceptance JSON
   (`python scripts/verify_fresh_baseline.py --json > baseline_acceptance.json`),
   the two snapshot paths and the `edgeguard_baseline` DAG run id.
   `uses_malware_complete` / `uses_tool_complete` are mandatory as soon as a MITRE actor
   exists. What consumers query in the graph:
   - The relationship types `SUBTECHNIQUE_OF`, `USES_MALWARE` and `USES_TOOL` (definitions in
     [RESILMESH_INTEROPERABILITY.md § 3.2](RESILMESH_INTEROPERABILITY.md)), and `TARGETS`
     from actors and malware to sectors; the Cypher model's training set needs examples for
     them.
   - Campaign membership is `PART_OF_CAMPAIGN`; `PART_OF` is ResilMesh's asset hierarchy alone.
   - Every relationship built from the sources carries `sources[]`, `source_refs[]` and
     `misp_event_ids[]`; relationships carry no `source_id`, `source_ids` or `report_ids`.
   - `CVE.cvss_score` is null and `severity` is `UNKNOWN` for a CVE without any CVSS, with
     `cvss_version`, `status` and `known_ransomware_use` alongside, and `CVE.attack_vector` is
     NVD's word for the attack vector of the scoring CVSS (`NETWORK`, `ADJACENT_NETWORK`,
     `LOCAL`, `PHYSICAL`), null without CVSS.
   - `CVE` nodes carry FIRST EPSS (`epss_score`, `epss_percentile`, `epss_score_date`,
     `epss_model_version`) and CISA's SSVC decision from NVD's record (`ssvc_exploitation`,
     `ssvc_automatable`, `ssvc_technical_impact`), also on the STIX `vulnerability`.
   - Descriptions: NVD's record sets a CVE's `description`, `published` and `last_modified`
     whenever NVD has a record of it, and any other record only fills them; MITRE's record
     sets a `Malware`, `ThreatActor` or `Tool` description, any other record only fills it,
     and the OTX collector gives malware families and adversaries no description. A
     description is the text of the highest-ranked source that gave one (NVD > CISA KEV >
     CISA ICS > any other source for a CVE, MITRE ATT&CK > a curated source > any other
     source for an entity) and names that source in `description_source`; a CVE without an
     NVD record shows the KEV's text over CISA ICS's, whatever the order of the events.
   - IPv6 indicators are `ipv6` and SSL Blacklist fingerprints `x509-fingerprint-sha1`.
   - The STIX bundles export every relationship with its provenance (extension definition
     1.7.0, with the explainability properties, the source of each description,
     `x_edgeguard_description_source`, and the aging of each indicator).
   - Every indicator ages by one rule from its latest report (the source's own date capped
     at the MISP time) and is retired after 730 days without one; the per-source measurement
     of [RUNBOOK.md](RUNBOOK.md#indicator-aging) follows the baseline.
   - A campaign rests on its actor's `ATTRIBUTED_TO` or `USES_MALWARE` links, so actors MITRE
     says use a malware have campaigns too; its links name the relationship types they rest
     on (`evidence_types`), and a campaign without evidence is deleted.
   - A curated package, once imported
     ([RUNBOOK § Importing a curated package](RUNBOOK.md#importing-a-curated-package)),
     adds `EXPLOITS` from actors and malware to CVEs and marks every link it touches with its
     TLP level.
6. **Enable the optional sources one at a time** (each followed by the acceptance script
   with `--require-cisa-ics` / `--require-ics` / `--require-malwarebazaar`):
   - `EDGEGUARD_ENABLE_CISA_ICS=true`, `docker compose up -d airflow`, then one **additive**
     `edgeguard baseline --days 730` (same DAG, no wipe). The daily task alone would load
     only the last `EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS` (30) days of advisories.
   - `EDGEGUARD_ENABLE_MITRE_ICS=true`, `docker compose up -d airflow`, then either the same
     additive baseline or `MITRE_FORCE_REFETCH=true` for one daily run — the daily MITRE
     task skips both bundles while the Enterprise bundle's ETag is unchanged.
   - `EDGEGUARD_ENABLE_MALWAREBAZAAR=true`, `docker compose up -d airflow`, then one
     `edgeguard_daily` run (or the additive baseline — both load the same recent export: the
     last 48 hours, at most `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` = 500 samples, labelled
     first), followed by `edgeguard_neo4j_sync` and
     `python scripts/verify_fresh_baseline.py --require-malwarebazaar`. The history builds up
     over the daily runs; there is no bulk load.

---

## Launch decision

If the items above pass, the baseline is cleared to run `edgeguard_baseline`.
Every launch flow goes through the DAG — `edgeguard baseline` /
`edgeguard fresh-baseline` are wrappers that trigger it; they add
confirmation + backup-gate UX, **not** a mutex.
See RUNBOOK § "Baseline launch path" for the full procedure:

1. Pause the 5 scheduled DAGs (`edgeguard_daily`, `edgeguard_medium_freq`,
   `edgeguard_pipeline`, `edgeguard_low_freq`, `edgeguard_neo4j_sync`)
   so they don't race the baseline.
2. `edgeguard fresh-baseline --days 730 --wipe-all` (destructive, see
   § [6] step 4) or `edgeguard baseline --days 730` (additive)
3. Watch `baseline_complete` and `baseline_release_lock`; unpause the 5
   scheduled DAGs after the lock is released. After a failed run the lock
   stays until the run is resumed and succeeds or 48 h have passed, and
   until then the scheduled DAGs skip.

**Baseline lock:** the `edgeguard_baseline`
DAG takes the lock itself. `baseline_acquire_lock` writes
`checkpoints/baseline_in_progress.lock` with the DAG run as holder before
`baseline_clean`, and `baseline_release_lock` removes it only after a
successful run. While it is held, the collectors of the scheduled DAGs
skip (`skip_reason_class=baseline_in_progress`), and `check_sync_needed`,
`run_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` of
`edgeguard_neo4j_sync` skip when they start. A failed run keeps the lock
so that clearing the failed task resumes under the mutex; the liveness
check prunes it once the run state is success, or when it is older than
`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC` (48 h). A refusal of
`baseline_clean` before the wipe (a typo'd `fresh_baseline`, an invalid
`wipe_scope`, the backup gate) releases the lock. Pausing the 5 scheduled
DAGs is still recommended: a task that is already running when the lock
is taken finishes its write.

---

## During the run

* Watch the `EdgeGuardMispFetchFallbackActive` (warning) and
  `EdgeGuardMispFetchFallbackHardError` (critical) alerts. Both stay
  silent for the entire run when everything is healthy.
* Watch the three critical-chain tasks' durations (`full_neo4j_sync`,
  `build_relationships`, `run_enrichment_jobs`) in the Airflow UI (Gantt /
  task duration) against their limits (6 h / 5 h / 5 h). Prometheus records
  only the sync's duration (`edgeguard_neo4j_sync_duration_seconds`,
  `edgeguard_pipeline_duration_seconds{pipeline_type="misp_to_neo4j"}`,
  buckets up to 600 s), per-job enrichment durations
  (`edgeguard_enrichment_duration_seconds{enricher_type}`) and the last
  completion of build_relationships
  (`edgeguard_build_relationships_last_completion_timestamp`).
* The `EdgeGuardSyncCoverageGap` alert is what catches silent
  truncation between MISP attribute count and processed count.

## After the run

Follow [`docs/RUNBOOK.md`](RUNBOOK.md) § "After the run" — postcheck
queries, sector-stats reconciliation, alert mute window cleanup.

### Fresh-baseline acceptance

After `build_relationships` and the enrichment jobs have run, execute the
read-only acceptance script against the new graph and keep its JSON with
the baseline record:

```bash
python scripts/verify_fresh_baseline.py --json > baseline_acceptance.json
```

It exits non-zero when any of these fail. A warning (`[WARN]`; in the JSON `ok: false` with
`mandatory: false`) is reported and leaves the exit code unchanged.

| Check | Expected |
|---|---|
| Edges labelled `misp_cooccurrence` (in `match_type`, `source_id` or `source_ids`) | 0 |
| `match_type = 'mitre_explicit'` edges whose source node has no MITRE source | 0 |
| `ATTRIBUTED_TO` edges without a `match_type` | 0; median actors per malware ≤ 10 |
| NVD-sourced `CVE` nodes carrying `cwe` / `ref_tags` / `cpe_type` / `result_impacts` | judged only on CVEs published > 45 days ago (NVD assigns reference tags and CPE configurations during analysis, weeks after publication — day-old CVEs have neither); thresholds 50 / 20 / 20 / 50 %; measured 2026-10-10 on the 730-day event: 93 / 57 / 58 / 91 %. Informational when fewer than 100 analysed CVEs are present (short smoke baselines) |
| `T1047`, `T1021.006`, `T1543.003`, `T1222.001`, `T1546.003`, Tool `S0005` | present (requires the MISP Import Regexp fix before re-import) |
| `ThreatActor` names containing `,`, ` and ` or ` & ` | 0 |
| `tlp` property (`tlp_on_every_node`) | on every EdgeGuard node parsed from a MISP attribute. The sync gives an attribute without a `tlp:` tag the level `EDGEGUARD_DEFAULT_TLP` and logs `[TLP] MISP attribute <uuid> has no tlp: tag`, so lost tags show in the sync log, not in this check |
| `edgeguard_managed` | on every node EdgeGuard created and every EdgeGuard edge; a node a partner created first that EdgeGuard wrote to carries `edgeguard_enriched = true` instead |
| ATT&CK domains (`in_tactic_same_domain`, always) | no `IN_TACTIC` between a technique and a tactic of different `attack_domain`. With `--require-ics` (`ics_techniques_present`), at least one `attack_domain = 'ics'` technique |
| CISA ICS (when `EDGEGUARD_ENABLE_CISA_ICS`) | `Source {source_id: 'cisa_ics'}` present with `SOURCED_FROM` edges; with `--require-cisa-ics` also the sectors its advisories state linked as `advisory_sector` once its records carry their zones (see "Sector evidence" below) |
| MalwareBazaar (when `EDGEGUARD_ENABLE_MALWAREBAZAAR`) | `Source {source_id: 'malwarebazaar'}` present with at least one sha256 hash indicator sourced from it (`--require-malwarebazaar`) |
| Revoked ATT&CK objects (`no_revoked_attack_techniques`, `no_revoked_attack_groups`, `no_revoked_attack_software`; `revoked_group_names_folded` is a **warning**) | no `Technique` carries an id `src/reference/attack_revoked_ids.json` lists, no `ThreatActor` from MITRE is a revoked group and no `Malware` / `Tool` from MITRE is revoked software (by name); a warning when an actor from another source bears a revoked group's name (the alias merge folds it into the successor). Informational without Technique nodes / MITRE actors / MITRE software; all three fail when the map cannot be read |
| Explainability (`translated_links_record_cited_ids`; `actor_merges_recorded` is informational) | every `USES_TECHNIQUE` link from an indicator to the successor of a revoked id in its `attack_ids` names that id in `r.cited_ids`; the count of actors with `merged_from` and of the names folded into them. Informational without such links; fails when the map cannot be read |
| Sub-technique hierarchy (`subtechnique_of_complete`) | every dotted-id `Technique` whose parent exists has a `SUBTECHNIQUE_OF` edge to it (493 on the September graph; 0 missing) |
| Group → software (`uses_malware_complete`, `uses_tool_complete`) | every MITRE `uses_malware` / `uses_tools` claim whose target node exists has its edge. Informational only while the graph has no MITRE actor; once one exists, zero claims fails the check (the `m` / `s` lists were lost in transit) |
| Pulse-scoped INDICATES (`pulse_indicates_complete`) | every family an indicator's OTX pulse named (`pulse_malware_families`) whose Malware node exists (by name, without the ATT&CK id suffix, through folded names) has its `INDICATES` edge. Informational while no indicator carries pulse families |
| Malware twins (`malware_attack_twins_folded`) | no `Malware` node from another source is named after an ATT&CK software id (`cobalt strike - s0154`, the MISP galaxy naming OTX uses), or carries such an alias of its own name, while the enrichment job `merge_malware_attack_twins` would fold it: into the MITRE `Malware` node of that id (read from the record MITRE delivered) or of that base name, or, for software without one, into the `Malware` node of its base name (`mimikatz - s0002` into `mimikatz`). A twin with neither (an ATT&CK tool no pulse has yet named by its base name) is reported, not failed. One whose id and base name lead to more than one MITRE node fails; the job skips it on every run, so it needs a decision by hand. Informational when no node is named with an id. After one run of the enrichment jobs without failed batches (`errors=0` on the job's `complete` line), only the ambiguous twins and the twins without a target remain, so the check passes when no ambiguous twin remains. Size of the problem on the graph of 2026-10-14: 136 twins holding 16,005 `INDICATES` links (how many of them have a MITRE target was not measured) |
| `no_global_sector_edges` | no `TARGETS` / `AFFECTS` edge ends at `Sector {name: 'global'}` (`global` is the no-sector marker) |
| Sector coverage (`sector_coverage`, informational) | `ThreatActor` / `Malware` → `Sector` `TARGETS` present for finance, energy, healthcare (on the September graph: ~200/100/100 actors and ~750/400/320 malware); energy CVEs well above 234, the count a keyword-only vocabulary yields |
| ResilMesh conformance | relationship types not written by EdgeGuard are listed (informational); every CVSSv30 / CVSSv31 / CVSSv40 node has one edge from and one edge to a CVE (`cvss_bidirectional`) |
| Relationship sources (`relationships_name_their_source`, `provenance_lists_are_lists`) | every EdgeGuard relationship built from the sources has a non-empty `r.sources`; `sources`, `source_refs`, `misp_event_ids` (and node `zone`, `source`, and the `SOURCED_FROM` lists `zones`, `stated_zones`, `stated_refs`) are lists, never strings |
| Provenance per relationship type (`relationship_provenance_complete`) | every EdgeGuard edge carries what its writers guarantee: `sources`, `source_refs`, `misp_event_ids` and `match_type` on the links built by `build_relationships` and the sync; the three lists, `match_type` (`campaign_grouping`) and `evidence_types` on `RUNS` and `PART_OF_CAMPAIGN`; the three lists on `REFERS_TO` (enrichment job, no evidence label); `sources` and `misp_event_ids` on `HAS_CVSS_*`; `source` (a string), `source_refs` and `misp_event_ids` on `SOURCED_FROM`. Presence is judged: an empty `misp_event_ids` list is legitimate (a link whose records name no MISP event) and only counted per type |
| Dropped relationship keys (`no_legacy_relationship_properties`) | no relationship of an EdgeGuard type carries `source_id`, `source_ids` or `report_ids` (other types are listed, never failed on); every `Source` node keeps `source_id`, its key |
| Campaign membership (`campaign_membership_is_part_of_campaign`) | no `PART_OF` ends at a `Campaign`; every `PART_OF_CAMPAIGN` runs from a `Malware` or `Indicator` to a `Campaign`. `PART_OF` stays ResilMesh's (IP → Subnet, the OrganizationUnit hierarchy) |
| Attribution from a source report (`attribution_from_single_actor_reports`) | no same-pulse `ATTRIBUTED_TO` rests only on OTX pulses whose actors are several actors (the aliases of one actor count as one, canonical reference), unless another feed asserts it, and none names such a pulse in its provenance. The pulses are step 2d's: those recorded on two or more actor nodes that are several actors, and those the OTX collector marked on indicators (`Indicator.several_actor_pulses`, judged with the canonical reference, from the IOCs the collector pushed; the MISP writer marks no stored copy; the detail counts them as `pulses_marked_on_indicators`). Informational without the reference. On the graph of 2026-10-15, a dry run of step 2d's statements (pulses recorded on two or more actor nodes): 475 links to remove and 24 to trim, from 35 pulses; counted from the pulses' own adversary fields instead: 515 links from 29 pulses. Informational too when the graph holds no same-pulse attribution, and when no actor records a pulse and no indicator a mark |
| Campaign malware membership (`campaign_malware_has_evidence`) | every `Malware -[:PART_OF_CAMPAIGN]-> Campaign` has the malware attributed to the campaign's actor (`ATTRIBUTED_TO`) or used by it (`USES_MALWARE`) (`build_campaign_nodes` step 2b prunes the rest; the definition is `src/campaign_evidence.py`, which the builder reads too). Informational without malware members |
| No campaign without evidence (`campaigns_have_evidence`) | every `Campaign` EdgeGuard built has an actor of its `actor_name` with an `ATTRIBUTED_TO` or `USES_MALWARE` link to a malware (`build_campaign_nodes` step 1b deletes the others with their links) and that actor's `RUNS`; no `RUNS` comes from an actor that is not the campaign's or has neither link (step 2c removes it). The detail counts `without_evidence`, `without_runs` and `runs_without_evidence`. A campaign with evidence whose indicators all expired is legitimate (`active = false`). Informational while there is no campaign EdgeGuard built and no `RUNS` without evidence; a `RUNS` without evidence into any campaign, a partner's included, fails |
| CVE scores (`cve_score_from_cvss`) | an EdgeGuard `CVE` with a CVSS sub-node whose `base_score` is in [0, 10] has the `cvss_score` / `cvss_version` of the sub-node selected in the order 3.1, 3.0, 2.0, 4.0 and a CVSS rating as `severity`; a `CVE` without one has a null score and version and `severity = 'UNKNOWN'`. Informational while there is no CVE |
| FIRST EPSS and CISA's SSVC (`cve_epss_and_ssvc`, **warning**) | warns when `CVE` nodes exist and none carries `epss_score`: EPSS is off (`EDGEGUARD_ENABLE_EPSS=false`) or the feed was unavailable (the enrichment task log has an `[EPSS]` line). Reports the CVEs with EPSS, the number of EPSS score dates (one expected; more mean a run stopped before clearing, or matched too few nodes to clear) and the latest, and the CVEs with a CISA SSVC decision and with `ssvc_exploitation = 'active'`. Informational while there is no CVE. On the hosted graph of 2026-10-15 (written by a test run of the job): 137,753 of 141,932 CVEs with EPSS, 2 score dates |
| Sector evidence (`sector_links_name_only_feeds_that_gave_the_sector`, `advisory_sector_only_where_cisa_stated`, `cisa_stated_sectors_linked_as_advisory_sector`, `sector_links_cite_only_records_that_gave_the_sector`, `sector_confidence_follows_label`) | every link to a `Sector` names only the feeds whose `SOURCED_FROM.zones` hold that sector (not judged when no edge has `zones`); `advisory_sector` only on `AFFECTS` from a CVE to a sector the `cisa_ics` edge lists in `stated_zones`, and every such stated sector linked with it (with `--require-cisa-ics`, at least one once the `cisa_ics` edges carry `zones`); a sector link cites, of the CISA ICS advisories, only those whose sector note names its sector (the edge's `stated_refs`; not judged when no edge has them); the confidence of a sector link is its label's value in `src/sector_evidence.py` (`zone_classification` 0.5, `advisory_sector` 0.9). Reported: `sector_evidence_breakdown`, `cisa_ics_contribution` (per sector: stated, by CISA alone, also inferred; CISA records with no tracked sector) and `node_sectors_without_a_feed` (and nodes with `global` next to a sector) |
| Ranked descriptions and indicator aging (`descriptions_name_their_source`, `indicators_have_aging_basis`) | every EdgeGuard node with a ranked description (labels from `src/description_ranking.py`) names its source in `description_source`; every EdgeGuard `Indicator` has `aging_basis` and `source_confidence`. Informational while the graph holds no such node |
| Per-source presence (`default_sources_delivered`, **warning**) | the `SOURCED_FROM` count of every `Source` node is listed; a source collected by default (`cisa_kev`, `mitre_attck`, `nvd`, `urlhaus`, `feodo_tracker`, `ssl_blacklist`) with none is a warning — look at that collector's task in the baseline run (an upstream outage skips it without failing the run). Keyed sources without data (`alienvault_otx`, `virustotal`, `threatfox`, `abuseipdb`: skipped by design without a key) and the flag-guarded ones (`cisa_ics`, `malwarebazaar`) are only listed |

### GraphRAG readiness verification

Several analyst-facing query shapes depend on properties the sync writes
(aliases, KEV markers) and on `build_relationships.py` having run after the
sync. Verify in this order (all read-only; Neo4j Browser or the HTTP runner):

1. **Aliases populated** — alias-based attribution and lookups
   ("Cozy Bear" → APT29) depend on them:
   ```cypher
   MATCH (a:ThreatActor) WHERE size(coalesce(a.aliases, [])) > 0
   RETURN count(a)  // expect hundreds, not 0
   ```
2. **KEV markers populated** — CVEs that only CISA reports carry the
   `cisa_exploit_add` property too:
   ```cypher
   MATCH (c:CVE) WHERE c.cisa_exploit_add IS NOT NULL RETURN count(c)
   ```
3. **`build_relationships.py` ran** — `IMPLEMENTS_TECHNIQUE`,
   `USES_TECHNIQUE`, and `IN_TACTIC` edges come ONLY from this job
   (deliberately kept out of the sync):
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
* [`prometheus/alerts.yml`](../prometheus/alerts.yml) — alert rule definitions

---

_Last updated: 2026-10-18_

## History

- 2026-10-18 — The deploy step of § [6] rebuilds every image and recreates every container (it rebuilt only the Airflow image, which left REST, GraphQL and STIX on the old code) and records the deployed commit in `.env` (`scripts/record_deployed_commit.sh` writes `EDGEGUARD_GIT_SHA`, which both `/health` responses report as `git_sha`).
- 2026-10-18 — The unicode-bypass audit item was removed, so the fresh-baseline item is [6]. The acceptance script has no `--legacy-graph` option: the description-source and aging checks are judged whenever the graph holds such nodes, and `--require-cisa-ics` requires a stated sector once the `cisa_ics` edges carry `zones`. Preflight check [9] covers `EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION` only (`EDGEGUARD_RESPECT_CALIBRATOR` was removed).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Restated as a guide to the current behaviour: change history moved here, the steps for kept deployments and graphs moved to the appendix.
- 2026-10-17 — Preflight with `--launch-path=dag` and checks [2], [7b], [9], [10] described; the DAG holds the baseline lock; smoke run applied with `docker compose up -d airflow`; the 50,000-event index cap; expected end state and memory thresholds of a 730-day baseline; minimum code checked by commit; acceptance rows for `no_global_sector_edges`, `pulse_indicates_complete`, `in_tactic_same_domain` and ResilMesh conformance.
- 2026-10-16 — Acceptance checks for sector evidence, ranked descriptions and indicator aging (`--legacy-graph` for older graphs) and for campaign evidence (`campaign_malware_attributed` became `campaign_malware_has_evidence`; `campaigns_have_evidence` added); collector pool step; fallback event count via `eventinfo`; description source ranking and STIX extension definitions 1.5.0 to 1.7.0.
- 2026-10-15 — CVE and entity description rules with the repair of kept graphs; acceptance checks for malware twins, revoked ATT&CK objects, explainability, EPSS and SSVC, relationship provenance, campaign membership, CVE scores and per-source presence; batched clean step and MISP delete timeout.
- 2026-10-12 — MalwareBazaar added as the third flag-guarded source; the scoped Neo4j wipe became the default of `fresh-baseline`.
- 2026-10-11 — Shared-database contract: `edgeguard_managed` on the nodes EdgeGuard creates, `edgeguard_enriched` on partner nodes it writes to, and every sync drops the six UNIQUE constraints earlier versions held on partner labels (`device_key`, `networkservice_key`, `softwareversion_key`, `application_key`, `role_key`, `user_key`).
- 2026-10-10 — Item [7] added for the October 2026 fresh re-feed: deploy `main` first (Airflow 3.3.2 image), MISP Import Regexp fix, optional source flags forwarded through compose `x-common-env`, snapshot and backup gate, one-command re-feed, hand-back.
- 2026-06-12 — GraphRAG readiness verification added, because the pre-June snapshot had 0/917 actors with aliases, ~480 CISA-only CVEs without `cisa_exploit_add` and none of the `build_relationships` edge types.
- 2026-06-11 — Pause list extended to all five scheduled DAGs; the CLI wrappers documented as triggers of the same DAG.
- 2026-04-28 — Launch decision rewritten as a DAG-only procedure; the smoke run is repeated when older than 7 days or run before the fallback metric wiring and the unicode audit script.
- 2026-04-25 — Checklist added together with the unicode-bypass audit script.
