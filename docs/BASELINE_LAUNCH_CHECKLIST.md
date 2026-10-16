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

**What:** run the 12-check preflight in strict mode against the actual
prod environment. This is the single most important check — it
exercises every PR-N29 invariant (sentinel class, retries=0, lock
max-age, alert wiring) in addition to the original 8 sanity checks.

**Command:**

```bash
EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh
```

**Pass criteria:** exit code 0, all 12 checks green. Specifically:

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
* `[12] source API keys` — each configured key (OTX, NVD, VirusTotal,
  ThreatFox, AbuseIPDB) is accepted by its provider. A rejected key is
  a warning (the source would be skipped for the whole baseline), a
  rejected NVD key is a failure (the NVD task would fail after the
  wipe). A source without a key is listed as information: decide
  before the launch whether the baseline should run without it

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

(rough scale; the actual fallback walks `/events/restSearch` for event
headers with ``eventinfo=%EdgeGuard%``, so on MISP 2.4.177 or later the
number above is an upper bound; an older MISP ignores that filter and the
fallback walks every event, i.e. the number above)

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
   empty (commit or drop any local change first), then `git pull` to a `main` that holds
   the CVE description rule (2026-10: NVD's record sets a CVE's `description`, `published`
   and `last_modified`, any other record only fills them; branch
   `fix/cve-description-source`) and the entity description rule (2026-10: MITRE's record
   sets a `Malware`, `ThreatActor` or `Tool` description, any other record only fills it,
   and the OTX collector gives malware families and adversaries no description; branch
   `fix/entity-description-source`) and the description source ranking (2026-10-16: a
   description is the text of the highest-ranked source that gave one, NVD > CISA KEV > CISA
   ICS > any other source for a CVE, MITRE ATT&CK > a curated source > any other source for an
   entity, named in `description_source`; branch `fix/campaigns-descriptions-aging`), or later:
   that state holds the 2026-10 relationship,
   CVE, indicator-type and curated-package changes the re-feed must run with. A `main`
   after #193 without the CVE rule re-feeds `OTX_META` JSON, OTX pulse names and the text of
   whichever KEV, OTX or ICS record merged last as CVE descriptions; without the entity rule
   it writes into MISP, as the description of each family and adversary, the description of
   the first pulse that named it, and an entity MITRE and OTX both name shows the text of
   whichever record merged last.
   Before that `git pull`, create the collector pool in the running container (2026-10:
   every collector task runs in the Airflow pool `edgeguard_collectors`, and until the
   pool exists the collectors of new runs are never scheduled, without an alert):
   `docker exec edgeguard_airflow airflow pools set edgeguard_collectors 4 "Collector tasks of all DAGs"`.
   After the recreate below, `docker exec edgeguard_airflow airflow pools list` must list
   it with the slots of `EDGEGUARD_COLLECTOR_POOL_SLOTS` (default 4); see
   [AIRFLOW_DAGS.md § Collector pool: upgrade and resizing](AIRFLOW_DAGS.md#collector-pool-upgrade-and-resizing-2026-10).
   The Airflow base is `apache/airflow:3.3.2-python3.12` (since #140), so back up the
   Airflow metadata DB and rebuild the image — `docker compose build airflow && docker
   compose up -d --force-recreate airflow` — following
   [AIRFLOW_DAGS.md § 3.2 → 3.3.2](AIRFLOW_DAGS.md#32--332-october-2026).
   `edgeguard version` must print `2026.10.10` (or later) and `edgeguard doctor` must
   report Airflow `3.3.x` with no drift warning; the DAG list must load with zero parse
   errors.
   A graph that is kept instead of re-fed needs one repair after this deploy (2026-10): the
   CVE descriptions and dates written before it are those of the record merged last (raw
   `OTX_META` JSON, OTX pulse names, CISA's KEV text, CISA ICS dates). Remove the descriptions
   that are metadata blocks or OTX pulse references, then run one full sync
   (`NEO4J_FULL_SYNC=true` with `force_sync`) as [RUNBOOK § Repairing CVE descriptions and dates](RUNBOOK.md#repairing-cve-descriptions-and-dates-2026-10)
   describes. The `Malware`, `ThreatActor` and `Tool` descriptions written before it are
   likewise those of the record merged last (an OTX pulse's text, a raw
   `MITRE_USES_TECHNIQUES` block): run the cleanup statements of [RUNBOOK § Repairing
   Malware, ThreatActor and Tool descriptions](RUNBOOK.md#repairing-malware-threatactor-and-tool-descriptions-2026-10)
   before the same full sync, which serves both. The re-feed below needs neither.
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
   container only through the `x-common-env` block of `docker-compose.yml` (added
   October 2026 — a checkout older than that silently ignores them); after changing
   `.env` run `docker compose up -d airflow`. `EDGEGUARD_DEFAULT_TLP` (`white`),
   `EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE` (`true`) and `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE`
   (`true`, 2026-10) keep their defaults.
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
   The `baseline_clean` step may take up to 60 minutes on a 730-day store: it deletes Neo4j
   relationships in batches before the nodes, and each MISP event delete may wait up to
   `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` (default 900 s; forwarded by `docker-compose.yml`, and
   used by `edgeguard clear misp` too). If the clean fails, the collectors and `full_neo4j_sync` refuse to run
   instead of writing into a half-wiped store ([RUNBOOK § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck-pr-n27-2026-10)).
5. **Hand back.** Return the acceptance JSON
   (`python scripts/verify_fresh_baseline.py --json > baseline_acceptance.json`),
   the two snapshot paths and the `edgeguard_baseline` DAG run id. The informational
   checks `uses_malware_complete` / `uses_tool_complete` become real once the MITRE
   collector of this build has run. Three relationship types exist for the first time
   after this re-feed — `SUBTECHNIQUE_OF`, `USES_MALWARE`, `USES_TOOL` (definitions in
   [RESILMESH_INTEROPERABILITY.md § 3.2](RESILMESH_INTEROPERABILITY.md)) — and
   `TARGETS` now also runs from actors and malware to sectors, so the Cypher model's
   training set needs examples for them. The graph of the next re-feed also changes what
   consumers query (2026-10): campaign membership is `PART_OF_CAMPAIGN` (`PART_OF` is
   ResilMesh's asset hierarchy alone); every relationship built from the sources carries
   `sources[]`, `source_refs[]` and `misp_event_ids[]`, and the relationship properties
   `source_id`, `source_ids` and `report_ids` no longer exist; `CVE.cvss_score` is null and
   `severity` is `UNKNOWN` for a CVE without any CVSS (no more 3.0 / LOW), with
   `cvss_version`, `status` and `known_ransomware_use` alongside, and `CVE.attack_vector` is
   NVD's word for the attack vector of the scoring CVSS (`NETWORK`, `ADJACENT_NETWORK`,
   `LOCAL`, `PHYSICAL`), null without CVSS; IPv6 indicators are `ipv6` and SSL Blacklist
   fingerprints `x509-fingerprint-sha1`; the STIX bundles export every relationship with its
   provenance (extension definition 1.7.0, with the explainability properties, the source of
   each description, `x_edgeguard_description_source`, and the aging of each indicator); every
   indicator ages by one rule from its latest report (the source's own date capped at the MISP
   time), retired after 730 days without one, and the per-source measurement of
   [RUNBOOK.md](RUNBOOK.md#indicator-aging-rollout-2026-10-16) follows the baseline (2026-10-16);
   a campaign rests on
   its actor's `ATTRIBUTED_TO` or (2026-10-16) `USES_MALWARE` links, so actors MITRE says use a
   malware have campaigns too, its links name the relationship types they rest on
   (`evidence_types`), and a campaign without evidence is deleted; `CVE` nodes carry
   FIRST EPSS (`epss_score`, `epss_percentile`, `epss_score_date`, `epss_model_version`) and
   CISA's SSVC decision from NVD's record (`ssvc_exploitation`, `ssvc_automatable`,
   `ssvc_technical_impact`), also on the STIX `vulnerability`; a CVE's `description`,
   `published` and `last_modified` are NVD's whenever NVD has a record of it (2026-10; no
   `OTX_META` JSON, OTX pulse name, KEV text or ICS advisory date in their place), and every
   description names its source in `description_source` (2026-10-16; a CVE without an NVD
   record shows the KEV's text over CISA ICS's, whatever the order of the events). A curated package, once imported
   ([RUNBOOK § Importing a curated package](RUNBOOK.md#importing-a-curated-package-2026-10)),
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

It exits non-zero when any of these fail. A warning (`[WARN]`; in the JSON `ok: false` with
`mandatory: false`) is reported and leaves the exit code unchanged:

| Check | Expected |
|---|---|
| Edges labelled `misp_cooccurrence` (`match_type`, or the legacy `source_id` / `source_ids` on a graph built before 2026-10) | 0 |
| `match_type = 'mitre_explicit'` edges whose source node has no MITRE source | 0 |
| `ATTRIBUTED_TO` edges without a `match_type` | 0; median actors per malware in single digits |
| NVD-sourced `CVE` nodes carrying `cwe` / `ref_tags` / `cpe_type` / `result_impacts` | judged only on CVEs published > 45 days ago (NVD assigns reference tags and CPE configurations during analysis, weeks after publication — day-old CVEs have neither); thresholds 50 / 20 / 20 / 50 %; measured 2026-10-10 on the 730-day event: 93 / 57 / 58 / 91 %. Informational when fewer than 100 analysed CVEs are present (short smoke baselines) |
| `T1047`, `T1021.006`, `T1543.003`, `T1222.001`, `T1546.003`, Tool `S0005` | present (requires the MISP Import Regexp fix before re-import) |
| `ThreatActor` names containing `,` or ` and ` | 0 |
| `tlp` property (`tlp_on_every_node`) | on every EdgeGuard node parsed from a MISP attribute. Since 2026-10 the sync gives an attribute without a `tlp:` tag the level `EDGEGUARD_DEFAULT_TLP` and logs `[TLP] MISP attribute <uuid> has no tlp: tag`, so lost tags show in the sync log, not in this check |
| `edgeguard_managed` | on every node EdgeGuard created and every EdgeGuard edge; a node a partner created first that EdgeGuard wrote to carries `edgeguard_enriched = true` instead |
| ICS (when `EDGEGUARD_ENABLE_MITRE_ICS`) | techniques with `attack_domain = 'ics'` link only to ICS tactics |
| CISA ICS (when `EDGEGUARD_ENABLE_CISA_ICS`) | `Source {source_id: 'cisa_ics'}` present with `SOURCED_FROM` edges; with `--require-cisa-ics` also the sectors its advisories state linked as `advisory_sector` once its records carry their zones (see "Sector evidence" below) |
| MalwareBazaar (when `EDGEGUARD_ENABLE_MALWAREBAZAAR`) | `Source {source_id: 'malwarebazaar'}` present with at least one sha256 hash indicator sourced from it (`--require-malwarebazaar`) |
| Revoked ATT&CK objects (`no_revoked_attack_techniques`, `no_revoked_attack_groups`, `no_revoked_attack_software`; `revoked_group_names_folded` is a **warning**) | no `Technique` carries an id `src/reference/attack_revoked_ids.json` lists, no `ThreatActor` from MITRE is a revoked group and no `Malware` / `Tool` from MITRE is revoked software (by name); a warning when an actor from another source bears a revoked group's name (the alias merge folds it into the successor). Informational without Technique nodes / MITRE actors / MITRE software; all three fail when the map cannot be read. A graph built before 2026-10 fails them (2026-10-15: 158 techniques, 6 groups, 1 piece of software) |
| Explainability (`translated_links_record_cited_ids`; `actor_merges_recorded` is informational) | every `USES_TECHNIQUE` link from an indicator to the successor of a revoked id in its `attack_ids` names that id in `r.cited_ids`; the count of actors with `merged_from` and of the names folded into them. Informational without such links; fails when the map cannot be read. A graph built before 2026-10 fails it (2026-10-15: 1,218 links, none recorded) |
| Sub-technique hierarchy (`subtechnique_of_complete`) | every dotted-id `Technique` whose parent exists has a `SUBTECHNIQUE_OF` edge to it (493 on the September graph; 0 missing) |
| Group → software (`uses_malware_complete`, `uses_tool_complete`) | every MITRE `uses_malware` / `uses_tools` claim whose target node exists has its edge (informational until the MITRE collector of the R6 build has run) |
| Malware twins (`malware_attack_twins_folded`, 2026-10) | no `Malware` node from another source is named after an ATT&CK software id (`cobalt strike - s0154`, the MISP galaxy naming OTX uses), or carries such an alias of its own name, while the enrichment job `merge_malware_attack_twins` would fold it: into the MITRE `Malware` node of that id (read from the record MITRE delivered) or of that base name, or, for software without one, into the `Malware` node of its base name (`mimikatz - s0002` into `mimikatz`). A twin with neither (an ATT&CK tool no pulse has yet named by its base name) is reported, not failed. One whose id and base name lead to more than one MITRE node fails; the job skips it on every run, so it needs a decision by hand. Informational when no node is named with an id. After one run of the enrichment jobs without failed batches (`errors=0` on the job's `complete` line), only the ambiguous twins and the twins without a target remain, so the check passes when no ambiguous twin remains. Size of the problem on the graph of 2026-10-14: 136 twins holding 16,005 `INDICATES` links (how many of them have a MITRE target was not measured) |
| Sector coverage (`sector_coverage`, informational) | `ThreatActor` / `Malware` → `Sector` `TARGETS` present for finance, energy, healthcare (2026-10: ~200/100/100 actors and ~750/400/320 malware on the September graph); energy CVEs well above the 234 of the keyword-only vocabulary |
| ResilMesh conformance | relationship names and directions unchanged; `HAS_CVSS_*` bidirectional |
| Relationship sources (`relationships_name_their_source`, `provenance_lists_are_lists`) | every EdgeGuard relationship built from the sources has a non-empty `r.sources`; `sources`, `source_refs`, `misp_event_ids` (and node `zone`, `source`) are lists, never strings |
| Provenance per relationship type (`relationship_provenance_complete`) | every EdgeGuard edge carries what its writers guarantee: `sources`, `source_refs`, `misp_event_ids` and `match_type` on the links built by `build_relationships` and the sync; the three lists, `match_type` (`campaign_grouping`, 2026-10-15) and `evidence_types` (2026-10-16) on `RUNS` and `PART_OF_CAMPAIGN`; the three lists on `REFERS_TO` (enrichment job, no evidence label); `sources` and `misp_event_ids` on `HAS_CVSS_*`; `source` (a string), `source_refs` and `misp_event_ids` on `SOURCED_FROM`. Presence is judged: an empty `misp_event_ids` list is legitimate (a link whose records name no MISP event) and only counted per type |
| Dropped relationship keys (`no_legacy_relationship_properties`) | no relationship of an EdgeGuard type carries `source_id`, `source_ids` or `report_ids` (other types are listed, never failed on); every `Source` node keeps `source_id`, its key |
| Campaign membership (`campaign_membership_is_part_of_campaign`) | no `PART_OF` ends at a `Campaign`; every `PART_OF_CAMPAIGN` runs from a `Malware` or `Indicator` to a `Campaign`. `PART_OF` stays ResilMesh's (IP → Subnet, the OrganizationUnit hierarchy) |
| Attribution from a source report (`attribution_from_single_actor_reports`) | no same-pulse `ATTRIBUTED_TO` rests only on OTX pulses whose actors are several actors (the aliases of one actor count as one, canonical reference), unless another feed asserts it, and none names such a pulse in its provenance. The pulses are step 2d's (2026-10-16): those recorded on two or more actor nodes that are several actors, and those the OTX collector marked on indicators (`Indicator.several_actor_pulses`, judged with the canonical reference, from the IOCs the collector pushed; the MISP writer marks no stored copy, 2026-10; the detail counts them as `pulses_marked_on_indicators`). Informational without the reference. On the graph of 2026-10-15, before the rule, step 2d's statements as a dry run (pulses recorded on two or more actor nodes): 475 links to remove and 24 to trim, from 35 pulses; counted from the pulses' own adversary fields instead: 515 links from 29 pulses. Informational too when the graph holds no same-pulse attribution (2026-10-16; it passed as mandatory), and when no actor records a pulse and no indicator a mark |
| Campaign malware membership (`campaign_malware_has_evidence`; `campaign_malware_attributed` until 2026-10-16) | every `Malware -[:PART_OF_CAMPAIGN]-> Campaign` has the malware attributed to the campaign's actor (`ATTRIBUTED_TO`) or, since 2026-10-16, used by it (`USES_MALWARE`) (`build_campaign_nodes` step 2b prunes the rest; the definition is `src/campaign_evidence.py`, which the builder reads too). Informational without malware members |
| No campaign without evidence (`campaigns_have_evidence`, 2026-10-16) | every `Campaign` EdgeGuard built has an actor of its `actor_name` with an `ATTRIBUTED_TO` or `USES_MALWARE` link to a malware (`build_campaign_nodes` step 1b deletes the others with their links) and that actor's `RUNS`; no `RUNS` comes from an actor that is not the campaign's or has neither link (step 2c removes it). The detail counts `without_evidence`, `without_runs` and `runs_without_evidence`. A campaign with evidence whose indicators all expired is legitimate (`active = false`). Informational while there is no campaign EdgeGuard built and no `RUNS` without evidence; a `RUNS` without evidence into any campaign (a partner's, or one written before) fails |
| CVE scores (`cve_score_from_cvss`) | an EdgeGuard `CVE` with a CVSS sub-node whose `base_score` is in [0, 10] has the `cvss_score` / `cvss_version` of the sub-node selected in the order 3.1, 3.0, 2.0, 4.0 and a CVSS rating as `severity`; a `CVE` without one has a null score and version and `severity = 'UNKNOWN'`. Informational while there is no CVE |
| FIRST EPSS and CISA's SSVC (`cve_epss_and_ssvc`, **warning**) | warns when `CVE` nodes exist and none carries `epss_score`: EPSS is off (`EDGEGUARD_ENABLE_EPSS=false`) or the feed was unavailable (the enrichment task log has an `[EPSS]` line). Reports the CVEs with EPSS, the number of EPSS score dates (one expected; more mean a run stopped before clearing, or matched too few nodes to clear) and the latest, and the CVEs with a CISA SSVC decision and with `ssvc_exploitation = 'active'`. Informational while there is no CVE. On the hosted graph of 2026-10-15 (written by a test run of the job): 137,753 of 141,932 CVEs with EPSS, 2 score dates |
| Sector evidence (`sector_links_name_only_feeds_that_gave_the_sector`, `advisory_sector_only_where_cisa_stated`, `cisa_stated_sectors_linked_as_advisory_sector`, `sector_links_cite_only_records_that_gave_the_sector`, `sector_confidence_follows_label`, 2026-10-16) | every link to a `Sector` names only the feeds whose `SOURCED_FROM.zones` hold that sector (not judged when no edge has `zones`, a graph built before); `advisory_sector` only on `AFFECTS` from a CVE to a sector the `cisa_ics` edge lists in `stated_zones`, and every such stated sector linked with it (with `--require-cisa-ics`, at least one once the `cisa_ics` edges carry `zones`; not required with `--legacy-graph`); a sector link cites, of the CISA ICS advisories, only those whose sector note names its sector (the edge's `stated_refs`; not judged when no edge has them); the confidence of a sector link is its label's value in `src/sector_evidence.py` (`zone_classification` 0.5, `advisory_sector` 0.9). Reported: `sector_evidence_breakdown`, `cisa_ics_contribution` (per sector: stated, by CISA alone, also inferred; CISA records with no tracked sector) and `node_sectors_without_a_feed` (and nodes with `global` next to a sector) |
| Ranked descriptions and indicator aging (`descriptions_name_their_source`, `indicators_have_aging_basis`, 2026-10-16) | every EdgeGuard node with a ranked description (labels from `src/description_ranking.py`) names its source in `description_source`; every EdgeGuard `Indicator` has `aging_basis` and `source_confidence`. The next baseline is the first built with these writers; on an older graph run with `--legacy-graph`, which reports both instead of judging them |
| Per-source presence (`default_sources_delivered`, **warning**) | the `SOURCED_FROM` count of every `Source` node is listed; a source collected by default (`cisa_kev`, `mitre_attck`, `nvd`, `urlhaus`, `feodo_tracker`, `ssl_blacklist`) with none is a warning — look at that collector's task in the baseline run (an upstream outage skips it without failing the run). Keyed sources without data (`alienvault_otx`, `virustotal`, `threatfox`, `abuseipdb`: skipped by design without a key) and the flag-guarded ones (`cisa_ics`, `malwarebazaar`) are only listed |

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

_Last updated: 2026-10-16 — "Fresh-baseline acceptance": the sector-evidence checks (sector links name only the feeds that gave the sector and cite only the CISA ICS advisories that name it; `advisory_sector` only on AFFECTS where CISA stated it, and on every sector CISA stated, required under `--require-cisa-ics` once the CISA ICS records carry their zones and not with `--legacy-graph`; confidence follows the label) and the description-source and aging checks (`--legacy-graph` for an older graph). Same day: step 0: create the collector pool `edgeguard_collectors` in the running container before the `git pull`, and check it with `airflow pools list` after the recreate. Same day: fallback event count: the fallback walks `/events/restSearch` for event headers with `eventinfo=%EdgeGuard%` (it sent `search`, which MISP ignores); on a MISP older than 2.4.177 it walks every event. Same day: `campaigns_have_evidence` judges a `RUNS` without evidence also on a graph without EdgeGuard campaigns. Same day: `attribution_from_single_actor_reports`: the indicator marks come from the IOCs the collector pushed; the MISP writer marks no stored copy. Same day: step 0 names the indicator aging (one rule from the latest report, retirement after 730 days, the per-source measurement after the baseline) and extension definition 1.7.0. Same day: step 0 names the description source ranking (`description_source`; CVE NVD > CISA KEV > CISA ICS > any other source, entity MITRE ATT&CK > a curated source > any other source) and STIX extension definition 1.6.0; the re-feed description line says every description names its source. Same day: campaign acceptance: `campaign_malware_attributed` is now `campaign_malware_has_evidence` (a malware member may rest on `USES_MALWARE` too), the new check `campaigns_have_evidence` fails on a campaign without evidence or a `RUNS` without it, and `relationship_provenance_complete` requires `match_type` and `evidence_types` on `RUNS` and `PART_OF_CAMPAIGN`; the consumer changes of the re-feed name the campaign evidence and the STIX extension definition 1.5.0. Same day: `attribution_from_single_actor_reports`: the pulses naming several actors include those marked on indicators (as in step 2d; judged with the canonical reference, also on IOCs MISP already holds), and the check is informational when the graph holds no same-pulse attribution. Prior: 2026-10-15 — step 0: without the entity rule, MISP holds for each family and adversary the description of the first pulse that named it (was: every pulse's). Same day: step 0: the minimum `main` also holds the entity description rule (MITRE's record sets a `Malware`, `ThreatActor` or `Tool` description; OTX gives families and adversaries none), and a kept graph runs that repair's cleanup before the same full sync. Same day: acceptance table: `attribution_from_single_actor_reports` and `campaign_malware_attributed`. Same day: acceptance table: Malware twins (`malware_attack_twins_folded`: twins the job folds into an ATT&CK node or into the node of their base name, what remains after one run); step 2: `EDGEGUARD_ENABLE_MALWARE_TWIN_MERGE` keeps its default. Same day: step 0: the minimum is a `main` that holds the CVE description rule (was `main` after #193 and the documentation update that follows it); the repair also removes OTX pulse references. Same day: step 0: the repair of CVE descriptions and dates on a graph that is kept (cleanup statement, then one full sync); step 5: CVE description and dates are NVD's. Same day: acceptance table: FIRST EPSS and CISA's SSVC (`cve_epss_and_ssvc`, warning); step 5: EPSS and SSVC on `CVE`, STIX extension definition 1.4.0. Same day: acceptance table: the explainability check (`translated_links_record_cited_ids`, and `actor_merges_recorded` as information); STIX extension definition 1.3.0. Same day: the revoked ATT&CK object checks (`no_revoked_attack_techniques`, `no_revoked_attack_groups`, `no_revoked_attack_software`, and the warning `revoked_group_names_folded`). Same day: acceptance table: the data contracts of the 2026-10 relationship-provenance, campaign-membership and CVE-score changes (`relationship_provenance_complete`, `no_legacy_relationship_properties`, `campaign_membership_is_part_of_campaign`, `cve_score_from_cvss`), the per-source presence warning (`default_sources_delivered`), the rows of the existing provenance checks, and where lost TLP tags now show (the sync log); the co-occurrence row checks `match_type` (and the legacy `source_id` / `source_ids`); § [7] step 4: the clean step's 60 minutes, batched relationship deletion, `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC`, and the refusal of the collectors after a failed clean; step 5: what changes for consumers (`PART_OF_CAMPAIGN`, relationship provenance, CVE scores, STIX provenance, curated `EXPLOITS`); after #189: the delete timeout is forwarded by `docker-compose.yml` and used by `edgeguard clear misp`; step 0: the minimum is `main` after #193 and the documentation update that follows it (was `ca9cdae`); step 5: `CVE.attack_vector`, IPv6 and certificate-fingerprint indicator types, STIX extension definition 1.2.0, curated TLP. Prior: 2026-10-12 — § [7] steps 2 and 6: MalwareBazaar as the third flag-guarded source (enable after acceptance, one at a time, `--require-malwarebazaar`); acceptance table row. Prior: 2026-10-10 (later) — § [7] step 2/6: flags reach the airflow container only via compose `x-common-env` (added), additive baseline after enabling CISA ICS, `MITRE_FORCE_REFETCH` for ICS. Earlier the same day — § [7]: deploy `main` (`ca9cdae`, Airflow 3.3.2 image rebuild) before the wipe, backup-gate env, DAG pause pointer, hand-back step with the three new relationship types. Prior: 2026-06-12 — added "GraphRAG readiness verification" to § After the run: post-baseline checks for the PR #126 write-side fixes (aliases, KEV markers) + the build_relationships edge types absent from the pre-June snapshot. Prior: 2026-06-11 — PR #125 docs correction: the lock sentinel is NOT written by the baseline DAG (PR-F2 de-scope, Issue #57) — manual pausing is the ONLY mutex on the DAG path, and the pause list now covers all 5 scheduled DAGs (added edgeguard_neo4j_sync); CLI wrappers exist (PR-C) but trigger the same DAG. Prior: 2026-04-28 — PR-N35 Tier-1 + PR-N36 follow-up:_
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
