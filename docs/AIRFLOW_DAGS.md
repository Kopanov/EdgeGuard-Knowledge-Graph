# EdgeGuard Airflow DAGs (operations guide)

**Purpose:** Automated ETL pipeline for threat intelligence collection and synchronization.  
**DAG Python files:** repository `dags/` directory.
**Airflow version:** Apache Airflow 3.3.x — base image `apache/airflow:3.3.2-python3.12` (see [Airflow version and image](#airflow-version-and-image)).

**Where you are in the docs:** Step **2** of the operator path — read after **[SETUP_GUIDE.md](SETUP_GUIDE.md)**. **Next →** **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for a safe first **`edgeguard_baseline`**. Full order: [SETUP_GUIDE.md § Start here](SETUP_GUIDE.md#start-here--then-read-these-next-operator-path).

---

## Airflow version and image

| Item | Value |
|---|---|
| Base image | `apache/airflow:3.3.2-python3.12` (`Dockerfile.airflow`) |
| Custom image tag | `edgeguard-airflow:3.3.2-python3.12` (`docker-compose.yml`) |
| Python packages | `apache-airflow[postgres]~=3.3.2` (3.3.x only; `~=3.3` would admit 3.4) + `apache-airflow-providers-standard~=1.5` (`requirements.txt`, `pyproject.toml`). The image installs `requirements-airflow-docker.txt`, which carries the same `fastapi!=0.136.3` exclusion as the root manifest, because the 3.3.2 base bundles that flagged release |
| Version check | `RECOMMENDED_VERSIONS["airflow"] = "3.3"`, so `edgeguard doctor` reports Airflow `3.3.x` without a drift warning |
| Operators | `airflow.providers.standard.operators.bash.BashOperator`, `airflow.providers.standard.operators.python.PythonOperator` / `ShortCircuitOperator` |
| `Variable`, `TaskGroup` | `airflow.sdk.Variable` and `airflow.sdk.TaskGroup`, each with a `try/except ImportError` fallback; `Variable.get(...)` takes its default positionally (2.x and 3.x both accept it) |
| `TriggerRule` | `airflow.task.trigger_rule.TriggerRule`, with an `ImportError` fallback to `airflow.utils.trigger_rule` (which emits `DeprecatedImportWarning` on 3.3.x); the DAGs load with zero warnings on 3.3.2 |
| Schedule keyword | `DAG(schedule=…)`; Airflow 3.x has no `schedule_interval` |
| API server port | `AIRFLOW__API__PORT` (the port is in the `[api]` section in 3.x); `docker-compose.yml` binds the API server to `127.0.0.1:8082` |
| API server JWT secret | `AIRFLOW__API_AUTH__JWT_SECRET`, read from the `.env` variable `AIRFLOW_API_AUTH_JWT_SECRET` |

`airflow.exceptions.AirflowException`, `from airflow import DAG` and `pendulum` work identically on 2.x and 3.x. EdgeGuard's REST API, NATS and GraphQL do not depend on the Airflow version.

**Why the 3.3 line:** CI scans the image with `trivy image --severity CRITICAL`, and `CVE-2026-33264` in `apache-airflow` (code execution via unsafe serialized-DAG deserialization) is fixed only from 3.3.0. The 3.3.2 constraints ship PyJWT 2.14.0, anyio 4.15.1, the SFTP provider 6.0.1, snowflake-connector 4.7.3 and `apache-airflow-providers-fab` 3.9.0, which allows Flask 3: the image runs **Flask 3.1.3**, which clears CVE-2026-27205. `requirements.txt` lists only `apache-airflow[postgres]` and `apache-airflow-providers-standard`, neither of which pulls the FAB provider. `pip install -r requirements.txt` therefore installs no Flask, and `pip-audit -r requirements.txt` does not see it. The Docker image bundles FAB (and with it Flask), because the upstream `apache/airflow` image ships the FAB auth manager. The API server is bound to loopback only (`127.0.0.1:8082`), so the web attack surface is not reachable from the network on a production host.

**Packages upgraded on top of the base image.** `Dockerfile.airflow` upgrades in place what the `apache/airflow:3.3.2-python3.12` base ships with a CRITICAL advisory that has a fixed release: the Debian packages `openssl`, `libssl3`, `libgnutls30`, `perl` and `libbrotli1`, and, after the requirements install, `pip` (26.2.2 or later), `certifi` (2026.10.19 or later) and `uv` (0.13.4 or later), whose bundled CA stores trusted the emSign roots of GHSA-6q48-6c7w-9gw2 and GHSA-hq85-5cpj-mr62, and `Authlib` (1.9.0 or later, below 2.0, which `flask-appbuilder` requires). It removes the `prek` hook runner, which serves Airflow development only. The tasks' `requests` and PyMISP calls verify TLS against this `certifi` bundle. `requirements.txt`, `requirements-airflow-docker.txt` and `pyproject.toml` also set `certifi>=2026.10.19`, so the `edgeguard-kg` image (REST, GraphQL) and a pip install resolve the fixed bundle as well, and a plain `docker compose build` rebuilds a cached requirements layer that holds an earlier one.

**pandas:** pandas 3 changes how DataFrame XComs are stored (Airflow 3.3.1 release note). The image pins `pandas~=2.2` and no EdgeGuard task stores a DataFrame XCom, so this matters only for a new task that returns a DataFrame.

**JWT secret.** The Airflow 3.x API server fails to start with `The value api_auth/jwt_secret must be set!` when the secret is missing, whatever the auth manager (it signs the `POST /auth/token` and execution-API tokens; this stack uses the Simple auth manager). Generate it once:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Add the output to .env:
#   AIRFLOW_API_AUTH_JWT_SECRET=<value>
```

Keep the value stable across restarts so issued tokens stay valid. `docker-compose.yml` reads it via `${AIRFLOW_API_AUTH_JWT_SECRET:-}` and sets `AIRFLOW__API_AUTH__JWT_SECRET` inside the container. Apply a new value with `docker compose up -d --force-recreate airflow`: a plain `up -d` can reuse a cached container that does not know the variable, and the API server log then shows the error above.

**Process topology:** the `airflow` service runs `airflow standalone`, which runs the scheduler, API server, DAG processor and triggerer as subprocesses and neither restarts nor exits when one of them dies ([Scheduler or triggerer stopped](#scheduler-or-triggerer-stopped)).

---

## Overview

EdgeGuard uses Apache Airflow to orchestrate the automated collection of threat intelligence from multiple sources, pushing to MISP, and syncing to Neo4j.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EdgeGuard Pipeline                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐   │
│  │   Sources    │ -> │     MISP     │ -> │   Neo4j      │ -> │  NATS   │   │
│  │ (feeds — see │    │ (Central Hub)│    │ (Knowledge   │    │ (Alerts)│   │
│  │ DATA_SOURCES)│    │              │    │   Graph)     │    │         │   │
│  └──────────────┘    └──────────────┘    └──────────────┘    └─────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Airflow orchestrates:
  1. External Collectors → MISP (scheduled by source)
  2. MISP → Neo4j sync (periodic)
  3. Alert generation via NATS
```

---

## DAG Structure

EdgeGuard defines **6** primary DAGs in `dags/edgeguard_pipeline.py` (baseline + five scheduled pipelines). **Optional** Prometheus metrics DAGs live in `dags/edgeguard_metrics_server.py`: **`edgeguard_metrics_server`** / **`edgeguard_metrics_server_scheduled`** (blocking metrics HTTP task only) and **`edgeguard_metrics_helpers`** (manual **generate_test_metrics** → **health_check**, run after the server is up). **generate_test_metrics** is for a single-process (bare-metal) metrics server only: with `PROMETHEUS_MULTIPROC_DIR` set (the Compose deployment) it records nothing, because the `metrics` service would serve its fake series as real ones, among them the last successful Neo4j sync that `EdgeGuardNeo4jSyncStale` and `EdgeGuardBuildRelationshipsSilentDeath` read.

### DAGs Overview (edgeguard_pipeline.py)

| DAG Name | Schedule | Purpose | Sources |
|----------|----------|---------|---------|
| `edgeguard_baseline` | Manual | One-time deep historical load | Tiered collectors → full MISP→Neo4j + enrichment |
| `edgeguard_pipeline` | Every 30 min | High-frequency updates | AlienVault OTX |
| `edgeguard_medium_freq` | Every 4 hours | Medium-frequency sources | CISA KEV, VirusTotal |
| `edgeguard_low_freq` | Every 8 hours | Low-frequency sources | NVD |
| `edgeguard_daily` | Daily at 2 AM | Daily feeds | MITRE, CISA ICS Advisories (on by default; `EDGEGUARD_ENABLE_CISA_ICS=false` turns it off), ThreatFox, AbuseIPDB, URLhaus, Feodo, SSLBlacklist, MalwareBazaar (flag-guarded, `EDGEGUARD_ENABLE_MALWAREBAZAAR`) |
| `edgeguard_neo4j_sync` | Every 72 h (`timedelta(days=3)`) | MISP → Neo4j sync + `build_relationships` + `run_enrichment_jobs` | All sources |

**Concurrency and timeout guards (all 6 DAGs):**

| DAG | `max_active_runs` | `dagrun_timeout` | Notes |
|-----|-------------------|------------------|-------|
| `edgeguard_pipeline` | 1 | 5h 30m | Covers OTX with full retry chain |
| `edgeguard_medium_freq` | 1 | 5h | CISA + VT with retries; both take a slot of the shared collector pool, so they run in parallel only while it has a free slot |
| `edgeguard_low_freq` | 1 | 8h 30m | NVD with full retry chain |
| `edgeguard_daily` | 1 | 8h 30m | 8 collectors with retries on the shared collector pool (`EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4); the timeout is sized for all 8 in parallel, and if every attempt reached its 2h `execution_timeout` they would need two rounds (about 12h 45m), so the second round would be skipped; real daily runs take minutes (`collect_malwarebazaar` is a no-op skip while its flag is off, the default, and `collect_cisa_ics` while `EDGEGUARD_ENABLE_CISA_ICS=false`) |
| `edgeguard_baseline` | 1 | 32h | Full historical collection + sync. `tier2_feeds` also runs `collect_cisa_ics` (baseline load of the 24-month advisory history; no-op skip while `EDGEGUARD_ENABLE_CISA_ICS=false`) and `collect_malwarebazaar` (recent export only; no-op skip while `EDGEGUARD_ENABLE_MALWAREBAZAAR` is off) |
| `edgeguard_neo4j_sync` | 1 | 68h | Full sync + relationships + enrichment. Every task of the chain failing on all three attempts takes 55h 57 min (`run_neo4j_sync` 3 × 8h (its default limit, `EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`) + 2 × 5 min, `build_relationships` and `run_enrichment_jobs` 3 × 5h + 2 × 5 min each, the checks 1h 27 min), plus 20% ≈ 67h. A requested full sync stands until it succeeds, so it may use all three attempts; a long run only delays the next scheduled one (`max_active_runs=1`) |

**Collector pool:** every `collect_*` task of every DAG runs in the Airflow pool `edgeguard_collectors` (slots: `EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4), so at most that many collectors run at once across all DAGs; the rest queue. Without it, the 7 baseline tier-2 collectors (or a daily catch-up run plus OTX, VirusTotal and NVD) all start together and exhaust MISP php-fpm workers or the `airflow` container memory limit. The Compose `airflow` service creates/resizes the pool on every start; outside Compose run `airflow pools set edgeguard_collectors 4 "Collector tasks"`, otherwise collector tasks are never scheduled. A new size needs a recreate of the container: see [Collector pool: setup and resizing](#collector-pool-setup-and-resizing).

`max_active_runs=1` prevents run pile-up when a run is slow. `dagrun_timeout` is wall-clock time from DAG run start — if the entire run (including retries) exceeds this, Airflow marks it as failed. These are calculated as worst-case: `execution_timeout x (1 + retries) + retries x retry_delay` summed across the sequential task chain, with a 20% buffer. The formula leaves out the time a collector waits for a slot of the collector pool: that wait counts against `dagrun_timeout` but not against `execution_timeout`, which starts only when the task runs. At the `dagrun_timeout` the scheduler marks every task that has not finished skipped, the collectors still running as well as those still waiting for a slot, and no task failure callback runs for them (no `[ALERT]` log, Slack message or error counter); `EdgeGuardCollectionStale` is the alert that catches it.

**Callbacks:** All DAGs inherit `on_failure_callback` (logs `[ALERT]`, sends Slack if enabled, increments Prometheus error counter) and `on_success_callback` (updates `edgeguard_dag_last_success_timestamp` gauge for stuck-run detection). The DAG run in progress is marked by the Airflow listener plugin `plugins/edgeguard_dag_run_state.py` (mounted as the plugins folder by docker-compose.yml), not by a DAG or task callback: the scheduler's run-started hook sets `edgeguard_dag_run_in_progress_start_timestamp` to the run's start, and the run-succeeded and run-failed hooks set it to 0, when the scheduler ends a run (also at the `dagrun_timeout`) and when a run is marked failed or successful by hand (UI, REST API, `edgeguard dag kill`; Airflow runs no DAG-level callback on that path). `EdgeGuardDAGRunStuck` fires for a run still marked in progress 15 minutes after its `dagrun_timeout`. A run deleted while in progress keeps its mark until the DAG's next run; [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#dag-run-in-progress) gives the command that clears it. `run_neo4j_sync` has its own failure callback, which runs the common one and then alerts when `NEO4J_FULL_SYNC` is still set (see the `edgeguard_neo4j_sync` walkthrough below).

**Baseline note:** `edgeguard_baseline` uses `is_paused_upon_creation=False` so manual triggers execute immediately without needing to unpause first.

#### Collector pool: setup and resizing

The start command of the Compose `airflow` service creates or resizes the pool `edgeguard_collectors` at every start of the container. `./dags` is bind-mounted and re-parsed while Airflow runs, but the start command takes effect only when the container is recreated. While the pool does not exist, the scheduler does not schedule collector tasks (it logs `Tasks using non-existent pool ... will not be scheduled`, and the UI shows a DAG warning about a non-existent pool), and at the `dagrun_timeout` they are marked skipped without a failure alert: collection stops silently until `EdgeGuardCollectionStale` fires. Task instances keep the pool they were created with. Recreating the container kills the tasks that are running, so recreate it only when no `edgeguard_baseline` run is in progress; `./install.sh --update` and `make update` pull, rebuild and recreate in one step.

**Check:** `docker exec edgeguard_airflow airflow pools list` lists `edgeguard_collectors` with the configured slots, and `docker compose logs airflow | grep 'collector pool'` shows `[edgeguard] collector pool edgeguard_collectors set to <n> slots`.

**Resizing.** Set `EDGEGUARD_COLLECTOR_POOL_SLOTS` in `.env` and run `docker compose up -d airflow`, which recreates the container; `docker compose restart airflow` keeps the old environment and so the old size. `airflow pools set edgeguard_collectors <n> "..."` in the container changes the size at once, but the next start of the container sets it back to the `.env` value. A value that is not a positive integer falls back to 4 with a message in `docker compose logs airflow`; while the pool cannot be set (for example before the metadata DB is migrated on a first start), the cause is logged every 30 failed attempts: the last exception line of the CLI output, or else its last line other than SQLAlchemy's "(Background on this error at: ...)" link.

**Without Compose** (the manual venv path in [SETUP_GUIDE.md § 4](SETUP_GUIDE.md#4-path-b--python--venv-no-docker)): run `airflow pools set edgeguard_collectors 4 "Collector tasks of all DAGs"` once after `airflow db migrate` and before the DAGs are unpaused; otherwise the collector tasks are never scheduled.

#### `edgeguard_baseline` task chain — additive vs destructive

The `edgeguard_baseline` DAG has two operational modes determined by
the `dag_run.conf` JSON when triggered:

| Mode | Trigger | Effect | When to use |
|------|---------|--------|-------------|
| **Additive** (default) | `airflow dags trigger edgeguard_baseline` (no conf) OR Airflow UI Trigger DAG with empty conf | `baseline_clean` task is a **no-op**; collectors run on top of existing graph + MISP state | Adding historical depth to an existing baseline; first-time setup on an empty graph |
| **Destructive (fresh-baseline)** | `airflow dags trigger edgeguard_baseline --conf '{"fresh_baseline": true, "baseline_days": 730}'` OR Airflow UI Trigger DAG with config `{"fresh_baseline": true}` | `baseline_clean` task **wipes Neo4j + MISP EdgeGuard events + checkpoints** before collectors run | Schema migration; recovering from a corrupted baseline; clean-slate re-collection |

**Task chain:**
`misp_health_check` → `source_key_check` → `baseline_acquire_lock` → `baseline_clean` (no-op or wipe — gated on `dag_run.conf`) → `baseline_start` → `tier1_core` (TaskGroup) → `tier2_feeds` (TaskGroup) → `full_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `baseline_postcheck` → `baseline_complete` → `baseline_release_lock` (only after a successful run). **There is no `tier3_low_freq` TaskGroup** in the baseline DAG; the daily-tier collectors live in the `edgeguard_daily` *incremental* DAG, not the baseline. **Top-level task IDs do not carry a `baseline_` prefix** — `airflow tasks state edgeguard_baseline full_neo4j_sync <run_id>` is the right shape (NOT `baseline_full_neo4j_sync`).

> **Note:** the four tier-1 collectors inside `tier1_core` run
> **sequentially** (`cisa → mitre → otx → nvd`), not in parallel,
> because concurrent writes from all four exhaust MISP's PHP-FPM workers
> and MISP answers with HTTP 500s, which loses NVD attributes. See
> [AIRFLOW_DAG_DESIGN.md § Tier 1 collectors — sequential](AIRFLOW_DAG_DESIGN.md#tier-1-collectors--sequential)
> for the full rationale + trade-off (~3h longer wall time, halved
> MISP write concurrency). Tier 2 runs as many collectors at once as
> the collector pool has free slots (see
> [Collector pool: setup and resizing](#collector-pool-setup-and-resizing)).

**`baseline_clean` task semantics:**

- Reads `dag_run.conf.fresh_baseline`. Accepts Python `True`, integer `1`, or strings `"true"`/`"True"`/`"1"`/`"yes"`/`"on"` (case- and whitespace-insensitive). Anything else (including the explicit-falsy strings `"false"`/`"0"`) is treated as additive — a typo in the JSON config does NOT trigger destruction.
- Calls `src.baseline_clean.reset_baseline_data(wipe_scope=…)` — atomic 3-step wipe (checkpoints → Neo4j → MISP DELETE) followed by a settle period and a verify-poll until all three datastores read zero. The Neo4j step deletes only EdgeGuard-managed nodes (`clear_edgeguard_managed`) unless `dag_run.conf.wipe_scope` is `"all"` (`clear_all`), so partner data on a shared ResilMesh database is kept by default. The checkpoint step deletes the checkpoint file: the baseline checkpoints, the cursors and the rest of the incremental state, the OTX retry list and the `report_pending` lists of OTX and CISA ICS included. It also sets the retry-list and `report_pending` gauges to empty lists. The MISP step deletes every event whose `info` contains `EdgeGuard`, the `-part<N>` and `-reports` events included, and with them their Event Reports. MISP's own log entries, which hold the report text, stay ([RUNBOOK.md § Report text in MISP's logs](RUNBOOK.md#report-text-in-misps-logs)).
- Has `retries=0` and `trigger_rule=ALL_SUCCESS` — destructive task does NOT auto-retry on failure (would re-execute the wipe), and ONLY runs after `misp_health_check`, `source_key_check` and `baseline_acquire_lock` have succeeded (its direct upstream is `baseline_acquire_lock`).
- **What it logs:** after the wipe, `BASELINE_CLEAN: deleted <N> Neo4j nodes, <M> MISP events, <K> checkpoint entries (<s>s)`: the nodes the Neo4j step deleted (every node under `wipe_scope` `all`, the EdgeGuard-managed ones otherwise), the MISP events it deleted, and the checkpoint entries found before the wipe.
- **Refusals before the wipe:** a typo'd destructive key (see *Unknown keys* below) and, for a fresh baseline, a `wipe_scope` other than `edgeguard` / `all` or the backup-timestamp gate fail the task and wipe nothing. The gate requires `EDGEGUARD_LAST_BACKUP_AT` within `EDGEGUARD_BACKUP_MAX_AGE_HOURS` (default 240 h); it is skipped when Neo4j and MISP are both empty (every probe succeeded), with `backup_check_passed_cli` or with `skip_backup_check`. Such a refusal also releases the baseline lock, so the corrected run is not refused by it: re-trigger with a corrected conf, or clear `baseline_clean` after fixing the environment (it takes the lock again before the wipe).
- **Wipe on a large graph:** the Neo4j step deletes relationships first, in batches of 50,000, then the nodes in batches of 10,000, because a node batch holding hub nodes ran a 2 GB heap out of memory on a 2.7M-relationship graph. Each MISP event delete waits up to **`EDGEGUARD_MISP_DELETE_TIMEOUT_SEC`** (default **900** s, because MISP deletes an event's attributes inside the request); `docker-compose.yml` forwards the setting, and `edgeguard clear misp` and `scripts/clear_misp.py` use the same timeout. The task's `execution_timeout` is **60 minutes**.
- **A failed clean stops the chain:** the collector tasks of `tier1_core` / `tier2_feeds` and `full_neo4j_sync` keep `trigger_rule=ALL_DONE` for per-source resilience, but each refuses to run unless `baseline_start` succeeded in this run; a refusal raises `AirflowFailException`, so the task fails without its retry. The decision uses the task states of the run as Airflow 3 reports them; only where Airflow reports none (Airflow 2, or a failed call) does it fall back to the XCom marker `baseline_start` returns on success. On Airflow 3, `baseline_postcheck` likewise fails when `full_neo4j_sync`, `build_relationships` or `run_enrichment_jobs` did not succeed. See [RUNBOOK.md § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck).
- **The postcheck fails a run whose graph breaks an invariant:** `baseline_postcheck` raises, so `baseline_complete` and `baseline_release_lock` do not run and the baseline lock stays held ([RUNBOOK.md § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck), 7d: recovery per invariant). INV-1: a `Campaign` exists when actors qualify for one. INV-2: an `Indicator` exists. INV-3: a `Source` exists. INV-4: every kill-chain phase whose `Tactic` exists has its `IN_TACTIC`, and every `uses_techniques` claim whose `Technique` exists its `EMPLOYS_TECHNIQUE` (ThreatActor) or `IMPLEMENTS_TECHNIQUE` (Malware, Tool) with `match_type` `mitre_explicit`; on a run with `collection_limit` 0 the claims themselves are judged too (a technique's phases reach a `Tactic`, the MITRE nodes of a label carry claims, a `Technique` exists when `collect_mitre` delivered), while a limited run is judged on the links only. INV-5: when `collect_nvd` delivered in this run, at least half of NVD's non-rejected CVEs (judged from 100) have a CVSS sub-node. INV-6: a collector task that succeeded with a status of `success`, not `skipped`, and a count of N leaves at least 0.9 × N `SOURCED_FROM` edges at its `Source` node, and every source named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES` that has a collector in this DAG (all but `virustotal`) holds a `SOURCED_FROM` edge. INV-4 to INV-6 run the statements of `src/graph_shape_checks.py` that the acceptance script runs, with the task states and returned statuses of this run's collectors (the status of a task that did not succeed in this run is not read: a cleared task keeps its earlier XCom). The task log gives each invariant's numbers and one WARNING table of the collectors that delivered nothing in this run (skipped, with `skip_reason_class`; failed; a task that did not succeed or did not run in this run; or one without a returned status); such a collector fails the run only when `EDGEGUARD_BASELINE_REQUIRED_SOURCES` names its source.
- **The chain checks the baseline lock:** the collectors refuse (`AirflowFailException`) while no baseline holds `checkpoints/baseline_in_progress.lock`, and `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` refuse unless the lock names this DAG run. `baseline_start`, and `baseline_clean` before the wipe, take the lock again for this run, so after a refusal clear `baseline_start` and then the refused task. A refusal of `baseline_clean` before the wipe releases the lock (bullet above). A failed run keeps the lock until it is resumed and succeeds, or until the sentinel reaches the age cap (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`, default 48 h). `python src/edgeguard.py dag kill` releases the lock of a baseline run it kills; to resume that run, clear `baseline_start` (it takes the lock again) and then the remaining tasks. While a baseline holds the lock, the scheduled collectors skip with `skip_reason_class=baseline_in_progress` (a green task) and the tasks of `edgeguard_neo4j_sync` skip (see *Airflow task: `run_neo4j_sync`* below and [RUNBOOK.md](RUNBOOK.md)).

**Baseline DAG conf — accepted keys:**

The baseline DAG accepts the following keys in `dag_run.conf`:

| Key | Type | Effect | Consumed by |
|---|---|---|---|
| `fresh_baseline` | bool / `1` / `"true"` / `"yes"` / `"on"` | Enables destructive wipe before collection. ANY other value = additive. | `baseline_clean` |
| `baseline_days` | int | Historical depth in days. Default 730. | `get_baseline_config` → all collectors |
| `collection_limit` | int | Per-source item cap. `0` = unlimited. | `get_baseline_config` → all collectors |
| `baseline_collection_limit` | int | Alias for `collection_limit` (kept for back-compat). | `get_baseline_config` |
| `clear_checkpoints` | `"all"` | No effect; not an accepted key, so it logs a `[BASELINE_CONF]` unknown-key warning. An additive baseline keeps every checkpoint, and a fresh baseline's `baseline_clean` always clears them, incremental cursors included. | — |
| `backup_check_passed_cli` | bool-ish (same parse as `fresh_baseline`) | Set automatically by `edgeguard fresh-baseline` AFTER its client-side backup gate ran — tells the DAG-side gate not to re-check (the container env may lack `EDGEGUARD_LAST_BACKUP_AT` in the CLI flow). Do not set by hand; use `skip_backup_check` instead. | `_baseline_clean` (backup gate) |
| `skip_backup_check` | bool-ish (same parse as `fresh_baseline`) | Explicit, loudly-logged operator bypass of the backup-timestamp gate for UI/API triggers — mirrors the CLI `--skip-backup-check` flag. Dev/test only; production wipes MUST take a backup first (docs/BACKUP.md). | `_baseline_clean` (backup gate) |
| `wipe_scope` | `"edgeguard"` (default) or `"all"` | Neo4j scope of the destructive step: EdgeGuard-managed nodes only, or every node in the database (CLI flag `--wipe-all`). Shared-database contract. | `_baseline_clean` |

**Unknown keys:** Airflow's conf-passing mechanism ignores unknown keys silently, so the DAG emits a `WARNING [BASELINE_CONF]` log line for each unrecognized key, with a "did you mean?" suggestion for common typos (e.g. `days` → `baseline_days`). Without it, a trigger with `{"days": 730}` (missing the `baseline_` prefix) falls through to defaults — additive mode with the wrong window depth, no visible error. Grep your DAG logs for `[BASELINE_CONF]` to spot misconfigured triggers. Exception: a typo of the destructive key with a truthy value (`fresh`, `destructive`, `wipe`) and no `fresh_baseline` key fails `baseline_clean` before anything is wiped.

**CLI vs DAG equivalence:** the operator commands `edgeguard fresh-baseline --days <N>` and `edgeguard baseline --days <N>` trigger this DAG with the appropriate `dag_run.conf` — they do NOT run a local pipeline. The destructive command (`edgeguard fresh-baseline`) prompts for typed `FRESH-BASELINE` confirmation before triggering; the additive command (`edgeguard baseline`) does not. Both trigger through `docker compose exec airflow airflow dags trigger` when the Compose `airflow` service runs in the current directory, and otherwise through the REST API (`POST /api/v2/dags/edgeguard_baseline/dagRuns` with `{"logical_date": null, "conf": {...}}`, sent once), so they also work on a bare-metal Airflow and inside the `airflow` container. Before triggering, both read the health answer and the queued or running runs of this DAG (on the Compose host, what the REST API does not give is read in the `airflow` container, without API credentials) and refuse while the scheduler or the metadata database is not healthy or a run is queued or running: with `max_active_runs=1` Airflow queues a second trigger, and a queued fresh baseline would wipe the graph the running one built ([CLI.md § Baseline triggers](CLI.md#baseline-triggers)). `python src/run_pipeline.py` runs no baseline ([One baseline path](#one-baseline-path)).

**Metrics (optional):** `edgeguard_metrics_server` (+ `…_scheduled`) and **`edgeguard_metrics_helpers`** in `dags/edgeguard_metrics_server.py` — default scrape URL `http://127.0.0.1:8001/metrics` (`EDGEGUARD_METRICS_HOST` / `EDGEGUARD_METRICS_PORT`).

#### One baseline path

Every baseline, a 7-day smoke run or the 730-day run, additive or fresh, runs through the `edgeguard_baseline` DAG, on an install with Docker and on one without it. An install without Docker runs Airflow with a PostgreSQL metadata database ([SETUP_GUIDE.md § 4](SETUP_GUIDE.md#4-path-b--python--venv-no-docker); SQLite is for development only, see [Troubleshooting](#dag-run-stuck-in-queued-scheduler-running-but-nothing-executes)) and triggers the DAG with `airflow dags trigger edgeguard_baseline`, from the Airflow UI ([BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md), Option B), or with `edgeguard baseline` / `edgeguard fresh-baseline`, which trigger through the Airflow REST API there ([CLI.md § Baseline triggers](CLI.md#baseline-triggers)).

`python src/run_pipeline.py` runs no baseline and writes nothing to Neo4j: it runs the enabled collectors once into MISP, with the incremental limits of the scheduled DAGs. `--baseline`, `--fresh-baseline`, `--baseline-days` and `--stix-flow` make it exit with code 2 before it takes its lock, wipes anything or runs a collector, with directions to the DAG. For development, the modules the DAGs run build the graph from MISP, each on its own ([CLI.md § Pipeline modules run on their own](CLI.md#pipeline-modules-run-on-their-own)).

---

## Source Schedules

**Note:** “Items/Run” figures below are **order-of-magnitude defaults**; effective limits come from `get_effective_limit()` (`EDGEGUARD_INCREMENTAL_LIMIT`, `EDGEGUARD_MAX_ENTRIES`, baseline Airflow Variables).

### By Frequency

#### High Frequency (Every 30 minutes)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| AlienVault OTX | `edgeguard_pipeline` | 30 req/min | ≤ 200 pulses modified after the cursor (`EDGEGUARD_INCREMENTAL_LIMIT`), oldest first, in pages of 100; the overlap's re-reads come on top ([COLLECTORS.md](COLLECTORS.md#scheduled-runs-limit-and-cursor)) |

#### Medium Frequency (Every 4 hours)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| CISA KEV | `edgeguard_medium_freq` | No limit | The whole KEV catalogue, compared with MISP in every run: new entries are added without a cap, and revised entries are edited in place, at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) edits per run, the rest in the next run |
| VirusTotal | `edgeguard_medium_freq` | 4 req/min, 500/day (ledger budget 400/day, 60 per run) | ≤ 60 hash enrichments per run |

#### Low Frequency (Every 8 hours)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| NVD | `edgeguard_low_freq` | 50 req/30sec (with key) | Every CVE modified since the stored cursor (≤2,000 per request): new CVEs added, stored CVEs NVD changed edited in MISP; at most `EDGEGUARD_NVD_MAX_PER_RUN` (5,000) MISP writes per run |

#### Daily (Once per day)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| MITRE ATT&CK | `edgeguard_daily` | No limit | The whole ATT&CK bundle when it changed (ETag, `EDGEGUARD_MITRE_CONDITIONAL_GET`): every technique, group, software and tactic in it; nothing when it is unchanged (`EDGEGUARD_MAX_ENTRIES` caps it when set) |
| CISA ICS Advisories (`collect_cisa_ics`) | `edgeguard_daily` | Polite: ≤ 4 req/s, ≤ `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1200) files | Advisories changed since the cursor (`changes.csv`); **task is skipped with success when `EDGEGUARD_ENABLE_CISA_ICS=false`** |
| ThreatFox | `edgeguard_daily` | No limit | The IOCs of the last 7 days (about 7,400), at most `EDGEGUARD_THREATFOX_MAX_PER_RUN` (10,000), the newest kept when the cap is reached |
| AbuseIPDB | `edgeguard_daily` | At most one blacklist request per run, none when the run reuses the answer fetched earlier on the same UTC day (free plan: at most 10,000 addresses per request, 5 blacklist requests per UTC day) | The blacklist, at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses, the request's `limit` |
| URLhaus | `edgeguard_daily` | One export download per run (about 16 MB) | The URLs of the `recent.csv` export (about 63,000 on 2026-10-24), at most `EDGEGUARD_URLHAUS_MAX_PER_RUN` (100,000), the newest kept when the cap is reached; skipped without `THREATFOX_API_KEY` |
| Feodo Tracker | `edgeguard_daily` | No limit | The servers of the 30-day list (5 on 2026-10-12; the complete history on a baseline), at most `EDGEGUARD_FEODO_MAX_PER_RUN` (15,000), those seen online most recently kept when the cap is reached |
| SSL Blacklist | `edgeguard_daily` | No limit | The whole blacklist (10,964 certificates on 2026-10-12), at most `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000), the newest by `Listingdate` kept when the cap is reached |
| MalwareBazaar (`collect_malwarebazaar`) | `edgeguard_daily` | One export download per run (about 450 KB) | Up to `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500) sha256 hashes of the last 48 hours, labelled samples first; **task is skipped with success unless `EDGEGUARD_ENABLE_MALWAREBAZAAR=true`**, and without `THREATFOX_API_KEY` |

---

## All Collectors

### Working Collectors (Pushing to MISP)

| Collector | Class | Source File | Zone Detection |
|-----------|-------|-------------|----------------|
| AlienVault OTX | `OTXCollector` | `otx_collector.py` | Keyword-based |
| NVD | `NVDCollector` | `nvd_collector.py` | `detect_zones_from_item()` + CVE description + flattened CPE criteria (`configurations_to_zone_text`) |
| CISA KEV | `CISACollector` | `cisa_collector.py` | Keyword-based |
| MITRE ATT&CK | `MITRECollector` | `mitre_collector.py` | N/A (TTPs) |
| VirusTotal | `VTCollector` | `vt_collector.py` | Scheduled on `edgeguard_medium_freq` (`virustotal_collector.py` / `VirusTotalCollector` exists for optional enrichment — not on a default DAG) |
| AbuseIPDB | `AbuseIPDBCollector` | `abuseipdb_collector.py` | Confidence-based |
| ThreatFox | `ThreatFoxCollector` | `global_feed_collector.py` | Malware family |
| URLhaus | `URLhausCollector` | `global_feed_collector.py` | Tags |
| Feodo | `FeodoCollector` | `finance_feed_collector.py` | Hardcoded Finance |
| SSL Blacklist | `SSLBlacklistCollector` | `finance_feed_collector.py` | Malware family |
| CISA ICS Advisories | `CISAICSCollector` | `cisa_ics_collector.py` | Source-asserted CISA sector → fixed table (Energy / Healthcare and Public Health / Financial Services); **on by default**: with `EDGEGUARD_ENABLE_CISA_ICS=false`, `run_cisa_ics_collection` logs "disabled by flag" and returns a skipped status (success, 0 items) |
| MalwareBazaar | `MalwareBazaarCollector` | `global_feed_collector.py` | Malware family label (`signature`); **flag-guarded**: `run_malwarebazaar_collection` / `run_baseline_malwarebazaar` log "disabled by flag" and return a skipped status (success, 0 items) unless `EDGEGUARD_ENABLE_MALWAREBAZAAR=true` |

### Placeholder Collectors (Not Yet Active)

| Collector | Source File | Notes |
|-----------|-------------|-------|
| Energy | `energy_feed_collector.py` | Placeholder; member-only feeds (EE-ISAC) not planned, no membership budgeted |
| Healthcare | `healthcare_feed_collector.py` | Placeholder; member-only feeds (Health-ISAC) not planned, no membership budgeted; HC3, a public US HHS source, is not collected |

---

## MISP Tagging

### Event level (new events from `MISPWriter`)

| Tag | Role |
|-----|------|
| **`EdgeGuard`** | Platform provenance (e.g. ResilMesh / EdgeGuard pipeline). **Only** event-level tag added on create. |

**`Event.info`** uses **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`), continued in `-part2`, `-part3`, ... once the event holds `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` attributes (not for OTX). Zone classification lives on attribute-level tags (`zone:Finance`, `zone:Healthcare`), not in the event name. A single event can contain multi-zone attributes. See [MISP_SOURCES.md](MISP_SOURCES.md).

### Attribute level (all pushed indicators/objects)

**Source tags** (per attribute):

| Source | MISP Tag |
|--------|----------|
| AlienVault OTX | `source:AlienVault-OTX` |
| NVD | `source:NVD` |
| CISA KEV | `source:CISA-KEV` |
| MITRE ATT&CK | `source:MITRE-ATT&CK` |
| VirusTotal | `source:VirusTotal` |
| AbuseIPDB | `source:AbuseIPDB` |
| ThreatFox | `source:ThreatFox` |
| URLhaus | `source:URLhaus` |
| Feodo Tracker | `source:Feodo-Tracker` |
| SSL Blacklist | `source:SSL-Blacklist` |
| MalwareBazaar | `source:MalwareBazaar` |

**Zone tags** (per attribute — source of truth for classification): `zone:Global`, `zone:Healthcare`, `zone:Energy`, `zone:Finance` (capitalization as written by `MISPWriter`), plus confidence tags. **`MISPWriter._get_zones_to_tag`** drops redundant `global` when any specific zone is present.

---

## Neo4j Sync

### Schedule
- **Frequency:** every 72 hours, a fixed interval (`schedule=timedelta(days=3)`, `NEO4J_SYNC_EVERY` in `dags/edgeguard_pipeline.py`). On Airflow 3 this is a DeltaTriggerTimetable (`[scheduler] create_delta_data_intervals` False, the default): a run is due 72 h after the logical date of the previous scheduled run, its data interval is that instant (`data_interval_end`), and manual runs do not move the schedule. With `catchup=False`, a run that fell due while the DAG was paused or Airflow was down starts once when it resumes, and the 72 h count from there.
- **Skip guard:** `check_sync_needed` skips a run when the last successful sync started less than **24 h** ago (`NEO4J_SYNC_MIN_GAP`). It exists for the run right after another sync — the baseline's `full_neo4j_sync` or a manual `force_sync` run, which stamp the state file. Of what that sync read, such a run re-reads only the attributes MISP stamped in the window overlap before its start (`EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h; step 2 of *Airflow task: `run_neo4j_sync`* below), but it would also repeat `build_relationships` and the enrichment jobs on the graph just built, which is why the guard exists. 24 h is longer than the rest of a baseline after its full sync starts (16 h 49 min with every task at its limit, the lock held to the end) and shorter than the shortest gap a regular run sees (72 h minus 16 h 42 min, the latest the previous sync can start: two failed 8 h attempts at the default limit of `EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`, two retry delays and the attempts of the two tasks before it; at the 22 h cap of that limit 27 h 18 min remain), so a regular run is never skipped, also after a sync that succeeded on a retry. The first scheduled sync after a baseline or a forced sync starts between 24 h and 96 h after it. The interval and the guard are fixed in `dags/edgeguard_pipeline.py`.
- **Process:** MISP → Neo4j using MERGE (upsert)
- **Monitoring:** `EdgeGuardNeo4jSyncStale` fires when no sync, scheduled or baseline, has completed in 122 h at the default limit (the longest gap between two sync starts, 96 h after a baseline's or a forced sync, plus the next sync's longest run: 32 min of `check_sync_needed` / `neo4j_health_check` attempts and three attempts of `run_neo4j_sync`'s default 8 h limit, `EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`, with two retry delays; 120 h 42 min, plus about an hour for the scheduler). The threshold follows the limit: `run_neo4j_sync` records its `execution_timeout` in `edgeguard_neo4j_sync_task_limit_seconds` when an attempt starts, and each hour above 8 adds 3 h ([RUNBOOK.md](RUNBOOK.md)); `edgeguard_last_success_timestamp{source="misp_to_neo4j"}`, stamped when a sync connects, is watched with 98 h by `EdgeGuardCollectionStale` (96 h plus the 32 min, with margin). `tests/test_monitoring_signals.py` simulates the schedule through the real guard and derives both from the tasks' limits. See [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md).

### Shared state directories

`./state` (sync state file) and `./checkpoints` (collector checkpoints, baseline lock sentinel) are bind-mounted into the Airflow container at `/opt/airflow/state` and `/opt/airflow/checkpoints`. The `airflow-init` service creates them owned by the container user (uid 50000) before Airflow starts. The host CLI (`edgeguard doctor`, `monitor`, `stats`, `checkpoint status`) therefore reads what the DAGs wrote; host-side writes or deletes (`edgeguard checkpoint clear`) go through `docker compose exec airflow …` unless the host user owns the directories.

### Airflow task: `run_neo4j_sync` (`edgeguard_neo4j_sync` DAG)

1. **`check_sync_needed`** (`ShortCircuitOperator`) — if the last successful sync (state file `state/edgeguard_last_neo4j_sync.json` under `EDGEGUARD_STATE_DIR`; `./state` is bind-mounted into the Airflow container, so the host CLI reads the same file) started less than **24 h** ago (`NEO4J_SYNC_MIN_GAP`; see *Skip guard* above), it **short-circuits** and **skips** `run_neo4j_sync` and **all downstream tasks** (`build_relationships`, `run_enrichment_jobs`, …). So a “green” DAG run can mean **sync did not run** (skipped); with the 72 h schedule that happens only after a baseline's or a forced sync. The state file holds the start time of the last successful sync, not its completion time (step 2). A manual trigger with **`dag_run.conf={"force_sync": true}`** (`airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`) bypasses this check and the `SKIP_NEXT_NEO4J_SYNC` flag. `check_sync_needed` also skips while a baseline holds the baseline lock, and `force_sync` does not bypass that. `run_neo4j_sync` (each attempt), `build_relationships` and `run_enrichment_jobs` check the lock again when they start and skip while a baseline holds it, because a baseline may take the lock after `check_sync_needed` ran. Such a skip stamps no state file and leaves `NEO4J_FULL_SYNC` and `SKIP_NEXT_NEO4J_SYNC` set, and the downstream tasks skip with it.
2. **`run_neo4j_sync`** — imports **`MISPToNeo4jSync`**, chooses **full** vs **incremental** sync (first-ever run or Airflow Variable **`NEO4J_FULL_SYNC=true`** → full; otherwise incremental). The incremental window is **derived from the state file** (`last_sync` − `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h, an overlap for clock skew and in-flight writes), so it covers everything since the last successful sync even across skipped runs, paused DAGs, or an Airflow outage; if the state file is unreadable it falls back to the fixed `EDGEGUARD_SYNC_INTERVAL_DAYS`+1d window. MISP stamps attribute timestamps itself, and the 1 h default holds because the collectors and the sync use the same MISP (one `MISP_URL`) and the Airflow and MISP hosts keep their clocks synchronised (NTP). A sync that reads a MISP filled by MISP-to-MISP synchronisation or import keeps the origin's timestamps and needs an overlap above the copy delay: an attribute that arrives later than the overlap falls before every later window and is never synced, while the run still succeeds. A clock difference between the two hosts larger than the overlap skips attributes the same way. An overlap from 0 up to 60 s is raised to 60 s with a warning (MISP timestamps are whole seconds); a non-numeric or negative value, or one above 720 h, logs a warning and uses the default, so a bad setting never fails the run. Calls **`sync.run()`**, then on success stamps the state file with the sync **start** time (not its completion time) and updates metrics. The task log states the mode, the reason, the attempt number and the limit in force for the attempt at the start (`Sync mode: FULL — … (attempt N), task limit H h` / `Sync mode: incremental — …`). **`NEO4J_FULL_SYNC` is cleared only after the full sync succeeded**, so every retry (`retries=2`) of a requested full sync runs in full: a failed or timed-out attempt never retries as an incremental run that stamps the state file and leaves the requested repair incomplete. If clearing the Variable fails after a successful sync, a warning is logged and the next scheduled run is a full sync again. The task's `execution_timeout` is **8h** by default (`EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS`, whole hours, at most 22; a remote Neo4j with many changed events can need more, and the 68h `dagrun_timeout` above is sized for the default): a full sync of a 730-day MISP has to fit the 6h limit of the baseline DAG's `full_neo4j_sync` (the sync writes CVEs in batches; the sync's `Duration:` line gives the duration of each run), and the default is that limit plus a third, because a limit at the duration of a full sync could fail every attempt of a request that stands until it succeeds. While `NEO4J_FULL_SYNC` stays set, no incremental sync runs; after the last failed attempt the task's failure callback (`_on_neo4j_sync_failure`, after the common `_on_task_failure`) logs an `[ALERT]` at ERROR saying so and how to clear the Variable, sends it to Slack when enabled and counts `edgeguard_pipeline_errors_total{error_type="full_sync_request_pending"}`, which the Prometheus alert `EdgeGuardNeo4jFullSyncRequestPending` reads ([RUNBOOK.md](RUNBOOK.md)). A manual `force_sync` run is incremental unless `NEO4J_FULL_SYNC` is set, and a first run (no state file) stays a full sync on retry because the state file is written only on success. The baseline DAG's `full_neo4j_sync` stamps the same file with its start time, so the first scheduled sync after a baseline is incremental from that point (minus the overlap).
   - **Incremental runs write only changed attributes:** the event index keeps every event *modified* in the window, but only attributes whose MISP `timestamp` is inside the window are written (log line `Event N: X of Y attributes changed since …`). Unchanged items of the same OTX pulse join only the report-scoped link build; finding them parses the event's unchanged attributes (CPU only, no Neo4j writes). With the 1 h overlap, the first incremental sync after a baseline re-merges only what the baseline wrote in its last hour. An edit that changes only event-level tags is not picked up incrementally, and an incremental run does not repair a Neo4j restored from a dump older than MISP — use `NEO4J_FULL_SYNC=true` for both. `EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` switches to whole-event processing. A full sync does not set `SKIP_NEXT_NEO4J_SYNC`; an operator-set flag skips the next incremental run once.
   - **OOM on very large attribute sets:** `sync_to_neo4j()` merges in **Python-side chunks** (default **500** items per chunk; no pause between chunks unless `EDGEGUARD_QUERY_PAUSE_SECONDS` is set). Events with **>5000 attributes** are automatically **streamed in pages** of 5000 with `gc.collect()` between pages. Set **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** lower on the Airflow worker if the process is still killed. Default **`AIRFLOW_MEMORY_LIMIT`** is **12g**, sized for events of 100K+ attributes: the sync holds an event's attribute list in memory, fetched whole up to `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` attributes (default 20000) and above it as `/attributes/restSearch` pages of 5000 joined into one list, so the streamed pages of 5000 (with `gc.collect()` between them) bound the parsed items, not the attribute list.
   - **MISP push accounting (collector tasks):** after each batch POST the writer reconciles the pushed attributes against the attribute list MISP returns for the event. Attributes absent from the response are logged (`[UNCONFIRMED]`) and counted in the writer stats (`attributes_unconfirmed`); a response without an attribute list marks the batch `batches_unverified`. With **`EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING=true`** (forwarded by `docker-compose.yml`) unconfirmed attributes also count as failed pushes and feed **`EDGEGUARD_MISP_MIN_SUCCESS_RATE`**; enable it after a live check shows no spurious unconfirmed attributes, because MISP normalises some values on save. A batch MISP answers with HTTP 5xx is looked up in the event by value before it is retried: MISP saves a batch before it builds its answer, which lists the whole event, and an event too large for its PHP `memory_limit` fails there (with 2048M, an OTX event past about 148,800 attributes: the OTX event of the 730-day baseline of 2026-11-01, which the event split leaves whole). A batch MISP holds in full counts as pushed and is not sent again (WARNING `[STORED-AFTER-5XX]`, writer stat `batches_stored_after_5xx`, a note on the push summary line); of a batch whose retries all fail, only the attributes MISP does not hold count as failed ([MISP_TUNING.md § Event size](MISP_TUNING.md#event-size)). The comparison ignores surrounding whitespace, and case only for the types whose case MISP changes on save (hashes, domains, host names, e-mail and IP addresses, CVE ids, ...: `_CASE_NORMALISED_TYPES` in `src/collectors/misp_writer.py`); any other value (text, malware and threat-actor names, URLs, file names, registry keys) the event holds only in another case is unconfirmed. MISP answers a batch with HTTP 200 while dropping attributes that fail its validation, so the writer avoids the known causes: a generic `hash` is typed `md5` / `sha1` / `sha256` / `sha512` by the length of its hex digest, characters outside the Basic Multilingual Plane (4-byte UTF-8, which MISP's 3-byte `utf8` columns reject for the whole batch with HTTP 500) are stripped from comments and tag names, and an attribute whose value needs them is skipped with a warning and counted as failed. See [COLLECTORS.md](COLLECTORS.md) § *MISP push: attribute types and characters*. Items no MISP attribute can be built from (an unknown item type, an empty value, CVE id, name or ATT&CK id) are reported by one `[CONVERT] N item(s) could not be converted to a MISP attribute, M of them counted as failed (…): <source>: <dropped> of <given> item(s), [not ]counted as failed (<count> <reason>, …); …` line per push (a WARNING, an ERROR when some count as failed) and the writer stats `items_not_converted` and `items_not_converted_failed`. They count as failed pushes only when the drop is systemic for the source in that push: all of its items, or at least half of them (`CONVERT_FAILED_MIN_SHARE` = 0.5 in `src/collectors/misp_writer.py`, where the value is justified). A source whose payload stops converting therefore fails its task, and the error names both causes (`… failures are attributes MISP did not store and, for a source all or at least half of whose items no MISP attribute could be built from, those items, logged by the writer as [CONVERT]`), while a few bad records neither turn a run red nor hold a cursor: the CISA ICS and NVD-baseline cursors and the MITRE ATT&CK ETag move only after a push without failures, and OTX, after a push with failures, advances its cursor and puts the pulses with an item the writer lists as unstored (a failed batch, or a systemic conversion drop) on its retry list, which later runs fetch by id and push in batches of their own; only a push whose listed items all failed at their MISP event (its lookup or creation) holds its cursor below them ([COLLECTORS.md § Scheduled runs: the retry list](COLLECTORS.md#scheduled-runs-the-retry-list)). A (source, date) group without attributes, or one MISP already holds entirely by a complete cross-event listing, neither looks up nor creates the day's event (`MISP push <source> (<date>): all N attributes already present under <tag> … no event looked up or created`); see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*.
   - **Empty or implausibly small windows:** a window with **fewer than `EDGEGUARD_SYNC_MIN_EVENTS`** events (default **`1`**; forwarded to the `airflow` service by `docker-compose.yml`, documented in `.env.example`) is a **failed** run: the sync logs an **ERROR**, records no success, processes nothing and `run_neo4j_sync` fails, so the state file is not stamped and the next run covers the window again. Scheduled syncs are at least 24 h apart and the collectors write to MISP every day (OTX every 30 minutes), so an empty window means nothing was collected; a sync forced minutes after another can also find none. **`0`** disables the guard: a zero-event window is then logged as a **WARNING**, recorded in the sync stats (`zero_events`, `events_index_total`) and reported as a successful run.
   - **Metrics after a successful sync:** the duration is observed once, `edgeguard_neo4j_sync_last_success_timestamp` is stamped, and the node count of every label EdgeGuard writes is read with one read-only query and set as `edgeguard_neo4j_nodes{label, zone="all"}`; a label without nodes is recorded as 0. A failed count logs a warning and keeps the previous values. `run_enrichment_jobs` reads the counts again after a successful enrichment (the Campaign nodes it creates). The baseline DAG's `full_neo4j_sync` records the duration and the stamp; the baseline's node counts are read at the end of a successful `run_enrichment_jobs` (baseline), because before the enrichment a fresh baseline has no Campaign nodes and a 0 would fire `EdgeGuardNeo4jLabelDropBig`.
   - **Partial loss is a failure:** `sync.run()` returns `False` (and `run_neo4j_sync` fails, with the reason in the task log) when any event could not be fetched or processed after retries (`events_failed`), when an item merge failed, or when relationship rows were dropped by permanent Neo4j batch failures (`relationships_failed`; grep **`[BATCH-PERMANENT-FAILURE]`** / **`[REL-ROWS-FAILED]`**). The same holds for an incomplete MISP event listing: a page of `/events/index` after the first that fails (a timeout or a dropped connection after the retries, with the `requests` error; any other failure with `_MispFallbackHardError`), a fallback `restSearch` page that is not JSON or fails with a request error that is not transient, any other error while listing (`_MispFallbackHardError`), and a listing that stopped at the page cap (`EDGEGUARD_MISP_MAX_PAGES` × `EDGEGUARD_MISP_PAGE_SIZE`, reason containing `MISP event index stopped at the page cap`). The run then does not stamp the state file past events it never listed. A green `run_neo4j_sync` therefore means that nothing in the window was lost, apart from what the run summary counts without failing the run: items no merge path accepts (`[ITEM-UNROUTABLE]`), ATT&CK values without a valid ATT&CK id (`[ATTACK-VALUE]`), and an event fetched in pages (more than `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` attributes, or after its whole-event fetch kept answering HTTP 5xx) whose pages bring fewer attribute rows than the MISP index lists. Such an event is synced with the rows received and counts as processed; it is logged as `[PAGED-FETCH-INCOMPLETE]`, counted in the run summary (`Events fetched in pages with fewer attributes than the MISP index lists: N`) and in the gauge `edgeguard_sync_events_paged_incomplete`, which the warning alert `EdgeGuardSyncPagedFetchIncomplete` reads, and the run does not fail for it, because MISP itself can leave rows out (an Allowedlist entry or a default search filter of the sync account) or the event can change after the index was read ([RUNBOOK.md](RUNBOOK.md) § *Large MISP events fetched in pages*).
   - **Event listing on a MISP that ignores paging:** MISP 2.5.45 reads `limit` and `page` of `GET /events/index` only from named parameters (`/limit:500/page:2`) or a request body, so it answers the query-string request with the whole listing on every page; it narrows by time only with a named `searchtimestamp:` or a request-body `timestamp`, and ignores the query-string `timestamp` as well as a named `timestamp:` (measured on the hosted MISP). The sync lists each event once: it de-duplicates rows by event id and stops at the first page that holds more rows than `limit` or brings no new event id. Without this, from 500 MISP events every page would repeat the listing up to the 100-page cap: each event in the window would be processed 100 times, very likely past the task's 8 h limit, and the state file would never be stamped. The query-string `timestamp` narrows nothing on that MISP; the window is applied client-side (`timestamp` / `date` of each row).
3. **Downstream** — `build_relationships` materializes cross-node edges (e.g. **`EMPLOYS_TECHNIQUE`** ThreatActor→Technique and **`IMPLEMENTS_TECHNIQUE`** Malware/Tool→Technique from MITRE **`uses_techniques`**; **`INDICATES`** from the indicator's source-asserted family label and from the families its OTX pulse named, …; whole-event co-occurrence is not used); `run_enrichment_jobs` runs decay/campaign/bridge jobs. Both can succeed with little effect if the sync wrote no nodes.
   - **Indicator aging time:** `run_neo4j_sync` (the Indicators it writes) and `run_enrichment_jobs` (the aging job, `decay_ioc_confidence`) evaluate the aging at the database's current time, lifted to a node's `aging_evaluated_at` (the time at which its aging values were last written) when that is later; no task passes a time of the run, and the baseline DAG's `full_neo4j_sync` and `run_enrichment_jobs` do the same. Real time only moves forward, so clearing an older run's failed `run_enrichment_jobs` (or its sync) after a newer run aged the graph, or a baseline overlapping a scheduled sync, evaluates at the time it runs and moves no node backwards (no retired indicator active again, no lower tier, no `aging_since` or STIX `modified` moved back); the lift covers a database clock set back and an overlapping transaction that stored a later time on the node (a write, or a job run that changed it), and the job locks each node it changes before it reads it. A write whose statement started before an aging job that changed nothing on the node, and which commits a newer report after it, evaluates that report at its statement's start, earlier than the job's time, until the next write or job ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md#indicator-aging), *When it is applied*).

MISP search/index responses are normalized in code (see **`normalize_misp_event_index_payload`** in [`run_misp_to_neo4j.py`](../src/run_misp_to_neo4j.py)): each row must become a **flat** event dict with **`id`**, not only `{'Event': {...}}`.

### Node Types
| Node Label | Count (approx) | Key Properties |
|------------|----------------|----------------|
| Indicator | ~8,000 | value, type, source, zone |
| Vulnerability | ~500 | cve_id, severity, cvss_score |
| ThreatActor | ~100 | name, aliases, description |
| Technique | ~300 | mitre_id, name, description |
| Malware | ~100 | name, family, type |
| Source | 16, one per registered source, keyed by its canonical id; a variant is a lookup key, never a node ([KNOWLEDGE_GRAPH.md](KNOWLEDGE_GRAPH.md), "Source nodes") | source_id, name, type, reliability |

### Deduplication
Neo4j uses UNIQUE constraints on the **natural key** per node label —
source / provenance lives on the `SOURCED_FROM` edge, NOT in the node key.
This is the source-truthful architecture: a CVE reported by both
NVD and MISP merges to ONE `Vulnerability` node, with separate edges
carrying per-source attribution + `source_reported_first_at` timestamps.

Constraints (from `Neo4jClient.create_constraints` in `src/neo4j_client.py`):

| Label | UNIQUE on |
|---|---|
| `Indicator` | `(indicator_type, value)` |
| `Vulnerability` / `CVE` / `CVSSv2` / `CVSSv30` / `CVSSv31` / `CVSSv40` | `cve_id` |
| `Malware` / `ThreatActor` / `Campaign` | `name` |
| `Technique` / `Tactic` / `Tool` | `mitre_id` |
| `Sector` | `name` |
| `Source` | `source_id` |
| `IP` | `address` |
| `Host` | `hostname` |
| `Subnet` | `range` |
| `Alert` | `alert_id` |
| `ThreatReport` / `VulnerabilityAdvisory` | `record_ref` (created ahead of the sync that writes these nodes) |

Device, NetworkService, SoftwareVersion, Application, Role and User carry **no** UNIQUE constraint, because their keys recur in ResilMesh's own data.

**Running again does NOT create duplicates** — MERGE on the natural key updates existing nodes, attaches a new `SOURCED_FROM` edge when a new source reports the same entity.

**MISP vs Neo4j:** The graph deduplication above is **independent** of MISP. The same logical IOC may still appear on **more than one** EdgeGuard MISP event (e.g., different dates); **`MISPWriter`** prefetch + cross-event-source dedup reduce **re-pushes** to MISP itself — see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*. `MISPWriter` continues a source/date event in `-part2`, `-part3`, ... past `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` (default 20000) attributes; OTX events are not split ([COLLECTION_AND_SYNC_LIMITS.md § MISP event parts](COLLECTION_AND_SYNC_LIMITS.md#misp-event-parts)).

---

## Features

### Built-in Features
- Circuit breaker for failed collectors
- Prometheus metrics export (via dedicated `edgeguard_metrics_server` DAG on port 8001)
- Slack alerts (optional)
- MISP **preflight** task (`misp_health_check` — fast `PythonOperator`, API+DB gate; see troubleshooting)
- Container health verification
- Rate limit awareness (each source group has its own DAG schedule)
- Incremental sync support
- Error handling and retry logic (`retries=2`, `retry_delay=5min`; baseline DAG default: `retries=1`).
  The four baseline critical-chain tasks
  — `baseline_clean`, `full_neo4j_sync`, `build_relationships`,
  `run_enrichment_jobs` (top-level task IDs in the baseline DAG; **no
  `baseline_` prefix**) — override to **`retries=0`**; the baseline's
  `source_key_check` has `retries=0` as well. A single retry on
  any 5–6h task would burn 12h of the 32h `dagrun_timeout` cap and could leave
  the graph in a partially-mutated state mid-enrichment. With `retries=0` a
  failure surfaces immediately to the operator (and to the
  `EdgeGuardMispFetchFallbackHardError` alert) instead of silently
  re-running for 6 more hours. See the `baseline_clean_task`,
  `baseline_full_sync_task`, `baseline_build_rels_task`,
  `baseline_enrichment_task` and `baseline_source_keys` definitions in
  `dags/edgeguard_pipeline.py` (search `retries=0`) for the sites and the
  comments that explain them.
- Execution timeouts on all tasks (prevents hung workers)
- `dagrun_timeout` on the baseline and the five scheduled DAGs (prevents entire DAG runs from hanging indefinitely); the metrics DAGs of `dags/edgeguard_metrics_server.py` have none
- `max_active_runs=1` on the baseline, the five scheduled DAGs and the two metrics-server DAGs (prevents concurrent run pile-up)
- `on_failure_callback` / `on_success_callback` for alerting and metrics; the listener plugin `plugins/edgeguard_dag_run_state.py` marks the DAG run in progress
- `ShortCircuitOperator` gates the Neo4j sync: it skips while a baseline holds the baseline lock or within 24 h of the last sync start, and runs on a corrupted state file
- Pipeline lock file (`checkpoints/pipeline.lock`) for CLI runs to prevent concurrent `run_pipeline.py` invocations
- A fresh baseline (`"fresh_baseline": true` in the run configuration; `edgeguard fresh-baseline`) performs a true clean slate in `baseline_clean`: clears Neo4j graph data + MISP EdgeGuard events + checkpoints, incremental cursors included (`reset_baseline_data`), then re-collects from scratch. After it, a baseline whose NVD push succeeded stores its start as the NVD incremental cursor; the other scheduled collectors start from their first-run lookback (for example `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` for OTX).
- MISP dedup logging: `[DEDUP] All N items were already present` only when nothing failed and no item was dropped in conversion, N being the attributes found present, `[CONVERT]` for items no attribute could be built from (counted as failed only when they are all or at least half of a source's items in the push), `[SKIP]` when nothing new to push, `[CASE-VARIANT]` (WARNING) for attributes of a push not pushed because they differ from an earlier attribute of the push only in surrounding whitespace or, for the types whose case MISP changes on save, in case ([COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*)

### Metrics Exported

A selection; the full list is in [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#available-metrics).

```
edgeguard_indicators_collected_total{source, zone, status}
edgeguard_neo4j_sync_duration_seconds
edgeguard_dag_runs_total{dag_id, status, run_type}
```

---

## Running DAGs

### Manual Run
```bash
# Start Airflow 3.x (from the compose stack — the canonical path)
docker compose up -d airflow
# The airflow service runs ``airflow standalone`` internally (scheduler +
# api-server + dag-processor + triggerer in one container, each in its own
# subprocess). The API lives
# on the port set by ``AIRFLOW__API__PORT`` (default 8082 in this repo to
# avoid the ResilMesh Temporal collision — see docker-compose.yml).
# Airflow 3.x has no ``webserver`` subcommand; ``api-server`` /
# ``standalone`` serve the UI and the API.

# Trigger specific DAG (via CLI, inside the container)
docker compose exec airflow airflow dags trigger edgeguard_pipeline
docker compose exec airflow airflow dags trigger edgeguard_daily

# Or via the operator-facing CLI (wrappers that trigger the DAG with the right conf):
edgeguard baseline --days 730           # additive baseline
edgeguard fresh-baseline --days 730     # destructive (typed confirmation + backup gate)
```

### Check Status
```bash
# List all DAGs
airflow dags list | grep edgeguard

# Show DAG tasks
airflow tasks list edgeguard_pipeline

# Show DAG runs
airflow dags list-runs edgeguard_pipeline
```

### EdgeGuard CLI (recommended — wraps Airflow REST API)

```bash
# See all DAG run states (color-coded)
python src/edgeguard.py dag status

# See only running/queued runs
python src/edgeguard.py dag status --state running

# Force-fail stuck DAG runs (preserves checkpoints + incremental state)
python src/edgeguard.py dag kill

# Kill a specific DAG only
python src/edgeguard.py dag kill --dag-id edgeguard_baseline

# Check data counts (by zone, by source, MISP breakdown)
python src/edgeguard.py stats --full

# Check baseline checkpoint progress
python src/edgeguard.py checkpoint status

# Pre-run readiness check (env vars, APIs, Neo4j, MISP, Airflow, disk)
python src/edgeguard.py preflight
```

### View Logs

Airflow UI → the task instance → Logs, or the file
`$AIRFLOW_HOME/logs/dag_id=<dag>/run_id=<run>/task_id=<task>/attempt=<n>.log`
(`/opt/airflow/logs/…` in the `airflow` container).

### Troubleshooting

| Problem | Solution |
|---------|----------|
| DAG runs stuck in "queued" | Run `edgeguard dag status`. When it reports the scheduler as not healthy, recover Airflow and keep the runs ([Scheduler or triggerer stopped](#scheduler-or-triggerer-stopped)). Otherwise check whether the DAG is paused, and only then consider killing stuck runs with `edgeguard dag kill` |
| Collectors failing repeatedly | Find the cause in the task log and `edgeguard_collection_failures_total`, fix it and clear the failed task; each Airflow task starts with every circuit breaker CLOSED ([RESILIENCE_CONFIG.md](RESILIENCE_CONFIG.md)), and `edgeguard heal` resets only the breakers of its own CLI process |
| Need a completely fresh start | `edgeguard fresh-baseline --days N` — refuses while the scheduler is not healthy or an `edgeguard_baseline` run is queued or running, enforces the backup-timestamp gate + requires typed `FRESH-BASELINE` confirmation; without a Compose `airflow` service it triggers through the REST API. See [`docs/BACKUP.md`](BACKUP.md) for the backup prerequisite. With `airflow dags trigger edgeguard_baseline --conf '{"fresh_baseline": true}'` in the Airflow environment instead, the gate runs in the `baseline_clean` task, so `EDGEGUARD_LAST_BACKUP_AT` goes into the environment of the Airflow processes, which then need a restart (set only in the shell that triggers, it does not reach the task); on stores that hold only test data, add `"skip_backup_check": true` to the conf instead. |
| Airflow not reachable | `edgeguard doctor` retries after 10s; check container: `docker compose ps airflow` |
| Runs stay "running" and no task starts | The scheduler has stopped while the API server still answers: `edgeguard dag status` lists the runs, names the scheduler as not healthy and exits 1. Restart Airflow (`docker compose restart airflow`) without triggering or pausing the DAG; finished tasks are not run again, and a task still running at the restart runs again from its start ([Scheduler or triggerer stopped](#scheduler-or-triggerer-stopped)) |
| `edgeguard dag` reports 401 or rejected credentials | The CLI speaks the Airflow 3 API (`/api/v2`, bearer token from `POST /auth/token`). Set `AIRFLOW_API_USER` / `AIRFLOW_API_PASSWORD` in `.env` (the `admin` password is in `/opt/airflow/simple_auth_manager_passwords.json.generated` inside the container); for an Airflow 2 deployment set `AIRFLOW_API_VERSION=v1`. |
| Pipeline already running (lock error) | Wait for it to finish, or delete `checkpoints/pipeline.lock` if stale |
| Need to clear just Neo4j or MISP | `edgeguard clear neo4j` / `edgeguard clear misp` / `edgeguard clear all` |
| OOM on large MISP events (100K+ attrs) | Events >5000 attributes are automatically streamed in pages. Increase `AIRFLOW_MEMORY_LIMIT` in `.env` if still failing |

---

## Environment Variables

```bash
# MISP
export MISP_URL="https://localhost:8443"
export MISP_API_KEY="your-misp-api-key"

# Neo4j (from **inside** Docker Compose services use bolt://neo4j:7687 — see docker-compose.yml x-common-env)
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USER="neo4j"
export NEO4J_PASSWORD="your-password"

# API Keys
export OTX_API_KEY="your-otx-key"
export NVD_API_KEY="your-nvd-key"
export VIRUSTOTAL_API_KEY="your-vt-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export THREATFOX_API_KEY="your-threatfox-key"

# Airflow
export AIRFLOW__CORE__EXECUTOR=LocalExecutor
export EDGEGUARD_BASE_DIR="/path/to/EdgeGuard-Knowledge-Graph"

# Monitoring
export EDGEGUARD_ENABLE_METRICS=true     # Enable Prometheus metrics
export EDGEGUARD_METRICS_PORT=8001       # Must not conflict with FastAPI (8000)

# Collector flags
# export EDGEGUARD_ENABLE_CISA_ICS=false   # CISA ICS advisories (edgeguard_daily → collect_cisa_ics, baseline tier 2), on by default; false → task skipped with success
# export EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN=1200   # per-run file cap (politeness toward GitHub raw)
# export EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES=50    # baseline sanity floor → transient skip + alert
export EDGEGUARD_ENABLE_MALWAREBAZAAR=true    # MalwareBazaar (edgeguard_daily → collect_malwarebazaar, baseline tier 2), off by default → task skipped with success
# export EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN=500   # per-run cap on samples pushed (labelled first; 0 = no cap)
```

---

## Troubleshooting

### Scheduler or triggerer stopped

`airflow standalone` (the Compose `airflow` service, or a bare-metal install that runs it) runs the scheduler, triggerer, DAG processor and API server as subprocesses and neither restarts nor exits when one of them dies; a metadata database error that outlasts Airflow's retries stops the scheduler and the triggerer. The API server keeps answering, and `/api/v2/monitor/health` answers HTTP 200 with `"unhealthy"` in its JSON body. No task starts, and a DAG run stays `running` without progressing or reaching its `dagrun_timeout`, which only the scheduler enforces.

**How it shows:**

- `edgeguard dag status` lists the runs, prints the scheduler as not healthy with its last heartbeat, and exits 1; `edgeguard doctor` and `edgeguard preflight` count a scheduler or metadata database that is not healthy as an error and a triggerer or DAG processor reported unhealthy as a warning. A triggerer or DAG processor that Airflow lists without status runs no job of its own (Airflow 2 parses the DAG files inside the scheduler by default) and is reported as information.
- `docker compose ps` shows the `airflow` service `unhealthy` (its healthcheck reads the scheduler status).
- Prometheus: `EdgeGuardAirflowSchedulerDown` (critical, after 5 minutes), `EdgeGuardAirflowComponentUnhealthy` and `EdgeGuardAirflowHealthUnreachable` (warnings, after 10 minutes).
- Check `[13]` of `scripts/preflight_baseline.sh`: a scheduler that is not healthy fails the check.

**Recovery:** when the metadata database is unhealthy, restore it first (`docker compose ps airflow_postgres`): Airflow does not start without it. A restart stops a task that is still running, and the new scheduler runs it again from its start, so when a task of the run is running and the run's time allows, let it end first. Then restart Airflow (`docker compose restart airflow`; bare metal: stop and start `airflow standalone`). Tasks that finished are not run again; do not trigger the DAG again and do not pause it. The stalled time counts against the run's `dagrun_timeout`. A triggerer or DAG processor alone does not stop a run: restart Airflow when no run is in progress. Details: [RUNBOOK.md](RUNBOOK.md), "Airflow scheduler or triggerer stopped".

**Metadata database:** the Compose stack uses PostgreSQL (`airflow_postgres`). A SQLite metadata database, Airflow's default when neither `AIRFLOW__DATABASE__SQL_ALCHEMY_CONN` nor `sql_alchemy_conn` in `airflow.cfg` names another backend, is for development only: a lock held a few seconds can stop the scheduler and the triggerer (the bare-metal setting and the `?timeout=60` fallback: [§ DAG run stuck in queued](#dag-run-stuck-in-queued-scheduler-running-but-nothing-executes)). Check `[13]` of `scripts/preflight_baseline.sh` warns on SQLite and never prints the connection string (it holds the database password).

### DAG run stuck in **queued** (scheduler “running” but nothing executes)

**Typical causes:** Airflow cannot reach its **metadata database**, migrations did not complete, or the scheduler process is unhealthy.

**EdgeGuard Docker Compose:** `docker-compose.yml` uses **PostgreSQL** (`airflow_postgres`) for metadata. Ensure Postgres is healthy, then restart:

```bash
docker compose ps
docker compose logs airflow_postgres
docker compose logs airflow
docker compose down && docker compose up -d
```

On first start, grab the Airflow UI bootstrap credentials from `docker compose logs airflow`.

**Bare-metal / pip Airflow:** set **`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`** to **PostgreSQL** (`postgresql+psycopg2://…`, example in `.env.example`; the `[postgres]` extra installs its driver) or **MySQL** (see [Apache Airflow database docs](https://airflow.apache.org/docs/apache-airflow/stable/howto/set-up-database.html)), in the environment of every Airflow process. SQLite, Airflow's default without this setting, is for development only (Apache Airflow says it must never be used in production): a lock one process holds can stop the scheduler, and a running baseline then stays `running` without progress, because only the scheduler enforces its timeouts. If you use SQLite anyway, append `?timeout=60` to its URL (`sqlite:////absolute/path/to/airflow.db?timeout=60`) so a connection waits up to 60 seconds for the lock. Keep **`AIRFLOW__CORE__EXECUTOR`** aligned with your deployment (e.g. `LocalExecutor` with a proper metadata backend).

**Scaling:** for multi-worker production layouts, prefer the [official Airflow compose](https://airflow.apache.org/docs/apache-airflow/stable/howto/docker-compose/index.html) or your platform’s chart — still with Postgres/MySQL metadata.

### `misp_health_check` (MISP preflight)

**Behaviour:**

- **`misp_health_check`** is a **`PythonOperator`** that runs **once** per DAG run and **fails fast** (typical runtime: a few HTTP calls, &lt; ~1–2 minutes); it does not re-poke until MISP is healthy.
- Pass criteria use **`MISPHealthCheck.check_health()`** → **`healthy_for_collection`** (same as **`healthy`** for API+DB; workers optional), because many MISP instances have **workers down** while **API + DB** are fine. With **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`**, preflight also requires **`checks["worker_status"]`**. Return type is **`MISPHealthCheckResult`** in **`src/misp_health.py`** (dict-like: **`[]`**, **`.get()`**, **`in`** for field names).

**Env vars (Airflow worker/scheduler environment):**

| Variable | Effect |
|----------|--------|
| *(default)* | Require **API + DB** only for preflight success. |
| `EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true` | Require workers as well (stricter: MISP must be “all green”). |
| `EDGEGUARD_SKIP_MISP_PREFLIGHT=true` | **Skip** the check entirely — emergency / debugging only; not recommended in production. |

If preflight still fails, fix **reachability** from the Airflow container to **`MISP_URL`** (see `docs/ENVIRONMENTS.md` — `localhost` inside Docker is usually wrong).

**Docker + Apache + `EDGEGUARD_MISP_HTTP_HOST` (common pitfall):**

- **`MISP_URL`** must be a hostname the **Airflow worker** resolves to the MISP container (e.g. Compose service name), not `https://localhost/...` unless MISP really listens there **inside the worker’s network namespace**.
- If Apache issues **absolute redirects** to `https://localhost/...`, the **requests** client may follow them and connect to **localhost on the Airflow container** (wrong service). Fix **Apache** (relative redirects, correct internal URL, or `ServerName` aligned with how clients connect) — that is **infrastructure**, not EdgeGuard.
- **`EDGEGUARD_MISP_HTTP_HOST`** sets the HTTP `Host` header when the TLS/SNI name must differ from the URL host (vhost). If you need `Host: localhost` for SSL but redirects break cross-container access, you must fix **redirect targets** in Apache; there is no safe “header only” workaround for bad `Location:` URLs.
- On **MISP 2.4.124**, `/servers/healthCheck` may be **missing (404)** or **redirect to login (302)**. EdgeGuard’s API probe uses **`allow_redirects=False`** on that URL and then tries **`/servers/getWorkers`** and **`/events/index`** so preflight matches what works with the API key.

**Self-signed MISP HTTPS (`certificate verify failed`):** EdgeGuard defaults to **verifying** TLS (**`EDGEGUARD_SSL_VERIFY`** defaults to **`true`**). For a **dev/lab** MISP with a self-signed cert, set **`EDGEGUARD_SSL_VERIFY=false`** on the **Airflow worker and scheduler** (same as other MISP env vars), then restart/recreate containers. In production, serve MISP with a certificate from a public CA: `requests` and PyMISP trust the `certifi` bundle, not the system store, so a CA installed in the image's system store is not used, and `docker-compose.yml` does not forward `REQUESTS_CA_BUNDLE`. The env name **`SSL_CERT_VERIFY`** is **not** read; optional alias: **`SSL_VERIFY=false`** only if **`EDGEGUARD_SSL_VERIFY`** is unset or blank. Only `false`, `0`, `no` or `off` (any case) turns verification off; any other value keeps it on and the task log shows a warning naming the variable and the value ([CONFIGURATION.md § TLS and trust](CONFIGURATION.md#tls-and-trust)).

### MISP → Neo4j sync logs **“No events”** while MISP has EdgeGuard events

**Causes to check:**

1. **Event discovery:** **`fetch_edgeguard_events()`** uses **`GET /events/index`** (then **`/events`**) with **client-side** filter: **`Event.info`** contains **`EDGEGUARD_MISP_EVENT_SEARCH`** (default **`EdgeGuard`**) **or** **`org.name`** is **`EdgeGuard`**. If the index fails, it falls back to PyMISP / requests **`restSearch`** for event headers only (**`metadata`**), filtered with **`eventinfo`** `%EdgeGuard%` (MISP 2.4.177 or later) and by the same client-side filter.

2. **JSON vs HTML:** The sync **`requests.Session`** sends **`Accept: application/json`** (and **`Authorization`**) so MISP returns JSON, not a login HTML page.

3. **Wrong substring / org:** Set **`EDGEGUARD_MISP_EVENT_SEARCH`** if titles don’t contain the default substring, or ensure publishing org name matches the filter if you rely on **`EdgeGuard`** org.

4. **Incremental window:** Incremental sync only keeps events whose **`timestamp`** / **`date`** (when present) is on/after the **`since`** window; baseline **`full_neo4j_sync`** uses **`incremental=False`** and loads all matching index rows (subject to index pagination caps).

5. **An empty window fails:** with the default **`EDGEGUARD_SYNC_MIN_EVENTS=1`** a window without EdgeGuard events fails `run_neo4j_sync` with `MISP returned 0 event(s) for the sync window`. Check the collector DAGs first (nothing was written to MISP since the last sync), then the event names and the discovery filter above. `0` restores an empty success — see the `run_neo4j_sync` walkthrough above.

### Airflow container: **neo4j** / **pymisp** missing after recreate

**Do not** rely on **`pip install`** inside a running `apache/airflow` container — packages are lost when the container is recreated.

**Compose fix:** the **`airflow`** service is built from **`Dockerfile.airflow`**, which installs **`requirements-airflow-docker.txt`**. After changing that file or Python deps, rebuild:

```bash
docker compose build airflow && docker compose up -d airflow
```

**`PYTHONPATH` and mounted `src/`:** Compose sets **`PYTHONPATH=/opt/airflow/src`** so imports like **`config`**, **`neo4j_client`**, **`misp_health`** resolve from the read-only **`./src:/opt/airflow/src`** mount. If you still see **`ModuleNotFoundError`**, confirm you recreated the stack after pulling **`docker-compose.yml`**, and that **`Dockerfile.airflow`** was rebuilt (custom image, not plain `apache/airflow`).

**`Dockerfile.airflow` + `tini`:** The custom image uses **`tini`** as PID 1 and **`CMD ["airflow", "standalone"]`**. Do **not** set **`command: standalone`** in Compose — that overrides **`CMD`** and can break the process list (e.g. **`tini -- standalone`** instead of **`tini -- airflow standalone`**). **`docker-compose.yml`** does override **`CMD`**: a **`bash -c`** command starts the detached loop that creates the collector pool and then runs **`exec airflow standalone`**, so **`tini`** still runs **`airflow standalone`**, which replaces the shell (see [Collector pool: setup and resizing](#collector-pool-setup-and-resizing)). Rebuild after **`Dockerfile.airflow`** changes.

### `edgeguard_baseline` — Tier1 MITRE / NVD failures, “zombie” tasks, long runs

**Symptoms:** `tier1_core.collect_mitre` or `collect_nvd` fails after **up_for_retry**, or NVD runs a long time then is marked **zombie** / killed.

**Tier2 / `full_neo4j_sync` vs Tier1 failures:** **`tier2_feeds`** tasks use **`TriggerRule.ALL_DONE`** on Tier1 upstreams, so a failed **`collect_otx`** (or another Tier1 task) does not leave Tier2 as **`upstream_failed`**. **`full_neo4j_sync`** uses **`ALL_DONE`** after Tier2 so MISP→Neo4j still runs when some bulk collectors fail — Neo4j reflects whatever landed in MISP. The collectors and `full_neo4j_sync` refuse to run when `baseline_clean` / `baseline_start` did not succeed in the same run, so a failed wipe does not let them write into a half-cleaned store; the collectors also refuse while no baseline holds the baseline lock, and `full_neo4j_sync` unless this run holds it (see `baseline_clean` task semantics above).

**How to trace**

| What | Where to look |
|------|----------------|
| **Root error** | Airflow UI → DAG `edgeguard_baseline` → failed task → **Log** (search: `MISP`, `HTTP`, `Timeout`, `Failed to push`, `MITRE`, `NVD`, `AirflowException`). |
| **MISP-side** | MISP server logs / web UI (auth errors, validation, rate limits, disk). Airflow must reach **`MISP_URL`** from **inside** the Airflow container. |
| **Config used** | Task **`baseline_start`** log prints **`BASELINE_DAYS`** and **`BASELINE_COLLECTION_LIMIT`** (Airflow **Admin → Variables**). |

**MITRE (`collect_mitre`)**

- Downloads a large STIX bundle (~80 MB) from GitHub, parses JSON, then **`misp_writer.push_items`** for thousands of objects. Failures are often **MISP timeouts**, **SSL**, **auth**, or **payload validation** — the task log and MISP logs together confirm it.
- **Scheduled (non-baseline) runs:** when **`EDGEGUARD_MITRE_CONDITIONAL_GET`** is enabled, the collector uses **`If-None-Match`**; **HTTP 304** skips download/parse/push if the bundle is unchanged. **Baseline** still fetches the full bundle.
- **`run_collector_with_metrics`** raises **`AirflowException`** if the collector returns **`success: false`** (including “all pushes failed”), so the UI shows a clear failure.
- If **`metrics_server`** is enabled, **`set_source_health(source, zone, healthy)`** requires **three** arguments; `edgeguard_pipeline.py` always passes the zone (e.g. **`"global"`**).

**`up_for_retry`:** With **`retries: 1`** on baseline Tier1 tasks, a first failure can show as **up_for_retry** until the retry is consumed; the final state should be **failed** or **success**, not stuck indefinitely.

**NVD (`collect_nvd`) — baseline**

- With **`BASELINE_DAYS`** set to **90** (or **730**), NVD walks many **120-day** API windows and **pages** (0.7 s between pages with an API key). Then it **processes** all CVEs and **pushes** to MISP in bulk — this can take **hours**.
- **`execution_timeout`** for baseline NVD is **5 hours** in `dags/edgeguard_pipeline.py`, because baseline runs take longer than 3 hours: at a 3-hour limit the task times out and retries while doing real work, which is not a zombie. If you need more wall-clock time, increase that timeout (and ensure the scheduler/worker is not restarted mid-run).
- **A failing MISP during the push.** The baseline's writer (`MISPWriter(..., baseline=True, task_ends_at=...)`, built once in `run_baseline_collector`) stops a push once MISP has kept failing for `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE` (3600 s), and a failing streak gets at most the time from its start to 10 minutes before the task's end, at least 60 s; the 10 minutes leave room for a batch request in flight whose answer comes within its timeouts (30 s to connect, 300 s for each wait for data). A streak that starts in the task's last minutes (the 60 s floor), an answer that keeps arriving slowly, and the requests the cap does not cut short or does not limit (event and part lookups, a new part's creation, listings; [MISP_TUNING.md](MISP_TUNING.md)) can still take a task to its `execution_timeout`. The task's end is its start (the task instance's `start_date`, or the time the callable starts) plus its `execution_timeout` (5 hours for `collect_otx` and `collect_nvd`, whose pushes start hours into the task, 2 hours for the others). A stopped push counts the items not sent as failed and the collector returns its status (`[MISP-PUSH-STOPPED]`, `EdgeGuardMispPushStopped`), so the task ends with its log instead of being killed at its limit: red unless it stored 95% or more first (`EDGEGUARD_MISP_MIN_SUCCESS_RATE`). Airflow retries a red collector task once, 5 minutes later, with a fresh cap; clear it after that once MISP answers again ([RUNBOOK.md](RUNBOOK.md), "MISP push stopped (MISP kept failing)"). The scheduled DAGs' writers take `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC` (900 s); the writers of `collect_otx` in `edgeguard_pipeline` (`run_otx_collection`, one hour) and of `collect_cisa_ics` in `edgeguard_daily` (`run_cisa_ics_collection`, two hours) are given their task's end too, so a failing streak and the pushes of their report records stop 10 minutes before it.
- A **“zombie”** message usually means the scheduler lost the task heartbeat (scheduler/worker restart, heavy CPU blocking, OOM, or platform kill) — check **`docker compose logs airflow`**, host **memory**, and whether the task process was killed. It is **not** always the same as hitting `execution_timeout`.

**Smoke test (recommended before a full baseline)**

See **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for copy-paste **`.env`** examples (`EDGEGUARD_BASELINE_DAYS=7`, `EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000`) and restart steps. For a printable runtime checklist (Docker + `airflow dags trigger`), see [`scripts/runtime_smoke_checklist.sh`](../scripts/runtime_smoke_checklist.sh).

Or use Airflow **Variables** only: `BASELINE_DAYS` = **`7`**, `BASELINE_COLLECTION_LIMIT` = **`500`** or **`1000`**.

After Tier1 succeeds, remove env overrides or restore Variables for production.

**NVD resume:** Baseline NVD writes checkpoints under **`get_source_checkpoint("nvd")`** — a new run can resume windows; see `src/collectors/nvd_collector.py` and `baseline_checkpoint` usage.

### DAG Not Running
1. Check that the scheduler is healthy: `edgeguard dag status` names a scheduler that is not healthy and exits 1 ([Scheduler or triggerer stopped](#scheduler-or-triggerer-stopped))
2. Verify DAG file is in `$AIRFLOW_HOME/dags/`
3. **Parse check:** `docker compose exec airflow airflow dags list-import-errors` on the stack, or `airflow dags list-import-errors` after `airflow db migrate` in a local Airflow; Airflow 3.x has no `airflow dags validate` subcommand. [`scripts/preflight_ci.sh`](../scripts/preflight_ci.sh) (`compileall`, `pytest`, an Airflow `DagBag` load with `NEO4J_PASSWORD` set) currently stops at its `DagBag` step on Airflow 3.3, whose `DagBag` has no `include_examples` argument.

### Collector Failures
1. Check API key configuration
2. Verify network connectivity to source
3. Check rate limits in the task log (Airflow UI → the task instance → Logs)

**Optional API keys (skip without failing the DAG):** If an optional key is unset, the corresponding task **succeeds** with a **warning** log, **`skipped: true`** in the return payload, Prometheus counter **`edgeguard_collector_skips_total`** (label `reason_class=...`), and **`edgeguard_indicators_collected_total{status="skipped"}`** (count 0). Supported optional sources:

| Env var | `reason_class` (metrics label) |
|---------|--------------------------------|
| **`ABUSEIPDB_API_KEY`** | `missing_abuseipdb_key` (also **`abuseipdb_auth_denied`** on HTTP 401/403) |
| **`OTX_API_KEY`** | `missing_otx_key` (also **`otx_auth_denied`** on 401/403) |
| **`VIRUSTOTAL_API_KEY`** | `missing_virustotal_key` (also **`virustotal_auth_denied`** on 401/403; **`virustotal_daily_budget`** / **`virustotal_rate_limited`** when the free-tier budget is spent; **`virustotal_candidates_unavailable`** when MISP cannot list hashes to enrich; **`virustotal_misp_unavailable`** when MISP is unreachable while the results are pushed) |
| **`THREATFOX_API_KEY`** (the abuse.ch Auth-Key of ThreatFox, URLhaus and MalwareBazaar) | `missing_threatfox_key` (ThreatFox) and `missing_abusech_key` (URLhaus, MalwareBazaar); also **`threatfox_auth_denied`**, **`urlhaus_auth_denied`** and **`malwarebazaar_auth_denied`** on 401/403 |

Add keys when you want those feeds. Values that are **empty**, **whitespace-only**, or YAML **placeholders** from `credentials/config.example.yaml` are treated as unset. **ThreatFox**, **URLhaus** and **MalwareBazaar** require the free abuse.ch key from **https://auth.abuse.ch/** — without it their tasks **skip** (success) so the baseline DAG can continue. **MalwareBazaar** also skips with `malwarebazaar_disabled_by_flag` while `EDGEGUARD_ENABLE_MALWAREBAZAAR` is off, and its 429/5xx/timeouts → `transient_external_error`. **URLhaus** fails the task when its export cannot be read for any other reason than a missing key or HTTP 401/403.

**Baseline in progress (`baseline_in_progress`):** while a baseline holds the baseline lock, every scheduled collector task skips the same way (success, `skipped: true`, `skip_reason_class=baseline_in_progress`); a baseline collector that finds the lock held by another baseline stands down with the same reason class and an ERROR log line.

**Is a key accepted?** A key that is set but not accepted by its provider is a configuration error. Inside a run, OTX, VirusTotal, ThreatFox, URLhaus, MalwareBazaar and AbuseIPDB return a *skipped* task that Airflow shows as successful, and a rejected **NVD** key fails the NVD task (NVD answers HTTP 404 `Invalid apiKey.`), which in a fresh baseline happens after the stores were wiped. Four places report it:

| Where | What it does |
|-------|--------------|
| `python src/edgeguard.py preflight` (section 1) and `python src/source_key_check.py [--json]` | One authenticated request per key (one ThreatFox query checks the abuse.ch key, and its line names each of ThreatFox, URLhaus and MalwareBazaar that is switched on): `key accepted`, `key REJECTED` (with the provider's reason), `no key`, or `key NOT VERIFIED` (provider unreachable or rate-limited: never a verdict on the key). A rejected optional key is a warning (`--strict` fails); a rejected NVD key, and a source named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES` that cannot deliver (no key, rejected key or switched off, also when the shared abuse.ch key is accepted for the abuse.ch sources that are switched on), are errors in `preflight`. Exit code of `source_key_check.py`: `0` nothing rejected, `1` a rejected key (source skipped), `2` a key state that stops a baseline |
| Baseline DAG, task `source_key_check` (after `misp_health_check`, before `baseline_acquire_lock` and `baseline_clean`) | Logs one `[SOURCE-KEYS]` line per key (ERROR for a rejected key). Fails the run, with nothing locked or wiped, only for a rejected NVD key or for a source named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES` that cannot deliver. A missing or rejected key of an optional source never blocks |
| `scripts/preflight_baseline.sh` check `[12]` | The same check on launch day: rejected key = warning (NO-GO under `EDGEGUARD_PREFLIGHT_STRICT=1`), blocker = failure |
| Every collector run | A skip with `reason_class=*_auth_denied` is logged at ERROR (`[SOURCE-ACCESS] <SOURCE> NOT collected — the provider denied access`) and raises the Prometheus alert `EdgeGuardSourceAccessDenied` |

Cost of one check: OTX and NVD requests are outside any quota; VirusTotal one lookup, counted in the daily ledger; it is not sent when the ledger is exhausted, while a VirusTotal collector run is writing the ledger (last write under 5 minutes ago), or within 20 seconds of the previous check, and a collector run that starts within a minute after a check waits for the rest of that minute (the limit of 4 lookups a minute is shared; an HTTP 429 answer to the check is never recorded as the end of the collector's day, and the collector does not end its day on an HTTP 429 that follows a check within two minutes); AbuseIPDB one `check` request (1,000 a day; the 5-a-day `blacklist` quota the collector needs is not used); ThreatFox one query. A key value is never logged or printed. `EDGEGUARD_SOURCE_KEY_CHECK=false` disables the requests.

**Other optional HTTP feeds** (no API key required, but if the upstream returns **401/403**, the task **skips** instead of failing): **NVD** (`nvd_auth_denied`; a rejected `NVD_API_KEY` is HTTP 404 and **fails** the task with `NVD rejected NVD_API_KEY`), **CISA KEV** (`cisa_auth_denied`), **MITRE** (`mitre_auth_denied`, e.g. GitHub), **Feodo** (`feodo_auth_denied`; `feodo_circuit_breaker_open`; outages → `transient_external_error`), **SSL Blacklist** (`sslbl_auth_denied`; `sslbl_circuit_breaker_open`; outages → `transient_external_error`).

**Collector allowlist (`EDGEGUARD_COLLECT_SOURCES`):** Optional comma-separated list of which collectors may run (e.g. `otx,nvd,cisa,mitre`). **Unset or empty** → all collectors run (subject to optional-key skips above). **`none`**, **`-`**, or **`0`** alone → no external collectors run; each collection task **succeeds** with **`skipped: true`** and **`skip_reason_class=collector_disabled_by_config`**. Unknown names are **logged and ignored**; if no valid names remain, behavior matches **unset** (fail-open). Applies to **Airflow** (`run_collector_with_metrics`) and [`run_pipeline.py`](../src/run_pipeline.py) (same canonical source keys as scheduled tasks, including both `virustotal` and `virustotal_enrich`). Implementation: [`src/collector_allowlist.py`](../src/collector_allowlist.py).

### MISP → Neo4j Sync Issues

**Limits (don’t confuse these):** Baseline **`BASELINE_COLLECTION_LIMIT`** caps **external collectors** (OTX, NVD, …), **not** how many MISP events the sync reads. The sync discovers events via **paginated `/events/index`** (each event listed once, also on a MISP that ignores the query-string paging; an incomplete listing fails the run). **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **500**) controls **Neo4j merge RAM** (parsed items per Python chunk; a pause between chunks only with `EDGEGUARD_QUERY_PAUSE_SECONDS`), **not** MISP fetch size. See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

0. **Sync fails almost immediately (baseline `full_neo4j_sync` or `run_neo4j_sync`):** The script does **not** call EdgeGuard REST/GraphQL — look at **MISP + Neo4j only**. Open the task log and search for **`Cannot start sync`**, **`MISP health check failed`**, **`Neo4j health check failed`**, **`No driver initialized`**, **`APOC`**, or **`circuit breaker`**. Typical fixes: **`NEO4J_URI` / `NEO4J_PASSWORD`** correct **from inside the Airflow worker** (e.g. `bolt://neo4j:7687`, not host-only `localhost` if Neo4j is another container), **APOC** installed and allowed (see `docker-compose` / Neo4j docs), **`MISP_URL`** reachable from the worker, and **`EDGEGUARD_MISP_HTTP_HOST`** if Apache vhost name ≠ URL hostname. Failed tasks raise **`AirflowException`** with a short **reason** suffix when available.
1. Verify Neo4j is running: `neo4j status`
2. Check MISP is accessible
3. Review sync logs for constraint violations
4. **“Tasks succeeded but Neo4j is empty”**
   - **`check_sync_needed` skipped the run:** confirm whether `run_neo4j_sync` is **skipped** (grey) vs **success** (green). A skip means that a baseline holds the baseline lock (log `Neo4j sync ShortCircuit: …`, or `run_neo4j_sync skipped: …` when the task checked the lock itself) or that the last successful sync started less than 24 h ago (`NEO4J_SYNC_MIN_GAP`; the 72 h interval and the guard are fixed in `dags/edgeguard_pipeline.py`). Trigger `airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'` to bypass the 24 h guard; it does not bypass the baseline lock, so wait for the baseline to release it. The Airflow Variable **`NEO4J_FULL_SYNC=true`** makes the next sync that runs a full one; it does not bypass the guard. Deleting the state file both bypasses the guard and forces a full sync.
   - **Sync ran but ingested 0 items:** In logs, look for **`Processing event None`** or **`Parsed 0 items`**, the sign of MISP rows that reached the loop as **`{'Event': {...}}`** instead of a flat dict; **`fetch_edgeguard_events`** normalizes both shapes. Also check the **incremental window**: it starts at the state file's `last_sync` minus `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS` (default 1 h); the fixed `EDGEGUARD_SYNC_INTERVAL_DAYS` window applies only when the state file is unreadable. Older EdgeGuard events need a **full** sync.
5. **PyMISP vs REST:** If PyMISP errors and the code falls back to **`/events/index`**, the JSON shape may be a **`response`** / **`events`** wrapper; that is handled when building the normalized list.
6. **Event view shape:** `get_event` / `/events/view` may return a **PyMISP object** or **`{'Event': ...}`**; the sync normalizes to a flat dict before reading **`Attribute`**. REST is always tried if PyMISP returns an unparsed type.
7. **MISP Objects vs flat attributes:** Ingestion uses the event’s top-level **`Attribute`** list. Events that store IOCs only inside **`Object`** (object templates) may log a warning and sync **zero** attributes until object expansion is implemented.
8. **OOM / worker killed during Neo4j insert:** The sync merges in **Python-side chunks** (default **500** items, no pause unless `EDGEGUARD_QUERY_PAUSE_SECONDS` is set). Events with **>5000 attributes** are streamed in pages of 5000. Default **`AIRFLOW_MEMORY_LIMIT`** is **12g** (100K+ attr events need 8-12GB). Lower **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** if still OOM.
9. **Cross-item relationships are per MISP event and per source report:** the sync pairs items **only when they share the same OTX pulse** (`pulse_id`) inside one event — `INDICATES` and `ATTRIBUTED_TO` with `match_type='otx_pulse'`, the latter only when the pulse's actors are one actor (aliases of one actor count as one, canonical threat-actor reference; the OTX collector marks a pulse naming several actors on every item of it, `several_actor_pulses`, because MISP drops an actor it already holds and an event may carry only some of the pulse's actors; `several_actor_pulses_by_name` when it judged without the reference, which the sync uses for its run only) — then writes nodes and edges for that event before moving on. Items are not paired across a whole event (actor↔technique, every indicator↔every malware), because EdgeGuard events are per-source, per-day buckets, not reports.
10. **Relationship batching:** **`EDGEGUARD_REL_BATCH_SIZE`** (default **500**) controls how many relationship definitions are sent per **`create_misp_relationships_batch`** UNWIND round-trip.
11. **Task success vs Airflow “failed” / SIGKILL:** If the graph is updated but the task is red, read **[HEARTBEAT.md](HEARTBEAT.md)** — a task heartbeat timeout (**`[scheduler] task_instance_heartbeat_timeout`**, Airflow default 300 s, set to 3600 s by `docker-compose.yml`) and **OOM (-9)** are common causes separate from application exceptions.

---

## File Structure

```
EdgeGuard-Knowledge-Graph/
├── dags/
│   ├── edgeguard_pipeline.py        # Collection DAGs (high/medium/low/daily + baseline)
│   └── edgeguard_metrics_server.py  # Dedicated metrics server DAG
├── plugins/
│   └── edgeguard_dag_run_state.py   # Listener plugin: marks each DAG run in progress
├── src/
│   ├── collector_allowlist.py      # EDGEGUARD_COLLECT_SOURCES (parse-time safe for DagBag)
│   ├── collectors/               # All collectors
│   │   ├── otx_collector.py
│   │   ├── nvd_collector.py
│   │   ├── cisa_collector.py
│   │   ├── mitre_collector.py
│   │   ├── vt_collector.py
│   │   ├── abuseipdb_collector.py
│   │   ├── global_feed_collector.py
│   │   ├── finance_feed_collector.py
│   │   └── misp_writer.py
│   ├── run_pipeline.py           # Collectors into MISP (development)
│   └── run_misp_to_neo4j.py      # Manual sync
└── docs/
    └── AIRFLOW_DAGS.md           # This guide (CLI, env, troubleshooting)
```

---

## Quick Reference

| Action | Command |
|--------|---------|
| List DAGs | `airflow dags list \| grep edgeguard` |
| Trigger pipeline | `airflow dags trigger edgeguard_pipeline` |
| Sync to Neo4j | `airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'` (without `force_sync`, a run within 24 h of the last sync start is skipped by `check_sync_needed`; a manual run does not move the 72 h schedule) |
| Check status | `airflow dags list-runs edgeguard_pipeline` |
| View logs | Airflow UI → the task instance → Logs, or `$AIRFLOW_HOME/logs/dag_id=<dag>/run_id=<run>/task_id=<task>/attempt=<n>.log` |

---

_Last updated: 2026-11-08_

## History

- 2026-11-08 — `collect_cisa_ics` runs by default in `edgeguard_daily` and the baseline; `EDGEGUARD_ENABLE_CISA_ICS=false` skips it with success. `baseline_clean`: what the wipe clears: the checkpoint file with the whole incremental state, the OTX retry list and the `report_pending` lists included, and their gauges set to empty lists; the EdgeGuard events with their `-part<N>` and `-reports` events and Event Reports. MISP's log entries stay.
- 2026-11-07 — The writer of the scheduled `collect_cisa_ics` is given its task's end (`task_ends_at`) too.
- 2026-11-07 — The writer of the scheduled `collect_otx` is given its task's end (`task_ends_at`), as the baseline's writer is: a failing streak and the pushes of the run's report records stop 10 minutes before it.
- 2026-11-07 — Deduplication: the constraint table names `ThreatReport` and `VulnerabilityAdvisory`, unique on `record_ref`, which `create_constraints` creates ahead of the sync that writes report records.
- 2026-11-06 — Python packages: `apache-airflow[postgres]~=3.3.2`. The two-part `~=3.3` admits every 3.x release, and CI installed Airflow 3.4.0 on its release; the image runs 3.3.2.
- 2026-11-03 — Baseline troubleshooting: the baseline's writer stops a push on a failing MISP after `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE` (3600 s), a failing streak at most until 10 minutes before its task's end (at least 60 s), so a push it stops lets the collector return its status (slow lookups and listings can still take the task to its `execution_timeout`); the scheduled writers stop after `EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC` (900 s).
- 2026-11-02 — Source schedules: an OTX run counts up to 200 pulses modified after the cursor, oldest first (`EDGEGUARD_INCREMENTAL_LIMIT`), the overlap's re-reads on top; the table gave 50 pulses; MISP push accounting: OTX puts the pulses with unstored items on its retry list and moves its cursor on, unless every unstored item failed at its MISP event (the text had the cursor held below them until the collector was fixed).
- 2026-11-02 — Checked against the code: `airflow standalone` runs its four components as subprocesses and neither restarts nor exits when one dies (the topology note placed them inside one process); `baseline_clean` documents its `BASELINE_CLEAN: deleted …` line; the postcheck's WARNING table lists every collector that delivered nothing, also one not run or without a returned status (it named skipped and failed only); MITRE ATT&CK pushes the whole bundle when it changed and nothing otherwise (the table gave 500 items); the MISP dedup logging names `[CASE-VARIANT]`; a SQLite metadata database is Airflow's default only when neither the environment nor `airflow.cfg` names a backend; the Airflow 3 commands take the DAG id as a positional argument and task logs are read in the UI or the log files (the page gave `list-runs -d` and `airflow logs`, which Airflow 3 rejects); the full-sync measurement still to be made is no longer named.
- 2026-11-02 — Baseline DAG: `baseline_postcheck` fails the run on INV-4 (ATT&CK links of the claims on the nodes; the claims themselves on an unlimited run), INV-5 (CVE score coverage after an NVD delivery) and INV-6 (each collector's delivery at its `Source` node, and the sources named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES`), with the acceptance script's statements, and lists the collectors that delivered nothing. It had checked INV-1 to INV-3 only, and INV-3 holds whenever the sync connects.
- 2026-11-02 — § One baseline path (was § In-process CLI baseline): `python src/run_pipeline.py` runs the collectors into MISP only and exits 2 on `--baseline`, `--fresh-baseline`, `--baseline-days` and `--stix-flow`; its in-process baseline, which loaded Neo4j through a STIX import and built a reduced graph, is retired. The fresh-baseline line names the DAG's `baseline_clean`; the troubleshooting row and the MISP preflight no longer name the in-process fresh baseline or `run_pipeline_misp_spt.py` (deleted). Check `[13]` of the preflight script fails on a scheduler that is not healthy (it named the DAG launch path, now the only one).
- 2026-11-02 — CLI vs DAG equivalence: `edgeguard baseline` / `fresh-baseline` trigger through the REST API without a running Compose `airflow` service (they used `docker compose exec` only) and refuse while the scheduler or metadata database is not healthy or an `edgeguard_baseline` run is queued or running (`max_active_runs=1` queues a second trigger instead of refusing it); on the Compose host they read in the `airflow` container what the REST API does not give. In-process CLI baseline: an install without Docker can also trigger with these commands (the section named only `airflow dags trigger` and the UI).
- 2026-11-02 — MISP push accounting: a batch answered with HTTP 5xx is looked up in the event before it is retried; one MISP holds in full counts as pushed (`[STORED-AFTER-5XX]`), and of a batch whose retries fail only what MISP lacks counts as failed (on 2026-11-01 the OTX collector counted 1,857 attributes as failed, of which MISP had stored 1,854).
- 2026-11-01 — `run_neo4j_sync`: the 8h default is the 6h limit of `full_neo4j_sync` plus a third, and the duration of a 730-day full sync with batched CVE writes is to be measured on the next 730-day run. The text had given that full sync as taking about 6h, the estimate for one `merge_cve` call per CVE: about 8 NVD CVEs per second in the 7-day baseline of 2026-11-01 on the test instance put a 730-day MISP at about 5.7 h, about 5.2 h of it CVEs.
- 2026-11-01 — The Airflow image upgrades `libbrotli1` and `Authlib` past the advisories CVE-2026-111497 and CVE-2026-96760.
- 2026-11-01 — MISP push accounting: case is ignored only for the types whose case MISP changes on save (a value the event held in another case had counted as stored).
- 2026-11-01 — Troubleshooting: "Scheduler or triggerer stopped" (`airflow standalone` keeps the API server up when the scheduler dies; how `edgeguard dag status`, `doctor`, `preflight`, the `airflow` healthcheck, the Airflow alerts and preflight check `[13]` report it; recovery: the metadata database first, a running task runs again from its start after a restart, no new trigger and no pause; SQLite metadata database for development only, `?timeout=60`). The queued-runs row checks the scheduler before `edgeguard dag kill`. "DAG Not Running" checks the scheduler with `edgeguard dag status` instead of starting `airflow scheduler`.
- 2026-11-01 — New § In-process CLI baseline: every baseline runs through the `edgeguard_baseline` DAG, also without Docker (Airflow with a PostgreSQL metadata database, triggered with `airflow dags trigger`, since the `edgeguard` wrappers need Compose); `python src/run_pipeline.py --baseline` is a development path whose STIX import builds a reduced graph, listed link by link (the page called it a legacy path with one asymmetry, the `DEGRADED MODE` handling). The bare-metal metadata database: PostgreSQL, SQLite for development only, `?timeout=60` with SQLite. A fresh baseline without Docker: `EDGEGUARD_LAST_BACKUP_AT` in the environment of the Airflow processes, or `skip_backup_check` on test data.
- 2026-10-25 — Node table: one `Source` node per registered source, keyed by its canonical id (the row counted a node per registry alias).
- 2026-10-25 — MISP event names: a source/date event continues in `-part2`, `-part3`, ... past `EDGEGUARD_MISP_EVENT_SPLIT_ABOVE` (default 20000) attributes, OTX events excepted (the page said partitioning MISP events is not implemented).
- 2026-10-25 — `EDGEGUARD_NEO4J_SYNC_TIMEOUT_HOURS` sets the `run_neo4j_sync` limit (default 8 h, at most 22 h); the `dagrun_timeout` table, the skip guard and the stale alert state that their 8 h is the default limit; the threshold of `EdgeGuardNeo4jSyncStale` follows the limit through `edgeguard_neo4j_sync_task_limit_seconds`, which each attempt sets when it starts; the mode line of the task log ends with the limit of the attempt.
- 2026-10-25 — Neo4j sync: a green `run_neo4j_sync` can include an event fetched in pages with fewer attribute rows than the MISP index lists (`[PAGED-FETCH-INCOMPLETE]`, run summary, the warning alert `EdgeGuardSyncPagedFetchIncomplete`, not a failure); the memory note names the attribute list the sync holds, not PyMISP JSON parsing; the MalwareBazaar and URLhaus skip rules are listed with the abuse.ch key, not among the feeds without a key.
- 2026-10-25 — URLhaus and MalwareBazaar need `THREATFOX_API_KEY`, the abuse.ch Auth-Key, in their v2 export URL (the keyless downloads answer HTTP 410 since 2026-10): `missing_abusech_key` and `urlhaus_auth_denied` added to the optional-key table, MalwareBazaar no longer listed as a keyless feed, the source key check reports the key for all three abuse.ch sources, and `edgeguard preflight` counts a required abuse.ch source that is switched off as an error even when the key is accepted; URLhaus reads the `recent.csv` export (about 63,000 URLs on 2026-10-24) with a cap of 100,000 (was 50,000).
- 2026-10-23 — Self-signed MISP HTTPS: only `false`, `0`, `no` or `off` turns TLS verification off; any other value of `EDGEGUARD_SSL_VERIFY` keeps it on with a warning in the task log.
- 2026-10-23 — The reading order points to SETUP_GUIDE.md (the README section it named was removed); HC3 is a public source, not a member-only feed; `dagrun_timeout` and `max_active_runs=1` are named for the DAGs that have them (the page said all DAGs); the parse check is `airflow dags list-import-errors`, because `preflight_ci.sh` stops at its `DagBag` step on Airflow 3.3.
- 2026-10-22 — The Airflow image upgrades `pip`, `certifi` and `uv` past the emSign CA advisories (GHSA-6q48-6c7w-9gw2, GHSA-hq85-5cpj-mr62) and removes the `prek` hook runner of the base image; every dependency list sets `certifi>=2026.10.19`; the MISP certificate troubleshooting names the trust store `requests` reads.
- 2026-10-18 — `EDGEGUARD_SYNC_MIN_EVENTS` defaults to 1: a sync window without EdgeGuard events fails `run_neo4j_sync` (it was an empty success that moved the sync cursor); `0` disables the guard.
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Rewritten as a guide to the current system: change history moved to this section, upgrade procedures to the appendix.
- 2026-10-17 — MISP push accounting: the OTX cursor after a push with failures advances up to the oldest pulse with an item the writer lists as unstored, so a few bad records hold no cursor.
- 2026-10-17 — The baseline chain (collectors, `full_neo4j_sync`, `build_relationships`, `run_enrichment_jobs`) and the sync DAG's writing tasks check the baseline lock; a refusal of `baseline_clean` before the wipe releases it; `source_key_check` has `retries=0`; troubleshooting of repeatedly failing collectors (each task starts with every circuit breaker closed).
- 2026-10-17 — `docker-compose.yml` sets the heartbeat timeout with the Airflow 3 names (it set the pre-3 names `scheduler_zombie_task_threshold`, `local_task_job_heartbeat_sec` and `zombie_detection_interval`, which Airflow 3 does not read); see [HEARTBEAT.md](HEARTBEAT.md).
- 2026-10-16 — The MISP event listing lists each event once on a MISP that ignores the query-string `limit` / `page` (MISP 2.5.45), and an incomplete listing fails the run; before, the sync went on with the rows read so far and stamped the state file past the events never listed.
- 2026-10-16 — Items no MISP attribute can be built from are logged as `[CONVERT]` (they were dropped silently) and count as failed pushes only when they are all or at least half of a source's items in the push.
- 2026-10-16 — Every `collect_*` task runs in the Airflow pool `edgeguard_collectors`, because all tier-2 feeds at once exhausted the MISP php-fpm workers and a daily catch-up run with OTX, VirusTotal and NVD reached the `airflow` container's memory limit.
- 2026-10-16 — The incremental window overlap is `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS` (default 1 h) instead of 1 day, because with the 1-day overlap every attribute a baseline wrote in the day before its full sync still counted as changed, so the first sync after a baseline that collected for less than a day re-merged all of it.
- 2026-10-16 — `edgeguard_neo4j_sync` runs every 72 h (`timedelta(days=3)`) instead of the cron `0 3 */3 * *` (gaps of 96 h at most month ends, 120 h after 28 February of a leap year, up to 143 h after a baseline) and skips within 24 h of the last sync start instead of 71 h (which skipped the run after a sync that succeeded on a retry); `EdgeGuardNeo4jSyncStale` 122 h instead of 145 h.
- 2026-10-16 — Feodo Tracker, SSL Blacklist and AbuseIPDB read their whole list up to their own per-run caps instead of a cut at 200.
- 2026-10-16 — CISA KEV compares the whole catalogue with MISP in every run and edits revised entries in place, at most `EDGEGUARD_KEV_MAX_EDITS_PER_RUN` (500) per run; the sync also reads the OTX collector's several-actor mark judged without the canonical reference (`several_actor_pulses_by_name`).
- 2026-10-16 — The indicator aging is evaluated at the database's current time, or at a node's later `aging_evaluated_at`; no task passes a time of the run.
- 2026-10-16 — The `restSearch` fallback asks for event headers with `eventinfo` (it sent `search`, which is not a restSearch parameter); `generate_test_metrics` records nothing with `PROMETHEUS_MULTIPROC_DIR` set; a pending full-sync request raises `EdgeGuardNeo4jFullSyncRequestPending`.
- 2026-10-15 — The DAG run in progress is marked by the listener plugin `plugins/edgeguard_dag_run_state.py`, because the former gauge was refreshed on every task success and never cleared, so `EdgeGuardDAGRunStuck` fired from one hour after a run until the DAG's next run (permanently after the baseline); node counts are read after each sync (the task set four labels to 0) and the sync duration is observed once (it was observed twice).
- 2026-10-15 — `run_neo4j_sync` clears `NEO4J_FULL_SYNC` only after a successful full sync (it was reset before `sync.run()`, so a failed attempt retried as an incremental run and the requested repair stayed incomplete), its timeout is 8 h instead of 4 h, and the sync DAG's `dagrun_timeout` is 68 h instead of 22 h.
- 2026-10-15 — `baseline_clean` deletes relationships in batches before the nodes, waits up to `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` (900 s, was 30 s) per MISP event delete and has a 60-minute timeout (was 20); the collectors and `full_neo4j_sync` refuse to run after a failed clean; the MISP writer types generic hashes by length and strips 4-byte UTF-8.
- 2026-10-15 — ThreatFox and URLhaus read their whole window up to their own per-run caps instead of a cut at 200.
- 2026-10-15 — The sync writes `ATTRIBUTED_TO` from an OTX pulse only when the pulse's actors are one actor; the OTX collector marks pulses naming several actors (`several_actor_pulses`).
- 2026-10-15 — Incremental syncs write only changed attributes (a sync right after a baseline re-merged every baseline attribute, about 2.5 h for about 366k items); `force_sync` conf; the baseline's `full_neo4j_sync` stamps the sync state file (the first sync after a baseline ran in full or re-read every attribute since the previous baseline); the `clear_checkpoints` conf key has no effect and a fresh baseline clears the incremental cursors.
- 2026-10-14 — NVD incremental runs read by `lastModified` cursor.
- 2026-10-12 — `collect_malwarebazaar` (flag-guarded) in `edgeguard_daily` and the baseline's `tier2_feeds`; `EDGEGUARD_SYNC_MIN_EVENTS` and the partial-loss failure rules of the Neo4j sync.
- 2026-10-12 — `wipe_scope` conf key (shared-database contract); `./state` and `./checkpoints` bind-mounted into the Airflow container.
- 2026-10-11 — Device, NetworkService, SoftwareVersion, Application, Role and User carry no UNIQUE constraint, and `create_constraints` drops one an earlier build created.
- 2026-10-10 — Cross-item relationships are built per source report (the same OTX pulse inside one event) instead of across a whole MISP event, because EdgeGuard events are per-source, per-day buckets; the flag-guarded CISA ICS collector (`collect_cisa_ics`) runs in `edgeguard_daily` and the baseline's `tier2_feeds`.
- 2026-10-10 — Airflow base image 3.3.2 instead of 3.2.0, because the CI image scan failed on six critical findings (`apache-airflow` CVE-2026-33264 and CVE-2026-42252, PyJWT CVE-2026-102268, anyio CVE-2026-63374, SFTP provider CVE-2026-50203, snowflake-connector CVE-2026-15925) and a patch bump to 3.2.2 would have left CVE-2026-33264 open; no DAG code had to change, and the DAGs import `TriggerRule` from `airflow.task.trigger_rule` (with a fallback) to avoid the 3.3 deprecation warning, and `pip-audit -r requirements.txt` became clean with no ignore list (airflow-core 3.3 requires `starlette>=1.0.1`).
- 2026-06-11 — The sync state file is stamped with the sync's start time instead of its completion time (the completion stamp landed just under the former 72 h guard and skipped every other scheduled sync, about 48 h of MISP events per cycle), the incremental window is derived from the state file, and the DAG-side backup gate (`backup_check_passed_cli`, `skip_backup_check`) checks the backup timestamp.
- 2026-04-28 — Baseline task chain corrected: top-level task IDs carry no `baseline_` prefix, the tier-2 group is `tier2_feeds`, there is no `tier3_low_freq` group, and `baseline_postcheck` is in the chain.
- 2026-04-23 — The baseline's critical-chain tasks (`baseline_clean`, `full_neo4j_sync`, `build_relationships`, `run_enrichment_jobs`) have `retries=0`.
- 2026-04-20 — Tier-1 baseline collectors run sequentially after the 2026-04-19 overnight baseline lost about 14.7% of NVD attributes to MISP HTTP 500s; unknown baseline conf keys log `[BASELINE_CONF]` after a trigger with `{"days": 730}` silently fell back to the defaults; typos of the destructive key fail `baseline_clean`.
- 2026-04-19 — The `edgeguard baseline` / `edgeguard fresh-baseline` wrappers trigger the baseline DAG with the matching conf instead of running a local pipeline.
- 2026-04-15 — Baseline NVD/OTX, `build_relationships` and `run_enrichment_jobs` timeouts raised from 3 h to 5 h after baseline re-runs hit the 3 h limit; MITRE technique edges split from a single `USES` into `EMPLOYS_TECHNIQUE` and `IMPLEMENTS_TECHNIQUE`.
- 2026-04-15 — Airflow upgraded from 2.11 to 3.2, because CVE-2026-27205 (flask), CVE-2025-32962 and CVE-2025-58065 (flask-appbuilder) and CVE-2025-66236 (apache-airflow) had fixes only in the 3.x line and 2.11 is end of life; the 3.2.0 image bundled Flask 2.2.5 (the FAB provider pinned `flask<2.3`), so CVE-2026-27205 stayed open there, mitigated by the loopback-only API binding, until the 3.3.2 base.
- 2026-03-28 — First published version; `misp_health_check` is a single-pass `PythonOperator` instead of a `PythonSensor` that blocked until the MISP workers were healthy.
