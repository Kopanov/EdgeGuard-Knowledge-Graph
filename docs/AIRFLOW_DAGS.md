# EdgeGuard Airflow DAGs (operations guide)

**Purpose:** Automated ETL pipeline for threat intelligence collection and synchronization.  
**DAG Python files:** repository `dags/` directory.
**Airflow version:** Apache Airflow 3.3.x — base image `apache/airflow:3.3.2-python3.12` (see [Airflow version and image](#airflow-version-and-image)).

**Where you are in the docs:** Step **2** of the operator path — read after **[SETUP_GUIDE.md](SETUP_GUIDE.md)**. **Next →** **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for a safe first **`edgeguard_baseline`**. Full order: [README.md § Recommended reading order](../README.md#-recommended-reading-order-new-operators).

---

## Airflow version and image

| Item | Value |
|---|---|
| Base image | `apache/airflow:3.3.2-python3.12` (`Dockerfile.airflow`) |
| Custom image tag | `edgeguard-airflow:3.3.2-python3.12` (`docker-compose.yml`) |
| Python packages | `apache-airflow[postgres]~=3.3` + `apache-airflow-providers-standard~=1.5` (`requirements.txt`, `pyproject.toml`). The image installs `requirements-airflow-docker.txt`, which carries the same `fastapi!=0.136.3` exclusion as the root manifest, because the 3.3.2 base bundles that flagged release |
| Version check | `RECOMMENDED_VERSIONS["airflow"] = "3.3"`, so `edgeguard doctor` reports Airflow `3.3.x` without a drift warning |
| Operators | `airflow.providers.standard.operators.bash.BashOperator`, `airflow.providers.standard.operators.python.PythonOperator` / `ShortCircuitOperator` |
| `Variable`, `TaskGroup` | `airflow.sdk.Variable` and `airflow.sdk.TaskGroup`, each with a `try/except ImportError` fallback; `Variable.get(...)` takes its default positionally (2.x and 3.x both accept it) |
| `TriggerRule` | `airflow.task.trigger_rule.TriggerRule`, with an `ImportError` fallback to `airflow.utils.trigger_rule` (which emits `DeprecatedImportWarning` on 3.3.x); the DAGs load with zero warnings on 3.3.2 |
| Schedule keyword | `DAG(schedule=…)`; Airflow 3.x has no `schedule_interval` |
| API server port | `AIRFLOW__API__PORT` (the port is in the `[api]` section in 3.x); `docker-compose.yml` binds the API server to `127.0.0.1:8082` |
| API server JWT secret | `AIRFLOW__API_AUTH__JWT_SECRET`, read from the `.env` variable `AIRFLOW_API_AUTH_JWT_SECRET` |

`airflow.exceptions.AirflowException`, `from airflow import DAG` and `pendulum` work identically on 2.x and 3.x. EdgeGuard's REST API, NATS and GraphQL do not depend on the Airflow version.

**Why the 3.3 line:** CI scans the image with `trivy image --severity CRITICAL`, and `CVE-2026-33264` in `apache-airflow` (code execution via unsafe serialized-DAG deserialization) is fixed only from 3.3.0. The 3.3.2 constraints ship PyJWT 2.14.0, anyio 4.15.1, the SFTP provider 6.0.1, snowflake-connector 4.7.3 and `apache-airflow-providers-fab` 3.9.0, which allows Flask 3: the image runs **Flask 3.1.3**, which clears CVE-2026-27205. `requirements.txt` lists only `apache-airflow[postgres]` and `apache-airflow-providers-standard`, neither of which pulls the FAB provider. `pip install -r requirements.txt` therefore installs no Flask, and `pip-audit -r requirements.txt` does not see it. The Docker image bundles FAB (and with it Flask), because the upstream `apache/airflow` image ships the FAB auth manager. The API server is bound to loopback only (`127.0.0.1:8082`), so the web attack surface is not reachable from the network on a production host.

**pandas:** pandas 3 changes how DataFrame XComs are stored (Airflow 3.3.1 release note). The image pins `pandas~=2.2` and no EdgeGuard task stores a DataFrame XCom, so this matters only for a new task that returns a DataFrame.

**JWT secret.** The Airflow 3.x API server fails to start with `The value api_auth/jwt_secret must be set!` when the secret is missing, whatever the auth manager (it signs the `POST /auth/token` and execution-API tokens; this stack uses the Simple auth manager). Generate it once:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
# Add the output to .env:
#   AIRFLOW_API_AUTH_JWT_SECRET=<value>
```

Keep the value stable across restarts so issued tokens stay valid. `docker-compose.yml` reads it via `${AIRFLOW_API_AUTH_JWT_SECRET:-}` and sets `AIRFLOW__API_AUTH__JWT_SECRET` inside the container. Apply a new value with `docker compose up -d --force-recreate airflow`: a plain `up -d` can reuse a cached container that does not know the variable, and the API server log then shows the error above.

**Process topology:** the `airflow` service runs a single `airflow standalone` process; Airflow 3's process manager runs the scheduler, API server, DAG processor and triggerer inside it.

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
| `edgeguard_daily` | Daily at 2 AM | Daily feeds | MITRE, CISA ICS Advisories (flag-guarded, `EDGEGUARD_ENABLE_CISA_ICS`), ThreatFox, AbuseIPDB, URLhaus, Feodo, SSLBlacklist, MalwareBazaar (flag-guarded, `EDGEGUARD_ENABLE_MALWAREBAZAAR`) |
| `edgeguard_neo4j_sync` | Every 72 h (`timedelta(days=3)`) | MISP → Neo4j sync + `build_relationships` + `run_enrichment_jobs` | All sources |

**Concurrency and timeout guards (all 6 DAGs):**

| DAG | `max_active_runs` | `dagrun_timeout` | Notes |
|-----|-------------------|------------------|-------|
| `edgeguard_pipeline` | 1 | 5h 30m | Covers OTX with full retry chain |
| `edgeguard_medium_freq` | 1 | 5h | CISA + VT with retries; both take a slot of the shared collector pool, so they run in parallel only while it has a free slot |
| `edgeguard_low_freq` | 1 | 8h 30m | NVD with full retry chain |
| `edgeguard_daily` | 1 | 8h 30m | 8 collectors with retries on the shared collector pool (`EDGEGUARD_COLLECTOR_POOL_SLOTS`, default 4); the timeout is sized for all 8 in parallel, and if every attempt reached its 2h `execution_timeout` they would need two rounds (about 12h 45m), so the second round would be skipped; real daily runs take minutes (`collect_cisa_ics` and `collect_malwarebazaar` are no-op skips while their flags are off) |
| `edgeguard_baseline` | 1 | 32h | Full historical collection + sync. `tier2_feeds` also runs `collect_cisa_ics` (baseline load of the 24-month advisory history; no-op skip while `EDGEGUARD_ENABLE_CISA_ICS` is off) and `collect_malwarebazaar` (recent export only; no-op skip while `EDGEGUARD_ENABLE_MALWAREBAZAAR` is off) |
| `edgeguard_neo4j_sync` | 1 | 68h | Full sync + relationships + enrichment. Every task of the chain failing on all three attempts takes 55h 57 min (`run_neo4j_sync` 3 × 8h + 2 × 5 min, `build_relationships` and `run_enrichment_jobs` 3 × 5h + 2 × 5 min each, the checks 1h 27 min), plus 20% ≈ 67h. A requested full sync stands until it succeeds, so it may use all three attempts; a long run only delays the next scheduled one (`max_active_runs=1`) |

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
`misp_health_check` → `source_key_check` → `baseline_acquire_lock` → `baseline_clean` (no-op or wipe — gated on `dag_run.conf`) → `baseline_start` → `tier1_core` (TaskGroup) → `tier2_feeds` (TaskGroup) → `full_neo4j_sync` → `build_relationships` → `run_enrichment_jobs` → `baseline_postcheck` → `baseline_complete` → `baseline_release_lock` (only after a successful run). **There is no `tier3_low_freq` TaskGroup** in the baseline DAG; the daily-tier collectors live in the `edgeguard_daily` *incremental* DAG, not the baseline. **Top-level task IDs do not carry a `baseline_` prefix** — `airflow tasks state edgeguard_baseline full_neo4j_sync` is the right shape (NOT `baseline_full_neo4j_sync`).

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
- Calls `src.baseline_clean.reset_baseline_data(wipe_scope=…)` — atomic 3-step wipe (checkpoints → Neo4j → MISP DELETE) followed by a settle period and a verify-poll until all three datastores read zero. The Neo4j step deletes only EdgeGuard-managed nodes (`clear_edgeguard_managed`) unless `dag_run.conf.wipe_scope` is `"all"` (`clear_all`), so partner data on a shared ResilMesh database is kept by default.
- Has `retries=0` and `trigger_rule=ALL_SUCCESS` — destructive task does NOT auto-retry on failure (would re-execute the wipe), and ONLY runs after `misp_health_check`, `source_key_check` and `baseline_acquire_lock` have succeeded (its direct upstream is `baseline_acquire_lock`).
- **Refusals before the wipe:** a typo'd destructive key (see *Unknown keys* below) and, for a fresh baseline, a `wipe_scope` other than `edgeguard` / `all` or the backup-timestamp gate fail the task and wipe nothing. The gate requires `EDGEGUARD_LAST_BACKUP_AT` within `EDGEGUARD_BACKUP_MAX_AGE_HOURS` (default 240 h); it is skipped when Neo4j and MISP are both empty (every probe succeeded), with `backup_check_passed_cli` or with `skip_backup_check`. Such a refusal also releases the baseline lock, so the corrected run is not refused by it: re-trigger with a corrected conf, or clear `baseline_clean` after fixing the environment (it takes the lock again before the wipe).
- **Wipe on a large graph:** the Neo4j step deletes relationships first, in batches of 50,000, then the nodes in batches of 10,000, because a node batch holding hub nodes ran a 2 GB heap out of memory on a 2.7M-relationship graph. Each MISP event delete waits up to **`EDGEGUARD_MISP_DELETE_TIMEOUT_SEC`** (default **900** s, because MISP deletes an event's attributes inside the request); `docker-compose.yml` forwards the setting, and `edgeguard clear misp` and `scripts/clear_misp.py` use the same timeout. The task's `execution_timeout` is **60 minutes**.
- **A failed clean stops the chain:** the collector tasks of `tier1_core` / `tier2_feeds` and `full_neo4j_sync` keep `trigger_rule=ALL_DONE` for per-source resilience, but each refuses to run unless `baseline_start` succeeded in this run; a refusal raises `AirflowFailException`, so the task fails without its retry. The decision uses the task states of the run as Airflow 3 reports them; only where Airflow reports none (Airflow 2, or a failed call) does it fall back to the XCom marker `baseline_start` returns on success. On Airflow 3, `baseline_postcheck` likewise fails when `full_neo4j_sync`, `build_relationships` or `run_enrichment_jobs` did not succeed. See [RUNBOOK.md § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck).
- **The chain checks the baseline lock:** the collectors refuse (`AirflowFailException`) while no baseline holds `checkpoints/baseline_in_progress.lock`, and `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` refuse unless the lock names this DAG run. `baseline_start`, and `baseline_clean` before the wipe, take the lock again for this run, so after a refusal clear `baseline_start` and then the refused task. A refusal of `baseline_clean` before the wipe releases the lock (bullet above). A failed run keeps the lock until it is resumed and succeeds, or until the sentinel reaches the age cap (`EDGEGUARD_BASELINE_LOCK_MAX_AGE_SEC`, default 48 h). While a baseline holds the lock, the scheduled collectors skip with `skip_reason_class=baseline_in_progress` (a green task) and the tasks of `edgeguard_neo4j_sync` skip (see *Airflow task: `run_neo4j_sync`* below and [RUNBOOK.md](RUNBOOK.md)).

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

**CLI vs DAG equivalence:** the operator commands `edgeguard fresh-baseline --days <N>` and `edgeguard baseline --days <N>` shell out to the Airflow CLI to trigger this DAG with the appropriate `dag_run.conf` — they do NOT run a local pipeline. The destructive command (`edgeguard fresh-baseline`) prompts for typed `FRESH-BASELINE` confirmation before triggering; the additive command (`edgeguard baseline`) does not.

**CLI-only `python src/run_pipeline.py --baseline` direct execution:** this legacy path runs the pipeline IN-PROCESS rather than triggering the DAG. It has one operator-visible asymmetry — `build_relationships` failures log a `WARN` and continue (so Step 5c enrichment still runs); the DAG raises `AirflowException` on the same failure. The CLI's degraded-mode behavior is documented in source comments at `src/run_pipeline.py:1565+`. Operators running the legacy CLI path should grep logs for `DEGRADED MODE` to detect missing link edges. The `edgeguard fresh-baseline` and `edgeguard baseline` wrappers inherit DAG semantics — no asymmetry there.

**Metrics (optional):** `edgeguard_metrics_server` (+ `…_scheduled`) and **`edgeguard_metrics_helpers`** in `dags/edgeguard_metrics_server.py` — default scrape URL `http://127.0.0.1:8001/metrics` (`EDGEGUARD_METRICS_HOST` / `EDGEGUARD_METRICS_PORT`).

**Note:** “Items/Run” figures below are **order-of-magnitude defaults**; effective limits come from `get_effective_limit()` (`EDGEGUARD_INCREMENTAL_LIMIT`, `EDGEGUARD_MAX_ENTRIES`, baseline Airflow Variables).

---

## Source Schedules

### By Frequency

#### High Frequency (Every 30 minutes)
| Source | DAG | Rate Limit | Items/Run |
|--------|-----|------------|-----------|
| AlienVault OTX | `edgeguard_pipeline` | 30 req/min | 50 pulses |

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
| MITRE ATT&CK | `edgeguard_daily` | No limit | 500 items |
| CISA ICS Advisories (`collect_cisa_ics`) | `edgeguard_daily` | Polite: ≤ 4 req/s, ≤ `EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN` (1200) files | Advisories changed since the cursor (`changes.csv`); **task is skipped with success unless `EDGEGUARD_ENABLE_CISA_ICS=true`** |
| ThreatFox | `edgeguard_daily` | No limit | The IOCs of the last 7 days (about 7,400), at most `EDGEGUARD_THREATFOX_MAX_PER_RUN` (10,000), the newest kept when the cap is reached |
| AbuseIPDB | `edgeguard_daily` | At most one blacklist request per run, none when the run reuses the answer fetched earlier on the same UTC day (free plan: at most 10,000 addresses per request, 5 blacklist requests per UTC day) | The blacklist, at most `EDGEGUARD_ABUSEIPDB_MAX_PER_RUN` (10,000) addresses, the request's `limit` |
| URLhaus | `edgeguard_daily` | No limit | The URLs of `csv_recent` (last 30 days, about 34,000), at most `EDGEGUARD_URLHAUS_MAX_PER_RUN` (50,000), the newest kept when the cap is reached |
| Feodo Tracker | `edgeguard_daily` | No limit | The servers of the 30-day list (5 on 2026-10-12; the complete history on a baseline), at most `EDGEGUARD_FEODO_MAX_PER_RUN` (15,000), those seen online most recently kept when the cap is reached |
| SSL Blacklist | `edgeguard_daily` | No limit | The whole blacklist (10,964 certificates on 2026-10-12), at most `EDGEGUARD_SSLBL_MAX_PER_RUN` (20,000), the newest by `Listingdate` kept when the cap is reached |
| MalwareBazaar (`collect_malwarebazaar`) | `edgeguard_daily` | One export download per run (about 450 KB) | Up to `EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN` (500) sha256 hashes of the last 48 hours, labelled samples first; **task is skipped with success unless `EDGEGUARD_ENABLE_MALWAREBAZAAR=true`** |

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
| CISA ICS Advisories | `CISAICSCollector` | `cisa_ics_collector.py` | Source-asserted CISA sector → fixed table (Energy / Healthcare and Public Health / Financial Services); **flag-guarded**: `run_cisa_ics_collection` logs "disabled by flag" and returns a skipped status (success, 0 items) unless `EDGEGUARD_ENABLE_CISA_ICS=true` |
| MalwareBazaar | `MalwareBazaarCollector` | `global_feed_collector.py` | Malware family label (`signature`); **flag-guarded**: `run_malwarebazaar_collection` / `run_baseline_malwarebazaar` log "disabled by flag" and return a skipped status (success, 0 items) unless `EDGEGUARD_ENABLE_MALWAREBAZAAR=true` |

### Placeholder Collectors (Not Yet Active)

| Collector | Source File | Notes |
|-----------|-------------|-------|
| Energy | `energy_feed_collector.py` | Placeholder; member-only feeds (EE-ISAC) not planned, no membership budgeted |
| Healthcare | `healthcare_feed_collector.py` | Placeholder; member-only feeds (Health-ISAC, HC3) not planned, no membership budgeted |

---

## MISP Tagging

### Event level (new events from `MISPWriter`)

| Tag | Role |
|-----|------|
| **`EdgeGuard`** | Platform provenance (e.g. ResilMesh / EdgeGuard pipeline). **Only** event-level tag added on create. |

**`Event.info`** uses **`EdgeGuard-{source}-{date}`** (e.g., `EdgeGuard-nvd-2026-03-29`). Zone classification lives on attribute-level tags (`zone:Finance`, `zone:Healthcare`), not in the event name. A single event can contain multi-zone attributes. See [MISP_SOURCES.md](MISP_SOURCES.md).

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
- **Skip guard:** `check_sync_needed` skips a run when the last successful sync started less than **24 h** ago (`NEO4J_SYNC_MIN_GAP`). It exists for the run right after another sync — the baseline's `full_neo4j_sync` or a manual `force_sync` run, which stamp the state file. Of what that sync read, such a run re-reads only the attributes MISP stamped in the window overlap before its start (`EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h; step 2 of *Airflow task: `run_neo4j_sync`* below), but it would also repeat `build_relationships` and the enrichment jobs on the graph just built, which is why the guard exists. 24 h is longer than the rest of a baseline after its full sync starts (16 h 49 min with every task at its limit, the lock held to the end) and shorter than the shortest gap a regular run sees (72 h minus 16 h 42 min, the latest the previous sync can start: two failed 8 h attempts, two retry delays and the attempts of the two tasks before it), so a regular run is never skipped, also after a sync that succeeded on a retry. The first scheduled sync after a baseline or a forced sync starts between 24 h and 96 h after it. The interval and the guard are fixed in `dags/edgeguard_pipeline.py`.
- **Process:** MISP → Neo4j using MERGE (upsert)
- **Monitoring:** `EdgeGuardNeo4jSyncStale` fires when no sync, scheduled or baseline, has completed in 122 h (the longest gap between two sync starts, 96 h after a baseline's or a forced sync, plus the next sync's longest run: 32 min of `check_sync_needed` / `neo4j_health_check` attempts and three attempts of `run_neo4j_sync`'s 8 h limit with two retry delays; 120 h 42 min, plus about an hour for the scheduler); `edgeguard_last_success_timestamp{source="misp_to_neo4j"}`, stamped when a sync connects, is watched with 98 h by `EdgeGuardCollectionStale` (96 h plus the 32 min, with margin). `tests/test_monitoring_signals.py` simulates the schedule through the real guard and derives both from the tasks' limits. See [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md).

### Shared state directories

`./state` (sync state file) and `./checkpoints` (collector checkpoints, baseline lock sentinel) are bind-mounted into the Airflow container at `/opt/airflow/state` and `/opt/airflow/checkpoints`. The `airflow-init` service creates them owned by the container user (uid 50000) before Airflow starts. The host CLI (`edgeguard doctor`, `monitor`, `stats`, `checkpoint status`) therefore reads what the DAGs wrote; host-side writes or deletes (`edgeguard checkpoint clear`) go through `docker compose exec airflow …` unless the host user owns the directories.

### Airflow task: `run_neo4j_sync` (`edgeguard_neo4j_sync` DAG)

1. **`check_sync_needed`** (`ShortCircuitOperator`) — if the last successful sync (state file `state/edgeguard_last_neo4j_sync.json` under `EDGEGUARD_STATE_DIR`; `./state` is bind-mounted into the Airflow container, so the host CLI reads the same file) started less than **24 h** ago (`NEO4J_SYNC_MIN_GAP`; see *Skip guard* above), it **short-circuits** and **skips** `run_neo4j_sync` and **all downstream tasks** (`build_relationships`, `run_enrichment_jobs`, …). So a “green” DAG run can mean **sync did not run** (skipped); with the 72 h schedule that happens only after a baseline's or a forced sync. The state file holds the start time of the last successful sync, not its completion time (step 2). A manual trigger with **`dag_run.conf={"force_sync": true}`** (`airflow dags trigger edgeguard_neo4j_sync --conf '{"force_sync": true}'`) bypasses this check and the `SKIP_NEXT_NEO4J_SYNC` flag. `check_sync_needed` also skips while a baseline holds the baseline lock, and `force_sync` does not bypass that. `run_neo4j_sync` (each attempt), `build_relationships` and `run_enrichment_jobs` check the lock again when they start and skip while a baseline holds it, because a baseline may take the lock after `check_sync_needed` ran. Such a skip stamps no state file and leaves `NEO4J_FULL_SYNC` and `SKIP_NEXT_NEO4J_SYNC` set, and the downstream tasks skip with it.
2. **`run_neo4j_sync`** — imports **`MISPToNeo4jSync`**, chooses **full** vs **incremental** sync (first-ever run or Airflow Variable **`NEO4J_FULL_SYNC=true`** → full; otherwise incremental). The incremental window is **derived from the state file** (`last_sync` − `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS`, default 1 h, an overlap for clock skew and in-flight writes), so it covers everything since the last successful sync even across skipped runs, paused DAGs, or an Airflow outage; if the state file is unreadable it falls back to the fixed `EDGEGUARD_SYNC_INTERVAL_DAYS`+1d window. MISP stamps attribute timestamps itself, and the 1 h default holds because the collectors and the sync use the same MISP (one `MISP_URL`) and the Airflow and MISP hosts keep their clocks synchronised (NTP). A sync that reads a MISP filled by MISP-to-MISP synchronisation or import keeps the origin's timestamps and needs an overlap above the copy delay: an attribute that arrives later than the overlap falls before every later window and is never synced, while the run still succeeds. A clock difference between the two hosts larger than the overlap skips attributes the same way. An overlap from 0 up to 60 s is raised to 60 s with a warning (MISP timestamps are whole seconds); a non-numeric or negative value, or one above 720 h, logs a warning and uses the default, so a bad setting never fails the run. Calls **`sync.run()`**, then on success stamps the state file with the sync **start** time (not its completion time) and updates metrics. The task log states the mode, the reason and the attempt number at the start (`Sync mode: FULL — …` / `Sync mode: incremental — …`). **`NEO4J_FULL_SYNC` is cleared only after the full sync succeeded**, so every retry (`retries=2`) of a requested full sync runs in full: a failed or timed-out attempt never retries as an incremental run that stamps the state file and leaves the requested repair incomplete. If clearing the Variable fails after a successful sync, a warning is logged and the next scheduled run is a full sync again. The task's `execution_timeout` is **8h**: a full sync of a 730-day MISP takes about 6h (the limit of the baseline DAG's `full_neo4j_sync`), plus a third, because a limit at the estimate could fail every attempt of a request that stands until it succeeds. While `NEO4J_FULL_SYNC` stays set, no incremental sync runs; after the last failed attempt the task's failure callback (`_on_neo4j_sync_failure`, after the common `_on_task_failure`) logs an `[ALERT]` at ERROR saying so and how to clear the Variable, sends it to Slack when enabled and counts `edgeguard_pipeline_errors_total{error_type="full_sync_request_pending"}`, which the Prometheus alert `EdgeGuardNeo4jFullSyncRequestPending` reads ([RUNBOOK.md](RUNBOOK.md)). A manual `force_sync` run is incremental unless `NEO4J_FULL_SYNC` is set, and a first run (no state file) stays a full sync on retry because the state file is written only on success. The baseline DAG's `full_neo4j_sync` stamps the same file with its start time, so the first scheduled sync after a baseline is incremental from that point (minus the overlap).
   - **Incremental runs write only changed attributes:** the event index keeps every event *modified* in the window, but only attributes whose MISP `timestamp` is inside the window are written (log line `Event N: X of Y attributes changed since …`). Unchanged items of the same OTX pulse join only the report-scoped link build; finding them parses the event's unchanged attributes (CPU only, no Neo4j writes). With the 1 h overlap, the first incremental sync after a baseline re-merges only what the baseline wrote in its last hour. An edit that changes only event-level tags is not picked up incrementally, and an incremental run does not repair a Neo4j restored from a dump older than MISP — use `NEO4J_FULL_SYNC=true` for both. `EDGEGUARD_SYNC_ATTRIBUTE_FILTER=false` switches to whole-event processing. A full sync does not set `SKIP_NEXT_NEO4J_SYNC`; an operator-set flag skips the next incremental run once.
   - **OOM on very large attribute sets:** `sync_to_neo4j()` merges in **Python-side chunks** (default **500** items per chunk; no pause between chunks unless `EDGEGUARD_QUERY_PAUSE_SECONDS` is set). Events with **>5000 attributes** are automatically **streamed in pages** of 5000 with `gc.collect()` between pages. Set **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** lower on the Airflow worker if the process is still killed. Default **`AIRFLOW_MEMORY_LIMIT`** is **12g** (100K+ attribute events need 8-12GB for PyMISP JSON parsing).
   - **MISP push accounting (collector tasks):** after each batch POST the writer reconciles the pushed attributes against the attribute list MISP returns for the event. Attributes absent from the response are logged (`[UNCONFIRMED]`) and counted in the writer stats (`attributes_unconfirmed`); a response without an attribute list marks the batch `batches_unverified`. With **`EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING=true`** (forwarded by `docker-compose.yml`) unconfirmed attributes also count as failed pushes and feed **`EDGEGUARD_MISP_MIN_SUCCESS_RATE`**; enable it after a live check shows no spurious unconfirmed attributes, because MISP normalises some values on save. MISP answers a batch with HTTP 200 while dropping attributes that fail its validation, so the writer avoids the known causes: a generic `hash` is typed `md5` / `sha1` / `sha256` / `sha512` by the length of its hex digest, characters outside the Basic Multilingual Plane (4-byte UTF-8, which MISP's 3-byte `utf8` columns reject for the whole batch with HTTP 500) are stripped from comments and tag names, and an attribute whose value needs them is skipped with a warning and counted as failed. See [COLLECTORS.md](COLLECTORS.md) § *MISP push: attribute types and characters*. Items no MISP attribute can be built from (an unknown item type, an empty value, CVE id, name or ATT&CK id) are reported by one `[CONVERT] N item(s) could not be converted to a MISP attribute, M of them counted as failed (…): <source>: <dropped> of <given> item(s), [not ]counted as failed (<count> <reason>, …); …` line per push (a WARNING, an ERROR when some count as failed) and the writer stats `items_not_converted` and `items_not_converted_failed`. They count as failed pushes only when the drop is systemic for the source in that push: all of its items, or at least half of them (`CONVERT_FAILED_MIN_SHARE` = 0.5 in `src/collectors/misp_writer.py`, where the value is justified). A source whose payload stops converting therefore fails its task, and the error names both causes (`… failures are attributes MISP did not store and, for a source all or at least half of whose items no MISP attribute could be built from, those items, logged by the writer as [CONVERT]`), while a few bad records neither turn a run red nor hold a cursor: the CISA ICS and NVD-baseline cursors and the MITRE ATT&CK ETag move only after a push without failures, and the OTX cursor after a push with failures advances up to the oldest pulse with an item the writer lists as unstored (a failed batch or event lookup, or a systemic conversion drop, whose items hold it until the collector is fixed). A (source, date) group without attributes, or one MISP already holds entirely by a complete cross-event listing, neither looks up nor creates the day's event (`MISP push <source> (<date>): all N attributes already present under <tag> … no event looked up or created`); see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*.
   - **Empty or implausibly small windows:** a window with **fewer than `EDGEGUARD_SYNC_MIN_EVENTS`** events (default **`1`**; forwarded to the `airflow` service by `docker-compose.yml`, documented in `.env.example`) is a **failed** run: the sync logs an **ERROR**, records no success, processes nothing and `run_neo4j_sync` fails, so the state file is not stamped and the next run covers the window again. Scheduled syncs are at least 24 h apart and the collectors write to MISP every day (OTX every 30 minutes), so an empty window means nothing was collected; a sync forced minutes after another can also find none. **`0`** disables the guard: a zero-event window is then logged as a **WARNING**, recorded in the sync stats (`zero_events`, `events_index_total`) and reported as a successful run.
   - **Metrics after a successful sync:** the duration is observed once, `edgeguard_neo4j_sync_last_success_timestamp` is stamped, and the node count of every label EdgeGuard writes is read with one read-only query and set as `edgeguard_neo4j_nodes{label, zone="all"}`; a label without nodes is recorded as 0. A failed count logs a warning and keeps the previous values. `run_enrichment_jobs` reads the counts again after a successful enrichment (the Campaign nodes it creates). The baseline DAG's `full_neo4j_sync` records the duration and the stamp; the baseline's node counts are read at the end of a successful `run_enrichment_jobs` (baseline), because before the enrichment a fresh baseline has no Campaign nodes and a 0 would fire `EdgeGuardNeo4jLabelDropBig`.
   - **Partial loss is a failure:** `sync.run()` returns `False` (and `run_neo4j_sync` fails, with the reason in the task log) when any event could not be fetched or processed after retries (`events_failed`), when an item merge failed, or when relationship rows were dropped by permanent Neo4j batch failures (`relationships_failed`; grep **`[BATCH-PERMANENT-FAILURE]`** / **`[REL-ROWS-FAILED]`**). The same holds for an incomplete MISP event listing: a page of `/events/index` after the first that fails (a timeout or a dropped connection after the retries, with the `requests` error; any other failure with `_MispFallbackHardError`), a fallback `restSearch` page that is not JSON or fails with a request error that is not transient, any other error while listing (`_MispFallbackHardError`), and a listing that stopped at the page cap (`EDGEGUARD_MISP_MAX_PAGES` × `EDGEGUARD_MISP_PAGE_SIZE`, reason containing `MISP event index stopped at the page cap`). The run then does not stamp the state file past events it never listed. A green `run_neo4j_sync` therefore means that nothing in the window was lost.
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
| Source | ~12 logical sources (~19 rows with registry aliases) | source_id, name |

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

Device, NetworkService, SoftwareVersion, Application, Role and User carry **no** UNIQUE constraint, because their keys recur in ResilMesh's own data.

**Running again does NOT create duplicates** — MERGE on the natural key updates existing nodes, attaches a new `SOURCED_FROM` edge when a new source reports the same entity.

**MISP vs Neo4j:** The graph deduplication above is **independent** of MISP. The same logical IOC may still appear on **more than one** EdgeGuard MISP event (e.g., different dates); **`MISPWriter`** prefetch + cross-event-source dedup reduce **re-pushes** to MISP itself — see [COLLECTORS.md](COLLECTORS.md) § *Duplicate avoidance*. Partitioning MISP events by date range, so that no single event exceeds about 20K attributes, is not implemented.

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
- `dagrun_timeout` on all DAGs (prevents entire DAG runs from hanging indefinitely)
- `max_active_runs=1` on all DAGs (prevents concurrent run pile-up)
- `on_failure_callback` / `on_success_callback` for alerting and metrics; the listener plugin `plugins/edgeguard_dag_run_state.py` marks the DAG run in progress
- `ShortCircuitOperator` gates the Neo4j sync: it skips while a baseline holds the baseline lock or within 24 h of the last sync start, and runs on a corrupted state file
- Pipeline lock file (`checkpoints/pipeline.lock`) for CLI runs to prevent concurrent `run_pipeline.py` invocations
- `--fresh-baseline` performs a true clean slate: clears Neo4j graph data + MISP EdgeGuard events + checkpoints, incremental cursors included (`reset_baseline_data`), then re-collects from scratch. After it, a baseline whose NVD push succeeded stores its start as the NVD incremental cursor; the other scheduled collectors start from their first-run lookback (for example `EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS` for OTX).
- MISP dedup logging: `[DEDUP] All N items were already present` only when nothing failed and no item was dropped in conversion, N being the attributes found present, `[CONVERT]` for items no attribute could be built from (counted as failed only when they are all or at least half of a source's items in the push), `[SKIP]` when nothing new to push

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
# api-server + dag-processor + triggerer in one process). The API lives
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
airflow dags list-runs -d edgeguard_pipeline
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
```bash
airflow logs <task_id> <dag_run_id>
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| DAG runs stuck in "queued" | Check if DAG is paused: `edgeguard dag status`. Kill stuck runs: `edgeguard dag kill` |
| Collectors failing repeatedly | Find the cause in the task log and `edgeguard_collection_failures_total`, fix it and clear the failed task; each Airflow task starts with every circuit breaker CLOSED ([RESILIENCE_CONFIG.md](RESILIENCE_CONFIG.md)), and `edgeguard heal` resets only the breakers of its own CLI process |
| Need a completely fresh start | `edgeguard fresh-baseline --days N` — enforces the backup-timestamp gate + requires typed `FRESH-BASELINE` confirmation. See [`docs/BACKUP.md`](BACKUP.md) for the backup prerequisite. (The legacy `python src/run_pipeline.py --baseline --fresh-baseline` path has NO backup gate and NO typed confirmation — **do not use** unless you understand you're bypassing both.) |
| Airflow not reachable | `edgeguard doctor` retries after 10s; check container: `docker compose ps airflow` |
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

# Optional collectors (default off)
export EDGEGUARD_ENABLE_CISA_ICS=true    # CISA ICS advisories (edgeguard_daily → collect_cisa_ics); off → task skipped with success
# export EDGEGUARD_CISA_ICS_MAX_ADVISORIES_PER_RUN=1200   # per-run file cap (politeness toward GitHub raw)
# export EDGEGUARD_CISA_ICS_MIN_EXPECTED_ADVISORIES=50    # baseline sanity floor → transient skip + alert
export EDGEGUARD_ENABLE_MALWAREBAZAAR=true    # MalwareBazaar (edgeguard_daily → collect_malwarebazaar, baseline tier 2); off → task skipped with success
# export EDGEGUARD_MALWAREBAZAAR_MAX_PER_RUN=500   # per-run cap on samples pushed (labelled first; 0 = no cap)
```

---

## Troubleshooting

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

**Bare-metal / pip Airflow:** set **`AIRFLOW__DATABASE__SQL_ALCHEMY_CONN`** to **PostgreSQL** or **MySQL** (see [Apache Airflow database docs](https://airflow.apache.org/docs/apache-airflow/stable/howto/set-up-database.html)). Keep **`AIRFLOW__CORE__EXECUTOR`** aligned with your deployment (e.g. `LocalExecutor` with a proper metadata backend).

**Scaling:** for multi-worker production layouts, prefer the [official Airflow compose](https://airflow.apache.org/docs/apache-airflow/stable/howto/docker-compose/index.html) or your platform’s chart — still with Postgres/MySQL metadata.

### `misp_health_check` (MISP preflight)

**Behaviour:**

- **`misp_health_check`** is a **`PythonOperator`** that runs **once** per DAG run and **fails fast** (typical runtime: a few HTTP calls, &lt; ~1–2 minutes); it does not re-poke until MISP is healthy.
- Pass criteria use **`MISPHealthCheck.check_health()`** → **`healthy_for_collection`** (same as **`healthy`** for API+DB; workers optional), because many MISP instances have **workers down** while **API + DB** are fine. With **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`**, preflight also requires **`checks["worker_status"]`**. Return type is **`MISPHealthCheckResult`** in **`src/misp_health.py`** (dict-like: **`[]`**, **`.get()`**, **`in`** for field names). Same policy as **`run_pipeline_misp_spt.check_misp_health()`**.

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

**Self-signed MISP HTTPS (`certificate verify failed`):** EdgeGuard defaults to **verifying** TLS (**`EDGEGUARD_SSL_VERIFY`** defaults to **`true`**). For a **dev/lab** MISP with a self-signed cert, set **`EDGEGUARD_SSL_VERIFY=false`** on the **Airflow worker and scheduler** (same as other MISP env vars), then restart/recreate containers. Prefer installing your CA in the image over disabling verify in production. The env name **`SSL_CERT_VERIFY`** is **not** read; optional alias: **`SSL_VERIFY=false`** only if **`EDGEGUARD_SSL_VERIFY`** is unset or empty.

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
- A **“zombie”** message usually means the scheduler lost the task heartbeat (scheduler/worker restart, heavy CPU blocking, OOM, or platform kill) — check **`docker compose logs airflow`**, host **memory**, and whether the task process was killed. It is **not** always the same as hitting `execution_timeout`.

**Smoke test (recommended before a full baseline)**

See **[BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md)** for copy-paste **`.env`** examples (`EDGEGUARD_BASELINE_DAYS=7`, `EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000`) and restart steps. For a printable runtime checklist (Docker + `airflow dags trigger`), see [`scripts/runtime_smoke_checklist.sh`](../scripts/runtime_smoke_checklist.sh).

Or use Airflow **Variables** only: `BASELINE_DAYS` = **`7`**, `BASELINE_COLLECTION_LIMIT` = **`500`** or **`1000`**.

After Tier1 succeeds, remove env overrides or restore Variables for production.

**NVD resume:** Baseline NVD writes checkpoints under **`get_source_checkpoint("nvd")`** — a new run can resume windows; see `src/collectors/nvd_collector.py` and `baseline_checkpoint` usage.

### DAG Not Running
1. Check Airflow scheduler is running: `airflow scheduler`
2. Verify DAG file is in `$AIRFLOW_HOME/dags/`
3. **CI / local parse check:** from repo root run [`scripts/preflight_ci.sh`](../scripts/preflight_ci.sh) (`compileall`, `pytest`, Airflow `DagBag` load with `NEO4J_PASSWORD` set). Airflow 3.x has no `airflow dags validate` subcommand; use `airflow dags list-import-errors` after `airflow db migrate` if you use the full CLI.

### Collector Failures
1. Check API key configuration
2. Verify network connectivity to source
3. Check rate limits: `airflow logs <task_id>`

**Optional API keys (skip without failing the DAG):** If an optional key is unset, the corresponding task **succeeds** with a **warning** log, **`skipped: true`** in the return payload, Prometheus counter **`edgeguard_collector_skips_total`** (label `reason_class=...`), and **`edgeguard_indicators_collected_total{status="skipped"}`** (count 0). Supported optional sources:

| Env var | `reason_class` (metrics label) |
|---------|--------------------------------|
| **`ABUSEIPDB_API_KEY`** | `missing_abuseipdb_key` (also **`abuseipdb_auth_denied`** on HTTP 401/403) |
| **`OTX_API_KEY`** | `missing_otx_key` (also **`otx_auth_denied`** on 401/403) |
| **`VIRUSTOTAL_API_KEY`** | `missing_virustotal_key` (also **`virustotal_auth_denied`** on 401/403; **`virustotal_daily_budget`** / **`virustotal_rate_limited`** when the free-tier budget is spent; **`virustotal_candidates_unavailable`** when MISP cannot list hashes to enrich; **`virustotal_misp_unavailable`** when MISP is unreachable while the results are pushed) |
| **`THREATFOX_API_KEY`** | `missing_threatfox_key` (also **`threatfox_auth_denied`** on 401/403) |

Add keys when you want those feeds. Values that are **empty**, **whitespace-only**, or YAML **placeholders** from `credentials/config.example.yaml` are treated as unset. **ThreatFox** requires a free key from **https://auth.abuse.ch/** — without it the task **skips** (success) so the baseline DAG can continue.

**Baseline in progress (`baseline_in_progress`):** while a baseline holds the baseline lock, every scheduled collector task skips the same way (success, `skipped: true`, `skip_reason_class=baseline_in_progress`); a baseline collector that finds the lock held by another baseline stands down with the same reason class and an ERROR log line.

**Is a key accepted?** A key that is set but not accepted by its provider is a configuration error. Inside a run, OTX, VirusTotal, ThreatFox and AbuseIPDB return a *skipped* task that Airflow shows as successful, and a rejected **NVD** key fails the NVD task (NVD answers HTTP 404 `Invalid apiKey.`), which in a fresh baseline happens after the stores were wiped. Four places report it:

| Where | What it does |
|-------|--------------|
| `python src/edgeguard.py preflight` (section 1) and `python src/source_key_check.py [--json]` | One authenticated request per keyed source: `key accepted`, `key REJECTED` (with the provider's reason), `no key`, or `key NOT VERIFIED` (provider unreachable or rate-limited: never a verdict on the key). A rejected optional key is a warning (`--strict` fails); a rejected NVD key is an error. Exit code of `source_key_check.py`: `0` nothing rejected, `1` a rejected key (source skipped), `2` a key state that stops a baseline |
| Baseline DAG, task `source_key_check` (after `misp_health_check`, before `baseline_acquire_lock` and `baseline_clean`) | Logs one `[SOURCE-KEYS]` line per source (ERROR for a rejected key). Fails the run, with nothing locked or wiped, only for a rejected NVD key or for a source named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES` that cannot deliver. A missing or rejected key of an optional source never blocks |
| `scripts/preflight_baseline.sh` check `[12]` | The same check on launch day: rejected key = warning (NO-GO under `EDGEGUARD_PREFLIGHT_STRICT=1`), blocker = failure |
| Every collector run | A skip with `reason_class=*_auth_denied` is logged at ERROR (`[SOURCE-ACCESS] <SOURCE> NOT collected — the provider denied access`) and raises the Prometheus alert `EdgeGuardSourceAccessDenied` |

Cost of one check: OTX and NVD requests are outside any quota; VirusTotal one lookup, counted in the daily ledger; it is not sent when the ledger is exhausted, while a VirusTotal collector run is writing the ledger (last write under 5 minutes ago), or within 20 seconds of the previous check, and a collector run that starts within a minute after a check waits for the rest of that minute (the limit of 4 lookups a minute is shared; an HTTP 429 answer to the check is never recorded as the end of the collector's day, and the collector does not end its day on an HTTP 429 that follows a check within two minutes); AbuseIPDB one `check` request (1,000 a day; the 5-a-day `blacklist` quota the collector needs is not used); ThreatFox one query. A key value is never logged or printed. `EDGEGUARD_SOURCE_KEY_CHECK=false` disables the requests.

**Other optional HTTP feeds** (no API key required, but if the upstream returns **401/403**, the task **skips** instead of failing): **NVD** (`nvd_auth_denied`; a rejected `NVD_API_KEY` is HTTP 404 and **fails** the task with `NVD rejected NVD_API_KEY`), **CISA KEV** (`cisa_auth_denied`), **MITRE** (`mitre_auth_denied`, e.g. GitHub), **Feodo** (`feodo_auth_denied`; `feodo_circuit_breaker_open`; outages → `transient_external_error`), **SSL Blacklist** (`sslbl_auth_denied`; `sslbl_circuit_breaker_open`; outages → `transient_external_error`), **MalwareBazaar** (`malwarebazaar_auth_denied`; `malwarebazaar_disabled_by_flag` while `EDGEGUARD_ENABLE_MALWAREBAZAAR` is off; 429/5xx/timeouts → `transient_external_error`). **URLhaus** usually returns empty success if downloads fail; it is a public CSV endpoint.

**Collector allowlist (`EDGEGUARD_COLLECT_SOURCES`):** Optional comma-separated list of which collectors may run (e.g. `otx,nvd,cisa,mitre`). **Unset or empty** → all collectors run (subject to optional-key skips above). **`none`**, **`-`**, or **`0`** alone → no external collectors run; each collection task **succeeds** with **`skipped: true`** and **`skip_reason_class=collector_disabled_by_config`**. Unknown names are **logged and ignored**; if no valid names remain, behavior matches **unset** (fail-open). Applies to **Airflow** (`run_collector_with_metrics`) and **CLI** [`run_pipeline.py`](../src/run_pipeline.py) Step 2 (same canonical source keys as scheduled tasks, including both `virustotal` and `virustotal_enrich`). Implementation: [`src/collector_allowlist.py`](../src/collector_allowlist.py).

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
│   ├── run_pipeline.py           # Manual pipeline run
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
| Check status | `airflow dags list-runs -d edgeguard_pipeline` |
| View logs | `airflow logs <task_id> <run_id>` |

---

_Last updated: 2026-10-18_

## History

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
