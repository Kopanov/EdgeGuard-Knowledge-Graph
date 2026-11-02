# EdgeGuard command reference

This page lists the `edgeguard` CLI commands, the `make` targets, the installer options, the operator scripts and the pipeline modules that run on their own. The settings these commands read are in [CONFIGURATION.md](CONFIGURATION.md).

---

## Running the CLI

The CLI reads its settings from the environment only; it does not read `.env`.

- **Docker install.** `edgeguard` is not installed in the images. Run a command in the `airflow` container, which receives the settings `docker-compose.yml` forwards and reaches Neo4j and MISP by their container addresses:

  ```bash
  docker compose exec airflow python /opt/airflow/src/edgeguard.py <command>
  ```

- **Pip install.** `pip install -e .` (or `./install.sh --python`) installs the `edgeguard` command. `python src/edgeguard.py <command>` works the same from the repository root.
- **Host shell.** Export the settings first, and point the host at the published ports when `.env` names container addresses:

  ```bash
  set -a; . ./.env; set +a
  export NEO4J_URI=bolt://localhost:7687
  ```

  `MISP_URL` must also be reachable from the host. The Airflow commands (`dag`, the DAG list of `preflight` and `doctor`) need `AIRFLOW_API_PASSWORD` on the host; inside the container the CLI reads the password file the Simple auth manager generates. Without it, `preflight` warns "Could not query DAG list". The same warning appears while Airflow has registered no EdgeGuard DAG yet; `doctor` names that case ("No EdgeGuard DAGs found in Airflow"). The Airflow check of `baseline` and `fresh-baseline` needs no API credentials on the Compose host ([Baseline triggers](#baseline-triggers)).
- **Baseline triggers.** `baseline` and `fresh-baseline` trigger the DAG through `docker compose exec` when `docker compose`, run from the current directory, lists the `airflow` service as running (the Compose host, from the repository directory), and through the Airflow REST API otherwise (a bare-metal Airflow, or the CLI inside the `airflow` container), at `AIRFLOW_WEBSERVER_URL` with the API credentials.

Every command accepts `--help`. `edgeguard --update` is a synonym of `edgeguard update`.

---

## Readiness and diagnosis

| Command | Purpose |
|---|---|
| `preflight` | Readiness check before a run |
| `doctor` | Connectivity, schema and configuration diagnosis |
| `validate` | Configuration check |
| `monitor` | One-shot health snapshot |
| `heal` | Reset breakers, remove lock files no process holds, trigger the pipeline DAG |

- **`preflight`** runs seven check groups: the required settings and a live check of each source API key, Neo4j and APOC, MISP, Airflow (a scheduler or metadata database that Airflow does not report healthy is an error, a triggerer or DAG processor reported unhealthy a warning, an Airflow that does not answer a warning), disk space, checkpoints, and the circuit breakers of the CLI process itself (the pipeline's breakers live in each Airflow task and are not visible to it). It exits 0 when ready and 1 when a check fails; `--strict` also fails on warnings. `--json` prints JSON after the text report on standard output.
- **`doctor`** checks MISP and its PyMISP compatibility, Neo4j and its constraints, Airflow (reachability, then the status of the scheduler and metadata database, an issue when not healthy, and of the triggerer and DAG processor, a warning when reported unhealthy; it asks once more after 10 seconds while the scheduler is not healthy, as right after a restart) and the paused or active DAGs, the baseline window, NATS (only when `NATS_URL` is set), the memory settings, the API keys, disk space, the last sync, the configured sources and version compatibility. `doctor --memory` compares Neo4j's heap, page cache and transaction memory and the host RAM with the recommended values ([MEMORY_TUNING.md](MEMORY_TUNING.md)); it reads the `neo4j` container's settings through `docker compose exec`, so run it with the pip-installed CLI on the Compose host, from the repository directory. Inside the `airflow` container, which has no Docker CLI and receives none of the Neo4j memory variables, it reports the Neo4j rows as unknown.
- **`validate`** checks rate limits, passwords, the Neo4j schema and production issues, among them disabled TLS verification, an `EDGEGUARD_SSL_VERIFY` value it does not recognise (verification then stays on) and a default Neo4j password.
- **`monitor`** prints one snapshot (MISP, Neo4j and its counts, the last sync, the circuit-breaker file, Prometheus) and exits 1 when MISP reports an error or Neo4j is down.
- **`heal`** resets the circuit breakers of its own CLI process, checks EdgeGuard's lock files, removes the circuit-breaker state file, and triggers the `edgeguard_pipeline` DAG. It looks only at EdgeGuard's own lock files, by name, and prints each one it removed or kept. Its closing summary counts the lock files it removed and those it kept, an event-creation lock that a running collector holds aside, and says EdgeGuard is healthy only when there was nothing to repair or keep:
  - The event-creation lock of the MISP writer (`EDGEGUARD_MISP_EVENT_LOCK_PATH`, default `/tmp/edgeguard_misp_get_or_create_event.lock`) is a file that a collector locks with `flock`. Heal removes it only while it holds that lock itself and keeps it while a running process holds it, so `heal` is safe while collectors run; a collector that was waiting on the removed file takes the lock again on the file the path names now.
  - `checkpoints/pipeline.lock` (the PID of an in-process `run_pipeline.py` run) and the baseline lock `checkpoints/baseline_in_progress.lock` are reported with their holder and never removed: `run_pipeline.py` replaces a pipeline lock whose process is gone, and the baseline lock is released by a successful baseline or reaped by its liveness check and age cap ([RUNBOOK.md § Baseline-day protocol](RUNBOOK.md#baseline-day-protocol), which also gives the manual removal).
  - No other file is touched: other `*.lock` files in the repository root or the temporary directory stay.

---

## Data, checkpoints and DAGs

| Command | Purpose |
|---|---|
| `stats` | Node counts and the last sync |
| `checkpoint status` | Baseline progress and incremental cursors |
| `checkpoint clear` | Clear baseline checkpoints |
| `dag status` | Airflow DAG run states and the scheduler's health |
| `dag kill` | Force-fail stuck DAG runs |

- **`stats`**: `--full` adds node counts by sector and by source and the MISP event summary; `--by-zone` and `--by-source` show one breakdown each; `--misp` counts MISP events and attributes per source over every page of `/events/index` that matches `EdgeGuard`, up to 200 pages of 500 events (a warning names a stop at that cap), each event once (a MISP that ignores the query-string paging answers the whole listing on every page).
- **`checkpoint status`**: `--source` filters one source. **`checkpoint clear`** keeps the incremental cursors unless `--include-incremental` is given; `--source` clears one source and `--force` skips the confirmation.
- **`dag status`**: `--dag-id`, `--state` (`running`, `queued`, `failed`, `success`) and `--limit` (runs per DAG, default 5). It reads Airflow's health answer first: when the scheduler or the metadata database is not healthy (`airflow standalone` keeps the API server up when the scheduler dies), it still lists the runs, states that the runs shown as running or queued are not progressing, and exits 1. The recovery it prints keeps the runs: restore the metadata database first when it is unhealthy, let a running task end when the run's time allows (a restart runs it again from its start), restart Airflow, and do not trigger the runs again. A triggerer or DAG processor that Airflow lists without status runs no job of its own and is information. **`dag kill`** keeps the checkpoints; `--dag-id`, `--dry-run` and `--force`.
- `stats`, `checkpoint status`, `dag status` and `preflight` accept `--json`; the JSON follows a text banner on standard output.

---

## Baseline triggers

| Command | Purpose |
|---|---|
| `baseline --days N` | Trigger an additive baseline |
| `fresh-baseline --days N` | Trigger a destructive baseline |

- **Airflow check.** Both commands first read Airflow's health answer and the `edgeguard_baseline` runs that are queued or running, through the REST API at `AIRFLOW_WEBSERVER_URL` (the health answer needs no credentials, the run list needs `AIRFLOW_API_PASSWORD`). On the Compose host (`docker compose`, run from the current directory, lists the `airflow` service as running) a reading the REST API does not give is taken in the `airflow` container, which reads the metadata database itself and needs no API credentials: `airflow dags list-runs edgeguard_baseline -o json` for the runs, and `airflow jobs check --job-type SchedulerJob` for the scheduler (exit 0: a scheduler is alive). The container is not asked once a reading refuses. The commands exit 2 without triggering:
  - when the scheduler or the metadata database is not reported healthy (the run would stay queued and start, a fresh baseline with its wipe, whenever the scheduler returns); the recovery is printed as by `dag status`, and a triggerer or DAG processor reported unhealthy is only a warning;
  - when an `edgeguard_baseline` run is queued or running: the DAG has `max_active_runs=1`, so Airflow queues a second run instead of refusing it, and a second fresh baseline starts when the first run ends and wipes the graph it built. The command names the run; `dag status --dag-id edgeguard_baseline` follows it, and `dag kill --dag-id edgeguard_baseline` ends it first when it is to be replaced;
  - when the `airflow` container answers `airflow jobs check` with "No alive jobs found." (the same refusal as an unhealthy scheduler);
  - when either answer can be read neither through the REST API (Airflow not reachable at `AIRFLOW_WEBSERVER_URL`, or no API credentials for the run list) nor in a running Compose `airflow` service (no such service in the current directory, or its command failed or gave no answer within 60 seconds), unless `--skip-airflow-check` is given. The flag replaces only a reading that is missing: a scheduler or metadata database reported not healthy, or a queued or running run, still refuses. One flag covers both readings because they come from the same Airflow. It is logged as a warning; check the Airflow UI first.
- **Trigger.** Through the Airflow REST API the command sends `POST /api/v2/dags/edgeguard_baseline/dagRuns` with `{"logical_date": null, "conf": {...}}` (Airflow 3 requires the `logical_date` key; with `AIRFLOW_API_VERSION=v1`, `{"conf": {...}}`), once. When Airflow does not answer in time the run may have been created: the command says so and does not send the request again; check `dag status --dag-id edgeguard_baseline` before a new trigger (the Airflow check refuses while that run is queued or running). The same holds when `docker compose exec` does not answer within 60 seconds.
- **`baseline`** triggers the `edgeguard_baseline` DAG with the run configuration `{"baseline_days": N}`; existing data stays and nothing is confirmed. Without `--days`, the window is `EDGEGUARD_BASELINE_DAYS` or 730 days.
- **`fresh-baseline`** checks Airflow, probes Neo4j, MISP and the checkpoints, shows what it would delete, runs the backup gate, asks you to type `FRESH-BASELINE`, checks Airflow again (the prompt may have stayed open), and triggers the DAG with `fresh_baseline` set. It exits 2 when the Airflow check refuses, when a store or the checkpoint file cannot be probed or the backup gate refuses, and 1 when the confirmation does not match.
  - The Neo4j wipe deletes only EdgeGuard-managed nodes; `--wipe-all` deletes every node and adds `"wipe_scope": "all"` to the run configuration.
  - `--skip-backup-check` bypasses the backup gate with a logged warning (the DAG receives `skip_backup_check`); otherwise the run configuration attests that the CLI ran the gate (`backup_check_passed_cli`).
  - `--force` skips the typed confirmation; the Airflow check and the probes still run.

The run configuration keys are listed in [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md); the procedure is in the README's [Running the 730-day baseline](../README.md#running-the-730-day-baseline) and in [BASELINE_LAUNCH_CHECKLIST.md](BASELINE_LAUNCH_CHECKLIST.md).

---

## Clearing data

| Command | Purpose |
|---|---|
| `clear neo4j` | Delete the graph data (constraints stay) |
| `clear misp` | Delete every EdgeGuard event from MISP |
| `clear all` | Neo4j, MISP and checkpoints |

- `clear neo4j --edgeguard-only` deletes only the nodes EdgeGuard created (`edgeguard_managed = true`) and their relationships; nodes a partner created first stay, also where EdgeGuard enriched them. Use it on a database shared with ResilMesh.
- Every `clear` command asks for confirmation; `--force` skips it. Each MISP event delete may wait up to `EDGEGUARD_MISP_DELETE_TIMEOUT_SEC` (900 s by default).

---

## Install, update and version

| Command | Purpose |
|---|---|
| `update` | Runs `./install.sh --update` |
| `version` | Release version and commit |
| `setup` | Prints the install steps |
| `source list`, `add`, `remove` | Edit the local source registry file |

- **`update`** runs `./install.sh --update`, which pulls the branch (fast-forward only) and then takes the Docker path when Docker Compose is available and the pip path otherwise; `--docker` or `--python` forces one.
- **`version`** prints the CalVer version from `pyproject.toml` and the short commit; `--no-git` prints the version only. `version` and `update` need no settings.
- **`setup`** prints the install steps; it is not an interactive wizard, and like the data commands it stops with an error while `NEO4J_PASSWORD` is not set in the environment.
- **`source`** edits `credentials/sources.yaml`, which no collector or DAG reads; collectors are selected with `EDGEGUARD_COLLECT_SOURCES` and the `EDGEGUARD_ENABLE_*` flags.

---

## Installer options

```bash
./install.sh                      # Docker Compose install (the default when Docker and Compose v2 exist)
./install.sh --python             # pip install into .venv, no Docker
./install.sh --python --dev       # also the development tools (ruff, mypy, pytest)
./install.sh --update             # git pull --ff-only, then the Docker or pip path
./install.sh --update --docker    # update on the Docker path; fail if Docker is missing
./install.sh --update --python    # update on the pip path
./install.sh --help
```

- Both paths create `.env` from `.env.example` when it is missing and generate a blank `EDGEGUARD_API_KEY`, `AIRFLOW_API_AUTH_JWT_SECRET` or `AIRFLOW_FERNET_KEY`; a value set in `.env` or exported in the shell is never replaced.
- `GRAFANA_ADMIN_PASSWORD` is generated only when the installer creates `.env`; `NEO4J_PASSWORD` only on the Docker path, before Neo4j's first start.
- The Docker path records the commit with `scripts/record_deployed_commit.sh`, builds the images, starts the stack and waits up to `EDGEGUARD_INSTALL_WAIT_SEC` seconds (default 300, read from the shell) for the services to become healthy.
- The pip path checks Python 3.12 or later, creates `.venv` and installs the `api`, `graphql` and `monitoring` extras; Airflow is a separate extra (`pip install -e '.[airflow]'`, [SETUP_GUIDE.md § 4](SETUP_GUIDE.md#4-path-b--python--venv-no-docker)).

---

## make targets

| Target | Runs |
|---|---|
| `make install` | Creates `.env`, then `./install.sh` |
| `make update` | `./install.sh --update` |
| `make install-py` | `pip install -e` with the API extras into `.venv` |
| `make install-dev` | The same with the `dev` extra |
| `make install-uv` | The same with `uv` |
| `make start`, `stop`, `restart` | `docker compose up -d` and `down` |
| `make build`, `logs` | `docker compose build`, `logs -f` |
| `make monitoring` | Prometheus and Grafana with the stack |
| `make lint`, `fmt`, `type-check`, `test`, `ci` | Ruff, Mypy and pytest |
| `make health`, `doctor` | `src/health_check.py`, `edgeguard doctor` |
| `make deploy-check` | `scripts/deployment_wiring_check.sh` (see below) |
| `make clean` | Removes `.venv` and the caches |

- `make install` creates `.env` before `./install.sh` runs, so the installer does not generate `GRAFANA_ADMIN_PASSWORD`, which keeps the template value `changeme`; set it in `.env`. `./install.sh` run directly generates it.
- `make install-py`, `install-dev` and `install-uv` generate none of the `.env` secrets and skip the installer's Python version check.
- `make lint`, `type-check`, `test`, `ci`, `health` and `doctor` call `python3` from the path: activate `.venv` first (`source .venv/bin/activate`). `make health` and `make doctor` also need the settings exported.
- `make logs-api` and `make logs-graphql` follow one service; `make test-graphql` runs the GraphQL tests; `make help` lists every target.

---

## Operator scripts

Run them from the repository root with the settings exported.

| Script | Purpose |
|---|---|
| `scripts/preflight_baseline.sh` | Readiness checks `[1]` to `[13]` before a baseline |
| `scripts/verify_fresh_baseline.py` | Acceptance checks of a loaded graph |
| `scripts/import_curated_package.py` | Validate and push a curated package to MISP |
| `scripts/record_deployed_commit.sh` | Write the deployed commit into `.env` |
| `scripts/clear_neo4j.py` | Delete the nodes EdgeGuard created |
| `scripts/clear_misp.py` | Delete EdgeGuard MISP events |
| `scripts/deployment_wiring_check.sh` | `preflight_ci.sh`, then optional live probes |
| `scripts/preflight_ci.sh` | Compile, unit tests, DAG parse (see below) |
| `scripts/resilmesh_stix_smoke.sh` | Export one STIX bundle of every type |
| `scripts/build_canonical_threat_actors.py` | Rebuild the canonical threat-actor reference |
| `scripts/build_attack_revoked_ids.py` | Rebuild the revoked ATT&CK id map |
| `scripts/run_cypher_catalog_http.py` | Run the Cypher catalog over the HTTP API |
| `scripts/runtime_smoke_checklist.sh` | Print and probe the runtime smoke steps |
| `scripts/debug_zone_check.py` | Standalone check of the sector logic |
| `scripts/neo4j_wss_bridge.py` | Local Bolt bridge to a WebSocket-only Neo4j |

- **`preflight_baseline.sh`**: `--launch-path=dag`, the `edgeguard_baseline` DAG, also checks the pause state of the five scheduled DAGs; without `--launch-path` (or `EDGEGUARD_PREFLIGHT_LAUNCH_PATH`) the script assumes `dag` and warns that it did. `--launch-path=cli`, the retired in-process baseline of `run_pipeline.py`, is refused (exit 1). The check fails while one of the five has a running run. Check `[13]` reads Airflow's health endpoint (`AIRFLOW_WEBSERVER_URL`; `/api/v2/monitor/health`, or `/health` with `AIRFLOW_API_VERSION=v1`): a scheduler that is not healthy fails the check; a SQLite metadata database is a warning. `--strict` (or `EDGEGUARD_PREFLIGHT_STRICT=1`) turns every warning into a failure. Exit 0 means ready.
  - Checks `[10]` to `[12]` use the repository's `.venv` (`./install.sh --python` creates it). Without it, check `[11]` reports `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` as missing `retries=0`, check `[10]` is skipped and check `[12]` runs with the system `python3`.
  - With the shipped `prometheus/alertmanager.yml`, check `[7b]` fails until the PagerDuty `service_key` is rendered or that receiver is removed ([PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#alertmanager-notifications)).
- **`verify_fresh_baseline.py`**, **`run_cypher_catalog_http.py`** and **`build_canonical_threat_actors.py --export-graph-actors`** read Neo4j through its HTTP API at `NEO4J_HTTP_URL`, then `NEO4J_HTTP`, with `NEO4J_USER`, `NEO4J_PASSWORD` and `NEO4J_DATABASE`. With neither set they read the Compose Neo4j at `http://127.0.0.1:7474` and send the credentials nowhere else; for another instance set `NEO4J_HTTP_URL` ([CONFIGURATION.md](CONFIGURATION.md#neo4j-connection-and-memory)). A set value that is not an `http://` or `https://` URL with a host, a numeric port (when it names one) and no space stops them with exit code 2 before any request.
- **`verify_fresh_baseline.py`**: `--json` prints the report as JSON; `--require-cisa-ics`, `--require-ics`, `--require-otx-industries` and `--require-malwarebazaar` fail when that source left no data. Exit 0: every mandatory check passed; 1: a check failed; 2: Neo4j not reachable, or the address is not a valid http(s) URL.

  ```bash
  set -a; . ./.env; set +a
  python3 scripts/verify_fresh_baseline.py                                      # the Compose Neo4j
  NEO4J_HTTP_URL=https://neo4j.example.org python3 scripts/verify_fresh_baseline.py  # another instance
  ```

- **`import_curated_package.py <package.json>`** validates the package; `--check-graph` reports which claims would attach to existing nodes, and `--push` creates the MISP event ([RUNBOOK.md § Importing a curated package](RUNBOOK.md#importing-a-curated-package)).
- **`clear_neo4j.py`** deletes, with `--force`, the nodes EdgeGuard created (`edgeguard_managed = true`) and their relationships, through the wipe of the fresh baseline; nodes another system created, such as a partner's `Vulnerability` and `CVE` nodes, stay, also where EdgeGuard enriched them. `--label` deletes only the EdgeGuard-created nodes of one label (no `--force` needed; the label must be one the graph client allows). `--full-wipe` deletes every node in the database, partner data included: it prints how many nodes EdgeGuard did not create and asks to type `FULL-WIPE`, also with `--force`; it cannot be combined with `--label`. `--dry-run` prints the scope and the nodes kept, and deletes nothing. After a delete the script recreates the `Source` nodes (`--no-recreate` leaves them out; never with `--label`) and clears the collector checkpoints. Every delete writes a line to the destructive-operations audit trail ([BACKUP.md](BACKUP.md#audit-trail-and-what-this-procedure-does-not-cover)), also a delete that fails part-way: that line has `details.outcome = "failed"` and counts the nodes and relationships deleted before the failure. Exit 0: done or dry run; 1: no action given, refused, aborted or failed; 2: `--label` with `--full-wipe`.
- **`clear_misp.py`** deletes the EdgeGuard MISP events; `clear_misp.py --old DAYS` deletes the events older than that. Both scripts take `--dry-run` and `--force`.
- **`preflight_ci.sh`** compiles `dags/` and `src/collectors/`, runs the unit tests and loads the DAGs with `DagBag(include_examples=False)`. On Airflow 3.3, whose `DagBag` has no `include_examples` argument, that step stops with a `TypeError`; check the DAG parse with `docker compose exec airflow airflow dags list-import-errors` instead.
- **`deployment_wiring_check.sh`** runs `preflight_ci.sh` first and stops when it fails, so on Airflow 3.3 it, and `make deploy-check`, stop at the DAG parse step. With `EDGEGUARD_DEPLOY_CHECK_LIVE=1` it then runs `src/health_check.py` and the REST and GraphQL health probes (`EDGEGUARD_REST_HEALTH_URL`, `EDGEGUARD_GRAPHQL_HEALTH_URL`; `EDGEGUARD_SKIP_HTTP_HEALTH=1` skips them).
- **`run_cypher_catalog_http.py`** plans every catalog query with `EXPLAIN`, runs the valid ones and prints their row counts; `--out <dir>` (or `CATALOG_OUTPUT_DIR`) also writes the results as JSON and Markdown. It first sends `RETURN 1`: when Neo4j does not answer (not reachable, credentials refused) it exits with code 2 before it runs a catalog query or writes a file. A catalog query that fails is reported and leaves the exit code 0.
- **`neo4j_wss_bridge.py`** run on its own requires `NEO4J_WSS_HOST`, the host of the Bolt-over-WebSocket endpoint that receives `NEO4J_USER` and `NEO4J_PASSWORD`; unset, it exits with code 2 before it connects.
- **`resilmesh_stix_smoke.sh`** reads `EDGEGUARD_API_BASE` (default `http://127.0.0.1:8000`) and `EDGEGUARD_API_KEY` ([RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md)).

---

## Pipeline modules run on their own

Each of these modules runs on its own, from the repository root, with the settings exported. The Airflow DAGs run the collectors, the sync, the link step and the enrichment jobs; they do not use `run_pipeline.py`:

```bash
python src/health_check.py           # MISP and Neo4j connectivity
python src/run_pipeline.py           # the enabled collectors, once, into MISP
python src/run_misp_to_neo4j.py      # incremental MISP → Neo4j sync
python src/run_misp_to_neo4j.py --full
python src/build_relationships.py    # rebuild the graph links
python src/enrichment_jobs.py        # the six enrichment jobs
```

A baseline, smoke or 730-day, runs through the `edgeguard_baseline` DAG on every install, with Docker or without it ([AIRFLOW_DAGS.md § One baseline path](AIRFLOW_DAGS.md#one-baseline-path)); `run_pipeline.py` is not a way to run one.

- **`run_misp_to_neo4j.py`** reads, without `--full`, the events of the last `EDGEGUARD_SYNC_INTERVAL_DAYS` days plus one (four by default). The Airflow task reads from the last sync's start minus `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS` instead. `--sector` sets the start date from the sector time range; it does not filter events by sector.
- **`run_pipeline.py`** runs every enabled collector once and pushes to MISP, as the scheduled DAGs call them: the incremental limit of each source, the `EDGEGUARD_COLLECT_SOURCES` allowlist, no baseline window. It writes nothing to Neo4j. It holds `checkpoints/pipeline.lock` while it runs and refuses to start while a live process holds it. Exit 0 when no collector failed (a skipped optional source is no failure), 1 when one reported failure or raised, or the lock is held. `--baseline`, `--fresh-baseline`, `--baseline-days` and `--stix-flow`, the options of the retired in-process baseline and its STIX import into Neo4j, exit 2 before the lock is taken or a collector runs, also on a shell without the Neo4j and MISP settings (as `--help` answers there), with directions to the `edgeguard_baseline` DAG (`edgeguard baseline` and `edgeguard fresh-baseline` on every install, with Docker Compose or without it, as in [Baseline triggers](#baseline-triggers); as the raw alternative, the additive and the fresh `airflow dags trigger edgeguard_baseline --conf ...` and where the fresh run's backup gate reads `EDGEGUARD_LAST_BACKUP_AT`) and to the modules above.
- **`health_check.py`** prints MISP's status and response time, Neo4j's status and version, and counts of `Vulnerability`, `Indicator`, `CVE`, `Malware`, `ThreatActor`, `Technique` and `Source` nodes and `SOURCED_FROM` relationships. Its "Last Pipeline Run" line reads `data/metrics.json`, which no pipeline step writes, so it shows "Never"; `edgeguard stats` shows the last sync.

---

_Last updated: 2026-11-02_

## History

- 2026-11-02 — `stats --misp` counts each event once on a MISP that answers the whole listing on every page.
- 2026-11-02 — `run_pipeline.py` runs the collectors into MISP only, exits 1 when a collector failed and 2 on `--baseline`, `--fresh-baseline`, `--baseline-days` and `--stix-flow`, with directions to the `edgeguard_baseline` DAG through the `edgeguard` baseline commands on every install, `airflow dags trigger` as the raw alternative (it loaded Neo4j through a STIX import, and its `--baseline` built a reduced graph); the module list runs it instead of its baseline. The refusal and `--help` need no Neo4j or MISP settings (`config` and the collectors are imported after them). `preflight_baseline.sh` refuses `--launch-path=cli`.
- 2026-11-02 — `baseline` and `fresh-baseline` read Airflow before they trigger and exit 2 while the scheduler or metadata database is not healthy, while an `edgeguard_baseline` run is queued or running, or when Airflow cannot be read (`--skip-airflow-check` for the last case only); `fresh-baseline` checks again after the confirmation. Without a running Compose `airflow` service they trigger through the Airflow REST API (they worked on the Compose host only), and a trigger that timed out is not repeated. On the Compose host the check reads in the `airflow` container what the REST API does not give (`airflow dags list-runs`, `airflow jobs check`), so it needs no API credentials there.
- 2026-11-01 — `dag status`, `doctor` and `preflight` read the status of Airflow's scheduler, triggerer, DAG processor and metadata database from the health answer (they reported only that the API server answered); `dag status` exits 1 when the scheduler is not healthy; `preflight_baseline.sh` check `[13]`.
- 2026-11-01 — `run_pipeline.py --baseline` is development only and builds a reduced graph (the module list offered a 730-day run of it, and the section said the DAGs run these steps); `preflight_baseline.sh` assumes `--launch-path=dag` when none is given (it assumed `cli`) and warns on `cli` that the graph is reduced.
- 2026-10-25 — `preflight_baseline.sh`: both launch paths fail while a scheduled DAG has a running run.
- 2026-10-25 — `run_pipeline.py`: the STIX flow names an event's source from its `source:*` tag, else its name, and skips a curated package's event.
- 2026-10-23 — `verify_fresh_baseline.py`, `run_cypher_catalog_http.py` and the graph export of `build_canonical_threat_actors.py` read the Compose Neo4j at `http://127.0.0.1:7474` when neither `NEO4J_HTTP_URL` nor `NEO4J_HTTP` is set (they used a built-in remote address) and stop with exit code 2 on an address that is not a valid http(s) URL; `run_cypher_catalog_http.py` also reads `NEO4J_HTTP` and exits 2 without writing its results when Neo4j does not answer a first `RETURN 1`; `neo4j_wss_bridge.py` requires `NEO4J_WSS_HOST`.
- 2026-10-23 — `scripts/clear_neo4j.py` deletes the nodes EdgeGuard created through the wipe of the fresh baseline, `--label` narrows that scope, `--full-wipe` asks for a typed confirmation, also with `--force`, and every delete writes a destructive-operations audit line, also one that fails part-way; it deleted every node of the EdgeGuard labels, partner `Vulnerability` and `CVE` nodes included, and recorded nothing.
- 2026-10-23 — `heal` removes the MISP writer's event-creation lock only when no process holds it, reports the pipeline and baseline locks without removing them and counts the kept lock files in its summary, and no longer removes other `*.lock` files in the repository root or the temporary directory.
- 2026-10-23 — `validate` reports an `EDGEGUARD_SSL_VERIFY` value it does not recognise; verification then stays on.
- 2026-10-23 — Created from the README's command reference, `make` targets and standalone commands, with the Docker form of every command, the host-shell settings, the `--json` output, the `preflight` breaker check, `heal`, `monitor`, `setup`, the `make install` and `make ci` behaviour, the operator scripts and the always-on STIX flow of `run_pipeline.py` stated as the code behaves.
