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

  `MISP_URL` must also be reachable from the host. The Airflow commands (`dag`, the DAG list of `preflight` and `doctor`) need `AIRFLOW_API_PASSWORD` on the host; inside the container the CLI reads the password file the Simple auth manager generates. Without it, `preflight` warns "Could not query DAG list". The same warning appears while Airflow has registered no EdgeGuard DAG yet; `doctor` names that case ("No EdgeGuard DAGs found in Airflow").
- **Compose host only.** `baseline` and `fresh-baseline` trigger the DAG through `docker compose exec`, so they run on the Compose host, from the repository directory, with the settings exported.

Every command accepts `--help`. `edgeguard --update` is a synonym of `edgeguard update`.

---

## Readiness and diagnosis

| Command | Purpose |
|---|---|
| `preflight` | Readiness check before a run |
| `doctor` | Connectivity, schema and configuration diagnosis |
| `validate` | Configuration check |
| `monitor` | One-shot health snapshot |
| `heal` | Reset breakers, remove lock files, trigger the pipeline DAG |

- **`preflight`** runs seven check groups: the required settings and a live check of each source API key, Neo4j and APOC, MISP, Airflow, disk space, checkpoints, and the circuit breakers of the CLI process itself (the pipeline's breakers live in each Airflow task and are not visible to it). It exits 0 when ready and 1 when a check fails; `--strict` also fails on warnings. `--json` prints JSON after the text report on standard output.
- **`doctor`** checks MISP and its PyMISP compatibility, Neo4j and its constraints, Airflow and the paused or active DAGs, the baseline window, NATS (only when `NATS_URL` is set), the memory settings, the API keys, disk space, the last sync, the configured sources and version compatibility. `doctor --memory` compares Neo4j's heap, page cache and transaction memory and the host RAM with the recommended values ([MEMORY_TUNING.md](MEMORY_TUNING.md)); it reads the `neo4j` container's settings through `docker compose exec`, so run it with the pip-installed CLI on the Compose host, from the repository directory. Inside the `airflow` container, which has no Docker CLI and receives none of the Neo4j memory variables, it reports the Neo4j rows as unknown.
- **`validate`** checks rate limits, passwords, the Neo4j schema and production issues, among them disabled TLS verification and a default Neo4j password.
- **`monitor`** prints one snapshot (MISP, Neo4j and its counts, the last sync, the circuit-breaker file, Prometheus) and exits 1 when MISP reports an error or Neo4j is down.
- **`heal`** resets the circuit breakers of its own CLI process, removes every `edgeguard_*.lock` in the temporary directory and every `*.lock` in the repository root, removes the circuit-breaker state file, and triggers the `edgeguard_pipeline` DAG. It does not check whether a process holds a lock file: inside the `airflow` container the pattern matches the event-creation lock of the MISP writer, so run it only while no collector runs. The baseline lock in `checkpoints/` is not touched.

---

## Data, checkpoints and DAGs

| Command | Purpose |
|---|---|
| `stats` | Node counts and the last sync |
| `checkpoint status` | Baseline progress and incremental cursors |
| `checkpoint clear` | Clear baseline checkpoints |
| `dag status` | Airflow DAG run states |
| `dag kill` | Force-fail stuck DAG runs |

- **`stats`**: `--full` adds node counts by sector and by source and the MISP event summary; `--by-zone` and `--by-source` show one breakdown each; `--misp` counts MISP events and attributes per source over every page of `/events/index` that matches `EdgeGuard`, up to 200 pages of 500 events (a warning names a stop at that cap).
- **`checkpoint status`**: `--source` filters one source. **`checkpoint clear`** keeps the incremental cursors unless `--include-incremental` is given; `--source` clears one source and `--force` skips the confirmation.
- **`dag status`**: `--dag-id`, `--state` (`running`, `queued`, `failed`, `success`) and `--limit` (runs per DAG, default 5). **`dag kill`** keeps the checkpoints; `--dag-id`, `--dry-run` and `--force`.
- `stats`, `checkpoint status`, `dag status` and `preflight` accept `--json`; the JSON follows a text banner on standard output.

---

## Baseline triggers

| Command | Purpose |
|---|---|
| `baseline --days N` | Trigger an additive baseline |
| `fresh-baseline --days N` | Trigger a destructive baseline |

- **`baseline`** triggers the `edgeguard_baseline` DAG with the run configuration `{"baseline_days": N}`; existing data stays and nothing is confirmed. Without `--days`, the window is `EDGEGUARD_BASELINE_DAYS` or 730 days.
- **`fresh-baseline`** probes Neo4j, MISP and the checkpoints, shows what it would delete, runs the backup gate, asks you to type `FRESH-BASELINE`, and triggers the DAG with `fresh_baseline` set. It exits 2 when a store or the checkpoint file cannot be probed or the backup gate refuses, and 1 when the confirmation does not match.
  - The Neo4j wipe deletes only EdgeGuard-managed nodes; `--wipe-all` deletes every node and adds `"wipe_scope": "all"` to the run configuration.
  - `--skip-backup-check` bypasses the backup gate with a logged warning (the DAG receives `skip_backup_check`); otherwise the run configuration attests that the CLI ran the gate (`backup_check_passed_cli`).
  - `--force` skips the typed confirmation; the probes still run.

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
| `scripts/preflight_baseline.sh` | Readiness checks `[1]` to `[12]` before a baseline |
| `scripts/verify_fresh_baseline.py` | Acceptance checks of a loaded graph |
| `scripts/import_curated_package.py` | Validate and push a curated package to MISP |
| `scripts/record_deployed_commit.sh` | Write the deployed commit into `.env` |
| `scripts/clear_neo4j.py` | Delete every node of the EdgeGuard labels |
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

- **`preflight_baseline.sh`**: `--launch-path=dag` also checks the pause state of the five scheduled DAGs; `--launch-path=cli` is for the in-process `python src/run_pipeline.py --baseline` and has no DAG pause-state check. `--strict` (or `EDGEGUARD_PREFLIGHT_STRICT=1`) turns every warning into a failure. Exit 0 means ready.
  - Checks `[10]` to `[12]` use the repository's `.venv` (`./install.sh --python` creates it). Without it, check `[11]` reports `full_neo4j_sync`, `build_relationships` and `run_enrichment_jobs` as missing `retries=0`, check `[10]` is skipped and check `[12]` runs with the system `python3`.
  - With the shipped `prometheus/alertmanager.yml`, check `[7b]` fails until the PagerDuty `service_key` is rendered or that receiver is removed ([PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md#alertmanager-notifications)).
- **`verify_fresh_baseline.py`** reads Neo4j through its HTTP API (`NEO4J_HTTP_URL`, then `NEO4J_HTTP`, with `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`); with neither set it uses a built-in remote address, so always set `NEO4J_HTTP_URL` (from the host `http://localhost:7474`). `--json` prints the report as JSON; `--require-cisa-ics`, `--require-ics`, `--require-otx-industries` and `--require-malwarebazaar` fail when that source left no data. Exit 0: every mandatory check passed; 1: a check failed; 2: Neo4j not reachable.

  ```bash
  NEO4J_HTTP_URL=http://localhost:7474 python3 scripts/verify_fresh_baseline.py
  ```

- **`import_curated_package.py <package.json>`** validates the package; `--check-graph` reports which claims would attach to existing nodes, and `--push` creates the MISP event ([RUNBOOK.md § Importing a curated package](RUNBOOK.md#importing-a-curated-package)).
- **`clear_neo4j.py`** deletes every node that carries one of the EdgeGuard labels, `Vulnerability` and `CVE` included, whoever created it, and records no destructive-operations entry; `--full-wipe` deletes every node, `--label` the nodes of one label, and `--no-recreate` leaves out the `Source` nodes it otherwise recreates. On a database shared with ResilMesh use `edgeguard clear neo4j --edgeguard-only` instead.
- **`clear_misp.py`** deletes the EdgeGuard MISP events; `clear_misp.py --old DAYS` deletes the events older than that. Both scripts take `--dry-run` and `--force`.
- **`preflight_ci.sh`** compiles `dags/` and `src/collectors/`, runs the unit tests and loads the DAGs with `DagBag(include_examples=False)`. On Airflow 3.3, whose `DagBag` has no `include_examples` argument, that step stops with a `TypeError`; check the DAG parse with `docker compose exec airflow airflow dags list-import-errors` instead.
- **`deployment_wiring_check.sh`** runs `preflight_ci.sh` first and stops when it fails, so on Airflow 3.3 it, and `make deploy-check`, stop at the DAG parse step. With `EDGEGUARD_DEPLOY_CHECK_LIVE=1` it then runs `src/health_check.py` and the REST and GraphQL health probes (`EDGEGUARD_REST_HEALTH_URL`, `EDGEGUARD_GRAPHQL_HEALTH_URL`; `EDGEGUARD_SKIP_HTTP_HEALTH=1` skips them).
- **`run_cypher_catalog_http.py`** reads `NEO4J_HTTP_URL` only (not `NEO4J_HTTP`); unset, it uses a built-in remote address, so set `NEO4J_HTTP_URL` before running it.
- **`resilmesh_stix_smoke.sh`** reads `EDGEGUARD_API_BASE` (default `http://127.0.0.1:8000`) and `EDGEGUARD_API_KEY` ([RESILMESH_QUICKSTART_STIX.md](RESILMESH_QUICKSTART_STIX.md)).

---

## Pipeline modules run on their own

The Airflow DAGs run these steps; each module also runs on its own, from the repository root, with the settings exported:

```bash
python src/health_check.py           # MISP and Neo4j connectivity
python src/run_misp_to_neo4j.py      # incremental MISP → Neo4j sync
python src/run_misp_to_neo4j.py --full
python src/build_relationships.py    # rebuild the graph links
python src/enrichment_jobs.py        # the six enrichment jobs
python src/run_pipeline.py --baseline --baseline-days 730
```

- **`run_misp_to_neo4j.py`** reads, without `--full`, the events of the last `EDGEGUARD_SYNC_INTERVAL_DAYS` days plus one (four by default). The Airflow task reads from the last sync's start minus `EDGEGUARD_SYNC_WINDOW_OVERLAP_HOURS` instead. `--sector` sets the start date from the sector time range; it does not filter events by sector.
- **`run_pipeline.py`** runs the collectors into MISP and then loads Neo4j through STIX 2.1 (MISP → STIX → Neo4j); the STIX flow is always on, and `--stix-flow` is accepted for compatibility. `--baseline` takes the baseline lock in-process, and `--fresh-baseline` clears Neo4j, MISP and the checkpoints first. The Airflow DAGs do not use this path.
- **`health_check.py`** prints MISP's status and response time, Neo4j's status and version, and counts of `Vulnerability`, `Indicator`, `CVE`, `Malware`, `ThreatActor`, `Technique` and `Source` nodes and `SOURCED_FROM` relationships. Its "Last Pipeline Run" line reads `data/metrics.json`, which no pipeline step writes, so it shows "Never"; `edgeguard stats` shows the last sync.

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — Created from the README's command reference, `make` targets and standalone commands, with the Docker form of every command, the host-shell settings, the `--json` output, the `preflight` breaker check, `heal`, `monitor`, `setup`, the `make install` and `make ci` behaviour, the operator scripts and the always-on STIX flow of `run_pipeline.py` stated as the code behaves.
