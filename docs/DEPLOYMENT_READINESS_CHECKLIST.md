# Deployment readiness checklist — logic and wiring

Use this runbook **in order** before a deployment or production test. Deep dives stay in linked docs; this page is the single ordered gate.

**Quick automation:** from repo root, `./scripts/deployment_wiring_check.sh` (Layer 1 always; Layer 3 + optional HTTP health if `EDGEGUARD_DEPLOY_CHECK_LIVE=1`). Or `make deploy-check`.

**Canonical assessment:** [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md)

---

## Data flow (what we are verifying)

External feeds → **Collectors** → **MISP** → (Airflow **MISP→Neo4j sync**) → **Neo4j** → **REST** (8000) / **GraphQL** (4001).

**Logic:** collectors return `make_status` / optional `skipped`; Airflow `run_collector_with_metrics` expects a status dict when `push_to_misp=True`.

**Wiring:** `MISP_URL`, `NEO4J_URI`, keys, and `EDGEGUARD_SSL_VERIFY` must be correct for **each runtime** (Airflow worker container vs host). See [ENVIRONMENTS.md](ENVIRONMENTS.md) and [MISP_SOURCES.md](MISP_SOURCES.md) (Docker / `localhost` pitfalls).

---

## Layer 1 — Static / CI (no live MISP or Neo4j)

Sign off on the **same git commit** you will deploy.

| Done | Check | Command / source | Pass |
|------|--------|------------------|------|
| [ ] | Syntax + collectors compile + pytest + DagBag | `./scripts/preflight_ci.sh` | Exit 0 |
| [ ] | Lint + format + mypy (matches CI) | `make lint` and `make type-check` | Clean |
| [ ] | Full CI parity (optional) | `make ci` | Exit 0 |

References: [preflight_ci.sh](../scripts/preflight_ci.sh), [.github/workflows/ci.yml](../.github/workflows/ci.yml), [Makefile](../Makefile).

**Python:** Use **3.12+** for local `make ci` / `preflight_ci.sh` parity with CI ([`pyproject.toml`](../pyproject.toml) `requires-python`). Apache Airflow 2.11 supports **3.11+** upstream; this repository standardizes on **3.12**.

`preflight_ci.sh` sets a dummy `NEO4J_PASSWORD` for DagBag import — see [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) troubleshooting.

---

## Layer 2 — Configuration and secrets

| Done | Check | How | Pass |
|------|--------|-----|------|
| [ ] | Required variables | `.env` / secrets; [ENVIRONMENTS.md](ENVIRONMENTS.md), [credentials/config.example.yaml](../credentials/config.example.yaml) | `NEO4J_PASSWORD`, `MISP_URL`, MISP API key, `NEO4J_URI` valid for target runtime |
| [ ] | SSL verify consistency | **`EDGEGUARD_SSL_VERIFY`** (or **`SSL_VERIFY`** if `EDGEGUARD_SSL_VERIFY` unset) on scheduler, workers, API, sync tasks | Same policy everywhere; **`SSL_CERT_VERIFY`** is not read (see README, SETUP_GUIDE) |
| [ ] | Optional API keys | [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — optional keys / `skip_reason_class` | Missing keys → **skipped** tasks (success), not hard failure — unless you require that feed |
| [ ] | Collector allowlist | `EDGEGUARD_COLLECT_SOURCES` — [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md), [.env.example](../.env.example) | If set: only listed sources run; others skip (`collector_disabled_by_config`); `none`/`-` disables all external collectors |
| [ ] | Baseline limits (before first baseline) | [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) | `BASELINE_DAYS` / `BASELINE_COLLECTION_LIMIT` or env overrides understood |
| [ ] | MISP→Neo4j sync memory (huge attribute counts) | `.env` / worker env: **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`** (default **1000**; **`0`** / **`all`** = single pass, expert-only); [README.md](../README.md), [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) | Lower if worker OOMs during Neo4j merge after parse |

Optional: `python src/edgeguard.py validate` — [SETUP_GUIDE.md](SETUP_GUIDE.md).

---

## Layer 3 — Runtime wiring (live stack)

Execute from the **same network context** as Airflow tasks (e.g. `docker exec` into `edgeguard_airflow` or the worker host).

| Done | Check | Command | Pass |
|------|--------|---------|------|
| [ ] | Preflight (recommended) | `python src/edgeguard.py preflight` | All 7 checks pass (env vars, APIs, Neo4j, MISP, Airflow, disk, breakers) |
| [ ] | MISP + Neo4j | `python src/health_check.py` or `make health` | `overall_healthy`; APOC noted for Neo4j ([ENVIRONMENTS.md](ENVIRONMENTS.md)) |
| [ ] | REST API health | `curl -s http://<api-host>:8000/health` (or your URL) | **HTTP 200** always; JSON `status: ok` and `neo4j_connected: true` when Neo4j ping + APOC pass ([README.md](../README.md) § Health) |
| [ ] | GraphQL health | `curl -sf http://<api-host>:4001/health` | **HTTP 200** when Neo4j is healthy; **503** if no driver or Neo4j/APOC unhealthy (`curl -f` fails on 503 — intended for “must be up” checks) |
| [ ] | Airflow | Scheduler up; DAGs not paused; optional: [runtime_smoke_checklist.sh](../scripts/runtime_smoke_checklist.sh) | UI / health reachable |
| [ ] | MISP from worker | Resolve `MISP_URL` from worker container | No mistaken `localhost` for remote MISP ([MISP_SOURCES.md](MISP_SOURCES.md)) |

`deployment_wiring_check.sh` with `EDGEGUARD_DEPLOY_CHECK_LIVE=1` runs `health_check.py` and optional curls (see script header for env vars).

---

## Layer 4 — Airflow task graph (logic + wiring)

| Done | Check | Action | Pass |
|------|--------|--------|------|
| [ ] | DAG import | `airflow dags list-import-errors` (after DB init) | Empty |
| [ ] | DAG concurrency guards | Airflow UI → each DAG → Details | `max_active_runs=1` and `dagrun_timeout` per [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) |
| [ ] | Baseline DAG unpaused | Airflow UI → `edgeguard_baseline` | `is_paused_upon_creation=False`; verify DAG is active |
| [ ] | MISP preflight | Run a tier DAG once; open `misp_health_check` logs | **`healthy`** / **`healthy_for_collection`** (API + DB); workers only if **`EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS=true`** ([AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)) |
| [ ] | Collector tasks | Logs for `collect_*` | Status dict; skips show `skipped` + reason class; real failures → task failed as designed |
| [ ] | Neo4j sync gate | Observe `full_neo4j_sync` / short-circuit | Matches [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) |
| [ ] | Baseline smoke (recommended) | [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md) | Short window + cap; logs show effective limits |

---

## Layer 5 — Observability (recommended for deployment test)

| Done | Check | Source |
|------|--------|--------|
| [ ] | Prometheus / metrics | [PROMETHEUS_SETUP.md](PROMETHEUS_SETUP.md), [docker-compose.monitoring.yml](../docker-compose.monitoring.yml) |
| [ ] | Collector skips | `edgeguard_collector_skips_total` — [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) |
| [ ] | Alerts | [prometheus/alerts.yml](../prometheus/alerts.yml) — verify `EdgeGuardDAGRunStuck`, `EdgeGuardDAGLastSuccessStale` and Alertmanager target (`alertmanager:9093`) |
| [ ] | Failure callbacks | Trigger a task failure; check logs for `[ALERT] Task FAILED:` message |

---

## Layer 6 — ResilMesh (only if in scope)

| Done | Check | Source |
|------|--------|--------|
| [ ] | Integration / NATS / TLP / RBAC | [RESILMESH_INTEGRATION_TESTING.md](RESILMESH_INTEGRATION_TESTING.md), [RESILMESH_INTEROPERABILITY.md](RESILMESH_INTEROPERABILITY.md) |

---

## Success criteria — “ready for deployment test”

- [ ] Layer 1 green on deploy commit.
- [ ] Layer 2 reviewed for target environment (**worker**-side `MISP_URL` / `NEO4J_URI`).
- [ ] Layer 3 green from that context.
- [ ] At least one manual run of `edgeguard_pipeline` (or a tier DAG) + optional baseline smoke per [BASELINE_SMOKE_TEST.md](BASELINE_SMOKE_TEST.md).

---

## Related scripts

| Script | Purpose |
|--------|---------|
| [scripts/deployment_wiring_check.sh](../scripts/deployment_wiring_check.sh) | Layer 1 + optional live checks |
| [scripts/preflight_ci.sh](../scripts/preflight_ci.sh) | CI-style static + DagBag |
| [scripts/runtime_smoke_checklist.sh](../scripts/runtime_smoke_checklist.sh) | Manual smoke reminders + optional Docker probe |
