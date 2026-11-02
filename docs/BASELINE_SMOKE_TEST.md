# Baseline smoke test (e.g. 7 days)

Use a **short** history window and optional **item cap** before running a full 1–2 year baseline.

A smoke run is a baseline like the full one: it runs through the **`edgeguard_baseline`** DAG on every install. With Docker Compose use Option A or B; without Docker, Airflow runs with a PostgreSQL metadata database ([SETUP_GUIDE.md § 4](SETUP_GUIDE.md#4-path-b--python--venv-no-docker)) and Option B applies.

**Where you are in the docs:** Step **3** of the operator path — after **[SETUP_GUIDE.md](SETUP_GUIDE.md)** and **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)**. Full order: [SETUP_GUIDE.md § Start here](SETUP_GUIDE.md#start-here--then-read-these-next-operator-path).

---

## Option A — Airflow DAG `edgeguard_baseline` (Docker Compose)

### 1. Set environment variables

In your project **`.env`** (same file as `NEO4J_PASSWORD`, `MISP_URL`, …):

```bash
EDGEGUARD_BASELINE_DAYS=7
EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000
```

- **`EDGEGUARD_BASELINE_DAYS`** — history window for sources that support dates (NVD, OTX, feeds that use `baseline_days`).
- **`EDGEGUARD_BASELINE_COLLECTION_LIMIT`** — max items **per source** for that run (`0` or unset = unlimited; `1000` keeps Tier1/Tier2 faster).

**Not the same as MISP→Neo4j:** This cap applies to **external collectors** (OTX, NVD, CISA, MITRE, feeds, …) in the baseline DAG. It does **not** change the **MISP → Neo4j** step, which lists EdgeGuard events through the paginated MISP event index (`EDGEGUARD_MISP_PAGE_SIZE`, default 500 rows per page, at most `EDGEGUARD_MISP_MAX_PAGES`, default 100 pages; a listing cut at that cap fails the sync) and merges with **Neo4j chunking** (`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`). See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

These are passed into the **Airflow** container via `docker-compose.yml` (`x-common-env`). They **override** Airflow Variables **when set** (non-empty), after `BASELINE_DAYS` / `BASELINE_COLLECTION_LIMIT` are read from the metadata DB.

### 2. Restart Airflow so it picks up `.env`

```bash
docker compose up -d airflow   # not `restart`: a restart keeps the old .env values
```

### 3. Trigger the DAG

Airflow UI → **DAGs** → **`edgeguard_baseline`** → **Trigger DAG**.

Check the **`baseline_start`** task log: it prints the effective **Item limit** and **History window**.

### 4. After the test

Remove or comment out the two lines in **`.env`**, restart Airflow again, and use **Admin → Variables** (`BASELINE_DAYS`, `BASELINE_COLLECTION_LIMIT`) for production, **or** leave defaults (730 days, unlimited cap). A test value of `EDGEGUARD_BASELINE_DAYS` left in place also narrows the scheduled NVD runs: they add only CVEs published within that many days, on KEV, or named in `EDGEGUARD_NVD_EXTRA_CVE_IDS` ([COLLECTORS.md § 2](COLLECTORS.md#2-nvd-collector)).

Starting the real run with `edgeguard fresh-baseline --days 730 --wipe-all`: the stores hold the test data, so the command asks for a recent backup (`EDGEGUARD_LAST_BACKUP_AT`, at most 240 hours old) and stops with `BACKUP GATE FAILED` without it. Record a backup (see [BACKUP.md](BACKUP.md)), or, when the stores hold nothing but the test data, add `--skip-backup-check`. On empty stores the check is skipped. The baseline's second task, `source_key_check` (after `misp_health_check`, before anything is locked or wiped), then reports which keyed sources will deliver; `python src/source_key_check.py` gives the same answer beforehand.

---

## Option B — Airflow Variables or run configuration (no `.env`; also without Docker)

1. **Admin → Variables**
   - `BASELINE_DAYS` = `7`
   - `BASELINE_COLLECTION_LIMIT` = `1000` (or `0` for unlimited in the 7-day window)
2. Trigger **`edgeguard_baseline`**.
3. Set variables back when done.

Or skip the Variables and give the window and the cap to this run only, in the environment of your Airflow install (without Docker) or with `docker compose exec airflow` in front (Compose):

```bash
airflow dags trigger edgeguard_baseline --conf '{"baseline_days": 7, "collection_limit": 1000}'
# a clean slate (wipes the EdgeGuard data in Neo4j and MISP and the checkpoints first; backup gate below):
airflow dags trigger edgeguard_baseline --conf '{"fresh_baseline": true, "baseline_days": 7, "collection_limit": 1000}'
```

A clean slate runs the backup gate in the `baseline_clean` task. Unless Neo4j and MISP are empty, it needs `EDGEGUARD_LAST_BACKUP_AT` (a backup at most `EDGEGUARD_BACKUP_MAX_AGE_HOURS` old, 240 by default; [BACKUP.md](BACKUP.md)) in the environment of the Airflow processes: in `.env` followed by `docker compose up -d airflow` on Compose; without Docker, in the environment the Airflow processes start from, followed by their restart. Set only in the shell that runs `airflow dags trigger`, it does not reach the task. When the stores hold nothing but test data, add `"skip_backup_check": true` to the run configuration instead (the `--skip-backup-check` of Option A belongs to `edgeguard fresh-baseline`).

The `baseline_start` task log prints the effective item limit and history window. The run configuration keys: [AIRFLOW_DAGS.md § `edgeguard_baseline` task chain](AIRFLOW_DAGS.md#edgeguard_baseline-task-chain--additive-vs-destructive).

---

## Checking the result

`edgeguard fresh-baseline --days 7` triggers the same DAG, the path the hosted pipeline runs (through `docker compose exec` on the Compose host, through the Airflow REST API without it), and enforces the backup-timestamp gate; `scripts/verify_fresh_baseline.py` is written for the graph of such a run. `python src/run_pipeline.py` runs no baseline: it runs the collectors into MISP only and exits 2 on `--baseline` ([CLI.md § Pipeline modules run on their own](CLI.md#pipeline-modules-run-on-their-own)).

On a 7-day window the acceptance script reports the CVE-properties check as *informational*: NVD assigns reference tags and CPE configurations weeks after publication, so day-old CVEs legitimately lack them.

`baseline_postcheck` judges a smoke run as it judges a full run, except that a run with an item limit (`collection_limit` above 0) is judged on its ATT&CK links only, not on the claims. The CVE score coverage (at least half of the non-rejected NVD CVEs with a CVSS sub-node, judged when NVD delivered and the graph holds at least 100 of them), each collector's delivery (at least 0.9 of its count as `SOURCED_FROM` edges at its `Source` node) and the sources named in `EDGEGUARD_BASELINE_REQUIRED_SOURCES` can fail a smoke run, and a failed postcheck keeps the baseline lock held ([RUNBOOK.md § 7](RUNBOOK.md#7-baseline-chain-stopped-after-a-failed-step-postcheck), 7d).

Requires MISP/Neo4j (and API keys) as for a normal run.

---

## References

- DAG config: `get_baseline_config()` in `dags/edgeguard_pipeline.py`
- NVD baseline behaviour: `docs/AIRFLOW_DAGS.md` (timeouts, checkpoints)
- Collection limits: `.env.example` (incremental vs baseline notes)

---

_Last updated: 2026-11-02_

## History

- 2026-11-02 — Checking the result: how `baseline_postcheck` judges a smoke run (ATT&CK links only with an item limit; CVE score coverage, each collector's delivery and the required sources as on a full run; a failed postcheck keeps the lock held). The section named only the acceptance script.
- 2026-11-02 — Option C (`python src/run_pipeline.py --baseline`, development only, a reduced graph) removed: `run_pipeline.py` runs the collectors into MISP only and refuses `--baseline`; its notes on checking a smoke run are under § Checking the result.
- 2026-11-02 — `edgeguard fresh-baseline` for a smoke run also without Compose (it triggers through the Airflow REST API there).
- 2026-11-01 — A smoke run goes through the `edgeguard_baseline` DAG on every install; Option B covers installs without Docker, with a run configuration for `airflow dags trigger`; Option C (`run_pipeline.py`, offered as the route without Airflow) is development only and builds a reduced graph. The fresh trigger of Option B states where its backup gate reads `EDGEGUARD_LAST_BACKUP_AT`.
- 2026-10-23 — The reading order points to SETUP_GUIDE.md; the README section it named was removed.
- 2026-10-17 — Restated as a guide to the current behaviour, with the change history moved here.
- 2026-10-17 — Option A: the MISP → Neo4j step lists events through the paginated MISP event index (`EDGEGUARD_MISP_PAGE_SIZE`, `EDGEGUARD_MISP_MAX_PAGES`) instead of a hardcoded page size of 1000; `source_key_check` named as the baseline's second task; the reading order points to README.md.
- 2026-10-16 — A MISP listing cut at the page cap fails the sync.
- 2026-10-15 — A test value of `EDGEGUARD_BASELINE_DAYS` left in place is stated to narrow the scheduled NVD runs.
- 2026-10-10 — `edgeguard fresh-baseline` named as the preferred path for the smoke run, since it runs the DAG the hosted pipeline uses and the backup gate.
- 2026-03-29 — CLI option for a clean-slate smoke run (`--fresh-baseline`) documented.
