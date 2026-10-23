# Baseline smoke test (e.g. 7 days)

Use a **short** history window and optional **item cap** before running a full 1–2 year baseline.

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

## Option B — Airflow Variables only (no `.env`)

1. **Admin → Variables**
   - `BASELINE_DAYS` = `7`
   - `BASELINE_COLLECTION_LIMIT` = `1000` (or `0` for unlimited in the 7-day window)
2. Trigger **`edgeguard_baseline`**.
3. Set variables back when done.

---

## Option C — CLI (`run_pipeline.py`, no Airflow)

From the repo root with `src` on `PYTHONPATH` and `.env` loaded:

```bash
cd /path/to/EdgeGuard-Knowledge-Graph
export EDGEGUARD_BASELINE_COLLECTION_LIMIT=1000   # optional cap per source
python src/run_pipeline.py --baseline --baseline-days 7
```

**For a true clean slate** (wipes Neo4j graph + MISP events + checkpoints, then re-collects):
```bash
python src/run_pipeline.py --baseline --fresh-baseline --baseline-days 7
```

> **Preferred:** `edgeguard fresh-baseline --days 7` — it triggers the `edgeguard_baseline` DAG (the path the hosted pipeline runs), enforces the backup-timestamp gate, and is what `scripts/verify_fresh_baseline.py` is written for. The in-process `run_pipeline.py` commands above serve development; they write some edges through a legacy direct path (see `Neo4jClient.create_malware_actor_relationship`).
 On a 7-day window the acceptance script reports the CVE-properties check as *informational*: NVD assigns reference tags and CPE configurations weeks after publication, so day-old CVEs legitimately lack them.

Requires MISP/Neo4j (and API keys) as for a normal run.

---

## References

- DAG config: `get_baseline_config()` in `dags/edgeguard_pipeline.py`
- NVD baseline behaviour: `docs/AIRFLOW_DAGS.md` (timeouts, checkpoints)
- Collection limits: `.env.example` (incremental vs baseline notes)

---

_Last updated: 2026-10-23_

## History

- 2026-10-23 — The reading order points to SETUP_GUIDE.md; the README section it named was removed.
- 2026-10-17 — Restated as a guide to the current behaviour, with the change history moved here.
- 2026-10-17 — Option A: the MISP → Neo4j step lists events through the paginated MISP event index (`EDGEGUARD_MISP_PAGE_SIZE`, `EDGEGUARD_MISP_MAX_PAGES`) instead of a hardcoded page size of 1000; `source_key_check` named as the baseline's second task; the reading order points to README.md.
- 2026-10-16 — A MISP listing cut at the page cap fails the sync.
- 2026-10-15 — A test value of `EDGEGUARD_BASELINE_DAYS` left in place is stated to narrow the scheduled NVD runs.
- 2026-10-10 — `edgeguard fresh-baseline` named as the preferred path for the smoke run, since it runs the DAG the hosted pipeline uses and the backup gate.
- 2026-03-29 — CLI option for a clean-slate smoke run (`--fresh-baseline`) documented.
