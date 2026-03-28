# Baseline smoke test (e.g. 7 days)

Use a **short** history window and optional **item cap** before running a full 1–2 year baseline.

**Where you are in the docs:** Step **3** of the operator path — after **[SETUP_GUIDE.md](SETUP_GUIDE.md)** and **[AIRFLOW_DAGS.md](AIRFLOW_DAGS.md)**. Full order: [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) § *Recommended reading order*.

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

**Not the same as MISP→Neo4j:** This cap applies to **external collectors** (OTX, NVD, CISA, MITRE, feeds, …) in the baseline DAG. It does **not** change the **MISP → Neo4j** step, which uses a **separate** hardcoded MISP search page size (**1000** “EdgeGuard” events per request today) and **Neo4j merge chunking** (`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`). See **[COLLECTION_AND_SYNC_LIMITS.md](COLLECTION_AND_SYNC_LIMITS.md)**.

These are passed into the **Airflow** container via `docker-compose.yml` (`x-common-env`). They **override** Airflow Variables **when set** (non-empty), after `BASELINE_DAYS` / `BASELINE_COLLECTION_LIMIT` are read from the metadata DB.

### 2. Restart Airflow so it picks up `.env`

```bash
docker compose up -d airflow
# or
docker compose restart airflow
```

### 3. Trigger the DAG

Airflow UI → **DAGs** → **`edgeguard_baseline`** → **Trigger DAG**.

Check the **`baseline_start`** task log: it prints the effective **Item limit** and **History window**.

### 4. After the test

Remove or comment out the two lines in **`.env`**, restart Airflow again, and use **Admin → Variables** (`BASELINE_DAYS`, `BASELINE_COLLECTION_LIMIT`) for production, **or** leave defaults (730 days, unlimited cap).

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

Requires MISP/Neo4j (and API keys) as for a normal run.

---

## References

- DAG config: `get_baseline_config()` in `dags/edgeguard_pipeline.py`
- NVD baseline behaviour: `docs/AIRFLOW_DAGS.md` (timeouts, checkpoints)
- Collection limits: `.env.example` (incremental vs baseline notes)
