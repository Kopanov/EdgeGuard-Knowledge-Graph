# Airflow heartbeats, zombies, and worker kills (EdgeGuard)

**Purpose:** Explain why a MISP → Neo4j (or similar) task can **finish its Python logic** yet Airflow still marks the run **failed**, or the worker receives **SIGKILL (-9)**.

## Heartbeats vs task success

- Airflow 3 runs every task under a **supervisor** process. While the task runs, the supervisor sends a heartbeat to the API server about every **`[workers] min_heartbeat_interval`** seconds (default **5**), whatever the task's Python code is doing; the supervisor is a separate process, so long imports or a long computation in the task do not delay it.
- The scheduler fails a task whose last heartbeat is older than **`[scheduler] task_instance_heartbeat_timeout`** (default **300** s; the Airflow 2 name is `scheduler_zombie_task_threshold`). It looks for such tasks every **`[scheduler] task_instance_heartbeat_timeout_detection_interval`** (default **10** s; Airflow 2 name `zombie_detection_interval`); that is a scan interval, not "kill after 10 s".
- A heartbeat timeout therefore means that the supervisor or the API server was unreachable, or the worker was overloaded. A long-running task alone does not cause one. `[scheduler] task_instance_heartbeat_sec` (Airflow 2 name `local_task_job_heartbeat_sec`) is defined, but no code of Airflow 3.3.2 reads it.

**Docker Compose (this repo):** `docker-compose.yml` sets **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT=3600`** and **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT_DETECTION_INTERVAL=60`** on the **airflow** service; both can be overridden in **`.env`**. The compose file sets no heartbeat interval, since no Airflow 3.3.2 code reads `task_instance_heartbeat_sec`. The value in effect:

```bash
docker exec edgeguard_airflow airflow config get-value scheduler task_instance_heartbeat_timeout
```

## SIGKILL (-9) vs “zombie”

| Signal / message | Typical cause |
|------------------|---------------|
| **Exit -9 / SIGKILL** | **OOM killer** (container memory limit), kernel, or platform kill—not a normal Python exception. |
| **Heartbeat timeout ("zombie")** | No heartbeat reached the API server for `task_instance_heartbeat_timeout`: the supervisor was killed, the API server was unreachable, or the worker was overloaded; not the task's own code running long. |

Distinguish these in logs: OOM often appears in **Docker / k8s** events; zombies appear in **Airflow scheduler** logs.

**Docker Compose — Airflow container memory:** `docker-compose.yml` sets **`deploy.resources.limits.memory: ${AIRFLOW_MEMORY_LIMIT:-12g}`** on **`airflow`**. Large MISP events (100K+ attributes) are sized at **8-12GB**: the sync holds an event's attribute list in memory. Events with up to **`EDGEGUARD_MISP_PAGED_FETCH_ABOVE`** attributes (default **20000**) are fetched whole (PyMISP `get_event`, REST `/events/view` as fallback), larger ones as `/events/restSearch` metadata plus `/attributes/restSearch` pages of 5000 joined into one list; the list is then parsed and written to Neo4j in pages of 5000. **-9** with free host RAM usually means the **container** cgroup limit — check **`docker inspect … OOMKilled`**, **`docker stats`**, and [SETUP_GUIDE.md](SETUP_GUIDE.md) § troubleshooting.

## MISP → Neo4j–specific notes

- **`EDGEGUARD_DEBUG_GC`:** Forced full **`gc.collect()`** after each Neo4j sync chunk is **opt-in** only. In **memory-constrained** workers it can **increase peak RSS** and contribute to OOM.
- **`EDGEGUARD_REL_BATCH_SIZE`:** Relationship writes use batched **UNWIND** (default **500** definitions per round-trip). Lower this if Neo4j transactions time out.
- **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`:** Python-side node merge chunking (separate from relationship batching).

## Further reading

- [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — operator guide and MISP → Neo4j troubleshooting.
- Airflow docs: **scheduler configuration** (`[scheduler] task_instance_heartbeat_timeout`) and **workers configuration** (`[workers] min_heartbeat_interval`).

---

_Last updated: 2026-10-25_

## History

- 2026-10-25 — Airflow container memory: events over `EDGEGUARD_MISP_PAGED_FETCH_ABOVE` (default 20000) attributes are fetched as metadata plus attribute pages of 5000 joined into one list (the page said the initial fetch loads the full event JSON).
- 2026-10-18 — Removed the procedures for data written by earlier versions (the project re-baselines after larger changes).
- 2026-10-17 — Rewritten as a guide to the current system; the Airflow 2 variable names moved to the appendix.
- 2026-10-17 — Airflow 3 heartbeats described (the supervisor's heartbeat every `[workers] min_heartbeat_interval`, the scheduler's `task_instance_heartbeat_timeout` and detection interval); `docker-compose.yml` sets the Airflow 3 names (3600 s timeout, 60 s detection interval) instead of the Airflow 2 names `SCHEDULER_ZOMBIE_TASK_THRESHOLD=3600`, `LOCAL_TASK_JOB_HEARTBEAT_SEC=30` and `ZOMBIE_DETECTION_INTERVAL=60`, which Airflow 3 does not read, so Airflow's defaults (300 s, 10 s) applied until then.
- 2026-04-26 — The Airflow version is named as Airflow 3.x (EdgeGuard's pinned version since 2026-04-15) instead of "Airflow 2.11 and 3.2".
- 2026-04-06 — First version.
