# Airflow heartbeats, zombies, and worker kills (EdgeGuard)

**Purpose:** Explain why a MISP → Neo4j (or similar) task can **finish its Python logic** yet Airflow still marks the run **failed**, or the worker receives **SIGKILL (-9)**.

## Heartbeats vs task success

- Airflow 3 runs every task under a **supervisor** process. While the task runs, the supervisor sends a heartbeat to the API server about every **`[workers] min_heartbeat_interval`** seconds (default **5**), whatever the task's Python code is doing; the supervisor is a separate process, so long imports or a long computation in the task do not delay it.
- The scheduler fails a task whose last heartbeat is older than **`[scheduler] task_instance_heartbeat_timeout`** (default **300** s; called `scheduler_zombie_task_threshold` before Airflow 3). It looks for such tasks every **`[scheduler] task_instance_heartbeat_timeout_detection_interval`** (default **10** s; formerly `zombie_detection_interval`); that is a scan interval, not "kill after 10 s".
- A heartbeat timeout therefore means that the supervisor or the API server was unreachable, or the worker was overloaded. A long-running task alone does not cause one. `[scheduler] task_instance_heartbeat_sec` (formerly `local_task_job_heartbeat_sec`) is still defined, but no code of Airflow 3.3.2 reads it.

**Docker Compose (this repo):** since 2026-10 `docker-compose.yml` sets **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT=3600`** and **`AIRFLOW__SCHEDULER__TASK_INSTANCE_HEARTBEAT_TIMEOUT_DETECTION_INTERVAL=60`** on the **airflow** service; both can be overridden in **`.env`**. Until then it set the pre-3 names `AIRFLOW__SCHEDULER__SCHEDULER_ZOMBIE_TASK_THRESHOLD=3600`, `AIRFLOW__SCHEDULER__LOCAL_TASK_JOB_HEARTBEAT_SEC=30` and `AIRFLOW__SCHEDULER__ZOMBIE_DETECTION_INTERVAL=60`, which Airflow 3 renamed without an alias and does not read, so Airflow's defaults applied: `task_instance_heartbeat_timeout` = **300** s and `task_instance_heartbeat_timeout_detection_interval` = **10** s (measured with Airflow 3.3.2 and the three old variables set). `LOCAL_TASK_JOB_HEARTBEAT_SEC` has no replacement in the compose file, since no Airflow 3.3.2 code reads its successor. The value in effect:

```bash
docker exec edgeguard_airflow airflow config get-value scheduler task_instance_heartbeat_timeout
```

## SIGKILL (-9) vs “zombie”

| Signal / message | Typical cause |
|------------------|---------------|
| **Exit -9 / SIGKILL** | **OOM killer** (container memory limit), kernel, or platform kill—not a normal Python exception. |
| **Heartbeat timeout ("zombie")** | No heartbeat reached the API server for `task_instance_heartbeat_timeout`: the supervisor was killed, the API server was unreachable, or the worker was overloaded; not the task's own code running long. |

Distinguish these in logs: OOM often appears in **Docker / k8s** events; zombies appear in **Airflow scheduler** logs.

**Docker Compose — Airflow container memory:** `docker-compose.yml` sets **`deploy.resources.limits.memory: ${AIRFLOW_MEMORY_LIMIT:-12g}`** on **`airflow`**. Large MISP events (100K+ attributes) require **8-12GB** due to PyMISP JSON parsing. Events are processed in pages of 5000 to limit amplification, but the initial event fetch loads the full JSON. **-9** with free host RAM usually means the **container** cgroup limit — check **`docker inspect … OOMKilled`**, **`docker stats`**, and [SETUP_GUIDE.md](SETUP_GUIDE.md) § troubleshooting.

## MISP → Neo4j–specific notes

- **`EDGEGUARD_DEBUG_GC`:** Forced full **`gc.collect()`** after each Neo4j sync chunk is **opt-in** only. In **memory-constrained** workers it can **increase peak RSS** and contribute to OOM.
- **`EDGEGUARD_REL_BATCH_SIZE`:** Relationship writes use batched **UNWIND** (default **500** definitions per round-trip). Lower this if Neo4j transactions time out.
- **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`:** Python-side node merge chunking (separate from relationship batching).

## Further reading

- [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — operator guide and MISP → Neo4j troubleshooting.
- Airflow docs: **scheduler configuration** (`[scheduler] task_instance_heartbeat_timeout`) and **workers configuration** (`[workers] min_heartbeat_interval`).

---

_Last updated: 2026-10-17 — Airflow 3 heartbeats: the supervisor heartbeats to the API server about every `[workers] min_heartbeat_interval` (5 s); the scheduler judges tasks by `task_instance_heartbeat_timeout` (300 s) every `task_instance_heartbeat_timeout_detection_interval` (10 s); `docker-compose.yml` now sets the Airflow 3 names (3600 s timeout, 60 s detection interval); the three pre-3 names it set until 2026-10 are not read, so Airflow's defaults applied until then. Prior: 2026-04-26 — PR-N33 docs audit: replaced "Airflow 2.11 and 3.2" mention with "Airflow 3.x" (EdgeGuard's pinned version since 2026-04-15). Prior: 2026-04-06._
