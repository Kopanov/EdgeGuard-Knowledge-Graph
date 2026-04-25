# Airflow heartbeats, zombies, and worker kills (EdgeGuard)

**Purpose:** Explain why a MISP → Neo4j (or similar) task can **finish its Python logic** yet Airflow still marks the run **failed**, or the worker receives **SIGKILL (-9)**.

## Heartbeats vs task success

- With **LocalExecutor**, a **LocalTaskJob** process supervises the task. The scheduler expects **periodic heartbeats** from that job.
- If **`local_task_job_heartbeat_sec = 0`**, Airflow **2.7+** does **not** disable heartbeats: the LocalTaskJob heartbeat interval **defaults to `scheduler_zombie_task_threshold`**. With a **large** threshold (e.g. **3600**), heartbeats can be **very infrequent**, which is confusing operationally and can interact badly with startup-heavy tasks (long imports before the first heartbeat is visible). Prefer an **explicit** non-zero value (e.g. **30** seconds).
- **`zombie_detection_interval`** (default **10** seconds in Airflow 3.x — EdgeGuard's pinned version since the 2026-04-15 upgrade) is how often the **scheduler scans** for zombies; it is **not** the same as "kill after 10s". Tasks are still judged against **`scheduler_zombie_task_threshold`** (time since last heartbeat). A **60** second scan interval is a common tweak to reduce scheduler churn.
- **Recommendation:** set **`local_task_job_heartbeat_sec`** explicitly, tune **`scheduler_zombie_task_threshold`** with your max task duration, and adjust **`zombie_detection_interval`** only if operators still see false zombie kills after heartbeats are sane.

**Docker Compose (this repo):** `docker-compose.yml` on the **airflow** service sets:

| Variable | Default (compose) | Role |
|----------|-------------------|------|
| **`AIRFLOW__SCHEDULER__SCHEDULER_ZOMBIE_TASK_THRESHOLD`** | **3600** | No heartbeat for this long → zombie (raises Airflow’s default **300**). |
| **`AIRFLOW__SCHEDULER__LOCAL_TASK_JOB_HEARTBEAT_SEC`** | **30** | LocalTaskJob heartbeats every 30s. |
| **`AIRFLOW__SCHEDULER__ZOMBIE_DETECTION_INTERVAL`** | **60** | Scheduler zombie scan interval (seconds). |

Override any of these in **`.env`** using the same names if needed.

## SIGKILL (-9) vs “zombie”

| Signal / message | Typical cause |
|------------------|---------------|
| **Exit -9 / SIGKILL** | **OOM killer** (container memory limit), kernel, or platform kill—not a normal Python exception. |
| **Zombie task** | Scheduler lost contact with the worker heartbeat or job process; often **config** or **worker overload**, not always application logic. |

Distinguish these in logs: OOM often appears in **Docker / k8s** events; zombies appear in **Airflow scheduler** logs.

**Docker Compose — Airflow container memory:** `docker-compose.yml` sets **`deploy.resources.limits.memory: ${AIRFLOW_MEMORY_LIMIT:-12g}`** on **`airflow`**. Large MISP events (100K+ attributes) require **8-12GB** due to PyMISP JSON parsing. Events are processed in pages of 5000 to limit amplification, but the initial event fetch loads the full JSON. **-9** with free host RAM usually means the **container** cgroup limit — check **`docker inspect … OOMKilled`**, **`docker stats`**, and [SETUP_GUIDE.md](SETUP_GUIDE.md) § troubleshooting.

## MISP → Neo4j–specific notes

- **`EDGEGUARD_DEBUG_GC`:** Forced full **`gc.collect()`** after each Neo4j sync chunk is **opt-in** only. In **memory-constrained** workers it can **increase peak RSS** and contribute to OOM.
- **`EDGEGUARD_REL_BATCH_SIZE`:** Relationship writes use batched **UNWIND** (default **500** definitions per round-trip). Lower this if Neo4j transactions time out.
- **`EDGEGUARD_NEO4J_SYNC_CHUNK_SIZE`:** Python-side node merge chunking (separate from relationship batching).

## Further reading

- [AIRFLOW_DAGS.md](AIRFLOW_DAGS.md) — operator guide and MISP → Neo4j troubleshooting.
- Airflow docs: **LocalExecutor**, **LocalTaskJob**, **scheduler configuration**.

---

_Last updated: 2026-04-26 — PR-N33 docs audit: replaced "Airflow 2.11 and 3.2" mention with "Airflow 3.x" (EdgeGuard's pinned version since 2026-04-15). Prior: 2026-04-06._
