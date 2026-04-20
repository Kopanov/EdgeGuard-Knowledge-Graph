# Flow Audit §1 — Baseline Sequence

**Date:** 2026-04-20
**Commit audited:** `8e39f88` (post PR-F9/G1/I/J merge)
**Scope:** Full `edgeguard baseline --days N` / `fresh-baseline` run, CLI + Airflow DAG paths
**Method:** Single-agent deep walk of `src/edgeguard.py` → `run_pipeline.py` + `dags/edgeguard_pipeline.py` → collectors → `misp_writer.py` → `run_misp_to_neo4j.py` → `build_relationships.py` + `enrichment_jobs.py` + `baseline_checkpoint.py` + `baseline_lock.py` + `baseline_clean.py`
**Goal:** Find residual bugs, race conditions, contract mismatches, and production-test risks that the prior 2026-04-20 multi-agent audit missed. Optimize for **730-day baseline run** risk.

---

## FINDING 1 [HIGH] — Baseline lock never acquired on DAG path; incrementals race baseline for 26+ hours

**File:** `dags/edgeguard_pipeline.py:2655-2697` + `src/edgeguard.py:2612-2628`
**Class:** Race condition + CLI-vs-DAG divergence

Both `cmd_baseline` and `cmd_fresh_baseline` now delegate to the Airflow DAG. The DAG has NO task that calls `acquire_baseline_lock()`. Every incremental DAG still calls `baseline_skip_reason()` on a sentinel nothing writes. Over a 26-hour baseline, ~52 OTX runs + 6 CISA/VT runs + 3 NVD runs + 1 daily + 1 neo4j_sync will attempt writes concurrently. Reintroduces the MISP PHP-FPM exhaustion that PR-F4 tier-1 serialization was meant to fix.

This IS Issue #57; it's called out here to remind us that the problem the CLI path used to mitigate (in-process lock) no longer applies when CLI delegates to DAG.

**Proposed fix:** Issue #57 resolution (DB-backed Variable mutex or ExternalTaskSensor gate) as PythonOperator bracketing `baseline_tier1 → … → baseline_enrichment`. Interim: document operator runbook to pause the 4 scheduled DAGs before triggering baseline.
**Regression test:** E2E that triggers `edgeguard_baseline` and asserts `is_baseline_running() is not None` during tier-1 TaskGroup.

---

## FINDING 2 [HIGH] — `_fetch_edgeguard_events_via_requests_index` drops `since` filter; scans entire MISP on re-triggers

**File:** `src/run_misp_to_neo4j.py:172-224` (esp. line 190 — no `timestamp`/`from` in params)
**Class:** Contract mismatch + latency

`_fetch_edgeguard_events_via_requests_index` accepts a `since` parameter but passes it ONLY to a client-side filter (line 215). The GET request itself has no timestamp/from param. The PyMISP/restSearch fallback DOES pass `timestamp` (lines 977, 997). Fresh baseline is fine (empty MISP), but any re-triggered baseline against a populated MISP walks up to 100 pages × 500 = 50,000 event rows before local filtering. The 100-page cap silently truncates — events past page 100 never sync to Neo4j.

**Impact on 730d baseline:** On re-baseline of a mature ResilMesh MISP (with federated peers), `full_neo4j_sync` spends 5-15 min on index-fetch alone and can silently truncate. Exact coverage-gap pattern the `EdgeGuardSyncCoverageGap` alert was built to catch — but the gap is UPSTREAM of the accounting.
**Proposed fix:** Add `params["timestamp"] = int(since.timestamp())` (and `params["searchall"] = "EdgeGuard"`) when `since` is not None.
**Regression test:** MISP with 60K events (50K non-EdgeGuard, 10K EdgeGuard); set `since = now - 3d`; assert GET count bounded by (EdgeGuard events in window / 500) + 1, not 100.

---

## FINDING 3 [HIGH] — Retry-pass can double-increment `events_failed` under cascading transient MISP failure

**File:** `src/run_misp_to_neo4j.py:3629-3673`
**Class:** Error-recovery accounting invariant

Event fails in main loop at 3486-3500, re-queued into `failed_events` without incrementing `events_failed`. Retry pre-bailout at 3629-3639 iterates `failed_events` and increments `events_failed` once. But the `skipped_large → failed_events` handoff at 3595-3596 re-adds events; if the same event already got counted as "permanent failure" at 3603-3604 when a cap hit, it's counted once. If mid-retry the `_consecutive_conn_failures >= 3` bail-out fires, the iteration `failed_events[retry_idx:]` counts remaining items — can go negative under interleaving. Invariant `events_index_total == events_processed + events_failed` breaks → `EdgeGuardSyncCoverageGap` false-positive flap → operators learn to ignore it → masks real coverage loss.

**Proposed fix:** Tag each entry with `_counted_as_failed: bool` first time `events_failed` increments; skip re-increment in bail-out paths.
**Regression test:** Unit test simulating: main-loop fails event X → re-queued → skipped_large retry fails X → moved to failed_events → pre-retry bail-out fires. Assert `events_failed == 1`, not 2.

---

## FINDING 4 [HIGH] — `run_build_relationships` subprocess buffers 5h stdout; OOM + truncation risk

**File:** `dags/edgeguard_pipeline.py:1704-1718` + `src/run_pipeline.py:1546-1594`
**Class:** Memory + error-recovery

Both DAG and CLI invoke `build_relationships.py` via `subprocess.run(..., capture_output=True, timeout=18000)`. `capture_output=True` buffers ENTIRE 5h of stdout+stderr in Airflow worker memory. On a 344K-node graph, that's tens of MB of APOC query progress logs. On failure, `logger.error(f"build_relationships failed:\n{result.stderr}")` dumps the whole buffer into Airflow log (double-logged). On timeout, buffered stdout is lost; child process may not have graceful-rollback window.

**Impact on 730d baseline:** Airflow worker memory balloons alongside Neo4j's own RAM. On 8GB worker + bumped `NEO4J_TX_MEMORY_MAX=8g`, real OOM risk — new since the 5h timeout bump.
**Proposed fix:** Stream stdout with `Popen` + iterated `.readline()` into Airflow logger; on timeout send SIGTERM, wait 30s, then SIGKILL.
**Regression test:** Mocked build_relationships writing 100MB stdout over 60s; assert parent Airflow task RSS stays under ~500MB.

---

## FINDING 5 [MEDIUM] — `run_pipeline.py` fresh-baseline holds pipeline.lock AFTER `reset_baseline_data` clears; scheduled DAG can slip

**File:** `src/run_pipeline.py:1075-1111, 1190-1217`
**Class:** Race + partial-state

`run()` acquires `pipeline.lock` + baseline_lock + enters `_run_pipeline_inner`. At 1204, `reset_baseline_data()` deletes all Neo4j + clears checkpoint via `_wipe_checkpoints(include_incremental=True)` — wipes OTX's modified-since cursor AND MITRE's ETag. If a scheduled DAG slips `baseline_skip_reason()` (see Finding 1), it starts from beginning-of-time and floods MISP. Also: `pipeline.lock` path (1068) is shared with non-baseline CLI runs — concurrent plain `run_pipeline.py` doesn't take baseline lock. Contract unclear.

**Proposed fix:** `_wipe_checkpoints` called from baseline path should preserve incremental state unless operator explicitly passed `clear_checkpoints: "all"`. Logic already exists in `_baseline_start_summary` (dags:2265), missing in `reset_baseline_data`.
**Regression test:** Populate incremental OTX cursor; call `reset_baseline_data()`; assert cursor survives unless `clear_checkpoints="all"`.

---

## FINDING 6 [MEDIUM] — Three compounding retry layers on MISP 5xx: up to 32 attempts per failed event

**File:** `src/collectors/misp_writer.py:588, 1619` + `src/run_misp_to_neo4j.py:3661-3693` + `src/collectors/collector_utils.py:59-108`
**Class:** Retry composition

`retry_with_backoff(max_retries=4, base_delay=10.0)` = 5 attempts with 10/20/40/80/160s delays = ~310s worst case per `_push_batch`. `_get_or_create_event` has 4 retries. Outer `push_items` doesn't retry (catches `MispTransientError` and counts batch failed), but `run()` retry_pass (3661) re-pushes entire events, each with `_push_batch` doing its 5-attempt ladder. For a transiently-broken event: 5 × several batches in main + cooldown + 5 × several batches in retry ≈ 10min+ per event, cascading up to 20 events by `_MAX_RETRY_FAILED_EVENTS`. Parent-DAG liveness callback (PR-F6) mitigates for collectors but NOT for sync phase.

**Impact on 730d baseline:** 5min MISP flake → tier-1 NVD collector spends 40+ min on backoff-waiting, eating 5h execution_timeout.
**Proposed fix:** Cap total cumulative retry wall-clock per-event (e.g., `max_retries × base_delay ≤ 120s`); jittered backoff. Or add liveness callback to `_process_single_event`.
**Regression test:** Monkeypatch `_push_batch` to always raise transient error; run `sync.run()` over 5 events with 30s budget; assert bails within ~35s, not hundreds.

---

## FINDING 7 [MEDIUM] — `is_attribute_creator_trusted` not enforced at MISP-write time; self-laundering + stale-UUID silent failure

**File:** `src/source_trust.py:323-379`, called from `src/source_truthful_timestamps.py:627`
**Class:** Security / trust-boundary

Trust allowlist is consulted at MISP-READ time, not write time. After EdgeGuard writes its own attributes, those events bear the EdgeGuard collector's creator org — so on read-back, trust is always TRUE for EdgeGuard's own writes regardless of upstream source. Defense is a no-op for the only path that matters. Separately: if `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` is set to a pre-wipe UUID but the new EdgeGuard MISP user has a different Orgc UUID, every attribute rejects with `TRUST_REASON_NOT_ALLOWLISTED` and no data lands in Neo4j. `_log_defense_state()` at import logs WARNING but there's no startup check tying configured UUIDs to live MISP user.

**Impact on 730d baseline:** In prod/staging with misconfigured allowlist, fresh-baseline completes "successfully" (all MISP pushes OK) but Neo4j ends with zero synced nodes. 6h full_sync silently drops everything.
**Proposed fix:** `assert_misp_preflight` verifies current MISP API user's Orgc UUID is in `EDGEGUARD_TRUSTED_MISP_ORG_UUIDS` if allowlist configured; fail DAG before any collector runs.
**Regression test:** Set allowlist to random UUID, run preflight; assert exit code non-zero with actionable message.

---

## FINDING 8 [MEDIUM] — `_baseline_start_summary` clears checkpoints on EVERY baseline — kills additive-baseline resume

**File:** `dags/edgeguard_pipeline.py:2687-2697` (chain) + `2251-2270` (clear_checkpoint)
**Class:** Partial-state interruption

Chain: `misp_health → baseline_clean → baseline_start → tier1 → ...`. `baseline_clean` no-ops unless `fresh_baseline=true`. `baseline_start` ALWAYS calls `clear_checkpoint()` (line 2266). On ADDITIVE baseline (no fresh_baseline), if tier-1 collector fails mid-page-50, the next retry starts from page 1 of every collector — checkpoint resume never actually fires. Second problem: on fresh-baseline, `_baseline_clean` ALREADY cleared checkpoints; `baseline_start` re-clears (harmless) then logs "Cleared baseline checkpoints (incremental cursors preserved)" — a lie, fresh-baseline already wiped them.

**Impact on 730d baseline:** Any retry/resume scenario loses all progress. 20h-in baseline that Airflow retries (retries=1 set) restarts from scratch. Checkpoint-resume story in `docs/BASELINE_CHECKPOINTS.md` is dead on arrival for DAG path.
**Proposed fix:** Move `clear_checkpoint()` INTO `_baseline_clean` on fresh-baseline branch only. Remove from `_baseline_start_summary`. Additive baselines MUST preserve checkpoints.
**Regression test:** Trigger `edgeguard_baseline` with no conf; after `baseline_start` completes, assert checkpoint file still contains pre-existing entries.

---

## FINDING 9 [MEDIUM] — `update_source_checkpoint` `pages` list is append-unbounded; O(n²) disk I/O amplification

**File:** `src/baseline_checkpoint.py:136-137`
**Class:** Unbounded growth + accounting

Every page increment appends to `entry["pages"]`. On 2-year NVD baseline with multi-window paginator (120-day × ~5K items), list can reach tens of thousands. File re-serialized atomically on every page increment (line 87) — each write = full dict. At 10K × 8 collectors = 80K entries, each write ≈ 400KB JSON re-serialized millions of times.

The `pages` list is ONLY used by `get_baseline_status()` (line 249) to report `len(data.get("pages", []))` — resume logic uses `current_page`. Write-only state carrying no semantic value.

**Proposed fix:** Drop `pages` (or cap at last 100 for debugging). Keep `current_page` + `pages_collected` counter.
**Regression test:** 10K page updates; assert file stays O(KB), not O(MB).

*Note: this is the same unbounded-growth issue flagged in §2 audit Finding 5.*

---

## FINDING 10 [LOW] — `_trigger_baseline_dag` 60s timeout too tight on cold Airflow scheduler

**File:** `src/edgeguard.py:2377-2426`
**Class:** Operator footgun

`docker compose exec -T airflow airflow dags trigger ...` with `timeout=60` against a scheduler JIT-importing a 2700-line DAG file + 11 collectors hits ceiling on cold starts. Operator sees "did not respond within 60s", re-runs, produces duplicate `manual__` run_ids (mitigated by `max_active_runs=1` but still noisy).

**Proposed fix:** Default to 180s, add one automatic retry on `TimeoutExpired`.

---

## FINDING 11 [LOW] — `record_pipeline_duration` reference may silent-fail

**File:** `src/run_misp_to_neo4j.py:3722-3726`
**Class:** Contract / silent-fail

`record_pipeline_duration("misp_to_neo4j", duration)` inside `if _METRICS_AVAILABLE: try/except: logger.debug(...)`. If name is not importable, fails silently at DEBUG level; Prometheus never records sync duration.

**Proposed fix:** Verify/fix import; fail loud on AttributeError once, not silently.

---

## What's handled well (do NOT change)

- **Atomic O_EXCL sentinel acquisition in `baseline_lock.py`** — PR #38 bugbot-driven rewrite; O_EXCL+corrupt-sentinel-probe handles known race windows
- **Preservation of incremental cursors on checkpoint clear** (`baseline_checkpoint.py:192-229`) — default-preserve contract is documented and honored
- **PR-F6 parent-DAG liveness callback** — correctly scoped to tier-1 collector sites; rate-limited to 60s; `AbortedByDagFailureException` properly NOT routed through transient/catastrophic error split
- **Tier-1 sequential chain** (cisa→mitre→otx→nvd) — empirically justified by 2026-04-19 NVD loss incident
- **MISP wipe's client-side "EdgeGuard in info" filter + 302-count-without-delete** (`baseline_clean.py:510-519, 572-585`) — protects against false positives AND permission-misconfig silent failures
- **`EDGEGUARD_MAX_EVENT_ATTRIBUTES` deferred-large-event path** + `_MAX_RETRY_FAILED_EVENTS` cap — two-phase retry with explicit caps is right shape
- **`reset_baseline_data` settle-verify-poll loop** with derived timeout — handles 350K-node case correctly (baseline_clean:665-675, 744-767)
- **PR-F5 baseline DAG conf typo validation** — exactly right UX for preventing `{"days": 730}` silent-additive trap
- **Retry decorator exception-typed** (`collector_utils.py:86-106`) — `TransientServerError` base class approach is clean
