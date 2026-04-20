# Flow Audit §2 — Checkpoint State Machine

**Date:** 2026-04-20
**Commit audited:** `8e39f88`
**Scope:** `src/baseline_checkpoint.py` state machine + consumer patterns
**Method:** Enumerate every (prior_state, operation) → (next_state) transition, verify correctness, find gaps, find race conditions
**Goal:** Resume correctness IS the production test. A 730-day baseline takes days and WILL get interrupted.

---

## FINDING 1 [HIGH] — `save_checkpoint` swallows exceptions; silent checkpoint freeze

**File:** `src/baseline_checkpoint.py:84-89`
**Class:** JSON write failures silently lost

`save_checkpoint` wraps `_atomic_write` in `try/except Exception`, logs a WARNING only. On ENOSPC, read-only tmp dir, or fsync failure mid-730d run, the caller (`update_source_checkpoint`) returns normally while checkpoint never advances on disk. Next restart resumes from last successful write, redoing work. In-memory counter (`total_batches_done` in `nvd_collector.py:600`) already incremented — "pages reported" and "pages persisted" diverge silently.

**Impact on 730d baseline:** Transient ENOSPC or permission error causes silent freeze. Operator sees collection logs advancing while `edgeguard baseline status` shows hours-old numbers. On interruption, resume redoes a large chunk.
**Proposed fix:** Re-raise from `save_checkpoint`, or at minimum `logger.error` with exception + set module-level "degraded" flag that `load_checkpoint`/`get_baseline_status` surface.
**Regression test:** Monkey-patch `_atomic_write` to raise `OSError`; assert `update_source_checkpoint` surfaces failure (raises or sets flag).

---

## FINDING 2 [HIGH] — `fcntl.flock` per-process + readers lock-free; future RMW callers race silently

**File:** `src/baseline_checkpoint.py:118-155, 173-189`
**Class:** Concurrent write correctness

`fcntl.flock` works across processes on POSIX — correct. `load → mutate → save` is held under the lock in `update_source_checkpoint` — correct. BUT:
(a) `load_checkpoint()` at line 122 opens a separate fd; flock doesn't protect other fds. Process without the lock (`get_source_checkpoint` from CLI at `edgeguard.py:1681`) reads via `load_checkpoint()` and can observe a moment where write half-completed on filesystems where `rename` isn't atomic under concurrent readers.
(b) Readers in `get_source_checkpoint`, `get_source_incremental`, `get_baseline_status`, `cmd_checkpoint_status` all bypass the lock — fine for POSIX rename atomicity BUT means any future code doing `get_source_checkpoint → mutate → save_checkpoint` silently loses updates.

**Impact on 730d baseline:** No immediate bug today. Operator running `edgeguard baseline status` during NVD write is safe. But the API invites the RMW footgun — first future caller that does it (e.g. someone writing a manual "update incremental cursor from baseline completion" script) will stomp writes.
**Proposed fix:** Document invariant "readers are lock-free but writers MUST use `update_source_*`"; add assertion or lint rule. Optionally open lock file with `"a+"` and keep one handle.
**Regression test:** Two subprocesses × `update_source_checkpoint` on different sources 200 times; assert final JSON has 400 updates, no cross-source lost writes.

---

## FINDING 3 [HIGH] — No recovery from corrupt checkpoint; silent data loss

**File:** `src/baseline_checkpoint.py:76-81`
**Class:** JSON parse failure on load

If checkpoint JSON is corrupt (truncated by power loss between fsync and rename, external SIGKILL mid-write, disk bitrot), `load_checkpoint` logs warning and returns `{}`. Next `update_source_checkpoint` overwrites corrupted file with fresh per-source skeleton. **All prior baseline progress across all sources lost in one line**, with only `logger.warning` as record.

**Impact on 730d baseline:** One corrupt byte in 100-day-old checkpoint → entire baseline restarts from window 0. Days of CVE collection re-done.
**Proposed fix:** On parse failure, rename corrupt file to `baseline_checkpoint.json.corrupt.{timestamp}` before returning `{}`. Keep a single `.bak` updated on each successful save. Refuse to start fresh if corrupt file exists without `EDGEGUARD_CHECKPOINT_FORCE_RESET=1`.
**Regression test:** Write corrupt JSON; call `load_checkpoint`; assert `.corrupt.` backup created; call `update_source_checkpoint`; assert pre-corruption `.bak` preserved.

---

## FINDING 4 [MEDIUM] — Orphaned `.tmp` files never cleaned

**File:** `src/baseline_checkpoint.py:55-66`
**Class:** Orphaned files

`_atomic_write` cleans tmp on its own exception path, but SIGKILL between `open(tmp, "w")` and try-block entry can leave orphan `.tmp`. `load_checkpoint` never inspects/cleans. Over a 2-year run with restarts, `checkpoints/` accumulates stale `.tmp` files.

**Proposed fix:** In `load_checkpoint`, check for `CHECKPOINT_FILE.with_suffix(".tmp")` and unlink (log warning) OR attempt JSON-parse-then-rename if main file missing (recovery path).

---

## FINDING 5 [MEDIUM] — `pages` list unbounded; O(n²) write cost

**File:** `src/baseline_checkpoint.py:136-137`
**Class:** Unbounded growth

NVD 730-day at 2000/batch = ~125 entries. Fine. But any future fine-grained paginator accumulates thousands. Every `update_source_checkpoint` reads + JSON-dumps + fsyncs full file → O(n²) disk I/O. `pages` is display-only — resume uses `current_page`/`nvd_window_idx`.

**Proposed fix:** Drop `pages` or cap to rolling window. Replace with `current_page` + `max_page_seen` integer.
**Regression test:** 10K page updates; JSON stays <50KB.

---

## FINDING 6 [MEDIUM] — Path-traversal guard test gap

**File:** `src/baseline_checkpoint.py:40-45`
**Class:** Hardening / test coverage

Guard is correct (`Path.is_relative_to` post-BH2-HIGH fix). But no test pinning it. A future refactor regressing to `startswith` has nothing to fail. Edge case: symlink inside project pointing at `.git/objects` passes guard.

**Proposed fix:** `tests/test_baseline_checkpoint_path_guard.py` with cases for `/etc/passwd`, `/tmp/evil`, symlink-outside, `/project-evil/state` (prefix substring attack).

---

## FINDING 7 [MEDIUM] — Lock file persists forever; NFS hang risk

**File:** `src/baseline_checkpoint.py:97-99, 118-121, 173-175`
**Class:** Lock lifecycle

`_checkpoint_lock_path()` creates `.lock` file on first write, never removes. `clear_checkpoint(include_incremental=True)` unlinks checkpoint but not `.lock`. On NFS, stale flock state could hang writer forever.

**Proposed fix:** `clear_checkpoint(source=None, include_incremental=True)` also unlinks `.lock` (under exclusive lock first, then unlink).

---

## FINDING 8 [HIGH] — Fresh-baseline + incremental cursor handoff; silent data gap

**File:** `src/baseline_clean.py:389-398`, `src/baseline_checkpoint.py:192-229`, `dags/edgeguard_pipeline.py:2265-2266`
**Class:** Baseline↔incremental interaction

`_wipe_checkpoints` uses `include_incremental=True`. Airflow `_baseline_start_summary` defaults to `include_incremental=False`. Triggering baseline DAG without `{"clear_checkpoints": "all"}` wipes baseline state but preserves OTX's `otx_last_pulse_modified` from previous INCREMENTAL run. Fresh baseline then collects 2 years of OTX and pushes — but incremental cursor still points at previous run's date. Next incremental reads stale cursor → fetches from that date → may MISS pulses modified during baseline.

**Impact on 730d baseline:** After baseline completes, first incremental run re-fetches overlap but may miss pulses modified during the baseline run itself. Silent data gap in handoff.
**Proposed fix:** At end of baseline, EITHER (a) always clear incremental cursors with warning when `clear_checkpoints != "all"`, OR (b) explicitly set `otx_last_pulse_modified` and `mitre_bundle_etag` to `now()` at baseline completion.
**Regression test:** incremental cursor = T0 → run baseline → assert cursor cleared OR cursor ≥ baseline_start_time.

---

## FINDING 9 [MEDIUM] — `completed=True` pops nvd-specific keys from ALL sources; leaky abstraction

**File:** `src/baseline_checkpoint.py:148-152`
**Class:** Cross-source coupling

`completed=True` branch calls `entry.pop("nvd_window_idx", None)` and `entry.pop("nvd_start_index", None)` regardless of source. If some OTHER source ever sets these keys in `extra` (collision), completing that source strips them. Leaky abstraction — generic API knows collector-specific keys. If NVD grows a third key (`nvd_current_cve_cursor`), completion leaves it stale.

**Proposed fix:** Move nvd-specific pops into `nvd_collector.py`. On completion call `update_source_checkpoint("nvd", completed=True, extra={"nvd_window_idx": None, ...})` and teach API to treat `None` in `extra` as "pop this key".

---

## FINDING 10 [MEDIUM] — `get_baseline_status` + `cmd_checkpoint_status` display `"page"` key that writer never sets

**File:** `src/baseline_checkpoint.py:245`, `src/edgeguard.py:1702`
**Class:** State-semantics mismatch (same class as PR-G1 round-1)

`get_baseline_status` at line 245: `any(k in data for k in ("page", "pages", ...))` — `"page"` never written, but `"pages"` IS, so check passes. `edgeguard.py:1702`: `data.get("page", data.get("pages_collected", "—"))` — neither key is what writer stores. Operator sees `"—"` for pages on every in-progress baseline.

**Impact on 730d baseline:** Cosmetic but undermines operator trust in `edgeguard baseline status` during a 3-day run.
**Proposed fix:** Replace both with `current_page`. Add source-pinning test.
**Regression test:** Write checkpoint with `page=42`; assert `cmd_checkpoint_status` displays 42, not `—`.

---

## FINDING 11 [LOW] — `datetime.now()` called repeatedly inside lock; clock-skew noise

**File:** `src/baseline_checkpoint.py:126, 150, 154, 180, 188`
**Class:** Cosmetics

Multiple `datetime.now(timezone.utc).isoformat()` per write. Under NTP correction mid-lock, `updated_at < completed_at` possible. Cosmetic only.

**Proposed fix:** Compute `now` once per call, reuse.

---

## FINDING 12 [MEDIUM] — `{completed: True, nvd_window_idx: X}` is a reachable state with no recovery

**File:** `src/collectors/nvd_collector.py:547-565`, `src/baseline_checkpoint.py:148-152`
**Class:** Unreachable-to-leave state

Normal ops keep the fields coupled (completed → keys popped). BUT: if `update_source_checkpoint("nvd", page=1, extra={"nvd_window_idx": 5})` is called on a completed entry (e.g. operator manual edit, or a future code path), state `{completed: True, nvd_window_idx: 5}` is reachable. Resume check (nvd:555) sees `completed=True`, skips resume. Counter resets to 0 (PR-G1 fix), fresh run starts. But `nvd_window_idx=5` stays stale in the file. No code removes it.

**Impact on 730d baseline:** Manual-edit recovery path is unsafe. Operator debugging could inadvertently trigger full restart.
**Proposed fix:** Treat `{completed: True, nvd_window_idx: present}` as error state — log warning + force either resume (clear `completed`) OR restart (clear window_idx). Don't silently pick one.
**Regression test:** Construct this state, call baseline collect, assert warning + consistent behavior.

---

## FINDING 13 [LOW] — `get_source_checkpoint` / `get_source_incremental` don't guard against non-dict entries

**File:** `src/baseline_checkpoint.py:94, 165`
**Class:** Defensive-check inconsistency

`clear_checkpoint` branches at 207, 222 have `isinstance(checkpoints[source], dict)` guards. Readers at 94 and 165 don't — a manually-edited/corrupt file with non-dict source value raises `AttributeError`.

**Proposed fix:** Add `isinstance` guard or use `getattr` pattern.

---

## What's handled well

- **Atomic write**: tmp → fsync → rename; cleanup on failure. POSIX-correct.
- **Path-traversal guard**: `Path.is_relative_to` is the correct primitive. Docstring explains prior `startswith` bug.
- **fcntl advisory lock** on BOTH `update_source_checkpoint` AND `update_source_incremental` — baseline and incremental writes don't race within same source entry.
- **Fresh-baseline counter reset** (PR-G1 Bugbot round-2): explicit `completed=True` reset handles re-run-after-complete transition.
- **Writer/reader key alignment** (PR-G1 Bugbot round-1): `current_page` read matches write; test pins it.
- **Incremental preservation contract**: `clear_checkpoint(include_incremental=False)` is default; wipe scripts opt-in to True. Well-documented.
- **MISP redirect/host-header hardening** in baseline_clean.py: max_redirects=0, EDGEGUARD_MISP_HTTP_HOST, 302-tracking, client-side `"EdgeGuard" in info` filter — defends wipe against DNS hijack + permission masquerade.
- **Settle+verify-poll** with derived timeout on Neo4j size: adaptive to scale.

---

## State transition table

Entity: `checkpoints[src]`. Keys: `completed`, `current_page`, `pages`, `items_collected`, `nvd_window_idx`, `nvd_start_index`, `incremental`.

| Prior state | Operation | Next state | Notes |
|---|---|---|---|
| absent | `update_source_checkpoint(src, page=1, items=N)` | `{current_page:1, pages:[1], items:N, completed:False, started_at, updated_at}` | Correct |
| in-progress | `update_source_checkpoint(src, page=P+1, items=M)` | `pages+[P+1]`, `current_page=P+1`, `items=M` | `pages` grows unbounded (F5) |
| in-progress | `update_source_checkpoint(src, completed=True)` | `completed=True`, `completed_at`, `nvd_*` popped | Correct |
| completed | `update_source_checkpoint(src, page=1, ...)` | `completed` stays True, `current_page=1`, nvd keys may re-appear | **F12: stuck state reachable via `extra={nvd_window_idx:X}` + no recovery** |
| in-progress | `clear_checkpoint(src, include_incremental=False)` | `{incremental:...}` preserved, else entry deleted | Correct |
| completed | `clear_checkpoint(src, include_incremental=False)` | Same as above | Correct |
| any | `clear_checkpoint(src, include_incremental=True)` | Entry deleted | Correct |
| global | `clear_checkpoint(None, include_incremental=True)` | File unlinked, `.lock` NOT cleaned | F7: lock residue |
| corrupt JSON | `load_checkpoint()` | Returns `{}`, corrupt file stays | **F3: silent data loss** |
| `.tmp` present, main absent | `load_checkpoint()` | Returns `{}`, tmp orphaned | **F4: recovery gap** |

**Gaps flagged:**
- `{completed:True, nvd_window_idx:X}` — reachable, no recovery
- Corrupt JSON → "start fresh, lose everything"
- `.tmp` orphans never reconciled
