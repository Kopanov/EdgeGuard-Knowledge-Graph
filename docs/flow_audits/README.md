# Flow Audits — Tier 1 Findings Index

Audits of the three production-test-critical flows, run 2026-04-20 against commit `8e39f88`. Findings are organized for **730-day baseline production-test readiness** — what bites a 2-year historical run.

## Audits

| # | Flow | File | Findings |
|---|------|------|----------|
| 1 | [Baseline sequence](01_baseline_sequence.md) | `src/edgeguard.py` → DAG → collectors → MISP → Neo4j | 11 |
| 2 | [Checkpoint state machine](02_checkpoint_state_machine.md) | `src/baseline_checkpoint.py` + consumers | 13 |
| 3 | [Collector → MISP → Neo4j](03_collector_misp_neo4j.md) | Write-path + read-path + merge | 13 areas |

**Total: ~37 findings.** Most are real; a minority are hardening/cosmetics.

---

## Tier A — Production-test blockers (must fix before 730d run)

These directly threaten a 2-year baseline's ability to complete or resume. Roughly 7 findings across the three audits:

| ID | Finding | File | Severity |
|----|---------|------|----------|
| §1-1 | Baseline lock never acquired on DAG path → incrementals race baseline for 26+ hours | `dags/edgeguard_pipeline.py:2655-2697` | HIGH |
| §1-2 | `fetch_edgeguard_events` missing `since` filter → entire MISP scan, 100-page cap silently truncates | `src/run_misp_to_neo4j.py:172-224` | HIGH |
| §1-4 | `run_build_relationships` subprocess buffers 5h stdout → OOM risk + truncation on failure | `dags/edgeguard_pipeline.py:1704-1718` + `src/run_pipeline.py:1546-1594` | HIGH |
| §1-8 | `baseline_start` clears checkpoints on every run → breaks additive-baseline resume | `dags/edgeguard_pipeline.py:2251-2270` | HIGH |
| §2-1 | `save_checkpoint` swallows exceptions → silent checkpoint freeze | `src/baseline_checkpoint.py:84-89` | HIGH |
| §2-3 | No recovery from corrupt checkpoint → one corrupt byte wipes 2 years of progress | `src/baseline_checkpoint.py:76-81` | HIGH |
| §2-8 | Fresh-baseline + incremental cursor handoff → silent data gap | `src/baseline_clean.py:389-398` + `dags:2265` | HIGH |

## Tier B — Accounting / silent-degradation (fix soon)

| ID | Finding | Severity |
|----|---------|----------|
| §1-3 | `events_failed` double-count → `EdgeGuardSyncCoverageGap` alert flap | HIGH |
| §1-6 | 3-layer retry composition → up to 32 attempts/event during MISP flake | MEDIUM |
| §1-7 / §3-D | Trust check against live MISP user not enforced → Orgc rotation silently drops all timestamps | MEDIUM |
| §2-2 | Readers lock-free — future RMW callers would race silently | HIGH (latent) |
| §2-10 | `get_baseline_status` reads `"page"` but writer sets `"current_page"` — operator sees `"—"` | MEDIUM |
| §2-12 | `{completed:True, nvd_window_idx:X}` reachable stuck state | MEDIUM |
| §3-G | Indicator sub-batch fails whole batch; others fail per-item → inconsistent partial-failure | MEDIUM |
| §3-J | `misp_event_ids[]` on node not edge; `raw_data` frozen on edge CREATE | MEDIUM |

## Tier C — Cosmetics / observability gaps

§1-5, §1-9/§2-5 (pages list unbounded — duplicate), §1-10, §1-11, §2-4, §2-6, §2-7, §2-9, §2-11, §2-13, §3-A/H/I/K-L/M, plus hardening tests.

## Tier D — Data-surface parity (not 730d, but real)

§3-F: STIX-export vs Cypher-sync emit different IOC counts for `email-dst`, `text` (non-MITRE), and `filename`/`regkey`/`mutex`/`yara`/`sigma`/`snort`/`btc`. ResilMesh consumers reading `/stix21` get fewer IOCs than `/graphql`. Real bug but not a baseline-stability issue.

---

## Proposed fix plan

Staged so each PR is shippable and reviewable.

### PR-K1 — Baseline resume robustness (Tier A, consolidated)

**Scope:** Everything that turns a 730-day baseline into a restartable-without-data-loss run.

- §1-8 — Move `clear_checkpoint()` into `_baseline_clean` on fresh-baseline branch only; remove from `_baseline_start_summary`. Additive baselines preserve checkpoints.
- §2-1 — `save_checkpoint` re-raises on write failures (or sets degraded flag surfaced via `get_baseline_status`).
- §2-3 — Corrupt JSON recovery: rename to `.corrupt.{timestamp}` before returning `{}`; refuse to start fresh without `EDGEGUARD_CHECKPOINT_FORCE_RESET=1`.
- §2-8 — Baseline completion updates incremental cursors (or wipes them with warning) so first post-baseline incremental doesn't miss data.

**Size estimate:** ~100-150 LOC across 3 files + 6-8 new regression tests. Medium-risk (touches baseline + checkpoint code; needs thorough tests).

### PR-K2 — MISP events-index fetch fix (Tier A, isolated)

- §1-2 — Add `timestamp` + `searchall` params to `_fetch_edgeguard_events_via_requests_index`.

**Size:** ~10-20 LOC + 1 regression test. Low-risk, high-impact.

### PR-K3 — Subprocess stdout streaming for build_relationships (Tier A, isolated)

- §1-4 — Replace `subprocess.run(capture_output=True)` with `Popen` + iterated stdout stream to Airflow logger; proper SIGTERM-then-SIGKILL on timeout.

**Size:** ~40 LOC across 2 files + 1 mock-subprocess test. Low-risk.

### PR-K4 — Baseline lock design spike (Tier A → Issue #57 path)

- §1-1 — This IS Issue #57. Not a patch; needs design decision. Options tracked in the issue. Interim: operator runbook to pause scheduled DAGs before triggering baseline.

**Size:** Design doc first, then implementation PR. Bigger scope.

### PR-K5 — Accounting / display fixes (Tier B, grouped)

- §1-3 — `events_failed` double-count
- §2-10 — `get_baseline_status` wrong key
- §2-12 — Detect `{completed:True, nvd_window_idx:X}` stuck state

**Size:** ~50-80 LOC + regression tests. Low-risk.

### PR-K6 — Trust-check operator hardening (Tier B)

- §1-7 / §3-D — Preflight check that MISP API user's Orgc is in allowlist (or allow-untrusted flag set).

**Size:** ~30 LOC in `assert_misp_preflight` + test.

### Later / separate track

- Tier C — grouped hygiene PR or folded into the above.
- Tier D (STIX export parity) — own audit + PR; design question, not just a bug. Likely PR-K7 or a follow-up to PR #33 (UUID work).

---

## Ordering recommendation

**Sprint 1 (most urgent for 730d readiness):**
1. PR-K1 (baseline resume) — biggest risk reduction per LOC
2. PR-K2 (MISP since filter) — tiny patch, huge silent-truncation fix
3. PR-K3 (subprocess streaming) — small, targeted, closes OOM risk

**Sprint 2 (soon after):**
4. PR-K5 (accounting fixes) — improves operator experience + alert reliability
5. PR-K6 (trust-check preflight) — safety net for the production-test itself
6. PR-K4 design spike for Issue #57 — architectural, needs discussion

**Sprint 3 (after 730d proves stable):**
7. Tier C hygiene
8. PR-K7 STIX/Cypher parity (Tier D)
