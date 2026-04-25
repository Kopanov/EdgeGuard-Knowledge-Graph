#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# preflight_baseline.sh — pre-kickoff readiness check for 730d MISP→Neo4j baseline
# -----------------------------------------------------------------------------
#
# Runs a sequence of operator-facing checks that MUST be green before you
# trigger a 730-day baseline. Designed to catch the exact failure modes that
# caused the 2026-04-19 MISP-PHP-FPM exhaustion + 14.7% NVD loss and the
# 2026-04-22 NULL-CVE-date / fragmented-zone-stats issues Bravo surfaced.
#
# Exit code:
#   0 = all checks green; safe to kickoff
#   1 = one or more checks failed; DO NOT launch
#
# Check matrix (all are hard-fail; caveats are WARNed but do not block unless
# EDGEGUARD_PREFLIGHT_STRICT=1):
#
#   [1] required env vars present (NEO4J_PASSWORD, MISP_API_KEY, MISP_URL)
#   [2] Neo4j reachable + APOC available + baseline-critical indexes present
#   [3] MISP API reachable + auth valid + server version ≥ 2.4
#   [4] launch-path decision confirmed (CLI or DAG+pause) — see RUNBOOK
#   [5] IF DAG launch path: the 4 incremental DAGs are PAUSED (Issue #57)
#   [6] Airflow worker RAM ≥ 4 GB
#   [7] Prometheus alerts.yml parses + edgeguard rule group loaded
#   [8] no stale baseline_lock sentinel from a previous aborted run
#   [9] kill-switch env vars set to safe defaults (none unexpectedly forced-on)
#   [10] coverage gate: last full pytest run was green
#
# Usage:
#   ./scripts/preflight_baseline.sh [--launch-path cli|dag]
#   EDGEGUARD_PREFLIGHT_STRICT=1 ./scripts/preflight_baseline.sh --launch-path dag
#
# See docs/RUNBOOK.md § "Baseline-day protocol" for manual equivalents.
# -----------------------------------------------------------------------------

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Colors (only if stdout is a tty)
if [ -t 1 ]; then
  C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YLW=$'\033[1;33m'
  C_CYN=$'\033[0;36m'; C_OFF=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YLW=''; C_CYN=''; C_OFF=''
fi

pass() { printf '  %s✓%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_YLW" "$C_OFF" "$*" >&2; WARNINGS=$((WARNINGS+1)); }
fail() { printf '  %s✗%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; FAILURES=$((FAILURES+1)); }
hdr()  { printf '\n%s== %s ==%s\n' "$C_CYN" "$*" "$C_OFF"; }

WARNINGS=0
FAILURES=0
LAUNCH_PATH="${EDGEGUARD_PREFLIGHT_LAUNCH_PATH:-}"
STRICT="${EDGEGUARD_PREFLIGHT_STRICT:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --launch-path) LAUNCH_PATH="$2"; shift 2 ;;
    --launch-path=*) LAUNCH_PATH="${1#*=}"; shift ;;
    --strict) STRICT=1; shift ;;
    -h|--help)
      sed -n '3,35p' "$0"
      exit 0
      ;;
    *) fail "unknown flag: $1"; exit 1 ;;
  esac
done

if [[ -z "${LAUNCH_PATH}" ]]; then
  warn "no --launch-path given; assuming 'cli'. Use --launch-path=dag to enable the DAG-pause check."
  LAUNCH_PATH="cli"
fi

case "$LAUNCH_PATH" in
  cli|dag) ;;
  *) fail "invalid --launch-path '$LAUNCH_PATH' (must be 'cli' or 'dag')"; exit 1 ;;
esac

# -----------------------------------------------------------------------------
# [1] required env vars present
# -----------------------------------------------------------------------------
hdr "[1] required env vars"
# NOTE (Bugbot round 1): measure ${#var_value}, not ${#var}. ${#var}
# returns the length of the variable NAME ("NEO4J_PASSWORD" = 14 chars);
# we want the length of the indirectly-referenced VALUE so a 40-char
# API key actually shows 40. The copy says "value not echoed" so the
# reported count must correspond to the value.
for var in NEO4J_PASSWORD MISP_API_KEY MISP_URL; do
  var_value="${!var:-}"
  if [[ -z "$var_value" ]]; then
    fail "$var is not set (export it or add to .env + docker compose up -d)"
  else
    pass "$var is set (${#var_value} chars — value not echoed)"
  fi
done

# -----------------------------------------------------------------------------
# [2] Neo4j reachable + APOC available + baseline-critical indexes present
# -----------------------------------------------------------------------------
hdr "[2] Neo4j reachability + indexes"
NEO4J_URL="${NEO4J_URL:-bolt://localhost:7687}"
# NOTE (Bugbot round 2, Low): NEO4J_PASSWORD must NOT be interpolated into
# the command line — it'd be visible via `ps aux` / /proc/*/cmdline to any
# user on the system, plus risks word-splitting on spaces or shell
# metacharacters. Instead:
#   - Build the command as a bash ARRAY (preserves word boundaries).
#   - For docker path: pass ``-e NEO4J_PASSWORD`` (by name, no =value) so
#     docker compose exec forwards the var from the calling shell into the
#     container env without ever putting the value in argv.
#   - Omit ``-p`` entirely; cypher-shell reads NEO4J_PASSWORD from its env
#     automatically when ``-p`` is absent.
export NEO4J_PASSWORD  # ensure docker compose exec -e NEO4J_PASSWORD sees it
if command -v docker >/dev/null 2>&1 && docker compose ps --services 2>/dev/null | grep -q neo4j; then
  NEO4J_CMD=(docker compose exec -T -e NEO4J_PASSWORD neo4j cypher-shell -u neo4j --format plain)
else
  # Fallback: assume cypher-shell is on PATH (reads NEO4J_PASSWORD from env)
  NEO4J_CMD=(cypher-shell -a "${NEO4J_URL}" -u neo4j --format plain)
fi

if "${NEO4J_CMD[@]}" "RETURN 1 AS ok;" >/dev/null 2>&1; then
  pass "Neo4j accepts auth + returns a query"
else
  fail "Neo4j not reachable at $NEO4J_URL with current credentials"
fi

APOC_OK=$("${NEO4J_CMD[@]}" "CALL dbms.procedures() YIELD name WHERE name STARTS WITH 'apoc.coll' RETURN count(*) AS n;" 2>/dev/null | tail -1 || true)
if [[ "$APOC_OK" =~ ^[1-9] ]]; then
  pass "APOC coll procedures present ($APOC_OK procs)"
else
  fail "APOC procedures missing (apoc.coll.sort is required for PR-N19 Fix #2 canonical zone ordering)"
fi

# Critical uniqueness constraints + the n.uuid index (PR #33 when merged)
INDEX_COUNT=$("${NEO4J_CMD[@]}" "SHOW INDEXES YIELD name WHERE name CONTAINS 'uuid' OR name CONTAINS 'indicator' OR name CONTAINS 'cve' RETURN count(*) AS n;" 2>/dev/null | tail -1 || true)
if [[ "$INDEX_COUNT" =~ ^[1-9] ]]; then
  pass "Neo4j has $INDEX_COUNT baseline-relevant indexes"
else
  warn "no baseline-relevant indexes found — did you run create_indexes()? See docs/RUNBOOK.md §4 remediation."
fi

# -----------------------------------------------------------------------------
# [3] MISP API reachable + auth valid
# -----------------------------------------------------------------------------
hdr "[3] MISP API reachability"

# NOTE (Bugbot round 2, Medium): honor EDGEGUARD_SSL_VERIFY / SSL_VERIFY so
# the preflight TLS posture matches the rest of the stack. Pre-fix, ``curl
# -k`` unconditionally disabled verification and sent MISP_API_KEY over an
# unverified TLS connection — MitM risk even when SSL_VERIFY=true was set
# project-wide. Semantics match src/config.py: only the literal string
# "true" (case-insensitive, stripped) enables verification; anything else
# disables (strict allow-list — typos default to disabled).
SSL_VERIFY_RAW="${EDGEGUARD_SSL_VERIFY:-${SSL_VERIFY:-}}"
SSL_VERIFY_NORM="$(printf '%s' "${SSL_VERIFY_RAW}" | tr '[:upper:]' '[:lower:]' | xargs 2>/dev/null || echo "")"
# Bugbot round 3 (PR #104, Low): pre-fix used
# ``CURL_TLS_FLAG=()`` (empty bash array) + ``"${CURL_TLS_FLAG[@]}"``
# expansion. Under bash < 4.4 with ``set -u`` active, expanding an
# EMPTY array via ``"${arr[@]}"`` raises "unbound variable" and aborts
# the script. This affects macOS's default bash 3.2 — a common
# operator workstation. The bug fired on the RECOMMENDED production
# path (``EDGEGUARD_SSL_VERIFY=true``), causing the script to abort
# with an unhelpful error instead of completing the MISP probe.
#
# Fix: use a plain string ``CURL_TLS_FLAG_STR`` (always set; empty
# string when verification enabled, ``-k`` when disabled), then
# expand unquoted so an empty value contributes nothing to argv.
# Safe across bash 3.2+ and POSIX sh.
if [[ "$SSL_VERIFY_NORM" == "true" ]]; then
  CURL_TLS_FLAG_STR=""
  pass "TLS verification enabled (EDGEGUARD_SSL_VERIFY=true)"
else
  CURL_TLS_FLAG_STR="-k"
  warn "TLS verification DISABLED (EDGEGUARD_SSL_VERIFY='${SSL_VERIFY_RAW:-unset}'); MISP_API_KEY will be sent over unverified TLS. Set EDGEGUARD_SSL_VERIFY=true for production."
fi

if [[ -n "${MISP_URL:-}" ]] && [[ -n "${MISP_API_KEY:-}" ]]; then
  # shellcheck disable=SC2086  # intentional unquoted: empty string must expand to nothing
  MISP_HTTP=$(curl $CURL_TLS_FLAG_STR -s -o /tmp/misp_preflight.out -w "%{http_code}" \
    -H "Authorization: ${MISP_API_KEY}" \
    -H "Accept: application/json" \
    "${MISP_URL%/}/servers/getVersion" || echo "000")
  if [[ "$MISP_HTTP" == "200" ]]; then
    MISP_VER=$(python3 -c "import json,sys; d=json.load(open('/tmp/misp_preflight.out')); print(d.get('version','?'))" 2>/dev/null || echo "?")
    pass "MISP auth OK (version $MISP_VER)"
  elif [[ "$MISP_HTTP" == "401" || "$MISP_HTTP" == "403" ]]; then
    fail "MISP auth failed (HTTP $MISP_HTTP) — MISP_API_KEY invalid or expired"
  else
    fail "MISP unreachable at $MISP_URL (HTTP $MISP_HTTP)"
  fi
  rm -f /tmp/misp_preflight.out
else
  fail "MISP_URL / MISP_API_KEY missing; cannot probe"
fi

# -----------------------------------------------------------------------------
# [4] + [5] launch-path decision (CLI assumed, or DAG+pause verification)
# -----------------------------------------------------------------------------
hdr "[4][5] launch-path = $LAUNCH_PATH"
if [[ "$LAUNCH_PATH" == "cli" ]]; then
  pass "CLI launch path — in-process baseline_lock will gate incrementals (src/run_pipeline.py:1093)"
  pass "No DAG pausing needed; baseline_skip_reason() will self-skip the 4 incrementals"
else
  # DAG path — verify the 4 incrementals are paused
  if ! command -v docker >/dev/null 2>&1; then
    warn "docker not found; cannot verify Airflow DAG pause state automatically"
  else
    for dag in edgeguard_daily edgeguard_medium_freq edgeguard_pipeline edgeguard_low_freq; do
      STATE=$(docker compose exec -T airflow-worker airflow dags details "$dag" 2>/dev/null | grep -iE '^is_paused' | awk '{print $NF}' || echo "")
      if [[ "$STATE" == "True" ]]; then
        pass "DAG $dag is PAUSED"
      elif [[ -z "$STATE" ]]; then
        warn "DAG $dag state not queryable (airflow-worker unresponsive?)"
      else
        fail "DAG $dag is NOT paused — pause it before baseline (docs/RUNBOOK.md Option B). Issue #57."
      fi
    done
  fi
fi

# -----------------------------------------------------------------------------
# [6] Airflow worker RAM ≥ 4 GB
# -----------------------------------------------------------------------------
hdr "[6] Airflow worker RAM"
if command -v docker >/dev/null 2>&1; then
  MEM_BYTES=$(docker inspect edgeguard-airflow-worker 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); m=d[0].get('HostConfig',{}).get('Memory',0) or 0; print(m)" 2>/dev/null || echo "0")
  if [[ "$MEM_BYTES" -ge 4294967296 ]]; then
    pass "airflow-worker memory limit $(($MEM_BYTES / 1024 / 1024)) MB (≥ 4 GB)"
  elif [[ "$MEM_BYTES" -eq 0 ]]; then
    warn "airflow-worker has no Docker memory limit set — baseline might get OOM-killed by host"
  else
    fail "airflow-worker memory limit $(($MEM_BYTES / 1024 / 1024)) MB is below 4 GB baseline minimum"
  fi
else
  warn "docker not available; skipping memory check"
fi

# -----------------------------------------------------------------------------
# [7] Prometheus alerts.yml parses + edgeguard rule group present
# -----------------------------------------------------------------------------
hdr "[7] Prometheus alerts"
if command -v promtool >/dev/null 2>&1; then
  if promtool check rules prometheus/alerts.yml >/dev/null 2>&1; then
    pass "prometheus/alerts.yml parses cleanly"
  else
    fail "promtool rejected prometheus/alerts.yml (run: promtool check rules prometheus/alerts.yml)"
  fi
else
  warn "promtool not installed; skipping alerts parse check (install Prometheus tools)"
fi

# Quick structural pin — expect the edgeguard_pipeline_observability rule group with at least 11 alerts.
# PR-N24 audit MED follow-up: bumped from ≥ 6 → ≥ 8 (PR-N21 Bravo-ops adds
# EdgeGuardBuildRelationshipsSilentDeath + EdgeGuardApocBatchPartial), then
# bumped again to ≥ 9 for PR-N24 H3 (EdgeGuardMispEventAttributesTruncated).
# PR-N31 (2026-04-25): bumped to ≥ 11 — added EdgeGuardMispFetchFallbackActive +
# EdgeGuardMispFetchFallbackHardError (operator visibility for the PR-N29
# fallback hardening; see prometheus/alerts.yml).
# This is a defense-in-depth structural pin — promtool above does the real validation.
ALERT_COUNT=$(grep -cE '^\s+- alert:' prometheus/alerts.yml 2>/dev/null || echo "0")
if [[ "$ALERT_COUNT" -ge 11 ]]; then
  pass "prometheus/alerts.yml has $ALERT_COUNT alert rules (≥ 11 required)"
else
  fail "prometheus/alerts.yml has only $ALERT_COUNT alerts — expected ≥ 11 (PR-N11/N12/N18/N21/N24/N31)"
fi

# -----------------------------------------------------------------------------
# [7b] PR-N24 BLOCKER B2: alertmanager pager wiring not still placeholder
# -----------------------------------------------------------------------------
# Pre-N24, ``prometheus/alertmanager.yml`` shipped with literal
# ``service_key: '<YOUR_PAGERDUTY_KEY>'``. PagerDuty silently 403s on
# every page. During the 26h baseline window, EVERY critical alert
# (BatchPermanentFailure, IneffectiveBatch, BuildRelationshipsSilentDeath,
# etc.) would have been emitted-but-unrouted — the on-call would never know.
#
# This check refuses to launch the baseline if a placeholder OR an
# un-rendered ``${ENV_VAR}`` template is still in place.
#
# Bugbot round 1 (2026-04-23): the original PR-N24 fix replaced the
# literal ``<YOUR_PAGERDUTY_KEY>`` with ``'${EDGEGUARD_PAGERDUTY_
# INTEGRATION_KEY}'`` thinking Alertmanager would substitute the
# env var. It does NOT — Alertmanager loads the YAML literally and
# would send ``${EDGEGUARD_PAGERDUTY_INTEGRATION_KEY}`` as the
# service key → same silent 403 as the original placeholder.
# Operators must render alertmanager.yml from a template (envsubst,
# helm, kustomize, etc.) BEFORE Alertmanager starts. This preflight
# now refuses both shapes (literal placeholder + un-rendered env var).
hdr "[7b] alertmanager pager wiring (PR-N24 B2)"
if [ -f prometheus/alertmanager.yml ]; then
  # Only fail when the placeholder appears as a YAML *value* (quoted
  # scalar), NOT when it appears in an explanatory ``#`` comment. The
  # comment block in alertmanager.yml documents the placeholder's
  # history; matching that would fail-close unnecessarily. The actual
  # failure mode is Alertmanager loading the placeholder as the
  # ``service_key:`` value — that only happens when it's in quotes.
  #
  # sed strips the trailing ``#...`` portion of each line before grep;
  # the placeholder / env-template patterns are then only matched
  # against uncommented YAML content.
  if sed 's/#.*$//' prometheus/alertmanager.yml | \
     grep -qE "'<YOUR_PAGERDUTY_KEY>'|\"<YOUR_PAGERDUTY_KEY>\"|'<YOUR_API_KEY>'|\"<YOUR_API_KEY>\"|'<PLACEHOLDER>'|\"<PLACEHOLDER>\"|'XXXXXXXX-XXXX'|\"XXXXXXXX-XXXX\"|'\\\$\\{[A-Z_][A-Z0-9_]*\\}'|\"\\\$\\{[A-Z_][A-Z0-9_]*\\}\""; then
    fail "prometheus/alertmanager.yml still contains a placeholder OR un-rendered \${...} env-var template as a YAML value — PagerDuty will silently 403 every alert (Alertmanager does NOT expand env vars in YAML). Render alertmanager.yml via envsubst/helm/kustomize before Alertmanager starts, OR insert a real PagerDuty integration key directly."
  else
    pass "alertmanager.yml has no placeholder or un-rendered env-template pager key values"
  fi
else
  warn "prometheus/alertmanager.yml not found — pager routing not configured"
fi

# -----------------------------------------------------------------------------
# [8] no stale baseline_lock sentinel
# -----------------------------------------------------------------------------
hdr "[8] baseline_lock sentinel"
if command -v docker >/dev/null 2>&1; then
  if docker compose exec -T airflow-worker test -f /tmp/edgeguard/baseline_lock.sentinel 2>/dev/null; then
    SENTINEL_AGE=$(docker compose exec -T airflow-worker stat -c %Y /tmp/edgeguard/baseline_lock.sentinel 2>/dev/null || echo "0")
    NOW=$(date +%s)
    AGE_H=$(( (NOW - SENTINEL_AGE) / 3600 ))
    if [[ $AGE_H -gt 48 ]]; then
      fail "stale baseline_lock.sentinel (age ${AGE_H}h) — previous baseline crashed; see baseline_lock.py:corrupt-sentinel-probe"
    else
      warn "baseline_lock.sentinel present (age ${AGE_H}h) — another baseline may be running"
    fi
  else
    pass "no stale baseline_lock sentinel"
  fi
else
  warn "docker not available; skipping sentinel check"
fi

# -----------------------------------------------------------------------------
# [9] kill-switches not forced on
# -----------------------------------------------------------------------------
hdr "[9] kill-switch env vars"
for sw in EDGEGUARD_RESPECT_CALIBRATOR EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION; do
  if [[ -n "${!sw:-}" ]]; then
    warn "$sw=${!sw} is set — confirm this is intentional (see RUNBOOK § Kill-switches)"
  else
    pass "$sw unset (safe default)"
  fi
done

# -----------------------------------------------------------------------------
# [10] last full pytest run was green (quick syntax pin)
# -----------------------------------------------------------------------------
hdr "[10] test suite syntax check"
if [[ -x ".venv/bin/pytest" ]]; then
  if .venv/bin/pytest --collect-only -q >/tmp/pytest_collect.out 2>&1; then
    TEST_COUNT=$(grep -cE '::test_' /tmp/pytest_collect.out || echo "0")
    pass "pytest collects $TEST_COUNT tests cleanly"
  else
    fail "pytest collection failed — see /tmp/pytest_collect.out"
  fi
else
  warn ".venv/bin/pytest not found; skipping collection check"
fi

# -----------------------------------------------------------------------------
# [11] PR-N29 invariants — DAG retries=0, sentinel class, lock max-age
# -----------------------------------------------------------------------------
# Defense-in-depth source-pin: PR-N29 hardened the baseline against three
# silent-failure modes (retries-budget overrun, MISP-fetch-fallback silent
# truncation, cross-host lock TTL). PR-N31 (2026-04-25) adds this preflight
# check so an inadvertent revert (rebase mishap, misguided "cleanup",
# manual edit) is caught BEFORE the baseline launches — not by an
# operator at hour 26 of a 32h dagrun.
#
# Fast-fail (grep, no Python). The full-fat invariant tests live in
# tests/test_pr_n29_pre_baseline_hardening.py and are part of the [10]
# pytest collection above.
hdr "[11] PR-N29 invariants (retries=0, sentinel, lock max-age)"

# (a) _MispFallbackHardError sentinel class is still defined
if grep -q "^class _MispFallbackHardError(Exception):" src/run_misp_to_neo4j.py 2>/dev/null; then
  pass "_MispFallbackHardError sentinel class present in src/run_misp_to_neo4j.py"
else
  fail "_MispFallbackHardError sentinel class missing — PR-N29 fallback hard-error surfacing reverted? (src/run_misp_to_neo4j.py)"
fi

# (b) baseline_lock max-age is at least 48h (cross-host buffer above 32h dagrun_timeout)
if grep -q "_BASELINE_LOCK_MAX_AGE_SEC_DEFAULT = 48 \* 3600" src/baseline_lock.py 2>/dev/null; then
  pass "baseline_lock max-age = 48h (PR-N29 M3)"
else
  fail "baseline_lock max-age != 48h — cross-host deployments may reap the sentinel mid-baseline (src/baseline_lock.py)"
fi

# (c) all three critical-chain tasks have retries=0 in the baseline DAG
RETRIES_ZERO_COUNT=0
for task in full_neo4j_sync build_relationships run_enrichment_jobs; do
  # Find the PythonOperator block whose task_id matches; allow ~3000 chars of
  # surrounding context (kwargs are spread out on multi-line definitions).
  if .venv/bin/python -c "
import re, sys
text = open('dags/edgeguard_pipeline.py').read()
anchor = 'task_id=\"$task\"'
idx = text.find(anchor)
if idx == -1:
    sys.exit(2)  # task_id missing → DAG structurally broken
start = text.rfind('PythonOperator(', 0, idx)
block = text[start:idx + 3000]
sys.exit(0 if 'retries=0' in block else 1)
" 2>/dev/null; then
    RETRIES_ZERO_COUNT=$((RETRIES_ZERO_COUNT+1))
  else
    fail "$task is missing retries=0 — a single retry on this 5-6h task would blow through the 32h dagrun_timeout (PR-N29 H1)"
  fi
done
if [[ $RETRIES_ZERO_COUNT -eq 3 ]]; then
  pass "all 3 critical-chain tasks have retries=0 (PR-N29 H1)"
fi

# (d) sentinel class is wired into the metric counter (PR-N31 follow-up)
if grep -q 'record_misp_fetch_fallback("pymisp", "hard_error")' src/run_misp_to_neo4j.py 2>/dev/null \
   && grep -q 'record_misp_fetch_fallback("rest_search", "hard_error")' src/run_misp_to_neo4j.py 2>/dev/null; then
  pass "_MispFallbackHardError raises increment edgeguard_misp_fetch_fallback_active_total{outcome=hard_error} (PR-N31)"
else
  warn "PR-N31 fallback metric not wired in both branches — operator alerts may be silent on hard-error path"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
printf '\n%s========================================%s\n' "$C_CYN" "$C_OFF"
if [[ $FAILURES -eq 0 ]] && { [[ "$STRICT" != "1" ]] || [[ $WARNINGS -eq 0 ]]; }; then
  printf '%s✓ preflight_baseline: READY%s  (warnings=%d, failures=%d)\n' \
    "$C_GRN" "$C_OFF" "$WARNINGS" "$FAILURES"
  printf 'Launch path confirmed: %s\n' "$LAUNCH_PATH"
  exit 0
else
  printf '%s✗ preflight_baseline: NOT READY%s  (warnings=%d, failures=%d)\n' \
    "$C_RED" "$C_OFF" "$WARNINGS" "$FAILURES"
  printf 'Address the ✗ items above (and ! items under --strict) before launching.\n'
  printf 'See docs/RUNBOOK.md § "Baseline-day protocol" for manual equivalents.\n'
  exit 1
fi
