#!/usr/bin/env python3
"""
PR-N26 — Backfill ``r.misp_event_ids[]`` on existing TARGETS / EXPLOITS /
INDICATES / AFFECTS edges produced by build_relationships before PR-N26.

## Why this script exists

Cloud-Neo4j audit on 2026-04-23 found that 5 edge types created by the
``build_relationships.py`` post-sync graph-traversal path silently dropped
the ``r.misp_event_ids[]`` provenance array, even though the underlying
edge IS MISP-derived (the cve_tag / zone tag / malware_family / co-occurrence
all originate from MISP attribute parsing). PR-N26 closes the wire-up in
the code; this script backfills the existing edges in-place.

**Pre-N26 cloud coverage (2026-04-23 against bolt+s://neo4j-bolt.edgeguard.org:443):**

| Relationship | Total | with misp_event_ids | gap |
|---|---|---|---|
| INDICATES | 19,370 | 6.6% (1,280) | 18,090 edges |
| TARGETS | 36,480 | 0% | 36,480 edges |
| EXPLOITS | 26,730 | 0% | 26,730 edges |
| AFFECTS | 1,221 | 0.1% (1) | ~1,220 edges |

Total: ~82,500 edges to backfill in the cloud snapshot above. Local
Neo4j almost certainly has the same gap.

## What it does

Pure Cypher — no MISP API calls needed. For each of 5 patterns, walks the
existing graph and propagates the originating node's
``misp_event_ids[]`` onto the edge.

| Pattern | match_type | Source of misp_event_ids[] |
|---|---|---|
| INDICATES (co-occurrence) | ``misp_cooccurrence`` | Intersection of i.misp_event_ids ∩ m.misp_event_ids |
| INDICATES (family-match) | ``malware_family`` | i.misp_event_ids (full list — superset) |
| EXPLOITS | ``cve_tag`` | i.misp_event_ids |
| TARGETS | (Indicator → Sector) | i.misp_event_ids |
| AFFECTS | (Vuln/CVE → Sector) | v.misp_event_ids |

The co-occurrence intersection is the only one that can recover the
EXACT MISP event(s) that produced the edge (because both endpoints carry
their own arrays and the edge was created when an event was in both).
The other four propagate the source endpoint's full list, which is a
**superset** of the true provenance — acceptable for backwards-traceability
and consistent with the PR-N26 forward write path.

## Idempotency

Safe to re-run. The backfill query is gated by ``coalesce(r.misp_event_ids,
[]) = []`` — if a previous baseline (or a previous run of this script)
populated the array, the script skips that edge. No race with concurrent
baselines.

## Usage

```bash
# Dry-run first — prints what WOULD be updated, writes nothing
./scripts/backfill_edge_misp_event_ids.py --dry-run

# Execute against cloud Neo4j
export NEO4J_URI="bolt+s://neo4j-bolt.edgeguard.org:443"
export NEO4J_PASSWORD="<cloud-password>"
./scripts/backfill_edge_misp_event_ids.py

# Run only one pattern (useful for incremental rollout)
./scripts/backfill_edge_misp_event_ids.py --only indicates_cooccurrence

# Tune batch size if Neo4j memory pressure is a concern
./scripts/backfill_edge_misp_event_ids.py --batch-size 1000
```

## Env vars required

| Var | Purpose |
|---|---|
| ``NEO4J_URI`` | Bolt URI. Use ``bolt+s://`` for strict-TLS (system-CA trust); ``bolt+ssc://`` for self-signed; plain ``bolt://`` for unencrypted. |
| ``NEO4J_PASSWORD`` | Neo4j password (read from env, never logged or echoed) |
| ``NEO4J_USER`` | (optional) Neo4j user (default: ``neo4j``) |

**Note on TLS:** TLS strictness is determined by the URI scheme, NOT by
``EDGEGUARD_SSL_VERIFY``. Pre-PR-N26 audit (Red Team + Prod Readiness, 2026-04-23):
the docstring previously claimed the env var was honored, but
``get_driver()`` does not consult it (the rest of the codebase honors it
via ``config.edgeguard_ssl_verify_from_env``, but this one-shot operator
script delegates to neo4j-driver's URI-scheme defaults). For a
self-signed cloud-staging instance use ``bolt+ssc://``; for production
use ``bolt+s://``.

## Exit codes

- 0 — all patterns backfilled cleanly
- 1 — any fatal error (connection, auth, unrecoverable exception)
- 2 — invalid CLI arguments

## See also

- ``src/build_relationships.py`` — the forward write path (PR-N26 fix)
- ``src/neo4j_client.py::create_misp_relationships_batch`` — Path A, already correct
- ``migrations/2026_05_edge_misp_event_ids_backfill_runbook.md`` — operator runbook
- ``scripts/backfill_cve_dates_from_nvd_meta.py`` — sister backfill (PR-N22)
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from typing import Dict, List, Tuple

from neo4j import READ_ACCESS, WRITE_ACCESS, Driver, GraphDatabase

# PR-N26 multi-agent audit Prod Readiness HIGH-2 (2026-04-23): the
# backfill writes to the same edges a running baseline would write. Without
# a concurrency guard, both writers contend on relationship properties →
# TX-timeout and lock-acquisition errors. ``is_baseline_running()`` checks
# the sentinel ``checkpoints/baseline_in_progress.lock`` written by
# ``src/baseline_lock.py``. Importable here because ``src/`` is on PYTHONPATH
# in the operator's runbook environment (see runbook pre-flight section).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
try:
    from baseline_lock import is_baseline_running  # type: ignore[import-not-found]
except ImportError:
    # Fallback — if baseline_lock can't be imported (e.g. invoked from a
    # non-repo working directory), the operator gets a warning and the
    # check is skipped. The check is defense-in-depth, not a hard
    # requirement; the runbook documents the manual pre-flight too.
    is_baseline_running = None  # type: ignore[assignment]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [backfill-edge-misp] %(message)s",
)
logger = logging.getLogger("backfill_edge_misp_event_ids")


# PR-N30 Cross-Checker H-2 (2026-04-24): sibling constant to
# ``src/build_relationships.py::CRITICAL_MAX_EVENT_IDS_PER_EDGE``.
#
# The cap MUST match the forward-write path. Pre-N30 Q4 (forward-write)
# capped at 200 but the backfill cooccurrence path was uncapped — so the
# same (i, m) edge could end up with different content depending on
# whether it was produced by forward-write or backfill. This constant
# documents + enforces the symmetric contract.
#
# The backfill script can't cleanly import from ``src/build_relationships``
# without triggering its module-level side effects (APOC + Sector UUID
# precomputation). So the constant is duplicated with a cross-reference
# comment. Grep ``CRITICAL_MAX_EVENT_IDS_PER_EDGE`` to find both sites —
# if you change one, change both.
CRITICAL_MAX_EVENT_IDS_PER_EDGE = 200


# ---------------------------------------------------------------------------
# Backfill patterns
# ---------------------------------------------------------------------------
# Each pattern is a (name, count_query, write_query) triple.
#
# - ``count_query`` returns the number of edges that match the gap (so dry-run
#   can report scope without touching anything).
# - ``write_query`` is the corresponding ``apoc.periodic.iterate`` call that
#   does the SET. Bounded by ``$batch_size`` to keep individual transactions
#   small enough to avoid Neo4j MemoryLimitExceededException on very wide
#   misp_event_ids arrays (some indicators carry 100+ entries).
#
# The write_query uses ``$batch_size`` as a Cypher parameter, NOT string
# interpolation, so the same plan is reused across runs.

PATTERNS: List[Tuple[str, str, str]] = [
    (
        "indicates_cooccurrence",
        # Count: INDICATES edges from MISP cooccurrence with no event_ids array.
        """
        MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
          AND coalesce(r.match_type, '') = 'misp_cooccurrence'
        RETURN count(r) AS gap
        """,
        # Write: stamp the INTERSECTION of i.misp_event_ids and m.misp_event_ids.
        # That's exactly the set of events that originally produced the edge
        # (Q4 in build_relationships iterates eid IN m.misp_event_ids and
        # MATCHes i WHERE eid IN i.misp_event_ids — so the intersection is
        # the historical set).
        #
        # PR-N30 Cross-Checker H-2 + M-1 (2026-04-24): filter nulls/empty
        # strings (Path A parity) AND cap to CRITICAL_MAX_EVENT_IDS_PER_EDGE
        # (forward-write Q4 parity). See module-level constant comment.
        f"""
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(r.match_type, "") = "misp_cooccurrence"
             RETURN i, r, m',
            'WITH i, r, m,
                  [eid IN coalesce(i.misp_event_ids, [])
                   WHERE eid IS NOT NULL AND size(eid) > 0
                     AND eid IN coalesce(m.misp_event_ids, [])][0..{CRITICAL_MAX_EVENT_IDS_PER_EDGE}] AS shared
             WHERE size(shared) > 0
             SET r.misp_event_ids = shared',
            {{batchSize: $batch_size, parallel: false}}
        )
        YIELD batches, total, committedOperations, errorMessages
        RETURN batches, total, committedOperations, errorMessages
        """,
    ),
    (
        "indicates_family_match",
        """
        MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
          AND coalesce(r.match_type, '') = 'malware_family'
        RETURN count(r) AS gap
        """,
        # PR-N30 Cross-Checker H-2 + M-1 (2026-04-24): same filter/cap as
        # the indicates_cooccurrence pattern — see module-level constant.
        f"""
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(r.match_type, "") = "malware_family"
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = [x IN coalesce(i.misp_event_ids, []) WHERE x IS NOT NULL AND size(x) > 0][0..{CRITICAL_MAX_EVENT_IDS_PER_EDGE}]',
            {{batchSize: $batch_size, parallel: false}}
        )
        YIELD batches, total, committedOperations, errorMessages
        RETURN batches, total, committedOperations, errorMessages
        """,
    ),
    (
        "exploits",
        """
        MATCH (i:Indicator)-[r:EXPLOITS]->(target)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
        RETURN count(r) AS gap
        """,
        # PR-N30 Cross-Checker H-2 + M-1 (2026-04-24).
        f"""
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:EXPLOITS]->(target)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = [x IN coalesce(i.misp_event_ids, []) WHERE x IS NOT NULL AND size(x) > 0][0..{CRITICAL_MAX_EVENT_IDS_PER_EDGE}]',
            {{batchSize: $batch_size, parallel: false}}
        )
        YIELD batches, total, committedOperations, errorMessages
        RETURN batches, total, committedOperations, errorMessages
        """,
    ),
    (
        "targets_indicator_to_sector",
        """
        MATCH (i:Indicator)-[r:TARGETS]->(:Sector)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
        RETURN count(r) AS gap
        """,
        # PR-N30 Cross-Checker H-2 + M-1 (2026-04-24).
        f"""
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:TARGETS]->(s:Sector)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = [x IN coalesce(i.misp_event_ids, []) WHERE x IS NOT NULL AND size(x) > 0][0..{CRITICAL_MAX_EVENT_IDS_PER_EDGE}]',
            {{batchSize: $batch_size, parallel: false}}
        )
        YIELD batches, total, committedOperations, errorMessages
        RETURN batches, total, committedOperations, errorMessages
        """,
    ),
    (
        "affects_vuln_to_sector",
        """
        MATCH (v)-[r:AFFECTS]->(:Sector)
        WHERE (v:Vulnerability OR v:CVE)
          AND coalesce(size(r.misp_event_ids), 0) = 0
        RETURN count(r) AS gap
        """,
        # PR-N30 Cross-Checker H-2 + M-1 (2026-04-24): note this one
        # reads ``v.misp_event_ids`` (Vulnerability/CVE source, not
        # Indicator) — matches Q7b's forward-write source.
        f"""
        CALL apoc.periodic.iterate(
            'MATCH (v)-[r:AFFECTS]->(s:Sector)
             WHERE (v:Vulnerability OR v:CVE)
               AND coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(v.misp_event_ids), 0) > 0
             RETURN v, r',
            'SET r.misp_event_ids = [x IN coalesce(v.misp_event_ids, []) WHERE x IS NOT NULL AND size(x) > 0][0..{CRITICAL_MAX_EVENT_IDS_PER_EDGE}]',
            {{batchSize: $batch_size, parallel: false}}
        )
        YIELD batches, total, committedOperations, errorMessages
        RETURN batches, total, committedOperations, errorMessages
        """,
    ),
]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PR-N26: backfill r.misp_event_ids[] on edge types created pre-N26",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report gap counts per pattern without writing.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=2000,
        help="apoc.periodic.iterate batch size (default 2000). Lower if Neo4j memory pressure.",
    )
    parser.add_argument(
        "--only",
        choices=[name for name, _, _ in PATTERNS],
        help="Run only one specific pattern (for incremental rollout).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Skip the baseline-concurrency pre-flight check. ONLY use if you've "
            "manually verified no baseline is currently writing to the same edges "
            "(e.g. against a non-prod cloud instance with no incremental DAGs). "
            "Without this flag the script aborts if checkpoints/baseline_in_progress.lock exists."
        ),
    )
    return parser.parse_args()


def get_driver() -> Driver:
    uri = os.environ.get("NEO4J_URI")
    password = os.environ.get("NEO4J_PASSWORD")
    if not uri:
        logger.error("NEO4J_URI not set — required (e.g. bolt+s://neo4j-bolt.edgeguard.org:443)")
        sys.exit(1)
    if not password:
        logger.error("NEO4J_PASSWORD not set — required")
        sys.exit(1)
    user = os.environ.get("NEO4J_USER", "neo4j")
    return GraphDatabase.driver(uri, auth=(user, password))


def run_pattern(
    driver, name: str, count_query: str, write_query: str, batch_size: int, dry_run: bool
) -> Dict[str, int]:
    """Execute one pattern. Returns {gap, batches, written, scanned, errors}.

    ``written`` = rows actually MUTATED (apoc.periodic.iterate
    ``committedOperations``) — accurate post-backfill count.

    ``scanned`` = INPUT rows consumed from the outer query (apoc ``total``).
    For patterns with an inner-query filter (e.g. indicates_cooccurrence
    skips rows where ``size(shared) == 0``), ``scanned > written``. The
    delta is logged as ``filter-skipped`` so operators can see the exact
    filter impact."""
    out = {"gap": 0, "batches": 0, "written": 0, "scanned": 0, "errors": 0}
    # PR-N30 Red Team H1 (2026-04-23, defense-in-depth): when dry-run is
    # set, open the session in READ_ACCESS mode. Today the ``count_query``
    # strings are read-only by inspection, but there's zero driver-side
    # constraint preventing a future maintainer from adding a stray
    # MERGE that would silently mutate on what the operator BELIEVED was
    # a safe dry-run. READ_ACCESS on the server side rejects writes with
    # ``neo4j.exceptions.ClientError`` — a LOUD failure instead of silent
    # corruption. No behaviour change today; surfaces any future drift.
    access_mode = READ_ACCESS if dry_run else WRITE_ACCESS
    with driver.session(default_access_mode=access_mode) as session:
        # Always run the count to give the operator a scope readout.
        result = session.run(count_query)
        record = result.single()
        out["gap"] = int(record["gap"]) if record else 0
        logger.info("[%s] gap = %d edges", name, out["gap"])

        if dry_run:
            logger.info("[%s] dry-run — skipping write", name)
            return out

        if out["gap"] == 0:
            logger.info("[%s] nothing to do", name)
            return out

        # Apply the backfill. apoc.periodic.iterate YIELDS:
        #   batches — number of inner-query transactions committed
        #   total — INPUT rows consumed from the outer query (per-batch * batch_size)
        #   committedOperations — rows actually MUTATED by the inner statement
        #   errorMessages — map of error-class → count (non-empty = per-row errors)
        #
        # Bugbot round 1 LOW (2026-04-23, PR #109): the original PR-N26 code
        # reported ``total`` as the "written" count. For patterns with an
        # inner-query filter (indicates_cooccurrence has
        # ``WHERE size(shared) > 0`` to skip empty intersections), ``total``
        # OVERCOUNTS because it reflects rows consumed, not rows mutated.
        # ``committedOperations`` is the accurate write count — report both
        # so operators can see the filter-skip delta (= total - committed).
        write_result = session.run(write_query, batch_size=batch_size)
        write_record = write_result.single()
        if write_record:
            out["batches"] = int(write_record["batches"])
            # Accurate count of edges actually MUTATED.
            out["written"] = int(write_record["committedOperations"])
            # Input rows consumed (includes filter-skipped).
            out["scanned"] = int(write_record["total"])
            err_messages = write_record["errorMessages"] or {}
            # apoc.periodic.iterate returns errorMessages as a map; non-empty
            # = at least one batch had a per-row error. Surface so operator
            # can investigate (most likely Neo4j memory pressure on a wide
            # misp_event_ids array).
            if err_messages:
                out["errors"] = sum(int(v) for v in err_messages.values() if isinstance(v, (int, float))) or 1
                logger.warning("[%s] %d batch errors: %s", name, out["errors"], err_messages)

        scanned = out.get("scanned", out["written"])
        skipped = scanned - out["written"] if scanned >= out["written"] else 0
        logger.info(
            "[%s] backfilled %d edges across %d batches (scanned=%d, filter-skipped=%d, errors=%d)",
            name,
            out["written"],
            out["batches"],
            scanned,
            skipped,
            out["errors"],
        )
    return out


def main() -> int:
    args = parse_args()

    # PR-N26 multi-agent audit Prod Readiness HIGH-2: refuse to write
    # while a baseline is in progress. Both writers contend on the same
    # relationship properties (TARGETS/EXPLOITS/INDICATES/AFFECTS edges),
    # which produces TX-timeout / lock-acquisition errors and leaves the
    # cloud graph in a partially-merged state. ``--force`` bypasses the
    # check (operator's responsibility to verify safety).
    if not args.force and is_baseline_running is not None:
        sentinel = is_baseline_running()
        if sentinel is not None:
            logger.error(
                "[BACKFILL-CONCURRENCY-BLOCK] baseline is currently in progress "
                "(sentinel=%s). Backfill writes to the same edges a baseline "
                "would write. Refusing to run; pass --force to override (only "
                "if you've manually verified safety).",
                sentinel,
            )
            return 1
    elif is_baseline_running is None:
        logger.warning(
            "[BACKFILL-CONCURRENCY-CHECK-SKIPPED] baseline_lock module could "
            "not be imported (running outside repo root?). Operator MUST "
            "manually verify no baseline is writing to the same Neo4j before "
            "proceeding. See migrations/2026_05_edge_misp_event_ids_backfill_runbook.md."
        )

    # PR-N26 multi-agent audit ROUND 2 (2026-04-23, Bug Hunter H-1 + Red Team
    # LOW-2 defense-in-depth): bind ``driver = None`` BEFORE the try so the
    # ``finally: driver.close()`` can't NameError-mask an earlier
    # ``get_driver()`` exception. This lets the operator see the original
    # failure (e.g. ``neo4j.exceptions.ConfigurationError`` on a malformed
    # URI) instead of a cryptic NameError traceback.
    driver = None
    selected = [(n, c, w) for n, c, w in PATTERNS if args.only is None or n == args.only]
    if not selected:
        logger.error("No patterns selected — check --only argument")
        return 2

    grand_total_written = 0
    grand_total_errors = 0
    grand_total_gap = 0
    # PR-N26 audit round 2 (Bug Hunter H-1): if pattern N crashes mid-way,
    # patterns N+1..end never run but the operator still needs to see the
    # summary (how much got backfilled before the crash — idempotent re-runs
    # pick up from there). ``aborted_at`` tracks which pattern (if any) ended
    # the loop abnormally so the summary log can surface it.
    aborted_at: str | None = None

    try:
        driver = get_driver()
        for name, count_q, write_q in selected:
            try:
                stats = run_pattern(driver, name, count_q, write_q, args.batch_size, args.dry_run)
                grand_total_gap += stats["gap"]
                grand_total_written += stats["written"]
                grand_total_errors += stats["errors"]
            except Exception:
                # PR-N26 audit round 2 Bug Hunter H-1: don't swallow the
                # error — but DO record which pattern died and still emit
                # the summary below (see finally). Abort remaining patterns
                # so a cascading Neo4j outage doesn't produce N misleading
                # per-pattern errors. logger.exception() includes the
                # traceback automatically; we don't need the bound name.
                logger.exception(
                    "[%s] FATAL — pattern crashed; aborting remaining patterns. "
                    "Re-run is idempotent (count-query gate skips already-done rows).",
                    name,
                )
                grand_total_errors += 1
                aborted_at = name
                break
    finally:
        if driver is not None:
            driver.close()
        # Summary ALWAYS runs, even on crash. Bug Hunter H-1: pre-fix, a
        # mid-run pattern crash raised out of main() and the summary log
        # was skipped entirely — operator saw a stack trace and no
        # accounting of what completed.
        logger.info("=" * 60)
        if aborted_at is not None:
            logger.warning(
                "Summary (PARTIAL — aborted at pattern '%s'): gap=%d, backfilled=%d, "
                "errors=%d (dry_run=%s). Idempotent re-run will resume.",
                aborted_at,
                grand_total_gap,
                grand_total_written,
                grand_total_errors,
                args.dry_run,
            )
        else:
            logger.info(
                "Summary: gap=%d, backfilled=%d, errors=%d (dry_run=%s)",
                grand_total_gap,
                grand_total_written,
                grand_total_errors,
                args.dry_run,
            )

    if grand_total_errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
