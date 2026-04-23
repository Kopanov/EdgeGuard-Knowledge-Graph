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
| ``NEO4J_URI`` | Bolt URI |
| ``NEO4J_PASSWORD`` | Neo4j password |
| ``EDGEGUARD_SSL_VERIFY`` | (optional) ``true`` for strict TLS (default strict) |

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

from neo4j import Driver, GraphDatabase

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [backfill-edge-misp] %(message)s",
)
logger = logging.getLogger("backfill_edge_misp_event_ids")


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
        """
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(r.match_type, "") = "misp_cooccurrence"
             RETURN i, r, m',
            'WITH i, r, m,
                  [eid IN coalesce(i.misp_event_ids, [])
                   WHERE eid IN coalesce(m.misp_event_ids, [])] AS shared
             WHERE size(shared) > 0
             SET r.misp_event_ids = shared',
            {batchSize: $batch_size, parallel: false}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
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
        """
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:INDICATES]->(m:Malware)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(r.match_type, "") = "malware_family"
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = i.misp_event_ids',
            {batchSize: $batch_size, parallel: false}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
        """,
    ),
    (
        "exploits",
        """
        MATCH (i:Indicator)-[r:EXPLOITS]->(target)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
        RETURN count(r) AS gap
        """,
        """
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:EXPLOITS]->(target)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = i.misp_event_ids',
            {batchSize: $batch_size, parallel: false}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
        """,
    ),
    (
        "targets_indicator_to_sector",
        """
        MATCH (i:Indicator)-[r:TARGETS]->(:Sector)
        WHERE coalesce(size(r.misp_event_ids), 0) = 0
        RETURN count(r) AS gap
        """,
        """
        CALL apoc.periodic.iterate(
            'MATCH (i:Indicator)-[r:TARGETS]->(s:Sector)
             WHERE coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(i.misp_event_ids), 0) > 0
             RETURN i, r',
            'SET r.misp_event_ids = i.misp_event_ids',
            {batchSize: $batch_size, parallel: false}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
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
        """
        CALL apoc.periodic.iterate(
            'MATCH (v)-[r:AFFECTS]->(s:Sector)
             WHERE (v:Vulnerability OR v:CVE)
               AND coalesce(size(r.misp_event_ids), 0) = 0
               AND coalesce(size(v.misp_event_ids), 0) > 0
             RETURN v, r',
            'SET r.misp_event_ids = v.misp_event_ids',
            {batchSize: $batch_size, parallel: false}
        )
        YIELD batches, total, errorMessages
        RETURN batches, total, errorMessages
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
    """Execute one pattern. Returns {gap, batches, written, errors}."""
    out = {"gap": 0, "batches": 0, "written": 0, "errors": 0}
    with driver.session() as session:
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

        # Apply the backfill. apoc.periodic.iterate returns batches/total/errorMessages.
        write_result = session.run(write_query, batch_size=batch_size)
        write_record = write_result.single()
        if write_record:
            out["batches"] = int(write_record["batches"])
            out["written"] = int(write_record["total"])
            err_messages = write_record["errorMessages"] or {}
            # apoc.periodic.iterate returns errorMessages as a map; non-empty
            # = at least one batch had a per-row error. Surface so operator
            # can investigate (most likely Neo4j memory pressure on a wide
            # misp_event_ids array).
            if err_messages:
                out["errors"] = sum(int(v) for v in err_messages.values() if isinstance(v, (int, float))) or 1
                logger.warning("[%s] %d batch errors: %s", name, out["errors"], err_messages)

        logger.info(
            "[%s] backfilled %d edges across %d batches (errors=%d)",
            name,
            out["written"],
            out["batches"],
            out["errors"],
        )
    return out


def main() -> int:
    args = parse_args()
    driver = get_driver()

    selected = [(n, c, w) for n, c, w in PATTERNS if args.only is None or n == args.only]
    if not selected:
        logger.error("No patterns selected — check --only argument")
        return 2

    grand_total_written = 0
    grand_total_errors = 0
    grand_total_gap = 0

    try:
        for name, count_q, write_q in selected:
            stats = run_pattern(driver, name, count_q, write_q, args.batch_size, args.dry_run)
            grand_total_gap += stats["gap"]
            grand_total_written += stats["written"]
            grand_total_errors += stats["errors"]
    finally:
        driver.close()

    logger.info("=" * 60)
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
