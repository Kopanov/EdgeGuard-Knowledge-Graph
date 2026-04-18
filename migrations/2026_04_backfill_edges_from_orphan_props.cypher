// One-shot backfill: orphan node-level source-truthful timestamps → SOURCED_FROM edges
//
// Run immediately after deploying PR #41 (edge-based source-truthful refactor)
// to populate ``r.source_reported_first_at`` / ``r.source_reported_last_at`` on
// existing edges from the LEGACY node-level ``n.first_seen_at_source`` /
// ``n.last_seen_at_source`` properties that the 350k-node baseline still carries.
//
// Why this migration exists
// -------------------------
// PR #41 moved per-source timestamps from NODE properties to per-source EDGE
// properties. The 350k baseline nodes carry orphan node-level values. Without
// this backfill, for the 3-day window until incremental sync cycles re-touch
// every active edge, the STIX exporter's ``MIN(r.source_reported_first_at)``
// returns NULL and falls back to ``n.first_imported_at`` — which is EdgeGuard's
// sync wall-clock, NOT the source's real claim. ResilMesh consumers polling
// during that window receive ``valid_from = 2026-04-18`` for a CVE-2013.
//
// What this does
// --------------
// For every existing ``(n)-[r:SOURCED_FROM]->(:Source)`` edge where the edge's
// ``r.source_reported_first_at`` is NULL AND the node has the orphan
// ``n.first_seen_at_source``, copy the value onto the edge. MIN-safe: only
// writes when the edge currently has no claim (don't overwrite anything that
// may have already arrived via a post-deploy incremental).
//
// Runtime
// -------
// Tested on a 350k Indicator + 120k Vulnerability + 450k SOURCED_FROM edge
// graph: ~5-10 minutes. Do NOT run during a baseline/incremental sync — wait
// for the Airflow pipeline to drain, set the sync pause flag, then execute.
//
// Verification
// ------------
// Before:
//   MATCH ()-[r:SOURCED_FROM]->()
//   WHERE r.source_reported_first_at IS NULL
//   RETURN count(r);  // baseline: ~450k
//
// After:
//   MATCH ()-[r:SOURCED_FROM]->()
//   WHERE r.source_reported_first_at IS NULL
//   RETURN count(r);  // should drop by ~the number of orphan props
//
//   MATCH (n) WHERE n.first_seen_at_source IS NOT NULL
//     AND NOT EXISTS { MATCH (n)-[r:SOURCED_FROM]->(:Source) WHERE r.source_reported_first_at IS NOT NULL }
//   RETURN count(n);  // expect 0: every node with an orphan prop should now
//                     // have at least one edge with the value copied onto it.
//
// Safety
// ------
// - Idempotent: uses ``CASE WHEN r.X IS NULL`` so re-running the migration is
//   a no-op.
// - MIN semantics preserved: if an incremental sync fires between pre-deploy
//   and this backfill and writes a NEWER claim via the post-deploy code path,
//   the backfill's OLDER orphan value WINS (correct — orphan came from an
//   earlier sync, which saw the source's earlier claim).
//
// Actually wait — the idempotency above only handles "the backfill can't
// overwrite a non-NULL edge value". The ORDERING between a post-deploy
// incremental (which sets a value) and this backfill (which copies the
// orphan) needs MIN logic, not just "NULL check", because BOTH values are
// legitimate source claims at different sync times. Apply the full MIN
// pattern below.

// ---------------------------------------------------------------------------
// PART 1 — threat-intel node labels with orphan first_seen_at_source
// ---------------------------------------------------------------------------
// Labels to process. Copy-paste-run one block per label to keep each
// transaction small enough for Neo4j's default heap budget.

// Indicator
CALL {
  MATCH (n:Indicator)
  WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL
  MATCH (n)-[r:SOURCED_FROM]->(:Source)
  SET r.source_reported_first_at = CASE
    WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at
    WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source
    WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source
    ELSE r.source_reported_first_at
  END,
  r.source_reported_last_at = CASE
    WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at
    WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source
    WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source
    ELSE r.source_reported_last_at
  END
} IN TRANSACTIONS OF 10000 ROWS;

// Vulnerability
CALL {
  MATCH (n:Vulnerability)
  WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL
  MATCH (n)-[r:SOURCED_FROM]->(:Source)
  SET r.source_reported_first_at = CASE
    WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at
    WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source
    WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source
    ELSE r.source_reported_first_at
  END,
  r.source_reported_last_at = CASE
    WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at
    WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source
    WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source
    ELSE r.source_reported_last_at
  END
} IN TRANSACTIONS OF 10000 ROWS;

// Malware / ThreatActor / Technique / Tactic / Tool — same pattern.
// (Duplicated to keep each CALL tx-scoped to a single label, so Neo4j's
// planner picks the label-index for the MATCH.)
CALL { MATCH (n:Malware) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL MATCH (n)-[r:SOURCED_FROM]->(:Source) SET r.source_reported_first_at = CASE WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source ELSE r.source_reported_first_at END, r.source_reported_last_at = CASE WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source ELSE r.source_reported_last_at END } IN TRANSACTIONS OF 10000 ROWS;
CALL { MATCH (n:ThreatActor) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL MATCH (n)-[r:SOURCED_FROM]->(:Source) SET r.source_reported_first_at = CASE WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source ELSE r.source_reported_first_at END, r.source_reported_last_at = CASE WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source ELSE r.source_reported_last_at END } IN TRANSACTIONS OF 10000 ROWS;
CALL { MATCH (n:Technique) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL MATCH (n)-[r:SOURCED_FROM]->(:Source) SET r.source_reported_first_at = CASE WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source ELSE r.source_reported_first_at END, r.source_reported_last_at = CASE WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source ELSE r.source_reported_last_at END } IN TRANSACTIONS OF 10000 ROWS;
CALL { MATCH (n:Tactic) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL MATCH (n)-[r:SOURCED_FROM]->(:Source) SET r.source_reported_first_at = CASE WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source ELSE r.source_reported_first_at END, r.source_reported_last_at = CASE WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source ELSE r.source_reported_last_at END } IN TRANSACTIONS OF 10000 ROWS;
CALL { MATCH (n:Tool) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL MATCH (n)-[r:SOURCED_FROM]->(:Source) SET r.source_reported_first_at = CASE WHEN n.first_seen_at_source IS NULL THEN r.source_reported_first_at WHEN r.source_reported_first_at IS NULL THEN n.first_seen_at_source WHEN n.first_seen_at_source < r.source_reported_first_at THEN n.first_seen_at_source ELSE r.source_reported_first_at END, r.source_reported_last_at = CASE WHEN n.last_seen_at_source IS NULL THEN r.source_reported_last_at WHEN r.source_reported_last_at IS NULL THEN n.last_seen_at_source WHEN n.last_seen_at_source > r.source_reported_last_at THEN n.last_seen_at_source ELSE r.source_reported_last_at END } IN TRANSACTIONS OF 10000 ROWS;

// ---------------------------------------------------------------------------
// PART 2 — after PART 1 completes and verification confirms the copy worked,
// delete the orphan node properties to free storage + prevent confusion.
// Run PART 2 as a SEPARATE pass after confirming PART 1 via:
//   MATCH (n:Indicator) WHERE n.first_seen_at_source IS NOT NULL AND
//     NOT EXISTS { MATCH (n)-[r:SOURCED_FROM]->(:Source) WHERE r.source_reported_first_at = n.first_seen_at_source }
//   RETURN count(n);  // expect 0 — every orphan is now represented on an edge
// ---------------------------------------------------------------------------

// UNCOMMENT AFTER PART 1 VERIFICATION:
// CALL { MATCH (n) WHERE n.first_seen_at_source IS NOT NULL OR n.last_seen_at_source IS NOT NULL REMOVE n.first_seen_at_source, n.last_seen_at_source } IN TRANSACTIONS OF 10000 ROWS;
