// PR #34 round 24 — heal existing nodes whose ``n.zone`` array accumulated
// ``'global'`` alongside specific sectors (healthcare/energy/finance) before
// the write-time override landed. Idempotent and safe to re-run.
//
// Context:
//   The per-text/per-item zone detection always returned either specific
//   sectors OR ``['global']`` — never mixed. But the Neo4j MERGE layer used
//   a plain APOC set union (no override), so two ingestions of the same
//   node (one healthcare-specific, one generic) accumulated to
//   ``n.zone = ['healthcare', 'global']``.
//
//   Round 24 applies the specifics-override-global rule on write. New
//   ingestions can no longer produce the corrupted shape, but any
//   pre-round-24 rows remain corrupted until this migration runs.
//
// How to run (one-off):
//   1. Deploy round 24+ to the cluster
//   2. Run this file once against Neo4j via cypher-shell:
//        cypher-shell -u neo4j -p $NEO4J_PASSWORD -f migrations/2026_04_zone_override_heal.cypher
//   3. The RETURN clause surfaces the heal count — expect a positive number
//      the first time, 0 on any subsequent re-run.
//
// No data loss: 'global' is ONLY removed when at least one specific sector
// remains, matching the collector-level rule. A node whose only zone was
// 'global' keeps it.

MATCH (n)
WHERE n.zone IS NOT NULL
  AND 'global' IN n.zone
  AND size([z IN n.zone WHERE z IS NOT NULL AND z <> 'global']) > 0
SET n.zone = [z IN n.zone WHERE z IS NOT NULL AND z <> 'global']
RETURN count(n) AS healed;
