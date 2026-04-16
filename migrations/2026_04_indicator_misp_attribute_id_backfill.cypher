// ============================================================================
// Migration: backfill Indicator.misp_attribute_id (and misp_attribute_ids[])
// ============================================================================
//
// Context
// -------
// Until 2026-04 the production MISP→Neo4j sync path (run_misp_to_neo4j.py
// _parse_misp_attribute) never wrote ``misp_attribute_id`` onto Indicator
// nodes. The storage layer was already wired (merge_indicators_batch
// passes the field through to Cypher), but the parser dropped the MISP
// attribute UUID and only emitted ``misp_event_id``. Result: ~146K
// Indicators with NULL ``misp_attribute_id`` and NULL/empty
// ``misp_attribute_ids[]`` — no direct line-of-sight back to a specific
// MISP attribute, only to the originating event.
//
// The forward fix lives in src/run_misp_to_neo4j.py — every new ingest
// from 2026-04 onwards carries the attribute UUID. This migration
// backfills the historical 146K nodes.
//
// Strategy
// --------
// Two passes, lowest-cost first:
//
//   PASS A — parse SOURCED_FROM.raw_data.
//     ``raw_data`` on the SOURCED_FROM edge is the JSON payload of the
//     item dict at merge time. Items emitted *after* the parse_attribute
//     fix already carry ``misp_attribute_id``; for earlier items the
//     field is absent. We attempt apoc.convert.fromJsonMap on the edge
//     payload and write back any uuid we find.
//
//   PASS B — operator runbook (see docs/MIGRATIONS.md).
//     For Indicators still NULL after Pass A, an out-of-band re-fetch
//     from MISP keyed by (misp_event_id, indicator_value, indicator_type)
//     is required. The script ``scripts/backfill_misp_attribute_id.py``
//     implements this and is the documented Pass B. This .cypher file
//     covers Pass A only.
//
// Safety
// ------
// - Uses apoc.periodic.iterate so the transaction log never grows
//   unbounded (146K nodes is comfortable in one transaction but
//   ResilMesh ops graphs are bigger).
// - Idempotent: re-running matches 0 already-populated rows on Pass A
//   and is a no-op for any node where a UUID was previously written.
// - parallel:false to avoid lock contention on the SOURCED_FROM edge
//   read alongside the Indicator write.
// - Writes BOTH the scalar misp_attribute_id (first-seen) AND extends
//   misp_attribute_ids[] via apoc.coll.toSet — the same shape that
//   merge_indicators_batch produces for new ingests.
//
// Pre-migration sanity check (run manually first):
//
//   MATCH (i:Indicator)
//   WHERE i.misp_attribute_id IS NULL OR i.misp_attribute_id = ''
//   RETURN count(i) AS null_before;
//
// Post-migration sanity check:
//
//   MATCH (i:Indicator)
//   WHERE i.misp_attribute_id IS NULL OR i.misp_attribute_id = ''
//   RETURN count(i) AS null_after_pass_a;
//
//   MATCH (i:Indicator)
//   WHERE i.misp_attribute_id IS NOT NULL AND i.misp_attribute_id <> ''
//   RETURN count(i) AS populated;
//
//   // The (null_before - null_after_pass_a) delta tells you how many
//   // nodes Pass A successfully recovered. The remainder is Pass B's job.
//
// Requires APOC. Operator runbook: docs/MIGRATIONS.md.
// ============================================================================


// ----------------------------------------------------------------------------
// PASS A: recover misp_attribute_id from SOURCED_FROM.raw_data JSON.
// Only touches Indicators that don't already have one.
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "MATCH (i:Indicator)-[r:SOURCED_FROM]->(:Source) " +
  "WHERE (i.misp_attribute_id IS NULL OR i.misp_attribute_id = '') " +
  "  AND r.raw_data IS NOT NULL " +
  "RETURN i, r.raw_data AS raw_data",
  "WITH i, raw_data, " +
  "     apoc.convert.fromJsonMap(raw_data) AS payload " +
  "WITH i, " +
  "     coalesce(payload.misp_attribute_id, payload.misp_attribute_uuid, '') AS recovered_id " +
  "WHERE recovered_id <> '' " +
  "SET i.misp_attribute_id = recovered_id, " +
  "    i.misp_attribute_ids = apoc.coll.toSet(coalesce(i.misp_attribute_ids, []) + [recovered_id])",
  {batchSize: 1000, parallel: false}
);


// ============================================================================
// Notes for operators
// ============================================================================
//
// - apoc.convert.fromJsonMap silently returns null on malformed JSON.
//   Such rows are harmless: the inner WITH filters them out via the
//   `WHERE recovered_id <> ''` clause.
//
// - Older raw_data payloads (pre-misp_attribute_id era) simply do not
//   contain the field. The query is a no-op for those rows; they roll
//   over to Pass B (out-of-band MISP re-fetch).
//
// - The Indicator UNIQUE constraint is on (indicator_type, value), not
//   on misp_attribute_id — so two Indicators that legitimately share an
//   attribute UUID (should not happen, but defensively) won't collide.
