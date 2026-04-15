// ============================================================================
// Migration: specialize USES → {EMPLOYS_TECHNIQUE, IMPLEMENTS_TECHNIQUE}
// ============================================================================
//
// Context
// -------
// Prior to 2026-04, every X→Technique edge from MITRE ATT&CK was a single
// generic USES. That conflated three semantically distinct claims:
//
//   - ThreatActor USES Technique  = attribution (who is observed doing this TTP)
//   - Malware     USES Technique  = capability  (what the code can do)
//   - Tool        USES Technique  = capability  (what the tool can do)
//
// Indicator→Technique was already specialized as USES_TECHNIQUE (OTX
// attack_ids), so USES was the odd one out. The mixed semantics hurt:
//   1. GraphRAG retrieval quality — the rel type is part of the LLM prompt
//      and "uses" tells the model much less than "employs"/"implements".
//   2. Cypher clarity — every query had to add endpoint-label filters.
//   3. Analyst interpretation — attribution and capability mean different
//      things operationally.
//
// This migration splits USES→Technique into two specialized types while
// leaving USES_TECHNIQUE (Indicator side) untouched. All non-Technique
// target USES edges — if any exist from legacy imports — are left alone.
//
// Safety
// ------
// - Uses apoc.periodic.iterate for batching so the transaction log never
//   grows unbounded on large graphs (81K USES edges were observed after
//   the 730-day NVD baseline).
// - Each block copies all properties (SET r2 = properties(r)) before
//   deleting the old edge. If the ingest code is rerun mid-migration it
//   will MERGE into the new type cleanly.
// - Parallel:false keeps lock contention predictable.
// - Each block is idempotent: running it again against an already-
//   migrated graph matches 0 rows and does nothing.
//
// Pre-migration sanity check (run manually first):
//
//   MATCH ()-[r:USES]->(t:Technique) RETURN count(r) AS before_count;
//
// Post-migration sanity check:
//
//   MATCH ()-[r:USES]->(t:Technique) RETURN count(r) AS remaining_uses;
//   // expected: 0
//
//   MATCH (a:ThreatActor)-[r:EMPLOYS_TECHNIQUE]->(:Technique)
//   RETURN count(r) AS employs_count;
//
//   MATCH (m:Malware)-[r:IMPLEMENTS_TECHNIQUE]->(:Technique)
//   RETURN count(r) AS malware_implements_count;
//
//   MATCH (tool:Tool)-[r:IMPLEMENTS_TECHNIQUE]->(:Technique)
//   RETURN count(r) AS tool_implements_count;
//
// before_count should equal employs_count + malware_implements_count +
// tool_implements_count (± any Campaign→Technique edges if you have them).
//
// Requires APOC. If APOC is unavailable, see the non-APOC variants at the
// bottom of this file.
//
// Operator runbook: docs/MIGRATIONS.md (pre-flight, backup, execute,
// post-flight, rollback instructions).
// ============================================================================


// ----------------------------------------------------------------------------
// 1. ThreatActor → Technique  ⇒  EMPLOYS_TECHNIQUE  (attribution)
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "MATCH (a:ThreatActor)-[r:USES]->(t:Technique) RETURN a, r, t",
  "MERGE (a)-[r2:EMPLOYS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r",
  {batchSize: 1000, parallel: false}
);


// ----------------------------------------------------------------------------
// 2. Campaign → Technique  ⇒  EMPLOYS_TECHNIQUE  (attribution)
//
// Included for forward-compat — no Campaign→USES→Technique edges are
// created by current code, but if any exist from a manual import they
// get the same attribution treatment as ThreatActor.
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "MATCH (c:Campaign)-[r:USES]->(t:Technique) RETURN c, r, t",
  "MERGE (c)-[r2:EMPLOYS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r",
  {batchSize: 1000, parallel: false}
);


// ----------------------------------------------------------------------------
// 3. Malware → Technique  ⇒  IMPLEMENTS_TECHNIQUE  (capability)
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "MATCH (m:Malware)-[r:USES]->(t:Technique) RETURN m, r, t",
  "MERGE (m)-[r2:IMPLEMENTS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r",
  {batchSize: 1000, parallel: false}
);


// ----------------------------------------------------------------------------
// 4. Tool → Technique  ⇒  IMPLEMENTS_TECHNIQUE  (capability)
// ----------------------------------------------------------------------------
CALL apoc.periodic.iterate(
  "MATCH (tool:Tool)-[r:USES]->(t:Technique) RETURN tool, r, t",
  "MERGE (tool)-[r2:IMPLEMENTS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r",
  {batchSize: 1000, parallel: false}
);


// ============================================================================
// Non-APOC variants (uncomment if APOC is not installed)
// ============================================================================
//
// These are single-transaction versions — safe on small graphs (<10K edges
// total) but will blow up the transaction log at the 80K+ scale seen in
// production. Prefer the APOC versions above.
//
// MATCH (a:ThreatActor)-[r:USES]->(t:Technique)
// MERGE (a)-[r2:EMPLOYS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r;
//
// MATCH (c:Campaign)-[r:USES]->(t:Technique)
// MERGE (c)-[r2:EMPLOYS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r;
//
// MATCH (m:Malware)-[r:USES]->(t:Technique)
// MERGE (m)-[r2:IMPLEMENTS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r;
//
// MATCH (tool:Tool)-[r:USES]->(t:Technique)
// MERGE (tool)-[r2:IMPLEMENTS_TECHNIQUE]->(t) SET r2 += properties(r) DELETE r;
