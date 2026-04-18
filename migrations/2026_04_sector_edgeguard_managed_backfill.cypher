// PR #37 — backfill ``edgeguard_managed = true`` on every Sector node
// auto-created by build_relationships before the fix landed.
//
// Background
// ----------
// The 7a (Indicator → Sector TARGETS) and 7b (Vulnerability/CVE → Sector
// AFFECTS) link queries used to MERGE Sector nodes WITHOUT setting
// ``edgeguard_managed``. The STIX exporter filters every Sector lookup
// with ``WHERE s.edgeguard_managed = true`` (strict equality, NULL
// fails — see src/stix_exporter.py:203,254,473). So Sectors created
// before the PR #37 fix are SILENTLY OMITTED from every STIX bundle,
// and along with them every TARGETS/AFFECTS SRO that points at them.
// ResilMesh consumers see indicators with no zone identity attached.
//
// Run
// ---
// Apply once after deploying the PR #37 fix:
//
//   cypher-shell -u $NEO4J_USER -p $NEO4J_PASSWORD -f \
//     migrations/2026_04_sector_edgeguard_managed_backfill.cypher
//
// Idempotent — re-running stamps already-flagged nodes harmlessly.
// Verification
// ------------
// Before:
//   MATCH (s:Sector) WHERE s.edgeguard_managed IS NULL OR s.edgeguard_managed <> true
//   RETURN count(s);
// After:
//   MATCH (s:Sector) WHERE s.edgeguard_managed IS NULL OR s.edgeguard_managed <> true
//   RETURN count(s);   // expect 0

MATCH (s:Sector)
WHERE s.edgeguard_managed IS NULL OR s.edgeguard_managed <> true
SET s.edgeguard_managed = true,
    s.last_updated = datetime()
RETURN count(s) AS sectors_backfilled;
