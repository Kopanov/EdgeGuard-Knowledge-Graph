#!/usr/bin/env python3
"""
EdgeGuard - Graph Relationship Builder
Creates edges between nodes in Neo4j

FIXED: Uses exact matching with confidence scoring instead of fuzzy CONTAINS matching
to prevent false positives (e.g., "APT" matching "AP").
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import time

from neo4j_client import Neo4jClient
from node_identity import compute_node_uuid

try:
    from metrics_server import record_neo4j_relationships

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

# Pause between queries to let Neo4j flush transactions and reclaim memory
_INTER_QUERY_PAUSE = 3  # seconds

# Pre-computed Sector node uuids for the 4 known zones — used in the TARGETS
# (7a) and AFFECTS (7b) queries below to stamp ``sec.uuid`` on Sector nodes
# auto-CREATEd by those MERGEs. Bugbot caught (PR #33 round 4) that without
# this stamp ``sec.uuid`` was NULL and downstream ``r.trg_uuid = sec.uuid``
# inherited NULL. APOC's apoc.create.uuid is random (v4) — no use for our
# deterministic UUIDv5 — so we precompute in Python and embed as a Cypher
# CASE expression literal in the query string.
_SECTOR_UUIDS: dict = {
    z: compute_node_uuid("Sector", {"name": z}) for z in ("healthcare", "energy", "finance", "global")
}
_SECTOR_UUID_CASE = (
    "CASE zone_name " + " ".join(f"WHEN '{name}' THEN '{u}'" for name, u in _SECTOR_UUIDS.items()) + " END"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _safe_run(client, label: str, query: str, stats: dict, stat_key: str) -> bool:
    """Run a single relationship query with fault tolerance.

    Returns True on success, False on failure (logged, not raised).
    """
    try:
        result = client.run(query)
        stats[stat_key] = result[0].get("count", 0) if result else 0
        logger.info(f"  [OK] {label}: {stats[stat_key]}")
        return True
    except Exception as e:
        logger.error(f"  [FAIL] {label}: {type(e).__name__}: {e}", exc_info=True)
        stats[stat_key] = 0
        return False


def _safe_run_batched(client, label, outer_query, inner_query, stats, stat_key, batch_size=5000):
    """Run a relationship query in batches using apoc.periodic.iterate.

    Splits the work into mini-transactions of batch_size to prevent OOM.
    Returns True on success, False on failure (logged, not raised).
    """
    query = f"""
    CALL apoc.periodic.iterate(
        '{outer_query}',
        '{inner_query}',
        {{batchSize: {batch_size}, parallel: false}}
    )
    YIELD batches, total, errorMessages
    RETURN total AS count, batches, errorMessages
    """
    try:
        result = client.run(query)
        if result:
            row = result[0]
            count = row.get("count", 0)
            batches_n = row.get("batches", 0)
            errors = row.get("errorMessages", [])
            stats[stat_key] = count
            if errors:
                logger.warning(f"  [PARTIAL] {label}: {count} in {batches_n} batches, errors: {errors[:3]}")
            else:
                logger.info(f"  [OK] {label}: {count} in {batches_n} batches")
        else:
            stats[stat_key] = 0
            logger.info(f"  [OK] {label}: 0 (no matches)")
        return True
    except Exception as e:
        logger.error(f"  [FAIL] {label}: {type(e).__name__}: {e}", exc_info=True)
        stats[stat_key] = 0
        return False


def build_relationships():
    """Build relationships between nodes using exact matching with confidence scoring."""
    client = Neo4jClient()

    if not client.connect():
        logger.error("Failed to connect to Neo4j")
        return False

    stats = {}
    failures = 0

    try:
        # 1. Technique → Tactic (IN_TACTIC) — kill-chain phase match
        logger.info("[LINK] 1/11 Technique → Tactic (kill-chain phase match)...")
        _outer = "MATCH (t:Technique) WHERE size(coalesce(t.tactic_phases, [])) > 0 RETURN t"
        _inner = 'WITH $t AS t MATCH (tc:Tactic) WHERE tc.shortname IS NOT NULL AND any(phase IN [p IN coalesce(t.tactic_phases, []) WHERE p IS NOT NULL] WHERE toLower(phase) = toLower(tc.shortname)) MERGE (t)-[r:IN_TACTIC]->(tc) ON CREATE SET r.confidence_score = 1.0, r.match_type = "kill_chain_phase", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, t.uuid), r.trg_uuid = coalesce(r.trg_uuid, tc.uuid)'
        if not _safe_run_batched(client, "Technique → Tactic", _outer, _inner, stats, "in_tactic"):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 2. Malware → ThreatActor (ATTRIBUTED_TO) — exact name match
        logger.info("[LINK] 2/11 Malware → ThreatActor (exact name match)...")
        _outer = "MATCH (m:Malware) WHERE (m.attributed_to IS NOT NULL AND m.attributed_to <> '') OR size(coalesce(m.aliases, [])) > 0 RETURN m"
        _inner = 'WITH $m AS m MATCH (a:ThreatActor) WHERE m.attributed_to = a.name OR m.attributed_to IN coalesce(a.aliases, []) OR a.name IN coalesce(m.aliases, []) MERGE (m)-[r:ATTRIBUTED_TO]->(a) ON CREATE SET r.confidence_score = 1.0, r.match_type = "exact", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, m.uuid), r.trg_uuid = coalesce(r.trg_uuid, a.uuid)'
        if not _safe_run_batched(client, "Malware → ThreatActor", _outer, _inner, stats, "attributed_to"):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 3a. Indicator → Vulnerability (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3a/11 Indicator → Vulnerability (exact CVE match)...")
        _q3a_outer = "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND i.cve_id <> '' RETURN i"
        _q3a_inner = 'WITH $i AS i MATCH (v:Vulnerability {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(v) ON CREATE SET r.confidence_score = 1.0, r.match_type = "cve_tag", r.source_id = "cve_tag_match", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, v.uuid)'
        if not _safe_run_batched(
            client, "Indicator → Vulnerability (EXPLOITS)", _q3a_outer, _q3a_inner, stats, "exploits_vuln"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 3b. Indicator → CVE (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3b/11 Indicator → CVE (exact CVE match)...")
        _q3b_outer = "MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND i.cve_id <> '' RETURN i"
        _q3b_inner = 'WITH $i AS i MATCH (c:CVE {cve_id: i.cve_id}) MERGE (i)-[r:EXPLOITS]->(c) ON CREATE SET r.confidence_score = 1.0, r.match_type = "cve_tag", r.source_id = "cve_tag_match", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, c.uuid)'
        if not _safe_run_batched(client, "Indicator → CVE (EXPLOITS)", _q3b_outer, _q3b_inner, stats, "exploits_cve"):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 4. Indicator → Malware (INDICATES) — MISP event co-occurrence (BATCHED)
        # This query caused OOM on 170K+ indicators. Uses apoc.periodic.iterate
        # to process in 5000-node mini-transactions instead of one giant transaction.
        #
        # Symmetric scalar+array handling on BOTH ends of the join (2026-04 fix):
        #   - Outer: include Indicators that have either the scalar misp_event_id OR
        #     a non-empty misp_event_ids[] array. Pre-fix the outer filter was
        #     scalar-only, missing Indicators ingested with array-only event references.
        #   - Inner: match Malware whose scalar misp_event_id = eid OR whose
        #     misp_event_ids[] array contains eid. Pre-fix this matched Malware only
        #     by its first-seen event scalar, dropping co-occurrence edges to Malware
        #     that re-appeared in later events.
        logger.info("[LINK] 4/11 Indicator → Malware (co-occurrence, batched)...")
        _q4_outer = (
            "MATCH (i:Indicator) "
            "WHERE (i.misp_event_id IS NOT NULL AND i.misp_event_id <> '') "
            "   OR (i.misp_event_ids IS NOT NULL AND size(i.misp_event_ids) > 0) "
            "RETURN i"
        )
        _q4_inner = (
            "WITH $i AS i "
            "WITH i, [eid IN coalesce(i.misp_event_ids, [i.misp_event_id]) "
            "  WHERE eid IS NOT NULL AND eid <> ''][0..200] AS eids "
            "UNWIND eids AS eid "
            "WITH i, eid "
            "MATCH (m:Malware) "
            "WHERE m.misp_event_id = eid "
            "   OR (m.misp_event_ids IS NOT NULL AND eid IN m.misp_event_ids) "
            "MERGE (i)-[r:INDICATES]->(m) "
            "ON CREATE SET r.confidence_score = 0.5, "
            '  r.match_type = "misp_cooccurrence", '
            '  r.source_id = "misp_cooccurrence", '
            "  r.created_at = datetime() "
            "SET r.src_uuid = coalesce(r.src_uuid, i.uuid), "
            "    r.trg_uuid = coalesce(r.trg_uuid, m.uuid)"
        )
        if not _safe_run_batched(
            client,
            "Indicator → Malware (co-occurrence)",
            _q4_outer,
            _q4_inner,
            stats,
            "indicates_cooccurrence",
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 5. ThreatActor → Technique (EMPLOYS_TECHNIQUE) — explicit ATT&CK
        # uses_techniques list. Attribution semantics: "who uses this TTP".
        # Split from a previously-generic USES in 2026-04 to improve GraphRAG
        # retrieval — see migrations/2026_04_specialize_uses_technique.cypher.
        logger.info("[LINK] 5/11 ThreatActor → Technique (ATT&CK explicit)...")
        _outer = "MATCH (a:ThreatActor) WHERE size(coalesce(a.uses_techniques, [])) > 0 RETURN a"
        _inner = 'WITH $a AS a UNWIND a.uses_techniques AS tid WITH a, tid MATCH (t:Technique {mitre_id: tid}) MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, a.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        if not _safe_run_batched(
            client, "ThreatActor → Technique (ATT&CK explicit)", _outer, _inner, stats, "employs_technique_explicit"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 6. Malware → Technique (IMPLEMENTS_TECHNIQUE) — MITRE STIX uses
        # relationships. Capability semantics: "what the code can do".
        logger.info("[LINK] 6/11 Malware → Technique (MITRE explicit)...")
        _outer = "MATCH (m:Malware) WHERE size(coalesce(m.uses_techniques, [])) > 0 RETURN m"
        _inner = 'WITH $m AS m UNWIND m.uses_techniques AS tid WITH m, tid MATCH (t:Technique {mitre_id: tid}) MERGE (m)-[r:IMPLEMENTS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, m.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        if not _safe_run_batched(
            client, "Malware → Technique (MITRE explicit)", _outer, _inner, stats, "malware_implements_technique"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 7a. Indicator → Sector (TARGETS)
        # The Sector node is auto-CREATEd here — stamp its uuid with the
        # deterministic Python-precomputed value embedded as a Cypher CASE
        # expression literal (sector names are a fixed set of 4). Without this,
        # sec.uuid would be NULL and r.trg_uuid would inherit NULL.
        logger.info("[LINK] 7a/11 Indicator → Sector (TARGETS)...")
        _q7a_outer = "MATCH (i:Indicator) WHERE size(coalesce(i.zone, [])) > 0 RETURN i"
        _q7a_inner = (
            "WITH $i AS i UNWIND i.zone AS zone_name WITH i, zone_name "
            "WHERE zone_name IS NOT NULL AND zone_name <> '' "
            "AND zone_name IN ['healthcare', 'energy', 'finance', 'global'] "
            "MERGE (sec:Sector {name: zone_name}) "
            f"  ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE} "
            f"  SET sec.uuid = coalesce(sec.uuid, {_SECTOR_UUID_CASE}) "
            "MERGE (i)-[r:TARGETS]->(sec) "
            "ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime() "
            "SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, sec.uuid)"
        )
        if not _safe_run_batched(
            client, "Indicator -> Sector (TARGETS)", _q7a_outer, _q7a_inner, stats, "indicator_targets_sector"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 7b. Vulnerability/CVE → Sector (AFFECTS)
        # Same Sector-uuid stamp as 7a — see comment above.
        logger.info("[LINK] 7b/11 Vulnerability/CVE → Sector (AFFECTS)...")
        _q7b_outer = "MATCH (v) WHERE (v:Vulnerability OR v:CVE) AND size(coalesce(v.zone, [])) > 0 RETURN v"
        _q7b_inner = (
            "WITH $v AS v UNWIND v.zone AS zone_name WITH v, zone_name "
            "WHERE zone_name IS NOT NULL AND zone_name <> '' "
            "AND zone_name IN ['healthcare', 'energy', 'finance', 'global'] "
            "MERGE (sec:Sector {name: zone_name}) "
            f"  ON CREATE SET sec.uuid = {_SECTOR_UUID_CASE} "
            f"  SET sec.uuid = coalesce(sec.uuid, {_SECTOR_UUID_CASE}) "
            "MERGE (v)-[r:AFFECTS]->(sec) "
            "ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime() "
            "SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, v.uuid), r.trg_uuid = coalesce(r.trg_uuid, sec.uuid)"
        )
        if not _safe_run_batched(
            client, "Vulnerability/CVE -> Sector (AFFECTS)", _q7b_outer, _q7b_inner, stats, "vuln_affects_sector"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 8. Indicator → Technique (USES_TECHNIQUE) — OTX attack_ids
        logger.info("[LINK] 8/11 Indicator → Technique (OTX attack_ids)...")
        _q8_outer = "MATCH (i:Indicator) WHERE size(coalesce(i.attack_ids, [])) > 0 RETURN i"
        _q8_inner = 'WITH $i AS i UNWIND i.attack_ids AS tech_id WITH i, tech_id MATCH (t:Technique {mitre_id: tech_id}) MERGE (i)-[r:USES_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.85, r.match_type = "otx_attack_ids", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        if not _safe_run_batched(
            client, "Indicator → Technique (attack_ids)", _q8_outer, _q8_inner, stats, "indicator_uses_technique"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 9. Indicator → Malware (INDICATES) — malware_family name match
        logger.info("[LINK] 9/11 Indicator → Malware (malware_family match)...")
        _q9_outer = "MATCH (i:Indicator) WHERE i.malware_family IS NOT NULL AND i.malware_family <> '' RETURN i"
        _q9_inner = 'WITH $i AS i MATCH (m:Malware) WHERE toLower(m.name) = toLower(i.malware_family) OR toLower(i.malware_family) IN [x IN coalesce(m.aliases, []) | toLower(x)] OR toLower(m.family) = toLower(i.malware_family) MERGE (i)-[r:INDICATES]->(m) ON CREATE SET r.created_at = datetime() SET r.confidence_score = CASE WHEN r.confidence_score IS NULL OR 0.8 > r.confidence_score THEN 0.8 ELSE r.confidence_score END, r.match_type = "malware_family", r.source_id = "malware_family_match", r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, i.uuid), r.trg_uuid = coalesce(r.trg_uuid, m.uuid)'
        if not _safe_run_batched(
            client, "Indicator → Malware (family match)", _q9_outer, _q9_inner, stats, "indicates_family"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # 10. Tool → Technique (IMPLEMENTS_TECHNIQUE) — MITRE uses_techniques.
        # Same capability semantics as Malware above; both are "code/tool can
        # execute this TTP".
        logger.info("[LINK] 10/11 Tool → Technique (MITRE explicit)...")
        _outer = "MATCH (tool:Tool) WHERE size(coalesce(tool.uses_techniques, [])) > 0 RETURN tool"
        _inner = 'WITH $tool AS tool UNWIND tool.uses_techniques AS tid WITH tool, tid MATCH (t:Technique {mitre_id: tid}) MERGE (tool)-[r:IMPLEMENTS_TECHNIQUE]->(t) ON CREATE SET r.confidence_score = 0.95, r.match_type = "mitre_explicit", r.created_at = datetime() SET r.updated_at = datetime(), r.src_uuid = coalesce(r.src_uuid, tool.uuid), r.trg_uuid = coalesce(r.trg_uuid, t.uuid)'
        if not _safe_run_batched(
            client, "Tool → Technique (MITRE explicit)", _outer, _inner, stats, "tool_implements_technique"
        ):
            failures += 1
        time.sleep(_INTER_QUERY_PAUSE)

        # Cross-source dedup is handled at ingest time via single-key MERGE
        # (name for Malware/ThreatActor, cve_id for CVE/Vulnerability, mitre_id
        # for Technique/Tactic/Tool). Source provenance tracked via `source`/`tags` arrays.

        # Get final stats
        try:
            logger.info("\n[STATS] Final Graph Statistics:")
            result = client.run("""
                MATCH (a)-[r]->(b)
                RETURN type(r) as relationship, count(*) as count,
                       avg(r.confidence_score) as avg_confidence
                ORDER BY count DESC
            """)
            for row in result:
                avg_conf = row.get("avg_confidence")
                if avg_conf is not None:
                    avg_conf = f"{float(avg_conf):.2f}"
                else:
                    avg_conf = "N/A"
                logger.info(f"   {row['relationship']}: {row['count']} (avg confidence: {avg_conf})")
        except Exception as e:
            logger.error(f"Failed to fetch final stats: {e}")

        # Log summary
        total_rels = sum(v for k, v in stats.items() if k != "multi_zone_indicators")
        logger.info(f"\nTotal relationships created: {total_rels}")
        if failures:
            logger.warning(f"Relationship types failed: {failures}/11 — partial success")

        if _METRICS_AVAILABLE:
            try:
                record_neo4j_relationships(stats)
            except Exception:
                logger.debug("Metrics recording failed", exc_info=True)

        return failures == 0

    except Exception as e:
        logger.error(f"Error building relationships: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        client.close()


if __name__ == "__main__":
    print("=" * 50)
    print("EdgeGuard - Building Graph Relationships")
    print("=" * 50)
    print("\nUsing EXACT matching with confidence scoring...")
    print()

    if build_relationships():
        print("\n✅ Relationships built successfully!")
    else:
        print("\n❌ Failed to build relationships")
        sys.exit(1)
