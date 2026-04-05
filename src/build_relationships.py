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

from neo4j_client import Neo4jClient

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
        if not _safe_run(
            client,
            "Technique → Tactic",
            """
            MATCH (t:Technique), (tc:Tactic)
            WHERE tc.shortname IS NOT NULL
              AND any(phase IN [p IN coalesce(t.tactic_phases, []) WHERE p IS NOT NULL]
                      WHERE toLower(phase) = toLower(tc.shortname))
            MERGE (t)-[r:IN_TACTIC]->(tc)
            SET r.confidence_score = 1.0, r.match_type = 'kill_chain_phase', r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "in_tactic",
        ):
            failures += 1

        # 2. Malware → ThreatActor (ATTRIBUTED_TO) — exact name match
        logger.info("[LINK] 2/11 Malware → ThreatActor (exact name match)...")
        if not _safe_run(
            client,
            "Malware → ThreatActor",
            """
            MATCH (m:Malware), (a:ThreatActor)
            WHERE (m.attributed_to IS NOT NULL AND m.attributed_to <> ''
                   AND (m.attributed_to = a.name OR m.attributed_to IN coalesce(a.aliases, [])))
               OR a.name IN coalesce(m.aliases, [])
            MERGE (m)-[r:ATTRIBUTED_TO]->(a)
            SET r.confidence_score = 1.0, r.match_type = 'exact', r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "attributed_to",
        ):
            failures += 1

        # 3a. Indicator → Vulnerability (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3a/11 Indicator → Vulnerability (exact CVE match)...")
        if not _safe_run(
            client,
            "Indicator → Vulnerability (EXPLOITS)",
            """
            MATCH (i:Indicator)
            WHERE i.cve_id IS NOT NULL AND i.cve_id <> ''
            MATCH (v:Vulnerability {cve_id: i.cve_id})
            MERGE (i)-[r:EXPLOITS]->(v)
            SET r.confidence_score = 1.0,
                r.match_type = 'cve_tag',
                r.source_id = 'cve_tag_match',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "exploits_vuln",
        ):
            failures += 1

        # 3b. Indicator → CVE (EXPLOITS) — exact CVE match (indexed)
        logger.info("[LINK] 3b/11 Indicator → CVE (exact CVE match)...")
        if not _safe_run(
            client,
            "Indicator → CVE (EXPLOITS)",
            """
            MATCH (i:Indicator)
            WHERE i.cve_id IS NOT NULL AND i.cve_id <> ''
            MATCH (c:CVE {cve_id: i.cve_id})
            MERGE (i)-[r:EXPLOITS]->(c)
            SET r.confidence_score = 1.0,
                r.match_type = 'cve_tag',
                r.source_id = 'cve_tag_match',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "exploits_cve",
        ):
            failures += 1

        # 4. Indicator → Malware (INDICATES) — MISP event co-occurrence
        logger.info("[LINK] 4/11 Indicator → Malware (MISP event co-occurrence)...")
        if not _safe_run(
            client,
            "Indicator → Malware (co-occurrence)",
            """
            MATCH (i:Indicator)
            WHERE i.misp_event_id IS NOT NULL AND i.misp_event_id <> ''
            WITH i, [eid IN coalesce(i.misp_event_ids, [i.misp_event_id])
                      WHERE eid IS NOT NULL AND eid <> ''] AS eids
            WHERE size(eids) > 0 AND size(eids) <= 200
            UNWIND eids AS eid
            WITH i, eid
            MATCH (m:Malware {misp_event_id: eid})
            MERGE (i)-[r:INDICATES]->(m)
            SET r.confidence_score = 0.5,
                r.match_type = 'misp_cooccurrence',
                r.source_id = 'misp_cooccurrence',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "indicates_cooccurrence",
        ):
            failures += 1

        # 5. ThreatActor → Technique (USES) — explicit ATT&CK uses_techniques list
        logger.info("[LINK] 5/11 ThreatActor → Technique (ATT&CK explicit)...")
        if not _safe_run(
            client,
            "ThreatActor → Technique (ATT&CK explicit)",
            """
            MATCH (a:ThreatActor), (t:Technique)
            WHERE t.mitre_id IS NOT NULL
              AND t.mitre_id <> ''
              AND t.mitre_id IN coalesce(a.uses_techniques, [])
            MERGE (a)-[r:USES]->(t)
            SET r.confidence_score = 0.95,
                r.match_type = 'mitre_explicit',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "uses_explicit",
        ):
            failures += 1

        # 6. Malware → Technique (USES) — MITRE STIX uses relationships
        logger.info("[LINK] 6/11 Malware → Technique (MITRE explicit)...")
        if not _safe_run(
            client,
            "Malware → Technique (MITRE explicit)",
            """
            MATCH (m:Malware), (t:Technique)
            WHERE t.mitre_id IS NOT NULL
              AND t.mitre_id <> ''
              AND t.mitre_id IN coalesce(m.uses_techniques, [])
            MERGE (m)-[r:USES]->(t)
            SET r.confidence_score = 0.95,
                r.match_type = 'mitre_explicit',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "malware_uses_technique",
        ):
            failures += 1

        # 7a. Indicator → Sector (TARGETS)
        logger.info("[LINK] 7a/11 Indicator → Sector (TARGETS)...")
        if not _safe_run(
            client,
            "Indicator → Sector (TARGETS)",
            """
            MATCH (i:Indicator)
            WHERE size(coalesce(i.zone, [])) > 0
            UNWIND i.zone AS zone_name
            WITH i, zone_name
            WHERE zone_name IS NOT NULL AND zone_name <> ''
              AND zone_name IN ['healthcare', 'energy', 'finance', 'global']
            MERGE (sec:Sector {name: zone_name})
            MERGE (i)-[r:TARGETS]->(sec)
            ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime()
            RETURN count(DISTINCT i) as count
        """,
            stats,
            "indicator_targets_sector",
        ):
            failures += 1

        # 7b. Vulnerability/CVE → Sector (AFFECTS)
        logger.info("[LINK] 7b/11 Vulnerability/CVE → Sector (AFFECTS)...")
        if not _safe_run(
            client,
            "Vulnerability/CVE → Sector (AFFECTS)",
            """
            MATCH (v)
            WHERE (v:Vulnerability OR v:CVE) AND size(coalesce(v.zone, [])) > 0
            UNWIND v.zone AS zone_name
            WITH v, zone_name
            WHERE zone_name IS NOT NULL AND zone_name <> ''
              AND zone_name IN ['healthcare', 'energy', 'finance', 'global']
            MERGE (sec:Sector {name: zone_name})
            MERGE (v)-[r:AFFECTS]->(sec)
            ON CREATE SET r.confidence_score = 1.0, r.created_at = datetime()
            RETURN count(DISTINCT v) as count
        """,
            stats,
            "vuln_affects_sector",
        ):
            failures += 1

        # 8. Indicator → Technique (USES_TECHNIQUE) — OTX attack_ids
        logger.info("[LINK] 8/11 Indicator → Technique (OTX attack_ids)...")
        if not _safe_run(
            client,
            "Indicator → Technique (attack_ids)",
            """
            MATCH (i:Indicator)
            WHERE size(coalesce(i.attack_ids, [])) > 0
            UNWIND i.attack_ids AS tech_id
            MATCH (t:Technique {mitre_id: tech_id})
            MERGE (i)-[r:USES_TECHNIQUE]->(t)
            ON CREATE SET r.confidence_score = 0.85,
                r.match_type = 'otx_attack_ids',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "indicator_uses_technique",
        ):
            failures += 1

        # 9. Indicator → Malware (INDICATES) — malware_family name match
        logger.info("[LINK] 9/11 Indicator → Malware (malware_family match)...")
        if not _safe_run(
            client,
            "Indicator → Malware (family match)",
            """
            MATCH (i:Indicator)
            WHERE i.malware_family IS NOT NULL AND i.malware_family <> ''
            MATCH (m:Malware)
            WHERE toLower(m.name) = toLower(i.malware_family)
               OR toLower(i.malware_family) IN [x IN coalesce(m.aliases, []) | toLower(x)]
               OR toLower(m.family) = toLower(i.malware_family)
            MERGE (i)-[r:INDICATES]->(m)
            ON CREATE SET r.confidence_score = 0.8,
                r.match_type = 'malware_family',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "indicates_family",
        ):
            failures += 1

        # 10. Tool → Technique (USES) — MITRE uses_techniques
        logger.info("[LINK] 10/11 Tool → Technique (MITRE explicit)...")
        if not _safe_run(
            client,
            "Tool → Technique (MITRE explicit)",
            """
            MATCH (tool:Tool), (t:Technique)
            WHERE t.mitre_id IS NOT NULL
              AND t.mitre_id <> ''
              AND t.mitre_id IN coalesce(tool.uses_techniques, [])
            MERGE (tool)-[r:USES]->(t)
            ON CREATE SET r.confidence_score = 0.95,
                r.match_type = 'mitre_explicit',
                r.created_at = datetime()
            RETURN count(*) as count
        """,
            stats,
            "tool_uses_technique",
        ):
            failures += 1

        # 11-13. IS_SAME_AS cross-source correlation
        # With tag removed from MERGE keys, same-name entities and same-cve_id
        # nodes already merge into a single node. IS_SAME_AS is no longer needed
        # for Malware (name-keyed), CVE (cve_id-keyed), or Vulnerability (cve_id-keyed).
        # Source provenance is tracked via the accumulated `source` and `tags` arrays.
        logger.info("[LINK] 11/11 Cross-source dedup — skipped (entities merge on name/cve_id, no IS_SAME_AS needed)")

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

        return failures == 0

    except Exception as e:
        logger.error(f"Error building relationships: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        client.close()


def build_relationships_with_fuzzy_matching():
    """Optional: Build relationships with fuzzy matching (opt-in, more prone to false positives).

    WARNING: This function uses CONTAINS matching which can create false positives.
    Use build_relationships() for production - this is for research/analysis only.
    """
    client = Neo4jClient()

    if not client.connect():
        logger.error("Failed to connect to Neo4j")
        return False

    logger.warning("[WARN]  Using fuzzy matching - this may create false positive relationships!")

    try:
        # Fuzzy match with LOWER confidence scores
        logger.info("[LINK] Creating fuzzy relationships (LOW confidence)...")

        # Only do fuzzy matching for specific known cases with low confidence
        result = client.run("""
            MATCH (m:Malware), (a:ThreatActor)
            WHERE m.attributed_to CONTAINS a.name OR a.name CONTAINS m.attributed_to
            AND m.attributed_to <> a.name  -- Exclude exact matches (already done above)
            MERGE (m)-[r:ATTRIBUTED_TO]->(a)
            SET r.confidence_score = 0.5, r.match_type = 'fuzzy', r.created_at = datetime()
            RETURN count(*) as count
        """)
        fuzzy_count = result[0].get("count", 0) if result else 0
        logger.info(f"  [OK] Fuzzy ATTRIBUTED_TO: {fuzzy_count} (confidence: 0.5)")

        return True

    except Exception as e:
        logger.error(f"Error in fuzzy matching: {e}")
        return False

    finally:
        client.close()


if __name__ == "__main__":
    print("=" * 50)
    print("🔗 EdgeGuard - Building Graph Relationships")
    print("=" * 50)
    print("\nUsing EXACT matching with confidence scoring...")
    print("To enable fuzzy matching (not recommended), call:")
    print("  build_relationships_with_fuzzy_matching()")
    print()

    if build_relationships():
        print("\n✅ Relationships built successfully!")
    else:
        print("\n❌ Failed to build relationships")
