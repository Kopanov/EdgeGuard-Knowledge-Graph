#!/usr/bin/env python3
"""
EdgeGuard — Post-Sync Enrichment Jobs
======================================
Four graph-quality jobs that run AFTER every MISP→Neo4j sync.
They are designed to be idempotent — safe to re-run at any time.

Jobs
----
1. decay_ioc_confidence   — Reduce confidence of stale indicators over time
2. build_campaign_nodes   — Group ThreatActor / Malware / Indicator into Campaigns
3. calibrate_cooccurrence — Adjust INDICATES/EXPLOITS confidence for large MISP feed dumps
4. bridge_vulnerability_cve — Create REFERS_TO between Vulnerability and CVE nodes
"""

import logging
import os
import sys
from typing import Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import NEO4J_READ_TIMEOUT  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. IOC CONFIDENCE DECAY
# ---------------------------------------------------------------------------


def decay_ioc_confidence(neo4j_client) -> Dict:
    """
    Time-decay confidence scores for Indicator and Vulnerability nodes.

    Threat intelligence has a shelf life.  An IP flagged 18 months ago
    with no recent sightings is far less actionable than one seen yesterday.

    Decay tiers (based on days since last_updated):
      < 90 days   → no change
      90–180 days → confidence × 0.85 (15% reduction)
      180–365 days→ confidence × 0.70 (30% reduction)
      > 365 days  → active = false (retired, not deleted)

    All changes are non-destructive:
    - Minimum confidence floor is 0.10 (node stays queryable)
    - Retired nodes (active=false) are kept for historical queries
    - first_imported_at and source are never touched
    """
    if not neo4j_client.driver:
        logger.error("decay_ioc_confidence: no Neo4j connection")
        return {}

    results = {}

    tiers = [
        # (label, min_days, max_days, multiplier, retire)
        ("Indicator", 90, 180, 0.85, False),
        ("Indicator", 180, 365, 0.70, False),
        ("Indicator", 365, None, 1.00, True),  # retire
        ("Vulnerability", 90, 180, 0.90, False),
        ("Vulnerability", 180, 365, 0.80, False),
        ("Vulnerability", 365, None, 1.00, True),
    ]

    try:
        with neo4j_client.driver.session() as session:
            for label, min_days, max_days, multiplier, retire in tiers:
                if retire:
                    cypher = f"""
                    MATCH (n:{label})
                    WHERE n.last_updated IS NOT NULL
                      AND n.active = true
                      AND duration.between(n.last_updated, datetime()).days > $min_days
                    SET n.active = false,
                        n.retired_at = datetime()
                    RETURN count(n) AS affected
                    """
                    desc = f"{label} retired (>{min_days}d)"
                else:
                    cypher = f"""
                    MATCH (n:{label})
                    WHERE n.last_updated IS NOT NULL
                      AND n.confidence_score IS NOT NULL
                      AND duration.between(n.last_updated, datetime()).days >= $min_days
                      AND duration.between(n.last_updated, datetime()).days < $max_days
                    SET n.confidence_score = CASE
                            WHEN n.confidence_score * $mult < 0.10 THEN 0.10
                            ELSE round(n.confidence_score * $mult * 100) / 100
                        END
                    RETURN count(n) AS affected
                    """
                    desc = f"{label} decayed ({min_days}–{max_days}d, ×{multiplier})"

                params = {"min_days": min_days, "max_days": max_days, "mult": multiplier}
                result = session.run(cypher, timeout=NEO4J_READ_TIMEOUT, **params)
                record = result.single()
                count = record["affected"] if record else 0
                results[desc] = count
                if count:
                    logger.info(f"  [DECAY] {desc}: {count} nodes")

    except Exception as e:
        logger.error(f"decay_ioc_confidence error: {e}")

    total = sum(results.values())
    logger.info(f"[DECAY] IOC decay complete — {total} nodes updated")
    return results


# ---------------------------------------------------------------------------
# 2. CAMPAIGN NODE BUILDER
# ---------------------------------------------------------------------------


def build_campaign_nodes(neo4j_client) -> Dict:
    """
    Materialise Campaign nodes from the existing threat graph.

    A Campaign represents a coordinated set of threat activity by one actor.
    We infer campaigns from graph structure:
      ThreatActor -[:ATTRIBUTED_TO]<- Malware -[:INDICATES]<- Indicator

    For each ThreatActor that has at least one attributed malware and one
    related indicator, we create a Campaign node and link:
      ThreatActor -[:RUNS]-> Campaign
      Malware     -[:PART_OF]-> Campaign
      Indicator   -[:PART_OF]-> Campaign  (sampled — up to 100 per campaign)

    Campaign properties:
      name            — "{actor_name} Campaign"
      actor_name      — source actor name
      indicator_count — number of indicators at last update
      malware_count   — number of malware families at last update
      first_seen      — earliest indicator.first_imported_at
      last_seen       — latest indicator.last_updated
      zone            — union of all indicator zones
      tag             — actor tag (for UNIQUE constraint key)
    """
    if not neo4j_client.driver:
        logger.error("build_campaign_nodes: no Neo4j connection")
        return {}

    results = {"campaigns_created": 0, "campaigns_updated": 0, "links_created": 0}

    try:
        with neo4j_client.driver.session() as session:
            # Step 1: Materialise Campaign nodes (one per ThreatActor with evidence)
            create_cypher = """
            MATCH (a:ThreatActor)<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
            WITH a,
                 collect(DISTINCT m)    AS malware_list,
                 collect(DISTINCT i)    AS indicators,
                 min(i.first_imported_at) AS first_seen,
                 max(i.last_updated)      AS last_seen,
                 apoc.coll.toSet(
                     reduce(z=[], ind IN collect(DISTINCT i) | z + coalesce(ind.zone, []))
                 ) AS all_zones
            WHERE size(malware_list) > 0 AND size(indicators) > 0
            MERGE (c:Campaign {name: a.name + ' Campaign'})
            ON CREATE SET c.created_at = datetime(),
                          c.actor_name = a.name
            SET c.tags = apoc.coll.toSet(coalesce(c.tags, []) + coalesce(a.tags, [])),
                c.last_updated     = datetime(),
                c.indicator_count  = size(indicators),
                c.malware_count    = size(malware_list),
                c.first_seen       = first_seen,
                c.last_seen        = last_seen,
                c.zone             = all_zones
            MERGE (a)-[:RUNS]->(c)
            RETURN count(DISTINCT c) AS campaigns
            """
            result = session.run(create_cypher, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["campaigns_created"] = record["campaigns"] if record else 0

            # Step 2: Link malware to their campaigns
            link_malware = """
            MATCH (a:ThreatActor)<-[:ATTRIBUTED_TO]-(m:Malware)
            MATCH (c:Campaign {actor_name: a.name})
            MERGE (m)-[:PART_OF]->(c)
            RETURN count(*) AS links
            """
            result = session.run(link_malware, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["links_created"] += record["links"] if record else 0

            # Step 3: Link indicators to their campaigns (sample: up to 100 per campaign)
            # Using LIMIT inside WITH to avoid huge relationship fans
            link_indicators = """
            MATCH (c:Campaign)
            MATCH (a:ThreatActor {name: c.actor_name})<-[:ATTRIBUTED_TO]-(m:Malware)<-[:INDICATES]-(i:Indicator)
            WITH c, collect(i)[0..100] AS indicators
            UNWIND indicators AS i
            MERGE (i)-[:PART_OF]->(c)
            RETURN count(*) AS links
            """
            result = session.run(link_indicators, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            results["links_created"] += record["links"] if record else 0

            # Step 4: Deactivate campaigns whose indicators are all retired
            logger.info("[DECAY] Deactivating campaigns with no active indicators...")
            cleanup_query = """
                MATCH (c:Campaign)<-[:PART_OF]-(i:Indicator)
                WITH c, collect(i.active) AS statuses
                WHERE NOT any(s IN statuses WHERE s = true)
                SET c.active = false
                RETURN count(c) as count
            """
            result = session.run(cleanup_query, timeout=NEO4J_READ_TIMEOUT)
            record = result.single()
            cleanup_count = record["count"] if record else 0
            logger.info(f"  [OK] Deactivated {cleanup_count} campaigns with no active indicators")
            results["campaigns_deactivated"] = cleanup_count

    except Exception as e:
        logger.error(f"build_campaign_nodes error: {e}")

    logger.info(f"[CAMPAIGNS] Built {results['campaigns_created']} campaigns, {results['links_created']} links")
    return results


# ---------------------------------------------------------------------------
# 3. CO-OCCURRENCE CONFIDENCE CALIBRATION
# ---------------------------------------------------------------------------


def calibrate_cooccurrence_confidence(neo4j_client) -> Dict:
    """
    Adjust confidence of MISP-event-co-occurrence INDICATES/EXPLOITS edges.

    Large bulk feed dumps (e.g. Feodo Tracker with 5,000 IPs and one malware
    tag) create co-occurrence relationships with artificially high confidence.
    The larger the MISP event, the weaker the actual co-occurrence signal.

    Confidence tiers by event size (number of indicators in same event):
      ≤ 10  → 0.90  (tight incident report — very strong signal)
      ≤ 20  → 0.80  (small report)
      ≤ 100 → 0.70  (medium feed)
      ≤ 500 → 0.50  (large feed)
      > 500 → 0.30  (bulk dump — weak signal)

    Only edges with source_id IN ('misp_cooccurrence', 'misp_correlation')
    are modified.  Manually curated edges (different source_id) are untouched.
    """
    if not neo4j_client.driver:
        logger.error("calibrate_cooccurrence_confidence: no Neo4j connection")
        return {}

    results = {}

    # Map: (min_size, max_size, new_confidence)
    # Co-occurrence confidence tiers — capped at 0.50 per co-occurrence ceiling.
    # Tight events (few indicators) get higher confidence within the range;
    # bulk dumps get lower confidence.
    tiers = [
        (0, 10, 0.50),
        (11, 20, 0.45),
        (21, 100, 0.40),
        (101, 500, 0.35),
        (501, None, 0.30),
    ]

    try:
        with neo4j_client.driver.session() as session:
            # Step 1: Pre-compute event sizes ONCE (instead of per-edge).
            # Previously each edge re-counted all indicators in its event — millions
            # of redundant COUNT queries. Now: one COUNT per event, then join.
            logger.info("  [CALIBRATE] Pre-computing MISP event sizes...")
            event_sizes_query = """
            MATCH (i:Indicator)
            WHERE i.misp_event_id IS NOT NULL
            WITH i.misp_event_id AS eid, count(i) AS sz
            RETURN eid, sz
            """
            event_size_result = session.run(event_sizes_query, timeout=NEO4J_READ_TIMEOUT)
            event_sizes = {r["eid"]: r["sz"] for r in event_size_result}
            if event_sizes:
                min_sz = min(event_sizes.values())
                max_sz = max(event_sizes.values())
                avg_sz = sum(event_sizes.values()) / len(event_sizes)
                logger.info(
                    f"  [CALIBRATE] Pre-computed sizes for {len(event_sizes)} events "
                    f"(min={min_sz}, max={max_sz}, avg={avg_sz:.0f})"
                )
            else:
                logger.info("  [CALIBRATE] No events with indicators found — skipping calibration")
                return results

            # Step 2: For each tier, collect matching event IDs and update edges in chunks.
            for min_s, max_s, conf in tiers:
                tier_label = f"size {min_s}\u2013{max_s if max_s else '\u221e'} \u2192 conf={conf}"
                try:
                    tier_eids = [
                        eid for eid, sz in event_sizes.items() if sz >= min_s and (max_s is None or sz <= max_s)
                    ]
                    if not tier_eids:
                        logger.info(f"  [CALIBRATE] {tier_label}: 0 events in range — skipped")
                        results[tier_label] = 0
                        continue

                    update_cypher = """
                    UNWIND $eids AS eid
                    MATCH (i:Indicator {misp_event_id: eid})-[r:INDICATES|EXPLOITS]->(target)
                    WHERE r.source_id IN ["misp_cooccurrence", "misp_correlation"]
                    SET r.confidence_score = $conf,
                        r.calibrated_at = datetime()
                    RETURN count(r) AS updated
                    """
                    total_updated = 0
                    chunk_size = 500  # event IDs per chunk (not edges)
                    for ci in range(0, len(tier_eids), chunk_size):
                        chunk = tier_eids[ci : ci + chunk_size]
                        result = session.run(update_cypher, eids=chunk, conf=conf, timeout=NEO4J_READ_TIMEOUT)
                        record = result.single()
                        total_updated += record["updated"] if record else 0

                    results[tier_label] = total_updated
                    if total_updated:
                        logger.info(f"  [CALIBRATE] {tier_label}: {total_updated} edges ({len(tier_eids)} events)")
                except Exception as tier_err:
                    logger.error(f"  [CALIBRATE] {tier_label} FAILED: {tier_err}")
                    results[tier_label] = 0

    except Exception as e:
        logger.error(f"calibrate_cooccurrence_confidence error: {e}")

    total = sum(results.values())
    tier_summary = ", ".join(f"{k}: {v}" for k, v in results.items() if v > 0)
    logger.info(f"[CALIBRATE] Confidence calibration complete — {total} edges updated")
    if tier_summary:
        logger.info(f"[CALIBRATE] Tier breakdown: {tier_summary}")
    return results


# ---------------------------------------------------------------------------
# JOB 4: Vulnerability ↔ CVE REFERS_TO Bridge
# ---------------------------------------------------------------------------
# The ResilMesh data model defines bidirectional REFERS_TO relationships
# between Vulnerability and CVE nodes (neo4j_relationships_properties.csv).
# EdgeGuard writes both node types but populates cve_id on both sides —
# the relationship itself is not created during the per-item sync.
# This job closes the gap in a single idempotent Cypher pass.
# ---------------------------------------------------------------------------


def bridge_vulnerability_cve(neo4j_client) -> Dict:
    """
    Create bidirectional REFERS_TO relationships between Vulnerability and
    CVE nodes that share the same cve_id value.

    ResilMesh schema (neo4j_relationships_properties.csv):
        (Vulnerability)-[:REFERS_TO]->(CVE)
        (CVE)-[:REFERS_TO]->(Vulnerability)

    Both directions are MERGEd so the job is safe to run repeatedly.
    """
    results: Dict = {"linked": 0, "errors": 0}

    query = """
    CALL apoc.periodic.iterate(
        'MATCH (v:Vulnerability) WHERE v.cve_id IS NOT NULL RETURN v',
        'WITH $v AS v MATCH (c:CVE {cve_id: v.cve_id}) MERGE (v)-[:REFERS_TO]->(c) MERGE (c)-[:REFERS_TO]->(v)',
        {batchSize: 1000, parallel: false}
    )
    YIELD total
    RETURN total AS linked
    """

    try:
        with neo4j_client.driver.session() as session:
            record = session.run(query, timeout=NEO4J_READ_TIMEOUT).single()
            results["linked"] = record["linked"] if record else 0
        logger.info(f"[BRIDGE] Vulnerability↔CVE REFERS_TO: {results['linked']} pairs linked")
    except Exception as e:
        logger.warning(f"[BRIDGE] Vulnerability↔CVE bridge failed: {e}")
        results["errors"] += 1

    return results


# ---------------------------------------------------------------------------
# CONVENIENCE RUNNER
# ---------------------------------------------------------------------------


def run_all_enrichment_jobs(neo4j_client) -> Dict:
    """
    Run all four post-sync enrichment jobs in sequence.

    Returns a summary dict for logging/metrics.
    """
    summary = {}

    logger.info("=" * 55)
    logger.info("Running post-sync enrichment jobs")
    logger.info("=" * 55)

    logger.info("\n[1/4] IOC Confidence Decay...")
    summary["decay"] = decay_ioc_confidence(neo4j_client)

    logger.info("\n[2/4] Campaign Node Builder...")
    summary["campaigns"] = build_campaign_nodes(neo4j_client)

    logger.info("\n[3/4] Co-occurrence Confidence Calibration...")
    summary["calibration"] = calibrate_cooccurrence_confidence(neo4j_client)

    logger.info("\n[4/4] Vulnerability↔CVE REFERS_TO Bridge...")
    summary["bridge"] = bridge_vulnerability_cve(neo4j_client)

    logger.info("\n[DONE] All enrichment jobs complete")
    return summary


if __name__ == "__main__":
    from neo4j_client import Neo4jClient

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    client = Neo4jClient()
    client.connect()
    run_all_enrichment_jobs(client)
    client.close()
