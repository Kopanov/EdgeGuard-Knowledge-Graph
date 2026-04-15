#!/usr/bin/env python3
"""
EdgeGuard - Main Pipeline Runner (MISP Single Point of Truth)

Orchestrates collection from sources → MISP → Neo4j

Usage:
    python3 run_pipeline_misp_spt.py [--skip-misp] [--skip-neo4j] [--sources otx,nvd,cisa,mitre]
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import logging
from datetime import datetime, timezone
from typing import Dict, List

from collectors.cisa_collector import CISACollector

# Import MISP writer and health check
from collectors.misp_writer import MISPWriter
from collectors.mitre_collector import MITRECollector
from collectors.nvd_collector import NVDCollector

# Import collectors
from collectors.otx_collector import OTXCollector
from config import MAX_ENTRIES_PER_SOURCE
from misp_health import MISPHealthCheck

# Import Neo4j sync
from run_misp_to_neo4j import MISPToNeo4jSync

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class EdgeGuardPipelineMISPSPT:
    """
    EdgeGuard Pipeline with MISP as Single Point of Truth.

    Phase 1: Collect from sources → Push to MISP
    Phase 2: Sync MISP → Neo4j
    """

    def __init__(self):
        self.misp_writer = MISPWriter()
        self.health_checker = MISPHealthCheck()
        self.collectors = {
            "otx": OTXCollector(self.misp_writer),
            "nvd": NVDCollector(self.misp_writer),
            "cisa": CISACollector(self.misp_writer),
            "mitre": MITRECollector(self.misp_writer),
        }
        self.mitre_collector = self.collectors["mitre"]

    def check_misp_health(self, require_workers: bool = False) -> bool:
        """Check if MISP is healthy before proceeding.

        Args:
            require_workers: If True, require workers to be healthy. If False (default),
                           consider healthy if API and DB are up.
        """
        logger.info("\n" + "=" * 60)
        logger.info("[SCAN] Checking MISP Health")
        logger.info("=" * 60)

        result = self.health_checker.check_health()

        logger.info(f"MISP Status: {result['status'].upper()}")
        logger.info(f"  API Connectivity: {'[OK]' if result['checks']['api_connectivity'] else '[ERR]'}")
        logger.info(f"  Database: {'[OK]' if result['checks']['database'] else '[ERR]'}")

        workers_ok = result["checks"]["worker_status"]
        if require_workers:
            logger.info(f"  Workers: {'[OK]' if workers_ok else '[ERR]'}")
        else:
            logger.info(f"  Workers: {'[OK]' if workers_ok else '[WARN] (skipped)'}")

        if result["details"]["version"]:
            logger.info(f"  Version: {result['details']['version']}")

        if result["details"]["issues"]:
            for issue in result["details"]["issues"]:
                logger.warning(f"  [WARN]  {issue}")

        if require_workers:
            return bool(result.get("healthy_for_collection", False) and result["checks"].get("worker_status", False))
        return bool(result.get("healthy_for_collection", False))

    def run_phase1_collect_to_misp(self, sources: List[str] = None, limit: int = None) -> Dict:
        """
        Phase 1: Collect from sources and push to MISP.

        Args:
            sources: List of source names to collect from (default: all)
            limit: Max items per source

        Returns:
            Dict with collection results
        """
        # Do not use `limit or MAX_ENTRIES_PER_SOURCE`: when MAX is 0 (unset / use
        # get_effective_limit), `None or 0` would become 0 and cap every collect at 0 items.
        if limit is None and MAX_ENTRIES_PER_SOURCE != 0:
            limit = MAX_ENTRIES_PER_SOURCE
        sources = sources or list(self.collectors.keys())

        logger.info("\n" + "=" * 60)
        logger.info("[FETCH] Phase 1: Collect Sources → Push to MISP")
        logger.info("=" * 60)

        results = {}
        total_success = 0
        total_failed = 0

        for source_name in sources:
            if source_name not in self.collectors:
                logger.warning(f"Unknown source: {source_name}")
                continue

            collector = self.collectors[source_name]

            try:
                logger.info(f"\n🔄 Collecting from {source_name}...")
                result = collector.collect(limit=limit, push_to_misp=True)
                results[source_name] = result

                if isinstance(result, dict):
                    if result.get("success"):
                        success_count = result.get("count", 0)
                        failed_count = result.get("failed", 0)
                        total_success += success_count
                        total_failed += failed_count
                        logger.info(f"[OK] {source_name}: {success_count} items pushed to MISP")
                    else:
                        logger.error(f"[ERR] {source_name}: {result.get('error', 'Unknown error')}")

            except Exception as e:
                logger.error(f"[ERR] {source_name}: Collection failed - {e}")
                results[source_name] = {"success": False, "error": str(e)}

        logger.info("\n" + "=" * 60)
        logger.info("[STATS] Phase 1 Summary")
        logger.info("=" * 60)
        logger.info(f"Total items pushed to MISP: {total_success}")
        logger.info(f"Failed: {total_failed}")

        return {
            "success": total_success > 0,
            "total_pushed": total_success,
            "total_failed": total_failed,
            "sources": results,
        }

    def run_phase2_misp_to_neo4j(self, incremental: bool = True) -> Dict:
        """
        Phase 2: Sync MISP to Neo4j.

        Args:
            incremental: If True, only sync recent data

        Returns:
            Dict with sync results
        """
        logger.info("\n" + "=" * 60)
        logger.info("🔄 Phase 2: MISP → Neo4j Sync")
        logger.info("=" * 60)

        sync = MISPToNeo4jSync()
        success = sync.run(incremental=incremental)

        stats = sync.get_stats()

        logger.info("\n[STATS] Phase 2 Summary")
        logger.info(f"Events processed: {stats['events_processed']}")
        logger.info(f"Indicators synced: {stats['indicators_synced']}")
        logger.info(f"Vulnerabilities synced: {stats['vulnerabilities_synced']}")
        logger.info(f"Malware synced: {stats['malware_synced']}")
        logger.info(f"Actors synced: {stats['actors_synced']}")
        logger.info(f"Techniques synced: {stats['techniques_synced']}")

        # Create relationships from MITRE data
        self._create_mitre_relationships()

        return {"success": success, "stats": stats}

    def _create_mitre_relationships(self):
        """Create MITRE ATT&CK relationships in Neo4j."""
        logger.info("\n[LINK] Creating MITRE ATT&CK relationships...")

        relationships = self.mitre_collector.get_relationships()
        logger.info(f"   Found {len(relationships)} relationships")

        # Import neo4j client for relationship creation
        from neo4j_client import Neo4jClient

        neo4j = Neo4jClient()
        if not neo4j.connect():
            logger.error("   Failed to connect to Neo4j for relationships")
            return

        try:
            rel_stats = {"uses": 0, "attributed_to": 0}

            for rel in relationships[:500]:  # Limit to prevent timeout
                try:
                    if rel["type"] == "uses":
                        # Post-2026-04 specialization: create_actor_technique_relationship
                        # writes EMPLOYS_TECHNIQUE matching only ThreatActor
                        # nodes. A malware source_type here would silently
                        # create nothing (or worse, attach to a ThreatActor
                        # that happens to share the malware's name). Malware
                        # → Technique edges are built post-sync by
                        # build_relationships.py from the uses_techniques
                        # property, so we simply skip them here instead of
                        # writing the wrong edge.
                        if rel["source_type"] == "actor" and rel["target_type"] == "technique":
                            neo4j.create_actor_technique_relationship(rel["source_name"], rel["target_mitre_id"])
                            rel_stats["uses"] += 1
                    elif rel["type"] == "attributed_to":
                        if rel["source_type"] == "malware" and rel["target_type"] == "actor":
                            neo4j.create_malware_actor_relationship(rel["source_name"], rel["target_name"])
                            rel_stats["attributed_to"] += 1
                except Exception:
                    pass  # Skip failed relationships

            logger.info(f"   [OK] Created {rel_stats['uses']} EMPLOYS_TECHNIQUE relationships (Actor→Technique)")
            logger.info(f"   [OK] Created {rel_stats['attributed_to']} ATTRIBUTED_TO relationships")

        finally:
            neo4j.close()

    def run(
        self, sources: List[str] = None, skip_misp: bool = False, skip_neo4j: bool = False, limit: int = None
    ) -> bool:
        """
        Run the complete MISP SPT pipeline.

        Args:
            sources: List of source names to collect from
            skip_misp: If True, skip Phase 1 (MISP collection)
            skip_neo4j: If True, skip Phase 2 (Neo4j sync)
            limit: Max items per source

        Returns:
            True if pipeline succeeded, False otherwise
        """
        start_time = datetime.now(timezone.utc)

        logger.info("\n" + "=" * 60)
        logger.info("[START] EdgeGuard Pipeline Started (MISP Single Point of Truth)")
        logger.info("=" * 60)

        # Check MISP health first
        if not skip_misp:
            if not self.check_misp_health():
                logger.error("[ERR] MISP health check failed. Aborting.")
                return False

        # Phase 1: Collect to MISP
        phase1_result = None
        if not skip_misp:
            phase1_result = self.run_phase1_collect_to_misp(sources=sources, limit=limit)
            if not phase1_result["success"]:
                logger.warning("[WARN]  Phase 1 completed with errors")

        # Phase 2: Sync to Neo4j
        phase2_result = None
        if not skip_neo4j:
            phase2_result = self.run_phase2_misp_to_neo4j(incremental=True)

        # Final summary
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        logger.info("\n" + "=" * 60)
        logger.info("[OK] EdgeGuard Pipeline Complete!")
        logger.info("=" * 60)
        logger.info(f"⏱️  Total time: {elapsed:.1f} seconds")

        if phase1_result:
            logger.info(f"[STATS] Phase 1 (MISP): {phase1_result['total_pushed']} items pushed")

        if phase2_result:
            stats = phase2_result.get("stats", {})
            total_synced = (
                stats.get("indicators_synced", 0)
                + stats.get("vulnerabilities_synced", 0)
                + stats.get("malware_synced", 0)
                + stats.get("actors_synced", 0)
                + stats.get("techniques_synced", 0)
            )
            logger.info(f"[STATS] Phase 2 (Neo4j): {total_synced} items synced")

        logger.info("\n[NET] Neo4j Browser: http://localhost:7474")
        logger.info("   User: neo4j / $NEO4J_PASSWORD (from .env)")
        logger.info(f"[NET] MISP: {self.misp_writer.url}")

        return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="EdgeGuard Pipeline (MISP Single Point of Truth)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_pipeline_misp_spt.py                    # Run full pipeline
  python3 run_pipeline_misp_spt.py --sources otx,cisa # Run only OTX and CISA
  python3 run_pipeline_misp_spt.py --skip-neo4j       # Only collect to MISP
  python3 run_pipeline_misp_spt.py --skip-misp        # Only sync MISP to Neo4j
  python3 run_pipeline_misp_spt.py --limit 50         # Limit items per source
        """,
    )
    parser.add_argument("--sources", "-s", type=str, help="Comma-separated list of sources (otx,nvd,cisa,mitre)")
    parser.add_argument("--skip-misp", action="store_true", help="Skip Phase 1 (collection to MISP)")
    parser.add_argument("--skip-neo4j", action="store_true", help="Skip Phase 2 (MISP to Neo4j sync)")
    parser.add_argument("--limit", "-l", type=int, help="Limit items per source")

    args = parser.parse_args()

    # Parse sources
    sources = None
    if args.sources:
        sources = [s.strip() for s in args.sources.split(",")]

    # Validate
    if args.skip_misp and args.skip_neo4j:
        parser.error("Cannot skip both MISP and Neo4j phases")

    # Run pipeline
    pipeline = EdgeGuardPipelineMISPSPT()
    success = pipeline.run(sources=sources, skip_misp=args.skip_misp, skip_neo4j=args.skip_neo4j, limit=args.limit)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
