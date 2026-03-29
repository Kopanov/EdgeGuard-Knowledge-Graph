#!/usr/bin/env python3
"""
EdgeGuard - Clear Neo4j Data Script

Clears all threat intelligence data from Neo4j while preserving:
- Source node definitions (recreate them)
- Schema (constraints and indexes)

Usage:
    python3 clear_neo4j.py [--dry-run] [--force]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import argparse
import logging
from typing import Dict

from neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)


EDGEGUARD_LABELS = [
    "Indicator",
    "Vulnerability",
    "Malware",
    "ThreatActor",
    "Technique",
    "Tactic",
    "Tool",
    "Campaign",
    "Sector",
    "Source",
    "CVE",
    "CVSSv2",
    "CVSSv30",
    "CVSSv31",
    "CVSSv40",
]


class Neo4jClearer:
    """
    Clears EdgeGuard threat intelligence data from Neo4j.

    Safe deletion:
    - By default deletes only nodes carrying EdgeGuard-managed labels
      (EDGEGUARD_LABELS) to avoid wiping other applications that share
      the same Neo4j instance.
    - Pass full_wipe=True to delete *all* nodes and relationships.
    - Optionally recreates Source nodes after clearing.
    - Preserves schema (constraints / indexes).
    """

    def __init__(self, client: Neo4jClient = None):
        self.client = client or Neo4jClient()

    def connect(self) -> bool:
        """Connect to Neo4j."""
        return self.client.connect()

    def get_counts(self, edgeguard_only: bool = True) -> Dict[str, int]:
        """
        Get current node counts by label.

        Args:
            edgeguard_only: When True (default) only counts EdgeGuard labels.

        Returns:
            Dict mapping label to count
        """
        counts = {}
        labels_to_count = EDGEGUARD_LABELS if edgeguard_only else []

        try:
            with self.client.driver.session() as session:
                if not labels_to_count:
                    result = session.run("CALL db.labels() YIELD label RETURN label")
                    labels_to_count = [record["label"] for record in result]

                for label in labels_to_count:
                    result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                    count = result.single()["count"]
                    counts[label] = count

        except Exception as e:
            logger.error(f"Error getting counts: {e}")

        return counts

    def get_relationship_counts(self) -> Dict[str, int]:
        """
        Get current relationship counts by type.

        Returns:
            Dict mapping relationship type to count
        """
        counts = {}

        try:
            with self.client.driver.session() as session:
                # Get all relationship types
                result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType")
                types = [record["relationshipType"] for record in result]

                # Count relationships for each type
                for rel_type in types:
                    result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) as count")
                    count = result.single()["count"]
                    counts[rel_type] = count

        except Exception as e:
            logger.error(f"Error getting relationship counts: {e}")

        return counts

    def clear_all(self, dry_run: bool = False, recreate_sources: bool = True, full_wipe: bool = False) -> Dict:
        """
        Clear EdgeGuard data from Neo4j.

        By default this is scoped to the labels defined in EDGEGUARD_LABELS so
        that other applications sharing the same Neo4j instance are not affected.
        Pass full_wipe=True only when you are certain no other data exists.

        Args:
            dry_run: If True, only show what would be deleted.
            recreate_sources: If True, recreate Source nodes after clearing.
            full_wipe: If True, delete ALL nodes and relationships (dangerous!).

        Returns:
            Dict with operation summary
        """
        logger.info("=" * 60)
        logger.info("[CLEAN] Neo4j Clear Operation")
        if full_wipe:
            logger.warning("[WARN]  full_wipe=True — ALL nodes and relationships will be removed")
        else:
            logger.info("Scoped to EdgeGuard labels: %s", ", ".join(EDGEGUARD_LABELS))
        logger.info("=" * 60)

        node_counts = self.get_counts(edgeguard_only=not full_wipe)
        rel_counts = self.get_relationship_counts() if full_wipe else {}

        total_nodes = sum(node_counts.values())
        total_rels = sum(rel_counts.values())

        if total_nodes == 0 and total_rels == 0:
            logger.info("No EdgeGuard data found in Neo4j")
            return {"success": True, "nodes_deleted": 0, "relationships_deleted": 0, "message": "Nothing to delete"}

        logger.info("\nNodes to delete:")
        for label, count in sorted(node_counts.items(), key=lambda x: -x[1]):
            if count > 0:
                logger.info(f"  - {label}: {count}")
        logger.info(f"  Total nodes: {total_nodes}")

        if rel_counts:
            logger.info("\nRelationships to delete:")
            for rel_type, count in sorted(rel_counts.items(), key=lambda x: -x[1]):
                if count > 0:
                    logger.info(f"  - {rel_type}: {count}")
            logger.info(f"  Total relationships: {total_rels}")

        if dry_run:
            logger.info(f"\n[SCAN] Dry run complete. Would delete {total_nodes} nodes and {total_rels} relationships.")
            return {
                "success": True,
                "nodes_deleted": 0,
                "relationships_deleted": 0,
                "would_delete_nodes": total_nodes,
                "would_delete_relationships": total_rels,
                "dry_run": True,
            }

        logger.info("\n[WARN]  Deleting data...")

        try:
            with self.client.driver.session() as session:
                if full_wipe:
                    session.run("MATCH ()-[r]->() DELETE r")
                    logger.info("  [OK] Deleted all relationships")
                    session.run("MATCH (n) DELETE n")
                    logger.info("  [OK] Deleted all nodes")
                else:
                    # Scoped: detach-delete only nodes that carry EdgeGuard labels.
                    # DETACH DELETE removes the node and all its relationships.
                    for label in EDGEGUARD_LABELS:
                        session.run(f"MATCH (n:{label}) DETACH DELETE n")
                    logger.info("  [OK] Deleted EdgeGuard-labelled nodes and their relationships")

        except Exception as e:
            logger.error(f"[ERR] Error during deletion: {e}")
            return {"success": False, "error": str(e)}

        if recreate_sources:
            logger.info("\n[INFO] Recreating Source nodes...")
            self.client.ensure_sources()

        logger.info("\n" + "=" * 60)
        logger.info("[OK] Neo4j Clear Complete")
        logger.info("=" * 60)
        logger.info(f"Deleted: {total_nodes} nodes")
        if recreate_sources:
            logger.info("Source nodes have been recreated")

        return {"success": True, "nodes_deleted": total_nodes, "relationships_deleted": total_rels}

    def clear_by_label(self, label: str, dry_run: bool = False) -> Dict:
        """
        Clear all nodes with a specific label.

        Args:
            label: Node label to clear
            dry_run: If True, only show what would be deleted

        Returns:
            Dict with operation summary
        """
        logger.info(f"\n[CLEAN] Clearing {label} nodes...")

        try:
            with self.client.driver.session() as session:
                # Get count
                result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                count = result.single()["count"]

                if count == 0:
                    logger.info(f"  No {label} nodes to delete")
                    return {"success": True, "deleted": 0}

                logger.info(f"  Found {count} {label} nodes")

                if dry_run:
                    logger.info(f"  [SCAN] Dry run: would delete {count} nodes")
                    return {"success": True, "deleted": 0, "would_delete": count, "dry_run": True}

                # Delete nodes and their relationships
                session.run(f"MATCH (n:{label}) DETACH DELETE n")
                logger.info(f"  [OK] Deleted {count} {label} nodes")

                return {"success": True, "deleted": count}

        except Exception as e:
            logger.error(f"[ERR] Error clearing {label}: {e}")
            return {"success": False, "error": str(e)}

    def close(self):
        """Close Neo4j connection."""
        self.client.close()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Clear threat intelligence data from Neo4j",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 clear_neo4j.py --dry-run          # Preview what would be deleted
  python3 clear_neo4j.py --force            # Delete all data
  python3 clear_neo4j.py --label Indicator  # Delete only Indicator nodes
        """,
    )
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show what would be deleted without deleting")
    parser.add_argument("--force", "-f", action="store_true", help="Skip confirmation and delete immediately")
    parser.add_argument("--label", "-l", type=str, help="Delete only nodes with this label")
    parser.add_argument("--no-recreate", action="store_true", help="Do not recreate Source nodes after clearing")
    parser.add_argument(
        "--full-wipe",
        action="store_true",
        help="Delete ALL nodes/relationships, not just EdgeGuard-labelled ones (dangerous!)",
    )

    args = parser.parse_args()

    # Require explicit action
    if not args.dry_run and not args.force and not args.label:
        parser.print_help()
        print("\n⚠️  No action specified. Use --dry-run to preview, --force to delete, or --label for specific nodes.")
        sys.exit(1)

    # Connect to Neo4j
    clearer = Neo4jClearer()

    if not clearer.connect():
        logger.error("Failed to connect to Neo4j. Exiting.")
        sys.exit(1)

    try:
        if args.label:
            result = clearer.clear_by_label(args.label, dry_run=args.dry_run)
        else:
            result = clearer.clear_all(
                dry_run=args.dry_run, recreate_sources=not args.no_recreate, full_wipe=args.full_wipe
            )

        # Clear checkpoint file so MITRE ETag and other cursors are reset
        if result.get("success") and not args.dry_run:
            try:
                from baseline_checkpoint import clear_checkpoint

                clear_checkpoint(include_incremental=True)
                logging.getLogger(__name__).info("Cleared baseline checkpoint + incremental cursors (full reset)")
            except Exception as e:
                logging.getLogger(__name__).warning("Could not clear checkpoint: %s", e)

        # Exit with appropriate code
        if result.get("success"):
            sys.exit(0)
        else:
            sys.exit(1)

    finally:
        clearer.close()


if __name__ == "__main__":
    main()
