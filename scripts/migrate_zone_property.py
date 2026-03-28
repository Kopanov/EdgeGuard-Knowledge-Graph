#!/usr/bin/env python3
"""
One-time migration script to normalize the `zone` property on all nodes.

Goal:
- Ensure `zone` is ALWAYS stored as a list of strings (e.g. ['finance', 'global'])
- Convert any legacy scalar `zone` values (e.g. 'finance') into single-element lists

Why:
- Queries assume `zone` is a list and use `$zone IN n.zone`
- Mixed types (string vs list) make Cypher predicates unreliable

Usage:
    python migrate_zone_property.py

Run this against your graph once after upgrading EdgeGuard to the
STIX-aligned zone semantics.
"""

import logging
import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import Neo4jClient  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def migrate_zone_to_list():
    client = Neo4jClient()
    if not client.connect():
        logger.error("Failed to connect to Neo4j")
        return False

    try:
        logger.info("Normalizing `zone` property on all nodes to be a list...")
        cypher = """
        MATCH (n)
        WHERE exists(n.zone) AND NOT n.zone IS NULL
        WITH n, n.zone AS z
        WHERE NOT (z IS LIST)
        SET n.zone = [z]
        RETURN count(n) AS updated
        """
        result = client.run(cypher)
        updated = result[0]["updated"] if result else 0
        logger.info("Updated %d nodes to have list-based `zone` property", updated)
        client.close()
        return True
    except Exception as e:
        logger.error("Zone migration failed: %s", e)
        client.close()
        return False


if __name__ == "__main__":
    ok = migrate_zone_to_list()
    sys.exit(0 if ok else 1)
