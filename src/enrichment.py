#!/usr/bin/env python3
"""
EdgeGuard - Enrichment Module
Enriches existing indicators by querying multiple sources
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import re

from collectors.virustotal_collector import VirusTotalCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnrichmentEngine:
    """
    Enriches indicators by querying multiple sources.

    Approach A: Feed Collection (current)
    - Pull data from feeds periodically
    - Each source has different indicators

    Approach B: Enrichment (this module)
    - Take existing indicator
    - Query multiple sources for same indicator
    - Get different perspectives on same data
    """

    def __init__(self, neo4j_client):
        self.neo4j = neo4j_client
        self.vt_collector = VirusTotalCollector()

    def enrich_all_indicators(self, limit=100):
        """
        Enrich existing indicators from Neo4j.

        For each indicator, query external sources and merge results.
        """
        enriched_count = 0

        with self.neo4j.driver.session() as session:
            # Get indicators that could benefit from enrichment
            # (those with lower confidence or from fewer sources)
            result = session.run(
                """
                MATCH (i:Indicator)
                WHERE i.confidence_score < 0.8 OR size(coalesce(i.source, [])) < 2
                RETURN i.value as value, i.indicator_type as type, i.source as current_source
                LIMIT $limit
            """,
                limit=limit,
            )

            indicators = list(result)
            logger.info(f"[TARGET] Enriching {len(indicators)} indicators...")

            for ind in indicators:
                try:
                    result = self.enrich_indicator(ind["value"], ind["type"])
                    if result:
                        # Merge the enriched data
                        self.neo4j.merge_indicator(result, source_id="virustotal")
                        enriched_count += 1

                except Exception as e:
                    logger.warning(f"Enrichment error for {ind['value']}: {e}")

        logger.info(f"[OK] Enriched {enriched_count} indicators")
        return enriched_count

    def enrich_indicator(self, value, indicator_type=None):
        """
        Enrich a single indicator from VirusTotal.

        Returns data dict or None if not found.
        """
        # Determine type if not provided
        if not indicator_type:
            indicator_type = self._guess_type(value)

        # Query VirusTotal
        if indicator_type == "domain":
            return self.vt_collector.query_domain(value)
        elif indicator_type == "ipv4":
            return self.vt_collector.query_ip(value)
        elif indicator_type in ["hash", "sha256", "md5"]:
            return self.vt_collector.query_hash(value)

        return None

    def _guess_type(self, value):
        """Guess indicator type from value"""

        # IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            return "ipv4"

        # Domain
        if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]+\.[a-zA-Z]{2,}", value):
            return "domain"

        # Hash (32, 64, or 128 chars)
        if re.match(r"^[a-fA-F0-9]{32}$", value):
            return "md5"
        if re.match(r"^[a-fA-F0-9]{64}$", value):
            return "sha256"

        return "unknown"

    def enrich_from_multiple_sources(self, value):
        """
        A/B Test: Get same indicator from multiple sources

        Returns dict with results from each source for comparison.
        """
        results = {}

        # Try VirusTotal
        vt_result = self.enrich_indicator(value)
        if vt_result:
            results["virustotal"] = vt_result

        # Could add more sources here:
        # - AlienVault OTX lookup
        # - AbuseIPDB lookup
        # - Hybrid Analysis

        return results


def run_enrichment(neo4j_client, limit=100):
    """Run enrichment on Neo4j data"""
    engine = EnrichmentEngine(neo4j_client)
    return engine.enrich_all_indicators(limit)


if __name__ == "__main__":
    from neo4j_client import Neo4jClient

    client = Neo4jClient()
    client.connect()

    count = run_enrichment(client, limit=10)
    print(f"\nEnriched {count} indicators")

    client.close()
