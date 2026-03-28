#!/usr/bin/env python3
"""
EdgeGuard - Standalone Enrichment Test
Run this separately to test enrichment with VirusTotal

Usage:
    python3 test_enrichment.py
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import time

from collectors.virustotal_collector import VirusTotalCollector
from neo4j_client import Neo4jClient


def test_enrichment():
    """Enrich a few indicators manually to test merge behavior"""

    client = Neo4jClient()
    client.connect()

    vt = VirusTotalCollector()

    # Get some indicators to enrich
    with client.driver.session() as session:
        result = session.run("""
            MATCH (i:Indicator)
            WHERE i.indicator_type IN ['domain', 'ipv4']
            RETURN i.value as value, i.indicator_type as type, i.source as source
            LIMIT 10
        """)

        indicators = list(result)

    print(f"=== Enriching {len(indicators)} Indicators ===\n")

    enriched = 0
    for ind in indicators:
        value = ind["value"]
        ind_type = ind["type"]

        print(f"Enriching: {value} ({ind_type})")

        # Query VirusTotal
        if ind_type == "domain":
            result = vt.query_domain(value)
        elif ind_type == "ipv4":
            result = vt.query_ip(value)
        else:
            result = None

        if result:
            # Merge with source tracking (creates edge with raw data)
            client.merge_indicator(result, source_id="virustotal")

            stats = result.get("vt_stats", {})
            print(f"  ✅ VT: {stats.get('malicious', 0)} malicious, conf: {result['confidence_score']:.2f}")
            enriched += 1
        else:
            print("  ❌ Not found in VT")

        # Rate limiting
        time.sleep(16)  # 4 requests/min

        if enriched >= 3:  # Just test 3 for now
            print("\n=== Test complete (limiting to 3 for now) ===")
            break

    # Show results
    print("\n=== MERGE RESULTS ===")
    for ind in indicators[:enriched]:
        value = ind["value"]

        # Get the merged result
        with client.driver.session() as session:
            r = session.run(
                """
                MATCH (i:Indicator {value: $value})-[r:SOURCED_FROM]->(s:Source)
                RETURN s.source_id as source, r.confidence as edge_conf
            """,
                value=value,
            )

            sources = list(r)
            print(f"\n{value}:")
            for s in sources:
                print(f"  - {s['source']}: confidence={s['edge_conf']}")

            # Get primary source
            r2 = session.run(
                """
                MATCH (i:Indicator {value: $value})
                RETURN i.source as primary, i.confidence_score as node_conf, i.sources as all_sources
            """,
                value=value,
            ).single()

            print(f"  Primary: {r2['primary']} (conf: {r2['node_conf']})")
            print(f"  All sources: {r2['all_sources']}")

    client.close()
    return enriched


if __name__ == "__main__":
    count = test_enrichment()
    print(f"\n✅ Enriched {count} indicators")
