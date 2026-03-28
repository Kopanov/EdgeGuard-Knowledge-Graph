#!/usr/bin/env python3
"""
EdgeGuard - ResilMesh Alert Processor
Processes incoming alerts from ResilMesh and returns enriched threat intelligence.

This module aligns EdgeGuard's Neo4j schema with ResilMesh alert format:
- Receives alerts on NATS topics: resilmesh.alerts.zone.<zone_id>
- Queries Neo4j for enrichment data
- Returns enriched responses on: resilmesh.enriched.alerts
"""

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import Neo4jClient
from package_meta import package_version

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ResilMeshAlert:
    """
    ResilMesh Alert Schema (as defined in mock_resilmesh_publisher.py)

    {
      "alert_id": "wazuh-001",
      "source": "wazuh",
      "zone": "healthcare",
      "timestamp": "...",
      "tags": ["healthcare", "finance"],  # Optional, for multi-zone
      "threat": {
        "indicator": "192.168.1.100",
        "type": "ip",                    # ip, domain, file_hash
        "malware": "TrickBot",
        "cve": "CVE-2021-43297",
        "description": "...",
        "severity": 9,                     # 1-10 scale
        "source_ip": "192.168.1.100",
        "dest_ip": "185.220.101.45",
        "hostname": "hospital-server-01",
        "user": "admin",
        # Zone-specific fields:
        "device_type": "MRI Scanner",      # healthcare
        "protocol": "IEC61850",            # energy
        "transaction_id": "TXN-001",       # finance
        "affected_files": 15000,           # ransomware
      }
    }
    """

    alert_id: str
    source: str
    zone: str
    timestamp: str
    threat: Dict[str, Any]
    tags: Optional[List[str]] = None

    @classmethod
    def from_dict(cls, data: Dict) -> "ResilMeshAlert":
        """Parse ResilMesh alert from dict"""
        return cls(
            alert_id=data.get("alert_id", "unknown"),
            source=data.get("source", "unknown"),
            zone=data.get("zone", "global"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            threat=data.get("threat", {}),
            tags=data.get("tags"),
        )


@dataclass
class EnrichedAlert:
    """
    EdgeGuard Enriched Response Schema

    {
      "alert_id": "wazuh-001",
      "enriched": true,
      "edgeguard_version": "<CalVer from pyproject.toml>",
      "latency_ms": 120,
      "query_metadata": {
        "indicator_found": true,
        "malware_found": true,
        "actor_found": true,
        "techniques_found": 3
      },
      "enrichment": {
        "indicator": "192.168.1.100",
        "indicator_type": "ip",
        "known_malware": ["TrickBot", "Emotet"],
        "threat_actors": ["Wizard Spider"],
        "techniques": [
          {
            "mitre_id": "T1071",
            "name": "Application Layer Protocol",
            "tactic": "Command and Control"
          }
        ],
        "cves": ["CVE-2021-43297"],
        "confidence": 0.85,
        "first_seen": "2025-01-15",
        "last_updated": "2026-03-07",
        "sectors_affected": ["healthcare", "finance"],
        "cross_zone_detected": true,
        "recommendations": [
          "Block indicator 192.168.1.100 at perimeter",
          "Check hospital-server-01 for compromise indicators"
        ]
      },
      "original_alert": { ... }  # Copy of incoming alert
    }
    """

    alert_id: str
    enriched: bool
    edgeguard_version: str
    latency_ms: float
    query_metadata: Dict[str, Any]
    enrichment: Dict[str, Any]
    original_alert: Dict[str, Any]

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class AlertProcessor:
    """
    Processes ResilMesh alerts and returns enriched threat intelligence.

    Schema Alignment:
    -----------------
    ResilMesh sends:
      - alert_id, source, zone, timestamp
      - threat.indicator (IP/domain/hash)
      - threat.type (ip|domain|file_hash)
      - threat.malware, threat.cve
      - Network context: source_ip, dest_ip, hostname
      - User context: user
      - Asset context: hostname, device_type
      - Multi-zone: tags array

    EdgeGuard stores (Full ResilMesh Schema):
      - Alert nodes (individual security events)
      - Indicator nodes (IP, Domain, Hash)
      - Asset nodes (hostname, device_type)
      - User nodes (username, domain)
      - NetworkContext nodes (source/dest IP pairs)
      - Zone nodes (for cross-zone tracking)
      - Malware nodes
      - ThreatActor nodes
      - Technique nodes (MITRE ATT&CK)
      - Vulnerability nodes (CVE)

    Relationships:
      - (Alert)-[:INVOLVES]->(Indicator)
      - (Alert)-[:TARGETS]->(Asset)
      - (Alert)-[:INVOLVES_USER]->(User)
      - (Alert)-[:HAS_CONTEXT]->(NetworkContext)
      - (Alert)-[:AFFECTS]->(Zone)
      - (Asset)-[:LOCATED_IN]->(Zone)
      - (Asset)-[:HAS_IP]->(Indicator)
      - (Indicator)-[:ATTRIBUTED_TO]->(Malware)
      - (Malware)-[:ATTRIBUTED_TO]->(ThreatActor)
      - (ThreatActor)-[:USES]->(Technique)
      - (Indicator)-[:INDICATES]->(Vulnerability)
    """

    VERSION = package_version()

    def __init__(self, neo4j_client: Optional[Neo4jClient] = None):
        self.neo4j = neo4j_client or Neo4jClient()
        self._connected = False

    def connect(self) -> bool:
        """Connect to Neo4j"""
        if not self._connected:
            self._connected = self.neo4j.connect()
        return self._connected

    def process_alert(self, alert_data: Dict) -> EnrichedAlert:
        """
        Main entry point: Process a ResilMesh alert and return enrichment.

        This method:
        1. Creates/updates all nodes (Alert, Indicator, Asset, User, NetworkContext, Zone)
        2. Creates all relationships between nodes
        3. Performs enrichment queries
        4. Updates the Alert with enrichment results
        5. Returns the enriched alert response

        Args:
            alert_data: Raw alert JSON from ResilMesh

        Returns:
            EnrichedAlert with full threat intelligence
        """
        start_time = datetime.now(timezone.utc)

        # Parse alert
        alert = ResilMeshAlert.from_dict(alert_data)
        logger.info(f"🚨 Processing alert: {alert.alert_id} (zone: {alert.zone})")

        # Ensure connection
        if not self.connect():
            logger.error("[ERR] Cannot process alert - Neo4j not connected")
            return self._create_error_response(alert, "Neo4j connection failed")

        # Step 1-7: Process complete ResilMesh alert (create all nodes and relationships)
        self.neo4j.process_complete_resilmesh_alert(alert_data)

        # Extract indicator from threat
        indicator = alert.threat.get("indicator")
        indicator_type = alert.threat.get("type", "unknown")

        if not indicator:
            return self._create_error_response(alert, "No indicator in alert")

        # Step 8: Query Neo4j for enrichment
        enrichment_data = self._enrich_indicator(indicator, indicator_type, alert)

        # Calculate latency
        latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        # Step 9: Update Alert with enrichment status
        self.neo4j.update_alert_enrichment_status(
            alert_id=alert.alert_id, enrichment_data=enrichment_data, latency_ms=latency_ms
        )

        # Build response
        return EnrichedAlert(
            alert_id=alert.alert_id,
            enriched=True,
            edgeguard_version=self.VERSION,
            latency_ms=round(latency_ms, 2),
            query_metadata=enrichment_data["metadata"],
            enrichment=enrichment_data["enrichment"],
            original_alert=alert_data,
        )

    def _enrich_indicator(self, indicator: str, indicator_type: str, alert: ResilMeshAlert) -> Dict:
        """
        Query Neo4j to enrich an indicator.

        Query strategy:
        1. Find the Indicator node
        2. Find related Malware (via ATTRIBUTED_TO)
        3. Find related ThreatActors (via USES from Malware)
        4. Find Techniques (via USES from Actor)
        5. Find CVEs (if mentioned in alert or linked to indicator)
        6. Find related Assets and Users from Alert context
        """
        enrichment = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "known_malware": [],
            "threat_actors": [],
            "techniques": [],
            "cves": [],
            "assets": [],
            "users": [],
            "confidence": 0.0,
            "first_seen": None,
            "last_updated": None,
            "sectors_affected": [alert.zone],
            "cross_zone_detected": False,
            "recommendations": [],
        }

        metadata = {
            "indicator_found": False,
            "malware_found": False,
            "actor_found": False,
            "techniques_found": 0,
            "cves_found": 0,
            "assets_found": 0,
            "users_found": 0,
        }

        try:
            with self.neo4j.driver.session() as session:
                # Query 1: Find indicator and direct properties
                indicator_result = session.run(
                    """
                    MATCH (i:Indicator {value: $indicator})
                    RETURN i {
                        .value, .indicator_type, .zone, .source,
                        .confidence_score, .first_seen, .last_updated
                    } as indicator
                """,
                    indicator=indicator,
                )

                indicator_record = indicator_result.single()
                if indicator_record:
                    ind_data = indicator_record["indicator"]
                    metadata["indicator_found"] = True
                    enrichment["confidence"] = ind_data.get("confidence_score", 0.0)
                    enrichment["first_seen"] = ind_data.get("first_seen")
                    enrichment["last_updated"] = ind_data.get("last_updated")

                    # Add zone from indicator if different from alert
                    ind_zone = ind_data.get("zone")
                    if ind_zone and ind_zone not in enrichment["sectors_affected"]:
                        enrichment["sectors_affected"].append(ind_zone)

                # Query 2: Find malware via ATTRIBUTED_TO relationship
                # Also check if malware name matches the one in the alert
                alert_malware = alert.threat.get("malware")

                malware_result = session.run(
                    """
                    MATCH (i:Indicator {value: $indicator})
                    OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(m:Malware)
                    RETURN collect(DISTINCT m {
                        .name, .family, .malware_types, .description
                    }) as malware_list
                """,
                    indicator=indicator,
                )

                malware_record = malware_result.single()
                if malware_record:
                    malware_list = [m for m in malware_record["malware_list"] if m]

                    # Add alert malware if provided but not in graph
                    if alert_malware and not any(m.get("name") == alert_malware for m in malware_list):
                        malware_list.append(
                            {
                                "name": alert_malware,
                                "family": None,
                                "malware_types": [],
                                "description": "From alert (not in graph)",
                            }
                        )

                    enrichment["known_malware"] = malware_list
                    metadata["malware_found"] = len(malware_list) > 0

                # Query 3: Find threat actors via malware
                actors_result = session.run(
                    """
                    MATCH (i:Indicator {value: $indicator})
                    OPTIONAL MATCH (i)-[:ATTRIBUTED_TO]->(m:Malware)
                    OPTIONAL MATCH (m)-[:ATTRIBUTED_TO]->(a:ThreatActor)
                    OPTIONAL MATCH (a)-[:USES]->(t:Technique)
                    RETURN collect(DISTINCT a {
                        .name, .aliases, .description
                    }) as actors,
                    collect(DISTINCT t {
                        .mitre_id, .name, .description
                    }) as techniques
                """,
                    indicator=indicator,
                )

                actors_record = actors_result.single()
                if actors_record:
                    actors = [a for a in actors_record["actors"] if a]
                    techniques = [t for t in actors_record["techniques"] if t]

                    enrichment["threat_actors"] = actors
                    enrichment["techniques"] = techniques
                    metadata["actor_found"] = len(actors) > 0
                    metadata["techniques_found"] = len(techniques)

                # Query 4: Find CVEs
                # First check if alert mentions a CVE
                alert_cve = alert.threat.get("cve")
                cves = []

                if alert_cve:
                    cves.append({"cve_id": alert_cve, "source": "alert"})

                # Also query for CVEs linked to this indicator
                cve_result = session.run(
                    """
                    MATCH (i:Indicator {value: $indicator})
                    OPTIONAL MATCH (i)-[:INDICATES]->(v:Vulnerability)
                    RETURN collect(DISTINCT v {
                        .cve_id, .cvss_score, .severity
                    }) as cves
                """,
                    indicator=indicator,
                )

                cve_record = cve_result.single()
                if cve_record:
                    db_cves = [v for v in cve_record["cves"] if v]
                    # Merge alert CVE with DB CVEs
                    db_cve_ids = {c["cve_id"] for c in cves if c.get("cve_id")}
                    for cve in db_cves:
                        if cve.get("cve_id") not in db_cve_ids:
                            cves.append(cve)

                enrichment["cves"] = cves
                metadata["cves_found"] = len(cves)

                # Query 5: Find related Assets and Users from Alert
                context_result = session.run(
                    """
                    MATCH (a:Alert)-[:TARGETS]->(asset:Asset)
                    MATCH (a:Alert)-[:INVOLVES_USER]->(u:User)
                    RETURN collect(DISTINCT asset {
                        .hostname, .asset_type, .device_type, .zone
                    }) as assets,
                    collect(DISTINCT u {
                        .username, .domain
                    }) as users
                """,
                    alert_id=alert.alert_id,
                )

                context_record = context_result.single()
                if context_record:
                    assets = [asset for asset in context_record["assets"] if asset]
                    users = [u for u in context_record["users"] if u]
                    enrichment["assets"] = assets
                    enrichment["users"] = users
                    metadata["assets_found"] = len(assets)
                    metadata["users_found"] = len(users)

                # Query 6: Multi-zone detection
                # Check if indicator affects multiple zones
                zones_result = session.run(
                    """
                    MATCH (i:Indicator {value: $indicator})
                    RETURN i.zone as zone
                """,
                    indicator=indicator,
                )

                zones_record = zones_result.single()
                if zones_record:
                    zone = zones_record["zone"]
                    if zone:
                        # zone is now an array
                        if isinstance(zone, list):
                            enrichment["sectors_affected"] = zone
                            enrichment["cross_zone_detected"] = len(zone) > 1
                        else:
                            # Handle legacy case where zone might be a string
                            enrichment["sectors_affected"] = [zone]
                            enrichment["cross_zone_detected"] = False

                # Add alert tags if present
                if alert.tags:
                    for tag in alert.tags:
                        if tag not in enrichment["sectors_affected"]:
                            enrichment["sectors_affected"].append(tag)
                    enrichment["cross_zone_detected"] = len(enrichment["sectors_affected"]) > 1

        except Exception as e:
            logger.error(f"Error enriching indicator {indicator}: {e}")
            metadata["error"] = str(e)

        # Generate recommendations
        enrichment["recommendations"] = self._generate_recommendations(indicator, indicator_type, alert, enrichment)

        return {"metadata": metadata, "enrichment": enrichment}

    def _generate_recommendations(
        self, indicator: str, indicator_type: str, alert: ResilMeshAlert, enrichment: Dict
    ) -> List[str]:
        """Generate security recommendations based on enrichment"""
        recommendations = []

        # Base recommendation: block the indicator
        if indicator_type == "ip":
            recommendations.append(f"Block IP {indicator} at perimeter firewall")
        elif indicator_type == "domain":
            recommendations.append(f"Block domain {indicator} via DNS sinkhole")
        elif indicator_type == "file_hash":
            recommendations.append(f"Block file hash {indicator} on endpoints")

        # Host-based recommendations
        hostname = alert.threat.get("hostname")
        if hostname:
            recommendations.append(f"Isolate host {hostname} for forensic analysis")
            recommendations.append(f"Check {hostname} for persistence mechanisms")

        # User-based recommendations
        user = alert.threat.get("user")
        if user:
            recommendations.append(f"Review activity for user '{user}'")
            recommendations.append(f"Force password reset for user '{user}'")

        # Malware-specific recommendations
        malware_list = enrichment.get("known_malware", [])
        for malware in malware_list:
            name = malware.get("name", "Unknown")
            recommendations.append(f"Deploy signatures for {name}")

        # CVE-specific recommendations
        cves = enrichment.get("cves", [])
        for cve in cves:
            cve_id = cve.get("cve_id") if isinstance(cve, dict) else cve
            if cve_id and cve_id.startswith("CVE-"):
                recommendations.append(f"Apply patch for {cve_id}")

        # Network recommendations
        dest_ip = alert.threat.get("dest_ip")
        if dest_ip:
            recommendations.append(f"Investigate outbound connections to {dest_ip}")

        # Cross-zone recommendations
        if enrichment.get("cross_zone_detected"):
            affected = enrichment.get("sectors_affected", [])
            recommendations.append(f"⚠️ Cross-zone threat detected - alert {', '.join(affected)} teams")

        return recommendations

    def _create_error_response(self, alert: ResilMeshAlert, error_message: str) -> EnrichedAlert:
        """Create an error response when enrichment fails"""
        return EnrichedAlert(
            alert_id=alert.alert_id,
            enriched=False,
            edgeguard_version=self.VERSION,
            latency_ms=0.0,
            query_metadata={"error": error_message},
            enrichment={},
            original_alert={},
        )

    def close(self):
        """Close Neo4j connection"""
        if self.neo4j:
            self.neo4j.close()


# Convenience functions for NATS integration


async def handle_resilmesh_alert(subject: str, data: dict, processor: AlertProcessor) -> dict:
    """
    NATS message handler for ResilMesh alerts.

    Usage with NATSClient:
        processor = AlertProcessor()
        await nats_client.subscribe("resilmesh.alerts.zone.*",
            lambda s, d: handle_resilmesh_alert(s, d, processor))
    """
    logger.info(f"[FETCH] Received alert on {subject}")

    result = processor.process_alert(data)
    return result.to_dict()


def create_nats_callback(processor: AlertProcessor):
    """
    Create a callback function for NATS subscription.

    Returns an async function suitable for nats_client.subscribe()
    """

    async def callback(subject: str, data: dict):
        return await handle_resilmesh_alert(subject, data, processor)

    return callback


# Example usage
if __name__ == "__main__":
    # Test with sample alert
    sample_alert = {
        "alert_id": "wazuh-test-001",
        "source": "wazuh",
        "zone": "healthcare",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": ["healthcare", "finance"],
        "threat": {
            "indicator": "192.168.1.100",
            "type": "ip",
            "malware": "TrickBot",
            "cve": "CVE-2021-43297",
            "description": "Test alert with full ResilMesh schema",
            "severity": 9,
            "source_ip": "192.168.1.100",
            "dest_ip": "185.220.101.45",
            "hostname": "hospital-server-01",
            "user": "admin",
            "device_type": "MRI Scanner",
        },
    }

    processor = AlertProcessor()
    result = processor.process_alert(sample_alert)

    print("\n" + "=" * 60)
    print("ENRICHED ALERT RESPONSE (Full ResilMesh Integration)")
    print("=" * 60)
    print(json.dumps(result.to_dict(), indent=2))

    processor.close()
