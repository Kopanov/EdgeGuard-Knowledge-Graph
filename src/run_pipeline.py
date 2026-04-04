#!/usr/bin/env python3
"""
EdgeGuard - Main Pipeline Runner
Orchestrates collection, filtering, and loading to Neo4j
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests

from collector_allowlist import collect_sources_allowlist_from_env, is_collector_enabled_by_allowlist
from collectors.abuseipdb_collector import AbuseIPDBCollector
from collectors.cisa_collector import CISACollector
from collectors.finance_feed_collector import FeodoCollector, SSLBlacklistCollector
from collectors.global_feed_collector import CyberCureCollector, ThreatFoxCollector, URLhausCollector
from collectors.misp_collector import MISPCollector
from collectors.misp_writer import MISPWriter
from collectors.mitre_collector import MITRECollector
from collectors.nvd_collector import NVDCollector
from collectors.otx_collector import OTXCollector
from collectors.virustotal_collector import VirusTotalCollector
from collectors.vt_collector import VTCollector
from config import baseline_collection_limit_from_env, get_effective_limit
from neo4j_client import Neo4jClient

# Import STIX conversion from run_misp_to_neo4j
try:
    from run_misp_to_neo4j import MISPToNeo4jSync

    STIX_AVAILABLE = True
except ImportError:
    STIX_AVAILABLE = False
    logging.warning("STIX conversion not available. Install stix2 library for STIX 2.1 support.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Source ID mapping (tag -> source_id)
SOURCE_ID_MAP = {
    "misp": "misp",
    "alienvault_otx": "alienvault_otx",
    "otx": "alienvault_otx",
    "nvd": "nvd",
    "cisa_kev": "cisa",
    "cisa": "cisa",
    "mitre_attck": "mitre_attck",
    "mitre": "mitre_attck",
    "virustotal": "virustotal",
    "virustotal_enrich": "virustotal",
    "abuseipdb": "abuseipdb",
    "feodo": "feodo",
    "feodo_tracker": "feodo",  # tag used by FeodoCollector
    "sslbl": "sslbl",
    "ssl_blacklist": "sslbl",  # tag used by SSLBlacklistCollector
    "urlhaus": "urlhaus",
    "cybercure": "cybercure",
    "threatfox": "threatfox",
}


def get_source_id(item, raise_on_unknown: bool = False):
    """Get source_id from item's tag or sources list

    Args:
        item: Dict with 'tag' or 'sources' keys
        raise_on_unknown: If True, raise ValueError for unknown sources

    Returns:
        Source ID string, or None if source cannot be determined

    Raises:
        ValueError: If source is unknown and raise_on_unknown is True
    """
    tag = item.get("tag", "")
    sources = item.get("source", item.get("sources", []))

    # Try tag first
    if tag in SOURCE_ID_MAP:
        return SOURCE_ID_MAP[tag]

    # Try first source
    if sources and sources[0] in SOURCE_ID_MAP:
        return SOURCE_ID_MAP[sources[0]]

    # Log warning for unknown source - record as 'unknown' but continue
    unknown_source = tag or (sources[0] if sources else "unknown")
    logger.warning(
        f"[WARN] Unknown source '{unknown_source}' - recording as 'unknown'. Add mapping to SOURCE_ID_MAP if needed."
    )

    # Default to 'unknown' for automated pipelines (data not lost, but marked for review)
    return "unknown"


class EdgeGuardPipeline:
    def __init__(self):
        self.neo4j = Neo4jClient()
        # Create shared MISPWriter instance for collectors that push to MISP
        self.misp_writer = MISPWriter()

        self.collectors = {
            "misp": MISPCollector(),
            "otx": OTXCollector(misp_writer=self.misp_writer),
            "nvd": NVDCollector(misp_writer=self.misp_writer),
            "cisa": CISACollector(misp_writer=self.misp_writer),
            "mitre": MITRECollector(misp_writer=self.misp_writer),
            "virustotal": VTCollector(misp_writer=self.misp_writer),
            # Legacy/enrichment VT collector (separate from vt_collector.VTCollector; same allowlist name as Airflow)
            "virustotal_enrich": VirusTotalCollector(misp_writer=self.misp_writer),
            # Finance-focused feeds - now with MISPWriter
            "feodo": FeodoCollector(misp_writer=self.misp_writer),
            "sslbl": SSLBlacklistCollector(misp_writer=self.misp_writer),
            # Additional feeds
            "urlhaus": URLhausCollector(misp_writer=self.misp_writer),
            "cybercure": CyberCureCollector(misp_writer=self.misp_writer),
            # ThreatFox: free key from https://auth.abuse.ch/ — without it collect() skips (optional).
            "threatfox": ThreatFoxCollector(misp_writer=self.misp_writer),
            # AbuseIPDB requires ABUSEIPDB_API_KEY env var (free tier: 1000 req/day)
            "abuseipdb": AbuseIPDBCollector(misp_writer=self.misp_writer),
        }
        self.mitre_collector = self.collectors["mitre"]  # Store for relationships
        self.stix_exporter = None
        if STIX_AVAILABLE:
            try:
                self.stix_exporter = MISPToNeo4jSync(neo4j_client=self.neo4j)
                logger.info("[OK] STIX exporter initialized successfully")
            except Exception as e:
                logger.warning(f"[WARN] Could not initialize STIX exporter: {type(e).__name__}: {e}")

    def export_to_stix21(self, output_path: str = None) -> dict:
        """
        Export all MISP events to STIX 2.1 format.

        Args:
            output_path: Optional path to save STIX 2.1 JSON bundle

        Returns:
            STIX 2.1 bundle as dictionary
        """
        if not STIX_AVAILABLE or not self.stix_exporter:
            logger.error("STIX 2.1 export not available. Install stix2 library.")
            return {"error": "STIX library not available"}

        logger.info("\n🔄 Exporting MISP events to STIX 2.1 format...")

        try:
            # Fetch all EdgeGuard events from MISP
            events = self.stix_exporter.fetch_edgeguard_events()

            if not events:
                logger.info("No events found to export")
                return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "spec_version": "2.1", "objects": []}

            # Convert all events to STIX 2.1
            all_stix_objects = []

            for event in events:
                event_id = event.get("id")
                if event_id is None:
                    logger.warning("Skipping MISP event row with no id during STIX export")
                    continue
                logger.debug(f"Converting event {event_id} to STIX 2.1")

                # Fetch full event details
                full_event = self.stix_exporter.fetch_event_details(str(event_id))
                if not full_event:
                    logger.warning(f"Skipping event {event_id} - failed to fetch details")
                    continue

                # Convert to STIX 2.1 using PyMISP to_stix2()
                stix_bundle = self.stix_exporter.convert_to_stix21(full_event)

                if "objects" in stix_bundle:
                    all_stix_objects.extend(stix_bundle["objects"])

            # Create master bundle
            master_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": all_stix_objects,
            }

            # Save to file if output path provided
            if output_path:
                with open(output_path, "w") as f:
                    json.dump(master_bundle, f, indent=2)
                logger.info(f"   [OK] STIX 2.1 bundle saved to: {output_path}")

            logger.info(f"   [OK] Exported {len(events)} events ({len(all_stix_objects)} STIX objects)")
            return master_bundle

        except Exception as e:
            logger.error(f"   [ERR] STIX 2.1 export failed: {e}")
            return {"error": str(e)}

    def export_single_event_to_stix21(self, event_id: str) -> dict:
        """
        Export a single MISP event to STIX 2.1 format using PyMISP to_stix2().

        Args:
            event_id: MISP event ID

        Returns:
            STIX 2.1 bundle as dictionary
        """
        if not STIX_AVAILABLE or not self.stix_exporter:
            logger.error("STIX 2.1 export not available")
            return {"error": "STIX library not available"}

        try:
            # Fetch event details
            event = self.stix_exporter.fetch_event_details(event_id)
            if not event:
                return {"error": f"Event {event_id} not found"}

            # Convert using PyMISP to_stix2()
            stix_bundle = self.stix_exporter.convert_to_stix21(event)
            return stix_bundle

        except Exception as e:
            logger.error(f"Error exporting event {event_id} to STIX 2.1: {e}")
            return {"error": str(e)}

    def _extract_zones_from_stix_labels(self, obj: dict) -> list:
        """Extract zones from a STIX object.

        SDOs store zones in ``labels`` (e.g. ``zone:finance``).
        SCOs store zones in the custom ``x_edgeguard_zones`` property to comply
        with the STIX 2.1 spec (SCOs have no ``labels`` property).

        Args:
            obj: STIX object dict

        Returns:
            List of zones (e.g., ['finance', 'global'])
        """
        # Check both locations; prefer x_edgeguard_zones (SCOs) then labels (SDOs)
        zone_sources = list(obj.get("x_edgeguard_zones") or []) + list(obj.get("labels") or [])
        zones = []
        for label in zone_sources:
            if label and label.startswith("zone:"):
                zone = label.replace("zone:", "").strip()
                if zone:
                    zones.append(zone)
        return zones if zones else ["global"]

    def _create_indicates_relationships(self) -> int:
        """
        Create INDICATES relationships using MISP event co-occurrence.

        The correct threat-intel logic: when an Indicator (IP, domain, hash) and
        a Malware node share the same MISP event ID, they were observed together
        in the same threat report — the indicator is evidence of the malware.

        This avoids the false-positive trap of text matching (an IP value like
        '1.2.3.4' will never meaningfully "contain" a malware name like 'TrickBot').

        Returns:
            Number of INDICATES relationships created
        """
        try:
            # Co-occurrence query: Indicators and Malware that share a MISP event
            # are linked with INDICATES.  Works cross-source because misp_event_id
            # is stored on every node that came through the MISP pipeline.
            cooccurrence_query = """
            MATCH (i:Indicator)
            WHERE i.misp_event_id IS NOT NULL AND i.misp_event_id <> ''
            WITH i, coalesce(i.misp_event_ids, [i.misp_event_id]) AS eids
            UNWIND eids AS eid
            WITH i, eid
            MATCH (m:Malware {misp_event_id: eid})
            MERGE (i)-[r:INDICATES]->(m)
            ON CREATE SET r.created_at = datetime(),
                          r.source_id  = 'misp_cooccurrence',
                          r.confidence_score = 0.5
            SET r.updated_at = datetime()
            RETURN count(r) AS created
            """
            results = self.neo4j.run(cooccurrence_query)
            record = results[0] if results else None
            indicates_count = record.get("created", 0) if record else 0
            logger.info(f"   ℹ️ INDICATES (co-occurrence): {indicates_count} relationships")

            # Second pass: Indicators that explicitly mention a CVE are linked to
            # that CVE/Vulnerability via EXPLOITS (more specific than INDICATES).
            exploits_query = """
            MATCH (i:Indicator)
            WHERE i.cve_id IS NOT NULL AND i.cve_id <> ''
            MATCH (v)
            WHERE (v:Vulnerability OR v:CVE) AND v.cve_id = i.cve_id
            MERGE (i)-[r:EXPLOITS]->(v)
            ON CREATE SET r.created_at = datetime(),
                          r.source_id  = 'cve_tag_match',
                          r.confidence_score = 0.9
            SET r.updated_at = datetime()
            RETURN count(r) AS created
            """
            results = self.neo4j.run(exploits_query)
            record = results[0] if results else None
            exploits_count = record.get("created", 0) if record else 0
            logger.info(f"   ℹ️ EXPLOITS (CVE tag match): {exploits_count} relationships")

            return indicates_count + exploits_count

        except Exception as e:
            logger.warning(f"   [WARN] INDICATES/EXPLOITS creation failed: {e}")
            return 0

    def load_stix21_to_neo4j(self, stix_bundle: dict) -> dict:
        """
        Load STIX 2.1 bundle data into Neo4j.

        This method parses STIX 2.1 objects and creates corresponding
        nodes in Neo4j, enabling the flow: MISP → STIX → Neo4j

        Args:
            stix_bundle: STIX 2.1 bundle dictionary

        Returns:
            Dict with counts of loaded objects by type
        """
        stats = {
            "indicators": 0,
            "vulnerabilities": 0,
            "malware": 0,
            "actors": 0,
            "techniques": 0,
            "observables": 0,
            "relationships_indicates": 0,
            "relationships_attributed_to": 0,
            "errors": 0,
        }

        objects = stix_bundle.get("objects", [])
        logger.info(f"   Loading {len(objects)} STIX objects into Neo4j...")

        # First pass: build ID mapping for relationship resolution
        id_map = {}  # STIX ID -> {type, name, mitre_id}

        for obj in objects:
            obj_type = obj.get("type", "")
            stix_id = obj.get("id", "")

            if obj_type == "indicator":
                # Extract indicator value from pattern
                pattern = obj.get("pattern", "")
                indicator_data = self._parse_stix_pattern(pattern)
                if indicator_data:
                    id_map[stix_id] = {
                        "type": "indicator",
                        "value": indicator_data.get("value", ""),
                        "indicator_type": indicator_data.get("type", "unknown"),
                    }
            elif obj_type == "malware":
                id_map[stix_id] = {"type": "malware", "name": obj.get("name", "")}
            elif obj_type == "tool":
                id_map[stix_id] = {"type": "tool", "name": obj.get("name", "")}
            elif obj_type == "threat-actor":
                id_map[stix_id] = {"type": "actor", "name": obj.get("name", "")}
            elif obj_type == "attack-pattern":
                external_refs = obj.get("external_references", [])
                mitre_id = ""
                for ext in external_refs:
                    if ext.get("source_name") == "mitre-attack":
                        mitre_id = ext.get("external_id", "")
                        break
                id_map[stix_id] = {"type": "technique", "name": obj.get("name", ""), "mitre_id": mitre_id}
            elif obj_type == "x-mitre-tactic":
                external_refs = obj.get("external_references", [])
                mitre_id = ""
                shortname = obj.get("x_mitre_shortname", "")
                for ext in external_refs:
                    if ext.get("source_name") == "mitre-attack":
                        mitre_id = ext.get("external_id", "")
                        break
                id_map[stix_id] = {
                    "type": "tactic",
                    "name": obj.get("name", ""),
                    "mitre_id": mitre_id,
                    "shortname": shortname,
                }
            elif obj_type == "vulnerability":
                id_map[stix_id] = {"type": "vulnerability", "cve_id": obj.get("name", "")}
            elif obj_type in ["ipv4-addr", "ipv6-addr", "domain-name", "url"]:
                id_map[stix_id] = {"type": "observable", "value": obj.get("value", ""), "observable_type": obj_type}

        logger.info(f"   Built ID map with {len(id_map)} entries")

        # Second pass: create nodes and relationships
        for obj in objects:
            try:
                obj_type = obj.get("type", "")

                # Handle Indicator objects
                if obj_type == "indicator":
                    pattern = obj.get("pattern", "")
                    # Parse pattern to extract indicator value
                    indicator_data = self._parse_stix_pattern(pattern)
                    if indicator_data:
                        ok = self.neo4j.merge_indicator(
                            {
                                "indicator_type": indicator_data.get("type", "unknown"),
                                "value": indicator_data.get("value", ""),
                                "zone": self._extract_zones_from_stix_labels(obj),
                                "tag": "stix_import",
                                "source": [obj.get("x_edgeguard_source", "unknown")],  # Source as array (like zone)
                                "first_seen": obj.get("created", datetime.now(timezone.utc).isoformat()),
                                "last_updated": obj.get("modified", datetime.now(timezone.utc).isoformat()),
                                "confidence_score": 0.7,
                                "misp_event_id": None,
                            },
                            source_id=obj.get("x_edgeguard_source", "unknown"),
                        )
                        if ok:
                            stats["indicators"] += 1

                # Handle Vulnerability objects (CVE)
                elif obj_type == "vulnerability":
                    vuln_name = obj.get("name", "")
                    # Check if it looks like a CVE
                    import re

                    if re.match(r"^CVE-\d{4}-\d{4,}$", vuln_name, re.IGNORECASE):
                        ok = self.neo4j.merge_vulnerability(
                            {
                                "cve_id": vuln_name.upper(),
                                "description": obj.get("description", ""),
                                "cvss_score": 0.0,
                                "severity": "UNKNOWN",
                                "attack_vector": "UNKNOWN",
                                "zone": self._extract_zones_from_stix_labels(obj),
                                "tag": "stix_import",
                                "source": [obj.get("x_edgeguard_source", "unknown")],  # Source as array (like zone)
                                "first_seen": obj.get("created", datetime.now(timezone.utc).isoformat()),
                                "last_updated": obj.get("modified", datetime.now(timezone.utc).isoformat()),
                                "confidence_score": 0.7,
                                "misp_event_id": None,
                            },
                            source_id=obj.get("x_edgeguard_source", "unknown"),
                        )
                        if ok:
                            stats["vulnerabilities"] += 1

                # Handle Threat Actor objects
                elif obj_type == "threat-actor":
                    ok = self.neo4j.merge_actor(
                        {
                            "name": obj.get("name", ""),
                            "aliases": obj.get("aliases", []),
                            "description": obj.get("description", ""),
                            "zone": self._extract_zones_from_stix_labels(obj),
                            "tag": "stix_import",
                            "source": [obj.get("x_edgeguard_source", "unknown")],  # Source as array (like zone)
                            "confidence_score": 0.7,
                        },
                        source_id=obj.get("x_edgeguard_source", "unknown"),
                    )
                    if ok:
                        stats["actors"] += 1

                # Handle Malware objects
                elif obj_type == "malware":
                    ok = self.neo4j.merge_malware(
                        {
                            "name": obj.get("name", ""),
                            "malware_types": obj.get("malware_types", []),
                            "family": obj.get("name", ""),
                            "description": obj.get("description", ""),
                            "zone": self._extract_zones_from_stix_labels(obj),
                            "tag": "stix_import",
                            "source": [obj.get("x_edgeguard_source", "unknown")],  # Source as array (like zone)
                            "confidence_score": 0.7,
                        },
                        source_id=obj.get("x_edgeguard_source", "unknown"),
                    )
                    if ok:
                        stats["malware"] += 1

                # Handle Tool objects (Cobalt Strike, Mimikatz, etc.)
                elif obj_type == "tool":
                    mitre_id = ""
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            mitre_id = ref.get("external_id", "")
                            break
                    self.neo4j.merge_tool(
                        {
                            "mitre_id": mitre_id,
                            "name": obj.get("name", ""),
                            "description": obj.get("description", ""),
                            "tool_types": obj.get("labels", []),
                            "zone": self._extract_zones_from_stix_labels(obj),
                            "tag": "stix_import",
                            "source": [obj.get("x_edgeguard_source", "unknown")],
                            "confidence_score": 0.7,
                        },
                        source_id=obj.get("x_edgeguard_source", "unknown"),
                    )
                    stats.setdefault("tools", 0)
                    stats["tools"] += 1

                # Handle Attack Pattern (Technique) objects
                elif obj_type == "attack-pattern":
                    # Try to extract MITRE ID from external references
                    mitre_id = ""
                    external_refs = obj.get("external_references", [])
                    for ref in external_refs:
                        if ref.get("source_name") == "mitre-attack":
                            mitre_id = ref.get("external_id", "")
                            break

                    self.neo4j.merge_technique(
                        {
                            "mitre_id": mitre_id,
                            "name": obj.get("name", ""),
                            "description": obj.get("description", ""),
                            "platforms": [],
                            "zone": self._extract_zones_from_stix_labels(obj),
                            "tag": "stix_import",
                            "source": [obj.get("x_edgeguard_source", "unknown")],  # Source as array (like zone)
                            "confidence_score": 0.8,
                        },
                        source_id=obj.get("x_edgeguard_source", "unknown"),
                    )
                    stats["techniques"] += 1

                # Handle Tactic objects (x-mitre-tactic)
                elif obj_type == "x-mitre-tactic":
                    mitre_id = ""
                    shortname = obj.get("x_mitre_shortname", "")
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") == "mitre-attack":
                            mitre_id = ref.get("external_id", "")
                            break
                    self.neo4j.merge_tactic(
                        {
                            "mitre_id": mitre_id,
                            "name": obj.get("name", ""),
                            "shortname": shortname,
                            "description": obj.get("description", ""),
                            "zone": ["global"],
                            "tag": "stix_import",
                            "source": [obj.get("x_edgeguard_source", "unknown")],
                            "confidence_score": 1.0,
                        },
                        source_id=obj.get("x_edgeguard_source", "unknown"),
                    )
                    stats.setdefault("tactics", 0)
                    stats["tactics"] += 1

                # Handle observable objects (IPv4, domain, etc.)
                elif obj_type in ["ipv4-addr", "ipv6-addr", "domain-name", "url"]:
                    # Convert observable to indicator
                    indicator_type = self._stix_observable_type_to_indicator(obj_type)
                    value = obj.get("value", "")
                    if value:
                        self.neo4j.merge_indicator(
                            {
                                "indicator_type": indicator_type,
                                "value": value,
                                "zone": self._extract_zones_from_stix_labels(obj),
                                "tag": "stix_import",
                                "source": [obj.get("x_edgeguard_source", "unknown")],
                                "first_seen": datetime.now(timezone.utc).isoformat(),
                                "last_updated": datetime.now(timezone.utc).isoformat(),
                                "confidence_score": 0.7,
                                "misp_event_id": None,
                            },
                            source_id=obj.get("x_edgeguard_source", "unknown"),
                        )
                        stats["observables"] += 1

                # Handle STIX Relationship objects
                elif obj_type == "relationship":
                    rel_type = obj.get("relationship_type", "")
                    src_ref = obj.get("source_ref", "")
                    tgt_ref = obj.get("target_ref", "")

                    src = id_map.get(src_ref, {})
                    tgt = id_map.get(tgt_ref, {})

                    if not src or not tgt:
                        continue

                    # Handle INDICATES (Indicator -> Malware)
                    if rel_type == "indicates":
                        if src["type"] == "indicator" and tgt["type"] == "malware":
                            self.neo4j.create_indicator_malware_relationship(
                                src["value"], tgt["name"], source_id=obj.get("x_edgeguard_source", "unknown")
                            )
                            stats["relationships_indicates"] += 1

                    # Handle ATTRIBUTED_TO (Malware -> ThreatActor)
                    elif rel_type == "attributed-to":
                        if src["type"] == "malware" and tgt["type"] == "actor":
                            self.neo4j.create_malware_actor_relationship(src["name"], tgt["name"])
                            stats["relationships_attributed_to"] += 1

                    # Handle USES (Actor/Malware -> Technique)
                    elif rel_type == "uses":
                        if src["type"] in ["actor", "malware"] and tgt["type"] == "technique":
                            if src["type"] == "actor":
                                self.neo4j.create_actor_technique_relationship(src["name"], tgt["mitre_id"])
                            # Note: malware-technique relationship would need a separate method
                            # For now, we skip malware->technique via STIX relationships

                # Handle STIX Report objects (containers)
                elif obj_type == "report":
                    # Reports contain references to other objects - we could
                    # create relationships here if needed
                    pass

            except Exception as e:
                logger.warning(f"[WARN] Error loading STIX object {obj.get('id', 'unknown')}: {type(e).__name__}: {e}")
                stats["errors"] += 1

        return stats

    def _parse_stix_pattern(self, pattern: str) -> Optional[dict]:
        """
        Parse a STIX pattern to extract indicator type and value.

        Args:
            pattern: STIX pattern string (e.g., "[ipv4-addr:value = '1.2.3.4']")

        Returns:
            Dict with 'type' and 'value' or None if not parseable
        """
        import re

        # Pattern for ipv4-addr:value
        match = re.search(r"ipv4-addr:value\s*=\s*'([^']+)'", pattern)
        if match:
            return {"type": "ipv4", "value": match.group(1)}

        # Pattern for ipv6-addr:value
        match = re.search(r"ipv6-addr:value\s*=\s*'([^']+)'", pattern)
        if match:
            return {"type": "ipv6", "value": match.group(1)}

        # Pattern for domain-name:value
        match = re.search(r"domain-name:value\s*=\s*'([^']+)'", pattern)
        if match:
            return {"type": "domain", "value": match.group(1)}

        # Pattern for url:value
        match = re.search(r"url:value\s*=\s*'([^']+)'", pattern)
        if match:
            return {"type": "url", "value": match.group(1)}

        # Pattern for file:hashes
        match = re.search(r"file:hashes\.'([^']+)'\s*=\s*'([^']+)'", pattern)
        if match:
            return {"type": "hash", "value": match.group(2)}

        return None

    def _stix_observable_type_to_indicator(self, observable_type: str) -> str:
        """Map STIX observable type to EdgeGuard indicator type."""
        mapping = {
            "ipv4-addr": "ipv4",
            "ipv6-addr": "ipv6",
            "domain-name": "domain",
            "url": "url",
            "file": "hash",
            "email-addr": "email",
        }
        return mapping.get(observable_type, "unknown")

    def _run_stix_flow(self) -> dict:
        """
        Run the STIX 2.1 flow: Fetch from MISP → Convert to STIX → Load to Neo4j.

        Returns:
            Dict with counts of loaded objects by type
        """
        loaded = {"vulnerabilities": 0, "indicators": 0, "malware": 0, "actors": 0, "techniques": 0, "tactics": 0}

        try:
            # Step 3a: Fetch all EdgeGuard events from MISP
            logger.info("   🔄 Step 3a: Fetching events from MISP...")
            events = self.stix_exporter.fetch_edgeguard_events()

            if not events:
                logger.info("   ℹ️  No events found to convert")
                return loaded

            logger.info(f"   [OK] Fetched {len(events)} events from MISP")

            # Step 3b: Convert all events to STIX 2.1
            logger.info("   🔄 Step 3b: Converting events to STIX 2.1 format...")
            all_stix_objects = []
            conversion_errors = 0

            for event in events:
                event_id = event.get("id")
                event_info = event.get("info", "")
                if event_id is None:
                    logger.warning("   [WARN] Skipping MISP event row with no id during STIX pipeline")
                    conversion_errors += 1
                    continue
                logger.debug(f"   Converting event {event_id} to STIX 2.1")

                # Extract source from event info (format: EdgeGuard-{source}-{date})
                source_from_event = "unknown"
                try:
                    parts = event_info.split("-", 2)
                    if len(parts) >= 2:
                        source_from_event = parts[1]  # e.g., "alienvault_otx"
                except Exception as e:
                    logger.debug(f"Could not extract source from event info '{event_info}': {e}")

                try:
                    # Fetch full event details
                    full_event = self.stix_exporter.fetch_event_details(str(event_id))
                    if not full_event:
                        logger.warning(f"   [WARN]  Skipping event {event_id} - failed to fetch details")
                        conversion_errors += 1
                        continue

                    # Convert to STIX 2.1 using PyMISP to_stix2()
                    stix_bundle = self.stix_exporter.convert_to_stix21(full_event)

                    if "objects" in stix_bundle:
                        # Add x_edgeguard_source to each object
                        for obj in stix_bundle["objects"]:
                            obj["x_edgeguard_source"] = source_from_event
                        all_stix_objects.extend(stix_bundle["objects"])

                except Exception as e:
                    logger.warning(f"   [WARN]  Error converting event {event_id}: {e}")
                    conversion_errors += 1

            logger.info(f"   [OK] Converted {len(events) - conversion_errors}/{len(events)} events")
            logger.info(f"   [STATS] Total STIX objects created: {len(all_stix_objects)}")

            # Step 3c: Load STIX objects into Neo4j
            # Re-verify Neo4j connectivity before heavy write phase (may have died during 5h+ Step 2)
            logger.info("   🔍 Step 3c: Verifying Neo4j connectivity before write phase...")
            _neo4j_ok = False
            for _retry in range(3):
                # neo4j.run() re-raises transient errors after retry exhaustion,
                # so we catch exceptions here to drive our own reconnect loop.
                try:
                    _test = self.neo4j.run("RETURN 1 AS ok")
                except Exception:
                    _test = []
                if _test:
                    _neo4j_ok = True
                    break
                # Failed — sleep and try to reconnect
                logger.warning(f"   Neo4j not reachable (attempt {_retry + 1}/3)")
                if _retry < 2:
                    import time

                    time.sleep(10)
                    try:
                        if self.neo4j.connect():
                            logger.info("   Neo4j reconnected")
                        else:
                            logger.warning(f"   Neo4j reconnect returned False (attempt {_retry + 1}/3)")
                    except Exception as e:
                        logger.warning(f"   Neo4j reconnect failed: {e}")

            if not _neo4j_ok:
                logger.error("   [FAIL] Neo4j is unreachable after 3 attempts — cannot load data!")
                logger.error("   Check: docker compose ps neo4j / docker compose logs neo4j")
                return loaded  # Return with 0 counts — don't report success

            logger.info("   ✅ Neo4j connectivity verified — starting write phase...")
            master_bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "objects": all_stix_objects,
            }

            stix_stats = self.load_stix21_to_neo4j(master_bundle)

            # Aggregate counts
            loaded["indicators"] = stix_stats.get("indicators", 0) + stix_stats.get("observables", 0)
            loaded["vulnerabilities"] = stix_stats.get("vulnerabilities", 0)
            loaded["malware"] = stix_stats.get("malware", 0)
            loaded["actors"] = stix_stats.get("actors", 0)
            loaded["techniques"] = stix_stats.get("techniques", 0)
            loaded["relationships_indicates"] = stix_stats.get("relationships_indicates", 0)
            loaded["relationships_attributed_to"] = stix_stats.get("relationships_attributed_to", 0)

            _stix_total = sum(
                v for k, v in loaded.items() if k not in ("relationships_indicates", "relationships_attributed_to")
            )
            if _stix_total > 0:
                logger.info(f"   [OK] STIX flow complete: {_stix_total} objects loaded")
            else:
                logger.error("   [FAIL] STIX flow complete but 0 objects loaded — Neo4j writes failed!")
            logger.info(f"      - INDICATES relationships: {loaded['relationships_indicates']}")
            logger.info(f"      - ATTRIBUTED_TO relationships: {loaded['relationships_attributed_to']}")

        except Exception as e:
            logger.error(f"   [ERR] STIX flow error: {e}")

        return loaded

    def run(
        self,
        stix_export: bool = False,
        stix_output: str = None,
        stix_event_id: str = None,
        use_stix_flow: bool = False,
        baseline: bool = False,
        baseline_days: int = 730,
        fresh_baseline: bool = False,
    ):
        """
        Run the complete pipeline.

        Args:
            stix_export: If True, export to STIX 2.1 format after pipeline completion
            stix_output: Output file path for STIX 2.1 bundle
            stix_event_id: If provided, export only this specific event to STIX 2.1
            use_stix_flow: If True, use STIX 2.1 as intermediate format (MISP → STIX → Neo4j)
            baseline: If True, collect historical data (all available, not just latest)
            baseline_days: How many days back to collect in baseline mode (default: 365)
            fresh_baseline: If True with baseline, perform a true clean slate: clear Neo4j
                graph data, delete MISP EdgeGuard events, and discard checkpoints before
                re-collecting. Default False preserves existing data and checkpoints for resume.
        """
        # ── Pipeline lock: prevent concurrent CLI runs ──
        # NOTE: This lock only protects CLI invocations (python run_pipeline.py).
        # Airflow DAGs use max_active_runs=1 for concurrency control instead.
        lock_dir = os.path.join(os.path.dirname(__file__), "..", "checkpoints")
        os.makedirs(lock_dir, exist_ok=True)
        lock_path = os.path.join(lock_dir, "pipeline.lock")
        try:
            if os.path.exists(lock_path):
                with open(lock_path) as f:
                    old_pid = int(f.read().strip())
                # Check if the process is still alive
                try:
                    os.kill(old_pid, 0)
                    # Process exists (signal 0 succeeded) — could be ours or another user's
                    logger.error(
                        f"Another pipeline process (PID {old_pid}) is still running. "
                        "Aborting to prevent data races. "
                        "If this is stale, delete checkpoints/pipeline.lock and retry."
                    )
                    return False
                except PermissionError:
                    # PID exists but owned by another user — treat as alive (safe side)
                    logger.error(
                        f"Pipeline lock held by PID {old_pid} (different user). "
                        "Aborting. Delete checkpoints/pipeline.lock if stale."
                    )
                    return False
                except ProcessLookupError:
                    logger.info(f"Stale lock file found (PID {old_pid} is gone) — removing.")
        except (ValueError, IOError):
            pass
        with open(lock_path, "w") as f:
            f.write(str(os.getpid()))

        import atexit
        import signal

        def _cleanup_lock(*_args):
            try:
                if os.path.exists(lock_path):
                    os.remove(lock_path)
            except OSError:
                pass

        atexit.register(_cleanup_lock)

        def _sigterm_handler(signum, frame):
            _cleanup_lock()
            sys.exit(1)

        signal.signal(signal.SIGTERM, _sigterm_handler)

        try:
            return self._run_pipeline_inner(
                stix_export=stix_export,
                stix_output=stix_output,
                stix_event_id=stix_event_id,
                use_stix_flow=use_stix_flow,
                baseline=baseline,
                baseline_days=baseline_days,
                fresh_baseline=fresh_baseline,
            )
        finally:
            _cleanup_lock()

    def _run_pipeline_inner(
        self,
        stix_export=False,
        stix_output=None,
        stix_event_id=None,
        use_stix_flow=False,
        baseline=False,
        baseline_days=730,
        fresh_baseline=False,
    ):
        """Inner pipeline logic, separated so the lock is always cleaned up."""
        # Import baseline checkpoint utilities
        from baseline_checkpoint import clear_checkpoint, get_baseline_status

        # Log baseline mode
        if baseline:
            logger.info(f"BASELINE MODE: Collecting historical data (last {baseline_days} days)")
            if fresh_baseline:
                logger.info("=== FRESH BASELINE: clearing all data for clean start ===")

                # 1. Clear checkpoints (preserves incremental by default)
                clear_checkpoint()
                logger.info("  [1/3] Cleared checkpoints")

                # 2. Clear Neo4j graph data
                try:
                    from neo4j_client import Neo4jClient

                    _neo4j = Neo4jClient()
                    if _neo4j.connect():
                        try:
                            _neo4j.clear_all()
                            logger.info("  [2/3] Cleared Neo4j graph data")
                        finally:
                            _neo4j.close()
                    else:
                        logger.warning("  [2/3] Could not connect to Neo4j — skipping clear")
                except Exception as e:
                    logger.warning(f"  [2/3] Could not clear Neo4j: {e}")

                # 3. Clear MISP EdgeGuard events
                try:
                    import warnings

                    import requests as _req
                    import urllib3

                    from config import MISP_API_KEY as _misp_key
                    from config import MISP_URL as _misp_url
                    from config import SSL_VERIFY as _verify
                    from config import apply_misp_http_host_header

                    _sess = _req.Session()
                    _sess.headers.update({"Authorization": _misp_key, "Accept": "application/json"})
                    apply_misp_http_host_header(_sess)

                    # Delete all EdgeGuard events. Always re-fetch page 1 (deleted events
                    # disappear, shifting remaining events to page 1). Safety cap: 20 iterations.
                    _deleted = 0
                    for _round in range(20):
                        with warnings.catch_warnings():
                            if not _verify:
                                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
                            _resp = _sess.get(
                                f"{_misp_url}/events/index",
                                params={"searchall": "EdgeGuard", "limit": 500},
                                verify=_verify,
                                timeout=(15, 60),
                            )
                        if _resp.status_code != 200:
                            break

                        _json = _resp.json()
                        if isinstance(_json, list):
                            _events = _json
                        elif isinstance(_json, dict):
                            _events = _json.get("response", _json.get("Event", []))
                            if isinstance(_events, dict):
                                _events = [_events]
                        else:
                            _events = []

                        if not _events:
                            break  # No more events

                        for ev in _events:
                            eid = ev.get("id") or ev.get("Event", {}).get("id")
                            if eid:
                                with warnings.catch_warnings():
                                    if not _verify:
                                        warnings.filterwarnings(
                                            "ignore", category=urllib3.exceptions.InsecureRequestWarning
                                        )
                                    _del_resp = _sess.delete(
                                        f"{_misp_url}/events/{eid}", verify=_verify, timeout=(15, 30)
                                    )
                                if _del_resp.status_code == 200:
                                    _deleted += 1

                    logger.info(f"  [3/3] Cleared {_deleted} MISP EdgeGuard events")
                except Exception as e:
                    logger.warning(f"  [3/3] Could not clear MISP events: {e}")

                logger.info("=== Fresh baseline ready — collecting from scratch ===")
            else:
                existing = get_baseline_status()
                if existing:
                    completed = [s for s, d in existing.items() if d.get("completed")]
                    in_progress = [s for s, d in existing.items() if not d.get("completed")]
                    if in_progress:
                        logger.info("Resuming baseline (add --fresh-baseline to restart from scratch)")
                        logger.info(f"  Completed: {completed}, In-progress: {in_progress}")
                    else:
                        logger.info("All previous checkpoints are completed — starting fresh baseline")
                        clear_checkpoint()
                else:
                    logger.info("No existing checkpoints — starting fresh baseline")
        else:
            logger.info("UPDATE MODE: Collecting latest data only")

        # Generate run ID for reproducibility and traceability
        run_id = str(uuid.uuid4())[:8]

        # Try to get git commit hash for traceability
        git_commit = None
        try:
            import subprocess

            git_commit = (
                subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"],
                    cwd=os.path.dirname(os.path.abspath(__file__)),
                    stderr=subprocess.DEVNULL,
                )
                .decode()
                .strip()
            )
        except Exception:
            pass  # Not a git repo or git not available

        start_time = datetime.now(timezone.utc)
        logger.info("=" * 60)
        logger.info(f"[START] EdgeGuard Pipeline Started (run_id: {run_id})")
        if git_commit:
            logger.info(f"📌 Git commit: {git_commit}")
        if use_stix_flow:
            logger.info("🔄 STIX 2.1 pipeline flow enabled (MISP → STIX → Neo4j)")
        if stix_export:
            logger.info("[PUSH] STIX 2.1 export enabled")
        if stix_event_id:
            logger.info(f"[PUSH] Single event STIX export: Event {stix_event_id}")
        logger.info("=" * 60)

        # Step 1: Connect to Neo4j
        logger.info("\n📡 Step 1: Connecting to Neo4j...")
        if not self.neo4j.connect():
            logger.error("Failed to connect to Neo4j. Exiting.")
            return False

        # Create constraints and indexes
        self.neo4j.create_constraints()
        self.neo4j.create_indexes()

        # Ensure source nodes exist (no clearing - data accumulates)
        logger.info("\n[INFO] Ensuring Source nodes exist...")
        self.neo4j.ensure_sources()

        # Step 2: Collect from all external sources and push to MISP
        logger.info("\n[FETCH] Step 2: Collecting from sources and pushing to MISP...")
        total_pushed = 0
        step2_ok: list[str] = []
        step2_skipped: list[tuple[str, str, str]] = []  # (source, reason, reason_class)
        step2_failed: list[tuple[str, str]] = []  # (source, error) — success=False dict
        step2_exceptions: list[tuple[str, str]] = []  # (source, message)

        # Collectors that push to MISP (all except MISP collector itself)
        external_collectors = {k: v for k, v in self.collectors.items() if k != "misp"}

        _allow = collect_sources_allowlist_from_env()
        if _allow is not None:
            logger.info(
                f"   EDGEGUARD_COLLECT_SOURCES allowlist active: "
                f"{sorted(_allow) if _allow else '(none — all external collectors disabled)'}",
            )

        for source_name, collector in external_collectors.items():
            if not is_collector_enabled_by_allowlist(source_name, _allow):
                reason = "Not in EDGEGUARD_COLLECT_SOURCES allowlist"
                rclass = "collector_disabled_by_config"
                logger.warning(f"   [SKIP] {source_name}: {reason} [{rclass}]")
                step2_skipped.append((source_name, reason, rclass))
                continue
            try:
                logger.info(f"\n   Collecting from {source_name}...")
                # Baseline uses BASELINE_COLLECTION_LIMIT (env); cron uses incremental limits
                if baseline:
                    effective_limit = baseline_collection_limit_from_env()
                else:
                    effective_limit = get_effective_limit(source_name)
                logger.info(f"   ℹ️  Limit for {source_name}: {effective_limit if effective_limit else 'unlimited'}")
                if baseline:
                    logger.info(f"   ℹ️  {source_name}: Baseline mode - collecting historical data")
                # Push to MISP (MISP becomes the single source of truth)
                if hasattr(collector, "collect"):
                    import inspect

                    sig = inspect.signature(collector.collect)
                    if "push_to_misp" in sig.parameters:
                        if "baseline" in sig.parameters:
                            data = collector.collect(
                                limit=effective_limit, push_to_misp=True, baseline=baseline, baseline_days=baseline_days
                            )
                        else:
                            data = collector.collect(limit=effective_limit, push_to_misp=True)
                    else:
                        if "baseline" in sig.parameters:
                            data = collector.collect(
                                limit=effective_limit, baseline=baseline, baseline_days=baseline_days
                            )
                        else:
                            data = collector.collect(limit=effective_limit)
                else:
                    data = collector.collect(limit=effective_limit)

                # Handle both list and dict return types (collectors may return status dict when push_to_misp=True)
                if isinstance(data, dict):
                    logger.debug(f"   ℹ️ {source_name} returned dict with keys: {data.keys()}")
                    if data.get("skipped") is True:
                        reason = str(data.get("skip_reason") or "optional source skipped")
                        rclass = str(data.get("skip_reason_class") or "")
                        extra = f" [{rclass}]" if rclass else ""
                        logger.warning(f"   [SKIP] {source_name}: {reason}{extra}")
                        step2_skipped.append((source_name, reason, rclass))
                        continue
                    if data.get("success") is False:
                        err = data.get("error") or (
                            f"success=false (failed={data.get('failed', 0)}, count={data.get('count', 0)})"
                        )
                        logger.error(f"   [ERR] {source_name}: {err}")
                        step2_failed.append((source_name, str(err)))
                        continue
                    count = int(data.get("count", 0) or 0)
                    logger.info(f"   [OK] {source_name}: {count} items pushed to MISP")
                    total_pushed += count
                    step2_ok.append(source_name)
                else:
                    count = len(data) if data else 0
                    logger.info(f"   [OK] {source_name}: {count} items pushed to MISP")
                    total_pushed += count
                    step2_ok.append(source_name)
            except requests.exceptions.Timeout as e:
                msg = f"Timeout: {e}"
                logger.error(f"   [ERR] {source_name} collector timed out - service may be slow")
                step2_exceptions.append((source_name, msg))
            except requests.exceptions.ConnectionError as e:
                msg = f"ConnectionError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - connection error (service down?)")
                step2_exceptions.append((source_name, msg))
            except ImportError as e:
                msg = f"ImportError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - missing dependency: {e}")
                step2_exceptions.append((source_name, msg))
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                logger.error(f"   [ERR] {source_name} collector failed: {msg}")
                step2_exceptions.append((source_name, msg))

        logger.info(f"\n[STATS] Total pushed to MISP: {total_pushed} items")
        logger.info("\n[SUMMARY] Step 2 — collection by source:")
        logger.info(f"   • Succeeded ({len(step2_ok)}): {', '.join(step2_ok) if step2_ok else '—'}")
        if step2_skipped:
            logger.warning(f"   • Skipped optional ({len(step2_skipped)}) — pipeline continues; no data from:")
            for name, reason, rclass in step2_skipped:
                rc = f" [{rclass}]" if rclass else ""
                logger.warning(f"      - {name}:{rc} {reason}")
        else:
            logger.info("   • Skipped optional: none")
        if step2_failed:
            logger.error(f"   • Collector reported failure ({len(step2_failed)}):")
            for name, err in step2_failed:
                logger.error(f"      - {name}: {err}")
        else:
            logger.info("   • Collector reported failure: none")
        if step2_exceptions:
            logger.error(f"   • Raised exception ({len(step2_exceptions)}):")
            for name, err in step2_exceptions:
                logger.error(f"      - {name}: {err}")
        else:
            logger.info("   • Raised exception: none")
        if step2_failed or step2_exceptions:
            logger.warning(
                "[WARN] Step 2 had failures — MISP may be missing data from those sources; "
                "review logs above and fix keys/connectivity before relying on a full baseline."
            )

        # Step 3: MISP → Neo4j (STIX 2.1 flow only)
        loaded = {
            "vulnerabilities": 0,
            "indicators": 0,
            "cves": 0,
            "malware": 0,
            "actors": 0,
            "techniques": 0,
            "tactics": 0,
            "relationships_indicates": 0,
            "relationships_attributed_to": 0,
        }
        inactive_stats = {}

        if use_stix_flow:
            # STIX 2.1 FLOW: MISP → STIX → Neo4j
            logger.info("\n[SAVE] Step 3: Converting MISP data to STIX 2.1 and loading to Neo4j...")

            if not STIX_AVAILABLE or not self.stix_exporter:
                logger.error("   [ERR] STIX 2.1 flow requested but STIX library not available!")
                logger.error("   STIX flow is required - pipeline cannot continue without STIX support.")
                return False
            else:
                loaded = self._run_stix_flow()
                inactive_stats = {}  # STIX flow handles inactive nodes differently

        # Step 4: Create relationships
        logger.info("\n[LINK] Step 4: Creating relationships...")

        # Get relationships from MITRE collector
        relationships = self.mitre_collector.get_relationships()
        logger.info(f"   Found {len(relationships)} relationships to process")

        rel_stats = {"uses": 0, "attributed_to": 0}

        # Create relationships from MITRE collector
        # Track for debugging and derived relationships
        actor_uses_malware = []  # For deriving ATTRIBUTED_TO
        missing_techniques = set()

        for rel in relationships:
            try:
                if rel["type"] == "uses":
                    if rel["source_type"] in ["actor", "malware"] and rel["target_type"] == "technique":
                        success = self.neo4j.create_actor_technique_relationship(
                            rel["source_name"], rel["target_mitre_id"], source_id="mitre_attck"
                        )
                        if success:
                            rel_stats["uses"] += 1
                        else:
                            missing_techniques.add(rel["target_mitre_id"])
                    # Track actor/malware -> malware for deriving ATTRIBUTED_TO
                    elif rel["source_type"] in ["actor", "malware"] and rel["target_type"] == "malware":
                        actor_uses_malware.append(
                            {
                                "actor": rel["source_name"],
                                "malware": rel["target_name"],
                                "source_type": rel["source_type"],
                            }
                        )
                elif rel["type"] == "attributed_to":
                    if rel["source_type"] == "malware" and rel["target_type"] == "actor":
                        self.neo4j.create_malware_actor_relationship(
                            rel["source_name"], rel["target_name"], source_id="mitre_attck"
                        )
                        rel_stats["attributed_to"] += 1
            except Exception as e:
                logger.warning(f"   [WARN] Failed to create relationship: {e}")

        # Log missing techniques for debugging
        if missing_techniques:
            logger.info(
                f"   ℹ️ {len(missing_techniques)} techniques not found in Neo4j (sample: {list(missing_techniques)[:5]})"
            )

        # Derive ATTRIBUTED_TO: if Actor uses Malware, then Malware is attributed to Actor
        logger.info(f"   ℹ️ Deriving {len(actor_uses_malware)} ATTRIBUTED_TO relationships from 'uses malware'...")
        derived_attributed = 0
        for rel in actor_uses_malware:
            try:
                if rel["malware"] and rel["actor"]:
                    success = self.neo4j.create_malware_actor_relationship(
                        rel["malware"], rel["actor"], source_id="mitre_derived"
                    )
                    if success:
                        derived_attributed += 1
            except Exception as e:
                logger.debug(f"   ATTRIBUTED_TO derive error for {rel.get('malware')} → {rel.get('actor')}: {e}")
        logger.info(f"   [OK] Derived {derived_attributed} ATTRIBUTED_TO relationships")

        # Create INDICATES/EXPLOITS via MISP event co-occurrence and CVE tag matching
        logger.info("   ℹ️ Creating INDICATES/EXPLOITS relationships (MISP event co-occurrence)...")
        indicates_created = self._create_indicates_relationships()
        logger.info(f"   [OK] Created {indicates_created} INDICATES relationships")

        logger.info(f"   [OK] Created {rel_stats['uses']} USES relationships")
        logger.info(f"   [OK] Created {rel_stats['attributed_to']} ATTRIBUTED_TO relationships")

        # Step 5: Enrich existing indicators from multiple sources
        logger.info("\n[TARGET] Step 5: Enriching indicators (A/B test)...")
        try:
            from enrichment import EnrichmentEngine

            enricher = EnrichmentEngine(self.neo4j)
            enriched = enricher.enrich_all_indicators(limit=50)
            logger.info(f"   [OK] Enriched {enriched} indicators with additional sources")
        except Exception as e:
            logger.warning(f"   [WARN] Enrichment skipped: {e}")

        # Step 6: Get final stats
        logger.info("\n[STATS] Step 6: Final Statistics...")
        stats = self.neo4j.get_stats()

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Check if anything is actually in Neo4j (use real counts, not pipeline counters)
        total_loaded = sum(
            stats.get(k, 0) for k in ("Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique")
        )

        logger.info("\n" + "=" * 60)
        if total_loaded > 0:
            logger.info("[OK] EdgeGuard Pipeline Complete!")
        else:
            logger.error("[FAIL] EdgeGuard Pipeline Complete — BUT 0 NODES LOADED TO NEO4J!")
            logger.error("       Data was collected to MISP but NOT synced to Neo4j.")
            logger.error("       Check Neo4j connectivity: docker compose ps neo4j")
        logger.info("=" * 60)
        logger.info(f"\n⏱️  Total time: {elapsed:.1f} seconds")
        logger.info("\n[STATS] Nodes loaded:")
        logger.info(f"   - Vulnerabilities: {loaded['vulnerabilities']}")
        logger.info(f"   - Indicators: {loaded['indicators']}")
        logger.info(f"   - Malware: {loaded['malware']}")
        logger.info(f"   - Threat Actors: {loaded['actors']}")
        logger.info(f"   - Techniques: {loaded['techniques']}")

        # Calculate total relationships
        total_indicates = loaded.get("relationships_indicates", 0)
        total_attributed_to = loaded.get("relationships_attributed_to", 0) + rel_stats.get("attributed_to", 0)
        total_uses = rel_stats.get("uses", 0)

        logger.info("\n[STATS] Relationships created:")
        logger.info(f"   - USES (Actor/Malware → Technique): {total_uses}")
        logger.info(f"   - ATTRIBUTED_TO (Malware → Actor): {total_attributed_to}")
        logger.info(f"   - INDICATES (Indicator → Malware): {total_indicates}")

        # Report inactive nodes if available
        if inactive_stats:
            logger.info("\n[STATS] Stale nodes marked inactive:")
            logger.info(f"   - Indicators: {inactive_stats.get('indicators_marked_inactive', 0)}")
            logger.info(f"   - Vulnerabilities: {inactive_stats.get('vulnerabilities_marked_inactive', 0)}")

        logger.info("\n[STATS] By zone:")
        for zone, count in stats.get("by_zone", {}).items():
            logger.info(f"   - {zone}: {count}")

        logger.info("\n[NET] Neo4j Browser: http://localhost:7474")
        logger.info("   User: neo4j / <configured via NEO4J_PASSWORD>")

        # Close connection
        self.neo4j.close()

        # Step 7: Export to STIX 2.1 if requested
        if stix_export or stix_event_id:
            logger.info("\n[PUSH] Step 7: Exporting to STIX 2.1 format...")

            if stix_event_id:
                # Export single event
                stix_bundle = self.export_single_event_to_stix21(stix_event_id)
                if "error" not in stix_bundle:
                    output_file = stix_output or f"stix_event_{stix_event_id}.json"
                    with open(output_file, "w") as f:
                        json.dump(stix_bundle, f, indent=2)
                    logger.info(f"   [OK] Single event exported to: {output_file}")
                    logger.info(f"   [STATS] Objects in bundle: {len(stix_bundle.get('objects', []))}")
            else:
                # Export all events
                stix_bundle = self.export_to_stix21(output_path=stix_output)
                if "error" not in stix_bundle:
                    logger.info("   [OK] STIX 2.1 export complete")
                    logger.info(f"   [STATS] Total objects: {len(stix_bundle.get('objects', []))}")

        if use_stix_flow:
            return total_loaded > 0
        # Non-STIX flow: pipeline only pushes to MISP (Step 2).
        # Neo4j sync is handled separately (Airflow edgeguard_neo4j_sync DAG).
        # Return True if collection ran (regardless of Neo4j state).
        return True


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description="EdgeGuard Pipeline - Orchestrates threat intel collection and STIX 2.1 export"
    )
    parser.add_argument(
        "--stix", action="store_true", help="Export MISP events to STIX 2.1 format after pipeline completion"
    )
    parser.add_argument(
        "--stix-output",
        type=str,
        default="edgeguard_stix21.json",
        help="Output file path for STIX 2.1 bundle (default: edgeguard_stix21.json)",
    )
    parser.add_argument(
        "--stix-event",
        type=str,
        metavar="EVENT_ID",
        help="Export a specific MISP event to STIX 2.1 format (provide event ID)",
    )
    parser.add_argument(
        "--stix-flow",
        action="store_true",
        default=True,  # STIX flow is now the default
        help="Use STIX 2.1 as intermediate format in pipeline (MISP → STIX → Neo4j) [default: enabled]",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        default=False,
        help="Collect available, historical data (all not just latest). Default: False (latest updates only)",
    )
    _bd_default = 730  # Match Airflow DAG default (2 years)
    _bd_env = os.environ.get("EDGEGUARD_BASELINE_DAYS", "").strip()
    if _bd_env:
        try:
            _bd_default = int(_bd_env)
        except ValueError:
            pass
    parser.add_argument(
        "--baseline-days",
        type=int,
        default=_bd_default,
        help="How many days back for baseline mode (default: 365, or EDGEGUARD_BASELINE_DAYS if set)",
    )
    parser.add_argument(
        "--fresh-baseline",
        action="store_true",
        default=False,
        help="True clean slate: clear Neo4j graph + MISP events + checkpoints, then re-collect (use with --baseline)",
    )

    args = parser.parse_args()

    # Validate STIX flow is available
    if args.stix_flow and not STIX_AVAILABLE:
        print("\n⚠️  Warning: --stix-flow requested but STIX library not available.")
        print("   Install with: pip install stix2 pymisp")
        print("   Falling back to direct MISP → Neo4j flow...")

    pipeline = EdgeGuardPipeline()
    success = pipeline.run(
        stix_export=args.stix,
        stix_output=args.stix_output,
        stix_event_id=args.stix_event,
        use_stix_flow=args.stix_flow,
        baseline=args.baseline,
        baseline_days=args.baseline_days,
        fresh_baseline=args.fresh_baseline,
    )

    if success:
        print("\n🎉 Pipeline completed successfully!")
        if args.stix_flow:
            print("🔄 STIX 2.1 pipeline flow was used")
        if args.stix or args.stix_event:
            print(f"📤 STIX 2.1 export: {'Enabled' if args.stix else f'Event {args.stix_event}'}")
    else:
        print("\n❌ Pipeline failed. Check logs.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
