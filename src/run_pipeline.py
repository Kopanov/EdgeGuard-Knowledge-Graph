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
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests

from collector_allowlist import collect_sources_allowlist_from_env, is_collector_enabled_by_allowlist
from collector_failure_alerts import report_collector_failure
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


# PR #35 commit 2: surface CLI-path collector failures to Prometheus + Slack
# (Vanko follow-up audit). Wrapped in a thin helper so the four except
# branches below stay readable AND so the call is best-effort: a metric
# emission failure never masks the underlying collector exception.
def _report_failure_with_metrics(source_name: str, exc: BaseException) -> None:
    """Best-effort dashboard-visibility for a CLI-path collector failure.

    Calls ``report_collector_failure`` from ``collector_failure_alerts``
    which:
      - classifies transient vs catastrophic via class-name walk
      - emits Prometheus metrics (collection-status, source-health,
        skip-counter, pipeline-error)
      - sends a Slack alert if EDGEGUARD_ENABLE_SLACK_ALERTS=1

    Wrapped in a try/except so a metrics-server outage or Slack 500
    doesn't break the CLI's own error reporting.
    """
    try:
        report_collector_failure(source_name, exc)
    except Exception as report_err:
        logging.getLogger(__name__).warning(
            "[%s] failure-reporting helper raised %s — continuing without dashboard signal",
            source_name,
            type(report_err).__name__,
        )


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

        # PR-C v2 audit fix (Cross-Checker B2): track build_relationships
        # degraded-mode for Step 5b. The CLI deliberately does NOT raise on
        # build_relationships exit != 0 (it would lose Step 5c); instead it
        # marks here so a downstream caller / test can detect.
        self._build_relationships_degraded: bool = False

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
            # are linked with INDICATES.  Works cross-source because every MISP-
            # derived node accumulates its event ids in misp_event_ids[].
            # Co-occurrence: batched via apoc.periodic.iterate (prevents OOM on 170K+ indicators).
            #
            # PR #33 round 10: dropped legacy scalar misp_event_id from both
            # filter and join. Outer filter only includes nodes with a non-
            # empty misp_event_ids array; inner join matches by array IN
            # membership.
            # PR #34 round 28 (bugbot MED): stamp r.src_uuid / r.trg_uuid on
            # both co-occurrence and EXPLOITS edges so the CLI path produces
            # the same cross-environment-traceable edges as the primary
            # build_relationships.py path. Without this, edges created via
            # run_pipeline.py CLI had NULL endpoint uuids, silently breaking
            # the delta-sync contract for any operator who preferred this
            # code path.
            cooccurrence_query = """
            CALL apoc.periodic.iterate(
                'MATCH (i:Indicator) WHERE i.misp_event_ids IS NOT NULL AND size(i.misp_event_ids) > 0 RETURN i',
                'WITH $i AS i
                 WITH i, [eid IN i.misp_event_ids WHERE eid IS NOT NULL AND eid <> ""][0..200] AS eids
                 UNWIND eids AS eid WITH i, eid
                 MATCH (m:Malware) WHERE m.misp_event_ids IS NOT NULL AND eid IN m.misp_event_ids
                 MERGE (i)-[r:INDICATES]->(m)
                 ON CREATE SET r.created_at = datetime(), r.source_id = "misp_cooccurrence", r.confidence_score = 0.5, r.src_uuid = i.uuid, r.trg_uuid = m.uuid
                 SET r.updated_at = datetime(),
                     r.src_uuid = coalesce(r.src_uuid, i.uuid),
                     r.trg_uuid = coalesce(r.trg_uuid, m.uuid)',
                {batchSize: 5000, parallel: false}
            )
            YIELD total
            RETURN total AS created
            """
            results = self.neo4j.run(cooccurrence_query)
            record = results[0] if results else None
            indicates_count = record.get("created", 0) if record else 0
            logger.info(f"   INDICATES (co-occurrence, batched): {indicates_count} relationships")

            time.sleep(3)  # Let Neo4j flush between relationship queries

            # Second pass: Indicators that explicitly mention a CVE are linked to
            # that CVE/Vulnerability via EXPLOITS (more specific than INDICATES).
            # EXPLOITS: batched via apoc.periodic.iterate
            exploits_query = """
            CALL apoc.periodic.iterate(
                'MATCH (i:Indicator) WHERE i.cve_id IS NOT NULL AND i.cve_id <> "" RETURN i',
                'WITH $i AS i
                 MATCH (c:CVE {cve_id: i.cve_id})
                 MERGE (i)-[r:EXPLOITS]->(c)
                 ON CREATE SET r.created_at = datetime(), r.source_id = "cve_tag_match", r.confidence_score = 0.9, r.src_uuid = i.uuid, r.trg_uuid = c.uuid
                 SET r.updated_at = datetime(),
                     r.src_uuid = coalesce(r.src_uuid, i.uuid),
                     r.trg_uuid = coalesce(r.trg_uuid, c.uuid)',
                {batchSize: 5000, parallel: false}
            )
            YIELD total
            RETURN total AS created
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
                        ok = self.neo4j.merge_cve(
                            {
                                "cve_id": vuln_name.upper(),
                                "description": obj.get("description", ""),
                                "cvss_score": None,  # None = unscored; 0.0 is a valid CVSS score
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

                    # Handle STIX "uses" predicate → EMPLOYS_TECHNIQUE (Actor)
                    # or IMPLEMENTS_TECHNIQUE (Malware/Tool). The STIX SRO
                    # type stays "uses" on input; we route to the right
                    # specialized edge based on the source type at write
                    # time. See 2026-04 refactor note in neo4j_client.py.
                    elif rel_type == "uses":
                        if src["type"] in ["actor", "malware"] and tgt["type"] == "technique":
                            if src["type"] == "actor":
                                self.neo4j.create_actor_technique_relationship(src["name"], tgt["mitre_id"])
                            # Malware→Technique (IMPLEMENTS_TECHNIQUE) is
                            # created post-sync by build_relationships.py
                            # from the uses_techniques property, not here.

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
                    # PR #33 round 13: upgraded debug → warning so the
                    # operator sees STIX export source-extraction failures
                    # in production logs (debug is invisible by default).
                    logger.warning(f"Could not extract source from event info '{event_info}': {e}")

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
        baseline_days: int | None = None,
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
            baseline_days: How many days back to collect in baseline mode. ``None``
                defers to ``baseline_config.resolve_baseline_days(explicit=None)`` —
                respects ``EDGEGUARD_BASELINE_DAYS`` env, then falls back to the
                shipped ``DEFAULT_BASELINE_DAYS`` (730). PR-C v2 audit fix
                (Maintainer H1 + Cross-Checker B1): the previous hardcoded 730
                literal was the very pattern ``baseline_config`` was meant to
                consolidate.
            fresh_baseline: If True with baseline, perform a true clean slate: clear Neo4j
                graph data, delete MISP EdgeGuard events, and discard checkpoints before
                re-collecting. Default False preserves existing data and checkpoints for resume.
        """
        if baseline_days is None:
            from baseline_config import resolve_baseline_days

            baseline_days = resolve_baseline_days(explicit=None)
        # ── Pipeline lock: prevent concurrent CLI runs ──
        # NOTE: This lock only protects CLI invocations (python run_pipeline.py).
        # Airflow DAGs use max_active_runs=1 for concurrency control instead.
        lock_dir = os.path.join(os.path.dirname(__file__), "..", "checkpoints")
        os.makedirs(lock_dir, exist_ok=True)
        lock_path = os.path.join(lock_dir, "pipeline.lock")

        # PR #38 (Bug Hunter Tier S S2): atomic lock acquisition via
        # ``O_CREAT|O_EXCL|O_WRONLY``. The previous TOCTOU pattern —
        # ``os.path.exists(lock_path)`` then ``with open(lock_path, "w")`` —
        # could let two CLI invocations both find no lock and both write
        # their PID, last writer wins. Two pipelines then ran concurrently,
        # racing MISP event creation and Neo4j MERGEs (the very condition
        # the lock was meant to prevent).
        #
        # ``O_EXCL`` is POSIX-defined as atomic create-or-fail: if the
        # file already exists, ``os.open`` raises ``FileExistsError`` AND
        # does NOT touch the existing file. No window for a racing process
        # to slip in. Stale-lock recovery (the "PID is gone" case) still
        # uses the read-then-unlink-then-retry pattern below — but the
        # final lock acquisition itself is atomic.
        def _read_lock_pid(path: str) -> Optional[int]:
            """Read the PID stored in the pipeline lock file, or None on any error.

            PR-A audit fix (Bug Hunter HIGH H2): used by ``_cleanup_lock``
            to verify the lock still belongs to THIS process before
            unlinking. Mirrors the read-then-compare-pid pattern in
            ``baseline_lock.release_baseline_lock``. Returns None for
            any read or parse error — caller treats None as "don't
            unlink" (safer than treating it as match).
            """
            try:
                with open(path) as fh:
                    return int(fh.read().strip())
            except (OSError, ValueError):
                return None

        def _try_atomic_lock_acquire(path: str) -> bool:
            """Single atomic create-or-fail attempt.

            Returns True iff THIS process now exclusively owns the lock
            file. Returns False on FileExistsError (someone else holds
            it). Returns False on write failure too — the partial sentinel
            is rolled back so a retry can proceed cleanly. Any other
            OSError on the create itself propagates to the caller.

            PR #38 commit X (bugbot MED): added the write-failure
            rollback. Previously a write OSError propagated up
            uncaught while the empty/partial lock file lingered on
            disk → next CLI invocation would see a "live" lock and
            refuse to start, even though the prior process never
            actually held it. Mirrors the baseline_lock.py pattern.
            """
            try:
                # 0o644 — owner rw, others r (matches the previous open(..., "w") default)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except FileExistsError:
                return False
            except OSError as exc:
                # PR #38 commit X (bugbot MED): catch the broader OSError too.
                # PermissionError, ENOSPC (disk full), EROFS (read-only fs) etc.
                # would otherwise propagate UNCAUGHT through the caller — the
                # pipeline crashes with a stack trace instead of cleanly
                # refusing to start. Mirrors the baseline_lock.py pattern.
                logger.error(f"Failed to acquire pipeline lock at {path}: {exc}")
                return False
            write_failed = False
            try:
                os.write(fd, str(os.getpid()).encode("ascii"))
            except OSError as exc:
                logger.error(f"Failed to write pipeline-lock PID to {path}: {exc}")
                write_failed = True
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if write_failed:
                # Roll back the partial sentinel so the next attempt isn't blocked.
                try:
                    os.unlink(path)
                except OSError:
                    pass
                return False
            return True

        if not _try_atomic_lock_acquire(lock_path):
            # File exists. Read the PID, decide if it's stale, and possibly retry once.
            try:
                with open(lock_path) as f:
                    old_pid = int(f.read().strip())
            except (ValueError, OSError):
                # Lock file unreadable / malformed.
                #
                # PR #38 commit X (bugbot HIGH): age-gate the auto-recovery
                # to avoid the same TOCTOU race fixed in baseline_lock.py
                # (see ``_is_corrupt_sentinel`` docstring there for the
                # full scenario). Without an age check, Process B could
                # see Process A's mid-write empty file, unlink it, and
                # retry — both processes end up "holding" the lock.
                #
                # Refuse the auto-recovery if the file is fresh (< 5 min);
                # operator must manually delete a fresh lock that's
                # genuinely corrupt.
                _PIPELINE_LOCK_RECOVERY_AGE_SECS = 300
                try:
                    age_secs = time.time() - os.stat(lock_path).st_mtime
                except OSError:
                    age_secs = 0  # treat unstat-able as fresh → refuse
                if age_secs < _PIPELINE_LOCK_RECOVERY_AGE_SECS:
                    logger.error(
                        f"Lock file {lock_path} is unreadable BUT only {age_secs:.0f}s old — "
                        f"refusing to auto-recover (could race a competitor mid-write). "
                        f"Either wait {(_PIPELINE_LOCK_RECOVERY_AGE_SECS - age_secs):.0f}s or "
                        f"manually delete the file if you're sure it's stale."
                    )
                    return False
                logger.warning(
                    f"Lock file {lock_path} unreadable + {age_secs:.0f}s old — treating as stale and removing."
                )
                try:
                    os.unlink(lock_path)
                except OSError:
                    pass
                if not _try_atomic_lock_acquire(lock_path):
                    logger.error("Lost lock-acquisition race after stale-lock cleanup. Aborting.")
                    return False
            else:
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
                    try:
                        os.unlink(lock_path)
                    except OSError:
                        pass
                    # Single retry; if a competitor grabbed it in the gap, fail loudly.
                    if not _try_atomic_lock_acquire(lock_path):
                        logger.error(
                            "Lost lock-acquisition race after stale-lock cleanup — "
                            "another process grabbed the lock. Aborting."
                        )
                        return False

        import atexit
        import signal

        # Baseline runs also take an additional cross-process sentinel that
        # scheduled Airflow collector DAGs check before running. This
        # prevents a CLI baseline and a regularly-scheduled DAG task from
        # racing on MISP/Neo4j writes. Non-baseline runs do NOT take this
        # lock — they're expected to share the pipeline with Airflow.
        baseline_lock_held = False
        if baseline:
            from baseline_lock import acquire_baseline_lock

            if not acquire_baseline_lock():
                # Another baseline is already running — refuse to start.
                # Bugbot LOW (PR-A audit on f60e213 + 329559e): use the
                # ``_read_lock_pid`` helper rather than re-inlining the
                # PID-check logic. Despite its definition appearing
                # earlier-in-source than ``_cleanup_lock``, ``_read_lock_pid``
                # IS in scope here — both inner functions and the
                # ``acquire_baseline_lock`` failure path are in the same
                # ``run()`` body, and Python resolves nested-function names
                # via the enclosing scope at call time.
                # PR-A audit fix (Bugbot LOW on commit 8ab02ac): the previous
                # ``if existing_pid == os.getpid()`` else-branch fired with
                # ``existing_pid=None`` (lock missing/unreadable) and logged
                # a misleading "sentinel pid=None != current pid=X" — implying
                # a PID mismatch when the real cause was a missing/corrupt
                # file. Mirror ``_cleanup_lock``'s explicit None-guard so
                # the only warning fires on a genuine PID mismatch.
                existing_pid = _read_lock_pid(lock_path)
                if existing_pid is not None and existing_pid == os.getpid():
                    try:
                        os.remove(lock_path)
                    except OSError:
                        pass
                elif existing_pid is not None:
                    logger.warning(
                        "Not removing pipeline lock on baseline-acquire failure: sentinel pid=%s != current pid=%s",
                        existing_pid,
                        os.getpid(),
                    )
                # else: existing_pid is None — lock missing/unreadable;
                # don't remove and don't warn (no actionable information).
                return False
            baseline_lock_held = True

        def _cleanup_lock(*_args):
            # PR-A audit fix (Bug Hunter HIGH H2): only remove the lock file
            # if it still belongs to THIS process. Earlier code did a blind
            # ``os.remove(lock_path)`` — but the stale-PID recovery path
            # (lines 1027-1032) lets a competing process unlink-and-re-acquire
            # the same lock. Without the PID check, this process's atexit
            # handler then unlinks the OTHER process's freshly-acquired lock,
            # opening a window where a third invocation can also acquire.
            # Two pipelines run concurrently, racing MERGE. Mirrors the
            # release_baseline_lock pattern in src/baseline_lock.py.
            try:
                pid = _read_lock_pid(lock_path)
                if pid is not None and pid == os.getpid():
                    os.remove(lock_path)
                elif pid is not None:
                    logger.warning(
                        "Not removing pipeline lock: sentinel pid=%s != current pid=%s",
                        pid,
                        os.getpid(),
                    )
            except OSError:
                pass
            if baseline_lock_held:
                try:
                    from baseline_lock import release_baseline_lock as _release

                    _release()
                except Exception:
                    logger.debug("Baseline lock release failed", exc_info=True)

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
        baseline_days=None,
        fresh_baseline=False,
    ):
        """Inner pipeline logic, separated so the lock is always cleaned up.

        ``baseline_days=None`` defers to ``baseline_config.resolve_baseline_days``
        — same SSoT as the public ``run()`` method.
        """
        if baseline_days is None:
            from baseline_config import resolve_baseline_days

            baseline_days = resolve_baseline_days(explicit=None)
        # Import baseline checkpoint utilities. ``clear_checkpoint`` is still
        # used by the resume-completed-baseline branch below (line ~1152).
        from baseline_checkpoint import clear_checkpoint, get_baseline_status

        # Log baseline mode
        if baseline:
            logger.info(f"BASELINE MODE: Collecting historical data (last {baseline_days} days)")
            if fresh_baseline:
                # PR-C audit fix (Cross-Checker H3 + Prod Readiness HIGH): the
                # previous inline 3-step clean (checkpoints, Neo4j, MISP) lived
                # here as 80 LOC of paginated DELETE loops. It silently logged
                # warnings on partial failures (the ``except Exception`` blocks
                # at the previous lines 1134/1196), leaving operators with a
                # half-cleaned state that was harder to debug than a clean
                # failure. Replaced by the shared helper that wipes + settles
                # + verifies + raises BaselineCleanError on any step failure.
                # Same code path is now used by the new ``baseline_clean``
                # Airflow task (PR-C wires it in dags/edgeguard_pipeline.py).
                from baseline_clean import BaselineCleanError, reset_baseline_data

                try:
                    clean_result = reset_baseline_data()
                    logger.info(
                        "Fresh-baseline clean complete: deleted %d Neo4j nodes, "
                        "%d MISP events, %d checkpoint entries (%.1fs)",
                        clean_result.before.neo4j_count,
                        clean_result.before.misp_count,
                        clean_result.before.checkpoint_count,
                        clean_result.duration_seconds,
                    )
                except BaselineCleanError as e:
                    logger.error("Fresh-baseline clean FAILED: %s", e)
                    return False  # Refuse to run collectors on a half-cleaned state.

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
                # PR #35 commit 2: emit Prometheus + Slack visibility
                # so CLI-path failures are dashboard-visible, not just logged.
                _report_failure_with_metrics(source_name, e)
            except requests.exceptions.ConnectionError as e:
                msg = f"ConnectionError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - connection error (service down?)")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)
            except ImportError as e:
                msg = f"ImportError: {e}"
                logger.error(f"   [ERR] {source_name} collector failed - missing dependency: {e}")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)
            except Exception as e:
                msg = f"{type(e).__name__}: {e}"
                logger.error(f"   [ERR] {source_name} collector failed: {msg}")
                step2_exceptions.append((source_name, msg))
                _report_failure_with_metrics(source_name, e)

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
                    # After the 2026-04 USES→{EMPLOYS,IMPLEMENTS}_TECHNIQUE
                    # split, create_actor_technique_relationship writes
                    # EMPLOYS_TECHNIQUE matching only ThreatActor. Malware
                    # → Technique edges (IMPLEMENTS_TECHNIQUE) are built
                    # post-sync by build_relationships.py from the
                    # `uses_techniques` property on Malware nodes — skip
                    # them here rather than routing a malware source to
                    # the actor-only method.
                    if rel["source_type"] == "actor" and rel["target_type"] == "technique":
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

        logger.info(f"   [OK] Created {rel_stats['uses']} EMPLOYS_TECHNIQUE relationships (Actor→Technique)")
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

        # PR-C audit fix (Cross-Checker HIGH H1 + H2): CLI ↔ DAG parity.
        # The Airflow DAG runs ``build_relationships.py`` and
        # ``enrichment_jobs.run_all_enrichment_jobs`` after the sync — but
        # the CLI never invoked either. Operators running
        # ``python run_pipeline.py --baseline`` got a broken graph: no
        # IMPLEMENTS_TECHNIQUE / TARGETS / AFFECTS edges (the 12 link
        # queries in build_relationships.py were skipped), no Campaign
        # nodes, no IOC decay, no Vulnerability↔CVE bridges. Fixed by
        # invoking both here, gated to ``baseline=True`` to avoid
        # surprising incremental-mode CLI users with extra latency.
        if baseline:
            # Step 5b: build_relationships (12 cross-entity link queries).
            # Subprocess-isolated to match the DAG's invocation shape.
            logger.info("\n[TARGET] Step 5b: build_relationships (CLI parity with DAG)...")
            try:
                import subprocess

                br_result = subprocess.run(
                    [sys.executable, os.path.join(os.path.dirname(__file__), "build_relationships.py")],
                    capture_output=True,
                    text=True,
                    timeout=18000,  # 5h, matches DAG's run_build_relationships
                    check=False,
                )
                if br_result.returncode == 0:
                    logger.info("   [OK] build_relationships complete")
                else:
                    # PR-C v2 audit fix (Cross-Checker B2, comprehensive
                    # 7-agent audit): the previous comment claimed "same
                    # behavior as the DAG", but the DAG actually raises
                    # ``AirflowException`` on non-zero exit (see
                    # ``dags/edgeguard_pipeline.py``: ``run_build_relationships``
                    # at lines 1618-1633). The CLI deliberately diverges —
                    # local operators want a "degraded-mode finish" rather
                    # than a hard abort that loses Step 5c enrichment too.
                    # Acknowledge the asymmetry explicitly so the parity
                    # claim isn't a lie.
                    #
                    # Operator hint: the graph edges from build_relationships
                    # (12 link queries: IMPLEMENTS_TECHNIQUE, TARGETS,
                    # AFFECTS, ...) will be MISSING. Re-run
                    # ``python src/build_relationships.py`` standalone to
                    # complete the graph.
                    logger.warning(
                        "   [WARN] build_relationships exited with code %d. "
                        "Graph is in DEGRADED MODE (link edges missing). "
                        "DAG would have raised AirflowException; CLI continues "
                        "to allow Step 5c enrichment to run. "
                        "Re-run ``python src/build_relationships.py`` standalone to repair. "
                        "stderr (last 500 chars): %s",
                        br_result.returncode,
                        (br_result.stderr or "")[-500:],
                    )
                    # Mark on the pipeline instance so a downstream caller /
                    # test can detect degraded-mode without parsing logs.
                    self._build_relationships_degraded = True
            except Exception as e:
                logger.warning(f"   [WARN] build_relationships skipped: {e}")
                self._build_relationships_degraded = True

            # Step 5c: post-sync enrichment_jobs (4 jobs: decay, campaigns,
            # calibrate, bridge_vuln_cve). In-process because each job is
            # short-running and shares the existing Neo4jClient.
            logger.info("\n[TARGET] Step 5c: post-sync enrichment_jobs (CLI parity with DAG)...")
            try:
                from enrichment_jobs import run_all_enrichment_jobs

                summary = run_all_enrichment_jobs(self.neo4j)
                logger.info("   [OK] Enrichment jobs complete: %s", summary)
            except Exception as e:
                logger.warning(f"   [WARN] Enrichment jobs skipped: {e}")

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
        # rel_stats["uses"] only counts actor→technique edges created via
        # create_actor_technique_relationship (EMPLOYS_TECHNIQUE). Malware
        # and Tool → Technique edges (IMPLEMENTS_TECHNIQUE) are built by
        # build_relationships.py after the sync and are NOT reflected in
        # this counter — don't pretend otherwise in the log.
        total_employs_technique = rel_stats.get("uses", 0)

        logger.info("\n[STATS] Relationships created (this pipeline pass):")
        logger.info(f"   - EMPLOYS_TECHNIQUE (Actor → Technique): {total_employs_technique}")
        logger.info(
            "   - IMPLEMENTS_TECHNIQUE (Malware/Tool → Technique): built post-sync by "
            "build_relationships.py — see its own log line"
        )
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
    # PR-C v2 audit fix (Maintainer H1 + Cross-Checker B1, comprehensive
    # 7-agent audit): the SSoT module ``baseline_config.resolve_baseline_days``
    # was created in PR-C but only the new ``edgeguard.cmd_*`` callers used
    # it — the legacy CLI parser here, ``run_pipeline.run(baseline_days=730)``,
    # ``_run_pipeline_inner(baseline_days=730)``, and the DAG's
    # ``get_baseline_config`` all kept hardcoded 730 literals. Wire the SSoT
    # in here so the docstring's "single source of truth" claim is real.
    #
    # Cross-Checker D4: the previous help text said "default: 365" while
    # ``_bd_default = 730`` — corrected below.
    from baseline_config import DEFAULT_BASELINE_DAYS, resolve_baseline_days

    _bd_default = resolve_baseline_days(explicit=None)  # respects env, falls back to default
    parser.add_argument(
        "--baseline-days",
        type=int,
        default=_bd_default,
        help=(
            f"How many days back for baseline mode (default: {DEFAULT_BASELINE_DAYS}, "
            "or EDGEGUARD_BASELINE_DAYS env var if set)"
        ),
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
