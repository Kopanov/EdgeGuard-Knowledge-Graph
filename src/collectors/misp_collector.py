#!/usr/bin/env python3
"""
EdgeGuard Prototype - MISP Collector
Collects events from local MISP instance

PR-M2 §4-Agent4: 10 wall-clock-NOW fallbacks of the form
``event.get("date", datetime.now(timezone.utc).isoformat())`` were
replaced with the honest-NULL form ``(event.get("date") or None)``
across this file (lines 248, 282, 302, 346, 373, 396, 422, 443, 465,
484 in the pre-PR-M2 layout). The previous form silently substituted
today's wall-clock for the ``first_seen`` of every re-synced MISP
attribute whose source event lacked a ``date`` field — corrupting
the source-truthful chronology of the indicators on the SOURCED_FROM
edge MIN-CASE forever. The honest-NULL form lets ``coerce_iso(None)``
produce None downstream so the MIN-CASE preserves any prior real value.
See docs/TIMESTAMPS.md "Invariant 1 — Honest NULL".
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
import re

import requests

from config import (
    DEFAULT_SECTOR,
    MISP_API_KEY,
    MISP_URL,
    SOURCE_TAGS,
    SSL_VERIFY,
    apply_misp_http_host_header,
    detect_zones_from_text,
    resolve_collection_limit,
)

logger = logging.getLogger(__name__)


class MISPCollector:
    # Source mapping from MISP tags to original source names
    SOURCE_TAG_MAPPING = {
        "AlienVault-OTX": "alienvault_otx",
        "NVD": "nvd",
        "CISA-KEV": "cisa_kev",
        "MITRE-ATT&CK": "mitre_attck",
        "VirusTotal": "virustotal",
        "AbuseIPDB": "abuseipdb",
        "Feodo-Tracker": "feodo",
        "SSL-Blacklist": "sslbl",
        "URLhaus": "urlhaus",
        "CyberCure": "cybercure",
        "ThreatFox": "threatfox",
    }

    def __init__(self):
        self.url = MISP_URL
        self.api_key = MISP_API_KEY
        self.tag = SOURCE_TAGS["misp"]

        # Persistent session: reuses TCP connections across the many per-event
        # GETs, avoiding the overhead of a fresh handshake for every request.
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self.session.verify = SSL_VERIFY
        apply_misp_http_host_header(self.session)

    def detect_sectors(self, text):
        """Detect ALL sectors from text (tags, description) using common zone detection.

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        return detect_zones_from_text(text)

    def extract_original_source(self, tags):
        """
        Extract the original source from MISP tags.

        MISP events/attributes often have tags like 'source:AlienVault-OTX' or
        'AlienVault-OTX' that indicate the original data source before it was
        ingested into MISP.

        Args:
            tags: List of tag dictionaries or strings from MISP

        Returns:
            Original source name (e.g., 'alienvault_otx') or None if not found
        """
        if not tags:
            return None

        for tag in tags:
            # Handle both dict and string formats
            tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)

            # Check for source: prefix tags
            if tag_name.startswith("source:"):
                source_name = tag_name.replace("source:", "").strip()
                return self.SOURCE_TAG_MAPPING.get(source_name, source_name.lower().replace(" ", "_"))

            # Check direct mappings (e.g., 'AlienVault-OTX')
            if tag_name in self.SOURCE_TAG_MAPPING:
                return self.SOURCE_TAG_MAPPING[tag_name]

            # Check if tag contains source-related keywords
            for source_key, source_value in self.SOURCE_TAG_MAPPING.items():
                if source_key.lower() in tag_name.lower():
                    return source_value

        return None

    # ------------------------------------------------------------------
    # Zone-extraction helpers (defined at class level, not inside the loop)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_zones_from_tags(tags_list):
        """Return all zone names found in a list of MISP tag dicts/strings."""
        zones = []
        for tag in tags_list:
            tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
            if tag_name.startswith("zone:"):
                zone_name = tag_name.replace("zone:", "").lower().strip()
                if zone_name:
                    zones.append(zone_name)
        return zones

    def _get_item_zones(self, item_tags, fallback_event_json: str = ""):
        """Return (primary_zone, zones_list) for a MISP item.

        Priority:
        1. Explicit ``zone:`` tags on the item.
        2. ``fallback_event_json`` text-based sector detection.
        3. ``DEFAULT_SECTOR``.
        """
        zones = self._extract_zones_from_tags(item_tags)
        if zones:
            return zones[0], zones
        detected = self.detect_sectors(fallback_event_json) if fallback_event_json else []
        if detected:
            return detected[0], detected
        return DEFAULT_SECTOR, [DEFAULT_SECTOR]

    def collect(self, limit=None):
        """Collect events from MISP — indicators, vulnerabilities, threat actors, techniques, malware.

        Uses a persistent :class:`requests.Session` to reuse TCP connections
        across the per-event detail fetches, eliminating per-request
        handshake overhead.

        Returns:
            tuple: (list of all node-type dicts, set of active event IDs)
        """
        limit = resolve_collection_limit(limit, "misp", baseline=False)

        MAX_ATTRIBUTES_PER_EVENT = 500
        PROGRESS_INTERVAL = 5

        try:
            # limit=0 means unlimited; cap the event index fetch to avoid huge single responses
            if limit and limit > 0:
                fetch_limit = min(limit * 3, 2000)
            else:
                fetch_limit = 2000
            logger.info(f"MISP: Starting collection (limit={limit}, fetching up to {fetch_limit} events)...")

            # --- 1. Fetch event index -------------------------------------------
            response = self.session.get(
                f"{self.url}/events",
                params={"limit": fetch_limit},
                timeout=30,
            )

            if response.status_code != 200:
                logger.error(f"MISP API error: {response.status_code}")
                return [], set()

            events = response.json()
            if isinstance(events, dict):
                events = events.get("events", [])

            logger.info(f"   Found {len(events)} events in MISP")

            active_event_ids = set()
            counts = {
                "indicators": 0,
                "vulnerabilities": 0,
                "threat_actors": 0,
                "techniques": 0,
                "malware": 0,
            }
            processed = []
            events_to_process = events[:fetch_limit]
            logger.info(
                f"   Processing up to {len(events_to_process)} events "
                f"(max {MAX_ATTRIBUTES_PER_EVENT} attributes each)..."
            )

            # --- 2. Fetch full detail for each event (session reuse) -----------
            for idx, event in enumerate(events_to_process):
                event_id = event.get("id")
                if not event_id:
                    continue

                if (idx + 1) % PROGRESS_INTERVAL == 0 or idx == 0:
                    logger.info(f"   Processing event {idx + 1}/{len(events_to_process)} (ID: {event_id})...")

                active_event_ids.add(str(event_id))

                full_response = self.session.get(
                    f"{self.url}/events/{event_id}",
                    timeout=30,
                )
                if full_response.status_code == 200:
                    full_event = full_response.json().get("Event", {})
                else:
                    full_event = event

                event_tags = full_event.get("Tag", [])
                original_source = self.extract_original_source(event_tags)
                source = original_source if original_source else self.tag
                sources = [source]

                # Cache serialised event text for text-based zone fallback
                event_text_lower = json.dumps(full_event).lower()

                # === INDICATORS (attributes) ===
                attributes = full_event.get("Attribute", [])
                if len(attributes) > MAX_ATTRIBUTES_PER_EVENT:
                    logger.warning(
                        f"      Event {event_id} has {len(attributes)} attributes "
                        f"(limiting to {MAX_ATTRIBUTES_PER_EVENT})"
                    )

                # === INDICATORS + CVEs in a single pass ===
                # Extract any CVE mentioned in the event title first.
                cve_id = self.extract_cve(event.get("info", ""))
                if cve_id:
                    _, zones = self._get_item_zones(event_tags, event_text_lower)
                    processed.append(
                        {
                            "node_type": "vulnerability",
                            "cve_id": cve_id,
                            "description": event.get("info", "")[:500],
                            "zone": zones,
                            "tag": source,
                            "source": sources,
                            "first_seen": (event.get("date") or None),
                            "confidence_score": 0.5,
                            "severity": "UNKNOWN",
                            "cvss_score": 0.0,
                            "attack_vector": "NETWORK",
                            "misp_event_id": str(event_id),
                        }
                    )
                    counts["vulnerabilities"] += 1

                for attr in attributes[:MAX_ATTRIBUTES_PER_EVENT]:
                    attr_tags = attr.get("Tag", [])
                    all_tags = event_tags + attr_tags
                    attr_source = self.extract_original_source(all_tags) or source

                    attr_zones = self._extract_zones_from_tags(all_tags)
                    zones = attr_zones if attr_zones else self.detect_sectors(event_text_lower)

                    # If this attribute carries a CVE, emit a structured vulnerability node
                    # in addition to (or instead of) a generic indicator.
                    attr_type = attr.get("type", "")
                    # PR-N5 B4 (Bug Hunter F3, audit 09): defensive
                    # str-coerce. A buggy MISP relay returning
                    # ``value: 12345`` (int, not str) would crash the
                    # next line's ``.lower()`` with AttributeError
                    # mid-batch, killing the whole event's processing.
                    #
                    # PR-N5 R1 Bugbot LOW (2026-04-21): earlier form
                    # ``str(attr.get("value", "") or "")`` had a latent
                    # falsy-int bug — ``0 or ""`` evaluates to ``""``
                    # because ``0`` is falsy, so an integer zero value
                    # silently became an empty string instead of ``"0"``.
                    # Explicit ``is not None`` check handles zero / False
                    # correctly; only None falls to the empty-string path.
                    _raw_value = attr.get("value")
                    attr_value = str(_raw_value) if _raw_value is not None else ""
                    if attr_type == "vulnerability" or "cve" in attr_value.lower():
                        cve_val = self.extract_cve(attr_value)
                        if cve_val:
                            processed.append(
                                {
                                    "node_type": "vulnerability",
                                    "cve_id": cve_val,
                                    "description": attr.get("comment", "")[:500] or "CVE from MISP attribute",
                                    "zone": zones,
                                    "tag": attr_source,
                                    "source": [attr_source],
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.6,
                                    "severity": "UNKNOWN",
                                    "cvss_score": 0.0,
                                    "attack_vector": "NETWORK",
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["vulnerabilities"] += 1
                            continue  # don't also emit as a generic indicator

                    processed.append(
                        {
                            "node_type": "indicator",
                            "indicator_type": self.map_attribute_type(attr_type),
                            "value": attr_value,
                            "zone": zones,
                            "tag": attr_source,
                            "source": [attr_source],
                            "first_seen": (event.get("date") or None),
                            "confidence_score": 0.5,
                            "source_event": event.get("id"),
                            "misp_event_id": str(event_id),
                            # MISP attribute UUID — stable cross-instance identifier.
                            # Aligned 2026-04 with run_misp_to_neo4j.py (the production
                            # path); previously used attr.id (numeric, per-instance auto-
                            # increment) which was not portable across MISP instances.
                            "misp_attribute_id": str(attr.get("uuid", "") or ""),
                            "misp_tags": [t.get("name", "") if isinstance(t, dict) else str(t) for t in all_tags],
                        }
                    )
                    counts["indicators"] += 1

                # === OBJECTS (Threat Actors, Malware, Techniques) ===
                objects = full_event.get("Object", [])
                for obj in objects:
                    obj_name = obj.get("name", "").lower()
                    obj_attributes = {
                        a.get("object_relation", ""): a.get("value", "") for a in obj.get("Attribute", [])
                    }
                    obj_tags = obj.get("Tag", [])
                    all_obj_tags = event_tags + obj_tags
                    obj_source = self.extract_original_source(all_obj_tags) or source
                    _, zones = self._get_item_zones(all_obj_tags, event_text_lower)

                    # THREAT ACTOR objects
                    if obj_name in ["threat-actor", "threatactor", "actor"]:
                        actor_name = (
                            obj_attributes.get("name")
                            or obj_attributes.get("aliases")
                            or obj.get("meta-category", "Unknown")
                        )
                        if actor_name and actor_name != "Unknown":
                            processed.append(
                                {
                                    "node_type": "threat_actor",
                                    "name": actor_name,
                                    "aliases": obj_attributes.get("aliases", ""),
                                    "description": obj_attributes.get("description", "")[:500],
                                    "zone": zones,
                                    "tag": obj_source,
                                    "source": [obj_source],  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.6,
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["threat_actors"] += 1

                    # MALWARE objects
                    elif obj_name in ["malware", "virus", "trojan"]:
                        malware_name = (
                            obj_attributes.get("malware-type")
                            or obj_attributes.get("name")
                            or obj_attributes.get("aliases")
                            or "Unknown"
                        )
                        if malware_name and malware_name != "Unknown":
                            processed.append(
                                {
                                    "node_type": "malware",
                                    "name": malware_name,
                                    "malware_types": obj_attributes.get("type", ""),
                                    "family": obj_attributes.get("family", ""),
                                    "description": obj_attributes.get("description", "")[:500],
                                    "zone": zones,
                                    "tag": obj_source,
                                    "source": [obj_source],  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.6,
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["malware"] += 1

                    # ATTACK PATTERN / TECHNIQUE objects (MITRE ATT&CK)
                    elif obj_name in ["attack-pattern", "attackpattern", "mitre-attack"]:
                        tech_id = obj_attributes.get("id") or obj_attributes.get("mitre-attack-id") or ""
                        tech_name = obj_attributes.get("name") or obj_attributes.get("summary", "Unknown")
                        if tech_id or tech_name != "Unknown":
                            processed.append(
                                {
                                    "node_type": "technique",
                                    "mitre_id": tech_id,
                                    "name": tech_name,
                                    "description": obj_attributes.get("description", "")[:500],
                                    "platforms": obj_attributes.get("platforms", ""),
                                    "zone": zones,
                                    "tag": obj_source,
                                    "source": [obj_source],  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.7,  # Higher confidence for MITRE
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["techniques"] += 1

                # === GALAXY TAGS (MITRE ATT&CK) ===
                _, zones = self._get_item_zones(event_tags, event_text_lower)
                for tag in event_tags:
                    tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)

                    # MITRE ATT&CK Technique tags: "misp-galaxy:mitre-attack-pattern="
                    if "mitre-attack-pattern" in tag_name.lower():
                        technique_data = self.parse_mitre_galaxy_tag(tag_name)
                        if technique_data:
                            processed.append(
                                {
                                    "node_type": "technique",
                                    "mitre_id": technique_data.get("id", ""),
                                    "name": technique_data.get("name", ""),
                                    "description": technique_data.get("description", "")[:500],
                                    "zone": zones,
                                    "tag": source,
                                    "source": sources,  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.8,
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["techniques"] += 1

                    # MITRE ATT&CK Threat Actor tags: "misp-galaxy:mitre-threat-actor="
                    elif "mitre-threat-actor" in tag_name.lower() or "threat-actor" in tag_name.lower():
                        actor_name = tag_name.split("=")[-1].strip('"') if "=" in tag_name else tag_name
                        if actor_name and actor_name != tag_name:
                            processed.append(
                                {
                                    "node_type": "threat_actor",
                                    "name": actor_name,
                                    "aliases": "",
                                    "description": f"Threat actor from MISP galaxy: {tag_name}",
                                    "zone": zones,
                                    "tag": source,
                                    "source": sources,  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.7,
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["threat_actors"] += 1

                    # MITRE Malware tags: "misp-galaxy:mitre-malware="
                    elif "mitre-malware" in tag_name.lower():
                        malware_name = tag_name.split("=")[-1].strip('"') if "=" in tag_name else tag_name
                        if malware_name and malware_name != tag_name:
                            processed.append(
                                {
                                    "node_type": "malware",
                                    "name": malware_name,
                                    "malware_types": "",
                                    "family": malware_name,
                                    "description": f"Malware from MISP galaxy: {tag_name}",
                                    "zone": zones,
                                    "tag": source,
                                    "source": sources,  # Source as array (like zone)
                                    "first_seen": (event.get("date") or None),
                                    "confidence_score": 0.7,
                                    "misp_event_id": str(event_id),
                                }
                            )
                            counts["malware"] += 1

                    # Extract CVE from tags too
                    cve_from_tag = self.extract_cve(tag_name)
                    if cve_from_tag:
                        processed.append(
                            {
                                "node_type": "vulnerability",
                                "cve_id": cve_from_tag,
                                "description": f"CVE from MISP tag: {tag_name}",
                                "zone": zones,
                                "tag": source,
                                "source": sources,  # Source as array (like zone)
                                "first_seen": (event.get("date") or None),
                                "confidence_score": 0.5,
                                "severity": "UNKNOWN",
                                "cvss_score": 0.0,
                                "attack_vector": "NETWORK",
                                "misp_event_id": str(event_id),
                            }
                        )
                        counts["vulnerabilities"] += 1

            logger.info(f"   Deduplicating {len(processed)} processed items...")

            # Deduplicate based on node type and key identifier
            seen = set()
            unique = []
            dedup_interval = max(1, len(processed) // 10)  # Log progress every 10%

            for idx, item in enumerate(processed):
                # Progress logging for large datasets
                if (idx + 1) % dedup_interval == 0:
                    logger.info(
                        f"      Deduplicating... {idx + 1}/{len(processed)} ({(idx + 1) * 100 // len(processed)}%)"
                    )

                node_type = item.get("node_type", "indicator")
                if node_type == "indicator" and item.get("value"):
                    key = f"indicator:{item.get('indicator_type')}:{item.get('value')}"
                elif node_type == "vulnerability" and item.get("cve_id"):
                    key = f"vulnerability:{item.get('cve_id')}"
                elif node_type == "threat_actor" and item.get("name"):
                    key = f"threat_actor:{item.get('name')}"
                elif node_type == "malware" and item.get("name"):
                    key = f"malware:{item.get('name')}"
                elif node_type == "technique" and (item.get("mitre_id") or item.get("name")):
                    key = f"technique:{item.get('mitre_id')}:{item.get('name')}"
                else:
                    continue

                if key not in seen:
                    seen.add(key)
                    unique.append(item)

            # Log detailed counts
            logger.info(f"[OK] MISP: Processed {len(unique)} unique nodes from {len(active_event_ids)} events")
            logger.info(
                f"   - Indicators: {counts['indicators']} -> {sum(1 for u in unique if u.get('node_type') == 'indicator')}"
            )
            logger.info(
                f"   - Vulnerabilities: {counts['vulnerabilities']} -> {sum(1 for u in unique if u.get('node_type') == 'vulnerability')}"
            )
            logger.info(
                f"   - Threat Actors: {counts['threat_actors']} -> {sum(1 for u in unique if u.get('node_type') == 'threat_actor')}"
            )
            logger.info(
                f"   - Techniques: {counts['techniques']} -> {sum(1 for u in unique if u.get('node_type') == 'technique')}"
            )
            logger.info(
                f"   - Malware: {counts['malware']} -> {sum(1 for u in unique if u.get('node_type') == 'malware')}"
            )

            return unique, active_event_ids

        except Exception as e:
            logger.error(f"MISP collection error: {e}")
            return [], set()

    def map_attribute_type(self, attr_type):
        """Map MISP attribute types to standard"""
        mapping = {
            "ip-src": "ipv4",
            "ip-dst": "ipv4",
            "domain": "domain",
            "url": "url",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "email-src": "email",
            "email-dst": "email",
            "hostname": "domain",
            "uri": "url",
        }
        mapped = mapping.get(attr_type)
        if mapped is None:
            # PR #34 round 18: surface unmapped MISP attribute types instead
            # of silently returning "unknown". The counter lets an operator
            # see which types are dropping into the bucket — useful when MISP
            # adds a new attribute type and EdgeGuard's mapping needs to
            # catch up.
            try:
                from metrics_server import record_misp_unmapped_attribute_type

                record_misp_unmapped_attribute_type(attr_type or "<empty>")
            except Exception:
                pass
            logger.debug("MISP attribute type %r is not mapped — falling back to 'unknown'", attr_type)
            return "unknown"
        return mapped

    def extract_cve(self, text):
        """Extract CVE ID from text"""
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
        if cve_match:
            return cve_match.group(0).upper()
        return None

    def parse_mitre_galaxy_tag(self, tag_name):
        """Parse MITRE ATT&CK galaxy tags to extract technique ID and name.

        MISP galaxy tags look like:
        - misp-galaxy:mitre-attack-pattern="Access Token Manipulation - T1134"
        - misp-galaxy:mitre-attack-pattern="Account Discovery - T1087"

        Returns dict with 'id' and 'name' or None if not parseable.
        """
        # Pattern: "Technique Name - T1234" at the end of the tag
        # Extract T#### format
        mitre_match = re.search(r'-\s*(T\d{4}(?:\.\d{3})?)\s*"?$', tag_name)
        if mitre_match:
            mitre_id = mitre_match.group(1)
            # Extract name from the tag value
            if "=" in tag_name:
                name_part = tag_name.split("=")[-1].strip('"')
                # Remove the "- T####" suffix
                name = re.sub(r"\s*-\s*T\d{4}(?:\.\d{3})?\s*$", "", name_part).strip()
                return {"id": mitre_id, "name": name}

        # Try another pattern: just look for T#### anywhere
        mitre_match = re.search(r"(T\d{4}(?:\.\d{3})?)", tag_name)
        if mitre_match:
            mitre_id = mitre_match.group(1)
            if "=" in tag_name:
                name = tag_name.split("=")[-1].strip('"')
                return {"id": mitre_id, "name": name}

        return None


def test_misp():
    """Test MISP collection"""
    collector = MISPCollector()
    results, event_ids = collector.collect(limit=50)
    print(f"\n📥 MISP Test: Collected {len(results)} items from {len(event_ids)} events")
    return results, event_ids


if __name__ == "__main__":
    test_misp()
