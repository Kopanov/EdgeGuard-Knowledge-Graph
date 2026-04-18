#!/usr/bin/env python3
"""
EdgeGuard Prototype - MITRE ATT&CK Collector
Collects TTPs, tactics, and threat actors from MITRE ATT&CK and pushes to MISP
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from typing import Optional, Tuple

import requests

from baseline_checkpoint import get_source_incremental, update_source_incremental
from collectors.collector_utils import (
    RateLimiter,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    retry_with_backoff,
)

# Import MISP writer
from collectors.misp_writer import MISPWriter
from config import MITRE_USE_CONDITIONAL_GET, SOURCE_TAGS, SSL_VERIFY, detect_zones_from_text, resolve_collection_limit
from resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

# Circuit breaker for MITRE (very reliable but good to have)
MITRE_CIRCUIT_BREAKER = get_circuit_breaker("mitre", failure_threshold=3, recovery_timeout=1800)

# Rate limiter for MITRE (GitHub CDN rate limits apply)
MITRE_RATE_LIMITER = RateLimiter(min_interval=1.0)  # 1 request per second max

# Maximum number of ATT&CK relationships to store for Neo4j graph building.
# ATT&CK v14+ contains 11,000+ relationships; setting this to 0 means no cap.
# Override via the MITRE_MAX_RELATIONSHIPS environment variable.
import os as _os

MITRE_MAX_RELATIONSHIPS: int = int(_os.getenv("MITRE_MAX_RELATIONSHIPS", "0"))


class MITRECollector:
    """
    MITRE ATT&CK Collector.

    Flow: MITRE STIX → Process → Push to MISP → Return status
    Stores relationships for later Neo4j graph building.
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.tag = SOURCE_TAGS["mitre"]
        self.misp_writer = misp_writer or MISPWriter()
        self.relationships: list = []

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _download_stix_bundle(self, etag: Optional[str] = None) -> Tuple[Optional[dict], Optional[str]]:
        """Download the MITRE ATT&CK STIX bundle (~80 MB) with retry.

        Returns:
            (bundle, new_etag) on 200; (None, etag_sent) on 304 Not Modified.
        """
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        response = request_with_rate_limit_retries(
            "GET",
            self.attack_url,
            session=None,
            timeout=180,
            verify=SSL_VERIFY,
            max_rate_limit_retries=3,
            fallback_delay_sec=60.0,
            retry_on_403=False,
            context="MITRE",
            headers=headers,
        )
        if response.status_code == 304:
            logger.info("MITRE ATT&CK: HTTP 304 — STIX bundle unchanged (conditional GET)")
            return None, etag
        if response.status_code != 200:
            raise requests.exceptions.HTTPError(f"MITRE ATT&CK fetch error: {response.status_code}")
        new_etag = response.headers.get("ETag") or response.headers.get("etag")
        if new_etag:
            new_etag = new_etag.strip()
        return response.json(), new_etag

    def detect_sectors(self, text):
        """Detect ALL sectors from technique/actor description using common zone detection.

        Returns:
            List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
        """
        return detect_zones_from_text(text)

    def health_check(self) -> dict:
        """Check MITRE ATT&CK feed health."""
        if not MITRE_CIRCUIT_BREAKER.can_execute():
            return {
                "healthy": False,
                "error": "Circuit breaker open",
                "circuit_state": MITRE_CIRCUIT_BREAKER.state.name,
            }
        return {"healthy": True, "circuit_state": MITRE_CIRCUIT_BREAKER.state.name}

    def collect(self, limit=None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365):
        """
        Collect techniques and actors from MITRE ATT&CK and optionally push to MISP.

        Args:
            limit: Maximum number of items to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back to collect in baseline mode

        Returns:
            Dict with status and counts if push_to_misp=True, else list of processed items
        """
        limit = resolve_collection_limit(limit, "mitre", baseline=baseline)

        # Note: MITRE is a static dataset - baseline vs normal doesn't change much
        # But we pass the parameter anyway for consistency

        # Check circuit breaker
        if not MITRE_CIRCUIT_BREAKER.can_execute():
            logger.warning("MITRE circuit breaker open - skipping")
            return self._return_status(False, 0, "Circuit breaker open") if push_to_misp else []

        # Rate limiting
        MITRE_RATE_LIMITER.wait_if_needed()

        try:
            etag = None
            force_refetch = os.getenv("MITRE_FORCE_REFETCH", "").lower() in ("1", "true", "yes")
            if not baseline and not force_refetch and MITRE_USE_CONDITIONAL_GET:
                etag = (get_source_incremental("mitre").get("mitre_bundle_etag") or "").strip() or None

            bundle, new_etag = self._download_stix_bundle(etag=etag)

            if bundle is None:
                # 304 Not Modified — bundle unchanged. This is normal for incremental
                # runs, but if this is a clean start (no MITRE data in graph), warn
                # the operator and suggest clearing the ETag cache or using baseline mode.
                logger.info(
                    "MITRE ATT&CK: No new data (304 Not Modified). If this is a fresh install, "
                    'clear the checkpoint: python3 -c "from baseline_checkpoint import clear_checkpoint; '
                    "clear_checkpoint('mitre')\" or set MITRE_FORCE_REFETCH=true"
                )
                MITRE_CIRCUIT_BREAKER.record_success()
                if push_to_misp:
                    return self._return_status(True, 0, None, 0)
                return []

            objects = bundle.get("objects", [])

            logger.info(f"[FETCH] MITRE ATT&CK: Fetched {len(objects)} STIX objects")

            # Build ID mapping for relationships
            id_map = {}  # STIX ID -> {type, mitre_id, name}

            # First pass: build ID map
            for obj in objects:
                obj_type = obj.get("type", "")
                stix_id = obj.get("id", "")

                if obj_type == "attack-pattern":
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break
                    id_map[stix_id] = {"type": "technique", "mitre_id": mitre_id, "name": obj.get("name", "")}

                elif obj_type == "x-mitre-tactic":
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break
                    shortname = obj.get("x_mitre_shortname", "")
                    id_map[stix_id] = {
                        "type": "tactic",
                        "mitre_id": mitre_id,
                        "name": obj.get("name", ""),
                        "shortname": shortname,
                    }

                elif obj_type == "intrusion-set":
                    id_map[stix_id] = {"type": "actor", "name": obj.get("name", "")}

                elif obj_type == "malware":
                    id_map[stix_id] = {"type": "malware", "name": obj.get("name", "")}

                elif obj_type == "tool":
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break
                    id_map[stix_id] = {"type": "tool", "mitre_id": mitre_id, "name": obj.get("name", "")}

            # Second pass: extract relationships
            relationships = []
            for obj in objects:
                if obj.get("type") == "relationship":
                    src_ref = obj.get("source_ref", "")
                    tgt_ref = obj.get("target_ref", "")
                    rel_type = obj.get("relationship_type", "")

                    src = id_map.get(src_ref, {})
                    tgt = id_map.get(tgt_ref, {})

                    if src and tgt:
                        # Map STIX relationship to our graph relationship
                        if rel_type == "uses":
                            if src["type"] in ["actor", "malware", "tool"] and tgt["type"] == "technique":
                                relationships.append(
                                    {
                                        "type": "uses",
                                        "source_type": src["type"],
                                        "source_name": src["name"],
                                        "target_type": tgt["type"],
                                        "target_mitre_id": tgt.get("mitre_id", ""),
                                        "target_name": tgt["name"],
                                    }
                                )
                        elif rel_type == "subtechnique-of":
                            if src["type"] == "technique" and tgt["type"] == "technique":
                                relationships.append(
                                    {
                                        "type": "subtechnique_of",
                                        "source_type": src["type"],
                                        "source_mitre_id": src.get("mitre_id", ""),
                                        "source_name": src["name"],
                                        "target_type": tgt["type"],
                                        "target_mitre_id": tgt.get("mitre_id", ""),
                                        "target_name": tgt["name"],
                                    }
                                )
                        elif rel_type == "attributed-to":
                            if src["type"] == "malware" and tgt["type"] == "actor":
                                relationships.append(
                                    {
                                        "type": "attributed_to",
                                        "source_type": src["type"],
                                        "source_name": src["name"],
                                        "target_type": tgt["type"],
                                        "target_name": tgt["name"],
                                    }
                                )

            # Store relationships for Neo4j graph building.
            # Apply cap only when explicitly configured; by default keep all.
            if MITRE_MAX_RELATIONSHIPS > 0:
                self.relationships = relationships[:MITRE_MAX_RELATIONSHIPS]
                logger.info(
                    f"   → Extracted {len(relationships)} relationships "
                    f"(capped at {MITRE_MAX_RELATIONSHIPS} via MITRE_MAX_RELATIONSHIPS)"
                )
            else:
                self.relationships = relationships
                logger.info(f"   → Extracted {len(relationships)} relationships (no cap)")

            # Build lookup: actor_name → [technique_mitre_ids] from explicit USES relationships.
            # Used to populate uses_techniques on ThreatActor nodes so build_relationships.py
            # can create ThreatActor -[:USES]-> Technique without co-occurrence guesswork.
            _actor_uses: dict = {}
            _malware_uses: dict = {}
            _tool_uses: dict = {}
            for rel in self.relationships:
                if rel["type"] == "uses" and rel.get("target_mitre_id"):
                    if rel["source_type"] == "actor":
                        bucket = _actor_uses
                    elif rel["source_type"] == "tool":
                        bucket = _tool_uses
                    else:
                        bucket = _malware_uses
                    name = rel["source_name"]
                    if name not in bucket:
                        bucket[name] = []
                    bucket[name].append(rel["target_mitre_id"])

            # Separate by type
            techniques = []
            tactics = []
            actors = []
            malware = []
            tools = []

            for obj in objects:
                obj_type = obj.get("type", "")

                if obj_type == "attack-pattern":
                    # Technique — also extract kill-chain phases for IN_TACTIC linkage
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break

                    tactic_phases = [
                        kc["phase_name"]
                        for kc in obj.get("kill_chain_phases", [])
                        if kc.get("kill_chain_name") == "mitre-attack"
                    ]

                    if mitre_id:
                        description = obj.get("description", "")[:500]
                        techniques.append(
                            {
                                "type": "technique",
                                "mitre_id": mitre_id,
                                "name": obj.get("name", ""),
                                "description": description,
                                "zone": self.detect_sectors(description) or ["global"],
                                "tag": self.tag,
                                "source": [self.tag],
                                # PR (S5): MITRE STIX objects carry created/modified
                                # timestamps that ARE canonical world-truth (when MITRE first
                                # published the technique/actor/etc.). Pass them through to
                                # MISP via the first_seen/last_seen attribute fields, which
                                # parse_attribute will then route to first_seen_at_source.
                                "first_seen": obj.get("created"),
                                "last_seen": obj.get("modified"),
                                "platforms": obj.get("x_mitre_platforms", []),
                                "data_sources": obj.get("x_mitre_data_sources", []),
                                "tactic_phases": tactic_phases,
                                "detection": (obj.get("x_mitre_detection", "") or "")[:1000],
                                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                                "confidence_score": 0.8,
                            }
                        )

                elif obj_type == "x-mitre-tactic":
                    # Tactic node — required for IN_TACTIC relationships
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break

                    shortname = obj.get("x_mitre_shortname", "")
                    if mitre_id and shortname:
                        tactic_desc = obj.get("description", "")
                        tactics.append(
                            {
                                "type": "tactic",
                                "mitre_id": mitre_id,
                                "name": obj.get("name", ""),
                                "shortname": shortname,
                                "zone": self.detect_sectors(tactic_desc) or ["global"],
                                "tag": self.tag,
                                "source": [self.tag],
                                # PR (S5): MITRE STIX objects carry created/modified
                                # timestamps that ARE canonical world-truth (when MITRE first
                                # published the technique/actor/etc.). Pass them through to
                                # MISP via the first_seen/last_seen attribute fields, which
                                # parse_attribute will then route to first_seen_at_source.
                                "first_seen": obj.get("created"),
                                "last_seen": obj.get("modified"),
                                "confidence_score": 0.9,
                            }
                        )

                elif obj_type == "intrusion-set":
                    # Threat Actor
                    description = obj.get("description", "")
                    sectors = self.detect_sectors(description)
                    actor_name = obj.get("name", "")

                    actors.append(
                        {
                            "type": "actor",
                            "name": actor_name,
                            "aliases": obj.get("aliases", []),
                            "description": description[:500],
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            # PR (S5): MITRE STIX objects carry created/modified
                            # timestamps that ARE canonical world-truth (when MITRE first
                            # published the technique/actor/etc.). Pass them through to
                            # MISP via the first_seen/last_seen attribute fields, which
                            # parse_attribute will then route to first_seen_at_source.
                            "first_seen": obj.get("created"),
                            "last_seen": obj.get("modified"),
                            "confidence_score": 0.7,
                            # Explicit technique list from MITRE ATT&CK USES relationships.
                            # Stored as a node property so build_relationships.py can create
                            # ThreatActor -[:USES]-> Technique without co-occurrence guesswork.
                            "uses_techniques": _actor_uses.get(actor_name, []),
                        }
                    )

                elif obj_type == "malware":
                    # Malware
                    description = obj.get("description", "")
                    sectors = self.detect_sectors(description)

                    malware.append(
                        {
                            "type": "malware",
                            "name": obj.get("name", ""),
                            # STIX 2 uses ``labels``; some bundles also use ``malware_types``.
                            "malware_types": obj.get("malware_types", []) or obj.get("labels", []),
                            "family": obj.get("name", ""),
                            "description": description[:500],
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            # PR (S5): MITRE STIX objects carry created/modified
                            # timestamps that ARE canonical world-truth (when MITRE first
                            # published the technique/actor/etc.). Pass them through to
                            # MISP via the first_seen/last_seen attribute fields, which
                            # parse_attribute will then route to first_seen_at_source.
                            "first_seen": obj.get("created"),
                            "last_seen": obj.get("modified"),
                            "confidence_score": 0.7,
                            # Explicit technique IDs from ATT&CK relationship objects (malware ``uses`` technique).
                            # Serialized into MISP via ``MITRE_USES_TECHNIQUES:`` so MISP→Neo4j can rebuild edges.
                            "uses_techniques": _malware_uses.get(obj.get("name", ""), []),
                        }
                    )

                elif obj_type == "tool":
                    # Tool (e.g. Cobalt Strike S0154, Mimikatz S0002) — distinct from malware
                    description = obj.get("description", "")
                    sectors = self.detect_sectors(description)
                    tool_name = obj.get("name", "")

                    # Extract MITRE ID (S####) from external_references
                    external_ids = obj.get("external_references", [])
                    mitre_id = ""
                    for ext in external_ids:
                        if ext.get("source_name") == "mitre-attack":
                            mitre_id = ext.get("external_id", "")
                            break

                    if not mitre_id:
                        logger.debug("Tool %s has no MITRE ID — skipping", tool_name)
                        continue

                    tools.append(
                        {
                            "type": "tool",
                            "mitre_id": mitre_id,
                            "name": tool_name,
                            "description": description[:500],
                            "tool_types": obj.get("labels", []),
                            "zone": sectors,
                            "tag": self.tag,
                            "source": [self.tag],
                            # PR (S5): MITRE STIX objects carry created/modified
                            # timestamps that ARE canonical world-truth (when MITRE first
                            # published the technique/actor/etc.). Pass them through to
                            # MISP via the first_seen/last_seen attribute fields, which
                            # parse_attribute will then route to first_seen_at_source.
                            "first_seen": obj.get("created"),
                            "last_seen": obj.get("modified"),
                            "confidence_score": 0.7,
                            "uses_techniques": _tool_uses.get(tool_name, []),
                        }
                    )

            # Tactics are small (~14 nodes) — always include all of them.
            # Remaining budget split: 50% techniques, 20% actors, 15% malware, 15% tools.
            effective_limit = limit if limit is not None else 999999
            all_items = (
                tactics
                + techniques[: int(effective_limit * 0.50)]
                + actors[: int(effective_limit * 0.20)]
                + malware[: int(effective_limit * 0.15)]
                + tools[: int(effective_limit * 0.15)]
            )

            if baseline and len(all_items) == 0:
                logger.warning("MITRE baseline returned 0 items — verify STIX bundle URL")

            logger.info(f"[OK] MITRE ATT&CK: Processed {len(all_items)} items")
            logger.info(f"   - Tactics:    {len(tactics)}")
            logger.info(f"   - Techniques: {len(techniques[: int(effective_limit * 0.50)])}")
            logger.info(f"   - Actors:     {len(actors[: int(effective_limit * 0.20)])}")
            logger.info(f"   - Malware:    {len(malware[: int(effective_limit * 0.15)])}")
            logger.info(f"   - Tools:      {len(tools[: int(effective_limit * 0.15)])}")

            # Push to MISP if requested
            if push_to_misp:
                success, failed = self.misp_writer.push_items(all_items)

                # Log push status but always return the items (consistent return type)
                if success > 0:
                    logger.info(f"[OK] MITRE ATT&CK: Successfully pushed {success} items to MISP")
                if failed > 0:
                    logger.warning(f"[WARN] MITRE ATT&CK: Failed to push {failed} items to MISP")

                if new_etag and failed == 0:
                    update_source_incremental("mitre", mitre_bundle_etag=new_etag)

                MITRE_CIRCUIT_BREAKER.record_success()
                ok = failed == 0
                err = None
                if failed > 0:
                    err = f"MISP push reported {failed} failed attribute(s) ({success} ok)"
                return self._return_status(success=ok, count=len(all_items), failed=failed, error=err)
            else:
                if new_etag:
                    update_source_incremental("mitre", mitre_bundle_etag=new_etag)
                MITRE_CIRCUIT_BREAKER.record_success()
                return all_items if limit is None else all_items[:limit]

        except Exception as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"MITRE ATT&CK: auth/access denied (e.g. GitHub) — skipping: {e}")
                MITRE_CIRCUIT_BREAKER.record_failure()
                return make_skipped_optional_source(
                    "mitre",
                    skip_reason=str(e),
                    skip_reason_class="mitre_auth_denied",
                )
            logger.error(f"MITRE ATT&CK collection error: {e}")
            MITRE_CIRCUIT_BREAKER.record_failure()
            return self._return_status(False, 0, str(e)) if push_to_misp else []

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0):
        """Return standardized status dict (delegates to shared make_status)."""
        return make_status("mitre", success, count=count, failed=failed, error=error)

    def get_relationships(self):
        """Return extracted relationships for Neo4j graph building."""
        return self.relationships


def test_mitre():
    """Test MITRE ATT&CK collection and MISP push"""
    collector = MITRECollector()
    result = collector.collect(limit=500)  # MITRE: Public API, no rate limit
    print("\n📥 MITRE ATT&CK Test Result:")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    test_mitre()
