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
from config import (
    ENABLE_MITRE_ICS,
    MITRE_ICS_ATTACK_URL,
    MITRE_USE_CONDITIONAL_GET,
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_text,
    resolve_collection_limit,
)
from resilience import get_circuit_breaker

logger = logging.getLogger(__name__)

# Circuit breaker for MITRE (very reliable but good to have)
MITRE_CIRCUIT_BREAKER = get_circuit_breaker("mitre", failure_threshold=3, recovery_timeout=1800)

# Rate limiter for MITRE (GitHub CDN rate limits apply)
MITRE_RATE_LIMITER = RateLimiter(min_interval=1.0)  # 1 request per second max

# Maximum number of ATT&CK relationships to store for Neo4j graph building.
# ATT&CK v14+ contains 11,000+ relationships; setting this to 0 means no cap.
# Override via EDGEGUARD_MITRE_MAX_RELATIONSHIPS — the name README/.env.example
# have documented since PR-D, which previously was read by nothing (2026-06
# README audit). The bare legacy name MITRE_MAX_RELATIONSHIPS still works as a
# fallback so existing deployments don't silently lose their cap. `or` chains
# (not getenv defaults) so a compose-style set-but-empty value means "unset".
import os as _os

MITRE_MAX_RELATIONSHIPS: int = int(
    _os.getenv("EDGEGUARD_MITRE_MAX_RELATIONSHIPS") or _os.getenv("MITRE_MAX_RELATIONSHIPS") or "0"
)

# ATT&CK domain markers (2026-10, ATT&CK for ICS opt-in via ENABLE_MITRE_ICS).
# Every emitted item and relationship carries ``attack_domain`` so downstream
# (MISP writer, MISP→Neo4j parser, Technique→Tactic linking by tactic short
# name) can tell the two matrices apart: 9 of the 12 ICS tactic short names
# (``execution``, ``persistence``, ...) are identical to Enterprise ones, while
# tactic IDs (TA01xx vs TA00xx) and technique IDs (T08xx vs T1xxx) never collide.
ATTACK_DOMAIN_ENTERPRISE = "enterprise"
ATTACK_DOMAIN_ICS = "ics"

# ``kill_chain_phases[].kill_chain_name`` differs per bundle (verified against
# mitre/cti ics-attack.json, ATT&CK v19.2): Enterprise uses ``mitre-attack``,
# ICS uses ``mitre-ics-attack``. Filtering ICS techniques with the Enterprise
# name would leave them with empty ``tactic_phases``.
ENTERPRISE_KILL_CHAIN_NAME = "mitre-attack"
ICS_KILL_CHAIN_NAME = "mitre-ics-attack"


def _record_ics_failure(exc: BaseException) -> None:
    """Tick the pipeline error counter for an ICS bundle failure.

    Mirrors the catastrophic branch of
    ``collector_failure_alerts.report_collector_failure`` —
    ``record_pipeline_error(f"collect_{source}", exc_type, source)`` — but is
    scoped to the optional ICS sub-fetch: the Enterprise ingest has already
    succeeded, so we must NOT fail the task or trip the MITRE circuit breaker;
    just leave a metric + log trail. Lazy import so slim containers without
    ``prometheus_client`` degrade gracefully (same pattern as misp_collector).
    """
    try:
        from metrics_server import record_pipeline_error

        record_pipeline_error("collect_mitre_ics", type(exc).__name__, "mitre")
    except Exception as me:
        logger.debug("MITRE ATT&CK for ICS: metric emit failed: %s", me)


class MITRECollector:
    """
    MITRE ATT&CK Collector.

    Flow: MITRE STIX → Process → Push to MISP → Return status
    Stores relationships for later Neo4j graph building.
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.attack_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        # ATT&CK for ICS bundle — only fetched when ENABLE_MITRE_ICS is on.
        self.ics_attack_url = MITRE_ICS_ATTACK_URL
        self.tag = SOURCE_TAGS["mitre"]
        self.misp_writer = misp_writer or MISPWriter()
        self.relationships: list = []

    @retry_with_backoff(max_retries=3, base_delay=5.0)
    def _download_stix_bundle(
        self, etag: Optional[str] = None, url: Optional[str] = None
    ) -> Tuple[Optional[dict], Optional[str]]:
        """Download a MITRE ATT&CK STIX bundle with retry.

        Defaults to the Enterprise bundle (~80 MB, ``self.attack_url``); the
        opt-in ICS path passes ``url=self.ics_attack_url`` (~3.5 MB).

        Returns:
            (bundle, new_etag) on 200; (None, etag_sent) on 304 Not Modified.
        """
        headers = {}
        if etag:
            headers["If-None-Match"] = etag
        response = request_with_rate_limit_retries(
            "GET",
            url or self.attack_url,
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
        """Check MITRE ATT&CK feed health (Enterprise; ICS is opt-in and never
        affects the breaker — only its enablement is reported here)."""
        if not MITRE_CIRCUIT_BREAKER.can_execute():
            return {
                "healthy": False,
                "error": "Circuit breaker open",
                "circuit_state": MITRE_CIRCUIT_BREAKER.state.name,
                "mitre_ics_enabled": ENABLE_MITRE_ICS,
            }
        return {
            "healthy": True,
            "circuit_state": MITRE_CIRCUIT_BREAKER.state.name,
            "mitre_ics_enabled": ENABLE_MITRE_ICS,
        }

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
                if ENABLE_MITRE_ICS:
                    # ICS has no ETag of its own and is only fetched alongside a
                    # changed Enterprise bundle (both are versioned together in
                    # mitre/cti). First-time enablement on an existing deployment
                    # therefore needs a forced refetch or a baseline run.
                    logger.info(
                        "MITRE ATT&CK for ICS: skipped (Enterprise bundle unchanged). "
                        "To ingest ICS now, set MITRE_FORCE_REFETCH=true or run in baseline mode."
                    )
                MITRE_CIRCUIT_BREAKER.record_success()
                if push_to_misp:
                    return self._return_status(True, 0, None, 0)
                return []

            objects = bundle.get("objects", [])

            logger.info(f"[FETCH] MITRE ATT&CK: Fetched {len(objects)} STIX objects")

            # Relationship cap is a TOTAL across bundles (0 / unset = no cap).
            rel_cap = MITRE_MAX_RELATIONSHIPS if MITRE_MAX_RELATIONSHIPS > 0 else None
            parsed = self._parse_bundle(
                objects,
                domain=ATTACK_DOMAIN_ENTERPRISE,
                kill_chain_name=ENTERPRISE_KILL_CHAIN_NAME,
                max_relationships=rel_cap,
            )

            # Opt-in ATT&CK for ICS (2026-10): fetched AFTER Enterprise, parsed
            # with the same code path, merged by mitre_id / name. Failure is
            # isolated inside _collect_ics_bundle — Enterprise items survive.
            if ENABLE_MITRE_ICS:
                ics_cap = None if rel_cap is None else max(0, rel_cap - len(parsed["relationships"]))
                ics_parsed = self._collect_ics_bundle(max_relationships=ics_cap)
                if ics_parsed is not None:
                    parsed = self._merge_domain_bundles(parsed, ics_parsed)
                    logger.info(
                        f"[OK] MITRE ATT&CK for ICS: merged "
                        f"{len(ics_parsed['techniques'])} techniques, {len(ics_parsed['tactics'])} tactics, "
                        f"{len(ics_parsed['actors'])} actors, {len(ics_parsed['malware'])} malware"
                    )

            # Store relationships for Neo4j graph building (cap applied per bundle above).
            self.relationships = parsed["relationships"]

            techniques = parsed["techniques"]
            tactics = parsed["tactics"]
            actors = parsed["actors"]
            malware = parsed["malware"]
            tools = parsed["tools"]

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
            # PR-N24 BLOCKER B3 (proactive audit 2026-04-22): same shape as
            # PR-N17 NVD silent-window-drop + PR-N23 CISA fix. Pre-N24
            # ``return self._return_status(False, 0, str(e)) if push_to_misp
            # else []`` returned an EMPTY LIST when push_to_misp=False
            # (alert-preview / baseline-drain / test-harness flows) —
            # indistinguishable from "MITRE has no updates today".
            # Fix: when push_to_misp=True still return status dict (Airflow
            # contract); when False, re-raise so caller sees the actual error.
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise

    def _parse_bundle(
        self,
        objects: list,
        *,
        domain: str,
        kill_chain_name: str,
        max_relationships: Optional[int] = None,
    ) -> dict:
        """Parse one ATT&CK STIX bundle into collector items + relationships.

        Shared by the Enterprise and (opt-in) ICS bundles — see
        ``ENABLE_MITRE_ICS``. ``domain`` is stamped onto every item and
        relationship as ``attack_domain``; ``kill_chain_name`` selects which
        ``kill_chain_phases`` feed ``tactic_phases`` (``mitre-attack`` for
        Enterprise, ``mitre-ics-attack`` for ICS).

        Zoning is unchanged: items are zoned from their description text via
        ``detect_sectors`` exactly as before. ICS objects additionally carry
        ``x_mitre_sectors`` / ``x-mitre-asset`` targets — deliberately NOT used
        for zoning here (possible follow-up: map ICS sectors to EdgeGuard zones).

        Returns:
            dict with keys ``techniques``, ``tactics``, ``actors``, ``malware``,
            ``tools``, ``relationships`` (lists in the same shapes as before).
        """
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
                                    "attack_domain": domain,
                                    "source_type": src["type"],
                                    "source_name": src["name"],
                                    "target_type": tgt["type"],
                                    "target_mitre_id": tgt.get("mitre_id", ""),
                                    "target_name": tgt["name"],
                                }
                            )
                        elif src["type"] == "actor" and tgt["type"] in ("malware", "tool"):
                            # 2026-10 (R6): group → software ``uses`` — carried as uses_malware /
                            # uses_tools on the actor item → USES_MALWARE / USES_TOOL edges.
                            relationships.append(
                                {
                                    "type": "uses_software",
                                    "attack_domain": domain,
                                    "source_type": "actor",
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
                                    "attack_domain": domain,
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
                                    "attack_domain": domain,
                                    "source_type": src["type"],
                                    "source_name": src["name"],
                                    "target_type": tgt["type"],
                                    "target_name": tgt["name"],
                                }
                            )

        # Relationships are stored by ``collect()`` for Neo4j graph building.
        # Apply cap only when explicitly configured; by default keep all.
        # ``max_relationships`` is None (no cap) or the remaining budget for
        # this bundle — ``collect()`` derives it from MITRE_MAX_RELATIONSHIPS
        # so the cap stays a TOTAL across Enterprise + ICS.
        if max_relationships is not None:
            total = len(relationships)
            relationships = relationships[:max_relationships]
            logger.info(
                f"   → [{domain}] Extracted {total} relationships "
                f"(capped at {max_relationships} via MITRE_MAX_RELATIONSHIPS)"
            )
        else:
            logger.info(f"   → [{domain}] Extracted {len(relationships)} relationships (no cap)")

        # Build lookup: actor_name → [technique_mitre_ids] from explicit MITRE STIX
        # ``uses`` relationships. Used to populate uses_techniques on ThreatActor
        # nodes so build_relationships.py can create
        # ThreatActor -[:EMPLOYS_TECHNIQUE]-> Technique without co-occurrence
        # guesswork. (Edge type renamed from generic ``USES`` to specialized
        # ``EMPLOYS_TECHNIQUE`` in 2026-04 PR #41 — see docs/KNOWLEDGE_GRAPH.md.)
        _actor_uses: dict = {}
        _malware_uses: dict = {}
        _tool_uses: dict = {}
        _actor_uses_malware: dict = {}  # actor name → [malware names]   (2026-10 R6)
        _actor_uses_tools: dict = {}  # actor name → [tool mitre ids]   (2026-10 R6)
        for rel in relationships:
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
            elif rel["type"] == "uses_software":
                name = rel["source_name"]
                if rel["target_type"] == "malware":
                    _actor_uses_malware.setdefault(name, []).append(rel["target_name"])
                else:
                    _actor_uses_tools.setdefault(name, []).append(rel.get("target_mitre_id") or rel["target_name"])

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
                    if kc.get("kill_chain_name") == kill_chain_name
                ]

                if mitre_id:
                    description = obj.get("description", "")[:500]
                    techniques.append(
                        {
                            "type": "technique",
                            "attack_domain": domain,
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
                            "attack_domain": domain,
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
                        "attack_domain": domain,
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
                        # Explicit technique list from MITRE ATT&CK ``uses``
                        # STIX relationships. Stored as a node property so
                        # build_relationships.py can create
                        # ThreatActor -[:EMPLOYS_TECHNIQUE]-> Technique
                        # without co-occurrence guesswork. (Edge type renamed
                        # from generic ``USES`` in 2026-04 PR #41.)
                        "uses_techniques": _actor_uses.get(actor_name, []),
                        "uses_malware": _actor_uses_malware.get(actor_name, []),
                        "uses_tools": _actor_uses_tools.get(actor_name, []),
                    }
                )

            elif obj_type == "malware":
                # Malware
                description = obj.get("description", "")
                sectors = self.detect_sectors(description)

                malware.append(
                    {
                        "type": "malware",
                        "attack_domain": domain,
                        "name": obj.get("name", ""),
                        # ATT&CK malware SDOs carry aliases in the MITRE
                        # extension field ``x_mitre_aliases`` (the plain
                        # ``aliases`` key only exists on intrusion-sets).
                        # Feeds build_relationships Q9 INDICATES
                        # (i.malware_family ∈ m.aliases) — added 2026-06
                        # with the alias round-trip fix. (Malware aliases
                        # do NOT feed actor attribution: the old Q2
                        # Branch-3 path was removed as a forgery vector.)
                        "aliases": obj.get("x_mitre_aliases", []) or obj.get("aliases", []),
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
                        "attack_domain": domain,
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

        return {
            "techniques": techniques,
            "tactics": tactics,
            "actors": actors,
            "malware": malware,
            "tools": tools,
            "relationships": relationships,
        }

    def _collect_ics_bundle(self, max_relationships: Optional[int] = None) -> Optional[dict]:
        """Fetch + parse the ATT&CK for ICS bundle, fully isolated.

        Any failure (network, HTTP, JSON, parse) is logged, counted via the
        pipeline error metric and swallowed so the already-processed Enterprise
        items are still returned/pushed. Deliberately does NOT touch
        ``MITRE_CIRCUIT_BREAKER``: an ICS outage must not open the breaker and
        block the next Enterprise run. No conditional GET for ICS — the bundle
        is ~3.5 MB and only fetched when the Enterprise bundle changed (see the
        304 branch in ``collect``).

        Returns the ``_parse_bundle`` dict, or None on failure.
        """
        try:
            MITRE_RATE_LIMITER.wait_if_needed()
            bundle, _ = self._download_stix_bundle(etag=None, url=self.ics_attack_url)
            if bundle is None:
                raise RuntimeError("ICS bundle fetch returned no body")
            objects = bundle.get("objects", [])
            logger.info(f"[FETCH] MITRE ATT&CK for ICS: Fetched {len(objects)} STIX objects")
            return self._parse_bundle(
                objects,
                domain=ATTACK_DOMAIN_ICS,
                kill_chain_name=ICS_KILL_CHAIN_NAME,
                max_relationships=max_relationships,
            )
        except Exception as e:
            # Isolation: Enterprise ingest continues. Not re-raised on purpose
            # (this helper is outside the push_to_misp contract that the
            # PR-N24 B3 scan enforces on ``collect``).
            logger.error(f"MITRE ATT&CK for ICS: fetch/parse failed — continuing with Enterprise only: {e}")
            _record_ics_failure(e)
            return None

    @staticmethod
    def _merge_domain_bundles(primary: dict, secondary: dict) -> dict:
        """Merge a second parsed bundle (ICS) into the primary (Enterprise).

        - techniques / tactics: keyed by ``mitre_id``. ICS ids (T08xx / TA01xx)
          never collide with Enterprise (T1xxx / TA00xx); duplicates are skipped
          defensively.
        - actors / malware / tools: keyed by ``name``. Groups and malware that
          appear in both bundles (e.g. "Sandworm Team", "Stuxnet") are the SAME
          STIX object published in both domain bundles (``x_mitre_domains`` lists
          both). They are emitted ONCE, keeping the Enterprise item (so
          ``attack_domain`` stays "enterprise" — Enterprise is the canonical home
          and the downstream name-keyed Neo4j merge sees one node) with
          ``uses_techniques`` UNIONED so the ICS technique links are preserved.
        - relationships: concatenated (each carries its own ``attack_domain``).
        """
        merged = {k: list(v) for k, v in primary.items()}

        for key in ("techniques", "tactics"):
            seen = {it.get("mitre_id") for it in merged[key]}
            for it in secondary.get(key, []):
                mid = it.get("mitre_id")
                if mid in seen:
                    logger.debug("MITRE merge: skipping duplicate %s %s from %s", key, mid, it.get("attack_domain"))
                    continue
                seen.add(mid)
                merged[key].append(it)

        for key in ("actors", "malware", "tools"):
            by_name = {}
            for it in merged[key]:
                by_name.setdefault(it.get("name"), it)
            for it in secondary.get(key, []):
                existing = by_name.get(it.get("name"))
                if existing is None:
                    by_name[it.get("name")] = it
                    merged[key].append(it)
                    continue
                for list_key in ("uses_techniques", "uses_malware", "uses_tools"):
                    have = existing.get(list_key) or []
                    seen_t = set(have)
                    extra = []
                    for t in it.get(list_key) or []:
                        if t not in seen_t:
                            seen_t.add(t)
                            extra.append(t)
                    if extra:
                        existing[list_key] = list(have) + extra

        # 2026-10 review fix: a group/malware present in BOTH bundles carries the same
        # STIX relationship objects twice; de-duplicate so the CLI relationship step
        # (capped list) is not spent on repeats. Order preserved, first occurrence kept.
        seen_rels: set = set()
        merged["relationships"] = []
        for rel in list(primary.get("relationships", [])) + list(secondary.get("relationships", [])):
            key = json.dumps(rel, sort_keys=True, default=str) if isinstance(rel, dict) else repr(rel)
            if key in seen_rels:
                continue
            seen_rels.add(key)
            merged["relationships"].append(rel)
        return merged

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
