"""
EdgeGuard GraphQL API
=====================
Strawberry + FastAPI GraphQL endpoint, mirroring the ISIM GraphQL convention
(port 4001 by default) so ResilMesh can query EdgeGuard data the same way it
queries ISIM.

Run standalone:
    uvicorn src.graphql_api:app --host 127.0.0.1 --port 4001

Or import `app` into a combined runner alongside the REST API.

GraphQL endpoint:  POST /graphql
GraphQL Playground: GET  /graphql  (disabled in production via EDGEGUARD_GRAPHQL_PLAYGROUND=false)
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import List, Optional

import strawberry
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from strawberry.fastapi import GraphQLRouter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from graphql_schema import (
    CVE,
    Campaign,
    CVSSv2,
    CVSSv30,
    CVSSv31,
    CVSSv40,
    Indicator,
    IndicatorFilter,
    Malware,
    NodeFilter,
    Tactic,
    Technique,
    ThreatActor,
    Tool,
    ToolFilter,
    Vulnerability,
    VulnerabilityFilter,
)
from neo4j_client import NEO4J_READ_TIMEOUT, Neo4jClient
from package_meta import package_version

logger = logging.getLogger(__name__)

# Used to construct back-links to the originating MISP event (e.g. misp_event_url field)
MISP_URL = os.getenv("MISP_URL", "").rstrip("/")

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
EDGEGUARD_API_KEY = os.getenv("EDGEGUARD_API_KEY", "")
_ENV = os.getenv("EDGEGUARD_ENV", "dev").lower()

# PR (security A6) — Red Team Tier A: previously the API-key requirement
# only fired when ``EDGEGUARD_ENV=prod``. A staging deployment with the
# default ``EDGEGUARD_ENV=dev`` (or no env var at all) silently ran with
# NO authentication — and ``_verify_api_key`` short-circuited the check
# whenever ``EDGEGUARD_API_KEY`` was empty, making every endpoint
# anonymously accessible. An internet-exposed staging instance would
# leak the entire graph via ``/graph/explore?limit=500``.
#
# New rule: in non-prod environments, EITHER set ``EDGEGUARD_API_KEY``
# (auth enforced for everyone) OR bind to loopback only (``127.0.0.1``)
# so the unauthenticated endpoint isn't reachable from the network.
# Operators who genuinely want public unauth dev access can opt in
# via the explicit escape hatch ``EDGEGUARD_ALLOW_UNAUTH=1``.
# PR #40 commit X (bugbot HIGH): the security check MUST read the same
# env var the server actually binds to. The server at line 725 reads
# ``EDGEGUARD_GRAPHQL_HOST`` (with "127.0.0.1" default). The previous
# code here read ``EDGEGUARD_API_HOST`` first (a REST-API var that the
# GraphQL server never honors) — an operator setting
# ``EDGEGUARD_API_HOST=127.0.0.1`` (loopback for REST) +
# ``EDGEGUARD_GRAPHQL_HOST=0.0.0.0`` (all-interfaces for GraphQL)
# would pass this safety check but the server would actually bind to
# 0.0.0.0 unauthenticated.
_BIND_HOST = os.getenv("EDGEGUARD_GRAPHQL_HOST", "127.0.0.1").strip()
_ALLOW_UNAUTH = os.getenv("EDGEGUARD_ALLOW_UNAUTH", "").strip().lower() in ("1", "true", "yes", "on")

if _ENV == "prod" and not EDGEGUARD_API_KEY:
    raise RuntimeError(
        "EDGEGUARD_API_KEY must be set when EDGEGUARD_ENV=prod. "
        "Set a strong random value before starting the GraphQL API in production."
    )

if not EDGEGUARD_API_KEY and _BIND_HOST not in ("127.0.0.1", "localhost", "::1") and not _ALLOW_UNAUTH:
    raise RuntimeError(
        f"EDGEGUARD_API_KEY is unset AND the bind host ({_BIND_HOST!r}) is not loopback. "
        "Refusing to start an unauthenticated GraphQL endpoint reachable from the network. "
        "Either set EDGEGUARD_API_KEY (recommended), bind to 127.0.0.1, "
        "or opt in explicitly with EDGEGUARD_ALLOW_UNAUTH=1 (not recommended)."
    )


def _verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    """Dependency: require valid API key when EDGEGUARD_API_KEY is configured."""
    if EDGEGUARD_API_KEY and x_api_key != EDGEGUARD_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Api-Key header")


limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])


# ---------------------------------------------------------------------------
# Neo4j helpers
# ---------------------------------------------------------------------------


def _row_to_dict(record) -> dict:
    return dict(record)


def _neo4j_list(val) -> Optional[List[str]]:
    if val is None:
        return None
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


# ---------------------------------------------------------------------------
# Resolvers — each returns plain Strawberry dataclass instances
# ---------------------------------------------------------------------------


def _cve_effective_score_severity(c, cv40_node, cv31_node, cv30_node, cv2_node):
    """
    Use CVE node properties when set; otherwise derive from linked CVSS sub-nodes
    (same priority as MISP→Neo4j NVD_META: v3.1 → v3.0 → v2 → v4.0).
    Uses ``is not None`` so a score of 0.0 is preserved.
    """
    score = c.get("cvss_score")
    if score is None:
        score = c.get("base_score")
    severity = c.get("severity") or c.get("base_severity")
    if score is not None:
        return score, severity
    for node in (cv31_node, cv30_node, cv2_node, cv40_node):
        if node is not None:
            bs = node.get("base_score")
            if bs is not None:
                return bs, node.get("base_severity") or severity
    return None, severity


def _resolve_cve(client: Neo4jClient, cve_id: str) -> Optional[CVE]:
    query = """
    MATCH (c:CVE {cve_id: $cve_id})
    OPTIONAL MATCH (c)-[:HAS_CVSS_v40]->(cv40:CVSSv40)
    OPTIONAL MATCH (c)-[:HAS_CVSS_v31]->(cv31:CVSSv31)
    OPTIONAL MATCH (c)-[:HAS_CVSS_v30]->(cv30:CVSSv30)
    OPTIONAL MATCH (c)-[:HAS_CVSS_v2]->(cv2:CVSSv2)
    RETURN c, cv40, cv31, cv30, cv2
    LIMIT 1
    """
    with client.driver.session() as session:
        record = session.run(query, cve_id=cve_id, timeout=NEO4J_READ_TIMEOUT).single()
    if not record:
        return None

    c = record["c"]
    cv40_node = record["cv40"] if record["cv40"] else None
    cv31_node = record["cv31"] if record["cv31"] else None
    cv30_node = record["cv30"] if record["cv30"] else None
    cv2_node = record["cv2"] if record["cv2"] else None

    eff_score, eff_severity = _cve_effective_score_severity(c, cv40_node, cv31_node, cv30_node, cv2_node)

    return CVE(
        cve_id=c.get("cve_id", ""),
        description=c.get("description"),
        published=c.get("published"),
        last_modified=c.get("last_modified"),
        cpe_type=_neo4j_list(c.get("cpe_type")),
        result_impacts=_neo4j_list(c.get("result_impacts")),
        ref_tags=_neo4j_list(c.get("ref_tags")),
        cwe=_neo4j_list(c.get("cwe")),
        base_score=eff_score,
        base_severity=eff_severity,
        edgeguard_managed=c.get("edgeguard_managed"),
        uuid=c.get("uuid"),
        source=_neo4j_list(c.get("source")),
        zone=_neo4j_list(c.get("zone")),
        first_imported_at=str(c["first_imported_at"]) if c.get("first_imported_at") else None,
        last_updated=str(c["last_updated"]) if c.get("last_updated") else None,
        last_imported_from=c.get("last_imported_from"),
        version_constraints=c.get("version_constraints"),
        cisa_cwes=c.get("cisa_cwes"),
        cisa_notes=c.get("cisa_notes"),
        cvss_v40=CVSSv40(
            vector_string=cv40_node.get("vector_string", ""),
            base_score=cv40_node.get("base_score"),
            base_severity=cv40_node.get("base_severity"),
        )
        if cv40_node
        else None,
        cvss_v31=CVSSv31(
            vector_string=cv31_node.get("vector_string", ""),
            attack_vector=cv31_node.get("attack_vector"),
            attack_complexity=cv31_node.get("attack_complexity"),
            privileges_required=cv31_node.get("privileges_required"),
            user_interaction=cv31_node.get("user_interaction"),
            scope=cv31_node.get("scope"),
            confidentiality_impact=cv31_node.get("confidentiality_impact"),
            integrity_impact=cv31_node.get("integrity_impact"),
            availability_impact=cv31_node.get("availability_impact"),
            base_score=cv31_node.get("base_score"),
            base_severity=cv31_node.get("base_severity"),
            impact_score=cv31_node.get("impact_score"),
            exploitability_score=cv31_node.get("exploitability_score"),
        )
        if cv31_node
        else None,
        cvss_v30=CVSSv30(
            vector_string=cv30_node.get("vector_string", ""),
            attack_vector=cv30_node.get("attack_vector"),
            attack_complexity=cv30_node.get("attack_complexity"),
            privileges_required=cv30_node.get("privileges_required"),
            user_interaction=cv30_node.get("user_interaction"),
            scope=cv30_node.get("scope"),
            confidentiality_impact=cv30_node.get("confidentiality_impact"),
            integrity_impact=cv30_node.get("integrity_impact"),
            availability_impact=cv30_node.get("availability_impact"),
            base_score=cv30_node.get("base_score"),
            base_severity=cv30_node.get("base_severity"),
            impact_score=cv30_node.get("impact_score"),
            exploitability_score=cv30_node.get("exploitability_score"),
        )
        if cv30_node
        else None,
        cvss_v2=CVSSv2(
            vector_string=cv2_node.get("vector_string", ""),
            access_vector=cv2_node.get("access_vector"),
            access_complexity=cv2_node.get("access_complexity"),
            authentication=cv2_node.get("authentication"),
            confidentiality_impact=cv2_node.get("confidentiality_impact"),
            integrity_impact=cv2_node.get("integrity_impact"),
            availability_impact=cv2_node.get("availability_impact"),
            base_score=cv2_node.get("base_score"),
            base_severity=cv2_node.get("base_severity"),
            impact_score=cv2_node.get("impact_score"),
            exploitability_score=cv2_node.get("exploitability_score"),
            obtain_all_privilege=cv2_node.get("obtain_all_privilege"),
            obtain_user_privilege=cv2_node.get("obtain_user_privilege"),
            obtain_other_privilege=cv2_node.get("obtain_other_privilege"),
            user_interaction_required=cv2_node.get("user_interaction_required"),
            ac_insuf_info=cv2_node.get("ac_insuf_info"),
        )
        if cv2_node
        else None,
    )


def _resolve_vulnerabilities(client: Neo4jClient, f: VulnerabilityFilter) -> List[Vulnerability]:
    conditions = ["n.edgeguard_managed = true"]
    params: dict = {"limit": min(f.limit, _MAX_GRAPHQL_LIMIT), "offset": f.offset, "min_cvss": f.min_cvss}

    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone
    if f.status is not strawberry.UNSET and f.status:
        conditions.append("$status IN n.status")
        params["status"] = f.status
    if f.min_cvss > 0:
        conditions.append("n.cvss_score >= $min_cvss")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    query = f"""
    MATCH (n:Vulnerability)
    {where}
    RETURN n
    ORDER BY n.cvss_score DESC
    SKIP $offset LIMIT $limit
    """
    results = []
    with client.driver.session() as session:
        for record in session.run(query, **params, timeout=NEO4J_READ_TIMEOUT):
            n = record["n"]
            # PR #34 round 21 (bugbot LOW): normalize empty misp_event_ids
            # to None for cross-resolver consistency. The Indicator resolver
            # uses ``event_ids or None`` (line ~327) so empty lists collapse
            # to None — Vulnerability used to return ``[]`` for the same empty
            # state. The schema declares ``Optional[List[str]]`` so both shapes
            # are valid GraphQL, but consumers (RAG / xAI) treating "absent"
            # and "empty" differently would see the same logical state two
            # different ways. Normalize at the resolver to converge.
            vuln_event_ids = _neo4j_list(n.get("misp_event_ids")) or None
            results.append(
                Vulnerability(
                    cve_id=n.get("cve_id", ""),
                    description=n.get("description"),
                    status=_neo4j_list(n.get("status")),
                    severity=n.get("severity"),
                    cvss_score=n.get("cvss_score"),
                    zone=_neo4j_list(n.get("zone")),
                    edgeguard_managed=n.get("edgeguard_managed"),
                    uuid=n.get("uuid"),
                    source=_neo4j_list(n.get("source")),
                    last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
                    misp_event_ids=vuln_event_ids,
                    first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                    last_imported_from=n.get("last_imported_from"),
                    version_constraints=n.get("version_constraints"),
                    cisa_cwes=n.get("cisa_cwes"),
                    cisa_notes=n.get("cisa_notes"),
                )
            )
    return results


def _resolve_indicators(client: Neo4jClient, f: IndicatorFilter) -> List[Indicator]:
    conditions = ["n.edgeguard_managed = true"]
    params: dict = {"limit": min(f.limit, _MAX_GRAPHQL_LIMIT), "offset": f.offset}

    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone
    if f.indicator_type is not strawberry.UNSET and f.indicator_type:
        conditions.append("n.indicator_type = $indicator_type")
        params["indicator_type"] = f.indicator_type
    if f.active_only:
        conditions.append("n.active = true")
    if f.min_confidence > 0:
        conditions.append("n.confidence_score >= $min_confidence")
        params["min_confidence"] = f.min_confidence

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    query = f"""
    MATCH (n:Indicator)
    {where}
    RETURN n
    ORDER BY n.confidence_score DESC
    SKIP $offset LIMIT $limit
    """
    results = []
    with client.driver.session() as session:
        for record in session.run(query, **params, timeout=NEO4J_READ_TIMEOUT):
            n = record["n"]
            event_ids = _neo4j_list(n.get("misp_event_ids")) or []
            event_urls: Optional[List[str]] = (
                [f"{MISP_URL}/events/view/{eid}" for eid in event_ids if eid] if (MISP_URL and event_ids) else None
            )
            results.append(
                Indicator(
                    value=n.get("value", ""),
                    indicator_type=n.get("indicator_type", ""),
                    confidence_score=n.get("confidence_score"),
                    zone=_neo4j_list(n.get("zone")),
                    active=n.get("active"),
                    source=_neo4j_list(n.get("source")),
                    last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
                    edgeguard_managed=n.get("edgeguard_managed"),
                    uuid=n.get("uuid"),
                    misp_event_ids=event_ids or None,
                    # PR #34 round 22 (bugbot LOW): normalize empty list to None
                    # for cross-resolver / cross-field consistency. Round 21
                    # fixed the same shape on misp_event_ids and on the
                    # Vulnerability resolver — bugbot caught the missed mirror
                    # site here. Without this collapse, an Indicator with no
                    # MISP attribute IDs surfaced ``misp_event_ids: null`` and
                    # ``misp_attribute_ids: []`` in the same response.
                    misp_attribute_ids=_neo4j_list(n.get("misp_attribute_ids")) or None,
                    misp_event_urls=event_urls,
                    first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                    last_imported_from=n.get("last_imported_from"),
                    yara_rules=n.get("yara_rules"),
                    sigma_rules=n.get("sigma_rules"),
                    sandbox_verdicts=n.get("sandbox_verdicts"),
                    abuse_categories=n.get("abuse_categories"),
                    indicator_role=n.get("indicator_role"),
                    url_status=n.get("url_status"),
                    last_online=n.get("last_online"),
                    threat_label=n.get("threat_label"),
                    threat_category=n.get("threat_category"),
                )
            )
    return results


_MAX_GRAPHQL_LIMIT = 500


def _resolve_list(client: Neo4jClient, label: str, f: NodeFilter, cls, mapper):
    conditions = []
    params: dict = {"limit": min(f.limit, _MAX_GRAPHQL_LIMIT), "offset": f.offset}

    if f.edgeguard_managed_only:
        conditions.append("n.edgeguard_managed = true")
    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    query = f"""
    MATCH (n:{label})
    {where}
    RETURN n
    ORDER BY n.confidence_score DESC
    SKIP $offset LIMIT $limit
    """
    results = []
    with client.driver.session() as session:
        for record in session.run(query, **params, timeout=NEO4J_READ_TIMEOUT):
            results.append(mapper(record["n"]))
    return results


# ---------------------------------------------------------------------------
# Strawberry Query root
# ---------------------------------------------------------------------------

# Neo4j client singleton — initialised in FastAPI lifespan
_client: Optional[Neo4jClient] = None


def _get_client() -> Neo4jClient:
    if _client is None:
        raise RuntimeError("Neo4j client not initialised")
    return _client


@strawberry.type
class Query:
    @strawberry.field(description="Fetch a single CVE by ID, including nested CVSS scores.")
    def cve(self, cve_id: str) -> Optional[CVE]:
        return _resolve_cve(_get_client(), cve_id)

    @strawberry.field(description="List vulnerabilities with optional zone / status / CVSS filters.")
    def vulnerabilities(
        self,
        filter: Optional[VulnerabilityFilter] = strawberry.UNSET,
    ) -> List[Vulnerability]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else VulnerabilityFilter()
        return _resolve_vulnerabilities(_get_client(), f)

    @strawberry.field(description="List threat indicators (IPs, domains, hashes, URLs). Active-only by default.")
    def indicators(
        self,
        filter: Optional[IndicatorFilter] = strawberry.UNSET,
    ) -> List[Indicator]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else IndicatorFilter()
        return _resolve_indicators(_get_client(), f)

    @strawberry.field(description="List threat actors. Part of planned ISIM schema extension.")
    def threat_actors(
        self,
        filter: Optional[NodeFilter] = strawberry.UNSET,
    ) -> List[ThreatActor]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else NodeFilter()
        return _resolve_list(
            _get_client(),
            "ThreatActor",
            f,
            ThreatActor,
            lambda n: ThreatActor(
                name=n.get("name", ""),
                description=n.get("description"),
                sophistication=n.get("sophistication"),
                primary_motivation=n.get("primary_motivation"),
                resource_level=n.get("resource_level"),
                zone=_neo4j_list(n.get("zone")),
                confidence_score=n.get("confidence_score"),
                source=_neo4j_list(n.get("source")),
                edgeguard_managed=n.get("edgeguard_managed"),
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List malware families. Part of planned ISIM schema extension.")
    def malware(
        self,
        filter: Optional[NodeFilter] = strawberry.UNSET,
    ) -> List[Malware]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else NodeFilter()
        return _resolve_list(
            _get_client(),
            "Malware",
            f,
            Malware,
            lambda n: Malware(
                name=n.get("name", ""),
                malware_types=_neo4j_list(n.get("malware_types")),
                description=n.get("description"),
                zone=_neo4j_list(n.get("zone")),
                confidence_score=n.get("confidence_score"),
                source=_neo4j_list(n.get("source")),
                edgeguard_managed=n.get("edgeguard_managed"),
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List MITRE ATT&CK techniques. Part of planned ISIM schema extension.")
    def techniques(
        self,
        filter: Optional[NodeFilter] = strawberry.UNSET,
    ) -> List[Technique]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else NodeFilter()
        return _resolve_list(
            _get_client(),
            "Technique",
            f,
            Technique,
            lambda n: Technique(
                technique_id=n.get("mitre_id", ""),
                name=n.get("name", ""),
                description=n.get("description"),
                detection=n.get("detection"),
                is_subtechnique=n.get("is_subtechnique"),
                tactic_refs=_neo4j_list(n.get("tactic_phases")),
                zone=_neo4j_list(n.get("zone")),
                confidence_score=n.get("confidence_score"),
                edgeguard_managed=n.get("edgeguard_managed"),
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List MITRE ATT&CK tactics (kill-chain phases).")
    def tactics(
        self,
        filter: Optional[NodeFilter] = strawberry.UNSET,
    ) -> List[Tactic]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else NodeFilter()
        return _resolve_list(
            _get_client(),
            "Tactic",
            f,
            Tactic,
            lambda n: Tactic(
                tactic_id=n.get("mitre_id", ""),
                name=n.get("name", ""),
                description=n.get("description"),
                edgeguard_managed=n.get("edgeguard_managed"),
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List inferred campaign nodes built by the co-occurrence enrichment job.")
    def campaigns(
        self,
        filter: Optional[NodeFilter] = strawberry.UNSET,
    ) -> List[Campaign]:
        f = filter if (filter is not strawberry.UNSET and filter is not None) else NodeFilter()
        return _resolve_list(
            _get_client(),
            "Campaign",
            f,
            Campaign,
            lambda n: Campaign(
                name=n.get("name", ""),
                description=n.get("description"),
                zone=_neo4j_list(n.get("zone")),
                confidence_score=n.get("confidence_score"),
                first_seen=str(n.get("first_seen")) if n.get("first_seen") else None,
                last_seen=str(n.get("last_seen")) if n.get("last_seen") else None,
                edgeguard_managed=n.get("edgeguard_managed"),
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List MITRE ATT&CK tools (Cobalt Strike, Mimikatz, etc.).")
    def tools(
        self,
        filter: Optional[ToolFilter] = strawberry.UNSET,
        limit: int = 100,
    ) -> List[Tool]:
        client = _get_client()
        conditions = ["n.edgeguard_managed = true"]
        params: dict = {"limit": limit}

        f = filter if (filter is not strawberry.UNSET and filter is not None) else ToolFilter()
        if f.name is not strawberry.UNSET and f.name:
            conditions.append("toLower(n.name) CONTAINS toLower($name)")
            params["name"] = f.name
        if f.zone is not strawberry.UNSET and f.zone:
            conditions.append("$zone IN n.zone")
            params["zone"] = f.zone

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"""
        MATCH (n:Tool)
        {where}
        RETURN n
        ORDER BY n.confidence_score DESC
        LIMIT $limit
        """
        results = []
        with client.driver.session() as session:
            for record in session.run(query, **params, timeout=NEO4J_READ_TIMEOUT):
                n = record["n"]
                results.append(
                    Tool(
                        mitre_id=n.get("mitre_id", ""),
                        name=n.get("name", ""),
                        description=n.get("description"),
                        tag=n.get("tag"),
                        tool_types=_neo4j_list(n.get("tool_types")),
                        uses_techniques=_neo4j_list(n.get("uses_techniques")),
                        zone=_neo4j_list(n.get("zone")),
                        sources=_neo4j_list(n.get("source")),
                        confidence_score=n.get("confidence_score"),
                        edgeguard_managed=n.get("edgeguard_managed"),
                        uuid=n.get("uuid"),
                        first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                        last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
                    )
                )
        return results


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

GRAPHQL_PLAYGROUND = os.getenv("EDGEGUARD_GRAPHQL_PLAYGROUND", "false").lower() == "true"

# PR (security S8 + A7) — Red Team Tier S/A — defense in depth on the
# GraphQL surface:
#
# * ``QueryDepthLimiter(max_depth=8)``: cap nested-field depth so a
#   malicious request can't fan out into hundreds of OPTIONAL MATCH
#   joins per resolver and exhaust the Neo4j bolt pool. 8 is generous —
#   the deepest legitimate query in our schema (CVE → vuln → indicator
#   → malware → technique → tactic) is 6.
#
# * ``DisableIntrospection``: hide the schema in production
#   (``EDGEGUARD_ENV=prod``) so reconnaissance probes can't enumerate
#   every queryable field for follow-up complexity attacks. Stays
#   ON in dev/staging so developers can use GraphiQL/Apollo Studio.
#
# Both are extensions, not middleware — they run inside Strawberry's
# request lifecycle so the limit applies BEFORE the resolver fans out
# (vs. middleware which would run after parse).
from graphql.validation import NoSchemaIntrospectionCustomRule  # noqa: E402
from strawberry.extensions import QueryDepthLimiter  # noqa: E402
from strawberry.extensions.add_validation_rules import AddValidationRules  # noqa: E402

_GRAPHQL_MAX_DEPTH = int(os.getenv("EDGEGUARD_GRAPHQL_MAX_DEPTH", "8"))
_IS_PROD = os.getenv("EDGEGUARD_ENV", "dev").strip().lower() == "prod"

_extensions: list = [QueryDepthLimiter(max_depth=_GRAPHQL_MAX_DEPTH)]
if _IS_PROD:
    # Block introspection in prod via the canonical graphql-core rule.
    _extensions.append(AddValidationRules([NoSchemaIntrospectionCustomRule]))

schema = strawberry.Schema(query=Query, extensions=_extensions)
graphql_router = GraphQLRouter(schema, graphql_ide="graphiql" if GRAPHQL_PLAYGROUND else None)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    logger.info("EdgeGuard GraphQL — connecting to Neo4j …")
    _client = Neo4jClient()
    if not _client.connect():
        logger.error("[ERR] GraphQL: Neo4j connection failed on startup")
    else:
        logger.info("[OK] GraphQL: Neo4j connected")
    yield
    if _client:
        logger.info("EdgeGuard GraphQL — closing Neo4j connection")
        _client.close()


app = FastAPI(
    title="EdgeGuard GraphQL API",
    description=(
        "Graph-Augmented Threat Intelligence — GraphQL interface. "
        "Exposes CVE, Vulnerability, Indicator, ThreatActor, Malware, "
        "Technique, Tactic, Tool, Campaign node types from the shared Neo4j graph. "
        "Designed for ISIM-compatible access on port 4001."
    ),
    version=package_version(),
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

allowed_origins = os.getenv("EDGEGUARD_CORS_ORIGINS", "http://localhost,http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

app.include_router(
    graphql_router,
    prefix="/graphql",
    dependencies=[Depends(_verify_api_key)],
)


@app.get("/health")
async def health():
    """Liveness probe — uses Neo4j ping + APOC check (same semantics as REST ``query_api`` /health)."""
    if _client is None or not _client.is_connected():
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "neo4j_connected": False},
        )
    neo4j_ok = bool(_client.health_check().get("healthy"))
    if not neo4j_ok:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "neo4j_connected": False},
        )
    return {"status": "ok", "neo4j_connected": True}


if __name__ == "__main__":
    import uvicorn

    try:
        port = int(os.getenv("EDGEGUARD_GRAPHQL_PORT", "4001"))
    except (ValueError, TypeError):
        port = 4001
    host = os.getenv("EDGEGUARD_GRAPHQL_HOST", "127.0.0.1")
    uvicorn.run("graphql_api:app", host=host, port=port, reload=False)
