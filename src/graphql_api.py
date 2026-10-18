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

import hmac
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import strawberry
from fastapi import Depends, FastAPI, Header, HTTPException, Request
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
from ioc_normalize import indicator_type_filter, normalize_cve_id
from neo4j_client import NEO4J_READ_TIMEOUT, Neo4jClient
from package_meta import deployed_git_sha, package_version

logger = logging.getLogger(__name__)

# Used to construct back-links to the originating MISP event (e.g. misp_event_url field)
MISP_URL = os.getenv("MISP_URL", "").rstrip("/")

# A MISP attribute reference as the graph stores it: the attribute UUID (``attr.uuid``, stable across
# MISP instances), or a numeric attribute id from an older sync. Anything else is not turned into a link.
_MISP_ATTRIBUTE_REF = re.compile(
    r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+)$"
)

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------
EDGEGUARD_API_KEY = os.getenv("EDGEGUARD_API_KEY", "")

# PR-N24 audit HIGH: import the canonical "is production env?" check
# from src/config.py so graphql_api and query_api can never disagree on
# the prod/non-prod classification. Pre-N24 each module defined its own
# check (graphql_api.py had _is_prod_env, query_api.py had _ENV ==
# "prod") — split state. See ``config.is_production_env`` for full
# rationale + allowlist.
from config import is_production_env  # noqa: E402

# Module-level prod flag — used by both the API-key enforcement gate
# (below) AND the GraphQL introspection extension (further down).
# Always agrees with src/query_api.py via the shared helper.
_IS_PROD = is_production_env()
# Backwards-compat: the legacy ``_ENV`` literal is still used by some
# downstream readers / tests. Keep it for surface compatibility but
# DON'T use it for security-relevant gating — is_production_env() is
# the canonical check.
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

if _IS_PROD and not EDGEGUARD_API_KEY:
    raise RuntimeError(
        "EDGEGUARD_API_KEY must be set when EDGEGUARD_ENV is prod (or unset/typo'd "
        "since PR-N23 secure defaults treat unrecognized values as prod). "
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
    """Dependency: require valid API key when EDGEGUARD_API_KEY is configured.

    PR-N3 §9-B7 (Red Team): replaced naive ``!=`` string comparison
    with ``hmac.compare_digest`` to defeat timing side-channels. The
    naive ``!=`` short-circuits at the first byte mismatch, so an
    attacker on a low-latency network can recover the API key one byte
    at a time by measuring response-time differences. ``compare_digest``
    runs in time independent of where (or whether) the inputs differ.

    Edge cases:
      * ``x_api_key is None`` — header missing; reject without invoking
        compare_digest (which would crash on None).
      * ``x_api_key`` is a string but type-mismatched in an exotic way
        (e.g. bytes from a misbehaving client) — wrapped in str() to
        keep ``compare_digest`` happy; still constant-time vs the
        reference value.
    """
    if not EDGEGUARD_API_KEY:
        return
    if x_api_key is None or not hmac.compare_digest(str(EDGEGUARD_API_KEY), str(x_api_key)):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Api-Key header")


_GRAPHQL_RATE_LIMIT_DEFAULT = "120/minute"


def _graphql_rate_limit() -> str:
    """Per-client-address limit of every GraphQL route (``EDGEGUARD_RATE_LIMIT_GRAPHQL``, slowapi
    syntax such as ``600/minute``); unset, blank or not a valid limit string gives the default, so a
    typo cannot stop the service from starting. Behind a reverse proxy every client shares the
    proxy's address and so one limit."""
    raw = (os.getenv("EDGEGUARD_RATE_LIMIT_GRAPHQL") or "").strip()
    if not raw:
        return _GRAPHQL_RATE_LIMIT_DEFAULT
    try:
        from limits import parse_many

        parse_many(raw)
    except ValueError:
        logger.warning(
            "EDGEGUARD_RATE_LIMIT_GRAPHQL=%r is not a valid rate limit; using %s", raw, _GRAPHQL_RATE_LIMIT_DEFAULT
        )
        return _GRAPHQL_RATE_LIMIT_DEFAULT
    return raw


_GRAPHQL_RATE_LIMIT = _graphql_rate_limit()
limiter = Limiter(key_func=get_remote_address, default_limits=[_GRAPHQL_RATE_LIMIT])


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


def _misp_attribute_urls(attribute_ids: List[str]) -> Optional[List[str]]:
    """``<MISP_URL>/attributes/view/<uuid>`` for each stored MISP attribute reference, in stored order.

    The event-level links (``misp_event_urls``) open a whole source event, which for OTX or NVD holds
    100,000+ attributes; this link names the one attribute. None when ``MISP_URL`` is unset or nothing
    usable is stored; a value that is neither a UUID nor a numeric id is skipped.
    """
    if not MISP_URL or not attribute_ids:
        return None
    refs = (str(ref).strip() for ref in attribute_ids)
    urls = [f"{MISP_URL}/attributes/view/{ref}" for ref in refs if _MISP_ATTRIBUTE_REF.fullmatch(ref)]
    return urls or None


# ---------------------------------------------------------------------------
# Resolvers — each returns plain Strawberry dataclass instances
# ---------------------------------------------------------------------------


def _cve_effective_score_severity(c, cv40_node, cv31_node, cv30_node, cv2_node):
    """
    Use CVE node properties when set; otherwise derive from linked CVSS sub-nodes
    (same order as ``cvss_selection.CVSS_VERSIONS``: v3.1 → v3.0 → v2 → v4.0).
    Uses ``is not None`` so a score of 0.0 is preserved. Returns (score, severity, version);
    since 2026-10 ``merge_cve`` sets the node values from the sub-nodes, so the fallback only
    serves nodes written before.
    """
    score = c.get("cvss_score")
    if score is None:
        score = c.get("base_score")
    severity = c.get("severity") or c.get("base_severity")
    if score is not None:
        return score, severity, c.get("cvss_version")
    for node, version in ((cv31_node, "3.1"), (cv30_node, "3.0"), (cv2_node, "2.0"), (cv40_node, "4.0")):
        if node is not None:
            bs = node.get("base_score")
            if bs is not None:
                return bs, node.get("base_severity") or severity, version
    return None, severity, None


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

    eff_score, eff_severity, eff_version = _cve_effective_score_severity(c, cv40_node, cv31_node, cv30_node, cv2_node)

    return CVE(
        cve_id=c.get("cve_id", ""),
        description=c.get("description"),
        description_source=c.get("description_source"),
        published=c.get("published"),
        last_modified=c.get("last_modified"),
        cpe_type=_neo4j_list(c.get("cpe_type")),
        result_impacts=_neo4j_list(c.get("result_impacts")),
        ref_tags=_neo4j_list(c.get("ref_tags")),
        cwe=_neo4j_list(c.get("cwe")),
        base_score=eff_score,
        base_severity=eff_severity,
        cvss_version=eff_version,
        edgeguard_managed=c.get("edgeguard_managed"),
        uuid=c.get("uuid"),
        source=_neo4j_list(c.get("source")),
        zone=_neo4j_list(c.get("zone")),
        tlp=c.get("tlp"),
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


def _clamp_limit(limit: int) -> int:
    """1 ≤ limit ≤ _MAX_GRAPHQL_LIMIT (negative or zero values reached Cypher before 2026-10)."""
    return min(max(int(limit), 1), _MAX_GRAPHQL_LIMIT)


def _clamp_offset(offset: int) -> int:
    """0 ≤ offset ≤ _MAX_GRAPHQL_OFFSET."""
    return min(max(int(offset), 0), _MAX_GRAPHQL_OFFSET)


def _resolve_vulnerabilities(client: Neo4jClient, f: VulnerabilityFilter) -> List[Vulnerability]:
    conditions = ["(n.edgeguard_managed = true OR n.edgeguard_enriched = true)"]
    params: dict = {"limit": _clamp_limit(f.limit), "offset": _clamp_offset(f.offset), "min_cvss": f.min_cvss}

    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone
    if f.status is not strawberry.UNSET and f.status:
        conditions.append("$status IN n.status")
        params["status"] = f.status
    if f.min_cvss > 0:
        conditions.append("n.cvss_score >= $min_cvss")

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    # 2026-10: the MISP → Neo4j sync writes every vulnerability as ``:CVE`` (``merge_cve``); no
    # scheduled writer reaches ``:Vulnerability`` (the alert path writes none), so this list read a
    # label the sync does not write and answered []. Ties on the score go by cve_id so pages are
    # stable.
    query = f"""
    MATCH (n:CVE)
    {where}
    RETURN n
    ORDER BY coalesce(n.cvss_score, -1) DESC, n.cve_id
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
                    description_source=n.get("description_source"),
                    status=_neo4j_list(n.get("status")),
                    severity=n.get("severity"),
                    # Null for a CVE without CVSS (2026-10): never a placeholder score.
                    cvss_score=n.get("cvss_score"),
                    cvss_version=n.get("cvss_version"),
                    published=str(n["published"]) if n.get("published") else None,
                    zone=_neo4j_list(n.get("zone")),
                    tlp=n.get("tlp"),
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
    conditions = ["(n.edgeguard_managed = true OR n.edgeguard_enriched = true)"]
    params: dict = {"limit": _clamp_limit(f.limit), "offset": _clamp_offset(f.offset)}

    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone
    if f.indicator_type is not strawberry.UNSET and f.indicator_type:
        # 2026-10: md5 / sha1 / sha256 / sha512 select the ``hash`` nodes of that digest length
        # (the graph stores every file digest as ``hash``); same rule as the REST filters.
        graph_type, value_pattern = indicator_type_filter(f.indicator_type)
        conditions.append("n.indicator_type = $indicator_type")
        params["indicator_type"] = graph_type
        if value_pattern is not None:
            conditions.append("n.value =~ $indicator_value_pattern")
            params["indicator_value_pattern"] = value_pattern
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
    ORDER BY coalesce(n.confidence_score, -1) DESC
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
            attribute_ids = _neo4j_list(n.get("misp_attribute_ids")) or []
            results.append(
                Indicator(
                    value=n.get("value", ""),
                    indicator_type=n.get("indicator_type", ""),
                    confidence_score=n.get("confidence_score"),
                    zone=_neo4j_list(n.get("zone")),
                    tlp=n.get("tlp"),
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
                    misp_attribute_urls=_misp_attribute_urls(attribute_ids),
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
                    # 2026-10-16: the aging properties (``indicator_aging``).
                    last_reported_at=_str_or_none(n.get("last_reported_at")),
                    last_reported_source=n.get("last_reported_source"),
                    last_reported_ref=n.get("last_reported_ref"),
                    last_recorded_at=_str_or_none(n.get("last_recorded_at")),
                    source_confidence=(
                        n.get("source_confidence")
                        if n.get("source_confidence") is not None
                        else n.get("confidence_score")
                    ),
                    aging_basis=n.get("aging_basis"),
                    aging_tier=n.get("aging_tier"),
                    aging_factor=n.get("aging_factor"),
                    aging_since=_str_or_none(n.get("aging_since")),
                    aging_evaluated_at=_str_or_none(n.get("aging_evaluated_at")),
                    retired_by=n.get("retired_by"),
                    retired_at=_str_or_none(n.get("retired_at")),
                )
            )
    return results


def _str_or_none(value) -> Optional[str]:
    """A stored time as a string (the same form as ``first_imported_at``), or None."""
    return str(value) if value is not None else None


_MAX_GRAPHQL_LIMIT = 500


def _resolve_list(client: Neo4jClient, label: str, f: NodeFilter, cls, mapper):
    conditions = []
    params: dict = {"limit": _clamp_limit(f.limit), "offset": _clamp_offset(f.offset)}

    if f.edgeguard_managed_only:
        conditions.append("(n.edgeguard_managed = true OR n.edgeguard_enriched = true)")
    if f.zone is not strawberry.UNSET and f.zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = f.zone

    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    query = f"""
    MATCH (n:{label})
    {where}
    RETURN n
    ORDER BY coalesce(n.confidence_score, -1) DESC
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
        # READ-side canonicalization (src/ioc_normalize.py): analyst paste
        # variants ('cve 2021 44228', en-dash) → 'CVE-2021-44228'; fall back
        # to the raw input when no CVE id is recognized.
        return _resolve_cve(_get_client(), normalize_cve_id(cve_id) or cve_id)

    @strawberry.field(
        description=(
            "List vulnerabilities (the CVE nodes EdgeGuard created or enriched) with optional zone / status / "
            "CVSS filters, highest score first."
        )
    )
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
                description_source=n.get("description_source"),
                sophistication=n.get("sophistication"),
                primary_motivation=n.get("primary_motivation"),
                resource_level=n.get("resource_level"),
                zone=_neo4j_list(n.get("zone")),
                tlp=n.get("tlp"),
                confidence_score=n.get("confidence_score"),
                source=_neo4j_list(n.get("source")),
                edgeguard_managed=n.get("edgeguard_managed"),
                # PR (S5) (bugbot MED): source-truthful + import
                # wall-clock timestamps, matching Indicator / Vulnerability /
                # Malware resolvers.
                first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
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
                description_source=n.get("description_source"),
                zone=_neo4j_list(n.get("zone")),
                tlp=n.get("tlp"),
                confidence_score=n.get("confidence_score"),
                source=_neo4j_list(n.get("source")),
                edgeguard_managed=n.get("edgeguard_managed"),
                first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
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
                description_source=n.get("description_source"),
                detection=n.get("detection"),
                is_subtechnique=n.get("is_subtechnique"),
                tactic_refs=_neo4j_list(n.get("tactic_phases")),
                zone=_neo4j_list(n.get("zone")),
                tlp=n.get("tlp"),
                confidence_score=n.get("confidence_score"),
                edgeguard_managed=n.get("edgeguard_managed"),
                first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
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
                description_source=n.get("description_source"),
                tlp=n.get("tlp"),
                edgeguard_managed=n.get("edgeguard_managed"),
                first_imported_at=str(n["first_imported_at"]) if n.get("first_imported_at") else None,
                last_updated=str(n["last_updated"]) if n.get("last_updated") else None,
                uuid=n.get("uuid"),
            ),
        )

    @strawberry.field(description="List inferred campaign nodes built by the campaign enrichment job.")
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
                tlp=n.get("tlp"),
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
        conditions = ["(n.edgeguard_managed = true OR n.edgeguard_enriched = true)"]
        # PR-F9 Red Team audit (HIGH): ``limit`` was bound directly into
        # Cypher without the ``_MAX_GRAPHQL_LIMIT=500`` cap that EVERY
        # other resolver applies (vulnerabilities / malwares / actors
        # etc.). A caller requesting ``tools(limit: 100000000)``
        # exhausts the Neo4j heap + Bolt-pool + FastAPI worker before
        # the read timeout fires — trivial DoS on a public-ish surface.
        # Clamp identically to the sibling resolvers.
        params: dict = {"limit": min(max(limit, 1), _MAX_GRAPHQL_LIMIT)}

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
        ORDER BY coalesce(n.confidence_score, -1) DESC
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
                        description_source=n.get("description_source"),
                        tag=n.get("tag"),
                        tool_types=_neo4j_list(n.get("tool_types")),
                        uses_techniques=_neo4j_list(n.get("uses_techniques")),
                        zone=_neo4j_list(n.get("zone")),
                        tlp=n.get("tlp"),
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
from graphql import (  # noqa: E402
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLError,
    InlineFragmentNode,
    OperationDefinitionNode,
    ValidationRule,
)
from graphql.validation import NoSchemaIntrospectionCustomRule  # noqa: E402
from strawberry.extensions import MaxAliasesLimiter, QueryDepthLimiter, SchemaExtension  # noqa: E402
from strawberry.extensions.add_validation_rules import AddValidationRules  # noqa: E402


def _env_graphql_max_depth(default: int = 8) -> int:
    """Query-depth limit from the environment; unset, empty, non-numeric or non-positive → *default*
    (2026-10: an empty forwarded variable used to raise ValueError at import and stop the API)."""
    raw = (os.getenv("EDGEGUARD_GRAPHQL_MAX_DEPTH") or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


_GRAPHQL_MAX_DEPTH = _env_graphql_max_depth()


def _env_positive_int(name: str, default: int) -> int:
    """Positive integer from the environment; unset, empty, non-numeric or non-positive → default."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


# 2026-10 readiness check: 300 aliased root fields ran 300 Cypher statements in one request.
_GRAPHQL_MAX_ALIASES = _env_positive_int("EDGEGUARD_GRAPHQL_MAX_ALIASES", 15)
_MAX_GRAPHQL_OFFSET = 100_000  # same ceiling as the REST API
# Expanded selection budget checked BEFORE validation (Bugbot on #151, round 2): Strawberry's
# QueryDepthLimiter re-walks every fragment spread without memoisation, so a chain of doubling
# fragments costs exponential validation time regardless of the alias / root-field caps.
_GRAPHQL_MAX_SELECTIONS = _env_positive_int("EDGEGUARD_GRAPHQL_MAX_SELECTIONS", 2000)
_GRAPHQL_MAX_FRAGMENT_DEPTH = 16
_GRAPHQL_MAX_FIELD_NESTING = 64  # plain field nesting; the depth limiter (8) still applies after validation
_MAX_BODY_BYTES = _env_positive_int("EDGEGUARD_MAX_BODY_BYTES", 1 * 1024 * 1024)
# Note: ``_IS_PROD`` is defined at the top of this module (line ~70)
# alongside the API-key auth check. The single source of truth is
# ``_is_prod_env()`` so the introspection-enable check below and the
# auth-gate check above ALWAYS agree. PR-N23 Bugbot round 1 (PR #107
# MEDIUM) — pre-fix had two separate env reads that could disagree.


def _make_root_field_limit_rule(max_fields: int) -> type:  # noqa: C901 — one rule, two small methods
    """graphql-core validation rule capping the root fields one operation executes.

    Counts aliases and expands fragment spreads (every spread occurrence counts), which is the
    fan-out ``MaxAliasesLimiter`` misses: one fragment holding a few aliased root fields, spread
    many times, still executed one Cypher statement per expanded field (Bugbot on #151).
    """

    class MaxRootFieldsRule(ValidationRule):
        # Bugbot on #151: a chain of doubling fragments made the expansion exponential and a long
        # linear chain hit RecursionError before the cap was checked. The walk now stops as soon as
        # the running total exceeds the cap (bounded work: at most max_fields + 1 fields are ever
        # counted) and refuses nesting deeper than _MAX_SPREAD_DEPTH.
        _MAX_SPREAD_DEPTH = 16

        def enter_operation_definition(self, node, *_args):  # noqa: ANN001
            total = self._count(node.selection_set, frozenset(), 0, 0)
            if total > max_fields:
                self.report_error(
                    GraphQLError(
                        f"more than {max_fields} root fields requested (aliases and fragments expanded); "
                        f"allowed: {max_fields}",
                        node,
                    )
                )

        def _count(self, selection_set, seen, total, depth):  # noqa: ANN001
            """Running count of root fields; returns early once ``total`` exceeds the cap."""
            if selection_set is None:
                return total
            if depth > self._MAX_SPREAD_DEPTH:
                return max_fields + 1  # too deeply nested to be legitimate: treat as over the cap
            for sel in selection_set.selections:
                if total > max_fields:
                    return total
                if isinstance(sel, FieldNode):
                    total += 1
                elif isinstance(sel, InlineFragmentNode):
                    total = self._count(sel.selection_set, seen, total, depth + 1)
                elif isinstance(sel, FragmentSpreadNode):
                    name = sel.name.value
                    if name in seen:
                        continue  # cycles are rejected by NoFragmentCyclesRule; never recurse into one
                    fragment = self.context.get_fragment(name)
                    if fragment is not None:
                        total = self._count(fragment.selection_set, seen | {name}, total, depth + 1)
            return total

    return MaxRootFieldsRule


def _expanded_selection_count(document: Any, cap: int, max_depth: int) -> tuple[int, Optional[str]]:
    """Selections an operation would execute after expanding fragments, computed with memoisation
    (linear in document size). Returns ``(count, problem)``; ``problem`` names a fragment cycle or
    nesting deeper than ``max_depth``. Counting stops once ``cap`` is exceeded."""
    fragments = {d.name.value: d for d in document.definitions if isinstance(d, FragmentDefinitionNode)}
    size_memo: Dict[str, int] = {}
    nest_memo: Dict[str, int] = {}
    problem: Optional[str] = None

    def nesting(name: str, stack: frozenset) -> int:
        """Spread levels below fragment ``name`` (memoised by name; independent of where it is used —
        Bugbot on #151: a depth check that only ran on the first visit was bypassed by spreading F0..Fn
        in that order). The walk itself is bounded: once the chain of spreads being followed is longer
        than ``max_depth`` the document is rejected without recursing further, so a long linear chain
        can never exhaust the interpreter stack (Bugbot round 4)."""
        nonlocal problem
        if name in nest_memo:
            return nest_memo[name]
        fragment = fragments.get(name)
        if fragment is None:
            return 0
        if name in stack:
            problem = f"fragment cycle through {name}"
            return max_depth + 1
        if len(stack) > max_depth:
            problem = f"fragment nesting deeper than {max_depth}"
            return max_depth + 1
        below = 0

        def walk(selection_set: Any, field_depth: int) -> None:
            nonlocal below, problem
            if selection_set is None or problem is not None:
                return
            if field_depth > _GRAPHQL_MAX_FIELD_NESTING:
                problem = f"selection nesting deeper than {_GRAPHQL_MAX_FIELD_NESTING}"
                return
            for sel in selection_set.selections:
                if isinstance(sel, (FieldNode, InlineFragmentNode)):
                    walk(sel.selection_set, field_depth + 1)
                elif isinstance(sel, FragmentSpreadNode):
                    below = max(below, 1 + nesting(sel.name.value, stack | {name}))
                if problem is not None:
                    return

        walk(fragment.selection_set, 0)
        if problem is None:
            nest_memo[name] = below
        return below

    def size(selection_set: Any, stack: frozenset, depth: int, field_depth: int = 0) -> int:
        nonlocal problem
        if selection_set is None or problem is not None:
            return 0
        if field_depth > _GRAPHQL_MAX_FIELD_NESTING:
            problem = f"selection nesting deeper than {_GRAPHQL_MAX_FIELD_NESTING}"
            return cap + 1
        total = 0
        for sel in selection_set.selections:
            if isinstance(sel, FieldNode):
                total += 1 + size(sel.selection_set, stack, depth, field_depth + 1)
            elif isinstance(sel, InlineFragmentNode):
                total += size(sel.selection_set, stack, depth + 1)
            elif isinstance(sel, FragmentSpreadNode):
                name = sel.name.value
                if name in stack:
                    problem = f"fragment cycle through {name}"
                    return cap + 1
                if depth + 1 + nesting(name, stack) > max_depth:
                    problem = problem or f"fragment nesting deeper than {max_depth}"
                    return cap + 1
                if name not in size_memo:
                    fragment = fragments.get(name)
                    size_memo[name] = size(fragment.selection_set, stack | {name}, depth + 1) if fragment else 0
                total += size_memo[name]
            if total > cap or problem is not None:
                return total
        return total

    total = 0
    for definition in document.definitions:
        if isinstance(definition, OperationDefinitionNode):
            total += size(definition.selection_set, frozenset(), 0)
            if total > cap or problem:
                break
    return total, problem


class FragmentBudget(SchemaExtension):
    """Rejects a document whose expanded size, fragment nesting or fragment cycles would make
    validation itself expensive — before any validation rule runs. Setting
    ``pre_execution_errors`` makes Strawberry skip ``validate_document`` and answer with the error."""

    def on_validate(self):  # noqa: ANN201 — Strawberry hook (generator)
        ctx = self.execution_context
        document = getattr(ctx, "graphql_document", None)
        if document is not None and ctx.pre_execution_errors is None:
            count, problem = _expanded_selection_count(document, _GRAPHQL_MAX_SELECTIONS, _GRAPHQL_MAX_FRAGMENT_DEPTH)
            if problem is not None:
                ctx.pre_execution_errors = [GraphQLError(f"Query rejected: {problem}")]
            elif count > _GRAPHQL_MAX_SELECTIONS:
                ctx.pre_execution_errors = [
                    GraphQLError(
                        f"Query rejected: more than {_GRAPHQL_MAX_SELECTIONS} selections after fragment expansion"
                    )
                ]
        yield


class MaxRootFieldsLimiter(AddValidationRules):
    """Extension installing the root-field rule (its own class so it is distinguishable from the
    prod-only introspection rule, which is also an AddValidationRules instance)."""

    def __init__(self, max_fields: int) -> None:
        super().__init__([_make_root_field_limit_rule(max_fields)])


_extensions: list = [
    FragmentBudget(),
    QueryDepthLimiter(max_depth=_GRAPHQL_MAX_DEPTH),
    MaxAliasesLimiter(max_alias_count=_GRAPHQL_MAX_ALIASES),
    MaxRootFieldsLimiter(_GRAPHQL_MAX_ALIASES),
]
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
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if _IS_PROD:

    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(_verify_api_key)])
    @limiter.limit(_GRAPHQL_RATE_LIMIT)
    async def openapi_document(request: Request) -> dict:
        """OpenAPI document for key holders (prod); rate-limited like every other route."""
        return app.openapi()


@app.middleware("http")
async def enforce_body_size(request: Request, call_next):
    """Reject requests whose Content-Length exceeds the configured maximum (same cap as the REST API)."""
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > _MAX_BODY_BYTES:
        return JSONResponse({"detail": f"Request body too large (max {_MAX_BODY_BYTES} bytes)"}, status_code=413)
    return await call_next(request)


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
    """Liveness probe — uses Neo4j ping + APOC check (same semantics as REST ``query_api`` /health).

    ``git_sha`` is the commit the container was deployed from (``EDGEGUARD_GIT_SHA``; null when
    unset), in every state.
    """
    git_sha = deployed_git_sha()
    if _client is None or not _client.is_connected():
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "neo4j_connected": False, "git_sha": git_sha},
        )
    neo4j_ok = bool(_client.health_check().get("healthy"))
    if not neo4j_ok:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "neo4j_connected": False, "git_sha": git_sha},
        )
    return {"status": "ok", "neo4j_connected": True, "git_sha": git_sha}


if __name__ == "__main__":
    import uvicorn

    try:
        port = int(os.getenv("EDGEGUARD_GRAPHQL_PORT", "4001"))
    except (ValueError, TypeError):
        port = 4001
    host = os.getenv("EDGEGUARD_GRAPHQL_HOST", "127.0.0.1")
    # PR-A audit fix (Red Team HIGH): docker-compose's ``graphql`` service now
    # invokes ``python -m src.graphql_api`` so the EDGEGUARD_GRAPHQL_HOST env-var
    # safety check actually gates the bind (parity with the REST API). Multi-worker
    # config moves to EDGEGUARD_GRAPHQL_WORKERS so production posture matches.
    try:
        workers = int(os.getenv("EDGEGUARD_GRAPHQL_WORKERS", "1"))
    except (ValueError, TypeError):
        workers = 1
    # PR-A audit fix (Bugbot MED on commit ce37238): use ``"src.graphql_api:app"``
    # so uvicorn's worker reimport resolves regardless of PYTHONPATH. Same
    # reasoning as src/query_api.py:1170 — the bare ``"graphql_api:app"``
    # only works when PYTHONPATH includes /app/src.
    uvicorn.run("src.graphql_api:app", host=host, port=port, reload=False, workers=workers)
