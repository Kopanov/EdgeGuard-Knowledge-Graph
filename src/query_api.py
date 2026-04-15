"""
FastAPI Query Engine for GraphRAG
REST endpoints for threat intelligence queries
"""

import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from neo4j_client import Neo4jClient
from package_meta import package_version

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Neo4j query timeout (seconds) — prevents hung queries from blocking API workers
_NEO4J_QUERY_TIMEOUT = 300

# Initialize OpenTelemetry
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# Global Neo4j client
neo4j_client: Optional[Neo4jClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - connect/disconnect Neo4j."""
    global neo4j_client

    # Startup
    logger.info("🔌 Connecting to Neo4j...")
    neo4j_client = Neo4jClient()
    if not neo4j_client.connect():
        logger.error("[ERR] Failed to connect to Neo4j on startup")
    else:
        logger.info("[OK] Connected to Neo4j")

    yield

    # Shutdown
    if neo4j_client:
        logger.info("🔌 Closing Neo4j connection...")
        neo4j_client.close()


ADMIN_QUERY_ENABLED = os.getenv("EDGEGUARD_ENABLE_ADMIN_QUERY", "false").lower() == "true"
ADMIN_QUERY_TOKEN = os.getenv("EDGEGUARD_ADMIN_TOKEN")

# ── Rate limiting ─────────────────────────────────────────────────────────────
# Default: 60 read requests / minute per IP.  Admin endpoint is more restricted.
_RATE_LIMIT_READ = os.getenv("EDGEGUARD_RATE_LIMIT_READ", "60/minute")
_RATE_LIMIT_ADMIN = os.getenv("EDGEGUARD_RATE_LIMIT_ADMIN", "10/minute")
limiter = Limiter(key_func=get_remote_address)

# API key for the public read endpoints.  Set EDGEGUARD_API_KEY to a non-empty
# value to require authentication.  Leave unset only in local dev.
_API_KEY = os.getenv("EDGEGUARD_API_KEY")
_ENV = os.getenv("EDGEGUARD_ENV", "dev").lower()

if _ENV == "prod" and not _API_KEY:
    raise RuntimeError(
        "EDGEGUARD_API_KEY must be set when EDGEGUARD_ENV=prod. "
        "Set a strong random value before starting the API in production."
    )
if not _API_KEY:
    logger.warning(
        "EDGEGUARD_API_KEY is not configured — all API endpoints are UNAUTHENTICATED. "
        "Set EDGEGUARD_API_KEY to enable authentication."
    )


def _verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    """Dependency: require a valid API key when EDGEGUARD_API_KEY is configured."""
    if _API_KEY and x_api_key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


_PKG_VERSION = package_version()

# Initialize FastAPI app
app = FastAPI(
    title="EdgeGuard Query API",
    description="REST API for querying threat intelligence data from Neo4j GraphRAG",
    version=_PKG_VERSION,
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

try:
    _MAX_BODY_BYTES = int(os.getenv("EDGEGUARD_MAX_BODY_BYTES", str(1 * 1024 * 1024)))
except (ValueError, TypeError):
    _MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MB default


@app.middleware("http")
async def enforce_body_size(request: Request, call_next):
    """Reject requests whose Content-Length exceeds the configured maximum."""
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > _MAX_BODY_BYTES:
        return JSONResponse(
            {"detail": f"Request body too large (max {_MAX_BODY_BYTES} bytes)"},
            status_code=413,
        )
    return await call_next(request)


# Instrument FastAPI with OpenTelemetry
FastAPIInstrumentor.instrument_app(app)


# Add trace ID to responses
@app.middleware("http")
async def add_trace_id(request, call_next):
    span = trace.get_current_span()
    response = await call_next(request)
    response.headers["X-Trace-ID"] = str(span.get_span_context().trace_id)
    return response


# CORS middleware
allowed_origins = os.getenv("EDGEGUARD_CORS_ORIGINS", "http://localhost,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in allowed_origins if o.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "X-Admin-Token", "Content-Type"],
)


# ============================================================================
# Enums for validated string parameters
# ============================================================================

from enum import Enum


class ZoneEnum(str, Enum):
    global_ = "global"
    healthcare = "healthcare"
    energy = "energy"
    finance = "finance"


class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IndicatorTypeEnum(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"
    sha512 = "sha512"
    email = "email"
    hash = "hash"


# ============================================================================
# Pydantic Models
# ============================================================================


class ThreatQuery(BaseModel):
    """Natural language threat query request."""

    query: str = Field(..., min_length=1, max_length=500, description="Natural language query string")
    zone: Optional[ZoneEnum] = Field(None, description="Filter by zone/sector")
    limit: int = Field(10, ge=1, le=100, description="Maximum results to return")
    # return_cypher is restricted to dev mode only (see endpoint guard below)
    return_cypher: bool = Field(False, description="Include generated Cypher in response (dev mode only)")


class IndicatorSearch(BaseModel):
    """Indicator search request."""

    value: str = Field(..., min_length=1, max_length=512, description="Indicator value to search for")
    zone: Optional[ZoneEnum] = Field(None, description="Filter by zone/sector")
    indicator_type: Optional[IndicatorTypeEnum] = Field(None, description="Filter by indicator type")


class ThreatResponse(BaseModel):
    """Threat query response."""

    query: str
    results: List[Dict[str, Any]]
    total: int
    zone: Optional[str] = None
    execution_time_ms: float
    cypher: Optional[str] = Field(
        default=None,
        description="Generated Cypher query (included only when requested).",
    )


class IndicatorResponse(BaseModel):
    """Indicator search response."""

    value: str
    found: bool
    indicator: Optional[Dict[str, Any]] = None
    related: List[Dict[str, Any]] = []
    zone: Optional[str] = None


class ZoneThreatsResponse(BaseModel):
    """Zone threats response."""

    zone: str
    threats: List[Dict[str, Any]]
    total: int
    summary: Dict[str, Any]


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    neo4j_connected: bool
    version: str = _PKG_VERSION


class GraphQueryRequest(BaseModel):
    """Direct Cypher query request (admin use)."""

    cypher: str = Field(..., description="Cypher query to execute")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


# ============================================================================
# API Endpoints
# ============================================================================


@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Health check endpoint.

    Returns API status and Neo4j connectivity.
    """
    global neo4j_client

    if neo4j_client is None:
        neo4j_ok = False
    else:
        # Full ping + APOC check — Neo4jClient.is_connected() is driver-only (fast path for other routes).
        neo4j_ok = bool(neo4j_client.health_check().get("healthy"))

    return HealthResponse(
        status="ok" if neo4j_ok else "degraded",
        neo4j_connected=neo4j_ok,
        version=_PKG_VERSION,
    )


@app.post("/query", response_model=ThreatResponse, dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def query_threats(request: Request, q: ThreatQuery):
    """
    Natural language query endpoint.

    Translates natural language queries to Cypher and returns enriched results.

    Examples:
    - "Show me all high severity CVEs"
    - "Find threats related to APT29"
    - "What indicators are in the finance sector?"
    """
    with tracer.start_as_current_span("query_threats") as span:
        span.set_attribute("query.text", q.query)
        span.set_attribute("zone", q.zone or "global")

        import time

        start_time = time.time()

        if not neo4j_client or not neo4j_client.is_connected():
            raise HTTPException(status_code=503, detail="Neo4j not connected")

        # Parse natural language query to Cypher.
        # Sanitize newlines before logging to prevent log injection.
        _safe_q = q.query.replace("\n", "\\n").replace("\r", "\\r")
        cypher_query = _parse_natural_language(q.query, q.zone.value if q.zone else None)
        span.set_attribute("query.length", len(q.query))
        span.set_attribute("zone", q.zone.value if q.zone else "global")
        logger.info("Graph query: length=%d zone=%s", len(q.query), q.zone or "global")
        logger.debug("Graph query text=%r cypher=%s", _safe_q, cypher_query)

        try:
            with tracer.start_as_current_span("neo4j.execute") as neo4j_span:
                params: Dict[str, Any] = {"limit": q.limit}
                if q.zone:
                    params["zone"] = q.zone.value
                with neo4j_client.driver.session() as session:
                    result = session.run(cypher_query, **params, timeout=_NEO4J_QUERY_TIMEOUT)
                    records = [dict(record["n"]) for record in result]
                neo4j_span.set_attribute("records.count", len(records))

            execution_time = (time.time() - start_time) * 1000
            span.set_attribute("execution_time_ms", execution_time)

            return ThreatResponse(
                query=q.query,
                results=records,
                total=len(records),
                zone=q.zone.value if q.zone else None,
                execution_time_ms=round(execution_time, 2),
                # Only expose the generated Cypher in non-production builds.
                cypher=cypher_query if (q.return_cypher and _ENV != "prod") else None,
            )

        except Exception as e:
            logger.error("Query failed", exc_info=True)
            span.set_attribute("error", True)
            span.set_attribute("error.message", str(e))
            raise HTTPException(status_code=500, detail="Internal error — see server logs")


@app.post("/search/indicator", response_model=IndicatorResponse, dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def search_indicator(request: Request, s: IndicatorSearch):
    """
    Search for a specific indicator.

    Returns the indicator and related threats/entities.
    """
    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    try:
        with neo4j_client.driver.session() as session:
            # Find the indicator
            query = """
                MATCH (n:Indicator {value: $value})
                WHERE n.edgeguard_managed = true
                RETURN n LIMIT 1
            """
            result = session.run(query, value=s.value, timeout=_NEO4J_QUERY_TIMEOUT)
            record = result.single()

            if not record:
                return IndicatorResponse(value=s.value, found=False, zone=s.zone.value if s.zone else None)

            indicator = dict(record["n"])

            # Find related entities
            related_query = """
                MATCH (n:Indicator {value: $value})--(related)
                WHERE n.edgeguard_managed = true
                RETURN related LIMIT 10
            """
            related_result = session.run(related_query, value=s.value, timeout=_NEO4J_QUERY_TIMEOUT)
            related = [dict(r["related"]) for r in related_result]

            return IndicatorResponse(
                value=s.value, found=True, indicator=indicator, related=related, zone=s.zone.value if s.zone else None
            )

    except Exception:
        logger.error("Indicator search failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


@app.get("/zone/{zone}", response_model=ZoneThreatsResponse, dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def get_zone_threats(
    request: Request,
    zone: ZoneEnum,
    limit: int = Query(10, ge=1, le=100),
    severity: Optional[SeverityEnum] = Query(None, description="Filter by severity"),
):
    """
    Get threats for a specific zone/sector.

    Returns all threat intelligence relevant to the specified zone.
    """
    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    try:
        with neo4j_client.driver.session() as session:
            # Build query with optional severity filter
            where_clause = "$zone IN n.zone AND n.edgeguard_managed = true"
            if severity:
                where_clause += " AND n.severity = $severity"

            query = f"""
                MATCH (n)
                WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR n:ThreatActor OR n:Technique OR n:Campaign)
                  AND {where_clause}
                RETURN n
                ORDER BY n.last_updated DESC
                LIMIT $limit
            """

            params = {"zone": zone.value, "limit": limit}
            if severity:
                params["severity"] = severity.value.upper()

            result = session.run(query, **params, timeout=_NEO4J_QUERY_TIMEOUT)
            threats = [dict(r["n"]) for r in result]

            # Get summary stats
            summary_query = """
                MATCH (n)
                WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR n:ThreatActor OR n:Technique OR n:Campaign)
                  AND $zone IN n.zone AND n.edgeguard_managed = true
                RETURN
                    count(n) as total,
                    count(CASE WHEN n.severity = 'CRITICAL' THEN 1 END) as critical,
                    count(CASE WHEN n.severity = 'HIGH' THEN 1 END) as high,
                    count(CASE WHEN n.severity = 'MEDIUM' THEN 1 END) as medium,
                    count(CASE WHEN n.severity = 'LOW' THEN 1 END) as low
            """
            summary_result = session.run(summary_query, zone=zone.value, timeout=_NEO4J_QUERY_TIMEOUT)
            summary_record = summary_result.single()
            summary = {
                "total": summary_record["total"],
                "by_severity": {
                    "critical": summary_record["critical"],
                    "high": summary_record["high"],
                    "medium": summary_record["medium"],
                    "low": summary_record["low"],
                },
            }

            return ZoneThreatsResponse(zone=zone.value, threats=threats, total=len(threats), summary=summary)

    except Exception:
        logger.error("Zone threats query failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


@app.get("/indicators", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def list_indicators(
    request: Request,
    indicator_type: Optional[IndicatorTypeEnum] = Query(None, description="Filter by type"),
    zone: Optional[ZoneEnum] = Query(None, description="Filter by zone"),
    source: Optional[str] = Query(None, max_length=100, description="Filter by source"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=100_000),
):
    """
    List all indicators with optional filters.

    Supports pagination with limit/offset.
    """
    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    try:
        with neo4j_client.driver.session() as session:
            # Build dynamic WHERE clause
            conditions = []
            params = {"limit": limit, "offset": offset}

            if indicator_type:
                conditions.append("n.indicator_type = $indicator_type")
                params["indicator_type"] = indicator_type.value
            if zone:
                conditions.append("$zone IN n.zone")
                params["zone"] = zone.value
            if source:
                conditions.append("$source IN n.source")
                params["source"] = source

            conditions.append("n.edgeguard_managed = true")
            where_clause = " AND ".join(conditions) if conditions else "1=1"

            query = f"""
                MATCH (n:Indicator)
                WHERE {where_clause}
                RETURN n
                ORDER BY n.last_updated DESC
                SKIP $offset
                LIMIT $limit
            """

            result = session.run(query, **params, timeout=_NEO4J_QUERY_TIMEOUT)
            indicators = [dict(r["n"]) for r in result]

            # Get total count
            count_query = f"""
                MATCH (n:Indicator)
                WHERE {where_clause}
                RETURN count(n) as total
            """
            count_params = {k: v for k, v in params.items() if k not in ["limit", "offset"]}
            count_result = session.run(count_query, **count_params, timeout=_NEO4J_QUERY_TIMEOUT)
            total = count_result.single()["total"]

            return {"indicators": indicators, "total": total, "limit": limit, "offset": offset}

    except Exception:
        logger.error("List indicators failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


@app.get("/vulnerabilities", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def list_vulnerabilities(
    request: Request,
    severity: Optional[SeverityEnum] = Query(None, description="Filter by severity"),
    zone: Optional[ZoneEnum] = Query(None, description="Filter by zone"),
    limit: int = Query(50, ge=1, le=500),
):
    """
    List CVE vulnerabilities.

    Returns CVEs with optional severity and zone filters.
    """
    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    try:
        with neo4j_client.driver.session() as session:
            conditions = ["(n:Vulnerability OR n:CVE OR n.type = 'vulnerability')", "n.edgeguard_managed = true"]
            params = {"limit": limit}

            if severity:
                conditions.append("n.severity = $severity")
                params["severity"] = severity.value.upper()
            if zone:
                conditions.append("$zone IN n.zone")
                params["zone"] = zone.value

            where_clause = " AND ".join(conditions)

            query = f"""
                MATCH (n)
                WHERE {where_clause}
                RETURN n
                ORDER BY n.cvss_score DESC
                LIMIT $limit
            """

            result = session.run(query, **params, timeout=_NEO4J_QUERY_TIMEOUT)
            vulnerabilities = [dict(r["n"]) for r in result]

            return {"vulnerabilities": vulnerabilities, "total": len(vulnerabilities)}

    except Exception:
        logger.error("List vulnerabilities failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


class GraphView(str, Enum):
    attacks = "attacks"
    actors = "actors"
    indicators = "indicators"
    vulnerabilities = "vulnerabilities"


@app.get("/graph/explore", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def graph_explore(
    request: Request,
    view: GraphView = Query(GraphView.attacks, description="Graph view to render"),
    zone: Optional[ZoneEnum] = Query(default=None, description="Filter by zone"),
    limit: int = Query(default=100, ge=10, le=500, description="Max nodes to return"),
):
    """
    Return Cytoscape.js-formatted graph data for the interactive visualization.

    Views:
    - **attacks**: Malware → Indicators → Sectors
    - **actors**: ThreatActors → Techniques (→ Tactics)
    - **indicators**: IOCs grouped by zone
    - **vulnerabilities**: CVEs sized by CVSS, CISA KEV highlighted
    """
    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    zone_param: dict = {}
    if zone:
        zone_param = {"zone": zone.value}

    nodes: list = []
    edges: list = []
    seen_ids: set = set()

    def _add_node(nid: str, label: str, ntype: str, extra: dict | None = None):
        if nid not in seen_ids:
            seen_ids.add(nid)
            data = {"id": nid, "label": label, "type": ntype}
            if extra:
                data.update(extra)
            nodes.append({"data": data})

    def _add_edge(src: str, tgt: str, etype: str, extra: dict | None = None):
        data = {"source": src, "target": tgt, "type": etype}
        if extra:
            data.update(extra)
        edges.append({"data": data})

    try:
        with neo4j_client.driver.session(default_access_mode="READ") as session:
            if view == GraphView.attacks:
                # Malware → Indicators → Sectors
                zone_ind = ""
                if zone:
                    zone_ind = "AND $zone IN coalesce(i.zone, [])"

                # Malware → Indicator edges are INDICATES (dropped/observed
                # artifact) or DROPS (file drop). The legacy filter included
                # "USES" which was incorrect — USES here was previously
                # (Actor/Malware)→Technique, not Malware→Indicator, so any
                # match was unreachable. Kept the two valid types.
                cypher = f"""
                    MATCH (m:Malware)-[r]->(i:Indicator)
                    WHERE type(r) IN ['INDICATES', 'DROPS'] AND m.edgeguard_managed = true
                    {zone_ind}
                    WITH m, i, type(r) AS rel_type
                    LIMIT $limit
                    RETURN m.name AS malware_name, m.family AS malware_family,
                           i.value AS ind_value, i.indicator_type AS ind_type,
                           coalesce(i.zone, ['global']) AS ind_zones,
                           i.confidence_score AS ind_confidence,
                           i.indicator_role AS ind_role,
                           i.threat_label AS ind_threat_label,
                           rel_type
                """
                result = session.run(cypher, limit=limit, **zone_param, timeout=_NEO4J_QUERY_TIMEOUT)
                for r in result:
                    mid = f"malware:{r['malware_name']}"
                    iid = f"indicator:{r['ind_value']}"
                    _add_node(mid, r["malware_name"], "malware", {"family": r.get("malware_family", "")})
                    _add_node(
                        iid,
                        r["ind_value"],
                        "indicator",
                        {
                            "indicator_type": r.get("ind_type", ""),
                            "confidence": r.get("ind_confidence", 0),
                            "sector": r.get("ind_zones", ["global"])[0] if r.get("ind_zones") else "global",
                            "indicator_role": r.get("ind_role", ""),
                            "threat_label": r.get("ind_threat_label", ""),
                        },
                    )
                    _add_edge(mid, iid, r.get("rel_type", "INDICATES"))
                    for z in r.get("ind_zones", []):
                        sid = f"sector:{z}"
                        _add_node(sid, z.title(), "sector", {"sector": z})
                        _add_edge(iid, sid, "BELONGS_TO")

            elif view == GraphView.actors:
                # ThreatActors → Techniques (→ Tactics)
                zone_act = ""
                if zone:
                    zone_act = "AND $zone IN coalesce(a.zone, [])"

                cypher = f"""
                    MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
                    WHERE t.mitre_id IS NOT NULL AND a.edgeguard_managed = true
                    {zone_act}
                    WITH a, t
                    LIMIT $limit
                    OPTIONAL MATCH (t)-[:IN_TACTIC]->(tac:Tactic)
                    RETURN a.name AS actor_name,
                           coalesce(a.zone, ['global']) AS actor_zones,
                           t.mitre_id AS technique_id, t.name AS technique_name,
                           collect(DISTINCT tac.name) AS tactics
                """
                result = session.run(cypher, limit=limit, **zone_param, timeout=_NEO4J_QUERY_TIMEOUT)
                for r in result:
                    aid = f"actor:{r['actor_name']}"
                    tid = f"technique:{r['technique_id']}"
                    _add_node(
                        aid,
                        r["actor_name"],
                        "actor",
                        {"sector": r.get("actor_zones", ["global"])[0] if r.get("actor_zones") else "global"},
                    )
                    _add_node(
                        tid,
                        r["technique_id"],
                        "technique",
                        {"name": r.get("technique_name", ""), "tactics": r.get("tactics", [])},
                    )
                    _add_edge(aid, tid, "EMPLOYS_TECHNIQUE")
                    for tac in r.get("tactics") or []:
                        tacid = f"tactic:{tac}"
                        _add_node(tacid, tac, "tactic")
                        _add_edge(tid, tacid, "IN_TACTIC")

            elif view == GraphView.indicators:
                # Indicators grouped by zone
                zone_ind = ""
                if zone:
                    zone_ind = "AND $zone IN coalesce(n.zone, [])"

                cypher = f"""
                    MATCH (n:Indicator)
                    WHERE n.value IS NOT NULL AND n.edgeguard_managed = true
                    {zone_ind}
                    RETURN n.value AS value, n.indicator_type AS ind_type,
                           coalesce(n.zone, ['global']) AS zones,
                           n.confidence_score AS confidence,
                           n.malware_family AS malware_family,
                           n.domain AS domain,
                           n.source AS sources,
                           n.indicator_role AS indicator_role,
                           n.url_status AS url_status,
                           n.threat_label AS threat_label,
                           n.abuse_categories AS abuse_categories
                    ORDER BY n.confidence_score DESC
                    LIMIT $limit
                """
                result = session.run(cypher, limit=limit, **zone_param, timeout=_NEO4J_QUERY_TIMEOUT)
                for r in result:
                    iid = f"indicator:{r['value']}"
                    _add_node(
                        iid,
                        r["value"],
                        "indicator",
                        {
                            "indicator_type": r.get("ind_type", ""),
                            "confidence": r.get("confidence", 0),
                            "malware_family": r.get("malware_family", ""),
                            "sector": r.get("zones", ["global"])[0] if r.get("zones") else "global",
                            "sources": r.get("sources", []),
                            "indicator_role": r.get("indicator_role", ""),
                            "url_status": r.get("url_status", ""),
                            "threat_label": r.get("threat_label", ""),
                            "abuse_categories": r.get("abuse_categories", []),
                        },
                    )
                    for z in r.get("zones", []):
                        sid = f"sector:{z}"
                        _add_node(sid, z.title(), "sector", {"sector": z})
                        _add_edge(iid, sid, "BELONGS_TO")

            elif view == GraphView.vulnerabilities:
                # CVEs sized by CVSS, CISA KEV highlighted.
                # CISA KEV fields live on CVE nodes (via merge_cve), while CVSS/severity
                # live on Vulnerability nodes (via merge_vulnerability). Query both labels
                # and coalesce so KEV data is never missed.
                zone_vuln = ""
                if zone:
                    zone_vuln = "AND $zone IN coalesce(n.zone, [])"

                cypher = f"""
                    MATCH (n)
                    WHERE (n:Vulnerability OR n:CVE) AND n.cve_id IS NOT NULL AND n.edgeguard_managed = true
                    {zone_vuln}
                    WITH n.cve_id AS cve_id,
                         max(n.cvss_score) AS cvss_score,
                         head(collect(n.severity)) AS severity,
                         head(collect(n.attack_vector)) AS attack_vector,
                         reduce(z = [], x IN collect(coalesce(n.zone, ['global'])) | z + x) AS zones_raw,
                         head(collect(n.cisa_exploit_add)) AS cisa_exploit_add,
                         head(collect(n.cisa_action_due)) AS cisa_action_due,
                         head(collect(n.cisa_notes)) AS cisa_notes,
                         head(collect(n.cisa_cwes)) AS cisa_cwes,
                         head(collect(n.version_constraints)) AS version_constraints,
                         head(collect(n.description)) AS description
                    WITH cve_id, cvss_score, severity, attack_vector,
                         apoc.coll.toSet(zones_raw) AS zones,
                         cisa_exploit_add, cisa_action_due, cisa_notes,
                         cisa_cwes, version_constraints, description
                    ORDER BY coalesce(cvss_score, 0) DESC
                    LIMIT $limit
                    RETURN cve_id, cvss_score, severity, attack_vector, zones,
                           cisa_exploit_add, cisa_action_due, cisa_notes,
                           cisa_cwes, version_constraints, description
                """
                result = session.run(cypher, limit=limit, **zone_param, timeout=_NEO4J_QUERY_TIMEOUT)
                vuln_ids = []
                for r in result:
                    vid = f"vuln:{r['cve_id']}"
                    is_kev = bool(r.get("cisa_exploit_add"))
                    _add_node(
                        vid,
                        r["cve_id"],
                        "vulnerability",
                        {
                            "cvss_score": r.get("cvss_score", 0),
                            "severity": r.get("severity", "UNKNOWN"),
                            "attack_vector": r.get("attack_vector", ""),
                            "is_kev": is_kev,
                            "cisa_action_due": r.get("cisa_action_due", ""),
                            "cisa_notes": r.get("cisa_notes", ""),
                            "cisa_cwes": r.get("cisa_cwes", []),
                            "version_constraints": r.get("version_constraints"),
                            "description": (r.get("description") or "")[:200],
                            "sector": r.get("zones", ["global"])[0] if r.get("zones") else "global",
                        },
                    )
                    vuln_ids.append(r["cve_id"])
                    for z in r.get("zones", []):
                        sid = f"sector:{z}"
                        _add_node(sid, z.title(), "sector", {"sector": z})
                        _add_edge(vid, sid, "IN_ZONE")

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges)},
        }

    except Exception:
        logger.error("Graph explore failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


@app.get("/stix/export/{object_type}/{identifier}", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def stix_export(
    request: Request,
    object_type: str,
    identifier: str,
):
    """Export a STIX 2.1 bundle centred on a threat-intel object.

    Supported ``object_type`` values:

    - ``indicator`` — ``identifier`` is the indicator value (IP, domain,
      hash, URL, …). Returns the indicator + its 1-hop neighbourhood.
    - ``actor`` — ``identifier`` is a ThreatActor name or alias. Returns
      actor + attributed malware + employed techniques + campaigns.
    - ``technique`` — ``identifier`` is a MITRE ATT&CK ID (e.g. ``T1055``).
      Returns the technique + everything that uses it.
    - ``cve`` — ``identifier`` is a CVE ID (e.g. ``CVE-2021-44228``).
      Returns the CVE + indicators that exploit it + affected sectors.

    Response Content-Type: ``application/stix+json;version=2.1``.

    Prototype — see ``docs/STIX21_EXPORTER_PROPOSAL.md`` for auth,
    pagination, and rate-limit notes (no custom rate-limit middleware is
    added yet; the endpoint is subject to the default read rate limit).
    """
    from fastapi.responses import JSONResponse as _JSON

    from stix_exporter import StixExporter

    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    exporter = StixExporter(neo4j_client)
    try:
        ot = object_type.lower()
        if ot == "indicator":
            bundle = exporter.export_indicator(identifier)
        elif ot == "actor":
            bundle = exporter.export_threat_actor(identifier)
        elif ot == "technique":
            bundle = exporter.export_technique(identifier)
        elif ot == "cve":
            bundle = exporter.export_cve(identifier)
        else:
            # Static error string (no f-string interpolation of the URL
            # path parameter). Every other HTTPException in this file uses
            # a fixed generic message; bugbot caught this as the only
            # f-string `detail` and flagged it for consistency with the
            # project convention.
            raise HTTPException(
                status_code=400,
                detail="Unsupported object_type. Use one of: indicator, actor, technique, cve.",
            )
    except HTTPException:
        raise
    except Exception:
        logger.error("STIX export failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")

    return _JSON(
        content=bundle,
        media_type=StixExporter.MEDIA_TYPE,
    )


@app.post("/admin/query", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_ADMIN)
async def admin_query(
    request: Request,
    query: GraphQueryRequest,
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
):
    """
    Execute a raw Cypher query (admin use only).

    WARNING: This endpoint allows arbitrary Cypher execution.
    Use with caution and proper authentication.
    """
    if not ADMIN_QUERY_ENABLED:
        raise HTTPException(status_code=403, detail="Admin query endpoint is disabled")

    # Require a non-empty token when the endpoint is enabled.
    # Refusing to serve if no token is configured prevents open access caused
    # by a missing env var from being silently mistaken for a secure state.
    if not ADMIN_QUERY_TOKEN:
        raise HTTPException(
            status_code=503,
            detail="Admin query endpoint is enabled but EDGEGUARD_ADMIN_TOKEN is not set. "
            "Configure the token before using this endpoint.",
        )
    if not x_admin_token or x_admin_token != ADMIN_QUERY_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")

    if not neo4j_client or not neo4j_client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")

    # Block any write/destructive Cypher operations — this endpoint is read-only.
    _WRITE_PATTERN = re.compile(
        r"\b(CREATE|MERGE|DELETE|DETACH\s+DELETE|SET|REMOVE|DROP|CALL\s+apoc\.)\b",
        re.IGNORECASE,
    )
    if _WRITE_PATTERN.search(query.cypher):
        raise HTTPException(
            status_code=400,
            detail="Write operations (CREATE/MERGE/DELETE/SET/REMOVE/DROP/CALL apoc.*) are not permitted.",
        )

    # Validate parameter values — prevent deeply nested dicts that exhaust the parser.
    if len(query.parameters) > 20:
        raise HTTPException(status_code=400, detail="Too many query parameters (max 20)")

    try:
        # Use a read-only session so Neo4j itself rejects any write attempt that
        # slips through the keyword check.
        with neo4j_client.driver.session(default_access_mode="READ") as session:
            result = session.run(query.cypher, **query.parameters, timeout=_NEO4J_QUERY_TIMEOUT)
            records = [dict(r) for r in result]
            return {"results": records, "count": len(records)}

    except Exception as e:
        logger.error(f"Admin query failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error — see server logs")


# ============================================================================
# Helper Functions
# ============================================================================


def _parse_natural_language(query: str, zone: Optional[str] = None) -> str:
    """
    Parse natural language query to Cypher.

    This is a simple keyword-based parser. In production, this would use
    an LLM or more sophisticated NLP to generate Cypher queries.
    """
    query_lower = query.lower()

    # CVE/Vulnerability queries
    if any(kw in query_lower for kw in ["cve", "vulnerability", "cvss"]):
        base_query = "MATCH (n) WHERE (n:Vulnerability OR n:CVE) AND n.edgeguard_managed = true"

        if "high" in query_lower or "critical" in query_lower:
            base_query += " AND (n.severity IN ['HIGH', 'CRITICAL'] OR n.cvss_score >= 7.0)"
        elif "medium" in query_lower:
            base_query += " AND n.severity = 'MEDIUM'"
        elif "low" in query_lower:
            base_query += " AND n.severity = 'LOW'"

        if zone:
            base_query += " AND $zone IN n.zone"

        return base_query + " RETURN n LIMIT $limit"

    # Actor queries
    if any(kw in query_lower for kw in ["actor", "apt", "threat group", "actor"]):
        base_query = "MATCH (n:ThreatActor) WHERE n.edgeguard_managed = true"
        if zone:
            base_query += " AND $zone IN n.zone"
        return base_query + " RETURN n LIMIT $limit"

    # Indicator queries
    if any(kw in query_lower for kw in ["indicator", "ip", "domain", "hash", "malicious"]):
        base_query = "MATCH (n:Indicator)"

        if "ip" in query_lower:
            base_query += " WHERE n.indicator_type = 'ipv4' AND n.edgeguard_managed = true"
        elif "domain" in query_lower:
            base_query += " WHERE n.indicator_type = 'domain' AND n.edgeguard_managed = true"
        elif "hash" in query_lower:
            base_query += " WHERE n.indicator_type = 'hash' AND n.edgeguard_managed = true"
        else:
            base_query += " WHERE n.edgeguard_managed = true"

        if zone:
            base_query += " AND $zone IN n.zone"

        return base_query + " RETURN n LIMIT $limit"

    # Default: search across labeled threat-intel nodes (avoid full-graph scan)
    base_query = (
        "MATCH (n) WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR "
        "n:ThreatActor OR n:Technique OR n:Campaign) AND n.edgeguard_managed = true"
    )
    if zone:
        base_query += " AND $zone IN n.zone"
    return base_query + " RETURN n LIMIT $limit"


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    # Get configuration from environment
    host = os.getenv("EDGEGUARD_API_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("EDGEGUARD_API_PORT", "8000"))
    except (ValueError, TypeError):
        port = 8000
    reload = os.getenv("EDGEGUARD_API_RELOAD", "false").lower() == "true"

    logger.info(f"[START] Starting EdgeGuard Query API on {host}:{port}")

    uvicorn.run("query_api:app", host=host, port=port, reload=reload, log_level="info")
