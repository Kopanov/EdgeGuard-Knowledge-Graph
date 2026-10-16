"""
FastAPI Query Engine for GraphRAG
REST endpoints for threat intelligence queries
"""

import asyncio
import hmac
import logging
import os
import re
import sys
import threading
from contextlib import asynccontextmanager
from typing import Any, Dict, List, NoReturn, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from neo4j import exceptions as _neo4j_exceptions
from neo4j import time as _neo4j_time

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ioc_normalize import (
    canonicalize_lookup,
    indicator_type_filter,
    normalize_cve_id,
    normalize_mitre_technique_id,
)
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
    reconnect_task = None
    if not neo4j_client.connect():
        # Keep trying in the background (off the event loop, every _RECONNECT_INTERVAL_SEC): the
        # data routes answer 503 at once while disconnected and recover without a restart.
        logger.error("[ERR] Failed to connect to Neo4j on startup — retrying in the background")
        reconnect_task = asyncio.create_task(_reconnect_until_connected(neo4j_client))
    else:
        logger.info("[OK] Connected to Neo4j")

    yield

    if reconnect_task is not None:
        # Cancel and wait for the task to acknowledge; the awaited future resolves at once, the
        # daemon worker thread (if a connect attempt is in flight) ends with the process.
        reconnect_task.cancel()
        await asyncio.gather(reconnect_task, return_exceptions=True)

    # Shutdown. While a connect attempt is still in flight the driver may be assigned or closed
    # by the worker thread; nothing is closed here in that case (the process is exiting).
    if neo4j_client and not _reconnect_in_progress:
        logger.info("🔌 Closing Neo4j connection...")
        neo4j_client.close()


ADMIN_QUERY_ENABLED = os.getenv("EDGEGUARD_ENABLE_ADMIN_QUERY", "false").lower() == "true"
ADMIN_QUERY_TOKEN = os.getenv("EDGEGUARD_ADMIN_TOKEN")

# ── Rate limiting ─────────────────────────────────────────────────────────────
# Default: 60 read requests / minute per IP.  Admin endpoint is more restricted.


def _env_rate_limit(name: str, default: str) -> str:
    """slowapi limit string from the environment; unset, empty or blank falls back to *default*
    (2026-10: an empty forwarded variable used to reach ``Limiter.limit("")`` and break every request)."""
    raw = (os.getenv(name) or "").strip()
    return raw or default


_RATE_LIMIT_READ = _env_rate_limit("EDGEGUARD_RATE_LIMIT_READ", "60/minute")
_RATE_LIMIT_ADMIN = _env_rate_limit("EDGEGUARD_RATE_LIMIT_ADMIN", "10/minute")
limiter = Limiter(key_func=get_remote_address)

# API key for the public read endpoints.  Set EDGEGUARD_API_KEY to a non-empty
# value to require authentication.  Leave unset only in local dev.
_API_KEY = os.getenv("EDGEGUARD_API_KEY")

# PR-N24 audit HIGH (proactive 2026-04-22): pre-N24 this module used
# ``_ENV = os.getenv("EDGEGUARD_ENV", "dev").lower()`` then ``if _ENV
# == "prod"`` — the fails-open pattern PR-N23 BLOCKER #5 fixed for
# graphql_api but missed for query_api. Asymmetry: typo
# ``EDGEGUARD_ENV=production`` would treat graphql_api as prod
# (introspection blocked) but query_api as non-prod (API-key
# enforcement skipped at startup). Maintainer Dev + Integration audit
# agents both flagged this; lifting the canonical check to
# ``src/config.py:is_production_env`` so both APIs share the same
# fail-closed allowlist semantics.
from config import is_production_env  # noqa: E402

_IS_PROD = is_production_env()

if _IS_PROD and not _API_KEY:
    raise RuntimeError(
        "EDGEGUARD_API_KEY must be set when EDGEGUARD_ENV is prod (or unset/typo'd "
        "since PR-N24 secure defaults treat unrecognized values as prod). "
        "Set a strong random value before starting the API in production."
    )

# PR (security A6) — Red Team Tier A: in non-prod environments, refuse
# to start an unauthenticated API endpoint that's reachable from the
# network. Operator must EITHER set EDGEGUARD_API_KEY (auth enforced)
# OR bind to loopback only (127.0.0.1). Genuine "public unauth dev"
# is opt-in via EDGEGUARD_ALLOW_UNAUTH=1.
_BIND_HOST = os.getenv("EDGEGUARD_API_HOST", "127.0.0.1").strip()
_ALLOW_UNAUTH = os.getenv("EDGEGUARD_ALLOW_UNAUTH", "").strip().lower() in ("1", "true", "yes", "on")

if not _API_KEY and _BIND_HOST not in ("127.0.0.1", "localhost", "::1") and not _ALLOW_UNAUTH:
    raise RuntimeError(
        f"EDGEGUARD_API_KEY is unset AND the bind host ({_BIND_HOST!r}) is not loopback. "
        "Refusing to start an unauthenticated REST API reachable from the network. "
        "Either set EDGEGUARD_API_KEY (recommended), bind to 127.0.0.1, "
        "or opt in explicitly with EDGEGUARD_ALLOW_UNAUTH=1 (not recommended)."
    )

if not _API_KEY:
    logger.warning(
        "EDGEGUARD_API_KEY is not configured — all API endpoints are UNAUTHENTICATED. "
        "Set EDGEGUARD_API_KEY to enable authentication."
    )


def _verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    """Dependency: require a valid API key when EDGEGUARD_API_KEY is configured.

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
    if not _API_KEY:
        return
    if x_api_key is None or not hmac.compare_digest(str(_API_KEY), str(x_api_key)):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


_PKG_VERSION = package_version()

# Initialize FastAPI app
app = FastAPI(
    title="EdgeGuard Query API",
    description="REST API for querying threat intelligence data from Neo4j GraphRAG",
    version=_PKG_VERSION,
    lifespan=lifespan,
    # 2026-10 readiness check: Swagger / ReDoc / the OpenAPI document were served without the
    # API key. In prod they are disabled; the OpenAPI document stays available to key holders
    # on /openapi.json (route below) for partner discovery.
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if _IS_PROD:

    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(_verify_api_key)])
    @limiter.limit(_RATE_LIMIT_READ)
    async def openapi_document(request: Request) -> Dict[str, Any]:
        """OpenAPI document for key holders (prod): discovery without exposing it anonymously; rate-limited."""
        return app.openapi()


_NEO4J_TEMPORAL_TYPES = (_neo4j_time.DateTime, _neo4j_time.Date, _neo4j_time.Time, _neo4j_time.Duration)


def _jsonable(value: Any) -> Any:
    """Make one Neo4j property value JSON-friendly: temporal types become ISO-8601 strings."""
    if isinstance(value, _NEO4J_TEMPORAL_TYPES):
        return value.iso_format()
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


_NEO4J_UNAVAILABLE = (_neo4j_exceptions.ServiceUnavailable, _neo4j_exceptions.SessionExpired)


def _raise_api_error(exc: BaseException, what: str) -> NoReturn:
    """Turn a handler exception into the right HTTP status: 503 while the graph database is
    unavailable (2026-10 readiness check: an outage used to surface as 500), 500 otherwise.
    Details stay in the server log; HTTPExceptions raised inside the handler pass through."""
    if isinstance(exc, HTTPException):
        raise exc
    if isinstance(exc, _NEO4J_UNAVAILABLE):
        logger.error("%s: graph database unavailable", what, exc_info=True)
        raise HTTPException(status_code=503, detail="Graph database unavailable — retry later") from exc
    logger.error("%s", what, exc_info=True)
    raise HTTPException(status_code=500, detail="Internal error — see server logs") from exc


def _node_props(node: Any) -> Dict[str, Any]:
    """Properties of a Neo4j node (or ``None``) as a plain dict with ISO-8601 timestamps.

    2026-10: FastAPI's encoder falls back to ``vars()`` for ``neo4j.time`` objects, so every
    ``last_updated`` / ``first_imported_at`` left the REST API as a ``{"_DateTime__date": …}``
    object. Every endpoint that returns raw node properties goes through this helper.
    """
    return {k: _jsonable(v) for k, v in dict(node or {}).items()}


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

# PR #34 round 24 (bugbot MED, same-pattern fix): derive the ZoneEnum
# members from ``config.VALID_ZONES`` so the FastAPI query-param validator
# stays in lockstep with the canonical zone set. Previously the 4 members
# were hardcoded — if a 5th zone were added to ``VALID_ZONES`` and someone
# forgot to update this enum, the filter/membership check in the Cypher
# layer would ACCEPT the new zone, but FastAPI would REJECT the inbound
# query string before it ever reached the resolver (asymmetric behavior).
# Now: one change in config.py propagates everywhere.
#
# Python's ``global`` is a reserved keyword, so the historical enum member
# name is ``global_`` (trailing underscore) while its value stays ``"global"``.
# Preserve that contract so consumers referencing ``ZoneEnum.global_`` keep
# working.


def _zone_member_name(zone: str) -> str:
    """Translate a zone string into a valid Python Enum member name.

    Python reserved words can't be used as attribute names; we append a
    trailing underscore by convention. Any other zone name is used as-is.
    """
    return f"{zone}_" if zone in {"global", "class", "import", "return"} else zone


def _build_zone_enum() -> type:
    from config import VALID_ZONES

    members = {_zone_member_name(z): z for z in sorted(VALID_ZONES)}
    return Enum("ZoneEnum", members, type=str)


ZoneEnum = _build_zone_enum()


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
    # TLS certificate fingerprints (SSL Blacklist, 2026-10)
    x509_fingerprint_sha1 = "x509-fingerprint-sha1"


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


class RelatedRelationship(BaseModel):
    """How one related node is connected to the indicator found by ``/search/indicator`` (2026-10)."""

    relationship_type: str = Field(description="Graph relationship type, e.g. INDICATES, EXPLOITS, USES_TECHNIQUE.")
    direction: str = Field(
        description="'outgoing' (indicator → related node) or 'incoming' (related node → indicator)."
    )
    labels: List[str] = Field(default=[], description="The related node's labels, sorted.")


class IndicatorResponse(BaseModel):
    """Indicator search response."""

    value: str
    found: bool
    indicator: Optional[Dict[str, Any]] = None
    related: List[Dict[str, Any]] = Field(
        default=[],
        description=(
            "Properties of the related nodes: Malware, ThreatActor and CVE / Vulnerability first, then "
            "Technique, Campaign, Sector and any other label, at most 10 per kind, in a stable order."
        ),
    )
    # 2026-10: optional, so a client that reads only ``related`` is unaffected.
    relationships: List[RelatedRelationship] = Field(
        default=[],
        description="Same order and length as `related`: element i states how `related[i]` is connected.",
    )
    zone: Optional[str] = None
    normalized_value: Optional[str] = Field(
        default=None,
        description="Canonical form of `value` bound into the graph MATCH (refanged + NFC + case-folded).",
    )


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


class ActorTechniqueSummary(BaseModel):
    """One employed technique in an actor summary."""

    mitre_id: Optional[str] = None
    name: Optional[str] = None


class ActorSummaryResponse(BaseModel):
    """Threat-actor profile + top-N related entities with total counts."""

    name: str
    aliases: List[str] = []
    description: Optional[str] = None
    description_source: Optional[str] = Field(
        default=None,
        description=(
            "The source whose text `description` is (its canonical id, e.g. 'mitre_attck'; 2026-10-16); "
            "null when the actor has no description or it was written before 2026-10-16."
        ),
    )
    sophistication: Optional[str] = None
    motivation: Optional[str] = None
    confidence_score: Optional[float] = None
    zone: List[str] = []
    source: List[str] = []
    resolved_by: str = Field(description="How the actor was matched: 'name' (canonical) or 'alias'.")
    malware: List[str] = Field(default=[], description="Attributed malware names (up to 10).")
    malware_total: int = 0
    techniques: List[ActorTechniqueSummary] = Field(default=[], description="Employed techniques (up to 15).")
    technique_total: int = 0
    campaigns: List[str] = Field(default=[], description="Campaign names run by the actor (up to 5).")
    campaign_total: int = 0


# ============================================================================
# API Endpoints
# ============================================================================


# Background reconnect (2026-10): when the client failed to connect at startup, every request used
# to fail with 503 until the process was restarted. ``connect()`` retries with backoff and a 60 s
# connection timeout, so it must never run on the event loop; the lifespan runs it in a worker
# thread every ``_RECONNECT_INTERVAL_SEC`` until it succeeds, and the request guard only reads the
# connection state.
_RECONNECT_INTERVAL_SEC = 30.0
# True while a background ``connect()`` attempt is in flight. ``connect()`` assigns the driver
# before its verification query and closes it again on failure, so requests must not use the
# client during that window; the guard and ``/health`` answer 503 instead.
_reconnect_in_progress = False


def _run_in_daemon_thread(fn):
    """Run ``fn`` in a daemon thread and return a future that resolves on the event loop.

    A daemon thread (not the default executor) so that a connect attempt still waiting on the
    driver's connection timeout cannot delay process exit; a cancelled future simply drops the
    result when the thread finishes.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()

    def _deliver(setter, value) -> None:
        if not future.done():
            setter(value)

    def _target() -> None:
        try:
            result = fn()
        except BaseException as exc:  # delivered to the awaiting task as an exception
            payload, setter = exc, future.set_exception
        else:
            payload, setter = result, future.set_result
        try:
            loop.call_soon_threadsafe(_deliver, setter, payload)
        except RuntimeError:  # event loop already closed (process exiting)
            pass

    threading.Thread(target=_target, name="neo4j-reconnect", daemon=True).start()
    return future


async def _reconnect_until_connected(client, interval: float = _RECONNECT_INTERVAL_SEC) -> None:
    """Retry ``client.connect()`` off the event loop until it succeeds (cancelled on shutdown)."""
    global _reconnect_in_progress
    while True:
        _reconnect_in_progress = True
        try:
            ok = await _run_in_daemon_thread(client.connect)
        except asyncio.CancelledError:
            raise  # the flag stays True: the worker may still touch the driver
        except Exception as exc:  # the driver already logged; keep retrying
            ok = False
            logger.warning("Neo4j reconnect attempt failed: %s", exc)
        _reconnect_in_progress = False
        if ok:
            logger.info("[OK] Connected to Neo4j (startup connection had failed)")
            return
        await asyncio.sleep(interval)


def _require_neo4j() -> None:
    """Raise 503 unless the Neo4j client is connected and no connect attempt is in flight.
    Never blocks: reconnection is the lifespan's background task."""
    client = neo4j_client
    if client is None or _reconnect_in_progress or not client.is_connected():
        raise HTTPException(status_code=503, detail="Neo4j not connected")


@app.get("/health", response_model=HealthResponse)
async def health():
    """
    Health check endpoint.

    Returns API status and Neo4j connectivity.
    """
    global neo4j_client

    if neo4j_client is None or _reconnect_in_progress:
        # No client, or a background connect attempt is assigning/closing the driver right now.
        neo4j_ok = False
    else:
        # Full ping + APOC check — Neo4jClient.is_connected() is driver-only (fast path for other routes).
        neo4j_ok = bool(neo4j_client.health_check().get("healthy"))

    payload = HealthResponse(
        status="ok" if neo4j_ok else "degraded",
        neo4j_connected=neo4j_ok,
        version=_PKG_VERSION,
    )
    if not neo4j_ok:
        # 503 while degraded: the compose healthcheck and partner probes see the outage
        # (a 200 "degraded" could never fail a healthcheck).
        body = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()
        return JSONResponse(status_code=503, content=body)
    return payload


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

        _require_neo4j()

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
                    records = [_node_props(record["n"]) for record in result]
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
                # PR-N24 H1: use _IS_PROD (fail-closed allowlist from
                # config.is_production_env()) instead of the pre-N24
                # ``_ENV != "prod"`` strict-equality check, which would
                # leak Cypher when EDGEGUARD_ENV='production' (typo) or
                # any other non-allowlisted value.
                cypher=cypher_query if (q.return_cypher and not _IS_PROD) else None,
            )

        except Exception as e:
            span.set_attribute("error", True)
            span.set_attribute("error.message", str(e))
            _raise_api_error(e, "Query failed")


# 2026-10: the related nodes of ``/search/indicator``. The undirected ``LIMIT 10`` without an
# ``ORDER BY`` returned an arbitrary ten neighbours (Technique and Campaign nodes could crowd out the
# malware the indicator ``INDICATES``) and no relationship type. Each (relationship type, direction,
# node) appears once; the nodes are grouped by kind in a fixed priority — what the indicator points
# at (Malware, ThreatActor, CVE / Vulnerability) before its context (Technique, Campaign, Sector)
# and any other label (the alphabetically first label names the kind) — and ordered inside a kind
# by relationship type, direction and natural key, at most ``$per_kind`` per kind. The final
# ``ORDER BY`` carries each row's position in its kind, so the order does not depend on how the
# runtime streams the unwound lists. The lookup is bound to the node the route returns
# (``$element_id``): one value may be stored under several types, and matching on the value alone
# mixed in the neighbours of the other types' nodes, with a direction relative to a node the
# response does not contain.
_SEARCH_RELATED_PER_KIND = 10
_SEARCH_RELATED_CYPHER = """
    MATCH (n:Indicator)-[r]-(related)
    WHERE elementId(n) = $element_id
      AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)
      AND ($zone IS NULL OR $zone IN coalesce(n.zone, []))
      AND (related.edgeguard_managed = true OR related.edgeguard_enriched = true)
    WITH DISTINCT related, type(r) AS relationship_type,
         CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END AS direction
    WITH related, relationship_type, direction,
         CASE
           WHEN related:Malware THEN 'Malware'
           WHEN related:ThreatActor THEN 'ThreatActor'
           WHEN related:CVE OR related:Vulnerability THEN 'CVE'
           WHEN related:Technique THEN 'Technique'
           WHEN related:Campaign THEN 'Campaign'
           WHEN related:Sector THEN 'Sector'
           ELSE reduce(k = '', l IN labels(related) | CASE WHEN k = '' OR l < k THEN l ELSE k END)
         END AS kind
    WITH related, relationship_type, direction, kind,
         CASE kind
           WHEN 'Malware' THEN 0 WHEN 'ThreatActor' THEN 1 WHEN 'CVE' THEN 2
           WHEN 'Technique' THEN 3 WHEN 'Campaign' THEN 4 WHEN 'Sector' THEN 5 ELSE 6
         END AS priority
    ORDER BY priority, kind, relationship_type, direction,
             coalesce(related.cve_id, related.mitre_id, related.name, related.value, related.source_id),
             related.uuid
    WITH priority, kind,
         collect({node: related, relationship_type: relationship_type, direction: direction})[..$per_kind] AS rows
    UNWIND range(0, size(rows) - 1) AS position
    WITH priority, kind, position, rows[position] AS row
    RETURN row.node AS related, row.relationship_type AS relationship_type, row.direction AS direction,
           labels(row.node) AS labels
    ORDER BY priority, kind, position
"""


@app.post("/search/indicator", response_model=IndicatorResponse, dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def search_indicator(request: Request, s: IndicatorSearch):
    """
    Search for a specific indicator.

    Returns the indicator and related threats/entities: ``related`` holds the related nodes'
    properties and ``relationships`` (2026-10) the relationship type and direction of each, in
    the same order — Malware, ThreatActor and CVE / Vulnerability before Technique, Campaign,
    Sector and other labels, at most ``_SEARCH_RELATED_PER_KIND`` per kind. When the value is
    stored under several types, the indicator of the resolved type answers (``indicator_type``
    mapped to the graph type, or the type inferred from the value), otherwise the lowest type;
    ``related`` and ``relationships`` are that indicator's.
    """
    _require_neo4j()

    try:
        # READ-side canonicalization (src/ioc_normalize.py): infer the type
        # when the caller omits it, then refang + NFC + case-fold so analyst
        # paste variants ("EvIl[.]CoM", "EVIL.COM" with no type) hit the
        # write-side MERGE keys — the SAME shared path the alert enrichment
        # uses, so a value that enriches on ingest also resolves on search.
        # Raw value stays echoed in the response.
        resolved_type, normalized_value = canonicalize_lookup(
            s.indicator_type.value if s.indicator_type else None,
            s.value,
        )
        # An empty/whitespace/zero-width-only input normalizes to "" — there
        # is no graph key to look up, and MATCH {value: ""} could false-match
        # a legacy empty-key node. Treat as not-found without querying.
        if not normalized_value:
            return IndicatorResponse(
                value=s.value,
                found=False,
                zone=s.zone.value if s.zone else None,
                normalized_value=normalized_value,
            )
        with neo4j_client.driver.session() as session:
            # Find the indicator
            # 2026-10 readiness check: ``zone`` was accepted and echoed but never applied.
            # One value may be stored under several types ((indicator_type, value) is the key).
            # 2026-10: the node of the resolved type answers (the type the caller gave, mapped to
            # the graph type — md5 → hash — or the one inferred from the value), otherwise the
            # lowest type, so repeated searches return the same node; the caller's type was
            # ignored before.
            zone_value = s.zone.value if s.zone else None
            query = """
                MATCH (n:Indicator {value: $value})
                WHERE (n.edgeguard_managed = true OR n.edgeguard_enriched = true)
                  AND ($zone IS NULL OR $zone IN coalesce(n.zone, []))
                RETURN n, elementId(n) AS element_id
                ORDER BY CASE WHEN n.indicator_type = $preferred_type THEN 0 ELSE 1 END, n.indicator_type
                LIMIT 1
            """
            result = session.run(
                query,
                value=normalized_value,
                zone=zone_value,
                preferred_type=resolved_type,
                timeout=_NEO4J_QUERY_TIMEOUT,
            )
            record = result.single()

            if not record:
                return IndicatorResponse(
                    value=s.value,
                    found=False,
                    zone=s.zone.value if s.zone else None,
                    normalized_value=normalized_value,
                )

            indicator = _node_props(record["n"])

            # Find related entities (2026-10: of the node found, directed, typed and in a stable
            # order; see ``_SEARCH_RELATED_CYPHER``).
            related_rows = list(
                session.run(
                    _SEARCH_RELATED_CYPHER,
                    element_id=record["element_id"],
                    zone=zone_value,
                    per_kind=_SEARCH_RELATED_PER_KIND,
                    timeout=_NEO4J_QUERY_TIMEOUT,
                )
            )
            related = [_node_props(r["related"]) for r in related_rows]
            relationships = [
                RelatedRelationship(
                    relationship_type=r["relationship_type"],
                    direction=r["direction"],
                    labels=sorted(str(label) for label in (r["labels"] or [])),
                )
                for r in related_rows
            ]

            return IndicatorResponse(
                value=s.value,
                found=True,
                indicator=indicator,
                related=related,
                relationships=relationships,
                zone=s.zone.value if s.zone else None,
                normalized_value=normalized_value,
            )

    except Exception as exc:
        _raise_api_error(exc, "Indicator search failed")


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
    _require_neo4j()

    try:
        with neo4j_client.driver.session() as session:
            # Build query with optional severity filter
            where_clause = "$zone IN n.zone AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
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
            threats = [_node_props(r["n"]) for r in result]

            # Get summary stats
            summary_query = """
                MATCH (n)
                WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR n:ThreatActor OR n:Technique OR n:Campaign)
                  AND $zone IN n.zone AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)
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

    except Exception as exc:
        _raise_api_error(exc, "Zone threats query failed")


def _indicator_filter_conditions(
    indicator_type: Optional[str],
    zone: Optional[str],
    source: Optional[str],
) -> "tuple[list[str], dict[str, Any]]":
    """Shared Indicator WHERE conditions for ``/indicators`` AND the Wazuh
    CDB export — single source so a filter fix in one cannot silently miss
    the other (always includes the ``edgeguard_managed`` scope)."""
    conditions: list[str] = []
    params: Dict[str, Any] = {}
    if indicator_type:
        # 2026-10: the graph stores every file digest as ``hash``; md5 / sha1 / sha256 / sha512
        # select the ``hash`` nodes whose value has that digest's hexadecimal length
        # (``ioc_normalize.indicator_type_filter``). An exact comparison never matched.
        graph_type, value_pattern = indicator_type_filter(indicator_type)
        conditions.append("n.indicator_type = $indicator_type")
        params["indicator_type"] = graph_type
        if value_pattern is not None:
            conditions.append("n.value =~ $indicator_value_pattern")
            params["indicator_value_pattern"] = value_pattern
    if zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = zone
    if source:
        conditions.append("$source IN n.source")
        params["source"] = source
    conditions.append("(n.edgeguard_managed = true OR n.edgeguard_enriched = true)")
    return conditions, params


def _vulnerability_filter_conditions(
    severity: Optional[str],
    zone: Optional[str],
) -> "tuple[list[str], dict[str, Any]]":
    """Shared CVE/Vulnerability WHERE conditions for ``/vulnerabilities``
    AND the Wazuh CDB export (same single-source rationale as above)."""
    conditions = [
        "(n:Vulnerability OR n:CVE OR n.type = 'vulnerability')",
        "(n.edgeguard_managed = true OR n.edgeguard_enriched = true)",
    ]
    params: Dict[str, Any] = {}
    if severity:
        conditions.append("n.severity = $severity")
        params["severity"] = severity.upper()
    if zone:
        conditions.append("$zone IN n.zone")
        params["zone"] = zone
    return conditions, params


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
    _require_neo4j()

    try:
        with neo4j_client.driver.session() as session:
            conditions, filter_params = _indicator_filter_conditions(
                indicator_type.value if indicator_type else None,
                zone.value if zone else None,
                source,
            )
            params = {**filter_params, "limit": limit, "offset": offset}
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
            indicators = [_node_props(r["n"]) for r in result]

            # Get total count
            count_query = f"""
                MATCH (n:Indicator)
                WHERE {where_clause}
                RETURN count(n) as total
            """
            count_result = session.run(count_query, **filter_params, timeout=_NEO4J_QUERY_TIMEOUT)
            total = count_result.single()["total"]

            return {"indicators": indicators, "total": total, "limit": limit, "offset": offset}

    except Exception as exc:
        _raise_api_error(exc, "List indicators failed")


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
    _require_neo4j()

    try:
        with neo4j_client.driver.session() as session:
            conditions, filter_params = _vulnerability_filter_conditions(
                severity.value if severity else None,
                zone.value if zone else None,
            )
            params = {**filter_params, "limit": limit}
            where_clause = " AND ".join(conditions)

            query = f"""
                MATCH (n)
                WHERE {where_clause}
                RETURN n
                ORDER BY coalesce(n.cvss_score, -1) DESC
                LIMIT $limit
            """

            result = session.run(query, **params, timeout=_NEO4J_QUERY_TIMEOUT)
            vulnerabilities = [_node_props(r["n"]) for r in result]

            return {"vulnerabilities": vulnerabilities, "total": len(vulnerabilities)}

    except Exception as exc:
        _raise_api_error(exc, "List vulnerabilities failed")


class CdbListEnum(str, Enum):
    indicators = "indicators"
    cves = "cves"


# Wazuh CDB export: hard cap on exported entries. One bounded query — CDB
# lists of this size load fine in wazuh-analysisd; raise deliberately (with
# a Wazuh-side memory check) if a deployment ever needs more.
# 2026-10: the cap keeps the most recently updated entries (it kept the
# alphabetically first ones), and a cut list is reported in the
# ``X-EdgeGuard-Truncated`` response header and the log.
_CDB_EXPORT_MAX_ENTRIES = 50_000

# CDB keys: the file format splits each line on the FIRST ':' — a key
# containing ':' silently truncates, so such values are SKIPPED (count
# surfaced in the X-EdgeGuard-Skipped response header). In practice this
# excludes ``url`` (scheme colon) and ``ipv6`` (address colons) indicator
# types — match those in Wazuh via rules on the enriched alert path
# instead of CDB lookups. Embedded newlines would likewise corrupt the
# line-oriented format.
_CDB_KEY_FORBIDDEN_CHARS = (":", "\n", "\r")

# 2026-10: newest first by the last sync that reported the entry (``n.last_updated``; Cypher sorts
# null first in a descending order, hence the explicit null rank), ties by key; one row beyond the
# cap so the route can tell a cut list from a complete one.
_CDB_ORDER_AND_LIMIT = "ORDER BY (n.last_updated IS NULL), n.last_updated DESC, key LIMIT $cap + 1"


def _cdb_value_sanitize(text: str) -> str:
    """Sanitize a CDB VALUE fragment: the value side may not contain line
    breaks (line-oriented format); ':' is technically legal after the first
    separator but trips naive parsers — normalize both to '_'."""
    out = str(text)
    for ch in (":", "\n", "\r"):
        out = out.replace(ch, "_")
    return out


@app.get("/export/wazuh/cdb", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def export_wazuh_cdb(
    request: Request,
    list_name: CdbListEnum = Query(
        CdbListEnum.indicators, alias="list", description="Which intelligence list to export"
    ),
    zone: Optional[ZoneEnum] = Query(None, description="Sector/zone filter (omit for all zones)"),
    indicator_type: Optional[IndicatorTypeEnum] = Query(
        None, description="Indicator-type filter (indicators list only)"
    ),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence_score"),
):
    """Export sector-specific IOC/CVE intelligence as a Wazuh CDB list.

    The agreed first Wazuh integration (2026-06, Stage-2): EdgeGuard exports
    CTI that Wazuh rules consume via ``<list lookup="match_key">`` CDB
    lookups. Format: one ``key:value`` entry per line — the IOC (or CVE id)
    is the key; the value carries human-readable context (type, confidence,
    severity, KEV date).

    Semantics (documented deviations from the JSON listing endpoints):
      * Only ACTIVE entries are exported (``coalesce(n.active, true)``) —
        this is an operational blocklist feed; indicators retired by the
        confidence-decay job must drop out of Wazuh on the next pull.
      * Keys containing ':' / line breaks are skipped (see
        ``_CDB_KEY_FORBIDDEN_CHARS`` — excludes url/ipv6 types), count in
        the ``X-EdgeGuard-Skipped`` header.
      * At most ``_CDB_EXPORT_MAX_ENTRIES`` entries. Since 2026-10 the
        entries are ordered newest first by ``n.last_updated`` (the last
        sync that reported them; entries without it last), ties by key, so
        the cap keeps the most recently updated entries and the order is
        deterministic; before, the cap kept the alphabetically first keys.
        ``X-EdgeGuard-Truncated: true`` (and a log warning) says the list
        was cut; ``false`` that it is complete.

    Filter logic is shared with ``/indicators`` and ``/vulnerabilities``
    via ``_indicator_filter_conditions`` / ``_vulnerability_filter_conditions``
    — not forked.
    """
    _require_neo4j()

    try:
        zone_value = zone.value if zone else None
        if list_name is CdbListEnum.indicators:
            conditions, params = _indicator_filter_conditions(
                indicator_type.value if indicator_type else None, zone_value, None
            )
            match_clause = "MATCH (n:Indicator)"
            return_clause = (
                "RETURN n.value AS key, n.indicator_type AS type, "
                f"n.confidence_score AS confidence {_CDB_ORDER_AND_LIMIT}"
            )
        else:
            conditions, params = _vulnerability_filter_conditions(None, zone_value)
            match_clause = "MATCH (n)"
            return_clause = (
                "RETURN n.cve_id AS key, n.severity AS severity, n.cvss_score AS cvss, "
                f"n.cisa_exploit_add AS kev {_CDB_ORDER_AND_LIMIT}"
            )

        # Operational blocklist: decay-retired entries must drop out.
        conditions.append("coalesce(n.active, true) = true")
        if min_confidence is not None:
            conditions.append("n.confidence_score >= $min_confidence")
            params["min_confidence"] = min_confidence
        params["cap"] = _CDB_EXPORT_MAX_ENTRIES

        query = f"{match_clause} WHERE {' AND '.join(conditions)} {return_clause}"

        lines: list[str] = []
        skipped = 0
        with neo4j_client.driver.session() as session:
            # One row more than the cap: its presence is what tells a cut list from a complete one.
            rows = list(session.run(query, **params, timeout=_NEO4J_QUERY_TIMEOUT))
        truncated = len(rows) > _CDB_EXPORT_MAX_ENTRIES
        if truncated:
            logger.warning(
                "Wazuh CDB export truncated: list=%s zone=%s kept the %d most recently updated entries",
                list_name.value,
                zone_value or "all",
                _CDB_EXPORT_MAX_ENTRIES,
            )
        for r in rows[:_CDB_EXPORT_MAX_ENTRIES]:
            key = r["key"]
            if not isinstance(key, str) or not key.strip():
                skipped += 1
                continue
            key = key.strip()
            if any(ch in key for ch in _CDB_KEY_FORBIDDEN_CHARS):
                skipped += 1
                continue
            if list_name is CdbListEnum.indicators:
                itype = _cdb_value_sanitize(r["type"] or "unknown")
                conf = r["confidence"]
                value = f"type={itype} confidence={conf:.2f}" if isinstance(conf, (int, float)) else f"type={itype}"
            else:
                sev = _cdb_value_sanitize(r["severity"] or "unknown")
                cvss = r["cvss"]
                value = f"severity={sev} cvss={cvss}" if isinstance(cvss, (int, float)) else f"severity={sev}"
                if r["kev"]:
                    value += f" kev={_cdb_value_sanitize(r['kev'])}"
            lines.append(f"{key}:{value}")

        body = "\n".join(lines) + ("\n" if lines else "")
        filename = f"edgeguard_{zone_value or 'all'}_{list_name.value}.cdb"
        return PlainTextResponse(
            body,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-EdgeGuard-Entries": str(len(lines)),
                "X-EdgeGuard-Skipped": str(skipped),
                "X-EdgeGuard-Truncated": "true" if truncated else "false",
            },
        )

    except Exception as exc:
        _raise_api_error(exc, "Wazuh CDB export failed")


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
    # 2026-10: the description said "Max nodes"; LIMIT applies to the rows each view reads.
    limit: int = Query(
        default=100,
        ge=10,
        le=500,
        description=(
            "Max rows the view reads ((indicator, malware) or (actor, technique) pairs, indicators, CVEs); "
            "sector and tactic nodes come on top, so the node count can exceed it"
        ),
    ),
):
    """
    Return Cytoscape.js-formatted graph data for the interactive visualization.

    Views:
    - **attacks**: Indicators → the Malware they indicate (``INDICATES``), and the Indicators' sectors
    - **actors**: ThreatActors → Techniques (→ Tactics)
    - **indicators**: IOCs grouped by zone
    - **vulnerabilities**: CVEs sized by CVSS, CISA KEV highlighted

    Edges named after a graph relationship (``INDICATES``, ``EMPLOYS_TECHNIQUE``, ``IN_TACTIC``) point
    the way the relationship does; ``BELONGS_TO`` / ``IN_ZONE`` link a node to a sector node built
    from its ``zone`` property and are not graph relationships.
    """
    _require_neo4j()

    zone_param: dict = {}
    if zone:
        zone_param = {"zone": zone.value}

    nodes: list = []
    edges: list = []
    seen_ids: set = set()
    # 2026-10: one edge per (source, target, type); a node reached on several rows (an indicator
    # of two malware, a technique of two actors) added its sector / tactic edge once per row.
    seen_edges: set = set()

    def _add_node(nid: str, label: str, ntype: str, extra: dict | None = None):
        if nid not in seen_ids:
            seen_ids.add(nid)
            data = {"id": nid, "label": label, "type": ntype}
            if extra:
                data.update(extra)
            nodes.append({"data": data})

    def _add_edge(src: str, tgt: str, etype: str, extra: dict | None = None):
        if (src, tgt, etype) in seen_edges:
            return
        seen_edges.add((src, tgt, etype))
        data = {"source": src, "target": tgt, "type": etype}
        if extra:
            data.update(extra)
        edges.append({"data": data})

    try:
        with neo4j_client.driver.session(default_access_mode="READ") as session:
            if view == GraphView.attacks:
                # Indicators → the Malware they indicate, and the Indicators' sectors
                zone_ind = ""
                if zone:
                    zone_ind = "AND $zone IN coalesce(i.zone, [])"

                # 2026-10: every writer creates (Indicator)-[:INDICATES]->(Malware)
                # (build_relationships, the sync's relationship batches, neo4j_client); the view
                # matched (Malware)-[INDICATES|DROPS]->(Indicator), a direction and a DROPS type
                # nothing writes, so the default view was always empty. The edge is drawn in
                # graph direction, indicator → malware.
                cypher = f"""
                    MATCH (i:Indicator)-[:INDICATES]->(m:Malware)
                    WHERE (m.edgeguard_managed = true OR m.edgeguard_enriched = true)
                      AND (i.edgeguard_managed = true OR i.edgeguard_enriched = true)
                    {zone_ind}
                    WITH m, i
                    LIMIT $limit
                    RETURN m.name AS malware_name, m.family AS malware_family,
                           i.value AS ind_value, i.indicator_type AS ind_type,
                           coalesce(i.zone, ['global']) AS ind_zones,
                           i.confidence_score AS ind_confidence,
                           i.indicator_role AS ind_role,
                           i.threat_label AS ind_threat_label
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
                    _add_edge(iid, mid, "INDICATES")
                    for z in r.get("ind_zones", []):
                        sid = f"sector:{z}"
                        _add_node(sid, z.title(), "sector", {"sector": z})
                        _add_edge(iid, sid, "BELONGS_TO")

            elif view == GraphView.actors:
                # ThreatActors → Techniques (→ Tactics)
                zone_act = ""
                if zone:
                    zone_act = "AND $zone IN coalesce(a.zone, [])"

                # PR #33 round 12: dropped the `|USES` rollout-window
                # fallback. Pre-release fresh start has no legacy USES edges;
                # write path emits EMPLOYS_TECHNIQUE for ThreatActor →
                # Technique exclusively (see build_relationships.py 5/11).
                cypher = f"""
                    MATCH (a:ThreatActor)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
                    WHERE t.mitre_id IS NOT NULL AND (a.edgeguard_managed = true OR a.edgeguard_enriched = true)
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
                    WHERE n.value IS NOT NULL AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)
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
                    ORDER BY coalesce(n.confidence_score, -1) DESC
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
                # The sync writes CVE nodes (score, severity and KEV fields, ``merge_cve``);
                # Vulnerability nodes come only from the per-item fallback and the alert path
                # (2026-10). Both labels are read and grouped by cve_id, so a twin pair is one node.
                zone_vuln = ""
                if zone:
                    zone_vuln = "AND $zone IN coalesce(n.zone, [])"

                cypher = f"""
                    MATCH (n)
                    WHERE (n:Vulnerability OR n:CVE) AND n.cve_id IS NOT NULL AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)
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
                         // 2026-10-16: the description with the source it came from, both of one node.
                         head([d IN collect([n.description, n.description_source]) WHERE d[0] IS NOT NULL]) AS described
                    WITH cve_id, cvss_score, severity, attack_vector,
                         apoc.coll.toSet(zones_raw) AS zones,
                         cisa_exploit_add, cisa_action_due, cisa_notes,
                         cisa_cwes, version_constraints, described[0] AS description,
                         described[1] AS description_source
                    ORDER BY coalesce(cvss_score, 0) DESC
                    LIMIT $limit
                    RETURN cve_id, cvss_score, severity, attack_vector, zones,
                           cisa_exploit_add, cisa_action_due, cisa_notes,
                           cisa_cwes, version_constraints, description, description_source
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
                            "description_source": r.get("description_source"),
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

    except Exception as exc:
        _raise_api_error(exc, "Graph explore failed")


# Per-collection bound on related nodes in a STIX export. Declared here
# (rather than imported) because ``stix_exporter`` is imported lazily inside
# the route; the values MUST equal ``stix_exporter._DEFAULT_LIMIT`` and
# ``stix_exporter._MAX_LIMIT`` (pinned by tests/test_stix_exporter.py) and
# follow the ``Query(..., ge=1, le=500)`` read clamps used above.
_STIX_DEFAULT_LIMIT = 100
_STIX_MAX_LIMIT = 500


@app.get("/stix/types", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def stix_types(request: Request):
    """Discovery endpoint — list supported STIX export object types.

    ResilMesh integrators hit this first to learn which
    ``/stix/export/{object_type}/{identifier}`` values are valid
    without having to read the docstring on the export endpoint. Each
    entry includes a working example identifier so a smoke test can
    curl straight from the response.

    2026-10: each ``returns`` names every graph relationship the export
    walks at ``depth=2`` (the 2026-10 additions included), and
    ``relationship_mappings`` lists the STIX relationship each graph
    relationship becomes — derived from the exporter's own table
    (``stix_exporter.stix_relationship_mappings``).
    """
    from stix_exporter import stix_relationship_mappings

    return {
        "media_type": "application/stix+json;version=2.1",
        "default_depth": 2,
        "supported_depths": [1, 2],
        # Per-collection bound on related nodes (``?limit=``); mirrors
        # ``stix_exporter._DEFAULT_LIMIT`` / ``_MAX_LIMIT``.
        "default_limit": _STIX_DEFAULT_LIMIT,
        "max_limit": _STIX_MAX_LIMIT,
        "object_types": [
            {
                "name": "indicator",
                "identifier": "indicator value (IP, domain, hash, URL)",
                "example": "1.2.3.4",
                "returns": (
                    "indicator + 1 hop: INDICATES malware, EXPLOITS CVEs, USES_TECHNIQUE techniques, "
                    "TARGETS sectors, PART_OF_CAMPAIGN campaigns"
                ),
                "primary_relation": "indicates→malware",
            },
            {
                "name": "actor",
                "identifier": "ThreatActor name or alias (case-insensitive)",
                "example": "APT28",
                "returns": (
                    "actor + attributed malware (ATTRIBUTED_TO), EMPLOYS_TECHNIQUE techniques, the "
                    "IMPLEMENTS_TECHNIQUE techniques of the attributed malware, RUNS campaigns, "
                    "USES_MALWARE malware, USES_TOOL tools, EXPLOITS CVEs, TARGETS sectors"
                ),
                "primary_relation": "intrusion-set uses malware",
            },
            {
                "name": "technique",
                "identifier": "MITRE ATT&CK technique ID (a revoked ID exports its successor)",
                "example": "T1059",
                "returns": (
                    "technique + actors (EMPLOYS_TECHNIQUE), malware and tools (IMPLEMENTS_TECHNIQUE), "
                    "indicators (USES_TECHNIQUE), parent technique and sub-techniques (SUBTECHNIQUE_OF)"
                ),
                "primary_relation": "actors uses technique",
            },
            {
                "name": "cve",
                "identifier": "CVE identifier",
                "example": "CVE-2021-44228",
                "returns": (
                    "CVE + exploiting indicators, threat actors and malware (EXPLOITS) + affected sectors (AFFECTS)"
                ),
                "primary_relation": "indicators related-to CVE",
            },
        ],
        # Graph relationship → STIX relationship, in graph direction; pairs not listed are
        # exported as ``related-to``.
        "relationship_mappings": stix_relationship_mappings(),
    }


@app.get("/stix/export/{object_type}/{identifier:path}", dependencies=[Depends(_verify_api_key)])
@limiter.limit(_RATE_LIMIT_READ)
async def stix_export(
    request: Request,
    object_type: str,
    identifier: str,
    depth: int = Query(
        2,
        ge=1,
        le=2,
        description="1 = primary relation only (smaller bundle); 2 = full 1-hop neighborhood (default)",
    ),
    limit: int = Query(
        _STIX_DEFAULT_LIMIT,
        ge=1,
        le=_STIX_MAX_LIMIT,
        description=(
            "Maximum related nodes per collection (malware, techniques, indicators, ...); "
            "each collection is ordered by its natural key before truncation"
        ),
    ),
):
    """Export a STIX 2.1 bundle centred on a threat-intel object.

    Supported ``object_type`` values:

    - ``indicator`` — ``identifier`` is the indicator value (IP, domain,
      hash, URL, …). Returns the indicator + 1 hop: INDICATES malware,
      EXPLOITS CVEs, USES_TECHNIQUE techniques, TARGETS sectors,
      PART_OF_CAMPAIGN campaigns.
    - ``actor`` — ``identifier`` is a ThreatActor name or alias. Returns
      the actor + attributed malware (ATTRIBUTED_TO), EMPLOYS_TECHNIQUE
      techniques, the IMPLEMENTS_TECHNIQUE techniques of the attributed
      malware, RUNS campaigns, USES_MALWARE malware, USES_TOOL tools,
      EXPLOITS CVEs, TARGETS sectors.
    - ``technique`` — ``identifier`` is a MITRE ATT&CK ID (e.g. ``T1055``).
      Returns the technique + actors (EMPLOYS_TECHNIQUE), malware and tools
      (IMPLEMENTS_TECHNIQUE), indicators (USES_TECHNIQUE), parent technique
      and sub-techniques (SUBTECHNIQUE_OF).
    - ``cve`` — ``identifier`` is a CVE ID (e.g. ``CVE-2021-44228``).
      Returns the CVE + exploiting indicators, threat actors and malware
      (EXPLOITS) + affected sectors (AFFECTS).

    The same neighbourhoods are listed by ``GET /stix/types`` (``returns``),
    with the STIX relationship each graph relationship becomes
    (``relationship_mappings``; 2026-10, the bullets above described the
    neighbourhoods before the 2026-10 relationships).

    The ``identifier`` segment uses the FastAPI ``:path`` converter so it
    can capture values containing slashes (e.g. URL indicators like
    ``http://evil.com/malware``). The default converter only matches a
    single path segment and would 404 on any URL with a slash after the
    host — not viable for the documented indicator types.

    ``depth=1`` returns a minimal bundle (seed + primary relation only);
    ``depth=2`` (default) returns the full 1-hop neighborhood. Useful
    for ResilMesh smoke tests that want a smaller response.

    ``limit`` (default 100, maximum 500; values outside ``[1, 500]`` are
    rejected with 422) bounds every related-node collection in the
    bundle. Collections are ordered by their natural key before the
    bound is applied, so truncation is deterministic.

    Every bundle carries the EdgeGuard producer ``identity`` (referenced
    by ``created_by_ref``), the ``extension-definition`` that declares
    the ``x_edgeguard_*`` properties, and the TLP ``marking-definition``
    objects referenced by ``object_marking_refs``.

    Response Content-Type: ``application/stix+json;version=2.1``.

    Prototype — see ``docs/STIX21_EXPORTER_PROPOSAL.md`` for auth,
    pagination, and rate-limit notes (no custom rate-limit middleware is
    added yet; the endpoint is subject to the default read rate limit).
    """
    from fastapi.responses import JSONResponse as _JSON

    from stix_exporter import StixExporter

    _require_neo4j()

    exporter = StixExporter(neo4j_client)
    try:
        ot = object_type.lower()
        if ot == "indicator":
            # READ-side canonicalization: infer type from the value shape and
            # refang + NFC + case-fold so a defanged / mixed-case IOC path
            # ("EvIl[.]CoM", "EVIL.COM") resolves to the stored node — same
            # shared path as /search/indicator and alert enrichment.
            # canonicalize_lookup yields "" only for empty / whitespace /
            # zero-width-only input — there is no graph key to export, so
            # reject (same empty-key guard as /search/indicator) instead of
            # running a MATCH on a meaningless value.
            _t, _norm = canonicalize_lookup(None, identifier)
            if not _norm:
                raise HTTPException(
                    status_code=400,
                    detail="Indicator identifier is empty after normalization.",
                )
            bundle = exporter.export_indicator(_norm, depth=depth, limit=limit)
        elif ot == "actor":
            bundle = exporter.export_threat_actor(identifier, depth=depth, limit=limit)
        elif ot == "technique":
            # READ-side canonicalization (parity with the cve/indicator
            # branches): 't1059' / 'T 1059' → 'T1059' (the graph stores the
            # canonical uppercase Tnnnn(.nnn) form). Raw fallback when the
            # paste isn't a recognizable technique id.
            bundle = exporter.export_technique(
                normalize_mitre_technique_id(identifier) or identifier, depth=depth, limit=limit
            )
        elif ot == "cve":
            # READ-side canonicalization: 'cve 2021 44228' / en-dash paste
            # variants → 'CVE-2021-44228' (graph stores uppercase CVE ids).
            bundle = exporter.export_cve(normalize_cve_id(identifier) or identifier, depth=depth, limit=limit)
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
    except Exception as exc:
        _raise_api_error(exc, "STIX export failed")

    return _JSON(
        content=bundle,
        media_type=StixExporter.MEDIA_TYPE,
    )


# Alias-aware actor resolution + fenced aggregation, modeled on
# stix_exporter.export_threat_actor: a ``WITH … collect(DISTINCT …)`` step
# between every OPTIONAL MATCH keeps the row count bounded by one
# collection at a time instead of the Cartesian product of all four.
# Actor names are stored LOWERCASE at write time
# (node_identity.canonicalize_merge_key); aliases keep display case — hence
# toLower(trim(…)) on both the input and each alias. $name is ALWAYS a
# bound parameter (Cypher-injection rule), never interpolated.
_ACTOR_SUMMARY_CYPHER = """
    MATCH (a:ThreatActor)
    WHERE (a.edgeguard_managed = true OR a.edgeguard_enriched = true)
      AND (a.name = toLower(trim($name))
           OR any(x IN coalesce(a.aliases, []) WHERE toLower(trim(x)) = toLower(trim($name))))
    // Deterministic tiebreak: a canonical-NAME hit always wins over an
    // alias-only hit, then by name for stability — so when two managed
    // actors share the same alias string, we never return the wrong
    // profile nondeterministically (Bugbot 2026-06).
    WITH a, (CASE WHEN a.name = toLower(trim($name)) THEN 0 ELSE 1 END) AS _match_rank
    ORDER BY _match_rank, a.name
    LIMIT 1
    OPTIONAL MATCH (m:Malware)-[:ATTRIBUTED_TO]->(a)
      WHERE (m.edgeguard_managed = true OR m.edgeguard_enriched = true)
    WITH a, collect(DISTINCT m.name) AS malware_names
    OPTIONAL MATCH (a)-[:EMPLOYS_TECHNIQUE]->(t:Technique)
      WHERE (t.edgeguard_managed = true OR t.edgeguard_enriched = true)
    WITH a, malware_names, collect(DISTINCT t {.mitre_id, .name}) AS technique_rows
    OPTIONAL MATCH (a)-[:RUNS]->(c:Campaign)
      WHERE (c.edgeguard_managed = true OR c.edgeguard_enriched = true)
    WITH a, malware_names, technique_rows, collect(DISTINCT c.name) AS campaign_names
    RETURN a {.name, .aliases, .description, .description_source, .sophistication, .motivation,
              .primary_motivation, .confidence_score, .zone, .source} AS actor,
           a.name = toLower(trim($name)) AS resolved_by_name,
           malware_names[0..10] AS malware,
           size(malware_names) AS malware_total,
           technique_rows[0..15] AS techniques,
           size(technique_rows) AS technique_total,
           campaign_names[0..5] AS campaigns,
           size(campaign_names) AS campaign_total
"""


def _as_str_list(val: Any) -> List[str]:
    """Coerce a Neo4j property (scalar, list, or None) to a list of strings."""
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


@app.get(
    "/actors/{name}/summary",
    response_model=ActorSummaryResponse,
    dependencies=[Depends(_verify_api_key)],
)
@limiter.limit(_RATE_LIMIT_READ)
async def actor_summary(request: Request, name: str):
    """Summarize a threat actor: profile + attributed malware, employed
    techniques, and campaigns (top-N lists with total counts).

    Resolution is alias-aware and case-insensitive — ``name`` may be the
    canonical (lowercase-stored) actor name or any alias in its observed
    display case. Returns 404 when no actor matches.
    """
    _require_neo4j()

    try:
        with neo4j_client.driver.session(default_access_mode="READ") as session:
            record = session.run(_ACTOR_SUMMARY_CYPHER, name=name, timeout=_NEO4J_QUERY_TIMEOUT).single()

        if not record:
            raise HTTPException(status_code=404, detail="Threat actor not found")

        actor = _node_props(record["actor"])
        techniques = [
            ActorTechniqueSummary(mitre_id=t.get("mitre_id"), name=t.get("name"))
            for t in (record["techniques"] or [])
            if t
        ]
        return ActorSummaryResponse(
            name=actor.get("name", ""),
            aliases=_as_str_list(actor.get("aliases")),
            description=actor.get("description"),
            description_source=actor.get("description_source"),
            sophistication=actor.get("sophistication"),
            motivation=actor.get("motivation") or actor.get("primary_motivation"),
            confidence_score=actor.get("confidence_score"),
            zone=_as_str_list(actor.get("zone")),
            source=_as_str_list(actor.get("source")),
            resolved_by="name" if record["resolved_by_name"] else "alias",
            malware=[m for m in (record["malware"] or []) if m],
            malware_total=record["malware_total"] or 0,
            techniques=techniques,
            technique_total=record["technique_total"] or 0,
            campaigns=[c for c in (record["campaigns"] or []) if c],
            campaign_total=record["campaign_total"] or 0,
        )

    except HTTPException:
        raise
    except Exception as exc:
        _raise_api_error(exc, "Actor summary failed")


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

    _require_neo4j()

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
        _raise_api_error(e, "Admin query failed")


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
        base_query = (
            "MATCH (n) WHERE (n:Vulnerability OR n:CVE) AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
        )

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
        base_query = "MATCH (n:ThreatActor) WHERE (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
        if zone:
            base_query += " AND $zone IN n.zone"
        return base_query + " RETURN n LIMIT $limit"

    # Indicator queries
    if any(kw in query_lower for kw in ["indicator", "ip", "domain", "hash", "malicious"]):
        base_query = "MATCH (n:Indicator)"

        if "ip" in query_lower:
            # Both address families: the sync types IPv6 addresses ``ipv6`` (2026-10).
            base_query += (
                " WHERE n.indicator_type IN ['ipv4', 'ipv6']"
                " AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
            )
        elif "domain" in query_lower:
            base_query += (
                " WHERE n.indicator_type = 'domain' AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
            )
        elif "hash" in query_lower:
            base_query += (
                " WHERE n.indicator_type = 'hash' AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
            )
        else:
            base_query += " WHERE (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"

        if zone:
            base_query += " AND $zone IN n.zone"

        return base_query + " RETURN n LIMIT $limit"

    # Default: search across labeled threat-intel nodes (avoid full-graph scan)
    base_query = (
        "MATCH (n) WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware OR "
        "n:ThreatActor OR n:Technique OR n:Campaign) AND (n.edgeguard_managed = true OR n.edgeguard_enriched = true)"
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
    # PR-A audit fix (Red Team HIGH): the docker-compose ``api`` service now
    # invokes ``python -m src.query_api`` (instead of ``python -m uvicorn ...
    # --host 0.0.0.0 --workers 2``) so the EDGEGUARD_API_HOST env-var safety
    # check at lines 88-102 actually gates the bind. ``EDGEGUARD_API_WORKERS``
    # restores the multi-worker config (default 1 to match the prior reload-safe
    # default; compose sets =2 for production posture). Reload mode forces 1
    # worker because uvicorn's reload + workers are mutually exclusive.
    try:
        workers = int(os.getenv("EDGEGUARD_API_WORKERS", "1"))
    except (ValueError, TypeError):
        workers = 1
    if reload and workers > 1:
        logger.warning("EDGEGUARD_API_RELOAD=true forces EDGEGUARD_API_WORKERS=1 (uvicorn limitation)")
        workers = 1

    logger.info(f"[START] Starting EdgeGuard Query API on {host}:{port} (workers={workers})")

    # PR-A audit fix (Bugbot MED on commit ce37238): the previous
    # ``uvicorn.run("query_api:app", ...)`` import string relied on
    # ``PYTHONPATH=/app/src`` being set so uvicorn's worker reimport could
    # resolve the bare module name. Compose + the Docker image both set
    # PYTHONPATH, but if this module is invoked via ``python -m
    # src.query_api`` from a context without that PYTHONPATH (local dev
    # without venv activate, ad-hoc test harness), uvicorn's worker
    # reimport raises ``ModuleNotFoundError: query_api``. ``"src.query_api:app"``
    # works regardless of PYTHONPATH because it matches the actual module
    # path under the project root.
    uvicorn.run("src.query_api:app", host=host, port=port, reload=reload, workers=workers, log_level="info")
