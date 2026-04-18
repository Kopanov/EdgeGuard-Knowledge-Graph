#!/usr/bin/env python3
"""
EdgeGuard - Neo4j Client with Source Tracking
Handles connection, graph operations, and source tracking with data quality

Production-ready features:
- Connection retry logic with exponential backoff
- Comprehensive error handling and logging
- Batch processing for bulk inserts
- Health checks
- Timeouts for all operations
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

# Add src to path if needed
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from neo4j import GraphDatabase
    from neo4j import exceptions as neo4j_exceptions
except ImportError:
    raise ImportError("neo4j package not installed. Run: pip install neo4j")

# Deterministic per-node UUIDs for cross-environment traceability — see
# src/node_identity.py for the namespace, canonicalization rules, and the
# per-label natural-key map.
from node_identity import canonicalize_merge_key, compute_node_uuid, edge_endpoint_uuids  # noqa: E402
from query_pause import query_pause  # noqa: E402

# Configure logging
logger = logging.getLogger(__name__)

# Prometheus metrics (optional – gracefully degrade when metrics_server is not importable)
try:
    from metrics_server import NEO4J_QUERIES, NEO4J_QUERY_DURATION

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

# Configuration constants
NEO4J_CONNECTION_TIMEOUT = 60  # seconds
NEO4J_READ_TIMEOUT = 300  # seconds (5 min; 120s was too low for 441K-node graph)
_REL_QUERY_TIMEOUT = 60  # seconds — shorter timeout for relationship UNWIND to fail fast on lock contention
MAX_RETRIES = 5
RETRY_DELAY_BASE = 2  # seconds (exponential backoff base)
BATCH_SIZE = 1000  # Maximum items per batch

# Whitelist of node labels that may be used in dynamic Cypher queries.
# If new labels are added to the data model they must also be listed here.
#
# Keep in sync with ResilMesh model CSVs (monorepo):
#   ../data model - general/Neo4j/neo4j_nodes_properties.csv
#   ../data model - general/Neo4j/neo4j_relationships_properties.csv
# CI: ``tests/test_neo4j_csv_model_alignment.py`` (skipped if CSV path missing).
#
# Covers: (1) merge_node_with_source / _merge_cvss_node / apply_sector_labels / get_stats,
# (2) every MERGE/MATCH primary label in this module (ResilMesh topology + alerts).
_ALLOWED_NODE_LABELS: frozenset = frozenset(
    {
        # Threat intel — MISP / NVD / MITRE / enrichment
        "Alert",
        "Campaign",
        "CVE",
        "Indicator",
        "Malware",
        "Sector",
        "Source",
        "Tactic",
        "Technique",
        "ThreatActor",
        "Tool",
        "Vulnerability",
        # CVSS sub-nodes on CVE (ResilMesh / ISIM)
        "CVSSv2",
        "CVSSv30",
        "CVSSv31",
        "CVSSv40",
        # ResilMesh topology (process_resilmesh_alert / merge_* helpers below)
        "Application",
        "Component",
        "Device",
        "Host",
        "IP",
        "Mission",
        "MissionDependency",
        "NetworkService",
        "Node",
        "OrganizationUnit",
        "Role",
        "SoftwareVersion",
        "Subnet",
        "User",
    }
)


def _validate_label(label: str) -> str:
    """Raise ValueError if *label* is not in the allowed set, else return it."""
    if label not in _ALLOWED_NODE_LABELS:
        raise ValueError(
            f"Cypher injection guard: '{label}' is not an allowed node label. Allowed: {sorted(_ALLOWED_NODE_LABELS)}"
        )
    return label


# Compiled regex for validating Cypher property/relationship names.
# Allows only identifiers: letter or underscore, followed by letters/digits/underscores.
_PROP_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_rel_type(name: str) -> str:
    """Raise ValueError if *name* is not a safe Cypher relationship-type identifier."""
    if not _PROP_NAME_RE.match(name):
        raise ValueError(
            f"Cypher injection guard: '{name}' is not a valid relationship type name. "
            "Only alphanumeric characters and underscores are allowed."
        )
    return name


def _validate_prop_name(name: str) -> str:
    """Raise ValueError if *name* is not a safe Cypher property identifier."""
    if not _PROP_NAME_RE.match(name):
        raise ValueError(
            f"Cypher injection guard: '{name}' is not a valid property name. "
            "Only alphanumeric characters and underscores are allowed."
        )
    return name


# --------------------------------------------------------------------------- #
# Zone accumulation — override 'global' if any specific sector exists
# --------------------------------------------------------------------------- #
#
# PR #34 round 24: the per-text/per-item zone detection in ``config.py`` and
# the MISP writer enforce the rule "if a specific sector matches, drop
# 'global' from the zone list." But the Neo4j MERGE layer used to accumulate
# zones with a plain APOC set union — so an Indicator first ingested from a
# healthcare-specific feed (zone=["healthcare"]) and later seen by a generic
# feed (zone=["global"]) would accumulate to ``n.zone = ["healthcare",
# "global"]`` after the second MERGE. That re-introduced "global" alongside
# the specific sector and broke filtering / RAG semantics ("WHERE 'global'
# IN n.zone" started matching healthcare nodes).
#
# This helper builds the canonical "drop-global-if-specifics-exist"
# accumulator clause — one source of truth used by every node MERGE that
# accumulates zones. The CASE expression is small enough that re-evaluating
# the union twice is negligible vs the readability win.
def _zone_override_global_clause(node_var: str, source_expr: str) -> str:
    """Return a Cypher SET-clause fragment that accumulates zones with the
    "specifics-override-global" rule applied at write time.

    Args:
        node_var: the bound node variable in the MERGE (e.g. ``"n"`` or ``"i"``).
        source_expr: the Cypher expression yielding the new zones to merge in
            (e.g. ``"$zone"`` or ``"item.zone"``). Must already be a list.

    Returns:
        A string suitable for splicing into a ``SET ...`` clause, e.g.::

            f"SET {node_var}.score = 1, {_zone_override_global_clause('n', '$zone')}, ..."

    Result semantics (for any ingestion):
        - if union(existing, new) contains any sector other than 'global'
          → store only the specifics (drop 'global')
        - else (only 'global' or empty) → store the union as-is
    """
    # Validate the variable name to prevent Cypher injection via caller bug.
    # (Both inputs are constructed by EdgeGuard code, never by user input —
    # but a typo could still produce broken Cypher; better to fail loudly.)
    if not _PROP_NAME_RE.match(node_var):
        raise ValueError(f"_zone_override_global_clause: invalid node_var {node_var!r}")
    union = f"apoc.coll.toSet(coalesce({node_var}.zone, []) + {source_expr})"
    specifics = f"[z IN {union} WHERE z <> 'global']"
    return f"{node_var}.zone = CASE WHEN size({specifics}) > 0 THEN {specifics} ELSE {union} END"


def nonempty_graph_string(value: Any) -> Optional[str]:
    """
    Normalize a generic string used as a graph relationship endpoint (names, ids, values).

    Returns None for null, empty, or whitespace-only — callers must not create edges on unknowns.
    """
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def normalize_cve_id_for_graph(value: Any) -> Optional[str]:
    """
    Return a canonical CVE id string for graph keys/relationships, or None if unknown.

    Never returns blank/whitespace — callers must not MERGE or link on null/empty data.
    """
    s = nonempty_graph_string(value)
    return s.upper() if s else None


def resolve_vulnerability_cve_id(item: Dict[str, Any]) -> Optional[str]:
    """
    Resolve CVE identifier for Vulnerability MERGE keys and cross-item relationships.

    MISP vulnerability attributes often carry the CVE only in ``value``; some ingestion
    paths omit ``cve_id``. Returns an uppercase string (e.g. CVE-2025-32432) or None.
    """
    cid = normalize_cve_id_for_graph(item.get("cve_id"))
    if cid:
        return cid
    if item.get("type") == "vulnerability":
        return normalize_cve_id_for_graph(item.get("value"))
    return None


# Source definitions
SOURCES = {
    "alienvault_otx": {"name": "AlienVault OTX", "type": "threat_intel", "reliability": 0.7},
    "virustotal": {"name": "VirusTotal", "type": "threat_intel", "reliability": 0.8},
    "abuseipdb": {"name": "AbuseIPDB", "type": "threat_intel", "reliability": 0.65},
    "mitre_attck": {"name": "MITRE ATT&CK", "type": "framework", "reliability": 0.95},
    "nvd": {"name": "NVD", "type": "vulnerability_db", "reliability": 0.9},
    "misp": {"name": "MISP", "type": "threat_intel", "reliability": 0.75},
    "cisa": {"name": "CISA KEV", "type": "advisory", "reliability": 0.9},
    "cisa_kev": {"name": "CISA KEV", "type": "advisory", "reliability": 0.9},
    "feodo": {"name": "Feodo Tracker", "type": "threat_intel", "reliability": 0.7},
    "sslbl": {"name": "SSL Blacklist", "type": "threat_intel", "reliability": 0.65},
    "urlhaus": {"name": "URLhaus", "type": "threat_intel", "reliability": 0.7},
    "cybercure": {"name": "CyberCure", "type": "threat_intel", "reliability": 0.6},
    "threatfox": {"name": "ThreatFox", "type": "threat_intel", "reliability": 0.7},
}


def retry_with_backoff(max_retries: int = MAX_RETRIES, base_delay: float = RETRY_DELAY_BASE):
    """Decorator for retry logic with exponential backoff."""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries + 1):  # +1: first attempt + max_retries retries (matches collector_utils)
                try:
                    return func(*args, **kwargs)
                except (
                    neo4j_exceptions.ServiceUnavailable,
                    neo4j_exceptions.TransientError,
                    ConnectionError,  # includes ConnectionRefusedError, ConnectionResetError, BrokenPipeError
                    TimeoutError,
                ) as e:
                    last_exception = e
                    if attempt >= max_retries:
                        break  # exhausted all retries
                    delay = base_delay * (2**attempt)
                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. Retrying in {delay}s..."
                    )
                    time.sleep(delay)
                except Exception as e:
                    # Non-retryable exception
                    logger.error(f"{func.__name__} failed with non-retryable error: {e}")
                    raise

            logger.error(f"{func.__name__} failed after {max_retries + 1} attempts")
            raise last_exception

        return wrapper

    return decorator


class Neo4jClient:
    """Production-ready Neo4j client with retry logic and batch processing."""

    def __init__(self, uri: str = None, user: str = None, password: str = None):
        from config import NEO4J_PASSWORD, NEO4J_URI, NEO4J_USER

        self.uri = uri or NEO4J_URI
        self.user = user or NEO4J_USER
        self.password = password or NEO4J_PASSWORD
        self.driver = None
        self._connection_healthy = False

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def connect(self) -> bool:
        """
        Connect to Neo4j with retry logic.

        Returns:
            True if connection successful, False otherwise
        """
        try:
            logger.info(f"Connecting to Neo4j at {self.uri}")
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                connection_timeout=NEO4J_CONNECTION_TIMEOUT,
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=120,
            )

            # Verify connection with health check
            with self.driver.session() as session:
                result = session.run("RETURN 1 as test", timeout=NEO4J_READ_TIMEOUT)
                result.single()

            self._connection_healthy = True
            logger.info("Connected to Neo4j successfully")
            return True

        except neo4j_exceptions.AuthError as e:
            logger.error(f"Neo4j authentication failed: {e}")
            self._connection_healthy = False
            return False
        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            self._connection_healthy = False
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Neo4j connection failed: {type(e).__name__}: {e}")
            self._connection_healthy = False
            return False

    def close(self) -> None:
        """Close connection safely."""
        if self.driver:
            try:
                self.driver.close()
                logger.info("Neo4j connection closed")
            except Exception as e:
                logger.warning(f"Error closing Neo4j connection: {e}")
            finally:
                self.driver = None
                self._connection_healthy = False

    def is_connected(self) -> bool:
        """True if a Bolt driver was created (after :meth:`connect`).

        This is a **fast** check for API request guards; it does not ping the
        server. Use :meth:`health_check` for liveness + APOC validation.
        """
        return self.driver is not None

    def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on Neo4j connection.

        Returns:
            Dict with health status information
        """
        if not self.driver:
            return {"healthy": False, "error": "No driver initialized"}

        try:
            with self.driver.session() as session:
                start_time = time.time()
                result = session.run("RETURN 1 as test", timeout=10)
                result.single()
                response_time = time.time() - start_time

                # Get database info
                db_info = session.run(
                    "CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition",
                    timeout=NEO4J_READ_TIMEOUT,
                )
                db_record = db_info.single()

                base = {
                    "healthy": True,
                    "response_time_ms": round(response_time * 1000, 2),
                    "database": db_record["name"] if db_record else "unknown",
                    "version": db_record["versions"][0] if db_record and db_record["versions"] else "unknown",
                    "edition": db_record["edition"] if db_record else "unknown",
                }

                # APOC is required for MERGE list deduplication (apoc.coll.toSet) and sector labels.
                try:
                    apoc_test = session.run("RETURN size(apoc.coll.toSet([1, 2, 2])) AS n", timeout=10)
                    row = apoc_test.single()
                    if row is None or row["n"] != 2:
                        raise RuntimeError("APOC apoc.coll.toSet returned unexpected result")
                    base["apoc_available"] = True
                except Exception as apoc_err:
                    logger.error(f"Neo4j APOC check failed (sync will not work): {apoc_err}")
                    return {
                        "healthy": False,
                        "error": (
                            "Neo4j APOC plugin is missing or not allowed. "
                            "EdgeGuard requires APOC (e.g. docker-compose: NEO4J_PLUGINS='[\"apoc\"]' "
                            "and dbms.security.procedures allowlist for apoc.*). "
                            f"Details: {apoc_err}"
                        ),
                        "apoc_available": False,
                    }

                return base
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"healthy": False, "error": str(e)}

    @retry_with_backoff(max_retries=3)
    def run(self, query: str, parameters: Dict = None, timeout: int = None) -> List[Dict]:
        """
        Run a generic query with retry logic.

        Args:
            query: Cypher query string
            parameters: Query parameters
            timeout: Query timeout in seconds

        Returns:
            List of result records
        """
        if not self.driver:
            logger.error("Cannot run query: no connection to Neo4j")
            return []

        timeout = timeout or NEO4J_READ_TIMEOUT
        parameters = parameters or {}

        _t0 = time.monotonic()
        try:
            with self.driver.session() as session:
                result = session.run(query, parameters, timeout=timeout)
                records = [dict(record) for record in result]
            if _METRICS_AVAILABLE:
                NEO4J_QUERIES.labels(query_type="cypher", status="success").inc()
                NEO4J_QUERY_DURATION.labels(query_type="cypher").observe(time.monotonic() - _t0)
            return records
        except neo4j_exceptions.CypherSyntaxError as e:
            if _METRICS_AVAILABLE:
                NEO4J_QUERIES.labels(query_type="cypher", status="error").inc()
            logger.error(f"Cypher syntax error: {e}")
            return []
        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            if _METRICS_AVAILABLE:
                NEO4J_QUERIES.labels(query_type="cypher", status="error").inc()
            raise  # let @retry_with_backoff handle transient errors
        except neo4j_exceptions.DatabaseError as e:
            if _METRICS_AVAILABLE:
                NEO4J_QUERIES.labels(query_type="cypher", status="error").inc()
            logger.error(f"Neo4j database error: {type(e).__name__}: {e}")
            return []

    @retry_with_backoff(max_retries=3)
    def clear_all(self) -> bool:
        """
        Clear all nodes and relationships safely.

        Returns:
            True if successful, False otherwise
        """
        if not self.driver:
            logger.error("Cannot clear: no connection to Neo4j")
            return False

        try:
            logger.warning("Clearing all nodes and relationships from Neo4j...")
            with self.driver.session() as session:
                # Get counts before clearing
                counts = session.run("MATCH (n) RETURN count(n) as count", timeout=NEO4J_READ_TIMEOUT)
                node_count = counts.single()["count"]

                # Clear in batches to avoid memory issues
                batch_size = 10000
                deleted = 0
                while deleted < node_count:
                    result = session.run(
                        f"MATCH (n) WITH n LIMIT {batch_size} DETACH DELETE n RETURN count(n) as deleted",
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    batch_deleted = result.single()["deleted"]
                    if batch_deleted == 0:
                        break
                    deleted += batch_deleted
                    logger.debug(f"Deleted batch of {batch_deleted} nodes")

                # Clear Source nodes
                session.run("MATCH (s:Source) DETACH DELETE s", timeout=NEO4J_READ_TIMEOUT)

            logger.info(f"Cleared {deleted} nodes and relationships")
            return True

        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error clearing Neo4j: {e}")
            return False

    @retry_with_backoff(max_retries=3)
    def create_constraints(self) -> Tuple[int, int]:
        """
        Create UNIQUE constraints with error handling.

        Returns:
            Tuple of (success_count, error_count)
        """
        if not self.driver:
            logger.error("Cannot create constraints: no connection")
            return 0, 0

        # Migration: drop old compound (name/cve_id, tag) constraints before creating
        # single-key ones. Harmless if they don't exist (IF EXISTS).
        old_constraints = [
            "DROP CONSTRAINT cve_key IF EXISTS",
            "DROP CONSTRAINT vulnerability_key IF EXISTS",
            "DROP CONSTRAINT malware_key IF EXISTS",
            "DROP CONSTRAINT actor_key IF EXISTS",
            "DROP CONSTRAINT technique_key IF EXISTS",
            "DROP CONSTRAINT tactic_key IF EXISTS",
            "DROP CONSTRAINT campaign_key IF EXISTS",
            "DROP CONSTRAINT tool_key IF EXISTS",
            "DROP CONSTRAINT indicator_key IF EXISTS",
            # Drop old compound CVSS constraints (cve_id, tag) → single-key (cve_id)
            "DROP CONSTRAINT cvssv31_key IF EXISTS",
            "DROP CONSTRAINT cvssv2_key IF EXISTS",
            "DROP CONSTRAINT cvssv30_key IF EXISTS",
            "DROP CONSTRAINT cvssv40_key IF EXISTS",
        ]
        with self.driver.session() as session:
            for stmt in old_constraints:
                try:
                    session.run(stmt, timeout=NEO4J_READ_TIMEOUT)
                except Exception as drop_err:
                    # PR #33 round 13: silent ``except: pass`` replaced with a
                    # DEBUG log so an operator running in verbose mode can see
                    # which old-constraint drops were no-ops vs which silently
                    # masked a real schema error. Most invocations are no-ops
                    # (constraint already absent on a fresh DB), so DEBUG is
                    # the right level — INFO would spam.
                    logger.debug("Drop legacy constraint %r: %s (likely already absent)", stmt[:60], drop_err)

            # Deduplicate CVSS nodes before creating single-key constraints.
            # Old compound key (cve_id, tag) may have created multiple nodes per CVE.
            # Keep the first node (by elementId), move relationships, delete duplicates.
            for cvss_label in ("CVSSv31", "CVSSv30", "CVSSv2", "CVSSv40"):
                try:
                    dedup_result = session.run(
                        f"""
                        MATCH (n:{cvss_label})
                        WITH n.cve_id AS cid, collect(n) AS nodes
                        WHERE size(nodes) > 1
                        WITH nodes[0] AS keep, nodes[1..] AS dups
                        UNWIND dups AS dup
                        // Move any relationships from duplicate to keeper
                        WITH keep, dup
                        OPTIONAL MATCH (dup)-[r]-()
                        DELETE r
                        DETACH DELETE dup
                        RETURN count(dup) AS removed
                        """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    row = dedup_result.single()
                    removed = row["removed"] if row else 0
                    if removed > 0:
                        logger.info("CVSS dedup: removed %s duplicate %s nodes", removed, cvss_label)
                except Exception as e:
                    logger.debug("CVSS dedup for %s skipped: %s", cvss_label, e)

        constraints = [
            # Source nodes
            "CREATE CONSTRAINT source_key IF NOT EXISTS FOR (s:Source) REQUIRE (s.source_id) IS UNIQUE",
            # CVE / Vulnerability — separate labels kept for backward compat
            "CREATE CONSTRAINT cve_key IF NOT EXISTS FOR (c:CVE) REQUIRE (c.cve_id) IS UNIQUE",
            # Vulnerability: match the 2-field MERGE key used in merge_vulnerabilities_batch
            "CREATE CONSTRAINT vulnerability_key IF NOT EXISTS FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE",
            # Indicator: match the 2-field MERGE key used in merge_indicators_batch
            "CREATE CONSTRAINT indicator_key IF NOT EXISTS FOR (i:Indicator) REQUIRE (i.indicator_type, i.value) IS UNIQUE",
            # Threat-graph node types
            "CREATE CONSTRAINT malware_key IF NOT EXISTS FOR (m:Malware) REQUIRE (m.name) IS UNIQUE",
            "CREATE CONSTRAINT actor_key IF NOT EXISTS FOR (a:ThreatActor) REQUIRE (a.name) IS UNIQUE",
            "CREATE CONSTRAINT technique_key IF NOT EXISTS FOR (t:Technique) REQUIRE (t.mitre_id) IS UNIQUE",
            # MITRE tactics — 14 fixed nodes; unique by mitre_id only
            "CREATE CONSTRAINT tactic_key IF NOT EXISTS FOR (t:Tactic) REQUIRE (t.mitre_id) IS UNIQUE",
            # Tool nodes — MITRE tools, keyed by mitre_id only
            "CREATE CONSTRAINT tool_key IF NOT EXISTS FOR (t:Tool) REQUIRE (t.mitre_id) IS UNIQUE",
            # Sector nodes — created dynamically; must stay unique by name
            "CREATE CONSTRAINT sector_key IF NOT EXISTS FOR (s:Sector) REQUIRE (s.name) IS UNIQUE",
            # CVSS sub-nodes — one per CVE (CVSS scores are properties of the vuln, not the source)
            "CREATE CONSTRAINT cvssv31_key IF NOT EXISTS FOR (n:CVSSv31) REQUIRE (n.cve_id) IS UNIQUE",
            "CREATE CONSTRAINT cvssv2_key IF NOT EXISTS FOR (n:CVSSv2) REQUIRE (n.cve_id) IS UNIQUE",
            "CREATE CONSTRAINT cvssv30_key IF NOT EXISTS FOR (n:CVSSv30) REQUIRE (n.cve_id) IS UNIQUE",
            "CREATE CONSTRAINT cvssv40_key IF NOT EXISTS FOR (n:CVSSv40) REQUIRE (n.cve_id) IS UNIQUE",
            # Campaign nodes — one per actor, keyed by name only
            "CREATE CONSTRAINT campaign_key IF NOT EXISTS FOR (c:Campaign) REQUIRE (c.name) IS UNIQUE",
            # PR #34 round 26 (invariant audit): added the missing 10 UNIQUE
            # constraints to match the labels declared in
            # ``node_identity._NATURAL_KEYS``. Without these, two concurrent
            # MERGEs on the same logical (label, key) could create duplicate
            # nodes — silently violating the deterministic-uuid contract that
            # underpins delta sync. Pinned by
            # ``test_every_natural_key_label_has_a_unique_constraint``.
            # ResilMesh / topology
            "CREATE CONSTRAINT ip_key IF NOT EXISTS FOR (n:IP) REQUIRE (n.address) IS UNIQUE",
            "CREATE CONSTRAINT host_key IF NOT EXISTS FOR (n:Host) REQUIRE (n.hostname) IS UNIQUE",
            "CREATE CONSTRAINT device_key IF NOT EXISTS FOR (n:Device) REQUIRE (n.device_id) IS UNIQUE",
            "CREATE CONSTRAINT subnet_key IF NOT EXISTS FOR (n:Subnet) REQUIRE (n.range) IS UNIQUE",
            "CREATE CONSTRAINT networkservice_key IF NOT EXISTS FOR (n:NetworkService) REQUIRE (n.port, n.protocol) IS UNIQUE",  # noqa: E501
            "CREATE CONSTRAINT softwareversion_key IF NOT EXISTS FOR (n:SoftwareVersion) REQUIRE (n.version) IS UNIQUE",
            "CREATE CONSTRAINT application_key IF NOT EXISTS FOR (n:Application) REQUIRE (n.name) IS UNIQUE",
            "CREATE CONSTRAINT role_key IF NOT EXISTS FOR (n:Role) REQUIRE (n.permission) IS UNIQUE",
            # User: composite (username, domain) — domain is normalized to
            # 'default' for None/"" inputs (PR #34 round 25, see
            # merge_resilmesh_user) so the constraint compares apples-to-apples.
            "CREATE CONSTRAINT user_key IF NOT EXISTS FOR (n:User) REQUIRE (n.username, n.domain) IS UNIQUE",
            # Alert: alert_id is the upstream-provided idempotency key.
            "CREATE CONSTRAINT alert_key IF NOT EXISTS FOR (n:Alert) REQUIRE (n.alert_id) IS UNIQUE",
        ]

        success_count = 0
        error_count = 0

        with self.driver.session() as session:
            for constraint in constraints:
                try:
                    session.run(constraint, timeout=NEO4J_READ_TIMEOUT)
                    logger.info(f"Constraint created: {constraint[:50]}...")
                    success_count += 1
                except neo4j_exceptions.DatabaseError as e:
                    # Constraint may already exist or be unsupported
                    logger.debug(f"Constraint (may exist): {e}")
                    success_count += 1  # Not a failure if it exists
                except Exception as e:
                    logger.warning(f"Constraint error: {e}")
                    error_count += 1

        logger.info(f"Constraints: {success_count} succeeded, {error_count} failed")
        return success_count, error_count

    @retry_with_backoff(max_retries=3)
    def create_indexes(self) -> Tuple[int, int]:
        """
        Create indexes for performance.

        Returns:
            Tuple of (success_count, error_count)
        """
        if not self.driver:
            logger.error("Cannot create indexes: no connection")
            return 0, 0

        indexes = [
            "CREATE INDEX source_id_idx IF NOT EXISTS FOR (s:Source) ON (s.source_id)",
            "CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
            "CREATE INDEX indicator_value IF NOT EXISTS FOR (i:Indicator) ON (i.value)",
            "CREATE INDEX indicator_type IF NOT EXISTS FOR (i:Indicator) ON (i.indicator_type)",
            "CREATE INDEX indicator_source IF NOT EXISTS FOR (i:Indicator) ON (i.source)",
            "CREATE INDEX indicator_zone IF NOT EXISTS FOR (i:Indicator) ON (i.zone)",
            "CREATE INDEX malware_name IF NOT EXISTS FOR (m:Malware) ON (m.name)",
            "CREATE INDEX actor_name IF NOT EXISTS FOR (a:ThreatActor) ON (a.name)",
            "CREATE INDEX technique_mitre IF NOT EXISTS FOR (t:Technique) ON (t.mitre_id)",
            # PR #34 round 18: dropped indicator_original_source +
            # vulnerability_original_source indexes — the n.original_source
            # property they backed had ZERO production readers (no GraphQL
            # field, no STIX export, no Cypher MATCH/WHERE). The Python
            # helper that EXTRACTS original_source from MISP tags is alive
            # (it derives the canonical `source` field), only the Neo4j
            # property write + indexes were dead.
            # Active/inactive tracking indexes
            "CREATE INDEX indicator_active IF NOT EXISTS FOR (i:Indicator) ON (i.active)",
            "CREATE INDEX vulnerability_active IF NOT EXISTS FOR (v:Vulnerability) ON (v.active)",
            # PR #33 round 10: dropped 5 legacy-scalar indexes (indicator/
            # vulnerability/malware/actor _misp_event_id and
            # indicator_misp_attribute_id). All readers now match against
            # misp_event_ids[] / misp_attribute_ids[] via list-membership
            # predicates (`eid IN n.misp_event_ids`) — Neo4j 5 handles those
            # without an index; an explicit array-membership index would only
            # help at much larger scale (>10M rows).
            "CREATE INDEX tactic_shortname IF NOT EXISTS FOR (t:Tactic) ON (t.shortname)",
            "CREATE INDEX technique_tactic_phases IF NOT EXISTS FOR (t:Technique) ON (t.tactic_phases)",
            # CVSS sub-node lookup indexes
            "CREATE INDEX cvssv31_cve_id IF NOT EXISTS FOR (n:CVSSv31) ON (n.cve_id)",
            "CREATE INDEX cvssv30_cve_id IF NOT EXISTS FOR (n:CVSSv30) ON (n.cve_id)",
            "CREATE INDEX cvssv2_cve_id IF NOT EXISTS FOR (n:CVSSv2) ON (n.cve_id)",
            "CREATE INDEX cvssv40_cve_id IF NOT EXISTS FOR (n:CVSSv40) ON (n.cve_id)",
            # Campaign enrichment indexes
            "CREATE INDEX campaign_actor_name IF NOT EXISTS FOR (c:Campaign) ON (c.actor_name)",
            "CREATE INDEX campaign_zone IF NOT EXISTS FOR (c:Campaign) ON (c.zone)",
            # Decay / active tracking
            "CREATE INDEX indicator_last_updated IF NOT EXISTS FOR (i:Indicator) ON (i.last_updated)",
            "CREATE INDEX vulnerability_last_updated IF NOT EXISTS FOR (v:Vulnerability) ON (v.last_updated)",
            # build_relationships performance: CVE.cve_id needed for EXPLOITS query
            "CREATE INDEX cve_cve_id IF NOT EXISTS FOR (c:CVE) ON (c.cve_id)",
            # Deterministic per-node UUID indexes — added 2026-04 for delta-sync
            # local→cloud (cloud MERGEs by uuid) and self-describing edge serialization
            # (xAI / RAG consumers resolve r.src_uuid / r.trg_uuid back to nodes by uuid).
            # Index, not UNIQUE constraint — natural-key UNIQUE constraints already
            # prevent duplicate nodes; UUIDv5 collisions are negligible; and the
            # constraint creation can't run before the backfill populates the field.
            "CREATE INDEX indicator_uuid IF NOT EXISTS FOR (i:Indicator) ON (i.uuid)",
            "CREATE INDEX vulnerability_uuid IF NOT EXISTS FOR (v:Vulnerability) ON (v.uuid)",
            "CREATE INDEX cve_uuid IF NOT EXISTS FOR (c:CVE) ON (c.uuid)",
            "CREATE INDEX malware_uuid IF NOT EXISTS FOR (m:Malware) ON (m.uuid)",
            "CREATE INDEX actor_uuid IF NOT EXISTS FOR (a:ThreatActor) ON (a.uuid)",
            "CREATE INDEX technique_uuid IF NOT EXISTS FOR (t:Technique) ON (t.uuid)",
            "CREATE INDEX tactic_uuid IF NOT EXISTS FOR (t:Tactic) ON (t.uuid)",
            "CREATE INDEX tool_uuid IF NOT EXISTS FOR (t:Tool) ON (t.uuid)",
            "CREATE INDEX sector_uuid IF NOT EXISTS FOR (s:Sector) ON (s.uuid)",
            "CREATE INDEX source_uuid IF NOT EXISTS FOR (s:Source) ON (s.uuid)",
            "CREATE INDEX campaign_uuid IF NOT EXISTS FOR (c:Campaign) ON (c.uuid)",
            "CREATE INDEX cvssv2_uuid IF NOT EXISTS FOR (n:CVSSv2) ON (n.uuid)",
            "CREATE INDEX cvssv30_uuid IF NOT EXISTS FOR (n:CVSSv30) ON (n.uuid)",
            "CREATE INDEX cvssv31_uuid IF NOT EXISTS FOR (n:CVSSv31) ON (n.uuid)",
            "CREATE INDEX cvssv40_uuid IF NOT EXISTS FOR (n:CVSSv40) ON (n.uuid)",
            # Topology uuid indexes — added 2026-04 round 7 to close the gap that the
            # 8 ResilMesh topology merge_* functions weren't stamping n.uuid (audit
            # finding after PR #33 round 6).
            "CREATE INDEX ip_uuid IF NOT EXISTS FOR (i:IP) ON (i.uuid)",
            "CREATE INDEX host_uuid IF NOT EXISTS FOR (h:Host) ON (h.uuid)",
            "CREATE INDEX device_uuid IF NOT EXISTS FOR (d:Device) ON (d.uuid)",
            "CREATE INDEX subnet_uuid IF NOT EXISTS FOR (s:Subnet) ON (s.uuid)",
            "CREATE INDEX networkservice_uuid IF NOT EXISTS FOR (n:NetworkService) ON (n.uuid)",
            "CREATE INDEX softwareversion_uuid IF NOT EXISTS FOR (sv:SoftwareVersion) ON (sv.uuid)",
            "CREATE INDEX application_uuid IF NOT EXISTS FOR (a:Application) ON (a.uuid)",
            "CREATE INDEX role_uuid IF NOT EXISTS FOR (r:Role) ON (r.uuid)",
            # PR #34 round 23: User + Alert uuid indexes — close the
            # delta-sync coverage gap. Both labels now stamp n.uuid in their
            # respective MERGE sites (merge_resilmesh_user, create_alert_node).
            "CREATE INDEX user_uuid IF NOT EXISTS FOR (u:User) ON (u.uuid)",
            "CREATE INDEX alert_uuid IF NOT EXISTS FOR (a:Alert) ON (a.uuid)",
        ]

        success_count = 0
        error_count = 0

        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index, timeout=NEO4J_READ_TIMEOUT)
                    logger.info(f"Index created: {index[:40]}...")
                    success_count += 1
                except neo4j_exceptions.DatabaseError as e:
                    logger.debug(f"Index (may exist): {e}")
                    success_count += 1
                except (
                    neo4j_exceptions.ServiceUnavailable,
                    neo4j_exceptions.TransientError,
                    ConnectionError,
                    TimeoutError,
                ):
                    raise  # let @retry_with_backoff handle transient errors
                except Exception as e:
                    logger.warning(f"Index error: {e}")
                    error_count += 1

        logger.info(f"Indexes: {success_count} succeeded, {error_count} failed")
        return success_count, error_count

    @retry_with_backoff(max_retries=3)
    def ensure_sources(self) -> bool:
        """
        Ensure all Source nodes exist.

        Returns:
            True if successful
        """
        if not self.driver:
            logger.error("Cannot ensure sources: no connection")
            return False

        try:
            with self.driver.session() as session:
                for source_id, info in SOURCES.items():
                    # Deterministic Source uuid — referenced by SOURCED_FROM edges'
                    # trg_uuid stamping in merge_indicators_batch / merge_vulnerabilities_batch.
                    source_uuid = compute_node_uuid("Source", {"source_id": source_id})
                    query = """
                    MERGE (s:Source {source_id: $source_id})
                    ON CREATE SET s.created_at = datetime(),
                                  s.uuid = $source_uuid
                    SET s.name = $name,
                        s.type = $type,
                        s.reliability = $reliability,
                        s.updated_at = datetime(),
                        s.uuid = coalesce(s.uuid, $source_uuid)
                    """
                    session.run(
                        query,
                        source_id=source_id,
                        source_uuid=source_uuid,
                        name=info["name"],
                        type=info["type"],
                        reliability=info["reliability"],
                        timeout=NEO4J_READ_TIMEOUT,
                    )

            logger.info(f"Ensured {len(SOURCES)} Source nodes exist")
            return True

        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error ensuring sources: {e}")
            return False

    @retry_with_backoff(max_retries=3)
    def apply_sector_labels(self) -> int:
        """
        Apply secondary sector labels (e.g. :Finance, :Healthcare) to all nodes that
        carry a non-'global' zone value.  Labels are derived from the node's ``zone``
        list property and are applied with APOC so the label name is dynamic.

        This must be called *after* nodes have been merged so that the ``zone``
        property is already present.

        Returns:
            Number of nodes that received at least one new sector label.
        """
        if not self.driver:
            logger.error("Cannot apply sector labels: no connection")
            return 0

        # Scope to EdgeGuard-managed node labels only — avoids a full-graph scan
        # (`MATCH (n)`) and prevents accidentally labelling nodes from other
        # applications that share the same Neo4j instance.
        edgeguard_labels = [
            "Indicator",
            "Vulnerability",
            "Malware",
            "ThreatActor",
            "Technique",
            "Tactic",
            "Campaign",
            "Tool",
            "Source",
            "CVE",
        ]
        per_label_query = """
        MATCH (n:{label})
        WHERE n.zone IS NOT NULL AND size(n.zone) > 0
        WITH n, [z IN n.zone WHERE z <> 'global' | apoc.text.capitalize(z)] AS sectorLabels
        WHERE size(sectorLabels) > 0
        CALL apoc.create.addLabels(n, sectorLabels) YIELD node
        RETURN count(DISTINCT node) AS labeled
        """

        total_labeled = 0
        try:
            with self.driver.session() as session:
                for lbl in edgeguard_labels:
                    _validate_label(lbl)
                    result = session.run(per_label_query.format(label=lbl), timeout=NEO4J_READ_TIMEOUT)
                    record = result.single()
                    total_labeled += record["labeled"] if record else 0
            logger.info(f"Applied sector labels to {total_labeled} nodes")
            return total_labeled
        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error applying sector labels: {e}")
            return 0

    def merge_node_with_source(
        self, label: str, key_props: Dict, data: Dict, source_id: str, extra_props: Dict = None
    ) -> bool:
        """
        Merge a node with proper source tracking.

        Args:
            label: Node label (e.g., 'Indicator', 'Vulnerability')
            key_props: Dict of key properties for MERGE
            data: Dict of all properties to store
            source_id: The source providing this data
            extra_props: Additional properties to set on the node (beyond standard fields)

        Returns:
            True if successful
        """
        if not self.driver:
            logger.error("Cannot merge node: no connection")
            return False

        try:
            # Validate property names before interpolating into Cypher.
            for k in key_props:
                _validate_prop_name(k)
            # Build key property assignments
            key_set = ", ".join([f"{k}: ${k}" for k in key_props.keys()])

            # Serialize raw data to JSON string for storage
            raw_data = {k: v for k, v in data.items() if k not in key_props}

            # Get source as array (like zone)
            source_array = data.get("source", [source_id])
            if isinstance(source_array, str):
                source_array = [source_array]

            # Include original_source if present in the data
            original_source = data.get("original_source")
            if original_source:
                raw_data["original_source"] = original_source

            raw_data_json = json.dumps(raw_data, default=str)

            confidence = data.get("confidence_score", 0.5)
            zone = data.get("zone", ["global"])  # zone is an array
            # Accumulate tag into tags array (tag removed from MERGE key)
            tag_value = data.get("tag", source_id)
            tag_array = [tag_value] if tag_value else [source_id]

            _validate_label(label)

            # Deterministic per-node UUID — uuid5(namespace, canonical(label, key_props)).
            # Stable across machines and Neo4j instances so the cloud copy of a
            # local Indicator has the same n.uuid; edges carry src_uuid/trg_uuid
            # that resolve correctly cross-environment. Computed here from the
            # actual MERGE key (not the label's documented natural key) so the
            # uuid always matches what the Cypher MERGE binds to.
            node_uuid = compute_node_uuid(label, key_props)

            # PR #34 round 24: apply "specifics-override-global" at accumulation
            # time — see _zone_override_global_clause for full rationale.
            _zone_clause = _zone_override_global_clause("n", "$zone")
            # PR (S5): source-truthful timestamps — same MIN/MAX CASE pattern
            # used by the Indicator/Vulnerability batch paths. Pulled from
            # data.get("first_seen_at_source") which parse_attribute populated
            # via the allowlist-gated extractor. NULL never overwrites a
            # populated value; earliest first / latest last wins.
            first_seen_at_source = data.get("first_seen_at_source")
            last_seen_at_source = data.get("last_seen_at_source")
            query = f"""
            MERGE (n:{label} {{{key_set}}})
            ON CREATE SET n.first_imported_at = datetime(),
                          n.uuid = $node_uuid,
                          n.first_seen_at_source = $first_seen_at_source,
                          n.last_seen_at_source = $last_seen_at_source

            // Always accumulate sources and zones — provenance is never overwritten.
            // Use APOC to deduplicate the merged arrays in one step.
            SET n.confidence_score = CASE
                    WHEN n.confidence_score IS NULL OR $confidence > n.confidence_score
                    THEN $confidence
                    ELSE n.confidence_score END,
                n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_array),
                {_zone_clause},
                n.tags = apoc.coll.toSet(coalesce(n.tags, []) + $tag_array),
                n.tag = coalesce(n.tag, $tag_value),
                n.last_updated = datetime(),
                n.last_imported_from = $source_id,
                n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END,
                n.edgeguard_managed = true,
                // n.uuid is deterministic — coalesce so we never overwrite it.
                // (Defensive only; same input always produces same uuid, but if a
                // node was created before this code was deployed it will get the
                // uuid stamped here on next MERGE.)
                n.uuid = coalesce(n.uuid, $node_uuid),
                // PR (S5): source-truthful timestamps — MIN for first, MAX for last.
                // NULL never overwrites a populated value (defended at the AND clause).
                n.first_seen_at_source = CASE
                    WHEN $first_seen_at_source IS NOT NULL
                     AND (n.first_seen_at_source IS NULL OR $first_seen_at_source < n.first_seen_at_source)
                    THEN $first_seen_at_source
                    ELSE n.first_seen_at_source END,
                n.last_seen_at_source = CASE
                    WHEN $last_seen_at_source IS NOT NULL
                     AND (n.last_seen_at_source IS NULL OR $last_seen_at_source > n.last_seen_at_source)
                    THEN $last_seen_at_source
                    ELSE n.last_seen_at_source END
            """

            # PR #33 round 10: dropped legacy scalars misp_event_id / misp_attribute_id
            # (pre-release, no real data to migrate). Multi-event provenance lives only
            # in the misp_event_ids[] / misp_attribute_ids[] arrays, accumulated
            # via apoc.coll.toSet so duplicates within an array are de-duped.
            misp_event_id = data.get("misp_event_id")
            if misp_event_id:
                query += """,
                n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + [$misp_event_id])"""

            misp_attribute_id = data.get("misp_attribute_id")
            if misp_attribute_id:
                query += """,
                n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + [$misp_attribute_id])"""

            # PR #34 round 17: deleted ``n.original_published_date`` and
            # ``n.original_modified_date`` SET clauses. They were intended to
            # capture the upstream NVD ``published`` / ``last_modified`` dates,
            # but every non-NVD path (CISA KEV, OTX, MISP-event-only) silently
            # fell back to the MISP event date — making the field name lie
            # ("original" really means "first-seen-by-EdgeGuard"). The
            # canonical EdgeGuard first-touch / last-modified values already
            # live in ``first_imported_at`` (precise timestamp + TZ) and
            # ``last_updated``. Zero readers in production: no GraphQL field,
            # no STIX export, no Cypher consumer, no doc reference.

            # PR #34 round 18: deleted ``n.original_source`` SET clause +
            # the matching index. The Neo4j property had ZERO production
            # readers (no GraphQL field, no STIX export, no Cypher
            # MATCH/WHERE). The Python helper that EXTRACTS original_source
            # from MISP tags is alive (line 847 above) — it's stored on the
            # SOURCED_FROM edge's r.raw_data JSON for audit trail, and the
            # extraction in misp_collector derives the canonical `source`
            # field. Only the dead n.original_source write is removed.

            # Add extra_props (aliases, description, etc.) if provided.
            # Validate every property name before interpolating into Cypher.
            # Array properties that should ACCUMULATE (deduplicated) across sources,
            # not overwrite. Scalar properties are set with last-write-wins.
            _ARRAY_ACCUMULATE_PROPS = frozenset(
                {
                    "aliases",
                    "malware_types",
                    "uses_techniques",
                    "tactic_phases",
                }
            )
            extra_props = extra_props or {}
            params_extra = {}
            for prop_name, prop_value in extra_props.items():
                _validate_prop_name(prop_name)
                if prop_value is not None and prop_value != "":
                    if prop_name in _ARRAY_ACCUMULATE_PROPS and isinstance(prop_value, list):
                        query += f", n.{prop_name} = apoc.coll.toSet(coalesce(n.{prop_name}, []) + ${prop_name})"
                    else:
                        query += f", n.{prop_name} = ${prop_name}"
                    params_extra[prop_name] = prop_value

            if params_extra:
                key_str = ", ".join(f"{k}={v}" for k, v in key_props.items())
                logger.debug(
                    "MERGE %s(%s): promoting %s to node properties",
                    label,
                    key_str,
                    list(params_extra.keys()),
                )

            # Check existing confidence before update for audit logging
            check_query = f"""
            MATCH (n:{label} {{{key_set}}})
            RETURN n.confidence_score as existing_confidence, n.source as existing_source, n.retired_at as retired_at
            """

            with self.driver.session() as session:
                # Check existing values for audit
                existing = session.run(check_query, **{k: v for k, v in key_props.items()}, timeout=NEO4J_READ_TIMEOUT)
                existing_record = existing.single()

                if existing_record:
                    existing_conf = existing_record.get("existing_confidence")
                    existing_src = existing_record.get("existing_source")
                    key_str = ", ".join(f"{k}={v}" for k, v in key_props.items())
                    if existing_conf is not None and confidence < existing_conf:
                        logger.info(
                            f"AUDIT: Skipping lower-confidence update for {label}({key_str}): "
                            f"existing={existing_conf} (source={existing_src}), new={confidence} (source={source_id})"
                        )
                    # Log when a retired node is re-imported but kept inactive
                    existing_retired = existing_record.get("retired_at")
                    if existing_retired is not None:
                        logger.warning(
                            f"AUDIT: Re-imported retired node {label}({key_str}): "
                            f"active flag preserved (retired_at={existing_retired}), source={source_id}"
                        )

                # Execute the merge
                params = {
                    **key_props,
                    "source_id": source_id,
                    "source_array": source_array,
                    "confidence": confidence,
                    "zone": zone,
                    "tag_array": tag_array,
                    "tag_value": tag_value,
                    "node_uuid": node_uuid,
                    # PR (S5): source-truthful timestamps; bind even when None
                    # so the Cypher CASE clauses can compare against them.
                    # NULL never overwrites a populated value (CASE guards).
                    "first_seen_at_source": first_seen_at_source,
                    "last_seen_at_source": last_seen_at_source,
                    **params_extra,
                }
                if misp_event_id:
                    params["misp_event_id"] = misp_event_id
                if misp_attribute_id:
                    params["misp_attribute_id"] = misp_attribute_id
                if original_source:
                    params["original_source"] = original_source
                # PR #34 round 17 historical context: removed the lossy
                # ``first_seen`` / ``last_seen_val`` params along with the
                # NVD-specific ``original_published_date``/``original_modified_date``
                # SET clauses. PR (S5) reintroduces SOURCE-TRUTHFUL
                # timestamps as separate, allowlist-gated fields
                # (``first_seen_at_source`` / ``last_seen_at_source``)
                # bound above, so the previous semantic-conflation bug
                # doesn't return.
                session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)

            # Now create/update the SOURCED_FROM relationship with raw data
            return self._upsert_sourced_relationship(label, key_props, source_id, raw_data_json, confidence)

        except Exception as e:
            logger.error(f"Error merging node {label}: {e}")
            return False

    @retry_with_backoff(max_retries=3)
    def _upsert_sourced_relationship(
        self, label: str, key_props: Dict, source_id: str, raw_data_json: str, confidence: float
    ) -> bool:
        """
        Create or update SOURCED_FROM relationship with raw data on the edge.

        Returns:
            True if successful
        """
        if not self.driver:
            return False

        _validate_label(label)
        for k in key_props:
            _validate_prop_name(k)
        key_conditions = " AND ".join([f"n.{k} = ${k}" for k in key_props.keys()])

        # Endpoint uuids — same canonicalization as the actual node MERGEs, so
        # r.src_uuid/r.trg_uuid resolve back to (label, key_props) and (Source, source_id).
        src_uuid, trg_uuid = edge_endpoint_uuids(label, key_props, "Source", {"source_id": source_id})

        query = f"""
        MATCH (n:{label})
        WHERE {key_conditions}
        MATCH (s:Source {{source_id: $source_id}})
        MERGE (n)-[r:SOURCED_FROM]->(s)
        ON CREATE SET r.imported_at = datetime(),
            r.raw_data = $raw_data,
            r.src_uuid = $src_uuid,
            r.trg_uuid = $trg_uuid
        SET r.confidence = $confidence,
            r.source = $source_id,
            r.updated_at = datetime(),
            r.edgeguard_managed = true,
            r.src_uuid = coalesce(r.src_uuid, $src_uuid),
            r.trg_uuid = coalesce(r.trg_uuid, $trg_uuid)
        """

        try:
            with self.driver.session() as session:
                params = {
                    **key_props,
                    "source_id": source_id,
                    "raw_data": raw_data_json,
                    "confidence": confidence,
                    "src_uuid": src_uuid,
                    "trg_uuid": trg_uuid,
                }
                session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
            return True
        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.warning(f"SOURCED_FROM relationship error: {e}")
            return False

    def merge_vulnerability(self, data: Dict, source_id: str = "nvd") -> bool:
        """MERGE a Vulnerability node with source tracking."""
        cve_id = resolve_vulnerability_cve_id(data)
        if not cve_id:
            logger.warning(
                "merge_vulnerability: missing resolvable cve_id (expected cve_id or type=vulnerability with value)"
            )
            return False
        data = dict(data)
        data["cve_id"] = cve_id
        key_props = {"cve_id": cve_id}
        extra_props: Dict[str, Any] = {}
        if data.get("description"):
            extra_props["description"] = data["description"]
        if data.get("cvss_score") is not None:
            extra_props["cvss_score"] = data["cvss_score"]
        if data.get("severity"):
            extra_props["severity"] = data["severity"]
        if data.get("attack_vector"):
            extra_props["attack_vector"] = data["attack_vector"]
        return self.merge_node_with_source("Vulnerability", key_props, data, source_id, extra_props=extra_props or None)

    def merge_indicator(self, data: Dict, source_id: str = "alienvault_otx") -> bool:
        """MERGE an Indicator node with source tracking.

        PR #37 commit X (bugbot HIGH): the natural-key value is canonicalized
        via ``canonicalize_merge_key`` BEFORE the MERGE, matching the
        treatment in ``merge_indicators_batch`` and ``merge_malware``/
        ``merge_actor``. Without this, indicators arriving through the
        single-item path (VirusTotal enrichment, STIX pipeline import,
        ``_sync_single_item`` fallback) retained original casing in the
        Cypher MERGE while UUID was computed case-insensitively → two
        Neo4j nodes sharing ONE uuid. The audit-driven batch fix was
        applied in PR #37 commit 3 but the single-item path was missed
        — bugbot caught it.
        """
        key_props = canonicalize_merge_key(
            "Indicator",
            {
                "indicator_type": data.get("indicator_type"),
                "value": data.get("value"),
            },
        )
        # Promote enrichment fields to queryable node properties
        extra_props: Dict = {}
        if data.get("attack_ids"):
            extra_props["attack_ids"] = data["attack_ids"]
        if data.get("targeted_countries"):
            extra_props["targeted_countries"] = data["targeted_countries"]
        if data.get("malware_family"):
            extra_props["malware_family"] = data["malware_family"]
        if data.get("malware_malpedia"):
            extra_props["malware_malpedia"] = data["malware_malpedia"]
        if data.get("reference"):
            extra_props["reference"] = data["reference"]
        if data.get("reporter"):
            extra_props["reporter"] = data["reporter"]
        if data.get("domain"):
            extra_props["domain"] = data["domain"]
        if data.get("hostnames"):
            extra_props["hostnames"] = data["hostnames"]
        return self.merge_node_with_source("Indicator", key_props, data, source_id, extra_props=extra_props or None)

    def merge_cve(self, data: Dict, source_id: str = "nvd") -> bool:
        """
        MERGE a CVE node with source tracking, then create CVSS sub-nodes.

        After merging the CVE, creates CVSS sub-nodes (v4.0 / v3.1 / v3.0 / v2) when
        ``cvss_v40_data`` / ``cvss_v31_data`` / ``cvss_v30_data`` / ``cvss_v2_data`` are present,
        with matching ``HAS_CVSS_*`` relationships (ResilMesh schema).
        """
        cve_id = resolve_vulnerability_cve_id(data)
        if not cve_id:
            logger.warning("merge_cve: missing resolvable cve_id (expected cve_id or type=vulnerability with value)")
            return False
        data = dict(data)
        data["cve_id"] = cve_id
        key_props = {"cve_id": cve_id}

        # Promote CISA KEV fields to queryable node properties so analysts
        # can filter on e.g. "all CVEs on the CISA KEV list".
        #
        # PR #34 round 18: deleted ``reference_urls`` from extra_props.
        # The NVD collector parses up to 10 advisory URLs per CVE and
        # forwards them here, but ZERO consumers downstream
        # (no GraphQL field, no STIX export, no Cypher query). Same
        # dead-write pattern as round-17's ``original_*_date`` cleanup.
        extra_props: Dict = {}
        if data.get("cisa_exploit_add"):
            extra_props["cisa_exploit_add"] = data["cisa_exploit_add"]
        if data.get("cisa_action_due"):
            extra_props["cisa_action_due"] = data["cisa_action_due"]
        if data.get("cisa_required_action"):
            extra_props["cisa_required_action"] = data["cisa_required_action"]
        if data.get("cisa_vulnerability_name"):
            extra_props["cisa_vulnerability_name"] = data["cisa_vulnerability_name"]
        if data.get("description"):
            extra_props["description"] = data["description"]
        if data.get("cvss_score") is not None:
            extra_props["cvss_score"] = data["cvss_score"]
        if data.get("severity"):
            extra_props["severity"] = data["severity"]
        if data.get("attack_vector"):
            extra_props["attack_vector"] = data["attack_vector"]

        ok = self.merge_node_with_source("CVE", key_props, data, source_id, extra_props=extra_props or None)
        if not ok:
            return False
        # Create CVSS sub-nodes (ResilMesh schema)
        tag = data.get("tag", "default")
        if data.get("cvss_v40_data"):
            self._merge_cvss_node(cve_id, tag, "CVSSv40", "HAS_CVSS_v40", data["cvss_v40_data"])
        if data.get("cvss_v31_data"):
            self._merge_cvss_node(cve_id, tag, "CVSSv31", "HAS_CVSS_v31", data["cvss_v31_data"])
        if data.get("cvss_v30_data"):
            self._merge_cvss_node(cve_id, tag, "CVSSv30", "HAS_CVSS_v30", data["cvss_v30_data"])
        if data.get("cvss_v2_data"):
            self._merge_cvss_node(cve_id, tag, "CVSSv2", "HAS_CVSS_v2", data["cvss_v2_data"])
        return True

    def _merge_cvss_node(self, cve_id: str, tag: str, label: str, rel_type: str, cvss_data: Dict) -> bool:
        """
        MERGE a CVSS sub-node (v2 / v3.0 / v3.1 / v4.0) and link it to its parent CVE.

        Implements the ResilMesh schema, e.g.:
          [CVE]-[:HAS_CVSS_v31]->[CVSSv31 {...}]
          [CVE]-[:HAS_CVSS_v30]->[CVSSv30 {...}]
          [CVE]-[:HAS_CVSS_v2]->[CVSSv2 {...}]

        Both HAS_CVSS_v* edges are stamped with src_uuid/trg_uuid (the CVE's
        and the CVSS sub-node's deterministic uuids) for cross-environment
        traceability and self-describing edge serialization.
        """
        if not self.driver or not cve_id:
            return False
        try:
            _validate_label(label)
            _validate_rel_type(rel_type)

            # Build SET clause dynamically from the cvss_data dict.
            # Filter out None/empty values to avoid setting properties to NULL.
            filtered_cvss = {k: v for k, v in cvss_data.items() if v is not None and v != ""}
            prop_assignments = []
            for k in filtered_cvss:
                _validate_prop_name(k)
                prop_assignments.append(f"n.{k} = ${k}")
            set_clause = ", ".join(prop_assignments) if prop_assignments else "n.created = true"

            cve_uuid = compute_node_uuid("CVE", {"cve_id": cve_id})
            cvss_uuid = compute_node_uuid(label, {"cve_id": cve_id})

            query = f"""
            MATCH (cve:CVE {{cve_id: $cve_id}})
            MERGE (n:{label} {{cve_id: $cve_id}})
            ON CREATE SET n.uuid = $cvss_uuid
            SET {set_clause},
                n.tag = coalesce(n.tag, $tag),
                n.last_updated = datetime(),
                n.edgeguard_managed = true,
                n.uuid = coalesce(n.uuid, $cvss_uuid)
            MERGE (cve)-[r1:{rel_type}]->(n)
                ON CREATE SET r1.src_uuid = $cve_uuid, r1.trg_uuid = $cvss_uuid
            SET r1.src_uuid = coalesce(r1.src_uuid, $cve_uuid),
                r1.trg_uuid = coalesce(r1.trg_uuid, $cvss_uuid)
            MERGE (n)-[r2:{rel_type}]->(cve)
                ON CREATE SET r2.src_uuid = $cvss_uuid, r2.trg_uuid = $cve_uuid
            SET r2.src_uuid = coalesce(r2.src_uuid, $cvss_uuid),
                r2.trg_uuid = coalesce(r2.trg_uuid, $cve_uuid)
            """
            # NB (PR #33 round 8, bugbot MED): spread filtered_cvss FIRST so the
            # explicit cve_uuid / cvss_uuid / cve_id / tag entries below always
            # win on key collision. If cvss_data ever contained a key named
            # ``cve_uuid`` or ``cvss_uuid`` (passes _validate_prop_name), a
            # later spread would silently overwrite the computed deterministic
            # uuids with attribute data.
            params = {
                **filtered_cvss,
                "cve_id": cve_id,
                "tag": tag,
                "cve_uuid": cve_uuid,
                "cvss_uuid": cvss_uuid,
            }
            dropped = len(cvss_data) - len(filtered_cvss)
            with self.driver.session() as session:
                session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
            logger.debug(
                "%s node merged for CVE %s (%s properties set, %s null/empty filtered)",
                label,
                cve_id,
                len(filtered_cvss),
                dropped,
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to merge {label} for CVE {cve_id}: {e}")
            return False

    def merge_malware(self, data: Dict, source_id: str = "alienvault_otx") -> bool:
        """MERGE a Malware node with source tracking.

        PR #37 (Logic Tracker Tier S): the natural-key ``name`` is now
        lowercase + NFC + stripped via ``canonicalize_merge_key`` BEFORE
        the MERGE. Without this, ``Malware{name:"TrickBot"}`` (OTX) and
        ``Malware{name:"trickbot"}`` (CyberCure) became two distinct
        nodes that shared the SAME ``n.uuid`` (UUID computation already
        lowercases its hash input — see node_identity.py:340 — so the
        original Cypher-side case-sensitive MERGE was the only thing
        creating duplicates). Operators who relied on display case can
        recover the variant strings from ``n.aliases[]``.
        """
        key_props = canonicalize_merge_key("Malware", {"name": data.get("name")})
        # Store malware types and aliases on the node for easier querying
        malware_types = data.get("malware_types", [])
        aliases = data.get("aliases", [])
        # MITRE ATT&CK STIX ``uses`` edges (technique IDs), via collector + MISP MITRE_USES_TECHNIQUES comment
        uses_techniques = data.get("uses_techniques", [])

        extra_props: Dict[str, Any] = {
            "malware_types": malware_types,
            "aliases": aliases,
            "uses_techniques": uses_techniques,
        }
        if data.get("description"):
            extra_props["description"] = data["description"]
        return self.merge_node_with_source("Malware", key_props, data, source_id, extra_props=extra_props)

    def merge_actor(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a ThreatActor node with source tracking.

        PR #37: same ``canonicalize_merge_key`` treatment as ``merge_malware``
        — actor names like "APT29"/"apt29"/"Apt29" all merge into a single
        canonical lowercase node. Display-case variants are still
        recoverable via ``n.aliases[]``. (Note: this does NOT solve the
        actor-rename problem — e.g. APT29 → Cozy Bear → Midnight Blizzard
        — that's Tier A A1 and needs an alias-graph resolution pass,
        not just casing.)
        """
        key_props = canonicalize_merge_key("ThreatActor", {"name": data.get("name")})
        aliases = data.get("aliases", [])
        description = data.get("description", "")
        # uses_techniques: list of MITRE technique IDs this actor explicitly uses,
        # extracted from the ATT&CK STIX relationships bundle by the MITRE collector.
        uses_techniques = data.get("uses_techniques", [])

        extra_props: Dict[str, Any] = {
            "aliases": aliases,
            "description": description,
            "uses_techniques": uses_techniques,
        }
        if data.get("sophistication"):
            extra_props["sophistication"] = data["sophistication"]
        if data.get("primary_motivation"):
            extra_props["primary_motivation"] = data["primary_motivation"]
        if data.get("resource_level"):
            extra_props["resource_level"] = data["resource_level"]
        return self.merge_node_with_source("ThreatActor", key_props, data, source_id, extra_props=extra_props)

    def merge_technique(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a Technique node with source tracking."""
        key_props = {
            "mitre_id": data.get("mitre_id"),
        }
        extra_props: Dict[str, Any] = {"tactic_phases": data.get("tactic_phases", [])}
        extra_props["detection"] = data.get("detection", "")
        extra_props["is_subtechnique"] = data.get("is_subtechnique", False)
        if data.get("name"):
            extra_props["name"] = data["name"]
        if data.get("description"):
            extra_props["description"] = data["description"]
        return self.merge_node_with_source("Technique", key_props, data, source_id, extra_props=extra_props)

    def merge_tactic(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a Tactic node with source tracking."""
        key_props = {
            "mitre_id": data.get("mitre_id"),
        }
        extra_props: Dict[str, Any] = {"shortname": data.get("shortname", "")}
        if data.get("name"):
            extra_props["name"] = data["name"]
        if data.get("description"):
            extra_props["description"] = data["description"]
        return self.merge_node_with_source("Tactic", key_props, data, source_id, extra_props=extra_props)

    def merge_tool(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a Tool node with source tracking."""
        key_props = {
            "mitre_id": data.get("mitre_id"),
        }
        extra_props: Dict[str, Any] = {}
        if data.get("uses_techniques"):
            extra_props["uses_techniques"] = data["uses_techniques"]
        if data.get("tool_types"):
            extra_props["tool_types"] = data["tool_types"]
        if data.get("name"):
            extra_props["name"] = data["name"]
        if data.get("description"):
            extra_props["description"] = data["description"]
        if data.get("aliases"):
            extra_props["aliases"] = data["aliases"]
        return self.merge_node_with_source("Tool", key_props, data, source_id, extra_props=extra_props)

    @retry_with_backoff(max_retries=3)
    def mark_inactive_nodes(self, active_event_ids: List[str]) -> Dict[str, int]:
        """
        Mark nodes as inactive if NONE of their MISP event IDs are in the active list,
        and re-activate nodes whose events re-enter the active list.

        A node is considered active if ANY event in its ``misp_event_ids[]`` array is
        currently active. PR #33 round 10 dropped the legacy ``misp_event_id`` scalar
        — provenance lives only in the array now.

        Both Indicators and Vulnerabilities get the symmetric pair:

        - re-activation gate (``any(eid IN n.misp_event_ids WHERE eid IN $active_ids)``)
          — sets ``active = true`` unless ``retired_at`` indicates manual decommission.
        - deactivation gate (``none(eid IN n.misp_event_ids WHERE eid IN $active_ids)``)
          — sets ``active = false``.

        Nodes without any MISP event reference are not affected.

        Args:
            active_event_ids: List of event IDs that are currently active in MISP

        Returns:
            Dict with counts of marked inactive nodes by label
        """
        if not self.driver:
            logger.error("Cannot mark inactive nodes: no connection")
            return {}

        if not active_event_ids:
            logger.warning("No active event IDs provided, skipping inactive marking")
            return {}

        results = {}

        try:
            # Convert to set for efficient lookup
            active_ids_set = set(str(eid) for eid in active_event_ids)

            # Re-activate Indicators where ANY of their MISP event IDs is currently active.
            # ``retired_at`` (manual decommission) wins over the auto-active reset.
            query_indicators = """
            MATCH (n:Indicator)
            WITH n, [eid IN coalesce(n.misp_event_ids, []) WHERE eid IS NOT NULL AND eid <> ''] AS event_ids
            WHERE size(event_ids) > 0 AND any(eid IN event_ids WHERE eid IN $active_ids)
            SET n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END
            """

            query_indicators_inactive = """
            MATCH (n:Indicator)
            WITH n, [eid IN coalesce(n.misp_event_ids, []) WHERE eid IS NOT NULL AND eid <> ''] AS event_ids
            WHERE size(event_ids) > 0 AND none(eid IN event_ids WHERE eid IN $active_ids)
            SET n.active = false
            RETURN count(n) as count
            """

            # Re-activate Vulnerabilities where ANY of their MISP event IDs is active.
            # Mirrors query_indicators above so a Vulnerability that was marked inactive
            # gets re-activated when its events re-enter the active list.
            # ``retired_at`` (manual decommission) wins over the auto-active reset.
            query_vulnerabilities = """
            MATCH (n:Vulnerability)
            WITH n, [eid IN coalesce(n.misp_event_ids, []) WHERE eid IS NOT NULL AND eid <> ''] AS event_ids
            WHERE size(event_ids) > 0 AND any(eid IN event_ids WHERE eid IN $active_ids)
            SET n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END
            """

            # Mark inactive Vulnerabilities — same any-of / none-of semantics.
            query_vulnerabilities_inactive = """
            MATCH (n:Vulnerability)
            WITH n, [eid IN coalesce(n.misp_event_ids, []) WHERE eid IS NOT NULL AND eid <> ''] AS event_ids
            WHERE size(event_ids) > 0 AND none(eid IN event_ids WHERE eid IN $active_ids)
            SET n.active = false
            RETURN count(n) as count
            """

            with self.driver.session() as session:
                # First, mark all nodes with ANY active MISP event ID as active.
                # Indicators and Vulnerabilities both get the re-activation pass so a
                # node previously flipped inactive comes back when its events do.
                session.run(query_indicators, active_ids=list(active_ids_set), timeout=NEO4J_READ_TIMEOUT)
                session.run(query_vulnerabilities, active_ids=list(active_ids_set), timeout=NEO4J_READ_TIMEOUT)

                # Mark inactive Indicators
                result = session.run(
                    query_indicators_inactive, active_ids=list(active_ids_set), timeout=NEO4J_READ_TIMEOUT
                )
                record = result.single()
                results["indicators_marked_inactive"] = record["count"] if record else 0

                # Mark inactive Vulnerabilities
                result = session.run(
                    query_vulnerabilities_inactive, active_ids=list(active_ids_set), timeout=NEO4J_READ_TIMEOUT
                )
                record = result.single()
                results["vulnerabilities_marked_inactive"] = record["count"] if record else 0

            total_inactive = sum(results.values())
            logger.info(f"Marked {total_inactive} nodes as inactive (not in {len(active_ids_set)} active MISP events)")
            logger.info(f"   - Indicators: {results.get('indicators_marked_inactive', 0)}")
            logger.info(f"   - Vulnerabilities: {results.get('vulnerabilities_marked_inactive', 0)}")

            return results

        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except Exception as e:
            logger.error(f"Error marking inactive nodes: {e}")
            return {}

    def merge_indicators_batch(self, items: List[Dict], source_id: str = "misp") -> Tuple[int, int]:
        """
        Batch merge indicators using UNWIND for better performance.

        Args:
            items: List of indicator dicts
            source_id: Source identifier

        Returns:
            Tuple of (success_count, error_count)
        """
        if not self.driver or not items:
            return 0, len(items) if items else 0

        success_count = 0
        error_count = 0

        # The Source node uuid is the same for every row in this batch — compute
        # once and pass as a query-level param. Used for r.trg_uuid on the
        # SOURCED_FROM edge created by the inner Cypher.
        source_node_uuid = compute_node_uuid("Source", {"source_id": source_id})

        # Process in batches
        for i in range(0, len(items), BATCH_SIZE):
            batch = items[i : i + BATCH_SIZE]

            try:
                # Prepare batch data with zone information
                batch_data = []
                for item in batch:
                    raw_data = {k: v for k, v in item.items() if k not in ["indicator_type", "value", "tag"]}
                    # Extract zone from item (always a list — defensive coercion)
                    zone = item.get("zone", ["global"])
                    if isinstance(zone, str):
                        zone = [zone] if zone else ["global"]
                    # Extract source as array (like zone)
                    source_list = item.get("source", [source_id])
                    if isinstance(source_list, str):
                        source_list = [source_list]
                    tag = item.get("tag", "default")

                    # PR #37 (Logic Tracker Tier S): canonicalize the merge-key
                    # value via ``canonicalize_merge_key`` BEFORE both UUID
                    # computation and the Cypher MERGE. Without this, an
                    # Indicator with ``value="Conti"`` (one feed) and
                    # ``value="conti"`` (another feed) collided on uuid (UUID
                    # is computed case-insensitively at node_identity.py:340)
                    # but landed as TWO Cypher nodes (MERGE matches case-
                    # sensitively). Canonicalization is per-type — IPs/hashes/
                    # domains lowercased; URLs/emails/file-paths left as-is
                    # (case is meaningful there). See node_identity.py
                    # ``canonicalize_merge_key`` for the full rules.
                    # PR #37 commit X (bugbot LOW): import is hoisted to
                    # module level (line 36) so it doesn't re-resolve
                    # once per item in this hot batch loop.
                    canonical_key = canonicalize_merge_key(
                        "Indicator",
                        {"indicator_type": item.get("indicator_type"), "value": item.get("value")},
                    )
                    canonical_value = canonical_key.get("value")

                    # Per-row Indicator uuid — same uuid will be computed by every
                    # other process MERGEing the same (indicator_type, value), so
                    # cloud copy / delta-sync resolves correctly. Computed from
                    # the CANONICAL value so the uuid + the MERGE key agree
                    # (otherwise we'd silently re-introduce the duplicate-uuid
                    # state that caused the bug).
                    node_uuid = compute_node_uuid(
                        "Indicator",
                        {"indicator_type": item.get("indicator_type"), "value": canonical_value},
                    )

                    batch_item = {
                        "indicator_type": item.get("indicator_type"),
                        "value": canonical_value,
                        "tag": tag,
                        "source_id": source_id,
                        "source_array": source_list,
                        "confidence": item.get("confidence_score", 0.5),
                        "zone": zone,
                        "raw_data": json.dumps(raw_data, default=str),
                        "node_uuid": node_uuid,
                        # PR (S5): source-truthful timestamps — see
                        # source_truthful_timestamps.py for the per-source
                        # allowlist. NULL when source is unreliable; the
                        # MERGE Cypher's MIN/MAX CASE clauses preserve any
                        # existing value rather than overwriting with NULL.
                        "first_seen_at_source": item.get("first_seen_at_source"),
                        "last_seen_at_source": item.get("last_seen_at_source"),
                    }

                    # PR #34 round 17 historical context: dropped the old
                    # first_seen / last_seen pass-through (along with the
                    # NVD-specific original_published_date / original_modified_date
                    # SET clauses) because non-NVD paths silently fell back
                    # to MISP event date. Canonical EdgeGuard times live in
                    # first_imported_at + last_updated. PR (S5) reintroduces
                    # the SOURCE-TRUTHFUL timestamps as separate, allowlist-
                    # gated fields (first_seen_at_source / last_seen_at_source)
                    # so the previous semantic-conflation bug doesn't return.

                    # Add MISP IDs if present
                    if item.get("misp_event_id"):
                        batch_item["misp_event_id"] = item.get("misp_event_id")
                    if item.get("misp_attribute_id"):
                        batch_item["misp_attribute_id"] = item.get("misp_attribute_id")

                    # New enrichment fields (stored as-is if present, None-safe)
                    if item.get("indicator_role"):
                        batch_item["indicator_role"] = item["indicator_role"]
                    if item.get("url_status"):
                        batch_item["url_status"] = item["url_status"]
                    if item.get("last_online"):
                        batch_item["last_online"] = item["last_online"]
                    if item.get("abuse_categories"):
                        batch_item["abuse_categories"] = item["abuse_categories"]
                    if item.get("yara_rules"):
                        batch_item["yara_rules"] = item["yara_rules"]
                    if item.get("sigma_rules"):
                        batch_item["sigma_rules"] = item["sigma_rules"]
                    if item.get("threat_label"):
                        batch_item["threat_label"] = item["threat_label"]

                    batch_data.append(batch_item)

                # PR #34 round 24: zone-accumulation now applies the
                # specifics-override-global rule on write — see
                # _zone_override_global_clause for rationale.
                _zone_clause = _zone_override_global_clause("n", "item.zone")
                # PR (S5): two new properties — `n.first_seen_at_source` and
                # `n.last_seen_at_source`. Both nullable; populated only when
                # parse_attribute extracted a value via the reliable-source
                # allowlist (NVD/CISA/MITRE/VT/AbuseIPDB/ThreatFox/URLhaus/
                # Feodo/SSL Blacklist). Merge logic uses MIN for first / MAX
                # for last so out-of-order arrivals (incremental writes
                # before baseline backfill, or vice versa) settle on the
                # canonical earliest+latest world observation. NULL never
                # overwrites a real value.
                query = f"""
                UNWIND $batch as item
                MERGE (n:Indicator {{indicator_type: item.indicator_type, value: item.value}})
                ON CREATE SET n.first_imported_at = datetime(),
                              n.uuid = item.node_uuid,
                              n.first_seen_at_source = item.first_seen_at_source,
                              n.last_seen_at_source = item.last_seen_at_source
                SET n.confidence_score = CASE
                        WHEN n.confidence_score IS NULL OR item.confidence > n.confidence_score
                        THEN item.confidence
                        ELSE n.confidence_score END,
                    n.source = apoc.coll.toSet(coalesce(n.source, []) + item.source_array),
                    {_zone_clause},
                    n.tags = apoc.coll.toSet(coalesce(n.tags, []) + [item.tag]),
                    n.last_updated = datetime(),
                    n.last_imported_from = item.source_id,
                    n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END,
                    n.edgeguard_managed = true,
                    n.uuid = coalesce(n.uuid, item.node_uuid),
                    n.first_seen_at_source = CASE
                        WHEN item.first_seen_at_source IS NOT NULL
                         AND (n.first_seen_at_source IS NULL OR item.first_seen_at_source < n.first_seen_at_source)
                        THEN item.first_seen_at_source
                        ELSE n.first_seen_at_source END,
                    n.last_seen_at_source = CASE
                        WHEN item.last_seen_at_source IS NOT NULL
                         AND (n.last_seen_at_source IS NULL OR item.last_seen_at_source > n.last_seen_at_source)
                        THEN item.last_seen_at_source
                        ELSE n.last_seen_at_source END,
                    n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + CASE WHEN item.misp_event_id IS NOT NULL THEN [item.misp_event_id] ELSE [] END),
                    n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + CASE WHEN item.misp_attribute_id IS NOT NULL THEN [item.misp_attribute_id] ELSE [] END),
                    n.indicator_role = coalesce(item.indicator_role, n.indicator_role),
                    n.url_status = coalesce(item.url_status, n.url_status),
                    n.last_online = coalesce(item.last_online, n.last_online),
                    n.abuse_categories = apoc.coll.toSet(coalesce(n.abuse_categories, []) + coalesce(item.abuse_categories, [])),
                    n.yara_rules = apoc.coll.toSet(coalesce(n.yara_rules, []) + coalesce(item.yara_rules, [])),
                    n.sigma_rules = apoc.coll.toSet(coalesce(n.sigma_rules, []) + coalesce(item.sigma_rules, [])),
                    n.threat_label = coalesce(item.threat_label, n.threat_label)
                WITH n, item
                MATCH (s:Source {{source_id: item.source_id}})
                MERGE (n)-[r:SOURCED_FROM]->(s)
                ON CREATE SET r.imported_at = datetime(),
                    r.raw_data = item.raw_data,
                    r.src_uuid = item.node_uuid,
                    r.trg_uuid = $source_node_uuid
                SET r.confidence = item.confidence,
                    r.source = item.source_id,
                    r.updated_at = datetime(),
                    r.edgeguard_managed = true,
                    r.src_uuid = coalesce(r.src_uuid, item.node_uuid),
                    r.trg_uuid = coalesce(r.trg_uuid, $source_node_uuid)
                """

                with self.driver.session() as session:
                    session.run(
                        query,
                        batch=batch_data,
                        source_node_uuid=source_node_uuid,
                        timeout=NEO4J_READ_TIMEOUT,
                    )

                success_count += len(batch)
                logger.debug(f"Batch merged {len(batch)} indicators")

            except Exception as e:
                logger.error(f"Batch merge error: {e}")
                error_count += len(batch)

        return success_count, error_count

    def merge_vulnerabilities_batch(self, items: List[Dict], source_id: str = "misp") -> Tuple[int, int]:
        """
        Batch merge vulnerabilities using UNWIND for better performance.

        Args:
            items: List of vulnerability dicts
            source_id: Source identifier

        Returns:
            Tuple of (success_count, error_count)
        """
        if not self.driver or not items:
            return 0, len(items) if items else 0

        success_count = 0
        error_count = 0

        # Source node uuid is stable for the whole batch — see merge_indicators_batch.
        source_node_uuid = compute_node_uuid("Source", {"source_id": source_id})

        for i in range(0, len(items), BATCH_SIZE):
            batch = items[i : i + BATCH_SIZE]

            try:
                batch_data = []
                skipped = 0
                for item in batch:
                    cve_id = resolve_vulnerability_cve_id(item)
                    if not cve_id:
                        logger.warning(
                            "Skipping vulnerability batch item: no resolvable cve_id (misp_event_id=%s, type=%s)",
                            item.get("misp_event_id"),
                            item.get("type"),
                        )
                        skipped += 1
                        continue

                    raw_data = {k: v for k, v in item.items() if k not in ["cve_id", "tag"]}
                    # Extract zone from item (always a list — defensive coercion)
                    zone = item.get("zone", ["global"])
                    if isinstance(zone, str):
                        zone = [zone] if zone else ["global"]
                    # Extract source as array (like zone)
                    source_list = item.get("source", [source_id])
                    if isinstance(source_list, str):
                        source_list = [source_list]

                    # Per-row Vulnerability uuid; same logic as Indicator batch.
                    node_uuid = compute_node_uuid("Vulnerability", {"cve_id": cve_id})

                    batch_item = {
                        "cve_id": cve_id,
                        "tag": item.get("tag", "default"),
                        "source_id": source_id,
                        "source_array": source_list,
                        "confidence": item.get("confidence_score", 0.5),
                        "zone": zone,
                        "raw_data": json.dumps(raw_data, default=str),
                        "node_uuid": node_uuid,
                        # PR (S5): source-truthful timestamps; see indicator
                        # batch above for the rationale + per-source allowlist.
                        "first_seen_at_source": item.get("first_seen_at_source"),
                        "last_seen_at_source": item.get("last_seen_at_source"),
                    }

                    # Add MISP IDs if present
                    if item.get("misp_event_id"):
                        batch_item["misp_event_id"] = item.get("misp_event_id")
                    if item.get("misp_attribute_id"):
                        batch_item["misp_attribute_id"] = item.get("misp_attribute_id")
                    # ResilMesh requires status (LIST OF STRING)
                    batch_item["status"] = item.get("status", ["active"])

                    # NVD / CISA enrichment fields
                    if item.get("version_constraints"):
                        batch_item["version_constraints"] = json.dumps(item["version_constraints"], default=str)
                    if item.get("cisa_cwes"):
                        batch_item["cisa_cwes"] = item["cisa_cwes"]
                    if item.get("cisa_notes"):
                        batch_item["cisa_notes"] = item["cisa_notes"]

                    batch_data.append(batch_item)

                if not batch_data:
                    error_count += skipped
                    continue

                # PR #34 round 24: zone-accumulation applies the
                # specifics-override-global rule on write.
                _zone_clause = _zone_override_global_clause("n", "item.zone")
                # PR (S5): source-truthful first/last_seen via MIN/MAX CASE
                # — same pattern as merge_indicators_batch above. NULL never
                # overwrites a populated value; the earliest first_seen and
                # latest last_seen win across re-imports + multi-source merges.
                query = f"""
                UNWIND $batch as item
                MERGE (n:Vulnerability {{cve_id: item.cve_id}})
                ON CREATE SET n.first_imported_at = datetime(),
                    n.status = item.status,
                    n.uuid = item.node_uuid,
                    n.first_seen_at_source = item.first_seen_at_source,
                    n.last_seen_at_source = item.last_seen_at_source
                SET n.confidence_score = CASE
                        WHEN n.confidence_score IS NULL OR item.confidence > n.confidence_score
                        THEN item.confidence
                        ELSE n.confidence_score END,
                    n.source = apoc.coll.toSet(coalesce(n.source, []) + item.source_array),
                    {_zone_clause},
                    n.tags = apoc.coll.toSet(coalesce(n.tags, []) + [item.tag]),
                    n.tag = coalesce(n.tag, item.tag),
                    n.last_updated = datetime(),
                    n.last_imported_from = item.source_id,
                    n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END,
                    n.edgeguard_managed = true,
                    n.uuid = coalesce(n.uuid, item.node_uuid),
                    n.first_seen_at_source = CASE
                        WHEN item.first_seen_at_source IS NOT NULL
                         AND (n.first_seen_at_source IS NULL OR item.first_seen_at_source < n.first_seen_at_source)
                        THEN item.first_seen_at_source
                        ELSE n.first_seen_at_source END,
                    n.last_seen_at_source = CASE
                        WHEN item.last_seen_at_source IS NOT NULL
                         AND (n.last_seen_at_source IS NULL OR item.last_seen_at_source > n.last_seen_at_source)
                        THEN item.last_seen_at_source
                        ELSE n.last_seen_at_source END,
                    n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + CASE WHEN item.misp_event_id IS NOT NULL THEN [item.misp_event_id] ELSE [] END),
                    n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + CASE WHEN item.misp_attribute_id IS NOT NULL THEN [item.misp_attribute_id] ELSE [] END),
                    n.version_constraints = coalesce(item.version_constraints, n.version_constraints),
                    n.cisa_cwes = apoc.coll.toSet(coalesce(n.cisa_cwes, []) + coalesce(item.cisa_cwes, [])),
                    n.cisa_notes = coalesce(item.cisa_notes, n.cisa_notes)
                WITH n, item
                MATCH (s:Source {{source_id: item.source_id}})
                MERGE (n)-[r:SOURCED_FROM]->(s)
                ON CREATE SET r.imported_at = datetime(),
                    r.raw_data = item.raw_data,
                    r.src_uuid = item.node_uuid,
                    r.trg_uuid = $source_node_uuid
                SET r.confidence = item.confidence,
                    r.source = item.source_id,
                    r.updated_at = datetime(),
                    r.edgeguard_managed = true,
                    r.src_uuid = coalesce(r.src_uuid, item.node_uuid),
                    r.trg_uuid = coalesce(r.trg_uuid, $source_node_uuid)
                """

                with self.driver.session() as session:
                    session.run(
                        query,
                        batch=batch_data,
                        source_node_uuid=source_node_uuid,
                        timeout=NEO4J_READ_TIMEOUT,
                    )

                success_count += len(batch_data)
                error_count += skipped

            except Exception as e:
                logger.error(f"Batch vulnerability merge error: {e}")
                error_count += len(batch)

        return success_count, error_count

    def link_to_source(self, node_label: str, node_key: Dict, source_id: str) -> bool:
        """Create SOURCED_FROM relationship to Source node."""
        if not self.driver:
            return False

        _validate_label(node_label)
        for k in node_key:
            _validate_prop_name(k)
        key_conditions = " AND ".join([f"n.{k} = ${k}" for k in node_key.keys()])

        query = f"""
        MATCH (n:{node_label})
        WHERE {key_conditions}
        MATCH (s:Source {{source_id: $source_id}})
        MERGE (n)-[r:SOURCED_FROM]->(s)
        SET r.imported_at = datetime(), r.updated_at = datetime()
        """

        try:
            with self.driver.session() as session:
                params = {**node_key, "source_id": source_id}
                session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
            return True
        except Exception as e:
            logger.warning(f"Link to source failed: {e}")
            return False

    def create_actor_technique_relationship(
        self, actor_name: str, technique_mitre_id: str, source_id: str = "mitre_attck"
    ) -> bool:
        """Create EMPLOYS_TECHNIQUE relationship: ThreatActor -> Technique.

        Matches actors by name or alias and techniques by mitre_id, cross-source
        (no tag filter) so that enrichment links work regardless of which collector
        ingested each node.

        Semantic note: ``EMPLOYS_TECHNIQUE`` is the attribution edge ("who uses
        this TTP"), distinct from ``IMPLEMENTS_TECHNIQUE`` (the capability edge
        on Malware/Tool). Split from a previously-generic ``USES`` in the
        2026-04 refactor to improve GraphRAG retrieval and Cypher clarity.
        """
        if not self.driver:
            return False

        an = nonempty_graph_string(actor_name)
        tid = nonempty_graph_string(technique_mitre_id)
        if not an or not tid:
            logger.debug("Skipping actor↔technique link: missing actor name or technique id")
            return False

        logger.debug(f"Creating actor-technique relationship: {an} -> {tid}")

        query = """
        MATCH (a:ThreatActor)
        WHERE a.name = $actor_name OR $actor_name IN coalesce(a.aliases, [])
        MATCH (t:Technique {mitre_id: $technique_mitre_id})
        MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.7,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, a.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, t.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    actor_name=an,
                    technique_mitre_id=tid,
                    source_id=source_id,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                logger.debug(f"Actor-technique relationship created: {an} -> {tid}")
            return True
        except Exception as e:
            logger.warning(f"Actor-technique relationship error: {e}")
            return False

    def create_malware_actor_relationship(
        self, malware_name: str, actor_name: str, source_id: str = "mitre_attck"
    ) -> bool:
        """Create ATTRIBUTED_TO relationship: Malware -> ThreatActor.

        Matches by name or alias, cross-source (no tag filter).
        Each OR group is wrapped in parentheses to avoid the Cypher operator
        precedence bug where AND binds tighter than OR, which previously
        caused incorrect Cartesian matches.
        """
        if not self.driver:
            return False

        mn = nonempty_graph_string(malware_name)
        an = nonempty_graph_string(actor_name)
        if not mn or not an:
            logger.debug("Skipping malware↔actor link: missing malware or actor name")
            return False

        logger.debug(f"Creating malware-actor relationship: {mn} -> {an}")

        query = """
        MATCH (m:Malware)
        WHERE (m.name = $malware_name OR $malware_name IN coalesce(m.aliases, []))
        MATCH (a:ThreatActor)
        WHERE (a.name = $actor_name OR $actor_name IN coalesce(a.aliases, []))
        MERGE (m)-[r:ATTRIBUTED_TO]->(a)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.7,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, m.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, a.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    malware_name=mn,
                    actor_name=an,
                    source_id=source_id,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                logger.debug(f"Malware-actor relationship created: {mn} -> {an}")
            return True
        except Exception as e:
            logger.warning(f"Malware-actor relationship error: {e}")
            return False

    def create_indicator_vulnerability_relationship(
        self, indicator_value: str, cve_id: str, source_id: str = "misp"
    ) -> bool:
        """Create INDICATES/EXPLOITS relationship: Indicator -> Vulnerability or CVE.

        Matches the Indicator by value (any type) and links to both Vulnerability
        and CVE nodes (NVD-rich items are stored under the CVE label), cross-source.
        """
        if not self.driver:
            return False

        ind = nonempty_graph_string(indicator_value)
        cve = normalize_cve_id_for_graph(cve_id)
        if not ind or not cve:
            logger.debug("Skipping indicator↔vulnerability link: missing normalized indicator value or CVE id")
            return False

        logger.debug(f"Creating indicator-vulnerability relationship: {ind} -> {cve}")

        # Link to Vulnerability nodes (MISP-sourced)
        query_vuln = """
        MATCH (i:Indicator {value: $value})
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (i)-[r:INDICATES]->(v)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """
        # Link to CVE nodes (NVD-sourced, ResilMesh schema)
        query_cve = """
        MATCH (i:Indicator {value: $value})
        MATCH (v:CVE {cve_id: $cve_id})
        MERGE (i)-[r:INDICATES]->(v)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query_vuln, value=ind, cve_id=cve, source_id=source_id, timeout=NEO4J_READ_TIMEOUT)
                session.run(query_cve, value=ind, cve_id=cve, source_id=source_id, timeout=NEO4J_READ_TIMEOUT)
                logger.debug(f"Indicator-vulnerability relationship created: {ind} -> {cve}")
            return True
        except Exception as e:
            logger.warning(f"Indicator-vulnerability relationship error: {e}")
            return False

    def create_indicator_malware_relationship(
        self, indicator_value: str, malware_name: str, source_id: str = "misp"
    ) -> bool:
        """Create INDICATES relationship: Indicator -> Malware.

        Matches Malware by name or aliases, cross-source (no tag filter).
        """
        if not self.driver:
            return False

        iv = nonempty_graph_string(indicator_value)
        mn = nonempty_graph_string(malware_name)
        if not iv or not mn:
            logger.debug("Skipping indicator↔malware link: missing indicator value or malware name")
            return False

        logger.debug(f"Creating indicator-malware relationship: {iv} -> {mn}")

        query = """
        MATCH (i:Indicator {value: $indicator_value})
        MATCH (m:Malware)
        WHERE (m.name = $malware_name OR $malware_name IN coalesce(m.aliases, []))
        MERGE (i)-[r:INDICATES]->(m)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.6,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, m.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    indicator_value=iv,
                    malware_name=mn,
                    source_id=source_id,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                logger.debug(f"Indicator-malware relationship created: {iv} -> {mn}")
            return True
        except Exception as e:
            logger.warning(f"Indicator-malware relationship error: {e}")
            return False

    def create_indicator_sector_relationship(
        self, indicator_value: str, sector_name: str, source_id: str = "misp"
    ) -> bool:
        """Create TARGETS relationship: Indicator -> Sector."""
        if not self.driver:
            return False

        iv = nonempty_graph_string(indicator_value)
        sec = nonempty_graph_string(sector_name)
        if not iv or not sec:
            logger.debug("Skipping indicator↔sector link: missing indicator value or sector name")
            return False

        # First ensure the Sector node exists with its deterministic uuid stamped.
        # Pre-2026-04 the Sector creation here didn't stamp s.uuid — the
        # subsequent rel query's ``coalesce(r.trg_uuid, s.uuid)`` then read
        # NULL. Bugbot caught this on PR #33 round 5; same fix as 7a/7b in
        # build_relationships.py.
        sec_uuid = compute_node_uuid("Sector", {"name": sec})
        ensure_sector_query = """
        MERGE (s:Sector {name: $sector_name})
        ON CREATE SET s.created_at = datetime(),
                      s.uuid = $sector_uuid
        SET s.updated_at = datetime(),
            s.uuid = coalesce(s.uuid, $sector_uuid)
        """

        # Create the relationship
        rel_query = """
        MATCH (i:Indicator {value: $indicator_value})
        MATCH (s:Sector {name: $sector_name})
        MERGE (i)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """

        try:
            with self.driver.session() as session:
                session.run(
                    ensure_sector_query,
                    sector_name=sec,
                    sector_uuid=sec_uuid,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                session.run(
                    rel_query,
                    indicator_value=iv,
                    sector_name=sec,
                    source_id=source_id,
                    timeout=NEO4J_READ_TIMEOUT,
                )
            return True
        except Exception as e:
            logger.warning(f"Indicator-sector relationship error: {e}")
            return False

    def create_vulnerability_sector_relationship(self, cve_id: str, sector_name: str, source_id: str = "misp") -> bool:
        """Create AFFECTS relationship: Vulnerability/CVE -> Sector.

        PR #33 round 11 (bugbot LOW): edge type changed from TARGETS to
        AFFECTS to match the canonical schema (TARGETS reserved for
        Indicator → Sector; Vuln/CVE → Sector is AFFECTS — see
        build_relationships.py 7b query and ARCHITECTURE.md).

        Handles both label variants:
        - Vulnerability: items from MISP/non-NVD sources
        - CVE: items from NVD (stored via merge_cve for ResilMesh compatibility)
        """
        if not self.driver:
            return False

        cve = normalize_cve_id_for_graph(cve_id)
        sec = nonempty_graph_string(sector_name)
        if not cve or not sec:
            logger.debug("Skipping vulnerability↔sector link: missing normalized CVE id or sector name")
            return False

        # Same Sector uuid stamp as create_indicator_sector_relationship (round 5
        # bugbot fix) — pre-compute the deterministic uuid and stamp on Sector
        # creation so the rel query's ``coalesce(r.trg_uuid, s.uuid)`` reads a
        # populated value rather than NULL.
        sec_uuid = compute_node_uuid("Sector", {"name": sec})
        ensure_sector_query = """
        MERGE (s:Sector {name: $sector_name})
        ON CREATE SET s.created_at = datetime(),
                      s.uuid = $sector_uuid
        SET s.updated_at = datetime(),
            s.uuid = coalesce(s.uuid, $sector_uuid)
        """

        rel_props = """
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.source_id = $source_id,
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, v.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """

        # Vulnerability label (MISP/non-NVD) — AFFECTS per canonical schema.
        vuln_query = f"""
        MATCH (v:Vulnerability {{cve_id: $cve_id}})
        MATCH (s:Sector {{name: $sector_name}})
        MERGE (v)-[r:AFFECTS]->(s)
        {rel_props}
        """
        # CVE label (NVD — ResilMesh schema) — AFFECTS per canonical schema.
        cve_query = f"""
        MATCH (v:CVE {{cve_id: $cve_id}})
        MATCH (s:Sector {{name: $sector_name}})
        MERGE (v)-[r:AFFECTS]->(s)
        {rel_props}
        """

        try:
            with self.driver.session() as session:
                session.run(
                    ensure_sector_query,
                    sector_name=sec,
                    sector_uuid=sec_uuid,
                    timeout=NEO4J_READ_TIMEOUT,
                )
                session.run(vuln_query, cve_id=cve, sector_name=sec, source_id=source_id, timeout=NEO4J_READ_TIMEOUT)
                session.run(cve_query, cve_id=cve, sector_name=sec, source_id=source_id, timeout=NEO4J_READ_TIMEOUT)
            return True
        except Exception as e:
            logger.warning(f"Vulnerability-sector relationship error: {e}")
            return False

    def create_misp_relationships_batch(self, relationships: List[Dict], source_id: str = "misp") -> int:
        """
        Create MISP-derived relationships in bulk via UNWIND.

        Mirrors the semantics of ``create_actor_technique_relationship``,
        ``create_malware_actor_relationship``, ``create_indicator_malware_relationship``,
        ``create_indicator_sector_relationship``, ``create_vulnerability_sector_relationship``,
        and ``create_indicator_vulnerability_relationship`` (null/blank endpoints skipped).

        Unknown ``rel_type`` / shape combinations are skipped during row collection.
        Each UNWIND query runs in its own try/except so earlier groups still commit if a
        later group fails (returns sum of row counts for successful groups only).
        """
        if not self.driver or not relationships:
            return 0

        # Split from a previously-generic "USES" bucket in the 2026-04 refactor:
        # EMPLOYS_TECHNIQUE = attribution  (ThreatActor/Campaign → Technique)
        # IMPLEMENTS_TECHNIQUE = capability (Malware/Tool → Technique)
        # USES_TECHNIQUE already existed for Indicator → Technique (OTX attack_ids)
        #
        # EMPLOYS_TECHNIQUE rows are further split by from_type so each
        # UNWIND MATCH can hit a single label index. Without that split,
        # Campaign rows routed to a ThreatActor-only query silently matched
        # zero nodes while _run_rows still counted them as success.
        actor_employs_rows: List[Dict[str, Any]] = []
        campaign_employs_rows: List[Dict[str, Any]] = []
        implements_rows: List[Dict[str, Any]] = []
        attr_rows: List[Dict[str, Any]] = []
        ind_mal_rows: List[Dict[str, Any]] = []
        tgt_ind_rows: List[Dict[str, Any]] = []
        tgt_vuln_rows: List[Dict[str, Any]] = []
        expl_rows: List[Dict[str, Any]] = []

        _dropped_rels = 0
        for rel in relationships:
            rt = rel.get("rel_type")
            fk = rel.get("from_key") or {}
            tk = rel.get("to_key") or {}
            conf = rel.get("confidence", 0.5)
            # Originating MISP event id, stamped by parse_attribute /
            # _build_cross_item_relationships. Threaded into each row dict so the
            # Cypher MERGE can accumulate it on r.misp_event_ids[]. Empty/None →
            # the SET clause skips the array append (CASE expression).
            mev = str(rel.get("misp_event_id", "") or "")
            # NOTE: edge src_uuid / trg_uuid are NO LONGER pre-computed in the
            # dispatch loop. Each Cypher template SETs them directly from the
            # MATCHed node's bound-variable .uuid (Mechanism B), e.g. for
            # INDICATES: `r.src_uuid = coalesce(r.src_uuid, i.uuid)`. This
            # eliminates an entire class of bugs where the precomputed uuid
            # disagreed with the actual node uuid because the from_key dict
            # was incomplete (e.g. Indicator from_key missing indicator_type
            # → uuid computed from "" → wrong fallback uuid that doesn't
            # match the node's n.uuid). Bugbot caught this on PR #33 round 4.
            #
            # Backward-compat: accept legacy "USES" rel_type from callers that
            # haven't been migrated yet, and route based on from_type. New
            # code should emit the specialized rel_type directly.
            if rt in ("EMPLOYS_TECHNIQUE", "IMPLEMENTS_TECHNIQUE") or (
                rt == "USES" and rel.get("to_type") == "Technique"
            ):
                # Require an explicit from_type. The previous default of
                # "ThreatActor" silently misrouted any IMPLEMENTS_TECHNIQUE
                # caller that forgot to set it — their row went to the
                # actor bucket and never matched a Malware/Tool node,
                # while _run_rows still counted it as success. Drop the
                # row loudly instead, so a caller that omits from_type
                # sees it in the dropped-rel warning and fixes the call.
                from_type = rel.get("from_type")
                if from_type is None:
                    logger.warning(
                        "Dropping %s row with no from_type — specialized technique "
                        "rel_types must set from_type explicitly (ThreatActor, "
                        "Campaign, Malware, or Tool)",
                        rt,
                    )
                    _dropped_rels += 1
                    continue
                mid = nonempty_graph_string(tk.get("mitre_id"))
                if from_type == "ThreatActor":
                    an = nonempty_graph_string(fk.get("name"))
                    if an and mid:
                        actor_employs_rows.append(
                            {
                                "actor": an,
                                "mitre_id": mid,
                                "source_id": source_id,
                                "confidence": conf,
                                "misp_event_id": mev,
                            }
                        )
                    else:
                        _dropped_rels += 1
                elif from_type == "Campaign":
                    cn = nonempty_graph_string(fk.get("name"))
                    if cn and mid:
                        campaign_employs_rows.append(
                            {
                                "campaign": cn,
                                "mitre_id": mid,
                                "source_id": source_id,
                                "confidence": conf,
                                "misp_event_id": mev,
                            }
                        )
                    else:
                        _dropped_rels += 1
                elif from_type == "Malware":
                    # Malware natural key is `name` — used by the Cypher MATCH.
                    nm = nonempty_graph_string(fk.get("name"))
                    if nm and mid:
                        implements_rows.append(
                            {
                                "entity": nm,
                                "entity_label": "Malware",
                                "mitre_id": mid,
                                "source_id": source_id,
                                "confidence": conf,
                                "misp_event_id": mev,
                            }
                        )
                    else:
                        _dropped_rels += 1
                elif from_type == "Tool":
                    # Tool's natural key is `mitre_id` (UNIQUE constraint on Tool.mitre_id —
                    # see Neo4jClient.create_constraints). Producers send from_key as
                    # ``{"mitre_id": ...}`` — earlier shared-with-Malware code read
                    # fk.get("name") and silently dropped Tool rows. Now Tool routes
                    # through its own branch with the correct key, and the q_tool_implements
                    # Cypher MATCHes on tool.mitre_id (not tool.name) to match.
                    tool_mid = nonempty_graph_string(fk.get("mitre_id"))
                    if tool_mid and mid:
                        implements_rows.append(
                            {
                                "entity": tool_mid,
                                "entity_label": "Tool",
                                "mitre_id": mid,
                                "source_id": source_id,
                                "confidence": conf,
                                "misp_event_id": mev,
                            }
                        )
                    else:
                        _dropped_rels += 1
                else:
                    _dropped_rels += 1
            elif rt == "ATTRIBUTED_TO":
                mn = nonempty_graph_string(fk.get("name"))
                an = nonempty_graph_string(tk.get("name"))
                if mn and an:
                    attr_rows.append(
                        {
                            "malware": mn,
                            "actor": an,
                            "source_id": source_id,
                            "confidence": conf,
                            "misp_event_id": mev,
                        }
                    )
                else:
                    _dropped_rels += 1
            elif rt == "INDICATES" and rel.get("to_type") == "Malware":
                iv = nonempty_graph_string(fk.get("value"))
                mn = nonempty_graph_string(tk.get("name"))
                if iv and mn:
                    ind_mal_rows.append(
                        {
                            "value": iv,
                            "malware": mn,
                            "source_id": source_id,
                            "confidence": conf,
                            "misp_event_id": mev,
                        }
                    )
                else:
                    _dropped_rels += 1
            elif rt == "TARGETS":
                # Canonical: Indicator → Sector. PR #33 round 12 split the
                # Vulnerability→Sector path off into a separate ``AFFECTS``
                # branch (below) — TARGETS now exclusively means
                # Indicator → Sector.
                sec = nonempty_graph_string(tk.get("name"))
                if not sec:
                    _dropped_rels += 1
                    continue
                sec_uuid = compute_node_uuid("Sector", {"name": sec})
                ft = rel.get("from_type")
                if ft == "Indicator":
                    iv = nonempty_graph_string(fk.get("value"))
                    if iv:
                        tgt_ind_rows.append(
                            {
                                "value": iv,
                                "sector": sec,
                                "source_id": source_id,
                                "confidence": conf,
                                "misp_event_id": mev,
                                "sector_uuid": sec_uuid,
                            }
                        )
                    else:
                        _dropped_rels += 1
                else:
                    # TARGETS with non-Indicator from_type is now invalid (Vuln/CVE
                    # use AFFECTS, Tool→Sector is unsupported here).
                    logger.debug("Dropping TARGETS row with non-Indicator from_type=%s — use AFFECTS for Vuln/CVE", ft)
                    _dropped_rels += 1
            elif rt == "AFFECTS":
                # Canonical: Vulnerability/CVE → Sector. Replayed against BOTH
                # labels (q_aff_vuln + q_aff_cve) — Mechanism B uuids mean one
                # row dict serves both queries (each template reads its
                # MATCHed node's .uuid directly).
                sec = nonempty_graph_string(tk.get("name"))
                if not sec:
                    _dropped_rels += 1
                    continue
                sec_uuid = compute_node_uuid("Sector", {"name": sec})
                cid = normalize_cve_id_for_graph(fk.get("cve_id"))
                if cid:
                    tgt_vuln_rows.append(
                        {
                            "cve_id": cid,
                            "sector": sec,
                            "source_id": source_id,
                            "confidence": conf,
                            "misp_event_id": mev,
                            "sector_uuid": sec_uuid,
                        }
                    )
                else:
                    _dropped_rels += 1
            elif rt == "EXPLOITS":
                iv = nonempty_graph_string(fk.get("value"))
                cid = normalize_cve_id_for_graph(tk.get("cve_id"))
                if iv and cid:
                    # expl_rows replays against BOTH Vulnerability and CVE labels.
                    # Mechanism B (template reads i.uuid / v.uuid directly) means
                    # no per-label uuid precomputation needed.
                    expl_rows.append(
                        {
                            "value": iv,
                            "cve_id": cid,
                            "source_id": source_id,
                            "confidence": conf,
                            "misp_event_id": mev,
                        }
                    )
                else:
                    _dropped_rels += 1

        # PR #33 round 13: log the drop count UNCONDITIONALLY so the operator
        # can distinguish "0 drops" (healthy) from "we forgot to log" (silent).
        # WARNING when there are drops, INFO when there are none.
        if _dropped_rels:
            logger.warning(
                "Relationship batch: %s/%s definitions dropped (blank/missing endpoints)",
                _dropped_rels,
                len(relationships),
            )
        else:
            logger.info(
                "Relationship batch: 0/%s dropped (all definitions had non-blank endpoints)",
                len(relationships),
            )

        total = 0

        # Attribution edge: ThreatActor → Technique
        q_actor_employs = """
        UNWIND $rows AS row
        MATCH (a:ThreatActor)
        WHERE a.name = row.actor OR row.actor IN coalesce(a.aliases, [])
        MATCH (t:Technique {mitre_id: row.mitre_id})
        MERGE (a)-[r:EMPLOYS_TECHNIQUE]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, a.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, t.uuid)
        """
        # Attribution edge: Campaign → Technique. Separate from the
        # ThreatActor query so the planner hits a single label index.
        # (Merging both into one query via OR or UNION fragments the plan
        # and was the root cause of the silent 0-row bug caught by bugbot
        # on PR #24 — Campaign rows routed to a ThreatActor-only query.)
        q_campaign_employs = """
        UNWIND $rows AS row
        MATCH (c:Campaign)
        WHERE c.name = row.campaign OR row.campaign IN coalesce(c.aliases, [])
        MATCH (t:Technique {mitre_id: row.mitre_id})
        MERGE (c)-[r:EMPLOYS_TECHNIQUE]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, c.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, t.uuid)
        """
        # Capability edge: Malware or Tool → Technique. Single query handles
        # both labels via CALL ... apoc.do.case-style branching; we run one
        # UNWIND per from_type inside the caller so planner can use label
        # lookups efficiently (see _run_rows calls below).
        q_malware_implements = """
        UNWIND $rows AS row
        MATCH (m:Malware)
        WHERE (m.name = row.entity OR row.entity IN coalesce(m.aliases, []))
        MATCH (t:Technique {mitre_id: row.mitre_id})
        MERGE (m)-[r:IMPLEMENTS_TECHNIQUE]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, m.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, t.uuid)
        """
        # Tool's natural key (and UNIQUE constraint) is mitre_id, NOT name —
        # the dispatch loop above puts the Tool's mitre_id into row.entity for
        # this query. Aliases-based matching wouldn't apply here (Tool's
        # canonical id is the MITRE id). Pre-2026-04 this query MATCHed by
        # tool.name, which silently dropped every Tool row sent through this
        # path because parse_attribute correctly sends from_key={"mitre_id": …}.
        q_tool_implements = """
        UNWIND $rows AS row
        MATCH (tool:Tool {mitre_id: row.entity})
        MATCH (t:Technique {mitre_id: row.mitre_id})
        MERGE (tool)-[r:IMPLEMENTS_TECHNIQUE]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, tool.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, t.uuid)
        """
        q_attr = """
        UNWIND $rows AS row
        MATCH (m:Malware)
        WHERE (m.name = row.malware OR row.malware IN coalesce(m.aliases, []))
        MATCH (a:ThreatActor)
        WHERE (a.name = row.actor OR row.actor IN coalesce(a.aliases, []))
        MERGE (m)-[r:ATTRIBUTED_TO]->(a)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, m.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, a.uuid)
        """
        q_ind_mal = """
        UNWIND $rows AS row
        MATCH (i:Indicator {value: row.value})
        MATCH (m:Malware)
        WHERE (m.name = row.malware OR row.malware IN coalesce(m.aliases, []))
        MERGE (i)-[r:INDICATES]->(m)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, m.uuid)
        """
        q_tgt_ind = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime(),
                      s.uuid = row.sector_uuid
        SET s.updated_at = datetime(),
            s.uuid = coalesce(s.uuid, row.sector_uuid)
        WITH row, s
        MATCH (i:Indicator {value: row.value})
        MERGE (i)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """
        # PR #33 round 11 (bugbot LOW): Vulnerability/CVE → Sector edges use
        # AFFECTS, not TARGETS. TARGETS is reserved for Indicator → Sector
        # (see q_tgt_ind below + build_relationships.py 7a). Vuln/CVE → Sector
        # is AFFECTS (build_relationships.py 7b + ARCHITECTURE.md edges table).
        q_aff_vuln = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime(),
                      s.uuid = row.sector_uuid
        SET s.updated_at = datetime(),
            s.uuid = coalesce(s.uuid, row.sector_uuid)
        WITH row, s
        MATCH (v:Vulnerability {cve_id: row.cve_id})
        MERGE (v)-[r:AFFECTS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, v.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """
        q_aff_cve = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime(),
                      s.uuid = row.sector_uuid
        SET s.updated_at = datetime(),
            s.uuid = coalesce(s.uuid, row.sector_uuid)
        WITH row, s
        MATCH (v:CVE {cve_id: row.cve_id})
        MERGE (v)-[r:AFFECTS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, v.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """
        q_expl_vuln = """
        UNWIND $rows AS row
        MATCH (i:Indicator {value: row.value})
        MATCH (v:Vulnerability {cve_id: row.cve_id})
        MERGE (i)-[r:EXPLOITS]->(v)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.match_type = 'cve_tag',
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """
        q_expl_cve = """
        UNWIND $rows AS row
        MATCH (i:Indicator {value: row.value})
        MATCH (v:CVE {cve_id: row.cve_id})
        MERGE (i)-[r:EXPLOITS]->(v)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.match_type = 'cve_tag',
            r.misp_event_ids = apoc.coll.toSet(
                coalesce(r.misp_event_ids, []) +
                CASE WHEN row.misp_event_id IS NOT NULL AND row.misp_event_id <> ''
                     THEN [row.misp_event_id] ELSE [] END
            ),
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """

        def _run_rows(session: Any, label: str, query: str, rows: List[Dict[str, Any]]) -> None:
            nonlocal total
            if not rows:
                return
            try:
                session.run(query, rows=rows, timeout=_REL_QUERY_TIMEOUT)
                total += len(rows)
            except Exception as e:
                # Each UNWIND is auto-committed; do not zero the whole batch on one failure.
                logger.warning("MISP relationship batch %s failed (%s rows): %s", label, len(rows), e)

        with self.driver.session() as session:
            _run_rows(session, "EMPLOYS_TECHNIQUE_actor", q_actor_employs, actor_employs_rows)
            if actor_employs_rows:
                query_pause()
            _run_rows(session, "EMPLOYS_TECHNIQUE_campaign", q_campaign_employs, campaign_employs_rows)
            if campaign_employs_rows:
                query_pause()
            # Split IMPLEMENTS_TECHNIQUE rows by entity_label so each UNWIND
            # hits a single label index instead of a union scan.
            mal_impl_rows = [r for r in implements_rows if r.get("entity_label") == "Malware"]
            tool_impl_rows = [r for r in implements_rows if r.get("entity_label") == "Tool"]
            _run_rows(session, "IMPLEMENTS_TECHNIQUE_malware", q_malware_implements, mal_impl_rows)
            if mal_impl_rows:
                query_pause()
            _run_rows(session, "IMPLEMENTS_TECHNIQUE_tool", q_tool_implements, tool_impl_rows)
            if tool_impl_rows:
                query_pause()
            _run_rows(session, "ATTRIBUTED_TO", q_attr, attr_rows)
            if attr_rows:
                query_pause()
            _run_rows(session, "INDICATES_malware", q_ind_mal, ind_mal_rows)
            if ind_mal_rows:
                query_pause()
            _run_rows(session, "TARGETS_indicator", q_tgt_ind, tgt_ind_rows)
            if tgt_vuln_rows:
                # Same row payload replayed against two labels (Vulnerability + CVE).
                # No per-label uuid swap is needed anymore — each template's SET
                # reads its MATCHed node's bound .uuid directly (Mechanism B), so
                # the same row dict works for both queries.
                query_pause()
                _run_rows(session, "AFFECTS_vulnerability", q_aff_vuln, tgt_vuln_rows)
                query_pause()
                _run_rows(session, "AFFECTS_cve", q_aff_cve, tgt_vuln_rows)
            if expl_rows:
                # Same as TARGETS_vuln/cve — Mechanism B uuids mean one row dict
                # serves both EXPLOITS templates without any precomputed swap.
                query_pause()
                _run_rows(session, "EXPLOITS_vulnerability", q_expl_vuln, expl_rows)
                query_pause()
                _run_rows(session, "EXPLOITS_cve", q_expl_cve, expl_rows)

        return total

    def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics."""
        if not self.driver:
            return {"error": "No connection"}

        stats = {}

        try:
            with self.driver.session() as session:
                # Count nodes by type (labels must stay in _ALLOWED_NODE_LABELS)
                for label in [
                    "Vulnerability",
                    "Indicator",
                    "CVE",
                    "Malware",
                    "ThreatActor",
                    "Technique",
                    "Tactic",
                    "Campaign",
                    "Tool",
                    "Sector",
                    "CVSSv2",
                    "CVSSv30",
                    "CVSSv31",
                    "CVSSv40",
                    "Alert",
                ]:
                    try:
                        _validate_label(label)
                        result = session.run(f"MATCH (n:{label}) RETURN count(n) as count", timeout=NEO4J_READ_TIMEOUT)
                        record = result.single()
                        stats[label] = record["count"] if record else 0
                    except Exception as e:
                        logger.warning(f"Error counting {label}: {e}")
                        stats[label] = 0

                # Count Source nodes
                try:
                    result = session.run("MATCH (s:Source) RETURN count(s) as count", timeout=NEO4J_READ_TIMEOUT)
                    record = result.single()
                    stats["Sources"] = record["count"] if record else 0
                except Exception:
                    stats["Sources"] = 0

                # Count by source (now an array - use UNWIND)
                try:
                    result = session.run(
                        """
                        MATCH (n) 
                        WHERE n.source IS NOT NULL
                        UNWIND n.source AS s
                        RETURN s as source, count(DISTINCT n) as count
                        ORDER BY count DESC
                    """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    stats["by_source"] = {row["source"]: row["count"] for row in result}
                except Exception:
                    stats["by_source"] = {}

                # Count SOURCED_FROM relationships
                try:
                    result = session.run(
                        "MATCH ()-[r:SOURCED_FROM]->() RETURN count(r) as count", timeout=NEO4J_READ_TIMEOUT
                    )
                    record = result.single()
                    stats["sourced_relationships"] = record["count"] if record else 0
                except Exception:
                    stats["sourced_relationships"] = 0

                # Count by zone - properly handle arrays with UNWIND
                try:
                    result = session.run(
                        """
                        MATCH (n) 
                        WHERE n.zone IS NOT NULL
                        UNWIND n.zone AS z
                        RETURN z as zone, count(DISTINCT n) as count
                        ORDER BY count DESC
                    """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    stats["by_zone"] = {row["zone"]: row["count"] for row in result}
                except Exception:
                    stats["by_zone"] = {}

                # Count multi-zone nodes (appear in 2+ zones)
                try:
                    result = session.run(
                        """
                        MATCH (n)
                        WHERE n.zone IS NOT NULL AND size(n.zone) > 1
                        RETURN count(n) AS multi_zone_count
                    """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    record = result.single()
                    stats["multi_zone_count"] = record["multi_zone_count"] if record else 0
                except Exception:
                    stats["multi_zone_count"] = 0

                # Count active/inactive for Indicators and Vulnerabilities (only those
                # with at least one MISP event in misp_event_ids[]).
                try:
                    result = session.run(
                        """
                        MATCH (n:Indicator)
                        WHERE n.misp_event_ids IS NOT NULL AND size(n.misp_event_ids) > 0
                        RETURN n.active as active, count(n) as count
                    """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    stats["indicators_active"] = {str(row["active"]): row["count"] for row in result}
                except Exception:
                    stats["indicators_active"] = {}

                try:
                    result = session.run(
                        """
                        MATCH (n:Vulnerability)
                        WHERE n.misp_event_ids IS NOT NULL AND size(n.misp_event_ids) > 0
                        RETURN n.active as active, count(n) as count
                    """,
                        timeout=NEO4J_READ_TIMEOUT,
                    )
                    stats["vulnerabilities_active"] = {str(row["active"]): row["count"] for row in result}
                except Exception:
                    stats["vulnerabilities_active"] = {}

            return stats

        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {"error": str(e)}

    def get_node_with_sources(self, label: str, key_props: Dict) -> Optional[Dict]:
        """Get a node with all its raw source data from relationships."""
        if not self.driver:
            return None

        _validate_label(label)
        for k in key_props:
            _validate_prop_name(k)
        key_conditions = " AND ".join([f"n.{k} = ${k}" for k in key_props.keys()])

        query = f"""
        MATCH (n:{label})
        WHERE {key_conditions}
        OPTIONAL MATCH (n)-[r:SOURCED_FROM]->(s:Source)
        RETURN n, collect(DISTINCT s.source_id) as source_ids,
               collect({{source: s.source_id, raw_data: r.raw_data, confidence: r.confidence, imported_at: r.imported_at}}) as source_relationships
        """

        try:
            with self.driver.session() as session:
                result = session.run(query, **key_props, timeout=NEO4J_READ_TIMEOUT)
                record = result.single()
                if record:
                    node_data = dict(record["n"]._properties)
                    sources = []
                    for rel in record["source_relationships"]:
                        if rel.get("source"):
                            sources.append(
                                {
                                    "source": rel["source"],
                                    "confidence": rel.get("confidence"),
                                    "raw_data": json.loads(rel["raw_data"]) if rel.get("raw_data") else None,
                                    "imported_at": str(rel.get("imported_at")) if rel.get("imported_at") else None,
                                }
                            )
                    return {"node": node_data, "sources": sources}
        except Exception as e:
            logger.error(f"Error getting node with sources: {e}")

        return None

    def find_duplicates_by_source(self, label: str, value: str) -> Optional[Dict]:
        """Find same indicator/value from multiple sources with raw data comparison."""
        if not self.driver:
            return None

        _validate_label(label)
        query = f"""
        MATCH (n:{label} {{value: $value}})-[r:SOURCED_FROM]->(s:Source)
        RETURN n.value as value, s.source_id as source, r.raw_data as raw_data, 
               r.confidence as confidence, r.imported_at as imported_at
        """

        try:
            with self.driver.session() as session:
                result = session.run(query, value=value, timeout=NEO4J_READ_TIMEOUT)
                sources = []
                for record in result:
                    sources.append(
                        {
                            "source": record["source"],
                            "confidence": record["confidence"],
                            "raw_data": json.loads(record["raw_data"]) if record["raw_data"] else None,
                            "imported_at": str(record["imported_at"]) if record["imported_at"] else None,
                        }
                    )
                return {"value": value, "sources": sources}
        except Exception as e:
            logger.error(f"Error finding duplicates: {e}")
            return None

    def get_active_indicators(self, limit: int = 100, indicator_type: str = None) -> List[Dict]:
        """
        Get active indicators only (with active=true or no active property).

        Args:
            limit: Maximum number of results
            indicator_type: Optional filter by indicator type

        Returns:
            List of indicator nodes
        """
        if not self.driver:
            return []

        type_filter = "AND n.indicator_type = $indicator_type" if indicator_type else ""

        query = f"""
        MATCH (n:Indicator)
        WHERE (n.active = true OR n.active IS NULL)
          AND n.misp_event_ids IS NOT NULL AND size(n.misp_event_ids) > 0
        {type_filter}
        RETURN n
        LIMIT $limit
        """

        try:
            with self.driver.session() as session:
                params = {"limit": limit}
                if indicator_type:
                    params["indicator_type"] = indicator_type
                result = session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
                return [dict(record["n"]._properties) for record in result]
        except Exception as e:
            logger.error(f"Error getting active indicators: {e}")
            return []

    def get_active_vulnerabilities(self, limit: int = 100, min_cvss: float = None) -> List[Dict]:
        """
        Get active vulnerabilities only (with active=true or no active property).

        Args:
            limit: Maximum number of results
            min_cvss: Optional minimum CVSS score filter

        Returns:
            List of vulnerability nodes
        """
        if not self.driver:
            return []

        cvss_filter = "AND n.cvss_score >= $min_cvss" if min_cvss is not None else ""

        query = f"""
        MATCH (n:Vulnerability)
        WHERE (n.active = true OR n.active IS NULL)
          AND n.misp_event_ids IS NOT NULL AND size(n.misp_event_ids) > 0
        {cvss_filter}
        RETURN n
        ORDER BY n.cvss_score DESC
        LIMIT $limit
        """

        try:
            with self.driver.session() as session:
                params = {"limit": limit}
                if min_cvss is not None:
                    params["min_cvss"] = min_cvss
                result = session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
                return [dict(record["n"]._properties) for record in result]
        except Exception as e:
            logger.error(f"Error getting active vulnerabilities: {e}")
            return []

    def get_inactive_nodes(self, label: str = "Indicator", limit: int = 100) -> List[Dict]:
        """
        Get inactive nodes (marked as active=false).

        Args:
            label: Node label ('Indicator' or 'Vulnerability')
            limit: Maximum number of results

        Returns:
            List of inactive nodes
        """
        if not self.driver:
            return []

        _validate_label(label)
        query = f"""
        MATCH (n:{label})
        WHERE n.active = false
        RETURN n
        LIMIT $limit
        """

        try:
            with self.driver.session() as session:
                result = session.run(query, limit=limit, timeout=NEO4J_READ_TIMEOUT)
                return [dict(record["n"]._properties) for record in result]
        except Exception as e:
            logger.error(f"Error getting inactive {label} nodes: {e}")
            return []

    # ============================================================
    # RESILMESH SCHEMA - NODE MERGE METHODS
    # ============================================================

    def merge_ip(self, data: dict) -> bool:
        """MERGE an IP node. Properties: address, status, tag (LIST), version.

        ResilMesh spec: tag is LIST OF STRING identifying components that
        contributed data. We accumulate via apoc.coll.toSet so multiple
        sources are tracked.

        PR #37 (Bug Hunter Tier S A3): refuses to merge when ``address``
        is missing or empty. Without this guard, ``MERGE (i:IP
        {address: NULL})`` matches/creates a single sentinel node that
        every subsequent unknown-IP merge HIJACKS — silently folding
        all unknown-IP rows into one Neo4j node and breaking
        deduplication. Common trigger: ResilMesh/ISIM payload arriving
        from an incomplete CMDB sync. Same pattern fix as the existing
        ``merge_device`` validation.
        """
        address = data.get("address")
        if not address or (isinstance(address, str) and not address.strip()):
            logger.warning("merge_ip refused: missing or empty 'address' — skipping to avoid null-key collapse")
            return False
        # PR #33 follow-up: stamp deterministic IP n.uuid for cross-environment
        # traceability. Same compute_node_uuid pattern as the MISP-side mergers.
        ip_uuid = compute_node_uuid("IP", {"address": address})
        query = """
        MERGE (i:IP {address: $address})
        ON CREATE SET i.uuid = $ip_uuid
        SET i.status = $status,
            i.tag = apoc.coll.toSet(coalesce(i.tag, []) + $tag_list),
            i.version = $version,
            i.edgeguard_managed = true,
            i.first_seen = CASE WHEN i.first_seen IS NULL THEN datetime() ELSE i.first_seen END,
            i.last_updated = datetime(),
            i.uuid = coalesce(i.uuid, $ip_uuid)
        """
        try:
            # Normalise tag to a list for ResilMesh compatibility
            raw_tag = data.get("tag")
            tag_list = [raw_tag] if isinstance(raw_tag, str) else (raw_tag or [])
            with self.driver.session() as session:
                session.run(
                    query,
                    address=address,
                    ip_uuid=ip_uuid,
                    status=data.get("status"),
                    tag_list=tag_list,
                    version=data.get("version"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated IP: {address}")
            return True
        except Exception as e:
            logger.error(f"Error creating IP: {e}")
            return False

    def merge_host(self, data: dict) -> bool:
        """MERGE a Host node. Properties: hostname

        PR #37: refuses null/empty hostname to avoid the same null-key
        collapse described in ``merge_ip``.
        """
        hostname = data.get("hostname")
        if not hostname or (isinstance(hostname, str) and not hostname.strip()):
            logger.warning("merge_host refused: missing or empty 'hostname' — skipping to avoid null-key collapse")
            return False
        host_uuid = compute_node_uuid("Host", {"hostname": hostname})
        query = """
        MERGE (h:Host {hostname: $hostname})
        ON CREATE SET h.uuid = $host_uuid
        SET h.edgeguard_managed = true,
            h.first_seen = CASE WHEN h.first_seen IS NULL THEN datetime() ELSE h.first_seen END,
            h.last_updated = datetime(),
            h.uuid = coalesce(h.uuid, $host_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, host_uuid=host_uuid, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated Host: {hostname}")
            return True
        except Exception as e:
            logger.error(f"Error creating Host: {e}")
            return False

    def merge_device(self, data: dict) -> bool:
        """MERGE a Device node. Properties: device_id (required for deterministic uuid)."""
        # Bugbot (PR #33 round 8, MED): the previous fallback ``str(id(data))``
        # used Python's memory-address id() — non-deterministic across calls,
        # processes, and machines. compute_node_uuid would then hash an
        # ephemeral value, producing a different n.uuid every time the same
        # logical Device was MERGEd, silently violating the uuid contract.
        # Refuse the call instead of writing a poisoned node.
        device_id = data.get("device_id")
        if not device_id:
            logger.error(
                "merge_device: data missing required 'device_id' — cannot compute deterministic uuid; refusing"
            )
            return False
        device_uuid = compute_node_uuid("Device", {"device_id": device_id})
        query = """
        MERGE (d:Device {device_id: $device_id})
        ON CREATE SET d.uuid = $device_uuid
        SET d.edgeguard_managed = true,
            d.first_seen = CASE WHEN d.first_seen IS NULL THEN datetime() ELSE d.first_seen END,
            d.last_updated = datetime(),
            d.uuid = coalesce(d.uuid, $device_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=device_id, device_uuid=device_uuid, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated Device: {device_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating Device: {e}")
            return False

    def merge_subnet(self, data: dict) -> bool:
        """MERGE a Subnet node. Properties: range, note, version"""
        subnet_range = data.get("range")
        subnet_uuid = compute_node_uuid("Subnet", {"range": subnet_range})
        query = """
        MERGE (s:Subnet {range: $range})
        ON CREATE SET s.uuid = $subnet_uuid
        SET s.edgeguard_managed = true,
            s.note = $note,
            s.version = $version,
            s.first_seen = CASE WHEN s.first_seen IS NULL THEN datetime() ELSE s.first_seen END,
            s.last_updated = datetime(),
            s.uuid = coalesce(s.uuid, $subnet_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    range=subnet_range,
                    subnet_uuid=subnet_uuid,
                    note=data.get("note"),
                    version=data.get("version"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated Subnet: {subnet_range}")
            return True
        except Exception as e:
            logger.error(f"Error creating Subnet: {e}")
            return False

    def merge_networkservice(self, data: dict) -> bool:
        """MERGE a NetworkService node. Properties: port, protocol, service"""
        port = data.get("port")
        protocol = data.get("protocol")
        ns_uuid = compute_node_uuid("NetworkService", {"port": port, "protocol": protocol})
        query = """
        MERGE (ns:NetworkService {port: $port, protocol: $protocol})
        ON CREATE SET ns.uuid = $ns_uuid
        SET ns.edgeguard_managed = true,
            ns.service = $service,
            ns.first_seen = CASE WHEN ns.first_seen IS NULL THEN datetime() ELSE ns.first_seen END,
            ns.last_updated = datetime(),
            ns.uuid = coalesce(ns.uuid, $ns_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    port=port,
                    protocol=protocol,
                    ns_uuid=ns_uuid,
                    service=data.get("service"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated NetworkService: {port}/{protocol}")
            return True
        except Exception as e:
            logger.error(f"Error creating NetworkService: {e}")
            return False

    def merge_softwareversion(self, data: dict) -> bool:
        """MERGE a SoftwareVersion node. Properties: cve_timestamp, version"""
        version = data.get("version")
        sv_uuid = compute_node_uuid("SoftwareVersion", {"version": version})
        query = """
        MERGE (sv:SoftwareVersion {version: $version})
        ON CREATE SET sv.uuid = $sv_uuid
        SET sv.edgeguard_managed = true,
            sv.cve_timestamp = $cve_timestamp,
            sv.first_seen = CASE WHEN sv.first_seen IS NULL THEN datetime() ELSE sv.first_seen END,
            sv.last_updated = datetime(),
            sv.uuid = coalesce(sv.uuid, $sv_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    version=version,
                    sv_uuid=sv_uuid,
                    cve_timestamp=data.get("cve_timestamp"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated SoftwareVersion: {version}")
            return True
        except Exception as e:
            logger.error(f"Error creating SoftwareVersion: {e}")
            return False

    def merge_application(self, data: dict) -> bool:
        """MERGE an Application node. Properties: name"""
        name = data.get("name")
        app_uuid = compute_node_uuid("Application", {"name": name})
        query = """
        MERGE (a:Application {name: $name})
        ON CREATE SET a.uuid = $app_uuid
        SET a.edgeguard_managed = true,
            a.first_seen = CASE WHEN a.first_seen IS NULL THEN datetime() ELSE a.first_seen END,
            a.last_updated = datetime(),
            a.uuid = coalesce(a.uuid, $app_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=name, app_uuid=app_uuid, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated Application: {name}")
            return True
        except Exception as e:
            logger.error(f"Error creating Application: {e}")
            return False

    # PR #33 round 12: deleted the 4 standalone merge_cvssv2/30/31/40 (and
    # their create_cve_has_cvss_v* / create_cvssv*_has_cvssv*_cve helper
    # callers). They were vector_string-keyed and uuid-less — superseded by
    # the canonical _merge_cvss_node (called from merge_cve) which keys on
    # cve_id and stamps the deterministic uuid. Pre-release fresh-start has
    # no callers and no legacy data depending on the old path.

    def merge_role(self, data: dict) -> bool:
        """MERGE a Role node. Properties: permission"""
        permission = data.get("permission")
        role_uuid = compute_node_uuid("Role", {"permission": permission})
        query = """
        MERGE (r:Role {permission: $permission})
        ON CREATE SET r.uuid = $role_uuid
        SET r.edgeguard_managed = true,
            r.first_seen = CASE WHEN r.first_seen IS NULL THEN datetime() ELSE r.first_seen END,
            r.last_updated = datetime(),
            r.uuid = coalesce(r.uuid, $role_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=permission, role_uuid=role_uuid, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated Role: {permission}")
            return True
        except Exception as e:
            logger.error(f"Error creating Role: {e}")
            return False

    def merge_component(self, data: dict) -> bool:
        """MERGE a Component node. Properties: name"""
        query = """
        MERGE (c:Component {name: $name})
        SET c.edgeguard_managed = true,
            c.first_seen = CASE WHEN c.first_seen IS NULL THEN datetime() ELSE c.first_seen END,
            c.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=data.get("name"), timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated Component: {data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Component: {e}")
            return False

    def merge_mission(self, data: dict) -> bool:
        """MERGE a Mission node. Properties: criticality, structure, description, name"""
        query = """
        MERGE (m:Mission {name: $name})
        SET m.edgeguard_managed = true,
            m.criticality = $criticality,
            m.structure = $structure,
            m.description = $description,
            m.first_seen = CASE WHEN m.first_seen IS NULL THEN datetime() ELSE m.first_seen END,
            m.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    name=data.get("name"),
                    criticality=data.get("criticality"),
                    structure=data.get("structure"),
                    description=data.get("description"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated Mission: {data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Mission: {e}")
            return False

    def merge_organizationunit(self, data: dict) -> bool:
        """MERGE an OrganizationUnit node. Properties: name"""
        query = """
        MERGE (o:OrganizationUnit {name: $name})
        SET o.edgeguard_managed = true,
            o.first_seen = CASE WHEN o.first_seen IS NULL THEN datetime() ELSE o.first_seen END,
            o.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=data.get("name"), timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated OrganizationUnit: {data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error creating OrganizationUnit: {e}")
            return False

    def merge_missiondependency(self, data: dict) -> bool:
        """MERGE a MissionDependency node. Properties: dependency_id (required)."""
        # PR #33 round 9: same anti-pattern audit as merge_device round 8 —
        # the previous ``str(id(data))`` fallback used Python's memory-address
        # id(), producing a different MERGE key every call for the same
        # logical dependency. Each call would create a duplicate
        # MissionDependency node. Refuse the call instead. (MissionDependency
        # is not in _NATURAL_KEYS so there is no n.uuid to poison, but
        # accepting an ephemeral key still violates the dedup contract.)
        dependency_id = data.get("dependency_id")
        if not dependency_id:
            logger.error(
                "merge_missiondependency: data missing required 'dependency_id' — "
                "would create duplicate nodes per call; refusing"
            )
            return False
        query = """
        MERGE (md:MissionDependency {dependency_id: $dependency_id})
        SET md.edgeguard_managed = true,
            md.first_seen = CASE WHEN md.first_seen IS NULL THEN datetime() ELSE md.first_seen END,
            md.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, dependency_id=dependency_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated MissionDependency: {dependency_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating MissionDependency: {e}")
            return False

    def merge_resilmesh_user(self, data: dict) -> bool:
        """MERGE a ResilMesh User node. Properties: username, domain.

        PR #34 round 23: stamps deterministic ``n.uuid`` so User nodes
        participate in the cross-environment delta-sync contract.

        PR #34 round 25 (red-team audit): normalize ``domain=None`` and
        ``domain=""`` to ``"default"`` explicitly. Previously,
        ``data.get("domain", "default")`` returned ``"default"`` ONLY when
        the key was missing; if the caller passed ``domain=None`` or
        ``domain=""`` explicitly, ``domain`` would be that falsy value →
        ``compute_node_uuid`` produced a DIFFERENT uuid for the same
        logical user. Three callers (missing key, None, empty string) all
        represent "no domain specified" — must canonicalize to ONE form.
        """
        username = data.get("username")
        if not username:
            logger.error("merge_resilmesh_user: missing username — cannot MERGE without natural key")
            return False
        # ``data.get("domain") or "default"`` collapses None/""/missing-key
        # to the single canonical "default" form.
        domain = data.get("domain") or "default"
        # Deterministic uuid — MUST use the same key dict the MERGE binds to.
        node_uuid = compute_node_uuid("User", {"username": username, "domain": domain})
        query = """
        MERGE (u:User {username: $username, domain: $domain})
        ON CREATE SET u.uuid = $node_uuid
        SET u.edgeguard_managed = true,
            u.first_seen = CASE WHEN u.first_seen IS NULL THEN datetime() ELSE u.first_seen END,
            u.last_updated = datetime(),
            u.uuid = coalesce(u.uuid, $node_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, username=username, domain=domain, node_uuid=node_uuid, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Created/updated ResilMesh User: {username}")
            return True
        except Exception as e:
            logger.error(f"Error creating User: {e}")
            return False

    def merge_resilmesh_vulnerability(self, data: dict) -> bool:
        """MERGE a ResilMesh Vulnerability node. Properties: status, description, name, cve_id.

        This is the ResilMesh-native path used when data arrives from the
        ResilMesh platform directly (e.g., via ISIM GraphQL or NATS).
        The MISP pipeline uses ``merge_vulnerabilities_batch()`` instead,
        which keys on ``cve_id`` — both produce compatible nodes.

        Stamps the same deterministic n.uuid as the MISP path so a node MERGEd
        through either path gets the same uuid.
        """
        # PR #37 (Bug Hunter Tier S A3): refuse to merge when ``cve_id`` is
        # missing. Previously this defaulted to the sentinel
        # ``"CVE-0000-00000"`` — every ResilMesh vuln payload missing a
        # CVE then collapsed onto the SAME ``Vulnerability {cve_id:
        # "CVE-0000-00000"}`` node, with ``name``/``status``/``description``
        # overwritten on every call. Single poisoned node accumulated
        # hundreds of unrelated vulnerability identities; last writer
        # always won. ResilMesh users with vendor advisories or internal
        # scan findings (no CVE assigned) hit this path silently.
        # Caller MUST pass a real cve_id; refuse rather than corrupt.
        cve_id = data.get("cve_id")
        if not cve_id or (isinstance(cve_id, str) and not cve_id.strip()):
            logger.warning(
                "merge_resilmesh_vulnerability refused: missing 'cve_id' — "
                "vendor advisories without a CVE need their own node type, "
                "not the CVE-0000-00000 sentinel that silently collapses unrelated rows."
            )
            return False
        # Default name only after cve_id validation
        name = data.get("name", "unknown")
        vuln_uuid = compute_node_uuid("Vulnerability", {"cve_id": cve_id})
        query = """
        MERGE (v:Vulnerability {cve_id: $cve_id})
        ON CREATE SET v.uuid = $vuln_uuid
        SET v.name = coalesce(v.name, $name)
        SET v.status = $status,
            v.description = $description,
            v.edgeguard_managed = true,
            v.first_seen = CASE WHEN v.first_seen IS NULL THEN datetime() ELSE v.first_seen END,
            v.last_updated = datetime(),
            v.uuid = coalesce(v.uuid, $vuln_uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    name=name,
                    cve_id=cve_id,
                    vuln_uuid=vuln_uuid,
                    status=data.get("status"),
                    description=data.get("description"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated ResilMesh Vulnerability: {name}")
            return True
        except Exception as e:
            logger.error(f"Error creating Vulnerability: {e}")
            return False

    def merge_resilmesh_cve(self, data: dict) -> bool:
        """MERGE a ResilMesh CVE node with full ResilMesh-spec properties.

        This is the ResilMesh-native path. The MISP pipeline uses
        ``merge_cve()`` which sets the same properties plus EdgeGuard
        extensions (CISA KEV, reference_urls). Both produce compatible
        CVE nodes keyed on ``cve_id`` with the same deterministic n.uuid.
        """
        cve_id = data.get("cve_id")
        cve_uuid = compute_node_uuid("CVE", {"cve_id": cve_id})
        query = """
        MERGE (c:CVE {cve_id: $cve_id})
        ON CREATE SET c.uuid = $cve_uuid
        SET c.description = $description,
            c.published = $published,
            c.last_modified = $last_modified,
            c.cpe_type = $cpe_type,
            c.result_impacts = $result_impacts,
            c.ref_tags = $ref_tags,
            c.cwe = $cwe,
            c.edgeguard_managed = true,
            c.tags = apoc.coll.toSet(coalesce(c.tags, []) + [$tag]),
            c.tag = coalesce(c.tag, $tag),
            c.first_seen = CASE WHEN c.first_seen IS NULL THEN datetime() ELSE c.first_seen END,
            c.last_updated = datetime(),
            c.uuid = coalesce(c.uuid, $cve_uuid)
        """
        try:
            tag = data.get("tag", "default")
            with self.driver.session() as session:
                session.run(
                    query,
                    cve_id=cve_id,
                    cve_uuid=cve_uuid,
                    tag=tag,
                    description=data.get("description"),
                    published=data.get("published"),
                    last_modified=data.get("last_modified"),
                    cpe_type=data.get("cpe_type"),
                    result_impacts=data.get("result_impacts"),
                    ref_tags=data.get("ref_tags"),
                    cwe=data.get("cwe"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated ResilMesh CVE: {cve_id}")
            return True
        except Exception as e:
            logger.error(f"Error creating CVE: {e}")
            return False

    def merge_node(self, data: dict) -> bool:
        """MERGE a ResilMesh Node entity with centrality metrics. Properties: node_id, degree_centrality, pagerank_centrality"""
        query = """
        MERGE (n:Node {node_id: $node_id})
        SET n.edgeguard_managed = true,
            n.degree_centrality = $degree_centrality,
            n.pagerank_centrality = $pagerank_centrality,
            n.first_seen = CASE WHEN n.first_seen IS NULL THEN datetime() ELSE n.first_seen END,
            n.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    node_id=data.get("node_id"),
                    degree_centrality=data.get("degree_centrality"),
                    pagerank_centrality=data.get("pagerank_centrality"),
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Created/updated ResilMesh Node: {data.get('node_id')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Node: {e}")
            return False

    # ============================================================
    # RESILMESH SCHEMA - ALL 45 RELATIONSHIP METHODS
    # Generated from: /Users/user/Documents/python-projects/ResilMesh guidance/model/neo4j_relationships_properties.csv
    # ============================================================

    # 1. SoftwareVersion ON Host
    def create_softwareversion_on_host(self, version: str, hostname: str) -> bool:
        """Create ON relationship: SoftwareVersion -> Host"""
        query = """
        MATCH (sv:SoftwareVersion {version: $version})
        MATCH (h:Host {hostname: $hostname})
        MERGE (sv)-[r:ON]->(h)
        ON CREATE SET r.src_uuid = sv.uuid, r.trg_uuid = h.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, sv.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, h.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, version=version, hostname=hostname, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked SoftwareVersion {version} ON Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create SoftwareVersion ON Host: {e}")
            return False

    # 2. Role TO Device
    def create_role_to_device(self, permission: str, device_id: str) -> bool:
        """Create TO relationship: Role -> Device"""
        query = """
        MATCH (r:Role {permission: $permission})
        MATCH (d:Device {device_id: $device_id})
        MERGE (r)-[rel:TO]->(d)
        ON CREATE SET rel.src_uuid = r.uuid, rel.trg_uuid = d.uuid
        SET rel.created_at = datetime(),
            rel.updated_at = datetime(),
            rel.src_uuid = coalesce(rel.src_uuid, r.uuid),
            rel.trg_uuid = coalesce(rel.trg_uuid, d.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=permission, device_id=device_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Role {permission} TO Device {device_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Role TO Device: {e}")
            return False

    # 3. Role ASSIGNED_TO User
    def create_role_assigned_to_user(self, permission: str, username: str, domain: str = "default") -> bool:
        """Create ASSIGNED_TO relationship: Role -> User.

        PR #34 round 23: stamps r.src_uuid / r.trg_uuid from bound endpoint
        vars now that User has a deterministic n.uuid (added in round 23).
        """
        query = """
        MATCH (r:Role {permission: $permission})
        MATCH (u:User {username: $username, domain: $domain})
        MERGE (r)-[rel:ASSIGNED_TO]->(u)
        ON CREATE SET rel.src_uuid = r.uuid, rel.trg_uuid = u.uuid
        SET rel.created_at = datetime(),
            rel.updated_at = datetime(),
            rel.src_uuid = coalesce(rel.src_uuid, r.uuid),
            rel.trg_uuid = coalesce(rel.trg_uuid, u.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=permission, username=username, domain=domain, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Role {permission} ASSIGNED_TO User {username}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Role ASSIGNED_TO User: {e}")
            return False

    # 4. User ASSIGNED_TO Role
    def create_user_assigned_to_role(self, username: str, domain: str, permission: str) -> bool:
        """Create ASSIGNED_TO relationship: User -> Role.

        PR #34 round 23: stamps r.src_uuid / r.trg_uuid (round-23 User uuid).
        """
        query = """
        MATCH (u:User {username: $username, domain: $domain})
        MATCH (r:Role {permission: $permission})
        MERGE (u)-[rel:ASSIGNED_TO]->(r)
        ON CREATE SET rel.src_uuid = u.uuid, rel.trg_uuid = r.uuid
        SET rel.created_at = datetime(),
            rel.updated_at = datetime(),
            rel.src_uuid = coalesce(rel.src_uuid, u.uuid),
            rel.trg_uuid = coalesce(rel.trg_uuid, r.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, username=username, domain=domain, permission=permission, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked User {username} ASSIGNED_TO Role {permission}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create User ASSIGNED_TO Role: {e}")
            return False

    # 5. Device TO Role
    def create_device_to_role(self, device_id: str, permission: str) -> bool:
        """Create TO relationship: Device -> Role"""
        query = """
        MATCH (d:Device {device_id: $device_id})
        MATCH (r:Role {permission: $permission})
        MERGE (d)-[rel:TO]->(r)
        ON CREATE SET rel.src_uuid = d.uuid, rel.trg_uuid = r.uuid
        SET rel.created_at = datetime(),
            rel.updated_at = datetime(),
            rel.src_uuid = coalesce(rel.src_uuid, d.uuid),
            rel.trg_uuid = coalesce(rel.trg_uuid, r.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=device_id, permission=permission, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Device {device_id} TO Role {permission}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Device TO Role: {e}")
            return False

    # 6. Device HAS_IDENTITY Host
    def create_device_has_identity_host(self, device_id: str, hostname: str) -> bool:
        """Create HAS_IDENTITY relationship: Device -> Host"""
        query = """
        MATCH (d:Device {device_id: $device_id})
        MATCH (h:Host {hostname: $hostname})
        MERGE (d)-[r:HAS_IDENTITY]->(h)
        ON CREATE SET r.src_uuid = d.uuid, r.trg_uuid = h.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, d.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, h.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=device_id, hostname=hostname, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Device {device_id} HAS_IDENTITY Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Device HAS_IDENTITY Host: {e}")
            return False

    # 7. SoftwareVersion IN Vulnerability
    def create_softwareversion_in_vulnerability(self, *, version: str, cve_id: str) -> bool:
        """Create IN relationship: SoftwareVersion -> Vulnerability.

        Vulnerability's natural key is cve_id (per node_identity._NATURAL_KEYS).
        Keyword-only signature (PR #33 round 11) prevents positional swaps;
        round 12 dropped the unused ``vuln_name`` log-only kwarg.
        """
        query = """
        MATCH (sv:SoftwareVersion {version: $version})
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (sv)-[r:IN]->(v)
        ON CREATE SET r.src_uuid = sv.uuid, r.trg_uuid = v.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, sv.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, version=version, cve_id=cve_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked SoftwareVersion {version} IN Vulnerability {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create SoftwareVersion IN Vulnerability: {e}")
            return False

    # 8. IP HAS_ASSIGNED Node
    def create_ip_has_assigned_node(self, address: str, node_id: str) -> bool:
        """Create HAS_ASSIGNED relationship: IP -> Node"""
        query = """
        MATCH (i:IP {address: $address})
        MATCH (n:Node {node_id: $node_id})
        MERGE (i)-[r:HAS_ASSIGNED]->(n)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, address=address, node_id=node_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked IP {address} HAS_ASSIGNED Node {node_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create IP HAS_ASSIGNED Node: {e}")
            return False

    # 9. Node IS_A Host
    def create_node_is_a_host(self, node_id: str, hostname: str) -> bool:
        """Create IS_A relationship: Node -> Host"""
        query = """
        MATCH (n:Node {node_id: $node_id})
        MATCH (h:Host {hostname: $hostname})
        MERGE (n)-[r:IS_A]->(h)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, node_id=node_id, hostname=hostname, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Node {node_id} IS_A Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Node IS_A Host: {e}")
            return False

    # 10. Node HAS_ASSIGNED IP
    def create_node_has_assigned_ip(self, node_id: str, address: str) -> bool:
        """Create HAS_ASSIGNED relationship: Node -> IP"""
        query = """
        MATCH (n:Node {node_id: $node_id})
        MATCH (i:IP {address: $address})
        MERGE (n)-[r:HAS_ASSIGNED]->(i)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, node_id=node_id, address=address, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Node {node_id} HAS_ASSIGNED IP {address}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Node HAS_ASSIGNED IP: {e}")
            return False

    # 11. Host IS_A Node
    def create_host_is_a_node(self, hostname: str, node_id: str) -> bool:
        """Create IS_A relationship: Host -> Node"""
        query = """
        MATCH (h:Host {hostname: $hostname})
        MATCH (n:Node {node_id: $node_id})
        MERGE (h)-[r:IS_A]->(n)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, node_id=node_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Host {hostname} IS_A Node {node_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Host IS_A Node: {e}")
            return False

    # 12. Host HAS_IDENTITY Device
    def create_host_has_identity_device(self, hostname: str, device_id: str) -> bool:
        """Create HAS_IDENTITY relationship: Host -> Device"""
        query = """
        MATCH (h:Host {hostname: $hostname})
        MATCH (d:Device {device_id: $device_id})
        MERGE (h)-[r:HAS_IDENTITY]->(d)
        ON CREATE SET r.src_uuid = h.uuid, r.trg_uuid = d.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, h.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, d.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, device_id=device_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Host {hostname} HAS_IDENTITY Device {device_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Host HAS_IDENTITY Device: {e}")
            return False

    # 13. Host ON SoftwareVersion
    def create_host_on_softwareversion(self, hostname: str, version: str) -> bool:
        """Create ON relationship: Host -> SoftwareVersion"""
        query = """
        MATCH (h:Host {hostname: $hostname})
        MATCH (sv:SoftwareVersion {version: $version})
        MERGE (h)-[r:ON]->(sv)
        ON CREATE SET r.src_uuid = h.uuid, r.trg_uuid = sv.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, h.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, sv.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, version=version, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Host {hostname} ON SoftwareVersion {version}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Host ON SoftwareVersion: {e}")
            return False

    # 14. IP PART_OF Subnet
    def create_ip_part_of_subnet(self, address: str, subnet_range: str) -> bool:
        """Create PART_OF relationship: IP -> Subnet"""
        query = """
        MATCH (i:IP {address: $address})
        MATCH (s:Subnet {range: $subnet_range})
        MERGE (i)-[r:PART_OF]->(s)
        ON CREATE SET r.src_uuid = i.uuid, r.trg_uuid = s.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, i.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, s.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, address=address, subnet_range=subnet_range, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked IP {address} PART_OF Subnet {subnet_range}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create IP PART_OF Subnet: {e}")
            return False

    # 15. Subnet PART_OF IP
    def create_subnet_part_of_ip(self, subnet_range: str, address: str) -> bool:
        """Create PART_OF relationship: Subnet -> IP"""
        query = """
        MATCH (s:Subnet {range: $subnet_range})
        MATCH (i:IP {address: $address})
        MERGE (s)-[r:PART_OF]->(i)
        ON CREATE SET r.src_uuid = s.uuid, r.trg_uuid = i.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, s.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, i.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, subnet_range=subnet_range, address=address, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Subnet {subnet_range} PART_OF IP {address}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Subnet PART_OF IP: {e}")
            return False

    # 16. Mission FOR OrganizationUnit
    def create_mission_for_organizationunit(self, mission_name: str, orgunit_name: str) -> bool:
        """Create FOR relationship: Mission -> OrganizationUnit"""
        query = """
        MATCH (m:Mission {name: $mission_name})
        MATCH (o:OrganizationUnit {name: $orgunit_name})
        MERGE (m)-[r:FOR]->(o)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, mission_name=mission_name, orgunit_name=orgunit_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Mission {mission_name} FOR OrganizationUnit {orgunit_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Mission FOR OrganizationUnit: {e}")
            return False

    # 17. Mission SUPPORTS Component
    def create_mission_supports_component(self, mission_name: str, component_name: str) -> bool:
        """Create SUPPORTS relationship: Mission -> Component"""
        query = """
        MATCH (m:Mission {name: $mission_name})
        MATCH (c:Component {name: $component_name})
        MERGE (m)-[r:SUPPORTS]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, mission_name=mission_name, component_name=component_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Mission {mission_name} SUPPORTS Component {component_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Mission SUPPORTS Component: {e}")
            return False

    # 18. Component FROM MissionDependency
    def create_component_from_missiondependency(self, component_name: str, dependency_id: str) -> bool:
        """Create FROM relationship: Component -> MissionDependency"""
        query = """
        MATCH (c:Component {name: $component_name})
        MATCH (md:MissionDependency {dependency_id: $dependency_id})
        MERGE (c)-[r:FROM]->(md)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, component_name=component_name, dependency_id=dependency_id, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked Component {component_name} FROM MissionDependency {dependency_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component FROM MissionDependency: {e}")
            return False

    # 19. Component PROVIDED_BY Host
    def create_component_provided_by_host(self, component_name: str, hostname: str) -> bool:
        """Create PROVIDED_BY relationship: Component -> Host"""
        query = """
        MATCH (c:Component {name: $component_name})
        MATCH (h:Host {hostname: $hostname})
        MERGE (c)-[r:PROVIDED_BY]->(h)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, component_name=component_name, hostname=hostname, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Component {component_name} PROVIDED_BY Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component PROVIDED_BY Host: {e}")
            return False

    # 20. Component SUPPORTS Mission
    def create_component_supports_mission(self, component_name: str, mission_name: str) -> bool:
        """Create SUPPORTS relationship: Component -> Mission"""
        query = """
        MATCH (c:Component {name: $component_name})
        MATCH (m:Mission {name: $mission_name})
        MERGE (c)-[r:SUPPORTS]->(m)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, component_name=component_name, mission_name=mission_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Component {component_name} SUPPORTS Mission {mission_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component SUPPORTS Mission: {e}")
            return False

    # 21. Component TO MissionDependency
    def create_component_to_missiondependency(self, component_name: str, dependency_id: str) -> bool:
        """Create TO relationship: Component -> MissionDependency"""
        query = """
        MATCH (c:Component {name: $component_name})
        MATCH (md:MissionDependency {dependency_id: $dependency_id})
        MERGE (c)-[r:TO]->(md)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, component_name=component_name, dependency_id=dependency_id, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked Component {component_name} TO MissionDependency {dependency_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component TO MissionDependency: {e}")
            return False

    # 22. OrganizationUnit FOR Mission
    def create_organizationunit_for_mission(self, orgunit_name: str, mission_name: str) -> bool:
        """Create FOR relationship: OrganizationUnit -> Mission"""
        query = """
        MATCH (o:OrganizationUnit {name: $orgunit_name})
        MATCH (m:Mission {name: $mission_name})
        MERGE (o)-[r:FOR]->(m)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, orgunit_name=orgunit_name, mission_name=mission_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked OrganizationUnit {orgunit_name} FOR Mission {mission_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create OrganizationUnit FOR Mission: {e}")
            return False

    # 23. OrganizationUnit PART_OF OrganizationUnit
    def create_organizationunit_part_of_organizationunit(self, child_orgunit: str, parent_orgunit: str) -> bool:
        """Create PART_OF relationship: OrganizationUnit -> OrganizationUnit"""
        query = """
        MATCH (child:OrganizationUnit {name: $child_orgunit})
        MATCH (parent:OrganizationUnit {name: $parent_orgunit})
        MERGE (child)-[r:PART_OF]->(parent)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, child_orgunit=child_orgunit, parent_orgunit=parent_orgunit, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked OrganizationUnit {child_orgunit} PART_OF OrganizationUnit {parent_orgunit}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create OrganizationUnit PART_OF OrganizationUnit: {e}")
            return False

    # 24. Subnet PART_OF Subnet
    def create_subnet_part_of_subnet(self, child_subnet: str, parent_subnet: str) -> bool:
        """Create PART_OF relationship: Subnet -> Subnet"""
        query = """
        MATCH (child:Subnet {range: $child_subnet})
        MATCH (parent:Subnet {range: $parent_subnet})
        MERGE (child)-[r:PART_OF]->(parent)
        ON CREATE SET r.src_uuid = child.uuid, r.trg_uuid = parent.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, child.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, parent.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, child_subnet=child_subnet, parent_subnet=parent_subnet, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Subnet {child_subnet} PART_OF Subnet {parent_subnet}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Subnet PART_OF Subnet: {e}")
            return False

    # 25. Subnet PART_OF OrganizationUnit
    def create_subnet_part_of_organizationunit(self, subnet_range: str, orgunit_name: str) -> bool:
        """Create PART_OF relationship: Subnet -> OrganizationUnit"""
        query = """
        MATCH (s:Subnet {range: $subnet_range})
        MATCH (o:OrganizationUnit {name: $orgunit_name})
        MERGE (s)-[r:PART_OF]->(o)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, subnet_range=subnet_range, orgunit_name=orgunit_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Subnet {subnet_range} PART_OF OrganizationUnit {orgunit_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Subnet PART_OF OrganizationUnit: {e}")
            return False

    # 26. MissionDependency TO Component
    def create_missiondependency_to_component(self, dependency_id: str, component_name: str) -> bool:
        """Create TO relationship: MissionDependency -> Component"""
        query = """
        MATCH (md:MissionDependency {dependency_id: $dependency_id})
        MATCH (c:Component {name: $component_name})
        MERGE (md)-[r:TO]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, dependency_id=dependency_id, component_name=component_name, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked MissionDependency {dependency_id} TO Component {component_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create MissionDependency TO Component: {e}")
            return False

    # 27. MissionDependency FROM Component
    def create_missiondependency_from_component(self, dependency_id: str, component_name: str) -> bool:
        """Create FROM relationship: MissionDependency -> Component"""
        query = """
        MATCH (md:MissionDependency {dependency_id: $dependency_id})
        MATCH (c:Component {name: $component_name})
        MERGE (md)-[r:FROM]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, dependency_id=dependency_id, component_name=component_name, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked MissionDependency {dependency_id} FROM Component {component_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create MissionDependency FROM Component: {e}")
            return False

    # 28. OrganizationUnit PART_OF Subnet
    def create_organizationunit_part_of_subnet(self, orgunit_name: str, subnet_range: str) -> bool:
        """Create PART_OF relationship: OrganizationUnit -> Subnet"""
        query = """
        MATCH (o:OrganizationUnit {name: $orgunit_name})
        MATCH (s:Subnet {range: $subnet_range})
        MERGE (o)-[r:PART_OF]->(s)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, orgunit_name=orgunit_name, subnet_range=subnet_range, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked OrganizationUnit {orgunit_name} PART_OF Subnet {subnet_range}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create OrganizationUnit PART_OF Subnet: {e}")
            return False

    # 29. Node IS_CONNECTED_TO Node (with start/end properties)
    def create_node_is_connected_to_node(
        self, node1_id: str, node2_id: str, start: int = None, end: int = None
    ) -> bool:
        """Create IS_CONNECTED_TO relationship: Node -> Node (with start/end properties)"""
        query = """
        MATCH (n1:Node {node_id: $node1_id})
        MATCH (n2:Node {node_id: $node2_id})
        MERGE (n1)-[r:IS_CONNECTED_TO]->(n2)
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.start = $start,
            r.end = $end
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, node1_id=node1_id, node2_id=node2_id, start=start, end=end, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked Node {node1_id} IS_CONNECTED_TO Node {node2_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Node IS_CONNECTED_TO Node: {e}")
            return False

    # 30. NetworkService ON Host (with status property)
    def create_networkservice_on_host(self, port: int, protocol: str, hostname: str, status: str = None) -> bool:
        """Create ON relationship: NetworkService -> Host (with status property)"""
        query = """
        MATCH (ns:NetworkService {port: $port, protocol: $protocol})
        MATCH (h:Host {hostname: $hostname})
        MERGE (ns)-[r:ON]->(h)
        ON CREATE SET r.src_uuid = ns.uuid, r.trg_uuid = h.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.status = $status,
            r.src_uuid = coalesce(r.src_uuid, ns.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, h.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, port=port, protocol=protocol, hostname=hostname, status=status, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked NetworkService {port}/{protocol} ON Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create NetworkService ON Host: {e}")
            return False

    # 31. Host PROVIDED_BY Component
    def create_host_provided_by_component(self, hostname: str, component_name: str) -> bool:
        """Create PROVIDED_BY relationship: Host -> Component"""
        query = """
        MATCH (h:Host {hostname: $hostname})
        MATCH (c:Component {name: $component_name})
        MERGE (h)-[r:PROVIDED_BY]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, component_name=component_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Host {hostname} PROVIDED_BY Component {component_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Host PROVIDED_BY Component: {e}")
            return False

    # 32. Host ON NetworkService (with status property)
    def create_host_on_networkservice(self, hostname: str, port: int, protocol: str, status: str = None) -> bool:
        """Create ON relationship: Host -> NetworkService (with status property)"""
        query = """
        MATCH (h:Host {hostname: $hostname})
        MATCH (ns:NetworkService {port: $port, protocol: $protocol})
        MERGE (h)-[r:ON]->(ns)
        ON CREATE SET r.src_uuid = h.uuid, r.trg_uuid = ns.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.status = $status,
            r.src_uuid = coalesce(r.src_uuid, h.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, ns.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query, hostname=hostname, port=port, protocol=protocol, status=status, timeout=NEO4J_READ_TIMEOUT
                )
            logger.info(f"Linked Host {hostname} ON NetworkService {port}/{protocol}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Host ON NetworkService: {e}")
            return False

    # 33. Application HAS_IDENTITY Component
    def create_application_has_identity_component(self, app_name: str, component_name: str) -> bool:
        """Create HAS_IDENTITY relationship: Application -> Component"""
        query = """
        MATCH (a:Application {name: $app_name})
        MATCH (c:Component {name: $component_name})
        MERGE (a)-[r:HAS_IDENTITY]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, app_name=app_name, component_name=component_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Application {app_name} HAS_IDENTITY Component {component_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Application HAS_IDENTITY Component: {e}")
            return False

    # 34. Component HAS_IDENTITY Application
    def create_component_has_identity_application(self, component_name: str, app_name: str) -> bool:
        """Create HAS_IDENTITY relationship: Component -> Application"""
        query = """
        MATCH (c:Component {name: $component_name})
        MATCH (a:Application {name: $app_name})
        MERGE (c)-[r:HAS_IDENTITY]->(a)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, component_name=component_name, app_name=app_name, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Component {component_name} HAS_IDENTITY Application {app_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component HAS_IDENTITY Application: {e}")
            return False

    # 35. Vulnerability REFERS_TO CVE
    def create_vulnerability_refers_to_cve(self, *, cve_id: str) -> bool:
        """Create REFERS_TO relationship: Vulnerability -> CVE.

        Vulnerability's natural key is cve_id (per node_identity._NATURAL_KEYS).
        Keyword-only signature (PR #33 round 11) prevents positional swaps;
        round 12 dropped the unused ``vuln_name`` log-only kwarg. Note: the
        canonical bridge_vulnerability_cve query in enrichment_jobs.py creates
        the same REFERS_TO edge — this helper is a single-pair convenience.
        """
        query = """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (v)-[r:REFERS_TO]->(c)
        ON CREATE SET r.src_uuid = v.uuid, r.trg_uuid = c.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, v.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, c.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Vulnerability {cve_id} REFERS_TO CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Vulnerability REFERS_TO CVE: {e}")
            return False

    # 36. Vulnerability IN SoftwareVersion
    def create_vulnerability_in_softwareversion(self, *, cve_id: str, version: str) -> bool:
        """Create IN relationship: Vulnerability -> SoftwareVersion.

        Keyword-only (PR #33 round 11). Round 12 dropped vuln_name kwarg.
        """
        query = """
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MATCH (sv:SoftwareVersion {version: $version})
        MERGE (v)-[r:IN]->(sv)
        ON CREATE SET r.src_uuid = v.uuid, r.trg_uuid = sv.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, v.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, sv.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, version=version, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked Vulnerability {cve_id} IN SoftwareVersion {version}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Vulnerability IN SoftwareVersion: {e}")
            return False

    # 37. CVE REFERS_TO Vulnerability
    def create_cve_refers_to_vulnerability(self, *, cve_id: str) -> bool:
        """Create REFERS_TO relationship: CVE -> Vulnerability.

        Keyword-only (PR #33 round 11). Round 12 dropped vuln_name kwarg.
        """
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (v:Vulnerability {cve_id: $cve_id})
        MERGE (c)-[r:REFERS_TO]->(v)
        ON CREATE SET r.src_uuid = c.uuid, r.trg_uuid = v.uuid
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.src_uuid = coalesce(r.src_uuid, c.uuid),
            r.trg_uuid = coalesce(r.trg_uuid, v.uuid)
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, timeout=NEO4J_READ_TIMEOUT)
            logger.info(f"Linked CVE {cve_id} REFERS_TO Vulnerability {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE REFERS_TO Vulnerability: {e}")
            return False

    # PR #33 round 12: deleted the 8 vector_string-keyed CVSS edge helpers
    # (create_cve_has_cvss_v2/30/31/40 + create_cvssv*_has_cvssv*_cve) along
    # with the 4 standalone CVSS mergers above. The canonical _merge_cvss_node
    # (called from merge_cve) creates the bidirectional HAS_CVSS_v* edges
    # with stamped src_uuid/trg_uuid; no separate helper needed.

    # ============================================================
    # RESILMESH ALERT/INDICATOR METHODS
    # ============================================================

    def create_alert_node(self, alert_data: dict) -> bool:
        """Create an Alert node from a ResilMesh alert.

        PR #34 round 23: stamps deterministic ``n.uuid`` so Alert nodes
        participate in the cross-environment delta-sync contract.
        """
        try:
            alert_id = alert_data.get("alert_id")
            if not alert_id:
                logger.error("create_alert_node: missing alert_id — cannot MERGE without natural key")
                return False
            source = alert_data.get("source", "unknown")
            zone = alert_data.get("zone", ["global"])  # zone is now an array
            timestamp = alert_data.get("timestamp", datetime.now(timezone.utc).isoformat())
            _tags = alert_data.get("tags", [])
            threat = alert_data.get("threat", {})

            indicator = threat.get("indicator")
            indicator_type = threat.get("type", "unknown")
            malware = threat.get("malware")
            cve = threat.get("cve")
            description = threat.get("description", "")
            severity = threat.get("severity", 0)

            # Deterministic uuid — keyed on alert_id (the UNIQUE constraint).
            node_uuid = compute_node_uuid("Alert", {"alert_id": alert_id})

            query = """
            MERGE (a:Alert {alert_id: $alert_id})
            ON CREATE SET a.uuid = $node_uuid
            SET a.source = $source,
                a.zone = $zone,
                a.timestamp = $timestamp,
                a.severity = $severity,
                a.description = $description,
                a.indicator = $indicator,
                a.indicator_type = $indicator_type,
                a.malware = $malware,
                a.cve = $cve,
                a.enriched = false,
                a.received_at = datetime(),
                a.last_updated = datetime(),
                a.uuid = coalesce(a.uuid, $node_uuid)
            """

            with self.driver.session() as session:
                session.run(
                    query,
                    alert_id=alert_id,
                    source=source,
                    zone=zone,
                    timestamp=timestamp,
                    severity=severity,
                    description=description,
                    indicator=indicator,
                    indicator_type=indicator_type,
                    malware=malware,
                    cve=cve,
                    node_uuid=node_uuid,
                    timeout=NEO4J_READ_TIMEOUT,
                )

            logger.info(f"Created/updated Alert node: {alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to create Alert node: {e}")
            return False

    def link_alert_to_indicator(self, alert_id: str, indicator_value: str) -> bool:
        """Create INVOLVES relationship between Alert and Indicator.

        PR #34 round 23: stamps r.src_uuid / r.trg_uuid from bound endpoint
        vars (Alert uuid added in round 23; Indicator uuid was already there).
        """
        try:
            query = """
            MATCH (a:Alert {alert_id: $alert_id})
            MATCH (i:Indicator {value: $indicator_value})
            MERGE (a)-[r:INVOLVES]->(i)
            ON CREATE SET r.src_uuid = a.uuid, r.trg_uuid = i.uuid
            SET r.created_at = datetime(),
                r.source = 'resilmesh',
                r.src_uuid = coalesce(r.src_uuid, a.uuid),
                r.trg_uuid = coalesce(r.trg_uuid, i.uuid)
            """

            with self.driver.session() as session:
                session.run(query, alert_id=alert_id, indicator_value=indicator_value, timeout=NEO4J_READ_TIMEOUT)

            logger.info(f"Linked Alert {alert_id} to Indicator {indicator_value}")
            return True

        except Exception as e:
            logger.warning(f"Failed to link Alert to Indicator: {e}")
            return False

    def update_alert_enrichment_status(self, alert_id: str, enrichment_data: dict, latency_ms: float) -> bool:
        """Update an Alert node with enrichment results."""
        try:
            query = """
            MATCH (a:Alert {alert_id: $alert_id})
            SET a.enriched = true,
                a.enrichment_latency_ms = $latency_ms,
                a.enrichment_data = $enrichment_data,
                a.enrichment_timestamp = datetime()
            """
            with self.driver.session() as session:
                session.run(
                    query,
                    alert_id=alert_id,
                    enrichment_data=json.dumps(enrichment_data),
                    latency_ms=latency_ms,
                    timeout=NEO4J_READ_TIMEOUT,
                )
            logger.info(f"Updated Alert {alert_id} with enrichment data")
            return True
        except Exception as e:
            logger.error(f"Failed to update alert enrichment: {e}")
            return False

    def get_alert_with_enrichment(self, alert_id: str) -> dict:
        """Retrieve an Alert with its enrichment data."""
        query = """
        MATCH (a:Alert {alert_id: $alert_id})
        OPTIONAL MATCH (a)-[:INVOLVES]->(i:Indicator)
        RETURN a, collect(i) as indicators
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, alert_id=alert_id, timeout=NEO4J_READ_TIMEOUT)
                record = result.single()
                if record:
                    alert = dict(record["a"]._properties)
                    alert["indicators"] = [dict(i._properties) for i in record["indicators"] if i]
                    return alert
                return None
        except Exception as e:
            logger.error(f"Error getting alert: {e}")
            return None

    def create_indicator_from_alert(self, indicator_value, indicator_type, zone, alert_data=None, zones=None):
        """Create an Indicator node from a ResilMesh alert."""
        now = datetime.now(timezone.utc).isoformat()

        type_mapping = {
            "ip": "ipv4",
            "ipv4": "ipv4",
            "ipv6": "ipv6",
            "domain": "domain",
            "file_hash": "hash",
            "hash": "hash",
            "sha256": "sha256",
            "md5": "md5",
        }
        normalized_type = type_mapping.get(indicator_type, indicator_type)

        # zone is now an array
        zone_array = zones if zones else (zone if isinstance(zone, list) else [zone])

        data = {
            "indicator_type": normalized_type,
            "value": indicator_value,
            "tag": f"{zone_array[0]}_{normalized_type}",
            "zone": zone_array,
            "first_seen": now,
            "last_updated": now,
            "source": ["resilmesh"],
            "confidence_score": 0.8 if alert_data else 0.5,
        }

        # PR #34 round 18: dropped n.original_source SET — Neo4j property had
        # zero readers (see neo4j_client.py:606 deletion comment).
        # PR #34 round 24: zone accumulation applies specifics-override-global
        # rule on write.
        _zone_clause_i = _zone_override_global_clause("i", "$zone")
        query = f"""
        MERGE (i:Indicator {{indicator_type: $indicator_type, value: $value}})
        SET i.first_seen = CASE WHEN i.first_seen IS NULL THEN datetime() ELSE i.first_seen END,
            i.last_updated = datetime(),
            i.source = apoc.coll.toSet(coalesce(i.source, []) + $source),
            i.confidence_score = CASE
                WHEN i.confidence_score IS NULL OR $confidence_score > i.confidence_score
                THEN $confidence_score
                ELSE i.confidence_score END,
            {_zone_clause_i},
            i.tags = apoc.coll.toSet(coalesce(i.tags, []) + ['resilmesh']),
            i.edgeguard_managed = true,
            i.active = CASE WHEN i.retired_at IS NOT NULL THEN i.active ELSE true END
        """

        try:
            with self.driver.session() as session:
                session.run(query, **data, timeout=NEO4J_READ_TIMEOUT)
                logger.info(f"Created/updated indicator: {indicator_value} ({normalized_type})")
                return True
        except Exception:
            fallback_query = f"""
            MERGE (i:Indicator {{indicator_type: $indicator_type, value: $value}})
            SET i.first_seen = CASE WHEN i.first_seen IS NULL THEN $first_seen ELSE i.first_seen END,
                i.last_updated = $last_updated,
                i.confidence_score = CASE
                    WHEN i.confidence_score IS NULL OR $confidence_score > i.confidence_score
                    THEN $confidence_score
                    ELSE i.confidence_score END,
                {_zone_clause_i}
            """
            try:
                with self.driver.session() as session:
                    session.run(fallback_query, **data, timeout=NEO4J_READ_TIMEOUT)
                    return True
            except Exception as e2:
                logger.error(f"Failed to create indicator: {e2}")
                return False

    def process_complete_resilmesh_alert(self, alert_data: dict) -> dict:
        """Process a complete ResilMesh alert, creating all nodes and relationships."""
        result = {
            "alert_id": alert_data.get("alert_id"),
            "created_nodes": [],
            "created_relationships": [],
            "errors": [],
        }

        try:
            alert_id = alert_data.get("alert_id")
            zone = alert_data.get("zone", "global")
            tags = alert_data.get("tags", [])
            threat = alert_data.get("threat", {})

            # 1. Create Alert node
            if self.create_alert_node(alert_data):
                result["created_nodes"].append(f"Alert:{alert_id}")

            # 2. Create Indicator
            indicator = threat.get("indicator")
            indicator_type = threat.get("type", "unknown")
            if indicator:
                zones = tags if tags else [zone]
                self.create_indicator_from_alert(
                    indicator_value=indicator,
                    indicator_type=indicator_type,
                    zone=zone,
                    alert_data=alert_data,
                    zones=zones,
                )
                result["created_nodes"].append(f"Indicator:{indicator}")
                self.link_alert_to_indicator(alert_id, indicator)

            logger.info(f"Complete ResilMesh alert processing finished for {alert_id}")

        except Exception as e:
            logger.error(f"Error processing complete alert: {e}")
            result["errors"].append(str(e))

        return result

    # ============================================================
    # STUB METHODS FOR TEST COMPATIBILITY
    # ============================================================

    def get_enrichment_chain(self, indicator_value: str) -> Optional[Dict]:
        """Stub for get_enrichment_chain - returns sample data for testing."""
        return {"indicator": {"value": indicator_value}, "malware": [], "resolved_ips": [], "targeted_hosts": []}


def test_connection():
    """Test Neo4j connection with health check."""
    client = Neo4jClient()

    if client.connect():
        # Run health check
        health = client.health_check()
        print(f"\nHealth Check: {health}")

        # Test operations
        client.create_constraints()
        client.create_indexes()
        client.ensure_sources()

        stats = client.get_stats()
        print(f"\nNeo4j Stats: {stats}")

        client.close()
        return True

    return False


if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    success = test_connection()
    sys.exit(0 if success else 1)
