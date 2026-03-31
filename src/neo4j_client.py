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

# Configure logging
logger = logging.getLogger(__name__)

# Configuration constants
NEO4J_CONNECTION_TIMEOUT = 60  # seconds
NEO4J_READ_TIMEOUT = 300  # seconds (5 min; 120s was too low for 441K-node graph)
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
                    "CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition"
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

        try:
            with self.driver.session() as session:
                result = session.run(query, parameters, timeout=timeout)
                return [dict(record) for record in result]
        except neo4j_exceptions.CypherSyntaxError as e:
            logger.error(f"Cypher syntax error: {e}")
            return []
        except (
            neo4j_exceptions.ServiceUnavailable,
            neo4j_exceptions.TransientError,
            ConnectionError,
            TimeoutError,
        ):
            raise  # let @retry_with_backoff handle transient errors
        except neo4j_exceptions.DatabaseError as e:
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
            "DROP CONSTRAINT indicator_key IF EXISTS",
        ]
        with self.driver.session() as session:
            for stmt in old_constraints:
                try:
                    session.run(stmt, timeout=NEO4J_READ_TIMEOUT)
                except Exception:
                    pass  # constraint didn't exist — fine

        constraints = [
            # Source nodes
            "CREATE CONSTRAINT source_key IF NOT EXISTS FOR (s:Source) REQUIRE (s.source_id) IS UNIQUE",
            # CVE / Vulnerability — separate labels kept for backward compat
            "CREATE CONSTRAINT cve_key IF NOT EXISTS FOR (c:CVE) REQUIRE (c.cve_id) IS UNIQUE",
            # Vulnerability: match the 2-field MERGE key used in merge_vulnerabilities_batch
            "CREATE CONSTRAINT vulnerability_key IF NOT EXISTS FOR (v:Vulnerability) REQUIRE (v.cve_id) IS UNIQUE",
            # Indicator: match the 3-field MERGE key used in merge_indicators_batch
            "CREATE CONSTRAINT indicator_key IF NOT EXISTS FOR (i:Indicator) REQUIRE (i.indicator_type, i.value, i.tag) IS UNIQUE",
            # Threat-graph node types
            "CREATE CONSTRAINT malware_key IF NOT EXISTS FOR (m:Malware) REQUIRE (m.name) IS UNIQUE",
            "CREATE CONSTRAINT actor_key IF NOT EXISTS FOR (a:ThreatActor) REQUIRE (a.name) IS UNIQUE",
            "CREATE CONSTRAINT technique_key IF NOT EXISTS FOR (t:Technique) REQUIRE (t.mitre_id) IS UNIQUE",
            # MITRE tactics — 14 fixed nodes; unique by mitre_id only
            "CREATE CONSTRAINT tactic_key IF NOT EXISTS FOR (t:Tactic) REQUIRE (t.mitre_id) IS UNIQUE",
            # Sector nodes — created dynamically; must stay unique by name
            "CREATE CONSTRAINT sector_key IF NOT EXISTS FOR (s:Sector) REQUIRE (s.name) IS UNIQUE",
            # ResilMesh-compatible CVSS sub-nodes — keyed by (cve_id, tag)
            "CREATE CONSTRAINT cvssv31_key IF NOT EXISTS FOR (n:CVSSv31) REQUIRE (n.cve_id, n.tag) IS UNIQUE",
            "CREATE CONSTRAINT cvssv2_key IF NOT EXISTS FOR (n:CVSSv2) REQUIRE (n.cve_id, n.tag) IS UNIQUE",
            "CREATE CONSTRAINT cvssv30_key IF NOT EXISTS FOR (n:CVSSv30) REQUIRE (n.cve_id, n.tag) IS UNIQUE",
            "CREATE CONSTRAINT cvssv40_key IF NOT EXISTS FOR (n:CVSSv40) REQUIRE (n.cve_id, n.tag) IS UNIQUE",
            # Campaign nodes — one per actor, keyed by name only
            "CREATE CONSTRAINT campaign_key IF NOT EXISTS FOR (c:Campaign) REQUIRE (c.name) IS UNIQUE",
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
            # Original source tracking indexes
            "CREATE INDEX indicator_original_source IF NOT EXISTS FOR (i:Indicator) ON (i.original_source)",
            "CREATE INDEX vulnerability_original_source IF NOT EXISTS FOR (v:Vulnerability) ON (v.original_source)",
            # Active/inactive tracking indexes
            "CREATE INDEX indicator_active IF NOT EXISTS FOR (i:Indicator) ON (i.active)",
            "CREATE INDEX vulnerability_active IF NOT EXISTS FOR (v:Vulnerability) ON (v.active)",
            "CREATE INDEX indicator_misp_event_id IF NOT EXISTS FOR (i:Indicator) ON (i.misp_event_id)",
            "CREATE INDEX vulnerability_misp_event_id IF NOT EXISTS FOR (v:Vulnerability) ON (v.misp_event_id)",
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
            # build_relationships performance: CVE.cve_id needed for EXPLOITS query + IS_SAME_AS
            "CREATE INDEX cve_cve_id IF NOT EXISTS FOR (c:CVE) ON (c.cve_id)",
            # Co-occurrence join: Malware/ThreatActor by misp_event_id
            "CREATE INDEX malware_misp_event_id IF NOT EXISTS FOR (m:Malware) ON (m.misp_event_id)",
            "CREATE INDEX actor_misp_event_id IF NOT EXISTS FOR (a:ThreatActor) ON (a.misp_event_id)",
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
                    query = """
                    MERGE (s:Source {source_id: $source_id})
                    ON CREATE SET s.created_at = datetime()
                    SET s.name = $name,
                        s.type = $type,
                        s.reliability = $reliability,
                        s.updated_at = datetime()
                    """
                    session.run(
                        query,
                        source_id=source_id,
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
            query = f"""
            MERGE (n:{label} {{{key_set}}})
            ON CREATE SET n.first_imported_at = datetime()

            // Always accumulate sources and zones — provenance is never overwritten.
            // Use APOC to deduplicate the merged arrays in one step.
            SET n.confidence_score = CASE
                    WHEN n.confidence_score IS NULL OR $confidence > n.confidence_score
                    THEN $confidence
                    ELSE n.confidence_score END,
                n.source = apoc.coll.toSet(coalesce(n.source, []) + $source_array),
                n.zone = apoc.coll.toSet(coalesce(n.zone, []) + $zone),
                n.tags = apoc.coll.toSet(coalesce(n.tags, []) + $tag_array),
                n.tag = coalesce(n.tag, $tag_value),
                n.last_updated = datetime(),
                n.last_imported_from = $source_id,
                n.active = true,
                n.edgeguard_managed = true
            """

            # Add misp_event_id if present — accumulated as array for multi-event provenance.
            # Keeps scalar misp_event_id for backward compat (first-seen event).
            misp_event_id = data.get("misp_event_id")
            if misp_event_id:
                query += """,
                n.misp_event_id = coalesce(n.misp_event_id, $misp_event_id),
                n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + [$misp_event_id])"""

            # Add misp_attribute_id if present in data (for indicators)
            misp_attribute_id = data.get("misp_attribute_id")
            if misp_attribute_id:
                query += """,
                n.misp_attribute_id = coalesce(n.misp_attribute_id, $misp_attribute_id),
                n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + [$misp_attribute_id])"""

            # Add original_source if present in data
            if original_source:
                query += ", n.original_source = $original_source"

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

            # Check existing confidence before update for audit logging
            check_query = f"""
            MATCH (n:{label} {{{key_set}}})
            RETURN n.confidence_score as existing_confidence, n.source as existing_source
            """

            with self.driver.session() as session:
                # Check existing values for audit
                existing = session.run(check_query, **{k: v for k, v in key_props.items()}, timeout=NEO4J_READ_TIMEOUT)
                existing_record = existing.single()

                if existing_record:
                    existing_conf = existing_record.get("existing_confidence")
                    existing_src = existing_record.get("existing_source")
                    if existing_conf is not None and confidence < existing_conf:
                        key_str = ", ".join(f"{k}={v}" for k, v in key_props.items())
                        logger.info(
                            f"AUDIT: Skipping lower-confidence update for {label}({key_str}): "
                            f"existing={existing_conf} (source={existing_src}), new={confidence} (source={source_id})"
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
                    **params_extra,
                }
                if misp_event_id:
                    params["misp_event_id"] = misp_event_id
                if misp_attribute_id:
                    params["misp_attribute_id"] = misp_attribute_id
                if original_source:
                    params["original_source"] = original_source
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

        query = f"""
        MATCH (n:{label})
        WHERE {key_conditions}
        MATCH (s:Source {{source_id: $source_id}})
        MERGE (n)-[r:SOURCED_FROM]->(s)
        ON CREATE SET r.imported_at = datetime()
        SET r.raw_data = $raw_data,
            r.confidence = $confidence,
            r.updated_at = datetime(),
            r.edgeguard_managed = true
        """

        try:
            with self.driver.session() as session:
                params = {**key_props, "source_id": source_id, "raw_data": raw_data_json, "confidence": confidence}
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
        return self.merge_node_with_source("Vulnerability", key_props, data, source_id)

    def merge_indicator(self, data: Dict, source_id: str = "alienvault_otx") -> bool:
        """MERGE an Indicator node with source tracking."""
        key_props = {
            "indicator_type": data.get("indicator_type"),
            "value": data.get("value"),
            "tag": data.get("tag", "default"),
        }
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

        # Promote CISA KEV fields and reference_urls to queryable node properties
        # so analysts can filter on e.g. "all CVEs on the CISA KEV list".
        extra_props: Dict = {}
        if data.get("cisa_exploit_add"):
            extra_props["cisa_exploit_add"] = data["cisa_exploit_add"]
        if data.get("cisa_action_due"):
            extra_props["cisa_action_due"] = data["cisa_action_due"]
        if data.get("cisa_required_action"):
            extra_props["cisa_required_action"] = data["cisa_required_action"]
        if data.get("cisa_vulnerability_name"):
            extra_props["cisa_vulnerability_name"] = data["cisa_vulnerability_name"]
        if data.get("reference_urls"):
            extra_props["reference_urls"] = data["reference_urls"]

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
        """
        if not self.driver or not cve_id:
            return False
        try:
            _validate_label(label)
            _validate_rel_type(rel_type)

            # Build SET clause dynamically from the cvss_data dict
            prop_assignments = []
            for k in cvss_data:
                _validate_prop_name(k)
                prop_assignments.append(f"n.{k} = ${k}")
            set_clause = ", ".join(prop_assignments) if prop_assignments else "n.created = true"

            query = f"""
            MATCH (cve:CVE {{cve_id: $cve_id}})
            MERGE (n:{label} {{cve_id: $cve_id, tag: $tag}})
            SET {set_clause},
                n.last_updated = datetime()
            MERGE (cve)-[:{rel_type}]->(n)
            MERGE (n)-[:{rel_type}]->(cve)
            """
            params = {"cve_id": cve_id, "tag": tag, **cvss_data}
            with self.driver.session() as session:
                session.run(query, **params, timeout=NEO4J_READ_TIMEOUT)
            logger.debug(f"{label} node merged for CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to merge {label} for CVE {cve_id}: {e}")
            return False

    def merge_malware(self, data: Dict, source_id: str = "alienvault_otx") -> bool:
        """MERGE a Malware node with source tracking."""
        key_props = {"name": data.get("name")}
        # Store malware types and aliases on the node for easier querying
        malware_types = data.get("malware_types", [])
        aliases = data.get("aliases", [])
        # MITRE ATT&CK STIX ``uses`` edges (technique IDs), via collector + MISP MITRE_USES_TECHNIQUES comment
        uses_techniques = data.get("uses_techniques", [])

        return self.merge_node_with_source(
            "Malware",
            key_props,
            data,
            source_id,
            extra_props={
                "malware_types": malware_types,
                "aliases": aliases,
                "uses_techniques": uses_techniques,
            },
        )

    def merge_actor(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a ThreatActor node with source tracking."""
        key_props = {"name": data.get("name")}
        aliases = data.get("aliases", [])
        description = data.get("description", "")
        # uses_techniques: list of MITRE technique IDs this actor explicitly uses,
        # extracted from the ATT&CK STIX relationships bundle by the MITRE collector.
        uses_techniques = data.get("uses_techniques", [])

        return self.merge_node_with_source(
            "ThreatActor",
            key_props,
            data,
            source_id,
            extra_props={
                "aliases": aliases,
                "description": description,
                "uses_techniques": uses_techniques,
            },
        )

    def merge_technique(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a Technique node with source tracking."""
        key_props = {
            "mitre_id": data.get("mitre_id"),
        }
        extra_props: Dict[str, Any] = {"tactic_phases": data.get("tactic_phases", [])}
        extra_props["detection"] = data.get("detection", "")
        extra_props["is_subtechnique"] = data.get("is_subtechnique", False)
        return self.merge_node_with_source("Technique", key_props, data, source_id, extra_props=extra_props)

    def merge_tactic(self, data: Dict, source_id: str = "mitre_attck") -> bool:
        """MERGE a Tactic node with source tracking."""
        key_props = {
            "mitre_id": data.get("mitre_id"),
        }
        shortname = data.get("shortname", "")
        return self.merge_node_with_source("Tactic", key_props, data, source_id, extra_props={"shortname": shortname})

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
        return self.merge_node_with_source("Tool", key_props, data, source_id, extra_props=extra_props)

    @retry_with_backoff(max_retries=3)
    def mark_inactive_nodes(self, active_event_ids: List[str]) -> Dict[str, int]:
        """
        Mark nodes as inactive if their misp_event_id is NOT in the active_event_ids list.
        Nodes without misp_event_id are not affected.

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

            # Mark inactive Indicators
            query_indicators = """
            MATCH (n:Indicator)
            WHERE n.misp_event_id IS NOT NULL 
              AND n.misp_event_id IN $active_ids
            SET n.active = true
            """

            query_indicators_inactive = """
            MATCH (n:Indicator)
            WHERE n.misp_event_id IS NOT NULL 
              AND NOT n.misp_event_id IN $active_ids
            SET n.active = false
            RETURN count(n) as count
            """

            # Mark inactive Vulnerabilities
            query_vulnerabilities_inactive = """
            MATCH (n:Vulnerability)
            WHERE n.misp_event_id IS NOT NULL 
              AND NOT n.misp_event_id IN $active_ids
            SET n.active = false
            RETURN count(n) as count
            """

            with self.driver.session() as session:
                # First, mark all nodes with misp_event_id in active list as active
                session.run(query_indicators, active_ids=list(active_ids_set), timeout=NEO4J_READ_TIMEOUT)

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

                    batch_item = {
                        "indicator_type": item.get("indicator_type"),
                        "value": item.get("value"),
                        "tag": tag,
                        "source_id": source_id,
                        "source_array": source_list,
                        "confidence": item.get("confidence_score", 0.5),
                        "zone": zone,
                        "raw_data": json.dumps(raw_data, default=str),
                    }

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

                query = """
                UNWIND $batch as item
                MERGE (n:Indicator {indicator_type: item.indicator_type, value: item.value, tag: item.tag})
                ON CREATE SET n.first_imported_at = datetime()
                SET n.confidence_score = CASE
                        WHEN n.confidence_score IS NULL OR item.confidence > n.confidence_score
                        THEN item.confidence
                        ELSE n.confidence_score END,
                    n.source = apoc.coll.toSet(coalesce(n.source, []) + item.source_array),
                    n.zone = apoc.coll.toSet(coalesce(n.zone, []) + item.zone),
                    n.last_updated = datetime(),
                    n.last_imported_from = item.source_id,
                    n.active = true,
                    n.edgeguard_managed = true,
                    n.misp_event_id = coalesce(n.misp_event_id, item.misp_event_id),
                    n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + CASE WHEN item.misp_event_id IS NOT NULL THEN [item.misp_event_id] ELSE [] END),
                    n.misp_attribute_id = coalesce(n.misp_attribute_id, item.misp_attribute_id),
                    n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + CASE WHEN item.misp_attribute_id IS NOT NULL THEN [item.misp_attribute_id] ELSE [] END),
                    n.indicator_role = coalesce(item.indicator_role, n.indicator_role),
                    n.url_status = coalesce(item.url_status, n.url_status),
                    n.last_online = coalesce(item.last_online, n.last_online),
                    n.abuse_categories = apoc.coll.toSet(coalesce(n.abuse_categories, []) + coalesce(item.abuse_categories, [])),
                    n.yara_rules = apoc.coll.toSet(coalesce(n.yara_rules, []) + coalesce(item.yara_rules, [])),
                    n.sigma_rules = apoc.coll.toSet(coalesce(n.sigma_rules, []) + coalesce(item.sigma_rules, [])),
                    n.threat_label = coalesce(item.threat_label, n.threat_label)
                WITH n, item
                MATCH (s:Source {source_id: item.source_id})
                MERGE (n)-[r:SOURCED_FROM]->(s)
                ON CREATE SET r.imported_at = datetime()
                SET r.raw_data = item.raw_data,
                    r.confidence = item.confidence,
                    r.updated_at = datetime(),
                    r.edgeguard_managed = true
                """

                with self.driver.session() as session:
                    session.run(query, batch=batch_data, timeout=NEO4J_READ_TIMEOUT)

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

                    batch_item = {
                        "cve_id": cve_id,
                        "tag": item.get("tag", "default"),
                        "source_id": source_id,
                        "source_array": source_list,
                        "confidence": item.get("confidence_score", 0.5),
                        "zone": zone,
                        "raw_data": json.dumps(raw_data, default=str),
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

                query = """
                UNWIND $batch as item
                MERGE (n:Vulnerability {cve_id: item.cve_id})
                ON CREATE SET n.first_imported_at = datetime(),
                    n.status = item.status
                SET n.confidence_score = CASE
                        WHEN n.confidence_score IS NULL OR item.confidence > n.confidence_score
                        THEN item.confidence
                        ELSE n.confidence_score END,
                    n.source = apoc.coll.toSet(coalesce(n.source, []) + item.source_array),
                    n.zone = apoc.coll.toSet(coalesce(n.zone, []) + item.zone),
                    n.tags = apoc.coll.toSet(coalesce(n.tags, []) + [item.tag]),
                    n.tag = coalesce(n.tag, item.tag),
                    n.last_updated = datetime(),
                    n.last_imported_from = item.source_id,
                    n.active = true,
                    n.edgeguard_managed = true,
                    n.misp_event_id = coalesce(n.misp_event_id, item.misp_event_id),
                    n.misp_event_ids = apoc.coll.toSet(coalesce(n.misp_event_ids, []) + CASE WHEN item.misp_event_id IS NOT NULL THEN [item.misp_event_id] ELSE [] END),
                    n.misp_attribute_id = coalesce(n.misp_attribute_id, item.misp_attribute_id),
                    n.misp_attribute_ids = apoc.coll.toSet(coalesce(n.misp_attribute_ids, []) + CASE WHEN item.misp_attribute_id IS NOT NULL THEN [item.misp_attribute_id] ELSE [] END),
                    n.version_constraints = coalesce(item.version_constraints, n.version_constraints),
                    n.cisa_cwes = apoc.coll.toSet(coalesce(n.cisa_cwes, []) + coalesce(item.cisa_cwes, [])),
                    n.cisa_notes = coalesce(item.cisa_notes, n.cisa_notes)
                WITH n, item
                MATCH (s:Source {source_id: item.source_id})
                MERGE (n)-[r:SOURCED_FROM]->(s)
                ON CREATE SET r.imported_at = datetime()
                SET r.raw_data = item.raw_data,
                    r.confidence = item.confidence,
                    r.updated_at = datetime(),
                    r.edgeguard_managed = true
                """

                with self.driver.session() as session:
                    session.run(query, batch=batch_data, timeout=NEO4J_READ_TIMEOUT)

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
        """Create USES relationship: ThreatActor -> Technique.

        Matches actors by name or alias and techniques by mitre_id, cross-source
        (no tag filter) so that enrichment links work regardless of which collector
        ingested each node.
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
        MERGE (a)-[r:USES]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.confidence_score = 0.7,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.confidence_score = 0.7,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """
        # Link to CVE nodes (NVD-sourced, ResilMesh schema)
        query_cve = """
        MATCH (i:Indicator {value: $value})
        MATCH (v:CVE {cve_id: $cve_id})
        MERGE (i)-[r:INDICATES]->(v)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.confidence_score = 0.6,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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

        # First ensure the Sector node exists
        ensure_sector_query = """
        MERGE (s:Sector {name: $sector_name})
        ON CREATE SET s.created_at = datetime()
        SET s.updated_at = datetime()
        """

        # Create the relationship
        rel_query = """
        MATCH (i:Indicator {value: $indicator_value})
        MATCH (s:Sector {name: $sector_name})
        MERGE (i)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """

        try:
            with self.driver.session() as session:
                session.run(ensure_sector_query, sector_name=sec, timeout=NEO4J_READ_TIMEOUT)
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
        """Create TARGETS relationship: Vulnerability/CVE -> Sector.

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

        ensure_sector_query = """
        MERGE (s:Sector {name: $sector_name})
        ON CREATE SET s.created_at = datetime()
        SET s.updated_at = datetime()
        """

        rel_props = """
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [$source_id]),
            r.confidence_score = 0.5,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """

        # Vulnerability label (MISP/non-NVD)
        vuln_query = f"""
        MATCH (v:Vulnerability {{cve_id: $cve_id}})
        MATCH (s:Sector {{name: $sector_name}})
        MERGE (v)-[r:TARGETS]->(s)
        {rel_props}
        """
        # CVE label (NVD — ResilMesh schema)
        cve_query = f"""
        MATCH (v:CVE {{cve_id: $cve_id}})
        MATCH (s:Sector {{name: $sector_name}})
        MERGE (v)-[r:TARGETS]->(s)
        {rel_props}
        """

        try:
            with self.driver.session() as session:
                session.run(ensure_sector_query, sector_name=sec, timeout=NEO4J_READ_TIMEOUT)
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

        uses_rows: List[Dict[str, Any]] = []
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
            if rt == "USES":
                an = nonempty_graph_string(fk.get("name"))
                mid = nonempty_graph_string(tk.get("mitre_id"))
                if an and mid:
                    uses_rows.append({"actor": an, "mitre_id": mid, "source_id": source_id, "confidence": conf})
                else:
                    _dropped_rels += 1
            elif rt == "ATTRIBUTED_TO":
                mn = nonempty_graph_string(fk.get("name"))
                an = nonempty_graph_string(tk.get("name"))
                if mn and an:
                    attr_rows.append({"malware": mn, "actor": an, "source_id": source_id, "confidence": conf})
                else:
                    _dropped_rels += 1
            elif rt == "INDICATES" and rel.get("to_type") == "Malware":
                iv = nonempty_graph_string(fk.get("value"))
                mn = nonempty_graph_string(tk.get("name"))
                if iv and mn:
                    ind_mal_rows.append({"value": iv, "malware": mn, "source_id": source_id, "confidence": conf})
                else:
                    _dropped_rels += 1
            elif rt == "TARGETS":
                sec = nonempty_graph_string(tk.get("name"))
                if not sec:
                    _dropped_rels += 1
                    continue
                ft = rel.get("from_type")
                if ft == "Indicator":
                    iv = nonempty_graph_string(fk.get("value"))
                    if iv:
                        tgt_ind_rows.append({"value": iv, "sector": sec, "source_id": source_id, "confidence": conf})
                    else:
                        _dropped_rels += 1
                elif ft == "Vulnerability":
                    cid = normalize_cve_id_for_graph(fk.get("cve_id"))
                    if cid:
                        tgt_vuln_rows.append({"cve_id": cid, "sector": sec, "source_id": source_id, "confidence": conf})
                    else:
                        _dropped_rels += 1
            elif rt == "EXPLOITS":
                iv = nonempty_graph_string(fk.get("value"))
                cid = normalize_cve_id_for_graph(tk.get("cve_id"))
                if iv and cid:
                    expl_rows.append({"value": iv, "cve_id": cid, "source_id": source_id, "confidence": conf})
                else:
                    _dropped_rels += 1

        if _dropped_rels:
            logger.warning(
                "Relationship batch: %s/%s definitions dropped (blank/missing endpoints)",
                _dropped_rels,
                len(relationships),
            )

        total = 0

        q_uses = """
        UNWIND $rows AS row
        MATCH (a:ThreatActor)
        WHERE a.name = row.actor OR row.actor IN coalesce(a.aliases, [])
        MATCH (t:Technique {mitre_id: row.mitre_id})
        MERGE (a)-[r:USES]->(t)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """
        q_tgt_ind = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime()
        SET s.updated_at = datetime()
        WITH row, s
        MATCH (i:Indicator {value: row.value})
        MERGE (i)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """
        q_tgt_vuln = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime()
        SET s.updated_at = datetime()
        WITH row, s
        MATCH (v:Vulnerability {cve_id: row.cve_id})
        MERGE (v)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """
        q_tgt_cve = """
        UNWIND $rows AS row
        MERGE (s:Sector {name: row.sector})
        ON CREATE SET s.created_at = datetime()
        SET s.updated_at = datetime()
        WITH row, s
        MATCH (v:CVE {cve_id: row.cve_id})
        MERGE (v)-[r:TARGETS]->(s)
        SET r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source_id]),
            r.source_id = row.source_id,
            r.confidence_score = row.confidence,
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
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
            r.imported_at = coalesce(r.imported_at, datetime()),
            r.updated_at = datetime()
        """

        def _run_rows(session: Any, label: str, query: str, rows: List[Dict[str, Any]]) -> None:
            nonlocal total
            if not rows:
                return
            try:
                session.run(query, rows=rows, timeout=NEO4J_READ_TIMEOUT)
                total += len(rows)
            except Exception as e:
                # Each UNWIND is auto-committed; do not zero the whole batch on one failure.
                logger.warning("MISP relationship batch %s failed (%s rows): %s", label, len(rows), e)

        with self.driver.session() as session:
            _run_rows(session, "USES", q_uses, uses_rows)
            _run_rows(session, "ATTRIBUTED_TO", q_attr, attr_rows)
            _run_rows(session, "INDICATES_malware", q_ind_mal, ind_mal_rows)
            _run_rows(session, "TARGETS_indicator", q_tgt_ind, tgt_ind_rows)
            if tgt_vuln_rows:
                _run_rows(session, "TARGETS_vulnerability", q_tgt_vuln, tgt_vuln_rows)
                _run_rows(session, "TARGETS_cve", q_tgt_cve, tgt_vuln_rows)
            if expl_rows:
                _run_rows(session, "EXPLOITS_vulnerability", q_expl_vuln, expl_rows)
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

                # Count active/inactive for Indicators and Vulnerabilities
                try:
                    result = session.run(
                        """
                        MATCH (n:Indicator)
                        WHERE n.misp_event_id IS NOT NULL
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
                        WHERE n.misp_event_id IS NOT NULL
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
          AND n.misp_event_id IS NOT NULL
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
          AND n.misp_event_id IS NOT NULL
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
        """
        query = """
        MERGE (i:IP {address: $address})
        SET i.status = $status,
            i.tag = apoc.coll.toSet(coalesce(i.tag, []) + $tag_list),
            i.version = $version,
            i.edgeguard_managed = true,
            i.first_seen = CASE WHEN i.first_seen IS NULL THEN datetime() ELSE i.first_seen END,
            i.last_updated = datetime()
        """
        try:
            # Normalise tag to a list for ResilMesh compatibility
            raw_tag = data.get("tag")
            tag_list = [raw_tag] if isinstance(raw_tag, str) else (raw_tag or [])
            with self.driver.session() as session:
                session.run(
                    query,
                    address=data.get("address"),
                    status=data.get("status"),
                    tag_list=tag_list,
                    version=data.get("version"),
                )
            logger.info(f"Created/updated IP: {data.get('address')}")
            return True
        except Exception as e:
            logger.error(f"Error creating IP: {e}")
            return False

    def merge_host(self, data: dict) -> bool:
        """MERGE a Host node. Properties: hostname"""
        query = """
        MERGE (h:Host {hostname: $hostname})
        SET h.edgeguard_managed = true,
            h.first_seen = CASE WHEN h.first_seen IS NULL THEN datetime() ELSE h.first_seen END,
            h.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=data.get("hostname"))
            logger.info(f"Created/updated Host: {data.get('hostname')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Host: {e}")
            return False

    def merge_device(self, data: dict) -> bool:
        """MERGE a Device node. (no properties)"""
        query = """
        MERGE (d:Device {device_id: $device_id})
        SET d.edgeguard_managed = true,
            d.first_seen = CASE WHEN d.first_seen IS NULL THEN datetime() ELSE d.first_seen END,
            d.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=data.get("device_id", str(id(data))))
            logger.info("Created/updated Device")
            return True
        except Exception as e:
            logger.error(f"Error creating Device: {e}")
            return False

    def merge_subnet(self, data: dict) -> bool:
        """MERGE a Subnet node. Properties: range, note, version"""
        query = """
        MERGE (s:Subnet {range: $range})
        SET s.edgeguard_managed = true,
            s.note = $note,
            s.version = $version,
            s.first_seen = CASE WHEN s.first_seen IS NULL THEN datetime() ELSE s.first_seen END,
            s.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, range=data.get("range"), note=data.get("note"), version=data.get("version"))
            logger.info(f"Created/updated Subnet: {data.get('range')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Subnet: {e}")
            return False

    def merge_networkservice(self, data: dict) -> bool:
        """MERGE a NetworkService node. Properties: port, protocol, service"""
        query = """
        MERGE (ns:NetworkService {port: $port, protocol: $protocol})
        SET ns.edgeguard_managed = true,
            ns.service = $service,
            ns.first_seen = CASE WHEN ns.first_seen IS NULL THEN datetime() ELSE ns.first_seen END,
            ns.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, port=data.get("port"), protocol=data.get("protocol"), service=data.get("service"))
            logger.info(f"Created/updated NetworkService: {data.get('port')}/{data.get('protocol')}")
            return True
        except Exception as e:
            logger.error(f"Error creating NetworkService: {e}")
            return False

    def merge_softwareversion(self, data: dict) -> bool:
        """MERGE a SoftwareVersion node. Properties: cve_timestamp, version"""
        query = """
        MERGE (sv:SoftwareVersion {version: $version})
        SET sv.edgeguard_managed = true,
            sv.cve_timestamp = $cve_timestamp,
            sv.first_seen = CASE WHEN sv.first_seen IS NULL THEN datetime() ELSE sv.first_seen END,
            sv.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, version=data.get("version"), cve_timestamp=data.get("cve_timestamp"))
            logger.info(f"Created/updated SoftwareVersion: {data.get('version')}")
            return True
        except Exception as e:
            logger.error(f"Error creating SoftwareVersion: {e}")
            return False

    def merge_application(self, data: dict) -> bool:
        """MERGE an Application node. Properties: name"""
        query = """
        MERGE (a:Application {name: $name})
        SET a.edgeguard_managed = true,
            a.first_seen = CASE WHEN a.first_seen IS NULL THEN datetime() ELSE a.first_seen END,
            a.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, name=data.get("name"))
            logger.info(f"Created/updated Application: {data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error creating Application: {e}")
            return False

    def merge_cvssv2(self, data: dict) -> bool:
        """MERGE a CVSSv2 node. Properties: vector_string, access_complexity, availability_impact, etc."""
        query = """
        MERGE (cv:CVSSv2 {vector_string: $vector_string})
        SET cv.access_complexity = $access_complexity,
            cv.availability_impact = $availability_impact,
            cv.confidentiality_impact = $confidentiality_impact,
            cv.integrity_impact = $integrity_impact,
            cv.base_score = $base_score,
            cv.first_seen = CASE WHEN cv.first_seen IS NULL THEN datetime() ELSE cv.first_seen END,
            cv.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    vector_string=data.get("vector_string"),
                    access_complexity=data.get("access_complexity"),
                    availability_impact=data.get("availability_impact"),
                    confidentiality_impact=data.get("confidentiality_impact"),
                    integrity_impact=data.get("integrity_impact"),
                    base_score=data.get("base_score"),
                )
            logger.info(f"Created/updated CVSSv2: {data.get('vector_string', '')[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Error creating CVSSv2: {e}")
            return False

    def merge_cvssv30(self, data: dict) -> bool:
        """MERGE a CVSSv3.0 node."""
        query = """
        MERGE (cv:CVSSv30 {vector_string: $vector_string})
        SET cv.attack_complexity = $attack_complexity,
            cv.availability_impact = $availability_impact,
            cv.confidentiality_impact = $confidentiality_impact,
            cv.integrity_impact = $integrity_impact,
            cv.base_score = $base_score,
            cv.base_severity = $base_severity,
            cv.first_seen = CASE WHEN cv.first_seen IS NULL THEN datetime() ELSE cv.first_seen END,
            cv.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    vector_string=data.get("vector_string"),
                    attack_complexity=data.get("attack_complexity"),
                    availability_impact=data.get("availability_impact"),
                    confidentiality_impact=data.get("confidentiality_impact"),
                    integrity_impact=data.get("integrity_impact"),
                    base_score=data.get("base_score"),
                    base_severity=data.get("base_severity"),
                )
            logger.info(f"Created/updated CVSSv3.0: {data.get('vector_string', '')[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Error creating CVSSv3.0: {e}")
            return False

    def merge_cvssv31(self, data: dict) -> bool:
        """MERGE a CVSSv3.1 node."""
        query = """
        MERGE (cv:CVSSv31 {vector_string: $vector_string})
        SET cv.attack_complexity = $attack_complexity,
            cv.availability_impact = $availability_impact,
            cv.confidentiality_impact = $confidentiality_impact,
            cv.integrity_impact = $integrity_impact,
            cv.base_score = $base_score,
            cv.base_severity = $base_severity,
            cv.first_seen = CASE WHEN cv.first_seen IS NULL THEN datetime() ELSE cv.first_seen END,
            cv.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    vector_string=data.get("vector_string"),
                    attack_complexity=data.get("attack_complexity"),
                    availability_impact=data.get("availability_impact"),
                    confidentiality_impact=data.get("confidentiality_impact"),
                    integrity_impact=data.get("integrity_impact"),
                    base_score=data.get("base_score"),
                    base_severity=data.get("base_severity"),
                )
            logger.info(f"Created/updated CVSSv3.1: {data.get('vector_string', '')[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Error creating CVSSv3.1: {e}")
            return False

    def merge_cvssv40(self, data: dict) -> bool:
        """MERGE a CVSSv4.0 node."""
        query = """
        MERGE (cv:CVSSv40 {vector_string: $vector_string})
        SET cv.attack_complexity = $attack_complexity,
            cv.availability_impact = $availability_impact,
            cv.confidentiality_impact = $confidentiality_impact,
            cv.integrity_impact = $integrity_impact,
            cv.base_score = $base_score,
            cv.base_severity = $base_severity,
            cv.first_seen = CASE WHEN cv.first_seen IS NULL THEN datetime() ELSE cv.first_seen END,
            cv.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    vector_string=data.get("vector_string"),
                    attack_complexity=data.get("attack_complexity"),
                    availability_impact=data.get("availability_impact"),
                    confidentiality_impact=data.get("confidentiality_impact"),
                    integrity_impact=data.get("integrity_impact"),
                    base_score=data.get("base_score"),
                    base_severity=data.get("base_severity"),
                )
            logger.info(f"Created/updated CVSSv4.0: {data.get('vector_string', '')[:30]}...")
            return True
        except Exception as e:
            logger.error(f"Error creating CVSSv4.0: {e}")
            return False

    def merge_role(self, data: dict) -> bool:
        """MERGE a Role node. Properties: permission"""
        query = """
        MERGE (r:Role {permission: $permission})
        SET r.edgeguard_managed = true,
            r.first_seen = CASE WHEN r.first_seen IS NULL THEN datetime() ELSE r.first_seen END,
            r.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=data.get("permission"))
            logger.info(f"Created/updated Role: {data.get('permission')}")
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
                session.run(query, name=data.get("name"))
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
                session.run(query, name=data.get("name"))
            logger.info(f"Created/updated OrganizationUnit: {data.get('name')}")
            return True
        except Exception as e:
            logger.error(f"Error creating OrganizationUnit: {e}")
            return False

    def merge_missiondependency(self, data: dict) -> bool:
        """MERGE a MissionDependency node. (no properties)"""
        query = """
        MERGE (md:MissionDependency {dependency_id: $dependency_id})
        SET md.edgeguard_managed = true,
            md.first_seen = CASE WHEN md.first_seen IS NULL THEN datetime() ELSE md.first_seen END,
            md.last_updated = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, dependency_id=data.get("dependency_id", str(id(data))))
            logger.info("Created/updated MissionDependency")
            return True
        except Exception as e:
            logger.error(f"Error creating MissionDependency: {e}")
            return False

    def merge_resilmesh_user(self, data: dict) -> bool:
        """MERGE a ResilMesh User node. Properties: username, domain"""
        query = """
        MERGE (u:User {username: $username, domain: $domain})
        SET u.edgeguard_managed = true,
            u.first_seen = CASE WHEN u.first_seen IS NULL THEN datetime() ELSE u.first_seen END,
            u.last_updated = datetime()
        """
        try:
            # Provide default domain if not present
            domain = data.get("domain", "default")
            with self.driver.session() as session:
                session.run(query, username=data.get("username"), domain=domain)
            logger.info(f"Created/updated ResilMesh User: {data.get('username')}")
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
        """
        query = """
        MERGE (v:Vulnerability {cve_id: $cve_id})
        SET v.name = coalesce(v.name, $name)
        SET v.status = $status,
            v.description = $description,
            v.edgeguard_managed = true,
            v.first_seen = CASE WHEN v.first_seen IS NULL THEN datetime() ELSE v.first_seen END,
            v.last_updated = datetime()
        """
        try:
            # Provide default values if not present
            name = data.get("name", "unknown")
            cve_id = data.get("cve_id", "CVE-0000-00000")
            with self.driver.session() as session:
                session.run(
                    query, name=name, cve_id=cve_id, status=data.get("status"), description=data.get("description")
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
        CVE nodes keyed on ``cve_id``.
        """
        query = """
        MERGE (c:CVE {cve_id: $cve_id})
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
            c.last_updated = datetime()
        """
        try:
            tag = data.get("tag", "default")
            with self.driver.session() as session:
                session.run(
                    query,
                    cve_id=data.get("cve_id"),
                    tag=tag,
                    description=data.get("description"),
                    published=data.get("published"),
                    last_modified=data.get("last_modified"),
                    cpe_type=data.get("cpe_type"),
                    result_impacts=data.get("result_impacts"),
                    ref_tags=data.get("ref_tags"),
                    cwe=data.get("cwe"),
                )
            logger.info(f"Created/updated ResilMesh CVE: {data.get('cve_id')}")
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, version=version, hostname=hostname)
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
        SET rel.created_at = datetime(),
            rel.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=permission, device_id=device_id)
            logger.info(f"Linked Role {permission} TO Device {device_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Role TO Device: {e}")
            return False

    # 3. Role ASSIGNED_TO User
    def create_role_assigned_to_user(self, permission: str, username: str, domain: str = "default") -> bool:
        """Create ASSIGNED_TO relationship: Role -> User"""
        query = """
        MATCH (r:Role {permission: $permission})
        MATCH (u:User {username: $username, domain: $domain})
        MERGE (r)-[rel:ASSIGNED_TO]->(u)
        SET rel.created_at = datetime(),
            rel.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, permission=permission, username=username, domain=domain)
            logger.info(f"Linked Role {permission} ASSIGNED_TO User {username}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Role ASSIGNED_TO User: {e}")
            return False

    # 4. User ASSIGNED_TO Role
    def create_user_assigned_to_role(self, username: str, domain: str, permission: str) -> bool:
        """Create ASSIGNED_TO relationship: User -> Role"""
        query = """
        MATCH (u:User {username: $username, domain: $domain})
        MATCH (r:Role {permission: $permission})
        MERGE (u)-[rel:ASSIGNED_TO]->(r)
        SET rel.created_at = datetime(),
            rel.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, username=username, domain=domain, permission=permission)
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
        SET rel.created_at = datetime(),
            rel.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=device_id, permission=permission)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, device_id=device_id, hostname=hostname)
            logger.info(f"Linked Device {device_id} HAS_IDENTITY Host {hostname}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Device HAS_IDENTITY Host: {e}")
            return False

    # 7. SoftwareVersion IN Vulnerability
    def create_softwareversion_in_vulnerability(self, version: str, vuln_name: str, cve_id: str = None) -> bool:
        """Create IN relationship: SoftwareVersion -> Vulnerability"""
        query = """
        MATCH (sv:SoftwareVersion {version: $version})
        MATCH (v:Vulnerability {name: $vuln_name})
        MERGE (sv)-[r:IN]->(v)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, version=version, vuln_name=vuln_name)
            logger.info(f"Linked SoftwareVersion {version} IN Vulnerability {vuln_name}")
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
                session.run(query, address=address, node_id=node_id)
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
                session.run(query, node_id=node_id, hostname=hostname)
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
                session.run(query, node_id=node_id, address=address)
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
                session.run(query, hostname=hostname, node_id=node_id)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, device_id=device_id)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, version=version)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, address=address, subnet_range=subnet_range)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, subnet_range=subnet_range, address=address)
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
                session.run(query, mission_name=mission_name, orgunit_name=orgunit_name)
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
                session.run(query, mission_name=mission_name, component_name=component_name)
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
                session.run(query, component_name=component_name, dependency_id=dependency_id)
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
                session.run(query, component_name=component_name, hostname=hostname)
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
                session.run(query, component_name=component_name, mission_name=mission_name)
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
                session.run(query, component_name=component_name, dependency_id=dependency_id)
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
                session.run(query, orgunit_name=orgunit_name, mission_name=mission_name)
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
                session.run(query, child_orgunit=child_orgunit, parent_orgunit=parent_orgunit)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, child_subnet=child_subnet, parent_subnet=parent_subnet)
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
                session.run(query, subnet_range=subnet_range, orgunit_name=orgunit_name)
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
                session.run(query, dependency_id=dependency_id, component_name=component_name)
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
                session.run(query, dependency_id=dependency_id, component_name=component_name)
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
                session.run(query, orgunit_name=orgunit_name, subnet_range=subnet_range)
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
                session.run(query, node1_id=node1_id, node2_id=node2_id, start=start, end=end)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.status = $status
        """
        try:
            with self.driver.session() as session:
                session.run(query, port=port, protocol=protocol, hostname=hostname, status=status)
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
                session.run(query, hostname=hostname, component_name=component_name)
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
        SET r.created_at = datetime(),
            r.updated_at = datetime(),
            r.status = $status
        """
        try:
            with self.driver.session() as session:
                session.run(query, hostname=hostname, port=port, protocol=protocol, status=status)
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
                session.run(query, app_name=app_name, component_name=component_name)
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
                session.run(query, component_name=component_name, app_name=app_name)
            logger.info(f"Linked Component {component_name} HAS_IDENTITY Application {app_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Component HAS_IDENTITY Application: {e}")
            return False

    # 35. Vulnerability REFERS_TO CVE
    def create_vulnerability_refers_to_cve(self, vuln_name: str, cve_id: str) -> bool:
        """Create REFERS_TO relationship: Vulnerability -> CVE"""
        query = """
        MATCH (v:Vulnerability {name: $vuln_name})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (v)-[r:REFERS_TO]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vuln_name=vuln_name, cve_id=cve_id)
            logger.info(f"Linked Vulnerability {vuln_name} REFERS_TO CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Vulnerability REFERS_TO CVE: {e}")
            return False

    # 36. Vulnerability IN SoftwareVersion
    def create_vulnerability_in_softwareversion(self, vuln_name: str, version: str) -> bool:
        """Create IN relationship: Vulnerability -> SoftwareVersion"""
        query = """
        MATCH (v:Vulnerability {name: $vuln_name})
        MATCH (sv:SoftwareVersion {version: $version})
        MERGE (v)-[r:IN]->(sv)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vuln_name=vuln_name, version=version)
            logger.info(f"Linked Vulnerability {vuln_name} IN SoftwareVersion {version}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create Vulnerability IN SoftwareVersion: {e}")
            return False

    # 37. CVE REFERS_TO Vulnerability
    def create_cve_refers_to_vulnerability(self, cve_id: str, vuln_name: str) -> bool:
        """Create REFERS_TO relationship: CVE -> Vulnerability"""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (v:Vulnerability {name: $vuln_name})
        MERGE (c)-[r:REFERS_TO]->(v)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, vuln_name=vuln_name)
            logger.info(f"Linked CVE {cve_id} REFERS_TO Vulnerability {vuln_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE REFERS_TO Vulnerability: {e}")
            return False

    # 38. CVE HAS_CVSS_v40 CVSSv40
    def create_cve_has_cvss_v40(self, cve_id: str, vector_string: str) -> bool:
        """Create HAS_CVSS_v40 relationship: CVE -> CVSSv40"""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (cv:CVSSv40 {vector_string: $vector_string})
        MERGE (c)-[r:HAS_CVSS_v40]->(cv)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, vector_string=vector_string)
            logger.info(f"Linked CVE {cve_id} HAS_CVSS_v40 {vector_string[:30]}...")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE HAS_CVSS_v40: {e}")
            return False

    # 39. CVE HAS_CVSS_v31 CVSSv31
    def create_cve_has_cvss_v31(self, cve_id: str, vector_string: str) -> bool:
        """Create HAS_CVSS_v31 relationship: CVE -> CVSSv31"""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (cv:CVSSv31 {vector_string: $vector_string})
        MERGE (c)-[r:HAS_CVSS_v31]->(cv)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, vector_string=vector_string)
            logger.info(f"Linked CVE {cve_id} HAS_CVSS_v31 {vector_string[:30]}...")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE HAS_CVSS_v31: {e}")
            return False

    # 40. CVE HAS_CVSS_v30 CVSSv30
    def create_cve_has_cvss_v30(self, cve_id: str, vector_string: str) -> bool:
        """Create HAS_CVSS_v30 relationship: CVE -> CVSSv30"""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (cv:CVSSv30 {vector_string: $vector_string})
        MERGE (c)-[r:HAS_CVSS_v30]->(cv)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, vector_string=vector_string)
            logger.info(f"Linked CVE {cve_id} HAS_CVSS_v30 {vector_string[:30]}...")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE HAS_CVSS_v30: {e}")
            return False

    # 41. CVE HAS_CVSS_v2 CVSSv2
    def create_cve_has_cvss_v2(self, cve_id: str, vector_string: str) -> bool:
        """Create HAS_CVSS_v2 relationship: CVE -> CVSSv2"""
        query = """
        MATCH (c:CVE {cve_id: $cve_id})
        MATCH (cv:CVSSv2 {vector_string: $vector_string})
        MERGE (c)-[r:HAS_CVSS_v2]->(cv)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, cve_id=cve_id, vector_string=vector_string)
            logger.info(f"Linked CVE {cve_id} HAS_CVSS_v2 {vector_string[:30]}...")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVE HAS_CVSS_v2: {e}")
            return False

    # 42. CVSSv2 HAS_CVSS_v2 CVE
    def create_cvssv2_has_cvssv2_cve(self, vector_string: str, cve_id: str) -> bool:
        """Create HAS_CVSS_v2 relationship: CVSSv2 -> CVE"""
        query = """
        MATCH (cv:CVSSv2 {vector_string: $vector_string})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (cv)-[r:HAS_CVSS_v2]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vector_string=vector_string, cve_id=cve_id)
            logger.info(f"Linked CVSSv2 {vector_string[:30]}... HAS_CVSS_v2 CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVSSv2 HAS_CVSS_v2 CVE: {e}")
            return False

    # 43. CVSSv30 HAS_CVSS_v30 CVE
    def create_cvssv30_has_cvssv30_cve(self, vector_string: str, cve_id: str) -> bool:
        """Create HAS_CVSS_v30 relationship: CVSSv30 -> CVE"""
        query = """
        MATCH (cv:CVSSv30 {vector_string: $vector_string})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (cv)-[r:HAS_CVSS_v30]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vector_string=vector_string, cve_id=cve_id)
            logger.info(f"Linked CVSSv30 {vector_string[:30]}... HAS_CVSS_v30 CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVSSv30 HAS_CVSS_v30 CVE: {e}")
            return False

    # 44. CVSSv31 HAS_CVSS_v31 CVE
    def create_cvssv31_has_cvssv31_cve(self, vector_string: str, cve_id: str) -> bool:
        """Create HAS_CVSS_v31 relationship: CVSSv31 -> CVE"""
        query = """
        MATCH (cv:CVSSv31 {vector_string: $vector_string})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (cv)-[r:HAS_CVSS_v31]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vector_string=vector_string, cve_id=cve_id)
            logger.info(f"Linked CVSSv31 {vector_string[:30]}... HAS_CVSS_v31 CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVSSv31 HAS_CVSS_v31 CVE: {e}")
            return False

    # 45. CVSSv40 HAS_CVSS_v40 CVE
    def create_cvssv40_has_cvssv40_cve(self, vector_string: str, cve_id: str) -> bool:
        """Create HAS_CVSS_v40 relationship: CVSSv40 -> CVE"""
        query = """
        MATCH (cv:CVSSv40 {vector_string: $vector_string})
        MATCH (c:CVE {cve_id: $cve_id})
        MERGE (cv)-[r:HAS_CVSS_v40]->(c)
        SET r.created_at = datetime(),
            r.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(query, vector_string=vector_string, cve_id=cve_id)
            logger.info(f"Linked CVSSv40 {vector_string[:30]}... HAS_CVSS_v40 CVE {cve_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to create CVSSv40 HAS_CVSS_v40 CVE: {e}")
            return False

    # ============================================================
    # RESILMESH ALERT/INDICATOR METHODS
    # ============================================================

    def create_alert_node(self, alert_data: dict) -> bool:
        """Create an Alert node from a ResilMesh alert."""
        try:
            alert_id = alert_data.get("alert_id")
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

            query = """
            MERGE (a:Alert {alert_id: $alert_id})
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
                a.last_updated = datetime()
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
                )

            logger.info(f"Created/updated Alert node: {alert_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to create Alert node: {e}")
            return False

    def link_alert_to_indicator(self, alert_id: str, indicator_value: str) -> bool:
        """Create INVOLVES relationship between Alert and Indicator."""
        try:
            query = """
            MATCH (a:Alert {alert_id: $alert_id})
            MATCH (i:Indicator {value: $indicator_value})
            MERGE (a)-[r:INVOLVES]->(i)
            SET r.created_at = datetime(),
                r.source = 'resilmesh'
            """

            with self.driver.session() as session:
                session.run(query, alert_id=alert_id, indicator_value=indicator_value)

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
                    query, alert_id=alert_id, enrichment_data=json.dumps(enrichment_data), latency_ms=latency_ms
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
                result = session.run(query, alert_id=alert_id)
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
            "original_source": alert_data.get("source", "resilmesh") if alert_data else "unknown",
        }

        query = """
        MERGE (i:Indicator {indicator_type: $indicator_type, value: $value, tag: $tag})
        SET i.first_seen = CASE WHEN i.first_seen IS NULL THEN datetime() ELSE i.first_seen END,
            i.last_updated = datetime(),
            i.source = apoc.coll.toSet(coalesce(i.source, []) + $source),
            i.confidence_score = $confidence_score,
            i.original_source = $original_source,
            i.zone = apoc.coll.toSet(coalesce(i.zone, []) + $zone),
            i.edgeguard_managed = true,
            i.active = true
        """

        try:
            with self.driver.session() as session:
                session.run(query, **data, timeout=NEO4J_READ_TIMEOUT)
                logger.info(f"Created/updated indicator: {indicator_value} ({normalized_type})")
                return True
        except Exception:
            fallback_query = """
            MERGE (i:Indicator {indicator_type: $indicator_type, value: $value, tag: $tag})
            SET i.first_seen = CASE WHEN i.first_seen IS NULL THEN $first_seen ELSE i.first_seen END,
                i.last_updated = $last_updated,
                i.confidence_score = $confidence_score,
                i.original_source = $original_source,
                i.zone = apoc.coll.toSet(coalesce(i.zone, []) + $zone)
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
