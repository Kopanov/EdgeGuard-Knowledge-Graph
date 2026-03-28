#!/usr/bin/env python3
"""
EdgeGuard - Health Check Module

Provides health check functionality for MISP and Neo4j connectivity.
Used by the monitoring system and CLI to report system status.
"""

import concurrent.futures
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import urllib3

from config import (
    MISP_API_KEY,
    MISP_URL,
    NEO4J_PASSWORD,
    NEO4J_URI,
    NEO4J_USER,
    SSL_VERIFY,
    apply_misp_http_host_header,
)
from neo4j_client import Neo4jClient

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

# Configuration constants
MISP_CONNECT_TIMEOUT = 30
MISP_REQUEST_TIMEOUT = 300  # Match run_misp_to_neo4j — large events need 5 min


def health_check_misp(misp_url: str = None, misp_api_key: str = None) -> Dict[str, Any]:
    """
    Check MISP health by making a test API call.

    Args:
        misp_url: MISP URL (defaults to config MISP_URL)
        misp_api_key: MISP API key (defaults to config MISP_API_KEY)

    Returns:
        Dict with health status:
        - healthy: bool
        - response_time_ms: float
        - status_code: int (if applicable)
        - error: str (if not healthy)
    """
    url = misp_url or MISP_URL
    api_key = misp_api_key or MISP_API_KEY

    try:
        session = requests.Session()
        session.headers.update(
            {
                "Authorization": api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        apply_misp_http_host_header(session)

        start_time = time.time()
        response = session.get(
            f"{url}/users/view", verify=SSL_VERIFY, timeout=(MISP_CONNECT_TIMEOUT, MISP_REQUEST_TIMEOUT)
        )
        response_time = time.time() - start_time

        if response.status_code == 200:
            return {
                "healthy": True,
                "response_time_ms": round(response_time * 1000, 2),
                "status_code": response.status_code,
            }
        else:
            return {
                "healthy": False,
                "error": f"HTTP {response.status_code}",
                "response_time_ms": round(response_time * 1000, 2),
            }

    except requests.exceptions.ConnectionError as e:
        logger.error(f"MISP connection error: {e}")
        return {"healthy": False, "error": f"Connection error: {e}"}
    except requests.exceptions.Timeout as e:
        logger.error(f"MISP timeout: {e}")
        return {"healthy": False, "error": f"Timeout: {e}"}
    except Exception as e:
        logger.error(f"MISP health check failed: {type(e).__name__}: {e}")
        return {"healthy": False, "error": f"{type(e).__name__}: {e}"}


def health_check_neo4j(neo4j_uri: str = None, neo4j_user: str = None, neo4j_password: str = None) -> Dict[str, Any]:
    """
    Check Neo4j health by connecting and running a test query.

    Args:
        neo4j_uri: Neo4j URI (defaults to config NEO4J_URI)
        neo4j_user: Neo4j user (defaults to config NEO4J_USER)
        neo4j_password: Neo4j password (defaults to config NEO4J_PASSWORD)

    Returns:
        Dict with health status:
        - healthy: bool
        - response_time_ms: float
        - database: str
        - version: str
        - edition: str
        - error: str (if not healthy)
    """
    uri = neo4j_uri or NEO4J_URI
    user = neo4j_user or NEO4J_USER
    password = neo4j_password or NEO4J_PASSWORD

    neo4j_health_timeout = 30  # seconds

    def _run_neo4j_health():
        client = Neo4jClient(uri=uri, user=user, password=password)
        if not client.connect():
            return {"healthy": False, "error": "Failed to connect to Neo4j"}
        health = client.health_check()
        client.close()
        return health

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_neo4j_health)
            return future.result(timeout=neo4j_health_timeout)

    except concurrent.futures.TimeoutError:
        logger.error(f"Neo4j health check timed out after {neo4j_health_timeout}s")
        return {"healthy": False, "error": f"Health check timed out after {neo4j_health_timeout}s"}
    except Exception as e:
        logger.error(f"Neo4j health check failed: {type(e).__name__}: {e}")
        return {"healthy": False, "error": f"{type(e).__name__}: {e}"}


def get_neo4j_node_counts(neo4j_uri: str = None, neo4j_user: str = None, neo4j_password: str = None) -> Dict[str, Any]:
    """
    Get node counts from Neo4j for all relevant labels.

    Args:
        neo4j_uri: Neo4j URI (defaults to config NEO4J_URI)
        neo4j_user: Neo4j user (defaults to config NEO4J_USER)
        neo4j_password: Neo4j password (defaults to config NEO4J_PASSWORD)

    Returns:
        Dict with counts for each node type
    """
    uri = neo4j_uri or NEO4J_URI
    user = neo4j_user or NEO4J_USER
    password = neo4j_password or NEO4J_PASSWORD

    counts = {}

    try:
        client = Neo4jClient(uri=uri, user=user, password=password)

        if not client.connect():
            return {"error": "Failed to connect to Neo4j"}

        stats = client.get_stats()
        client.close()

        # Extract relevant counts
        counts = {
            "vulnerabilities": stats.get("Vulnerability", 0),
            "indicators": stats.get("Indicator", 0),
            "cve": stats.get("CVE", 0),
            "malware": stats.get("Malware", 0),
            "threat_actors": stats.get("ThreatActor", 0),
            "techniques": stats.get("Technique", 0),
            "sources": stats.get("Sources", 0),
            "relationships": stats.get("sourced_relationships", 0),
        }

    except Exception as e:
        logger.error(f"Failed to get Neo4j node counts: {e}")
        counts = {"error": str(e)}

    return counts


def get_last_pipeline_run() -> Optional[str]:
    """
    Get the timestamp of the last successful pipeline run.

    Returns:
        ISO format timestamp string or None if no record found
    """
    # Check for metrics file which stores last run info
    metrics_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "metrics.json")

    try:
        if os.path.exists(metrics_path):
            import json

            with open(metrics_path, "r") as f:
                metrics = json.load(f)
                last_run = metrics.get("last_run")
                if last_run:
                    return last_run
    except Exception as e:
        logger.debug(f"Could not read last pipeline run: {e}")

    return None


def health_check() -> Dict[str, Any]:
    """
    Perform comprehensive health check of all EdgeGuard services.

    Returns:
        Dict with health status:
        - misp_healthy: bool
        - neo4j_healthy: bool
        - misp_details: dict
        - neo4j_details: dict
        - last_pipeline_run: str (ISO timestamp or None)
        - node_counts: dict
        - timestamp: str (ISO timestamp of this check)
        - overall_healthy: bool
    """
    logger.info("Running EdgeGuard health check...")

    # Check MISP health
    misp_health = health_check_misp()

    # Check Neo4j health
    neo4j_health = health_check_neo4j()

    # Get node counts if Neo4j is healthy
    node_counts = {}
    if neo4j_health.get("healthy"):
        node_counts = get_neo4j_node_counts()

    # Get last pipeline run
    last_run = get_last_pipeline_run()

    # Determine overall health
    overall_healthy = misp_health.get("healthy", False) and neo4j_health.get("healthy", False)

    result = {
        "misp_healthy": misp_health.get("healthy", False),
        "neo4j_healthy": neo4j_health.get("healthy", False),
        "misp_details": misp_health,
        "neo4j_details": neo4j_health,
        "last_pipeline_run": last_run,
        "node_counts": node_counts,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "overall_healthy": overall_healthy,
    }

    logger.info(f"Health check complete: MISP={result['misp_healthy']}, Neo4j={result['neo4j_healthy']}")

    return result


def format_health_status(status: Dict[str, Any]) -> str:
    """
    Format health check results as a human-readable string.

    Args:
        status: Health check result dict from health_check()

    Returns:
        Formatted string
    """
    lines = [
        "=" * 50,
        "EdgeGuard Health Status",
        "=" * 50,
        "",
        f"Overall Status: {'✅ HEALTHY' if status['overall_healthy'] else '❌ UNHEALTHY'}",
        f"Check Time: {status['timestamp']}",
        "",
        "MISP:",
        f"  Status: {'✅ Healthy' if status['misp_healthy'] else '❌ Unhealthy'}",
    ]

    if status["misp_healthy"]:
        misp = status["misp_details"]
        lines.append(f"  Response Time: {misp.get('response_time_ms', 'N/A')} ms")
    else:
        lines.append(f"  Error: {status['misp_details'].get('error', 'Unknown')}")

    lines.extend(
        [
            "",
            "Neo4j:",
            f"  Status: {'✅ Healthy' if status['neo4j_healthy'] else '❌ Unhealthy'}",
        ]
    )

    if status["neo4j_healthy"]:
        neo4j = status["neo4j_details"]
        lines.append(f"  Response Time: {neo4j.get('response_time_ms', 'N/A')} ms")
        lines.append(f"  Version: {neo4j.get('version', 'Unknown')}")
        lines.append(f"  Edition: {neo4j.get('edition', 'Unknown')}")
        if neo4j.get("apoc_available") is True:
            lines.append("  APOC: ✅ loaded (required for MISP→Neo4j sync)")
    else:
        lines.append(f"  Error: {status['neo4j_details'].get('error', 'Unknown')}")

    lines.extend(
        [
            "",
            "Node Counts:",
        ]
    )

    counts = status.get("node_counts", {})
    if "error" in counts:
        lines.append(f"  Error: {counts['error']}")
    else:
        lines.append(f"  Vulnerabilities: {counts.get('vulnerabilities', 0)}")
        lines.append(f"  Indicators: {counts.get('indicators', 0)}")
        lines.append(f"  CVE: {counts.get('cve', 0)}")
        lines.append(f"  Malware: {counts.get('malware', 0)}")
        lines.append(f"  Threat Actors: {counts.get('threat_actors', 0)}")
        lines.append(f"  Techniques: {counts.get('techniques', 0)}")
        lines.append(f"  Sources: {counts.get('sources', 0)}")
        lines.append(f"  Relationships: {counts.get('relationships', 0)}")

    lines.extend(
        [
            "",
            f"Last Pipeline Run: {status['last_pipeline_run'] or 'Never'}",
            "=" * 50,
        ]
    )

    return "\n".join(lines)


def main():
    """CLI entry point for health check."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    status = health_check()
    print(format_health_status(status))

    # Exit with appropriate code
    sys.exit(0 if status["overall_healthy"] else 1)


if __name__ == "__main__":
    main()
