#!/usr/bin/env python3
"""
EdgeGuard Prometheus Metrics Server

Exposes Prometheus metrics for EdgeGuard threat intelligence pipeline.
Can run as standalone server or embedded thread.

Metrics exposed:
- edgeguard_indicators_collected_total - Total indicators collected by source/zone
- edgeguard_collection_failures_total - Collection failures by source
- edgeguard_collection_duration_seconds - Collection duration histogram
- edgeguard_misp_events_total - MISP events by source
- edgeguard_misp_attributes_total - MISP attributes by type
- edgeguard_neo4j_nodes - Neo4j node counts by label
- edgeguard_neo4j_relationships - Neo4j relationship counts
- edgeguard_neo4j_sync_duration_seconds - Neo4j sync duration
- edgeguard_circuit_breaker_state - Circuit breaker state (0=closed, 1=half-open, 2=open)
- edgeguard_service_up - Service health (1=up, 0=down)
- edgeguard_last_success_timestamp - Unix timestamp of last successful collection
- edgeguard_pipeline_duration_seconds - Total pipeline duration
- edgeguard_dag_runs_total - DAG run counter by status
"""

import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Dict, Optional

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Prometheus client
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    raise ImportError("prometheus_client not installed. Run: pip install prometheus_client")

# Import existing metrics from resilience module
from resilience import PROMETHEUS_AVAILABLE as RESILIENCE_PROMETHEUS_AVAILABLE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ================================================================================
# METRICS REGISTRY - EdgeGuard Metrics
# ================================================================================

# Use the default registry to include resilience.py metrics
registry = REGISTRY

# Application info
APP_INFO = Info("edgeguard", "EdgeGuard application information")

# Collection metrics
INDICATORS_COLLECTED = Counter(
    "edgeguard_indicators_collected_total", "Total indicators collected", ["source", "zone", "status"]
)

COLLECTOR_SKIPS = Counter(
    "edgeguard_collector_skips_total",
    "Collector skipped (optional source, e.g. missing API key) — task still succeeded",
    ["source", "reason_class"],
)

COLLECTION_DURATION = Histogram(
    "edgeguard_collection_duration_seconds",
    "Time spent collecting indicators",
    ["source", "zone"],
    buckets=[0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
)

# MISP metrics
MISP_EVENTS = Counter("edgeguard_misp_events_total", "Total MISP events created", ["source", "zone"])

MISP_ATTRIBUTES = Counter("edgeguard_misp_attributes_total", "Total MISP attributes created", ["type", "source"])

MISP_PUSH_DURATION = Histogram(
    "edgeguard_misp_push_duration_seconds",
    "Time spent pushing to MISP",
    ["source"],
    buckets=[0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
)

MISP_HEALTH = Gauge("edgeguard_misp_health", "MISP health status (1=healthy, 0=unhealthy)", ["check_type"])

# Neo4j metrics
NEO4J_NODES = Gauge("edgeguard_neo4j_nodes", "Number of nodes in Neo4j by label", ["label", "zone"])

NEO4J_RELATIONSHIPS = Gauge("edgeguard_neo4j_relationships", "Number of relationships in Neo4j by type", ["rel_type"])

NEO4J_SYNC_DURATION = Histogram(
    "edgeguard_neo4j_sync_duration_seconds",
    "Time spent syncing MISP to Neo4j",
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)

NEO4J_QUERIES = Counter("edgeguard_neo4j_queries_total", "Total Neo4j queries executed", ["query_type", "status"])

NEO4J_QUERY_DURATION = Histogram(
    "edgeguard_neo4j_query_duration_seconds",
    "Time spent on Neo4j queries",
    ["query_type"],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
)

# Pipeline metrics
PIPELINE_DURATION = Histogram(
    "edgeguard_pipeline_duration_seconds",
    "Total pipeline execution time",
    ["pipeline_type"],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0],
)

PIPELINE_ERRORS = Counter("edgeguard_pipeline_errors_total", "Total pipeline errors", ["task", "error_type", "source"])

PIPELINE_STAGES = Gauge("edgeguard_pipeline_stage", "Current pipeline stage (1=running, 0=idle)", ["stage"])

# DAG/Airflow metrics
DAG_RUNS = Counter("edgeguard_dag_runs_total", "Total DAG runs", ["dag_id", "status", "run_type"])

# Stuck-run detection: set to time.time() on success, alert if stale
DAG_LAST_SUCCESS = Gauge(
    "edgeguard_dag_last_success_timestamp",
    "Unix timestamp of last successful DAG run (0 = never succeeded)",
    ["dag_id"],
)

DAG_RUN_START = Gauge(
    "edgeguard_dag_run_start_timestamp",
    "Unix timestamp when the current DAG run started (0 = idle)",
    ["dag_id"],
)

DAG_RUN_DURATION = Histogram(
    "edgeguard_dag_run_duration_seconds",
    "DAG run duration",
    ["dag_id"],
    buckets=[30.0, 60.0, 120.0, 300.0, 600.0, 1200.0],
)

TASK_DURATION = Histogram(
    "edgeguard_task_duration_seconds",
    "Individual task duration",
    ["task_id", "dag_id"],
    buckets=[1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0],
)

# Data source health
SOURCE_HEALTH = Gauge(
    "edgeguard_source_health", "Data source health status (1=healthy, 0=unhealthy)", ["source", "zone"]
)

SOURCE_LATENCY = Histogram(
    "edgeguard_source_latency_seconds",
    "Data source response latency",
    ["source"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

# Processing metrics
INDICATORS_PROCESSED = Counter(
    "edgeguard_indicators_processed_total",
    "Total indicators processed (enriched, transformed)",
    ["operation", "status"],
)

ENRICHMENT_DURATION = Histogram(
    "edgeguard_enrichment_duration_seconds",
    "Time spent enriching indicators",
    ["enricher_type"],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

# Set application info
APP_INFO.info(
    {"version": os.getenv("EDGEGUARD_VERSION", "1.0.0"), "environment": os.getenv("EDGEGUARD_ENV", "development")}
)

# ================================================================================
# HELPER FUNCTIONS
# ================================================================================


def record_collection(source: str, zone: str, count: int, status: str = "success"):
    """Record indicator collection."""
    INDICATORS_COLLECTED.labels(source=source, zone=zone, status=status).inc(count)


def record_collector_skip(source: str, reason_class: str = "missing_api_key"):
    """Record that an optional collector was skipped (e.g. no API key)."""
    safe = (reason_class or "unknown").replace('"', "")[:80]
    COLLECTOR_SKIPS.labels(source=source, reason_class=safe).inc()


def record_collection_duration(source: str, zone: str, duration: float):
    """Record collection duration."""
    COLLECTION_DURATION.labels(source=source, zone=zone).observe(duration)


def record_misp_push(source: str, zone: str, event_count: int, attr_count: int, duration: float):
    """Record MISP push metrics."""
    MISP_EVENTS.labels(source=source, zone=zone).inc(event_count)
    MISP_PUSH_DURATION.labels(source=source).observe(duration)


def record_misp_attribute(indicator_type: str, source: str):
    """Record MISP attribute creation."""
    MISP_ATTRIBUTES.labels(type=indicator_type, source=source).inc()


def record_neo4j_sync(node_counts: Dict[str, int], duration: float):
    """Record Neo4j sync metrics."""
    NEO4J_SYNC_DURATION.observe(duration)
    for label, count in node_counts.items():
        zone = "unknown"
        if ":" in label:
            label, zone = label.split(":", 1)
        NEO4J_NODES.labels(label=label, zone=zone).set(count)


def record_neo4j_relationships(rel_counts: Dict[str, int]):
    """Record Neo4j relationship counts."""
    for rel_type, count in rel_counts.items():
        NEO4J_RELATIONSHIPS.labels(rel_type=rel_type).set(count)


def record_pipeline_duration(pipeline_type: str, duration: float):
    """Record pipeline execution duration."""
    PIPELINE_DURATION.labels(pipeline_type=pipeline_type).observe(duration)


def record_pipeline_error(task: str, error_type: str, source: str = "unknown"):
    """Record pipeline error."""
    PIPELINE_ERRORS.labels(task=task, error_type=error_type, source=source).inc()


def record_dag_run(dag_id: str, status: str, run_type: str = "scheduled"):
    """Record DAG run."""
    DAG_RUNS.labels(dag_id=dag_id, status=status, run_type=run_type).inc()


def record_task_duration(task_id: str, dag_id: str, duration: float):
    """Record task execution duration."""
    TASK_DURATION.labels(task_id=task_id, dag_id=dag_id).observe(duration)


def set_source_health(source: str, zone: str, healthy: bool):
    """Set source health status."""
    SOURCE_HEALTH.labels(source=source, zone=zone).set(1 if healthy else 0)


def record_source_latency(source: str, latency: float):
    """Record source response latency."""
    SOURCE_LATENCY.labels(source=source).observe(latency)


def set_misp_health(api_healthy: bool, db_healthy: bool, workers_healthy: bool):
    """Set MISP health status."""
    MISP_HEALTH.labels(check_type="api").set(1 if api_healthy else 0)
    MISP_HEALTH.labels(check_type="database").set(1 if db_healthy else 0)
    MISP_HEALTH.labels(check_type="workers").set(1 if workers_healthy else 0)


def set_pipeline_stage(stage: str, running: bool):
    """Set pipeline stage status."""
    PIPELINE_STAGES.labels(stage=stage).set(1 if running else 0)


def record_indicators_processed(operation: str, count: int, status: str = "success"):
    """Record processed indicators."""
    INDICATORS_PROCESSED.labels(operation=operation, status=status).inc(count)


def record_enrichment_duration(enricher_type: str, duration: float):
    """Record enrichment duration."""
    ENRICHMENT_DURATION.labels(enricher_type=enricher_type).observe(duration)


def get_all_metrics() -> bytes:
    """Get all metrics in Prometheus format."""
    return generate_latest(registry)


# ================================================================================
# HTTP SERVER
# ================================================================================


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

    allow_reuse_address = True
    daemon_threads = True


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Prometheus metrics."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        logger.debug(f"{self.address_string()} - {format % args}")

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(get_all_metrics())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            health_status = {
                "status": "healthy",
                "timestamp": time.time(),
                "metrics_enabled": True,
                "resilience_metrics": RESILIENCE_PROMETHEUS_AVAILABLE,
            }
            self.wfile.write(json.dumps(health_status).encode())
        elif self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html>
                <head><title>EdgeGuard Metrics</title></head>
                <body>
                <h1>EdgeGuard Prometheus Metrics</h1>
                <p><a href="/metrics">Metrics</a></p>
                <p><a href="/health">Health Check</a></p>
                </body>
                </html>
            """)
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests."""
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


# ================================================================================
# SERVER CLASSES
# ================================================================================


class MetricsServer:
    """
    Standalone Prometheus metrics server for EdgeGuard.

    Usage:
        # Standalone mode
        server = MetricsServer(port=8001)
        server.start()

        # Embedded mode (as thread)
        server = MetricsServer(port=8001)
        server.start_threaded()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8001):
        self.host = host
        self.port = port
        self.server: Optional[ThreadedHTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the metrics server (blocking)."""
        self.server = ThreadedHTTPServer((self.host, self.port), MetricsHandler)
        self._running = True
        logger.info(f"Prometheus metrics server starting on http://{self.host}:{self.port}")
        logger.info(f"  - Metrics: http://{self.host}:{self.port}/metrics")
        logger.info(f"  - Health:  http://{self.host}:{self.port}/health")

        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down metrics server...")
            self.stop()

    def start_threaded(self) -> threading.Thread:
        """Start the metrics server in a separate thread (non-blocking)."""
        self.server = ThreadedHTTPServer((self.host, self.port), MetricsHandler)
        self._running = True

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        logger.info(f"Prometheus metrics server started in thread on http://{self.host}:{self.port}")
        logger.info(f"  - Metrics: http://{self.host}:{self.port}/metrics")
        logger.info(f"  - Health:  http://{self.host}:{self.port}/health")

        return self.thread

    def stop(self):
        """Stop the metrics server."""
        self._running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Metrics server stopped")

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


# ================================================================================
# SINGLETON INSTANCE
# ================================================================================

_server_instance: Optional[MetricsServer] = None


def get_metrics_server(host: str = None, port: int = None) -> MetricsServer:
    """
    Get or create the singleton metrics server instance.

    Usage:
        server = get_metrics_server(port=8001)
        server.start_threaded()  # Start in background thread
    """
    global _server_instance

    if _server_instance is None:
        host = host or os.getenv("EDGEGUARD_METRICS_HOST", "127.0.0.1")
        if port is None:
            try:
                port = int(os.getenv("EDGEGUARD_METRICS_PORT", "8001"))
            except (ValueError, TypeError):
                port = 8001
        _server_instance = MetricsServer(host=host, port=port)

    return _server_instance


def start_metrics_server(host: str = None, port: int = None, threaded: bool = True) -> Optional[MetricsServer]:
    """
    Convenience function to start the metrics server.

    Args:
        host: Bind host (default: 127.0.0.1)
        port: Bind port (default: 8001)
        threaded: If True, start in background thread; if False, block

    Returns:
        MetricsServer instance if threaded, None if blocking
    """
    server = get_metrics_server(host, port)

    if threaded:
        server.start_threaded()
        return server
    else:
        server.start()
        return None


# ================================================================================
# MAIN
# ================================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="EdgeGuard Prometheus Metrics Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Bind port (default: 8001)")
    parser.add_argument("--test-metrics", action="store_true", help="Generate test metrics")

    args = parser.parse_args()

    # Generate test metrics if requested
    if args.test_metrics:
        logger.info("Generating test metrics...")

        # Simulate some data
        for source in ["otx", "nvd", "cisa", "misp", "abuseipdb"]:
            record_collection(source, "global", 100, "success")
            record_collection(source, "global", 5, "failed")
            set_source_health(source, "global", True)
            record_collection_duration(source, "global", 5.0)
            record_misp_push(source, "global", 10, 100, 2.0)

        # Neo4j metrics
        record_neo4j_sync({"Indicator": 5000, "Threat": 500, "Sector": 10, "Country": 200}, 30.0)

        # Circuit breaker metrics (through resilience module)
        from resilience import CIRCUIT_BREAKER_STATE

        CIRCUIT_BREAKER_STATE.labels(service="otx").set(0)
        CIRCUIT_BREAKER_STATE.labels(service="nvd").set(0)

        logger.info("Test metrics generated")

    # Start server (blocking mode)
    logger.info("Starting EdgeGuard Metrics Server...")
    server = MetricsServer(host=args.host, port=args.port)
    server.start()
