"""
EdgeGuard Metrics Server DAG

This DAG runs the Prometheus metrics server as a long-running task.
The metrics server exposes all EdgeGuard metrics on port 8001 by default (`EDGEGUARD_METRICS_PORT`, configurable).

Usage:
    - Enable this DAG to run the metrics server continuously
    - Configure EDGEGUARD_METRICS_PORT and EDGEGUARD_METRICS_HOST env vars
    - Prometheus should be configured to scrape from this endpoint

Metrics Endpoint (default port):
    - http://127.0.0.1:8001/metrics - Prometheus metrics
    - http://127.0.0.1:8001/health  - Health check
"""

import logging
import os
import sys
from datetime import timedelta

import pendulum
from airflow import DAG

# Airflow 3.x: PythonOperator moved to apache-airflow-providers-standard.
from airflow.providers.standard.operators.python import PythonOperator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get configuration from environment
METRICS_PORT = int(os.getenv("EDGEGUARD_METRICS_PORT", "8001"))
# Default to loopback so the metrics endpoint is not reachable from other hosts
# on a shared ResilMesh server. Override with EDGEGUARD_METRICS_HOST=0.0.0.0
# only when Prometheus runs on a separate machine and must reach this port.
METRICS_HOST = os.getenv("EDGEGUARD_METRICS_HOST", "127.0.0.1")

# Add src to path
BASE_DIR = os.getenv("EDGEGUARD_BASE_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))

# Default arguments
default_args = {
    "owner": "edgeguard",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 1,
    "retry_delay": timedelta(minutes=1),
}


def run_metrics_server(**context):
    """
    Run the EdgeGuard Prometheus metrics server.

    This function starts the metrics server and runs it indefinitely.
    The server exposes /metrics endpoint for Prometheus scraping.
    """
    try:
        from metrics_server import MetricsServer

        logger.info(f"Starting EdgeGuard Metrics Server on {METRICS_HOST}:{METRICS_PORT}")
        logger.info(f"Metrics endpoint: http://{METRICS_HOST}:{METRICS_PORT}/metrics")
        logger.info(f"Health endpoint: http://{METRICS_HOST}:{METRICS_PORT}/health")

        # Create and start the server in a background thread so the Airflow
        # task does not block indefinitely — Airflow can manage the lifecycle.
        server = MetricsServer(host=METRICS_HOST, port=METRICS_PORT)
        server_thread = server.start_threaded()

        logger.info("Metrics server started in background thread")

        # Keep alive until Airflow kills the task or a signal is received
        try:
            server_thread.join()
        except KeyboardInterrupt:
            logger.info("Metrics server shutting down")
            server.stop()

    except ImportError as e:
        logger.error(f"Failed to import metrics_server: {e}")
        logger.error("Make sure prometheus_client is installed: pip install prometheus_client")
        raise
    except Exception as e:
        logger.error(f"Metrics server error: {e}")
        raise


def health_check(**context):
    """
    Health check for the metrics server.
    This task verifies the metrics server is responding.
    """
    import json
    import urllib.request

    health_url = f"http://{METRICS_HOST}:{METRICS_PORT}/health"

    try:
        with urllib.request.urlopen(health_url, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                logger.info(f"Metrics server health: {data}")
                return True
            else:
                logger.warning(f"Health check returned status {response.status}")
                return False
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
        return False


def generate_test_metrics(**context):
    """
    Generate test metrics for demonstration purposes.
    This is useful for testing the Grafana dashboards.
    """
    try:
        from metrics_server import (
            record_collection,
            record_collection_duration,
            record_misp_push,
            record_neo4j_sync,
            set_source_health,
        )

        logger.info("Generating test metrics...")

        # Simulate collections from different sources
        sources = [
            ("otx", "global", 150),
            ("nvd", "global", 75),
            ("cisa", "us", 25),
            ("abuseipdb", "global", 200),
            ("virustotal", "global", 50),
            ("misp", "internal", 1000),
        ]

        for source, zone, count in sources:
            record_collection(source, zone, count, "success")
            record_collection(source, zone, count // 20, "failed")  # 5% failure rate
            record_collection_duration(source, zone, 5.0)
            set_source_health(source, zone, True)
            record_misp_push(source, zone, count // 10, count, 2.0)

        # Simulate Neo4j data
        record_neo4j_sync(
            {
                "Indicator": 5000,
                "Threat": 500,
                "Sector": 10,
                "Country": 200,
                "AttackPattern": 150,
                "Vulnerability": 300,
            },
            30.0,
        )

        logger.info("Test metrics generated successfully")
        return True

    except Exception as e:
        logger.error(f"Failed to generate test metrics: {e}")
        return False


# ================================================================================
# DAG DEFINITION
# ================================================================================

# Note: This DAG is designed to run the metrics server continuously.
# Set schedule_interval=None and trigger it manually or via API.
# The metrics server task will run indefinitely until stopped.

dag = DAG(
    "edgeguard_metrics_server",
    default_args=default_args,
    description="EdgeGuard Prometheus Metrics Server",
    schedule_interval=None,  # Manual trigger only
    start_date=pendulum.datetime(2025, 1, 1, tz="UTC"),
    catchup=False,
    tags=["edgeguard", "metrics", "prometheus", "monitoring"],
    max_active_runs=1,  # Only one instance should run at a time
)

# Single long-running task — ``server.start()`` blocks, so do not add sibling tasks to this DAG
# (they would run in parallel and race the bind / health probe). Use ``edgeguard_metrics_helpers`` below
# to run health or test-metric tasks in a separate manual trigger.
metrics_server_task = PythonOperator(
    task_id="run_metrics_server",
    python_callable=run_metrics_server,
    execution_timeout=timedelta(hours=24),
    dag=dag,
)

# ================================================================================
# ALTERNATIVE DAG: Metrics Server with Auto-Restart
# ================================================================================

# This DAG runs the metrics server with a schedule, allowing Airflow to
# restart it periodically if it fails.

dag_with_restart = DAG(
    "edgeguard_metrics_server_scheduled",
    default_args=default_args,
    description="EdgeGuard Metrics Server (Auto-Restart)",
    schedule_interval="@once",  # Run once, restart on failure
    start_date=pendulum.datetime(2025, 1, 1, tz="UTC"),
    catchup=False,
    tags=["edgeguard", "metrics", "prometheus", "monitoring", "scheduled"],
    max_active_runs=1,
)

metrics_server_scheduled = PythonOperator(
    task_id="run_metrics_server",
    python_callable=run_metrics_server,
    execution_timeout=timedelta(hours=24),
    dag=dag_with_restart,
)


# ================================================================================
# Helpers DAG — manual only (no race with blocking metrics server task)
# ================================================================================

helpers_dag = DAG(
    "edgeguard_metrics_helpers",
    default_args=default_args,
    description="EdgeGuard metrics: test data + HTTP health probe (run manually; metrics server must be up for health_check)",
    schedule_interval=None,
    start_date=pendulum.datetime(2025, 1, 1, tz="UTC"),
    catchup=False,
    tags=["edgeguard", "metrics", "prometheus", "monitoring", "manual"],
)

generate_test_metrics_task = PythonOperator(
    task_id="generate_test_metrics",
    python_callable=generate_test_metrics,
    execution_timeout=timedelta(minutes=15),
    dag=helpers_dag,
)

health_check_task = PythonOperator(
    task_id="health_check",
    python_callable=health_check,
    execution_timeout=timedelta(minutes=5),
    dag=helpers_dag,
)

generate_test_metrics_task >> health_check_task

# ================================================================================
# USAGE INSTRUCTIONS
# ================================================================================
"""
1. Start the metrics server (blocking task): trigger **edgeguard_metrics_server** (or **edgeguard_metrics_server_scheduled**).
   Only **run_metrics_server** is in that DAG — no parallel tasks racing the HTTP bind.

2. Optional: trigger **edgeguard_metrics_helpers** manually after the server is up — **generate_test_metrics** then **health_check**.

3. Prometheus: scrape **host.docker.internal:8001** — see **prometheus/prometheus.yml**.
"""
