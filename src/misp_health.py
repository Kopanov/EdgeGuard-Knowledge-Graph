#!/usr/bin/env python3
"""
EdgeGuard - MISP Health Check Module
Monitors MISP service health and API connectivity
"""

import os
import sys

# Add src to path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

import requests
import urllib3

from config import MISP_API_KEY, MISP_URL, SSL_VERIFY, apply_misp_http_host_header

try:
    from metrics_server import set_misp_health

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Health-check timeout (seconds).  Longer than a simple ping but shorter than
# the 300s READ_TIMEOUT used for full event fetches — health endpoints should
# respond within a few seconds even on a loaded MISP.
MISP_HEALTH_TIMEOUT = 30


@dataclass
class MISPHealthCheckResult:
    """Structured MISP health snapshot.

    Airflow DAGs and older code use dict-style access (``result['status']``,
    ``result.get('healthy_for_collection')``); other callers may use attributes.
    """

    healthy: bool
    status: str
    checks: Dict[str, bool]
    details: Dict[str, Any]
    timestamp: str
    healthy_for_collection: bool

    def __getitem__(self, key: str) -> Any:
        if not hasattr(self, key):
            raise KeyError(key)
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like ``.get`` for compatibility with DAGs and ``run_misp_to_neo4j``."""
        return getattr(self, key, default) if hasattr(self, key) else default

    def __contains__(self, key: object) -> bool:
        """Support ``\"checks\" in result`` (e.g. Airflow DAG) without full Mapping ABC."""
        return isinstance(key, str) and hasattr(self, key)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MISPHealthCheck:
    """
    MISP Health Check and Monitoring.

    Features:
    - Check MISP /servers/healthCheck endpoint
    - Verify API connectivity
    - Check database connectivity
    - Return standardized health status
    """

    def __init__(self, url: str = None, api_key: str = None, verify_ssl: bool = None):
        """
        Initialize MISP health checker.

        Args:
            url: MISP instance URL (defaults to config.MISP_URL)
            api_key: MISP API key (defaults to config.MISP_API_KEY)
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url or MISP_URL
        self.api_key = api_key or MISP_API_KEY
        self.verify_ssl = verify_ssl if verify_ssl is not None else SSL_VERIFY
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}
        )
        apply_misp_http_host_header(self.session)

    def check_health(self) -> MISPHealthCheckResult:
        """
        Perform comprehensive health check on MISP.

        Returns:
            :class:`MISPHealthCheckResult` (supports both attribute and dict-style access).
        """
        checks: Dict[str, bool] = {
            "api_connectivity": False,
            "database": False,
            "worker_status": False,
        }
        details: Dict[str, Any] = {"version": None, "uptime": None, "issues": []}
        timestamp = datetime.now(timezone.utc).isoformat()

        # Check 1: API Connectivity via health endpoint
        api_ok, api_details = self._check_api_health()
        checks["api_connectivity"] = api_ok
        details["version"] = api_details.get("version")
        details["uptime"] = api_details.get("uptime")

        # Check MISP server version compatibility with PyMISP library
        misp_version = details.get("version")
        if misp_version and api_ok:
            version_ok, version_warning = self._check_version_compatibility(misp_version)
            if not version_ok:
                details["issues"].append(version_warning)
                details["version_compatible"] = False
                logger.warning(f"MISP version compatibility: {version_warning}")
            else:
                details["version_compatible"] = True

        if not api_ok:
            details["issues"].append(f"API connectivity failed: {api_details.get('error')}")

        # Check 2: Database connectivity
        db_ok, db_details = self._check_database()
        checks["database"] = db_ok

        if not db_ok:
            details["issues"].append(f"Database check failed: {db_details.get('error')}")

        # Check 3: Worker status (optional, may not be available in all MISP versions)
        worker_ok, worker_details = self._check_workers()
        checks["worker_status"] = worker_ok

        if not worker_ok:
            details["issues"].append(f"Worker check failed: {worker_details.get('error')}")

        # API + DB are enough for collectors and MISP→Neo4j sync; workers are async helpers.
        healthy_for_collection = bool(checks["api_connectivity"] and checks["database"])

        # Human-readable status (workers down → degraded, not unhealthy).
        if all(checks.values()):
            status = "healthy"
        elif healthy_for_collection:
            status = "degraded"
        else:
            status = "unhealthy"

        # Permissive ``healthy``: same as API+DB so CLI/metrics don't flag red when only workers fail.
        # For strict worker requirement, use ``checks["worker_status"]`` (see DAG + EDGEGUARD_MISP_HEALTH_REQUIRE_WORKERS).
        healthy = healthy_for_collection

        if _METRICS_AVAILABLE:
            try:
                set_misp_health(
                    api_healthy=api_ok,
                    db_healthy=db_ok,
                    workers_healthy=worker_ok,
                )
            except Exception:
                logger.debug("Metrics recording failed", exc_info=True)

        return MISPHealthCheckResult(
            healthy=healthy,
            status=status,
            checks=checks,
            details=details,
            timestamp=timestamp,
            healthy_for_collection=healthy_for_collection,
        )

    def _check_api_health(self) -> Tuple[bool, Dict]:
        """
        Check MISP API health.

        Order:
        1. ``/servers/healthCheck`` — not present or auth-gated on some MISP 2.4.x builds
           (404 / 302). We use ``allow_redirects=False`` so a redirect to HTML login does not
           become a fake 200 + JSONDecodeError (which previously skipped all fallbacks).
        2. ``/servers/getWorkers`` — typically accepts API key auth on 2.4.124+ when healthCheck
           does not.
        3. ``/servers/serverSettings/diagnostics`` — optional.
        4. ``/events/index?limit=1`` — last resort API+DB probe.

        Returns:
            Tuple of (success, details_dict)
        """
        try:
            # 1) healthCheck — do not follow redirects (avoids wrong Host / login HTML as "200")
            response = self.session.get(
                f"{self.url}/servers/healthCheck",
                verify=self.verify_ssl,
                timeout=MISP_HEALTH_TIMEOUT,
                allow_redirects=False,
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    data = None
                if isinstance(data, dict):
                    details = {
                        "version": data.get("version"),
                        "uptime": data.get("uptime"),
                        "status": data.get("status", "unknown"),
                    }
                    is_healthy = str(data.get("status", "")).lower() in ("ok", "healthy", "success")
                    return is_healthy, details

            # 2) getWorkers — stable with Authorization on many MISP versions where healthCheck fails
            response = self.session.get(
                f"{self.url}/servers/getWorkers", verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )
            if response.status_code == 200:
                try:
                    data = response.json()
                except ValueError:
                    data = None
                if isinstance(data, dict):
                    return True, {"version": "unknown", "uptime": "unknown", "via": "getWorkers"}

            # 3) diagnostics
            response = self.session.get(
                f"{self.url}/servers/serverSettings/diagnostics", verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )

            if response.status_code == 200:
                return True, {"version": "unknown", "uptime": "unknown", "via": "diagnostics"}

            # 4) list events
            response = self.session.get(
                f"{self.url}/events/index", params={"limit": 1}, verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )

            if response.status_code == 200:
                return True, {"version": "unknown", "uptime": "unknown", "via": "events/index"}

            return False, {"error": f"HTTP {response.status_code}"}

        except requests.exceptions.Timeout:
            return False, {"error": "Connection timeout"}
        except requests.exceptions.ConnectionError as e:
            return False, {"error": f"Connection error: {str(e)}"}
        except Exception as e:
            return False, {"error": str(e)}

    @staticmethod
    def _check_version_compatibility(server_version: str) -> Tuple[bool, str]:
        """Check if MISP server version is compatible with installed PyMISP.

        Returns:
            Tuple of (compatible: bool, message: str)
        """
        try:
            # Parse server version (e.g., "2.4.123" or "2.5.1")
            parts = server_version.strip().split(".")
            major, minor = int(parts[0]), int(parts[1])
            patch = int(parts[2]) if len(parts) > 2 else 0

            # Check PyMISP version
            try:
                import pymisp

                pymisp_version = getattr(pymisp, "__version__", "unknown")
            except ImportError:
                pymisp_version = "not installed"

            # Known incompatibilities:
            # PyMISP 2.5.x requires MISP >= 2.4.170 (CakePHP 5 API changes)
            # PyMISP 2.4.x works with MISP 2.4.x but some features may be missing
            if pymisp_version != "not installed" and pymisp_version != "unknown":
                pymisp_parts = pymisp_version.split(".")
                pymisp_minor = int(pymisp_parts[1]) if len(pymisp_parts) > 1 else 0

                if pymisp_minor >= 5 and minor <= 4 and patch < 170:
                    return False, (
                        f"PyMISP {pymisp_version} may be incompatible with MISP server {server_version}. "
                        f"PyMISP 2.5+ expects MISP >= 2.4.170. This can cause Airflow DAG parser hangs. "
                        f"Fix: either upgrade MISP to >= 2.4.170 or pin pymisp~=2.4 in requirements.txt"
                    )

            # Warn if server is very old
            if major == 2 and minor == 4 and patch < 150:
                return True, f"MISP {server_version} is old — consider upgrading for best compatibility"

            return True, f"MISP {server_version} compatible with PyMISP {pymisp_version}"

        except (ValueError, IndexError):
            return True, f"Could not parse MISP version '{server_version}' — skipping compatibility check"

    def _check_database(self) -> Tuple[bool, Dict]:
        """
        Check database connectivity by fetching a simple query.

        Returns:
            Tuple of (success, details_dict)
        """
        try:
            # Try to fetch event list (tests database connectivity)
            response = self.session.get(
                f"{self.url}/events/index", params={"limit": 1}, verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )

            if response.status_code == 200:
                return True, {"status": "connected"}

            # Try to fetch tags list
            response = self.session.get(
                f"{self.url}/tags", params={"limit": 1}, verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )

            if response.status_code == 200:
                return True, {"status": "connected"}

            return False, {"error": f"Database check failed: HTTP {response.status_code}"}

        except requests.exceptions.Timeout:
            return False, {"error": "Database connection timeout"}
        except Exception as e:
            return False, {"error": str(e)}

    def _check_workers(self) -> Tuple[bool, Dict]:
        """
        Check MISP worker status.

        Returns:
            Tuple of (success, details_dict)

        Note: This may not be available in all MISP versions/configurations.
        """
        try:
            # Try to get worker status via API
            response = self.session.get(
                f"{self.url}/servers/getWorkers", verify=self.verify_ssl, timeout=MISP_HEALTH_TIMEOUT
            )

            if response.status_code == 200:
                try:
                    data = response.json()
                except (ValueError, TypeError):
                    return False, {"error": "Malformed JSON from getWorkers"}
                # MISP getWorkers returns queues at top level, not nested under "workers"
                # Response format: {"default": {...}, "cache": {...}, "email": {...}}
                workers = data.get("workers", data)  # fallback to top-level if no "workers" key

                # Check if critical workers are running
                critical_workers = ["default", "email", "cache"]
                running = 0

                for worker_type in critical_workers:
                    if worker_type in workers:
                        worker_info = workers[worker_type]
                        # Worker info can be a dict with "workers" list or direct list
                        if isinstance(worker_info, dict):
                            worker_list = worker_info.get("workers", [])
                            if worker_list or worker_info.get("alive", False):
                                running += 1
                        elif isinstance(worker_info, list) and len(worker_info) > 0:
                            running += 1

                if running >= 2:  # At least 2 of 3 critical workers
                    return True, {"running_workers": running}
                else:
                    return False, {"error": f"Only {running} critical workers running"}

            # Workers endpoint may not be available, don't fail health check
            return True, {"status": "unknown", "note": "Worker status endpoint not available"}

        except Exception as e:
            # Worker check is optional, don't fail health check
            return True, {"status": "unknown", "note": str(e)}

    def is_healthy(self) -> bool:
        """
        Quick check if MISP is healthy.

        Returns:
            True if healthy, False otherwise
        """
        result = self.check_health()
        return bool(result.healthy)

    def wait_for_healthy(self, timeout: int = 60, interval: int = 5) -> bool:
        """
        Wait for MISP to become healthy.

        Args:
            timeout: Maximum time to wait (seconds)
            interval: Check interval (seconds)

        Returns:
            True if healthy within timeout, False otherwise
        """
        import time

        start = datetime.now(timezone.utc)

        while (datetime.now(timezone.utc) - start).total_seconds() < timeout:
            if self.is_healthy():
                logger.info(f"[OK] MISP is healthy after {(datetime.now(timezone.utc) - start).total_seconds():.1f}s")
                return True

            logger.info(f"[WAIT] Waiting for MISP to become healthy... ({interval}s)")
            time.sleep(interval)

        logger.error(f"[ERR] MISP did not become healthy within {timeout}s")
        return False

    def get_status_summary(self) -> str:
        """
        Get a human-readable status summary.

        Returns:
            Status string
        """
        result = self.check_health()

        lines = [
            f"MISP Status: {result.status.upper()}",
            f"  API Connectivity: {'✅' if result.checks['api_connectivity'] else '❌'}",
            f"  Database: {'✅' if result.checks['database'] else '❌'}",
            f"  Workers: {'✅' if result.checks['worker_status'] else '❌'}",
        ]

        if result.details["version"]:
            lines.append(f"  Version: {result.details['version']}")

        if result.details["issues"]:
            lines.append(f"  Issues: {', '.join(result.details['issues'])}")

        return "\n".join(lines)


def check_misp_health():
    """
    Standalone health check function.

    Returns:
        :class:`MISPHealthCheckResult` (dict-compatible).
    """
    checker = MISPHealthCheck()
    return checker.check_health()


def main():
    """Main entry point for command-line usage."""
    import argparse

    parser = argparse.ArgumentParser(description="MISP Health Check")
    parser.add_argument("--wait", "-w", action="store_true", help="Wait for MISP to become healthy")
    parser.add_argument("--timeout", "-t", type=int, default=60, help="Timeout for wait mode (seconds)")
    parser.add_argument("--interval", "-i", type=int, default=5, help="Check interval (seconds)")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    checker = MISPHealthCheck()

    if args.wait:
        healthy = checker.wait_for_healthy(timeout=args.timeout, interval=args.interval)
        sys.exit(0 if healthy else 1)
    else:
        result = checker.check_health()

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(checker.get_status_summary())

        sys.exit(0 if result.healthy else 1)


if __name__ == "__main__":
    main()
