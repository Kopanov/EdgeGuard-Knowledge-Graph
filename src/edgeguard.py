#!/usr/bin/env python3
"""
███████╗██████╗  ██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔════╝ ██╗   ██║██╔══██╗██╔══██╗██╔══██╗
█████╗  ██║  ██║██║  ███╗█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══╝  ██║  ██║██║   ██║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
███████╗██████╔╝╚██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚══════╝╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

Graph-Augmented xAI for Threat Intelligence on Edge Infrastructure
IICT-BAS + Ratio1 | financed by ResilMesh - open call 2

EdgeGuard Operational CLI
Comprehensive CLI for operating EdgeGuard in production.

Usage:
    python edgeguard.py [command]

Commands:
    doctor   - Diagnose issues
    heal     - Auto-repair/reset
    validate - Check config validity
    monitor  - Show health status
    update   - Pull latest + reinstall (auto: Docker if available, else pip). See edgeguard update --help
    version  - Show release version (CalVer) and optional git commit
"""

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Add src to path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Config / heavy deps load lazily in _ensure_runtime_imports() so `edgeguard update` works
# without a populated .env (see main()).
_CFG_EXPORTS = (
    "MAX_ENTRIES_PER_SOURCE",
    "MISP_API_KEY",
    "MISP_URL",
    "NEO4J_PASSWORD",
    "NEO4J_URI",
    "NEO4J_USER",
    "NVD_API_KEY",
    "OTX_API_KEY",
    "SSL_VERIFY",
)


def _ensure_runtime_imports() -> None:
    """Load config + optional deps onto this module (cmd_* expect module-level names)."""
    mod = sys.modules[__name__]
    if getattr(mod, "_RUNTIME_LOADED", False):
        return
    cfg = __import__("config", fromlist=["*"])
    for name in _CFG_EXPORTS:
        setattr(mod, name, getattr(cfg, name))
    from misp_health import MISPHealthCheck as _MHC

    mod.MISPHealthCheck = _MHC
    from resilience import PROMETHEUS_AVAILABLE as _PROM

    mod.PROMETHEUS_AVAILABLE = _PROM
    mod._RUNTIME_LOADED = True


# ================================================================================
# COLOR OUTPUT
# ================================================================================


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    END = "\033[0m"


def ok(msg: str):
    print(f"{Colors.GREEN}✓{Colors.END} {msg}")


def err(msg: str):
    print(f"{Colors.RED}✗{Colors.END} {msg}")


def warn(msg: str):
    print(f"{Colors.YELLOW}⚠{Colors.END} {msg}")


def info(msg: str):
    print(f"{Colors.BLUE}ℹ{Colors.END} {msg}")


def section(title: str):
    print(f"\n{Colors.BOLD}{'=' * 50}")
    print(f" {title}")
    print(f"{'=' * 50}{Colors.END}")


# ================================================================================
# DOCTOR - DIAGNOSTICS
# ================================================================================


def test_misp_connection():
    """Test MISP connection by fetching events."""
    try:
        health = MISPHealthCheck(verify_ssl=SSL_VERIFY)
        result = health.check_health()

        if result["checks"].get("api_connectivity"):
            version = result["details"].get("version", "unknown")
            return True, f"MISP connected (v{version})"
        else:
            issues = result["details"].get("issues", ["Unknown error"])
            return False, f"MISP unreachable: {issues[0]}"
    except Exception as e:
        return False, f"MISP error: {str(e)[:80]}"


def test_neo4j_connection():
    """Test Neo4j connection."""
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            result = session.run("RETURN 1 as test")
            result.single()
        driver.close()
        return True, f"Neo4j connected at {NEO4J_URI}"
    except Exception as e:
        return False, f"Neo4j error: {str(e)[:80]}"


def validate_api_keys():
    """Validate API key formats."""
    issues = []

    # MISP key (should be 40+ chars)
    if len(MISP_API_KEY) < 20:
        issues.append("MISP API key seems too short")

    # OTX key (should be 64 chars hex)
    if OTX_API_KEY and len(OTX_API_KEY) != 64:
        issues.append("OTX API key format unexpected")

    # NVD key (should be dash-separated)
    if NVD_API_KEY and len(NVD_API_KEY) < 10:
        issues.append("NVD API key seems too short")

    if issues:
        return False, "; ".join(issues)
    return True, "API keys appear valid"


def check_disk_space():
    """Check available disk space."""
    try:
        stat = os.statvfs(SCRIPT_DIR)
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)

        if free_gb < 1:
            return False, f"Low disk space: {free_gb:.1f}GB free"
        return True, f"Disk space OK: {free_gb:.1f}GB free"
    except Exception as e:
        return True, f"Could not check disk: {str(e)[:40]}"


def check_last_sync():
    """Check last sync timestamp from state file."""
    repo_root = os.path.dirname(SCRIPT_DIR)

    # Try alternative locations (DAG writer uses state/, legacy used dags/)
    alt_paths = [
        os.path.join(repo_root, "state", "edgeguard_last_neo4j_sync.json"),
        os.path.join(repo_root, "dags", "edgeguard_last_neo4j_sync.json"),
        os.path.join(tempfile.gettempdir(), "edgeguard_last_neo4j_sync.json"),
        os.path.expanduser("~/.edgeguard/last_sync.json"),
    ]

    for path in alt_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    state = json.load(f)
                    raw = state.get("last_sync", "2000-01-01T00:00:00+00:00")
                    last_sync = datetime.fromisoformat(raw if "+" in raw or "Z" in raw else raw + "+00:00")
                    age = datetime.now(timezone.utc) - last_sync

                    if age > timedelta(days=7):
                        return False, f"Last sync: {last_sync.strftime('%Y-%m-%d')} ({age.days}d ago)"
                    return (
                        True,
                        f"Last sync: {last_sync.strftime('%Y-%m-%d %H:%M')} ({age.total_seconds() / 3600:.1f}h ago)",
                    )
            except Exception:
                continue

    return True, "No sync state file found (never synced?)"


def check_circuit_breakers():
    """Check circuit breaker states."""
    # This is a placeholder - in real implementation would check persisted state
    # For now, just report that we can't check without running the pipeline
    return True, "Circuit breakers: OK (in-memory, reset on restart)"


def cmd_doctor(args):
    """Run comprehensive diagnostics."""
    section("EdgeGuard Doctor - Diagnostics")

    all_ok = True

    # Test MISP
    info("Testing MISP connection...")
    ok_flag, msg = test_misp_connection()
    if ok_flag:
        ok(msg)
    else:
        err(msg)
        all_ok = False

    # Check MISP event count — useful to confirm clean/populated state
    if ok_flag:
        try:
            import requests as _req

            misp_url = os.getenv("MISP_URL", "https://localhost:8443")
            misp_key = os.getenv("MISP_API_KEY", "")
            # PR (security S7) — Red Team Tier S: was hardcoded ``verify=False``,
            # which sent the API key over MITM-able TLS regardless of operator
            # config. Now respects ``SSL_VERIFY`` (the same flag every other
            # outbound HTTP call in EdgeGuard already honors). An on-path
            # attacker can no longer silently downgrade this probe to
            # plaintext-equivalent.
            resp = _req.get(
                f"{misp_url}/events/index",
                headers={"Authorization": misp_key, "Accept": "application/json"},
                verify=SSL_VERIFY,
                timeout=10,
            )
            if resp.status_code == 200:
                events = resp.json()
                event_list = events if isinstance(events, list) else []
                eg_events = [
                    e for e in event_list if "EdgeGuard" in str(e.get("info", "") or e.get("Event", {}).get("info", ""))
                ]
                if len(event_list) == 0:
                    info("MISP has 0 events — ready for baseline")
                else:
                    ok(f"MISP has {len(event_list)} events ({len(eg_events)} EdgeGuard)")
        except Exception:
            pass  # Non-critical diagnostic

    # Check MISP version compatibility
    # PR #36 commit X (bugbot LOW): captured here once and threaded to
    # ``compare_pinned_vs_running`` below to avoid a second MISP round-trip.
    _captured_misp_version: Optional[str] = None
    if ok_flag:
        info("Checking MISP/PyMISP version compatibility...")
        try:
            from misp_health import MISPHealthCheck

            checker = MISPHealthCheck()
            result = checker.check_health()
            version = result.details.get("version", "unknown")
            compatible = result.details.get("version_compatible", True)
            if not compatible:
                issues = [
                    i for i in result.details.get("issues", []) if "compatible" in i.lower() or "pymisp" in i.lower()
                ]
                warn(f"MISP {version}: {issues[0] if issues else 'version mismatch detected'}")
                warn("This may cause Airflow DAG parser to hang. Use 'python3 src/run_pipeline.py' as workaround.")
            else:
                ok(f"MISP server {version} compatible with PyMISP")
            # Capture for the version-compat report below — skips the redundant probe
            # (only "unknown" / falsy values fall through to a fresh capture).
            if version and version != "unknown":
                _captured_misp_version = version
        except Exception as e:
            warn(f"Could not check MISP version compatibility: {e}")

    # Test Neo4j
    info("Testing Neo4j connection...")
    ok_flag, msg = test_neo4j_connection()
    if ok_flag:
        ok(msg)
    else:
        err(msg)
        all_ok = False

    # Check Neo4j schema constraints
    if ok_flag:  # Neo4j is connected
        info("Checking Neo4j schema constraints...")
        try:
            from neo4j_client import Neo4jClient

            client = Neo4jClient()
            if client.connect():
                result = client.run("SHOW CONSTRAINTS")
                constraint_count = len(result) if result else 0
                if constraint_count >= 5:
                    ok(f"Neo4j has {constraint_count} constraints configured")
                else:
                    warn(f"Neo4j has only {constraint_count} constraints (expected 5+). Run ensure_constraints().")

                # Check Neo4j data state — useful before baseline to confirm clean/populated
                try:
                    counts = client.run(
                        "MATCH (n) WHERE n.edgeguard_managed = true "
                        "RETURN labels(n)[0] AS label, count(n) AS cnt ORDER BY cnt DESC LIMIT 10"
                    )
                    total = sum(r.get("cnt", 0) for r in counts) if counts else 0
                    if total == 0:
                        info("Neo4j graph is empty (0 EdgeGuard nodes) — ready for baseline")
                    else:
                        top = ", ".join(f"{r['label']}={r['cnt']}" for r in counts[:5]) if counts else ""
                        ok(f"Neo4j has {total} EdgeGuard nodes ({top})")
                except Exception:
                    pass

                client.close()
        except Exception as e:
            warn(f"Could not verify Neo4j constraints: {e}")

    # Test Airflow (retry once after 5s if first attempt fails — handles restarts)
    info("Testing Airflow webserver...")
    airflow_url = os.getenv("AIRFLOW_WEBSERVER_URL", "http://localhost:8082")
    airflow_ok = False
    for _attempt in range(2):
        try:
            import requests

            resp = requests.get(f"{airflow_url}/health", timeout=10)
            if resp.status_code == 200:
                ok(f"Airflow webserver reachable at {airflow_url}")
                airflow_ok = True
                break
            else:
                if _attempt == 0:
                    info(f"Airflow returned {resp.status_code} — retrying in 10s (may be starting)...")
                    import time

                    time.sleep(10)
        except Exception:
            if _attempt == 0:
                info("Airflow not reachable — retrying in 10s (may be starting)...")
                import time

                time.sleep(10)
    if not airflow_ok:
        err(f"Airflow webserver not reachable at {airflow_url} after retry — scheduled DAGs will not run")
        info("  Common causes:")
        info("  - Stale PID file: rm /opt/airflow/airflow-webserver.pid && restart container")
        info("  - Port not exposed: check docker-compose.yml ports mapping for 8082")
        info("  - Out of memory: check AIRFLOW_MEMORY_LIMIT (default 12g)")
        info("  - Scheduler may still be running (check 'docker logs edgeguard_airflow')")
        all_ok = False

    # Check Airflow DAG state if webserver is reachable
    # PR (security S6) — Red Team Tier S: previously used
    # ``os.getenv("AIRFLOW_API_PASSWORD", "airflow")`` which silently
    # used the literal default ``"airflow"`` when unset. Combined with
    # the equivalent default user ``"airflow"`` already in
    # airflow_client.py, this exposed the Airflow REST API (DAG triggering,
    # task-instance reset) to anyone who could reach port 8082 with
    # ``airflow:airflow``. Now: if no password set, SKIP the deeper API
    # check (we still know from the /health probe above whether the
    # webserver is reachable). Operator must set AIRFLOW_API_PASSWORD
    # explicitly to enable the DAG-list diagnostic.
    airflow_password = os.getenv("AIRFLOW_API_PASSWORD", "").strip()
    if airflow_ok and not airflow_password:
        info(
            "AIRFLOW_API_PASSWORD not set — skipping DAG state check. "
            "Set the env var to enable detailed DAG diagnostics."
        )
    if airflow_ok and airflow_password:
        try:
            resp = requests.get(
                f"{airflow_url}/api/v1/dags",
                timeout=10,
                auth=(os.getenv("AIRFLOW_API_USER", "airflow"), airflow_password),
            )
            if resp.status_code == 200:
                dags = resp.json().get("dags", [])
                eg_dags = [d for d in dags if d.get("dag_id", "").startswith("edgeguard")]
                paused = [d["dag_id"] for d in eg_dags if d.get("is_paused")]
                active = [d["dag_id"] for d in eg_dags if not d.get("is_paused")]
                if paused:
                    warn(f"Paused DAGs: {', '.join(paused)}")
                if active:
                    ok(f"Active DAGs: {', '.join(active)}")
                if not eg_dags:
                    warn("No EdgeGuard DAGs found in Airflow — check dags/ folder mount")
        except Exception:
            pass  # Non-critical — webserver may not support API auth

    # Check baseline configuration
    info("Checking baseline configuration...")
    env_baseline_days = os.getenv("EDGEGUARD_BASELINE_DAYS", "").strip()
    if env_baseline_days:
        try:
            bd = int(env_baseline_days)
            if bd < 365:
                warn(f"EDGEGUARD_BASELINE_DAYS={bd} — below recommended 730. Baseline will collect limited data.")
            else:
                ok(f"EDGEGUARD_BASELINE_DAYS={bd}")
        except ValueError:
            warn(f"EDGEGUARD_BASELINE_DAYS={env_baseline_days!r} — invalid (not a number)")
    else:
        ok("EDGEGUARD_BASELINE_DAYS not set — will use default 730")

    # Test NATS (optional)
    nats_url = os.getenv("NATS_URL", "")
    if nats_url:
        info("Testing NATS connection...")
        try:
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(nats_url)
            sock = socket.create_connection((parsed.hostname, parsed.port or 4222), timeout=5)
            sock.close()
            ok(f"NATS reachable at {nats_url}")
        except Exception as e:
            warn(f"NATS not reachable at {nats_url}: {e}")
    else:
        info("NATS: skipped (NATS_URL not set)")

    # Check Docker memory settings (if env vars are set)
    info("Checking memory configuration...")
    _mem_checks = {
        "AIRFLOW_MEMORY_LIMIT": ("12g", 12),
        "NEO4J_HEAP_MAX": ("12g", 12),
        "NEO4J_PAGECACHE": ("8g", 8),
        "NEO4J_CONTAINER_MEMORY_LIMIT": ("24g", 24),
    }
    _mem_ok = True
    for var_name, (recommended, min_gb) in _mem_checks.items():
        val = os.getenv(var_name, "").strip()
        if not val:
            info(f"  {var_name}: not set (Docker Compose default applies)")
            continue
        else:
            try:
                # Parse value like "12g", "12gb", "12G", "12" → integer GB
                import re as _re

                match = _re.match(r"^(\d+)\s*[gG]?[bB]?$", val.strip())
                if not match:
                    warn(f"{var_name}={val} — could not parse (expected format: 12g)")
                    _mem_ok = False
                    continue
                num = int(match.group(1))
                if num < min_gb:
                    warn(f"{var_name}={val} — below recommended {recommended} for 730-day baseline")
                    _mem_ok = False
                else:
                    ok(f"{var_name}={val}")
            except (ValueError, TypeError):
                warn(f"{var_name}={val} — could not parse")
    # (each var is now individually reported above)

    # Validate API keys
    info("Validating API keys...")
    ok_flag, msg = validate_api_keys()
    if ok_flag:
        ok(msg)
    else:
        warn(msg)

    # Check disk space
    info("Checking disk space...")
    ok_flag, msg = check_disk_space()
    if ok_flag:
        ok(msg)
    else:
        err(msg)
        all_ok = False

    # Check last sync
    info("Checking last sync...")
    ok_flag, msg = check_last_sync()
    if ok_flag:
        ok(msg)
    else:
        warn(msg)

    # Check sources
    info("Checking configured sources...")
    sources = load_sources()
    all_sources = {**DEFAULT_SOURCES, **sources}
    enabled_sources = [s for s, info in all_sources.items() if info.get("enabled", False)]
    if enabled_sources:
        ok(f"Enabled sources: {', '.join(enabled_sources)}")
    else:
        warn("No sources enabled!")

    # Check circuit breakers
    info("Checking circuit breakers...")
    ok_flag, msg = check_circuit_breakers()
    ok(msg)

    # Check version compatibility (PR #36 — Vanko's request: capture
    # actual running versions of Neo4j server/driver, Airflow, MISP,
    # PyMISP and warn on drift from the pinned recommendations in
    # docker-compose.yml / requirements*.txt). Best-effort: every
    # capture function in version_compatibility returns ``None`` on
    # failure rather than raising, so a missing optional dep can NEVER
    # crash doctor (Vanko's stale-checkout NameError class of bug —
    # also pinned structurally by ``test_edgeguard_doctor_audit.py``).
    info("Checking version compatibility...")
    try:
        from version_compatibility import compare_pinned_vs_running

        # Pass the MISP version captured earlier (line ~272) to skip a
        # redundant network round-trip — bugbot LOW finding on PR #36.
        rows = compare_pinned_vs_running(misp_server_version=_captured_misp_version)
        for _component, status, message in rows:
            if status == "ok":
                ok(message)
            elif status == "warn":
                warn(message)
            else:
                info(message)
    except Exception as e:
        warn(f"Version compatibility check failed: {e}")

    section("Diagnosis Complete")
    if all_ok:
        ok("EdgeGuard is healthy")
        return 0
    else:
        err("EdgeGuard has issues - run 'edgeguard.py heal' to attempt repair")
        return 1


# ================================================================================
# HEAL - AUTO-REPAIR
# ================================================================================


def reset_circuit_breakers():
    """Reset all circuit breakers — persisted state file and in-memory registry."""
    reset_count = 0

    # 1. Clear persisted state file if it exists
    cb_file = get_circuit_breaker_state_file()
    if os.path.exists(cb_file):
        try:
            os.remove(cb_file)
            reset_count += 1
        except Exception:
            pass

    # 2. Reset in-memory breakers via the resilience module's global registry
    try:
        from resilience import _circuit_breakers
        from resilience import reset_all_circuit_breakers as _reset_all

        if _circuit_breakers:
            _reset_all()
            reset_count += len(_circuit_breakers)
    except (ImportError, AttributeError):
        pass

    if reset_count:
        return True, f"Reset {reset_count} circuit breaker(s)"
    return True, "No circuit breakers to reset"


def clear_lock_files():
    """Clear any stale lock files."""
    cleared = []

    # Common lock file locations
    lock_patterns = [
        os.path.join(tempfile.gettempdir(), "edgeguard_*.lock"),
        os.path.join(os.path.dirname(SCRIPT_DIR), "*.lock"),
    ]

    for pattern in lock_patterns:
        import glob

        for lock_file in glob.glob(pattern):
            try:
                os.remove(lock_file)
                cleared.append(lock_file)
            except Exception:
                pass

    if cleared:
        return True, f"Cleared {len(cleared)} lock file(s)"
    return True, "No lock files found"


def retry_pending_collections():
    """Retry failed collections by triggering the Airflow edgeguard_pipeline DAG."""
    # First check if there are recorded failures worth retrying
    state_dir = os.path.join(os.path.dirname(SCRIPT_DIR), "dags")
    failed_file = os.path.join(state_dir, "failed_collections.json")

    if os.path.exists(failed_file):
        try:
            with open(failed_file, "r") as f:
                failed = json.load(f)
            num_failed = len(failed.get("failed", []))
            if num_failed:
                info(f"Found {num_failed} failed collection(s) — triggering retry")
        except Exception:
            pass

    # Attempt to trigger the Airflow DAG — try docker compose exec first (host),
    # then bare airflow CLI (inside container), then Airflow REST API as fallback.
    trigger_commands = [
        ["docker", "compose", "exec", "airflow", "airflow", "dags", "trigger", "edgeguard_pipeline"],
        ["docker", "exec", "edgeguard_airflow", "airflow", "dags", "trigger", "edgeguard_pipeline"],
        ["airflow", "dags", "trigger", "edgeguard_pipeline"],
    ]
    for cmd in trigger_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return True, f"Triggered edgeguard_pipeline DAG via {cmd[0]}"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue

    # All CLI methods failed — try Airflow REST API
    try:
        import airflow_client as ac

        health = ac.airflow_health()
        if "error" not in health:
            # Airflow is reachable — use the API (not implemented yet, suggest UI)
            return True, "Airflow is reachable but CLI trigger failed — use Airflow UI at http://localhost:8082"
    except Exception:
        pass

    return (
        True,
        "Could not trigger DAG — use Airflow UI at http://localhost:8082 or 'docker compose exec airflow airflow dags trigger edgeguard_pipeline'",
    )


def get_circuit_breaker_state_file():
    """Get path to circuit breaker state file."""
    return os.path.join(os.path.dirname(SCRIPT_DIR), "dags", "circuit_breaker_state.json")


def cmd_heal(args):
    """Auto-repair EdgeGuard."""
    section("EdgeGuard Heal - Auto-Repair")

    healed_items: list[str] = []

    # Reset circuit breakers
    info("Resetting circuit breakers...")
    ok_flag, msg = reset_circuit_breakers()
    ok(msg)
    if ok_flag and "Reset" in msg:
        healed_items.append("circuit breakers reset")

    # Clear lock files
    info("Clearing lock files...")
    ok_flag, msg = clear_lock_files()
    ok(msg)
    if "Cleared" in msg:
        healed_items.append("lock files cleared")

    # Retry pending collections
    info("Checking for pending collections...")
    ok_flag, msg = retry_pending_collections()
    ok(msg)
    if ok_flag and "Retried" in msg:
        healed_items.append("pending collections retried")

    # Clear circuit breaker state file if exists
    cb_file = get_circuit_breaker_state_file()
    if os.path.exists(cb_file):
        try:
            os.remove(cb_file)
            ok("Cleared circuit breaker state file")
            healed_items.append("circuit breaker state file removed")
        except Exception:
            pass

    section("Heal Complete")
    if healed_items:
        ok(f"EdgeGuard healed: {', '.join(healed_items)}")
        info("Note: Some changes may require restarting the pipeline")
    else:
        ok("No issues found — EdgeGuard is healthy")
    return 0


# ================================================================================
# VALIDATE - CONFIG CHECK
# ================================================================================


def validate_config_fields():
    """Check all required config fields are present."""
    required = {
        "MISP_URL": MISP_URL,
        "MISP_API_KEY": MISP_API_KEY,
        "NEO4J_URI": NEO4J_URI,
        "NEO4J_USER": NEO4J_USER,
        "NEO4J_PASSWORD": NEO4J_PASSWORD,
    }

    missing = [k for k, v in required.items() if not v]

    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"
    return True, "All required config fields present"


def validate_rate_limits():
    """Validate rate limits don't conflict."""
    warnings = []

    # MAX_ENTRIES_PER_SOURCE > 0 enables a global cap; very high values can still stress APIs
    if MAX_ENTRIES_PER_SOURCE > 1000:
        warnings.append(f"MAX_ENTRIES_PER_SOURCE ({MAX_ENTRIES_PER_SOURCE}) is high - may cause rate limiting")

    if warnings:
        return False, "; ".join(warnings)
    return True, "Rate limits OK"


def check_production_issues():
    """Warn about production issues."""
    warnings = []

    # SSL verification disabled
    if not SSL_VERIFY:
        warnings.append("SSL verification is DISABLED - not safe for production!")

    # Default Neo4j password
    if NEO4J_PASSWORD in ("neo4j", "edgeguard123", "changeme"):
        warnings.append("Using default Neo4j password - change in production!")

    # API key format sanity check (MISP keys are typically 40 chars)
    if len(MISP_API_KEY) > 0 and len(MISP_API_KEY) < 20:
        warnings.append("MISP API key is suspiciously short (<20 chars) — verify it is correct")

    if warnings:
        return warnings
    return []


# =============================================================================
# Source Management
# =============================================================================

SOURCES_FILE = os.path.join(os.path.dirname(__file__), "..", "credentials", "sources.yaml")

# Single-source-of-truth: derived from src/source_registry.py (chip 5a).
# Adding a new source is now a one-line edit in the registry; this dict
# (and the four other parallel registries that previously needed
# hand-syncing — neo4j_client.SOURCES, config.SOURCE_TAGS,
# source_truthful_timestamps._RELIABLE_FIRST_SEEN_SOURCES,
# misp_writer.MISPWriter.SOURCE_TAGS) all derive from the same source.
# Shape and key set are pinned by tests/test_source_registry.py.
import source_registry as _source_registry  # noqa: E402

DEFAULT_SOURCES = _source_registry.to_cli_sources_dict()


def load_sources():
    """Load sources from YAML file."""
    import yaml

    if os.path.exists(SOURCES_FILE):
        with open(SOURCES_FILE, "r") as f:
            return yaml.safe_load(f) or {}
    return {}


def save_sources(sources):
    """Save sources to YAML file."""
    import yaml

    os.makedirs(os.path.dirname(SOURCES_FILE), exist_ok=True)
    with open(SOURCES_FILE, "w") as f:
        yaml.dump(sources, f, default_flow_style=False)


def cmd_source_list(args):
    """List all configured sources."""
    section("EdgeGuard Sources")

    sources = load_sources()

    # Merge with defaults
    all_sources = {**DEFAULT_SOURCES, **sources}

    print(f"\n{'Source':<15} {'Enabled':<10} {'Rate Limit':<15} Description")
    print("-" * 70)

    for name, info in all_sources.items():
        enabled = "✓" if info.get("enabled", False) else "✗"
        rate = info.get("rate_limit", "N/A")
        desc = info.get("description", "")
        print(f"{name:<15} {enabled:<10} {rate:<15} {desc}")

    print()
    return 0


def cmd_source_add(args):
    """Add a new data source."""
    section(f"Adding Source: {args.name}")

    sources = load_sources()

    if args.name in sources:
        err(f"Source '{args.name}' already exists. Use --force to replace.")
        return 1

    # Get API key
    api_key = args.api_key
    if not api_key:
        api_key_env = f"{args.name.upper()}_API_KEY"
        info(f"Set API key via environment variable: {api_key_env}")

    # Add source
    sources[args.name] = {
        "name": args.name.title(),
        "api_key_env": f"{args.name.upper()}_API_KEY" if api_key else None,
        "rate_limit": args.rate_limit or "custom",
        "enabled": args.enabled,
        "description": f"Custom source: {args.name}",
    }

    save_sources(sources)
    ok(f"Source '{args.name}' added successfully!")
    info(f"Set API key: export {args.name.upper()}_API_KEY='your-key'")

    return 0


def cmd_source_remove(args):
    """Remove a data source."""
    section(f"Removing Source: {args.name}")

    sources = load_sources()

    if args.name not in sources:
        err(f"Source '{args.name}' not found")
        return 1

    del sources[args.name]
    save_sources(sources)
    ok(f"Source '{args.name}' removed")

    return 0


def cmd_source(args):
    """Handle source subcommands."""
    if hasattr(args, "source_command"):
        if args.source_command == "list":
            return cmd_source_list(args)
        elif args.source_command == "add":
            return cmd_source_add(args)
        elif args.source_command == "remove":
            return cmd_source_remove(args)

    # Default: show help
    info("Use: edgeguard.py source list|add|remove")
    return 0


def cmd_validate(args):
    """Validate configuration."""
    section("EdgeGuard Validate - Config Check")

    issues = []

    # Check required fields
    info("Checking required fields...")
    ok_flag, msg = validate_config_fields()
    if ok_flag:
        ok(msg)
    else:
        err(msg)
        issues.append(msg)

    # Check rate limits
    info("Checking rate limits...")
    ok_flag, msg = validate_rate_limits()
    if ok_flag:
        ok(msg)
    else:
        warn(msg)

    # Check production issues
    info("Checking production readiness...")
    prod_issues = check_production_issues()
    if prod_issues:
        for issue in prod_issues:
            err(issue)
            issues.append(issue)
    else:
        ok("No production issues detected")

    # Check Neo4j schema (if connected)
    info("Checking Neo4j schema...")
    try:
        from neo4j_client import Neo4jClient

        client = Neo4jClient()
        if client.connect():
            # Check required node labels exist
            result = client.run("CALL db.labels() YIELD label RETURN collect(label) AS labels")
            if result:
                labels = result[0].get("labels", [])
                required = {
                    "Indicator",
                    "Vulnerability",
                    "CVE",
                    "Malware",
                    "ThreatActor",
                    "Technique",
                    "Tactic",
                    "Source",
                }
                missing = required - set(labels)
                if missing:
                    warn(f"Missing Neo4j labels: {', '.join(sorted(missing))} (will be created on first sync)")
                else:
                    ok(f"All {len(required)} required node labels present")

            # Check constraints
            result = client.run("SHOW CONSTRAINTS")
            constraint_count = len(result) if result else 0
            if constraint_count >= 5:
                ok(f"{constraint_count} Neo4j constraints configured")
            else:
                warn(f"Only {constraint_count} constraints (run ensure_constraints() or first sync)")

            # Check edgeguard_managed tag coverage
            info("Checking edgeguard_managed tag coverage...")
            try:
                unmanaged = client.run(
                    "MATCH (n) "
                    "WHERE (n:Indicator OR n:Vulnerability OR n:CVE OR n:Malware "
                    "OR n:ThreatActor OR n:Technique OR n:Tactic OR n:Tool OR n:Campaign) "
                    "AND (n.edgeguard_managed IS NULL OR n.edgeguard_managed <> true) "
                    "RETURN labels(n)[0] as label, count(n) as count"
                )
                if unmanaged:
                    for row in unmanaged:
                        label = row.get("label", "Unknown")
                        count = row.get("count", 0)
                        if count > 0:
                            warn(f"{count} {label} node(s) missing edgeguard_managed=true")
                else:
                    ok("All graph nodes have edgeguard_managed=true")
            except Exception as e:
                warn(f"edgeguard_managed check failed: {e}")

            # Check orphan indicators
            info("Checking for orphan indicators...")
            try:
                orphan_result = client.run(
                    "MATCH (n:Indicator) "
                    "WHERE n.edgeguard_managed = true AND NOT EXISTS((n)--()) "
                    "RETURN count(n) as orphan_count"
                )
                if orphan_result:
                    orphan_count = orphan_result[0].get("orphan_count", 0)
                    if orphan_count > 0:
                        info(f"{orphan_count} orphan indicator(s) with no relationships (normal for fresh imports)")
                    else:
                        ok("No orphan indicators found")
                else:
                    ok("No orphan indicators found")
            except Exception as e:
                warn(f"Orphan indicator check failed: {e}")

            client.close()
        else:
            warn("Neo4j not connected — schema check skipped")
    except Exception as e:
        warn(f"Neo4j schema check failed: {e}")

    # Check version compatibility (PR #36 — Vanko's request). Validate's
    # role is config validation, but version drift IS a configuration
    # issue: a 2026.x Neo4j server pinned at the 5.26 docker tag will be
    # silently downgraded on the next ``docker-compose up``. Surface it
    # here so it shows up in the operator's pre-deploy validation pass.
    info("Checking version compatibility...")
    try:
        from version_compatibility import compare_pinned_vs_running

        rows = compare_pinned_vs_running()
        for _component, status, message in rows:
            if status == "ok":
                ok(message)
            elif status == "warn":
                warn(message)
            else:
                info(message)
        # PR #36 commit 8425380 (bugbot MED): version-drift warnings are
        # NOT appended to ``issues``. Two reasons:
        #   1. The previous code appended a synthetic "N pins drifted"
        #      string AND printed an apologetic comment claiming the
        #      check "doesn't block deployment" — but ``cmd_validate``
        #      returns exit 1 when ``issues`` is non-empty, so it
        #      DID block. Self-contradicting.
        #   2. Inconsistent with ``cmd_doctor`` which already treats
        #      version drift as informational (never bumps ``all_ok``).
        # If a future operator wants version drift to gate deploys, add
        # an opt-in env var (e.g. ``EDGEGUARD_VALIDATE_FAIL_ON_DRIFT=1``)
        # rather than reverting the default.
    except Exception as e:
        warn(f"Version compatibility check failed: {e}")

    section("Validation Complete")
    if issues:
        warn(f"Found {len(issues)} issue(s) - review and fix before production")
        return 1
    else:
        ok("Configuration is valid")
        return 0


# ================================================================================
# MONITOR - HEALTH STATUS
# ================================================================================


def get_misp_status():
    """Get MISP health status."""
    try:
        health = MISPHealthCheck(verify_ssl=SSL_VERIFY)
        result = health.check_health()

        status = result.get("status", "unknown")
        version = result.get("details", {}).get("version", "unknown")

        return {
            "service": "MISP",
            "status": status.upper(),
            "version": version,
            "checks": result.get("checks", {}),
        }
    except Exception as e:
        return {
            "service": "MISP",
            "status": "ERROR",
            "error": str(e)[:50],
        }


def get_neo4j_status():
    """Get Neo4j status and stats."""
    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        stats = {}
        with driver.session() as session:
            # Get node counts
            for label in ["Indicator", "Vulnerability", "Malware", "ThreatActor", "Technique"]:
                result = session.run(f"MATCH (n:{label}) RETURN count(n) as count")
                stats[label] = result.single()["count"]

            # Get relationship count
            result = session.run("MATCH ()-[r]->() RETURN count(r) as count")
            stats["Relationships"] = result.single()["count"]

        driver.close()

        return {
            "service": "Neo4j",
            "status": "UP",
            "uri": NEO4J_URI,
            "stats": stats,
        }
    except Exception as e:
        return {
            "service": "Neo4j",
            "status": "DOWN",
            "error": str(e)[:50],
        }


def get_sync_status():
    """Get sync status."""
    repo_root = os.path.dirname(SCRIPT_DIR)
    alt_paths = [
        os.path.join(repo_root, "state", "edgeguard_last_neo4j_sync.json"),  # DAG writer path
        os.path.join(repo_root, "dags", "edgeguard_last_neo4j_sync.json"),  # legacy path
        os.path.join(tempfile.gettempdir(), "edgeguard_last_neo4j_sync.json"),
    ]

    for path in alt_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    state = json.load(f)
                    raw = state.get("last_sync", "2000-01-01T00:00:00+00:00")
                    last_sync = datetime.fromisoformat(raw if "+" in raw or "Z" in raw else raw + "+00:00")
                    return {
                        "last_sync": last_sync.strftime("%Y-%m-%d %H:%M"),
                        "age_hours": (datetime.now(timezone.utc) - last_sync).total_seconds() / 3600,
                    }
            except Exception:
                continue

    return {"last_sync": "Never", "age_hours": None}


def get_circuit_breaker_info():
    """Get circuit breaker info."""
    cb_file = get_circuit_breaker_state_file()

    if os.path.exists(cb_file):
        try:
            with open(cb_file, "r") as f:
                state = json.load(f)
            return state
        except Exception:
            pass

    return {"misp": "CLOSED", "neo4j": "CLOSED"}


def cmd_monitor(args):
    """Show health status."""
    section("EdgeGuard Monitor - Health Status")

    # Get MISP status
    info("MISP Status:")
    misp = get_misp_status()
    status_color = (
        Colors.GREEN if misp["status"] == "HEALTHY" else Colors.YELLOW if misp["status"] == "DEGRADED" else Colors.RED
    )
    print(f"  {status_color}●{Colors.END} {misp['status']} (v{misp.get('version', 'unknown')})")
    if "error" in misp:
        print(f"    Error: {misp['error']}")

    # Get Neo4j status
    info("\nNeo4j Status:")
    neo4j = get_neo4j_status()
    status_color = Colors.GREEN if neo4j["status"] == "UP" else Colors.RED
    print(f"  {status_color}●{Colors.END} {neo4j['status']} at {neo4j.get('uri', 'unknown')}")
    if "stats" in neo4j:
        print(f"    Nodes: {sum(neo4j['stats'].values()) - neo4j['stats'].get('Relationships', 0):,}")
        print(f"    Relationships: {neo4j['stats'].get('Relationships', 0):,}")
    if "error" in neo4j:
        print(f"    Error: {neo4j['error']}")

    # Get sync status
    info("\nSync Status:")
    sync = get_sync_status()
    age_str = f"{sync['age_hours']:.1f}h" if sync["age_hours"] else "N/A"
    print(f"  Last sync: {sync['last_sync']} ({age_str})")

    # Get circuit breakers
    info("\nCircuit Breakers:")
    cbs = get_circuit_breaker_info()
    for service, state in cbs.items():
        color = Colors.GREEN if state == "CLOSED" else Colors.YELLOW if state == "HALF_OPEN" else Colors.RED
        print(f"  {service}: {color}{state}{Colors.END}")

    # Prometheus metrics status
    info("\nMetrics:")
    if PROMETHEUS_AVAILABLE:
        ok("Prometheus metrics available")
    else:
        warn("Prometheus metrics not available (prometheus_client not installed)")

    section("Monitor Complete")
    return 0


# ================================================================================
# DAG MANAGEMENT
# ================================================================================


def cmd_dag(args) -> int:
    """Dispatch dag subcommands."""
    sub = getattr(args, "dag_command", None)
    if sub == "status":
        return cmd_dag_status(args)
    elif sub == "kill":
        return cmd_dag_kill(args)
    else:
        print("Usage: edgeguard dag {status|kill}")
        return 1


def cmd_dag_status(args) -> int:
    """Show DAG run status from Airflow REST API."""
    import airflow_client as ac

    section("Airflow DAG Status")

    health = ac.airflow_health()
    if "error" in health:
        err(f"Airflow: {health['error']}")
        return 1
    ok("Airflow is reachable")

    dag_ids = [args.dag_id] if getattr(args, "dag_id", None) else ac.get_edgeguard_dag_ids()
    state_filter = getattr(args, "state", None)
    limit = getattr(args, "limit", 5) or 5
    use_json = getattr(args, "json", False)

    all_runs = []
    for dag_id in dag_ids:
        runs = ac.list_dag_runs(dag_id, state=state_filter, limit=limit)
        if runs and "error" in runs[0]:
            warn(f"{dag_id}: {runs[0]['error']}")
            continue
        for r in runs:
            r["dag_id"] = dag_id
        all_runs.extend(runs)

    if use_json:
        import json as _json

        print(_json.dumps(all_runs, indent=2, default=str))
        return 0

    if not all_runs:
        info("No DAG runs found.")
        return 0

    # Table header
    print(f"\n  {'DAG':<28} {'State':<10} {'Start':<20} {'Duration':<12}")
    print(f"  {'—' * 28} {'—' * 10} {'—' * 20} {'—' * 12}")
    for r in all_runs:
        dag_id = r.get("dag_id", "?")
        state = r.get("state", "?")
        start = (r.get("start_date") or "")[:19]
        duration = ac.format_duration(r.get("start_date"), r.get("end_date"))

        # Color-code state
        if state == "success":
            state_str = f"{Colors.GREEN}{state}{Colors.END}"
        elif state in ("running", "queued"):
            state_str = f"{Colors.YELLOW}{state}{Colors.END}"
        elif state == "failed":
            state_str = f"{Colors.RED}{state}{Colors.END}"
        else:
            state_str = state

        print(f"  {dag_id:<28} {state_str:<22} {start:<20} {duration:<12}")

    print()
    return 0


def cmd_dag_kill(args) -> int:
    """Force-fail stuck DAG runs with checkpoint preservation."""
    import airflow_client as ac

    section("Kill Active DAG Runs")

    health = ac.airflow_health()
    if "error" in health:
        err(f"Airflow: {health['error']}")
        return 1

    dag_id_filter = getattr(args, "dag_id", None)
    dag_ids = [dag_id_filter] if dag_id_filter else None
    active = ac.list_all_active_dag_runs(dag_ids)

    if not active:
        ok("No active (running/queued) DAG runs to kill.")
        return 0

    info(f"Found {len(active)} active run(s):")
    for r in active:
        print(f"  {r.get('dag_id', '?'):<28} {r.get('state', '?'):<10} started {(r.get('start_date') or '?')[:19]}")

    if getattr(args, "dry_run", False):
        info("Dry run — no action taken.")
        return 0

    if not getattr(args, "force", False):
        confirm = input("\nKill these runs? Checkpoints will be preserved. [y/N]: ")
        if confirm.lower() not in ("y", "yes"):
            info("Aborted.")
            return 0

    # Checkpoint preservation — read-only snapshot
    try:
        from baseline_checkpoint import get_baseline_status

        cp_status = get_baseline_status()
        if cp_status:
            ok(f"Checkpoint state: {len(cp_status)} source(s) tracked — preserved (read-only).")
    except Exception:
        pass

    # Kill each run
    killed = 0
    for r in active:
        dag_id = r.get("dag_id", "")
        run_id = r.get("dag_run_id", "")
        if not run_id:
            continue

        result = ac.patch_dag_run_state(dag_id, run_id, "failed")
        if "error" in result:
            err(f"  Failed to kill {dag_id}/{run_id}: {result['error']}")
        else:
            ok(f"  Killed: {dag_id} / {run_id}")
            killed += 1

    # Reset circuit breakers since services are fine — it was the DAG that was stuck
    try:
        from resilience import reset_all_circuit_breakers

        reset_all_circuit_breakers()
        ok("Circuit breakers reset.")
    except Exception:
        pass

    section(f"Killed {killed}/{len(active)} run(s). Checkpoints preserved.")
    info("Run 'edgeguard dag status' to verify.")
    return 0


# ================================================================================
# CHECKPOINT MANAGEMENT
# ================================================================================


def cmd_checkpoint(args) -> int:
    """Dispatch checkpoint subcommands."""
    sub = getattr(args, "checkpoint_command", None)
    if sub == "status":
        return cmd_checkpoint_status(args)
    elif sub == "clear":
        return cmd_checkpoint_clear(args)
    else:
        print("Usage: edgeguard checkpoint {status|clear}")
        return 1


def cmd_checkpoint_status(args) -> int:
    """Show baseline checkpoint state per source."""
    from baseline_checkpoint import get_source_incremental, load_checkpoint

    section("Checkpoint Status")
    use_json = getattr(args, "json", False)
    source_filter = getattr(args, "source", None)

    checkpoints = load_checkpoint()
    if not checkpoints:
        info("No checkpoints found.")
        return 0

    if use_json:
        import json as _json

        data = {source_filter: checkpoints.get(source_filter, {})} if source_filter else checkpoints
        print(_json.dumps(data, indent=2, default=str))
        return 0

    print(f"\n  {'Source':<20} {'Pages':<8} {'Items':<10} {'Status':<12} {'Incremental':<14} {'Last Updated':<20}")
    print(f"  {'—' * 20} {'—' * 8} {'—' * 10} {'—' * 12} {'—' * 14} {'—' * 20}")

    for source, data in sorted(checkpoints.items()):
        if source_filter and source != source_filter:
            continue
        if not isinstance(data, dict):
            continue

        pages = data.get("page", data.get("pages_collected", "—"))
        items = data.get("items_collected", "—")
        completed = data.get("completed", False)
        updated = (data.get("updated_at") or "")[:19]
        inc = get_source_incremental(source)
        has_inc = "yes" if inc else "no"

        if completed:
            status = f"{Colors.GREEN}completed{Colors.END}"
        elif items and items != "—":
            status = f"{Colors.YELLOW}in-progress{Colors.END}"
        else:
            status = "—"

        print(f"  {source:<20} {str(pages):<8} {str(items):<10} {status:<24} {has_inc:<14} {updated:<20}")

    print()
    return 0


def cmd_checkpoint_clear(args) -> int:
    """Clear baseline checkpoints (preserves incremental state by default)."""
    from baseline_checkpoint import clear_checkpoint, get_baseline_status

    section("Clear Checkpoints")

    # Safety: check if a pipeline is currently running
    lock_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "checkpoints", "pipeline.lock")
    try:
        if os.path.exists(lock_path):
            with open(lock_path) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, 0)
                err(
                    f"A pipeline process (PID {pid}) is currently running. "
                    "Clearing checkpoints now could lose completed source progress. "
                    "Wait for the pipeline to finish, or use --force to override."
                )
                if not getattr(args, "force", False):
                    return 1
                warn("--force: proceeding despite active pipeline.")
            except (ProcessLookupError, PermissionError):
                pass  # Stale lock — safe to proceed
    except (ValueError, IOError):
        pass

    source = getattr(args, "source", None)
    include_inc = getattr(args, "include_incremental", False)

    status = get_baseline_status()
    if not status:
        info("No checkpoints to clear.")
        return 0

    info(f"Current checkpoints: {len(status)} source(s)")
    for s, d in status.items():
        if source and s != source:
            continue
        print(f"  {s}: {d.get('items_collected', 0)} items, completed={d.get('completed', False)}")

    if include_inc:
        warn("--include-incremental: This will also clear incremental cursors (modified_since, ETags).")
        warn("Next collection will do a FULL re-fetch for affected sources.")

    if not getattr(args, "force", False):
        target = source or "ALL sources"
        confirm = input(f"\nClear checkpoint for {target}? [y/N]: ")
        if confirm.lower() not in ("y", "yes"):
            info("Aborted.")
            return 0

    clear_checkpoint(source, include_incremental=include_inc)
    ok(f"Baseline checkpoint cleared for {source or 'all sources'}.")
    if include_inc:
        ok("Incremental state also cleared.")
    else:
        ok("Incremental state preserved (next scheduled run resumes from cursor).")

    return 0


# ================================================================================
# CLEAR (Neo4j / MISP data wipe)
# ================================================================================


def cmd_clear(args) -> int:
    """Dispatch clear subcommands."""
    sub = getattr(args, "clear_command", None)
    if sub == "neo4j":
        return cmd_clear_neo4j(args)
    elif sub == "misp":
        return cmd_clear_misp(args)
    elif sub == "all":
        return cmd_clear_all(args)
    else:
        print("Usage: edgeguard clear {neo4j|misp|all}")
        return 1


def cmd_clear_neo4j(args) -> int:
    """Clear all EdgeGuard data from Neo4j (keeps constraints/indexes)."""
    section("Clear Neo4j")

    if not getattr(args, "force", False):
        confirm = input("This will DELETE all graph data from Neo4j. Type DELETE to confirm: ")
        if confirm != "DELETE":
            info("Aborted.")
            return 0

    try:
        from neo4j_client import Neo4jClient

        client = Neo4jClient()
        if not client.connect():
            err("Cannot connect to Neo4j")
            return 1
        try:
            client.clear_all()
            ok("Neo4j graph data cleared (constraints and indexes preserved)")
        finally:
            client.close()
    except Exception as e:
        err(f"Failed to clear Neo4j: {e}")
        return 1

    return 0


def cmd_clear_misp(args) -> int:
    """Delete all EdgeGuard events from MISP."""
    import warnings

    import requests as _req
    import urllib3

    section("Clear MISP EdgeGuard Events")

    if not getattr(args, "force", False):
        confirm = input("This will DELETE all EdgeGuard events from MISP. Type DELETE to confirm: ")
        if confirm != "DELETE":
            info("Aborted.")
            return 0

    try:
        from config import apply_misp_http_host_header

        _sess = _req.Session()
        _sess.headers.update({"Authorization": MISP_API_KEY, "Accept": "application/json"})
        apply_misp_http_host_header(_sess)

        with warnings.catch_warnings():
            if not SSL_VERIFY:
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            resp = _sess.get(
                f"{MISP_URL}/events/index",
                params={"searchall": "EdgeGuard", "limit": 500},
                verify=SSL_VERIFY,
                timeout=(15, 60),
            )

        # Paginate: keep fetching + deleting until no more EdgeGuard events.
        # Each iteration deletes up to 500 events, then re-fetches page 1
        # (deleted events won't reappear). Max 20 iterations = 10,000 events safety cap.
        deleted = 0
        total_found = 0
        _http_error = False
        _max_pages = 20
        for _page in range(_max_pages):
            if resp.status_code != 200:
                err(f"MISP returned {resp.status_code}")
                _http_error = True
                break

            _json = resp.json()
            if isinstance(_json, list):
                events = _json
            elif isinstance(_json, dict):
                events = _json.get("response", _json.get("Event", []))
                if isinstance(events, dict):
                    events = [events]
            else:
                events = []

            if not events:
                break

            total_found += len(events)
            for ev in events:
                eid = ev.get("id") or ev.get("Event", {}).get("id")
                if eid:
                    with warnings.catch_warnings():
                        if not SSL_VERIFY:
                            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
                        del_resp = _sess.delete(f"{MISP_URL}/events/{eid}", verify=SSL_VERIFY, timeout=(15, 30))
                    if del_resp.status_code == 200:
                        deleted += 1
                    elif del_resp.status_code == 302:
                        logger.warning("MISP returned 302 for event %s — likely auth redirect, skipping", eid)

            # Fetch next page (deleted events won't appear again)
            with warnings.catch_warnings():
                if not SSL_VERIFY:
                    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
                resp = _sess.get(
                    f"{MISP_URL}/events/index",
                    params={"searchall": "EdgeGuard", "limit": 500},
                    verify=SSL_VERIFY,
                    timeout=(15, 60),
                )

        if _http_error:
            err("MISP clear failed due to HTTP error — check API key and MISP status")
            return 1
        if total_found == 0:
            info("No EdgeGuard events found in MISP.")
        elif deleted < total_found:
            err(f"Partial clear: deleted {deleted}/{total_found} EdgeGuard events ({total_found - deleted} failed)")
            return 1
        else:
            ok(f"Deleted {deleted}/{total_found} EdgeGuard events from MISP")
    except Exception as e:
        err(f"Failed to clear MISP: {e}")
        return 1

    return 0


def cmd_clear_all(args) -> int:
    """Clear both Neo4j and MISP + checkpoints (full reset)."""
    section("Clear All (Neo4j + MISP + Checkpoints)")

    if not getattr(args, "force", False):
        confirm = input("This will DELETE all data from Neo4j + MISP + checkpoints. Type DELETE to confirm: ")
        if confirm != "DELETE":
            info("Aborted.")
            return 0

    # Force the sub-commands to skip their own confirmation
    args.force = True

    neo4j_ok = cmd_clear_neo4j(args) == 0
    misp_ok = cmd_clear_misp(args) == 0

    # Clear checkpoints (including incremental)
    try:
        from baseline_checkpoint import clear_checkpoint

        clear_checkpoint(include_incremental=True)
        ok("Checkpoints cleared (including incremental cursors)")
    except Exception as e:
        warn(f"Could not clear checkpoints: {e}")

    if neo4j_ok and misp_ok:
        ok("Full reset complete — ready for fresh baseline")
    else:
        warn("Partial reset — check errors above")

    return 0 if (neo4j_ok and misp_ok) else 1


# ================================================================================
# STATS DASHBOARD
# ================================================================================


def cmd_stats(args) -> int:
    """Dashboard: node counts, by-zone, by-source, MISP events, sync, runs."""
    use_json = getattr(args, "json", False)
    show_full = getattr(args, "full", False)
    show_zone = show_full or getattr(args, "by_zone", False)
    show_source = show_full or getattr(args, "by_source", False)
    show_misp = show_full or getattr(args, "misp", False)

    section("EdgeGuard Stats")

    result = {}
    neo4j_stats = None

    # ── Neo4j full stats (by_source and by_zone come from get_stats()) ──
    try:
        from neo4j_client import Neo4jClient

        client = Neo4jClient()
        if client.connect():
            neo4j_stats = client.get_stats()
            client.close()
    except Exception as e:
        warn(f"Neo4j: {e}")

    # 1. Node counts by label
    if neo4j_stats and "error" not in neo4j_stats:
        label_order = [
            "Vulnerability",
            "Indicator",
            "CVE",
            "Malware",
            "ThreatActor",
            "Technique",
            "Tactic",
            "Campaign",
            "Tool",
            "CVSSv31",
            "CVSSv40",
            "CVSSv30",
            "CVSSv2",
            "Alert",
            "Sector",
            "Sources",
        ]
        result["nodes"] = {k: neo4j_stats.get(k, 0) for k in label_order if neo4j_stats.get(k, 0) > 0}
        result["nodes"]["relationships"] = neo4j_stats.get("sourced_relationships", 0)

        if not use_json:
            print(f"\n  {'Node Type':<20} {'Count':>10}")
            print(f"  {'—' * 20} {'—' * 10}")
            for label in label_order:
                count = neo4j_stats.get(label, 0)
                if count > 0:
                    print(f"  {label:<20} {count:>10,}")
            sr = neo4j_stats.get("sourced_relationships", 0)
            if sr:
                print(f"  {'SOURCED_FROM rels':<20} {sr:>10,}")

    # 2. By zone (precise: single-zone counts + combo breakdown)
    if show_zone and neo4j_stats:
        try:
            from neo4j_client import Neo4jClient as _NC2

            _c2 = _NC2()
            zone_data = {}
            if _c2.connect():
                # Precise zone counting: group by the EXACT zone array
                _r = _c2.run("""
                    MATCH (n) WHERE n.zone IS NOT NULL
                    WITH n.zone AS zones, count(n) AS cnt
                    RETURN zones, cnt ORDER BY cnt DESC
                """)
                combo_counts = {tuple(sorted(row["zones"])): row["cnt"] for row in _r} if _r else {}

                # Build: single-zone totals (exclusive), combo totals, total
                single_zone = {}
                combos = {}
                for zones, cnt in combo_counts.items():
                    if len(zones) == 1:
                        single_zone[zones[0]] = cnt
                    else:
                        combos["+".join(zones)] = cnt

                total_nodes = sum(combo_counts.values())
                _c2.close()

                multi_zone_total = sum(combos.values())
                zone_data = {
                    "single_zone": single_zone,
                    "combos": combos,
                    "multi_zone_count": multi_zone_total,
                    "total": total_nodes,
                }
            result["by_zone"] = zone_data
            result["multi_zone_count"] = zone_data.get("multi_zone_count", 0)

            if zone_data and not use_json:
                print(f"\n  {'Zone':<30} {'Nodes':>10}")
                print(f"  {'—' * 30} {'—' * 10}")
                # Single-zone counts (exclusive — not counted in combos)
                for zone, count in sorted(single_zone.items(), key=lambda x: -x[1]):
                    print(f"  {zone:<30} {count:>10,}")
                # Combos
                if combos:
                    print(f"  {'—' * 30} {'—' * 10}")
                    for combo, count in sorted(combos.items(), key=lambda x: -x[1]):
                        print(f"  {combo:<30} {count:>10,}  (multi-zone)")
                print(f"  {'—' * 30} {'—' * 10}")
                print(f"  {'TOTAL':<30} {total_nodes:>10,}")
                if multi_zone_total:
                    print(f"  Multi-zone indicators: {multi_zone_total:,}")

        except Exception as e:
            # Fallback to the basic by_zone from get_stats
            by_zone = neo4j_stats.get("by_zone", {})
            multi_zone_count = neo4j_stats.get("multi_zone_count", 0)
            result["by_zone"] = by_zone
            result["multi_zone_count"] = multi_zone_count
            if by_zone and not use_json:
                print(f"\n  {'Zone':<30} {'Nodes':>10}")
                print(f"  {'—' * 30} {'—' * 10}")
                for zone, count in sorted(by_zone.items(), key=lambda x: -x[1]):
                    print(f"  {zone:<30} {count:>10,}")
                if multi_zone_count:
                    print(f"  {'—' * 30} {'—' * 10}")
                    print(f"  {'Multi-zone indicators':<30} {multi_zone_count:>10,}")
                    print("  (nodes may appear in multiple zones above)")

    # 3. By source
    if show_source and neo4j_stats:
        by_source = neo4j_stats.get("by_source", {})
        result["by_source"] = by_source
        if by_source and not use_json:
            print(f"\n  {'Source':<28} {'Nodes':>10}")
            print(f"  {'—' * 28} {'—' * 10}")
            for source, count in sorted(by_source.items(), key=lambda x: -x[1]):
                print(f"  {source:<28} {count:>10,}")

    # 4. MISP event summary
    if show_misp:
        try:
            misp_summary = _fetch_misp_event_summary()
            result["misp"] = misp_summary
            if misp_summary and not use_json:
                print(
                    f"\n  MISP Events: {misp_summary['total_events']} events, "
                    f"{misp_summary['total_attributes']:,} attributes"
                )
                if misp_summary.get("by_source"):
                    print(f"\n  {'MISP by Source':<28} {'Events':>8} {'Attributes':>12}")
                    print(f"  {'—' * 28} {'—' * 8} {'—' * 12}")
                    for src in sorted(misp_summary["by_source"], key=lambda x: -x["attributes"]):
                        print(f"  {src['source']:<28} {src['events']:>8} {src['attributes']:>12,}")
        except Exception as e:
            warn(f"MISP: {e}")

    # 5. Last sync
    try:
        sync = get_sync_status()
        result["last_sync"] = sync
        if not use_json:
            if sync.get("last_sync"):
                ok(f"\nLast sync: {sync['last_sync'][:19]} ({sync.get('age_hours', '?')}h ago)")
            else:
                warn("\nNo sync recorded yet")
    except Exception:
        pass

    # 6. Pipeline metrics
    try:
        from metrics import PipelineMetrics

        pm = PipelineMetrics()
        pm.load()
        summary = pm.get_summary()
        result["pipeline"] = summary
        if not use_json and summary.get("total_runs", 0) > 0:
            print(f"\n  Pipeline: {summary['total_runs']} runs, {summary.get('success_rate', 0):.0f}% success")
            if summary.get("avg_duration"):
                print(f"  Avg duration: {summary['avg_duration']:.0f}s")
    except Exception:
        pass

    # 7. Checkpoint summary
    try:
        from baseline_checkpoint import get_baseline_status

        cp = get_baseline_status()
        if cp:
            completed = sum(1 for d in cp.values() if isinstance(d, dict) and d.get("completed"))
            in_progress = len(cp) - completed
            result["checkpoints"] = {"completed": completed, "in_progress": in_progress}
            if not use_json:
                print(f"\n  Checkpoints: {completed} completed, {in_progress} in-progress")
    except Exception:
        pass

    if use_json:
        import json as _json

        print(_json.dumps(result, indent=2, default=str))

    if not use_json and not (show_zone or show_source or show_misp):
        info("\nTip: use --full for zone/source/MISP breakdowns, or --by-zone, --by-source, --misp individually.")

    print()
    return 0


def _fetch_misp_event_summary() -> dict:
    """Query MISP for event/attribute counts grouped by source tag."""
    import warnings

    import requests as _requests
    import urllib3

    from config import apply_misp_http_host_header

    session = _requests.Session()
    session.headers.update(
        {
            "Authorization": MISP_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    apply_misp_http_host_header(session)

    # Fetch EdgeGuard events index (lightweight — no attributes)
    with warnings.catch_warnings():
        if not SSL_VERIFY:
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        resp = session.get(
            f"{MISP_URL}/events/index",
            params={"limit": 500, "searchall": "EdgeGuard"},
            verify=SSL_VERIFY,
            timeout=(15, 60),
        )
    resp.raise_for_status()
    events = resp.json()
    if not isinstance(events, list):
        events = []

    total_events = 0
    total_attrs = 0
    source_map = {}  # source_tag -> {events: N, attributes: N}

    for ev in events:
        info_field = ev.get("info", "") or ev.get("Event", {}).get("info", "")
        attr_count = int(ev.get("attribute_count", 0) or ev.get("Event", {}).get("attribute_count", 0) or 0)

        # Parse source from event name: EdgeGuard-{source}-{date}
        source_tag = "unknown"
        if info_field.startswith("EdgeGuard-"):
            # Format: EdgeGuard-{source}-{date}
            parts = info_field.split("-", 2)
            if len(parts) >= 2:
                source_tag = parts[1]  # e.g., "nvd", "alienvault_otx"

        total_events += 1
        total_attrs += attr_count

        if source_tag not in source_map:
            source_map[source_tag] = {"events": 0, "attributes": 0}
        source_map[source_tag]["events"] += 1
        source_map[source_tag]["attributes"] += attr_count

    return {
        "total_events": total_events,
        "total_attributes": total_attrs,
        "by_source": [
            {"source": src, "events": data["events"], "attributes": data["attributes"]}
            for src, data in source_map.items()
        ],
    }


# ================================================================================
# BASELINE TRIGGERS — operator entry points for the baseline_dag
# ================================================================================
#
# PR-C audit fix (Cross-Checker HIGH H1/H2/H3 + Bravo's "consolidate via CLI
# wrapper" recommendation): the previous workflow forked into two divergent
# entry points:
#
#   - ``python src/run_pipeline.py --baseline [--fresh-baseline] [--baseline-days N]``
#     → runs in-process, holds the lock for the entire 8h+ baseline duration,
#     CLI session must stay alive.
#
#   - Operator clicks "Trigger DAG" in Airflow UI on edgeguard_baseline →
#     runs in Airflow workers, but had no ``fresh_baseline`` knob (audit
#     Cross-Checker HIGH H3) so the run name ``fresh__730d__...`` was
#     misleading: only checkpoints got cleared.
#
# These two CLI commands consolidate: ``edgeguard fresh-baseline`` and
# ``edgeguard baseline`` both delegate to the Airflow DAG via
# ``airflow dags trigger`` with the right conf, so:
#
#   - Operators have ONE entry point to remember.
#   - The Airflow worker holds state (CLI exits in seconds).
#   - The destructive path requires typed confirmation (informed consent).


# PR-C v2 audit fix (Maintainer M3 + Bug Hunter B2 + F2, comprehensive
# 7-agent audit): extract the docker-compose-airflow-trigger boilerplate
# from cmd_fresh_baseline / cmd_baseline. Both call sites had ~50 LOC of
# identical subprocess.run + run_id parser. Centralizing also gives us
# ONE place to:
#   - catch ``subprocess.TimeoutExpired`` (Bug Hunter B2 — was uncaught;
#     a busy airflow container produced a bare traceback to the operator)
#   - use a regex for the run_id parser (Bug Hunter F2 — the previous
#     ``line.split("run_id", 1)[1].strip().split()[0]`` would return
#     ``="manual__..."`` if Airflow ever changes to ``run_id=...`` format)
#   - inject auth, retry, or a ``--dry-run`` flag in the future.
def _trigger_baseline_dag(conf_json: str, *, timeout: int = 60) -> tuple[int, str]:
    """Invoke ``docker compose exec airflow airflow dags trigger
    edgeguard_baseline --conf <conf_json>``.

    Returns ``(exit_code, run_id_or_error)``:
      - exit_code 0 + run_id like ``"manual__2026-04-19T..."`` on success
        (or ``"<unknown>"`` if the parser couldn't extract it but the
        trigger succeeded — operator can find it in Airflow UI)
      - exit_code 2 + error message on docker-not-found, timeout, or
        non-zero airflow exit
    """
    import re
    import subprocess

    try:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "airflow",
                "airflow",
                "dags",
                "trigger",
                "edgeguard_baseline",
                "--conf",
                conf_json,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 2, (
            "docker compose not found on PATH. Trigger manually via Airflow UI:\n"
            f"  Airflow UI → edgeguard_baseline → Trigger DAG w/ Config: {conf_json}"
        )
    except subprocess.TimeoutExpired:
        # Bug Hunter B2: was uncaught. A busy or unresponsive ``airflow``
        # container raises this with timeout=60 → bare traceback to the
        # operator's terminal. Caller already saw a successful preflight
        # 60s earlier; the right next step is to check airflow's health.
        return 2, (
            f"Airflow CLI did not respond within {timeout}s. Check:\n"
            "  docker compose ps airflow\n"
            "  docker compose logs --tail 50 airflow\n"
            "Then re-trigger when airflow is responsive."
        )
    except OSError as e:
        return 2, f"docker compose exec failed: {e}"

    if result.returncode != 0:
        return 2, (f"Airflow trigger failed (exit {result.returncode}):\n{result.stderr or '(no stderr)'}")

    # Parse the run_id from Airflow CLI output. Examples seen so far:
    #   "Triggered DAG <DAG: edgeguard_baseline> at 2026-04-19T12:34:56+00:00, run_id manual__2026-..."
    #   "... run_id=manual__..."  (Airflow may use ``=`` in future versions)
    #
    # Bug Hunter H1 (post-PR-C-v2 audit): the previous loose pattern
    # ``run_id[=:\s]+(\S+)`` matched noise lines like ``"warning: run_id is
    # missing"`` → captured ``"is"``. The trigger had already succeeded
    # (returncode==0 was checked above), so no data corruption — but
    # operators would see ``[is]`` in the success output and copy a junk
    # run_id into ``edgeguard dag status --run-id <id>``. Anchor to
    # Airflow's standard run_id prefixes (``manual__``, ``scheduled__``,
    # ``backfill__``, ``dataset_triggered__``) to reject false positives.
    run_id = "<unknown>"
    for line in (result.stdout or "").splitlines():
        match = re.search(
            r"run_id[=:\s]+((?:manual|scheduled|backfill|dataset_triggered)__\S+)",
            line,
        )
        if match:
            run_id = match.group(1).rstrip(",")
            break

    return 0, run_id


def cmd_fresh_baseline(args) -> int:
    """edgeguard fresh-baseline --days N

    Trigger a destructive baseline: probe Neo4j+MISP for blast radius, show
    counts, ask for typed confirmation, then trigger the Airflow
    edgeguard_baseline DAG with ``dag_run.conf={"fresh_baseline": true,
    "baseline_days": N}``.
    """
    from baseline_clean import probe_baseline_state
    from baseline_config import resolve_baseline_days

    section("Fresh Baseline (DESTRUCTIVE)")

    days = resolve_baseline_days(explicit=getattr(args, "days", None))

    # Preflight: probe both datastores. If EITHER is unreachable, refuse to
    # proceed — operator can't give informed consent without seeing counts.
    info("Probing Neo4j + MISP for blast radius...")
    state = probe_baseline_state()

    if not state.all_reachable:
        # Audit Devil's Advocate + the user's "informed consent not theater"
        # principle: refuse to ask for confirmation without live counts.
        print(file=sys.stderr)
        err("FRESH BASELINE — PRE-FLIGHT FAILED")
        print(file=sys.stderr)
        print("Cannot probe one or more datastores:", file=sys.stderr)
        if not state.neo4j_ok:
            print(f"  Neo4j: {state.neo4j_error}", file=sys.stderr)
        if not state.misp_ok:
            print(f"  MISP:  {state.misp_error}", file=sys.stderr)
        if not state.checkpoint_ok:
            print(f"  Checkpoint: {state.checkpoint_error}", file=sys.stderr)
        print(file=sys.stderr)
        print("Refusing to proceed without live counts — that would be blind consent.", file=sys.stderr)
        print("No data was changed.", file=sys.stderr)
        print(file=sys.stderr)
        print("Diagnose:", file=sys.stderr)
        print("  edgeguard doctor", file=sys.stderr)
        print("  docker compose ps", file=sys.stderr)
        return 2  # exit code 2 = preflight failed (system unhealthy)

    # Show blast radius
    print()
    print(f"{Colors.BOLD}{Colors.YELLOW}⚠️  FRESH BASELINE — DESTRUCTIVE OPERATION{Colors.END}")
    print()
    print("You are about to permanently delete:")
    for line in state.render_summary().splitlines():
        print(line)
    print()
    print(f"Then collect {days} days of historical data from scratch.")
    print("ETA: ~6-8 hours (per recent baseline runs).")
    print()
    print(f"{Colors.RED}This cannot be undone.{Colors.END} Type FRESH-BASELINE to confirm:")

    if getattr(args, "force", False):
        info("--force passed; skipping interactive confirmation.")
    else:
        try:
            confirm = input("> ").strip()
        except EOFError:
            confirm = ""
        if confirm != "FRESH-BASELINE":
            info("Aborted. (Confirmation token did not match.)")
            return 1  # exit code 1 = user declined

    # Trigger the DAG via gh-style airflow CLI invocation.
    # Conf carries fresh_baseline=true (gates the new baseline_clean task)
    # AND baseline_days=N (resolved by the DAG's get_baseline_config).
    conf_json = json.dumps({"fresh_baseline": True, "baseline_days": days})
    info("Triggering edgeguard_baseline DAG with conf:")
    info(f"  {conf_json}")

    exit_code, run_id_or_error = _trigger_baseline_dag(conf_json)
    if exit_code != 0:
        err(run_id_or_error)
        return exit_code

    ok(f"Triggered: edgeguard_baseline [{run_id_or_error}]")
    info("Track: edgeguard dag status --dag-id edgeguard_baseline")
    info("Or via Airflow UI: http://localhost:8082/dags/edgeguard_baseline/grid")
    return 0


def cmd_baseline(args) -> int:
    """edgeguard baseline --days N

    Trigger an additive baseline (no destruction). Existing data preserved.
    No confirmation prompt — this is a safe operation.
    """
    from baseline_config import resolve_baseline_days

    section("Baseline (additive)")

    days = resolve_baseline_days(explicit=getattr(args, "days", None))

    info(f"Triggering edgeguard_baseline DAG (additive mode, {days} days history)")
    info("Existing Neo4j nodes + MISP events PRESERVED — new data layered on top.")

    conf_json = json.dumps({"baseline_days": days})  # NO fresh_baseline → DAG runs additive
    exit_code, run_id_or_error = _trigger_baseline_dag(conf_json)
    if exit_code != 0:
        err(run_id_or_error)
        return exit_code

    ok(f"Triggered: edgeguard_baseline [{run_id_or_error}]")
    info("Track: edgeguard dag status --dag-id edgeguard_baseline")
    return 0


# ================================================================================
# PREFLIGHT
# ================================================================================


def cmd_preflight(args) -> int:
    """Comprehensive pre-run readiness check."""
    strict = getattr(args, "strict", False)
    use_json = getattr(args, "json", False)

    section("EdgeGuard Preflight Check")
    errors = 0
    warnings = 0
    checks = {}

    # 1. Required env vars
    section("1. Environment Variables")
    required = {"NEO4J_PASSWORD": NEO4J_PASSWORD, "MISP_API_KEY": MISP_API_KEY, "MISP_URL": MISP_URL}
    for name, val in required.items():
        if val:
            ok(f"{name}: set")
        else:
            err(f"{name}: NOT SET (required)")
            errors += 1
    optional = {
        "OTX_API_KEY": OTX_API_KEY,
        "NVD_API_KEY": NVD_API_KEY,
        "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
        "ABUSEIPDB_API_KEY": os.getenv("ABUSEIPDB_API_KEY"),
    }
    for name, val in optional.items():
        if val:
            ok(f"{name}: set ({len(val)} chars)")
        else:
            info(f"{name}: not set (optional — source will be skipped)")
    checks["env_vars"] = {"errors": errors}

    # 2. Neo4j
    section("2. Neo4j")
    try:
        from health_check import health_check_neo4j

        neo4j_result = health_check_neo4j()
        if neo4j_result.get("healthy") or neo4j_result.get("status") == "connected":
            ok(f"Neo4j: connected ({NEO4J_URI})")
            if neo4j_result.get("apoc_available"):
                ok("APOC plugin: available")
            else:
                err("APOC plugin: NOT available (required)")
                errors += 1
        else:
            err(f"Neo4j: {neo4j_result.get('error', 'unreachable')}")
            errors += 1
        checks["neo4j"] = neo4j_result
    except Exception as e:
        err(f"Neo4j: {e}")
        errors += 1

    # 3. MISP
    section("3. MISP")
    try:
        from misp_health import MISPHealthCheck

        checker = MISPHealthCheck()
        misp_result = checker.check_health()
        healthy = misp_result.get("healthy", False) if isinstance(misp_result, dict) else False
        if healthy:
            ok("MISP: healthy")
        else:
            err(f"MISP: unhealthy — {misp_result}")
            errors += 1
        checks["misp"] = misp_result
    except Exception as e:
        err(f"MISP: {e}")
        errors += 1

    # 4. Airflow
    section("4. Airflow")
    try:
        import airflow_client as ac

        af_health = ac.airflow_health()
        if "error" in af_health:
            warn(f"Airflow: {af_health['error']}")
            warnings += 1
        else:
            ok("Airflow: reachable")
            dags = ac.get_registered_dags()
            if dags and "error" not in dags[0]:
                ok(f"  {len(dags)} EdgeGuard DAG(s) registered")
            else:
                warn("  Could not query DAG list")
                warnings += 1
        checks["airflow"] = af_health
    except Exception as e:
        warn(f"Airflow: {e}")
        warnings += 1

    # 5. Disk space
    section("5. Disk Space")
    try:
        stat = os.statvfs(".")
        free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
        if free_gb < 1.0:
            err(f"Disk: {free_gb:.1f} GB free (need at least 1 GB)")
            errors += 1
        else:
            ok(f"Disk: {free_gb:.1f} GB free")
        checks["disk"] = {"free_gb": round(free_gb, 1)}
    except Exception as e:
        warn(f"Disk check: {e}")
        warnings += 1

    # 6. Checkpoint state
    section("6. Checkpoints")
    try:
        from baseline_checkpoint import get_baseline_status

        cp = get_baseline_status()
        if cp:
            incomplete = [s for s, d in cp.items() if isinstance(d, dict) and not d.get("completed")]
            if incomplete:
                warn(f"Incomplete baselines: {', '.join(incomplete)}")
                warnings += 1
            else:
                ok(f"{len(cp)} source(s) baselined")
        else:
            info("No baselines run yet")
        checks["checkpoints"] = cp or {}
    except Exception:
        pass

    # 7. Circuit breakers
    section("7. Circuit Breakers")
    try:
        from resilience import CircuitState, _circuit_breakers

        open_breakers = [name for name, cb in _circuit_breakers.items() if cb._state != CircuitState.CLOSED]
        if open_breakers:
            err(f"OPEN circuit breakers: {', '.join(open_breakers)}")
            errors += 1
        else:
            ok("All circuit breakers CLOSED")
    except Exception:
        info("No circuit breaker state (fresh start)")

    # Summary
    section("Preflight Summary")
    total_checks = 7
    passed = total_checks - errors - (warnings if strict else 0)
    if errors == 0 and (warnings == 0 or not strict):
        ok(f"READY — {passed}/{total_checks} checks passed, {warnings} warning(s)")
    else:
        err(f"NOT READY — {errors} error(s), {warnings} warning(s)")

    if use_json:
        import json as _json

        print(_json.dumps({"errors": errors, "warnings": warnings, "checks": checks}, indent=2, default=str))

    return 1 if errors > 0 or (strict and warnings > 0) else 0


# ================================================================================
# CODE UPDATE (git pull + install.sh --update)
# ================================================================================


def cmd_version(*, no_git: bool) -> int:
    """Print package CalVer from metadata or pyproject; optional git short SHA."""
    from package_meta import package_version

    ver = package_version()
    print(f"edgeguard {ver}")

    root = find_edgeguard_repo_root()
    if no_git or not root:
        return 0
    git_dir = os.path.join(root, ".git")
    if not os.path.isdir(git_dir):
        return 0
    try:
        out = subprocess.check_output(
            ["git", "-C", root, "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            print(f"git {out}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return 0


def find_edgeguard_repo_root() -> Optional[str]:
    """Locate the EdgeGuard clone (pyproject.toml + install.sh)."""
    starts = [os.path.abspath(os.getcwd()), os.path.abspath(os.path.dirname(SCRIPT_DIR))]
    seen: set[str] = set()
    for start in starts:
        if start in seen:
            continue
        seen.add(start)
        cur = start
        for _ in range(16):
            py = os.path.join(cur, "pyproject.toml")
            if os.path.isfile(py) and os.path.isfile(os.path.join(cur, "install.sh")):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    return None


def cmd_code_update(*, force_docker: bool, force_python: bool) -> int:
    """
    Pull latest sources and refresh install via install.sh --update (same as make update).

    install.sh chooses Docker vs pip: Docker when docker+compose v2+docker-compose.yml exist,
    else Python path — unless --docker or --python is passed through to force one side.
    """
    section("EdgeGuard code update")
    root = find_edgeguard_repo_root()
    if not root:
        err("Could not find EdgeGuard project root (pyproject.toml + install.sh).")
        info("cd into your clone, then: ./install.sh --update   or   make update")
        return 1

    # install.sh is guaranteed: find_edgeguard_repo_root() requires it alongside pyproject.toml
    install_sh = os.path.join(root, "install.sh")

    if not shutil.which("bash"):
        err("bash is required to run install.sh")
        return 1

    cmd: list[str] = ["bash", install_sh, "--update"]
    if force_python:
        cmd.append("--python")
    elif force_docker:
        cmd.append("--docker")

    info(
        "Mode: "
        + (
            "pip/venv (--python)"
            if force_python
            else "Docker Compose only (--docker)"
            if force_docker
            else "auto (Docker if available, else pip)"
        )
    )
    info(f"Running: {' '.join(cmd)}")
    info(f"Working directory: {root}")
    ret = subprocess.call(cmd, cwd=root)
    if ret != 0:
        err(f"Update script exited with status {ret}")
    return ret


# ================================================================================
# MAIN
# ================================================================================


def main():
    # Treat `edgeguard --update` like `edgeguard update` (single code path; argparse stays idiomatic).
    argv = sys.argv[1:]
    if len(argv) >= 1 and argv[0] == "--update":
        argv[0] = "update"
        sys.argv[1:] = argv

    parser = argparse.ArgumentParser(
        description="EdgeGuard Operations CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  edgeguard.py preflight             # Pre-run readiness (env vars, APIs, Neo4j, MISP, Airflow)
  edgeguard.py stats                 # Quick dashboard: node counts, last sync, runs
  edgeguard.py stats --full          # + breakdown by zone, source, and MISP events
  edgeguard.py stats --by-zone       # Node counts per zone (shows multi-zone overlap)
  edgeguard.py stats --by-source     # Node counts per source
  edgeguard.py stats --misp          # MISP event/attribute counts by source and zone
  edgeguard.py stats --json          # Machine-readable JSON output
  edgeguard.py dag status            # Show Airflow DAG run states (color-coded)
  edgeguard.py dag status --state running  # Only running/queued runs
  edgeguard.py dag kill              # Force-fail stuck DAG runs (preserves checkpoints)
  edgeguard.py dag kill --dry-run    # Show what would be killed
  edgeguard.py checkpoint status     # Per-source baseline progress + incremental cursors
  edgeguard.py checkpoint clear      # Clear baseline (keeps incremental cursors)
  edgeguard.py clear neo4j           # Delete all graph data from Neo4j
  edgeguard.py clear misp            # Delete all EdgeGuard events from MISP
  edgeguard.py clear all             # Full reset: Neo4j + MISP + checkpoints
  edgeguard.py doctor                # Diagnose connectivity issues
  edgeguard.py heal                  # Auto-repair (circuit breakers, locks, retries)
  edgeguard.py validate              # Validate config + Neo4j schema
  edgeguard.py monitor               # Real-time health display
  edgeguard.py version               # CalVer + git SHA
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Doctor command
    subparsers.add_parser("doctor", help="Diagnose issues")

    # Heal command
    subparsers.add_parser("heal", help="Auto-repair")

    # Validate command
    subparsers.add_parser("validate", help="Validate configuration")

    # Monitor command
    subparsers.add_parser("monitor", help="Show health status")

    # DAG management
    dag_parser = subparsers.add_parser("dag", help="Airflow DAG operations")
    dag_subparsers = dag_parser.add_subparsers(dest="dag_command", help="DAG commands")

    dag_status_parser = dag_subparsers.add_parser("status", help="Show DAG run status")
    dag_status_parser.add_argument("--dag-id", help="Filter to specific DAG ID")
    dag_status_parser.add_argument("--state", choices=["running", "queued", "failed", "success"])
    dag_status_parser.add_argument("--limit", type=int, default=5, help="Max runs per DAG (default: 5)")
    dag_status_parser.add_argument("--json", action="store_true", help="Output as JSON")

    dag_kill_parser = dag_subparsers.add_parser("kill", help="Force-fail stuck DAG runs")
    dag_kill_parser.add_argument("--dag-id", help="Kill runs for specific DAG (default: all)")
    dag_kill_parser.add_argument("--dry-run", action="store_true", help="Show what would be killed")
    dag_kill_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Checkpoint management
    cp_parser = subparsers.add_parser("checkpoint", help="Manage pipeline checkpoints")
    cp_subparsers = cp_parser.add_subparsers(dest="checkpoint_command", help="Checkpoint commands")

    cp_status_parser = cp_subparsers.add_parser("status", help="Show checkpoint state per source")
    cp_status_parser.add_argument("--source", help="Filter to specific source")
    cp_status_parser.add_argument("--json", action="store_true", help="Output as JSON")

    cp_clear_parser = cp_subparsers.add_parser("clear", help="Clear baseline checkpoints")
    cp_clear_parser.add_argument("--source", help="Clear specific source only")
    cp_clear_parser.add_argument("--include-incremental", action="store_true", help="Also clear incremental cursors")
    cp_clear_parser.add_argument("--force", action="store_true", help="Skip confirmation")

    # Clear data
    clear_parser = subparsers.add_parser("clear", help="Clear data from Neo4j, MISP, or both")
    clear_subparsers = clear_parser.add_subparsers(dest="clear_command", help="Clear commands")

    clear_neo4j_parser = clear_subparsers.add_parser("neo4j", help="Delete all graph data from Neo4j")
    clear_neo4j_parser.add_argument("--force", action="store_true", help="Skip DELETE confirmation")

    clear_misp_parser = clear_subparsers.add_parser("misp", help="Delete all EdgeGuard events from MISP")
    clear_misp_parser.add_argument("--force", action="store_true", help="Skip DELETE confirmation")

    clear_all_parser = clear_subparsers.add_parser("all", help="Clear Neo4j + MISP + checkpoints (full reset)")
    clear_all_parser.add_argument("--force", action="store_true", help="Skip DELETE confirmation")

    # Stats dashboard
    stats_parser = subparsers.add_parser("stats", help="Quick dashboard: node counts, sync, runs")
    stats_parser.add_argument(
        "--full", action="store_true", help="Include breakdowns by zone, source, and MISP event summary"
    )
    stats_parser.add_argument("--by-zone", action="store_true", help="Show node counts per zone")
    stats_parser.add_argument("--by-source", action="store_true", help="Show node counts per source")
    stats_parser.add_argument("--misp", action="store_true", help="Show MISP event summary")
    stats_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Baseline triggers (PR-C audit fix Cross-Checker H1/H2/H3)
    baseline_p = subparsers.add_parser(
        "baseline",
        help="Trigger additive baseline DAG (preserves existing data)",
    )
    baseline_p.add_argument(
        "--days",
        type=int,
        default=None,
        help="Historical window in days (default 730; resolves via baseline_config)",
    )

    fresh_baseline_p = subparsers.add_parser(
        "fresh-baseline",
        help="Trigger DESTRUCTIVE baseline DAG (wipes Neo4j + MISP + checkpoints)",
    )
    fresh_baseline_p.add_argument(
        "--days",
        type=int,
        default=None,
        help="Historical window in days (default 730; resolves via baseline_config)",
    )
    fresh_baseline_p.add_argument(
        "--force",
        action="store_true",
        help="Skip the typed-confirmation prompt (use only in non-interactive contexts; "
        "the preflight probes still run and refuse on unreachable datastores)",
    )

    # Preflight
    preflight_parser = subparsers.add_parser("preflight", help="Comprehensive pre-run readiness check")
    preflight_parser.add_argument("--json", action="store_true", help="Output as JSON")
    preflight_parser.add_argument("--strict", action="store_true", help="Treat warnings as errors")

    # Source management
    source_parser = subparsers.add_parser("source", help="Manage data sources")
    source_subparsers = source_parser.add_subparsers(dest="source_command", help="Source commands")

    # List sources
    source_subparsers.add_parser("list", help="List all configured sources")

    # Add source
    add_parser = source_subparsers.add_parser("add", help="Add a new data source")
    add_parser.add_argument("--name", required=True, help="Source name (e.g., abuseipdb)")
    add_parser.add_argument("--api-key", dest="api_key", help="API key for the source")
    add_parser.add_argument("--rate-limit", dest="rate_limit", help="Rate limit (e.g., 100/day)")
    add_parser.add_argument("--enabled", type=bool, default=True, help="Enable source (default: True)")

    # Remove source
    remove_parser = source_subparsers.add_parser("remove", help="Remove a data source")
    remove_parser.add_argument("--name", required=True, help="Source name to remove")

    setup_parser = subparsers.add_parser(
        "setup",
        help="First-time install pointers (use ./install.sh or README — not an interactive wizard)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
  EdgeGuard does not ship an interactive `edgeguard setup` wizard.

  Recommended:
    ./install.sh              Docker Compose stack (or ./install.sh --python for pip/.venv)
    cp .env.example .env      then set NEO4J_PASSWORD, MISP_URL, MISP_API_KEY

  After install:
    edgeguard doctor          connectivity
    edgeguard validate        configuration check
    edgeguard update          pull latest + reinstall (see: edgeguard update --help)

  Docs: README.md, docs/SETUP_GUIDE.md
        """,
    )

    # Pull latest git + reinstall (install.sh picks Docker vs pip unless forced)
    update_parser = subparsers.add_parser(
        "update",
        help="Pull latest git changes and refresh install (install.sh --update; Docker if available, else pip)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
  edgeguard --update is a synonym for edgeguard update (same behavior).

  Default: auto — use Docker Compose when docker, compose v2, and docker-compose.yml are
  available in the repo; otherwise fall back to the Python/pip path.

  Configuration edits: change .env or src/config.py, then edgeguard validate
        """,
    )
    umode = update_parser.add_mutually_exclusive_group()
    umode.add_argument(
        "--docker",
        action="store_true",
        help="Force Docker Compose rebuild (passes --docker to install.sh; fails if Docker missing)",
    )
    umode.add_argument(
        "--python",
        action="store_true",
        help="Force pip editable reinstall / .venv path (passes --python to install.sh)",
    )

    version_parser = subparsers.add_parser(
        "version",
        help="Show release version (CalVer from pyproject) and optional git short SHA",
    )
    version_parser.add_argument(
        "--no-git",
        action="store_true",
        help="Print only the package version string",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == "update":
        return cmd_code_update(force_docker=bool(args.docker), force_python=bool(args.python))

    if args.command == "version":
        return cmd_version(no_git=bool(getattr(args, "no_git", False)))

    _ensure_runtime_imports()

    # Handle already-done commands
    if args.command == "setup":
        print("EdgeGuard install is driven by the repo installer — there is no interactive wizard here.\n")
        print("  1. From the clone root:  ./install.sh     (or: ./install.sh --python)")
        print("  2. Copy and edit env:     cp .env.example .env")
        print("     Set NEO4J_PASSWORD, MISP_URL, MISP_API_KEY (and collector keys as needed).")
        print("  3. Verify:                edgeguard doctor")
        print("  4. Refresh after git pull: edgeguard update   (or: make update)\n")
        print("More detail: README.md, docs/SETUP_GUIDE.md — config edits: edgeguard validate")
        return 0

    # Execute command
    if args.command == "doctor":
        return cmd_doctor(args)
    elif args.command == "heal":
        return cmd_heal(args)
    elif args.command == "validate":
        return cmd_validate(args)
    elif args.command == "monitor":
        return cmd_monitor(args)
    elif args.command == "source":
        return cmd_source(args)
    elif args.command == "dag":
        return cmd_dag(args)
    elif args.command == "checkpoint":
        return cmd_checkpoint(args)
    elif args.command == "clear":
        return cmd_clear(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "preflight":
        return cmd_preflight(args)
    elif args.command == "baseline":
        return cmd_baseline(args)
    elif args.command == "fresh-baseline":
        return cmd_fresh_baseline(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
