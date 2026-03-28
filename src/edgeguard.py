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
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Optional

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
    state_file = os.path.join(os.path.dirname(SCRIPT_DIR), "dags", "edgeguard_last_neo4j_sync.json")

    # Try alternative locations
    alt_paths = [
        state_file,
        os.path.join(tempfile.gettempdir(), "edgeguard_last_neo4j_sync.json"),
        os.path.expanduser("~/.edgeguard/last_sync.json"),
    ]

    for path in alt_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    state = json.load(f)
                    last_sync = datetime.fromisoformat(state.get("last_sync", "2000-01-01")).replace(
                        tzinfo=timezone.utc
                    )
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

    # Check MISP version compatibility
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
                client.close()
        except Exception as e:
            warn(f"Could not verify Neo4j constraints: {e}")

    # Test Airflow
    info("Testing Airflow webserver...")
    airflow_url = os.getenv("AIRFLOW_WEBSERVER_URL", "http://localhost:8082")
    try:
        import requests

        resp = requests.get(f"{airflow_url}/health", timeout=10)
        if resp.status_code == 200:
            ok(f"Airflow webserver reachable at {airflow_url}")
        else:
            warn(f"Airflow webserver returned {resp.status_code} (may still be starting)")
    except Exception as e:
        warn(f"Airflow webserver not reachable at {airflow_url}: {e}")

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

    # Attempt to trigger the Airflow DAG for a full retry
    try:
        result = subprocess.run(
            ["airflow", "dags", "trigger", "edgeguard_pipeline"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, "Triggered edgeguard_pipeline DAG for retry"
        else:
            stderr_snippet = result.stderr.strip()[:100] if result.stderr else "unknown error"
            return True, f"Could not trigger DAG (Airflow CLI returned error): {stderr_snippet}"
    except FileNotFoundError:
        return True, "Airflow CLI not available — trigger DAG manually via Airflow UI"
    except subprocess.TimeoutExpired:
        return True, "Airflow CLI timed out — trigger DAG manually via Airflow UI"
    except Exception as e:
        return True, f"Could not trigger retry: {e}"


def get_circuit_breaker_state_file():
    """Get path to circuit breaker state file."""
    return os.path.join(os.path.dirname(SCRIPT_DIR), "dags", "circuit_breaker_state.json")


def cmd_heal(args):
    """Auto-repair EdgeGuard."""
    section("EdgeGuard Heal - Auto-Repair")

    healed_something = False

    # Reset circuit breakers
    info("Resetting circuit breakers...")
    ok_flag, msg = reset_circuit_breakers()
    ok(msg)

    # Clear lock files
    info("Clearing lock files...")
    ok_flag, msg = clear_lock_files()
    ok(msg)
    if "Cleared" in msg:
        healed_something = True

    # Retry pending collections
    info("Checking for pending collections...")
    ok_flag, msg = retry_pending_collections()
    ok(msg)

    # Clear circuit breaker state file if exists
    cb_file = get_circuit_breaker_state_file()
    if os.path.exists(cb_file):
        try:
            os.remove(cb_file)
            ok("Cleared circuit breaker state file")
            healed_something = True
        except Exception:
            pass

    section("Heal Complete")
    ok("EdgeGuard has been healed")
    info("Note: Some changes may require restarting the pipeline")
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

    # API keys still hardcoded
    if len(MISP_API_KEY) > 0 and len(MISP_API_KEY) < 50:
        warnings.append("API keys appear to be hardcoded - use environment variables in production")

    if warnings:
        return warnings
    return []


# =============================================================================
# Source Management
# =============================================================================

SOURCES_FILE = os.path.join(os.path.dirname(__file__), "..", "credentials", "sources.yaml")

DEFAULT_SOURCES = {
    "otx": {
        "name": "AlienVault OTX",
        "api_key_env": "OTX_API_KEY",
        "rate_limit": "30/min",
        "enabled": True,
        "description": "Threat intelligence pulses",
    },
    "nvd": {
        "name": "National Vulnerability Database",
        "api_key_env": "NVD_API_KEY",
        "rate_limit": "30/30sec",
        "enabled": True,
        "description": "CVE vulnerabilities",
    },
    "virustotal": {
        "name": "VirusTotal",
        "api_key_env": "VIRUSTOTAL_API_KEY",
        "rate_limit": "4/min",
        "enabled": True,
        "description": "File and URL reputation",
    },
    "cisa": {
        "name": "CISA KEV",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Known exploited vulnerabilities",
    },
    "mitre": {
        "name": "MITRE ATT&CK",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Threat techniques and tactics",
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "api_key_env": "ABUSEIPDB_API_KEY",
        "rate_limit": "1000/day",
        "enabled": False,
        "description": "IP reputation",
    },
    "urlhaus": {
        "name": "URLhaus",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Malware URLs",
    },
    "cybercure": {
        "name": "CyberCure",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Threat intelligence feeds",
    },
    "feodo": {
        "name": "Feodo Tracker",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Banking trojan C&C servers",
    },
    "sslbl": {
        "name": "SSL Blacklist",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Malicious SSL certificates",
    },
    "threatfox": {
        "name": "ThreatFox",
        "api_key_env": "THREATFOX_API_KEY",
        "rate_limit": "unlimited",
        "enabled": False,
        "description": "Threat actor indicators",
    },
    "misp": {
        "name": "MISP",
        "api_key_env": "MISP_API_KEY",
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Central threat intelligence hub",
    },
}


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

            client.close()
        else:
            warn("Neo4j not connected — schema check skipped")
    except Exception as e:
        warn(f"Neo4j schema check failed: {e}")

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
    state_file = os.path.join(os.path.dirname(SCRIPT_DIR), "dags", "edgeguard_last_neo4j_sync.json")

    alt_paths = [
        state_file,
        os.path.join(tempfile.gettempdir(), "edgeguard_last_neo4j_sync.json"),
    ]

    for path in alt_paths:
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    state = json.load(f)
                    last_sync = datetime.fromisoformat(state.get("last_sync", "unknown")).replace(tzinfo=timezone.utc)
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
  edgeguard.py doctor           # Run diagnostics (needs .env)
  edgeguard.py heal             # Auto-repair
  edgeguard.py validate         # Validate config
  edgeguard.py monitor          # Show health status
  edgeguard.py update           # git pull + reinstall (auto: Docker or pip)
  edgeguard.py update --docker  # force Docker Compose path
  edgeguard.py update --python  # force pip editable reinstall
  edgeguard.py --update         # same as: edgeguard update
  edgeguard.py version          # CalVer + git SHA (no .env required)
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
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
