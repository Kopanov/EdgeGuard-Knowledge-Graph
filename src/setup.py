#!/usr/bin/env python3
"""
EdgeGuard Setup CLI
===================
Interactive first-time setup for EdgeGuard configuration.
Creates config.yaml from user input with validation.
"""

import getpass
import re
import sys
from pathlib import Path


# Colors for terminal output
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_header():
    """Print welcome header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}")
    print("=" * 60)
    print("         Welcome to EdgeGuard Setup!")
    print("=" * 60)
    print(f"{Colors.RESET}")
    print("This wizard will help you configure EdgeGuard for first-time use.")
    print("Press Enter to accept default values shown in brackets.\n")


def print_success(msg: str):
    """Print success message."""
    print(f"{Colors.GREEN}✓{Colors.RESET} {msg}")


def print_warning(msg: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠{Colors.RESET} {msg}")


def print_error(msg: str):
    """Print error message."""
    print(f"{Colors.RED}✗{Colors.RESET} {msg}")


def print_info(msg: str):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ{Colors.RESET} {msg}")


def validate_url(url: str) -> bool:
    """Validate URL format."""
    url_pattern = re.compile(
        r"^https?://"  # http:// or https://
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain
        r"localhost|"  # localhost
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # or IP
        r"(?::\d+)?"  # optional port
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return url_pattern.match(url) is not None


def validate_api_key(key: str, service: str) -> bool:
    """Validate API key format (basic length check)."""
    if not key or len(key) < 8:
        return False
    # Most API keys are alphanumeric, possibly with dashes
    return bool(re.match(r"^[a-zA-Z0-9_-]+$", key))


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    """Prompt for yes/no answer."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ("y", "yes"):
            return True
        if response in ("n", "no"):
            return False
        print_error("Please answer 'y' or 'n'")


def prompt_with_default(prompt: str, default: str, hidden: bool = False) -> str:
    """Prompt for input with a default value."""
    while True:
        if hidden:
            response = getpass.getpass(
                f"{prompt} [{Colors.YELLOW}default: {Colors.RESET}{Colors.BOLD}{mask_value(default)}{Colors.RESET}]: "
            )
        else:
            response = input(f"{prompt} [{Colors.YELLOW}{default}{Colors.RESET}]: ").strip()

        if not response:
            return default

        # Validation feedback
        return response


def mask_value(value: str) -> str:
    """Mask a value for display."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def get_credentials_dir() -> Path:
    """Get the credentials directory path."""
    return Path(__file__).parent.parent / "credentials"


def get_config_path() -> Path:
    """Get the config.yaml path."""
    return get_credentials_dir() / "config.yaml"


def check_existing_config() -> bool:
    """Check if config.yaml already exists."""
    config_path = get_config_path()
    if config_path.exists():
        print_warning(f"Found existing config at {config_path}")
        return prompt_yes_no("Overwrite existing configuration?", default=False)
    return True


def validate_rate_limits(config: dict) -> list:
    """Validate rate limit settings and return warnings."""
    warnings = []
    intervals = config.get("intervals", {})
    misp_interval = intervals.get("misp_refresh_interval", 8)
    nvd_interval = intervals.get("source_intervals", {}).get("nvd", 0.5)
    vt_interval = intervals.get("source_intervals", {}).get("virustotal", 0.25)

    # MISP/OTX: recommend >= 30 min for OTX (30 req/min)
    if misp_interval < 2:
        warnings.append(
            f"MISP_REFRESH_INTERVAL ({misp_interval}h) is below recommended minimum "
            f"of 2h for OTX rate limiting (30 req/min)"
        )

    # NVD: recommend >= 30 sec
    if nvd_interval < 0.008:  # 30 seconds in hours
        warnings.append(f"NVD interval ({nvd_interval}h) may exceed rate limits. Recommended: >= 30 seconds (0.008h)")

    # VirusTotal: recommend >= 15 sec (4 req/min)
    if vt_interval < 0.004:  # 15 seconds in hours
        warnings.append(
            f"VirusTotal interval ({vt_interval}h) may exceed rate limits. Recommended: >= 15 seconds (0.004h)"
        )

    return warnings


def generate_config(
    misp_url: str,
    misp_api_key: str,
    misp_admin_email: str,
    misp_admin_password: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    otx_api_key: str,
    nvd_api_key: str,
    virustotal_api_key: str,
    abuseipdb_api_key: str,
    ssl_verify: bool,
    enable_metrics: bool,
    misp_interval: int,
    neo4j_interval: int,
) -> str:
    """Generate YAML configuration content."""

    # Build the config YAML
    config_lines = [
        "# =============================================================================",
        "# EdgeGuard Configuration",
        "# Generated by EdgeGuard Setup CLI",
        "# =============================================================================",
        "",
        "# NEO4J CONFIGURATION",
        "neo4j:",
        f'  uri: "{neo4j_uri}"',
        f'  user: "{neo4j_user}"',
        f'  password: "{neo4j_password}"',
        "",
        "# MISP CONFIGURATION",
        "misp:",
        f'  url: "{misp_url}"',
        f'  api_key: "{misp_api_key}"',
        f'  admin_email: "{misp_admin_email}"',
        f'  admin_password: "{misp_admin_password}"',
        f"  ssl_verify: {str(ssl_verify).lower()}",
        "",
        "# ALIENVAULT OTX",
        "otx:",
        f'  api_key: "{otx_api_key}"',
        "",
        "# NVD",
        "nvd:",
        f'  api_key: "{nvd_api_key}"',
        "",
        "# VIRUSTOTAL",
        "virustotal:",
        f'  api_key: "{virustotal_api_key}"',
        "  rate_limit: 4",
        "  daily_quota: 500",
        "",
        "# ABUSEIPDB (Optional)",
        "abuseipdb:",
        f'  api_key: "{abuseipdb_api_key}"',
        "",
        "# SLACK ALERTS (Optional)",
        "slack:",
        '  webhook_url: ""',
        "",
        "# EDGEGUARD SETTINGS",
        "edgeguard:",
        f"  enable_metrics: {str(enable_metrics).lower()}",
        "  max_entries_per_source: 500",
        "",
        "# COLLECTION INTERVALS",
        "intervals:",
        f"  misp_refresh_interval: {misp_interval}",
        f"  neo4j_sync_interval: {neo4j_interval}",
        "  source_intervals:",
        "    otx: 2",
        "    cisa: 0.5",
        "    nvd: 0.5",
        "    mitre: 24",
        "",
        "# SECTOR TIME RANGES (months)",
        "sector_time_ranges:",
        "  healthcare: 24",
        "  energy: 24",
        "  finance: 48",
        "  global: 12",
    ]

    return "\n".join(config_lines)


def check_prerequisites():
    """
    Check if required services (MISP, Neo4j) are available.
    Returns True to continue, False to abort.
    """
    print(f"{Colors.BOLD}{Colors.HEADER}=== PREREQUISITES CHECK ==={Colors.RESET}\n")
    print_info("EdgeGuard requires MISP and Neo4j to be running.\n")

    # Check MISP
    print(f"{Colors.BOLD}--- MISP ---{Colors.RESET}")
    has_misp = prompt_yes_no("Do you have a MISP instance running?", default=True)

    if not has_misp:
        print_warning("\n" + "=" * 60)
        print_warning("MISP is REQUIRED for EdgeGuard to work.")
        print_warning("=" * 60)
        print("""
To install MISP:
1. Docker: docker run -it -p 8443:443 -p 8080:80 --name misp -d coolacid/misp
2. Or follow: https://www.misp-project.org/download/

After installing MISP, run setup again.
""")
        return False

    # Check Neo4j
    print(f"\n{Colors.BOLD}--- Neo4j ---{Colors.RESET}")
    has_neo4j = prompt_yes_no("Do you have a Neo4j database running?", default=True)

    if not has_neo4j:
        print_warning("\n" + "=" * 60)
        print_warning("Neo4j is REQUIRED for EdgeGuard to work.")
        print_warning("=" * 60)
        print("""
To install Neo4j:
1. Docker: docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/$NEO4J_PASSWORD neo4j
2. Or follow: https://neo4j.com/download/

After installing Neo4j, run setup again.
""")
        return False

    print_success("\n✓ Prerequisites check passed!")
    return True


def run_setup():
    """Run the interactive setup wizard."""
    print_header()

    # Check prerequisites FIRST
    if not check_prerequisites():
        print_info("\nSetup aborted. Install prerequisites and run again.")
        return False

    # Check for existing config
    if not check_existing_config():
        print_info("Setup cancelled. Your existing config is preserved.")
        return False

    print_info("\nLet's configure your EdgeGuard instance...\n")

    # Credential Storage Method
    print(f"{Colors.BOLD}--- Credential Storage Method ---{Colors.RESET}")
    print("""
How would you like to store credentials?

  1. YAML file (credentials/api_keys.yaml)
     - Saves to file for convenience
     - Easy to edit manually
     
  2. Environment variables
     - More secure (not stored in files)
     - Recommended for production
""")

    cred_choice = prompt_with_default("Choose (1 or 2)", "1")
    use_yaml = cred_choice.strip() == "1"

    if use_yaml:
        print_info("Using YAML file for credentials")
        # Ensure credentials directory exists
        import os

        cred_dir = os.path.join(os.path.dirname(__file__), "..", "credentials")
        os.makedirs(cred_dir, exist_ok=True)
    else:
        print_info("Using environment variables")
        print("""
After setup, set these environment variables:

  # Neo4j
  export NEO4J_URI="bolt://localhost:7687"
  export NEO4J_USER="neo4j"
  export NEO4J_PASSWORD="your-password"
  
  # MISP
  export MISP_URL="https://localhost:8443"
  export MISP_API_KEY="your-api-key"
  
  # Source API Keys
  export OTX_API_KEY="your-otx-key"
  export NVD_API_KEY="your-nvd-key"
  export VIRUSTOTAL_API_KEY="your-vt-key"
""")

    print()

    # Neo4j Configuration
    print(f"{Colors.BOLD}--- Neo4j Configuration ---{Colors.RESET}")
    neo4j_uri = prompt_with_default("Neo4j URI", "bolt://localhost:7687")
    neo4j_user = prompt_with_default("Neo4j username", "neo4j")
    neo4j_password = getpass.getpass("Neo4j password: ")
    if not neo4j_password:
        neo4j_password = "changeme"  # Default — operator must change in .env
        print_info("Using default Neo4j password 'changeme' — change in .env for production")
    print()

    # MISP Configuration
    print(f"{Colors.BOLD}--- MISP Configuration ---{Colors.RESET}")
    misp_url = prompt_with_default("MISP URL", "https://localhost:8443")
    while True:
        misp_api_key = getpass.getpass("MISP API Key: ").strip()
        if misp_api_key and validate_api_key(misp_api_key, "MISP"):
            break
        if not misp_api_key:
            misp_api_key = "YOUR_MISP_API_KEY_HERE"
            print_warning("Using placeholder API key - you must update this!")
            break
        print_error("Invalid API key format. Must be alphanumeric with dashes/underscores.")

    misp_admin_email = prompt_with_default("MISP admin email", "admin@admin.test")
    misp_admin_password = getpass.getpass("MISP admin password: ").strip()
    if not misp_admin_password:
        misp_admin_password = "changeme"
        print_info("Using default MISP password 'changeme' — change for production")
    print()

    # SSL Verification
    print(f"{Colors.BOLD}--- Security Settings ---{Colors.RESET}")
    ssl_verify = prompt_yes_no("Enable SSL verification?", default=False)
    enable_metrics = prompt_yes_no("Enable metrics collection?", default=False)
    print()

    # API Keys
    print(f"{Colors.BOLD}--- API Keys ---{Colors.RESET}")
    print_info("Press Enter to skip optional services")

    # OTX
    otx_input = getpass.getpass("AlienVault OTX API Key: ").strip()
    otx_api_key = otx_input if otx_input else ""

    # NVD
    nvd_input = getpass.getpass("NVD API Key: ").strip()
    nvd_api_key = nvd_input if nvd_input else ""

    # VirusTotal
    vt_input = getpass.getpass("VirusTotal API Key: ").strip()
    virustotal_api_key = vt_input if vt_input else ""

    # AbuseIPDB
    abuse_input = getpass.getpass("AbuseIPDB API Key (optional): ").strip()
    abuseipdb_api_key = abuse_input if abuse_input else ""
    print()

    # Intervals
    print(f"{Colors.BOLD}--- Collection Intervals ---{Colors.RESET}")
    print_info("Rate limit recommendations:")
    print("  • OTX: >= 2 hours (30 req/min)")
    print("  • NVD: >= 30 seconds")
    print("  • VirusTotal: >= 15 seconds (4 req/min)")
    print()

    while True:
        misp_interval_str = prompt_with_default("MISP refresh interval (hours)", "8")
        try:
            misp_interval = int(misp_interval_str)
            if misp_interval > 0:
                break
            print_error("Interval must be positive")
        except ValueError:
            print_error("Please enter a valid number")

    while True:
        neo4j_interval_str = prompt_with_default("Neo4j sync interval (hours)", "72")
        try:
            neo4j_interval = int(neo4j_interval_str)
            if neo4j_interval > 0:
                break
            print_error("Interval must be positive")
        except ValueError:
            print_error("Please enter a valid number")
    print()

    # Build config dictionary for validation
    config = {
        "intervals": {"misp_refresh_interval": misp_interval, "source_intervals": {"nvd": 0.5, "virustotal": 0.25}}
    }

    # Validate rate limits
    warnings = validate_rate_limits(config)
    if warnings:
        print(f"{Colors.YELLOW}{Colors.BOLD}--- Rate Limit Warnings ---{Colors.RESET}")
        for warning in warnings:
            print_warning(warning)
        print()

    # Generate config
    print(f"{Colors.BOLD}--- Creating Configuration ---{Colors.RESET}")
    config_content = generate_config(
        misp_url=misp_url,
        misp_api_key=misp_api_key,
        misp_admin_email=misp_admin_email,
        misp_admin_password=misp_admin_password,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        otx_api_key=otx_api_key,
        nvd_api_key=nvd_api_key,
        virustotal_api_key=virustotal_api_key,
        abuseipdb_api_key=abuseipdb_api_key,
        ssl_verify=ssl_verify,
        enable_metrics=enable_metrics,
        misp_interval=misp_interval,
        neo4j_interval=neo4j_interval,
    )

    # Write config file
    config_path = get_config_path()
    try:
        with open(config_path, "w") as f:
            f.write(config_content)
        print_success(f"Configuration saved to {config_path}")
    except Exception as e:
        print_error(f"Failed to write config: {e}")
        return False

    # Final checks
    print()
    print_success("EdgeGuard setup complete!")
    print()
    print(f"{Colors.BOLD}Next steps:{Colors.RESET}")
    print("  1. Review your config at: credentials/config.yaml")
    print("  2. Ensure Neo4j is running")
    print("  3. Run: python src/run_pipeline.py")
    print()

    return True


def update_config():
    """Update existing configuration."""
    print_header()
    print_info("EdgeGuard Configuration Update\n")

    # Check if config exists
    config_path = get_config_path()
    if not config_path.exists():
        print_error("No config file found. Run 'python setup.py' first to create one.")
        return False

    # Load existing config
    import yaml

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    print_info("Current configuration loaded.\n")

    # Show menu
    print(f"{Colors.BOLD}What would you like to update?{Colors.RESET}")
    print("  1. Neo4j configuration")
    print("  2. MISP configuration")
    print("  3. API Keys (OTX, NVD, VirusTotal)")
    print("  4. Security settings (SSL, metrics)")
    print("  5. Collection limits (time ranges, max entries)")
    print("  6. All of the above")
    print("  0. Cancel\n")

    choice = input(f"{Colors.BOLD}Enter choice [0-6]: {Colors.RESET}")

    if choice == "0":
        print_info("Update cancelled.")
        return False

    # Update based on choice
    if choice in ["1", "6"]:
        print(f"\n{Colors.BOLD}--- Neo4j Configuration ---{Colors.RESET}")
        config["neo4j"]["uri"] = prompt_with_default(
            "Neo4j URI", config.get("neo4j", {}).get("uri", "bolt://localhost:7687")
        )
        config["neo4j"]["user"] = prompt_with_default("Neo4j username", config.get("neo4j", {}).get("user", "neo4j"))
        config["neo4j"]["password"] = getpass.getpass("Neo4j password: ") or config.get("neo4j", {}).get("password", "")

    if choice in ["2", "6"]:
        print(f"\n{Colors.BOLD}--- MISP Configuration ---{Colors.RESET}")
        config["misp"]["url"] = prompt_with_default(
            "MISP URL", config.get("misp", {}).get("url", "https://localhost:8443")
        )
        config["misp"]["api_key"] = getpass.getpass("MISP API Key: ") or config.get("misp", {}).get("api_key", "")
        config["misp"]["admin_email"] = prompt_with_default(
            "MISP admin email", config.get("misp", {}).get("admin_email", "admin@admin.test")
        )
        config["misp"]["admin_password"] = getpass.getpass("MISP admin password: ") or config.get("misp", {}).get(
            "admin_password", ""
        )

    if choice in ["3", "6"]:
        print(f"\n{Colors.BOLD}--- API Keys ---{Colors.RESET}")
        config["otx"]["api_key"] = getpass.getpass("OTX API Key: ") or config.get("otx", {}).get("api_key", "")
        config["nvd"]["api_key"] = getpass.getpass("NVD API Key: ") or config.get("nvd", {}).get("api_key", "")
        config["virustotal"]["api_key"] = getpass.getpass("VirusTotal API Key: ") or config.get("virustotal", {}).get(
            "api_key", ""
        )
        print_info("API keys updated.")

    if choice in ["4", "6"]:
        print(f"\n{Colors.BOLD}--- Security Settings ---{Colors.RESET}")
        current_ssl = config.get("edgeguard", {}).get("ssl_verify", False)
        config["edgeguard"]["ssl_verify"] = prompt_yes_no("Enable SSL verification?", default=current_ssl)
        current_metrics = config.get("edgeguard", {}).get("enable_metrics", False)
        config["edgeguard"]["enable_metrics"] = prompt_yes_no("Enable Prometheus metrics?", default=current_metrics)

    if choice in ["5", "6"]:
        print(f"\n{Colors.BOLD}--- Collection Limits ---{Colors.RESET}")
        print_info("Current time ranges (months):")
        for sector, months in config.get("intervals", {}).get("sector_time_ranges", {}).items():
            new_months = prompt_with_default(f"  {sector}", str(months))
            config.setdefault("intervals", {}).setdefault("sector_time_ranges", {})[sector] = int(new_months)

        max_entries = config.get("edgeguard", {}).get("max_entries_per_source", 500)
        new_max = prompt_with_default("Max entries per source", str(max_entries))
        config.setdefault("edgeguard", {})["max_entries_per_source"] = int(new_max)

    # Save updated config
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print_success(f"\n✓ Configuration saved to {config_path}")
    return True


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="EdgeGuard Setup")
    parser.add_argument("--update", "-u", action="store_true", help="Update existing configuration")
    parser.add_argument("--check", "-c", action="store_true", help="Check prerequisites only")
    args = parser.parse_args()

    try:
        if args.check:
            # Just check prerequisites
            return check_prerequisites()
        elif args.update:
            success = update_config()
        else:
            success = run_setup()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Setup failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
