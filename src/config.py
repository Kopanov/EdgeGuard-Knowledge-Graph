# EdgeGuard Prototype Configuration
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, MutableMapping, Optional, Protocol

# Deployment environment
# ----------------------
# EdgeGuard can run in different environments (dev, stage, prod, edge, etc.).
# Use EDGEGUARD_ENV to signal the current environment in logs and any
# environment-specific configuration you layer on top.
#
# Examples:
#   export EDGEGUARD_ENV="dev"
#   export EDGEGUARD_ENV="prod"
#   export EDGEGUARD_ENV="edge"   # for edge devices / gateways
EDGEGUARD_ENV = os.getenv("EDGEGUARD_ENV", "dev")


def _require_env(name: str) -> str:
    """Fetch a required environment variable or raise a clear error.

    This is used for secrets that must never have in-code defaults
    (e.g. database passwords, API keys).
    """
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required environment variable {name} is not set.")
    return value


def _env_int(name: str, default: int) -> int:
    """Read an env var as int, falling back to *default* on missing or bad value."""
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return int(raw.strip())
    except (ValueError, TypeError):
        return default


def _env_float(name: str, default: float) -> float:
    """Read an env var as float, falling back to *default* on missing or bad value."""
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return float(raw.strip())
    except (ValueError, TypeError):
        return default


# Neo4j Connection
# --------------------
# Connection Types:
#   Local: bolt://localhost:7687 (default)
#   Remote: bolt://your-neo4j-server.com:7687
#
# For remote Neo4j, you can use:
#   - bolt://hostname:port (encrypted)
#   - bolt+routing://hostname:7687 (for clusters)
#
# Authentication:
#   - Username/Password (no in-code default password)
#   - Or use kerberos/tokens for enterprise
#
# Environment variables:
#   export NEO4J_URI="bolt://your-server.com:7687"
#   export NEO4J_USER="neo4j"
#   export NEO4J_PASSWORD="your-secure-password"  # REQUIRED
#   export NEO4J_DATABASE="neo4j"  # For Neo4j 5.x multi-database

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
# Password is required – fail fast if missing to avoid weak defaults
NEO4J_PASSWORD = _require_env("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

# Connection Pool Settings
NEO4J_MAX_CONNECTION_LIFETIME = 3600  # seconds
NEO4J_MAX_CONNECTION_POOL_SIZE = 50

# API Keys (loaded from EdgeGuard keys)


def get_sector_cutoff_date(sector: str = "global") -> str:
    """Get cutoff date for a sector (ISO format)."""
    months = SECTOR_TIME_RANGES.get(sector, SECTOR_TIME_RANGES["global"])
    cutoff = datetime.now(timezone.utc) - timedelta(days=months * 30)
    return cutoff.strftime("%Y-%m-%d")


# PR #34 round 28 (cross-checker audit): deleted ``detect_zone_from_text``
# (singular). It returned the FIRST matching sector or the default — but every
# call site in production uses the PLURAL ``detect_zones_from_text`` (returns
# a list, supports multi-zone). The singular version had ZERO importers across
# src/, scripts/, dags/, tests/ — pure dead public API. A future contributor
# unaware of the deprecation could have grabbed it for "simple single-zone
# detection" and silently lost multi-zone semantics. Deleted to remove the
# trap.

# Minimum weighted score for a sector to count in ``detect_zones_from_text`` (per field).
# At default ``body`` weight 1.5, a single keyword match scores 1.5 — so 2.0 wrongly required
# two matches for typical CVE/feed sentences.
# Must be > 0; zero would match everything into every sector.
ZONE_DETECT_THRESHOLD = max(0.1, _env_float("EDGEGUARD_ZONE_DETECT_THRESHOLD", 1.5))

# Minimum combined score in ``detect_zones_from_item`` after multi-field accumulation.
# Must be > 0; zero would match everything into every sector.
ZONE_ITEM_COMBINED_THRESHOLD = max(0.1, _env_float("EDGEGUARD_ZONE_ITEM_THRESHOLD", 1.5))


def detect_zones_from_text(text: str, default_zone: str = "global", context: str = "body") -> list:
    """Detect sectors from text using CONSERVATIVE weighted scoring.

    Args:
        text: Text to analyze (malware name, description, etc.)
        default_zone: Default zone if no match (default: "global")
        context: Where this text comes from - "title", "alias", "description", "tag", "body"
                 Title/aliases get higher weight, tags get lower weight

    Returns:
        List of zone names (e.g., ['finance', 'healthcare'] or ['global'] if no match)
    """
    if not text:
        return [default_zone]

    # Context weight: title/alias = 3x, description = 2x, tags/body = 1x
    context_weights = {
        "title": 3.0,
        "alias": 3.0,
        "name": 3.0,
        "description": 2.0,
        "body": 1.5,
        "tag": 1.0,
        "default": 1.0,
    }
    weight = context_weights.get(context, context_weights["default"])

    score_threshold = ZONE_DETECT_THRESHOLD

    text_lower = text.lower()
    sector_scores = {zone: 0.0 for zone in SECTOR_KEYWORDS}

    # NEGATIVE KEYWORDS - explicit exclusions (stronger than positive matches)
    negative_keywords = {
        "healthcare": [
            "not healthcare",
            "no healthcare",
            "except hospital",
            "excluding medical",
            "non-medical",
            "non-hospital",
            "unrelated to healthcare",
        ],
        "energy": [
            "not energy",
            "no energy",
            "except power",
            "excluding grid",
            "non-energy",
            "non-grid",
            "unrelated to energy",
        ],
        "finance": [
            "not finance",
            "no finance",
            "except bank",
            "excluding payment",
            "non-financial",
            "non-banking",
            "unrelated to finance",
        ],
    }

    # Check negative keywords first - if found, exclude that sector entirely
    excluded_sectors = set()
    for zone, neg_kws in negative_keywords.items():
        for neg_kw in neg_kws:
            if re.search(r"\b" + re.escape(neg_kw) + r"\b", text_lower):
                excluded_sectors.add(zone)

    # Positive keyword matching with weights (pre-compiled patterns)
    for zone, patterns in _SECTOR_PATTERNS.items():
        if zone in excluded_sectors:
            continue

        for pattern in patterns:
            matches = len(pattern.findall(text_lower))
            if matches > 0:
                sector_scores[zone] += matches * weight

    # Filter sectors by score threshold
    matched_sectors = [zone for zone, score in sector_scores.items() if score >= score_threshold]

    # Filter against the canonical zone whitelist before returning.
    valid = [z for z in matched_sectors if z in VALID_ZONES]
    return valid if valid else [default_zone]


def detect_zones_from_item(item: dict) -> list:
    """Detect zones from a full item with multiple text fields.

    This function analyzes multiple fields with different weights:
    - name/aliases: highest weight (primary identity)
    - title: high weight
    - description: medium weight
    - tags: lower weight (often noisy)

    Args:
        item: Dict with keys like 'name', 'description', 'tags', 'alias', etc.

    Returns:
        List of zone names
    """
    if not item:
        return ["global"]

    combined_scores = {zone: 0.0 for zone in SECTOR_KEYWORDS}

    # Priority 1: name/alias (highest weight - primary identity)
    for field in ["name", "alias", "aliases", "family"]:
        if field in item and item[field]:
            zones = detect_zones_from_text(str(item[field]), context="name")
            if zones != ["global"]:
                for z in zones:
                    combined_scores[z] += 3.0

    # Priority 2: title/info
    for field in ["title", "info", "event_name"]:
        if field in item and item[field]:
            zones = detect_zones_from_text(str(item[field]), context="title")
            if zones != ["global"]:
                for z in zones:
                    combined_scores[z] += 2.5

    # Priority 3: description
    for field in ["description", "comment", "detail"]:
        if field in item and item[field]:
            zones = detect_zones_from_text(str(item[field]), context="description")
            if zones != ["global"]:
                for z in zones:
                    combined_scores[z] += 1.5

    # Priority 4: tags (lowest weight - often noisy)
    if "tags" in item and item["tags"]:
        tags_text = " ".join(str(t) for t in item["tags"])
        zones = detect_zones_from_text(tags_text, context="tag")
        if zones != ["global"]:
            for z in zones:
                combined_scores[z] += 0.5

    threshold = ZONE_ITEM_COMBINED_THRESHOLD
    max_score = max(combined_scores.values()) if combined_scores else 0

    if max_score < threshold:
        return ["global"]

    # Only return sectors within 50% of max score (prevents weak matches)
    matched = [s for s, score in combined_scores.items() if score >= max_score * 0.5 and score >= threshold]

    return matched if matched else ["global"]


# MISP Configuration
# ------------------
# MISP API Key
# ------------
# To get your API key:
#   1. Log in to MISP at https://your-misp-server
#   2. Go to: Administration > Users > Your Profile
#   3. Click "Authentication Keys"
#   4. Add new key
#   5. Copy the key (shown once)
#
# The key is used for:
#   - Reading events
#   - Writing events
#   - Searching attributes
#
MISP_URL = os.getenv("MISP_URL", "https://localhost:8443")
# MISP API key is required for any real deployment; no in-code default.
MISP_API_KEY = _require_env("MISP_API_KEY")
_MISP_KEY_PLACEHOLDERS = {"your-misp-api-key-here", "changeme", "YOUR_API_KEY_HERE"}
if MISP_API_KEY in _MISP_KEY_PLACEHOLDERS:
    raise RuntimeError(
        f"MISP_API_KEY is still a placeholder ('{MISP_API_KEY[:12]}…'). Set a real key in .env — see .env.example."
    )

# When MISP is reached via Docker DNS / IP (e.g. http://misp_misp_1) but Apache's
# ServerName is different (e.g. misp-edgeguard), set this to the vhost name so the
# HTTP Host header matches what the web server expects. Read at call time (not only
# at import) so tests and late env updates work.
#   export EDGEGUARD_MISP_HTTP_HOST=misp-edgeguard


class _SessionLike(Protocol):
    headers: MutableMapping[str, str]


def get_edgeguard_misp_http_host() -> str:
    """Return MISP HTTP Host override from EDGEGUARD_MISP_HTTP_HOST, or empty string."""
    return os.getenv("EDGEGUARD_MISP_HTTP_HOST", "").strip()


def apply_misp_http_host_header(session: _SessionLike) -> None:
    """Set ``Host`` on a ``requests.Session`` (or similar) used for MISP REST calls."""
    host = get_edgeguard_misp_http_host()
    if host:
        session.headers["Host"] = host


def misp_http_headers_for_pymisp() -> Optional[Dict[str, str]]:
    """Return ``http_headers`` for :class:`pymisp.PyMISP` when Host must differ from URL."""
    host = get_edgeguard_misp_http_host()
    if not host:
        return None
    return {"Host": host}


# SSL/TLS Verification
# -------------------
# When SSL_VERIFY = True:
#   - Validates the MISP server's SSL certificate
#   - Prevents man-in-the-middle attacks
#   - Requires valid (not self-signed) certificate
#
# When SSL_VERIFY = False (current dev setting):
#   - Accepts self-signed certificates
#   - OK for local development
#   - INSECURE for production
#
# Production: verify TLS (default).
# Development: internal MISP with self-signed cert → EDGEGUARD_SSL_VERIFY=false
# (or SSL_VERIFY=false — alias read only when EDGEGUARD_SSL_VERIFY is unset/empty).
# ``SSL_CERT_VERIFY`` is not read by EdgeGuard.
#
# Set via environment: export EDGEGUARD_SSL_VERIFY=true|false
def edgeguard_ssl_verify_from_env() -> bool:
    """True = verify TLS for HTTPS (MISP, collectors). Default True (secure)."""
    for key in ("EDGEGUARD_SSL_VERIFY", "SSL_VERIFY"):
        raw = os.getenv(key)
        if raw is None:
            continue
        stripped = str(raw).strip()
        if not stripped:
            continue
        return stripped.lower() == "true"
    return True


SSL_VERIFY = edgeguard_ssl_verify_from_env()


def _env_bool(name: str, default: str = "true") -> bool:
    raw = os.getenv(name, default)
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


# MISP push: prefetch existing (type, value) per target event to skip duplicates (reruns + overlap).
MISP_PREFETCH_EXISTING_ATTRS = _env_bool("EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS", "true")

# OTX incremental: first-run / no-checkpoint lookback; overlap subtracted from stored cursor to avoid gaps.
OTX_INCREMENTAL_LOOKBACK_DAYS = _env_int("EDGEGUARD_OTX_INCREMENTAL_LOOKBACK_DAYS", 3)
OTX_INCREMENTAL_OVERLAP_SEC = _env_int("EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC", 300)
OTX_INCREMENTAL_MAX_PAGES = _env_int("EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES", 25)

# MITRE: use If-None-Match on the STIX bundle URL when not in baseline mode (304 → skip re-push).
MITRE_USE_CONDITIONAL_GET = _env_bool("EDGEGUARD_MITRE_CONDITIONAL_GET", "true")

OTX_API_KEY = os.getenv("OTX_API_KEY")

# NVD - Load from environment variables (secure)
NVD_API_KEY = os.getenv("NVD_API_KEY")

# VirusTotal — environment variable takes priority; credentials file is a fallback.
# Use split('=', 1) so base64-encoded keys containing '=' are not truncated.
credentials_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "credentials", "api_keys.yaml")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_RATE_LIMIT = 4
if not VIRUSTOTAL_API_KEY:
    try:
        with open(credentials_path, "r") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("VIRUSTOTAL_API_KEY="):
                    VIRUSTOTAL_API_KEY = line.split("=", 1)[1].strip()
                elif line.startswith("VIRUSTOTAL_RATE_LIMIT="):
                    try:
                        VIRUSTOTAL_RATE_LIMIT = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
    except (FileNotFoundError, PermissionError, IOError) as e:
        import logging

        logging.getLogger(__name__).debug(f"Credentials file not found at {credentials_path}: {e}")

# Collection Limits (see get_effective_limit() below)

# Sector time ranges (months of historical data to fetch)
# Standardized to 24 months (2 years) for consistency across all sectors
SECTOR_TIME_RANGES = {"healthcare": 24, "energy": 24, "finance": 24, "global": 24}

# Max entries per source per sync run.
# Use get_effective_limit(source) to retrieve the effective value.
#
# Single-variable control:
#   MAX_ENTRIES_PER_SOURCE = 0   → no limit (fetch all, rate-limiting still applies)
#   MAX_ENTRIES_PER_SOURCE = 500 → cap every source at 500 items
#
# Per-source exceptions: add a source key to NO_LIMIT_SOURCES to bypass
# the global cap for that source only.
#
# The former ENABLE_MAX_ENTRIES_LIMIT boolean has been removed — it created
# a dual-bool situation where two independent variables controlled the same
# thing (0 already means "off").  Migrate: replace ENABLE_MAX_ENTRIES_LIMIT=False
# with MAX_ENTRIES_PER_SOURCE=0.
MAX_ENTRIES_PER_SOURCE = _env_int("EDGEGUARD_MAX_ENTRIES", 0)

# Incremental (regular cron) collection limit.
#
# Applied on every normal scheduled collection run — keeps each 2-3 day
# window scan fast and lightweight.  Baseline runs use a separate limit
# (BASELINE_COLLECTION_LIMIT Airflow Variable) and ignore this setting.
#
#   0 → no item cap (only the sector time-range window applies)
#   N → collect at most N items per source per run  (e.g. 200, 500)
#
# Can also be set as an Airflow Variable "INCREMENTAL_COLLECTION_LIMIT"
# at runtime, which takes precedence over the env var.
INCREMENTAL_COLLECTION_LIMIT = _env_int("EDGEGUARD_INCREMENTAL_LIMIT", 200)

# Sources that bypass the count limit (get all data)
# These sources will still respect SECTOR_TIME_RANGES (time limit)
# Add sources here when needed (e.g., {'cisa', 'mitre'})
NO_LIMIT_SOURCES = set()  # Empty for now - feature available but not active


def get_effective_limit(source: str = None, default_limit: int = None) -> Optional[int]:
    """
    Get the effective per-run item limit for a source.

    Priority (highest to lowest):
      1. NO_LIMIT_SOURCES — per-source bypass, always returns None
      2. EDGEGUARD_MAX_ENTRIES — global hard override (0 = use incremental default)
      3. EDGEGUARD_INCREMENTAL_LIMIT — default cap for regular cron runs
         (0 = unlimited; baseline runs have their own separate limit)

    Args:
        source: Source name (e.g., 'cisa', 'mitre', 'otx') — checked against
                NO_LIMIT_SOURCES for a per-source bypass.
        default_limit: Ignored; kept for call-site compatibility.

    Returns:
        int : cap to apply
        None: no cap (fetch all; time-range limits still apply)
    """
    if source and source.lower() in NO_LIMIT_SOURCES:
        return None
    # Explicit global override takes precedence
    if MAX_ENTRIES_PER_SOURCE != 0:
        return MAX_ENTRIES_PER_SOURCE
    # Default: apply incremental cap (0 means unlimited)
    return INCREMENTAL_COLLECTION_LIMIT if INCREMENTAL_COLLECTION_LIMIT > 0 else None


def resolve_collection_limit(
    limit: Optional[int],
    source: Optional[str] = None,
    *,
    baseline: bool = False,
) -> Optional[int]:
    """
    Resolve per-run item cap for collector ``collect()`` methods.

    Scheduled **baseline** runs pass ``limit=None`` when the baseline cap is
    unlimited (Airflow Variable ``BASELINE_COLLECTION_LIMIT`` ≤ 0, or env for
    ``run_pipeline --baseline``). That must **not** be replaced with the
    incremental default (e.g. 200).

    Regular (cron) runs pass an explicit limit from the DAG, or rely on the
    incremental default when ``limit`` is omitted.

    Returns:
        int: explicit cap
        None: no per-item cap (process everything fetched, subject to API/time filters)
    """
    if limit is not None:
        return limit
    if baseline:
        return None
    return get_effective_limit(source)


def baseline_collection_limit_from_env() -> Optional[int]:
    """
    Per-source cap for ``run_pipeline --baseline`` (not Airflow).

    Same semantics as Airflow Variable ``BASELINE_COLLECTION_LIMIT``:
    unset / ``0`` / negative → unlimited (``None``); positive → cap per source.

    Reads ``EDGEGUARD_BASELINE_COLLECTION_LIMIT`` first, then ``BASELINE_COLLECTION_LIMIT``
    (aligned with the baseline DAG env overrides in ``dags/edgeguard_pipeline.py``).
    """
    raw_str = os.getenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT") or os.getenv("BASELINE_COLLECTION_LIMIT") or "0"
    try:
        raw = int(str(raw_str).strip())
    except ValueError:
        raw = 0
    return None if raw <= 0 else raw


# Sector Mapping - CONSERVATIVE keywords (no malware families!)
# Malware families will be linked via relationships, not keywords
SECTOR_KEYWORDS = {
    "healthcare": [
        # Sector-specific terms with word-boundary matching
        "hospital",
        "hospitals",
        "healthcare",
        "healthcare sector",
        "medical device",
        "medical devices",
        "medical imaging",
        "mri scan",
        "ct-scan",
        "xray",
        "x-ray",
        "ultrasound",
        "diagnostic imaging",
        "pacemaker",
        "insulin pump",
        "defibrillator",
        "dialysis",
        "pacs server",
        "ehr system",
        "medical",
        "electronic health record",
        "electronic medical records",
        "patient data",
        "medical records",
        "hipaa",
        "pharma",
        "pharmaceutical",
        "pharma company",
        "pharmacy",
        "drug manufacturer",
        "biomedical",
        "biotechnology",
        "clinical trial",
        "medical laboratory",
        "lab corporation",
        "diagnostic lab",
        "health clinic",
        "clinic",
        "medical center",
        "patient monitoring",
        "patient record",
        "patient portal",
        "dicom",
        "hl7",
        "fhir",
        "health it",
        "healthcare software",
        "clinical software",
        "telehealth",
    ],
    "energy": [
        # Sector-specific terms with word-boundary matching
        "scada",
        "scada system",
        "industrial control",
        "industrial control system",
        "distributed control system",
        "plc controller",
        "programmable logic controller",
        "scada hmi",
        "electric grid",
        "power grid",
        "electrical grid",
        "substation",
        "power transformer",
        "electrical transformer",
        "power transmission",
        "distribution grid",
        "smart grid",
        "grid infrastructure",
        "power utility",
        "nuclear plant",
        "nuclear facility",
        "power plant",
        "oil pipeline",
        "gas pipeline",
        "pipeline scada",
        "refinery",
        "petrochemical",
        "oil refinery",
        "renewable energy",
        "solar farm",
        "wind farm",
        "hydro plant",
        "critical infrastructure",
        "energy sector",
        "ot security",
        "ot network",
        "operational technology",
        "industrial network",
        "modbus",
        "opc ua",
        "ethernet ip",
        "profinet",
        "substation automation",
        "grid load management",
        "grid operations",
        "energy management system",
    ],
    "finance": [
        # Sector-specific terms with word-boundary matching
        "banking trojan",
        "financial trojan",
        "payment card",
        "credit card",
        "debit card",
        "card data",
        "card fraud",
        "atm malware",
        "pos malware",
        "point of sale",
        "banking",
        "banking sector",
        "financial sector",
        "investment firm",
        "investment bank",
        "trading platform",
        "stock exchange",
        "brokerage",
        "stock broker",
        "cryptocurrency exchange",
        "crypto exchange",
        "bitcoin exchange",
        "swift payment",
        "swift network",
        "swift transfer",
        "ach payment",
        "ach transfer",
        "wire transfer fraud",
        "fintech",
        "digital banking",
        "online banking",
        "insurance company",
        "insurance sector",
        "underwriting",
        "erp system",
        "sap erp",
        "sap system",
        "oracle financial",
        "accounting software",
        "know your customer",
        "anti money laundering",
        "fraud detection",
        "anti-fraud",
        "fraud prevention",
        "payment gateway",
        "payment processor",
        "merchant services",
        "financial services",
        "payment processing",
        "core banking",
        "core banking system",
        "trading system",
        "crypto wallet",
    ],
}

# Default sector for generic threats
DEFAULT_SECTOR = "global"

# Valid zone values — used to filter out unexpected strings before they reach Neo4j.
VALID_ZONES: frozenset = frozenset({"global", "healthcare", "energy", "finance"})

# Pre-compiled word-boundary patterns for SECTOR_KEYWORDS.
# Built once at module load time to avoid re-compiling on every call.
_SECTOR_PATTERNS: dict = {
    zone: [re.compile(r"\b" + re.escape(kw) + r"\b", re.IGNORECASE) for kw in kws]
    for zone, kws in SECTOR_KEYWORDS.items()
}

# Tags for sources — maps CLI shortname → canonical collector-emitted tag.
# Single-source-of-truth derivation from src/source_registry.py (chip 5a).
# Restricted to the legacy 7-key shape so existing callers that do
# ``SOURCE_TAGS["X"]`` and rely on KeyError-on-typo for missing keys
# don't suddenly start resolving keys that previously failed. The full
# registry-derived map (~12 keys) is available via
# ``source_registry.cli_to_canonical_tag_map()`` for new callers.
import source_registry as _source_registry  # noqa: E402

SOURCE_TAGS = _source_registry.cli_to_canonical_tag_map_legacy_subset()

# Pipeline Intervals (hours)
# Phase 1: Source → MISP refresh interval
MISP_REFRESH_INTERVAL = 8  # Default: 8 hours (best practice for slower sources)
MISP_ACTIVE_FEED_INTERVAL = 0.5  # 30 minutes for OTX (high-frequency live feed)

# Phase 2: MISP → Neo4j sync interval
NEO4J_SYNC_INTERVAL = 72  # Default: 72 hours (3 days)

# Source-specific collection intervals (must match the DAG schedule_interval values)
# OTX:         every 30 min  (edgeguard_pipeline DAG — */30 * * * *)
# CISA/VT:     every 4 hours (edgeguard_medium_freq DAG — 0 */4 * * *)
# NVD:         every 8 hours (edgeguard_low_freq DAG — 0 */8 * * *)
# MITRE+daily: every 24 h    (edgeguard_daily DAG — 0 2 * * *)
SOURCE_INTERVALS = {
    "otx": 0.5,  # 30 min
    "cisa": 4,  # 4 hours — matches edgeguard_medium_freq schedule
    "nvd": 8,  # 8 hours — matches edgeguard_low_freq schedule
    "mitre": 24,  # 24 hours — matches edgeguard_daily schedule
    "virustotal": 4,  # 4 hours — matches edgeguard_medium_freq schedule
}
