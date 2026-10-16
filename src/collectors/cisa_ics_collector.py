#!/usr/bin/env python3
"""
EdgeGuard - CISA ICS Advisories Collector (CSAF 2.0)

Collects ICS-CERT / ICS medical advisories that CISA publishes as CSAF 2.0
JSON files in the public ``cisagov/CSAF`` GitHub repository
(``csaf_files/OT/white/<year>/<advisory>.json``) and pushes one
``vulnerability`` item per CVE to MISP (2026-10-16: the advisories that name
the CVE are merged by ``merge_items_per_cve``; before, one item per
(advisory, CVE), and MISP kept whichever came first).

Why a second CISA collector next to KEV
---------------------------------------
KEV tells us *which* CVEs are exploited; ICS advisories tell us *which
critical-infrastructure sectors* a CVE touches. The sector is asserted by
CISA in the advisory's ``"Critical infrastructure sectors"`` note — it is
NOT guessed by the keyword detector. The sector → zone mapping is therefore
a fixed table (``ICS_SECTOR_ZONE_MAP``) and ``detect_zones_from_text`` is
deliberately NOT applied to these items. The note names the sectors where
the affected product is *deployed*, not the sectors an adversary targets: in
the graph a mapped sector is the CVE's ``AFFECTS`` link labelled
``advisory_sector`` at 0.9 (``sector_evidence``, 2026-10-16), never
``TARGETS``.

Safety contract (2026-10)
-------------------------
- **Flag-guarded**: ``EDGEGUARD_ENABLE_CISA_ICS`` (default OFF). When off,
  ``collect()`` logs "disabled by flag" and returns a skipped status
  (``success=True``, ``count=0``) without a single HTTP request.
- **Isolated**: shares nothing with the KEV collector except the generic
  helpers in ``collector_utils`` (retry, rate limiter, status factory).
- **Polite**: sequential fetches through a ``RateLimiter`` (4 req/s), HTTP
  429/5xx backoff via ``request_with_rate_limit_retries``, exponential
  retries via ``retry_with_backoff``, a dedicated circuit breaker, and an
  overall per-run cap (``CISA_ICS_MAX_ADVISORIES_PER_RUN``).
- **Per-file failures never abort the run**: a file that is not a JSON
  object with ``document`` + ``vulnerabilities`` (or that 404s) is counted
  under ``stats`` and skipped.
- **Baseline sanity floor**: when at least ``CISA_ICS_MIN_EXPECTED_ADVISORIES``
  advisories were attempted but fewer than that parsed successfully (or the
  index lists nothing in the window), ``CISAICSBaselineFloorError`` is
  raised BEFORE anything is pushed. It subclasses ``TransientServerError``
  so ``run_collector_with_metrics`` classifies it as transient → task
  skipped + Slack alert, instead of writing a thin, misleading dataset.
- **Incremental runs** use ``changes.csv`` with a cursor stored via
  ``baseline_checkpoint.update_source_incremental`` (advanced only after a
  clean MISP push, mirroring the OTX / MITRE cursors).
"""

import csv
import io
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from baseline_checkpoint import get_source_incremental, update_source_incremental
from collectors.collector_utils import (
    RateLimiter,
    TransientServerError,
    make_skipped_optional_source,
    make_status,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)
from collectors.misp_writer import MISPWriter
from config import (
    CISA_ICS_BASE_URL,
    CISA_ICS_MAX_ADVISORIES_PER_RUN,
    CISA_ICS_MIN_EXPECTED_ADVISORIES,
    SSL_VERIFY,
    VALID_ZONES,
    resolve_collection_limit,
)
from cvss_selection import QUALITATIVE_SEVERITIES, UNKNOWN_SEVERITY, clamp_cvss_score, severity_from_score
from resilience import get_circuit_breaker
from source_registry import cisa_ics_advisory_url
from source_truthful_timestamps import coerce_iso

logger = logging.getLogger(__name__)

SOURCE_ID = "cisa_ics"

# Incremental window used when no cursor is stored yet (first run after enabling
# the flag). CISA publishes ~5-15 ICS advisories per week.
CISA_ICS_INCREMENTAL_DAYS = int(os.environ.get("EDGEGUARD_CISA_ICS_INCREMENTAL_DAYS", "30"))
# Overlap subtracted from the stored cursor so a change that landed in the same
# second as the previous run's newest row is not missed.
CISA_ICS_INCREMENTAL_OVERLAP_SEC = 24 * 3600

# Circuit breaker: GitHub raw is reliable; 3 consecutive failures → open for 30 min.
CISA_ICS_CIRCUIT_BREAKER = get_circuit_breaker("cisa_ics", failure_threshold=3, recovery_timeout=1800)
CISA_ICS_RATE_LIMITER = RateLimiter(min_interval=0.25)  # ≤ 4 requests/second against raw.githubusercontent.com

CISA_ICS_REQUEST_TIMEOUT = 60  # seconds
CISA_ICS_CONNECT_TIMEOUT = 15  # seconds
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds
# A burst of consecutive per-file failures means the upstream is broken for
# everyone, not just one advisory — abort instead of grinding through 900 files.
MAX_CONSECUTIVE_FETCH_FAILURES = 10

INDEX_FILE = "index.txt"
CHANGES_FILE = "changes.csv"

# Sector → zone mapping. EXACT table (2026-10): any other CISA sector contributes
# nothing; an advisory with no mapped sector lands in ``global``.
ICS_SECTOR_ZONE_MAP: Dict[str, str] = {
    "Energy": "energy",
    "Healthcare and Public Health": "healthcare",
    "Financial Services": "finance",
}
_ICS_SECTOR_ZONE_LOOKUP: Dict[str, str] = {k.strip().lower(): v for k, v in ICS_SECTOR_ZONE_MAP.items()}
assert set(ICS_SECTOR_ZONE_MAP.values()) <= VALID_ZONES, (
    f"ICS_SECTOR_ZONE_MAP targets must be a subset of VALID_ZONES; invalid: {set(ICS_SECTOR_ZONE_MAP.values()) - VALID_ZONES}"
)

SECTORS_NOTE_TITLE = "critical infrastructure sectors"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_INDEX_LINE_RE = re.compile(r"^(?P<year>\d{4})/(?P<file>[A-Za-z0-9._-]+\.json)$")
# CISA file names encode the initial publication day: ``icsa-26-281-01`` →
# day 281 of 2026 (2026-10-08). Used ONLY to pre-filter / order the baseline
# fetch list; the authoritative date filter is ``initial_release_date``.
_FILENAME_DATE_RE = re.compile(r"^(?P<year>\d{4})/ics[a-z]*-\d{2}-(?P<doy>\d{3})-\d{2}.*\.json$")
# Safety margin for the file-name pre-filter (file-name day vs. the real
# initial_release_date can differ slightly; re-issues keep the original number).
FILENAME_DATE_MARGIN_DAYS = 45

_CVSS_AV = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
_CVSS_LH = {"L": "LOW", "H": "HIGH"}
_CVSS_NLH = {"N": "NONE", "L": "LOW", "H": "HIGH"}
_CVSS_UI = {"N": "NONE", "R": "REQUIRED"}
_CVSS_SCOPE = {"U": "UNCHANGED", "C": "CHANGED"}

# Values when an advisory carries no CVSS block (2026-10): no score, severity UNKNOWN and no
# attack vector. They used to be 7.0 / HIGH, copied from the KEV collector's ransomware-derived
# values, and were stored as if they were CVSS (246 CVEs on the hosted 730-day baseline), with an
# invented attack vector NETWORK (also used for a CVSS block whose vector names none).
DEFAULT_SEVERITY = UNKNOWN_SEVERITY
DEFAULT_CVSS_SCORE: Optional[float] = None
DEFAULT_ATTACK_VECTOR: Optional[str] = None

DESCRIPTION_MAX_CHARS = 1000
MAX_AFFECTED_PRODUCTS = 10


class CISAICSTransientError(TransientServerError):
    """Upstream (GitHub raw) 429/5xx or outage-shaped failure — retried by
    ``retry_with_backoff``; if it escapes ``collect()`` the DAG classifies it
    as transient (skip + alert), never as a code defect."""


class CISAICSBaselineFloorError(TransientServerError):
    """Baseline sanity floor violated (too few advisories parsed, or an empty
    index window). Raised BEFORE any MISP push so a broken upstream cannot
    produce a thin dataset that looks like a successful baseline."""


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable without HTTP)
# ---------------------------------------------------------------------------


def map_sectors_to_zones(sectors: Iterable[str]) -> List[str]:
    """Map CISA sector names to EdgeGuard zones with the fixed table.

    Unknown sectors contribute nothing; no mapped sector → ``["global"]``.
    Every returned zone is validated against ``config.VALID_ZONES``.
    """
    zones: List[str] = []
    for raw in sectors or []:
        zone = _ICS_SECTOR_ZONE_LOOKUP.get(str(raw or "").strip().lower())
        if zone and zone in VALID_ZONES and zone not in zones:
            zones.append(zone)
    return zones or ["global"]


def parse_sectors(document: Dict[str, Any]) -> List[str]:
    """Return the raw sector names from the ``"Critical infrastructure sectors"`` note(s)."""
    out: List[str] = []
    for note in document.get("notes") or []:
        if not isinstance(note, dict):
            continue
        if str(note.get("title") or "").strip().lower() != SECTORS_NOTE_TITLE:
            continue
        for part in str(note.get("text") or "").split(","):
            name = part.strip()
            if name and name not in out:
                out.append(name)
    return out


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string (``...Z`` or offset) to an aware UTC datetime; None if unparseable."""
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso_utc(value: Any) -> Optional[str]:
    """CSAF timestamp (``...T06:00:00.000000Z``) → ``2026-10-08T06:00:00+00:00``.

    Normalises to the same tz-aware ISO form the NVD collector emits; falls
    back to ``coerce_iso`` for anything ``datetime.fromisoformat`` rejects
    (date-only strings etc.). ``None`` when absent — never wall-clock.
    """
    dt = _parse_dt(value)
    return dt.isoformat() if dt is not None else coerce_iso(value)


def path_published_date(path: str) -> Optional[datetime]:
    """Approximate initial publication date derived from the file name, or None."""
    match = _FILENAME_DATE_RE.match(path or "")
    if not match:
        return None
    try:
        return datetime(int(match.group("year")), 1, 1, tzinfo=timezone.utc) + timedelta(
            days=int(match.group("doy")) - 1
        )
    except ValueError:
        return None


def _to_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parse_cvss_v3_vector(vector: str) -> Dict[str, str]:
    """Expand a CVSS v3.x vector string into NVD-style component names."""
    out: Dict[str, str] = {}
    for part in str(vector or "").split("/"):
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        if key == "AV":
            out["attack_vector"] = _CVSS_AV.get(val, "")
        elif key == "AC":
            out["attack_complexity"] = _CVSS_LH.get(val, "")
        elif key == "PR":
            out["privileges_required"] = _CVSS_NLH.get(val, "")
        elif key == "UI":
            out["user_interaction"] = _CVSS_UI.get(val, "")
        elif key == "S":
            out["scope"] = _CVSS_SCOPE.get(val, "")
        elif key == "C":
            out["confidentiality_impact"] = _CVSS_NLH.get(val, "")
        elif key == "I":
            out["integrity_impact"] = _CVSS_NLH.get(val, "")
        elif key == "A":
            out["availability_impact"] = _CVSS_NLH.get(val, "")
    return out


def extract_cvss(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the first ``cvss_v3`` score block and shape it like the NVD collector does.

    Returns a dict with ``cvss_v31_data`` / ``cvss_v30_data`` (one populated, or
    both None), ``cvss_score``, ``severity``, ``attack_vector``, ``result_impacts``.
    A block without a valid base score is not a CVSS (2026-10: it used to become 0.0 / HIGH).
    """
    for entry in vuln.get("scores") or []:
        if not isinstance(entry, dict):
            continue
        v3 = entry.get("cvss_v3")
        if not isinstance(v3, dict):
            continue
        base_score = clamp_cvss_score(v3.get("baseScore"))
        if base_score is None:
            continue
        vector = str(v3.get("vectorString") or "")
        comps = _parse_cvss_v3_vector(vector)
        base_severity = str(v3.get("baseSeverity") or "").upper()
        if base_severity not in QUALITATIVE_SEVERITIES:
            base_severity = severity_from_score(base_score, "3.1")
        payload = {
            "vector_string": vector,
            "attack_vector": str(v3.get("attackVector") or comps.get("attack_vector", "")).upper(),
            "attack_complexity": str(v3.get("attackComplexity") or comps.get("attack_complexity", "")).upper(),
            "privileges_required": str(v3.get("privilegesRequired") or comps.get("privileges_required", "")).upper(),
            "user_interaction": str(v3.get("userInteraction") or comps.get("user_interaction", "")).upper(),
            "scope": str(v3.get("scope") or comps.get("scope", "")).upper(),
            "confidentiality_impact": str(
                v3.get("confidentialityImpact") or comps.get("confidentiality_impact", "")
            ).upper(),
            "integrity_impact": str(v3.get("integrityImpact") or comps.get("integrity_impact", "")).upper(),
            "availability_impact": str(v3.get("availabilityImpact") or comps.get("availability_impact", "")).upper(),
            "base_score": base_score,
            "base_severity": base_severity,
            "impact_score": _to_float(v3.get("impactScore")),
            "exploitability_score": _to_float(v3.get("exploitabilityScore")),
        }
        version = str(v3.get("version") or "")
        if not version and vector.startswith("CVSS:"):
            version = vector.split("/", 1)[0].split(":", 1)[1]
        is_v30 = version.startswith("3.0")
        return {
            "cvss_v31_data": None if is_v30 else payload,
            "cvss_v30_data": payload if is_v30 else None,
            "cvss_score": base_score,
            "severity": base_severity,
            "attack_vector": payload["attack_vector"] or DEFAULT_ATTACK_VECTOR,
            "result_impacts": [
                i
                for i in (
                    payload["confidentiality_impact"],
                    payload["integrity_impact"],
                    payload["availability_impact"],
                )
                if i
            ],
        }
    return {
        "cvss_v31_data": None,
        "cvss_v30_data": None,
        "cvss_score": DEFAULT_CVSS_SCORE,
        "severity": DEFAULT_SEVERITY,
        "attack_vector": DEFAULT_ATTACK_VECTOR,
        "result_impacts": [],
    }


def extract_products(product_tree: Any) -> Tuple[List[str], str, str]:
    """Walk ``product_tree.branches`` → (``["<vendor> <product>", ...]``, first vendor, first product)."""
    products: List[str] = []
    first_vendor = ""
    first_product = ""

    def _walk(branches: Any, vendor: str) -> None:
        nonlocal first_vendor, first_product
        if not isinstance(branches, list):
            return
        for branch in branches:
            if not isinstance(branch, dict):
                continue
            category = str(branch.get("category") or "")
            name = str(branch.get("name") or "").strip()
            current_vendor = vendor
            if category == "vendor" and name:
                current_vendor = name
                if not first_vendor:
                    first_vendor = name
            elif category == "product_name" and name:
                if not first_product:
                    first_product = name
                label = f"{current_vendor} {name}".strip()
                if label not in products:
                    products.append(label)
            _walk(branch.get("branches"), current_vendor)

    if isinstance(product_tree, dict):
        _walk(product_tree.get("branches"), "")
    return products[:MAX_AFFECTED_PRODUCTS], first_vendor, first_product


def advisory_url(advisory_id: str, document: Dict[str, Any], raw_url: str) -> str:
    """cisa.gov URL for the advisory: a ``self`` reference on cisa.gov if present,
    else derived from the id pattern, else the raw GitHub URL."""
    for ref in document.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "")
        if ref.get("category") == "self" and url.startswith("https://www.cisa.gov/"):
            return url
    return cisa_ics_advisory_url(advisory_id) or raw_url


def _first_vuln_note_text(vuln: Dict[str, Any]) -> str:
    notes = [n for n in (vuln.get("notes") or []) if isinstance(n, dict) and str(n.get("text") or "").strip()]
    for note in notes:
        if note.get("category") == "summary":
            return str(note["text"]).strip()
    return str(notes[0]["text"]).strip() if notes else ""


def parse_index(text: str) -> List[str]:
    """``index.txt`` → list of ``YYYY/<file>.json`` paths (order preserved, junk lines dropped)."""
    out: List[str] = []
    seen: set = set()
    for line in (text or "").splitlines():
        candidate = line.strip()
        if _INDEX_LINE_RE.match(candidate) and candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def parse_changes(text: str) -> List[Tuple[str, str]]:
    """``changes.csv`` (``"YYYY/<file>.json","<ISO timestamp>"``, no header) → ``[(path, ts), ...]``."""
    out: List[Tuple[str, str]] = []
    for row in csv.reader(io.StringIO(text or "")):
        if len(row) < 2:
            continue
        path, ts = row[0].strip(), row[1].strip()
        if _INDEX_LINE_RE.match(path) and _parse_dt(ts) is not None:
            out.append((path, ts))
    return out


def _advisory_order_key(item: Dict[str, Any]) -> Tuple[datetime, str]:
    """Newest advisory last: its ``last_modified`` (a missing date sorts first), then its id."""
    modified = _parse_dt(item.get("last_modified")) or datetime.min.replace(tzinfo=timezone.utc)
    return modified, str(item.get("advisory_id") or "")


def _sorted_union(items: List[Dict[str, Any]], key: str) -> List[str]:
    values = {str(v) for item in items for v in (item.get(key) or []) if v is not None and str(v) != ""}
    return sorted(values)


def _advisory_zones(group: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Advisory id → the sorted specific zones (no ``global``) its sector note maps to, keys sorted.

    An (advisory, CVE) item gives its own advisory and zones; an item merged before keeps its map. A key
    shared by two items takes the union."""
    out: Dict[str, Set[str]] = {}
    for x in group:
        given = x.get("advisory_zones")
        if not isinstance(given, dict):
            ids = x.get("advisory_ids") or [x.get("advisory_id")]
            given = {a: x.get("zone") or [] for a in ids if a}
        for advisory, zones in given.items():
            if not advisory:
                continue
            listed = [zones] if isinstance(zones, str) else list(zones or [])
            out.setdefault(str(advisory), set()).update(str(z) for z in listed if z and str(z) != "global")
    return {advisory: sorted(out[advisory]) for advisory in sorted(out)}


def merge_items_per_cve(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One item per CVE from the (advisory, CVE) items, independent of their order (2026-10-16).

    A CVE that several advisories name (a shared component, a multi-vendor product, a re-issued
    advisory) became one item per advisory, and MISPWriter keeps the first item of a value: the CVE kept
    the sectors and the references of whichever advisory came first, which differs between a baseline
    (newest first) and an incremental run (oldest first). The merged item takes:

    * the union of the zones (``global`` dropped once a sector is present), of CISA's sector names
      (``ics_sectors``) and of the reference URLs, sorted, and the sorted advisory ids (``advisory_ids``);
    * every other field (description, advisory id and title, vendor, product, affected products, CWE,
      CVSS, impacts) from the newest advisory (largest ``last_modified``, then largest advisory id);
    * the earliest ``published`` / ``first_seen`` and the latest ``last_modified`` / ``last_seen``.

    The sectors are also kept per advisory (``advisory_zones``: advisory id → the specific zones its
    sector note maps to, ``[]`` for an advisory that maps to none), so a sector link cites only the
    advisories that name its sector (``sector_evidence.stated_refs``), not every advisory of the CVE.

    A CVE that one advisory names gets the same form (sorted lists). The items are returned sorted by
    CVE id.
    """
    by_cve: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        by_cve.setdefault(str(item.get("cve_id") or ""), []).append(item)
    merged: List[Dict[str, Any]] = []
    for cve_id in sorted(by_cve):
        group = sorted(by_cve[cve_id], key=_advisory_order_key)
        item = dict(group[-1])
        zones = _sorted_union(group, "zone")
        specific = [z for z in zones if z != "global"]
        item["zone"] = specific or zones or ["global"]
        item["ics_sectors"] = _sorted_union(group, "ics_sectors")
        item["reference_urls"] = _sorted_union(group, "reference_urls")
        item["advisory_ids"] = sorted(
            {str(a) for x in group for a in (x.get("advisory_ids") or [x.get("advisory_id")]) if a}
        )
        item["advisory_zones"] = _advisory_zones(group)
        for key, pick in (("published", min), ("first_seen", min), ("last_modified", max), ("last_seen", max)):
            dated: List[Tuple[datetime, str]] = []
            for x in group:
                parsed = _parse_dt(x.get(key))
                if parsed is not None:
                    dated.append((parsed, str(x[key])))
            if dated:
                item[key] = pick(dated)[1]
            else:
                item.pop(key, None)
        merged.append(item)
    return merged


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class CISAICSCollector:
    """CISA ICS advisories (CSAF 2.0) collector — see module docstring for the safety contract."""

    def __init__(self, misp_writer: MISPWriter = None):
        base = (CISA_ICS_BASE_URL or "").strip()
        self.base_url = base if base.endswith("/") else base + "/"
        self.tag = SOURCE_ID
        self.misp_writer = misp_writer or MISPWriter()
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Flag / health
    # ------------------------------------------------------------------

    @staticmethod
    def is_enabled() -> bool:
        """Return ``config.ENABLE_CISA_ICS`` (resolved when ``config`` is imported; tests patch the attribute)."""
        import config as _config

        return bool(getattr(_config, "ENABLE_CISA_ICS", False))

    def health_check(self) -> Dict[str, Any]:
        """Check reachability of the advisory index on GitHub raw."""
        if not CISA_ICS_CIRCUIT_BREAKER.can_execute():
            return {
                "healthy": False,
                "error": "Circuit breaker open",
                "circuit_state": CISA_ICS_CIRCUIT_BREAKER.state.name,
            }
        try:
            start_time = time.time()
            response = requests.get(
                self.base_url + INDEX_FILE,
                timeout=(CISA_ICS_CONNECT_TIMEOUT, CISA_ICS_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                allow_redirects=False,
            )
            response_time = time.time() - start_time
            if response.status_code == 200:
                return {
                    "healthy": True,
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
            return {
                "healthy": False,
                "error": f"HTTP {response.status_code}",
                "response_time_ms": round(response_time * 1000, 2),
            }
        except requests.exceptions.Timeout as e:
            return {"healthy": False, "error": f"Timeout: {e}"}
        except requests.exceptions.ConnectionError as e:
            return {"healthy": False, "error": f"Connection error: {e}"}
        except Exception as e:
            return {"healthy": False, "error": f"{type(e).__name__}: {e}"}

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    @retry_with_backoff(max_retries=MAX_RETRIES, base_delay=RETRY_DELAY_BASE)
    def _get(self, url: str) -> requests.Response:
        """GET with rate limiting, 429/5xx backoff, retries and circuit-breaker accounting.

        Raises ``CISAICSTransientError`` (retried) on 429/5xx, plain
        ``requests.exceptions.HTTPError`` (NOT retried) on other non-200 codes.
        """
        CISA_ICS_RATE_LIMITER.wait_if_needed()
        try:
            response = request_with_rate_limit_retries(
                "GET",
                url,
                session=self._session,
                timeout=(CISA_ICS_CONNECT_TIMEOUT, CISA_ICS_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
                max_rate_limit_retries=3,
                fallback_delay_sec=30.0,
                retry_on_403=False,
                context="CISA-ICS",
            )
        except Exception:
            CISA_ICS_CIRCUIT_BREAKER.record_failure()
            raise
        code = response.status_code
        if code == 200:
            CISA_ICS_CIRCUIT_BREAKER.record_success()
            return response
        if code == 429 or code >= 500:
            CISA_ICS_CIRCUIT_BREAKER.record_failure()
            raise CISAICSTransientError(f"CISA ICS upstream HTTP {code} for {url}", response=response)
        # 4xx: permanent for this URL (missing file / layout change) — not a service outage.
        raise requests.exceptions.HTTPError(f"CISA ICS HTTP {code} for {url}", response=response)

    def _fetch_text(self, name: str) -> str:
        return self._get(self.base_url + name).text

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def _select_baseline_paths(self, baseline_days: int) -> Tuple[List[str], datetime]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=baseline_days)
        years = set(range(cutoff.year, datetime.now(timezone.utc).year + 1))
        prefilter_cutoff = cutoff - timedelta(days=FILENAME_DATE_MARGIN_DAYS)
        dated: List[Tuple[datetime, str]] = []
        undated: List[str] = []
        for path in parse_index(self._fetch_text(INDEX_FILE)):
            if int(path[:4]) not in years:
                continue
            published = path_published_date(path)
            if published is None:
                undated.append(path)  # unknown naming — fetch and let initial_release_date decide
            elif published >= prefilter_cutoff:
                dated.append((published, path))
        dated.sort(reverse=True)  # newest first so the per-run cap drops the oldest, not random, files
        undated.sort(reverse=True)
        return [p for _, p in dated] + undated, cutoff

    def _select_incremental_paths(self) -> Tuple[List[str], Dict[str, str]]:
        """Paths changed since the stored cursor (minus overlap), oldest first, with their change timestamps."""
        cursor = (get_source_incremental(SOURCE_ID).get("cisa_ics_last_change_ts") or "").strip() or None
        cursor_dt = _parse_dt(cursor) if cursor else None
        if cursor_dt is not None:
            since = cursor_dt - timedelta(seconds=CISA_ICS_INCREMENTAL_OVERLAP_SEC)
            logger.info(f"CISA ICS incremental: cursor={cursor} (overlap {CISA_ICS_INCREMENTAL_OVERLAP_SEC}s)")
        else:
            since = datetime.now(timezone.utc) - timedelta(days=CISA_ICS_INCREMENTAL_DAYS)
            logger.info(f"CISA ICS incremental: no cursor — lookback {CISA_ICS_INCREMENTAL_DAYS} days")
        selected: Dict[str, str] = {}
        for path, ts in parse_changes(self._fetch_text(CHANGES_FILE)):
            ts_dt = _parse_dt(ts)
            if ts_dt is None or ts_dt < since:
                continue
            if path not in selected or ts > selected[path]:
                selected[path] = ts
        paths = sorted(selected, key=lambda p: (selected[p], p))  # oldest first so a capped run advances safely
        return paths, selected

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_advisory(self, data: Any, path: str) -> Tuple[List[Dict[str, Any]], int]:
        """One CSAF document → ``(items, skipped_vulns)``.

        Raises ``ValueError`` when the payload is not a JSON object carrying a
        ``document`` object and a ``vulnerabilities`` list — the caller counts
        it as malformed and moves on.
        """
        if not isinstance(data, dict):
            raise ValueError(f"{path}: payload is {type(data).__name__}, expected JSON object")
        document = data.get("document")
        vulnerabilities = data.get("vulnerabilities")
        if not isinstance(document, dict):
            raise ValueError(f"{path}: missing/invalid 'document' object")
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"{path}: missing/invalid 'vulnerabilities' list")

        tracking = document.get("tracking") if isinstance(document.get("tracking"), dict) else {}
        advisory_id = (
            str(tracking.get("id") or "").strip().upper() or os.path.splitext(os.path.basename(path))[0].upper()
        )
        title = str(document.get("title") or "").strip()
        initial_iso = _iso_utc(tracking.get("initial_release_date"))
        current_iso = _iso_utc(tracking.get("current_release_date")) or initial_iso
        sectors = parse_sectors(document)
        zones = map_sectors_to_zones(sectors)
        raw_url = self.base_url + path
        url = advisory_url(advisory_id, document, raw_url)
        affected_products, vendor, product = extract_products(data.get("product_tree"))
        header = f"{advisory_id}: {title}" if title else advisory_id

        items: List[Dict[str, Any]] = []
        skipped = 0
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                skipped += 1
                continue
            cve_id = str(vuln.get("cve") or "").strip().upper()
            if not _CVE_RE.match(cve_id):
                skipped += 1
                logger.debug(f"CISA ICS {advisory_id}: skipping vulnerability without valid CVE id ({cve_id!r})")
                continue
            cwe = vuln.get("cwe") if isinstance(vuln.get("cwe"), dict) else {}
            cwe_id = str(cwe.get("id") or "").strip().upper()
            cwe_list = [cwe_id] if _CWE_RE.match(cwe_id) else []
            note = _first_vuln_note_text(vuln)
            description = f"{header} — {note}" if note else header
            cvss = extract_cvss(vuln)

            item: Dict[str, Any] = {
                "type": "vulnerability",
                "cve_id": cve_id,
                "description": description[:DESCRIPTION_MAX_CHARS],
                # Source-asserted sectors — NOT the keyword detector.
                "zone": list(zones),
                "tag": self.tag,
                "source": [self.tag],
                "confidence_score": 0.9,  # authoritative government advisory
                "severity": cvss["severity"],
                "cvss_score": cvss["cvss_score"],
                "attack_vector": cvss["attack_vector"],
                "vendor": vendor,
                "product": product,
                "affected_products": list(affected_products),
                "cwe": cwe_list,
                "ref_tags": [],
                "reference_urls": [url],
                "cpe_type": [],
                "result_impacts": cvss["result_impacts"],
                "cvss_v31_data": cvss["cvss_v31_data"],
                "cvss_v30_data": cvss["cvss_v30_data"],
                # Source-truthful timestamps (honest-NULL: omitted below when absent).
                "published": initial_iso,
                "last_modified": current_iso,
                "first_seen": initial_iso,
                "last_seen": current_iso,
                # Advisory provenance (2026-10-16): MISPWriter carries the advisory ids, CISA's own
                # sector names and the zones of each advisory in NVD_META, the sync puts them on the
                # CVE's SOURCED_FROM edge (``raw_data``) and names the advisories in ``source_refs``
                # (``cisa_ics:<id>``). ``merge_items_per_cve`` takes the union over the advisories that
                # name the CVE and keeps the zones per advisory (``advisory_zones``).
                "advisory_id": advisory_id,
                "advisory_ids": [advisory_id],
                "advisory_title": title,
                "ics_sectors": list(sectors),
            }
            for key in ("published", "last_modified", "first_seen", "last_seen"):
                if item[key] is None:
                    del item[key]
            items.append(item)
        return items, skipped

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 730
    ) -> Any:
        """Collect ICS advisories and optionally push to MISP.

        Returns a status dict when ``push_to_misp=True`` (Airflow contract),
        otherwise the list of processed items.
        """
        if not self.is_enabled():
            logger.info(
                "CISA ICS collector disabled by flag (EDGEGUARD_ENABLE_CISA_ICS is not true) — skipping, 0 items"
            )
            if push_to_misp:
                return make_skipped_optional_source(
                    SOURCE_ID,
                    skip_reason="disabled by flag EDGEGUARD_ENABLE_CISA_ICS",
                    skip_reason_class="cisa_ics_disabled_by_flag",
                )
            return []

        limit = resolve_collection_limit(limit, SOURCE_ID, baseline=baseline)
        stats = {
            "candidates": 0,
            "attempted": 0,
            "parsed_ok": 0,
            "fetch_failed": 0,
            "malformed": 0,
            "outside_window": 0,
            "skipped_vulns": 0,
        }
        processed: List[Dict[str, Any]] = []
        change_ts: Dict[str, str] = {}
        processed_max_ts: Optional[str] = None

        try:
            if not CISA_ICS_CIRCUIT_BREAKER.can_execute():
                raise CISAICSTransientError("CISA ICS circuit breaker open — skipping run")

            if baseline:
                logger.info(f"📜 Baseline mode: CISA ICS advisories within {baseline_days} days...")
                paths, cutoff = self._select_baseline_paths(baseline_days)
            else:
                paths, change_ts = self._select_incremental_paths()
                cutoff = None
            stats["candidates"] = len(paths)

            cap = max(0, int(CISA_ICS_MAX_ADVISORIES_PER_RUN))
            if cap and len(paths) > cap:
                logger.warning(
                    f"CISA ICS: {len(paths)} advisories selected, capping at CISA_ICS_MAX_ADVISORIES_PER_RUN={cap}"
                )
                paths = paths[:cap]
            logger.info(f"CISA ICS: {stats['candidates']} advisories selected, fetching up to {len(paths)}")

            consecutive_failures = 0
            for path in paths:
                if limit is not None and len(processed) >= limit:
                    break
                if not CISA_ICS_CIRCUIT_BREAKER.can_execute():
                    raise CISAICSTransientError("CISA ICS circuit breaker opened mid-run — aborting before push")
                stats["attempted"] += 1
                try:
                    data = self._get(self.base_url + path).json()
                except (
                    requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.HTTPError,  # includes CISAICSTransientError after retries
                    ValueError,  # JSON decode error
                ) as e:
                    stats["fetch_failed"] += 1
                    consecutive_failures += 1
                    logger.warning(f"CISA ICS: fetch failed for {path}: {type(e).__name__}: {e}")
                    if consecutive_failures >= MAX_CONSECUTIVE_FETCH_FAILURES:
                        raise CISAICSTransientError(
                            f"CISA ICS: {consecutive_failures} consecutive advisory fetch failures — upstream broken"
                        ) from e
                    continue
                consecutive_failures = 0
                if path in change_ts and (processed_max_ts is None or change_ts[path] > processed_max_ts):
                    processed_max_ts = change_ts[path]
                try:
                    items, skipped = self.parse_advisory(data, path)
                except ValueError as e:
                    stats["malformed"] += 1
                    logger.warning(f"CISA ICS: malformed advisory skipped — {e}")
                    continue
                stats["parsed_ok"] += 1
                stats["skipped_vulns"] += skipped
                if cutoff is not None and items:
                    first_seen = _parse_dt(items[0].get("first_seen"))
                    if first_seen is not None and first_seen < cutoff:
                        stats["outside_window"] += 1
                        continue
                processed.extend(items)

            if limit is not None:
                processed = processed[:limit]
            # 2026-10-16: one item per CVE, whatever the order of the advisories (newest first in a
            # baseline, oldest first in an incremental run). MISPWriter keeps the first item of a value,
            # so before this a CVE named by several advisories kept one advisory's sectors only.
            advisory_items = len(processed)
            processed = merge_items_per_cve(processed)
            if len(processed) < advisory_items:
                logger.info(
                    "CISA ICS: %d (advisory, CVE) items merged into %d CVE items", advisory_items, len(processed)
                )

            if baseline:
                self._enforce_baseline_floor(stats, baseline_days)

            logger.info(
                f"[OK] CISA ICS: {len(processed)} CVE items from {stats['parsed_ok']} advisories "
                f"(attempted={stats['attempted']}, fetch_failed={stats['fetch_failed']}, "
                f"malformed={stats['malformed']}, outside_window={stats['outside_window']}, "
                f"skipped_vulns={stats['skipped_vulns']})"
            )

            if not push_to_misp:
                return processed

            if not processed:
                st = self._return_status(True, 0, failed=0)
                st["stats"] = dict(stats)
                # Same gate as the push path below (Bugbot on PR #136): an advisory that failed to
                # fetch must stay in front of the cursor, or a later file's timestamp moves the
                # cursor past it and it is never retried until it changes again.
                if not baseline and processed_max_ts and stats.get("fetch_failed", 0) == 0:
                    self._advance_cursor(processed_max_ts)
                elif not baseline and processed_max_ts:
                    logger.warning(
                        "CISA ICS: cursor NOT advanced on empty run (fetch failures=%s) — will retry next run",
                        stats.get("fetch_failed", 0),
                    )
                return st

            success, failed = self.misp_writer.push_items(processed)
            if success > 0:
                logger.info(f"[OK] CISA ICS: Successfully pushed {success} items to MISP")
            if failed > 0:
                logger.warning(f"[WARN] CISA ICS: Failed to push {failed} items to MISP")

            st = status_after_misp_push(SOURCE_ID, len(processed), success, failed)
            st["circuit_breaker_state"] = CISA_ICS_CIRCUIT_BREAKER.state.name
            st["stats"] = dict(stats)
            # Cursor advances only after a CLEAN push (mirrors the OTX / MITRE cursors).
            # 2026-10 review fix: a failed fetch must not be skipped by the cursor moving past it —
            # advance only when every selected advisory was fetched and pushed cleanly.
            if not baseline and failed == 0 and stats.get("fetch_failed", 0) == 0 and processed_max_ts:
                self._advance_cursor(processed_max_ts)
            elif not baseline and processed_max_ts:
                logger.warning(
                    "CISA ICS: cursor NOT advanced (push failures=%s, fetch failures=%s) — will retry next run",
                    failed,
                    stats.get("fetch_failed", 0),
                )
            return st

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, TransientServerError) as e:
            # Upstream outage / baseline floor → propagate so run_collector_with_metrics
            # classifies it as transient (task skipped + alert, nothing partial written).
            logger.error(f"CISA ICS transient failure: {type(e).__name__}: {e}")
            raise
        except requests.exceptions.HTTPError as e:
            # 4xx on index/changes (layout change) — permanent, needs an operator.
            logger.error(f"CISA ICS HTTP error: {e}")
            if push_to_misp:
                return self._return_status(False, 0, str(e))
            raise
        except Exception as e:
            # Code defects fail loudly (DAG catastrophic branch) — never masked as a status dict.
            logger.error(f"CISA ICS collection error: {type(e).__name__}: {e}")
            raise

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _enforce_baseline_floor(self, stats: Dict[str, int], baseline_days: int) -> None:
        floor = max(0, int(CISA_ICS_MIN_EXPECTED_ADVISORIES))
        reason: Optional[str] = None
        if stats["candidates"] == 0:
            reason = f"index lists 0 advisories in the {baseline_days}-day window (upstream layout change?)"
        elif floor and stats["attempted"] >= floor and stats["parsed_ok"] < floor:
            reason = (
                f"only {stats['parsed_ok']} of {stats['attempted']} attempted advisories parsed "
                f"(floor CISA_ICS_MIN_EXPECTED_ADVISORIES={floor}; fetch_failed={stats['fetch_failed']}, "
                f"malformed={stats['malformed']})"
            )
        if reason is None:
            return
        logger.error(f"CISA ICS baseline sanity floor violated — {reason}. Nothing pushed to MISP.")
        try:
            from metrics_server import record_pipeline_error

            record_pipeline_error(f"collect_{SOURCE_ID}", "CISAICSBaselineFloorError", SOURCE_ID)
        except Exception as me:  # noqa: BLE001 - metrics must never mask the floor error
            logger.debug(f"metric emit failed (baseline floor): {me}")
        raise CISAICSBaselineFloorError(f"CISA ICS baseline sanity floor violated: {reason}")

    @staticmethod
    def _advance_cursor(max_ts: str) -> None:
        try:
            update_source_incremental(SOURCE_ID, cisa_ics_last_change_ts=max_ts)
            logger.info(f"CISA ICS incremental cursor advanced to {max_ts}")
        except Exception as e:  # noqa: BLE001 - a checkpoint write error must not fail an otherwise clean run
            logger.warning(f"CISA ICS: could not persist incremental cursor: {type(e).__name__}: {e}")

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Standard status dict for Airflow when push_to_misp=True."""
        result = make_status(SOURCE_ID, success, count=count, failed=failed, error=error)
        result["circuit_breaker_state"] = CISA_ICS_CIRCUIT_BREAKER.state.name
        return result


def test_cisa_ics() -> Any:
    """Manual smoke test: collect without pushing and print the first items."""
    collector = CISAICSCollector()
    result = collector.collect(limit=20, push_to_misp=False)
    print("\n📥 CISA ICS Test Result:")
    print(json.dumps(result if isinstance(result, dict) else result[:3], indent=2, default=str))
    return result


if __name__ == "__main__":
    test_cisa_ics()
