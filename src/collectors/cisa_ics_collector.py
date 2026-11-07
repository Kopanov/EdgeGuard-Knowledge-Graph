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

import report_records
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
# The other document notes the report record reads (2026-11-07): the advisory's summary, where the product is
# deployed, and the vendor's headquarters.
ADVISORY_SUMMARY_NOTE_TITLE = "advisory summary"
COUNTRIES_NOTE_TITLE = "countries/areas deployed"
HEADQUARTERS_NOTE_TITLE = "company headquarters location"
# A listed name that holds commas itself: the critical infrastructure sector of that name (CISA's list of the 16
# sectors). ``split_note_list`` keeps it whole.
LISTED_NAMES_WITH_COMMAS: Tuple[str, ...] = ("Nuclear Reactors, Materials, and Waste",)
_LEADING_CONJUNCTION_RE = re.compile(r"^(?:and|&)\s+", re.IGNORECASE)
# Country and territory names (ISO 3166) that hold "and" themselves: ``split_countries_note`` keeps them whole.
COUNTRY_NAMES_WITH_AND: Tuple[str, ...] = (
    "Antigua and Barbuda",
    "Bosnia and Herzegovina",
    "Heard Island and McDonald Islands",
    "Saint Kitts and Nevis",
    "Saint Pierre and Miquelon",
    "Saint Vincent and the Grenadines",
    "Sao Tome and Principe",
    "South Georgia and the South Sandwich Islands",
    "Svalbard and Jan Mayen",
    "Trinidad and Tobago",
    "Turks and Caicos Islands",
    "Wallis and Futuna",
)
_AND_RE = re.compile(r"\s+and\s+", re.IGNORECASE)
# The full stop that ends a note's sentence: after a lower-case letter only, so ``"U.S."`` keeps its own.
_SENTENCE_END_RE = re.compile(r"(?<=[a-z])\.\s*$")
# The title of a vulnerability note of category ``details`` that holds a score, not the vulnerability's text.
_SCORE_NOTE_TITLE_RE = re.compile(r"^\s*(?:cvss|ssvc)\b", re.IGNORECASE)
_SECTOR_SUFFIX_RE = re.compile(r"\s+sector$", re.IGNORECASE)
# The CSAF product_status lists that name affected products (CSAF 2.0, 3.2.3.9).
AFFECTED_PRODUCT_STATUSES: Tuple[str, ...] = ("first_affected", "known_affected", "last_affected")
_ADVISORY_KIND_RE = re.compile(r"^(ICSA|ICSMA)-")

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

MAX_AFFECTED_PRODUCTS = 10

# Report records (2026-11-07): the records pushed per ``MISPWriter.push_reports`` call (``report_pending`` is saved
# after each, so a task killed during the pushes loses the outcome of one batch at most), and the records of
# ``report_pending`` whose advisories one run reads for their records only.
REPORT_BATCH = 100
REPORT_PENDING_PER_RUN = 100
# The counts of a run's record pushes (``report_counts`` of its status), as ``MISPWriter.push_reports`` gives them.
REPORT_COUNT_KEYS: Tuple[str, ...] = (
    "reports_added",
    "reports_updated",
    "reports_unchanged",
    "reports_deleted_in_misp",
    "reports_failed",
    "reports_foreign",
    "reports_skipped",
    "report_tag_drift",
)


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
    Every returned zone is validated against ``config.VALID_ZONES``. Case and a trailing word ``Sector`` are
    ignored (2026-11-07: ``"Healthcare and Public Health Sector"`` in ICSMA-24-254-01 mapped to nothing).
    """
    zones: List[str] = []
    for raw in sectors or []:
        zone = _ICS_SECTOR_ZONE_LOOKUP.get(_SECTOR_SUFFIX_RE.sub("", str(raw or "").strip()).lower())
        if zone and zone in VALID_ZONES and zone not in zones:
            zones.append(zone)
    return zones or ["global"]


def note_texts(document: Dict[str, Any], title: str) -> List[str]:
    """The trimmed, non-empty texts of the document notes titled *title* (case and surrounding spaces ignored),
    in document order."""
    out: List[str] = []
    for note in document.get("notes") or []:
        if not isinstance(note, dict):
            continue
        if str(note.get("title") or "").strip().lower() != title:
            continue
        text = str(note.get("text") or "").strip()
        if text:
            out.append(text)
    return out


def split_note_list(text: str) -> List[str]:
    """The names a note lists, in order, each once: the text split at commas, each part trimmed, a leading
    ``and`` / ``&`` of the last part of a list (``"Critical Manufacturing, Energy, and Water"``) removed. A name
    that holds commas itself (``LISTED_NAMES_WITH_COMMAS``) is kept whole. A name that holds ``and`` without a
    comma before it (``"Food and Agriculture"``) is one name."""
    protected = str(text or "")
    kept: Dict[str, str] = {}
    for index, name in enumerate(LISTED_NAMES_WITH_COMMAS):
        token = f"\x00{index}\x00"
        kept[token] = name
        protected = re.sub(re.escape(name), token, protected, flags=re.IGNORECASE)
    out: List[str] = []
    for part in protected.split(","):
        name = _LEADING_CONJUNCTION_RE.sub("", part.strip()).strip()
        name = kept.get(name, name)
        if name and "\x00" not in name and name not in out:
            out.append(name)
    return out


def split_countries_note(text: str) -> List[str]:
    """The names the note "Countries/areas deployed" lists, in order, each once: ``split_note_list`` of the text
    without the full stop that ends its sentence (``"Asia."``; ``"U.S."`` keeps its own), and a part that still
    joins names with ``and`` (``"Europe, the Middle East and Asia."``) split there, except within a country name
    that holds ``and`` itself (``COUNTRY_NAMES_WITH_AND``)."""
    out: List[str] = []
    for part in split_note_list(_SENTENCE_END_RE.sub("", str(text or "").strip())):
        protected = part
        kept: Dict[str, str] = {}
        for index, name in enumerate(COUNTRY_NAMES_WITH_AND):
            token = f"\x00{index}\x00"
            kept[token] = name
            protected = re.sub(re.escape(name), token, protected, flags=re.IGNORECASE)
        for piece in _AND_RE.split(protected):
            name = piece.strip()
            for token, original in kept.items():
                name = name.replace(token, original)
            if name and name not in out:
                out.append(name)
    return out


def parse_sectors(document: Dict[str, Any]) -> List[str]:
    """The sector names the ``"Critical infrastructure sectors"`` note(s) list (``split_note_list``): a list such
    as ``"Commercial Facilities, Critical Manufacturing, and Energy"`` gives ``"Energy"``, never ``"and Energy"``
    (2026-11-07)."""
    out: List[str] = []
    for text in note_texts(document, SECTORS_NOTE_TITLE):
        for name in split_note_list(text):
            if name not in out:
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
    A block without a valid base score is not a CVSS (2026-10: it used to become 0.0 / HIGH); a
    missing impact or exploitability sub-score is None (2026-10: it used to become 0.0).
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
            # 2026-10: CSAF's cvss_v3 block carries no impact or exploitability sub-score, so these are
            # None (not written to the CVSS sub-node) unless the block gives a valid one. They were 0.0,
            # which the graph showed as CISA's sub-scores.
            "impact_score": clamp_cvss_score(v3.get("impactScore")),
            "exploitability_score": clamp_cvss_score(v3.get("exploitabilityScore")),
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


def product_tree_names(product_tree: Any) -> Tuple[List[str], List[str], List[str]]:
    """Walk ``product_tree.branches`` → (the vendor names, the ``"<vendor> <product>"`` labels of the
    ``product_name`` branches, the ``"<vendor> <family>"`` labels of the ``product_family`` branches), each in
    tree order and once."""
    vendors: List[str] = []
    products: List[str] = []
    families: List[str] = []

    def _walk(branches: Any, vendor: str) -> None:
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
                if name not in vendors:
                    vendors.append(name)
            elif category in ("product_name", "product_family") and name:
                label = f"{current_vendor} {name}".strip()
                listed = products if category == "product_name" else families
                if label not in listed:
                    listed.append(label)
            _walk(branch.get("branches"), current_vendor)

    if isinstance(product_tree, dict):
        _walk(product_tree.get("branches"), "")
    return vendors, products, families


def extract_products(product_tree: Any) -> Tuple[List[str], str, str]:
    """Walk ``product_tree.branches`` → (``["<vendor> <product>", ...]``, first vendor, first product)."""
    vendors, products, _families = product_tree_names(product_tree)
    first_product = ""

    def _first(branches: Any) -> None:
        nonlocal first_product
        for branch in branches if isinstance(branches, list) else []:
            if first_product or not isinstance(branch, dict):
                continue
            name = str(branch.get("name") or "").strip()
            if branch.get("category") == "product_name" and name:
                first_product = name
                return
            _first(branch.get("branches"))

    if isinstance(product_tree, dict):
        _first(product_tree.get("branches"))
    return products[:MAX_AFFECTED_PRODUCTS], vendors[0] if vendors else "", first_product


def product_id_names(product_tree: Any) -> Dict[str, str]:
    """``product_id`` → full product name over the whole product tree: the ``product`` of every branch, the
    ``full_product_names`` and the ``full_product_name`` of every relationship (CSAF 2.0, 3.2.2)."""
    names: Dict[str, str] = {}

    def _add(full: Any) -> None:
        if not isinstance(full, dict):
            return
        product_id = str(full.get("product_id") or "").strip()
        name = str(full.get("name") or "").strip()
        if product_id and name and product_id not in names:
            names[product_id] = name

    def _walk(branches: Any) -> None:
        for branch in branches if isinstance(branches, list) else []:
            if isinstance(branch, dict):
                _add(branch.get("product"))
                _walk(branch.get("branches"))

    if isinstance(product_tree, dict):
        _walk(product_tree.get("branches"))
        for full in product_tree.get("full_product_names") or []:
            _add(full)
        for relationship in product_tree.get("relationships") or []:
            if isinstance(relationship, dict):
                _add(relationship.get("full_product_name"))
    return names


def affected_product_names(vuln: Dict[str, Any], names: Dict[str, str]) -> List[str]:
    """The full names of the products a vulnerability's ``product_status`` lists as affected
    (``AFFECTED_PRODUCT_STATUSES``), resolved through the product tree (*names*, ``product_id_names``), in
    the order given and once; an id the tree does not name is left out."""
    status = vuln.get("product_status") if isinstance(vuln.get("product_status"), dict) else {}
    out: List[str] = []
    for key in AFFECTED_PRODUCT_STATUSES:
        for product_id in status.get(key) or []:
            name = names.get(str(product_id or "").strip())
            if name and name not in out:
                out.append(name)
    return out


def vulnerability_summary(vuln: Dict[str, Any]) -> str:
    """The vulnerability's own text, whole: its first note of category ``summary`` (CISA's "Vulnerability
    Summary"), else its first of category ``description`` (the "CVE Description" of an advisory converted from a
    vendor's), else its first of category ``details`` whose title names no score (a converted advisory that files
    its "CVE description" or "Vulnerability Details" there: 2 of the 7,764 vulnerabilities of 2024-2026), else
    ``""``. A ``details`` note titled CVSS or SSVC (a score) and a note of another category (an untitled
    ``other`` heading) are no summary."""
    notes = [n for n in (vuln.get("notes") or []) if isinstance(n, dict) and str(n.get("text") or "").strip()]
    for category in ("summary", "description"):
        for note in notes:
            if note.get("category") == category:
                return str(note["text"]).strip()
    for note in notes:
        if note.get("category") == "details" and not _SCORE_NOTE_TITLE_RE.match(str(note.get("title") or "")):
            return str(note["text"]).strip()
    return ""


def vulnerability_remediations(vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """The vulnerability's remediations as ``{"category", "details"}`` (CSAF 2.0, 3.2.3.12): ``vendor_fix``,
    ``mitigation``, ``workaround``, ``none_available``, ``no_fix_planned``."""
    out: List[Dict[str, str]] = []
    for entry in vuln.get("remediations") or []:
        if isinstance(entry, dict) and str(entry.get("category") or "").strip():
            out.append({"category": str(entry["category"]).strip(), "details": str(entry.get("details") or "")})
    return out


def vulnerability_cwes(vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """The vulnerability's CWE as ``{"id", "name"}``: CSAF 2.0's ``cwe`` object, or the entries of a CSAF 2.1
    ``cwes`` list."""
    listed = vuln.get("cwes")
    given = [vuln.get("cwe"), *(listed if isinstance(listed, list) else [])]
    return [
        {"id": str(c.get("id") or "").strip().upper(), "name": str(c.get("name") or "").strip()}
        for c in given
        if isinstance(c, dict) and str(c.get("id") or "").strip()
    ]


def advisory_kind(advisory_id: str) -> Optional[str]:
    """``ICSA`` or ``ICSMA`` from the advisory id, None for an id of another form."""
    match = _ADVISORY_KIND_RE.match(str(advisory_id or "").strip().upper())
    return match.group(1) if match else None


def csaf_document_url(document: Dict[str, Any], path: str, raw_url: str) -> str:
    """The URL of the advisory's CSAF file: the document's ``self`` reference that ends with the file's name
    (CISA's own copy on GitHub; a converted advisory also names the vendor's CSAF file, under another name),
    else the URL the collector read (*raw_url*)."""
    file_name = "/" + os.path.basename(path or "").lower()
    for ref in document.get("references") or []:
        if not isinstance(ref, dict) or ref.get("category") != "self":
            continue
        url = str(ref.get("url") or "").strip()
        if file_name != "/" and url.lower().endswith(file_name):
            return url
    return raw_url


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


def _listed_record_key(path: str) -> str:
    """The lower-case file name of a listed advisory path without ``.json``: its lower-case advisory id (every
    file of 2024-2026 is named after its ``tracking.id``, read 2026-11-07)."""
    return os.path.splitext(os.path.basename(path))[0].lower()


def _advisory_parts(data: Any, path: str) -> Tuple[Dict[str, Any], List[Any], Dict[str, Any], str]:
    """``(document, vulnerabilities, tracking, advisory id)`` of a CSAF payload. Raises ``ValueError`` when it is
    not a JSON object carrying a ``document`` object and a ``vulnerabilities`` list. The advisory id is
    ``tracking.id`` upper-cased, else the file name's."""
    if not isinstance(data, dict):
        raise ValueError(f"{path}: payload is {type(data).__name__}, expected JSON object")
    document = data.get("document")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(document, dict):
        raise ValueError(f"{path}: missing/invalid 'document' object")
    if not isinstance(vulnerabilities, list):
        raise ValueError(f"{path}: missing/invalid 'vulnerabilities' list")
    tracking = document.get("tracking") if isinstance(document.get("tracking"), dict) else {}
    advisory_id = str(tracking.get("id") or "").strip().upper() or os.path.splitext(os.path.basename(path))[0].upper()
    return document, vulnerabilities, tracking, advisory_id


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
        # The advisory files the run's listing (``index.txt`` or ``changes.csv``) names, by lower-case file name
        # without ``.json`` (the lower-case advisory id): where the records on ``report_pending`` are read from.
        self._listing: Dict[str, str] = {}

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
            self._listing.setdefault(_listed_record_key(path), path)
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
            self._listing.setdefault(_listed_record_key(path), path)
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
        document, vulnerabilities, tracking, advisory_id = _advisory_parts(data, path)
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
                # 2026-11-07: the whole text, uncut (MISP holds the source's text); the sync caps the graph's copy
                # (``text_caps.CVE_DESCRIPTION_CAP``).
                "description": description,
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

    def parse_advisory_record(self, data: Any, path: str) -> Dict[str, Any]:
        """One CSAF document → its report record (``report_records.build_record`` for ``cisa_ics``, 2026-11-07).

        The record holds what the advisory says, as it says it (docs/MISP_SOURCES.md, "Report records"):

        * ``record_id``: ``tracking.id`` (as ``parse_advisory`` reads it); ``url``: the cisa.gov page
          (``advisory_url``); ``csaf_url``: the CSAF file (``csaf_document_url``); ``kind``: ICSA or ICSMA;
        * ``title``; ``description``: the note "Advisory Summary" (else the document's first note of category
          ``summary``), whole; ``publisher``: ``document.publisher.name``; ``tlp``: ``distribution.tlp.label``;
        * ``published`` / ``last_modified``: ``tracking.initial_release_date`` / ``current_release_date`` (the
          initial date when there is no current one); ``revision``: the number of ``tracking.revision_history``
          entries; ``version``: ``tracking.version`` as given (a whole number, or a version such as ``1.0.1``);
        * ``deployment_sectors``, ``deployment_countries``: the names the notes "Critical infrastructure sectors"
          and "Countries/areas deployed" list (``split_note_list``, ``split_countries_note``);
          ``vendor_headquarters``: the text of the note "Company headquarters location" (the texts of several
          such notes joined with ``", "``);
        * ``vendors``, ``products``: the vendor names and ``"<vendor> <product>"`` labels of the product tree,
          all of them (``product_tree_names``); a tree without a ``product_name`` branch gives its
          ``"<vendor> <family>"`` labels (13 of the 1,389 advisories of 2024-2026; one more, ICSA-25-303-01,
          has only specification branches and gives no product);
        * ``cve_ids`` and ``vulnerabilities``, one entry per vulnerability with a valid CVE id: ``cve_id``,
          ``summary`` (``vulnerability_summary``, whole), ``remediations`` (category and details),
          ``affected_products`` (``affected_product_names``) and ``cwes`` (id and name).

        Raises ``ValueError`` for a payload ``parse_advisory`` refuses. An advisory without a CVE gets a record
        with empty ``cve_ids`` and ``vulnerabilities``. A list the record's item cap cuts (``report_records.list_cuts``;
        no advisory of 2024-2026 reaches one) is logged at WARNING ``[REPORTS]`` with the record reference and the
        counts.
        """
        document, vulnerabilities, tracking, advisory_id = _advisory_parts(data, path)
        raw_url = self.base_url + path
        vendors, products, families = product_tree_names(data.get("product_tree"))
        names = product_id_names(data.get("product_tree"))
        entries: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            cve_id = str(vuln.get("cve") or "").strip().upper()
            if not _CVE_RE.match(cve_id):
                continue
            entries.append(
                {
                    "cve_id": cve_id,
                    "summary": vulnerability_summary(vuln),
                    "remediations": vulnerability_remediations(vuln),
                    "affected_products": affected_product_names(vuln, names),
                    "cwes": vulnerability_cwes(vuln),
                }
            )
        distribution = document.get("distribution") if isinstance(document.get("distribution"), dict) else {}
        tlp = distribution.get("tlp") if isinstance(distribution.get("tlp"), dict) else {}
        publisher = document.get("publisher") if isinstance(document.get("publisher"), dict) else {}
        summary = note_texts(document, ADVISORY_SUMMARY_NOTE_TITLE) or [
            str(n.get("text") or "").strip()
            for n in document.get("notes") or []
            if isinstance(n, dict) and n.get("category") == "summary" and str(n.get("text") or "").strip()
        ]
        countries: List[str] = []
        for text in note_texts(document, COUNTRIES_NOTE_TITLE):
            countries.extend(name for name in split_countries_note(text) if name not in countries)
        history = tracking.get("revision_history")
        fields = {
            "record_id": advisory_id,
            "url": advisory_url(advisory_id, document, raw_url),
            "title": document.get("title"),
            "description": summary[0] if summary else "",
            "published": tracking.get("initial_release_date"),
            "last_modified": tracking.get("current_release_date") or tracking.get("initial_release_date"),
            "revision": len(history) if isinstance(history, list) else None,
            "version": tracking.get("version") if isinstance(tracking.get("version"), str) else None,
            "tlp": tlp.get("label"),
            "publisher": publisher.get("name"),
            "kind": advisory_kind(advisory_id),
            "csaf_url": csaf_document_url(document, path, raw_url),
            "vendors": vendors,
            "products": products or families,
            "deployment_sectors": parse_sectors(document),
            "deployment_countries": countries,
            "vendor_headquarters": ", ".join(dict.fromkeys(note_texts(document, HEADQUARTERS_NOTE_TITLE))) or None,
            "cve_ids": [entry["cve_id"] for entry in entries],
            "vulnerabilities": entries,
        }
        record = report_records.build_record(report_records.SOURCE_CISA_ICS, fields)
        for name, kept, given in report_records.list_cuts(report_records.SOURCE_CISA_ICS, fields):
            logger.warning(
                "[REPORTS] CISA ICS %s: the record keeps %d of the %d %s (its cap)",
                record["record_ref"],
                kept,
                given,
                name,
            )
        return record

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 730
    ) -> Any:
        """Collect ICS advisories and optionally push to MISP.

        Returns a status dict when ``push_to_misp=True`` (Airflow contract),
        otherwise the list of processed items.

        Report records (2026-11-07): every advisory fetched and parsed in the window gets its report record
        (``parse_advisory_record``), an advisory without a CVE included. With ``push_to_misp`` the records are
        written (``_push_records``: ``MISPWriter.push_reports``, ``REPORT_BATCH`` at a time) after the CVE items
        (an item batch's answer carries every report of the event, so records written first would come back with
        every batch) and before the return of a run without items, and those whose push failed or was not tried
        go on the ``report_pending`` list of the ``cisa_ics`` incremental state (``report_records.note_report_push``,
        baselines included). So do the records the run could not build or read: an advisory in the window that
        could not be fetched (by its file name's date on a baseline), a record that could not be built. Each run
        that pushes also reads the advisories of up to ``REPORT_PENDING_PER_RUN`` records on that list
        (``_pending_paths``) for their records only. A record failure does not hold the cursor: the list keeps the
        record. The cursor stays only while a record is neither in MISP nor saved on the list (the list could not
        be saved).
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
            "records": 0,
            "pending_fetched": 0,
            "pending_failed": 0,
            "pending_not_listed": 0,
        }
        processed: List[Dict[str, Any]] = []
        records: Dict[str, Dict[str, Any]] = {}
        # Records the run could not build or read (``{"record_ref", "reason", "permanent"}``), settled on
        # ``report_pending`` with the push's outcome.
        record_failures: List[Dict[str, Any]] = []
        change_ts: Dict[str, str] = {}
        processed_max_ts: Optional[str] = None

        try:
            if not CISA_ICS_CIRCUIT_BREAKER.can_execute():
                raise CISAICSTransientError("CISA ICS circuit breaker open — skipping run")

            self._listing = {}
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
            pending_paths: Dict[str, str] = {}
            pending_refs: Set[str] = set()
            if push_to_misp:
                pending_paths, not_listed, pending_refs = self._pending_paths(paths)
                stats["pending_not_listed"] = len(not_listed)
                # A failed try, not a permanent exit: an advisory really withdrawn is given up after
                # EDGEGUARD_REPORT_PENDING_MAX_DAYS ([REPORT-GAVE-UP], the given-up metric), a listing read badly once
                # loses nothing.
                record_failures.extend(
                    {
                        "record_ref": ref,
                        "reason": "the listing does not name the advisory: its record cannot be read",
                        "permanent": False,
                    }
                    for ref in not_listed
                )

            consecutive_failures = 0
            for path in [*paths, *pending_paths]:
                pending_ref = pending_paths.get(path)
                if pending_ref is None and limit is not None and len(processed) >= limit:
                    continue
                if not CISA_ICS_CIRCUIT_BREAKER.can_execute():
                    raise CISAICSTransientError("CISA ICS circuit breaker opened mid-run — aborting before push")
                stats["pending_fetched" if pending_ref else "attempted"] += 1
                try:
                    data = self._get(self.base_url + path).json()
                except (
                    requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.HTTPError,  # includes CISAICSTransientError after retries
                    ValueError,  # JSON decode error
                ) as e:
                    consecutive_failures += 1
                    logger.warning(f"CISA ICS: fetch failed for {path}: {type(e).__name__}: {e}")
                    if pending_ref:
                        stats["pending_failed"] += 1
                        record_failures.append(
                            {
                                "record_ref": pending_ref,
                                "reason": f"the advisory could not be fetched ({type(e).__name__})",
                                "permanent": False,
                            }
                        )
                    else:
                        stats["fetch_failed"] += 1
                        # The record waits on report_pending: a baseline sets no cursor, and the look-back of the
                        # run after it may not reach this advisory again. On a baseline only an advisory whose file
                        # name dates it inside the window (a record on the list is written whatever its date).
                        published = path_published_date(path)
                        if cutoff is None or published is None or published >= cutoff:
                            record_failures.append(
                                {
                                    "record_ref": report_records.format_record_ref(
                                        SOURCE_ID, _listed_record_key(path).upper()
                                    ),
                                    "reason": f"the advisory could not be fetched ({type(e).__name__})",
                                    "permanent": False,
                                }
                            )
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
                    logger.warning(f"CISA ICS: malformed advisory skipped — {e}")
                    if pending_ref:
                        stats["pending_failed"] += 1
                        record_failures.append(
                            {"record_ref": pending_ref, "reason": "the advisory is malformed", "permanent": False}
                        )
                    else:
                        stats["malformed"] += 1
                    continue
                record: Optional[Dict[str, Any]] = None
                failure: Optional[Dict[str, Any]] = None
                record_ref = report_records.format_record_ref(SOURCE_ID, _advisory_parts(data, path)[3])
                try:
                    record = self.parse_advisory_record(data, path)
                except ValueError as e:
                    logger.warning(f"CISA ICS: the report record of {record_ref} could not be built: {e}")
                    failure = {"record_ref": record_ref, "reason": "the record could not be built", "permanent": False}
                if pending_ref:
                    self._keep_record(records, record_failures, record, failure)
                    continue
                stats["parsed_ok"] += 1
                stats["skipped_vulns"] += skipped
                if cutoff is not None:
                    # The window applies to the advisory (its record and its items) by its initial release date.
                    initial = _parse_dt(_iso_utc(_advisory_parts(data, path)[2].get("initial_release_date")))
                    if initial is not None and initial < cutoff:
                        stats["outside_window"] += 1
                        # A record on report_pending is written whatever its date: an earlier run collected it.
                        if record_ref in pending_refs:
                            self._keep_record(records, record_failures, record, failure)
                        continue
                self._keep_record(records, record_failures, record, failure)
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

            stats["records"] = len(records)
            logger.info(
                f"[OK] CISA ICS: {len(processed)} CVE items and {len(records)} report records from "
                f"{stats['parsed_ok']} advisories (attempted={stats['attempted']}, "
                f"fetch_failed={stats['fetch_failed']}, malformed={stats['malformed']}, "
                f"outside_window={stats['outside_window']}, skipped_vulns={stats['skipped_vulns']}, "
                f"pending_fetched={stats['pending_fetched']}, pending_failed={stats['pending_failed']}, "
                f"pending_not_listed={stats['pending_not_listed']})"
            )
            self.last_records = [records[ref] for ref in sorted(records)]

            if not push_to_misp:
                return processed

            if not processed:
                # 2026-11-07: the records before the return of a run without items, so an advisory that names no CVE
                # still gets its record.
                report_counts, unsaved = self._push_records(self.last_records, record_failures)
                hold_cursor_for_records = bool(unsaved)
                st = self._return_status(True, 0, failed=0)
                st["stats"] = dict(stats)
                st["report_counts"] = report_counts
                # Same gate as the push path below (Bugbot on PR #136): an advisory that failed to
                # fetch must stay in front of the cursor, or a later file's timestamp moves the
                # cursor past it and it is never retried until it changes again.
                if (
                    not baseline
                    and processed_max_ts
                    and stats.get("fetch_failed", 0) == 0
                    and not hold_cursor_for_records
                ):
                    self._advance_cursor(processed_max_ts)
                elif not baseline and processed_max_ts:
                    logger.warning(
                        "CISA ICS: cursor NOT advanced on empty run (fetch failures=%s, records neither in MISP nor "
                        "on report_pending=%s) — will retry next run",
                        stats.get("fetch_failed", 0),
                        len(unsaved),
                    )
                return st

            success, failed = self.misp_writer.push_items(processed)
            if success > 0:
                logger.info(f"[OK] CISA ICS: Successfully pushed {success} items to MISP")
            if failed > 0:
                logger.warning(f"[WARN] CISA ICS: Failed to push {failed} items to MISP")
            # 2026-11-07: the records after the CVE items. MISP answers each item batch with the whole event, every
            # report included (live check L6), so records written first would come back with every batch.
            report_counts, unsaved = self._push_records(self.last_records, record_failures)
            hold_cursor_for_records = bool(unsaved)

            st = status_after_misp_push(SOURCE_ID, len(processed), success, failed)
            st["circuit_breaker_state"] = CISA_ICS_CIRCUIT_BREAKER.state.name
            st["stats"] = dict(stats)
            st["report_counts"] = report_counts
            # Cursor advances only after a CLEAN push (mirrors the OTX / MITRE cursors).
            # 2026-10 review fix: a failed fetch must not be skipped by the cursor moving past it —
            # advance only when every selected advisory was fetched and pushed cleanly. 2026-11-07: a record whose
            # push failed is kept on report_pending and does not hold the cursor; one that is neither in MISP nor
            # saved on that list does.
            if (
                not baseline
                and failed == 0
                and stats.get("fetch_failed", 0) == 0
                and not hold_cursor_for_records
                and processed_max_ts
            ):
                self._advance_cursor(processed_max_ts)
            elif not baseline and processed_max_ts:
                logger.warning(
                    "CISA ICS: cursor NOT advanced (push failures=%s, fetch failures=%s, records neither in MISP nor "
                    "on report_pending=%s) — will retry next run",
                    failed,
                    stats.get("fetch_failed", 0),
                    len(unsaved),
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
    # Report records (2026-11-07)
    # ------------------------------------------------------------------

    def _pending_paths(self, selected: List[str]) -> Tuple[Dict[str, str], List[str], Set[str]]:
        """The advisories to read for the records on ``report_pending``: ``({path: record_ref}, [record_ref, ...]
        the listing does not name, {every record_ref considered})``. Up to ``REPORT_PENDING_PER_RUN`` records,
        those tried longest ago first (``report_records.pending_record_refs``); a record whose advisory the run
        reads anyway (*selected*) needs no path of its own, and its record is written even outside the baseline's
        window. A record whose advisory the listing does not name is a failed try (logged at WARNING with its
        reference); a listing without a row names nothing, so it leaves every entry untouched and untried. A list
        that cannot be read is logged and gives nothing."""
        try:
            refs = report_records.pending_record_refs(report_records.SOURCE_CISA_ICS)
        except Exception as exc:  # noqa: BLE001 - an unreadable list must not stop the collection
            logger.warning(
                "[REPORT-PENDING] CISA ICS: report_pending could not be read (%s: %s)", type(exc).__name__, exc
            )
            return {}, [], set()
        if refs and not self._listing:
            logger.warning(
                "[REPORT-PENDING] CISA ICS: the listing gave no advisory: the %d record(s) on report_pending are left "
                "untouched",
                len(refs),
            )
            return {}, [], set()
        chosen = set(selected)
        paths: Dict[str, str] = {}
        not_listed: List[str] = []
        considered = refs[: max(0, REPORT_PENDING_PER_RUN)]
        for ref in considered:
            path = self._listing.get(ref.split(":", 1)[1].lower())
            if path is None:
                not_listed.append(ref)
            elif path not in chosen and path not in paths:
                paths[path] = ref
        if paths or not_listed:
            logger.info(
                "[REPORT-PENDING] CISA ICS: %d of %d record(s) on report_pending: %d advisory file(s) read for their "
                "records, %d not listed (a failed try each)",
                len(considered),
                len(refs),
                len(paths),
                len(not_listed),
            )
        if not_listed:
            logger.warning(
                "[REPORT-PENDING] CISA ICS: the listing does not name the advisory of %d record(s) on report_pending: "
                "%s",
                len(not_listed),
                ", ".join(not_listed[:50]) + (" ..." if len(not_listed) > 50 else ""),
            )
        return paths, not_listed, set(considered)

    def _push_records(
        self, records: List[Dict[str, Any]], failures: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], Set[str]]:
        """Write *records* with ``MISPWriter.push_reports``, ``REPORT_BATCH`` at a time, and keep those whose push
        failed or was not tried on ``report_pending`` (``report_records.note_report_push`` after each batch, which
        also feeds its gauges and names the records given up). *failures*: records the run could not build or
        read (failed; permanent ones leave the list), settled with the first batch. The writer's parent-DAG
        liveness callback and task end (``task_ends_at``) bound each push; once a push leaves records untried, the
        later batches are not pushed and count as untried for the same reason. A run without records still
        settles the list once.

        Returns the run's ``report_counts`` and the record references that are neither in MISP nor saved on the
        list (a save failed: the batch and every later one; ERROR ``[REPORT-PENDING]``)."""
        counts: Dict[str, Any] = {
            "records": len(records),
            **{key: 0 for key in REPORT_COUNT_KEYS},
            "pending": 0,
            "given_up": 0,
            "pending_saved": True,
        }
        counts["reports_failed"] += sum(1 for f in failures if not f.get("permanent"))
        writer = self.misp_writer
        stop_reason: Optional[str] = None
        batches = [records[i : i + REPORT_BATCH] for i in range(0, len(records), REPORT_BATCH)] or [[]]
        for position, batch in enumerate(batches):
            stats: Dict[str, Any] = {"settled": [], "failed": list(failures) if position == 0 else [], "skipped": []}
            if batch and stop_reason is not None:
                stats["skipped"] = [{"record_ref": r["record_ref"], "reason": stop_reason} for r in batch]
                counts["reports_skipped"] += len(batch)
            elif batch:
                pushed = writer.push_reports(report_records.SOURCE_CISA_ICS, batch)
                for key in ("settled", "failed", "skipped"):
                    stats[key] = [*(pushed.get(key) or []), *stats[key]]
                for key in REPORT_COUNT_KEYS:
                    counts[key] += int(pushed.get(key) or 0)
                if pushed.get("skipped"):
                    stop_reason = str(pushed["skipped"][0].get("reason") or "the push of the records stopped")
            try:
                settled = report_records.note_report_push(report_records.SOURCE_CISA_ICS, stats)
            except Exception as exc:  # noqa: BLE001 - the outcome is logged and holds the cursor
                done = set(stats["settled"]) | {f.get("record_ref") for f in stats["failed"] if f.get("permanent")}
                unsaved = {
                    r["record_ref"] for later in batches[position:] for r in later if r["record_ref"] not in done
                }
                if position == 0:
                    unsaved |= {f["record_ref"] for f in failures if not f.get("permanent")}
                left = sum(len(later) for later in batches[position + 1 :])
                counts["reports_skipped"] += left
                counts["pending_saved"] = False
                logger.error(
                    "[REPORT-PENDING] CISA ICS: report_pending could not be saved (%s: %s): %d record(s) are neither "
                    "in MISP nor on the list%s; the cursor does not pass their advisories (refs: %s)",
                    type(exc).__name__,
                    exc,
                    len(unsaved),
                    f", {left} of them not pushed" if left else "",
                    ", ".join(sorted(unsaved)[:50]) + (" ..." if len(unsaved) > 50 else ""),
                )
                self._log_report_counts(counts)
                return counts, unsaved
            counts["pending"] = len(settled.entries)
            counts["given_up"] += len(settled.given_up)
        self._log_report_counts(counts)
        return counts, set()

    @staticmethod
    def _keep_record(
        records: Dict[str, Dict[str, Any]],
        failures: List[Dict[str, Any]],
        record: Optional[Dict[str, Any]],
        failure: Optional[Dict[str, Any]],
    ) -> None:
        """The run writes *record*, or lists *failure* (the record could not be built) on report_pending."""
        if record is not None:
            records[record["record_ref"]] = record
        elif failure is not None:
            failures.append(failure)

    @staticmethod
    def _log_report_counts(counts: Dict[str, Any]) -> None:
        logger.log(
            logging.WARNING
            if counts["reports_failed"] or counts["reports_skipped"] or counts["pending"] or not counts["pending_saved"]
            else logging.INFO,
            "[REPORTS] CISA ICS: %d advisory record(s) this run: %d added, %d updated, %d unchanged, %d deleted in "
            "MISP, %d failed, %d not tried; %d record(s) on report_pending after the run, %d given up",
            counts["records"],
            counts["reports_added"],
            counts["reports_updated"],
            counts["reports_unchanged"],
            counts["reports_deleted_in_misp"],
            counts["reports_failed"],
            counts["reports_skipped"],
            counts["pending"],
            counts["given_up"],
        )

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
