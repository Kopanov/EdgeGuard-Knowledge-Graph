"""Report records: one MISP Event Report per source record (schema ``edgeguard.report.v1``).

A *report record* holds what one source record says, as the source says it: an AlienVault OTX pulse
(graph label ``ThreatReport``) or a CISA ICS CSAF advisory (graph label ``VulnerabilityAdvisory``). MISP
keeps one Event Report per record in the source's day event (``MISPWriter.push_reports``); the
MISP → Neo4j sync reads it back (later work). This module is the shared, network-free part:

* the record schema v1 and its normalisation (``build_record``, ``otx_pulse_record``): types, caps on list
  sizes and string lengths, characters MISP cannot store removed, lists de-duplicated and sorted, the
  indicator list capped at ``EDGEGUARD_REPORT_MAX_INDICATORS`` in (type, value) order with the exact
  total kept in ``indicator_count``;
* the digest (``compute_digest``): SHA-256 of the canonical JSON of the normalised source facts. Derived
  judgements (zones, canonical actors, country codes) are not in the record; the sync derives them, so a
  change of the derivation rules never changes a digest or rewrites MISP;
* the Event Report content (``render_content`` / ``parse_content``): the description in a code fence
  longer than any backtick run it holds, then the sentinel line ``<!-- edgeguard:report-meta v1 -->``
  and exactly one fenced JSON block (the *meta block*: every field but the description, the digest and
  a self-digest) to the end of the content;
* the report uuid (``report_uuid``): ``node_identity.compute_node_uuid(label, {"record_ref": ...})``, so
  the MISP report uuid, the graph node uuid and the STIX ``report--<uuid>`` id are one value;
* the MISP-side values of a report: its name (``report_name``), distribution (``report_distribution``),
  tags (``report_tags``), the TLP that gates it (``gating_tlp``) and the event names it may live in
  (``report_event_info_pattern``);
* the ``report_pending`` list (``note_report_push``, ``update_report_pending``): per source, the records
  whose push failed, kept in the collector's incremental state on baselines and scheduled runs until a
  push settles them or they are given up (``EDGEGUARD_REPORT_PENDING_MAX_DAYS``, ``[REPORT-GAVE-UP]``).

docs/MISP_SOURCES.md, "Report records (Event Reports)", describes the format and the writer's flow.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

SCHEMA = "edgeguard.report.v1"
SENTINEL = "<!-- edgeguard:report-meta v1 -->"
# The heading between the description and the sentinel line, for a reader of the report in MISP's UI.
META_HEADING = "## EdgeGuard record"

SOURCE_OTX = "alienvault_otx"
SOURCE_CISA_ICS = "cisa_ics"
# The graph label of each source's records.
REPORT_LABELS: Dict[str, str] = {SOURCE_OTX: "ThreatReport", SOURCE_CISA_ICS: "VulnerabilityAdvisory"}
REPORT_SOURCES: Tuple[str, ...] = tuple(REPORT_LABELS)
# The key of each source's collector in the incremental state (``baseline_checkpoint``): the
# ``report_pending`` list lives beside that collector's cursor.
_STATE_SOURCES: Dict[str, str] = {SOURCE_OTX: "otx", SOURCE_CISA_ICS: "cisa_ics"}

# TLP levels a record can state (MISP's ``tlp`` taxonomy, TLP 1.0 and 2.0) and those a report is
# restricted at: an amber or red record gets MISP distribution 0 ("Your organisation only"; the events
# have distribution 1, which every organisation on the MISP reads), and a record that states no known
# level counts as amber.
TLP_LEVELS: Tuple[str, ...] = ("white", "clear", "green", "amber", "amber+strict", "red")
RESTRICTED_TLP = frozenset({"amber", "amber+strict", "red"})
UNKNOWN_TLP_GATES_AS = "amber"
DISTRIBUTION_INHERIT_EVENT = 5
DISTRIBUTION_OWN_ORGANISATION = 0

# MISP stores ``EventReport.name`` in varchar(255), counted in characters; 256 answered HTTP 500 on
# MISP 2.5.50 with strict SQL (live check L8, 2026-11-07).
REPORT_NAME_MAX_CHARS = 255
# Suffix of the companion event that takes new records when the day event is above the writer's split
# limit (``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE``): ``EdgeGuard-<source>-<date>-reports``.
REPORT_EVENT_SUFFIX = "-reports"

# The hard bound of the indicator list (``EDGEGUARD_REPORT_MAX_INDICATORS`` is clamped to it). A reader
# accepts any list up to it, so a record written under a larger setting still reads.
INDICATORS_HARD_MAX = 20000

# Safety caps of the meta block. They bound what one record can put into MISP and sit well above the real
# records: an OTX description is at most 1,024 characters at the source; the 1,389 CISA ICS advisories of
# 2024-2026 (read 2026-11-07) give at most 85 distinct remediations and 644 affected products for one CVE
# (ICSA-26-113-03, ICSA-24-235-03), 497 products and 486 CVEs for one advisory (ICSA-24-193-05,
# ICSA-25-226-07), a vulnerability summary of 3,998 characters as the record holds it (4,102 with the source's
# CRLF line ends), a product name of 219 characters and a record of about 940 KB (ICSA-26-295-11). A list
# item longer than its cap is left out, never cut (a cut name or URL would be another value); a text longer
# than its cap is cut at a word end; a list longer than its item cap keeps its first items in sort order, and
# ``list_cuts`` names such a list so the caller can log it. The graph's own caps (summary 500, title 255, ...)
# are applied by the sync.
DESCRIPTION_MAX_CHARS = 1_000_000
TITLE_MAX_CHARS = 2000
URL_MAX_CHARS = 2048
NAME_MAX_CHARS = 200
_ID_MAX_CHARS = 200
_ATTACK_ID_MAX_CHARS = 32
_INDICATOR_TYPE_MAX_CHARS = 64
_INDICATOR_VALUE_MAX_CHARS = 4096
_CVE_SUMMARY_MAX_CHARS = 20000
_REMEDIATION_CATEGORY_MAX_CHARS = 64
_REMEDIATION_DETAILS_MAX_CHARS = 8000
_PRODUCT_MAX_CHARS = 300
_CWE_NAME_MAX_CHARS = 300
_MAX_CWES = 20
_MAX_REMEDIATIONS = 500
_MAX_AFFECTED_PRODUCTS = 5000
_MAX_VULNERABILITIES = 1000
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE_ID_RE = re.compile(r"^CWE-\d+$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------- #
# Field schema
# --------------------------------------------------------------------------- #
#
# Each field: (kind, options). Kinds: "id" (required record id), "text" (one line, cut at a word end),
# "block" (multi-line text, cut at a word end), "url" (left out above its cap), "iso" (ISO 8601 in UTC),
# "int" (whole number >= 0), "tlp" (a known level), "texts" (list of one-line texts), "urls", "cves",
# "pairs" (indicator pairs), "count" (indicator_count) and "vulns" (CISA ICS per-CVE entries). A scalar the
# source does not give is None (the description ""), a list the source does not give is empty.
_COMMON_FIELDS: Tuple[Tuple[str, str, Dict[str, int]], ...] = (
    ("record_id", "id", {"max_chars": _ID_MAX_CHARS}),
    ("url", "url", {"max_chars": URL_MAX_CHARS}),
    ("title", "text", {"max_chars": TITLE_MAX_CHARS}),
    ("description", "block", {"max_chars": DESCRIPTION_MAX_CHARS}),
    ("published", "iso", {}),
    ("last_modified", "iso", {}),
    ("revision", "int", {}),
    ("tlp", "tlp", {}),
)

_SOURCE_FIELDS: Dict[str, Tuple[Tuple[str, str, Dict[str, int]], ...]] = {
    # An OTX pulse as the subscribed list (``tlp``) and the answer by id (``TLP``) give it. ``author`` is
    # ``author_name``; ``tags`` and ``references`` keep OTX's names (the sync stores them as
    # ``report_tags`` and ``reference_urls``); ``cve_ids`` are the values of the pulse's CVE indicators.
    SOURCE_OTX: (
        ("author", "text", {"max_chars": NAME_MAX_CHARS}),
        ("industries", "texts", {"max_items": 200, "max_chars": NAME_MAX_CHARS}),
        ("targeted_countries", "texts", {"max_items": 300, "max_chars": NAME_MAX_CHARS}),
        ("tags", "texts", {"max_items": 500, "max_chars": NAME_MAX_CHARS}),
        ("references", "urls", {"max_items": 500, "max_chars": URL_MAX_CHARS}),
        ("adversary", "text", {"max_chars": 500}),
        ("malware_families", "texts", {"max_items": 500, "max_chars": NAME_MAX_CHARS}),
        ("attack_ids", "texts", {"max_items": 1000, "max_chars": _ATTACK_ID_MAX_CHARS}),
        ("cve_ids", "cves", {"max_items": 5000}),
        ("indicators", "pairs", {}),
        ("indicator_count", "count", {}),
    ),
    # A CISA ICS CSAF advisory (``cisa_ics_collector.parse_advisory_record``). ``kind`` is ICSA or ICSMA;
    # ``revision`` is the number of ``tracking.revision_history`` entries and ``version`` is ``tracking.version``
    # as given (a whole number, or a version such as ``1.0.1``: 72 of the 1,389 advisories of 2024-2026 read on
    # 2026-11-07, where the whole numbers always equalled the count); ``deployment_sectors`` and
    # ``deployment_countries`` are the names the document notes list, ``vendor_headquarters`` the text of its
    # note(s); ``vulnerabilities`` holds one entry per CVE.
    SOURCE_CISA_ICS: (
        ("publisher", "text", {"max_chars": NAME_MAX_CHARS}),
        ("kind", "text", {"max_chars": 16}),
        ("csaf_url", "url", {"max_chars": URL_MAX_CHARS}),
        ("vendors", "texts", {"max_items": 100, "max_chars": NAME_MAX_CHARS}),
        ("products", "texts", {"max_items": 2000, "max_chars": _PRODUCT_MAX_CHARS}),
        ("deployment_sectors", "texts", {"max_items": 100, "max_chars": NAME_MAX_CHARS}),
        ("deployment_countries", "texts", {"max_items": 300, "max_chars": NAME_MAX_CHARS}),
        ("vendor_headquarters", "text", {"max_chars": NAME_MAX_CHARS}),
        ("cve_ids", "cves", {"max_items": 5000}),
        ("version", "text", {"max_chars": 32}),
        ("vulnerabilities", "vulns", {}),
    ),
}

# Keys of a record that are not source fields: the schema name, the source, the record reference and the
# digest. The meta block adds ``self_digest``.
_IDENTITY_KEYS = ("schema", "source", "record_ref")
_DERIVED_KEYS = ("digest",)


def record_fields(source: str) -> Tuple[str, ...]:
    """The source fields of a *source* record, in their order (``ValueError`` for another source)."""
    return tuple(name for name, _kind, _opts in _fields_of(source))


def _fields_of(source: str) -> Tuple[Tuple[str, str, Dict[str, int]], ...]:
    if source not in _SOURCE_FIELDS:
        raise ValueError(f"no report records for source {source!r} (known: {', '.join(REPORT_SOURCES)})")
    return _COMMON_FIELDS + _SOURCE_FIELDS[source]


def report_label(source: str) -> str:
    """The graph label of *source*'s records (``ValueError`` for another source)."""
    if source not in REPORT_LABELS:
        raise ValueError(f"no report records for source {source!r} (known: {', '.join(REPORT_SOURCES)})")
    return REPORT_LABELS[source]


def format_record_ref(source: str, record_id: str) -> str:
    """``"<source>:<record id>"``: the exact ``source_refs`` string of the record (``source_registry.format_source_ref``)."""
    from source_registry import format_source_ref

    ref = format_source_ref(source, record_id)
    if not ref:
        raise ValueError(f"record of {source!r} without a record id")
    return ref


# --------------------------------------------------------------------------- #
# Value normalisation
# --------------------------------------------------------------------------- #


def strip_unstorable(text: str) -> str:
    """*text* without the characters MISP cannot store or JSON cannot carry: those outside the Basic
    Multilingual Plane (4-byte UTF-8, as ``misp_writer._strip_non_bmp`` drops them; a utf8mb3 column
    fails or cuts at them), lone surrogates and NUL."""
    return "".join(ch for ch in text if ord(ch) <= 0xFFFF and not 0xD800 <= ord(ch) <= 0xDFFF and ch != "\x00")


def _line_text(value: Any) -> str:
    """A one-line text: unstorable characters removed, control and line-separator characters as spaces,
    runs of whitespace as one space, trimmed; ``""`` for a value that is not a string."""
    if not isinstance(value, str):
        return ""
    text = strip_unstorable(value)
    text = "".join(" " if unicodedata.category(ch) in ("Cc", "Zl", "Zp") else ch for ch in text)
    return " ".join(text.split())


def _block_text(value: Any) -> str:
    """A multi-line text: unstorable characters removed, line ends as ``\\n``, control characters other
    than ``\\n`` and ``\\t`` removed, trimmed; ``""`` for a value that is not a string."""
    if not isinstance(value, str):
        return ""
    text = strip_unstorable(value).replace("\r\n", "\n").replace("\r", "\n")
    text = "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch) != "Cc")
    return text.strip()


def cut_at_word_end(text: str, max_chars: int) -> str:
    """*text* when it has at most *max_chars* characters, otherwise its longest start of at most
    *max_chars* characters that ends at a word end (before whitespace), trailing whitespace removed; a
    first word longer than *max_chars* is cut at *max_chars*. Never appends an ellipsis."""
    if len(text) <= max_chars:
        return text
    if text[max_chars].isspace():
        return text[:max_chars].rstrip()
    head = text[:max_chars]
    cut = max((head.rfind(ch) for ch in (" ", "\n", "\t")), default=-1)
    return head[:cut].rstrip() if cut > 0 and head[:cut].strip() else head


def _iso(value: Any) -> Optional[str]:
    """An ISO 8601 date-time as UTC ``isoformat`` (a value without a zone is UTC), or None."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        raw = value.strip()
        if raw[-1] in "Zz":
            raw = raw[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    try:
        return dt.astimezone(timezone.utc).isoformat()
    except (OverflowError, ValueError):  # a date at the end of the calendar whose zone puts it past year 9999
        return None


def iso_datetime(value: Any) -> Optional[datetime]:
    """*value* (ISO 8601, a value without a zone is UTC) as an aware UTC datetime, or None."""
    text = _iso(value)
    return datetime.fromisoformat(text) if text else None


def _int(value: Any) -> Optional[int]:
    """A whole number >= 0 (an int, or a string of digits), or None. A bool is no number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def tlp_level(value: Any) -> Optional[str]:
    """The TLP level *value* names (case and a ``tlp:`` prefix ignored), or None for no known level."""
    if not isinstance(value, str):
        return None
    level = value.strip().lower()
    if level.startswith("tlp:"):
        level = level[4:].strip()
    return level if level in TLP_LEVELS else None


def _url(value: Any, max_chars: int) -> Optional[str]:
    text = _line_text(value)
    if not text or len(text) > max_chars:
        return None
    return text


def _texts(values: Any, max_items: int, max_chars: int) -> List[str]:
    """One-line texts, empty ones and those longer than *max_chars* left out, de-duplicated, sorted, the
    first *max_items*."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    kept = {text for text in (_line_text(v) for v in values) if text and len(text) <= max_chars}
    return sorted(kept)[:max_items]


def _urls(values: Any, max_items: int, max_chars: int) -> List[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    kept = {url for url in (_url(v, max_chars) for v in values) if url}
    return sorted(kept)[:max_items]


def _cve(value: Any) -> Optional[str]:
    text = _line_text(value).upper()
    return text if _CVE_ID_RE.match(text) else None


def _cves(values: Any, max_items: int) -> List[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    return sorted({cve for cve in (_cve(v) for v in values) if cve})[:max_items]


def _pairs(values: Any) -> List[List[str]]:
    """Distinct ``[misp_type, value]`` pairs in (type, value) order. A pair whose value is empty, holds a
    character MISP cannot store (the writer never stores such a value) or is longer than 4,096 characters
    is left out; type and value are trimmed and otherwise kept as given."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    kept = set()
    for pair in values:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        attr_type, value = pair
        if not isinstance(attr_type, str) or not isinstance(value, str):
            continue
        attr_type, value = _line_text(attr_type), value.strip()
        if not attr_type or len(attr_type) > _INDICATOR_TYPE_MAX_CHARS:
            continue
        if not value or len(value) > _INDICATOR_VALUE_MAX_CHARS or strip_unstorable(value) != value:
            continue
        kept.add((attr_type, value))
    return [list(pair) for pair in sorted(kept)]


def _remediations(values: Any, max_items: Optional[int] = None) -> List[Dict[str, str]]:
    """Remediation entries ``{"category", "details"}``, one per distinct pair, sorted, the first *max_items*
    (default ``_MAX_REMEDIATIONS``)."""
    if not isinstance(values, (list, tuple)):
        return []
    kept = {}
    for entry in values:
        if not isinstance(entry, Mapping):
            continue
        category = _line_text(entry.get("category"))
        if not category or len(category) > _REMEDIATION_CATEGORY_MAX_CHARS:
            continue
        details = cut_at_word_end(_block_text(entry.get("details")), _REMEDIATION_DETAILS_MAX_CHARS)
        kept[(category, details)] = {"category": category, "details": details}
    return [kept[key] for key in sorted(kept)][: _MAX_REMEDIATIONS if max_items is None else max_items]


def _cwes(values: Any, max_items: Optional[int] = None) -> List[Dict[str, Optional[str]]]:
    """CWE entries ``{"id": "CWE-<n>", "name": <the advisory's name or None>}``: an entry without a valid id is
    left out, a name longer than 300 characters is None; one entry per id (of several names, the first in sort
    order, so the order given does not matter), sorted by id number, the first *max_items* (default 20)."""
    if not isinstance(values, (list, tuple)):
        return []
    kept: Dict[str, Optional[str]] = {}
    for entry in values:
        if not isinstance(entry, Mapping):
            continue
        cwe_id = _line_text(entry.get("id")).upper()
        if not _CWE_ID_RE.match(cwe_id):
            continue
        name = _line_text(entry.get("name"))
        name_or_none = name if name and len(name) <= _CWE_NAME_MAX_CHARS else None
        given = kept.get(cwe_id)
        if cwe_id not in kept or (name_or_none is not None and (given is None or name_or_none < given)):
            kept[cwe_id] = name_or_none
    ordered = sorted(kept, key=lambda c: (int(c[4:]), c))
    return [{"id": cwe_id, "name": kept[cwe_id]} for cwe_id in ordered][: _MAX_CWES if max_items is None else max_items]


_VULN_KEYS = ("cve_id", "summary", "remediations", "affected_products", "cwes")


def _vulns(values: Any, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
    """CISA ICS per-CVE entries: ``cve_id``, the vulnerability's ``summary`` note, its ``remediations``
    (CSAF ``category`` and ``details``), its ``affected_products`` and its ``cwes`` (``id`` and ``name``,
    ``_cwes``); an entry without a valid CVE id is left out, an entry with another key raises ``ValueError``;
    sorted by CVE id (then by content), the first *max_items* (default 1,000)."""
    if not isinstance(values, (list, tuple)):
        return []
    kept: Dict[str, Dict[str, Any]] = {}
    for entry in values:
        if not isinstance(entry, Mapping):
            continue
        unknown = set(entry) - set(_VULN_KEYS)
        if unknown:
            raise ValueError(f"unknown keys in a vulnerability entry: {sorted(unknown)}")
        cve = _cve(entry.get("cve_id"))
        if not cve:
            continue
        clean = {
            "cve_id": cve,
            "summary": cut_at_word_end(_block_text(entry.get("summary")), _CVE_SUMMARY_MAX_CHARS),
            "remediations": _remediations(entry.get("remediations")),
            "affected_products": _texts(entry.get("affected_products"), _MAX_AFFECTED_PRODUCTS, _PRODUCT_MAX_CHARS),
            "cwes": _cwes(entry.get("cwes")),
        }
        kept[_canonical_json(clean)] = clean
    ordered = [kept[key] for key in sorted(kept, key=lambda k: (kept[k]["cve_id"], k))]
    return ordered[: _MAX_VULNERABILITIES if max_items is None else max_items]


def _normalise_value(kind: str, value: Any, opts: Dict[str, int], max_indicators: int) -> Any:
    if kind == "id":
        text = _line_text(value)
        if len(text) > opts["max_chars"]:
            raise ValueError(f"record id longer than {opts['max_chars']} characters")
        return text
    if kind == "text":
        return cut_at_word_end(_line_text(value), opts["max_chars"]) or None
    if kind == "block":
        return cut_at_word_end(_block_text(value), opts["max_chars"])
    if kind == "url":
        return _url(value, opts["max_chars"])
    if kind == "iso":
        return _iso(value)
    if kind == "int":
        return _int(value)
    if kind == "tlp":
        return tlp_level(value)
    if kind == "texts":
        return _texts(value, opts["max_items"], opts["max_chars"])
    if kind == "urls":
        return _urls(value, opts["max_items"], opts["max_chars"])
    if kind == "cves":
        return _cves(value, opts["max_items"])
    if kind == "pairs":
        return _pairs(value)[:max_indicators]
    if kind == "vulns":
        return _vulns(value)
    raise AssertionError(f"unknown field kind {kind!r}")  # pragma: no cover - the schema is fixed


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_sha256(content: str) -> str:
    """SHA-256 (hex) of an Event Report content as MISP stores it (UTF-8)."""
    return _sha256(content)


def max_indicators_setting() -> int:
    """``EDGEGUARD_REPORT_MAX_INDICATORS`` (``config.report_max_indicators``), at most ``INDICATORS_HARD_MAX``."""
    from config import report_max_indicators

    return max(0, min(INDICATORS_HARD_MAX, report_max_indicators()))


def build_record(source: str, fields: Mapping[str, Any], *, max_indicators: Optional[int] = None) -> Dict[str, Any]:
    """The normalised record of *source* (``alienvault_otx`` or ``cisa_ics``) from *fields*.

    *fields* holds the source fields (``record_fields(source)``); a missing field is empty (None, ``""``
    or ``[]``), an unknown one raises ``ValueError``. ``schema``, ``source``, ``record_ref`` and ``digest``
    may be present (a record given again): the first three must match, the digest is computed anew.
    ``record_id`` is required. Values are normalised as the module docstring says; the indicator list
    keeps the first *max_indicators* pairs (default ``EDGEGUARD_REPORT_MAX_INDICATORS``) in (type, value)
    order, and ``indicator_count`` is the number given, at least the number of distinct pairs before the
    cap. The result has every field of the source, ``schema``, ``source``, ``record_ref`` and ``digest``.
    """
    return _normalise(source, fields, max_indicators=max_indicators)


def _normalise(source: str, fields: Mapping[str, Any], *, max_indicators: Optional[int]) -> Dict[str, Any]:
    spec = _fields_of(source)
    if not isinstance(fields, Mapping):
        raise ValueError("record fields must be a mapping")
    known = {name for name, _kind, _opts in spec} | set(_IDENTITY_KEYS) | set(_DERIVED_KEYS)
    unknown = sorted(set(fields) - known)
    if unknown:
        raise ValueError(f"unknown record fields for {source}: {unknown}")
    if "schema" in fields and fields["schema"] != SCHEMA:
        raise ValueError(f"record schema {fields['schema']!r} is not {SCHEMA}")
    if "source" in fields and fields["source"] != source:
        raise ValueError(f"record of {fields['source']!r} given as {source!r}")
    cap = max_indicators_setting() if max_indicators is None else max(0, min(INDICATORS_HARD_MAX, max_indicators))
    record: Dict[str, Any] = {"schema": SCHEMA, "source": source}
    values: Dict[str, Any] = {}
    for name, kind, opts in spec:
        if kind == "count":
            continue
        values[name] = _normalise_value(kind, fields.get(name), opts, cap)
    if not values["record_id"]:
        raise ValueError(f"record of {source!r} without a record id")
    record["record_id"] = values["record_id"]
    record["record_ref"] = format_record_ref(source, values["record_id"])
    if "record_ref" in fields and fields["record_ref"] != record["record_ref"]:
        raise ValueError(f"record_ref {fields['record_ref']!r} does not belong to record id {values['record_id']!r}")
    for name, kind, _opts in spec:
        if name == "record_id":
            continue
        if kind == "count":
            given = _int(fields.get(name))
            distinct = len(_pairs(fields.get("indicators")))
            values[name] = max(given or 0, distinct)
        record[name] = values[name]
    record["digest"] = compute_digest(record)
    return record


def list_cuts(source: str, fields: Mapping[str, Any]) -> List[Tuple[str, int, int]]:
    """The lists of *fields* that ``build_record`` cuts at their item cap, as ``(list, kept, given)``: *given* is
    the number of distinct items after normalisation, *kept* the cap. A CISA ICS per-CVE list is named
    ``vulnerabilities[<CVE id>].<list>``. The indicator list is not named: ``indicator_count`` keeps its total.
    Empty for a record within every cap. Call it with fields ``build_record`` accepts."""
    cuts: List[Tuple[str, int, int]] = []
    unbounded = sys.maxsize
    for name, kind, opts in _fields_of(source):
        value = fields.get(name)
        if kind == "texts":
            given, cap = len(_texts(value, unbounded, opts["max_chars"])), opts["max_items"]
        elif kind == "urls":
            given, cap = len(_urls(value, unbounded, opts["max_chars"])), opts["max_items"]
        elif kind == "cves":
            given, cap = len(_cves(value, unbounded)), opts["max_items"]
        elif kind == "vulns":
            given, cap = len(_vulns(value, unbounded)), _MAX_VULNERABILITIES
            for entry in value if isinstance(value, (list, tuple)) else []:
                cve = _cve(entry.get("cve_id")) if isinstance(entry, Mapping) else None
                if not cve:
                    continue
                for part, count, part_cap in (
                    ("remediations", len(_remediations(entry.get("remediations"), unbounded)), _MAX_REMEDIATIONS),
                    (
                        "affected_products",
                        len(_texts(entry.get("affected_products"), unbounded, _PRODUCT_MAX_CHARS)),
                        _MAX_AFFECTED_PRODUCTS,
                    ),
                    ("cwes", len(_cwes(entry.get("cwes"), unbounded)), _MAX_CWES),
                ):
                    if count > part_cap:
                        cuts.append((f"vulnerabilities[{cve}].{part}", part_cap, count))
        else:
            continue
        if given > cap:
            cuts.append((name, cap, given))
    return cuts


def compute_digest(record: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the canonical JSON (sorted keys, ASCII, no spaces) of the record's source facts:
    every key but ``schema``, ``digest`` and ``self_digest``, the description included."""
    facts = {k: v for k, v in record.items() if k not in ("schema", "digest", "self_digest")}
    return _sha256(_canonical_json(facts))


def report_uuid(record_ref: str, label: str) -> str:
    """The uuid of the report of *record_ref*: ``node_identity.compute_node_uuid(label, {"record_ref":
    record_ref})``, lower case. It is the graph node's uuid and the uuid of its STIX ``report--<uuid>``;
    both labels map to the STIX type ``report``, so it depends on *record_ref* only."""
    from node_identity import compute_node_uuid

    if label not in REPORT_LABELS.values():
        raise ValueError(f"{label!r} is not a report label")
    return compute_node_uuid(label, {"record_ref": record_ref}).lower()


def record_uuid(record: Mapping[str, Any]) -> str:
    """``report_uuid`` of a record."""
    return report_uuid(record["record_ref"], report_label(record["source"]))


def gating_tlp(record: Mapping[str, Any]) -> str:
    """The TLP the report is written and gated at: the record's level, or amber when it states none."""
    return tlp_level(record.get("tlp")) or UNKNOWN_TLP_GATES_AS


def report_distribution(record: Mapping[str, Any]) -> int:
    """MISP distribution of the report: 0 ("Your organisation only") for amber and red, else 5 ("Inherit
    event"; EdgeGuard's events have distribution 1, "This community only")."""
    return DISTRIBUTION_OWN_ORGANISATION if gating_tlp(record) in RESTRICTED_TLP else DISTRIBUTION_INHERIT_EVENT


def report_tags(record: Mapping[str, Any], source_tag: str) -> List[Dict[str, str]]:
    """The tags of a new report: ``EdgeGuard``, the source tag and ``tlp:<gating level>``."""
    return [{"name": "EdgeGuard"}, {"name": source_tag}, {"name": f"tlp:{gating_tlp(record)}"}]


def report_name(record: Mapping[str, Any]) -> str:
    """The report's MISP name: the title (else the record reference), cut at a word end to at most 255
    characters (``EventReport.name`` is varchar(255)); the full title stays in the meta block."""
    title = _line_text(record.get("title")) or _line_text(record.get("record_ref"))
    return cut_at_word_end(title, REPORT_NAME_MAX_CHARS)


def report_event_info_pattern(source: str) -> "re.Pattern[str]":
    """The ``Event.info`` of an event a record of *source* may live in: ``EdgeGuard-<source>-<date>``, a
    part (``-part<N>``) or the companion event (``-reports``)."""
    return re.compile(rf"^EdgeGuard-{re.escape(source)}-\d{{4}}-\d{{2}}-\d{{2}}(-part\d+|{REPORT_EVENT_SUFFIX})?$")


# --------------------------------------------------------------------------- #
# OTX pulse → record
# --------------------------------------------------------------------------- #


OTX_PULSE_URL = "https://otx.alienvault.com/pulse/{}"


def _otx_family_name(entry: Any) -> str:
    """The name of one ``malware_families`` entry: a string, or an object named by ``name``,
    ``display_name`` or ``id`` (the rule of ``otx_collector._family_entry_name``)."""
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, Mapping):
        for key in ("name", "display_name", "id"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _otx_attack_id(entry: Any) -> str:
    """One ``attack_ids`` entry: a string, or an object's ``id``."""
    if isinstance(entry, Mapping):
        entry = entry.get("id")
    return entry.strip() if isinstance(entry, str) else ""


def otx_pulse_record(
    pulse: Mapping[str, Any],
    indicators: Iterable[Sequence[str]],
    *,
    indicator_count: Optional[int] = None,
    max_indicators: Optional[int] = None,
) -> Dict[str, Any]:
    """The record of an OTX pulse as ``/api/v1/pulses/subscribed`` or ``/api/v1/pulses/{id}`` answers it.

    *indicators*: the pulse's indicators as the MISP attributes the writer stores them, ``(misp type,
    value)`` pairs (a CVE is ``("vulnerability", "CVE-...")``); ``cve_ids`` are the values of the
    ``vulnerability`` pairs. *indicator_count*: the pulse's indicator total when the caller knows it is
    larger than the pairs given. The two answers differ in keys (``tlp`` / ``TLP``; ``author`` only by id;
    ``extract_source`` and ``more_indicators`` only in the list), not in the facts read here, so both give
    the same record and digest.
    """
    pairs = [list(p) for p in indicators]
    pulse_id = pulse.get("id")
    author = pulse.get("author_name")
    if not (isinstance(author, str) and author.strip()) and isinstance(pulse.get("author"), Mapping):
        author = pulse["author"].get("username")
    tlp: Optional[str] = None
    for key in ("tlp", "TLP"):
        stated = pulse.get(key)
        if isinstance(stated, str) and stated.strip():
            tlp = stated
            break
    fields = {
        "record_id": pulse_id if isinstance(pulse_id, str) else "",
        "url": OTX_PULSE_URL.format(pulse_id) if isinstance(pulse_id, str) and pulse_id.strip() else None,
        "title": pulse.get("name"),
        "description": pulse.get("description"),
        "published": pulse.get("created"),
        "last_modified": pulse.get("modified"),
        "revision": pulse.get("revision"),
        "tlp": tlp,
        "author": author,
        "industries": pulse.get("industries"),
        "targeted_countries": pulse.get("targeted_countries"),
        "tags": pulse.get("tags"),
        "references": pulse.get("references"),
        "adversary": pulse.get("adversary"),
        "malware_families": [_otx_family_name(e) for e in _as_list(pulse.get("malware_families"))],
        "attack_ids": [_otx_attack_id(e) for e in _as_list(pulse.get("attack_ids"))],
        "cve_ids": [p[1] for p in pairs if len(p) == 2 and p[0] == "vulnerability"],
        "indicators": pairs,
        "indicator_count": indicator_count,
    }
    return build_record(SOURCE_OTX, fields, max_indicators=max_indicators)


# --------------------------------------------------------------------------- #
# Event Report content
# --------------------------------------------------------------------------- #


def _fence_for(text: str) -> str:
    """A backtick fence longer than any run of backticks in *text* (at least three)."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def meta_block(record: Mapping[str, Any]) -> Dict[str, Any]:
    """The meta block of a record: every key but the description, with ``self_digest``, the SHA-256 of the
    canonical JSON of the block without it."""
    meta = {k: v for k, v in record.items() if k != "description"}
    meta.pop("self_digest", None)
    meta["self_digest"] = _sha256(_canonical_json(meta))
    return meta


def render_content(record: Mapping[str, Any]) -> str:
    """The Event Report content of a normalised record (``build_record``): the description in a code fence
    longer than any backtick run it holds, the heading ``## EdgeGuard record``, the sentinel line and one
    fenced JSON block (the meta block on one line, keys sorted, ASCII) to the end. A sentinel line or a
    fenced block inside the description stays inside its fence, and ``parse_content`` takes the last
    sentinel, so neither can stand for the record."""
    if record.get("schema") != SCHEMA or not isinstance(record.get("digest"), str):
        raise ValueError("render_content takes a record build_record made")
    description = record.get("description") or ""
    if not isinstance(description, str):
        raise ValueError("record description must be a string")
    fence = _fence_for(description)
    meta = json.dumps(meta_block(record), sort_keys=True, ensure_ascii=True)
    return f"{fence}\n{description}\n{fence}\n\n{META_HEADING}\n\n{SENTINEL}\n```json\n{meta}\n```\n"


_TAIL_RE = re.compile(r"\A```json\n([^\n]*)\n```\n?\Z")


def parse_content(content: Any) -> Optional[Tuple[str, Dict[str, Any]]]:
    """``(description, meta)`` of an Event Report content written by ``render_content``, or None.

    The meta block is the JSON block after the **last** sentinel line, which must be followed by exactly
    one fenced ``json`` block and nothing else. Before the sentinel come the heading and the description's
    fence: its closing line, and the nearest line above it equal to it, enclose the description (text
    before the opening fence, such as a summary MISP prepended, is ignored). The block must be in the
    normal form ``build_record`` gives (types, caps, sorted lists, every field of its source and no other),
    name schema v1, and carry a self-digest that matches it. The description is returned as stored; it is
    not checked against the block's ``digest`` (MISP users may edit it).
    """
    if not isinstance(content, str):
        return None
    marker = f"\n{SENTINEL}\n"
    at = content.rfind(marker)
    if at < 0:
        return None
    tail = _TAIL_RE.match(content[at + len(marker) :])
    if tail is None:
        return None
    try:
        meta = json.loads(tail.group(1))
    except (ValueError, RecursionError):  # RecursionError: a block nested some 10,000 levels deep
        return None
    head = content[:at]
    heading = f"\n\n{META_HEADING}\n"
    if not head.endswith(heading):
        return None
    lines = head[: -len(heading)].split("\n")
    fence = lines[-1]
    if len(fence) < 3 or set(fence) != {"`"}:
        return None
    try:
        opening = max(i for i in range(len(lines) - 1) if lines[i] == fence)
    except ValueError:
        return None
    description = "\n".join(lines[opening + 1 : -1])
    if _fence_for(description) != fence or not valid_meta(meta, description):
        return None
    return description, meta


def valid_meta(meta: Any, description: str = "") -> bool:
    """Whether *meta* is a meta block of schema v1 in normal form with a matching self-digest."""
    if not isinstance(meta, dict) or meta.get("schema") != SCHEMA or meta.get("source") not in REPORT_SOURCES:
        return False
    self_digest = meta.get("self_digest")
    body = {k: v for k, v in meta.items() if k != "self_digest"}
    if not isinstance(self_digest, str) or self_digest != _sha256(_canonical_json(body)):
        return False
    digest = meta.get("digest")
    if not isinstance(digest, str) or not _DIGEST_RE.match(digest):
        return False
    facts = {k: v for k, v in body.items() if k != "digest"}
    expected = {name for name in record_fields(meta["source"]) if name != "description"} | set(_IDENTITY_KEYS)
    if set(facts) != expected:
        return False
    try:
        normal = _normalise(meta["source"], {**facts, "description": description}, max_indicators=INDICATORS_HARD_MAX)
    except (ValueError, TypeError):
        return False
    normal.pop("digest")
    normal.pop("description")
    return normal == facts


def record_from_content(content: Any) -> Optional[Dict[str, Any]]:
    """The record an Event Report content holds (description and meta block, without ``self_digest``), or
    None (``parse_content``). For a content written by ``render_content`` it equals the record rendered."""
    parsed = parse_content(content)
    if parsed is None:
        return None
    description, meta = parsed
    record = {k: v for k, v in meta.items() if k != "self_digest"}
    order = ["schema", "source", "record_id", "record_ref", *record_fields(meta["source"])[1:], "digest"]
    record["description"] = description
    return {key: record[key] for key in order}


def digest_matches(description: str, meta: Mapping[str, Any]) -> bool:
    """Whether the block's ``digest`` covers *description* as stored (False after an edit of the text in MISP)."""
    record = {k: v for k, v in meta.items() if k != "self_digest"}
    record["description"] = description
    return compute_digest(record) == meta.get("digest")


# --------------------------------------------------------------------------- #
# report_pending: records whose push failed
# --------------------------------------------------------------------------- #
#
# Per source, the records whose Event Report MISP does not hold as the record says, in the incremental
# state of the source's collector (``checkpoints[<otx|cisa_ics>]["incremental"]["report_pending"]``).
# The list is independent of the item retry list (``otx_retry_pulses``): a record is pushed whatever
# happened to its items, on baselines and scheduled runs alike, and ``push_reports`` never writes the
# writer's item bookkeeping. A plain baseline keeps the incremental state (``clear_checkpoint``); the
# fresh baseline's wipe clears it with MISP, which frees every report uuid (live check L12).
# Each entry: ``record_ref``, ``first_failed_at`` (UTC ISO 8601), ``attempts`` (pushes that failed),
# ``last_tried_at`` (the last push that failed; absent when the record was never tried) and
# ``last_reason`` (printable ASCII, at most 300 characters). An entry whose source record a run could not
# fetch also holds ``first_fetch_failed_at`` and ``last_fetch_failed_at`` (the fetches that failed since the
# record was last read; no push try): they order the list and give up a record whose source keeps failing.
PENDING_STATE_KEY = "report_pending"
_PENDING_REASON_MAX = 300
_GAVE_UP_PER_LINE = 50


def pending_state_source(source: str) -> str:
    """The incremental-state key whose ``report_pending`` list holds *source*'s records."""
    report_label(source)
    return _STATE_SOURCES[source]


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _reason(text: Any) -> str:
    raw = str(text or "")[:_PENDING_REASON_MAX]
    return "".join(c if c.isascii() and c.isprintable() else "?" for c in raw)


def _pending_entries(raw: Any, source: str, now: datetime) -> List[Dict[str, Any]]:
    """The stored list, copied: entries whose ``record_ref`` belongs to *source*, the first of each; a
    ``first_failed_at`` that does not read is *now*, ``attempts`` that is not a whole number 0; the fetch-failure
    times are kept when both read."""
    if not isinstance(raw, list):
        return []
    entries: List[Dict[str, Any]] = []
    seen = set()
    prefix = f"{source}:"
    for entry in raw:
        ref = entry.get("record_ref") if isinstance(entry, dict) else None
        if not isinstance(ref, str) or not ref.startswith(prefix) or len(ref) <= len(prefix) or ref in seen:
            continue
        seen.add(ref)
        kept: Dict[str, Any] = {"record_ref": ref}
        first = iso_datetime(entry.get("first_failed_at"))
        kept["first_failed_at"] = _utc_iso(first or now)
        attempts = entry.get("attempts")
        kept["attempts"] = attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0
        tried = iso_datetime(entry.get("last_tried_at"))
        if tried is not None:
            kept["last_tried_at"] = _utc_iso(tried)
        kept["last_reason"] = _reason(entry.get("last_reason"))
        first_fetch = iso_datetime(entry.get("first_fetch_failed_at"))
        last_fetch = iso_datetime(entry.get("last_fetch_failed_at"))
        if first_fetch is not None and last_fetch is not None:
            kept["first_fetch_failed_at"] = _utc_iso(first_fetch)
            kept["last_fetch_failed_at"] = _utc_iso(last_fetch)
        entries.append(kept)
    return entries


def load_report_pending(source: str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """The ``report_pending`` list of *source* as stored (copied and checked, ``_pending_entries``)."""
    from baseline_checkpoint import get_source_incremental

    now = now or datetime.now(timezone.utc)
    return _pending_entries(get_source_incremental(pending_state_source(source)).get(PENDING_STATE_KEY), source, now)


def _last_touched(entry: Mapping[str, Any]) -> datetime:
    """The later of an entry's last push try and its last failed fetch (the earliest time when neither)."""
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    times = [iso_datetime(entry.get(key)) for key in ("last_tried_at", "last_fetch_failed_at")]
    return max((t for t in times if t is not None), default=epoch)


def pending_record_refs(source: str) -> List[str]:
    """The record references on *source*'s ``report_pending`` list, those tried or fetched in vain longest ago
    first (neither first of all): a record whose source record keeps failing to be fetched goes behind the
    others, so it cannot hold them back."""
    entries = load_report_pending(source)
    entries.sort(key=lambda e: (_last_touched(e), e["record_ref"]))
    return [e["record_ref"] for e in entries]


class PendingSettled(NamedTuple):
    """The ``report_pending`` list after a push (``settle_report_pending``)."""

    entries: List[Dict[str, Any]]  # the list kept, first failure first
    added: List[str]  # records put on the list now
    cleared: List[str]  # records taken off: settled in MISP, or a permanent failure
    still: List[str]  # records that failed again and stay
    given_up: List[Dict[str, Any]]  # entries given up (failing EDGEGUARD_REPORT_PENDING_MAX_DAYS and tried since,
    # or its source record failing to be fetched for that long)


def settle_report_pending(
    entries: List[Dict[str, Any]],
    *,
    settled: Iterable[str] = (),
    failed: Iterable[Tuple[str, str]] = (),
    skipped: Iterable[Tuple[str, str]] = (),
    permanent: Iterable[str] = (),
    fetch_failed: Iterable[Tuple[str, str]] = (),
    fetched: Iterable[str] = (),
    now: datetime,
    max_days: int,
) -> PendingSettled:
    """The list after a push. *settled*: records MISP now holds as the record says (added, updated,
    unchanged, or deleted in MISP and respected): taken off. *permanent*: records that can never be written
    (a uuid in a foreign event): taken off, not added. *failed*: ``(record_ref, reason)`` of records whose
    push failed: an entry's ``attempts`` + 1 and ``last_tried_at`` *now*, or a new entry. *skipped*:
    ``(record_ref, reason)`` of records not tried (the deadline came, MISP kept failing, no day event): a new
    entry without ``last_tried_at``; an entry on the list is left as it is. *fetch_failed*: ``(record_ref,
    reason)`` of records on the list whose source record could not be fetched: ``last_fetch_failed_at`` *now*
    (``first_fetch_failed_at`` too when absent) and ``last_reason``; no try, so ``attempts`` and
    ``last_tried_at`` stay. *fetched*: records whose source record was read; a try (*failed*) also reads it.
    Either ends the entry's fetch failures. An entry first failed more than *max_days* ago is then given up when
    it was tried after that deadline, so a record waiting while no run tried it gets one try first, or when its
    source record has failed to be fetched for more than *max_days* and the last of those fetches came after
    the deadline, so a record whose source never answers does not stay on the list for ever while a fetch
    failure shorter than *max_days* gives up nothing."""
    by_ref: Dict[str, Dict[str, Any]] = {e["record_ref"]: dict(e) for e in entries}
    now_iso = _utc_iso(now)
    for ref in fetched:
        entry = by_ref.get(ref)
        if entry is not None:
            entry.pop("first_fetch_failed_at", None)
            entry.pop("last_fetch_failed_at", None)
    cleared: List[str] = []
    for ref in [*settled, *permanent]:
        if by_ref.pop(ref, None) is not None:
            cleared.append(ref)
    permanent_refs = set(permanent)
    added: List[str] = []
    still: List[str] = []
    for ref, reason in failed:
        if ref in permanent_refs:
            continue
        entry = by_ref.get(ref)
        if entry is None:
            entry = by_ref[ref] = {"record_ref": ref, "first_failed_at": now_iso, "attempts": 0}
            added.append(ref)
        elif ref not in still:
            still.append(ref)
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        entry["last_tried_at"] = now_iso
        entry["last_reason"] = _reason(reason)
        entry.pop("first_fetch_failed_at", None)
        entry.pop("last_fetch_failed_at", None)
    for ref, reason in skipped:
        if ref in permanent_refs or ref in by_ref:
            continue
        by_ref[ref] = {"record_ref": ref, "first_failed_at": now_iso, "attempts": 0, "last_reason": _reason(reason)}
        added.append(ref)
    for ref, reason in fetch_failed:
        entry = by_ref.get(ref)
        if entry is None or ref in permanent_refs:
            continue
        entry.setdefault("first_fetch_failed_at", now_iso)
        entry["last_fetch_failed_at"] = now_iso
        entry["last_reason"] = _reason(reason)
    span = timedelta(days=max(1, max_days))
    kept: List[Dict[str, Any]] = []
    given_up: List[Dict[str, Any]] = []
    for entry in sorted(by_ref.values(), key=lambda e: (e["first_failed_at"], e["record_ref"])):
        first = iso_datetime(entry["first_failed_at"]) or now
        tried = iso_datetime(entry.get("last_tried_at"))
        expired = tried is not None and min(tried, now) - span > first
        first_fetch = iso_datetime(entry.get("first_fetch_failed_at"))
        last_fetch = iso_datetime(entry.get("last_fetch_failed_at"))
        if first_fetch is not None and last_fetch is not None:
            last_fetch = min(last_fetch, now)
            expired = expired or (last_fetch - span > first and last_fetch - first_fetch > span)
        (given_up if expired else kept).append(entry)
    return PendingSettled(kept, added, cleared, still, given_up)


def _log_given_up(source: str, given_up: List[Dict[str, Any]], max_days: int) -> None:
    for start in range(0, len(given_up), _GAVE_UP_PER_LINE):
        chunk = given_up[start : start + _GAVE_UP_PER_LINE]
        logger.error(
            "[REPORT-GAVE-UP] %s: %d report record(s) given up%s (EDGEGUARD_REPORT_PENDING_MAX_DAYS=%d): MISP does "
            "not hold them as their source says, and no run pushes them again until a run collects their record: %s",
            source,
            len(given_up),
            f" ({start + 1}-{start + len(chunk)})" if len(given_up) > _GAVE_UP_PER_LINE else "",
            max_days,
            "; ".join(
                f"{e['record_ref']} (attempts {e.get('attempts', 0)}, first failed {e.get('first_failed_at')}, "
                + (
                    f"its source record not fetched since {e['first_fetch_failed_at']}, "
                    if e.get("first_fetch_failed_at")
                    else ""
                )
                + f"last reason: {e.get('last_reason') or 'unknown'})"
                for e in chunk
            ),
        )


def _record_pending_metrics(source: str, entries: List[Dict[str, Any]], given_up: int) -> None:
    """``edgeguard_report_pending_records``, ``..._oldest_failure_timestamp_seconds`` and
    ``edgeguard_report_pending_given_up_total`` (``metrics_server.record_report_pending``); a metrics failure
    is logged at DEBUG and never fails the caller."""
    try:
        from metrics_server import record_report_pending

        firsts = [iso_datetime(e.get("first_failed_at")) for e in entries]
        oldest = min((f for f in firsts if f is not None), default=None)
        record_report_pending(source, len(entries), oldest.timestamp() if oldest is not None else 0.0, given_up)
    except Exception as exc:
        logger.debug("report_pending metrics not recorded: %s", exc)


def update_report_pending(
    source: str,
    *,
    settled: Iterable[str] = (),
    failed: Iterable[Tuple[str, str]] = (),
    skipped: Iterable[Tuple[str, str]] = (),
    permanent: Iterable[str] = (),
    fetch_failed: Iterable[Tuple[str, str]] = (),
    fetched: Iterable[str] = (),
    now: Optional[datetime] = None,
) -> PendingSettled:
    """Settle *source*'s ``report_pending`` list (``settle_report_pending``) and store it in the incremental
    state of the source's collector, with ``EDGEGUARD_REPORT_PENDING_MAX_DAYS``. Records given up are named
    in ERROR ``[REPORT-GAVE-UP]`` lines; the metrics follow the list."""
    from baseline_checkpoint import update_source_incremental
    from config import report_pending_max_days

    now = now or datetime.now(timezone.utc)
    max_days = report_pending_max_days()
    entries = load_report_pending(source, now)
    result = settle_report_pending(
        entries,
        settled=list(settled),
        failed=list(failed),
        skipped=list(skipped),
        permanent=list(permanent),
        fetch_failed=list(fetch_failed),
        fetched=list(fetched),
        now=now,
        max_days=max_days,
    )
    update_source_incremental(pending_state_source(source), **{PENDING_STATE_KEY: result.entries})
    if result.given_up:
        _log_given_up(source, result.given_up, max_days)
    if result.added or result.still or result.cleared:
        logger.info(
            "[REPORT-PENDING] %s: %d record(s) on the list (%d added, %d failing again, %d cleared, %d given up)",
            source,
            len(result.entries),
            len(result.added),
            len(result.still),
            len(result.cleared),
            len(result.given_up),
        )
    _record_pending_metrics(source, result.entries, len(result.given_up))
    return result


def note_report_push(source: str, stats: Mapping[str, Any], *, now: Optional[datetime] = None) -> PendingSettled:
    """``update_report_pending`` with the outcome of ``MISPWriter.push_reports`` (its stats dict)."""
    failed = [f for f in stats.get("failed") or [] if isinstance(f, Mapping) and f.get("record_ref")]
    return update_report_pending(
        source,
        settled=[r for r in stats.get("settled") or [] if isinstance(r, str)],
        failed=[(f["record_ref"], f.get("reason") or "") for f in failed if not f.get("permanent")],
        skipped=[
            (s["record_ref"], s.get("reason") or "")
            for s in stats.get("skipped") or []
            if isinstance(s, Mapping) and s.get("record_ref")
        ],
        permanent=[f["record_ref"] for f in failed if f.get("permanent")],
        now=now,
    )
