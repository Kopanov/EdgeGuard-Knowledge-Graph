#!/usr/bin/env python3
"""
EdgeGuard - MISP Writer Module
Pushes indicators to MISP as the single point of truth
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib
import json
import logging
import math
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Sequence, Tuple, Union

import requests
import urllib3

import report_records  # noqa: E402  — report records (Event Reports), 2026-11-07
import source_registry  # noqa: E402  — single source of truth for source→MISP-tag mapping (chip 5a)
from attack_values import attack_object_id, attack_value_key, format_attack_value
from collectors.collector_utils import TransientServerError, retry_after_sleep_seconds, retry_with_backoff
from config import (
    DEFAULT_SECTOR,
    MISP_API_KEY,
    MISP_CROSS_EVENT_DEDUP,
    MISP_PREFETCH_EXISTING_ATTRS,
    MISP_URL,
    SSL_VERIFY,
    apply_misp_http_host_header,
    misp_push_max_failing_seconds,
    misp_refresh_last_seen_days,
    misp_refresh_max_per_run,
    misp_refresh_max_seconds,
    misp_report_throttle_seconds,
    otx_industry_zones,
)
from cvss_selection import cvss_rating_tag, normalize_attack_vector
from lock_files import exclusive_flock, misp_event_lock_path
from sector_evidence import report_zone_entry, report_zone_pairs

# PR-N4: Prometheus metrics for permanent-failure counter + adaptive-
# backoff trigger. Optional import so MISPWriter can run in environments
# without prometheus_client installed (CI, dev shells, dry-run).
#
# PR-N5 C7: honest-NULL violation counter joins the same optional bundle.
try:
    from metrics_server import (
        MISP_PUSH_BACKOFF_TRIGGERED as _MISP_BACKOFF_TRIGGERED,
    )
    from metrics_server import (
        MISP_PUSH_PERMANENT_FAILURES as _MISP_PUSH_PERMANENT_FAILURES,
    )

    try:
        from metrics_server import (
            MISP_HONEST_NULL_VIOLATIONS as _MISP_HONEST_NULL_VIOLATIONS,
        )
    except ImportError:
        # Older metrics_server without the PR-N5 counter — set to None so
        # the guard below degrades gracefully without breaking the PR-N4
        # metrics that ARE available.
        _MISP_HONEST_NULL_VIOLATIONS = None  # type: ignore[assignment]

    try:
        from metrics_server import (
            MISP_PUSH_STOPPED as _MISP_PUSH_STOPPED,
        )
    except ImportError:
        # Older metrics_server without the 2026-11-03 counter of stopped pushes.
        _MISP_PUSH_STOPPED = None  # type: ignore[assignment]

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False
    _MISP_PUSH_PERMANENT_FAILURES = None  # type: ignore[assignment]
    _MISP_BACKOFF_TRIGGERED = None  # type: ignore[assignment]
    _MISP_HONEST_NULL_VIOLATIONS = None  # type: ignore[assignment]
    _MISP_PUSH_STOPPED = None  # type: ignore[assignment]

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def _validate_honest_null(item: Dict[str, Any], source_hint: Optional[str] = None) -> None:
    """PR-N5 C7 (Devil's Advocate F5, audit 09) — defensive runtime
    guard for the PR-M2 honest-NULL invariant.

    **Invariant under guard:** when a source does NOT report
    ``first_seen`` / ``last_seen``, EdgeGuard stores NULL rather than
    manufacturing a wall-clock substitute. Manufacturing substitutes
    would turn ``n.source_reported_first_at`` into a lie — downstream
    consumers couldn't distinguish "source said so" from "EdgeGuard
    guessed".

    **What this guard catches:** a future collector (or a future bug
    in an existing one) that starts coercing a missing source timestamp
    to ``datetime.now(timezone.utc).isoformat()``. Pre-guard that
    corruption was invisible in the MISPWriter layer — nodes and edges
    would just carry a fresh-looking ``source_reported_first_at``
    indistinguishable from a real claim.

    **Heuristic:** ``first_seen`` / ``last_seen`` values within
    **±5 minutes of wall-clock NOW** are flagged. Real source claims
    virtually never land in that window (even an NVD CVE published
    "today" was published hours-to-days ago by the time we ingest it).
    False positives are possible (e.g. a MISP attribute created right
    now and immediately federated to us) but they're rare enough that
    a WARN is the right disposition, not an exception.

    **Action on violation:** logs a WARNING with structured context +
    emits the ``edgeguard_misp_honest_null_violation_total`` Prometheus
    counter so operators can alert on it. Does NOT raise — the point
    is detection, not breaking a live push.
    """
    from datetime import datetime, timezone

    from source_truthful_timestamps import coerce_iso

    # ±5-minute window is a heuristic tuned for "this looks wall-clock NOW-ish".
    # Real source claims are essentially never this fresh.
    _suspicious_window_sec = 300.0
    _now_epoch = datetime.now(timezone.utc).timestamp()

    # PR-N5 R2 Bugbot MED (2026-04-21): include ``last_modified`` in
    # the field list. The downstream chokepoint
    # ``_apply_source_truthful_timestamps`` reads ``last_modified`` as
    # an alias for ``last_seen`` (NVD/STIX collectors emit it under
    # this name) — so a collector that manufactures
    # ``item["last_modified"] = NOW`` but leaves ``last_seen`` unset
    # would propagate the wall-clock substitute into the MISP attribute
    # as ``last_seen`` while bypassing the honest-NULL guard entirely.
    # Adding ``"last_modified"`` to this loop closes the gap; the WARN
    # message already templates ``%s=...`` so the violation reports
    # the field as ``last_modified``, preserving the audit trail.
    for field in ("first_seen", "last_seen", "last_modified"):
        raw = item.get(field)
        if raw is None or raw == "":
            continue  # honest NULL — the desired case
        iso = coerce_iso(raw)
        if not iso:
            continue  # unparseable, let the existing pathway log
        try:
            val_epoch = datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            continue
        delta = abs(val_epoch - _now_epoch)
        if delta <= _suspicious_window_sec:
            # Looks wall-clock NOW-ish.
            source = source_hint or item.get("tag") or item.get("source") or "unknown"
            if isinstance(source, list):
                source = source[0] if source else "unknown"
            logger.warning(
                "[honest-NULL] Item %s=%r within ±%.0fs of wall-clock NOW "
                "(delta=%.0fs, source=%s, item_type=%s, value=%r). "
                "This is suspicious — real source claims are rarely that fresh. "
                "Possible causes: (1) collector manufacturing a NOW() substitute "
                "(violates PR-M2 honest-NULL invariant); (2) genuine MISP "
                "attribute federated immediately after creation (rare). "
                "If (1), check the collector's %s extraction path.",
                field,
                iso,
                _suspicious_window_sec,
                delta,
                source,
                item.get("type") or item.get("indicator_type") or "?",
                item.get("value") or item.get("cve_id") or item.get("name") or "?",
                field,
            )
            try:
                # PR-N5 R1 Bugbot LOW (2026-04-21): check the COUNTER
                # itself for None, not just ``_METRICS_AVAILABLE``. When
                # the outer ``metrics_server`` import succeeds (PR-N4
                # counters are present) but the nested PR-N5 counter
                # import fails (older metrics_server without the new
                # counter — backward-compat path), ``_METRICS_AVAILABLE``
                # stays ``True`` while ``_MISP_HONEST_NULL_VIOLATIONS``
                # stays ``None``. ``None.labels(...)`` raises
                # AttributeError — the try/except below catches it, but
                # the DEBUG log fires on EVERY violation (noisy + lies
                # about the true failure mode). Explicit None check
                # avoids the exception path entirely in that case.
                if _MISP_HONEST_NULL_VIOLATIONS is not None:
                    _MISP_HONEST_NULL_VIOLATIONS.labels(source=str(source), field=field).inc()
            except Exception as _metric_err:
                # Same non-silent pattern as the other metric guards.
                logger.debug(
                    "honest-NULL violation metric increment failed: %s",
                    _metric_err,
                    exc_info=True,
                )


# Traffic Light Protocol labels MISP's ``tlp`` taxonomy accepts (TLP 1.0 + 2.0).
_VALID_TLP = frozenset({"white", "clear", "green", "amber", "amber+strict", "red"})
# 2026-10: the ladder of ``neo4j_client._tlp_rank_case``, for merges made before an item reaches MISP.
_TLP_RANK = {"white": 1, "clear": 1, "green": 2, "amber": 3, "amber+strict": 4, "red": 5}


def _tlp_level(raw: Any) -> str:
    """The TLP level written for ``raw``: a known label (``tlp:`` prefix and case ignored),
    otherwise the deployment default ``config.EDGEGUARD_DEFAULT_TLP``."""
    from config import EDGEGUARD_DEFAULT_TLP

    level = str(raw or "").strip().lower().replace("tlp:", "")
    return level if level in _VALID_TLP else EDGEGUARD_DEFAULT_TLP


# The per-pulse copies an OTX item carries into its attribute's ``OTX_META`` block: the pulse's name, tags,
# references and targeted countries. They repeat the pulse's own text on every indicator of the pulse.
PULSE_COPY_KEYS = ("pulse_name", "pulse_tags", "pulse_references", "targeted_countries")
# The TLP levels whose pulse text may be copied onto indicators.
_PULSE_COPY_LEVELS = frozenset({"white", "clear", "green"})


def pulse_copies_allowed(pulse_tlp: Any) -> bool:
    """Whether an OTX pulse's text may be copied onto its items (``PULSE_COPY_KEYS``): only when the pulse states
    a known TLP level that is white, clear or green. Amber, amber+strict and red keep the text in the pulse's
    report record (``report_records``, MISP distribution 0); a pulse that states no known level counts as amber,
    as its report record does (``report_records.gating_tlp``)."""
    return report_records.tlp_level(pulse_tlp) in _PULSE_COPY_LEVELS


def tlp_rank(raw: Any) -> int:
    """Rank of the TLP level ``raw`` is written as (2026-10): white / clear 1, green 2, amber 3,
    amber+strict 4, red 5.

    A value outside the ladder (empty, misspelt) ranks as the deployment default it is written
    as, so it never displaces a known level that is more restrictive.
    """
    return _TLP_RANK.get(_tlp_level(raw), 0)


def _tlp_tag(item: Dict[str, Any]) -> str:
    """Return the ``tlp:<level>`` tag for an item (2026-10, fresh-baseline PR).

    The proposal commits EdgeGuard to TLP handling, but no attribute carried a TLP
    tag before this change. Every source EdgeGuard collects today is open
    (``config.EDGEGUARD_DEFAULT_TLP``, default ``white``); a source that states
    its own level (OTX pulses carry ``pulse_tlp``, or an item may set ``tlp``)
    overrides the default when the value is a known TLP label.
    """
    return f"tlp:{_tlp_level(item.get('tlp') or item.get('pulse_tlp') or '')}"


def _attack_domain(item: Dict[str, Any]) -> str:
    """ATT&CK domain of a technique / tactic item (2026-10): ``enterprise`` or ``ics``.

    The MITRE collector stamps ``attack_domain`` on every item; anything else
    (or an unknown value) is treated as Enterprise so pre-existing data keeps
    its meaning. Carried as the ``attack-domain:<domain>`` MISP tag so the sync
    can keep ICS techniques linked to ICS tactics only (9 of the 12 ICS tactic
    short names are identical to Enterprise ones).
    """
    domain = str(item.get("attack_domain") or "enterprise").strip().lower()
    return domain if domain in ("enterprise", "ics", "mobile") else "enterprise"


# 2026-10: ATT&CK marks a retired object without a successor ``x_mitre_deprecated: true``. The MITRE
# collector keeps such objects with ``deprecated: True``; the flag travels as this MISP tag and the
# sync (``run_misp_to_neo4j._extract_deprecated_tag``) sets ``n.deprecated = true`` on the node, so
# its links stay and consumers can filter. Revoked objects never reach the writer.
ATTACK_DEPRECATED_TAG = "attack-status:deprecated"


def _deprecated_tags(item: Dict[str, Any]) -> List[str]:
    """``[ATTACK_DEPRECATED_TAG]`` for an item ATT&CK deprecated, else ``[]``."""
    return [ATTACK_DEPRECATED_TAG] if item.get("deprecated") is True else []


# 2026-11-07: MISP holds the source's text; the MISP -> Neo4j sync caps what reaches the graph (``text_caps``).
# The description of a technique, tactic, group, malware or tool is written in full: after the comment's
# ``MITRE_*`` block, or as the whole comment without one. ATT&CK's longest is 4,668 characters (T1553.003,
# Enterprise ATT&CK 20.1); the bound only guards the comment column (TEXT, 64 KB) against a runaway text.
ENTITY_DESCRIPTION_MAX_CHARS = 8000
# 2026-11-07: every platform ATT&CK lists (at most 10 on one object of ATT&CK 20.1, 22 values in all), in
# ATT&CK's casing. The count bound never binds on ATT&CK; a value longer than the length bound is skipped.
_MAX_PLATFORM_TAGS = 32
_MAX_PLATFORM_CHARS = 64
# ATT&CK's own MISP galaxies (cluster value "<name> - <ATT&CK id>"), by item type. Techniques carry
# ``mitre-attack-pattern``; ATT&CK publishes no galaxy of tactics.
_ATTACK_GALAXY_BY_TYPE = {"actor": "mitre-intrusion-set", "malware": "mitre-malware", "tool": "mitre-tool"}
_ATTACK_ID_RE_BY_TYPE = {
    "actor": re.compile(r"^G\d{4}$", re.ASCII),
    "malware": re.compile(r"^S\d{4}$", re.ASCII),
    "tool": re.compile(r"^S\d{4}$", re.ASCII),
}
_ATTACK_DOMAINS = ("enterprise", "ics", "mobile")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _entity_description(item: Dict[str, Any], limit: int = ENTITY_DESCRIPTION_MAX_CHARS) -> str:
    """The item's ``description`` as MISP stores it (2026-11-07): control characters removed (as
    ``sanitize_value`` does), surrounding whitespace stripped, otherwise the source's text, markup included.

    A text over ``limit`` characters (none of ATT&CK's) is cut at its last whitespace within the limit, or at the
    limit when it holds none, with no "..." appended, and a ``[ENTITY-TEXT]`` warning gives the lengths."""
    text = item.get("description")
    if not isinstance(text, str):
        return ""
    text = _CONTROL_CHARS_RE.sub("", text).strip()
    if len(text) <= limit:
        return text
    window = text[: limit + 1]
    space = max(window.rfind(" "), window.rfind("\t"), window.rfind("\n"), window.rfind("\r"))
    out = text[:space].rstrip() if space > 0 else text[:limit]
    logger.warning(
        "[ENTITY-TEXT] %s %s: description of %d characters written as its first %d (limit %d)",
        item.get("type") or "item",
        item.get("mitre_id") or "",
        len(text),
        len(out),
        limit,
    )
    return out


def _platform_tags(item: Dict[str, Any]) -> List[str]:
    """``platform:<name>`` for every ATT&CK platform of a technique or software item, in ATT&CK's casing
    (``platform:Network Devices``, ``platform:Field Controller/RTU/PLC/IED``), de-duplicated
    case-insensitively, order kept (2026-11-07; the writer kept the first 3, lower-cased). MISP keeps the casing of
    a tag it already holds; the sync reads the values back in ATT&CK's spelling (``attack_platforms``)."""
    tags: List[str] = []
    seen: set = set()
    for platform in item.get("platforms") or []:
        if not isinstance(platform, str):
            continue
        name = " ".join(_CONTROL_CHARS_RE.sub("", platform).split())
        if not name or len(name) > _MAX_PLATFORM_CHARS or name.casefold() in seen:
            continue
        seen.add(name.casefold())
        tags.append(f"platform:{name}")
        if len(tags) == _MAX_PLATFORM_TAGS:
            break
    return tags


def _alias_tags(item: Dict[str, Any]) -> List[str]:
    """``alias:<name>`` for each of the item's ``aliases`` (at most 20, each up to 100 characters): the MISP-side
    carrier of the alias round trip for actors, malware and (2026-11-07) tools."""
    tags: List[str] = []
    for alias in (item.get("aliases") or [])[:20]:
        alias_s = sanitize_value(str(alias), max_length=100)
        if alias_s:
            tags.append(f"alias:{alias_s}")
    return tags


def _attack_domain_tags(item: Dict[str, Any]) -> List[str]:
    """``attack-domain:<domain>`` for each ATT&CK domain a group or software item lists (``attack_domains``, from
    ``x_mitre_domains``; 2026-11-07), order kept. An item without the key (any source but ATT&CK) gets none."""
    tags: List[str] = []
    for domain in item.get("attack_domains") or []:
        name = str(domain).strip().lower()
        tag = f"attack-domain:{name}"
        if name in _ATTACK_DOMAINS and tag not in tags:
            tags.append(tag)
    return tags


def _attack_galaxy_tags(item: Dict[str, Any], name: str) -> List[str]:
    """ATT&CK's own MISP galaxy cluster tag for a group, malware or tool item with an ATT&CK id (2026-11-07):
    ``misp-galaxy:mitre-intrusion-set="APT29 - G0016"``, ``misp-galaxy:mitre-malware="BlackEnergy - S0089"``,
    ``misp-galaxy:mitre-tool="Net - S0039"``. MISP attaches the cluster (ATT&CK's full card) to the attribute.
    It goes beside the community cluster tag; an item without a valid id (another source) gets none."""
    item_type = str(item.get("type") or "")
    galaxy = _ATTACK_GALAXY_BY_TYPE.get(item_type)
    attack_id = str(item.get("mitre_id") or "").strip().upper()
    if galaxy is None or not _ATTACK_ID_RE_BY_TYPE[item_type].match(attack_id) or '"' in name:
        return []
    return [f'misp-galaxy:{galaxy}="{name} - {attack_id}"']


# 2026-10 audit: the 730-day baseline is ONE collector run, so a family named in N pulses carries
# all N ids in `rids`; the earlier 32 cut every link beyond the 33rd pulse (Mirai, Cobalt Strike,
# AgentTesla appear in hundreds). MISP `comment` is TEXT (64 KB); 500 × ~27 chars ≈ 13 KB.
_MAX_REPORT_IDS = 500
# 2026-10-18: ``MITRE_USES_TECHNIQUES.ind``, the OTX pulse's own industries (a pulse lists a handful).
_MAX_INDUSTRIES = 20
_MAX_INDUSTRY_CHARS = 64
# 2026-10: an OTX_META ``pa`` entry, "family::adversary::pulse" (family and adversary up to 128
# characters each, the pulse id up to 64).
_MAX_PAIR_CHARS = 128 + 2 + 128 + 2 + 64


# Bugbot on PR #144 (High): the OTX_META / TF_META comments were hard-sliced at 4000 characters, so a
# few dozen pulse ids (or a long description) cut the JSON mid-token and the sync's json.loads
# dropped the WHOLE block — pulse_id, report_ids, families, attack_ids. Shrink list fields instead
# (longest-first, halving), then long strings, then drop optional keys; the result is always valid
# JSON. The budget stays 4000 (MISP renders comments inline); the TEXT column itself holds 64 KB.
_META_COMMENT_BUDGET = 4000
# 2026-10: ``pa`` is shrunk before ``report_ids`` and ``mf``. A pair carries its pulse, so an IOC listed
# by many pulses carried one pair per pulse and the halving cut ``report_ids`` first: 120 pulses naming
# several actors and 10 naming one kept 1 of 129 report ids and 1 of 8 families. ``pa`` holds the first
# pair of each family and adversary before the later pulses' (``_otx_meta_pairs``), so shrinking it drops
# those first; ``sap`` / ``sapn`` follow ``report_ids`` (``_fit_meta_comment``). 2026-10-18:
# ``report_stated_zones`` (the zones the later pulses' industries state) is shrunk first: it holds the
# first pulse of each zone before the others (``_report_stated_zones``), so the statement of every zone
# stays while it fits, and it follows ``report_ids`` as the marks do.
_META_SHRINK_LISTS = (
    "report_stated_zones",
    "pa",
    "report_ids",
    "mf",
    "attack_ids",
    "targeted_countries",
    "otx_industries",
    "pulse_tags",
    "pulse_references",
    "tags",
    "yara_rules",
    "sigma_rules",
    # 2026-11-07: the list-source lists of ``TF_META`` (``_TF_META_SOURCE_LISTS``), after the feed's tags:
    # the ports first, the record ids last (they name the source records).
    "ports",
    "threat_types",
    "families",
    "ioc_ids",
)
# Optional keys of the shared feed-metadata comment (``TF_META``). They are written only when
# the item carries a value and are rehydrated by the sync into the Indicator properties of the
# same name, which the REST and GraphQL APIs expose. Without them those properties stayed empty
# for every indicator that arrives through MISP (URLhaus ``url_status`` / ``last_online``,
# Feodo Tracker ``last_online``, VirusTotal ``threat_label`` / ``yara_rules`` / ``sigma_rules``).
_TF_META_OPTIONAL_STRINGS = ("url_status", "last_online", "threat_label")
_TF_META_OPTIONAL_LISTS = ("yara_rules", "sigma_rules")
_TF_META_MAX_LIST_ITEMS = 20
_TF_META_MAX_ITEM_CHARS = 200
# 2026-11-07: list-source fields of ``TF_META``, optional like the keys above (written only when the item
# carries a value) and written as the source gives them, never cut by the writer; only the comment budget
# shortens them (``_fit_meta_comment``). ``c2_status`` (Feodo Tracker); ``listing_reason`` (verbatim),
# ``listing_family`` (the family part of the reason, the list's own label, never a category word) (SSL Blacklist);
# ``ip_country_code`` (where the address is, never a targeted country) (AbuseIPDB); ``file_name``,
# ``file_md5``, ``file_sha1``, ``file_type`` (MalwareBazaar, VirusTotal); ``meaningful_name``,
# ``threat_category`` (VirusTotal).
_TF_META_SOURCE_STRINGS = (
    "c2_status",
    "listing_reason",
    "listing_family",
    "ip_country_code",
    "file_name",
    "file_md5",
    "file_sha1",
    "file_type",
    "meaningful_name",
    "threat_category",
)
# Non-negative ints: ``confidence_level`` (ThreatFox's 0-100 scale, the highest of the value's records; apart
# from the node's ``source_confidence`` and the edge's ``confidence``), ``abuse_confidence_score`` (AbuseIPDB,
# 0-100), ``file_size`` (bytes), ``detection_malicious`` / ``detection_total`` (VirusTotal engines).
_TF_META_SOURCE_INTS = (
    "confidence_level",
    "abuse_confidence_score",
    "file_size",
    "detection_malicious",
    "detection_total",
)
# Lists of every record of a value: ``ports`` (ints; ThreatFox ip:port, Feodo Tracker), ``ioc_ids``,
# ``threat_types`` (ThreatFox), ``families`` (ThreatFox, Feodo Tracker; the primary record's family first).
_TF_META_SOURCE_LISTS = ("ports", "ioc_ids", "threat_types", "families")
# Facts that change at the source after the first report. The writer never re-comments a stored attribute (a
# re-reported value only gets ``last_seen``, ``_refresh_stored_copies``), so MISP keeps the values of the
# first report for the life of the attribute; ``as_of`` records when they were read.
_TF_META_TIME_VARIANT = (
    "url_status",
    "last_online",
    "c2_status",
    "abuse_confidence_score",
    "detection_malicious",
    "detection_total",
)
_META_SHRINK_STRINGS = ("description", "pulse_name", "reference", "file_name", "meaningful_name", "listing_reason")


def _tf_meta_source_fields(indicator: Dict[str, Any]) -> Dict[str, Any]:
    """The list-source keys of ``TF_META`` an item carries (2026-11-07), in the order of the key tuples.

    Strings are stripped and kept whole; ints are kept when they are non-negative ints (not bools); a list
    keeps its distinct non-empty entries in order, ints for ``ports`` (1-65535) and strings otherwise, all of
    them: only the comment budget shortens a list (``_fit_meta_comment``, with its warning). A key without a
    usable value is left out, so no value is invented.
    """
    fields: Dict[str, Any] = {}
    for key in _TF_META_SOURCE_STRINGS:
        value = indicator.get(key)
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()
    for key in _TF_META_SOURCE_INTS:
        value = indicator.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            fields[key] = value
    for key in _TF_META_SOURCE_LISTS:
        raw = indicator.get(key)
        if not isinstance(raw, (list, tuple)):
            continue
        kept: List[Any] = []
        seen: set = set()
        for entry in raw:
            if key == "ports":
                if isinstance(entry, bool) or not isinstance(entry, int) or not 0 < entry < 65536:
                    continue
            elif isinstance(entry, str) and entry.strip():
                entry = entry.strip()
            elif isinstance(entry, int) and not isinstance(entry, bool):
                entry = str(entry)
            else:
                continue
            if entry not in seen:
                seen.add(entry)
                kept.append(entry)
        if kept:
            fields[key] = kept
    return fields


def _tf_meta_as_of() -> str:
    """``TF_META.as_of`` (2026-11-07): the time the attribute is built, ISO 8601 UTC to the second. The
    collectors push right after reading their source, so it dates the time-variant values of the report."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# 2026-10: the several-actor marks of a metadata block: ``sap`` (judged with the canonical threat-actor
# reference; the sync also stores it on the Indicator node) and ``sapn`` (judged by name because the
# reference could not be loaded; the sync uses it for its own run only).
_MARK_KEYS = ("sap", "sapn")


def _sap_within_reports(meta: Dict[str, Any], key: str, marks: Any) -> None:
    """Set ``meta[key]`` (``sap`` / ``sapn``) to the pulses of *marks* still in ``pulse_id`` + ``report_ids``
    (2026-10).

    Used only when the comment is over its budget: a mark then goes with its pulse's id, so the block keeps
    the marks of the pulse buckets the sync groups the IOC into. The sync stores every ``sap`` entry on the
    Indicator node, where step 2d reads it for the whole graph, so the mark of a pulse cut from
    ``report_ids`` is lost on this IOC; the pulse's other IOCs carry it. The key is left out when no mark
    remains; *marks* that are not a list leave ``meta`` unchanged.
    """
    if not isinstance(marks, list):
        return
    reports = {str(meta.get("pulse_id") or "")} | {str(x) for x in (meta.get("report_ids") or [])}
    kept = [x for x in marks if str(x) in reports]
    if kept:
        meta[key] = kept
    else:
        meta.pop(key, None)


def _stated_zones_within_reports(meta: Dict[str, Any]) -> None:
    """Keep the ``report_stated_zones`` entries of ``meta`` whose pulse is still in ``pulse_id`` +
    ``report_ids`` (2026-10-18), so a zone never cites a pulse the shrunk block no longer names. Used only
    when the comment is over its budget; the list may become empty while ``report_ids`` is shrunk, so that
    it takes its entries back when ``report_ids`` does, and ``_fit_meta_comment`` drops it if it stays
    empty."""
    entries = meta.get("report_stated_zones")
    if not isinstance(entries, list):
        return
    reports = {str(meta.get("pulse_id") or "")} | {str(x) for x in (meta.get("report_ids") or [])}
    meta["report_stated_zones"] = [
        e for e in entries if any(report in reports for _zone, report in report_zone_pairs([e]))
    ]


def _fit_meta_comment(prefix: str, meta: Dict[str, Any], budget: int = _META_COMMENT_BUDGET) -> str:
    """``prefix + json.dumps(meta)``, shrunk until it fits *budget* without ever breaking the JSON.

    2026-10: ``sap`` and ``sapn`` keep the marks of the pulses still in ``pulse_id`` + ``report_ids`` after
    each step (``_sap_within_reports``), so they shrink with ``report_ids``; so does ``report_stated_zones``
    (2026-10-18, ``_stated_zones_within_reports``). Halving stops at the first length
    that fits and could leave a quarter of the budget unused, so at the end each shrunk list takes back,
    from the last shrunk to the first, the longest part of what it held that still fits.
    """
    comment = prefix + json.dumps(meta, default=str)
    if len(comment) <= budget:
        return comment
    original_len = len(comment)
    original = dict(meta)
    meta = dict(meta)

    def _render() -> str:
        for mark_key in _MARK_KEYS:
            _sap_within_reports(meta, mark_key, original.get(mark_key))
        _stated_zones_within_reports(meta)
        return prefix + json.dumps(meta, default=str)

    comment = _render()
    for key in _META_SHRINK_LISTS:
        while len(comment) > budget and isinstance(meta.get(key), list) and len(meta[key]) > 1:
            meta[key] = meta[key][: max(1, len(meta[key]) // 2)]
            comment = _render()
    for key in _META_SHRINK_STRINGS:
        while len(comment) > budget and isinstance(meta.get(key), str) and len(meta[key]) > 32:
            meta[key] = meta[key][: max(32, len(meta[key]) // 2)]
            comment = _render()
    for key in _META_SHRINK_LISTS + _META_SHRINK_STRINGS:
        if len(comment) <= budget:
            break
        if key in meta:
            meta.pop(key)
            comment = _render()
    if len(comment) <= budget:
        for key in reversed(_META_SHRINK_LISTS):
            full, kept = original.get(key), meta.get(key)
            if not isinstance(full, list) or not isinstance(kept, list) or len(kept) >= len(full):
                continue
            fits, too_long = len(kept), len(full) + 1
            while too_long - fits > 1:
                mid = (fits + too_long) // 2
                meta[key] = full[:mid]
                if len(_render()) <= budget:
                    fits = mid
                else:
                    too_long = mid
            meta[key] = full[:fits]
            comment = _render()
    if meta.get("report_stated_zones") == []:
        meta.pop("report_stated_zones")
        comment = prefix + json.dumps(meta, default=str)
    logger.warning(
        "%s comment shrunk to fit MISP: %d -> %d chars (lists shortened / optional keys dropped, JSON intact)",
        prefix.rstrip(":"),
        original_len,
        len(comment),
    )
    return comment


_MAX_OTX_META_PAIRS = 50


def _otx_meta_pairs(pairs: Any) -> List[str]:
    """``OTX_META.pa``: the IOC's ``"family::adversary::pulse"`` pairs, the first pair of each family and
    adversary before the later pulses' pairs for them (2026-10), at most ``_MAX_OTX_META_PAIRS``.

    The collector folds later pulses after the first, so the first pair of a family and adversary is the
    first pulse's (family and adversary compared case-insensitively, trimmed). The same pair from N pulses
    was N entries in pulse order and crowded ``report_ids`` and ``mf`` out of the comment budget: ``pa`` is
    shrunk first and from the end (``_fit_meta_comment``), so the later pulses' pairs go before any first
    pair, and they stay while the comment fits. They keep the provenance of those pulses: an IOC shared by
    two pulses naming the same family and adversary may be the only record of the second. A pair longer
    than ``_MAX_PAIR_CHARS`` is left out, never cut: a cut pair would name another actor or another pulse.
    """
    firsts: List[str] = []
    later: List[str] = []
    seen_pairs: set = set()
    seen_keys: set = set()
    for raw in pairs or []:
        pair = str(raw) if raw else ""
        if not pair or len(pair) > _MAX_PAIR_CHARS:
            continue
        parts = [part.strip().lower() for part in pair.split("::")]
        if tuple(parts) in seen_pairs:
            continue
        seen_pairs.add(tuple(parts))
        key = tuple(parts[:2])
        if key in seen_keys:
            later.append(pair)
        else:
            seen_keys.add(key)
            firsts.append(pair)
    return (firsts + later)[:_MAX_OTX_META_PAIRS]


def _report_stated_zones(item: Dict[str, Any]) -> List[str]:
    """``OTX_META.report_stated_zones`` / ``MITRE_USES_TECHNIQUES.rsz`` (2026-10-18): the zones the later
    pulses of the run that listed the item state through their industries, as ``"<zone>|<pulse id>"``
    (``sector_evidence.report_zone_entry``), only for the pulses the block names in ``report_ids`` (the
    first ``_MAX_REPORT_IDS``), the first pulse of each zone before the other pulses of that zone, at most
    ``_MAX_REPORT_IDS`` entries. A malformed entry is left out."""
    reports = set([str(x)[:64] for x in (item.get("report_ids") or []) if x][:_MAX_REPORT_IDS])
    if not reports:
        return []
    firsts: List[str] = []
    later: List[str] = []
    zones_seen: set = set()
    for zone, report in report_zone_pairs(item.get("report_stated_zones")):
        if report[:64] not in reports:
            continue
        entry = report_zone_entry(zone, report[:64])
        if zone in zones_seen:
            later.append(entry)
        else:
            zones_seen.add(zone)
            firsts.append(entry)
    return (firsts + later)[:_MAX_REPORT_IDS]


def _cve_pulse_meta(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """The ``OTX_META`` block of a CVE an OTX pulse names (2026-10-18), ``{}`` for a CVE of no pulse.

    ``pulse_id`` (the pulse), ``report_ids`` (the other pulses of the collector run that named the CVE)
    and ``pulse_name`` (only for a white, clear or green pulse: ``pulse_copies_allowed``); the keys and bounds of
    an OTX indicator's block (``create_attribute``). No
    ``description``: the pulse's name says where the CVE was seen, not what it is.
    """
    pulse_id = str(vuln.get("pulse_id") or "").strip()[:64]
    report_ids = [str(x).strip()[:64] for x in (vuln.get("report_ids") or []) if x and str(x).strip()]
    if not pulse_id and not report_ids:
        return {}
    meta: Dict[str, Any] = {"pulse_id": pulse_id, "report_ids": report_ids[:_MAX_REPORT_IDS]}
    # 2026-11-07: the name of an amber or red pulse, or of one without a known TLP, is left out
    # (``pulse_copies_allowed``).
    pulse_name = str(vuln.get("pulse_name") or "").strip() if pulse_copies_allowed(vuln.get("pulse_tlp")) else ""
    if pulse_name:
        meta["pulse_name"] = pulse_name
    return meta


def _technique_meta(item: Dict[str, Any]) -> Dict[str, Any]:
    """Build the ``MITRE_USES_TECHNIQUES:`` JSON block for malware / actor / tool items.

    Keys (all optional; the block is omitted entirely when none applies):
      ``t``   — ``uses_techniques``: ATT&CK technique ids from MITRE's explicit
                ``uses`` relationships (the MITRE collector is the only producer).
      ``rt``  — ``reported_techniques`` (2026-10): technique ids a source *report*
                lists for the entity — today the OTX pulse ``attack_ids``. Downstream
                these become ``EMPLOYS_TECHNIQUE`` / ``IMPLEMENTS_TECHNIQUE`` edges with
                ``match_type = "otx_pulse"`` and a lower confidence than ``t``.
      ``pid`` — ``pulse_id`` (2026-10): the OTX pulse the entity came from, so the
                MISP→Neo4j sync can link items of the same report and the node can
                keep ``pulse_ids`` provenance.
      ``rids`` — ``report_ids`` (2026-10): the other pulses of the same collector run
                that named the entity (folded in by the collector's dedup), so the sync
                pairs it with the IOCs of every one of them, not only the first.
      ``m`` / ``s`` — ``uses_malware`` / ``uses_tools`` (2026-10, R6): malware names and tool
                ATT&CK ids MITRE's explicit ``uses`` relationships attach to a group, so the
                sync can write ``USES_MALWARE`` / ``USES_TOOL`` (actors only).
      ``sap`` — ``several_actor_pulses`` (2026-10): those of the entity's pulses whose
                adversaries are several actors; the sync attributes no malware from them.
      ``sapn`` — ``several_actor_pulses_by_name`` (2026-10): the same judgement made by name
                because the collector could not load the canonical threat-actor reference (the
                aliases of one actor count as several); the sync attributes no malware from them.
      ``ind`` — ``otx_industries`` (2026-10-18): the industries the OTX pulse classified itself into
                (as OTX names them), so the sync can tell the sectors the pulse states from those
                EdgeGuard inferred from its text (``sector_evidence.stated_zones``); an indicator
                carries them in ``OTX_META.otx_industries``.
      ``rsz`` — ``report_stated_zones`` (2026-10-18): the zones the industries of the pulses in ``rids``
                state, ``"<zone>|<pulse id>"`` (``_report_stated_zones``); an indicator carries them in
                ``OTX_META.report_stated_zones``.
      ``aid`` — the ATT&CK id of a MITRE group (``G0007``) or malware (``S0609``) (2026-11,
                ``attack_object_id``), so the sync can set the node's ``mitre_id`` and cite
                ``mitre_attck:<id>`` in ``source_refs``. A tool's id is in its value.
    Lists are capped so the comment stays within MISP field limits.
    """
    meta: Dict[str, Any] = {}
    attack_id = attack_object_id(str(item.get("type") or ""), item.get("mitre_id"))
    if attack_id:
        meta["aid"] = attack_id
    uses = item.get("uses_techniques") or []
    if uses:
        meta["t"] = [str(x) for x in list(uses)[:400]]
    reported = item.get("reported_techniques") or []
    if reported:
        meta["rt"] = [str(x) for x in list(reported)[:400]]
    pulse_id = item.get("pulse_id")
    if pulse_id:
        meta["pid"] = str(pulse_id)[:64]
    report_ids = [str(x)[:64] for x in (item.get("report_ids") or []) if x]
    if report_ids:
        meta["rids"] = report_ids[:_MAX_REPORT_IDS]
    for mark_key, field_name in (("sap", "several_actor_pulses"), ("sapn", "several_actor_pulses_by_name")):
        marks = [str(x)[:64] for x in (item.get(field_name) or []) if x]
        if marks:
            meta[mark_key] = marks[:_MAX_REPORT_IDS]
    industries = item.get("otx_industries")
    if isinstance(industries, (list, tuple)):
        named = [str(x).strip()[:_MAX_INDUSTRY_CHARS] for x in industries if x is not None and str(x).strip()]
        # The names the industry table maps come first, so the cap never drops a sector statement.
        named = [x for x in named if otx_industry_zones([x])] + [x for x in named if not otx_industry_zones([x])]
        if named:
            meta["ind"] = named[:_MAX_INDUSTRIES]
    stated_by_reports = _report_stated_zones(item)
    if stated_by_reports:
        meta["rsz"] = stated_by_reports
    # 2026-10 (R6): MITRE group → software ``uses`` (actors only)
    uses_malware = [str(x)[:128] for x in (item.get("uses_malware") or []) if x]
    if uses_malware:
        meta["m"] = uses_malware[:200]
    uses_tools = [str(x)[:64] for x in (item.get("uses_tools") or []) if x]
    if uses_tools:
        meta["s"] = uses_tools[:200]
    return meta


def _apply_source_truthful_timestamps(attribute: Dict[str, Any], item: Dict[str, Any]) -> None:
    """Forward the collector's ``first_seen`` / ``last_seen`` (or
    ``last_modified``) into the MISP attribute dict via the MISP
    2.4.120+ native fields.

    PR (S5) (bugbot HIGH): consolidated here to fix the
    bug where only 2 of 7 ``create_*_attribute`` methods honored the
    passthrough. Previously indicators (``87d3529``) and vulnerabilities
    (``ac25b07``) got the fix; malware, threat actors, techniques,
    tactics, and tools silently dropped their source-truthful
    timestamps at the MISPWriter handoff. MITRE is the primary
    affected source — every MITRE ATT&CK SDO carries a canonical
    ``created`` timestamp, which the collector mapped into
    ``item["first_seen"]`` but which was then discarded here.

    PR (S5) (post-merge audit — converged finding from
    bugbot MED / Cross-Checker F5 / Red Team #6 / Bug Hunter #1/#5 /
    Logic Tracker #6): the previous ``isinstance(str)`` gate silently
    dropped THREE real-world scenarios:
    1. VirusTotal's ``first_submission_date`` is an **int** epoch —
       collector passes it straight through, `isinstance(str)` False,
       dropped → entire VT source-truthful path broken.
    2. ``datetime`` objects (from e.g. ``stix2.utils.STIXdatetime`` or
       any future collector using structured parsing) — dropped.
    3. Date-only strings like CISA's ``"2024-03-15"`` — passed the
       string gate but Neo4j's Cypher ``datetime()`` then rejected
       them, crashing the UNWIND batch. The ``coerce_iso`` helper was
       hardened to normalize these to ``"2024-03-15T00:00:00+00:00"``
       on the READ path, but the WRITE path (here) bypassed it.

    Fix: use the canonical ``coerce_iso`` helper from
    ``source_truthful_timestamps``. It handles None, empty string,
    Unix int/float epoch, datetime objects, date-only strings
    (normalized to ISO with UTC midnight), and full ISO — returning
    ``None`` for unparseable / empty inputs. If the result is a
    non-empty string, we set it on the MISP attribute; otherwise the
    field is intentionally omitted (PyMISP rejects empty strings).
    """
    # Lazy import to avoid a potential circular dependency (the
    # source_truthful_timestamps module lives at src/ root; this
    # collector module is under src/collectors/).
    from source_truthful_timestamps import coerce_iso, iso_before

    # PR-N5 C7 (audit 09): runtime honest-NULL invariant check.
    # Detects collectors that manufacture wall-clock-NOW substitutes
    # instead of passing NULL through when the source is silent. See
    # ``_validate_honest_null`` docstring for heuristic + rationale.
    # Runs BEFORE the coerce_iso calls below so the raw item state
    # is observed (the coerce helper could normalize differently).
    _validate_honest_null(item)

    first_seen = coerce_iso(item.get("first_seen"))
    # last_modified (NVD / STIX) is accepted as an alias for last_seen.
    last_seen = coerce_iso(item.get("last_seen")) or coerce_iso(item.get("last_modified"))
    if first_seen and last_seen and iso_before(last_seen, first_seen):
        # MISP rejects an attribute whose last_seen precedes its first_seen, and a rejected
        # attribute counts against the collector's push success rate. The pair is inconsistent
        # source data: keep the first-seen claim, drop the last-seen one.
        logger.debug(
            "Dropping last_seen %s earlier than first_seen %s for %s",
            last_seen,
            first_seen,
            sanitize_value(str(item.get("value", "")), max_length=80),
        )
        last_seen = None
    if first_seen:
        attribute["first_seen"] = first_seen
    if last_seen:
        attribute["last_seen"] = last_seen


def _consistent_last_seen(item: Dict[str, Any]) -> Any:
    """``item["last_seen"]`` for the metadata comment, or ``""`` when it precedes ``first_seen``.

    ``_apply_source_truthful_timestamps`` omits such a value from the attribute's native field;
    the comment must not keep it, or the sync's comment fallback would bring it back.
    """
    from source_truthful_timestamps import coerce_iso, iso_before

    raw = item.get("last_seen", "")
    if raw and iso_before(coerce_iso(raw), coerce_iso(item.get("first_seen"))):
        return ""
    return raw


def _resolve_vulnerability_cve_id_for_misp(item: Dict) -> Optional[str]:
    """
    Same rules as ``neo4j_client.resolve_vulnerability_cve_id`` (keep in sync).

    MISP vulnerability attributes often only have ``value`` (CVE id), not ``cve_id``.
    """
    cve_id = item.get("cve_id")
    if cve_id is not None and str(cve_id).strip():
        return str(cve_id).strip().upper()
    if item.get("type") == "vulnerability":
        val = item.get("value")
        if val is not None and str(val).strip():
            return str(val).strip().upper()
    return None


# 2026-10: the fields each ``MISPWriter.create_*_attribute`` needs non-empty after
# ``sanitize_value``; without them it returns None, and ``push_items`` names the field in the
# reason it logs for the items it could not convert.
_CONVERSION_REQUIRES: Dict[str, str] = {
    "indicator": "value",
    "vulnerability": "cve_id",
    "malware": "name",
    "actor": "name",
    "technique": "mitre_id or name",
    "tactic": "mitre_id or name",
    "tool": "mitre_id or name",
}

# 2026-10: the share of a source's items in one ``push_items`` call that must fail conversion
# before those items count as failed pushes. Below it they are only reported (the ``[CONVERT]``
# line and ``stats["items_not_converted"]``); a source all of whose items fail conversion always
# counts them as failed.
#
# Why 0.5. Items that cannot be converted have two causes. A defect in a single record (one OTX
# pulse with a malformed CVE reference) drops that record's item and nothing else. A change in the
# source's payload that the collector no longer reads drops every item of the kind it affects, on
# every record: for a source of one item kind (the indicator feeds; NVD, CISA KEV and CISA ICS,
# which deliver vulnerabilities) that is every item, for OTX and MITRE ATT&CK the share of that
# kind. The threshold must lie far above the share one bad record has in a small incremental
# window, because a counted failure keeps the source's cursor or ETag (MITRE ATT&CK, CISA ICS, the
# cursor an NVD baseline seeds) or, for OTX, puts the pulse of each counted item on the retry list
# (``MISPWriter.last_push_unstored_items``; 2026-11-02), so a later run reads the same record again and
# fails again.
# At 0.5 one bad item fails a push only when the source has at most two items in it, and the cursor
# moves at the first run whose window holds three or more; a payload change that breaks most of a
# source's items still fails the run. A value such as 0.05 (the complement of the default
# ``EDGEGUARD_MISP_MIN_SUCCESS_RATE``) would fail every push in which one bad item is among at most
# 20 items of its source, and keep the cursor until a window held 21. The price of 0.5: a payload
# change that breaks only a minority kind of a mixed source (for example OTX's CVE references) is
# reported on every run but does not fail it.
CONVERT_FAILED_MIN_SHARE = 0.5


class MispTransientError(TransientServerError):
    """Raised manually for HTTP 5xx from MISP so @retry_with_backoff can catch
    it selectively. Inheriting from ``collector_utils.TransientServerError``
    (a subclass of ``requests.exceptions.HTTPError``) means the shared retry
    decorator in ``collector_utils.py`` retries this class by name, without
    having to widen its catch clause to all ``HTTPError`` values. 4xx errors
    and any other ``HTTPError`` raised by ``response.raise_for_status()``
    stay permanent."""


class MispLookupError(Exception):
    """The event lookup (``/events/restSearch``) answered with a non-transient failure.

    Raised instead of returning an empty result: an empty result means "no such event" and leads
    to event creation, which after a failed lookup could duplicate a same-day event that exists.
    """


# 2026-10: the event lookup pages through ``/events/restSearch``. MISP filters on ``eventinfo`` only
# from 2.4.177; an older MISP ignores the filter and answers the events of the whole store, so the
# lookup reads pages until a row carries the exact event name or a page comes back short. The cap
# bounds that walk (40 x 500 event headers); reaching it fails the lookup instead of creating an
# event that may already exist beyond the cap.
EVENT_LOOKUP_PAGE_SIZE = 500
EVENT_LOOKUP_MAX_PAGES = 40


# Let @retry_with_backoff on _get_or_create_event / _push_batch retry these (must re-raise, not swallow).
# MispTransientError is a TransientServerError subclass, which is also in the
# decorator's catch tuple in collector_utils.retry_with_backoff.
_TRANSIENT_HTTP_ERRORS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ReadTimeout,
    requests.exceptions.ChunkedEncodingError,
    MispTransientError,
)

# 2026-11-03: the cap on the time one ``push_items`` call goes on while MISP keeps failing
# (``config.misp_push_max_failing_seconds``). A failing streak starts at the start of the first request of the push
# that fails (a batch answered HTTP 429 or 5xx, a timeout or a connection error, a failed attempt of an event or part
# lookup) and covers what follows it: the lookups after a 5xx, the back-off, ``Retry-After`` and cooldown waits, and
# the requests that fail again. A batch ``_push_batch`` returns from (stored, refused with HTTP 4xx, partly stored)
# ends it, and so does the group's event lookup before the batches when it returns; the next failure starts a new
# streak with the whole cap. Successful requests and the throttle pause between batches never start one, so time
# alone never stops a push; within a streak its time is wall time, the throttle pauses between its failing batches
# included. The cap is checked before each batch, before a group of a push of several sources and before each
# retry (``_misp_retry_gives_up``), never by cutting a request short (a read timeout limits each wait for data, not
# the whole answer). The lookups after a 5xx get timeouts of at most the time left (``_stored_after_server_error``),
# and a cooldown that would reach the cap is not slept. The day's event lookup, the lookups of later event parts and
# a new part's creation (made after the last check before its first batch) stop retrying at the cap but keep their
# full timeouts; the listings (no retries) and the refresh of re-reported indicators are not limited by it. So a MISP
# that answers slowly can keep a push going past the cap, most of all through the parts of a large day
# (``_event_split_above``). The writer keeps the cap of the call in
# ``_misp_push_failing_cap`` (seconds; 0 or unset:
# no cap), the start of the streak in ``_misp_push_failing_since`` (``time.monotonic()``; unset: none) and, for a
# writer given its task's end (``task_ends_at``: the baseline's and the scheduled OTX and CISA ICS runs'),
# ``_misp_push_failing_end_by``; all are read with ``getattr``
# defaults that mean no cap, because many tests build the writer without ``__init__`` and ``_push_batch`` is also
# called outside a push.

# A writer given its task's end gives a failing streak at most the time until this long before the task's
# ``execution_timeout`` ends (at least ``PUSH_FAILING_FLOOR_SEC``), so a push it stops lets the collector return its
# status before Airflow kills the task (a killed task saves nothing). It leaves room for a batch request in flight
# whose answer comes within its timeouts and for the summary; a streak that starts in the task's last minutes, an
# answer that keeps arriving slowly, and the requests the cap does not limit (above) can still reach the task's end.
PUSH_TASK_END_MARGIN_SEC = 600.0
# The least cap a streak gets near its task's end: a few attempts, so one failed request does not stop a push.
PUSH_FAILING_FLOOR_SEC = 60.0
_PUSH_CAP_SETTING = "EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC"
_PUSH_CAP_SETTING_BASELINE = "EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE"


def _is_seconds(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _failing_streak(writer: Any, failed_attempt_started: Optional[float] = None) -> Optional[Tuple[float, float]]:
    """The cap of *writer*'s failing streak and the seconds it has lasted (2026-11-03), or None when no cap
    applies or, without *failed_attempt_started*, no streak is on. *failed_attempt_started*: the
    ``time.monotonic()`` at which a request that failed started; when no streak is on, the streak starts there. The
    cap is the push's (``_misp_push_failing_cap``); for a writer given its task's end it is at most the time from the
    streak's start to ``_misp_push_failing_end_by`` (the task's end less ``PUSH_TASK_END_MARGIN_SEC``), and at least
    ``PUSH_FAILING_FLOOR_SEC``. The clock is read only while a streak is on."""
    cap = getattr(writer, "_misp_push_failing_cap", None)
    if not _is_seconds(cap) or cap <= 0:
        return None
    since = getattr(writer, "_misp_push_failing_since", None)
    if not _is_seconds(since):
        if failed_attempt_started is None:
            return None
        since = failed_attempt_started
        writer._misp_push_failing_since = since
    end_by = getattr(writer, "_misp_push_failing_end_by", None)
    if _is_seconds(end_by):
        cap = min(cap, max(PUSH_FAILING_FLOOR_SEC, end_by - since))
    return cap, time.monotonic() - since


def _push_cap_text(writer: Any, cap: float) -> str:
    """The setting behind the cap *cap* of *writer*'s streak, for the log lines (2026-11-03)."""
    setting = getattr(writer, "_misp_push_failing_setting", None) or _PUSH_CAP_SETTING
    value = getattr(writer, "_misp_push_failing_cap", None)
    text = f"{setting}={value:g}" if _is_seconds(value) else setting
    if _is_seconds(value) and cap < value:
        text += f"; {cap:.0f}s to {PUSH_TASK_END_MARGIN_SEC:.0f}s before the task's end"
    return text


def _misp_retry_gives_up(args: tuple, attempt_started: float, delay: float) -> Optional[str]:
    """``retry_with_backoff``'s *give_up* for the writer's requests (2026-11-03): no retry when its delay would reach
    the cap of the push's failing streak (``_failing_streak``), which the failed attempt starts when none is on. The
    decorator then re-raises the attempt's error, as after the last attempt."""
    writer = args[0] if args else None
    streak = _failing_streak(writer, attempt_started)
    if streak is None:
        return None
    cap, failing_for = streak
    if failing_for + delay < cap:
        return None
    return (
        f"MISP has kept failing for {failing_for:.0f}s, and the retry in {delay:.0f}s would reach the push's cap of "
        f"{cap:.0f}s on failure time ({_push_cap_text(writer, cap)})"
    )


class KnownAttribute(NamedTuple):
    """An attribute MISP already holds (``MISPWriter.index_source_attributes``)."""

    uuid: str
    event_id: str
    # Digest of the ``NVD_META`` comment (``nvd_meta_digest``); None when the comment has none.
    meta_digest: Optional[str]
    tags: Tuple[str, ...]
    # 2026-10 (KEV revisions): the attribute's MISP ``timestamp`` (epoch seconds; None when the listing
    # row has none), whether it sits in an event EdgeGuard created (``Event.info`` starts with
    # ``EdgeGuard-``), and its parsed ``NVD_META`` (only with ``keep_meta``, for the logs of an edit).
    written: Optional[float] = None
    own_event: bool = True
    meta: Optional[Dict[str, Any]] = None


_NVD_META_PREFIX = "NVD_META:"
# ``NVD_META`` lists whose order carries no meaning. They are compared sorted: before 2026-10 the
# NVD collector built them from sets, so a stored copy can list the same values in another order.
_NVD_META_UNORDERED_KEYS = ("cwe", "ref_tags", "cpe_type", "affected_products")
# Tag families that describe NVD's current score: an update replaces them.
_REPLACED_VULNERABILITY_TAG_PREFIXES = ("severity:", "cvss:")
# 2026-10: a KEV edit also replaces the tag ``ransomware:known``, the only ransomware tag EdgeGuard writes.
# CISA can revert an entry's ransomware use from Known to Unknown, and the KEV collector is the only writer
# of that tag, so the stored copy then keeps CISA's latest statement instead of a stale tag. Only that tag:
# any other ``ransomware:`` tag (a machine tag of MISP's ``ransomware`` taxonomy an analyst attached, such
# as ``ransomware:type="crypto-ransomware"``) is not EdgeGuard's and is left alone.
KEV_REPLACED_TAGS = ("severity:", "cvss:", "ransomware:known")


# Bounds of the CISA ICS provenance in ``NVD_META`` (2026-10-16): a CVE is named by a few advisories,
# and CISA lists 16 critical-infrastructure sectors.
_MAX_ADVISORY_IDS = 50
_MAX_ADVISORY_ID_CHARS = 32
_MAX_ICS_SECTORS = 20
_MAX_ICS_SECTOR_CHARS = 100
# A zone name (``config.VALID_ZONES``); each advisory maps to at most the three tracked sectors.
_MAX_ADVISORY_ZONES = 10
_MAX_ADVISORY_ZONE_CHARS = 32


def _bounded_strings(values: Any, max_items: int, max_chars: int) -> List[str]:
    """The non-empty strings of a list, each trimmed and cut to ``max_chars``, de-duplicated in order, at
    most ``max_items``; ``[]`` for anything that is not a list."""
    if not isinstance(values, (list, tuple)):
        return []
    out: List[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()[:max_chars]
        if text and text not in out:
            out.append(text)
        if len(out) >= max_items:
            break
    return out


def _bounded_advisory_zones(value: Any, advisory_ids: Sequence[str]) -> Dict[str, List[str]]:
    """The zones of each advisory (2026-10-16), for the advisories kept in ``advisory_ids`` only, keys and
    zones sorted; ``{}`` for anything that is not such a map."""
    if not isinstance(value, dict):
        return {}
    out: Dict[str, List[str]] = {}
    for advisory in sorted(set(advisory_ids)):
        zones = value.get(advisory)
        if isinstance(zones, (list, tuple)):
            out[advisory] = sorted(_bounded_strings(list(zones), _MAX_ADVISORY_ZONES, _MAX_ADVISORY_ZONE_CHARS))
    return out


def nvd_meta_digest(meta: Dict[str, Any]) -> str:
    """Digest of an ``NVD_META`` payload, for telling a changed CVE from an unchanged one.

    ``last_modified`` is left out: NVD moves it for changes to data EdgeGuard does not store
    (translations, CNA product data), and such a change needs no MISP edit. CISA's SSVC decision
    points (``ssvc``, 2026-10) are stored, so a change to them is a change of the CVE. ``attack_vector``
    is left out too (2026-10): it is derived from the CVSS payloads, which the digest covers, and
    copies written before 2026-10 hold a letter (``N``) or ``UNKNOWN`` where the item now has NVD's
    word, so every stored copy would have looked changed. A key whose value is empty (``""``,
    ``None``, ``[]``, ``{}``) counts as absent, so a key a later EdgeGuard version adds with an
    empty value does not make every stored copy look changed.
    """
    data = normalised_nvd_meta(meta)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def normalised_nvd_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    """An ``NVD_META`` payload as ``nvd_meta_digest`` compares it: ``last_modified`` and ``attack_vector``
    left out, keys with empty values dropped, the unordered lists sorted. Shared with the logs of an
    edit (``vulnerability_update.meta_changed_keys``, 2026-10), so the keys an edit names are exactly
    the ones that changed its digest."""
    data = json.loads(json.dumps(meta, default=str))
    data.pop("last_modified", None)
    data.pop("attack_vector", None)
    data = {key: value for key, value in data.items() if value not in ("", None, [], {})}
    for key in _NVD_META_UNORDERED_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            data[key] = sorted(value, key=lambda v: json.dumps(v, sort_keys=True))
    return data


def nvd_meta_of_comment(comment: Any) -> Optional[Dict[str, Any]]:
    """The parsed ``NVD_META`` of an attribute comment, or None when it carries none or it is not
    readable (2026-10)."""
    if not isinstance(comment, str) or not comment.startswith(_NVD_META_PREFIX):
        return None
    try:
        meta = json.loads(comment[len(_NVD_META_PREFIX) :])
    except ValueError:
        return None
    return meta if isinstance(meta, dict) else None


def _nvd_meta_digest_of_comment(comment: Any) -> Optional[str]:
    """``nvd_meta_digest`` of an attribute comment, or None when it carries no readable ``NVD_META``."""
    meta = nvd_meta_of_comment(comment)
    return nvd_meta_digest(meta) if meta is not None else None


def _vulnerability_tag_changes(
    current: Sequence[str],
    desired: Sequence[str],
    replaced: Sequence[str] = _REPLACED_VULNERABILITY_TAG_PREFIXES,
) -> Tuple[List[str], List[str]]:
    """Tags to attach and to detach so a stored CVE attribute matches a rebuilt one.

    The tags ``replaced`` names are replaced: an entry ending in ``:`` names a family (every tag with
    that prefix), any other entry one tag (2026-10). By default the families ``severity:`` and
    ``cvss:``, which describe NVD's current score; a KEV edit also passes the tag ``ransomware:known``
    (``KEV_REPLACED_TAGS``, 2026-10), so a reverted ransomware use detaches it. Zone, KEV and source
    tags, and ``ransomware:known`` outside KEV edits, are only added: zones accumulate on the graph node,
    so detaching a zone tag would not remove the zone there. ``zone:Global`` is added only to an
    attribute with no zone tag (a sector tag already says more). A ``tlp:`` tag is added only when the
    attribute has none (someone may have raised it in MISP). Tags of any other family, every other
    ``ransomware:`` tag included, are left alone.

    Names compare without case: MISP resolves a tag name case-insensitively, so ``CVSS:low`` in its
    tag table stands for ``cvss:low``.
    """
    replaced_families = tuple(entry.lower() for entry in replaced if entry.endswith(":"))
    replaced_names = {entry.lower() for entry in replaced if not entry.endswith(":")}
    current_lower = {tag.lower() for tag in current}
    has_tlp = any(tag.startswith("tlp:") for tag in current_lower)
    has_zone = any(tag.startswith("zone:") for tag in current_lower)
    attach: List[str] = []
    for tag in desired:
        lower = tag.lower()
        if lower in current_lower or lower in {t.lower() for t in attach}:
            continue
        if (has_tlp and lower.startswith("tlp:")) or (has_zone and lower == "zone:global"):
            continue
        attach.append(tag)
    desired_lower = {tag.lower() for tag in desired}
    detach = sorted(
        tag
        for tag in set(current)
        if (tag.lower() in replaced_names or tag.lower().startswith(replaced_families))
        and tag.lower() not in desired_lower
    )
    return attach, detach


# 2026-10: attribute edits pause like ``push_items`` batches: ``EDGEGUARD_MISP_BATCH_THROTTLE_SEC``
# after every ``EDITS_PER_THROTTLE`` edits. 50 is the batch size ``push_items`` uses on events above
# 100,000 attributes, where the copies of the NVD baseline are.
EDITS_PER_THROTTLE = 50

# 2026-10: the refresh of re-reported indicators stops after this many failed edits in a row. A
# failed edit costs up to three attempts with 5 s and 10 s pauses and a read timeout each, so
# while MISP fails, trying every due edit would outlast the collector task's time limit.
REFRESH_MAX_CONSECUTIVE_FAILURES = 5


def misp_batch_throttle_seconds() -> float:
    """``EDGEGUARD_MISP_BATCH_THROTTLE_SEC`` as ``push_items`` reads it (default 5.0, also for a value
    that is not a number); negative means no pause, a non-finite value the default."""
    try:
        value = float(os.environ.get("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5.0"))
    except (TypeError, ValueError):
        return 5.0
    if not math.isfinite(value):
        return 5.0
    return max(0.0, value)


def _edited_attribute(body: Any) -> Optional[Dict[str, Any]]:
    """The attribute in MISP's answer to ``POST /attributes/edit/{uuid}``, with its tags under ``Tag``.

    MISP 2.5 answers ``{"Attribute": {..., "Tag": [...]}}``: ``JSONConverterTool::convertAttribute``
    moves the attribute's tags into it. An answer wrapped in ``response``, or one with the tags beside
    ``Attribute`` (a ``Tag`` list, or CakePHP's ``AttributeTag`` rows), is read the same way, so a
    stored edit is not taken for a failed one. None when the answer holds no attribute.
    """
    if isinstance(body, dict) and isinstance(body.get("response"), dict):
        body = body["response"]
    if not isinstance(body, dict) or not isinstance(body.get("Attribute"), dict):
        return None
    attribute = dict(body["Attribute"])
    if "Tag" not in attribute:
        tags = body.get("Tag")
        if not isinstance(tags, list):
            rows = attribute.get("AttributeTag") or body.get("AttributeTag") or []
            tags = [row["Tag"] for row in rows if isinstance(row, dict) and isinstance(row.get("Tag"), dict)]
        attribute["Tag"] = tags
    return attribute


def _edit_confirmed(stored: Dict[str, Any], changes: Dict[str, Any], written_after: Optional[float] = None) -> bool:
    """Whether MISP's answer to an attribute edit shows the comment, the ``last_seen`` (compared to
    the second, as an instant) and the tag changes (tag names compared without case, as MISP
    resolves them), and, with ``written_after``, an attribute ``timestamp`` later than it (2026-10:
    a refresh exists to move that timestamp)."""
    if "comment" in changes and stored.get("comment") != changes["comment"]:
        return False
    if "last_seen" in changes:
        sent, kept = _iso_epoch(changes["last_seen"]), _iso_epoch(stored.get("last_seen"))
        if (sent is None) != (kept is None) or (sent is not None and kept is not None and int(sent) != int(kept)):
            return False
    if written_after is not None:
        try:
            if float(stored.get("timestamp")) <= written_after:
                return False
        except (TypeError, ValueError):
            return False
    names = {str(tag.get("name")).lower() for tag in stored.get("Tag") or [] if isinstance(tag, dict)}
    for tag in changes.get("Tag") or []:
        if bool(tag.get("deleted")) == (str(tag.get("name")).lower() in names):
            return False
    return True


# 2026-11: the attribute types whose value MISP changes in case on save (MISP 2.5,
# ``AttributeValidationTool::modifyBeforeValidation``): hashes and other fingerprints, host names,
# domains, e-mail addresses, IP addresses (an IPv6 address is written in lower case), MAC addresses,
# UUIDs and booleans are lower-cased (of a ``filename|<hash>`` value, the hash part); CVE ids,
# weaknesses, HTTP methods, hex, IBAN / BIC and AS numbers upper-cased. MISP stores every other value
# (text, malware and threat-actor names, URLs, file names, registry keys, ...) in the case given. A
# case-insensitive comparison of every type confirmed the active ATT&CK for ICS malware "Triton" because
# the event held the deprecated "TRITON": MISP had not stored "Triton", and the loss went unreported.
# The type names are lower-cased ("as" for MISP's "AS"): the comparison reads the type case-insensitively.
_CASE_NORMALISED_TYPES = frozenset(
    {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512/224", "sha512/256",
        "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ja3-fingerprint-md5", "jarm-fingerprint",
        "hassh-md5", "hasshserver-md5", "pehash", "authentihash", "vhash", "imphash", "telfhash", "tlsh",
        "cdhash", "dom-hash", "anonymised", "uuid", "boolean",
        "x509-fingerprint-md5", "x509-fingerprint-sha1", "x509-fingerprint-sha256",
        "hostname", "hostname|port", "domain", "domain|ip", "onion-address",
        "email", "email-src", "email-dst", "target-email", "whois-registrant-email",
        "ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "mac-address", "mac-eui-64",
        "filename|md5", "filename|sha1", "filename|imphash", "filename|sha224", "filename|sha256",
        "filename|sha384", "filename|sha512", "filename|sha512/224", "filename|sha512/256",
        "filename|sha3-224", "filename|sha3-256", "filename|sha3-384", "filename|sha3-512",
        "filename|authentihash", "filename|vhash", "filename|pehash", "filename|tlsh",
        "vulnerability", "weakness", "http-method", "hex", "iban", "bic", "as",
    }
)  # fmt: skip


def _attribute_match_key(attribute: Any) -> Optional[Tuple[str, str]]:
    """``(type, value)`` key used to recognise a pushed attribute in a MISP event response.

    MISP trims surrounding whitespace on save and changes the case of some types' values (hashes,
    domains, host names and e-mail addresses are lower-cased, CVE ids upper-cased:
    ``_CASE_NORMALISED_TYPES``), so the comparison is whitespace-trimmed, and case-insensitive for
    those types only: any other value that differs from the stored one in case only is a different
    value. Returns None when the attribute lacks a type or a value.
    """
    if not isinstance(attribute, dict):
        return None
    attr_type = attribute.get("type")
    value = attribute.get("value")
    if attr_type is None or value is None:
        return None
    type_norm = str(attr_type).strip().lower()
    value_norm = str(value).strip()
    if type_norm in _CASE_NORMALISED_TYPES:
        value_norm = value_norm.lower()
    if not value_norm:
        return None
    return (type_norm, value_norm)


# 2026-11: how many case variants the ``[CASE-VARIANT]`` line of a push names.
_CASE_VARIANT_LOG_SAMPLE = 5


def _within_push_key(attribute: Any) -> Tuple[str, str]:
    """``(type, value)`` key of the dedup within one push (2026-11): ``_attribute_match_key``'s rule, so
    two attributes MISP holds as one value (surrounding whitespace, and the case of
    ``_CASE_NORMALISED_TYPES``) are pushed once. An attribute without a type or a value keeps its exact
    ``(type, value)``."""
    key = _attribute_match_key(attribute)
    if key is not None:
        return key
    if not isinstance(attribute, dict):
        return ("", str(attribute))
    return (str(attribute.get("type")), str(attribute.get("value")))


def _dedup_key(attr_type: Any, value: Any) -> Tuple[str, Any]:
    """``(type, value)`` key of the duplicate check against what MISP holds: the keys of the existing
    attributes (per event, across the source's events, a caller's ``known_source_keys``), the index of
    stored copies, and the pushed attribute looked up in both (the refresh of a re-reported indicator).

    2026-11: compared as MISP compares a value with the one it stores, the rule of the dedup within the
    push (``_within_push_key``): surrounding whitespace ignored, and case for ``_CASE_NORMALISED_TYPES``.
    MISP holds a hash sent as ``ABC…`` as ``abc…``, so a re-reported ``ABC…`` is the stored copy: present,
    and refreshed when due. Compared exactly, it was pushed again on every run and its copy never
    refreshed, and a later ``abc…`` the within-push dedup dropped took the matching spelling with it. Any
    other type (URLs, names, text) keeps its case. 2026-10-21: a ``text`` value that reads as an ATT&CK
    entry is keyed in its current ``<id> - <name>`` form, so an ``<id>: <name>`` value (the form
    MISPWriter wrote before 2026-10-20) counts as present. Not used by ``_attribute_match_key``: a
    pushed value is confirmed against what MISP stored for it.
    """
    key = _within_push_key({"type": attr_type, "value": value})
    if key[0] == "text":
        return (key[0], attack_value_key(key[1]))
    return key


def _iso_epoch(raw: Any) -> Optional[float]:
    """An ISO 8601 date as epoch seconds (a date without zone is UTC, as MISP stores it); None when
    empty or unreadable (2026-10)."""
    if raw in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


class StoredCopy(NamedTuple):
    """The stored copy of a re-reported indicator that a refresh would edit (2026-10).

    ``written`` is the attribute's MISP ``timestamp`` (MISP's last write, epoch seconds): the
    incremental sync re-reads an attribute only when it moves. ``first_seen`` / ``last_seen`` are
    the source's claims as MISP stores them; a refresh keeps them unless the source now claims a
    later ``last_seen``. Since 2026-10-16 the indicator ages from ``last_seen`` capped at
    ``written`` (``written`` when there is no ``last_seen``; ``indicator_aging``), so a refresh
    makes it younger only when the source's date moved, or, without one, to the time of the edit.
    """

    written: float
    uuid: str
    first_seen: Optional[str]
    last_seen: Optional[str]


# 2026-10: the events ``_get_or_create_event`` creates (``EdgeGuard-{source}-{date}``, ``-part<N>``; since 2026-11-07
# also ``-reports``, which holds report records only).
# Only copies in them are refreshed: the sync reads EdgeGuard's events, and a copy that keeps the
# source tag in an analyst's or a federated organisation's event is not EdgeGuard's to edit.
_OWN_EVENT_PREFIX = "EdgeGuard-"


_EVENT_SPLIT_DEFAULT = 20000
# The smallest limit accepted: a typo such as 20 would cut a 140,000-attribute NVD baseline into
# thousands of events, each looked up on every later push of the day.
_EVENT_SPLIT_MIN = 1000


def _event_split_above() -> int:
    """``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`` (2026-10): attributes one event of a source/date takes before
    the writer opens the next part (``EdgeGuard-<source>-<date>-part2``); ``0`` (or less) = never split.

    The prod NVD event of 2026-10-22 reached 145,261 attributes (about 550 MB of JSON): MISP answered
    HTTP 500 to a view of it, its edit handler choked, and every batch's prefetch of the event cost more
    than the one before. The default equals ``EDGEGUARD_MISP_PAGED_FETCH_ABOVE`` (20000), so each part
    still loads with one ``/events/view``. A value that is not a whole number, or one from 1 to 999,
    logs a warning and uses the default.
    """
    raw = (os.environ.get("EDGEGUARD_MISP_EVENT_SPLIT_ABOVE") or "").strip()
    if not raw:
        return _EVENT_SPLIT_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "EDGEGUARD_MISP_EVENT_SPLIT_ABOVE=%r is not a whole number — using %d", raw, _EVENT_SPLIT_DEFAULT
        )
        return _EVENT_SPLIT_DEFAULT
    if value <= 0:
        return 0
    if value < _EVENT_SPLIT_MIN:
        logger.warning(
            "EDGEGUARD_MISP_EVENT_SPLIT_ABOVE=%d is below %d — using %d (0 turns the split off)",
            value,
            _EVENT_SPLIT_MIN,
            _EVENT_SPLIT_DEFAULT,
        )
        return _EVENT_SPLIT_DEFAULT
    return value


class _PrefetchedKeys(set):
    """The ``(type, value)`` keys of an event's attributes (``MISPWriter._get_existing_attribute_keys``).

    ``complete`` is False when the listing stopped early or the prefetch is off, and ``failed`` is True
    when it stopped early (an error, a non-JSON answer, the page cap) (2026-10): the number of keys is
    then no size of the event, and the event split (``_event_split_above``) takes the size from the
    event's ``attribute_count`` instead.
    """

    def __init__(self, keys: Sequence = (), complete: bool = True, failed: bool = False):
        super().__init__(keys)
        self.complete = complete
        self.failed = failed


class _PendingPart(NamedTuple):
    """A ``-partN`` event ``push_items`` creates when its first batch is about to be written (2026-10): after
    the pause and the liveness check of that batch, so a push that stops early leaves no empty part behind."""

    source: str
    date: str
    part: int


def _attribute_report_ids(attribute: Dict[str, Any]) -> List[str]:
    """The source-report ids (OTX pulses) an attribute names in its metadata comment, or ``[]`` (2026-10).

    ``OTX_META`` (indicators, CVEs) carries ``pulse_id`` + ``report_ids``; the ``MITRE_USES_TECHNIQUES``
    block of OTX malware and actors carries ``pid`` + ``rids``. The sync links items per report within one
    event (``_build_cross_item_relationships``), so a group with any such attribute is never split
    (``push_items``): a shared malware, actor or CVE item carries the ids of every pulse naming it, which
    joins nearly all of a day's pulses into one report.
    """
    comment = attribute.get("comment")
    if not isinstance(comment, str) or ":" not in comment:
        return []
    prefix, _, body = comment.partition(":")
    if prefix not in ("OTX_META", "MITRE_USES_TECHNIQUES"):
        return []
    try:
        meta, _end = json.JSONDecoder().raw_decode(body)
    except ValueError:
        return []
    if not isinstance(meta, dict):
        return []
    ids = [meta.get("pulse_id"), meta.get("pid")] + list(meta.get("report_ids") or []) + list(meta.get("rids") or [])
    return list(dict.fromkeys(str(x).strip() for x in ids if x and str(x).strip()))


def _allot_to_parts(
    attributes: List[Dict[str, Any]], rooms: Sequence[int], cap: int
) -> Tuple[List[List[Dict[str, Any]]], List[List[Dict[str, Any]]]]:
    """Cut ``attributes`` for the event split (2026-10, see ``_event_split_above``): one chunk per existing
    part, in order, of at most its room (empty where a part takes none), then chunks of at most ``cap``
    for new parts. No new-part chunk is empty, so no part is created that receives nothing."""
    chunks: List[List[Dict[str, Any]]] = []
    rest = list(attributes)
    for room in rooms:
        take = max(0, room)
        chunks.append(rest[:take])
        rest = rest[take:]
    return chunks, [rest[k : k + cap] for k in range(0, len(rest), cap)]


def _event_name(source: str, date: str, part: int = 1) -> str:
    """``EdgeGuard-<source>-<date>``; part 2 and later append ``-part<N>`` (2026-10, see ``_event_split_above``).
    The first part keeps the name events had before the split. Readers take the source as the second
    ``-`` field of the name, so the suffix does not move it."""
    name = f"{_OWN_EVENT_PREFIX}{source}-{date}"
    return name if part <= 1 else f"{name}-part{part}"


def _report_event_name(source: str, date: str) -> str:
    """``EdgeGuard-<source>-<date>-reports`` (2026-11-07): the companion event that takes the new report records of
    a day whose event holds more attributes than ``_event_split_above`` allows (``MISPWriter.push_reports``)."""
    return f"{_event_name(source, date)}{report_records.REPORT_EVENT_SUFFIX}"


def _note_stored_copy(
    seen: Dict[Tuple[str, str], Optional[StoredCopy]],
    key: Tuple[str, str],
    attribute: Dict[str, Any],
) -> None:
    """Record for ``key`` the copy in an EdgeGuard event that MISP wrote last (2026-10).

    A source can hold an indicator in several events (pushed on different days before the
    cross-event check existed); the copy written last decides whether the indicator needs a
    refresh, and that copy is the one edited. A row whose ``Event.info`` is not an EdgeGuard event
    name, or without uuid or readable ``timestamp``, is not recorded.
    """
    event = attribute.get("Event")
    info = event.get("info") if isinstance(event, dict) else None
    if not isinstance(info, str) or not info.startswith(_OWN_EVENT_PREFIX):
        return
    uuid = str(attribute.get("uuid") or "").strip()
    try:
        written = float(attribute.get("timestamp"))
    except (TypeError, ValueError):
        return
    if not uuid:
        return
    current = seen.get(key)
    if current is None or written > current.written:
        seen[key] = StoredCopy(
            written=written,
            uuid=uuid,
            first_seen=attribute.get("first_seen") or None,
            last_seen=attribute.get("last_seen") or None,
        )


def _refreshed_last_seen(stored_copy: StoredCopy, reported: Any, now: float) -> Optional[str]:
    """The ``last_seen`` a refresh sends for ``stored_copy`` (2026-10): the source's ``reported`` claim when
    it is later than the stored ``last_seen`` (or, without one, not earlier than the stored
    ``first_seen``, which MISP requires) and not in the future; otherwise the stored value
    unchanged, so the field keeps holding what a source claimed and never the time of a run."""
    reported_at = _iso_epoch(reported)
    if reported_at is not None and reported_at <= now:
        stored_at = _iso_epoch(stored_copy.last_seen)
        if stored_at is not None:
            if reported_at > stored_at:
                return str(reported)
        else:
            first_at = _iso_epoch(stored_copy.first_seen)
            if first_at is None or reported_at >= first_at:
                return str(reported)
    return stored_copy.last_seen


def _strip_non_bmp(text: str) -> str:
    """Drop characters outside the Basic Multilingual Plane (4-byte UTF-8, e.g. emoji).

    MISP's MySQL/MariaDB text columns use 3-byte ``utf8``; one emoji in an attribute comment or
    tag name makes the INSERT fail (``1366 Incorrect string value``) and MISP answers the whole
    batch with HTTP 500 (2026-10-12 fresh baseline, OTX pulse names with flag emoji).
    """
    return "".join(ch for ch in text if ord(ch) <= 0xFFFF)


def _value_is_storable(attr: Dict) -> bool:
    """False when the attribute's ``value`` holds 4-byte characters, which MISP cannot store."""
    value = attr.get("value")
    return not (isinstance(value, str) and any(ord(ch) > 0xFFFF for ch in value))


def _make_attributes_storable(attributes: List[Dict]) -> List[Dict]:
    """Strip 4-byte characters from descriptive fields; drop attributes whose value needs them.

    ``comment`` and tag names are descriptive, so stripping keeps the indicator. A ``value`` is
    the indicator itself: rewriting it would store a different IOC, so such an attribute is
    skipped with a warning instead of failing its whole batch.
    """
    storable: List[Dict] = []
    for attr in attributes:
        value = attr.get("value")
        if not _value_is_storable(attr):
            logger.warning(
                "[SKIP] attribute value contains 4-byte characters MISP cannot store: type=%s value=%r",
                attr.get("type"),
                value[:80],
            )
            continue
        clean = dict(attr)
        if isinstance(clean.get("comment"), str):
            clean["comment"] = _strip_non_bmp(clean["comment"])
        if isinstance(clean.get("Tag"), list):
            clean["Tag"] = [
                {**tag, "name": _strip_non_bmp(tag["name"])}
                if isinstance(tag, dict) and isinstance(tag.get("name"), str)
                else tag
                for tag in clean["Tag"]
            ]
        storable.append(clean)
    return storable


def _batches(attrs: List[Dict], size: int, key_of: Callable[[Dict], Any]) -> List[List[Dict]]:
    """*attrs* in batches of at most *size* (2026-11-02). Attributes for which *key_of* differs never share a
    batch: each key's attributes are batched apart, in their order, the keys in the order of their first
    attribute. With one key for all (``push_items`` without ``batch_key``) the batches follow *attrs*."""
    by_key: Dict[Any, List[Dict]] = {}
    for attr in attrs:
        by_key.setdefault(key_of(attr), []).append(attr)
    return [group[i : i + size] for group in by_key.values() for i in range(0, len(group), size)]


def _strict_push_accounting() -> bool:
    """``EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING`` truthy: attributes absent from the returned event
    count as failed pushes (they then feed ``EDGEGUARD_MISP_MIN_SUCCESS_RATE``). Off by default:
    MISP normalises some values on save (whitespace, and the case of ``_CASE_NORMALISED_TYPES``, are
    tolerated by the comparison; rarer rewrites such as IPv6 compression are not), so the strict
    mode is meant to be enabled after a live check shows no spurious unconfirmed attributes.
    """
    return os.environ.get("EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING", "").strip().lower() in ("1", "true", "yes", "on")


def _confirm_pushed_attributes(
    attempted: List[Dict[str, Any]], saved: Any
) -> Optional[Tuple[int, List[Tuple[str, str]]]]:
    """Reconcile a pushed batch against the ``Event.Attribute`` list MISP returns on event edit.

    ``POST /events/{id}`` answers with the full event; its ``Attribute`` list holds every
    attribute now stored on the event (newly added and pre-existing). An attempted attribute
    is confirmed when a stored attribute with the same type and normalised value is present.

    Returns None when the response carries no usable attribute list, in which case the batch
    cannot be verified from the response. Otherwise returns ``(confirmed_count,
    unconfirmed_keys)`` where ``unconfirmed_keys`` lists the attempted attributes that are
    absent from the stored event.
    """
    if isinstance(saved, dict):
        saved = [saved]
    if not isinstance(saved, list) or not saved:
        return None
    present = set()
    for stored in saved:
        key = _attribute_match_key(stored)
        if key is not None:
            present.add(key)
    if not present:
        return None
    confirmed = 0
    unconfirmed: List[Tuple[str, str]] = []
    for attribute in attempted:
        key = _attribute_match_key(attribute)
        if key is not None and key in present:
            confirmed += 1
        else:
            attr_type = attribute.get("type") if isinstance(attribute, dict) else None
            unconfirmed.append(key or (str(attr_type or "unknown"), "<no value>"))
    return confirmed, unconfirmed


def _event_id_and_info_from_restsearch_row(row: Any) -> Tuple[Optional[str], Optional[str]]:
    """Extract (id, info) from one MISP restSearch row (wrapped or flat)."""
    if not isinstance(row, dict):
        return None, None
    ev = row.get("Event")
    if isinstance(ev, dict):
        eid, info = ev.get("id"), ev.get("info")
    else:
        eid, info = row.get("id"), row.get("info")
    if eid is not None:
        eid = str(eid)
    if info is not None:
        info = str(info)
    return eid, info


def _event_id_exact_from_restsearch_rows(rows: List[Any], event_name: str) -> Optional[str]:
    """
    Only accept an **exact** ``Event.info`` match; taking ``response[0]`` can attach one feed's
    items to another source's event.

    2026-10: the rows are not all matches. A MISP older than 2.4.177 ignores the ``eventinfo``
    filter and answers events of the whole store, and MISP's own match follows the database
    collation, which is usually case-insensitive.
    """
    for row in rows:
        eid, info = _event_id_and_info_from_restsearch_row(row)
        if eid and info == event_name:
            return eid
    return None


def _event_attribute_count_from_restsearch_rows(rows: List[Any], event_name: str) -> Optional[int]:
    """``attribute_count`` of the row named exactly ``event_name``, or None (2026-10).

    MISP 2.5 answers the metadata lookup with ``"attribute_count": "145261"`` (a string; measured on the
    hosted MISP 2.5.45). The event split reads a part's size from it when the part's attribute listing
    is incomplete.
    """
    for row in rows:
        eid, info = _event_id_and_info_from_restsearch_row(row)
        if not (eid and info == event_name):
            continue
        ev = row.get("Event") if isinstance(row.get("Event"), dict) else row
        try:
            return max(0, int(str(ev.get("attribute_count")).strip()))
        except (TypeError, ValueError):
            return None
    return None


@contextmanager
def _cross_process_event_creation_lock():
    """
    Serialize MISP event creation across processes (e.g. Airflow LocalExecutor workers).

    Without this, two collectors can both see "no event" and create duplicates — or worse, rely on
    ambiguous restSearch hits. The lock is an ``flock`` on ``EDGEGUARD_MISP_EVENT_LOCK_PATH``
    (``lock_files.exclusive_flock``): a collector that waited on a file ``edgeguard heal`` removed takes
    the lock again on the current file. On platforms without ``fcntl``, the context is a no-op.
    """
    with exclusive_flock(misp_event_lock_path()):
        yield


def sanitize_value(value: str, max_length: int = 255) -> str:
    """Sanitize a threat-intelligence value for safe storage in MISP.

    Removes control characters and null bytes, enforces a maximum length,
    and strips surrounding whitespace.

    HTML-escaping is intentionally NOT applied: it would corrupt indicator
    values that legitimately contain ``&``, ``<``, ``>``, or ``"``
    (e.g. URLs with query strings, file paths, regex patterns).

    Args:
        value:      Input string to sanitize.
        max_length: Maximum allowed byte-length (default 255).

    Returns:
        Sanitized string safe for use in MISP attributes.
    """
    if not value or not isinstance(value, str):
        return ""
    # Remove null bytes and ASCII control characters (0x00–0x1F except tab/newline)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
    value = value.strip()
    if len(value) > max_length:
        value = value[: max_length - 3] + "..."
    return value


def rate_limited(max_per_second: float = 2.0):
    """Rate limiting decorator to avoid overwhelming APIs.

    Args:
        max_per_second: Maximum calls allowed per second
    """
    min_interval = 1.0 / max_per_second if max_per_second > 0 else 0.5
    last_call_time = [0.0]  # Use list for mutable closure

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_call_time[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            result = func(*args, **kwargs)
            last_call_time[0] = time.time()
            return result

        return wrapper

    return decorator


# --------------------------------------------------------------------------- #
# Report records (2026-11-07): MISPWriter.push_reports and report_preflight
# --------------------------------------------------------------------------- #

# A push of report records stops after this many records in a row failed because MISP answered HTTP 5xx or did not
# answer (each after one more try); the records not tried are listed as skipped, so a MISP that is down costs a few
# requests and not two per record.
REPORT_MAX_CONSECUTIVE_FAILURES = 5


class _ReportAnswer(NamedTuple):
    """One report request: the HTTP status (None when MISP did not answer), the JSON body (None when the answer
    was no JSON) and the problem as the log names it (status and tries; never the body)."""

    status: Optional[int]
    body: Any
    problem: str

    @property
    def transient(self) -> bool:
        return self.status is None or self.status >= 500


class ReportPreflight(NamedTuple):
    """The read-only check of the writer key for report records (``MISPWriter.report_preflight``)."""

    ok: bool  # no problem found
    problems: Tuple[str, ...]  # what keeps reports or their tags from being written as intended
    org_id: Optional[str]  # the organisation of the writer key (``User.org_id``)
    perm_tagger: Optional[bool]  # None: the role could not be read
    perm_tag_editor: Optional[bool]
    perm_sync_authoritative: Optional[bool]
    tags_checked: Tuple[str, ...]  # the tags the writer sets on reports
    missing_tags: Tuple[str, ...]  # those of them this MISP does not hold


def report_tag_names() -> Tuple[str, ...]:
    """Every tag ``push_reports`` may set on a report: ``EdgeGuard``, the source tags of the report sources and
    ``tlp:<level>`` for each TLP level a record can state."""
    sources = tuple(MISPWriter.SOURCE_TAGS[s] for s in report_records.REPORT_SOURCES)
    return ("EdgeGuard", *sources, *(f"tlp:{level}" for level in report_records.TLP_LEVELS))


def _role_flag(role: Dict[str, Any], key: str) -> Optional[bool]:
    """A ``Role.perm_*`` flag as MISP answers it (``true`` / ``false``, or ``1`` / ``0``); None when absent."""
    if key not in role:
        return None
    value = role.get(key)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true")
    return bool(value)


def _writer_org_of(body: Any) -> Optional[str]:
    """The organisation id in an answer of ``GET /users/view/me`` (``User.org_id``, else ``Organisation.id``)."""
    if not isinstance(body, dict):
        return None
    for holder, key in (("User", "org_id"), ("Organisation", "id")):
        part = body.get(holder)
        value = part.get(key) if isinstance(part, dict) else None
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _report_deleted(report: Dict[str, Any]) -> bool:
    """Whether MISP holds the report as soft-deleted (``deleted`` true; MISP 2.5 answers a bool)."""
    return report.get("deleted") not in (False, 0, "0")


def _stored_report_problem(body: Any, uuid: str, content_sha: str, name: str) -> Optional[str]:
    """Why MISP's answer to an add or an edit does not show the report as sent, or None when it does (live checks
    L1, L2 and L8 of 2026-11-07): the answer must hold ``EventReport`` with the uuid sent, the content's SHA-256,
    the name sent and ``deleted`` false. A failed edit answers HTTP 200 ``[]``, a failed tag change HTTP 200
    ``{"saved": false}``, and a database without strict SQL mode cuts a value without an error."""
    report = body.get("EventReport") if isinstance(body, dict) else None
    if not isinstance(report, dict):
        return "the answer holds no report"
    if str(report.get("uuid") or "") != uuid:
        return "the answer names another report"
    content = report.get("content")
    if not isinstance(content, str) or report_records.content_sha256(content) != content_sha:
        return "MISP holds other content"
    if report.get("name") != name:
        return "MISP holds another name"
    if _report_deleted(report):
        return "MISP holds the report as deleted"
    return None


class MISPWriter:
    """
    Writes indicators to MISP as the single point of truth.

    Features:
    - Batch uploads for efficiency
    - Automatic sector-based event organization
    - Deduplication within batches
    - Support for all EdgeGuard indicator types
    """

    # Timeout constants for MISP API calls (defined before use)
    CONNECT_TIMEOUT = 30  # seconds
    READ_TIMEOUT = 300  # seconds — MISP needs time for large events (95K+ attributes)
    # 2026-11-03: (connect, read) timeout of the light request that ends a back-off cooldown early when MISP
    # answers it (``_misp_answers``).
    COOLDOWN_PROBE_TIMEOUT = (10, 30)

    # Mapping from EdgeGuard indicator types to MISP attribute types. MISP's ``ip-dst`` holds
    # IPv4 and IPv6 addresses alike (there is no IPv6 type); the sync reads the family back
    # from the value.
    TYPE_MAPPING = {
        "ipv4": "ip-dst",
        "ipv6": "ip-dst",
        "ip": "ip-dst",
        "domain": "domain",
        "hostname": "hostname",
        "url": "url",
        "uri": "url",
        "hash": "sha256",  # Default to sha256, can be overridden
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
        # SHA-1 fingerprint of a TLS certificate (SSL Blacklist, 2026-10): MISP's own type for it,
        # so the fingerprint is not stored as the ``sha1`` of a file.
        "x509-fingerprint-sha1": "x509-fingerprint-sha1",
        "email": "email-src",
        "cve": "vulnerability",
        "filename": "filename",
        "filepath": "filename",
        "mutex": "mutex",
        "registry": "regkey",
        "yara": "yara",
        "sigma": "sigma",
        "snort": "snort",
        "bitcoin": "btc",
        "unknown": "text",
    }

    # Source to MISP tag mapping. Single-source-of-truth derivation from
    # src/source_registry.py (chip 5a) — adding a new source is now a
    # one-line edit there. The derived map covers every alias (so the
    # writer resolves a lookup by either canonical id OR legacy short
    # name to the same MISP tag), which extends the historical key set
    # but does not change behavior for any existing input.
    SOURCE_TAGS = source_registry.source_to_misp_tag_map()

    def __init__(
        self,
        url: str = None,
        api_key: str = None,
        verify_ssl: bool = None,
        liveness_callback: Optional[Callable[[], None]] = None,
        baseline: bool = False,
        task_ends_at: Optional[float] = None,
    ):
        """
        Initialize MISP writer.

        Args:
            url: MISP instance URL (defaults to config.MISP_URL)
            api_key: MISP API key (defaults to config.MISP_API_KEY)
            verify_ssl: Whether to verify SSL certificates (defaults to config.SSL_VERIFY)
            liveness_callback: PR-F6 (Issue #65) — optional zero-arg callable
                invoked between MISP push batches. Should raise
                ``AbortedByDagFailureException`` (or any exception) to
                signal the collector to abort cleanly. Used for the
                parent-DAG-liveness orphan-process safeguard. ``None``
                (default) preserves legacy behavior — push_items runs
                to completion regardless of parent-DAG state.
            baseline: 2026-11-03, the baseline's writer (``run_baseline_collector``): its pushes stop after
                ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`` of failure time instead of
                ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC`` (``config.misp_push_max_failing_seconds``).
            task_ends_at: 2026-11-03, when the task's ``execution_timeout`` ends (a ``time.time()`` value), or
                None: a failing streak then gets at most the time from its start to ``PUSH_TASK_END_MARGIN_SEC``
                before that end, and at least ``PUSH_FAILING_FLOOR_SEC`` (``_failing_streak``).
        """
        self.url = url or MISP_URL
        self.api_key = api_key or MISP_API_KEY

        # Use config value if not explicitly specified
        if verify_ssl is None:
            self.verify_ssl = SSL_VERIFY
        else:
            self.verify_ssl = verify_ssl

        # Warn if SSL is disabled
        if not self.verify_ssl:
            logger.warning("SSL verification is DISABLED. This is OK for local dev only!")
            logger.warning("For production, set EDGEGUARD_SSL_VERIFY=true or set SSL_VERIFY=True")
        else:
            logger.info("SSL verification is ENABLED")

        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}
        )
        apply_misp_http_host_header(self.session)
        self.stats = {
            "events_created": 0,
            "attributes_added": 0,
            "batches_sent": 0,
            "errors": 0,
            "attrs_skipped_existing": 0,
            # Attributes edited in place (NVD incremental runs, 2026-10).
            "attributes_updated": 0,
            # Re-reported indicators whose stored copy was refreshed (2026-10; also counted in
            # attributes_updated), the refresh edits that failed, and the due refreshes left for a
            # later run (per-run cap, time budget, or a stop after consecutive failures).
            "attributes_refreshed": 0,
            "attributes_refresh_failed": 0,
            "attributes_refresh_deferred": 0,
            # Batches MISP answered with HTTP 200 but without an attribute list, so the
            # attempted count could not be verified against the stored event.
            "batches_unverified": 0,
            # Attributes absent from the stored event MISP returned after an HTTP 200 push.
            "attributes_unconfirmed": 0,
            # Items no MISP attribute could be built from (2026-10), and those of them counted as
            # failed pushes: only a source whose items all, or at least CONVERT_FAILED_MIN_SHARE of
            # them, failed conversion in one push counts them.
            "items_not_converted": 0,
            "items_not_converted_failed": 0,
            # Batches MISP answered with HTTP 5xx and stored in full (2026-11-02, ``_stored_after_server_error``).
            "batches_stored_after_5xx": 0,
        }
        # PR-F6 (Issue #65): per-batch parent-DAG liveness callback.
        # ``None`` = no check (legacy / incremental DAGs); a callable
        # = check before each batch. See src/parent_dag_liveness.py.
        self.liveness_callback = liveness_callback
        # 2026-11-03: the cap on failure time of a push (``_arm_push_cap``); read with ``getattr`` defaults.
        self.baseline = bool(baseline)
        self.task_ends_at = task_ends_at
        # 2026-11-03: set by each ``push_items`` call (see its docstring); defaults for a writer that pushed nothing.
        self.last_push_unsent_items: List[int] = []
        self.last_push_stopped = False

    def _restsearch_events_for_name(self, event_name: str) -> List[Any]:
        """Look up the event named ``event_name`` through ``/events/restSearch``.

        Returns the rows of the page that holds a row with exactly this ``Event.info``, or an empty
        list when no page holds one ("no such event"). The caller still picks the exact row.

        2026-10: the request names the filter ``eventinfo``, an exact ``Event.info`` match for a
        value without ``%``. The earlier ``info`` key is not a restSearch parameter: MISP dropped it
        and answered the first events of the store, so once the store held more events than one
        answer, the same-day event was missed and a duplicate was created. MISP honours
        ``eventinfo`` from 2.4.177 on; on an older MISP the lookup pages until a row carries the
        name or a page comes back short (``EVENT_LOOKUP_MAX_PAGES`` bounds it). ``metadata`` asks
        for event headers only: the lookup reads id and info, and a full event with all of its
        attributes made a php-fpm worker grow by GBs per lookup.

        Raises ``MispTransientError`` on HTTP 429 / 5xx and ``MispLookupError`` on any other failure
        or when the page cap is reached without a short page: the event may exist beyond the cap.
        """
        for page in range(1, EVENT_LOOKUP_MAX_PAGES + 1):
            rows = self._restsearch_event_page(event_name, page)
            if _event_id_exact_from_restsearch_rows(rows, event_name):
                return rows
            if len(rows) < EVENT_LOOKUP_PAGE_SIZE:
                return []
        logger.error(
            "MISP event lookup for %r reached the page cap (%d pages of %d events) without the event or a "
            "short page: this MISP most likely ignores the eventinfo filter (older than 2.4.177) and holds "
            "more events than the cap covers. No event is created after an incomplete lookup; upgrade MISP "
            "to 2.4.177 or later, or raise EVENT_LOOKUP_MAX_PAGES in src/collectors/misp_writer.py",
            event_name,
            EVENT_LOOKUP_MAX_PAGES,
            EVENT_LOOKUP_PAGE_SIZE,
        )
        raise MispLookupError(
            f"Event lookup for {event_name!r} reached the page cap ({EVENT_LOOKUP_MAX_PAGES} pages) without a result"
        )

    def _restsearch_event_page(
        self, event_name: str, page: int, timeout: Optional[Tuple[float, float]] = None, quiet: bool = False
    ) -> List[Any]:
        """One page of the event lookup; returns the ``response`` list (see ``_restsearch_events_for_name``).
        *timeout*: (connect, read), the writer's own by default; *quiet*: an answer other than HTTP 200 is logged
        at DEBUG, not as a failed lookup (2026-11-03, both for ``_misp_answers``)."""
        response = self.session.post(
            f"{self.url}/events/restSearch",
            json={
                "returnFormat": "json",
                "eventinfo": event_name,
                "metadata": True,
                "limit": EVENT_LOOKUP_PAGE_SIZE,
                "page": page,
            },
            verify=self.verify_ssl,
            timeout=timeout or (self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
        )
        if response.status_code != 200:
            detail = (response.text or "")[:500]
            if response.status_code == 429 or response.status_code >= 500:
                # Rate limit or server error: let @retry_with_backoff on the caller retry with its
                # exponential backoff. No sleep here: the confirming lookup runs inside the
                # cross-process event-creation lock, and a Retry-After wait taken there would hold
                # the lock against every parallel collector.
                logger.log(
                    logging.DEBUG if quiet else logging.WARNING,
                    "MISP restSearch for event lookup answered HTTP %s — the caller retries with backoff: %s",
                    response.status_code,
                    detail,
                )
                raise MispTransientError(
                    f"MISP {response.status_code} on event lookup for {event_name!r}", response=response
                )
            logger.log(
                logging.DEBUG if quiet else logging.ERROR,
                "MISP restSearch for event lookup failed: HTTP %s — %s; no event is created after a failed lookup",
                response.status_code,
                detail,
            )
            raise MispLookupError(f"MISP {response.status_code} on event lookup for {event_name!r}")
        data = response.json()
        return data.get("response") or []

    def _misp_answers(self, source: str) -> bool:
        """Whether MISP answers a light request with HTTP 200 (2026-11-03): the first page of the lookup of the
        source's event of the day (``_restsearch_event_page``: event headers only, nothing written, failures logged
        at DEBUG), with the short ``COOLDOWN_PROBE_TIMEOUT``. Any other answer and any exception is no.
        ``push_items`` asks it during a back-off cooldown, after each 30 s step while the cooldown has at least the
        probe's timeouts left, and ends the cooldown when MISP answers."""
        try:
            name = _event_name(
                sanitize_value(str(source), max_length=50), datetime.now(timezone.utc).strftime("%Y-%m-%d")
            )
            self._restsearch_event_page(name, 1, timeout=self.COOLDOWN_PROBE_TIMEOUT, quiet=True)
            return True
        except Exception as e:
            logger.debug("MISP did not answer the cooldown's probe (%s: %s)", type(e).__name__, e)
            return False

    def _arm_push_cap(self) -> None:
        """Set the cap on failure time of the ``push_items`` call that starts (2026-11-03, ``_failing_streak``):
        ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC``, or ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`` for the
        baseline's writer (``config.misp_push_max_failing_seconds``); a writer given its task's end
        (``task_ends_at``) also stops a streak ``PUSH_TASK_END_MARGIN_SEC`` before that end. No streak is on."""
        baseline = getattr(self, "baseline", False) is True
        cap = misp_push_max_failing_seconds(baseline=baseline)
        self._misp_push_failing_cap = cap
        self._misp_push_failing_setting = _PUSH_CAP_SETTING_BASELINE if baseline else _PUSH_CAP_SETTING
        self._misp_push_failing_since = None
        self._misp_push_failing_end_by = None
        ends_at = getattr(self, "task_ends_at", None)
        if cap > 0 and _is_seconds(ends_at):
            self._misp_push_failing_end_by = time.monotonic() + (ends_at - time.time()) - PUSH_TASK_END_MARGIN_SEC

    def _get_existing_source_attribute_keys(
        self,
        source_tag: str,
        stored_copy_of: Optional[Dict[Tuple[str, str], Optional[StoredCopy]]] = None,
        listing_complete: Optional[Dict[str, bool]] = None,
    ) -> set:
        """Build a set of (MISP attribute type, value) already pushed under
        ANY MISP event tagged with ``source_tag`` — across all events,
        not just one.

        2026-10 (re-reported indicators): ``stored_copy_of`` maps the keys of the indicators a push
        reports to ``None``; for each of those keys that the listing finds in an EdgeGuard event,
        it is set to the ``StoredCopy`` MISP wrote last (uuid, ``timestamp``, ``first_seen``,
        ``last_seen``). The rows the listing already reads carry these fields and their event's
        ``info``, so this adds no request, and only the keys asked for are kept: memory grows with
        the push, not with the source. 2026-11: the keys of both, the returned set and ``stored_copy_of``,
        are ``_dedup_key``s (as MISP compares values), so a copy stored as ``abc…`` answers ``ABC…``.

        2026-10 (event lookup after the cross-event check): ``listing_complete`` receives
        ``{tag: True}`` when the listing read the source's attributes up to MISP's last (short)
        page. Nothing is recorded when the check is off, the tag is empty, or the listing stopped
        early (an error, a non-JSON answer, the page cap), so a caller can tell a complete keyset
        from a partial or empty one: ``push_items`` skips the event lookup of a group only on a
        complete one.

        PR-F7 (Issue #61 quick-fix): the per-event prefetch
        (:meth:`_get_existing_attribute_keys`) misses duplicates across
        different MISP events for the same source. Bravo's 2026-04-19
        incident measured 72,479 CVEs duplicated between event 19
        (``EdgeGuard-nvd-2026-04-19``) and event 20
        (``EdgeGuard-nvd-2026-04-20``) — both runs pushed the same NVD
        baseline window on different UTC days, creating two events with
        the same content.

        Uses MISP's ``attributes/restSearch`` ``tags`` filter — one
        query per source per :meth:`push_items` call (cached by the
        caller). Paginated identically to the per-event variant. Returns
        an empty set when:

          - ``EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS`` is disabled
            (master switch — also gates the per-event prefetch)
          - ``EDGEGUARD_MISP_CROSS_EVENT_DEDUP`` is disabled (this
            feature's opt-out)
          - ``source_tag`` is empty (defensive — caller couldn't resolve)
          - The probe fails (any HTTP error / parse error) — degrades
            cleanly to per-event-only dedup; no harm

        Cost: ~30-40 seconds for ~92K NVD attributes paginated 5000/page
        (~19 requests). Amortized over the entire baseline run (one call
        per source per push_items invocation, not per batch).

        Event size is bounded by the event split (``_event_split_above``, ``-part<N>``; not OTX). With
        the split, a complete listing is also what keeps an attribute out of a second part of the day;
        without one, ``push_items`` lists the other parts.
        """
        if not MISP_PREFETCH_EXISTING_ATTRS:
            return set()
        if not MISP_CROSS_EVENT_DEDUP:
            return set()
        tag = (source_tag or "").strip()
        if not tag:
            return set()
        keys: set = set()
        page = 1
        page_limit = 5000
        max_pages = 200
        while page <= max_pages:
            try:
                response = self.session.post(
                    f"{self.url}/attributes/restSearch",
                    json={
                        "returnFormat": "json",
                        "tags": [tag],
                        "page": page,
                        "limit": page_limit,
                    },
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2),
                )
            except _TRANSIENT_HTTP_ERRORS as ex:
                # PR-F7 Bugbot round-3 / multi-agent audit (Logic Tracker HIGH,
                # Devil's Advocate HIGH, Bug Hunter HIGH): previously this
                # branch re-raised transient errors. That was WRONG —
                # ``push_items`` has no retry decorator around this call,
                # so the exception propagated → collector ``except
                # Exception`` → catastrophic classification → [CRITICAL]
                # HARD-FAILED alert + entire NVD batch (~92K attrs) lost.
                # The docstring promises "degrades cleanly to per-event
                # dedup; no harm" — deliver on that.
                #
                # PR-F7 Bugbot round-4 (Medium on commit 90a0ab5):
                # previous fix was ``return set()`` — which discarded
                # every page already collected. On NVD (~19 pages) a
                # transient blip on page 15 threw away ~70K valid keys
                # → all cross-event dedup lost for the run, most likely
                # to happen exactly when MISP is under load (the
                # scenario this PR targets). Fix: ``break`` preserves
                # the partial keyset (strictly better than empty). The
                # sibling ``_get_existing_attribute_keys`` already uses
                # the same pattern.
                logger.warning(
                    "MISP cross-event prefetch transient error for tag=%s page=%s after %s keys: %s — "
                    "preserving partial keyset, degrading to per-event for remainder "
                    "(PR-F7: fail-OPEN, no collector abort)",
                    tag,
                    page,
                    len(keys),
                    ex,
                )
                break
            except Exception as ex:
                logger.warning(
                    "MISP cross-event prefetch failed for tag=%s page=%s after %s keys: %s — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    tag,
                    page,
                    len(keys),
                    ex,
                )
                break
            if response.status_code != 200:
                # PR-F7 Bugbot round-4: preserve partial keyset (same
                # rationale as the transient-error break above).
                logger.warning(
                    "MISP cross-event prefetch HTTP %s for tag=%s page=%s after %s keys — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    response.status_code,
                    tag,
                    page,
                    len(keys),
                )
                break
            try:
                data = response.json()
            except ValueError:
                logger.warning(
                    "MISP cross-event prefetch non-JSON response for tag=%s page=%s after %s keys — "
                    "preserving partial keyset, degrading to per-event for remainder",
                    tag,
                    page,
                    len(keys),
                )
                break
            resp = data.get("response", data)
            attrs: List = []
            if isinstance(resp, list):
                attrs = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    attrs = raw
                elif isinstance(raw, dict):
                    attrs = [raw]
            for a in attrs:
                if not isinstance(a, dict):
                    continue
                t = a.get("type")
                v = a.get("value")
                if t is not None and v is not None and str(v).strip():
                    key = _dedup_key(str(t), str(v))
                    keys.add(key)
                    if stored_copy_of is not None and key in stored_copy_of:
                        _note_stored_copy(stored_copy_of, key, a)
            if len(attrs) < page_limit:
                if listing_complete is not None:
                    listing_complete[tag] = True
                break
            page += 1
        else:
            # 2026-10: the page cap ended the listing, not MISP's last page: the keys are partial.
            logger.warning(
                "MISP cross-event prefetch for tag=%s stopped at the page cap (%s pages of %s) after %s keys — "
                "the listing is incomplete",
                tag,
                max_pages,
                page_limit,
                len(keys),
            )
        if keys:
            logger.info(
                "MISP cross-event prefetch tag=%s: %s existing keys (will skip duplicates at push time — PR-F7)",
                tag,
                len(keys),
            )
        return keys

    def _get_existing_attribute_keys(self, event_id: str) -> set:
        """
        Build a set of (MISP attribute type, value) already on the event.

        Used to avoid re-posting the same indicator when collectors re-run or incremental
        windows overlap. MISP does not dedupe across different events (e.g. different days).
        The result is a ``_PrefetchedKeys``: ``complete`` is False when the listing stopped early or the
        prefetch is off (2026-10, read by the event split).
        """
        if not MISP_PREFETCH_EXISTING_ATTRS:
            return _PrefetchedKeys(complete=False)
        eid = sanitize_value(str(event_id), max_length=20)
        if not eid:
            return _PrefetchedKeys(complete=False)
        keys: set = set()
        complete = False
        page = 1
        page_limit = 5000
        max_pages = 200
        while page <= max_pages:
            try:
                response = self.session.post(
                    f"{self.url}/attributes/restSearch",
                    json={
                        "returnFormat": "json",
                        "eventid": eid,
                        "page": page,
                        "limit": page_limit,
                    },
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2),
                )
            except _TRANSIENT_HTTP_ERRORS:
                raise
            except Exception as ex:
                logger.warning("MISP attributes/restSearch failed for event %s page %s: %s", eid, page, ex)
                break
            if response.status_code != 200:
                logger.warning(
                    "MISP attributes/restSearch HTTP %s for event %s — skipping prefetch",
                    response.status_code,
                    eid,
                )
                break
            try:
                data = response.json()
            except ValueError:
                break
            resp = data.get("response", data)
            attrs: List = []
            if isinstance(resp, list):
                attrs = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    attrs = raw
                elif isinstance(raw, dict):
                    attrs = [raw]
            for a in attrs:
                if not isinstance(a, dict):
                    continue
                t = a.get("type")
                v = a.get("value")
                if t is not None and v is not None and str(v).strip():
                    keys.add(_dedup_key(str(t), str(v)))
            if len(attrs) < page_limit:
                complete = True
                break
            page += 1
        if keys:
            logger.debug("MISP event %s: prefetched %s existing attribute keys", eid, len(keys))
        return _PrefetchedKeys(keys, complete=complete, failed=not complete)

    def index_source_attributes(
        self, source_tag: str, attr_type: str, *, keep_meta: bool = False
    ) -> Dict[str, List[KnownAttribute]]:
        """Every ``attr_type`` attribute MISP holds under ``source_tag``, by upper-case value.

        NVD incremental runs (2026-10) use it to tell a new CVE from a known one and to compare a
        known CVE with NVD's current record. Each attribute keeps its uuid, event, tag names and a
        digest of its ``NVD_META`` comment; the comments themselves are not kept (the 140,000 NVD
        attributes of the 730-day baseline carry about 0.5 GB of them). Each also keeps its MISP
        ``timestamp`` and whether its event is one EdgeGuard created (``Event.info`` starting with
        ``EdgeGuard-``, the rule of the indicator refresh), and, with ``keep_meta`` (KEV runs, about
        1,800 attributes; 2026-10), its parsed ``NVD_META``.

        Unlike the duplicate prefetch, which degrades to a partial key set, this listing is complete
        or the call fails: a CVE missing from a partial listing would be pushed again as new.
        Raises ``MispTransientError`` (timeout, connection error, HTTP 429 or 5xx after retries) or
        ``MispLookupError`` (any other unusable answer).
        """
        tag = (source_tag or "").strip()
        if not tag:
            raise MispLookupError("index_source_attributes needs a source tag")
        index: Dict[str, List[KnownAttribute]] = {}
        page = 1
        page_limit = 5000
        max_pages = 400
        listed = 0
        while True:
            if page > max_pages:
                raise MispLookupError(
                    f"MISP lists more than {max_pages * page_limit} {attr_type} attributes under {tag}; listing stopped"
                )
            response = self._post_with_retries(
                f"{self.url}/attributes/restSearch",
                # includeAllTags: a tag marked not exportable in MISP is listed too, so a stored copy
                # that has it is not taken for one that lacks it.
                {
                    "returnFormat": "json",
                    "tags": [tag],
                    "type": attr_type,
                    "page": page,
                    "limit": page_limit,
                    "includeAllTags": True,
                },
                context=f"attribute listing {tag} page {page}",
            )
            if response.status_code != 200:
                raise MispLookupError(
                    f"MISP attributes/restSearch for {tag} page {page} answered HTTP {response.status_code}"
                )
            try:
                data = response.json()
            except ValueError as e:
                raise MispLookupError(f"MISP attributes/restSearch for {tag} page {page} is not JSON") from e
            resp = data.get("response", data) if isinstance(data, dict) else data
            attrs: List = []
            if isinstance(resp, list):
                attrs = resp
            elif isinstance(resp, dict):
                raw = resp.get("Attribute")
                if isinstance(raw, list):
                    attrs = raw
                elif isinstance(raw, dict):
                    attrs = [raw]
            for attr in attrs:
                if not isinstance(attr, dict):
                    continue
                value = str(attr.get("value") or "").strip().upper()
                uuid = str(attr.get("uuid") or "").strip()
                if not value or not uuid:
                    continue
                tags = tuple(
                    sorted(str(t.get("name")) for t in attr.get("Tag") or [] if isinstance(t, dict) and t.get("name"))
                )
                meta = nvd_meta_of_comment(attr.get("comment"))
                try:
                    written: Optional[float] = float(attr.get("timestamp"))
                except (TypeError, ValueError):
                    written = None
                event = attr.get("Event")
                info = event.get("info") if isinstance(event, dict) else None
                index.setdefault(value, []).append(
                    KnownAttribute(
                        uuid=uuid,
                        event_id=str(attr.get("event_id") or ""),
                        meta_digest=nvd_meta_digest(meta) if meta is not None else None,
                        tags=tags,
                        written=written,
                        own_event=isinstance(info, str) and info.startswith(_OWN_EVENT_PREFIX),
                        meta=meta if keep_meta else None,
                    )
                )
                listed += 1
            if len(attrs) < page_limit:
                break
            page += 1
        logger.info("MISP: %d %s attribute(s) under %s (%d distinct values)", listed, attr_type, tag, len(index))
        return index

    def existing_values(self, source_tag: str, attr_type: str, values: Sequence[str]) -> set:
        """Which of *values* MISP holds as ``attr_type`` attributes under ``source_tag`` (upper-case).

        Asked by value, 500 at a time (2026-10, to confirm NVD additions MISP's answers did not
        confirm). Raises ``MispTransientError`` / ``MispLookupError`` like ``index_source_attributes``.
        """
        rows = self._attributes_by_value({"tags": [source_tag], "type": attr_type}, values, f"{attr_type} value(s)")
        found = {str(r.get("value") or "").strip().upper() for r in rows}
        found.discard("")
        return found

    def _attributes_by_value(
        self, filters: Dict[str, Any], values: Sequence[str], what: str, until: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """The attribute rows ``attributes/restSearch`` answers for *values* under *filters*, asked 500
        values at a time, 2,000 rows a page. Raises ``MispTransientError`` / ``MispLookupError``.
        *until*: see ``_post_with_retries`` (2026-11-03)."""
        found: List[Dict[str, Any]] = []
        wanted = [str(v) for v in values if str(v or "").strip()]
        for i in range(0, len(wanted), 500):
            chunk = wanted[i : i + 500]
            page = 1
            while True:
                response = self._post_with_retries(
                    f"{self.url}/attributes/restSearch",
                    {"returnFormat": "json", **filters, "value": chunk, "page": page, "limit": 2000},
                    context=f"lookup of {len(chunk)} {what}",
                    until=until,
                )
                if response.status_code != 200:
                    raise MispLookupError(f"MISP attributes/restSearch by value answered HTTP {response.status_code}")
                try:
                    data = response.json()
                except ValueError as e:
                    raise MispLookupError("MISP attributes/restSearch by value is not JSON") from e
                resp = data.get("response", data) if isinstance(data, dict) else data
                rows = resp.get("Attribute", []) if isinstance(resp, dict) else resp
                rows = rows if isinstance(rows, list) else [rows]
                found.extend(r for r in rows if isinstance(r, dict))
                if len(rows) < 2000:
                    break
                page += 1
        return found

    def _stored_after_server_error(
        self, event_id: str, attributes: List[Dict], until: Optional[float] = None
    ) -> Optional[Tuple[int, List[Dict]]]:
        """Which attributes of a batch MISP stored although it answered the push with HTTP 5xx (2026-11-02).

        MISP answers an event edit with the whole event (``_push_batch``). An event too large for its PHP
        ``memory_limit`` to hold in that answer is saved first and then fails with HTTP 500, so the status
        says nothing about the data: on 1 Nov 2026, with 2 GB, every batch pushed to an OTX event past about
        148,800 attributes answered 500 and was stored, and re-sending it cost four retries and a cooldown.
        The batch's values are therefore looked up in the event (``attributes/restSearch`` by value, with
        the lower- and upper-case forms of the types MISP changes in case) and matched as a 200 answer is
        (``_attribute_match_key``). Returns ``(stored count, unstored attributes)``, or None when the lookup
        fails (then nothing is known and the batch is retried as before).

        2026-11-03, *until* (a ``time.monotonic()`` value, or None): the time left of the push's cap on failure
        time (``_failing_streak``). The lookup gets no more (``_post_with_retries``); with none left it is not
        made and None is returned, so the batch counts as failed when its retries end there.
        """
        if until is not None and time.monotonic() >= until:
            logger.warning(
                "MISP push to event %s: no lookup of the batch after the server error, the push's cap on failure "
                "time has no time left — the batch counts as not stored",
                event_id,
            )
            return None
        values: set = set()
        for attribute in attributes:
            value = str(attribute.get("value") or "").strip()
            if not value:
                continue
            values.add(value)
            if str(attribute.get("type") or "").strip().lower() in _CASE_NORMALISED_TYPES:
                values.update((value.lower(), value.upper()))
        try:
            rows = self._attributes_by_value(
                {"eventid": event_id}, sorted(values), f"value(s) of event {event_id}", until=until
            )
        except (MispLookupError, *_TRANSIENT_HTTP_ERRORS) as e:
            logger.warning(
                "MISP push to event %s: lookup of the batch after the server error failed (%s: %s) — retrying the batch",
                event_id,
                type(e).__name__,
                e,
            )
            return None
        present = {key for key in (_attribute_match_key(r) for r in rows) if key is not None}
        unstored = [a for a in attributes if _attribute_match_key(a) not in present]
        return len(attributes) - len(unstored), unstored

    def _post_with_retries(
        self, url: str, payload: Dict[str, Any], *, context: str, attempts: int = 3, until: Optional[float] = None
    ):
        """POST *payload*; a timeout, connection error, HTTP 429 or 5xx is retried (5 s, then 10 s).

        Returns the response of the first attempt that is not transient. Raises
        ``MispTransientError`` when every attempt was.

        2026-11-03, *until* (a ``time.monotonic()`` value, or None): the lookups after a 5xx inside a push get only
        the time left of the push's cap on failure time (``_stored_after_server_error``). No attempt or pause
        starts at or after it, and each attempt's timeouts are at most the time left; then it raises
        ``MispTransientError`` as after the last attempt.
        """
        last_problem = ""
        made = 0
        for attempt in range(attempts):
            timeout: Tuple[float, float] = (self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2)
            if until is not None:
                left = until - time.monotonic()
                if left <= 0:
                    last_problem = f"{last_problem}; " if last_problem else ""
                    last_problem += "no time left of the push's cap on failure time"
                    break
                timeout = (min(timeout[0], left), min(timeout[1], left))
            made += 1
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    verify=self.verify_ssl,
                    timeout=timeout,
                )
            except _TRANSIENT_HTTP_ERRORS as e:
                last_problem = f"{type(e).__name__}: {e}"
            else:
                if response.status_code != 429 and response.status_code < 500:
                    return response
                last_problem = f"HTTP {response.status_code}"
            logger.warning("MISP %s: %s (attempt %d of %d)", context, last_problem, attempt + 1, attempts)
            if attempt + 1 < attempts:
                pause = 5.0 * (2**attempt)
                if until is not None and time.monotonic() + pause >= until:
                    last_problem += "; no time left of the push's cap on failure time for another attempt"
                    break
                time.sleep(pause)
        raise MispTransientError(f"MISP {context} failed after {made} attempt(s): {last_problem}")

    @retry_with_backoff(max_retries=4, base_delay=10.0, give_up=_misp_retry_gives_up)
    def _get_or_create_event(
        self, source: str, date: str = None, part: int = 1, *, reports: bool = False, **_kwargs
    ) -> Optional[str]:
        """Get or create a MISP event for a source/date combination.

        Event naming: ``EdgeGuard-{source}-{date}``, ``-part{N}`` appended from part 2 (2026-10,
        ``_event_split_above``); with *reports* (2026-11-07) the companion event of the day's report records,
        ``EdgeGuard-{source}-{date}-reports`` (``push_reports``).  Zone classification lives
        on attribute-level tags (``zone:Finance``, ``zone:Healthcare``), not in
        the event name — a single event can contain multi-zone attributes.

        Uses MISP's ``restSearch`` endpoint, then filters to an **exact** ``Event.info`` match.
        Event **creation** is serialized with a file lock so two processes do not
        create duplicate same-day events after a miss.

        Returns:
            Event ID if successful, None otherwise.
        """
        source = sanitize_value(source, max_length=50)

        date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        event_name = _report_event_name(source, date) if reports else _event_name(source, date, part)

        try:
            rows = self._restsearch_events_for_name(event_name)
            exact = _event_id_exact_from_restsearch_rows(rows, event_name)
            if exact:
                self._note_event_size(exact, _event_attribute_count_from_restsearch_rows(rows, event_name))
                return exact
        except _TRANSIENT_HTTP_ERRORS:
            raise
        except Exception as e:
            # A lookup that failed for a non-transient reason must not fall through to event
            # creation: the same-day event may exist and a second one would duplicate it. The
            # batch is reported as failed by the caller (push_items counts a missing event id).
            logger.error("Event lookup for %r failed (%s: %s) — no event is created", event_name, type(e).__name__, e)
            return None

        # MISP is the single store every collector writes to and the store the knowledge graph is
        # built from (FIRST EPSS scores on existing CVE nodes are the one feed written to Neo4j
        # directly). Distribution 1 is MISP's "This community only": every organisation on this
        # MISP instance can read the event (0 would be "Your organisation only"). EdgeGuard does not
        # publish the events, so MISP server synchronisation and feeds do not forward them to other
        # instances.
        event_data = {
            "Event": {
                "info": event_name,
                "distribution": 1,  # This community only (see above)
                "threat_level_id": 3,  # Low
                "analysis": 0,  # Initial
                "date": date,
                "Attribute": [],
                # Event is an organizational container: ``EdgeGuard-{source}-{date}`` (``-part<N>``) groups
                # by source + day.  Zone classification lives on **attributes** (``zone:…`` tags)
                # so multi-zone items are handled correctly.  The single event tag marks the
                # events EdgeGuard wrote (provenance inside this MISP instance).
                "Tag": [{"name": "EdgeGuard"}],
            }
        }

        try:
            with _cross_process_event_creation_lock():
                rows2 = self._restsearch_events_for_name(event_name)
                exact2 = _event_id_exact_from_restsearch_rows(rows2, event_name)
                if exact2:
                    self._note_event_size(exact2, _event_attribute_count_from_restsearch_rows(rows2, event_name))
                    return exact2

                response = self.session.post(
                    f"{self.url}/events",
                    json=event_data,
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
                )

                if response.status_code in (200, 201):
                    result = response.json()
                    ev = result.get("Event") or {}
                    event_id = ev.get("id")
                    created_info = ev.get("info")
                    if created_info and str(created_info) != event_name:
                        logger.error(
                            "MISP created event info mismatch: expected %r got %r (id=%s)",
                            event_name,
                            created_info,
                            event_id,
                        )
                    if event_id:
                        self.stats["events_created"] += 1
                        self._note_event_size(str(event_id), 0)
                        logger.info(f"Created MISP event: {event_name} (ID: {event_id})")
                        return str(event_id)
                    return None
                logger.error(f"Failed to create event: {response.status_code} - {response.text}")
                self.stats["errors"] += 1
                return None

        except _TRANSIENT_HTTP_ERRORS:
            raise
        except Exception as e:
            logger.error(f"Event creation error: {e}")
            self.stats["errors"] += 1
            return None

    @retry_with_backoff(max_retries=4, base_delay=10.0, give_up=_misp_retry_gives_up)
    def _find_event_id(self, event_name: str) -> Optional[str]:
        """The id of the event named exactly ``event_name``, or None; never creates one. Notes the
        event's ``attribute_count`` (``_note_event_size``)."""
        rows = self._restsearch_events_for_name(event_name)
        event_id = _event_id_exact_from_restsearch_rows(rows, event_name)
        if event_id:
            self._note_event_size(event_id, _event_attribute_count_from_restsearch_rows(rows, event_name))
        return event_id

    def _note_event_size(self, event_id: str, count: Optional[int]) -> None:
        """Remember the ``attribute_count`` an event lookup answered (2026-10, the size of a part for the
        event split; ``__dict__`` because some tests build the writer without ``__init__``)."""
        sizes = self.__dict__.setdefault("_event_sizes", {})
        if count is None:
            sizes.pop(str(event_id), None)  # each lookup is authoritative: no size kept from an earlier one
        else:
            sizes[str(event_id)] = count

    def _list_part(self, event_id: str) -> set:
        """``_get_existing_attribute_keys`` for a later part of the event split (2026-10). A network error
        does not abort the push: the part's listing counts as failed, so its size comes from its
        ``attribute_count`` (or it counts as full) and the dedup degrades as for an incomplete listing."""
        try:
            return self._get_existing_attribute_keys(event_id)
        except _TRANSIENT_HTTP_ERRORS as e:
            logger.warning(
                "Listing of MISP event %s failed (%s: %s) — sized by its attribute_count", event_id, type(e).__name__, e
            )
            return _PrefetchedKeys(complete=False, failed=True)

    def _part_size(self, event_id: str, keys: Optional[set], cap: int) -> int:
        """Attributes the event holds, for the event split (2026-10): the larger of its prefetched keys and
        the ``attribute_count`` its lookup answered. An event whose listing failed and whose lookup gave no
        count counts as full (``cap``), so a MISP error never sends a full part another cap; with the
        prefetch off and no count, the size is unknown and counts as 0: the event takes up to one more limit."""
        counted = self.__dict__.get("_event_sizes", {}).get(str(event_id))
        listed = len(keys) if keys is not None else 0
        if keys is not None and getattr(keys, "complete", True):
            return max(listed, counted or 0)
        if counted is not None:
            return max(listed, counted)
        if keys is None or getattr(keys, "failed", False):
            return cap
        return listed

    def _find_later_parts(self, source: str, date: str, part_ids: List[str]) -> Tuple[List[str], bool]:
        """``part_ids`` with the ids of the ``-part2``, ``-part3`` ... events of the source/date that exist,
        and whether the walk reached the first missing part (2026-10).

        Each lookup notes the part's ``attribute_count``. A failed lookup ends the walk at the parts found
        so far and returns False: no part is created then, since the one the lookup missed may exist.
        """
        source = sanitize_value(source, max_length=50)
        date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        parts = list(part_ids)
        try:
            while True:
                nxt = self._find_event_id(_event_name(source, date, len(parts) + 1))
                if not nxt:
                    return parts, True
                parts.append(nxt)
        except Exception as e:
            logger.warning(
                "Lookup of part %d of %r failed (%s: %s) — no later part is created in this push",
                len(parts) + 1,
                _event_name(source, date),
                type(e).__name__,
                e,
            )
            return parts, False

    def _get_zones_to_tag(self, item: Dict) -> List[str]:
        """
        Determine which zone tags to apply based on the new equal-importance logic.

        Rules:
        - All detected specific zones (healthcare, energy, finance) are equal - tag ALL
        - Global is special:
          * If specific zones + global detected → tag only specific zones (global is implicit)
          * If ONLY global detected → tag global as primary

        Args:
            item: EdgeGuard item dict with 'zone' key (now an array)

        Returns:
            List of zone names to tag
        """
        # Get zones array (zone is now always an array)
        zones = item.get("zone", ["global"])
        if not isinstance(zones, list):
            zones = [zones] if zones else ["global"]

        # Filter logic:
        # - If 'global' in zones AND other zones exist: exclude 'global' (it's implicit)
        # - If ONLY 'global' in zones: keep 'global'
        # - Otherwise: keep all zones
        specific_zones = [z for z in zones if z and z != "global"]

        if specific_zones:
            # We have specific zones - tag them all equally
            return specific_zones
        else:
            # Only global - tag it (or fallback to default)
            global_zones = [z for z in zones if z]
            return global_zones if global_zones else [DEFAULT_SECTOR]

    def map_indicator_type(self, edgeguard_type: str, value: str = None) -> str:
        """
        Map EdgeGuard indicator type to MISP attribute type.

        Args:
            edgeguard_type: EdgeGuard type string
            value: Optional value for additional type detection

        Returns:
            MISP attribute type string
        """
        # A generic "hash" carries MD5, SHA1, SHA256 or SHA512 values (the OTX collector maps every
        # FileHash-* indicator to "hash"). Pick the MISP type from the digest length, because MISP
        # answers HTTP 200 and silently drops an attribute whose value does not fit its type.
        if edgeguard_type == "hash" and value:
            digest = value.strip()
            if all(c in "0123456789abcdefABCDEF" for c in digest):
                by_length = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
                if len(digest) in by_length:
                    return by_length[len(digest)]

        # Direct mapping
        if edgeguard_type in self.TYPE_MAPPING:
            return self.TYPE_MAPPING[edgeguard_type]

        # Try to detect from value if type is unknown
        if value:
            val_lower = value.lower()

            # IP address detection
            parts = value.split(".")
            if len(parts) == 4:
                try:
                    if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        return "ip-dst"
                except (ValueError, TypeError):
                    pass

            # Hash detection
            if len(value) in [32, 40, 64, 128] and all(c in "0123456789abcdefABCDEF" for c in value):
                if len(value) == 32:
                    return "md5"
                elif len(value) == 40:
                    return "sha1"
                elif len(value) == 64:
                    return "sha256"
                else:
                    return "sha512"

            # CVE detection
            if val_lower.startswith("cve-"):
                return "vulnerability"

            # URL detection
            if val_lower.startswith(("http://", "https://")):
                return "url"

            # Email detection
            if "@" in value and "." in value:
                return "email-src"

            # Domain detection
            if "." in value and not val_lower.isdigit():
                return "domain"

        return "text"

    def create_attribute(self, indicator: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard indicator.

        Args:
            indicator: EdgeGuard indicator dict with keys like:
                      indicator_type, value, zone, tag, sources, etc.

        Returns:
            MISP attribute dict or None
        """
        ind_type = indicator.get("indicator_type", "unknown")
        value = indicator.get("value")

        if not value:
            return None

        # Sanitize the value
        value = sanitize_value(value, max_length=1024)
        if not value:
            return None

        misp_type = self.map_indicator_type(ind_type, value)

        # Build tags for attribute
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(indicator)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = indicator.get("tag", "unknown")
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(indicator))  # 2026-10: TLP on every attribute

        # Add confidence tag
        confidence = indicator.get("confidence_score", 0.5)
        if confidence >= 0.8:
            tags.append("confidence:high")
        elif confidence >= 0.5:
            tags.append("confidence:medium")
        else:
            tags.append("confidence:low")

        # PR (S5) (bugbot HIGH): the first_seen / last_seen
        # passthrough previously inlined here has been consolidated into
        # the ``_apply_source_truthful_timestamps`` helper below
        # (applied uniformly across all 7 create_*_attribute methods).

        # Encode rich metadata as JSON comment for sources with structured data
        # (same pattern as NVD_META for vulnerabilities).
        # 2026-10 (regular-update linking, found while testing): OTX_META used to be written only when the
        # pulse carried ATT&CK ids or targeted countries — an OTX IOC from any other pulse lost its
        # pulse_id / report_ids (so the sync could not group it) and now its families / adversaries.
        # Any pulse-level field marks an OTX indicator.
        pulse_copies = pulse_copies_allowed(indicator.get("pulse_tlp"))
        has_otx_meta = any(
            indicator.get(k)
            for k in (
                "attack_ids",
                "targeted_countries",
                "pulse_id",
                "report_ids",
                "pulse_malware_families",
                "pulse_malware_actor_pairs",
                "several_actor_pulses",
                "several_actor_pulses_by_name",
            )
        )
        has_tf_meta = bool(
            indicator.get("malware_malpedia")
            or indicator.get("reference")
            or indicator.get("tags")
            or any(indicator.get(_k) for _k in _TF_META_OPTIONAL_STRINGS + _TF_META_OPTIONAL_LISTS)
            or _tf_meta_source_fields(indicator)
        )

        if has_otx_meta:
            otx_meta = {
                "attack_ids": indicator.get("attack_ids", []),
                "targeted_countries": indicator.get("targeted_countries", []),
                "pulse_tags": indicator.get("pulse_tags", []),
                "pulse_references": indicator.get("pulse_references", []),
                "pulse_author": indicator.get("pulse_author", ""),
                "pulse_tlp": indicator.get("pulse_tlp", ""),
                "otx_industries": indicator.get("otx_industries", []),
                "description": indicator.get("description", ""),
                "pulse_name": indicator.get("pulse_name", ""),
                # PR-N10 Fix #3 (2026-04-21) added ``malware_family`` and
                # ``attributed_to`` to OTX_META, as TF_META carries them.
                # 2026-10: both are kept for compatibility and are always
                # empty: the OTX collector puts neither key on an indicator.
                # The families a pulse names travel as ``mf`` and its
                # family/adversary pairs as ``pa`` (below); the sync reads
                # them into ``pulse_malware_families`` /
                # ``pulse_malware_actor_pairs``, which build_relationships
                # steps 9b and 2d link. Q9 reads ``Indicator.malware_family``
                # only, so OTX is no family-label feed
                # (``relationship_provenance.FAMILY_LABEL_FEEDS``).
                "malware_family": indicator.get("malware_family", ""),
                "attributed_to": indicator.get("attributed_to", ""),
                # PR-N13 (2026-04-21 pre-baseline audit Fix #5): preserve
                # ``pulse_id`` (OTX native pulse UUID — the stable
                # cross-deployment dedup key for re-sync against OTX),
                # ``indicator_role`` (e.g. "C2" / "dropper" — drives
                # MITRE-killchain mapping and is LIVE-WIRED at
                # ``neo4j_client.merge_indicators_batch:~L2169`` which
                # currently reads None because OTX_META never carried
                # it), and ``is_active`` (source-side activity state).
                # All three were emitted by
                # ``otx_collector.py:462,479-488`` and silently dropped
                # on the MISP round-trip.
                "pulse_id": indicator.get("pulse_id", ""),
                # 2026-10: other pulses of the same run that listed this IOC (collector
                # dedup) — the sync pairs the IOC with the malware/actors of all of them.
                "report_ids": [str(x)[:64] for x in (indicator.get("report_ids") or []) if x][:_MAX_REPORT_IDS],
                # 2026-10-18: the zones the industries of those other pulses state, "<zone>|<pulse id>"
                # (``_report_stated_zones``); pruned below when empty.
                "report_stated_zones": _report_stated_zones(indicator),
                "indicator_role": indicator.get("indicator_role", ""),
                "is_active": indicator.get("is_active", True),
                # 2026-10 (regular-update linking): families named by the pulse(s) that listed this IOC and
                # the "family::adversary::pulse" pairs of the SAME pulse (Q9b / Q2d link from the indicator
                # side; the family attribute itself is a cross-event duplicate and is never re-pushed).
                # Pruned below when empty. Kept last: test_pr_n13 pins the key order inside a fixed window.
                # One pair per family and adversary (``_otx_meta_pairs``).
                "mf": [str(x)[:128] for x in (indicator.get("pulse_malware_families") or []) if x][:20],
                "pa": _otx_meta_pairs(indicator.get("pulse_malware_actor_pairs")),
                # 2026-10: the pulses that listed this IOC whose adversaries are several actors (the
                # sync attributes no malware from them and stores ``sap`` on the Indicator node, where
                # build_relationships step 2d reads it). ``sapn``: judged by name, without the canonical
                # reference; the sync uses it for its own run only, never stores it. When the comment is
                # over its budget, only the marks of the pulses still in pulse_id + report_ids are kept
                # (``_fit_meta_comment``).
                "sap": [str(x)[:64] for x in (indicator.get("several_actor_pulses") or []) if x][:_MAX_REPORT_IDS],
                "sapn": [str(x)[:64] for x in (indicator.get("several_actor_pulses_by_name") or []) if x][
                    :_MAX_REPORT_IDS
                ],
            }
            for _k in ("mf", "pa", "sap", "sapn", "report_stated_zones"):
                if not otx_meta.get(_k):
                    otx_meta.pop(_k, None)
            # 2026-11-07: an amber or red pulse, or one that states no known TLP, keeps its text in its report
            # record (MISP distribution 0): its copies are written empty, and ``pulse_id`` and ``pulse_tlp`` stay
            # for the sync's linking (``pulse_copies_allowed``).
            if not pulse_copies:
                for _k in PULSE_COPY_KEYS:
                    otx_meta[_k] = "" if _k == "pulse_name" else []
            comment = _fit_meta_comment("OTX_META:", otx_meta)
        elif has_tf_meta:
            tf_meta = {
                "malware_malpedia": indicator.get("malware_malpedia", ""),
                "reference": indicator.get("reference", ""),
                "tags": indicator.get("tags", []),
                "last_seen": _consistent_last_seen(indicator),
                "threat_type_desc": indicator.get("threat_type_desc", ""),
                "malware_family": indicator.get("malware_family", ""),
                "reporter": indicator.get("reporter", ""),
                # PR-N10 Fix #3: mirror OTX_META's new ``attributed_to``
                # so TF-sourced indicators also carry the attribution
                # hint through the MISP round-trip.
                "attributed_to": indicator.get("attributed_to", ""),
                # PR-N13 (2026-04-21 pre-baseline audit Fix #4): preserve
                # ``threat_type`` (payload / C2 / exfil category),
                # ``ioc_id`` (canonical ThreatFox ID — the stable
                # cross-system dedup key for re-ingest across daily
                # CSV exports), and ``malware_alias`` (alternate
                # names). All three were emitted by
                # ``global_feed_collector.py:240-243`` and silently
                # dropped here, losing ``ioc_id`` cross-day dedup.
                # Mirror of the OTX_META ``malware_family`` fix in
                # PR-N10 #3. No writer stores ``malware_alias`` as a
                # property (it is only in the SOURCED_FROM raw_data),
                # and no build_relationships step reads it (Q9 matches
                # the indicator's ``malware_family`` against the names
                # and aliases of the ``Malware`` nodes).
                "threat_type": indicator.get("threat_type", ""),
                "ioc_id": indicator.get("ioc_id", ""),
                "malware_alias": indicator.get("malware_alias", ""),
            }
            for _k in _TF_META_OPTIONAL_STRINGS:
                _v = indicator.get(_k)
                if _v:
                    tf_meta[_k] = str(_v)[:_TF_META_MAX_ITEM_CHARS]
            for _k in _TF_META_OPTIONAL_LISTS:
                _raw = indicator.get(_k)
                _vals = [
                    str(x)[:_TF_META_MAX_ITEM_CHARS] for x in (_raw if isinstance(_raw, (list, tuple)) else []) if x
                ]
                if _vals:
                    tf_meta[_k] = _vals[:_TF_META_MAX_LIST_ITEMS]
            # 2026-11-07: the list-source fields, then the time of the first report's time-variant values.
            tf_meta.update(_tf_meta_source_fields(indicator))
            if any(_k in tf_meta for _k in _TF_META_TIME_VARIANT):
                tf_meta["as_of"] = _tf_meta_as_of()
            comment = _fit_meta_comment("TF_META:", tf_meta)
        else:
            pulse_name = indicator.get("pulse_name") if pulse_copies else ""
            comment = sanitize_value(pulse_name or indicator.get("description", ""), max_length=255)

        attribute = {
            "type": misp_type,
            "value": value,
            # No max_length truncation when storing JSON — truncation would break JSON parsing.
            "comment": comment
            if (has_otx_meta or has_tf_meta or comment)
            else f"From {sanitize_value(source, max_length=50)}",
            # Detection flag: set for indicators unless the collector clears it for the item
            # (for example a Feodo Tracker server reported offline: history, not a blocking candidate).
            "to_ids": bool(indicator.get("to_ids", True)),
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): consolidated via helper so
        # the passthrough lives in ONE place — previously five of the
        # seven create_*_attribute methods silently dropped these fields.
        _apply_source_truthful_timestamps(attribute, indicator)

        return attribute

    def create_vulnerability_attribute(self, vuln: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard vulnerability.

        Args:
            vuln: EdgeGuard vulnerability dict with keys like:
                  cve_id, description, zone, tag, severity, etc.

        Returns:
            MISP attribute dict or None
        """
        cve_id = vuln.get("cve_id")
        if not cve_id:
            return None

        # Sanitize CVE ID
        cve_id = sanitize_value(cve_id, max_length=50)
        if not cve_id:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(vuln)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(vuln.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(vuln))  # 2026-10: TLP on every attribute

        # Add severity tag
        severity = sanitize_value(vuln.get("severity", "UNKNOWN"), max_length=20)
        if severity:
            tags.append(f"severity:{severity.lower()}")

        # CVSS rating tag, only when the item carries a CVSS score (2026-10). Every score below
        # 4.0 used to be tagged ``cvss:low``, including the 0 an unscored CVE carried, which the
        # sync read back as 3.0 / LOW; a real 0.0 is now ``cvss:none``.
        cvss_tag = cvss_rating_tag(vuln.get("cvss_score"), severity)
        if cvss_tag:
            tags.append(cvss_tag)

        # Add CISA KEV tag if from CISA source or if NVD entry has CISA KEV data
        if source in ["cisa", "cisa_kev"] or vuln.get("cisa_exploit_add"):
            tags.append("CISA-KEV")

            # Add ransomware tag if applicable
            ransomware = vuln.get("known_ransomware_use", "Unknown")
            if ransomware == "Known":
                tags.append("ransomware:known")

        description = sanitize_value(vuln.get("description", ""), max_length=200)
        vendor = sanitize_value(vuln.get("vendor", ""), max_length=100)
        product = sanitize_value(vuln.get("product", ""), max_length=100)

        # For NVD-sourced CVEs, embed the rich metadata as JSON so the MISP→Neo4j
        # pipeline can reconstruct the full CVE/CVSS graph without calling NVD again.
        # The prefix "NVD_META:" acts as a sentinel for the reader.
        nvd_fields = {
            "published": vuln.get("published", ""),
            "last_modified": vuln.get("last_modified", ""),
            "cwe": vuln.get("cwe", []),
            "ref_tags": vuln.get("ref_tags", []),
            "reference_urls": vuln.get("reference_urls", []),
            "cpe_type": vuln.get("cpe_type", []),
            "result_impacts": vuln.get("result_impacts", []),
            "affected_products": vuln.get("affected_products", []),
            # 2026-10: NVD's word for the attack vector of the CVSS that gives the score, null without
            # one (``cvss_selection``); it was "UNKNOWN" for an item without one. The sync derives the
            # attack vector from the CVSS payloads below and does not read this key.
            "attack_vector": normalize_attack_vector(vuln.get("attack_vector")),
            "cvss_v40_data": vuln.get("cvss_v40_data"),
            "cvss_v31_data": vuln.get("cvss_v31_data"),
            "cvss_v30_data": vuln.get("cvss_v30_data"),
            "cvss_v2_data": vuln.get("cvss_v2_data"),
            "description": vuln.get("description", ""),
            "vendor": vendor,
            "product": product,
            # CISA KEV exploitability intelligence
            "cisa_exploit_add": vuln.get("cisa_exploit_add", ""),
            "cisa_action_due": vuln.get("cisa_action_due", ""),
            "cisa_required_action": vuln.get("cisa_required_action", ""),
            "cisa_vulnerability_name": vuln.get("cisa_vulnerability_name", ""),
            # 2026-10: CISA's knownRansomwareCampaignUse ("Known" / "Unknown"), KEV records only.
            # It used to become a 9.0 / 7.0 score; the ``ransomware:known`` tag never reached Neo4j.
            "known_ransomware_use": vuln.get("known_ransomware_use", ""),
            # PR-N13 (2026-04-21 pre-baseline audit Fix #3): preserve
            # ``version_constraints`` (up to 10 per-CPE range entries)
            # and ``status`` (active / rejected list) through the MISP
            # round-trip. Pre-PR-N13 both fields were emitted by
            # ``nvd_collector.py`` (version_constraints at line 975,
            # status at lines 892+924) but OMITTED here, so every
            # NVD CVE reached Neo4j with ``version_constraints=None``
            # and ``status=default``. ``neo4j_client.merge_cve``
            # already consumes both fields when present (live
            # JSON-serialize logic at ~line 2389-2431); this closes
            # the collector-side drop so Neo4j actually sees them.
            # ``status=["rejected"]`` is especially important — a
            # withdrawn/duplicate CVE otherwise silently lands as if
            # active, polluting downstream triage queues.
            "version_constraints": vuln.get("version_constraints", []),
            "status": vuln.get("status", []),
            # 2026-10: CISA's SSVC decision points from NVD's record (``nvd_collector.cisa_ssvc``):
            # {"exploitation", "automatable", "technical_impact", "version", "timestamp"} or None.
            "ssvc": vuln.get("ssvc"),
        }
        # 2026-10-16: a CISA ICS record's advisory ids, CISA's own sector names (all 16, not only the
        # three mapped to zones) and the zones of each advisory, so the graph can name the advisories
        # behind a sector (``cisa_ics:<id>``, only those that name it) and keep CISA's words. Only when
        # the item carries them: NVD and KEV records get no new key, so their NVD_META (and its digest,
        # ``nvd_meta_digest``) is unchanged.
        advisory_ids = _bounded_strings(vuln.get("advisory_ids"), _MAX_ADVISORY_IDS, _MAX_ADVISORY_ID_CHARS)
        if advisory_ids:
            nvd_fields["advisory_ids"] = advisory_ids
        advisory_zones = _bounded_advisory_zones(vuln.get("advisory_zones"), advisory_ids)
        if advisory_zones:
            nvd_fields["advisory_zones"] = advisory_zones
        ics_sectors = _bounded_strings(vuln.get("ics_sectors"), _MAX_ICS_SECTORS, _MAX_ICS_SECTOR_CHARS)
        if ics_sectors:
            nvd_fields["ics_sectors"] = ics_sectors
        has_nvd_meta = any(
            [
                nvd_fields["published"],
                nvd_fields["cwe"],
                nvd_fields["cvss_v40_data"],
                nvd_fields["cvss_v31_data"],
                nvd_fields["cvss_v30_data"],
                nvd_fields["cvss_v2_data"],
                # KEV marker round-trip (2026-06): CISA-collector CVEs carry
                # cisa_exploit_add but none of the NVD enrichment fields above,
                # so the META comment was skipped and the KEV marker silently
                # dropped between MISP and Neo4j (480 KEV-only CVEs on the
                # 2026-04 baseline had no queryable KEV property). The KEV date
                # alone now qualifies the attribute for the META carrier.
                nvd_fields["cisa_exploit_add"],
                # 2026-10-16: a CISA ICS record without ``published`` still carries its advisories.
                nvd_fields.get("advisory_ids"),
            ]
        )

        # 2026-10-18: a CVE an OTX pulse names (the collector's ``cve_references`` item, which carries the
        # pulse metadata) is written with an ``OTX_META`` block holding the pulse (``pulse_id``, the other
        # pulses of the run in ``report_ids``, ``pulse_name``), as an OTX indicator of type CVE already is
        # (``create_attribute``). The sync groups the CVE into its report from it and links the report's
        # indicators to it (Indicator -> INDICATES -> CVE, ``otx_pulse``). The comment was the note
        # "Referenced in OTX pulse: <name>", which named no pulse id, so the CVE joined no report.
        otx_pulse_meta = _cve_pulse_meta(vuln)

        if has_nvd_meta:
            import json as _json

            comment = "NVD_META:" + _json.dumps(nvd_fields, default=str)
        elif otx_pulse_meta:
            comment = _fit_meta_comment("OTX_META:", otx_pulse_meta)
        else:
            comment_parts = []
            if vendor:
                comment_parts.append(f"Vendor: {vendor}")
            if product:
                comment_parts.append(f"Product: {product}")
            if description:
                comment_parts.append(description)
            comment = " | ".join(comment_parts) if comment_parts else f"CVE from {source}"

        attribute = {
            "type": "vulnerability",
            "value": cve_id.upper(),
            # No max_length truncation when storing JSON — truncation would break JSON parsing.
            "comment": comment if (has_nvd_meta or otx_pulse_meta) else sanitize_value(comment, max_length=500),
            "to_ids": False,  # CVEs don't make good IDS indicators
            "Tag": [{"name": tag} for tag in tags],
        }

        _apply_source_truthful_timestamps(attribute, vuln)
        return attribute

    def plan_vulnerability_update(
        self,
        vuln: Dict,
        known: Sequence[KnownAttribute],
        *,
        replaced_tags: Sequence[str] = _REPLACED_VULNERABILITY_TAG_PREFIXES,
    ) -> List[Tuple[KnownAttribute, Dict[str, Any]]]:
        """The edits that bring MISP's stored copies of a CVE in line with the vulnerability item.

        The item is turned into the attribute a new push would write (``create_vulnerability_attribute``)
        and compared with each stored copy: ``NVD_META`` by digest (``nvd_meta_digest``, so a change
        only to ``last_modified`` needs no edit) and the tags by family (``_vulnerability_tag_changes``;
        ``replaced_tags`` names the families and tags an edit replaces, ``KEV_REPLACED_TAGS`` for KEV,
        2026-10). Each copy that differs gets one edit: the new comment, ``first_seen`` /
        ``last_seen``, and the tags to attach or detach. Empty when every copy matches.
        """
        attribute = self.create_vulnerability_attribute(vuln)
        if not attribute:
            return []
        comment = str(attribute.get("comment") or "")
        digest = _nvd_meta_digest_of_comment(comment)
        desired_tags = [
            str(tag["name"]) for tag in attribute.get("Tag", []) if isinstance(tag, dict) and tag.get("name")
        ]
        plans: List[Tuple[KnownAttribute, Dict[str, Any]]] = []
        for stored in known:
            attach, detach = _vulnerability_tag_changes(stored.tags, desired_tags, replaced_tags)
            if stored.meta_digest == digest and not attach and not detach:
                continue
            changes: Dict[str, Any] = {"comment": comment}
            for key in ("first_seen", "last_seen"):
                if attribute.get(key):
                    changes[key] = attribute[key]
            tag_changes = [{"name": tag} for tag in attach] + [{"name": tag, "deleted": True} for tag in detach]
            if tag_changes:
                changes["Tag"] = tag_changes
            plans.append((stored, changes))
        return plans

    def update_attribute(self, uuid: str, changes: Dict[str, Any], *, written_after: Optional[float] = None) -> bool:
        """Edit one attribute in place (``POST /attributes/edit/{uuid}``); True when MISP shows the edit.

        MISP 2.5 saves the attribute with a new timestamp and moves its event's timestamp
        (``AttributesController::edit`` → ``unpublishEvent``), so the incremental MISP → Neo4j sync
        picks the change up. Tags in ``changes["Tag"]`` are attached, those marked ``deleted``
        detached. A timeout, connection error, HTTP 429 or 5xx is retried twice; MISP's answer must
        then show the new comment, ``last_seen`` and tag changes, and, when ``written_after`` is
        given, an attribute timestamp later than it (2026-10), or the edit counts as failed.
        """
        uid = sanitize_value(str(uuid), max_length=64)
        if not uid:
            return False
        try:
            response = self._post_with_retries(
                f"{self.url}/attributes/edit/{uid}", {"Attribute": changes}, context=f"edit of attribute {uid}"
            )
        except MispTransientError as e:
            self.stats["errors"] += 1
            logger.error("[UPDATE-FAILED] attribute %s: %s", uid, e)
            return False
        if response.status_code != 200:
            self.stats["errors"] += 1
            logger.error(
                "[UPDATE-FAILED] attribute %s: HTTP %s — %s", uid, response.status_code, (response.text or "")[:300]
            )
            return False
        try:
            body = response.json()
        except ValueError:
            body = None
        stored = _edited_attribute(body)
        if stored is None or not _edit_confirmed(stored, changes, written_after):
            self.stats["attributes_unconfirmed"] = self.stats.get("attributes_unconfirmed", 0) + 1
            logger.error(
                "[UNCONFIRMED-EDIT] attribute %s: MISP answered HTTP 200 but its answer does not show the edit", uid
            )
            return False
        self.stats["attributes_updated"] = self.stats.get("attributes_updated", 0) + 1
        return True

    def create_malware_attribute(self, malware: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard malware entry.

        Args:
            malware: EdgeGuard malware dict with keys like:
                     name, malware_types, family, description, etc.

        Returns:
            MISP attribute dict or None
        """
        name = malware.get("name")
        if not name:
            return None

        # Sanitize the name
        name = sanitize_value(name, max_length=255)
        if not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(malware)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(malware.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(malware))  # 2026-10: TLP on every attribute

        # Add malware type tags
        malware_types = malware.get("malware_types", [])
        for mtype in malware_types:
            mt = sanitize_value(str(mtype), max_length=50).lower()
            if mt:
                tags.append(f"malware-type:{mt}")

        # Add family tag
        family = sanitize_value(malware.get("family", ""), max_length=100)
        if family and family != name:
            tags.append(f"malware-family:{family}")

        # Add alias tags (2026-06, alias round-trip): same carrier as actors.
        # ATT&CK malware aliases (x_mitre_aliases) feed build_relationships
        # Q9 INDICATES (i.malware_family ∈ m.aliases) — without this tag the
        # aliases never survived the MISP round-trip. (They do NOT feed actor
        # attribution: the old Q2 Branch-3 path that read m.aliases was
        # removed 2026-06 as a forgery vector — see build_relationships.py.)
        # Cap matches the actor path.
        tags.extend(_alias_tags(malware))

        # Add MITRE ATT&CK galaxy tag for malware - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:malware="{name}"')
        # 2026-11-07: ATT&CK's own cluster beside it, its domains and its platforms (ATT&CK software only).
        tags.extend(_attack_galaxy_tags(malware, name))
        tags.extend(_attack_domain_tags(malware))
        tags.extend(_platform_tags(malware))
        tags.extend(_deprecated_tags(malware))  # 2026-10: ATT&CK x_mitre_deprecated

        # 2026-11-07: the source's full text (``_entity_description``); the graph's cap is the sync's.
        description = _entity_description(malware)

        # Preserve technique IDs and the source report id through MISP (same idea as
        # NVD_META for CVEs). ``run_misp_to_neo4j.parse_attribute`` reads the keys back:
        #   "t"   MITRE-explicit ``uses_techniques``  (ATT&CK ``uses`` relationships)
        #   "rt"  ``reported_techniques``              (2026-10: pulse-level ATT&CK ids, OTX)
        #   "pid" ``pulse_id``                         (2026-10: OTX pulse = source report)
        meta = _technique_meta(malware)
        if meta:
            import json as _json

            comment = "MITRE_USES_TECHNIQUES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"Malware from {source}"

        attribute = {
            "type": "malware-type",
            "value": name,
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): MITRE malware SDOs carry the
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, malware)
        return attribute

    def create_actor_attribute(self, actor: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard threat actor entry.

        Args:
            actor: EdgeGuard actor dict with keys like:
                   name, aliases, description, etc.

        Returns:
            MISP attribute dict or None
        """
        name = actor.get("name")
        if not name:
            return None

        # Sanitize the name
        name = sanitize_value(name, max_length=255)
        if not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(actor)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(actor.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(actor))  # 2026-10: TLP on every attribute

        # Add alias tags — the MISP-side carrier for the alias round-trip:
        # run_misp_to_neo4j.parse_attribute rehydrates ``alias:`` tags into
        # item["aliases"], which merge_actor persists (PR-N14 sanitizer
        # downstream: 50-item cap + placeholder filter + 200-char truncation).
        # Cap raised 5 → 20 (2026-06): MITRE intrusion-sets commonly carry
        # 5-10 aliases and the old cap could drop the very alias an analyst
        # searches by ("Cozy Bear" vs "APT29"); 20 covers the ATT&CK p99
        # while still bounding MISP tag growth from a hostile feed.
        tags.extend(_alias_tags(actor))

        # Add MITRE threat-actor galaxy tag - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:threat-actor="{name}"')
        # 2026-11-07: ATT&CK's own cluster beside the community one, and the group's domains (ATT&CK groups only).
        tags.extend(_attack_galaxy_tags(actor, name))
        tags.extend(_attack_domain_tags(actor))
        tags.extend(_deprecated_tags(actor))  # 2026-10: ATT&CK x_mitre_deprecated

        # 2026-11-07: the source's full text (``_entity_description``); the graph's cap is the sync's.
        description = _entity_description(actor)

        # Preserve technique IDs + source report id through MISP (same keys as the
        # malware path: "t" explicit, "rt" reported, "pid" pulse id).
        meta = _technique_meta(actor)
        if meta:
            import json as _json

            comment = "MITRE_USES_TECHNIQUES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"Threat actor from {source}"

        attribute = {
            "type": "threat-actor",
            "value": name,
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): MITRE intrusion-set SDOs carry
        # the canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, actor)
        return attribute

    def create_technique_attribute(self, technique: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from an EdgeGuard technique entry.

        Args:
            technique: EdgeGuard technique dict with keys like:
                      mitre_id, name, description, platforms, etc.

        Returns:
            MISP attribute dict or None
        """
        mitre_id = technique.get("mitre_id")
        name = technique.get("name")

        if not mitre_id or not name:
            return None

        # Sanitize inputs
        mitre_id = sanitize_value(mitre_id, max_length=20)
        name = sanitize_value(name, max_length=255)

        if not mitre_id or not name:
            return None

        # Build tags
        tags = []

        # Add zone/sector tags using new equal-importance logic
        zones_to_tag = self._get_zones_to_tag(technique)
        for z in zones_to_tag:
            tags.append(f"zone:{z.capitalize()}")

        # Add source tag
        source = sanitize_value(technique.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(technique))  # 2026-10: TLP on every attribute
        tags.append(f"attack-domain:{_attack_domain(technique)}")  # 2026-10: enterprise | ics

        # 2026-11-07: every platform, in ATT&CK's casing (``_platform_tags``).
        tags.extend(_platform_tags(technique))

        # Add MITRE ATT&CK galaxy tags - CRITICAL for STIX conversion
        # This enables PyMISP to recognize and convert to attack-pattern
        tags.append(f'misp-galaxy:mitre-attack-pattern="{name} - {mitre_id}"')
        tags.append(f'mitre-attack:technique="{mitre_id}"')
        tags.extend(_deprecated_tags(technique))  # 2026-10: ATT&CK x_mitre_deprecated

        # 2026-11-07: the source's full text (``_entity_description``); the graph's cap is the sync's.
        description = _entity_description(technique)
        tactic_phases = technique.get("tactic_phases") or []

        # Preserve technique→tactic phase mapping through MISP.
        # ``run_misp_to_neo4j.parse_attribute`` reads this prefix into ``tactic_phases``.
        if tactic_phases:
            import json as _json

            meta = {"p": list(tactic_phases)[:20]}
            comment = "MITRE_TACTIC_PHASES:" + _json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"MITRE ATT&CK technique from {source}"

        # 2026-10-20: "<id> - <name>", without a colon: MISP's default Import Regexp rules rewrote the
        # form "<id>: <name>" ("T1059.003: Windows Command Shell" was stored as
        # "T1059.00%WINDIR%\Command Shell"); see ``attack_values``.
        attribute = {
            "type": "text",
            "value": format_attack_value(mitre_id, name),
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }

        # PR (S5) (bugbot HIGH): attack-pattern SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, technique)
        return attribute

    def create_tactic_attribute(self, tactic: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from a MITRE ATT&CK tactic (x-mitre-tactic).

        Tactics use the same ``text`` value as techniques (``TA0001 - Initial Access``,
        ``attack_values.format_attack_value``) so MISP→Neo4j parsing can recognize them. Previously
        ``push_items`` had no branch for ``type: tactic``, so tactics were silently skipped.
        """
        mitre_id = tactic.get("mitre_id")
        name = tactic.get("name")
        if not mitre_id or not name:
            return None

        mitre_id = sanitize_value(str(mitre_id), max_length=20)
        name = sanitize_value(str(name), max_length=255)
        shortname = sanitize_value(str(tactic.get("shortname", "")), max_length=50)
        if not mitre_id or not name:
            return None

        tags = []
        for z in self._get_zones_to_tag(tactic):
            tags.append(f"zone:{z.capitalize()}")

        source = sanitize_value(tactic.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(tactic))  # 2026-10: TLP on every attribute
        tags.append(f"attack-domain:{_attack_domain(tactic)}")  # 2026-10: enterprise | ics

        if shortname:
            tags.append(f"mitre-tactic:{shortname.lower()}")
        tags.extend(_deprecated_tags(tactic))  # 2026-10: ATT&CK x_mitre_deprecated

        # 2026-11-07: the source's full text (``_entity_description``); the graph's cap is the sync's.
        description = _entity_description(tactic)

        attribute = {
            "type": "text",
            "value": format_attack_value(mitre_id, name),
            "comment": description if description else "MITRE ATT&CK tactic",
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }
        # PR (S5) (bugbot HIGH): x-mitre-tactic SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, tactic)
        return attribute

    def create_tool_attribute(self, tool: Dict) -> Optional[Dict]:
        """
        Create a MISP attribute from a MITRE ATT&CK tool (Cobalt Strike, Mimikatz, etc.).

        Tools are stored as ``text`` attributes with the value ``S#### - Name``
        (``attack_values.format_attack_value``), as techniques and tactics are. The
        ``uses_techniques`` list is preserved via ``MITRE_USES_TECHNIQUES:``
        comment prefix for round-trip through MISP→Neo4j.
        """
        mitre_id = tool.get("mitre_id")
        name = tool.get("name")
        if not mitre_id or not name:
            return None

        mitre_id = sanitize_value(str(mitre_id), max_length=20)
        name = sanitize_value(str(name), max_length=255)
        if not mitre_id or not name:
            return None

        tags = []
        for z in self._get_zones_to_tag(tool):
            tags.append(f"zone:{z.capitalize()}")

        source = sanitize_value(tool.get("tag", "unknown"), max_length=50)
        if source in self.SOURCE_TAGS:
            tags.append(self.SOURCE_TAGS[source])
        else:
            tags.append(f"source:{source}")
        tags.append(_tlp_tag(tool))  # 2026-10: TLP on every attribute

        # Tag as tool type for MISP galaxy compatibility
        tags.append(f'misp-galaxy:tool="{name}"')
        # 2026-11-07: ATT&CK's own cluster beside the community one, the tool's aliases (as actors and malware
        # carry theirs), its domains and its platforms.
        tags.extend(_attack_galaxy_tags(tool, name))
        tags.extend(_alias_tags(tool))
        tags.extend(_attack_domain_tags(tool))
        tags.extend(_platform_tags(tool))
        tags.extend(_deprecated_tags(tool))  # 2026-10: ATT&CK x_mitre_deprecated
        for ttype in tool.get("tool_types", []):
            tt = sanitize_value(str(ttype), max_length=50).lower()
            if tt:
                tags.append(f"tool-type:{tt}")

        # 2026-11-07: the source's full text (``_entity_description``); the graph's cap is the sync's.
        description = _entity_description(tool)
        uses_techniques = tool.get("uses_techniques") or []

        if uses_techniques:
            meta = {"t": list(uses_techniques)[:400]}
            comment = "MITRE_USES_TECHNIQUES:" + json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"MITRE ATT&CK tool: {name}"

        attribute = {
            "type": "text",
            "value": format_attack_value(mitre_id, name),
            "comment": comment,
            "to_ids": False,
            "Tag": [{"name": tag} for tag in tags],
        }
        # PR (S5) (bugbot HIGH): MITRE tool SDOs carry
        # canonical ``created`` / ``modified`` as first_seen / last_seen.
        _apply_source_truthful_timestamps(attribute, tool)
        return attribute

    def push_items(
        self,
        items: List[Dict],
        batch_size: int = 500,
        *,
        known_source_keys: Optional[Dict[str, set]] = None,
        batch_key: Optional[Callable[[Dict], Any]] = None,
        deadline: Optional[float] = None,
    ) -> Tuple[int, int]:
        """
        Push a list of items to MISP in batches.

        Args:
            items: List of EdgeGuard items (indicators, vulnerabilities, etc.)
            batch_size: Number of items per batch. Overridden by
                ``EDGEGUARD_MISP_PUSH_BATCH_SIZE`` env var when set — lets ops
                dial the batch size down without a code change if MISP is
                choking on large pushes (e.g. the 22% HTTP 500 failure rate
                observed on the 730-day NVD baseline).
            known_source_keys: ``{source_tag: {(type, value), ...}}`` the caller has already
                listed (2026-10, NVD incremental runs via ``index_source_attributes``); used in
                place of the cross-event prefetch for that tag, so MISP is not listed twice.
            batch_key: a function of an item; items it maps to different values are never in one
                batch (2026-11-02, below).
            deadline: a ``time.monotonic()`` value after which no batch starts and no refresh edit
                starts (2026-11-02, below).

        Returns:
            Tuple of (successful_count, failed_count)

        2026-10 (re-reported indicators): an indicator the source already holds in MISP is not
        pushed again, but when MISP last wrote its stored copy (the attribute ``timestamp``) more
        than ``EDGEGUARD_MISP_REFRESH_LAST_SEEN_DAYS`` ago, the copy is edited
        (``_refresh_stored_copies``) so that MISP stamps it anew and the incremental sync reads it
        again. The counts are ``stats["attributes_refreshed"]`` / ``["attributes_refresh_failed"]`` /
        ``["attributes_refresh_deferred"]``; a failed refresh is logged and does not count as a
        failed push.

        2026-10 (push accounting): an item no MISP attribute can be built from (an unknown item
        type, or a ``create_*_attribute`` that returns None, such as an empty value) is reported:
        one ``[CONVERT]`` log line per push gives, per source, how many of its items could not be
        converted, the reasons and whether they count as failed, and
        ``stats["items_not_converted"]`` counts them. They count as failed (and in
        ``stats["items_not_converted_failed"]``) only when the drop is systemic for the source in
        this push: every item of the source failed conversion, or at least
        ``CONVERT_FAILED_MIN_SHARE`` of them did. A source whose payload stops converting thus fails
        ``status_after_misp_push``, while a few bad records neither turn a run red nor hold a
        collector's cursor or ETag: CISA ICS, the NVD baseline seed and MITRE ATT&CK move only after
        a push without failures, and OTX retries the pulses with an item in
        ``last_push_unstored_items``, which lists the items of a systemic drop (below). A
        (source, date) group left without attributes reaches neither the event lookup nor MISP.
        With cross-event dedup on and a complete listing of the source's attributes (or
        ``known_source_keys``), the cross-event filter runs before ``_get_or_create_event``: a
        group MISP already holds entirely neither looks up nor creates the day's event, and the
        refresh candidates of the group are decided there. With dedup off or a listing that stopped
        early, the order stays: event, per-event filter, cross-event filter, because partial keys
        can miss the copy in today's event and the refresh decision needs the copy MISP wrote last.
        ``[DEDUP] All N items were already present`` is logged only when nothing failed or was
        dropped, N being the attributes found present.

        2026-10 (several-actor marks): an OTX indicator carries the pulses that the collector judged,
        with the canonical threat-actor reference, to name several actors (``several_actor_pulses``,
        ``OTX_META.sap``), in the attribute it pushes. The writer never adds a mark to a stored copy:
        MISP keeps what the sources said, and the mark is EdgeGuard's judgement. A pulse edited later
        to name several actors, whose IOCs MISP already holds and which brings no new IOC, is therefore
        marked on no Indicator node (a known limit, to be closed by a per-pulse MISP record); the
        pulse's new IOCs carry the mark.

        PR-N4 — adaptive scaling for MISP-at-scale (closes the on-call
        report from 2026-04-21 where a 730d baseline lost ~11,500 attrs
        across OTX + NVD pushes due to MISP HTTP 500s on large events):

        The default ``batch_size=500, throttle=5s`` works well when MISP
        events are small (<50K attrs). At ~50K+ attributes per event
        the MISP PHP/MySQL backend starts crashing per batch
        (worker OOMs, MySQL transaction timeouts, Apache prefork
        restarts). EdgeGuard now adapts on a per-event basis:

          existing_attrs >= 100K → batch_size=50,  throttle=30s
          existing_attrs >= 50K  → batch_size=100, throttle=15s
          existing_attrs <  50K  → use the configured/default values

        Per-batch HTTP POST is smaller, MISP PHP can finish, less
        likely to OOM. The thresholds are env-tunable via
        ``EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD`` (default 50000) and
        ``EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD`` (default 100000).

        Plus an adaptive backoff: after N consecutive HTTP 5xx batch
        failures (default 3, env ``EDGEGUARD_MISP_BACKOFF_THRESHOLD``)
        the writer inserts a longer cooldown (up to 5min, env
        ``EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC``) before the next batch
        — gives MISP time to fully recover instead of hammering a
        struggling worker.  The failure counter persists across
        ``push_items`` calls (instance-scoped on ``self``) and resets
        only after **2 consecutive fully-successful** batches — one
        success could be a fluke; two suggests genuine recovery.
        During the cooldown the writer wakes every 30s to call the
        parent-DAG liveness callback so a sibling task failure is
        detected within ~30s rather than after the full cooldown.
        2026-11-03: after a 30 s step, while the cooldown has at least
        ``COOLDOWN_PROBE_TIMEOUT`` (10 + 30 s) left, it also sends a light
        request (``_misp_answers``); an HTTP 200 ends the cooldown. The
        request's time counts toward the cooldown, so the liveness
        callback can then run up to 70 s apart.

        See docs/MISP_TUNING.md for the full playbook (php.ini /
        my.cnf settings + when to apply each EdgeGuard env knob).

        2026-10 (event split): a group goes to ``EdgeGuard-<source>-<date>`` and, past
        ``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`` attributes, to ``-part2``, ``-part3`` ... (the push goes to the
        first part with room; a new part is created right before its first batch); a group with
        source-report ids (OTX) is not split. See ``_event_split_above`` and
        docs/COLLECTION_AND_SYNC_LIMITS.md.

        2026-10 (unstored items): after the call, ``self.last_push_unstored_items`` lists the
        positions in *items* of the items MISP did not store because their batch, their group's
        event lookup, the creation of their part or the lookup of a further part failed, and of the
        items of a systemic conversion drop (below). OTX fetches their pulses again by id on later runs
        (its retry list), or holds its cursor below them when every listed item failed at its event
        (``last_push_event_failed_items``, 2026-11-02). The items of a batch are listed after HTTP
        4xx, a batch error or HTTP 429 after the retries; after HTTP 5xx and the retries, the
        attributes the lookup in the event does not find (all of them when that lookup fails); when
        the event id is empty once sanitised (no request is sent, 2026-11-02); and under strict
        accounting when an HTTP 200 confirms none of the batch. The attributes missing from a batch
        MISP answered with HTTP 200 and partly stored are not listed. The items no attribute could be
        built from are listed when their source's drop is systemic (``CONVERT_FAILED_MIN_SHARE``): a
        payload the collector no longer reads, whose items a later run stores once the collector
        reads it again; single bad records below the share are not. Values MISP can never store
        (4-byte characters) are not listed either: a later run cannot store them.

        2026-11-02 (items that failed at their event): ``self.last_push_event_failed_items`` lists the
        positions, among the unstored items, of those listed because the MISP event their attribute goes
        to could not be used: the lookup or creation of their group's event failed (after the retries,
        or without an event id), the lookup of a further part failed, their part could not be created,
        or the event id was empty once sanitised. No batch carried them, so a push whose listed items
        are all in it is one MISP failed as a whole (unreachable, or the day's event failing), not one
        of items MISP refused. A batch MISP answered with an error is a failure of its items, whatever
        share of the push it holds: one value MISP refuses fails its whole batch. The OTX collector
        holds its cursor after a push whose listed items all failed at their event and puts the pulses
        of the listed items of any other push on its retry list.

        2026-11-02 (*batch_key*): a function of an item; attributes whose items it maps to different
        values never share a batch, each value's attributes being batched apart, in the order of the
        first item of each value (``_batches``; the attribute of several items in the push takes the
        value of the first). Without it the batches follow the order of the items, as before. The OTX
        collector passes it so that each pulse of its retry list is pushed in batches of its own: a
        value MISP refuses then fails no item of another pulse. The throttle applies between all
        batches.

        2026-11-02 (*deadline*): a ``time.monotonic()`` value. A batch starts only when the throttle
        pause before it, and the back-off cooldown when one is due, end before the deadline; otherwise
        the push stops there, and ``self.last_push_skipped_items`` lists the positions of the items of
        that batch and of every later one, which are neither stored nor failed (nothing was sent for
        them). A batch already sent is not interrupted: its attempts after HTTP 5xx can take it past the
        deadline. The refresh of re-reported indicators starts no edit after the deadline either. The
        event lookups and listings before the first batch are not bounded by it. Without a deadline the
        push is unchanged. The OTX collector passes one for the push of the pulses of its retry list
        (``EDGEGUARD_OTX_RETRY_MAX_SECONDS``).

        2026-11-03 (a cap on failure time): a push stops once MISP has kept failing for
        ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC`` (900 s; ``0``: no cap), or for the baseline's writer
        ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC_BASELINE`` (3600 s), which also stops a streak
        ``PUSH_TASK_END_MARGIN_SEC`` before its task's end (``_failing_streak``). The time is that of the current
        failing streak: from the start of the first request that fails (a batch answered HTTP 429 or 5xx, a timeout
        or a connection error, a failed attempt of an event or part lookup) through the lookups, waits and attempts
        that follow, the throttle pauses between its failing batches included; a batch ``_push_batch`` returns from
        ends it, and so does the group's event lookup before the batches. A batch's retries stop when the next wait
        would reach the cap (the decorator's *give_up*), a ``Retry-After`` wait is cut to the time left, the lookups
        after a 5xx get timeouts of at most the time left, and before a batch the push stops when the batch would
        start at or after the cap: the streak has reached it, or the throttle pause and the back-off cooldown due
        before the batch would (they are not slept); the check runs again after the pause, the cooldown and the
        liveness check (a new part is created after it). In a push of several
        sources the push also stops before a group's listings and event lookup once the streak has reached the cap.
        The cap never cuts a request short; the event and part lookups and a new part's creation stop retrying at it
        but keep their full timeouts, and the listings and the refresh are not limited by it, so a MISP that answers
        slowly can keep a push going past the cap (``_failing_streak``). A stopped push sends nothing more and
        creates no part. The items of the batches not sent, of the current group and of every later one, count as
        failed and are listed in ``last_push_unstored_items`` and in ``self.last_push_unsent_items``;
        ``self.last_push_stopped`` is True, one ERROR ``[MISP-PUSH-STOPPED]`` names the stop,
        ``edgeguard_misp_push_stopped_total`` counts it, the back-off counters are reset (the next push on the writer
        starts without a cooldown), and the refresh of re-reported indicators is left for a later run. The batch
        whose retries the cap cut short is a failed batch like any other (it was sent and answered). The push returns
        its counts as usual. A timeout or a connection error after the retries still raises out of ``push_items``,
        sooner with the cap. During a back-off cooldown, after a 30 s step while the cooldown has at least the
        probe's timeouts left, a light request (``_misp_answers``) ends the cooldown when MISP answers it with HTTP
        200; its time counts toward the cooldown, so the light requests never make it longer than its length (the
        liveness checks between the steps are not counted).
        """
        self.last_push_unstored_items: List[int] = []
        self.last_push_event_failed_items: List[int] = []
        self.last_push_skipped_items: List[int] = []
        self.last_push_unsent_items = []
        self.last_push_stopped = False
        if not items:
            return 0, 0
        # 2026-11-03: the cap on failure time of this call (``_failing_streak``).
        self._arm_push_cap()

        total_items = len(items)

        # Env override wins over caller default so ops can tune without redeploying.
        _env_batch = os.environ.get("EDGEGUARD_MISP_PUSH_BATCH_SIZE")
        if _env_batch:
            try:
                env_val = int(_env_batch)
                if env_val > 0:
                    batch_size = env_val
            except (ValueError, TypeError):
                logger.warning(
                    "Ignoring invalid EDGEGUARD_MISP_PUSH_BATCH_SIZE=%r; using %d",
                    _env_batch,
                    batch_size,
                )

        # Guard against invalid batch_size (0 would crash range())
        batch_size = max(1, batch_size)

        # Group items by (source, date) — zone lives on attribute tags, not event name. A group is
        # created by its first converted attribute (2026-10), so a group whose items all fail
        # conversion reaches neither the event lookup nor MISP.
        grouped: Dict[Tuple[str, str], List[Dict]] = {}
        # 2026-10: (type, value) of the indicators each source reports in this push — the
        # candidates for a last_seen refresh when MISP already holds them. 2026-11: keyed by ``_dedup_key``.
        reported_indicators: Dict[str, set] = {}
        # 2026-10: per source, the reasons items could not be converted to a MISP attribute and
        # how many items each reason dropped, and the number of items each source gave. A source's
        # drops count as failed only when they are systemic (``CONVERT_FAILED_MIN_SHARE``).
        not_converted: Dict[str, Dict[str, int]] = {}
        items_per_source: Dict[str, int] = {}

        # 2026-10: (type, value) → positions in *items*, to name the items of a failed batch; per
        # source, the positions of the items no attribute could be built from, listed as unstored
        # when the source's drop is systemic. 2026-11: keyed as the dedup within the push keys
        # (``_within_push_key``), so the item of a variant it drops is unstored with the attribute kept.
        item_positions_by_key: Dict[Tuple[Any, Any], List[int]] = {}
        not_converted_positions: Dict[str, List[int]] = {}
        unstored_positions: set = set()
        # 2026-11-02: the positions listed because their event could not be used (``last_push_event_failed_items``).
        event_failed_positions: set = set()
        # 2026-11-02: the positions of the items not sent because *deadline* came (``last_push_skipped_items``).
        skipped_positions: set = set()
        # 2026-11-03: the positions of the items not sent because the push stopped (``last_push_unsent_items``).
        unsent_positions: set = set()

        def _note_unstored(attrs: List[Dict], at_the_event: bool = False, unsent: bool = False) -> None:
            for a in attrs:
                if _value_is_storable(a):
                    positions = item_positions_by_key.get(_within_push_key(a), ())
                    unstored_positions.update(positions)
                    if at_the_event:
                        event_failed_positions.update(positions)
                    if unsent:
                        unsent_positions.update(positions)

        def _note_skipped(attrs: List[Dict]) -> None:
            for a in attrs:
                skipped_positions.update(item_positions_by_key.get(_within_push_key(a), ()))

        def _key_of(attr: Dict) -> Any:
            # The batch key of an attribute (2026-11-02): *batch_key* of the first item it was built from.
            positions = item_positions_by_key.get(_within_push_key(attr))
            return batch_key(items[positions[0]]) if batch_key is not None and positions else None

        for item_position, item in enumerate(items):
            source = item.get("tag", "unknown")
            date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            key = (source, date)
            items_per_source[str(source)] = items_per_source.get(str(source), 0) + 1

            # Convert item to MISP attribute
            item_type = item.get("type", "")
            convert: Optional[Callable[[Dict], Optional[Dict]]]
            if "indicator_type" in item and "value" in item:
                kind, convert = "indicator", self.create_attribute
            elif item_type == "vulnerability" or _resolve_vulnerability_cve_id_for_misp(item):
                kind, convert = "vulnerability", self.create_vulnerability_attribute
            elif item_type == "malware":
                kind, convert = "malware", self.create_malware_attribute
            elif item_type == "actor":
                kind, convert = "actor", self.create_actor_attribute
            elif item_type == "technique":
                kind, convert = "technique", self.create_technique_attribute
            elif item_type == "tactic":
                kind, convert = "tactic", self.create_tactic_attribute
            elif item_type == "tool":
                kind, convert = "tool", self.create_tool_attribute
            else:
                kind, convert = "", None

            attr = convert(item) if convert is not None else None
            if not attr:
                if convert is None:
                    reason = f"unknown item type {item_type!r}"
                else:
                    reason = f"{kind} with an empty {_CONVERSION_REQUIRES[kind]}"
                source_reasons = not_converted.setdefault(str(source), {})
                source_reasons[reason] = source_reasons.get(reason, 0) + 1
                not_converted_positions.setdefault(str(source), []).append(item_position)
                continue

            grouped.setdefault(key, []).append(attr)
            item_positions_by_key.setdefault(_within_push_key(attr), []).append(item_position)
            if kind == "indicator":
                reported_indicators.setdefault(source, set()).add(_dedup_key(attr.get("type"), attr.get("value")))

        not_converted_ct = 0
        # 2026-10: the dropped items of the sources for which the drop is systemic in this push;
        # they are failures of the push, the others are reported only.
        not_converted_failed_ct = 0
        if not_converted:
            parts: List[str] = []
            # Sorted so that the same payload always gives the same line.
            for src in sorted(not_converted):
                dropped = sum(not_converted[src].values())
                given = items_per_source.get(src, dropped)
                systemic = dropped >= given or dropped / given >= CONVERT_FAILED_MIN_SHARE
                not_converted_ct += dropped
                if systemic:
                    not_converted_failed_ct += dropped
                    # Listed as unstored (2026-10): a collector that reads the payload again can
                    # store them, so OTX treats them like the items of a failed batch.
                    unstored_positions.update(not_converted_positions.get(src, ()))
                reasons = ", ".join(f"{count} {reason}" for reason, count in sorted(not_converted[src].items()))
                verdict = "counted as failed" if systemic else "not counted as failed"
                parts.append(f"{src}: {dropped} of {given} item(s), {verdict} ({reasons})")
            # A WARNING when every drop is only reported; an ERROR when a source's drop fails the push.
            logger.log(
                logging.ERROR if not_converted_failed_ct else logging.WARNING,
                "[CONVERT] %d item(s) could not be converted to a MISP attribute, %d of them counted as failed "
                "(a source's items count as failed when all or at least %.0f%% of them fail conversion): %s",
                not_converted_ct,
                not_converted_failed_ct,
                CONVERT_FAILED_MIN_SHARE * 100,
                "; ".join(parts),
            )
            self.stats["items_not_converted"] = self.stats.get("items_not_converted", 0) + not_converted_ct
            self.stats["items_not_converted_failed"] = (
                self.stats.get("items_not_converted_failed", 0) + not_converted_failed_ct
            )

        # 2026-10: per resolved source tag, the reported indicators whose stored copy the
        # cross-event prefetch should describe (see ``_get_existing_source_attribute_keys``).
        refresh_days = misp_refresh_last_seen_days()
        refresh_cutoff = time.time() - refresh_days * 86400
        stored_copies_by_tag: Dict[str, Dict[Tuple[str, str], Optional[StoredCopy]]] = {}
        if refresh_days > 0:
            for _source, _keys in reported_indicators.items():
                _lookup = stored_copies_by_tag.setdefault(self.SOURCE_TAGS.get(_source, f"source:{_source}"), {})
                for _key in _keys:
                    _lookup.setdefault(_key, None)
        # ``_dedup_key`` → (the stored copy to edit, last_seen of the re-reported item)
        refresh_due: Dict[Tuple[str, str], Tuple[StoredCopy, Optional[str]]] = {}

        # Resolve events + prefetch existing (type, value); build work queue (post-filter batch counts).
        total_success = 0
        # 2026-10: the items of a source whose drop in conversion is systemic are failures of this
        # push; the other items no attribute could be built from are only reported.
        total_failed = not_converted_failed_ct
        # 2026-10: attributes skipped because MISP already holds them (per-event + cross-event), the
        # N of the "[DEDUP] All N items were already present" line.
        present_ct = 0
        processed_batches = 0
        start_time = time.time()
        # 2026-11-03: the push stopped because MISP kept failing past the cap (``_failing_streak``): the source and
        # the batch it stopped at, the streak's cap and length (set before a group's lookup or before a batch).
        stop: Optional[Tuple[str, int, float, float]] = None
        # 2026-11-02: the batches of this push MISP stored although it answered HTTP 5xx (summary line).
        stored_after_5xx_before = self.__dict__.get("stats", {}).get("batches_stored_after_5xx", 0)
        # PR-N4 round 2 (Bugbot R2-A): widened from 2-tuple to 4-tuple
        # carrying (source, event_id, existing_attrs_count, attrs).
        # The threading was added in round 1 (F1: stale source) + round 1
        # (F2: avoid duplicate _get_existing_attribute_keys fetch); the
        # type annotation was forgotten and silently misled mypy.
        push_queue: List[Tuple[str, Union[str, _PendingPart], int, List[Dict]]] = []
        # 2026-10: the event split limit, read once per push (an invalid value warns once).
        split_knob = _event_split_above()

        # PR-F7 (Issue #61 quick-fix): cache cross-event prefetch per
        # source so a single push_items call doesn't re-fetch the same
        # tag set N times when grouped has multiple (source, date)
        # entries for the same source. The fetch itself can be 30-40s
        # on a 92K-attr NVD source — caching matters.
        cross_event_cache: Dict[str, set] = {}
        # 2026-10: the source tags whose cross-event keys are complete — the listing read every page,
        # or the caller supplied its own complete listing (``known_source_keys``).
        cross_event_complete: Dict[str, bool] = {}

        def _note_refresh_due(source_tag: str, candidates: List[Dict]) -> None:
            # 2026-10: a re-reported indicator held in an earlier EdgeGuard event whose stored copy
            # MISP last wrote before the cutoff is refreshed after the pushes (``_refresh_stored_copies``).
            # A copy in today's event was written today, after the cutoff, so it is never due.
            _copies = stored_copies_by_tag.get(source_tag)
            if not _copies or refresh_days <= 0:
                return
            # 2026-11: looked up by ``_dedup_key``, the key the existing-attribute check skipped it by, so a
            # pushed ``ABC…`` finds the copy MISP stored as ``abc…``; the edit names that copy's uuid.
            for a in candidates:
                _key = _dedup_key(a.get("type"), a.get("value"))
                _copy = _copies.get(_key)
                if _copy is not None and _copy.written < refresh_cutoff:
                    refresh_due[_key] = (_copy, a.get("last_seen"))

        def _cross_event_note(cross_event_keys: set, checked_first: bool) -> str:
            # Says why the cross-event count of the skip line may be 0: a bare "0 cross-event" did
            # not tell "checked, none found" from "check disabled or failed".
            if not MISP_CROSS_EVENT_DEDUP:
                return "cross-event DISABLED"
            if not cross_event_keys:
                # Enabled but empty: no duplicates, or the listing failed (its WARNING above is the
                # record of that); "unavailable" keeps the 0 from reading as "checked, none found".
                return "cross-event unavailable/empty"
            if checked_first:
                return "cross-event PR-F7 active, checked before the event lookup"
            return "cross-event PR-F7 active"

        for (source, date), attributes in grouped.items():
            # Deduplicate attributes by value. 2026-11: compared as MISP compares a pushed attribute with the
            # value it stores (``_within_push_key``): whitespace, and the case of the types whose case MISP
            # changes on save. The first attribute is pushed; a later one that differs from it only so is
            # logged, because its comment and tags (an OTX item's report ids) are not merged into the first.
            seen: Dict[Tuple[str, str], Dict] = {}
            unique_attrs = []
            variants: List[Tuple[Any, Any, Any]] = []
            for attr in attributes:
                key = _within_push_key(attr)
                kept = seen.get(key)
                if kept is None:
                    seen[key] = attr
                    unique_attrs.append(attr)
                elif (kept.get("type"), kept.get("value")) != (attr.get("type"), attr.get("value")):
                    variants.append((attr.get("type"), attr.get("value"), kept.get("value")))
            if variants:
                logger.warning(
                    "[CASE-VARIANT] MISP push %s (%s): %d attribute(s) not pushed, each the same value as an attribute "
                    "earlier in this push but for case or surrounding whitespace, which MISP stores as one value; "
                    "their comments and tags are not merged into the attribute pushed (first %d: %s)",
                    source,
                    date,
                    len(variants),
                    min(len(variants), _CASE_VARIANT_LOG_SAMPLE),
                    "; ".join(
                        f"{t} {dropped!r} (pushed: {pushed!r})"
                        for t, dropped, pushed in variants[:_CASE_VARIANT_LOG_SAMPLE]
                    ),
                )

            # 2026-11-03 (a cap on failure time, ``_failing_streak``): once a streak a group before began (its
            # event or part lookup failing) has reached its cap, the push stops before this group's listings and
            # event lookup. The group goes to the queue unlooked-up, and the push loop counts its attributes, with
            # those of every other entry, as not sent. Only a push of several sources has a group after another.
            if stop is None:
                streak = _failing_streak(self)
                if streak is not None and streak[1] >= streak[0]:
                    stop = (str(source), 1, streak[0], streak[1])
            if stop is not None:
                if unique_attrs:
                    push_queue.append((source, "", 0, unique_attrs))
                continue

            # PR-F7: the cache key is the RESOLVED ``source_tag`` — not the raw ``source``
            # string. Two sources can share a tag via the registry's alias
            # map (e.g. ``cisa`` and ``cisa_kev`` both map to
            # ``source:CISA-KEV``). Keying by raw ``source`` would double-fetch
            # the same tag set; keying by resolved tag collapses aliases into
            # one cache entry, which is what the prefetch cost model expects.
            source_tag = self.SOURCE_TAGS.get(source, f"source:{source}")
            if source_tag not in cross_event_cache:
                if known_source_keys is not None and source_tag in known_source_keys:
                    # 2026-11: keyed as the check compares (``_dedup_key``); NVD and KEV give upper-case CVE ids.
                    cross_event_cache[source_tag] = {_dedup_key(t, v) for t, v in known_source_keys[source_tag]}
                    cross_event_complete[source_tag] = True
                else:
                    cross_event_cache[source_tag] = self._get_existing_source_attribute_keys(
                        source_tag,
                        stored_copy_of=stored_copies_by_tag.get(source_tag),
                        listing_complete=cross_event_complete,
                    )
            cross_event_keys = cross_event_cache[source_tag]

            # 2026-10: with cross-event dedup on and a complete listing, the cross-event filter runs
            # before the event lookup: a group MISP already holds entirely (a re-run) then neither
            # looks up nor creates the day's event. With dedup off or a listing that stopped early
            # (an error, a non-JSON answer, the page cap) the order stays per-event first. Today's
            # attributes count as present in either order, since the per-event filter runs after
            # the lookup; the order matters for the refresh of re-reported indicators, which edits
            # the copy MISP wrote last. Partial keys can hold an earlier event's stale copy of an
            # indicator whose copy in today's event lies on a page the listing never read: checked
            # first, the indicator would be skipped before the per-event filter and the stale copy
            # refreshed although MISP wrote today's copy today. Only a complete listing names the
            # copy MISP wrote last.
            checked_first = bool(MISP_CROSS_EVENT_DEDUP and cross_event_complete.get(source_tag))

            # PR-F7: filter in TWO explicit steps so the skip-count attribution for each layer is
            # exact: a diagnostic summed over the list before the within-push dedup could exceed
            # ``skipped_ct``. Each step's contribution is exactly the difference in lengths, so the
            # per-event + cross-event counts always add up to ``skipped_ct``, in either order.
            cross_event_skipped = 0
            if checked_first:
                # Cross-event filter first (attrs in ANY EdgeGuard event for this source).
                group_ct = len(unique_attrs)
                after_cross_event = [
                    a for a in unique_attrs if _dedup_key(a.get("type"), a.get("value")) not in cross_event_keys
                ]
                cross_event_skipped = group_ct - len(after_cross_event)
                if cross_event_skipped:
                    _note_refresh_due(source_tag, unique_attrs)
                # Counted here, before the event lookup: they are present whether or not it succeeds.
                self.stats["attrs_skipped_existing"] += cross_event_skipped
                present_ct += cross_event_skipped
                unique_attrs = after_cross_event
                if not unique_attrs:
                    logger.info(
                        "MISP push %s (%s): all %s attributes already present under %s (0 per-event + %s "
                        "cross-event; %s) — no event looked up or created",
                        source,
                        date,
                        cross_event_skipped,
                        source_tag,
                        cross_event_skipped,
                        _cross_event_note(cross_event_keys, checked_first),
                    )
                    continue

            # Get or create the group's event (2026-10: part 1; later parts below, ``_event_split_above``). A
            # transient failure that survives the retry decorator is recorded as a failed batch for this
            # source group; the remaining groups are pushed.
            try:
                event_id = self._get_or_create_event(source, date)
                # 2026-11-03: MISP answered the lookup, so a failing streak it began ends (``_failing_streak``).
                self._misp_push_failing_since = None
            except _TRANSIENT_HTTP_ERRORS as e:
                logger.error(
                    "Event lookup/creation for source %r failed after retries (%s: %s) — %d attribute(s) counted as failed",
                    source,
                    type(e).__name__,
                    e,
                    len(unique_attrs),
                )
                self.stats["errors"] += 1
                total_failed += len(unique_attrs)
                _note_unstored(unique_attrs, at_the_event=True)
                continue
            if not event_id:
                total_failed += len(unique_attrs)
                _note_unstored(unique_attrs, at_the_event=True)
                continue

            per_event_keys = self._get_existing_attribute_keys(event_id)
            # 2026-10: the event split (``_event_split_above``). A group with an attribute of a source report
            # (OTX) is not split: the sync links items per report within one event, and a shared malware/CVE
            # item carries the ids of nearly every pulse of the day, so no cut keeps the reports whole. It
            # goes to the event as before.
            split_above = 0 if split_knob > 0 and any(_attribute_report_ids(a) for a in unique_attrs) else split_knob
            part_ids = [event_id]
            part_sizes: List[int] = []
            target = 0
            walk_complete = True
            earlier_keys: set = set()
            if split_above > 0:
                first_keys = per_event_keys
                part_sizes = [self._part_size(event_id, per_event_keys, split_above)]
                # The later parts are looked up when part 1 is full or this push does not fit it, so an overflow
                # never goes to a part whose size was not read, and on every push without a complete cross-event
                # listing (``checked_first``), whose dedup then needs every other part of the day: part 1 can be
                # short (a failed batch) while later parts exist.
                if part_sizes[0] >= split_above or len(unique_attrs) > split_above - part_sizes[0] or not checked_first:
                    part_ids, walk_complete = self._find_later_parts(source, date, part_ids)
                    # Without a complete cross-event listing every part is listed for the dedup below, and the
                    # listing sizes it too; otherwise a later part is sized by its lookup's ``attribute_count``
                    # (no count: full).
                    part_keys: Dict[int, set] = {0: first_keys}
                    if not checked_first:
                        for k in range(1, len(part_ids)):
                            part_keys[k] = self._list_part(part_ids[k])
                    part_sizes += [
                        self._part_size(part_ids[k], part_keys.get(k), split_above) for k in range(1, len(part_ids))
                    ]
                    # The first part with room takes the push: parts fill in order, and a part left short
                    # (a failed batch) is filled before a new one is opened.
                    target = next((k for k, size in enumerate(part_sizes) if size < split_above), len(part_ids) - 1)
                    if target:
                        event_id = part_ids[target]
                        if target not in part_keys:
                            part_keys[target] = self._list_part(event_id)
                        per_event_keys = part_keys[target]
                        part_sizes[target] = self._part_size(event_id, per_event_keys, split_above)
                    # An attribute already in another part of the day must not be added again: a complete
                    # cross-event listing names it; without one the other parts' listings are used here.
                    if not checked_first:
                        for k, keys_k in part_keys.items():
                            if k != target:
                                earlier_keys |= keys_k
            before_ct = len(unique_attrs)
            # Per-event filter (attrs already in THIS event, or in an earlier part of the day)
            after_per_event = [
                a for a in unique_attrs if _dedup_key(a.get("type"), a.get("value")) not in per_event_keys
            ]
            if earlier_keys:
                after_per_event = [
                    a for a in after_per_event if _dedup_key(a.get("type"), a.get("value")) not in earlier_keys
                ]
            per_event_skipped = before_ct - len(after_per_event)
            if checked_first:
                unique_attrs = after_per_event
            else:
                # Cross-event filter on the remainder (attrs in ANY OTHER
                # EdgeGuard event for this source). PR-F7's value is
                # exactly this number: duplicates that the per-event
                # prefetch would have missed.
                unique_attrs = [
                    a for a in after_per_event if _dedup_key(a.get("type"), a.get("value")) not in cross_event_keys
                ]
                cross_event_skipped = len(after_per_event) - len(unique_attrs)
                if cross_event_skipped:
                    _note_refresh_due(source_tag, after_per_event)
            skipped_ct = per_event_skipped + cross_event_skipped
            if skipped_ct:
                # A group checked first has its cross-event skips counted already.
                newly_skipped = per_event_skipped if checked_first else skipped_ct
                self.stats["attrs_skipped_existing"] += newly_skipped
                present_ct += newly_skipped
                logger.info(
                    "MISP event %s: skipping %s attributes already present (%s per-event + %s cross-event; %s)",
                    event_id,
                    skipped_ct,
                    per_event_skipped,
                    cross_event_skipped,
                    _cross_event_note(cross_event_keys, checked_first),
                )
            if not unique_attrs:
                continue
            # PR-N4 (Bugbot round 1): thread ``source`` and the
            # already-fetched per-event attribute count INTO the queue.
            #
            #  * ``source`` is needed by the second loop's Prometheus
            #    metric increments. The pre-fix version reused the
            #    outer-loop ``source`` variable, which retains its last
            #    iteration's value after the loop ends — silently
            #    mis-attributing every metric in a multi-source push.
            #  * ``existing_attrs_count`` is needed for adaptive scaling.
            #    Pre-fix the second loop re-called
            #    ``_get_existing_attribute_keys(event_id)`` (a 30-60s
            #    paginated REST call on large events) — doubling the
            #    prefetch cost on the exact events PR-N4 targets. Reuse
            #    the count we already paid for during dedup.
            #
            if split_above <= 0:
                push_queue.append((source, event_id, len(per_event_keys), unique_attrs))
                continue
            if not walk_complete and not cross_event_complete.get(source_tag):
                # A later part the walk could not look up may hold some of these attributes, and without a
                # complete cross-event listing (the writer's own, or the caller's ``known_source_keys``)
                # nothing else names them: nothing of the group is written.
                logger.error(
                    "MISP push %s (%s): the lookup of a later part failed and there is no complete cross-event "
                    "listing — %d attribute(s) counted as failed, nothing written",
                    source,
                    date,
                    len(unique_attrs),
                )
                self.stats["errors"] += 1
                total_failed += len(unique_attrs)
                _note_unstored(unique_attrs, at_the_event=True)
                continue
            # 2026-10: the part found above takes attributes up to ``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE``, the later
            # parts that exist take what fits them, and the rest goes to new parts of at most the limit each.
            # A new part is created by the push loop when its first batch is about to be written
            # (``_PendingPart``), so a push that stops early leaves no empty part.
            later = range(target, len(part_ids))
            chunks, new_chunks = _allot_to_parts(
                unique_attrs, [split_above - part_sizes[k] for k in later], split_above
            )
            for k, chunk in zip(later, chunks, strict=True):
                if chunk:
                    push_queue.append((source, part_ids[k], part_sizes[k], chunk))
            if new_chunks and not walk_complete:
                lost = [a for chunk in new_chunks for a in chunk]
                logger.error(
                    "MISP push %s (%s): %d attribute(s) do not fit the parts found, and the lookup of the next "
                    "part failed — counted as failed, no part created",
                    source,
                    date,
                    len(lost),
                )
                self.stats["errors"] += 1
                total_failed += len(lost)
                _note_unstored(lost, at_the_event=True)
                new_chunks = []
            for part_no, chunk in enumerate(new_chunks, start=len(part_ids) + 1):
                push_queue.append((source, _PendingPart(source, date, part_no), 0, chunk))
            if len(part_ids) > 1 or new_chunks:
                logger.info(
                    "MISP push %s (%s): split above %d — %s",
                    source,
                    date,
                    split_above,
                    "; ".join(
                        [
                            f"part {k + 1} (event {part_ids[k]}) holds {part_sizes[k]}, takes {len(chunk)}"
                            for k, chunk in zip(later, chunks, strict=True)
                        ]
                        + [f"new part {n} takes {len(c)}" for n, c in enumerate(new_chunks, start=len(part_ids) + 1)]
                    ),
                )

        # Only a true dedup skip: nothing failed (#216: a group whose event lookup/creation failed is
        # counted as failed) and nothing was dropped in conversion (2026-10; a drop that is only
        # reported rules the line out too, since not every item was present), and N is the number
        # of attributes MISP was found to hold.
        if not push_queue and present_ct > 0 and total_failed == 0 and not_converted_ct == 0:
            logger.warning(
                "[DEDUP] All %d items were already present in MISP — nothing new to push. "
                "This is normal on re-runs. Use 'edgeguard fresh-baseline' (the edgeguard_baseline DAG with "
                "fresh_baseline) to force re-collection.",
                present_ct,
            )

        # Throttle delay between batches — gives MISP time to free memory
        # when processing large events (e.g. the OTX event of a 730-day baseline, about 150,000 attributes).
        try:
            batch_throttle = float(os.environ.get("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "5.0"))
        except (ValueError, TypeError):
            batch_throttle = 5.0

        # PR-N4 adaptive-scaling thresholds + backoff knobs (env-tunable
        # so ops can tune without code change). See push_items docstring.
        #
        # PR-N4 round 2 (Bugbot R2-B + 7-agent audit Red Team #1, Bug Hunter
        # #2): every env var is now BOUNDS-CHECKED on parse. Pre-fix, an
        # operator setting ``EDGEGUARD_MISP_BACKOFF_THRESHOLD=0`` would
        # immediately satisfy ``_consecutive_failures (0) >= 0``, firing
        # the 5-min cooldown on the first batch and turning a 30-min push
        # into a multi-hour stall with the confusing log "0 consecutive
        # 5xx failures — entering extended cooldown." Negative values had
        # similar pathologies. Now: unparseable / out-of-bounds values
        # log a WARNING and use the safe default. See docs/MISP_TUNING.md
        # § "EdgeGuard-side env knobs" for valid ranges.
        def _bounded_int_env(name: str, default: int, *, lo: int, hi: int) -> int:
            raw = os.environ.get(name)
            if not raw:
                return default
            try:
                val = int(raw.strip())
            except (ValueError, TypeError):
                logger.warning("%s=%r is not a valid integer; using default %d", name, raw, default)
                return default
            if val < lo or val > hi:
                logger.warning(
                    "%s=%d is out of valid range [%d, %d]; using default %d",
                    name,
                    val,
                    lo,
                    hi,
                    default,
                )
                return default
            return val

        def _bounded_float_env(name: str, default: float, *, lo: float, hi: float) -> float:
            raw = os.environ.get(name)
            if not raw:
                return default
            try:
                val = float(raw.strip())
            except (ValueError, TypeError):
                logger.warning("%s=%r is not a valid float; using default %.1f", name, raw, default)
                return default
            # Bugbot R5 (commit bb86c329): reject NaN and ±inf BEFORE the
            # bounds check.  Python's ``float("nan") < lo`` and ``> hi``
            # both return False, so NaN slips past the ``val < lo or
            # val > hi`` guard and propagates into the caller. For
            # ``_backoff_cooldown_sec`` specifically this silently
            # DISABLES the cooldown: the ``_backoff_cooldown_sec > 0``
            # check later in push_items evaluates False for NaN, so the
            # adaptive cooldown never fires — the opposite of what an
            # operator setting an (accidentally-NaN) value intended.
            # ``math.isfinite()`` rejects NaN, +inf, and -inf in one
            # call.  ``_bounded_int_env`` doesn't need this guard
            # because ``int("nan")`` / ``int("inf")`` raise ValueError
            # and take the parse-fail branch above.
            if not math.isfinite(val):
                logger.warning(
                    "%s=%r resolved to non-finite value (NaN/inf); using default %.1f",
                    name,
                    raw,
                    default,
                )
                return default
            if val < lo or val > hi:
                logger.warning(
                    "%s=%.1f is out of valid range [%.1f, %.1f]; using default %.1f",
                    name,
                    val,
                    lo,
                    hi,
                    default,
                )
                return default
            return val

        # Bounds rationale:
        # * tier thresholds (large / huge): floor 1 (no zero — would
        #   classify every event as "huge"); ceil 10M (sanity cap; MISP
        #   events with >10M attrs are pathological regardless)
        # * backoff threshold: floor 2 (one consecutive 5xx isn't enough
        #   to warrant a 5-min pause; require at least 2 — this matches
        #   the comment intent and prevents an operator typo of "1"
        #   from turning the @retry_with_backoff's first-attempt-fail
        #   into a 5-min stall); ceil 100 (effectively-disabled threshold).
        #   Bugbot R4 (commit 001846b) caught the prior floor=1 silently
        #   contradicting this comment — now load-bearing.
        # * cooldown: floor 0.0 (operator can disable the cooldown by
        #   setting to 0; the cooldown branch then becomes a no-op);
        #   ceil 3600.0 (1 hour — anything longer is almost certainly
        #   a typo, e.g. 999999)
        _large_threshold = _bounded_int_env("EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD", 50000, lo=1, hi=10_000_000)
        _huge_threshold = _bounded_int_env("EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD", 100000, lo=1, hi=10_000_000)
        _backoff_threshold = _bounded_int_env("EDGEGUARD_MISP_BACKOFF_THRESHOLD", 3, lo=2, hi=100)
        _backoff_cooldown_sec = _bounded_float_env("EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC", 300.0, lo=0.0, hi=3600.0)

        # PR-N4 round 2 (Red Team #6, Bug Hunter #3, Devil's Advocate):
        # validate that HUGE > LARGE so the tier-resolution logic below
        # produces semantically correct labels.  Pre-fix, an operator
        # mistakenly setting LARGE=100000, HUGE=50000 (inverted) would
        # cause every event in the 50K-100K range to mis-label as "huge"
        # and over-throttle (50/batch + 30s instead of 100/batch + 15s).
        # Auto-swap + warn rather than silently accept the inversion.
        if _huge_threshold <= _large_threshold:
            logger.warning(
                "MISP adaptive-scaling thresholds inverted: LARGE=%d, HUGE=%d "
                "(huge must be > large). Auto-swapping; please fix the env vars "
                "EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD / "
                "EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD per docs/MISP_TUNING.md.",
                _large_threshold,
                _huge_threshold,
            )
            _large_threshold, _huge_threshold = _huge_threshold, _large_threshold

        # PR-N4 helper: resolve the adaptive-scaling tier from an
        # existing-attribute count. Defined inside push_items so the
        # closure captures the env-tuned thresholds; both the
        # ``total_batches`` precompute (immediately below) and the
        # inner loop (further below) use the same logic — no
        # duplication / drift risk.
        def _adaptive_for(existing_ct: int) -> Tuple[int, float, str]:
            if existing_ct >= _huge_threshold:
                return min(50, batch_size), max(30.0, batch_throttle), "huge"
            if existing_ct >= _large_threshold:
                return min(100, batch_size), max(15.0, batch_throttle), "large"
            return batch_size, batch_throttle, "default"

        # PR-N4 (Bugbot round 1, LOW): ``total_batches`` recomputed using
        # the per-event ``effective_batch_size`` (the adaptive tier may
        # downscale from the static ``batch_size``). Pre-fix this was
        # computed once with the static value, so when scaling kicked in
        # the progress log reported >100% and negative ETAs on huge
        # events. Now uses the same ``_adaptive_for`` helper as the inner
        # loop — single source of truth.
        total_batches = sum(
            len(_batches(attrs, _adaptive_for(existing_ct)[0], _key_of))
            for _src, _eid, existing_ct, attrs in push_queue
        )

        # PR-N4 round 2 (Devil's Advocate #1): track consecutive 5xx
        # failures on the WRITER INSTANCE so the count persists across
        # successive ``push_items`` calls. Pre-fix the counter was
        # local-var scoped (`_consecutive_failures = 0` at function
        # entry) and reset every call — meaning a sustained MISP
        # degradation that flapped across multiple push_items calls
        # never accumulated 3 consecutive failures within ANY single
        # call, so the cooldown never fired even though MISP was clearly
        # struggling. Now the count is on ``self`` and only resets on
        # SUSTAINED recovery (Fix #3 below).
        #
        # Defensive ``getattr`` (not ``self.``): same pattern as
        # ``liveness_callback`` lower in the file — existing tests
        # construct MISPWriter via __new__ and bypass __init__, so the
        # instance attribute may not exist on test instances.
        if not hasattr(self, "_misp_push_consecutive_failures"):
            self._misp_push_consecutive_failures = 0
        if not hasattr(self, "_misp_push_consecutive_successes"):
            self._misp_push_consecutive_successes = 0

        # 2026-10: (source, date) groups whose new part could not be created; their later parts are not
        # created either, so the walk of the next push finds no part after a gap.
        failed_part_groups: set = set()
        # 2026-11-02: the batch before which *deadline* stopped the push (0: not stopped); no later batch is sent.
        stopped_before_batch = 0
        # 2026-11-03: the batches and attributes not sent because the push stopped (``stop``).
        unsent_batches = unsent_attrs = 0

        def _note_unsent(attrs: List[Dict], batch_count: int) -> None:
            # 2026-11-03: attributes not sent because the push stopped; they count as failed, as ``_push_batch``
            # counts a failed batch (values that cannot be stored included), and their items are listed.
            nonlocal total_failed, unsent_batches, unsent_attrs
            total_failed += len(attrs)
            unsent_attrs += len(attrs)
            unsent_batches += batch_count
            _note_unstored(attrs, unsent=True)

        for source, event_id, existing_attrs_count, unique_attrs in push_queue:
            if stopped_before_batch:
                _note_skipped(unique_attrs)
                continue
            pending = event_id if isinstance(event_id, _PendingPart) else None
            if pending is not None:
                event_id = None
                if (pending.source, pending.date) in failed_part_groups:
                    total_batches -= len(_batches(unique_attrs, _adaptive_for(existing_attrs_count)[0], _key_of))
                    logger.error(
                        "MISP push %s (%s): part %d not created — %d attribute(s) counted as failed",
                        pending.source,
                        pending.date,
                        pending.part,
                        len(unique_attrs),
                    )
                    total_failed += len(unique_attrs)
                    _note_unstored(unique_attrs, at_the_event=True)
                    continue
            if stop is not None:
                # 2026-11-03: after a stop no batch of a later entry is sent and no part is created.
                _note_unsent(unique_attrs, len(_batches(unique_attrs, _adaptive_for(existing_attrs_count)[0], _key_of)))
                continue
            # PR-N4: ADAPTIVE SCALING. ``existing_attrs_count`` was
            # captured during the dedup loop above (we already paid for
            # ``_get_existing_attribute_keys(event_id)`` there) and
            # threaded through ``push_queue``. No second MISP call here.
            #
            # Bugbot round 1 caught the duplicate fetch (lines 1505 and
            # 1613 both called the same paginated 30-60s REST endpoint)
            # AND the silent except-pass that defaulted to 0 on lookup
            # failure (defeating adaptive scaling exactly when it was
            # most needed). Both fixed by threading the dedup-time count
            # through ``push_queue``.
            effective_batch_size, effective_throttle, _scale_tier = _adaptive_for(existing_attrs_count)
            if _scale_tier != "default":
                logger.info(
                    "[PUSH] Event %s has %d existing attrs (>= %s threshold) — "
                    "adaptive scaling: batch_size=%d, throttle=%.0fs (was %d / %.0fs)",
                    event_id,
                    existing_attrs_count,
                    _scale_tier,
                    effective_batch_size,
                    effective_throttle,
                    batch_size,
                    batch_throttle,
                )

            # Send attributes in batches (2026-11-02: apart per *batch_key*, ``_batches``)
            queue_batches = _batches(unique_attrs, effective_batch_size, _key_of)
            for i, batch in enumerate(queue_batches):
                # 2026-11-03 (a cap on failure time, ``_failing_streak``): while MISP keeps failing, the push stops
                # before this batch when the batch would start at or after the streak's cap: the streak has reached
                # it, or the throttle pause and the back-off cooldown due before the batch would reach it (they are
                # not slept). Nothing more is sent: the attributes of this batch and of every later one count as
                # failed (``_note_unsent``). Read only while a streak is on, so a push MISP answers is never
                # stopped by time alone.
                streak = _failing_streak(self)
                if streak is not None:
                    cap, failing_for = streak
                    pause = effective_throttle if (i > 0 or processed_batches > 0) and effective_throttle > 0 else 0.0
                    if self._misp_push_consecutive_failures >= _backoff_threshold and _backoff_cooldown_sec > 0:
                        pause += _backoff_cooldown_sec
                    if failing_for + pause >= cap:
                        stop = (str(source), processed_batches + 1, cap, failing_for)
                        rest = queue_batches[i:]
                        _note_unsent([a for b in rest for a in b], len(rest))
                        break

                # 2026-11-02 (*deadline*): the batch starts only when the throttle pause before it, and the
                # back-off cooldown when one is due, end before the deadline. Otherwise nothing more is sent:
                # the items of this batch and of every later one are skipped, neither stored nor failed.
                if deadline is not None:
                    wait = effective_throttle if (i > 0 or processed_batches > 0) and effective_throttle > 0 else 0.0
                    if self._misp_push_consecutive_failures >= _backoff_threshold and _backoff_cooldown_sec > 0:
                        wait += _backoff_cooldown_sec
                    if time.monotonic() + wait >= deadline:
                        _note_skipped([a for rest in queue_batches[i:] for a in rest])
                        stopped_before_batch = processed_batches + 1
                        break

                # Throttle between batches (skip only the very first batch of the first event)
                if (i > 0 or processed_batches > 0) and effective_throttle > 0:
                    time.sleep(effective_throttle)

                # PR-N4 adaptive backoff: if we've seen N consecutive 5xx
                # failures (instance-scoped via self._misp_push_*), insert
                # an extended cooldown BEFORE retrying. The
                # @retry_with_backoff decorator on _push_batch retries
                # internally with 10s × 2^n delay (max ~70s budget per
                # batch); that's not enough when the underlying MISP is
                # stuck OOMing. The cooldown gives MISP a real chance to
                # recover before we send the next request.
                #
                # PR-N4 round 2 (Logic Tracker #1, Prod Readiness #3 #7):
                # CHUNKED sleep with a liveness check between chunks.
                # Pre-fix the cooldown was a single ``time.sleep(300)``
                # call that blocked the parent-DAG liveness callback for
                # the full 5 minutes. If a sibling DAG task failed during
                # that window, EdgeGuard slept through the failure signal
                # and continued pushing for ~5 min before noticing.
                # Now we sleep in 30s chunks, calling the liveness
                # callback between each — DAG-failure detection latency
                # drops from 5min to ~30s.
                if self._misp_push_consecutive_failures >= _backoff_threshold and _backoff_cooldown_sec > 0:
                    logger.warning(
                        "[PUSH] %d consecutive 5xx failures (>= threshold %d) — "
                        "entering extended cooldown for %.0fs before next batch. "
                        "MISP backend appears overwhelmed; check backend RAM / "
                        "PHP memory_limit / MySQL innodb_buffer_pool_size — see "
                        "docs/MISP_TUNING.md.",
                        self._misp_push_consecutive_failures,
                        _backoff_threshold,
                        _backoff_cooldown_sec,
                    )
                    if _METRICS_AVAILABLE:
                        try:
                            _MISP_BACKOFF_TRIGGERED.labels(source=source).inc()
                        except Exception as _metric_err:
                            # Bugbot (PR-N4 round 1): don't swallow silently.
                            # Metric failures shouldn't block the push, but they
                            # SHOULD be debuggable — if Prometheus client is
                            # mis-configured (e.g. duplicate registry registration)
                            # the operator needs to see something other than
                            # "no metric ever increments."
                            logger.debug(
                                "MISP backoff-triggered metric increment failed: %s",
                                _metric_err,
                                exc_info=True,
                            )
                    # Chunked sleep + liveness check. ``_BACKOFF_LIVENESS_CHUNK_SEC``
                    # default 30s — short enough to detect parent-DAG death
                    # within 30s, long enough that we don't burn CPU calling
                    # the rate-limited liveness callback.
                    _liveness_cb_in_cooldown = getattr(self, "liveness_callback", None)
                    _chunk = 30.0
                    _slept = 0.0
                    while _slept < _backoff_cooldown_sec:
                        _step = min(_chunk, _backoff_cooldown_sec - _slept)
                        time.sleep(_step)
                        _slept += _step
                        # Liveness check; re-raises AbortedByDagFailureException
                        # if parent DAG died (per PR-F6 contract).
                        if _liveness_cb_in_cooldown is not None:
                            _liveness_cb_in_cooldown()
                        # 2026-11-03: after a step, while the cooldown has at least the probe's timeouts left, a
                        # light request (``_misp_answers``): MISP answering it with HTTP 200 ends the cooldown
                        # early. The time the request takes counts toward the cooldown, so a probe that waits out
                        # its timeouts never makes the cooldown longer than its length.
                        if _backoff_cooldown_sec - _slept >= sum(self.COOLDOWN_PROBE_TIMEOUT):
                            _probe_started = time.monotonic()
                            _answered = self._misp_answers(source)
                            _slept += max(0.0, time.monotonic() - _probe_started)
                            if _answered:
                                logger.info(
                                    "[PUSH] MISP answered after %.0fs of the %.0fs cooldown — the push goes on",
                                    _slept,
                                    _backoff_cooldown_sec,
                                )
                                break
                    # Reset the counter so we don't immediately re-pause
                    # if the next batch ALSO fails — the @retry_with_backoff
                    # gives it 4 attempts; if those fail, we'll re-trigger
                    # the cooldown after another N consecutive batch-level
                    # failures.
                    self._misp_push_consecutive_failures = 0
                    self._misp_push_consecutive_successes = 0

                # PR-F6 (Issue #65): parent-DAG liveness check BEFORE the
                # next push. If the parent dag_run has been marked failed
                # (e.g., a sibling task failed), the callback raises
                # ``AbortedByDagFailureException`` to exit the collector
                # cleanly between batches — no half-written events. The
                # callback is rate-limited internally (default 60s
                # between actual API probes), so calling it every batch
                # is cheap. ``None`` (the default) preserves legacy
                # behavior — push_items runs to completion regardless.
                # Re-raises ANY exception from the callback so callers
                # can distinguish parent-DAG-died from other failures.
                #
                # ``getattr`` (not ``self.``) is deliberate: existing tests
                # construct MISPWriter via ``__new__`` to bypass __init__
                # for test-isolation reasons (see
                # tests/test_incremental_dedup.py). The new
                # ``liveness_callback`` attribute would otherwise be
                # missing on those instances and crash push_items. The
                # defensive ``getattr`` keeps the legacy test pattern
                # working without requiring every test to opt-in.
                liveness_cb = getattr(self, "liveness_callback", None)
                if liveness_cb is not None:
                    liveness_cb()

                # 2026-11-03: checked again after the pause, the cooldown and the liveness check, which can take longer
                # than counted above: no batch starts here once the streak has reached its cap. A new part is created
                # after this check, so a slow creation lets its first batch start past the cap.
                streak = _failing_streak(self)
                if streak is not None and streak[1] >= streak[0]:
                    stop = (str(source), processed_batches + 1, streak[0], streak[1])
                    rest = queue_batches[i:]
                    _note_unsent([a for b in rest for a in b], len(rest))
                    break

                # 2026-10: a new part of the event split is created here, after the throttle pause, the
                # back-off cooldown and the liveness check of its first batch, so a push that stops before it
                # writes to a part leaves no empty part. A part that cannot be created fails its attributes
                # and every later new part of its group (``failed_part_groups``).
                if pending is not None and event_id is None:
                    try:
                        event_id = self._get_or_create_event(pending.source, pending.date, pending.part)
                    except _TRANSIENT_HTTP_ERRORS as e:
                        logger.error(
                            "Creation of part %d of %s (%s) failed after retries (%s: %s)",
                            pending.part,
                            pending.source,
                            pending.date,
                            type(e).__name__,
                            e,
                        )
                        self.stats["errors"] += 1
                    if not event_id:
                        failed_part_groups.add((pending.source, pending.date))
                        total_batches -= len(_batches(unique_attrs, effective_batch_size, _key_of))
                        logger.error(
                            "MISP push %s (%s): part %d not created — %d attribute(s) counted as failed",
                            pending.source,
                            pending.date,
                            pending.part,
                            len(unique_attrs),
                        )
                        total_failed += len(unique_attrs)
                        _note_unstored(unique_attrs, at_the_event=True)
                        break
                    logger.info(
                        "MISP push %s (%s): part %d is event %s — %d attribute(s) go to it",
                        pending.source,
                        pending.date,
                        pending.part,
                        event_id,
                        len(unique_attrs),
                    )

                # Progress logging
                processed_batches += 1
                elapsed = time.time() - start_time
                progress_pct = (processed_batches / total_batches * 100) if total_batches > 0 else 0

                # Calculate estimated remaining time
                if processed_batches > 0:
                    avg_time_per_batch = elapsed / processed_batches
                    remaining_batches = total_batches - processed_batches
                    eta_seconds = avg_time_per_batch * remaining_batches
                    eta_str = f"~{int(eta_seconds)}s remaining"
                else:
                    eta_str = "calculating..."

                logger.info(
                    f"[PUSH] Pushing batch {processed_batches}/{total_batches} ({progress_pct:.1f}%) - {elapsed:.1f}s elapsed, {eta_str}"
                )

                # After @retry_with_backoff exhausts its attempts on a
                # persistent 5xx, _push_batch re-raises MispTransientError.
                # Without this try/except the exception would crash out of
                # push_items and skip every remaining batch and event in the
                # push queue — strictly worse than the pre-fix behaviour
                # where 5xx returned (0, len(attributes)) and the loop
                # continued. Count the batch as failed and move on so one
                # bad event doesn't destroy a whole NVD push.
                try:
                    success, failed = self._push_batch(event_id, batch)
                    # 2026-11-03: MISP answered the batch, so a failing streak ends (``_failing_streak``).
                    self._misp_push_failing_since = None
                    if success == 0 and failed:
                        # HTTP 4xx, a batch error, none confirmed (strict) or an event id empty once sanitised: none
                        # stored. 2026-11-02: an empty id sent no request, so its items failed at the event.
                        _note_unstored(batch, at_the_event=not sanitize_value(str(event_id), max_length=20))
                    # PR-N4 round 2 (Cross-Checker #2, Bug Hunter #5):
                    # require N CONSECUTIVE FULL SUCCESSES before
                    # resetting the failure counter. Pre-fix, a single
                    # success between two failure clusters reset the
                    # counter, masking a chronically-flapping backend.
                    # ``_REQUIRED_RECOVERIES = 2`` — one success could
                    # be a fluke; two suggests genuine recovery. Kept
                    # in-function (not env-tunable) because the right
                    # answer doesn't vary across deployments.
                    if success > 0 and failed == 0:
                        self._misp_push_consecutive_successes += 1
                        if self._misp_push_consecutive_successes >= 2:
                            self._misp_push_consecutive_failures = 0
                    else:
                        # Partial success (some attrs failed but no exception):
                        # don't count as recovery, but don't punish either.
                        self._misp_push_consecutive_successes = 0
                except MispTransientError as exc:
                    # PR-N4 round 2 (Bug Hunter #6, Prod Readiness #11):
                    # sanitize event_id in log output. ``event_id`` is
                    # operator-controlled-but-tainted (it comes from MISP
                    # API responses; if MISP is compromised, it could
                    # contain log-injection sequences). Strip ANSI/control
                    # chars defensively.
                    _safe_event_id = "".join(c for c in str(event_id) if c.isprintable() and c not in ("\r", "\n"))[:64]
                    # 2026-11-02: what MISP held of the batch after the last 5xx (``_stored_after_server_error``)
                    # counts as pushed; only the rest failed. Unknown (None, a timeout or a failed lookup):
                    # the whole batch failed.
                    stored_after_error = getattr(exc, "stored_after_error", None)
                    if stored_after_error is not None:
                        success, unstored = stored_after_error
                        failed = len(batch) - success
                        self.stats["attributes_added"] += success
                        _note_unstored(unstored)
                    else:
                        success, failed = 0, len(batch)
                        _note_unstored(batch)
                    logger.error(
                        "Batch %s for event %s failed after retries (%s) — %d of %d attribute(s) counted as failed "
                        "and continuing",
                        processed_batches,
                        _safe_event_id,
                        exc,
                        failed,
                        len(batch),
                    )
                    self.stats["errors"] += 1
                    # PR-N4 round 2 (Cross-Checker #2): instance-scoped
                    # counter persists across push_items calls so a
                    # flapping backend eventually trips the cooldown.
                    self._misp_push_consecutive_failures += 1
                    self._misp_push_consecutive_successes = 0
                    # PR-N4: emit Prometheus permanent-failure counter so
                    # operators can alert on data loss rate. Pre-PR-N4 the
                    # only signal was the log line above, which Bravo had
                    # to hand-count from. ``source`` is the resolved
                    # source string from the outer loop's ``grouped`` dict.
                    #
                    # PR-N4 round 2 (Maintainer Dev #4, Bug Hunter #4):
                    # DROPPED ``event_id`` label. Each MISP run creates a
                    # new event_id (date-stamped), so labelling by event_id
                    # produced a new Prometheus time series every day.
                    # Over 365 days that's 365 unbounded series PER
                    # SOURCE — would balloon Prometheus storage and
                    # slow alerting queries. ``source`` alone gives
                    # operators the actionable signal ("OTX is dropping
                    # batches") without the cardinality.
                    if _METRICS_AVAILABLE:
                        try:
                            _MISP_PUSH_PERMANENT_FAILURES.labels(source=source).inc()
                        except Exception as _metric_err:
                            # Bugbot (PR-N4 round 1): don't swallow silently.
                            # See backoff-trigger metric block above for rationale.
                            logger.debug(
                                "MISP permanent-failure metric increment failed: %s",
                                _metric_err,
                                exc_info=True,
                            )
                total_success += success
                total_failed += failed

        if stopped_before_batch:
            logger.info(
                "[PUSH] the push's deadline came before batch %d of %d could start: %d item(s) not sent, neither "
                "stored nor failed",
                stopped_before_batch,
                total_batches,
                len(skipped_positions),
            )

        stopped_note = ""
        if stop is not None:
            # 2026-11-03: one ERROR and one count per stopped push. The back-off counters are reset here only, so
            # the next push on this writer does not begin with a cooldown; otherwise they carry over between calls.
            stop_source, stop_batch, stop_cap, stop_failing = stop
            self._misp_push_consecutive_failures = 0
            self._misp_push_consecutive_successes = 0
            logger.error(
                "[MISP-PUSH-STOPPED] MISP push %s: MISP kept failing for %.0fs (%s), so the push stopped before "
                "batch %d of %d: %d batch(es) with %d attribute(s) not sent, counted as failed; the push ends and "
                "the run goes on",
                stop_source,
                stop_failing,
                _push_cap_text(self, stop_cap),
                stop_batch,
                total_batches,
                unsent_batches,
                unsent_attrs,
            )
            if _METRICS_AVAILABLE and _MISP_PUSH_STOPPED is not None:
                try:
                    _MISP_PUSH_STOPPED.labels(source=stop_source).inc()
                except Exception as _metric_err:
                    logger.debug("MISP push-stopped metric increment failed: %s", _metric_err, exc_info=True)
            stopped_note = (
                f"; stopped after {stop_failing:.0f}s of MISP failing, {unsent_attrs} attribute(s) not sent "
                "([MISP-PUSH-STOPPED])"
            )

        refreshed_note = ""
        if refresh_due and stop is not None:
            # 2026-11-03: no refresh edit after a stop: each would meet the MISP that stopped the push. The edits due
            # are left for a later run that reports the indicators again, as the refresh's own limits leave them.
            self.stats["attributes_refresh_deferred"] = self.stats.get("attributes_refresh_deferred", 0) + len(
                refresh_due
            )
            logger.warning(
                "[REFRESH] %d re-reported indicator(s) whose stored copy MISP last wrote more than %d days ago: "
                "0 refreshed, 0 failed, %d left for a later run (the push stopped: MISP kept failing)",
                len(refresh_due),
                refresh_days,
                len(refresh_due),
            )
            refreshed_note = f"; {len(refresh_due)} refresh(es) of existing attributes left for a later run"
        elif refresh_due:
            refreshed, _refresh_failed = self._refresh_stored_copies(refresh_due, refresh_days, deadline=deadline)
            refreshed_note = f"; {refreshed} existing attribute(s) refreshed"
        skipped_note = (
            f"; {len(skipped_positions)} item(s) not sent before the push's deadline" if skipped_positions else ""
        )

        # Final summary. 2026-10: the items dropped in conversion but not counted as failed are named,
        # so that neither line reads as if every item had been pushed or found present.
        total_elapsed = time.time() - start_time
        reported_only_ct = not_converted_ct - not_converted_failed_ct
        reported_note = (
            f"; {reported_only_ct} item(s) not converted, not counted as failed ([CONVERT])" if reported_only_ct else ""
        )
        stored_after_5xx = self.__dict__.get("stats", {}).get("batches_stored_after_5xx", 0) - stored_after_5xx_before
        stored_note = (
            f"; {stored_after_5xx} batch(es) stored although MISP answered HTTP 5xx ([STORED-AFTER-5XX])"
            if stored_after_5xx
            else ""
        )
        if total_success > 0 or total_failed > 0:
            logger.info(
                f"[OK] MISP push complete: {total_success} succeeded, {total_failed} failed{reported_note}"
                f"{stored_note}{refreshed_note}{skipped_note}{stopped_note} in {total_elapsed:.1f}s"
            )
        elif skipped_positions:
            logger.info(
                f"[SKIP] MISP push: 0 attributes pushed{reported_note}{refreshed_note}{skipped_note} "
                f"in {total_elapsed:.1f}s"
            )
        elif total_items > 0:
            deduplicated = (
                f"{total_items - not_converted_ct} items deduplicated{reported_note}"
                if not_converted_ct
                else f"{total_items} items all deduplicated"
            )
            logger.info(
                f"[SKIP] MISP push: 0 new attributes to push ({deduplicated}{refreshed_note}) in {total_elapsed:.1f}s"
            )
        else:
            logger.info("[OK] MISP push: no items provided")

        self.last_push_unstored_items = sorted(unstored_positions)
        self.last_push_event_failed_items = sorted(event_failed_positions)
        self.last_push_skipped_items = sorted(skipped_positions)
        self.last_push_unsent_items = sorted(unsent_positions)
        self.last_push_stopped = stop is not None
        # 2026-11-03: the cap belongs to this call; a request made outside a push has none.
        self._misp_push_failing_cap = None
        self._misp_push_failing_since = None
        return total_success, total_failed

    def _refresh_stored_copies(
        self,
        due: Dict[Tuple[str, str], Tuple[StoredCopy, Optional[str]]],
        refresh_days: int,
        deadline: Optional[float] = None,
    ) -> Tuple[int, int]:
        """Refresh the stored copies of indicators a source reported again (2026-10).

        ``due`` maps ``(type, value)`` to the ``StoredCopy`` to edit and the ``last_seen`` of the
        re-reported item (None when the source sends none). Each copy gets one ``update_attribute``
        edit with ``{"last_seen": ...}`` and nothing else: value, type, tags and comment stay as they
        are. The value sent is the source's claim when it is later than the stored one, otherwise
        the stored value unchanged (``_refreshed_last_seen``): the field holds what a source claimed,
        never the time of a run. The edit exists for its side effect: MISP stamps the attribute and
        its event with a new timestamp, so the incremental MISP → Neo4j sync reads the attribute
        again, and the next refresh of the copy is due only one interval later. Since 2026-10-16
        the indicator ages from the source's ``last_seen`` capped at that timestamp
        (``indicator_aging``): the edit moves its age when the source's date moved, or, for a source
        without a date, to the time of the edit. MISP's answer must show a timestamp later than
        the stored one.

        The longest unwritten go first, at most ``EDGEGUARD_MISP_REFRESH_MAX_PER_RUN``. The edits
        are paced like the NVD edits (``EDGEGUARD_MISP_BATCH_THROTTLE_SEC`` after every
        ``EDITS_PER_THROTTLE``) and check the parent-DAG liveness callback at the same points. They
        stop once ``EDGEGUARD_MISP_REFRESH_MAX_SECONDS`` is spent or after
        ``REFRESH_MAX_CONSECUTIVE_FAILURES`` failed edits in a row (MISP failing: each failure costs
        up to three attempts), so the refresh cannot use up the collector task's time limit. What is
        not attempted is counted as deferred and is due again on the next run that reports it. With a
        *deadline* (a ``time.monotonic()`` value, ``push_items``' argument, 2026-11-02) no edit starts at
        or after it either.
        Returns ``(refreshed, failed)``.
        """
        ordered = sorted(due.values(), key=lambda entry: entry[0].written)
        cap = misp_refresh_max_per_run()
        budget = misp_refresh_max_seconds()
        stop_reasons: List[str] = []
        deferred = 0
        if cap and len(ordered) > cap:
            deferred = len(ordered) - cap
            ordered = ordered[:cap]
            stop_reasons.append(f"EDGEGUARD_MISP_REFRESH_MAX_PER_RUN={cap}")
        now = time.time()
        started = time.monotonic()
        pause = misp_batch_throttle_seconds()
        liveness_cb = getattr(self, "liveness_callback", None)
        refreshed = failed = consecutive_failures = 0
        for done, (stored_copy, reported) in enumerate(ordered, 1):
            if budget and done > 1 and time.monotonic() - started >= budget:
                deferred += len(ordered) - done + 1
                stop_reasons.append(f"EDGEGUARD_MISP_REFRESH_MAX_SECONDS={budget} spent")
                break
            if deadline is not None and time.monotonic() >= deadline:
                deferred += len(ordered) - done + 1
                stop_reasons.append("the push's deadline came")
                break
            changes = {"last_seen": _refreshed_last_seen(stored_copy, reported, now)}
            if self.update_attribute(stored_copy.uuid, changes, written_after=stored_copy.written):
                refreshed += 1
                consecutive_failures = 0
            else:
                failed += 1
                consecutive_failures += 1
                if consecutive_failures >= REFRESH_MAX_CONSECUTIVE_FAILURES and done < len(ordered):
                    deferred += len(ordered) - done
                    stop_reasons.append(f"stopped after {consecutive_failures} failed edits in a row")
                    break
            if done % EDITS_PER_THROTTLE == 0 and done < len(ordered):
                if liveness_cb is not None:
                    liveness_cb()
                if pause:
                    time.sleep(pause)
        self.stats["attributes_refreshed"] = self.stats.get("attributes_refreshed", 0) + refreshed
        self.stats["attributes_refresh_failed"] = self.stats.get("attributes_refresh_failed", 0) + failed
        self.stats["attributes_refresh_deferred"] = self.stats.get("attributes_refresh_deferred", 0) + deferred
        log = logger.warning if failed or deferred else logger.info
        log(
            "[REFRESH] %d re-reported indicator(s) whose stored copy MISP last wrote more than %d days ago: "
            "%d refreshed, %d failed, %d left for a later run%s",
            len(due),
            refresh_days,
            refreshed,
            failed,
            deferred,
            f" ({'; '.join(stop_reasons)})" if stop_reasons else "",
        )
        return refreshed, failed

    # 2026-11-03: three retries (four attempts, 10/20/40 s apart); they were four. The event lookups keep four.
    @retry_with_backoff(max_retries=3, base_delay=10.0, give_up=_misp_retry_gives_up)
    @rate_limited(max_per_second=2.0)
    def _push_batch(self, event_id: str, attributes: List[Dict]) -> Tuple[int, int]:
        """
        Push a batch of attributes to a MISP event.

        Args:
            event_id: MISP event ID
            attributes: List of MISP attribute dicts

        Returns:
            Tuple of (successful_count, failed_count)

        2026-11-02: an event id that is empty once sanitised (MISP answered an id of only whitespace or
        control characters) sends no request and counts the batch as failed. It returned (0, 0), which
        ``push_items`` and its callers read as a batch MISP already held: the run passed, and the OTX
        cursor, which advances after a push without failures, would pass items MISP never received.
        """
        if not attributes:
            return 0, 0
        # Sanitize event_id first
        event_id = sanitize_value(event_id, max_length=20)
        if not event_id:
            logger.error(
                "MISP push: the event id is empty once sanitised — %d attribute(s) not sent, counted as failed",
                len(attributes),
            )
            self.stats["errors"] += 1
            return 0, len(attributes)
        storable = _make_attributes_storable(attributes)
        skipped_unstorable = len(attributes) - len(storable)
        attributes = storable
        if not attributes:
            return 0, skipped_unstorable

        # 2026-11-03: the start of this attempt, for the push's cap on failure time (``_failing_streak``); read only
        # while a push with a cap runs.
        cap = getattr(self, "_misp_push_failing_cap", None)
        attempt_started = time.monotonic() if _is_seconds(cap) and cap > 0 else None
        try:
            # Prepare payload
            payload = {"Attribute": attributes}

            response = self.session.post(
                f"{self.url}/events/{event_id}",
                json=payload,
                verify=self.verify_ssl,
                timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
            )

            if response.status_code == 200:
                result = response.json()
                attempted = len(attributes)
                # MISP answers the event edit with the full event: ``Event.Attribute`` lists
                # every attribute now stored on the event (newly added and pre-existing), not
                # only the ones in this batch. A pushed attribute is therefore counted only
                # when it is present in that list: HTTP 200 confirms the event edit, not every
                # attribute in it, since MISP may store the event while rejecting individual
                # attributes. A response without a usable attribute list leaves the batch
                # unverified: the attempted count is kept and the batch is recorded as such
                # in the stats.
                saved: Any = []
                errors_payload: Any = None
                if isinstance(result, dict):
                    event_body = result.get("Event")
                    if isinstance(event_body, dict):
                        saved = event_body.get("Attribute", [])
                    errors_payload = result.get("errors")
                stored_total = len(saved) if isinstance(saved, list) else (1 if isinstance(saved, dict) else 0)

                reconciled = _confirm_pushed_attributes(attributes, saved)
                if reconciled is None:
                    success_count = attempted
                    failed_count = 0
                    self.stats["batches_unverified"] = self.stats.get("batches_unverified", 0) + 1
                    logger.info(
                        "[UNVERIFIED] MISP accepted the batch for event %s (HTTP 200) but the response carried "
                        "no attribute list; counting all %d attempted attributes as pushed",
                        event_id,
                        attempted,
                    )
                else:
                    confirmed, unconfirmed = reconciled
                    strict = _strict_push_accounting()
                    if unconfirmed:
                        self.stats["attributes_unconfirmed"] = self.stats.get("attributes_unconfirmed", 0) + len(
                            unconfirmed
                        )
                        logger.warning(
                            "[UNCONFIRMED] MISP returned HTTP 200 for event %s but %d of %d pushed attributes "
                            "are absent from the returned event (sample: %s)%s — %s",
                            event_id,
                            len(unconfirmed),
                            attempted,
                            unconfirmed[:5],
                            f" — response errors: {str(errors_payload)[:500]}" if errors_payload else "",
                            "counted as failed (EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING)"
                            if strict
                            else "counted as pushed; set EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING=true to count them as failed",
                        )
                    if strict:
                        success_count, failed_count = confirmed, len(unconfirmed)
                    else:
                        success_count, failed_count = attempted, 0

                self.stats["attributes_added"] += success_count
                self.stats["batches_sent"] += 1

                logger.info(
                    f"[OK] Added {success_count} attributes to event {event_id} (total in event: {stored_total})"
                )

                return success_count, failed_count + skipped_unstorable
            else:
                # 400 responses usually include a JSON error body — log enough to debug MISP validation.
                detail = (response.text or "")[:4000]
                types_in_batch = [a.get("type") for a in attributes[:30]]
                logger.error(
                    "Failed to add attributes: %s — attribute types (first 30): %s — body (truncated): %s",
                    response.status_code,
                    types_in_batch,
                    detail,
                )
                # 5xx is usually transient (MISP under memory pressure on large
                # NVD events); raise so @retry_with_backoff can give it another
                # shot with exponential delay. Do NOT increment stats["errors"]
                # here — the decorator may succeed on a later attempt, and we
                # don't want to inflate the counter once per retry. The
                # terminal failure path (last raise from the decorator) is
                # handled by the outer caller which counts failed_count.
                if response.status_code == 429 or response.status_code >= 500:
                    stored = None
                    if response.status_code == 429:
                        # Rate limited: honour Retry-After (bounded by collector_utils) before the
                        # decorator's exponential backoff retries the batch.
                        wait = retry_after_sleep_seconds(response, fallback=0.0)
                        # 2026-11-03: at most the time left of the push's cap on failure time; none left, no wait.
                        streak = (
                            _failing_streak(self, attempt_started) if wait and attempt_started is not None else None
                        )
                        if streak is not None and wait > streak[0] - streak[1]:
                            wait = max(0.0, streak[0] - streak[1])
                            logger.warning(
                                "MISP rate limit (HTTP 429) on event %s: the Retry-After wait is cut to %.0fs, the "
                                "time left of the push's cap on failure time (%s)",
                                event_id,
                                wait,
                                _push_cap_text(self, streak[0]),
                            )
                        if wait:
                            logger.warning(
                                "MISP rate limit (HTTP 429) on event %s — sleeping %.0fs (Retry-After) before the retry",
                                event_id,
                                wait,
                            )
                            time.sleep(wait)
                    else:
                        # 2026-11-02: a 5xx can come after the save (``_stored_after_server_error``): a batch
                        # MISP stored in full is pushed, not sent again. 2026-11-03: the lookup gets only the time
                        # left of the push's cap on failure time; this attempt starts the streak when none is on.
                        streak = _failing_streak(self, attempt_started) if attempt_started is not None else None
                        until = None if streak is None else time.monotonic() + streak[0] - streak[1]
                        stored = self._stored_after_server_error(event_id, attributes, until=until)
                        if stored is not None and not stored[1]:
                            self.stats["attributes_added"] += stored[0]
                            self.stats["batches_sent"] += 1
                            self.stats["batches_stored_after_5xx"] = self.stats.get("batches_stored_after_5xx", 0) + 1
                            logger.warning(
                                "[STORED-AFTER-5XX] MISP answered HTTP %s for event %s but holds all %d attributes of "
                                "the batch — counted as pushed, not sent again. MISP saved the batch and then failed "
                                "building its answer, which lists the whole event: past the size its PHP memory_limit "
                                "can answer, every batch to this event ends so (docs/MISP_TUNING.md)",
                                response.status_code,
                                event_id,
                                stored[0],
                            )
                            return stored[0], skipped_unstorable
                    error = MispTransientError(
                        f"MISP {response.status_code} pushing batch to event {event_id}",
                        response=response,
                    )
                    # What MISP holds of the batch after this answer (None: not known), for the count of a
                    # batch whose retries all fail (``push_items``).
                    error.stored_after_error = stored
                    raise error
                # Other 4xx: permanent validation failure — count once and return.
                self.stats["errors"] += 1
                return 0, len(attributes) + skipped_unstorable

        except _TRANSIENT_HTTP_ERRORS as e:
            logger.warning(f"MISP batch transient error (will retry): {e}")
            raise
        except Exception as e:
            logger.error(f"Batch push error: {e}")
            self.stats["errors"] += 1
            return 0, len(attributes) + skipped_unstorable

    def push_indicators(self, indicators: List[Dict], source: str, batch_size: int = 500) -> Tuple[int, int]:
        """
        Push indicators to MISP (convenience method).

        Args:
            indicators: List of EdgeGuard indicator dicts
            source: Source name for the indicators
            batch_size: Number of indicators per batch

        Returns:
            Tuple of (successful_count, failed_count)
        """
        # Ensure source tag is set
        for ind in indicators:
            if "tag" not in ind or not ind["tag"]:
                ind["tag"] = source

        return self.push_items(indicators, batch_size)

    # ------------------------------------------------------------------ report records (2026-11-07)

    def push_reports(
        self,
        source: str,
        records: Sequence[Mapping[str, Any]],
        *,
        liveness_callback: Optional[Callable[[], None]] = None,
        deadline: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Write each report record of *source* (``alienvault_otx`` or ``cisa_ics``) as one MISP Event Report.

        *records*: records ``report_records.build_record`` (or ``otx_pulse_record``) made; each is normalised
        again, and one that is not a valid record of *source* fails permanently. Records with the same
        ``record_ref`` are written once: the newest ``last_modified``, the first among equals. The report's
        uuid is ``report_records.record_uuid`` (the graph node's uuid), its content ``render_content``.

        The day event is the source's ``EdgeGuard-<source>-<date>`` (``_get_or_create_event``, with its lock);
        when that event holds more attributes than ``EDGEGUARD_MISP_EVENT_SPLIT_ABOVE`` (``_event_split_above``,
        0 = never), new records go to ``EdgeGuard-<source>-<date>-reports``. Per record (docs/MISP_SOURCES.md,
        "Report records (Event Reports)"):

        1. ``POST /eventReports/add/<event id>`` with uuid, name (``report_name``, at most 255 characters),
           content, distribution (``report_distribution``: 0 for amber and red, else 5) and the tags
           ``EdgeGuard``, the source tag and ``tlp:<level>``. It is written only when the answer shows
           ``EventReport`` with that uuid, the content's SHA-256, that name and ``deleted`` false.
        2. On any HTTP 403, ``GET /eventReports/view/<uuid>``: a report in an event that is not one of the
           source's EdgeGuard events (``report_records.report_event_info_pattern``) of the writer key's
           organisation (``GET /users/view/me``) is a permanent failure (``[REPORT-UUID-FOREIGN]``); a deleted
           report is respected, never restored or edited (``reports_deleted_in_misp``); a stored meta block with
           the same digest, or with a later ``last_modified``, is left as it is (``reports_unchanged``);
           otherwise ``POST /eventReports/edit/<uuid>`` with name, content and distribution, checked as the add.
        3. After an edit that changes the record's TLP, ``removeTag`` of the old ``tlp:`` tag and ``addTag`` of
           the new one, by tag id, each checked for ``saved`` (``_swap_report_tlp``: the ``addTag`` is sent
           whatever the ``removeTag`` answered, and an old tag that is not on the report counts as gone); a
           failure counts in ``report_tag_drift`` and does not fail the record (the reader never relies on
           report tags).

        Reports never travel in ``POST /events/<id>``. These requests are not wrapped in the writer's retry
        decorator: an HTTP 4xx is never tried again, an HTTP 5xx, a timeout or a connection error once more.
        After ``REPORT_MAX_CONSECUTIVE_FAILURES`` records in a row failed that way, the rest are skipped, and
        so they are once the push's failing streak reaches its cap (``_failing_streak``,
        ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC``). ``EDGEGUARD_MISP_REPORT_THROTTLE_SEC`` is the pause between
        records. *liveness_callback* (default the writer's) is called before each record, and its exception
        propagates. *deadline*: a ``time.monotonic()`` value; for a writer given ``task_ends_at``, the task's end
        less ``PUSH_TASK_END_MARGIN_SEC`` too, whichever comes first: no record starts when its pause would end at
        or after it, and no report request starts after it. The logs carry uuid, ``record_ref``, lengths and
        SHA-256 only, never content or MISP's answers. ``last_push_*`` is not written.

        Returns the stats: ``reports_added``, ``reports_updated``, ``reports_unchanged``, ``reports_failed``
        (``reports_foreign`` among them), ``reports_deleted_in_misp``, ``report_tag_drift``,
        ``reports_skipped``; ``settled`` (the ``record_ref`` of every record MISP now holds as the record says,
        or deleted and respected), ``failed`` (``{"record_ref", "reason", "permanent"}``), ``skipped``
        (``{"record_ref", "reason"}``, not tried) and ``event_id``. ``report_records.note_report_push`` keeps
        the failed and skipped records on the source's ``report_pending`` list.
        """
        label = report_records.report_label(source)
        stats: Dict[str, Any] = {
            "source": source,
            "event_id": None,
            "reports_added": 0,
            "reports_updated": 0,
            "reports_unchanged": 0,
            "reports_failed": 0,
            "reports_deleted_in_misp": 0,
            "reports_foreign": 0,
            "report_tag_drift": 0,
            "reports_skipped": 0,
            "settled": [],
            "failed": [],
            "skipped": [],
        }
        chosen: Dict[str, Dict[str, Any]] = {}
        for given in records or []:
            try:
                record = report_records.build_record(source, given)
            except (ValueError, TypeError) as e:
                ref = given.get("record_ref") if isinstance(given, Mapping) else None
                self._report_failed(stats, ref if isinstance(ref, str) else "<invalid>", f"invalid record: {e}", True)
                continue
            ref = record["record_ref"]
            kept = chosen.get(ref)
            if kept is None or (
                report_records.iso_datetime(record["last_modified"]) or datetime.min.replace(tzinfo=timezone.utc)
            ) > (report_records.iso_datetime(kept["last_modified"]) or datetime.min.replace(tzinfo=timezone.utc)):
                chosen[ref] = record
        todo = list(chosen.values())
        if not todo:
            return self._log_report_stats(stats) if stats["reports_failed"] else stats
        self._arm_push_cap()
        # The push's stop point: its deadline, or its task's end less PUSH_TASK_END_MARGIN_SEC (a writer given
        # ``task_ends_at``), whichever comes first. No record and no report request starts at or after it, so the
        # collector can save ``report_pending`` before Airflow kills the task (a killed task saves nothing).
        ends_at = getattr(self, "task_ends_at", None)
        stops = [(deadline, "the push's deadline came")] if deadline is not None else []
        if _is_seconds(ends_at):
            stops.append(
                (
                    time.monotonic() + (ends_at - time.time()) - PUSH_TASK_END_MARGIN_SEC,
                    f"the task's end is near: no record starts later than {PUSH_TASK_END_MARGIN_SEC:.0f} s before "
                    "task_ends_at",
                )
            )
        stop_at, stop_reason = min(stops, key=lambda stop: stop[0]) if stops else (None, "")
        self._report_stop_at = stop_at
        try:
            if stop_at is not None and time.monotonic() >= stop_at:
                self._skip_reports(stats, todo, f"{stop_reason} before the first record")
                return self._log_report_stats(stats)
            event_id, problem = self._report_event_id(source)
            if not event_id:
                self._skip_reports(stats, todo, problem)
                return self._log_report_stats(stats)
            # MISP answered the lookup, so a failing streak its retries began ends (``_failing_streak``).
            self._misp_push_failing_since = None
            stats["event_id"] = event_id
            self._push_report_records(stats, todo, event_id, source, label, stop_at, stop_reason, liveness_callback)
        finally:
            # The stop point and the cap belong to this call; a request made outside a push has none.
            self._report_stop_at = None
            self._misp_push_failing_cap = None
            self._misp_push_failing_since = None
        return self._log_report_stats(stats)

    def _push_report_records(
        self,
        stats: Dict[str, Any],
        todo: Sequence[Dict[str, Any]],
        event_id: str,
        source: str,
        label: str,
        stop_at: Optional[float],
        stop_reason: str,
        liveness_callback: Optional[Callable[[], None]],
    ) -> None:
        """The record loop of ``push_reports``. Before each record the rest is skipped when the record's pause
        would end at or after *stop_at*, when the push's failing streak has reached its cap (``_failing_streak``:
        ``EDGEGUARD_MISP_PUSH_MAX_FAILING_SEC``, or the baseline's setting, at most until
        ``PUSH_TASK_END_MARGIN_SEC`` before the task's end), or after ``REPORT_MAX_CONSECUTIVE_FAILURES`` records
        in a row failed on HTTP 5xx or no answer. Such a failure starts the streak at the record's start; any other
        outcome ends it."""
        source_tag = self.SOURCE_TAGS.get(source, source)
        callback = liveness_callback if liveness_callback is not None else getattr(self, "liveness_callback", None)
        pause = misp_report_throttle_seconds()
        in_a_row = 0
        for position, record in enumerate(todo):
            wait = pause if position > 0 else 0.0
            if stop_at is not None and time.monotonic() + wait >= stop_at:
                self._skip_reports(stats, todo[position:], stop_reason)
                break
            streak = _failing_streak(self)
            if streak is not None and streak[1] + wait >= streak[0]:
                self._skip_reports(
                    stats,
                    todo[position:],
                    f"MISP kept failing for {streak[1]:.0f} s ({_push_cap_text(self, streak[0])})",
                )
                break
            if in_a_row >= REPORT_MAX_CONSECUTIVE_FAILURES:
                self._skip_reports(
                    stats,
                    todo[position:],
                    f"MISP kept failing: {in_a_row} records in a row answered HTTP 5xx or nothing",
                )
                break
            if wait:
                time.sleep(wait)
            if callback is not None:
                callback()
            started = time.monotonic()
            kind, reason, transient = self._push_report(event_id, source, label, source_tag, record, stats)
            ref = record["record_ref"]
            if kind in ("added", "updated", "unchanged", "deleted"):
                stats["reports_deleted_in_misp" if kind == "deleted" else f"reports_{kind}"] += 1
                stats["settled"].append(ref)
            elif kind == "foreign":
                stats["reports_foreign"] += 1
                self._report_failed(stats, ref, reason, True)
            else:
                self._report_failed(stats, ref, reason, False)
            if kind == "failed" and transient:
                in_a_row += 1
                _failing_streak(self, started)
            else:
                in_a_row = 0
                self._misp_push_failing_since = None

    @staticmethod
    def _report_failed(stats: Dict[str, Any], ref: str, reason: str, permanent: bool) -> None:
        stats["reports_failed"] += 1
        stats["failed"].append({"record_ref": ref, "reason": reason, "permanent": permanent})

    @staticmethod
    def _skip_reports(stats: Dict[str, Any], records: Sequence[Mapping[str, Any]], reason: str) -> None:
        stats["reports_skipped"] += len(records)
        stats["skipped"].extend({"record_ref": r["record_ref"], "reason": reason} for r in records)
        logger.warning("[REPORTS] %s: %d record(s) not pushed: %s", stats["source"], len(records), reason)

    @staticmethod
    def _log_report_stats(stats: Dict[str, Any]) -> Dict[str, Any]:
        log = (
            logger.warning
            if stats["reports_failed"] or stats["reports_skipped"] or stats["report_tag_drift"]
            else logger.info
        )
        log(
            "[REPORTS] %s: %d added, %d updated, %d unchanged, %d deleted in MISP (left as they are), %d failed "
            "(%d in a foreign event), %d skipped, %d tag change(s) failed; event %s",
            stats["source"],
            stats["reports_added"],
            stats["reports_updated"],
            stats["reports_unchanged"],
            stats["reports_deleted_in_misp"],
            stats["reports_failed"],
            stats["reports_foreign"],
            stats["reports_skipped"],
            stats["report_tag_drift"],
            stats["event_id"],
        )
        return stats

    def _report_event_id(self, source: str) -> Tuple[Optional[str], str]:
        """The event new records of *source* go to, and the problem when there is none: the day event, or its
        ``-reports`` companion when the day event holds more than ``_event_split_above`` attributes (0 = never)."""
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        try:
            day_event = self._get_or_create_event(source, date)
        except Exception as e:
            return None, f"the lookup of the day event failed ({type(e).__name__})"
        if not day_event:
            return None, "the day event could not be looked up or created"
        split = _event_split_above()
        size = self.__dict__.get("_event_sizes", {}).get(str(day_event))
        if split <= 0 or not isinstance(size, int) or size <= split:
            return str(day_event), ""
        try:
            companion = self._get_or_create_event(source, date, reports=True)
        except Exception as e:
            return None, f"the lookup of the reports event failed ({type(e).__name__})"
        if not companion:
            return None, "the reports event could not be looked up or created"
        logger.info(
            "[REPORTS] %s: the day event %s holds %d attributes (EDGEGUARD_MISP_EVENT_SPLIT_ABOVE=%d); new records "
            "go to %s (event %s)",
            source,
            day_event,
            size,
            split,
            _report_event_name(source, date),
            companion,
        )
        return str(companion), ""

    def _report_request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> _ReportAnswer:
        """One report request, outside the writer's retry decorator: HTTP 5xx, a timeout or a connection error is
        tried once more, HTTP 4xx never. The answer's body is returned, never logged. Inside ``push_reports`` no
        attempt starts at or after the push's stop point (``_report_stop_at``: its deadline, or its task's end
        less ``PUSH_TASK_END_MARGIN_SEC``); a request not sent then counts as no answer, and an attempt not
        repeated keeps the first attempt's answer. An attempt in flight keeps its timeouts, which fit in that
        margin."""
        url = f"{self.url}{path}"
        timeout = (self.CONNECT_TIMEOUT, self.READ_TIMEOUT)
        stop_at = getattr(self, "_report_stop_at", None)
        first: Optional[_ReportAnswer] = None
        for attempt in (1, 2):
            if stop_at is not None and time.monotonic() >= stop_at:
                if first is None:
                    return _ReportAnswer(None, None, "no answer (not sent: the push's time was up)")
                return first._replace(problem=f"{first.problem}, not tried again: the push's time was up")
            tries = " (tried twice)" if attempt == 2 else ""
            try:
                if method == "GET":
                    response = self.session.get(url, verify=self.verify_ssl, timeout=timeout)
                else:
                    response = self.session.post(url, json=payload, verify=self.verify_ssl, timeout=timeout)
            except requests.exceptions.RequestException as e:
                answer = _ReportAnswer(None, None, f"no answer ({type(e).__name__}){tries}")
            else:
                try:
                    body = response.json()
                except ValueError:
                    body = None
                answer = _ReportAnswer(response.status_code, body, f"HTTP {response.status_code}{tries}")
            if attempt == 2 or not answer.transient:
                return answer
            first = answer
        return first  # pragma: no cover - the loop always returns

    def _report_writer_org(self) -> Tuple[Optional[str], _ReportAnswer]:
        """The organisation id of the writer key (``GET /users/view/me``), read once per writer."""
        cached = self.__dict__.get("_report_writer_org_id")
        if cached:
            return cached, _ReportAnswer(200, None, "HTTP 200")
        answer = self._report_request("GET", "/users/view/me")
        org = _writer_org_of(answer.body) if answer.status == 200 else None
        if org:
            self.__dict__["_report_writer_org_id"] = org
        return org, answer

    def _report_tag_ids(self, names: Sequence[str]) -> Dict[str, str]:
        """Tag id per tag name, for the names this MISP holds (``POST /tags/search/x/1``, an exact match; ids are
        kept per writer). A tag is addressed by id: MISP reads ``tlp:white`` in a path as a named parameter."""
        cache: Dict[str, str] = self.__dict__.setdefault("_report_tag_id_cache", {})
        wanted = [n for n in names if n.lower() not in cache]
        if wanted:
            answer = self._report_request("POST", "/tags/search/x/1", {"tag": wanted})
            rows = answer.body if answer.status == 200 and isinstance(answer.body, list) else []
            for row in rows:
                tag = row.get("Tag") if isinstance(row, dict) else None
                if isinstance(tag, dict) and isinstance(tag.get("name"), str) and tag.get("id") is not None:
                    cache[tag["name"].lower()] = str(tag["id"])
        return {n: cache[n.lower()] for n in names if n.lower() in cache}

    def _swap_report_tlp(self, report_id: str, old: Optional[str], new: str) -> bool:
        """``removeTag`` of ``tlp:<old>`` (when known), then ``addTag`` of ``tlp:<new>``, by tag id. The ``addTag``
        is sent whatever the ``removeTag`` answered. True when the old tag is gone and MISP answered ``saved`` true
        to the ``addTag`` (a tag already attached answers ``saved`` true, "0 tags added"). The old tag counts as
        gone when this MISP does not hold it, or when ``removeTag`` answers HTTP 200 ``{"saved": false,
        "errors": "Invalid event-report - tag combination."}``: the tag is not on the report
        (``EventReportsController::removeTag``, MISP 2.5.45 and 2.5.50). That happens after an earlier swap
        whose ``addTag`` failed, after an add that dropped a missing tag, or after an edit with a
        ``perm_sync_authoritative`` key, which strips the report's tags."""
        names = [f"tlp:{level}" for level in (old, new) if level]
        ids = self._report_tag_ids(names)
        ok = True
        old_id = ids.get(f"tlp:{old}") if old else None
        if old_id is not None:
            answer = self._report_request("POST", f"/eventReports/removeTag/{report_id}/{old_id}", {})
            body = answer.body if isinstance(answer.body, dict) else {}
            not_attached = answer.status == 200 and "tag combination" in str(body.get("errors") or "")
            if not not_attached and not (answer.status == 200 and body.get("saved") is True):
                ok = False
        new_id = ids.get(f"tlp:{new}")
        if new_id is None:
            return False
        answer = self._report_request("POST", f"/eventReports/addTag/{report_id}/{new_id}", {})
        return ok and answer.status == 200 and isinstance(answer.body, dict) and answer.body.get("saved") is True

    def _push_report(
        self, event_id: str, source: str, label: str, source_tag: str, record: Dict[str, Any], stats: Dict[str, Any]
    ) -> Tuple[str, str, bool]:
        """Write one record (``push_reports``, steps 1 to 3). Returns ``(outcome, reason, transient)``: the outcome
        ``added``, ``updated``, ``unchanged``, ``deleted``, ``foreign`` or ``failed``; the reason of a failure;
        whether it was MISP answering HTTP 5xx or nothing."""
        ref = record["record_ref"]
        uuid = report_records.report_uuid(ref, label)
        content = report_records.render_content(record)
        sha = report_records.content_sha256(content)
        name = report_records.report_name(record)
        distribution = report_records.report_distribution(record)
        sent = f"uuid={uuid} record_ref={ref} content_chars={len(content)} sha256={sha[:16]}"
        add = self._report_request(
            "POST",
            f"/eventReports/add/{event_id}",
            {
                "EventReport": {
                    "uuid": uuid,
                    "name": name,
                    "content": content,
                    "distribution": distribution,
                    "Tag": report_records.report_tags(record, source_tag),
                }
            },
        )
        if add.status == 200:
            problem = _stored_report_problem(add.body, uuid, sha, name)
            if problem is None:
                logger.debug("[REPORT-ADDED] %s event=%s", sent, event_id)
                return "added", "", False
            logger.warning("[REPORT-FAILED] %s: the add answered HTTP 200 but %s", sent, problem)
            return "failed", f"the add answered HTTP 200 but {problem}", False
        if add.status != 403:
            logger.warning("[REPORT-FAILED] %s: the add answered %s", sent, add.problem)
            return "failed", f"the add answered {add.problem}", add.transient
        # Any 403: the uuid may be taken (this record, revised or not, deleted, or a foreign report), or the add
        # was refused for another reason; the report as MISP holds it decides.
        view = self._report_request("GET", f"/eventReports/view/{uuid}")
        stored = view.body.get("EventReport") if view.status == 200 and isinstance(view.body, dict) else None
        if not isinstance(stored, dict) or str(stored.get("uuid") or "") != uuid:
            logger.warning(
                "[REPORT-FAILED] %s: the add answered HTTP 403 and the view of the uuid %s", sent, view.problem
            )
            return (
                "failed",
                f"the add answered HTTP 403 and the view of the uuid answered {view.problem}",
                view.transient,
            )
        event = view.body.get("Event") if isinstance(view.body.get("Event"), dict) else {}
        org, me = self._report_writer_org()
        if org is None:
            logger.warning(
                "[REPORT-FAILED] %s: the writer key's organisation is unknown (GET /users/view/me %s)", sent, me.problem
            )
            return (
                "failed",
                f"the writer key's organisation is unknown (GET /users/view/me answered {me.problem})",
                me.transient,
            )
        info = str(event.get("info") or "")
        if not report_records.report_event_info_pattern(source).match(info) or str(event.get("orgc_id") or "") != org:
            logger.error(
                "[REPORT-UUID-FOREIGN] %s: MISP holds the uuid in event %s, which is not an EdgeGuard event of %s "
                "created by the writer key's organisation; the record is not written (permanent)",
                sent,
                event.get("id"),
                source,
            )
            return (
                "foreign",
                f"the uuid belongs to a report in event {event.get('id')}, not an EdgeGuard event of {source} of this organisation",
                False,
            )
        if _report_deleted(stored):
            logger.info(
                "[REPORT-DELETED-IN-MISP] %s: the report is deleted in MISP (event %s); the deletion is respected",
                sent,
                event.get("id"),
            )
            return "deleted", "", False
        parsed = report_records.parse_content(stored.get("content"))
        stored_meta = parsed[1] if parsed is not None else None
        if stored_meta is not None:
            if stored_meta.get("digest") == record["digest"]:
                logger.debug("[REPORT-UNCHANGED] %s", sent)
                return "unchanged", "", False
            stored_at = report_records.iso_datetime(stored_meta.get("last_modified"))
            new_at = report_records.iso_datetime(record.get("last_modified"))
            if stored_at is not None and new_at is not None and stored_at > new_at:
                logger.info("[REPORT-UNCHANGED] %s: MISP holds a later version of the record (last_modified)", sent)
                return "unchanged", "", False
        edit = self._report_request(
            "POST",
            f"/eventReports/edit/{uuid}",
            {"EventReport": {"name": name, "content": content, "distribution": distribution}},
        )
        if edit.status != 200:
            logger.warning("[REPORT-FAILED] %s: the edit answered %s", sent, edit.problem)
            return "failed", f"the edit answered {edit.problem}", edit.transient
        problem = _stored_report_problem(edit.body, uuid, sha, name)
        if problem is not None:
            logger.warning("[REPORT-FAILED] %s: the edit answered HTTP 200 but %s", sent, problem)
            return "failed", f"the edit answered HTTP 200 but {problem}", False
        old_tlp = report_records.gating_tlp(stored_meta) if stored_meta is not None else None
        new_tlp = report_records.gating_tlp(record)
        if old_tlp != new_tlp and not self._swap_report_tlp(str(stored.get("id") or uuid), old_tlp, new_tlp):
            stats["report_tag_drift"] += 1
            logger.warning(
                "[REPORT-TAG-DRIFT] %s: the report's tlp tag could not be changed from %s to %s; the meta block and "
                "the distribution carry tlp:%s",
                sent,
                old_tlp or "unknown",
                new_tlp,
                new_tlp,
            )
        logger.info("[REPORT-UPDATED] %s", sent)
        return "updated", "", False

    def report_preflight(self, tag_names: Optional[Sequence[str]] = None) -> ReportPreflight:
        """Read-only check of the writer key for report records: its role (``GET /users/view/me``) must have
        ``perm_tagger`` (without it MISP drops every report tag) and lack ``perm_sync_authoritative`` (with it
        every report edit strips the report's tags), and every tag the writer sets (*tag_names*, default
        ``report_tag_names()``) must exist (``POST /tags/search/x/1``) unless the role has ``perm_tag_editor``
        (without it MISP drops a missing tag instead of creating it). Writes nothing; logs the outcome without
        any answer body."""
        names = tuple(tag_names) if tag_names is not None else report_tag_names()
        problems: List[str] = []
        me = self._report_request("GET", "/users/view/me")
        role = me.body.get("Role") if me.status == 200 and isinstance(me.body, dict) else None
        org = _writer_org_of(me.body) if me.status == 200 else None
        if isinstance(role, dict):
            tagger = _role_flag(role, "perm_tagger")
            editor = _role_flag(role, "perm_tag_editor")
            authoritative = _role_flag(role, "perm_sync_authoritative")
            if not tagger:
                problems.append("the writer key's role lacks perm_tagger: MISP drops the tags of every report")
            if authoritative:
                problems.append(
                    "the writer key's role has perm_sync_authoritative: every report edit strips the report's tags"
                )
        else:
            tagger = editor = authoritative = None
            problems.append(f"the writer key's role could not be read (GET /users/view/me answered {me.problem})")
        missing: Tuple[str, ...] = ()
        search = self._report_request("POST", "/tags/search/x/1", {"tag": list(names)})
        if search.status == 200 and isinstance(search.body, list):
            held = {
                row["Tag"]["name"].lower()
                for row in search.body
                if isinstance(row, dict)
                and isinstance(row.get("Tag"), dict)
                and isinstance(row["Tag"].get("name"), str)
            }
            missing = tuple(n for n in names if n.lower() not in held)
            if missing and not editor:
                problems.append(
                    "tags the writer sets are missing on this MISP and the role lacks perm_tag_editor, so MISP drops "
                    f"them from the reports: {', '.join(missing)}"
                )
        else:
            problems.append(f"the tags could not be read (POST /tags/search/x/1 answered {search.problem})")
        result = ReportPreflight(
            ok=not problems,
            problems=tuple(problems),
            org_id=org,
            perm_tagger=tagger,
            perm_tag_editor=editor,
            perm_sync_authoritative=authoritative,
            tags_checked=names,
            missing_tags=missing,
        )
        if result.ok:
            logger.info("[REPORT-PREFLIGHT] the writer key can write report records and their tags")
        else:
            logger.error("[REPORT-PREFLIGHT] %s", "; ".join(problems))
        return result

    def get_stats(self) -> Dict[str, int]:
        """Get writer statistics."""
        return self.stats.copy()

    def reset_stats(self):
        """Reset writer statistics."""
        self.stats = {
            "events_created": 0,
            "attributes_added": 0,
            "batches_sent": 0,
            "errors": 0,
            "attrs_skipped_existing": 0,
            "attributes_updated": 0,
            "attributes_refreshed": 0,
            "attributes_refresh_failed": 0,
            "attributes_refresh_deferred": 0,
            "batches_unverified": 0,
            "attributes_unconfirmed": 0,
            "items_not_converted": 0,
            "items_not_converted_failed": 0,
            "batches_stored_after_5xx": 0,
        }


def test_misp_writer():
    """Test MISP writer functionality."""
    writer = MISPWriter()

    # Test indicator type mapping
    print("Testing type mapping:")
    print(f"  ipv4 -> {writer.map_indicator_type('ipv4')}")
    print(f"  domain -> {writer.map_indicator_type('domain')}")
    print(f"  hash -> {writer.map_indicator_type('hash')}")

    # Test attribute creation
    print("\nTesting attribute creation:")

    indicator = {
        "indicator_type": "ipv4",
        "value": "192.168.1.1",
        "zone": ["finance"],
        "tag": "otx",
        "confidence_score": 0.8,
        "first_seen": "2024-01-01T00:00:00Z",
        "pulse_name": "Test pulse",
    }

    attr = writer.create_attribute(indicator)
    print(f"  Indicator attribute: {json.dumps(attr, indent=2)}")

    vulnerability = {
        "type": "vulnerability",
        "cve_id": "CVE-2024-1234",
        "description": "Test vulnerability",
        "zone": ["healthcare"],
        "tag": "nvd",
        "severity": "HIGH",
        "cvss_score": 8.5,
    }

    vuln_attr = writer.create_vulnerability_attribute(vulnerability)
    print(f"  Vulnerability attribute: {json.dumps(vuln_attr, indent=2)}")

    print("\nMISP Writer test complete!")


if __name__ == "__main__":
    test_misp_writer()
