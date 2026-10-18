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
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

import requests
import urllib3

import source_registry  # noqa: E402  — single source of truth for source→MISP-tag mapping (chip 5a)
from collectors.collector_utils import TransientServerError, retry_after_sleep_seconds, retry_with_backoff
from config import (
    DEFAULT_SECTOR,
    MISP_API_KEY,
    MISP_CROSS_EVENT_DEDUP,
    MISP_PREFETCH_EXISTING_ATTRS,
    MISP_URL,
    SSL_VERIFY,
    apply_misp_http_host_header,
    misp_refresh_last_seen_days,
    misp_refresh_max_per_run,
    misp_refresh_max_seconds,
)
from cvss_selection import cvss_rating_tag, normalize_attack_vector

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

    _METRICS_AVAILABLE = True
except ImportError:
    _METRICS_AVAILABLE = False
    _MISP_PUSH_PERMANENT_FAILURES = None  # type: ignore[assignment]
    _MISP_BACKOFF_TRIGGERED = None  # type: ignore[assignment]
    _MISP_HONEST_NULL_VIOLATIONS = None  # type: ignore[assignment]

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


# 2026-10 audit: the 730-day baseline is ONE collector run, so a family named in N pulses carries
# all N ids in `rids`; the earlier 32 cut every link beyond the 33rd pulse (Mirai, Cobalt Strike,
# AgentTesla appear in hundreds). MISP `comment` is TEXT (64 KB); 500 × ~27 chars ≈ 13 KB.
_MAX_REPORT_IDS = 500
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
# those first; ``sap`` / ``sapn`` follow ``report_ids`` (``_fit_meta_comment``).
_META_SHRINK_LISTS = (
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
_META_SHRINK_STRINGS = ("description", "pulse_name", "reference")


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


def _fit_meta_comment(prefix: str, meta: Dict[str, Any], budget: int = _META_COMMENT_BUDGET) -> str:
    """``prefix + json.dumps(meta)``, shrunk until it fits *budget* without ever breaking the JSON.

    2026-10: ``sap`` and ``sapn`` keep the marks of the pulses still in ``pulse_id`` + ``report_ids`` after
    each step (``_sap_within_reports``), so they shrink with ``report_ids``. Halving stops at the first length
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
    Lists are capped so the comment stays within MISP field limits.
    """
    meta: Dict[str, Any] = {}
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
# cursor an NVD baseline seeds) or, for OTX, holds the cursor below the pulse of each counted item
# (``MISPWriter.last_push_unstored_items``), so the next run reads the same record again and fails again.
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


def _attribute_match_key(attribute: Any) -> Optional[Tuple[str, str]]:
    """``(type, value)`` key used to recognise a pushed attribute in a MISP event response.

    MISP normalises some values on save (hashes, domains, hostnames and e-mail addresses are
    lower-cased, surrounding whitespace is trimmed), so the comparison is case-insensitive
    and whitespace-trimmed. Returns None when the attribute lacks a type or a value.
    """
    if not isinstance(attribute, dict):
        return None
    attr_type = attribute.get("type")
    value = attribute.get("value")
    if attr_type is None or value is None:
        return None
    value_norm = str(value).strip().lower()
    if not value_norm:
        return None
    return (str(attr_type).strip().lower(), value_norm)


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


# 2026-10: the events ``_get_or_create_event`` creates (``EdgeGuard-{source}-{date}``). Only copies in
# them are refreshed: the sync reads EdgeGuard's events, and a copy that keeps the source tag in
# an analyst's or a federated organisation's event is not EdgeGuard's to edit.
_OWN_EVENT_PREFIX = "EdgeGuard-"


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


def _strict_push_accounting() -> bool:
    """``EDGEGUARD_MISP_STRICT_PUSH_ACCOUNTING`` truthy: attributes absent from the returned event
    count as failed pushes (they then feed ``EDGEGUARD_MISP_MIN_SUCCESS_RATE``). Off by default:
    MISP normalises some values on save (case, whitespace are tolerated by the comparison; rarer
    rewrites such as IPv6 compression are not), so the strict mode is meant to be enabled after a
    live check shows no spurious unconfirmed attributes.
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


@contextmanager
def _cross_process_event_creation_lock():
    """
    Serialize MISP event creation across processes (e.g. Airflow LocalExecutor workers).

    Without this, two collectors can both see "no event" and create duplicates — or worse, rely on
    ambiguous restSearch hits. Uses ``fcntl`` (Unix). On platforms without ``fcntl``, the context is a no-op.
    """
    try:
        import fcntl
    except ImportError:
        yield
        return

    path = os.environ.get(
        "EDGEGUARD_MISP_EVENT_LOCK_PATH",
        "/tmp/edgeguard_misp_get_or_create_event.lock",
    )
    lock_f = open(path, "a+", encoding="utf-8")
    try:
        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_f.close()


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
        }
        # PR-F6 (Issue #65): per-batch parent-DAG liveness callback.
        # ``None`` = no check (legacy / incremental DAGs); a callable
        # = check before each batch. See src/parent_dag_liveness.py.
        self.liveness_callback = liveness_callback

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

    def _restsearch_event_page(self, event_name: str, page: int) -> List[Any]:
        """One page of the event lookup; returns the ``response`` list (see ``_restsearch_events_for_name``)."""
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
            timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT),
        )
        if response.status_code != 200:
            detail = (response.text or "")[:500]
            if response.status_code == 429 or response.status_code >= 500:
                # Rate limit or server error: let @retry_with_backoff on the caller retry with its
                # exponential backoff. No sleep here: the confirming lookup runs inside the
                # cross-process event-creation lock, and a Retry-After wait taken there would hold
                # the lock against every parallel collector.
                logger.warning(
                    "MISP restSearch for event lookup answered HTTP %s — the caller retries with backoff: %s",
                    response.status_code,
                    detail,
                )
                raise MispTransientError(
                    f"MISP {response.status_code} on event lookup for {event_name!r}", response=response
                )
            logger.error(
                "MISP restSearch for event lookup failed: HTTP %s — %s; no event is created after a failed lookup",
                response.status_code,
                detail,
            )
            raise MispLookupError(f"MISP {response.status_code} on event lookup for {event_name!r}")
        data = response.json()
        return data.get("response") or []

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
        the push, not with the source.

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

        See also Issue #61 — the architectural fix is event partitioning
        by attribute date, not push date. This helper is the cheap
        quick-fix until #61 lands.
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
                    key = (str(t), str(v))
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
        """
        if not MISP_PREFETCH_EXISTING_ATTRS:
            return set()
        eid = sanitize_value(str(event_id), max_length=20)
        if not eid:
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
                    keys.add((str(t), str(v)))
            if len(attrs) < page_limit:
                break
            page += 1
        if keys:
            logger.debug("MISP event %s: prefetched %s existing attribute keys", eid, len(keys))
        return keys

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
        found: set = set()
        wanted = [str(v) for v in values if str(v or "").strip()]
        for i in range(0, len(wanted), 500):
            chunk = wanted[i : i + 500]
            page = 1
            while True:
                response = self._post_with_retries(
                    f"{self.url}/attributes/restSearch",
                    {
                        "returnFormat": "json",
                        "tags": [source_tag],
                        "type": attr_type,
                        "value": chunk,
                        "page": page,
                        "limit": 2000,
                    },
                    context=f"lookup of {len(chunk)} {attr_type} value(s)",
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
                found.update(str(r.get("value") or "").strip().upper() for r in rows if isinstance(r, dict))
                if len(rows) < 2000:
                    break
                page += 1
        found.discard("")
        return found

    def _post_with_retries(self, url: str, payload: Dict[str, Any], *, context: str, attempts: int = 3):
        """POST *payload*; a timeout, connection error, HTTP 429 or 5xx is retried (5 s, then 10 s).

        Returns the response of the first attempt that is not transient. Raises
        ``MispTransientError`` when every attempt was.
        """
        last_problem = ""
        for attempt in range(attempts):
            try:
                response = self.session.post(
                    url,
                    json=payload,
                    verify=self.verify_ssl,
                    timeout=(self.CONNECT_TIMEOUT, self.READ_TIMEOUT * 2),
                )
            except _TRANSIENT_HTTP_ERRORS as e:
                last_problem = f"{type(e).__name__}: {e}"
            else:
                if response.status_code != 429 and response.status_code < 500:
                    return response
                last_problem = f"HTTP {response.status_code}"
            logger.warning("MISP %s: %s (attempt %d of %d)", context, last_problem, attempt + 1, attempts)
            if attempt + 1 < attempts:
                time.sleep(5.0 * (2**attempt))
        raise MispTransientError(f"MISP {context} failed after {attempts} attempts: {last_problem}")

    @retry_with_backoff(max_retries=4, base_delay=10.0)
    def _get_or_create_event(self, source: str, date: str = None, **_kwargs) -> Optional[str]:
        """Get or create a MISP event for a source/date combination.

        Event naming: ``EdgeGuard-{source}-{date}``.  Zone classification lives
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
        event_name = f"EdgeGuard-{source}-{date}"

        try:
            rows = self._restsearch_events_for_name(event_name)
            exact = _event_id_exact_from_restsearch_rows(rows, event_name)
            if exact:
                return exact
        except _TRANSIENT_HTTP_ERRORS:
            raise
        except Exception as e:
            # A lookup that failed for a non-transient reason must not fall through to event
            # creation: the same-day event may exist and a second one would duplicate it. The
            # batch is reported as failed by the caller (push_items counts a missing event id).
            logger.error("Event lookup for %r failed (%s: %s) — no event is created", event_name, type(e).__name__, e)
            return None

        # MISP is the single store every collector writes to and the only source the knowledge graph
        # is built from. Distribution 1 is MISP's "This community only": every organisation on this
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
                # Event is an organizational container: ``EdgeGuard-{source}-{date}`` groups by
                # source + day.  Zone classification lives on **attributes** (``zone:…`` tags)
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
        has_tf_meta = (
            indicator.get("malware_malpedia")
            or indicator.get("reference")
            or indicator.get("tags")
            or any(indicator.get(_k) for _k in _TF_META_OPTIONAL_STRINGS + _TF_META_OPTIONAL_LISTS)
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
            for _k in ("mf", "pa", "sap", "sapn"):
                if not otx_meta.get(_k):
                    otx_meta.pop(_k, None)
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
                # dropped here, losing ``ioc_id`` cross-day dedup +
                # losing the alias signal Q2/Q9 consumes. Mirror of
                # the OTX_META ``malware_family`` fix in PR-N10 #3.
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
            comment = _fit_meta_comment("TF_META:", tf_meta)
        else:
            comment = sanitize_value(indicator.get("pulse_name") or indicator.get("description", ""), max_length=255)

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

        if has_nvd_meta:
            import json as _json

            comment = "NVD_META:" + _json.dumps(nvd_fields, default=str)
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
            "comment": comment if has_nvd_meta else sanitize_value(comment, max_length=500),
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
        aliases = malware.get("aliases", [])
        for alias in aliases[:20]:
            alias_s = sanitize_value(str(alias), max_length=100)
            if alias_s:
                tags.append(f"alias:{alias_s}")

        # Add MITRE ATT&CK galaxy tag for malware - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:malware="{name}"')
        tags.extend(_deprecated_tags(malware))  # 2026-10: ATT&CK x_mitre_deprecated

        description = sanitize_value(malware.get("description", ""), max_length=400)

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
            comment = sanitize_value(comment, max_length=500)

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
        aliases = actor.get("aliases", [])
        for alias in aliases[:20]:
            alias_s = sanitize_value(str(alias), max_length=100)
            if alias_s:
                tags.append(f"alias:{alias_s}")

        # Add MITRE threat-actor galaxy tag - CRITICAL for STIX conversion
        tags.append(f'misp-galaxy:threat-actor="{name}"')
        tags.extend(_deprecated_tags(actor))  # 2026-10: ATT&CK x_mitre_deprecated

        description = sanitize_value(actor.get("description", ""), max_length=255)

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

        # Add platform tags
        platforms = technique.get("platforms", [])
        for platform in platforms[:3]:  # Limit to 3 platforms
            plat = sanitize_value(str(platform), max_length=50).lower()
            if plat:
                tags.append(f"platform:{plat}")

        # Add MITRE ATT&CK galaxy tags - CRITICAL for STIX conversion
        # This enables PyMISP to recognize and convert to attack-pattern
        tags.append(f'misp-galaxy:mitre-attack-pattern="{name} - {mitre_id}"')
        tags.append(f'mitre-attack:technique="{mitre_id}"')
        tags.extend(_deprecated_tags(technique))  # 2026-10: ATT&CK x_mitre_deprecated

        description = sanitize_value(technique.get("description", ""), max_length=255)
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

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
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

        Tactics use the same ``text`` pattern as techniques (``TA0001: Name``) so
        MISP→Neo4j parsing can recognize them. Previously ``push_items`` had no
        branch for ``type: tactic``, so tactics were silently skipped.
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

        description = sanitize_value(str(tactic.get("description", "")), max_length=255)

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
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

        Tools are stored as ``text`` attributes with ``S####: Name`` format,
        following the same pattern as techniques and tactics. The
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
        tags.extend(_deprecated_tags(tool))  # 2026-10: ATT&CK x_mitre_deprecated
        for ttype in tool.get("tool_types", []):
            tt = sanitize_value(str(ttype), max_length=50).lower()
            if tt:
                tags.append(f"tool-type:{tt}")

        description = sanitize_value(str(tool.get("description", "")), max_length=400)
        uses_techniques = tool.get("uses_techniques") or []

        if uses_techniques:
            meta = {"t": list(uses_techniques)[:400]}
            comment = "MITRE_USES_TECHNIQUES:" + json.dumps(meta, separators=(",", ":"))
            if description:
                comment = comment + "\n" + description
        else:
            comment = description if description else f"MITRE ATT&CK tool: {name}"
            comment = sanitize_value(comment, max_length=500)

        attribute = {
            "type": "text",
            "value": f"{mitre_id}: {name}",
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
        a push without failures, OTX after a push with failures only up to the oldest pulse with an
        item in ``last_push_unstored_items``, which lists the items of a systemic drop (below). A
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
        the writer inserts a longer cooldown (default 5min, env
        ``EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC``) before the next batch
        — gives MISP time to fully recover instead of hammering a
        struggling worker.  The failure counter persists across
        ``push_items`` calls (instance-scoped on ``self``) and resets
        only after **2 consecutive fully-successful** batches — one
        success could be a fluke; two suggests genuine recovery.
        During the cooldown the writer wakes every 30s to call the
        parent-DAG liveness callback so a sibling task failure is
        detected within ~30s rather than after the full cooldown.

        See docs/MISP_TUNING.md for the full playbook (php.ini /
        my.cnf settings + when to apply each EdgeGuard env knob).

        2026-10 (unstored items): after the call, ``self.last_push_unstored_items`` lists the
        positions in *items* of the items MISP did not store because their batch, or their group's
        event lookup, failed, and of the items of a systemic conversion drop (below). A cursor that
        must not pass them (OTX) stops below them. A batch
        failed when MISP stored none of it: HTTP 4xx, a batch error, HTTP 429 or 5xx after the
        retries, and under strict accounting an HTTP 200 that confirms none of it; attributes
        missing from a batch MISP partly stored are not listed. The items no attribute could be
        built from are listed when their source's drop is systemic (``CONVERT_FAILED_MIN_SHARE``): a
        payload the collector no longer reads, whose items a later run stores once the collector
        reads it again; single bad records below the share are not. Values MISP can never store
        (4-byte characters) are not listed either: a later run cannot store them.
        """
        self.last_push_unstored_items: List[int] = []
        if not items:
            return 0, 0

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
        # candidates for a last_seen refresh when MISP already holds them.
        reported_indicators: Dict[str, set] = {}
        # 2026-10: per source, the reasons items could not be converted to a MISP attribute and
        # how many items each reason dropped, and the number of items each source gave. A source's
        # drops count as failed only when they are systemic (``CONVERT_FAILED_MIN_SHARE``).
        not_converted: Dict[str, Dict[str, int]] = {}
        items_per_source: Dict[str, int] = {}

        # 2026-10: (type, value) → positions in *items*, to name the items of a failed batch; per
        # source, the positions of the items no attribute could be built from, listed as unstored
        # when the source's drop is systemic.
        item_positions_by_key: Dict[Tuple[Any, Any], List[int]] = {}
        not_converted_positions: Dict[str, List[int]] = {}
        unstored_positions: set = set()

        def _note_unstored(attrs: List[Dict]) -> None:
            for a in attrs:
                if _value_is_storable(a):
                    unstored_positions.update(item_positions_by_key.get((a.get("type"), a.get("value")), ()))

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
            item_positions_by_key.setdefault((attr.get("type"), attr.get("value")), []).append(item_position)
            if kind == "indicator":
                reported_indicators.setdefault(source, set()).add((attr.get("type"), attr.get("value")))

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
                    # store them, so they hold the OTX cursor like the items of a failed batch.
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
        # (type, value) → (the stored copy to edit, last_seen of the re-reported item)
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
        # PR-N4 round 2 (Bugbot R2-A): widened from 2-tuple to 4-tuple
        # carrying (source, event_id, existing_attrs_count, attrs).
        # The threading was added in round 1 (F1: stale source) + round 1
        # (F2: avoid duplicate _get_existing_attribute_keys fetch); the
        # type annotation was forgotten and silently misled mypy.
        push_queue: List[Tuple[str, str, int, List[Dict]]] = []

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
            for a in candidates:
                _copy = _copies.get((a.get("type"), a.get("value")))
                if _copy is not None and _copy.written < refresh_cutoff:
                    refresh_due[(a.get("type"), a.get("value"))] = (_copy, a.get("last_seen"))

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
            # Deduplicate attributes by value
            seen = set()
            unique_attrs = []
            for attr in attributes:
                key = f"{attr['type']}:{attr['value']}"
                if key not in seen:
                    seen.add(key)
                    unique_attrs.append(attr)

            # PR-F7: the cache key is the RESOLVED ``source_tag`` — not the raw ``source``
            # string. Two sources can share a tag via the registry's alias
            # map (e.g. ``cisa`` and ``cisa_kev`` both map to
            # ``source:CISA-KEV``). Keying by raw ``source`` would double-fetch
            # the same tag set; keying by resolved tag collapses aliases into
            # one cache entry, which is what the prefetch cost model expects.
            source_tag = self.SOURCE_TAGS.get(source, f"source:{source}")
            if source_tag not in cross_event_cache:
                if known_source_keys is not None and source_tag in known_source_keys:
                    cross_event_cache[source_tag] = set(known_source_keys[source_tag])
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
                after_cross_event = [a for a in unique_attrs if (a.get("type"), a.get("value")) not in cross_event_keys]
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

            # Get or create event. A transient failure that survives the retry decorator is
            # recorded as a failed batch for this source group; the remaining groups are pushed.
            try:
                event_id = self._get_or_create_event(source, date)
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
                _note_unstored(unique_attrs)
                continue
            if not event_id:
                total_failed += len(unique_attrs)
                _note_unstored(unique_attrs)
                continue

            per_event_keys = self._get_existing_attribute_keys(event_id)
            before_ct = len(unique_attrs)
            # Per-event filter (attrs already in THIS event)
            after_per_event = [a for a in unique_attrs if (a.get("type"), a.get("value")) not in per_event_keys]
            per_event_skipped = before_ct - len(after_per_event)
            if checked_first:
                unique_attrs = after_per_event
            else:
                # Cross-event filter on the remainder (attrs in ANY OTHER
                # EdgeGuard event for this source). PR-F7's value is
                # exactly this number: duplicates that the per-event
                # prefetch would have missed.
                unique_attrs = [a for a in after_per_event if (a.get("type"), a.get("value")) not in cross_event_keys]
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
            push_queue.append((source, event_id, len(per_event_keys), unique_attrs))

        # Only a true dedup skip: nothing failed (#216: a group whose event lookup/creation failed is
        # counted as failed) and nothing was dropped in conversion (2026-10; a drop that is only
        # reported rules the line out too, since not every item was present), and N is the number
        # of attributes MISP was found to hold.
        if not push_queue and present_ct > 0 and total_failed == 0 and not_converted_ct == 0:
            logger.warning(
                "[DEDUP] All %d items were already present in MISP — nothing new to push. "
                "This is normal on re-runs. Use --fresh-baseline to force re-collection.",
                present_ct,
            )

        # Throttle delay between batches — gives MISP time to free memory
        # when processing large events (e.g. 95K NVD attributes).
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
            (len(attrs) + _adaptive_for(existing_ct)[0] - 1) // _adaptive_for(existing_ct)[0]
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

        for source, event_id, existing_attrs_count, unique_attrs in push_queue:
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

            # Send attributes in batches
            for i in range(0, len(unique_attrs), effective_batch_size):
                batch = unique_attrs[i : i + effective_batch_size]

                # Throttle between batches (skip only the very first batch of the first event)
                if (i > 0 or processed_batches > 0) and effective_throttle > 0:
                    time.sleep(effective_throttle)

                # PR-N4 adaptive backoff: if we've seen N consecutive 5xx
                # failures (instance-scoped via self._misp_push_*), insert
                # an extended cooldown BEFORE retrying. The
                # @retry_with_backoff decorator on _push_batch retries
                # internally with 10s × 2^n delay (max ~150s budget per
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
                    if success == 0 and failed:
                        _note_unstored(batch)  # HTTP 4xx, a batch error, or none confirmed (strict): none stored
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
                    logger.error(
                        "Batch %s for event %s failed after retries (%s) — counting batch as failed and continuing",
                        processed_batches,
                        _safe_event_id,
                        exc,
                    )
                    success, failed = 0, len(batch)
                    _note_unstored(batch)
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

        refreshed_note = ""
        if refresh_due:
            refreshed, _refresh_failed = self._refresh_stored_copies(refresh_due, refresh_days)
            refreshed_note = f"; {refreshed} existing attribute(s) refreshed"

        # Final summary. 2026-10: the items dropped in conversion but not counted as failed are named,
        # so that neither line reads as if every item had been pushed or found present.
        total_elapsed = time.time() - start_time
        reported_only_ct = not_converted_ct - not_converted_failed_ct
        reported_note = (
            f"; {reported_only_ct} item(s) not converted, not counted as failed ([CONVERT])" if reported_only_ct else ""
        )
        if total_success > 0 or total_failed > 0:
            logger.info(
                f"[OK] MISP push complete: {total_success} succeeded, {total_failed} failed{reported_note}"
                f"{refreshed_note} in {total_elapsed:.1f}s"
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
        return total_success, total_failed

    def _refresh_stored_copies(
        self, due: Dict[Tuple[str, str], Tuple[StoredCopy, Optional[str]]], refresh_days: int
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
        not attempted is counted as deferred and is due again on the next run that reports it.
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

    @retry_with_backoff(max_retries=4, base_delay=10.0)
    @rate_limited(max_per_second=2.0)
    def _push_batch(self, event_id: str, attributes: List[Dict]) -> Tuple[int, int]:
        """
        Push a batch of attributes to a MISP event.

        Args:
            event_id: MISP event ID
            attributes: List of MISP attribute dicts

        Returns:
            Tuple of (successful_count, failed_count)
        """
        # Sanitize event_id first
        event_id = sanitize_value(event_id, max_length=20)
        if not event_id or not attributes:
            return 0, 0
        storable = _make_attributes_storable(attributes)
        skipped_unstorable = len(attributes) - len(storable)
        attributes = storable
        if not attributes:
            return 0, skipped_unstorable

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
                    if response.status_code == 429:
                        # Rate limited: honour Retry-After (bounded by collector_utils) before the
                        # decorator's exponential backoff retries the batch.
                        wait = retry_after_sleep_seconds(response, fallback=0.0)
                        if wait:
                            logger.warning(
                                "MISP rate limit (HTTP 429) on event %s — sleeping %.0fs (Retry-After) before the retry",
                                event_id,
                                wait,
                            )
                            time.sleep(wait)
                    raise MispTransientError(
                        f"MISP {response.status_code} pushing batch to event {event_id}",
                        response=response,
                    )
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
