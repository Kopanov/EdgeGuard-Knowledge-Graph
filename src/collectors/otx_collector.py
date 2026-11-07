#!/usr/bin/env python3
"""
EdgeGuard Prototype - AlienVault OTX Collector
Collects threat pulses from AlienVault OTX and pushes to MISP

Production-ready features:
- Comprehensive error handling
- Retry logic with exponential backoff
- Circuit breaker pattern for outage handling
- Health checks before collection
- Prometheus metrics integration
- Timeout handling for API calls
- Detailed logging
"""

import copy
import hashlib
import json
import logging
import os
import re
import sys
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
from urllib.parse import quote

import urllib3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

# Import MISP writer
from actor_name_hygiene import clean_actor_names, dropped_geopolitical_names, strip_trailing_parenthetical
from attack_software_names import split_attack_software_id

# Import baseline checkpoint (incremental cursor only — no page-based checkpointing)
from baseline_checkpoint import (
    get_source_incremental,
    update_source_incremental,
)
from canonical_threat_actors import (
    CanonicalReference,
    ReferenceUnavailable,
    actor_identities,
    load_canonical_reference,
    name_key,
)

# Shared utilities
from collectors.collector_utils import (
    OTX_API_KEY_PLACEHOLDERS,
    is_auth_or_access_denied,
    make_skipped_optional_source,
    make_status,
    optional_api_key_effective,
    request_with_rate_limit_retries,
    retry_with_backoff,
    status_after_misp_push,
)
from collectors.misp_writer import _CASE_NORMALISED_TYPES, MISPWriter, tlp_rank
from config import (
    OTX_API_KEY,
    OTX_BASELINE_MAX_PAGES,
    OTX_INCREMENTAL_LOOKBACK_DAYS,
    OTX_INCREMENTAL_MAX_PAGES,
    OTX_INCREMENTAL_OVERLAP_SEC,
    SOURCE_TAGS,
    SSL_VERIFY,
    detect_zones_from_text,
    otx_industry_zones,
    otx_retry_max_days,
    otx_retry_max_pulses,
    otx_retry_max_seconds,
    otx_retry_per_run,
    resolve_collection_limit,
)
from node_identity import fold_url_scheme_and_host

# Import resilience utilities
from resilience import (
    check_service_health,
    get_circuit_breaker,
    record_collection_failure,
    record_collection_success,
)
from sector_evidence import report_zone_entry

# Suppress InsecureRequestWarning only when SSL verification is explicitly disabled.
if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Configuration constants
OTX_CONNECT_TIMEOUT = 30  # Connection timeout (seconds)
OTX_REQUEST_TIMEOUT = 120  # Read timeout (seconds)
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # seconds

# Circuit breaker for OTX (shared registry — see resilience.py)
OTX_CIRCUIT_BREAKER = get_circuit_breaker("otx", failure_threshold=3, recovery_timeout=3600)


def _pulse_name_key(name: Any) -> str:
    """The same-run key of a malware family or adversary name: its graph key (``name_key``: NFC, trimmed,
    lower-case), a run of whitespace inside it counting as one space (2026-11)."""
    if not isinstance(name, str):
        return str(name)
    return name_key(" ".join(name.split()))


# The types of ``_CASE_NORMALISED_TYPES`` that MISP upper-cases on save (CVE ids, weaknesses, ...); it
# lower-cases the others.
_UPPER_CASED_TYPES = frozenset({"vulnerability", "weakness", "http-method", "hex", "iban", "bic", "as"})
assert _UPPER_CASED_TYPES <= _CASE_NORMALISED_TYPES


def _pulse_value_key(indicator_type: Any, value: Any) -> str:
    """The same-run key of an indicator value, compared as MISP compares it on the type MISPWriter sends
    (2026-11): a value of a type MISP changes in case on save (``_CASE_NORMALISED_TYPES``) in the case MISP
    stores it: CVE ids and the other ``_UPPER_CASED_TYPES`` upper-cased, hashes, domains, IP and e-mail
    addresses lower-cased; a URL with its scheme and host lower-cased (``fold_url_scheme_and_host``, the
    graph's ``url`` key); any other value as given. NFC-normalised and trimmed, as the graph keys it; a
    defanged value stays as it is. A CVE indicator and a pulse's CVE reference of the same id therefore
    share one key (the upper-cased id) and fold into one item."""
    if not isinstance(value, str):
        return str(value)
    text = unicodedata.normalize("NFC", value).strip()
    misp_type = MISPWriter.TYPE_MAPPING.get(str(indicator_type))
    if misp_type == "url":
        return fold_url_scheme_and_host(text)
    if misp_type in _UPPER_CASED_TYPES:
        return text.upper()
    if misp_type in _CASE_NORMALISED_TYPES:
        return text.lower()
    return text


def _pulse_item_key(item: Dict[str, Any]) -> str:
    """Same-run identity of an OTX item (what two pulses naming the same thing share).

    2026-11: items are compared as MISP and the graph compare them. In one event MISP does not store an
    attribute whose type and value match, ignoring case, an attribute an earlier request stored, so a
    later pulse's ``DCRAT`` beside an earlier ``DcRat`` was dropped with that pulse's id. Malware and
    adversary names are keyed by ``_pulse_name_key`` and indicator values by ``_pulse_value_key``;
    ``_dedupe_pulse_items`` folds a case variant into the first item, which keeps the first pulse's
    spelling.
    """
    if "indicator_type" in item and "value" in item:
        return f"{item.get('indicator_type')}:{_pulse_value_key(item.get('indicator_type'), item.get('value'))}"
    if item.get("type") == "malware":
        return f"malware:{_pulse_name_key(item.get('name'))}"
    if item.get("type") == "vulnerability":
        # The key of a CVE indicator of the same id (``_pulse_value_key``): the two fold into one item.
        return f"cve:{_pulse_value_key('cve', item.get('cve_id'))}"
    if item.get("type") == "actor":
        return f"actor:{_pulse_name_key(item.get('name'))}"
    return str(item)


# 2026-10 (regular-update linking, audit follow-up): the families and adversaries a pulse
# names travel on EVERY indicator of the pulse (``OTX_META.mf`` / ``.adv`` →
# ``Indicator.pulse_malware_families`` / ``.pulse_malware_actor_pairs``), so build_relationships
# Q9b / Q2d can link from the indicator side. The same-run pairing in the sync covers
# the baseline only: after it, a known family is a cross-event duplicate in MISP and is
# never re-pushed, so a later pulse's IOCs had no family in their event and got no edge.
_MAX_PULSE_FAMILIES = 20
_MAX_PULSE_ADVERSARIES = 5
_MAX_PULSE_PAIRS = 50  # families × adversaries of ONE pulse, encoded "family::adversary"
_PULSE_NAME_PLACEHOLDERS = frozenset({"", "unknown", "n/a", "none", "null", "-"})

# OTX indicator types whose value is a hex digest of something other than a file: an import hash, a
# PE hash, a TLS client fingerprint and a certificate fingerprint. MISPWriter types a generic
# ``hash`` by its digest length (md5 / sha1 / sha256 / sha512), which would store these as file
# hashes, so they are not collected (2026-10). Typed ``sha256`` before that, MISP dropped them.
_NON_FILE_HASH_TYPES = frozenset({"FileHash-IMPHASH", "FileHash-PEHASH", "JA3", "SSLCertFingerprint"})


def _pulse_tlp(pulse: Dict[str, Any]) -> str:
    """The TLP level the pulse states, or ``""`` when it states none.

    OTX names the field by endpoint: the subscribed list (``/api/v1/pulses/subscribed``, every
    scheduled and baseline run) answers ``tlp``, a pulse read by id (``/api/v1/pulses/{id}``, the
    retry list) answers ``TLP`` (``tests/fixtures/otx_pulse_keys_2026_11_07.json``). Both are read,
    so an item carries its pulse's level on either path; without one it is written at the deployment
    default (``EDGEGUARD_DEFAULT_TLP``).
    """
    for key in ("tlp", "TLP"):
        value = pulse.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _pulse_actor_pairs(families: List[str], adversaries: List[str], pulse_id: Any = None) -> List[str]:
    """``"family::adversary::pulse"`` for every family × adversary named by ONE pulse. Encoding the pair
    (Bugbot on PR #145) keeps the same-pulse guarantee when the lists of several pulses are unioned on a
    shared IOC — two flat lists would cross-link a family from pulse A with an actor from pulse B. The
    pulse id (2026-10) is the link's provenance in ``build_relationships`` step 2d: MISP drops an actor
    or family it already holds, so the nodes do not record a later pulse that names them. Without a
    pulse id the pair is ``"family::adversary"`` (pairs written before 2026-10 have that form)."""
    pid = str(pulse_id).strip() if pulse_id is not None else ""
    if "::" in pid:
        pid = ""
    out: List[str] = []
    for fam in families:
        for adv in adversaries:
            if fam and adv and "::" not in fam and "::" not in adv:
                out.append(f"{fam}::{adv}::{pid}" if pid else f"{fam}::{adv}")
            if len(out) >= _MAX_PULSE_PAIRS:
                return out
    return out


def _family_entry_name(entry: Any) -> str:
    """The name of one ``malware_families`` entry: a string, or an object named by ``name``,
    ``display_name`` or, last, ``id`` (OTX gives a malware family the family name as its id, the
    ``/malware/<id>`` path; no recorded pulse in the repository carries an object entry, so all three
    keys are read); ``""`` for anything else."""
    if isinstance(entry, str):
        return entry.strip()
    if isinstance(entry, dict):
        for key in ("name", "display_name", "id"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _pulse_family_names(families: Any) -> List[str]:
    """Family names a pulse lists (``malware_families`` entries, see ``_family_entry_name``),
    trimmed, placeholder-free, de-duplicated case-insensitively, first-seen order, capped.

    2026-10: a name that carries its ATT&CK software id (``"Cobalt Strike - S0154"``, the MISP
    galaxy naming) is given without it, as the malware item is named (``split_attack_software_id``).
    """
    out: List[str] = []
    seen: set = set()
    for fam in families or []:
        name, _attack_id = split_attack_software_id(_family_entry_name(fam))
        key = name.lower()
        if key in _PULSE_NAME_PLACEHOLDERS or key in seen:
            continue
        seen.add(key)
        out.append(name[:128])
        if len(out) >= _MAX_PULSE_FAMILIES:
            break
    return out


def _pulse_family_keys(families: Any) -> Set[str]:
    """The ``ThreatActor`` keys (``canonical_threat_actors.name_key``, whitespace collapsed) of every
    family name a pulse lists, as given, without its ATT&CK software id, and without a trailing
    parenthetical as the actor-name hygiene drops it (``"Lumma Stealer (LummaC2)"`` is also
    ``lumma stealer``) (2026-10-18). Every entry counts, not only the first ``_MAX_PULSE_FAMILIES``:
    each one becomes a malware item."""
    keys: Set[str] = set()
    for fam in families or []:
        raw = _family_entry_name(fam)
        if not raw:
            continue
        base, _attack_id = split_attack_software_id(raw)
        base = " ".join(base.split())
        for name in (raw, base, strip_trailing_parenthetical(base)):
            key = name_key(" ".join(name.split()))
            if key:
                keys.add(key)
    return keys


def _adversaries_not_named_as_pulse_families(
    adversaries: List[str], families: Any, reference: Optional[CanonicalReference]
) -> Tuple[List[str], List[str]]:
    """``(kept, dropped)`` of a pulse's adversary names (2026-10-18).

    A name the same pulse lists both as adversary and as a malware family (equal ``name_key``,
    ``_pulse_family_keys``) is an actor only when the canonical threat-actor reference resolves it
    (``reference.canonical_for``): "Kimsuky" or "Akira" stay actors, "Lumma Stealer" or "AsyncRAT"
    are dropped and stay the pulse's malware item. A name the reference lists as ambiguous or
    never_merge (``winnti``, ``golden chickens``, ``lumma stealer``) does not resolve and counts as
    unknown. A name only another pulse lists as a family is kept. Without the reference (``None``)
    the rule cannot decide and every name is kept. An actor the reference lacks is added through
    ``src/reference/canonical_threat_actor_overrides.json``."""
    if reference is None or not adversaries:
        return list(adversaries), []
    family_keys = _pulse_family_keys(families)
    if not family_keys:
        return list(adversaries), []
    kept: List[str] = []
    dropped: List[str] = []
    for name in adversaries:
        if name_key(name) in family_keys and reference.canonical_for(name) is None:
            dropped.append(name)
        else:
            kept.append(name)
    return kept, dropped


def _adversaries_not_listed_as_no_actors(
    adversaries: List[str], reference: Optional[CanonicalReference]
) -> Tuple[List[str], List[str]]:
    """``(kept, dropped)`` of a pulse's adversary names (2026-11-05): a name the canonical threat-actor
    reference lists as no actor (``reference.is_not_actor``: a technique, malware, a kit, a hosting
    network, a forum, a company or a campaign that a report gave as its adversary, reviewed in
    ``src/reference/canonical_threat_actor_overrides.json``) is dropped, whatever families the pulse
    lists. Without the reference (``None``) nothing is dropped."""
    if reference is None or not adversaries:
        return list(adversaries), []
    kept: List[str] = []
    dropped: List[str] = []
    for name in adversaries:
        (dropped if reference.is_not_actor(name) else kept).append(name)
    return kept, dropped


_MAX_LOGGED_PULSES_PER_NAME = 3


def _dropped_name_with_pulses(name: str, pulse_ids: List[str]) -> str:
    """``"north korea (2 pulses: p1, p2)"``: a name of an ``[ACTOR-NAMES]`` line (the country line, 2026-10-22;
    the not-actor line, 2026-11-05) with the number of pulses that carried it and the first
    ``_MAX_LOGGED_PULSES_PER_NAME`` of their ids."""
    shown = ", ".join(pulse_ids[:_MAX_LOGGED_PULSES_PER_NAME])
    more = ", …" if len(pulse_ids) > _MAX_LOGGED_PULSES_PER_NAME else ""
    noun = "pulse" if len(pulse_ids) == 1 else "pulses"
    return f"{name} ({len(pulse_ids)} {noun}: {shown}{more})"


def _fold_duplicate_pulse_item(kept: Dict[str, Any], dup: Dict[str, Any]) -> None:
    """Fold a same-run duplicate into the kept item.

    2026-10 (fresh-baseline PR, Bugbot finding): the kept item used to be the
    first pulse's copy and the later pulses were dropped, so a malware family
    or actor named in five pulses of one run reached MISP with the first
    pulse's ``pulse_id`` only — report-scoped ``INDICATES`` / ``ATTRIBUTED_TO``
    then paired it with IOCs of that one pulse and left the IOCs of the other
    four unlinked although they shared a pulse with it. Every later pulse now
    contributes its id to ``report_ids`` (``MITRE_USES_TECHNIQUES.rids`` /
    ``OTX_META.report_ids`` on the MISP attribute; the sync groups on
    ``[pulse_id] + report_ids``) and its ATT&CK ids to ``reported_techniques``.
    The kept item takes the most restrictive ``pulse_tlp`` of the pulses (2026-10).

    2026-10-18: a later pulse's industries are its statement of the sectors its campaign targets
    (``sector_evidence``). The zones they map to (``config.otx_industry_zones``) join the kept item's
    ``zone`` (``global`` dropped once a sector is present) and are recorded with the pulse as
    ``"<zone>|<pulse id>"`` entries in ``report_stated_zones``, so the sync labels and cites the statement
    whichever pulse listed the item first. The zones keyword detection found in a later pulse's text are
    not added: the kept item's inferred zones stay the first pulse's.
    """
    # Copy-on-write (Bugbot on PR #134, round 2): ``reported_techniques`` is the pulse's
    # ``pulse_attack_ids`` list object, shared by reference with ``attack_ids`` in
    # ``pulse_meta`` and with every sibling item of the same pulse. Appending in place
    # would leak the later pulse's ATT&CK ids onto indicators and entities that never
    # appeared in it. Always rebind a fresh list on the kept item before extending it.
    dup_pid = dup.get("pulse_id")
    if dup_pid and dup_pid != kept.get("pulse_id"):
        rids = list(kept.get("report_ids") or [])
        if dup_pid not in rids:
            rids.append(dup_pid)
        kept["report_ids"] = rids
    # The later pulse's sector statement (copy-on-write: ``zone`` is the pulse's ``sectors`` list, shared by
    # every item of the kept pulse).
    if dup_pid and dup_pid != kept.get("pulse_id"):
        stated_by_dup = otx_industry_zones(dup.get("otx_industries"))
        if stated_by_dup:
            zones = [z for z in (kept.get("zone") or []) if z]
            zones += [z for z in stated_by_dup if z not in zones]
            kept["zone"] = [z for z in zones if z != "global"] if len(zones) > 1 else zones
            entries = list(kept.get("report_stated_zones") or [])
            entries += [e for e in (report_zone_entry(z, str(dup_pid)) for z in stated_by_dup) if e not in entries]
            kept["report_stated_zones"] = entries
    extra_tids = [t for t in (dup.get("reported_techniques") or []) if t not in (kept.get("reported_techniques") or [])]
    if extra_tids:
        kept["reported_techniques"] = list(kept.get("reported_techniques") or []) + extra_tids
    # Families / adversaries of every pulse that listed the IOC, the pulses among them that name
    # several actors, and the names a malware item was given (2026-10: "Cobalt Strike - S0154" next
    # to "Cobalt Strike") (copy-on-write as above).
    for _list_key in (
        "pulse_malware_families",
        "pulse_malware_actor_pairs",
        "several_actor_pulses",
        "several_actor_pulses_by_name",
        "aliases",
    ):
        _extra = [x for x in (dup.get(_list_key) or []) if x not in (kept.get(_list_key) or [])]
        if _extra:
            kept[_list_key] = list(kept.get(_list_key) or []) + _extra
    # 2026-10: the most restrictive TLP of the pulses that listed the item (white / clear < green <
    # amber < amber+strict < red, as MISPWriter writes them: ``tlp_rank``). The kept copy's level
    # used to win, so an IOC listed first by a white pulse and then by an amber one was pushed white.
    if tlp_rank(dup.get("pulse_tlp")) > tlp_rank(kept.get("pulse_tlp")):
        kept["pulse_tlp"] = dup.get("pulse_tlp")


def _dedupe_pulse_items(processed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One item per identity, keeping the first copy and folding the rest into it."""
    kept_by_key: Dict[str, Dict[str, Any]] = {}
    unique: List[Dict[str, Any]] = []
    for item in processed:
        if not (item.get("value") or item.get("name") or item.get("cve_id")):
            continue
        key = _pulse_item_key(item)
        kept = kept_by_key.get(key)
        if kept is None:
            kept_by_key[key] = item
            unique.append(item)
        else:
            _fold_duplicate_pulse_item(kept, item)
    return unique


# Pulse ids a run names in its pulse-count log lines (repeated page rows, pulses that yielded no item).
_MAX_LOGGED_PULSE_IDS = 20

# Pulses per page of a scheduled run's fetch (``limit`` of ``/api/v1/pulses/subscribed``).
_OTX_INCREMENTAL_PAGE_SIZE = 100


def _first_copy_of_each_pulse(rows: List[Dict]) -> Tuple[List[Dict], List[str]]:
    """The page rows with the first copy of each pulse id kept, and the ids of the rows left out, in order.

    2026-11-02: ``/api/v1/pulses/subscribed`` is paged by offset (``page`` and ``limit``) and the request
    names no sort order, so the order can shift between two page requests (a pulse modified while the
    pages are read, or pulses that share a ``modified`` time): a pulse can come back on a later page and
    another be passed over. A row without an id is kept as it is.
    """
    seen: Set[str] = set()
    kept: List[Dict] = []
    repeated: List[str] = []
    for pulse in rows:
        pid = pulse.get("id")
        if not pid:
            kept.append(pulse)
            continue
        key = str(pid)
        if key in seen:
            repeated.append(key)
            continue
        seen.add(key)
        kept.append(pulse)
    return kept, repeated


def _pulse_ids_for_log(ids: List[str]) -> str:
    """The first ``_MAX_LOGGED_PULSE_IDS`` distinct ids of *ids*, in order, and how many more there are."""
    distinct = list(dict.fromkeys(ids))
    shown = ", ".join(distinct[:_MAX_LOGGED_PULSE_IDS])
    more = len(distinct) - _MAX_LOGGED_PULSE_IDS
    return f"{shown}, … ({more} more)" if more > 0 else shown


def _pulse_modified_dt(pulse: Dict) -> Optional[datetime]:
    """The pulse's ``modified`` as a timezone-aware datetime (OTX writes it without a zone: UTC), or ``None``
    when it is missing or does not parse."""
    raw = pulse.get("modified")
    if not raw or not isinstance(raw, str):
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class _IncrementalPulses(NamedTuple):
    """The pulses of a scheduled run, as ``_incremental_pulses_within_limit`` divides them."""

    process: List[Dict]  # the pulses the run processes, in the order OTX returned them
    deferred: List[Dict]  # the pulses the limit leaves to a later run, oldest first
    reread: int  # pulses processed outside the limit: modified at or before the stored cursor
    undated: List[str]  # ids of the pulses processed outside the limit for want of a readable ``modified``


def _incremental_pulses_within_limit(
    pulses: List[Dict], cursor: Optional[datetime], limit: Optional[int]
) -> _IncrementalPulses:
    """The pulses a scheduled run processes and the pulses its limit defers (2026-11-02).

    OTX returns the subscribed pulses newest-modified first (60 pulses read on 2026-11-02 in pages of 20:
    ``modified`` never rose from one row to the next). Cut at the limit in that order, a window larger than
    the limit lost its oldest pulses, because the cursor moved to the newest pulse processed and passed
    them. The limit therefore counts the pulses modified after the stored *cursor* oldest first (by
    ``modified``, then id), and every pulse it defers is modified at or after the newest pulse it took: the
    next run reads it again, after its cursor, or at the cursor inside the overlap.

    Processed outside the limit, whenever read:

    - a pulse modified at or before *cursor*: the run reads it only because the request starts
      ``EDGEGUARD_OTX_INCREMENTAL_OVERLAP_SEC`` before the cursor. Counted, more re-reads than the limit
      (pulses that share the cursor's ``modified`` value) would take every slot on every run, and the cursor
      would never move;
    - a pulse without a readable ``modified``: it cannot be placed against the cursor or move it.

    With no *cursor* (none stored, or one that does not parse: the look-back window) every pulse with a
    readable ``modified`` counts. A run thus processes at most *limit* pulses modified after the cursor, plus
    the re-reads of the overlap and the pulses without a readable ``modified``. The re-reads are every pulse
    modified in the overlap before the cursor: a few in a sparse window, but while a backlog of more than
    *limit* pulses per overlap drains, every pulse the previous runs took in that span, so a run can reach the
    page ceiling. *limit* ``None`` processes every pulse. The pulses processed keep the order OTX returned
    them in (newest first), so the same-run fold keeps the newest pulse's copy of an item, as a baseline does.
    """
    if limit is None:
        return _IncrementalPulses(list(pulses), [], 0, [])
    outside: List[Dict] = []
    undated: List[str] = []
    counted: List[Tuple[datetime, str, Dict]] = []
    for pulse in pulses:
        modified = _pulse_modified_dt(pulse)
        if modified is None:
            outside.append(pulse)
            undated.append(str(pulse.get("id") or "?"))
        elif cursor is not None and modified <= cursor:
            outside.append(pulse)
        else:
            counted.append((modified, str(pulse.get("id") or ""), pulse))
    counted.sort(key=lambda entry: (entry[0], entry[1]))
    chosen = {id(pulse) for pulse in outside} | {id(entry[2]) for entry in counted[:limit]}
    return _IncrementalPulses(
        process=[pulse for pulse in pulses if id(pulse) in chosen],
        deferred=[entry[2] for entry in counted[limit:]],
        reread=len(outside) - len(undated),
        undated=undated,
    )


def _pulses_without_item(pulses: List[Dict], items: List[Dict[str, Any]]) -> List[str]:
    """The ids of *pulses* that no item names, as its pulse (``pulse_id``) or as a later pulse that listed it
    (``report_ids``, the same-run fold): the pulses that yielded nothing to push (2026-11-02).

    A pulse without an id is never among them: it has no id to match or to name. The run still counts it
    among the pulses processed, so an id-less pulse that yielded no item is in the processed count of the
    ``[PULSES] … processed`` line but not in its no-item count (OTX gives every pulse an id)."""
    named: Set[str] = set()
    for item in items:
        for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])]:
            if pid:
                named.add(str(pid))
    return [str(p.get("id")) for p in pulses if p.get("id") and str(p.get("id")) not in named]


# 2026-11-02: the OTX retry list, kept in the incremental state beside ``otx_last_pulse_modified``. A scheduled
# run whose push leaves items unstored in batches MISP answered (or in a systemic conversion drop) moves its
# cursor on and puts the pulses of those items on the list; later runs fetch them by id (``/api/v1/pulses/{id}``)
# and push them after the window's push, each in batches of its own and within ``EDGEGUARD_OTX_RETRY_MAX_SECONDS``,
# until a pulse is recovered (none of its items listed, and every item that failed earlier pushed again), OTX
# answers HTTP 404, or it is given up (``EDGEGUARD_OTX_RETRY_MAX_DAYS``, ``EDGEGUARD_OTX_RETRY_MAX_PULSES``). Each
# entry: ``id``, ``modified`` (as OTX wrote it, when readable), ``first_failed_at`` and ``last_tried_at`` (the start
# of the run that put the pulse on the list or last pushed its items, UTC), ``attempts`` (the runs that pushed the
# pulse and kept it on the list), ``last_reason``, ``failed_items`` (``_item_ref`` of up to ``_FAILED_ITEMS_KEPT`` of
# its items that failed), after a fetch by id that failed ``last_fetch_failed_at``, and on the pulse the push of the
# list's pulses begins with, when that push raised or the task was killed, ``last_push_started_at``.
_RETRY_STATE_KEY = "otx_retry_pulses"
# Given-up pulses named per ``[OTX-RETRY-GAVE-UP]`` line.
_GAVE_UP_PER_LINE = 50
# Failed items recorded per entry, so that a retry whose answer lacks them is noticed.
_FAILED_ITEMS_KEPT = 10
# The longest ``last_reason`` kept: printable ASCII characters (``_reason_text``).
_REASON_KEPT = 300
# ``failed_items`` reference (``_failed_item_ref``): the key's type, at most 32 letters, digits, ``_``, ``.`` or
# ``-``, and 16 hex digits of the key's SHA-256, so at most 49 ASCII characters whatever the value (a URL can run to
# thousands).
_FAILED_ITEM_REF = re.compile(r"[A-Za-z0-9_.-]{1,32}:[0-9a-f]{16}")
# An entry of an OTX pulse id (24 characters) written by this module takes at most this many bytes of the state file
# (``baseline_checkpoint`` writes it with ``json.dump(..., indent=2)``; at its place in the file each line of the
# entry is indented by 8 spaces and each reference by 10). The largest takes about 1,710: ten references of 49
# characters, a reason of 300 printable ASCII characters, of which JSON escapes only ``"`` and ``\`` (two bytes
# each), five timestamps, ``modified`` and the attempts. An entry with one failed item and the reason of a failed
# push takes about 490. The list thus takes at most 2 MB of the file at its default cap of 1,000.
_RETRY_ENTRY_MAX_BYTES = 2000


def _utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _iso_utc(raw: Any) -> Optional[datetime]:
    """*raw* (ISO 8601) as a timezone-aware datetime (a value without a zone is UTC), or ``None``."""
    return _pulse_modified_dt({"modified": raw})


def _failed_item_ref(key: str) -> str:
    """The reference ``failed_items`` keeps of an item's identity key (``_pulse_item_key``, 2026-11-02): the key's
    type (the text before its first ``:``, another character than a letter, a digit, ``_``, ``.`` or ``-`` as
    ``_``, at most 32; ``item`` without one) and 16 hex digits of the SHA-256 of the whole key, at most 49 ASCII
    characters. A key already in that form is its own reference, so a stored reference compares equal to the
    reference of the same item, and a key stored whole is read as its reference."""
    if _FAILED_ITEM_REF.fullmatch(key):
        return key
    kind = re.sub(r"[^A-Za-z0-9_.-]", "_", key.split(":", 1)[0])[:32] if ":" in key[1:] else "item"
    return f"{kind or 'item'}:{hashlib.sha256(key.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"


def _reason_text(text: str) -> str:
    """*text* as ``last_reason`` keeps it: printable ASCII (another character, a control character included,
    becomes ``?``, so JSON escapes none of them to six bytes), at most ``_REASON_KEPT``."""
    return "".join(c if c.isascii() and c.isprintable() else "?" for c in text[:_REASON_KEPT])


def _item_ref(item: Dict[str, Any]) -> str:
    """``_failed_item_ref`` of *item*'s identity key."""
    return _failed_item_ref(_pulse_item_key(item))


def _retry_entries(raw: Any, now: datetime) -> Tuple[List[Dict[str, Any]], int]:
    """The entries of the stored retry list, copied: those with a non-empty string ``id``, the first of each id,
    and the number left out. An entry whose ``first_failed_at`` does not read starts its time on the list
    *now*; ``attempts`` that is not a whole number counts as 0; ``failed_items`` keeps the references
    (``_failed_item_ref``) of its first ``_FAILED_ITEMS_KEPT`` strings."""
    if raw is None:
        return [], 0
    if not isinstance(raw, list):
        return [], 1
    entries: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for entry in raw:
        pid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(pid, str) or not pid or pid in seen:
            continue
        seen.add(pid)
        kept = dict(entry)
        if _iso_utc(kept.get("first_failed_at")) is None:
            kept["first_failed_at"] = _utc_iso(now)
        attempts = kept.get("attempts")
        kept["attempts"] = attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0
        if "failed_items" in kept:
            failed_items = kept["failed_items"]
            kept["failed_items"] = (
                [_failed_item_ref(k) for k in failed_items if isinstance(k, str)][:_FAILED_ITEMS_KEPT]
                if isinstance(failed_items, list)
                else []
            )
        entries.append(kept)
    return entries, len(raw) - len(entries)


def _first_failed(entry: Dict[str, Any]) -> datetime:
    return _iso_utc(entry.get("first_failed_at")) or datetime.max.replace(tzinfo=timezone.utc)


def _last_tried(entry: Dict[str, Any]) -> datetime:
    return _iso_utc(entry.get("last_tried_at")) or _first_failed(entry)


def _retry_order(entry: Dict[str, Any]) -> Tuple[datetime, str]:
    """The order in which a run fetches and pushes the pulses of the list (2026-11-02): tried longest ago first.
    A fetch by id that failed is no try (``last_tried_at`` stays), but it puts the pulse behind those tried since
    (``last_fetch_failed_at``), so a pulse OTX keeps failing to answer cannot hold back the others. So does the
    start of a push of the list's pulses that began with the pulse and raised, or whose task was killed
    (``last_push_started_at``, written before that push), so a pulse whose batch raises on every run cannot hold
    back the others either. A pulse whose items a run did not push (its time budget ran out, or its window's push
    failed at the MISP event) keeps its place, first."""
    later = [_iso_utc(entry.get(key)) for key in ("last_fetch_failed_at", "last_push_started_at")]
    return (max([_last_tried(entry), *(t for t in later if t is not None)]), entry["id"])


def _list_pulse(item: Dict[str, Any], order: Dict[str, Tuple[datetime, str]]) -> Optional[str]:
    """The pulse of the retry list in whose batches *item* goes in the push of the list's pulses (2026-11-02): of
    the pulses the item names (``pulse_id`` and ``report_ids``) that are in *order* (``_retry_order`` of the pulses
    on the list), the one first in it; ``None`` when it names none. An item a window pulse without an id shares
    with a pulse of the list names that pulse only through ``report_ids``."""
    named = [str(pid) for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])] if pid and str(pid) in order]
    return min(named, key=order.__getitem__) if named else None


def _named_pulses(items: List[Dict[str, Any]], positions: Any) -> Set[str]:
    """The ids of the pulses the items of *items* at *positions* name (``pulse_id`` and ``report_ids``)."""
    named: Set[str] = set()
    for pos in positions if isinstance(positions, (list, tuple, set, range)) else ():
        if isinstance(pos, int) and 0 <= pos < len(items):
            item = items[pos]
            named.update(str(pid) for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])] if pid)
    return named


def _pulses_with_listed_items(
    items: List[Dict[str, Any]], unstored: Any, known_ids: Set[str]
) -> Optional[Dict[str, List[str]]]:
    """Per pulse id, the references (``_item_ref``) of its items the writer listed as unstored (*unstored*:
    positions in *items*); a listed item counts for its pulse (``pulse_id``) and for every later pulse that
    listed it (``report_ids``, the same-run fold). ``None`` when the failed items are unknown: the writer gave no
    list, or a listed item names no pulse or a pulse the run did not process (not in *known_ids*)."""
    if not isinstance(unstored, (list, tuple, set)):
        return None
    keys: Dict[str, List[str]] = {}
    for pos in unstored:
        item = items[pos] if isinstance(pos, int) and 0 <= pos < len(items) else {}
        ids = [str(pid) for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])] if pid]
        if not ids or any(pid not in known_ids for pid in ids):
            return None
        for pid in dict.fromkeys(ids):
            keys.setdefault(pid, []).append(_item_ref(item))
    return keys


def _items_per_pulse(items: List[Dict[str, Any]]) -> Dict[str, Set[str]]:
    """Per pulse id, the references (``_item_ref``) of the items that name it (``pulse_id`` or ``report_ids``)."""
    keys: Dict[str, Set[str]] = {}
    for item in items:
        for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])]:
            if pid:
                keys.setdefault(str(pid), set()).add(_item_ref(item))
    return keys


def _merged_failing(
    first: Optional[Dict[str, List[str]]], second: Optional[Dict[str, List[str]]]
) -> Optional[Dict[str, List[str]]]:
    """The listed items per pulse of two pushes of one run; ``None`` when either push's failures are unknown."""
    if first is None or second is None:
        return None
    merged = {pid: list(keys) for pid, keys in first.items()}
    for pid, keys in second.items():
        merged.setdefault(pid, []).extend(keys)
    return merged


def _failed_at_the_event(unstored: Any, event_failed: Any) -> bool:
    """Whether MISP failed the push as a whole (2026-11-02): at least one item is listed as unstored, and
    every listed item failed at its event (``last_push_event_failed_items``: the lookup or creation of the
    day's event, or of a part of it, failed), so none of them reached a batch: MISP unreachable, or the day's
    event failing. A batch MISP answered with an error is a failure of its items, whatever share of the push it
    holds: one value MISP refuses fails its whole batch, which can hold every new item of the push."""

    def positions(raw: Any) -> Set[int]:
        if not isinstance(raw, (list, tuple, set)):
            return set()
        return {p for p in raw if isinstance(p, int)}

    listed = positions(unstored)
    return bool(listed) and listed <= positions(event_failed)


class _RetrySettled(NamedTuple):
    """The retry list after a scheduled run (``_settle_retry_list``)."""

    entries: List[Dict[str, Any]]  # the list kept, first failure first
    added: List[str]  # pulses put on the list by this run
    recovered: List[str]  # pulses of the list processed by this run, every failed item stored or found
    failing: List[str]  # pulses of the list processed by this run that stay on it
    incomplete: List[str]  # among *failing*: pulses read without items that failed earlier
    given_up: List[Dict[str, Any]]  # entries given up (too long on the list, or beyond the cap)


class _WindowSettled(NamedTuple):
    """The retry list after the window's push of a scheduled run (2026-11-02), before the push of its pulses."""

    failing: Optional[Dict[str, List[str]]]  # the window's push: listed items per pulse (``None``: unknown)
    whole: bool  # the window's push failed at the MISP event
    settled: _RetrySettled  # the list with the pulses the window's push added, within the cap
    saved: List[Dict[str, Any]]  # the list as the incremental state holds it now
    items: List[Dict[str, Any]]  # the items of the push of the list's pulses, in ``_retry_order``
    order: Dict[str, Tuple[datetime, str]]  # ``_retry_order`` of the pulses read on the list and still on it
    pushes: bool  # the run pushes *items* (there are some, and the window's push neither failed at the event
    # nor stopped because MISP kept failing)
    held: Set[str]  # 2026-11-03: the pulses the items that stopped push did not send name (``last_push_unsent_items``)


def _settle_retry_list(
    entries: List[Dict[str, Any]],
    processed: List[Dict[str, Any]],
    failing: Optional[Dict[str, List[str]]],
    pushed: Dict[str, Set[str]],
    *,
    add: bool,
    outage: bool,
    reason: str,
    now: datetime,
    max_days: int,
    max_pulses: int,
    by_age: bool = True,
) -> _RetrySettled:
    """The retry list after a push of the pulses *processed* (pulses of the window, and pulses of the list whose
    items the run pushed: fetched by id or read in the window).

    *failing*: per pulse id, the references of its items the writer listed as unstored; ``None`` when the failed
    items are unknown (every processed pulse of the list then stays). *pushed*: per pulse id, the references of
    the items the run pushed for it (``_items_per_pulse``). A pulse of the list processed by the run leaves it
    (recovered) when none of its items is listed and every item recorded as failed (``failed_items``) was pushed
    for it, so stored or found in MISP; otherwise it stays with ``attempts`` + 1 and ``last_tried_at`` the run's
    start, and its ``failed_items`` become the items listed now and those recorded that the pulse as read now
    lacks (``incomplete``: a pulse modified to drop the item, or an answer by id without it; it is given up in the
    end, with an ERROR, not taken off as recovered). With *add* (a push of item failures) every failing pulse
    not yet on the list is added. With *outage* (every listed item failed at its MISP event) the run tells
    nothing about the pulses: a pulse of the list that stays is left as it was (no attempt, no ``last_tried_at``,
    no reason), and none is given up by age.

    With *by_age*, an entry first failed more than *max_days* ago is then given up when it was tried after that
    deadline (its ``last_tried_at``, set when a run pushed its items), so a pulse that waited on the list while no
    run pushed it gets one try first: after a pause of the scheduled runs, beyond the fetches or the time budget
    of a run, read by the window and deferred by the limit (which the cursor cannot pass), while its fetch by id
    failed, or while its push raised. Beyond *max_pulses* the entries whose first failure is the oldest are given
    up, tried or not, also without *by_age* (the settlement after the window's push, whose list is written before
    the list's pulses are pushed). A try recorded here (``last_tried_at``) drops ``last_push_started_at``."""
    by_id: Dict[str, Dict[str, Any]] = {entry["id"]: entry for entry in entries}
    pulses: Dict[str, Dict[str, Any]] = {str(p["id"]): p for p in processed if p.get("id")}
    now_iso = _utc_iso(now)
    listed_now = failing or {}

    def note(entry: Dict[str, Any], pid: str, missing: List[str]) -> None:
        entry["last_tried_at"] = now_iso
        entry.pop("last_push_started_at", None)
        listed = listed_now.get(pid)
        if listed:
            text = f"{len(listed)} item(s) listed as unstored; {reason}"
        elif missing:
            text = f"{len(missing)} item(s) that failed earlier are not in the pulse as read now; {reason}"
        else:
            text = reason
        entry["last_reason"] = _reason_text(text)
        if failing is not None:
            entry["failed_items"] = list(dict.fromkeys([*(listed or []), *missing]))[:_FAILED_ITEMS_KEPT]
        modified = pulses[pid].get("modified")
        if _pulse_modified_dt(pulses[pid]) is not None:
            entry["modified"] = modified

    recovered: List[str] = []
    still: List[str] = []
    incomplete: List[str] = []
    for pid in pulses:
        entry = by_id.get(pid)
        if entry is None:
            continue
        missing = [k for k in entry.get("failed_items") or [] if k not in pushed.get(pid, set())]
        if failing is not None and pid not in failing and not missing:
            del by_id[pid]
            recovered.append(pid)
            continue
        still.append(pid)
        if outage:
            continue
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        note(entry, pid, missing)
        if missing and pid not in listed_now:
            incomplete.append(pid)
    added: List[str] = []
    if add and failing:
        for pid in failing:
            if pid in by_id or pid not in pulses:
                continue
            entry = {"id": pid, "first_failed_at": now_iso, "attempts": 1}
            note(entry, pid, [])
            by_id[pid] = entry
            added.append(pid)
    ordered = sorted(by_id.values(), key=lambda e: (_first_failed(e), e["id"]))
    span = timedelta(days=max_days)
    given_up: List[Dict[str, Any]] = []
    kept: List[Dict[str, Any]] = []
    for e in ordered:
        # Tried after its deadline (first failure + max_days); a last try later than the run (another host's
        # clock, a hand edit) counts as the run's start, so the deadline has passed by now too.
        expired = by_age and not outage and min(_last_tried(e), now) - span > _first_failed(e)
        (given_up if expired else kept).append(e)
    if len(kept) > max_pulses:
        given_up += kept[: len(kept) - max_pulses]
        kept = kept[len(kept) - max_pulses :]
    return _RetrySettled(kept, added, recovered, still, incomplete, given_up)


def _log_given_up(gave_up: List[Dict[str, Any]]) -> None:
    """The ERROR ``[OTX-RETRY-GAVE-UP]`` lines naming the pulses given up, ``_GAVE_UP_PER_LINE`` a line."""
    for start in range(0, len(gave_up), _GAVE_UP_PER_LINE):
        chunk = gave_up[start : start + _GAVE_UP_PER_LINE]
        logger.error(
            "[OTX-RETRY-GAVE-UP] OTX: %d pulse(s) given up%s (EDGEGUARD_OTX_RETRY_MAX_DAYS=%d, "
            "EDGEGUARD_OTX_RETRY_MAX_PULSES=%d): their failed items are not in MISP and no scheduled run collects "
            "them; a baseline whose window reaches their modified does once the cause is fixed: %s",
            len(gave_up),
            f" ({start + 1}-{start + len(chunk)})" if len(gave_up) > _GAVE_UP_PER_LINE else "",
            otx_retry_max_days(),
            otx_retry_max_pulses(),
            "; ".join(
                f"{e['id']} (modified {e.get('modified', 'unknown')}, attempts {e.get('attempts', 0)}, "
                f"first failed {e.get('first_failed_at')}, last reason: {e.get('last_reason', 'unknown')})"
                for e in chunk
            ),
        )


def _record_otx_retry_metrics(entries: List[Dict[str, Any]], given_up: int) -> None:
    """``edgeguard_otx_retry_pulses``, ``edgeguard_otx_retry_oldest_failure_timestamp_seconds`` and
    ``edgeguard_otx_retry_given_up_total`` (``metrics_server.record_otx_retry_list``); a metrics failure is
    logged at DEBUG and never fails the run."""
    try:
        from metrics_server import record_otx_retry_list

        oldest = min((_first_failed(e) for e in entries), default=None)
        record_otx_retry_list(len(entries), oldest.timestamp() if oldest is not None else 0.0, given_up)
    except Exception as exc:
        logger.debug("OTX retry metrics not recorded: %s", exc)


class OTXCollector:
    """
    AlienVault OTX Collector.

    Production-ready features:
    - Retry logic with exponential backoff
    - Circuit breaker pattern for extended outages
    - Health checks before collection
    - Prometheus metrics integration
    - Timeout handling
    - Comprehensive error logging
    """

    def __init__(self, misp_writer: MISPWriter = None):
        self.base_url = "https://otx.alienvault.com"
        self.api_key = optional_api_key_effective(OTX_API_KEY, OTX_API_KEY_PLACEHOLDERS)
        self.tag = SOURCE_TAGS["otx"]
        self.misp_writer = misp_writer or MISPWriter()
        self.source_name = "otx"

        # Create a session for better connection handling
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            }
        )

        # Get circuit breaker for this collector
        self.circuit_breaker = OTX_CIRCUIT_BREAKER
        # The canonical threat-actor reference, loaded on first use (``_report_actor_reference``).
        self._actor_reference = None
        self._actor_reference_loaded = False

    def _report_actor_reference(self):
        """The canonical threat-actor reference that tells whether a pulse's adversaries are one actor,
        whether an adversary the pulse also lists as a malware family is an actor, and which adversary
        names were reviewed as no actors, or ``None`` when it is unavailable (logged once): the names are
        then told apart as written, so the aliases of one actor count as several and the pulse attributes
        nothing, an adversary named like one of the pulse's families is kept as an actor
        (``_adversaries_not_named_as_pulse_families``), and no name is dropped as no actor
        (``_adversaries_not_listed_as_no_actors``)."""
        if not getattr(self, "_actor_reference_loaded", False):
            self._actor_reference_loaded = True
            self._actor_reference = None
            try:
                self._actor_reference = load_canonical_reference()
            except ReferenceUnavailable as exc:
                logger.warning(
                    "[ATTRIBUTION] canonical reference unavailable (%s): a pulse's adversaries are told apart by "
                    "name, an adversary the pulse also lists as a malware family is kept as an actor, and no "
                    "adversary is dropped as a name the reference lists as no actor",
                    exc,
                )
        return getattr(self, "_actor_reference", None)

    @staticmethod
    def _max_pulse_modified_iso(pulses: List[Dict]) -> Optional[str]:
        """Latest OTX pulse ``modified`` timestamp among *pulses* (ISO string), or None.

        2026-11-02: the values are compared as UTC (``_pulse_modified_dt``: a value without a zone is UTC),
        so pulses that mix values with and without a zone are compared instead of raising ``TypeError``;
        the newest is returned as its own value reads (without a zone when OTX wrote it so).
        """
        best: Optional[Tuple[datetime, str]] = None
        for p in pulses:
            dt = _pulse_modified_dt(p)
            if dt is not None and (best is None or dt > best[0]):
                best = (dt, p["modified"])
        return datetime.fromisoformat(best[1].replace("Z", "+00:00")).isoformat() if best else None

    @staticmethod
    def _pulses_before_oldest(pulses: List[Dict], held_ids: set) -> List[Dict]:
        """The *pulses* modified before the oldest pulse whose id is in *held_ids*.

        2026-10: the cursor goes no further than these, so the next run reads the held pulses again.
        All of them when *held_ids* is empty; none when a held pulse is missing or has no readable
        ``modified`` (the cursor then stays where it is).
        """
        if not held_ids:
            return list(pulses)
        held = {p.get("id"): _pulse_modified_dt(p) for p in pulses if p.get("id") in held_ids}
        if set(held) != set(held_ids) or any(dt is None for dt in held.values()):
            return []
        oldest = min(held.values())
        return [p for p in pulses if (dt := _pulse_modified_dt(p)) is not None and dt < oldest]

    def health_check(self) -> Dict[str, Any]:
        """
        Check OTX API health.

        Returns:
            Dict with health status
        """
        try:
            start_time = time.time()
            response = self.session.get(
                f"{self.base_url}/api/v1/pulses/subscribed",
                params={"limit": 1},
                timeout=(OTX_CONNECT_TIMEOUT, OTX_REQUEST_TIMEOUT),
                verify=SSL_VERIFY,
            )
            response_time = time.time() - start_time

            if response.status_code == 200:
                return {
                    "healthy": True,
                    "response_time_ms": round(response_time * 1000, 2),
                    "status_code": response.status_code,
                }
            else:
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

    def check_service_available(self) -> bool:
        """
        Check if OTX service is available before collection.
        Uses circuit breaker state if available, otherwise does health check.

        Returns:
            True if service is available, False otherwise
        """
        # Check circuit breaker state
        if not self.circuit_breaker.can_execute():
            logger.warning(f"OTX circuit breaker is {self.circuit_breaker.state.name} - skipping collection")
            return False

        # Then do health check
        return check_service_health(self.source_name, self.health_check)

    def detect_sectors(self, text: str) -> List[str]:
        """Detect sectors from text using canonical scorer."""
        return detect_zones_from_text(text)

    @retry_with_backoff(max_retries=MAX_RETRIES)
    def _fetch_pulses(self, limit: int = None, modified_since: str = None, page: int = 1) -> List[Dict]:
        """
        Fetch pulses from OTX API with retry logic.

        Args:
            limit: Maximum number of pulses to fetch per page
            modified_since: ISO timestamp to fetch pulses modified since (for historical)
            page: Page number for pagination

        Returns:
            List of pulse dicts
        """
        params = {"limit": limit or 50, "page": page}
        if modified_since:
            params["modified_since"] = modified_since

        ms_dbg = modified_since[:19] if modified_since else "latest"
        logger.info(f"Fetching pulses from OTX... (page={page}, modified_since={ms_dbg})")

        response = request_with_rate_limit_retries(
            "GET",
            f"{self.base_url}/api/v1/pulses/subscribed",
            session=self.session,
            max_rate_limit_retries=5,
            fallback_delay_sec=90.0,
            retry_on_403=False,
            context="OTX",
            params=params,
            timeout=(OTX_CONNECT_TIMEOUT, OTX_REQUEST_TIMEOUT),
            verify=SSL_VERIFY,
        )

        if response.status_code != 200:
            raise requests.exceptions.HTTPError(
                f"OTX API error: {response.status_code} (after rate-limit retries where applicable)"
            )

        data = response.json()
        pulses = data.get("results", []) if isinstance(data, dict) else data
        # 2026-10: OTX states how many pulses match the request; a baseline logs it (coverage check).
        count = data.get("count") if isinstance(data, dict) else None
        self._otx_reported_total = count if isinstance(count, int) and not isinstance(count, bool) else None

        logger.info(f"[FETCH] OTX: Fetched {len(pulses)} pulses")
        return pulses

    def _fetch_retry_pulses(
        self, entries: List[Dict[str, Any]], window_ids: Set[str], per_run: int, now: datetime
    ) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
        """Fetch by id up to *per_run* pulses of the retry list *entries* that are not in the run's window
        (*window_ids*: a pulse the window read is processed there), in ``_retry_order``: those tried longest ago
        first (2026-11-02).

        One ``GET {base_url}/api/v1/pulses/{id}`` each, with the session, timeouts and TLS setting of the page
        fetch and 2 s after each request. HTTP 200 with the pulse: the pulse is processed with the window's.
        HTTP 404: the pulse was deleted or is no longer subscribed; it leaves the list (WARNING). Any other
        answer keeps it (WARNING, ``last_reason``, ``last_fetch_failed_at``) and is no try: its items were not
        pushed, so neither ``attempts`` nor ``last_tried_at`` changes, and the give-up rule does not count it.
        HTTP 429 or 5xx (429, 502, 503 and 504 after one retry) or an error of the request itself (a timeout, a
        connection error, a body cut off: any ``requests`` exception) also stops the fetches of this run (OTX is
        not answering), and the pulses not fetched wait for the next run. A fetch does not change the entry of a
        pulse it answered: the push of the pulse's items is its try. The entries of *entries* are updated in
        place and the 404s removed. Returns the pulses fetched, the ids answered 404 and the ids with another
        error."""
        now_iso = _utc_iso(now)
        due = sorted((e for e in entries if e["id"] not in window_ids), key=_retry_order)[: max(0, per_run)]
        if due:
            logger.info(
                "[OTX-RETRY] OTX: fetching %d of the %d pulse(s) on the retry list by id "
                "(EDGEGUARD_OTX_RETRY_PER_RUN=%d; %d of them are in this run's window, which processes or "
                "defers them)",
                len(due),
                len(entries),
                per_run,
                len(entries) - sum(1 for e in entries if e["id"] not in window_ids),
            )
        fetched: List[Dict[str, Any]] = []
        not_found: List[str] = []
        errors: List[str] = []
        for n, entry in enumerate(due):
            pid = entry["id"]
            problem: Optional[str] = None
            stop = False
            try:
                response = request_with_rate_limit_retries(
                    "GET",
                    f"{self.base_url}/api/v1/pulses/{quote(pid, safe='')}",
                    session=self.session,
                    max_rate_limit_retries=1,
                    fallback_delay_sec=30.0,
                    retry_on_403=False,
                    context="OTX",
                    timeout=(OTX_CONNECT_TIMEOUT, OTX_REQUEST_TIMEOUT),
                    verify=SSL_VERIFY,
                )
            except requests.exceptions.RequestException as exc:
                problem, stop = type(exc).__name__, True
            else:
                status = response.status_code
                if status == 404:
                    not_found.append(pid)
                    logger.warning(
                        "[OTX-RETRY] OTX: pulse %s answered HTTP 404 (deleted, or no longer subscribed): it leaves "
                        "the retry list after %d attempt(s), first failed at %s; its items are not in MISP",
                        pid,
                        entry.get("attempts", 0),
                        entry.get("first_failed_at"),
                    )
                elif status != 200:
                    problem, stop = f"HTTP {status}", status == 429 or status >= 500
                else:
                    try:
                        body = response.json()
                    except ValueError:
                        body = None
                    if isinstance(body, dict) and str(body.get("id")) == pid:
                        fetched.append(body)
                    else:
                        problem = "an answer that is not the pulse"
            time.sleep(2)  # OTX free tier: 30 requests a minute, as between page requests
            if problem:
                errors.append(pid)
                entry["last_fetch_failed_at"] = now_iso
                entry["last_reason"] = _reason_text(f"fetch by id failed in the run started {now_iso}: {problem}")
                left = len(due) - n - 1
                logger.warning(
                    "[OTX-RETRY] OTX: pulse %s could not be fetched by id (%s); it stays on the retry list%s",
                    pid,
                    problem,
                    f", and the {left} other pulse(s) due wait for the next run" if stop and left else "",
                )
            if stop:
                break
        if not_found:
            gone = set(not_found)
            entries[:] = [e for e in entries if e["id"] not in gone]
        return fetched, not_found, errors

    def collect(
        self, limit: int = None, push_to_misp: bool = True, baseline: bool = False, baseline_days: int = 365
    ) -> Dict[str, Any]:
        """
        Collect pulses from OTX and optionally push to MISP.

        Args:
            limit: Maximum number of pulses to collect
            push_to_misp: Whether to push collected data to MISP
            baseline: If True, collect historical data (all available)
            baseline_days: How many days back to collect in baseline mode

        Returns:
            Dict with status and counts if push_to_misp=True, else list of processed items. After a fetch the
            dict carries ``pulse_counts``: the page rows read, the distinct pulses, the rows that repeated a
            pulse already read, the pulses processed, those that yielded no item and those the limit of a
            scheduled run deferred to the next run (``deferred``, 0 in a baseline). A scheduled run that pushed
            adds the retry list (2026-11-02): ``retry_pending`` (pulses on it after the run), ``retry_added``,
            ``retry_fetched`` (fetched by id and processed), ``retry_recovered``, ``retry_given_up``,
            ``retry_not_found`` (HTTP 404, left the list), ``retry_fetch_failed`` and ``retry_not_pushed``
            (pulses of the list the run read but did not push: ``EDGEGUARD_OTX_RETRY_MAX_SECONDS`` ran out,
            the window's push failed at the MISP event, or a push stopped because MISP kept failing). 2026-11-03:
            ``held_unsent``, the pulses of the window held because the window's push stopped before sending items
            of theirs (``[MISP-PUSH-STOPPED]``).
        """
        limit = resolve_collection_limit(limit, "otx", baseline=baseline)

        # Optional source: no OTX key → skip without failing the DAG (same contract as AbuseIPDB / VT)
        if not optional_api_key_effective(self.api_key, OTX_API_KEY_PLACEHOLDERS):
            logger.warning(
                "OTX: No API key — skipping collection (optional source). "
                "Set OTX_API_KEY for AlienVault OTX; https://otx.alienvault.com/"
            )
            if push_to_misp:
                st = make_status(
                    "otx",
                    True,
                    count=0,
                    failed=0,
                    skipped=True,
                    skip_reason="OTX_API_KEY not set (optional — https://otx.alienvault.com/)",
                    skip_reason_class="missing_otx_key",
                )
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            return []

        # Check if service is available before attempting collection
        if not self.check_service_available():
            error_msg = f"OTX service unavailable (circuit breaker: {self.circuit_breaker.state.name})"
            record_collection_failure(self.source_name, error_msg)
            return self._return_status(False, 0, error_msg)

        try:
            # The stored incremental cursor of a scheduled run; None in a baseline, without a stored cursor or
            # when it does not parse (the run then reads the look-back window).
            cursor_dt: Optional[datetime] = None
            # 2026-11-02: the retry list of a scheduled run, as read (``stored_retry``) and as the run uses it
            # (``retry_entries``); a baseline neither reads nor changes it.
            run_started = datetime.now(timezone.utc)
            stored_retry: Any = None
            retry_entries: List[Dict[str, Any]] = []
            if baseline:
                # Baseline mode: collect all historical data with pagination.
                # No page-based checkpoint — OTX pagination is unstable across
                # different time windows (baseline_days can be 120, 365, 730).
                # A saved page number from a previous window is meaningless.
                # The incremental cursor (modified_since in "incremental" sub-dict)
                # is separate and unaffected.
                logger.info(f"Baseline mode: Collecting last {baseline_days} days of OTX data...")

                all_pulses = []
                modified_since = (datetime.now(timezone.utc) - timedelta(days=baseline_days)).isoformat()
                page = 1
                max_pages = OTX_BASELINE_MAX_PAGES
                consecutive_empty = 0

                while page <= max_pages and consecutive_empty < 3:
                    pulses = self._fetch_pulses(limit=limit, modified_since=modified_since, page=page)
                    if not pulses:
                        consecutive_empty += 1
                        page += 1
                        if consecutive_empty >= 3:
                            logger.info("   3 consecutive empty pages — stopping baseline fetch")
                            break
                        continue
                    consecutive_empty = 0
                    all_pulses.extend(pulses)
                    logger.info(f"   Page {page}: {len(pulses)} pulses (total: {len(all_pulses)})")
                    if page == 1:
                        self._log_baseline_coverage(baseline_days, max_pages, limit or 50)
                    page += 1
                    time.sleep(2)  # OTX free tier: 30 req/min → 2 s between page fetches

                # 2026-11-02: one copy per pulse id (offset paging can return a pulse twice).
                pulses, repeated_rows = _first_copy_of_each_pulse(all_pulses)
                rows_read = len(all_pulses)
                if page > max_pages and consecutive_empty == 0:
                    # 2026-10: the last page was full, so older pulses of the window were not read.
                    logger.warning(
                        "OTX baseline stopped at its page ceiling (EDGEGUARD_OTX_BASELINE_MAX_PAGES=%d, %d pulses): "
                        "pulses older than the last page read were not collected; raise the ceiling to read them",
                        max_pages,
                        len(pulses),
                    )
                if not pulses:
                    logger.warning(
                        "OTX baseline returned 0 pulses for %s-day window — verify API key and OTX connectivity",
                        baseline_days,
                    )
                reported = getattr(self, "_otx_reported_total", None)
                of_reported = f" of {reported} that OTX reported for the window" if reported is not None else ""
                logger.info(
                    f"   Baseline complete: {len(pulses)} distinct pulses collected{of_reported} "
                    f"({rows_read} rows read, {len(repeated_rows)} of them repeating a pulse already read)"
                )
            else:
                # Incremental: only pulses modified since last successful run (checkpoint + overlap).
                inc = get_source_incremental("otx")
                stored = inc.get("otx_last_pulse_modified")
                stored_retry = inc.get(_RETRY_STATE_KEY)
                retry_entries, unusable = _retry_entries(stored_retry, run_started)
                if unusable:
                    logger.warning(
                        "[OTX-RETRY] OTX: %d entr(y/ies) of the stored retry list without a usable pulse id left out",
                        unusable,
                    )
                overlap = timedelta(seconds=max(0, OTX_INCREMENTAL_OVERLAP_SEC))
                if stored:
                    try:
                        base_dt = datetime.fromisoformat(stored.replace("Z", "+00:00"))
                        # PR-M2 §4-F9: ``stored`` may have been written by an
                        # older checkpoint version that omitted the ``Z``
                        # suffix entirely (just ``"2024-01-15T10:00:00"``).
                        # ``str.replace("Z", "+00:00")`` is a no-op on that
                        # string, so ``fromisoformat`` returns a NAIVE
                        # datetime, and subtracting ``overlap`` (which is a
                        # tz-aware-arithmetic-safe timedelta) silently
                        # produces a naive result that downstream
                        # ``coerce_iso`` would treat differently than a
                        # tz-aware one. Defensive UTC injection ensures
                        # the resume cursor is always tz-aware, matching
                        # docs/TIMESTAMPS.md "Invariant 2".
                        if base_dt.tzinfo is None:
                            base_dt = base_dt.replace(tzinfo=timezone.utc)
                        modified_since = (base_dt - overlap).isoformat()
                        cursor_dt = base_dt
                    except (ValueError, TypeError):
                        modified_since = (
                            datetime.now(timezone.utc) - timedelta(days=OTX_INCREMENTAL_LOOKBACK_DAYS)
                        ).isoformat()
                else:
                    modified_since = (
                        datetime.now(timezone.utc) - timedelta(days=OTX_INCREMENTAL_LOOKBACK_DAYS)
                    ).isoformat()
                logger.info(
                    "OTX incremental: modified_since=%s (max_pages=%s)",
                    modified_since[:22],
                    OTX_INCREMENTAL_MAX_PAGES,
                )
                all_incr: List[Dict] = []
                page_i = 1
                last_page_rows = 0
                while page_i <= OTX_INCREMENTAL_MAX_PAGES:
                    page_pulses = self._fetch_pulses(
                        limit=_OTX_INCREMENTAL_PAGE_SIZE,
                        modified_since=modified_since,
                        page=page_i,
                    )
                    if not page_pulses:
                        break
                    all_incr.extend(page_pulses)
                    last_page_rows = len(page_pulses)
                    page_i += 1
                    time.sleep(2)
                # 2026-11-02: one copy per pulse id, before the per-run limit (a repeated row took a slot).
                pulses, repeated_rows = _first_copy_of_each_pulse(all_incr)
                rows_read = len(all_incr)
                reported = getattr(self, "_otx_reported_total", None)
                of_reported = f" of {reported} that OTX reported for the window" if reported is not None else ""
                logger.info(
                    f"OTX incremental: {len(pulses)} distinct pulses read{of_reported} "
                    f"({rows_read} rows read, {len(repeated_rows)} of them repeating a pulse already read)"
                )
                # 2026-11-02: the fetch stopped at its page ceiling with pulses left to read (a full last page,
                # or OTX reporting more pulses than were read). OTX returns the newest-modified pulses first, so
                # those not read are the oldest of the window, older than every pulse the run can process.
                if page_i > OTX_INCREMENTAL_MAX_PAGES and (
                    last_page_rows >= _OTX_INCREMENTAL_PAGE_SIZE or (reported is not None and reported > len(pulses))
                ):
                    logger.warning(
                        "OTX incremental stopped at its page ceiling (EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES=%d, %d per "
                        "page): %d distinct pulses read%s. OTX returns the newest-modified pulses first, so the pulses "
                        "not read are the oldest of the window, and any advance of the cursor passes them; raise "
                        "EDGEGUARD_OTX_INCREMENTAL_MAX_PAGES or run a baseline to read them",
                        OTX_INCREMENTAL_MAX_PAGES,
                        _OTX_INCREMENTAL_PAGE_SIZE,
                        len(pulses),
                        of_reported,
                    )

            if repeated_rows:
                logger.warning(
                    "[PULSES] OTX: %d page row(s) repeated %d pulse(s) already read (repeated ids: %s); the first "
                    "copy of each is kept. If the page order shifted between requests, as many other pulses may "
                    "have been passed over.",
                    len(repeated_rows),
                    len(set(repeated_rows)),
                    _pulse_ids_for_log(repeated_rows),
                )

            # Process pulses
            processed = []
            non_file_hashes = 0
            # 2026-10-18: adversary names a pulse also lists as its malware family, unknown to the
            # canonical reference (``_adversaries_not_named_as_pulse_families``), per run, and the
            # number of pulses that left one out.
            adversaries_named_as_family: Set[str] = set()
            pulses_naming_an_adversary_as_family = 0
            # 2026-10-22: country and state names and nationality adjectives the name hygiene dropped
            # from adversary fields (rule (c), ``dropped_geopolitical_names``), per run: name -> the
            # pulses that carried it, and the number of such pulses. Logged once, below, so that a group
            # whose common name is a country can be noticed and written under a qualified name.
            geopolitical_adversary_names: Dict[str, List[str]] = {}
            pulses_with_a_geopolitical_adversary_name = 0
            # 2026-11-05: adversary names the canonical reference lists as no actors
            # (``_adversaries_not_listed_as_no_actors``), per run: name -> the pulses that carried it, and the
            # number of such pulses. Logged once, below.
            not_actor_adversary_names: Dict[str, List[str]] = {}
            pulses_with_a_not_actor_adversary_name = 0

            deferred: List[Dict] = []
            if baseline:
                to_process = pulses if limit is None else pulses[:limit]
            else:
                # 2026-11-02: the limit counts the pulses modified after the cursor, oldest first; OTX returns
                # them newest first, and cut in that order the cursor passed the older pulses of the window.
                selection = _incremental_pulses_within_limit(pulses, cursor_dt, limit)
                to_process, deferred = selection.process, selection.deferred
                if selection.undated:
                    logger.warning(
                        "[PULSES] OTX: %d pulse(s) without a readable 'modified' processed outside the limit; they "
                        "cannot move the cursor, so every run that reads them processes them again (ids: %s)",
                        len(selection.undated),
                        _pulse_ids_for_log(selection.undated),
                    )
                if deferred:
                    logger.info(
                        "[PULSES] OTX: %d pulse(s) deferred to the next run: the run's limit of %d "
                        "(EDGEGUARD_INCREMENTAL_LIMIT, or EDGEGUARD_MAX_ENTRIES when set) counts the pulses modified "
                        "after the cursor, oldest first, and the run took those modified up to %s; %d pulse(s) "
                        "re-read inside the overlap window were processed outside the limit",
                        len(deferred),
                        limit,
                        self._max_pulse_modified_iso(to_process),
                        selection.reread,
                    )
            # 2026-11-02: pulses of the retry list, fetched by id and processed with the window's; they count
            # toward no limit and never move the cursor.
            retried: List[Dict[str, Any]] = []
            retry_not_found: List[str] = []
            retry_fetch_failed: List[str] = []
            if not baseline and push_to_misp and retry_entries:
                retried, retry_not_found, retry_fetch_failed = self._fetch_retry_pulses(
                    retry_entries,
                    {str(p.get("id")) for p in pulses if p.get("id")},
                    otx_retry_per_run(),
                    run_started,
                )

            def _process_pulse(pulse: Dict) -> None:
                """Append the items of *pulse* to ``processed``."""
                nonlocal non_file_hashes, pulses_naming_an_adversary_as_family
                nonlocal pulses_with_a_geopolitical_adversary_name, pulses_with_a_not_actor_adversary_name
                # Detect ALL sectors — start with keyword-based detection
                pulse_text = json.dumps(pulse).lower()
                sectors = self.detect_sectors(pulse_text)

                # OTX's own classification: the pulse's ``industries`` are the report author's
                # statement of the sectors its campaign targets. Their zones join the keyword hits
                # in the item's zones, and the raw list travels with every item (``otx_industries``):
                # the sync takes the zones it maps to as the pulse's statement (``otx_industries`` on
                # TARGETS, ``sector_evidence``, 2026-10-18), the keyword hits as inferred.
                #
                # PR-N6 hotfix #4 (audit 09, Maintainer #1): the industry map lives in
                # ``config.OTX_INDUSTRY_ZONE_ALIASES`` beside ``VALID_ZONES`` / ``SECTOR_KEYWORDS``,
                # read through ``config.otx_industry_zones`` (the collector and the sync read it alike).
                otx_industries = pulse.get("industries", [])
                industry_zones = otx_industry_zones(otx_industries)
                if industry_zones:
                    for mapped in industry_zones:
                        if mapped not in sectors:
                            sectors.append(mapped)
                    # Remove "global" if we now have specific sectors
                    if len(sectors) > 1 and "global" in sectors:
                        sectors = [s for s in sectors if s != "global"]

                # Pulse-level metadata (available on all items from this pulse)
                pulse_attack_ids = [
                    aid.get("id", aid) if isinstance(aid, dict) else str(aid) for aid in pulse.get("attack_ids", [])
                ]
                pulse_targeted_countries = pulse.get("targeted_countries", [])
                pulse_tags = pulse.get("tags", [])
                pulse_references = pulse.get("references", [])[:10]
                pulse_author = pulse.get("author_name", "")
                pulse_adversary = pulse.get("adversary", "")
                pulse_tlp = _pulse_tlp(pulse)
                # 2026-10: the pulse's description is stored on no item. It describes the report, and it was
                # given only to the malware family and adversary items below, as their description: every
                # family and adversary a pulse named showed that pulse's text, in place of ATT&CK's where
                # both describe the entity, depending on which record the sync merged last. It still feeds
                # sector detection above (the whole pulse is scanned), so it decides the zone of every item.

                # PR-M2 §4-F5: read the source's pulse-level timestamps
                # ONCE at the top of the per-pulse block and use them for
                # the per-indicator ``first_seen`` / ``last_seen``
                # propagation further down.
                # Bugbot caught (PR-M2 round 1, LOW): the previous code
                # assigned ``pulse_created = pulse.get("created", "")``
                # for filtering, then later reassigned
                # ``pulse_created = pulse.get("created")`` (None default)
                # for honest-NULL propagation — same name, two semantics,
                # latent breakage if a future edit moved one assignment.
                # Single source of truth eliminates the shadowing risk;
                # downstream honest-NULL gating (``if indicator_first_seen``)
                # treats ``""`` as "absent" too.
                #
                # OTX is intentionally NOT on ``_RELIABLE_FIRST_SEEN_SOURCES``
                # so the read-side ``extract_source_truthful_timestamps``
                # correctly ignores OTX's claim. BUT the MISP attribute
                # itself still carries whatever we put here, so non-EdgeGuard
                # consumers (ResilMesh, SIEM bridges) reading MISP directly
                # will see this value as the source's claim.
                #
                # Honest-NULL pattern (mirrors AbuseIPDB blacklist): omit
                # ``first_seen`` when the source field is absent rather
                # than substituting wall-clock NOW. Per-indicator
                # ``ind.get("created")`` overrides the pulse-level
                # ``pulse.get("created")`` when present (OTX returns
                # per-indicator timestamps for some pulse types).
                # Concept 1 in docs/TIMESTAMPS.md.
                pulse_created = pulse.get("created")  # may be None or "" — honest NULL
                pulse_modified = pulse.get("modified")

                # No age filter on the pulse (2026-10): the request bounds it by ``modified_since``
                # (baseline: ``baseline_days``; incremental: the stored cursor). The former
                # SECTOR_TIME_RANGES filter here compared OTX's zone-less ``created``
                # ("2023-01-25T11:11:02.458000") with a timezone-aware cutoff and swallowed the
                # TypeError, so it had not dropped a pulse since v2026.3.28. Made to work, it would
                # have dropped pulses created more than 24 months ago that are still being updated,
                # new IOCs included.

                # Shared metadata dict for all items from this pulse
                # 2026-10 (regular-update linking): computed once per pulse, stamped on each IOC below.
                pulse_family_names = _pulse_family_names(pulse.get("malware_families", []))
                # 2026-10: a pulse whose adversaries are several actors does not say which family is
                # whose, so it attributes nothing: no family::adversary pairs, and every item of it
                # records the pulse in ``several_actor_pulses`` for the sync. Decided here, on the whole
                # adversary list (the aliases of one actor count as one, canonical reference): MISP
                # drops an actor or family it already holds, so downstream a later pulse is incomplete.
                # Without the reference the aliases of one actor count as several: the pulse still writes
                # no pair, but the mark goes to ``several_actor_pulses_by_name``, which the sync uses for
                # its own run and never stores on a node, so build_relationships step 2d removes no link
                # on a judgement made without the reference.
                # 2026-10-18: the adversary names are decided once, here, and the several-actor decision,
                # the pairs and the actor items below all use them: ``clean_actor_names`` drops composites'
                # junk, descriptions and country / state names ("APT37, North Korea" is one actor), and a
                # name the pulse also lists as a malware family is an actor only when the canonical
                # reference resolves it (``_adversaries_not_named_as_pulse_families``; kept without it).
                # 2026-11-05: before that rule, a name the reference lists as no actor (ClickFix, Proton66)
                # is dropped (``_adversaries_not_listed_as_no_actors``; kept without the reference).
                # The names dropped here, like the pulse's non-file hashes, reach the run's tallies (the
                # [ACTOR-NAMES] and [SKIP] lines) at the end of this function, once every item of the pulse is
                # built (2026-11-05): a pulse of the retry list whose answer cannot be processed (below)
                # leaves no item and no count.
                actor_reference = self._report_actor_reference()
                _adversary_names, _not_actors = _adversaries_not_listed_as_no_actors(
                    clean_actor_names(pulse_adversary or ""), actor_reference
                )
                pulse_all_actor_names, _named_as_family = _adversaries_not_named_as_pulse_families(
                    _adversary_names, pulse.get("malware_families", []), actor_reference
                )
                _geopolitical_names = dropped_geopolitical_names(pulse_adversary or "")
                pulse_several_actors = len(actor_identities(pulse_all_actor_names, actor_reference)) > 1
                pulse_mark = [str(pulse.get("id"))] if pulse_several_actors and pulse.get("id") else []
                pulse_actor_names = pulse_all_actor_names[:_MAX_PULSE_ADVERSARIES]
                pulse_actor_pairs = (
                    []
                    if pulse_several_actors
                    else _pulse_actor_pairs(pulse_family_names, pulse_actor_names, pulse.get("id"))
                )
                pulse_meta = {
                    "pulse_id": pulse.get("id"),
                    "several_actor_pulses": pulse_mark if actor_reference is not None else [],
                    "several_actor_pulses_by_name": pulse_mark if actor_reference is None else [],
                    "pulse_name": pulse.get("name", "")[:100],
                    "pulse_tags": pulse_tags[:20],
                    "pulse_references": pulse_references,
                    "pulse_author": pulse_author,
                    "pulse_tlp": pulse_tlp,
                    "attack_ids": pulse_attack_ids,
                    "targeted_countries": pulse_targeted_countries,
                    "otx_industries": otx_industries,
                }
                # Extract indicators - one entry per indicator (zone holds all matched sectors)
                indicators = pulse.get("indicators", [])
                pulse_non_file_hashes = 0
                for ind in indicators:
                    if ind.get("type") in _NON_FILE_HASH_TYPES:
                        pulse_non_file_hashes += 1
                        continue
                    indicator_type = self.map_indicator_type(ind.get("type"), ind.get("indicator"))
                    indicator_value = ind.get("indicator")
                    indicator_first_seen = ind.get("created") or pulse_created
                    indicator_last_seen = ind.get("modified") or pulse_modified
                    item: Dict[str, Any] = {
                        "indicator_type": indicator_type,
                        "value": indicator_value,
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        "description": ind.get("description", "") or ind.get("title", ""),
                        "indicator_role": ind.get("role", ""),
                        "is_active": ind.get("is_active", True),
                        # 2026-10 (regular-update linking): see _pulse_family_names.
                        "pulse_malware_families": list(pulse_family_names),
                        "pulse_malware_actor_pairs": list(pulse_actor_pairs),
                        **pulse_meta,
                    }
                    if indicator_first_seen:
                        item["first_seen"] = indicator_first_seen
                    if indicator_last_seen:
                        item["last_seen"] = indicator_last_seen
                    processed.append(item)

                # Extract malware families
                # PR-M2 §4-F5 (Bugbot round 3): symmetric honest-NULL
                # propagation. Indicator + CVE branches use
                # ``pulse_created`` / ``pulse_modified`` for first_seen /
                # last_seen; the malware-family branch must follow the
                # same pattern or the per-pulse timestamp contract is
                # broken (some entities from one pulse carry the source's
                # claim, others don't — silently inconsistent).
                # 2026-10: OTX names families as the MISP ATT&CK galaxy does, with the ATT&CK software
                # id as a suffix ("Cobalt Strike - S0154"). Passed through, each became a Malware node
                # of its own beside the ATT&CK one ("cobalt strike"), and the indicators of the family
                # split between the two (136 such twins on the graph of 2026-10-14). The item is named
                # by the base name and keeps the original string as an alias. An entry without a name
                # is skipped (it became a placeholder "Unknown" item before, rejected at the node merge).
                malware_families = pulse.get("malware_families", []) or []
                for mal in malware_families:
                    raw_family = _family_entry_name(mal)
                    if not raw_family:
                        continue
                    mal_name, attack_software_id = split_attack_software_id(raw_family)
                    mal_item: Dict[str, Any] = {
                        "type": "malware",
                        "name": mal_name,
                        "aliases": [raw_family] if attack_software_id else [],
                        "malware_types": ["unknown"],
                        "family": mal_name,
                        # 2026-10: no description — the pulse's text describes the report, not the family.
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        # 2026-10: pulse-level ATT&CK ids are a report association,
                        # not MITRE's explicit "uses" relationship — they travel as
                        # ``reported_techniques`` (→ IMPLEMENTS_TECHNIQUE with
                        # match_type ``otx_pulse``), never as ``uses_techniques``.
                        "reported_techniques": pulse_attack_ids,
                        **pulse_meta,
                    }
                    if pulse_created:
                        mal_item["first_seen"] = pulse_created
                    if pulse_modified:
                        mal_item["last_seen"] = pulse_modified
                    processed.append(mal_item)

                # Extract CVE references (no cap — collect all CVEs from pulse)
                # PR-M2 §4-F5: same honest-NULL treatment for CVE entries
                # synthesized from the pulse. OTX's claim about a CVE's
                # first_seen is the pulse's ``created`` timestamp if the
                # API provided it; otherwise we omit the field rather
                # than substituting wall-clock NOW.
                cve_refs = pulse.get("cve_references", [])
                for cve in cve_refs:
                    cve_item: Dict[str, Any] = {
                        "type": "vulnerability",
                        "cve_id": cve.upper() if isinstance(cve, str) else cve.get("cve", "").upper(),
                        "description": f"Referenced in OTX pulse: {pulse.get('name', '')}",
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        "severity": "UNKNOWN",
                        # A pulse reference carries no CVSS (0.0 was tagged cvss:low) and no attack
                        # vector (an invented "NETWORK" was sent until 2026-10).
                        "cvss_score": None,
                        **pulse_meta,
                    }
                    if pulse_created:
                        cve_item["first_seen"] = pulse_created
                    if pulse_modified:
                        cve_item["last_seen"] = pulse_modified
                    processed.append(cve_item)

                # Extract named adversary as a ThreatActor if present.
                # PR-M2 §4-F5 (Bugbot round 3): symmetric honest-NULL
                # propagation — see malware-family branch above for
                # rationale. Same pulse-level timestamps apply.
                # 2026-10: OTX's free-text ``adversary`` is a report field, not a
                # name — pulses ship composites ("apt-c-13, sandworm, frozenbarents",
                # "head mare and twelve") and descriptions ("multiple russian
                # state-backed groups"). ``clean_actor_names`` splits the former into
                # one actor item each and drops the latter, so no ThreatActor node is
                # ever created from a phrase. 2026-10-18: the names decided above
                # (``pulse_all_actor_names``), uncapped.
                for adversary_name in pulse_all_actor_names:
                    actor_item: Dict[str, Any] = {
                        "type": "actor",
                        "name": adversary_name,
                        # 2026-10: no description — the pulse's text describes the report, not the actor.
                        "zone": sectors,
                        "tag": self.tag,
                        "source": [self.tag],
                        "confidence_score": 0.5,
                        # 2026-10: see the malware branch — pulse ids are reported, not MITRE-explicit.
                        "reported_techniques": pulse_attack_ids,
                        "aliases": [],
                        **pulse_meta,
                    }
                    if pulse_created:
                        actor_item["first_seen"] = pulse_created
                    if pulse_modified:
                        actor_item["last_seen"] = pulse_modified
                    processed.append(actor_item)

                # The pulse's tallies, now that all its items are built (see the adversary names above).
                non_file_hashes += pulse_non_file_hashes
                _pulse_id = str(pulse.get("id") or "?")
                if _not_actors:
                    pulses_with_a_not_actor_adversary_name += 1
                    for _dropped in {n.lower() for n in _not_actors}:
                        not_actor_adversary_names.setdefault(_dropped, []).append(_pulse_id)
                if _named_as_family:
                    adversaries_named_as_family.update(n.lower() for n in _named_as_family)
                    pulses_naming_an_adversary_as_family += 1
                if _geopolitical_names:
                    pulses_with_a_geopolitical_adversary_name += 1
                    for _dropped in {n.lower() for n in _geopolitical_names}:
                        geopolitical_adversary_names.setdefault(_dropped, []).append(_pulse_id)

            for pulse in to_process:
                _process_pulse(pulse)
            # 2026-11-02: the pulses fetched by id come after the window's, so the same-run fold keeps the window's
            # copy of an item both list. An answer by id that cannot be processed (a field of another type than a
            # subscribed pulse carries, which raises one of the errors caught here) is set aside like a failed
            # fetch: the pulse stays on the list, without an attempt, and the run goes on.
            entries_by_id = {e["id"]: e for e in retry_entries}
            for pulse in list(retried):
                first = len(processed)
                try:
                    _process_pulse(pulse)
                except (TypeError, AttributeError, ValueError, KeyError) as exc:
                    del processed[first:]
                    retried.remove(pulse)
                    pid = str(pulse.get("id"))
                    retry_fetch_failed.append(pid)
                    problem = f"{type(exc).__name__}: {exc}"[:200]
                    entries_by_id[pid]["last_fetch_failed_at"] = _utc_iso(run_started)
                    entries_by_id[pid]["last_reason"] = _reason_text(
                        f"the answer by id of the run started {_utc_iso(run_started)} could not be read ({problem})"
                    )
                    logger.warning(
                        "[OTX-RETRY] OTX: the answer by id for pulse %s could not be read (%s); it stays on the retry "
                        "list",
                        pid,
                        problem,
                    )

            # Deduplicate — later pulses fold their pulse id / reported techniques into
            # the kept item (see _dedupe_pulse_items; Bugbot finding on PR #134).
            unique = _dedupe_pulse_items(processed)

            logger.info(f"[OK] OTX: Processed {len(unique)} unique items")
            # 2026-11-02: the pulses of the run that yielded no item (no collected indicator, malware family,
            # CVE or adversary), so a pulse count above the graph's is told apart from items lost later.
            without_item = _pulses_without_item(to_process, unique)
            logger.info(
                "[PULSES] OTX: %d pulse(s) processed, %d of them yielded no item%s",
                len(to_process),
                len(without_item),
                f" (no collected indicator, malware family, CVE or adversary): {_pulse_ids_for_log(without_item)}"
                if without_item
                else "",
            )
            pulse_counts = {
                "rows_read": rows_read,
                "distinct": len(pulses),
                "repeated_rows": len(repeated_rows),
                "processed": len(to_process),
                "without_item": len(without_item),
                "deferred": len(deferred),
            }
            if adversaries_named_as_family:
                logger.info(
                    "[ACTOR-NAMES] OTX: %d distinct adversary name(s) in %d pulse(s), which the same pulse lists "
                    "as a malware family and the canonical threat-actor reference does not know, not taken as "
                    "actors (they stay malware): %s",
                    len(adversaries_named_as_family),
                    pulses_naming_an_adversary_as_family,
                    ", ".join(sorted(adversaries_named_as_family)),
                )
            if geopolitical_adversary_names:
                logger.info(
                    "[ACTOR-NAMES] OTX: %d distinct country, state, nationality or state-agency name(s) in %d "
                    "pulse(s), dropped from the adversary field by the actor-name hygiene (never actor names; a "
                    "group named after a country or an agency needs a qualified name): %s",
                    len(geopolitical_adversary_names),
                    pulses_with_a_geopolitical_adversary_name,
                    "; ".join(
                        _dropped_name_with_pulses(name, geopolitical_adversary_names[name])
                        for name in sorted(geopolitical_adversary_names)
                    ),
                )
            if not_actor_adversary_names:
                logger.info(
                    "[ACTOR-NAMES] OTX: %d distinct adversary name(s) in %d pulse(s) that the canonical threat-actor "
                    "reference lists as no actors, dropped from the adversary field: %s",
                    len(not_actor_adversary_names),
                    pulses_with_a_not_actor_adversary_name,
                    "; ".join(
                        _dropped_name_with_pulses(name, not_actor_adversary_names[name])
                        for name in sorted(not_actor_adversary_names)
                    ),
                )
            if non_file_hashes:
                logger.info(
                    "[SKIP] OTX: %d indicators of a non-file hash type (%s) not collected",
                    non_file_hashes,
                    ", ".join(sorted(_NON_FILE_HASH_TYPES)),
                )

            def _cursor_after(cursor_pulses: List[Dict]) -> Optional[str]:
                """The cursor value over *cursor_pulses*: the newest ``modified`` among them, or ``None`` (the
                cursor stays) when there is none.

                Audit finding BH-H1: the cursor was taken over ``pulses``, the full fetched list, so when
                EDGEGUARD_INCREMENTAL_LIMIT cut the run (250 modified pulses, limit 200) the cursor reached the
                newest of all 250 and the 50 left out were never read again. It is taken over the pulses the run
                processed (``to_process``) or a part of them. 2026-11-02: that alone did not protect the pulses
                left out, because OTX returns the pulses newest first and the limit kept the newest 200: the
                cursor still passed the 50 older ones. The limit now takes the pulses modified after the stored
                cursor oldest first (``_incremental_pulses_within_limit``), so every pulse it leaves out is
                modified at or after the newest pulse attempted, and the next run reads it again. The pulses
                fetched by id from the retry list are never among *cursor_pulses*.
                """
                return self._max_pulse_modified_iso(cursor_pulses) if cursor_pulses else None

            # 2026-11-02: a scheduled run pushes its window first: every item that names a pulse not on the retry
            # list (``window_items``), as one push. It then saves the cursor and the pulses that push put on the
            # list, within the list's cap, so a run that fails or is killed later keeps them. Then it pushes the
            # items that only pulses of the list name (``retry_items``), each pulse in batches of its own and those
            # tried longest ago first, within EDGEGUARD_OTX_RETRY_MAX_SECONDS, and settles the list. A baseline
            # reads no list: every item is a window item.
            listed_ids = {e["id"] for e in retry_entries}
            window_ids = {str(p.get("id")) for p in to_process if p.get("id")}
            known_ids = window_ids | {str(p.get("id")) for p in retried}
            retry_order = {e["id"]: _retry_order(e) for e in retry_entries}
            pushed_refs = {} if baseline else _items_per_pulse(unique)
            stored_list = stored_retry if isinstance(stored_retry, list) else []

            def _only_listed(item: Dict[str, Any]) -> bool:
                named = [str(pid) for pid in [item.get("pulse_id"), *(item.get("report_ids") or [])] if pid]
                return bool(named) and all(pid in listed_ids for pid in named)

            window_items = [item for item in unique if not _only_listed(item)]
            retry_items = [item for item in unique if _only_listed(item)]

            def _outcome(items: List[Dict[str, Any]], failed: int) -> Tuple[Optional[Dict[str, List[str]]], bool]:
                """The pulses with listed items of the push of *items* that just ended (``None``: unknown), and
                whether MISP failed that push at the event (``_failed_at_the_event``), also when a listed item
                names no pulse the run processed (an OTX row without an id): an outage whatever the items name."""
                if failed <= 0:
                    return {}, False
                unstored = getattr(self.misp_writer, "last_push_unstored_items", None)
                failing = _pulses_with_listed_items(items, unstored, known_ids)
                whole = _failed_at_the_event(unstored, getattr(self.misp_writer, "last_push_event_failed_items", None))
                return failing, whole

            def _after_window_push(success: int, failed: int) -> Optional[_WindowSettled]:
                """The cursor, and the pulses of the window put on the retry list, after the window's push of a
                scheduled run; written in one update of the incremental state before the push of the list's
                pulses (a baseline changes neither).

                - Without failures the cursor advances to the newest pulse processed, also when MISP already held
                  every item (``push_items`` counts an item MISP holds as neither stored nor failed, so such a
                  push returns (0, 0); with the oldest-first limit a cursor that moved only after a stored item
                  made every run take the same pulses while the newer ones waited).
                - After a push with failures whose listed items all name pulses the run processed, the cursor
                  advances as after a push without failures, and every pulse a listed item names (its
                  ``pulse_id`` and ``report_ids``) that is not on the list yet goes on it. This includes a batch
                  MISP refused as a whole (HTTP 4xx, or 429 / 5xx after the retries), whatever share of the push
                  it held: one value MISP refuses fails its batch, and read as an outage it held the cursor on
                  every run that pushed the value. Failures the writer does not list (values with 4-byte
                  characters, attributes missing from a batch MISP answered with HTTP 200 and partly stored) put
                  no pulse on it; a single record no attribute could be built from is reported and not counted as
                  failed.
                - When every listed item failed at its event (``_failed_at_the_event``: MISP unreachable when the
                  push started, or the lookup or creation of the day's event failing), none of the unstored items
                  reached a batch: the cursor stops below the oldest pulse of the window with a listed item, stays
                  when there is none older or that pulse has no readable ``modified``, and no pulse goes on the
                  list. The pulses of the list are then not pushed in this run and keep their entries: an outage
                  holds back nothing MISP could have stored, and the next run reads the window again.
                  When a listed item names no pulse the run processed, the cursor stays.
                - A writer that gives no list, or a listed item that names no pulse the run processed (and not every
                  listed item failed at its event): the failed items are unknown, the cursor stays and no pulse goes
                  on the list.
                - 2026-11-03: a push that stopped because MISP kept failing (``last_push_stopped``,
                  ``[MISP-PUSH-STOPPED]``) did not send the items it lists in ``last_push_unsent_items``, which say
                  nothing about their pulses (an outage, not a refusal). The pulses those items name are held: the
                  cursor stops below the oldest of them in the window, stays when that pulse has no readable
                  ``modified``, and none of them goes on the list; the pulses whose items were sent and failed go on
                  it as above. A pulse already on the list that an unsent item names keeps its entry unchanged, also
                  when the push's other failures are unknown (a listed item names no pulse the run processed: the
                  cursor stays and no pulse goes on the list), and the pulses of the list are not pushed in this
                  run; a listed pulse read in the window whose items were all sent follows that push.

                The pulses with unstored items come from the writer's list, never from the items' positions: the
                pulses of ``unique[:success]`` (2026-10) named a failed batch's pulses whenever an earlier batch
                failed or items were already present. The cursor passes only pulses whose items were stored or
                found in MISP, or that are on the list as written in the same update.

                The list written here holds at most EDGEGUARD_OTX_RETRY_MAX_PULSES: beyond it the pulses that first
                failed longest ago are given up now, with the ERROR and the counter, and their items are not pushed,
                so a run that raises or is killed later leaves no longer list. When the pulses of the list are to be
                pushed, the entry written of the pulse their push begins with carries ``last_push_started_at``: if
                that push raises or the task is killed, that pulse goes behind the others at the next run
                (``_retry_order``), so a pulse whose batch raises on every run cannot keep the others from being
                pushed. The final write replaces the mark (``_push_and_settle_the_list``).
                """
                if baseline:
                    return None
                now_iso = _utc_iso(run_started)
                failing, whole = _outcome(window_items, failed)
                # 2026-11-03: a push that stopped because MISP kept failing (``[MISP-PUSH-STOPPED]``) did not send
                # the items it lists in ``last_push_unsent_items``: an outage, not a refusal, for their pulses. The
                # pulses those items name are held whatever else the push's failures say (``_named_pulses`` needs
                # no known ids, so a window row without an id does not undo it); without that list they are
                # unknown, and every pulse of the window with a listed item, or else every pulse of the window,
                # is held.
                stopped = failed > 0 and getattr(self.misp_writer, "last_push_stopped", False) is True
                unsent_list = getattr(self.misp_writer, "last_push_unsent_items", None) if stopped else None
                unsent_known = isinstance(unsent_list, (list, tuple, set))
                unsent_held: Set[str] = set()
                if stopped:
                    if unsent_known:
                        unsent_held = _named_pulses(window_items, unsent_list)
                    else:
                        unsent_held = set(failing) if failing is not None else set(window_ids)
                if whole:
                    held = set(failing or {}) & window_ids
                    new_cursor = (
                        None if failing is None else _cursor_after(self._pulses_before_oldest(to_process, held))
                    )
                    reason = f"MISP failed the push of the run started {now_iso} at the day's event"
                    if new_cursor and not held:
                        where = f"advances to {new_cursor} (no pulse of the window has an item)"
                    elif new_cursor:
                        where = f"moves to {new_cursor}, below the oldest pulse of the window with a listed item"
                    else:
                        where = "stays where it was"
                    logger.warning(
                        "[OTX-RETRY] OTX: every unstored item of the push failed at its MISP event (MISP "
                        "unreachable, or the lookup or creation of the day's event failing): no pulse goes on the "
                        "retry list, and the cursor %s, so the next run reads those pulses again; the pulses of the "
                        "retry list are not pushed in this run and keep their entries",
                        where,
                    )
                elif failing is None:
                    new_cursor = None
                    reason = f"the MISP push of the run started {now_iso} failed {failed} item(s) without naming them"
                    logger.warning(
                        "[OTX-RETRY] OTX: the push failed %d item(s) the writer did not name (no list of unstored "
                        "items, or a listed item of no pulse this run processed): the cursor stays, and no pulse "
                        "goes on the retry list%s",
                        failed,
                        (
                            "; the push stopped because MISP kept failing ([MISP-PUSH-STOPPED]): the pulses of the "
                            "retry list are not pushed in this run, and those an item not sent names keep their "
                            f"entries (ids: {_pulse_ids_for_log(sorted(unsent_held & listed_ids))})"
                        )
                        if stopped
                        else "",
                    )
                elif stopped:
                    # 2026-11-03: the pulses the unsent items name are held as after a failure at the event: the
                    # cursor stops below the oldest of them in the window and none goes on the list; the pulses
                    # whose items were sent and failed go on it as after any batch failure. Without a list of the
                    # unsent items they are unknown: the cursor stays and no pulse goes on the list.
                    held_window = unsent_held & window_ids
                    new_cursor = (
                        _cursor_after(self._pulses_before_oldest(to_process, held_window)) if unsent_known else None
                    )
                    failing = {pid: keys for pid, keys in failing.items() if pid not in unsent_held}
                    reason = f"MISP push of the run started {now_iso}: {failed} of {len(window_items)} item(s) failed"
                    if new_cursor and not held_window:
                        where = f"advances to {new_cursor} (no pulse of the window has an item not sent)"
                    elif new_cursor:
                        where = f"moves to {new_cursor}, below the oldest pulse of the window with an item not sent"
                    else:
                        where = "stays where it was"
                    logger.warning(
                        "[OTX-RETRY] OTX: the MISP push stopped because MISP kept failing ([MISP-PUSH-STOPPED]): the "
                        "items of %d pulse(s) of the window were not sent; those pulses do not go on the retry list, "
                        "and the cursor %s, so the next run reads them again. The pulses of the retry list are not "
                        "pushed in this run: those an item not sent names keep their entries, and those read in the "
                        "window otherwise follow its push (ids not sent: %s)",
                        len(held_window),
                        where,
                        _pulse_ids_for_log(sorted(held_window)),
                    )
                else:
                    new_cursor = _cursor_after(to_process)
                    reason = f"MISP push of the run started {now_iso}: {failed} of {len(window_items)} item(s) failed"
                settled = _settle_retry_list(
                    retry_entries,
                    [p for p in to_process if str(p.get("id")) not in listed_ids],
                    failing,
                    pushed_refs,
                    add=failing is not None and not whole,
                    outage=whole,
                    reason=reason,
                    now=run_started,
                    max_days=otx_retry_max_days(),
                    max_pulses=otx_retry_max_pulses(),
                    by_age=False,
                )
                # The items of the push of the list's pulses: those of the pulses still on the list, each in the
                # batches of the pulse of the list it names that comes first in ``_retry_order`` (``_list_pulse``).
                order = {e["id"]: retry_order[e["id"]] for e in settled.entries if e["id"] in retry_order}
                keyed = [(pid, item) for item in retry_items if (pid := _list_pulse(item, order))]
                keyed.sort(key=lambda pair: order[pair[0]])
                list_items = [item for _pid, item in keyed]
                pushes = bool(list_items) and not whole and not stopped
                updates: Dict[str, Any] = {}
                saved = copy.deepcopy(settled.entries)
                if pushes:
                    first = keyed[0][0]
                    for entry in saved:
                        if entry["id"] == first:
                            entry["last_push_started_at"] = now_iso
                if new_cursor:
                    updates["otx_last_pulse_modified"] = new_cursor
                if saved != stored_list:
                    updates[_RETRY_STATE_KEY] = saved
                if updates:
                    update_source_incremental("otx", **updates)
                if settled.given_up:
                    _log_given_up(settled.given_up)
                    _record_otx_retry_metrics(settled.entries, len(settled.given_up))
                if settled.added:
                    logger.warning(
                        "[OTX-RETRY] OTX: %d pulse(s) put on the retry list: the writer lists items of theirs as "
                        "unstored in batches MISP answered with an error; the cursor moves on, and the next runs "
                        "fetch them by id and push each in batches of its own (ids: %s)",
                        len(settled.added),
                        _pulse_ids_for_log(settled.added),
                    )
                return _WindowSettled(failing, whole, settled, saved, list_items, order, pushes, unsent_held)

            def _push_and_settle_the_list(window: _WindowSettled, window_failed: int) -> Tuple[int, int]:
                """Push the items of the pulses of the retry list (``window.items``) and settle the list; returns the
                push's counts.

                The push starts after the window's settlement, unless the window's push failed at the MISP event.
                Each pulse goes in batches of its own (``push_items``' ``batch_key``: ``_list_pulse``, so an item
                two pulses of the list name goes in the batches of the one first in ``_retry_order``), so a value
                MISP refuses fails only its own pulse, in ``_retry_order``, and no batch starts once
                EDGEGUARD_OTX_RETRY_MAX_SECONDS has passed since the push began (``push_items``' ``deadline``; its
                event lookup and listings count toward it). The pulses whose items were not all sent
                (``last_push_skipped_items``), or not pushed at all, keep their entries unchanged: no attempt, no
                ``last_tried_at``, first at the next run. 2026-11-03: so do the pulses whose items a push that stopped
                because MISP kept failing did not send (``last_push_unsent_items``, this push's or the window's).

                A pulse of the list the run pushed (fetched by id, or read again in the window) leaves the list when
                none of its items is listed and the items recorded as failed were pushed (recovered), and stays
                otherwise (``attempts`` + 1, ``last_tried_at`` the run's start); after an unknown failure it stays.
                A failure at the event leaves the entries as they were and gives up no pulse by age: it says
                nothing about the pulses. A pulse first failed more than ``EDGEGUARD_OTX_RETRY_MAX_DAYS`` ago and
                pushed since that deadline is given up with an ERROR (``[OTX-RETRY-GAVE-UP]``) and counted in
                ``edgeguard_otx_retry_given_up_total``, as the pulses beyond ``EDGEGUARD_OTX_RETRY_MAX_PULSES`` were
                after the window's push; a pulse no run pushed since its deadline (the limit deferred it, the run's
                fetches stopped first, its fetch failed, the time budget ran out, or its push raised) is not given
                up by age. The list is written again when it differs from the list written after the window's
                push, which it does whenever ``last_push_started_at`` was written there.
                """
                now_iso = _utc_iso(run_started)
                success = failed = 0
                list_items = window.items
                pushes = window.pushes
                skipped: Any = []
                unsent: Any = []
                failing_retries: Optional[Dict[str, List[str]]] = {}
                whole_retries = False
                if pushes:
                    budget = otx_retry_max_seconds()
                    started = time.monotonic()
                    success, failed = self.misp_writer.push_items(
                        list_items, batch_key=lambda item: _list_pulse(item, window.order), deadline=started + budget
                    )
                    spent = time.monotonic() - started
                    skipped = getattr(self.misp_writer, "last_push_skipped_items", None) or []
                    # 2026-11-03: the items a push that stopped because MISP kept failing did not send.
                    if failed > 0 and getattr(self.misp_writer, "last_push_stopped", False) is True:
                        unsent = getattr(self.misp_writer, "last_push_unsent_items", None) or []
                    failing_retries, whole_retries = _outcome(list_items, failed)
                    if success > 0:
                        logger.info(f"[OK] OTX: Successfully pushed {success} items of the retry list to MISP")
                    if failed > 0:
                        logger.warning(f"[WARN] OTX: Failed to push {failed} items of the retry list to MISP")
                out_of_time = set(window.order) & _named_pulses(list_items, skipped) if pushes else set()
                stopped = set(window.order) & _named_pulses(list_items, unsent) if pushes else set()
                not_pushed = (
                    out_of_time | stopped
                    if pushes
                    else set(window.order) & _named_pulses(list_items, range(len(list_items)))
                )
                # 2026-11-03: a pulse of the list that an item the window's stopped push did not send names keeps
                # its entry too.
                not_pushed |= window.held & listed_ids
                if pushes and out_of_time:
                    logger.warning(
                        "[OTX-RETRY] OTX: the push of the retry list's pulses reached its time budget "
                        "(EDGEGUARD_OTX_RETRY_MAX_SECONDS=%d) after %.0f s: %d pulse(s) were not pushed; they keep "
                        "their entries and are pushed first by the next run (ids: %s)",
                        budget,
                        spent,
                        len(out_of_time),
                        _pulse_ids_for_log(sorted(out_of_time)),
                    )
                if pushes and stopped:
                    logger.warning(
                        "[OTX-RETRY] OTX: the push of the retry list's pulses stopped because MISP kept failing "
                        "([MISP-PUSH-STOPPED]) after %.0f s: %d pulse(s) were not pushed; they keep their entries and "
                        "are pushed first by the next run (ids: %s)",
                        spent,
                        len(stopped),
                        _pulse_ids_for_log(sorted(stopped)),
                    )
                if whole_retries:
                    logger.warning(
                        "[OTX-RETRY] OTX: every unstored item of the push of the retry list's pulses failed at its "
                        "MISP event (MISP unreachable, or the lookup or creation of the day's event failing): the "
                        "pulses keep their entries"
                    )
                failing = _merged_failing(window.failing, failing_retries)
                if failing is None:
                    reason = (
                        f"the MISP push of the run started {now_iso} failed {window_failed + failed} item(s) "
                        "without naming them"
                    )
                else:
                    reason = (
                        f"MISP push of the run started {now_iso}: {window_failed} of {len(window_items)} item(s) of "
                        f"its window and {failed} of {len(list_items)} of the retry list failed"
                    )
                pushed_listed = [
                    p
                    for p in [*to_process, *retried]
                    if (pid := str(p.get("id"))) in listed_ids and pid not in not_pushed
                ]
                settled = _settle_retry_list(
                    window.settled.entries,
                    pushed_listed,
                    failing,
                    pushed_refs,
                    add=False,
                    outage=window.whole or whole_retries,
                    reason=reason,
                    now=run_started,
                    max_days=otx_retry_max_days(),
                    max_pulses=otx_retry_max_pulses(),
                )
                if settled.entries != window.saved:
                    update_source_incremental("otx", **{_RETRY_STATE_KEY: copy.deepcopy(settled.entries)})

                if settled.recovered:
                    logger.info(
                        "[OTX-RETRY] OTX: %d pulse(s) recovered: none of their items is listed as unstored, and "
                        "they leave the retry list (ids: %s)",
                        len(settled.recovered),
                        _pulse_ids_for_log(settled.recovered),
                    )
                if settled.incomplete:
                    logger.warning(
                        "[OTX-RETRY] OTX: %d pulse(s) of the retry list read without items of theirs that failed "
                        "earlier (the pulse no longer lists them, or the answer by id lacks them); they stay on "
                        "the list (ids: %s)",
                        len(settled.incomplete),
                        _pulse_ids_for_log(settled.incomplete),
                    )
                _log_given_up(settled.given_up)
                _record_otx_retry_metrics(settled.entries, len(settled.given_up))
                # The pulses given up beyond the cap after the window's push were logged and counted then.
                gave_up = [*window.settled.given_up, *settled.given_up]
                added = window.settled.added
                pulse_counts.update(
                    retry_pending=len(settled.entries),
                    retry_added=len(added),
                    retry_fetched=len(retried),
                    retry_recovered=len(settled.recovered),
                    retry_given_up=len(gave_up),
                    retry_not_found=len(retry_not_found),
                    retry_fetch_failed=len(retry_fetch_failed),
                    retry_not_pushed=len(not_pushed),
                    held_unsent=len(window.held & window_ids),
                )
                if settled.entries or stored_retry or added or gave_up or retried or retry_not_found:
                    oldest = settled.entries[0]["first_failed_at"] if settled.entries else None
                    logger.log(
                        logging.WARNING if settled.entries else logging.INFO,
                        "[OTX-RETRY] OTX: %d pulse(s) on the retry list after the run%s; this run fetched %d by "
                        "id, recovered %d, added %d and gave up %d; %d answered HTTP 404, %d could not be fetched "
                        "or read, %d were not pushed (time budget, a stopped push, or a failure at the MISP event)",
                        len(settled.entries),
                        f" (the first failure of the longest waiting: {oldest})" if settled.entries else "",
                        len(retried),
                        len(settled.recovered),
                        len(added),
                        len(gave_up),
                        len(retry_not_found),
                        len(retry_fetch_failed),
                        len(not_pushed),
                    )
                return success, failed

            # Push to MISP if requested
            if push_to_misp:
                record_collection_success(self.source_name)
                success = failed = 0
                if window_items:
                    success, failed = self.misp_writer.push_items(window_items)
                    if success > 0:
                        logger.info(f"[OK] OTX: Successfully pushed {success} items to MISP")
                    if failed > 0:
                        logger.warning(f"[WARN] OTX: Failed to push {failed} items to MISP")

                # The cursor and the retry list after the pushes (``_after_window_push``, then
                # ``_push_and_settle_the_list``). The status below is unchanged: a push with failures fails the run
                # when it stored nothing or falls below EDGEGUARD_MISP_MIN_SUCCESS_RATE, whatever happens to the
                # cursor. Items the time budget left unsent count neither way; 2026-11-03: the items a push that
                # stopped because MISP kept failing did not send count as failed (``last_push_unsent_items``).
                window = _after_window_push(success, failed)
                if window is not None:
                    retry_success, retry_failed = _push_and_settle_the_list(window, failed)
                    success, failed = success + retry_success, failed + retry_failed

                self.circuit_breaker.record_success()
                st = status_after_misp_push("otx", len(unique), success, failed)
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                st["pulse_counts"] = pulse_counts
                return st
            else:
                record_collection_success(self.source_name)
                self.circuit_breaker.record_success()
                cursor = None if baseline else _cursor_after(to_process)
                if cursor:
                    update_source_incremental("otx", otx_last_pulse_modified=cursor)
                return unique

        # PR-N24 BLOCKER B3 (proactive audit 2026-04-22): on push_to_misp=False,
        # the docstring says "return list of processed items" — but pre-N24
        # all 4 exception handlers returned a status DICT regardless,
        # which the alert-preview / test-harness / baseline-drain caller
        # could not distinguish from a successful empty-list result.
        # Same shape as the PR-N17 NVD bug + PR-N23 CISA fix. Mirroring
        # CISA's resolution (cisa_collector.py:312-355): when
        # push_to_misp=True still return status dict (Airflow contract);
        # when False, re-raise so the caller sees the actual error.
        except requests.exceptions.Timeout as e:
            error_msg = f"Timeout: {e}"
            logger.error(f"OTX timeout: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {e}"
            logger.error(f"OTX connection error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except requests.exceptions.HTTPError as e:
            if push_to_misp and is_auth_or_access_denied(e):
                logger.warning(f"OTX: auth/access denied — skipping (optional): {e}")
                self.circuit_breaker.record_success()
                record_collection_success(self.source_name)
                st = make_skipped_optional_source(
                    "otx",
                    skip_reason=str(e),
                    skip_reason_class="otx_auth_denied",
                )
                st["circuit_breaker_state"] = self.circuit_breaker.state.name
                return st
            error_msg = f"HTTP error: {e}"
            logger.error(f"OTX HTTP error: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            logger.error(f"OTX collection error: {type(e).__name__}: {e}")
            self.circuit_breaker.record_failure()
            record_collection_failure(self.source_name, error_msg)
            if push_to_misp:
                return self._return_status(False, 0, error_msg)
            raise

    def _return_status(self, success: bool, count: int, error: str = None, failed: int = 0) -> Dict[str, Any]:
        """Return standardized status dict."""
        result = make_status("otx", success, count=count, failed=failed, error=error)
        result["circuit_breaker_state"] = self.circuit_breaker.state.name
        return result

    def _log_baseline_coverage(self, baseline_days: int, max_pages: int, page_size: int) -> None:
        """Log how many pulses OTX reports for the baseline window and whether the page ceiling reads
        them all (2026-10): the coverage of a baseline is then stated, not inferred."""
        reported = getattr(self, "_otx_reported_total", None)
        if reported is None:
            return
        per_page = max(page_size, 1)
        readable = max_pages * per_page
        logger.info(
            "   OTX reports %d subscribed pulses modified in the last %d days; the page ceiling reads up to %d "
            "(EDGEGUARD_OTX_BASELINE_MAX_PAGES=%d, %d per page)",
            reported,
            baseline_days,
            readable,
            max_pages,
            per_page,
        )
        if reported > readable:
            logger.warning(
                "OTX baseline: the page ceiling stops %d pulses short of the window; set "
                "EDGEGUARD_OTX_BASELINE_MAX_PAGES to at least %d to read them all",
                reported - readable,
                -(-reported // per_page),
            )

    def map_indicator_type(self, ind_type: str, value: str = None) -> str:
        """Map OTX indicator types to standard EdgeGuard types"""
        mapping = {
            "IPv4": "ipv4",
            "IPv6": "ipv6",
            "domain": "domain",
            "URL": "url",
            "MD5": "hash",
            "SHA1": "hash",
            "SHA256": "hash",
            "SHA384": "hash",
            "SHA512": "hash",
            "EMAIL": "email",
            "FILE_HASH_MD5": "hash",
            "FILE_HASH_SHA1": "hash",
            "FILE_HASH_SHA256": "hash",
            "FileHash-SHA256": "hash",
            "FileHash-MD5": "hash",
            "FileHash-SHA1": "hash",
            "Email": "email",
            "email": "email",
            "CVE": "cve",
        }

        # Check type mapping first
        result = mapping.get(ind_type)
        if result:
            return result

        # Fallback: analyze the value itself
        if value:
            val_lower = value.lower()

            # IP address pattern (IPv4) - STRICT check
            parts = value.split(".")
            if len(parts) == 4:
                try:
                    if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                        return "ipv4"
                except (ValueError, TypeError):
                    pass

            # Email before domain: "user@host.tld" also contains a dot, and typed as a domain MISP
            # rejects it ("Domain has an invalid format") while answering a batch push with 200.
            if "@" in value and "." in value.split("@")[-1]:
                return "email"

            # Domain patterns
            if "." in val_lower and not val_lower.startswith("http"):
                if not val_lower.isdigit() and len(value) > 4:
                    excluded = ["cve-", "md5", "sha1", "sha256"]
                    if not any(val_lower.startswith(ex) for ex in excluded):
                        return "domain"

            # Email pattern
            if "@" in value and "." in value:
                return "email"
            # Hash patterns
            if len(value) in [32, 40, 64, 128] and all(c in "0123456789abcdefABCDEF" for c in value):
                return "hash"
            # CVE pattern
            if val_lower.startswith("cve-"):
                return "cve"
            # URL pattern
            if val_lower.startswith(("http://", "https://")):
                return "url"

        return "unknown"


def test_otx() -> Dict[str, Any]:
    """Test OTX collection and MISP push"""
    collector = OTXCollector()
    result = collector.collect(limit=500)  # OTX: 30 req/min, safe to fetch 500
    print("\n📥 OTX Test Result:")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    test_otx()
