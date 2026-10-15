#!/usr/bin/env python3
"""Build EdgeGuard's canonical threat-actor reference (``src/reference/canonical_threat_actors.json``).

The same actor reaches the graph under several names (``lazarus`` from one feed, ``lazarus group``
from ATT&CK), which splits its evidence across duplicate ``ThreatActor`` nodes. This script turns
the MISP galaxy threat-actor clusters into a reviewed dictionary of canonical actors and their
synonyms. It does not touch the graph: the alias-merge job reads the reference in a later step.

Inputs
------
``--galaxy``     the threat-actor entities export of the MISP galaxies
                 (``galaxy_threat_actors_<date>.json``: one record per galaxy cluster of the
                 threat-actor, mitre-intrusion-set, microsoft-activity-group, 360net-threat-actor and
                 mitre-ics-groups galaxies, with ``name``, ``aliases``, ``external_ids.mitre_attack``
                 and ``provenance``).
``--overrides``  hand-reviewed decisions (``src/reference/canonical_threat_actor_overrides.json``):
                 ``merge`` (names into a canonical key), ``never_merge`` (names) and
                 ``canonical_name`` (display names). Applied last, so a rebuild keeps them.

Grouping rules (a wrong merge is worse than a missed one)
---------------------------------------------------------
Keys are normalised like ``node_identity.canonicalize_merge_key`` normalises a ``ThreatActor``
name on write: NFC, trimmed, lower-case. The ``name_key`` of the input is not used (it is NFKC).

1. Anchor by ATT&CK id. All records with the same ``mitre_attack`` id are one actor whose
   canonical name and key are the ATT&CK group name (the mitre-intrusion-set value without its
   `` - G0032`` suffix), i.e. the name EdgeGuard writes for that group. A record whose own name is
   the ATT&CK name of a *different* group (the galaxy names several ATT&CK ids for it and the
   export kept the first) is not anchored by that id; it goes through rule 2 instead.
2. A record without an ATT&CK id joins an anchored actor only when its name equals that actor's
   key, one of its ATT&CK aliases, or the name of a record anchored to it (rule 1), and that name
   belongs to exactly one anchored actor (an actor key outranks another actor's alias). Names that
   differ only in spaces, hyphens, dots or underscores are the same name ("SaintBear" is ATT&CK's
   "Saint Bear"); the exact name is tried first. A 360net-threat-actor name is also tried without
   its `` - APT-C-NN`` id ("Darkhotel - APT-C-06"). Otherwise records with the same name form an
   actor of their own, named after the threat-actor galaxy value, else the
   microsoft-activity-group, the 360net-threat-actor or the mitre-ics-groups value.
3. Synonyms are the names the records give for their actor (aliases, and the names of joined
   records). They never merge two actors.
4. A synonym claimed by more than one actor goes to the actor whose own name it is: an actor key
   always stays with its actor; otherwise an ATT&CK alias or a record's own name outranks a
   galaxy synonym. If no single actor holds the strongest claim, the name is ambiguous and is
   never merged. ATT&CK group ids listed as synonyms are dropped (the id is ``mitre_attack``), and
   so are placeholder names (``node_identity.is_placeholder_name``). A synonym is taken as
   EdgeGuard's actor-name hygiene writes it (``actor_name_hygiene.clean_actor_names``: a trailing
   parenthetical is dropped); a list of names is not a synonym.
5. Suffix rule. For every actor key and ATT&CK alias, the variant with a trailing `` group`` /
   `` team`` removed (or added, when the name has neither) becomes a synonym when no actor claims
   it yet; a variant two actors would get is ambiguous. A shortened name keeps at least three
   characters and a letter, and nothing is added to a name that already has the word ``group`` or
   ``team`` in it. Shortened names can be common words; the report lists them for review.
6. Overrides are applied last: ``merge`` (a name into a canonical key; creates the actor when no
   actor has that key, folds an actor without an ATT&CK id whose key is the name, never folds an
   ATT&CK group), ``never_merge`` (takes a name out of every actor and lists it as ambiguous) and
   ``canonical_name`` (sets the display name; a name with another key re-keys an actor without an
   ATT&CK id and keeps the old key as a synonym).

The output is deterministic: the same inputs and ``--version`` give a byte-identical file.
``--version`` defaults to the build date (CalVer ``YYYY.MM.DD``); ``generated_at`` is that date.

Report
------
The build prints the counts, the rule effects and every override decision. With
``--graph-actors`` (an export made by ``--export-graph-actors``) it also checks the canonical keys
against the names EdgeGuard wrote for the ATT&CK groups, and reports how the graph's actor names
resolve: how many resolve, the duplicate groups the merge job would fold, and the unresolved
names by relationship count (the first 50 in the report; ``--unresolved-out`` writes all).

``--export-graph-actors PATH`` reads every ``ThreatActor`` node's name, aliases, sources,
relationship count and pulse count over the Neo4j HTTP Query API v2 in read mode (same
settings as ``scripts/verify_fresh_baseline.py``: ``NEO4J_HTTP_URL`` or ``NEO4J_HTTP``,
``NEO4J_DATABASE``, ``NEO4J_USER``, ``NEO4J_PASSWORD``). Graph-derived files must be written
outside the repository; the script refuses a path inside it.

Usage::

    python scripts/build_canonical_threat_actors.py --export-graph-actors /tmp/graph_actors.json
    python scripts/build_canonical_threat_actors.py --galaxy galaxy_threat_actors_20261013.json \\
        --graph-actors /tmp/graph_actors.json --unresolved-out /tmp/unresolved_actors.json

Exit code 0 = built (or exported); 1 = invalid input or override; 2 = Neo4j unreachable.
"""

from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from actor_name_hygiene import clean_actor_names  # noqa: E402
from node_identity import canonicalize_merge_key, is_placeholder_name  # noqa: E402

DEFAULT_OUT = _SRC / "reference" / "canonical_threat_actors.json"
DEFAULT_OVERRIDES = _SRC / "reference" / "canonical_threat_actor_overrides.json"

SCHEMA_VERSION = 1
MITRE_GALAXY = "mitre-intrusion-set"
# Display-name preference for an actor without an ATT&CK id (rule 2), then any other galaxy.
GALAXY_NAME_PRIORITY: Tuple[str, ...] = (
    "threat-actor",
    "microsoft-activity-group",
    "360net-threat-actor",
    "mitre-ics-groups",
    MITRE_GALAXY,
)
ORIGIN_MITRE = "mitre"
ORIGIN_SUFFIX = "suffix_rule"
ORIGIN_OVERRIDE = "override"
GALAXY_ORIGIN_PREFIX = "misp_galaxy:"
NAME_SUFFIXES: Tuple[str, ...] = (" group", " team")
OVERRIDE_STATUSES = frozenset({"proposed", "accepted"})

# Claim strength (rule 4): lower wins. An actor key always wins and is not a claim.
TIER_OWN_NAME = 1  # an ATT&CK alias, or the name of a record that belongs to the actor
TIER_SYNONYM = 2  # an alias a galaxy record gives

_ATTACK_NAME_SUFFIX_RE = re.compile(r"\s+-\s+G\d{4}\s*$")
# The 360net-threat-actor galaxy appends its own group id to every name ("Darkhotel - APT-C-06").
# Rule 2 also tries the name without it; the full value stays the record's name.
_THREE_SIXTY_GALAXY = "360net-threat-actor"
_THREE_SIXTY_ID_SUFFIX_RE = re.compile(r"\s+-\s+APT-C-\d+\s*$", re.IGNORECASE)
_ATTACK_GROUP_ID_RE = re.compile(r"^G\d{4}$")
_GROUP_OR_TEAM_WORD_RE = re.compile(r"\b(?:group|team)\b")
_SEPARATORS_RE = re.compile(r"[\s\-_.]+")
_ATTACK_ID_KEY_RE = re.compile(r"^g\d{4}$")
_VERSION_RE = re.compile(r"^(\d{4})\.(\d{2})\.(\d{2})$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

DESCRIPTION = (
    "Canonical threat actors for EdgeGuard: one entry per actor with its canonical key (the "
    "ThreatActor name EdgeGuard writes, normalised like node_identity.canonicalize_merge_key), its "
    "ATT&CK group id and the synonyms that name it. Built from the MISP galaxy threat-actor "
    "clusters by scripts/build_canonical_threat_actors.py, with the hand-reviewed decisions of "
    "canonical_threat_actor_overrides.json applied last. Names listed under 'ambiguous' point to "
    "more than one actor, or were marked never_merge, and are never merged."
)
RULES: Tuple[str, ...] = (
    "Records with the same ATT&CK id are one actor named after the ATT&CK group; a record whose own "
    "name is the ATT&CK name of a different group is not anchored by its id.",
    "A record without an ATT&CK id joins an anchored actor only when its name (for the "
    "360net-threat-actor galaxy also the name without its ' - APT-C-NN' id) is that actor's key, an "
    "ATT&CK alias of it or the name of a record anchored to it, for exactly one actor; names that "
    "differ only in spaces, hyphens, dots or underscores are the same name. Otherwise records with "
    "the same name form an actor of their own.",
    "Synonyms never merge two actors.",
    "A name claimed by several actors goes to the actor whose own name it is (actor key, then ATT&CK "
    "alias or record name, then galaxy synonym); a tie makes it ambiguous. ATT&CK ids, placeholder "
    "names and lists of names are not synonyms; a synonym is taken as EdgeGuard's actor-name hygiene "
    "writes it.",
    "Suffix rule: the variant with or without a trailing ' group' / ' team' of an actor key or "
    "ATT&CK alias is a synonym when no other actor claims it (a shortened name keeps at least three "
    "characters and a letter; nothing is added to a name that already contains 'group' or 'team').",
    "Overrides are applied last: merge, then never_merge, then canonical_name.",
)
ATTRIBUTION: Tuple[Dict[str, str], ...] = (
    {
        "source": "MISP galaxy (threat-actor, mitre-intrusion-set, microsoft-activity-group, "
        "360net-threat-actor and mitre-ics-groups galaxies)",
        "licence": "CC0-1.0",
        "url": "https://github.com/MISP/misp-galaxy",
    },
    {
        "source": "MITRE ATT&CK (group names, ids and aliases, as carried by the mitre-intrusion-set galaxy)",
        "notice": "© The MITRE Corporation. This work is reproduced and distributed with the "
        "permission of The MITRE Corporation.",
        "url": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
    },
)


class ReferenceInputError(ValueError):
    """Invalid galaxy input or override decision (exit code 1)."""


# --------------------------------------------------------------------------- names


def actor_key(name: Any) -> str:
    """The key EdgeGuard writes for a ``ThreatActor`` called ``name`` (NFC, trimmed, lower-case);
    ``""`` for a non-string."""
    if not isinstance(name, str):
        return ""
    value = canonicalize_merge_key("ThreatActor", {"name": name}).get("name")
    return value if isinstance(value, str) else ""


def strip_attack_suffix(name: str) -> str:
    """``"Lazarus Group - G0032"`` -> ``"Lazarus Group"`` (the mitre-intrusion-set galaxy value)."""
    return _ATTACK_NAME_SUFFIX_RE.sub("", name).strip()


def suffix_variants(key: str) -> List[str]:
    """Rule 5: ``"sandworm team"`` -> ``["sandworm"]``; ``"turla"`` -> ``["turla group", "turla team"]``.

    A shortened name must keep at least three characters and a letter (``"313 team"`` gives
    nothing); a name that already has the word ``group`` / ``team`` in it (``"threat
    group-3390"``, ``"group 72"``) gets no suffix added."""
    for suffix in NAME_SUFFIXES:
        if key.endswith(suffix):
            base = key[: -len(suffix)].strip()
            if len(base) >= 3 and any(ch.isalpha() for ch in base) and not is_placeholder_name(base):
                return [base]
            return []
    if _GROUP_OR_TEAM_WORD_RE.search(key):
        return []
    return [key + suffix for suffix in NAME_SUFFIXES]


def compact_key(key: str) -> str:
    """``key`` without spaces, hyphens, dots and underscores. Rule 2 matches names by it as well:
    ``"white bear"``, ``"whitebear"`` and ``"white-bear"`` are one name."""
    return _SEPARATORS_RE.sub("", key)


def _usable(key: str) -> bool:
    return bool(key) and not is_placeholder_name(key)


def _galaxy_origin(galaxy: str) -> str:
    return ORIGIN_MITRE if galaxy == MITRE_GALAXY else GALAXY_ORIGIN_PREFIX + galaxy


def _galaxy_rank(galaxy: str) -> int:
    return GALAXY_NAME_PRIORITY.index(galaxy) if galaxy in GALAXY_NAME_PRIORITY else len(GALAXY_NAME_PRIORITY)


# --------------------------------------------------------------------------- input


@dataclass(frozen=True)
class GalaxyRecord:
    galaxy: str
    source_record: str
    name: str
    key: str
    mitre_attack: Optional[str]
    aliases: Tuple[Tuple[str, str], ...]  # (display name, key), usable keys only, in input order

    @property
    def origin(self) -> str:
        return _galaxy_origin(self.galaxy)

    @property
    def join_keys(self) -> Tuple[str, ...]:
        """Keys rule 2 matches: the record's key and, for a 360net-threat-actor record, its key
        without the ``" - APT-C-NN"`` group id."""
        if self.galaxy == _THREE_SIXTY_GALAXY:
            head = actor_key(_THREE_SIXTY_ID_SUFFIX_RE.sub("", self.name))
            if _usable(head) and head != self.key:
                return (self.key, head)
        return (self.key,)


@dataclass
class BuildStats:
    """What each rule did; printed by the report."""

    records_by_galaxy: Dict[str, int] = field(default_factory=dict)
    skipped_records: List[str] = field(default_factory=list)
    attack_groups: int = 0
    attack_ids_without_mitre_record: List[str] = field(default_factory=list)
    anchor_conflicts: List[Dict[str, str]] = field(default_factory=list)
    joined: Dict[str, int] = field(default_factory=dict)
    joined_by_spacing: List[Dict[str, str]] = field(default_factory=list)
    join_ambiguous: List[Dict[str, Any]] = field(default_factory=list)
    standalone_actors: int = 0
    dropped_placeholder_names: int = 0
    dropped_attack_id_synonyms: int = 0
    dropped_attack_id_synonyms_of_other_groups: List[Dict[str, str]] = field(default_factory=list)
    synonyms_rewritten_by_name_hygiene: List[Dict[str, str]] = field(default_factory=list)
    synonyms_dropped_by_name_hygiene: List[Dict[str, str]] = field(default_factory=list)
    actor_keys_claimed_elsewhere: int = 0
    contested_resolved: List[Dict[str, Any]] = field(default_factory=list)
    suffix_added: int = 0
    suffix_also_existing: int = 0
    suffix_blocked: int = 0
    suffix_ambiguous: List[str] = field(default_factory=list)
    suffix_shortened: List[Dict[str, str]] = field(default_factory=list)
    overrides: List[Dict[str, Any]] = field(default_factory=list)


def _record_from_input(raw: Mapping[str, Any], stats: BuildStats) -> Optional[GalaxyRecord]:
    provenance = raw.get("provenance") or {}
    source_record = str(provenance.get("source_record") or raw.get("id") or "")
    galaxy = source_record.split("/", 1)[0] if "/" in source_record else ""
    raw_name = raw.get("name")
    if not galaxy or not isinstance(raw_name, str):
        stats.skipped_records.append(source_record or repr(raw.get("id")))
        return None
    name = strip_attack_suffix(raw_name)
    key = actor_key(name)
    external_ids = raw.get("external_ids") or {}
    attack_id = external_ids.get("mitre_attack")
    if attack_id is not None:
        attack_id = str(attack_id).strip().upper()
        if not _ATTACK_GROUP_ID_RE.match(attack_id):
            raise ReferenceInputError(f"{source_record}: malformed mitre_attack id {attack_id!r}")
    if not _usable(key):
        stats.skipped_records.append(source_record)
        stats.dropped_placeholder_names += 1
        return None
    aliases: List[Tuple[str, str]] = []
    for alias in raw.get("aliases") or []:
        alias_name = alias.get("name") if isinstance(alias, Mapping) else alias
        if not isinstance(alias_name, str) or not actor_key(alias_name):
            continue
        if is_placeholder_name(alias_name):
            stats.dropped_placeholder_names += 1
            continue
        # A synonym is the name EdgeGuard would write for it: its actor-name hygiene drops a trailing
        # parenthetical ("xHunt campaign (<source>)" -> "xHunt campaign") and splits lists. A list
        # or a description never reaches the graph as one name, so it is not a synonym.
        cleaned = clean_actor_names(alias_name)
        if len(cleaned) != 1:
            stats.synonyms_dropped_by_name_hygiene.append(
                {"record": source_record, "synonym": alias_name, "why": "list" if cleaned else "not a name"}
            )
            continue
        alias_key = actor_key(cleaned[0])
        if alias_key != actor_key(alias_name):
            stats.synonyms_rewritten_by_name_hygiene.append(
                {"record": source_record, "synonym": alias_name, "written_as": alias_key}
            )
        alias_name = cleaned[0]
        if _ATTACK_ID_KEY_RE.match(alias_key):
            stats.dropped_attack_id_synonyms += 1
            if alias_key.upper() != attack_id:
                stats.dropped_attack_id_synonyms_of_other_groups.append(
                    {"record": source_record, "name": name, "mitre_attack": attack_id or "", "synonym": alias_name}
                )
            continue
        aliases.append((alias_name, alias_key))
    return GalaxyRecord(galaxy, source_record, name, key, attack_id, tuple(aliases))


def load_galaxy_records(doc: Mapping[str, Any], stats: BuildStats) -> List[GalaxyRecord]:
    raw_records = doc.get("records")
    if not isinstance(raw_records, list) or not raw_records:
        raise ReferenceInputError("galaxy input has no 'records' list")
    records: List[GalaxyRecord] = []
    seen: Set[str] = set()
    for raw in raw_records:
        if not isinstance(raw, Mapping):
            raise ReferenceInputError("galaxy input: every record must be an object")
        record = _record_from_input(raw, stats)
        if record is None:
            continue
        if record.source_record in seen:
            raise ReferenceInputError(f"galaxy input: duplicate record {record.source_record}")
        seen.add(record.source_record)
        records.append(record)
        stats.records_by_galaxy[record.galaxy] = stats.records_by_galaxy.get(record.galaxy, 0) + 1
    records.sort(key=lambda r: (r.source_record, r.key))
    return records


def galaxy_input_metadata(doc: Mapping[str, Any], file_name: str, sha256: str) -> Dict[str, Any]:
    """The ``inputs`` entry of the galaxy export: its own version fields and, per galaxy, the
    galaxy/cluster version and the raw dump it was built from."""
    galaxies: Dict[str, Dict[str, Any]] = {}
    for raw in doc.get("records") or []:
        provenance = raw.get("provenance") or {}
        galaxy = str(provenance.get("source_record") or "").split("/", 1)[0]
        if not galaxy:
            continue
        entry = galaxies.setdefault(galaxy, {"galaxy": galaxy, "versions": set(), "raw_files": set(), "records": 0})
        entry["records"] += 1
        if provenance.get("source_version"):
            entry["versions"].add(str(provenance["source_version"]))
        if provenance.get("raw_file") or provenance.get("raw_sha256"):
            entry["raw_files"].add(
                (Path(str(provenance.get("raw_file") or "")).name, str(provenance.get("raw_sha256") or ""))
            )
    notes = doc.get("notes") or {}
    return {
        "role": "galaxy",
        "file": file_name,
        "sha256": sha256,
        "dataset": doc.get("dataset"),
        "schema_version": doc.get("schema_version"),
        "generated_at": doc.get("generated_at"),
        "record_count": doc.get("record_count"),
        "misp_version": notes.get("misp_version"),
        "galaxies": [
            {
                "galaxy": g["galaxy"],
                "version": "; ".join(sorted(g["versions"])) or None,
                "records": g["records"],
                "raw_files": [{"file": f, "sha256": h} for f, h in sorted(g["raw_files"])],
            }
            for g in sorted(galaxies.values(), key=lambda g: (_galaxy_rank(g["galaxy"]), g["galaxy"]))
        ],
    }


# --------------------------------------------------------------------------- overrides


@dataclass(frozen=True)
class OverrideDecision:
    kind: str  # "merge" | "never_merge" | "canonical_name"
    names: Tuple[str, ...]  # merge / never_merge: the names as written
    into: str  # merge: target key; canonical_name: the actor key
    display_name: str  # canonical_name: the display name
    reason: str
    date: str
    status: str

    def as_record(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"decision": self.kind}
        if self.kind == "merge":
            out.update({"names": list(self.names), "into": self.into})
        elif self.kind == "never_merge":
            out["names"] = list(self.names)
        else:
            out.update({"key": self.into, "name": self.display_name})
        out.update({"reason": self.reason, "date": self.date, "status": self.status})
        return out


def _check_common(entry: Mapping[str, Any], where: str) -> Tuple[str, str, str]:
    reason = entry.get("reason")
    date = entry.get("date")
    status = entry.get("status")
    if not isinstance(reason, str) or not reason.strip():
        raise ReferenceInputError(f"{where}: 'reason' is required")
    if not isinstance(date, str) or not _DATE_RE.match(date):
        raise ReferenceInputError(f"{where}: 'date' must be YYYY-MM-DD")
    try:
        _dt.date.fromisoformat(date)
    except ValueError as exc:
        raise ReferenceInputError(f"{where}: invalid date {date!r}") from exc
    if status not in OVERRIDE_STATUSES:
        raise ReferenceInputError(f"{where}: 'status' must be one of {sorted(OVERRIDE_STATUSES)}")
    return reason.strip(), date, str(status)


def _names(entry: Mapping[str, Any], where: str) -> Tuple[str, ...]:
    names = entry.get("names")
    if not isinstance(names, list) or not names:
        raise ReferenceInputError(f"{where}: 'names' must be a non-empty list")
    out: List[str] = []
    for name in names:
        if not _usable(actor_key(name)):
            raise ReferenceInputError(f"{where}: unusable name {name!r}")
        out.append(str(name))
    return tuple(out)


def load_overrides(doc: Mapping[str, Any]) -> List[OverrideDecision]:
    """Validate the overrides document and return its decisions in file order."""
    unknown = set(doc) - {"schema_version", "description", "merge", "never_merge", "canonical_name"}
    if unknown:
        raise ReferenceInputError(f"overrides: unknown sections {sorted(unknown)}")
    decisions: List[OverrideDecision] = []
    for i, entry in enumerate(doc.get("merge") or []):
        where = f"overrides merge[{i}]"
        reason, date, status = _check_common(entry, where)
        into = actor_key(entry.get("into"))
        if not _usable(into):
            raise ReferenceInputError(f"{where}: 'into' must name the canonical key")
        decisions.append(OverrideDecision("merge", _names(entry, where), into, "", reason, date, status))
    for i, entry in enumerate(doc.get("never_merge") or []):
        where = f"overrides never_merge[{i}]"
        reason, date, status = _check_common(entry, where)
        decisions.append(OverrideDecision("never_merge", _names(entry, where), "", "", reason, date, status))
    for i, entry in enumerate(doc.get("canonical_name") or []):
        where = f"overrides canonical_name[{i}]"
        reason, date, status = _check_common(entry, where)
        key = actor_key(entry.get("key"))
        display = entry.get("name")
        if not _usable(key) or not isinstance(display, str) or not _usable(actor_key(display)):
            raise ReferenceInputError(f"{where}: 'key' and 'name' are required")
        decisions.append(OverrideDecision("canonical_name", (), key, display.strip(), reason, date, status))

    merged_into: Dict[str, str] = {}
    never: Set[str] = set()
    for d in decisions:
        for name in d.names:
            k = actor_key(name)
            if d.kind == "merge":
                if merged_into.get(k, d.into) != d.into:
                    raise ReferenceInputError(f"overrides: {name!r} is merged into two actors")
                merged_into[k] = d.into
            elif d.kind == "never_merge":
                never.add(k)
    both = sorted(never & (set(merged_into) | set(merged_into.values())))
    if both:
        raise ReferenceInputError(f"overrides: {both} are both merged and never_merge")
    chained = sorted(k for k, target in merged_into.items() if target in merged_into and merged_into[target] != target)
    if chained:
        raise ReferenceInputError(f"overrides: merge targets that are themselves merged elsewhere: {chained}")
    return decisions


# --------------------------------------------------------------------------- build


@dataclass
class _Actor:
    key: str
    name: str
    mitre_attack: Optional[str]
    records: List[GalaxyRecord] = field(default_factory=list)
    origins: Set[str] = field(default_factory=set)
    synonyms: Dict[str, Set[str]] = field(default_factory=dict)  # key -> origins
    mitre_aliases: Set[str] = field(default_factory=set)


class _Claims:
    """Synonym key -> actor key -> (strongest tier, origins)."""

    def __init__(self) -> None:
        self._by_key: Dict[str, Dict[str, Tuple[int, Set[str]]]] = defaultdict(dict)

    def add(self, synonym: str, actor: str, tier: int, origin: str) -> None:
        current = self._by_key[synonym].get(actor)
        if current is None:
            self._by_key[synonym][actor] = (tier, {origin})
        else:
            current[1].add(origin)
            self._by_key[synonym][actor] = (min(current[0], tier), current[1])

    def items(self) -> Iterable[Tuple[str, Dict[str, Tuple[int, Set[str]]]]]:
        return sorted(self._by_key.items())


def _anchored_actors(
    records: Sequence[GalaxyRecord], stats: BuildStats
) -> Tuple[Dict[str, _Actor], List[GalaxyRecord]]:
    """Rule 1. Returns the ATT&CK actors by id and the records left for rule 2."""
    by_id: Dict[str, List[GalaxyRecord]] = defaultdict(list)
    for r in records:
        if r.mitre_attack:
            by_id[r.mitre_attack].append(r)

    actors: Dict[str, _Actor] = {}
    for attack_id in sorted(by_id):
        members = sorted(by_id[attack_id], key=lambda r: (_galaxy_rank(r.galaxy), r.name, r.source_record))
        mitre_records = [r for r in members if r.galaxy == MITRE_GALAXY]
        if mitre_records:
            head = mitre_records[0]
        else:
            head = members[0]
            stats.attack_ids_without_mitre_record.append(attack_id)
        actors[attack_id] = _Actor(key=head.key, name=head.name, mitre_attack=attack_id)
    stats.attack_groups = len(actors)

    key_owner: Dict[str, str] = {}
    for attack_id, actor in actors.items():
        if actor.key in key_owner:
            raise ReferenceInputError(
                f"ATT&CK groups {key_owner[actor.key]} and {attack_id} share the canonical key {actor.key!r}"
            )
        key_owner[actor.key] = attack_id

    leftover: List[GalaxyRecord] = []
    for r in records:
        if not r.mitre_attack:
            leftover.append(r)
            continue
        other = key_owner.get(r.key)
        if other is not None and other != r.mitre_attack:
            stats.anchor_conflicts.append(
                {
                    "record": r.source_record,
                    "name": r.name,
                    "mitre_attack": r.mitre_attack,
                    "attack_name_of": other,
                }
            )
            leftover.append(r)
            continue
        actors[r.mitre_attack].records.append(r)
    for actor in actors.values():
        for r in actor.records:
            if r.galaxy == MITRE_GALAXY:
                actor.mitre_aliases.update(k for _, k in r.aliases)
    return actors, leftover


def _join_or_standalone(
    anchored: Dict[str, _Actor], leftover: Sequence[GalaxyRecord], stats: BuildStats
) -> Dict[str, _Actor]:
    """Rule 2. Adds joined records to their ATT&CK actor; returns the standalone actors by key.

    A name is matched as it is first and then by its compact form (``compact_key``), so
    ``"SaintBear"`` joins ATT&CK's ``"Saint Bear"``."""
    exact: Dict[str, Dict[str, str]] = defaultdict(dict)  # name key -> attack id -> how
    for attack_id, actor in anchored.items():
        for alias in actor.mitre_aliases:
            exact[alias].setdefault(attack_id, "attack_alias")
        for r in actor.records:
            exact[r.key].setdefault(attack_id, "record_name")
        exact[actor.key][attack_id] = "key"
    compact: Dict[str, Dict[str, str]] = defaultdict(dict)
    for name_key in sorted(exact):
        for attack_id, how in exact[name_key].items():
            if compact[compact_key(name_key)].get(attack_id) != "key":
                compact[compact_key(name_key)][attack_id] = how

    joined: Dict[str, int] = defaultdict(int)
    standalone_records: Dict[str, List[GalaxyRecord]] = defaultdict(list)
    for r in leftover:
        hits: Dict[str, str] = {}
        spacing = False
        for join_key in r.join_keys:
            hits = exact.get(join_key, {})
            if hits:
                break
        else:
            for join_key in r.join_keys:
                hits = compact.get(compact_key(join_key), {})
                if hits:
                    spacing = True
                    break
        # An actor key outranks an alias or record name of another actor (rule 4): "unc2452" is
        # ATT&CK group G0118 even though APT29 (G0016) lists it as an alias.
        by_key = [a for a, how in hits.items() if how == "key"]
        if by_key:
            hits = {by_key[0]: "key"}
        if len(hits) == 1:
            (attack_id, how), *_ = hits.items()
            anchored[attack_id].records.append(r)
            joined[how + (" (spacing)" if spacing else "")] += 1
            if spacing:
                stats.joined_by_spacing.append(
                    {"record": r.source_record, "name": r.name, "actor": anchored[attack_id].key}
                )
            continue
        if len(hits) > 1:
            stats.join_ambiguous.append(
                {"record": r.source_record, "name": r.name, "candidates": [anchored[a].key for a in sorted(hits)]}
            )
        standalone_records[compact_key(r.key)].append(r)
    stats.joined = dict(sorted(joined.items()))

    standalone: Dict[str, _Actor] = {}
    for name in sorted(standalone_records):
        members = sorted(standalone_records[name], key=lambda r: (_galaxy_rank(r.galaxy), r.name, r.source_record))
        head = members[0]
        standalone[head.key] = _Actor(key=head.key, name=head.name, mitre_attack=None, records=members)
    stats.standalone_actors = len(standalone)
    return standalone


def _collect_claims(actors: Mapping[str, _Actor]) -> _Claims:
    claims = _Claims()
    for actor in actors.values():
        for r in actor.records:
            actor.origins.add(r.origin)
            if r.key != actor.key:
                claims.add(r.key, actor.key, TIER_OWN_NAME, r.origin)
            for _, alias_key in r.aliases:
                if alias_key == actor.key:
                    continue
                tier = TIER_OWN_NAME if r.galaxy == MITRE_GALAXY and actor.mitre_attack else TIER_SYNONYM
                claims.add(alias_key, actor.key, tier, r.origin)
    return claims


def _resolve_claims(actors: Mapping[str, _Actor], claims: _Claims, stats: BuildStats) -> Dict[str, Dict[str, Set[str]]]:
    """Rule 4. Fills each actor's synonyms; returns the ambiguous names (key -> actor -> origins)."""
    ambiguous: Dict[str, Dict[str, Set[str]]] = {}
    for synonym, by_actor in claims.items():
        if synonym in actors:
            stats.actor_keys_claimed_elsewhere += 1
            continue
        best = min(tier for tier, _ in by_actor.values())
        winners = sorted(a for a, (tier, _) in by_actor.items() if tier == best)
        if len(winners) == 1:
            winner = winners[0]
            actors[winner].synonyms[synonym] = set(by_actor[winner][1])
            if len(by_actor) > 1:
                stats.contested_resolved.append(
                    {"name": synonym, "actor": winner, "over": sorted(a for a in by_actor if a != winner)}
                )
        else:
            ambiguous[synonym] = {a: set(origins) for a, (_, origins) in by_actor.items()}
    return ambiguous


def _apply_suffix_rule(
    actors: Mapping[str, _Actor], ambiguous: Dict[str, Dict[str, Set[str]]], stats: BuildStats
) -> None:
    """Rule 5."""
    owner: Dict[str, str] = {}
    for actor in actors.values():
        owner[actor.key] = actor.key
        for synonym in actor.synonyms:
            owner[synonym] = actor.key
    proposals: Dict[str, Set[str]] = defaultdict(set)
    for key in sorted(actors):
        actor = actors[key]
        bases = [actor.key] + sorted(a for a in actor.mitre_aliases if a in actor.synonyms)
        for base in bases:
            for variant in suffix_variants(base):
                if variant == actor.key:
                    continue
                if owner.get(variant) == actor.key:
                    if ORIGIN_SUFFIX not in actor.synonyms[variant]:
                        actor.synonyms[variant].add(ORIGIN_SUFFIX)
                        stats.suffix_also_existing += 1
                    continue
                if variant in owner or variant in ambiguous:
                    stats.suffix_blocked += 1
                    continue
                proposals[variant].add(actor.key)
    for variant in sorted(proposals):
        proposers = sorted(proposals[variant])
        if len(proposers) == 1:
            actors[proposers[0]].synonyms[variant] = {ORIGIN_SUFFIX}
            stats.suffix_added += 1
            if not variant.endswith(NAME_SUFFIXES):
                # A shortened name can be a common word ("medusa"): listed for review.
                stats.suffix_shortened.append({"name": variant, "actor": proposers[0]})
        else:
            ambiguous[variant] = {p: {ORIGIN_SUFFIX} for p in proposers}
            stats.suffix_ambiguous.append(variant)


def _apply_overrides(
    actors: Dict[str, _Actor],
    ambiguous: Dict[str, Dict[str, Set[str]]],
    never_merge: Dict[str, Dict[str, Any]],
    decisions: Sequence[OverrideDecision],
    stats: BuildStats,
) -> None:
    """Rule 6: merges, then never_merge, then display names. Every decision is recorded with its effect."""

    def owner_of(key: str) -> Optional[str]:
        if key in actors:
            return key
        for actor in actors.values():
            if key in actor.synonyms:
                return actor.key
        return None

    for d in (d for d in decisions if d.kind == "merge"):
        effects: List[str] = []
        target_owner = owner_of(d.into)
        if target_owner is None:
            if d.into in ambiguous:
                raise ReferenceInputError(f"override merge into {d.into!r}: that name is ambiguous, not an actor")
            actors[d.into] = _Actor(key=d.into, name=d.into, mitre_attack=None, origins={ORIGIN_OVERRIDE})
            effects.append(f"created actor {d.into!r}")
        elif target_owner != d.into:
            raise ReferenceInputError(
                f"override merge into {d.into!r}: that name is a synonym of {target_owner!r}; name the actor key"
            )
        target = actors[d.into]
        for name in d.names:
            k = actor_key(name)
            if k == target.key:
                effects.append(f"{k!r} is the actor key")
                continue
            current = owner_of(k)
            if current == target.key:
                target.synonyms[k].add(ORIGIN_OVERRIDE)
                effects.append(f"{k!r} already a synonym ({', '.join(sorted(target.synonyms[k] - {ORIGIN_OVERRIDE}))})")
            elif current is not None and current == k:
                folded = actors[k]
                if folded.mitre_attack:
                    raise ReferenceInputError(
                        f"override merge: {k!r} is ATT&CK group {folded.mitre_attack}; ATT&CK groups are never merged"
                    )
                del actors[k]
                target.records.extend(folded.records)
                target.origins.update(folded.origins)
                for synonym, origins in folded.synonyms.items():
                    target.synonyms.setdefault(synonym, set()).update(origins)
                target.synonyms[k] = {ORIGIN_OVERRIDE}
                effects.append(f"folded actor {k!r} ({len(folded.synonyms)} synonyms) into {target.key!r}")
                # The folded actor's claims on ambiguous names are now the target's; a name that only
                # the two of them claimed belongs to the target.
                for name_key in sorted(ambiguous):
                    claimants = ambiguous[name_key]
                    if k not in claimants:
                        continue
                    claimants.setdefault(target.key, set()).update(claimants.pop(k))
                    if len(claimants) == 1:
                        target.synonyms[name_key] = ambiguous.pop(name_key)[target.key]
                        effects.append(f"resolved ambiguous {name_key!r} (claimed by {k!r} and {target.key!r} only)")
            elif current is not None:
                origins = actors[current].synonyms.pop(k)
                target.synonyms[k] = {ORIGIN_OVERRIDE}
                effects.append(f"moved {k!r} from {current!r} ({', '.join(sorted(origins))})")
            elif k in ambiguous:
                claimant_keys = sorted(ambiguous.pop(k))
                target.synonyms[k] = {ORIGIN_OVERRIDE}
                effects.append(f"resolved ambiguous {k!r} (claimed by {', '.join(claimant_keys)})")
            else:
                target.synonyms[k] = {ORIGIN_OVERRIDE}
                effects.append(f"added {k!r}")
        stats.overrides.append({**d.as_record(), "effect": effects})

    for d in (d for d in decisions if d.kind == "never_merge"):
        effects = []
        for name in d.names:
            k = actor_key(name)
            if k in actors:
                raise ReferenceInputError(
                    f"override never_merge {k!r}: it is the key of an actor; never_merge applies to synonyms"
                )
            claims: Dict[str, Set[str]] = dict(ambiguous.pop(k, {}))
            current = owner_of(k)
            if current is not None:
                claims[current] = actors[current].synonyms.pop(k)
            ambiguous[k] = claims
            never_merge[k] = {"reason": d.reason, "date": d.date, "status": d.status}
            if claims:
                effects.append(f"{k!r} no longer resolves (claimed by {', '.join(sorted(claims))})")
            else:
                effects.append(f"{k!r} listed (no actor claims it)")
        stats.overrides.append({**d.as_record(), "effect": effects})

    for d in (d for d in decisions if d.kind == "canonical_name"):
        if d.into not in actors:
            raise ReferenceInputError(f"override canonical_name {d.into!r}: no actor has that key")
        actor = actors[d.into]
        effects = [f"display name {actor.name!r} -> {d.display_name!r}"]
        new_key = actor_key(d.display_name)
        if new_key != actor.key:
            # Re-key: the new name becomes the key, the old key a synonym of the same actor.
            current = owner_of(new_key)
            if current is not None and current != actor.key:
                raise ReferenceInputError(
                    f"override canonical_name {d.into!r}: {new_key!r} belongs to actor {current!r}"
                )
            if new_key in ambiguous:
                raise ReferenceInputError(
                    f"override canonical_name {d.into!r}: {new_key!r} is ambiguous or never_merge"
                )
            if actor.mitre_attack:
                raise ReferenceInputError(
                    f"override canonical_name {d.into!r}: the key of ATT&CK group {actor.mitre_attack} is its ATT&CK name"
                )
            actor.synonyms.pop(new_key, None)
            old_key = actor.key
            del actors[old_key]
            actor.key = new_key
            actor.synonyms[old_key] = {r.origin for r in actor.records if r.key == old_key} | {ORIGIN_OVERRIDE}
            actors[new_key] = actor
            for claimants in ambiguous.values():
                if old_key in claimants:
                    claimants[new_key] = claimants.pop(old_key)
            effects.append(f"key {old_key!r} -> {new_key!r} ({old_key!r} kept as a synonym)")
        actor.name = d.display_name
        stats.overrides.append({**d.as_record(), "effect": effects})


def _check_invariants(actors: Mapping[str, _Actor], ambiguous: Mapping[str, Any]) -> None:
    seen: Dict[str, str] = {}

    def claim(key: str, where: str) -> None:
        if key != actor_key(key) or not _usable(key):
            raise AssertionError(f"key {key!r} ({where}) is not normalised")
        if key in seen:
            raise AssertionError(f"key {key!r} is both {seen[key]} and {where}")
        seen[key] = where

    for actor in actors.values():
        claim(actor.key, f"actor {actor.key!r}")
        for synonym in actor.synonyms:
            claim(synonym, f"synonym of {actor.key!r}")
    for key, claimants in ambiguous.items():
        claim(key, "ambiguous")
        unknown = sorted(set(claimants) - set(actors))
        if unknown:
            raise AssertionError(f"ambiguous {key!r} names {unknown}, which are not actor keys")


def build_reference(
    galaxy_doc: Mapping[str, Any],
    overrides_doc: Mapping[str, Any],
    *,
    version: str,
    inputs: Sequence[Mapping[str, Any]] = (),
) -> Tuple[Dict[str, Any], BuildStats]:
    """Pure: the reference document and what each rule did. Raises ``ReferenceInputError``."""
    match = _VERSION_RE.match(version)
    if not match:
        raise ReferenceInputError(f"version {version!r} must be CalVer YYYY.MM.DD")
    try:
        generated = _dt.date(int(match[1]), int(match[2]), int(match[3]))
    except ValueError as exc:
        raise ReferenceInputError(f"version {version!r} is not a date") from exc

    stats = BuildStats()
    decisions = load_overrides(overrides_doc)
    records = load_galaxy_records(galaxy_doc, stats)
    anchored, leftover = _anchored_actors(records, stats)
    standalone = _join_or_standalone(anchored, leftover, stats)

    actors: Dict[str, _Actor] = {}
    for actor in list(anchored.values()) + list(standalone.values()):
        if actor.key in actors:  # a standalone name equal to an ATT&CK key joined in rule 2
            raise AssertionError(f"duplicate actor key {actor.key!r}")
        actors[actor.key] = actor

    claims = _collect_claims(actors)
    ambiguous = _resolve_claims(actors, claims, stats)
    _apply_suffix_rule(actors, ambiguous, stats)
    never_merge: Dict[str, Dict[str, Any]] = {}
    _apply_overrides(actors, ambiguous, never_merge, decisions, stats)
    _check_invariants(actors, ambiguous)

    actor_entries: List[Dict[str, Any]] = []
    for key in sorted(actors):
        actor = actors[key]
        by_origin: Dict[str, List[str]] = defaultdict(list)
        for synonym in sorted(actor.synonyms):
            for origin in actor.synonyms[synonym]:
                by_origin[origin].append(synonym)
        actor_entries.append(
            {
                "name": actor.name,
                "key": actor.key,
                "mitre_attack": actor.mitre_attack,
                "origins": sorted(actor.origins),
                "records": sorted(r.source_record for r in actor.records),
                "synonyms": sorted(actor.synonyms),
                # origin -> the synonyms it gives (a synonym is listed under each of its origins)
                "synonym_origins": {o: by_origin[o] for o in sorted(by_origin)},
            }
        )
    ambiguous_entries: List[Dict[str, Any]] = []
    for key in sorted(ambiguous):
        entry: Dict[str, Any] = {
            "key": key,
            "actors": sorted(ambiguous[key]),
            "origins": {a: sorted(ambiguous[key][a]) for a in sorted(ambiguous[key])},
        }
        if key in never_merge:
            entry["never_merge"] = never_merge[key]
        ambiguous_entries.append(entry)

    reference: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "generated_at": generated.isoformat(),
        "description": DESCRIPTION,
        "generator": "scripts/build_canonical_threat_actors.py",
        "key_normalisation": "NFC, trimmed, lower-case (node_identity.canonicalize_merge_key for ThreatActor)",
        "inputs": [dict(i) for i in inputs],
        "attribution": [dict(a) for a in ATTRIBUTION],
        "rules": list(RULES),
        "counts": {
            "actors": len(actor_entries),
            "attack_groups": sum(1 for a in actor_entries if a["mitre_attack"]),
            "synonyms": sum(len(a["synonyms"]) for a in actor_entries),
            "ambiguous": len(ambiguous_entries),
        },
        "actors": actor_entries,
        "ambiguous": ambiguous_entries,
    }
    return reference, stats


def serialize_reference(reference: Mapping[str, Any]) -> str:
    return json.dumps(reference, indent=1, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- lookup + report


@dataclass(frozen=True)
class Resolution:
    actor: Optional[str]  # canonical key, None when ambiguous or unknown
    how: str  # "key" | "synonym" | "ambiguous" | "never_merge" | "unresolved"


def build_index(reference: Mapping[str, Any]) -> Dict[str, Resolution]:
    index: Dict[str, Resolution] = {}
    for actor in reference["actors"]:
        index[actor["key"]] = Resolution(actor["key"], "key")
        for synonym in actor["synonyms"]:
            index[synonym] = Resolution(actor["key"], "synonym")
    for entry in reference["ambiguous"]:
        index[entry["key"]] = Resolution(None, "never_merge" if "never_merge" in entry else "ambiguous")
    return index


def resolve(index: Mapping[str, Resolution], name: Any) -> Resolution:
    return index.get(actor_key(name), Resolution(None, "unresolved"))


def load_graph_actors(doc: Any) -> List[Dict[str, Any]]:
    rows = doc.get("actors") if isinstance(doc, Mapping) else doc
    if not isinstance(rows, list):
        raise ReferenceInputError("graph actors: expected a list or an object with 'actors'")
    out = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            raise ReferenceInputError("graph actors: every row needs a 'name'")
        out.append(
            {
                "name": row["name"],
                "aliases": [a for a in (row.get("aliases") or []) if isinstance(a, str)],
                "source": [s for s in (row.get("source") or []) if isinstance(s, str)],
                "relationships": int(row.get("relationships") or 0),
                "pulses": int(row.get("pulses") or 0),
            }
        )
    return out


_TRIAGE_SUFFIXES: Tuple[str, ...] = (
    " ransomware group",
    " ransomware gang",
    " ransomware",
    " group",
    " gang",
    " team",
    " apt",
)


def _strip_triage_suffixes(key: str) -> str:
    changed = True
    while changed:
        changed = False
        for suffix in _TRIAGE_SUFFIXES:
            if key.endswith(suffix) and len(key) > len(suffix) + 1:
                key = key[: -len(suffix)].strip()
                changed = True
                break
    return key


def build_report(
    reference: Mapping[str, Any],
    stats: BuildStats,
    graph_actors: Optional[Sequence[Mapping[str, Any]]] = None,
    mitre_source: str = "mitre_attck",
    top: int = 50,
) -> Dict[str, Any]:
    actors = reference["actors"]
    report: Dict[str, Any] = {
        "version": reference["version"],
        "counts": {
            **reference["counts"],
            "standalone_actors": stats.standalone_actors,
            "actors_created_by_overrides": sum(1 for a in actors if a["origins"] == [ORIGIN_OVERRIDE]),
            "synonyms_by_origin": _count_origins(actors),
        },
        "rules": {
            "records_by_galaxy": dict(sorted(stats.records_by_galaxy.items())),
            "skipped_records": stats.skipped_records,
            "attack_ids_without_mitre_record": stats.attack_ids_without_mitre_record,
            "anchor_conflicts": stats.anchor_conflicts,
            "joined_by_name": stats.joined,
            "joined_by_spacing_variant": stats.joined_by_spacing,
            "join_ambiguous_records": stats.join_ambiguous,
            "dropped_placeholder_names": stats.dropped_placeholder_names,
            "dropped_attack_id_synonyms": stats.dropped_attack_id_synonyms,
            "attack_id_synonyms_naming_another_group": stats.dropped_attack_id_synonyms_of_other_groups,
            "synonyms_rewritten_by_name_hygiene": stats.synonyms_rewritten_by_name_hygiene,
            "synonyms_dropped_by_name_hygiene": stats.synonyms_dropped_by_name_hygiene,
            "contested_names_resolved_by_claim_strength": len(stats.contested_resolved),
            "contested_examples": stats.contested_resolved[:25],
            "suffix_rule": {
                "added": stats.suffix_added,
                "already_synonyms": stats.suffix_also_existing,
                "blocked_claimed_elsewhere": stats.suffix_blocked,
                "ambiguous": stats.suffix_ambiguous,
                "shortened_names": stats.suffix_shortened,
            },
        },
        "overrides": stats.overrides,
    }
    if graph_actors is None:
        return report

    index = build_index(reference)
    by_key = {a["key"]: a for a in actors}
    rows = []
    for g in graph_actors:
        res = resolve(index, g["name"])
        rows.append({**g, "key": actor_key(g["name"]), "resolves_to": res.actor, "how": res.how})
    how_counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        how_counts[row["how"]] += 1

    mitre_nodes = {row["key"]: row for row in rows if mitre_source in row["source"]}
    anchored = {a["key"]: a for a in actors if a["mitre_attack"]}
    keys_not_on_graph = [
        {"mitre_attack": a["mitre_attack"], "key": k, "graph_node": _graph_presence(k, rows)}
        for k, a in sorted(anchored.items(), key=lambda kv: kv[1]["mitre_attack"])
        if k not in mitre_nodes
    ]
    graph_only = [
        {
            "graph_name": k,
            "resolves_to": mitre_nodes[k]["resolves_to"],
            "how": mitre_nodes[k]["how"],
            "relationships": mitre_nodes[k]["relationships"],
        }
        for k in sorted(mitre_nodes)
        if k not in anchored
    ]

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["resolves_to"]:
            groups[row["resolves_to"]].append(row)
    duplicate_groups = []
    for canonical, members in groups.items():
        if len(members) < 2:
            continue
        members = sorted(members, key=lambda r: (-r["relationships"], r["key"]))
        mitre_members = [m["key"] for m in members if mitre_source in m["source"]]
        duplicate_groups.append(
            {
                "canonical": canonical,
                "mitre_attack": by_key[canonical]["mitre_attack"],
                "graph_names": [m["key"] for m in members],
                "relationships": sum(m["relationships"] for m in members),
                "canonical_on_graph": any(m["key"] == canonical for m in members),
                "attack_nodes_not_canonical": [k for k in mitre_members if k != canonical],
            }
        )
    duplicate_groups.sort(key=lambda g: (-len(g["graph_names"]), -g["relationships"], g["canonical"]))

    unresolved = sorted(
        (r for r in rows if r["how"] == "unresolved"),
        key=lambda r: (-r["relationships"], -r["pulses"], r["key"]),
    )
    candidates = []
    for r in unresolved:
        base = _strip_triage_suffixes(r["key"])
        if base != r["key"]:
            res = resolve(index, base)
            if res.actor or res.how in ("ambiguous", "never_merge"):
                candidates.append({"graph_name": r["key"], "base": base, "resolves_to": res.actor, "how": res.how})

    # The alias merge job reads the ATT&CK aliases on the graph today: the ones the reference gives
    # to another actor (or none) are where the two would disagree.
    alias_conflicts = []
    aliases_unknown = []
    for k, node in sorted(mitre_nodes.items()):
        if k not in anchored:
            continue
        for alias in sorted({actor_key(a) for a in node["aliases"]}):
            if not _usable(alias) or alias == k:
                continue
            res = resolve(index, alias)
            if res.how == "unresolved":
                aliases_unknown.append({"attack_group": k, "graph_alias": alias})
            elif res.actor != k:
                alias_conflicts.append(
                    {"attack_group": k, "graph_alias": alias, "reference": res.actor, "how": res.how}
                )

    report["graph"] = {
        "actors": len(rows),
        "attack_nodes": len(mitre_nodes),
        "resolution": dict(sorted(how_counts.items())),
        "resolved": how_counts["key"] + how_counts["synonym"],
        "canonical_key_check": {
            "attack_keys_matching_graph": len(anchored) - len(keys_not_on_graph),
            "attack_keys_not_on_graph": keys_not_on_graph,
            "graph_attack_names_not_canonical_keys": graph_only,
        },
        "duplicate_groups": {
            "groups": len(duplicate_groups),
            "nodes_folded": sum(len(g["graph_names"]) - 1 for g in duplicate_groups),
            "into_attack_groups": sum(1 for g in duplicate_groups if g["mitre_attack"]),
            "canonical_not_on_graph": [g["canonical"] for g in duplicate_groups if not g["canonical_on_graph"]],
            "containing_another_attack_node": [g for g in duplicate_groups if g["attack_nodes_not_canonical"]],
            "largest": duplicate_groups[:25],
            "all": duplicate_groups,
        },
        "unresolved": {
            "count": len(unresolved),
            "relationships": sum(r["relationships"] for r in unresolved),
            "top": [
                {"name": r["key"], "relationships": r["relationships"], "pulses": r["pulses"], "source": r["source"]}
                for r in unresolved[:top]
            ],
            "all": [
                {"name": r["key"], "relationships": r["relationships"], "pulses": r["pulses"], "source": r["source"]}
                for r in unresolved
            ],
            "suffix_variant_candidates": candidates,
        },
        "graph_attack_aliases_resolving_elsewhere": alias_conflicts,
        "graph_attack_aliases_unknown": aliases_unknown,
        "seed_decisions_on_graph": _decisions_on_graph(stats.overrides, rows, index),
    }
    return report


def _graph_presence(key: str, rows: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for row in rows:
        if row["key"] == key:
            return ", ".join(row["source"]) or "present"
    return None


def _count_origins(actors: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for actor in actors:
        for origin, synonyms in actor["synonym_origins"].items():
            counts[origin] += len(synonyms)
    return dict(sorted(counts.items()))


def _decisions_on_graph(
    decisions: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]], index: Mapping[str, Resolution]
) -> List[Dict[str, Any]]:
    on_graph = {r["key"]: r for r in rows}
    out = []
    for d in decisions:
        names = [actor_key(n) for n in d.get("names", [])] + ([d["into"]] if d.get("into") else [])
        if d["decision"] == "canonical_name":
            names = [d["key"]]
        out.append(
            {
                "decision": d["decision"],
                "names": names,
                "on_graph": {
                    n: {"relationships": on_graph[n]["relationships"], "resolves_to": resolve(index, n).actor}
                    for n in names
                    if n in on_graph
                },
            }
        )
    return out


def format_report(report: Mapping[str, Any], top: int = 50) -> str:
    lines: List[str] = []
    c = report["counts"]
    r = report["rules"]
    lines.append(f"Canonical threat-actor reference {report['version']}")
    lines.append(
        f"  actors {c['actors']} (ATT&CK groups {c['attack_groups']}, standalone {c['standalone_actors']}, "
        f"created by overrides {c['actors_created_by_overrides']}); synonyms {c['synonyms']}; ambiguous {c['ambiguous']}"
    )
    lines.append(f"  synonym origins: {json.dumps(c['synonyms_by_origin'])}")
    lines.append(f"  records by galaxy: {json.dumps(r['records_by_galaxy'])}; skipped {len(r['skipped_records'])}")
    lines.append(f"  joined by name (rule 2): {json.dumps(r['joined_by_name'])}")
    for item in r["joined_by_spacing_variant"]:
        lines.append(f"  joined by a spacing variant: {item['name']!r} -> {item['actor']}")
    for conflict in r["anchor_conflicts"]:
        lines.append(
            f"  anchor conflict: {conflict['record']} {conflict['name']!r} carries {conflict['mitre_attack']} but its "
            f"name is the ATT&CK name of {conflict['attack_name_of']}; joined by name instead"
        )
    for item in r["join_ambiguous_records"]:
        lines.append(f"  join ambiguous (own actor): {item['name']!r} matches {', '.join(item['candidates'])}")
    if r["attack_ids_without_mitre_record"]:
        lines.append(f"  ATT&CK ids without a mitre-intrusion-set record: {r['attack_ids_without_mitre_record']}")
    lines.append(
        f"  dropped: placeholder names {r['dropped_placeholder_names']}, ATT&CK ids as synonyms "
        f"{r['dropped_attack_id_synonyms']} ({len(r['attack_id_synonyms_naming_another_group'])} naming another group)"
    )
    lines.append(
        f"  synonyms as EdgeGuard's name hygiene writes them: rewritten "
        f"{len(r['synonyms_rewritten_by_name_hygiene'])}, dropped {len(r['synonyms_dropped_by_name_hygiene'])}"
    )
    lines.append(f"  contested names resolved by claim strength: {r['contested_names_resolved_by_claim_strength']}")
    s = r["suffix_rule"]
    lines.append(
        f"  suffix rule: added {s['added']}, already synonyms {s['already_synonyms']}, "
        f"blocked {s['blocked_claimed_elsewhere']}, ambiguous {len(s['ambiguous'])}"
    )
    if s["shortened_names"]:
        shortened = ", ".join(f"{i['name']} ({i['actor']})" for i in s["shortened_names"])
        lines.append(f"  suffix rule, shortened names to review (a short name can be a common word): {shortened}")
    lines.append("")
    lines.append(f"Override decisions ({len(report['overrides'])}):")
    for d in report["overrides"]:
        what = d.get("names") or [d.get("name")]
        target = f" -> {d['into']!r}" if d.get("into") else ""
        key = f" {d['key']!r}" if d["decision"] == "canonical_name" else ""
        lines.append(f"  [{d['status']}] {d['decision']}{key} {what}{target}: {'; '.join(d['effect'])}")
        lines.append(f"      reason: {d['reason']}")

    g = report.get("graph")
    if not g:
        return "\n".join(lines) + "\n"
    lines.append("")
    lines.append(
        f"Graph: {g['actors']} ThreatActor nodes ({g['attack_nodes']} ATT&CK); resolve to a canonical actor: "
        f"{g['resolved']} ({json.dumps(g['resolution'])})"
    )
    k = g["canonical_key_check"]
    lines.append(f"  canonical keys equal to the ATT&CK node names: {k['attack_keys_matching_graph']}")
    for item in k["attack_keys_not_on_graph"]:
        lines.append(
            f"  mismatch: {item['mitre_attack']} {item['key']!r} has no ATT&CK node (node: {item['graph_node']})"
        )
    for item in k["graph_attack_names_not_canonical_keys"]:
        lines.append(
            f"  ATT&CK node {item['graph_name']!r} ({item['relationships']} rels) has no ATT&CK id in the galaxy; "
            f"reference: {item['how']} {item['resolves_to']}"
        )
    d = g["duplicate_groups"]
    lines.append(
        f"  duplicate groups the merge job would fold: {d['groups']} ({d['nodes_folded']} nodes; "
        f"{d['into_attack_groups']} into ATT&CK groups)"
    )
    for group in d["largest"][:10]:
        attack = f" {group['mitre_attack']}" if group["mitre_attack"] else ""
        lines.append(f"    {group['canonical']}{attack}: {group['graph_names']} ({group['relationships']} rels)")
    if d["canonical_not_on_graph"]:
        lines.append(f"  groups whose canonical key is not a node: {d['canonical_not_on_graph']}")
    for group in d["containing_another_attack_node"]:
        lines.append(
            f"  WARNING group {group['canonical']!r} contains ATT&CK nodes {group['attack_nodes_not_canonical']}"
        )
    u = g["unresolved"]
    lines.append(f"  unresolved: {u['count']} names ({u['relationships']} relationships); top {min(top, u['count'])}:")
    for item in u["top"][:top]:
        lines.append(f"    {item['relationships']:5d} rels {item['pulses']:3d} pulses  {item['name']}")
    if u["suffix_variant_candidates"]:
        lines.append("  unresolved names whose base name resolves (review candidates):")
        for item in u["suffix_variant_candidates"]:
            lines.append(f"    {item['graph_name']!r} -> base {item['base']!r}: {item['how']} {item['resolves_to']}")
    conflicts = g["graph_attack_aliases_resolving_elsewhere"]
    lines.append(
        f"  ATT&CK node aliases on the graph that the reference resolves elsewhere: {len(conflicts)} "
        f"(unknown to the reference: {len(g['graph_attack_aliases_unknown'])})"
    )
    for item in conflicts[:25]:
        lines.append(f"    {item['attack_group']}: {item['graph_alias']!r} -> {item['how']} {item['reference']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- graph export (read-only)

_EXPORT_CYPHER = """
MATCH (a:ThreatActor)
RETURN a.name AS name, a.aliases AS aliases, a.source AS source,
       COUNT { (a)--() } AS relationships,
       COUNT { UNWIND coalesce(a.pulse_ids, []) AS p RETURN DISTINCT p } AS pulses
ORDER BY name
"""


def _http_query(statement: str, timeout: int = 300) -> Tuple[str, List[Dict[str, Any]]]:
    base = (os.getenv("NEO4J_HTTP_URL") or os.getenv("NEO4J_HTTP") or "https://neo4j.edgeguard.org").rstrip("/")
    url = f"{base}/db/{os.getenv('NEO4J_DATABASE', 'neo4j')}/query/v2"
    auth = f"{os.getenv('NEO4J_USER', 'neo4j')}:{os.getenv('NEO4J_PASSWORD', '')}"
    body = json.dumps({"statement": statement, "parameters": {}, "accessMode": "Read"}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    # The Cloudflare proxy in front of the hosted instance rejects urllib's default agent
    # (same workaround as scripts/verify_fresh_baseline.py).
    req.add_header(
        "User-Agent",
        os.getenv(
            "NEO4J_HTTP_USER_AGENT",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36",
        ),
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode())
    if payload.get("errors"):
        raise RuntimeError(payload["errors"])
    data = payload["data"]
    return url, [dict(zip(data["fields"], row, strict=True)) for row in data["values"]]


def export_graph_actors(out: Path) -> int:
    url, rows = _http_query(_EXPORT_CYPHER)
    doc = {
        "exported_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "url": url,
        "count": len(rows),
        "actors": rows,
    }
    out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(rows)


# --------------------------------------------------------------------------- CLI


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(_REPO_ROOT)
        return True
    except ValueError:
        return False


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("--galaxy", type=Path, help="threat-actor entities export of the MISP galaxies")
    ap.add_argument("--overrides", type=Path, default=DEFAULT_OVERRIDES)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--version", default=None, help="CalVer YYYY.MM.DD (default: today, UTC)")
    ap.add_argument("--graph-actors", type=Path, help="graph export (from --export-graph-actors) for the report")
    ap.add_argument("--unresolved-out", type=Path, help="write every unresolved graph name here (outside the repo)")
    ap.add_argument("--report-json", type=Path, help="write the full report as JSON here (outside the repo)")
    ap.add_argument("--top", type=int, default=50, help="unresolved names shown in the report (default 50)")
    ap.add_argument(
        "--export-graph-actors",
        type=Path,
        metavar="PATH",
        help="read ThreatActor names, aliases and sources from Neo4j (read-only) into PATH and exit",
    )
    args = ap.parse_args(argv)

    for path in (args.export_graph_actors, args.unresolved_out, args.report_json):
        if path is not None and _inside_repo(path):
            print(f"refusing to write graph-derived data inside the repository: {path}", file=sys.stderr)
            return 1

    if args.export_graph_actors is not None:
        try:
            n = export_graph_actors(args.export_graph_actors)
        except (urllib.error.URLError, OSError, RuntimeError) as exc:
            print(f"ERROR: cannot read ThreatActor nodes from Neo4j: {exc}", file=sys.stderr)
            return 2
        print(f"exported {n} ThreatActor nodes to {args.export_graph_actors}")
        return 0

    if args.galaxy is None:
        ap.error("--galaxy is required to build the reference")
    version = args.version or _dt.datetime.now(_dt.timezone.utc).strftime("%Y.%m.%d")
    try:
        galaxy_doc = _read_json(args.galaxy)
        overrides_doc = _read_json(args.overrides)
        inputs = [
            galaxy_input_metadata(galaxy_doc, args.galaxy.name, _sha256(args.galaxy)),
            {
                "role": "overrides",
                "file": args.overrides.name,
                "sha256": _sha256(args.overrides),
                "decisions": sum(len(overrides_doc.get(k) or []) for k in ("merge", "never_merge", "canonical_name")),
            },
        ]
        reference, stats = build_reference(galaxy_doc, overrides_doc, version=version, inputs=inputs)
        graph = load_graph_actors(_read_json(args.graph_actors)) if args.graph_actors else None
    except (ReferenceInputError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(serialize_reference(reference), encoding="utf-8")
    report = build_report(reference, stats, graph, top=args.top)
    print(f"wrote {args.out} ({args.out.stat().st_size:,} bytes)\n")
    print(format_report(report, top=args.top), end="")
    if args.unresolved_out is not None and "graph" in report:
        args.unresolved_out.write_text(
            json.dumps(report["graph"]["unresolved"]["all"], indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"\nwrote {len(report['graph']['unresolved']['all'])} unresolved names to {args.unresolved_out}")
    if args.report_json is not None:
        args.report_json.write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
