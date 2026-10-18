#!/usr/bin/env python3
"""Build EdgeGuard's canonical threat-actor reference (``src/reference/canonical_threat_actors.json``).

The same actor reaches the graph under several names (``lazarus`` from one feed, ``lazarus group``
from ATT&CK), which splits its evidence across duplicate ``ThreatActor`` nodes. This script turns
the MISP galaxy threat-actor clusters and the ATT&CK version EdgeGuard loaded into a reviewed
dictionary of canonical actors and their synonyms. It never writes to the graph; the actor alias
merge (``enrichment_jobs.merge_alias_duplicate_actors``) reads the reference.

Inputs
------
``--galaxy``             the threat-actor entities export of the MISP galaxies
                         (``galaxy_threat_actors_<date>.json``: one record per cluster of the
                         threat-actor, mitre-intrusion-set, microsoft-activity-group,
                         360net-threat-actor and mitre-ics-groups galaxies, with ``name``,
                         ``aliases``, ``external_ids.mitre_attack`` and ``provenance``).
``--attack-galaxy-raw``  the raw mitre-intrusion-set galaxy dump that export was built from; its
                         ``revoked-by`` relations say which ATT&CK groups were revoked into which.
``--graph-actors``       an export made by ``--export-graph-actors``. Its ATT&CK-sourced nodes, with
                         the aliases MITRE delivered for them, are the ATT&CK version EdgeGuard
                         loaded (newer than the galaxy copy); the rest of it feeds the report.
``--overrides``          hand-reviewed decisions (``src/reference/canonical_threat_actor_overrides.json``),
                         applied last so that a rebuild keeps them.

Grouping rules (a wrong merge is worse than a missed one)
---------------------------------------------------------
Keys are normalised like ``node_identity.canonicalize_merge_key`` normalises a ``ThreatActor``
name on write: NFC, trimmed, lower-case. The ``name_key`` of the input is not used (it is NFKC).

1. Anchor by ATT&CK id. All records with the same ``mitre_attack`` id are one actor whose
   canonical name and key are the ATT&CK group name (the mitre-intrusion-set value without its
   `` - G0032`` suffix). A record whose own name is the ATT&CK name of a different, not revoked
   group (the galaxy names several ATT&CK ids for it and the export kept the first) is not
   anchored by that id; it goes through rule 2 instead.

   * A group ATT&CK revoked into another (``revoked-by``) is folded into its successor. Its key,
     name and aliases become synonyms of the successor (origin ``mitre_revoked``).
   * The ATT&CK version EdgeGuard loaded is anchored too. For each ATT&CK-sourced graph node, its
     name and the aliases MITRE delivered for it are ATT&CK claims, the strongest after an actor
     key (origin ``mitre_loaded``). The delivered aliases are read from the node's SOURCED_FROM
     edge to the ATT&CK source, not from the node: the node's ``aliases`` also hold every name the
     actor alias merge folded into it, which must not come back as ATT&CK claims. A node whose name
     is no galaxy group's key does one of three things:
     - it goes to its successor when it is a revoked group;
     - it renames the galaxy group whose ATT&CK id its description carries;
     - otherwise it becomes an anchor by name.
2. A record without an ATT&CK id joins an anchored actor only when its name equals that actor's
   key, one of its ATT&CK aliases or revoked names, or the name of a record anchored to it.
   That name must belong to exactly one anchored actor; an actor key outranks another actor's
   alias. Names that differ only in spaces, hyphens, dots or underscores are the same name
   ("SaintBear" is ATT&CK's "Saint Bear"); the exact name is tried first. A 360net-threat-actor
   name is also tried without its `` - APT-C-NN`` id ("Darkhotel - APT-C-06"). Otherwise records
   with the same name form an actor of their own. It is named after the threat-actor galaxy
   value, else the microsoft-activity-group or the mitre-ics-groups value. A 360net-threat-actor
   record that joins no ATT&CK actor is left out: its key (a Chinese name or "<name> - APT-C-NN")
   is a name no feed writes, and its English synonyms belong to other actors.
3. Synonyms are the names the records give for their actor (aliases, and the names of joined
   records). They never merge two actors.
4. A synonym claimed by more than one actor goes to the actor whose own name it is. In order:
   - an actor key always stays with its actor;
   - then a loaded ATT&CK alias;
   - then a galaxy ATT&CK alias, a revoked group's name or a record's own name;
   - then a plain galaxy synonym.
   If no single actor holds the strongest claim, the name is ambiguous and is never merged. The
   spellings of one name (rule 2: they differ only in spaces, hyphens, dots or underscores) are
   settled together after rule 5: when they belong to different actors, the actor holding the
   strongest spelling keeps its spellings, and the other spellings are ambiguous; on a tie every
   spelling is ambiguous ("dark seoul" / "darkseoul").
   Some names are never synonyms: ATT&CK group ids (the id is ``mitre_attack``), placeholder names
   (``node_identity.is_placeholder_name``) and lists of names. A synonym is taken as EdgeGuard's
   actor-name hygiene writes it (``actor_name_hygiene.clean_actor_names``: a trailing parenthetical
   is dropped).
5. Suffix rule. Applies to every actor key, ATT&CK alias and revoked name: the variant with a
   trailing `` group`` / `` team`` removed (or added, when the name has neither) becomes a
   synonym when no actor claims it yet. A variant two actors would get is ambiguous, and so is a
   variant another actor holds only by a plain galaxy synonym ("winnti": ATT&CK's "Winnti Group"
   against a galaxy synonym of APT41). A shortened name keeps at least three characters and a
   letter. Nothing is added to a name that already has the word ``group`` or ``team`` in it.
   Shortened names can be common words; the report lists them for review.
6. Overrides are applied last, in this order:
   - ``never_merge`` with an ``actor`` takes the names away from that actor and never gives them
     back to it;
   - ``merge`` puts a name into a canonical key. It creates the actor when no actor has that key,
     and folds an actor without an ATT&CK id whose key is the name. It never folds an ATT&CK
     group.
   - ``never_merge`` without an ``actor`` takes a name out of every actor and lists it as
     ambiguous;
   - ``canonical_name`` sets the display name. A name with another key re-keys an actor that is
     not an ATT&CK group and keeps the old key as a synonym.

The output is deterministic: the same inputs and ``--version`` give a byte-identical file.
``--version`` defaults to the build date (CalVer ``YYYY.MM.DD``); ``generated_at`` is that date.

Report
------
The build prints the counts, the rule effects and every override decision. With
``--graph-actors`` it also reports on the graph:
- it checks the canonical keys against the names EdgeGuard wrote for the ATT&CK groups;
- it reports how the graph's actor names resolve and the duplicate groups the merge would fold;
- it reports the ATT&CK aliases the reference gives elsewhere;
- it lists names that differ only in spelling (``triage_key``) and the suffix-rule short forms
  that exist on the graph;
- it ranks the unresolved names by relationship count: the first 50 in the report, all of them
  with ``--unresolved-out``.

``--export-graph-actors PATH`` reads every ``ThreatActor`` node over the Neo4j HTTP Query API v2
in read mode: name, aliases, sources, relationship count, pulse count and malware names. For an
ATT&CK node it also reads the record MITRE delivered (its SOURCED_FROM edge to the ATT&CK source):
the delivered aliases (``attack_aliases``) and the ATT&CK group id the delivered description links
to (else the id the node's own description links to). It uses the same settings as
``scripts/verify_fresh_baseline.py``: ``NEO4J_HTTP_URL`` or ``NEO4J_HTTP``, ``NEO4J_DATABASE``,
``NEO4J_USER``, ``NEO4J_PASSWORD``. Graph-derived files must be written outside the
repository; the script refuses a path inside it.

Usage::

    python scripts/build_canonical_threat_actors.py --export-graph-actors /tmp/graph_threat_actors.json
    python scripts/build_canonical_threat_actors.py --galaxy galaxy_threat_actors_20261013.json \\
        --attack-galaxy-raw misp_galaxy_mitre-intrusion-set_20261013.json \\
        --graph-actors /tmp/graph_threat_actors.json --unresolved-out /tmp/unresolved_actors.json

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

import canonical_threat_actors as reference_lookup  # noqa: E402
from actor_name_hygiene import clean_actor_names  # noqa: E402
from node_identity import canonicalize_merge_key, is_placeholder_name  # noqa: E402

DEFAULT_OUT = _SRC / "reference" / "canonical_threat_actors.json"
DEFAULT_OVERRIDES = _SRC / "reference" / "canonical_threat_actor_overrides.json"

SCHEMA_VERSION = 1
MITRE_GALAXY = "mitre-intrusion-set"
MITRE_SOURCE = "mitre_attck"  # the graph's source tag of ATT&CK nodes (SOURCE_TAGS["mitre"])
# Display-name preference for an actor without an ATT&CK id (rule 2), then any other galaxy.
GALAXY_NAME_PRIORITY: Tuple[str, ...] = (
    "threat-actor",
    "microsoft-activity-group",
    "360net-threat-actor",
    "mitre-ics-groups",
    MITRE_GALAXY,
)
ORIGIN_MITRE = "mitre"
ORIGIN_MITRE_LOADED = "mitre_loaded"
ORIGIN_MITRE_REVOKED = "mitre_revoked"
ORIGIN_SUFFIX = "suffix_rule"
ORIGIN_OVERRIDE = "override"
GALAXY_ORIGIN_PREFIX = "misp_galaxy:"
NAME_SUFFIXES: Tuple[str, ...] = (" group", " team")
OVERRIDE_STATUSES = frozenset({"proposed", "accepted"})

# Claim strength (rule 4): lower wins. An actor key always wins and is not a claim.
TIER_LOADED_ATTACK = 0  # an alias of the ATT&CK version EdgeGuard loaded
TIER_OWN_NAME = 1  # a galaxy ATT&CK alias, a revoked group's name, or a record's own name
TIER_SYNONYM = 2  # an alias a galaxy record gives

_ATTACK_NAME_SUFFIX_RE = re.compile(r"\s+-\s+G\d{4}\s*$")
# The 360net-threat-actor galaxy appends its own group id to every name ("Darkhotel - APT-C-06").
# Rule 2 also tries the name without it; the full value stays the record's name.
_THREE_SIXTY_GALAXY = "360net-threat-actor"
_THREE_SIXTY_ID_SUFFIX_RE = re.compile(r"\s+-\s+APT-C-\d+\s*$", re.IGNORECASE)
_ATTACK_GROUP_ID_RE = re.compile(r"^G\d{4}$")
_ATTACK_GROUP_URL_RE = re.compile(r"attack\.mitre\.org/groups/(G\d{4})")
_GROUP_OR_TEAM_WORD_RE = re.compile(r"\b(?:group|team)\b")
_SEPARATORS_RE = re.compile(r"[\s\-_.]+")
_ATTACK_ID_KEY_RE = re.compile(r"^g\d{4}$")
_VERSION_RE = re.compile(r"^(\d{4})\.(\d{2})\.(\d{2})$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

DESCRIPTION = (
    "Canonical threat actors for EdgeGuard: one entry per actor with its canonical key (the "
    "ThreatActor name EdgeGuard writes, normalised like node_identity.canonicalize_merge_key), its "
    "ATT&CK group id and the synonyms that name it. Built by scripts/build_canonical_threat_actors.py "
    "from the MISP galaxy threat-actor clusters and the ATT&CK version EdgeGuard loaded, with the "
    "hand-reviewed decisions of canonical_threat_actor_overrides.json applied last. Names listed "
    "under 'ambiguous' point to more than one actor, or were marked never_merge, and are never merged."
)
RULES: Tuple[str, ...] = (
    "Records with the same ATT&CK id are one actor named after the ATT&CK group; a record whose own "
    "name is the ATT&CK name of a different group is not anchored by its id. A group ATT&CK revoked "
    "into another is folded into its successor (origin mitre_revoked). The ATT&CK version EdgeGuard "
    "loaded anchors too: its names and the aliases MITRE delivered for them are the strongest claims "
    "after an actor key (origin mitre_loaded), and a group the galaxy copy does not have is anchored "
    "by its name.",
    "A record without an ATT&CK id joins an anchored actor only when its name (for the "
    "360net-threat-actor galaxy also the name without its ' - APT-C-NN' id) is that actor's key, an "
    "ATT&CK alias or revoked name of it or the name of a record anchored to it, for exactly one "
    "actor; names that differ only in spaces, hyphens, dots or underscores are the same name. "
    "Otherwise records with the same name form an actor of their own; a 360net-threat-actor record "
    "that joins no ATT&CK actor is left out.",
    "Synonyms never merge two actors.",
    "A name claimed by several actors goes to the actor whose own name it is (actor key, then loaded "
    "ATT&CK alias, then galaxy ATT&CK alias, revoked name or record name, then galaxy synonym); a tie "
    "makes it ambiguous. Spellings of one name held by different actors stay with the actor holding "
    "the strongest spelling and are ambiguous for the others (all of them on a tie). ATT&CK ids, "
    "placeholder names and lists of names are not synonyms; a synonym is taken as EdgeGuard's "
    "actor-name hygiene writes it.",
    "Suffix rule: the variant with or without a trailing ' group' / ' team' of an actor key or "
    "ATT&CK name is a synonym when no other actor claims it, and ambiguous when another actor holds "
    "it only by a galaxy synonym (a shortened name keeps at least three characters and a letter; "
    "nothing is added to a name that already contains 'group' or 'team').",
    "Overrides are applied last: never_merge with an actor, merge, never_merge, canonical_name.",
)
ATTRIBUTION: Tuple[Dict[str, str], ...] = (
    {
        "source": "MISP galaxy (threat-actor, mitre-intrusion-set, microsoft-activity-group, "
        "360net-threat-actor and mitre-ics-groups galaxies)",
        "licence": "CC0-1.0",
        "url": "https://github.com/MISP/misp-galaxy",
    },
    {
        "source": "MITRE ATT&CK (group names, ids, aliases and revocations, from the mitre-intrusion-set "
        "galaxy and from the ATT&CK version EdgeGuard loaded)",
        "notice": "© The MITRE Corporation. This work is reproduced and distributed with the "
        "permission of The MITRE Corporation.",
        "url": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
    },
)


class ReferenceInputError(ValueError):
    """Invalid input or override decision (exit code 1)."""


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


def triage_key(key: str) -> str:
    """``compact_key`` with ``0`` read as ``o`` (``"cl0p"`` / ``"clop"``). Used only to list
    spelling variants in the report, never to merge."""
    return compact_key(key).replace("0", "o")


def clean_synonym(name: Any) -> Tuple[str, str]:
    """``(status, key)`` of a name as a synonym: the key EdgeGuard's actor-name hygiene writes for
    it. ``status`` is ``ok``, ``rewritten`` (a trailing parenthetical dropped), ``list`` / ``not a
    name`` (no single name, key ``""``), ``placeholder`` / ``empty`` (key ``""``) or ``attack_id``."""
    if not isinstance(name, str) or not actor_key(name):
        return "empty", ""
    if is_placeholder_name(name):
        return "placeholder", ""
    cleaned = clean_actor_names(name)
    if len(cleaned) != 1:
        return ("list" if cleaned else "not a name"), ""
    key = actor_key(cleaned[0])
    if _ATTACK_ID_KEY_RE.match(key):
        return "attack_id", key
    return ("rewritten" if key != actor_key(name) else "ok"), key


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
    aliases: Tuple[str, ...]  # synonym keys, in input order

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


@dataclass(frozen=True)
class LoadedAttackGroup:
    """An ATT&CK-sourced ``ThreatActor`` node: a group of the ATT&CK version EdgeGuard loaded."""

    key: str
    name: str  # display name: the alias spelled like the key, else the key
    attack_id: Optional[str]  # from the delivered (else the node's) description link, when it has one
    aliases: Tuple[str, ...]  # synonym keys (``clean_synonym``) of the delivered aliases, without the key


@dataclass
class BuildStats:
    """What each rule did; printed by the report."""

    records_by_galaxy: Dict[str, int] = field(default_factory=dict)
    skipped_records: List[str] = field(default_factory=list)
    attack_groups: int = 0
    attack_ids_without_mitre_record: List[str] = field(default_factory=list)
    anchor_conflicts: List[Dict[str, str]] = field(default_factory=list)
    revoked_folds: List[Dict[str, str]] = field(default_factory=list)
    revoked_without_successor: List[str] = field(default_factory=list)
    loaded_groups: int = 0
    loaded_revoked_nodes: List[Dict[str, str]] = field(default_factory=list)
    loaded_renamed: List[Dict[str, str]] = field(default_factory=list)
    loaded_anchored: List[Dict[str, Optional[str]]] = field(default_factory=list)
    loaded_id_mismatches: List[Dict[str, str]] = field(default_factory=list)
    joined: Dict[str, int] = field(default_factory=dict)
    joined_by_spacing: List[Dict[str, str]] = field(default_factory=list)
    join_ambiguous: List[Dict[str, Any]] = field(default_factory=list)
    unjoined_360net: List[Dict[str, str]] = field(default_factory=list)  # left out (rule 2)
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
    suffix_contested: List[Dict[str, Any]] = field(default_factory=list)  # held by a plain synonym: ambiguous
    suffix_shortened: List[Dict[str, str]] = field(default_factory=list)  # added by the rule
    suffix_short_forms: List[Dict[str, str]] = field(default_factory=list)  # every short form it derived
    spelling_variants_ambiguous: List[Dict[str, Any]] = field(default_factory=list)  # rule 4, by compact name
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
    aliases: List[str] = []
    for alias in raw.get("aliases") or []:
        raw_alias = alias.get("name") if isinstance(alias, Mapping) else alias
        alias_name = str(raw_alias)
        # A synonym is the name EdgeGuard would write for it: its actor-name hygiene drops a trailing
        # parenthetical ("xHunt campaign (<source>)" -> "xHunt campaign") and splits lists. A list
        # or a description never reaches the graph as one name, so it is not a synonym.
        status, alias_key = clean_synonym(raw_alias)
        if status == "empty":
            continue
        if status == "placeholder":
            stats.dropped_placeholder_names += 1
            continue
        if status in ("list", "not a name"):
            stats.synonyms_dropped_by_name_hygiene.append(
                {"record": source_record, "synonym": alias_name, "why": status}
            )
            continue
        if status == "attack_id":
            stats.dropped_attack_id_synonyms += 1
            if alias_key.upper() != attack_id:
                stats.dropped_attack_id_synonyms_of_other_groups.append(
                    {"record": source_record, "name": name, "mitre_attack": attack_id or "", "synonym": alias_name}
                )
            continue
        if status == "rewritten":
            stats.synonyms_rewritten_by_name_hygiene.append(
                {"record": source_record, "synonym": alias_name, "written_as": alias_key}
            )
        aliases.append(alias_key)
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


def load_revocations(raw_doc: Mapping[str, Any]) -> Dict[str, str]:
    """Revoked ATT&CK group id -> the id it was revoked into, from the ``revoked-by`` relations of
    a raw mitre-intrusion-set galaxy dump (MISP ``/galaxy_clusters/restSearch`` response)."""
    payload = raw_doc.get("payload") if isinstance(raw_doc, Mapping) else None
    entries = payload.get("response") if isinstance(payload, Mapping) else None
    if not isinstance(entries, list) or not entries:
        raise ReferenceInputError("ATT&CK galaxy dump: no payload.response cluster list")
    clusters = [e.get("GalaxyCluster", e) for e in entries if isinstance(e, Mapping)]
    id_of: Dict[str, str] = {}
    for cluster in clusters:
        for element in cluster.get("GalaxyElement") or []:
            if element.get("key") == "external_id" and _ATTACK_GROUP_ID_RE.match(str(element.get("value"))):
                id_of[str(cluster.get("uuid"))] = str(element["value"])
    revocations: Dict[str, str] = {}
    for cluster in clusters:
        for relation in cluster.get("GalaxyClusterRelation") or []:
            if relation.get("referenced_galaxy_cluster_type") != "revoked-by":
                continue
            revoked = id_of.get(str(cluster.get("uuid")))
            successor = id_of.get(str(relation.get("referenced_galaxy_cluster_uuid")))
            if not revoked or not successor:
                raise ReferenceInputError(
                    f"ATT&CK galaxy dump: revoked-by relation of {cluster.get('value')!r} without ids"
                )
            if revocations.get(revoked, successor) != successor:
                raise ReferenceInputError(f"ATT&CK galaxy dump: {revoked} is revoked into two groups")
            revocations[revoked] = successor
    return dict(sorted(revocations.items()))


def load_loaded_attack(
    graph_rows: Iterable[Mapping[str, Any]], mitre_source: str = MITRE_SOURCE
) -> List[LoadedAttackGroup]:
    """The ATT&CK groups EdgeGuard loaded: the ATT&CK-sourced rows of a graph export (``load_graph_actors``).

    The aliases are those MITRE delivered (``attack_aliases``), never the node's ``aliases``: those
    also hold the names the actor alias merge folded in, which are not ATT&CK claims. A node without
    a delivered record contributes its name only."""
    groups: Dict[str, LoadedAttackGroup] = {}
    for row in graph_rows:
        if mitre_source not in (row.get("source") or []):
            continue
        key = actor_key(row.get("name"))
        if not _usable(key):
            continue
        aliases = [a for a in (row.get("attack_aliases") or []) if isinstance(a, str)]
        display = next((a.strip() for a in aliases if actor_key(a) == key), str(row.get("name")).strip())
        keys = sorted({k for status, k in map(clean_synonym, aliases) if status in ("ok", "rewritten") and k != key})
        attack_id = row.get("attack_id")
        attack_id = attack_id if isinstance(attack_id, str) and _ATTACK_GROUP_ID_RE.match(attack_id) else None
        groups[key] = LoadedAttackGroup(key, display, attack_id, tuple(keys))
    return [groups[k] for k in sorted(groups)]


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
    actor: str = ""  # never_merge: the actor the names are kept away from ("" = every actor)

    def as_record(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"decision": self.kind}
        if self.kind == "merge":
            out.update({"names": list(self.names), "into": self.into})
        elif self.kind == "never_merge":
            out["names"] = list(self.names)
            if self.actor:
                out["actor"] = self.actor
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
        actor = ""
        if entry.get("actor") is not None:
            actor = actor_key(entry.get("actor"))
            if not _usable(actor):
                raise ReferenceInputError(f"{where}: 'actor' must name an actor key")
        decisions.append(
            OverrideDecision("never_merge", _names(entry, where), "", "", reason, date, status, actor=actor)
        )
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
    kept_away: Set[Tuple[str, str]] = set()
    for d in decisions:
        for name in d.names:
            k = actor_key(name)
            if d.kind == "merge":
                if merged_into.get(k, d.into) != d.into:
                    raise ReferenceInputError(f"overrides: {name!r} is merged into two actors")
                merged_into[k] = d.into
            elif d.kind == "never_merge" and d.actor:
                kept_away.add((k, d.actor))
            elif d.kind == "never_merge":
                never.add(k)
    both = sorted(never & (set(merged_into) | set(merged_into.values())))
    if both:
        raise ReferenceInputError(f"overrides: {both} are both merged and never_merge")
    contradicted = sorted(k for k, target in merged_into.items() if (k, target) in kept_away)
    if contradicted:
        raise ReferenceInputError(f"overrides: {contradicted} are merged into an actor they are kept away from")
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
    attack_aliases: Set[str] = field(default_factory=set)  # the galaxy copy's ATT&CK aliases
    loaded_aliases: Set[str] = field(default_factory=set)  # the loaded ATT&CK version's aliases
    revoked_names: Set[str] = field(default_factory=set)  # names of the groups revoked into this one
    revoked: List[Dict[str, str]] = field(default_factory=list)  # [{"mitre_attack", "name"}]
    loaded: bool = False  # the loaded ATT&CK version has a node with this key

    @property
    def is_attack_group(self) -> bool:
        return self.mitre_attack is not None or self.loaded

    def attack_names(self) -> Set[str]:
        return (self.attack_aliases | self.loaded_aliases | self.revoked_names) - {self.key}


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

    def tier(self, synonym: str, actor: str) -> Optional[int]:
        """The strongest tier of ``actor``'s claim on ``synonym``; ``None`` when it has none."""
        claim = self._by_key.get(synonym, {}).get(actor)
        return claim[0] if claim is not None else None


def _anchor_attack_groups(
    records: Sequence[GalaxyRecord],
    stats: BuildStats,
    revocations: Mapping[str, str],
    loaded: Sequence[LoadedAttackGroup],
) -> Tuple[Dict[str, _Actor], List[GalaxyRecord]]:
    """Rule 1. Returns the ATT&CK actors by key and the records left for rule 2."""
    by_id: Dict[str, List[GalaxyRecord]] = defaultdict(list)
    for r in records:
        if r.mitre_attack:
            by_id[r.mitre_attack].append(r)

    def final(attack_id: str) -> str:
        seen = [attack_id]
        while attack_id in revocations:
            attack_id = revocations[attack_id]
            if attack_id in seen:
                raise ReferenceInputError(f"ATT&CK revocations form a cycle: {' -> '.join(seen + [attack_id])}")
            seen.append(attack_id)
        return attack_id

    groups: Dict[str, _Actor] = {}
    for attack_id in sorted(by_id):
        members = sorted(by_id[attack_id], key=lambda r: (_galaxy_rank(r.galaxy), r.name, r.source_record))
        mitre_records = [r for r in members if r.galaxy == MITRE_GALAXY]
        if mitre_records:
            head = mitre_records[0]
        else:
            head = members[0]
            stats.attack_ids_without_mitre_record.append(attack_id)
        groups[attack_id] = _Actor(key=head.key, name=head.name, mitre_attack=attack_id)

    key_owner: Dict[str, str] = {}
    for attack_id, actor in groups.items():
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
        if other is not None and final(other) != final(r.mitre_attack):
            stats.anchor_conflicts.append(
                {"record": r.source_record, "name": r.name, "mitre_attack": r.mitre_attack, "attack_name_of": other}
            )
            leftover.append(r)
            continue
        groups[r.mitre_attack].records.append(r)
    for attack_id, actor in groups.items():
        for r in actor.records:
            if r.galaxy == MITRE_GALAXY and r.mitre_attack == attack_id:
                actor.attack_aliases.update(r.aliases)

    # Revoked groups fold into their successor.
    revoked_keys: Dict[str, str] = {}  # revoked group's key -> successor id
    for revoked_id in sorted(revocations):
        if revoked_id not in groups:
            continue
        successor_id = final(revoked_id)
        if successor_id not in groups:
            stats.revoked_without_successor.append(revoked_id)
            continue
        gone = groups.pop(revoked_id)
        target = groups[successor_id]
        target.records.extend(gone.records)
        target.revoked_names |= {gone.key} | gone.attack_aliases | gone.revoked_names
        target.revoked.extend([{"mitre_attack": revoked_id, "name": gone.name}] + gone.revoked)
        revoked_keys[gone.key] = successor_id
        stats.revoked_folds.append(
            {"revoked": revoked_id, "name": gone.name, "into": successor_id, "successor": target.key}
        )

    # The ATT&CK version EdgeGuard loaded: its names are what the graph holds.
    anchors: Dict[str, _Actor] = {actor.key: actor for actor in groups.values()}
    stats.loaded_groups = len(loaded)
    pending: List[LoadedAttackGroup] = []
    for g in loaded:
        matched = anchors.get(g.key)
        if matched is None:
            pending.append(g)
            continue
        matched.loaded = True
        matched.loaded_aliases.update(g.aliases)
        if g.attack_id and matched.mitre_attack and g.attack_id != matched.mitre_attack:
            stats.loaded_id_mismatches.append({"node": g.key, "galaxy": matched.mitre_attack, "loaded": g.attack_id})
    renamed: List[LoadedAttackGroup] = []
    for g in pending:
        revoked_into = revoked_keys.get(g.key)
        if revoked_into is None and g.attack_id is not None and g.attack_id in revocations:
            revoked_into = final(g.attack_id)
        if revoked_into is not None and revoked_into in groups:
            target = groups[revoked_into]
            target.revoked_names |= {g.key} | set(g.aliases)
            stats.loaded_revoked_nodes.append({"node": g.key, "successor": target.key})
            continue
        renamed.append(g)
    for g in renamed:
        same_id = groups.get(g.attack_id) if g.attack_id else None
        if same_id is not None and not same_id.loaded:
            # ATT&CK renamed the group: the loaded name is what EdgeGuard writes.
            old = same_id.key
            del anchors[old]
            same_id.key, same_id.name, same_id.loaded = g.key, g.name, True
            same_id.attack_aliases.add(old)
            same_id.loaded_aliases.update(g.aliases)
            anchors[g.key] = same_id
            stats.loaded_renamed.append({"mitre_attack": same_id.mitre_attack or "", "galaxy": old, "loaded": g.key})
            continue
        new_id = g.attack_id if g.attack_id and g.attack_id not in groups and g.attack_id not in revocations else None
        anchors[g.key] = _Actor(key=g.key, name=g.name, mitre_attack=new_id, loaded=True, loaded_aliases=set(g.aliases))
        stats.loaded_anchored.append({"key": g.key, "mitre_attack": new_id})
    stats.attack_groups = len(anchors)
    return anchors, leftover


def _join_or_standalone(
    anchors: Dict[str, _Actor], leftover: Sequence[GalaxyRecord], stats: BuildStats
) -> Dict[str, _Actor]:
    """Rule 2. Adds joined records to their ATT&CK actor; returns the standalone actors by key.

    A name is matched as it is first and then by its compact form (``compact_key``), so
    ``"SaintBear"`` joins ATT&CK's ``"Saint Bear"``."""
    exact: Dict[str, Dict[str, str]] = defaultdict(dict)  # name key -> anchor key -> how
    for anchor_key, actor in anchors.items():
        for alias in actor.attack_names():
            exact[alias].setdefault(anchor_key, "attack_alias")
        for r in actor.records:
            exact[r.key].setdefault(anchor_key, "record_name")
        exact[anchor_key][anchor_key] = "key"
    compact: Dict[str, Dict[str, str]] = defaultdict(dict)
    for name_key in sorted(exact):
        for anchor_key, how in exact[name_key].items():
            if compact[compact_key(name_key)].get(anchor_key) != "key":
                compact[compact_key(name_key)][anchor_key] = how

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
        # ATT&CK group G0118's own name although APT29 (G0016) lists it as an alias.
        by_key = [a for a, how in hits.items() if how == "key"]
        if by_key:
            hits = {by_key[0]: "key"}
        if len(hits) == 1:
            (anchor_key, how), *_ = hits.items()
            anchors[anchor_key].records.append(r)
            joined[how + (" (spacing)" if spacing else "")] += 1
            if spacing:
                stats.joined_by_spacing.append({"record": r.source_record, "name": r.name, "actor": anchor_key})
            continue
        if len(hits) > 1:
            stats.join_ambiguous.append({"record": r.source_record, "name": r.name, "candidates": sorted(hits)})
        if r.galaxy == _THREE_SIXTY_GALAXY:
            # The 360net-threat-actor galaxy names known groups in Chinese or by its own id
            # ("摩诃草 - APT-C-09"). A record that joins no ATT&CK actor would only add a key no
            # feed writes, and take English synonyms from the actors that own them ("sofacy group",
            # "hangover"); it is left out and listed in the report.
            stats.unjoined_360net.append({"record": r.source_record, "name": r.name})
            continue
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
        if actor.loaded:
            actor.origins.add(ORIGIN_MITRE_LOADED)
        if actor.revoked:
            actor.origins.add(ORIGIN_MITRE_REVOKED)
        revoked_ids = {r["mitre_attack"] for r in actor.revoked}
        for r in actor.records:
            actor.origins.add(r.origin)
            revoked_record = r.galaxy == MITRE_GALAXY and r.mitre_attack in revoked_ids
            origin = ORIGIN_MITRE_REVOKED if revoked_record else r.origin
            if r.key != actor.key:
                claims.add(r.key, actor.key, TIER_OWN_NAME, origin)
            attack_record = r.galaxy == MITRE_GALAXY and (revoked_record or r.mitre_attack == actor.mitre_attack)
            for alias_key in r.aliases:
                if alias_key != actor.key:
                    claims.add(alias_key, actor.key, TIER_OWN_NAME if attack_record else TIER_SYNONYM, origin)
        for alias in sorted(actor.loaded_aliases - {actor.key}):
            claims.add(alias, actor.key, TIER_LOADED_ATTACK, ORIGIN_MITRE_LOADED)
        for name in sorted(actor.revoked_names - {actor.key}):
            claims.add(name, actor.key, TIER_OWN_NAME, ORIGIN_MITRE_REVOKED)
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
    actors: Mapping[str, _Actor], ambiguous: Dict[str, Dict[str, Set[str]]], claims: _Claims, stats: BuildStats
) -> None:
    """Rule 5. A variant that another actor holds only by a plain galaxy synonym is ambiguous: the
    ATT&CK name it derives from and that synonym disagree ("winnti" of ATT&CK's "Winnti Group"
    against a galaxy synonym of APT41)."""
    owner: Dict[str, str] = {}
    for actor in actors.values():
        owner[actor.key] = actor.key
        for synonym in actor.synonyms:
            owner[synonym] = actor.key
    proposals: Dict[str, Set[str]] = defaultdict(set)
    contested: Dict[str, Set[str]] = defaultdict(set)  # variant -> the actors whose names give it
    for key in sorted(actors):
        actor = actors[key]
        bases = [actor.key] + sorted(a for a in actor.attack_names() if a in actor.synonyms)
        for base in bases:
            for variant in suffix_variants(base):
                if variant == actor.key:
                    continue
                shortened = not variant.endswith(NAME_SUFFIXES)
                if owner.get(variant) == actor.key:
                    if ORIGIN_SUFFIX not in actor.synonyms[variant]:
                        actor.synonyms[variant].add(ORIGIN_SUFFIX)
                        stats.suffix_also_existing += 1
                        if shortened:
                            stats.suffix_short_forms.append({"name": variant, "actor": actor.key, "rule": "already"})
                    continue
                holder = owner.get(variant)
                if holder is not None and holder != variant and claims.tier(variant, holder) == TIER_SYNONYM:
                    contested[variant].add(actor.key)
                    continue
                if variant in owner or variant in ambiguous:
                    stats.suffix_blocked += 1
                    if shortened:
                        stats.suffix_short_forms.append({"name": variant, "actor": actor.key, "rule": "blocked"})
                    continue
                proposals[variant].add(actor.key)
    for variant in sorted(contested):
        holder = owner[variant]
        claimants: Dict[str, Set[str]] = {holder: actors[holder].synonyms.pop(variant)}
        for proposer in sorted(contested[variant]):
            claimants[proposer] = {ORIGIN_SUFFIX}
        ambiguous[variant] = claimants
        stats.suffix_contested.append({"name": variant, "held_by": holder, "variant_of": sorted(contested[variant])})
        if not variant.endswith(NAME_SUFFIXES):
            stats.suffix_short_forms.extend(
                {"name": variant, "actor": p, "rule": "contested"} for p in sorted(contested[variant])
            )
    for variant in sorted(proposals):
        proposers = sorted(proposals[variant])
        shortened = not variant.endswith(NAME_SUFFIXES)
        if len(proposers) == 1:
            actors[proposers[0]].synonyms[variant] = {ORIGIN_SUFFIX}
            stats.suffix_added += 1
            if shortened:
                # A shortened name can be a common word ("medusa"): listed for review.
                stats.suffix_shortened.append({"name": variant, "actor": proposers[0]})
                stats.suffix_short_forms.append({"name": variant, "actor": proposers[0], "rule": "added"})
        else:
            ambiguous[variant] = {p: {ORIGIN_SUFFIX} for p in proposers}
            stats.suffix_ambiguous.append(variant)
            if shortened:
                stats.suffix_short_forms.extend({"name": variant, "actor": p, "rule": "ambiguous"} for p in proposers)


_KEY_STRENGTH = -1  # an actor key: stronger than every claim
_SUFFIX_STRENGTH = TIER_SYNONYM + 1  # a name only the suffix rule gives


def _settle_spelling_variants(
    actors: Mapping[str, _Actor], ambiguous: Dict[str, Dict[str, Set[str]]], claims: _Claims, stats: BuildStats
) -> None:
    """Rule 4 for names that differ only in spaces, hyphens, dots or underscores: rule 2 treats them
    as one name ("dark seoul" / "darkseoul"), so they cannot belong to two actors. When they do, the
    actor holding the strongest spelling keeps its spellings (an actor key, then a loaded ATT&CK
    alias, then a galaxy ATT&CK alias, revoked name or record name, then a galaxy synonym, then a
    suffix-rule name). Every other actor's spelling is ambiguous, and so is every spelling when no
    single actor holds the strongest one. An actor key always stays with its actor."""
    owner: Dict[str, str] = {}
    for actor in actors.values():
        owner[actor.key] = actor.key
        for synonym in actor.synonyms:
            owner[synonym] = actor.key

    def strength(name: str) -> int:
        holder = owner[name]
        if name == holder:
            return _KEY_STRENGTH
        tier = claims.tier(name, holder)
        return tier if tier is not None else _SUFFIX_STRENGTH

    def origins(name: str) -> Set[str]:
        holder = owner[name]
        return set(actors[holder].origins) if name == holder else set(actors[holder].synonyms[name])

    by_compact: Dict[str, List[str]] = defaultdict(list)
    for name in owner:
        by_compact[compact_key(name)].append(name)
    for compact in sorted(by_compact):
        names = sorted(by_compact[compact])
        holders = {owner[n] for n in names}
        if len(holders) < 2:
            continue
        best = min(strength(n) for n in names)
        best_holders = {owner[n] for n in names if strength(n) == best}
        keep = next(iter(best_holders)) if len(best_holders) == 1 else None
        claimants: Dict[str, Set[str]] = defaultdict(set)
        for n in names:
            claimants[owner[n]] |= origins(n)
        for n in names:
            holder = owner[n]
            if n == holder or holder == keep:
                continue
            actors[holder].synonyms.pop(n)
            ambiguous[n] = {a: set(o) for a, o in sorted(claimants.items())}
            stats.spelling_variants_ambiguous.append(
                {"name": n, "held_by": holder, "spellings": {m: owner[m] for m in names}, "kept_by": keep}
            )


def _apply_overrides(
    actors: Dict[str, _Actor],
    ambiguous: Dict[str, Dict[str, Set[str]]],
    never_merge: Dict[str, Dict[str, Any]],
    pairs: List[Dict[str, Any]],
    decisions: Sequence[OverrideDecision],
    stats: BuildStats,
) -> None:
    """Rule 6: never_merge with an actor, merges, never_merge, display names. Every decision is
    recorded with its effect."""

    def owner_of(key: str) -> Optional[str]:
        if key in actors:
            return key
        for actor in actors.values():
            if key in actor.synonyms:
                return actor.key
        return None

    kept_away: Dict[str, Dict[str, Set[str]]] = {}  # name -> actor it is kept away from -> its claim
    pair_decisions = [d for d in decisions if d.kind == "never_merge" and d.actor]
    for d in pair_decisions:
        if d.actor not in actors:
            raise ReferenceInputError(f"override never_merge with actor {d.actor!r}: no actor has that key")
        effects: List[str] = []
        for name in d.names:
            k = actor_key(name)
            if k == d.actor:
                raise ReferenceInputError(f"override never_merge {k!r}: it is the key of {d.actor!r}")
            claim: Set[str] = set()
            if k in actors[d.actor].synonyms:
                claim = actors[d.actor].synonyms.pop(k)
                effects.append(f"{k!r} taken from {d.actor!r} ({', '.join(sorted(claim))})")
            elif k in ambiguous and d.actor in ambiguous[k]:
                claim = ambiguous[k].pop(d.actor)
                effects.append(f"{d.actor!r} no longer claims ambiguous {k!r}")
            else:
                effects.append(f"{k!r} is not {d.actor!r}'s")
            kept_away.setdefault(k, {})[d.actor] = claim
            pairs.append({"name": k, "actor": d.actor, "reason": d.reason, "date": d.date, "status": d.status})
        stats.overrides.append({**d.as_record(), "effect": effects})

    for d in (d for d in decisions if d.kind == "merge"):
        effects = []
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
                if folded.is_attack_group:
                    raise ReferenceInputError(
                        f"override merge: {k!r} is an ATT&CK group; ATT&CK groups are never merged"
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

    for d in (d for d in decisions if d.kind == "never_merge" and not d.actor):
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
            if actor.is_attack_group:
                raise ReferenceInputError(f"override canonical_name {d.into!r}: an ATT&CK group keeps its ATT&CK name")
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

    # A name kept away from an actor must not have come back to it; one that belongs to no actor
    # now is listed as never merged.
    pair_info = {(p["name"], p["actor"]): p for p in pairs}
    for k in sorted(kept_away):
        current = owner_of(k)
        for excluded in sorted(kept_away[k]):
            if current == excluded:
                raise ReferenceInputError(f"override: {k!r} is kept away from {excluded!r} but belongs to it")
        if current is None:
            claims = ambiguous.setdefault(k, {})
            for excluded, claim in kept_away[k].items():
                if claim and excluded in actors:
                    claims.setdefault(excluded, set()).update(claim)
            if k not in never_merge:
                first = pair_info[(k, sorted(kept_away[k])[0])]
                never_merge[k] = {
                    "reason": first["reason"],
                    "date": first["date"],
                    "status": first["status"],
                    "actor": first["actor"],
                }


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
    revocations: Optional[Mapping[str, str]] = None,
    loaded_attack: Sequence[LoadedAttackGroup] = (),
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
    anchors, leftover = _anchor_attack_groups(records, stats, revocations or {}, loaded_attack)
    standalone = _join_or_standalone(anchors, leftover, stats)

    actors: Dict[str, _Actor] = {}
    for actor in list(anchors.values()) + list(standalone.values()):
        if actor.key in actors:  # a standalone name equal to an ATT&CK key joined in rule 2
            raise AssertionError(f"duplicate actor key {actor.key!r}")
        actors[actor.key] = actor

    claims = _collect_claims(actors)
    ambiguous = _resolve_claims(actors, claims, stats)
    _apply_suffix_rule(actors, ambiguous, claims, stats)
    _settle_spelling_variants(actors, ambiguous, claims, stats)
    never_merge: Dict[str, Dict[str, Any]] = {}
    pairs: List[Dict[str, Any]] = []
    _apply_overrides(actors, ambiguous, never_merge, pairs, decisions, stats)
    _check_invariants(actors, ambiguous)

    actor_entries: List[Dict[str, Any]] = []
    revoked_entries: List[Dict[str, Any]] = []
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
        for revoked in actor.revoked:
            revoked_entries.append(
                {
                    "mitre_attack": revoked["mitre_attack"],
                    "name": revoked["name"],
                    "key": actor_key(revoked["name"]),
                    "revoked_into": actor.mitre_attack,
                    "actor": actor.key,
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
            "attack_groups": sum(1 for a in actor_entries if a["mitre_attack"] or ORIGIN_MITRE_LOADED in a["origins"]),
            "synonyms": sum(len(a["synonyms"]) for a in actor_entries),
            "ambiguous": len(ambiguous_entries),
        },
        "actors": actor_entries,
        "ambiguous": ambiguous_entries,
        "revoked_attack_groups": sorted(revoked_entries, key=lambda e: e["mitre_attack"]),
        "never_merge_pairs": sorted(pairs, key=lambda p: (p["name"], p["actor"])),
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


def load_graph_actors(doc: Any, mitre_source: str = MITRE_SOURCE) -> List[Dict[str, Any]]:
    """The rows of a graph export. ``attack_aliases`` (the aliases MITRE delivered) is required on
    every ATT&CK row; it is ``None`` when the node has no delivered record."""
    rows = doc.get("actors") if isinstance(doc, Mapping) else doc
    if not isinstance(rows, list):
        raise ReferenceInputError("graph actors: expected a list or an object with 'actors'")
    out = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            raise ReferenceInputError("graph actors: every row needs a 'name'")
        source = row.get("source")
        sources = [source] if isinstance(source, str) else [s for s in (source or []) if isinstance(s, str)]
        if mitre_source in sources and "attack_aliases" not in row:
            raise ReferenceInputError(
                f"graph actors: ATT&CK node {row['name']!r} has no 'attack_aliases'; the export predates "
                "them, re-export with --export-graph-actors"
            )
        attack_id = row.get("attack_id")
        attack_aliases = row.get("attack_aliases")
        out.append(
            {
                "name": row["name"],
                "aliases": [a for a in (row.get("aliases") or []) if isinstance(a, str)],
                "attack_aliases": (
                    [a for a in attack_aliases if isinstance(a, str)] if isinstance(attack_aliases, list) else None
                ),
                "source": sources,
                "relationships": int(row.get("relationships") or 0),
                "pulses": int(row.get("pulses") or 0),
                "malware": sorted({m for m in (row.get("malware") or []) if isinstance(m, str)}),
                "attack_id": attack_id if isinstance(attack_id, str) else None,
            }
        )
    return out


def graph_input_metadata(doc: Any, file_name: str, sha256: str, mitre_source: str = MITRE_SOURCE) -> Dict[str, Any]:
    rows = load_graph_actors(doc, mitre_source)
    attack = [r for r in rows if mitre_source in r["source"]]
    return {
        "role": "loaded_attack",
        "file": file_name,
        "sha256": sha256,
        "exported_at": doc.get("exported_at") if isinstance(doc, Mapping) else None,
        "threat_actor_nodes": len(rows),
        "attack_nodes": len(attack),
        "attack_nodes_with_id": sum(1 for r in attack if r["attack_id"]),
        "attack_nodes_with_delivered_aliases": sum(1 for r in attack if r["attack_aliases"] is not None),
        "used": "the names of the ATT&CK-sourced ThreatActor nodes, and the aliases and group ids of the "
        "records MITRE delivered for them (the ATT&CK version EdgeGuard loaded)",
    }


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
    mitre_source: str = MITRE_SOURCE,
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
            "never_merge_pairs": len(reference.get("never_merge_pairs", [])),
        },
        "rules": {
            "records_by_galaxy": dict(sorted(stats.records_by_galaxy.items())),
            "skipped_records": stats.skipped_records,
            "attack_ids_without_mitre_record": stats.attack_ids_without_mitre_record,
            "anchor_conflicts": stats.anchor_conflicts,
            "revoked_folds": stats.revoked_folds,
            "revoked_without_successor": stats.revoked_without_successor,
            "loaded_attack": {
                "groups": stats.loaded_groups,
                "revoked_nodes": stats.loaded_revoked_nodes,
                "renamed": stats.loaded_renamed,
                "anchored_by_name": stats.loaded_anchored,
                "id_mismatches": stats.loaded_id_mismatches,
            },
            "joined_by_name": stats.joined,
            "joined_by_spacing_variant": stats.joined_by_spacing,
            "join_ambiguous_records": stats.join_ambiguous,
            "unjoined_360net_records_left_out": stats.unjoined_360net,
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
                "contested_by_a_galaxy_synonym": stats.suffix_contested,
                "shortened_names": stats.suffix_shortened,
            },
            "spelling_variants_made_ambiguous": stats.spelling_variants_ambiguous,
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
    row_by_key = {r["key"]: r for r in rows}
    how_counts: Dict[str, int] = defaultdict(int)
    for row in rows:
        how_counts[row["how"]] += 1

    attack_nodes = {row["key"]: row for row in rows if mitre_source in row["source"]}
    attack_actors = {a["key"]: a for a in actors if a["mitre_attack"] or ORIGIN_MITRE_LOADED in a["origins"]}
    keys_not_on_graph = [
        {"mitre_attack": a["mitre_attack"], "key": k} for k, a in sorted(attack_actors.items()) if k not in attack_nodes
    ]
    nodes_not_keys = [
        {
            "graph_name": k,
            "resolves_to": node["resolves_to"],
            "how": node["how"],
            "relationships": node["relationships"],
            "revoked": any(r["key"] == k for r in reference.get("revoked_attack_groups", [])),
        }
        for k, node in sorted(attack_nodes.items())
        if k not in attack_actors
    ]

    # The pairs under the rule the actor alias merge applies (the same function the merge calls).
    pairs = reference_lookup.reference_merge_candidates(
        reference_lookup.validate_reference(reference, "built"), rows, mitre_source
    )
    groups: Dict[str, List[str]] = defaultdict(list)
    for dup, canonical in pairs:
        groups[canonical].append(dup)
    duplicate_groups = []
    for canonical, dups in groups.items():
        dups = sorted(dups, key=lambda k: (-row_by_key[k]["relationships"], k))
        duplicate_groups.append(
            {
                "canonical": canonical,
                "mitre_attack": by_key[canonical]["mitre_attack"],
                "attack_group": canonical in attack_actors,
                "duplicates": dups,
                "relationships_moved": sum(row_by_key[k]["relationships"] for k in dups),
                "relationships": row_by_key[canonical]["relationships"]
                + sum(row_by_key[k]["relationships"] for k in dups),
            }
        )
    duplicate_groups.sort(key=lambda g: (-len(g["duplicates"]), -g["relationships"], g["canonical"]))

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

    # ATT&CK aliases on the graph that the reference gives to another actor (or to none).
    alias_conflicts = []
    aliases_unknown = []
    for k, node in sorted(attack_nodes.items()):
        expected = node["resolves_to"]
        cleaned = (clean_synonym(a) for a in node["aliases"])
        for alias in sorted({key for status, key in cleaned if status in ("ok", "rewritten")}):
            if alias == k:
                continue
            res = resolve(index, alias)
            if res.how == "unresolved":
                aliases_unknown.append({"attack_node": k, "graph_alias": alias})
            elif res.actor != expected:
                alias_conflicts.append(
                    {
                        "attack_node": k,
                        "expected": expected,
                        "graph_alias": alias,
                        "reference": res.actor,
                        "how": res.how,
                    }
                )

    # Spelling variants: graph names and reference names that share a triage key but resolve
    # differently (or not at all). Listed for review, never merged by this rule.
    by_triage: Dict[str, Set[str]] = defaultdict(set)
    for name in set(row_by_key) | set(index):
        by_triage[triage_key(name)].add(name)
    spelling: List[Dict[str, Any]] = []
    for tkey, names in by_triage.items():
        if len(names) < 2 or not names & set(row_by_key):
            continue
        targets = {resolve(index, n).actor for n in names}
        if len(targets) < 2 and None not in targets:
            continue
        spelling.append(
            {
                "triage_key": tkey,
                "names": [
                    {
                        "name": n,
                        "graph_relationships": row_by_key[n]["relationships"] if n in row_by_key else None,
                        "resolves_to": resolve(index, n).actor,
                        "how": resolve(index, n).how,
                    }
                    for n in sorted(names)
                ],
            }
        )
    spelling.sort(key=lambda v: (-sum(int(n["graph_relationships"] or 0) for n in v["names"]), v["triage_key"]))

    shortened_on_graph = []
    for item in sorted(stats.suffix_short_forms, key=lambda i: (i["name"], i["actor"])):
        short_row = row_by_key.get(item["name"])
        if short_row is None:
            continue
        canonical_row = row_by_key.get(item["actor"])
        shared = (
            sorted(
                {_malware_key(m) for m in short_row["malware"]} & {_malware_key(m) for m in canonical_row["malware"]}
            )
            if canonical_row
            else []
        )
        shortened_on_graph.append(
            {
                "name": item["name"],
                "from": item["actor"],
                "suffix_rule": item["rule"],
                "resolves_to": short_row["resolves_to"],
                "how": short_row["how"],
                "relationships": short_row["relationships"],
                "pulses": short_row["pulses"],
                "canonical_relationships": canonical_row["relationships"] if canonical_row else None,
                "shared_malware": shared,
            }
        )

    report["graph"] = {
        "actors": len(rows),
        "attack_nodes": len(attack_nodes),
        "resolution": dict(sorted(how_counts.items())),
        "resolved": how_counts["key"] + how_counts["synonym"],
        "canonical_key_check": {
            "attack_keys_matching_graph": len(attack_actors) - len(keys_not_on_graph),
            "attack_keys_not_on_graph": keys_not_on_graph,
            "graph_attack_nodes_not_canonical_keys": nodes_not_keys,
        },
        "duplicate_groups": {
            "groups": len(duplicate_groups),
            "nodes_folded": len(pairs),
            "into_attack_groups": sum(1 for g in duplicate_groups if g["attack_group"]),
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
        "spelling_variants": spelling,
        "suffix_short_forms_on_graph": shortened_on_graph,
        "graph_attack_aliases_resolving_elsewhere": alias_conflicts,
        "graph_attack_aliases_unknown": aliases_unknown,
        "seed_decisions_on_graph": _decisions_on_graph(stats.overrides, rows, index),
    }
    return report


_SOFTWARE_ID_SUFFIX_RE = re.compile(r"\s+-\s+s\d{4}$")


def _malware_key(name: str) -> str:
    """A Malware node name without the ATT&CK software id some feeds append ("prestige - s1058")."""
    return _SOFTWARE_ID_SUFFIX_RE.sub("", name.strip().lower())


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
        names = [actor_key(n) for n in d.get("names", [])] + [d[k] for k in ("into", "actor") if d.get(k)]
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
        f"created by overrides {c['actors_created_by_overrides']}); synonyms {c['synonyms']}; "
        f"ambiguous {c['ambiguous']}; never_merge pairs {c['never_merge_pairs']}"
    )
    lines.append(f"  synonym origins: {json.dumps(c['synonyms_by_origin'])}")
    lines.append(f"  records by galaxy: {json.dumps(r['records_by_galaxy'])}; skipped {len(r['skipped_records'])}")
    for fold in r["revoked_folds"]:
        lines.append(
            f"  revoked ATT&CK group folded: {fold['revoked']} {fold['name']!r} -> {fold['into']} {fold['successor']!r}"
        )
    for revoked_id in r["revoked_without_successor"]:
        lines.append(f"  revoked ATT&CK group {revoked_id} kept: its successor is not in the galaxy")
    la = r["loaded_attack"]
    lines.append(
        f"  loaded ATT&CK version: {la['groups']} groups; revoked nodes {len(la['revoked_nodes'])}, renamed "
        f"{len(la['renamed'])}, anchored by name {[(a['key'], a['mitre_attack']) for a in la['anchored_by_name']]}, "
        f"id mismatches {la['id_mismatches']}"
    )
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
    if r["unjoined_360net_records_left_out"]:
        names = ", ".join(repr(i["name"]) for i in r["unjoined_360net_records_left_out"])
        lines.append(f"  360net-threat-actor records that join no ATT&CK actor, left out: {names}")
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
    for item in s["contested_by_a_galaxy_synonym"]:
        lines.append(
            f"  suffix rule, ambiguous: {item['name']!r} is a galaxy synonym of {item['held_by']!r} and a variant "
            f"of {', '.join(repr(a) for a in item['variant_of'])}"
        )
    for item in r["spelling_variants_made_ambiguous"]:
        kept = f"kept by {item['kept_by']!r}" if item["kept_by"] else "no single actor holds the strongest spelling"
        spellings = ", ".join(f"{name!r} ({holder})" for name, holder in sorted(item["spellings"].items()))
        lines.append(f"  spelling variant ambiguous: {item['name']!r} of {item['held_by']!r} — {spellings}; {kept}")
    lines.append("")
    lines.append(f"Override decisions ({len(report['overrides'])}):")
    for d in report["overrides"]:
        what = d.get("names") or [d.get("name")]
        target = f" -> {d['into']!r}" if d.get("into") else ""
        away = f" (from {d['actor']!r})" if d.get("actor") else ""
        key = f" {d['key']!r}" if d["decision"] == "canonical_name" else ""
        lines.append(f"  [{d['status']}] {d['decision']}{key} {what}{target}{away}: {'; '.join(d['effect'])}")
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
    lines.append(f"  ATT&CK canonical keys that are ATT&CK nodes: {k['attack_keys_matching_graph']}")
    for item in k["attack_keys_not_on_graph"]:
        lines.append(f"  ATT&CK group without a node: {item['mitre_attack']} {item['key']!r}")
    for item in k["graph_attack_nodes_not_canonical_keys"]:
        kind = "revoked group" if item["revoked"] else "not a canonical key"
        lines.append(
            f"  ATT&CK node {item['graph_name']!r} ({item['relationships']} rels) is a {kind}; "
            f"reference: {item['how']} {item['resolves_to']}"
        )
    d = g["duplicate_groups"]
    lines.append(
        f"  duplicate groups the merge would fold: {d['groups']} ({d['nodes_folded']} nodes; "
        f"{d['into_attack_groups']} into ATT&CK groups)"
    )
    for group in d["all"]:
        attack = f" {group['mitre_attack']}" if group["mitre_attack"] else ""
        lines.append(
            f"    {group['canonical']}{attack} <- {group['duplicates']} ({group['relationships_moved']} of "
            f"{group['relationships']} rels move)"
        )
    u = g["unresolved"]
    lines.append(f"  unresolved: {u['count']} names ({u['relationships']} relationships); top {min(top, u['count'])}:")
    for item in u["top"][:top]:
        lines.append(f"    {item['relationships']:5d} rels {item['pulses']:3d} pulses  {item['name']}")
    if u["suffix_variant_candidates"]:
        lines.append("  unresolved names whose base name resolves (review candidates):")
        for item in u["suffix_variant_candidates"]:
            lines.append(f"    {item['graph_name']!r} -> base {item['base']!r}: {item['how']} {item['resolves_to']}")
    lines.append(
        f"  spelling variants (same triage key, resolved differently or not at all): {len(g['spelling_variants'])}"
    )
    for item in g["spelling_variants"]:
        names = "; ".join(
            f"{n['name']} [{n['graph_relationships'] if n['graph_relationships'] is not None else '-'} rels, "
            f"{n['how']} {n['resolves_to'] or ''}]".replace(" ]", "]")
            for n in item["names"]
        )
        lines.append(f"    {item['triage_key']}: {names}")
    lines.append(f"  suffix-rule short forms that are graph names: {len(g['suffix_short_forms_on_graph'])}")
    for item in g["suffix_short_forms_on_graph"]:
        lines.append(
            f"    {item['name']!r} (from {item['from']!r}, {item['suffix_rule']}): {item['relationships']} rels, "
            f"{item['pulses']} pulses; "
            f"reference: {item['how']} {item['resolves_to']}; canonical node {item['canonical_relationships']} rels; "
            f"shared malware {item['shared_malware']}"
        )
    conflicts = g["graph_attack_aliases_resolving_elsewhere"]
    lines.append(
        f"  ATT&CK node aliases on the graph that the reference resolves elsewhere: {len(conflicts)} "
        f"(unknown to the reference: {len(g['graph_attack_aliases_unknown'])})"
    )
    for item in conflicts:
        lines.append(
            f"    {item['attack_node']} (expected {item['expected']}): {item['graph_alias']!r} -> "
            f"{item['how']} {item['reference']}"
        )
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- graph export (read-only)

# An ATT&CK node's ``aliases`` are not ATT&CK's alone: the sync accumulates every source's aliases
# on the node and the actor alias merge adds the names it folds in. The record MITRE delivered is
# kept on the node's SOURCED_FROM edge to the ATT&CK source (``raw_data``, written when the edge is
# created): its aliases are ATT&CK's own. Its ``description`` is ATT&CK's too since 2026-10 (MITRE's
# record ranks first, ``description_ranking``; ``description_source`` names it since 2026-10-16); a
# graph built before that may still hold
# the text of the feed merged last there, so the group link is read from the delivered record first.
_EXPORT_CYPHER = """
MATCH (a:ThreatActor)
OPTIONAL MATCH (a)-[sf:SOURCED_FROM]->(:Source {source_id: $mitre_source})
WITH a, head(collect(sf.raw_data)) AS attack_raw
RETURN a.name AS name, a.aliases AS aliases, a.source AS source,
       COUNT { (a)--() } AS relationships,
       COUNT { UNWIND coalesce(a.pulse_ids, []) AS p RETURN DISTINCT p } AS pulses,
       [(m:Malware)-[:ATTRIBUTED_TO]->(a) | m.name] + [(a)-[:USES_MALWARE]->(m:Malware) | m.name] AS malware,
       CASE WHEN $mitre_source IN coalesce(a.source, []) THEN left(coalesce(a.description, ''), 300) END AS attack_description,
       CASE WHEN $mitre_source IN coalesce(a.source, []) THEN attack_raw END AS attack_raw
ORDER BY name
"""


def _http_query(
    statement: str, parameters: Optional[Mapping[str, Any]] = None, timeout: int = 300
) -> Tuple[str, List[Dict[str, Any]]]:
    base = (os.getenv("NEO4J_HTTP_URL") or os.getenv("NEO4J_HTTP") or "https://neo4j.edgeguard.org").rstrip("/")
    url = f"{base}/db/{os.getenv('NEO4J_DATABASE', 'neo4j')}/query/v2"
    auth = f"{os.getenv('NEO4J_USER', 'neo4j')}:{os.getenv('NEO4J_PASSWORD', '')}"
    body = json.dumps({"statement": statement, "parameters": dict(parameters or {}), "accessMode": "Read"}).encode()
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


def attack_delivery(raw_data: Any) -> Tuple[Optional[List[str]], str]:
    """``(aliases, description)`` of the record MITRE delivered for an ATT&CK node (the JSON in its
    SOURCED_FROM edge's ``raw_data``); ``(None, "")`` when there is none or it is not readable."""
    if not isinstance(raw_data, str):
        return None, ""
    try:
        doc = json.loads(raw_data)
    except ValueError:
        return None, ""
    if not isinstance(doc, Mapping):
        return None, ""
    aliases = doc.get("aliases")
    description = doc.get("description")
    return (
        [a for a in aliases if isinstance(a, str)] if isinstance(aliases, list) else None,
        description if isinstance(description, str) else "",
    )


def export_rows(raw_rows: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Export rows from the query rows: malware names de-duplicated; for an ATT&CK node the aliases
    MITRE delivered (``attack_aliases``) and the ATT&CK group id its delivered description links to,
    else the id the node's description links to (no description is kept)."""
    rows = []
    for raw in raw_rows:
        attack_aliases, delivered_description = attack_delivery(raw.get("attack_raw"))
        match = _ATTACK_GROUP_URL_RE.search(delivered_description) or _ATTACK_GROUP_URL_RE.search(
            raw.get("attack_description") or ""
        )
        rows.append(
            {
                "name": raw.get("name"),
                "aliases": raw.get("aliases"),
                "attack_aliases": attack_aliases,
                "source": raw.get("source"),
                "relationships": raw.get("relationships"),
                "pulses": raw.get("pulses"),
                "malware": sorted({m for m in (raw.get("malware") or []) if isinstance(m, str)}),
                "attack_id": match.group(1) if match else None,
            }
        )
    return rows


def export_graph_actors(out: Path) -> int:
    url, raw_rows = _http_query(_EXPORT_CYPHER, {"mitre_source": MITRE_SOURCE})
    rows = export_rows(raw_rows)
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
    ap.add_argument("--attack-galaxy-raw", type=Path, help="raw mitre-intrusion-set galaxy dump (ATT&CK revocations)")
    ap.add_argument("--overrides", type=Path, default=DEFAULT_OVERRIDES)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--version", default=None, help="CalVer YYYY.MM.DD (default: today, UTC)")
    ap.add_argument(
        "--graph-actors",
        type=Path,
        help="graph export (from --export-graph-actors): the loaded ATT&CK version, and the report",
    )
    ap.add_argument("--unresolved-out", type=Path, help="write every unresolved graph name here (outside the repo)")
    ap.add_argument("--report-json", type=Path, help="write the full report as JSON here (outside the repo)")
    ap.add_argument("--top", type=int, default=50, help="unresolved names shown in the report (default 50)")
    ap.add_argument(
        "--export-graph-actors",
        type=Path,
        metavar="PATH",
        help="read the ThreatActor nodes from Neo4j (read-only) into PATH and exit",
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
        galaxy_meta = galaxy_input_metadata(galaxy_doc, args.galaxy.name, _sha256(args.galaxy))
        inputs: List[Dict[str, Any]] = [galaxy_meta]
        revocations: Dict[str, str] = {}
        if args.attack_galaxy_raw is not None:
            raw_sha = _sha256(args.attack_galaxy_raw)
            built_from = {
                f["sha256"] for g in galaxy_meta["galaxies"] if g["galaxy"] == MITRE_GALAXY for f in g["raw_files"]
            }
            if raw_sha not in built_from:
                raise ReferenceInputError(
                    f"{args.attack_galaxy_raw.name} is not the mitre-intrusion-set dump the galaxy export was built from"
                )
            revocations = load_revocations(_read_json(args.attack_galaxy_raw))
            inputs.append(
                {
                    "role": "attack_revocations",
                    "file": args.attack_galaxy_raw.name,
                    "sha256": raw_sha,
                    "revoked_groups": len(revocations),
                }
            )
        else:
            print("WARNING: no --attack-galaxy-raw: revoked ATT&CK groups are not folded", file=sys.stderr)
        graph_doc = _read_json(args.graph_actors) if args.graph_actors else None
        graph = load_graph_actors(graph_doc) if graph_doc is not None else None
        loaded = load_loaded_attack(graph) if graph is not None else []
        if graph_doc is not None and args.graph_actors is not None:
            inputs.append(graph_input_metadata(graph_doc, args.graph_actors.name, _sha256(args.graph_actors)))
        inputs.append(
            {
                "role": "overrides",
                "file": args.overrides.name,
                "sha256": _sha256(args.overrides),
                "decisions": sum(len(overrides_doc.get(k) or []) for k in ("merge", "never_merge", "canonical_name")),
            }
        )
        reference, stats = build_reference(
            galaxy_doc, overrides_doc, version=version, inputs=inputs, revocations=revocations, loaded_attack=loaded
        )
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
