"""Canonical threat-actor reference: load, validate, resolve (2026-10).

``src/reference/canonical_threat_actors.json`` names the canonical actor for each threat-actor name
EdgeGuard may write. It is built by ``scripts/build_canonical_threat_actors.py`` from the MITRE
ATT&CK groups, the public MISP galaxies (CC0) and reviewed decisions, and versioned by date. The
actor alias merge (``enrichment_jobs.merge_alias_duplicate_actors``) uses it to fold duplicate
``ThreatActor`` nodes into their canonical node.

Every name in the file has one place: the key of one actor, a synonym of one actor, or an entry of
``ambiguous`` (a name that points to more than one actor, or was marked never_merge). A name is
looked up by the key EdgeGuard writes for it (``node_identity.canonicalize_merge_key``).

``EDGEGUARD_CANONICAL_THREAT_ACTORS`` overrides the path. A file that is missing, unreadable,
larger than ``MAX_REFERENCE_BYTES``, of another ``schema_version`` or inconsistent raises
``ReferenceUnavailable``; the merge then runs on ATT&CK aliases alone.

The reference is the reviewed authority on the names it lists: an ATT&CK-alias pair whose duplicate
it marks ambiguous or never_merge, or gives to another actor (or to itself), is not merged.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from node_identity import canonicalize_merge_key, is_placeholder_name

REFERENCE_PATH_ENV = "EDGEGUARD_CANONICAL_THREAT_ACTORS"
DEFAULT_REFERENCE_PATH = Path(__file__).resolve().parent / "reference" / "canonical_threat_actors.json"
MITRE_SOURCE = "mitre_attck"  # SOURCE_TAGS["mitre"]: ATT&CK-sourced nodes are never duplicates
SCHEMA_VERSION = 1  # the file layout this module reads
MAX_REFERENCE_BYTES = 16 * 1024 * 1024  # the shipped file is about 0.7 MB

_VERSION_RE = re.compile(r"([0-9]{4})\.([0-9]{2})\.([0-9]{2})")  # used with fullmatch: ASCII digits only


class ReferenceUnavailable(Exception):
    """The reference cannot be used; the message says why."""


def name_key(name: Any) -> str:
    """The ``ThreatActor`` key EdgeGuard writes for ``name`` (NFC, trimmed, lower-case); ``""`` for
    a non-string."""
    if not isinstance(name, str):
        return ""
    value = canonicalize_merge_key("ThreatActor", {"name": name}).get("name")
    return value if isinstance(value, str) else ""


@dataclass(frozen=True)
class CanonicalReference:
    version: str
    path: str
    actor_count: int
    owners: Mapping[str, str]  # name key -> canonical key (an actor key maps to itself)
    blocked: FrozenSet[str]  # ambiguous or never_merge: never resolved
    attack_actors: FrozenSet[str] = field(default_factory=frozenset)

    def canonical_for(self, name: Any) -> Optional[str]:
        """The canonical key of ``name``, or ``None`` when it is unknown, ambiguous or never_merge."""
        key = name_key(name)
        if not key or key in self.blocked:
            return None
        return self.owners.get(key)


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReferenceUnavailable(reason)


def _normalised(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == name_key(value) and not is_placeholder_name(value)


def validate_reference(doc: Any, path: str = "") -> CanonicalReference:
    """Check the reference's structure and that every name has exactly one place."""
    _require(isinstance(doc, Mapping), "not a JSON object")
    schema = doc.get("schema_version")
    _require(
        type(schema) is int and schema == SCHEMA_VERSION,
        f"schema_version {schema!r} is not {SCHEMA_VERSION}",
    )
    version = doc.get("version")
    match = _VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    _require(match is not None, f"version {version!r} is not CalVer YYYY.MM.DD")
    assert match is not None
    try:
        _dt.date(int(match[1]), int(match[2]), int(match[3]))
    except ValueError:
        raise ReferenceUnavailable(f"version {version!r} is not a date") from None
    actors = doc.get("actors")
    _require(isinstance(actors, list) and bool(actors), "no actors")
    owners: Dict[str, str] = {}
    attack: Set[str] = set()
    keys: Set[str] = set()
    for actor in actors:
        _require(isinstance(actor, Mapping), "an actor entry is not an object")
        key = actor.get("key")
        _require(_normalised(key), f"actor key {key!r} is not normalised")
        _require(key not in keys, f"actor key {key!r} appears twice")
        keys.add(key)
        if actor.get("mitre_attack") or "mitre_loaded" in (actor.get("origins") or []):
            attack.add(key)
    for actor in actors:
        key = actor["key"]
        synonyms = actor.get("synonyms")
        _require(isinstance(synonyms, list), f"actor {key!r} has no synonym list")
        for synonym in synonyms:
            _require(_normalised(synonym), f"synonym {synonym!r} of {key!r} is not normalised")
            _require(synonym not in keys, f"synonym {synonym!r} of {key!r} is the key of an actor")
            _require(synonym not in owners, f"synonym {synonym!r} belongs to {owners.get(synonym)!r} and {key!r}")
            owners[synonym] = key
    owners.update({k: k for k in keys})
    blocked: Set[str] = set()
    ambiguous = doc.get("ambiguous")
    _require(isinstance(ambiguous, list), "no ambiguous list")
    for entry in ambiguous:
        _require(isinstance(entry, Mapping), "an ambiguous entry is not an object")
        key = entry.get("key")
        _require(_normalised(key), f"ambiguous name {key!r} is not normalised")
        _require(key not in owners, f"ambiguous name {key!r} belongs to actor {owners.get(key)!r}")
        _require(key not in blocked, f"ambiguous name {key!r} appears twice")
        blocked.add(key)
    return CanonicalReference(
        version=str(version),
        path=path,
        actor_count=len(keys),
        owners=owners,
        blocked=frozenset(blocked),
        attack_actors=frozenset(attack),
    )


def load_canonical_reference(path: Union[str, Path, None] = None) -> CanonicalReference:
    """Load and validate the reference (``path``, else ``EDGEGUARD_CANONICAL_THREAT_ACTORS``, else
    the file shipped in ``src/reference/``). Raises ``ReferenceUnavailable``."""
    chosen = Path(path or os.getenv(REFERENCE_PATH_ENV) or DEFAULT_REFERENCE_PATH)
    try:
        if not chosen.is_file():
            if chosen.exists():
                raise ReferenceUnavailable(f"{chosen} is not a regular file")
            raise FileNotFoundError(chosen)
        size = chosen.stat().st_size
        if size > MAX_REFERENCE_BYTES:
            raise ReferenceUnavailable(f"{chosen} has {size} bytes, more than {MAX_REFERENCE_BYTES}")
        with chosen.open(encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise ReferenceUnavailable(f"{chosen} not found") from None
    except (OSError, ValueError) as exc:
        raise ReferenceUnavailable(f"cannot read {chosen}: {exc}") from None
    try:
        return validate_reference(doc, str(chosen))
    except ReferenceUnavailable as exc:
        raise ReferenceUnavailable(f"{chosen}: {exc}") from None


def _sources(value: Any) -> List[str]:
    """A node's ``source`` as a list of strings: a scalar string is one source; any other value
    (an APOC merge can leave odd types) holds none."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [s for s in value if isinstance(s, str)]
    return []


def reference_merge_candidates(
    reference: CanonicalReference,
    graph_actors: Iterable[Mapping[str, Any]],
    mitre_source: str = MITRE_SOURCE,
) -> List[Tuple[str, str]]:
    """``(duplicate name, canonical key)`` pairs the reference gives the alias merge.

    ``graph_actors`` are the graph's ``ThreatActor`` nodes (``name``, ``source``). A node is a
    duplicate when it is not ATT&CK-sourced and its name resolves, unambiguously and not
    never_merge, to a canonical key other than its own, and a node with that key exists. Each pair
    carries the duplicate's name as stored, which the merge matches on."""
    rows = [r for r in graph_actors if isinstance(r.get("name"), str)]
    on_graph = {r["name"] for r in rows}
    pairs: Set[Tuple[str, str]] = set()
    for row in rows:
        if mitre_source in _sources(row.get("source")):
            continue
        name = row["name"]
        if is_placeholder_name(name):
            continue
        canonical = reference.canonical_for(name)
        if canonical is None or canonical == name_key(name) or canonical not in on_graph:
            continue
        pairs.add((name, canonical))
    return sorted(pairs)


@dataclass
class MergePlan:
    """What the alias merge does in one run."""

    pairs: List[Tuple[str, str]]  # (canonical, duplicate), sorted
    reference_canonicals: List[str]  # canonicals that only the reference may name (passed to APPLY)
    reference_pairs: List[Tuple[str, str]] = field(default_factory=list)  # (duplicate, canonical) kept
    from_attack: int = 0
    from_reference: int = 0
    ambiguous: List[Tuple[str, List[str]]] = field(default_factory=list)  # (duplicate, canonicals)
    conflicts: List[Tuple[str, List[str]]] = field(default_factory=list)  # (duplicate, canonicals)
    chains: List[Tuple[str, str]] = field(default_factory=list)  # (duplicate, canonical) skipped
    blocked: List[Tuple[str, str]] = field(default_factory=list)  # (duplicate, ATT&CK canonical) skipped

    @property
    def candidates(self) -> int:
        return len(self.pairs) + len(self.ambiguous) + len(self.conflicts) + len(self.chains) + len(self.blocked)


def plan_alias_merges(
    attack_rows: Iterable[Mapping[str, Any]],
    reference_pairs: Sequence[Tuple[str, str]],
    reference: Optional[CanonicalReference] = None,
) -> MergePlan:
    """Combine the two rules' candidates into the pairs to merge.

    ``attack_rows`` are the ATT&CK-alias candidates (``duplicate_name``, ``canonical_names``); a
    duplicate that is an alias of more than one ATT&CK node is ambiguous. ``reference_pairs`` come
    from ``reference_merge_candidates``. A duplicate the two rules give different canonicals is a
    conflict, and a node that would be both a canonical and a duplicate in this run is not merged
    as a duplicate (no chains, no cycles). Skipped pairs are listed, never merged.

    With ``reference``, the reviewed reference also checks the ATT&CK-alias pairs. A canonical's
    ``aliases`` hold ATT&CK's aliases and every name merged into it, so the ATT&CK rule alone
    would keep folding a name a reviewer has since marked never_merge. A pair whose duplicate the
    reference marks ambiguous or never_merge is ``blocked``. A pair whose duplicate it gives to
    another actor, or keeps as an actor of its own, is a conflict. A name the reference does not
    list is left to the ATT&CK rule."""
    proposals: Dict[str, Dict[str, Set[str]]] = {}  # duplicate -> canonical -> rules
    ambiguous: List[Tuple[str, List[str]]] = []
    blocked: List[Tuple[str, str]] = []
    for row in attack_rows:
        duplicate = row.get("duplicate_name")
        canonicals = sorted({c for c in (row.get("canonical_names") or []) if c})
        if not duplicate or not canonicals:
            continue
        if len(canonicals) > 1:
            ambiguous.append((duplicate, canonicals))
            continue
        canonical = canonicals[0]
        if reference is not None:
            duplicate_key = name_key(duplicate)
            if duplicate_key in reference.blocked:
                blocked.append((duplicate, canonical))
                continue
            owner = reference.owners.get(duplicate_key)
            if owner is not None and owner != name_key(canonical):
                # The reference's own answer competes with the ATT&CK rule's: a conflict below.
                proposals.setdefault(duplicate, {}).setdefault(owner, set()).add("reference")
        proposals.setdefault(duplicate, {}).setdefault(canonical, set()).add("attack")
    ambiguous_names = {d for d, _ in ambiguous}
    for duplicate, canonical in reference_pairs:
        if duplicate in ambiguous_names:
            # ATT&CK lists the name under several groups: the reference does not settle it.
            ambiguous = [(d, sorted(set(c) | {canonical})) if d == duplicate else (d, c) for d, c in ambiguous]
            continue
        proposals.setdefault(duplicate, {}).setdefault(canonical, set()).add("reference")

    conflicts = sorted((d, sorted(c)) for d, c in proposals.items() if len(c) > 1)
    single = {d: next(iter(c.items())) for d, c in proposals.items() if len(c) == 1}
    canonical_names = {canonical for canonical, _ in single.values()}
    chains = sorted((d, c) for d, (c, _) in single.items() if d in canonical_names)
    chained = {d for d, _ in chains}
    kept = {d: (c, rules) for d, (c, rules) in single.items() if d not in chained}
    reference_kept = sorted((d, c) for d, (c, rules) in kept.items() if "reference" in rules)
    return MergePlan(
        pairs=sorted((c, d) for d, (c, _) in kept.items()),
        reference_canonicals=sorted({c for _, c in reference_kept}),
        reference_pairs=reference_kept,
        from_attack=sum(1 for _, rules in kept.values() if "attack" in rules),
        from_reference=len(reference_kept),
        ambiguous=sorted(ambiguous),
        conflicts=conflicts,
        chains=chains,
        blocked=sorted(blocked),
    )


__all__ = [
    "DEFAULT_REFERENCE_PATH",
    "MAX_REFERENCE_BYTES",
    "MITRE_SOURCE",
    "REFERENCE_PATH_ENV",
    "SCHEMA_VERSION",
    "CanonicalReference",
    "MergePlan",
    "ReferenceUnavailable",
    "load_canonical_reference",
    "name_key",
    "plan_alias_merges",
    "reference_merge_candidates",
    "validate_reference",
]
