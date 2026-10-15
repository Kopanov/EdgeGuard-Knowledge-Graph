"""ATT&CK software ids in malware family names (2026-10).

OTX pulses name malware families the way the MISP ATT&CK galaxy names its clusters, with the
ATT&CK software id as a suffix: ``"Cobalt Strike - S0154"``, ``"njRAT - S0385"``. The collector
passed those names through unchanged, ``merge_malware`` only lowercases, and every one became a
``Malware`` node of its own (``cobalt strike - s0154``) beside the node ATT&CK delivered
(``cobalt strike``). On the graph of 2026-10-14 there were 136 such twins holding 16,005
``INDICATES`` links; the ATT&CK Cobalt Strike node showed 55 indicators instead of about 2,078.

This module holds what every site needs to treat such a name as the family it names:

* ``split_attack_software_id`` — the base name and the id of a suffixed name (the collectors and the
  MISP→Neo4j sync name the node by the base and keep the original string as an alias);
* ``CYPHER_SOFTWARE_ID_SUFFIX`` / ``CYPHER_SUFFIXED_NAME`` — the same rule as Java regular expressions
  for Cypher (``apoc.text.replace`` and ``=~``), passed as query parameters so no escaping is needed
  inside ``apoc.periodic.iterate`` statements (``build_relationships`` steps 9b / 2d, the twin merge's
  candidate read and merge statement, the acceptance checks);
* ``cypher_family_name_variants`` / ``folded_family_names`` — how steps 9b / 2d (and the acceptance
  check that mirrors 9b) find the ``Malware`` node of a family name: as given, without the id, and
  through the names the twin merge folded into a node (``merged_from``);
* ``attack_software_id`` — the ATT&CK id of a MITRE ``Malware`` node, read from the record MITRE
  delivered (its ``SOURCED_FROM`` edge's ``raw_data``; the node has no ``mitre_id``);
* ``plan_twin_folds`` — which non-MITRE node folds into which node: the MITRE node of its id or base
  name, else the non-MITRE node of its base name (the enrichment job ``merge_malware_attack_twins`` and
  ``scripts/verify_fresh_baseline.py``).

Standard library only: ``scripts/verify_fresh_baseline.py`` imports this module outside the
pipeline's environment.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

# A trailing ATT&CK software id: whitespace, a hyphen, whitespace, ``S`` and four digits. ASCII
# whitespace only (``re.ASCII``), the set Java's ``\s`` matches, so the Cypher patterns below decide
# exactly as this one does. The base must end with a non-space character: ``" - S0154"`` alone is
# not a family name.
_SUFFIXED_NAME_RE = re.compile(r"^(?P<base>.*\S)\s+-\s+(?P<id>S[0-9]{4})\s*$", re.IGNORECASE | re.ASCII | re.DOTALL)

# Java regular expressions with the same meaning, for Cypher. ``CYPHER_SOFTWARE_ID_SUFFIX`` is
# removed with ``apoc.text.replace`` (the base name remains); ``CYPHER_SUFFIXED_NAME`` is a full match
# for ``=~`` (a name that carries an id).
CYPHER_SOFTWARE_ID_SUFFIX = r"(?i)(?<=\S)\s+-\s+S[0-9]{4}\s*$"
CYPHER_SUFFIXED_NAME = r"(?is).*\S\s+-\s+S[0-9]{4}\s*"

# The ``Malware`` nodes that hold folded names (``merged_from``, written only by the merge jobs) and the
# MITRE-sourced ones, whose names are never redirected: ``folded_family_names`` turns the rows into the
# ``$folded_families`` map of steps 9b / 2d. Parameter: ``$mitre_source``.
CYPHER_FOLDED_FAMILIES_READ = (
    "MATCH (m:Malware) WHERE m.merged_from IS NOT NULL OR $mitre_source IN coalesce(m.source, []) "
    "RETURN m.name AS name, m.merged_from AS merged_from, $mitre_source IN coalesce(m.source, []) AS mitre"
)

# The non-MITRE ``Malware`` nodes named by the base name of a twin (``twin_base_names``): the node a
# twin without a MITRE target folds into. Parameters: ``$bases``, ``$mitre_source``. No APOC: a scalar
# ``aliases`` is read as a list in Python.
CYPHER_BASE_NODES_READ = (
    "MATCH (b:Malware) WHERE b.name IN $bases AND NOT $mitre_source IN coalesce(b.source, []) "
    "RETURN b.name AS name, b.aliases AS aliases"
)


def cypher_family_name_variants(var: str) -> str:
    """Cypher list: the ``Malware`` names under which the canonical family name ``var`` is found.

    The name as given and, when it ends with an ATT&CK software id, the name without it
    (``"cobalt strike - s0154"`` → ``"cobalt strike"``); each replaced by the node it was folded into
    when the twin merge folded a node of that name (``$folded_families``, ``folded_family_names``:
    ``"agenttesla"`` → ``"agent tesla"``). De-duplicated. Reads the ``$software_id_suffix`` and
    ``$folded_families`` parameters; double quotes only, as the statements of ``apoc.periodic.iterate``
    are wrapped in single quotes.
    """
    return (
        f'apoc.coll.toSet([_fv IN [{var}, trim(apoc.text.replace({var}, $software_id_suffix, ""))] '
        "| coalesce($folded_families[_fv], _fv)])"
    )


# The link every ATT&CK software description opens with: ``[Cobalt Strike](https://attack.mitre.org/
# software/S0154)``.
_ATTACK_SOFTWARE_LINK_RE = re.compile(
    r"\[([^\]]+)\]\(https?://attack\.mitre\.org/software/(S[0-9]{4})/?\)", re.IGNORECASE
)


def split_attack_software_id(name: Any) -> Tuple[str, Optional[str]]:
    """``(base name, ATT&CK id)`` of a family name that ends with an ATT&CK software id.

    ``"Cobalt Strike - S0154"`` → ``("Cobalt Strike", "S0154")``; case and surrounding whitespace are
    ignored (``"njrat  -  s0385 "`` → ``("njrat", "S0385")``) and the id is returned upper-case. A name
    without an id comes back stripped with ``None``; a non-string comes back as ``("", None)``.
    """
    if not isinstance(name, str):
        return "", None
    text = name.strip()
    match = _SUFFIXED_NAME_RE.match(text)
    if match is None:
        return text, None
    return match.group("base").strip(), match.group("id").upper()


def _canonical(name: Any) -> str:
    """The ``Malware`` merge key of ``name`` (NFC, stripped, lower-case: ``canonicalize_merge_key``)."""
    if not isinstance(name, str):
        return ""
    return unicodedata.normalize("NFC", name).strip().lower()


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def attack_software_id(raw_data: Any, name: Any = None) -> Optional[str]:
    """The ATT&CK software id of a MITRE ``Malware`` node, from the record MITRE delivered.

    ``raw_data`` is the JSON on the node's ``SOURCED_FROM`` edge to the ATT&CK source (written when the
    edge is created, so another feed cannot change it); its ``description`` is ATT&CK's, which opens with
    a link to the software itself. The link whose text is the node's ``name`` decides; without a
    ``name``, or when no link carries it, a link at the very start of the description does. ``None``
    when there is no readable record or no such link.
    """
    if not isinstance(raw_data, str):
        return None
    try:
        document = json.loads(raw_data)
    except ValueError:
        return None
    description = document.get("description") if isinstance(document, Mapping) else None
    if not isinstance(description, str):
        return None
    wanted = _canonical(name)
    if wanted:
        for match in _ATTACK_SOFTWARE_LINK_RE.finditer(description):
            if _canonical(match.group(1)) == wanted:
                return match.group(2).upper()
    opening = _ATTACK_SOFTWARE_LINK_RE.match(description.lstrip())
    return opening.group(2).upper() if opening else None


def software_id_claims(name: Any, aliases: Any = None) -> List[Tuple[str, str]]:
    """``(canonical base name, ATT&CK id)`` pairs a ``Malware`` node states about itself.

    Its name, when the name ends with an id; and every alias that ends with an id and whose base is the
    node's own name (the original string a collector keeps when it names the node by the base). An
    alias naming another family is not a claim about this node.
    """
    claims: List[Tuple[str, str]] = []
    own = _canonical(name)
    base, sid = split_attack_software_id(name)
    if sid:
        claims.append((_canonical(base), sid))
    for alias in _as_list(aliases):
        alias_base, alias_id = split_attack_software_id(alias)
        if alias_id and own and _canonical(alias_base) == own and (own, alias_id) not in claims:
            claims.append((own, alias_id))
    return claims


def folded_family_names(rows: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    """``{folded name → name of the Malware node it was folded into}`` for steps 9b / 2d.

    ``rows`` — ``{"name", "merged_from", "mitre"}`` of ``Malware`` nodes (``CYPHER_FOLDED_FAMILIES_READ``).
    Every ``merged_from`` entry names a node the twin merge folded into this one; an entry that carries
    an ATT&CK software id also stands for its base name, which the collectors write since 2026-10
    (``"agenttesla - s0331"`` folded into ``agent tesla`` → ``"agenttesla"`` too). A folded node is
    gone, and a later pulse that names the family is a MISP cross-event duplicate, so without this map
    its indicators would find no node. ``merged_from`` is written only by the merge jobs, unlike
    ``aliases``, which every source writes (PR-N14). A name that leads to two nodes, or that is the
    name of a MITRE-sourced node, is left out: an ATT&CK node is never redirected.
    """
    mitre_names: Set[str] = set()
    targets: Dict[str, Set[str]] = {}
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        own = _canonical(name)
        if row.get("mitre"):
            mitre_names.add(own)
        for entry in _as_list(row.get("merged_from")):
            for key in {_canonical(entry), _canonical(split_attack_software_id(entry)[0])}:
                if key and key != own:
                    targets.setdefault(key, set()).add(name)
    return {
        key: next(iter(nodes)) for key, nodes in sorted(targets.items()) if len(nodes) == 1 and key not in mitre_names
    }


def twin_base_names(twins: Iterable[Mapping[str, Any]]) -> List[str]:
    """The canonical base names of the rows named with an ATT&CK software id, sorted: the names
    ``CYPHER_BASE_NODES_READ`` looks up (``"mimikatz - s0002"`` → ``"mimikatz"``)."""
    bases: Set[str] = set()
    for row in twins:
        base, sid = split_attack_software_id(row.get("name"))
        if sid and base:
            bases.add(_canonical(base))
    return sorted(bases)


@dataclass(frozen=True)
class TwinFoldPlan:
    """What ``plan_twin_folds`` decided.

    ``pairs`` — ``(MITRE node name, twin name)``, sorted; ``base_pairs`` — ``(non-MITRE node name, twin
    name)``, sorted: twins without a MITRE target that fold into the node named by their base name;
    ``no_target`` — twins with neither (left as they are); ``ambiguous`` — twins whose id and base name
    lead to more than one MITRE node, with those nodes (skipped); ``candidates`` — the nodes that state
    an id at all.
    """

    pairs: List[Tuple[str, str]] = field(default_factory=list)
    base_pairs: List[Tuple[str, str]] = field(default_factory=list)
    no_target: List[str] = field(default_factory=list)
    ambiguous: List[Tuple[str, List[str]]] = field(default_factory=list)
    candidates: int = 0


def plan_twin_folds(
    twins: Iterable[Mapping[str, Any]],
    attack_ids: Mapping[str, Optional[str]],
    software_successors: Optional[Mapping[str, str]] = None,
    base_nodes: Optional[Mapping[str, Any]] = None,
) -> TwinFoldPlan:
    """The node each twin folds into.

    ``twins`` — rows ``{"name", "aliases"}`` of non-MITRE ``Malware`` nodes; ``attack_ids`` — the MITRE
    ``Malware`` nodes, ``name → ATT&CK id`` (``None`` when the id cannot be read); ``software_successors``
    — revoked software id → successor (``attack_revoked``), applied to the twin's ids first;
    ``base_nodes`` — the non-MITRE ``Malware`` nodes named by a twin's base name, ``name → aliases``
    (``CYPHER_BASE_NODES_READ`` over ``twin_base_names``).

    A MITRE node is a target when its id is one the twin states, or when its name is the twin's base
    name and its id is unknown or one the twin states (a name whose id contradicts the twin's is not the
    same software). One target: a pair. Several: ``ambiguous``.

    None (2026-10): ATT&CK software without a MITRE ``Malware`` node, chiefly the ATT&CK tools. Since the
    collectors name a family by its base name, a later pulse creates the node ``mimikatz`` beside the
    twin ``mimikatz - s0002``, and steps 9b / 2d link indicators written before to both. A twin named
    with an id therefore folds into the non-MITRE node of its base name (``base_pairs``) when that node
    states no other id; twins of one base name that state different ids are not one software and fold
    nowhere. Otherwise the twin is ``no_target``.
    """
    successors = dict(software_successors or {})
    by_id: Dict[str, Set[str]] = {}
    for attack_name, attack_id in attack_ids.items():
        if attack_id:
            by_id.setdefault(str(attack_id).upper(), set()).add(attack_name)
    canonical_targets = {_canonical(n): n for n in attack_ids}

    pairs: List[Tuple[str, str]] = []
    no_target: List[str] = []
    ambiguous: List[Tuple[str, List[str]]] = []
    unresolved: List[Tuple[str, Set[str]]] = []
    candidates = 0
    seen: Set[str] = set()
    for row in twins:
        twin = row.get("name")
        if not isinstance(twin, str) or not twin.strip() or twin in seen or twin in attack_ids:
            continue
        claims = software_id_claims(twin, row.get("aliases"))
        if not claims:
            continue
        seen.add(twin)
        candidates += 1
        ids = {successors.get(sid, sid) for _base, sid in claims}
        targets: Set[str] = set()
        for sid in ids:
            targets |= by_id.get(sid, set())
        for base, _sid in claims:
            same_name = canonical_targets.get(base)
            if same_name is None:
                continue
            same_name_id = attack_ids.get(same_name)
            if same_name_id is None or str(same_name_id).upper() in ids:
                targets.add(same_name)
        if len(targets) == 1:
            pairs.append((next(iter(targets)), twin))
        elif not targets:
            unresolved.append((twin, ids))
        else:
            ambiguous.append((twin, sorted(targets)))

    # Twins without a MITRE target: the non-MITRE node of their base name, when it states no other id.
    by_base_name = {_canonical(n): n for n in (base_nodes or {}) if isinstance(n, str) and n.strip()}
    folding = {twin for _target, twin in pairs}
    groups: Dict[str, List[Tuple[str, Set[str]]]] = {}
    for twin, ids in unresolved:
        base, base_id = split_attack_software_id(twin)
        node = by_base_name.get(_canonical(base)) if base_id else None
        if node is None or node == twin or node in folding or node in attack_ids:
            no_target.append(twin)
            continue
        node_ids = {successors.get(s, s) for _base, s in software_id_claims(node, (base_nodes or {}).get(node))}
        if node_ids and not node_ids & ids:
            no_target.append(twin)  # the node of that name states another id: another software
            continue
        groups.setdefault(node, []).append((twin, ids | node_ids))
    base_pairs: List[Tuple[str, str]] = []
    for node, members in groups.items():
        if len(set().union(*(ids for _twin, ids in members))) > 1:
            no_target.extend(twin for twin, _ids in members)
        else:
            base_pairs.extend((node, twin) for twin, _ids in members)
    return TwinFoldPlan(
        pairs=sorted(pairs),
        base_pairs=sorted(base_pairs),
        no_target=sorted(no_target),
        ambiguous=sorted(ambiguous),
        candidates=candidates,
    )


__all__ = [
    "CYPHER_BASE_NODES_READ",
    "CYPHER_FOLDED_FAMILIES_READ",
    "CYPHER_SOFTWARE_ID_SUFFIX",
    "CYPHER_SUFFIXED_NAME",
    "TwinFoldPlan",
    "attack_software_id",
    "cypher_family_name_variants",
    "folded_family_names",
    "plan_twin_folds",
    "software_id_claims",
    "split_attack_software_id",
    "twin_base_names",
]
