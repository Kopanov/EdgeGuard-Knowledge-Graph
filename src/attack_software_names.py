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
  candidate read, the acceptance check);
* ``attack_software_id`` — the ATT&CK id of a MITRE ``Malware`` node, read from the record MITRE
  delivered (its ``SOURCED_FROM`` edge's ``raw_data``; the node has no ``mitre_id``);
* ``plan_twin_folds`` — which non-MITRE node folds into which MITRE node (the enrichment job
  ``merge_malware_attack_twins`` and ``scripts/verify_fresh_baseline.py``).

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


@dataclass(frozen=True)
class TwinFoldPlan:
    """What ``plan_twin_folds`` decided.

    ``pairs`` — ``(MITRE node name, twin name)``, sorted; ``no_target`` — twins no MITRE node matches
    (left as they are); ``ambiguous`` — twins whose id and base name lead to more than one MITRE node,
    with those nodes (skipped); ``candidates`` — the nodes that state an id at all.
    """

    pairs: List[Tuple[str, str]] = field(default_factory=list)
    no_target: List[str] = field(default_factory=list)
    ambiguous: List[Tuple[str, List[str]]] = field(default_factory=list)
    candidates: int = 0


def plan_twin_folds(
    twins: Iterable[Mapping[str, Any]],
    attack_ids: Mapping[str, Optional[str]],
    software_successors: Optional[Mapping[str, str]] = None,
) -> TwinFoldPlan:
    """The MITRE ``Malware`` node each twin folds into.

    ``twins`` — rows ``{"name", "aliases"}`` of non-MITRE ``Malware`` nodes; ``attack_ids`` — the MITRE
    ``Malware`` nodes, ``name → ATT&CK id`` (``None`` when the id cannot be read); ``software_successors``
    — revoked software id → successor (``attack_revoked``), applied to the twin's ids first.

    A MITRE node is a target when its id is one the twin states, or when its name is the twin's base
    name and its id is unknown or one the twin states (a name whose id contradicts the twin's is not the
    same software). One target: a pair. None: ``no_target``. Several: ``ambiguous``.
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
            no_target.append(twin)
        else:
            ambiguous.append((twin, sorted(targets)))
    return TwinFoldPlan(
        pairs=sorted(pairs), no_target=sorted(no_target), ambiguous=sorted(ambiguous), candidates=candidates
    )


__all__ = [
    "CYPHER_SOFTWARE_ID_SUFFIX",
    "CYPHER_SUFFIXED_NAME",
    "TwinFoldPlan",
    "attack_software_id",
    "plan_twin_folds",
    "software_id_claims",
    "split_attack_software_id",
]
