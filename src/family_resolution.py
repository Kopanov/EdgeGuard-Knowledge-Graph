"""Which ``Malware`` nodes a feed's family label names (``build_relationships`` step 9).

ThreatFox (``malware_printable``), MalwareBazaar (``signature``) and Feodo Tracker (``malware``) label an
indicator with a malware family: ``Indicator.malware_family``, a string as the feed wrote it
(``"SalatStealer"``, ``"Cobalt Strike"``, ``"Venom RAT"``). The feed collectors create no ``Malware`` node,
so the label links only when another source (ATT&CK, OTX) created a node of that family. Step 9 links the
indicator to the nodes the label names (``INDICATES``, ``match_type`` ``malware_family``, 0.8).

The rule, decided once per run for every distinct label (``resolve_feed_families``):

1. exact: the label, stripped and lower-cased, equals the stripped, lower-cased name of a node or one of its
   aliases. Every such node is a target (``"Formbook"`` names the OTX node ``formbook`` and the ATT&CK node
   ``xloader``, whose alias it is);
2. only when the exact match finds no node: the label without separators (lower-case; whitespace, hyphens,
   underscores and dots removed, ``separator_free``) equals a node's name without separators. Names only,
   never aliases. One such node is the target (``"SalatStealer"`` → ``salat stealer``); several are none,
   and the label is reported as ambiguous (``ambiguous``).

A placeholder label (``"Unknown malware"``, ``"Unknown Loader"``: ``node_identity.is_placeholder_name``)
names no node, and a node whose name is a placeholder is never a target. A label that names no node stays
unlinked (``unresolved``): no node is created for it.

The result is a map keyed by the label exactly as stored (``targets``), passed to step 9 as
``$family_targets``: the step looks the label up as it is, so the case folding and trimming are decided
here only. The acceptance script (``scripts/verify_fresh_baseline.py``, check ``family_indicates_complete``)
resolves the labels with the same function and judges the links against the result.

``tool_named_malware`` lists the non-MITRE ``Malware`` nodes whose name without separators is the name of an
ATT&CK ``Tool`` (``asyncrat``, ``quasar rat`` beside the tools AsyncRAT and QuasarRAT): OTX pulses name tools
as malware families, and their indicators link to the ``Malware`` node only (acceptance check
``attack_tool_named_malware``, informational).

Standard library and ``node_identity`` only: ``scripts/verify_fresh_baseline.py`` imports this module outside
the pipeline's environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Set

from node_identity import is_placeholder_name

# The source id of the MITRE ATT&CK collector (``source`` of the nodes it delivered).
MITRE_SOURCE = "mitre_attck"

# The distinct family labels on the indicators, with the number of indicators of each.
CYPHER_FEED_FAMILIES_READ = (
    "MATCH (i:Indicator) WHERE i.malware_family IS NOT NULL RETURN i.malware_family AS family, count(*) AS indicators"
)
# The names and aliases of the Malware nodes (``source``: ``tool_named_malware`` leaves the MITRE ones out).
CYPHER_MALWARE_NAMES_READ = (
    "MATCH (m:Malware) WHERE m.name IS NOT NULL RETURN m.name AS name, m.aliases AS aliases, m.source AS source"
)

# Separators a family name is written with or without: "Salat Stealer", "Salat-Stealer", "salat_stealer",
# "lockbit.black". ``\s`` is Unicode whitespace.
_SEPARATORS_RE = re.compile(r"[\s\-_.]+")


def family_key(name: Any) -> str:
    """``name`` stripped and lower-cased: the exact comparison of rule 1. ``""`` for a non-string."""
    return name.strip().lower() if isinstance(name, str) else ""


def separator_free(name: Any) -> str:
    """``family_key(name)`` without whitespace, hyphens, underscores and dots: the comparison of rule 2."""
    return _SEPARATORS_RE.sub("", family_key(name))


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _is_mitre(row: Mapping[str, Any]) -> bool:
    return MITRE_SOURCE in _as_list(row.get("source"))


@dataclass(frozen=True)
class FamilyResolution:
    """What ``resolve_feed_families`` decided, each keyed by the label as stored.

    ``targets`` — the names of the ``Malware`` nodes the label names (sorted): ``$family_targets`` of step 9;
    ``separator_free_matches`` — the labels of ``targets`` found by rule 2, with their node;
    ``ambiguous`` — labels whose rule-2 match finds several nodes, with those nodes (linked to none);
    ``unresolved`` — labels that name no node; ``placeholders`` — placeholder labels (sorted lists).
    """

    targets: Dict[str, List[str]] = field(default_factory=dict)
    separator_free_matches: Dict[str, str] = field(default_factory=dict)
    ambiguous: Dict[str, List[str]] = field(default_factory=dict)
    unresolved: List[str] = field(default_factory=list)
    placeholders: List[str] = field(default_factory=list)

    def summary(self, indicators: Mapping[Any, Any], limit: int = 50) -> Dict[str, Any]:
        """The resolution in numbers, with ``indicators`` — label → number of indicators that carry it
        (``CYPHER_FEED_FAMILIES_READ``): ``claims`` (indicators whose label is no placeholder), ``target_missing``
        (of them, those whose label names no node: unresolved or ambiguous), ``placeholder_indicators``, the
        labels found by rule 2, the ambiguous labels, and the unresolved labels with their indicators (the
        ``limit`` largest)."""

        def count(label: str) -> int:
            value = indicators.get(label)
            return value if isinstance(value, int) else 0

        unlinked = list(self.unresolved) + list(self.ambiguous)
        unresolved = sorted(self.unresolved, key=lambda label: (-count(label), label))
        return {
            "claims": sum(count(label) for label in [*self.targets, *unlinked]),
            "target_missing": sum(count(label) for label in unlinked),
            "placeholder_indicators": sum(count(label) for label in self.placeholders),
            "separator_free_matches": dict(sorted(self.separator_free_matches.items())),
            "ambiguous": {
                label: {"indicators": count(label), "nodes": nodes} for label, nodes in sorted(self.ambiguous.items())
            },
            "unresolved_families": len(unresolved),
            "unresolved": {label: count(label) for label in unresolved[:limit]},
        }


def resolve_feed_families(labels: Iterable[Any], nodes: Iterable[Mapping[str, Any]]) -> FamilyResolution:
    """The ``Malware`` nodes each family label names, by the rule of the module docstring.

    ``labels`` — the ``Indicator.malware_family`` values (``CYPHER_FEED_FAMILIES_READ``; duplicates and
    non-strings are ignored, and so is a label that is blank once stripped, which step 9 never reads);
    ``nodes`` — rows ``{"name", "aliases"}`` of the ``Malware`` nodes (``CYPHER_MALWARE_NAMES_READ``; an alias
    stored as a single value counts as one alias, a blank or non-string one as none).
    """
    exact: Dict[str, Set[str]] = {}
    by_separator_free_name: Dict[str, Set[str]] = {}
    for row in nodes:
        name = row.get("name")
        if not isinstance(name, str) or not family_key(name) or is_placeholder_name(name):
            continue
        for key in {family_key(x) for x in [name, *_as_list(row.get("aliases"))] if isinstance(x, str)}:
            if key:
                exact.setdefault(key, set()).add(name)
        bare = separator_free(name)
        if bare:
            by_separator_free_name.setdefault(bare, set()).add(name)

    targets: Dict[str, List[str]] = {}
    separator_free_matches: Dict[str, str] = {}
    ambiguous: Dict[str, List[str]] = {}
    unresolved: Set[str] = set()
    placeholders: Set[str] = set()
    for label in labels:
        if not isinstance(label, str) or not family_key(label) or label in targets:
            continue
        if is_placeholder_name(label):
            placeholders.add(label)
            continue
        named = exact.get(family_key(label))
        if named:
            targets[label] = sorted(named)
            continue
        bare = separator_free(label)
        candidates = by_separator_free_name.get(bare, set()) if bare else set()
        if len(candidates) == 1:
            node = next(iter(candidates))
            targets[label] = [node]
            separator_free_matches[label] = node
        elif candidates:
            ambiguous[label] = sorted(candidates)
        else:
            unresolved.add(label)
    return FamilyResolution(
        targets=targets,
        separator_free_matches=separator_free_matches,
        ambiguous=ambiguous,
        unresolved=sorted(unresolved),
        placeholders=sorted(placeholders),
    )


def tool_named_malware(
    malware: Iterable[Mapping[str, Any]], tools: Iterable[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    """The non-MITRE ``Malware`` nodes whose name without separators is that of an ATT&CK ``Tool``.

    ``malware`` — rows ``{"name", "source"}`` (``CYPHER_MALWARE_NAMES_READ``); ``tools`` — rows ``{"name",
    "mitre_id", "source"}`` of the ``Tool`` nodes, of which those from MITRE count. One row per pair, sorted
    by the Malware name: ``malware``, ``tool``, ``tool_id`` and ``exact_name`` (the stripped, lower-cased names
    are equal, not only the names without separators).
    """
    by_bare: Dict[str, List[Mapping[str, Any]]] = {}
    for tool in tools:
        if isinstance(tool.get("name"), str) and separator_free(tool["name"]) and _is_mitre(tool):
            by_bare.setdefault(separator_free(tool["name"]), []).append(tool)
    pairs: List[Dict[str, Any]] = []
    for row in malware:
        name = row.get("name")
        if not isinstance(name, str) or _is_mitre(row):
            continue
        for tool in by_bare.get(separator_free(name), []):
            pairs.append(
                {
                    "malware": name,
                    "tool": tool["name"],
                    "tool_id": tool.get("mitre_id"),
                    "exact_name": family_key(name) == family_key(tool["name"]),
                }
            )
    return sorted(pairs, key=lambda p: (p["malware"], str(p["tool"])))
