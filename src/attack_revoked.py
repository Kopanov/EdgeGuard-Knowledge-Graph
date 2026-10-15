"""Revoked MITRE ATT&CK ids and their successors (2026-10).

ATT&CK keeps a replaced object in its data with ``revoked: true`` and a ``revoked-by``
relationship to its successor. The MITRE collector skips revoked objects
(``collectors.mitre_collector``), but the feeds keep citing the old ids: OTX pulses name ``T1086``
for PowerShell, which ATT&CK moved to ``T1059.001``. Wherever a feed names a technique by id,
EdgeGuard translates a revoked id to its successor first, so the link lands on the technique that
exists:

* ``build_relationships`` — every ``MATCH (t:Technique {mitre_id: …})`` and its orphan count, via
  the Cypher map parameter ``$revoked`` (``coalesce($revoked[tid], tid)``);
* the MISP→Neo4j sync — technique ids of ``misp-galaxy:mitre-attack-pattern`` tags and of curated
  claims (``run_misp_to_neo4j``), and ``scripts/import_curated_package.py``, which reports each
  translation;
* the STIX export of a technique (``StixExporter.export_technique``).

The map is ``src/reference/attack_revoked_ids.json``, built from the MITRE galaxies of MISP by
``scripts/build_attack_revoked_ids.py`` (rebuild it at every ATT&CK release; ``docs/RUNBOOK.md``).
It is read once per process. When the file is missing or invalid, one warning is logged and
nothing is translated: a run never fails because of the map.

Standard library only: ``scripts/verify_fresh_baseline.py`` imports this module outside the
pipeline's environment.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

logger = logging.getLogger(__name__)

MAP_PATH = Path(__file__).resolve().parent / "reference" / "attack_revoked_ids.json"

# Map section → full-match pattern of the ids it holds (``scripts/build_attack_revoked_ids.SECTIONS``).
_SECTIONS: Dict[str, "re.Pattern[str]"] = {
    "techniques": re.compile(r"T\d{4}(?:\.\d{3})?"),
    "groups": re.compile(r"G\d{4}"),
    "software": re.compile(r"S\d{4}"),
}


@dataclass(frozen=True)
class RevokedAttackIds:
    """The revoked ids of one map file: ``revoked id → successor id`` per kind of object.

    ``loaded`` is False when the file was missing or invalid (``problem`` says why); the maps are
    then empty and every lookup returns its input.
    """

    loaded: bool = False
    version: str = ""
    path: str = ""
    problem: str = ""
    techniques: Mapping[str, str] = field(default_factory=dict)
    groups: Mapping[str, str] = field(default_factory=dict)
    software: Mapping[str, str] = field(default_factory=dict)
    # revoked id → the revoked object's name; successor id → the successor's name (all kinds), for
    # reports and the acceptance check
    names: Mapping[str, str] = field(default_factory=dict)
    successor_names: Mapping[str, str] = field(default_factory=dict)

    def technique_successor(self, mitre_id: Any) -> Optional[str]:
        """The successor of a revoked technique id (case and surrounding space ignored), else ``None``."""
        if mitre_id is None:
            return None
        return self.techniques.get(str(mitre_id).strip().upper())

    def translate_technique(self, mitre_id: Any) -> Any:
        """``mitre_id``'s successor when ATT&CK revoked it; ``mitre_id`` unchanged otherwise."""
        successor = self.technique_successor(mitre_id)
        return successor if successor is not None else mitre_id

    def group_names(self) -> List[str]:
        """The names of the revoked groups (``"UNC2452"``, ``"APT34"`` …), sorted.

        A name a successor group also bears (case ignored) is left out: it names a live group too.
        """
        live = {self.successor_names[s].casefold() for s in self.groups.values() if self.successor_names.get(s)}
        return sorted(self.names[g] for g in self.groups if self.names.get(g) and self.names[g].casefold() not in live)


_cache: Dict[str, RevokedAttackIds] = {}


def _parse(document: Any) -> Tuple[Dict[str, Dict[str, str]], Dict[str, str], Dict[str, str], str]:
    """``(sections, names, successor names, version)`` of a map document; raises ``ValueError``
    naming the first problem."""
    if not isinstance(document, dict):
        raise ValueError("the file is not a JSON object")
    version = document.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("no 'version'")
    sections: Dict[str, Dict[str, str]] = {}
    names: Dict[str, str] = {}
    successor_names: Dict[str, str] = {}
    for section, pattern in _SECTIONS.items():
        entries = document.get(section)
        if not isinstance(entries, dict):
            raise ValueError(f"'{section}' is missing or not an object")
        out: Dict[str, str] = {}
        for revoked_id, entry in entries.items():
            if not isinstance(revoked_id, str) or not pattern.fullmatch(revoked_id):
                raise ValueError(f"'{section}' holds a malformed id {revoked_id!r}")
            successor = entry.get("successor") if isinstance(entry, dict) else None
            if not isinstance(successor, str) or not pattern.fullmatch(successor):
                raise ValueError(f"{revoked_id}: malformed successor {successor!r}")
            if successor == revoked_id:
                raise ValueError(f"{revoked_id} is its own successor")
            out[revoked_id] = successor
            name = entry.get("name")
            if isinstance(name, str) and name.strip():
                names[revoked_id] = name.strip()
            successor_name = entry.get("successor_name")
            if isinstance(successor_name, str) and successor_name.strip():
                successor_names[successor] = successor_name.strip()
        # The builder follows every chain to its end; a successor that is itself revoked would make
        # one lookup land on another revoked id.
        chained = sorted(r for r, s in out.items() if s in out)
        if chained:
            raise ValueError(f"successor of {chained[0]} is itself revoked (unresolved chain)")
        sections[section] = out
    return sections, names, successor_names, version.strip()


def load_revoked_ids(path: Optional[Path] = None) -> RevokedAttackIds:
    """The revoked-id map at ``path`` (default ``MAP_PATH``), read and validated once per process.

    A missing or invalid file logs one warning and yields an empty map (``loaded`` False).
    """
    target = Path(path) if path is not None else MAP_PATH
    key = str(target)
    cached = _cache.get(key)
    if cached is not None:
        return cached
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
        sections, names, successor_names, version = _parse(document)
    except FileNotFoundError:
        result = RevokedAttackIds(path=key, problem="file not found")
    except Exception as e:  # never fail a run because of the map: unreadable is the same as absent
        result = RevokedAttackIds(path=key, problem=f"{type(e).__name__}: {e}")
    else:
        result = RevokedAttackIds(
            loaded=True,
            version=version,
            path=key,
            techniques=sections["techniques"],
            groups=sections["groups"],
            software=sections["software"],
            names=names,
            successor_names=successor_names,
        )
        logger.info(
            "[ATT&CK] revoked-id map %s: %d techniques, %d groups, %d software",
            version,
            len(result.techniques),
            len(result.groups),
            len(result.software),
        )
    if not result.loaded:
        logger.warning(
            "[ATT&CK] revoked-id map %s not used (%s): revoked ATT&CK ids are not translated in this run",
            key,
            result.problem,
        )
    _cache[key] = result
    return result


def technique_successors(path: Optional[Path] = None) -> Dict[str, str]:
    """``{revoked technique id: successor id}`` — the ``$revoked`` Cypher parameter (empty when unusable)."""
    return dict(load_revoked_ids(path).techniques)


def reset_cache() -> None:
    """Forget the maps read so far (tests; a long-lived process after a map update)."""
    _cache.clear()


__all__ = [
    "MAP_PATH",
    "RevokedAttackIds",
    "load_revoked_ids",
    "reset_cache",
    "technique_successors",
]
