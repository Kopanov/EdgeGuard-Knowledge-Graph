"""ATT&CK's platform names, in ATT&CK's own spelling (2026-11-07).

MISPWriter writes every ATT&CK platform of a technique, malware or tool as a ``platform:<name>`` tag in
ATT&CK's casing (``platform:Network Devices``). MISP resolves a tag name without regard to case and keeps the
casing of a tag it already holds (``Tag::captureTag`` matches ``LOWER(name)``; the ``tags.name`` column is
case-insensitive), so on a MISP that holds the lower-case ``platform:`` tags of earlier writer versions
(``platform:windows``, ``platform:network devices``) an attribute comes back with those. The MISP -> Neo4j sync
therefore maps each platform value it reads to ATT&CK's spelling with ``canonical_attack_platforms``.

``ATTACK_PLATFORMS`` lists every value of ``x_mitre_platforms`` on the technique (``attack-pattern``), malware
and tool objects of the Enterprise and ICS ATT&CK 20.1 bundles of ``mitre-attack/attack-stix-data`` (measured
2026-11-07; ``Office 365`` is on revoked objects only and is kept for the tags earlier versions wrote). A value
the table does not hold (a platform a later ATT&CK release adds) passes unchanged. Standard library only.
"""

from __future__ import annotations

from typing import Dict, Iterable, List

ATTACK_PLATFORMS = (
    "Android",
    "Containers",
    "Control Server",
    "Data Historian",
    "ESXi",
    "Embedded",
    "Engineering Workstation",
    "Field Controller/RTU/PLC/IED",
    "Human-Machine Interface",
    "IaaS",
    "Identity Provider",
    "Input/Output Server",
    "Linux",
    "Network Devices",
    "None",
    "Office 365",
    "Office Suite",
    "PRE",
    "SaaS",
    "Safety Instrumented System/Protection Relay",
    "Windows",
    "iOS",
    "macOS",
)

_BY_FOLDED: Dict[str, str] = {name.casefold(): name for name in ATTACK_PLATFORMS}


def canonical_attack_platform(value: str) -> str:
    """``value`` (a ``platform:`` tag's text) in ATT&CK's spelling: whitespace collapsed, then looked up without
    regard to case; a value the table does not hold is returned with only its whitespace collapsed."""
    name = " ".join(str(value).split())
    return _BY_FOLDED.get(name.casefold(), name)


def canonical_attack_platforms(values: Iterable[str]) -> List[str]:
    """Each value through ``canonical_attack_platform``, blanks dropped, de-duplicated without regard to case,
    order kept."""
    out: List[str] = []
    seen: set = set()
    for value in values:
        name = canonical_attack_platform(value)
        if name and name.casefold() not in seen:
            seen.add(name.casefold())
            out.append(name)
    return out
