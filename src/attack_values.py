"""The MISP attribute value of an ATT&CK technique, tactic or tool (2026-10-20).

MISPWriter writes each ATT&CK technique, tactic and tool (Enterprise and ATT&CK for ICS) as a MISP
``text`` attribute whose value is the ATT&CK id, `` - `` and the name: ``T1059.003 - Windows Command
Shell``, ``TA0002 - Execution``, ``S0005 - Windows Credential Editor`` (``format_attack_value``).

The value carries no colon because of MISP's Import Regexp rules, which MISP applies to the value of
every attribute it stores. The default rules normalise Windows paths in file-name indicators, and
those for Windows, Program Files, ProgramData, Documents and Settings and Users begin with any
character, a colon and any character (``/.:.Windows./i`` → ``%WINDIR%\\``). They rewrote the
earlier form ``<id>: <name>`` whenever the name began with such a word: MISP stored ``T1059.003:
Windows Command Shell`` as ``T1059.00%WINDIR%\\Command Shell``, and the entry became a node with a
broken id and no name. Each fresh MISP database holds the default rules again.

``parse_attack_value`` reads both forms (the id, then ``:`` or `` - ``, then the name), for the
MISP→Neo4j sync and its STIX conversion (``run_misp_to_neo4j``). The id must have one of the forms
ATT&CK gives a technique (``T1234``, ``T1234.123``), a tactic (``TA1234``) or a piece of software
(``S1234``); no writer puts a group (``G1234``) in a ``text`` attribute. ``looks_like_attack_value``
tells a value that starts like an ATT&CK id, so the sync can skip, with a warning, one that holds no
valid id (a value MISP rewrote) instead of making it a node.

Standard library only.
"""

from __future__ import annotations

import re
from typing import Any, NamedTuple, Optional

# Between the id and the name in the value MISPWriter writes.
ATTACK_VALUE_SEPARATOR = " - "

# The id, then ``:`` (the earlier form) or `` - `` (the current one), then the name; or the id alone.
# Upper-case ASCII ids only, as ATT&CK writes them; ``TA`` is tried before ``T``.
_ATTACK_VALUE_RE = re.compile(
    r"^(?P<id>TA\d{4}|T\d{4}(?:\.\d{3})?|S\d{4})(?:(?:\s*:\s*|\s+-\s+)(?P<name>\S.*?))?\s*$",
    re.ASCII | re.DOTALL,
)

# A value that starts like an ATT&CK id: ``T``, ``TA`` or ``S`` and three digits, followed by a
# fourth digit (the id forms above) or by ``%`` (a MISP Import Regexp replacement that took the id's
# last digit, as in ``T104%WINDIR%\\Management Instrumentation`` and ``S000%WINDIR%\\Credential
# Editor``).
_ATTACK_LIKE_RE = re.compile(r"^(?:TA|T|S)\d{3}[\d%]", re.ASCII)

_KIND_BY_PREFIX = (("TA", "tactic"), ("T", "technique"), ("S", "tool"))


class AttackValue(NamedTuple):
    """An ATT&CK entry read from a MISP ``text`` value: ``kind`` is ``technique``, ``tactic`` or
    ``tool``; ``name`` is empty when the value holds the id alone."""

    kind: str
    mitre_id: str
    name: str


def format_attack_value(mitre_id: str, name: str) -> str:
    """The MISP value of an ATT&CK entry: ``"T1059.003 - Windows Command Shell"``."""
    return f"{mitre_id}{ATTACK_VALUE_SEPARATOR}{name}"


def parse_attack_value(value: Any) -> Optional[AttackValue]:
    """The ATT&CK entry a MISP ``text`` value names, in either form, else ``None``.

    ``"T1059.003 - Windows Command Shell"`` and ``"T1059.003: Windows Command Shell"`` both give
    ``AttackValue("technique", "T1059.003", "Windows Command Shell")``. ``None`` for a non-string, a
    value that is no ATT&CK entry and a value whose id is not a valid ATT&CK id
    (``"T1059.00%WINDIR%\\Command Shell"``); ``looks_like_attack_value`` tells the last case apart.
    """
    if not isinstance(value, str):
        return None
    match = _ATTACK_VALUE_RE.match(value.strip())
    if match is None:
        return None
    mitre_id = match.group("id")
    kind = next(kind for prefix, kind in _KIND_BY_PREFIX if mitre_id.startswith(prefix))
    return AttackValue(kind, mitre_id, (match.group("name") or "").strip())


def looks_like_attack_value(value: Any) -> bool:
    """True when ``value`` starts like an ATT&CK id (see ``_ATTACK_LIKE_RE``), whether or not the id
    is valid: the sync reads such a value as an ATT&CK entry or skips it."""
    return isinstance(value, str) and _ATTACK_LIKE_RE.match(value.strip()) is not None


def attack_value_key(value: Any) -> Any:
    """The one form of an ATT&CK ``text`` value that dedup compares (2026-10-21).

    A value that ``parse_attack_value`` reads is returned in the current form
    (``format_attack_value``), so MISP's ``T1059.003: Windows Command Shell`` and the
    ``T1059.003 - Windows Command Shell`` MISPWriter writes now are one key. Any other value, a
    mangled one (``"T1059.00%WINDIR%\\Command Shell"``) included, is returned unchanged.
    """
    parsed = parse_attack_value(value)
    if parsed is None or not parsed.name:
        return value
    return format_attack_value(parsed.mitre_id, parsed.name)


__all__ = [
    "ATTACK_VALUE_SEPARATOR",
    "AttackValue",
    "attack_value_key",
    "format_attack_value",
    "looks_like_attack_value",
    "parse_attack_value",
]
