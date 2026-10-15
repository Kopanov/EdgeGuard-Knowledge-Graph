"""Which CVSS score and attack vector a CVE shows (2026-10).

A CVE's ``cvss_score`` and ``severity`` are the base score and qualitative rating of one of
its CVSS versions, taken in the order v3.1 → v3.0 → v2 → v4.0, and ``cvss_version`` names
that version. A CVE without any CVSS has no score (None) and severity ``UNKNOWN``. Nothing
else counts as a CVSS score: not a 0.0 placeholder, not a ``cvss:`` tag band, not a value
derived from another field (CISA KEV ransomware use, a collector default). 0.0 itself is a
valid score (rating NONE).

Its ``attack_vector`` is the attack vector of the same CVSS, in NVD's words (``NETWORK``,
``ADJACENT_NETWORK``, ``LOCAL``, ``PHYSICAL``), and None without CVSS.

Before 2026-10 an unscored CVE was tagged ``cvss:low`` in MISP and read back as 3.0 / LOW
(14,451 CVEs of the hosted 730-day baseline), the sync ignored CVSS 3.0, and whichever record
was merged last set the node's score. The NVD collector (MISP tags), the MISP → Neo4j sync
(item values) and ``Neo4jClient.merge_cve`` (node values, from the CVSS sub-nodes) now apply
the same order, ``CVSS_VERSIONS``. The attack vector had the same defect: the NVD collector
sent the letter of the vector string's ``AV`` metric (``N``, ``L``, ``A``, ``P``) or ``UNKNOWN``,
the KEV and OTX collectors an invented ``NETWORK``, and the record merged last set the node's
value; on the hosted graph of 2026-10-15, 147 CVEs showed ``NETWORK`` while their CVSS 3.1 said
``LOCAL``, ``ADJACENT_NETWORK`` or ``PHYSICAL``.

Dependency-free on purpose: the collectors import it without pulling in the Neo4j client.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Mapping, NamedTuple, Optional, Tuple


class CvssVersion(NamedTuple):
    payload_key: str  # key of the payload in a collector item and in NVD_META
    version: str  # value of ``cvss_version``
    label: str  # Neo4j sub-node label
    rel_type: str  # CVE → sub-node relationship
    vector_field: Optional[str]  # payload / sub-node field naming the attack vector; None: vector string only


CVSS_VERSIONS: Tuple[CvssVersion, ...] = (
    CvssVersion("cvss_v31_data", "3.1", "CVSSv31", "HAS_CVSS_v31", "attack_vector"),
    CvssVersion("cvss_v30_data", "3.0", "CVSSv30", "HAS_CVSS_v30", "attack_vector"),
    CvssVersion("cvss_v2_data", "2.0", "CVSSv2", "HAS_CVSS_v2", "access_vector"),
    # NVD's CVSS 4.0 payload keeps only the vector string, the base score and the rating.
    CvssVersion("cvss_v40_data", "4.0", "CVSSv40", "HAS_CVSS_v40", None),
)

UNKNOWN_SEVERITY = "UNKNOWN"
QUALITATIVE_SEVERITIES: Tuple[str, ...] = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# NVD's word for each spelling CVSS data uses for an attack vector (compared in upper case): the
# value of the ``AV`` metric in the vector string of every CVSS version, NVD's words (CVSS 3.x
# ``attackVector``, CVSS 2 ``accessVector``) and CVSS 4.0's ``ADJACENT``. ``Neo4jClient`` builds its
# Cypher from this table, so the node and the sync apply the same mapping.
ATTACK_VECTOR_SPELLINGS: Dict[str, str] = {
    "N": "NETWORK",
    "NETWORK": "NETWORK",
    "A": "ADJACENT_NETWORK",
    "ADJACENT": "ADJACENT_NETWORK",
    "ADJACENT_NETWORK": "ADJACENT_NETWORK",
    "L": "LOCAL",
    "LOCAL": "LOCAL",
    "P": "PHYSICAL",
    "PHYSICAL": "PHYSICAL",
}


def clamp_cvss_score(value: Any) -> Optional[float]:
    """PR-N14 (pre-baseline audit Fix #1, 2026-04-21): clamp a CVSS
    base_score to the valid [0.0, 10.0] range + reject non-finite.

    Pre-PR-N14, an attacker-controlled NVD_META with ``base_score:
    "1e309"`` reached ``float(...)`` → Python ``inf`` → landed on the
    CVE node as ``n.cvss_score = Infinity``. Two consequences:

      * GraphQL ``vulnerabilities(min_cvss: 9.0) ORDER BY n.cvss_score
        DESC`` permanently placed the forged CVE at the top of the
        triage queue, masking real P1s.
      * STIX export emitted `"cvss_score": Infinity` which is NOT valid
        JSON — downstream parsers crashed.

    Returns None for unparseable / non-finite / out-of-range values so
    callers can propagate NULL (honest-NULL per PR-N5 C7). Valid inputs
    pass through as floats. (Moved here from ``neo4j_client`` in 2026-10,
    which re-exports it.)
    """
    if value is None:
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(f):
        # inf / -inf / NaN — reject (honest-NULL).
        return None
    if f < 0.0 or f > 10.0:
        # Outside the NIST-defined CVSS range.
        return None
    return f


def severity_from_score(score: float, version: str) -> str:
    """Qualitative rating of a base score: NVD's CVSS 2 scale for version "2.0" (LOW below 4.0,
    MEDIUM below 7.0, HIGH), the CVSS 3.x / 4.0 scale otherwise (NONE at 0.0, LOW, MEDIUM from
    4.0, HIGH from 7.0, CRITICAL from 9.0)."""
    if version == "2.0":
        if score >= 7.0:
            return "HIGH"
        return "MEDIUM" if score >= 4.0 else "LOW"
    if score == 0.0:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    return "MEDIUM" if score >= 4.0 else "LOW"


def _scoring_cvss(payloads: Mapping[str, Any]) -> Optional[Tuple[CvssVersion, Mapping[str, Any], float]]:
    """Version, payload and base score of the first CVSS payload with a valid base score, in the
    order of ``CVSS_VERSIONS``; None when there is none."""
    for v in CVSS_VERSIONS:
        data = payloads.get(v.payload_key)
        if not isinstance(data, Mapping):
            continue
        score = clamp_cvss_score(data.get("base_score"))
        if score is not None:
            return v, data, score
    return None


def select_cvss(payloads: Mapping[str, Any]) -> Tuple[Optional[float], str, Optional[str]]:
    """``(score, severity, version)`` of the first CVSS payload with a valid base score, in the
    order of ``CVSS_VERSIONS``; ``(None, "UNKNOWN", None)`` when there is none.

    ``payloads`` is an NVD collector item or an NVD_META dict (keys ``cvss_v31_data`` …). The
    severity is the payload's own ``base_severity`` when that is a CVSS rating, otherwise the
    rating of the score (NVD puts the CVSS 2 rating outside ``cvssData``; older NVD_META copies
    of CVSS 2 payloads have it empty).
    """
    picked = _scoring_cvss(payloads)
    if picked is None:
        return None, UNKNOWN_SEVERITY, None
    v, data, score = picked
    severity = str(data.get("base_severity") or "").strip().upper()
    if severity not in QUALITATIVE_SEVERITIES:
        severity = severity_from_score(score, v.version)
    return score, severity, v.version


def select_cvss_payload(payloads: Mapping[str, Any]) -> Optional[Tuple[CvssVersion, Mapping[str, Any]]]:
    """The CVSS version and payload that give the score (``select_cvss``); None without CVSS."""
    picked = _scoring_cvss(payloads)
    return (picked[0], picked[1]) if picked else None


def _attack_vector_word(value: Any) -> Optional[str]:
    """NVD's word for a spelling in ``ATTACK_VECTOR_SPELLINGS`` (any case), else None."""
    if value is None:
        return None
    return ATTACK_VECTOR_SPELLINGS.get(str(value).strip().upper())


def _vector_string_attack_vector(vector: Any) -> Optional[str]:
    """NVD's word for the ``AV`` metric of a CVSS vector string, else None. Only the metric named
    ``AV`` counts, not CVSS 4.0's modified ``MAV``."""
    if vector is None:
        return None
    for metric in str(vector).strip().split("/"):
        if metric.startswith("AV:"):
            return _attack_vector_word(metric[3:])
    return None


def normalize_attack_vector(value: Any) -> Optional[str]:
    """NVD's word (``NETWORK``, ``ADJACENT_NETWORK``, ``LOCAL``, ``PHYSICAL``) for an attack vector
    given as a word, a letter or a CVSS vector string; None for anything else (``UNKNOWN``, empty,
    None).

    Words and letters: NVD's words, CVSS 4.0's ``ADJACENT`` and the letters ``N``, ``A``, ``L``,
    ``P``, in any case. Vector strings: CVSS 2 (``AV:N/AC:L/Au:N/…``), 3.x (``CVSS:3.1/AV:L/…``)
    and 4.0 (``CVSS:4.0/AV:P/…``); the value of their ``AV`` metric.
    """
    if value is None:
        return None
    text = str(value).strip()
    return _vector_string_attack_vector(text) if ":" in text else _attack_vector_word(text)


def payload_attack_vector(data: Mapping[str, Any], version: CvssVersion) -> Optional[str]:
    """The attack vector of one CVSS payload or sub-node, in NVD's words: its version's field
    (``attack_vector`` of CVSS 3.x, ``access_vector`` of CVSS 2), else the ``AV`` metric of its
    ``vector_string`` (where a CVSS 4.0 payload has it). Mirrored in Cypher by
    ``neo4j_client._cve_attack_vector_from_best_cypher``."""
    stated = _attack_vector_word(data.get(version.vector_field)) if version.vector_field else None
    return stated or _vector_string_attack_vector(data.get("vector_string"))


def cvss_attack_vector(payloads: Mapping[str, Any]) -> Optional[str]:
    """The attack vector of the CVSS payload that gives the score (``select_cvss_payload``), in
    NVD's words; None without CVSS. ``payloads`` as for ``select_cvss``."""
    picked = select_cvss_payload(payloads)
    return payload_attack_vector(picked[1], picked[0]) if picked else None


def cvss_rating_tag(score: Any, severity: Any) -> Optional[str]:
    """The ``cvss:<rating>`` MISP tag for a CVE item, or None when the item carries no CVSS score.

    The rating is the item's severity when that is a CVSS rating, otherwise the CVSS 3.x rating
    of the score. 0.0 with an UNKNOWN or empty severity is the placeholder older producers sent
    for an unscored CVE (it was tagged ``cvss:low``), not a score.
    """
    value = clamp_cvss_score(score)
    if value is None:
        return None
    rating = str(severity or "").strip().upper()
    if rating in QUALITATIVE_SEVERITIES:
        return f"cvss:{rating.lower()}"
    if value == 0.0:
        return None
    return f"cvss:{severity_from_score(value, '3.1').lower()}"
