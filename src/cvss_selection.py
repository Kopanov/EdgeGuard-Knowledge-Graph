"""Which CVSS score a CVE shows (2026-10).

A CVE's ``cvss_score`` and ``severity`` are the base score and qualitative rating of one of
its CVSS versions, taken in the order v3.1 → v3.0 → v2 → v4.0, and ``cvss_version`` names
that version. A CVE without any CVSS has no score (None) and severity ``UNKNOWN``. Nothing
else counts as a CVSS score: not a 0.0 placeholder, not a ``cvss:`` tag band, not a value
derived from another field (CISA KEV ransomware use, a collector default). 0.0 itself is a
valid score (rating NONE).

Before 2026-10 an unscored CVE was tagged ``cvss:low`` in MISP and read back as 3.0 / LOW
(14,451 CVEs of the hosted 730-day baseline), the sync ignored CVSS 3.0, and whichever record
was merged last set the node's score. The NVD collector (MISP tags), the MISP → Neo4j sync
(item values) and ``Neo4jClient.merge_cve`` (node values, from the CVSS sub-nodes) now apply
the same order, ``CVSS_VERSIONS``.

Dependency-free on purpose: the collectors import it without pulling in the Neo4j client.
"""

from __future__ import annotations

import math
from typing import Any, Mapping, NamedTuple, Optional, Tuple


class CvssVersion(NamedTuple):
    payload_key: str  # key of the payload in a collector item and in NVD_META
    version: str  # value of ``cvss_version``
    label: str  # Neo4j sub-node label
    rel_type: str  # CVE → sub-node relationship


CVSS_VERSIONS: Tuple[CvssVersion, ...] = (
    CvssVersion("cvss_v31_data", "3.1", "CVSSv31", "HAS_CVSS_v31"),
    CvssVersion("cvss_v30_data", "3.0", "CVSSv30", "HAS_CVSS_v30"),
    CvssVersion("cvss_v2_data", "2.0", "CVSSv2", "HAS_CVSS_v2"),
    CvssVersion("cvss_v40_data", "4.0", "CVSSv40", "HAS_CVSS_v40"),
)

UNKNOWN_SEVERITY = "UNKNOWN"
QUALITATIVE_SEVERITIES: Tuple[str, ...] = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")


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


def select_cvss(payloads: Mapping[str, Any]) -> Tuple[Optional[float], str, Optional[str]]:
    """``(score, severity, version)`` of the first CVSS payload with a valid base score, in the
    order of ``CVSS_VERSIONS``; ``(None, "UNKNOWN", None)`` when there is none.

    ``payloads`` is an NVD collector item or an NVD_META dict (keys ``cvss_v31_data`` …). The
    severity is the payload's own ``base_severity`` when that is a CVSS rating, otherwise the
    rating of the score (NVD puts the CVSS 2 rating outside ``cvssData``; older NVD_META copies
    of CVSS 2 payloads have it empty).
    """
    for v in CVSS_VERSIONS:
        data = payloads.get(v.payload_key)
        if not isinstance(data, Mapping):
            continue
        score = clamp_cvss_score(data.get("base_score"))
        if score is None:
            continue
        severity = str(data.get("base_severity") or "").strip().upper()
        if severity not in QUALITATIVE_SEVERITIES:
            severity = severity_from_score(score, v.version)
        return score, severity, v.version
    return None, UNKNOWN_SEVERITY, None


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
