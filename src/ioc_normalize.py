"""READ-side input normalization for analyst-supplied IOC values.

Why this module exists
----------------------
The WRITE side canonicalizes natural keys before any Neo4j MERGE
(``node_identity.canonicalize_merge_key``: NFC-normalize + strip, and
lowercase for the case-insensitive labels/indicator-types). Analyst input
arriving at the query APIs (REST ``/search/indicator``, STIX export,
GraphQL ``cve`` resolver, NATS alert enrichment) is raw paste material:
defanged URLs (``hxxp://evil[.]com``), mixed-case hashes, en-dash CVE ids
copied from PDFs. Without a matching READ-side normalization, an exact-key
``MATCH`` silently misses nodes the graph actually contains.

Write-side parity guarantee
---------------------------
Every rule here either *reuses* the write-side helper data directly or is a
strict superset of it that converges to the same canonical form:

* Zero-width/bidi stripping reuses
  ``node_identity._ZERO_WIDTH_AND_BIDI_TRANSLATE`` (the exact translate
  table the write-side placeholder filter uses).
* Case-folding for indicator values reuses
  ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES`` — the same set
  ``canonicalize_merge_key`` consults before lowercasing a MERGE key.
* NFC-normalize + strip mirrors ``canonicalize_merge_key`` /
  ``canonicalize_field_value`` exactly.

Refanging is READ-side only by design: the write side ingests
machine-generated feeds that are not defanged, so there is nothing to
mirror — refanging can only *add* matches, never diverge from a stored key.

Do NOT import ``query_api`` / ``graphql_api`` / ``alert_processor`` here —
those modules import this one (cycle guard).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Optional

from node_identity import (
    _CASE_INSENSITIVE_INDICATOR_TYPES,
    _ZERO_WIDTH_AND_BIDI_TRANSLATE,
)

# Conservative defang vocabulary only — exotic schemes (``meow://`` etc.)
# are deliberately NOT rewritten. Patterns are applied in order; bracket
# forms first so ``hxxp[:]//`` resolves to ``hxxp://`` before the scheme
# rewrite sees it.
_DEFANG_REPLACEMENTS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Bracketed dots: evil[.]com / evil(.)com / evil{.}com → evil.com
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    # Bracketed colon: hxxp[:]// → hxxp://
    (re.compile(r"\[:\]"), ":"),
    # Bracketed at-sign: user[@]example.com → user@example.com
    (re.compile(r"\[@\]"), "@"),
    # Spelled-out at-sign (optional surrounding spaces): user [at] example → user@example
    (re.compile(r"\s*[\[(]at[\])]\s*", re.IGNORECASE), "@"),
    # Defanged schemes — only with an explicit ``://`` following, so plain
    # words containing "hxxp" are never rewritten.
    (re.compile(r"hxxps(?=://)", re.IGNORECASE), "https"),
    (re.compile(r"hxxp(?=://)", re.IGNORECASE), "http"),
)

# Fixpoint bound: nested defanging (``[[.]]``) needs >1 pass to become
# idempotent; the bound keeps adversarial deeply-nested input O(1).
_REFANG_MAX_PASSES = 8


def refang(value: str) -> str:
    """Conservatively refang a defanged IOC string.

    Rewrites only the common defang vocabulary (``hxxp(s)://``, ``[.]``,
    ``(.)``, ``{.}``, ``[:]``, ``[at]``/``(at)``/``[@]``), strips the
    zero-width/bidi control characters via the write-side translate table
    (``node_identity._ZERO_WIDTH_AND_BIDI_TRANSLATE`` — parity guarantee),
    and strips surrounding whitespace.

    Idempotent (substitutions run to a bounded fixpoint) and never raises:
    non-``str`` input is returned unchanged.
    """
    if not isinstance(value, str):
        return value
    out = value.translate(_ZERO_WIDTH_AND_BIDI_TRANSLATE)
    for _ in range(_REFANG_MAX_PASSES):
        prev = out
        for pattern, replacement in _DEFANG_REPLACEMENTS:
            out = pattern.sub(replacement, out)
        if out == prev:
            break
    return out.strip()


# Indicator types where case IS meaningful — mirror of the exclusion list
# documented above ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES``
# (URL paths, file/registry paths, RFC email local-parts). Anything in
# neither set is treated as *unknown* and falls through to the hex-hash
# heuristic below.
_KNOWN_CASE_SENSITIVE_INDICATOR_TYPES = frozenset({"url", "email", "filename", "filepath", "regkey", "cmdline"})

# md5 / sha1 / sha256 / sha512 hex-digest lengths.
_HEX_HASH_LENGTHS = frozenset({32, 40, 64, 128})
_HEX_VALUE_RE = re.compile(r"[0-9a-fA-F]+")


def normalize_indicator_value(indicator_type: Optional[str], value: str) -> str:
    """Normalize an analyst-supplied indicator value for graph lookup.

    Pipeline: :func:`refang` → NFC-normalize + strip → lowercase IFF the
    type is in ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES`` (the
    exact set the write side consults in ``canonicalize_merge_key`` — this
    is the write-side parity guarantee: the value bound into a read-side
    ``MATCH`` equals the value the write side used as its MERGE key).

    When ``indicator_type`` is None or not a recognized type (neither
    case-insensitive nor known case-sensitive — e.g. ``hash``,
    ``file_hash``), a hex-hash heuristic applies: a pure-hex value of
    length 32/40/64/128 (md5/sha1/sha256/sha512) is lowercased, matching
    how the write side stores those digests under their concrete types.
    The generic ``hash`` type is intentionally routed through the
    heuristic rather than the set membership (a parallel change may add
    ``hash`` to the write-side set; both routes converge on lowercase).

    Never raises: non-``str`` ``value`` is returned unchanged.
    """
    if not isinstance(value, str):
        return value
    out = unicodedata.normalize("NFC", refang(value)).strip()
    itype = indicator_type.strip().lower() if isinstance(indicator_type, str) else None
    if itype in _CASE_INSENSITIVE_INDICATOR_TYPES:
        return out.lower()
    if itype is None or itype not in _KNOWN_CASE_SENSITIVE_INDICATOR_TYPES:
        if len(out) in _HEX_HASH_LENGTHS and _HEX_VALUE_RE.fullmatch(out):
            return out.lower()
    return out


# Accepts analyst paste variants: 'CVE-2021-44228', 'cve 2021 44228',
# 'cve_2021_44228', en-dash/em-dash separators (PDF copy artifacts).
_CVE_RE = re.compile(r"cve[\s_–—-]*(\d{4})[\s_–—-]+(\d{4,})", re.IGNORECASE)


def normalize_cve_id(value: str) -> Optional[str]:
    """Extract and canonicalize a CVE id from an analyst-supplied string.

    Returns the canonical ``CVE-YYYY-NNNN…`` form (uppercase, hyphen
    separators) or ``None`` when no CVE id is present. The canonical form
    matches the write side: ``neo4j_client.normalize_cve_id_for_graph``
    uppercases CVE ids before every MERGE, so the output here is exactly
    the graph key (write-side parity; see also ``node_identity`` which
    hashes CVE natural keys case-insensitively).

    Never raises: non-``str`` input returns ``None``.
    """
    if not isinstance(value, str):
        return None
    match = _CVE_RE.search(refang(value))
    if not match:
        return None
    return f"CVE-{match.group(1)}-{match.group(2)}"


_MITRE_TECHNIQUE_RE = re.compile(r"t\s*(\d{4})(\.(\d{3}))?", re.IGNORECASE)


def normalize_mitre_technique_id(value: str) -> Optional[str]:
    """Extract and canonicalize a MITRE ATT&CK technique id.

    Returns ``T1059`` / ``T1059.001`` (uppercase ``T``, dotted
    sub-technique) or ``None`` when no technique id is present. Matches the
    write-side storage form: MITRE collectors store ``Technique.mitre_id``
    in the canonical uppercase ``Tnnnn(.nnn)`` form (``node_identity``
    keys Technique nodes on ``mitre_id``).

    Never raises: non-``str`` input returns ``None``.
    """
    if not isinstance(value, str):
        return None
    match = _MITRE_TECHNIQUE_RE.search(refang(value))
    if not match:
        return None
    sub = match.group(3)
    return f"T{match.group(1)}.{sub}" if sub else f"T{match.group(1)}"
