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

import ipaddress
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
    # Spelled-out at-sign — BALANCED bracket pairs only ([at] or (at), not
    # the mismatched [at) / (at]). Surrounding whitespace IS consumed
    # because the email defang convention is "user [at] example [dot] com";
    # the filename-corruption risk the review flagged ("data [at] rest.txt"
    # → "data@rest.txt") is handled upstream by type-scoping in
    # normalize_indicator_value (refang only runs for network/email types,
    # never filename/regkey/cmdline).
    (re.compile(r"\s*(?:\[at\]|\(at\))\s*", re.IGNORECASE), "@"),
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
    zero-width/bidi control characters using
    ``node_identity._ZERO_WIDTH_AND_BIDI_TRANSLATE`` (the SAME table the
    write side uses — but only to REJECT such values via
    ``is_placeholder_name``, not to scrub them out of a stored value). So
    the zero-width strip here is a READ-side defense for analyst paste; it
    is NOT a two-way parity guarantee — a feed that managed to persist a
    value with embedded zero-width chars would not be found by a stripped
    lookup. Also strips surrounding whitespace.

    Idempotent for realistic inputs: substitutions run to a fixpoint
    bounded at ``_REFANG_MAX_PASSES`` passes, which resolves any practical
    nesting depth (each pass peels one bracket level). Pathologically deep
    adversarial nesting (>8 levels) may stop one pass short of the fixpoint
    — acceptable because the only consequence is a lookup miss, never a
    crash (all patterns are linear-time; no ReDoS). Never raises: non-``str``
    input is returned unchanged.
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


# Graph (EdgeGuard) indicator types where defanging is a real analyst
# convention, so refang is safe. Brackets/`(at)` in any OTHER type
# (filename, registry, cmdline, …) may be literal content. These are the
# POST-mapping (graph) names — type reconciliation runs first.
_REFANGABLE_INDICATOR_TYPES = frozenset({"ipv4", "ipv6", "domain", "url", "email"})


# Indicator types where case IS meaningful — mirror of the exclusion list
# documented above ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES``
# (URL paths, file/registry paths, RFC email local-parts). Anything in
# neither set is treated as *unknown* and falls through to the hex-hash
# heuristic below.
_KNOWN_CASE_SENSITIVE_INDICATOR_TYPES = frozenset(
    {"url", "email", "filename", "filepath", "registry", "regkey", "cmdline", "bitcoin", "monero", "ethereum"}
)

# Alert/MISP-attribute type vocab → EdgeGuard graph type. MUST mirror
# ``run_misp_to_neo4j.MISPToNeo4jSync.TYPE_MAPPING`` so a read-side
# (indicator_type, value) lookup keys the SAME node the write side MERGEd —
# without this, an alert typed "hostname" / "btc" / "regkey" / "email-src"
# created DUPLICATE nodes (the write side stored domain / bitcoin / registry
# / email). ``ip`` is resolved by VALUE shape (ipv4 vs ipv6) since one
# label can't cover both. ``file_hash``/``filehash`` are ResilMesh aliases
# for "hash". A parity test (tests/test_ioc_normalize_*) pins this against
# the real TYPE_MAPPING so the two can't silently drift.
_GRAPH_TYPE_MAP = {
    "ip-dst": "ipv4",
    "ip-src": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "hash": "hash",
    "file_hash": "hash",
    "filehash": "hash",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
    "vulnerability": "cve",
    "filename": "filename",
    "regkey": "registry",
    "registry": "registry",
    "mutex": "mutex",
    "yara": "yara",
    "sigma": "sigma",
    "snort": "snort",
    "btc": "bitcoin",
    "bitcoin": "bitcoin",
}

# md5 / sha1 / sha256 / sha512 hex-digest lengths.
_HEX_HASH_LENGTHS = frozenset({32, 40, 64, 128})
_HEX_VALUE_RE = re.compile(r"[0-9a-fA-F]+")


def _blank_type_to_none(indicator_type: Optional[str]) -> Optional[str]:
    """Collapse every "no type given" form to ``None``: actual ``None``,
    an empty / whitespace-only string, and EdgeGuard's ``"unknown"``
    sentinel. Returns the stripped-lowercased type otherwise.

    Single source of truth so inference + refang fire identically whether
    the caller passes ``None``, ``""``, ``"  "``, or ``"unknown"`` — without
    this, a ``type: ""`` alert was treated as a distinct real type and
    skipped both inference and refang.
    """
    if not isinstance(indicator_type, str):
        return None
    stripped = indicator_type.strip().lower()
    return None if stripped in ("", "unknown") else stripped


def _resolve_graph_type(indicator_type: Optional[str], value: str) -> Optional[str]:
    """Resolve an analyst/sensor/MISP type to the EdgeGuard GRAPH type the
    write side actually stores (via ``_GRAPH_TYPE_MAP``), so read-side
    lookups key the same node. A blank type is inferred from the value
    shape; the special ResilMesh ``"ip"`` is resolved to ipv4/ipv6 by shape;
    an unmapped type passes through unchanged. Returns ``None`` when nothing
    can be resolved.
    """
    itype = _blank_type_to_none(indicator_type)
    if itype is None:
        return infer_indicator_type(value) if isinstance(value, str) else None
    if itype == "ip":
        return _classify_ip(refang(value).strip()) if isinstance(value, str) else None
    return _GRAPH_TYPE_MAP.get(itype, itype)


def normalize_indicator_value(indicator_type: Optional[str], value: str) -> str:
    """Normalize an analyst-supplied indicator value for graph lookup.

    Pipeline: resolve the GRAPH type (:func:`_resolve_graph_type` — maps the
    alert/MISP vocab to what the write side stores) → :func:`refang` (only
    for network/email graph types) → NFC-normalize + strip → lowercase IFF
    the graph type is in ``node_identity._CASE_INSENSITIVE_INDICATOR_TYPES``
    (the exact set ``canonicalize_merge_key`` consults — the write-side
    parity guarantee: the value bound into a read-side ``MATCH`` equals the
    value the write side used as its MERGE key).

    Resolving the graph type FIRST is what keeps e.g. a ``btc`` alert
    (write side stores ``bitcoin``, case-SENSITIVE Base58) from being
    wrongly lowercased, and a ``hostname`` alert (→ ``domain``) folding the
    same way the write side did.

    For an unknown/uninferable type a hex-hash heuristic is the last resort:
    a pure-hex value of length 32/40/64/128 is lowercased.

    Never raises: non-``str`` ``value`` is returned unchanged.
    """
    if not isinstance(value, str):
        return value
    gtype = _resolve_graph_type(indicator_type, value)
    base = refang(value) if (gtype is None or gtype in _REFANGABLE_INDICATOR_TYPES) else value
    out = unicodedata.normalize("NFC", base).strip()
    if gtype in _CASE_INSENSITIVE_INDICATOR_TYPES:
        return out.lower()
    if gtype is None or gtype not in _KNOWN_CASE_SENSITIVE_INDICATOR_TYPES:
        if len(out) in _HEX_HASH_LENGTHS and _HEX_VALUE_RE.fullmatch(out):
            return out.lower()
    return out


# Value-shape detectors for inferring an indicator type when the source
# gives none (ResilMesh/Wazuh alerts default threat type to "unknown").
# Conservative on purpose — only UNAMBIGUOUS shapes are claimed; anything
# else returns None so the caller leaves the value untyped rather than
# guessing wrong.
_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
# Domain shape: dotted labels + alpha TLD, with an OPTIONAL trailing root
# dot (FQDN form "evil.com."). Label/TLD classes include Unicode letters
# (``¡-￿``) so IDN/homograph domains ("münchen.de", "россия.рф")
# classify the same as their punycode form — the write side stores IDN
# domains NFC-folded, so this keeps read/write parity. (Django's URL host
# pattern uses the same Unicode range.)
_DOMAIN_RE = re.compile(
    r"(?:[A-Za-z0-9¡-￿](?:[A-Za-z0-9¡-￿-]{0,61}[A-Za-z0-9¡-￿])?\.)+"
    r"[A-Za-z¡-￿]{2,63}\.?"
)
# Final labels that are common file/document extensions, NOT real TLDs —
# guards against a bare typeless filename ("pos-malware.exe", "report.pdf")
# being mislabeled a domain (→ wrong block-recommendation + mistyped node).
# A single-label value like "evil.exe" is rejected; a genuinely multi-label
# host ("mail.evil.com") is unaffected. (.zip/.mov ARE real TLDs now, so
# they are deliberately NOT here — folding their case is harmless anyway.)
_FILE_EXTENSION_FINAL_LABELS = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "bin",
        "dat",
        "scr",
        # NOTE: ".com" is deliberately EXCLUDED — it is overwhelmingly the
        # most common domain TLD; the legacy DOS .com executable is
        # vanishingly rare in modern CTI, and treating .com as a file
        # extension would mislabel every .com DOMAIN as untyped.
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "js",
        "jar",
        "msi",
        "tmp",
        "log",
        "ini",
        "cfg",
        "txt",
        "csv",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "rtf",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "bmp",
        "iso",
        "img",
        "lnk",
        "hta",
    }
)


def _classify_ip(value: str) -> Optional[str]:
    """Return 'ipv4' / 'ipv6' for a STRICTLY valid IP literal, else None.

    Uses the stdlib ``ipaddress`` validator instead of a loose regex — a
    hex+colon shape check wrongly accepted non-addresses like ``dead:beef``
    and MAC addresses (``00:1a:2b:3c:4d:5e``) as IPv6, mislabeling the node
    type and breaking MISP-sync key parity. ``%zone`` scope-id suffixes
    (``fe80::1%eth0``) are stripped before validation since the graph stores
    the bare address.
    """
    candidate = value.split("%", 1)[0] if "%" in value else value
    try:
        return "ipv4" if ipaddress.ip_address(candidate).version == 4 else "ipv6"
    except ValueError:
        return None


def infer_indicator_type(value: str) -> Optional[str]:
    """Best-effort indicator-type inference from a value's shape.

    For typeless inputs (an alert whose ``type`` is missing or the
    ``"unknown"`` sentinel) this lets the caller store the indicator under
    the SAME ``(indicator_type, value)`` MERGE key — and apply the same
    case-folding — that the MISP sync would use, so the two don't become
    duplicate nodes for the same host.

    Only unambiguous shapes are claimed: ``url`` (has ``://``), ``email``
    (``local@domain``), ``ipv4``/``ipv6``, ``hash`` (hex of 32/40/64/128),
    and ``domain`` (dotted hostname with an alpha TLD, no path/space/@).
    Returns ``None`` for anything ambiguous (e.g. a bare word, a file path)
    so the caller keeps it untyped rather than mislabeling it.

    Never raises: non-``str`` input returns ``None``. Input is refanged
    first so defanged alerts (``1.2.3[.]4``, ``hxxp://``) classify.
    """
    if not isinstance(value, str):
        return None
    v = refang(value).strip()
    if not v:
        return None
    low = v.lower()
    if low.startswith(("http://", "https://", "ftp://")):
        # Well-formedness: a real URL has a non-empty host after ``://`` and
        # NO interior whitespace. Without this, a space-corrupted paste
        # ("http:// evil.com") was confidently mislabeled 'url' and bound a
        # space-containing value that can never match a stored node (and the
        # embedded host was never recovered). A scheme-bearing-but-malformed
        # value resolves to None here (it isn't a domain/ip/hash either).
        after = v.split("://", 1)[1].strip()
        return "url" if (after and not any(c.isspace() for c in v)) else None
    if _EMAIL_RE.fullmatch(v):
        return "email"
    # Strict IP validation (ipaddress) — rejects non-addresses like
    # "dead:beef" / MAC addresses that a loose hex+colon shape accepted.
    ip_type = _classify_ip(v)
    if ip_type:
        return ip_type
    if len(v) in _HEX_HASH_LENGTHS and _HEX_VALUE_RE.fullmatch(v):
        return "hash"
    # Domain/hostname: dotted labels, alpha TLD, none of the URL/email/path
    # characters — AND the final label is not a common file extension (so a
    # bare typeless filename "pos-malware.exe" stays unknown rather than
    # being mislabeled a domain and given a bogus DNS-sinkhole recommendation).
    if not any(c in v for c in "/\\@ \t") and _DOMAIN_RE.fullmatch(v):
        # Final label ignoring an optional trailing root dot ("report.pdf."
        # is still a filename, not a domain).
        final_label = v.rstrip(".").rsplit(".", 1)[-1].lower()
        if final_label not in _FILE_EXTENSION_FINAL_LABELS:
            return "domain"
    return None


def canonicalize_lookup(indicator_type: Optional[str], value: str) -> tuple[Optional[str], str]:
    """Read-side lookup canonicalization shared by every entrypoint that
    resolves an analyst/sensor-supplied indicator against the graph (REST
    /search/indicator, STIX indicator export, alert enrichment).

    Returns ``(resolved_type, normalized_value)``:
      - ``resolved_type`` is the given type, or — when it is "blank"
        (``None`` / empty / whitespace / the ``"unknown"`` sentinel) — the
        type inferred from the value's shape (:func:`infer_indicator_type`),
        or ``None`` if uninferable.
      - ``normalized_value`` is :func:`normalize_indicator_value` applied
        with the resolved type (refang + NFC + case-fold to the write-side
        MERGE key), stripped. May be ``""`` when the input is empty /
        whitespace / non-str — callers MUST treat ``""`` as "no usable
        lookup key" and not run a graph query against it.

    Centralizing this prevents the per-entrypoint drift where one path
    inferred + folded while another bound the raw value, so identical paste
    enriched on ingest yet returned not-found on search.
    """
    resolved_type = _resolve_graph_type(indicator_type, value)
    normalized = normalize_indicator_value(indicator_type, value)
    normalized = normalized.strip() if isinstance(normalized, str) else ""
    # A value that refangs/normalizes to pure punctuation (e.g. a bare
    # defang token "[.]" → ".") has no usable lookup key — treat as empty so
    # callers short-circuit instead of MATCHing a junk single-char value.
    if not any(ch.isalnum() for ch in normalized):
        normalized = ""
    return resolved_type, normalized


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


# Trailing ``(?![.\d])`` guard: after the (optional) sub-technique, the next
# char must not be a digit or a dot. So an over-long run ("T10590") or a
# malformed sub ("T1059.0012", "T1059.01") fails to match outright rather
# than silently truncating to a DIFFERENT real technique ("T1059"). Groups:
# 1 = 4-digit base, 2 = 3-digit sub (or None).
_MITRE_TECHNIQUE_RE = re.compile(r"t\s*(\d{4})(?:\.(\d{3}))?(?![.\d])", re.IGNORECASE)


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
    sub = match.group(2)
    return f"T{match.group(1)}.{sub}" if sub else f"T{match.group(1)}"
