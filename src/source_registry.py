"""Single-source-of-truth registry for EdgeGuard data sources.

Closes spawned-task chip 5a from the PR #41 audit: before this module,
five parallel hand-maintained registries described "what sources
EdgeGuard knows about". Every PR that touched sources had to keep them
in sync, and forgetting any one of the five produced a different
silent-failure mode:

* ``src/neo4j_client.py:SOURCES`` — drives ``ensure_sources`` (Neo4j
  ``:Source`` node creation) AND the defensive batch pre-validation
  added in PR #41 (refuses to write a SOURCED_FROM edge whose
  ``source_id`` is not in this dict).  **Forget to add a new source
  here → PR #41's defensive guard refuses every write from that source,
  silently dropping the relationship batch.**
* ``src/edgeguard.py:DEFAULT_SOURCES`` — drives the ``edgeguard
  sources`` CLI listing.  **Forget to add a new source here → it
  doesn't appear in the CLI; operators don't know it exists.**
* ``src/config.py:SOURCE_TAGS`` — maps the CLI shortname (``otx``,
  ``mitre``, ``cisa``) to the canonical collector-emitted tag
  (``alienvault_otx``, ``mitre_attck``, ``cisa_kev``).  **Forget to
  add a new source → collector falls back to its module-local
  ``self.tag = "..."`` constant, which may not match the canonical tag,
  silently fragmenting per-source provenance across two
  ``Source`` nodes.**
* ``src/source_truthful_timestamps.py:_RELIABLE_FIRST_SEEN_SOURCES`` —
  the allowlist of sources whose first/last_seen claims land on the
  ``r.source_reported_first_at`` / ``r.source_reported_last_at`` edge
  fields.  **Forget to add a new source here → its source-truthful
  timestamps are silently dropped (extract returns ``(None, None)``);
  the source-truthful pipeline that PR #41 just shipped is dead
  for that source.**
* ``src/collectors/misp_writer.py:MISPWriter.SOURCE_TAGS`` — maps
  source id to the human-readable MISP tag string (``source:NVD``,
  ``source:CISA-KEV``).  **Forget to add a new source → the MISP
  attribute carries no source tag, breaking the
  ``raw_data.original_source`` round-trip and silently disabling the
  source-truthful timestamp extraction in
  ``run_misp_to_neo4j.parse_attribute``.**

Every one of those failure modes is silent. Adding a new source today
is a five-place edit with five separate bugs waiting if you miss one.

This module replaces all five with a single declarative table. Each
of the five legacy registries becomes a one-liner derivation:

```python
# src/neo4j_client.py
from source_registry import to_neo4j_sources_dict
SOURCES = to_neo4j_sources_dict()  # shape unchanged; callers untouched

# src/edgeguard.py
from source_registry import to_cli_sources_dict
DEFAULT_SOURCES = to_cli_sources_dict()

# src/config.py
from source_registry import cli_to_canonical_tag_map
SOURCE_TAGS = cli_to_canonical_tag_map()

# src/source_truthful_timestamps.py
from source_registry import reliable_first_seen_aliases
_RELIABLE_FIRST_SEEN_SOURCES = reliable_first_seen_aliases()

# src/collectors/misp_writer.py
from source_registry import source_to_misp_tag_map
class MISPWriter:
    SOURCE_TAGS = source_to_misp_tag_map()
```

Every existing call site keeps the SAME variable name and the SAME
shape — this is a behavior-preserving refactor. Parity is pinned by
``tests/test_source_registry.py`` (the derived dicts must match
captured pre-refactor snapshots byte-for-byte).

To add a new source: append one ``Source(...)`` entry below. All five
derivations recompute on next import. ``test_adding_a_new_source_*``
in the test file pins the propagation invariant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

# ===========================================================================
# Source dataclass — one record per logical source
# ===========================================================================


@dataclass(frozen=True)
class Source:
    """A single threat-intel data source.

    Frozen so the registry can be a module-level constant safely shared
    across processes / threads (no accidental mutation).

    Attributes
    ----------
    canonical_id : str
        The canonical tag — what the collector emits and what
        ``:Source.source_id`` is keyed on in Neo4j. MUST be lowercased
        + ASCII; case-sensitive comparisons depend on it.
    aliases : tuple[str, ...]
        Additional case-insensitive lookup keys for the same source.
        E.g. ``Source(canonical_id="cisa_kev", aliases=("cisa",))``
        — both spellings find the same record. ``canonical_id`` is
        IMPLICITLY the first alias; do not include it again.
    display_name : str
        Human-readable name shown in CLI / docs / Neo4j ``:Source.name``.
    source_type : str
        One of ``threat_intel`` / ``advisory`` / ``framework`` /
        ``vulnerability_db`` / ``curated``. Drives Neo4j ``:Source.type``.
        ``curated`` marks a curated package imported once into MISP rather
        than a feed polled by a collector.
    reliability : float
        ``[0.0, 1.0]`` confidence base used by the merge layer for
        corroboration scoring. Drives Neo4j ``:Source.reliability``.
    cli_id : Optional[str]
        Short id used in ``edgeguard run --sources X,Y,Z`` and the
        ``edgeguard sources`` CLI listing. ``None`` means the source
        is not exposed via the CLI (rare; mostly for sources that are
        always-on / have no toggle).
    api_key_env : Optional[str]
        Env var name for the API key. ``None`` for free / no-key sources.
    rate_limit : str
        Human-readable rate limit (e.g. ``"30/min"``, ``"1000/day"``,
        ``"unlimited"``). Surfaced in the CLI listing for operator
        capacity planning.
    cli_default_enabled : bool
        Whether the CLI lists this source as enabled-by-default.
        ``False`` for sources that require keys the user might not
        have or that we deliberately keep dormant.
    cli_description : str
        One-sentence description for the CLI listing.
    misp_tag : str
        The MISP tag string the writer attaches to attributes
        (``"source:NVD"`` / ``"source:CISA-KEV"`` etc.). Round-trips
        as ``raw_data.original_source`` via ``parse_attribute``.
    reliable_first_seen : bool
        ``True`` ⇒ this source's first_seen / last_seen claims land
        on the ``SOURCED_FROM`` edge as
        ``r.source_reported_first_at`` / ``r.source_reported_last_at``.
        ``False`` ⇒ the source publishes a first_seen field but it
        means something other than "first observed" (OTX
        pulse-publish-date, MISP-only pipeline metadata) —
        extractor returns
        ``(None, None)`` and the value never reaches the edge.
    """

    canonical_id: str
    display_name: str
    source_type: str
    reliability: float
    misp_tag: str
    reliable_first_seen: bool
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    cli_id: Optional[str] = None
    api_key_env: Optional[str] = None
    rate_limit: str = "unlimited"
    cli_default_enabled: bool = True
    cli_description: str = ""
    # Curated sources (2026-10): the evidence label (``r.match_type``) of the claims a package
    # curated by this source carries. ``None`` for feeds; a curated
    # package from a source without one gets ``CURATED_OTHER_LABEL``.
    curated_label: Optional[str] = None
    # Optional override for the CLI listing's "name" column. Defaults
    # to display_name when unset. The only source that uses this today
    # is NVD: the historical CLI listing called it "National
    # Vulnerability Database" while the historical Neo4j Source.name
    # was just "NVD" (acronym fits dashboard widths). Refactor
    # preserves both.
    cli_display_name: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate Source invariants at construction time.

        PR #43 audit-2 (Maintainer Dev / Bug Hunter): the previous
        contract said "MUST be lowercased" in a docstring but no
        runtime check enforced it. Adding ``Source(aliases=("VT",))``
        with uppercase silently broke ``get_source`` (which lowercases
        the input but compared against the raw key). Catch the violation
        at registration so a future contributor sees the failure
        immediately.
        """
        # canonical_id MUST be lowercase ASCII (matches Cypher / collector convention)
        if self.canonical_id != self.canonical_id.lower() or not self.canonical_id.isascii():
            raise ValueError(f"Source(canonical_id={self.canonical_id!r}): canonical_id must be lowercase ASCII")
        # Same for every alias
        for alias in self.aliases:
            if alias != alias.lower() or not alias.isascii():
                raise ValueError(
                    f"Source(canonical_id={self.canonical_id!r}, aliases=...): alias {alias!r} must be lowercase ASCII"
                )

    @property
    def all_keys(self) -> Tuple[str, ...]:
        """``(canonical_id,) + aliases`` — every key under which this
        source can be looked up: ``get_source`` / ``canonical_source_id``,
        the reliable first-seen allowlist, the MISP tag map and the
        metrics label bound. The Neo4j ``Source`` node is keyed by
        ``canonical_id`` alone (``to_neo4j_sources_dict``).
        """
        return (self.canonical_id,) + self.aliases


# ===========================================================================
# The registry — single source of truth
# ===========================================================================
#
# ORDERING NOTE: tests/test_source_registry.py asserts the LEGACY
# byte-for-byte shape of every derived dict. The order of entries in
# this list IS PART OF THE PUBLIC CONTRACT for the derived ``SOURCES``
# / ``DEFAULT_SOURCES`` dicts (Python 3.7+ dicts preserve insertion
# order; downstream callers that iterate may depend on it). When
# adding a new source, append AT THE END unless there's a specific
# reason to insert earlier.
#
# Entries are listed in the historical order they appeared in the
# legacy ``SOURCES`` dict in ``neo4j_client.py``, so the derived
# dict matches byte-for-byte.

_REGISTRY: Tuple[Source, ...] = (
    Source(
        canonical_id="alienvault_otx",
        aliases=("otx",),
        display_name="AlienVault OTX",
        source_type="threat_intel",
        reliability=0.7,
        cli_id="otx",
        api_key_env="OTX_API_KEY",
        rate_limit="30/min",
        cli_default_enabled=True,
        cli_description="Threat intelligence pulses",
        misp_tag="source:AlienVault-OTX",
        # OTX pulse.created is the pulse-author-time, NOT the IOC
        # first-observed time. Excluded from source-truthful pipeline.
        reliable_first_seen=False,
    ),
    Source(
        canonical_id="virustotal",
        aliases=("vt",),
        display_name="VirusTotal",
        source_type="threat_intel",
        reliability=0.8,
        cli_id="virustotal",
        api_key_env="VIRUSTOTAL_API_KEY",
        rate_limit="4/min",
        cli_default_enabled=True,
        cli_description="File and URL reputation",
        misp_tag="source:VirusTotal",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="abuseipdb",
        display_name="AbuseIPDB",
        source_type="threat_intel",
        reliability=0.65,
        cli_id="abuseipdb",
        api_key_env="ABUSEIPDB_API_KEY",
        rate_limit="1000/day",
        cli_default_enabled=False,
        cli_description="IP reputation",
        misp_tag="source:AbuseIPDB",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="mitre_attck",
        aliases=("mitre",),
        display_name="MITRE ATT&CK",
        source_type="framework",
        reliability=0.95,
        cli_id="mitre",
        api_key_env=None,
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Threat techniques and tactics",
        misp_tag="source:MITRE-ATT&CK",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="nvd",
        display_name="NVD",
        # Historical asymmetry: Neo4j stores the acronym (fits in
        # dashboard widths), CLI listing spells out the full name.
        cli_display_name="National Vulnerability Database",
        source_type="vulnerability_db",
        reliability=0.9,
        cli_id="nvd",
        api_key_env="NVD_API_KEY",
        rate_limit="30/30sec",
        cli_default_enabled=True,
        cli_description="CVE vulnerabilities",
        misp_tag="source:NVD",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="misp",
        display_name="MISP",
        source_type="threat_intel",
        reliability=0.75,
        cli_id="misp",
        api_key_env="MISP_API_KEY",
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Central threat intelligence hub",
        misp_tag="source:MISP",
        # MISP-collector / sector feeds are pipeline metadata only —
        # not a source-truthful first-seen claim.
        reliable_first_seen=False,
    ),
    Source(
        canonical_id="cisa_kev",
        aliases=("cisa",),
        display_name="CISA KEV",
        source_type="advisory",
        reliability=0.9,
        cli_id="cisa",
        api_key_env=None,
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Known exploited vulnerabilities",
        misp_tag="source:CISA-KEV",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="feodo_tracker",
        aliases=("feodo",),
        display_name="Feodo Tracker",
        source_type="threat_intel",
        reliability=0.7,
        cli_id="feodo",
        api_key_env=None,
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Banking trojan C&C servers",
        misp_tag="source:Feodo-Tracker",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="ssl_blacklist",
        aliases=("sslbl", "abusech_ssl"),
        display_name="SSL Blacklist",
        source_type="threat_intel",
        reliability=0.65,
        cli_id="sslbl",
        api_key_env=None,
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Malicious SSL certificates",
        misp_tag="source:SSL-Blacklist",
        reliable_first_seen=True,
    ),
    # URLhaus: the v2 ``recent.csv`` export carries the abuse.ch Auth-Key in its URL path, the
    # key ThreatFox and MalwareBazaar use too (``THREATFOX_API_KEY``); without it the source is
    # skipped.
    Source(
        canonical_id="urlhaus",
        display_name="URLhaus",
        source_type="threat_intel",
        reliability=0.7,
        cli_id="urlhaus",
        api_key_env="THREATFOX_API_KEY",
        rate_limit="unlimited",
        cli_default_enabled=True,
        cli_description="Malware URLs",
        misp_tag="source:URLhaus",
        reliable_first_seen=True,
    ),
    Source(
        canonical_id="threatfox",
        display_name="ThreatFox",
        source_type="threat_intel",
        reliability=0.7,
        cli_id="threatfox",
        api_key_env="THREATFOX_API_KEY",
        rate_limit="unlimited",
        cli_default_enabled=False,
        cli_description="Threat actor indicators",
        misp_tag="source:ThreatFox",
        reliable_first_seen=True,
    ),
    # CISA ICS advisories (2026-10): CSAF 2.0 files from cisagov/CSAF with a
    # source-asserted critical-infrastructure sector per advisory. Flag-guarded
    # (EDGEGUARD_ENABLE_CISA_ICS, default OFF) — hence cli_default_enabled=False.
    Source(
        canonical_id="cisa_ics",
        aliases=("cisa-ics", "ics_advisories"),
        display_name="CISA ICS Advisories",
        source_type="advisory",
        reliability=0.9,
        cli_id="cisa_ics",
        api_key_env=None,
        rate_limit="unlimited",
        cli_default_enabled=False,
        cli_description="ICS-CERT advisories with critical-infrastructure sectors",
        misp_tag="source:CISA-ICS",
        # initial_release_date / current_release_date are CISA's own publish
        # timestamps — a genuine source-truthful first/last claim.
        reliable_first_seen=True,
    ),
    # MalwareBazaar (abuse.ch, 2026-10): sha256 hashes of recent malware samples with the
    # family label (``signature``). Flag-guarded (EDGEGUARD_ENABLE_MALWAREBAZAAR, default
    # OFF) — hence cli_default_enabled=False. The recent export carries the abuse.ch Auth-Key
    # (``THREATFOX_API_KEY``) in its URL path; without it the source is skipped.
    Source(
        canonical_id="malwarebazaar",
        aliases=("bazaar", "mb"),
        display_name="MalwareBazaar",
        source_type="threat_intel",
        reliability=0.7,
        cli_id="malwarebazaar",
        api_key_env="THREATFOX_API_KEY",
        rate_limit="unlimited",
        cli_default_enabled=False,
        cli_description="Malware sample hashes with family labels",
        misp_tag="source:MalwareBazaar",
        # first_seen_utc is when MalwareBazaar first saw the sample — a genuine
        # source-truthful first-seen claim (same treatment as URLhaus / ThreatFox).
        reliable_first_seen=True,
    ),
    # Curated sources (2026-10): packages imported once into MISP as their own event, not
    # feeds polled by a collector — hence no ``cli_id``. No aliases on purpose: every alias
    # becomes an extra ``:Source`` node (see ``to_neo4j_sources_dict``).
    Source(
        canonical_id="coreideas",
        display_name="Core Ideas",
        source_type="curated",
        reliability=0.85,
        cli_default_enabled=False,
        cli_description="Curated threat-intelligence package (one-time import)",
        misp_tag="source:CoreIdeas",
        # A curated claim has no first-observed date of its own.
        reliable_first_seen=False,
        curated_label="coreideas_curated",
    ),
    Source(
        canonical_id="misp_galaxy",
        display_name="MISP Galaxy",
        source_type="curated",
        reliability=0.8,
        cli_default_enabled=False,
        cli_description="MISP galaxy clusters (community knowledge base)",
        misp_tag="source:MISP-Galaxy",
        reliable_first_seen=False,
    ),
)


# ===========================================================================
# Lookup helpers
# ===========================================================================


def all_sources() -> Tuple[Source, ...]:
    """Return the registry tuple in declaration order."""
    return _REGISTRY


def get_source(id_or_alias: str) -> Optional[Source]:
    """Resolve any canonical id OR alias to its ``Source`` record.

    Case-insensitive (lowercased + stripped). Returns ``None`` for
    unknown ids — callers should treat that as "not in the registry"
    not "use a default" (no defaults; we want explicit failures).
    """
    if not id_or_alias:
        return None
    needle = id_or_alias.strip().lower()
    if not needle:
        return None
    for src in _REGISTRY:
        if needle in src.all_keys:
            return src
    return None


def all_aliases() -> FrozenSet[str]:
    """Every key under which any source can be looked up — canonical
    ids + aliases, all lowercased. Used by ``metrics_server`` to
    bound the ``source_id`` Prometheus label cardinality.
    """
    out: set[str] = set()
    for src in _REGISTRY:
        out.update(src.all_keys)
    return frozenset(out)


def _validate_no_alias_collisions() -> None:
    """PR #43 audit-2 (MED — bugbot): two ``Source`` records sharing an
    alias would produce divergent results between ``get_source`` (which
    returns the FIRST match) and the dict-building helpers (``out[key] = ...``
    LAST wins). Validate at module import time so a contributor's typo
    fails immediately, not silently in production.

    Pre-existing test ``test_aliases_do_not_collide_with_other_sources_canonical_ids``
    only checked alias-vs-canonical-id collisions; this catches the
    alias-vs-alias case too.
    """
    seen: Dict[str, str] = {}  # key → first canonical_id that owns it
    for src in _REGISTRY:
        for key in src.all_keys:
            owner = seen.get(key)
            if owner is not None and owner != src.canonical_id:
                raise ValueError(
                    f"Source registry: alias collision on {key!r} — "
                    f"both {owner!r} and {src.canonical_id!r} claim it. "
                    "Two sources sharing an alias produce divergent results "
                    "between get_source (first wins) and the dict-building "
                    "helpers (last wins). Pick a unique alias."
                )
            seen[key] = src.canonical_id


_validate_no_alias_collisions()


# ===========================================================================
# Derivation helpers — each replaces one of the 5 legacy registries
# ===========================================================================


def to_neo4j_sources_dict() -> Dict[str, Dict[str, object]]:
    """The ``neo4j_client.SOURCES`` dict: ``{canonical_id: {"name": str, "type": str, "reliability": float}}``.

    One entry per registered source, keyed by its canonical id, in registry order.
    ``ensure_sources`` creates one ``Source`` node per entry, so the graph holds one node per
    source. An alias (``otx``, ``cisa``, ``vt``, ...) is a lookup key and never a node: every
    ``SOURCED_FROM`` writer resolves the id it is given with ``canonical_source_id`` before it
    matches the ``Source`` node.
    """
    return {
        src.canonical_id: {
            "name": src.display_name,
            "type": src.source_type,
            "reliability": src.reliability,
        }
        for src in _REGISTRY
    }


# PR #43 audit-2 (LOW — bugbot): the legacy `edgeguard.DEFAULT_SOURCES`
# dict had a hand-curated key order that drove the `edgeguard sources`
# CLI listing. The pre-refactor order was (otx, nvd, virustotal, cisa,
# mitre, abuseipdb, urlhaus, feodo, sslbl, threatfox, misp);
# the registry order matches `neo4j_client.SOURCES` instead, which
# differs. Use this explicit list to preserve operator-facing ordering.
# Anything not in the list is appended in registry order at the end —
# so adding a new Source with a fresh `cli_id` doesn't require updating
# this list (it just appears at the end of the CLI listing, which is
# the expected behavior for a new source).
_LEGACY_CLI_LISTING_ORDER: Tuple[str, ...] = (
    "otx",
    "nvd",
    "virustotal",
    "cisa",
    "mitre",
    "abuseipdb",
    "urlhaus",
    "feodo",
    "sslbl",
    "threatfox",
    "misp",
)


def to_cli_sources_dict() -> Dict[str, Dict[str, object]]:
    """Re-creates the legacy ``edgeguard.DEFAULT_SOURCES`` dict shape.

    Schema: ``{cli_id: {"name", "api_key_env", "rate_limit", "enabled",
    "description"}}``

    One entry per source whose ``cli_id`` is set (currently all of
    them). Skips sources with ``cli_id is None``.

    Insertion order matches the legacy ``DEFAULT_SOURCES`` order via
    ``_LEGACY_CLI_LISTING_ORDER`` (PR #43 audit-2 LOW — bugbot:
    operators iterating the CLI listing depend on this order).
    Sources whose ``cli_id`` is not in the legacy list are appended
    in registry order at the end.

    Raises ``ValueError`` if two ``Source`` records share a ``cli_id``
    (PR #43 audit M2 — Devil's Advocate / Cross-Checker): the previous
    implementation silently overwrote the earlier entry, so a
    contributor who accidentally re-used an existing ``cli_id`` for
    a new source would get the new mapping AND drop the old one with
    no error. Both ``to_cli_sources_dict`` and
    ``cli_to_canonical_tag_map`` enforce the same uniqueness check.
    """
    by_cli_id: Dict[str, Source] = {}
    for src in _REGISTRY:
        if src.cli_id is None:
            continue
        if src.cli_id in by_cli_id:
            raise ValueError(
                f"duplicate cli_id={src.cli_id!r} in registry: "
                f"second occurrence on canonical_id={src.canonical_id!r}. "
                "Each cli_id must map to exactly one Source — silently "
                "overwriting would drop the earlier source from the CLI listing."
            )
        by_cli_id[src.cli_id] = src

    out: Dict[str, Dict[str, object]] = {}
    # First emit entries in the documented legacy order
    for cli_id in _LEGACY_CLI_LISTING_ORDER:
        if cli_id in by_cli_id:
            out[cli_id] = _cli_payload(by_cli_id.pop(cli_id))
    # Then any new sources (not in the legacy list) in registry order
    for cli_id, src in by_cli_id.items():
        out[cli_id] = _cli_payload(src)
    return out


def _cli_payload(src: Source) -> Dict[str, object]:
    """Helper: construct the per-source CLI dict payload."""
    return {
        "name": src.cli_display_name or src.display_name,
        "api_key_env": src.api_key_env,
        "rate_limit": src.rate_limit,
        "enabled": src.cli_default_enabled,
        "description": src.cli_description,
    }


def cli_to_canonical_tag_map() -> Dict[str, str]:
    """Re-creates the legacy ``config.SOURCE_TAGS`` dict shape.

    Schema: ``{cli_id: canonical_tag}`` — used by collectors to set
    ``self.tag = SOURCE_TAGS["nvd"]`` etc.

    One entry per source whose ``cli_id`` is set; the value is the
    source's ``canonical_id`` (so a source with ``cli_id="cisa"``
    and ``canonical_id="cisa_kev"`` produces ``{"cisa": "cisa_kev"}``).

    NOTE: the legacy ``config.SOURCE_TAGS`` only listed 7 sources
    (the ones with collectors that look themselves up by shortname).
    For backward-compat ``cli_to_canonical_tag_map_legacy_subset``
    matches the historical 7-key shape — wire it from
    ``config.SOURCE_TAGS``. **Use the full map below ONLY for new
    callers** (PR #43 audit M3): existing collector code does
    ``SOURCE_TAGS["X"]`` and relies on KeyError on typos. Widening
    the legacy 7 keys to all 12 silently starts resolving keys that
    previously failed — undesired behavior change.

    Raises ``ValueError`` on duplicate ``cli_id`` — same uniqueness
    invariant as ``to_cli_sources_dict``.
    """
    out: Dict[str, str] = {}
    for src in _REGISTRY:
        if src.cli_id is None:
            continue
        if src.cli_id in out:
            raise ValueError(
                f"duplicate cli_id={src.cli_id!r} in registry: "
                f"second occurrence on canonical_id={src.canonical_id!r}. "
                "Each cli_id must map to exactly one canonical_id."
            )
        out[src.cli_id] = src.canonical_id
    return out


# Subset of cli_to_canonical_tag_map that matches the legacy 7-key
# config.SOURCE_TAGS — kept verbatim so existing collectors that do
# ``SOURCE_TAGS["X"]`` (KeyError on missing) don't suddenly start
# resolving keys that didn't exist before.
_LEGACY_SOURCE_TAGS_KEYS: FrozenSet[str] = frozenset({"misp", "otx", "nvd", "cisa", "mitre", "virustotal", "abuseipdb"})


def cli_to_canonical_tag_map_legacy_subset() -> Dict[str, str]:
    """Same as ``cli_to_canonical_tag_map`` but restricted to the
    7 keys the historical ``config.SOURCE_TAGS`` exposed.

    Existing collector code does ``SOURCE_TAGS["X"]`` and EXPECTS
    KeyError on a missing key (defensive: catches typos at collector
    init). Widening the legacy 7-key map to the full ~12-key map
    would silently start resolving keys that previously failed —
    behavior change. Use this restricted form when wiring
    ``config.SOURCE_TAGS`` for backward-compat.
    """
    full = cli_to_canonical_tag_map()
    return {k: v for k, v in full.items() if k in _LEGACY_SOURCE_TAGS_KEYS}


def reliable_first_seen_aliases() -> FrozenSet[str]:
    """Re-creates the legacy ``_RELIABLE_FIRST_SEEN_SOURCES`` frozenset.

    Returns every key (canonical id + aliases) of every source whose
    ``reliable_first_seen`` flag is True. The
    ``is_reliable_first_seen_source`` lookup runs against this set
    after lowercasing the input.
    """
    out: set[str] = set()
    for src in _REGISTRY:
        if src.reliable_first_seen:
            out.update(src.all_keys)
    return frozenset(out)


def misp_tag_to_canonical_map() -> Dict[str, str]:
    """``{misp_tag_name_without_prefix: canonical_id}`` — the reverse of ``source_to_misp_tag_map``.

    Drives ``MISPToNeo4jSync.SOURCE_MAPPING`` (``source:ThreatFox`` → ``threatfox``), which
    used to be a sixth hand-kept list: a source added here without that list was synced as
    ``misp``.
    """
    out: Dict[str, str] = {}
    for src in _REGISTRY:
        name = src.misp_tag[len("source:") :] if src.misp_tag.startswith("source:") else src.misp_tag
        out[name] = src.canonical_id
    return out


# Evidence label of a curated claim whose package source has no ``curated_label``. Also the name
# under which the sync records a claim source that is not a registered curated source
# (``is_curated_source``) in ``r.sources`` / ``r.source_refs`` (2026-10): the labels and the
# source names of the curated layer both come from closed lists.
CURATED_OTHER_LABEL = "curated_other"


def curated_label_for(source: Optional[str]) -> str:
    """The ``r.match_type`` of claims in a curated package from ``source`` (2026-10).

    The registered source's ``curated_label``, else
    ``curated_other`` — the label list stays closed whatever package arrives.
    """
    src = get_source(source) if source else None
    return (src.curated_label if src and src.curated_label else None) or CURATED_OTHER_LABEL


def curated_source_ids() -> Tuple[str, ...]:
    """Canonical ids of the registered curated sources, in registry order (2026-10)."""
    return tuple(src.canonical_id for src in _REGISTRY if src.source_type == "curated")


def is_curated_source(name: Optional[str]) -> bool:
    """True when ``name`` (id or alias) is a registered curated source (2026-10).

    Only these may assert a curated claim: ``scripts/import_curated_package.py`` refuses a claim
    from any other source, and the sync records one that still arrives under
    ``CURATED_OTHER_LABEL``, so no other name reaches ``r.sources`` or the STIX export.
    """
    src = get_source(name) if name else None
    return src is not None and src.source_type == "curated"


def canonical_source_id(name: Optional[str]) -> Optional[str]:
    """Return the canonical id for a source name or alias; an unknown name comes back normalised.

    Relationship provenance (``r.sources``) names the feed, never an evidence label. An
    unknown name is kept (lowercased, stripped) so attribution is never lost; ``get_source``
    tells a caller whether the name is registered. ``None`` for a missing or blank name.
    """
    if name is None:
        return None
    needle = str(name).strip().lower()
    if not needle:
        return None
    src = get_source(needle)
    return src.canonical_id if src else needle


SOURCE_REF_SEPARATOR = ":"
_SOURCE_REF_MAX_RECORD_CHARS = 200


def format_source_ref(source: Optional[str], record_id: object) -> Optional[str]:
    """``"<canonical source>:<record id>"``: a feed's own id for the record behind a claim.

    Examples: ``alienvault_otx:5f3c…`` (OTX pulse), ``threatfox:1234567`` (IOC id),
    ``mitre_attck:G0016`` (ATT&CK id). ``None`` when either part is missing or blank. The
    record id is trimmed and capped so a malformed upstream value cannot bloat a property.
    """
    src = canonical_source_id(source)
    if not src or record_id is None:
        return None
    rid = str(record_id).strip()
    if not rid:
        return None
    return f"{src}{SOURCE_REF_SEPARATOR}{rid[:_SOURCE_REF_MAX_RECORD_CHARS]}"


# CISA ICS advisory ids (2026-10-16): ``ICSA-24-123-01`` (ICS advisories) and ``ICSMA-24-123-01`` (ICS
# medical advisories), each with an optional revision letter. The public page of an advisory is under
# the path of its kind on cisa.gov.
_CISA_ICS_ADVISORY_ID_RE = re.compile(r"^(?P<kind>ICSA|ICSMA)-\d{2}-\d{3}-\d{2}[A-Z]?$")
_CISA_ICS_ADVISORY_PATHS = {"ICSA": "ics-advisories", "ICSMA": "ics-medical-advisories"}


def cisa_ics_advisory_url(advisory_id: object) -> Optional[str]:
    """The cisa.gov page of a CISA ICS advisory id (2026-10-16); ``None`` for an id of another form.

    One rule for the collector (``cisa_ics_collector.advisory_url``, when the advisory names no page of
    its own) and the STIX export (``external_references`` of ``cisa_ics:<advisory id>``).
    """
    rid = str(advisory_id or "").strip().upper()
    match = _CISA_ICS_ADVISORY_ID_RE.match(rid)
    if not match:
        return None
    return f"https://www.cisa.gov/news-events/{_CISA_ICS_ADVISORY_PATHS[match.group('kind')]}/{rid.lower()}"


def source_to_misp_tag_map() -> Dict[str, str]:
    """Re-creates the legacy ``MISPWriter.SOURCE_TAGS`` dict.

    Schema: ``{source_id: misp_tag_string}``. One entry per alias so
    a writer call that looks up by either the canonical id OR a legacy
    alias finds the same MISP tag.

    NOTE: the historical map skipped a few aliases (e.g. it had
    ``feodo`` but not ``feodo_tracker``). For backward-compat we
    ship a full alias-expanded map — adding new keys does NOT change
    existing behavior because looking up an unrecognized key was
    already a no-op (the writer skipped the tag). New aliases just
    extend the lookup surface.
    """
    out: Dict[str, str] = {}
    for src in _REGISTRY:
        for key in src.all_keys:
            out[key] = src.misp_tag
    return out
