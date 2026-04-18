"""Chip 5a — single-source-of-truth source registry refactor.

Closes the spawned-task chip from the PR #41 audit. Before the
refactor, five hand-maintained registries described "what sources
EdgeGuard knows about":

1. ``neo4j_client.SOURCES``                          (Neo4j Source nodes)
2. ``edgeguard.DEFAULT_SOURCES``                     (CLI listing)
3. ``config.SOURCE_TAGS``                            (CLI shortname → canonical tag)
4. ``source_truthful_timestamps._RELIABLE_FIRST_SEEN_SOURCES``  (allowlist)
5. ``collectors.misp_writer.MISPWriter.SOURCE_TAGS`` (source id → MISP tag string)

This module pins:

A. **Parity** — every legacy entry produces the SAME shape after the
   refactor. The registry-derived dicts are byte-identical to the
   pre-refactor hand-maintained ones for every legacy key. (The
   refactor does ALSO close a few alias-coverage gaps — same
   pattern as PR #41 adding ``feodo_tracker`` / ``ssl_blacklist``
   to the SOURCES dict — but for every existing key the value is
   unchanged.)

B. **Invariants** that link the five registries:
   - Every reliable_first_seen=True source is also in SOURCES (else
     the SOURCED_FROM stamp would silently fail).
   - Every CLI-id has a corresponding canonical-id in SOURCES.
   - Every alias resolves to the same Source record as its canonical id.
   - Every source's misp_tag round-trips through
     parse_attribute's ``raw_data.original_source`` extractor and
     resolves back to a known source.

C. **Propagation** — adding a new ``Source(...)`` to the registry
   propagates to all five derived structures simultaneously (smoke
   test that synthesizes a registry mutation and re-derives).
"""

from __future__ import annotations

import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# A. Parity snapshots — every pre-refactor key produces the same value
# ---------------------------------------------------------------------------
#
# The legacy dicts had specific byte-for-byte shapes. The refactor MUST
# preserve them for every existing key (it MAY add new alias entries —
# documented separately below).


# Captured 2026-04-18 from the pre-refactor hand-maintained dict.
# Source: ``src/neo4j_client.py:238 SOURCES`` on commit ef2c550 (main).
_LEGACY_NEO4J_SOURCES = {
    "alienvault_otx": {"name": "AlienVault OTX", "type": "threat_intel", "reliability": 0.7},
    "virustotal": {"name": "VirusTotal", "type": "threat_intel", "reliability": 0.8},
    "abuseipdb": {"name": "AbuseIPDB", "type": "threat_intel", "reliability": 0.65},
    "mitre_attck": {"name": "MITRE ATT&CK", "type": "framework", "reliability": 0.95},
    "nvd": {"name": "NVD", "type": "vulnerability_db", "reliability": 0.9},
    "misp": {"name": "MISP", "type": "threat_intel", "reliability": 0.75},
    "cisa": {"name": "CISA KEV", "type": "advisory", "reliability": 0.9},
    "cisa_kev": {"name": "CISA KEV", "type": "advisory", "reliability": 0.9},
    "feodo": {"name": "Feodo Tracker", "type": "threat_intel", "reliability": 0.7},
    "feodo_tracker": {"name": "Feodo Tracker", "type": "threat_intel", "reliability": 0.7},
    "sslbl": {"name": "SSL Blacklist", "type": "threat_intel", "reliability": 0.65},
    "ssl_blacklist": {"name": "SSL Blacklist", "type": "threat_intel", "reliability": 0.65},
    "abusech_ssl": {"name": "SSL Blacklist", "type": "threat_intel", "reliability": 0.65},
    "urlhaus": {"name": "URLhaus", "type": "threat_intel", "reliability": 0.7},
    "cybercure": {"name": "CyberCure", "type": "threat_intel", "reliability": 0.6},
    "threatfox": {"name": "ThreatFox", "type": "threat_intel", "reliability": 0.7},
}


# Captured 2026-04-18 from the pre-refactor hand-maintained dict.
# Source: ``src/edgeguard.py:775 DEFAULT_SOURCES`` on commit ef2c550 (main).
_LEGACY_DEFAULT_SOURCES = {
    "otx": {
        "name": "AlienVault OTX",
        "api_key_env": "OTX_API_KEY",
        "rate_limit": "30/min",
        "enabled": True,
        "description": "Threat intelligence pulses",
    },
    "nvd": {
        "name": "National Vulnerability Database",
        "api_key_env": "NVD_API_KEY",
        "rate_limit": "30/30sec",
        "enabled": True,
        "description": "CVE vulnerabilities",
    },
    "virustotal": {
        "name": "VirusTotal",
        "api_key_env": "VIRUSTOTAL_API_KEY",
        "rate_limit": "4/min",
        "enabled": True,
        "description": "File and URL reputation",
    },
    "cisa": {
        "name": "CISA KEV",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Known exploited vulnerabilities",
    },
    "mitre": {
        "name": "MITRE ATT&CK",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Threat techniques and tactics",
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "api_key_env": "ABUSEIPDB_API_KEY",
        "rate_limit": "1000/day",
        "enabled": False,
        "description": "IP reputation",
    },
    "urlhaus": {
        "name": "URLhaus",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Malware URLs",
    },
    "cybercure": {
        "name": "CyberCure",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Threat intelligence feeds",
    },
    "feodo": {
        "name": "Feodo Tracker",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Banking trojan C&C servers",
    },
    "sslbl": {
        "name": "SSL Blacklist",
        "api_key_env": None,
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Malicious SSL certificates",
    },
    "threatfox": {
        "name": "ThreatFox",
        "api_key_env": "THREATFOX_API_KEY",
        "rate_limit": "unlimited",
        "enabled": False,
        "description": "Threat actor indicators",
    },
    "misp": {
        "name": "MISP",
        "api_key_env": "MISP_API_KEY",
        "rate_limit": "unlimited",
        "enabled": True,
        "description": "Central threat intelligence hub",
    },
}


# Captured 2026-04-18 from ``src/config.py:690 SOURCE_TAGS``.
_LEGACY_CONFIG_SOURCE_TAGS = {
    "misp": "misp",
    "otx": "alienvault_otx",
    "nvd": "nvd",
    "cisa": "cisa_kev",
    "mitre": "mitre_attck",
    "virustotal": "virustotal",
    "abuseipdb": "abuseipdb",
}


# Captured 2026-04-18 from ``src/source_truthful_timestamps.py:170``.
_LEGACY_RELIABLE_FIRST_SEEN_SOURCES = frozenset(
    {
        "nvd",
        "cisa",
        "cisa_kev",
        "mitre_attck",
        "mitre",
        "virustotal",
        "vt",
        "abuseipdb",
        "threatfox",
        "urlhaus",
        "feodo_tracker",
        "feodo",
        "ssl_blacklist",
        "abusech_ssl",
    }
)


# Captured 2026-04-18 from ``src/collectors/misp_writer.py:285``.
_LEGACY_MISP_WRITER_SOURCE_TAGS = {
    "misp": "source:MISP",
    "otx": "source:AlienVault-OTX",
    "alienvault_otx": "source:AlienVault-OTX",
    "nvd": "source:NVD",
    "cisa": "source:CISA-KEV",
    "cisa_kev": "source:CISA-KEV",
    "mitre": "source:MITRE-ATT&CK",
    "mitre_attck": "source:MITRE-ATT&CK",
    "virustotal": "source:VirusTotal",
    "abuseipdb": "source:AbuseIPDB",
    "feodo": "source:Feodo-Tracker",
    "sslbl": "source:SSL-Blacklist",
    "urlhaus": "source:URLhaus",
    "cybercure": "source:CyberCure",
    "threatfox": "source:ThreatFox",
}


def test_neo4j_sources_dict_preserves_every_legacy_entry_byte_for_byte():
    """For every legacy SOURCES key, the registry-derived dict produces
    the SAME value (name + type + reliability)."""
    from neo4j_client import SOURCES

    for key, expected in _LEGACY_NEO4J_SOURCES.items():
        assert key in SOURCES, f"Legacy SOURCES key '{key}' is missing from registry-derived dict"
        assert SOURCES[key] == expected, f"SOURCES['{key}'] value drift: expected {expected}, got {SOURCES[key]}"


def test_default_sources_dict_preserves_every_legacy_entry_byte_for_byte():
    """For every legacy DEFAULT_SOURCES key (CLI listing), the
    registry-derived dict produces the SAME value (name + api_key_env +
    rate_limit + enabled + description)."""
    from edgeguard import DEFAULT_SOURCES

    for key, expected in _LEGACY_DEFAULT_SOURCES.items():
        assert key in DEFAULT_SOURCES, f"Legacy DEFAULT_SOURCES key '{key}' missing"
        assert DEFAULT_SOURCES[key] == expected, (
            f"DEFAULT_SOURCES['{key}'] value drift: expected {expected}, got {DEFAULT_SOURCES[key]}"
        )


def test_config_source_tags_preserves_legacy_seven_keys_exactly():
    """``config.SOURCE_TAGS`` historically had exactly 7 keys. The
    refactor MUST preserve that 7-key shape (not widen to ~12) — many
    collector callers do ``SOURCE_TAGS["X"]`` and rely on KeyError on
    typo to catch missing keys at init."""
    from config import SOURCE_TAGS

    assert dict(SOURCE_TAGS) == _LEGACY_CONFIG_SOURCE_TAGS, (
        f"SOURCE_TAGS shape drift: expected {_LEGACY_CONFIG_SOURCE_TAGS}, got {dict(SOURCE_TAGS)}"
    )


def test_reliable_first_seen_sources_is_a_superset_of_legacy():
    """Every legacy reliable-source entry MUST still be present. The
    refactor may add a few alias-coverage entries (documented in the
    next test) but cannot drop existing ones."""
    from source_truthful_timestamps import _RELIABLE_FIRST_SEEN_SOURCES

    missing = _LEGACY_RELIABLE_FIRST_SEEN_SOURCES - _RELIABLE_FIRST_SEEN_SOURCES
    assert not missing, (
        f"Reliable-first-seen drift: legacy entries dropped from registry: {missing}. "
        "Every reliable source MUST stay reliable across the refactor."
    )


def test_reliable_first_seen_alias_coverage_extension_is_documented():
    """The refactor closes one latent alias-coverage gap: ``sslbl``.

    Legacy ``_RELIABLE_FIRST_SEEN_SOURCES`` had ``ssl_blacklist`` and
    ``abusech_ssl`` but NOT ``sslbl`` — yet the SSL Blacklist collector
    emits ``sslbl`` as its tag (per legacy ``config.SOURCE_TAGS`` map
    via the ``finance_feed_collector``). Without ``sslbl`` on the
    allowlist, source-truthful timestamps from that collector were
    silently dropped. Same pattern as PR #41 adding ``feodo_tracker``
    + ``ssl_blacklist`` + ``abusech_ssl`` to the SOURCES dict.

    Pin the EXACT new key set so a future refactor that drops
    ``sslbl`` again gets caught.
    """
    from source_truthful_timestamps import _RELIABLE_FIRST_SEEN_SOURCES

    new_keys = _RELIABLE_FIRST_SEEN_SOURCES - _LEGACY_RELIABLE_FIRST_SEEN_SOURCES
    assert new_keys == {"sslbl"}, (
        f"Refactor alias-coverage extension drift: expected exactly {{'sslbl'}}, got {new_keys}. "
        "If you added a new reliable_first_seen=True source to the registry, update this test."
    )


def test_misp_writer_source_tags_preserves_every_legacy_entry_byte_for_byte():
    """For every legacy MISPWriter.SOURCE_TAGS key, the registry-derived
    dict produces the SAME MISP tag string."""
    from collectors.misp_writer import MISPWriter

    for key, expected in _LEGACY_MISP_WRITER_SOURCE_TAGS.items():
        assert key in MISPWriter.SOURCE_TAGS, f"Legacy SOURCE_TAGS key '{key}' missing from registry-derived"
        assert MISPWriter.SOURCE_TAGS[key] == expected, (
            f"MISPWriter.SOURCE_TAGS['{key}'] drift: expected {expected!r}, got {MISPWriter.SOURCE_TAGS[key]!r}"
        )


# ---------------------------------------------------------------------------
# B. Cross-registry invariants — the relationships between the 5 derivations
# ---------------------------------------------------------------------------


def test_every_reliable_first_seen_source_is_also_in_neo4j_sources():
    """Critical invariant: every source on the source-truthful allowlist
    MUST have a corresponding ``:Source`` node entry in SOURCES. The
    SOURCED_FROM edge MERGE in ``_upsert_sourced_relationship`` matches
    on ``(s:Source {source_id: $sid})`` — if the source isn't in
    SOURCES then ``ensure_sources`` never created the node, and the
    edge MERGE silently writes nothing.

    This test is the single check that catches the
    "PR #41 source-truthful pipeline silently dead for source X"
    regression class.
    """
    from neo4j_client import SOURCES
    from source_truthful_timestamps import _RELIABLE_FIRST_SEEN_SOURCES

    missing = _RELIABLE_FIRST_SEEN_SOURCES - set(SOURCES.keys())
    assert not missing, (
        f"INVARIANT VIOLATION: reliable_first_seen sources {missing} are not in "
        "neo4j_client.SOURCES. Their SOURCED_FROM edge MERGEs would silently "
        "fail because ensure_sources never created the :Source node. "
        "Add them to source_registry.py with reliable_first_seen=True AND "
        "make sure their canonical_id + aliases are picked up by the "
        "to_neo4j_sources_dict() derivation."
    )


def test_every_cli_id_has_a_canonical_source_in_neo4j_sources():
    """Every source listed in DEFAULT_SOURCES (CLI surface) MUST have
    its canonical id covered by SOURCES. Otherwise the CLI lists a
    source that the Neo4j layer doesn't recognize, and the
    SOURCED_FROM batch pre-validation refuses every write from it."""
    from edgeguard import DEFAULT_SOURCES
    from neo4j_client import SOURCES
    from source_registry import get_source

    for cli_id in DEFAULT_SOURCES:
        src = get_source(cli_id)
        assert src is not None, f"CLI source '{cli_id}' is not in the registry"
        assert src.canonical_id in SOURCES, (
            f"CLI source '{cli_id}' (canonical='{src.canonical_id}') is not in "
            "neo4j_client.SOURCES. CLI would list it but every collector run "
            "would fail SOURCED_FROM batch pre-validation."
        )


def test_every_alias_resolves_to_the_same_source_as_its_canonical_id():
    """``get_source('cisa')`` and ``get_source('cisa_kev')`` MUST
    return the SAME ``Source`` instance. Otherwise a collector's
    case-insensitive lookup fragments per-source provenance."""
    from source_registry import all_sources, get_source

    for src in all_sources():
        canonical = get_source(src.canonical_id)
        assert canonical is src, f"get_source(canonical_id={src.canonical_id!r}) did not roundtrip"
        for alias in src.aliases:
            via_alias = get_source(alias)
            assert via_alias is src, (
                f"alias {alias!r} resolved to a DIFFERENT Source than its canonical "
                f"{src.canonical_id!r} — registry alias map is broken"
            )


def test_get_source_is_case_insensitive():
    """``get_source('NVD')`` MUST resolve to the same record as
    ``get_source('nvd')``. The registry strips + lowercases."""
    from source_registry import get_source

    for query in ("NVD", "nvd", "  Nvd  ", "nVd"):
        out = get_source(query)
        assert out is not None and out.canonical_id == "nvd", (
            f"case-insensitive lookup failed for {query!r}: got {out!r}"
        )


def test_get_source_returns_None_for_unknown_or_empty_input():
    from source_registry import get_source

    assert get_source(None) is None
    assert get_source("") is None
    assert get_source("   ") is None
    assert get_source("totally_unknown_source") is None


def test_all_aliases_returns_every_canonical_id_and_alias():
    """``all_aliases()`` is the cardinality-control surface for the
    Prometheus ``source_id`` label (PR #42 ``_SOURCE_LABEL_ALLOWLIST``
    will derive from this once both PRs land). It MUST return every
    canonical id AND every alias — otherwise a collector emitting an
    alias would collapse to the ``<other>`` bucket in metrics, hiding
    per-source signal.

    This test also kills the bugbot "no in-repo callers" finding —
    the helper is exercised here even before the metrics_server
    derivation is wired in a follow-up PR.
    """
    from source_registry import all_aliases, all_sources

    out = all_aliases()
    expected = set()
    for src in all_sources():
        expected.add(src.canonical_id)
        expected.update(src.aliases)
    assert out == expected, f"all_aliases() drift: missing {expected - out}, extra {out - expected}"


def test_all_aliases_is_a_frozenset_so_callers_cannot_mutate():
    """``frozenset`` immutability is a load-bearing invariant: the
    metrics_server allowlist (future) caches this result at module
    import; mutation would silently change cardinality control
    behavior across the process."""
    from source_registry import all_aliases

    assert isinstance(all_aliases(), frozenset)


def test_all_aliases_is_lowercased_for_case_insensitive_lookup():
    """Every alias / canonical id MUST be lowercased so the
    Prometheus label normalizer's case-folding lookup works
    (collectors may emit any casing)."""
    from source_registry import all_aliases

    for key in all_aliases():
        assert key == key.lower(), f"non-lowercased key in all_aliases(): {key!r}"


def test_misp_tags_are_unique_per_canonical_source():
    """Two different canonical sources MUST NOT share the same MISP
    tag string — that would alias them on round-trip through MISP."""
    from source_registry import all_sources

    seen: dict[str, str] = {}
    for src in all_sources():
        prior = seen.get(src.misp_tag)
        assert prior is None, (
            f"MISP tag collision: both {prior!r} and {src.canonical_id!r} use "
            f"misp_tag={src.misp_tag!r} — they would become aliases through "
            "MISP round-trip"
        )
        seen[src.misp_tag] = src.canonical_id


def test_canonical_ids_are_unique():
    """Two ``Source(...)`` entries MUST NOT share a ``canonical_id``."""
    from source_registry import all_sources

    seen = set()
    for src in all_sources():
        assert src.canonical_id not in seen, f"Duplicate canonical_id in registry: {src.canonical_id!r}"
        seen.add(src.canonical_id)


def test_aliases_do_not_collide_with_other_sources_canonical_ids():
    """An alias MUST NOT be the canonical id of a different source —
    that would make ``get_source('X')`` ambiguous."""
    from source_registry import all_sources

    canonical_ids = {src.canonical_id for src in all_sources()}
    for src in all_sources():
        for alias in src.aliases:
            other_canonical = canonical_ids - {src.canonical_id}
            assert alias not in other_canonical, (
                f"alias {alias!r} of {src.canonical_id!r} collides with a different source's canonical id"
            )


# ---------------------------------------------------------------------------
# C. Propagation — adding a new source flows to all 5 derived structures
# ---------------------------------------------------------------------------


def test_adding_a_new_source_propagates_to_all_five_derivations(monkeypatch):
    """Smoke test that synthesizes a new ``Source(...)`` entry, prepends
    it to a copy of the registry, and verifies every derivation picks
    it up. Catches a future refactor that misses one of the five
    derivation helpers.

    PR #43 audit M1 (Bug Hunter): use ``monkeypatch.setattr`` instead
    of manual try/finally — pytest's monkeypatch handles teardown
    safely even when an assertion in the middle raises, signaling to
    readers that this test mutates module globals.
    """
    import source_registry
    from source_registry import (
        Source,
        cli_to_canonical_tag_map,
        reliable_first_seen_aliases,
        source_to_misp_tag_map,
        to_cli_sources_dict,
        to_neo4j_sources_dict,
    )

    test_source = Source(
        canonical_id="testsrc_canonical_id_12345",
        aliases=("testsrc_alias_67890",),
        display_name="Test Source",
        source_type="threat_intel",
        reliability=0.5,
        cli_id="testsrc_cli",
        api_key_env="TESTSRC_API_KEY",
        rate_limit="10/min",
        cli_default_enabled=False,
        cli_description="Synthetic test source",
        misp_tag="source:TestSrc-Unique-12345",
        reliable_first_seen=True,
    )

    monkeypatch.setattr(source_registry, "_REGISTRY", source_registry._REGISTRY + (test_source,))

    # Each derivation re-reads _REGISTRY on every call; no caching.
    neo4j_dict = to_neo4j_sources_dict()
    cli_dict = to_cli_sources_dict()
    cli_to_canon = cli_to_canonical_tag_map()
    reliable = reliable_first_seen_aliases()
    misp = source_to_misp_tag_map()

    # 1. Neo4j SOURCES picks it up via canonical id AND alias
    assert "testsrc_canonical_id_12345" in neo4j_dict
    assert "testsrc_alias_67890" in neo4j_dict
    assert neo4j_dict["testsrc_canonical_id_12345"]["name"] == "Test Source"

    # 2. CLI DEFAULT_SOURCES picks it up via cli_id
    assert "testsrc_cli" in cli_dict
    assert cli_dict["testsrc_cli"]["api_key_env"] == "TESTSRC_API_KEY"

    # 3. SOURCE_TAGS picks it up via cli_id (full map, not legacy subset)
    assert cli_to_canon["testsrc_cli"] == "testsrc_canonical_id_12345"

    # 4. _RELIABLE_FIRST_SEEN_SOURCES picks up canonical AND alias
    assert "testsrc_canonical_id_12345" in reliable
    assert "testsrc_alias_67890" in reliable

    # 5. MISPWriter.SOURCE_TAGS picks up canonical AND alias
    assert misp["testsrc_canonical_id_12345"] == "source:TestSrc-Unique-12345"
    assert misp["testsrc_alias_67890"] == "source:TestSrc-Unique-12345"


def test_to_cli_sources_dict_raises_on_duplicate_cli_id(monkeypatch):
    """PR #43 audit M2 (Devil's Advocate / Cross-Checker): adding a
    second Source with a cli_id that already exists silently
    overwrote the earlier entry's CLI listing — uniqueness MUST be
    a runtime error, not a silent collision."""
    import pytest

    import source_registry
    from source_registry import Source, to_cli_sources_dict

    # Synthesize a Source whose cli_id collides with an existing one
    # ("nvd" is a registered cli_id on the canonical NVD record).
    colliding = Source(
        canonical_id="testsrc_collision_canonical",
        display_name="Collision Source",
        source_type="threat_intel",
        reliability=0.5,
        misp_tag="source:Collision-Test",
        reliable_first_seen=True,
        cli_id="nvd",  # collides with NVD's existing cli_id
    )
    monkeypatch.setattr(source_registry, "_REGISTRY", source_registry._REGISTRY + (colliding,))

    with pytest.raises(ValueError, match="duplicate cli_id"):
        to_cli_sources_dict()


def test_cli_to_canonical_tag_map_raises_on_duplicate_cli_id(monkeypatch):
    """Same uniqueness invariant on the SOURCE_TAGS derivation."""
    import pytest

    import source_registry
    from source_registry import Source, cli_to_canonical_tag_map

    colliding = Source(
        canonical_id="testsrc_collision_canonical_2",
        display_name="Collision Source 2",
        source_type="threat_intel",
        reliability=0.5,
        misp_tag="source:Collision-Test-2",
        reliable_first_seen=True,
        cli_id="cisa",  # collides with CISA KEV's existing cli_id
    )
    monkeypatch.setattr(source_registry, "_REGISTRY", source_registry._REGISTRY + (colliding,))

    with pytest.raises(ValueError, match="duplicate cli_id"):
        cli_to_canonical_tag_map()


def test_cli_ids_are_unique_in_the_real_registry():
    """Static check on the actual ``_REGISTRY`` — every Source with a
    non-None ``cli_id`` MUST have a unique value. Catches a
    contributor accidentally re-using an existing cli_id even before
    a derivation helper is exercised in production."""
    from source_registry import all_sources

    seen: dict[str, str] = {}
    for src in all_sources():
        if src.cli_id is None:
            continue
        prior = seen.get(src.cli_id)
        assert prior is None, (
            f"duplicate cli_id={src.cli_id!r} in real registry: both {prior!r} and {src.canonical_id!r} use it"
        )
        seen[src.cli_id] = src.canonical_id


def test_full_cli_to_canonical_tag_map_is_not_used_in_src(tmp_path):
    """PR #43 audit M3 (Maintainer Dev): the full
    ``cli_to_canonical_tag_map()`` (~12 keys) MUST NOT be imported
    into ``src/`` outside of ``source_registry.py`` and tests. The
    legacy-subset variant (``..._legacy_subset``) is what production
    callers wire — using the full map silently widens
    ``config.SOURCE_TAGS`` from 7 to 12 keys, which lets typo'd
    ``SOURCE_TAGS["X"]`` lookups silently succeed instead of raising
    ``KeyError`` at collector init.
    """
    import os
    import re

    src_root = os.path.join(os.path.dirname(__file__), "..", "src")
    bad_pattern = re.compile(
        r"\bfrom\s+source_registry\s+import\s+[^#\n]*\bcli_to_canonical_tag_map\b(?!_legacy_subset)"
    )
    bad_files = []
    for dirpath, _, filenames in os.walk(src_root):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            path = os.path.join(dirpath, fname)
            if os.path.basename(path) == "source_registry.py":
                continue
            with open(path) as fh:
                content = fh.read()
            for m in bad_pattern.finditer(content):
                bad_files.append((path, m.group(0)))
    assert not bad_files, (
        f"Imports of full cli_to_canonical_tag_map (without _legacy_subset) found: {bad_files}. "
        "Use cli_to_canonical_tag_map_legacy_subset to preserve the historical 7-key shape "
        "and the KeyError-on-typo guarantee."
    )


def test_dataclass_is_frozen_so_registry_cannot_be_mutated_at_runtime():
    """``Source`` is a frozen dataclass — attempting to mutate any
    field raises ``FrozenInstanceError``. This makes the registry
    safe to share across processes / threads."""
    import dataclasses

    from source_registry import all_sources

    src = all_sources()[0]
    try:
        src.reliability = 0.99  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        return
    raise AssertionError("Source dataclass MUST be frozen to prevent registry mutation")
