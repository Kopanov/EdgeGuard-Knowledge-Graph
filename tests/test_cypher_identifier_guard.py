"""Names inlined into Cypher end at the end of the string (2026-11).

``neo4j_client._PROP_NAME_RE`` guards every relationship type, property and variable name that EdgeGuard writes
into a Cypher statement: ``_validate_rel_type``, ``_validate_prop_name``, ``_zone_override_global_clause``,
``_sourced_zone_items``, ``_unstated_sector_link_items``, ``_dedup_concat_clause``, and the names of a CVSS
payload, which come from the ``NVD_META`` comment of a MISP attribute (``_prepare_cve_write`` for the batched CVE
write, ``run_misp_to_neo4j._meta_cvss_payload`` when the sync reads the attribute). It was anchored with ``$``,
which also matches before a final newline, so ``baseScore\\n`` passed: the single CVE write then referenced
``$baseScore`` while the parameter map held ``baseScore\\n`` (a missing-parameter error on every sync), and the
batch read ``row.cvss.baseScore`` (null, so the entry was silently ignored). The pattern now ends with ``\\Z``.
``description_ranking._SOURCE_ID_RE`` (source ids inlined as string literals) likewise.

The CVSS payload cases are in ``tests/test_cve_batch_writes.py`` (``_prepare_cve_write``) and
``tests/test_cve_nvd_precedence.py`` (``_meta_cvss_payload``, on a real hosted ``NVD_META``).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import description_ranking  # noqa: E402
import neo4j_client as nc  # noqa: E402

GUARDS = {
    "_validate_rel_type": lambda name: nc._validate_rel_type(name),
    "_validate_prop_name": lambda name: nc._validate_prop_name(name),
    "_zone_override_global_clause node_var": lambda name: nc._zone_override_global_clause(name, "$zone"),
    "_zone_override_global_clause prop": lambda name: nc._zone_override_global_clause("n", "$zone", prop=name),
    "_sourced_zone_items": lambda name: nc._sourced_zone_items(name, "$zones", "$stated", "$refs"),
    "_unstated_sector_link_items": lambda name: nc._unstated_sector_link_items(name),
    "_dedup_concat_clause var": lambda name: nc._dedup_concat_clause(f"{name}.source", "$source"),
    "_dedup_concat_clause name": lambda name: nc._dedup_concat_clause(f"n.{name}", "$source"),
}


@pytest.mark.parametrize("guard", sorted(GUARDS))
def test_a_name_with_a_trailing_newline_is_refused(guard):
    with pytest.raises(ValueError):
        GUARDS[guard]("baseScore\n")


@pytest.mark.parametrize("guard", sorted(GUARDS))
@pytest.mark.parametrize("name", ["r", "zone", "baseScore", "_x1", "HAS_CVSS_v31"])
def test_an_identifier_passes(guard, name):
    assert GUARDS[guard](name)


@pytest.mark.parametrize("name", ["baseScore\n", "baseScore\n\n", "base Score", "x\r", "1x", ""])
def test_the_pattern_matches_whole_identifiers_only(name):
    assert nc._PROP_NAME_RE.match(name) is None


def test_a_source_id_with_a_trailing_newline_cannot_be_inlined(monkeypatch):
    """A registered source id is inlined into the description ranking's Cypher as a string literal."""
    real = [src for src in description_ranking.all_sources() if src.ranked_for_descriptions]
    odd = SimpleNamespace(canonical_id="nvd_mirror\n", ranked_for_descriptions=True, reliability=0.5)
    monkeypatch.setattr(description_ranking, "all_sources", lambda: (*real, odd))
    with pytest.raises(ValueError, match="cannot be inlined"):
        description_ranking.DescriptionRanking("test", ("CVE",), (("nvd",),))
    monkeypatch.setattr(description_ranking, "all_sources", lambda: tuple(real))
    assert description_ranking.DescriptionRanking("test", ("CVE",), (("nvd",),)).top_source == "nvd"
