"""The source ranking of node descriptions (``src/description_ranking.py``, 2026-10-16).

Until 2026-10-16 NVD's record set a CVE's description and MITRE's record an entity's, and every other
record only filled an empty one: on a node without such a record the first source to arrive kept its
text, so the node depended on the order of the events in the sync. Now a record sets the description, and
``description_source``, when its source ranks at least as high as the stored text's: CVE NVD > CISA KEV >
CISA ICS > any other source; entity MITRE ATT&CK > a curated source > any other source; inside a group by
registry reliability, then id; an unregistered source below every registered one, by id. A description
without ``description_source`` (written before) counts as the top source's.

This module checks the ranking itself, the rule's Python mirror (``DescriptionRanking.replaces``) and that
the result does not depend on the order of arrival. ``apply_statement`` is the shared reader of a merge
statement's ranked SET for the path tests (``tests/test_cve_description_source.py``,
``tests/test_entity_description_source.py``); ``tests/test_description_ranking_neo4j.py`` checks on a real
database that the Cypher agrees with the mirror.
"""

from __future__ import annotations

import itertools
import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import description_ranking as dr  # noqa: E402
import source_registry  # noqa: E402

CVE, ENTITY = dr.CVE_DESCRIPTIONS, dr.ENTITY_DESCRIPTIONS
# The parameters ``Neo4jClient.merge_node_with_source`` binds the record's description to.
SINGLE_PARAMS = ("$ranked_description", "$ranked_description_source", "$ranked_description_rank")


def apply_statement(node: dict, query: str, params: dict, ranking: dr.DescriptionRanking, var: str = "n") -> None:
    """What a merge statement does to ``description`` / ``description_source`` of *node* (in place).

    The statement must carry the ranking's own SET (``set_cypher`` with the parameters of
    ``merge_node_with_source``) or no assignment of either property at all; any other form fails the
    test. The decision is the Python mirror ``replaces``, which the Neo4j module holds to the Cypher."""
    block = ranking.set_cypher(var, var, *SINGLE_PARAMS)
    rest = query.replace(block, "")
    assert not re.search(rf"\b{var}\.description(_source)? = ", rest), "description written outside the ranking"
    if block not in query:
        return
    assert query.count(block) == 1
    record = dr.RankedDescription(
        text=params["ranked_description"],
        source=params["ranked_description_source"],
        rank=params["ranked_description_rank"],
    )
    assert record.rank == ranking.rank(record.source), "the rank the statement carries is the source's"
    if ranking.replaces(node.get("description"), node.get("description_source"), record):
        node["description"], node["description_source"] = record.text, record.source


def after(ranking: dr.DescriptionRanking, records, stored: dict | None = None) -> dict:
    """The node after the ``(text, source)`` records in order, by the Python mirror."""
    node = dict(stored or {})
    for text, source in records:
        record = ranking.record(text, source)
        if record is not None and ranking.replaces(node.get("description"), node.get("description_source"), record):
            node["description"], node["description_source"] = record.text, record.source
    return node


# ================================================================ the ranking
class TestRanks:
    def test_cve_ranking_is_nvd_kev_ics_then_the_rest(self):
        order = sorted(CVE.ranks, key=CVE.ranks.get, reverse=True)
        assert order[:3] == ["nvd", "cisa_kev", "cisa_ics"]
        assert CVE.top_source == "nvd" and CVE.top_rank == len(source_registry.all_sources())

    def test_entity_ranking_is_mitre_then_curated_then_the_rest(self):
        order = sorted(ENTITY.ranks, key=ENTITY.ranks.get, reverse=True)
        curated = list(source_registry.curated_source_ids())
        assert curated, "the registry holds curated sources"
        assert order[0] == "mitre_attck" and ENTITY.top_source == "mitre_attck"
        assert sorted(order[1 : 1 + len(curated)]) == sorted(curated)

    @pytest.mark.parametrize("ranking", [CVE, ENTITY], ids=["cve", "entity"])
    def test_every_registered_source_has_its_own_rank_and_an_unknown_one_ranks_0(self, ranking):
        ids = {src.canonical_id for src in source_registry.all_sources()}
        assert set(ranking.ranks) == ids
        assert sorted(ranking.ranks.values()) == list(range(1, len(ids) + 1)), "distinct: no two sources tie"
        for unknown in ("stix_import", "resilmesh", "Some Vendor"):
            assert ranking.rank(unknown) == 0

    @pytest.mark.parametrize("ranking", [CVE, ENTITY], ids=["cve", "entity"])
    def test_inside_a_group_reliability_then_id(self, ranking):
        grouped = {sid for group in ranking.groups for sid in group}
        rest = [src for src in source_registry.all_sources() if src.canonical_id not in grouped]
        expected = [src.canonical_id for src in sorted(rest, key=lambda s: (-s.reliability, s.canonical_id))]
        assert sorted((s.canonical_id for s in rest), key=ranking.ranks.get, reverse=True) == expected
        # Core Ideas (0.85) ranks above MISP Galaxy (0.8) among the curated sources.
        assert ENTITY.rank("coreideas") > ENTITY.rank("misp_galaxy")

    def test_an_alias_ranks_as_its_source(self):
        assert ENTITY.rank("mitre") == ENTITY.rank("mitre_attck")
        assert CVE.rank("cisa") == CVE.rank("cisa_kev") and CVE.rank("CISA-ICS") == CVE.rank("cisa_ics")
        record = ENTITY.record("text", "mitre")
        assert record == dr.RankedDescription(text="text", source="mitre_attck", rank=ENTITY.top_rank)

    @pytest.mark.parametrize("text", [None, "", "   ", 42, ["x"]])
    def test_a_record_without_text_gives_none(self, text):
        assert CVE.record(text, "nvd") is None

    def test_a_record_without_a_source_gives_none(self):
        assert CVE.record("text", None) is None and CVE.record("text", "  ") is None

    def test_ranking_for_label(self):
        assert dr.ranking_for_label("CVE") is CVE and dr.ranking_for_label("Vulnerability") is CVE
        for label in ("Malware", "ThreatActor", "Tool", "Technique", "Tactic"):
            assert dr.ranking_for_label(label) is ENTITY
        assert dr.ranking_for_label("Indicator") is None and dr.ranking_for_label("Campaign") is None

    def test_a_group_naming_an_unregistered_source_is_refused(self):
        with pytest.raises(ValueError, match="unregistered"):
            dr.DescriptionRanking(name="x", labels=("X",), groups=(("not_a_source",),))


# ================================================================ the rule
class TestReplaces:
    @pytest.mark.parametrize("stored", [None, ""])
    def test_any_record_fills_an_empty_description(self, stored):
        for source in ("ssl_blacklist", "stix_import", "nvd"):
            assert CVE.replaces(stored, None, CVE.record("text", source))

    def test_a_higher_source_replaces_a_lower_one_and_never_the_reverse(self):
        assert CVE.replaces("ICS text", "cisa_ics", CVE.record("KEV text", "cisa_kev"))
        assert not CVE.replaces("KEV text", "cisa_kev", CVE.record("ICS text", "cisa_ics"))
        assert ENTITY.replaces("MISP text", "misp", ENTITY.record("Core Ideas text", "coreideas"))
        assert not ENTITY.replaces("ATT&CK text", "mitre_attck", ENTITY.record("Core Ideas text", "coreideas"))

    def test_the_same_source_revises_its_own_text(self):
        assert CVE.replaces("KEV text v1", "cisa_kev", CVE.record("KEV text v2", "cisa_kev"))
        assert CVE.replaces("partner v1", "resilmesh", CVE.record("partner v2", "resilmesh"))

    def test_a_registered_source_replaces_an_unregistered_one(self):
        assert ENTITY.replaces("bundle text", "stix_import", ENTITY.record("MISP text", "misp"))
        assert not ENTITY.replaces("MISP text", "misp", ENTITY.record("bundle text", "stix_import"))

    def test_two_unregistered_sources_by_id(self):
        # ``resilmesh`` sorts before ``stix_import``: it ranks higher.
        assert CVE.replaces("bundle text", "stix_import", CVE.record("partner text", "resilmesh"))
        assert not CVE.replaces("partner text", "resilmesh", CVE.record("bundle text", "stix_import"))

    @pytest.mark.parametrize(("ranking", "top"), [(CVE, "nvd"), (ENTITY, "mitre_attck")], ids=["cve", "entity"])
    def test_a_description_written_before_counts_as_the_top_sources(self, ranking, top):
        for source in ranking.ranks:
            if source != top:
                assert not ranking.replaces("legacy text", None, ranking.record("text", source)), source
        assert not ranking.replaces("legacy text", None, ranking.record("text", "stix_import"))
        assert ranking.replaces("legacy text", None, ranking.record("text", top))


class TestOrderOfArrival:
    """One text per source (what MISP holds, see the module docstring of ``description_ranking``): the
    node is the same in every order, and it is the highest-ranked source's text."""

    CVE_RECORDS = [
        ("NVD text", "nvd"),
        ("KEV text", "cisa_kev"),
        ("ICS text", "cisa_ics"),
        ("OTX block text", "alienvault_otx"),
        ("MISP-native text", "misp"),
        ("bundle text", "stix_import"),
        ("partner text", "resilmesh"),
    ]
    ENTITY_RECORDS = [
        ("ATT&CK text", "mitre_attck"),
        ("Core Ideas text", "coreideas"),
        ("Galaxy text", "misp_galaxy"),
        ("MISP-native text", "misp"),
        ("bundle text", "stix_import"),
    ]

    @pytest.mark.parametrize(
        ("ranking", "records"),
        [(CVE, CVE_RECORDS), (ENTITY, ENTITY_RECORDS)],
        ids=["cve", "entity"],
    )
    def test_every_order_of_every_subset_gives_the_highest_ranked_text(self, ranking, records):
        for size in range(1, len(records) + 1):
            for subset in itertools.combinations(records, size):
                # Registered sources never tie; two unregistered ones rank by id, the first id higher.
                best = min(subset, key=lambda r: (-ranking.rank(r[1]), r[1]))
                results = {tuple(after(ranking, order).items()) for order in itertools.permutations(subset)}
                assert results == {(("description", best[0]), ("description_source", best[1]))}, subset

    @pytest.mark.parametrize("stored", [{"description": "legacy text"}, {"description": ""}])
    def test_from_a_node_written_before_every_order_agrees(self, stored):
        subset = self.CVE_RECORDS[1:4]  # KEV, ICS, OTX: no NVD record
        results = {tuple(sorted(after(CVE, order, stored).items())) for order in itertools.permutations(subset)}
        assert len(results) == 1
        node = dict(next(iter(results)))
        if stored["description"]:
            assert node == {"description": "legacy text"}, "only NVD's record replaces it"
        else:
            assert node == {"description": "KEV text", "description_source": "cisa_kev"}


# ================================================================ the Cypher
class TestCypher:
    @pytest.mark.parametrize("ranking", [CVE, ENTITY], ids=["cve", "entity"])
    def test_the_stored_rank_names_every_registered_source(self, ranking):
        expr = ranking.stored_rank_cypher("n")
        assert expr.startswith("CASE WHEN n.description IS NULL OR n.description = '' THEN -1 ")
        assert f"WHEN n.description_source IS NULL THEN {ranking.top_rank} " in expr
        for sid, rank in ranking.ranks.items():
            assert f"WHEN '{sid}' THEN {rank} " in expr
        assert expr.endswith("ELSE 0 END END")

    def test_the_set_decides_once_then_sets_both_properties(self):
        block = CVE.set_cypher("n", "n, item", "item.description", "item.description_source", "item.description_rank")
        first, second, third = block.split("\n")
        assert first.startswith("WITH n, item, (item.description IS NOT NULL AND item.description <> '' AND ")
        assert first.endswith(" AS description_replaces")
        assert (
            second == "SET n.description = CASE WHEN description_replaces THEN item.description ELSE n.description END,"
        )
        assert third.strip() == (
            "n.description_source = CASE WHEN description_replaces THEN item.description_source "
            "ELSE n.description_source END"
        )

    def test_the_merge_choice_reads_each_node_once(self):
        expr = ENTITY.best_of_cypher("c", "dups")
        assert expr.startswith("reduce(_db = [c, CASE WHEN c.description IS NULL")
        assert "_dx IN [_dn IN dups | [_dn, CASE WHEN _dn.description IS NULL" in expr
        assert expr.endswith(")[0]")

    def test_a_source_id_that_cannot_be_inlined_is_refused(self, monkeypatch):
        bad = source_registry.Source(
            canonical_id="it's", display_name="x", source_type="threat_intel", reliability=0.1, misp_tag="x",
            reliable_first_seen=False,
        )  # fmt: skip
        monkeypatch.setattr(dr, "all_sources", lambda: source_registry.all_sources() + (bad,))
        with pytest.raises(ValueError, match="cannot be inlined"):
            dr.DescriptionRanking(name="x", labels=("X",), groups=(("nvd",),))


class TestBestOf:
    """The node whose description an alias or twin merge keeps (``best_of``; ``best_of_cypher`` on Neo4j)."""

    def test_the_highest_ranked_text_in_any_order_and_the_canonical_on_a_tie(self):
        canonical = {"name": "clop", "description": "MISP text", "description_source": "misp"}
        dups = [
            {"name": "cl0p", "description": "Core Ideas text", "description_source": "coreideas"},
            {"name": "clop ransomware group", "description": "bundle text", "description_source": "stix_import"},
            {"name": "clop gang"},
        ]
        for order in itertools.permutations(dups):
            assert ENTITY.best_of(canonical, list(order))["name"] == "cl0p"
        tie = {"name": "clop team", "description": "other MISP text", "description_source": "misp"}
        assert ENTITY.best_of(canonical, [tie]) is canonical

    def test_a_canonical_written_before_keeps_its_pair(self):
        # ``discard`` used to keep the canonical's text and take the duplicate's description_source.
        canonical = {"name": "apt28", "description": "legacy text"}
        dup = {"name": "fancy bear", "description": "MISP text", "description_source": "misp"}
        assert ENTITY.best_of(canonical, [dup]) is canonical

    def test_among_duplicates_of_one_source_the_first_name(self):
        canonical = {"name": "a"}
        dups = [
            {"name": "c", "description": "text c", "description_source": "misp"},
            {"name": "b", "description": "text b", "description_source": "misp"},
        ]
        for order in itertools.permutations(dups):
            assert ENTITY.best_of(canonical, list(order))["name"] == "b"
