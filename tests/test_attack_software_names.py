"""ATT&CK software ids in malware family names (2026-10): ``src/attack_software_names.py``.

OTX names families as the MISP ATT&CK galaxy does (``"Cobalt Strike - S0154"``), and each such name
became a ``Malware`` node beside the one ATT&CK delivered (136 twins holding 16,005 ``INDICATES``
links on the graph of 2026-10-14). These tests pin the shared helper every site uses, the Java
patterns that carry the same rule into Cypher, the ATT&CK id read from the record MITRE delivered,
the map of folded names that steps 9b / 2d resolve through, and the plan that decides which twin
folds into which node (the MITRE node of its id or base name, else the node of its base name).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from attack_software_names import (  # noqa: E402
    CYPHER_BASE_NODES_READ,
    CYPHER_FOLDED_FAMILIES_READ,
    CYPHER_SOFTWARE_ID_SUFFIX,
    CYPHER_SUFFIXED_NAME,
    attack_software_id,
    cypher_family_name_variants,
    folded_family_names,
    plan_twin_folds,
    software_id_claims,
    split_attack_software_id,
    twin_base_names,
)

# Family names as OTX pulses list them (the MISP galaxy cluster names), and names that only look alike.
_SUFFIXED = {
    "Cobalt Strike - S0154": ("Cobalt Strike", "S0154"),
    "njRAT - S0385": ("njRAT", "S0385"),
    "Agent Tesla - S0331": ("Agent Tesla", "S0331"),
    "cobalt strike - s0154": ("cobalt strike", "S0154"),
    "  Emotet  -   S0367  ": ("Emotet", "S0367"),
    "Emotet\t-\tS0367": ("Emotet", "S0367"),
    "BlackEnergy 3 - Win32 - S0089": ("BlackEnergy 3 - Win32", "S0089"),
}
_NOT_SUFFIXED = [
    "Cobalt Strike",
    "Cobalt Strike-S0154",  # no whitespace around the hyphen: not the galaxy naming
    "Cobalt Strike - S015",  # three digits
    "Cobalt Strike - S01540",  # five digits
    "PowerShell - T1059.001",  # a technique cluster, not software
    "Lazarus Group - G0032",  # a group cluster
    "- S0154",  # no base name
    "S0154",
    "",
]


class TestSplit:
    @pytest.mark.parametrize("name, expected", sorted(_SUFFIXED.items()))
    def test_a_trailing_software_id_is_split_off(self, name, expected):
        assert split_attack_software_id(name) == expected

    @pytest.mark.parametrize("name", _NOT_SUFFIXED)
    def test_other_names_come_back_stripped_without_an_id(self, name):
        assert split_attack_software_id(name) == (name.strip(), None)

    @pytest.mark.parametrize("value", [None, 154, ["Cobalt Strike - S0154"], {"name": "x"}])
    def test_a_non_string_is_no_name(self, value):
        assert split_attack_software_id(value) == ("", None)

    def test_only_the_last_id_is_removed(self):
        assert split_attack_software_id("X - S0001 - S0002") == ("X - S0001", "S0002")


class TestCypherPatternsDecideAsTheHelper:
    """The Java patterns are run here with Python's ``re`` in ASCII mode: for the syntax they use
    (``(?i)``, ``(?s)``, ``\\s``, ``\\S``, ``[0-9]``, a look-behind, ``$``) both engines agree, and Java's
    ``\\s`` is the ASCII set. Cypher applies them to ``toLower(trim(name))``."""

    _CORPUS = sorted(_SUFFIXED) + _NOT_SUFFIXED + ["x - s0154", "A  -  b  - s1234", "a -\ns0154"]

    @pytest.mark.parametrize("name", _CORPUS)
    def test_replace_leaves_the_base_name(self, name):
        cypher_input = name.strip().lower()
        replaced = re.sub(CYPHER_SOFTWARE_ID_SUFFIX, "", cypher_input, flags=re.ASCII).strip()
        assert replaced == split_attack_software_id(name)[0].lower()

    @pytest.mark.parametrize("name", _CORPUS)
    def test_full_match_finds_exactly_the_suffixed_names(self, name):
        matched = re.fullmatch(CYPHER_SUFFIXED_NAME, name, flags=re.ASCII) is not None
        assert matched == (split_attack_software_id(name)[1] is not None)

    def test_the_patterns_hold_no_quote_characters(self):
        # They travel as parameters, but a quote would also break a statement they were pasted into.
        for pattern in (CYPHER_SOFTWARE_ID_SUFFIX, CYPHER_SUFFIXED_NAME):
            assert "'" not in pattern and '"' not in pattern


class TestFamilyNameVariants:
    """Steps 9b / 2d (2026-10): the name as given and without the id, each through ``$folded_families``."""

    def test_the_expression(self):
        assert cypher_family_name_variants("family") == (
            'apoc.coll.toSet([_fv IN [family, trim(apoc.text.replace(family, $software_id_suffix, ""))] '
            "| coalesce($folded_families[_fv], _fv)])"
        )

    def test_no_single_quote_for_apoc_periodic_iterate(self):
        # The step statements are wrapped in single quotes; the expression and the reads use none.
        for text in (cypher_family_name_variants("f"), CYPHER_FOLDED_FAMILIES_READ, CYPHER_BASE_NODES_READ):
            assert "'" not in text

    def test_the_reads_take_their_parameters(self):
        assert "m.merged_from AS merged_from" in CYPHER_FOLDED_FAMILIES_READ
        assert "$mitre_source IN coalesce(m.source, []) AS mitre" in CYPHER_FOLDED_FAMILIES_READ
        assert "b.name IN $bases AND NOT $mitre_source IN coalesce(b.source, [])" in CYPHER_BASE_NODES_READ
        assert "apoc." not in CYPHER_FOLDED_FAMILIES_READ + CYPHER_BASE_NODES_READ, "no APOC in the reads"


class TestFoldedFamilyNames:
    """``$folded_families``: the names the twin merge folded, to the node that holds them now."""

    def test_a_name_folded_by_id_resolves_to_the_attack_node(self):
        # "agenttesla" (named by the base since 2026-10) was folded into ATT&CK "agent tesla": a later
        # pulse naming "AgentTesla" is a MISP duplicate, and its indicators must still find a node.
        rows = [{"name": "agent tesla", "merged_from": ["agenttesla"], "mitre": True}]
        assert folded_family_names(rows) == {"agenttesla": "agent tesla"}

    def test_a_suffixed_entry_also_stands_for_its_base_name(self):
        rows = [{"name": "agent tesla", "merged_from": ["agenttesla - s0331"], "mitre": True}]
        assert folded_family_names(rows) == {"agenttesla": "agent tesla", "agenttesla - s0331": "agent tesla"}

    def test_a_base_name_that_is_the_node_itself_is_no_entry(self):
        rows = [
            {"name": "cobalt strike", "merged_from": ["cobalt strike - s0154"], "mitre": True},
            {"name": "mimikatz", "merged_from": ["mimikatz - s0002"], "mitre": False},  # base-name fold
        ]
        assert folded_family_names(rows) == {
            "cobalt strike - s0154": "cobalt strike",
            "mimikatz - s0002": "mimikatz",
        }

    def test_an_attack_node_name_is_never_redirected(self):
        rows = [
            {"name": "foo", "merged_from": None, "mitre": True},
            {"name": "bar", "merged_from": ["foo - s0001"], "mitre": True},
        ]
        assert folded_family_names(rows) == {"foo - s0001": "bar"}

    def test_a_name_that_leads_to_two_nodes_is_left_out(self):
        rows = [
            {"name": "a", "merged_from": ["x - s0001"], "mitre": True},
            {"name": "b", "merged_from": ["x - s0002"], "mitre": True},
        ]
        assert folded_family_names(rows) == {"x - s0001": "a", "x - s0002": "b"}

    def test_a_scalar_list_and_rows_without_a_name(self):
        rows = [
            {"name": "njrat", "merged_from": "njrat - s0385", "mitre": True},
            {"name": None, "merged_from": ["x"]},
            {"c": 0},
        ]
        assert folded_family_names(rows) == {"njrat - s0385": "njrat"}

    def test_names_are_canonical(self):
        rows = [{"name": "agent tesla", "merged_from": ["  AgentTesla  "], "mitre": True}]
        assert folded_family_names(rows) == {"agenttesla": "agent tesla"}


class TestTwinBaseNames:
    def test_the_base_names_of_the_rows_named_with_an_id(self):
        rows = [
            {"name": "mimikatz - s0002"},
            {"name": "Cobalt Strike - S0154"},
            {"name": "agenttesla", "aliases": ["AgentTesla - S0331"]},  # named by the base already
            {"name": None},
        ]
        assert twin_base_names(rows) == ["cobalt strike", "mimikatz"]


def _mitre_raw(name: str, description: str, **extra) -> str:
    """The ``raw_data`` of a MITRE ``Malware`` node's SOURCED_FROM edge: the sync item without its
    key property (``merge_node_with_source``), as JSON."""
    item = {
        "type": "malware",
        "aliases": [name],
        "deprecated": False,
        "malware_types": ["malware"],
        "family": name,
        "description": description,
        "curated": False,
        "zone": ["global"],
        "tag": "mitre_attck",
        "source": ["mitre_attck"],
        "confidence_score": 0.7,
        "misp_event_id": "12",
        "tlp": "white",
        "uses_techniques": ["T1059.001"],
        **extra,
    }
    return json.dumps(item)


_CS_DESCRIPTION = (
    "[Cobalt Strike](https://attack.mitre.org/software/S0154) is a commercial, full-featured, remote "
    "access tool. It is used by [APT29](https://attack.mitre.org/groups/G0016)."
)


class TestAttackSoftwareId:
    def test_the_self_link_of_the_delivered_description(self):
        assert attack_software_id(_mitre_raw("Cobalt Strike", _CS_DESCRIPTION), "cobalt strike") == "S0154"

    def test_the_link_with_the_node_name_wins_over_an_earlier_one(self):
        description = (
            "A loader of [Cobalt Strike](https://attack.mitre.org/software/S0154): "
            "[Bumblebee](https://attack.mitre.org/software/S1039/) is a custom loader."
        )
        assert attack_software_id(_mitre_raw("Bumblebee", description), "bumblebee") == "S1039"

    def test_without_a_name_an_opening_link_decides(self):
        assert attack_software_id(_mitre_raw("Cobalt Strike", _CS_DESCRIPTION)) == "S0154"

    def test_a_link_that_neither_names_the_node_nor_opens_the_text_is_not_its_id(self):
        description = "A loader of [Cobalt Strike](https://attack.mitre.org/software/S0154)."
        assert attack_software_id(_mitre_raw("Bumblebee", description), "bumblebee") is None

    def test_the_comment_prefix_of_an_unparsed_comment_does_not_hide_the_link(self):
        # A comment the sync could not parse is kept whole as the description.
        description = 'MITRE_USES_TECHNIQUES:{"t":["T1059"]\n' + _CS_DESCRIPTION
        assert attack_software_id(_mitre_raw("Cobalt Strike", description), "cobalt strike") == "S0154"

    @pytest.mark.parametrize(
        "raw",
        [None, "", "not json", "[1, 2]", json.dumps({"description": None}), json.dumps({"aliases": []}), 17],
    )
    def test_no_readable_record_is_no_id(self, raw):
        assert attack_software_id(raw, "cobalt strike") is None

    def test_a_group_link_is_not_a_software_id(self):
        raw = _mitre_raw("x", "[APT29](https://attack.mitre.org/groups/G0016) uses it.")
        assert attack_software_id(raw, "apt29") is None


class TestClaims:
    def test_the_name_states_its_id(self):
        assert software_id_claims("cobalt strike - s0154") == [("cobalt strike", "S0154")]

    def test_an_alias_of_the_own_name_states_an_id(self):
        # What the collectors write since 2026-10: the node by the base name, the original as alias.
        assert software_id_claims("agenttesla", ["AgentTesla - S0331", "agent tesla"]) == [("agenttesla", "S0331")]

    def test_an_alias_naming_another_family_states_nothing(self):
        assert software_id_claims("benign", ["Cobalt Strike - S0154"]) == []

    def test_a_scalar_alias_is_read_as_a_list(self):
        assert software_id_claims("njrat", "njRAT - S0385") == [("njrat", "S0385")]

    def test_a_plain_name_states_nothing(self):
        assert software_id_claims("emotet", None) == []


class TestPlan:
    ATTACK = {
        "cobalt strike": "S0154",
        "agent tesla": "S0331",
        "njrat": None,  # its record could not be read: matched by name
        "emotet": "S0367",
        "poisonivy": "S0012",
    }

    def _plan(self, *rows, attack=None, successors=None, base_nodes=None):
        return plan_twin_folds(list(rows), self.ATTACK if attack is None else attack, successors, base_nodes)

    def test_a_twin_folds_into_the_node_of_its_id(self):
        plan = self._plan({"name": "cobalt strike - s0154", "aliases": None})
        assert plan.pairs == [("cobalt strike", "cobalt strike - s0154")] and plan.candidates == 1

    def test_the_id_decides_when_the_names_differ(self):
        plan = self._plan({"name": "agenttesla", "aliases": ["AgentTesla - S0331"]})
        assert plan.pairs == [("agent tesla", "agenttesla")]

    def test_the_base_name_decides_when_the_id_is_unknown(self):
        plan = self._plan({"name": "njrat - s0385", "aliases": []})
        assert plan.pairs == [("njrat", "njrat - s0385")]

    def test_a_name_whose_id_contradicts_the_twin_is_no_target(self):
        plan = self._plan({"name": "emotet - s0001", "aliases": []})
        assert plan.pairs == [] and plan.no_target == ["emotet - s0001"]

    def test_a_twin_without_a_mitre_node_is_left_and_counted(self):
        # Mimikatz S0002 is an ATT&CK tool: a Tool node, never a Malware merge target.
        plan = self._plan({"name": "mimikatz - s0002", "aliases": []})
        assert plan.pairs == [] and plan.no_target == ["mimikatz - s0002"] and plan.candidates == 1

    def test_id_and_base_name_leading_to_two_nodes_is_ambiguous(self):
        plan = self._plan({"name": "njrat - s0154", "aliases": []})
        assert plan.pairs == [] and plan.ambiguous == [("njrat - s0154", ["cobalt strike", "njrat"])]

    def test_a_revoked_id_is_translated_to_its_successor(self):
        plan = self._plan({"name": "darkmoon - s0209", "aliases": []}, successors={"S0209": "S0012"})
        assert plan.pairs == [("poisonivy", "darkmoon - s0209")]
        assert self._plan({"name": "darkmoon - s0209", "aliases": []}).no_target == ["darkmoon - s0209"]

    def test_two_mitre_nodes_of_one_id_are_ambiguous(self):
        plan = self._plan({"name": "x - s0154", "aliases": []}, attack={"cobalt strike": "S0154", "cs": "S0154"})
        assert plan.ambiguous == [("x - s0154", ["cobalt strike", "cs"])]

    def test_rows_without_a_claim_and_repeated_rows_are_not_candidates(self):
        plan = self._plan(
            {"name": "emotet", "aliases": ["Emotet"]},
            {"name": "cobalt strike - s0154", "aliases": []},
            {"name": "cobalt strike - s0154", "aliases": []},
            {"name": None, "aliases": []},
            {"name": "cobalt strike", "aliases": ["Cobalt Strike - S0154"]},  # the MITRE node itself
        )
        assert plan.candidates == 1 and plan.pairs == [("cobalt strike", "cobalt strike - s0154")]

    def test_pairs_are_sorted(self):
        plan = self._plan(
            {"name": "njrat - s0385", "aliases": []},
            {"name": "cobalt strike - s0154", "aliases": []},
        )
        assert plan.pairs == [("cobalt strike", "cobalt strike - s0154"), ("njrat", "njrat - s0385")]


class TestPlanBaseNameTargets:
    """ATT&CK software without a MITRE ``Malware`` node (2026-10): since the collectors name a family by
    its base name, a later pulse creates "mimikatz" beside the twin "mimikatz - s0002", and steps 9b / 2d
    would link every indicator written before to both. The twin folds into the node of its base name."""

    ATTACK = TestPlan.ATTACK
    MIMIKATZ = {"name": "mimikatz - s0002", "aliases": []}

    def _plan(self, *rows, base_nodes=None, successors=None):
        return plan_twin_folds(list(rows), self.ATTACK, successors, base_nodes)

    def test_a_twin_without_a_mitre_target_folds_into_the_node_of_its_base_name(self):
        plan = self._plan(self.MIMIKATZ, base_nodes={"mimikatz": ["Mimikatz - S0002"]})
        assert plan.base_pairs == [("mimikatz", "mimikatz - s0002")]
        assert plan.pairs == [] and plan.no_target == []

    def test_a_node_of_the_base_name_that_states_no_id_takes_it(self):
        plan = self._plan(self.MIMIKATZ, base_nodes={"mimikatz": None})
        assert plan.base_pairs == [("mimikatz", "mimikatz - s0002")]

    def test_without_that_node_the_twin_is_no_target(self):
        plan = self._plan(self.MIMIKATZ, base_nodes={})
        assert plan.base_pairs == [] and plan.no_target == ["mimikatz - s0002"]

    def test_a_node_that_states_another_id_is_another_software(self):
        plan = self._plan(self.MIMIKATZ, base_nodes={"mimikatz": ["Mimikatz - S9999"]})
        assert plan.base_pairs == [] and plan.no_target == ["mimikatz - s0002"]

    def test_a_revoked_id_of_the_node_is_translated_first(self):
        plan = self._plan(self.MIMIKATZ, base_nodes={"mimikatz": ["Mimikatz - S9999"]}, successors={"S9999": "S0002"})
        assert plan.base_pairs == [("mimikatz", "mimikatz - s0002")]

    def test_twins_of_one_base_name_with_different_ids_fold_nowhere(self):
        plan = self._plan(
            {"name": "foo - s0001", "aliases": []}, {"name": "foo - s0002", "aliases": []}, base_nodes={"foo": []}
        )
        assert plan.base_pairs == [] and plan.no_target == ["foo - s0001", "foo - s0002"]

    def test_twins_of_one_base_name_and_one_id_both_fold(self):
        plan = self._plan(self.MIMIKATZ, {"name": "mimikatz  -  s0002", "aliases": []}, base_nodes={"mimikatz": []})
        assert plan.base_pairs == [("mimikatz", "mimikatz  -  s0002"), ("mimikatz", "mimikatz - s0002")]

    def test_a_mitre_target_wins_over_a_node_of_the_base_name(self):
        plan = self._plan({"name": "cobalt strike - s0154", "aliases": []}, base_nodes={"cobalt strike": []})
        assert plan.pairs == [("cobalt strike", "cobalt strike - s0154")] and plan.base_pairs == []

    def test_a_node_that_folds_into_a_mitre_node_takes_no_twin(self):
        # "agenttesla" folds into ATT&CK "agent tesla" (S0331); "agenttesla - s9999" names another id.
        plan = self._plan(
            {"name": "agenttesla", "aliases": ["AgentTesla - S0331"]},
            {"name": "agenttesla - s9999", "aliases": []},
            base_nodes={"agenttesla": ["AgentTesla - S0331"]},
        )
        assert plan.pairs == [("agent tesla", "agenttesla")]
        assert plan.base_pairs == [] and plan.no_target == ["agenttesla - s9999"]

    def test_a_twin_named_by_the_base_already_has_no_base_name_target(self):
        # An alias-only claim: the node is the base-named node itself.
        plan = self._plan({"name": "mimikatz", "aliases": ["Mimikatz - S0002"]}, base_nodes={"mimikatz": []})
        assert plan.base_pairs == [] and plan.no_target == ["mimikatz"]
