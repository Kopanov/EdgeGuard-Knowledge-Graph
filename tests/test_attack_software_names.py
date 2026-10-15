"""ATT&CK software ids in malware family names (2026-10): ``src/attack_software_names.py``.

OTX names families as the MISP ATT&CK galaxy does (``"Cobalt Strike - S0154"``), and each such name
became a ``Malware`` node beside the one ATT&CK delivered (136 twins holding 16,005 ``INDICATES``
links on the graph of 2026-10-14). These tests pin the shared helper every site uses, the Java
patterns that carry the same rule into Cypher, the ATT&CK id read from the record MITRE delivered,
and the plan that decides which twin folds into which MITRE node.
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
    CYPHER_SOFTWARE_ID_SUFFIX,
    CYPHER_SUFFIXED_NAME,
    attack_software_id,
    plan_twin_folds,
    software_id_claims,
    split_attack_software_id,
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

    def _plan(self, *rows, attack=None, successors=None):
        return plan_twin_folds(list(rows), self.ATTACK if attack is None else attack, successors)

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
