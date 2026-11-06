"""Tests for ``src/actor_name_hygiene.py`` — pure threat-actor name hygiene.

Covers the public helpers (``split_composite_actor_name``,
``is_generic_actor_name``, ``clean_actor_names``, ``dropped_geopolitical_names``) against the junk observed
in the deployed graph (composite OTX adversary strings, generic descriptions)
plus a regression table of real-looking names that must pass through
unchanged — the module's design rule is "prefer not splitting / not
flagging over doing so wrongly".
"""

from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-actor-hygiene")
os.environ.setdefault("MISP_API_KEY", "test-key-actor-hygiene")

from actor_name_hygiene import (  # noqa: E402
    AND_SPLIT_MIN_SIDE_LEN,
    GENERIC_LAST_WORDS,
    clean_actor_names,
    dropped_geopolitical_names,
    is_generic_actor_name,
    split_composite_actor_name,
)

# ===========================================================================
# split_composite_actor_name
# ===========================================================================


class TestSplitCompositeActorName:
    @pytest.mark.parametrize(
        "composite, expected",
        [
            # The three shapes seen in the deployed graph.
            ("apt-c-13, sandworm, frozenbarents", ["apt-c-13", "sandworm", "frozenbarents"]),
            ("head mare and twelve", ["head mare", "twelve"]),
            (
                "lockbit, cl0p, refined kitten, wicked panda, fancy bear",
                ["lockbit", "cl0p", "refined kitten", "wicked panda", "fancy bear"],
            ),
            # Semicolon / slash-with-spaces / ampersand separators.
            ("apt28; apt29", ["apt28", "apt29"]),
            ("apt28 / fancy bear", ["apt28", "fancy bear"]),
            ("sandworm & apt28", ["sandworm", "apt28"]),
            ("Sandworm AND APT28", ["Sandworm", "APT28"]),
            # Three-way "and".
            ("apt28 and apt29 and apt30", ["apt28", "apt29", "apt30"]),
            # Oxford comma residue.
            ("lockbit, cl0p, and fancy bear", ["lockbit", "cl0p", "fancy bear"]),
            ("apt28 and, apt29", ["apt28", "apt29"]),
            # Mixed separators.
            ("apt28, apt29 and apt30; apt31", ["apt28", "apt29", "apt30", "apt31"]),
            # "&&" joins two names like "&" (2026-11-05: an OTX adversary field of the 3 Nov baseline).
            ("BlackHatSect0r && DXQRTXX", ["BlackHatSect0r", "DXQRTXX"]),
            ("apt28 && apt29 and apt30", ["apt28", "apt29", "apt30"]),
            ("lockbit, && cl0p", ["lockbit", "cl0p"]),
        ],
    )
    def test_splits_composites(self, composite, expected):
        assert split_composite_actor_name(composite) == expected

    def test_plain_name_returned_trimmed(self):
        assert split_composite_actor_name("  Mustang Panda  ") == ["Mustang Panda"]

    def test_plain_generic_name_is_not_judged_by_split(self):
        """``split`` only drops generic FRAGMENTS of a composite; a plain
        name passes through so callers can distinguish the two. ``clean``
        is the function that rejects a standalone generic name."""
        assert split_composite_actor_name("russian hackers") == ["russian hackers"]
        assert clean_actor_names("russian hackers") == []

    def test_generic_fragments_dropped_when_split(self):
        assert split_composite_actor_name("lockbit, cl0p, and others") == ["lockbit", "cl0p"]
        assert split_composite_actor_name("apt28 and russian hackers") == ["apt28"]
        assert split_composite_actor_name("apt28, unknown") == ["apt28"]

    def test_all_fragments_generic_yields_empty(self):
        assert split_composite_actor_name("russian hackers, chinese apt") == []

    @pytest.mark.parametrize(
        "name",
        [
            "Black & White",  # both sides protected idiom halves
            "search and destroy",
            "operation search and destroy",  # protected prefix
            "Operation Hack and Leak",
            # 2026-11-05: the threat-actor galaxy's actor "Stealth Mango and Tangelo" is one name.
            "Stealth Mango and Tangelo",
            "Stealth Mango & Tangelo",
            "Stealth Mango && Tangelo",  # the separator this change added
            "stealth mango and tangelo group",
            "stealth mango && tangelo team",
            "a and b",  # sides shorter than AND_SPLIT_MIN_SIDE_LEN
            "ab & cd",
            "ab && cd",
            "apt28&&apt29",  # no whitespace around the ampersands
            "at&t",  # no whitespace around the ampersand
            "C&C",
            "apt28/fancy bear",  # bare slash is NOT a separator
            "sandworm team",
            "cut and paste",
        ],
    )
    def test_does_not_split_when_unsure(self, name):
        assert split_composite_actor_name(name) == [name.strip()]

    def test_min_side_len_constant_is_honoured(self):
        short = "x" * (AND_SPLIT_MIN_SIDE_LEN - 1)
        ok = "y" * AND_SPLIT_MIN_SIDE_LEN
        assert split_composite_actor_name(f"{short} and {ok}") == [f"{short} and {ok}"]
        assert split_composite_actor_name(f"{ok} and {ok}z") == [ok, f"{ok}z"]

    def test_drops_empty_and_single_char_fragments(self):
        assert split_composite_actor_name("apt28, , x, apt29") == ["apt28", "apt29"]
        assert split_composite_actor_name(",,;") == []
        assert split_composite_actor_name("x") == []
        assert split_composite_actor_name("") == []
        assert split_composite_actor_name("   ") == []
        assert split_composite_actor_name("and") == []
        assert split_composite_actor_name("&&") == []

    def test_a_protected_name_in_a_list_is_one_of_its_names(self):
        # 2026-11-05: the comma split still applies; only the and-split of the name itself is refused.
        assert split_composite_actor_name("APT36, Stealth Mango and Tangelo") == ["APT36", "Stealth Mango and Tangelo"]
        assert clean_actor_names("Stealth Mango and Tangelo; Transparent Tribe") == [
            "Stealth Mango and Tangelo",
            "Transparent Tribe",
        ]

    def test_dedup_case_insensitive_preserves_first_spelling_and_order(self):
        assert split_composite_actor_name("APT28, apt28, Apt29, APT28") == ["APT28", "Apt29"]

    def test_non_string_input(self):
        assert split_composite_actor_name(None) == []  # type: ignore[arg-type]
        assert split_composite_actor_name(42) == []  # type: ignore[arg-type]

    # -- Unicode / whitespace edge cases ------------------------------------

    def test_nbsp_and_tabs_collapse_to_single_space(self):
        assert split_composite_actor_name("apt28 and apt29") == ["apt28", "apt29"]
        assert split_composite_actor_name("mustang\t\tpanda") == ["mustang panda"]
        assert split_composite_actor_name(" apt28 , apt29 ") == ["apt28", "apt29"]

    def test_fullwidth_and_ideographic_separators(self):
        assert split_composite_actor_name("apt28，apt29；apt30、apt31") == [
            "apt28",
            "apt29",
            "apt30",
            "apt31",
        ]

    def test_nfc_normalisation(self):
        nfd = "Café Bear"  # e + combining acute
        assert split_composite_actor_name(nfd) == ["Café Bear"]

    def test_case_is_preserved(self):
        assert split_composite_actor_name("Mustang Panda, RedDelta") == ["Mustang Panda", "RedDelta"]


# ===========================================================================
# Parentheses and legal forms (2026-11-06)
# ===========================================================================


class TestParenthesesAndLegalForms:
    """A list separator inside parentheses or before a company's legal form never splits. The comma
    split made the ThreatActor nodes ``black owl (bo team`` and ``ltd.`` on the test instance's sync
    of 2026-11-06, and ``videostrong technology co.`` on the graph of 2026-11-03."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # The five adversary strings of the defect report: one name each.
            ("Black Owl (BO Team, Hackers of the Black Owl)", ["Black Owl"]),
            ("Black Owl (BO Team; Hackers)", ["Black Owl"]),
            ("Sichuan Silence Information Technology Co., Ltd.", ["Sichuan Silence Information Technology Co., Ltd."]),
            ("Integrity Technology Group, Inc.", ["Integrity Technology Group, Inc."]),
            ("i-Soon (Anxun Information Technology Co., Ltd.)", ["i-Soon"]),
            # The adversary fields of the two OTX reports, as OTX gives them: one is cut off.
            ("Black Owl (BO Team", ["Black Owl"]),
            ("Videostrong Technology Co., Ltd.", ["Videostrong Technology Co., Ltd."]),
            # Every list separator inside a parenthetical, ASCII and full-width.
            ("Black Owl (BO Team / Hackers)", ["Black Owl"]),
            ("Black Owl (BO Team，Hackers；Owls、Birds)", ["Black Owl"]),
            ("APT37 (Korea, North)", ["APT37"]),
            # A list of names with parentheticals still splits outside them.
            ("APT28 (Fancy Bear, Sofacy), APT29 (Cozy Bear; The Dukes)", ["APT28", "APT29"]),
            ("APT28 (Fancy Bear, Sofacy) and APT29", ["APT28", "APT29"]),
            ("APT28 and APT29 (Cozy Bear, The Dukes)", ["APT28", "APT29"]),
            # A company beside an actor: the legal form stays with the company.
            ("Flax Typhoon, Integrity Technology Group, Inc.", ["Flax Typhoon", "Integrity Technology Group, Inc."]),
            (
                "Sichuan Silence Information Technology Co., Ltd., APT41",
                ["Sichuan Silence Information Technology Co., Ltd.", "APT41"],
            ),
            ("Integrity Technology Group, Inc. (Flax Typhoon)", ["Integrity Technology Group, Inc."]),
            ("Integrity Technology Group, Inc. and APT41", ["Integrity Technology Group, Inc.", "APT41"]),
            ("Sichuan Silence Information Technology Co.,Ltd.", ["Sichuan Silence Information Technology Co.,Ltd."]),
            ("Example Holdings, LLC", ["Example Holdings, LLC"]),
            ("Example Holdings, LLC.", ["Example Holdings, LLC."]),
            ("Example Systems, GmbH.", ["Example Systems, GmbH."]),
            ("Example Systems, GmbH", ["Example Systems, GmbH"]),
            ("Example Systems, S.A.", ["Example Systems, S.A."]),
            ("Example Systems, Corp.", ["Example Systems, Corp."]),
            ("Example Systems Pte., Ltd.", ["Example Systems Pte., Ltd."]),
            # The and-split leaves a legal form with its name.
            ("Example & Co.", ["Example & Co."]),
            ("Example GmbH & Co. KG", ["Example GmbH & Co. KG"]),
            # A legal form on its own is no name.
            ("Ltd.", []),
            ("Co., Ltd.", []),
            ("LLC", []),
            ("Inc.", []),
            # A word stored without a final dot also counts with one.
            ("LLC.", []),
            ("GmbH.", []),
            ("PLC.", []),
            ("JSC.", []),
            ("Ltd., APT41", ["APT41"]),
            # The bare "INC" is INC Ransom in the canonical reference: a name, also in a list.
            ("INC", ["INC"]),
            ("LockBit, INC", ["LockBit", "INC"]),
            ("LockBit, INC Ransom", ["LockBit", "INC Ransom"]),
            # A real name that ends with a legal-form word is untouched.
            ("Trickbot LLC", ["Trickbot LLC"]),
            ("Evil Corp", ["Evil Corp"]),
            # Unbalanced parentheses: an unclosed one cuts the fragment, a stray closing one is removed.
            ("Black Owl (BO Team, Hackers", ["Black Owl"]),
            ("APT28 (Fancy Bear) (Sofacy", ["APT28"]),
            ("Hackers of the Black Owl)", ["Hackers of the Black Owl"]),
            ("APT28), Fancy Bear", ["APT28", "Fancy Bear"]),
            ("(BO Team", []),
            ("NoName057(16", ["NoName057"]),
            ("NoName057(16)", ["NoName057(16)"]),  # no whitespace before "(": one group's real name
            # Full-width parentheses: the and-split never cuts inside them either, and with whitespace
            # before them the parenthetical is dropped like an ASCII one.
            ("APT37（Reaper and Group123）", ["APT37（Reaper and Group123）"]),
            ("APT37（Reaper & Group123, ScarCruft）", ["APT37（Reaper & Group123, ScarCruft）"]),
            ("APT37 （Reaper，Group123）", ["APT37"]),
            ("North Korea （APT37）", ["APT37"]),
            # A legal form written without a space after its dot.
            ("Co.Ltd.", []),
            ("Example Technology, Co.Ltd.", ["Example Technology, Co.Ltd."]),
            ("Example Technology Co.Ltd., APT41", ["Example Technology Co.Ltd.", "APT41"]),
        ],
    )
    def test_clean_actor_names(self, raw, expected):
        assert clean_actor_names(raw) == expected

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # A parenthetical a country or agency stands before is the name, and it can be a list.
            ("North Korea (APT37, Reaper)", ["APT37", "Reaper"]),
            ("DPRK (Kimsuky; APT43)", ["Kimsuky", "APT43"]),
            ("APT28, North Korea (APT37, Reaper)", ["APT28", "APT37", "Reaper"]),
            ("North Korea (Integrity Technology Group, Inc.)", ["Integrity Technology Group, Inc."]),
        ],
    )
    def test_a_parenthetical_list_behind_a_country_gives_its_names(self, raw, expected):
        assert clean_actor_names(raw) == expected
        assert dropped_geopolitical_names(raw) == []

    def test_a_parenthetical_list_of_descriptions_behind_a_country_leaves_the_country(self):
        assert clean_actor_names("North Korea (unknown, various)") == []
        assert dropped_geopolitical_names("North Korea (unknown, various)") == ["North Korea"]

    def test_a_full_width_parenthetical_without_whitespace_before_it_is_kept_whole(self):
        # Like "NoName057(16)": the threat-actor galaxy's record "APT37（Reaper）" is a name of the reference as
        # it is. A separator inside still never splits.
        assert clean_actor_names("APT37（Reaper）") == ["APT37（Reaper）"]
        assert clean_actor_names("APT37（Reaper，Group123）") == ["APT37（Reaper，Group123）"]

    def test_an_agency_with_a_full_width_parenthetical_is_dropped(self):
        # The and-split had made the name "security" of it.
        raw = "mois （ministry of intelligence and security）"
        assert clean_actor_names(raw) == []
        assert dropped_geopolitical_names(raw) == ["mois"]

    @pytest.mark.parametrize(
        "name",
        [
            "Ltd.",
            "ltd",
            "Co., Ltd.",
            "Co.Ltd.",
            "LLC",
            "LLC.",
            "l.l.c.",
            "Inc.",
            "GmbH",
            "GmbH.",
            "S.A.",
            "PLC",
            "PLC.",
            "JSC.",
            "Pty Ltd",
        ],
    )
    def test_a_legal_form_on_its_own_is_generic(self, name):
        assert is_generic_actor_name(name) is True

    @pytest.mark.parametrize(
        "name",
        [
            "INC",
            "inc",
            "Integrity Technology Group, Inc.",
            "Sichuan Silence Information Technology Co., Ltd.",
            "Trickbot LLC",
            "Evil Corp",
            "Ltda",  # "ltd" followed by a letter is no legal-form word
        ],
    )
    def test_a_name_with_a_legal_form_word_is_not_generic(self, name):
        assert is_generic_actor_name(name) is False

    def test_the_legal_form_list_is_lower_case_and_leaves_out_the_bare_inc(self):
        from actor_name_hygiene import LEGAL_FORM_WORDS

        for word in LEGAL_FORM_WORDS:
            assert word == word.lower().strip() and " " not in word and "," not in word, word
        assert {"co.", "ltd.", "inc.", "llc", "gmbh", "s.a.", "corp."} <= LEGAL_FORM_WORDS
        # "inc" is INC Ransom (canonical reference); two undotted letters are as likely a name.
        assert not {"inc", "co", "corp", "ag", "sa", "bv", "nv", "ab", "oy", "as"} & LEGAL_FORM_WORDS

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # A legal form joins only a part that holds a name and does not end with a conjunction.
            ("); Ltd.", []),
            ("APT28 and; Ltd.", ["APT28"]),
            ("APT28, and, Ltd.", ["APT28"]),
            ("APT28 and aka, Ltd.", ["APT28"]),
            ("Example, Ltd. and, Inc.", ["Example, Ltd."]),
            # A doubled conjunction leaves none behind (the names were "APT28 and" and "and APT29").
            ("APT28 and and", ["APT28"]),
            ("APT28 and and APT29", ["APT28", "APT29"]),
            ("and and APT29", ["APT29"]),
            # A dangling alias marker at the end, as at the start.
            ("APT28 aka, APT29", ["APT28", "APT29"]),
            ("Fancy Bear a.k.a.", ["Fancy Bear"]),
        ],
    )
    def test_no_fragment_keeps_a_separator_or_a_dangling_conjunction(self, raw, expected):
        assert clean_actor_names(raw) == expected

    def test_a_long_list_is_cleaned_in_linear_time(self):
        # 2026-11-06: joining legal forms re-read the growing name, the state-agency rule tried every split
        # of a long name, and the conjunctions were stripped one pass each; 8,000 parts took seconds. A
        # loose bound, far above the time it takes.
        import time

        start = time.perf_counter()
        assert clean_actor_names("Example" + ", Ltd." * 8000) == ["Example" + ", Ltd." * 8000]
        assert clean_actor_names("Example" + " Ltd." * 8000) == ["Example" + " Ltd." * 8000]
        assert clean_actor_names("APT28" + " and" * 8000) == ["APT28"]
        assert clean_actor_names("and " * 8000 + "APT28") == ["APT28"]
        assert time.perf_counter() - start < 2.0


def _parentheses_balance(name: str) -> bool:
    depth = 0
    for ch in name:
        if ch in "(（":
            depth += 1
        elif ch in ")）":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


# Written apart from the module's LEGAL_FORM_WORDS, so the check does not read the rule it checks.
_LEGAL_FORM_RE_WORD = r"(?:co\.|ltd\.?|inc\.|corp\.|llc\.?|gmbh\.?|plc\.?|jsc\.?|s\.a\.|limited\.?)"
_ONLY_A_LEGAL_FORM_RE = re.compile(rf"{_LEGAL_FORM_RE_WORD}(?:(?:[\s,]+|(?<=\.)){_LEGAL_FORM_RE_WORD})*")


def _assert_clean_names(raw: str) -> None:
    """Every name ``clean_actor_names`` returns for ``raw`` has balanced parentheses, is more than a legal
    form and a character, and comes out of ``clean_actor_names`` as it is: the MISP→Neo4j sync skips a
    threat-actor attribute whose name the hygiene would change, so a name the collector writes must be
    kept by the sync."""
    for name in clean_actor_names(raw):
        assert _parentheses_balance(name), (raw, name)
        assert not _ONLY_A_LEGAL_FORM_RE.fullmatch(name.lower()), (raw, name)
        assert len(name) > 1, (raw, name)
        assert clean_actor_names(name) == [name], (raw, name)


_FUZZ_TOKENS = (
    "Kimsuky",
    "Lazarus Group",
    "(",
    ")",
    "（",
    "）",
    ", ",
    "; ",
    " / ",
    " and ",
    " & ",
    "Inc.",
    "INC",
    "Co., Ltd.",
    "Co.Ltd.",
    "LLC.",
    " （",
    " aka ",
    "aka",
    "North Korea",
    "unknown",
)


def test_every_combination_of_names_separators_parentheses_and_legal_forms_gives_clean_names():
    """All 9,723 strings of up to three of the tokens (2026-11-06: on the code before, 4-token strings of a
    similar set gave 22,445 names with unbalanced parentheses and 374 that the hygiene changed again)."""
    import itertools

    count = 0
    for size in (1, 2, 3):
        for combo in itertools.product(_FUZZ_TOKENS, repeat=size):
            _assert_clean_names("".join(combo))
            count += 1
    assert count == 21 + 21**2 + 21**3


# ===========================================================================
# is_generic_actor_name
# ===========================================================================


class TestIsGenericActorName:
    @pytest.mark.parametrize(
        "name",
        [
            # The three shapes seen in the deployed graph.
            "multiple russian state-backed groups",
            "russian cybercrime groups",
            "russia-nexus apt",
            # Spec examples.
            "russian hackers",
            "ransomware groups",
            "state-backed groups",
            "apt groups",
            # Leading quantifier / unknown-ness words.
            "various hacktivists",
            "unknown actor",
            "unknown apt",
            "unnamed group",
            "several apt groups",
            # Last-word role nouns.
            "iranian hackers",
            "lockbit affiliates",
            "pro-russian hacktivists",
            "north korean actors",
            "ransomware operators",
            # Sponsorship / origin qualifiers.
            "china-based actor",
            "china nexus actor",
            # A language qualifier (2026-11-05: OTX adversary fields of the 3 Nov baseline).
            "chinese-speaking group",
            "Chinese-Speaking Threat Group",
            "russian-speaking actors",
            "chinese speaking group",
            "russian-speaking",
            "iran-affiliated",
            "kremlin-linked",
            "state-sponsored",
            "state sponsored group",
            "russia-aligned hacktivists",
            # All-descriptor multi-word names.
            "chinese apt",
            "iranian threat actor",
            "ransomware group",
            "pro-russian group",
            "initial access brokers",
            "russian cyber group",
            # Placeholders shared with node_identity.
            "unknown",
            "threat actor",
            "apt",
            "n/a",
            "",
            # Exact phrases / junk fragments.
            "others",
            "and others",
            "etc.",
            "and",
            # Trailing punctuation / case / whitespace tolerant.
            "Russian Hackers.",
            "  MULTIPLE  RUSSIAN  GROUPS  ",
            "(unknown)",
        ],
    )
    def test_generic(self, name):
        assert is_generic_actor_name(name) is True, name

    @pytest.mark.parametrize(
        "name",
        [
            # Spec: must stay names even though they contain descriptor tokens.
            "gorgon group",
            "lazarus group",
            "wizard spider",
            "night dragon",
            "apt28",
            "the gentlemen",
            "sandworm team",
            "nasir security",
            # Real names with a descriptor as LAST word (singular group/team).
            "equation group",
            "winnti group",
            "cobalt group",
            "gamaredon group",
            "gaza hackers team",
            "turk hack team",
            # Real names containing nexus / brokers / unit / army / country nouns.
            "nexus zeta",
            "the shadow brokers",
            "unit 8200",
            "unit 74455",
            "cyber army of russia reborn",
            "syrian electronic army",
            "iranian cyber army",
            # Hyphen / digit names.
            "apt-c-13",
            "dev-0586",
            "storm-0558",
            "unc6384",
            "ta505",
            "fin7",
            # Hacktivist collectives.
            "anonymous sudan",
            "cyber partisans",
            "people's cyber army",
            "guardians of peace",
            "killnet",
            # Single words are never generic unless placeholder / exact phrase.
            "sandworm",
            "twelve",
            "play",
        ],
    )
    def test_not_generic(self, name):
        assert is_generic_actor_name(name) is False, name

    def test_non_string_is_generic(self):
        assert is_generic_actor_name(None) is True  # type: ignore[arg-type]
        assert is_generic_actor_name(12) is True  # type: ignore[arg-type]

    def test_singular_group_is_not_a_last_word_signal(self):
        """Pin the design decision: ``"group"`` / ``"team"`` must NOT be in
        the last-word set, otherwise every ``"<name> group"`` actor dies."""
        assert "group" not in GENERIC_LAST_WORDS
        assert "team" not in GENERIC_LAST_WORDS
        assert "brokers" not in GENERIC_LAST_WORDS  # "the shadow brokers"

    def test_zero_width_characters_do_not_bypass_placeholder_check(self):
        assert is_generic_actor_name("unknown​") is True
        assert is_generic_actor_name("﻿apt") is True


# ===========================================================================
# clean_actor_names
# ===========================================================================


class TestCleanActorNames:
    def test_split_then_drop_generic(self):
        assert clean_actor_names("apt28 and russian hackers") == ["apt28"]
        assert clean_actor_names("multiple russian state-backed groups") == []
        assert clean_actor_names("russia-nexus apt") == []
        assert clean_actor_names("lockbit, cl0p, refined kitten, wicked panda, fancy bear") == [
            "lockbit",
            "cl0p",
            "refined kitten",
            "wicked panda",
            "fancy bear",
        ]

    def test_plain_real_name_untouched(self):
        assert clean_actor_names("Mustang Panda") == ["Mustang Panda"]

    def test_empty_and_non_string(self):
        assert clean_actor_names("") == []
        assert clean_actor_names(None) == []  # type: ignore[arg-type]


# ===========================================================================
# Regression table — real-looking names that must pass through UNCHANGED
# through every helper (not split, not flagged, trimmed only).
# ===========================================================================

REAL_ACTOR_NAMES = [
    "APT28",
    "apt29",
    "APT-C-36",
    "Mustang Panda",
    "RedDelta",
    "Twill Typhoon",
    "UNC6384",
    "Lazarus Group",
    "Gorgon Group",
    "Equation Group",
    "Sandworm Team",
    "Wizard Spider",
    "Night Dragon",
    "The Gentlemen",
    "The Dukes",
    "The Shadow Brokers",
    "Nasir Security",
    "Cozy Bear",
    "Fancy Bear",
    "Charming Kitten",
    "Refined Kitten",
    "Wicked Panda",
    "Volt Typhoon",
    "Salt Typhoon",
    "Midnight Blizzard",
    "Scattered Spider",
    "Evil Corp",
    "Black Basta",
    "LockBit",
    "Cl0p",
    "TA505",
    "FIN7",
    "DEV-0586",
    "Storm-0558",
    "Unit 8200",
    "Cyber Army of Russia Reborn",
    "Syrian Electronic Army",
    "Anonymous Sudan",
    "Cyber Partisans",
    "People's Cyber Army",
    "Guardians of Peace",
    "KillNet",
    "NoName057(16)",
    "MuddyWater",
    "OilRig",
    "Turla",
    "Head Mare",
    "Twelve",
    "FrozenBarents",
    "Dark Caracal",
    "Energetic Bear",
    "Sea Turtle",
    "Earth Preta",
    "BRONZE PRESIDENT",
    "Nexus Zeta",
]


@pytest.mark.parametrize("name", REAL_ACTOR_NAMES)
def test_real_names_pass_through_unchanged(name):
    assert split_composite_actor_name(name) == [name]
    assert is_generic_actor_name(name) is False
    assert clean_actor_names(name) == [name]


# ===========================================================================
# Country and state names, nationality adjectives (2026-10-18)
# ===========================================================================


# Country and state names and nationality adjectives on their own (rule (c)).
COUNTRY_STATE_AND_NATIONALITY_NAMES = (
    # ISO 3166 short names, any case, edge punctuation tolerated.
    "north korea",
    "North Korea",
    "russia",
    "China",
    "iran",
    "Israel.",
    "(china)",
    "viet nam",
    "türkiye",
    "turkey",
    "côte d'ivoire",
    "united states of america",
    "guinea-bissau",
    # Long and short state forms.
    "dprk",
    "DPRK",
    "prc",
    "roc",
    "usa",
    "us",
    "U.S.",
    "U.S.A.",
    "uk",
    "U.K.",
    "uae",
    "ussr",
    "russian federation",
    "people's republic of china",
    "people’s republic of china",  # typographic apostrophe
    "democratic people's republic of korea",
    "islamic republic of iran",
    "republic of korea",
    "south korea",
    "korea",
    "taiwan",
    "palestine",
    "gaza",
    "crimea",
    "kosovo",
    "great britain",
    "soviet union",
    # Names with " and " are not split into two halves.
    "bosnia and herzegovina",
    "Trinidad and Tobago",
    # A nationality adjective on its own.
    "russian",
    "Chinese",
    "iranian",
    "north korean",
    "korean",
    "israeli",
    "ukrainian",
    "belarusian",
    # Spellings compared without apostrophes, dots or hyphens.
    "peoples republic of china",
    "people\u02bcs republic of china",  # modifier-letter apostrophe
    "democratic peoples republic of korea",
    "N. Korea",
    "N.Korea",
    "North-Korea",
    "u. s.",
    # Long state forms and adjectives.
    "state of israel",
    "kingdom of saudi arabia",
    "republic of türkiye",
    "republic of turkey",
    "socialist republic of vietnam",
    "republic of ireland",
    "Lao PDR",
    "persia",
    "persian",
    "kurdish",
    "azeri",
    "belarussian",
)


class TestCountryAndStateNames:
    """A country or state, or a nationality adjective on its own, says where an actor is said to be
    from, never which actor it is: OTX adversary fields list "APT37, North Korea"."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # A country name with a parenthetical of its own is dropped whole, not kept as "Malvinas".
            ("Falkland Islands (Malvinas)", []),
            # A country name with "and" inside a longer "and" list is one name, then dropped.
            ("APT28 and Bosnia and Herzegovina", ["APT28"]),
            ("Lazarus and Saint Kitts and Nevis", ["Lazarus"]),
            ("Trinidad & Tobago and APT41", ["APT41"]),
            # 2026-11-05: "&&" inside a country name reads as "and", as in the other spellings.
            ("Trinidad && Tobago", []),
            ("APT41, Trinidad && Tobago", ["APT41"]),
            ("Trinidad && Tobago and APT41", ["APT41"]),
            # Ordinary "and" lists still split.
            ("Head Mare and Twelve", ["Head Mare", "Twelve"]),
            ("APT28 and APT29", ["APT28", "APT29"]),
        ],
    )
    def test_country_names_inside_composites_never_leave_fragments(self, raw, expected):
        assert clean_actor_names(raw) == expected

    @pytest.mark.parametrize("name", COUNTRY_STATE_AND_NATIONALITY_NAMES)
    def test_generic(self, name):
        assert is_generic_actor_name(name) is True, name
        assert clean_actor_names(name) == [], name

    @pytest.mark.parametrize(
        "name",
        [
            # A country or nationality inside a longer name stays a name.
            "cyber army of russia reborn",
            "anonymous sudan",
            "syrian electronic army",
            "iranian cyber army",
            "gaza hackers team",
            "turk hack team",
            "russian business network",
            "korean dragon",
            "china chopper crew",
            "lazarus group",
            "kimsuky",
        ],
    )
    def test_names_containing_a_country_stay_names(self, name):
        assert is_generic_actor_name(name) is False, name

    def test_a_country_beside_an_actor_is_dropped(self):
        # The OTX adversary field of a pulse on APT37 (ScarCruft).
        assert clean_actor_names("APT37, North Korea") == ["APT37"]
        assert clean_actor_names("Lazarus Group; DPRK") == ["Lazarus Group"]
        assert clean_actor_names("Kimsuky and North Korea") == ["Kimsuky"]
        assert clean_actor_names("Lazarus Group (North Korea)") == ["Lazarus Group"]
        # The actor in parentheses behind a country is the name.
        assert clean_actor_names("North Korea (APT37)") == ["APT37"]
        assert clean_actor_names("DPRK (Kimsuky)") == ["Kimsuky"]
        assert clean_actor_names("Korea (Democratic People's Republic of)") == []
        assert clean_actor_names("North Korea (unknown)") == []
        assert clean_actor_names("Cuba (Ransomware)") == []
        assert clean_actor_names("North Korea (unknown and APT41)") == ["APT41"]
        assert clean_actor_names("apt28, Bosnia and Herzegovina") == ["apt28"]
        assert clean_actor_names("Sandworm, Russia, Russian Federation") == ["Sandworm"]

    def test_inverted_country_names_leave_no_fragment(self):
        assert clean_actor_names("Korea, North") == []
        assert clean_actor_names("Korea, South") == []
        assert clean_actor_names("APT37, Korea, North") == ["APT37"]
        assert clean_actor_names("Korea, Democratic People's Republic of") == []
        assert clean_actor_names("Macedonia, the Former Yugoslav Republic of") == []

    def test_a_country_name_with_and_is_never_split(self):
        assert split_composite_actor_name("Bosnia and Herzegovina") == ["Bosnia and Herzegovina"]
        assert split_composite_actor_name("Antigua & Barbuda") == ["Antigua & Barbuda"]


# ===========================================================================
# State intelligence and security agencies (2026-11-05)
# ===========================================================================

# A state agency on its own, also behind a country or nationality or followed by "of" and a country:
# never an actor name (rule (c)). The first three are OTX adversary fields of the 3 Nov baseline.
STATE_AGENCY_NAMES_ON_THEIR_OWN = (
    "MOIS",
    "Russian Federal Security Service",
    "russian intelligence services",
    "mois",
    "FSB",
    "the FSB",
    "GRU",
    "SVR",
    "MSS",
    "F.S.B.",
    "Federal Security Service",
    "Federal Security Service of the Russian Federation",
    "Main Intelligence Directorate",
    "Foreign Intelligence Service",
    "Russian Foreign Intelligence Service",
    "Ministry of State Security",
    "Chinese Ministry of State Security",
    "Ministry of State Security of the People's Republic of China",
    "Ministry of Intelligence and Security",
    "Iran's Ministry of Intelligence and Security",
    "Iranian Ministry of Intelligence",
    "russian gru",
    "Russia's FSB",
    "chinese mss",
    "Russian intelligence service",
    "U.S. intelligence services",
    "north korean intelligence agencies",
    "russian special services",
    "Security Service of Ukraine",
)


class TestStateAgencies:
    """A state intelligence or security agency says who is said to sponsor an actor, never which actor
    it is: the galaxies name several groups of each (APT28 and Sandworm Team of GRU units, MuddyWater
    and APT39 of Iran's MOIS)."""

    @pytest.mark.parametrize("name", STATE_AGENCY_NAMES_ON_THEIR_OWN)
    def test_generic(self, name):
        assert is_generic_actor_name(name) is True, name
        assert clean_actor_names(name) == [], name
        assert dropped_geopolitical_names(name) == [" ".join(name.split())], "logged like a country name"

    @pytest.mark.parametrize(
        "name",
        [
            # A proper name that contains an agency stays a name.
            "GRU Unit 26165",
            "Russian GRU Unit 74455",
            "fsb center 16",
            "APT28",
            "MuddyWater",
            "Nasir Security",
            "Security Service Hackers Team",
            "GRUnt",  # an acronym inside a word
        ],
    )
    def test_names_containing_an_agency_stay_names(self, name):
        assert is_generic_actor_name(name) is False, name
        assert clean_actor_names(name) == [name], name

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # A pulse naming the actor and its sponsor names one actor.
            ("APT28, GRU", ["APT28"]),
            ("Sandworm, GRU, Russia", ["Sandworm"]),
            ("MuddyWater; MOIS", ["MuddyWater"]),
            ("Turla and FSB", ["Turla"]),
            ("FSB and GRU", []),
            ("FSB && GRU", []),
            # The spelled-out name with "and" is one name, also inside an "and" list.
            ("Ministry of Intelligence and Security", []),
            ("APT34 and Ministry of Intelligence and Security", ["APT34"]),
            ("MOIS (Ministry of Intelligence and Security)", []),
            # 2026-11-05: also with "&" or "&&", on its own, after a comma and inside an "and" list.
            ("Ministry of Intelligence & Security", []),
            ("Ministry of Intelligence && Security", []),
            ("APT34, Ministry of Intelligence && Security", ["APT34"]),
            ("APT34 && Ministry of Intelligence && Security", ["APT34"]),
            # The actor in parentheses behind an agency is the name, as behind a country.
            ("FSB (Turla)", ["Turla"]),
            ("Turla (FSB)", ["Turla"]),
            ("Ministry of State Security (MSS)", []),
        ],
    )
    def test_an_agency_beside_an_actor_is_dropped(self, raw, expected):
        assert clean_actor_names(raw) == expected

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("APT28, GRU", ["GRU"]),
            ("Sandworm, GRU, Russia", ["GRU", "Russia"]),
            ("APT34 and Ministry of Intelligence and Security", ["Ministry of Intelligence and Security"]),
            ("MOIS (Ministry of Intelligence and Security)", ["MOIS"]),
            ("FSB (Turla)", []),
            ("GRU Unit 26165", []),
        ],
    )
    def test_dropped_agencies_are_returned_like_country_names(self, raw, expected):
        assert dropped_geopolitical_names(raw) == expected

    def test_the_list_is_lower_case_trimmed_and_small(self):
        from actor_name_hygiene import STATE_AGENCY_NAMES

        for name in STATE_AGENCY_NAMES:
            assert name == " ".join(name.lower().split()), name
        assert {"fsb", "gru", "svr", "mss", "mois"} <= STATE_AGENCY_NAMES
        assert len(STATE_AGENCY_NAMES) < 25


# ===========================================================================
# No name of the canonical threat-actor reference is generic
# ===========================================================================

# Names the reference gives an actor that the rules judged generic before the country rule
# (2026-10-18): galaxy records named as placeholders, and "hacking team" (rule b4: both words are
# descriptors). Pinned so that a change to any rule list that makes another reference name generic,
# or one of these a name again, is a decision taken here.
REFERENCE_NAMES_GENERIC_BEFORE_COUNTRY_RULE = frozenset(
    {"[unnamed group]", "hacking team", "unnamed actor", "unnamed actor group", "unnamed actor team"}
)
# Names of the reference that clean_actor_names does not keep as they are: the generic names above, and no
# other. Pinned so that a rule change that alters any other name of the reference is a decision taken here
# (2026-11-05: the "&&" separator, the "-speaking" qualifier and state agencies changed none, and the
# threat-actor galaxy's record "Stealth Mango and Tangelo", which the and-split made two names, became a
# protected prefix).
REFERENCE_NAMES_NOT_KEPT_AS_THEY_ARE = REFERENCE_NAMES_GENERIC_BEFORE_COUNTRY_RULE


class TestTheCanonicalReferenceIsNeverGeneric:
    @pytest.fixture(scope="class")
    def reference_doc(self):
        import json

        from canonical_threat_actors import DEFAULT_REFERENCE_PATH

        return json.loads(DEFAULT_REFERENCE_PATH.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def reference_names(self, reference_doc):
        names = set()
        for actor in reference_doc["actors"]:
            names.add(actor["key"])
            names.update(actor["synonyms"])
        assert len(names) > 5000, "every key and synonym of the shipped reference"
        return names

    def test_no_key_or_synonym_is_generic(self, reference_names):
        generic = {n for n in reference_names if is_generic_actor_name(n)}
        assert generic == REFERENCE_NAMES_GENERIC_BEFORE_COUNTRY_RULE

    def test_every_name_of_the_reference_is_kept_as_it_is(self, reference_doc, reference_names):
        """Every actor key and synonym, ambiguous name and not-actor name of the committed reference comes
        out of clean_actor_names unchanged, except the pinned names."""
        listed = {e["key"] for e in reference_doc["ambiguous"]} | {e["key"] for e in reference_doc["not_actors"]}
        changed = {n for n in reference_names | listed if clean_actor_names(n) != [n]}
        assert changed == REFERENCE_NAMES_NOT_KEPT_AS_THEY_ARE
        assert len(listed) > 100

    def test_the_reference_resolves_no_country_state_nationality_or_agency_name(self):
        from actor_name_hygiene import COUNTRY_AND_STATE_NAMES, NATIONALITY_ADJECTIVES, STATE_AGENCY_NAMES
        from canonical_threat_actors import load_canonical_reference

        reference = load_canonical_reference()
        names = COUNTRY_AND_STATE_NAMES | NATIONALITY_ADJECTIVES | STATE_AGENCY_NAMES
        resolved = sorted(n for n in names if reference.canonical_for(n))
        assert resolved == []

    def test_the_lists_are_lower_case_and_trimmed(self):
        from actor_name_hygiene import COUNTRY_AND_STATE_NAMES, NATIONALITY_ADJECTIVES

        for name in COUNTRY_AND_STATE_NAMES | NATIONALITY_ADJECTIVES:
            assert name == " ".join(name.lower().split()), name

    def test_no_name_of_the_reference_begins_with_a_legal_form(self, reference_doc, reference_names):
        """A list fragment that begins with a legal-form word joins the fragment before it (2026-11-06), so
        such a reference name behind a comma would be swallowed. None is; ``inc`` (INC Ransom) is a name."""
        from actor_name_hygiene import LEGAL_FORM_WORDS

        listed = {e["key"] for e in reference_doc["ambiguous"]} | {e["key"] for e in reference_doc["not_actors"]}
        first_words = {n.replace(",", " ").split()[0] for n in reference_names | listed if n.split()}
        # A legal-form word also counts with a final dot ("llc.").
        assert not (first_words | {w[:-1] for w in first_words if w.endswith(".")}) & LEGAL_FORM_WORDS
        assert "inc" in reference_names and clean_actor_names("LockBit, INC") == ["LockBit", "INC"]


# ===========================================================================
# dropped_geopolitical_names (2026-10-22)
# ===========================================================================


class TestDroppedGeopoliticalNames:
    """The country and state names and nationality adjectives that ``clean_actor_names`` drops from a
    name (rule (c)); the OTX collector logs those of its adversary fields."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            # A country beside the actor.
            ("APT37, North Korea", ["North Korea"]),
            ("Lazarus Group; DPRK", ["DPRK"]),
            ("Kimsuky and North Korea", ["North Korea"]),
            ("Sandworm, Russia, Russian Federation", ["Russia", "Russian Federation"]),
            ("apt28, Bosnia and Herzegovina", ["Bosnia and Herzegovina"]),
            ("APT28 and Bosnia and Herzegovina", ["Bosnia and Herzegovina"]),
            ("Trinidad & Tobago and APT41", ["Trinidad and Tobago"]),  # rejoined from the "&"-split sides
            ("Trinidad && Tobago", ["Trinidad && Tobago"]),
            ("APT34, Ministry of Intelligence && Security", ["Ministry of Intelligence && Security"]),
            # A country on its own, as the adversary of a group whose common name is that country.
            ("Russia", ["Russia"]),
            ("Cuba", ["Cuba"]),
            ("russian", ["russian"]),
            ("Falkland Islands (Malvinas)", ["Falkland Islands (Malvinas)"]),
            # The inverted form is one name.
            ("Korea, North", ["North Korea"]),
            ("APT37, Korea, North", ["North Korea"]),
            # Case-insensitive duplicates once, first spelling and order kept.
            ("DPRK, dprk, North Korea", ["DPRK", "North Korea"]),
            # A fragment that yields a name drops nothing.
            ("North Korea (APT37)", []),
            ("DPRK (Kimsuky)", []),
            ("Lazarus Group (North Korea)", []),
            ("North Korea (unknown and APT41)", []),  # the and-split of the parenthetical yields APT41
            ("Cuba Ransomware Gang", []),
            ("cyber army of russia reborn", []),
            ("APT37", []),
            # A parenthetical that yields no name, a description or a placeholder, leaves the country.
            ("North Korea (unknown)", ["North Korea"]),
            ("Cuba (Ransomware)", ["Cuba"]),
            ("China (APT)", ["China"]),
            ("APT41, Cuba (ransomware group)", ["Cuba"]),
            # Descriptions and placeholders are dropped, but they are not country names.
            ("russian hackers", []),
            ("APT28, unknown", []),
            ("", []),
        ],
    )
    def test_returns_the_country_names_clean_actor_names_drops(self, raw, expected):
        assert dropped_geopolitical_names(raw) == expected

    def test_non_string_input(self):
        assert dropped_geopolitical_names(None) == []  # type: ignore[arg-type]
        assert dropped_geopolitical_names(42) == []  # type: ignore[arg-type]

    @pytest.mark.parametrize("name", COUNTRY_STATE_AND_NATIONALITY_NAMES)
    def test_a_country_name_on_its_own_is_returned_whole(self, name):
        assert dropped_geopolitical_names(name) == [" ".join(name.split())]


def _fixture_inputs() -> list:
    """Every string this module passes to a hygiene helper: the first argument of each call written
    with a string literal, every entry of a ``parametrize`` list (the first item of a tuple entry, or
    the module constant the list names), and ``REAL_ACTOR_NAMES``."""
    helpers = {
        "clean_actor_names",
        "dropped_geopolitical_names",
        "is_generic_actor_name",
        "split_composite_actor_name",
    }
    found = set(REAL_ACTOR_NAMES)

    def add(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add(node.value)

    for node in ast.walk(ast.parse(Path(__file__).read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
        if name in helpers and node.args:
            add(node.args[0])
        elif name == "parametrize" and len(node.args) >= 2:
            values = node.args[1]
            if isinstance(values, ast.Name):  # a module constant (not FIXTURE_INPUTS, built from this)
                found.update(v for v in globals().get(values.id, ()) if isinstance(v, str))
                continue
            for entry in getattr(values, "elts", []):
                add(entry.elts[0] if isinstance(entry, ast.Tuple) and entry.elts else entry)
    return sorted(found)


FIXTURE_INPUTS = _fixture_inputs()


def test_every_fixture_of_this_module_is_checked():
    assert len(FIXTURE_INPUTS) > 250
    for sample in ("APT37, North Korea", "North Korea (APT37)", "russian hackers", "Mustang Panda", "u. s."):
        assert sample in FIXTURE_INPUTS, sample


@pytest.mark.parametrize("raw", FIXTURE_INPUTS)
def test_dropped_geopolitical_names_agrees_with_clean_actor_names(raw):
    """On every fixture of this module: no dropped name is a name ``clean_actor_names`` keeps, every
    dropped name is a country, state, nationality or agency name that ``clean_actor_names`` drops on its own,
    the dropped names together yield no name and drop the same names again, and no kept name drops
    anything."""
    names = clean_actor_names(raw)
    dropped = dropped_geopolitical_names(raw)
    assert not {n.casefold() for n in names} & {d.casefold() for d in dropped}, (names, dropped)
    for name in dropped:
        assert is_generic_actor_name(name) is True, name
        assert clean_actor_names(name) == [], name
        assert dropped_geopolitical_names(name) == [name], name
    assert clean_actor_names("; ".join(dropped)) == []
    assert dropped_geopolitical_names("; ".join(dropped)) == dropped
    assert all(dropped_geopolitical_names(name) == [] for name in names), "a kept name is no country name"


@pytest.mark.parametrize("raw", FIXTURE_INPUTS)
def test_every_name_of_every_fixture_is_clean(raw):
    """2026-11-06: no name has unbalanced parentheses or is only a legal form, and every name is kept as it
    is when it is cleaned again."""
    _assert_clean_names(raw)
