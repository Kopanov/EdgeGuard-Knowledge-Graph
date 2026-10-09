"""Tests for ``src/actor_name_hygiene.py`` — pure threat-actor name hygiene.

Covers the three public helpers (``split_composite_actor_name``,
``is_generic_actor_name``, ``clean_actor_names``) against the junk observed
in the deployed graph (composite OTX adversary strings, generic descriptions)
plus a regression table of real-looking names that must pass through
unchanged — the module's design rule is "prefer not splitting / not
flagging over doing so wrongly".
"""

from __future__ import annotations

import os
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
            "a and b",  # sides shorter than AND_SPLIT_MIN_SIDE_LEN
            "ab & cd",
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
            "north korea",
            "russia",
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
