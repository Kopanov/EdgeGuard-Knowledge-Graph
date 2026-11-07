"""``text_caps.cap_text``: markup stripped, then a cut at a sentence or word end (2026-11-07).

Real texts: ``tests/fixtures/text_caps_sources_2026_11_07.json`` holds six ATT&CK objects of the Enterprise bundle of
attack-stix-data (collection 20.1) with their descriptions verbatim (two techniques with markdown links, runs of
citations and ``<code>`` tags; a group; a malware; a tool; a tactic) and two NVD API 2.0 records whose descriptions
are longer than 1,000 characters (CVE-2026-2411 with "e.g.", CVE-2026-69245 with version numbers and IP addresses).
Older MISP copies are made by the writer's own cut (``misp_writer.sanitize_value``: 255 characters with "...").
The other texts are constructed, each to isolate one rule, and say so.
"""

from __future__ import annotations

import json
import random
import re
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import text_caps  # noqa: E402
from collectors.misp_writer import sanitize_value  # noqa: E402
from text_caps import (  # noqa: E402
    CISA_SHORT_DESCRIPTION_CAP,
    CVE_DESCRIPTION_CAP,
    ENTITY_DESCRIPTION_CAP,
    SUMMARY_CAP,
    cap_text,
    capped,
    strip_markup,
)

FIXTURE = json.loads((TESTS / "fixtures" / "text_caps_sources_2026_11_07.json").read_text())
ATTACK = {o["external_references"][0]["external_id"]: o["description"] for o in FIXTURE["attack"]}
NVD = {v["cve"]["id"]: next(d["value"] for d in v["cve"]["descriptions"] if d["lang"] == "en") for v in FIXTURE["nvd"]}
REAL_TEXTS = [*ATTACK.values(), *NVD.values()]
MARKUP = ("(Citation:", "](", "<code>", "</code>")


def _is_sentence_end(text: str) -> bool:
    return bool(re.search(r"[.!?][\"')\]’”]*\Z", text))


# ---------------------------------------------------------------------------------------------- the caps
class TestCaps:
    def test_the_plan_caps(self):
        assert (CVE_DESCRIPTION_CAP, ENTITY_DESCRIPTION_CAP, CISA_SHORT_DESCRIPTION_CAP, SUMMARY_CAP) == (
            1000,
            500,
            500,
            500,
        )

    def test_the_fixture_texts_are_what_the_tests_need(self):
        """Not vacuous: the recorded texts hold every kind of markup and exceed the caps."""
        technique = ATTACK["T1036.007"]
        assert all(m in technique for m in MARKUP) and ")(Citation:" in technique
        assert all(len(t) > CVE_DESCRIPTION_CAP for t in NVD.values())
        assert len(ATTACK["T1059.001"]) > ENTITY_DESCRIPTION_CAP and len(ATTACK["G0007"]) > ENTITY_DESCRIPTION_CAP
        assert len(ATTACK["TA0001"]) < ENTITY_DESCRIPTION_CAP and not any(m in ATTACK["TA0001"] for m in MARKUP)


# ---------------------------------------------------------------------------------------------- markup
class TestMarkup:
    def test_an_attack_technique_loses_links_citations_and_code_tags(self):
        text = strip_markup(ATTACK["T1036.007"])
        assert not any(m in text for m in MARKUP)
        # A link keeps its name; code keeps its text; a run of citations goes whole.
        assert "gain Initial Access into a user’s system via Spearphishing Attachment then User Execution." in text
        assert "(ex: File.txt.exe may render in some views as just File.txt)." in text
        assert "system’s policies.\n\nAdversaries may abuse double extensions" in text  # no " \n" left
        # A "." that starts a token keeps the space before it.
        assert "(ex: explorer.exe)" in text and "such as .exe, .lnk, .hta, and .scr, often" in text

    def test_spaces_the_stripping_leaves_are_normalised(self):
        for text in REAL_TEXTS:
            out = strip_markup(text)
            if out == text:
                continue
            assert "  " not in out
            assert not re.search(r"[ \t]+[.,;:!?](\s|\Z)", out)
            assert not re.search(r"[ \t]\n|\n[ \t]", out)
            assert out == out.strip()

    def test_a_double_space_between_links_becomes_one(self):
        # T1059.001 has "[Empire](…),  [PowerSploit](…)" with two spaces.
        assert ",  [PowerSploit]" in ATTACK["T1059.001"]
        assert "including Empire, PowerSploit, PoshC2, and PSAttack." in strip_markup(ATTACK["T1059.001"])

    def test_a_text_without_markup_keeps_its_spacing(self):
        # Constructed: two spaces and a space before a full stop, no markup.
        text = "Version 2.0  fixes it . Upgrade now ."
        assert strip_markup(text) == text
        assert cap_text(text, 500) == (text, False, len(text))

    def test_a_space_before_a_closing_parenthesis_goes(self):
        # Constructed.
        assert strip_markup("used by APT28 (and others (Citation: Vendor 2020) ).") == "used by APT28 (and others)."

    def test_a_citation_name_with_parentheses(self):
        # Constructed: ATT&CK citation names may hold a year in parentheses.
        assert strip_markup("A tool.(Citation: Microsoft (2021)) Next.") == "A tool. Next."

    def test_a_link_url_with_parentheses(self):
        # Constructed.
        assert strip_markup("See [Foo](https://en.wikipedia.org/wiki/Foo_(bar)) here.") == "See Foo here."

    def test_a_link_inside_a_links_name_is_stripped_too(self):
        # Constructed: stripping repeats until nothing changes.
        assert strip_markup("A [[B](http://b)](http://a) c.") == "A B c."

    def test_code_tags_in_any_case(self):
        assert strip_markup("Run <CODE>cmd.exe</Code> now.") == "Run cmd.exe now."

    def test_text_that_is_only_markup(self):
        for text in ("(Citation: A)(Citation: B)", "<code></code>", " (Citation: A) "):
            assert cap_text(text, 500) == ("", False, 0)


class TestOlderMispCopies:
    """MISP copies an older writer cut at 255 characters with "..." (``sanitize_value``), as MISP holds ATT&CK's
    descriptions written before the collector cut moved to the sync."""

    @pytest.mark.parametrize("ext_id", sorted(ATTACK))
    def test_no_markup_is_left_whatever_the_cut(self, ext_id):
        full = ATTACK[ext_id]
        for length in range(60, min(len(full), 600), 7):
            copy = sanitize_value(full, max_length=length)
            out = cap_text(copy, ENTITY_DESCRIPTION_CAP)[0]
            assert not any(m in out for m in MARKUP), (ext_id, length, out[-80:])
            assert "[" not in out and "(Cit" not in out, (ext_id, length, out[-80:])

    def test_a_copy_cut_inside_a_citation_ends_before_it(self):
        full = ATTACK["T1059.001"]
        at = full.index("(Citation: TechNet PowerShell)") + len("(Citation: Tech")
        copy = full[:at] + "..."
        assert cap_text(copy, 500)[0] == "Adversaries may abuse PowerShell commands and scripts for execution. " + (
            "PowerShell is a powerful interactive command-line interface and scripting environment included in the "
            "Windows operating system."
        )

    @pytest.mark.parametrize("inside", ["(C...", "(Cit...", "(Citation..."])
    def test_a_copy_cut_inside_the_word_citation(self, inside):
        assert cap_text("It ends here." + inside, 500)[0] == "It ends here."

    def test_a_copy_cut_inside_a_link_url_keeps_the_name(self):
        full = ATTACK["T1059.001"]
        at = full.index("[Empire](https://attack.mitre.org/software/S0363)") + len("[Empire](https://attack.mi")
        assert cap_text(full[:at] + "...", 1000)[0].endswith("tools are available, including Empire")

    def test_a_copy_cut_inside_a_link_name_keeps_the_text(self):
        full = ATTACK["T1059.001"]
        at = full.index("[PowerSploit]") + len("[PowerSp")
        assert cap_text(full[:at] + "...", 1000)[0].endswith("including Empire, PowerSp...")

    def test_a_copy_within_the_cap_keeps_its_trailing_dots(self):
        copy = sanitize_value(ATTACK["TA0001"], max_length=255)
        assert copy.endswith("...")
        assert cap_text(copy, 500) == (copy, False, len(copy))


# ---------------------------------------------------------------------------------------------- the cut
class TestCut:
    @pytest.mark.parametrize("cap", [CVE_DESCRIPTION_CAP, ENTITY_DESCRIPTION_CAP, 300, 120])
    def test_every_real_text(self, cap):
        cut_somewhere = False
        for text in REAL_TEXTS:
            stripped = strip_markup(text)
            out, truncated, full_length = cap_text(text, cap)
            assert full_length == len(stripped)
            assert truncated == (len(stripped) > cap)
            assert len(out) <= cap and stripped.startswith(out)
            assert "..." not in out[-3:] or not truncated
            if truncated:
                cut_somewhere = True
                following = stripped[len(out)]
                assert not (out[-1].isalnum() and following.isalnum()), "never mid-word"
                assert len(out) >= cap // 2 or not _is_sentence_end(out)
            assert cap_text(out, cap) == (out, False, len(out)), "idempotent"
        assert cut_somewhere

    def test_a_cve_description_over_1000_cuts_at_its_last_sentence_end(self):
        out, truncated, full_length = cap_text(NVD["CVE-2026-69245"], CVE_DESCRIPTION_CAP)
        assert (truncated, full_length) == (True, len(NVD["CVE-2026-69245"]))
        # "127.0.0.1." ends a sentence; the version numbers and dotted addresses before it end none.
        assert out.endswith("reads them as 192.168.0.1 and 127.0.0.1.")
        assert NVD["CVE-2026-69245"][len(out) :].startswith(" A cookie stored for Domain=0x7f000001")

    def test_an_attack_group_cuts_at_its_last_sentence_end_within_500(self):
        out, truncated, _ = cap_text(ATTACK["G0007"], ENTITY_DESCRIPTION_CAP)
        assert truncated and out.startswith("APT28 is a threat group that has been attributed to Russia's General")
        assert out.endswith("in an attempt to interfere with the U.S. presidential election.")

    def test_us_is_no_sentence_end(self):
        stripped = strip_markup(ATTACK["G0007"])
        cap = stripped.index("U.S. presidential") + len("U.S. pres")
        expected = stripped[: stripped.index("since at least 2004.") + len("since at least 2004.")]
        assert len(expected) >= cap // 2  # the sentence end before it is within the half-cap floor
        assert cap_text(ATTACK["G0007"], cap)[0] == expected

    def test_eg_is_no_sentence_end(self):
        text = NVD["CVE-2026-2411"]
        cap = text.index("(e.g. BT_GATT_PERM_READ_ENCRYPT") + len("(e.g. BT_GATT_PERM_READ_ENCRYPT / REA")
        out = cap_text(text, cap)[0]
        assert out.endswith("(e.g. BT_GATT_PERM_READ_ENCRYPT /")

    @pytest.mark.parametrize(
        "abbreviation", ["e.g.", "i.e.", "vs.", "Inc.", "Corp.", "Ltd.", "No.", "Nov.", "J.", "a.k.a.", "U.K."]
    )
    def test_an_abbreviation_ends_no_sentence(self, abbreviation):
        # Constructed: the abbreviation is the only candidate within the cap, after the half-cap floor.
        text = "x" * 10 + " word word word word " + abbreviation + " Then more text follows here."
        cap = text.index(abbreviation) + len(abbreviation) + 6
        out = cap_text(text, cap)[0]
        assert out.endswith(abbreviation + " Then"), out

    def test_an_ellipsis_ends_no_sentence(self):
        text = "aaaa bbbb cccc dddd... Then more text follows here."
        assert cap_text(text, text.index("Then") + 6)[0] == "aaaa bbbb cccc dddd... Then"

    def test_a_full_stop_before_a_lowercase_word_ends_no_sentence(self):
        text = "aaaa bbbb cccc dddd. then more text follows here."
        assert cap_text(text, text.index("then") + 6)[0] == "aaaa bbbb cccc dddd. then"

    @pytest.mark.parametrize("end", ["!", "?", '."', ".)", ".”"])
    def test_other_sentence_ends(self, end):
        text = f"aaaa bbbb cccc dddd{end} Then more text follows here."
        assert cap_text(text, text.index("Then") + 6)[0] == f"aaaa bbbb cccc dddd{end}"

    def test_a_sentence_end_before_half_the_cap_gives_way_to_a_word_end(self):
        # Constructed: the only sentence end keeps less than half of the cap.
        text = "Short. " + "Word " * 40
        assert cap_text(text, 100)[0] == "Short." + " Word" * 18

    def test_a_sentence_end_just_below_half_the_cap_is_not_taken(self):
        text = "a" * 48 + ". " + "Word " * 40
        assert cap_text(text, 100)[0] == "a" * 48 + "." + " Word" * 10

    def test_a_sentence_end_at_half_the_cap_is_taken(self):
        text = "a" * 49 + ". " + "Word " * 40
        assert cap_text(text, 100)[0] == "a" * 49 + "."

    def test_a_word_ending_at_the_cap_is_kept(self):
        text = "aaaa bbbb cccc dddd eeee"
        assert cap_text(text, 19)[0] == "aaaa bbbb cccc dddd"
        assert cap_text(text, 18)[0] == "aaaa bbbb cccc"

    def test_a_word_cut_drops_the_separators_it_leaves(self):
        assert cap_text("aaaa bbbb, (cccc dddd eeee", 12)[0] == "aaaa bbbb"
        assert cap_text("aaaa bbbb - cccc dddd eeee", 12)[0] == "aaaa bbbb"

    def test_no_ellipsis_is_appended(self):
        out, truncated, _ = cap_text("word " * 300, 500)
        assert truncated and not out.endswith("...") and out.endswith("word")

    def test_a_first_word_longer_than_the_cap(self):
        blob = "A" * 600
        assert cap_text(blob, 500) == ("", True, 600)
        assert cap_text(blob + " tail", 500) == ("", True, 605)

    def test_normalising_can_close_markup_which_is_then_stripped(self):
        # Constructed: removing the spaces before "." and ")" turns "[N](http://y . )" into a link.
        assert strip_markup("(Citation: A) See [N](http://y . ) now.") == "See N now."

    def test_a_cut_inside_brackets_leaves_no_unclosed_bracket(self):
        # Constructed: the cut falls inside "[a b]"; the "[" it would leave at the end goes.
        assert cap_text("Some words here [alpha beta gamma] end", 24) == ("Some words here alpha", True, 38)

    def test_idempotent_on_mixed_texts(self):
        """Constructed texts from tokens of every rule (markup, unclosed markup, abbreviations, punctuation,
        spaces), with a fixed seed: capping a capped text changes nothing and no text exceeds its cap."""
        tokens = [
            "word", "Word", "e.g.", "U.S.", "v1.2.3", "end.", "End.", "(Citation: A B)", "(Citation: X (2020))",
            "[Name](https://x.org/a_(b))", "[a b", "c]", "<code>", "</code>", "(", ")", ",", ".", "...", "  ", "\n",
            "\n\n", " ", "\t", "(Cit", "[N](http://y", "!", "?", '"', "'",
        ]  # fmt: skip
        rnd = random.Random(20261107)
        for _ in range(20000):
            text = "".join(rnd.choice(tokens) + rnd.choice(["", " ", " ", "  "]) for _ in range(rnd.randint(1, 60)))
            cap = rnd.randint(1, 120)
            out, _truncated, _full = cap_text(text, cap)
            assert len(out) <= cap, (text, cap)
            assert cap_text(out, cap) == (out, False, len(out)), (text, cap)

    def test_newlines_are_word_ends(self):
        text = "aaaa\nbbbb\ncccc"
        assert cap_text(text, 11)[0] == "aaaa\nbbbb"


# ---------------------------------------------------------------------------------------------- inputs
class TestInputs:
    @pytest.mark.parametrize("value", [None, 5, ["a"], {"a": 1}, b"bytes"])
    def test_a_value_that_is_not_a_string(self, value):
        assert cap_text(value, 500) == ("", False, 0)
        assert capped(value, 500) is value

    @pytest.mark.parametrize("cap", [0, -1, True, 1.5, "500", None])
    def test_a_cap_that_is_not_a_positive_int(self, cap):
        with pytest.raises(ValueError):
            cap_text("text", cap)

    def test_capped_is_the_first_value(self):
        assert capped(ATTACK["G0007"], 500) == cap_text(ATTACK["G0007"], 500)[0]

    def test_the_module_imports_the_standard_library_only(self):
        source = Path(text_caps.__file__).read_text()
        imports = set(re.findall(r"^(?:from|import) (\w+)", source, re.MULTILINE))
        assert imports <= {"__future__", "re", "typing"}
