"""``text_caps.cap_text``: markup stripped, then a cut at a sentence or word end (2026-11-07).

Real texts: ``tests/fixtures/text_caps_sources_2026_11_07.json`` holds six ATT&CK objects of the Enterprise bundle of
attack-stix-data (collection 20.1) with their descriptions verbatim (two techniques with markdown links, runs of
citations and ``<code>`` tags; a group; a malware; a tool; a tactic) and two NVD API 2.0 records whose descriptions
are longer than 1,000 characters (CVE-2026-2411 with "e.g.", CVE-2026-69245 with version numbers and IP addresses),
and five NVD API 2.0 records of the kernel.org CNA whose descriptions hold a ``[`` that opens no link (half-open
intervals, a memory region, an indented kernel log that NVD ends in ``[    2\n---truncated---``). Older MISP copies
are made by the writer's own cut (``misp_writer.sanitize_value``: a length with "..."). The other texts are
constructed, each to isolate one rule, and say so.
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
KERNEL = {
    v["cve"]["id"]: next(d["value"] for d in v["cve"]["descriptions"] if d["lang"] == "en")
    for v in FIXTURE["nvd_kernel"]
}
REAL_TEXTS = [*ATTACK.values(), *NVD.values(), *KERNEL.values()]
MARKUP = ("(Citation:", "](", "<code>", "</code>")


# The list the module documents, written out so that a test fails when an entry goes.
KNOWN_ABBREVIATIONS = (
    "approx.", "al.", "cf.", "co.", "corp.", "dept.", "dr.", "e.g.", "est.", "fig.", "i.e.", "inc.", "jr.", "ltd.",
    "mr.", "mrs.", "ms.", "no.", "nos.", "op.", "pp.", "prof.", "rev.", "sr.", "st.", "ver.", "viz.", "vol.", "vs.",
    "jan.", "feb.", "mar.", "apr.", "jun.", "jul.", "aug.", "sep.", "sept.", "oct.", "nov.", "dec.",
)  # fmt: skip


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

    def test_no_space_is_left_at_a_line_start_or_end(self):
        # Constructed: a citation at the start and at the end of a line.
        assert strip_markup("First.\n(Citation: A) Second. (Citation: B)\nThird.") == "First.\nSecond.\nThird."

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
    """MISP copies an older writer cut with "..." (``sanitize_value``: 255 or 400 characters), as MISP holds
    ATT&CK's descriptions written before the collector cut moved to the sync. Read with ``older_cut`` (step 1a),
    as the entity descriptions are."""

    @pytest.mark.parametrize("ext_id", sorted(ATTACK))
    def test_no_markup_is_left_whatever_the_cut(self, ext_id):
        full = ATTACK[ext_id]
        cut_in_markup = 0
        for length in range(10, min(len(full), 1200) + 1):
            copy = sanitize_value(full, max_length=length)
            out = cap_text(copy, ENTITY_DESCRIPTION_CAP, older_cut=True)[0]
            assert not any(m in out for m in MARKUP), (ext_id, length, out[-80:])
            assert "[" not in out and "(Cit" not in out and "<co" not in out, (ext_id, length, out[-80:])
            cut_in_markup += strip_markup(copy) != copy and copy != full
        assert cut_in_markup or ext_id == "TA0001"

    def test_the_writers_own_lengths(self):
        """The copies MISPWriter makes (255 for a technique, an actor and a tactic, 400 for malware and a tool)."""
        for ext_id, length in (("T1059.001", 255), ("T1036.007", 255), ("G0007", 255), ("S0154", 400)):
            copy = sanitize_value(ATTACK[ext_id], max_length=length)
            assert copy.endswith("...")
            out = cap_text(copy, ENTITY_DESCRIPTION_CAP, older_cut=True)[0]
            assert not any(m in out for m in MARKUP) and "[" not in out, (ext_id, out[-80:])

    def test_without_older_cut_a_copy_keeps_its_end(self):
        """A CVE description is read without step 1a: its "..." copies hold real brackets."""
        copy = "The handler walks rb_threads[c..."
        assert cap_text(copy, CVE_DESCRIPTION_CAP) == (copy, False, len(copy))
        assert cap_text(copy, CVE_DESCRIPTION_CAP, older_cut=True)[0] == "The handler walks rb_threadsc"

    def test_a_name_holds_no_parenthesis_or_line_break(self):
        # Constructed after T1564.004's "Data [known as Alternate Data Streams (ADSs) when more than one ...]".
        copy = "Data [known as Alternate Data Streams (ADSs) when more than one..."
        assert cap_text(copy, 500, older_cut=True)[0] == copy
        copy = "A list [of\nitems..."
        assert cap_text(copy, 500, older_cut=True)[0] == copy

    def test_a_copy_cut_just_after_a_link_name(self):
        full = ATTACK["G0007"]
        at = full.index("[APT28]") + len("[APT28]")
        assert cap_text(full[:at] + "...", 500, older_cut=True)[0] == "APT28"
        at = full.index("[APT28](") + len("[APT28](")
        assert cap_text(full[:at] + "...", 500, older_cut=True)[0] == "APT28"

    def test_a_removal_at_the_end_keeps_the_spacing_before_it(self):
        # Constructed: a text without closed markup keeps its spacing; only the end the removal leaves is trimmed.
        text = "Two  spaces stay .\n  Indented line uses [PowerSp..."
        assert cap_text(text, 500, older_cut=True)[0] == "Two  spaces stay .\n  Indented line uses PowerSp"
        assert cap_text("Two  spaces stay . (Cit...", 500, older_cut=True)[0] == "Two  spaces stay ."

    def test_a_copy_cut_inside_a_code_tag(self):
        text = "Run <code>cmd.exe</code> or <co..."
        assert cap_text(text, 500, older_cut=True)[0] == "Run cmd.exe or"
        assert cap_text("Run </cod...", 500, older_cut=True)[0] == "Run"

    def test_a_copy_cut_inside_a_citation_name_with_parentheses(self):
        assert cap_text("A tool.(Citation: Microsoft (20...", 500, older_cut=True)[0] == "A tool."
        assert cap_text("A tool.(Citation: Microsoft (2021) Blog...", 500, older_cut=True)[0] == "A tool."

    def test_an_earlier_cut_construct_brought_to_the_end_goes_too(self):
        # Constructed: removing the citation brings the cut link name to the end.
        assert cap_text("Uses [a b...(Cit...", 500, older_cut=True)[0] == "Uses a b"

    def test_a_cut_at_an_ellipsis_of_the_text_is_idempotent(self):
        # Constructed: the word cut ends just after the text's own "..." behind an unclosed "[".
        text = "word [alpha beta... gamma delta epsilon zeta"
        out = cap_text(text, 20, older_cut=True)
        assert out == ("word alpha beta", True, len(text))
        assert cap_text(out[0], 20, older_cut=True) == (out[0], False, len(out[0]))
        assert cap_text(text, 20) == ("word [alpha beta...", True, len(text))

    def test_a_copy_cut_inside_a_citation_ends_before_it(self):
        full = ATTACK["T1059.001"]
        at = full.index("(Citation: TechNet PowerShell)") + len("(Citation: Tech")
        copy = full[:at] + "..."
        expected = "Adversaries may abuse PowerShell commands and scripts for execution. " + (
            "PowerShell is a powerful interactive command-line interface and scripting environment included in the "
            "Windows operating system."
        )
        assert cap_text(copy, 500, older_cut=True)[0] == expected

    @pytest.mark.parametrize("inside", ["(C...", "(Cit...", "(Citation...", " (Citation: Vendor 20..."])
    def test_a_copy_cut_inside_the_word_citation(self, inside):
        assert cap_text("It ends here." + inside, 500, older_cut=True)[0] == "It ends here."

    def test_a_copy_cut_inside_a_link_url_keeps_the_name(self):
        full = ATTACK["T1059.001"]
        at = full.index("[Empire](https://attack.mitre.org/software/S0363)") + len("[Empire](https://attack.mi")
        assert cap_text(full[:at] + "...", 1000, older_cut=True)[0].endswith("tools are available, including Empire")

    def test_a_copy_cut_inside_a_link_name_keeps_the_text(self):
        """The name keeps the text the cut left, without the writer's "..." (decided: the graph's text carries no
        ellipsis it did not get from its source)."""
        full = ATTACK["T1059.001"]
        at = full.index("[PowerSploit]") + len("[PowerSp")
        assert cap_text(full[:at] + "...", 1000, older_cut=True)[0].endswith("including Empire, PowerSp")

    def test_a_copy_within_the_cap_keeps_its_trailing_dots(self):
        copy = sanitize_value(ATTACK["TA0001"], max_length=255)
        assert copy.endswith("...")
        assert cap_text(copy, 500, older_cut=True) == (copy, False, len(copy))


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
            # A prefix: the cut appends nothing (CVE-2026-80981's code holds a "..." of its own, which may end it).
            assert len(out) <= cap and stripped.startswith(out)
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

    def test_the_known_abbreviations(self):
        assert text_caps._ABBREVIATIONS == frozenset(KNOWN_ABBREVIATIONS)

    @pytest.mark.parametrize("abbreviation", sorted(set(KNOWN_ABBREVIATIONS) - {"e.g.", "i.e."}))
    def test_every_known_abbreviation_ends_no_sentence(self, abbreviation):
        # Constructed, as above, for each entry in lowercase and capitalised.
        for form in (abbreviation, abbreviation.capitalize()):
            text = "x" * 10 + " word word word word " + form + " Then more text follows here."
            cap = text.index(form) + len(form) + 6
            assert cap_text(text, cap)[0].endswith(form + " Then"), form

    def test_eg_and_ie_are_dotted_letters_too(self):
        """The list holds "e.g." and "i.e.", which are dotted letters too, so the loop above leaves them out."""
        assert {"e.g.", "i.e."} <= text_caps._ABBREVIATIONS
        assert all(text_caps._DOTTED_LETTERS_RE.match(t) for t in ("e.g.", "i.e.", "E.g."))

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

    @pytest.mark.parametrize("separator", [",", ";", ":", "(", "[", "{", "-", "–", "—"])
    def test_every_separator_the_cut_leaves_is_dropped(self, separator):
        # Constructed: the cut falls inside "cccc", just after the separator and its space.
        text = f"aaaa bbbb {separator} cccc dddd"
        assert cap_text(text, text.index("cccc") + 2)[0] == "aaaa bbbb"

    @pytest.mark.parametrize("space", ["\t", "\r", "\n", " "])
    def test_every_whitespace_is_a_word_end(self, space):
        text = f"aaaa{space}bbbb{space}cccc"
        assert cap_text(text, 11)[0] == f"aaaa{space}bbbb"

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

    def test_a_cut_inside_brackets_keeps_the_sources_bracket(self):
        # Constructed: the cut falls inside "[alpha beta gamma]", which opens no link: the kept text is a prefix.
        assert cap_text("Some words here [alpha beta gamma] end", 24) == ("Some words here [alpha", True, 38)
        # A "[" the cut would leave at the very end is a separator and goes.
        assert cap_text("Some words here [ alpha beta", 18) == ("Some words here", True, 28)

    def test_a_cut_that_drops_a_later_bracket_keeps_an_earlier_one(self):
        # Constructed: an interval early, a closed "[a]" (no link) that the cut drops.
        text = "Region [0, len) is checked first. Then the rest of it [a] is read."
        out = cap_text(text, 50)[0]
        assert out == "Region [0, len) is checked first." and text.startswith(out)

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
            for older_cut in (False, True):
                out, _truncated, _full = cap_text(text, cap, older_cut)
                assert len(out) <= cap, (text, cap, older_cut)
                assert cap_text(out, cap, older_cut) == (out, False, len(out)), (text, cap, older_cut)
            # Without step 1a the capped text is a prefix of the stripped text.
            assert strip_markup(text).startswith(cap_text(text, cap)[0]), (text, cap)

    def test_newlines_are_word_ends(self):
        text = "aaaa\nbbbb\ncccc"
        assert cap_text(text, 11)[0] == "aaaa\nbbbb"


# ---------------------------------------------------------------------------------------------- "[" without a link
class TestBracketsThatOpenNoLink:
    """Kernel CVE descriptions (NVD API 2.0, kernel.org CNA) hold a "[" that opens no link: it and the text's
    spacing are kept, within the cap and over it."""

    def test_the_fixture_texts_are_what_the_tests_need(self):
        assert "mres->ml[0..num_locks) past the" in KERNEL["CVE-2026-89494"]
        assert "opaque_len in [0, GSS_KRB5_TOK_HDR_LEN) is" in KERNEL["CVE-2026-89541"]
        assert "Zero the [unc_size, frame_size) tail" in KERNEL["CVE-2026-89616"]
        assert (
            "region [ffff88813c8e2b80, " in KERNEL["CVE-2026-81014"] and "\tlength = count;" in KERNEL["CVE-2026-81014"]
        )
        assert KERNEL["CVE-2026-80981"].endswith("[    2\n---truncated---")
        assert "\n  [    2.523161] BUG" in KERNEL["CVE-2026-80981"]
        assert all(len(t) > CVE_DESCRIPTION_CAP for t in KERNEL.values())

    @pytest.mark.parametrize("cve_id", sorted(KERNEL))
    def test_within_the_cap_the_text_is_unchanged(self, cve_id):
        text = KERNEL[cve_id]
        assert strip_markup(text) == text
        assert cap_text(text, len(text)) == (text, False, len(text))

    @pytest.mark.parametrize("cve_id", sorted(KERNEL))
    def test_over_the_cap_the_text_is_a_prefix(self, cve_id):
        text = KERNEL[cve_id]
        out, truncated, full_length = cap_text(text, CVE_DESCRIPTION_CAP)
        assert truncated and full_length == len(text) and len(out) <= CVE_DESCRIPTION_CAP
        assert text.startswith(out) and len(out) > CVE_DESCRIPTION_CAP // 2

    def test_the_sync_ranking_keeps_the_interval(self):
        from description_ranking import CVE_DESCRIPTIONS

        ranked = CVE_DESCRIPTIONS.record(KERNEL["CVE-2026-89494"], "nvd")
        assert ranked is not None and "mres->ml[0..num_locks) past the" in ranked.text
        assert KERNEL["CVE-2026-89494"].startswith(ranked.text)

    def test_a_text_without_markup_keeps_its_interval_and_spacing(self):
        # Constructed.
        text = "The fix bounds offset to [0, len) before the copy.  See   the  patch."
        assert cap_text(text, 1000) == (text, False, len(text))


# ---------------------------------------------------------------------------------------------- time
class TestTime:
    """Each text is read a bounded number of times: a 64 KB text full of brackets is capped at once."""

    @pytest.mark.parametrize(
        "text",
        [
            "[a " * 22000,
            "x[" * 32000,
            "[... " * 13000,
            "(C..." * 13000,
            "[" * 16000 + "a" + "](u)" * 12000,
            "[x" * 12000 + "](u)" * 12000,
            "(Citation: x " * 5000,
        ],
        ids=["unclosed", "x[", "older-cut-names", "older-cut-citations", "nested-links", "nested-names", "citations"],
    )
    def test_a_64_kb_text(self, text):
        import time

        assert len(text) > 60000
        start = time.perf_counter()
        for older_cut in (False, True):
            for cap in (CVE_DESCRIPTION_CAP, ENTITY_DESCRIPTION_CAP):
                cap_text(text, cap, older_cut)
        assert time.perf_counter() - start < 2.0


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
        copy = "Uses [PowerSp..."
        assert capped(copy, 500) == copy and capped(copy, 500, older_cut=True) == "Uses PowerSp"

    def test_the_module_imports_the_standard_library_only(self):
        source = Path(text_caps.__file__).read_text()
        imports = set(re.findall(r"^(?:from|import) (\w+)", source, re.MULTILINE))
        assert imports <= {"__future__", "re", "typing"}
