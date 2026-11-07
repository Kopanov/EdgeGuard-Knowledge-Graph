"""The caps on the texts the MISP -> Neo4j sync writes to the graph (2026-11-07).

MISP holds the text a source gives as the collector sent it; the graph holds a short form of it. Every cut of a
text bound for Neo4j is made here, on the sync's write path (``Neo4jClient``), never in a collector:

- ``CVE.description`` and ``Vulnerability.description``: ``CVE_DESCRIPTION_CAP`` (1,000 characters);
- the description of a ``Technique`` (sub-techniques included), ``Tactic``, ``ThreatActor``, ``Malware`` and
  ``Tool``: ``ENTITY_DESCRIPTION_CAP`` (500);
- ``CVE.cisa_short_description`` (CISA KEV's ``shortDescription`` as a node property of its own; no writer sets
  it yet): ``CISA_SHORT_DESCRIPTION_CAP`` (500).

``cap_text(text, cap)`` returns ``(text, truncated, full_length)``:

1. **Markup is stripped first.** A markdown link ``[Name](url)`` becomes ``Name``; every ``(Citation: X)`` is
   removed, also a run of several; the tags ``<code>`` and ``</code>`` are removed and the text between them is
   kept. A copy that an older writer cut inside markup ends in an unclosed citation, which is removed, or an
   unclosed link, which keeps its name. Stripping, with the normalising of spaces below, repeats until nothing
   changes, so a link inside a link's name is stripped too. When something was stripped, the spaces it leaves are normalised: no run of spaces or tabs,
   no space or tab before a ``.``, ``,``, ``;``, ``:``, ``!`` or ``?`` that ends a word group (one followed by
   whitespace or the end, so ``.exe`` keeps its space) or before ``)``, none at the start or end of a line, and
   none at either end of the text. A text without markup keeps its spacing.
2. **A text longer than the cap is cut**, at the last sentence end within the cap that keeps at least half of
   it, otherwise at the last whitespace within the cap. A sentence end is ``.``, ``!`` or ``?`` (with any
   closing quotes or brackets after it) followed by whitespace and then by no lowercase letter. A ``.`` does not
   end a sentence after a known abbreviation (``e.g.``, ``i.e.``, ``vs.``, ``Inc.``, a month, ...), a single
   letter (``J.``), dotted letters (``U.S.``, ``a.k.a.``) or an ellipsis; a ``.`` inside a token (``v1.2``,
   ``1.2.3``, ``example.com``) is followed by no whitespace and so ends nothing. The cut never splits a word
   and never appends an ellipsis; separators the cut leaves at the end (whitespace, ``,``, ``;``, ``:``, an
   opening bracket, a dash) are dropped.
3. **``full_length``** is the length of the whole stripped text; ``truncated`` is whether the text was cut.

Edge cases, decided:

- ``None`` or a value that is not a string gives ``("", False, 0)``. A writer leaves such a value as it is.
- ``cap`` below 1 raises ``ValueError``: every cap is a constant of this module.
- A text whose first word is longer than the cap (a URL, an encoded blob) gives ``("", True, full_length)``:
  the cut never splits a word, so the graph gets no text and MISP keeps the whole.
- A text that is only markup gives ``("", False, 0)``.
- A text within the cap that ends in ``...`` (a MISP copy an older writer cut, such as an ATT&CK description cut
  at 255 characters) is kept as it is; over the cap, it is cut like any other text.

The function is idempotent: capping a capped text changes nothing. Standard library only.
"""

from __future__ import annotations

import re
from typing import Any, Tuple

# The caps (characters). 1,000 for a CVE's description is an explicit exception to 500: 500 would cut 28% of the
# CVE descriptions of the 730-day test graph.
SUMMARY_CAP = 500
CVE_DESCRIPTION_CAP = 1000
ENTITY_DESCRIPTION_CAP = SUMMARY_CAP
CISA_SHORT_DESCRIPTION_CAP = SUMMARY_CAP

# ------------------------------------------------------------------------------------------------ markup
# ``(Citation: X)``; the name may hold one level of balanced parentheses ("(Citation: Microsoft (2021))").
_CITATION_RE = re.compile(r"\(Citation:[^()]*(?:\([^()]*\)[^()]*)*\)")
# ``[Name](url)``: the name holds no bracket; the URL holds no whitespace and one level of balanced parentheses
# ("https://en.wikipedia.org/wiki/Foo_(bar)").
_LINK_RE = re.compile(r"\[([^\[\]]*)\]\((?:[^()\s]|\([^()\s]*\))*\)")
_CODE_TAG_RE = re.compile(r"</?code>", re.IGNORECASE)
# The markup an older writer's cut left unclosed at the end of a text: a citation, also one cut inside the word
# "Citation" ("(Cita..."); a link cut inside its URL ("[Name](https://attack.mi...") or its name ("[Na...").
_UNCLOSED_CITATION_RE = re.compile(r"\((?:Citation:[^)]*|C(?:i(?:t(?:a(?:t(?:i(?:on?)?)?)?)?)?)?\.+)\Z")
_UNCLOSED_LINK_RE = re.compile(r"\[([^\[\]]*)\]\([^)\s]*\Z")
_UNCLOSED_LINK_NAME_RE = re.compile(r"\[([^\[\]]*)\Z")

_SPACE_RUN_RE = re.compile(r"[ \t]{2,}")
_SPACE_BEFORE_PUNCT_RE = re.compile(r"[ \t]+(?:([.,;:!?])(?=\s|\Z)|(\)))")
_SPACE_AT_LINE_END_RE = re.compile(r"[ \t]+\n")
_SPACE_AT_LINE_START_RE = re.compile(r"\n[ \t]+")

# ------------------------------------------------------------------------------------------------ the cut
# A candidate sentence end: terminal punctuation, any closing quotes or brackets, then whitespace (not consumed).
_SENTENCE_END_RE = re.compile(r"[.!?][\"'’”)\]]*(?=\s)")
# Dotted letters: "U.S.", "e.g.", "a.k.a.".
_DOTTED_LETTERS_RE = re.compile(r"^(?:[A-Za-z]\.){2,}$")
# Tokens that end in a "." without ending a sentence (lowercase, with their dot).
_ABBREVIATIONS = frozenset(
    {
        "approx.",
        "al.",
        "cf.",
        "co.",
        "corp.",
        "dept.",
        "dr.",
        "e.g.",
        "est.",
        "fig.",
        "i.e.",
        "inc.",
        "jr.",
        "ltd.",
        "mr.",
        "mrs.",
        "ms.",
        "no.",
        "nos.",
        "op.",
        "pp.",
        "prof.",
        "rev.",
        "sr.",
        "st.",
        "ver.",
        "viz.",
        "vol.",
        "vs.",
        "jan.",
        "feb.",
        "mar.",
        "apr.",
        "jun.",
        "jul.",
        "aug.",
        "sep.",
        "sept.",
        "oct.",
        "nov.",
        "dec.",
    }
)
# What the cut drops at the end of the text it keeps.
_CUT_TAIL_CHARS = " \t\r\n,;:([{-–—"


def _strip_once(text: str) -> str:
    text = _CITATION_RE.sub("", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _CODE_TAG_RE.sub("", text)
    text = _UNCLOSED_CITATION_RE.sub("", text)
    text = _UNCLOSED_LINK_RE.sub(r"\1", text)
    return _UNCLOSED_LINK_NAME_RE.sub(r"\1", text)


def _normalise_spaces(text: str) -> str:
    text = _SPACE_RUN_RE.sub(" ", text)
    text = _SPACE_BEFORE_PUNCT_RE.sub(lambda m: m.group(1) or m.group(2), text)
    text = _SPACE_AT_LINE_END_RE.sub("\n", text)
    text = _SPACE_AT_LINE_START_RE.sub("\n", text)
    return text.strip()


def strip_markup(text: str) -> str:
    """``text`` without markdown links, ``(Citation: X)`` and ``<code>`` tags, spaces normalised where something
    was stripped (step 1 of the module docstring). A text without markup is returned as it is."""
    stripped = text
    # Each pass that changes the text shortens it, so the loop ends. The spaces are normalised in each pass, since
    # normalising can close markup ("[N](http://x . )" becomes the link "[N](http://x.)") or bring an unclosed one
    # to the end of the text.
    while True:
        again = _strip_once(stripped)
        if again == stripped:
            return stripped
        stripped = _normalise_spaces(again)


def _ends_sentence(text: str, end: int) -> bool:
    """Whether the punctuation run ``text[:end]`` closes is a sentence end (``end`` is followed by whitespace)."""
    rest = text[end:].lstrip()
    if rest and rest[0].islower():
        return False
    head = text[:end].rstrip("\"'’”)]")
    if not head.endswith("."):
        return True  # "!" or "?"
    if head.endswith(".."):
        return False  # an ellipsis
    start = max(head.rfind(" "), head.rfind("\t"), head.rfind("\n")) + 1
    token = head[start:].lstrip("\"'‘“([")
    if len(token) == 2 and token[0].isalpha():
        return False  # a single letter: an initial
    if _DOTTED_LETTERS_RE.match(token):
        return False
    return token.lower() not in _ABBREVIATIONS


def _cut(text: str, cap: int) -> str:
    """``text`` (longer than ``cap``) cut to at most ``cap`` characters (step 2 of the module docstring)."""
    window = text[: cap + 1]  # the character at ``cap`` tells whether ``cap`` itself is a word end
    floor = cap // 2
    for match in reversed(list(_SENTENCE_END_RE.finditer(window))):
        end = match.end()
        if end > cap:
            continue
        if end < floor:
            break
        if _ends_sentence(text, end):
            return text[:end]
    space = max(window.rfind(" "), window.rfind("\t"), window.rfind("\n"), window.rfind("\r"))
    if space <= 0:
        return ""
    return text[:space].rstrip(_CUT_TAIL_CHARS)


def cap_text(text: Any, cap: int) -> Tuple[str, bool, int]:
    """``(text, truncated, full_length)``: ``text`` without markup and cut to at most ``cap`` characters at a
    sentence or word end; whether it was cut; the length of the whole stripped text (module docstring)."""
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise ValueError(f"cap_text: the cap must be a positive int, not {cap!r}")
    if not isinstance(text, str):
        return "", False, 0
    stripped = strip_markup(text)
    full_length = len(stripped)
    if full_length <= cap:
        return stripped, False, full_length
    # A cut inside brackets can leave an unclosed "[" at the end, which a second strip would remove; stripping
    # the cut text keeps the function idempotent.
    return strip_markup(_cut(stripped, cap)), True, full_length


def capped(text: Any, cap: int) -> Any:
    """The capped form of ``text`` (``cap_text``'s first value) when it is a string; any other value as it is."""
    if not isinstance(text, str):
        return text
    return cap_text(text, cap)[0]
