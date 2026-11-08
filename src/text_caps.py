"""The caps on the texts the MISP -> Neo4j sync writes to the graph (2026-11-07).

MISP holds the text a source gives as the collector sent it; the graph holds a short form of it. Every cut of a
text bound for Neo4j is made here, on the sync's write path (``Neo4jClient``), never in a collector:

- ``CVE.description`` and ``Vulnerability.description``: ``CVE_DESCRIPTION_CAP`` (1,000 characters);
- the description of a ``Technique`` (sub-techniques included), ``Tactic``, ``ThreatActor``, ``Malware`` and
  ``Tool``: ``ENTITY_DESCRIPTION_CAP`` (500);
- CISA KEV's ``shortDescription`` as a node property of its own (``CVE.cisa_short_description``, which no writer
  sets): ``CISA_SHORT_DESCRIPTION_CAP`` (500).

``cap_text(text, cap, older_cut=False, emphasis=False)`` returns ``(text, truncated, full_length)``:

1. **Markup is stripped first.** A markdown link ``[Name](url)`` becomes ``Name``; every ``(Citation: X)`` is
   removed, also a run of several; the tags ``<code>`` and ``</code>`` are removed and the text between them is
   kept. Stripping repeats, with the normalising of spaces below, until nothing changes (at most
   ``_MAX_STRIP_PASSES`` passes, so a link inside a link's name is stripped too and a text of any length takes
   linear time). When something was stripped, the spaces it leaves are normalised: no run of spaces or tabs, no
   space or tab before a ``.``, ``,``, ``;``, ``:``, ``!`` or ``?`` that ends a word group (one followed by
   whitespace or the end, so ``.exe`` keeps its space) or before ``)``, none at the start or end of a line, and
   none at either end of the text. A text without markup keeps its spacing, and a ``[`` that opens no link
   (``ml[0..num_locks)``, ``[0, len)``, a kernel log's ``[    2.523161]``) is kept.
1a. **An older writer's cut** (``older_cut=True``, for the entity descriptions only): an older MISPWriter cut an
   ATT&CK description inside its markup and appended ``...`` (``misp_writer.sanitize_value``). At the end of such
   a text, an unclosed citation (also one cut inside the word "Citation": ``(Cita...``) or ``<code>`` tag is
   removed with the ``...``, and an unclosed link keeps its name without the ``...`` (``[PowerSp...`` becomes
   ``PowerSp``; ``[Empire](https://attack.mi...`` and ``[APT39]...`` become ``Empire`` and ``APT39``); the
   whitespace this leaves at the end goes. A link name holds no line break or parenthesis. Only the end of the
   text is read (its last ``_OLDER_CUT_TAIL`` characters), and only a text that ends in ``...``. A
   ``CVE`` or ``Vulnerability`` description never held ATT&CK markup, so its ``...`` copies (``rb_threads[c...``)
   keep their ``[``.
1b. **Emphasis** (``emphasis=True``, for the entity descriptions only): markdown bold ``**`` and the inline HTML
   tags ``<b>``, ``<strong>``, ``<i>`` and ``<em>`` with their closing tags are removed, the text between them
   kept, outside backtick code spans. A code span runs from a backtick to the next one, or to the end of the text
   for a backtick left open; its content is kept as it is (``/proc/<PID>/maps``, ``<DOMAIN>``, ``<script>``).
   This is part of the stripping of step 1 and repeats with it. Bullet lists are kept. A ``CVE`` or
   ``Vulnerability`` description keeps its ``**`` and tags: NVD writes ``** REJECT **`` and ``** DISPUTED **``,
   and a description of a flaw can name a tag or hold ``/**/``.
2. **A text longer than the cap is cut**, at the last sentence end within the cap that keeps at least half of
   it, otherwise at the last whitespace within the cap. A sentence end is ``.``, ``!`` or ``?`` (with any
   closing quotes or brackets after it) followed by whitespace and then by no lowercase letter. A ``.`` does not
   end a sentence after a known abbreviation (``e.g.``, ``i.e.``, ``vs.``, ``Inc.``, a month, ...), a single
   letter (``J.``), dotted letters (``U.S.``, ``a.k.a.``) or an ellipsis; a ``.`` inside a token (``v1.2``,
   ``1.2.3``, ``example.com``) is followed by no whitespace and so ends nothing. The cut never splits a word
   and never appends an ellipsis; separators the cut leaves at the end (whitespace, ``,``, ``;``, ``:``, an
   opening bracket, a dash) are dropped, and so is a last line that holds only a list marker (``*``, ``-`` or
   ``+``, after any spaces or tabs) left by a cut inside a bulleted list, with the separators before it. ``*`` is
   not a separator: a closing ``**`` stays. The kept text is a prefix of the stripped text (with ``older_cut``,
   of the stripped text before step 1a reads the cut's own end).
3. **``full_length``** is the length of the whole stripped text; ``truncated`` is whether the text was cut.

Edge cases, decided:

- ``None`` or a value that is not a string gives ``("", False, 0)``. A writer leaves such a value as it is.
- ``cap`` below 1 raises ``ValueError``: every cap is a constant of this module.
- A text whose first word is longer than the cap (a URL, an encoded blob) gives ``("", True, full_length)``:
  the cut never splits a word, so the graph gets no text and MISP keeps the whole.
- A text that is only markup gives ``("", False, 0)``.
- A text within the cap that ends in ``...`` (a MISP copy an older writer cut, such as an ATT&CK description cut
  at 255 characters) keeps its ``...`` unless step 1a removes markup there; over the cap, it is cut like any
  other text.

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
# Step 1b (``emphasis``): markdown bold and the inline HTML emphasis tags, removed outside backtick code spans.
_EMPHASIS_RE = re.compile(r"\*\*|</?(?:b|strong|i|em)>", re.IGNORECASE)
# A backtick code span: a backtick up to the next one, or to the end of the text for a backtick left open (a cut
# can fall inside a span, and what it keeps of the span is still code).
_CODE_SPAN_RE = re.compile(r"`[^`]*(?:`|\Z)")
# The markup an older writer's cut left unclosed before the "..." it appended (step 1a): a citation, also one cut
# inside the word "Citation" ("(Cita...") or inside a name with a year ("(Citation: Microsoft (20..."); a
# ``<code>`` tag; a link cut after its name ("[APT39]...") or inside its URL ("[Name](https://attack.mi...");
# a link name ("[Na..."), which holds no line break or parenthesis.
_OLDER_CUT_END = r"\.\.\.\Z"
_UNCLOSED_CITATION_RE = re.compile(
    r"\((?:Citation:[^()]*(?:\([^()]*\)[^()]*)*(?:\([^()]*)?|C(?:i(?:t(?:a(?:t(?:i(?:on?)?)?)?)?)?)?)" + _OLDER_CUT_END
)
_UNCLOSED_CODE_TAG_RE = re.compile(r"</?(?:c(?:o(?:d(?:e)?)?)?)?" + _OLDER_CUT_END, re.IGNORECASE)
_UNCLOSED_LINK_RE = re.compile(r"\[([^\[\]\n]*)\](?:\([^()\s]*)?" + _OLDER_CUT_END)
_UNCLOSED_LINK_NAME_RE = re.compile(r"\[([^\[\]\n()]*)" + _OLDER_CUT_END)
# Step 1a reads this many characters at the end of a text: a citation or a link name is far shorter.
_OLDER_CUT_TAIL = 300
# Step 1 repeats at most this often: each pass strips one level of nested links, and no source nests deeper.
_MAX_STRIP_PASSES = 16

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
# A last line that holds only a list marker: what a cut inside a bulleted list leaves ("...\n*", "...\n  *").
_MARKER_LINE_END_RE = re.compile(r"(?:\A|\n)[ \t]*[*+-]\Z")


def _strip_emphasis(text: str) -> str:
    """``text`` without ``**`` and the inline HTML emphasis tags outside backtick code spans (step 1b)."""
    if "`" not in text:
        return _EMPHASIS_RE.sub("", text)
    parts = []
    start = 0
    for span in _CODE_SPAN_RE.finditer(text):
        parts.append(_EMPHASIS_RE.sub("", text[start : span.start()]))
        parts.append(span.group())
        start = span.end()
    parts.append(_EMPHASIS_RE.sub("", text[start:]))
    return "".join(parts)


def _strip_once(text: str, emphasis: bool = False) -> str:
    text = _CITATION_RE.sub("", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _CODE_TAG_RE.sub("", text)
    return _strip_emphasis(text) if emphasis else text


def _normalise_spaces(text: str) -> str:
    text = _SPACE_RUN_RE.sub(" ", text)
    text = _SPACE_BEFORE_PUNCT_RE.sub(lambda m: m.group(1) or m.group(2), text)
    text = _SPACE_AT_LINE_END_RE.sub("\n", text)
    text = _SPACE_AT_LINE_START_RE.sub("\n", text)
    return text.strip()


def _strip_older_cut(text: str) -> str:
    """``text`` without the markup an older writer's cut left unclosed before its ``...`` (step 1a)."""
    # Each round that changes the text shortens it and reads only its end, so the loop ends in linear time; it
    # repeats because a removal can bring an earlier cut construct to the end ("[a b...(Cit..."), which makes
    # the result idempotent.
    while text.endswith("..."):
        head, tail = text[:-_OLDER_CUT_TAIL], text[-_OLDER_CUT_TAIL:]
        new = _UNCLOSED_CITATION_RE.sub("", tail)
        new = _UNCLOSED_CODE_TAG_RE.sub("", new)
        new = _UNCLOSED_LINK_RE.sub(r"\1", new)
        new = _UNCLOSED_LINK_NAME_RE.sub(r"\1", new)
        if new == tail:
            break
        # The removals are at the end: the only space they leave is there.
        text = (head + new).rstrip()
    return text


def strip_markup(text: str, older_cut: bool = False, emphasis: bool = False) -> str:
    """``text`` without markdown links, ``(Citation: X)`` and ``<code>`` tags, spaces normalised where something
    was stripped (step 1 of the module docstring); with ``older_cut``, also without the markup an older writer's
    cut left unclosed at the end (step 1a); with ``emphasis``, also without ``**`` and the inline HTML emphasis
    tags outside backtick code spans (step 1b). A text without markup is returned as it is."""
    stripped = text
    # The spaces are normalised in each pass that changed the text, since normalising can close markup
    # ("[N](http://x . )" becomes the link "[N](http://x.)").
    for _ in range(_MAX_STRIP_PASSES):
        again = _strip_once(stripped, emphasis)
        if again == stripped:
            break
        stripped = _normalise_spaces(again)
    return _strip_older_cut(stripped) if older_cut else stripped


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
    out = text[:space].rstrip(_CUT_TAIL_CHARS)
    # A cut inside a bulleted list can keep a last line that holds only the next item's marker.
    while _MARKER_LINE_END_RE.search(out):
        out = _MARKER_LINE_END_RE.sub("", out).rstrip(_CUT_TAIL_CHARS)
    return out


def cap_text(text: Any, cap: int, older_cut: bool = False, emphasis: bool = False) -> Tuple[str, bool, int]:
    """``(text, truncated, full_length)``: ``text`` without markup and cut to at most ``cap`` characters at a
    sentence or word end; whether it was cut; the length of the whole stripped text (module docstring).
    ``older_cut``: the text may be a copy an older writer cut inside markup (step 1a; the entity descriptions).
    ``emphasis``: ``**`` and the inline HTML emphasis tags are markup too (step 1b; the entity descriptions)."""
    if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
        raise ValueError(f"cap_text: the cap must be a positive int, not {cap!r}")
    if not isinstance(text, str):
        return "", False, 0
    stripped = strip_markup(text, older_cut, emphasis)
    full_length = len(stripped)
    if full_length <= cap:
        return stripped, False, full_length
    out = _cut(stripped, cap)
    # A cut can end just after a "..." of the text itself ("word [alpha beta... gamma"); step 1a reads that end
    # as it would when the capped text is capped again, which keeps the function idempotent.
    return (_strip_older_cut(out) if older_cut else out), True, full_length


def capped(text: Any, cap: int, older_cut: bool = False, emphasis: bool = False) -> Any:
    """The capped form of ``text`` (``cap_text``'s first value) when it is a string; any other value as it is."""
    if not isinstance(text, str):
        return text
    return cap_text(text, cap, older_cut, emphasis)[0]
