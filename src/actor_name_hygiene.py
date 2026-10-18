"""Threat-actor name hygiene — pure string helpers, no I/O, no Neo4j.

Why this module exists
----------------------
AlienVault OTX pulses carry a free-text ``adversary`` field and MISP
``threat-actor`` galaxy tags are hand-typed. In the deployed graph that
produced three kinds of junk ``ThreatActor`` nodes:

1. **Composite names** — several actors in one string
   (``"apt-c-13, sandworm, frozenbarents"``, ``"head mare and twelve"``,
   ``"lockbit, cl0p, refined kitten, wicked panda, fancy bear"``).
2. **Generic descriptions** that are not names at all
   (``"multiple russian state-backed groups"``, ``"russian cybercrime groups"``,
   ``"russia-nexus apt"``), and country or state names standing beside the
   actor (``"apt37, north korea"``).
3. Alias-duplicates of a canonical MITRE actor (``"reddelta"`` next to
   ``"mustang panda"``) — handled downstream by
   ``enrichment_jobs.merge_alias_duplicate_actors``, not here.

This module fixes (1) and (2) at the string level so the collectors / the
MISP→Neo4j parser can call :func:`clean_actor_names` before any MERGE.
Names reaching the graph are later lower-cased, NFC-normalised and trimmed
by ``node_identity.canonicalize_merge_key`` — this module therefore keeps
the caller's case and only trims / NFC-normalises / collapses whitespace.

Design rule: **prefer not splitting / not flagging over doing so wrongly**.
A real actor name that slips through unchanged is a cosmetic problem; a real
actor name that gets split in two or dropped is data loss. Every list below
is a module constant so it can be tuned without touching the logic.

Public API
----------
``split_composite_actor_name(name) -> list[str]``
``is_generic_actor_name(name) -> bool``
``clean_actor_names(name) -> list[str]``
``strip_trailing_parenthetical(name) -> str``
"""

from __future__ import annotations

import re
import unicodedata
from typing import List

from node_identity import is_placeholder_name

# ---------------------------------------------------------------------------
# Splitting rules
# ---------------------------------------------------------------------------

# Hard list separators — always split. ASCII comma / semicolon plus their
# full-width and ideographic forms (NFC does not fold those to ASCII, and
# CJK-language pulses do emit them). A slash splits ONLY when it has
# whitespace on both sides (``"apt28 / fancy bear"``); a bare ``a/b`` is
# left alone because it is more likely a single token than a list.
_LIST_SEPARATOR_RE = re.compile(r"[,;，；、]|\s+/\s+")

# Word separators — ``" and "`` / ``" & "`` with whitespace on both sides,
# case-insensitive. ``"at&t"`` / ``"c&c"`` (no whitespace) never match.
_WORD_SEPARATOR_RE = re.compile(r"\s+(?:and|&)\s+", re.IGNORECASE)

# Oxford-comma residue: after a comma split a fragment may start or end with
# a dangling conjunction (``"lockbit, cl0p, and fancy bear"`` →
# ``"and fancy bear"``; ``"apt28 and, apt29"`` → ``"apt28 and"``). Strip it;
# a fragment that IS just the conjunction becomes empty and is dropped.
_LEADING_CONJUNCTION_RE = re.compile(r"^(?:and|&|aka|a\.k\.a\.?|also known as)(?:\s+|$)", re.IGNORECASE)
_TRAILING_CONJUNCTION_RE = re.compile(r"(?:^|\s+)(?:and|&)$", re.IGNORECASE)

# Minimum length (characters, after trim) of EACH side of an ``and`` / ``&``
# split. Shorter sides (``"a and b"``) are not names and the split is refused.
AND_SPLIT_MIN_SIDE_LEN = 3

# Names starting with one of these prefixes are campaign / operation titles
# where ``and`` is part of the title (``"operation search and destroy"``).
# Compared lower-cased, after whitespace collapse. Tunable.
AND_SPLIT_PROTECTED_PREFIXES: tuple = ("operation ", "op. ", "op ")

# If EITHER side of an ``and`` / ``&`` split is one of these (lower-cased,
# trimmed) the split is refused — they are halves of idioms / brand-like
# names, not actor names. Deliberately small; tunable.
AND_SPLIT_PROTECTED_SIDES: frozenset = frozenset(
    "black white command control search destroy hack leak cut paste smash grab "
    "hit run cat mouse hide seek trial error rock roll salt pepper".split()
)

_WHITESPACE_RE = re.compile(r"\s+")

# ---------------------------------------------------------------------------
# Generic-name rules
# ---------------------------------------------------------------------------

# (a) Exact phrases (lower-cased, whitespace-collapsed) that are never a
# name. ``node_identity._REJECTED_PLACEHOLDER_NAMES`` (``"unknown"``,
# ``"apt"``, ``"threat actor"``, ``"n/a"`` …) is consulted as well via
# ``is_placeholder_name`` so the two filters cannot drift apart.
GENERIC_ACTOR_PHRASES: frozenset = frozenset(
    {
        "and",
        "&",
        "or",
        "other",
        "others",
        "and others",
        "etc",
        "etc.",
        "et al",
        "et al.",
        "more",
        "and more",
        "various",
        "multiple",
        "several",
        "many",
        "misc",
        "miscellaneous",
        "team",
        "group",
        "groups",
        "gang",
        "gangs",
        "crew",
        "crews",
        "actors",
        "hackers",
        "hacker group",
        "hacking group",
        "hacktivist",
        "hacktivists",
        "cybercriminal",
        "cybercriminals",
        "cyber criminals",
        "criminals",
        "criminal group",
        "ransomware group",
        "ransomware gang",
        "ransomware groups",
        "ransomware gangs",
        "ransomware operators",
        "ransomware affiliates",
        "apt groups",
        "apts",
        "nation state",
        "nation-state",
        "state actor",
        "state actors",
        "state-sponsored",
        "state sponsored",
        "initial access broker",
        "initial access brokers",
        "insider",
        "insiders",
        "malicious insider",
        "malicious insiders",
        "script kiddie",
        "script kiddies",
        "unattributed",
        "unidentified",
        "not attributed",
        "no attribution",
        "none known",
    }
)

# (b1) A name whose FIRST word is one of these is a description
# (``"multiple russian state-backed groups"``, ``"unknown apt"``,
# ``"various hacktivists"``). No real actor name starts with these.
GENERIC_LEADING_WORDS: frozenset = frozenset(
    "multiple various several numerous many unknown unnamed unidentified unspecified "
    "unattributed undisclosed other others miscellaneous assorted".split()
)

# (b2) A name whose LAST word is one of these is a description
# (``"russian hackers"``, ``"ransomware groups"``, ``"state-backed groups"``,
# ``"lockbit affiliates"``). NOTE: the singular ``"group"`` / ``"team"`` are
# NOT here — ``"lazarus group"``, ``"gorgon group"``, ``"sandworm team"`` are
# real names. Singular ``"group"`` is only generic through rule (b4).
# ``"brokers"`` is deliberately absent: ``"the shadow brokers"`` is a real
# actor (``"initial access brokers"`` is caught by (a) / (b4) instead).
GENERIC_LAST_WORDS: frozenset = frozenset(
    "groups actor actors hackers hacktivists cybercriminal cybercriminals criminals "
    "gangs crews operators affiliates attackers adversaries apts insiders scammers "
    "spammers fraudsters extortionists threats".split()
)

# (b3) Regex signals that only occur in descriptions. Matched against the
# lower-cased, whitespace-collapsed name. Each is a sponsorship / origin
# qualifier no proper name contains: ``"russia-nexus apt"``,
# ``"china nexus actor"``, ``"iran-affiliated"``, ``"pro-russia aligned"``,
# ``"kremlin-linked"``, ``"china-based"``, ``"state-backed"``.
# ``"nexus zeta"`` (a real persona) does NOT match: the bare word needs a
# nationality in front of it.
GENERIC_SIGNAL_PATTERNS: tuple = (
    re.compile(r"\b[a-z]+-nexus\b"),
    re.compile(
        r"\b(?:china|chinese|russia|russian|iran|iranian|dprk|korea|korean|north korea|"
        r"vietnam|india|pakistan|turkey|israel|belarus|syria|ukraine)[ -]nexus\b"
    ),
    re.compile(r"\b[a-z]+-based\b"),
    re.compile(
        r"\b(?:state|government|nation|kremlin|gru|fsb|svr|mss|pla|irgc|mois)[ -]"
        r"(?:sponsored|backed|aligned|affiliated|linked|associated|directed|run)\b"
    ),
    re.compile(r"\b(?:affiliated|aligned|sponsored|backed|linked|associated)\b"),
)

# (b4) Descriptor vocabulary. A MULTI-word name made ENTIRELY of descriptor
# words is a description (``"ransomware group"``, ``"chinese apt"``,
# ``"iranian threat actor"``, ``"russian cyber group"``). One non-descriptor
# word anywhere (``"lazarus"``, ``"gorgon"``, ``"sandworm"``, ``"gentlemen"``,
# ``"nasir"``, ``"8200"``) keeps the name. Country NOUNS (``"russia"``,
# ``"china"``) are intentionally NOT descriptors, so a name that contains one
# (``"cyber army of russia reborn"``) is kept; a name that IS a country or
# state is generic through rule (c). Words are split on whitespace AND
# hyphen, so ``"state-backed"`` is the two descriptors ``state`` + ``backed``,
# ``"pro-russian"`` is ``pro`` + ``russian``, while ``"apt-c-13"`` contains the
# non-descriptors ``c`` + ``13``.
GENERIC_DESCRIPTOR_WORDS: frozenset = frozenset(
    # quantity / unknown-ness / hedges
    "multiple various several numerous many unknown unnamed unidentified unspecified "
    "unattributed undisclosed other others new emerging suspected alleged likely "
    "possible possibly potential unconfirmed malicious sophisticated advanced persistent "
    # kind of actor
    "ransomware hacking hacker hackers hacktivist hacktivists cybercrime cybercriminal "
    "cybercriminals criminal criminals crimeware apt apts threat threats espionage cyber "
    "cyberespionage malware phishing scam scammer scammers fraud fraudsters extortion "
    "extortionists initial access broker brokers iab iabs insider insiders spammer "
    "spammers mercenary mercenaries contractor contractors "
    # sponsorship / alignment
    "state nation sponsored backed aligned affiliated linked associated government "
    "military intelligence nexus based pro anti "
    # nationality / region ADJECTIVES (not nouns)
    "russian chinese iranian north south korean dprk vietnamese indian pakistani turkish "
    "israeli palestinian ukrainian belarusian syrian lebanese american european asian "
    "african middle eastern east west western southeast latin brazilian nigerian arab "
    "arabic persian soviet "
    # structural nouns
    "group groups actor actors gang gangs crew crews team teams operator operators "
    "operation operations campaign campaigns collective collectives entity entities "
    "adversary adversaries attacker attackers affiliate affiliates unit units cell cells "
    "organization organizations organisation organisations org orgs syndicate syndicates "
    "faction factions network networks forum forums community communities persona "
    "personas individual individuals "
    # glue
    "and or of the a an with by from in to for &".split()
)


def _names(text: str) -> frozenset:
    """The names of a ``|``-separated list (a name may contain spaces)."""
    return frozenset(n.strip() for n in text.split("|") if n.strip())


# (c) Country and state names, and nationality adjectives, as the WHOLE name (2026-10-18). They
# say where an actor is said to be from, never which actor it is: OTX adversary fields list
# ``"apt37, north korea"``, ``"lazarus group; dprk"``. A name that merely CONTAINS one stays a name
# (``"cyber army of russia reborn"``, ``"anonymous sudan"``, ``"syrian electronic army"``). Compared
# lower-cased, whitespace-collapsed, edge punctuation stripped, without apostrophes (``"people's"`` =
# ``"peoples"``), with dots and hyphens read as spaces and a run of single letters joined (``"u.s."`` =
# ``"us"``, ``"n. korea"`` = ``"n korea"``, ``"north-korea"`` = ``"north korea"``), ``&`` as ``and`` and a
# leading ``"the "`` ignored (``"the netherlands"``). No entry of either list is a name the canonical
# threat-actor reference resolves (tests/test_actor_name_hygiene.py checks it). Rule (c) does not
# consult the reference: an actor whose whole name is a country or state (a group named ``"cuba"``) is
# kept by taking that name out of these lists, not by adding it to the reference.
#
# COUNTRY_AND_STATE_NAMES: the ISO 3166-1 short names (natural word order; accented names also
# without accents), the long and short forms of states, constituent countries, disputed and occupied
# territories, former states, and the state forms that ISO's inverted names ("korea, republic of")
# leave after the comma split.
COUNTRY_AND_STATE_NAMES: frozenset = _names(
    # ISO 3166-1 short names
    "afghanistan|åland islands|aland islands|albania|algeria|american samoa|andorra|angola|anguilla|antarctica|"
    "antigua and barbuda|argentina|armenia|aruba|australia|austria|azerbaijan|bahamas|bahrain|bangladesh|barbados|"
    "belarus|belgium|belize|benin|bermuda|bhutan|bolivia|plurinational state of bolivia|bonaire|sint eustatius|saba|"
    "bosnia and herzegovina|botswana|bouvet island|brazil|british indian ocean territory|brunei darussalam|brunei|"
    "bulgaria|burkina faso|burundi|cabo verde|cape verde|cambodia|cameroon|canada|cayman islands|"
    "central african republic|chad|chile|china|christmas island|cocos (keeling) islands|cocos islands|colombia|"
    "comoros|congo|republic of the congo|democratic republic of the congo|cook islands|costa rica|côte d'ivoire|"
    "cote d'ivoire|ivory coast|croatia|cuba|curaçao|curacao|cyprus|czechia|czech republic|denmark|djibouti|dominica|"
    "dominican republic|ecuador|egypt|el salvador|equatorial guinea|eritrea|estonia|eswatini|swaziland|ethiopia|"
    "falkland islands|falkland islands (malvinas)|faroe islands|fiji|finland|france|french guiana|french polynesia|"
    "french southern territories|gabon|gambia|georgia|germany|ghana|gibraltar|greece|greenland|grenada|guadeloupe|"
    "guam|guatemala|guernsey|guinea|guinea-bissau|guyana|haiti|heard island and mcdonald islands|holy see|vatican|"
    "vatican city|honduras|hong kong|hungary|iceland|india|indonesia|iran|islamic republic of iran|persia|iraq|"
    "ireland|republic of ireland|"
    "isle of man|israel|state of israel|italy|jamaica|japan|jersey|jordan|kazakhstan|kenya|kiribati|korea|"
    "north korea|south korea|n korea|s korea|democratic people's republic of korea|republic of korea|dpr korea|"
    "kuwait|kyrgyzstan|lao people's democratic republic|lao pdr|laos|latvia|lebanon|lesotho|liberia|libya|"
    "liechtenstein|lithuania|luxembourg|"
    "macao|macau|north macedonia|macedonia|former yugoslav republic of macedonia|madagascar|malawi|malaysia|maldives|"
    "mali|malta|marshall islands|"
    "martinique|mauritania|mauritius|mayotte|mexico|micronesia|federated states of micronesia|moldova|"
    "republic of moldova|monaco|mongolia|montenegro|montserrat|morocco|mozambique|myanmar|burma|namibia|nauru|nepal|"
    "netherlands|kingdom of the netherlands|holland|new caledonia|new zealand|nicaragua|niger|nigeria|niue|"
    "norfolk island|northern mariana islands|norway|oman|pakistan|palau|palestine|state of palestine|panama|"
    "papua new guinea|paraguay|peru|philippines|pitcairn|poland|portugal|puerto rico|qatar|réunion|reunion|romania|"
    "russia|russian federation|rwanda|saint barthélemy|saint barthelemy|saint helena|ascension|tristan da cunha|"
    "saint kitts and nevis|saint lucia|st lucia|saint martin|saint pierre and miquelon|"
    "saint vincent and the grenadines|samoa|san marino|sao tome and principe|são tomé and príncipe|saudi arabia|"
    "kingdom of saudi arabia|"
    "senegal|serbia|seychelles|sierra leone|singapore|sint maarten|slovakia|slovenia|solomon islands|somalia|"
    "south africa|south georgia and the south sandwich islands|south sudan|spain|sri lanka|sudan|suriname|"
    "svalbard and jan mayen|sweden|switzerland|syria|syrian arab republic|taiwan|tajikistan|tanzania|"
    "united republic of tanzania|thailand|timor-leste|east timor|togo|tokelau|tonga|trinidad and tobago|tunisia|"
    "türkiye|turkiye|turkey|republic of türkiye|republic of turkiye|republic of turkey|turkmenistan|"
    "turks and caicos islands|tuvalu|uganda|ukraine|united arab emirates|"
    "united kingdom|united kingdom of great britain and northern ireland|united kingdom of great britain|"
    "great britain|britain|england|scotland|wales|northern ireland|united states|united states of america|america|"
    "united states minor outlying islands|uruguay|uzbekistan|vanuatu|venezuela|bolivarian republic of venezuela|"
    "viet nam|vietnam|socialist republic of viet nam|socialist republic of vietnam|virgin islands|"
    "british virgin islands|us virgin islands|wallis and futuna|western sahara|yemen|"
    "zambia|zimbabwe|"
    # short state forms
    "dprk|prc|roc|rok|drc|ksa|usa|us|uk|uae|ussr|people's republic of china|republic of china|"
    # disputed and occupied territories, former states
    "gaza|gaza strip|west bank|crimea|kosovo|abkhazia|south ossetia|transnistria|northern cyprus|donbas|donbass|"
    "tibet|xinjiang|soviet union|yugoslavia|czechoslovakia|"
    # what ISO's inverted names leave after the comma split ("iran, islamic republic of")
    "republic of|islamic republic of|democratic people's republic of|united republic of|democratic republic of the|"
    "state of|federated states of|plurinational state of|bolivarian republic of|province of china|kingdom of the|"
    "former yugoslav republic of|"
)

# Nationality adjectives on their own (``"russian"``, ``"north korean"``). As a
# word inside a longer name they are rule (b4)'s descriptors, which needs two
# or more words; on their own they are generic through rule (c).
NATIONALITY_ADJECTIVES: frozenset = _names(
    "afghan|albanian|algerian|american|angolan|argentine|argentinian|armenian|australian|austrian|azerbaijani|"
    "azeri|bahraini|bangladeshi|belarusian|belarussian|belgian|bolivian|bosnian|brazilian|british|bulgarian|burmese|"
    "cambodian|"
    "cameroonian|canadian|chilean|chinese|colombian|congolese|croatian|cuban|cypriot|czech|danish|dutch|ecuadorian|"
    "egyptian|emirati|english|eritrean|estonian|ethiopian|filipino|finnish|french|georgian|german|ghanaian|greek|"
    "guatemalan|haitian|honduran|hungarian|icelandic|indian|indonesian|iranian|iraqi|irish|israeli|italian|jamaican|"
    "japanese|jordanian|kazakh|kazakhstani|kenyan|korean|north korean|south korean|kosovar|kurdish|kuwaiti|kyrgyz|"
    "lao|"
    "laotian|latvian|lebanese|libyan|lithuanian|macedonian|malaysian|maltese|mexican|moldovan|mongolian|montenegrin|"
    "moroccan|nepalese|nepali|nicaraguan|nigerian|norwegian|omani|pakistani|palestinian|panamanian|paraguayan|"
    "persian|peruvian|philippine|polish|portuguese|qatari|romanian|russian|rwandan|saudi|scottish|senegalese|serbian|"
    "singaporean|slovak|slovenian|somali|south african|spanish|sri lankan|sudanese|swedish|swiss|syrian|taiwanese|"
    "tajik|tanzanian|thai|tunisian|turkish|turkmen|ugandan|ukrainian|uruguayan|uzbek|venezuelan|vietnamese|welsh|"
    "yemeni|zambian|zimbabwean|soviet|"
)


_APOSTROPHES = "'\u2018\u2019\u02bc"


def _geo_key(name: str) -> str:
    """The form rule (c) compares: lower-case, no apostrophes, dots and hyphens as spaces, ``&`` as
    ``and``, whitespace collapsed, a run of single letters joined (``"u s a"`` = ``"usa"``), a
    leading ``"the "`` dropped."""
    text = name.lower()
    for mark in _APOSTROPHES:
        text = text.replace(mark, "")
    words: List[str] = []
    letters = ""
    for word in text.replace(".", " ").replace("-", " ").replace("&", " and ").split():
        if len(word) == 1 and word.isalpha():
            letters += word
            continue
        if letters:
            words.append(letters)
            letters = ""
        words.append(word)
    if letters:
        words.append(letters)
    key = " ".join(words)
    return key[4:] if key.startswith("the ") else key


_GEOPOLITICAL_KEYS: frozenset = frozenset(_geo_key(n) for n in COUNTRY_AND_STATE_NAMES | NATIONALITY_ADJECTIVES)


def _is_geopolitical_name(name: str) -> bool:
    return _geo_key(name) in _GEOPOLITICAL_KEYS


_WORD_SPLIT_RE = re.compile(r"[\s\-]+")
_EDGE_PUNCT = " .!?\"'`()[]{}"

# The inverted "Korea, North" / "Korea, South" (rule (c)), followed by a list separator or the end.
_KOREA_INVERTED_RE = re.compile(
    r"\b(?P<korea>korea)\s*[,，]\s*(?P<side>north|south)\b(?=\s*(?:[,;，；、]|$))", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise(name: str) -> str:
    """NFC-normalise, collapse any Unicode whitespace run to one space, trim."""
    return _WHITESPACE_RE.sub(" ", unicodedata.normalize("NFC", name)).strip()


# 2026-10 audit: "Name (Alias)" is the dominant composite form on the hosted graph (27 of 815
# non-MITRE actors: "apt28 (fancy bear)", "kimsuky (apt43)", "apt-c-00 (ocean lotus)"). Keep the
# head; the parenthetical is an alias the MITRE alias merge resolves when it is one.
# Whitespace before "(" and a letter inside are required: "NoName057(16)" is one group's real name.
_TRAILING_PAREN_RE = re.compile(r"^(?P<head>.+?)\s+\((?P<inner>[^()]*[A-Za-z][^()]*)\)$")


def strip_trailing_parenthetical(fragment: str) -> str:
    """``"Name (Alias)"`` -> ``"Name"``; anything else unchanged. When the head is a country or state
    and the parenthetical is not (rule (c)), the parenthetical is the name (2026-10-18):
    ``"North Korea (APT37)"`` -> ``"APT37"``."""
    m = _TRAILING_PAREN_RE.match(fragment)
    if not m:
        return fragment
    head = m.group("head").strip()
    inner = m.group("inner").strip()
    if (
        len(inner) > 1
        and _is_geopolitical_name(head.strip(_EDGE_PUNCT))
        and not _is_geopolitical_name(inner.strip(_EDGE_PUNCT))
    ):
        return inner
    return head if len(head) > 1 else fragment


def _try_and_split(fragment: str) -> List[str]:
    """Split ``fragment`` on ``" and "`` / ``" & "`` if every guard passes,
    else return ``[fragment]`` unchanged.

    Guards (all must hold for the split to happen):
      * at least one separator present;
      * the name does not start with an ``AND_SPLIT_PROTECTED_PREFIXES`` entry;
      * the name is not a country or state (``"trinidad and tobago"``, rule (c));
      * every resulting side is >= ``AND_SPLIT_MIN_SIDE_LEN`` chars;
      * no side (lower-cased) is in ``AND_SPLIT_PROTECTED_SIDES``.
    """
    sides = [s.strip() for s in _WORD_SEPARATOR_RE.split(fragment)]
    if len(sides) < 2:
        return [fragment]
    if fragment.lower().startswith(AND_SPLIT_PROTECTED_PREFIXES):
        return [fragment]
    # 2026-10-18: a country name with "and" ("bosnia and herzegovina") is one name, which rule (c)
    # then drops, not two names.
    if _is_geopolitical_name(fragment.strip(_EDGE_PUNCT)):
        return [fragment]
    for side in sides:
        if len(side) < AND_SPLIT_MIN_SIDE_LEN or side.lower() in AND_SPLIT_PROTECTED_SIDES:
            return [fragment]
        # 2026-10 audit: never split inside a parenthetical —
        # "mois (ministry of intelligence and security)" produced a ThreatActor "security)".
        if side.count("(") != side.count(")"):
            return [fragment]
    return sides


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def split_composite_actor_name(name: str) -> List[str]:
    """Split a composite actor string into its individual actor names.

    Rules, in order:

    1. NFC-normalise, collapse whitespace, trim. Non-string input → ``[]``.
    2. Split on hard list separators: ``,`` ``;`` (ASCII, full-width,
       ideographic) and ``/`` **only when surrounded by whitespace**.
    3. Strip a dangling conjunction left by an Oxford comma
       (``"and fancy bear"`` → ``"fancy bear"``).
    4. Split each fragment on ``" and "`` / ``" & "`` (case-insensitive,
       whitespace on both sides) ONLY when every side is at least
       ``AND_SPLIT_MIN_SIDE_LEN`` chars, no side is in
       ``AND_SPLIT_PROTECTED_SIDES`` and the fragment does not start with an
       ``AND_SPLIT_PROTECTED_PREFIXES`` entry. When unsure, the fragment is
       kept whole — ``"at&t"`` / ``"c&c"`` (no whitespace) are never split.
    5. Drop empty and 1-character fragments.
    6. When the name WAS split (more than one fragment survived step 5),
       drop fragments that are generic per :func:`is_generic_actor_name`
       (``"lockbit, cl0p and others"`` → ``["lockbit", "cl0p"]``).
       An unsplit (plain) name is returned as-is — ``["<trimmed name>"]`` —
       even if it is generic; use :func:`clean_actor_names` to reject it.
    7. De-duplicate case-insensitively, preserving first-seen order and the
       first-seen spelling.

    Case is preserved — ``canonicalize_merge_key`` lower-cases at MERGE time.
    """
    if not isinstance(name, str):
        return []
    normalised = _normalise(name)
    if not normalised:
        return []
    # 2026-10-18: the inverted "Korea, North" is one country name, not "Korea" and "North".
    normalised = _KOREA_INVERTED_RE.sub(lambda m: f"{m.group('side')} {m.group('korea')}", normalised)

    fragments: List[str] = []
    for raw in _LIST_SEPARATOR_RE.split(normalised):
        frag = _LEADING_CONJUNCTION_RE.sub("", raw.strip())
        frag = _TRAILING_CONJUNCTION_RE.sub("", frag).strip()
        if not frag:
            continue
        # Strip BEFORE the and-split (so "mois (ministry of intelligence and security)" is never
        # split inside the parenthesis) and AGAIN on every side after it (Bugbot on PR #144:
        # "apt28 (fancy bear) and apt29 (cozy bear)" kept both parentheticals).
        frag = strip_trailing_parenthetical(frag)
        fragments.extend(strip_trailing_parenthetical(side) for side in _try_and_split(frag))

    fragments = [f for f in (f.strip() for f in fragments) if len(f) > 1]

    if len(fragments) > 1:
        fragments = [f for f in fragments if not is_generic_actor_name(f)]

    seen: set = set()
    out: List[str] = []
    for frag in fragments:
        key = frag.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(frag)
    return out


def is_generic_actor_name(name: str) -> bool:
    """Return True when ``name`` is a *description* of an actor rather than
    a name (``"multiple russian state-backed groups"``, ``"russian hackers"``,
    ``"russia-nexus apt"``, ``"unknown"``).

    Conservative by design — a real name that merely CONTAINS a descriptor
    token stays a name: ``"gorgon group"``, ``"lazarus group"``,
    ``"sandworm team"``, ``"wizard spider"``, ``"night dragon"``,
    ``"the gentlemen"``, ``"nasir security"``, ``"apt28"``, ``"unit 8200"``,
    ``"the shadow brokers"``.

    Rules (any one → generic):
      (a)  exact phrase in ``GENERIC_ACTOR_PHRASES`` or a placeholder per
           ``node_identity.is_placeholder_name`` (``"unknown"``, ``"apt"`` …);
      (b1) first word in ``GENERIC_LEADING_WORDS`` (``multiple``, ``various``,
           ``unknown``, ``unnamed``, ``several`` …);
      (b2) last word in ``GENERIC_LAST_WORDS`` (``groups``, ``actors?``,
           ``hackers``, ``hacktivists``, ``cybercriminals?`` …) — singular
           ``group`` / ``team`` are deliberately NOT in that set;
      (b3) a ``GENERIC_SIGNAL_PATTERNS`` regex hits (``<x>-nexus``,
           ``<x>-based``, ``state-sponsored``, ``affiliated``, ``aligned`` …);
      (b4) the name has >= 2 words and EVERY word (split on whitespace and
           hyphen) is in ``GENERIC_DESCRIPTOR_WORDS`` (``"ransomware group"``,
           ``"chinese apt"``, ``"apt groups"``) — one unknown word keeps it;
      (c)  the whole name is a country or state (``COUNTRY_AND_STATE_NAMES``:
           ``"north korea"``, ``"dprk"``, ``"u.s."``, ``"russian federation"``)
           or a nationality adjective (``NATIONALITY_ADJECTIVES``: ``"russian"``,
           ``"north korean"``) — a name that contains one stays a name
           (``"cyber army of russia reborn"``).

    Single-word names are only generic through rules (a) and (c): ``"apt28"``,
    ``"sandworm"``, ``"play"`` are names (or at least not provably not).
    Non-string input → True (not a name).
    """
    if not isinstance(name, str):
        return True
    canonical = _normalise(name).lower()
    if not canonical:
        return True
    # (a) exact phrases + shared placeholder sentinel set.
    if canonical in GENERIC_ACTOR_PHRASES or is_placeholder_name(canonical):
        return True

    core = canonical.strip(_EDGE_PUNCT)
    if not core:
        return True
    if core in GENERIC_ACTOR_PHRASES or is_placeholder_name(core):
        return True
    # (c) a country or state, or a nationality adjective, as the whole name.
    if _is_geopolitical_name(canonical) or _is_geopolitical_name(core):
        return True
    space_words = core.split(" ")

    # (b1) leading quantifier / unknown-ness word.
    if space_words[0] in GENERIC_LEADING_WORDS:
        return True
    # (b2) plural / role noun as the last word.
    if space_words[-1] in GENERIC_LAST_WORDS:
        return True
    # (b3) sponsorship / origin qualifiers.
    for pattern in GENERIC_SIGNAL_PATTERNS:
        if pattern.search(core):
            return True
    # (b4) multi-word name made only of descriptor words.
    words = [w for w in _WORD_SPLIT_RE.split(core) if w]
    if len(words) >= 2 and all(w in GENERIC_DESCRIPTOR_WORDS for w in words):
        return True
    return False


def clean_actor_names(name: str) -> List[str]:
    """Split a (possibly composite) actor string and drop generic fragments.

    Convenience wrapper = :func:`split_composite_actor_name` followed by
    :func:`is_generic_actor_name` on every fragment, so a plain generic name
    (``"russian cybercrime groups"``) yields ``[]`` and a composite with junk
    (``"apt28 and russian hackers"``) yields ``["apt28"]``. This is the entry
    point collectors / the MISP→Neo4j parser should call before MERGE.
    """
    return [n for n in split_composite_actor_name(name) if not is_generic_actor_name(n)]


__all__ = [
    "AND_SPLIT_MIN_SIDE_LEN",
    "AND_SPLIT_PROTECTED_PREFIXES",
    "AND_SPLIT_PROTECTED_SIDES",
    "COUNTRY_AND_STATE_NAMES",
    "GENERIC_ACTOR_PHRASES",
    "GENERIC_DESCRIPTOR_WORDS",
    "GENERIC_LAST_WORDS",
    "GENERIC_LEADING_WORDS",
    "GENERIC_SIGNAL_PATTERNS",
    "NATIONALITY_ADJECTIVES",
    "clean_actor_names",
    "is_generic_actor_name",
    "split_composite_actor_name",
    "strip_trailing_parenthetical",
]
