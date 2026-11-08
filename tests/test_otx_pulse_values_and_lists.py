"""OTX indicator values, the report record's pairs, the pulse lists on the items and the TLP rule (2026-11-08).

Pinned on pulses read from OTX on 2026-11-08 (``tests/fixtures/otx_pulse_values_and_lists_2026_11_08.json``,
trimmed to the indicators that matter; its ``misp_pairs`` and ``misp_record`` are what a MISP 2.5 test instance held
after the 730-day baseline of that day):

* The report record lists exactly the (type, value) pairs the push sends to MISP (``otx_collector._record_pairs``).
  Pulse 5d8dcf19… lists five URLs twice, the second time with an upper-case host; the collector's same-run fold
  pushes the first spelling only, but the record listed both (99 pairs and ``indicator_count`` 99 against the 94
  attributes MISP held). Pulse 6389edf4… lists ``…/SENT_Kill[.]zip``, which MISP stores refanged; the collector sent
  it as given, so the push could not confirm it and the record named a value MISP does not hold. The collector now
  refangs a value as MISP refangs it on save (``misp_writer.refang_as_misp``) before the fold and the push, and the
  record folds as the collector does: MISP, the record and the graph hold one value.
* Every list the collector copies from a pulse onto its items (tags, references, ATT&CK ids, targeted countries,
  industries) is read as the pulse's record reads it (``report_records.otx_pulse_list``): no blank or
  whitespace-only item. OTX answered ``[""]`` for the tags of 689455e1… (2,107 attributes carried
  ``pulse_tags`` ``[""]``), the references of 686bd1d7… and the ATT&CK ids of 69d41711…, and lists with a blank
  beside real items for 677d38cb…, 6acf8607… and 6a019c5f….
* An amber or red pulse, or one that states no TLP (gated as amber), puts no copy of its text on its items: checked
  from the collector through ``MISPWriter``, the report record and the sync, on the shape of the real pulse
  6a019c5f… (tags, references, targeted countries, industries) with its TLP set, since no amber or red pulse has
  been recorded (the 2026-11-08 baseline read 3,017 white and 4 green pulses).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_otx_incremental_order import ROWS, _collect, _Otx, _recorded  # noqa: E402
from test_otx_report_records import (  # noqa: E402
    NO_COPIES,
    _collector,
    _copies,
    _env,  # noqa: F401  (autouse: the writer settings of the OTX record tests)
    _Misp,
    _otx_meta,
    _process,
    _real_writer,
    _RecordWriter,
)

import config  # noqa: E402
import report_records as rr  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402

FIXTURE = json.loads((TESTS / "fixtures" / "otx_pulse_values_and_lists_2026_11_08.json").read_text("utf-8"))
SOURCE = rr.SOURCE_OTX
CASE_PULSE = "5d8dcf197ec3aea4d3e338df"
DEFANG_PULSE = "6389edf4071ec7c595fc8204"
BLANK_LIST_PULSES = [
    "689455e11e25236fe810364b",
    "686bd1d71a879c051d569c88",
    "69d41711b3984d53ffc4f8ce",
    "677d38cbdaeb986028ebc193",
    "6acf8607ba5b3757d207eb86",
    "6a019c5f0a3344d92c4302a3",
]
SHAPE_PULSE = "6a019c5f0a3344d92c4302a3"
DEFANGED = "https://bashupload.com/uCiPm/SENT_Kill[.]zip"
REFANGED = "https://bashupload.com/uCiPm/SENT_Kill.zip"
LISTS = {  # pulse list -> the key of its copy on an item
    "tags": "pulse_tags",
    "references": "pulse_references",
    "attack_ids": "attack_ids",
    "targeted_countries": "targeted_countries",
    "industries": "otx_industries",
}
EVENT = {"id": "136", "info": "EdgeGuard-alienvault_otx-2026-11-08", "date": "2026-11-08", "Tag": []}


def _by_id(pid: str) -> Dict[str, Any]:
    """The fixture pulse as OTX answers it by id (``TLP``)."""
    return copy.deepcopy(FIXTURE["pulses"][pid]["pulse"])


def _subscribed(pulse: Dict[str, Any]) -> Dict[str, Any]:
    """*pulse* as the subscribed list answers it: ``tlp`` for ``TLP`` (none when it states none), with
    ``extract_source`` and ``more_indicators`` (``tests/fixtures/otx_pulse_keys_2026_11_07.json``)."""
    row = {k: v for k, v in pulse.items() if k != "TLP"}
    if "TLP" in pulse:
        row["tlp"] = pulse["TLP"]
    row.update(extract_source=[], more_indicators=False)
    return row


def _record(pulse: Dict[str, Any]) -> Dict[str, Any]:
    return rr.otx_pulse_record(pulse, oc._record_pairs(pulse, _collector().map_indicator_type))


def _pairs(record: Dict[str, Any]) -> List[Tuple[str, str]]:
    return [tuple(p) for p in record["indicators"]]  # type: ignore[misc]


def _misp_pairs(pid: str) -> List[Tuple[str, str]]:
    return sorted(tuple(p) for p in FIXTURE["pulses"][pid]["misp_pairs"])  # type: ignore[misc]


def _records_in(misp: _Misp) -> Dict[str, Dict[str, Any]]:
    """The records the MISP double holds, by pulse id, each with the report's ``distribution``."""
    out = {}
    for report in misp.reports.values():
        parsed = rr.parse_content(report["content"])
        assert parsed is not None
        _description, meta = parsed
        out[meta["record_id"]] = {**meta, "distribution": report["distribution"]}
    return out


def _indicators_in(misp: _Misp) -> List[Dict[str, Any]]:
    """The indicator attributes the MISP double holds: those with an ``OTX_META`` comment (a pulse's malware
    families and adversaries are attributes with a ``MITRE_USES_TECHNIQUES`` block)."""
    return [a for a in misp.attributes if str(a.get("comment") or "").startswith("OTX_META:")]


def _attributes_of(misp: _Misp, pid: str) -> List[Dict[str, Any]]:
    """The indicator attributes the MISP double holds whose ``OTX_META`` names *pid* (``pulse_id`` or
    ``report_ids``)."""
    out = []
    for attribute in _indicators_in(misp):
        meta = _otx_meta(attribute)
        if pid == meta.get("pulse_id") or pid in (meta.get("report_ids") or []):
            out.append(attribute)
    return out


def _synced(attribute: Dict[str, Any], n: int) -> Dict[str, Any]:
    """The item the MISP → Neo4j sync makes of *attribute* (``MISPToNeo4jSync.parse_attribute``)."""
    from run_misp_to_neo4j import MISPToNeo4jSync

    item, _relationships = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        {**attribute, "uuid": f"00000000-0000-4000-8000-{n:012d}"}, EVENT
    )
    assert item is not None
    return item


class _MispStoringAsMisp(_Misp):
    """The MISP double storing a url or domain value as MISP 2.5 does in the respect checked here: ``[.]`` as
    ``.`` (``ComplexTypeTool::refangValue``; MISP held ``…/SENT_Kill.zip`` for the defanged URL on 2026-11-08). It
    answers the push with the stored values, as MISP does, so the writer's confirmation compares the value sent
    with the value stored. ``sent`` keeps the attributes as the writer sent them."""

    def __init__(self):
        super().__init__()
        self.sent: List[Dict[str, Any]] = []

    def _handle(self, method: str, url: str, body: Any):
        path = url.split(self.url, 1)[1]
        if method == "POST" and path.startswith("/events/") and path[len("/events/") :].isdigit():
            self.sent.extend(copy.deepcopy(body.get("Attribute") or []))
            body = copy.deepcopy(body)
            for attribute in body.get("Attribute") or []:
                if attribute.get("type") in ("url", "domain"):
                    attribute["value"] = attribute["value"].replace("[.]", ".")
        return super()._handle(method, url, body)


def test_the_fixture_holds_what_the_findings_measured():
    """The trimmed pulses keep what the 2026-11-08 run got wrong: the case pulse's later upper-case spellings,
    the defanged URL, and the blank items the attributes of the blank-list pulses carried."""
    case = FIXTURE["pulses"][CASE_PULSE]
    assert case["misp_record"]["indicator_count"] == 99 and case["n_indicators"] == 99
    assert len(case["pulse"]["indicators"]) == 16 and len(case["misp_pairs"]) == 11
    assert _by_id(DEFANG_PULSE)["indicators"][6]["indicator"] == DEFANGED
    assert ["url", REFANGED] in FIXTURE["pulses"][DEFANG_PULSE]["misp_pairs"]
    for pid in BLANK_LIST_PULSES:
        assert any("" in copied for copied in FIXTURE["pulses"][pid]["misp_otx_meta_lists"].values()), pid


# --------------------------------------------------------------------------- MISP's refang rules


@pytest.mark.parametrize(
    "misp_type, value, stored",
    [
        ("url", DEFANGED, REFANGED),
        ("url", "hxxp://evil.example/a", "http://evil.example/a"),
        ("url", "HXXPS://evil.example/a", "httpS://evil.example/a"),  # MISP rewrites the prefix only
        ("url", "hxtp://a.example", "http://a.example"),
        ("url", "htxp://a.example", "http://a.example"),
        ("url", "h[tt]ps://a.example", "https://a.example"),
        ("url", "meow://a.example", "http://a.example"),
        ("url", "[hxxp://]evil.example/x", "http://evil.example/x"),
        ("url", "https[:]//evil[dot]example(dot)org/a", "https://evil.example.org/a"),
        ("link", "hxxp://evil[.]example", "http://evil.example"),
        ("domain", "evil[.]example", "evil.example"),
        ("hostname", "www[dot]evil.example", "www.evil.example"),
        ("ip-dst", "198.51.100[.]7", "198.51.100.7"),
        ("ip-src", "198[.]51.100.7", "198.51.100.7"),
        ("domain|ip", "evil[.]example|198.51.100.7", "evil.example|198.51.100.7"),
        ("email-src", "ops[@]evil[.]example", "ops@evil.example"),
        ("email-dst", "ops[at]evil.example", "ops@evil.example"),
        ("email", "ops[at]evil(dot)example", "ops@evil.example"),
    ],
)
def test_a_value_is_refanged_as_misp_stores_it(misp_type, value, stored):
    assert mw.refang_as_misp(misp_type, value) == stored


@pytest.mark.parametrize(
    "misp_type, value",
    [
        # Forms MISP does not rewrite: kept as given, as MISP stores them.
        ("url", "http://evil(.)example/a"),
        ("url", "http://evil{.}example/a"),
        ("url", "http://evil[DOT]example/a"),
        ("url", "http://evil.example/hxxp/a"),
        ("url", " hxxp://evil.example"),
        ("email-src", "ops(at)evil.example"),
        # Rules that belong to other types.
        ("domain", "hxxp-evil.example"),
        ("domain", "evil.example[:]8080"),
        ("ip-dst", "198.51.100.7[at]"),
        # Types MISP never refangs.
        ("sha256", "a" * 64),
        ("text", "Global[.]Mutex"),
        ("filename", "SENT_Kill[.]zip"),
        ("vulnerability", "CVE-2026-0001"),
        ("regkey", "HKLM\\Software[.]x"),
    ],
)
def test_a_value_misp_keeps_is_not_rewritten(misp_type, value):
    assert mw.refang_as_misp(misp_type, value) == value


def test_a_value_that_is_not_a_string_is_returned_as_given():
    assert mw.refang_as_misp("url", None) is None and mw.refang_as_misp("url", 5) == 5


def test_the_item_value_is_the_pulse_s_value_unless_misp_would_refang_it():
    """``_pulse_indicator_value``: the value as given (surrounding whitespace too, which the writer trims) when
    MISP would keep it; trimmed and refanged when MISP would refang it."""
    assert oc._pulse_indicator_value("url", DEFANGED) == REFANGED
    assert oc._pulse_indicator_value("url", f"  {DEFANGED}\n") == REFANGED
    assert oc._pulse_indicator_value("domain", "evil[.]example") == "evil.example"
    assert oc._pulse_indicator_value("url", " http://Setseta.com/set.exe ") == " http://Setseta.com/set.exe "
    assert oc._pulse_indicator_value("hash", "a" * 64) == "a" * 64
    assert oc._pulse_indicator_value("unknown", "Global[.]Mutex") == "Global[.]Mutex", "a text MISP keeps"
    assert oc._pulse_indicator_value("url", None) is None


# --------------------------------------------------------------------------- the record's pairs


@pytest.mark.parametrize("pid", [CASE_PULSE, DEFANG_PULSE])
@pytest.mark.parametrize("answer", ["by id", "subscribed"])
def test_the_record_lists_the_pairs_misp_holds(pid, answer):
    """The record of each real pulse lists exactly the (type, value) pairs MISP held for its indicators, and its
    ``indicator_count`` counts them: 11 of the case pulse's 16 kept indicators (the run's 94 of 99), all 13 of the
    defanged pulse's, the URL refanged. The window's copy and the answer by id give one record."""
    pulse = _by_id(pid)
    record = _record(_subscribed(pulse) if answer == "subscribed" else pulse)
    assert _pairs(record) == _misp_pairs(pid)
    assert record["indicator_count"] == len(_misp_pairs(pid))
    assert record["digest"] == _record(_by_id(pid))["digest"]
    assert not any("[.]" in value for _type, value in _pairs(record))


def test_a_url_listed_again_with_an_upper_case_host_is_one_pair_in_the_first_spelling():
    """The fold keeps the first spelling, whichever it is: listed in the reverse order, the upper-case spelling
    comes first and is the one listed (MISP stores a URL host in the case given). A URL with an upper-case host
    that the pulse lists once keeps it."""
    pulse = _by_id(CASE_PULSE)
    pairs = _pairs(_record(pulse))
    assert ("url", "http://setseta.com/set.exe") in pairs and ("url", "http://Setseta.com/set.exe") not in pairs
    assert ("url", "http://J5h4f9b6.com/set.exe") in pairs
    pulse["indicators"].reverse()
    reversed_pairs = _pairs(_record(pulse))
    assert ("url", "http://Setseta.com/set.exe") in reversed_pairs
    assert ("url", "http://setseta.com/set.exe") not in reversed_pairs
    assert len(reversed_pairs) == len(pairs) == 11


def test_urls_whose_paths_differ_in_case_stay_two_pairs():
    """The guard of the fold: the graph keeps two Indicators for URLs whose paths differ in case (the values of
    ``tests/fixtures/otx_case_variants_2026_11_01.json``), the collector two items and the record two pairs."""
    pulse = _by_id(CASE_PULSE)
    pulse["indicators"] = [
        {"type": "URL", "indicator": "http://twizt.net/Installed"},
        {"type": "URL", "indicator": "http://twizt.net/installed"},
    ]
    record = _record(pulse)
    assert _pairs(record) == [("url", "http://twizt.net/Installed"), ("url", "http://twizt.net/installed")]
    assert record["indicator_count"] == 2


def test_the_pushed_pairs_the_record_and_the_graph_hold_one_value(caplog):
    """End to end: the two pulses through the collector, ``MISPWriter`` and a MISP double that stores a defanged
    value refanged, as MISP does. Each record lists exactly the pairs of the attributes that name its pulse, the
    push confirms every attribute (the defanged URL was ``[UNCONFIRMED]`` on 2026-11-08), and the sync makes the
    Indicator of the stored value."""
    misp = _MispStoringAsMisp()
    pulses = [_subscribed(_by_id(CASE_PULSE)), _subscribed(_by_id(DEFANG_PULSE))]
    run = _collect(_Otx(pulses), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    assert run.status["success"] is True
    assert not [r for r in caplog.records if "[UNCONFIRMED]" in r.getMessage()]
    assert misp.sent and [(a["type"], a["value"]) for a in misp.sent] == [
        (a["type"], a["value"]) for a in misp.attributes
    ], "MISP stores every value as sent"
    records = _records_in(misp)
    for pid in (CASE_PULSE, DEFANG_PULSE):
        held = sorted((a["type"], a["value"]) for a in _attributes_of(misp, pid))
        assert held == _misp_pairs(pid) == _pairs(records[pid]), pid
        assert records[pid]["indicator_count"] == len(held)
    (stored,) = [a for a in misp.attributes if a["value"] == REFANGED]
    assert _synced(stored, 1)["value"] == REFANGED


def test_a_pulse_of_the_retry_list_is_pushed_refanged_and_without_blank_copies(caplog):
    """The retry list's path: the defanged pulse and the pulse whose tags OTX answers as ``[""]`` are on the list
    and answered by id (``TLP``); their items are pushed with the refanged value and no blank tag, and their
    records list the pairs MISP holds."""
    entries = [
        {
            "id": pid,
            "modified": FIXTURE["pulses"][pid]["pulse"]["modified"],
            "first_failed_at": "2026-11-07T00:00:00+00:00",
            "last_tried_at": "2026-11-07T00:00:00+00:00",
            "attempts": 1,
            "last_reason": "1 item(s) listed as unstored; an earlier run",
        }
        for pid in (DEFANG_PULSE, BLANK_LIST_PULSES[0])
    ]
    otx = _Otx(_recorded(range(3)))
    otx.by_id_only = {pid: _by_id(pid) for pid in (DEFANG_PULSE, BLANK_LIST_PULSES[0])}
    writer = _RecordWriter()
    state: Dict[str, Any] = {"otx_last_pulse_modified": ROWS[2]["modified"], "otx_retry_pulses": entries}
    run = _collect(otx, state, caplog, limit=None, writer=writer)
    assert run.status["pulse_counts"]["retry_fetched"] == 2 and state["otx_retry_pulses"] == []
    values = [item.get("value") for item in writer.pushed if item.get("pulse_id") == DEFANG_PULSE]
    assert REFANGED in values and DEFANGED not in values
    blank_tagged = [item for item in writer.pushed if item.get("pulse_id") == BLANK_LIST_PULSES[0]]
    assert blank_tagged and all(item["pulse_tags"] == [] for item in blank_tagged)
    records = {r["record_id"]: r for r in writer.pushed_records()}
    assert _pairs(records[DEFANG_PULSE]) == _misp_pairs(DEFANG_PULSE)
    assert _pairs(records[BLANK_LIST_PULSES[0]]) == _misp_pairs(BLANK_LIST_PULSES[0])


def test_a_pending_record_fetched_by_id_lists_the_folded_pairs(caplog):
    """The path of ``report_pending``: the case pulse's record, fetched by id, lists the 11 pairs MISP holds;
    its items are not pushed again."""
    rr.update_report_pending(SOURCE, failed=[(f"{SOURCE}:{CASE_PULSE}", "earlier")])
    otx = _Otx(_recorded(range(3)))
    otx.by_id_only[CASE_PULSE] = _by_id(CASE_PULSE)
    writer = _RecordWriter()
    _collect(otx, {"otx_last_pulse_modified": ROWS[2]["modified"]}, caplog, limit=None, writer=writer)
    (record,) = [r for r in writer.pushed_records() if r["record_id"] == CASE_PULSE]
    assert _pairs(record) == _misp_pairs(CASE_PULSE) and record["indicator_count"] == 11
    assert not any(item.get("pulse_id") == CASE_PULSE for item in writer.pushed)


# --------------------------------------------------------------------------- the pulse lists


@pytest.mark.parametrize("pid", BLANK_LIST_PULSES)
def test_a_pulse_list_drops_blank_items_and_agrees_with_the_record_misp_held(pid):
    """``otx_pulse_list`` on the real lists: the items other than blank ones, in the pulse's order; sorted they
    are the lists of the record MISP held, so the records of these pulses do not change."""
    pulse = _by_id(pid)
    expected_record = FIXTURE["pulses"][pid]["misp_record"]
    for field in LISTS:
        items = rr.otx_pulse_list(pulse, field)
        assert items == [x for x in pulse[field] if x.strip()], field
        assert sorted(items) == expected_record[field], field
        assert _record(pulse)[field] == expected_record[field], field


def test_a_pulse_list_item_is_read_as_the_record_reads_it():
    """Blank and whitespace-only items, items that are not strings and items over the field's length cap are
    left out, a run of whitespace is one space, a repeated item is kept once, the order is the pulse's; an
    ATT&CK id object gives its ``id``. Real items stay as given (the guard against over-cleaning)."""
    pulse = {
        "tags": ["", " ", "\t\n", "Stake-to-Earn", "cve-2024-4577", "  remote   access ", "remote access", None, 7],
        "references": ["", "https://isc.sans.edu/diary/rss/31564", "https://x.example/" + "a" * 2048],
        "attack_ids": ["", " T1059 ", {"id": "T1566"}, {"id": ""}, {"name": "Phishing"}, "T1059"],
        "targeted_countries": ["Austria", "", "France"],
        "industries": ["Finance", "x" * 201, "y" * 200],
    }
    assert rr.otx_pulse_list(pulse, "tags") == ["Stake-to-Earn", "cve-2024-4577", "remote access"]
    assert rr.otx_pulse_list(pulse, "references") == ["https://isc.sans.edu/diary/rss/31564"]
    assert rr.otx_pulse_list(pulse, "attack_ids") == ["T1059", "T1566"]
    assert rr.otx_pulse_list(pulse, "targeted_countries") == ["Austria", "France"]
    assert rr.otx_pulse_list(pulse, "industries") == ["Finance", "y" * 200]
    for field in LISTS:
        assert sorted(rr.otx_pulse_list(pulse, field)) == rr.otx_pulse_record({**pulse, "id": "p1"}, [])[field]


@pytest.mark.parametrize("value", [None, "", "tag", {"tag": 1}, 5])
def test_a_pulse_list_that_is_not_a_list_is_empty(value):
    for field in LISTS:
        assert rr.otx_pulse_list({field: value}, field) == []
    assert rr.otx_pulse_list({}, "tags") == []


def test_only_the_copied_lists_are_read():
    with pytest.raises(ValueError):
        rr.otx_pulse_list({"malware_families": ["x"]}, "malware_families")


@pytest.mark.parametrize("pid", BLANK_LIST_PULSES)
def test_the_collector_copies_the_lists_without_blank_items(pid):
    """Every item of the pulse carries the lists as ``otx_pulse_list`` reads them (references cut at 10, tags at
    20, as before); the malware and actor items' reported techniques are the ATT&CK ids without blanks."""
    collector = _collector()
    pulse = _subscribed(_by_id(pid))
    collector.misp_writer = None
    items = [i for i in _process(collector, [pulse]) if i.get("pulse_id") == pid]
    assert items
    for item in items:
        assert item["pulse_tags"] == rr.otx_pulse_list(pulse, "tags")[:20]
        assert item["pulse_references"] == rr.otx_pulse_list(pulse, "references")[:10]
        assert item["attack_ids"] == rr.otx_pulse_list(pulse, "attack_ids")
        assert item["targeted_countries"] == rr.otx_pulse_list(pulse, "targeted_countries")
        assert item["otx_industries"] == rr.otx_pulse_list(pulse, "industries")
        for key in ("pulse_tags", "pulse_references", "attack_ids", "targeted_countries", "otx_industries"):
            assert all(isinstance(x, str) and x.strip() for x in item[key]), (key, item[key])
        if item.get("type") in ("malware", "actor"):
            assert item["reported_techniques"] == rr.otx_pulse_list(pulse, "attack_ids")


def test_the_attributes_carry_no_blank_copy_and_agree_with_the_records(caplog):
    """End to end through ``MISPWriter``: no ``OTX_META`` list of the six pulses holds a blank string (the
    2026-11-08 run wrote ``[""]`` and lists with a blank), and each copy, sorted, is its record's list."""
    misp = _Misp()
    pulses = [_subscribed(_by_id(pid)) for pid in BLANK_LIST_PULSES]
    _collect(_Otx(pulses), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    records = _records_in(misp)
    for pid in BLANK_LIST_PULSES:
        attributes = _attributes_of(misp, pid)
        assert attributes, pid
        for attribute in attributes:
            meta = _otx_meta(attribute)
            for field, key in LISTS.items():
                assert "" not in meta[key] and all(x.strip() for x in meta[key]), (pid, key)
                assert sorted(meta[key]) == records[pid][field], (pid, key)


def test_a_pulse_whose_lists_are_null_is_processed_with_empty_copies():
    """A list given as null counts as empty, as in the record: the pulse is processed (it was an answer that
    could not be read, ``TypeError``), its items carry empty copies and its record empty lists."""
    collector = _collector()
    pulse = _subscribed(_by_id(BLANK_LIST_PULSES[1]))
    for field in LISTS:
        pulse[field] = None
    collector.misp_writer = None
    items = [i for i in _process(collector, [pulse]) if i.get("pulse_id") == pulse["id"]]
    assert items and all(item[key] == [] for item in items for key in LISTS.values())
    record = _record(pulse)
    assert all(record[field] == [] for field in LISTS)


# --------------------------------------------------------------------------- amber, red and unknown TLP


def _gated(level: Optional[str], pid: str = SHAPE_PULSE, name: Optional[str] = None) -> Dict[str, Any]:
    """The shape pulse as the subscribed list answers it, at TLP *level* (no TLP key for None)."""
    pulse = _by_id(SHAPE_PULSE)
    pulse.pop("TLP")
    if level is not None:
        pulse["TLP"] = level
    pulse["id"] = pid
    if name is not None:
        pulse["name"] = name
    return _subscribed(pulse)


def _text_of(pulse: Dict[str, Any]) -> List[str]:
    """The pulse's text that its items copy when it is white, clear or green."""
    return [pulse["name"], *rr.otx_pulse_list(pulse, "tags"), *rr.otx_pulse_list(pulse, "references")] + list(
        rr.otx_pulse_list(pulse, "targeted_countries")
    )


@pytest.mark.parametrize("level", ["amber", "red", None, "white"], ids=["amber", "red", "no TLP", "white"])
def test_a_gated_pulse_keeps_its_text_off_its_items_from_the_collector_to_the_sync(caplog, level):
    """An amber or red pulse, and a pulse that states no TLP: every attribute keeps ``pulse_id``, ``pulse_tlp``
    and ``report_ids`` and carries no copy of the pulse's name, tags, references or countries; the record holds
    the text at distribution 0 with ``tlp:amber`` (``tlp:red`` for red; no TLP is gated as amber); the sync's
    ``pulse_name`` is empty (the comment is an ``OTX_META`` block, ``_METADATA_COMMENT_RE``), and so are the
    copies on its item. The white pulse is the guard: its copies, its record at distribution 5 and its name in
    the sync."""
    misp = _Misp()
    pulse = _gated(level)
    run = _collect(_Otx([pulse]), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    assert run.status["success"] is True and len(_indicators_in(misp)) == 2
    gated = level != "white"
    tag = f"tlp:{level}" if level else f"tlp:{config.EDGEGUARD_DEFAULT_TLP}"
    if gated:  # the malware family attributes carry none of it either
        assert not [text for a in misp.attributes for text in _text_of(pulse) if text in str(a.get("comment"))]
    for n, attribute in enumerate(_indicators_in(misp)):
        meta = _otx_meta(attribute)
        assert meta["pulse_id"] == SHAPE_PULSE and meta["pulse_tlp"] == (level or "")
        assert meta["report_ids"] == [] and meta["otx_industries"] == ["Finance"]
        assert {"name": tag} in attribute["Tag"]
        synced = _synced(attribute, n)
        assert synced["pulse_id"] == SHAPE_PULSE and synced["pulse_tlp"] == (level or "")
        if gated:
            assert _copies(meta) == NO_COPIES
            assert not [text for text in _text_of(pulse) if text in attribute["comment"]]
            assert synced["pulse_name"] == ""
            assert synced["pulse_tags"] == synced["pulse_references"] == synced["targeted_countries"] == []
        else:
            assert meta["pulse_name"] == pulse["name"] and meta["targeted_countries"] == ["Austria", "France", "Italy"]
            assert synced["pulse_name"] == pulse["name"]
    record = _records_in(misp)[SHAPE_PULSE]
    (sent,) = misp.bodies("/eventReports/add/")
    if gated:
        assert record["distribution"] == str(rr.DISTRIBUTION_OWN_ORGANISATION)
        assert {"name": "tlp:red" if level == "red" else "tlp:amber"} in sent["EventReport"]["Tag"]
    else:
        assert record["distribution"] == str(rr.DISTRIBUTION_INHERIT_EVENT)
        assert {"name": "tlp:white"} in sent["EventReport"]["Tag"]
    assert record["tlp"] == level and record["tags"] == sorted(rr.otx_pulse_list(pulse, "tags"))
    assert record["targeted_countries"] == ["Austria", "France", "Italy"]


@pytest.mark.parametrize("amber_first", [False, True], ids=["white first", "amber first"])
def test_an_item_a_white_and_an_amber_pulse_list_carries_no_copy(caplog, amber_first):
    """The white shape pulse and an amber pulse listing the same indicators: each attribute names the first in
    ``pulse_id`` and the other in ``report_ids``, takes amber (the most restrictive) and carries no copy, also when
    the white pulse came first and its copies were the kept item's; the sync gives it no pulse name. Each pulse
    keeps its own record at its own level."""
    white = _gated("white")
    amber = _gated("amber", pid="6a019c5f0a3344d92c43aaaa", name="Amber report on the same infrastructure")
    first, later = (amber, white) if amber_first else (white, amber)
    misp = _Misp()
    _collect(_Otx([first, later]), {}, caplog, limit=None, baseline=True, writer=_real_writer(misp))
    assert len(_indicators_in(misp)) == 2
    for n, attribute in enumerate(_indicators_in(misp)):
        meta = _otx_meta(attribute)
        assert {meta["pulse_id"], *meta["report_ids"]} == {white["id"], amber["id"]}
        assert meta["pulse_tlp"] == "amber" and _copies(meta) == NO_COPIES
        assert {"name": "tlp:amber"} in attribute["Tag"]
        assert not [text for text in _text_of(white) + _text_of(amber) if text in attribute["comment"]]
        assert _synced(attribute, n)["pulse_name"] == ""
    records = _records_in(misp)
    assert records[white["id"]]["distribution"] == str(rr.DISTRIBUTION_INHERIT_EVENT)
    assert records[amber["id"]]["distribution"] == str(rr.DISTRIBUTION_OWN_ORGANISATION)
    seen: Set[Tuple[str, str]] = set(_pairs(records[white["id"]]))
    assert seen == set(_pairs(records[amber["id"]])) == {(a["type"], a["value"]) for a in _indicators_in(misp)}
