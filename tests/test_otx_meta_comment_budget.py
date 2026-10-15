"""The ``OTX_META`` comment of an IOC that many pulses list (2026-10).

The comment has a budget of 4000 characters (``misp_writer._fit_meta_comment``): over it, lists are
shortened in a fixed order, never cut mid-token. Since a pair carries its pulse
(``"family::adversary::pulse"``), the same family and adversary named by N pulses were N entries of
``pa`` (up to 50), and ``sap`` (the pulses naming several actors) was never shortened. ``report_ids``
came first in the order, so for an IOC many pulses list the halving took the report ids (the pulses
the sync groups the IOC with) and then the families: 30 pulses naming APT28 kept 14 of 29 report ids;
120 pulses naming several actors and 10 naming one kept 1 of 129 report ids and 1 of 8 families.

Now ``pa`` holds one pair per family and adversary (the first pulse's), it is shortened before
``report_ids`` and ``mf``, ``sap`` keeps only the marks of the pulses still in ``pulse_id`` +
``report_ids`` (the sync reads a mark only for the pulse buckets the item is in), and the lists that
were shortened take back what still fits. The IOCs here go through the OTX collector's same-run fold
and ``MISPWriter.create_attribute``, then the sync's parser.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
_TESTS = Path(__file__).resolve().parent
for _p in (_SRC, _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import test_pulse_scoped_linking as _pulse_scoped  # noqa: E402  (its collector harness)

from collectors import misp_writer  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_HARNESS = _pulse_scoped.TestCollectorStampsPulseFamiliesAndAdversariesOnIndicators()
_IOC = "203.0.113.5"
_PREFIX = "OTX_META:"
_BUDGET = misp_writer._META_COMMENT_BUDGET
_EVENT = {"id": 7, "info": "EdgeGuard-alienvault_otx-2026-10-16", "date": "2026-10-16", "Tag": []}
_FAMILIES = ["Emotet", "TrickBot", "QakBot", "IcedID", "Cobalt Strike", "AgentTesla", "Formbook", "Lokibot"]


def _pid(n: int) -> str:
    """An OTX pulse id: 24 hexadecimal characters."""
    return f"6a4fdf500b5e6dffde{n:06x}"


def _pulse(n: int, families, adversary: str) -> dict:
    """A pulse as OTX returns it, with the fields that travel in ``OTX_META``."""
    pulse = _HARNESS._pulse(_pid(n), families, adversary, [_IOC])
    pulse["name"] = f"Campaign report {n}: infrastructure and payloads observed in the latest wave"
    pulse["tags"] = [f"tag-{n}-{k}" for k in range(12)]
    pulse["references"] = [f"https://research.example.org/{n}/report-{k}.html" for k in range(5)]
    pulse["targeted_countries"] = ["Germany", "France", "United States"]
    pulse["attack_ids"] = ["T1059", "T1566.001", "T1105", "T1071.001"]
    return pulse


def _through_the_writer(pulses):
    """The IOC item after the collector's fold, and its ``OTX_META`` comment and block."""
    items = _HARNESS._collect(pulses, limit=len(pulses))
    ioc = next(i for i in items if i.get("value") == _IOC)
    attr = MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False).create_attribute(ioc)
    comment = attr["comment"]
    assert comment.startswith(_PREFIX) and len(comment) <= _BUDGET, len(comment)
    return ioc, attr, json.loads(comment[len(_PREFIX) :])


@pytest.mark.parametrize("count", [30, 60])
def test_pulses_naming_one_actor_keep_every_report_id_and_one_pair_per_family_and_adversary(count):
    # Two families and two names of APT28 per pulse: four pairs per pulse, 50 entries before.
    ioc, _attr, meta = _through_the_writer(
        [_pulse(n, ["Zebrocy", "X-Agent"], "APT28, Fancy Bear") for n in range(count)]
    )
    assert len(ioc["report_ids"]) == count - 1
    assert meta["report_ids"] == ioc["report_ids"], "every pulse the sync groups the IOC with"
    assert meta["mf"] == ["Zebrocy", "X-Agent"]
    first = _pid(0)
    assert meta["pa"] == [
        f"Zebrocy::APT28::{first}",
        f"Zebrocy::Fancy Bear::{first}",
        f"X-Agent::APT28::{first}",
        f"X-Agent::Fancy Bear::{first}",
    ], "the first pulse's pair of each family and adversary"
    assert "sap" not in meta


def test_pulses_naming_several_actors_shorten_the_marks_with_the_report_ids():
    several = [_pulse(n, _FAMILIES[:4], "Gamaredon, Turla") for n in range(120)]
    single = [_pulse(200 + n, [_FAMILIES[n % 8]], "TA542") for n in range(10)]
    ioc, attr, meta = _through_the_writer(several + single)
    assert len(ioc["report_ids"]) == 129 and len(ioc["several_actor_pulses"]) == 120
    assert len(ioc["pulse_malware_families"]) == 8

    # The families survive whole, the report ids as far as the budget allows (1 of 129 before).
    assert meta["mf"] == ioc["pulse_malware_families"]
    kept = meta["report_ids"]
    assert kept == ioc["report_ids"][: len(kept)] and len(kept) >= 40, len(kept)
    # ``sap`` holds exactly the marks of the pulses still in pulse_id + report_ids.
    buckets = {meta["pulse_id"], *kept}
    assert set(meta["sap"]) == buckets & set(ioc["several_actor_pulses"])
    # One more report id (with its mark) would not fit.
    nxt = ioc["report_ids"][len(kept)]
    bigger = dict(meta, report_ids=kept + [nxt], sap=meta["sap"] + [nxt])
    assert len(_PREFIX + json.dumps(bigger)) > _BUDGET
    # The pairs (single-actor pulses only) were shortened first: the first pulse's pair is kept.
    assert meta["pa"][0] == f"{_FAMILIES[0]}::TA542::{_pid(200)}"

    # The sync reads the block back: the pulses it groups the IOC with, and their marks.
    item, _rels = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(
        {**attr, "uuid": "20000000-0000-0000-0000-00000000abcd"}, _EVENT
    )
    assert item["pulse_id"] == _pid(0) and item["report_ids"] == kept
    assert item["several_actor_pulses"] == meta["sap"]
    assert item["pulse_malware_families"] == ioc["pulse_malware_families"]


class TestTheHelpers:
    def test_pairs_are_one_per_family_and_adversary_the_first_kept(self):
        pairs = [
            "Emotet::TA542::p1",
            "emotet:: ta542 ::p2",
            "Emotet::TA542",
            "Emotet::Mummy Spider::p2",
            "Emotet::" + "x" * 320 + "::p3",
            "",
            None,
        ]
        assert misp_writer._otx_meta_pairs(pairs) == ["Emotet::TA542::p1", "Emotet::Mummy Spider::p2"]
        assert len(misp_writer._otx_meta_pairs([f"f{i}::a::p" for i in range(80)])) == 50

    def test_pairs_go_before_report_ids_and_families(self):
        meta = {
            "pulse_id": "p0",
            "report_ids": [f"r{i:023d}" for i in range(60)],
            "mf": [f"family-{i}" for i in range(8)],
            "pa": [f"family-{i}::actor-{i}::r{i:023d}" for i in range(50)],
        }
        out = json.loads(misp_writer._fit_meta_comment("X:", meta, budget=2600)[2:])
        assert out["report_ids"] == meta["report_ids"] and out["mf"] == meta["mf"]
        assert 1 <= len(out["pa"]) < 50 and out["pa"] == meta["pa"][: len(out["pa"])]

    def test_marks_follow_the_report_ids_and_come_back_with_them(self):
        meta = {
            "pulse_id": "p0",
            "report_ids": [f"r{i:023d}" for i in range(100)],
            "sap": ["p0"] + [f"r{i:023d}" for i in range(100)],
        }
        comment = misp_writer._fit_meta_comment("X:", meta, budget=3000)
        out = json.loads(comment[2:])
        assert len(comment) <= 3000 and 1 <= len(out["report_ids"]) < 100
        assert out["sap"] == ["p0"] + out["report_ids"], "the marks of the pulses still listed, in order"
        # The longest prefix that fits: one more report id and its mark do not.
        nxt = meta["report_ids"][len(out["report_ids"])]
        bigger = dict(out, report_ids=out["report_ids"] + [nxt], sap=out["sap"] + [nxt])
        assert len("X:" + json.dumps(bigger)) > 3000

    def test_a_comment_within_the_budget_is_unchanged(self):
        meta = {"pulse_id": "p0", "report_ids": ["r1"], "sap": ["r9"], "pa": ["a::b::p0", "A::B::p1"]}
        assert misp_writer._fit_meta_comment("X:", meta) == "X:" + json.dumps(meta)
