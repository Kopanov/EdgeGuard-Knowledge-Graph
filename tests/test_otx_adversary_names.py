"""Which names of an OTX pulse's ``adversary`` field become actors (2026-10-18).

Two rules act before the collector builds its actor items, its ``family::adversary::pulse`` pairs and
its decision whether the pulse names several actors, so all three see the same names:

* A country or state name, or a nationality adjective on its own, is never an actor name
  (``actor_name_hygiene``, rule (c) of ``is_generic_actor_name``): a pulse on APT37 whose adversary
  field reads "APT37, North Korea" names one actor.
* A name the same pulse lists both as adversary and as a malware family is an actor only when the
  canonical threat-actor reference resolves it. On the hosted graph of 2026-10-18, 181 of 859
  ThreatActor names were also Malware names. Reference 2026.10.17 knew 34 of them (Kimsuky, Akira,
  Qilin, Medusa, ...). Reference 2026.10.20 also holds, through override decisions, 29 ransomware
  operations named after their ransomware (Rhysida, BlackSuit, Trigona, ...) as actors of their own,
  and Conti, LockBit and Nefilim as names of the actor the galaxies name as their developer or operator
  (Wizard Spider, BITWISE SPIDER, GOLD MANSARD), so 66 stay actors. The other 115 (Lumma Stealer,
  AsyncRAT, Agent Tesla, Mirai, Zloader, and ransomware names the review left out, such as Nitrogen and
  Kraken) are dropped for a pulse that lists them as its family, and stay the pulse's malware item.
  Without the reference the rule cannot decide and the name is kept.

The fixture names are names from that measurement.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
_TESTS = Path(__file__).resolve().parent
for _p in (_SRC, _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

os.environ.setdefault("NEO4J_PASSWORD", "test")
os.environ.setdefault("MISP_API_KEY", "test")

import test_pulse_scoped_linking as _pulse_scoped  # noqa: E402  (its collector harness)

import canonical_threat_actors as cta  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402

_HARNESS = _pulse_scoped.TestCollectorStampsPulseFamiliesAndAdversariesOnIndicators()
_pulse = _HARNESS._pulse


def _actors(items):
    return [i["name"] for i in items if i.get("type") == "actor"]


def _malware(items):
    return [i["name"] for i in items if i.get("type") == "malware"]


def _ioc(items, value):
    return next(i for i in items if i.get("value") == value)


@pytest.fixture(scope="module")
def reference():
    return cta.load_canonical_reference()


# The measured names the reference knew before 2026-10-20 (reference 2026.10.17).
KNOWN_BEFORE = (
    "agenda", "akira", "applejeus", "beast", "black basta", "blackbyte", "carbanak", "clop",
    "contagious interview", "dragonforce", "evilnum", "fog ransomware", "funksec", "gelsemium", "interlock",
    "kimsuky", "kinsing", "luminousmoth", "machete", "magecart", "medusa", "moonstone sleet", "muddywater",
    "night dragon", "play", "qilin", "ransomhub", "romcom", "rtm", "taidoor", "the gentlemen", "tradertraitor",
    "uac-0006", "uta0388",
)  # fmt: skip
# Ransomware operations named after their ransomware, in the reference since 2026-10-20 (override
# decisions), written as their display name.
RANSOMWARE_OPERATIONS = (
    "BlackNevas", "BlackSuit", "Brain Cipher", "Cactus", "Cicada3301", "CrazyHunter", "DeadLock", "DEVMAN",
    "ELPACO-team", "Embargo", "Everest", "Global Group", "Gunra", "HellCat", "HellDown", "HelloKitty", "Kyber",
    "Lynx", "Makop", "Mallox", "NightSpire", "Payouts King", "Rhysida", "SECP0", "Termite", "Trigona", "Vect",
    "Warlock", "Yurei",
)  # fmt: skip
# Ransomware operations the galaxies attribute to an actor the reference holds as their developer or
# operator: since 2026-10-20 (override decisions) the name counts as that actor.
OPERATIONS_OF_A_KNOWN_OPERATOR = (
    ("Conti", "wizard spider"), ("LockBit", "bitwise spider"), ("Nefilim", "gold mansard"),
)  # fmt: skip
# Ransomware names the review left out: the name also names a trojan, stealer, loader, botnet, banking
# trojan or backdoor (Aurora: ATT&CK Hydraq; Anubis, Kraken, Osiris, Chaos; Nitrogen and Morpheus, which
# malpedia also gives to a loader: 'Nitrogen Loader', 'Morpheus Loader').
RANSOMWARE_NAMES_LEFT_OUT = ("Aurora", "Anubis", "Kraken", "Osiris", "Chaos", "Nitrogen", "Morpheus")


class TestCountryNamesInTheAdversaryField:
    def test_a_country_beside_the_actor_leaves_one_actor_and_a_single_actor_pulse(self):
        items = _HARNESS._collect([_pulse("p-nk", ["ROKRAT"], "APT37, North Korea", ["203.0.113.20"])])
        assert _actors(items) == ["APT37"]
        ioc = _ioc(items, "203.0.113.20")
        assert ioc["pulse_malware_actor_pairs"] == ["ROKRAT::APT37::p-nk"], "one actor: the pulse attributes"
        assert all(i["several_actor_pulses"] == [] for i in items)
        assert all(i["several_actor_pulses_by_name"] == [] for i in items)

    def test_a_pulse_naming_only_a_country_names_no_actor(self):
        items = _HARNESS._collect([_pulse("p-ru", ["Industroyer2"], "Russia", ["203.0.113.21"])])
        assert _actors(items) == []
        assert _ioc(items, "203.0.113.21")["pulse_malware_actor_pairs"] == []


class TestAnAdversaryTheSamePulseListsAsAMalwareFamily:
    @pytest.mark.parametrize(
        "name",
        ["Lumma Stealer", "AsyncRAT", "Agent Tesla", "Mirai", "Zloader", "Snake Keylogger", "ValleyRAT"]
        + list(RANSOMWARE_NAMES_LEFT_OUT),
    )
    def test_a_name_the_reference_does_not_resolve_stays_malware_only(self, reference, name):
        assert reference.canonical_for(name) is None
        items = _HARNESS._collect([_pulse("p-fam", [name], name, ["203.0.113.30"])])
        assert _actors(items) == [], "not an actor"
        assert _malware(items) == [name], "the pulse's malware family item is unchanged"
        ioc = _ioc(items, "203.0.113.30")
        assert ioc["pulse_malware_families"] == [name]
        assert ioc["pulse_malware_actor_pairs"] == []

    @pytest.mark.parametrize("name", ["Kimsuky", "Akira", "Qilin", "Medusa", "Agenda", "Play", "The Gentlemen"])
    def test_a_name_the_reference_resolves_stays_an_actor(self, reference, name):
        assert reference.canonical_for(name) is not None
        items = _HARNESS._collect([_pulse("p-known", [name], name, ["203.0.113.31"])])
        assert _actors(items) == [name]
        assert _malware(items) == [name]
        assert _ioc(items, "203.0.113.31")["pulse_malware_actor_pairs"] == [f"{name}::{name}::p-known"]

    @pytest.mark.parametrize("name", KNOWN_BEFORE)
    def test_every_measured_name_the_reference_knew_before_stays_an_actor(self, reference, name):
        assert reference.canonical_for(name) is not None
        items = _HARNESS._collect([_pulse("p-before", [name], name, ["203.0.113.46"])])
        assert _actors(items) == [name]
        assert _ioc(items, "203.0.113.46")["pulse_malware_actor_pairs"] == [f"{name}::{name}::p-before"]

    @pytest.mark.parametrize("name", RANSOMWARE_OPERATIONS)
    def test_a_ransomware_operation_named_after_its_ransomware_stays_an_actor(self, reference, name):
        # Reference 2026.10.20: the operation is an actor of its own, keyed by its name.
        assert reference.canonical_for(name) == cta.name_key(name)
        items = _HARNESS._collect([_pulse("p-ransom", [name], name, ["203.0.113.47"])])
        assert _actors(items) == [name]
        assert _malware(items) == [name], "the pulse's malware family item is unchanged"
        ioc = _ioc(items, "203.0.113.47")
        assert ioc["pulse_malware_actor_pairs"] == [f"{name}::{name}::p-ransom"], "the pulse attributes"

    @pytest.mark.parametrize("name,operator", OPERATIONS_OF_A_KNOWN_OPERATOR)
    def test_a_ransomware_operation_of_a_known_operator_stays_an_actor_counted_as_the_operator(
        self, reference, name, operator
    ):
        # Reference 2026.10.20: the name resolves to the operator, so the pulse keeps the actor; the actor
        # alias merge folds the node into the operator's node when the graph holds one.
        assert reference.canonical_for(name) == operator
        items = _HARNESS._collect([_pulse("p-operated", [name], name, ["203.0.113.49"])])
        assert _actors(items) == [name]
        assert _malware(items) == [name], "the pulse's malware family item is unchanged"
        assert _ioc(items, "203.0.113.49")["pulse_malware_actor_pairs"] == [f"{name}::{name}::p-operated"]

    def test_an_operation_beside_its_operator_names_one_actor(self):
        # Conti and Wizard Spider are one actor: the pulse attributes instead of counting two actors.
        items = _HARNESS._collect([_pulse("p-one", ["Conti"], "Wizard Spider, Conti", ["203.0.113.50"])])
        assert _actors(items) == ["Wizard Spider", "Conti"]
        ioc = _ioc(items, "203.0.113.50")
        assert ioc["several_actor_pulses"] == []
        assert ioc["pulse_malware_actor_pairs"] == ["Conti::Wizard Spider::p-one", "Conti::Conti::p-one"]

    def test_the_operations_are_the_override_decisions_of_2026_10_20(self):
        # The lists above and the docs count 29 operations, each one merge into a new key, and 3 operations
        # merged into the key of their operator.
        overrides = json.loads((_SRC / "reference" / "canonical_threat_actor_overrides.json").read_text())
        decisions = [d for d in overrides["merge"] if d["date"] == "2026-10-20"]
        own = {d["into"] for d in decisions if d["names"] == [d["into"]]}
        into_operator = {(n, d["into"]) for d in decisions if d["names"] != [d["into"]] for n in d["names"]}
        assert own == {cta.name_key(n) for n in RANSOMWARE_OPERATIONS}
        assert len(RANSOMWARE_OPERATIONS) == 29
        assert into_operator == {(cta.name_key(n), op) for n, op in OPERATIONS_OF_A_KNOWN_OPERATOR}
        assert own.isdisjoint(cta.name_key(n) for n in RANSOMWARE_NAMES_LEFT_OUT)

    def test_a_ransomware_operation_beside_a_known_actor_names_two_actors(self, reference):
        # Rhysida and Vanilla Tempest (Vice Society) are separate actors in the reference.
        assert (reference.canonical_for("Rhysida"), reference.canonical_for("Vice Society")) == (
            "rhysida",
            "vanilla tempest",
        )
        items = _HARNESS._collect([_pulse("p-two-groups", ["Rhysida"], "Rhysida, Vice Society", ["203.0.113.48"])])
        assert _actors(items) == ["Rhysida", "Vice Society"]
        ioc = _ioc(items, "203.0.113.48")
        assert ioc["pulse_malware_actor_pairs"] == [] and ioc["several_actor_pulses"] == ["p-two-groups"]

    def test_the_dropped_name_does_not_count_towards_several_actors(self):
        # Before 2026-10-18 "Agent Tesla" counted as a second actor: the pulse attributed nothing.
        items = _HARNESS._collect([_pulse("p-two", ["Agent Tesla"], "APT28, Agent Tesla", ["203.0.113.32"])])
        assert _actors(items) == ["APT28"]
        ioc = _ioc(items, "203.0.113.32")
        assert ioc["pulse_malware_actor_pairs"] == ["Agent Tesla::APT28::p-two"]
        assert all(i["several_actor_pulses"] == [] for i in items)

    def test_two_real_actors_beside_a_family_name_stay_several(self):
        items = _HARNESS._collect(
            [_pulse("p-three", ["Lumma Stealer"], "Gamaredon, Turla, Lumma Stealer", ["203.0.113.33"])]
        )
        assert _actors(items) == ["Gamaredon", "Turla"]
        ioc = _ioc(items, "203.0.113.33")
        assert ioc["pulse_malware_actor_pairs"] == [] and ioc["several_actor_pulses"] == ["p-three"]

    def test_names_are_compared_by_their_actor_key_and_without_the_attack_software_id(self):
        items = _HARNESS._collect(
            [
                _pulse("p-case", ["Lumma Stealer"], "  lumma   STEALER ", ["203.0.113.34"]),
                _pulse("p-sid", ["AsyncRAT - S1087"], "AsyncRAT", ["203.0.113.35"]),
                _pulse("p-obj", [{"name": "Agent Tesla"}], "agent tesla", ["203.0.113.36"]),
                _pulse("p-paren", ["Lumma Stealer (LummaC2)"], "Lumma Stealer (LummaC2)", ["203.0.113.44"]),
            ]
        )
        assert _actors(items) == []
        assert _ioc(items, "203.0.113.44")["pulse_malware_actor_pairs"] == []

    def test_every_family_of_the_pulse_counts_not_only_the_first_twenty(self):
        families = [f"Family{i:02d}" for i in range(25)] + ["Mirai"]
        items = _HARNESS._collect([_pulse("p-many", families, "Mirai", ["203.0.113.37"])])
        assert _actors(items) == []
        assert "Mirai" in _malware(items)

    def test_a_name_another_pulse_lists_as_malware_stays_an_actor(self):
        items = _HARNESS._collect(
            [
                _pulse("p-a", ["LockBit"], "", ["203.0.113.38"]),
                _pulse("p-b", ["StealBit"], "LockBit", ["203.0.113.39"]),
            ]
        )
        assert _actors(items) == ["LockBit"], "p-b does not list LockBit as a family"
        assert _ioc(items, "203.0.113.39")["pulse_malware_actor_pairs"] == ["StealBit::LockBit::p-b"]

    def test_the_run_logs_the_distinct_names_it_left_out(self, caplog):
        caplog.set_level(logging.INFO, logger=oc.logger.name)
        _HARNESS._collect(
            [
                _pulse("p-1", ["Lumma Stealer"], "Lumma Stealer", ["203.0.113.40"]),
                _pulse("p-2", ["Snake Keylogger"], "Snake Keylogger, Kimsuky", ["203.0.113.41"]),
                _pulse("p-3", ["Lumma Stealer"], "lumma stealer", ["203.0.113.45"]),
            ]
        )
        lines = [r.getMessage() for r in caplog.records if "[ACTOR-NAMES]" in r.getMessage()]
        assert len(lines) == 1
        assert lines[0].startswith("[ACTOR-NAMES] OTX: 2 distinct adversary name(s) in 3 pulse(s)")
        assert lines[0].endswith(": lumma stealer, snake keylogger"), "every distinct name, alphabetically"

    def test_without_the_reference_the_name_is_kept_and_the_warning_logged_once(self, monkeypatch, caplog):
        def unavailable(*_a, **_k):
            raise cta.ReferenceUnavailable("test: not found")

        monkeypatch.setattr(oc, "load_canonical_reference", unavailable)
        caplog.set_level(logging.WARNING, logger=oc.logger.name)
        items = _HARNESS._collect(
            [
                _pulse("p-1", ["Lumma Stealer"], "Lumma Stealer", ["203.0.113.42"]),
                _pulse("p-2", ["AsyncRAT"], "AsyncRAT", ["203.0.113.43"]),
            ]
        )
        assert sorted(_actors(items)) == ["AsyncRAT", "Lumma Stealer"], "the rule cannot decide without it"
        assert caplog.text.count("canonical reference unavailable") == 1


class TestTheHelper:
    def test_drops_only_unresolved_names_listed_as_a_family(self, reference):
        kept, dropped = oc._adversaries_not_named_as_pulse_families(
            ["Kimsuky", "Lumma Stealer", "APT28"], ["Kimsuky", "Lumma Stealer - S1213"], reference
        )
        assert kept == ["Kimsuky", "APT28"] and dropped == ["Lumma Stealer"]

    def test_a_family_with_a_trailing_parenthetical_is_compared_without_it(self, reference):
        kept, dropped = oc._adversaries_not_named_as_pulse_families(
            ["Lumma Stealer"], ["Lumma Stealer (LummaC2)"], reference
        )
        assert kept == [] and dropped == ["Lumma Stealer"]

    def test_an_ambiguous_name_counts_as_unknown(self, reference):
        # The reference lists "winnti" as ambiguous between apt41 and winnti group.
        assert reference.canonical_for("Winnti") is None
        assert oc._adversaries_not_named_as_pulse_families(["Winnti"], ["Winnti"], reference) == ([], ["Winnti"])

    def test_without_the_reference_or_families_nothing_is_dropped(self, reference):
        assert oc._adversaries_not_named_as_pulse_families(["Lumma Stealer"], ["Lumma Stealer"], None) == (
            ["Lumma Stealer"],
            [],
        )
        assert oc._adversaries_not_named_as_pulse_families(["Lumma Stealer"], [], reference) == (
            ["Lumma Stealer"],
            [],
        )
        assert oc._adversaries_not_named_as_pulse_families([], ["Lumma Stealer"], reference) == ([], [])
