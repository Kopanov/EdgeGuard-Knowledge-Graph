"""Canonical threat-actor reference (2026-10): the generator's rules and the committed file.

``scripts/build_canonical_threat_actors.py`` turns the MISP galaxy threat-actor clusters, the ATT&CK
revocations and the ATT&CK version EdgeGuard loaded into ``src/reference/canonical_threat_actors.json``:
canonical actors (anchored by ATT&CK), their synonyms, and the names that are ambiguous. The rules
are tested on small fixtures; the committed file is checked for consistency (the inputs it is built
from are not in the repository).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import random
import re
import sys
import unicodedata
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from node_identity import canonicalize_merge_key  # noqa: E402

REFERENCE = _SRC / "reference" / "canonical_threat_actors.json"
OVERRIDES = _SRC / "reference" / "canonical_threat_actor_overrides.json"


@pytest.fixture(scope="module")
def gen():
    spec = importlib.util.spec_from_file_location(
        "build_canonical_threat_actors", _ROOT / "scripts" / "build_canonical_threat_actors.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod  # dataclasses resolve their annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- fixtures

_counter = iter(range(1, 100000))


def rec(galaxy, name, aliases=(), attack=None):
    """One record of the galaxy entities export."""
    uuid = f"00000000-0000-0000-0000-{next(_counter):012d}"
    external = {"misp_galaxy_uuid": uuid}
    if attack:
        external["mitre_attack"] = attack
    return {
        "name": name,
        "name_key": name.lower(),
        "aliases": [{"name": a, "name_key": a.lower(), "source_field": "synonyms"} for a in aliases],
        "external_ids": external,
        "provenance": {
            "source_record": f"{galaxy}/{uuid}",
            "source_version": f"galaxy {galaxy} v1; cluster v1",
            "raw_file": f"open/raw/misp_galaxy_{galaxy}_20261013.json",
            "raw_sha256": "0" * 64,
        },
    }


def mitre(name, attack, aliases=()):
    return rec("mitre-intrusion-set", f"{name} - {attack}", aliases, attack)


def ta(name, aliases=(), attack=None):
    return rec("threat-actor", name, aliases, attack)


def ms(name, aliases=()):
    return rec("microsoft-activity-group", name, aliases)


def doc(*records):
    return {"dataset": "galaxy_threat_actors", "schema_version": "1.0", "records": list(records)}


def overrides(merge=(), never_merge=(), canonical_name=()):
    common = {"reason": "test decision", "date": "2026-10-15", "status": "proposed"}
    return {
        "schema_version": 1,
        "merge": [{**common, **m} for m in merge],
        "never_merge": [{**common, **n} for n in never_merge],
        "canonical_name": [{**common, **c} for c in canonical_name],
    }


def build(gen, *records, ovr=None, revocations=None, loaded=()):
    return gen.build_reference(
        doc(*records), ovr or overrides(), version="2026.10.15", revocations=revocations, loaded_attack=loaded
    )


def node(name, aliases=(), source=("mitre_attck",), relationships=0, attack_id=None, malware=()):
    """One row of a graph export (``--export-graph-actors``)."""
    return {
        "name": name,
        "aliases": list(aliases),
        "source": list(source),
        "relationships": relationships,
        "pulses": 0,
        "malware": list(malware),
        "attack_id": attack_id,
    }


def loaded(gen, *nodes):
    """The loaded ATT&CK version: ATT&CK-sourced graph rows."""
    return gen.load_loaded_attack(gen.load_graph_actors(list(nodes)))


def actors(reference):
    return {a["key"]: a for a in reference["actors"]}


def owner(reference, name):
    """The actor key a name resolves to, "AMBIGUOUS", or None."""
    for a in reference["actors"]:
        if name == a["key"] or name in a["synonyms"]:
            return a["key"]
    if any(e["key"] == name for e in reference["ambiguous"]):
        return "AMBIGUOUS"
    return None


def origins_of(actor, synonym):
    return sorted(o for o, names in actor["synonym_origins"].items() if synonym in names)


# --------------------------------------------------------------------------- keys


class TestKeys:
    @pytest.mark.parametrize("name", ["Lazarus Group", "  APT28 ", "Café Group", "ÉQUATION"])
    def test_actor_key_is_the_merge_key_edgeguard_writes(self, gen, name):
        assert gen.actor_key(name) == canonicalize_merge_key("ThreatActor", {"name": name})["name"]
        assert gen.actor_key(name) == unicodedata.normalize("NFC", name).strip().lower()

    def test_attack_suffix_is_stripped(self, gen):
        assert gen.strip_attack_suffix("Lazarus Group - G0032") == "Lazarus Group"
        assert gen.strip_attack_suffix("Threat Group-3390") == "Threat Group-3390"

    def test_input_name_key_is_not_trusted(self, gen):
        # The export's name_key is NFKC (U+2011 -> U+2010); EdgeGuard keeps the NFC form.
        record = ta("Larva‑25012")
        record["name_key"] = "larva‐25012"
        ref, _ = build(gen, record)
        assert list(actors(ref)) == ["larva‑25012"]


# --------------------------------------------------------------------------- rule 1


class TestAnchoring:
    def test_records_with_one_attack_id_are_one_actor_named_after_attack(self, gen):
        ref, stats = build(
            gen,
            mitre("Lazarus Group", "G0032", ["Labyrinth Chollima", "HIDDEN COBRA"]),
            ta("Lazarus Group", ["Hidden Cobra", "Guardians of Peace"], attack="G0032"),
            ta("Bureau 121", attack="G0032"),
        )
        a = actors(ref)
        assert list(a) == ["lazarus group"]
        assert a["lazarus group"]["name"] == "Lazarus Group"
        assert a["lazarus group"]["mitre_attack"] == "G0032"
        assert len(a["lazarus group"]["records"]) == 3
        assert {"labyrinth chollima", "hidden cobra", "guardians of peace", "bureau 121"} <= set(
            a["lazarus group"]["synonyms"]
        )
        assert origins_of(a["lazarus group"], "hidden cobra") == ["misp_galaxy:threat-actor", "mitre"]
        assert stats.attack_groups == 1

    def test_record_named_after_another_attack_group_is_not_anchored_by_its_id(self, gen):
        # The galaxy gives APT19 the ids G0009 and G0073; the export kept G0009 (Deep Panda).
        ref, stats = build(
            gen,
            mitre("Deep Panda", "G0009", ["Black Vine"]),
            mitre("APT19", "G0073", ["Codoso"]),
            ta("APT19", ["C0d0so", "Sunshop Group"], attack="G0009"),
        )
        a = actors(ref)
        assert "c0d0so" in a["apt19"]["synonyms"]
        assert "c0d0so" not in a["deep panda"]["synonyms"]
        assert [c["attack_name_of"] for c in stats.anchor_conflicts] == ["G0073"]

    def test_attack_ids_listed_as_synonyms_are_dropped(self, gen):
        ref, stats = build(gen, mitre("APT17", "G0025"), ta("APT17", ["G0025", "G0001", "Deputy Dog"], attack="G0025"))
        synonyms = actors(ref)["apt17"]["synonyms"]
        assert "deputy dog" in synonyms
        assert not [s for s in synonyms if re.fullmatch(r"g\d{4}", s)]
        assert stats.dropped_attack_id_synonyms == 2
        assert [d["synonym"] for d in stats.dropped_attack_id_synonyms_of_other_groups] == ["G0001"]

    def test_synonyms_are_taken_as_edgeguard_writes_them(self, gen):
        # The actor-name hygiene drops a trailing parenthetical and splits lists before MERGE.
        ref, stats = build(
            gen, ta("COBALT KATANA", ["xHunt campaign (Example Lab)", "Waterbug, Venomous Bear", "APT-Q-27,"])
        )
        synonyms = actors(ref)["cobalt katana"]["synonyms"]
        assert {"xhunt campaign", "apt-q-27"} <= set(synonyms)
        assert not [s for s in synonyms if "(" in s or "," in s or "waterbug" in s]
        assert len(stats.synonyms_rewritten_by_name_hygiene) == 2
        assert [d["synonym"] for d in stats.synonyms_dropped_by_name_hygiene] == ["Waterbug, Venomous Bear"]

    def test_placeholder_synonyms_are_dropped(self, gen):
        ref, stats = build(gen, ta("Some Actor", ["unknown", "N/A", "Real Alias"]))
        assert actors(ref)["some actor"]["synonyms"][0] == "real alias"
        assert stats.dropped_placeholder_names == 2


# --------------------------------------------------------------------------- rule 2


class TestPrimaryNameJoin:
    def _base(self):
        return [
            mitre("Sandworm Team", "G0034", ["ELECTRUM", "Voodoo Bear"]),
            ta("Sandworm", ["Telebots"], attack="G0034"),
        ]

    @pytest.mark.parametrize(
        "record, how",
        [
            (rec("mitre-ics-groups", "Sandworm Team"), "key"),
            (ms("Voodoo Bear", ["Seashell Blizzard"]), "attack_alias"),
            (rec("mitre-ics-groups", "Sandworm"), "record_name"),
        ],
    )
    def test_record_joins_by_key_attack_alias_or_anchored_record_name(self, gen, record, how):
        ref, stats = build(gen, *self._base(), record)
        assert list(actors(ref)) == ["sandworm team"]
        assert stats.joined == {how: 1}

    def test_threesixty_name_joins_without_its_group_id(self, gen):
        ref, _ = build(gen, *self._base(), rec("360net-threat-actor", "Sandworm Team - APT-C-13", ["Karba"]))
        a = actors(ref)
        assert list(a) == ["sandworm team"]
        assert {"sandworm team - apt-c-13", "karba"} <= set(a["sandworm team"]["synonyms"])

    def test_spacing_variant_joins_and_the_exact_name_wins(self, gen):
        ref, stats = build(
            gen,
            mitre("Saint Bear", "G1031", ["Lorec53"]),
            mitre("Turla", "G0010", ["WhiteBear"]),
            ta("SaintBear", ["UAC-0056"]),
            ta("White Bear"),
        )
        a = actors(ref)
        assert set(a) == {"saint bear", "turla"}
        assert "saintbear" in a["saint bear"]["synonyms"]
        assert "white bear" in a["turla"]["synonyms"]
        assert stats.joined == {"attack_alias (spacing)": 1, "key (spacing)": 1}

    def test_unmatched_spacing_variants_form_one_actor(self, gen):
        ref, _ = build(gen, ms("Cyber Av3ngers"), ta("CyberAv3ngers", ["Soldiers of Solomon"]))
        a = actors(ref)
        assert list(a) == ["cyberav3ngers"]  # the threat-actor galaxy value names it
        assert {"cyber av3ngers", "soldiers of solomon"} <= set(a["cyberav3ngers"]["synonyms"])
        assert gen.compact_key("apt-c-23") == gen.compact_key("apt c.23") == "aptc23"

    def test_name_of_two_attack_groups_does_not_join(self, gen):
        ref, stats = build(
            gen,
            mitre("APT29", "G0016", ["NOBELIUM"]),
            mitre("UNC2452", "G0118", ["NOBELIUM"]),
            ms("NOBELIUM"),
        )
        assert set(actors(ref)) == {"apt29", "unc2452", "nobelium"}
        assert stats.join_ambiguous[0]["candidates"] == ["apt29", "unc2452"]

    def test_attack_key_outranks_another_groups_alias(self, gen):
        ref, _ = build(gen, mitre("APT29", "G0016", ["UNC2452"]), mitre("UNC2452", "G0118"), ta("UNC2452"))
        a = actors(ref)
        assert set(a) == {"apt29", "unc2452"}
        assert len(a["unc2452"]["records"]) == 2
        assert "unc2452" not in a["apt29"]["synonyms"]

    def test_unmatched_records_with_one_name_form_one_actor_named_by_galaxy_priority(self, gen):
        ref, _ = build(gen, ms("RAZOR TIGER"), rec("360net-threat-actor", "razor tiger"), ta("Razor Tiger"))
        a = actors(ref)
        assert list(a) == ["razor tiger"]
        assert a["razor tiger"]["name"] == "Razor Tiger"  # the threat-actor galaxy value
        assert a["razor tiger"]["mitre_attack"] is None
        assert len(a["razor tiger"]["records"]) == 3


# --------------------------------------------------------------------------- rules 3 and 4


class TestSynonymsAndAmbiguity:
    def test_synonyms_never_bridge_two_actors(self, gen):
        # Star Blizzard lists Callisto as a synonym; Callisto stays its own actor.
        ref, _ = build(gen, ms("Star Blizzard", ["Callisto", "SEABORGIUM"]), ta("Callisto", ["COLDRIVER"]))
        a = actors(ref)
        assert set(a) == {"star blizzard", "callisto"}
        assert "callisto" not in a["star blizzard"]["synonyms"]
        assert "coldriver" in a["callisto"]["synonyms"]
        assert "seaborgium" not in a["callisto"]["synonyms"]

    def test_name_claimed_by_two_actors_is_ambiguous(self, gen):
        ref, _ = build(gen, ta("APT17", ["Aurora Panda"]), ms("Heart Typhoon", ["Aurora Panda"]))
        entry = next(e for e in ref["ambiguous"] if e["key"] == "aurora panda")
        assert entry["actors"] == ["apt17", "heart typhoon"]
        assert owner(ref, "aurora panda") == "AMBIGUOUS"

    def test_primary_key_exception(self, gen):
        # "andariel" is MITRE's own group, so it is not a Lazarus Group synonym.
        ref, stats = build(
            gen,
            mitre("Lazarus Group", "G0032"),
            ta("Lazarus Group", ["Andariel", "Bluenoroff"], attack="G0032"),
            mitre("Andariel", "G0138", ["Silent Chollima"]),
        )
        a = actors(ref)
        assert "andariel" not in a["lazarus group"]["synonyms"]
        assert owner(ref, "andariel") == "andariel"
        assert owner(ref, "bluenoroff") == "lazarus group"
        assert stats.actor_keys_claimed_elsewhere == 1

    def test_attack_alias_outranks_a_galaxy_synonym_of_another_actor(self, gen):
        ref, stats = build(
            gen,
            mitre("APT28", "G0007", ["Fancy Bear"]),
            rec("360net-threat-actor", "Fancy-Bear-CN - APT-C-20", ["Fancy Bear"]),
        )
        assert owner(ref, "fancy bear") == "apt28"
        assert stats.contested_resolved[0]["over"] == ["fancy-bear-cn - apt-c-20"]

    def test_two_attack_groups_listing_one_alias_make_it_ambiguous(self, gen):
        ref, _ = build(gen, mitre("APT29", "G0016", ["Dark Halo"]), mitre("UNC2452", "G0118", ["Dark Halo"]))
        assert owner(ref, "dark halo") == "AMBIGUOUS"


# --------------------------------------------------------------------------- rule 5


class TestSuffixRule:
    @pytest.mark.parametrize(
        "key, variants",
        [
            ("sandworm team", ["sandworm"]),
            ("gamaredon group", ["gamaredon"]),
            ("turla", ["turla group", "turla team"]),
            ("313 team", []),
            ("ab group", []),
            ("threat group-3390", []),
            ("group 72", []),
        ],
    )
    def test_variants(self, gen, key, variants):
        assert gen.suffix_variants(key) == variants

    def test_suffix_variant_of_key_and_attack_alias(self, gen):
        ref, _ = build(gen, mitre("Sandworm Team", "G0034", ["Telebots"]))
        a = actors(ref)["sandworm team"]
        assert {"sandworm", "telebots group", "telebots team"} <= set(a["synonyms"])
        assert origins_of(a, "sandworm") == ["suffix_rule"]

    def test_not_added_when_another_actor_claims_it(self, gen):
        ref, stats = build(gen, mitre("Gamaredon Group", "G0047"), ta("Gamaredon"))
        assert owner(ref, "gamaredon") == "gamaredon"
        assert "gamaredon" not in actors(ref)["gamaredon group"]["synonyms"]
        assert stats.suffix_blocked >= 1

    def test_variant_two_actors_would_get_is_ambiguous(self, gen):
        ref, _ = build(gen, ta("Daixin Team"), ms("Daixin Group"))
        assert owner(ref, "daixin") == "AMBIGUOUS"

    def test_existing_synonym_gains_the_origin(self, gen):
        # Aqua Blizzard joins Gamaredon Group (an ATT&CK alias) and brings the synonym "Gamaredon".
        ref, stats = build(
            gen, mitre("Gamaredon Group", "G0047", ["Aqua Blizzard"]), ms("Aqua Blizzard", ["Gamaredon"])
        )
        a = actors(ref)["gamaredon group"]
        assert origins_of(a, "gamaredon") == ["misp_galaxy:microsoft-activity-group", "suffix_rule"]
        assert stats.suffix_also_existing == 1


# --------------------------------------------------------------------------- rule 6


class TestOverrides:
    def test_merge_adds_a_name_and_wins_over_the_rules(self, gen):
        records = [mitre("Lazarus Group", "G0032"), ms("Diamond Sleet", ["Lazarus"]), ms("Onyx Sleet", ["Lazarus"])]
        ref, _ = build(gen, *records)
        assert owner(ref, "lazarus") == "AMBIGUOUS"
        ref, stats = build(gen, *records, ovr=overrides(merge=[{"names": ["Lazarus"], "into": "lazarus group"}]))
        assert owner(ref, "lazarus") == "lazarus group"
        assert origins_of(actors(ref)["lazarus group"], "lazarus") == ["override"]
        assert "resolved ambiguous" in stats.overrides[0]["effect"][0]

    def test_merge_creates_an_actor_and_folds_a_standalone_one(self, gen):
        ovr = overrides(
            merge=[{"names": ["interlock ransomware", "Interlock Gang"], "into": "interlock"}],
            canonical_name=[{"key": "interlock", "name": "Interlock"}],
        )
        ref, _ = build(gen, ta("Interlock Gang", ["Nefarious Spider"]), ovr=ovr)
        a = actors(ref)
        assert list(a) == ["interlock"]
        assert a["interlock"]["name"] == "Interlock"
        # The folded actor keeps its synonyms, its suffix-rule variants included.
        assert a["interlock"]["synonyms"] == [
            "interlock gang",
            "interlock gang group",
            "interlock gang team",
            "interlock ransomware",
            "nefarious spider",
        ]
        assert origins_of(a["interlock"], "interlock gang") == ["override"]
        assert "override" in a["interlock"]["origins"]

    def test_merge_never_folds_an_attack_group(self, gen):
        ovr = overrides(merge=[{"names": ["andariel"], "into": "lazarus group"}])
        with pytest.raises(gen.ReferenceInputError, match="ATT&CK groups are never merged"):
            build(gen, mitre("Lazarus Group", "G0032"), mitre("Andariel", "G0138"), ovr=ovr)

    def test_merge_into_a_synonym_is_refused(self, gen):
        ovr = overrides(merge=[{"names": ["x"], "into": "telebots"}])
        with pytest.raises(gen.ReferenceInputError, match="synonym of 'sandworm team'"):
            build(gen, mitre("Sandworm Team", "G0034", ["Telebots"]), ovr=ovr)

    def test_never_merge_removes_a_suffix_rule_synonym(self, gen):
        records = [mitre("Medusa Group", "G1051")]
        ref, _ = build(gen, *records)
        assert owner(ref, "medusa") == "medusa group"
        ref, _ = build(gen, *records, ovr=overrides(never_merge=[{"names": ["Medusa"]}]))
        assert owner(ref, "medusa") == "AMBIGUOUS"
        entry = next(e for e in ref["ambiguous"] if e["key"] == "medusa")
        assert entry["actors"] == ["medusa group"]
        assert entry["never_merge"]["status"] == "proposed"

    def test_never_merge_on_an_actor_key_is_refused(self, gen):
        with pytest.raises(gen.ReferenceInputError, match="key of an actor"):
            build(gen, ta("Bert"), ovr=overrides(never_merge=[{"names": ["bert"]}]))

    def test_canonical_name_rekeys_and_keeps_the_old_key(self, gen):
        ovr = overrides(canonical_name=[{"key": "unc1549", "name": "Nimbus Manticore"}])
        ref, _ = build(gen, ta("UNC1549", ["Nimbus Manticore", "TA455"]), ovr=ovr)
        a = actors(ref)
        assert list(a) == ["nimbus manticore"]
        assert a["nimbus manticore"]["name"] == "Nimbus Manticore"
        # The suffix rule ran on the galaxy key, before the override.
        assert a["nimbus manticore"]["synonyms"] == ["ta455", "unc1549", "unc1549 group", "unc1549 team"]
        assert origins_of(a["nimbus manticore"], "unc1549") == ["misp_galaxy:threat-actor", "override"]

    def test_canonical_name_rekey_carries_ambiguous_claims(self, gen):
        ovr = overrides(canonical_name=[{"key": "unc1549", "name": "Nimbus Manticore"}])
        ref, _ = build(gen, ta("UNC1549", ["Nimbus Manticore", "TA455"]), ms("Smoke Sandstorm", ["TA455"]), ovr=ovr)
        entry = next(e for e in ref["ambiguous"] if e["key"] == "ta455")
        assert entry["actors"] == ["nimbus manticore", "smoke sandstorm"]

    def test_canonical_name_never_rekeys_an_attack_group(self, gen):
        ovr = overrides(canonical_name=[{"key": "apt28", "name": "Fancy Bear"}])
        with pytest.raises(gen.ReferenceInputError, match="ATT&CK name"):
            build(gen, mitre("APT28", "G0007", ["Fancy Bear"]), ovr=ovr)

    def test_folding_an_actor_gives_the_target_the_names_only_the_two_claimed(self, gen):
        records = [ta("Storm-0062", ["DarkShadow", "Oro0lxy"]), ms("Shadow Typhoon", ["DarkShadow", "Oro0lxy"])]
        ref, _ = build(gen, *records, ta("Other", ["Oro0lxy"]))
        assert owner(ref, "darkshadow") == owner(ref, "oro0lxy") == "AMBIGUOUS"
        ovr = overrides(merge=[{"names": ["storm-0062"], "into": "shadow typhoon"}])
        ref, stats = build(gen, *records, ta("Other", ["Oro0lxy"]), ovr=ovr)
        assert owner(ref, "storm-0062") == owner(ref, "darkshadow") == "shadow typhoon"
        entry = next(e for e in ref["ambiguous"] if e["key"] == "oro0lxy")  # a third actor still claims it
        assert entry["actors"] == ["other", "shadow typhoon"]
        assert any("resolved ambiguous 'darkshadow'" in e for e in stats.overrides[0]["effect"])

    @pytest.mark.parametrize(
        "ovr, message",
        [
            (
                overrides(merge=[{"names": ["a b"], "into": "x"}], never_merge=[{"names": ["a b"]}]),
                "both merged and never_merge",
            ),
            (
                overrides(merge=[{"names": ["a b"], "into": "x"}, {"names": ["a b"], "into": "y"}]),
                "merged into two actors",
            ),
            (overrides(merge=[{"names": ["x"], "into": "y"}, {"names": ["y"], "into": "z"}]), "themselves merged"),
            (
                {"merge": [{"names": ["a"], "into": "b", "reason": "r", "date": "2026-13-01", "status": "proposed"}]},
                "date",
            ),
            (
                {"merge": [{"names": ["a"], "into": "b", "reason": "r", "date": "2026-10-15", "status": "maybe"}]},
                "status",
            ),
            ({"merge": [{"names": ["a"], "into": "b", "date": "2026-10-15", "status": "proposed"}]}, "reason"),
            ({"unknown": []}, "unknown sections"),
        ],
    )
    def test_invalid_overrides_are_refused(self, gen, ovr, message):
        with pytest.raises(gen.ReferenceInputError, match=message):
            gen.load_overrides(ovr)


# --------------------------------------------------------------------------- ATT&CK revocations


class TestRevokedGroups:
    def test_revoked_group_folds_into_its_successor(self, gen):
        ref, stats = build(
            gen,
            mitre("Charming Kitten", "G0058", ["Newscaster"]),
            mitre("Magic Hound", "G0059", ["Mint Sandstorm"]),
            ta("Charming Kitten", ["Ajax Team"], attack="G0058"),
            revocations={"G0058": "G0059"},
        )
        a = actors(ref)
        assert list(a) == ["magic hound"]
        # the revoked group's ATT&CK name, and the name of the galaxy record that carried its id
        assert origins_of(a["magic hound"], "charming kitten") == ["misp_galaxy:threat-actor", "mitre_revoked"]
        assert origins_of(a["magic hound"], "newscaster") == ["mitre_revoked"]
        assert "ajax team" in a["magic hound"]["synonyms"]
        assert "mitre_revoked" in a["magic hound"]["origins"]
        assert ref["revoked_attack_groups"] == [
            {
                "mitre_attack": "G0058",
                "name": "Charming Kitten",
                "key": "charming kitten",
                "revoked_into": "G0059",
                "actor": "magic hound",
            }
        ]
        assert stats.revoked_folds[0]["successor"] == "magic hound"

    def test_a_name_two_groups_shared_has_one_owner_after_the_fold(self, gen):
        records = [
            mitre("APT29", "G0016", ["NOBELIUM", "Dark Halo"]),
            mitre("UNC2452", "G0118", ["NOBELIUM", "Dark Halo"]),
            ms("NOBELIUM", ["Midnight Blizzard"]),
        ]
        ref, _ = build(gen, *records)
        assert owner(ref, "dark halo") == "AMBIGUOUS"
        assert "nobelium" in actors(ref)  # its own actor: the name of two ATT&CK groups
        ref, stats = build(gen, *records, revocations={"G0118": "G0016"})
        assert list(actors(ref)) == ["apt29"]
        assert owner(ref, "nobelium") == owner(ref, "dark halo") == owner(ref, "unc2452") == "apt29"
        assert owner(ref, "midnight blizzard") == "apt29"
        assert stats.join_ambiguous == []

    def test_record_carrying_a_revoked_id_is_no_anchor_conflict(self, gen):
        # Kimsuky's galaxy record carries G0086 (Stolen Pencil), which ATT&CK revoked into Kimsuky.
        ref, stats = build(
            gen,
            mitre("Kimsuky", "G0094"),
            mitre("Stolen Pencil", "G0086"),
            ta("Kimsuky", ["Velvet Chollima"], attack="G0086"),
            revocations={"G0086": "G0094"},
        )
        assert stats.anchor_conflicts == []
        assert {"stolen pencil", "velvet chollima"} <= set(actors(ref)["kimsuky"]["synonyms"])

    def test_revocation_chains_and_cycles(self, gen):
        ref, _ = build(
            gen,
            mitre("A", "G0001"),
            mitre("B", "G0002"),
            mitre("C", "G0003"),
            revocations={"G0001": "G0002", "G0002": "G0003"},
        )
        assert list(actors(ref)) == ["c"]
        with pytest.raises(gen.ReferenceInputError, match="cycle"):
            build(gen, mitre("A", "G0001"), mitre("B", "G0002"), revocations={"G0001": "G0002", "G0002": "G0001"})

    def test_revocations_are_read_from_the_raw_galaxy_dump(self, gen):
        def cluster(uuid, value, attack_id, revoked_by=None):
            relations = (
                [{"referenced_galaxy_cluster_type": "revoked-by", "referenced_galaxy_cluster_uuid": revoked_by}]
                if revoked_by
                else [{"referenced_galaxy_cluster_type": "uses", "referenced_galaxy_cluster_uuid": "x"}]
            )
            return {
                "GalaxyCluster": {
                    "uuid": uuid,
                    "value": value,
                    "GalaxyElement": [{"key": "external_id", "value": attack_id}],
                    "GalaxyClusterRelation": relations,
                }
            }

        raw = {
            "payload": {
                "response": [
                    cluster("u1", "UNC2452 - G0118", "G0118", revoked_by="u2"),
                    cluster("u2", "APT29 - G0016", "G0016"),
                ]
            }
        }
        assert gen.load_revocations(raw) == {"G0118": "G0016"}
        with pytest.raises(gen.ReferenceInputError):
            gen.load_revocations({"payload": {"response": []}})


# --------------------------------------------------------------------------- the loaded ATT&CK version


class TestLoadedAttack:
    def test_loaded_aliases_are_the_strongest_claims_and_join_records(self, gen):
        records = [mitre("APT28", "G0007", ["Fancy Bear"]), ms("Forest Blizzard", ["STRONTIUM"])]
        ref, _ = build(gen, *records)
        assert "forest blizzard" in actors(ref)  # the galaxy copy does not list it
        attack = loaded(gen, node("apt28", ["APT28", "Fancy Bear", "Forest Blizzard"], attack_id="G0007"))
        ref, stats = build(gen, *records, loaded=attack)
        a = actors(ref)
        assert list(a) == ["apt28"]
        assert origins_of(a["apt28"], "forest blizzard") == ["misp_galaxy:microsoft-activity-group", "mitre_loaded"]
        assert "strontium" in a["apt28"]["synonyms"]
        assert "mitre_loaded" in a["apt28"]["origins"]
        assert stats.loaded_groups == 1

    def test_loaded_alias_outranks_an_older_galaxy_alias(self, gen):
        ref, stats = build(
            gen,
            mitre("Group A", "G0001", ["Shared Name"]),
            mitre("Group B", "G0002"),
            loaded=loaded(gen, node("group b", ["Group B", "Shared Name"])),
        )
        assert owner(ref, "shared name") == "group b"
        assert stats.contested_resolved[0] == {"name": "shared name", "actor": "group b", "over": ["group a"]}

    def test_an_actor_key_still_outranks_a_loaded_alias(self, gen):
        # ATT&CK lists Thrip as an alias of Lotus Blossom while Thrip is its own group.
        ref, _ = build(
            gen,
            mitre("Lotus Blossom", "G0030"),
            mitre("Thrip", "G0076"),
            loaded=loaded(gen, node("lotus blossom", ["Lotus Blossom", "Thrip"])),
        )
        assert owner(ref, "thrip") == "thrip"

    def test_group_missing_from_the_galaxy_is_anchored_by_name(self, gen):
        ref, stats = build(
            gen,
            ta("UNC1549", ["Nimbus Manticore", "Smoke Sandstorm"]),
            loaded=loaded(gen, node("nimbus manticore", ["NIMBUS MANTICORE", "UNC1549", "TA455"], attack_id="G1059")),
        )
        a = actors(ref)
        assert list(a) == ["nimbus manticore"]
        assert (a["nimbus manticore"]["name"], a["nimbus manticore"]["mitre_attack"]) == ("NIMBUS MANTICORE", "G1059")
        assert {"unc1549", "ta455", "smoke sandstorm"} <= set(a["nimbus manticore"]["synonyms"])
        assert stats.loaded_anchored == [{"key": "nimbus manticore", "mitre_attack": "G1059"}]

    def test_group_renamed_in_the_loaded_version_takes_the_loaded_name(self, gen):
        ref, stats = build(
            gen,
            mitre("Old Name", "G1234", ["Alias"]),
            loaded=loaded(gen, node("new name", ["New Name"], attack_id="G1234")),
        )
        a = actors(ref)
        assert list(a) == ["new name"]
        assert a["new name"]["mitre_attack"] == "G1234"
        assert {"old name", "alias"} <= set(a["new name"]["synonyms"])
        assert stats.loaded_renamed == [{"mitre_attack": "G1234", "galaxy": "old name", "loaded": "new name"}]

    def test_revoked_group_still_loaded_goes_to_its_successor(self, gen):
        ref, stats = build(
            gen,
            mitre("APT29", "G0016"),
            mitre("UNC2452", "G0118"),
            revocations={"G0118": "G0016"},
            loaded=loaded(gen, node("apt29", ["APT29"]), node("unc2452", ["UNC2452", "StellarParticle"])),
        )
        a = actors(ref)
        assert list(a) == ["apt29"]
        assert origins_of(a["apt29"], "stellarparticle") == ["mitre_revoked"]
        assert stats.loaded_revoked_nodes == [{"node": "unc2452", "successor": "apt29"}]

    def test_loaded_rows_are_read_like_synonyms(self, gen):
        rows = [
            node("sandworm team", ["Sandworm Team", "BlackEnergy (Group)", "G0034", "unknown"], attack_id="G0034"),
            node("sandworm", [], source=("alienvault_otx",)),
            node("bad", [], attack_id="not-an-id"),
        ]
        groups = gen.load_loaded_attack(gen.load_graph_actors(rows))
        assert [(g.key, g.name, g.attack_id, g.aliases) for g in groups] == [
            ("bad", "bad", None, ()),
            ("sandworm team", "Sandworm Team", "G0034", ("blackenergy",)),
        ]

    def test_export_rows_keep_the_attack_id_not_the_description(self, gen):
        rows = gen.export_rows(
            [
                {
                    "name": "nimbus manticore",
                    "aliases": ["NIMBUS MANTICORE"],
                    "source": ["mitre_attck"],
                    "relationships": 3,
                    "pulses": 1,
                    "malware": ["minifast", "minifast", None],
                    "attack_description": "[NIMBUS MANTICORE](https://attack.mitre.org/groups/G1059) is ...",
                },
                {"name": "x", "aliases": None, "source": ["alienvault_otx"], "attack_description": None},
            ]
        )
        assert rows[0]["attack_id"] == "G1059" and rows[0]["malware"] == ["minifast"]
        assert "attack_description" not in rows[0]
        assert rows[1]["attack_id"] is None


# --------------------------------------------------------------------------- never_merge with an actor


class TestNeverMergePairs:
    def test_a_name_kept_away_from_an_actor_can_be_its_own_actor(self, gen):
        ovr = overrides(
            merge=[{"names": ["silverfox", "silver fox apt"], "into": "silver fox"}],
            never_merge=[{"names": ["Silver Fox"], "actor": "void arachne"}],
        )
        ref, _ = build(gen, ta("Void Arachne", ["Silver Fox", "Winos"]), ovr=ovr)
        a = actors(ref)
        assert set(a) == {"void arachne", "silver fox"}
        assert "silver fox" not in a["void arachne"]["synonyms"]
        assert a["silver fox"]["synonyms"] == ["silver fox apt", "silverfox"]
        assert [(p["name"], p["actor"]) for p in ref["never_merge_pairs"]] == [("silver fox", "void arachne")]

    def test_a_name_kept_away_and_owned_by_nobody_is_never_merged(self, gen):
        ovr = overrides(never_merge=[{"names": ["famous chollima"], "actor": "wagemole"}])
        ref, _ = build(gen, ta("Wagemole", ["Famous Chollima"]), ovr=ovr)
        entry = next(e for e in ref["ambiguous"] if e["key"] == "famous chollima")
        assert entry["actors"] == ["wagemole"]
        assert entry["never_merge"]["actor"] == "wagemole"
        assert owner(ref, "famous chollima") == "AMBIGUOUS"

    def test_merging_a_name_into_the_actor_it_is_kept_from_is_refused(self, gen):
        ovr = overrides(
            merge=[{"names": ["silver fox"], "into": "void arachne"}],
            never_merge=[{"names": ["silver fox"], "actor": "void arachne"}],
        )
        with pytest.raises(gen.ReferenceInputError, match="kept away from"):
            gen.load_overrides(ovr)

    def test_the_actor_must_exist(self, gen):
        with pytest.raises(gen.ReferenceInputError, match="no actor has that key"):
            build(gen, ta("Wagemole"), ovr=overrides(never_merge=[{"names": ["x y"], "actor": "nobody"}]))


# --------------------------------------------------------------------------- determinism + report


def _sample(gen):
    return [
        mitre("Sandworm Team", "G0034", ["ELECTRUM", "Voodoo Bear"]),
        ta("Sandworm", ["Telebots"], attack="G0034"),
        mitre("Lazarus Group", "G0032", ["HIDDEN COBRA"]),
        ta("Lazarus Group", ["Andariel", "Lazarus"], attack="G0032"),
        mitre("Andariel", "G0138"),
        ms("Seashell Blizzard", ["Sandworm", "IRIDIUM"]),
        ms("Heart Typhoon", ["Aurora Panda"]),
        ta("APT17", ["Aurora Panda"]),
        rec("360net-threat-actor", "Lazarus - APT-C-26", ["APT38"]),
    ]


class TestDeterminism:
    def test_same_inputs_give_identical_bytes_in_any_record_order(self, gen):
        records = _sample(gen)
        ovr = overrides(merge=[{"names": ["lazarus"], "into": "lazarus group"}], never_merge=[{"names": ["medusa"]}])
        first = gen.serialize_reference(gen.build_reference(doc(*records), ovr, version="2026.10.15")[0])
        shuffled = list(records)
        random.Random(7).shuffle(shuffled)
        second = gen.serialize_reference(gen.build_reference(doc(*shuffled), ovr, version="2026.10.15")[0])
        assert first == second
        assert first.endswith("}\n")

    def test_version_is_calver_and_sets_generated_at(self, gen):
        ref, _ = build(gen, *_sample(gen))
        assert (ref["version"], ref["generated_at"]) == ("2026.10.15", "2026-10-15")
        for bad in ("2026-10-15", "2026.13.01", "26.10.15"):
            with pytest.raises(gen.ReferenceInputError):
                gen.build_reference(doc(*_sample(gen)), overrides(), version=bad)

    def test_cli_build_is_byte_identical(self, gen, tmp_path):
        galaxy = tmp_path / "galaxy.json"
        galaxy.write_text(json.dumps(doc(*_sample(gen))), encoding="utf-8")
        ovr = tmp_path / "overrides.json"
        ovr.write_text(json.dumps(overrides()), encoding="utf-8")
        outs = []
        for name in ("a.json", "b.json"):
            out = tmp_path / name
            argv = ["--galaxy", str(galaxy), "--overrides", str(ovr), "--out", str(out), "--version", "2026.10.15"]
            assert gen.main(argv) == 0
            outs.append(out.read_bytes())
        assert outs[0] == outs[1]
        inputs = json.loads(outs[0])["inputs"]
        assert inputs[0]["sha256"] == hashlib.sha256(galaxy.read_bytes()).hexdigest()
        assert inputs[1]["sha256"] == hashlib.sha256(ovr.read_bytes()).hexdigest()


class TestReport:
    def test_graph_resolution_duplicates_and_mismatches(self, gen):
        ref, stats = build(gen, *_sample(gen))
        graph = [
            {"name": "sandworm team", "source": ["mitre_attck"], "relationships": 118, "pulses": 24},
            {"name": "sandworm", "source": ["alienvault_otx"], "relationships": 105, "pulses": 7},
            {"name": "lazarus group", "source": ["mitre_attck"], "relationships": 297, "pulses": 20},
            {"name": "andariel", "source": ["mitre_attck"], "relationships": 15, "pulses": 0},
            {"name": "aurora panda", "source": ["alienvault_otx"], "relationships": 9, "pulses": 1},
            {"name": "clop", "source": ["alienvault_otx"], "relationships": 93, "pulses": 4},
            {"name": "qilin", "source": ["alienvault_otx"], "relationships": 71, "pulses": 7},
            {"name": "new group", "source": ["mitre_attck"], "relationships": 3, "pulses": 0},
        ]
        report = gen.build_report(ref, stats, gen.load_graph_actors({"actors": graph}), top=1)
        g = report["graph"]
        assert g["resolved"] == 4
        assert g["resolution"]["ambiguous"] == 1
        assert [(d["canonical"], d["duplicates"]) for d in g["duplicate_groups"]["all"]] == [
            ("sandworm team", ["sandworm"])
        ]
        assert g["duplicate_groups"]["nodes_folded"] == 1
        assert [u["name"] for u in g["unresolved"]["all"]] == ["clop", "qilin", "new group"]
        assert len(g["unresolved"]["top"]) == 1
        check = g["canonical_key_check"]
        assert check["attack_keys_matching_graph"] == 3
        assert [m["graph_name"] for m in check["graph_attack_nodes_not_canonical_keys"]] == ["new group"]
        assert "Graph: 8 ThreatActor nodes" in gen.format_report(report, top=1)

    def test_merge_pairs_never_take_an_attack_node_or_a_missing_canonical(self, gen):
        ref, _ = build(
            gen,
            mitre("APT29", "G0016"),
            mitre("UNC2452", "G0118"),
            ta("Midnight Blizzard", ["Cozy Bear"]),
            revocations={"G0118": "G0016"},
        )
        index = gen.build_index(ref)
        rows = gen.load_graph_actors(
            [
                node("apt29", relationships=100),
                node("unc2452", relationships=31),  # ATT&CK-sourced: never a duplicate
                node("unc2452 group", source=("alienvault_otx",)),  # resolves to apt29 (suffix rule)
                node("cozy bear", source=("alienvault_otx",)),  # resolves to midnight blizzard, not on the graph
            ]
        )
        assert gen.merge_pairs(index, rows) == [("unc2452 group", "apt29")]

    def test_spelling_variants_and_short_forms_are_listed(self, gen):
        ref, stats = build(gen, mitre("Sandworm Team", "G0034"), ta("Black Basta"))
        graph = gen.load_graph_actors(
            [
                node("sandworm team", relationships=118, malware=["prestige", "industroyer2"]),
                node("sandworm", source=("alienvault_otx",), relationships=105, malware=["prestige - s1058"]),
                node("blackbasta", source=("alienvault_otx",), relationships=41),
                node("cl0p", source=("alienvault_otx",), relationships=68),
                node("clop", source=("alienvault_otx",), relationships=93),
            ]
        )
        g = gen.build_report(ref, stats, graph)["graph"]
        variants = {v["triage_key"]: [n["name"] for n in v["names"]] for v in g["spelling_variants"]}
        assert variants == {"blackbasta": ["black basta", "blackbasta"], "clop": ["cl0p", "clop"]}
        assert gen.triage_key("Cl0p") != gen.triage_key("clop")  # keys are lower-case first
        assert gen.triage_key(gen.actor_key("Cl0p")) == gen.triage_key("clop") == "clop"
        short = g["suffix_short_forms_on_graph"]
        assert [(s["name"], s["from"], s["shared_malware"]) for s in short] == [
            ("sandworm", "sandworm team", ["prestige"])
        ]

    def test_graph_derived_files_are_refused_inside_the_repo(self, gen):
        assert gen.main(["--export-graph-actors", str(_ROOT / "graph_actors.json")]) == 1
        assert not (_ROOT / "graph_actors.json").exists()


# --------------------------------------------------------------------------- the committed file


@pytest.fixture(scope="module")
def committed():
    return json.loads(REFERENCE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def committed_overrides(gen):
    data = json.loads(OVERRIDES.read_text(encoding="utf-8"))
    gen.load_overrides(data)  # valid
    return data


class TestCommittedReference:
    def test_metadata(self, committed):
        assert committed["schema_version"] == 1
        assert re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", committed["version"])
        assert committed["generated_at"] == committed["version"].replace(".", "-")
        roles = [i["role"] for i in committed["inputs"]]
        assert roles == ["galaxy", "attack_revocations", "loaded_attack", "overrides"]
        loaded_input = committed["inputs"][2]
        assert loaded_input["exported_at"] and loaded_input["attack_nodes"] > 0
        assert all(re.fullmatch(r"[0-9a-f]{64}", i["sha256"]) for i in committed["inputs"])
        notices = " ".join(a.get("notice", "") + a.get("licence", "") for a in committed["attribution"])
        assert "CC0-1.0" in notices
        assert (
            "© The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE "
            "Corporation." in notices
        )

    def test_built_from_the_committed_overrides(self, committed):
        overrides_input = next(i for i in committed["inputs"] if i["role"] == "overrides")
        assert overrides_input["file"] == OVERRIDES.name
        assert overrides_input["sha256"] == hashlib.sha256(OVERRIDES.read_bytes()).hexdigest(), (
            "canonical_threat_actor_overrides.json changed after the reference was built: rebuild it with "
            "scripts/build_canonical_threat_actors.py"
        )

    def test_every_name_has_exactly_one_place(self, gen, committed):
        seen = {}
        for a in committed["actors"]:
            for name in [a["key"], *a["synonyms"]]:
                assert name not in seen, f"{name!r} in {seen.get(name)} and {a['key']}"
                seen[name] = a["key"]
        for entry in committed["ambiguous"]:
            assert entry["key"] not in seen, f"{entry['key']!r} is ambiguous and belongs to {seen.get(entry['key'])}"
            seen[entry["key"]] = "ambiguous"
        for name in seen:
            assert name == gen.actor_key(name), f"{name!r} is not normalised"
            assert name and not gen.is_placeholder_name(name)

    def test_sorted_and_counted(self, committed):
        keys = [a["key"] for a in committed["actors"]]
        assert keys == sorted(keys)
        assert [e["key"] for e in committed["ambiguous"]] == sorted(e["key"] for e in committed["ambiguous"])
        counts = committed["counts"]
        assert counts["actors"] == len(keys)
        assert counts["synonyms"] == sum(len(a["synonyms"]) for a in committed["actors"])
        assert counts["ambiguous"] == len(committed["ambiguous"])
        assert counts["attack_groups"] == sum(
            1 for a in committed["actors"] if a["mitre_attack"] or "mitre_loaded" in a["origins"]
        )

    def test_actor_entries(self, committed):
        attack_ids = [a["mitre_attack"] for a in committed["actors"] if a["mitre_attack"]]
        assert len(attack_ids) == len(set(attack_ids))
        for a in committed["actors"]:
            assert a["key"] not in a["synonyms"]
            assert a["synonyms"] == sorted(set(a["synonyms"]))
            listed = {s for names in a["synonym_origins"].values() for s in names}
            assert listed == set(a["synonyms"]), a["key"]
            for origin, names in a["synonym_origins"].items():
                assert names == sorted(names)
                assert origin in ("mitre", "mitre_loaded", "mitre_revoked", "suffix_rule", "override") or (
                    origin.startswith("misp_galaxy:")
                ), origin
            assert a["mitre_attack"] is None or re.fullmatch(r"G\d{4}", a["mitre_attack"])
            assert a["records"] or a["origins"] in (["override"], ["mitre_loaded"])
        keys = {a["key"] for a in committed["actors"]}
        for entry in committed["ambiguous"]:
            assert entry["actors"] == sorted(entry["origins"])
            assert set(entry["actors"]) <= keys, entry["key"]
            assert len(entry["actors"]) > 1 or "never_merge" in entry

    def test_attack_groups_are_keyed_by_their_attack_name(self, committed):
        # The ATT&CK groups EdgeGuard writes (checked against the graph by the build report): a
        # sample whose ATT&CK name and id are stable.
        by_id = {a["mitre_attack"]: a for a in committed["actors"] if a["mitre_attack"]}
        assert by_id["G0032"]["key"] == "lazarus group"
        assert by_id["G0034"]["key"] == "sandworm team"
        assert by_id["G0007"]["key"] == "apt28"
        assert by_id["G0094"]["key"] == "kimsuky"
        assert by_id["G1059"]["key"] == "nimbus manticore"  # anchored by the loaded ATT&CK version
        assert len(by_id) >= 190

    def test_revoked_attack_groups_are_folded(self, gen, committed):
        revoked = {r["mitre_attack"]: r for r in committed["revoked_attack_groups"]}
        assert {k: r["actor"] for k, r in revoked.items()} == {
            "G0042": "patchwork",
            "G0057": "oilrig",
            "G0058": "magic hound",
            "G0074": "dragonfly",
            "G0086": "kimsuky",
            "G0118": "apt29",
        }
        assert not {a["mitre_attack"] for a in committed["actors"]} & set(revoked)
        index = gen.build_index(committed)
        for name, actor in (
            ("unc2452", "apt29"),
            ("nobelium", "apt29"),
            ("dark halo", "apt29"),
            ("apt34", "oilrig"),
            ("forest blizzard", "apt28"),
            ("iron liberty", "dragonfly"),
        ):
            assert gen.resolve(index, name).actor == actor, name

    def test_never_merge_pairs_hold(self, committed):
        by_key = {a["key"]: a for a in committed["actors"]}
        assert committed["never_merge_pairs"]
        for pair in committed["never_merge_pairs"]:
            assert pair["name"] not in by_key[pair["actor"]]["synonyms"], pair
            assert pair["status"] in ("proposed", "accepted") and pair["reason"]

    def test_overrides_are_applied(self, gen, committed, committed_overrides):
        by_key = {a["key"]: a for a in committed["actors"]}
        ambiguous = {e["key"]: e for e in committed["ambiguous"]}
        for decision in committed_overrides["merge"]:
            target = gen.actor_key(decision["into"])
            for name in decision["names"]:
                key = gen.actor_key(name)
                assert key == target or key in by_key[target]["synonyms"], (name, target)
        for decision in committed_overrides["never_merge"]:
            for name in decision["names"]:
                key = gen.actor_key(name)
                if decision.get("actor"):
                    assert key not in by_key[gen.actor_key(decision["actor"])]["synonyms"], name
                    assert (
                        key in by_key
                        or any(key in a["synonyms"] for a in by_key.values())
                        or ("never_merge" in ambiguous[key])
                    ), name
                else:
                    assert "never_merge" in ambiguous[key], name
        for decision in committed_overrides["canonical_name"]:
            key = gen.actor_key(decision["name"])
            assert by_key[key]["name"] == decision["name"]
        for section in ("merge", "never_merge", "canonical_name"):
            for decision in committed_overrides[section]:
                assert decision["status"] in ("proposed", "accepted")

    def test_lookup(self, gen, committed):
        index = gen.build_index(committed)
        assert gen.resolve(index, "Lazarus").actor == "lazarus group"
        assert gen.resolve(index, "Sandworm").actor == "sandworm team"
        assert gen.resolve(index, "andariel").actor == "andariel"
        assert gen.resolve(index, "medusa").how == "never_merge"
        assert gen.resolve(index, "famous chollima").how == "never_merge"
        assert gen.resolve(index, "silverfox").actor == "silver fox"
        assert gen.resolve(index, "no such actor").how == "unresolved"
