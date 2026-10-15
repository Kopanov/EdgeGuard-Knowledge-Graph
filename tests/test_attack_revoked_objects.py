"""Revoked and deprecated ATT&CK objects in the MITRE collector, and the ``deprecated`` flag (2026-10).

ATT&CK keeps a replaced object in its STIX bundle with ``revoked: true`` and a ``revoked-by``
relationship to its successor, and a retired object without a successor with
``x_mitre_deprecated: true``. On the hosted graph of 2026-10-15, 158 of 982 Technique nodes and 6
ThreatActor nodes were revoked objects (UNC2452 next to APT29, APT34 next to OilRig, …).

``MITRECollector._parse_bundle`` now skips revoked objects of every type (neither items nor
relationship endpoints), adds a revoked group's or software's name and aliases to its successor's
``aliases``, and keeps deprecated objects with ``deprecated: True``. The flag travels to the node
as the ``attack-status:deprecated`` MISP tag, the way ``attack_domain`` does. The fixtures below
follow the shape of the ATT&CK STIX 2.1 bundle (``mitre/cti`` ``enterprise-attack.json``).
"""

from __future__ import annotations

import logging
import os
import sys
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import attack_revoked  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402
from collectors.misp_writer import ATTACK_DEPRECATED_TAG, MISPWriter  # noqa: E402

ENT_KILL_CHAIN = "mitre-attack"
_CREATED = "2017-05-31T21:31:00.645Z"
_MODIFIED = "2025-10-24T17:48:25.234Z"


def _ext(mitre_id, kind="techniques"):
    return [
        {
            "source_name": "mitre-attack",
            "external_id": mitre_id,
            "url": f"https://attack.mitre.org/{kind}/{mitre_id.replace('.', '/')}",
        }
    ]


def _sdo(stix_type, stix_id, name, **fields):
    base = {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": _CREATED,
        "modified": _MODIFIED,
        "created_by_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
        "object_marking_refs": ["marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"],
        "name": name,
        "description": f"{name} description.",
        "x_mitre_domains": ["enterprise-attack"],
        "x_mitre_version": "1.0",
    }
    base.update(fields)
    return base


def _technique(stix_id, mitre_id, name, phases=("execution",), **fields):
    return _sdo(
        "attack-pattern",
        stix_id,
        name,
        external_references=_ext(mitre_id),
        kill_chain_phases=[{"kill_chain_name": ENT_KILL_CHAIN, "phase_name": p} for p in phases],
        x_mitre_is_subtechnique="." in mitre_id,
        x_mitre_platforms=["Windows"],
        **fields,
    )


def _group(stix_id, mitre_id, name, aliases, **fields):
    return _sdo("intrusion-set", stix_id, name, aliases=aliases, external_references=_ext(mitre_id, "groups"), **fields)


def _software(stix_type, stix_id, mitre_id, name, aliases, **fields):
    return _sdo(
        stix_type,
        stix_id,
        name,
        x_mitre_aliases=aliases,
        labels=[stix_type],
        external_references=_ext(mitre_id, "software"),
        **fields,
    )


def _rel(n, rel_type, src, tgt):
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--00000000-0000-4000-8000-{n:012d}",
        "created": _CREATED,
        "modified": _MODIFIED,
        "relationship_type": rel_type,
        "source_ref": src,
        "target_ref": tgt,
    }


T1059 = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830"
T1059_001 = "attack-pattern--970cdb5c-02fb-4c38-b17e-d6327cf3c810"
T1086 = "attack-pattern--f4882e23-8aa7-4b12-b28a-b349c12ee9e0"  # PowerShell, revoked by T1059.001
T1562 = "attack-pattern--3d333250-30e4-4a82-9edc-756c68afc529"  # revoked parent
T1562_001 = "attack-pattern--ac08589e-ee59-4935-8667-d845e38fe579"  # revoked sub-technique
T1685 = "attack-pattern--0a1b2c3d-0000-4000-8000-000000001685"  # successor of both
T1066 = "attack-pattern--00d0b012-8a03-410e-95de-5826bf542de6"  # revoked, no revoked-by in the bundle
T1497_DEP = "attack-pattern--0a1b2c3d-0000-4000-8000-0000000d0001"  # deprecated, no successor
APT29 = "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
UNC2452 = "intrusion-set--8d3ac2b1-b1d4-4b5e-9a1e-0c7f8c0f0001"
DRAGONFLY = "intrusion-set--1c63d4ec-0a75-4daa-b1df-0d11af3d3cc1"
DRAGONFLY2 = "intrusion-set--76d59913-1d24-4992-a8ac-05a3eb093f71"
OLD_GROUP = "intrusion-set--0a1b2c3d-0000-4000-8000-00000000b001"  # chain: OLD_GROUP -> DRAGONFLY2 -> DRAGONFLY
DEPRECATED_GROUP = "intrusion-set--0a1b2c3d-0000-4000-8000-00000000d002"
POISONIVY = "malware--b42378e0-f147-496f-992a-26a49705395b"
DARKMOON = "malware--310f437b-29e7-4844-848c-7220868d074a"
OLD_TUNNEL = "malware--0a1b2c3d-0000-4000-8000-00000000c001"  # malware revoked by a tool
NGROK = "tool--4ea12106-c0a1-4546-bb64-a1675d9f5dc7"
DEPRECATED_TOOL = "tool--0a1b2c3d-0000-4000-8000-00000000d003"


def _bundle():
    objects = [
        _technique(T1059, "T1059", "Command and Scripting Interpreter", revoked=False),  # explicit false: kept
        _technique(T1059_001, "T1059.001", "PowerShell"),
        _technique(T1086, "T1086", "PowerShell", revoked=True),
        _technique(T1562, "T1562", "Impair Defenses", phases=("defense-impairment",), revoked=True),
        _technique(T1562_001, "T1562.001", "Disable or Modify Tools", phases=("defense-impairment",), revoked=True),
        _technique(T1685, "T1685", "Disable or Modify Tools", phases=("defense-impairment",)),
        _technique(T1066, "T1066", "Indicator Removal from Tools", revoked=True),
        _technique(T1497_DEP, "T1497.999", "Retired Check", x_mitre_deprecated=True),
        _group(APT29, "G0016", "APT29", ["APT29", "NOBELIUM", "Cozy Bear"]),
        _group(UNC2452, "G0118", "UNC2452", ["UNC2452", "NOBELIUM", "StellarParticle", "Dark Halo"], revoked=True),
        _group(DRAGONFLY, "G0035", "Dragonfly", ["Dragonfly", "Energetic Bear"]),
        _group(DRAGONFLY2, "G0074", "Dragonfly 2.0", ["Dragonfly 2.0", "Berserk Bear"], revoked=True),
        _group(OLD_GROUP, "G9001", "Old Group", ["Old Group"], revoked=True),
        _group(DEPRECATED_GROUP, "G9002", "Retired Group", ["Retired Group", ""], x_mitre_deprecated=True),
        _software("malware", POISONIVY, "S0012", "PoisonIvy", ["PoisonIvy", "Poison Ivy"]),
        _software("malware", DARKMOON, "S0209", "Darkmoon", ["Darkmoon", "Moon"], revoked=True),
        _software("malware", OLD_TUNNEL, "S9000", "OldTunnel", ["OldTunnel", "NGROK"], revoked=True),
        _software("tool", NGROK, "S0508", "ngrok", ["ngrok"]),
        _software("tool", DEPRECATED_TOOL, "S9003", "Retired Tool", ["Retired Tool"], x_mitre_deprecated=True),
        _sdo(
            "x-mitre-tactic",
            "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5",
            "Execution",
            x_mitre_shortname="execution",
            external_references=_ext("TA0002", "tactics"),
        ),
        # revoked-by: revoked -> successor
        _rel(1, "revoked-by", T1086, T1059_001),
        _rel(2, "revoked-by", T1562, T1685),
        _rel(3, "revoked-by", T1562_001, T1685),
        _rel(4, "revoked-by", UNC2452, APT29),
        _rel(5, "revoked-by", DRAGONFLY2, DRAGONFLY),
        _rel(6, "revoked-by", OLD_GROUP, DRAGONFLY2),
        _rel(7, "revoked-by", DARKMOON, POISONIVY),
        _rel(8, "revoked-by", OLD_TUNNEL, NGROK),
        # uses / subtechnique-of / attributed-to, some reaching revoked objects
        _rel(10, "uses", APT29, T1059_001),
        _rel(11, "uses", APT29, T1086),  # to a revoked technique
        _rel(12, "uses", UNC2452, T1059),  # from a revoked group
        _rel(13, "uses", APT29, DARKMOON),  # to revoked software
        _rel(14, "uses", APT29, POISONIVY),
        _rel(15, "uses", POISONIVY, T1562_001),  # to a revoked sub-technique
        _rel(16, "uses", POISONIVY, T1685),
        _rel(17, "uses", NGROK, T1086),
        _rel(18, "uses", NGROK, T1059_001),
        _rel(19, "subtechnique-of", T1562_001, T1562),  # both revoked
        _rel(20, "subtechnique-of", T1059_001, T1059),
        _rel(21, "attributed-to", DARKMOON, APT29),  # from revoked software
        _rel(22, "attributed-to", POISONIVY, UNC2452),  # to a revoked group
        _rel(23, "uses", DEPRECATED_GROUP, T1497_DEP),  # deprecated objects keep their links
    ]
    return {"type": "bundle", "id": "bundle--3b2c6d08-0b1f-4bd1-9f19-6f0b2d0c0001", "objects": objects}


def _parse(objects=None, domain=mc.ATTACK_DOMAIN_ENTERPRISE, kill_chain=ENT_KILL_CHAIN):
    collector = mc.MITRECollector(misp_writer=MagicMock())
    return collector._parse_bundle(
        objects if objects is not None else _bundle()["objects"], domain=domain, kill_chain_name=kill_chain
    )


def _by_name(items):
    return {i["name"]: i for i in items}


REVOKED_NAMES = {"UNC2452", "Dragonfly 2.0", "Old Group", "Darkmoon", "OldTunnel"}
REVOKED_TECHNIQUES = {"T1086", "T1562", "T1562.001", "T1066"}


# --------------------------------------------------------------------------- revoked objects
class TestRevokedObjectsAreSkipped:
    def test_revoked_objects_are_not_items(self):
        parsed = _parse()
        assert {t["mitre_id"] for t in parsed["techniques"]} == {"T1059", "T1059.001", "T1685", "T1497.999"}
        names = {i["name"] for key in ("actors", "malware", "tools") for i in parsed[key]}
        assert not names & REVOKED_NAMES
        assert names == {"APT29", "Dragonfly", "Retired Group", "PoisonIvy", "ngrok", "Retired Tool"}

    def test_a_revoked_object_without_a_successor_in_the_bundle_is_still_skipped(self):
        assert "T1066" not in {t["mitre_id"] for t in _parse()["techniques"]}

    def test_relationships_that_reach_a_revoked_object_are_dropped(self):
        parsed = _parse()
        rels = parsed["relationships"]
        ends = {(r["source_name"], r.get("target_mitre_id") or r["target_name"]) for r in rels}
        assert ends == {
            ("APT29", "T1059.001"),
            ("APT29", "PoisonIvy"),  # group -> software (uses_software)
            ("PoisonIvy", "T1685"),
            ("ngrok", "T1059.001"),
            ("PowerShell", "T1059"),  # subtechnique-of between live techniques
            ("Retired Group", "T1497.999"),
        }
        assert not any(r.get("target_mitre_id") in REVOKED_TECHNIQUES for r in rels)
        assert not any(r["source_name"] in REVOKED_NAMES or r["target_name"] in REVOKED_NAMES for r in rels)
        assert not any(r["type"] == "attributed_to" for r in rels), "both attributed-to reach a revoked object"

    def test_technique_lists_hold_no_revoked_id(self):
        parsed = _parse()
        actors, malware, tools = (_by_name(parsed[k]) for k in ("actors", "malware", "tools"))
        assert actors["APT29"]["uses_techniques"] == ["T1059.001"]
        assert actors["APT29"]["uses_malware"] == ["PoisonIvy"], "the revoked Darkmoon is not a uses_malware claim"
        assert malware["PoisonIvy"]["uses_techniques"] == ["T1685"]
        assert tools["ngrok"]["uses_techniques"] == ["T1059.001"]

    def test_an_ics_bundle_is_parsed_the_same_way(self):
        ics_live = _technique("attack-pattern--ics-live", "T0800", "Activate Firmware Update Mode")
        ics_revoked = _technique("attack-pattern--ics-old", "T0803", "Block Command Message", revoked=True)
        for obj in (ics_live, ics_revoked):
            obj["kill_chain_phases"] = [{"kill_chain_name": mc.ICS_KILL_CHAIN_NAME, "phase_name": "execution"}]
            obj["x_mitre_domains"] = ["ics-attack"]
        parsed = _parse([ics_live, ics_revoked], domain=mc.ATTACK_DOMAIN_ICS, kill_chain=mc.ICS_KILL_CHAIN_NAME)
        assert [(t["mitre_id"], t["attack_domain"]) for t in parsed["techniques"]] == [("T0800", "ics")]


class TestSuccessorsInheritRevokedNames:
    def test_a_revoked_group_name_and_aliases_join_its_successor(self):
        """UNC2452 -> APT29: OTX's ``unc2452`` then finds APT29 by alias (lookups, the alias merge)."""
        actors = _by_name(_parse()["actors"])
        assert actors["APT29"]["aliases"] == [
            "APT29",
            "NOBELIUM",
            "Cozy Bear",
            "UNC2452",
            "StellarParticle",
            "Dark Halo",
        ]
        assert actors["Retired Group"]["aliases"] == ["Retired Group", ""], "no predecessor: aliases as published"

    def test_a_chain_in_the_bundle_reaches_the_last_successor(self):
        """Old Group -> Dragonfly 2.0 -> Dragonfly: both revoked names land on Dragonfly, after its own."""
        aliases = _by_name(_parse()["actors"])["Dragonfly"]["aliases"]
        assert aliases[:2] == ["Dragonfly", "Energetic Bear"]
        assert sorted(aliases[2:]) == ["Berserk Bear", "Dragonfly 2.0", "Old Group"]

    def test_revoked_software_names_join_the_successor_malware_or_tool(self):
        parsed = _parse()
        assert _by_name(parsed["malware"])["PoisonIvy"]["aliases"] == ["PoisonIvy", "Poison Ivy", "Darkmoon", "Moon"]
        # malware revoked by a tool; "NGROK" equals "ngrok" ignoring case and is not repeated
        assert _by_name(parsed["tools"])["ngrok"]["aliases"] == ["ngrok", "OldTunnel"]

    @pytest.mark.parametrize(
        "relationships",
        [
            [_rel(1, "revoked-by", UNC2452, OLD_GROUP), _rel(2, "revoked-by", OLD_GROUP, UNC2452)],  # loop
            [_rel(1, "revoked-by", UNC2452, APT29), _rel(2, "revoked-by", UNC2452, DRAGONFLY)],  # two successors
            [_rel(1, "revoked-by", UNC2452, "intrusion-set--not-in-the-bundle")],
            [],
        ],
    )
    def test_no_usable_successor_adds_nothing_and_does_not_fail(self, relationships):
        objects = [
            _group(APT29, "G0016", "APT29", ["APT29"]),
            _group(DRAGONFLY, "G0035", "Dragonfly", ["Dragonfly"]),
            _group(UNC2452, "G0118", "UNC2452", ["UNC2452"], revoked=True),
            _group(OLD_GROUP, "G9001", "Old Group", ["Old Group"], revoked=True),
            *relationships,
        ]
        actors = _by_name(_parse(objects)["actors"])
        assert set(actors) == {"APT29", "Dragonfly"}
        assert actors["APT29"]["aliases"] == ["APT29"] and actors["Dragonfly"]["aliases"] == ["Dragonfly"]


# --------------------------------------------------------------------------- the map falls behind
NEWLY_REVOKED = "attack-pattern--0a1b2c3d-0000-4000-8000-000000001999"


class TestRevokedTechniquesTheMapDoesNotList:
    """Feeds cite techniques by id, and only the revoked-id map translates them downstream. A
    technique ATT&CK revoked after the map was built is kept until the map is rebuilt, so the links
    that cite it are not lost; groups and software need no map (their names travel through
    ``revoked-by``)."""

    def test_it_is_kept_with_its_links_and_a_warning(self, caplog):
        objects = _bundle()["objects"] + [
            _technique(NEWLY_REVOKED, "T1999", "Newly Revoked", revoked=True),
            _rel(30, "uses", APT29, NEWLY_REVOKED),
        ]
        with caplog.at_level(logging.WARNING):
            parsed = _parse(objects)
        techniques = {t["mitre_id"] for t in parsed["techniques"]}
        assert "T1999" in techniques and not techniques & REVOKED_TECHNIQUES  # the map lists the others
        assert "T1999" in _by_name(parsed["actors"])["APT29"]["uses_techniques"]
        assert ("APT29", "T1999") in {(r["source_name"], r.get("target_mitre_id")) for r in parsed["relationships"]}
        (line,) = [r.getMessage() for r in caplog.records if "[ATTACK-REVOKED]" in r.getMessage()]
        assert "1 technique(s)" in line and "T1999" in line

    def test_without_the_map_revoked_techniques_are_kept_and_groups_and_software_are_not(self, monkeypatch, tmp_path):
        monkeypatch.setattr(attack_revoked, "MAP_PATH", tmp_path / "attack_revoked_ids.json")
        attack_revoked.reset_cache()
        try:
            parsed = _parse()
        finally:
            attack_revoked.reset_cache()
        assert REVOKED_TECHNIQUES <= {t["mitre_id"] for t in parsed["techniques"]}
        names = {i["name"] for key in ("actors", "malware", "tools") for i in parsed[key]}
        assert not names & REVOKED_NAMES
        assert "UNC2452" in _by_name(parsed["actors"])["APT29"]["aliases"]


# --------------------------------------------------------------------------- deprecated objects
class TestDeprecatedObjectsAreKeptAndMarked:
    def test_deprecated_items_carry_the_flag_and_the_others_do_not(self):
        parsed = _parse()
        flags = {
            i.get("mitre_id") or i["name"]: i["deprecated"]
            for key in ("techniques", "tactics", "actors", "malware", "tools")
            for i in parsed[key]
        }
        assert {k for k, v in flags.items() if v} == {"T1497.999", "Retired Group", "S9003"}
        assert flags["T1059"] is False and flags["TA0002"] is False and flags["APT29"] is False

    def test_a_deprecated_technique_keeps_its_links(self):
        parsed = _parse()
        assert _by_name(parsed["actors"])["Retired Group"]["uses_techniques"] == ["T1497.999"]


class TestCollect:
    def test_collect_pushes_no_revoked_object_and_marks_the_deprecated_ones(self, monkeypatch):
        writer = MagicMock()
        writer.push_items.return_value = (10, 0)
        collector = mc.MITRECollector(misp_writer=writer)
        breaker = MagicMock()
        breaker.can_execute.return_value = True
        monkeypatch.setattr(mc, "MITRE_CIRCUIT_BREAKER", breaker)
        monkeypatch.setattr(mc, "MITRE_MAX_RELATIONSHIPS", 0)
        monkeypatch.setattr(mc, "ENABLE_MITRE_ICS", False)
        monkeypatch.setattr(mc, "update_source_incremental", lambda *a, **k: None)
        monkeypatch.setattr(mc, "get_source_incremental", lambda *a, **k: {})
        monkeypatch.setattr(mc.MITRE_RATE_LIMITER, "wait_if_needed", lambda: None)
        monkeypatch.setattr(collector, "_download_stix_bundle", lambda etag=None, url=None: (deepcopy(_bundle()), None))
        status = collector.collect(push_to_misp=True, baseline=True)
        assert status["success"] is True
        (items,), _ = writer.push_items.call_args
        assert not {i.get("name") for i in items} & REVOKED_NAMES
        assert not {i.get("mitre_id") for i in items} & REVOKED_TECHNIQUES
        assert {i.get("mitre_id") or i["name"] for i in items if i["deprecated"]} == {
            "T1497.999",
            "Retired Group",
            "S9003",
        }
        rels = collector.get_relationships()
        assert rels and not any(r.get("target_mitre_id") in REVOKED_TECHNIQUES for r in rels)


# --------------------------------------------------------------------------- the flag through MISP to the node
def _writer():
    return MISPWriter(url="http://127.0.0.1:9", api_key="dummy", verify_ssl=False)


def _items():
    base = {"tag": "mitre_attck", "source": ["mitre_attck"], "zone": ["global"], "description": "d"}
    return {
        "technique": {**base, "type": "technique", "mitre_id": "T1497.999", "name": "Retired Check"},
        "tactic": {**base, "type": "tactic", "mitre_id": "TA0002", "name": "Execution", "shortname": "execution"},
        "actor": {**base, "type": "actor", "name": "APT99", "aliases": ["APT99"]},
        "malware": {**base, "type": "malware", "name": "Retired Malware", "aliases": [], "malware_types": ["malware"]},
        "tool": {**base, "type": "tool", "mitre_id": "S9003", "name": "Retired Tool"},
    }


_CREATE = {
    "technique": "create_technique_attribute",
    "tactic": "create_tactic_attribute",
    "actor": "create_actor_attribute",
    "malware": "create_malware_attribute",
    "tool": "create_tool_attribute",
}


class TestDeprecatedFlagReachesTheNode:
    @pytest.mark.parametrize("kind", sorted(_CREATE))
    def test_the_writer_tags_a_deprecated_item_only(self, kind):
        writer = _writer()
        create = getattr(writer, _CREATE[kind])
        tags = {t["name"] for t in create({**_items()[kind], "deprecated": True})["Tag"]}
        assert ATTACK_DEPRECATED_TAG in tags
        for flag in (False, None):
            tags = {t["name"] for t in create({**_items()[kind], "deprecated": flag})["Tag"]}
            assert ATTACK_DEPRECATED_TAG not in tags

    @pytest.mark.parametrize("kind", sorted(_CREATE))
    def test_the_sync_reads_the_flag_back(self, kind):
        import run_misp_to_neo4j as sync_mod

        writer = _writer()
        syncer = sync_mod.MISPToNeo4jSync.__new__(sync_mod.MISPToNeo4jSync)
        syncer.neo4j = MagicMock()
        syncer.stats = {"errors": 0}
        event = {"id": "7", "info": "EdgeGuard-mitre_attck-2026-10-15", "Tag": []}
        for flag in (True, False):
            attr = getattr(writer, _CREATE[kind])({**_items()[kind], "deprecated": flag})
            attr["uuid"] = "00000000-0000-4000-8000-000000000001"
            item, _ = syncer.parse_attribute(attr, event)
            assert item is not None and item["deprecated"] is flag, (kind, flag)
        assert sync_mod._ATTACK_DEPRECATED_TAG == ATTACK_DEPRECATED_TAG

    @pytest.mark.parametrize(
        "merge, data",
        [
            ("merge_technique", {"mitre_id": "T1497.999", "name": "Retired Check"}),
            ("merge_tactic", {"mitre_id": "TA0002", "name": "Execution"}),
            ("merge_tool", {"mitre_id": "S9003", "name": "Retired Tool"}),
            ("merge_actor", {"name": "APT99"}),
            ("merge_malware", {"name": "Retired Malware"}),
        ],
    )
    def test_the_merge_sets_the_node_property_only_when_deprecated(self, merge, data):
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.merge_node_with_source = MagicMock(return_value=True)
        assert getattr(client, merge)({**data, "deprecated": True}, source_id="mitre_attck")
        assert client.merge_node_with_source.call_args.kwargs["extra_props"]["deprecated"] is True
        for flag in (False, None):
            client.merge_node_with_source.reset_mock()
            getattr(client, merge)({**data, "deprecated": flag}, source_id="mitre_attck")
            assert "deprecated" not in client.merge_node_with_source.call_args.kwargs["extra_props"]

    def test_merge_node_with_source_writes_the_flag(self):
        """End of the path: the property reaches the Cypher ``SET`` as a parameter."""
        from neo4j_client import Neo4jClient

        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        session = client.driver.session.return_value.__enter__.return_value
        session.run.return_value.single.return_value = None  # no existing node
        client._upsert_sourced_relationship = MagicMock(return_value=True)
        data = {"mitre_id": "T1497.999", "name": "Retired Check", "deprecated": True}
        assert client.merge_technique(data, "mitre_attck") is True
        query, params = session.run.call_args.args[0], session.run.call_args.kwargs
        assert "n.deprecated = $deprecated" in query and params["deprecated"] is True
