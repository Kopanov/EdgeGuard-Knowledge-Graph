"""ATT&CK's source text and facts in MISP (2026-11-07).

MISP holds what ATT&CK publishes; the MISP -> Neo4j sync caps what reaches the graph (``text_caps``):

1. The MITRE collector passes each technique's, tactic's, group's, malware's and tool's whole description on (it
   cut them at 500 characters), and MISPWriter writes it whole after the comment's ``MITRE_*`` block, or as the
   whole comment without one (it cut groups, techniques and tactics at 255 characters, malware and tools at 400,
   with "..." added mid-word, and a comment without a block at 500), up to ``ENTITY_DESCRIPTION_MAX_CHARS``
   (8,000). A technique's zones are still read from the first 500 characters.
2. Every ATT&CK platform is a ``platform:`` tag, in ATT&CK's casing (the writer kept the first 3, lower-cased), on
   techniques and, new, on malware and tools.
3. Tools carry ``alias:`` tags, as groups and malware do.
4. Groups, malware and tools carry an ``attack-domain:`` tag per ATT&CK domain (``x_mitre_domains``).
5. Groups, malware and tools carry ATT&CK's own MISP galaxy cluster tag (``mitre-intrusion-set``,
   ``mitre-malware``, ``mitre-tool``) beside the community cluster tag.
6. The sync reads the long text after the block and stores it capped, and none of the new tags creates a node,
   a label or a link. It reads a technique's platform tags in ATT&CK's spelling whatever casing MISP holds them in
   (MISP keeps the casing of a tag it already holds, such as ``platform:windows``).

Fixture: ``tests/fixtures/attack_source_text_objects_2026_11_07.json``, real STIX objects of the attack-stix-data
bundles (Enterprise and ICS ATT&CK 20.1, fetched 2026-11-07), among them T1553.003, the technique with the longest
description (4,668 characters; the MISP galaxy copy, 4,680), and the MISP galaxy cluster tag names those objects
have on the project's test MISP (captured 2026-11-05). Where a test changes an object, it says so.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fake_bolt import FakeBolt  # noqa: E402

import neo4j_client as nc  # noqa: E402
from attack_platforms import ATTACK_PLATFORMS, canonical_attack_platform  # noqa: E402
from collectors import misp_writer as mw  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402
from run_misp_to_neo4j import _METADATA_COMMENT_RE, MISPToNeo4jSync  # noqa: E402
from text_caps import ENTITY_DESCRIPTION_CAP, cap_text  # noqa: E402

FIXTURE = json.loads((TESTS / "fixtures" / "attack_source_text_objects_2026_11_07.json").read_text(encoding="utf-8"))
REPO = TESTS.parent
WRITER = mw.MISPWriter.__new__(mw.MISPWriter)
EVENT = {"id": "601", "info": "EdgeGuard-mitre_attck-2026-11-07", "Tag": []}
_BUILDERS = {
    "technique": "create_technique_attribute",
    "tactic": "create_tactic_attribute",
    "actor": "create_actor_attribute",
    "malware": "create_malware_attribute",
    "tool": "create_tool_attribute",
}
_KEYS = {"technique": "techniques", "tactic": "tactics", "actor": "actors", "malware": "malware", "tool": "tools"}
_LABELS = {"technique": "Technique", "tactic": "Tactic", "actor": "ThreatActor", "malware": "Malware", "tool": "Tool"}
_MERGES = {
    "technique": "merge_technique",
    "tactic": "merge_tactic",
    "actor": "merge_actor",
    "malware": "merge_malware",
    "tool": "merge_tool",
}
# T1136 Create Account, as ATT&CK lists its platforms.
T1136_PLATFORMS = [
    "Windows",
    "IaaS",
    "Linux",
    "macOS",
    "Network Devices",
    "Containers",
    "SaaS",
    "Office Suite",
    "Identity Provider",
    "ESXi",
]


def _attack_id(obj: Dict[str, Any]) -> str:
    return mc._attack_external_id(obj)


def _object(domain: str, attack_id: str) -> Dict[str, Any]:
    (obj,) = [o for o in FIXTURE[domain] if o.get("type") != "relationship" and _attack_id(o) == attack_id]
    return obj


def _text(attack_id: str, domain: str = "enterprise") -> str:
    return _object(domain, attack_id)["description"]


def _parsed(domain: str = "enterprise", objects: List[Dict[str, Any]] = None) -> Dict[str, list]:
    collector = mc.MITRECollector(misp_writer=MagicMock())
    kill_chain = "mitre-attack" if domain == "enterprise" else mc.ICS_KILL_CHAIN_NAME
    return collector._parse_bundle(
        copy.deepcopy(objects if objects is not None else FIXTURE[domain]),
        domain=mc.ATTACK_DOMAIN_ENTERPRISE if domain == "enterprise" else mc.ATTACK_DOMAIN_ICS,
        kill_chain_name=kill_chain,
    )


def _merged() -> Dict[str, list]:
    return mc.MITRECollector._merge_domain_bundles(_parsed("enterprise"), _parsed("ics"))


def _item(kind: str, attack_id: str, parsed: Dict[str, list] = None) -> Dict[str, Any]:
    parsed = parsed if parsed is not None else _parsed()
    (item,) = [i for i in parsed[_KEYS[kind]] if i.get("mitre_id") == attack_id]
    return item


def _attribute(kind: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """The MISP attribute MISPWriter writes for ``item``, as MISP lists it (a uuid, the tags as objects)."""
    attribute = getattr(WRITER, _BUILDERS[kind])(copy.deepcopy(item))
    assert attribute is not None
    attribute.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{kind}:{item['name']}")), event_id="601", timestamp="1")
    return attribute


def _tags(attribute: Dict[str, Any]) -> List[str]:
    return [t["name"] for t in attribute["Tag"]]


def _comment_text(attribute: Dict[str, Any]) -> str:
    """The description in the comment: the text after the ``MITRE_*`` block, or the whole comment without one."""
    comment = attribute["comment"]
    if _METADATA_COMMENT_RE.match(comment):
        block, _, text = comment.partition("\n")
        json.loads(block.split(":", 1)[1])  # the block still parses
        return text
    return comment


def _synced(attribute: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    item, relationships = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(copy.deepcopy(attribute), EVENT)
    assert item is not None
    return item, relationships


@pytest.fixture
def bolt():
    opened = []

    def start():
        server = FakeBolt([])
        client = nc.Neo4jClient(uri=server.uri, user="neo4j", password="pw")
        opened.append((server, client))
        assert client.connect() is True
        return server, client

    yield start
    for server, client in opened:
        client.close()
        server.close()


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(nc.time, "sleep", lambda *_a, **_k: None)


def _statements(server: FakeBolt, marker: str) -> List[Dict[str, Any]]:
    return [params for query, params in zip(server.runs, server.parameters, strict=True) if marker in query]


# ============================================================================================ 1. the whole text
class TestTheCollectorPassesTheWholeText:
    def test_the_longest_technique_description_is_passed_whole(self):
        full = _text("T1553.003")
        assert len(full) == 4668
        assert _item("technique", "T1553.003")["description"] == full

    @pytest.mark.parametrize(
        ("kind", "attack_id", "length"),
        [
            ("technique", "T1136.001", 1331),
            ("tactic", "TA0004", 769),
            ("actor", "G0034", 1503),
            ("malware", "S1072", 667),
            ("tool", "S0039", 771),
            ("tool", "S0363", 648),
        ],
    )
    def test_every_kind_is_passed_whole(self, kind, attack_id, length):
        full = _text(attack_id)
        assert len(full) == length > 500
        assert _item(kind, attack_id)["description"] == full

    def test_an_ics_tactic_is_passed_whole(self):
        full = _text("TA0105", "ics")
        assert len(full) == 1796
        assert _item("tactic", "TA0105", _parsed("ics"))["description"] == full

    def test_a_techniques_zones_are_read_from_its_first_500_characters(self):
        """T1195 Supply Chain Compromise: a keyword after the 500th character would give it a sector."""
        full = _text("T1195")
        collector = mc.MITRECollector(misp_writer=MagicMock())
        assert collector.detect_sectors(full[:500]) == ["global"]
        assert collector.detect_sectors(full) == ["energy"]
        item = _item("technique", "T1195")
        assert item["description"] == full and item["zone"] == ["global"]

    def test_deprecated_detection_text_is_left_as_it_was(self):
        """``x_mitre_detection`` is deprecated in ATT&CK; the collector reads it as before (first 1,000)."""
        obj = copy.deepcopy(_object("enterprise", "T1136"))
        obj["x_mitre_detection"] = "d" * 1200  # constructed: ATT&CK 20.1 publishes no detection text
        item = _item("technique", "T1136", _parsed(objects=[obj]))
        assert item["detection"] == "d" * 1000


# ============================================================================================ 2. platforms
class TestPlatforms:
    def test_the_collector_passes_every_platform_of_a_technique(self):
        assert _item("technique", "T1136")["platforms"] == T1136_PLATFORMS

    @pytest.mark.parametrize(
        ("kind", "attack_id", "platforms"),
        [
            ("malware", "S1072", ["Field Controller/RTU/PLC/IED", "Engineering Workstation"]),
            ("tool", "S0363", ["Linux", "macOS", "Windows"]),
            ("tool", "S0039", ["Windows"]),
        ],
    )
    def test_the_collector_passes_the_platforms_of_software(self, kind, attack_id, platforms):
        assert _item(kind, attack_id)["platforms"] == platforms

    def test_every_platform_is_a_tag_in_attacks_casing(self):
        attribute = _attribute("technique", _item("technique", "T1136"))
        assert [t for t in _tags(attribute) if t.startswith("platform:")] == [f"platform:{p}" for p in T1136_PLATFORMS]

    @pytest.mark.parametrize(
        ("kind", "attack_id", "platforms"),
        [
            ("malware", "S1072", ["Field Controller/RTU/PLC/IED", "Engineering Workstation"]),
            ("tool", "S0363", ["Linux", "macOS", "Windows"]),
        ],
    )
    def test_software_carries_its_platform_tags(self, kind, attack_id, platforms):
        attribute = _attribute(kind, _item(kind, attack_id))
        assert [t for t in _tags(attribute) if t.startswith("platform:")] == [f"platform:{p}" for p in platforms]

    def test_the_sync_reads_every_platform(self):
        item, _ = _synced(_attribute("technique", _item("technique", "T1136")))
        assert item["platforms"] == T1136_PLATFORMS

    def test_the_sync_reads_attacks_casing_from_the_lower_case_tags_misp_holds(self):
        """MISP resolves a tag name without regard to case and keeps the casing of a tag it already holds, so an
        attribute pushed with ``platform:Windows`` comes back with an existing ``platform:windows``. Constructed: the
        writer's attribute with its platform tags as such a MISP returns them, a repeat and a value ATT&CK 20.1
        does not use."""
        attribute = _attribute("technique", _item("technique", "T1136"))
        for tag in attribute["Tag"]:
            if tag["name"].startswith("platform:"):
                tag["name"] = tag["name"].lower()
        attribute["Tag"] += [{"name": "platform:WINDOWS"}, {"name": "platform:Quantum  Device"}]
        item, _ = _synced(attribute)
        assert item["platforms"] == T1136_PLATFORMS + ["Quantum Device"]

    @pytest.mark.parametrize(
        ("stored", "attack"),
        [
            # Lower-case ``platform:`` tags, as the project's hosted MISP
            # listed them (structure audit of 2026-10-09).
            ("windows", "Windows"),
            ("linux", "Linux"),
            ("macos", "macOS"),
            ("esxi", "ESXi"),
            ("iaas", "IaaS"),
            ("pre", "PRE"),
            ("containers", "Containers"),
            ("network devices", "Network Devices"),
            ("office suite", "Office Suite"),
            ("identity provider", "Identity Provider"),
            ("saas", "SaaS"),
            ("office 365", "Office 365"),
            ("field controller/rtu/plc/ied", "Field Controller/RTU/PLC/IED"),
        ],
    )
    def test_each_lower_case_platform_tag_maps_to_attacks_name(self, stored, attack):
        assert canonical_attack_platform(stored) == attack

    def test_the_table_holds_every_platform_of_the_recorded_objects(self):
        recorded = {
            p for domain in ("enterprise", "ics") for o in FIXTURE[domain] for p in o.get("x_mitre_platforms") or []
        }
        assert recorded and recorded <= set(ATTACK_PLATFORMS)
        assert all(canonical_attack_platform(p) == p for p in ATTACK_PLATFORMS)

    def test_the_collector_skips_blank_and_non_string_platforms(self):
        obj = copy.deepcopy(_object("enterprise", "S0039"))
        obj["x_mitre_platforms"] = ["Windows", "", "  ", None, 5]  # constructed
        assert _item("tool", "S0039", _parsed(objects=[obj]))["platforms"] == ["Windows"]

    def test_control_characters_are_removed_from_a_platform(self):
        item = dict(_item("technique", "T1136"), platforms=["Win\x00dows", "Net\x1fwork Devices"])  # constructed
        assert [t for t in _tags(_attribute("technique", item)) if t.startswith("platform:")] == [
            "platform:Windows",
            "platform:Network Devices",
        ]

    def test_platform_values_are_cleaned_and_bounded(self):
        """Constructed values: a duplicate in another case, a blank, a non-string and an over-long name are skipped."""
        item = dict(
            _item("technique", "T1136"),
            platforms=["Windows", "windows", "  ", None, "x" * 65, "Network  Devices", "Linux"],
        )
        assert [t for t in _tags(_attribute("technique", item)) if t.startswith("platform:")] == [
            "platform:Windows",
            "platform:Network Devices",
            "platform:Linux",
        ]
        many = dict(item, platforms=[f"P{i}" for i in range(40)])
        assert len([t for t in _tags(_attribute("technique", many)) if t.startswith("platform:")]) == 32


# ============================================================================================ 3. tool aliases
class TestToolAliases:
    @pytest.mark.parametrize(
        ("attack_id", "aliases"),
        [("S0039", ["Net", "net.exe"]), ("S0363", ["Empire", "EmPyre", "PowerShell Empire"])],
    )
    def test_a_tool_carries_its_alias_tags(self, attack_id, aliases):
        item = _item("tool", attack_id)
        assert item["aliases"] == aliases
        assert [t for t in _tags(_attribute("tool", item)) if t.startswith("alias:")] == [f"alias:{a}" for a in aliases]

    def test_a_tools_alias_is_bounded_at_100_characters(self):
        item = dict(_item("tool", "S0039"), aliases=["a" * 150])  # constructed
        (alias,) = [t for t in _tags(_attribute("tool", item)) if t.startswith("alias:")]
        assert alias == "alias:" + "a" * 97 + "..."

    def test_actor_and_malware_alias_tags_are_unchanged(self):
        actor = _item("actor", "G0034")
        assert [t for t in _tags(_attribute("actor", actor)) if t.startswith("alias:")] == [
            f"alias:{a}" for a in actor["aliases"][:20]
        ]
        malware = _item("malware", "S1072")
        assert [t for t in _tags(_attribute("malware", malware)) if t.startswith("alias:")] == ["alias:Industroyer2"]


# ============================================================================================ 4. domains
class TestAttackDomains:
    @pytest.mark.parametrize(
        ("kind", "attack_id", "domains"),
        [
            ("actor", "G0034", ["enterprise", "ics", "mobile"]),
            ("malware", "S1072", ["ics", "enterprise"]),
            ("tool", "S0039", ["enterprise"]),
        ],
    )
    def test_the_collector_reads_x_mitre_domains(self, kind, attack_id, domains):
        assert _item(kind, attack_id)["attack_domains"] == domains
        assert _item(kind, attack_id, _merged())["attack_domains"] == domains

    @pytest.mark.parametrize(
        ("kind", "attack_id", "domains"),
        [
            ("actor", "G0034", ["enterprise", "ics", "mobile"]),
            ("malware", "S1072", ["ics", "enterprise"]),
            ("tool", "S0039", ["enterprise"]),
        ],
    )
    def test_each_domain_is_a_tag(self, kind, attack_id, domains):
        tags = _tags(_attribute(kind, _item(kind, attack_id)))
        assert [t for t in tags if t.startswith("attack-domain:")] == [f"attack-domain:{d}" for d in domains]

    def test_the_collector_reads_a_domain_in_any_case(self):
        """Constructed: ATT&CK writes its domains in lower case. Read from the Enterprise bundle, so the bundle's own
        domain (the fallback) is not the answer."""
        obj = copy.deepcopy(_object("enterprise", "S1072"))
        obj["x_mitre_domains"] = [" ICS-Attack "]
        assert _item("malware", "S1072", _parsed("enterprise", [obj]))["attack_domains"] == ["ics"]

    def test_an_object_without_domains_takes_its_bundles(self):
        obj = copy.deepcopy(_object("ics", "S1072"))
        del obj["x_mitre_domains"]  # constructed: every ATT&CK 20.1 group and software lists its domains
        assert _item("malware", "S1072", _parsed("ics", [obj]))["attack_domains"] == ["ics"]

    def test_the_items_of_one_object_unite_their_domains(self):
        """Constructed: the ICS copy of Sandworm Team lists only ``ics-attack``, the Enterprise one only
        ``enterprise-attack``; the kept item carries both."""
        ent = copy.deepcopy(_object("enterprise", "G0034"))
        ent["x_mitre_domains"] = ["enterprise-attack"]
        ics = copy.deepcopy(_object("ics", "G0034"))
        ics["x_mitre_domains"] = ["ics-attack"]
        merged = mc.MITRECollector._merge_domain_bundles(_parsed("enterprise", [ent]), _parsed("ics", [ics]))
        assert _item("actor", "G0034", merged)["attack_domains"] == ["enterprise", "ics"]

    def test_the_items_of_one_object_unite_their_platforms(self):
        """Constructed: in ATT&CK 20.1 both copies of Industroyer2 list the same platforms; here the Enterprise copy
        lists one and the ICS copy two. The kept item (Enterprise first) carries both, once each."""
        ent = copy.deepcopy(_object("enterprise", "S1072"))
        ent["x_mitre_platforms"] = ["Engineering Workstation"]
        ics = copy.deepcopy(_object("ics", "S1072"))
        ics["x_mitre_platforms"] = ["Field Controller/RTU/PLC/IED", "Engineering Workstation"]
        merged = mc.MITRECollector._merge_domain_bundles(_parsed("enterprise", [ent]), _parsed("ics", [ics]))
        item = _item("malware", "S1072", merged)
        assert item["platforms"] == ["Engineering Workstation", "Field Controller/RTU/PLC/IED"]
        assert "platform:Field Controller/RTU/PLC/IED" in _tags(_attribute("malware", item))

    def test_techniques_and_tactics_keep_their_one_domain_tag(self):
        for kind, attack_id in (("technique", "T1136"), ("tactic", "TA0004")):
            tags = _tags(_attribute(kind, _item(kind, attack_id)))
            assert [t for t in tags if t.startswith("attack-domain:")] == ["attack-domain:enterprise"]

    def test_unknown_domains_give_no_tag(self):
        item = dict(_item("actor", "G0034"), attack_domains=["enterprise", "pre", "ICS", "enterprise"])
        assert [t for t in _tags(_attribute("actor", item)) if t.startswith("attack-domain:")] == [
            "attack-domain:enterprise",
            "attack-domain:ics",
        ]


# ============================================================================================ 5. galaxy tags
class TestAttackGalaxyTags:
    @pytest.mark.parametrize(
        ("kind", "attack_id", "community"),
        [
            ("actor", "G0034", 'misp-galaxy:threat-actor="Sandworm Team"'),
            ("malware", "S1072", 'misp-galaxy:malware="Industroyer2"'),
            ("tool", "S0039", 'misp-galaxy:tool="Net"'),
            ("tool", "S0363", 'misp-galaxy:tool="Empire"'),
        ],
    )
    def test_attacks_own_cluster_beside_the_community_cluster(self, kind, attack_id, community):
        item = _item(kind, attack_id)
        tags = _tags(_attribute(kind, item))
        (cluster,) = FIXTURE["galaxy_clusters"][f"{item['name']} - {attack_id}"]
        assert community in tags
        assert cluster["tag_name"] in tags  # the tag the MISP galaxy cluster carries, as recorded
        assert [t for t in tags if t.startswith("misp-galaxy:mitre-")] == [cluster["tag_name"]]

    @pytest.mark.parametrize("attack_id", ["T1553.003", "T1136", "T1136.001"])
    def test_a_techniques_cluster_tag_is_the_recorded_one(self, attack_id):
        item = _item("technique", attack_id)
        (cluster,) = FIXTURE["galaxy_clusters"][f"{item['name']} - {attack_id}"]
        assert cluster["tag_name"] in _tags(_attribute("technique", item))

    def test_the_attack_id_is_read_stripped_and_upper_cased(self):
        item = dict(_item("tool", "S0039"), mitre_id=" s0039 ")  # constructed
        assert [t for t in _tags(_attribute("tool", item)) if t.startswith("misp-galaxy:mitre-")] == [
            'misp-galaxy:mitre-tool="Net - S0039"'
        ]

    @pytest.mark.parametrize(
        ("kind", "attack_id", "mitre_id"),
        [("tool", "S0039", "G0001"), ("actor", "G0034", "S0001"), ("malware", "S1072", "T1136")],
    )
    def test_an_id_of_another_kind_gives_no_attack_cluster(self, kind, attack_id, mitre_id):
        item = dict(_item(kind, attack_id), mitre_id=mitre_id)  # constructed
        assert not [t for t in _tags(_attribute(kind, item)) if t.startswith("misp-galaxy:mitre-")]

    def test_a_tool_without_an_id_gets_no_attack_cluster(self):
        """``create_tool_attribute`` writes no attribute for a tool without an id; the helper itself gives none."""
        assert mw._attack_galaxy_tags({"type": "tool", "name": "Net"}, "Net") == []

    @pytest.mark.parametrize(("kind", "attack_id"), [("actor", "G0034"), ("malware", "S1072"), ("tool", "S0039")])
    def test_a_name_with_a_double_quote_gets_no_attack_cluster(self, kind, attack_id):
        item = dict(_item(kind, attack_id), name='Net "x"')  # constructed: a quote would end the tag's value
        assert not [t for t in _tags(_attribute(kind, item)) if t.startswith("misp-galaxy:mitre-")]

    def test_an_item_without_an_attack_id_gets_none(self):
        """Constructed items as another source gives them (an OTX family or adversary): no ATT&CK id, domains or
        platforms, so none of their tags."""
        for kind, item in (
            ("malware", {"type": "malware", "name": "Industroyer2", "tag": "alienvault_otx"}),
            ("actor", {"type": "actor", "name": "Sandworm Team", "tag": "alienvault_otx"}),
            ("malware", {"type": "malware", "name": "X", "tag": "mitre_attck", "mitre_id": "G0034"}),
        ):
            tags = _tags(_attribute(kind, item))
            assert not [t for t in tags if t.startswith(("misp-galaxy:mitre-", "attack-domain:", "platform:"))]


# ============================================================================================ 6. MISP holds it
class TestMispHoldsTheWholeText:
    def test_the_longest_technique_round_trips(self):
        full = _text("T1553.003")
        attribute = _attribute("technique", _item("technique", "T1553.003"))
        assert attribute["comment"].startswith('MITRE_TACTIC_PHASES:{"p":["defense-impairment"]}\n')
        assert _comment_text(attribute) == full
        item, _ = _synced(attribute)
        assert item["description"] == full and item["tactic_phases"] == ["defense-impairment"]

    @pytest.mark.parametrize(
        ("kind", "attack_id", "block"),
        [
            ("technique", "T1136.001", "MITRE_TACTIC_PHASES"),
            ("actor", "G0034", "MITRE_USES_TECHNIQUES"),
            ("malware", "S1072", "MITRE_USES_TECHNIQUES"),
            ("tool", "S0039", "MITRE_USES_TECHNIQUES"),
        ],
    )
    def test_the_whole_text_follows_the_block(self, kind, attack_id, block):
        attribute = _attribute(kind, _item(kind, attack_id))
        assert attribute["comment"].startswith(block + ":")
        assert _comment_text(attribute) == _text(attack_id).strip()
        assert _synced(attribute)[0]["description"] == _text(attack_id).strip()

    def test_the_tools_block_still_carries_its_techniques(self):
        item, _ = _synced(_attribute("tool", _item("tool", "S0039")))
        assert item["uses_techniques"] == ["T1136.001"]

    @pytest.mark.parametrize(("kind", "attack_id"), [("tactic", "TA0004"), ("tool", "S0363")])
    def test_without_a_block_the_whole_text_is_the_comment(self, kind, attack_id):
        attribute = _attribute(kind, _item(kind, attack_id))
        assert not _METADATA_COMMENT_RE.match(attribute["comment"])
        # The writer strips the whitespace around a text (TA0004's ends in two spaces).
        assert attribute["comment"] == _text(attack_id).strip() and len(attribute["comment"]) > 500
        assert _synced(attribute)[0]["description"] == _text(attack_id).strip()

    def test_a_text_over_the_bound_is_cut_at_a_word_end(self, caplog):
        """Constructed: no ATT&CK text comes near ``ENTITY_DESCRIPTION_MAX_CHARS``."""
        long_text = "word " * 2000  # 10,000 characters
        item = dict(_item("tactic", "TA0004"), description=long_text)
        with caplog.at_level(logging.WARNING, logger=mw.logger.name):
            comment = _attribute("tactic", item)["comment"]
        assert len(comment) <= mw.ENTITY_DESCRIPTION_MAX_CHARS == 8000
        assert len(comment) > 7990 and long_text.startswith(comment) and comment.endswith("word")
        (line,) = [r.getMessage() for r in caplog.records if "[ENTITY-TEXT]" in r.getMessage()]
        assert "tactic TA0004: description of 9999 characters" in line and "word" not in line.split(":", 1)[1]

    def test_a_cut_at_a_run_of_whitespace_leaves_no_trailing_space(self):
        """Constructed: the last whitespace within the bound follows another one."""
        item = dict(_item("tactic", "TA0004"), description="a" * 7998 + "  " + "b" * 100)
        assert _attribute("tactic", item)["comment"] == "a" * 7998

    @pytest.mark.parametrize("description", [5, 12.5, ["a list"], {"a": "map"}])
    def test_a_description_that_is_not_text_gives_the_placeholder(self, description):
        item = dict(_item("tactic", "TA0004"), description=description)  # constructed
        assert _attribute("tactic", item)["comment"] == "MITRE ATT&CK tactic"

    def test_a_text_without_whitespace_over_the_bound_keeps_its_first_8000(self):
        item = dict(_item("tactic", "TA0004"), description="x" * 9000)
        assert _attribute("tactic", item)["comment"] == "x" * 8000

    def test_control_characters_are_removed_and_line_breaks_kept(self):
        item = dict(_item("tactic", "TA0004"), description=" A\x00b\x1fc.\n\nD\te. ")
        assert _attribute("tactic", item)["comment"] == "Abc.\n\nD\te."


# ============================================================================================ 7. the sync
def _without_new_tags(kind: str, attribute: Dict[str, Any]) -> Dict[str, Any]:
    """``attribute`` with the tags this change adds removed, and a technique's platform tags cut to its first 3 (the
    writer's tags before 2026-11-07, apart from the platforms' case)."""
    out = copy.deepcopy(attribute)
    kept = []
    platforms = 0
    for tag in out["Tag"]:
        name = tag["name"]
        if name.startswith("misp-galaxy:mitre-") and kind != "technique":
            continue
        if name.startswith("attack-domain:") and kind in ("actor", "malware", "tool"):
            continue
        if kind == "tool" and name.startswith("alias:"):
            continue
        if name.startswith("platform:"):
            platforms += 1
            if kind != "technique" or platforms > 3:
                continue
        kept.append(tag)
    out["Tag"] = kept
    return out


class TestTheSyncReadsTheNewTagsSafely:
    @pytest.mark.parametrize(
        ("kind", "attack_id"),
        [("actor", "G0034"), ("malware", "S1072"), ("tool", "S0039"), ("tool", "S0363"), ("technique", "T1136")],
    )
    def test_the_new_tags_change_only_the_platforms(self, kind, attack_id):
        attribute = _attribute(kind, _item(kind, attack_id, _merged()))
        before = _without_new_tags(kind, attribute)
        assert len(before["Tag"]) < len(attribute["Tag"])
        item, relationships = _synced(attribute)
        old_item, old_relationships = _synced(before)
        assert relationships == old_relationships
        if kind == "technique":
            assert item.pop("platforms") == T1136_PLATFORMS and old_item.pop("platforms") == T1136_PLATFORMS[:3]
        assert item == old_item

    @pytest.mark.parametrize(("kind", "attack_id"), [("actor", "G0034"), ("malware", "S1072"), ("tool", "S0039")])
    def test_no_tag_becomes_a_sector_zone_or_link(self, kind, attack_id):
        attribute = _attribute(kind, _item(kind, attack_id, _merged()))
        item, relationships = _synced(attribute)
        assert item["zone"] == ["global"]
        assert relationships == [] and item.get("relationships", []) == []
        syncer = MISPToNeo4jSync(neo4j_client=MagicMock())
        assert syncer._extract_sector_from_tags(attribute["Tag"]) is None
        assert syncer._extract_threat_actor_from_tags(attribute["Tag"]) == (
            "Sandworm Team" if kind == "actor" else None
        )

    @pytest.mark.parametrize(
        ("kind", "attack_id", "cut"),
        [
            ("technique", "T1553.003", True),
            ("actor", "G0034", True),
            ("tool", "S0039", True),
            ("tactic", "TA0004", True),
            # 667 characters, 500 or fewer once its markup is stripped: the node holds it without the markup
            ("malware", "S1072", False),
        ],
    )
    def test_the_sync_stores_the_capped_description(self, bolt, kind, attack_id, cut):
        full = _text(attack_id).strip()
        expected, truncated, length = cap_text(full, ENTITY_DESCRIPTION_CAP)
        assert len(full) > 500 and truncated is cut and len(expected) <= 500 and (length > 500) is cut
        server, client = bolt()
        item, _ = _synced(_attribute(kind, _item(kind, attack_id, _merged())))
        assert getattr(client, _MERGES[kind])(item, source_id="mitre_attck") is True
        (node,) = _statements(server, f"MERGE (n:{_LABELS[kind]} {{")
        assert node["ranked_description"] == expected
        (edge,) = [p for p in _statements(server, "MERGE (n)-[r:SOURCED_FROM]->(s)") if "raw_data" in p]
        assert json.loads(edge["raw_data"])["description"] == expected

    def test_the_chunk_merges_only_the_items_own_nodes(self, bolt):
        """Through ``_sync_to_neo4j_chunk``: one node per item, no Sector, no other label from a tag."""
        merged = _merged()
        items = [
            _synced(_attribute(kind, _item(kind, attack_id, merged)))[0]
            for kind, attack_id in (("actor", "G0034"), ("malware", "S1072"), ("tool", "S0039"), ("tool", "S0363"))
        ]
        server, client = bolt()
        assert MISPToNeo4jSync(neo4j_client=client)._sync_to_neo4j_chunk(items) == (4, 0)
        merges = [q for q in server.runs if "MERGE (n:" in q]
        assert sorted(q.split("MERGE (n:", 1)[1].split(" ", 1)[0] for q in merges) == [
            "Malware",
            "ThreatActor",
            "Tool",
            "Tool",
        ]
        assert not [q for q in server.runs if "Sector" in q]


# ============================================================================================ docs
class TestDocs:
    def test_the_attack_notice_is_in_data_sources(self):
        text = (REPO / "docs" / "DATA_SOURCES.md").read_text(encoding="utf-8")
        assert (
            "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The "
            "MITRE Corporation." in text
        )
        assert FIXTURE["_provenance"]["attack"]["licence"].startswith("MITRE ATT&CK, (c) 2026 The MITRE Corporation")

    @pytest.mark.parametrize("name", ["COLLECTORS.md", "MISP_SOURCES.md"])
    def test_the_platform_tag_casing_is_stated_as_the_current_state(self, name):
        """The main text says what MISP returns for a ``platform:`` tag it already holds in another casing; earlier
        writer behaviour belongs only in the History section."""
        main = (REPO / "docs" / name).read_text(encoding="utf-8").split("\n## History", 1)[0]
        assert "already holds a `platform:` tag in another casing (`platform:windows`" in main
        assert "earlier writer versions" not in main
        assert "lower-case `platform:` tags of" not in main
