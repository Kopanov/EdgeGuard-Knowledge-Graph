"""A Malware, ThreatActor or Tool description comes from MITRE ATT&CK (2026-10).

``merge_malware``, ``merge_actor`` and ``merge_tool`` set the description from whatever record was merged
last. The OTX collector gave every malware family and adversary of a pulse the pulse's description, so
ATT&CK's description of Cobalt Strike or Dragonfly was replaced by a report's text whenever an OTX record
was merged after MITRE's. The sync's malware branch stored a comment that was only a
``MITRE_USES_TECHNIQUES`` block (an OTX family from a pulse without a description) as the description
(``tail or description``), every branch that reads a block stored the raw comment when the block did not
parse, and the STIX objects of the opt-in STIX flow carried the raw comment.

The rule now: the source ranking MITRE ATT&CK > a curated source > any other source decides the description,
and the node names its source in ``description_source`` (``description_ranking``, 2026-10-16; until then
MITRE's record set it and any other record only filled an empty one, so on a node MITRE does not describe
the first source to arrive kept its text; a Technique or Tactic took any record's). The OTX collector gives family and adversary
items no description; the sync takes none from an OTX malware or actor attribute (MISP keeps the ones
written before 2026-10, with the pulse's text after the block), none from a metadata block, a block that
does not parse, a block after other text, or MISPWriter's placeholder for an item without text
(``run_misp_to_neo4j._entity_comment_description``). The STIX objects follow the same rule, and the MITRE
collector now gives tactics ATT&CK's description (the sync stored the placeholder "MITRE ATT&CK tactic").

Fixtures: ATT&CK STIX objects in the shape of the ``mitre/cti`` bundle (the helpers of
``test_attack_revoked_objects.py``) with ATT&CK's ids, names and descriptions of Dragonfly (G0035),
Cobalt Strike (S0154), Mimikatz (S0002), PowerShell (T1059.001) and Execution (TA0002); Dragonfly's
aliases as its attribute on the hosted MISP carried them on 2026-10-09. The real OTX malware and actor
attributes of the hosted MISP of 2026-10-09, KATARU and JeetBot, copied verbatim
(``tests/fixtures/otx_entity_attributes_2026_10_09.json``): a ``MITRE_USES_TECHNIQUES`` block in the form
MISPWriter wrote before 2026-10-10 (``t``), then the pulse's description. The KATARU pulse in the shape
the OTX API returns, rebuilt from what that MISP held of it: its name, reference, author, timestamps,
seven tags and sixteen ATT&CK ids, one of its indicators (160.191.242.92), and as its description the text
after the KATARU attribute's block (the pulse's description cut at 400 characters by MISPWriter; the rest
was not captured). The case of an entity MITRE and OTX both describe uses a constructed pulse
(``REPORT_PULSE``), since the capture holds no OTX attribute of such an entity; its pre-2026-10 attribute
is built both in the form MISPWriter writes since 2026-10-10 (``rt``, ``pid``) and in the earlier one.
All go through the collectors' own code (``MITRECollector._parse_bundle``, ``OTXCollector.collect``),
MISPWriter's attribute builders and the sync's ``parse_attribute``, as a baseline writes and reads them.
The same rule on a real Neo4j: ``tests/test_entity_description_neo4j.py`` and
``tests/test_description_ranking_neo4j.py``.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_attack_revoked_objects import _ext, _group, _parse, _rel, _sdo, _software, _technique  # noqa: E402
from test_description_ranking import SINGLE_PARAMS, apply_statement  # noqa: E402  (the ranked SET)

import neo4j_client  # noqa: E402
import run_misp_to_neo4j  # noqa: E402
from collectors import misp_writer  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402
from description_ranking import ENTITY_DESCRIPTIONS  # noqa: E402
from run_misp_to_neo4j import (  # noqa: E402
    _METADATA_COMMENT_RE,
    MISPToNeo4jSync,
    _entity_comment_description,
)

WRITER = misp_writer.MISPWriter.__new__(misp_writer.MISPWriter)

# ---------------------------------------------------------------- ATT&CK objects (mitre/cti bundle shape)
DRAGONFLY = "intrusion-set--1c63d4ec-0a75-4daa-b1df-0d11af3d3cc1"
COBALT_STRIKE = "malware--aafea02e-ece5-4bb2-91a6-3bf8c7f38a39"
MIMIKATZ = "tool--afc079f3-c0ea-4096-b75d-3f05338b7f60"
POWERSHELL = "attack-pattern--970cdb5c-02fb-4c38-b17e-d6327cf3c810"
EXECUTION = "x-mitre-tactic--4ca45d45-df4d-4613-8980-bac22d278fa5"

DRAGONFLY_ALIASES = [  # the alias: tags of the Dragonfly attribute on the hosted MISP, 2026-10-09
    "Dragonfly",
    "TEMP.Isotope",
    "DYMALLOY",
    "Berserk Bear",
    "TG-4192",
    "Crouching Yeti",
    "IRON LIBERTY",
    "Energetic Bear",
    "Ghost Blizzard",
    "BROMINE",
]
DRAGONFLY_TEXT = (
    "[Dragonfly](https://attack.mitre.org/groups/G0035) is a cyber espionage group that has been attributed "
    "to Russia's Federal Security Service (FSB) Center 16.(Citation: DOJ Russia Targeting Critical "
    "Infrastructure March 2022)(Citation: UK GOV FSB Factsheet April 2022) Active since at least 2010, "
    "Dragonfly has targeted defense and aviation companies, government entities, companies related to "
    "industrial control systems, and critical infrastructure sectors worldwide through supply chain, "
    "spearphishing, and drive-by compromise attacks.(Citation: Symantec Dragonfly)"
)
COBALT_STRIKE_TEXT = (
    "[Cobalt Strike](https://attack.mitre.org/software/S0154) is a commercial, full-featured, remote access "
    "tool that bills itself as “adversary simulation software designed to execute targeted attacks and "
    "emulate the post-exploitation actions of advanced threat actors”. Cobalt Strike’s interactive "
    "post-exploit capabilities cover the full range of ATT&CK tactics, all executed within a single, "
    "integrated system.(Citation: cobaltstrike manual)\n\nIn addition to its own capabilities, [Cobalt "
    "Strike](https://attack.mitre.org/software/S0154) leverages the capabilities of other well-known tools "
    "such as Metasploit and [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: cobaltstrike manual)"
)
MIMIKATZ_TEXT = (
    "[Mimikatz](https://attack.mitre.org/software/S0002) is a credential dumper capable of obtaining "
    "plaintext Windows account logins and passwords, along with many other features that make it useful "
    "for testing the security of networks. (Citation: Deply Mimikatz) (Citation: Adsecurity Mimikatz Guide)"
)
POWERSHELL_TEXT = (
    "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive "
    "command-line interface and scripting environment included in the Windows operating system.(Citation: "
    "TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of "
    "information and execution of code."
)
EXECUTION_TEXT = "The adversary is trying to run malicious code."
ATTACK_TEXT = {
    "actor": DRAGONFLY_TEXT,
    "malware": COBALT_STRIKE_TEXT,
    "tool": MIMIKATZ_TEXT,
    "technique": POWERSHELL_TEXT,
    "tactic": EXECUTION_TEXT,
}


def _attack_objects() -> list:
    return [
        _technique(POWERSHELL, "T1059.001", "PowerShell", description=POWERSHELL_TEXT),
        _group(DRAGONFLY, "G0035", "Dragonfly", DRAGONFLY_ALIASES, description=DRAGONFLY_TEXT),
        _software(
            "malware", COBALT_STRIKE, "S0154", "Cobalt Strike", ["Cobalt Strike"], description=COBALT_STRIKE_TEXT
        ),
        _software("tool", MIMIKATZ, "S0002", "Mimikatz", ["Mimikatz"], description=MIMIKATZ_TEXT),
        _sdo(
            "x-mitre-tactic",
            EXECUTION,
            "Execution",
            description=EXECUTION_TEXT,
            x_mitre_shortname="execution",
            external_references=_ext("TA0002", "tactics"),
        ),
        _rel(1, "uses", DRAGONFLY, POWERSHELL),
        _rel(2, "uses", DRAGONFLY, COBALT_STRIKE),
        _rel(3, "uses", DRAGONFLY, MIMIKATZ),
        _rel(4, "uses", COBALT_STRIKE, POWERSHELL),
        _rel(5, "uses", MIMIKATZ, POWERSHELL),
    ]


def mitre_items() -> dict:
    """The MITRE collector's items for the ATT&CK objects above, by kind."""
    parsed = _parse(_attack_objects())
    return {
        "actor": parsed["actors"][0],
        "malware": parsed["malware"][0],
        "tool": parsed["tools"][0],
        "technique": parsed["techniques"][0],
        "tactic": parsed["tactics"][0],
    }


# ---------------------------------------------------------------- real OTX attributes (hosted MISP, 2026-10-09)
_REAL = json.loads((TESTS / "fixtures" / "otx_entity_attributes_2026_10_09.json").read_text())["attributes"]


def as_misp_returns(captured: dict) -> dict:
    """A captured attribute as MISP returns it: its tag names as ``Tag`` objects."""
    attr = {k: copy.deepcopy(v) for k, v in captured.items() if k != "tags"}
    attr["Tag"] = [{"name": name} for name in captured["tags"]]
    return attr


REAL_OTX = {a["value"]: a for a in _REAL}  # KATARU (malware-type), JeetBot (threat-actor)
_KATARU_BLOCK, _, KATARU_TEXT = REAL_OTX["KATARU"]["comment"].partition("\n")
KATARU_IDS = json.loads(_KATARU_BLOCK.split(":", 1)[1])["t"]

# ---------------------------------------------------------------- OTX pulses (OTX API shape)
KATARU_PULSE = {
    "id": "68c30a2bd84d2a2fe1fc3f4b",
    # Rebuilt from the hosted MISP of 2026-10-09 (module docstring): OTX_META of its indicators (tags,
    # references, author, ATT&CK ids; no TLP, the collector read none), the KATARU attribute (description,
    # first_seen = the pulse's ``created``, last_seen = its ``modified``).
    "name": "KATARU: IoT Malware Adopts Public LPE Exploits",
    "description": KATARU_TEXT,
    "created": "2026-09-11T17:55:38.561000",
    "modified": "2026-09-14T10:32:06.888000",
    "adversary": "",
    "author_name": "AlienVault",
    "attack_ids": [{"id": i} for i in KATARU_IDS],
    "tags": [
        "telnet brute-force",
        "cve-2026-46300",
        "kataru",
        "cve-2026-31431",
        "cve-2026-43284",
        "ddos",
        "iot botnet",
    ],
    "references": ["https://www.nozominetworks.com/blog/kataru-iot-malware-adopts-public-lpe-exploits"],
    "targeted_countries": [],
    "industries": [],
    "malware_families": ["KATARU"],
    "indicators": [
        {"type": "IPv4", "indicator": "160.191.242.92", "description": "", "created": "2026-09-11T17:55:39"}
    ],
}
# Constructed: the capture of 2026-10-09 holds no OTX attribute of an entity ATT&CK also describes.
REPORT_TEXT = (
    "Phishing campaign against European energy operators: Word attachments drop Cobalt Strike beacons, "
    "and the operators used them to harvest credentials and move laterally."
)
REPORT_PULSE = {
    "id": "68c30a2bd84d2a2fe1fc3f4c",
    "name": "Dragonfly phishing against energy operators",
    "description": REPORT_TEXT,
    "created": "2026-09-12T08:10:00",
    "modified": "2026-09-12T08:10:00",
    "TLP": "white",
    "adversary": "Dragonfly",
    "author_name": "AlienVault",
    "attack_ids": [{"id": "T1566.001"}, {"id": "T1059.001"}],
    "tags": ["dragonfly", "energy"],
    "references": [],
    "industries": ["Energy"],
    "malware_families": [{"display_name": "Cobalt Strike", "name": "Cobalt Strike"}],
    "indicators": [{"type": "domain", "indicator": "update-check.example.org", "description": "C2 domain"}],
}


def otx_items(*pulses: dict) -> list:
    """The OTX collector's items for *pulses* (one incremental run)."""
    collector = oc.OTXCollector.__new__(oc.OTXCollector)
    collector.api_key = "a" * 64
    collector.tag = "alienvault_otx"
    collector.session = MagicMock()
    collector.rate_limiter = MagicMock()
    collector._last_http_status = 200
    collector.circuit_breaker = MagicMock()
    collector.misp_writer = None
    collector.source_name = "otx"
    pages = iter([[copy.deepcopy(p) for p in pulses]])
    with (
        patch.object(collector, "check_service_available", return_value=True),
        patch.object(collector, "_fetch_pulses", side_effect=lambda **_kw: next(pages, [])),
        patch.object(oc.time, "sleep"),
        patch.object(oc, "get_source_incremental", return_value={}),
        patch.object(oc, "update_source_incremental"),
    ):
        return collector.collect(limit=10, push_to_misp=False, baseline=False)


def otx_item(kind: str, name: str, *pulses: dict) -> dict:
    return next(i for i in otx_items(*pulses) if i.get("type") == kind and i["name"].lower() == name.lower())


def otx_item_before_2026_10(kind: str, name: str) -> dict:
    """The item the OTX collector gave until 2026-10 for *name* in ``REPORT_PULSE``: the pulse's
    description as the entity's. MISP keeps the attributes written from such items."""
    return dict(otx_item(kind, name, REPORT_PULSE), description=REPORT_TEXT)


# ---------------------------------------------------------------- MISP round trip
_BUILDERS = {
    "actor": "create_actor_attribute",
    "malware": "create_malware_attribute",
    "tool": "create_tool_attribute",
    "technique": "create_technique_attribute",
    "tactic": "create_tactic_attribute",
}
_EVENTS = {
    "mitre_attck": {"id": "33", "info": "EdgeGuard-mitre_attck-2026-10-13", "Tag": []},
    "alienvault_otx": {"id": "34", "info": "EdgeGuard-alienvault_otx-2026-10-13", "Tag": []},
    "misp": {"id": "35", "info": "Partner event", "Tag": []},
}


def written(kind: str, item: dict) -> dict:
    """The MISP attribute MISPWriter writes for *item*."""
    attr = getattr(WRITER, _BUILDERS[kind])(item)
    assert attr is not None
    attr["uuid"] = "5f0c1a2e-0000-4000-8000-0000000000%02d" % (sorted(_BUILDERS).index(kind) + 1)
    return attr


def synced(attr: dict, source: str = "mitre_attck") -> dict:
    """*attr* read by the sync."""
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(copy.deepcopy(attr), _EVENTS[source])
    assert item is not None
    return item


def stix(attr: dict) -> dict:
    """The STIX object the STIX flow builds from *attr*."""
    obj = MISPToNeo4jSync(neo4j_client=MagicMock())._attribute_to_stix21(
        copy.deepcopy(attr), "00000000-0000-4000-8000-000000000000", ["global"]
    )
    assert obj is not None
    return obj


def text_after_block(attr: dict) -> str:
    """The text MISPWriter wrote after the attribute's ``MITRE_*`` block (the entity's description)."""
    block, _, text = attr["comment"].partition("\n")
    assert _METADATA_COMMENT_RE.match(block) and text
    return text


def in_form_before_2026_10_10(attr: dict) -> dict:
    """An OTX attribute of *attr*'s in the form MISPWriter wrote before 2026-10-10, as the KATARU and
    JeetBot attributes of 2026-10-09 show it: the pulse's ATT&CK ids under ``t``, no ``pid``."""
    attr = copy.deepcopy(attr)
    block, sep, text = attr["comment"].partition("\n")
    meta = json.loads(block.split(":", 1)[1])
    attr["comment"] = "MITRE_USES_TECHNIQUES:" + json.dumps({"t": meta["rt"]}, separators=(",", ":")) + sep + text
    return attr


def cut_block(attr: dict) -> dict:
    """*attr* with its comment cut inside the block's JSON (a block that does not parse)."""
    attr = copy.deepcopy(attr)
    attr["comment"] = attr["comment"][:30]
    return attr


# ---------------------------------------------------------------- the statements merge_* send
def _recording_client():
    """A real Neo4jClient whose driver records every statement (no database)."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = MagicMock()
    client._uri = "bolt://localhost:7687"
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


_NODE_MERGE = re.compile(r"MERGE \(n:(Malware|ThreatActor|Tool|Technique|Tactic) \{(\w+): \$\w+\}\)")


def _node_merges(session) -> list:
    """(label, key value, statement, parameters) of every node MERGE sent so far."""
    out = []
    for call in session.run.call_args_list:
        match = _NODE_MERGE.search(call.args[0]) if call.args else None
        if match:
            out.append((match.group(1), call.kwargs[match.group(2)], call.args[0], call.kwargs))
    return out


def _apply(node: dict, query: str, params: dict) -> None:
    """What the statement does to ``description`` and ``description_source`` on *node*: the ranked SET
    (``apply_statement``); any other assignment of either fails the test."""
    apply_statement(node, query, params, ENTITY_DESCRIPTIONS)


def _ranked(query: str, params: dict):
    """The ranked description a statement carries: (text, source, rank), or None without one."""
    if ENTITY_DESCRIPTIONS.set_cypher("n", "n", *SINGLE_PARAMS) not in query:
        return None
    return params["ranked_description"], params["ranked_description_source"], params["ranked_description_rank"]


_MERGE = {
    "malware": "merge_malware",
    "actor": "merge_actor",
    "tool": "merge_tool",
    "technique": "merge_technique",
    "tactic": "merge_tactic",
}


def merged(*records: tuple, stored: dict | None = None) -> dict:
    """The node after ``merge_*`` of each ``(kind, item, source_id)`` record in order, all of one entity."""
    client, session = _recording_client()
    node: dict = dict(stored or {})
    keys = set()
    for kind, item, source_id in records:
        assert getattr(client, _MERGE[kind])(item, source_id=source_id)
        label, key, query, params = _node_merges(session)[-1]
        keys.add((label, key))
        _apply(node, query, params)
    assert len(keys) == 1, f"the records name different nodes: {keys}"
    return node


def description_of(node: dict):
    return node.get("description")


# ================================================================ the OTX collector
class TestOtxCollector:
    def test_family_and_adversary_items_carry_no_description(self):
        # Until 2026-10 both carried the pulse's description (``pulse_description[:1000]``).
        items = otx_items(KATARU_PULSE, REPORT_PULSE)
        entities = [i for i in items if i.get("type") in ("malware", "actor")]
        assert sorted((i["type"], i["name"]) for i in entities) == [
            ("actor", "Dragonfly"),
            ("malware", "Cobalt Strike"),
            ("malware", "KATARU"),
        ]
        for item in entities:
            assert "description" not in item, item["name"]
            assert item["pulse_id"] in (KATARU_PULSE["id"], REPORT_PULSE["id"]), "the pulse stays its provenance"
        for item in items:  # the pulses' descriptions are stored on no item
            assert not {KATARU_TEXT, REPORT_TEXT} & {v for v in item.values() if isinstance(v, str)}, item

    def test_the_pulse_text_still_decides_every_items_zone(self):
        # Sector detection scans the whole pulse, its description included: the same pulse with a
        # healthcare description puts the family and the IOC there, though neither carries the text.
        plain = otx_items(KATARU_PULSE)
        hospital = otx_items(dict(KATARU_PULSE, description="Attack on hospital networks and patient records"))
        assert {tuple(i["zone"]) for i in plain} == {("global",)}
        assert {tuple(i["zone"]) for i in hospital} == {("healthcare",)}
        assert {i.get("type", "indicator") for i in hospital} == {"indicator", "malware"}
        assert all("description" not in i for i in hospital if i.get("type") == "malware")

    def test_an_indicator_keeps_its_own_description(self):
        ioc = next(i for i in otx_items(REPORT_PULSE) if i.get("value") == "update-check.example.org")
        assert ioc["description"] == "C2 domain"
        assert ioc["pulse_name"] == REPORT_PULSE["name"]

    @pytest.mark.parametrize(
        ("kind", "name"), [("malware", "KATARU"), ("malware", "Cobalt Strike"), ("actor", "Dragonfly")]
    )
    def test_their_misp_comment_is_the_block_alone(self, kind, name):
        attr = written(kind, otx_item(kind, name, KATARU_PULSE, REPORT_PULSE))
        assert _METADATA_COMMENT_RE.match(attr["comment"]) and "\n" not in attr["comment"]
        assert json.loads(attr["comment"].split(":", 1)[1])["pid"] in (KATARU_PULSE["id"], REPORT_PULSE["id"])


# ================================================================ the sync never stores a block, a placeholder or a report's text
class TestSyncedDescription:
    @pytest.mark.parametrize("kind", ["actor", "malware", "tool", "technique"])
    def test_a_mitre_attribute_gives_attacks_text(self, kind):
        attr = written(kind, mitre_items()[kind])
        item = synced(attr)
        assert item["tag"] == "mitre_attck"
        assert item["description"] == text_after_block(attr)
        # ATT&CK's text, cut by MISPWriter (groups and techniques at 255 characters, software at 400)
        assert len(item["description"]) > 200 and item["description"].removesuffix("...") in ATTACK_TEXT[kind]

    def test_a_mitre_tactic_gives_attacks_text(self):
        # The MITRE collector read the tactic's description for zoning only; MISP held the placeholder.
        tactic = mitre_items()["tactic"]
        assert tactic["description"] == EXECUTION_TEXT
        attr = written("tactic", tactic)
        assert attr["comment"] == EXECUTION_TEXT
        assert synced(attr)["description"] == EXECUTION_TEXT

    @pytest.mark.parametrize("pulse_text", ["real", "none"])
    def test_an_otx_family_whose_comment_is_the_block_alone_gives_none(self, pulse_text):
        # Since 2026-10 every OTX family's comment is the block alone, whatever the pulse's text; before,
        # a family from a pulse without a description had that comment, and ``tail or description``
        # stored 'MITRE_USES_TECHNIQUES:{"rt":[...],"pid":"..."}' as the description.
        pulse = KATARU_PULSE if pulse_text == "real" else dict(KATARU_PULSE, description="")
        attr = written("malware", otx_item("malware", "KATARU", pulse))
        assert "\n" not in attr["comment"]
        item = synced(attr, "alienvault_otx")
        assert item["description"] == ""
        assert item["reported_techniques"] == KATARU_IDS
        assert item["pulse_id"] == KATARU_PULSE["id"]

    @pytest.mark.parametrize("name", ["KATARU", "JeetBot"])
    def test_a_real_otx_attribute_with_the_pulse_text_gives_none(self, name):
        # Copied verbatim from the hosted MISP of 2026-10-09; before 2026-10 the sync stored the pulse's
        # text after the block as the node's description.
        attr = as_misp_returns(REAL_OTX[name])
        block_ids = json.loads(attr["comment"].partition("\n")[0].split(":", 1)[1])["t"]
        assert text_after_block(attr) and len(block_ids) in (13, 16)
        item = synced(attr, "alienvault_otx")
        assert item["tag"] == "alienvault_otx" and item["name"].lower() == name.lower()
        assert item["description"] == ""
        # The block is still read: MISPWriter wrote the pulse's ids under ``t`` before 2026-10-10.
        assert item["uses_techniques"] == block_ids

    def test_the_text_of_a_real_otx_attribute_would_be_taken_from_another_source(self):
        # What keeps the pulse's text off the node is the attribute's source, not its form.
        comment = REAL_OTX["KATARU"]["comment"]
        assert _entity_comment_description(comment, "alienvault_otx") is None
        assert _entity_comment_description(comment, "misp") == KATARU_TEXT

    @pytest.mark.parametrize(("kind", "name"), [("malware", "Cobalt Strike"), ("actor", "Dragonfly")])
    def test_an_otx_attribute_written_before_2026_10_gives_none(self, kind, name):
        # MISP keeps them: the comment is the block, then the pulse's description.
        attr = written(kind, otx_item_before_2026_10(kind, name))
        assert text_after_block(attr) == REPORT_TEXT
        item = synced(attr, "alienvault_otx")
        assert item["description"] == ""
        assert item["reported_techniques"] == ["T1566.001", "T1059.001"], "the block is still read"

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool", "technique"])
    def test_a_block_that_does_not_parse_gives_none(self, kind):
        # Before 2026-10 each branch stored the raw comment ("MITRE_USES_TECHNIQUES:{\"t\":[\"T10...").
        attr = cut_block(written(kind, mitre_items()[kind]))
        item = synced(attr)
        assert item["description"] == ""
        assert item.get("uses_techniques", []) == [] and item.get("tactic_phases", []) == []

    @pytest.mark.parametrize(
        ("kind", "item", "comment"),
        [
            ("malware", {"name": "Cobalt Strike", "tag": "threatfox"}, "Malware from threatfox"),
            ("actor", {"name": "Dragonfly", "tag": "mitre_attck"}, "Threat actor from mitre_attck"),
            ("tool", {"mitre_id": "S0002", "name": "Mimikatz", "tag": "mitre_attck"}, "MITRE ATT&CK tool: Mimikatz"),
            (
                "technique",
                {"mitre_id": "T1059.001", "name": "PowerShell", "tag": "mitre_attck"},
                "MITRE ATT&CK technique from mitre_attck",
            ),
            (
                "tactic",
                {"mitre_id": "TA0002", "name": "Execution", "shortname": "execution", "tag": "mitre_attck"},
                "MITRE ATT&CK tactic",
            ),
        ],
        ids=["malware", "actor", "tool", "technique", "tactic"],
    )
    def test_misp_writers_placeholder_gives_none(self, kind, item, comment):
        attr = written(kind, dict(item, zone=["global"]))
        assert attr["comment"] == comment, "MISPWriter's comment for an item without text"
        assert synced(attr)["description"] == ""

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool"])
    def test_a_block_after_other_text_gives_none(self, kind):
        attr = written(kind, mitre_items()[kind])
        attr["comment"] = "Profile\n" + attr["comment"]
        assert synced(attr)["description"] == ""

    def test_the_helper_keeps_plain_text_and_drops_the_rest(self):
        assert _entity_comment_description("An actor profile", "misp") == "An actor profile"
        assert _entity_comment_description("An actor profile", "alienvault_otx") is None
        assert _entity_comment_description('MITRE_USES_TECHNIQUES:{"t":["T1059"]}\nText', "mitre_attck") == "Text"
        assert _entity_comment_description('Text MITRE_USES_TECHNIQUES:{"t":["T1059"]}', "mitre_attck") is None
        assert _entity_comment_description("Malware from MISP galaxy: misp-galaxy:x", "misp") == (
            "Malware from MISP galaxy: misp-galaxy:x"
        ), "only MISPWriter's exact placeholder is one"
        assert _entity_comment_description(None, "mitre_attck") is None

    @pytest.mark.parametrize(
        "text", ["Threat actor from Iran", "Malware from China", "Malware from APT28", "MITRE ATT&CK technique from T"]
    )
    def test_a_partners_short_text_is_no_placeholder(self, text):
        # MISPWriter's placeholder names the item's tag, a lowercase source id; a MISP-native or partner
        # text with another word after "from" is a description.
        assert _entity_comment_description(text, "misp") == text
        assert (
            synced(dict(written("actor", {"name": "Charming Kitten", "tag": "misp"}), comment=text), "misp")[
                "description"
            ]
            == text
        )

    @pytest.mark.parametrize("source", ["alienvault_otx", "mitre_attck", "threatfox", "unknown", "cisa_ics"])
    def test_every_source_ids_placeholder_is_one(self, source):
        for kind, name in (("malware", "Cobalt Strike"), ("actor", "Dragonfly")):
            attr = written(kind, {"name": name, "tag": source, "zone": ["global"]})
            assert attr["comment"].endswith(f" from {source}")
            assert _entity_comment_description(attr["comment"], "misp") is None

    def test_no_branch_gives_a_metadata_block(self):
        items = mitre_items()
        attrs = [(written(kind, items[kind]), "mitre_attck") for kind in _BUILDERS]
        attrs += [(cut_block(attr), source) for attr, source in attrs if _METADATA_COMMENT_RE.match(attr["comment"])]
        attrs += [
            (written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx"),
            (written("actor", otx_item_before_2026_10("actor", "Dragonfly")), "alienvault_otx"),
        ]
        attrs += [(as_misp_returns(captured), "alienvault_otx") for captured in REAL_OTX.values()]
        assert len(attrs) == 13
        for attr, source in attrs:
            description = synced(attr, source)["description"]
            assert "MITRE_USES_TECHNIQUES" not in description and "MITRE_TACTIC_PHASES" not in description, description
            assert not _METADATA_COMMENT_RE.match(description)


class TestWhereMispWriterWritesTheText:
    """Where MISPWriter puts ATT&CK's text and how much of it (docs/COLLECTORS.md, MITRE "Descriptions")."""

    @pytest.mark.parametrize(
        ("kind", "cut"), [("actor", 255), ("technique", 255), ("tactic", 255), ("malware", 400), ("tool", 400)]
    )
    def test_the_cut_length_of_each_kind(self, kind, cut):
        long_text = "Lorem ipsum dolor sit amet. " * 18  # 504 characters, over the MITRE collector's 500
        attr = written(kind, dict(mitre_items()[kind], description=long_text[:500]))
        text = synced(attr)["description"]
        assert len(text) == cut and text.endswith("...") and long_text.startswith(text[:-3])

    @pytest.mark.parametrize(
        ("kind", "without"),
        [("tactic", ()), ("technique", ("tactic_phases",)), ("tool", ("uses_techniques",))],
    )
    def test_without_a_block_the_text_is_the_whole_comment(self, kind, without):
        item = {k: v for k, v in mitre_items()[kind].items() if k not in without}
        comment = written(kind, item)["comment"]
        assert not _METADATA_COMMENT_RE.match(comment) and "\n" not in comment
        assert len(comment) > 40 and ATTACK_TEXT[kind].startswith(comment.removesuffix("..."))
        assert synced(written(kind, item))["description"] == comment


# ================================================================ merge_*: the source ranking decides
class TestMergeStatements:
    @pytest.mark.parametrize("kind", ["malware", "actor", "tool", "technique", "tactic"])
    def test_mitre_record_carries_its_text_at_the_top_rank(self, kind):
        client, session = _recording_client()
        item = synced(written(kind, mitre_items()[kind]))
        assert getattr(client, _MERGE[kind])(item, source_id="mitre_attck")
        _label, _key, query, params = _node_merges(session)[-1]
        assert item["description"], "MISP holds ATT&CK's text (cut to the writer's length)"
        assert _ranked(query, params) == (item["description"], "mitre_attck", ENTITY_DESCRIPTIONS.top_rank)
        _apply({}, query, params)  # no other assignment of the description

    @pytest.mark.parametrize("source_id", ["alienvault_otx", "stix_import", "misp", "coreideas"])
    @pytest.mark.parametrize("kind", ["malware", "actor", "tool", "technique", "tactic"])
    def test_another_record_carries_its_source_and_rank(self, kind, source_id):
        client, session = _recording_client()
        item = dict(mitre_items()[kind], description="Text from another record")
        assert getattr(client, _MERGE[kind])(item, source_id=source_id)
        _label, _key, query, params = _node_merges(session)[-1]
        rank = ENTITY_DESCRIPTIONS.rank(source_id)
        assert rank < ENTITY_DESCRIPTIONS.top_rank
        assert _ranked(query, params) == ("Text from another record", source_id, rank)

    @pytest.mark.parametrize("kind", ["malware", "actor", "tool", "technique", "tactic"])
    @pytest.mark.parametrize("source_id", ["mitre_attck", "alienvault_otx"])
    def test_a_record_without_text_writes_none(self, kind, source_id):
        client, session = _recording_client()
        assert getattr(client, _MERGE[kind])(dict(mitre_items()[kind], description=""), source_id=source_id)
        _label, _key, query, params = _node_merges(session)[-1]
        assert _ranked(query, params) is None
        assert not re.search(r"n\.description(_source)? = ", query)


class TestMergeOrder:
    """One entity's records in both orders: the text an OTX record carried until 2026-10 (the pulse's)
    against MITRE's, and records of sources ranked below MITRE."""

    @pytest.mark.parametrize(("kind", "otx_name"), [("malware", "Cobalt Strike"), ("actor", "Dragonfly")])
    @pytest.mark.parametrize("first", ["mitre", "otx"])
    def test_mitre_text_wins_in_both_orders(self, kind, otx_name, first):
        mitre = (kind, synced(written(kind, mitre_items()[kind])), "mitre_attck")
        otx = (kind, otx_item_before_2026_10(kind, otx_name), "alienvault_otx")
        node = merged(*((mitre, otx) if first == "mitre" else (otx, mitre)))
        assert node == {"description": mitre[1]["description"], "description_source": "mitre_attck"}

    @pytest.mark.parametrize("kind", ["technique", "tactic"])
    @pytest.mark.parametrize("first", ["mitre", "misp"])
    def test_a_technique_or_tactic_keeps_attacks_text_in_both_orders(self, kind, first):
        # Until 2026-10-16 any record set a Technique's or Tactic's description: the one merged last won.
        mitre = (kind, synced(written(kind, mitre_items()[kind])), "mitre_attck")
        other = (kind, dict(mitre_items()[kind], description="A MISP-native attribute's text"), "misp")
        node = merged(*((mitre, other) if first == "mitre" else (other, mitre)))
        assert node == {"description": mitre[1]["description"], "description_source": "mitre_attck"}

    @pytest.mark.parametrize("first", ["stix_import", "misp"])
    def test_without_mitre_a_registered_source_wins_over_an_unregistered_one(self, first):
        # Until 2026-10-16 the first of the two to arrive kept its text.
        bundle = ("malware", dict(mitre_items()["malware"], description="An external bundle's text"), "stix_import")
        native = ("malware", dict(mitre_items()["malware"], description="A MISP-native attribute's text"), "misp")
        node = merged(*((bundle, native) if first == "stix_import" else (native, bundle)))
        assert node == {"description": "A MISP-native attribute's text", "description_source": "misp"}

    @pytest.mark.parametrize("first", ["coreideas", "misp"])
    def test_without_mitre_a_curated_source_wins_over_another(self, first):
        curated = ("actor", dict(mitre_items()["actor"], description="Core Ideas profile"), "coreideas")
        native = ("actor", dict(mitre_items()["actor"], description="A MISP-native attribute's text"), "misp")
        node = merged(*((curated, native) if first == "coreideas" else (native, curated)))
        assert node == {"description": "Core Ideas profile", "description_source": "coreideas"}

    def test_an_empty_stored_description_counts_as_absent(self):
        record = ("actor", dict(mitre_items()["actor"], description="Partner text"), "stix_import")
        node = merged(record, stored={"description": ""})
        assert node == {"description": "Partner text", "description_source": "stix_import"}

    def test_a_revised_mitre_text_replaces_the_earlier_one(self):
        old = ("tool", dict(mitre_items()["tool"], description="ATT&CK v17 text"), "mitre_attck")
        new = ("tool", dict(mitre_items()["tool"], description="ATT&CK v18 text"), "mitre_attck")
        assert description_of(merged(old, new)) == "ATT&CK v18 text"

    def test_a_description_written_before_is_replaced_by_mitre_only(self):
        # A node of a graph built before 2026-10-16: a description, no description_source.
        legacy = {"description": "Text a record wrote before the ranking"}
        native = ("malware", dict(mitre_items()["malware"], description="A MISP-native attribute's text"), "misp")
        curated = ("malware", dict(mitre_items()["malware"], description="Core Ideas profile"), "coreideas")
        assert merged(native, curated, stored=legacy) == legacy
        mitre = ("malware", synced(written("malware", mitre_items()["malware"])), "mitre_attck")
        node = merged(native, mitre, curated, stored=legacy)
        assert node == {"description": mitre[1]["description"], "description_source": "mitre_attck"}


class TestSyncEndToEnd:
    """MISP attributes of the two sources read and merged by the sync, in both event orders."""

    @staticmethod
    def _node_after_sync(*attrs: tuple) -> dict:
        client, session = _recording_client()
        syncer = MISPToNeo4jSync(neo4j_client=client)
        items = [synced(attr, source) for attr, source in attrs]
        assert syncer.sync_to_neo4j(items)[:2] == (len(items), 0)
        node: dict = {}
        merges = _node_merges(session)
        assert len({(label, key) for label, key, _q, _p in merges}) == 1
        for _label, _key, query, params in merges:
            _apply(node, query, params)
        return node

    @pytest.mark.parametrize(("kind", "otx_name"), [("malware", "Cobalt Strike"), ("actor", "Dragonfly")])
    @pytest.mark.parametrize("first", ["mitre", "otx"])
    @pytest.mark.parametrize("form", ["since_2026_10_10", "before_2026_10_10"])
    def test_attacks_text_whatever_the_order(self, kind, otx_name, first, form):
        # MISP holds OTX attributes with the pulse's text in both block forms (module docstring).
        mitre = (written(kind, mitre_items()[kind]), "mitre_attck")
        otx_attr = written(kind, otx_item_before_2026_10(kind, otx_name))
        if form == "before_2026_10_10":
            otx_attr = in_form_before_2026_10_10(otx_attr)
        assert text_after_block(otx_attr) == REPORT_TEXT
        otx = (otx_attr, "alienvault_otx")
        node = self._node_after_sync(*((mitre, otx) if first == "mitre" else (otx, mitre)))
        assert description_of(node) == text_after_block(mitre[0])

    def test_an_otx_only_family_shows_nothing(self):
        node = self._node_after_sync(
            (written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx")
        )
        assert description_of(node) is None

    @pytest.mark.parametrize("name", ["KATARU", "JeetBot"])
    def test_a_real_otx_attribute_leaves_the_node_without_text(self, name):
        node = self._node_after_sync((as_misp_returns(REAL_OTX[name]), "alienvault_otx"))
        assert description_of(node) is None


# ================================================================ the STIX flow
class TestStixObjects:
    @pytest.mark.parametrize(
        ("kind", "stix_type"),
        [
            ("actor", "threat-actor"),
            ("malware", "malware"),
            ("tool", "tool"),
            ("technique", "attack-pattern"),
            ("tactic", "x-mitre-tactic"),
        ],
    )
    def test_a_mitre_object_carries_the_synced_description(self, kind, stix_type):
        attr = written(kind, mitre_items()[kind])
        obj = stix(attr)
        assert obj["type"] == stix_type
        assert obj["description"] == synced(attr)["description"] != ""

    @pytest.mark.parametrize(("name", "stix_type"), [("KATARU", "malware"), ("JeetBot", "threat-actor")])
    def test_a_real_otx_attribute_gives_an_object_without_description(self, name, stix_type):
        # Before 2026-10 the object carried the attribute's whole comment, block and pulse text.
        obj = stix(as_misp_returns(REAL_OTX[name]))
        assert obj["type"] == stix_type and obj["name"] == name
        assert "description" not in obj

    @pytest.mark.parametrize(
        "case",
        ["otx_block_only", "otx_before_2026_10", "cut_block", "tactic_placeholder", "tool_placeholder"],
    )
    def test_an_object_carries_no_block_placeholder_or_report_text(self, case):
        # Before 2026-10 every one of these objects carried the raw comment as its description.
        attr = {
            "otx_block_only": lambda: written("malware", otx_item("malware", "KATARU", KATARU_PULSE)),
            "otx_before_2026_10": lambda: written("actor", otx_item_before_2026_10("actor", "Dragonfly")),
            "cut_block": lambda: cut_block(written("malware", mitre_items()["malware"])),
            "tactic_placeholder": lambda: written(
                "tactic", {"mitre_id": "TA0002", "name": "Execution", "shortname": "execution", "tag": "mitre_attck"}
            ),
            "tool_placeholder": lambda: written(
                "tool", {"mitre_id": "S0002", "name": "Mimikatz", "tag": "mitre_attck"}
            ),
        }[case]()
        assert "description" not in stix(attr)


class TestStixImport:
    """``run_pipeline.load_stix21_to_neo4j`` (MISP → STIX → Neo4j, ``--stix-flow``): an object carries the
    source of its event (``x_edgeguard_source``), and the source ranking decides as in the attribute flow."""

    @staticmethod
    def _import(obj: dict, source: str):
        from run_pipeline import EdgeGuardPipeline

        client, session = _recording_client()
        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = client
        obj = dict(obj, x_edgeguard_source=source)  # as the STIX flow stamps the objects of an event
        pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [obj]})
        return _node_merges(session)[-1]

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool", "technique", "tactic"])
    def test_a_mitre_object_carries_the_attribute_flows_text_at_the_top_rank(self, kind):
        attr = written(kind, mitre_items()[kind])
        _label, _key, query, params = self._import(stix(attr), "mitre_attck")
        assert _ranked(query, params) == (synced(attr)["description"], "mitre_attck", ENTITY_DESCRIPTIONS.top_rank)

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool"])
    def test_another_object_carries_its_source_and_rank(self, kind):
        obj = dict(stix(written(kind, mitre_items()[kind])), description="An external bundle's text")
        _label, _key, query, params = self._import(obj, "stix_import")
        assert _ranked(query, params) == ("An external bundle's text", "stix_import", 0)

    def test_an_otx_object_writes_no_description(self):
        attr = written("actor", otx_item_before_2026_10("actor", "Dragonfly"))
        _label, _key, query, params = self._import(stix(attr), "alienvault_otx")
        assert _ranked(query, params) is None
        assert not re.search(r"n\.description(_source)? = ", query)


# ================================================================ the RUNBOOK repair (docs/RUNBOOK.md)
RUNBOOK_SECTION = "### Repairing Malware, ThreatActor and Tool descriptions"


def runbook_statements() -> list:
    """The Cypher of the RUNBOOK repair section, block by block: steps 1, 2, 3, 4 and the check."""
    doc = (TESTS.parent / "docs" / "RUNBOOK.md").read_text()
    section = re.split(r"\n#{2,3} ", doc.split(RUNBOOK_SECTION + "\n", 1)[1], maxsplit=1)[0]
    return [block.strip().rstrip(";") for block in re.findall(r"```cypher\n(.*?)```", section, re.S)]


def _cypher_patterns(statement: str) -> list:
    """The patterns of the ``=~`` comparisons in *statement*, as Neo4j reads the string literals."""
    return [literal.replace("\\\\", "\\") for literal in re.findall(r"=~ '((?:[^'\\]|\\.)*)'", statement)]


def _runbook_removes(text: str) -> bool:
    """Whether steps 1-2 match *text* on a node EdgeGuard created or wrote to (``=~`` is a full match)."""
    return any(re.fullmatch(p, text) for p in _cypher_patterns(runbook_statements()[1]))


class TestRunbookCleanup:
    def test_step_2_removes_what_step_1_counts(self):
        count, remove = runbook_statements()[:2]
        assert count.split("RETURN")[0] == remove.split("REMOVE")[0]
        assert len(_cypher_patterns(remove)) == 3

    def test_a_placeholder_is_removed_only_from_edgeguards_nodes(self):
        remove = runbook_statements()[1]
        guard, _, placeholder = remove.partition("(n.edgeguard_managed = true OR n.edgeguard_enriched = true)")
        assert placeholder.lstrip().startswith("AND n.description =~ '\\\\s*((Malware|Threat actor|")
        assert "Threat actor" not in guard

    @pytest.mark.parametrize(
        ("text", "removed"),
        [
            ('MITRE_USES_TECHNIQUES:{"rt":["T1082"],"pid":"68c30a2bd84d2a2fe1fc3f4b"}', True),
            ('MITRE_USES_TECHNIQUES:{"t":["T10', True),  # a block cut inside its JSON
            ('Profile\nMITRE_USES_TECHNIQUES:{"t":["T1059"]}', True),
            ("Malware from alienvault_otx", True),
            ("Threat actor from mitre_attck", True),
            ("MITRE ATT&CK technique from mitre_attck", True),
            ("MITRE ATT&CK tactic", True),
            ("MITRE ATT&CK tool: Mimikatz", True),
            ("Threat actor from Iran", False),
            ("Malware from APT28", False),
            (DRAGONFLY_TEXT, False),
            (KATARU_TEXT, False),  # an OTX pulse's text: step 4, on nodes MITRE does not describe
        ],
    )
    def test_what_steps_1_and_2_remove(self, text, removed):
        assert _runbook_removes(text) is removed

    @pytest.mark.parametrize(
        "text",
        [
            "Malware from threatfox",
            "Threat actor from unknown",
            "MITRE ATT&CK tactic",
            "MITRE ATT&CK tool: Cobalt Strike",
            "Threat actor from Iran",
            "Malware from China",
            "An actor profile",
        ],
    )
    def test_the_placeholders_are_the_ones_the_sync_drops(self, text):
        assert _runbook_removes(text) is (_entity_comment_description(text, "misp") is None)


# ================================================================ PyMISP's own STIX conversion
class TestPymispStixPath:
    """``convert_to_stix21`` prefers PyMISP's ``MISPEvent.to_stix2`` when the installed PyMISP has it
    (the pinned ``pymisp~=2.4`` allows such a version); its objects copy the attribute comment, so
    they follow the same description rule as the manual conversion."""

    def _convert(self, monkeypatch, objects, info):
        import pymisp

        class _Event:
            def load(self, _event):
                pass

            def to_stix2(self):
                return [dict(o) for o in objects]

        monkeypatch.setattr(pymisp, "MISPEvent", _Event)
        syncer = run_misp_to_neo4j.MISPToNeo4jSync.__new__(run_misp_to_neo4j.MISPToNeo4jSync)
        return syncer.convert_to_stix21({"info": info, "Tag": [], "Attribute": []})["objects"]

    def test_entity_objects_follow_the_description_rule(self, monkeypatch):
        objects = [
            {
                "type": "malware",
                "id": "malware--1",
                "name": "kazuar",
                "description": 'MITRE_USES_TECHNIQUES:{"rt":["T1082"]}',
            },
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "turla",
                "description": "Threat actor from mitre_attck",
            },
            {"type": "tool", "id": "tool--1", "name": "mimikatz", "description": "Mimikatz is a credential dumper."},
            {"type": "indicator", "id": "indicator--1", "description": 'OTX_META:{"pulse_id":"p1"}', "pattern": "[x]"},
        ]
        out = {o["id"]: o for o in self._convert(monkeypatch, objects, "EdgeGuard-mitre_attck-2026-10-15")}
        assert "description" not in out["malware--1"], "a metadata block is no description"
        assert "description" not in out["intrusion-set--1"], "MISPWriter's placeholder is no description"
        assert out["tool--1"]["description"] == "Mimikatz is a credential dumper."
        assert out["indicator--1"]["description"] == 'OTX_META:{"pulse_id":"p1"}', "only entity objects"

    def test_an_otx_events_entity_text_is_dropped(self, monkeypatch):
        objects = [
            {"type": "malware", "id": "malware--2", "name": "kataru", "description": "A pulse about a campaign."}
        ]
        out = self._convert(monkeypatch, objects, "EdgeGuard-alienvault_otx-2026-10-09")
        assert "description" not in out[0], "an OTX pulse's text describes the report"

    def test_the_event_source(self):
        assert run_misp_to_neo4j._event_source_id("EdgeGuard-alienvault_otx-2026-10-09") == "alienvault_otx"
        assert run_misp_to_neo4j._event_source_id("Some analyst event") == ""
