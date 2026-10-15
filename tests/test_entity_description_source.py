"""A Malware, ThreatActor or Tool description comes from MITRE ATT&CK (2026-10).

``merge_malware``, ``merge_actor`` and ``merge_tool`` set the description from whatever record was merged
last. The OTX collector gave every malware family and adversary of a pulse the pulse's description, so
ATT&CK's description of Cobalt Strike or Dragonfly was replaced by a report's text whenever an OTX record
was merged after MITRE's. The sync's malware branch stored a comment that was only a
``MITRE_USES_TECHNIQUES`` block (an OTX family from a pulse without a description) as the description
(``tail or description``), every branch that reads a block stored the raw comment when the block did not
parse, and the STIX objects of the opt-in STIX flow carried the raw comment.

The rule now: MITRE's record (``mitre_attck``) sets the description; any other record fills it only where
the node has none (``neo4j_client._entity_description_fill``). The OTX collector gives family and adversary
items no description; the sync takes none from an OTX malware or actor attribute (MISP keeps the ones
written before 2026-10, with the pulse's text after the block), none from a metadata block, a block that
does not parse, a block after other text, or MISPWriter's placeholder for an item without text
(``run_misp_to_neo4j._entity_comment_description``). The STIX objects follow the same rule, and the MITRE
collector now gives tactics ATT&CK's description (the sync stored the placeholder "MITRE ATT&CK tactic").

Fixtures: ATT&CK STIX objects in the shape of the ``mitre/cti`` bundle (the helpers of
``test_attack_revoked_objects.py``) with ATT&CK's ids, names and descriptions of Dragonfly (G0035),
Cobalt Strike (S0154), Mimikatz (S0002), PowerShell (T1059.001) and Execution (TA0002); Dragonfly's
aliases as its attribute on the hosted MISP carried them on 2026-10-09. OTX pulses in the shape the OTX
API returns, the first with the name, reference, ATT&CK ids and tags of the KATARU pulse on the hosted
MISP of 2026-10-09 and no description. Both go through the collectors' own code
(``MITRECollector._parse_bundle``, ``OTXCollector.collect``), MISPWriter's attribute builders and the
sync's ``parse_attribute``, as a baseline writes and reads them. The same rule on a real Neo4j:
``tests/test_entity_description_neo4j.py``.
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

import neo4j_client  # noqa: E402
from collectors import misp_writer  # noqa: E402
from collectors import otx_collector as oc  # noqa: E402
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


# ---------------------------------------------------------------- OTX pulses (OTX API shape)
KATARU_PULSE = {
    "id": "68c30a2bd84d2a2fe1fc3f4b",
    # Name, reference, ATT&CK ids and tags of the KATARU pulse on the hosted MISP, 2026-10-09.
    "name": "KATARU: IoT Malware Adopts Public LPE Exploits",
    "description": "",
    "created": "2026-09-11T17:55:39",
    "modified": "2026-09-14T10:32:06.888000",
    "TLP": "white",
    "adversary": "",
    "author_name": "AlienVault",
    "attack_ids": [{"id": "T1110.001"}, {"id": "T1498.001"}, {"id": "T1053.003"}, {"id": "T1082"}],
    "tags": ["telnet brute-force", "kataru", "iot botnet", "ddos"],
    "references": ["https://www.nozominetworks.com/blog/kataru-iot-malware-adopts-public-lpe-exploits"],
    "industries": [],
    "malware_families": ["KATARU"],
    "indicators": [{"type": "IPv4", "indicator": "160.191.242.92", "description": ""}],
}
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


_NODE_MERGE = re.compile(r"MERGE \(n:(Malware|ThreatActor|Tool) \{(\w+): \$\w+\}\)")
_SET = re.compile(r"n\.description = \$(\w+)")
_FILL = re.compile(
    r"n\.description = CASE WHEN n\.description IS NULL OR n\.description = '' THEN \$(\w+) ELSE n\.description END"
)


def _node_merges(session) -> list:
    """(label, key value, statement, parameters) of every node MERGE sent so far."""
    out = []
    for call in session.run.call_args_list:
        match = _NODE_MERGE.search(call.args[0]) if call.args else None
        if match:
            out.append((match.group(1), call.kwargs[match.group(2)], call.args[0], call.kwargs))
    return out


def _apply(node: dict, query: str, params: dict) -> None:
    """What the statement does to ``description`` on *node*: a plain SET replaces, the set-if-absent
    CASE fills an absent or empty value. Any other assignment of ``n.description`` fails the test."""
    assigned = re.findall(r"n\.description = (?!'')", query)  # not the IS-empty test
    plain, fill = _SET.findall(query), _FILL.findall(query)
    assert len(assigned) == len(plain) + len(fill) <= 1, query
    for param in plain:
        node["description"] = params[param]
    for param in fill:
        if node.get("description") in (None, ""):
            node["description"] = params[param]


_MERGE = {"malware": "merge_malware", "actor": "merge_actor", "tool": "merge_tool"}


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

    def test_an_otx_family_from_a_pulse_without_text_gives_none(self):
        # Before 2026-10: ``tail or description`` stored 'MITRE_USES_TECHNIQUES:{"rt":[...],"pid":"..."}'.
        attr = written("malware", otx_item("malware", "KATARU", KATARU_PULSE))
        item = synced(attr, "alienvault_otx")
        assert item["description"] == ""
        assert item["reported_techniques"] == ["T1110.001", "T1498.001", "T1053.003", "T1082"]
        assert item["pulse_id"] == KATARU_PULSE["id"]

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

    def test_no_branch_gives_a_metadata_block(self):
        items = mitre_items()
        attrs = [(written(kind, items[kind]), "mitre_attck") for kind in _BUILDERS]
        attrs += [(cut_block(attr), source) for attr, source in attrs if _METADATA_COMMENT_RE.match(attr["comment"])]
        attrs += [
            (written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx"),
            (written("actor", otx_item_before_2026_10("actor", "Dragonfly")), "alienvault_otx"),
        ]
        assert len(attrs) == 11
        for attr, source in attrs:
            description = synced(attr, source)["description"]
            assert "MITRE_USES_TECHNIQUES" not in description and "MITRE_TACTIC_PHASES" not in description, description
            assert not _METADATA_COMMENT_RE.match(description)


# ================================================================ merge_*: MITRE sets, any other record fills
class TestMergeStatements:
    @pytest.mark.parametrize("kind", ["malware", "actor", "tool"])
    def test_mitre_record_sets_the_description(self, kind):
        client, session = _recording_client()
        item = synced(written(kind, mitre_items()[kind]))
        assert getattr(client, _MERGE[kind])(item, source_id="mitre_attck")
        _label, _key, query, params = _node_merges(session)[-1]
        assert "n.description = $description" in query and params["description"] == item["description"]
        assert "$fill_description" not in query

    @pytest.mark.parametrize("source_id", ["alienvault_otx", "stix_import", "misp"])
    @pytest.mark.parametrize("kind", ["malware", "actor", "tool"])
    def test_another_record_only_fills_it(self, kind, source_id):
        client, session = _recording_client()
        item = dict(mitre_items()[kind], description="Text from another record")
        assert getattr(client, _MERGE[kind])(item, source_id=source_id)
        _label, _key, query, params = _node_merges(session)[-1]
        assert (
            "n.description = CASE WHEN n.description IS NULL OR n.description = '' "
            "THEN $fill_description ELSE n.description END"
        ) in query
        assert params["fill_description"] == "Text from another record"
        assert "n.description = $description" not in query

    @pytest.mark.parametrize("kind", ["malware", "actor", "tool"])
    @pytest.mark.parametrize("source_id", ["mitre_attck", "alienvault_otx"])
    def test_a_record_without_text_writes_none(self, kind, source_id):
        client, session = _recording_client()
        assert getattr(client, _MERGE[kind])(dict(mitre_items()[kind], description=""), source_id=source_id)
        _label, _key, query, _params = _node_merges(session)[-1]
        assert not re.search(r"n\.description = (?!'')", query)


class TestMergeOrder:
    """One entity's records in both orders: the text an OTX record carried until 2026-10 (the pulse's)
    against MITRE's."""

    @pytest.mark.parametrize(("kind", "otx_name"), [("malware", "Cobalt Strike"), ("actor", "Dragonfly")])
    @pytest.mark.parametrize("first", ["mitre", "otx"])
    def test_mitre_text_wins_in_both_orders(self, kind, otx_name, first):
        mitre = (kind, synced(written(kind, mitre_items()[kind])), "mitre_attck")
        otx = (kind, otx_item_before_2026_10(kind, otx_name), "alienvault_otx")
        node = merged(*((mitre, otx) if first == "mitre" else (otx, mitre)))
        assert description_of(node) == mitre[1]["description"]

    def test_without_mitre_the_first_text_fills_and_stays(self):
        first = ("malware", dict(mitre_items()["malware"], description="First text"), "stix_import")
        second = ("malware", dict(mitre_items()["malware"], description="Second text"), "misp")
        assert description_of(merged(first, second)) == "First text"

    def test_an_empty_stored_description_counts_as_absent(self):
        record = ("actor", dict(mitre_items()["actor"], description="Partner text"), "stix_import")
        assert description_of(merged(record, stored={"description": ""})) == "Partner text"

    def test_a_revised_mitre_text_replaces_the_earlier_one(self):
        old = ("tool", dict(mitre_items()["tool"], description="ATT&CK v17 text"), "mitre_attck")
        new = ("tool", dict(mitre_items()["tool"], description="ATT&CK v18 text"), "mitre_attck")
        assert description_of(merged(old, new)) == "ATT&CK v18 text"


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
    def test_attacks_text_whatever_the_order(self, kind, otx_name, first):
        mitre = (written(kind, mitre_items()[kind]), "mitre_attck")
        otx = (written(kind, otx_item_before_2026_10(kind, otx_name)), "alienvault_otx")
        node = self._node_after_sync(*((mitre, otx) if first == "mitre" else (otx, mitre)))
        assert description_of(node) == text_after_block(mitre[0])

    def test_an_otx_only_family_shows_nothing(self):
        node = self._node_after_sync(
            (written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx")
        )
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
    """``run_pipeline.load_stix21_to_neo4j`` (MISP → STIX → Neo4j, ``--stix-flow``): the objects of a MITRE
    event (``x_edgeguard_source`` ``mitre_attck``) set the description, any other only fills it."""

    @staticmethod
    def _import(obj: dict, source: str):
        from run_pipeline import EdgeGuardPipeline

        client, session = _recording_client()
        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = client
        obj = dict(obj, x_edgeguard_source=source)  # as the STIX flow stamps the objects of an event
        pipeline.load_stix21_to_neo4j({"type": "bundle", "objects": [obj]})
        return _node_merges(session)[-1]

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool"])
    def test_a_mitre_object_sets_the_description(self, kind):
        attr = written(kind, mitre_items()[kind])
        _label, _key, query, params = self._import(stix(attr), "mitre_attck")
        assert "n.description = $description" in query
        assert params["description"] == synced(attr)["description"]

    @pytest.mark.parametrize("kind", ["actor", "malware", "tool"])
    def test_another_object_only_fills_it(self, kind):
        obj = dict(stix(written(kind, mitre_items()[kind])), description="An external bundle's text")
        _label, _key, query, params = self._import(obj, "stix_import")
        assert "n.description = $description" not in query
        assert params["fill_description"] == "An external bundle's text"

    def test_an_otx_object_writes_no_description(self):
        attr = written("actor", otx_item_before_2026_10("actor", "Dragonfly"))
        _label, _key, query, _params = self._import(stix(attr), "alienvault_otx")
        assert not re.search(r"n\.description = (?!'')", query)
