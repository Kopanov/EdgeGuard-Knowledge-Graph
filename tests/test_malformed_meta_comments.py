"""A malformed metadata comment no longer fails a whole MISP event (2026-10).

``parse_attribute`` read ``OTX_META:`` / ``TF_META:`` (indicators) and ``MITRE_USES_TECHNIQUES:``
(malware) with ``json.loads`` and then called ``.get`` on the result. The indicator branch caught
only ``ValueError`` and the malware branch had no ``isinstance(dict)`` check, so a comment such
as ``OTX_META:null``, ``OTX_META:["x"]``, ``OTX_META:1``, ``TF_META:"s"`` or
``MITRE_USES_TECHNIQUES:null`` raised ``AttributeError``. The exception escaped the attribute's
parse: the event failed, the run failed, and every later incremental run failed on the same
event. ``{"t":"T1059"}`` gave ``uses_techniques`` ``['T', '1', '0', '5', '9']``.

Now a value other than a JSON object counts as no metadata (warning with the attribute UUID),
list-valued keys accept only lists, and well-formed comments parse exactly as before. The lists
keep only their strings and numbers (numbers as strings): they become node properties, and Neo4j
refuses a property list holding a map, a list, a null or mixed types, which failed the whole
batch. The STIX conversion reads a tool's comment the same way.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from run_misp_to_neo4j import MISPToNeo4jSync  # noqa: E402

_OTX_EVENT = {"id": 7, "info": "EdgeGuard-alienvault_otx-2026-10-10", "date": "2026-10-10", "Tag": []}
_TF_EVENT = {"id": 8, "info": "EdgeGuard-threatfox-2026-10-15", "date": "2026-10-15", "Tag": []}
_MITRE_EVENT = {"id": 9, "info": "EdgeGuard-mitre_attck-2026-10-15", "date": "2026-10-15", "Tag": []}

UUID = "30000000-0000-4000-8000-00000000beef"


def _syncer() -> MISPToNeo4jSync:
    return MISPToNeo4jSync(neo4j_client=MagicMock())


def _ioc(comment: str, value: str = "203.0.113.7") -> dict:
    return {"type": "ip-dst", "value": value, "uuid": UUID, "comment": comment, "Tag": []}


def _malware(comment: str) -> dict:
    return {"type": "malware-type", "value": "Emotet", "uuid": UUID, "comment": comment, "Tag": []}


@pytest.mark.parametrize(
    "comment, event",
    [
        ("OTX_META:null", _OTX_EVENT),
        ('OTX_META:["x"]', _OTX_EVENT),
        ("OTX_META:1", _OTX_EVENT),
        ('TF_META:"s"', _TF_EVENT),
        ("TF_META:null", _TF_EVENT),
    ],
    ids=["otx-null", "otx-list", "otx-number", "tf-string", "tf-null"],
)
def test_indicator_with_a_non_object_meta_is_kept_without_metadata(comment, event, caplog):
    with caplog.at_level(logging.WARNING):
        item, _rels = _syncer().parse_attribute(_ioc(comment), event)
    assert item is not None and item["value"] == "203.0.113.7", "the indicator itself is kept"
    for key in ("attack_ids", "pulse_id", "malware_family", "ioc_id", "report_ids"):
        assert key not in item, f"{key}: no metadata may be taken from a non-object comment"
    assert any("[META]" in r.message and UUID in r.message for r in caplog.records), "warning names the attribute"


def test_otx_list_valued_keys_accept_only_lists():
    comment = (
        'OTX_META:{"pulse_id":"p1","report_ids":"p2","mf":"Emotet","pa":"Emotet::apt28",'
        '"attack_ids":"T1059","targeted_countries":"DE","pulse_tags":"c2","otx_industries":"Finance"}'
    )
    item, _ = _syncer().parse_attribute(_ioc(comment), _OTX_EVENT)
    assert item["pulse_id"] == "p1", "the scalar keys of the object are still read"
    assert item["attack_ids"] == [] and item["targeted_countries"] == []
    assert item["pulse_tags"] == [] and item["otx_industries"] == []
    assert "report_ids" not in item, "a string is not split into one report id per character"
    assert "pulse_malware_families" not in item and "pulse_malware_actor_pairs" not in item


def test_well_formed_otx_and_tf_comments_parse_as_before():
    otx = (
        'OTX_META:{"attack_ids":["T1059"],"targeted_countries":["DE"],"pulse_tags":["c2"],'
        '"pulse_references":["https://example.org/r"],"pulse_author":"AlienVault","pulse_tlp":"green",'
        '"otx_industries":["Finance"],"description":"d","pulse_name":"pulse p1","malware_family":"Emotet",'
        '"attributed_to":"","pulse_id":"p1","report_ids":["p2"],"indicator_role":"c2","is_active":true,'
        '"mf":["Emotet"],"pa":["Emotet::apt28"]}'
    )
    item, _ = _syncer().parse_attribute(_ioc(otx), _OTX_EVENT)
    assert item["attack_ids"] == ["T1059"] and item["targeted_countries"] == ["DE"]
    assert item["pulse_tags"] == ["c2"] and item["pulse_references"] == ["https://example.org/r"]
    assert item["otx_industries"] == ["Finance"] and item["pulse_tlp"] == "green"
    assert item["report_ids"] == ["p2"] and item["pulse_malware_families"] == ["Emotet"]
    assert item["pulse_malware_actor_pairs"] == ["Emotet::apt28"] and item["pulse_name"] == "pulse p1"

    # URLhaus writes TF_META.tags as the feed's comma-separated string: it stays as it was.
    tf = (
        'TF_META:{"malware_malpedia":"","reference":"https://urlhaus.abuse.ch/url/3650001/",'
        '"tags":"32-bit,elf,mips,Mozi","last_seen":"","threat_type_desc":"","malware_family":"",'
        '"reporter":"geenensp","attributed_to":"","threat_type":"malware_download","ioc_id":"","malware_alias":""}'
    )
    item, _ = _syncer().parse_attribute(_ioc(tf), _TF_EVENT)
    assert item["tf_tags"] == "32-bit,elf,mips,Mozi" and item["reporter"] == "geenensp"
    assert item["reference"] == "https://urlhaus.abuse.ch/url/3650001/"


@pytest.mark.parametrize("payload", ["null", '["T1059"]', "1", '"T1059"'], ids=["null", "list", "number", "string"])
def test_malware_with_a_non_object_meta_keeps_the_description(payload, caplog):
    with caplog.at_level(logging.WARNING):
        item, _ = _syncer().parse_attribute(_malware(f"MITRE_USES_TECHNIQUES:{payload}\nBanking trojan."), _MITRE_EVENT)
    assert item is not None and item["name"] == "Emotet"
    assert item["uses_techniques"] == [] and item["reported_techniques"] == []
    assert item["description"] == "Banking trojan."
    assert any("[META] MITRE_USES_TECHNIQUES" in r.message and UUID in r.message for r in caplog.records)


def test_malware_string_technique_list_is_not_split_into_characters():
    item, _ = _syncer().parse_attribute(
        _malware('MITRE_USES_TECHNIQUES:{"t":"T1059","rt":"T1566","rids":"p2"}\nBanking trojan.'), _MITRE_EVENT
    )
    assert item["uses_techniques"] == [], "was ['T', '1', '0', '5', '9']"
    assert item["reported_techniques"] == []
    assert item.get("report_ids") in (None, [])

    item, _ = _syncer().parse_attribute(
        _malware('MITRE_USES_TECHNIQUES:{"t":["T1059","T1071"],"rt":["T1566"]}\nBanking trojan.'), _MITRE_EVENT
    )
    assert item["uses_techniques"] == ["T1059", "T1071"] and item["reported_techniques"] == ["T1566"]
    assert item["description"] == "Banking trojan."


def test_actor_string_lists_are_ignored():
    attr = {
        "type": "threat-actor",
        "value": "APT28",
        "uuid": UUID,
        "comment": 'MITRE_USES_TECHNIQUES:{"t":"T1059","rt":"T1566","m":"X-Agent","s":"Mimikatz"}\nRussian group.',
        "Tag": [],
    }
    item, _ = _syncer().parse_attribute(attr, _MITRE_EVENT)
    assert item["uses_techniques"] == [] and item["reported_techniques"] == []
    assert item["uses_malware"] == [] and item["uses_tools"] == []
    assert item["description"] == "Russian group."


def test_one_malformed_attribute_no_longer_fails_its_event():
    """Event level: the good attribute next to the malformed ones is written, nothing raises."""
    syncer = _syncer()
    syncer.stats = {"events_processed": 0, "events_failed": 0, "relationships_created": 0, "errors": 0}
    written: list = []
    syncer.sync_to_neo4j = lambda items: (written.extend(items), (len(items), 0, []))[1]
    syncer._create_relationships = lambda rels, source_id: 0
    syncer._write_cross_item_relationships = lambda rels: 0
    attributes = [
        _ioc("OTX_META:null", "203.0.113.1"),
        _ioc('OTX_META:["x"]', "203.0.113.2"),
        _ioc('OTX_META:{"pulse_id":"p1"}', "203.0.113.3"),
    ]
    parsed, _cross, errors = syncer._process_event_attributes("7", _OTX_EVENT, attributes)
    assert parsed == 3 and errors == 0
    assert sorted(i["value"] for i in written) == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert syncer.stats["events_processed"] == 1


def test_otx_list_elements_that_neo4j_cannot_store_are_dropped():
    """``n.attack_ids`` / ``n.targeted_countries`` are node properties: a list holding a map or mixed
    types failed the indicator batch (and the run). Strings stay as they are, numbers become strings."""
    comment = (
        'OTX_META:{"pulse_id":"p1","attack_ids":[{"id":"T1059"},"T1566",["T1071"],null,true],'
        '"targeted_countries":["DE",5],"pulse_tags":[{"t":"c2"}],"otx_industries":["Finance",2.5],'
        '"report_ids":["p2",{"id":"p3"}],"mf":[["Emotet"],"Qakbot"]}'
    )
    item, _ = _syncer().parse_attribute(_ioc(comment), _OTX_EVENT)
    assert item["attack_ids"] == ["T1566"]
    assert item["targeted_countries"] == ["DE", "5"]
    assert item["pulse_tags"] == [] and item["otx_industries"] == ["Finance", "2.5"]
    assert item["report_ids"] == ["p2"] and item["pulse_malware_families"] == ["Qakbot"]
    for key in ("attack_ids", "targeted_countries", "pulse_tags", "otx_industries", "report_ids"):
        assert all(isinstance(x, str) for x in item[key]), f"{key}: one type only, as Neo4j stores it"


def test_technique_lists_of_actors_malware_and_tools_keep_only_scalars():
    noisy = '["T1059",{"id":"T1071"},null,["T1003"]]'
    actor = {
        "type": "threat-actor",
        "value": "APT28",
        "uuid": UUID,
        "comment": f'MITRE_USES_TECHNIQUES:{{"t":{noisy},"rt":{noisy}}}\nRussian group.',
        "Tag": [],
    }
    item, _ = _syncer().parse_attribute(actor, _MITRE_EVENT)
    assert item["uses_techniques"] == ["T1059"] and item["reported_techniques"] == ["T1059"]

    actor["comment"] = f"MITRE_USES_TECHNIQUES:{noisy}\nRussian group."  # the older bare-list form
    item, _ = _syncer().parse_attribute(actor, _MITRE_EVENT)
    assert item["uses_techniques"] == ["T1059"]

    item, _ = _syncer().parse_attribute(
        _malware(f'MITRE_USES_TECHNIQUES:{{"t":{noisy}}}\nBanking trojan.'), _MITRE_EVENT
    )
    assert item["uses_techniques"] == ["T1059"]

    tool = {
        "type": "text",
        "value": "S0002: Mimikatz",
        "uuid": UUID,
        "comment": f"MITRE_USES_TECHNIQUES:{noisy}",
        "Tag": [],
    }
    item, _ = _syncer().parse_attribute(tool, _MITRE_EVENT)
    assert item["uses_techniques"] == ["T1059"]


def _tool(comment: str) -> dict:
    return {"type": "text", "value": "S0002: Mimikatz", "uuid": UUID, "comment": comment, "Tag": []}


@pytest.mark.parametrize(
    "payload", ["null", "1", '"T1059"', '{"t":"T1059"}'], ids=["null", "number", "string", "t-string"]
)
def test_stix_tool_with_a_malformed_comment_is_converted_without_techniques(payload):
    """``_attribute_to_stix21`` read the tool's comment with ``meta.get`` and caught no
    ``AttributeError``: ``null`` dropped the whole event from the STIX conversion, and
    ``{"t":"T1059"}`` gave one technique per character."""
    stix = _syncer()._attribute_to_stix21(
        _tool(f"MITRE_USES_TECHNIQUES:{payload}\nCredential dumper."), "ev", ["global"]
    )
    assert stix is not None and stix["type"] == "tool" and stix["name"] == "Mimikatz"
    assert "x_edgeguard_uses_techniques" not in stix
    assert stix["description"] == "Credential dumper."


def test_stix_tool_with_a_well_formed_comment_is_converted_as_before():
    stix = _syncer()._attribute_to_stix21(
        _tool('MITRE_USES_TECHNIQUES:{"t":["T1003","T1059"]}\nCredential dumper.'), "ev", ["global"]
    )
    assert stix["x_edgeguard_uses_techniques"] == ["T1003", "T1059"]
    assert stix["description"] == "Credential dumper."
    stix = _syncer()._attribute_to_stix21(_tool('MITRE_USES_TECHNIQUES:["T1003",{"x":1}]'), "ev", ["global"])
    assert stix["x_edgeguard_uses_techniques"] == ["T1003"], "the older bare-list form, as parse_attribute reads it"


def _technique(comment: str) -> dict:
    return {
        "type": "text",
        "value": "T1059: Command and Scripting Interpreter",
        "uuid": UUID,
        "comment": comment,
        "Tag": [{"name": 'mitre-attack:technique="T1059"'}],
    }


@pytest.mark.parametrize(
    "payload, phases",
    [
        ('{"p":"execution"}', []),
        ('{"p":["execution",{"x":1},null,3,["y"]]}', ["execution", "3"]),
        ('{"p":["execution","persistence"]}', ["execution", "persistence"]),
        ('["execution",{"x":1}]', ["execution"]),
        ("null", []),
        ('"execution"', []),
    ],
    ids=["string-p", "mixed-list", "well-formed", "bare-list", "null", "string"],
)
def test_technique_tactic_phases_are_read_through_the_meta_guards(payload, phases, caplog):
    """2026-10: the ``MITRE_TACTIC_PHASES`` block of a technique went straight to ``tactic_phases``:
    ``{"p":"execution"}`` gave a string, and a list holding a map or a null reached the node property,
    which Neo4j refuses for the whole batch."""
    with caplog.at_level(logging.WARNING):
        item, _ = _syncer().parse_attribute(
            _technique(f"MITRE_TACTIC_PHASES:{payload}\nAdversaries may abuse interpreters."), _MITRE_EVENT
        )
    assert item is not None and item["mitre_id"] == "T1059"
    assert item["tactic_phases"] == phases
    assert item["description"] == "Adversaries may abuse interpreters."
    if payload in ("null", '"execution"'):
        assert any("[META]" in r.message and UUID in r.message for r in caplog.records)
