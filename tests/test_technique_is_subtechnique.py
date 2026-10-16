"""``Technique.is_subtechnique`` follows the ATT&CK id (2026-10).

``merge_technique`` set ``is_subtechnique`` from the record (``data.get("is_subtechnique", False)``).
Only the MITRE collector's item carries the flag, and the MISP round trip drops it: MISPWriter writes
no flag into a technique attribute and the sync's parser sets none, so every sync wrote ``false`` onto
every sub-technique (all 506 dotted Technique nodes of the hosted graph on 2026-10-16), and GraphQL's
``Technique.is_subtechnique`` was wrong for each of them. The flag is now read from the normalised id,
as build_relationships step 1b reads the parent: ATT&CK identifies a sub-technique by its parent's id
and a dotted suffix.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_attack_revoked_objects import _parse, _technique  # noqa: E402
from test_entity_description_source import mitre_items, synced, written  # noqa: E402

import neo4j_client  # noqa: E402

PARENT = "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830"


def _merged_extra_props(item: Dict[str, Any]) -> Dict[str, Any]:
    """The properties ``merge_technique`` sends to the node SET for *item*, with its MERGE key."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    captured: Dict[str, Any] = {}

    def capture(label, key_props, data, source_id, extra_props=None, fill_props=None, description=None):
        captured.update(label=label, key=key_props, extra=extra_props or {})
        return True

    client.merge_node_with_source = capture  # type: ignore[method-assign]
    assert client.merge_technique(item, source_id="mitre_attck")
    assert captured["label"] == "Technique"
    return {**captured["extra"], "mitre_id": captured["key"]["mitre_id"]}


def _synced_technique(mitre_id: str, name: str, stix_id: str) -> Dict[str, Any]:
    """The MITRE collector's item for *mitre_id*, written to MISP and read back by the sync."""
    item = _parse([_technique(stix_id, mitre_id, name)])["techniques"][0]
    assert item["is_subtechnique"] is ("." in mitre_id), "the collector's own item carries the flag"
    return synced(written("technique", item))


def test_a_sub_technique_synced_from_misp_is_marked_as_one():
    item = synced(written("technique", mitre_items()["technique"]))  # T1059.001 PowerShell
    assert item["mitre_id"] == "T1059.001"
    # Why the record cannot be trusted for the flag: the MISP round trip does not carry it.
    assert "is_subtechnique" not in item
    props = _merged_extra_props(item)
    assert props["is_subtechnique"] is True, "T1059.001 was written as is_subtechnique=false on every sync"


def test_a_parent_technique_is_not_marked():
    item = _synced_technique("T1059", "Command and Scripting Interpreter", PARENT)
    assert _merged_extra_props(item)["is_subtechnique"] is False


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"mitre_id": "t1059.001", "name": "PowerShell"}, True),  # a MISP peer's lower-case id, normalised
        ({"mitre_id": " T1021.006 ", "name": "Windows Remote Management", "is_subtechnique": False}, True),
        ({"mitre_id": "T1021", "name": "Remote Services", "is_subtechnique": True}, False),
        ({"mitre_id": "T0817", "name": "Drive-by Compromise", "attack_domain": "ics"}, False),
    ],
    ids=["lower-case-dotted", "record-says-false", "record-says-true", "ics-technique"],
)
def test_the_flag_follows_the_normalised_id_whatever_the_record_says(record, expected):
    props = _merged_extra_props(record)
    assert props["mitre_id"] == record["mitre_id"].strip().upper()
    assert props["is_subtechnique"] is expected
