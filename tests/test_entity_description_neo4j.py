"""Malware, ThreatActor and Tool descriptions on a real Neo4j (2026-10).

MITRE ATT&CK's record (``mitre_attck``) sets the description; a record from any other source fills it only
where the node has none, an empty string counting as none (``neo4j_client._entity_description_fill``,
``tests/test_entity_description_source.py``). The records are the ones that suite builds: ATT&CK's
Dragonfly, Cobalt Strike and Mimikatz through the MITRE collector, MISPWriter and the sync, and the items
the OTX collector gave until 2026-10 (the pulse's description as the entity's), merged in both orders.
Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

FIXTURE = f"""
CREATE (:Source:{LABEL} {{source_id: 'mitre_attck'}})
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx'}})
CREATE (:Source:{LABEL} {{source_id: 'stix_import'}})
CREATE (:Source:{LABEL} {{source_id: 'misp'}})
"""

# The node each merge below writes to, created with the test label first (a MERGE would create one without).
NODES = {
    "malware": ("Malware", "name", "cobalt strike"),
    "actor": ("ThreatActor", "name", "dragonfly"),
    "tool": ("Tool", "mitre_id", "S0002"),
    "kataru": ("Malware", "name", "kataru"),
}
MERGE = {"malware": "merge_malware", "actor": "merge_actor", "tool": "merge_tool"}
ATTACK_NAMES = {"malware": "Cobalt Strike", "actor": "Dragonfly"}


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()
    with raw_driver.session() as session:
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert foreign == 0, "the test wrote a node without the test label"


def _create(raw_driver, node: str, **props) -> None:
    label, key, value = NODES[node]
    with raw_driver.session() as session:
        session.run(f"CREATE (n:{label}:{LABEL} {{{key}: $value}}) SET n += $props", value=value, props=props)


def _node(raw_driver, node: str) -> dict:
    label, key, value = NODES[node]
    with raw_driver.session() as session:
        rows = list(session.run(f"MATCH (n:{label} {{{key}: $value}}) RETURN properties(n) AS p", value=value))
    assert len(rows) == 1, f"one {label} node expected, found {len(rows)}"
    return rows[0]["p"]


def _mitre(kind: str) -> dict:
    """MITRE's record of *kind* as the sync reads it from MISP."""
    from test_entity_description_source import mitre_items, synced, written

    return synced(written(kind, mitre_items()[kind]))


def _otx_before_2026_10(kind: str) -> dict:
    """The OTX collector's item until 2026-10: the pulse's description as the entity's."""
    from test_entity_description_source import otx_item_before_2026_10

    return otx_item_before_2026_10(kind, ATTACK_NAMES[kind])


@pytest.mark.parametrize("first", ["mitre", "otx"])
@pytest.mark.parametrize("kind", ["malware", "actor"])
def test_attacks_text_wins_in_both_orders(client, raw_driver, kind, first):
    _create(raw_driver, kind)
    mitre, otx = _mitre(kind), _otx_before_2026_10(kind)
    records = [(mitre, "mitre_attck"), (otx, "alienvault_otx")]
    for item, source in records if first == "mitre" else records[::-1]:
        assert getattr(client, MERGE[kind])(item, source_id=source)
    node = _node(raw_driver, kind)
    assert node["description"] == mitre["description"]
    assert node["description"].startswith(f"[{ATTACK_NAMES[kind]}]")
    assert set(node["source"]) == {"mitre_attck", "alienvault_otx"}, "both records were merged"


def test_another_source_fills_an_empty_node_and_its_text_stays(client, raw_driver):
    _create(raw_driver, "actor", description="")
    first = dict(_mitre("actor"), description="An external bundle's text")
    second = dict(_mitre("actor"), description="A MISP-native attribute's text")
    assert client.merge_actor(first, source_id="stix_import")
    assert _node(raw_driver, "actor")["description"] == "An external bundle's text", "an empty value counts as none"
    assert client.merge_actor(second, source_id="misp")
    assert _node(raw_driver, "actor")["description"] == "An external bundle's text"
    assert client.merge_actor(_mitre("actor"), source_id="mitre_attck")
    assert _node(raw_driver, "actor")["description"] == _mitre("actor")["description"], "MITRE's record replaces it"


def test_a_tool_takes_mitres_revised_text_and_no_other(client, raw_driver):
    _create(raw_driver, "tool")
    assert client.merge_tool(dict(_mitre("tool"), description="ATT&CK v17 text"), source_id="mitre_attck")
    assert client.merge_tool(_mitre("tool"), source_id="mitre_attck")
    assert client.merge_tool(dict(_mitre("tool"), description="A STIX bundle's text"), source_id="stix_import")
    assert _node(raw_driver, "tool")["description"] == _mitre("tool")["description"]


def test_otx_records_as_synced_since_2026_10_write_no_description(client, raw_driver):
    from test_entity_description_source import KATARU_PULSE, otx_item, synced, written

    _create(raw_driver, "kataru")
    kataru = synced(written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx")
    assert kataru["description"] == ""
    assert client.merge_malware(kataru, source_id="alienvault_otx")
    node = _node(raw_driver, "kataru")
    assert "description" not in node, "an OTX-only family shows no description"
    assert sorted(node["reported_techniques"]) == ["T1053.003", "T1082", "T1110.001", "T1498.001"], "the record merged"
