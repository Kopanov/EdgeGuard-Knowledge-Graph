"""Malware, ThreatActor and Tool descriptions on a real Neo4j (2026-10).

The source ranking MITRE ATT&CK > a curated source > any other source decides the description, and the node
names its source in ``description_source`` (``description_ranking``, 2026-10-16; until then MITRE's record
set it and any other record only filled it); an empty string counts as no description
(``tests/test_entity_description_source.py``, every order: ``tests/test_description_ranking_neo4j.py``).
The records are the ones that suite builds: ATT&CK's
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
    assert (node["description"], node["description_source"]) == (mitre["description"], "mitre_attck")
    assert node["description"].startswith(f"[{ATTACK_NAMES[kind]}]")
    assert set(node["source"]) == {"mitre_attck", "alienvault_otx"}, "both records were merged"


def _described(raw_driver, node: str) -> tuple:
    props = _node(raw_driver, node)
    return props.get("description"), props.get("description_source")


def test_each_record_replaces_a_lower_ranked_text_and_none_replaces_mitres(client, raw_driver):
    # Until 2026-10-16 the external bundle's text, which arrived first, stayed against the MISP-native one.
    _create(raw_driver, "actor", description="")
    bundle = dict(_mitre("actor"), description="An external bundle's text")
    native = dict(_mitre("actor"), description="A MISP-native attribute's text")
    assert client.merge_actor(bundle, source_id="stix_import")
    assert _described(raw_driver, "actor") == ("An external bundle's text", "stix_import"), "'' counts as none"
    assert client.merge_actor(native, source_id="misp")
    assert _described(raw_driver, "actor") == ("A MISP-native attribute's text", "misp"), "a registered source"
    assert client.merge_actor(bundle, source_id="stix_import")
    assert _described(raw_driver, "actor") == ("A MISP-native attribute's text", "misp")
    assert client.merge_actor(_mitre("actor"), source_id="mitre_attck")
    assert _described(raw_driver, "actor") == (_mitre("actor")["description"], "mitre_attck")
    assert client.merge_actor(native, source_id="misp")
    assert _described(raw_driver, "actor") == (_mitre("actor")["description"], "mitre_attck")


def test_a_tool_takes_mitres_revised_text_and_no_other(client, raw_driver):
    _create(raw_driver, "tool")
    assert client.merge_tool(dict(_mitre("tool"), description="ATT&CK v17 text"), source_id="mitre_attck")
    assert client.merge_tool(_mitre("tool"), source_id="mitre_attck")
    assert client.merge_tool(dict(_mitre("tool"), description="A STIX bundle's text"), source_id="stix_import")
    assert _node(raw_driver, "tool")["description"] == _mitre("tool")["description"]


def test_otx_records_as_synced_since_2026_10_write_no_description(client, raw_driver):
    from test_entity_description_source import KATARU_IDS, KATARU_PULSE, otx_item, synced, written

    _create(raw_driver, "kataru")
    kataru = synced(written("malware", otx_item("malware", "KATARU", KATARU_PULSE)), "alienvault_otx")
    assert kataru["description"] == ""
    assert client.merge_malware(kataru, source_id="alienvault_otx")
    node = _node(raw_driver, "kataru")
    assert "description" not in node, "an OTX-only family shows no description"
    assert sorted(node["reported_techniques"]) == sorted(KATARU_IDS), "the record merged"


def test_the_real_kataru_attribute_of_2026_10_09_writes_no_description(client, raw_driver):
    # The attribute MISP held with the pulse's text after its block (tests/fixtures/otx_entity_attributes_2026_10_09.json).
    from test_entity_description_source import REAL_OTX, as_misp_returns, synced

    _create(raw_driver, "kataru")
    assert client.merge_malware(
        synced(as_misp_returns(REAL_OTX["KATARU"]), "alienvault_otx"), source_id="alienvault_otx"
    )
    assert "description" not in _node(raw_driver, "kataru")


# The RUNBOOK repair ("Repairing Malware, ThreatActor and Tool descriptions"), steps 2 and 4, run as written
# but on the test label only. (label, name, properties) of each node, and whether its description stays.
_REPAIR_NODES = [
    (
        "Malware",
        "kataru",
        {
            "edgeguard_managed": True,
            "source": ["alienvault_otx"],
            "description": 'MITRE_USES_TECHNIQUES:{"rt":["T1082"],"pid":"68c30a2bd84d2a2fe1fc3f4b"}',
        },
        False,
    ),
    (
        "Tactic",
        "execution",
        {"edgeguard_managed": True, "source": ["mitre_attck"], "description": "MITRE ATT&CK tactic"},
        False,
    ),
    (
        "ThreatActor",
        "dragonfly",
        {"edgeguard_enriched": True, "source": ["mitre_attck"], "description": "Threat actor from alienvault_otx"},
        False,
    ),
    ("ThreatActor", "jeetbot", {"edgeguard_managed": True, "source": ["alienvault_otx"], "description": "OTX"}, False),
    ("ThreatActor", "charming kitten", {"source": ["misp"], "description": "Threat actor from Iran"}, True),
    ("ThreatActor", "partner actor", {"source": ["misp"], "description": "Threat actor from misp"}, True),
    ("Malware", "partner family", {"source": ["alienvault_otx"], "description": "A partner's text"}, True),
    (
        "Malware",
        "cobalt strike",
        {"edgeguard_managed": True, "source": ["mitre_attck", "alienvault_otx"], "description": "ATT&CK"},
        True,
    ),
]


def test_the_runbook_repair_removes_edgeguards_text_and_keeps_a_partners(client, raw_driver):
    from test_entity_description_source import COBALT_STRIKE_TEXT, REAL_OTX, runbook_statements

    texts = {"OTX": REAL_OTX["JeetBot"]["comment"].partition("\n")[2], "ATT&CK": COBALT_STRIKE_TEXT}
    with raw_driver.session() as session:
        for label, name, props, _stays in _REPAIR_NODES:
            props = dict(props, description=texts.get(props["description"], props["description"]))
            session.run(f"CREATE (n:{label}:{LABEL} {{name: $name}}) SET n += $props", name=name, props=props)
        statements = runbook_statements()
        for step in (statements[1], statements[3]):  # steps 2 and 4
            assert step.count("MATCH (n)\n") == 1
            session.run(step.replace("MATCH (n)\n", f"MATCH (n:{LABEL})\n", 1))
        rows = {
            r["name"]: r["d"]
            for r in session.run(
                f"MATCH (n:{LABEL}) WHERE n.name IS NOT NULL RETURN n.name AS name, n.description AS d"
            )
        }
    for _label, name, _props, stays in _REPAIR_NODES:
        assert (rows[name] is not None) is stays, name
    assert rows["cobalt strike"] == COBALT_STRIKE_TEXT and rows["charming kitten"] == "Threat actor from Iran"
