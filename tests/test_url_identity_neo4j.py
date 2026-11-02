"""The ``url`` key on a real Neo4j with APOC: scheme and host lower-cased, the path as given (2026-11).

A mocked session shows the value a writer binds, not what a ``MERGE`` or ``MATCH`` finds among stored
nodes. Here the graph holds ``http://setseta.com/set.exe`` (as an earlier write or the lower-case
spelling of OTX pulse ``5d8dcf197ec3aea4d3e338df`` left it), and the OTX attribute MISP stored for the
pulse's other spelling, ``http://Setseta.com/set.exe``, goes through the production chain: the
attribute MISPWriter wrote for the item, parsed by the sync, merged by ``merge_indicators_batch``. It
must land on the stored node; so must the single-item merge, every link writer, the alert path, and a
REST search pasted in upper case, with or without a type, also for a scheme the lookup does not type
url (``htps://``). Two URLs whose paths differ in case
(``http://twizt.net/Installed`` / ``installed``, pulse ``679a2613007f9da5db46eb5f``) stay two nodes.

Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with ``EDGEGUARD_IT_NEO4J_URI``,
writes only nodes labelled ``EdgeGuardIT`` (the nodes the writers match exist beforehand with the label),
refuses any other node; a node a writer created without the label (the defect this module guards) is
labelled at teardown so the module still cleans the database, and the test fails.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)
from test_export_paths_neo4j import _api_modules  # noqa: E402  (query_api imported as dev)

import neo4j_client  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

STORED, PULSE_SPELLING, PASTED = (
    "http://setseta.com/set.exe",
    "http://Setseta.com/set.exe",
    "HTTP://SETSETA.COM/set.exe",
)
PATH_UPPER, PATH_LOWER = "http://twizt.net/Installed", "http://twizt.net/installed"
# A url of another scheme, as MISP stored it in the same event (pulse 67ca2991532d81738cbca1e8).
OTHER_SCHEME = "htps://cdn.discordapp.com/attachments/1316109420995809283/1316112071376769165/NativeApp_G4QLIQRa.exe"
PULSE = "5d8dcf197ec3aea4d3e338df"
EVENT = {"id": "55", "info": "EdgeGuard-alienvault_otx-2026-11-01", "date": "2026-11-01", "Tag": []}


def _uuid(value: str) -> str:
    return compute_node_uuid("Indicator", {"indicator_type": "url", "value": value})


FIXTURE = f"""
CREATE (:Source:{LABEL} {{source_id: 'alienvault_otx', edgeguard_managed: true}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'url', value: '{STORED}', uuid: '{_uuid(STORED)}', edgeguard_managed: true,
        source: ['alienvault_otx'], zone: ['global'], active: true}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'url', value: '{PATH_UPPER}', uuid: '{_uuid(PATH_UPPER)}',
        edgeguard_managed: true, source: ['alienvault_otx'], zone: ['global'], active: true}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'url', value: '{PATH_LOWER}', uuid: '{_uuid(PATH_LOWER)}',
        edgeguard_managed: true, source: ['alienvault_otx'], zone: ['global'], active: true}})
CREATE (:Indicator:{LABEL} {{indicator_type: 'url', value: '{OTHER_SCHEME}', uuid: '{_uuid(OTHER_SCHEME)}',
        edgeguard_managed: true, source: ['alienvault_otx'], zone: ['global'], active: true}})
CREATE (:Malware:{LABEL} {{name: 'kpot stealer', uuid: 'u-kpot', edgeguard_managed: true}})
CREATE (:CVE:{LABEL} {{cve_id: 'CVE-2024-3400', uuid: 'u-cve', edgeguard_managed: true}})
CREATE (:Sector:{LABEL} {{name: 'finance', uuid: '{compute_node_uuid("Sector", {"name": "finance"})}', edgeguard_managed: true}})
"""


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
        # A writer that missed the stored node created one without the label: label it so the module's
        # teardown removes it, then fail.
        stray = session.run(
            f"MATCH (n) WHERE NOT n:{LABEL} AND (n:Indicator OR n:Sector OR n:Source) SET n:{LABEL} "
            "RETURN collect(coalesce(n.value, n.name, n.source_id)) AS v"
        ).single()["v"]
        foreign = session.run(f"MATCH (n) WHERE NOT n:{LABEL} RETURN count(n) AS c").single()["c"]
    assert stray == [], f"a writer created a node beside the stored one: {stray}"
    assert foreign == 0, "the test wrote a node without the test label"


def _url_nodes(driver, lower_value: str):
    with driver.session() as session:
        return [
            dict(r)
            for r in session.run(
                "MATCH (i:Indicator {indicator_type: 'url'}) WHERE toLower(i.value) = $v "
                f"RETURN i.value AS value, i.uuid AS uuid, i:{LABEL} AS stored, i.source AS source, "
                "i.misp_event_ids AS events, [(i)-[:SOURCED_FROM]->(s:Source) | s.source_id] AS sourced_from "
                "ORDER BY i.value",
                v=lower_value,
            )
        ]


def _parsed_otx_attribute(value: str) -> dict:
    """The sync's item for the OTX attribute MISPWriter wrote for ``value`` in pulse ``PULSE``."""
    from collectors.misp_writer import MISPWriter
    from run_misp_to_neo4j import MISPToNeo4jSync

    item = {
        "indicator_type": "url",
        "value": value,
        "zone": ["global"],
        "tag": "alienvault_otx",
        "source": ["alienvault_otx"],
        "confidence_score": 0.5,
        "pulse_id": PULSE,
        "pulse_malware_families": ["KPOT Stealer"],
    }
    attr = MISPWriter.__new__(MISPWriter).create_attribute(item)
    attr.update(id="680425", event_id="55", uuid="6f3c1d5e-0000-4000-8000-000000680425", timestamp="1793538214")
    parsed, _rels = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(attr, EVENT)
    assert parsed["value"] == value, "the sync keeps the attribute's value; the merge keys it"
    return parsed


def test_the_batch_merge_of_a_parsed_misp_attribute_lands_on_the_stored_node(client, raw_driver):
    assert client.merge_indicators_batch([_parsed_otx_attribute(PULSE_SPELLING)], source_id="alienvault_otx") == (1, 0)
    nodes = _url_nodes(raw_driver, STORED)
    assert [(n["value"], n["uuid"], n["stored"]) for n in nodes] == [(STORED, _uuid(STORED), True)]
    assert nodes[0]["sourced_from"] == ["alienvault_otx"] and nodes[0]["events"] == ["55"]


def test_the_single_item_merge_lands_on_the_stored_node(client, raw_driver):
    assert client.merge_indicator({"indicator_type": "url", "value": PASTED}, source_id="alienvault_otx")
    assert [(n["value"], n["stored"]) for n in _url_nodes(raw_driver, STORED)] == [(STORED, True)]


def test_every_link_writer_matches_the_stored_node(client, raw_driver):
    client.create_misp_relationships_batch(
        [
            {
                "rel_type": "INDICATES",
                "from_type": "Indicator",
                "from_key": {"indicator_type": "url", "value": PULSE_SPELLING},
                "to_type": "Malware",
                "to_key": {"name": "KPOT Stealer"},
                "confidence": 0.6,
                "misp_event_id": "55",
                "source": "alienvault_otx",
                "source_refs": [f"alienvault_otx:{PULSE}"],
            }
        ],
        source_id="alienvault_otx",
    )
    assert client.create_indicator_vulnerability_relationship(
        PASTED, "CVE-2024-3400", source_id="alienvault_otx", indicator_type="url"
    )
    assert client.create_indicator_sector_relationship(
        PASTED, "finance", source_id="alienvault_otx", indicator_type="url"
    )
    with raw_driver.session() as session:
        links = sorted(
            (r["t"], r["target"])
            for r in session.run(
                f"MATCH (i:Indicator:{LABEL} {{value: $v}})-[r]->(x) WHERE NOT x:Source "
                "RETURN type(r) AS t, coalesce(x.name, x.cve_id) AS target",
                v=STORED,
            )
        )
    assert links == [("INDICATES", "CVE-2024-3400"), ("INDICATES", "kpot stealer"), ("TARGETS", "finance")]


def test_the_alert_path_merges_onto_the_stored_node(client, raw_driver):
    assert client.create_indicator_from_alert(PASTED, "url", "global")
    nodes = _url_nodes(raw_driver, STORED)
    assert [(n["value"], n["stored"]) for n in nodes] == [(STORED, True)]
    assert "resilmesh" in nodes[0]["source"]


def test_a_search_pasted_in_upper_case_finds_the_stored_node(client, raw_driver, monkeypatch):
    from fastapi.testclient import TestClient

    query_api, _graphql_api = _api_modules()
    monkeypatch.setattr(query_api, "neo4j_client", client)
    monkeypatch.setattr(query_api, "_API_KEY", None)
    rest = TestClient(query_api.app)
    for body in (
        {"value": PASTED},
        {"value": PULSE_SPELLING, "indicator_type": "url"},
        {"value": "hxxp://Setseta[.]com/set.exe"},
    ):
        answer = rest.post("/search/indicator", json=body).json()
        assert answer["found"] is True and answer["normalized_value"] == STORED, body
        assert answer["indicator"]["value"] == STORED and answer["indicator"]["uuid"] == _uuid(STORED)


def test_a_search_without_a_type_finds_a_url_of_another_scheme(client, raw_driver, monkeypatch):
    """The lookup types only http, https and ftp as url; without a type it still folds the scheme and host."""
    from fastapi.testclient import TestClient

    query_api, _graphql_api = _api_modules()
    monkeypatch.setattr(query_api, "neo4j_client", client)
    monkeypatch.setattr(query_api, "_API_KEY", None)
    pasted = OTHER_SCHEME.replace("htps://cdn.discordapp.com", "HTPS://CDN.DiscordApp.COM")
    answer = TestClient(query_api.app).post("/search/indicator", json={"value": pasted}).json()
    assert answer["found"] is True and answer["normalized_value"] == OTHER_SCHEME
    assert answer["indicator"]["value"] == OTHER_SCHEME and answer["indicator"]["uuid"] == _uuid(OTHER_SCHEME)


def test_urls_whose_paths_differ_in_case_stay_two_nodes(client, raw_driver):
    assert client.merge_indicators_batch([_parsed_otx_attribute(PATH_UPPER)], source_id="alienvault_otx") == (1, 0)
    nodes = _url_nodes(raw_driver, PATH_LOWER)
    assert [(n["value"], n["sourced_from"]) for n in nodes] == [(PATH_UPPER, ["alienvault_otx"]), (PATH_LOWER, [])]
