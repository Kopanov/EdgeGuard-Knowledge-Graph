"""The MISP -> Neo4j sync caps the texts it writes (2026-11-07, ``text_caps``).

MISP keeps the text the collector sent; the graph holds at most ``CVE_DESCRIPTION_CAP`` (1,000) characters of a
``CVE`` or ``Vulnerability`` description and ``ENTITY_DESCRIPTION_CAP`` (500) of a ``Technique``, ``Tactic``,
``ThreatActor``, ``Malware`` or ``Tool`` description, markup stripped and cut at a sentence or word end. The cap is
applied where the text reaches Neo4j (``DescriptionRanking.record``, which every writer of these descriptions
uses, and the ``SOURCED_FROM.raw_data`` copy of the record), so every path is covered: the batched CVE write
(``merge_cves_batch``, the sync's path), the single CVE write (``merge_cve``, its fallback), the Vulnerability
writes and the single entity writes.

Texts: ``tests/fixtures/text_caps_sources_2026_11_07.json`` (``test_text_caps.py``). The MISP attributes are built
by the collectors' and MISPWriter's own code from the recorded records, with the full source text in the
attribute where MISP holds it once no collector cuts it: ``NVD_META.description`` for a CVE, the text after the
``MITRE_*`` block (or the whole comment without one) for an ATT&CK object; that replacement of the collector's and
the writer's cut is constructed. Today's texts come from the real fixtures the CVE batch tests read
(``test_cve_batch_writes.py``): they reach the graph unchanged.
"""

from __future__ import annotations

import copy
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fake_bolt import FakeBolt, fail  # noqa: E402

import neo4j_client as nc  # noqa: E402
from collectors import mitre_collector as mc  # noqa: E402
from collectors.misp_writer import MISPWriter  # noqa: E402
from collectors.nvd_collector import NVDCollector  # noqa: E402
from description_ranking import CVE_DESCRIPTIONS, ENTITY_DESCRIPTIONS  # noqa: E402
from run_misp_to_neo4j import _METADATA_COMMENT_RE, MISPToNeo4jSync  # noqa: E402
from text_caps import CVE_DESCRIPTION_CAP, ENTITY_DESCRIPTION_CAP, cap_text, strip_markup  # noqa: E402

FIXTURE = json.loads((TESTS / "fixtures" / "text_caps_sources_2026_11_07.json").read_text())
WRITER = MISPWriter.__new__(MISPWriter)
NVD_EVENT = {"id": "501", "info": "EdgeGuard-nvd-2026-11-07", "Tag": []}
MITRE_EVENT = {"id": "502", "info": "EdgeGuard-mitre_attck-2026-11-07", "Tag": []}

SINGLE_CVE = "MERGE (n:CVE {cve_id: $cve_id})"
BATCH_CVE = "MERGE (n:CVE {cve_id: row.cve_id})"
SINGLE_VULNERABILITY = "MERGE (n:Vulnerability {cve_id: $cve_id})"
BATCH_VULNERABILITY = "MERGE (n:Vulnerability {cve_id: item.cve_id})"
SINGLE_EDGE = "MERGE (n)-[r:SOURCED_FROM]->(s)"
TYPE_ERROR = "Neo.ClientError.Statement.TypeError"


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(nc.time, "sleep", lambda *_a, **_k: None)


@pytest.fixture
def bolt():
    opened = []

    def start(*rules):
        server = FakeBolt(list(rules))
        client = nc.Neo4jClient(uri=server.uri, user="neo4j", password="pw")
        opened.append((server, client))
        assert client.connect() is True
        return server, client

    yield start
    for server, client in opened:
        client.close()
        server.close()


def _statements(server: FakeBolt, marker: str) -> List[Dict[str, Any]]:
    """The parameters of every statement the server received that contains ``marker``."""
    return [params for query, params in zip(server.runs, server.parameters, strict=True) if marker in query]


# ---------------------------------------------------------------------------------------------- CVE records
def _nvd_description(cve_id: str) -> str:
    (record,) = [v for v in FIXTURE["nvd"] if v["cve"]["id"] == cve_id]
    return next(d["value"] for d in record["cve"]["descriptions"] if d["lang"] == "en")


def _nvd_attribute(cve_id: str) -> Dict[str, Any]:
    """The MISP attribute of the recorded NVD record: the NVD collector's item, written by MISPWriter, with the
    full description in ``NVD_META`` (constructed: MISP holds it so once no collector cuts it)."""
    records = [v for v in FIXTURE["nvd"] if v["cve"]["id"] == cve_id]
    collector = NVDCollector.__new__(NVDCollector)
    collector.base_url, collector.api_key, collector._api_key_rejected = "http://fake", "k", False
    collector.tag = collector.source_name = "nvd"
    collector.misp_writer, collector.circuit_breaker = MagicMock(), MagicMock()
    with (
        patch.object(NVDCollector, "_fetch_modified_cves", return_value=(records, True)),
        patch.object(NVDCollector, "check_service_available", return_value=True),
    ):
        (item,) = collector.collect(limit=None, push_to_misp=False, baseline=False)
    item = dict(item, description=_nvd_description(cve_id))
    attribute = WRITER.create_vulnerability_attribute(item)
    attribute.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, cve_id)), event_id="501", timestamp="1")
    meta = json.loads(attribute["comment"][len("NVD_META:") :])
    assert meta["description"] == _nvd_description(cve_id), "MISP holds the full text"
    return attribute


def _synced_cve(cve_id: str) -> Dict[str, Any]:
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_nvd_attribute(cve_id), NVD_EVENT)
    assert item is not None and item["description"] == _nvd_description(cve_id), "the sync reads the full text"
    return item


LONG_CVES = ("CVE-2026-2411", "CVE-2026-69245")


def _capped_cve(cve_id: str) -> str:
    out, truncated, _ = cap_text(_nvd_description(cve_id), CVE_DESCRIPTION_CAP)
    assert truncated and len(out) <= 1000 and len(_nvd_description(cve_id)) > 1000
    return out


class TestCveDescription:
    @pytest.mark.parametrize("cve_id", LONG_CVES)
    def test_the_batch_path_of_the_sync_stores_it_capped(self, bolt, cve_id):
        server, client = bolt()
        sync = MISPToNeo4jSync(neo4j_client=client)
        assert sync._sync_to_neo4j_chunk([_synced_cve(cve_id)]) == (1, 0)
        (node,) = _statements(server, BATCH_CVE)
        (row,) = node["rows"]
        assert row["description"] == _capped_cve(cve_id) and row["description_source"] == "nvd"
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "rows" in p]
        (edge_row,) = edge["rows"]
        assert json.loads(edge_row["raw_data"])["description"] == _capped_cve(cve_id)
        assert not _statements(server, SINGLE_CVE)

    @pytest.mark.parametrize("cve_id", LONG_CVES)
    def test_the_single_path_stores_it_capped(self, bolt, cve_id):
        server, client = bolt()
        assert client.merge_cve(_synced_cve(cve_id), source_id="nvd") is True
        (node,) = _statements(server, SINGLE_CVE)
        assert node["ranked_description"] == _capped_cve(cve_id)
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "raw_data" in p]
        assert json.loads(edge["raw_data"])["description"] == _capped_cve(cve_id)

    def test_the_syncs_fallback_to_the_single_path_stores_it_capped(self, bolt):
        """A batch that fails is written one CVE at a time by ``merge_cve``."""
        server, client = bolt(fail(BATCH_CVE, TYPE_ERROR))
        sync = MISPToNeo4jSync(neo4j_client=client)
        assert sync._sync_to_neo4j_chunk([_synced_cve("CVE-2026-69245")]) == (1, 0)
        assert sync.stats["cve_batch_fallbacks"] == 1
        (node,) = _statements(server, SINGLE_CVE)
        assert node["ranked_description"] == _capped_cve("CVE-2026-69245")

    @pytest.mark.parametrize("cve_id", LONG_CVES)
    def test_the_vulnerability_writes_store_it_capped(self, bolt, cve_id):
        server, client = bolt()
        item = _synced_cve(cve_id)
        assert client.merge_vulnerability(copy.deepcopy(item), source_id="nvd") is True
        (node,) = _statements(server, SINGLE_VULNERABILITY)
        assert node["ranked_description"] == _capped_cve(cve_id)
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "raw_data" in p]
        assert json.loads(edge["raw_data"])["description"] == _capped_cve(cve_id)

        assert client.merge_vulnerabilities_batch([copy.deepcopy(item)], source_id="nvd") == (1, 0)
        (batch,) = _statements(server, BATCH_VULNERABILITY)
        (row,) = batch["batch"]
        assert row["description"] == _capped_cve(cve_id)
        assert json.loads(row["raw_data"])["description"] == _capped_cve(cve_id)

    def test_a_resilmesh_native_write_stores_it_capped(self, bolt):
        server, client = bolt()
        text = _nvd_description("CVE-2026-69245")
        assert client.merge_resilmesh_cve({"cve_id": "CVE-2026-69245", "description": text}) is True
        assert client.merge_resilmesh_vulnerability({"cve_id": "CVE-2026-69245", "description": text}) is True
        found = [p["description"] for p in server.parameters if "description_source" in p]
        assert found == [_capped_cve("CVE-2026-69245")] * 2

    def test_a_cve_description_of_900_characters_is_not_cut(self):
        # Constructed: the CVE cap is 1,000, not the 500 of the entities.
        text = ("This sentence has exactly forty-four chars. " * 21)[:900].rstrip()
        assert len(text) > 500
        ranked = CVE_DESCRIPTIONS.record(text, "nvd")
        assert ranked is not None and ranked.text == text


# ---------------------------------------------------------------------------------------------- ATT&CK records
_KINDS = {
    # kind: (ATT&CK id, parse key, MISPWriter builder, Neo4jClient merge, node MERGE marker)
    "technique": ("T1036.007", "techniques", "create_technique_attribute", "merge_technique", "Technique"),
    "subtechnique": ("T1059.001", "techniques", "create_technique_attribute", "merge_technique", "Technique"),
    "actor": ("G0007", "actors", "create_actor_attribute", "merge_actor", "ThreatActor"),
    "malware": ("S0154", "malware", "create_malware_attribute", "merge_malware", "Malware"),
    "tool": ("S0002", "tools", "create_tool_attribute", "merge_tool", "Tool"),
    "tactic": ("TA0001", "tactics", "create_tactic_attribute", "merge_tactic", "Tactic"),
}


def _attack_text(ext_id: str) -> str:
    return next(o["description"] for o in FIXTURE["attack"] if o["external_references"][0]["external_id"] == ext_id)


def _mitre_attribute(kind: str) -> Dict[str, Any]:
    """The MISP attribute of the recorded ATT&CK object: the MITRE collector's item, written by MISPWriter, with
    ATT&CK's full description after the ``MITRE_*`` block, or as the whole comment without one (constructed:
    MISP holds it so once neither the collector nor the writer cuts it)."""
    ext_id, key, builder, _merge, _label = _KINDS[kind]
    collector = mc.MITRECollector(misp_writer=MagicMock())
    parsed = collector._parse_bundle(
        copy.deepcopy(FIXTURE["attack"]), domain=mc.ATTACK_DOMAIN_ENTERPRISE, kill_chain_name="mitre-attack"
    )
    (item,) = [i for i in parsed[key] if i["mitre_id"] == ext_id]
    attribute = getattr(WRITER, builder)(item)
    assert attribute is not None
    full = _attack_text(ext_id)
    if _METADATA_COMMENT_RE.match(attribute["comment"]):
        attribute["comment"] = attribute["comment"].split("\n", 1)[0] + "\n" + full
    else:
        attribute["comment"] = full
    attribute.update(uuid=str(uuid.uuid5(uuid.NAMESPACE_URL, ext_id)), event_id="502", timestamp="1")
    return attribute


def _synced_entity(kind: str) -> Dict[str, Any]:
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_mitre_attribute(kind), MITRE_EVENT)
    full = _attack_text(_KINDS[kind][0])
    # The sync strips the whitespace around a text after a block (G0007's ends in a space).
    assert item is not None and item["description"] in (full, full.strip()), "the sync reads the full text"
    return item


class TestEntityDescription:
    @pytest.mark.parametrize("kind", ["technique", "subtechnique", "actor", "malware"])
    def test_a_long_description_is_stored_capped(self, bolt, kind):
        ext_id, _key, _builder, merge, label = _KINDS[kind]
        full = _attack_text(ext_id)
        expected, truncated, _ = cap_text(full, ENTITY_DESCRIPTION_CAP)
        assert truncated and len(full) > 500 and len(expected) <= 500
        server, client = bolt()
        assert getattr(client, merge)(_synced_entity(kind), source_id="mitre_attck") is True
        (node,) = _statements(server, f"MERGE (n:{label} {{")
        assert node["ranked_description"] == expected and node["ranked_description_source"] == "mitre_attck"
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "raw_data" in p]
        assert json.loads(edge["raw_data"])["description"] == expected

    @pytest.mark.parametrize("kind", sorted(_KINDS))
    def test_the_sync_stores_every_kind_capped(self, bolt, kind):
        """Through ``_sync_to_neo4j_chunk``: the description each node gets."""
        ext_id, _key, _builder, _merge, label = _KINDS[kind]
        server, client = bolt()
        sync = MISPToNeo4jSync(neo4j_client=client)
        assert sync._sync_to_neo4j_chunk([_synced_entity(kind)]) == (1, 0)
        (node,) = _statements(server, f"MERGE (n:{label} {{")
        assert node["ranked_description"] == cap_text(_attack_text(ext_id), ENTITY_DESCRIPTION_CAP)[0]
        assert len(node["ranked_description"]) <= 500

    def test_a_short_description_loses_only_its_markup(self, bolt):
        full = _attack_text("S0002")
        assert len(full) < 500 and "](" in full and "(Citation:" in full
        server, client = bolt()
        assert client.merge_tool(_synced_entity("tool"), source_id="mitre_attck") is True
        (node,) = _statements(server, "MERGE (n:Tool {")
        assert (
            node["ranked_description"]
            == strip_markup(full)
            == (
                "Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins and passwords, "
                "along with many other features that make it useful for testing the security of networks."
            )
        )

    def test_a_short_description_without_markup_is_unchanged(self, bolt):
        full = _attack_text("TA0001")
        server, client = bolt()
        assert client.merge_tactic(_synced_entity("tactic"), source_id="mitre_attck") is True
        (node,) = _statements(server, "MERGE (n:Tactic {")
        assert node["ranked_description"] == full

    @pytest.mark.parametrize("source_id", ["mitre_attck", "misp", "coreideas", "stix_import"])
    def test_every_source_is_capped(self, source_id):
        full = _attack_text("G0007")
        ranked = ENTITY_DESCRIPTIONS.record(full, source_id)
        assert ranked is not None and ranked.text == cap_text(full, 500)[0]

    def test_a_record_left_without_text_by_the_cap_gives_no_description(self):
        assert ENTITY_DESCRIPTIONS.record("(Citation: A)(Citation: B)", "mitre_attck") is None
        assert ENTITY_DESCRIPTIONS.record("x" * 600, "mitre_attck") is None
        assert CVE_DESCRIPTIONS.record("<code></code>", "nvd") is None


# ---------------------------------------------------------------------------------------------- today's texts
def _todays_cve_items() -> List[Tuple[Dict[str, Any], str]]:
    """The sync's items of the real CVE attributes the CVE batch tests read (hosted MISP and NVD records)."""
    from test_cve_batch_writes import _hosted_items, _nvd_items

    return [(item, item.get("tag", "misp")) for item in _nvd_items() + _hosted_items()]


class TestTodaysTexts:
    def test_todays_cve_descriptions_reach_the_graph_unchanged(self):
        items = _todays_cve_items()
        described = [(i, s) for i, s in items if isinstance(i.get("description"), str) and i["description"].strip()]
        assert len(described) > 50
        assert {s for _i, s in described} >= {"nvd", "cisa_kev", "cisa_ics"}
        for item, source_id in described:
            assert strip_markup(item["description"]) == item["description"], item["cve_id"]
            row = nc._prepare_cve_write(copy.deepcopy(item), source_id)
            assert row["node"]["description"] == item["description"], item["cve_id"]
            assert json.loads(row["edge"]["raw_data"])["description"] == item["description"], item["cve_id"]

    def test_the_raw_data_copy_keeps_every_other_field(self):
        item = _synced_cve("CVE-2026-69245")
        row = nc._prepare_cve_write(copy.deepcopy(item), "nvd")
        raw = json.loads(row["edge"]["raw_data"])
        expected = {k: v for k, v in item.items() if k != "cve_id"}
        expected["description"] = _capped_cve("CVE-2026-69245")
        assert raw == json.loads(json.dumps(expected, default=str))

    def test_the_rankings_caps(self):
        assert (CVE_DESCRIPTIONS.cap, ENTITY_DESCRIPTIONS.cap) == (1000, 500)
        assert CVE_DESCRIPTIONS.capped(None) is None and ENTITY_DESCRIPTIONS.capped(5) == 5
