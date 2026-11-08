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
import importlib.util
import json
import re
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

import enrichment_jobs  # noqa: E402
import neo4j_client as nc  # noqa: E402
from attack_software_names import attack_software_id  # noqa: E402
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
NVD_RECORDS = FIXTURE["nvd"] + FIXTURE["nvd_kernel"]


def _nvd_description(cve_id: str) -> str:
    (record,) = [v for v in NVD_RECORDS if v["cve"]["id"] == cve_id]
    return next(d["value"] for d in record["cve"]["descriptions"] if d["lang"] == "en")


def _nvd_attribute(cve_id: str) -> Dict[str, Any]:
    """The MISP attribute of the recorded NVD record: the NVD collector's item, written by MISPWriter, with the
    full description in ``NVD_META`` (constructed: MISP holds it so once no collector cuts it)."""
    records = [v for v in NVD_RECORDS if v["cve"]["id"] == cve_id]
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

    def test_a_bracket_that_opens_no_link_reaches_the_graph(self, bolt):
        """A kernel CVE description (NVD API 2.0, kernel.org CNA) with a half-open interval: the batch path stores
        a prefix of the source text that keeps the interval's "[" and the line breaks."""
        source = _nvd_description("CVE-2026-89494")
        server, client = bolt()
        sync = MISPToNeo4jSync(neo4j_client=client)
        assert sync._sync_to_neo4j_chunk([_synced_cve("CVE-2026-89494")]) == (1, 0)
        (node,) = _statements(server, BATCH_CVE)
        (row,) = node["rows"]
        assert source.startswith(row["description"]) and len(row["description"]) <= CVE_DESCRIPTION_CAP
        assert "mres->ml[0..num_locks) past the\n" in row["description"]
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "rows" in p]
        assert json.loads(edge["rows"][0]["raw_data"])["description"] == row["description"]

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


def written_attack_record(kind: str) -> Tuple[Dict[str, Any], str]:
    """What ``merge_malware`` / ``merge_actor`` write for the recorded ATT&CK object of ``kind`` (``malware``:
    Cobalt Strike S0154; ``actor``: APT28 G0007), on a FakeBolt server: the node's parameters and the record on
    its ``SOURCED_FROM`` edge (``raw_data``). The readers of the ATT&CK id take these (``attack_software_names.
    attack_software_id``, ``scripts/verify_fresh_baseline.py``, ``scripts/build_canonical_threat_actors.py``)."""
    _ext_id, _key, _builder, merge, label = _KINDS[kind]
    server = FakeBolt([])
    client = nc.Neo4jClient(uri=server.uri, user="neo4j", password="pw")
    try:
        assert client.connect() is True
        assert getattr(client, merge)(_synced_entity(kind), source_id="mitre_attck") is True
        (node,) = _statements(server, f"MERGE (n:{label} {{")
        (edge,) = [p for p in _statements(server, SINGLE_EDGE) if "raw_data" in p]
        return node, edge["raw_data"]
    finally:
        client.close()
        server.close()


def without_mitre_id(raw_data: str) -> str:
    """``raw_data`` without its ``mitre_id``, as a record written before the sync carried the id."""
    return json.dumps({k: v for k, v in json.loads(raw_data).items() if k != "mitre_id"})


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
        """A text within the cap reaches the graph unchanged; a longer one (the NVD collector no longer cuts at
        1,000 characters, 2026-11-07) is capped."""
        items = _todays_cve_items()
        described = [(i, s) for i, s in items if isinstance(i.get("description"), str) and i["description"].strip()]
        assert len(described) > 50
        assert {s for _i, s in described} >= {"nvd", "cisa_kev", "cisa_ics"}
        longer = 0
        for item, source_id in described:
            assert strip_markup(item["description"]) == item["description"], item["cve_id"]
            expected, truncated, _ = cap_text(item["description"], CVE_DESCRIPTION_CAP)
            assert truncated == (len(item["description"]) > CVE_DESCRIPTION_CAP), item["cve_id"]
            longer += truncated
            row = nc._prepare_cve_write(copy.deepcopy(item), source_id)
            assert row["node"]["description"] == expected, item["cve_id"]
            assert json.loads(row["edge"]["raw_data"])["description"] == expected, item["cve_id"]
        assert 0 < longer < len(described)

    def test_the_raw_data_copy_keeps_every_other_field(self):
        item = _synced_cve("CVE-2026-69245")
        row = nc._prepare_cve_write(copy.deepcopy(item), "nvd")
        raw = json.loads(row["edge"]["raw_data"])
        expected = {k: v for k, v in item.items() if k != "cve_id"}
        expected["description"] = _capped_cve("CVE-2026-69245")
        assert raw == json.loads(json.dumps(expected, default=str))

    def test_the_rankings_caps(self):
        assert (CVE_DESCRIPTIONS.cap, ENTITY_DESCRIPTIONS.cap) == (1000, 500)
        # Only an entity text is read as a copy an older writer cut inside ATT&CK's markup (``text_caps`` 1a).
        assert (CVE_DESCRIPTIONS.older_cut, ENTITY_DESCRIPTIONS.older_cut) == (False, True)
        assert ENTITY_DESCRIPTIONS.record("Uses [PowerSp...", "mitre_attck").text == "Uses PowerSp"
        assert ENTITY_DESCRIPTIONS.capped("Uses [PowerSp...") == "Uses PowerSp"
        assert CVE_DESCRIPTIONS.record("walks rb_threads[c...", "nvd").text == "walks rb_threads[c..."
        assert CVE_DESCRIPTIONS.capped("walks rb_threads[c...") == "walks rb_threads[c..."
        assert CVE_DESCRIPTIONS.capped(None) is None and ENTITY_DESCRIPTIONS.capped(5) == 5


# ---------------------------------------------------------------------------------------------- ATT&CK ids
class TestAttackIdsAfterTheCap:
    """The cap strips the link to the object itself that ATT&CK's description opens with, in ``raw_data`` too. The
    readers of the ATT&CK id take it from the node's ``mitre_id``, else the record's, before that link, so the
    twin merge and the canonical threat-actor reference keep every id on a graph this sync builds. End to end:
    from the record the writer stores to each reader's answer."""

    def test_the_written_record_has_the_id_and_no_link(self):
        assert _attack_text("S0154").startswith("[Cobalt Strike](https://attack.mitre.org/software/S0154)")
        node, raw = written_attack_record("malware")
        record = json.loads(raw)
        assert "](" not in record["description"] and record["description"].startswith("Cobalt Strike is")
        assert (node["mitre_id"], record["mitre_id"]) == ("S0154", "S0154")
        node, raw = written_attack_record("actor")
        record = json.loads(raw)
        assert "attack.mitre.org" not in record["description"] and "attack.mitre.org" not in node["ranked_description"]
        assert (node["mitre_id"], record["mitre_id"]) == ("G0007", "G0007")

    def test_attack_software_id_reads_the_ids(self):
        node, raw = written_attack_record("malware")
        assert attack_software_id(raw, "cobalt strike") == "S0154"
        assert attack_software_id(without_mitre_id(raw), "cobalt strike", node["mitre_id"]) == "S0154"
        # Not vacuous: the stripped description gives no id.
        assert attack_software_id(without_mitre_id(raw), "cobalt strike") is None
        assert attack_software_id(None, None, " s0154 ") == "S0154"
        assert attack_software_id(json.dumps({"mitre_id": "T1059"}), None, "G0007") is None

    @staticmethod
    def _twin_client(attack_rows):
        def run(query, **_kwargs):
            if "d.name =~ $suffixed" in query:
                # Its base name is no node's: only the id leads to the MITRE node.
                return iter([{"name": "cobaltstrike", "aliases": ["CobaltStrike - S0154"]}])
            if "AS attack_raw" in query:
                assert "c.mitre_id AS attack_id" in query
                return iter(attack_rows)
            if "b.name IN $bases" in query:
                return iter([])
            raise AssertionError(f"unexpected query: {query[:120]!r}")

        session = MagicMock()
        session.run = run
        session.__enter__ = lambda s: s
        session.__exit__ = lambda *a: False
        client = MagicMock()
        client.driver.session.return_value = session
        return client

    @pytest.mark.parametrize("read", ["node", "record", "neither"])
    def test_the_twin_merge_finds_the_mitre_node_by_its_id(self, monkeypatch, read):
        node, raw = written_attack_record("malware")
        attack_id, record = {
            "node": (node["mitre_id"], without_mitre_id(raw)),
            "record": (None, raw),
            "neither": (None, without_mitre_id(raw)),
        }[read]
        monkeypatch.setenv(enrichment_jobs._MALWARE_TWIN_MERGE_ENV_FLAG, "false")  # a dry run: the plan only
        result = enrichment_jobs.merge_malware_attack_twins(
            self._twin_client([{"name": node["name"], "attack_id": attack_id, "attack_raw": record}])
        )
        assert result["candidates"] == 1
        # "neither" is a record written before the sync carried the id: the stripped description gives none.
        assert result["no_target"] == (1 if read == "neither" else 0)

    @staticmethod
    def _reference_builder():
        path = TESTS.parent / "scripts" / "build_canonical_threat_actors.py"
        spec = importlib.util.spec_from_file_location("build_canonical_threat_actors_sync_text_caps", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = module  # dataclasses resolve their annotations through sys.modules
        spec.loader.exec_module(module)
        return module

    def test_the_actor_reference_export_keeps_the_group_id(self):
        builder = self._reference_builder()
        assert "a.mitre_id END AS attack_mitre_id" in builder._EXPORT_CYPHER
        node, raw = written_attack_record("actor")
        row = {
            "name": node["name"],
            "aliases": None,
            "source": ["mitre_attck"],
            "attack_raw": raw,
            "attack_mitre_id": node["mitre_id"],
            "attack_description": node["ranked_description"][:300],
        }
        assert builder.export_rows([row])[0]["attack_id"] == "G0007"
        assert builder.export_rows([dict(row, attack_raw=without_mitre_id(raw))])[0]["attack_id"] == "G0007"
        assert builder.export_rows([dict(row, attack_mitre_id=None)])[0]["attack_id"] == "G0007"
        # Not vacuous: neither the stripped delivered description nor the node's gives the id.
        assert (
            builder.export_rows([dict(row, attack_mitre_id=None, attack_raw=without_mitre_id(raw))])[0]["attack_id"]
            is None
        )
        assert builder.export_rows([dict(row, attack_mitre_id="APT28")])[0]["attack_id"] == "G0007"


DOCS = TESTS.parent / "docs"
# The docs that describe the capped texts or the ATT&CK id reading of the twin merge.
CHANGED_DOCS = (
    "ARCHITECTURE.md",
    "BASELINE_LAUNCH_CHECKLIST.md",
    "COLLECTORS.md",
    "KNOWLEDGE_GRAPH.md",
    "RESILMESH_INTEROPERABILITY.md",
    "RUNBOOK.md",
    "TECHNICAL_SPEC.md",
)


class TestDocs:
    def test_the_checklist_reads_a_mitre_nodes_id_as_the_twin_merge_does(self):
        """The acceptance row names the order ``attack_software_id`` reads: the node's ``mitre_id``, the delivered
        record's ``mitre_id``, then the link an older record's description opens with."""
        main, history = (DOCS / "BASELINE_LAUNCH_CHECKLIST.md").read_text().split("\n## History", 1)
        assert any(
            line.startswith("- 2026-11-07 — Malware twins:") and "`mitre_id`" in line for line in history.splitlines()
        )
        rows = [
            line for line in main.splitlines() if line.startswith("| Malware twins (`malware_attack_twins_folded`)")
        ]
        assert len(rows) == 1
        row = rows[0]
        assert "(read from the record MITRE delivered)" not in row
        order = [
            row.find("its `mitre_id`"),
            row.find("else the `mitre_id` of the record MITRE delivered"),
            row.find("else the link an older record's description opens with"),
        ]
        assert -1 not in order and order == sorted(order)

    @pytest.mark.parametrize("name", CHANGED_DOCS)
    def test_history_bullets_follow_each_other_without_blank_lines(self, name):
        """The History section holds this change's bullet; every bullet opens with its date (a day, or a month for
        a few older ones), newest first; ``_Last updated`` is the newest bullet's day; no blank line between bullets.

        No date is pinned to the top: a later change adds a newer bullet above it."""
        text = (DOCS / name).read_text()
        lines = text.split("\n## History", 1)[1].splitlines()
        bullets = [i for i, line in enumerate(lines) if line.startswith("- ")]
        assert len(bullets) > 1
        assert any(lines[i].startswith("- 2026-11-07 — ") for i in bullets)
        dated = [re.match(r"- (\d{4}-\d{2}(?:-\d{2})?) — ", lines[i]) for i in bullets]
        undated = [lines[i][:60] for i, m in zip(bullets, dated, strict=True) if m is None]
        assert undated == [], f"{name}: History bullet without a leading date: {undated}"
        dates = [m.group(1) for m in dated if m is not None]
        assert dates == sorted(dates, reverse=True), f"{name}: History is not newest first"
        last = re.search(r"_Last updated: (\d{4}-\d{2}-\d{2})_", text)
        assert last is not None and last.group(1) == dates[0], f"{name}: _Last updated is not the newest History date"
        blank = [lines[i - 1] for i in range(bullets[0], bullets[-1] + 1) if not lines[i].strip()]
        assert blank == [], f"{name}: blank line after {blank[0][:60]!r}"
