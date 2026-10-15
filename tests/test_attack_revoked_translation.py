"""Revoked ATT&CK technique ids are translated to their successor wherever a feed names a technique (2026-10).

The MITRE collector no longer creates nodes for revoked techniques, but the feeds keep citing their
ids: on the hosted graph of 2026-10-15, 24,440 links into revoked techniques came from OTX pulse
ids (``USES_TECHNIQUE`` 22,278, ``IMPLEMENTS_TECHNIQUE`` 1,772, ``EMPLOYS_TECHNIQUE`` 390). Every
site that matches a Technique by an id a feed names translates the id first, with the committed
map (``src/reference/attack_revoked_ids.json``, read through ``attack_revoked``):

* ``build_relationships`` — 12 of its 13 ``Technique {mitre_id: …}`` matches (6 link steps and their
  6 orphan counts), through the ``$revoked`` Cypher map parameter. The 13th, step 1b (sub-technique
  → parent), is never translated: a live sub-technique's parent is never revoked, and a revoked
  parent's successor is not the parent of the revoked sub-techniques under it;
* the MISP→Neo4j sync — technique ids of ``misp-galaxy:mitre-attack-pattern`` tags;
* curated claims — the sync's rows and ``scripts/import_curated_package.py``;
* the STIX export of a technique.

A missing or invalid map logs one warning and translates nothing; no run fails because of it.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_TESTS = Path(__file__).resolve().parent
for _p in (_SRC, _TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from build_rel_queries import assigned_queries  # noqa: E402

import attack_revoked  # noqa: E402
import build_relationships  # noqa: E402
import stix_exporter  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _curated_claim_rows  # noqa: E402

# Revoked in ATT&CK, with the successor the committed map names.
REVOKED = {"T1086": "T1059.001", "T1562.001": "T1685", "T1073": "T1574.001"}


@pytest.fixture
def no_map(monkeypatch, tmp_path):
    """The map file is missing: every site must match the id as given and the run must go on."""
    monkeypatch.setattr(attack_revoked, "MAP_PATH", tmp_path / "attack_revoked_ids.json")
    attack_revoked.reset_cache()
    yield
    attack_revoked.reset_cache()


@pytest.fixture(scope="module")
def importer():
    spec = importlib.util.spec_from_file_location(
        "import_curated_package", _ROOT / "scripts" / "import_curated_package.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_the_committed_map_names_the_successors_used_here():
    revoked = attack_revoked.load_revoked_ids()
    assert revoked.loaded and {t: revoked.techniques[t] for t in REVOKED} == REVOKED


# --------------------------------------------------------------------------- build_relationships
_TECHNIQUE_MATCH = re.compile(r"\((\w+):Technique \{mitre_id: (\w+)\}\)")


def _assigned_names() -> List[str]:
    tree = ast.parse(Path(build_relationships.__file__).read_text())
    names = {
        t.id for node in ast.walk(tree) if isinstance(node, ast.Assign) for t in node.targets if isinstance(t, ast.Name)
    }
    return sorted(n for n in names if n.startswith("_"))


def _technique_sites() -> List[Tuple[str, str, str]]:
    """Every ``(var:Technique {mitre_id: X})`` in the queries ``build_relationships`` assigns:
    ``(assignment, X, query)``."""
    sites = []
    for name in _assigned_names():
        try:
            values = assigned_queries(name)
        except Exception:
            continue  # not a query (constants that do not evaluate on their own)
        for query in values:
            if not isinstance(query, str):
                continue
            for match in _TECHNIQUE_MATCH.finditer(query):
                sites.append((name, match.group(2), query[: match.start()]))
    return sites


class TestBuildRelationships:
    def test_every_technique_match_but_the_parent_step_translates_its_id_first(self):
        sites = _technique_sites()
        assert len(sites) == 13, [(n, v) for n, v, _ in sites]
        translated = [(n, v, b) for n, v, b in sites if n != "_q1b_inner"]
        assert len(translated) == 12
        for name, var, before in translated:
            # toString: a map lookup by a number raises and would fail the whole batch
            assert f"coalesce($revoked[toString({var})], {var}) AS {var}" in before, f"{name}: {var} is not translated"
        ((_n, parent_var, before_parent),) = [(n, v, b) for n, v, b in sites if n == "_q1b_inner"]
        assert parent_var == "parent_id" and "$revoked" not in before_parent, "step 1b must not translate the parent"
        assert sorted(n for n, _v, _b in sites if n.endswith("_skip")) == [
            "_q10_skip",
            "_q5_skip",
            "_q5b_skip",
            "_q6_skip",
            "_q6b_skip",
            "_q8_skip",
        ], "the six orphan counts are among the 12"

    @staticmethod
    def _run_build(monkeypatch) -> List[Tuple[str, Optional[Dict[str, Any]]]]:
        calls: List[Tuple[str, Optional[Dict[str, Any]]]] = []
        apoc_row = {
            "count": 0,
            "batches": 1,
            "errorMessages": {},
            "failedBatches": 0,
            "failedOperations": 0,
            "wasTerminated": False,
            "batch": {"errors": {}},
            "operations": {"errors": {}},
            "updateStatistics": {},
        }

        class _Client:
            def connect(self):
                return True

            def close(self):
                pass

            def run(self, query, parameters=None):
                calls.append((query, parameters))
                if "apoc.periodic.iterate" in query:
                    return [dict(apoc_row)]
                return [{"c": 0, "count": 0}]

        monkeypatch.setattr(build_relationships, "Neo4jClient", _Client)
        monkeypatch.setattr(build_relationships, "query_pause", lambda: None)
        assert build_relationships.build_relationships() is True
        return calls

    def test_the_map_reaches_every_technique_step_and_its_orphan_count(self, monkeypatch):
        calls = self._run_build(monkeypatch)
        expected = {"revoked": attack_revoked.technique_successors()}
        assert expected["revoked"]["T1086"] == "T1059.001"
        iterate = [(q, p) for q, p in calls if "apoc.periodic.iterate" in q]
        technique_steps = [(q, p) for q, p in iterate if ":Technique {mitre_id:" in q]
        assert len(technique_steps) == 7
        parent_step = [(q, p) for q, p in technique_steps if "SUBTECHNIQUE_OF" in q]
        assert len(parent_step) == 1 and parent_step[0][1] is None, "step 1b takes no map"
        assert all(p == {"iterate_params": expected} for q, p in technique_steps if "SUBTECHNIQUE_OF" not in q)
        assert all(p is None for q, p in iterate if ":Technique {mitre_id:" not in q), "other steps take no map"
        counts = [(q, p) for q, p in calls if "apoc.periodic.iterate" not in q and "$revoked" in q]
        assert len(counts) == 6 and all(p == expected for _q, p in counts)

    def test_a_missing_map_translates_nothing_and_the_build_goes_on(self, monkeypatch, no_map, caplog):
        with caplog.at_level(logging.WARNING, logger="attack_revoked"):
            calls = self._run_build(monkeypatch)
        technique_steps = [
            p
            for q, p in calls
            if "apoc.periodic.iterate" in q and ":Technique {mitre_id:" in q and "SUBTECHNIQUE_OF" not in q
        ]
        assert len(technique_steps) == 6 and all(p == {"iterate_params": {"revoked": {}}} for p in technique_steps)
        assert sum(1 for r in caplog.records if "not translated" in r.getMessage()) == 1


# --------------------------------------------------------------------------- the sync: MISP tags
def _syncer() -> MISPToNeo4jSync:
    s = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    s.neo4j = MagicMock()
    s.stats = {"errors": 0}
    return s


def _actor_attribute(*technique_tags: str) -> Dict[str, Any]:
    return {
        "type": "threat-actor",
        "value": "apt29",
        "comment": "",
        "uuid": "11111111-2222-4333-8444-555555555555",
        "Tag": [{"name": "source:AlienVault-OTX"}, {"name": "tlp:white"}]
        + [{"name": f'misp-galaxy:mitre-attack-pattern="{t}"'} for t in technique_tags],
    }


_EVENT = {"id": "41", "info": "EdgeGuard-alienvault_otx-2026-10-15", "Tag": []}
_TAGS = ("PowerShell - T1086", "PowerShell - T1059.001", "Phishing - T1566")


def _employs(rels):
    return [r["to_key"]["mitre_id"] for r in rels if r["rel_type"] == "EMPLOYS_TECHNIQUE"]


class TestSyncTagRows:
    def test_a_revoked_tag_id_becomes_its_successor(self):
        _item, rels = _syncer().parse_attribute(_actor_attribute(*_TAGS), _EVENT)
        assert _employs(rels) == ["T1059.001", "T1566"], "T1086 -> T1059.001, which the tags also name: one row"

    def test_the_translated_row_reaches_the_writer(self):
        _item, rels = _syncer().parse_attribute(_actor_attribute("PowerShell - T1086"), _EVENT)
        client = Neo4jClient.__new__(Neo4jClient)
        client.driver = MagicMock()
        client._connection_healthy = True
        sent: List[Dict[str, Any]] = []
        session = MagicMock()
        session.run.side_effect = lambda query, **kw: sent.extend(kw.get("rows") or []) or MagicMock()
        client.driver.session.return_value.__enter__.return_value = session
        client.create_misp_relationships_batch(rels, source_id="alienvault_otx")
        assert [r["mitre_id"] for r in sent if "mitre_id" in r] == ["T1059.001"]

    def test_a_missing_map_keeps_the_id(self, no_map):
        _item, rels = _syncer().parse_attribute(_actor_attribute(*_TAGS), _EVENT)
        assert _employs(rels) == ["T1086", "T1059.001", "T1566"]


# --------------------------------------------------------------------------- curated claims
class TestCuratedClaims:
    def test_the_sync_links_a_revoked_technique_claim_to_the_successor(self, caplog):
        claims = [
            {"p": "uses_technique", "o": "t1086", "id": "c1"},
            {"p": "uses_technique", "o": "T1566", "id": "c2"},
            {"p": "uses_tool", "o": "S9000", "id": "c3"},  # software ids are not translated
        ]
        with caplog.at_level(logging.INFO):
            rows = _curated_claim_rows(claims, "ThreatActor", {"name": "apt29"}, "coreideas", "5")
        assert [r["to_key"] for r in rows] == [{"mitre_id": "T1059.001"}, {"mitre_id": "T1566"}, {"mitre_id": "S9000"}]
        assert rows[0]["source_refs"] == ["coreideas:c1"], "the claim's own record id is kept"
        assert any("T1086 -> T1059.001" in r.getMessage() for r in caplog.records)
        malware = _curated_claim_rows(
            [{"p": "implements_technique", "o": "T1562.001"}], "Malware", {"name": "lockbit"}, "coreideas", "5"
        )
        assert [r["to_key"] for r in malware] == [{"mitre_id": "T1685"}]

    def test_a_missing_map_keeps_the_claim_id(self, no_map):
        rows = _curated_claim_rows(
            [{"p": "uses_technique", "o": "T1086"}], "ThreatActor", {"name": "apt29"}, "coreideas", "5"
        )
        assert [r["to_key"] for r in rows] == [{"mitre_id": "T1086"}]

    @staticmethod
    def _package(*objects):
        return {
            "name": "2026-10-20_EdgeGuard_CoreIdeas_package",
            "source": "coreideas",
            "tlp": "amber",
            "entities": [
                {
                    "kind": "threat_actor",
                    "name": "apt29",
                    "claims": [{"p": "uses_technique", "o": o, "id": f"c{n}"} for n, o in enumerate(objects)],
                }
            ],
        }

    def test_the_importer_accepts_and_reports_a_revoked_id(self, importer):
        package = self._package("T1086", "t1086", "T1566")
        errors, warnings, summary = importer.validate(package)
        assert errors == [] and (summary["claims"], summary["claims_skipped"]) == (3, 0)
        assert summary["revoked_technique_ids"] == {"T1086": {"successor": "T1059.001", "claims": 2}}
        assert any("T1086" in w and "T1059.001" in w for w in warnings), warnings
        (attr,) = importer.build_event(package)["Event"]["Attribute"]
        assert "T1086" in attr["comment"], "imported as written; the sync translates"

    def test_check_graph_looks_up_the_successor(self, importer):
        graph = {"ThreatActor": {"apt29"}, "Technique": {"T1059.001", "T1566"}}

        def run_query(cypher, rows):
            return [
                {
                    "i": r["i"],
                    "subject_found": r["s"] in graph["ThreatActor"],
                    "object_found": r["o"] in graph["Technique"],
                }
                for r in rows
            ]

        report = importer.check_graph(self._package("T1086", "T1566"), run_query)
        assert (report["claims"], report["attach"]) == (2, 2)

    def test_the_importer_reports_nothing_without_the_map(self, importer, no_map):
        errors, warnings, summary = importer.validate(self._package("T1086"))
        assert errors == [] and summary["claims"] == 1 and summary["revoked_technique_ids"] == {}


# --------------------------------------------------------------------------- STIX export
class TestStixExport:
    @staticmethod
    def _export(mitre_id: str) -> List[Dict[str, Any]]:
        exporter = stix_exporter.StixExporter(MagicMock())
        seen: List[Dict[str, Any]] = []

        def run(cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
            seen.append(params)
            return []

        exporter._run = run  # type: ignore[method-assign]
        bundle = exporter.export_technique(mitre_id)
        assert bundle["type"] == "bundle"
        return seen

    def test_a_revoked_id_is_answered_with_the_successor(self):
        assert [p["mid"] for p in self._export("T1086")] == ["T1059.001"]
        assert [p["mid"] for p in self._export("T1562.001")] == ["T1685"]
        assert [p["mid"] for p in self._export("T1059.001")] == ["T1059.001"], "a current id is unchanged"

    def test_a_missing_map_keeps_the_id(self, no_map):
        assert [p["mid"] for p in self._export("T1086")] == ["T1086"]


def test_all_sites_load_the_map_once(monkeypatch):
    """One read per process: the sites share ``attack_revoked``'s cache."""
    attack_revoked.reset_cache()
    reads = []
    original = Path.read_text

    def counting(self, *a, **k):
        if self.name == "attack_revoked_ids.json":
            reads.append(str(self))
        return original(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", counting)
    _syncer().parse_attribute(_actor_attribute(*_TAGS), _EVENT)
    _curated_claim_rows([{"p": "uses_technique", "o": "T1086"}], "ThreatActor", {"name": "apt29"}, "coreideas", "5")
    TestStixExport._export("T1086")
    assert reads == [str(attack_revoked.MAP_PATH)]
    json.loads(original(attack_revoked.MAP_PATH))  # the file itself is readable JSON


# --------------------------------------------------------------------------- revoked technique nodes stay out
def _technique_attribute(value: str) -> Dict[str, Any]:
    return {
        "type": "text",
        "value": value,
        "comment": "",
        "uuid": "11111111-2222-4333-8444-666666666666",
        "Tag": [{"name": "source:MITRE"}, {"name": "tlp:white"}],
    }


class TestRevokedTechniqueNodesAreNotRebuilt:
    """An attribute written before the collector skipped revoked techniques must not bring the node
    back: the sync and the two readers of the legacy CLI path skip a technique id the map lists."""

    def test_the_sync_skips_a_revoked_technique_attribute(self):
        item, rels = _syncer().parse_attribute(_technique_attribute("T1086: PowerShell"), _EVENT)
        assert item is None and rels == []
        item, _rels = _syncer().parse_attribute(_technique_attribute("T1059.001: PowerShell"), _EVENT)
        assert item is not None and item["mitre_id"] == "T1059.001"

    def test_without_the_map_the_sync_keeps_it(self, no_map):
        item, _rels = _syncer().parse_attribute(_technique_attribute("T1086: PowerShell"), _EVENT)
        assert item is not None and item["mitre_id"] == "T1086"

    def test_the_cli_stix_import_skips_the_node_and_links_the_successor(self):
        from run_pipeline import EdgeGuardPipeline

        pipeline = EdgeGuardPipeline.__new__(EdgeGuardPipeline)
        pipeline.neo4j = MagicMock()

        def pattern(stix_id, mitre_id, name):
            return {
                "type": "attack-pattern",
                "id": stix_id,
                "name": name,
                "external_references": [{"source_name": "mitre-attack", "external_id": mitre_id}],
            }

        bundle = {
            "objects": [
                pattern("attack-pattern--old", "T1086", "PowerShell"),
                pattern("attack-pattern--new", "T1059.001", "PowerShell"),
                {
                    "type": "threat-actor",
                    "id": "threat-actor--a",
                    "name": "APT29",
                },  # the import reads threat-actor SDOs
                {
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "threat-actor--a",
                    "target_ref": "attack-pattern--old",
                },
            ]
        }
        stats = pipeline.load_stix21_to_neo4j(bundle)
        merged = [c.args[0]["mitre_id"] for c in pipeline.neo4j.merge_technique.call_args_list]
        assert merged == ["T1059.001"] and stats["revoked_techniques_skipped"] == 1
        pipeline.neo4j.create_actor_technique_relationship.assert_called_once_with("APT29", "T1059.001")

    def test_the_cli_misp_reader_emits_no_revoked_technique(self):
        from collectors.misp_collector import MISPCollector

        collector = MISPCollector.__new__(MISPCollector)
        collector.url, collector.tag = "https://misp.local", "misp"
        event = {
            "id": "7",
            "info": "event",
            "Tag": [
                {"name": 'misp-galaxy:mitre-attack-pattern="PowerShell - T1086"'},
                {"name": 'misp-galaxy:mitre-attack-pattern="PowerShell - T1059.001"'},
            ],
            "Attribute": [],
            "Object": [
                {"name": "attack-pattern", "Attribute": [{"object_relation": "id", "value": "T1562.001"}]},
                {"name": "attack-pattern", "Attribute": [{"object_relation": "id", "value": "T1566"}]},
            ],
        }
        index, full = MagicMock(status_code=200), MagicMock(status_code=200)
        index.json.return_value = [{"id": "7"}]
        full.json.return_value = {"Event": event}
        collector.session = MagicMock()
        collector.session.get.side_effect = [index, full]
        processed, _active = collector.collect(limit=1)
        techniques = sorted(i["mitre_id"] for i in processed if i.get("node_type") == "technique")
        assert techniques == ["T1059.001", "T1566"]
