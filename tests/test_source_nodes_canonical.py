"""One ``Source`` node per registered source, keyed by its canonical id (2026-10-25).

Until 2026-10-25 ``source_registry.to_neo4j_sources_dict`` had one entry per alias, so
``ensure_sources`` created a ``Source`` node for every alias as well (``otx`` beside
``alienvault_otx``, ``cisa`` beside ``cisa_kev``, ``vt`` beside ``virustotal``, ...): 26 nodes on the
730-day baseline of 2026-10-22, 10 of them holding data, and none of the alias nodes holding a
``SOURCED_FROM`` edge. Now ``SOURCES`` holds the canonical ids only, and every writer that matches a
``Source`` node (``_upsert_sourced_relationship``, ``merge_indicators_batch``,
``merge_vulnerabilities_batch``, ``link_to_source``) resolves the id it is given with
``canonical_source_id`` first, so an alias still writes its edge, to the canonical node. These tests
drive each writer with an alias and read the statement parameters it sends.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import neo4j_client as nc  # noqa: E402
import source_registry  # noqa: E402
from node_identity import compute_node_uuid  # noqa: E402

CANONICAL_IDS = {s.canonical_id for s in source_registry.all_sources()}
ALIASES = {alias: s.canonical_id for s in source_registry.all_sources() for alias in s.aliases}


class _Result:
    """A write result whose counters the batch writers inspect."""

    def __init__(self):
        self._counters = SimpleNamespace(nodes_created=1, properties_set=1, relationships_created=1)

    def consume(self):
        return SimpleNamespace(counters=self._counters)

    def single(self):
        return None


class _Session:
    def __init__(self, runs):
        self.runs = runs

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.runs.append((query, params))
        return _Result()


class _Driver:
    def __init__(self):
        self.runs: list = []

    def session(self, **kwargs):
        return _Session(self.runs)


def _client():
    """A real ``Neo4jClient`` built without a connection; the driver records each statement."""
    client = nc.Neo4jClient("bolt://edgeguard-test.invalid:7687", "neo4j", "unused")
    client.driver = _Driver()
    client._connection_healthy = True
    return client


def _source_uuid(source_id: str) -> str:
    return compute_node_uuid("Source", {"source_id": source_id})


class TestRegistry:
    def test_sources_holds_the_canonical_ids_only(self):
        assert set(nc.SOURCES) == CANONICAL_IDS
        assert not set(nc.SOURCES) & set(ALIASES), "an alias must not be a Source node"

    def test_every_alias_resolves_to_a_source_node(self):
        assert ALIASES, "the registry has aliases"
        for alias, canonical in ALIASES.items():
            assert source_registry.canonical_source_id(alias) == canonical
            assert canonical in nc.SOURCES

    def test_sources_keeps_each_sources_name_type_and_reliability(self):
        for src in source_registry.all_sources():
            assert nc.SOURCES[src.canonical_id] == {
                "name": src.display_name,
                "type": src.source_type,
                "reliability": src.reliability,
            }

    def test_ensure_sources_creates_one_node_per_canonical_id(self):
        client = _client()
        assert client.ensure_sources() is True
        merged = [p["source_id"] for q, p in client.driver.runs if "MERGE (s:Source" in q]
        assert sorted(merged) == sorted(CANONICAL_IDS)
        uuids = {p["source_id"]: p["source_uuid"] for q, p in client.driver.runs if "MERGE (s:Source" in q}
        assert all(uuids[sid] == _source_uuid(sid) for sid in CANONICAL_IDS)


class TestWritersResolveAliases:
    """Each writer that MATCHes a ``Source`` node, driven with an alias."""

    def test_merge_indicators_batch(self):
        client = _client()
        items = [
            {"indicator_type": "ipv4", "value": "203.0.113.7", "tag": "otx", "zone": ["global"]},
            {"indicator_type": "ipv4", "value": "203.0.113.8", "tag": "otx", "zone": ["global"], "source_id": "otx"},
        ]
        assert client.merge_indicators_batch(items, source_id="otx") == (2, 0)
        ((query, params),) = [r for r in client.driver.runs if "UNWIND $batch as item" in r[0]]
        assert "MATCH (s:Source {source_id: item.source_id})" in query
        assert {row["source_id"] for row in params["batch"]} == {"alienvault_otx"}
        assert params["source_node_uuid"] == _source_uuid("alienvault_otx")

    def test_merge_indicators_batch_logs_no_mismatch_for_an_alias_of_the_batch_source(self, caplog):
        client = _client()
        items = [{"indicator_type": "ipv4", "value": "203.0.113.9", "zone": ["global"], "source_id": "otx"}]
        with caplog.at_level("WARNING", logger=nc.logger.name):
            assert client.merge_indicators_batch(items, source_id="alienvault_otx") == (1, 0)
        assert "differs from batch source_id" not in caplog.text

    def test_merge_indicators_batch_still_refuses_an_unregistered_source(self):
        client = _client()
        items = [{"indicator_type": "ipv4", "value": "203.0.113.10", "zone": ["global"]}]
        assert client.merge_indicators_batch(items, source_id="not_a_registered_source") == (0, 1)
        assert not [r for r in client.driver.runs if "UNWIND $batch as item" in r[0]]

    def test_merge_vulnerabilities_batch(self):
        client = _client()
        items = [{"type": "vulnerability", "cve_id": "CVE-2026-1000", "tag": "cisa", "zone": ["global"]}]
        success, errors = client.merge_vulnerabilities_batch(items, source_id="cisa")
        assert (success, errors) == (1, 0)
        ((query, params),) = [r for r in client.driver.runs if "UNWIND $batch as item" in r[0]]
        assert "MATCH (s:Source {source_id: item.source_id})" in query
        assert {row["source_id"] for row in params["batch"]} == {"cisa_kev"}
        assert params["source_node_uuid"] == _source_uuid("cisa_kev")

    def test_single_item_write_through_upsert_sourced_relationship(self):
        client = _client()
        assert client._upsert_sourced_relationship(
            "Indicator", {"indicator_type": "ipv4", "value": "203.0.113.11"}, "feodo", "{}", 0.7
        )
        ((query, params),) = [r for r in client.driver.runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in r[0]]
        assert "MATCH (s:Source {source_id: $source_id})" in query
        assert params["source_id"] == "feodo_tracker"
        assert params["trg_uuid"] == _source_uuid("feodo_tracker")

    def test_merge_indicator_reaches_the_canonical_node(self):
        """The single-item path end to end: ``merge_indicator`` → ``merge_node_with_source`` →
        ``_upsert_sourced_relationship``."""
        client = _client()
        assert client.merge_indicator(
            {"indicator_type": "domain", "value": "example.test", "zone": ["global"], "tag": "sslbl"},
            source_id="sslbl",
        )
        upserts = [p for q, p in client.driver.runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]
        assert [p["source_id"] for p in upserts] == ["ssl_blacklist"]

    def test_single_item_node_provenance_names_the_canonical_source(self):
        """The node's own provenance (``n.source`` default, ``n.last_imported_from``, the report
        source) names the ``Source`` node its edge reaches, as the batch writer's does."""
        record = {"indicator_type": "domain", "value": "example.test", "zone": ["global"], "tag": "sslbl"}
        single = _client()
        assert single.merge_indicator(dict(record), source_id="sslbl")
        ((query, params),) = [r for r in single.driver.runs if "MERGE (n:Indicator" in r[0]]
        assert "n.last_imported_from = $source_id" in query
        assert params["source_id"] == "ssl_blacklist"
        assert params["source_array"] == ["ssl_blacklist"]

        batch = _client()
        assert batch.merge_indicators_batch([dict(record)], source_id="sslbl") == (1, 0)
        ((_, batch_params),) = [r for r in batch.driver.runs if "UNWIND $batch as item" in r[0]]
        (row,) = batch_params["batch"]
        assert (row["source_id"], row["source_array"]) == (params["source_id"], params["source_array"])

    def test_link_to_source(self):
        client = _client()
        assert client.link_to_source("Indicator", {"value": "203.0.113.12"}, "vt") is True
        ((query, params),) = [r for r in client.driver.runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in r[0]]
        assert params["source_id"] == "virustotal"

    @pytest.mark.parametrize("canonical", sorted(CANONICAL_IDS))
    def test_a_canonical_id_is_passed_unchanged(self, canonical):
        client = _client()
        assert client.link_to_source("Indicator", {"value": "203.0.113.13"}, canonical) is True
        ((_, params),) = [r for r in client.driver.runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in r[0]]
        assert params["source_id"] == canonical


def _statement_strings(path: Path):
    """``(line, text)`` of every string constant in *path* except docstrings: the Cypher statements,
    f-string parts included."""
    import ast

    tree = ast.parse(path.read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            yield node.lineno, node.value


class TestStixImport:
    """2026-10-25: the objects of an external STIX bundle that name no EdgeGuard source are attributed
    to ``stix_import``, now a registered source: ``ensure_sources`` creates its node, so the loader's
    records get their ``SOURCED_FROM`` edge (until then the edge's MATCH found no node)."""

    def test_stix_import_is_a_registered_source_with_a_node(self):
        from run_pipeline import STIX_IMPORT_SOURCE_ID

        src = source_registry.get_source(STIX_IMPORT_SOURCE_ID)
        assert src is not None and src.canonical_id == STIX_IMPORT_SOURCE_ID == "stix_import"
        assert src.source_type == "import" and src.cli_id is None and src.reliable_first_seen is False
        client = _client()
        assert client.ensure_sources() is True
        merged = {p["source_id"]: p["source_uuid"] for q, p in client.driver.runs if "MERGE (s:Source" in q}
        assert merged["stix_import"] == _source_uuid("stix_import")

    def test_the_loader_writes_an_external_bundles_records_to_the_stix_import_node(self):
        """End to end: ``EdgeGuardPipeline.load_stix21_to_neo4j`` with a real ``Neo4jClient`` whose
        driver records each statement."""
        from run_pipeline import EdgeGuardPipeline

        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = _client()
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '203.0.113.21']"},
                {"type": "malware", "id": "malware--1", "name": "ExampleRAT"},
            ],
        }
        pipeline.load_stix21_to_neo4j(bundle)
        upserts = [p for q, p in pipeline.neo4j.driver.runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in q]
        assert len(upserts) == 2, "one SOURCED_FROM edge per imported object"
        assert {p["source_id"] for p in upserts} == {"stix_import"}
        assert {p["trg_uuid"] for p in upserts} == {_source_uuid("stix_import")}
        assert "stix_import" in nc.SOURCES, "ensure_sources creates the node the edges MATCH"


class TestNodeSourceListsAreCanonical:
    """2026-10-25: a node's ``source`` list names canonical ids, whichever writer stores it and
    whatever name its record gives, so REST, GraphQL and the STIX export (``x_edgeguard_sources``)
    show the names of the ``Source`` nodes the node's ``SOURCED_FROM`` edges reach."""

    def test_the_resolution_rule(self):
        assert nc._canonical_source_list(["otx", "alienvault_otx", " OTX ", None, ""]) == ["alienvault_otx"]
        assert nc._canonical_source_list("sslbl") == ["ssl_blacklist"]
        assert nc._canonical_source_list(["cisa", "nvd"]) == ["cisa_kev", "nvd"]
        # As in ``r.sources``: a name the registry does not know is kept, lowercased and stripped.
        assert nc._canonical_source_list([" Partner Feed "]) == ["partner feed"]

    def test_single_item_write_with_an_explicit_source_list(self):
        client = _client()
        assert client.merge_indicator(
            {"indicator_type": "ipv4", "value": "203.0.113.31", "zone": ["global"], "source": ["otx", "OTX"]},
            source_id="otx",
        )
        ((_, params),) = [r for r in client.driver.runs if "MERGE (n:Indicator" in r[0]]
        assert params["source_array"] == ["alienvault_otx"]

    def test_indicator_batch_with_an_explicit_source_list(self):
        client = _client()
        items = [{"indicator_type": "ipv4", "value": "203.0.113.32", "zone": ["global"], "source": ["sslbl"]}]
        assert client.merge_indicators_batch(items, source_id="ssl_blacklist") == (1, 0)
        ((_, params),) = [r for r in client.driver.runs if "UNWIND $batch as item" in r[0]]
        assert [row["source_array"] for row in params["batch"]] == [["ssl_blacklist"]]

    def test_vulnerability_batch_with_an_explicit_source_list(self):
        client = _client()
        items = [{"type": "vulnerability", "cve_id": "CVE-2026-1001", "zone": ["global"], "source": "cisa"}]
        assert client.merge_vulnerabilities_batch(items, source_id="cisa_kev") == (1, 0)
        ((_, params),) = [r for r in client.driver.runs if "UNWIND $batch as item" in r[0]]
        assert [row["source_array"] for row in params["batch"]] == [["cisa_kev"]]

    def test_a_stix_bundle_that_names_a_variant(self):
        """End to end: an object whose ``x_edgeguard_source`` is a variant reaches the canonical
        ``Source`` node and names it in its ``source`` list."""
        from run_pipeline import EdgeGuardPipeline

        pipeline = EdgeGuardPipeline()
        pipeline.neo4j = _client()
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "pattern": "[ipv4-addr:value = '203.0.113.33']",
                    "x_edgeguard_source": "otx",
                }
            ],
        }
        pipeline.load_stix21_to_neo4j(bundle)
        runs = pipeline.neo4j.driver.runs
        ((_, node),) = [r for r in runs if "MERGE (n:Indicator" in r[0]]
        ((_, edge),) = [r for r in runs if "MERGE (n)-[r:SOURCED_FROM]->(s)" in r[0]]
        assert node["source_array"] == ["alienvault_otx"]
        assert (edge["source_id"], edge["trg_uuid"]) == ("alienvault_otx", _source_uuid("alienvault_otx"))


class TestMetricSourceLabels:
    """2026-10-25: the writer metrics carry the canonical id (docs/PROMETHEUS_SETUP.md, "Source label
    values"); the placeholder reject is counted before the merge resolves the name, so it resolves it."""

    @pytest.mark.parametrize("merge,label", [("merge_malware", "Malware"), ("merge_actor", "ThreatActor")])
    def test_a_placeholder_reject_counts_against_the_canonical_source(self, merge, label):
        from prometheus_client import REGISTRY

        def count(source):
            name = "edgeguard_merge_reject_placeholder_total"
            return REGISTRY.get_sample_value(name, {"label": label, "source": source}) or 0.0

        before_canonical, before_variant = count("alienvault_otx"), count("otx")
        client = _client()
        assert getattr(client, merge)({"name": "unknown", "zone": ["global"]}, source_id="otx") is False
        assert count("alienvault_otx") == before_canonical + 1
        assert count("otx") == before_variant


class TestStixFlowEventSource:
    """2026-10-25: the STIX flow names each object's source from its MISP event's name, as a canonical
    id; a name that gives no registered source is attributed to ``misp`` (it was ``"unknown"``, which no
    ``Source`` node carries)."""

    @pytest.mark.parametrize(
        "event_info,expected",
        [
            ("EdgeGuard-alienvault_otx-2026-10-22", "alienvault_otx"),
            ("EdgeGuard-otx-2026-10-22", "alienvault_otx"),
            ("EdgeGuard-nvd-2026-10-22-part2", "nvd"),
            ("EdgeGuard-cisa_ics-2026-10-20", "cisa_ics"),
            ("EdgeGuard-coreideas-2026-10-22", "coreideas"),
        ],
    )
    def test_a_registered_source_in_the_event_name(self, event_info, expected):
        from run_pipeline import _misp_event_source

        assert _misp_event_source(event_info) == expected

    @pytest.mark.parametrize("event_info", ["A partner's report", "", None, "EdgeGuard-notasource-2026-10-22"])
    def test_no_registered_source_falls_back_to_misp(self, event_info, caplog):
        from run_pipeline import _misp_event_source

        with caplog.at_level("WARNING"):
            assert _misp_event_source(event_info) == "misp"
        assert "attributing it to 'misp'" in caplog.text
        assert "misp" in nc.SOURCES

    def test_the_flow_uses_the_helper_and_never_unknown(self):
        text = (_SRC / "run_pipeline.py").read_text()
        assert "source_from_event = _misp_event_source(event_info)" in text
        assert 'source_from_event = "unknown"' not in text


def test_no_writer_creates_a_source_node():
    """Only ``ensure_sources`` creates ``Source`` nodes; every other statement MATCHes them, so an id
    the registry does not know can never become a node."""
    import re

    root = _SRC.parent
    creating = re.compile(r"(MERGE|CREATE)\s*\(\w*:Source\b")
    hits = [
        (f"{path.relative_to(root)}:{line}", text)
        for folder in ("src", "scripts", "dags")
        for path in sorted((root / folder).rglob("*.py"))
        for line, text in _statement_strings(path)
        if creating.search(text)
    ]
    assert len(hits) == 1, [where for where, _ in hits]
    where, text = hits[0]
    assert where.startswith("src/neo4j_client.py:") and "MERGE (s:Source {source_id: $source_id})" in text


def test_the_documented_variant_table_equals_the_registry():
    """``docs/KNOWLEDGE_GRAPH.md`` lists every source with the variants that resolve to it; the table
    must name exactly the registry's canonical ids, in registry order, each with its aliases."""
    import re

    lines = (_SRC.parent / "docs" / "KNOWLEDGE_GRAPH.md").read_text().splitlines()
    start = lines.index("| Source (canonical id) | Variants that resolve to it |") + 2
    rows = []
    for line in lines[start:]:
        if not line.startswith("|"):
            break
        source_cell, variants_cell = [cell.strip() for cell in line.strip("|").split("|")]
        canonical = re.match(r"`([^`]+)`", source_cell).group(1)
        variants = [] if variants_cell == "none" else re.findall(r"`([^`]+)`", variants_cell)
        rows.append((canonical, variants))
    assert rows == [(s.canonical_id, list(s.aliases)) for s in source_registry.all_sources()]
