"""Curated packages (2026-10): claims about existing entities, imported once through MISP.

A package (e.g. ``YYYY-MM-DD_EdgeGuard_CoreIdeas_package``) becomes one MISP event; each
actor / malware attribute names an existing node and carries its claims in a
``CURATED_CLAIMS:`` comment. The sync turns every claim into a relationship labelled with
the package's curated label (``coreideas_curated``, else ``curated_other``) at 0.85, with the
claim's own source in ``r.sources`` and its record id in ``r.source_refs``, MATCHing both
ends — a package never creates nodes and never changes the node it names.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-curated-packages")
os.environ.setdefault("MISP_API_KEY", "test-key-curated-packages")

import source_registry  # noqa: E402
from neo4j_client import Neo4jClient  # noqa: E402
from relationship_provenance import CURATED_CLAIMS_PREFIX, CURATED_PREDICATES  # noqa: E402
from run_misp_to_neo4j import MISPToNeo4jSync, _curated_claim_rows, _parse_curated_claims  # noqa: E402


@pytest.fixture(scope="module")
def importer():
    spec = importlib.util.spec_from_file_location(
        "import_curated_package", _ROOT / "scripts" / "import_curated_package.py"
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _claims_comment(claims, tail=""):
    return CURATED_CLAIMS_PREFIX + json.dumps({"c": claims}) + (("\n" + tail) if tail else "")


# --------------------------------------------------------------------------- labels
class TestLabels:
    def test_registered_curated_source_has_its_own_label(self):
        assert source_registry.curated_label_for("coreideas") == "coreideas_curated"

    @pytest.mark.parametrize("source", ["some_new_package", "misp_galaxy", "nvd", None, ""])
    def test_everything_else_is_curated_other(self, source):
        assert source_registry.curated_label_for(source) == "curated_other"


# --------------------------------------------------------------------------- parsing
class TestClaims:
    def test_parse(self):
        assert _parse_curated_claims("MITRE_USES_TECHNIQUES:{}") is None
        assert _parse_curated_claims("") is None
        assert _parse_curated_claims(CURATED_CLAIMS_PREFIX + "{not json") == []
        claims = [{"p": "uses_technique", "o": "t1566"}]
        assert _parse_curated_claims(_claims_comment(claims, "a description that is ignored")) == claims

    def test_actor_claims_become_rows(self):
        claims = [
            {"p": "uses_technique", "o": "t1566.001", "src": "coreideas", "id": "c1"},
            {"p": "uses_malware", "o": "emotet", "src": "misp_galaxy", "id": "u-1"},
            {"p": "uses_tool", "o": "s0002"},
            {"p": "exploits", "o": "cve-2021-44228", "id": "c3"},
            {"p": "implements_technique", "o": "T1486"},  # malware-only predicate: skipped
            {"p": "uses_technique", "o": ""},  # no object: skipped
        ]
        rows = _curated_claim_rows(claims, "ThreatActor", {"name": "apt29"}, "coreideas", "88")
        assert [(r["rel_type"], r["to_type"], r["to_key"]) for r in rows] == [
            ("EMPLOYS_TECHNIQUE", "Technique", {"mitre_id": "T1566.001"}),
            ("USES_MALWARE", "Malware", {"name": "emotet"}),
            ("USES_TOOL", "Tool", {"mitre_id": "S0002"}),
            ("EXPLOITS", "CVE", {"cve_id": "CVE-2021-44228"}),
        ]
        assert {r["match_type"] for r in rows} == {"coreideas_curated"}, (
            "the package's label, whatever the claim source"
        )
        assert {r["confidence"] for r in rows} == {0.85}
        assert [r["source"] for r in rows] == ["coreideas", "misp_galaxy", "coreideas", "coreideas"]
        assert [r["source_refs"] for r in rows] == [["coreideas:c1"], ["misp_galaxy:u-1"], [], ["coreideas:c3"]]
        assert all(r["from_key"] == {"name": "apt29"} and r["misp_event_id"] == "88" for r in rows)

    def test_malware_claims_become_rows(self):
        claims = [{"p": "implements_technique", "o": "T1486"}, {"p": "exploits", "o": "CVE-2017-11882"}]
        rows = _curated_claim_rows(claims, "Malware", {"name": "lockbit"}, "unregistered_pkg", "9")
        assert [r["rel_type"] for r in rows] == ["IMPLEMENTS_TECHNIQUE", "EXPLOITS"]
        assert {r["match_type"] for r in rows} == {"curated_other"}

    def test_predicates_cover_only_types_the_writer_handles(self):
        rel_types = {target[0] for by_subject in CURATED_PREDICATES.values() for target in by_subject.values()}
        assert rel_types == {"EMPLOYS_TECHNIQUE", "IMPLEMENTS_TECHNIQUE", "USES_MALWARE", "USES_TOOL", "EXPLOITS"}


# --------------------------------------------------------------------------- parse_attribute
def _syncer():
    s = MISPToNeo4jSync.__new__(MISPToNeo4jSync)
    s.neo4j = MagicMock()
    s.stats = {"errors": 0}
    return s


def _attr(attr_type, value, comment):
    return {
        "type": attr_type,
        "value": value,
        "comment": comment,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "Tag": [{"name": "source:CoreIdeas"}, {"name": "tlp:amber"}, {"name": "sector:energy"}],
    }


class TestParseAttribute:
    EVENT = {"id": "321", "info": "2026-10-20_EdgeGuard_CoreIdeas_package", "Tag": [{"name": "EdgeGuard"}]}

    def test_curated_actor_names_the_node_and_changes_nothing_on_it(self):
        comment = _claims_comment([{"p": "uses_technique", "o": "T1566", "src": "misp_galaxy", "id": "g1"}], "prose")
        item, rels = _syncer().parse_attribute(_attr("threat-actor", "apt29", comment), self.EVENT)
        assert item["tag"] == "coreideas"
        assert item["description"] == "" and item["zone"] == [] and item["tlp"] == ""
        assert item["uses_techniques"] == [] and item["reported_techniques"] == []
        curated = [r for r in rels if r.get("match_type") == "coreideas_curated"]
        assert len(curated) == 1
        assert curated[0]["source"] == "misp_galaxy", "the claim's own source survives _with_provenance"
        assert curated[0]["source_refs"] == ["misp_galaxy:g1"]

    def test_curated_malware_adds_no_types(self):
        comment = _claims_comment([{"p": "implements_technique", "o": "T1486"}])
        item, rels = _syncer().parse_attribute(_attr("malware-type", "lockbit", comment), self.EVENT)
        assert item["malware_types"] == [] and item["description"] == "" and item["zone"] == [] and item["tlp"] == ""
        assert [r["rel_type"] for r in rels if r.get("match_type") == "coreideas_curated"] == ["IMPLEMENTS_TECHNIQUE"]

    def test_curated_items_are_never_merged_as_nodes(self):
        """MERGE would create a node the graph lacks; a package only names existing nodes."""
        comment = _claims_comment([{"p": "uses_technique", "o": "T1566"}])
        syncer = _syncer()
        curated, _ = syncer.parse_attribute(_attr("threat-actor", "a-name-the-graph-lacks", comment), self.EVENT)
        ordinary, _ = syncer.parse_attribute(_attr("threat-actor", "apt29", "profile"), self.EVENT)
        assert curated["curated"] is True and ordinary["curated"] is False
        syncer._sync_to_neo4j_chunk = MagicMock(return_value=(1, 0))
        syncer.sync_to_neo4j([curated, ordinary])
        merged = [i for call in syncer._sync_to_neo4j_chunk.call_args_list for i in call.args[0]]
        assert merged == [ordinary]
        syncer._sync_to_neo4j_chunk.reset_mock()
        assert syncer.sync_to_neo4j([curated]) == (0, 0, [])
        syncer._sync_to_neo4j_chunk.assert_not_called()

    def test_ordinary_actor_attribute_is_unchanged(self):
        item, _ = _syncer().parse_attribute(_attr("threat-actor", "apt29", "An actor profile"), self.EVENT)
        assert item["description"] == "An actor profile" and item["tlp"] == "amber"


# --------------------------------------------------------------------------- writer
def _capturing_client():
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    captured: list = []

    def run(query, **kwargs):
        if kwargs.get("rows") is not None:
            captured.append((query, list(kwargs["rows"])))
        return MagicMock()

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    client.driver.session.return_value = session
    return client, captured


class TestWriter:
    def test_curated_rows_reach_their_templates_with_provenance(self):
        rows = _curated_claim_rows(
            [
                {"p": "uses_malware", "o": "Emotet", "id": "a"},
                {"p": "uses_tool", "o": "S0002", "id": "b"},
                {"p": "exploits", "o": "CVE-2021-44228", "id": "c"},
            ],
            "ThreatActor",
            {"name": "APT29"},
            "coreideas",
            "5",
        ) + _curated_claim_rows(
            [{"p": "exploits", "o": "CVE-2017-11882", "id": "d"}], "Malware", {"name": "LockBit"}, "coreideas", "5"
        )
        client, captured = _client_and_run(rows)
        by_merge = {q.split("MERGE ")[1].split("\n")[0].strip(): r for q, r in captured}
        assert set(by_merge) == {
            "(a)-[r:USES_MALWARE]->(m)",
            "(a)-[r:USES_TOOL]->(t)",
            "(a)-[r:EXPLOITS]->(c)",
            "(m)-[r:EXPLOITS]->(c)",
        }
        assert by_merge["(a)-[r:USES_MALWARE]->(m)"][0]["subject"] == "apt29", "canonical (lower-case) name keys"
        assert by_merge["(a)-[r:USES_MALWARE]->(m)"][0]["malware"] == "emotet"
        assert by_merge["(m)-[r:EXPLOITS]->(c)"][0]["subject"] == "lockbit"
        for query, batch in captured:
            assert (
                "MATCH (a:ThreatActor {name: row.subject})" in query or "MATCH (m:Malware {name: row.subject})" in query
            )
            assert "aliases" not in query, "exact canonical names only — never alias matching"
            assert "r.sources = apoc.coll.toSet(coalesce(r.sources, []) + [row.source])" in query
            assert all(r["match_type"] == "coreideas_curated" and r["source"] == "coreideas" for r in batch)
        assert by_merge["(a)-[r:EXPLOITS]->(c)"][0]["source_refs"] == ["coreideas:c"]

    def test_curated_technique_claims_match_exact_names_only(self):
        """Review finding on #179: the MISP-tag technique templates match aliases too, so a curated
        claim must take its own exact-name template (aliases come from untrusted MISP tags)."""
        rows = _curated_claim_rows(
            [{"p": "uses_technique", "o": "T1566", "id": "a"}], "ThreatActor", {"name": "APT29"}, "coreideas", "5"
        )
        rows += _curated_claim_rows(
            [{"p": "implements_technique", "o": "T1486", "id": "b"}], "Malware", {"name": "LockBit"}, "coreideas", "5"
        )
        _, captured = _client_and_run(rows)
        merges = {q.split("MERGE ")[1].split("\n")[0].strip(): (q, r) for q, r in captured}
        assert set(merges) == {"(a)-[r:EMPLOYS_TECHNIQUE]->(t)", "(m)-[r:IMPLEMENTS_TECHNIQUE]->(t)"}
        for query, _batch in merges.values():
            assert "aliases" not in query
            assert "{name: row.actor}" in query or "{name: row.entity}" in query
        assert merges["(a)-[r:EMPLOYS_TECHNIQUE]->(t)"][1][0]["actor"] == "apt29"
        assert merges["(m)-[r:IMPLEMENTS_TECHNIQUE]->(t)"][1][0]["entity"] == "lockbit"

    def test_misp_tag_technique_rows_keep_the_alias_template(self):
        rel = {
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "Cozy Bear"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1566"},
            "match_type": "misp_attribute_tag",
        }
        _, captured = _client_and_run([rel])
        assert len(captured) == 1 and "row.actor IN coalesce(a.aliases, [])" in captured[0][0]

    def test_indicator_exploits_rows_keep_the_cve_tag_path(self):
        rel = {
            "rel_type": "EXPLOITS",
            "from_type": "Indicator",
            "from_key": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "to_type": "Vulnerability",
            "to_key": {"cve_id": "CVE-2021-44228"},
            "match_type": "cve_tag",
        }
        _, captured = _client_and_run([rel])
        assert len(captured) == 2 and all("MATCH (i:Indicator {value: row.value})" in q for q, _ in captured)


def _client_and_run(rows):
    client, captured = _capturing_client()
    client.create_misp_relationships_batch(rows, source_id="misp")
    return client, captured


# --------------------------------------------------------------------------- import script
def _package(**overrides):
    package = {
        "name": "2026-10-20_EdgeGuard_CoreIdeas_package",
        "source": "coreideas",
        "tlp": "amber",
        "entities": [
            {"kind": "threat_actor", "name": "apt29", "claims": [{"p": "uses_technique", "o": "T1566", "id": "c1"}]},
            {
                "kind": "malware",
                "name": "lockbit",
                "claims": [
                    {"p": "exploits", "o": "CVE-2023-4966", "src": "misp_galaxy", "id": "g1"},
                    {"p": "uses_malware", "o": "x"},  # actor-only predicate on malware: skipped
                ],
            },
        ],
    }
    package.update(overrides)
    return package


class TestImportScript:
    def test_valid_package_summary(self, importer):
        errors, warnings, summary = importer.validate(_package())
        assert errors == []
        assert len(warnings) == 1 and "not allowed for Malware" in warnings[0]
        assert summary["label"] == "coreideas_curated"
        assert summary["claims"] == 2 and summary["claims_skipped"] == 1
        assert summary["by_claim_source"] == {"coreideas": 1, "misp_galaxy": 1}

    @pytest.mark.parametrize(
        "overrides, fragment",
        [
            ({"name": "Core Ideas package"}, "must contain 'EdgeGuard'"),
            ({"source": "nvd"}, "is a feed"),
            ({"tlp": "purple"}, "tlp"),
            ({"entities": []}, "non-empty list"),
            ({"entities": [{"kind": "campaign", "name": "x", "claims": []}]}, "kind"),
            (
                {
                    "entities": [
                        {"kind": "threat_actor", "name": "APT29", "claims": [{"p": "uses_technique", "o": "T1"}]},
                        {"kind": "threat_actor", "name": "apt29", "claims": [{"p": "uses_technique", "o": "T2"}]},
                    ]
                },
                "appears twice",
            ),
        ],
    )
    def test_invalid_packages_are_refused(self, importer, overrides, fragment):
        errors, _, _ = importer.validate(_package(**overrides))
        assert any(fragment in e for e in errors), errors

    def test_unregistered_source_is_allowed_with_curated_other(self, importer):
        errors, warnings, summary = importer.validate(_package(source="partner_pkg"))
        assert errors == [] and summary["label"] == "curated_other"
        assert any("not registered" in w for w in warnings)

    def test_comment_budget(self, importer):
        many = [{"p": "uses_technique", "o": f"T{n:04d}", "id": "x" * 40} for n in range(1500)]
        errors, _, _ = importer.validate(_package(entities=[{"kind": "threat_actor", "name": "a", "claims": many}]))
        assert any("comment budget" in e for e in errors)

    def test_event(self, importer):
        event = importer.build_event(_package())["Event"]
        assert event["info"] == "2026-10-20_EdgeGuard_CoreIdeas_package"
        assert event["distribution"] == 0 and event["published"] is False
        assert [t["name"] for t in event["Tag"]] == ["EdgeGuard", "source:CoreIdeas", "tlp:amber"]
        actor, malware = event["Attribute"]
        assert (actor["type"], actor["value"], actor["to_ids"]) == ("threat-actor", "apt29", False)
        assert actor["Tag"] == [{"name": "source:CoreIdeas"}]
        assert actor["comment"].startswith(CURATED_CLAIMS_PREFIX)
        # every claim names its source (the package's when the claim gives none)
        assert _parse_curated_claims(actor["comment"]) == [
            {"p": "uses_technique", "o": "T1566", "src": "coreideas", "id": "c1"}
        ]
        assert malware["type"] == "malware-type"
        assert _parse_curated_claims(malware["comment"]) == [
            {"p": "exploits", "o": "CVE-2023-4966", "src": "misp_galaxy", "id": "g1"}
        ], "invalid claims are not carried into MISP"

    def test_sync_reads_the_event_it_builds(self, importer):
        """Round trip: the importer's attribute, parsed by the sync, yields the package's claims."""
        attr = dict(importer.build_event(_package())["Event"]["Attribute"][0], uuid="u-1")
        event = {"id": "7", "info": "2026-10-20_EdgeGuard_CoreIdeas_package", "Tag": [{"name": "EdgeGuard"}]}
        item, rels = _syncer().parse_attribute(attr, event)
        assert item["tag"] == "coreideas"
        assert [(r["rel_type"], r["to_key"], r["source_refs"]) for r in rels] == [
            ("EMPLOYS_TECHNIQUE", {"mitre_id": "T1566"}, ["coreideas:c1"])
        ]

    def test_unregistered_package_keeps_its_name_in_r_sources(self, importer):
        """The sync maps an unknown ``source:*`` tag to ``misp``; the claims carry the name."""
        package = _package(source="partner_pkg")
        attr = dict(importer.build_event(package)["Event"]["Attribute"][0], uuid="u-2")
        assert attr["Tag"] == [{"name": "source:partner_pkg"}]
        event = {"id": "8", "info": package["name"], "Tag": [{"name": "EdgeGuard"}]}
        item, rels = _syncer().parse_attribute(attr, event)
        assert item["tag"] == "misp", "unknown source tags still map to misp at the attribute level"
        assert [(r["source"], r["match_type"], r["source_refs"]) for r in rels] == [
            ("partner_pkg", "curated_other", ["partner_pkg:c1"])
        ]

    @pytest.mark.parametrize(
        "payload",
        [
            [{"id": "1", "info": "2026-10-20_EdgeGuard_CoreIdeas_package"}],
            {"response": [{"id": "1", "info": "2026-10-20_EdgeGuard_CoreIdeas_package"}]},
            [{"Event": {"id": "1", "info": "2026-10-20_EdgeGuard_CoreIdeas_package"}}],
            {"response": [{"Event": {"id": "1", "info": "2026-10-20_EdgeGuard_CoreIdeas_package"}}]},
        ],
        ids=["flat", "response", "wrapped", "response-wrapped"],
    )
    def test_duplicate_check_reads_every_index_shape(self, importer, payload):
        assert importer._index_infos(payload) == ["2026-10-20_EdgeGuard_CoreIdeas_package"]

    def test_duplicate_check_tolerates_junk(self, importer):
        assert importer._index_infos(None) == [] and importer._index_infos({"errors": "x"}) == []
        assert importer._index_infos([1, "x", {"Event": "not a dict"}]) == []

    def test_dry_run_writes_nothing(self, importer, tmp_path, capsys):
        path = tmp_path / "pkg.json"
        path.write_text(json.dumps(_package()))
        assert importer.main([str(path)]) == 0
        assert "dry run, nothing written" in capsys.readouterr().out
