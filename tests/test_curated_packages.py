"""Curated packages (2026-10): claims about existing entities, imported once through MISP.

A package (e.g. ``YYYY-MM-DD_EdgeGuard_curated_package``) becomes one MISP event; each
actor / malware attribute names an existing node and carries its claims in a
``CURATED_CLAIMS:`` comment. The sync turns every claim into a relationship, MATCHing both
ends — a package never creates nodes and never changes the node it names. A link the claim
creates gets the package's curated label (its source's, else ``curated_other``) at
0.85; a link that already exists keeps its label and confidence. Either way the claim's own
source goes into ``r.sources`` and its record id into ``r.source_refs``.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
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

import neo4j_client  # noqa: E402
import source_registry  # noqa: E402
from neo4j_client import Neo4jClient, RelationshipBatchResult  # noqa: E402
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


def _one_claim_of_each_kind():
    """Rows for all six curated templates (actor and malware subjects)."""
    actor = _curated_claim_rows(
        [
            {"p": "uses_technique", "o": "T1566", "id": "a"},
            {"p": "uses_malware", "o": "emotet", "id": "b"},
            {"p": "uses_tool", "o": "S0002", "id": "c"},
            {"p": "exploits", "o": "CVE-2021-44228", "id": "d"},
        ],
        "ThreatActor",
        {"name": "apt29"},
        "coreideas",
        "5",
    )
    malware = _curated_claim_rows(
        [{"p": "implements_technique", "o": "T1486", "id": "e"}, {"p": "exploits", "o": "CVE-2017-11882", "id": "f"}],
        "Malware",
        {"name": "lockbit"},
        "coreideas",
        "5",
    )
    return actor + malware


def _split_top_level(text, sep=","):
    """``text`` split on ``sep`` outside parentheses / brackets / braces."""
    parts, depth, current = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _assignments(clause):
    """``{property: expression}`` for every ``r.<property> = <expression>`` of a SET clause."""
    out = {}
    for part in _split_top_level(clause):
        name, sep, expr = part.strip().partition("=")
        if sep and name.strip().startswith("r."):
            out[name.strip()[2:]] = " ".join(expr.split())
    return out


def _merge_clauses(query):
    """``(on_create, set_)``: the assignments of the ``ON CREATE SET`` (empty when the template has
    none) and of the plain ``SET`` that follow the template's ``MERGE``."""
    after_merge = query.split("MERGE ", 1)[1].split("\n", 1)[1]
    body = after_merge.split("RETURN ", 1)[0]
    on_create = {}
    if body.lstrip().startswith("ON CREATE SET "):
        first, body = body.lstrip()[len("ON CREATE SET ") :].split("\n", 1)
        on_create = _assignments(first)
    set_text = body.lstrip()
    assert set_text.startswith("SET "), set_text[:80]
    return on_create, _assignments(set_text[len("SET ") :])


def _after_write(link, query, created):
    """The link's properties after the template's write; written properties hold ``<written>``.

    On a link MERGE creates, ``ON CREATE SET`` and ``SET`` both run; on an existing link only
    ``SET`` does. ``row.<field>`` expressions are read as the row's value.
    """
    on_create, set_ = _merge_clauses(query)
    out = dict(link)
    for assignments in (on_create, set_) if created else (set_,):
        for prop, expr in assignments.items():
            out[prop] = expr if expr.startswith("row.") else "<written>"
    return out


class TestCuratedClaimsNeverRelabel:
    """Label takeover fix (2026-10): a curated claim writes its label and 0.85 only on a link it
    creates; on an existing link (an OTX ``otx_pulse`` 0.6 link, say) it adds its provenance and
    leaves ``match_type`` and ``confidence_score`` as they are. The OTX label is written on
    creation only, so a curated label written over it never came back."""

    OTX_LINK = {"match_type": "otx_pulse", "confidence_score": 0.6, "sources": ["alienvault_otx"]}

    def _curated_queries(self):
        _, captured = _client_and_run(_one_claim_of_each_kind())
        queries = {q.split("MERGE ")[1].split("\n")[0].strip(): q for q, _ in captured}
        assert len(queries) == 6, sorted(queries)
        return queries

    def test_an_existing_link_keeps_its_label_and_confidence(self):
        for merge, query in self._curated_queries().items():
            after = _after_write(self.OTX_LINK, query, created=False)
            assert (after["match_type"], after["confidence_score"]) == ("otx_pulse", 0.6), merge
            assert after["sources"] == "<written>", f"{merge}: the curated source is still added"
            assert {"source_refs", "misp_event_ids"} <= set(after), merge

    def test_a_link_the_claim_creates_gets_the_curated_label_and_confidence(self):
        for merge, query in self._curated_queries().items():
            after = _after_write({}, query, created=True)
            assert (after["match_type"], after["confidence_score"]) == ("row.match_type", "row.confidence"), merge
        rows = _one_claim_of_each_kind()
        assert {(r["match_type"], r["confidence"]) for r in rows} == {("coreideas_curated", 0.85)}

    def test_on_create_follows_the_merge_directly(self):
        """Cypher accepts ``ON CREATE SET`` only immediately after ``MERGE``."""
        for merge, query in self._curated_queries().items():
            assert f"MERGE {merge}\n        ON CREATE SET r.match_type = row.match_type" in query, merge

    def test_feed_templates_keep_the_stronger_evidence_rule(self):
        """Control: non-curated rows still move a link's label and confidence to stronger evidence."""
        rel = {
            "rel_type": "EMPLOYS_TECHNIQUE",
            "from_type": "ThreatActor",
            "from_key": {"name": "apt29"},
            "to_type": "Technique",
            "to_key": {"mitre_id": "T1566"},
            "confidence": 0.8,
            "match_type": "misp_attribute_tag",
        }
        ((query, _rows),) = _client_and_run([rel])[1]
        on_create, set_ = _merge_clauses(query)
        assert on_create == {}
        assert set_["match_type"].startswith("CASE WHEN r.confidence_score IS NULL OR")
        assert set_["confidence_score"].startswith("CASE WHEN r.confidence_score IS NULL OR")
        assert _after_write(self.OTX_LINK, query, created=False)["match_type"] == "<written>"


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

    def test_unregistered_package_source_is_refused(self, importer):
        """2026-10: the package's source asserts every claim that names none, so it must be a
        registered curated source (it used to be imported as ``curated_other``)."""
        errors, _, _ = importer.validate(_package(source="partner_pkg"))
        assert any("'partner_pkg' is not a registered curated source" in e for e in errors), errors

    def test_registered_curated_source_without_a_label_gets_curated_other(self, importer):
        errors, _, summary = importer.validate(_package(source="misp_galaxy"))
        assert errors == [] and summary["label"] == "curated_other"

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
        assert actor["Tag"] == [{"name": "source:CoreIdeas"}, {"name": "tlp:amber"}], "the package TLP on the attribute"
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

    def test_sync_records_an_unregistered_claim_source_as_curated_other(self):
        """Defence in depth (2026-10): an event the importer refuses — written by hand or by an
        older importer — cannot put its source's name into ``r.sources`` / ``r.source_refs``."""
        comment = _claims_comment([{"p": "uses_technique", "o": "T1566", "src": "partner_pkg", "id": "c1"}])
        attr = dict(
            _attr("threat-actor", "apt29", comment), Tag=[{"name": "source:partner_pkg"}, {"name": "tlp:amber"}]
        )
        event = {"id": "8", "info": "2026-10-20_EdgeGuard_partner_package", "Tag": [{"name": "EdgeGuard"}]}
        item, rels = _syncer().parse_attribute(attr, event)
        assert item["tag"] == "misp", "unknown source tags still map to misp at the attribute level"
        assert [(r["source"], r["match_type"], r["source_refs"]) for r in rels] == [
            ("curated_other", "curated_other", ["curated_other:c1"])
        ]
        assert "partner_pkg" not in json.dumps(rels)

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


# --------------------------------------------------------------------------- claims that do not attach
class _GraphSession:
    """A Neo4j session over a few nodes (``{label: {key value}}``).

    It answers the two queries the curated path depends on the way Neo4j does for exact-key
    patterns: a curated template's ``count(r)`` (rows whose two MATCHed ends exist) and the
    missing-ends lookup (the ends that do not). Every other query gets an empty result.
    """

    _PATTERN = re.compile(r"\(\w+:(\w+) \{(\w+): row\.(\w+)\}\)")

    def __init__(self, nodes):
        self.nodes = nodes
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, rows=None, **params):
        self.queries.append(query)
        ends = self._PATTERN.findall(query)
        found = [[row.get(field) in self.nodes.get(label, ()) for label, _key, field in ends] for row in rows or []]
        if "OPTIONAL MATCH" in query:
            missing = [
                {
                    "subject": None if hits[0] else row[ends[0][2]],
                    "object": None if hits[1] else row[ends[1][2]],
                }
                for row, hits in zip(rows, found, strict=True)
                if not all(hits)
            ]
            return missing[: params["limit"]]
        result = MagicMock()
        matched = sum(1 for hits in found if len(hits) == 2 and all(hits))
        result.single.return_value = {"matched": matched} if "RETURN count(r) AS matched" in query else None
        return result


def _graph_client(nodes):
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()
    session = _GraphSession(nodes)
    client.driver.session.return_value = session
    return client, session


GRAPH = {"ThreatActor": {"apt29"}, "Malware": {"emotet"}, "Technique": {"T1566"}, "Tool": set(), "CVE": set()}


class TestClaimsThatDoNotAttach:
    """Invisible misses fix (2026-10): rows sent are not links written. A claim whose subject or
    object is not in the graph matches nothing; the writer counts only matched curated rows as
    written and names the missing ends, and the sync logs how many claims attached."""

    CLAIMS = [
        {"p": "uses_malware", "o": "emotet", "id": "c1"},  # both ends exist: attaches
        {"p": "uses_malware", "o": "ghostware", "id": "c2"},  # no such malware
        {"p": "exploits", "o": "CVE-2099-0001", "id": "c3"},  # no such CVE
        {"p": "uses_tool", "o": "S0002", "id": "c4"},  # no such tool
    ]

    def test_writer_counts_matched_rows_and_names_the_missing_ends(self):
        """All six curated templates; three claims find both ends, five do not."""

        def rows(subject_type, name, *claims):
            return _curated_claim_rows(list(claims), subject_type, {"name": name}, "coreideas", "5")

        batch = (
            rows("ThreatActor", "apt29", {"p": "uses_technique", "o": "T1566"})  # attaches: no lookup
            + rows(
                "ThreatActor", "apt29", {"p": "uses_malware", "o": "emotet"}, {"p": "uses_malware", "o": "ghostware"}
            )
            + rows("ThreatActor", "apt-x", {"p": "uses_tool", "o": "S0002"})  # neither end exists
            + rows("ThreatActor", "apt29", {"p": "exploits", "o": "CVE-2099-0001"})
            + rows("Malware", "emotet", {"p": "implements_technique", "o": "T1566"})
            + rows(
                "Malware",
                "lockbit",
                {"p": "implements_technique", "o": "T1486"},
                {"p": "exploits", "o": "CVE-2017-11882"},
            )
        )
        client, session = _graph_client(GRAPH)
        result = client.create_misp_relationships_batch(batch, source_id="misp")
        assert int(result) == 3, "only the claims whose two ends exist are written links"
        assert (result.curated_sent, result.curated_matched, result.failed) == (8, 3, 0)
        assert sorted(result.curated_missing) == [
            "CVE 'CVE-2017-11882'",
            "CVE 'CVE-2099-0001'",
            "Malware 'ghostware'",
            "Malware 'lockbit'",
            "Technique 'T1486'",
            "ThreatActor 'apt-x'",
            "Tool 'S0002'",
        ]
        merges = [q for q in session.queries if "MERGE" in q]
        lookups = [q for q in session.queries if "OPTIONAL MATCH" in q]
        assert len(merges) == 6 and all("RETURN count(r) AS matched" in q for q in merges)
        assert len(lookups) == 5, "the name lookup runs only for the batches that fell short"
        assert not any("MERGE" in q or "SET " in q for q in lookups), "the lookup is read-only"

    def test_feed_rows_still_count_as_sent(self):
        """Control: the feed templates are unchanged — their rows count as written."""
        rel = {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "to_type": "Malware",
            "to_key": {"name": "emotet"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
        }
        client, _session = _graph_client(GRAPH)
        result = client.create_misp_relationships_batch([rel], source_id="misp")
        assert int(result) == 1 and getattr(result, "curated_sent", 0) == 0

    def test_missing_names_are_bounded(self):
        claims = [{"p": "uses_malware", "o": f"family-{n:03d}"} for n in range(60)]
        rows = _curated_claim_rows(claims, "ThreatActor", {"name": "apt29"}, "coreideas", "5")
        client, _session = _graph_client(GRAPH)
        result = client.create_misp_relationships_batch(rows, source_id="misp")
        assert (int(result), result.curated_sent) == (0, 60)
        assert len(result.curated_missing) == neo4j_client.CURATED_MISSING_SAMPLE

    def test_a_failed_name_lookup_keeps_the_counts(self, caplog):
        rows = _curated_claim_rows(self.CLAIMS[:2], "ThreatActor", {"name": "apt29"}, "coreideas", "5")
        client, session = _graph_client(GRAPH)
        real_run = session.run

        def run(query, rows=None, **params):
            if "OPTIONAL MATCH" in query:
                raise RuntimeError("lookup failed")
            return real_run(query, rows=rows, **params)

        session.run = run
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            result = client.create_misp_relationships_batch(rows, source_id="misp")
        assert (int(result), result.curated_sent, result.curated_matched, result.failed) == (1, 2, 1, 0)
        assert any("could not name the missing ends" in r.getMessage() for r in caplog.records)

    def test_sync_logs_the_claims_that_did_not_attach_and_counts_only_attached_links(self, importer, caplog):
        """End to end: the importer's event, parsed and written by the sync over the graph above."""
        package = _package(entities=[{"kind": "threat_actor", "name": "apt29", "claims": self.CLAIMS}])
        event = importer.build_event(package)["Event"]
        attributes = [dict(a, uuid=f"u-{n}") for n, a in enumerate(event["Attribute"])]
        full_event = {"id": "41", "info": event["info"], "Tag": event["Tag"], "Attribute": attributes}
        client, _session = _graph_client(GRAPH)
        sync = MISPToNeo4jSync(neo4j_client=client)
        with caplog.at_level(logging.INFO, logger="run_misp_to_neo4j"):
            sync._process_event_attributes("41", full_event, attributes)
        assert sync.stats["relationships_created"] == 1, "unattached claims are not created links"
        assert (sync.stats["curated_claims_attached"], sync.stats["curated_claims_unattached"]) == (1, 3)
        (line,) = [r for r in caplog.records if r.getMessage().startswith("[CURATED]")]
        assert line.levelno == logging.WARNING
        message = line.getMessage()
        assert "1 of 4 curated claim(s) attached; 3 did not" in message
        for name in ("Malware 'ghostware'", "CVE 'CVE-2099-0001'", "Tool 'S0002'"):
            assert name in message

    def test_sync_logs_at_info_when_every_claim_attached(self, caplog):
        sync = MISPToNeo4jSync(neo4j_client=MagicMock())
        sync.neo4j.create_misp_relationships_batch.side_effect = lambda chunk, source_id="misp": (
            RelationshipBatchResult(len(chunk), curated_sent=len(chunk), curated_matched=len(chunk))
        )
        rows = _curated_claim_rows(self.CLAIMS[:1], "ThreatActor", {"name": "apt29"}, "coreideas", "5")
        with caplog.at_level(logging.INFO, logger="run_misp_to_neo4j"):
            assert sync._create_relationships(rows, "misp") == 1
        (line,) = [r for r in caplog.records if r.getMessage().startswith("[CURATED]")]
        assert line.levelno == logging.INFO and "1 of 1 curated claim(s) attached" in line.getMessage()
        assert sync.stats["curated_claims_unattached"] == 0


# --------------------------------------------------------------------------- TLP of curated links
class TestCuratedLinkTlp:
    """TLP fix (2026-10): the package's TLP marks every claim's link. The level was on the MISP
    event only, the sync blanked it for curated attributes, and an SRO takes its marking from
    its endpoints only — so curated links exported as TLP:WHITE."""

    @pytest.mark.parametrize("tlp", [None, "", "  "])
    def test_importer_requires_a_tlp_level(self, importer, tlp):
        package = _package()
        if tlp is None:
            del package["tlp"]
        else:
            package["tlp"] = tlp
        errors, _, _ = importer.validate(package)
        assert any("missing 'tlp'" in e for e in errors), errors

    def test_importer_tags_every_attribute_with_the_package_tlp(self, importer):
        event = importer.build_event(_package(tlp=" Amber+Strict "))["Event"]
        assert {"name": "tlp:amber+strict"} in event["Tag"]
        assert event["Attribute"] and all({"name": "tlp:amber+strict"} in a["Tag"] for a in event["Attribute"])

    def test_sync_carries_the_attribute_tlp_into_the_claim_rows(self, importer):
        attr = dict(importer.build_event(_package(tlp="red"))["Event"]["Attribute"][0], uuid="u-1")
        event = {"id": "7", "info": "2026-10-20_EdgeGuard_CoreIdeas_package", "Tag": [{"name": "EdgeGuard"}]}
        item, rels = _syncer().parse_attribute(attr, event)
        assert item["tlp"] == "", "the node's own TLP is still not touched"
        assert rels and {r["tlp"] for r in rels} == {"red"}

    def test_an_event_tagged_before_attributes_were_tagged_gives_its_level(self):
        """Events imported before 2026-10 carry the TLP on the event only."""
        comment = _claims_comment([{"p": "uses_technique", "o": "T1566"}])
        attr = _attr("threat-actor", "apt29", comment)
        attr["Tag"] = [{"name": "source:CoreIdeas"}]
        event = {"id": "9", "info": "x_EdgeGuard_y", "Tag": [{"name": "EdgeGuard"}, {"name": "tlp:amber"}]}
        _, rels = _syncer().parse_attribute(attr, event)
        assert [r["tlp"] for r in rels] == ["amber"]

    def test_the_attribute_level_wins_over_the_event_level(self):
        comment = _claims_comment([{"p": "implements_technique", "o": "T1486"}])
        attr = _attr("malware-type", "lockbit", comment)  # tagged tlp:amber
        event = {"id": "9", "info": "x_EdgeGuard_y", "Tag": [{"name": "tlp:green"}]}
        _, rels = _syncer().parse_attribute(attr, event)
        assert [r["tlp"] for r in rels] == ["amber"]

    def test_writer_sends_the_level_and_every_curated_template_writes_r_tlp(self):
        rows = [dict(r, tlp="AMBER") for r in _one_claim_of_each_kind()]
        _, captured = _client_and_run(rows)
        assert len(captured) == 6
        for query, batch in captured:
            assert {row["tlp"] for row in batch} == {"amber"}
            _on_create, set_ = _merge_clauses(query)
            assert set_["tlp"].startswith("CASE WHEN CASE toLower(toString(row.tlp))"), "most restrictive wins"
            assert set_["tlp"].endswith("THEN row.tlp ELSE r.tlp END")
            # an existing link is marked too: the provenance the claim adds is as restricted
            assert _after_write(TestCuratedClaimsNeverRelabel.OTX_LINK, query, created=False)["tlp"] == "<written>"

    def test_feed_templates_write_no_relationship_tlp(self):
        """Control: only curated links carry ``r.tlp``."""
        rel = {
            "rel_type": "INDICATES",
            "from_type": "Indicator",
            "from_key": {"value": "1.2.3.4", "indicator_type": "ipv4"},
            "to_type": "Malware",
            "to_key": {"name": "emotet"},
            "confidence": 0.6,
            "match_type": "otx_pulse",
            "tlp": "red",
        }
        ((query, _rows),) = _client_and_run([rel])[1]
        assert "tlp" not in _merge_clauses(query)[1]


# --------------------------------------------------------------------------- who may assert a claim
class TestClaimSources:
    """Claim source fix (2026-10): only a registered curated source (``source_type == "curated"``
    in ``src/source_registry.py``) may assert a claim. Any other name could otherwise reach
    ``r.sources``, ``r.source_refs`` and the STIX export."""

    def _actor_with(self, *claims):
        return _package(entities=[{"kind": "threat_actor", "name": "apt29", "claims": list(claims)}])

    def test_registered_curated_sources(self):
        assert source_registry.curated_source_ids() == ("coreideas", "misp_galaxy")
        assert source_registry.is_curated_source("CoreIdeas") and source_registry.is_curated_source("misp_galaxy")
        for name in ("acme_intel", "nvd", "mitre_attck", "misp", "curated_other", "", None):
            assert not source_registry.is_curated_source(name), name

    @pytest.mark.parametrize("src", ["acme_intel", "nvd", "alienvault_otx", "curated_other"])
    def test_importer_rejects_a_claim_from_any_other_source(self, importer, src):
        package = self._actor_with(
            {"p": "uses_technique", "o": "T1566", "id": "c1"}, {"p": "uses_technique", "o": "T1059", "src": src}
        )
        errors, warnings, summary = importer.validate(package)
        assert errors == []
        assert (summary["claims"], summary["claims_skipped"]) == (1, 1)
        assert summary["claims_skipped_by_reason"] == {"source": 1}
        assert any(f"source {src!r} is not a registered curated source" in w for w in warnings), warnings
        (attr,) = importer.build_event(package)["Event"]["Attribute"]
        assert src not in attr["comment"], "a rejected claim never reaches MISP"
        assert _parse_curated_claims(attr["comment"]) == [
            {"p": "uses_technique", "o": "T1566", "src": "coreideas", "id": "c1"}
        ]

    @pytest.mark.parametrize("src", ["coreideas", "CoreIdeas", "misp_galaxy", None])
    def test_importer_accepts_a_registered_curated_source(self, importer, src):
        claim = {"p": "uses_technique", "o": "T1566", "id": "c1"}
        if src is not None:
            claim["src"] = src
        errors, _, summary = importer.validate(self._actor_with(claim))
        assert errors == [] and (summary["claims"], summary["claims_skipped"]) == (1, 0)

    def test_sync_keeps_a_registered_curated_claim_source(self):
        rows = _curated_claim_rows(
            [{"p": "uses_technique", "o": "T1566", "src": "misp_galaxy", "id": "u-1"}],
            "ThreatActor",
            {"name": "apt29"},
            "coreideas",
            "5",
        )
        assert [(r["source"], r["source_refs"]) for r in rows] == [("misp_galaxy", ["misp_galaxy:u-1"])]

    @pytest.mark.parametrize("src", ["acme_intel", "nvd", "Mitre_Attck"])
    def test_sync_records_any_other_claim_source_as_curated_other(self, src, caplog):
        with caplog.at_level(logging.WARNING, logger="run_misp_to_neo4j"):
            rows = _curated_claim_rows(
                [{"p": "uses_technique", "o": "T1566", "src": src, "id": "r-9"}],
                "ThreatActor",
                {"name": "apt29"},
                "coreideas",
                "5",
            )
        assert [(r["source"], r["source_refs"], r["match_type"]) for r in rows] == [
            ("curated_other", ["curated_other:r-9"], "coreideas_curated")
        ]
        assert any("not a registered curated source" in r.getMessage() for r in caplog.records)
        assert not any(src.lower() in r.getMessage().lower() for r in caplog.records), "the name is not logged"


# --------------------------------------------------------------------------- object id formats
class TestClaimIds:
    """Id format fix (2026-10): the importer rejects a claim whose object id is malformed —
    technique ``T1234`` / ``T1234.123``, tool ``S1234``, CVE ``CVE-YYYY-NNNN`` (four or more
    digits). Ids are checked as the sync keys them (trimmed, upper-case)."""

    def _validate(self, importer, predicate, obj, kind="threat_actor"):
        package = _package(entities=[{"kind": kind, "name": "apt29", "claims": [{"p": predicate, "o": obj}]}])
        errors, warnings, summary = importer.validate(package)
        assert errors == []
        return warnings, summary

    @pytest.mark.parametrize(
        "predicate, obj",
        [
            ("uses_technique", "T1566"),
            ("uses_technique", "T1566.001"),
            ("uses_technique", " t1566.001 "),
            ("uses_tool", "S0002"),
            ("uses_tool", "s1234"),
            ("exploits", "CVE-2021-44228"),
            ("exploits", "cve-2021-1234567"),
            ("uses_malware", "Cobalt Strike"),  # a malware name has no id format
        ],
    )
    def test_well_formed_ids_are_imported(self, importer, predicate, obj):
        warnings, summary = self._validate(importer, predicate, obj)
        assert (summary["claims"], summary["claims_skipped"]) == (1, 0), warnings

    @pytest.mark.parametrize(
        "predicate, obj, expected",
        [
            ("uses_technique", "T15", "T1234 or T1234.123"),
            ("uses_technique", "T15660", "T1234 or T1234.123"),
            ("uses_technique", "T1566.1", "T1234 or T1234.123"),
            ("uses_technique", "T1566.0011", "T1234 or T1234.123"),
            ("uses_technique", "TA0001", "T1234 or T1234.123"),
            ("uses_technique", "1566", "T1234 or T1234.123"),
            ("uses_technique", "T１５６６", "T1234 or T1234.123"),  # full-width digits
            ("uses_tool", "S12", "S1234"),
            ("uses_tool", "S00021", "S1234"),
            ("uses_tool", "T1566", "S1234"),
            ("exploits", "CVE-21-1234", "CVE-YYYY-NNNN"),
            ("exploits", "CVE-2021-123", "CVE-YYYY-NNNN"),
            ("exploits", "CVE2021-44228", "CVE-YYYY-NNNN"),
            ("exploits", "2021-44228", "CVE-YYYY-NNNN"),
        ],
    )
    def test_malformed_ids_are_rejected(self, importer, predicate, obj, expected):
        warnings, summary = self._validate(importer, predicate, obj)
        assert (summary["claims"], summary["claims_skipped"]) == (0, 1)
        assert summary["claims_skipped_by_reason"] == {"id": 1}
        assert any(f"id {obj!r} is malformed (expected {expected})" in w for w in warnings), warnings

    def test_malware_claims_are_checked_too(self, importer):
        warnings, summary = self._validate(importer, "implements_technique", "T99", kind="malware")
        assert summary["claims_skipped_by_reason"] == {"id": 1}
        warnings, summary = self._validate(importer, "exploits", "CVE-2017-11882", kind="malware")
        assert summary["claims_skipped"] == 0

    def test_a_malformed_claim_is_not_written_to_misp(self, importer):
        package = _package(
            entities=[
                {
                    "kind": "threat_actor",
                    "name": "apt29",
                    "claims": [{"p": "uses_tool", "o": "S0002", "id": "a"}, {"p": "uses_tool", "o": "S2", "id": "b"}],
                }
            ]
        )
        (attr,) = importer.build_event(package)["Event"]["Attribute"]
        assert [c["o"] for c in _parse_curated_claims(attr["comment"])] == ["S0002"]


# --------------------------------------------------------------------------- --check-graph
def _graph_reader(nodes, calls=None):
    """``run_query`` for ``check_graph`` over ``{label: {key value}}``, answering the lookup as Neo4j
    answers OPTIONAL MATCH on an exact key."""
    pattern = re.compile(r"\((\w+):(\w+) \{(\w+): row\.(\w+)\}\)")

    def run_query(cypher, rows):
        if calls is not None:
            calls.append((cypher, list(rows)))
        (s_label, _sk, s_field), (o_label, _ok, o_field) = [m[1:] for m in pattern.findall(cypher)]
        return [
            {
                "i": row["i"],
                "subject_found": row[s_field] in nodes.get(s_label, ()),
                "object_found": row[o_field] in nodes.get(o_label, ()),
            }
            for row in rows
        ]

    return run_query


class TestCheckGraph:
    """``--check-graph`` (2026-10): read-only, per predicate, the claims whose subject or object is
    not in the graph by the exact name or id the sync matches on."""

    PACKAGE = _package(
        entities=[
            {
                "kind": "threat_actor",
                "name": " APT29 ",
                "claims": [
                    {"p": "uses_technique", "o": "t1566"},  # both ends exist (keys normalised)
                    {"p": "uses_malware", "o": "Emotet"},  # both ends exist
                    {"p": "uses_malware", "o": "ghostware"},  # object missing
                    {"p": "exploits", "o": "CVE-2099-0001"},  # object missing
                    {"p": "uses_tool", "o": "S2"},  # malformed: not checked (not imported)
                ],
            },
            {"kind": "threat_actor", "name": "apt-x", "claims": [{"p": "uses_technique", "o": "T1566"}]},
            {"kind": "malware", "name": "lockbit", "claims": [{"p": "implements_technique", "o": "T1486"}]},
        ]
    )

    def test_report_per_predicate(self, importer):
        calls = []
        report = importer.check_graph(self.PACKAGE, _graph_reader(GRAPH, calls))
        assert (report["claims"], report["attach"], report["do_not_attach"]) == (6, 2, 4)
        by = report["by_predicate"]
        assert by["uses_technique (ThreatActor)"] == {
            "claims": 2,
            "attach": 1,
            "subject_missing": 1,
            "object_missing": 0,
            "missing_subjects": ["apt-x"],
            "missing_objects": [],
        }
        assert by["uses_malware (ThreatActor)"]["missing_objects"] == ["ghostware"]
        assert by["exploits (ThreatActor)"]["missing_objects"] == ["CVE-2099-0001"]
        assert by["implements_technique (Malware)"]["missing_subjects"] == ["lockbit"]
        assert by["implements_technique (Malware)"]["missing_objects"] == ["T1486"]
        assert "uses_tool (ThreatActor)" not in by, "a rejected claim is not checked"
        for cypher, _rows in calls:
            assert not re.search(r"\b(MERGE|CREATE|SET|DELETE|REMOVE)\b", cypher), "the check only reads"

    def test_large_groups_are_looked_up_in_batches(self, importer, monkeypatch):
        monkeypatch.setattr(importer, "CHECK_BATCH", 2)
        claims = [{"p": "uses_technique", "o": f"T{n:04d}"} for n in range(1564, 1569)]
        package = _package(entities=[{"kind": "threat_actor", "name": "apt29", "claims": claims}])
        calls = []
        report = importer.check_graph(package, _graph_reader(GRAPH, calls))
        assert [len(rows) for _cypher, rows in calls] == [2, 2, 1]
        assert report["by_predicate"]["uses_technique (ThreatActor)"]["attach"] == 1, "only T1566 exists"

    def test_main_prints_the_report_and_writes_nothing(self, importer, monkeypatch, tmp_path, capsys):
        driver = MagicMock()
        monkeypatch.setattr(importer, "_neo4j_reader", lambda: (driver, _graph_reader(GRAPH)))
        path = tmp_path / "pkg.json"
        path.write_text(json.dumps(self.PACKAGE))
        assert importer.main([str(path), "--check-graph"]) == 0
        out = capsys.readouterr().out
        report = json.loads(out[out.index('{\n  "check_graph"') : out.rindex("}") + 1])["check_graph"]
        assert report["do_not_attach"] == 4
        assert "dry run, nothing written" in out
        driver.close.assert_called_once()

    def test_check_graph_and_push_are_exclusive(self, importer, tmp_path):
        path = tmp_path / "pkg.json"
        path.write_text(json.dumps(_package()))
        with pytest.raises(SystemExit):
            importer.main([str(path), "--check-graph", "--push"])

    def test_without_a_password_nothing_is_checked(self, importer, monkeypatch, tmp_path, capsys):
        monkeypatch.delenv("NEO4J_PASSWORD", raising=False)
        path = tmp_path / "pkg.json"
        path.write_text(json.dumps(_package()))
        assert importer.main([str(path), "--check-graph"]) == 2
        assert "NEO4J_PASSWORD" in capsys.readouterr().err
