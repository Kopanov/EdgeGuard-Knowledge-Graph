"""Actor alias merge with the canonical threat-actor reference (2026-10).

``enrichment_jobs.merge_alias_duplicate_actors`` takes a second rule from
``src/reference/canonical_threat_actors.json`` (loaded and validated by
``src/canonical_threat_actors.py``): a ``ThreatActor`` node that is not MITRE-sourced and whose
name resolves to another canonical actor that is a node on the graph folds into that node. Pinned
here:

* the loader validates the file and the job falls back, with one warning, to the ATT&CK-alias rule
  alone when the file is missing, malformed or inconsistent;
* the reference candidates (a pure function over the graph's names and sources): never a
  MITRE-sourced duplicate, never a canonical that is not on the graph, never an ambiguous or
  never_merge name;
* conflicts between the two rules and chains are skipped and counted;
* the reference checks the ATT&CK-alias pairs: a name it blocks is skipped, a name it gives to
  another actor (or keeps as its own) is a conflict;
* APPLY accepts a canonical the reference named, and still never a MITRE-sourced duplicate;
* the dry run lists the reference pairs; the job end to end on a fake session, with APOC missing,
  a failed batch and the per-run cap.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-canonical-reference-merge")
os.environ.setdefault("MISP_API_KEY", "test-key-canonical-reference-merge")

import canonical_threat_actors as cta  # noqa: E402
import enrichment_jobs  # noqa: E402

FLAG = enrichment_jobs._ACTOR_ALIAS_MERGE_ENV_FLAG
ENV = cta.REFERENCE_PATH_ENV
WARNING_PREFIX = "[ACTOR-ALIAS-MERGE] canonical reference unavailable ("
WARNING_SUFFIX = "); merging by MITRE aliases only"


def actor(key, synonyms=(), mitre_attack=None, origins=("misp_galaxy:threat-actor",)):
    return {
        "name": key.title(),
        "key": key,
        "mitre_attack": mitre_attack,
        "origins": list(origins),
        "records": [],
        "synonyms": sorted(synonyms),
        "synonym_origins": {},
    }


def reference_doc(**overrides):
    doc = {
        "schema_version": 1,
        "version": "2026.10.15",
        "actors": [
            actor("lazarus group", ["lazarus", "apt-c-26"], mitre_attack="G0032", origins=["mitre"]),
            actor("sandworm team", ["sandworm"], mitre_attack="G0034", origins=["mitre"]),
            actor("clop", ["cl0p"], origins=["override"]),
            actor("silver fox", ["silverfox", "silver fox apt"], origins=["override"]),
            actor("apt29", ["nobelium", "unc2452"], mitre_attack="G0016", origins=["mitre"]),
            actor("medusa group", [], mitre_attack="G1051", origins=["mitre"]),
        ],
        "ambiguous": [
            {"key": "uac-0056", "actors": ["apt29", "sandworm team"], "origins": {}},
            {"key": "medusa", "actors": ["medusa group"], "origins": {}, "never_merge": {"reason": "clash"}},
        ],
    }
    doc.update(overrides)
    return doc


def write_reference(tmp_path, doc):
    path = tmp_path / "canonical_threat_actors.json"
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc, encoding="utf-8")
    return path


def graph_row(name, source=("alienvault_otx",)):
    return {"name": name, "source": list(source) if not isinstance(source, str) else source}


GRAPH = [
    graph_row("lazarus group", ("mitre_attck", "alienvault_otx")),
    graph_row("lazarus"),
    graph_row("apt-c-26"),
    graph_row("sandworm team", ("mitre_attck",)),
    graph_row("sandworm"),
    graph_row("clop"),
    graph_row("cl0p"),
    graph_row("silverfox"),  # canonical "silver fox" is not a node: no pair
    graph_row("apt29", ("mitre_attck",)),
    graph_row("unc2452", ("mitre_attck",)),  # a revoked ATT&CK group: never a duplicate
    graph_row("uac-0056"),  # ambiguous
    graph_row("medusa"),  # never_merge
    graph_row("medusa group", ("mitre_attck",)),
    graph_row("qilin"),  # unknown
]


@pytest.fixture
def reference():
    return cta.validate_reference(reference_doc(), "fixture")


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    monkeypatch.delenv(FLAG, raising=False)


# --------------------------------------------------------------------------- loader


class TestLoader:
    def test_committed_reference_is_the_default_and_is_valid(self, monkeypatch):
        monkeypatch.delenv(ENV, raising=False)
        ref = cta.load_canonical_reference()
        assert ref.path == str(cta.DEFAULT_REFERENCE_PATH)
        assert ref.actor_count > 1000
        assert ref.canonical_for("Lazarus") == "lazarus group"
        assert ref.canonical_for("medusa") == "medusa group"  # merged 2026-10-17 (was never_merge)
        assert ref.canonical_for("bert") is None  # never_merge

    def test_empty_variable_keeps_the_default(self, monkeypatch):
        monkeypatch.setenv(ENV, "")  # docker-compose forwards an empty value
        assert cta.load_canonical_reference().path == str(cta.DEFAULT_REFERENCE_PATH)

    def test_variable_overrides_the_path(self, monkeypatch, tmp_path):
        path = write_reference(tmp_path, reference_doc())
        monkeypatch.setenv(ENV, str(path))
        ref = cta.load_canonical_reference()
        assert (ref.path, ref.version, ref.actor_count) == (str(path), "2026.10.15", 6)

    def test_lookup(self, reference):
        assert reference.canonical_for("  Lazarus ") == "lazarus group"
        assert reference.canonical_for("lazarus group") == "lazarus group"
        assert reference.canonical_for("uac-0056") is None
        assert reference.canonical_for("medusa") is None
        assert reference.canonical_for("qilin") is None
        assert reference.canonical_for(None) is None
        assert "lazarus group" in reference.attack_actors and "clop" not in reference.attack_actors

    def test_a_blocked_name_never_resolves(self):
        ref = cta.CanonicalReference("2026.10.15", "x", 1, {"x": "x", "y": "x"}, frozenset({"y"}))
        assert ref.canonical_for("y") is None and ref.canonical_for("x") == "x"

    @pytest.mark.parametrize(
        "doc, reason",
        [
            ("{not json", "cannot read"),
            ([], "not a JSON object"),
            (reference_doc(version="2026-10-15"), "not CalVer"),
            (reference_doc(version="2026.13.40"), "not a date"),
            (reference_doc(actors=[]), "no actors"),
            (reference_doc(actors=[actor("Lazarus Group")]), "not normalised"),
            (reference_doc(actors=[actor("x"), actor("x")]), "appears twice"),
            (reference_doc(actors=[actor("x", ["Y"])]), "not normalised"),
            (reference_doc(actors=[actor("x", ["s"]), actor("z", ["s"])]), "belongs to"),
            (reference_doc(actors=[actor("x", ["z"]), actor("z")]), "is the key of an actor"),
            (reference_doc(actors=[{**actor("x"), "synonyms": "y"}]), "no synonym list"),
            (reference_doc(ambiguous=[{"key": "lazarus"}]), "belongs to actor"),
            (reference_doc(ambiguous=None), "no ambiguous list"),
            (reference_doc(schema_version=2), "schema_version 2 is not 1"),
            (reference_doc(schema_version=True), "schema_version True is not 1"),
            (reference_doc(schema_version="1"), "schema_version '1' is not 1"),
            ({k: v for k, v in reference_doc().items() if k != "schema_version"}, "schema_version None"),
            (reference_doc(version="2026.10.15\n"), "not CalVer"),
            (reference_doc(version="٢٠٢٦.10.15"), "not CalVer"),  # Arabic-Indic digits
        ],
    )
    def test_inconsistent_files_are_refused(self, tmp_path, doc, reason):
        path = write_reference(tmp_path, doc)
        with pytest.raises(cta.ReferenceUnavailable, match=reason):
            cta.load_canonical_reference(path)

    def test_missing_file(self, tmp_path):
        with pytest.raises(cta.ReferenceUnavailable, match="not found"):
            cta.load_canonical_reference(tmp_path / "nope.json")

    def test_a_directory_is_refused(self, tmp_path):
        with pytest.raises(cta.ReferenceUnavailable, match="not a regular file"):
            cta.load_canonical_reference(tmp_path)

    def test_an_oversized_file_is_refused_before_it_is_read(self, tmp_path, monkeypatch):
        path = write_reference(tmp_path, reference_doc())
        monkeypatch.setattr(cta, "MAX_REFERENCE_BYTES", path.stat().st_size - 1)
        with pytest.raises(cta.ReferenceUnavailable, match="bytes, more than"):
            cta.load_canonical_reference(path)

    def test_the_shipped_file_is_well_under_the_size_limit(self):
        assert cta.DEFAULT_REFERENCE_PATH.stat().st_size < cta.MAX_REFERENCE_BYTES / 4


# --------------------------------------------------------------------------- reference candidates


class TestReferenceCandidates:
    def test_pairs(self, reference):
        assert cta.reference_merge_candidates(reference, GRAPH) == [
            ("apt-c-26", "lazarus group"),
            ("cl0p", "clop"),
            ("lazarus", "lazarus group"),
            ("sandworm", "sandworm team"),
        ]

    def test_a_mitre_sourced_node_is_never_a_duplicate(self, reference):
        rows = [graph_row("apt29", ("mitre_attck",)), graph_row("unc2452", "mitre_attck"), graph_row("nobelium")]
        assert cta.reference_merge_candidates(reference, rows) == [("nobelium", "apt29")]

    def test_the_canonical_must_be_a_node(self, reference):
        assert cta.reference_merge_candidates(reference, [graph_row("silverfox"), graph_row("silver fox apt")]) == []
        rows = [graph_row("silverfox"), graph_row("silver fox")]
        assert cta.reference_merge_candidates(reference, rows) == [("silverfox", "silver fox")]

    def test_ambiguous_never_merge_unknown_and_placeholder_names_are_skipped(self, reference):
        rows = [graph_row(n) for n in ("uac-0056", "medusa", "qilin", "unknown")] + [
            graph_row("apt29", ("mitre_attck",))
        ]
        assert cta.reference_merge_candidates(reference, rows) == []

    def test_odd_source_values_hold_no_source(self, reference):
        # An APOC merge can leave odd types behind; they must not raise.
        rows = [
            {"name": "lazarus", "source": 7},
            {"name": "sandworm", "source": {"x": 1}},
            {"name": "lazarus group", "source": "mitre_attck"},
            {"name": "sandworm team", "source": ["mitre_attck", 3]},
        ]
        assert cta.reference_merge_candidates(reference, rows) == [
            ("lazarus", "lazarus group"),
            ("sandworm", "sandworm team"),
        ]


# --------------------------------------------------------------------------- planning


ATTACK_ROWS = [
    {"duplicate_name": "reddelta", "canonical_names": ["mustang panda"]},
    {"duplicate_name": "dark halo", "canonical_names": ["apt29", "unc2452"]},
]


class TestPlan:
    def test_attack_rule_alone_is_unchanged(self):
        plan = cta.plan_alias_merges(ATTACK_ROWS, [])
        assert plan.pairs == [("mustang panda", "reddelta")]
        assert plan.ambiguous == [("dark halo", ["apt29", "unc2452"])]
        assert plan.reference_canonicals == [] and plan.candidates == 2

    def test_both_rules_agreeing_give_one_pair(self):
        plan = cta.plan_alias_merges(ATTACK_ROWS, [("reddelta", "mustang panda"), ("cl0p", "clop")])
        assert plan.pairs == [("clop", "cl0p"), ("mustang panda", "reddelta")]
        assert (plan.from_attack, plan.from_reference) == (1, 2)
        assert plan.reference_canonicals == ["clop", "mustang panda"]
        assert plan.reference_pairs == [("cl0p", "clop"), ("reddelta", "mustang panda")]

    def test_a_conflict_is_skipped(self):
        plan = cta.plan_alias_merges(ATTACK_ROWS, [("reddelta", "camaro dragon")])
        assert plan.pairs == []
        assert plan.conflicts == [("reddelta", ["camaro dragon", "mustang panda"])]

    def test_a_chain_is_cut_at_the_node_that_is_also_a_canonical(self):
        rows = [{"duplicate_name": "x", "canonical_names": ["z"]}]
        plan = cta.plan_alias_merges(rows, [("y", "x")])
        assert plan.pairs == [("x", "y")]
        assert plan.chains == [("x", "z")]

    def test_a_cycle_merges_nothing(self):
        plan = cta.plan_alias_merges([{"duplicate_name": "x", "canonical_names": ["z"]}], [("z", "x")])
        assert plan.pairs == [] and plan.chains == [("x", "z"), ("z", "x")]

    def test_the_reference_does_not_settle_an_attack_ambiguity(self):
        plan = cta.plan_alias_merges(ATTACK_ROWS, [("dark halo", "apt29")])
        assert ("dark halo", ["apt29", "unc2452"]) in plan.ambiguous
        assert all(d != "dark halo" for _, d in plan.pairs)


class TestReferenceChecksTheAttackRule:
    """A canonical's ``aliases`` hold every name merged into it, so the ATT&CK rule alone would
    keep folding a name a reviewer has since marked never_merge or given to another actor."""

    def test_a_name_the_reference_blocks_is_not_merged(self, reference):
        rows = [
            {"duplicate_name": "medusa", "canonical_names": ["medusa group"]},  # never_merge
            {"duplicate_name": "uac-0056", "canonical_names": ["apt29"]},  # ambiguous in the reference
        ]
        plan = cta.plan_alias_merges(rows, [], reference=reference)
        assert plan.pairs == []
        assert plan.blocked == [("medusa", "medusa group"), ("uac-0056", "apt29")]
        assert plan.candidates == 2

    def test_a_name_the_reference_gives_to_another_actor_is_a_conflict(self, reference):
        # "lazarus" is the reference's lazarus group, even when that node is not on the graph.
        rows = [{"duplicate_name": "lazarus", "canonical_names": ["andariel"]}]
        plan = cta.plan_alias_merges(rows, [], reference=reference)
        assert plan.pairs == [] and plan.conflicts == [("lazarus", ["andariel", "lazarus group"])]

    def test_a_name_the_reference_keeps_as_an_actor_is_a_conflict(self, reference):
        rows = [{"duplicate_name": "clop", "canonical_names": ["ta505"]}]
        plan = cta.plan_alias_merges(rows, [], reference=reference)
        assert plan.pairs == [] and plan.conflicts == [("clop", ["clop", "ta505"])]

    def test_agreement_and_unknown_names_keep_the_attack_pair(self, reference):
        rows = [
            {"duplicate_name": "nobelium", "canonical_names": ["apt29"]},  # the reference agrees
            {"duplicate_name": "reddelta", "canonical_names": ["mustang panda"]},  # unknown to it
        ]
        plan = cta.plan_alias_merges(rows, [], reference=reference)
        assert plan.pairs == [("apt29", "nobelium"), ("mustang panda", "reddelta")]
        assert plan.blocked == [] and plan.conflicts == [] and plan.from_attack == 2

    def test_without_the_reference_the_attack_rule_is_unchanged(self):
        rows = [{"duplicate_name": "medusa", "canonical_names": ["medusa group"]}]
        assert cta.plan_alias_merges(rows, []).pairs == [("medusa group", "medusa")]


# --------------------------------------------------------------------------- the job


def _fake_client(attack_rows, graph_rows, *, apply_exc=None):
    calls: list = []

    def run(query, **kwargs):
        calls.append((query, kwargs))
        result = MagicMock()
        if "RETURN d.name AS duplicate_name" in query:
            result.__iter__ = lambda s: iter(attack_rows)
            return result
        if "RETURN a.name AS name, a.source AS source" in query:
            result.__iter__ = lambda s: iter(graph_rows)
            return result
        if "apoc.refactor.mergeNodes" in query:
            if apply_exc is not None:
                raise apply_exc
            result.single.return_value = {
                "merged": sum(len(g["duplicates"]) for g in kwargs["groups"]),
                "canonicals": len(kwargs["groups"]),
            }
            return result
        if "AS restamped" in query:
            result.single.return_value = {"restamped": 0}
            return result
        if "AS normalised_edges" in query:
            result.single.return_value = {"normalised_edges": 0}
            return result
        raise AssertionError(f"unexpected query: {query[:120]!r}")

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False
    # Each merge batch runs in an explicit transaction (2026-10-16): its statements reach ``run`` too.
    session.begin_transaction.return_value = session
    client = MagicMock()
    client.driver = MagicMock()
    client.driver.session.return_value = session
    return client, calls


def _applies(calls):
    return [kw for q, kw in calls if "apoc.refactor.mergeNodes" in q]


@pytest.fixture
def reference_file(tmp_path, monkeypatch):
    path = write_reference(tmp_path, reference_doc())
    monkeypatch.setenv(ENV, str(path))
    return path


class TestJob:
    def test_end_to_end(self, reference_file, caplog):
        caplog.set_level(logging.INFO, logger="enrichment_jobs")
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)

        assert res["reference_candidates"] == 4
        assert res["merged"] == 5
        assert res["candidates"] == 6  # 5 pairs + the ambiguous "dark halo"
        assert (res["skipped_ambiguous"], res["skipped_conflict"], res["skipped_chain"]) == (1, 0, 0)
        (apply,) = _applies(calls)
        assert apply["groups"] == [
            {"canonical": "clop", "duplicates": ["cl0p"]},
            {"canonical": "lazarus group", "duplicates": ["apt-c-26", "lazarus"]},
            {"canonical": "mustang panda", "duplicates": ["reddelta"]},
            {"canonical": "sandworm team", "duplicates": ["sandworm"]},
        ]
        assert apply["reference_canonicals"] == ["clop", "lazarus group", "sandworm team"]
        assert "[ACTOR-ALIAS-MERGE] canonical reference 2026.10.15: 6 actors" in caplog.text
        # One read of the graph's actors, between the ATT&CK candidates and the merge.
        kinds = [q.split("RETURN")[-1].strip()[:40] for q, _ in calls[:2]]
        assert "d.name AS duplicate_name" in kinds[0] and "a.name AS name" in kinds[1]

    def test_apply_accepts_reference_canonicals_and_never_a_mitre_duplicate(self, reference_file):
        query = enrichment_jobs._ACTOR_ALIAS_MERGE_APPLY_CYPHER
        assert "WHERE $mitre_source IN coalesce(c.source, []) OR c.name IN $reference_canonicals" in query
        assert "AND NOT $mitre_source IN coalesce(d.source, [])" in query
        client, calls = _fake_client([], [graph_row("apt29", ("mitre_attck",)), graph_row("unc2452", ("mitre_attck",))])
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["merged"] == 0 and _applies(calls) == []

    def test_conflicts_are_skipped_and_counted(self, reference_file, caplog):
        attack = [
            {"duplicate_name": "lazarus", "canonical_names": ["andariel"]},  # reference: lazarus group
            {"duplicate_name": "clop", "canonical_names": ["ta505"]},  # the reference keeps clop as an actor
        ]
        client, calls = _fake_client(attack, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        # Before the reference checked the ATT&CK rule, clop was skipped as a chain (it is the
        # reference canonical of cl0p in this run); it is a conflict now, and chains cannot occur.
        assert (res["skipped_conflict"], res["skipped_chain"], res["skipped_blocked"]) == (2, 0, 0)
        merged = {(g["canonical"], d) for kw in _applies(calls) for g in kw["groups"] for d in g["duplicates"]}
        assert ("andariel", "lazarus") not in merged and ("lazarus group", "lazarus") not in merged
        assert ("ta505", "clop") not in merged and ("clop", "cl0p") in merged
        assert caplog.text.count("(conflict)") == 2

    def test_a_name_the_reference_blocks_is_skipped_end_to_end(self, reference_file, caplog):
        caplog.set_level(logging.INFO, logger="enrichment_jobs")
        attack = ATTACK_ROWS + [{"duplicate_name": "medusa", "canonical_names": ["medusa group"]}]
        client, calls = _fake_client(attack, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["skipped_blocked"] == 1 and res["merged"] == 5
        merged = {(g["canonical"], d) for kw in _applies(calls) for g in kw["groups"] for d in g["duplicates"]}
        assert ("medusa group", "medusa") not in merged
        assert "skipping 'medusa' -> 'medusa group'" in caplog.text and "(blocked)" in caplog.text
        assert "skipped_blocked=1" in caplog.text

    def test_reference_data_that_cannot_be_applied_falls_back_with_one_warning(
        self, reference_file, monkeypatch, caplog
    ):
        def boom(*args, **kwargs):
            raise TypeError("odd graph data")

        monkeypatch.setattr(enrichment_jobs, "reference_merge_candidates", boom)
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        warnings = [r.getMessage() for r in caplog.records if "canonical reference unavailable" in r.getMessage()]
        assert warnings == [
            "[ACTOR-ALIAS-MERGE] canonical reference unavailable (TypeError: odd graph data); "
            "merging by MITRE aliases only"
        ]
        (apply,) = _applies(calls)
        assert apply["groups"] == [{"canonical": "mustang panda", "duplicates": ["reddelta"]}]
        assert apply["reference_canonicals"] == []
        assert res["merged"] == 1 and res["reference_candidates"] == 0

    def test_apoc_missing_with_the_reference_is_a_warning_and_merges_nothing(self, reference_file, caplog):
        class ProcedureNotFound(Exception):
            code = "Neo.ClientError.Procedure.ProcedureNotFound"

        client, calls = _fake_client(ATTACK_ROWS, GRAPH, apply_exc=ProcedureNotFound("apoc.refactor.mergeNodes"))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert (res["apoc_missing"], res["merged"], res["errors"]) == (1, 0, 0)
        assert "APOC unavailable" in caplog.text
        assert not any("AS restamped" in q for q, _ in calls)

    def test_a_failed_batch_with_the_reference_is_counted_and_the_next_batch_runs(
        self, reference_file, monkeypatch, caplog
    ):
        monkeypatch.setattr(enrichment_jobs, "_ACTOR_ALIAS_MERGE_BATCH_SIZE", 2)
        client, calls = _fake_client(ATTACK_ROWS, GRAPH, apply_exc=RuntimeError("Can't coerce String to List"))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["errors"] == 3 and res["merged"] == 0  # 5 pairs in batches of 2
        assert caplog.text.count("FAILED (") == 3

    def test_the_per_run_cap_with_the_reference(self, reference_file, monkeypatch, caplog):
        monkeypatch.setattr(enrichment_jobs, "_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN", 2)
        monkeypatch.setattr(enrichment_jobs, "_ACTOR_ALIAS_MERGE_BATCH_SIZE", 1)
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        applies = _applies(calls)
        assert res["merged"] == 2 and len(applies) == 2
        assert [g["canonical"] for kw in applies for g in kw["groups"]] == ["clop", "lazarus group"]
        assert all(kw["reference_canonicals"] == ["clop", "lazarus group", "sandworm team"] for kw in applies)
        assert "exceed the per-run cap 2" in caplog.text

    def test_dry_run_lists_the_reference_pairs(self, reference_file, monkeypatch, caplog):
        monkeypatch.setenv(FLAG, "false")
        caplog.set_level(logging.INFO, logger="enrichment_jobs")
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["merged"] == 0 and _applies(calls) == []
        assert res["reference_candidates"] == 4
        line = next(r.getMessage() for r in caplog.records if "DRY RUN" in r.getMessage())
        assert "4 from the canonical reference" in line
        for pair in ("('cl0p', 'clop')", "('lazarus', 'lazarus group')", "('sandworm', 'sandworm team')"):
            assert pair in line

    @pytest.mark.parametrize(
        "content",
        [None, "{not json", json.dumps(reference_doc(actors=[actor("x", ["s"]), actor("z", ["s"])]))],
        ids=["missing", "malformed", "inconsistent"],
    )
    def test_unavailable_reference_falls_back_with_one_warning(self, tmp_path, monkeypatch, caplog, content):
        path = tmp_path / "canonical_threat_actors.json"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        monkeypatch.setenv(ENV, str(path))
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        warnings = [r.getMessage() for r in caplog.records if "canonical reference unavailable" in r.getMessage()]
        assert len(warnings) == 1
        assert warnings[0].startswith(WARNING_PREFIX) and warnings[0].endswith(WARNING_SUFFIX)
        # Today's rule unchanged: no read of the actors, ATT&CK pairs only.
        assert not any("a.name AS name" in q for q, _ in calls)
        (apply,) = _applies(calls)
        assert apply["groups"] == [{"canonical": "mustang panda", "duplicates": ["reddelta"]}]
        assert apply["reference_canonicals"] == []
        assert res["reference_candidates"] == 0 and res["merged"] == 1

    def test_an_unexpected_loader_error_never_fails_enrichment(self, monkeypatch, caplog):
        def boom(path=None):
            raise RuntimeError("disk on fire")

        monkeypatch.setattr(enrichment_jobs, "load_canonical_reference", boom)
        client, calls = _fake_client(ATTACK_ROWS, GRAPH)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["merged"] == 1
        assert "canonical reference unavailable (RuntimeError: disk on fire)" in caplog.text

    def test_compose_and_env_example_carry_the_path_variable(self):
        assert ENV in (REPO_ROOT / ".env.example").read_text()
        assert f"{ENV}: ${{{ENV}:-}}" in (REPO_ROOT / "docker-compose.yml").read_text()
