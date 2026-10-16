"""Tests for ``enrichment_jobs.merge_alias_duplicate_actors`` (JOB 5).

The deployed graph had the same actor under several ThreatActor nodes
(``reddelta`` / ``twill typhoon`` / ``unc6384`` next to the MITRE node
``mustang panda`` whose ``aliases[]`` lists all three). The job folds the
non-MITRE duplicates into the MITRE canonical with
``apoc.refactor.mergeNodes``. These tests drive it with a mocked
``neo4j_client.driver.session()`` (same shape as
``tests/test_pr_m3d_campaign_determinism.py``) and pin:

* the candidate Cypher excludes MITRE-sourced duplicates, requires a
  MITRE-sourced canonical, matches on ``c.aliases`` and filters placeholders;
* the ambiguity guard skips a duplicate that matches several canonicals;
* ``EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE=false`` merges nothing;
* a missing APOC plugin is a WARNING + graceful return, not a failure;
* the explicit ``mergeNodes`` property strategy (scalars discard, lists
  combine, ``.*`` discard — never the ``.*: combine`` wildcard);
* the job is registered in ``run_all_enrichment_jobs`` BEFORE
  ``build_campaign_nodes``.

These tests pin the ATT&CK-alias rule on its own: the canonical threat-actor
reference is made unavailable, so the job runs today's rule unchanged. The
reference rule is tested in ``tests/test_canonical_reference_merge.py``.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-actor-alias-merge")
os.environ.setdefault("MISP_API_KEY", "test-key-actor-alias-merge")

import enrichment_jobs  # noqa: E402
import neo4j_client  # noqa: E402

FLAG = enrichment_jobs._ACTOR_ALIAS_MERGE_ENV_FLAG


# ---------------------------------------------------------------------------
# Mock plumbing
# ---------------------------------------------------------------------------


def _is_candidate_query(q: str) -> bool:
    return "RETURN d.name AS duplicate_name" in q


def _is_apply_query(q: str) -> bool:
    return "apoc.refactor.mergeNodes" in q


def _is_restamp_query(q: str) -> bool:
    return "AS restamped" in q


def _is_normalise_query(q: str) -> bool:
    return "AS normalised_edges" in q


def _fake_client(candidate_rows, *, apply_exc=None, restamped=0, candidate_exc=None):
    """Build a MagicMock Neo4j client whose session dispatches on query text.

    ``candidate_rows`` — list of ``{"duplicate_name": ..., "canonical_names": [...]}``
    ``apply_exc``      — raised from the mergeNodes query (APOC-missing / batch error)
    ``restamped``      — value returned by each uuid re-stamp query
    Returns ``(client, calls)`` where ``calls`` is the ordered ``[(query, kwargs)]``.
    """
    calls: list = []

    def run(query, **kwargs):
        calls.append((query, kwargs))
        result = MagicMock()
        if _is_candidate_query(query):
            if candidate_exc is not None:
                raise candidate_exc
            result.__iter__ = lambda s: iter(candidate_rows)
            return result
        if _is_apply_query(query):
            if apply_exc is not None:
                raise apply_exc
            groups = kwargs["groups"]
            result.single.return_value = {
                "merged": sum(len(g["duplicates"]) for g in groups),
                "canonicals": len(groups),
            }
            return result
        if _is_restamp_query(query):
            result.single.return_value = {"restamped": restamped}
            return result
        if _is_normalise_query(query):
            result.single.return_value = {"normalised_edges": 0}
            return result
        raise AssertionError(f"unexpected query: {query[:120]!r}")

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False

    client = MagicMock()
    client.driver = MagicMock()
    client.driver.session.return_value = session
    return client, calls


MUSTANG_PANDA_ROWS = [
    {"duplicate_name": "reddelta", "canonical_names": ["mustang panda"]},
    {"duplicate_name": "twill typhoon", "canonical_names": ["mustang panda"]},
    {"duplicate_name": "unc6384", "canonical_names": ["mustang panda"]},
    {"duplicate_name": "cozy bear", "canonical_names": ["apt29"]},
]


@pytest.fixture(autouse=True)
def _quiet_pause_and_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    monkeypatch.delenv(FLAG, raising=False)
    # No canonical reference: the job falls back to the ATT&CK-alias rule alone.
    monkeypatch.setenv("EDGEGUARD_CANONICAL_THREAT_ACTORS", str(tmp_path / "missing.json"))


# ---------------------------------------------------------------------------
# Candidate query shape
# ---------------------------------------------------------------------------


class TestCandidateQuery:
    def test_candidate_cypher_excludes_mitre_duplicates_and_uses_alias_matching(self):
        client, calls = _fake_client(MUSTANG_PANDA_ROWS)
        enrichment_jobs.merge_alias_duplicate_actors(client)

        cand = [(q, kw) for q, kw in calls if _is_candidate_query(q)]
        assert len(cand) == 1, "exactly one candidate query per run"
        query, kwargs = cand[0]

        # Duplicate must NOT be MITRE-sourced; canonical MUST be.
        assert "NOT $mitre_source IN coalesce(d.source, [])" in query
        assert "$mitre_source IN coalesce(c.source, [])" in query
        assert kwargs["mitre_source"] == "mitre_attck"
        # Alias matching, case/whitespace-insensitive on both sides.
        assert "toLower(trim(d.name))" in query
        assert "x IN c.aliases" in query
        assert "toLower(trim(toString(x)))" in query
        # Never the same node.
        assert "c <> d" in query
        # Placeholder filter on BOTH the duplicate name and the alias entries,
        # using the shared node_identity sentinel set.
        assert query.count("$placeholders") >= 2
        assert "unknown" in kwargs["placeholders"]
        assert "apt" in kwargs["placeholders"]
        assert "threat actor" in kwargs["placeholders"]
        # Grouped per duplicate so the ambiguity guard can see all canonicals.
        assert "collect(DISTINCT c.name) AS canonical_names" in query

    def test_blank_rows_are_ignored(self):
        rows = [
            {"duplicate_name": "", "canonical_names": ["apt29"]},
            {"duplicate_name": "x", "canonical_names": []},
            {"duplicate_name": "y", "canonical_names": None},
        ]
        client, calls = _fake_client(rows)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["candidates"] == 0
        assert res["merged"] == 0
        assert not any(_is_apply_query(q) for q, _ in calls)


# ---------------------------------------------------------------------------
# Merge behaviour
# ---------------------------------------------------------------------------


class TestMergeBehaviour:
    def test_merges_pairs_grouped_by_canonical(self):
        client, calls = _fake_client(MUSTANG_PANDA_ROWS, restamped=3)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)

        assert res["candidates"] == 4
        assert res["merged"] == 4
        assert res["skipped_ambiguous"] == 0
        assert res["errors"] == 0
        assert res["apoc_missing"] == 0
        assert res["restamped_edges"] == 6  # 3 outgoing + 3 incoming (one batch)

        applies = [(q, kw) for q, kw in calls if _is_apply_query(q)]
        assert len(applies) == 1, "4 pairs fit in one batch"
        query, kwargs = applies[0]
        groups = kwargs["groups"]
        assert groups == [
            {"canonical": "apt29", "duplicates": ["cozy bear"]},
            {"canonical": "mustang panda", "duplicates": ["reddelta", "twill typhoon", "unc6384"]},
        ]
        assert kwargs["mitre_source"] == "mitre_attck"
        assert kwargs["strategy"] is enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY

    def test_apply_cypher_shape(self):
        client, calls = _fake_client(MUSTANG_PANDA_ROWS)
        enrichment_jobs.merge_alias_duplicate_actors(client)
        query, kwargs = next((q, kw) for q, kw in calls if _is_apply_query(q))

        # Canonical-side / duplicate-side MITRE guards re-checked at merge time
        # so two canonical actors can never be merged. Without the reference the
        # second branch of the canonical guard names no node: only a MITRE-sourced
        # canonical can be merged into.
        assert "WHERE $mitre_source IN coalesce(c.source, []) OR c.name IN $reference_canonicals\n" in query
        assert kwargs["reference_canonicals"] == []
        assert "NOT $mitre_source IN coalesce(d.source, [])" in query
        assert "d <> c" in query
        # Aliases gain the duplicate names BEFORE mergeNodes.
        alias_set = query.index("SET c.aliases = apoc.coll.toSet(coalesce(c.aliases, []) + ")
        merge_call = query.index("CALL apoc.refactor.mergeNodes(")
        assert alias_set < merge_call
        # Canonical is the FIRST node in the list (discard = canonical wins).
        assert "mergeNodes([c] + dups" in query
        assert "properties: $strategy" in query
        assert "mergeRels: true" in query
        assert "produceSelfRel: false" in query
        assert "singleElementAsArray" not in query  # it would turn SOURCED_FROM's scalar r.source into a list
        # Explainability (2026-10): the names folded in, apart from aliases (which mix every source's),
        # recorded before the merge and kept across merges ("combine", wrapped back into a list).
        merged_from = query.index("c.merged_from = apoc.coll.toSet(coalesce(c.merged_from, []) + [d IN dups | d.name])")
        assert merged_from < merge_call
        assert enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY["merged_from"] == "combine"
        assert "merged_from" in enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS
        # Collapsed parallel edges: cited ids are combined like the other provenance lists (and
        # wrapped back into a list with them), and every edge of a group first takes the strongest
        # evidence (out- and incoming), since mergeNodes keeps one edge's scalars.
        assert enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY["cited_ids"] == "combine"
        # Every list property an actor node carries is combined (2026-10-15, hosted graph: aliases,
        # misp_attribute_ids, misp_event_ids, pulse_ids, reported_techniques, source, tags,
        # uses_malware, uses_techniques, uses_tools, zone), never dropped by the wildcard.
        for prop in (
            "aliases",
            "misp_attribute_ids",
            "misp_event_ids",
            "pulse_ids",
            "reported_techniques",
            "source",
            "tags",
            "uses_malware",
            "uses_techniques",
            "uses_tools",
            "zone",
            "merged_from",
        ):
            assert enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY[prop] == "combine", prop
            assert prop in enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS, prop
        assert "cited_ids" in enrichment_jobs._ACTOR_ALIAS_MERGE_EDGE_LIST_PROPS
        assert "cited_ids" not in enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS
        out_block = query.index(enrichment_jobs._strongest_on_parallel_edges("out"))
        in_block = query.index(enrichment_jobs._strongest_on_parallel_edges("in"))
        assert out_block < merge_call and in_block < merge_call
        block = enrichment_jobs._strongest_on_parallel_edges("out")
        assert "ORDER BY coalesce(e.confidence_score, -1.0) DESC" in block
        assert "SET e.confidence_score = best.confidence_score, e.match_type = best.match_type" in block
        # TLP (2026-10): never loosened by a merge. The canonical takes the most restrictive level of
        # the group before mergeNodes (whose "discard" then keeps it), and so does every edge of a
        # collapsing group; the ranking is the writers' own (_tlp_most_restrictive_clause).
        tlp_set = query.index("c.tlp = reduce(_t = c.tlp, _d IN dups | ")
        assert tlp_set < merge_call
        assert neo4j_client._tlp_most_restrictive_clause("_t", "_d.tlp") in query
        assert enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY["tlp"] == "discard"
        assert neo4j_client._tlp_most_restrictive_clause("_t", "_e.tlp") in block
        assert "e.tlp = tlp" in block

    def test_every_list_property_is_wrapped_back_into_a_list_in_the_merge_statement(self):
        # 2026-10: "combine" stores equal values as one string (two OTX nodes of one actor both hold
        # source ["alienvault_otx"]), and apoc.coll.toSet on that string fails the whole batch.
        query = enrichment_jobs._ACTOR_ALIAS_MERGE_APPLY_CYPHER
        after_merge = query[query.index("YIELD node") :]
        list_props = enrichment_jobs._ACTOR_ALIAS_MERGE_LIST_PROPS
        assert {"aliases", "source", "zone"} <= set(list_props)
        for prop in list_props:
            wrapped = enrichment_jobs._list_or_wrapped(f"node.{prop}")
            assert f"node.{prop} = {wrapped}" in after_merge
            assert f'apoc.meta.cypher.type(node.{prop}) STARTS WITH "LIST"' in wrapped
            assert f"ELSE [node.{prop}] END" in wrapped
        assert "apoc.coll.toSet(coalesce(node." not in after_merge

    def test_restamp_queries_follow_each_merge_batch(self):
        client, calls = _fake_client(MUSTANG_PANDA_ROWS, restamped=1)
        enrichment_jobs.merge_alias_duplicate_actors(client)
        kinds = [
            "cand"
            if _is_candidate_query(q)
            else "apply"
            if _is_apply_query(q)
            else "normalise"
            if _is_normalise_query(q)
            else "restamp"
            for q, _ in calls
        ]
        # 2026-10: after the uuid re-stamps, every ``combine`` property is wrapped back into a
        # list (APOC stores equal merged values as one string — 11 actors held ``zone`` as a
        # string on the 730-day graph).
        assert kinds == ["cand", "apply", "restamp", "restamp", "normalise"]
        norm_q, norm_kw = calls[4]
        assert norm_kw["canonicals"] == ["apt29", "mustang panda"]
        assert "ELSE [c.zone] END" in norm_q and "ELSE [r.sources] END" in norm_q
        out_q, out_kw = calls[2]
        in_q, in_kw = calls[3]
        assert "-[r]->()" in out_q and "SET r.src_uuid = c.uuid" in out_q
        assert "<-[r]-()" in in_q and "SET r.trg_uuid = c.uuid" in in_q
        assert out_kw["canonicals"] == ["apt29", "mustang panda"]
        assert in_kw["canonicals"] == ["apt29", "mustang panda"]

    def test_no_candidates_is_a_clean_noop(self):
        client, calls = _fake_client([])
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res == {
            "candidates": 0,
            "merged": 0,
            "skipped_ambiguous": 0,
            "errors": 0,
            "restamped_edges": 0,
            "apoc_missing": 0,
            "reference_candidates": 0,
            "skipped_conflict": 0,
            "skipped_chain": 0,
            "skipped_blocked": 0,
        }
        # Without the reference there is no second read of the graph.
        assert len(calls) == 1 and _is_candidate_query(calls[0][0])

    def test_no_driver_returns_empty_dict(self):
        client = MagicMock()
        client.driver = None
        assert enrichment_jobs.merge_alias_duplicate_actors(client) == {}


# ---------------------------------------------------------------------------
# Ambiguity guard
# ---------------------------------------------------------------------------


class TestAmbiguityGuard:
    def test_duplicate_matching_two_canonicals_is_skipped_and_counted(self):
        rows = [
            {"duplicate_name": "sandworm", "canonical_names": ["sandworm team", "voodoo bear"]},
            {"duplicate_name": "reddelta", "canonical_names": ["mustang panda"]},
        ]
        client, calls = _fake_client(rows)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)

        assert res["skipped_ambiguous"] == 1
        assert res["merged"] == 1
        assert res["candidates"] == 2
        applies = [kw for q, kw in calls if _is_apply_query(q)]
        assert len(applies) == 1
        merged_dups = [d for g in applies[0]["groups"] for d in g["duplicates"]]
        assert "sandworm" not in merged_dups
        assert merged_dups == ["reddelta"]

    def test_only_ambiguous_candidates_means_no_merge_query(self):
        rows = [{"duplicate_name": "sandworm", "canonical_names": ["sandworm team", "voodoo bear"]}]
        client, calls = _fake_client(rows)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["skipped_ambiguous"] == 1
        assert res["merged"] == 0
        assert not any(_is_apply_query(q) for q, _ in calls)


# ---------------------------------------------------------------------------
# Env flag (dry run)
# ---------------------------------------------------------------------------


class TestEnvFlag:
    @pytest.mark.parametrize("value", ["false", "0", "no", "off", " FALSE "])
    def test_flag_off_merges_nothing_but_counts_candidates(self, monkeypatch, value):
        monkeypatch.setenv(FLAG, value)
        client, calls = _fake_client(MUSTANG_PANDA_ROWS)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)

        assert res["candidates"] == 4
        assert res["merged"] == 0
        assert res["errors"] == 0
        assert not any(_is_apply_query(q) for q, _ in calls), "dry run must not call mergeNodes"
        assert not any(_is_restamp_query(q) for q, _ in calls)

    @pytest.mark.parametrize("value", ["true", "1", "yes", "on"])
    def test_flag_on_values(self, monkeypatch, value):
        monkeypatch.setenv(FLAG, value)
        assert enrichment_jobs._actor_alias_merge_enabled() is True

    def test_flag_defaults_to_enabled(self, monkeypatch):
        monkeypatch.delenv(FLAG, raising=False)
        assert enrichment_jobs._actor_alias_merge_enabled() is True

    def test_flag_name_matches_config(self):
        assert FLAG == "EDGEGUARD_ENABLE_ACTOR_ALIAS_MERGE"
        src = (SRC / "config.py").read_text()
        env_example = (SRC.parent / ".env.example").read_text()
        assert FLAG in env_example, ".env.example must document the operator flag the job reads at call time"
        assert "ENABLE_ACTOR_ALIAS_MERGE =" not in src, (
            "config.py must not grow an import-time mirror: the job reads the env var at call time "
            "(see enrichment_jobs._actor_alias_merge_enabled) and a constant here would be read by nothing"
        )


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


class _ProcedureNotFound(Exception):
    code = "Neo.ClientError.Procedure.ProcedureNotFound"


class TestFailureHandling:
    def test_apoc_missing_by_code_returns_gracefully(self):
        exc = _ProcedureNotFound("There is no procedure with the name `apoc.refactor.mergeNodes` registered")
        client, calls = _fake_client(MUSTANG_PANDA_ROWS, apply_exc=exc)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)  # must NOT raise
        assert res["apoc_missing"] == 1
        assert res["merged"] == 0
        assert res["errors"] == 0
        assert res["candidates"] == 4
        assert not any(_is_restamp_query(q) for q, _ in calls)

    def test_apoc_missing_by_message_returns_gracefully(self):
        exc = RuntimeError("Unknown function 'apoc.coll.toSet' (line 9, column 17)")
        client, _ = _fake_client(MUSTANG_PANDA_ROWS, apply_exc=exc)
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["apoc_missing"] == 1
        assert res["merged"] == 0

    def test_is_apoc_missing_error_negative(self):
        assert enrichment_jobs._is_apoc_missing_error(RuntimeError("DeadlockDetected")) is False
        assert enrichment_jobs._is_apoc_missing_error(RuntimeError("Unknown function 'foo'")) is False

    def test_other_batch_error_is_counted_not_raised(self):
        client, _ = _fake_client(MUSTANG_PANDA_ROWS, apply_exc=RuntimeError("constraint violation"))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        assert res["errors"] == 1
        assert res["merged"] == 0
        assert res["apoc_missing"] == 0

    def test_candidate_query_failure_reraises(self):
        """Whole-session failures must fail loudly (PR-N21), unlike the
        per-batch / APOC-missing paths."""
        client, _ = _fake_client([], candidate_exc=RuntimeError("driver dead"))
        with pytest.raises(RuntimeError, match="driver dead"):
            enrichment_jobs.merge_alias_duplicate_actors(client)


# ---------------------------------------------------------------------------
# Batching + cap
# ---------------------------------------------------------------------------


class TestBatchingAndCap:
    @staticmethod
    def _rows(n: int):
        # n distinct duplicates spread over 7 canonicals
        return [{"duplicate_name": f"dup-{i:04d}", "canonical_names": [f"canon-{i % 7}"]} for i in range(n)]

    def test_pairs_are_batched_per_transaction(self):
        n = 450
        client, calls = _fake_client(self._rows(n))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        applies = [kw for q, kw in calls if _is_apply_query(q)]
        sizes = [sum(len(g["duplicates"]) for g in kw["groups"]) for kw in applies]
        assert sizes == [200, 200, 50]
        assert res["merged"] == n
        # each batch is followed by its two re-stamp queries
        assert sum(1 for q, _ in calls if _is_restamp_query(q)) == 2 * len(applies)

    def test_hard_cap_per_run(self, monkeypatch):
        monkeypatch.setattr(enrichment_jobs, "_ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN", 100)
        client, calls = _fake_client(self._rows(450))
        res = enrichment_jobs.merge_alias_duplicate_actors(client)
        applies = [kw for q, kw in calls if _is_apply_query(q)]
        assert sum(len(g["duplicates"]) for kw in applies for g in kw["groups"]) == 100
        assert res["merged"] == 100
        assert res["candidates"] == 450  # reported, not merged this run

    def test_constants_are_sane(self):
        assert 1 <= enrichment_jobs._ACTOR_ALIAS_MERGE_BATCH_SIZE <= 1000
        assert enrichment_jobs._ACTOR_ALIAS_MERGE_MAX_PAIRS_PER_RUN >= enrichment_jobs._ACTOR_ALIAS_MERGE_BATCH_SIZE


# ---------------------------------------------------------------------------
# Property strategy map
# ---------------------------------------------------------------------------


class TestPropertyStrategy:
    STRATEGY = enrichment_jobs._ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY

    def test_identity_props_discard_so_canonical_keeps_name_and_uuid(self):
        for key in ("name", "uuid", "mitre_id"):
            assert self.STRATEGY[key] == "discard"

    def test_scalars_are_explicitly_discard(self):
        scalars = (
            "description",
            "confidence_score",
            "tag",
            "active",
            "first_imported_at",
            "last_updated",
            "last_imported_from",
            "edgeguard_managed",
            "tlp",
            "retired_at",
            "retired_by",
            "last_decayed_tier",
            "last_decayed_at",
            "sophistication",
            "primary_motivation",
            "resource_level",
        )
        for key in scalars:
            assert self.STRATEGY.get(key) == "discard", key

    def test_lists_are_combine(self):
        lists = (
            "aliases",
            "source",
            "zone",
            "tags",
            "uses_techniques",
            "reported_techniques",
            "misp_event_ids",
            "misp_attribute_ids",
            "pulse_ids",
        )
        for key in lists:
            assert self.STRATEGY.get(key) == "combine", key

    def test_wildcard_is_discard_never_combine(self):
        assert self.STRATEGY[".*"] == "discard"
        assert all(v in ("discard", "combine") for v in self.STRATEGY.values())

    @pytest.mark.parametrize("label", ["actor", "malware"])
    def test_the_merged_node_keeps_the_ranked_description_with_its_source(self, label):
        """2026-10-16: ``discard`` kept the canonical's description and, where the canonical had no
        ``description_source``, took a duplicate's, so the node could name a source that did not write its
        text. The statement picks the pair the source ranking keeps among the group before the merge
        (``best_of_cypher``) and sets both on the merged node after it."""
        from description_ranking import ENTITY_DESCRIPTIONS

        query = (
            enrichment_jobs._ACTOR_ALIAS_MERGE_APPLY_CYPHER
            if label == "actor"
            else enrichment_jobs._MALWARE_TWIN_MERGE_STATEMENTS.apply
        )
        chosen = query.index(f"{ENTITY_DESCRIPTIONS.best_of_cypher('c', 'dups')} AS described")
        kept = query.index(
            "WITH c, n_dups, dups, described.description AS kept_description,\n"
            "     described.description_source AS kept_description_source"
        )
        merge_call = query.index("CALL apoc.refactor.mergeNodes(")
        set_after = query.index(
            "SET node.description = kept_description,\n    node.description_source = kept_description_source,"
        )
        assert chosen < kept < merge_call < set_after
        assert self.STRATEGY["description_source"] == "discard"


# ---------------------------------------------------------------------------
# Registration in the runner
# ---------------------------------------------------------------------------


class TestRunnerRegistration:
    def _timed_job_order(self) -> list:
        """Names of the job functions passed to ``_timed`` inside
        ``run_all_enrichment_jobs``, in source order."""
        tree = ast.parse((SRC / "enrichment_jobs.py").read_text())
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "run_all_enrichment_jobs":
                order = []
                for inner in ast.walk(node):
                    if (
                        isinstance(inner, ast.Call)
                        and isinstance(inner.func, ast.Name)
                        and inner.func.id == "_timed"
                        and len(inner.args) >= 2
                        and isinstance(inner.args[1], ast.Name)
                    ):
                        order.append(inner.args[1].id)
                return order
        raise AssertionError("run_all_enrichment_jobs not found")

    def test_registered_before_build_campaign_nodes(self):
        order = self._timed_job_order()
        assert "merge_alias_duplicate_actors" in order, "job must be registered in run_all_enrichment_jobs"
        assert order.index("merge_alias_duplicate_actors") < order.index("build_campaign_nodes"), (
            f"alias merge must run BEFORE build_campaign_nodes; got {order}"
        )
        # The other jobs keep their relative order.
        assert order == [
            "bridge_vulnerability_cve",
            "merge_alias_duplicate_actors",
            "merge_malware_attack_twins",  # 2026-10: the Malware ATT&CK-id twin merge
            "build_campaign_nodes",
            "calibrate_cooccurrence_confidence",
            "decay_ioc_confidence",
            "enrich_cve_epss",
        ]

    def test_runtime_order_and_summary_key(self, monkeypatch):
        seen: list = []

        def _rec(name):
            def _job(client):
                seen.append(name)
                return {"n": 1}

            return _job

        monkeypatch.setattr(enrichment_jobs, "bridge_vulnerability_cve", _rec("bridge"))
        monkeypatch.setattr(enrichment_jobs, "merge_alias_duplicate_actors", _rec("actor_alias_merge"))
        monkeypatch.setattr(enrichment_jobs, "merge_malware_attack_twins", _rec("malware_twin_merge"))
        monkeypatch.setattr(enrichment_jobs, "build_campaign_nodes", _rec("campaigns"))
        monkeypatch.setattr(enrichment_jobs, "calibrate_cooccurrence_confidence", _rec("calibration"))
        monkeypatch.setattr(enrichment_jobs, "decay_ioc_confidence", _rec("decay"))
        monkeypatch.setattr(enrichment_jobs, "enrich_cve_epss", _rec("epss"))

        summary = enrichment_jobs.run_all_enrichment_jobs(MagicMock())
        assert seen == [
            "bridge",
            "actor_alias_merge",
            "malware_twin_merge",
            "campaigns",
            "calibration",
            "decay",
            "epss",
        ]
        assert summary["actor_alias_merge"] == {"n": 1}
