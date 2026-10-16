"""A merge batch of the actor alias merge and the Malware twin merge is one transaction (2026-10-16).

``_run_alias_merge_batches`` runs four statements per batch: the merge (``mergeNodes``, which deletes
the duplicates and moves their relationships), the ``src_uuid`` and ``trg_uuid`` re-stamps of the
moved relationships, and the list normalisation. Each was an auto-commit transaction of its own, so
the merge was committed before the follow-ups ran. When a follow-up failed, the log reported the
batch as rolled back while the merge stood, and no later run repaired it: the duplicates were gone,
so no pair named their canonical again, and its moved relationships kept the deleted duplicate's
uuid.

The session double below keeps the driver's transaction semantics: a statement run on the session
is committed at once; the statements of an explicit transaction take effect on ``commit()`` and are
discarded on a rollback (an exception leaving the ``with`` block). The graph it models holds the
duplicates not yet folded, so a later run sees what the previous one committed. Both callers of
``_run_alias_merge_batches`` are driven end to end. The same behaviour on a real Neo4j is in
``tests/test_actor_alias_merge_neo4j.py`` and ``tests/test_malware_twin_merge_neo4j.py``.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-alias-merge-transaction")
os.environ.setdefault("MISP_API_KEY", "test-key-alias-merge-transaction")

import enrichment_jobs  # noqa: E402
from neo4j_client import NEO4J_READ_TIMEOUT  # noqa: E402

WRITE_KINDS = ("apply", "restamp_out", "restamp_in", "normalise")


def _write_kind(query: str) -> Optional[str]:
    if "apoc.refactor.mergeNodes" in query:
        return "apply"
    if "AS restamped" in query:
        return "restamp_out" if "-[r]->()" in query else "restamp_in"
    if "AS normalised_edges" in query:
        return "normalise"
    return None


class _Result:
    def __init__(self, record: Optional[dict] = None, rows: Optional[List[dict]] = None):
        self._record = record
        self._rows = rows or []
        self.read = False

    def single(self):
        self.read = True
        return self._record

    def consume(self):
        self.read = True

    def __iter__(self):
        self.read = True
        return iter(self._rows)


class _Graph:
    """The duplicates not folded yet (duplicate -> canonical) and the writes each commit made.

    ``fail`` names, per statement kind (or ``"commit"``), the occurrences (1-based, over the graph's
    lifetime) that raise, as a transient server error would."""

    def __init__(self, job: str, duplicates: Dict[str, str], fail: Optional[Dict[str, Set[int]]] = None):
        self.job = job
        self.pending = dict(duplicates)
        self.fail = fail or {}
        self.seen: Dict[str, int] = {}
        self.commits: List[List[str]] = []  # the write kinds of each commit, in order
        self.restamped: Set[str] = set()  # canonicals whose moved relationships carry their uuid
        self.transactions: List["_Transaction"] = []

    def maybe_fail(self, kind: str) -> None:
        self.seen[kind] = self.seen.get(kind, 0) + 1
        if self.seen[kind] in self.fail.get(kind, set()):
            raise RuntimeError(f"Neo.TransientError.Transaction.LockClientStopped ({kind})")

    def answer(self, kind: str, params: dict) -> _Result:
        if kind == "apply":
            return _Result({"merged": sum(len(g["duplicates"]) for g in params["groups"])})
        if kind in ("restamp_out", "restamp_in"):
            return _Result({"restamped": len(params["canonicals"])})
        return _Result({"normalised_edges": 0})

    def commit(self, writes: List[Tuple[str, dict]]) -> None:
        for kind, params in writes:
            if kind == "apply":
                for group in params["groups"]:
                    for duplicate in group["duplicates"]:
                        self.pending.pop(duplicate, None)
            elif kind == "restamp_in":
                self.restamped.update(params["canonicals"])
        self.commits.append([kind for kind, _ in writes])

    def read(self, query: str) -> _Result:
        """The candidate reads of the two jobs, from the duplicates not folded yet."""
        if "AS duplicate_name" in query:
            return _Result(
                rows=[{"duplicate_name": d, "canonical_names": [c]} for d, c in sorted(self.pending.items())]
            )
        if "d.name =~ $suffixed" in query:
            return _Result(rows=[{"name": d, "aliases": []} for d in sorted(self.pending)])
        if "AS attack_raw" in query:  # MITRE nodes whose id cannot be read: the target is the base name
            return _Result(rows=[{"name": c, "attack_raw": None} for c in sorted(set(self.pending.values()))])
        if query == enrichment_jobs.CYPHER_BASE_NODES_READ:
            return _Result(rows=[])
        raise AssertionError(f"unexpected read: {query[:120]!r}")


class _Transaction:
    """The driver's explicit transaction: writes take effect on ``commit()``; leaving the ``with``
    block on an exception rolls back, and leaving it cleanly commits (neo4j 5)."""

    def __init__(self, graph: _Graph, timeout):
        self.graph = graph
        self.timeout = timeout
        self.statements: List[Tuple[str, dict]] = []
        self.results: List[_Result] = []
        self.state = "open"

    def run(self, query, parameters=None, **kwargs):
        kind = _write_kind(query)
        assert kind is not None, f"only the merge statements run in the transaction: {query[:120]!r}"
        self.graph.maybe_fail(kind)
        self.statements.append((kind, kwargs))
        result = self.graph.answer(kind, kwargs)
        self.results.append(result)
        return result

    def commit(self):
        assert self.state == "open"
        self.graph.maybe_fail("commit")
        self.graph.commit(self.statements)
        self.state = "committed"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *exc):
        if self.state == "open":
            if exc_type is None:
                self.commit()
            else:
                self.state = "rolled back"
        return False


class _Session:
    def __init__(self, graph: _Graph):
        self.graph = graph

    def run(self, query, parameters=None, **kwargs):
        kind = _write_kind(query)
        if kind is None:
            return self.graph.read(query)
        # An auto-commit transaction: committed when the statement completes.
        self.graph.maybe_fail(kind)
        self.graph.commit([(kind, kwargs)])
        return self.graph.answer(kind, kwargs)

    def begin_transaction(self, metadata=None, timeout=None):
        tx = _Transaction(self.graph, timeout)
        self.graph.transactions.append(tx)
        return tx

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Client:
    def __init__(self, graph: _Graph):
        self.driver = self
        self._graph = graph

    def session(self, **_kwargs):
        return _Session(self._graph)


JOBS = {
    "actor": (enrichment_jobs.merge_alias_duplicate_actors, "_ACTOR_ALIAS_MERGE_BATCH_SIZE"),
    "twin": (enrichment_jobs.merge_malware_attack_twins, "_MALWARE_TWIN_MERGE_BATCH_SIZE"),
}
ONE_PAIR = {
    "actor": {"reddelta": "mustang panda"},
    "twin": {"cobalt strike - s0154": "cobalt strike"},
}
TWO_PAIRS = {
    "actor": {"cozy bear": "apt29", "reddelta": "mustang panda"},
    "twin": {"cobalt strike - s0154": "cobalt strike", "njrat - s0385": "njrat"},
}


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
    monkeypatch.delenv(enrichment_jobs._ACTOR_ALIAS_MERGE_ENV_FLAG, raising=False)
    monkeypatch.delenv(enrichment_jobs._MALWARE_TWIN_MERGE_ENV_FLAG, raising=False)
    # No canonical reference: the actor merge runs on the ATT&CK-alias rows the double answers.
    monkeypatch.setenv("EDGEGUARD_CANONICAL_THREAT_ACTORS", str(tmp_path / "missing.json"))


def _run(job: str, graph: _Graph) -> dict:
    return JOBS[job][0](_Client(graph))


@pytest.mark.parametrize("job", sorted(JOBS))
@pytest.mark.parametrize("failing", ["restamp_out", "restamp_in", "normalise", "commit"])
def test_a_failure_after_the_merge_rolls_the_whole_batch_back(job, failing, caplog):
    graph = _Graph(job, ONE_PAIR[job], fail={failing: {1}})
    with caplog.at_level(logging.ERROR, logger="enrichment_jobs"):
        res = _run(job, graph)
    assert graph.commits == [], "nothing of the batch is committed, the merge included"
    assert graph.pending == ONE_PAIR[job], "the duplicate is still a node, so a later run merges it"
    assert [tx.state for tx in graph.transactions] == ["rolled back"]
    assert (res["merged"], res["restamped_edges"], res["errors"]) == (0, 0, 1), "counted only once committed"
    assert "batch 1/1 FAILED (1 pairs rolled back)" in caplog.text


@pytest.mark.parametrize("job", sorted(JOBS))
def test_the_next_run_merges_a_batch_that_failed(job):
    """The bug hunt's case: the uuid re-stamp fails after the merge on the first run."""
    graph = _Graph(job, ONE_PAIR[job], fail={"restamp_in": {1}})
    first = _run(job, graph)
    second = _run(job, graph)
    assert (first["merged"], first["errors"]) == (0, 1)
    assert (second["merged"], second["restamped_edges"], second["errors"]) == (1, 2, 0)
    assert graph.pending == {}
    assert graph.commits == [list(WRITE_KINDS)], "the merge and its follow-ups committed together"
    assert graph.restamped == set(ONE_PAIR[job].values()), "the canonical's moved relationships carry its uuid"


@pytest.mark.parametrize("job", sorted(JOBS))
def test_a_batch_is_one_transaction_with_a_transaction_timeout(job):
    graph = _Graph(job, ONE_PAIR[job])
    res = _run(job, graph)
    assert len(graph.transactions) == 1
    tx = graph.transactions[0]
    assert tx.timeout == float(NEO4J_READ_TIMEOUT), "the timeout is the transaction's"
    assert [kind for kind, _ in tx.statements] == list(WRITE_KINDS)
    assert all("timeout" not in params for _, params in tx.statements), "on tx.run it is only a query parameter"
    assert all(result.read for result in tx.results), "every result is read before the commit"
    assert tx.state == "committed" and graph.commits == [list(WRITE_KINDS)]
    assert (res["merged"], res["restamped_edges"], res["errors"]) == (1, 2, 0)


@pytest.mark.parametrize("job", sorted(JOBS))
def test_a_failed_batch_does_not_undo_or_add_to_the_counts_of_a_committed_one(job, monkeypatch):
    monkeypatch.setattr(enrichment_jobs, JOBS[job][1], 1)
    graph = _Graph(job, TWO_PAIRS[job], fail={"normalise": {2}})
    res = _run(job, graph)
    assert [tx.state for tx in graph.transactions] == ["committed", "rolled back"]
    assert graph.commits == [list(WRITE_KINDS)]
    assert len(graph.pending) == 1
    assert (res["merged"], res["restamped_edges"], res["errors"]) == (1, 2, 1)
