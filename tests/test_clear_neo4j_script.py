"""``scripts/clear_neo4j.py`` on a database shared with ResilMesh (2026-10).

The script deleted every node of a list of labels, ``Vulnerability`` and ``CVE`` included, whoever
created them, and wrote no destructive-operations audit line. It now deletes the nodes EdgeGuard
created (``edgeguard_managed = true``) through the wipe of the fresh baseline
(``baseline_clean._wipe_neo4j`` and ``Neo4jClient.clear_edgeguard_managed``), deletes every node only
with ``--full-wipe`` after a warning and a typed confirmation (also with ``--force``), and every delete appends
an audit line, also a delete that fails part-way.

The tests run the real ``Neo4jClient`` statements against ``_Graph``, an in-memory graph that executes
the statement shapes the clear paths send and records any other statement as unknown, so a statement
that selects nodes by label alone is executed with Cypher's meaning instead of being assumed away.
The same graph drives the other callers of the shared wipe: the fresh-baseline clean
(``reset_baseline_data``) and ``edgeguard clear neo4j --edgeguard-only``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest

_REPO = Path(__file__).resolve().parent.parent
for _p in (_REPO / "src", _REPO / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import clear_neo4j  # noqa: E402

import baseline_checkpoint  # noqa: E402
import destructive_ops_audit  # noqa: E402
import neo4j_client  # noqa: E402

# --------------------------------------------------------------------------- #
# In-memory graph that executes the statements of the clear paths
# --------------------------------------------------------------------------- #

_NODE = r"\((?P<var>\w+)(?::(?P<label>\w+))?\)"
# A count never deletes; the lookahead keeps a delete statement that ends in ``RETURN count(n)`` out.
_COUNT = re.compile(
    rf"^(?!.*\bDELETE\b)MATCH {_NODE}(?: WHERE (?P<pred>.+?))? RETURN count\((?P=var)\) (?:AS|as) (?P<alias>\w+)$"
)
_BREAKDOWN = re.compile(
    r"^MATCH \(n\) WHERE (?P<pred>.+?) RETURN labels\(n\)\[0\] AS label, count\(n\) AS cnt "
    r"ORDER BY cnt DESC LIMIT (?P<limit>\d+)$"
)
_NODE_DELETE = re.compile(
    rf"^MATCH {_NODE}(?: WHERE (?P<pred>.+?))?(?: WITH (?P=var) LIMIT (?P<limit>\d+))? "
    r"(?P<detach>DETACH )?DELETE (?P=var)(?: RETURN count\((?P=var)\) (?:AS|as) deleted)?$"
)
_REL_DELETE = re.compile(
    r"^MATCH (?:\(\)-\[r\]->\(\)|\(n(?::(?P<label>\w+))?\)-\[r\]-\(\) WHERE (?P<pred>.+?))"
    r"(?: WITH DISTINCT r LIMIT (?P<limit>\d+))? DELETE r(?P<ret> RETURN count\(r\) AS deleted)?$"
)
_SOURCE_MERGE = "MERGE (s:Source {source_id: $source_id})"

# The predicates the clear paths use, with Cypher's meaning: a missing property is null, null is not
# true, and a value of another type (the string "true") is not equal to the boolean true.
_PREDICATES = {
    "n.edgeguard_managed = true": lambda p: p.get("edgeguard_managed") is True,
    "coalesce(n.edgeguard_managed, false) <> true": lambda p: p.get("edgeguard_managed") is not True,
    "n.edgeguard_enriched = true": lambda p: p.get("edgeguard_enriched") is True,
}


class _Result:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def single(self) -> Optional[Dict[str, Any]]:
        return self._rows[0] if self._rows else None

    def consume(self) -> None:
        return None

    def __iter__(self):
        return iter(self._rows)


class _Graph:
    """Nodes and relationships plus every statement it was sent."""

    def __init__(self) -> None:
        self.nodes: Dict[int, Dict[str, Any]] = {}
        self.rels: Dict[int, Dict[str, Any]] = {}
        self.statements: List[str] = []
        self.unknown: List[str] = []
        self.fail_on: Optional[str] = None
        # (substring, n, error): the n-th statement that contains the substring raises the error, once.
        self.fail_nth: Optional[Tuple[str, int, BaseException]] = None
        self._fail_seen = 0
        self._next = 0

    # -- building ----------------------------------------------------------------
    def add_node(self, *labels: str, **props: Any) -> int:
        self._next += 1
        self.nodes[self._next] = {"labels": list(labels), "props": dict(props)}
        return self._next

    def add_rel(self, a: int, rel_type: str, b: int, **props: Any) -> int:
        self._next += 1
        self.rels[self._next] = {"a": a, "b": b, "type": rel_type, "props": dict(props)}
        return self._next

    # -- reading -----------------------------------------------------------------
    def node_ids(self) -> set:
        return set(self.nodes)

    def rel_types(self) -> set:
        return {r["type"] for r in self.rels.values()}

    # -- executing ---------------------------------------------------------------
    def _matches(self, node_id: int, label: Optional[str], pred: Optional[str]) -> bool:
        node = self.nodes[node_id]
        if label is not None and label not in node["labels"]:
            return False
        if pred is None:
            return True
        terms = pred.split(" AND ")
        if any(t not in _PREDICATES for t in terms):
            raise AssertionError(f"unknown predicate: {pred}")
        return all(_PREDICATES[t](node["props"]) for t in terms)

    def _select(self, label: Optional[str], pred: Optional[str]) -> List[int]:
        return [nid for nid in list(self.nodes) if self._matches(nid, label, pred)]

    def execute(self, query: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        q = " ".join(str(query).split())
        self.statements.append(q)
        if self.fail_on and self.fail_on in q:
            raise RuntimeError(f"injected failure on: {q}")
        if self.fail_nth and self.fail_nth[0] in q:
            self._fail_seen += 1
            if self._fail_seen == self.fail_nth[1]:
                raise self.fail_nth[2]
        if q.startswith(_SOURCE_MERGE):
            return self._merge_source(params)
        m = _COUNT.match(q)
        if m:
            return [{m["alias"]: len(self._select(m["label"], m["pred"]))}]
        m = _BREAKDOWN.match(q)
        if m:
            counts: Dict[str, int] = {}
            for nid in self._select(None, m["pred"]):
                first = self.nodes[nid]["labels"][0]
                counts[first] = counts.get(first, 0) + 1
            rows = sorted(counts.items(), key=lambda kv: -kv[1])[: int(m["limit"])]
            return [{"label": lbl, "cnt": cnt} for lbl, cnt in rows]
        m = _REL_DELETE.match(q)
        if m:
            if m["pred"] is None:
                hit = list(self.rels)
            else:
                chosen = set(self._select(m["label"], m["pred"]))
                hit = [rid for rid, r in self.rels.items() if r["a"] in chosen or r["b"] in chosen]
            if m["limit"]:
                hit = hit[: int(m["limit"])]
            for rid in hit:
                del self.rels[rid]
            return [{"deleted": len(hit)}] if m["ret"] else []
        m = _NODE_DELETE.match(q)
        if m:
            chosen = self._select(m["label"], m["pred"])
            if m["limit"]:
                chosen = chosen[: int(m["limit"])]
            attached = [rid for rid, r in self.rels.items() if r["a"] in chosen or r["b"] in chosen]
            if attached and not m["detach"]:
                raise RuntimeError("Cannot delete a node that still has relationships")
            for rid in attached:
                del self.rels[rid]
            for nid in chosen:
                del self.nodes[nid]
            return [{"deleted": len(chosen)}]
        self.unknown.append(q)
        raise AssertionError(f"statement the fake graph does not know: {q}")

    def _merge_source(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        for node in self.nodes.values():
            if "Source" in node["labels"] and node["props"].get("source_id") == params["source_id"]:
                if node["props"].get("edgeguard_managed") is not True:
                    node["props"]["edgeguard_enriched"] = True
                node["props"]["name"] = params["name"]
                return []
        self.add_node(
            "Source",
            source_id=params["source_id"],
            name=params["name"],
            uuid=params["source_uuid"],
            edgeguard_managed=True,
        )
        return []


class _Session:
    def __init__(self, graph: _Graph):
        self.graph = graph

    def __enter__(self) -> "_Session":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def run(self, query: Any, parameters: Optional[Dict[str, Any]] = None, **kwargs: Any) -> _Result:
        params = dict(parameters or {})
        params.update({k: v for k, v in kwargs.items() if k != "timeout"})
        return _Result(self.graph.execute(query, params))


class _Driver:
    def __init__(self, graph: _Graph):
        self.graph = graph

    def session(self, **_kwargs: Any) -> _Session:
        return _Session(self.graph)

    def close(self) -> None:
        return None


def _client(graph: _Graph):
    """A real ``Neo4jClient`` whose driver is the in-memory graph."""
    client = neo4j_client.Neo4jClient.__new__(neo4j_client.Neo4jClient)
    client.driver = _Driver(graph)
    client._connection_healthy = True
    client.connect = lambda: True  # type: ignore[method-assign]
    return client


# --------------------------------------------------------------------------- #
# The shared database: EdgeGuard's nodes beside a partner's
# --------------------------------------------------------------------------- #


class _Shared:
    """Ids of the nodes of ``_shared_graph``."""

    def __init__(self) -> None:
        g = _Graph()
        # Created by EdgeGuard
        self.indicator = g.add_node("Indicator", value="203.0.113.7", edgeguard_managed=True)
        self.malware = g.add_node("Malware", name="emotet", edgeguard_managed=True)
        self.eg_vuln = g.add_node("Vulnerability", cve_id="CVE-2024-0001", edgeguard_managed=True)
        self.eg_cve = g.add_node("CVE", cve_id="CVE-2024-0001", edgeguard_managed=True)
        self.source = g.add_node("Source", source_id="alienvault_otx", edgeguard_managed=True)
        # Created by a partner first; the CVE was later enriched by EdgeGuard
        self.p_vuln = g.add_node("Vulnerability", cve_id="CVE-2023-9999", status="open")
        self.p_cve = g.add_node("CVE", cve_id="CVE-2023-9999", edgeguard_enriched=True)
        self.host = g.add_node("Host", hostname="srv-01")
        # Marker values that are not the boolean true
        self.false_marker = g.add_node("Indicator", value="198.51.100.1", edgeguard_managed=False)
        self.string_marker = g.add_node("Indicator", value="198.51.100.2", edgeguard_managed="true")
        g.add_rel(self.indicator, "INDICATES", self.malware, edgeguard_managed=True)
        g.add_rel(self.indicator, "SOURCED_FROM", self.source, edgeguard_managed=True)
        g.add_rel(self.eg_vuln, "REFERS_TO", self.eg_cve, edgeguard_managed=True)
        g.add_rel(self.indicator, "EXPLOITS", self.p_cve, edgeguard_managed=True)
        g.add_rel(self.host, "HAS_VULNERABILITY", self.p_vuln)  # the partner's own relationship
        g.add_rel(self.p_vuln, "REFERS_TO", self.p_cve, edgeguard_managed=True)  # EdgeGuard edge, partner nodes
        self.graph = g
        self.edgeguard = {self.indicator, self.malware, self.eg_vuln, self.eg_cve, self.source}
        self.partner = {self.p_vuln, self.p_cve, self.host, self.false_marker, self.string_marker}


@pytest.fixture
def shared():
    return _Shared()


@pytest.fixture
def audit_file(tmp_path, monkeypatch):
    path = tmp_path / "destructive_ops.jsonl"
    monkeypatch.setenv(destructive_ops_audit.AUDIT_PATH_ENV, str(path))
    return path


@pytest.fixture
def confirm_full_wipe(monkeypatch):
    """Answers every prompt with the typed full-wipe confirmation; returns the prompts asked."""
    prompts: List[str] = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return clear_neo4j.FULL_WIPE_CONFIRMATION

    monkeypatch.setattr("builtins.input", answer)
    return prompts


@pytest.fixture
def small_batches(monkeypatch):
    """Node batches of 2 and no retry sleep, so a failure can fall between two batches of one clear."""
    monkeypatch.setattr(neo4j_client.Neo4jClient, "_CLEAR_NODE_BATCH", 2)
    monkeypatch.setattr(neo4j_client.time, "sleep", lambda _s: None)


@pytest.fixture
def checkpoint_calls(monkeypatch):
    calls: List[Dict[str, Any]] = []
    monkeypatch.setattr(baseline_checkpoint, "clear_checkpoint", lambda **kw: calls.append(kw))
    return calls


def _audit_lines(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _run_script(monkeypatch, graph: _Graph, *argv: str) -> int:
    """Run the script's entry point as ``python3 scripts/clear_neo4j.py <argv>`` against ``graph``."""
    client = _client(graph)
    monkeypatch.setattr(clear_neo4j, "Neo4jClient", lambda *a, **kw: client)
    monkeypatch.setattr(sys, "argv", ["clear_neo4j.py", *argv])
    try:
        rc = clear_neo4j.main()
    except SystemExit as exc:  # argparse errors, and the entry point of earlier versions
        rc = exc.code
    return rc


def _deleting_statements(graph: _Graph) -> List[str]:
    return [q for q in graph.statements if re.search(r"\bDELETE\b", q)]


# --------------------------------------------------------------------------- #
# Default scope: only what EdgeGuard created
# --------------------------------------------------------------------------- #


def test_default_run_deletes_only_the_nodes_edgeguard_created(monkeypatch, shared, audit_file, checkpoint_calls):
    rc = _run_script(monkeypatch, shared.graph, "--force", "--no-recreate")

    assert rc == 0
    assert shared.graph.node_ids() == shared.partner, "partner Vulnerability / CVE / Host and unmarked nodes stay"
    assert shared.graph.rel_types() == {"HAS_VULNERABILITY", "REFERS_TO"}
    assert not shared.graph.unknown
    assert checkpoint_calls == [{"include_incremental": True}]


def test_default_scope_never_selects_a_node_without_the_marker(monkeypatch, shared, audit_file, checkpoint_calls):
    _run_script(monkeypatch, shared.graph, "--force", "--no-recreate")

    deletes = _deleting_statements(shared.graph)
    assert deletes, "the run deleted something"
    for q in deletes:
        assert "WHERE n.edgeguard_managed = true" in q, q
    assert not any(q.startswith("MATCH ()-[r]->()") for q in shared.graph.statements)
    assert not any(re.match(r"MATCH \(\w+(:\w+)?\) (WITH|DETACH|DELETE)", q) for q in shared.graph.statements)
    assert not shared.graph.unknown


def test_default_run_recreates_the_source_nodes(monkeypatch, shared, audit_file, checkpoint_calls):
    rc = _run_script(monkeypatch, shared.graph, "--force")

    assert rc == 0
    sources = [n for n in shared.graph.nodes.values() if "Source" in n["labels"]]
    assert {n["props"]["source_id"] for n in sources} == set(neo4j_client.SOURCES)
    assert all(n["props"]["edgeguard_managed"] is True for n in sources)
    assert shared.partner <= shared.graph.node_ids()


def test_dry_run_deletes_nothing_and_reports_the_scope(monkeypatch, shared, audit_file, checkpoint_calls, capsys):
    before_nodes, before_rels = dict(shared.graph.nodes), dict(shared.graph.rels)

    rc = _run_script(monkeypatch, shared.graph, "--dry-run")

    out = capsys.readouterr().out
    assert rc == 0
    assert shared.graph.nodes == before_nodes and shared.graph.rels == before_rels
    assert not _deleting_statements(shared.graph)
    assert "In scope: 5 node(s) EdgeGuard created (edgeguard_managed = true)" in out
    assert "Kept: 5 node(s) EdgeGuard did not create (1 of them enriched by EdgeGuard)" in out
    assert _audit_lines(audit_file) == [], "a dry run deletes nothing and records nothing"
    assert checkpoint_calls == []


# --------------------------------------------------------------------------- #
# --label: the EdgeGuard-created nodes of one label
# --------------------------------------------------------------------------- #


def test_label_deletes_only_the_edgeguard_nodes_of_that_label(monkeypatch, shared, audit_file, checkpoint_calls):
    rc = _run_script(monkeypatch, shared.graph, "--label", "Vulnerability")

    assert rc == 0
    assert shared.graph.node_ids() == (shared.edgeguard | shared.partner) - {shared.eg_vuln}
    assert shared.p_vuln in shared.graph.nodes, "the partner's Vulnerability stays"
    for q in _deleting_statements(shared.graph):
        assert "MATCH (n:Vulnerability)" in q and "WHERE n.edgeguard_managed = true" in q, q
    assert not shared.graph.unknown


def test_a_label_outside_the_allow_list_is_refused_before_any_statement(
    monkeypatch, shared, audit_file, checkpoint_calls
):
    rc = _run_script(monkeypatch, shared.graph, "--label", "Indicator) DETACH DELETE (m")

    assert rc == 1
    assert shared.graph.statements == []
    assert _audit_lines(audit_file) == [] and checkpoint_calls == []


def test_label_cannot_be_combined_with_full_wipe(monkeypatch, shared, audit_file, checkpoint_calls):
    rc = _run_script(monkeypatch, shared.graph, "--label", "Vulnerability", "--full-wipe", "--force")

    assert rc == 2
    assert shared.graph.statements == []
    assert len(shared.graph.nodes) == 10


# --------------------------------------------------------------------------- #
# --full-wipe: every node, after a warning and a typed confirmation
# --------------------------------------------------------------------------- #


def test_full_wipe_without_force_asks_and_aborts_on_a_wrong_answer(
    monkeypatch, shared, audit_file, checkpoint_calls, capsys
):
    prompts: List[str] = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", answer)
    rc = _run_script(monkeypatch, shared.graph, "--full-wipe")

    out = capsys.readouterr().out
    assert rc == 1
    assert len(prompts) == 1 and clear_neo4j.FULL_WIPE_CONFIRMATION in prompts[0]
    assert "EVERY node in the database, 10 node(s)" in out
    assert "5 of them EdgeGuard did not create" in out
    assert len(shared.graph.nodes) == 10 and not _deleting_statements(shared.graph)
    assert _audit_lines(audit_file) == [] and checkpoint_calls == []


def test_full_wipe_aborts_when_stdin_is_closed(monkeypatch, shared, audit_file, checkpoint_calls):
    def closed(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", closed)
    rc = _run_script(monkeypatch, shared.graph, "--full-wipe")

    assert rc == 1
    assert len(shared.graph.nodes) == 10 and not _deleting_statements(shared.graph)


def test_full_wipe_with_force_still_asks_and_aborts_on_a_wrong_answer(
    monkeypatch, shared, audit_file, checkpoint_calls
):
    """``--force`` selects the default delete; it does not answer the whole-database confirmation."""
    prompts: List[str] = []

    def answer(prompt: str) -> str:
        prompts.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", answer)
    rc = _run_script(monkeypatch, shared.graph, "--full-wipe", "--force")

    assert rc == 1
    assert len(prompts) == 1 and clear_neo4j.FULL_WIPE_CONFIRMATION in prompts[0]
    assert len(shared.graph.nodes) == 10 and not _deleting_statements(shared.graph)
    assert _audit_lines(audit_file) == [] and checkpoint_calls == []


def test_full_wipe_with_the_typed_confirmation_deletes_every_node(
    monkeypatch, shared, audit_file, checkpoint_calls, confirm_full_wipe
):
    rc = _run_script(monkeypatch, shared.graph, "--full-wipe", "--no-recreate")

    assert rc == 0
    assert len(confirm_full_wipe) == 1
    assert shared.graph.nodes == {} and shared.graph.rels == {}
    assert not shared.graph.unknown
    assert checkpoint_calls == [{"include_incremental": True}]


def test_only_full_wipe_sends_an_unscoped_delete(monkeypatch, audit_file, checkpoint_calls, confirm_full_wipe):
    """The whole-database statements of ``clear_all`` appear with ``--full-wipe`` and in no other mode."""
    unscoped = re.compile(r"^MATCH (\(\)-\[r\]->\(\)|\(n\) WITH n LIMIT)")
    for argv in (("--force",), ("--label", "Indicator"), ("--force", "--no-recreate")):
        shared = _Shared()
        _run_script(monkeypatch, shared.graph, *argv)
        assert not any(unscoped.match(q) for q in shared.graph.statements), argv
    assert confirm_full_wipe == [], "only --full-wipe asks"
    shared = _Shared()
    _run_script(monkeypatch, shared.graph, "--full-wipe", "--force")
    assert any(unscoped.match(q) for q in shared.graph.statements)
    assert len(confirm_full_wipe) == 1


# --------------------------------------------------------------------------- #
# The destructive-operations audit line, one per deleting run
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("argv", "operation", "affected", "scope", "details"),
    [
        (
            ("--force",),
            "clear_edgeguard_managed",
            5,
            "edgeguard_managed = true",
            {"left_untouched": 5, "enriched_kept": 1},
        ),
        (
            ("--label", "Vulnerability"),
            "clear_edgeguard_managed",
            1,
            "edgeguard_managed = true AND n:Vulnerability",
            {"left_untouched": 1, "enriched_kept": 0, "label": "Vulnerability"},
        ),
        (("--full-wipe",), "clear_all", 10, "every node", None),
    ],
    ids=["default", "label", "full-wipe"],
)
def test_every_deleting_mode_writes_one_audit_line(
    monkeypatch, audit_file, checkpoint_calls, confirm_full_wipe, argv, operation, affected, scope, details
):
    shared = _Shared()
    rc = _run_script(monkeypatch, shared.graph, *argv)

    assert rc == 0
    lines = _audit_lines(audit_file)
    assert len(lines) == 1, lines
    line = lines[0]
    assert (line["operation"], line["target"], line["affected"], line["scope"]) == (operation, "neo4j", affected, scope)
    assert line.get("details") == details
    assert line["actor"]["program"] == "clear_neo4j.py"
    assert line["actor"]["user"]


def test_a_run_with_nothing_in_scope_still_writes_its_audit_line(monkeypatch, audit_file, checkpoint_calls):
    graph = _Graph()
    graph.add_node("Host", hostname="srv-01")

    rc = _run_script(monkeypatch, graph, "--force", "--no-recreate")

    assert rc == 0
    assert graph.node_ids() == {1}
    [line] = _audit_lines(audit_file)
    assert (line["operation"], line["affected"]) == ("clear_edgeguard_managed", 0)


def test_a_failed_delete_exits_1_keeps_the_checkpoints_and_records_what_it_deleted(
    monkeypatch, shared, audit_file, checkpoint_calls
):
    """The node batches fail after the relationship batches deleted the 4 relationships of EdgeGuard's nodes."""
    shared.graph.fail_on = "DETACH DELETE"

    rc = _run_script(monkeypatch, shared.graph, "--force")

    assert rc == 1
    assert checkpoint_calls == []
    assert len(shared.graph.rels) == 2 and len(shared.graph.nodes) == 10
    [line] = _audit_lines(audit_file)
    assert (line["operation"], line["affected"], line["scope"]) == (
        "clear_edgeguard_managed",
        0,
        "edgeguard_managed = true",
    )
    assert line["details"] == {
        "left_untouched": 5,
        "enriched_kept": 1,
        "relationships_deleted": 4,
        "outcome": "failed",
        "error": "RuntimeError",
    }


def test_a_delete_that_fails_before_deleting_anything_records_nothing(
    monkeypatch, shared, audit_file, checkpoint_calls
):
    shared.graph.fail_on = "DELETE r"

    rc = _run_script(monkeypatch, shared.graph, "--force")

    assert rc == 1
    assert len(shared.graph.rels) == 6 and len(shared.graph.nodes) == 10
    assert _audit_lines(audit_file) == []


def _run_edgeguard_clear(edgeguard_only: bool):
    def run(monkeypatch, graph: _Graph) -> int:
        import edgeguard

        client = _client(graph)
        monkeypatch.setattr("neo4j_client.Neo4jClient", lambda *a, **kw: client)
        return edgeguard.cmd_clear_neo4j(argparse.Namespace(force=True, edgeguard_only=edgeguard_only))

    return run


def _run_fresh_baseline_clean(monkeypatch, graph: _Graph) -> int:
    import baseline_clean

    client = _client(graph)
    monkeypatch.setattr("neo4j_client.Neo4jClient", lambda *a, **kw: client)
    monkeypatch.setattr(baseline_clean, "_probe_misp", lambda *a, **kw: (0, None))
    monkeypatch.setattr(baseline_clean, "_probe_checkpoint", lambda: (0, None))
    monkeypatch.setattr(baseline_clean, "_wipe_checkpoints", lambda: None)
    monkeypatch.setattr(baseline_clean, "_wipe_misp_events", lambda *a, **kw: 0)
    monkeypatch.setattr(baseline_clean.time, "sleep", lambda _s: None)
    try:
        baseline_clean.reset_baseline_data(settle_seconds=0.0, verify_timeout_seconds=5.0)
    except baseline_clean.BaselineCleanError:
        return 1
    return 0


def _run_script_with(*argv: str):
    def run(monkeypatch, graph: _Graph) -> int:
        return _run_script(monkeypatch, graph, *argv)

    return run


@pytest.mark.parametrize(
    ("runner", "operation", "relationships_deleted", "nodes_left"),
    [
        (_run_script_with("--force"), "clear_edgeguard_managed", 4, 10),
        (_run_script_with("--label", "Vulnerability"), "clear_edgeguard_managed", 1, 10),
        (_run_script_with("--full-wipe"), "clear_all", 6, 10),
        (_run_edgeguard_clear(edgeguard_only=True), "clear_edgeguard_managed", 4, 10),
        (_run_edgeguard_clear(edgeguard_only=False), "clear_all", 6, 10),
        (_run_fresh_baseline_clean, "clear_edgeguard_managed", 4, 10),
    ],
    ids=[
        "clear_neo4j.py",
        "clear_neo4j.py --label",
        "clear_neo4j.py --full-wipe",
        "edgeguard clear neo4j --edgeguard-only",
        "edgeguard clear neo4j",
        "fresh-baseline clean",
    ],
)
def test_every_caller_records_a_delete_that_fails_part_way(
    monkeypatch,
    shared,
    audit_file,
    checkpoint_calls,
    confirm_full_wipe,
    runner,
    operation,
    relationships_deleted,
    nodes_left,
):
    """A clear that fails after its relationship batches writes one line with what it deleted, for each caller."""
    shared.graph.fail_on = "DETACH DELETE"

    rc = runner(monkeypatch, shared.graph)

    assert rc == 1
    assert len(shared.graph.nodes) == nodes_left
    assert len(shared.graph.rels) == 6 - relationships_deleted
    [line] = _audit_lines(audit_file)
    assert (line["operation"], line["target"], line["affected"]) == (operation, "neo4j", 0)
    assert line["details"]["outcome"] == "failed"
    assert line["details"]["relationships_deleted"] == relationships_deleted
    assert line["details"]["error"] == "RuntimeError"


@pytest.mark.parametrize(
    ("argv", "operation", "nodes_left", "first_attempt", "second_attempt"),
    [
        (("--force", "--no-recreate"), "clear_edgeguard_managed", 5, (2, 4), 3),
        (("--full-wipe", "--no-recreate"), "clear_all", 0, (2, 6), 8),
    ],
    ids=["default", "full-wipe"],
)
def test_a_retried_delete_records_every_node_it_deleted(
    monkeypatch,
    shared,
    audit_file,
    checkpoint_calls,
    confirm_full_wipe,
    small_batches,
    argv,
    operation,
    nodes_left,
    first_attempt,
    second_attempt,
):
    """A transient error on the second node batch: the retry deletes the rest, and the two attempts' lines add up."""
    before = len(shared.graph.nodes)
    shared.graph.fail_nth = (
        "DETACH DELETE",
        2,
        neo4j_client.neo4j_exceptions.TransientError("Neo.TransientError.General.OutOfMemoryError"),
    )

    rc = _run_script(monkeypatch, shared.graph, *argv)

    assert rc == 0
    assert len(shared.graph.nodes) == nodes_left
    failed, completed = _audit_lines(audit_file)
    assert failed["operation"] == completed["operation"] == operation
    assert (failed["affected"], failed["details"]["relationships_deleted"]) == first_attempt
    assert (failed["details"]["outcome"], failed["details"]["error"]) == ("failed", "TransientError")
    assert completed["affected"] == second_attempt
    assert "outcome" not in (completed.get("details") or {})
    assert failed["affected"] + completed["affected"] == before - nodes_left


def test_no_action_prints_help_and_exits_1(monkeypatch, shared, audit_file, checkpoint_calls, capsys):
    rc = _run_script(monkeypatch, shared.graph)

    assert rc == 1
    assert shared.graph.statements == []
    assert "No action specified" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# The other callers of the shared wipe, end to end on the same graph
# --------------------------------------------------------------------------- #


def test_the_fresh_baseline_clean_keeps_partner_data(monkeypatch, shared, audit_file):
    import baseline_clean

    client = _client(shared.graph)
    monkeypatch.setattr("neo4j_client.Neo4jClient", lambda *a, **kw: client)
    monkeypatch.setattr(baseline_clean, "_probe_misp", lambda *a, **kw: (0, None))
    monkeypatch.setattr(baseline_clean, "_probe_checkpoint", lambda: (0, None))
    monkeypatch.setattr(baseline_clean, "_wipe_checkpoints", lambda: None)
    monkeypatch.setattr(baseline_clean, "_wipe_misp_events", lambda *a, **kw: 0)
    monkeypatch.setattr(baseline_clean.time, "sleep", lambda _s: None)

    result = baseline_clean.reset_baseline_data(settle_seconds=0.0, verify_timeout_seconds=5.0)

    assert result.before.neo4j_count == 5 and result.before.neo4j_total_count == 10
    assert shared.graph.node_ids() == shared.partner
    assert not shared.graph.unknown
    [line] = _audit_lines(audit_file)
    assert (line["operation"], line["affected"]) == ("clear_edgeguard_managed", 5)


def test_edgeguard_clear_neo4j_edgeguard_only_keeps_partner_data(monkeypatch, shared, audit_file):
    import edgeguard

    client = _client(shared.graph)
    monkeypatch.setattr("neo4j_client.Neo4jClient", lambda *a, **kw: client)

    rc = edgeguard.cmd_clear_neo4j(argparse.Namespace(force=True, edgeguard_only=True))

    assert rc == 0
    assert shared.graph.node_ids() == shared.partner
    assert not shared.graph.unknown
    [line] = _audit_lines(audit_file)
    assert (line["operation"], line["affected"], line["details"]) == (
        "clear_edgeguard_managed",
        5,
        {"left_untouched": 5, "enriched_kept": 1},
    )


def test_the_shared_wipe_refuses_a_label_with_the_all_scope_before_touching_the_client():
    import baseline_clean

    graph = _Graph()
    client = _client(graph)
    with pytest.raises(ValueError, match="label"):
        baseline_clean._wipe_neo4j(client, baseline_clean.WIPE_SCOPE_ALL, label="Indicator")
    assert graph.statements == []


def test_the_script_uses_the_wipe_of_the_fresh_baseline():
    """One deletion path: the script calls ``baseline_clean._wipe_neo4j``, which the baseline clean calls."""
    import baseline_clean

    seen: List[tuple] = []

    def fake_wipe(client: Any, scope: str = baseline_clean.WIPE_SCOPE_EDGEGUARD, *, label: Optional[str] = None):
        seen.append((scope, label))

    graph = _Graph()
    client = _client(graph)
    with (
        patch.object(baseline_clean, "_wipe_neo4j", fake_wipe),
        patch.object(baseline_checkpoint, "clear_checkpoint", lambda **kw: None),
        patch.object(clear_neo4j, "Neo4jClient", lambda *a, **kw: client),
        patch.object(sys, "argv", ["clear_neo4j.py", "--force", "--no-recreate"]),
    ):
        assert clear_neo4j.main() == 0
    assert seen == [(baseline_clean.WIPE_SCOPE_EDGEGUARD, None)]
