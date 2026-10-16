"""Every Neo4j write result is read where the caller's error handling can see its error (2026-10).

The neo4j 5 driver returns from ``session.run`` once the server has accepted a statement. An error
the server meets while it executes or commits the statement (a deadlock, a lock or transaction
timeout, a constraint violation, a value it cannot convert) arrives with the result. A result nobody
reads is read by ``Session.close``, which logs that error as a WARNING and does not raise it; a
result still unread when the same session runs its next statement is read there, so its error is
raised against that next statement. Until 2026-10-16 the batch MERGEs, the single-item merges, the
relationship groups of the MISP sync and the other write paths left their results unread (the batch
helper read it in the counter inspection, which logged the error at DEBUG and went on): failed rows
counted as written, no retry ran, and the sync run stayed green.

The tests drive the real driver against ``tests/fake_bolt.py``, which fails the result of a chosen
statement as a Neo4j server reports an execution error; ``tests/test_write_results_neo4j.py`` checks
the batch and single-item paths on a real Neo4j. ``TestNoWriteResultIsDiscarded`` finds a
``session.run`` or ``tx.run`` result in ``src/`` that is discarded as a bare statement or assigned to
a name its function never reads; a result read on one path and not on another is left to the
behavioural tests.
"""

from __future__ import annotations

import ast
import logging
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
for _p in (SRC, TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from fake_bolt import FakeBolt, count, fail  # noqa: E402

import enrichment_jobs  # noqa: E402
import neo4j_client as nc  # noqa: E402

DEADLOCK = "Neo.TransientError.Transaction.DeadlockDetected"  # retryable
TYPE_ERROR = "Neo.ClientError.Statement.TypeError"  # terminal

INDICATOR_BATCH = "MERGE (n:Indicator"
MALWARE_MERGE = "MERGE (n:Malware"
SOURCED_FROM_UPSERT = "MERGE (n)-[r:SOURCED_FROM]->(s)"
ATTRIBUTED_TO_GROUP = "MERGE (m)-[r:ATTRIBUTED_TO]->(a)"
INDICATES_GROUP = "MERGE (i)-[r:INDICATES]->(m)"


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setattr(nc.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(nc, "query_pause", lambda *_a, **_k: None)
    monkeypatch.setattr(enrichment_jobs, "query_pause", lambda *_a, **_k: None)
    monkeypatch.delenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", raising=False)


@pytest.fixture
def bolt():
    """``bolt(*rules)`` → ``(server, client)``: a fake server failing the given results, and a
    connected ``Neo4jClient`` (wrapped driver, as in production). Both are closed afterwards."""
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


def _indicators(n: int = 3):
    return [
        {"indicator_type": "ipv4", "value": f"203.0.113.{i}", "tag": "alienvault_otx", "zone": ["global"]}
        for i in range(1, n + 1)
    ]


def _relationships():
    """Two ATTRIBUTED_TO rows, then one INDICATES row: two groups, run in that order."""
    return [
        {"rel_type": "ATTRIBUTED_TO", "from_type": "Malware", "from_key": {"name": "trickbot"},
         "to_type": "ThreatActor", "to_key": {"name": "wizard spider"}, "match_type": "otx_pulse"},
        {"rel_type": "ATTRIBUTED_TO", "from_type": "Malware", "from_key": {"name": "emotet"},
         "to_type": "ThreatActor", "to_key": {"name": "ta542"}, "match_type": "otx_pulse"},
        {"rel_type": "INDICATES", "from_type": "Indicator",
         "from_key": {"value": "203.0.113.4", "indicator_type": "ipv4"},
         "to_type": "Malware", "to_key": {"name": "trickbot"}, "match_type": "otx_pulse"},
    ]  # fmt: skip


class TestBatchMerge:
    """``_execute_batch_with_retry``: the Indicator and Vulnerability batches (up to 1000 rows)."""

    def test_a_deadlock_is_retried_and_the_batch_written(self, bolt):
        server, client = bolt(fail(INDICATOR_BATCH, DEADLOCK))
        assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (3, 0)
        assert count(server.runs, INDICATOR_BATCH) == 2, "the deadlocked attempt is retried"
        assert count(server.committed, INDICATOR_BATCH) == 1

    def test_a_terminal_error_counts_every_row_as_an_error(self, bolt, caplog):
        server, client = bolt(fail(INDICATOR_BATCH, TYPE_ERROR))
        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (0, 3)
        assert count(server.runs, INDICATOR_BATCH) == 1, "a terminal error is not retried"
        assert any("[BATCH-PERMANENT-FAILURE]" in r.getMessage() for r in caplog.records)

    def test_a_connection_lost_while_the_batch_runs_is_retried(self, bolt):
        server, client = bolt(fail(INDICATOR_BATCH, drop=True))
        assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (3, 0)
        assert count(server.runs, INDICATOR_BATCH) == 2
        assert count(server.committed, INDICATOR_BATCH) == 1

    def test_a_transaction_timeout_is_logged_once_and_counted(self, bolt, caplog):
        server, client = bolt(
            fail(INDICATOR_BATCH, "Neo.ClientError.Transaction.TransactionTimedOutClientConfiguration")
        )
        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (0, 3)
        (timeout_line,) = [r.getMessage() for r in caplog.records if "[NEO4J-TIMEOUT]" in r.getMessage()]
        assert "MERGE (n:Indicator" in timeout_line
        assert any("[BATCH-PERMANENT-FAILURE]" in r.getMessage() for r in caplog.records)

    def test_the_counter_kill_switch_still_reads_the_result(self, bolt, monkeypatch):
        """The kill switch turns off the counter inspection only; the batch's error is still read."""
        monkeypatch.setenv("EDGEGUARD_DISABLE_MERGE_COUNTER_INSPECTION", "1")
        server, client = bolt(fail(INDICATOR_BATCH, DEADLOCK))
        assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (3, 0)
        assert count(server.runs, INDICATOR_BATCH) == 2

    def test_the_counters_are_read_from_the_summary_of_the_one_read(self, bolt, monkeypatch):
        seen = []
        monkeypatch.setattr(nc, "_record_batch_counters", lambda **kw: seen.append(kw))
        _server, client = bolt()
        assert client.merge_indicators_batch(_indicators(), source_id="alienvault_otx") == (3, 0)
        (call,) = seen
        assert call.get("result") is None and call["summary"].counters.nodes_created == 1


class TestSingleItemMerge:
    """``merge_node_with_source`` (node MERGE, then ``_upsert_sourced_relationship``) and the CVE helpers."""

    def test_a_deadlock_on_the_node_merge_is_retried(self, bolt):
        server, client = bolt(fail(MALWARE_MERGE, DEADLOCK))
        assert client.merge_malware({"name": "TrickBot", "tag": "alienvault_otx"}, source_id="alienvault_otx") is True
        assert count(server.runs, MALWARE_MERGE) == 2
        assert count(server.committed, MALWARE_MERGE) == 1

    def test_a_terminal_error_on_the_node_merge_returns_false(self, bolt):
        server, client = bolt(fail(MALWARE_MERGE, TYPE_ERROR))
        assert client.merge_malware({"name": "TrickBot", "tag": "alienvault_otx"}, source_id="alienvault_otx") is False
        assert count(server.runs, SOURCED_FROM_UPSERT) == 0, "no source link for a node that was not written"

    def test_a_deadlock_on_the_source_link_is_retried(self, bolt):
        server, client = bolt(fail(SOURCED_FROM_UPSERT, DEADLOCK))
        assert client.merge_malware({"name": "TrickBot", "tag": "alienvault_otx"}, source_id="alienvault_otx") is True
        assert count(server.committed, SOURCED_FROM_UPSERT) == 1

    def test_a_terminal_error_on_the_source_link_returns_false(self, bolt, caplog):
        """``merge_node_with_source`` returns this False without a line of its own, so the client's
        line for it names the node and the source (the sync's ``[MERGE-RETURNED-FALSE]`` names the
        entity too)."""
        server, client = bolt(fail(SOURCED_FROM_UPSERT, TYPE_ERROR))
        with caplog.at_level(logging.WARNING, logger="neo4j_client"):
            assert (
                client.merge_malware({"name": "TrickBot", "tag": "alienvault_otx"}, source_id="alienvault_otx") is False
            )
        (line,) = [r.getMessage() for r in caplog.records if "SOURCED_FROM relationship error" in r.getMessage()]
        assert "(terminal) for Malware(name=trickbot) source=alienvault_otx: CypherTypeError" in line

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c._merge_cvss_node("CVE-2026-1000", "nvd", "CVSSv31", "HAS_CVSS_v31", {"base_score": 9.8}),
            lambda c: c._replace_nvd_owned_cve_data("CVE-2026-1000", {"cwe": ["CWE-79"]}),
            lambda c: c._set_cve_score_from_cvss("CVE-2026-1000"),
        ],
        ids=["merge_cvss_node", "replace_nvd_owned_cve_data", "set_cve_score_from_cvss"],
    )
    def test_a_failed_cve_sub_write_returns_false(self, bolt, call):
        """The helper names the CVE in its own WARNING and returns False (``merge_cve`` does not yet
        act on the value: a separate change)."""
        server, client = bolt(fail("cve_id: $cve_id", TYPE_ERROR))
        assert call(client) is False


class TestRelationshipGroups:
    """``create_misp_relationships_batch``: the groups share one session; each group's error is its own."""

    def test_a_deadlock_on_a_middle_group_retries_that_group(self, bolt):
        server, client = bolt(fail(ATTRIBUTED_TO_GROUP, DEADLOCK))
        result = client.create_misp_relationships_batch(_relationships(), source_id="alienvault_otx")
        assert (int(result), result.failed) == (3, 0)
        assert count(server.runs, ATTRIBUTED_TO_GROUP) == 2, "ATTRIBUTED_TO is sent again, not INDICATES"
        assert count(server.committed, ATTRIBUTED_TO_GROUP) == 1
        assert count(server.runs, INDICATES_GROUP) == 1

    def test_a_deadlock_on_the_last_group_is_retried(self, bolt):
        server, client = bolt(fail(INDICATES_GROUP, DEADLOCK))
        result = client.create_misp_relationships_batch(_relationships(), source_id="alienvault_otx")
        assert (int(result), result.failed) == (3, 0)
        assert count(server.runs, INDICATES_GROUP) == 2
        assert count(server.committed, INDICATES_GROUP) == 1

    def test_a_terminal_error_is_charged_to_its_own_group(self, bolt, caplog):
        server, client = bolt(fail(ATTRIBUTED_TO_GROUP, TYPE_ERROR))
        with caplog.at_level(logging.ERROR, logger="neo4j_client"):
            result = client.create_misp_relationships_batch(_relationships(), source_id="alienvault_otx")
        assert (int(result), result.failed) == (1, 2), "the two ATTRIBUTED_TO rows failed, INDICATES was written"
        assert count(server.committed, INDICATES_GROUP) == 1
        (line,) = [r.getMessage() for r in caplog.records if "[BATCH-PERMANENT-FAILURE]" in r.getMessage()]
        assert "ATTRIBUTED_TO (2 rows)" in line

    def test_a_terminal_error_on_the_last_group_is_counted(self, bolt):
        server, client = bolt(fail(INDICATES_GROUP, TYPE_ERROR))
        result = client.create_misp_relationships_batch(_relationships(), source_id="alienvault_otx")
        assert (int(result), result.failed) == (2, 1)


class TestOtherWrites:
    """The same reading at every other write whose caller handles its error."""

    def test_ensure_sources_reports_a_failed_source_merge(self, bolt, monkeypatch):
        monkeypatch.setattr(nc, "SOURCES", {"alienvault_otx": nc.SOURCES["alienvault_otx"]})
        server, client = bolt(fail("MERGE (s:Source {source_id: $source_id})", TYPE_ERROR))
        assert client.ensure_sources() is False

    def test_a_failed_constraint_is_charged_to_itself_and_the_next_is_created(self, bolt):
        server, client = bolt(fail("CREATE CONSTRAINT indicator_key", TYPE_ERROR))
        created, errors = client.create_constraints()
        assert errors == 1
        assert count(server.committed, "CREATE CONSTRAINT malware_key") == 1

    def test_the_last_index_failing_is_counted(self, bolt):
        server, client = bolt(fail("CREATE INDEX alert_uuid", TYPE_ERROR))
        _created, errors = client.create_indexes()
        assert errors == 1

    def test_a_failed_second_statement_of_a_relationship_helper_returns_false(self, bolt):
        server, client = bolt(fail("MATCH (v:CVE {cve_id: $cve_id})", TYPE_ERROR))
        assert client.create_indicator_vulnerability_relationship("203.0.113.9", "CVE-2026-1000") is False

    def test_a_failed_topology_merge_returns_false(self, bolt):
        server, client = bolt(fail("MERGE (h:Host {hostname: $hostname})", TYPE_ERROR))
        assert client.merge_host({"hostname": "web-01"}) is False

    def test_a_failed_alert_merge_returns_false(self, bolt):
        server, client = bolt(fail("MERGE (a:Alert {alert_id: $alert_id})", TYPE_ERROR))
        assert client.create_alert_node({"alert_id": "a-1", "threat": {}}) is False

    def test_an_alias_merge_normalisation_error_fails_its_own_batch(self, bolt, caplog):
        statements = enrichment_jobs._AliasMergeStatements(
            apply="UNWIND $groups AS g RETURN count(g) AS merged",
            restamp_out="UNWIND $canonicals AS c RETURN count(c) AS restamped",
            restamp_in="UNWIND $canonicals AS c RETURN count(c) AS restamped",
            normalise="UNWIND $canonicals AS c MATCH (n:ThreatActor {name: c}) SET n.normalised = true",
        )
        server, client = bolt(fail("SET n.normalised", TYPE_ERROR))
        results = {"merged": 0, "restamped_edges": 0, "errors": 0}
        with caplog.at_level(logging.ERROR, logger="enrichment_jobs"):
            with client.driver.session() as session:
                assert enrichment_jobs._run_alias_merge_batches(
                    session,
                    [("apt28", "fancy bear"), ("apt29", "unc2452")],
                    statements=statements,
                    batch_size=1,
                    apply_params={},
                    results=results,
                    log_tag="ALIAS-MERGE",
                    canonical_noun="actors",
                )
        assert results["errors"] == 1
        failed = [r.getMessage() for r in caplog.records if "FAILED" in r.getMessage()]
        assert len(failed) == 1 and "batch 1/2 FAILED" in failed[0], "the first batch's statement failed"
        assert count(server.committed, "UNWIND $groups AS g") == 2, "the second batch still runs"


def _is_run(call) -> bool:
    """``<tx|s|*session>.run(...)``."""
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "run"):
        return False
    receiver = ast.unparse(call.func.value)
    return receiver in ("tx", "s") or receiver.endswith("session")


def _discarded_runs(path: Path, root: Path):
    """``<tx|s|*session>.run(...)`` results never read: a call used as a bare statement, or assigned
    to a name its function never reads. A result read on one path of a function and not on another
    is left to the behavioural tests above."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and _is_run(node.value):
            hits.add((node.lineno, f"{ast.unparse(node.value.func.value)}.run(...)"))
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        read = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        for stmt in ast.walk(node):
            target = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
            elif isinstance(stmt, ast.AnnAssign):
                target = stmt.target
            if isinstance(target, ast.Name) and _is_run(stmt.value) and target.id not in read:
                hits.add((stmt.lineno, f"{target.id} = {ast.unparse(stmt.value.func.value)}.run(...), never read"))
    for lineno, what in sorted(hits):
        yield f"{path.relative_to(root)}:{lineno}: {what}"


class TestNoWriteResultIsDiscarded:
    def test_every_run_in_src_reads_its_result(self):
        """A statement's result must be read (``.consume()``, ``.single()``, iteration) inside the
        caller's ``try``; a result left to ``Session.close`` loses its error."""
        found = [hit for path in sorted(SRC.rglob("*.py")) for hit in _discarded_runs(path, SRC.parent)]
        assert found == [], "write results never read:\n" + "\n".join(found)

    def test_the_scan_finds_a_discarded_run(self, tmp_path):
        probe = tmp_path / "probe.py"
        probe.write_text(
            "def f(driver):\n"
            "    with driver.session() as session:\n"
            "        session.run('MERGE (n:X)')\n"
            "        session.run('MERGE (n:Y)').consume()\n"
            "        rows = list(session.run('MATCH (n) RETURN n'))\n"
            "        result = session.run('MERGE (n:Z)')\n"
            "        summary = session.run('MERGE (n:W)')\n"
            "        summary.consume()\n"
            "        return rows\n"
        )
        assert list(_discarded_runs(probe, tmp_path)) == [
            "probe.py:3: session.run(...)",
            "probe.py:6: result = session.run(...), never read",
        ]
