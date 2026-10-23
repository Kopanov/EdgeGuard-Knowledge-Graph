"""Destructive-operations audit trail (2026-10): JSONL line + Prometheus counter, never raises."""

from __future__ import annotations

import inspect
import json
import os
import re
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import destructive_ops_audit as audit  # noqa: E402
import neo4j_client as nc  # noqa: E402


def _counter_value(operation: str, target: str) -> float:
    assert audit._DESTRUCTIVE_OPS is not None, "prometheus_client is installed in the test env"
    return audit._DESTRUCTIVE_OPS.labels(operation=operation, target=target)._value.get()


def test_record_appends_one_json_line_and_increments_counter(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "destructive_ops.jsonl"
    monkeypatch.setenv(audit.AUDIT_PATH_ENV, str(path))
    before = _counter_value("clear_all", "neo4j")
    rec = audit.record_destructive_op("clear_all", target="neo4j", affected=1234, scope="every node", details={"x": 1})
    rec2 = audit.record_destructive_op("clear_all", target="neo4j", affected=0)
    lines = path.read_text().splitlines()
    assert len(lines) == 2 and rec is not None and rec2 is not None
    first = json.loads(lines[0])
    assert first["operation"] == "clear_all" and first["target"] == "neo4j" and first["affected"] == 1234
    assert first["scope"] == "every node" and first["details"] == {"x": 1} and first["ts"].endswith("+00:00")
    assert "scope" not in json.loads(lines[1])
    assert _counter_value("clear_all", "neo4j") == before + 2


def test_empty_path_disables_the_file_but_not_the_counter(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.AUDIT_PATH_ENV, "  ")
    monkeypatch.chdir(tmp_path)
    before = _counter_value("cvss_dedup", "neo4j")
    rec = audit.record_destructive_op("cvss_dedup", target="neo4j", affected=3, scope="CVSSv31")
    assert rec is not None and audit.audit_path() is None
    assert not (tmp_path / "logs").exists()
    assert _counter_value("cvss_dedup", "neo4j") == before + 1


def test_default_path_is_under_logs(tmp_path, monkeypatch):
    monkeypatch.delenv(audit.AUDIT_PATH_ENV, raising=False)
    monkeypatch.chdir(tmp_path)
    audit.record_destructive_op("clear_edgeguard_managed", target="neo4j", affected=7)
    assert (tmp_path / "logs" / "destructive_ops.jsonl").exists()


def test_write_failure_is_logged_not_raised(tmp_path, monkeypatch, caplog):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setenv(audit.AUDIT_PATH_ENV, str(blocker / "trail.jsonl"))
    with caplog.at_level("WARNING"):
        assert audit.record_destructive_op("clear_all", target="neo4j", affected=1) is None
    assert any("audit line not written" in r.message for r in caplog.records)


def test_every_node_deleting_path_in_neo4j_client_records(monkeypatch):
    for method, op in (
        (nc.Neo4jClient.clear_all, "clear_all"),
        (nc.Neo4jClient.clear_edgeguard_managed, "clear_edgeguard_managed"),
        (nc.Neo4jClient.create_constraints, "cvss_dedup"),
    ):
        src = inspect.getsource(inspect.unwrap(method))
        assert re.search(rf'record_destructive_op\(\s*"{op}"', src), op


def test_clear_edgeguard_managed_records_counts(monkeypatch):
    seen = []
    monkeypatch.setattr(nc, "record_destructive_op", lambda op, **kw: seen.append((op, kw)))
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    session = client.driver.session.return_value.__enter__.return_value
    # count managed, count others, count enriched, the relationship pre-pass (empty), then one
    # delete batch that empties the set
    session.run.side_effect = [
        MagicMock(single=lambda: {"count": 5}),
        MagicMock(single=lambda: {"count": 40}),
        MagicMock(single=lambda: {"count": 2}),
        MagicMock(single=lambda: {"deleted": 0}),
        MagicMock(single=lambda: {"deleted": 5}),
    ]
    assert client.clear_edgeguard_managed() is True
    assert seen == [
        (
            "clear_edgeguard_managed",
            {
                "target": "neo4j",
                "affected": 5,
                "scope": "edgeguard_managed = true",
                "details": {"left_untouched": 40, "enriched_kept": 2},
            },
        )
    ]


def test_every_line_names_the_process_that_ran_the_delete(tmp_path, monkeypatch):
    """Who ran it (2026-10): the operating-system user, the host and the program of the process."""
    path = tmp_path / "trail.jsonl"
    monkeypatch.setenv(audit.AUDIT_PATH_ENV, str(path))
    monkeypatch.setattr(audit.getpass, "getuser", lambda: "operator1")
    monkeypatch.setattr(audit.socket, "gethostname", lambda: "edge-01")
    monkeypatch.setattr(sys, "argv", ["/opt/edgeguard/scripts/clear_neo4j.py", "--force"])
    rec = audit.record_destructive_op("clear_edgeguard_managed", target="neo4j", affected=3)
    assert rec is not None
    assert rec["actor"] == {"user": "operator1", "host": "edge-01", "program": "clear_neo4j.py"}
    assert json.loads(path.read_text())["actor"] == rec["actor"]


def test_an_unknown_user_does_not_stop_the_line(tmp_path, monkeypatch):
    monkeypatch.setenv(audit.AUDIT_PATH_ENV, str(tmp_path / "trail.jsonl"))

    def no_user() -> str:
        raise KeyError("getpwuid(): uid not found: 50000")

    monkeypatch.setattr(audit.getpass, "getuser", no_user)
    rec = audit.record_destructive_op("clear_all", target="neo4j", affected=1)
    assert rec is not None and "user" not in rec["actor"] and rec["actor"]["host"]
