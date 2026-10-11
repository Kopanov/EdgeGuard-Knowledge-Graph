"""Operations truthfulness and inbound alert validation (2026-10 production-readiness check).

`edgeguard preflight` could never report MISP healthy (dict guard vs dataclass), `stats` read keys
the summary never emits, `monitor` always exited 0 and invented breaker states, the fresh-baseline
blast radius showed only EdgeGuard nodes while the wipe deletes every node, `clear misp` lacked the
info-field guard baseline_clean applies, liveness probe failures were logged at DEBUG, the MISP
alert rule paged on the optional workers check, and an alert without ``alert_id`` or with a
non-object ``threat`` was processed (and answered ``enriched=true``) instead of being rejected.
"""

from __future__ import annotations

import inspect
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import alert_processor  # noqa: E402
import baseline_clean  # noqa: E402
import edgeguard  # noqa: E402
import metrics  # noqa: E402
import parent_dag_liveness  # noqa: E402
from misp_health import MISPHealthCheckResult  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent


class TestPreflightAndStats:
    def test_preflight_accepts_the_dataclass_health_result(self):
        src = inspect.getsource(edgeguard.cmd_preflight)
        assert 'hasattr(misp_result, "get")' in src
        assert "isinstance(misp_result, dict)" not in src
        healthy = MISPHealthCheckResult(
            healthy=True, status="healthy", checks={}, details={}, timestamp="t", healthy_for_collection=True
        )
        unhealthy = MISPHealthCheckResult(
            healthy=False, status="down", checks={}, details={}, timestamp="t", healthy_for_collection=False
        )
        assert bool(healthy.get("healthy", False)) is True
        assert bool(unhealthy.get("healthy", False)) is False

    def test_stats_reads_the_keys_the_summary_emits(self):
        src = inspect.getsource(edgeguard.cmd_stats)
        assert "success_rate_percent" in src and "average_duration_seconds" in src
        assert "'success_rate'" not in src and "'avg_duration'" not in src
        summary = metrics.PipelineMetrics().get_summary()
        assert "success_rate_percent" in summary and "average_duration_seconds" in summary


class TestMonitor:
    @pytest.fixture(autouse=True)
    def _runtime_names(self):
        # cmd_* functions expect the module-level names main() loads before dispatching
        edgeguard._ensure_runtime_imports()

    def test_breaker_state_is_unknown_when_nothing_wrote_the_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(edgeguard, "get_circuit_breaker_state_file", lambda: str(tmp_path / "absent.json"))
        assert edgeguard.get_circuit_breaker_info() == {"misp": "UNKNOWN", "neo4j": "UNKNOWN"}
        state = tmp_path / "state.json"
        state.write_text(json.dumps({"misp": "OPEN", "neo4j": "CLOSED"}))
        monkeypatch.setattr(edgeguard, "get_circuit_breaker_state_file", lambda: str(state))
        assert edgeguard.get_circuit_breaker_info() == {"misp": "OPEN", "neo4j": "CLOSED"}

    @pytest.mark.parametrize(
        "misp, neo4j, expected",
        [
            ({"status": "HEALTHY", "version": "2.5"}, {"status": "UP", "uri": "bolt://x"}, 0),
            ({"status": "DEGRADED", "version": "2.5"}, {"status": "UP", "uri": "bolt://x"}, 0),
            ({"status": "ERROR", "error": "refused"}, {"status": "UP", "uri": "bolt://x"}, 1),
            ({"status": "HEALTHY", "version": "2.5"}, {"status": "DOWN", "error": "refused"}, 1),
        ],
    )
    def test_monitor_exit_code_reflects_component_state(self, monkeypatch, capsys, misp, neo4j, expected):
        monkeypatch.setattr(edgeguard, "get_misp_status", lambda: misp)
        monkeypatch.setattr(edgeguard, "get_neo4j_status", lambda: neo4j)
        monkeypatch.setattr(edgeguard, "get_sync_status", lambda: {"last_sync": "Never", "age_hours": None})
        monkeypatch.setattr(edgeguard, "get_circuit_breaker_info", lambda: {"misp": "UNKNOWN", "neo4j": "UNKNOWN"})
        assert edgeguard.cmd_monitor(SimpleNamespace()) == expected
        assert "UNKNOWN" in capsys.readouterr().out


class TestDestructiveFlows:
    def test_clear_misp_applies_the_info_guard(self):
        src = inspect.getsource(edgeguard.cmd_clear_misp)
        assert '"EdgeGuard" not in event_info' in src and "continue" in src

    def test_probe_total_and_blast_radius_render(self):
        client = MagicMock()
        client.run.return_value = [{"cnt": 25}]
        assert baseline_clean._probe_neo4j_total(client) == 25
        failing = MagicMock()
        failing.run.side_effect = RuntimeError("down")
        assert baseline_clean._probe_neo4j_total(failing) == 0
        state = baseline_clean.BaselineState(neo4j_count=10, neo4j_total_count=25, neo4j_ok=True)
        text = state.render_summary()
        assert "Neo4j EdgeGuard nodes:" in text and "25" in text
        assert "15 not created by EdgeGuard" in text and "the wipe deletes every node" in text
        same = baseline_clean.BaselineState(neo4j_count=10, neo4j_total_count=10, neo4j_ok=True).render_summary()
        assert "not created by EdgeGuard" not in same


class TestOperatorVisibility:
    def test_liveness_probe_failures_are_warnings(self):
        src = inspect.getsource(parent_dag_liveness)
        assert 'logger.warning("Liveness probe API error' in src
        assert 'logger.warning("Liveness probe non-dict response' in src
        assert 'logger.debug("Liveness probe API error' not in src

    def test_misp_unhealthy_rule_ignores_the_optional_workers_check(self):
        rules = (_ROOT / "prometheus" / "alerts.yml").read_text()
        assert 'expr: edgeguard_misp_health{check_type!="workers"} == 0' in rules
        assert "expr: edgeguard_misp_health == 0" not in rules


class TestInboundAlertValidation:
    @pytest.mark.parametrize(
        "payload, fragment",
        [
            ({"zone": "energy", "threat": {"indicator": "1.2.3.4", "type": "ipv4"}}, "alert_id"),
            ({"alert_id": "", "threat": {}}, "alert_id"),
            ({"alert_id": 42, "threat": {}}, "alert_id"),
            ({"alert_id": "a-1", "threat": "x"}, "threat"),
            ({"alert_id": "a-1", "threat": ["x"]}, "threat"),
        ],
    )
    def test_invalid_payloads_are_named(self, payload, fragment):
        reason = alert_processor._invalid_payload_reason(payload)
        assert reason and fragment in reason

    @pytest.mark.parametrize(
        "payload", [{"alert_id": "a-1"}, {"alert_id": "a-1", "threat": {}}, {"alert_id": "a-1", "threat": None}]
    )
    def test_valid_payloads_pass(self, payload):
        assert alert_processor._invalid_payload_reason(payload) is None

    def test_process_alert_rejects_before_touching_the_database(self, monkeypatch, caplog):
        proc = alert_processor.AlertProcessor.__new__(alert_processor.AlertProcessor)
        proc.neo4j = MagicMock()

        def must_not_connect():
            raise AssertionError("connect() must not be called for an invalid payload")

        monkeypatch.setattr(proc, "connect", must_not_connect)
        with caplog.at_level("WARNING", logger="alert_processor"):
            resp = proc.process_alert({"zone": "energy", "threat": {"indicator": "1.2.3.4", "type": "ipv4"}})
        assert resp.enriched is False
        assert "alert_id" in resp.query_metadata["error"]
        assert any("[ALERT-REJECTED]" in r.message for r in caplog.records)
        assert not any("1.2.3.4" in r.message for r in caplog.records), "payload values must not be logged"
        resp2 = proc.process_alert({"alert_id": "a-2", "threat": "not-an-object"})
        assert resp2.enriched is False and "threat" in resp2.query_metadata["error"]
