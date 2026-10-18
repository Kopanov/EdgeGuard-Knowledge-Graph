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


class TestStatsLastSync:
    """``stats`` printed a green "Last sync: Never (Noneh ago)" when it read no sync state on the host
    (every host but the pipeline's, or a state file it cannot open or parse); it warns instead, in
    words true for both cases, and never formats a missing age (2026-10-18)."""

    NEVER = {"last_sync": "Never", "age_hours": None}

    def test_no_state_file_is_a_warning(self, capsys):
        edgeguard._print_last_sync(self.NEVER)
        out = capsys.readouterr().out
        assert "⚠" in out and "✓" not in out
        assert "Last sync: no readable sync state file on this host (none found, or unreadable)" in out
        assert "None" not in out and "Never" not in out

    def test_a_recorded_sync_is_a_success_with_a_rounded_age(self, capsys):
        edgeguard._print_last_sync({"last_sync": "2026-10-18 10:00", "age_hours": 2.4567})
        out = capsys.readouterr().out
        assert "✓" in out and "Last sync: 2026-10-18 10:00 (2.5h ago)" in out

    def test_a_missing_age_never_reaches_the_format(self, capsys):
        edgeguard._print_last_sync({"last_sync": "2026-10-18 10:00", "age_hours": None})
        out = capsys.readouterr().out
        assert "⚠" in out and "None" not in out

    def test_stats_misp_off_the_pipeline_host(self, monkeypatch, capsys):
        """The scorecard's case: ``stats --misp`` where no sync state file exists."""
        edgeguard._ensure_runtime_imports()
        unreachable = SimpleNamespace(Neo4jClient=lambda: SimpleNamespace(connect=lambda: False))
        monkeypatch.setitem(sys.modules, "neo4j_client", unreachable)
        monkeypatch.setattr(
            edgeguard,
            "_fetch_misp_event_summary",
            lambda: {"total_events": 2, "total_attributes": 10, "by_source": [], "truncated": False},
        )
        monkeypatch.setattr(edgeguard, "get_sync_status", lambda: dict(self.NEVER))
        args = SimpleNamespace(json=False, full=False, by_zone=False, by_source=False, misp=True)
        assert edgeguard.cmd_stats(args) == 0
        out = capsys.readouterr().out
        assert "MISP Events: 2 events" in out
        assert "Last sync: no readable sync state file on this host" in out
        assert "Noneh" not in out and "Last sync: Never" not in out

    @pytest.mark.parametrize("content", ["{not json", '{"last_sync": "yesterday"}'], ids=["corrupt", "bad-time"])
    def test_an_unreadable_state_file_gets_the_same_true_warning(self, monkeypatch, tmp_path, capsys, content):
        """A state file exists but cannot be parsed: ``get_sync_status`` answers "Never", and the
        warning must not claim that no file was found."""
        (tmp_path / "src").mkdir()
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "edgeguard_last_neo4j_sync.json").write_text(content)
        (tmp_path / "tmp").mkdir()
        monkeypatch.setattr(edgeguard, "SCRIPT_DIR", str(tmp_path / "src"))
        monkeypatch.setattr(edgeguard.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
        sync = edgeguard.get_sync_status()
        assert sync == self.NEVER
        edgeguard._print_last_sync(sync)
        out = capsys.readouterr().out
        assert "⚠" in out and "no readable sync state file on this host" in out
        assert "not found" not in out and "no sync state file found" not in out

    def test_json_output_keeps_the_raw_status(self, monkeypatch, capsys):
        edgeguard._ensure_runtime_imports()
        unreachable = SimpleNamespace(Neo4jClient=lambda: SimpleNamespace(connect=lambda: False))
        monkeypatch.setitem(sys.modules, "neo4j_client", unreachable)
        monkeypatch.setattr(edgeguard, "get_sync_status", lambda: dict(self.NEVER))
        args = SimpleNamespace(json=True, full=False, by_zone=False, by_source=False, misp=False)
        assert edgeguard.cmd_stats(args) == 0
        out = capsys.readouterr().out
        payload = json.loads(out[out.index("{") : out.rindex("}") + 1])
        assert payload["last_sync"] == self.NEVER


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


class _FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else []

    def json(self):
        return self._payload


class _FakeMispSession:
    """Search returns the foreign event on every page (it is never deleted); EdgeGuard events vanish once deleted."""

    def __init__(self):
        self.headers = {}
        self.deleted = []
        self.events = {
            "1": {"id": "1", "info": "EdgeGuard OTX pulses"},
            "2": {"id": "2", "info": "Partner event about CVEs (searchall hit on an attribute)"},
            "3": {"id": "3", "info": "[EdgeGuard] NVD CVEs"},
        }
        self.gets = 0

    def get(self, url, **kwargs):
        self.gets += 1
        return _FakeResponse(200, [dict(e) for e in self.events.values()])

    def delete(self, url, **kwargs):
        eid = url.rsplit("/", 1)[-1]
        self.deleted.append(eid)
        self.events.pop(eid, None)
        return _FakeResponse(200, {})


class TestDestructiveFlows:
    def test_clear_misp_applies_the_info_guard(self):
        src = inspect.getsource(edgeguard.cmd_clear_misp)
        assert '"EdgeGuard" not in event_info' in src and "continue" in src

    def test_clear_misp_skips_false_positives_and_terminates(self, monkeypatch, capsys):
        """Bugbot on #150: a skipped search hit used to stay in page 1 forever (loop to the page cap)
        and then count as a failed delete. Only the two EdgeGuard-named events are deleted, the
        loop stops when a page holds nothing new, and the command exits 0."""
        import requests

        edgeguard._ensure_runtime_imports()
        fake = _FakeMispSession()
        monkeypatch.setattr(requests, "Session", lambda: fake)
        monkeypatch.setattr(edgeguard, "apply_misp_http_host_header", lambda s: None, raising=False)
        rc = edgeguard.cmd_clear_misp(SimpleNamespace(force=True))
        out = capsys.readouterr().out
        assert rc == 0, out
        assert sorted(fake.deleted) == ["1", "3"]
        assert fake.gets <= 3, "the loop must stop once only skipped events remain"
        assert "Deleted 2/2" in out and "1 skipped" in out

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
        assert "15 not created by EdgeGuard" in text and "kept unless the wipe scope is 'all'" in text
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

    def test_null_threat_is_normalised_for_the_write_path(self, monkeypatch):
        """Bugbot on #150: ``threat: null`` passed validation but the write path received the raw
        payload with ``None`` and crashed before persisting the Alert node."""
        proc = alert_processor.AlertProcessor.__new__(alert_processor.AlertProcessor)
        proc.neo4j = MagicMock()
        monkeypatch.setattr(proc, "connect", lambda: True)
        payload = {"alert_id": "a-3", "zone": "energy", "threat": None}
        try:
            proc.process_alert(payload)
        except Exception:  # enrichment against a MagicMock graph may fail later; the write call is what matters
            pass
        proc.neo4j.process_complete_resilmesh_alert.assert_called_once()
        written = proc.neo4j.process_complete_resilmesh_alert.call_args.args[0]
        # the canonicaliser fills indicator/type into the (now dict) threat before the write
        assert isinstance(written["threat"], dict) and written["alert_id"] == "a-3"

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
