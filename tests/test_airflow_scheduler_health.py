"""Detection of a dead Airflow scheduler.

``airflow standalone`` (the Compose ``airflow`` service and the usual bare-metal setup) runs the
scheduler, triggerer, DAG processor and API server as subprocesses and neither restarts nor exits when
one of them dies. ``/api/v2/monitor/health`` then answers HTTP 200 with ``unhealthy`` in its JSON body
only, so every check that read the HTTP status or reachability alone reported Airflow as fine while no
task started and a DAG run stayed ``running`` (``dagrun_timeout`` is enforced by the scheduler).

The fixtures are the real answers of an Airflow 3.3.2 standalone install on 2026-11-01: the scheduler
and triggerer stopped on a metadata database error while the DAG processor kept running
(``airflow_health_unhealthy_2026_11_01.json``), and the same install after a restart
(``airflow_health_healthy_2026_11_01.json``).

Covered: the shared reader ``airflow_client.component_health``, each caller end to end (``doctor``,
``dag status``, ``dag kill``, ``preflight``, the metrics exporter's collector, the Compose healthcheck,
check ``[13]`` of ``scripts/preflight_baseline.sh``), and the alert rules that read the new gauges.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from prometheus_client import CollectorRegistry

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import airflow_client  # noqa: E402
import edgeguard  # noqa: E402
import metrics_exporter  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
HEALTHY = json.loads((_FIXTURES / "airflow_health_healthy_2026_11_01.json").read_text())
UNHEALTHY = json.loads((_FIXTURES / "airflow_health_unhealthy_2026_11_01.json").read_text())
SCHEDULER_HEARTBEAT = "2026-11-01T08:32:14.421196+00:00"  # last heartbeat in UNHEALTHY
RUNBOOK_SECTION = "Airflow scheduler or triggerer stopped"
_AIRFLOW_ALERTS = (
    "EdgeGuardAirflowSchedulerDown",
    "EdgeGuardAirflowComponentUnhealthy",
    "EdgeGuardAirflowHealthUnreachable",
)


# ---------------------------------------------------------------------------
# airflow_client.component_health — the shared reader
# ---------------------------------------------------------------------------


class TestComponentHealth:
    def test_the_stalled_install_names_scheduler_and_triggerer(self):
        health = airflow_client.component_health(UNHEALTHY)
        assert health.reachable and health.error is None
        assert health.statuses == {
            "metadatabase": "healthy",
            "scheduler": "unhealthy",
            "triggerer": "unhealthy",
            "dag_processor": "healthy",
        }
        assert health.not_healthy() == ["scheduler", "triggerer"]
        assert not health.is_healthy("scheduler") and health.is_healthy("dag_processor")
        assert health.latest_heartbeat("scheduler") == SCHEDULER_HEARTBEAT
        assert health.latest_heartbeat("metadatabase") is None
        text = health.describe("scheduler")
        assert text.startswith(f"scheduler unhealthy, last heartbeat {SCHEDULER_HEARTBEAT} (")
        assert text.endswith(" ago)")

    def test_the_restarted_install_is_healthy(self):
        health = airflow_client.component_health(HEALTHY)
        assert health.reachable
        assert health.not_healthy() == []
        assert list(health.statuses) == list(airflow_client.AIRFLOW_HEALTH_COMPONENTS)

    def test_a_missing_component_is_not_healthy(self):
        payload = {name: entry for name, entry in HEALTHY.items() if name != "triggerer"}
        health = airflow_client.component_health(payload)
        assert health.not_healthy() == ["triggerer"]
        assert "triggerer" not in health.statuses
        assert health.describe("triggerer") == "triggerer not reported by Airflow"

    def test_a_null_status_is_not_healthy(self):
        """Airflow 3 reports ``null`` for a triggerer or DAG processor that never ran (no job recorded)."""
        payload = dict(HEALTHY, triggerer={"status": None, "latest_triggerer_heartbeat": None})
        health = airflow_client.component_health(payload)
        assert health.statuses["triggerer"] is None
        assert health.not_healthy() == ["triggerer"]
        assert health.describe("triggerer") == "triggerer without status (no triggerer job recorded)"

    @pytest.mark.parametrize("entry", ["healthy", None, ["healthy"], {"status": True}, {}])
    def test_a_malformed_scheduler_entry_is_not_healthy(self, entry):
        health = airflow_client.component_health(dict(HEALTHY, scheduler=entry))
        assert health.statuses["scheduler"] is None
        assert health.not_healthy() == ["scheduler"]

    def test_an_error_answer_is_unreachable(self):
        health = airflow_client.component_health({"error": "Cannot connect to Airflow at http://x:8082."})
        assert not health.reachable
        assert health.error == "Cannot connect to Airflow at http://x:8082."
        assert health.statuses == {} and health.not_healthy() == list(airflow_client.AIRFLOW_HEALTH_COMPONENTS)

    @pytest.mark.parametrize("payload", [None, [], ["scheduler"], "healthy", 200])
    def test_an_answer_that_is_not_an_object_is_unreachable(self, payload):
        health = airflow_client.component_health(payload)
        assert not health.reachable and health.statuses == {}


class _Resp:
    def __init__(self, body):
        self.status_code = 200
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


class TestHealthCall:
    @pytest.fixture
    def answer(self, monkeypatch):
        """Make every request answer HTTP 200 with ``body``; returns the list of recorded requests."""
        monkeypatch.setenv("AIRFLOW_WEBSERVER_URL", "http://airflow.test:8082")
        monkeypatch.delenv("AIRFLOW_API_VERSION", raising=False)
        recorded = []

        def _answer(body):
            def request(method, url, **kwargs):
                recorded.append({"method": method, "url": url, **kwargs})
                return _Resp(body)

            monkeypatch.setattr(airflow_client.requests, "request", request)
            return recorded

        return _answer

    def test_the_real_answer_is_returned_with_http_200(self, answer):
        calls = answer(UNHEALTHY)
        assert airflow_client.airflow_health() == UNHEALTHY
        assert calls[0]["url"] == "http://airflow.test:8082/api/v2/monitor/health"
        assert calls[0]["timeout"] == airflow_client._TIMEOUT

    def test_a_shorter_timeout_is_passed_on(self, answer):
        calls = answer(HEALTHY)
        airflow_client.airflow_health(timeout=5.0)
        assert calls[0]["timeout"] == 5.0

    def test_a_json_answer_that_is_not_an_object_is_an_error(self, answer):
        answer(["healthy"])
        health = airflow_client.airflow_health()
        assert set(health) == {"error"} and "not a JSON object" in health["error"]


# ---------------------------------------------------------------------------
# CLI callers end to end
# ---------------------------------------------------------------------------


def _client(**overrides) -> types.SimpleNamespace:
    """An ``airflow_client`` stand-in: stubbed network calls, the real reader and formatter."""
    fields = {
        "component_health": airflow_client.component_health,
        "format_duration": airflow_client.format_duration,
        "AIRFLOW_HEALTH_COMPONENTS": airflow_client.AIRFLOW_HEALTH_COMPONENTS,
    }
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


def _line(lines, text):
    found = [ln for ln in lines if text in ln]
    assert found, f"no output line contains {text!r}"
    return found[0]


_DOCTOR_ENV_UNSET = (
    "AIRFLOW_API_PASSWORD",
    "NATS_URL",
    "EDGEGUARD_BASELINE_DAYS",
    "AIRFLOW_MEMORY_LIMIT",
    "NEO4J_HEAP_MAX",
    "NEO4J_PAGECACHE",
    "NEO4J_CONTAINER_MEMORY_LIMIT",
)


class TestDoctor:
    @pytest.fixture
    def run_doctor(self, monkeypatch, capsys):
        """``cmd_doctor`` with every check but Airflow passing; returns ``(exit code, output lines)``."""
        import time

        import requests

        for name in _DOCTOR_ENV_UNSET:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(time, "sleep", lambda seconds: None)  # the 10 s retry delay
        monkeypatch.setattr(edgeguard, "SSL_VERIFY", True, raising=False)
        monkeypatch.setattr(edgeguard, "test_misp_connection", lambda: (True, "MISP stub"))
        monkeypatch.setattr(edgeguard, "test_neo4j_connection", lambda: (True, "Neo4j stub"))

        def _no_network(*args, **kwargs):
            raise requests.exceptions.ConnectionError("no network in this test")

        monkeypatch.setattr(requests, "get", _no_network)  # the MISP event count (non-critical)
        result = types.SimpleNamespace(details={"version": "2.5.17", "version_compatible": True})
        monkeypatch.setitem(
            sys.modules,
            "misp_health",
            types.SimpleNamespace(MISPHealthCheck=lambda: types.SimpleNamespace(check_health=lambda: result)),
        )
        monkeypatch.setitem(
            sys.modules,
            "neo4j_client",
            types.SimpleNamespace(Neo4jClient=lambda: types.SimpleNamespace(connect=lambda: False)),
        )
        monkeypatch.setattr(edgeguard, "validate_api_keys", lambda: (True, "keys stub"))
        monkeypatch.setattr(edgeguard, "check_disk_space", lambda: (True, "disk stub"))
        monkeypatch.setattr(edgeguard, "check_last_sync", lambda: (True, "sync stub"))
        monkeypatch.setattr(edgeguard, "load_sources", lambda: {})
        monkeypatch.setattr(edgeguard, "DEFAULT_SOURCES", {"otx": {"enabled": True}}, raising=False)
        monkeypatch.setitem(
            sys.modules,
            "version_compatibility",
            types.SimpleNamespace(compare_pinned_vs_running=lambda **kw: []),
        )

        def _run(payload):
            calls = []
            monkeypatch.setitem(
                sys.modules,
                "airflow_client",
                _client(
                    airflow_health=lambda: calls.append(1) or payload,
                    get_registered_dags=lambda: [{"dag_id": "edgeguard_baseline", "is_paused": False}],
                ),
            )
            code = edgeguard.cmd_doctor(argparse.Namespace(memory=False))
            return code, capsys.readouterr().out.splitlines(), len(calls)

        return _run

    def test_a_healthy_airflow_passes(self, run_doctor):
        code, lines, calls = run_doctor(HEALTHY)
        assert code == 0 and calls == 1
        assert "✓" in _line(lines, "Airflow components healthy: metadatabase, scheduler, triggerer, dag_processor")
        assert "✓" in _line(lines, "EdgeGuard is healthy")
        assert not any("Recover: restart Airflow" in ln for ln in lines)

    def test_a_dead_scheduler_is_an_issue_and_a_dead_triggerer_a_warning(self, run_doctor):
        code, lines, calls = run_doctor(UNHEALTHY)
        assert code == 1 and calls == 2, "one retry, then the unhealthy answer is reported"
        assert "✓" in _line(lines, "Airflow webserver reachable")
        scheduler = _line(lines, f"Airflow scheduler unhealthy, last heartbeat {SCHEDULER_HEARTBEAT}")
        assert "✗" in scheduler and "no task starts" in scheduler
        triggerer = _line(lines, "Airflow triggerer unhealthy, last heartbeat 2026-11-01T08:32:16.883439+00:00")
        assert "⚠" in triggerer
        assert "✓" in _line(lines, "Airflow components healthy: metadatabase, dag_processor")
        recover = _line(lines, "Recover: restart Airflow")
        assert "continues where it stopped" in recover and "do not trigger it again" in recover
        assert "✗" in _line(lines, "EdgeGuard has issues")
        # The DAG list still runs: the API server answers.
        assert "✓" in _line(lines, "Active DAGs: edgeguard_baseline")

    def test_a_dead_triggerer_alone_is_a_warning(self, run_doctor):
        payload = dict(HEALTHY, triggerer=UNHEALTHY["triggerer"])
        code, lines, calls = run_doctor(payload)
        assert code == 0 and calls == 1
        assert "⚠" in _line(lines, "Airflow triggerer unhealthy")
        assert "ℹ" in _line(lines, "Recover: restart Airflow")
        assert not any("✗" in ln for ln in lines)


_RUN = {
    "dag_run_id": "manual__2026-11-01T08:30:00+00:00",
    "state": "running",
    "start_date": "2026-11-01T08:30:12.000000+00:00",
    "end_date": None,
}


class TestDagStatus:
    @pytest.fixture
    def run_status(self, monkeypatch, capsys):
        def _run(payload, use_json=False):
            monkeypatch.setitem(
                sys.modules,
                "airflow_client",
                _client(
                    airflow_health=lambda: payload,
                    get_edgeguard_dag_ids=lambda: ["edgeguard_baseline"],
                    list_dag_runs=lambda dag_id, state=None, limit=5: [dict(_RUN)],
                ),
            )
            code = edgeguard.cmd_dag_status(argparse.Namespace(dag_id=None, state=None, limit=5, json=use_json))
            return code, capsys.readouterr().out

        return _run

    def test_runs_are_listed_and_the_dead_scheduler_fails_the_command(self, run_status):
        code, out = run_status(UNHEALTHY)
        lines = out.splitlines()
        assert code == 1
        assert "✗" in _line(lines, f"Airflow scheduler unhealthy, last heartbeat {SCHEDULER_HEARTBEAT}")
        row = _line(lines, "edgeguard_baseline")
        assert "running" in row and "2026-11-01T08:30:12" in row
        final = lines[[i for i, ln in enumerate(lines) if ln.strip()][-1]]
        assert "✗" in final and "runs shown as running or queued are not progressing" in final
        assert "do not trigger it again" in final
        assert out.index("Airflow scheduler unhealthy") < out.index("edgeguard_baseline") < out.index("not progressing")

    def test_a_healthy_airflow_lists_the_runs_and_exits_0(self, run_status):
        code, out = run_status(HEALTHY)
        assert code == 0
        assert "edgeguard_baseline" in out and "not progressing" not in out and "✗" not in out

    def test_json_output_stays_parseable_and_the_exit_code_reports_the_scheduler(self, run_status):
        code, out = run_status(UNHEALTHY, use_json=True)
        assert code == 1
        runs = json.loads(out[out.index("[\n") :])
        assert runs[0]["dag_run_id"] == _RUN["dag_run_id"] and runs[0]["dag_id"] == "edgeguard_baseline"
        assert out.index("Airflow scheduler unhealthy") < out.index("[\n")

    def test_an_unreachable_airflow_is_still_an_error(self, run_status):
        code, out = run_status({"error": "Cannot connect to Airflow at http://localhost:8082. Is it running?"})
        assert code == 1 and "Cannot connect to Airflow" in out and "edgeguard_baseline" not in out


def test_dag_kill_works_while_the_scheduler_is_dead(monkeypatch, capsys):
    """``dag kill`` needs only the API server: a run of a stalled baseline can still be marked failed."""
    patched = []
    monkeypatch.setitem(
        sys.modules,
        "airflow_client",
        _client(
            airflow_health=lambda: UNHEALTHY,
            list_all_active_dag_runs=lambda dag_ids: [dict(_RUN, dag_id="edgeguard_daily")],
            patch_dag_run_state=lambda dag_id, run_id, state: patched.append((dag_id, run_id, state)) or {},
        ),
    )
    code = edgeguard.cmd_dag_kill(argparse.Namespace(dag_id=None, dry_run=False, force=True))
    assert code == 0
    assert patched == [("edgeguard_daily", _RUN["dag_run_id"], "failed")]
    assert "Killed: edgeguard_daily" in capsys.readouterr().out


class TestPreflight:
    @pytest.fixture
    def run_preflight(self, monkeypatch):
        import io
        from contextlib import redirect_stdout

        resilience = importlib.import_module("resilience")
        monkeypatch.setattr(resilience, "_circuit_breakers", {})
        for name, value in (
            ("NEO4J_PASSWORD", "x"),
            ("MISP_API_KEY", "k"),
            ("MISP_URL", "https://misp.test"),
            ("NEO4J_URI", "bolt://neo4j.test:7687"),
        ):
            monkeypatch.setattr(edgeguard, name, value, raising=False)
        monkeypatch.delenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", raising=False)
        monkeypatch.setattr(importlib.import_module("source_key_check"), "check_source_keys", lambda sources=None: [])
        monkeypatch.setattr(
            importlib.import_module("health_check"),
            "health_check_neo4j",
            lambda: {"healthy": True, "apoc_available": True},
        )
        monkeypatch.setattr(importlib.import_module("baseline_checkpoint"), "get_baseline_status", lambda: {})

        def _run(payload, strict=False):
            monkeypatch.setitem(sys.modules, "airflow_client", airflow_client)
            monkeypatch.setattr(airflow_client, "airflow_health", lambda: payload)
            monkeypatch.setattr(airflow_client, "get_registered_dags", lambda: [{"dag_id": "edgeguard_baseline"}])
            out = io.StringIO()
            with patch("misp_health.MISPHealthCheck") as misp, redirect_stdout(out):
                misp.return_value.check_health.return_value = {"healthy": True}
                code = edgeguard.cmd_preflight(argparse.Namespace(strict=strict, json=True))
            text = out.getvalue()
            summary = json.loads(text[text.rindex('{\n  "errors"') :])
            return code, summary, text

        return _run

    def test_a_healthy_airflow_is_ready(self, run_preflight):
        code, summary, text = run_preflight(HEALTHY)
        assert (code, summary["errors"], summary["warnings"]) == (0, 0, 0), text
        assert "Airflow components healthy: metadatabase, scheduler, triggerer, dag_processor" in text
        assert summary["checks"]["airflow"] == HEALTHY

    def test_a_dead_scheduler_is_an_error_and_a_dead_triggerer_a_warning(self, run_preflight):
        code, summary, text = run_preflight(UNHEALTHY)
        assert (code, summary["errors"], summary["warnings"]) == (1, 1, 1), text
        assert f"Airflow scheduler unhealthy, last heartbeat {SCHEDULER_HEARTBEAT}" in text
        assert "NOT READY — 1 error(s), 1 warning(s)" in text
        assert summary["checks"]["airflow"]["scheduler"]["status"] == "unhealthy"

    def test_a_dead_triggerer_alone_fails_only_under_strict(self, run_preflight):
        payload = dict(HEALTHY, triggerer=UNHEALTHY["triggerer"])
        code, summary, _ = run_preflight(payload)
        assert (code, summary["errors"], summary["warnings"]) == (0, 0, 1)
        code, _, _ = run_preflight(payload, strict=True)
        assert code == 1

    def test_an_unreachable_airflow_stays_a_warning(self, run_preflight):
        code, summary, text = run_preflight({"error": "Cannot connect to Airflow at http://localhost:8082."})
        assert (code, summary["errors"], summary["warnings"]) == (0, 0, 1)
        assert "Airflow components healthy" not in text


# ---------------------------------------------------------------------------
# Metrics exporter: scrape-time collector
# ---------------------------------------------------------------------------


class TestAirflowHealthCollector:
    @pytest.fixture
    def answer(self, monkeypatch):
        """Make ``airflow_client.airflow_health`` return ``payload``; returns the recorded timeouts."""
        monkeypatch.delenv(metrics_exporter.AIRFLOW_HEALTH_ENV, raising=False)
        monkeypatch.setitem(sys.modules, "airflow_client", airflow_client)
        timeouts = []

        def _answer(payload):
            def health(timeout=None):
                timeouts.append(timeout)
                if isinstance(payload, Exception):
                    raise payload
                return payload

            monkeypatch.setattr(airflow_client, "airflow_health", health)
            return timeouts

        return _answer

    @staticmethod
    def _registry():
        registry = CollectorRegistry()
        assert metrics_exporter.register_airflow_health(registry) is True
        return registry

    @staticmethod
    def _component(registry, name):
        return registry.get_sample_value("edgeguard_airflow_component_healthy", {"component": name})

    def test_healthy(self, answer):
        timeouts = answer(HEALTHY)
        registry = self._registry()
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 1.0
        for name in airflow_client.AIRFLOW_HEALTH_COMPONENTS:
            assert self._component(registry, name) == 1.0, name
        # Asked at every collection (each get_sample_value collects), always with the short timeout.
        assert timeouts and set(timeouts) == {metrics_exporter.AIRFLOW_HEALTH_TIMEOUT_SEC}
        assert metrics_exporter.AIRFLOW_HEALTH_TIMEOUT_SEC < 10, "below Prometheus' default scrape timeout"

    def test_unhealthy(self, answer):
        answer(UNHEALTHY)
        registry = self._registry()
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 1.0
        assert self._component(registry, "scheduler") == 0.0
        assert self._component(registry, "triggerer") == 0.0
        assert self._component(registry, "metadatabase") == 1.0
        assert self._component(registry, "dag_processor") == 1.0

    def test_only_the_listed_components_get_a_series_and_null_is_0(self, answer):
        answer({"metadatabase": {"status": "healthy"}, "scheduler": {"status": None}})
        registry = self._registry()
        assert self._component(registry, "scheduler") == 0.0
        assert self._component(registry, "triggerer") is None

    def test_unreachable(self, answer):
        answer({"error": "Cannot connect to Airflow at http://airflow:8082."})
        registry = self._registry()
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 0.0
        assert self._component(registry, "scheduler") is None, "no component series without an answer"

    def test_a_failing_health_call_does_not_fail_the_scrape(self, answer):
        answer(RuntimeError("boom"))
        registry = self._registry()
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 0.0

    @pytest.mark.parametrize("value", ["false", "0", "off", " No "])
    def test_switched_off(self, answer, monkeypatch, value):
        timeouts = answer(HEALTHY)
        monkeypatch.setenv(metrics_exporter.AIRFLOW_HEALTH_ENV, value)
        registry = CollectorRegistry()
        assert metrics_exporter.register_airflow_health(registry) is False
        assert registry.get_sample_value("edgeguard_airflow_health_up") is None
        assert timeouts == [], "Airflow is not asked"

    @pytest.mark.parametrize("value", [None, "true", "1", "", "yes"])
    def test_on_by_default_and_when_set(self, answer, monkeypatch, value):
        answer(HEALTHY)
        if value is not None:
            monkeypatch.setenv(metrics_exporter.AIRFLOW_HEALTH_ENV, value)
        assert metrics_exporter.airflow_health_enabled() is True
        assert self._registry().get_sample_value("edgeguard_airflow_health_up") == 1.0

    def test_the_served_registry_carries_the_aggregate_and_the_airflow_gauges(self, answer, monkeypatch, tmp_path):
        """``serve`` (the ``metrics`` compose service) registers the collector on the registry it serves."""
        answer(UNHEALTHY)
        served = {}

        class _Stop(Exception):
            pass

        def _start(port, addr, registry):
            served.update(port=port, addr=addr, registry=registry)

        def _sleep(seconds):
            raise _Stop

        import prometheus_client

        monkeypatch.setattr(prometheus_client, "start_http_server", _start)
        monkeypatch.setattr(metrics_exporter.time, "sleep", _sleep)
        with pytest.raises(_Stop):
            metrics_exporter.serve("127.0.0.1", 8001, str(tmp_path))
        registry = served["registry"]
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 1.0
        assert self._component(registry, "scheduler") == 0.0

    def test_the_described_names_are_the_collected_names(self, answer):
        answer(HEALTHY)
        collector = metrics_exporter.AirflowHealthCollector()
        described = {family.name for family in collector.describe()}
        collected = {family.name for family in collector.collect()}
        assert described == collected == {"edgeguard_airflow_health_up", "edgeguard_airflow_component_healthy"}


# ---------------------------------------------------------------------------
# Alert rules and their documentation
# ---------------------------------------------------------------------------


def _alert(name):
    rules = yaml.safe_load((_ROOT / "prometheus" / "alerts.yml").read_text())
    found = [r for g in rules["groups"] for r in g["rules"] if r.get("alert") == name]
    assert len(found) == 1, name
    return found[0]


class TestAlerts:
    def test_scheduler_down_is_critical_after_5_minutes(self):
        rule = _alert("EdgeGuardAirflowSchedulerDown")
        assert rule["expr"].strip() == 'edgeguard_airflow_component_healthy{component="scheduler"} == 0'
        assert rule["for"] == "5m"
        assert rule["labels"] == {"severity": "critical", "component": "airflow"}
        description = rule["annotations"]["description"]
        assert "do not trigger it again" in description and RUNBOOK_SECTION in description

    def test_the_other_components_are_a_warning_after_10_minutes(self):
        rule = _alert("EdgeGuardAirflowComponentUnhealthy")
        assert rule["expr"].strip() == 'edgeguard_airflow_component_healthy{component!="scheduler"} == 0'
        assert rule["for"] == "10m"
        assert rule["labels"] == {"severity": "warning", "component": "airflow"}
        assert "$labels.component" in rule["annotations"]["summary"]

    def test_an_unanswered_health_endpoint_is_a_warning_after_10_minutes(self):
        rule = _alert("EdgeGuardAirflowHealthUnreachable")
        assert rule["expr"].strip() == "edgeguard_airflow_health_up == 0"
        assert rule["for"] == "10m"
        assert rule["labels"] == {"severity": "warning", "component": "airflow"}

    def test_the_rules_select_label_values_the_collector_emits(self):
        """The ``component`` values come from the payload keys (``AirflowHealthCollector`` emits one per key)."""
        emitted = set(airflow_client.component_health(UNHEALTHY).statuses)
        assert emitted == {"metadatabase", "scheduler", "triggerer", "dag_processor"}
        for name in ("EdgeGuardAirflowSchedulerDown", "EdgeGuardAirflowComponentUnhealthy"):
            selected = re.findall(r'component!?="([a-z_]+)"', _alert(name)["expr"])
            assert selected == ["scheduler"], name

    def test_the_docs_name_the_alerts_and_the_metrics(self):
        table = (_ROOT / "docs" / "PROMETHEUS_SETUP.md").read_text().split("\n## History", 1)[0]
        for name in _AIRFLOW_ALERTS:
            assert f"| `{name}` |" in table, name
        for metric in ("edgeguard_airflow_health_up", "edgeguard_airflow_component_healthy"):
            assert f"| `{metric}` |" in table, metric
        assert f"`{metrics_exporter.AIRFLOW_HEALTH_ENV}`" in table
        runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
        section = runbook.split(f"## {RUNBOOK_SECTION}", 1)[1].split("\n## ", 1)[0]
        for text in ("EdgeGuardAirflowSchedulerDown", "docker compose restart airflow", "dagrun_timeout"):
            assert text in section, text
        assert "| `EdgeGuardAirflowSchedulerDown` | **critical** |" in runbook
        env_example = (_ROOT / ".env.example").read_text()
        assert f"# {metrics_exporter.AIRFLOW_HEALTH_ENV}=true" in env_example


# ---------------------------------------------------------------------------
# docker-compose.yml
# ---------------------------------------------------------------------------


def _compose():
    return yaml.safe_load((_ROOT / "docker-compose.yml").read_text())


class TestCompose:
    def test_the_healthcheck_reads_the_scheduler_status(self):
        test = _compose()["services"]["airflow"]["healthcheck"]["test"]
        assert test[0] == "CMD-SHELL" and len(test) == 2
        command = test[1]
        assert "curl -fsS" in command and "http://localhost:8082/api/v2/monitor/health" in command
        assert '["scheduler"]["status"] == "healthy"' in command
        # Compose interpolates "$" in the file; the command needs none.
        assert "$" not in command

    @pytest.fixture
    def run_healthcheck(self, tmp_path):
        """Run the healthcheck command with ``curl`` answering a payload and ``python`` = this interpreter."""
        command = _compose()["services"]["airflow"]["healthcheck"]["test"][1]
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text('#!/bin/sh\n[ -n "$STUB_BODY" ] || exit 7\ncat "$STUB_BODY"\n')
        (bin_dir / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        for stub in bin_dir.iterdir():
            stub.chmod(0o755)

        def _run(payload):
            env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}", "STUB_BODY": ""}
            if payload is not None:
                body = tmp_path / "body.json"
                body.write_text(payload if isinstance(payload, str) else json.dumps(payload))
                env["STUB_BODY"] = str(body)
            done = subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True, text=True, timeout=60)
            return done.returncode

        return _run

    def test_the_healthcheck_passes_only_a_healthy_scheduler(self, run_healthcheck):
        assert run_healthcheck(HEALTHY) == 0
        assert run_healthcheck(UNHEALTHY) != 0
        assert run_healthcheck(dict(UNHEALTHY, scheduler=HEALTHY["scheduler"])) == 0, "a dead triggerer alone"
        assert run_healthcheck({k: v for k, v in HEALTHY.items() if k != "scheduler"}) != 0
        assert run_healthcheck(dict(HEALTHY, scheduler={"status": None})) != 0
        assert run_healthcheck("<html>proxy error</html>") != 0
        assert run_healthcheck(None) != 0, "curl fails"

    def test_the_metrics_service_reads_the_airflow_api_server(self):
        services = _compose()["services"]
        env = services["metrics"]["environment"]
        port = str(services["airflow"]["environment"]["AIRFLOW__API__PORT"])
        assert env["AIRFLOW_WEBSERVER_URL"] == f"http://airflow:{port}"
        assert env[metrics_exporter.AIRFLOW_HEALTH_ENV] == "${EDGEGUARD_METRICS_AIRFLOW_HEALTH:-true}"
        assert "edgeguard_net" in services["metrics"]["networks"] and "edgeguard_net" in services["airflow"]["networks"]

    def test_no_service_waits_for_a_healthy_airflow(self):
        """The healthcheck turns unhealthy with the scheduler; no service start depends on it."""
        for name, service in _compose()["services"].items():
            depends = service.get("depends_on") or {}
            if isinstance(depends, dict) and "airflow" in depends:
                assert depends["airflow"]["condition"] == "service_started", name


# ---------------------------------------------------------------------------
# scripts/preflight_baseline.sh check [13]
# ---------------------------------------------------------------------------

_SECRET = "s3cret-Passw0rd"


class TestPreflightScriptCheck13:
    @pytest.fixture
    def run_check(self, tmp_path):
        script = (_ROOT / "scripts" / "preflight_baseline.sh").read_text()
        block = script[script.index('hdr "[13]') : script.index("# Summary\n")]
        block = block[: block.rindex("esac\n") + 5]
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(
            '#!/bin/sh\necho "$*" >> "$STUB_DIR/curl_args"\n[ -n "$STUB_BODY" ] || exit 7\ncat "$STUB_BODY"\n'
        )
        # docker compose exec -T airflow airflow config get-value database sql_alchemy_conn
        (bin_dir / "docker").write_text(
            '#!/bin/sh\necho "$*" >> "$STUB_DIR/docker_args"\n'
            'echo "[2026-11-01T12:00:00] {configuration.py} WARNING - a log line"\n'
            'echo "$STUB_CONN"\n'
        )
        for stub in bin_dir.iterdir():
            stub.chmod(0o755)
        harness = (
            "set -uo pipefail\n"
            'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n' + block
        )

        def _run(payload, launch_path="dag", conn_env=None, docker_conn=None, url=None):
            env = {
                "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "STUB_DIR": str(tmp_path),
                "STUB_BODY": "",
                "STUB_CONN": docker_conn or "",
                "LAUNCH_PATH": launch_path,
            }
            if payload is not None:
                body = tmp_path / "body.json"
                body.write_text(json.dumps(payload))
                env["STUB_BODY"] = str(body)
            if conn_env is not None:
                env["AIRFLOW__DATABASE__SQL_ALCHEMY_CONN"] = conn_env
            if url is not None:
                env["AIRFLOW_WEBSERVER_URL"] = url
            done = subprocess.run(
                ["bash", "-c", harness], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
            )
            assert done.returncode == 0, done.stderr
            assert _SECRET not in done.stdout + done.stderr, "the connection string is never printed"
            return done.stdout.splitlines()

        return _run

    @staticmethod
    def _kinds(lines):
        return [line.split("|", 1)[0] for line in lines]

    def test_dead_scheduler_fails_the_dag_path(self, run_check, tmp_path):
        lines = run_check(UNHEALTHY, conn_env=f"postgresql+psycopg2://airflow:{_SECRET}@airflow_postgres:5432/airflow")
        assert self._kinds(lines) == ["PASS", "FAIL", "WARN", "PASS", "PASS"]
        assert lines[1].startswith(f"FAIL|Airflow scheduler: unhealthy (last heartbeat {SCHEDULER_HEARTBEAT})")
        assert "do not trigger it again" in lines[1]
        assert lines[2].startswith("WARN|Airflow triggerer: unhealthy")
        assert lines[4] == "PASS|Airflow metadata database is postgresql (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN)"
        assert (tmp_path / "curl_args").read_text().split() == [
            "-fsS",
            "--max-time",
            "15",
            "http://localhost:8082/api/v2/monitor/health",
        ]

    def test_dead_scheduler_is_a_warning_on_the_cli_path(self, run_check):
        lines = run_check(UNHEALTHY, launch_path="cli")
        assert self._kinds(lines)[:4] == ["PASS", "WARN", "WARN", "PASS"]
        assert "the scheduled DAGs do not run" in lines[1]

    def test_healthy_airflow_passes(self, run_check):
        lines = run_check(HEALTHY, url="http://airflow.test:8082/")
        assert self._kinds(lines[:4]) == ["PASS"] * 4

    def test_missing_or_null_scheduler_status_is_not_healthy(self, run_check):
        missing = {k: v for k, v in HEALTHY.items() if k != "scheduler"}
        assert run_check(missing)[1] == "FAIL|Airflow scheduler: unknown — " + (
            "no task starts and DAG runs do not progress; restart Airflow (docker compose restart airflow, "
            "or restart airflow standalone); a DAG run in progress continues where it stopped, do not trigger "
            'it again (docs/RUNBOOK.md, "Airflow scheduler or triggerer stopped")'
        )
        assert run_check(dict(HEALTHY, scheduler={"status": None}))[1].startswith("FAIL|Airflow scheduler: unknown")
        assert run_check(dict(HEALTHY, triggerer={"status": None}))[2].startswith("WARN|Airflow triggerer: unknown")

    def test_unreachable_airflow_is_a_warning(self, run_check):
        lines = run_check(None)
        assert lines[0].startswith(
            "WARN|Airflow health endpoint not reachable at http://localhost:8082/api/v2/monitor/health"
        )

    def test_sqlite_from_the_environment_is_a_warning(self, run_check):
        lines = run_check(HEALTHY, launch_path="cli", conn_env="sqlite:////Users/x/airflow/airflow.db")
        sqlite = lines[-1]
        assert sqlite.startswith("WARN|Airflow metadata database is SQLite (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN)")
        assert "development only" in sqlite and "PostgreSQL" in sqlite and "?timeout=60" in sqlite

    def test_the_dag_path_asks_the_airflow_service_without_printing_the_value(self, run_check, tmp_path):
        lines = run_check(HEALTHY, docker_conn=f"sqlite:////opt/airflow/{_SECRET}/airflow.db")
        assert lines[-1].startswith("WARN|Airflow metadata database is SQLite (airflow config get-value")
        assert (tmp_path / "docker_args").read_text().strip() == (
            "compose exec -T airflow airflow config get-value database sql_alchemy_conn"
        )
        lines = run_check(HEALTHY, docker_conn=f"postgresql+psycopg2://airflow:{_SECRET}@airflow_postgres/airflow")
        assert (
            lines[-1]
            == "PASS|Airflow metadata database is postgresql (airflow config get-value database sql_alchemy_conn)"
        )

    def test_the_cli_path_without_the_variable_does_not_ask_docker(self, run_check, tmp_path):
        lines = run_check(HEALTHY, launch_path="cli", docker_conn="sqlite:////x.db")
        assert lines[-1].startswith("  - Airflow metadata database backend not checked")
        assert not (tmp_path / "docker_args").exists()

    def test_the_header_and_the_help_list_check_13(self):
        script = (_ROOT / "scripts" / "preflight_baseline.sh").read_text()
        header = script.split("set -uo pipefail", 1)[0]
        assert "#   [13] Airflow components and metadata database" in header
        done = subprocess.run(
            ["bash", str(_ROOT / "scripts" / "preflight_baseline.sh"), "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert "[13] Airflow components and metadata database" in done.stdout
        assert "# Usage:" in done.stdout
