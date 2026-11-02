"""Detection of a dead Airflow scheduler.

``airflow standalone`` (the Compose ``airflow`` service, or a bare-metal install that runs it) runs the
scheduler, triggerer, DAG processor and API server as subprocesses and neither restarts nor exits when
one of them dies. ``/api/v2/monitor/health`` then answers HTTP 200 with ``unhealthy`` in its JSON body
only, so every check that read the HTTP status or reachability alone reported Airflow as fine while no
task started and a DAG run stayed ``running`` (``dagrun_timeout`` is enforced by the scheduler).

The fixtures are the real answers of an Airflow 3.3.2 standalone install on 2026-11-01: the scheduler
and triggerer stopped on a metadata database error while the DAG processor kept running
(``airflow_health_unhealthy_2026_11_01.json``), and the same install after a restart
(``airflow_health_healthy_2026_11_01.json``).

Two shapes are derived from Airflow 3.3.2's ``airflow/api/common/airflow_health.py``: a metadata database
that the API server cannot read (every component then reports ``unhealthy``) and a deployment whose
triggerer and DAG processor run no job of their own (``null`` status, as the DAG processor of Airflow 2
by default).

Covered: the shared reader ``airflow_client.component_health``, each caller end to end (``doctor``,
``dag status``, ``dag kill``, ``preflight``, the metrics exporter's collector, the Compose healthcheck,
check ``[13]`` of ``scripts/preflight_baseline.sh``, the probe of ``scripts/runtime_smoke_checklist.sh``),
and the alert rules that read the new gauges.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import shutil
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
# The API server's job queries fail: metadatabase "unhealthy", and every component keeps its "unhealthy"
# default without a heartbeat (get_airflow_health sets nothing else when the queries raise).
DATABASE_DOWN = {
    "metadatabase": {"status": "unhealthy"},
    "scheduler": {"status": "unhealthy", "latest_scheduler_heartbeat": None},
    "triggerer": {"status": "unhealthy", "latest_triggerer_heartbeat": None},
    "dag_processor": {"status": "unhealthy", "latest_dag_processor_heartbeat": None},
}
# No triggerer or DAG processor job recorded: Airflow reports a null status for both.
WITHOUT_JOBS = dict(
    HEALTHY,
    triggerer={"status": None, "latest_triggerer_heartbeat": None},
    dag_processor={"status": None, "latest_dag_processor_heartbeat": None},
)
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

    def test_a_missing_scheduler_is_not_healthy(self):
        payload = {name: entry for name, entry in HEALTHY.items() if name != "scheduler"}
        health = airflow_client.component_health(payload)
        assert health.not_healthy() == ["scheduler"] and health.without_job() == []
        assert "scheduler" not in health.statuses
        assert health.describe("scheduler") == "scheduler not reported by Airflow"

    def test_a_missing_triggerer_runs_no_job(self):
        payload = {name: entry for name, entry in HEALTHY.items() if name != "triggerer"}
        health = airflow_client.component_health(payload)
        assert not health.is_healthy("triggerer")
        assert health.not_healthy() == [] and health.without_job() == ["triggerer"]
        assert health.describe("triggerer") == "triggerer not reported by Airflow"

    def test_a_null_scheduler_status_is_not_healthy(self):
        health = airflow_client.component_health(dict(HEALTHY, scheduler={"status": None}))
        assert health.statuses["scheduler"] is None
        assert health.not_healthy() == ["scheduler"] and health.without_job() == []
        assert health.describe("scheduler") == "scheduler without status (no scheduler job recorded)"

    def test_a_null_triggerer_or_dag_processor_status_runs_no_job(self):
        """Airflow reports ``null`` for a triggerer or DAG processor of which it has recorded no job."""
        health = airflow_client.component_health(WITHOUT_JOBS)
        assert health.statuses["triggerer"] is None and health.statuses["dag_processor"] is None
        assert not health.is_healthy("triggerer") and not health.is_healthy("dag_processor")
        assert health.not_healthy() == []
        assert health.without_job() == ["triggerer", "dag_processor"]
        assert health.describe("dag_processor") == "dag_processor without status (no dag_processor job recorded)"

    def test_an_unreadable_metadata_database_makes_every_component_unhealthy(self):
        health = airflow_client.component_health(DATABASE_DOWN)
        assert health.not_healthy() == list(airflow_client.AIRFLOW_HEALTH_COMPONENTS)
        assert health.without_job() == []
        assert health.describe("scheduler") == "scheduler unhealthy"

    @pytest.mark.parametrize("entry", ["healthy", None, ["healthy"], {"status": True}, {}])
    def test_a_malformed_scheduler_entry_is_not_healthy(self, entry):
        health = airflow_client.component_health(dict(HEALTHY, scheduler=entry))
        assert health.statuses["scheduler"] is None
        assert health.not_healthy() == ["scheduler"]

    def test_an_error_answer_is_unreachable(self):
        health = airflow_client.component_health({"error": "Cannot connect to Airflow at http://x:8082."})
        assert not health.reachable
        assert health.error == "Cannot connect to Airflow at http://x:8082."
        assert health.statuses == {} and health.not_healthy() == ["metadatabase", "scheduler"]

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


def test_the_cli_errors_are_the_required_components():
    assert edgeguard._AIRFLOW_ERROR_COMPONENTS == airflow_client.AIRFLOW_REQUIRED_COMPONENTS


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
        assert "ℹ" in recover and "do not trigger the DAG run again" in recover
        # A restart stops a task still running, and the new scheduler runs it again from its start.
        assert "runs again from its start" in recover and "let it end first" in recover
        assert "states-for-dag-run" in recover
        assert not any("restore the metadata database" in ln for ln in lines), "the database is healthy"
        assert "✗" in _line(lines, "EdgeGuard has issues")
        # The DAG list still runs: the API server answers.
        assert "✓" in _line(lines, "Active DAGs: edgeguard_baseline")

    def test_a_dead_triggerer_alone_is_a_warning_without_a_restart_during_a_run(self, run_doctor):
        payload = dict(HEALTHY, triggerer=UNHEALTHY["triggerer"])
        code, lines, calls = run_doctor(payload)
        assert code == 0 and calls == 1
        assert "⚠" in _line(lines, "Airflow triggerer unhealthy")
        later = _line(lines, "Recover: a DAG run in progress continues without the triggerer")
        assert "ℹ" in later and "restart Airflow when no DAG run is in progress" in later
        assert not any("Recover: restart Airflow" in ln for ln in lines)
        assert not any("✗" in ln for ln in lines)

    def test_a_triggerer_and_dag_processor_without_job_are_information(self, run_doctor):
        """Airflow 2 parses the DAG files in the scheduler: its DAG processor reports a null status."""
        code, lines, calls = run_doctor(WITHOUT_JOBS)
        assert code == 0 and calls == 1
        assert "✓" in _line(lines, "Airflow components healthy: metadatabase, scheduler")
        for name in ("triggerer", "dag_processor"):
            line = _line(lines, f"Airflow {name} without status (no {name} job recorded)")
            assert "ℹ" in line and "it does not run as a process of its own" in line
        assert not any("⚠" in ln or "✗" in ln for ln in lines if "Airflow" in ln)
        assert not any("Recover:" in ln for ln in lines)
        assert "✓" in _line(lines, "EdgeGuard is healthy")

    def test_an_unreadable_metadata_database_is_restored_before_the_restart(self, run_doctor):
        code, lines, calls = run_doctor(DATABASE_DOWN)
        assert code == 1 and calls == 2
        assert "✗" in _line(lines, "Airflow metadatabase unhealthy: the API server cannot read")
        assert "✗" in _line(lines, "Airflow scheduler unhealthy: no task starts")
        assert "⚠" in _line(lines, "Airflow triggerer unhealthy")
        database = _line(lines, "Recover: restore the metadata database first")
        assert "docker compose ps airflow_postgres" in database
        assert lines.index(database) < lines.index(_line(lines, "Recover: restart Airflow"))


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
        assert "do not trigger the runs again" in final
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

    def test_a_triggerer_and_dag_processor_without_job_are_ready(self, run_preflight):
        code, summary, text = run_preflight(WITHOUT_JOBS)
        assert (code, summary["errors"], summary["warnings"]) == (0, 0, 0), text
        assert "Airflow dag_processor without status (no dag_processor job recorded)" in text
        code, _, _ = run_preflight(WITHOUT_JOBS, strict=True)
        assert code == 0, "no warning, so --strict passes too"

    def test_an_unreadable_metadata_database_counts_two_errors(self, run_preflight):
        code, summary, text = run_preflight(DATABASE_DOWN)
        assert (code, summary["errors"], summary["warnings"]) == (1, 2, 2), text
        assert "Recover: restore the metadata database first" in text

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

    def test_a_scheduler_without_status_or_missing_is_0(self, answer):
        answer({"metadatabase": {"status": "healthy"}, "scheduler": {"status": None}})
        registry = self._registry()
        assert self._component(registry, "metadatabase") == 1.0
        assert self._component(registry, "scheduler") == 0.0
        answer({"metadatabase": {"status": "healthy"}})
        assert self._component(self._registry(), "scheduler") == 0.0, "SchedulerDown fires on a missing scheduler"

    def test_a_triggerer_or_dag_processor_without_job_has_no_series(self, answer):
        answer(WITHOUT_JOBS)
        registry = self._registry()
        assert self._component(registry, "scheduler") == 1.0 and self._component(registry, "metadatabase") == 1.0
        assert self._component(registry, "triggerer") is None
        assert self._component(registry, "dag_processor") is None
        answer({name: entry for name, entry in HEALTHY.items() if name != "triggerer"})
        assert self._component(self._registry(), "triggerer") is None

    def test_an_unreadable_metadata_database_gives_every_component_0(self, answer):
        answer(DATABASE_DOWN)
        registry = self._registry()
        assert registry.get_sample_value("edgeguard_airflow_health_up") == 1.0
        for name in airflow_client.AIRFLOW_HEALTH_COMPONENTS:
            assert self._component(registry, name) == 0.0, name

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
# src/metrics_server.py serves the gauges as well (2026-11)
# ---------------------------------------------------------------------------


class TestMetricsServerServesAirflowHealth:
    """``python src/metrics_server.py`` (PROMETHEUS_SETUP Option A on a bare-metal install), the in-task server of a
    single-process install and the ``edgeguard_metrics_server`` DAG serve the Airflow health gauges as the exporter
    does. Before, only ``metrics_exporter.serve`` registered the collector, so on these servers the series were
    absent and the alerts on them (plain comparisons, no ``absent()``) could not fire. Measured before the change:
    no ``edgeguard_airflow_*`` series from ``MetricsServer`` in either mode."""

    @pytest.fixture
    def scrape(self, monkeypatch):
        """Start ``MetricsServer`` on a free port and return a function that scrapes its ``/metrics``."""
        import urllib.request

        import metrics_server

        monkeypatch.delenv(metrics_exporter.AIRFLOW_HEALTH_ENV, raising=False)
        monkeypatch.delenv(metrics_exporter.MULTIPROC_ENV, raising=False)
        monkeypatch.setitem(sys.modules, "airflow_client", airflow_client)
        servers = []

        def _start():
            server = metrics_server.MetricsServer(host="127.0.0.1", port=0)
            assert server.start_threaded() is not None
            servers.append(server)
            return server

        def _scrape(server=None):
            server = server or (servers[-1] if servers else _start())
            port = server.server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=30) as answer:
                return answer.read().decode()

        _scrape.start = _start
        yield _scrape
        for server in servers:
            server.stop()
        # The collector on the default registry would ask Airflow at every later collection of it.
        if metrics_server._airflow_health_collector is not None:
            metrics_server.registry.unregister(metrics_server._airflow_health_collector)
        metrics_server._airflow_health_collector = None
        metrics_server._airflow_health_served = None

    @staticmethod
    def _series(text):
        return sorted(line for line in text.splitlines() if line.startswith("edgeguard_airflow_"))

    def test_unreachable_airflow_is_served_as_health_up_0(self, scrape, monkeypatch):
        """The real health call against a closed port: the endpoint does not answer."""
        monkeypatch.setenv("AIRFLOW_WEBSERVER_URL", "http://127.0.0.1:9")
        assert self._series(scrape()) == ["edgeguard_airflow_health_up 0.0"]

    def test_a_dead_scheduler_is_served(self, scrape, monkeypatch):
        monkeypatch.setattr(airflow_client, "airflow_health", lambda timeout=None: UNHEALTHY)
        assert self._series(scrape()) == [
            'edgeguard_airflow_component_healthy{component="dag_processor"} 1.0',
            'edgeguard_airflow_component_healthy{component="metadatabase"} 1.0',
            'edgeguard_airflow_component_healthy{component="scheduler"} 0.0',
            'edgeguard_airflow_component_healthy{component="triggerer"} 0.0',
            "edgeguard_airflow_health_up 1.0",
        ]

    def test_the_multi_process_mode_serves_them_with_the_aggregate(self, scrape, monkeypatch, tmp_path):
        monkeypatch.setattr(airflow_client, "airflow_health", lambda timeout=None: UNHEALTHY)
        monkeypatch.setenv(metrics_exporter.MULTIPROC_ENV, str(tmp_path))
        first, second = scrape(), scrape()
        assert 'edgeguard_airflow_component_healthy{component="scheduler"} 0.0' in self._series(first)
        assert self._series(first) == self._series(second), "a fresh registry per scrape, one collector on it"
        import metrics_server

        assert metrics_server._airflow_health_collector is None, "the default registry is not served here"

    def test_two_servers_register_the_collector_once(self, scrape, monkeypatch, caplog):
        import metrics_server

        monkeypatch.setattr(airflow_client, "airflow_health", lambda timeout=None: HEALTHY)
        with caplog.at_level(logging.WARNING, logger="metrics_server"):
            first, second = scrape.start(), scrape.start()
        collector = metrics_server._airflow_health_collector
        assert collector is not None and metrics_server._airflow_health_served is True
        assert not [r for r in caplog.records if "not served" in r.getMessage()]
        for server in (first, second):
            assert self._series(scrape(server)).count("edgeguard_airflow_health_up 1.0") == 1

    @pytest.mark.parametrize("multiprocess", [False, True])
    def test_switched_off(self, scrape, monkeypatch, tmp_path, multiprocess):
        calls = []
        monkeypatch.setattr(airflow_client, "airflow_health", lambda timeout=None: calls.append(timeout) or HEALTHY)
        monkeypatch.setenv(metrics_exporter.AIRFLOW_HEALTH_ENV, "false")
        if multiprocess:
            monkeypatch.setenv(metrics_exporter.MULTIPROC_ENV, str(tmp_path))
        assert self._series(scrape()) == [] and calls == []

    def test_importing_the_module_registers_nothing(self):
        """A DAG file imports ``metrics_server``: the import alone must neither register the collector nor ask
        Airflow (a fresh interpreter, Airflow at a closed port)."""
        code = (
            "import sys; sys.path.insert(0, 'src'); import metrics_server; "
            "from prometheus_client import REGISTRY; "
            "print(REGISTRY.get_sample_value('edgeguard_airflow_health_up'), metrics_server._airflow_health_served)"
        )
        env = {k: v for k, v in os.environ.items() if k != metrics_exporter.MULTIPROC_ENV}
        env["AIRFLOW_WEBSERVER_URL"] = "http://127.0.0.1:9"
        done = subprocess.run(
            [sys.executable, "-c", code], cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120
        )
        assert done.returncode == 0, done.stderr
        assert done.stdout.split() == ["None", "None"]


# ---------------------------------------------------------------------------
# Alert rules and their documentation
# ---------------------------------------------------------------------------


def _alert_rules():
    rules = yaml.safe_load((_ROOT / "prometheus" / "alerts.yml").read_text())
    return [r for g in rules["groups"] for r in g["rules"] if "alert" in r]


def _alert(name):
    found = [r for r in _alert_rules() if r["alert"] == name]
    assert len(found) == 1, name
    return found[0]


def _collected(monkeypatch, payload):
    """The samples ``AirflowHealthCollector`` serves for ``payload``: ``(name, labels, value)``."""
    monkeypatch.setitem(sys.modules, "airflow_client", airflow_client)
    monkeypatch.setattr(airflow_client, "airflow_health", lambda timeout=None: payload)
    collector = metrics_exporter.AirflowHealthCollector()
    return [(x.name, x.labels, x.value) for family in collector.collect() for x in family.samples]


def _firing(rule, samples):
    """The label sets of the alerts that ``rule`` (``<metric>{<label>="v"} == 0`` or ``!=``) raises for
    ``samples``, after Prometheus applies the rule's labels, which overwrite a series label of the same
    name."""
    match = re.fullmatch(r'(\w+)\{(\w+)(!?=)"([^"]*)"\} == 0', rule["expr"].strip())
    assert match, rule["expr"]
    metric, label, op, value = match.groups()
    return [
        frozenset({**labels, **rule["labels"], "alertname": rule["alert"]}.items())
        for name, labels, sample in samples
        if name == metric and sample == 0 and (labels.get(label) == value) == (op == "=")
    ]


class TestAlerts:
    def test_scheduler_down_is_critical_after_5_minutes(self):
        rule = _alert("EdgeGuardAirflowSchedulerDown")
        assert rule["expr"].strip() == 'edgeguard_airflow_component_healthy{component="scheduler"} == 0'
        assert rule["for"] == "5m"
        assert rule["labels"] == {"severity": "critical"}, "the alert keeps the series' component label"
        description = rule["annotations"]["description"]
        assert "do not trigger the run again" in description and RUNBOOK_SECTION in description
        assert "runs again from its start" in description and "restore the database first" in description

    def test_the_other_components_are_a_warning_after_10_minutes(self):
        rule = _alert("EdgeGuardAirflowComponentUnhealthy")
        assert rule["expr"].strip() == 'edgeguard_airflow_component_healthy{component!="scheduler"} == 0'
        assert rule["for"] == "10m"
        assert rule["labels"] == {"severity": "warning"}, "the alert keeps the series' component label"
        assert "$labels.component" in rule["annotations"]["summary"]
        description = rule["annotations"]["description"]
        assert "restart Airflow when no DAG run is in progress" in description
        assert "restore the database first" in description

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

    def test_no_rule_label_overwrites_a_label_of_the_component_gauge(self, monkeypatch):
        gauge_labels = {
            key
            for name, labels, _ in _collected(monkeypatch, UNHEALTHY)
            if name == "edgeguard_airflow_component_healthy"
            for key in labels
        }
        assert gauge_labels == {"component"}
        selecting = [r for r in _alert_rules() if "edgeguard_airflow_component_healthy" in r["expr"]]
        assert {r["alert"] for r in selecting} == set(_AIRFLOW_ALERTS[:2])
        for rule in selecting:
            assert not gauge_labels & set(rule["labels"]), rule["alert"]

    def test_components_down_at_once_give_one_alert_each(self, monkeypatch):
        """A database outage reports every component unhealthy. Prometheus refuses to evaluate a rule
        whose alerts share one label set after its rule labels are applied, so the warning would not
        fire if a rule label overwrote ``component``."""
        samples = _collected(monkeypatch, DATABASE_DOWN)
        warnings = _firing(_alert("EdgeGuardAirflowComponentUnhealthy"), samples)
        assert len(warnings) == len(set(warnings)) == 3
        assert {dict(a)["component"] for a in warnings} == {"metadatabase", "triggerer", "dag_processor"}
        critical = _firing(_alert("EdgeGuardAirflowSchedulerDown"), samples)
        assert [dict(a)["component"] for a in critical] == ["scheduler"]
        assert dict(critical[0])["severity"] == "critical"

    def test_the_stalled_install_raises_the_critical_alert_and_one_warning(self, monkeypatch):
        samples = _collected(monkeypatch, UNHEALTHY)
        assert len(_firing(_alert("EdgeGuardAirflowSchedulerDown"), samples)) == 1
        warnings = _firing(_alert("EdgeGuardAirflowComponentUnhealthy"), samples)
        assert [dict(a)["component"] for a in warnings] == ["triggerer"]

    def test_components_without_job_raise_no_alert(self, monkeypatch):
        samples = _collected(monkeypatch, WITHOUT_JOBS)
        for name in _AIRFLOW_ALERTS[:2]:
            assert _firing(_alert(name), samples) == [], name

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
        block = block[: block.rindex("\nfi\n") + 4]  # the end of the metadata database check
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(
            '#!/bin/sh\necho "$*" >> "$STUB_DIR/curl_args"\n[ -n "$STUB_BODY" ] || exit 7\ncat "$STUB_BODY"\n'
        )
        # The check never runs the airflow CLI: its first call writes an airflow.cfg and logs/ (2026-11).
        (bin_dir / "airflow").write_text('#!/bin/sh\necho "$*" >> "$STUB_DIR/airflow_args"\necho "sqlite:////x.db"\n')
        # A Compose install: docker compose exec -T airflow airflow config get-value database sql_alchemy_conn
        compose_dir = tmp_path / "compose"
        compose_dir.mkdir()
        (compose_dir / "docker").write_text(
            '#!/bin/sh\necho "$*" >> "$STUB_DIR/docker_args"\n'
            'echo "[2026-11-01T12:00:00] {configuration.py} WARNING - a log line"\n'
            'echo "$STUB_CONN"\n'
        )
        for stub in [*bin_dir.iterdir(), *compose_dir.iterdir()]:
            stub.chmod(0o755)
        # The other commands the check and the stubs run, and nothing else: no docker of this host is reachable.
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        for tool in ("python3", "tr", "cat"):
            found = shutil.which(tool)
            assert found is not None, tool
            (tools_dir / tool).symlink_to(os.path.realpath(found))
        bash = shutil.which("bash")
        assert bash is not None
        (tmp_path / "home").mkdir()
        # No LAUNCH_PATH: the DAG is the only launch path, and under ``set -u`` the check fails if it reads one.
        harness = (
            "set -uo pipefail\n"
            'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n' + block
        )

        def _run(payload, compose=True, conn_env=None, docker_conn=None, url=None, api_version=None, extra_env=None):
            """``compose=False``: an install without Compose, with no ``docker`` on the PATH."""
            path = [bin_dir, compose_dir, tools_dir] if compose else [bin_dir, tools_dir]
            env = {
                "PATH": os.pathsep.join(str(directory) for directory in path),
                "STUB_DIR": str(tmp_path),
                "STUB_BODY": "",
                "STUB_CONN": docker_conn or "",
                # An empty home: the check never reads the developer's ~/airflow/airflow.cfg.
                "HOME": str(tmp_path / "home"),
                **(extra_env or {}),
            }
            if payload is not None:
                body = tmp_path / "body.json"
                body.write_text(json.dumps(payload))
                env["STUB_BODY"] = str(body)
            if conn_env is not None:
                env["AIRFLOW__DATABASE__SQL_ALCHEMY_CONN"] = conn_env
            if url is not None:
                env["AIRFLOW_WEBSERVER_URL"] = url
            if api_version is not None:
                env["AIRFLOW_API_VERSION"] = api_version
            done = subprocess.run(
                [bash, "-c", harness], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
            )
            assert done.returncode == 0, done.stderr
            assert _SECRET not in done.stdout + done.stderr, "the connection string is never printed"
            assert not (tmp_path / "airflow_args").exists(), "the airflow CLI is never run"
            return done.stdout.splitlines()

        return _run

    @staticmethod
    def _cfg(directory, conn=None, line=None):
        """``directory/airflow.cfg``: Airflow 3.3.2's own (``fixtures/airflow_3_3_2_cfg_database.cfg``: its
        ``[core]`` start and ``[database]`` section as the first CLI call wrote them), with ``conn`` as its
        ``sql_alchemy_conn`` or ``line`` in place of that line."""
        text = (_FIXTURES / "airflow_3_3_2_cfg_database.cfg").read_text()
        default = "sql_alchemy_conn = sqlite:////home/edgeguard/airflow/airflow.db\n"
        assert text.count(default) == 1
        if conn is not None:
            text = text.replace(default, f"sql_alchemy_conn = {conn}\n")
        elif line is not None:
            text = text.replace(default, line)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "airflow.cfg"
        path.write_text(text)
        return path

    @staticmethod
    def _kinds(lines):
        return [line.split("|", 1)[0] for line in lines]

    def test_dead_scheduler_fails_the_dag_path(self, run_check, tmp_path):
        lines = run_check(UNHEALTHY, conn_env=f"postgresql+psycopg2://airflow:{_SECRET}@airflow_postgres:5432/airflow")
        assert self._kinds(lines) == ["PASS", "FAIL", "WARN", "PASS", "PASS"]
        assert lines[1].startswith(f"FAIL|Airflow scheduler: unhealthy (last heartbeat {SCHEDULER_HEARTBEAT})")
        assert "restart Airflow" in lines[1] and "before the launch" in lines[1]
        assert '"Airflow scheduler or triggerer stopped"' in lines[1]
        assert "restore the metadata database" not in lines[1]
        assert lines[2].startswith("WARN|Airflow triggerer: unhealthy")
        assert lines[4] == "PASS|Airflow metadata database is postgresql (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN)"
        assert (tmp_path / "curl_args").read_text().split() == [
            "-fsS",
            "--max-time",
            "15",
            "http://localhost:8082/api/v2/monitor/health",
        ]

    def test_dead_scheduler_fails_without_compose_too(self, run_check, tmp_path):
        """The ``edgeguard_baseline`` DAG is the only launch path, with Compose or without it: a scheduler that is
        not healthy fails the check on every install (it was a warning on the retired ``cli`` path)."""
        lines = run_check(UNHEALTHY, compose=False)
        assert self._kinds(lines)[:4] == ["PASS", "FAIL", "WARN", "PASS"]
        assert lines[1].startswith("FAIL|Airflow scheduler: unhealthy")
        assert "no task starts and DAG runs do not progress" in lines[1]
        assert not (tmp_path / "docker_args").exists()

    def test_healthy_airflow_passes(self, run_check):
        lines = run_check(HEALTHY, url="http://airflow.test:8082/")
        assert self._kinds(lines[:4]) == ["PASS"] * 4

    def test_missing_or_null_scheduler_status_is_not_healthy(self, run_check):
        missing = {k: v for k, v in HEALTHY.items() if k != "scheduler"}
        assert run_check(missing)[1] == "FAIL|Airflow scheduler: unknown — " + (
            "no task starts and DAG runs do not progress; restart Airflow (docker compose restart airflow, "
            "or restart airflow standalone) before the launch; with a DAG run in progress, read "
            'docs/RUNBOOK.md, "Airflow scheduler or triggerer stopped" first'
        )
        assert run_check(dict(HEALTHY, scheduler={"status": None}))[1].startswith("FAIL|Airflow scheduler: unknown")

    def test_a_triggerer_or_dag_processor_without_job_is_information(self, run_check):
        lines = run_check(WITHOUT_JOBS, conn_env="postgresql://airflow@db/airflow")
        assert self._kinds(lines)[:2] == ["PASS", "PASS"]
        assert lines[2] == (
            "  - Airflow triggerer: unknown — no triggerer job recorded; it does not run as a process of its own"
        )
        assert lines[3].startswith("  - Airflow dag_processor: unknown — no dag_processor job recorded")
        assert not any(line.startswith(("WARN|", "FAIL|")) for line in lines)

    def test_an_unreadable_metadata_database_is_restored_first(self, run_check):
        lines = run_check(DATABASE_DOWN, conn_env="postgresql://airflow@db/airflow")
        assert self._kinds(lines)[:4] == ["FAIL", "FAIL", "WARN", "WARN"]
        assert lines[0].startswith("FAIL|Airflow metadatabase: unhealthy — no task starts")
        assert "restore the metadata database first (docker compose ps airflow_postgres" in lines[0]
        assert "restore the metadata database" not in lines[1]

    def test_airflow_2_is_asked_at_its_health_path(self, run_check, tmp_path):
        run_check(WITHOUT_JOBS, api_version=" V1 ")
        assert (tmp_path / "curl_args").read_text().split()[-1] == "http://localhost:8082/health"

    def test_unreachable_airflow_is_a_warning(self, run_check):
        lines = run_check(None)
        assert lines[0].startswith(
            "WARN|Airflow health endpoint not reachable at http://localhost:8082/api/v2/monitor/health"
        )

    def test_sqlite_from_the_environment_is_a_warning(self, run_check):
        lines = run_check(HEALTHY, compose=False, conn_env="sqlite:////Users/x/airflow/airflow.db")
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

    def test_without_compose_the_check_goes_on_to_the_cfg_and_the_default(self, run_check, tmp_path):
        """No ``docker`` on the PATH: no Compose service is asked, and the lookup goes on to airflow.cfg and
        Airflow's default (it does not stop at a ``docker compose`` that cannot run)."""
        lines = run_check(HEALTHY, compose=False, docker_conn="postgresql://airflow@db/airflow")
        assert lines[-1].startswith("WARN|Airflow metadata database is SQLite (not set in this shell, and no ")
        assert not (tmp_path / "docker_args").exists()

    # 2026-11: a bare-metal install keeps the connection string in airflow.cfg, where the first CLI call
    # writes Airflow's default, SQLite (measured with Airflow 3.3.2); the check read only the environment
    # variable and printed "not checked" there, the case its SQLite warning exists for.
    def test_sqlite_in_airflow_cfg_is_a_warning(self, run_check, tmp_path):
        cfg = self._cfg(tmp_path / "afhome")
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1].startswith(f"WARN|Airflow metadata database is SQLite ([database] sql_alchemy_conn in {cfg}):")
        assert "development only" in lines[-1] and "?timeout=60" in lines[-1]

    def test_postgresql_in_airflow_cfg_passes_without_printing_the_value(self, run_check, tmp_path):
        cfg = self._cfg(tmp_path / "afhome", conn=f"postgresql+psycopg2://airflow:{_SECRET}@db:5432/airflow")
        lines = run_check(HEALTHY, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1] == f"PASS|Airflow metadata database is postgresql ([database] sql_alchemy_conn in {cfg})"
        assert (tmp_path / "docker_args").exists(), "the DAG path asks the airflow service first"

    def test_the_cfg_is_where_airflow_looks_for_it(self, run_check, tmp_path):
        """``AIRFLOW_CONFIG``, else ``$AIRFLOW_HOME/airflow.cfg``, else ``~/airflow/airflow.cfg``."""
        home_cfg = self._cfg(tmp_path / "home" / "airflow")
        lines = run_check(HEALTHY, compose=False)
        assert lines[-1].startswith(
            f"WARN|Airflow metadata database is SQLite ([database] sql_alchemy_conn in {home_cfg})"
        )
        self._cfg(tmp_path / "afhome", conn="postgresql://airflow@db/airflow")
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1].startswith("PASS|Airflow metadata database is postgresql")
        other = self._cfg(tmp_path / "elsewhere", conn="mysql://airflow@db/airflow")
        lines = run_check(
            HEALTHY,
            compose=False,
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome"), "AIRFLOW_CONFIG": str(other)},
        )
        assert lines[-1] == f"PASS|Airflow metadata database is mysql ([database] sql_alchemy_conn in {other})"

    def test_the_variable_takes_precedence_over_the_cfg(self, run_check, tmp_path):
        self._cfg(tmp_path / "afhome")
        lines = run_check(
            HEALTHY,
            compose=False,
            conn_env=f"postgresql+psycopg2://airflow:{_SECRET}@db/airflow",
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")},
        )
        assert lines[-1] == "PASS|Airflow metadata database is postgresql (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN)"

    def test_the_dag_path_reads_the_cfg_when_the_airflow_service_gives_no_value(self, run_check, tmp_path):
        cfg = self._cfg(tmp_path / "afhome")
        lines = run_check(HEALTHY, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert (tmp_path / "docker_args").exists()
        assert lines[-1].startswith(f"WARN|Airflow metadata database is SQLite ([database] sql_alchemy_conn in {cfg})")
        lines = run_check(HEALTHY, docker_conn="postgresql://airflow@airflow_postgres/airflow")
        assert lines[-1] == (
            "PASS|Airflow metadata database is postgresql (airflow config get-value database sql_alchemy_conn)"
        )

    def test_set_nowhere_is_airflows_default_sqlite(self, run_check, tmp_path):
        """No variable and no airflow.cfg: an Airflow started from this shell would use its default, SQLite. The
        check says so without running the airflow CLI, which would write a cfg and logs/ there."""
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1].startswith(
            f"WARN|Airflow metadata database is SQLite (not set in this shell, and no {tmp_path}/afhome/airflow.cfg: "
            "Airflow's default):"
        )
        assert not (tmp_path / "afhome").exists(), "nothing is written"

    def test_the_dag_path_without_any_answer_is_not_determined(self, run_check):
        lines = run_check(HEALTHY)
        assert lines[-1] == (
            "WARN|Airflow metadata database backend not determined "
            "(airflow config get-value database sql_alchemy_conn gave no connection string)"
        )

    @pytest.mark.parametrize(
        "variable",
        [
            "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD",
            "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_SECRET",
            "AIRFLOW__CORE__SQL_ALCHEMY_CONN_CMD",
        ],
    )
    def test_a_command_or_secret_is_not_run(self, run_check, tmp_path, variable):
        """Airflow takes these before airflow.cfg; the check neither runs the command nor reads the secret."""
        self._cfg(tmp_path / "afhome")
        lines = run_check(
            HEALTHY,
            compose=False,
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome"), variable: f"echo sqlite:////{_SECRET}.db"},
        )
        assert lines[-1] == (
            f"  - Airflow metadata database backend not checked ({variable} is set; this check runs no "
            "command and reads no secrets backend)"
        )

    def test_the_deprecated_core_variable_is_read(self, run_check, tmp_path):
        self._cfg(tmp_path / "afhome", conn="postgresql://airflow@db/airflow")
        lines = run_check(
            HEALTHY,
            compose=False,
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome"), "AIRFLOW__CORE__SQL_ALCHEMY_CONN": "sqlite:////x.db"},
        )
        assert lines[-1].startswith("WARN|Airflow metadata database is SQLite (AIRFLOW__CORE__SQL_ALCHEMY_CONN)")

    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            (
                "sql_alchemy_conn_cmd = cat /run/secrets/airflow_db\n",
                "  - Airflow metadata database backend not checked ([database] sql_alchemy_conn_cmd in {cfg}; this check runs no command and reads no secrets backend)",
            ),
            (
                "sql_alchemy_conn_secret = airflow/db\n",
                "  - Airflow metadata database backend not checked ([database] sql_alchemy_conn_secret in {cfg}; this check runs no command and reads no secrets backend)",
            ),
            ("\n", "WARN|Airflow metadata database is SQLite (not set in this shell or in {cfg}: Airflow's default): "),
        ],
    )
    def test_a_cfg_without_the_value(self, run_check, tmp_path, line, expected):
        cfg = self._cfg(tmp_path / "afhome", line=line)
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1].startswith(expected.format(cfg=cfg))

    def test_the_deprecated_core_option_in_the_cfg_is_read(self, run_check, tmp_path):
        cfg = self._cfg(tmp_path / "afhome", line="\n")
        cfg.write_text(
            cfg.read_text().replace("[core]\n", f"[core]\nsql_alchemy_conn = postgresql://airflow:{_SECRET}@db/af\n")
        )
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1] == f"PASS|Airflow metadata database is postgresql ([core] sql_alchemy_conn in {cfg})"

    def test_an_unreadable_cfg_is_not_determined(self, run_check, tmp_path):
        directory = tmp_path / "afhome"
        directory.mkdir()
        (directory / "airflow.cfg").write_text("sql_alchemy_conn = sqlite:////x.db\n")  # no section header
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(directory)})
        assert lines[-1] == (
            f"WARN|Airflow metadata database backend not determined ({directory}/airflow.cfg could not be read)"
        )

    # The lookup order, pinned with sources that disagree (2026-11-02). It is Airflow 3.3.2's: its own
    # conf.get("database", "sql_alchemy_conn") took the [database] name before the deprecated [core] one, in the
    # environment a value before its _CMD form and the environment before airflow.cfg, and in airflow.cfg every
    # value before every _cmd, the [database] _cmd before the [core] one; the _SECRET and _secret forms come after
    # the _CMD and _cmd ones in its code (_get_env_var_option, _lookup_sequence).
    _NOT_CHECKED = (
        "  - Airflow metadata database backend not checked ({}; this check runs no command and reads no secrets "
        "backend)"
    )
    # In Airflow's order: each source takes precedence over every source after it.
    _ENV_ORDER = {
        "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN": "postgresql://airflow@db/airflow",
        "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD": f"echo sqlite:////{_SECRET}.db",
        "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_SECRET": "airflow/db",
        "AIRFLOW__CORE__SQL_ALCHEMY_CONN": "sqlite:////x.db",
        "AIRFLOW__CORE__SQL_ALCHEMY_CONN_CMD": f"echo postgresql://airflow:{_SECRET}@db/airflow",
        "AIRFLOW__CORE__SQL_ALCHEMY_CONN_SECRET": "airflow/db",
    }

    def test_the_airflow_service_answer_wins_over_a_cfg_under_airflow_home(self, run_check, tmp_path):
        """A Compose host that also keeps an airflow.cfg under ``AIRFLOW_HOME`` (a local install's, with
        Airflow's SQLite default): on the DAG path the value the airflow service uses is judged, either way."""
        self._cfg(tmp_path / "afhome")
        lines = run_check(
            HEALTHY,
            docker_conn=f"postgresql+psycopg2://airflow:{_SECRET}@airflow_postgres/airflow",
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")},
        )
        assert lines[-1] == (
            "PASS|Airflow metadata database is postgresql (airflow config get-value database sql_alchemy_conn)"
        )
        self._cfg(tmp_path / "afhome", conn="postgresql://airflow@db/airflow")
        lines = run_check(
            HEALTHY,
            docker_conn="sqlite:////opt/airflow/airflow.db",
            extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")},
        )
        assert lines[-1].startswith(
            "WARN|Airflow metadata database is SQLite (airflow config get-value database sql_alchemy_conn):"
        )

    @pytest.mark.parametrize(
        ("first", "expected"),
        [
            pytest.param(
                "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN",
                "PASS|Airflow metadata database is postgresql (AIRFLOW__DATABASE__SQL_ALCHEMY_CONN)",
                id="DATABASE",
            ),
            pytest.param(
                "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD",
                _NOT_CHECKED.format("AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_CMD is set"),
                id="DATABASE_CMD",
            ),
            pytest.param(
                "AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_SECRET",
                _NOT_CHECKED.format("AIRFLOW__DATABASE__SQL_ALCHEMY_CONN_SECRET is set"),
                id="DATABASE_SECRET",
            ),
            pytest.param(
                "AIRFLOW__CORE__SQL_ALCHEMY_CONN",
                "WARN|Airflow metadata database is SQLite (AIRFLOW__CORE__SQL_ALCHEMY_CONN):",
                id="CORE",
            ),
            pytest.param(
                "AIRFLOW__CORE__SQL_ALCHEMY_CONN_CMD",
                _NOT_CHECKED.format("AIRFLOW__CORE__SQL_ALCHEMY_CONN_CMD is set"),
                id="CORE_CMD",
            ),
            pytest.param(
                "AIRFLOW__CORE__SQL_ALCHEMY_CONN_SECRET",
                _NOT_CHECKED.format("AIRFLOW__CORE__SQL_ALCHEMY_CONN_SECRET is set"),
                id="CORE_SECRET",
            ),
        ],
    )
    def test_the_environment_is_read_in_airflows_order(self, run_check, tmp_path, first, expected):
        """``first`` and every variable after it in Airflow's order are set, the ones before it are not, and an
        airflow.cfg with PostgreSQL sits behind them all: the check judges ``first``."""
        names = list(self._ENV_ORDER)
        variables = {name: self._ENV_ORDER[name] for name in names[names.index(first) :]}
        self._cfg(tmp_path / "afhome", conn="postgresql://airflow@db/airflow")
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome"), **variables})
        assert lines[-1].startswith(expected)

    @pytest.mark.parametrize(
        ("database", "core", "expected"),
        [
            pytest.param(
                "sql_alchemy_conn = sqlite:////x.db\n",
                "sql_alchemy_conn = postgresql://airflow@db/airflow\n",
                "WARN|Airflow metadata database is SQLite ([database] sql_alchemy_conn in {cfg}):",
                id="database-before-core",
            ),
            pytest.param(
                f"sql_alchemy_conn = postgresql://airflow:{_SECRET}@db/airflow\n"
                "sql_alchemy_conn_cmd = echo sqlite:////x.db\nsql_alchemy_conn_secret = airflow/db\n",
                "",
                "PASS|Airflow metadata database is postgresql ([database] sql_alchemy_conn in {cfg})",
                id="value-before-its-cmd-and-secret",
            ),
            pytest.param(
                "sql_alchemy_conn_cmd = echo sqlite:////x.db\n",
                "sql_alchemy_conn = postgresql://airflow@db/airflow\n",
                "PASS|Airflow metadata database is postgresql ([core] sql_alchemy_conn in {cfg})",
                id="core-value-before-database-cmd",
            ),
            pytest.param(
                "sql_alchemy_conn_cmd = echo postgresql://airflow@db/airflow\n",
                "sql_alchemy_conn_cmd = echo sqlite:////x.db\n",
                _NOT_CHECKED.format("[database] sql_alchemy_conn_cmd in {cfg}"),
                id="database-cmd-before-core-cmd",
            ),
            pytest.param(
                "sql_alchemy_conn_secret = airflow/db\n",
                "sql_alchemy_conn_cmd = echo sqlite:////x.db\n",
                _NOT_CHECKED.format("[core] sql_alchemy_conn_cmd in {cfg}"),
                id="core-cmd-before-database-secret",
            ),
        ],
    )
    def test_airflow_cfg_is_read_in_airflows_order(self, run_check, tmp_path, database, core, expected):
        """``database`` in place of the ``[database] sql_alchemy_conn`` line of Airflow 3.3.2's own cfg, and
        ``core`` at the start of its ``[core]`` section."""
        cfg = self._cfg(tmp_path / "afhome", line=database)
        cfg.write_text(cfg.read_text().replace("[core]\n", "[core]\n" + core, 1))
        lines = run_check(HEALTHY, compose=False, extra_env={"AIRFLOW_HOME": str(tmp_path / "afhome")})
        assert lines[-1].startswith(expected.format(cfg=cfg))

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


# ---------------------------------------------------------------------------
# scripts/runtime_smoke_checklist.sh optional probe
# ---------------------------------------------------------------------------


class TestRuntimeSmokeProbe:
    @pytest.fixture
    def run_probe(self, tmp_path):
        """Run the script with a stub ``docker`` (a running ``edgeguard_airflow`` whose ``curl`` answers a
        payload) and ``python3`` = this interpreter."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "docker").write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  info) exit 0 ;;\n"
            "  ps) echo edgeguard_airflow ;;\n"
            '  exec) echo "$*" >> "$STUB_DIR/exec_args"; [ -n "$STUB_BODY" ] || exit 22; cat "$STUB_BODY" ;;\n'
            "  *) exit 1 ;;\n"
            "esac\n"
        )
        (bin_dir / "python3").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        for stub in bin_dir.iterdir():
            stub.chmod(0o755)

        def _run(payload):
            env = {
                "PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin",
                "STUB_DIR": str(tmp_path),
                "STUB_BODY": "",
            }
            if payload is not None:
                body = tmp_path / "body.json"
                body.write_text(json.dumps(payload))
                env["STUB_BODY"] = str(body)
            done = subprocess.run(
                ["bash", str(_ROOT / "scripts" / "runtime_smoke_checklist.sh")],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert done.returncode == 0, done.stderr
            return done.stdout.splitlines()

        return _run

    def test_a_healthy_scheduler_is_ok(self, run_probe, tmp_path):
        lines = run_probe(HEALTHY)
        assert " Airflow OK (scheduler healthy)" in lines
        assert not any("NOT healthy" in line for line in lines)
        assert (tmp_path / "exec_args").read_text().split() == [
            "exec",
            "edgeguard_airflow",
            "curl",
            "-sf",
            "http://localhost:8082/api/v2/monitor/health",
        ]

    def test_a_dead_scheduler_is_not_ok_although_the_endpoint_answers(self, run_probe):
        lines = run_probe(UNHEALTHY)
        assert any(line.startswith(" Airflow scheduler NOT healthy: restart Airflow") for line in lines)
        assert " Airflow OK (scheduler healthy)" not in lines

    def test_a_failed_request_is_reported(self, run_probe):
        lines = run_probe(None)
        assert " Airflow health check failed" in lines
        assert not any("Airflow OK" in line for line in lines)
