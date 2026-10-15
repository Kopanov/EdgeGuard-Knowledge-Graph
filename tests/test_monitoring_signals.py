"""Monitoring signals that reported the wrong state (2026-10, confirmed on main 6590719).

* Node gauges: ``edgeguard_neo4j_nodes`` was set to 0 after every sync (the sync task read
  attributes ``MISPToNeo4jSync`` does not have); the counts are now read from the graph.
* DAG run state: the start gauge was refreshed on every task success and never cleared, so
  ``EdgeGuardDAGRunStuck`` fired after every run. It now marks the run in progress only.
* Alert thresholds that fired on a normal schedule: the per-DAG last-success limit, the 304 and
  skipped collector runs, the MISP to Neo4j sync staleness at month ends.
* Collection counter: every collector run added its count twice to
  ``edgeguard_indicators_collected_total`` (and its duration twice to the MISP push histogram).

The DAG callables run for real; only Neo4j, MISP and the Airflow Variable store are replaced.
The multi-process tests record in child processes against a temporary metrics directory, the way
the Airflow task processes and the ``metrics`` service of the compose deployment do.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml
from croniter import croniter
from prometheus_client import REGISTRY, generate_latest
from prometheus_client.parser import text_string_to_metric_families

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_DAGS = _ROOT / "dags"
sys.path.insert(0, str(_SRC))

import metrics_exporter  # noqa: E402
import metrics_server  # noqa: E402
import neo4j_client  # noqa: E402
from collectors.collector_utils import make_status  # noqa: E402

_RULES = yaml.safe_load((_ROOT / "prometheus" / "alerts.yml").read_text())
_DAG_IDS = {
    "edgeguard_pipeline",
    "edgeguard_medium_freq",
    "edgeguard_low_freq",
    "edgeguard_daily",
    "edgeguard_neo4j_sync",
    "edgeguard_baseline",
}


def _rule(name: str, key: str = "alert") -> dict:
    found = [r for g in _RULES["groups"] for r in g["rules"] if r.get(key) == name]
    assert len(found) == 1, (name, len(found))
    return found[0]


def _norm(expr: str) -> str:
    return " ".join(expr.split())


def _label_map(record: str, label: str) -> dict:
    expr = _rule(record, key="record")["expr"]
    pairs = re.findall(r'label_replace\(vector\((\d+)\), "%s", "([a-z0-9_]+)", "", ""\)' % label, expr)
    assert len(pairs) == expr.count("label_replace("), "every branch of the map must parse"
    return {value: int(seconds) for seconds, value in pairs}


def _sample(name: str, labels: dict | None = None):
    return REGISTRY.get_sample_value(name, labels or {})


class _StubVariable:
    """Airflow Variable stand-in: get() returns the caller's default."""

    @staticmethod
    def get(key, default=None):
        return default

    @staticmethod
    def set(key, value):
        return None


@pytest.fixture(scope="module")
def dag_module():
    """The DAG file loaded as an isolated module (Airflow is a declared dependency)."""
    spec = importlib.util.spec_from_file_location("_dag_module_monitoring_signals", _DAGS / "edgeguard_pipeline.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def dags(dag_module):
    from airflow import DAG

    found = {d.dag_id: d for d in vars(dag_module).values() if isinstance(d, DAG)}
    assert set(found) == _DAG_IDS
    return found


@pytest.fixture()
def compose_metrics(dag_module, monkeypatch, tmp_path):
    """The compose configuration in this process: metrics enabled, metrics_server's collectors bound
    in the DAG module (as its import does when the multi-process directory is set), no in-task HTTP
    server, no baseline lock."""
    monkeypatch.setattr(dag_module, "ENABLE_PROMETHEUS_METRICS", True)
    monkeypatch.setattr(dag_module, "PROMETHEUS_AVAILABLE", True)
    for name in (
        "DAG_RUN_START",
        "DAG_LAST_SUCCESS",
        "NEO4J_NODES",
        "INDICATORS_COLLECTED",
        "MISP_PUSH_DURATION",
        "NEO4J_SYNC_DURATION",
    ):
        monkeypatch.setattr(dag_module, name, getattr(metrics_server, name), raising=False)
    monkeypatch.setattr(dag_module, "ensure_metrics_server", lambda: None)
    monkeypatch.setattr(dag_module, "Variable", _StubVariable)
    monkeypatch.setenv("EDGEGUARD_BASELINE_LOCK_PATH", str(tmp_path / "no_such.lock"))
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("EDGEGUARD_COLLECT_SOURCES", raising=False)
    assert dag_module.METRICS_SERVER_AVAILABLE
    return metrics_server


# ---------------------------------------------------------------------------
# Node gauges
# ---------------------------------------------------------------------------


class _FakeSession:
    def __init__(self, rows, queries):
        self._rows, self._queries = rows, queries

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, parameters=None, **kwargs):
        self._queries.append((query, kwargs))
        return iter(self._rows)


class _FakeDriver:
    def __init__(self, rows):
        self.rows, self.sessions, self.queries = rows, [], []

    def session(self, **kwargs):
        self.sessions.append(kwargs)
        return _FakeSession(self.rows, self.queries)


def _client_with_rows(rows):
    """A client whose driver is the production timeout proxy around a recording fake driver."""
    client = neo4j_client.Neo4jClient(uri="bolt://unused:7687", user="neo4j", password="x")
    fake = _FakeDriver(rows)
    client.driver = neo4j_client._TimeoutDriver(fake)
    return client, fake


class TestNodeCountQuery:
    def test_one_read_only_query_counts_every_label_edgeguard_writes(self):
        labels = neo4j_client.NODE_COUNT_LABELS
        client, fake = _client_with_rows([{"label": label, "count": 10 * i} for i, label in enumerate(labels)])

        counts = client.count_nodes_by_label()

        assert counts == {label: 10 * i for i, label in enumerate(labels)}
        assert fake.sessions == [{"default_access_mode": neo4j_client.READ_ACCESS}]
        assert len(fake.queries) == 1, "one query for all labels"
        statement, _ = fake.queries[0]
        assert statement.timeout and statement.timeout > 0, "a server-side transaction timeout"
        query = statement.text
        branches = [b.strip() for b in query.split("UNION ALL")]
        assert branches == [f"MATCH (n:{label}) RETURN '{label}' AS label, count(n) AS count" for label in labels]
        assert not re.search(r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH)\b", query)
        assert set(labels) == set(neo4j_client._STATS_NODE_LABELS) | {"Source"}
        assert {"Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique", "Source"} <= set(labels)

    def test_missing_rows_and_no_connection_raise_instead_of_reporting_zero(self):
        labels = neo4j_client.NODE_COUNT_LABELS
        client, _ = _client_with_rows([{"label": label, "count": 5} for label in labels[1:]])
        with pytest.raises(RuntimeError, match="expected"):
            client.count_nodes_by_label()
        client.driver = None
        with pytest.raises(RuntimeError, match="not connected"):
            client.count_nodes_by_label()


def _install_client(monkeypatch, client_class) -> None:
    """Serve ``client_class`` to the DAG helper's ``from neo4j_client import Neo4jClient``.

    Patched through ``sys.modules``: other test modules re-import ``neo4j_client``, so the module
    object imported at the top of this file is not necessarily the one the import resolves to.
    """
    monkeypatch.setitem(sys.modules, "neo4j_client", SimpleNamespace(Neo4jClient=client_class))


def _fake_client_class(*, counts=None, connect=True, error=None):
    class _Client:
        closed = []

        def __init__(self, *args, **kwargs):
            pass

        def connect(self):
            return connect

        def count_nodes_by_label(self):
            if error is not None:
                raise error
            return dict(counts or {})

        def close(self):
            type(self).closed.append(True)

    return _Client


class TestNodeGauges:
    def test_counts_are_recorded_per_label_with_the_zone_the_alerts_read(
        self, dag_module, compose_metrics, monkeypatch
    ):
        counts = {"Indicator": 345678, "Vulnerability": 120034, "Source": 14}
        client_class = _fake_client_class(counts=counts)
        _install_client(monkeypatch, client_class)

        assert dag_module.record_neo4j_node_counts() is True

        for label, count in counts.items():
            assert _sample("edgeguard_neo4j_nodes", {"label": label, "zone": "all"}) == count
        assert client_class.closed == [True]

    @pytest.mark.parametrize(
        "client_kwargs",
        [{"error": RuntimeError("count query timed out")}, {"connect": False}],
        ids=["query-fails", "connect-fails"],
    )
    def test_a_failed_count_keeps_the_previous_values(
        self, dag_module, compose_metrics, monkeypatch, caplog, client_kwargs
    ):
        metrics_server.NEO4J_NODES.labels(label="Malware", zone="all").set(4321)
        _install_client(monkeypatch, _fake_client_class(**client_kwargs))

        with caplog.at_level(logging.WARNING):
            assert dag_module.record_neo4j_node_counts() is False

        assert _sample("edgeguard_neo4j_nodes", {"label": "Malware", "zone": "all"}) == 4321
        assert any("node counts not recorded" in r.getMessage() for r in caplog.records)

    def _fake_sync(self, monkeypatch, success=True):
        class _Sync:
            _last_sync_failure_reason = None

            def run(self, incremental=True, since=None):
                return success

        monkeypatch.setitem(sys.modules, "run_misp_to_neo4j", SimpleNamespace(MISPToNeo4jSync=_Sync))

    def test_scheduled_sync_observes_once_and_reads_the_counts(self, dag_module, compose_metrics, monkeypatch):
        """Before: the duration was observed twice, and every label was set to 0 under zone=unknown."""
        self._fake_sync(monkeypatch)
        node_reads = []
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: node_reads.append(1) or True)
        metrics_server.NEO4J_NODES.labels(label="Indicator", zone="unknown").set(55)
        observed = _sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0
        started = time.time()

        dag_module.run_neo4j_sync()

        assert _sample("edgeguard_neo4j_sync_duration_seconds_count") == observed + 1
        assert _sample("edgeguard_neo4j_sync_last_success_timestamp") >= started
        assert node_reads == [1]
        assert _sample("edgeguard_neo4j_nodes", {"label": "Indicator", "zone": "unknown"}) == 55, "no 0 written"

    def test_baseline_full_sync_counts_as_a_sync(self, dag_module, compose_metrics, monkeypatch):
        self._fake_sync(monkeypatch)
        monkeypatch.setattr(dag_module, "_require_baseline_start", lambda *args, **kwargs: None)
        node_reads = []
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: node_reads.append(1) or True)
        observed = _sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0
        started = time.time()

        assert dag_module.run_baseline_full_sync() == {"synced": True}

        assert _sample("edgeguard_neo4j_sync_last_success_timestamp") >= started
        assert _sample("edgeguard_neo4j_sync_duration_seconds_count") == observed + 1
        assert node_reads == [1]

    def test_failed_sync_records_nothing(self, dag_module, compose_metrics, monkeypatch):
        self._fake_sync(monkeypatch, success=False)
        node_reads = []
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: node_reads.append(1) or True)
        observed = _sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0

        with pytest.raises(Exception, match="Neo4j sync failed"):
            dag_module.run_neo4j_sync()

        assert node_reads == []
        assert (_sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0) == observed


# ---------------------------------------------------------------------------
# DAG run in progress
# ---------------------------------------------------------------------------


def _in_progress(dag_id: str):
    return _sample("edgeguard_dag_run_in_progress_start_timestamp", {"dag_id": dag_id})


def _callbacks(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


class TestDagRunInProgress:
    def test_a_task_marks_the_run_start_and_the_run_end_clears_it(self, dag_module, compose_metrics):
        start = datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc)
        dag = SimpleNamespace(dag_id="edgeguard_daily")

        dag_module._on_task_execute({"dag": dag, "dag_run": SimpleNamespace(start_date=start)})
        assert _in_progress("edgeguard_daily") == start.timestamp()

        dag_module._on_task_success({"dag": dag})
        assert _in_progress("edgeguard_daily") == start.timestamp(), "a task success no longer moves the mark"
        assert _sample("edgeguard_dag_last_success_timestamp", {"dag_id": "edgeguard_daily"}) > start.timestamp()

        dag_module._on_dag_run_end({"dag": dag, "run_id": "scheduled__2026-10-15T02:00:00+00:00", "reason": "success"})
        assert _in_progress("edgeguard_daily") == 0

    def test_every_dag_marks_its_runs_and_clears_the_mark_when_a_run_ends(self, dag_module, dags):
        for dag in dags.values():
            assert _callbacks(dag.on_success_callback) == [dag_module._on_dag_run_end], dag.dag_id
            assert _callbacks(dag.on_failure_callback) == [dag_module._on_dag_run_end], dag.dag_id
            assert dag.tasks, dag.dag_id
            for task in dag.tasks:
                assert dag_module._on_task_execute in _callbacks(task.on_execute_callback), task.task_id
                assert dag_module._on_task_success in _callbacks(task.on_success_callback), task.task_id

    def test_the_former_series_is_no_longer_read_or_written(self, dag_module):
        alerts = (_ROOT / "prometheus" / "alerts.yml").read_text()
        assert "edgeguard_dag_run_start_timestamp" not in alerts
        assert metrics_server.DAG_RUN_START._name == "edgeguard_dag_run_in_progress_start_timestamp"
        src = (_DAGS / "edgeguard_pipeline.py").read_text()
        assert '"edgeguard_dag_run_start_timestamp"' not in src


# ---------------------------------------------------------------------------
# Alert thresholds
# ---------------------------------------------------------------------------


def _cron_fires(expression: str, start: datetime, end: datetime) -> list:
    iterator = croniter(expression, start)
    fires = []
    while True:
        fire = iterator.get_next(datetime)
        if fire > end:
            return fires
        fires.append(fire)


def _longest_interval(expression: str) -> float:
    fires = _cron_fires(
        expression, datetime(2027, 1, 1, tzinfo=timezone.utc), datetime(2029, 1, 1, tzinfo=timezone.utc)
    )
    return max((b - a).total_seconds() for a, b in pairwise(fires))


class TestDagAlerts:
    def test_run_stuck_fires_only_for_a_run_in_progress_past_its_timeout(self, dags):
        expr = _norm(_rule("EdgeGuardDAGRunStuck")["expr"])
        assert expr == (
            "(time() - (edgeguard_dag_run_in_progress_start_timestamp > 0)) "
            "> on (dag_id) group_left () edgeguard:dag_run_max_seconds"
        )
        limits = _label_map("edgeguard:dag_run_max_seconds", "dag_id")
        assert limits == {dag_id: int(dag.dagrun_timeout.total_seconds()) + 900 for dag_id, dag in dags.items()}

    def test_last_success_limit_follows_each_dags_schedule(self, dags):
        expr = _norm(_rule("EdgeGuardDAGLastSuccessStale")["expr"])
        assert expr == (
            "(time() - (edgeguard_dag_last_success_timestamp > 0)) "
            "> on (dag_id) group_left () edgeguard:dag_max_success_gap_seconds"
        )
        gaps = _label_map("edgeguard:dag_max_success_gap_seconds", "dag_id")
        scheduled = {dag_id: dag for dag_id, dag in dags.items() if dag.schedule is not None}
        watched_elsewhere = {
            "edgeguard_daily": "EdgeGuardDailyDAGStale",
            "edgeguard_neo4j_sync": "EdgeGuardNeo4jSyncStale",
        }
        assert set(gaps) | set(watched_elsewhere) == set(scheduled), "every scheduled DAG is watched once"
        assert not set(gaps) & set(watched_elsewhere)
        assert "edgeguard_baseline" not in scheduled, "manual"
        for dag_id, gap in gaps.items():
            dag = scheduled[dag_id]
            interval = _longest_interval(dag.schedule)
            # One interval to the next run's first task, plus the longest a run (any task) can last.
            assert gap == interval + dag.dagrun_timeout.total_seconds(), dag_id
        # The single 6 h limit was shorter than edgeguard_low_freq's own interval: it fired every cycle.
        assert _longest_interval(scheduled["edgeguard_low_freq"].schedule) > 21600
        daily = _norm(_rule("EdgeGuardDailyDAGStale")["expr"])
        assert "> 90000" in daily and _longest_interval(scheduled["edgeguard_daily"].schedule) < 90000


def _write_state(state_dir: Path, last_sync: datetime) -> None:
    state_dir.mkdir(mode=0o700, exist_ok=True)
    (state_dir / "edgeguard_last_neo4j_sync.json").write_text(json.dumps({"last_sync": last_sync.isoformat()}))


def _sync_starts(dag_module, state_dir: Path, fires: list, last_start: datetime) -> list:
    """Sync start times the real should_run_neo4j_sync admits for the given cron fires.

    The state file is written relative to the wall clock (``now - elapsed``), so the guard's own
    ``datetime.now`` sees the simulated elapsed time. A sync stamps its start one minute after the fire.
    """
    starts = []
    for fire in fires:
        _write_state(state_dir, datetime.now(timezone.utc) - (fire - last_start))
        if dag_module.should_run_neo4j_sync():
            last_start = fire + timedelta(minutes=1)
            starts.append(last_start)
    return starts


class TestSyncStaleness:
    def test_threshold_covers_the_longest_gap_of_the_three_day_schedule(
        self, dag_module, dags, compose_metrics, tmp_path
    ):
        sync_dag = dags["edgeguard_neo4j_sync"]
        assert sync_dag.schedule == "0 3 */3 * *"
        state_dir = tmp_path / "state"
        fires = _cron_fires(
            sync_dag.schedule, datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2033, 1, 1, tzinfo=timezone.utc)
        )
        starts = _sync_starts(dag_module, state_dir, fires[1:], fires[0] + timedelta(minutes=1))
        gaps = [(b - a).total_seconds() / 3600 for a, b in pairwise(starts)]
        assert round(max(gaps)) == 120, "28 February to 4 March in a leap year"
        non_leap = [
            (b - a).total_seconds() / 3600 for a, b in pairwise(starts) if a.year not in (2028, 2032) or a.month != 2
        ]
        assert round(max(non_leap)) == 96, "the fire after the 31st is skipped by the 71 h guard"
        month_end_gaps_2027 = [g for a, g in zip(starts[:-1], gaps, strict=True) if a.year == 2027 and g > 73]
        assert len(month_end_gaps_2027) >= 8, "the former 72 h limit fired at most month ends"

        # A baseline's full sync restarts the guard: the next scheduled sync may be one fire later.
        after_baseline = []
        for hour in range(0, 24 * 31 * 2, 1):
            baseline_start = datetime(2027, 1, 1, tzinfo=timezone.utc) + timedelta(hours=hour, minutes=7)
            upcoming = [f for f in fires if f > baseline_start][:4]
            first = _sync_starts(dag_module, state_dir, upcoming, baseline_start)[0]
            after_baseline.append((first - baseline_start).total_seconds() / 3600)
        assert 142 < max(after_baseline) < 144

        expr = _norm(_rule("EdgeGuardNeo4jSyncStale")["expr"])
        assert expr == (
            "time() - edgeguard_neo4j_sync_last_success_timestamp > 518400 "
            "and edgeguard_neo4j_sync_last_success_timestamp > 0"
        )
        threshold_h = 518400 / 3600
        timeout_h = sync_dag.dagrun_timeout.total_seconds() / 3600
        # The stamp is written when a sync ends, so the next sync may take up to its timeout longer.
        assert max(gaps) + timeout_h <= threshold_h
        assert max(after_baseline) <= threshold_h
        assert _rule("EdgeGuardNeo4jSyncStale")["for"] == "1h"


class TestCollectorOutcomes:
    def test_outcome_gauge_keeps_exactly_one_outcome_per_source(self):
        metrics_server.record_collector_outcome("outcome_unit_probe", "collected")
        metrics_server.record_collector_outcome("outcome_unit_probe", "not_modified")
        values = {
            o: _sample("edgeguard_collector_last_run_outcome", {"source": "outcome_unit_probe", "outcome": o})
            for o in metrics_server.COLLECTOR_RUN_OUTCOMES
        }
        assert values == {o: (1.0 if o == "not_modified" else 0.0) for o in metrics_server.COLLECTOR_RUN_OUTCOMES}
        with pytest.raises(ValueError):
            metrics_server.record_collector_outcome("outcome_unit_probe", "unchanged")

    def test_make_status_flags_not_modified_only_when_asked(self):
        assert make_status("mitre", True, count=0, not_modified=True)["not_modified"] is True
        assert "not_modified" not in make_status("mitre", True, count=0)

    @pytest.mark.parametrize(
        "result, outcome, status",
        [
            ({"success": True, "count": 7}, "collected", "success"),
            ({"success": True, "count": 0}, "empty", "success"),
            ({"success": True, "count": 0, "not_modified": True}, "not_modified", "not_modified"),
            (
                {"success": True, "count": 0, "skipped": True, "skip_reason_class": "missing_probe_key"},
                "skipped",
                "skipped",
            ),
        ],
    )
    def test_a_run_records_its_outcome_and_adds_its_count_once(
        self, dag_module, compose_metrics, result, outcome, status
    ):
        source = f"probe_{outcome}"

        class _Collector:
            def __init__(self, misp_writer=None, **kwargs):
                pass

            def collect(self, limit=None, push_to_misp=True):
                return {"source": source, "failed": 0, **result}

        labels = {"source": source, "zone": "global", "status": status}
        before = _sample("edgeguard_indicators_collected_total", labels) or 0.0
        pushes = _sample("edgeguard_misp_push_duration_seconds_count", {"source": source}) or 0.0

        dag_module.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)

        for candidate in metrics_server.COLLECTOR_RUN_OUTCOMES:
            assert _sample("edgeguard_collector_last_run_outcome", {"source": source, "outcome": candidate}) == (
                1.0 if candidate == outcome else 0.0
            ), candidate
        assert _sample("edgeguard_indicators_collected_total", labels) == before + result["count"]
        assert _sample("edgeguard_misp_push_duration_seconds_count", {"source": source}) == pushes + 1

    def test_failed_and_disabled_runs_record_their_outcome(self, dag_module, compose_metrics, monkeypatch):
        class _Failing:
            def __init__(self, misp_writer=None, **kwargs):
                pass

            def collect(self, limit=None, push_to_misp=True):
                return {"source": "probe_failed", "success": False, "count": 0, "failed": 3}

        with pytest.raises(Exception, match="success=false"):
            dag_module.run_collector_with_metrics("probe_failed", _Failing, MagicMock(), limit=10)
        assert _sample("edgeguard_collector_last_run_outcome", {"source": "probe_failed", "outcome": "failed"}) == 1

        monkeypatch.setattr(dag_module, "is_collector_enabled_by_allowlist", lambda name: False)
        dag_module.run_collector_with_metrics("probe_disabled", _Failing, MagicMock(), limit=10)
        assert _sample("edgeguard_collector_last_run_outcome", {"source": "probe_disabled", "outcome": "skipped"}) == 1

    def test_no_indicators_alert_leaves_out_not_modified_and_skipped_sources(self):
        expr = _norm(_rule("EdgeGuardNoIndicatorsCollected")["expr"])
        assert expr == (
            "sum by (source) (increase(edgeguard_indicators_collected_total[26h])) == 0 "
            "and on (source) max by (source) (edgeguard_source_health) == 1 "
            "unless on (source) "
            'max by (source) (edgeguard_collector_last_run_outcome{outcome=~"not_modified|skipped"}) == 1'
        )
        assert {"not_modified", "skipped", "empty"} <= set(metrics_server.COLLECTOR_RUN_OUTCOMES)


# ---------------------------------------------------------------------------
# Multi-process: the compose deployment (task processes, DAG processor, metrics service)
# ---------------------------------------------------------------------------

_CHILD = r"""
import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

sys.path[:0] = [sys.argv[1], sys.argv[2]]
import edgeguard_pipeline as ep

step = sys.argv[3]
dag = SimpleNamespace(dag_id="edgeguard_daily")
if step == "collect":
    class Probe:
        def __init__(self, misp_writer=None, **kwargs):
            pass

        def collect(self, limit=None, push_to_misp=True):
            return {"source": "o8_probe", "success": True, "count": 7, "failed": 0}

    ep.run_collector_with_metrics("o8_probe", Probe, MagicMock(), limit=10)
elif step == "start":
    started = datetime.fromtimestamp(float(sys.argv[4]), timezone.utc)
    ep._on_task_execute({"dag": dag, "dag_run": SimpleNamespace(start_date=started)})
elif step == "end":
    ep._on_dag_run_end({"dag": dag, "run_id": "scheduled__probe", "reason": "success"})
flags = {
    "enabled": ep.ENABLE_PROMETHEUS_METRICS,
    "prometheus": ep.PROMETHEUS_AVAILABLE,
    "metrics_server": ep.METRICS_SERVER_AVAILABLE,
    "multiprocess": bool(ep.MULTIPROC_METRICS_DIR),
}
print("FLAGS=" + json.dumps(flags))
"""


def _run_child(tmp_path: Path, metrics_dir: Path, *args: str) -> None:
    env = dict(
        os.environ,
        PROMETHEUS_MULTIPROC_DIR=str(metrics_dir),
        NEO4J_PASSWORD="x",
        MISP_API_KEY="x",
        EDGEGUARD_ENV="dev",
        EDGEGUARD_BASELINE_LOCK_PATH=str(tmp_path / "no_such.lock"),
    )
    env.pop("EDGEGUARD_COLLECT_SOURCES", None)
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(_DAGS), str(_SRC), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    flags = [line for line in proc.stdout.splitlines() if line.startswith("FLAGS=")]
    assert flags and json.loads(flags[-1][len("FLAGS=") :]) == {
        "enabled": True,
        "prometheus": True,
        "metrics_server": True,
        "multiprocess": True,
    }, "the child must run in the compose metrics mode"


def _aggregate(metrics_dir: Path) -> dict:
    text = generate_latest(metrics_exporter.build_registry(str(metrics_dir))).decode()
    values = {}
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            values[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return values


def _value(values: dict, name: str, **labels) -> float | None:
    return values.get((name, tuple(sorted(labels.items()))))


class TestMultiProcess:
    def test_one_run_adds_its_count_once_and_the_run_mark_follows_the_newest_write(self, tmp_path):
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        _run_child(tmp_path, metrics_dir, "collect")
        values = _aggregate(metrics_dir)
        collected = _value(
            values, "edgeguard_indicators_collected_total", source="o8_probe", zone="global", status="success"
        )
        assert collected == 7.0, "one run of 7 indicators adds 7 (it added 14 when both helpers counted)"
        assert _value(values, "edgeguard_misp_push_duration_seconds_count", source="o8_probe") == 1.0
        assert _value(values, "edgeguard_collector_last_run_outcome", source="o8_probe", outcome="collected") == 1.0

        first_start = datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc).timestamp()
        _run_child(tmp_path, metrics_dir, "start", str(first_start))
        mark = "edgeguard_dag_run_in_progress_start_timestamp"
        assert _value(_aggregate(metrics_dir), mark, dag_id="edgeguard_daily") == first_start

        _run_child(tmp_path, metrics_dir, "end")  # the DAG processor, another process
        assert _value(_aggregate(metrics_dir), mark, dag_id="edgeguard_daily") == 0.0

        next_start = first_start + 86400
        _run_child(tmp_path, metrics_dir, "start", str(next_start))
        assert _value(_aggregate(metrics_dir), mark, dag_id="edgeguard_daily") == next_start
