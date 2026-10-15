"""Monitoring signals that reported the wrong state (2026-10, confirmed on main 6590719).

* Node gauges: ``edgeguard_neo4j_nodes`` was set to 0 after every sync (the sync task read
  attributes ``MISPToNeo4jSync`` does not have); the counts are now read from the graph.
* DAG run state: the start gauge was refreshed on every task success and never cleared, so
  ``EdgeGuardDAGRunStuck`` fired after every run. It now marks the run in progress only, from the
  Airflow listener plugin ``plugins/edgeguard_dag_run_state.py`` (scheduler and API server hooks).
* Alert thresholds that fired on a normal schedule: the per-DAG last-success limit, the 304 and
  skipped collector runs, the MISP to Neo4j sync staleness at month ends.
* Collection counter: every collector run added its count twice to
  ``edgeguard_indicators_collected_total`` (and its duration twice to the MISP push histogram).

The DAG callables run for real; only Neo4j, MISP and the Airflow Variable store are replaced.
The multi-process tests record in child processes against a temporary metrics directory, the way
the Airflow task processes, the scheduler, the API server and the ``metrics`` service of the
compose deployment do; the listener tests load the plugin through Airflow's own plugin manager.
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
from collectors.collector_utils import make_skipped_optional_source, make_status  # noqa: E402

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
        return iter(self._rows(query) if callable(self._rows) else self._rows)


class _FakeDriver:
    def __init__(self, rows):
        self.rows, self.sessions, self.queries = rows, [], []

    def session(self, **kwargs):
        self.sessions.append(kwargs)
        return _FakeSession(self.rows, self.queries)

    def close(self):
        self.closed = True


def _client_with_rows(rows):
    """A client whose driver is the production timeout proxy around a recording fake driver."""
    client = neo4j_client.Neo4jClient(uri="bolt://unused:7687", user="neo4j", password="x")
    fake = _FakeDriver(rows)
    client.driver = neo4j_client._TimeoutDriver(fake)
    return client, fake


_COUNT_THEN_NAME = re.compile(r"^MATCH \(n:(\w+)\) WITH count\(n\) AS c RETURN '(\w+)' AS label, c AS count$")
_NAME_IN_AGGREGATION = re.compile(r"^MATCH \(n:(\w+)\) RETURN '(\w+)' AS label, count\(n\) AS count$")


def _cypher_count_rows(store: dict):
    """Rows Cypher returns for a ``UNION ALL`` of per-label count branches, from ``store`` (label -> nodes).

    An aggregation without a grouping key yields one row even on empty input; one whose RETURN also
    projects a literal (``RETURN 'Alert' AS label, count(n)``) groups by it and yields no row when
    no node matches. Any other branch shape fails the test.
    """

    def rows(statement) -> list:
        out = []
        for branch in (b.strip() for b in statement.text.split("UNION ALL")):
            if m := _COUNT_THEN_NAME.match(branch):
                out.append({"label": m.group(2), "count": store.get(m.group(1), 0)})
            elif m := _NAME_IN_AGGREGATION.match(branch):
                if store.get(m.group(1), 0):
                    out.append({"label": m.group(2), "count": store[m.group(1)]})
            else:
                raise AssertionError(f"unexpected count branch: {branch!r}")
        return out

    return rows


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
        assert branches == [
            f"MATCH (n:{label}) WITH count(n) AS c RETURN '{label}' AS label, c AS count" for label in labels
        ]
        assert not re.search(r"\b(CREATE|MERGE|SET|DELETE|REMOVE|DETACH)\b", query)
        assert {"Indicator", "Vulnerability", "CVE", "Malware", "ThreatActor", "Technique", "Source"} <= set(labels)

    def test_a_label_without_nodes_is_counted_as_zero(self):
        """Alert has no nodes in the compose deployment, Campaign none before the first enrichment.

        With the label as a literal next to count(n) in one RETURN, Cypher returned no row for them,
        the row check raised, and no count was ever recorded.
        """
        store = {label: 100 + i for i, label in enumerate(neo4j_client.NODE_COUNT_LABELS)}
        store.update(Alert=0, Campaign=0)
        client, _ = _client_with_rows(_cypher_count_rows(store))

        assert client.count_nodes_by_label() == store

        # The fake follows Cypher for the former shape too: those labels would have no row.
        former = SimpleNamespace(
            text="\nUNION ALL\n".join(
                f"MATCH (n:{label}) RETURN '{label}' AS label, count(n) AS count" for label in ("Alert", "Indicator")
            )
        )
        assert _cypher_count_rows(store)(former) == [{"label": "Indicator", "count": store["Indicator"]}]

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

    def test_a_label_without_nodes_is_recorded_as_zero(self, dag_module, compose_metrics, monkeypatch):
        """End to end through the real client and query: a label without nodes (Alert in the compose
        deployment) is recorded as 0 instead of failing the whole count."""
        store = {label: 50 + i for i, label in enumerate(neo4j_client.NODE_COUNT_LABELS)}
        store["Alert"] = 0
        metrics_server.NEO4J_NODES.labels(label="Alert", zone="all").set(9)

        class _Client(neo4j_client.Neo4jClient):
            def __init__(self, *args, **kwargs):
                super().__init__(uri="bolt://unused:7687", user="neo4j", password="x")
                self.driver = neo4j_client._TimeoutDriver(_FakeDriver(_cypher_count_rows(store)))

            def connect(self):
                return True

        _install_client(monkeypatch, _Client)

        assert dag_module.record_neo4j_node_counts() is True

        assert _sample("edgeguard_neo4j_nodes", {"label": "Alert", "zone": "all"}) == 0
        assert _sample("edgeguard_neo4j_nodes", {"label": "Indicator", "zone": "all"}) == store["Indicator"]

    def test_baseline_full_sync_counts_as_a_sync_without_node_counts(self, dag_module, compose_metrics, monkeypatch):
        """The full sync stamps the sync; the node counts wait for the enrichment (no Campaign yet)."""
        self._fake_sync(monkeypatch)
        monkeypatch.setattr(dag_module, "_require_baseline_start", lambda *args, **kwargs: None)
        node_reads = []
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: node_reads.append(1) or True)
        observed = _sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0
        started = time.time()

        assert dag_module.run_baseline_full_sync() == {"synced": True}

        assert _sample("edgeguard_neo4j_sync_last_success_timestamp") >= started
        assert _sample("edgeguard_neo4j_sync_duration_seconds_count") == observed + 1
        assert node_reads == []

    def _fake_enrichment(self, monkeypatch, events, error=None):
        def run_all_enrichment_jobs(client):
            events.append("enrichment")
            if error is not None:
                raise error
            return {"campaigns": 3}

        class _Client:
            def connect(self):
                return True

            def close(self):
                events.append("closed")

        monkeypatch.setitem(
            sys.modules, "enrichment_jobs", SimpleNamespace(run_all_enrichment_jobs=run_all_enrichment_jobs)
        )
        _install_client(monkeypatch, _Client)

    @pytest.mark.parametrize("task", ["run_baseline_enrichment", "run_enrichment_jobs"])
    def test_counts_are_taken_after_a_successful_enrichment(self, dag_module, compose_metrics, monkeypatch, task):
        events = []
        self._fake_enrichment(monkeypatch, events)
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: events.append("counts") or True)

        getattr(dag_module, task)()

        assert events == ["enrichment", "closed", "counts"]

    @pytest.mark.parametrize("task", ["run_baseline_enrichment", "run_enrichment_jobs"])
    def test_a_failed_enrichment_records_no_counts(self, dag_module, compose_metrics, monkeypatch, task):
        events = []
        self._fake_enrichment(monkeypatch, events, error=RuntimeError("campaign builder failed"))
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: events.append("counts") or True)

        with pytest.raises(Exception, match="nrichment failed"):
            getattr(dag_module, task)()

        assert "counts" not in events

    def test_failed_sync_records_nothing(self, dag_module, compose_metrics, monkeypatch):
        self._fake_sync(monkeypatch, success=False)
        node_reads = []
        monkeypatch.setattr(dag_module, "record_neo4j_node_counts", lambda: node_reads.append(1) or True)
        observed = _sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0

        with pytest.raises(Exception, match="Neo4j sync failed"):
            dag_module.run_neo4j_sync()

        assert node_reads == []
        assert (_sample("edgeguard_neo4j_sync_duration_seconds_count") or 0.0) == observed


def _dashboard_node_panels() -> dict:
    dashboard = json.loads((_ROOT / "grafana" / "dashboards" / "edgeguard-overview.json").read_text())

    def walk(panels):
        for panel in panels:
            yield panel
            yield from walk(panel.get("panels", []))

    return {
        panel["title"]: [(t["expr"], t.get("legendFormat")) for t in panel.get("targets", [])]
        for panel in walk(dashboard["panels"])
        if any("edgeguard_neo4j_nodes" in t.get("expr", "") for t in panel.get("targets", []))
    }


def test_dashboard_reads_the_per_label_series_the_sync_records():
    """The zone="unknown" series the former code left at 0 stay in the metrics directory: a panel
    without the zone filter drew them as flat zero lines next to the real counts."""
    panels = _dashboard_node_panels()
    assert panels["Neo4j Node Counts by Label"] == [('edgeguard_neo4j_nodes{zone="all"}', "{{label}}")]
    assert panels["Neo4j Node Count Change (24 h) by Label"] == [
        ('edgeguard_neo4j_nodes{zone="all"} - (edgeguard_neo4j_nodes{zone="all"} offset 1d)', "{{label}}")
    ]
    assert panels["Neo4j Total Nodes"] == [("sum(edgeguard_neo4j_nodes)", "Total Nodes")], "zeros add nothing"


# ---------------------------------------------------------------------------
# DAG run in progress
# ---------------------------------------------------------------------------


_PLUGIN = _ROOT / "plugins" / "edgeguard_dag_run_state.py"


@pytest.fixture()
def run_state_listener(monkeypatch):
    """The plugin's listener, from the plugins-folder file loaded the way Airflow's plugin manager
    loads it (module named after the file, registered in ``sys.modules`` before it runs)."""
    spec = importlib.util.spec_from_file_location(_PLUGIN.stem, _PLUGIN)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    (listener,) = module.EdgeGuardDagRunStatePlugin.listeners
    return SimpleNamespace(module=module, listener=listener)


def _in_progress(dag_id: str):
    return _sample("edgeguard_dag_run_in_progress_start_timestamp", {"dag_id": dag_id})


def _callbacks(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


class TestDagRunInProgress:
    def test_the_run_hooks_mark_a_started_run_and_clear_it_when_it_ends(
        self, run_state_listener, monkeypatch, tmp_path
    ):
        # The hooks write only in the multi-process mode; the values land in this process's registry.
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
        listener = run_state_listener.listener
        start = datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc)
        run = SimpleNamespace(dag_id="edgeguard_daily", run_id="scheduled__probe", start_date=start)

        listener.on_dag_run_running(dag_run=run, msg="started")
        assert _in_progress("edgeguard_daily") == start.timestamp()
        listener.on_dag_run_failed(dag_run=run, msg="Dag Run's state was manually set to `failed`.")
        assert _in_progress("edgeguard_daily") == 0

        restarted = SimpleNamespace(
            dag_id="edgeguard_daily", run_id="scheduled__probe", start_date=start + timedelta(hours=1)
        )
        listener.on_dag_run_running(dag_run=restarted, msg="started")
        assert _in_progress("edgeguard_daily") == restarted.start_date.timestamp()
        listener.on_dag_run_success(dag_run=restarted, msg="success")
        assert _in_progress("edgeguard_daily") == 0

    def test_an_older_run_ending_keeps_the_mark_of_the_run_in_progress(self, run_state_listener, monkeypatch, tmp_path):
        """Marking an older run failed by hand fires the same hook while the current run goes on."""
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
        from airflow.models.dagrun import DagRun

        start = datetime(2026, 10, 15, 2, 0, tzinfo=timezone.utc)
        live = SimpleNamespace(dag_id="edgeguard_daily", run_id="scheduled__live", start_date=start)
        old = SimpleNamespace(dag_id="edgeguard_daily", run_id="manual__old", start_date=start - timedelta(days=1))
        running: list = [live]
        monkeypatch.setattr(DagRun, "find", staticmethod(lambda **kw: list(running)))
        listener = run_state_listener.listener

        listener.on_dag_run_running(dag_run=live, msg="started")
        listener.on_dag_run_failed(dag_run=old, msg="Dag Run's state was manually set to `failed`.")
        assert _in_progress("edgeguard_daily") == start.timestamp(), "the live run stays marked"

        running.clear()
        listener.on_dag_run_success(dag_run=live, msg="success")
        assert _in_progress("edgeguard_daily") == 0

    def test_an_unreadable_run_list_clears_the_mark(self, run_state_listener, monkeypatch, tmp_path, caplog):
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(tmp_path))
        from airflow.models.dagrun import DagRun

        def unreadable(**_kw):
            raise RuntimeError("metadata database unavailable")

        monkeypatch.setattr(DagRun, "find", staticmethod(unreadable))
        run = SimpleNamespace(
            dag_id="edgeguard_low_freq", run_id="r", start_date=datetime(2026, 10, 15, tzinfo=timezone.utc)
        )
        run_state_listener.listener.on_dag_run_running(dag_run=run, msg="started")
        with caplog.at_level(logging.WARNING):
            run_state_listener.listener.on_dag_run_failed(dag_run=run, msg="timed_out")
        assert _in_progress("edgeguard_low_freq") == 0
        assert any("Running runs of edgeguard_low_freq not read" in r.getMessage() for r in caplog.records)

    def test_outside_the_multi_process_mode_the_hooks_write_nothing(self, run_state_listener, monkeypatch):
        """The scheduler's own registry is served by nothing; only the shared directory reaches Prometheus."""
        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        metrics_server.DAG_RUN_START.labels(dag_id="probe_no_multiproc").set(123)

        run_state_listener.listener.on_dag_run_failed(dag_run=SimpleNamespace(dag_id="probe_no_multiproc"), msg="x")

        assert _in_progress("probe_no_multiproc") == 123

    def test_a_metrics_failure_never_reaches_the_scheduler(self, run_state_listener, monkeypatch, caplog):
        def unwritable():
            raise OSError("metrics directory is read-only")

        monkeypatch.setattr(run_state_listener.module, "_run_start_gauge", unwritable)
        run = SimpleNamespace(dag_id="edgeguard_daily", start_date=None)

        with caplog.at_level(logging.WARNING):
            run_state_listener.listener.on_dag_run_running(dag_run=run, msg="started")
            run_state_listener.listener.on_dag_run_failed(dag_run=run, msg="timed_out")

        assert sum("in-progress mark of edgeguard_daily not written" in r.getMessage() for r in caplog.records) == 2

    def test_the_compose_deployment_loads_the_plugin(self):
        airflow = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())["services"]["airflow"]
        folder = airflow["environment"]["AIRFLOW__CORE__PLUGINS_FOLDER"]
        assert f"./{_PLUGIN.parent.name}:{folder}:ro" in airflow["volumes"]
        assert airflow["environment"]["PROMETHEUS_MULTIPROC_DIR"], "the hooks write in the multi-process mode only"

    def test_no_dag_or_task_callback_writes_the_mark(self, dag_module, dags):
        """A DAG-level end callback runs late in the DAG processor and can clear the next run's mark,
        and none runs when a run is marked failed by hand; the listener hooks are the only writer."""
        assert "DAG_RUN_START" not in (_DAGS / "edgeguard_pipeline.py").read_text()
        for dag in dags.values():
            assert dag.tasks, dag.dag_id
            for task in dag.tasks:
                # DAG_LAST_SUCCESS (EdgeGuardDAGLastSuccessStale).
                assert dag_module._on_task_success in _callbacks(task.on_success_callback), task.task_id

    def test_the_former_series_is_no_longer_read_or_written(self):
        exprs = [r["expr"] for g in _RULES["groups"] for r in g["rules"]]
        assert exprs and not any("edgeguard_dag_run_start_timestamp" in e for e in exprs)
        assert metrics_server.DAG_RUN_START._name == "edgeguard_dag_run_in_progress_start_timestamp"
        assert '"edgeguard_dag_run_start_timestamp"' not in (_DAGS / "edgeguard_pipeline.py").read_text()


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

    def test_the_comment_table_gives_each_dags_dagrun_timeout(self, dags):
        # 2026-10: the table above the record lists the timeouts the record adds 15 minutes to; the sync's
        # row gave the record's value (68 h 15 min) where the others give the timeout.
        text = (_ROOT / "prometheus" / "alerts.yml").read_text()
        table = text.split("# 2026-10: the longest a run of each DAG may be in progress", 1)[1]
        table = table.split("- record: edgeguard:dag_run_max_seconds", 1)[0]
        rows = dict(re.findall(r"(edgeguard_\w+)\s+(\d+ h(?: \d+ min)?)", table))

        def seconds(value: str) -> int:
            hours, _, rest = value.partition(" h")
            return int(hours) * 3600 + (int(rest.split()[0]) * 60 if rest.strip() else 0)

        assert {dag_id: seconds(v) for dag_id, v in rows.items()} == {
            dag_id: int(dag.dagrun_timeout.total_seconds()) for dag_id, dag in dags.items()
        }

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


class TestBuildRelationshipsSilentDeath:
    def test_compares_the_last_sync_with_the_last_completion(self):
        """build_relationships runs directly after a successful sync (scheduled DAG and baseline): a
        sync completed longer ago than every attempt can take, with no completion stamped since, is a
        silent death. The former rule ("no completion in 6 h while a baseline task succeeded in the
        last 6 h") fired through every collection phase of a baseline."""
        expr = _norm(_rule("EdgeGuardBuildRelationshipsSilentDeath")["expr"])
        assert expr == (
            "( edgeguard_neo4j_sync_last_success_timestamp > on() "
            "(edgeguard_build_relationships_last_completion_timestamp or on() vector(0)) ) "
            "and on() ( (time() - edgeguard_neo4j_sync_last_success_timestamp) > (15 * 60 * 60 + 25 * 60) ) "
            "and on() ( (time() - edgeguard_neo4j_sync_last_success_timestamp) < (36 * 60 * 60) )"
        )
        assert "edgeguard_dag_last_success_timestamp" not in expr, "no longer tied to any baseline task"

    def test_the_threshold_waits_for_every_attempt(self, dags):
        """A first attempt killed at its limit is retried: the rule must not page while a retry may still
        complete. Its threshold is the longest any build_relationships task can take, every attempt and
        retry delay included, plus 15 minutes."""
        worst = {
            dag_id: (task.retries + 1) * task.execution_timeout + task.retries * task.retry_delay
            for dag_id, dag in dags.items()
            for task in dag.tasks
            if task.task_id == "build_relationships"
        }
        assert set(worst) == {"edgeguard_neo4j_sync", "edgeguard_baseline"}
        assert not any(
            task.retry_exponential_backoff
            for d in dags.values()
            for task in d.tasks
            if task.task_id == "build_relationships"
        )
        assert max(worst.values()) + timedelta(minutes=15) == timedelta(hours=15, minutes=25), worst
        assert timedelta(hours=36) > timedelta(hours=15, minutes=25), "the rule has a firing window"

    def test_a_completion_stamps_the_gauge(self):
        before = _sample("edgeguard_build_relationships_last_completion_timestamp") or 0
        time.sleep(0.01)
        metrics_server.record_build_relationships_completion()
        after = _sample("edgeguard_build_relationships_last_completion_timestamp")
        assert after is not None and after > before and abs(after - time.time()) < 5


class TestFullSyncRequestPendingAlert:
    """2026-10: run_neo4j_sync's failure callback counts a requested full sync (``NEO4J_FULL_SYNC``) that
    failed on its last attempt; no rule read that series, so the request could keep every scheduled run
    a full sync, with no incremental sync, without an alert."""

    _LABELS = {"task": "run_neo4j_sync", "error_type": "full_sync_request_pending", "source": "edgeguard_neo4j_sync"}

    def test_the_rule_reads_the_series_the_failure_callback_counts(
        self, dag_module, dags, compose_metrics, monkeypatch
    ):
        class _Pending(_StubVariable):
            @staticmethod
            def get(key, default=None):
                return "true" if key == "NEO4J_FULL_SYNC" else default

        monkeypatch.setattr(dag_module, "Variable", _Pending)
        monkeypatch.setattr(dag_module, "PIPELINE_ERRORS", metrics_server.PIPELINE_ERRORS, raising=False)
        monkeypatch.setattr(dag_module, "_on_task_failure", lambda context: None)
        monkeypatch.setattr(dag_module, "ENABLE_SLACK_ALERTS", False)
        before = _sample("edgeguard_pipeline_errors_total", self._LABELS) or 0
        dag_module._on_neo4j_sync_failure(
            {"dag": dags["edgeguard_neo4j_sync"], "task_instance": SimpleNamespace(task_id="run_neo4j_sync")}
        )
        assert _sample("edgeguard_pipeline_errors_total", self._LABELS) == before + 1

        rule = _rule("EdgeGuardNeo4jFullSyncRequestPending")
        selectors = re.findall(r"\b(edgeguard_\w+)\{([^}]*)\}", rule["expr"])
        assert len(selectors) == 3, "the increase clause and both sides of the first-failure clause"
        wanted = {k: v for k, v in self._LABELS.items() if k != "source"}
        for metric, matchers in selectors:
            assert metric == "edgeguard_pipeline_errors_total"
            assert dict(re.findall(r'(\w+)="([^"]*)"', matchers)) == wanted
        # Every alert names metrics src/metrics_server.py defines.
        assert '"edgeguard_pipeline_errors_total"' in (_SRC / "metrics_server.py").read_text()

    def test_the_first_failure_fires_and_the_window_is_the_sync_interval(self):
        rule = _rule("EdgeGuardNeo4jFullSyncRequestPending")
        selector = 'edgeguard_pipeline_errors_total{task="run_neo4j_sync", error_type="full_sync_request_pending"}'
        assert _norm(rule["expr"]) == (
            f"sum by (source) ( increase({selector}[3d]) ) > 0 or "
            f"( sum by (source) ({selector}) unless sum by (source) ({selector} offset 3d) )"
        ), "increase() is 0 for a new series: the second clause catches the first failure"
        assert rule["for"] == "0m" and rule["labels"]["severity"] == "warning"

    def test_the_docs_name_it(self):
        table = (_ROOT / "docs" / "PROMETHEUS_SETUP.md").read_text()
        assert "| `EdgeGuardNeo4jFullSyncRequestPending` |" in table
        runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
        section = runbook.split("## Requesting a full MISP → Neo4j sync", 1)[1].split("\n## ", 1)[0]
        assert "`EdgeGuardNeo4jFullSyncRequestPending`" in section

    def test_the_readme_counts_the_rules(self):
        # 2026-10: the launch-day monitoring step said 37 rules when the file held 38, and 39 with this one.
        rules = [r for g in _RULES["groups"] for r in g["rules"] if "alert" in r]
        readme = (_ROOT / "README.md").read_text()
        assert f"({len(rules)} alert rules at HEAD across {len(_RULES['groups'])} groups)" in readme

    def test_it_says_it_clears_three_days_after_the_last_failure(self):
        # 2026-10: the rule reads a counter over a 3-day window, so it keeps firing after the request was
        # cleared or a later run succeeded; "still pending" said otherwise.
        annotations = _rule("EdgeGuardNeo4jFullSyncRequestPending")["annotations"]
        assert "pending" not in annotations["summary"] and "in the last 3 days" in annotations["summary"]
        assert "clears 3 days after the last failure" in annotations["description"]
        runbook = (_ROOT / "docs" / "RUNBOOK.md").read_text()
        section = runbook.split("## Requesting a full MISP → Neo4j sync", 1)[1].split("\n## ", 1)[0]
        assert "clears 3 days after the last failure" in section
        row = next(
            line
            for line in (_ROOT / "docs" / "PROMETHEUS_SETUP.md").read_text().splitlines()
            if line.startswith("| `EdgeGuardNeo4jFullSyncRequestPending` |")
        )
        assert "clears 3 days after the last failure" in row


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


def _simulate_sync_schedule(dag_module, schedule: str, state_dir: Path) -> SimpleNamespace:
    """Sync starts of the 3-day cron through the real cadence guard, 2025-2032 (two leap years).

    ``gaps``: hours between consecutive scheduled sync starts. ``after_baseline``: hours from a
    baseline's full sync (which restarts the guard) to the next scheduled sync start, for a baseline
    starting at every hour of January and February 2027.
    """
    fires = _cron_fires(schedule, datetime(2025, 1, 1, tzinfo=timezone.utc), datetime(2033, 1, 1, tzinfo=timezone.utc))
    starts = _sync_starts(dag_module, state_dir, fires[1:], fires[0] + timedelta(minutes=1))
    after_baseline = []
    for hour in range(0, 24 * 31 * 2, 1):
        baseline_start = datetime(2027, 1, 1, tzinfo=timezone.utc) + timedelta(hours=hour, minutes=7)
        upcoming = [f for f in fires if f > baseline_start][:4]
        first = _sync_starts(dag_module, state_dir, upcoming, baseline_start)[0]
        after_baseline.append((first - baseline_start).total_seconds() / 3600)
    return SimpleNamespace(
        starts=starts,
        gaps=[(b - a).total_seconds() / 3600 for a, b in pairwise(starts)],
        after_baseline=after_baseline,
    )


class TestSyncStaleness:
    def test_threshold_covers_the_longest_gap_of_the_three_day_schedule(
        self, dag_module, dags, compose_metrics, tmp_path
    ):
        sync_dag = dags["edgeguard_neo4j_sync"]
        assert sync_dag.schedule == "0 3 */3 * *"
        sim = _simulate_sync_schedule(dag_module, sync_dag.schedule, tmp_path / "state")
        starts, gaps = sim.starts, sim.gaps
        assert round(max(gaps)) == 120, "28 February to 4 March in a leap year"
        non_leap = [
            (b - a).total_seconds() / 3600 for a, b in pairwise(starts) if a.year not in (2028, 2032) or a.month != 2
        ]
        assert round(max(non_leap)) == 96, "the fire after the 31st is skipped by the 71 h guard"
        month_end_gaps_2027 = [g for a, g in zip(starts[:-1], gaps, strict=True) if a.year == 2027 and g > 73]
        assert len(month_end_gaps_2027) >= 8, "the former 72 h limit fired at most month ends"
        # A baseline's full sync restarts the guard: the next scheduled sync may be one fire later.
        assert 142 < max(sim.after_baseline) < 144

        expr = _norm(_rule("EdgeGuardNeo4jSyncStale")["expr"])
        assert expr == (
            "time() - edgeguard_neo4j_sync_last_success_timestamp > 522000 "
            "and edgeguard_neo4j_sync_last_success_timestamp > 0"
        )
        threshold_h = 522000 / 3600
        # The stamp is written when run_neo4j_sync succeeds, so the next sync may take up to every
        # attempt of that task longer (never longer than the DAG run's timeout).
        sync_task = sync_dag.get_task("run_neo4j_sync")
        attempts = sync_task.retries + 1
        task_h = (
            attempts * sync_task.execution_timeout + sync_task.retries * sync_task.retry_delay
        ).total_seconds() / 3600
        duration_h = min(task_h, sync_dag.dagrun_timeout.total_seconds() / 3600)
        assert max(gaps) + duration_h <= threshold_h, (max(gaps), duration_h)
        assert max(sim.after_baseline) <= threshold_h
        assert _rule("EdgeGuardNeo4jSyncStale")["for"] == "1h"

    def test_misp_to_neo4j_staleness_covers_the_longest_gap_between_two_syncs(
        self, dag_module, dags, compose_metrics, tmp_path
    ):
        """``misp_to_neo4j`` is stamped when a sync connects (and again on a clean run), so two
        stamps are at most one start-to-start gap apart; the 26 h catch-all fired 46 h of every 72 h."""
        sim = _simulate_sync_schedule(dag_module, dags["edgeguard_neo4j_sync"].schedule, tmp_path / "state")
        longest_s = max(max(sim.gaps), max(sim.after_baseline)) * 3600
        limit_s = _label_map("edgeguard:collector_max_stale_seconds", "source")["misp_to_neo4j"]
        assert longest_s < limit_s <= longest_s + 3 * 3600, "covers the longest gap, with at most 3 h margin"


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
            (make_status("probe_collected", True, count=7), "collected", "success"),
            (make_status("probe_empty", True, count=0), "empty", "success"),
            (make_status("probe_not_modified", True, count=0, not_modified=True), "not_modified", "not_modified"),
            (
                make_skipped_optional_source(
                    "probe_skipped", skip_reason="no API key configured", skip_reason_class="missing_probe_key"
                ),
                "skipped",
                "skipped",
            ),
        ],
    )
    def test_a_run_records_its_outcome_and_adds_its_count_once(
        self, dag_module, compose_metrics, result, outcome, status
    ):
        source = result["source"]

        class _Collector:
            def __init__(self, misp_writer=None, **kwargs):
                pass

            def collect(self, limit=None, push_to_misp=True):
                return dict(result)

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
                return make_status("probe_failed", False, count=0, failed=3)

        with pytest.raises(Exception, match="success=false"):
            dag_module.run_collector_with_metrics("probe_failed", _Failing, MagicMock(), limit=10)
        assert _sample("edgeguard_collector_last_run_outcome", {"source": "probe_failed", "outcome": "failed"}) == 1

        monkeypatch.setattr(dag_module, "is_collector_enabled_by_allowlist", lambda name: False)
        dag_module.run_collector_with_metrics("probe_disabled", _Failing, MagicMock(), limit=10)
        assert _sample("edgeguard_collector_last_run_outcome", {"source": "probe_disabled", "outcome": "skipped"}) == 1

    @staticmethod
    def _outcomes(source: str) -> dict:
        return {
            o: _sample("edgeguard_collector_last_run_outcome", {"source": source, "outcome": o})
            for o in metrics_server.COLLECTOR_RUN_OUTCOMES
        }

    @pytest.mark.parametrize(
        "path, outcome",
        [
            ("baseline_in_progress", "skipped"),
            ("not_a_status_dict", "failed"),
            ("parent_dag_aborted", "skipped"),
            ("transient_external_error", "skipped"),
            ("catastrophic_error", "failed"),
        ],
    )
    def test_every_other_exit_path_records_its_outcome(self, dag_module, compose_metrics, monkeypatch, path, outcome):
        """Each path overwrites the previous outcome; a path that wrote none would leave ``collected``."""
        import baseline_lock
        from parent_dag_liveness import AbortedByDagFailureException

        source = f"probe_path_{path}"
        metrics_server.record_collector_outcome(source, "collected")
        monkeypatch.setattr(dag_module, "send_slack_alert", lambda *args, **kwargs: None)

        def collect():
            if path == "not_a_status_dict":
                return []  # the shape a collector returns with push_to_misp=False
            if path == "parent_dag_aborted":
                raise AbortedByDagFailureException("edgeguard_baseline", "manual__probe", "failed")
            if path == "transient_external_error":
                raise ConnectionError("Connection reset by peer")
            if path == "catastrophic_error":
                raise TypeError("unsupported operand type(s) for +: 'int' and 'NoneType'")
            return make_status(source, True, count=7)

        class _Collector:
            def __init__(self, misp_writer=None, **kwargs):
                pass

            def collect(self, limit=None, push_to_misp=True):
                return collect()

        if path == "baseline_in_progress":
            assert baseline_lock.acquire_baseline_lock() is True  # an in-process baseline holds the lock
        try:
            if path == "not_a_status_dict":
                with pytest.raises(dag_module.AirflowException, match="expected a status dict"):
                    dag_module.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)
            elif path == "catastrophic_error":
                with pytest.raises(TypeError, match="unsupported operand"):
                    dag_module.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)
            else:
                result = dag_module.run_collector_with_metrics(source, _Collector, MagicMock(), limit=10)
                assert result["skipped"] is True and result["skip_reason_class"] == path
        finally:
            if path == "baseline_in_progress":
                baseline_lock.release_baseline_lock()

        assert self._outcomes(source) == {
            o: (1.0 if o == outcome else 0.0) for o in metrics_server.COLLECTOR_RUN_OUTCOMES
        }

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
from unittest.mock import MagicMock

sys.path[:0] = [sys.argv[1], sys.argv[2]]
import edgeguard_pipeline as ep


class Probe:
    def __init__(self, misp_writer=None, **kwargs):
        pass

    def collect(self, limit=None, push_to_misp=True):
        return {"source": "o8_probe", "success": True, "count": 7, "failed": 0}


ep.run_collector_with_metrics("o8_probe", Probe, MagicMock(), limit=10)
flags = {
    "enabled": ep.ENABLE_PROMETHEUS_METRICS,
    "prometheus": ep.PROMETHEUS_AVAILABLE,
    "metrics_server": ep.METRICS_SERVER_AVAILABLE,
    "multiprocess": bool(ep.MULTIPROC_METRICS_DIR),
}
print("FLAGS=" + json.dumps(flags))
"""

# A scheduler or API server process: Airflow's listener manager loads the plugins folder named by
# AIRFLOW__CORE__PLUGINS_FOLDER, then each step changes the run's state the way Airflow does and
# calls the hook through Airflow's own code. After every step the process prints the mark as the
# ``metrics`` service would serve it (aggregated from the shared directory).
_LISTENER_CHILD = r"""
import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

sys.path.insert(0, sys.argv[1])
from airflow.api_fastapi.core_api.datamodels.dag_run import DagRunMutableStates
from airflow.api_fastapi.core_api.services.public import dag_run as dag_run_service
from airflow.listeners.listener import get_listener_manager
from airflow.models.dagrun import DagRun
from airflow.utils.state import DagRunState
from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

import metrics_exporter

listeners = sorted(type(p).__module__ for p in get_listener_manager().pm.get_plugins())
print("LISTENERS=" + json.dumps(listeners))
dag_id = sys.argv[2]
run = DagRun(dag_id=dag_id, run_id="manual__probe", run_type="manual")


def mark():
    text = generate_latest(metrics_exporter.build_registry(None)).decode()
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            if sample.name == "edgeguard_dag_run_in_progress_start_timestamp" and sample.labels == {"dag_id": dag_id}:
                return sample.value
    return None


def set_state_in_database(*, dag, run_id, commit, session):
    # The database update of mark_tasks.set_dag_run_state_to_*; the listener call stays Airflow's.
    return [], []


for step in sys.argv[3:]:
    action, _, arg = step.partition("=")
    if action == "scheduler_start":
        # SchedulerJobRunner._start_queued_dagruns: RUNNING with start_date now, then the hook.
        run.state = DagRunState.RUNNING
        run.start_date = datetime.fromtimestamp(float(arg), timezone.utc)
        run.notify_dagrun_state_changed(msg="started")
    elif action == "scheduler_end":
        # DagRun.update_state, or the scheduler's dagrun_timeout branch for a failed run.
        run.state = DagRunState(arg)
        run.notify_dagrun_state_changed(msg="timed_out" if arg == "failed" else "success")
    elif action == "api":
        # PATCH /api/v2/dags/{dag_id}/dagRuns/{run_id} {"state": arg}: UI "Mark run as ...", `edgeguard dag kill`.
        dag_run_service.set_dag_run_state_to_failed = set_state_in_database
        dag_run_service.set_dag_run_state_to_success = set_state_in_database
        dag_run_service.patch_dag_run_state(
            dag=SimpleNamespace(dag_id=dag_id), dag_run=run, state=DagRunMutableStates(arg), session=None
        )
    else:
        raise SystemExit(f"unknown step {step}")
    print("MARK=" + json.dumps(mark()))
"""


def _child_env(tmp_path: Path, metrics_dir: Path) -> dict:
    env = dict(
        os.environ,
        PROMETHEUS_MULTIPROC_DIR=str(metrics_dir),
        NEO4J_PASSWORD="x",
        MISP_API_KEY="x",
        EDGEGUARD_ENV="dev",
        EDGEGUARD_BASELINE_LOCK_PATH=str(tmp_path / "no_such.lock"),
    )
    env.pop("EDGEGUARD_COLLECT_SOURCES", None)
    return env


def _run_child(tmp_path: Path, metrics_dir: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(_DAGS), str(_SRC)],
        env=_child_env(tmp_path, metrics_dir),
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


def _run_listener_child(tmp_path: Path, metrics_dir: Path, dag_id: str, *steps: str) -> list:
    """Run ``steps`` in a new Airflow process with the repository's plugins folder; the marks after each."""
    env = _child_env(tmp_path, metrics_dir)
    env.update(
        AIRFLOW_HOME=str(tmp_path / "airflow_home"),
        AIRFLOW__CORE__PLUGINS_FOLDER=str(_PLUGIN.parent),
        AIRFLOW__CORE__LOAD_EXAMPLES="false",
    )
    proc = subprocess.run(
        [sys.executable, "-c", _LISTENER_CHILD, str(_SRC), dag_id, *steps],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    lines = proc.stdout.splitlines()
    listeners = [json.loads(line[len("LISTENERS=") :]) for line in lines if line.startswith("LISTENERS=")]
    assert listeners == [[_PLUGIN.stem]], "Airflow loaded the plugin from the plugins folder"
    return [json.loads(line[len("MARK=") :]) for line in lines if line.startswith("MARK=")]


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
    def test_one_run_adds_its_count_once(self, tmp_path):
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        _run_child(tmp_path, metrics_dir)
        values = _aggregate(metrics_dir)
        collected = _value(
            values, "edgeguard_indicators_collected_total", source="o8_probe", zone="global", status="success"
        )
        assert collected == 7.0, "one run of 7 indicators adds 7 (it added 14 when both helpers counted)"
        assert _value(values, "edgeguard_misp_push_duration_seconds_count", source="o8_probe") == 1.0
        assert _value(values, "edgeguard_collector_last_run_outcome", source="o8_probe", outcome="collected") == 1.0

    def test_the_scheduler_and_the_api_server_keep_the_run_mark(self, tmp_path):
        """Each step runs in the process Airflow runs it in, so the ``mostrecent`` merge is exercised.

        A run marked failed by hand goes through the API server, which runs no DAG-level callback:
        with the former callbacks the mark kept the run's start and EdgeGuardDAGRunStuck fired once
        the start was older than the limit, until the DAG's next run.
        """
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()
        dag_id = "edgeguard_baseline"
        start = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc).timestamp()

        assert _run_listener_child(tmp_path, metrics_dir, dag_id, f"scheduler_start={start}") == [start]
        assert _run_listener_child(tmp_path, metrics_dir, dag_id, "api=failed") == [0.0]

        later = start + 3 * 86400
        steps = (f"scheduler_start={later}", "scheduler_end=failed", f"scheduler_start={later + 3600}")
        assert _run_listener_child(tmp_path, metrics_dir, dag_id, *steps) == [later, 0.0, later + 3600]
        assert _run_listener_child(tmp_path, metrics_dir, dag_id, "api=success") == [0.0]

        last = later + 7 * 86400
        steps = (f"scheduler_start={last}", "scheduler_end=success")
        assert _run_listener_child(tmp_path, metrics_dir, dag_id, *steps) == [last, 0.0]
        assert _value(_aggregate(metrics_dir), "edgeguard_dag_run_in_progress_start_timestamp", dag_id=dag_id) == 0.0
