"""Counter series that ``increase()`` reads start at 0 (2026-11-08).

Prometheus' ``increase()`` does not count the value a series already holds in its first sample, and the
multi-process mode of ``prometheus_client`` exports no ``_created`` sample. A 730-day baseline that started
with an empty multi-process directory created each source's ``edgeguard_indicators_collected_total`` series
with its full count, and ``EdgeGuardNoIndicatorsCollected`` fired for the 8 sources that had collected. Every
collector task now creates, before its collector runs, the ``success`` series of every collector and the
``edgeguard_report_pending_given_up_total`` series of every report source at 0
(``metrics_server.start_series_at_zero``, called by the DAG's ``ensure_metrics_server``).

The multi-process cases run in child processes with their own ``PROMETHEUS_MULTIPROC_DIR``, as Airflow task
processes do, and read the directory the way the ``metrics`` service serves it.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
_DAGS = _ROOT / "dags"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import metrics_exporter  # noqa: E402
from collector_allowlist import COLLECT_SOURCES_CANONICAL  # noqa: E402
from report_records import REPORT_SOURCES  # noqa: E402

COLLECTED = "edgeguard_indicators_collected_total"
GIVEN_UP = "edgeguard_report_pending_given_up_total"

# A task process: metrics_server imported as the DAG module imports it, then one step.
_FUNCTION_CHILD = r"""
import json
import sys

sys.path.insert(0, sys.argv[1])
import metrics_server

step = sys.argv[2]
if step == "zero":
    print("CREATED=" + json.dumps(metrics_server.start_series_at_zero()))
elif step == "run":
    # What a collector task records after a run of 7 Feodo indicators, and a CISA ICS push that gave up 2 records.
    metrics_server.record_collection("feodo", "global", 7, "success")
    metrics_server.record_report_pending("cisa_ics", 0, 0.0, 2)
else:
    raise SystemExit(f"unknown step {step}")
"""

# A collector task of the compose deployment: the DAG module imported as Airflow imports it, one run of a
# collector whose ``collect`` scrapes the shared directory while it runs, before the run's count is added.
_DAG_CHILD = r"""
import json
import logging
import sys
from unittest.mock import MagicMock

sys.path[:0] = [sys.argv[1], sys.argv[2]]
import edgeguard_pipeline as ep
import metrics_exporter
from collectors.collector_utils import make_status
from prometheus_client import generate_latest
from prometheus_client.parser import text_string_to_metric_families


def scrape():
    text = generate_latest(metrics_exporter.build_registry(None)).decode()
    return [[s.name, s.labels, s.value] for f in text_string_to_metric_families(text) for s in f.samples]


warnings = []


class _Warnings(logging.Handler):
    def emit(self, record):
        if record.levelno >= logging.WARNING:
            warnings.append(record.getMessage())


ep.logger.addHandler(_Warnings())
if sys.argv[3] == "failing":

    def _failing():
        raise OSError("No space left on device")

    ep.start_series_at_zero = _failing

seen = {}


class Feodo:
    def __init__(self, misp_writer=None, **kwargs):
        pass

    def collect(self, limit=None, push_to_misp=True):
        seen["during"] = scrape()
        return make_status("feodo", True, count=7)


result = ep.run_collector_with_metrics("feodo", Feodo, MagicMock(), limit=10)
print("RESULT=" + json.dumps({"success": result["success"], "count": result["count"],
                              "multiprocess": bool(ep.MULTIPROC_METRICS_DIR)}))
print("DURING=" + json.dumps(seen["during"]))
print("WARNINGS=" + json.dumps(warnings))
"""


def _env(tmp_path: Path, metrics_dir: Path) -> dict:
    env = dict(
        os.environ,
        PROMETHEUS_MULTIPROC_DIR=str(metrics_dir),
        PYTHONDONTWRITEBYTECODE="1",
        NEO4J_PASSWORD="x",
        MISP_API_KEY="x",
        EDGEGUARD_ENV="dev",
        EDGEGUARD_BASELINE_LOCK_PATH=str(tmp_path / "no_such.lock"),
        AIRFLOW_HOME=str(tmp_path / "airflow_home"),
    )
    env.pop("EDGEGUARD_COLLECT_SOURCES", None)
    return env


def _child(tmp_path: Path, metrics_dir: Path, code: str, *args: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        [sys.executable, "-c", code, *args],
        env=_env(tmp_path, metrics_dir),
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    return proc


def _line(proc: subprocess.CompletedProcess, prefix: str):
    lines = [line for line in proc.stdout.splitlines() if line.startswith(prefix)]
    assert lines, proc.stdout[-2000:]
    return json.loads(lines[-1][len(prefix) :])


def _samples(text: str) -> dict:
    return {
        (sample.name, tuple(sorted(sample.labels.items()))): sample.value
        for family in text_string_to_metric_families(text)
        for sample in family.samples
    }


def _aggregate(metrics_dir: Path) -> dict:
    """The samples the ``metrics`` service serves from ``metrics_dir``."""
    return _samples(generate_latest(metrics_exporter.build_registry(str(metrics_dir))).decode())


def _key(name: str, **labels: str) -> tuple:
    return (name, tuple(sorted(labels.items())))


def _expected_zero_series() -> set:
    collected = {_key(COLLECTED, source=s, zone="global", status="success") for s in COLLECT_SOURCES_CANONICAL}
    return collected | {_key(GIVEN_UP, source=s) for s in REPORT_SOURCES}


def _labelled(values: dict) -> set:
    """Series with labels, histogram buckets aside: the series a call creates (an unlabelled metric exists from
    the import of its module in every process)."""
    return {key for key in values if {name for name, _ in key[1]} - {"le"}}


class TestMultiProcess:
    def test_a_scrape_sees_every_series_at_zero(self, tmp_path):
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        proc = _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "zero")

        expected = _expected_zero_series()
        assert _line(proc, "CREATED=") == len(expected) == len(COLLECT_SOURCES_CANONICAL) + len(REPORT_SOURCES)
        values = _aggregate(metrics_dir)
        assert {key: values.get(key) for key in expected} == dict.fromkeys(expected, 0.0)
        # Nothing else: no gauge (a source that never runs gets no edgeguard_source_health series, so
        # EdgeGuardNoIndicatorsCollected cannot fire for it), no other status or zone.
        assert _labelled(values) == expected

    def test_the_first_run_adds_to_the_series_that_started_at_zero(self, tmp_path):
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "zero")
        _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "run")

        values = _aggregate(metrics_dir)
        assert values[_key(COLLECTED, source="feodo", zone="global", status="success")] == 7.0
        assert values[_key(GIVEN_UP, source="cisa_ics")] == 2.0
        assert values[_key(GIVEN_UP, source="alienvault_otx")] == 0.0
        assert values[_key(COLLECTED, source="threatfox", zone="global", status="success")] == 0.0
        counters = {key for key in _labelled(values) if key[0] in (COLLECTED, GIVEN_UP)}
        assert counters == _expected_zero_series(), "the run added to the same series, it made no new one"

    def test_creating_the_series_again_keeps_their_counts(self, tmp_path):
        """A later task (and a compaction of the files of exited tasks) must not lower or reset a count."""
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "zero")
        _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "run")
        _child(tmp_path, metrics_dir, _FUNCTION_CHILD, str(_SRC), "zero")

        feodo = _key(COLLECTED, source="feodo", zone="global", status="success")
        ics = _key(GIVEN_UP, source="cisa_ics")
        values = _aggregate(metrics_dir)
        assert (values[feodo], values[ics]) == (7.0, 2.0)

        report = metrics_exporter.compact_multiproc_dir(str(metrics_dir), live_pids=set())
        assert report["merged_types"] >= 1
        values = _aggregate(metrics_dir)
        assert (values[feodo], values[ics]) == (7.0, 2.0)


class TestCollectorTask:
    def test_a_scrape_during_the_first_run_sees_the_series_at_zero(self, tmp_path):
        """The finding itself: the run's count follows a 0 sample of the same series."""
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        proc = _child(tmp_path, metrics_dir, _DAG_CHILD, str(_DAGS), str(_SRC), "normal")

        assert _line(proc, "RESULT=") == {"success": True, "count": 7, "multiprocess": True}
        assert not [w for w in _line(proc, "WARNINGS=") if "Counter series" in w]
        during = {_key(name, **labels): value for name, labels, value in _line(proc, "DURING=")}
        expected = _expected_zero_series()
        assert {key: during.get(key) for key in expected} == dict.fromkeys(expected, 0.0), (
            "every source's series exists at 0 while the first collector runs"
        )
        after = _aggregate(metrics_dir)
        assert after[_key(COLLECTED, source="feodo", zone="global", status="success")] == 7.0
        assert after[_key(COLLECTED, source="urlhaus", zone="global", status="success")] == 0.0

    def test_a_failure_to_create_the_series_does_not_fail_the_task(self, tmp_path):
        metrics_dir = tmp_path / "metrics_multiproc"
        metrics_dir.mkdir()

        proc = _child(tmp_path, metrics_dir, _DAG_CHILD, str(_DAGS), str(_SRC), "failing")

        assert _line(proc, "RESULT=") == {"success": True, "count": 7, "multiprocess": True}
        assert [w for w in _line(proc, "WARNINGS=") if w.startswith("Counter series not created at 0")] == [
            "Counter series not created at 0 (increase() may not count this run): No space left on device"
        ]
        during = {_key(name, **labels) for name, labels, _ in _line(proc, "DURING=")}
        assert not during & _expected_zero_series()
        assert _aggregate(metrics_dir)[_key(COLLECTED, source="feodo", zone="global", status="success")] == 7.0


class TestCoverage:
    def test_every_collector_the_dag_runs_has_its_series(self):
        """A collector name outside COLLECT_SOURCES_CANONICAL would get no series at 0."""
        dag = (_DAGS / "edgeguard_pipeline.py").read_text()
        scheduled = set(re.findall(r'run_collector_with_metrics\(\s*"(\w+)"', dag))
        baseline = set(re.findall(r'run_baseline_collector\(\s*"(\w+)"', dag))
        assert len(scheduled) >= 12 and len(baseline) >= 11
        assert scheduled | baseline <= COLLECT_SOURCES_CANONICAL

    def test_a_run_is_counted_under_the_zone_the_series_start_in(self):
        """``run_collector_with_metrics`` records a run under the zone its status names, ``global`` without one;
        a collector status names none."""
        import metrics_server
        from collectors.collector_utils import make_status

        assert "zone" not in make_status("feodo", True, count=7)
        dag = (_DAGS / "edgeguard_pipeline.py").read_text()
        assert 'zone = result.get("zone", "global")' in dag
        assert (metrics_server.ZERO_START_ZONE, metrics_server.ZERO_START_STATUS) == ("global", "success")

    def test_the_dag_creates_the_series_before_the_collector_runs(self):
        dag = (_DAGS / "edgeguard_pipeline.py").read_text()
        ensure = dag[
            dag.index("def ensure_metrics_server") : dag.index("def ", dag.index("def ensure_metrics_server") + 1)
        ]
        assert "start_series_at_zero()" in ensure
        assert ensure.index("start_series_at_zero()") < ensure.index("if MULTIPROC_METRICS_DIR:")
        wrapper = dag[dag.index("def run_collector_with_metrics") :]
        assert wrapper.index("ensure_metrics_server()") < wrapper.index("collector.collect(")
        sync = dag[dag.index("def run_neo4j_sync") :]
        assert sync.index("ensure_metrics_server()") < sync.index("def ", 1), "the sync task creates them too"
