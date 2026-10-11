"""Multi-process metrics exposure (2026-10 production-readiness check, blocker B1).

Under Airflow's LocalExecutor every task is its own process; metrics written there never reached
Prometheus. With ``PROMETHEUS_MULTIPROC_DIR`` set, values go to shared files, the exporter serves the
aggregate, gauges carry most-recent semantics and the directory is compacted.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml
from prometheus_client import generate_latest
from prometheus_client.mmap_dict import MmapedDict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import metrics_exporter  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"


def _key(metric: str, name: str, labels: dict, help_text: str = "h") -> str:
    # same encoding prometheus_client uses for its mmap keys
    return json.dumps([metric, name, labels, help_text])


class TestGaugeSemantics:
    def test_every_gauge_in_the_registry_is_mostrecent(self):
        os.environ.setdefault("NEO4J_PASSWORD", "x")
        os.environ.setdefault("MISP_API_KEY", "x")
        from prometheus_client import REGISTRY

        import metrics_server  # noqa: F401
        import resilience  # noqa: F401

        gauges = [c for c in REGISTRY._names_to_collectors.values() if getattr(c, "_type", None) == "gauge"]
        assert gauges, "no gauges registered?"
        wrong = sorted({c._name for c in gauges if getattr(c, "_multiprocess_mode", None) != "mostrecent"})
        assert not wrong, wrong

    def test_dag_gauges_are_mostrecent(self):
        src = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        calls = [m.start() for m in re.finditer(r"\b_?Gauge\(", src)]
        assert len(calls) >= 6
        for start in calls:
            window = src[start : start + 400]
            assert 'multiprocess_mode="mostrecent"' in window, window[:120]


class TestModeSwitches:
    def test_mode_detection_and_directory_creation(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        assert metrics_exporter.multiprocess_mode_active() is False
        target = tmp_path / "mp"
        monkeypatch.setenv("PROMETHEUS_MULTIPROC_DIR", str(target))
        assert metrics_exporter.multiprocess_mode_active() is True
        assert metrics_exporter.ensure_multiproc_dir() == str(target) and target.is_dir()

    def test_dag_and_metrics_dag_do_not_start_servers_in_multiprocess_mode(self):
        dag = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
        assert "MULTIPROC_METRICS_DIR" in dag and "compact_multiproc_dir(MULTIPROC_METRICS_DIR" in dag
        assert "ENABLE_PROMETHEUS_METRICS = os.getenv" in dag and "or bool(" in dag
        mdag = (_ROOT / "dags" / "edgeguard_metrics_server.py").read_text()
        assert 'os.getenv("PROMETHEUS_MULTIPROC_DIR")' in mdag


class TestEndToEnd:
    def test_value_recorded_in_another_process_is_served_by_the_aggregate(self, tmp_path, monkeypatch):
        """The defect itself: a child process records metrics; the parent, with an aggregated
        registry, sees them without any HTTP server in the child."""
        mp = tmp_path / "mp"
        mp.mkdir()
        env = dict(os.environ, PROMETHEUS_MULTIPROC_DIR=str(mp), NEO4J_PASSWORD="x", MISP_API_KEY="x")
        code = (
            "import sys; sys.path.insert(0, %r); import metrics_server as m, resilience as r; "
            "m.INDICATORS_COLLECTED.labels(source='otx', zone='energy', status='success').inc(7); "
            "r.LAST_SUCCESS.labels(source='otx').set(1700000000)"
        ) % str(_SRC)
        subprocess.run([sys.executable, "-c", code], check=True, env=env, timeout=120, capture_output=True)
        assert any(mp.glob("counter_*.db")) and any(mp.glob("gauge_mostrecent_*.db"))
        text = generate_latest(metrics_exporter.build_registry(str(mp))).decode()
        assert re.search(r'edgeguard_indicators_collected_total\{[^}]*source="otx"[^}]*\} 7\.0', text), text[:600]
        assert 'edgeguard_last_success_timestamp{source="otx"} 1.7e+09' in text
        assert "pid=" not in text, "most-recent gauges must not leak a pid label"


class TestCompaction:
    def _write(self, directory: Path, name: str, rows):
        d = MmapedDict(str(directory / name))
        for key, value, ts in rows:
            d.write_value(key, value, ts)
        d.close()

    def test_dead_process_files_are_merged_and_live_ones_kept(self, tmp_path):
        k_counter = _key("edgeguard_x_total", "edgeguard_x_total", {"source": "a"})
        k_gauge = _key("edgeguard_g", "edgeguard_g", {"source": "a"})
        self._write(tmp_path, "counter_101.db", [(k_counter, 3.0, 0.0)])
        self._write(tmp_path, "counter_102.db", [(k_counter, 4.0, 0.0)])
        self._write(tmp_path, "counter_303.db", [(k_counter, 100.0, 0.0)])  # live process, must stay
        self._write(tmp_path, "gauge_mostrecent_101.db", [(k_gauge, 1.0, 10.0)])
        self._write(tmp_path, "gauge_mostrecent_102.db", [(k_gauge, 2.0, 20.0)])
        report = metrics_exporter.compact_multiproc_dir(str(tmp_path), live_pids={303})
        assert report["merged_types"] == 2 and report["removed_files"] == 4
        names = sorted(p.name for p in tmp_path.glob("*.db"))
        assert names == ["counter_303.db", "counter_merged.db", "gauge_mostrecent_merged.db"]
        text = generate_latest(metrics_exporter.build_registry(str(tmp_path))).decode()
        assert 'edgeguard_x_total{source="a"} 107.0' in text  # 3 + 4 merged + 100 live
        assert 'edgeguard_g{source="a"} 2.0' in text  # newest timestamp wins

    def test_second_compaction_folds_into_the_existing_merged_file(self, tmp_path):
        k = _key("edgeguard_y_total", "edgeguard_y_total", {})
        self._write(tmp_path, "counter_1.db", [(k, 1.0, 0.0)])
        metrics_exporter.compact_multiproc_dir(str(tmp_path), live_pids=set())
        self._write(tmp_path, "counter_2.db", [(k, 2.0, 0.0)])
        report = metrics_exporter.compact_multiproc_dir(str(tmp_path), live_pids=set())
        assert report["removed_files"] == 1
        text = generate_latest(metrics_exporter.build_registry(str(tmp_path))).decode()
        assert "edgeguard_y_total 3.0" in text

    def test_threshold_and_missing_directory(self, tmp_path):
        assert "skipped" in metrics_exporter.compact_multiproc_dir(str(tmp_path / "absent"))
        assert "skipped" in metrics_exporter.compact_multiproc_dir(str(tmp_path), min_files=5)

    def test_other_gauge_modes_are_left_alone(self, tmp_path):
        k = _key("edgeguard_z", "edgeguard_z", {})
        self._write(tmp_path, "gauge_all_7.db", [(k, 1.0, 0.0)])
        report = metrics_exporter.compact_multiproc_dir(str(tmp_path), live_pids=set())
        assert report["merged_types"] == 0 and (tmp_path / "gauge_all_7.db").exists()


class TestComposeWiring:
    def test_airflow_and_metrics_service_share_the_directory(self):
        compose = yaml.safe_load((_ROOT / "docker-compose.yml").read_text())
        airflow = compose["services"]["airflow"]
        assert airflow["environment"]["PROMETHEUS_MULTIPROC_DIR"] == "/opt/airflow/metrics_multiproc"
        assert "metrics_multiproc:/opt/airflow/metrics_multiproc" in airflow["volumes"]
        assert not any(p.endswith(":8001") for p in airflow.get("ports", [])), "tasks no longer serve metrics"
        metrics = compose["services"]["metrics"]
        assert metrics["command"] == ["python", "-m", "src.metrics_exporter"]
        assert "127.0.0.1:8001:8001" in metrics["ports"]
        assert "metrics_multiproc:/opt/airflow/metrics_multiproc" in metrics["volumes"]
        assert metrics["environment"]["PROMETHEUS_MULTIPROC_DIR"] == "/opt/airflow/metrics_multiproc"
        assert "metrics_multiproc" in compose["volumes"]

    def test_exporter_refuses_to_run_without_the_directory(self, monkeypatch):
        monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)
        assert metrics_exporter.main() == 2
