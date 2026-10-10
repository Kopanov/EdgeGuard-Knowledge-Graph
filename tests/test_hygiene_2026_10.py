"""Pins for the 2026-10 hygiene PR: nothing hidden, nothing stale.

* ``conftest.py`` has no ``collect_ignore`` — every ``tests/test_*.py`` is collected, so a test
  that fails is seen (three files were ignored for months; two were dead and deleted, one was
  repaired and un-ignored).
* The DAG imports ``TriggerRule`` from ``airflow.task.trigger_rule`` and the Airflow exceptions
  from ``airflow.sdk.exceptions`` (Airflow 3.3) with ``ImportError`` fallbacks to the old paths
  (2.x / 3.2) — no ``DeprecatedImportWarning`` on DAG parse.
* ``Dockerfile.airflow`` no longer carries the GitPython override — the 3.3.2 base ships
  ``GitPython==3.1.62`` (airflow-core pins it exactly), so the line was a no-op.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_no_test_file_is_hidden_from_collection():
    conftest = (_ROOT / "tests" / "conftest.py").read_text()
    assert "collect_ignore" not in conftest
    for dead in ("test_otx_collector.py", "test_enrichment.py"):
        assert not (_ROOT / "tests" / dead).exists(), f"{dead} was dead code behind collect_ignore"
    assert (_ROOT / "tests" / "test_resilmesh_schema.py").exists(), "the salvaged contract tests stay"


def test_dag_imports_trigger_rule_from_the_3_3_path_with_fallback():
    src = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
    new = src.index("from airflow.task.trigger_rule import TriggerRule")
    old = src.index("from airflow.utils.trigger_rule import TriggerRule")
    assert new < old, "new path first, old path only in the ImportError fallback"
    assert "except ImportError" in src[new:old]


def test_dag_imports_exceptions_from_the_task_sdk_with_fallback():
    src = (_ROOT / "dags" / "edgeguard_pipeline.py").read_text()
    new = src.index("from airflow.sdk.exceptions import AirflowException, AirflowSkipException")
    old = src.index("from airflow.exceptions import AirflowException, AirflowSkipException")
    assert new < old and "except ImportError" in src[new:old]


def test_dockerfile_has_no_redundant_gitpython_override():
    df = (_ROOT / "Dockerfile.airflow").read_text()
    assert "GitPython" not in df
    assert "FROM apache/airflow:3.3.2-python3.12" in df
