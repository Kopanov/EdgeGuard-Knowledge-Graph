"""Fresh-baseline path: the sync state after the baseline, Airflow 3 Variables, MISP delete timeouts (2026-10)."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from stub_cleanup import dag_module_import

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
_SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "scripts")
for _p in (_DAGS, _SRC, _SCRIPTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-readiness")
os.environ.setdefault("MISP_API_KEY", "test-key-readiness")


def _dag():
    for key in list(sys.modules):
        if key in ("edgeguard_pipeline", "airflow", "opentelemetry") or key.startswith(("airflow.", "opentelemetry.")):
            del sys.modules[key]
    import importlib

    with dag_module_import():
        return importlib.import_module("edgeguard_pipeline")


class _TaskSdkVariable:
    """Airflow 3 Task SDK signature: the default is ``default``; ``default_var`` raises TypeError."""

    values = {"BASELINE_DAYS": "14"}

    @classmethod
    def get(cls, key, default=None, **kwargs):
        if kwargs:
            raise TypeError(f"Variable.get() got an unexpected keyword argument {next(iter(kwargs))!r}")
        return cls.values.get(key, default)


def test_baseline_variables_are_read_on_airflow_3(monkeypatch):
    ep = _dag()
    monkeypatch.delenv("EDGEGUARD_BASELINE_DAYS", raising=False)
    monkeypatch.delenv("EDGEGUARD_BASELINE_COLLECTION_LIMIT", raising=False)
    with patch.object(ep, "Variable", _TaskSdkVariable):
        _limit, days = ep.get_baseline_config(context={"dag_run": MagicMock(conf={})})
    assert days == 14, "the BASELINE_DAYS Variable applies when neither conf nor env sets the window"


def test_the_baseline_full_sync_stamps_the_sync_state(monkeypatch, tmp_path):
    ep = _dag()
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path))
    ti = MagicMock(spec=["xcom_pull"])
    ti.xcom_pull.return_value = {"started": True}
    sync = MagicMock()
    sync.run.return_value = True
    before = datetime.now(timezone.utc)
    with patch("run_misp_to_neo4j.MISPToNeo4jSync", return_value=sync):
        ep.run_baseline_full_sync(ti=ti)
    stamp = json.loads((tmp_path / "edgeguard_last_neo4j_sync.json").read_text())["last_sync"]
    assert before <= datetime.fromisoformat(stamp) <= datetime.now(timezone.utc), "the start time of the full sync"
    sync.run.assert_called_once_with(incremental=False)


def test_a_failed_baseline_sync_leaves_the_state_alone(monkeypatch, tmp_path):
    ep = _dag()
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path))
    ti = MagicMock(spec=["xcom_pull"])
    ti.xcom_pull.return_value = {"started": True}
    sync = MagicMock()
    sync.run.return_value = False
    with patch("run_misp_to_neo4j.MISPToNeo4jSync", return_value=sync), pytest.raises(ep.AirflowException):
        ep.run_baseline_full_sync(ti=ti)
    assert not (tmp_path / "edgeguard_last_neo4j_sync.json").exists()


def test_the_clear_misp_script_waits_for_a_large_event_delete(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_MISP_DELETE_TIMEOUT_SEC", "777")
    import clear_misp

    cleaner = clear_misp.MISPClearer.__new__(clear_misp.MISPClearer)
    cleaner.url = "https://misp.local"
    cleaner.verify_ssl = False
    cleaner.session = MagicMock()
    cleaner.session.delete.return_value = MagicMock(status_code=200)
    assert cleaner.delete_event("42") is True
    assert cleaner.session.delete.call_args.kwargs["timeout"] == (15, 777)
