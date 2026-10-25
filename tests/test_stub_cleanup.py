"""Tests for the ``sys.modules`` helpers in ``tests/stub_cleanup.py``."""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest
import stub_cleanup
from stub_cleanup import dag_module_import, sys_modules_restored


def test_sys_modules_restored_puts_back_what_the_block_replaced_removed_or_added(monkeypatch):
    kept = types.ModuleType("eg_stub_cleanup_kept")
    removed = types.ModuleType("eg_stub_cleanup_removed")
    monkeypatch.setitem(sys.modules, "eg_stub_cleanup_kept", kept)
    monkeypatch.setitem(sys.modules, "eg_stub_cleanup_removed", removed)
    monkeypatch.delitem(sys.modules, "eg_stub_cleanup_added", raising=False)

    with sys_modules_restored():
        sys.modules["eg_stub_cleanup_kept"] = MagicMock()
        del sys.modules["eg_stub_cleanup_removed"]
        sys.modules["eg_stub_cleanup_added"] = MagicMock()

    assert sys.modules["eg_stub_cleanup_kept"] is kept
    assert sys.modules["eg_stub_cleanup_removed"] is removed
    assert "eg_stub_cleanup_added" not in sys.modules


def test_sys_modules_restored_removes_a_project_module_imported_in_the_block(monkeypatch):
    """A project module imported in the block may hold the stand-ins: it is removed afterwards, so the next
    import loads it anew. A third-party module imported in the block stays loaded."""
    monkeypatch.delitem(sys.modules, "package_meta", raising=False)
    monkeypatch.delitem(sys.modules, "colorsys", raising=False)

    with sys_modules_restored():
        importlib.import_module("package_meta")
        importlib.import_module("colorsys")

    assert "package_meta" not in sys.modules
    assert "colorsys" in sys.modules


def test_dag_module_import_drops_only_airflow_and_opentelemetry_stand_ins(monkeypatch):
    for name in ("airflow.eg_stub_cleanup", "opentelemetry.eg_stub_cleanup", "airflow_eg_stub_cleanup"):
        monkeypatch.setitem(sys.modules, name, MagicMock())

    with dag_module_import():
        pass

    assert "airflow.eg_stub_cleanup" not in sys.modules
    assert "opentelemetry.eg_stub_cleanup" not in sys.modules
    # A sibling module such as ``airflow_client`` is not Airflow.
    assert isinstance(sys.modules["airflow_eg_stub_cleanup"], MagicMock)


def test_dag_module_import_raises_an_import_error_where_airflow_is_installed(monkeypatch):
    monkeypatch.setattr(stub_cleanup, "airflow_installed", lambda: True)
    with pytest.raises(ImportError, match="half-loaded"):
        try:
            with dag_module_import():
                raise ImportError("half-loaded airflow")
        except pytest.skip.Exception:
            # A skip is not an exception pytest.raises catches: without this the test would skip, not fail.
            pytest.fail("dag_module_import skipped although Airflow is installed")


def test_dag_module_import_skips_where_airflow_is_not_installed(monkeypatch):
    monkeypatch.setattr(stub_cleanup, "airflow_installed", lambda: False)
    with pytest.raises(pytest.skip.Exception, match="not importable without Airflow"):
        with dag_module_import():
            raise ImportError("No module named 'airflow'")


def test_airflow_installed_ignores_a_stand_in_in_sys_modules(monkeypatch):
    """``importlib.util.find_spec`` raises ``ValueError`` for a MagicMock entry; the check looks at ``sys.path``."""
    expected = stub_cleanup.airflow_installed()
    monkeypatch.setitem(sys.modules, "airflow", MagicMock())
    assert stub_cleanup.airflow_installed() is expected
