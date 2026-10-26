"""Tests for the ``sys.modules`` helpers in ``tests/stub_cleanup.py``.

``drop_modules_for_test`` puts ``sys.modules`` back as the test found it (2026-10-25). Its tests use a module
written for the test: one loaded before the test, and one that was not.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import sys
import types
import uuid
from unittest.mock import MagicMock

import pytest
import stub_cleanup
from stub_cleanup import dag_module_import, drop_modules_for_test, sys_modules_restored


@pytest.fixture
def module_name(tmp_path, monkeypatch):
    name = f"_stub_cleanup_probe_{uuid.uuid4().hex}"
    (tmp_path / f"{name}.py").write_text("LOADED = object()\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    yield name
    sys.modules.pop(name, None)


def test_a_loaded_module_is_imported_anew_and_the_original_comes_back(module_name):
    original = importlib.import_module(module_name)
    with pytest.MonkeyPatch.context() as mp:
        drop_modules_for_test(mp, module_name)
        assert module_name not in sys.modules
        fresh = importlib.import_module(module_name)
        assert fresh is not original and fresh.LOADED is not original.LOADED
    assert sys.modules[module_name] is original


def test_a_module_not_loaded_before_is_removed_with_the_copy_the_test_imported(module_name):
    assert module_name not in sys.modules
    with pytest.MonkeyPatch.context() as mp:
        drop_modules_for_test(mp, module_name)
        importlib.import_module(module_name)
        assert module_name in sys.modules
    assert module_name not in sys.modules, "the test's copy must not stay behind for later importers"


def test_a_name_passed_twice_still_restores_the_original(module_name):
    original = importlib.import_module(module_name)
    with pytest.MonkeyPatch.context() as mp:
        drop_modules_for_test(mp, module_name)
        importlib.import_module(module_name)
        drop_modules_for_test(mp, module_name)
        importlib.import_module(module_name)
    assert sys.modules[module_name] is original


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


def test_sys_modules_restored_puts_back_the_same_when_the_block_raises(monkeypatch):
    """A failing import inside the ``test_graphql_api`` fixture must not leave its stand-ins behind."""
    kept = types.ModuleType("eg_stub_cleanup_kept")
    removed = types.ModuleType("eg_stub_cleanup_removed")
    monkeypatch.setitem(sys.modules, "eg_stub_cleanup_kept", kept)
    monkeypatch.setitem(sys.modules, "eg_stub_cleanup_removed", removed)
    monkeypatch.delitem(sys.modules, "eg_stub_cleanup_added", raising=False)

    with pytest.raises(RuntimeError, match="the block failed"):
        with sys_modules_restored():
            sys.modules["eg_stub_cleanup_kept"] = MagicMock()
            del sys.modules["eg_stub_cleanup_removed"]
            sys.modules["eg_stub_cleanup_added"] = MagicMock()
            raise RuntimeError("the block failed")

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


def test_airflow_installed_is_false_without_airflow_on_the_path(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "path", [str(tmp_path)])
    assert stub_cleanup.airflow_installed() is False


def test_airflow_installed_is_true_where_airflow_is_installed():
    """CI installs Airflow: a check that answered False there would turn every DAG import error into a skip."""
    try:
        importlib.metadata.distribution("apache-airflow")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("apache-airflow is not installed")
    assert stub_cleanup.airflow_installed() is True
