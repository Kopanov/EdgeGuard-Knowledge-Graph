"""``drop_modules_for_test`` puts ``sys.modules`` back as the test found it (2026-10-25).

The suite's own runs only reach the helper with the module already loaded, so these tests use a module
written for the test: one loaded before the test, and one that was not.
"""

from __future__ import annotations

import importlib
import sys
import uuid

import pytest
from stub_cleanup import drop_modules_for_test


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
