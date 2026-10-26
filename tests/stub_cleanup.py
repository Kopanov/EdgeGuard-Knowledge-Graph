"""
Helpers that keep test modules from seeing the module stand-ins of other test modules.

``tests/test_graphql_api.py`` imports ``graphql_api`` against MagicMock stand-ins for ``neo4j_client``,
``neo4j``, ``pymisp``, ``airflow.*`` and ``opentelemetry.*``; sys_modules_restored() takes them out again
after that file's tests. clear_graphql_api_magicmock_stubs() removes MagicMock entries for neo4j / PyMISP
at module import time in a test file that needs the real drivers.

drop_modules_for_test() removes modules for one test so that the test imports them anew,
and puts ``sys.modules`` back as it was afterwards.

dag_module_import() wraps the import of a DAG file: it skips the test only where Airflow is not installed.
"""

from __future__ import annotations

import importlib.machinery
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock

import pytest

# Modules that must be re-imported after stubs are removed (may have cached bad imports).
_REIMPORT_AFTER_CLEAR = (
    "alert_processor",
    "neo4j_client",
    "run_pipeline",
    "run_misp_to_neo4j",
)

_ROOT = Path(__file__).resolve().parent.parent
_PROJECT_DIRS = (_ROOT / "src", _ROOT / "dags")


def clear_graphql_api_magicmock_stubs() -> None:
    keys = [
        k for k in list(sys.modules.keys()) if k == "neo4j_client" or k.startswith("neo4j") or k.startswith("pymisp")
    ]
    removed = False
    for key in keys:
        mod = sys.modules.get(key)
        if isinstance(mod, MagicMock):
            del sys.modules[key]
            removed = True
    # Only after a stub was removed: dropping the real modules would leave later test modules with a
    # second copy, while the ones collected earlier patch the first.
    if removed:
        for name in _REIMPORT_AFTER_CLEAR:
            sys.modules.pop(name, None)


def drop_modules_for_test(monkeypatch, *names: str) -> None:
    """Remove *names* from ``sys.modules`` for the current test, so that the test imports them anew.

    After the test ``sys.modules`` holds what it held before: the original module, or no entry when
    none was loaded (the copy the test imported is then removed too). A copy left behind is what later
    code that imports the module at call time gets, while test files that imported it at collection
    patch the original, so those tests depended on the file order (2026-10-25).
    """
    for name in names:
        # Recording the entry first (``None`` when absent) makes monkeypatch remove a module the test
        # imports where none was loaded before; the delitem then restores an original one.
        monkeypatch.setitem(sys.modules, name, sys.modules.get(name))
        monkeypatch.delitem(sys.modules, name)


def _is_project_module(module: object) -> bool:
    origin = getattr(module, "__file__", None)
    if not origin:
        return False
    path = Path(origin).resolve()
    return any(path.is_relative_to(d) for d in _PROJECT_DIRS)


@contextmanager
def sys_modules_restored() -> Iterator[None]:
    """Put ``sys.modules`` back as it was before the block when the block ends.

    An entry the block replaced or removed gets its module back. An entry the block added is removed
    when it is a MagicMock stand-in or a project module (``src/``, ``dags/``): a project module imported
    in the block may hold the stand-ins. Third-party modules imported in the block stay loaded, since
    some of them (extension modules) cannot be imported a second time.
    """
    before = dict(sys.modules)
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n not in before]:
            module = sys.modules[name]
            if isinstance(module, MagicMock) or _is_project_module(module):
                del sys.modules[name]
        for name, module in before.items():
            if sys.modules.get(name) is not module:
                sys.modules[name] = module


def drop_airflow_magicmock_stubs() -> None:
    """Remove MagicMock entries for ``airflow`` / ``opentelemetry`` and their submodules from ``sys.modules``.

    Only Airflow itself: sibling modules such as ``airflow_client`` are patched by object identity in
    other test modules and stay. Airflow's ``settings.py`` imports ``opentelemetry.sdk.resources``, so a
    stand-in ``opentelemetry.sdk`` breaks the import of the real Airflow ("not a package").
    """
    for name in list(sys.modules):
        if name in ("airflow", "opentelemetry") or name.startswith(("airflow.", "opentelemetry.")):
            if isinstance(sys.modules[name], MagicMock):
                del sys.modules[name]


def airflow_installed() -> bool:
    """Whether Airflow can be imported from ``sys.path``, whatever ``sys.modules`` holds.

    ``importlib.util.find_spec`` reads ``sys.modules`` first and raises ``ValueError`` for a MagicMock
    entry, which has no ``__spec__``.
    """
    return importlib.machinery.PathFinder.find_spec("airflow") is not None


@contextmanager
def dag_module_import() -> Iterator[None]:
    """Import a DAG file in the block against the real Airflow.

    MagicMock entries for ``airflow.*`` / ``opentelemetry.*`` are removed first. An error in the block
    skips the test only where Airflow is not installed; with Airflow installed it is raised, so a DAG
    test cannot turn into a skip because of what another test module left in ``sys.modules``.
    """
    drop_airflow_magicmock_stubs()
    try:
        yield
    except Exception as e:
        if airflow_installed():
            raise
        pytest.skip(f"DAG module not importable without Airflow: {e}")
