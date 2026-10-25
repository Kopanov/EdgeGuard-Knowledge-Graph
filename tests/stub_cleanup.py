"""
Remove MagicMock entries that test_graphql_api.py injects into sys.modules.

Those stubs allow GraphQL tests to import without neo4j/pymisp, but they break
integration tests that need the real drivers. Call clear_graphql_api_magicmock_stubs()
at module import time in any test file that needs real Neo4j / PyMISP.

drop_modules_for_test() removes modules for one test so that the test imports them anew,
and puts ``sys.modules`` back as it was afterwards.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

# Modules that must be re-imported after stubs are removed (may have cached bad imports).
_REIMPORT_AFTER_CLEAR = (
    "alert_processor",
    "neo4j_client",
    "run_pipeline",
    "run_misp_to_neo4j",
)


def clear_graphql_api_magicmock_stubs() -> None:
    keys = [
        k for k in list(sys.modules.keys()) if k == "neo4j_client" or k.startswith("neo4j") or k.startswith("pymisp")
    ]
    for key in keys:
        mod = sys.modules.get(key)
        if isinstance(mod, MagicMock):
            del sys.modules[key]
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
