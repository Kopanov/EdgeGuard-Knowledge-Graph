"""
Remove MagicMock entries that test_graphql_api.py injects into sys.modules.

Those stubs allow GraphQL tests to import without neo4j/pymisp, but they break
integration tests that need the real drivers. Call clear_graphql_api_magicmock_stubs()
at module import time in any test file that needs real Neo4j / PyMISP.
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
