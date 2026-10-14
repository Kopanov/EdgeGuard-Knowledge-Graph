"""Runtime text of the queries assigned in ``src/build_relationships.py``, for source-pin tests.

Since 2026-10 (relationship provenance) the step queries are assembled from shared Cypher
fragments (``relationship_provenance.prov_with`` / ``prov_set``), so joining the string
literals of an assignment no longer reproduces the query. ``assigned_queries`` evaluates each
assignment's expression in the module namespace instead, which yields exactly the text that
runs.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import List

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def assigned_queries(name: str) -> List[str]:
    """Every value assigned to ``name`` in ``build_relationships.py``, in source order."""
    import build_relationships

    path = Path(build_relationships.__file__)
    nodes = [
        node
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
    ]
    namespace = vars(build_relationships)
    return [
        eval(compile(ast.Expression(node.value), str(path), "eval"), namespace)  # noqa: S307 — our own source
        for node in sorted(nodes, key=lambda n: n.lineno)
    ]


def assigned_query(name: str) -> str:
    """The first value assigned to ``name`` (the step-specific names are assigned once)."""
    values = assigned_queries(name)
    if not values:
        raise AssertionError(f"{name} is not assigned in build_relationships.py")
    return values[0]
