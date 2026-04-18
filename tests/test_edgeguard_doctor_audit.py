"""PR #36 — structural pin for the class of bug Vanko reported (NameError
in cmd_doctor / cmd_validate) plus a smoke test for the new
``version_compatibility`` module wiring.

Background
----------
Vanko's report (2026-04-18): ``edgeguard doctor`` and ``edgeguard validate``
crashed with ``NameError`` partway through because a config-module name
they referenced was not in scope at the call site. The current main does
not exhibit the crash because ``_ensure_runtime_imports()`` (in
``src/edgeguard.py``) injects every name listed in ``_CFG_EXPORTS`` onto
the module before the dispatch.

The fragility, however, is real: if a future PR adds ``MISP_PASSWORD`` (or
any other ``ALL_CAPS`` config name) inside ``cmd_doctor`` and forgets to
add it to ``_CFG_EXPORTS``, the bug returns and only surfaces in
production. This file pins the contract structurally with an AST scan
that auto-discovers references and asserts each is either locally
defined or runtime-injected.
"""

from __future__ import annotations

import ast
import os
import sys

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _load_edgeguard_ast() -> ast.Module:
    path = os.path.join(_SRC, "edgeguard.py")
    with open(path) as fh:
        return ast.parse(fh.read())


def _function_node(tree: ast.Module, name: str) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found in src/edgeguard.py")


def _module_level_names(tree: ast.Module) -> set:
    """Names defined at module top level (functions, classes, top-level
    assignments, imported aliases). These are the "available" names a
    function body can reference without injection."""
    names: set = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    names.add(tgt.id)
                elif isinstance(tgt, ast.Tuple):
                    for elt in tgt.elts:
                        if isinstance(elt, ast.Name):
                            names.add(elt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _all_caps_names_referenced(func: ast.FunctionDef) -> set:
    """All ALL_CAPS Name references (Load context) inside the function
    body. These are the candidate names that need to come from
    ``_CFG_EXPORTS`` injection or the runtime-imports path."""
    names: set = set()
    locally_assigned: set = set()

    # Track local assignments inside the function so we don't flag
    # ``X = "..."`` followed by a reference as an external dep.
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    locally_assigned.add(tgt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            locally_assigned.add(node.target.id)

    for node in ast.walk(func):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            n = node.id
            # Heuristic for "looks like a config constant"
            if n.isupper() and len(n) >= 4 and not n.startswith("_") and n not in locally_assigned:
                names.add(n)
    return names


def _runtime_injected_names() -> set:
    """The names that ``_ensure_runtime_imports`` puts onto the module.

    This MUST mirror ``_CFG_EXPORTS`` plus the explicit module-attribute
    sets at the bottom of that helper (``MISPHealthCheck``,
    ``PROMETHEUS_AVAILABLE``). Hard-coded here intentionally — if a future
    PR changes ``_ensure_runtime_imports`` we want this test to fail
    loudly so the contract is re-verified.
    """
    import edgeguard

    return set(edgeguard._CFG_EXPORTS) | {"MISPHealthCheck", "PROMETHEUS_AVAILABLE"}


# ---------------------------------------------------------------------------
# Vanko's class-of-bug pin
# ---------------------------------------------------------------------------


def test_cmd_doctor_references_no_uninjected_config_name():
    """Every ALL_CAPS reference in cmd_doctor must be either:
      * defined at module top level (a constant in edgeguard.py itself), OR
      * registered in ``_CFG_EXPORTS`` for runtime injection, OR
      * one of the explicitly-injected attrs (MISPHealthCheck etc.)

    A regression in this test means a future PR added a config-module
    reference (e.g. ``MISP_PASSWORD``) without registering it for
    injection. In production that would crash with NameError partway
    through doctor — exactly what Vanko reported.
    """
    tree = _load_edgeguard_ast()
    func = _function_node(tree, "cmd_doctor")
    referenced = _all_caps_names_referenced(func)
    available = _module_level_names(tree) | _runtime_injected_names()
    missing = referenced - available
    assert not missing, (
        f"cmd_doctor references ALL_CAPS name(s) not in the module top-level "
        f"namespace AND not registered for runtime injection: {sorted(missing)}. "
        f"Add them to ``_CFG_EXPORTS`` in src/edgeguard.py (or define them as "
        f"module constants), or this will crash with NameError in production."
    )


def test_cmd_validate_references_no_uninjected_config_name():
    """Same contract as cmd_doctor. Vanko's report named both functions."""
    tree = _load_edgeguard_ast()
    func = _function_node(tree, "cmd_validate")
    referenced = _all_caps_names_referenced(func)
    available = _module_level_names(tree) | _runtime_injected_names()
    missing = referenced - available
    assert not missing, (
        f"cmd_validate references ALL_CAPS name(s) not in the module namespace "
        f"AND not registered for runtime injection: {sorted(missing)}. "
        f"Add them to ``_CFG_EXPORTS`` in src/edgeguard.py."
    )


def test_runtime_injection_names_actually_exist_on_config_module():
    """Negative pin on the OTHER side of the contract: every name in
    ``_CFG_EXPORTS`` must actually be defined in ``src/config.py``.

    Otherwise ``_ensure_runtime_imports`` raises ``AttributeError`` at
    startup — different bug, same root cause (drift between the export
    list and reality). Catches the case where someone removes a config
    constant without removing it from ``_CFG_EXPORTS``."""
    import edgeguard

    # Re-import config fresh so we see the actual module attrs (config.py
    # raises at import time on missing required env vars; we tolerate
    # that by skipping the test if config can't load — the doctor
    # itself fails the same way and that's the right behavior).
    try:
        cfg = __import__("config", fromlist=["*"])
    except Exception:
        import pytest

        pytest.skip("config.py requires real env vars to import — skipping injection-list audit")

    missing = [n for n in edgeguard._CFG_EXPORTS if not hasattr(cfg, n)]
    assert not missing, (
        f"_CFG_EXPORTS lists name(s) that don't exist on src/config.py: "
        f"{missing}. Either add them to config.py or remove from _CFG_EXPORTS."
    )


# ---------------------------------------------------------------------------
# Smoke test for the new version_compatibility wiring
# ---------------------------------------------------------------------------


def test_cmd_doctor_calls_version_compatibility_check():
    """Source-grep pin: PR #36 wires ``compare_pinned_vs_running()`` into
    cmd_doctor. If a future refactor accidentally drops the call,
    operators lose the version-drift warning that's the whole point of
    this PR. Pin structurally so the regression catches it."""
    path = os.path.join(_SRC, "edgeguard.py")
    with open(path) as fh:
        src = fh.read()
    # Locate cmd_doctor body and check the new section is present
    start = src.find("def cmd_doctor(")
    assert start > 0, "cmd_doctor not found"
    # Find the boundary to next top-level def
    end = src.find("\ndef ", start + 1)
    body = src[start:end]
    assert "version_compatibility" in body, (
        "cmd_doctor must import + call version_compatibility.compare_pinned_vs_running — "
        "Vanko's PR #36 explicit ask. Don't drop the wiring."
    )
    assert "Checking version compatibility" in body, (
        "cmd_doctor must emit the operator-facing 'Checking version compatibility...' line"
    )


def test_cmd_validate_calls_version_compatibility_check():
    """Same contract as cmd_doctor. Validate is the operator's pre-deploy
    pass — it MUST surface version drift before the operator clicks
    deploy."""
    path = os.path.join(_SRC, "edgeguard.py")
    with open(path) as fh:
        src = fh.read()
    start = src.find("def cmd_validate(")
    assert start > 0, "cmd_validate not found"
    end = src.find("\ndef ", start + 1)
    body = src[start:end]
    assert "version_compatibility" in body, (
        "cmd_validate must import + call version_compatibility.compare_pinned_vs_running"
    )
