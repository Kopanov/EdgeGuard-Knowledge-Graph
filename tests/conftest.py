"""
Pytest configuration — adds src/ to sys.path so tests can import project modules
without needing an installed package.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set before any test module imports `collectors.*` (config.py requires these at import).
if not os.getenv("NEO4J_PASSWORD"):
    os.environ["NEO4J_PASSWORD"] = "pytest-dummy-neo4j-password"
if not os.getenv("MISP_API_KEY"):
    os.environ["MISP_API_KEY"] = "pytest-dummy-misp-key"

# ``graphql_api`` and ``query_api`` raise at import time when ``EDGEGUARD_ENV`` is unset
# (secure default: unset/unknown = prod) and no ``EDGEGUARD_API_KEY`` is configured. The
# suite only passed because ``tests/test_graphql_api.py`` and
# ``tests/test_ioc_normalize_and_actor_summary.py`` run the same ``setdefault`` at module
# level and pytest imports every module during collection before the first test runs —
# so five files (``test_auth_and_api_hardening``, ``test_pr33_bugbot_fixes``,
# ``test_pr_n3_api_key_timing_attack``, ``test_query_api``, ``test_round26_invariants``)
# failed whenever run on their own (found 2026-10-10). Make the suite's implicit default
# explicit here; tests that exercise prod semantics set and restore the variable themselves.
os.environ.setdefault("EDGEGUARD_ENV", "dev")


@pytest.fixture(autouse=True)
def _edgeguard_required_env(monkeypatch):
    """Re-apply if a test clears env vars."""
    if not os.getenv("NEO4J_PASSWORD"):
        monkeypatch.setenv("NEO4J_PASSWORD", "pytest-dummy-neo4j-password")
    if not os.getenv("MISP_API_KEY"):
        monkeypatch.setenv("MISP_API_KEY", "pytest-dummy-misp-key")


@pytest.fixture(autouse=True)
def _reset_source_trust_env(monkeypatch):
    """PR #44 audit M4 (Bug Hunter / Maintainer Dev): reset
    ``source_trust`` module-level allowlists after every test so a
    test that monkeypatches the env vars + calls ``_reload_env``
    doesn't leak state into the next test.

    Tests that don't import ``source_trust`` pay nothing —
    ``sys.modules.get(...)`` returns None and the fixture short-circuits.
    """
    yield
    src_mod = sys.modules.get("source_trust")
    if src_mod is None:
        return
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_UUIDS", raising=False)
    monkeypatch.delenv("EDGEGUARD_TRUSTED_MISP_ORG_NAMES", raising=False)
    if hasattr(src_mod, "_reload_env"):
        src_mod._reload_env()
