"""
Audit MAX_ENTRIES / EDGEGUARD_MAX_ENTRIES semantics in config.

Regression: `limit or MAX_ENTRIES_PER_SOURCE` must never be used — when MAX is 0,
`None or 0` became 0 and capped every collect at zero items.
"""

from __future__ import annotations

import importlib

import pytest


def _reload_config(monkeypatch: pytest.MonkeyPatch, **env: str) -> None:
    monkeypatch.setenv("NEO4J_PASSWORD", "audit-neo4j-pass")
    monkeypatch.setenv("MISP_API_KEY", "x" * 42)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    import config

    importlib.reload(config)


def test_config_has_no_enable_max_entries_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stale boolean removed — use MAX_ENTRIES_PER_SOURCE=0 for 'no global override'."""
    _reload_config(monkeypatch)
    import config

    assert not hasattr(config, "ENABLE_MAX_ENTRIES_LIMIT")
    assert hasattr(config, "MAX_ENTRIES_PER_SOURCE")


def test_get_effective_limit_max_zero_uses_incremental(monkeypatch: pytest.MonkeyPatch) -> None:
    """EDGEGUARD_MAX_ENTRIES=0 does not block incremental default."""
    _reload_config(
        monkeypatch,
        EDGEGUARD_MAX_ENTRIES="0",
        EDGEGUARD_INCREMENTAL_LIMIT="203",
    )
    import config

    importlib.reload(config)
    assert config.get_effective_limit("otx") == 203


def test_get_effective_limit_max_nonzero_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    _reload_config(
        monkeypatch,
        EDGEGUARD_MAX_ENTRIES="777",
        EDGEGUARD_INCREMENTAL_LIMIT="200",
    )
    import config

    importlib.reload(config)
    assert config.get_effective_limit("nvd") == 777


def test_get_effective_limit_negative_override_is_not_a_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """``EDGEGUARD_MAX_ENTRIES=-1`` used to be handed to collectors as a limit (``items[:-1]``)."""
    _reload_config(
        monkeypatch,
        EDGEGUARD_MAX_ENTRIES="-1",
        EDGEGUARD_INCREMENTAL_LIMIT="200",
    )
    import config

    importlib.reload(config)
    # otx: a source under the generic incremental limit (NVD applies its own per-run cap, 2026-10)
    assert config.get_effective_limit("otx") == 200
