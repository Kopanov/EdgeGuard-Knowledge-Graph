"""
Audit MAX_ENTRIES / EDGEGUARD_MAX_ENTRIES semantics across config and MISP-SPT runner.

Regression: `limit or MAX_ENTRIES_PER_SOURCE` must never be used — when MAX is 0,
`None or 0` became 0 and capped every collect at zero items.
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def stub_run_misp_to_neo4j():
    """Avoid importing neo4j_client via run_misp_to_neo4j when loading run_pipeline_misp_spt."""
    name = "run_misp_to_neo4j"
    fake = types.ModuleType(name)
    fake.MISPToNeo4jSync = MagicMock()
    sys.modules[name] = fake
    yield
    sys.modules.pop(name, None)


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


def test_misp_spt_passes_none_when_global_max_zero(
    monkeypatch: pytest.MonkeyPatch,
    stub_run_misp_to_neo4j,
) -> None:
    """Phase1 must not coerce (None, MAX=0) → limit=0."""
    _reload_config(monkeypatch, EDGEGUARD_MAX_ENTRIES="0", EDGEGUARD_INCREMENTAL_LIMIT="200")
    import run_pipeline_misp_spt as spt

    importlib.reload(spt)

    captured: dict = {}

    def fake_collect(self, limit=None, push_to_misp=True, **kwargs):
        captured["limit"] = limit
        return {"success": True, "count": 0}

    pipeline = spt.EdgeGuardPipelineMISPSPT()
    with patch.object(spt.OTXCollector, "collect", fake_collect):
        pipeline.run_phase1_collect_to_misp(sources=["otx"], limit=None)

    assert captured.get("limit") is None


def test_misp_spt_passes_explicit_global_when_set(
    monkeypatch: pytest.MonkeyPatch,
    stub_run_misp_to_neo4j,
) -> None:
    _reload_config(monkeypatch, EDGEGUARD_MAX_ENTRIES="444", EDGEGUARD_INCREMENTAL_LIMIT="200")
    import run_pipeline_misp_spt as spt

    importlib.reload(spt)

    captured: dict = {}

    def fake_collect(self, limit=None, push_to_misp=True, **kwargs):
        captured["limit"] = limit
        return {"success": True, "count": 0}

    pipeline = spt.EdgeGuardPipelineMISPSPT()
    with patch.object(spt.OTXCollector, "collect", fake_collect):
        pipeline.run_phase1_collect_to_misp(sources=["otx"], limit=None)

    assert captured.get("limit") == 444


def test_misp_spt_explicit_zero_preserved(
    monkeypatch: pytest.MonkeyPatch,
    stub_run_misp_to_neo4j,
) -> None:
    """Caller limit=0 must stay 0, not replaced by MAX_ENTRIES."""
    _reload_config(monkeypatch, EDGEGUARD_MAX_ENTRIES="500", EDGEGUARD_INCREMENTAL_LIMIT="200")
    import run_pipeline_misp_spt as spt

    importlib.reload(spt)

    captured: dict = {}

    def fake_collect(self, limit=None, push_to_misp=True, **kwargs):
        captured["limit"] = limit
        return {"success": True, "count": 0}

    pipeline = spt.EdgeGuardPipelineMISPSPT()
    with patch.object(spt.OTXCollector, "collect", fake_collect):
        pipeline.run_phase1_collect_to_misp(sources=["otx"], limit=0)

    assert captured.get("limit") == 0
