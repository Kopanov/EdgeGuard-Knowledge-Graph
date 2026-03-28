"""
Regression tests for baseline vs incremental collection limits.

Verifies resolve_collection_limit() and baseline env helper without live APIs.
"""

from unittest.mock import MagicMock, patch


def test_resolve_explicit_limit_unchanged():
    import config

    assert config.resolve_collection_limit(42, "otx", baseline=False) == 42
    assert config.resolve_collection_limit(42, "otx", baseline=True) == 42


def test_resolve_baseline_none_does_not_call_incremental_default():
    import config

    with patch.object(config, "get_effective_limit", side_effect=AssertionError("should not run")):
        assert config.resolve_collection_limit(None, "otx", baseline=True) is None


def test_resolve_incremental_none_uses_get_effective_limit():
    import config

    with patch.object(config, "get_effective_limit", return_value=200) as m:
        assert config.resolve_collection_limit(None, "otx", baseline=False) == 200
        m.assert_called_once_with("otx")


def test_baseline_collection_limit_from_env(monkeypatch):
    """Reads os.environ each call — no config reload required."""
    from config import baseline_collection_limit_from_env

    monkeypatch.delenv("BASELINE_COLLECTION_LIMIT", raising=False)
    assert baseline_collection_limit_from_env() is None

    monkeypatch.setenv("BASELINE_COLLECTION_LIMIT", "0")
    assert baseline_collection_limit_from_env() is None

    monkeypatch.setenv("BASELINE_COLLECTION_LIMIT", "-1")
    assert baseline_collection_limit_from_env() is None

    monkeypatch.setenv("BASELINE_COLLECTION_LIMIT", "750")
    assert baseline_collection_limit_from_env() == 750


def test_otx_fetch_pulses_default_page_limit_when_collect_limit_none():
    """Baseline unlimited (limit=None): OTX API still gets a bounded per-page size (50)."""
    import collectors.otx_collector as mod

    class DummySession:
        def __init__(self):
            self.last_params = None

        def request(self, method, url, params=None, timeout=None, verify=None, **kw):
            self.last_params = params

            class R:
                status_code = 200

                def json(self):
                    return {"results": []}

            return R()

    c = mod.OTXCollector()
    c.session = DummySession()
    c._fetch_pulses(limit=None, modified_since=None, page=1)
    assert c.session.last_params.get("limit") == 50


def test_vt_collect_uncapped_maps_to_safe_integer():
    """VT math must not receive None after resolve (rate / batch sizing)."""
    from collectors.vt_collector import VTCollector

    vt = VTCollector(misp_writer=MagicMock())
    vt.api_key = None  # optional source: no API calls; empty list when not pushing to MISP
    out = vt.collect(limit=None, push_to_misp=False, baseline=True)
    assert out == []
