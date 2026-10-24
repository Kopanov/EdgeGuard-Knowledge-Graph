"""URLhaus (abuse.ch) v2 export (2026-10) — the Auth-Key sits in the URL path.

No network. Covers: URL construction with the key in the path (one URL, no ``csv_top10k``
mirror), no usable key → skipped status without a request, HTTP 401/403 → skipped, and the key
never reaching logs, exception text or the returned error for a failing download.
"""

from __future__ import annotations

import os
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import collectors.global_feed_collector as gfc  # noqa: E402

KEY = "k3yAbCdEf0123456789SECRETvalue"  # fake abuse.ch Auth-Key; must never show up in logs or errors
EXPORT_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{KEY}/recent.csv"
REDACTED_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/<redacted>/recent.csv"
ROW = (
    '"3650001","2026-10-15 07:01:04","http://203.0.113.1:40001/i","online","2026-10-15 07:01:04",'
    '"malware_download","elf,Mozi","https://urlhaus.abuse.ch/url/3650001/","geenensp"\n'
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(gfc.URLHAUS_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr("collectors.collector_utils.time.sleep", lambda _s: None)
    for name in ("can_execute",):
        monkeypatch.setattr(gfc.URLHAUS_CIRCUIT_BREAKER, name, lambda: True)
    monkeypatch.setattr(gfc.URLHAUS_CIRCUIT_BREAKER, "record_success", lambda: None)
    monkeypatch.setattr(gfc.URLHAUS_CIRCUIT_BREAKER, "record_failure", lambda: None)


def _collector(api_key: str = KEY) -> gfc.URLhausCollector:
    return gfc.URLhausCollector(api_key=api_key, misp_writer=MagicMock())


def _response(code: int, text: str = "x") -> requests.Response:
    r = requests.Response()
    r.status_code = code
    r.url = EXPORT_URL
    r._content = text.encode()
    r.reason = "Gone" if code == 410 else "Error"
    return r


def _said(caplog, *extra: Any) -> str:
    return "\n".join([r.getMessage() for r in caplog.records] + [str(e) for e in extra])


def test_one_export_url_with_the_key_in_the_path_and_a_read_timeout_for_16_mb(monkeypatch):
    calls = []

    def fake(method, url, **kw):
        calls.append({"method": method, "url": url, **kw})
        return _response(200, "# header\n" + ROW)

    monkeypatch.setattr(gfc, "request_with_rate_limit_retries", fake)
    c = _collector(f"  {KEY}  ")
    assert c.urls == [EXPORT_URL], "csv_top10k has no v2 equivalent and is dropped"
    out = c.collect(push_to_misp=False)
    assert [r["value"] for r in out] == ["http://203.0.113.1:40001/i"]
    assert len(calls) == 1
    assert calls[0]["url"] == EXPORT_URL and calls[0]["log_url"] == REDACTED_URL
    assert "headers" not in calls[0] and calls[0]["timeout"] == (15, 120)


@pytest.mark.parametrize("api_key", ["", "   ", "demo", "YOUR_THREATFOX_API_KEY_HERE"])
def test_no_usable_key_is_skipped_without_a_request(monkeypatch, caplog, api_key):
    monkeypatch.setattr(gfc, "request_with_rate_limit_retries", lambda *a, **kw: pytest.fail("no request"))
    c = _collector(api_key)
    assert c.urls == []
    with caplog.at_level("WARNING"):
        st = c.collect(push_to_misp=True)
    assert st["success"] is True and st["skipped"] is True and st["count"] == 0
    assert st["skip_reason_class"] == "missing_abusech_key"
    assert "https://auth.abuse.ch/" in st["skip_reason"] and "THREATFOX_API_KEY" in st["skip_reason"]
    assert any("THREATFOX_API_KEY" in r.getMessage() and "auth.abuse.ch" in r.getMessage() for r in caplog.records)
    assert c.collect(push_to_misp=False) == []
    c.misp_writer.push_indicators.assert_not_called()


def test_key_defaults_to_the_environment(monkeypatch):
    monkeypatch.setenv("THREATFOX_API_KEY", "envkey0123456789")
    assert gfc.URLhausCollector(misp_writer=MagicMock()).api_key == "envkey0123456789"


@pytest.mark.parametrize("code", [401, 403])
def test_auth_denied_is_skipped_not_failed(monkeypatch, caplog, code):
    monkeypatch.setattr("collectors.collector_utils.requests.request", lambda *a, **kw: _response(code))
    c = _collector()
    with caplog.at_level("DEBUG"):
        st = c.collect(push_to_misp=True)
    assert st["success"] is True and st["skipped"] is True
    assert st["skip_reason_class"] == "urlhaus_auth_denied"
    assert KEY not in _said(caplog, st)
    assert c.collect(push_to_misp=False) == []


@pytest.mark.parametrize("code", [404, 410, 500])
def test_failed_download_does_not_leak_the_key(monkeypatch, caplog, code):
    """Drives the real HTTP helper (only ``requests.request`` is faked)."""
    monkeypatch.setattr("collectors.collector_utils.requests.request", lambda *a, **kw: _response(code))
    c = _collector()
    with caplog.at_level("DEBUG"):
        st = c.collect(push_to_misp=True)
        with pytest.raises(RuntimeError) as ei:
            c.collect(push_to_misp=False)
    assert st["success"] is False
    assert KEY not in _said(caplog, st, ei.value)


def test_connection_error_does_not_leak_the_key(monkeypatch, caplog):
    def boom(*_a, **_kw):
        raise requests.exceptions.ConnectionError(
            f"HTTPSConnectionPool(host='urlhaus-api.abuse.ch', port=443): Max retries exceeded with url: "
            f"/v2/files/exports/{KEY}/recent.csv (Caused by NewConnectionError('refused'))"
        )

    monkeypatch.setattr("collectors.collector_utils.requests.request", boom)
    c = _collector()
    with caplog.at_level("DEBUG"):
        st = c.collect(push_to_misp=True)
    assert st["success"] is False
    assert KEY not in _said(caplog, st)
    assert any("<redacted>" in r.getMessage() for r in caplog.records)
