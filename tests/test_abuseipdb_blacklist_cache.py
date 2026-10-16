"""AbuseIPDB blacklist: 429 quota exhaustion fails loudly; fetched blacklist is cached across retries."""

import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

from collectors.abuseipdb_collector import AbuseIPDBCollector

API = {"data": [{"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100, "countryCode": "US"}]}


def _resp(status, body=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    r.text = ""
    return r


@pytest.fixture
def col(tmp_path, monkeypatch):
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path))
    monkeypatch.delenv("EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS", raising=False)
    c = AbuseIPDBCollector(api_key="k" * 40, misp_writer=MagicMock())
    c.misp_writer.push_indicators.return_value = (1, 0)
    c.MIN_INTERVAL_SECONDS = 0
    return c


def _patch(*responses):
    return patch("collectors.abuseipdb_collector.request_with_rate_limit_retries", side_effect=list(responses))


def test_429_reports_failure(col):
    with _patch(_resp(429)):
        status = col.collect(baseline=True)
    assert status["success"] is False
    assert "429" in status["error"]
    col.misp_writer.push_indicators.assert_not_called()


def test_success_writes_cache(col, tmp_path):
    with _patch(_resp(200, API)):
        status = col.collect(baseline=True)
    assert status["success"] is True and status["count"] == 1
    cached = json.loads((tmp_path / "abuseipdb_blacklist_cache.json").read_text())
    assert cached["response"] == API
    assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []


def test_retry_uses_cache_without_http_call(col):
    with _patch(_resp(200, API)):
        col.collect(baseline=True)
    with _patch() as req:
        status = col.collect(baseline=True)
    req.assert_not_called()
    assert status["success"] is True and status["count"] == 1


def test_cache_hit_survives_quota_exhaustion_on_retry(col):
    with _patch(_resp(200, API)):
        col.collect(baseline=True)
    with _patch(_resp(429)) as req:
        assert col.collect(baseline=True)["success"] is True
    req.assert_not_called()


def test_different_params_not_served_from_cache(col):
    with _patch(_resp(200, API)):
        col.collect(baseline=True, confidence_minimum=90)
    with _patch(_resp(200, API)) as req:
        col.collect(baseline=True, confidence_minimum=75)
    assert req.call_count == 1


def test_stale_cache_calls_api(col, tmp_path):
    with _patch(_resp(200, API)):
        col.collect(baseline=True)
    path = tmp_path / "abuseipdb_blacklist_cache.json"
    cached = json.loads(path.read_text())
    cached["fetched_at"] = time.time() - 21 * 3600
    path.write_text(json.dumps(cached))
    with _patch(_resp(200, API)) as req:
        col.collect(baseline=True)
    assert req.call_count == 1


def test_cache_disabled_with_zero(col, tmp_path, monkeypatch):
    monkeypatch.setenv("EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS", "0")
    with _patch(_resp(200, API), _resp(200, API)) as req:
        col.collect(baseline=True)
        col.collect(baseline=True)
    assert req.call_count == 2
    assert not (tmp_path / "abuseipdb_blacklist_cache.json").exists()


def test_unwritable_state_dir_still_collects(col, tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(blocker / "sub"))
    with _patch(_resp(200, API)):
        status = col.collect(baseline=True)
    assert status["success"] is True and status["count"] == 1
