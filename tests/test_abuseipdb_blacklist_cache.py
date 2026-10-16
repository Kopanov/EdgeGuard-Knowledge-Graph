"""AbuseIPDB blacklist: 429 quota exhaustion fails loudly; fetched blacklist is cached across retries.

2026-10 follow-ups: the cache is reused only on the UTC day it was fetched (AbuseIPDB's quota day),
an empty answer is not kept, a blacklist 429 fails without the inner rate-limit backoff, the state
directory comes from the shared ``collector_utils.state_dir``, and the suite keeps the cache out of
``<repo>/state``.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from collectors import virustotal_budget
from collectors.abuseipdb_collector import AbuseIPDBCollector, _blacklist_cache_path
from collectors.collector_utils import state_dir

API = {"data": [{"ipAddress": "1.2.3.4", "abuseConfidenceScore": 100, "countryCode": "US"}]}
REPO_STATE_DIR = Path(__file__).resolve().parents[1] / "state"


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


# --------------------------------------------------------------------------- 2026-10 follow-ups


def _write_cache(tmp_path, fetched_at, params=None, response=None):
    path = tmp_path / "abuseipdb_blacklist_cache.json"
    path.write_text(
        json.dumps(
            {
                "fetched_at": fetched_at,
                "params": params or {"confidenceMinimum": 90, "limit": 10000},
                "response": API if response is None else response,
            }
        )
    )
    return path


def test_cache_file_written_here_matches_the_collector_request(col, tmp_path):
    """Control for the tests below: a file written by ``_write_cache`` with a current fetch time is
    reused, so their fresh request is caused by the fetch time alone."""
    _write_cache(tmp_path, time.time())
    with _patch() as req:
        assert col.collect(baseline=True)["count"] == 1
    req.assert_not_called()


def test_cache_from_an_earlier_utc_day_is_not_reused(col, tmp_path, monkeypatch, caplog):
    """AbuseIPDB's quota is counted per UTC day: an answer fetched before 00:00 UTC is not reused
    afterwards, even within the maximum age, because the new day's quota allows a fresh request."""
    monkeypatch.setenv("EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS", "48")
    midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    _write_cache(tmp_path, midnight.timestamp() - 60)
    with caplog.at_level(logging.INFO, logger="collectors.abuseipdb_collector"), _patch(_resp(200, API)) as req:
        assert col.collect(baseline=True)["success"] is True
    assert req.call_count == 1
    assert any("not on the current UTC quota day" in r.getMessage() for r in caplog.records)


def test_cache_with_a_fetch_time_in_the_future_is_not_reused(col, tmp_path, caplog):
    _write_cache(tmp_path, time.time() + 600)
    with caplog.at_level(logging.INFO, logger="collectors.abuseipdb_collector"), _patch(_resp(200, API)) as req:
        col.collect(baseline=True)
    assert req.call_count == 1
    assert any("requesting a fresh one" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("fetched_at", ["not-a-number", 1e300, None])
def test_cache_with_an_unreadable_fetch_time_is_not_reused(col, tmp_path, fetched_at):
    _write_cache(tmp_path, fetched_at)
    with _patch(_resp(200, API)) as req:
        assert col.collect(baseline=True)["success"] is True
    assert req.call_count == 1


def test_reuse_is_logged_with_its_age(col, caplog):
    with _patch(_resp(200, API)):
        col.collect(baseline=True)
    with caplog.at_level(logging.INFO, logger="collectors.abuseipdb_collector"), _patch() as req:
        col.collect(baseline=True)
    req.assert_not_called()
    reuse = [r.getMessage() for r in caplog.records if "reusing the blacklist fetched" in r.getMessage()]
    assert len(reuse) == 1 and "h old, same UTC quota day, max 20.0h" in reuse[0]


def test_empty_answer_is_not_cached(col, tmp_path):
    with _patch(_resp(200, {"data": []}), _resp(200, API)) as req:
        assert col.collect(baseline=True)["count"] == 0
        assert not (tmp_path / "abuseipdb_blacklist_cache.json").exists()
        assert col.collect(baseline=True)["count"] == 1
    assert req.call_count == 2, "a rerun fetches again instead of reusing the empty answer"


def test_cached_empty_list_is_not_reused(col, tmp_path):
    """A file written before 2026-10 may hold an empty answer; it is not served."""
    _write_cache(tmp_path, time.time(), response={"data": []})
    with _patch(_resp(200, API)) as req:
        assert col.collect(baseline=True)["count"] == 1
    assert req.call_count == 1


# Through the real HTTP helper: only the session's request is replaced.


def _http(status, body=None, headers=None):
    r = requests.Response()
    r.status_code = status
    r.headers.update(headers or {})
    r._content = json.dumps(body).encode() if body is not None else b""
    return r


def test_blacklist_429_fails_at_once_without_the_rate_limit_backoff(col):
    """A blacklist 429 is the spent daily quota: one request, no sleep, a failed status (red task)."""
    col.session.request = MagicMock(return_value=_http(429, headers={"Retry-After": "36000"}))
    with patch("collectors.collector_utils.time.sleep") as sleep:
        status = col.collect(baseline=True)
    assert col.session.request.call_count == 1
    sleep.assert_not_called()
    assert status["success"] is False
    assert "daily blacklist quota exhausted (429)" in status["error"]
    col.misp_writer.push_indicators.assert_not_called()


def test_blacklist_503_is_still_retried(col):
    col.session.request = MagicMock(side_effect=[_http(503), _http(200, API)])
    with patch("collectors.collector_utils.time.sleep") as sleep:
        status = col.collect(baseline=True)
    assert col.session.request.call_count == 2
    assert sleep.call_count == 1
    assert status["success"] is True and status["count"] == 1


def test_check_endpoint_keeps_the_429_backoff(col):
    """Only the blacklist request skips the backoff; ``check_ip`` (enrichment) still waits and retries."""
    col.session.request = MagicMock(return_value=_http(429))
    with patch("collectors.collector_utils.time.sleep") as sleep:
        assert col.check_ip("192.0.2.1") is None
    assert col.session.request.call_count == 4
    assert sleep.call_count == 3


# Shared state directory (``collector_utils.state_dir``).


def test_cache_and_virustotal_ledger_follow_the_shared_state_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("EDGEGUARD_VIRUSTOTAL_BUDGET_PATH", raising=False)
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path))
    assert state_dir() == str(tmp_path)
    assert _blacklist_cache_path() == os.path.join(str(tmp_path), "abuseipdb_blacklist_cache.json")
    assert virustotal_budget.ledger_path() == os.path.join(str(tmp_path), "virustotal_daily_budget.json")
    for unset in (None, ""):
        if unset is None:
            monkeypatch.delenv("EDGEGUARD_STATE_DIR")
        else:
            monkeypatch.setenv("EDGEGUARD_STATE_DIR", unset)
        assert state_dir() == str(REPO_STATE_DIR)
        assert _blacklist_cache_path() == str(REPO_STATE_DIR / "abuseipdb_blacklist_cache.json")
        assert virustotal_budget.ledger_path() == str(REPO_STATE_DIR / "virustotal_daily_budget.json")


# Suite isolation (tests/conftest.py).


def _abuseipdb_files_in_repo_state():
    if not REPO_STATE_DIR.is_dir():
        return {}
    return {
        p.name: p.stat().st_mtime_ns
        for p in REPO_STATE_DIR.iterdir()
        if p.name == "abuseipdb_blacklist_cache.json" or p.name.startswith(".abuseipdb_blacklist_")
    }


def test_suite_runs_leave_no_cache_in_the_repository_state_directory(monkeypatch):
    """Without the conftest setting, a collector run with a fake request wrote its answer to
    ``<repo>/state``; a second run within the cache window was then served from it (0 requests),
    and a local collector run with the same parameters would have pushed the test addresses."""
    assert os.environ.get("EDGEGUARD_ABUSEIPDB_BLACKLIST_CACHE_HOURS") == "0"
    monkeypatch.delenv("EDGEGUARD_STATE_DIR", raising=False)
    assert _blacklist_cache_path() == str(REPO_STATE_DIR / "abuseipdb_blacklist_cache.json")
    before = _abuseipdb_files_in_repo_state()
    c = AbuseIPDBCollector(api_key="k" * 40, misp_writer=MagicMock())
    c.misp_writer.push_indicators.return_value = (1, 0)
    c.MIN_INTERVAL_SECONDS = 0
    with _patch(_resp(200, API), _resp(200, API)) as req:
        assert c.collect()["success"] is True
        assert c.collect()["success"] is True
    assert req.call_count == 2
    assert _abuseipdb_files_in_repo_state() == before
