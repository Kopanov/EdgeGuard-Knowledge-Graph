"""Feodo Tracker: baseline runs download the complete C2 history, regular runs the 30-day list."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

CSV = (
    "################################################################\n"
    "# Feodo Tracker Botnet C2 IP Blocklist (CSV)                   #\n"
    "################################################################\n"
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\n'
    '"2024-05-01 10:00:00","203.0.113.10","443","offline","2024-06-01","Emotet"\n'
    '"2026-10-01 08:30:00","198.51.100.7","8080","online","2026-10-11","QakBot"\n'
)


class FakeResponse:
    status_code = 200
    text = CSV

    def raise_for_status(self) -> None:
        return None


@pytest.fixture
def feodo(monkeypatch: pytest.MonkeyPatch):
    from collectors import finance_feed_collector as mod

    calls: List[Dict[str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        calls.append({"method": method, "url": url})
        return FakeResponse()

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", fake_request)
    monkeypatch.setattr(mod.FEODO_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(mod.FEODO_CIRCUIT_BREAKER, "can_execute", lambda: True)
    writer = MagicMock()
    writer.push_indicators.return_value = (2, 0)
    collector = mod.FeodoCollector(misp_writer=writer)
    collector._test_calls = calls  # type: ignore[attr-defined]
    return collector


def test_list_url_selects_the_history_for_baselines_and_the_30_day_list_otherwise(feodo) -> None:
    assert feodo.list_url(True).endswith("/ipblocklist_aggressive.csv")
    assert feodo.list_url(False).endswith("/ipblocklist.csv")
    assert feodo.url == feodo.URL_RECENT and feodo.baseline_url == feodo.URL_AGGRESSIVE


def test_baseline_run_downloads_the_aggressive_list(feodo) -> None:
    items = feodo.collect(limit=None, push_to_misp=False, baseline=True)
    assert [c["url"] for c in feodo._test_calls] == [feodo.URL_AGGRESSIVE]
    assert [i["value"] for i in items] == ["203.0.113.10", "198.51.100.7"]
    assert items[0]["malware_family"] == "emotet" and items[0]["status"] == "offline"
    assert items[1]["first_seen"] == "2026-10-01 08:30:00" and items[1]["port"] == "8080"
    assert all(i["indicator_type"] == "ipv4" and i["tag"] == "feodo_tracker" for i in items)


def test_regular_run_downloads_the_30_day_list(feodo) -> None:
    items = feodo.collect(limit=None, push_to_misp=False, baseline=False)
    assert [c["url"] for c in feodo._test_calls] == [feodo.URL_RECENT]
    assert len(items) == 2


def test_both_lists_share_the_parser_and_the_misp_push_path(feodo) -> None:
    status = feodo.collect(limit=None, push_to_misp=True, baseline=True)
    assert status["success"] is True and status["count"] == 2 and status["source"] == "feodo"
    pushed, source = feodo.misp_writer.push_indicators.call_args.args
    assert source == "feodo" and len(pushed) == 2


def test_limit_applies_to_the_history_download_too(feodo) -> None:
    items = feodo.collect(limit=1, push_to_misp=False, baseline=True)
    assert len(items) == 1 and feodo._test_calls[0]["url"] == feodo.URL_AGGRESSIVE
