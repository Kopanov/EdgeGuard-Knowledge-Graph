"""Tests for HTTP 429/502/503/504 Retry-After handling in collector_utils."""

from types import SimpleNamespace
from unittest.mock import patch

import requests

from collectors.collector_utils import request_with_rate_limit_retries, retry_after_sleep_seconds


def test_retry_after_numeric_header():
    r = SimpleNamespace(headers={"Retry-After": "42"})
    assert retry_after_sleep_seconds(r, 99.0) == 42.0


def test_retry_after_missing_uses_fallback():
    r = SimpleNamespace(headers={})
    assert retry_after_sleep_seconds(r, 30.0) == 30.0


def test_request_429_then_success():
    bad = requests.Response()
    bad.status_code = 429
    bad.headers = {"Retry-After": "0"}

    ok = requests.Response()
    ok.status_code = 200
    ok._content = b"{}"
    ok.headers = {}

    with patch("collectors.collector_utils.requests.request", side_effect=[bad, ok]) as m:
        r = request_with_rate_limit_retries(
            "GET",
            "https://example.test/api",
            session=None,
            max_rate_limit_retries=3,
            fallback_delay_sec=0.01,
            context="test",
        )
    assert r.status_code == 200
    assert m.call_count == 2


def test_request_429_exhausted_returns_last_response():
    bad = requests.Response()
    bad.status_code = 429
    bad.headers = {}

    with patch("collectors.collector_utils.requests.request", return_value=bad) as m:
        r = request_with_rate_limit_retries(
            "GET",
            "https://example.test/api",
            session=None,
            max_rate_limit_retries=2,
            fallback_delay_sec=0.01,
            context="test",
        )
    assert r.status_code == 429
    assert m.call_count == 3  # initial + 2 retries


def test_request_504_then_success():
    bad = requests.Response()
    bad.status_code = 504
    bad.headers = {}

    ok = requests.Response()
    ok.status_code = 200
    ok._content = b"{}"
    ok.headers = {}

    with patch("collectors.collector_utils.requests.request", side_effect=[bad, ok]) as m:
        r = request_with_rate_limit_retries(
            "GET",
            "https://example.test/api",
            session=None,
            max_rate_limit_retries=3,
            fallback_delay_sec=0.01,
            context="test",
        )
    assert r.status_code == 200
    assert m.call_count == 2


def test_request_403_no_retry_by_default():
    forbidden = requests.Response()
    forbidden.status_code = 403
    forbidden.headers = {}

    with patch("collectors.collector_utils.requests.request", return_value=forbidden) as m:
        r = request_with_rate_limit_retries(
            "GET",
            "https://example.test/api",
            session=None,
            max_rate_limit_retries=3,
            fallback_delay_sec=0.01,
            context="test",
        )
    assert r.status_code == 403
    assert m.call_count == 1
