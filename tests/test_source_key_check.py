"""Live check of the source API keys, and the places that report its result.

``edgeguard preflight`` reported an optional key as "set (N chars)". Whether the provider
accepts the key was learned only inside a run: a skipped task that Airflow shows as
successful (OTX, VirusTotal, ThreatFox, AbuseIPDB), or a failed NVD task after a fresh
baseline had wiped the stores.

The provider answers used here were measured on 2026-10-13 with deliberately wrong keys:
OTX ``403 {"detail": "Authentication required"}``; NVD ``404`` with the header
``message: Invalid apiKey.``; VirusTotal ``401 WrongCredentialsError``; ThreatFox
``403 {"query_status": "unknown_auth_key"}``; AbuseIPDB ``401`` with an ``errors`` list.
"""

from __future__ import annotations

import importlib
import io
import json
import logging
import os
import subprocess
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import requests
import yaml

import source_key_check as skc

ROOT = Path(__file__).resolve().parent.parent
SECRET = "5ecret5ecret5ecret5ecret5ecret5ecret5ecret5ecret5ecret5ecret5ecr"  # 64 characters, never a real key


def _config():
    """The ``config`` module the code under test will import now.

    Other test modules delete ``config`` from ``sys.modules`` and import it again, so a
    reference taken when this file was imported can be a module nobody reads any more.
    """
    return importlib.import_module("config")


class _Response:
    def __init__(self, status: int, body: Any = None, headers: Optional[Dict[str, str]] = None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.closed = False
        self.body_read = False

    def json(self) -> Any:
        self.body_read = True
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body

    def close(self) -> None:
        self.closed = True


class _HTTP:
    """Stands in for ``requests.get`` / ``requests.post``; any URL without a prepared answer fails the test."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.answers: Dict[str, Any] = {}

    def _do(self, method: str, url: str, **kwargs: Any) -> Any:
        self.calls.append({"method": method, "url": url, **kwargs})
        assert url in self.answers, f"unexpected request to {url}"
        answer = self.answers[url]
        if isinstance(answer, BaseException):
            raise answer
        return answer

    def get(self, url: str, **kwargs: Any) -> Any:
        return self._do("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self._do("POST", url, **kwargs)

    def urls(self) -> List[str]:
        return [call["url"] for call in self.calls]


URLS = {
    "otx": skc.OTX_PROBE_URL,
    "nvd": skc.NVD_PROBE_URL,
    "virustotal": skc.VIRUSTOTAL_PROBE_URL,
    "threatfox": skc.THREATFOX_PROBE_URL,
    "abuseipdb": skc.ABUSEIPDB_PROBE_URL,
}


@pytest.fixture
def http(monkeypatch, tmp_path):
    """No key configured, no switch set, a private VirusTotal ledger, and no real network."""
    for name in (
        "OTX_API_KEY",
        "NVD_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "THREATFOX_API_KEY",
        "ABUSEIPDB_API_KEY",
        "EDGEGUARD_COLLECT_SOURCES",
        "EDGEGUARD_SOURCE_KEY_CHECK",
        "EDGEGUARD_BASELINE_REQUIRED_SOURCES",
        "EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET",
    ):
        monkeypatch.delenv(name, raising=False)
    for name in ("OTX_API_KEY", "NVD_API_KEY", "VIRUSTOTAL_API_KEY"):
        monkeypatch.setattr(_config(), name, None)
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_BUDGET_PATH", str(tmp_path / "vt_ledger.json"))
    fake = _HTTP()
    monkeypatch.setattr(skc.requests, "get", fake.get)
    monkeypatch.setattr(skc.requests, "post", fake.post)
    return fake


def _set_key(monkeypatch, source: str, value: Optional[str] = SECRET) -> None:
    if source in ("otx", "nvd", "virustotal"):
        monkeypatch.setattr(_config(), f"{source.upper()}_API_KEY", value)
        if source == "virustotal" and value:
            monkeypatch.setenv("VIRUSTOTAL_API_KEY", value)
    else:
        monkeypatch.setenv(f"{source.upper()}_API_KEY", value or "")


def _one(source: str) -> skc.SourceKeyStatus:
    (status,) = skc.check_source_keys([source])
    return status


# ---------------------------------------------------------------------------
# What each provider's answer means
# ---------------------------------------------------------------------------

REJECTIONS = [
    ("otx", _Response(403, {"detail": "Authentication required"}), "HTTP 403 Authentication required"),
    ("nvd", _Response(404, None, {"message": "Invalid apiKey."}), "HTTP 404 Invalid apiKey."),
    ("virustotal", _Response(401, {"error": {"code": "WrongCredentialsError"}}), "HTTP 401 WrongCredentialsError"),
    ("threatfox", _Response(403, {"query_status": "unknown_auth_key"}), "HTTP 403 unknown_auth_key"),
    ("threatfox", _Response(401, {"error": "Unauthorized"}), "HTTP 401"),
    (
        "abuseipdb",
        _Response(401, {"errors": [{"detail": "Authentication failed."}]}),
        "HTTP 401 Authentication failed.",
    ),
]


@pytest.mark.parametrize("source", list(URLS))
def test_an_accepted_key_is_valid(http, monkeypatch, source) -> None:
    _set_key(monkeypatch, source)
    http.answers[URLS[source]] = _Response(200, {"data": []})
    status = _one(source)
    assert (status.status, status.will_collect, status.task_fails) == (skc.VALID, True, False)
    assert "will be collected" in status.message()


@pytest.mark.parametrize("source, response, detail", REJECTIONS)
def test_a_refused_key_is_rejected_with_the_providers_reason(http, monkeypatch, source, response, detail) -> None:
    _set_key(monkeypatch, source)
    http.answers[URLS[source]] = response
    status = _one(source)
    assert status.status == skc.REJECTED and status.will_collect is False
    assert status.detail == detail
    assert status.is_problem and "REJECTED" in status.message()


def test_a_rejected_nvd_key_fails_the_task_the_others_skip(http, monkeypatch) -> None:
    for source, response, _detail in REJECTIONS:
        _set_key(monkeypatch, source)
        http.answers[URLS[source]] = response
    by_source = {status.source: status for status in skc.check_source_keys()}
    assert by_source["nvd"].task_fails is True and "task will FAIL" in by_source["nvd"].message()
    for source in ("otx", "virustotal", "threatfox", "abuseipdb"):
        assert by_source[source].task_fails is False and "will be SKIPPED" in by_source[source].message()


@pytest.mark.parametrize(
    "source, response",
    [
        ("otx", _Response(429)),
        ("otx", _Response(500)),
        ("nvd", _Response(403)),  # NVD's rate limit, not a verdict on the key
        ("nvd", _Response(404)),  # a 404 without the "Invalid apiKey." header says nothing about the key
        ("nvd", _Response(503, None, {"message": "Service unavailable"})),
        ("virustotal", _Response(429, {"error": {"code": "QuotaExceededError"}})),
        ("threatfox", _Response(502)),
        ("abuseipdb", _Response(429, {"errors": [{"detail": "Daily rate limit of 1000 requests exceeded"}]})),
    ],
)
def test_an_answer_that_is_not_about_the_key_is_never_a_verdict(http, monkeypatch, source, response) -> None:
    _set_key(monkeypatch, source)
    http.answers[URLS[source]] = response
    status = _one(source)
    assert status.status == skc.UNVERIFIED and status.will_collect is None and not status.is_problem
    assert "NOT VERIFIED" in status.message() and f"HTTP {response.status_code}" in status.detail


def test_virustotal_not_found_is_an_authenticated_answer(http, monkeypatch) -> None:
    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(404, {"error": {"code": "NotFoundError"}})
    assert _one("virustotal").status == skc.VALID


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("timed out"),
        requests.exceptions.ConnectionError("refused"),
        requests.exceptions.SSLError("certificate"),
        requests.exceptions.ChunkedEncodingError("cut"),
    ],
)
def test_an_unreachable_provider_is_unverified(http, monkeypatch, error) -> None:
    _set_key(monkeypatch, "otx")
    http.answers[URLS["otx"]] = error
    status = _one("otx")
    assert status.status == skc.UNVERIFIED and type(error).__name__ in status.detail


def test_a_defect_in_one_probe_does_not_stop_the_others(http, monkeypatch, caplog) -> None:
    _set_key(monkeypatch, "otx")
    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["otx"]] = TypeError("boom")
    http.answers[URLS["threatfox"]] = _Response(200)
    with caplog.at_level(logging.WARNING, logger="source_key_check"):
        by_source = {status.source: status for status in skc.check_source_keys()}
    assert by_source["otx"].status == skc.UNVERIFIED and "TypeError" in by_source["otx"].detail
    assert by_source["threatfox"].status == skc.VALID
    assert any("failed internally" in record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# What is sent, and what is not
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source, method, header",
    [
        ("otx", "GET", "X-OTX-API-KEY"),
        ("nvd", "GET", "apiKey"),
        ("virustotal", "GET", "x-apikey"),
        ("threatfox", "POST", "Auth-Key"),
        ("abuseipdb", "GET", "Key"),
    ],
)
def test_the_key_travels_in_the_header_the_collector_uses_and_nowhere_else(
    http, monkeypatch, source, method, header
) -> None:
    _set_key(monkeypatch, source)
    http.answers[URLS[source]] = _Response(200, {})
    _one(source)
    (call,) = http.calls
    assert call["method"] == method and call["headers"][header] == SECRET
    assert SECRET not in call["url"]
    assert SECRET not in json.dumps(call.get("params") or {}) and SECRET not in json.dumps(call.get("json") or {})
    assert call["timeout"] == skc.PROBE_TIMEOUT


def test_abuseipdb_probe_spares_the_blacklist_quota(http, monkeypatch) -> None:
    """The free plan allows 5 blacklist downloads a day, and the collector needs them."""
    _set_key(monkeypatch, "abuseipdb")
    http.answers[URLS["abuseipdb"]] = _Response(200, {})
    _one("abuseipdb")
    assert http.urls() == ["https://api.abuseipdb.com/api/v2/check"]


def test_threatfox_probe_is_the_collectors_query_and_leaves_the_body_alone(http, monkeypatch) -> None:
    _set_key(monkeypatch, "threatfox")
    response = _Response(200, {"query_status": "ok", "data": ["large"]})
    http.answers[URLS["threatfox"]] = response
    assert _one("threatfox").status == skc.VALID
    (call,) = http.calls
    assert call["json"] == {"query": "get_iocs", "days": 1} and call["stream"] is True
    assert response.body_read is False and response.closed is True


def test_nvd_probe_closes_the_streamed_answer(http, monkeypatch) -> None:
    _set_key(monkeypatch, "nvd")
    response = _Response(200, {"totalResults": 1})
    http.answers[URLS["nvd"]] = response
    assert _one("nvd").status == skc.VALID
    assert http.calls[0]["params"] == {"resultsPerPage": 1} and response.closed and not response.body_read


@pytest.mark.parametrize(
    "source, value",
    [
        ("otx", None),
        ("otx", "   "),
        ("otx", "YOUR_OTX_API_KEY_HERE"),
        ("virustotal", "YOUR_VT_API_KEY"),
        ("threatfox", "demo"),
        ("threatfox", ""),
        ("abuseipdb", "YOUR_ABUSEIPDB_API_KEY_HERE"),
    ],
)
def test_no_key_or_a_template_placeholder_sends_nothing(http, monkeypatch, source, value) -> None:
    _set_key(monkeypatch, source, value)
    status = _one(source)
    assert (status.status, status.will_collect) == (skc.NOT_SET, False)
    assert "will be skipped" in status.message() and not status.is_problem
    assert http.calls == []


def test_nvd_without_a_key_still_collects(http) -> None:
    status = _one("nvd")
    assert (status.status, status.will_collect) == (skc.NOT_SET, True)
    assert "lower public rate" in status.message() and http.calls == []


def test_a_source_switched_off_by_the_allowlist_is_not_probed(http, monkeypatch) -> None:
    _set_key(monkeypatch, "otx")
    _set_key(monkeypatch, "nvd")
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "nvd,cisa")
    http.answers[URLS["nvd"]] = _Response(200)
    by_source = {status.source: status for status in skc.check_source_keys()}
    assert by_source["otx"].status == skc.DISABLED and by_source["otx"].will_collect is False
    assert by_source["nvd"].status == skc.VALID
    assert http.urls() == [URLS["nvd"]]


@pytest.mark.parametrize("value", ["false", "0", "no", "OFF"])
def test_the_switch_disables_every_request(http, monkeypatch, value) -> None:
    for source in URLS:
        _set_key(monkeypatch, source)
    monkeypatch.setenv("EDGEGUARD_SOURCE_KEY_CHECK", value)
    statuses = skc.check_source_keys()
    assert [status.status for status in statuses] == [skc.UNVERIFIED] * 5
    assert http.calls == [] and skc.exit_code(statuses) == 0


def test_virustotal_is_probed_when_only_its_second_collector_is_allowed(http, monkeypatch) -> None:
    """``virustotal`` and ``virustotal_enrich`` use the same key."""
    _set_key(monkeypatch, "virustotal")
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "virustotal_enrich")
    http.answers[URLS["virustotal"]] = _Response(200, {})
    assert _one("virustotal").status == skc.VALID
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "otx")
    assert _one("virustotal").status == skc.DISABLED


def test_fixed_order_and_selection(http) -> None:
    assert [status.source for status in skc.check_source_keys()] == [
        "otx",
        "nvd",
        "virustotal",
        "threatfox",
        "abuseipdb",
    ]
    assert [status.source for status in skc.check_source_keys(["ThreatFox ", "nvd"])] == ["nvd", "threatfox"]
    assert [status.source for status in skc.check_source_keys(["URLhaus"])] == ["threatfox"], "same key"


# ---------------------------------------------------------------------------
# The abuse.ch Auth-Key: ThreatFox, URLhaus and MalwareBazaar
# ---------------------------------------------------------------------------


def _malwarebazaar_flag(monkeypatch, on: bool) -> None:
    monkeypatch.setattr(_config(), "ENABLE_MALWAREBAZAAR", on)


def _abusech(statuses: List[skc.SourceKeyStatus]) -> skc.SourceKeyStatus:
    (status,) = [status for status in statuses if status.source == "threatfox"]
    return status


@pytest.mark.parametrize(
    "allowed, flag, named",
    [
        ("urlhaus", False, "urlhaus"),
        ("urlhaus,nvd", True, "urlhaus"),
        ("malwarebazaar", True, "malwarebazaar"),
        ("urlhaus,malwarebazaar", True, "urlhaus, malwarebazaar"),
    ],
)
def test_the_abusech_key_is_checked_for_urlhaus_and_malwarebazaar_when_threatfox_is_switched_off(
    http, monkeypatch, allowed, flag, named
) -> None:
    """Both exports carry the abuse.ch Auth-Key (THREATFOX_API_KEY) in their URL path."""
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", allowed)
    _malwarebazaar_flag(monkeypatch, flag)
    missing = _one("threatfox")
    assert (missing.status, missing.will_collect) == (skc.NOT_SET, False)
    assert missing.message().startswith(f"{named}: no key (THREATFOX_API_KEY ")
    assert "will be skipped" in missing.message() and "https://auth.abuse.ch/" in missing.message()

    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["threatfox"]] = _Response(403, {"query_status": "unknown_auth_key"})
    rejected = _one("threatfox")
    assert rejected.status == skc.REJECTED and rejected.is_problem
    assert rejected.message().startswith(f"{named}: key REJECTED by the provider (THREATFOX_API_KEY; HTTP 403")
    assert "will be SKIPPED" in rejected.message()
    assert http.urls() == [URLS["threatfox"]], "one ThreatFox query checks the key shared by the three sources"


def test_the_abusech_key_messages_name_every_source_that_uses_it(http, monkeypatch) -> None:
    _malwarebazaar_flag(monkeypatch, True)
    every = _one("threatfox")
    assert every.message().startswith("threatfox, urlhaus, malwarebazaar: no key (THREATFOX_API_KEY ")
    assert "these sources will be skipped" in every.message()
    assert every.sources == ("threatfox", "urlhaus", "malwarebazaar") and every.switched_off == ()

    _malwarebazaar_flag(monkeypatch, False)  # the default: MalwareBazaar is flag-guarded
    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["threatfox"]] = _Response(200)
    default = _one("threatfox")
    assert default.status == skc.VALID and default.switched_off == ("malwarebazaar",)
    assert default.message() == (
        "threatfox, urlhaus: key accepted by the provider (THREATFOX_API_KEY) — these sources will be collected "
        "(malwarebazaar uses the same key and is switched off)"
    )
    assert default.as_dict()["sources"] == ("threatfox", "urlhaus", "malwarebazaar")


def test_the_abusech_key_is_not_checked_when_all_three_sources_are_off(http, monkeypatch) -> None:
    _set_key(monkeypatch, "threatfox")
    _malwarebazaar_flag(monkeypatch, True)
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "otx,feodo")
    status = _one("threatfox")
    assert status.status == skc.DISABLED and http.calls == []
    assert status.message().startswith("threatfox, urlhaus, malwarebazaar: switched off by EDGEGUARD_COLLECT_SOURCES")
    _malwarebazaar_flag(monkeypatch, False)
    monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", "malwarebazaar")
    assert _one("threatfox").status == skc.DISABLED, "MalwareBazaar runs only with EDGEGUARD_ENABLE_MALWAREBAZAAR"
    assert "EDGEGUARD_ENABLE_MALWAREBAZAAR" in _one("threatfox").detail


@pytest.mark.parametrize("required", ["urlhaus", "malwarebazaar", " URLhaus , MalwareBazaar "])
def test_urlhaus_and_malwarebazaar_can_be_required_sources_of_a_baseline(http, monkeypatch, caplog, required) -> None:
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", required)
    _malwarebazaar_flag(monkeypatch, True)
    with caplog.at_level(logging.WARNING, logger="source_key_check"):
        statuses = skc.check_source_keys()
        blockers = skc.baseline_blockers(statuses)
    assert len(blockers) == 1 and blockers[0].startswith("required source (EDGEGUARD_BASELINE_REQUIRED_SOURCES)")
    assert "no key (THREATFOX_API_KEY" in blockers[0] and skc.exit_code(statuses) == 2
    assert not any("not a keyed source" in record.getMessage() for record in caplog.records)

    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["threatfox"]] = _Response(403, {"query_status": "unknown_auth_key"})
    assert len(skc.baseline_blockers(skc.check_source_keys())) == 1, "a rejected key: the source cannot deliver"
    http.answers[URLS["threatfox"]] = _Response(200)
    assert skc.baseline_blockers(skc.check_source_keys()) == []


@pytest.mark.parametrize(
    "required, allowed, flag",
    [
        ("urlhaus", "threatfox,malwarebazaar", True),  # URLhaus left out of EDGEGUARD_COLLECT_SOURCES
        ("malwarebazaar", "", False),  # EDGEGUARD_ENABLE_MALWAREBAZAAR is off
    ],
)
def test_a_required_abusech_source_that_is_switched_off_stops_a_baseline_with_a_valid_key(
    http, monkeypatch, required, allowed, flag
) -> None:
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", required)
    if allowed:
        monkeypatch.setenv("EDGEGUARD_COLLECT_SOURCES", allowed)
    _malwarebazaar_flag(monkeypatch, flag)
    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["threatfox"]] = _Response(200)
    status = _one("threatfox")
    assert status.status == skc.VALID and status.switched_off == (required,)
    (blocker,) = skc.baseline_blockers([status])
    assert f"({required} uses the same key and is switched off)" in blocker
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "threatfox")
    assert skc.baseline_blockers([status]) == [], "ThreatFox itself is switched on and its key is accepted"


# ---------------------------------------------------------------------------
# VirusTotal: the probe is a lookup, so it is counted
# ---------------------------------------------------------------------------


def _ledger(tmp_path) -> Dict[str, Any]:
    return json.loads((tmp_path / "vt_ledger.json").read_text())


def _age_ledger(tmp_path, seconds: float, *fields: str) -> None:
    """Move ledger timestamps into the past, as if that much time had gone by."""
    data = _ledger(tmp_path)
    for field in fields:
        then = datetime.fromisoformat(data[field]) - timedelta(seconds=seconds)
        data[field] = then.isoformat()
    (tmp_path / "vt_ledger.json").write_text(json.dumps(data))


def test_virustotal_probe_is_counted_and_recorded_as_a_key_check(http, monkeypatch, tmp_path) -> None:
    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(200, {"data": {}})
    assert _one("virustotal").status == skc.VALID
    ledger = _ledger(tmp_path)
    assert ledger["used"] == 1 and ledger["updated_by"] == "key_check"
    assert ledger["key_check_at"] and ledger["exhausted"] is False


def test_a_rate_limit_answer_to_the_probe_does_not_end_the_collectors_day(http, monkeypatch, tmp_path) -> None:
    """VirusTotal answers 429 for the per-minute limit too; only the collector's own lookups end its day."""
    from collectors.virustotal_budget import VirusTotalBudget

    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(429, {"error": {"code": "QuotaExceededError"}})
    status = _one("virustotal")
    assert status.status == skc.UNVERIFIED and "HTTP 429 QuotaExceededError" in status.detail
    budget = VirusTotalBudget()
    assert budget.is_exhausted() is False and budget.used == 1 and budget.remaining == 399


@pytest.mark.parametrize("old_format", [False, True], ids=["current ledger", "ledger without a writer field"])
def test_virustotal_is_not_probed_while_a_collector_run_writes_the_ledger(
    http, monkeypatch, tmp_path, old_format
) -> None:
    from collectors.virustotal_budget import VirusTotalBudget

    _set_key(monkeypatch, "virustotal")
    running = VirusTotalBudget()
    running.consume(7)
    running.save()  # what a collector run does before its first lookup and every 10 lookups
    if old_format:
        data = _ledger(tmp_path)
        del data["updated_by"], data["key_check_at"]
        (tmp_path / "vt_ledger.json").write_text(json.dumps(data))
    _age_ledger(tmp_path, 299, "updated_at")
    status = _one("virustotal")
    assert status.status == skc.UNVERIFIED and "collector run wrote its ledger" in status.detail
    assert http.calls == [] and _ledger(tmp_path)["used"] == 7, "nothing sent, nothing counted"


def test_virustotal_is_probed_once_the_collector_has_been_quiet(http, monkeypatch, tmp_path) -> None:
    from collectors.virustotal_budget import VirusTotalBudget

    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(200, {"data": {}})
    finished = VirusTotalBudget()
    finished.consume(7)
    finished.save()
    _age_ledger(tmp_path, 301, "updated_at")
    assert _one("virustotal").status == skc.VALID
    assert len(http.calls) == 1 and _ledger(tmp_path)["used"] == 8


def test_virustotal_checks_are_spaced_twenty_seconds_apart(http, monkeypatch, tmp_path) -> None:
    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(401, {"error": {"code": "WrongCredentialsError"}})
    assert _one("virustotal").status == skc.REJECTED
    again = _one("virustotal")
    assert again.status == skc.UNVERIFIED and "the key was checked" in again.detail
    assert len(http.calls) == 1 and _ledger(tmp_path)["used"] == 1
    # The operator corrects the key and checks again a little later: the request is sent.
    _age_ledger(tmp_path, 21, "updated_at", "key_check_at")
    http.answers[URLS["virustotal"]] = _Response(200, {"data": {}})
    assert _one("virustotal").status == skc.VALID
    assert len(http.calls) == 2 and _ledger(tmp_path)["used"] == 2


def test_virustotal_check_is_in_the_ledger_before_the_request_leaves(http, monkeypatch, tmp_path) -> None:
    """A collector run that starts, or is answered 429, during the round trip must find the check."""
    _set_key(monkeypatch, "virustotal")
    at_request_time: List[Dict[str, Any]] = []

    def get(url: str, **_kwargs: Any) -> Any:
        at_request_time.append(_ledger(tmp_path))
        raise requests.exceptions.ReadTimeout("no answer")

    monkeypatch.setattr(skc.requests, "get", get)
    assert _one("virustotal").status == skc.UNVERIFIED
    (seen,) = at_request_time
    assert seen["used"] == 1 and seen["updated_by"] == "key_check" and seen["key_check_at"]
    assert _ledger(tmp_path)["used"] == 1, "a request that may have reached VirusTotal stays counted"


def test_virustotal_is_not_probed_when_the_daily_budget_is_used(http, monkeypatch) -> None:
    _set_key(monkeypatch, "virustotal")
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET", "0")
    status = _one("virustotal")
    assert status.status == skc.UNVERIFIED and "budget is used" in status.detail
    assert http.calls == []


def test_virustotal_key_from_the_credentials_file_is_named_as_such(http, monkeypatch) -> None:
    """``config`` falls back to ``credentials/api_keys.yaml``; the report must say which key was refused."""
    monkeypatch.setattr(_config(), "VIRUSTOTAL_API_KEY", "left-over-template-value")
    http.answers[URLS["virustotal"]] = _Response(401, {"error": {"code": "WrongCredentialsError"}})
    status = _one("virustotal")
    assert status.status == skc.REJECTED
    assert "VIRUSTOTAL_API_KEY in credentials/api_keys.yaml" in status.message()


def test_virustotal_key_origin_is_the_variable_when_set_or_when_nothing_is_configured(http, monkeypatch) -> None:
    assert _one("virustotal").configured_in == "VIRUSTOTAL_API_KEY", "neither the variable nor the file holds a key"
    _set_key(monkeypatch, "virustotal")
    http.answers[URLS["virustotal"]] = _Response(200, {})
    assert _one("virustotal").configured_in == "VIRUSTOTAL_API_KEY"


# ---------------------------------------------------------------------------
# A key value never leaves the process
# ---------------------------------------------------------------------------


def test_a_key_echoed_by_the_provider_is_masked_everywhere(http, monkeypatch, capsys, caplog) -> None:
    echoes = {
        "otx": _Response(403, {"detail": f"key {SECRET} is not known"}),
        "nvd": _Response(404, None, {"message": f"Invalid apiKey. {SECRET}"}),
        "virustotal": _Response(401, {"error": {"code": f"Wrong {SECRET}"}}),
        "threatfox": _Response(403, {"query_status": f"unknown_auth_key {SECRET}"}),
        "abuseipdb": _Response(401, {"errors": [{"detail": f"{SECRET} revoked"}]}),
    }
    for source, response in echoes.items():
        _set_key(monkeypatch, source)
        http.answers[URLS[source]] = response
    statuses = skc.check_source_keys()
    assert [status.status for status in statuses] == [skc.REJECTED] * 5
    with caplog.at_level(logging.DEBUG):
        skc.log_report(statuses, logging.getLogger("source_key_check"))
        assert skc.main([]) == 2
        assert skc.main(["--json"]) == 2
    everything = (
        capsys.readouterr().out
        + caplog.text
        + json.dumps([status.as_dict() for status in statuses])
        + "".join(skc.baseline_blockers(statuses, required=list(URLS)))
    )
    assert SECRET not in everything and "***" in everything


# ---------------------------------------------------------------------------
# What stops a baseline, exit codes, log levels
# ---------------------------------------------------------------------------


def _status(source: str, status: str, will_collect: Optional[bool], task_fails: bool = False) -> skc.SourceKeyStatus:
    return skc.SourceKeyStatus(
        source, f"{source.upper()}_API_KEY", status, "HTTP 403", will_collect, task_fails, "https://x"
    )


OPTIONAL_REJECTED = _status("threatfox", skc.REJECTED, False)
NVD_REJECTED = _status("nvd", skc.REJECTED, False, task_fails=True)
OTX_VALID = _status("otx", skc.VALID, True)
ABUSE_NOT_SET = _status("abuseipdb", skc.NOT_SET, False)
NVD_NOT_SET = _status("nvd", skc.NOT_SET, True)
VT_UNVERIFIED = _status("virustotal", skc.UNVERIFIED, None)
OTX_DISABLED = _status("otx", skc.DISABLED, False)


def test_an_optional_source_never_stops_a_baseline_by_default(http) -> None:
    statuses = [OPTIONAL_REJECTED, ABUSE_NOT_SET, VT_UNVERIFIED, OTX_DISABLED, NVD_NOT_SET]
    assert skc.baseline_blockers(statuses) == []
    assert skc.exit_code(statuses) == 1, "a rejected key is reported by the command, without being a blocker"
    assert skc.exit_code([ABUSE_NOT_SET, VT_UNVERIFIED, OTX_VALID, NVD_NOT_SET]) == 0


def test_a_rejected_nvd_key_stops_a_baseline(http) -> None:
    blockers = skc.baseline_blockers([OTX_VALID, NVD_REJECTED])
    assert len(blockers) == 1 and blockers[0].startswith("nvd: key REJECTED")
    assert skc.exit_code([OTX_VALID, NVD_REJECTED]) == 2


def test_required_sources_stop_a_baseline_only_when_known_not_to_deliver(http, monkeypatch) -> None:
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", " ThreatFox, abuseipdb ,virustotal,otx,nvd ")
    assert skc.required_sources() == {"threatfox", "abuseipdb", "virustotal", "otx", "nvd"}
    blockers = skc.baseline_blockers([OPTIONAL_REJECTED, ABUSE_NOT_SET, VT_UNVERIFIED, OTX_VALID, NVD_NOT_SET])
    assert [blocker.split(" — ")[1].split(":")[0] for blocker in blockers] == ["threatfox", "abuseipdb"]
    assert all(blocker.startswith("required source (EDGEGUARD_BASELINE_REQUIRED_SOURCES)") for blocker in blockers)
    assert len(skc.baseline_blockers([_status("otx", skc.DISABLED, False)])) == 1, "required but switched off"


def test_an_unknown_required_name_is_reported_not_enforced(http, monkeypatch, caplog) -> None:
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "feodo")
    with caplog.at_level(logging.WARNING, logger="source_key_check"):
        assert skc.baseline_blockers([OTX_VALID]) == []
    assert any(
        "'feodo'" in record.getMessage() and "not a keyed source" in record.getMessage() for record in caplog.records
    )


def test_log_levels(http, caplog) -> None:
    with caplog.at_level(logging.DEBUG, logger="t"):
        skc.log_report(
            [OTX_VALID, NVD_NOT_SET, ABUSE_NOT_SET, VT_UNVERIFIED, OPTIONAL_REJECTED, OTX_DISABLED],
            logging.getLogger("t"),
        )
    levels = [(record.levelname, record.getMessage().split(":")[0]) for record in caplog.records]
    assert levels == [
        ("INFO", "[SOURCE-KEYS] otx"),
        ("INFO", "[SOURCE-KEYS] nvd"),
        ("WARNING", "[SOURCE-KEYS] abuseipdb"),
        ("WARNING", "[SOURCE-KEYS] virustotal"),
        ("ERROR", "[SOURCE-KEYS] threatfox"),
        ("WARNING", "[SOURCE-KEYS] otx"),
    ]


def test_command_output_and_exit_code(http, monkeypatch, capsys) -> None:
    _set_key(monkeypatch, "otx")
    _set_key(monkeypatch, "threatfox")
    http.answers[URLS["otx"]] = _Response(200)
    http.answers[URLS["threatfox"]] = _Response(403, {"query_status": "unknown_auth_key"})
    assert skc.main([]) == 1
    lines = capsys.readouterr().out.strip().splitlines()
    assert [line.split(" ")[0] for line in lines] == ["OK", "NO-KEY", "NO-KEY", "REJECTED", "NO-KEY"]
    assert skc.main(["--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert [(row["source"], row["status"]) for row in payload][3] == ("threatfox", "rejected")


# ---------------------------------------------------------------------------
# edgeguard preflight
# ---------------------------------------------------------------------------


def _preflight(monkeypatch, statuses, strict: bool = False) -> Dict[str, Any]:
    import airflow_client
    import edgeguard
    import health_check

    # cmd_* functions read config values from module-level names that the command line entry point loads.
    for name in edgeguard._CFG_EXPORTS:
        monkeypatch.setattr(edgeguard, name, getattr(_config(), name), raising=False)
    monkeypatch.setattr(
        importlib.import_module("source_key_check"), "check_source_keys", lambda sources=None: list(statuses)
    )
    monkeypatch.setattr(health_check, "health_check_neo4j", lambda: {"healthy": True, "apoc_available": True})
    monkeypatch.setattr(airflow_client, "airflow_health", lambda: {"error": "not reachable in this test"})
    out = io.StringIO()
    with patch("misp_health.MISPHealthCheck") as misp, redirect_stdout(out):
        misp.return_value.check_health.return_value = {"healthy": True, "healthy_for_collection": True}
        code = edgeguard.cmd_preflight(SimpleNamespace(strict=strict, json=True))
    text = out.getvalue()
    summary = json.loads(text[text.rindex('{\n  "errors"') :])
    return {
        "code": code,
        "errors": summary["errors"],
        "warnings": summary["warnings"],
        "text": text,
        "checks": summary["checks"],
    }


def test_preflight_counts_a_rejected_optional_key_as_a_warning(http, monkeypatch) -> None:
    clean = _preflight(monkeypatch, [OTX_VALID, NVD_NOT_SET, ABUSE_NOT_SET, VT_UNVERIFIED])
    rejected = _preflight(monkeypatch, [OTX_VALID, NVD_NOT_SET, ABUSE_NOT_SET, VT_UNVERIFIED, OPTIONAL_REJECTED])
    assert (rejected["errors"], rejected["warnings"]) == (clean["errors"], clean["warnings"] + 1)
    assert "threatfox: key REJECTED" in rejected["text"] and "set (" not in rejected["text"]
    assert [row["source"] for row in rejected["checks"]["source_keys"]][-1] == "threatfox"
    assert rejected["code"] == clean["code"], "not strict: a warning does not change the exit code"
    strict = _preflight(monkeypatch, [OTX_VALID, OPTIONAL_REJECTED], strict=True)
    assert strict["code"] == 1


def test_preflight_counts_a_rejected_nvd_key_and_a_missing_required_source_as_errors(http, monkeypatch) -> None:
    clean = _preflight(monkeypatch, [OTX_VALID, ABUSE_NOT_SET])
    nvd = _preflight(monkeypatch, [OTX_VALID, ABUSE_NOT_SET, NVD_REJECTED])
    assert (nvd["errors"], nvd["warnings"], nvd["code"]) == (clean["errors"] + 1, clean["warnings"], 1)
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "abuseipdb")
    required = _preflight(monkeypatch, [OTX_VALID, ABUSE_NOT_SET])
    assert (required["errors"], required["code"]) == (clean["errors"] + 1, 1)
    assert "[named in EDGEGUARD_BASELINE_REQUIRED_SOURCES]" in required["text"]


def test_preflight_counts_a_required_urlhaus_without_the_abusech_key_as_an_error(http, monkeypatch) -> None:
    statuses = skc.check_source_keys()  # no key configured anywhere
    clean = _preflight(monkeypatch, statuses)
    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "urlhaus")
    required = _preflight(monkeypatch, statuses)
    assert (required["errors"], required["code"]) == (clean["errors"] + 1, 1)
    assert "no key (THREATFOX_API_KEY" in required["text"]
    assert "[named in EDGEGUARD_BASELINE_REQUIRED_SOURCES]" in required["text"]


# ---------------------------------------------------------------------------
# The baseline DAG and the collector wrapper
# ---------------------------------------------------------------------------


def _import_dag_module():
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            or key.startswith("airflow")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    dags = os.path.join(os.path.dirname(__file__), "..", "dags")
    if dags not in sys.path:
        sys.path.insert(0, dags)
    return importlib.import_module("edgeguard_pipeline")


@pytest.fixture
def dag():
    try:
        ep = _import_dag_module()
    except Exception:
        pytest.skip("Airflow not installed in this test env")
    names = (
        "ensure_metrics_server",
        "log_circuit_breaker_status",
        "send_slack_alert",
        "set_source_health",
        "set_last_success_timestamp",
        "record_dag_run",
        "record_collection",
        "record_collection_duration",
        "record_collector_skip",
        "record_indicators",
        "record_misp_push",
        "record_misp_push_duration",
        "record_task_duration",
    )
    patches = [patch.object(ep, name, MagicMock()) for name in names]
    patches += [
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _name: True),
        patch("baseline_lock.baseline_skip_reason", lambda **_kw: None),
        patch("collectors.misp_writer.MISPWriter", MagicMock()),
        patch("parent_dag_liveness.make_liveness_callback", lambda *_a, **_k: None),
    ]
    for p in patches:
        p.start()
    yield ep
    for p in reversed(patches):
        p.stop()


def test_the_key_report_runs_before_the_lock_and_the_wipe(dag) -> None:
    assert dag.baseline_source_keys.upstream_task_ids == {"misp_health_check"}
    assert dag.baseline_acquire_lock_task.upstream_task_ids == {"source_key_check"}
    assert dag.baseline_clean_task.upstream_task_ids == {dag.baseline_acquire_lock_task.task_id}
    assert dag.baseline_source_keys.retries == 0


def test_baseline_task_reports_and_continues_for_optional_sources(dag, monkeypatch, caplog) -> None:
    import source_key_check

    monkeypatch.delenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", raising=False)
    monkeypatch.setattr(
        source_key_check,
        "check_source_keys",
        lambda sources=None: [OTX_VALID, OPTIONAL_REJECTED, ABUSE_NOT_SET, VT_UNVERIFIED],
    )
    with caplog.at_level(logging.INFO):
        assert dag._baseline_source_key_check() is None
    by_level = {
        record.levelname: record.getMessage() for record in caplog.records if "[SOURCE-KEYS]" in record.getMessage()
    }
    assert "threatfox: key REJECTED" in by_level["ERROR"] and "otx: key accepted" in by_level["INFO"]


def test_baseline_task_stops_the_run_on_a_blocker(dag, monkeypatch, caplog) -> None:
    import source_key_check

    monkeypatch.delenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", raising=False)
    monkeypatch.setattr(source_key_check, "check_source_keys", lambda sources=None: [OTX_VALID, NVD_REJECTED])
    with caplog.at_level(logging.ERROR), pytest.raises(dag.AirflowException, match="nothing was locked or wiped"):
        dag._baseline_source_key_check()
    assert any("BLOCKER nvd: key REJECTED" in record.getMessage() for record in caplog.records)

    monkeypatch.setenv("EDGEGUARD_BASELINE_REQUIRED_SOURCES", "threatfox")
    monkeypatch.setattr(source_key_check, "check_source_keys", lambda sources=None: [OTX_VALID, OPTIONAL_REJECTED])
    with pytest.raises(dag.AirflowException):
        dag._baseline_source_key_check()


class _SkippingCollector:
    result: Dict[str, Any] = {}

    def __init__(self, misp_writer=None, **_kwargs):
        pass

    def collect(self, limit=None, push_to_misp=True, **_kwargs):
        return dict(type(self).result)


def _skip(reason_class: str) -> Dict[str, Any]:
    return {
        "source": "threatfox",
        "success": True,
        "count": 0,
        "failed": 0,
        "skipped": True,
        "skip_reason": "403 Client Error: Forbidden",
        "skip_reason_class": reason_class,
    }


def test_a_denied_source_is_logged_as_an_error_and_counted_under_its_class(dag, caplog) -> None:
    _SkippingCollector.result = _skip("threatfox_auth_denied")
    with caplog.at_level(logging.WARNING):
        result = dag.run_collector_with_metrics("threatfox", _SkippingCollector, MagicMock(), limit=10)
    assert result["skipped"] is True, "the task stays green: an optional source never blocks the pipeline"
    errors = [record.getMessage() for record in caplog.records if record.levelname == "ERROR"]
    assert len(errors) == 1 and errors[0].startswith("[SOURCE-ACCESS] THREATFOX NOT collected")
    assert "threatfox_auth_denied" in errors[0] and "source_key_check.py" in errors[0]
    dag.record_collector_skip.assert_called_once_with("threatfox", "threatfox_auth_denied")


def test_a_missing_key_stays_a_routine_warning(dag, caplog) -> None:
    _SkippingCollector.result = _skip("missing_threatfox_key")
    with caplog.at_level(logging.WARNING):
        dag.run_collector_with_metrics("threatfox", _SkippingCollector, MagicMock(), limit=10)
    assert [record for record in caplog.records if record.levelname == "ERROR"] == []
    assert any("THREATFOX skipped" in record.getMessage() for record in caplog.records if record.levelname == "WARNING")


# ---------------------------------------------------------------------------
# NVD collector: a rejected key is named, not reported as an outage
# ---------------------------------------------------------------------------


def _nvd_collect(monkeypatch, api_key: Optional[str], response: _Response) -> Dict[str, Any]:
    from collectors import nvd_collector

    collector = nvd_collector.NVDCollector(misp_writer=MagicMock())
    collector.api_key = api_key
    collector.circuit_breaker = MagicMock()
    collector.circuit_breaker.can_execute.return_value = True
    collector.circuit_breaker.state.name = "CLOSED"
    monkeypatch.setattr(nvd_collector.requests, "get", lambda *_a, **_k: response)
    monkeypatch.setattr(nvd_collector, "record_collection_failure", MagicMock())
    return collector.collect(limit=1, push_to_misp=True)


def test_nvd_collector_names_a_rejected_key(monkeypatch) -> None:
    status = _nvd_collect(monkeypatch, "wrong-key", _Response(404, None, {"message": "Invalid apiKey."}))
    assert status["success"] is False
    assert status["error"].startswith("NVD rejected NVD_API_KEY (HTTP 404 Invalid apiKey.)")
    assert "service unavailable" not in status["error"]


@pytest.mark.parametrize(
    "api_key, response",
    [
        ("some-key", _Response(503)),
        ("some-key", _Response(404)),  # a 404 that is not about the key
        ("some-key", _Response(403, None, {"message": "Forbidden"})),
        (None, _Response(404, None, {"message": "Invalid apiKey."})),  # no key configured: nothing to reject
    ],
)
def test_nvd_collector_keeps_the_outage_message_for_everything_else(monkeypatch, api_key, response) -> None:
    status = _nvd_collect(monkeypatch, api_key, response)
    assert status["success"] is False and status["error"].startswith("NVD service unavailable")


# ---------------------------------------------------------------------------
# Launch-day script and alert rule
# ---------------------------------------------------------------------------


def test_launch_script_maps_the_command_output(tmp_path) -> None:
    """Check [12] of preflight_baseline.sh: REJECTED is a warning, BLOCKER a failure, the rest is information."""
    script = (ROOT / "scripts" / "preflight_baseline.sh").read_text()
    block = script[script.index('hdr "[12]') : script.index("# Summary\n")]
    block = block[: block.rindex("fi\n") + 3]
    (tmp_path / "src").mkdir()
    stub = tmp_path / "python3"
    stub.write_text(
        "#!/bin/sh\n"
        'echo "$*" > called_with.txt\n'
        'echo "OK otx: key accepted"\n'
        'echo "NO-KEY abuseipdb: no key"\n'
        'echo "REJECTED threatfox: key REJECTED"\n'
        'echo "UNKNOWN virustotal: key NOT VERIFIED"\n'
        'echo "BLOCKER nvd: key REJECTED"\n'
        "exit 2\n"
    )
    stub.chmod(0o755)
    harness = (
        "set -uo pipefail\n"
        'pass() { echo "PASS|$*"; }\nwarn() { echo "WARN|$*"; }\nfail() { echo "FAIL|$*"; }\nhdr() { :; }\n' + block
    )
    env = {"PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}"}
    done = subprocess.run(["bash", "-c", harness], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "called_with.txt").read_text().strip() == "src/source_key_check.py"
    assert done.stdout.splitlines() == [
        "PASS|otx: key accepted",
        "  - NO-KEY abuseipdb: no key",
        "WARN|threatfox: key REJECTED",
        "  - UNKNOWN virustotal: key NOT VERIFIED",
        "FAIL|nvd: key REJECTED",
    ]


def test_alert_rule_covers_every_denied_source_and_the_first_denied_run() -> None:
    rules = yaml.safe_load((ROOT / "prometheus" / "alerts.yml").read_text())
    (rule,) = [
        r for group in rules["groups"] for r in group["rules"] if r.get("alert") == "EdgeGuardSourceAccessDenied"
    ]
    expr = " ".join(rule["expr"].split())
    selector = 'edgeguard_collector_skips_total{reason_class=~".+_auth_denied"}'
    assert f"increase({selector}[25h])" in expr
    assert (
        f"sum by (source, reason_class) ({selector}) unless sum by (source, reason_class) ({selector} offset 25h)"
        in expr
    )
    assert rule["labels"]["severity"] == "warning" and "$labels.source" in rule["annotations"]["summary"]
    # The label the rule selects on is the one the collectors emit.
    import re

    emitted = set()
    for path in list((ROOT / "src" / "collectors").glob("*.py")):
        emitted |= set(re.findall(r'"([a-z_]+_auth_denied)"', path.read_text()))
    assert {"otx_auth_denied", "virustotal_auth_denied", "threatfox_auth_denied", "abuseipdb_auth_denied"} <= emitted
    assert all(re.fullmatch(r".+_auth_denied", name) for name in emitted)
