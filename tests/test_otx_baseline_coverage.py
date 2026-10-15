"""A baseline logs how many pulses OTX reports for its window and whether the page ceiling reads them (2026-10).

OTX answers every page of ``/api/v1/pulses/subscribed`` with ``count``, the number of pulses that match
the request. The baseline logs it after the first page, warns at once when the page ceiling cannot read
them all, and states the share it read at the end, so the coverage of a run is stated rather than
inferred from attribute counts.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from collectors import otx_collector  # noqa: E402
from collectors.otx_collector import OTXCollector  # noqa: E402

_PULSE = {
    "id": "6710e46581edfe9bba0da3f2",
    "name": "Loader campaign",
    "description": "",
    "author_name": "example",
    "created": "2026-10-13T11:11:02.458000",
    "modified": "2026-10-13T23:37:29.579000",
    "TLP": "white",
    "tags": [],
    "references": [],
    "industries": [],
    "targeted_countries": [],
    "malware_families": [],
    "attack_ids": [],
    "indicators": [{"id": 1, "indicator": "phish.example.net", "type": "hostname", "created": "2026-10-13T23:37:31"}],
}


def _collector() -> OTXCollector:
    c = OTXCollector.__new__(OTXCollector)
    c.api_key = "a" * 64
    c.base_url = "https://otx.example"
    c.tag = "alienvault_otx"
    c.session = MagicMock()
    c.rate_limiter = MagicMock()
    c._last_http_status = 200
    c.circuit_breaker = MagicMock()
    c.misp_writer = None
    c.source_name = "otx"
    return c


def _run(caplog, *, count, max_pages):
    def answer(method, url, params=None, **_kw):
        response = MagicMock(status_code=200)
        body = {"results": [_PULSE] if params["page"] == 1 else []}
        if count is not None:
            body["count"] = count
        response.json.return_value = body
        return response

    c = _collector()
    with (
        patch.object(c, "check_service_available", return_value=True),
        patch.object(otx_collector, "request_with_rate_limit_retries", side_effect=answer),
        patch.object(otx_collector.time, "sleep"),
        patch.object(otx_collector, "get_source_incremental", return_value={}),
        patch.object(otx_collector, "update_source_incremental"),
        patch.object(otx_collector, "OTX_BASELINE_MAX_PAGES", max_pages),
        caplog.at_level("INFO", logger=otx_collector.logger.name),
    ):
        c.collect(limit=None, push_to_misp=False, baseline=True, baseline_days=730)
    return [r for r in caplog.records if r.name == otx_collector.logger.name]


def test_the_reported_total_and_the_ceiling_are_logged(caplog):
    records = _run(caplog, count=120, max_pages=200)
    messages = [r.getMessage() for r in records]
    assert any(
        "OTX reports 120 subscribed pulses modified in the last 730 days; the page ceiling reads up to 10000" in m
        for m in messages
    )
    assert any(
        "Baseline complete: 1 total pulses collected of 120 that OTX reported for the window" in m for m in messages
    )
    assert not [r for r in records if r.levelname == "WARNING" and "page ceiling stops" in r.getMessage()]


def test_a_ceiling_below_the_total_warns_at_the_start(caplog):
    records = _run(caplog, count=120, max_pages=2)
    warnings = [r.getMessage() for r in records if r.levelname == "WARNING"]
    assert any("stops 20 pulses short of the window" in m and "at least 3" in m for m in warnings)


def test_an_answer_without_a_count_logs_no_coverage(caplog):
    messages = [r.getMessage() for r in _run(caplog, count=None, max_pages=200)]
    assert not any("OTX reports" in m for m in messages)
    assert any(m.endswith("Baseline complete: 1 total pulses collected") for m in messages)
