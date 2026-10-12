"""VirusTotal free-tier safety: daily budget ledger, lookup enrichment, and the optional-source contract.

The collector must never block the workflow: an exhausted budget, an HTTP 429, a rejected key
or an unreachable MISP all end in ``success=True`` + ``skipped=True`` with an explicit reason,
and every quota event is logged with the ``[VT-QUOTA]`` prefix.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
import requests

H1 = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
H4 = "d" * 64

SRC = Path(__file__).resolve().parent.parent / "src"


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers: Dict[str, str] = {}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}", response=self)  # type: ignore[arg-type]


def _vt_file(sha256: str, malicious: int = 50, undetected: int = 20) -> Dict[str, Any]:
    return {
        "data": {
            "id": sha256,
            "type": "file",
            "attributes": {
                "sha256": sha256,
                "md5": "0" * 32,
                "sha1": "1" * 40,
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": undetected,
                },
                "first_submission_date": 1_700_000_000,
                "last_submission_date": 1_700_100_000,
                "type_description": "Win32 EXE",
                "size": 1234,
                "names": ["bank-statement.exe"],
                "meaningful_name": "bank-statement.exe",
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.emotet",
                    "popular_threat_category": [{"value": "trojan", "count": 10}],
                },
            },
        }
    }


def _misp_rows(*values: str) -> FakeResponse:
    return FakeResponse(200, {"response": {"Attribute": [{"type": "sha256", "value": v} for v in values]}})


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


@pytest.fixture
def ledger_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "state" / "virustotal_daily_budget.json"
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_BUDGET_PATH", str(path))
    for name in (
        "EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET",
        "EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN",
        "EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS",
    ):
        monkeypatch.delenv(name, raising=False)
    return path


def _write_ledger(path: Path, **fields: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    base = {"date": _today(), "budget": 400, "used": 0, "exhausted": False, "looked_up": {}}
    base.update(fields)
    path.write_text(json.dumps(base))


@pytest.fixture
def collector(ledger_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A collector with a stub MISP writer and a recording VirusTotal transport."""
    from collectors import vt_collector as mod

    writer = MagicMock()
    writer.url = "https://misp.test"
    writer.verify_ssl = False
    writer.push_items.return_value = (1, 0)
    vt = mod.VTCollector(misp_writer=writer)
    vt.api_key = "k" * 64
    vt.rate_limiter = MagicMock()  # no sleeping in tests

    calls: List[str] = []
    responses: Dict[str, Any] = {}

    request_kwargs: List[Dict[str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        sha = url.rsplit("/", 1)[-1]
        calls.append(sha)
        request_kwargs.append(kwargs)
        resp = responses.get(sha)
        if isinstance(resp, Exception):
            raise resp
        return resp if resp is not None else FakeResponse(404, {})

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", fake_request)
    vt._test_calls = calls  # type: ignore[attr-defined]
    vt._test_request_kwargs = request_kwargs  # type: ignore[attr-defined]
    vt._test_responses = responses  # type: ignore[attr-defined]
    return vt


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


def test_new_utc_day_resets_the_counter_but_keeps_the_lookup_memory(ledger_path: Path) -> None:
    from collectors.virustotal_budget import VirusTotalBudget

    _write_ledger(ledger_path, date="2000-01-01", used=399, exhausted=True, looked_up={H1: "ok", H2: "not_found"})
    budget = VirusTotalBudget()
    assert budget.used == 0
    assert budget.exhausted is False
    assert budget.remaining == 400
    assert budget.already_looked_up(H1) and budget.already_looked_up(H2)
    assert not budget.already_looked_up(H3)


def test_same_day_ledger_is_honoured_and_persisted(ledger_path: Path) -> None:
    from collectors.virustotal_budget import VirusTotalBudget

    _write_ledger(ledger_path, used=398)
    budget = VirusTotalBudget()
    assert budget.remaining == 2
    budget.consume(1)
    budget.remember(H1, "ok")
    budget.save()
    on_disk = json.loads(ledger_path.read_text())
    assert on_disk["used"] == 399
    assert on_disk["looked_up"] == {H1: "ok"}
    assert on_disk["date"] == _today()


def test_corrupt_ledger_is_treated_as_a_fresh_day_not_an_error(
    ledger_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from collectors.virustotal_budget import VirusTotalBudget

    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_text("{not json")
    with caplog.at_level(logging.WARNING):
        budget = VirusTotalBudget()
    assert budget.remaining == 400
    assert any("[VT-QUOTA]" in r.getMessage() and "unreadable" in r.getMessage() for r in caplog.records)


def test_invalid_knob_values_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    from collectors import virustotal_budget as vb

    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET", "many")
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN", "-5")
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_CANDIDATE_DAYS", "0")
    assert vb.daily_budget() == vb.DAILY_BUDGET_DEFAULT
    assert vb.max_lookups_per_run() == vb.MAX_LOOKUPS_PER_RUN_DEFAULT
    assert vb.candidate_days() == vb.CANDIDATE_DAYS_DEFAULT
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_DAILY_BUDGET", "0")
    assert vb.daily_budget() == 0  # zero is a valid "no lookups today" setting


# ---------------------------------------------------------------------------
# Budget gates (no VirusTotal or MISP contact)
# ---------------------------------------------------------------------------


def test_exhausted_budget_skips_without_contacting_virustotal_or_misp(collector, ledger_path: Path, caplog) -> None:
    _write_ledger(ledger_path, used=400)
    with caplog.at_level(logging.INFO):
        out = collector.collect(limit=50, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True
    assert out["skip_reason_class"] == "virustotal_daily_budget"
    assert collector._test_calls == []
    collector.misp_writer.session.post.assert_not_called()
    assert any("[VT-QUOTA]" in r.getMessage() for r in caplog.records)


def test_exhausted_budget_without_misp_push_returns_empty_list(collector, ledger_path: Path) -> None:
    _write_ledger(ledger_path, used=400)
    assert collector.collect(limit=50, push_to_misp=False) == []
    assert collector._test_calls == []


@pytest.mark.parametrize(
    "limit, baseline, per_run_env, used, expected",
    [
        (None, True, None, 0, 60),  # baseline passes no limit: the per-run cap applies
        (5, False, None, 0, 5),  # task limit below the cap
        (200, False, "10", 0, 10),  # operator lowered the per-run cap
        (200, False, None, 397, 3),  # only three lookups left today
    ],
)
def test_lookups_per_run_are_bounded_by_cap_limit_and_remaining_budget(
    collector, ledger_path: Path, monkeypatch, limit, baseline, per_run_env, used, expected
) -> None:
    if per_run_env is not None:
        monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN", per_run_env)
    _write_ledger(ledger_path, used=used)
    wanted: List[int] = []

    def fake_candidates(n: int, budget) -> List[str]:
        wanted.append(n)
        return []

    monkeypatch.setattr(collector, "_candidate_hashes", fake_candidates)
    out = collector.collect(limit=limit, push_to_misp=True, baseline=baseline)
    assert wanted == [expected]
    assert out["success"] is True and out["count"] == 0 and not out.get("skipped")


# ---------------------------------------------------------------------------
# Candidate selection
# ---------------------------------------------------------------------------


def test_candidates_come_from_misp_sha256_attributes_minus_the_ledger_memory(collector, ledger_path: Path) -> None:
    _write_ledger(ledger_path, looked_up={H1: "not_found"})
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2, "abc", "0" * 32, H2.upper())
    from collectors.virustotal_budget import VirusTotalBudget

    out = collector._candidate_hashes(10, VirusTotalBudget())
    assert out == [H2]  # H1 already looked up; "abc" and the md5 are not sha256; H2 deduplicated
    payload = collector.misp_writer.session.post.call_args.kwargs["json"]
    assert payload["type"] == "sha256"
    assert payload["tags"] == ["!source:VirusTotal"]
    assert payload["timestamp"] == "30d"
    assert payload["returnFormat"] == "json"


def test_candidate_pages_stop_once_enough_hashes_are_collected(collector, ledger_path: Path, monkeypatch) -> None:
    from collectors import vt_collector as mod
    from collectors.virustotal_budget import VirusTotalBudget

    monkeypatch.setattr(mod, "MISP_CANDIDATE_PAGE_SIZE", 2)
    collector.misp_writer.session.post.side_effect = [_misp_rows(H1, H2), _misp_rows(H3, H4), _misp_rows()]
    assert collector._candidate_hashes(3, VirusTotalBudget()) == [H1, H2, H3]
    assert collector.misp_writer.session.post.call_count == 2


def test_candidate_listing_retries_transient_misp_errors(collector, monkeypatch) -> None:
    from collectors import collector_utils
    from collectors.virustotal_budget import VirusTotalBudget

    monkeypatch.setattr(collector_utils.time, "sleep", lambda s: None)
    collector.misp_writer.session.post.side_effect = [
        requests.exceptions.ConnectionError("blip"),
        FakeResponse(503, {}),
        _misp_rows(H1),
    ]
    assert collector._candidate_hashes(5, VirusTotalBudget()) == [H1]
    assert collector.misp_writer.session.post.call_count == 3


def test_candidate_listing_gives_up_after_the_retry_budget(collector, monkeypatch) -> None:
    from collectors import collector_utils

    monkeypatch.setattr(collector_utils.time, "sleep", lambda s: None)
    collector.misp_writer.session.post.return_value = FakeResponse(503, {})
    out = collector.collect(limit=10, push_to_misp=True)
    assert out.get("skipped") is True and out["skip_reason_class"] == "virustotal_candidates_unavailable"
    assert collector.misp_writer.session.post.call_count == 4  # first attempt + MAX_RETRIES
    assert collector._test_calls == []


def test_non_transient_misp_http_error_is_not_retried(collector, monkeypatch) -> None:
    from collectors import collector_utils

    monkeypatch.setattr(collector_utils.time, "sleep", lambda s: None)
    collector.misp_writer.session.post.return_value = FakeResponse(403, {})
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["skip_reason_class"] == "virustotal_candidates_unavailable"
    assert collector.misp_writer.session.post.call_count == 1


def test_misp_failure_while_listing_candidates_is_a_skip_not_a_failure(collector) -> None:
    collector.misp_writer.session.post.side_effect = requests.exceptions.ConnectionError("misp down")
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True
    assert out["skip_reason_class"] == "virustotal_candidates_unavailable"
    assert collector._test_calls == []


def test_misp_failure_without_push_propagates(collector) -> None:
    collector.misp_writer.session.post.side_effect = requests.exceptions.ConnectionError("misp down")
    with pytest.raises(requests.exceptions.ConnectionError):
        collector.collect(limit=10, push_to_misp=False)


def test_no_candidates_is_a_zero_count_success(collector) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows()
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out["count"] == 0 and not out.get("skipped")
    assert collector._test_calls == []
    collector.misp_writer.push_items.assert_not_called()


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------


def test_lookup_outcomes_200_404_429_and_the_ledger(collector, ledger_path: Path, caplog) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2, H3, H4)
    collector._test_responses.update(
        {H1: FakeResponse(200, _vt_file(H1)), H2: FakeResponse(404, {}), H3: FakeResponse(429, {})}
    )
    with caplog.at_level(logging.INFO):
        out = collector.collect(limit=10, push_to_misp=True)

    # H4 was never requested: the 429 stopped the run.
    assert collector._test_calls == [H1, H2, H3]
    pushed = collector.misp_writer.push_items.call_args.args[0]
    assert [i["value"] for i in pushed] == [H1]
    item = pushed[0]
    assert item["indicator_type"] == "hash" and item["tag"] == "virustotal"
    assert item["first_seen"] == "2023-11-14T22:13:20+00:00"
    assert item["threat_label"] == "trojan.emotet"
    assert isinstance(item["zone"], list) and item["zone"]  # zone detection ran (conservative keyword set)

    assert out["success"] is True and out["count"] == 1 and not out.get("skipped")
    assert out["vt_lookups"] == 2 and out["vt_enriched"] == 1 and out["vt_unknown"] == 1
    assert out["vt_stopped"] == "rate_limited"
    assert out["vt_budget_remaining"] == 0

    on_disk = json.loads(ledger_path.read_text())
    assert on_disk["looked_up"] == {H1: "ok", H2: "not_found"}
    assert on_disk["exhausted"] is True and on_disk["used"] == 400
    quota = [r.getMessage() for r in caplog.records if "[VT-QUOTA]" in r.getMessage()]
    assert any("exhausted" in m for m in quota)
    assert any("run finished" in m and "stopped early: rate_limited" in m for m in quota)


def test_429_before_any_success_is_skipped_rate_limited_and_persisted(collector, ledger_path: Path) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2)
    collector._test_responses[H1] = FakeResponse(429, {})
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True
    assert out["skip_reason_class"] == "virustotal_rate_limited"
    assert collector._test_calls == [H1]
    assert json.loads(ledger_path.read_text())["exhausted"] is True
    # The next run on the same day does not contact VirusTotal at all.
    collector._test_calls.clear()
    again = collector.collect(limit=10, push_to_misp=True)
    assert again["skip_reason_class"] == "virustotal_daily_budget"
    assert collector._test_calls == []


def test_lookups_counted_persist_across_runs(collector, ledger_path: Path) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2)
    collector._test_responses.update({H1: FakeResponse(200, _vt_file(H1)), H2: FakeResponse(404, {})})
    collector.collect(limit=10, push_to_misp=True)
    assert json.loads(ledger_path.read_text())["used"] == 2
    # Second run: both hashes are remembered, nothing is looked up again.
    collector._test_calls.clear()
    out = collector.collect(limit=10, push_to_misp=True)
    assert collector._test_calls == []
    assert out["count"] == 0 and json.loads(ledger_path.read_text())["used"] == 2


def test_200_without_a_usable_object_keeps_the_hash_eligible(collector, ledger_path: Path) -> None:
    """A truncated body or an unexpected shape must not exclude the hash forever (it is retried later)."""

    class BrokenJSON(FakeResponse):
        def json(self) -> Any:
            raise ValueError("truncated")

    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2, H3)
    collector._test_responses.update(
        {
            H1: BrokenJSON(200, {}),
            H2: FakeResponse(200, {"data": {"id": H2, "attributes": {}}}),  # no sha256 → _process_file keeps id
            H3: FakeResponse(200, {"data": {}}),  # empty object
        }
    )
    out = collector.collect(limit=10, push_to_misp=True)
    on_disk = json.loads(ledger_path.read_text())
    assert H1 not in on_disk["looked_up"] and H3 not in on_disk["looked_up"]
    assert on_disk["looked_up"][H2] == "ok"  # a minimal object still yields an item
    assert on_disk["used"] == 3  # the quota was spent either way
    assert out["vt_lookup_errors"] == 2 and out["vt_enriched"] == 1


def test_enriched_hash_is_remembered_only_after_the_misp_push_succeeded(collector, ledger_path: Path) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2)
    collector._test_responses.update({H1: FakeResponse(200, _vt_file(H1)), H2: FakeResponse(200, _vt_file(H2))})
    collector.misp_writer.push_items.return_value = (1, 1)  # one attribute failed, the writer cannot say which
    out = collector.collect(limit=10, push_to_misp=True)
    on_disk = json.loads(ledger_path.read_text())
    assert H1 not in on_disk["looked_up"] and H2 not in on_disk["looked_up"]
    assert on_disk["used"] == 2  # the quota was spent
    assert out["count"] == 2 and out["vt_enriched"] == 2
    pushed = collector.misp_writer.push_items.call_args.args[0]
    assert all("_vt_lookup_sha256" not in i for i in pushed)
    # Next run: both hashes are looked up again (and remembered once the push succeeds).
    collector._test_calls.clear()
    collector.misp_writer.push_items.return_value = (2, 0)
    collector.collect(limit=10, push_to_misp=True)
    assert collector._test_calls == [H1, H2]
    assert json.loads(ledger_path.read_text())["looked_up"] == {H1: "ok", H2: "ok"}


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("misp down"),
        requests.exceptions.ReadTimeout("misp slow"),
    ],
)
def test_misp_outage_during_the_push_is_a_skip_so_airflow_does_not_repeat_the_lookups(
    collector, ledger_path: Path, error
) -> None:
    """A failed task is retried by Airflow (retries=2): three attempts would spend the same lookups three times."""
    collector.misp_writer.session.post.return_value = _misp_rows(H1)
    collector._test_responses[H1] = FakeResponse(200, _vt_file(H1))
    collector.misp_writer.push_items.side_effect = error
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True
    assert out["skip_reason_class"] == "virustotal_misp_unavailable"
    on_disk = json.loads(ledger_path.read_text())
    assert on_disk["used"] == 1 and on_disk["looked_up"] == {}, "the lookup is counted, the hash stays eligible"


def test_a_code_defect_in_the_push_is_still_a_failure(collector, ledger_path: Path) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1)
    collector._test_responses[H1] = FakeResponse(200, _vt_file(H1))
    collector.misp_writer.push_items.side_effect = TypeError("unexpected keyword")
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is False and not out.get("skipped"), "only transient MISP errors are skips"
    assert json.loads(ledger_path.read_text())["used"] == 1


def test_every_lookup_passes_the_limiter_once_and_is_never_retried_inside_the_http_helper(collector) -> None:
    """A retry inside the helper bypasses the 4-per-minute limiter and is not counted against the budget."""
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2, H3)
    collector._test_responses.update({H1: FakeResponse(200, _vt_file(H1)), H2: FakeResponse(503, {})})
    collector.collect(limit=10, push_to_misp=True)
    assert [k["max_rate_limit_retries"] for k in collector._test_request_kwargs] == [0, 0, 0]
    assert collector.rate_limiter.wait_if_needed.call_count == 3


@pytest.mark.parametrize(
    "bad",
    [
        requests.exceptions.ChunkedEncodingError("truncated"),
        requests.exceptions.ContentDecodingError("gzip"),
        FakeResponse(200, []),
        FakeResponse(200, "text"),
        FakeResponse(200, {"data": ["not", "an", "object"]}),
    ],
)
def test_a_broken_answer_is_counted_and_the_run_continues(collector, ledger_path: Path, bad) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2)
    collector._test_responses.update({H1: bad, H2: FakeResponse(200, _vt_file(H2))})
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out["count"] == 1 and not out.get("skipped")
    assert out["vt_lookup_errors"] == 1 and out["vt_enriched"] == 1
    assert json.loads(ledger_path.read_text())["looked_up"] == {H2: "ok"}, "the broken hash stays eligible"


def test_ledger_is_written_during_the_run_so_a_killed_task_stays_accounted(collector, ledger_path: Path) -> None:
    """Airflow's execution timeout raises a BaseException: no ``except Exception`` and no final save runs."""
    from collectors import vt_collector as mod

    hashes = [f"{i:064x}" for i in range(1, 31)]
    collector.misp_writer.session.post.return_value = _misp_rows(*hashes)

    class Killed(BaseException):
        pass

    collector._test_responses[hashes[24]] = Killed("task timeout")  # raised on the 25th lookup
    real = mod.request_with_rate_limit_retries

    def killing(method: str, url: str, **kwargs: Any):
        resp = collector._test_responses.get(url.rsplit("/", 1)[-1])
        if isinstance(resp, BaseException):
            raise resp
        return real(method, url, **kwargs)

    mod.request_with_rate_limit_retries = killing
    try:
        with pytest.raises(Killed):
            collector.collect(limit=30, push_to_misp=True)
    finally:
        mod.request_with_rate_limit_retries = real
    on_disk = json.loads(ledger_path.read_text())
    assert on_disk["used"] == 20, "24 lookups were made; the ledger holds the last periodic save (every 10)"
    assert len(on_disk["looked_up"]) == 20, "hashes unknown to VirusTotal are remembered as the run goes"


def test_per_run_cap_is_bounded_by_what_fits_in_the_task_timeout(monkeypatch, caplog) -> None:
    from collectors import virustotal_budget as vb

    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN", "500")
    with caplog.at_level(logging.WARNING):
        assert vb.max_lookups_per_run() == vb.MAX_LOOKUPS_PER_RUN_CEILING == 200
    assert any("[VT-QUOTA]" in r.getMessage() and "exceeds" in r.getMessage() for r in caplog.records)
    monkeypatch.setenv("EDGEGUARD_VIRUSTOTAL_MAX_LOOKUPS_PER_RUN", "200")
    assert vb.max_lookups_per_run() == 200


def test_description_and_zone_text_use_the_label_virustotal_returns(collector) -> None:
    item = collector._process_file(_vt_file(H1)["data"])
    assert "Threat: trojan.emotet" in item["description"], "suggested_threat_label, not a non-existent attribute"
    assert item["threat_label"] == "trojan.emotet"


def test_without_misp_push_delivered_items_are_remembered(collector, ledger_path: Path) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1)
    collector._test_responses[H1] = FakeResponse(200, _vt_file(H1))
    out = collector.collect(limit=10, push_to_misp=False)
    assert [i["value"] for i in out] == [H1] and "_vt_lookup_sha256" not in out[0]
    assert json.loads(ledger_path.read_text())["looked_up"] == {H1: "ok"}


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_key_is_skipped_as_auth_denied(collector, status: int) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1)
    collector._test_responses[H1] = FakeResponse(status, {})
    out = collector.collect(limit=10, push_to_misp=True)
    assert out["success"] is True and out.get("skipped") is True
    assert out["skip_reason_class"] == "virustotal_auth_denied"


def test_consecutive_transport_errors_stop_the_run_but_keep_results(collector) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1, H2, H3, H4, "e" * 64)
    collector._test_responses.update(
        {
            H1: FakeResponse(200, _vt_file(H1)),
            H2: requests.exceptions.ConnectionError("x"),
            H3: requests.exceptions.Timeout("y"),
            H4: FakeResponse(503, {}),
        }
    )
    out = collector.collect(limit=10, push_to_misp=True)
    assert collector._test_calls == [H1, H2, H3, H4]  # stopped after three consecutive errors
    assert out["success"] is True and out["count"] == 1
    assert out["vt_stopped"] == "http_errors" and out["vt_lookup_errors"] == 3


def test_without_misp_push_items_are_returned(collector) -> None:
    collector.misp_writer.session.post.return_value = _misp_rows(H1)
    collector._test_responses[H1] = FakeResponse(200, _vt_file(H1))
    out = collector.collect(limit=10, push_to_misp=False)
    assert isinstance(out, list) and [i["value"] for i in out] == [H1]
    collector.misp_writer.push_items.assert_not_called()


# ---------------------------------------------------------------------------
# Factual guard: no synthetic indicators, no premium-only endpoints
# ---------------------------------------------------------------------------


def test_collector_has_no_test_hash_fallback_and_no_search_feed_queries() -> None:
    src = (SRC / "collectors" / "vt_collector.py").read_text()
    for test_hash in (
        "44d88612fea8a8f36de82e1278abb02f",  # EICAR
        "098f6bcd4621d373cade4e832627b4f6",  # md5("test")
        "5d41402abc4b2a76b9719d911017c592",  # md5("hello")
        "5ebe2294ecd0e0f08eab7690d2a6ee69",  # md5("secret")
    ):
        assert test_hash not in src, "synthetic test hashes must never be published as threat indicators"
    assert "type:file+tag:malware" not in src and "type:url+tag:malware" not in src
    assert "/search" not in src, "Intelligence search is a premium endpoint; the free tier supports lookups only"


def test_ledger_default_path_follows_the_state_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from collectors import virustotal_budget as vb

    monkeypatch.delenv("EDGEGUARD_VIRUSTOTAL_BUDGET_PATH", raising=False)
    monkeypatch.setenv("EDGEGUARD_STATE_DIR", str(tmp_path))
    assert vb.ledger_path() == os.path.join(str(tmp_path), "virustotal_daily_budget.json")
    monkeypatch.delenv("EDGEGUARD_STATE_DIR")
    assert vb.ledger_path().endswith(os.path.join("state", "virustotal_daily_budget.json"))
