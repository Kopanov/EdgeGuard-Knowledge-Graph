"""Failure policy of the Feodo Tracker and SSL Blacklist downloads: an upstream outage is a skipped task.

Both collectors used to turn every exception into ``success=False``. ``run_collector_with_metrics``
fails a task on that status, so a timeout or an HTTP 503 at abuse.ch made the Airflow task red,
while the same outage on other feeds is classified as a transient external error (task skipped,
alert sent). The collectors now re-raise transient errors for that classifier and keep
``success=False`` for what needs an operator.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest
import requests
from stub_cleanup import dag_module_import

from collector_failure_alerts import is_transient_external_error


class Resp:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers: dict = {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}", response=self)  # type: ignore[arg-type]


FEODO_CSV = (
    '"first_seen_utc","dst_ip","dst_port","c2_status","last_online","malware"\r\n'
    '"2024-05-01 10:00:00","203.0.113.10","443","offline","2024-06-01","Emotet"\r\n'
)
SSLBL_CSV = "# comment\r\nListingdate,SHA1,Listingreason\r\n2024-05-01 10:00:00,0123456789abcdef0123456789abcdef01234567,Dridex C&C\r\n"


@pytest.fixture(params=["feodo", "sslbl"])
def feed(request, monkeypatch):
    """(collector, calls, set_answer) for each of the two feeds, with fresh breakers and no sleeps."""
    from collectors import collector_utils
    from collectors import finance_feed_collector as mod
    from resilience import CircuitBreaker

    calls: List[str] = []
    box: dict = {"answer": Resp(200, FEODO_CSV if request.param == "feodo" else SSLBL_CSV)}

    def fake_request(method: str, url: str, **kwargs: Any):
        calls.append(url)
        answer = box["answer"]
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(mod, "request_with_rate_limit_retries", fake_request)
    monkeypatch.setattr(collector_utils.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod, "FEODO_CIRCUIT_BREAKER", CircuitBreaker("feodo_test", failure_threshold=3))
    monkeypatch.setattr(mod, "SSLBL_CIRCUIT_BREAKER", CircuitBreaker("sslbl_test", failure_threshold=3))
    monkeypatch.setattr(mod.FEODO_RATE_LIMITER, "wait_if_needed", lambda: None)
    monkeypatch.setattr(mod.SSLBL_RATE_LIMITER, "wait_if_needed", lambda: None)
    writer = MagicMock()
    writer.push_indicators.return_value = (1, 0)
    cls = mod.FeodoCollector if request.param == "feodo" else mod.SSLBlacklistCollector
    breaker = lambda: mod.FEODO_CIRCUIT_BREAKER if request.param == "feodo" else mod.SSLBL_CIRCUIT_BREAKER  # noqa: E731
    return request.param, cls(misp_writer=writer), calls, box, breaker, mod


def test_healthy_download_still_succeeds(feed) -> None:
    name, collector, calls, _box, _breaker, _mod = feed
    status = collector.collect(push_to_misp=True)
    assert status["success"] is True and status["count"] == 1 and status["source"] == name
    assert len(calls) == 1


@pytest.mark.parametrize("code", [429, 500, 502, 503, 504, 520])
def test_http_429_and_5xx_are_raised_as_transient_and_not_multiplied(feed, code) -> None:
    _name, collector, calls, box, breaker, mod = feed
    box["answer"] = Resp(code, "upstream trouble")
    with pytest.raises(mod.FeedTransientError) as exc_info:
        collector.collect(push_to_misp=True)
    assert is_transient_external_error(exc_info.value), "run_collector_with_metrics must classify it as transient"
    assert len(calls) == 1, (
        "the HTTP helper retries these codes itself; the transport-retry decorator must not repeat it"
    )
    assert breaker().get_status()["failure_count"] == 1
    collector.misp_writer.push_indicators.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ReadTimeout("read timed out"),
        requests.exceptions.ConnectionError("connection refused"),
        requests.exceptions.ChunkedEncodingError("truncated"),
    ],
)
def test_transport_errors_are_retried_then_raised_as_transient(feed, error) -> None:
    _name, collector, calls, box, breaker, _mod = feed
    box["answer"] = error
    with pytest.raises(type(error)):
        collector.collect(push_to_misp=True)
    assert len(calls) == 4, "first attempt + 3 transport retries"
    assert breaker().get_status()["failure_count"] == 1


def test_a_permanent_http_error_is_a_failed_status_when_pushing_and_raises_otherwise(feed) -> None:
    name, collector, _calls, box, _breaker, _mod = feed
    box["answer"] = Resp(404, "gone")
    status = collector.collect(push_to_misp=True)
    assert status["success"] is False and status["source"] == name and not status.get("skipped")
    with pytest.raises(requests.exceptions.HTTPError):
        collector.collect(push_to_misp=False)


@pytest.mark.parametrize("code", [401, 403])
def test_access_denied_is_a_skip(feed, code) -> None:
    name, collector, _calls, box, breaker, _mod = feed
    box["answer"] = Resp(code, "forbidden")
    status = collector.collect(push_to_misp=True)
    assert status["success"] is True and status.get("skipped") is True
    assert status["skip_reason_class"] == f"{name}_auth_denied"
    assert breaker().get_status()["failure_count"] == 0


def test_open_circuit_breaker_is_a_skip_not_a_failed_task(feed) -> None:
    name, collector, calls, box, breaker, _mod = feed
    box["answer"] = Resp(503, "down")
    for _ in range(3):
        with pytest.raises(_mod.FeedTransientError):
            collector.collect(push_to_misp=True)
    assert breaker().can_execute() is False
    calls.clear()
    status = collector.collect(push_to_misp=True)
    assert status["success"] is True and status.get("skipped") is True
    assert status["skip_reason_class"] == f"{name}_circuit_breaker_open"
    assert calls == [], "no request while the breaker is open"
    assert collector.collect(push_to_misp=False) == []


def test_a_code_defect_is_not_classified_as_transient(feed, monkeypatch) -> None:
    name, collector, _calls, _box, _breaker, mod = feed
    monkeypatch.setattr(mod, "detect_zones_from_text", lambda _t: (_ for _ in ()).throw(TypeError("defect")))
    status = collector.collect(push_to_misp=True)
    assert status["success"] is False and "defect" in status["error"], "a defect fails the task; it is not skipped"
    with pytest.raises(TypeError):
        collector.collect(push_to_misp=False)


# ---------------------------------------------------------------------------
# Through the real DAG wrapper: the task outcome
# ---------------------------------------------------------------------------


def _import_dag_module():
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            # airflow itself, not sibling modules such as ``airflow_client`` that other test modules
            # patch by object identity
            or key == "airflow"
            or key.startswith("airflow.")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    dags = os.path.join(os.path.dirname(__file__), "..", "dags")
    if dags not in sys.path:
        sys.path.insert(0, dags)
    return importlib.import_module("edgeguard_pipeline")


def test_upstream_outage_leaves_the_airflow_task_green_and_skipped(feed) -> None:
    name, collector, _calls, box, _breaker, _mod = feed
    with dag_module_import():
        ep = _import_dag_module()
    box["answer"] = Resp(503, "down")
    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", MagicMock()) as slack,
        patch.object(ep, "set_source_health", MagicMock()) as set_health,
        patch.object(ep, "record_dag_run", MagicMock()),
        patch.object(ep, "record_collection", MagicMock()),
        patch.object(ep, "record_collection_duration", MagicMock()),
        patch.object(ep, "record_collector_skip", MagicMock()) as record_skip,
        patch.object(ep, "record_pipeline_error", MagicMock()),
        patch.object(ep, "record_error", MagicMock()),
        patch("baseline_lock.baseline_skip_reason", lambda **_kw: None, create=True),
    ):
        result = ep.run_collector_with_metrics(name, type(collector), MagicMock(), limit=10)
    assert result["success"] is True and result["skipped"] is True
    assert result["skip_reason_class"] == "transient_external_error"
    set_health.assert_called_with(name, "global", False)
    assert any(call.args[1] == "transient_external_error" for call in record_skip.call_args_list)
    assert slack.called, "the outage is still reported through the alert path"
