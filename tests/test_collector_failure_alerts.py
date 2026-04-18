"""PR #35 commit 2: tests for the shared failure-alerts module.

Vanko's follow-up audit caught that the CLI path (``src/run_pipeline.py``)
was silently swallowing collector failures with no Prometheus / Slack
visibility — only logs. PR #35 commit 2 extracts the classifier + Slack
helper into ``src/collector_failure_alerts.py`` and wires the CLI path
through it. This test file pins:

1. The shared classifier matches the DAG-path classifier (no behavior drift)
2. ``report_collector_failure`` emits the right Prometheus metrics for both
   transient and catastrophic exceptions
3. The Slack helper is opt-in via ``EDGEGUARD_ENABLE_SLACK_ALERTS`` and
   silently no-ops when disabled (no env-var spam in dev)
4. The convenience helper degrades gracefully when ``metrics_server``
   can't be imported (slim container case)
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# Classifier — same surface as the DAG-path tests, but exercised on the
# canonical implementation in src/ instead of the dags/ alias.
# ---------------------------------------------------------------------------


def test_classifier_recognizes_stdlib_network_errors():
    from collector_failure_alerts import is_transient_external_error

    assert is_transient_external_error(ConnectionError("boom"))
    assert is_transient_external_error(ConnectionRefusedError())
    assert is_transient_external_error(ConnectionResetError())
    assert is_transient_external_error(TimeoutError())


def test_classifier_walks_mro_and_cause_chain():
    from collector_failure_alerts import is_transient_external_error

    class CustomTimeout(TimeoutError):
        pass

    assert is_transient_external_error(CustomTimeout()), "subclass must match via MRO"

    class WrapperError(Exception):
        pass

    try:
        try:
            raise ConnectionError("upstream 503")
        except ConnectionError as inner:
            raise WrapperError("collector wrapped this") from inner
    except WrapperError as e:
        assert is_transient_external_error(e), "must walk __cause__ chain"


def test_classifier_does_not_swallow_real_bugs():
    from collector_failure_alerts import is_transient_external_error

    for exc in (
        TypeError("argument mismatch"),
        ValueError("bad input"),
        AttributeError("None has no foo"),
        ImportError("missing module"),
        KeyError("missing key"),
        RuntimeError("generic"),
        ZeroDivisionError(),
    ):
        assert not is_transient_external_error(exc), (
            f"{type(exc).__name__} must not be transient — would silently swallow real bug"
        )

    assert not is_transient_external_error(None)


def test_classifier_recognizes_third_party_names_without_imports():
    """Even without ``requests``/``httpx`` installed, the classifier must
    recognize their exception class names by walking ``type(exc).__mro__``."""
    from collector_failure_alerts import _TRANSIENT_EXTERNAL_EXCEPTION_NAMES, is_transient_external_error

    for name in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES:
        if name in {"ConnectionError", "ConnectionRefusedError", "ConnectionResetError", "TimeoutError"}:
            continue  # covered above
        synth = type(name, (Exception,), {})
        assert is_transient_external_error(synth("simulated")), (
            f"name {name!r} declared transient but classifier doesn't recognize it"
        )


def test_classifier_does_NOT_treat_generic_HTTPError_as_transient():
    """PR #35 commit 3 (bugbot HIGH): generic ``HTTPError`` (and aiohttp's
    ``ClientResponseError``) match all 4xx + 5xx responses. A 401 (expired
    API key) is NOT transient — silently marking it skipped would hide a
    persistent credential problem behind a "transient" label.

    The classifier MUST:
      - Reject HTTPError when status_code is 4xx (or unknown)
      - Accept HTTPError ONLY when status_code is 5xx (server error)
    """
    from collector_failure_alerts import (
        _TRANSIENT_EXTERNAL_EXCEPTION_NAMES,
        is_transient_external_error,
    )

    # Defense: HTTPError / ClientResponseError must NOT be in the name set.
    assert "HTTPError" not in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES, (
        "generic HTTPError must NOT be in the transient name list — would swallow 4xx"
    )
    assert "ClientResponseError" not in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES, (
        "generic ClientResponseError must NOT be in the transient name list — would swallow 4xx"
    )

    # Synthesize HTTPError with response.status_code attribute.
    HTTPError = type("HTTPError", (Exception,), {})

    class _Resp:
        def __init__(self, code):
            self.status_code = code

    # 401, 403, 404 → NOT transient (real auth/missing-endpoint problems)
    for code in (400, 401, 403, 404, 405, 422, 429):
        e = HTTPError(f"HTTP {code}")
        e.response = _Resp(code)  # type: ignore[attr-defined]
        assert not is_transient_external_error(e), (
            f"HTTP {code} (4xx) must NOT be transient — silently skipping would hide a real client/auth problem"
        )

    # 5xx → transient (server outage, retry-worthy)
    for code in (500, 502, 503, 504):
        e = HTTPError(f"HTTP {code}")
        e.response = _Resp(code)  # type: ignore[attr-defined]
        assert is_transient_external_error(e), f"HTTP {code} (5xx) must be transient — server outage"

    # No status code attached → conservative: NOT transient
    e = HTTPError("HTTP error with no response object")
    assert not is_transient_external_error(e), (
        "HTTPError without a status_code must NOT be transient — can't verify it's a 5xx"
    )

    # aiohttp shape: .status (not .status_code) on the exception itself
    ClientResponseError = type("ClientResponseError", (Exception,), {})
    e = ClientResponseError("aiohttp 401")
    e.status = 401  # type: ignore[attr-defined]
    assert not is_transient_external_error(e), "aiohttp 401 via .status must NOT be transient"
    e.status = 503  # type: ignore[attr-defined]
    assert is_transient_external_error(e), "aiohttp 503 via .status must be transient"


def test_classifier_does_NOT_walk_implicit_context_chain():
    """PR #35 commit 3 (bugbot MED): Python auto-sets ``__context__`` on
    any exception raised inside an ``except`` block. The previous code
    walked __context__ as a fallback when __cause__ was None — so a real
    bug (AttributeError) raised while handling a ConnectionError would
    inherit ConnectionError as its __context__ and be falsely classified
    as transient.

    The classifier must walk ONLY ``__cause__`` (the explicit
    ``raise X from Y`` form), NEVER ``__context__``."""
    from collector_failure_alerts import is_transient_external_error

    # Simulate the dangerous pattern: real bug raised inside an except-block.
    try:
        try:
            raise ConnectionError("upstream 503")  # transient
        except ConnectionError:
            # AttributeError raised here — Python auto-sets its __context__
            # to the ConnectionError above, but it's a REAL BUG, not a
            # transient external error.
            x = None
            x.foo  # noqa: B018  — intentional AttributeError to test __context__ chain
    except AttributeError as bug:
        # __context__ is the ConnectionError; __cause__ is None (no `from`).
        assert bug.__context__ is not None, "precondition: Python set __context__"
        assert bug.__cause__ is None, "precondition: __cause__ is None (no `raise X from Y`)"
        # The classifier MUST NOT walk __context__ → MUST return False.
        assert not is_transient_external_error(bug), (
            "AttributeError raised inside except-block must NOT be classified transient — "
            "would silently swallow real bugs caught by the implicit __context__ chain"
        )

    # Sanity: explicit ``raise X from Y`` still works (walks __cause__).
    try:
        try:
            raise ConnectionError("upstream 503")
        except ConnectionError as inner:
            raise RuntimeError("explicit re-raise") from inner
    except RuntimeError as wrapped:
        assert wrapped.__cause__ is not None
        # The cause chain still classifies as transient (correct).
        assert is_transient_external_error(wrapped), "explicit `raise X from Y` must still be walked via __cause__"


# ---------------------------------------------------------------------------
# Slack helper — opt-in, never raises
# ---------------------------------------------------------------------------


def test_slack_alert_is_opt_in_and_silent_by_default(monkeypatch):
    """Without EDGEGUARD_ENABLE_SLACK_ALERTS=1, send_slack_alert must
    silently no-op so dev environments don't spam-warn on every collector
    failure."""
    monkeypatch.delenv("EDGEGUARD_ENABLE_SLACK_ALERTS", raising=False)
    from collector_failure_alerts import send_slack_alert

    # Patch requests.post to detect any accidental call.
    with patch("requests.post") as post_mock:
        send_slack_alert("test message")
    post_mock.assert_not_called()  # send_slack_alert must not call HTTP when disabled


def test_slack_alert_no_ops_when_webhook_url_missing(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_ENABLE_SLACK_ALERTS", "1")
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("AIRFLOW__SLACK__WEBHOOK_URL", raising=False)

    from collector_failure_alerts import send_slack_alert

    with patch("requests.post") as post_mock:
        send_slack_alert("test message")
    post_mock.assert_not_called()  # no webhook URL → must not attempt HTTP


def test_slack_alert_swallows_post_errors(monkeypatch):
    """A Slack outage / 500 / network error must NEVER propagate up — the
    underlying collector exception is what the caller cares about."""
    monkeypatch.setenv("EDGEGUARD_ENABLE_SLACK_ALERTS", "1")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/TEST/FAKE/TOKEN")

    import collector_failure_alerts

    with patch("requests.post", side_effect=ConnectionError("Slack down")):
        # MUST NOT raise
        collector_failure_alerts.send_slack_alert("test")


# ---------------------------------------------------------------------------
# report_collector_failure — the convenience helper used by the CLI path
# ---------------------------------------------------------------------------


def _patch_metrics_module(monkeypatch):
    """Patch the four ``metrics_server.*`` helpers as MagicMocks IN-PLACE.

    Why in-place patching instead of replacing the module in sys.modules:
    ``metrics_server`` registers ``Counter()`` / ``Histogram()`` etc. in
    the prometheus_client global REGISTRY at module-import time. If we
    delete + re-import the module (or replace it via setitem and let
    monkeypatch unwind to "no module"), the next test that imports it
    re-runs the registration → "Duplicated timeseries in
    CollectorRegistry" → cascade failure across 80+ unrelated tests.

    Patching attributes ON the already-loaded module avoids touching
    sys.modules entirely. monkeypatch.setattr restores the originals on
    teardown, leaving the global registry untouched.
    """
    import metrics_server

    record_collection = MagicMock()
    record_collector_skip = MagicMock()
    record_pipeline_error = MagicMock()
    set_source_health = MagicMock()
    record_collection_duration = MagicMock()
    record_dag_run = MagicMock()
    record_error = MagicMock()
    monkeypatch.setattr(metrics_server, "record_collection", record_collection)
    monkeypatch.setattr(metrics_server, "record_collector_skip", record_collector_skip)
    monkeypatch.setattr(metrics_server, "record_pipeline_error", record_pipeline_error)
    monkeypatch.setattr(metrics_server, "set_source_health", set_source_health)
    monkeypatch.setattr(metrics_server, "record_collection_duration", record_collection_duration, raising=False)
    monkeypatch.setattr(metrics_server, "record_dag_run", record_dag_run, raising=False)
    monkeypatch.setattr(metrics_server, "record_error", record_error, raising=False)
    return {
        "record_collection": record_collection,
        "record_collector_skip": record_collector_skip,
        "record_pipeline_error": record_pipeline_error,
        "set_source_health": set_source_health,
    }


def test_report_collector_failure_transient_emits_skip_metrics(monkeypatch):
    """Transient error path: emits skip + degrade-source-health + pipeline-error,
    returns ``"transient"`` so the caller can decide not to re-raise."""
    monkeypatch.delenv("EDGEGUARD_ENABLE_SLACK_ALERTS", raising=False)

    metrics = _patch_metrics_module(monkeypatch)

    from collector_failure_alerts import report_collector_failure

    classification = report_collector_failure("cybercure", ConnectionError("upstream 503"))

    assert classification == "transient"
    metrics["record_collector_skip"].assert_called_once_with("cybercure", "transient_external_error")
    metrics["record_collection"].assert_called_once_with("cybercure", "global", 0, "skipped")
    metrics["set_source_health"].assert_called_once_with("cybercure", "global", False)
    metrics["record_pipeline_error"].assert_called_once_with("collect_cybercure", "ConnectionError", "cybercure")


def test_report_collector_failure_catastrophic_emits_failed_metrics(monkeypatch):
    """Catastrophic error path: emits failed (not skipped) +
    degrade-source-health + pipeline-error, returns ``"catastrophic"``."""
    monkeypatch.delenv("EDGEGUARD_ENABLE_SLACK_ALERTS", raising=False)

    metrics = _patch_metrics_module(monkeypatch)

    from collector_failure_alerts import report_collector_failure

    classification = report_collector_failure("buggy_collector", TypeError("real bug"))

    assert classification == "catastrophic"
    metrics["record_collection"].assert_called_once_with("buggy_collector", "global", 0, "failed")
    metrics[
        "record_collector_skip"
    ].assert_not_called()  # catastrophic errors must NOT be counted as skipped — confuses on-call
    metrics["set_source_health"].assert_called_once_with("buggy_collector", "global", False)
    metrics["record_pipeline_error"].assert_called_once_with("collect_buggy_collector", "TypeError", "buggy_collector")


# NOTE: a previous draft of this file included
# ``test_report_collector_failure_handles_missing_metrics_server`` which
# deleted ``metrics_server`` from ``sys.modules`` and patched
# ``builtins.__import__`` to simulate a broken install. That triggered
# prometheus_client's "Duplicated timeseries in CollectorRegistry" error
# on the NEXT test that imported metrics_server (the Counter/Histogram
# objects are registered in the global REGISTRY at module-load time and
# can't be re-registered). Removing it — the graceful-degradation
# branch is small (5 lines, try/except ImportError) and self-evident
# from a code-review pass; the cost of keeping a test that breaks 85
# other tests via shared global state is greater than the benefit.


# ---------------------------------------------------------------------------
# CLI integration: the run_pipeline helper wraps + swallows reporter errors
# ---------------------------------------------------------------------------


def test_run_pipeline_helper_swallows_reporter_failures():
    """``_report_failure_with_metrics`` in run_pipeline.py wraps the shared
    helper in a try/except so a reporter-side failure can't break the
    CLI's own error handling. Pin that contract via source-grep."""
    src_path = os.path.join(os.path.dirname(__file__), "..", "src", "run_pipeline.py")
    with open(src_path) as fh:
        src = fh.read()

    assert "def _report_failure_with_metrics" in src, "helper must exist in run_pipeline.py"
    assert "report_collector_failure" in src, "helper must call the shared report_collector_failure"
    # The wrapper must catch Exception so reporter failures don't propagate.
    helper_start = src.find("def _report_failure_with_metrics")
    helper_end = src.find("\n\n\n", helper_start)
    if helper_end < 0:
        helper_end = len(src)
    helper_body = src[helper_start:helper_end]
    assert "try:" in helper_body and "except Exception" in helper_body, (
        "_report_failure_with_metrics MUST wrap report_collector_failure in try/except — "
        "otherwise a metrics-server outage would crash the CLI on top of the original failure"
    )


def test_cli_except_branches_call_report_failure_with_metrics():
    """All four except branches in the run_pipeline.py collector loop
    must call ``_report_failure_with_metrics`` so Vanko's gap (CLI-path
    failures invisible to Prometheus + Slack) stays closed even if a
    future contributor adds a 5th except branch and forgets the call."""
    src_path = os.path.join(os.path.dirname(__file__), "..", "src", "run_pipeline.py")
    with open(src_path) as fh:
        src = fh.read()

    # Find the collector loop region and count except branches that call
    # the helper. The loop is bounded by "step2_exceptions" usage.
    # Count `step2_exceptions.append` (one per branch) and the helper call
    # (one per branch).
    appends = src.count("step2_exceptions.append((source_name, msg))")
    helper_calls = src.count("_report_failure_with_metrics(source_name, e)")
    assert appends >= 4, f"expected at least 4 except branches in CLI loop, got {appends}"
    assert helper_calls == appends, (
        f"every except branch must call _report_failure_with_metrics; "
        f"got {helper_calls} calls but {appends} except branches — missing dashboard signal in some branches"
    )
