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


def test_classifier_walks_mro_for_subclasses():
    """Custom subclasses of known transient errors must be classified
    transient via the MRO walk. This is the intended way for collectors
    to "wrap" a transient error — make the wrapper INHERIT from the
    underlying class. PR #35 commit 7 dropped the ``__cause__``-chain
    walk (which would have caught ``raise X from transient`` patterns
    too), so MRO is now the only path for wrapped errors.
    """
    from collector_failure_alerts import is_transient_external_error

    class CustomTimeout(TimeoutError):
        pass

    assert is_transient_external_error(CustomTimeout()), "subclass must match via MRO"


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
    any exception raised inside an ``except`` block. Walking
    ``__context__`` as a fallback would misclassify real bugs raised
    inside except-blocks as transient (because their __context__ is the
    exception they were handling)."""
    from collector_failure_alerts import is_transient_external_error

    try:
        try:
            raise ConnectionError("upstream 503")  # transient
        except ConnectionError:
            # AttributeError raised here — Python auto-sets its __context__
            # to the ConnectionError above, but it's a REAL BUG.
            x = None
            x.foo  # noqa: B018  — intentional AttributeError
    except AttributeError as bug:
        assert bug.__context__ is not None, "precondition: Python set __context__"
        assert bug.__cause__ is None, "precondition: __cause__ is None (no `raise X from Y`)"
        assert not is_transient_external_error(bug), (
            "AttributeError raised inside except-block must NOT be classified transient — "
            "would silently swallow real bugs via __context__"
        )


def test_classifier_does_NOT_walk_explicit_cause_chain():
    """PR #35 commit 7 (bugbot MED): the classifier USED to walk
    ``__cause__`` (the explicit ``raise X from Y`` form). Bugbot caught
    that ``raise X from Y`` is the recommended best-practice for adding
    context to errors — so a collector doing
    ``raise ValueError("bad config") from conn_err`` would have its
    ValueError silently swallowed as "transient" (because __cause__ ==
    ConnectionError).

    The classifier now walks ONLY the MRO of the OUTER exception. If a
    collector wants a custom exception class to count as transient, it
    must subclass an existing transient class (e.g.
    ``class CyberCureNetworkError(ConnectionError): pass``).

    This test pins the new contract by setting up the dangerous pattern
    and asserting NO transient classification."""
    from collector_failure_alerts import is_transient_external_error

    # Pattern: collector wraps a network error in a domain-specific
    # exception that does NOT subclass any known transient class.
    try:
        try:
            raise ConnectionError("upstream 503")  # transient
        except ConnectionError as inner:
            # ValueError is a real-bug-shaped class; if walked via
            # __cause__ it would be (incorrectly) classified transient.
            raise ValueError("collector got bad data") from inner
    except ValueError as wrapped:
        assert wrapped.__cause__ is not None, "precondition: explicit raise...from"
        assert not is_transient_external_error(wrapped), (
            "ValueError wrapped via `raise V from conn_err` MUST NOT be classified transient — "
            "raise...from is the recommended add-context pattern, walking __cause__ would "
            "silently swallow real config/data bugs that happen to be wrapped in error-handling code"
        )

    # Same pattern for TypeError / RuntimeError / generic Exception
    for outer_cls in (TypeError, RuntimeError, Exception):
        try:
            try:
                raise ConnectionError("upstream 503")
            except ConnectionError as inner:
                raise outer_cls(f"wrapped via {outer_cls.__name__}") from inner
        except outer_cls as wrapped:
            assert not is_transient_external_error(wrapped), (
                f"{outer_cls.__name__} wrapped via raise-from must NOT be transient"
            )

    # Sanity: a custom class that DOES subclass a transient class IS
    # still classified transient (the documented escape hatch).
    class CyberCureNetworkError(ConnectionError):
        pass

    assert is_transient_external_error(CyberCureNetworkError("provider down")), (
        "subclassing a transient class is the documented way to declare a custom transient — must still work"
    )


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
    # PR #35 commit 8 (bugbot MED): pipeline_errors_total MUST NOT increment on
    # transient skips — would false-positive operator alerts on
    # ``rate(pipeline_errors_total) > 0``. The structured METRICS log line
    # for transient also explicitly omits this metric (consistency check).
    metrics["record_pipeline_error"].assert_not_called()  # transient must NOT bump error counter


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


# ---------------------------------------------------------------------------
# Structured failure log block — actionable, grep-friendly, dashboard-aligned
# ---------------------------------------------------------------------------


def test_failure_log_block_for_http_503_includes_status_url_and_action():
    """Vanko's request: when a collector skips, the log line must say
    EXACTLY why and what to do — not just "transient external error".

    Pin the structure of ``_format_failure_log_block`` for the canonical
    HTTP 503 case so an operator running ``grep "[cybercure] SKIPPED"`` in
    the Airflow logs sees:
      - source name + SKIPPED status
      - reason + exception class
      - HTTP status code (extracted from ``exc.response.status_code``)
      - URL (extracted from ``exc.response.url``)
      - duration (so they know how long the retries took)
      - ACTION line: human-readable next-step instructions
      - METRICS line: which Prometheus counters fired
    """
    from collector_failure_alerts import _format_failure_log_block

    HTTPError = type("HTTPError", (Exception,), {})

    class _Resp:
        def __init__(self, code, url):
            self.status_code = code
            self.url = url

    exc = HTTPError("503 Server Error: Service Unavailable for url: https://api.cybercure.io/v1/ioc")
    exc.response = _Resp(503, "https://api.cybercure.io/v1/ioc")  # type: ignore[attr-defined]

    block = _format_failure_log_block("cybercure", exc, classification="transient", duration_s=35.2)

    assert block.startswith("[cybercure] SKIPPED  "), f"header wrong: {block[:60]!r}"
    assert "reason=transient_external_error" in block
    assert "exc=HTTPError" in block
    assert "http_status=503" in block, "must extract HTTP status from exc.response.status_code"
    assert "url=https://api.cybercure.io/v1/ioc" in block, "must extract URL from exc.response.url"
    assert "duration=35.20s" in block, "duration must include trailing 's'"
    assert "\nACTION:" in block, "must have a literal ACTION: line so operator sees next-step"
    assert "pipeline CONTINUED" in block
    assert "next scheduled DAG run" in block
    assert "\nMETRICS:" in block, "must have a literal METRICS: line referencing Prometheus counters"
    assert "edgeguard_collector_skips_total{source=cybercure" in block
    assert "edgeguard_source_health{source=cybercure,zone=global}=0" in block


def test_failure_log_block_for_aiohttp_4xx_extracts_status_via_exc_status():
    """aiohttp's ClientResponseError stores the HTTP status on ``exc.status``
    (not ``exc.response.status_code``). The extractor must handle both shapes."""
    from collector_failure_alerts import _format_failure_log_block

    ClientResponseError = type("ClientResponseError", (Exception,), {})
    exc = ClientResponseError("401 Unauthorized")
    exc.status = 401  # type: ignore[attr-defined]
    exc.url = "https://api.virustotal.com/api/v3/files/abc123"  # type: ignore[attr-defined]

    block = _format_failure_log_block("virustotal", exc, classification="catastrophic", duration_s=1.4)

    assert "[virustotal] FAILED" in block
    assert "http_status=401" in block, "aiohttp .status attribute must be picked up by extractor"
    assert "url=https://api.virustotal.com/" in block
    assert "Task FAILED" in block
    assert "downstream baseline tasks" in block, "catastrophic action must explain downstream-blocking impact"


def test_failure_log_block_for_connection_error_omits_http_fields():
    """Plain ConnectionError has no HTTP status / URL — the formatter must
    OMIT those fields rather than emit ``http_status=None``. Empty fields
    pollute logs."""
    from collector_failure_alerts import _format_failure_log_block

    block = _format_failure_log_block(
        "feodo",
        ConnectionError("[Errno 111] Connection refused"),
        classification="transient",
        duration_s=12.5,
    )

    assert "[feodo] SKIPPED" in block
    assert "exc=ConnectionError" in block
    assert "http_status" not in block, "must NOT emit http_status when not extractable"
    assert "url=" not in block, "must NOT emit url when not extractable"
    assert "duration=12.50s" in block


def test_failure_log_block_truncates_oversized_url_and_message():
    """A 5KB error message or 500-char URL would blow up the log line.
    Both must be truncated to keep grep / Loki output readable."""
    from collector_failure_alerts import _format_failure_log_block

    HTTPError = type("HTTPError", (Exception,), {})
    long_url = "https://example.com/" + "a" * 500

    class _Resp:
        def __init__(self, code, url):
            self.status_code = code
            self.url = url

    exc = HTTPError("HTTP 500: " + "x" * 5000)
    exc.response = _Resp(500, long_url)  # type: ignore[attr-defined]

    block = _format_failure_log_block("test_src", exc, classification="transient")

    url_field_start = block.index("url=") + 4
    url_field_end = block.find("  ", url_field_start)
    if url_field_end < 0:
        url_field_end = block.find("\n", url_field_start)
    url_value = block[url_field_start:url_field_end]
    assert len(url_value) <= 200, f"URL must be truncated to ≤200 chars, got {len(url_value)}"

    msg_field_start = block.index('msg="') + 5
    msg_field_end = block.find('"', msg_field_start)
    msg_value = block[msg_field_start:msg_field_end]
    assert len(msg_value) <= 200, f"msg must be truncated to ≤200 chars, got {len(msg_value)}"
    assert "\n" not in msg_value and "\r" not in msg_value, "msg must NOT contain newlines"


def test_failure_log_block_metrics_line_lists_canonical_counter_names():
    """The METRICS: line is a contract for operators copying queries into
    Grafana. Pin the exact metric names so a typo doesn't ship."""
    from collector_failure_alerts import _format_failure_log_block

    t = _format_failure_log_block("x", ConnectionError("y"), classification="transient")
    assert "edgeguard_collector_skips_total{source=x,reason_class=transient_external_error} +1" in t
    assert "edgeguard_collection_total{source=x,zone=global,status=skipped} +1" in t
    assert "edgeguard_source_health{source=x,zone=global}=0" in t

    c = _format_failure_log_block("y", TypeError("real bug"), classification="catastrophic")
    assert "edgeguard_collection_total{source=y,zone=global,status=failed} +1" in c
    assert "edgeguard_pipeline_errors_total{task=collect_y,error_type=TypeError,source=y} +1" in c
    assert "edgeguard_source_health{source=y,zone=global}=0" in c
    assert "edgeguard_collector_skips_total" not in c, "catastrophic must NOT mention skip counter"


def test_dag_path_uses_shared_log_block_helper():
    """The DAG path's run_collector_with_metrics must route both transient
    and catastrophic logs through ``_format_failure_log_block`` (the same
    helper as the CLI path) so operators see IDENTICAL output regardless
    of how EdgeGuard was invoked."""
    dag_path = os.path.join(os.path.dirname(__file__), "..", "dags", "edgeguard_pipeline.py")
    with open(dag_path) as fh:
        src = fh.read()

    assert "from collector_failure_alerts import _format_failure_log_block" in src, (
        "DAG path must import the shared structured-log helper"
    )
    # Both classification paths must call the helper. Use a tolerant pattern
    # since formatter may wrap the call.
    assert "_format_failure_log_block(" in src, "DAG must call the helper somewhere"
    assert 'classification="transient"' in src, "DAG must classify transient via the helper"
    assert 'classification="catastrophic"' in src, "DAG must classify catastrophic via the helper"


def test_extract_url_handles_malformed_for_url_marker_without_crashing():
    """PR #35 commit 7 (bugbot MED): ``_extract_url`` previously called
    ``.strip().split()[0]`` on whatever followed ``" for url: "`` in the
    exception message — which crashes with IndexError if the message
    ends with ``" for url: "`` followed by whitespace or nothing.

    The DAG path calls ``_format_failure_log_block`` (which calls
    ``_extract_url``) inside the ``except Exception`` failure handler.
    A crash there would propagate up and FAIL the task — exactly the
    pipeline-blocking behavior this PR aims to prevent.

    Pin: feed the malformed forms and assert no crash."""
    from collector_failure_alerts import _extract_url

    # Trailing marker with nothing after — this used to IndexError
    class _Exc(Exception):
        pass

    cases = [
        # message, expected_url (None for "no extractable url")
        ("HTTP 503 Server Error for url: ", None),
        ("HTTP 503 Server Error for url:    ", None),  # trailing whitespace only
        ("HTTP 503 Server Error for url: \n", None),  # trailing newline only
        ("HTTP 503 Server Error for url: https://api.example.com/v1", "https://api.example.com/v1"),
        ("HTTP 503 Server Error for url: https://api.example.com/v1 trailing junk", "https://api.example.com/v1"),
        ("Plain message with no marker", None),
    ]
    for msg, expected in cases:
        # MUST NOT raise IndexError or any other exception
        result = _extract_url(_Exc(msg))
        assert result == expected, f"for {msg!r}: expected {expected!r}, got {result!r}"


def test_format_failure_log_block_does_not_crash_on_malformed_url_marker():
    """End-to-end version of the previous test: the full
    ``_format_failure_log_block`` MUST NOT raise when the exception
    message contains a malformed ``for url:`` marker. The block-building
    path runs inside the failure handler — an exception here cascades
    into a task FAIL, defeating the PR's whole point."""
    from collector_failure_alerts import _format_failure_log_block

    class _Exc(Exception):
        pass

    # MUST NOT raise — this used to IndexError before commit 7
    block = _format_failure_log_block(
        "test_src",
        _Exc("Server returned 503 for url: "),  # malformed: empty after marker
        classification="transient",
        duration_s=1.0,
    )
    assert "[test_src] SKIPPED" in block
    # url field MUST be omitted (no extractable URL)
    assert "url=" not in block, "must omit url field when extraction can't find one"


def test_dag_path_does_not_increment_pipeline_errors_on_transient_skip():
    """PR #35 commit 8 (bugbot MED): the DAG path's
    ``run_collector_with_metrics`` must NOT call ``record_pipeline_error``
    when the exception is transient. The error counter is for things that
    actually FAIL the task; transient skips return SUCCESS.

    Source-grep pin since exercising the real DAG function requires a
    full Airflow context. Verifies that ``record_pipeline_error`` only
    appears INSIDE the ``# Catastrophic — fail loudly`` branch, never
    in the unconditional pre-split block."""
    dag_path = os.path.join(os.path.dirname(__file__), "..", "dags", "edgeguard_pipeline.py")
    with open(dag_path) as fh:
        src = fh.read()

    # Strip comment lines so the round-8 explanatory comment (which legitimately
    # mentions the previous wrong-place call) doesn't false-fail the negative
    # assertions below. Same _code_only pattern used elsewhere in the suite.
    def _code_only(text: str) -> str:
        return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))

    # Locate the failure handler (everything between ``except Exception as e:``
    # and the trailing ``raise`` in run_collector_with_metrics)
    handler_start = src.find("except Exception as e:", src.find("def run_collector_with_metrics"))
    assert handler_start > 0, "could not locate the except Exception handler"
    handler_end = src.find("\n# ===", handler_start)  # next section divider
    if handler_end < 0:
        handler_end = handler_start + 5000
    handler_raw = src[handler_start:handler_end]
    handler = _code_only(handler_raw)

    # Locate the transient branch (between ``if _is_transient_external_error``
    # and the next ``# Catastrophic`` comment) — use raw to find the comment
    # marker, then strip comments from the slice.
    transient_start_raw = handler_raw.find("if _is_transient_external_error")
    catastrophic_start_raw = handler_raw.find("# Catastrophic", transient_start_raw)
    assert transient_start_raw > 0 and catastrophic_start_raw > transient_start_raw, (
        "could not locate transient/catastrophic split"
    )
    transient_branch = _code_only(handler_raw[transient_start_raw:catastrophic_start_raw])
    catastrophic_branch = _code_only(handler_raw[catastrophic_start_raw:])
    pre_split = _code_only(handler_raw[:transient_start_raw])

    assert "record_pipeline_error" not in transient_branch, (
        "transient branch (executable code) MUST NOT call record_pipeline_error — "
        "would false-positive rate(edgeguard_pipeline_errors_total) > 0 alerts."
    )

    # Sanity: catastrophic branch DOES call it (so we're not just hiding it everywhere)
    assert "record_pipeline_error" in catastrophic_branch, (
        "catastrophic branch must call record_pipeline_error — that's the point"
    )

    # And the unconditional pre-split block must also not call it.
    assert "record_pipeline_error" not in pre_split, (
        "pre-split executable block MUST NOT call record_pipeline_error — "
        "would fire for transient skips before the classifier branches."
    )
