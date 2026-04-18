"""PR #35 regression tests — collector failures must not block the baseline pipeline.

Background
----------
A CyberCure feed outage on 2026-04-18 raised ``ConnectionError`` from inside
``CyberCureCollector.collect()``. The previous ``run_collector_with_metrics``
re-raised every ``Exception``, marking the Airflow task FAILED. The default
``trigger_rule="all_success"`` on downstream baseline tasks
(``build_relationships``, ``run_enrichment_jobs``, ``baseline_complete``)
then blocked the entire pipeline — full_neo4j_sync had ``ALL_DONE`` and
ran, but build_relationships saw upstream_failed and skipped.

User policy: "if a feed fails for an external reason, log + continue, don't
block everything." PR #35 implements this with two complementary fixes:

1. ``_is_transient_external_error`` classifier + graceful-degradation branch
   in ``run_collector_with_metrics``. Network/timeout/HTTP errors → return
   skipped status (success=True), task stays GREEN, Slack alert + Prometheus
   metric still record the failure for visibility.
2. Explicit ``trigger_rule`` on the three downstream baseline tasks so the
   chain has unambiguous semantics regardless of upstream task state.

These tests pin both fixes so a future refactor can't silently regress them.
"""

from __future__ import annotations

import os
import sys

_DAGS = os.path.join(os.path.dirname(__file__), "..", "dags")
_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
for _p in (_DAGS, _SRC):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Transient-error classifier
# ---------------------------------------------------------------------------


def _import_dag_module():
    """Defer import — Airflow may not be installed in every test env.

    Mirrors the cleanup in ``test_edgeguard_collector_contract.py``:
    ``test_graphql_api.py`` registers MagicMock placeholders for
    ``airflow.*`` (and Airflow 3.2's ``opentelemetry.*`` deps) so GraphQL
    tests can import without a real Airflow install. If those stubs are
    still in ``sys.modules`` when we try to import ``edgeguard_pipeline``,
    the import either fails or pulls in a half-mocked Airflow that
    breaks the DAG file. Purge before importing so we get the REAL
    Airflow.
    """
    for key in list(sys.modules):
        if (
            key == "edgeguard_pipeline"
            or key.startswith("airflow")
            or key == "opentelemetry"
            or key.startswith("opentelemetry.")
        ):
            del sys.modules[key]
    import importlib

    return importlib.import_module("edgeguard_pipeline")


def test_transient_error_classifier_recognizes_common_network_errors():
    """The classifier must recognize stdlib + popular HTTP library errors
    by class name. Without this, ``CyberCureCollector`` raising a
    ``requests.ConnectionError`` would be treated as a hard bug instead
    of a transient external failure."""
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env — skipping DAG-module test")

    # Stdlib
    assert ep._is_transient_external_error(ConnectionError("boom"))
    assert ep._is_transient_external_error(ConnectionRefusedError())
    assert ep._is_transient_external_error(ConnectionResetError())
    assert ep._is_transient_external_error(TimeoutError())

    # Subclass via custom class — MRO walk must catch it. After PR #35
    # commit 7 dropped the __cause__ walk (bugbot MED — was swallowing
    # wrapped real bugs), MRO is the ONLY way for custom transient
    # classes. Collectors that need to wrap a transient error should
    # subclass it directly.
    class CyberCureRequestTimeout(TimeoutError):
        pass

    assert ep._is_transient_external_error(CyberCureRequestTimeout())

    # Negative pin: ``raise X from transient`` (the recommended add-context
    # pattern) MUST NOT be classified transient. The classifier deliberately
    # ignores __cause__ — see the canonical pin in
    # tests/test_collector_failure_alerts.py::test_classifier_does_NOT_walk_explicit_cause_chain.
    class CollectorError(Exception):
        pass

    try:
        try:
            raise ConnectionError("upstream 503")
        except ConnectionError as inner:
            raise CollectorError("collector wrapper") from inner
    except CollectorError as e:
        assert not ep._is_transient_external_error(e), (
            "post-commit-7: __cause__ chain MUST NOT be walked — wrapped errors "
            "must subclass a known transient class to be classified transient"
        )


def test_transient_error_classifier_does_not_swallow_real_bugs():
    """A TypeError, ValueError, AttributeError, ImportError etc. must NOT
    be classified as transient — they indicate a real EdgeGuard bug we
    want to surface loudly. Otherwise we'd silently swallow code defects."""
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    for exc in (
        TypeError("argument mismatch"),
        ValueError("bad input"),
        AttributeError("None has no foo"),
        ImportError("missing module"),
        KeyError("missing key"),
        RuntimeError("generic"),
        ZeroDivisionError("math"),
    ):
        assert not ep._is_transient_external_error(exc), (
            f"{type(exc).__name__} must not be treated as transient — would silently swallow real bug"
        )

    # Also: None / non-exception input must safely return False
    assert not ep._is_transient_external_error(None)


def test_transient_error_classifier_recognizes_named_third_party_errors():
    """Even without ``requests`` / ``httpx`` installed, the classifier must
    recognize their exception class names by walking ``type(exc).__mro__``.
    Synthesize fake classes with the canonical names to verify."""
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    # The classifier matches on class name strings — simulate every entry
    # in _TRANSIENT_EXTERNAL_EXCEPTION_NAMES and verify each is recognized.
    for name in ep._TRANSIENT_EXTERNAL_EXCEPTION_NAMES:
        # Skip the names that are also stdlib (already covered above).
        if name in {"ConnectionError", "ConnectionRefusedError", "TimeoutError"}:
            continue
        synth = type(name, (Exception,), {})
        instance = synth("simulated")
        assert ep._is_transient_external_error(instance), (
            f"name {name!r} declared transient but classifier doesn't recognize it"
        )


# ---------------------------------------------------------------------------
# Trigger-rule pins on downstream baseline tasks
# ---------------------------------------------------------------------------


def test_baseline_downstream_tasks_have_non_blocking_trigger_rules():
    """The three downstream-of-collectors tasks (build_relationships,
    run_enrichment_jobs, baseline_complete) must have explicit
    non-default trigger rules so a single collector failure cannot block
    the pipeline.

    Source-grep the DAG file because importing the actual TaskGroup
    requires Airflow runtime."""
    dag_path = os.path.join(os.path.dirname(__file__), "..", "dags", "edgeguard_pipeline.py")
    with open(dag_path) as fh:
        src = fh.read()

    # Locate the three task definitions and verify each has the trigger_rule
    # arg with the expected value. Use a regex that tolerates indentation.
    import re

    def _has_trigger_rule(task_id: str, expected_rule: str) -> bool:
        pattern = rf"task_id=\"{re.escape(task_id)}\".*?trigger_rule=TriggerRule\.{re.escape(expected_rule)}"
        return bool(re.search(pattern, src, re.DOTALL))

    assert _has_trigger_rule("build_relationships", "NONE_FAILED_MIN_ONE_SUCCESS"), (
        "build_relationships task must use NONE_FAILED_MIN_ONE_SUCCESS — "
        "default ALL_SUCCESS would block when a sibling collector failed"
    )
    assert _has_trigger_rule("run_enrichment_jobs", "NONE_FAILED_MIN_ONE_SUCCESS"), (
        "run_enrichment_jobs must use NONE_FAILED_MIN_ONE_SUCCESS"
    )
    assert _has_trigger_rule("baseline_complete", "ALL_DONE"), (
        "baseline_complete must use ALL_DONE so the operator gets a "
        "termination signal even if some upstream task failed"
    )


def test_run_collector_with_metrics_grace_path_returns_skipped_on_transient_error():
    """End-to-end behavioral test: ``run_collector_with_metrics`` with a
    collector that raises a transient error must:
      - return a dict with ``success=True`` and ``skipped=True``
      - NOT re-raise
      - call set_source_health(..., False) so dashboards show degradation
    """
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    from unittest.mock import MagicMock, patch

    # Build a fake collector class whose .collect() raises ConnectionError.
    class _FailingCollector:
        def __init__(self, *_a, **_kw):
            pass

        def collect(self, *_a, **_kw):
            raise ConnectionError("simulated CyberCure outage")

    fake_writer = MagicMock()

    # Patch the heavy/external calls so the function only exercises the
    # transient-handling branch.
    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", lambda *_a, **_kw: None),
        patch.object(ep, "set_source_health", MagicMock()) as set_health,
        patch.object(ep, "record_dag_run", MagicMock()),
        patch.object(ep, "record_collection", MagicMock()),
        patch.object(ep, "record_collection_duration", MagicMock()),
        patch.object(ep, "record_collector_skip", MagicMock()) as record_skip,
        patch.object(ep, "record_pipeline_error", MagicMock()),
        patch.object(ep, "record_error", MagicMock()),
        patch("baseline_lock.baseline_skip_reason", lambda: None, create=True),
    ):
        result = ep.run_collector_with_metrics(
            "cybercure",
            _FailingCollector,
            fake_writer,
            limit=10,
        )

    assert isinstance(result, dict), "must return a status dict, not raise"
    assert result.get("success") is True, "transient external error must be reported as success=True"
    assert result.get("skipped") is True, "must be marked skipped"
    assert result.get("skip_reason_class") == "transient_external_error", (
        f"skip_reason_class wrong: {result.get('skip_reason_class')}"
    )
    # PR #35 commit 3 (bugbot LOW): the previous tuple-wrapped form
    # ``(set_health.assert_called_with(...), "msg")`` discarded the
    # message — assert_called_with's failure already raises with its own
    # mismatch detail, the docstring above the test explains why.
    set_health.assert_called_with("cybercure", "global", False)
    # The skip metric must record the reason so operators can see WHY downstream proceeded.
    assert any(call.args[1] == "transient_external_error" for call in record_skip.call_args_list), (
        "must record_collector_skip(..., 'transient_external_error') for visibility"
    )


def test_run_collector_with_metrics_still_raises_on_real_bugs():
    """Negative pin: a TypeError or ImportError must STILL re-raise. We
    explicitly do NOT want to silently swallow real bugs."""
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    from unittest.mock import MagicMock, patch

    import pytest

    class _BuggyCollector:
        def __init__(self, *_a, **_kw):
            pass

        def collect(self, *_a, **_kw):
            raise TypeError("argument 'foo' missing — real bug, not transient")

    fake_writer = MagicMock()

    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", lambda *_a, **_kw: None),
        patch.object(ep, "set_source_health", MagicMock()),
        patch.object(ep, "record_dag_run", MagicMock()),
        patch.object(ep, "record_collection", MagicMock()),
        patch.object(ep, "record_pipeline_error", MagicMock()),
        patch.object(ep, "record_error", MagicMock()),
        patch("baseline_lock.baseline_skip_reason", lambda: None, create=True),
    ):
        with pytest.raises(TypeError, match="real bug"):
            ep.run_collector_with_metrics(
                "buggy",
                _BuggyCollector,
                fake_writer,
                limit=10,
            )


# ---------------------------------------------------------------------------
# Bugbot MED (PR #35 commit 9) — metric-emission failures must not block
# ---------------------------------------------------------------------------


def test_metric_emission_failure_does_not_break_transient_skip_path():
    """PR #35 bugbot MED regression pin.

    Background: ``record_collection``, ``record_collection_duration``,
    ``record_collector_skip``, and ``set_source_health`` are called inside
    the same ``except Exception as e:`` handler that's trying to GRACEFULLY
    skip a transient failure. If a metric call itself raises (Prometheus
    label cardinality blow-up, registry contention, double-registration
    Counter bug — all observed in production), without ``_safe()`` wrapping
    that metric exception would propagate UP through the same except,
    the function would re-raise, the Airflow task would FAIL, and the
    pipeline would block — defeating the entire purpose of PR #35.

    Contract: every metric call in the DAG handler is wrapped in a local
    ``_safe()`` that swallows + debug-logs metric exceptions, mirroring
    the pattern in ``src.collector_failure_alerts.report_collector_failure``.

    This test injects a bomb into ``record_collection`` and verifies the
    transient path STILL returns the success-skipped status dict instead
    of re-raising the bomb.
    """
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    from unittest.mock import MagicMock, patch

    class _FailingCollector:
        def __init__(self, *_a, **_kw):
            pass

        def collect(self, *_a, **_kw):
            raise ConnectionError("simulated transient outage")

    fake_writer = MagicMock()

    def _bomb(*_a, **_kw):
        # Simulates prometheus_client raising on a label cardinality issue
        # or a duplicated Counter registration — both real production errors.
        raise RuntimeError("simulated metric registry failure")

    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", lambda *_a, **_kw: None),
        # The four metric calls in the transient branch — each made to bomb.
        patch.object(ep, "set_source_health", side_effect=_bomb),
        patch.object(ep, "record_dag_run", side_effect=_bomb),
        patch.object(ep, "record_collection", side_effect=_bomb),
        patch.object(ep, "record_collection_duration", side_effect=_bomb),
        patch.object(ep, "record_collector_skip", side_effect=_bomb),
        # Catastrophic-branch metrics aren't reached on this path but
        # patched to bomb anyway so we'd notice if a refactor sent
        # control through there by mistake.
        patch.object(ep, "record_pipeline_error", side_effect=_bomb),
        patch.object(ep, "record_error", side_effect=_bomb),
        patch("baseline_lock.baseline_skip_reason", lambda: None, create=True),
    ):
        # Must NOT raise. If the bomb propagates, the task FAILS and PR #35 is dead.
        result = ep.run_collector_with_metrics(
            "cybercure",
            _FailingCollector,
            fake_writer,
            limit=10,
        )

    assert isinstance(result, dict), (
        "metric failure inside transient branch must NOT escape the handler — "
        "PR #35 explicitly exists to keep the task GREEN on transient failures"
    )
    assert result.get("success") is True
    assert result.get("skipped") is True
    assert result.get("skip_reason_class") == "transient_external_error"


def test_metric_emission_failure_does_not_mask_catastrophic_exception():
    """Negative pin: when a metric call bombs inside the catastrophic branch,
    the ORIGINAL catastrophic exception (e.g. TypeError from a real bug)
    must still propagate — NOT the metric's RuntimeError. Otherwise an
    operator paged on the Slack alert would chase a misleading
    'metric registry failure' instead of the actual TypeError that broke
    the collector."""
    try:
        ep = _import_dag_module()
    except Exception:
        import pytest

        pytest.skip("Airflow not installed in this test env")

    from unittest.mock import MagicMock, patch

    import pytest

    class _BuggyCollector:
        def __init__(self, *_a, **_kw):
            pass

        def collect(self, *_a, **_kw):
            raise TypeError("argument 'foo' missing — real bug")

    fake_writer = MagicMock()

    def _bomb(*_a, **_kw):
        raise RuntimeError("metric registry simulated failure — must not mask TypeError")

    with (
        patch.object(ep, "ensure_metrics_server", lambda: None),
        patch.object(ep, "log_circuit_breaker_status", lambda: None),
        patch.object(ep, "is_collector_enabled_by_allowlist", lambda _: True),
        patch.object(ep, "send_slack_alert", lambda *_a, **_kw: None),
        patch.object(ep, "set_source_health", side_effect=_bomb),
        patch.object(ep, "record_dag_run", side_effect=_bomb),
        patch.object(ep, "record_collection", side_effect=_bomb),
        patch.object(ep, "record_collection_duration", side_effect=_bomb),
        patch.object(ep, "record_pipeline_error", side_effect=_bomb),
        patch.object(ep, "record_error", side_effect=_bomb),
        patch("baseline_lock.baseline_skip_reason", lambda: None, create=True),
    ):
        # Must propagate the TypeError, NOT the RuntimeError from the metric bomb.
        with pytest.raises(TypeError, match="real bug"):
            ep.run_collector_with_metrics(
                "buggy",
                _BuggyCollector,
                fake_writer,
                limit=10,
            )
