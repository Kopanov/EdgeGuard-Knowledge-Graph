"""CyberCure 5xx outage → soft-skip pin (2026-04-19 baseline regression).

Vanko's overnight ``edgeguard_baseline`` run failed two tasks:

1. ``build_relationships`` — killed at exactly 45min × 2 attempts
   (Airflow execution_timeout was hardcoded to 45min while the
   subprocess timeout was 5h; baseline against 344K-node graph
   needs hours, not minutes).
2. ``collect_cybercure`` — CyberCure API returned HTTP 503 across
   all 3 feeds; circuit breaker tripped open and the task FAILED.

Fix #2 in this module's PR: CyberCure is intentionally on the
``_REJECTED_ON_PURPOSE`` list in ``source_truthful_timestamps`` (its
``first_seen`` is synthetic ``now()``, not authoritative). An
upstream outage in this LOW-VALUE optional source must not fail the
baseline DAG — promote to soft-skip with a bounded
``skip_reason_class`` so Prometheus tracks the rejection rate via
``edgeguard_collector_skips_total``.

Two distinct soft-skip paths:

* **Circuit breaker open**  → ``cybercure_circuit_breaker_open``
* **All feeds 5xx in one run** → ``cybercure_all_feeds_unreachable``

Operator alerts can distinguish "we hit the breaker" (multi-run
outage) from "every feed 5xx'd just now" (acute outage).
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _new_collector_with_breaker_open() -> Any:
    """Build a CyberCureCollector with the global breaker forced open.

    Mocks the MISP writer so no network IO. The CYBERCURE breaker is
    a module-global singleton — tests MUST reset it after each run
    via ``_reset_cybercure_breaker`` (called from ``_reset_breaker``).
    """
    from collectors.global_feed_collector import (
        CYBERCURE_CIRCUIT_BREAKER,
        CyberCureCollector,
    )

    # Force the breaker open by recording enough failures to trip it.
    for _ in range(CYBERCURE_CIRCUIT_BREAKER.failure_threshold + 1):
        CYBERCURE_CIRCUIT_BREAKER.record_failure()
    assert not CYBERCURE_CIRCUIT_BREAKER.can_execute(), (
        "test setup failed: breaker should be open after threshold + 1 failures"
    )

    collector = CyberCureCollector(misp_writer=MagicMock())
    return collector, CYBERCURE_CIRCUIT_BREAKER


def _reset_breaker(_breaker: Any) -> None:
    """Restore the cybercure breaker to clean closed state — MUST be
    called in every test's ``finally`` clause (the global breaker
    is module-level state that leaks between tests otherwise).
    """
    from resilience import reset_circuit_breaker

    reset_circuit_breaker("cybercure")


# ---------------------------------------------------------------------------
# 1. Circuit breaker open → soft-skip
# ---------------------------------------------------------------------------


def test_cybercure_circuit_breaker_open_returns_soft_skip_status():
    """When the global circuit breaker is OPEN, the collector MUST
    return a status dict with ``success=True, skipped=True`` and the
    bounded reason class — NOT ``success=False`` (which would fail
    the Airflow task)."""
    collector, breaker = _new_collector_with_breaker_open()
    try:
        status: Dict[str, Any] = collector.collect(push_to_misp=True, baseline=False)  # type: ignore[assignment]

        assert status["success"] is True, f"breaker-open path must return success=True (soft-skip), got {status}"
        assert status.get("skipped") is True, (
            f"breaker-open path must set skipped=True so Airflow doesn't fail the task, got {status}"
        )
        assert status.get("skip_reason_class") == "cybercure_circuit_breaker_open", (
            f"breaker-open must use bounded reason class for Prometheus label, got {status.get('skip_reason_class')!r}"
        )
        assert status.get("count") == 0
    finally:
        _reset_breaker(breaker)


def test_cybercure_circuit_breaker_open_logs_warning(caplog):
    """The soft-skip path MUST still emit a WARNING log so operators
    monitoring logs see the outage."""
    import logging

    caplog.set_level(logging.WARNING, logger="collectors.global_feed_collector")
    collector, breaker = _new_collector_with_breaker_open()
    try:
        collector.collect(push_to_misp=True, baseline=False)
        assert any("circuit breaker open" in r.message.lower() for r in caplog.records), (
            f"expected WARNING about circuit breaker; got: {[r.message for r in caplog.records]}"
        )
    finally:
        _reset_breaker(breaker)


def test_cybercure_circuit_breaker_open_returns_empty_list_when_not_pushing():
    """The non-MISP caller path (``push_to_misp=False``) returns an
    empty list, NOT a soft-skip status dict — the soft-skip semantic
    is Airflow-specific."""
    collector, breaker = _new_collector_with_breaker_open()
    try:
        result = collector.collect(push_to_misp=False, baseline=False)
        assert result == []
    finally:
        _reset_breaker(breaker)


# ---------------------------------------------------------------------------
# 2. All feeds 5xx in one run → soft-skip with distinct reason class
# ---------------------------------------------------------------------------


def test_cybercure_all_feeds_failing_returns_soft_skip_with_distinct_reason():
    """When EVERY feed (ip / url / hash) raises during a single run
    but the breaker is closed, the collector MUST soft-skip with a
    DIFFERENT reason class than the breaker-open path. Operators
    distinguish 'we hit the breaker after multi-run failures' from
    'every feed 5xx'd in this single run'.

    Reset the breaker FIRST so a leak from a previous test (or run
    order) doesn't divert the test through the breaker-open branch.
    """
    from resilience import reset_circuit_breaker

    reset_circuit_breaker("cybercure")

    from collectors.global_feed_collector import CyberCureCollector

    collector = CyberCureCollector(misp_writer=MagicMock())
    try:
        # Simulate every _fetch_feed call raising (covers all 3 feed types)
        with patch.object(
            collector,
            "_fetch_feed",
            side_effect=RuntimeError("503 Service Unavailable"),
        ):
            status: Dict[str, Any] = collector.collect(push_to_misp=True, baseline=False)  # type: ignore[assignment]

        assert status["success"] is True
        assert status.get("skipped") is True
        assert status.get("skip_reason_class") == "cybercure_all_feeds_unreachable", (
            f"all-feeds-down must use the distinct reason class, got {status.get('skip_reason_class')!r}"
        )
        # The skip_reason should mention how many feeds failed for triage
        assert "feed" in (status.get("skip_reason") or "").lower()
    finally:
        reset_circuit_breaker("cybercure")


def test_cybercure_partial_success_does_not_soft_skip():
    """If at least ONE feed succeeded, the collector returns a
    normal-success status (NOT soft-skip). The soft-skip is only
    triggered when ALL feeds failed."""
    from resilience import reset_circuit_breaker

    reset_circuit_breaker("cybercure")

    from collectors.global_feed_collector import CyberCureCollector

    writer = MagicMock()
    writer.push_indicators.return_value = (1, 0)  # 1 success, 0 failed
    collector = CyberCureCollector(misp_writer=writer)
    try:
        # 1st feed succeeds (returns one valid indicator), other 2 raise
        call_counter = {"n": 0}

        def _fetch_one_works(url: str) -> str:
            call_counter["n"] += 1
            if call_counter["n"] == 1:
                return "192.0.2.1\n"  # 1 valid IP for the "ip" feed
            raise RuntimeError("503 Service Unavailable")

        with patch.object(collector, "_fetch_feed", side_effect=_fetch_one_works):
            status: Dict[str, Any] = collector.collect(push_to_misp=True, baseline=False)  # type: ignore[assignment]

        # Partial success → success=True but NOT skipped
        assert status["success"] is True
        assert status.get("skipped") is not True, (
            f"partial-success path must NOT soft-skip; only all-feeds-failed does. Got: {status}"
        )
    finally:
        reset_circuit_breaker("cybercure")


# ---------------------------------------------------------------------------
# 3. Soft-skip status round-trips through Airflow's record_collector_skip
# ---------------------------------------------------------------------------


def test_soft_skip_reason_classes_are_bounded_strings():
    """Both new reason classes MUST be bounded snake_case strings —
    Prometheus uses them as label values; unbounded values would
    blow up cardinality."""
    expected = {"cybercure_circuit_breaker_open", "cybercure_all_feeds_unreachable"}
    for reason in expected:
        # snake_case + ASCII + no spaces (valid Prometheus label)
        assert reason.replace("_", "").isalnum()
        assert reason == reason.lower()
        assert " " not in reason
        assert len(reason) < 80, "reason class should fit Prometheus label cardinality budget"
