"""Tests for resilience.CircuitBreaker registry (shared with collectors)."""

import pytest

from resilience import CircuitState, get_circuit_breaker, reset_circuit_breaker


@pytest.fixture(autouse=True)
def _reset_test_breaker():
    name = "pytest_cb_test"
    reset_circuit_breaker(name)
    yield
    reset_circuit_breaker(name)


def test_get_circuit_breaker_singleton():
    a = get_circuit_breaker("singleton_cb", failure_threshold=2, recovery_timeout=1)
    b = get_circuit_breaker("singleton_cb", failure_threshold=99, recovery_timeout=99)
    assert a is b
    assert a.failure_threshold == 2


def test_record_failure_opens_after_threshold():
    cb = get_circuit_breaker("pytest_cb_test", failure_threshold=2, recovery_timeout=3600)
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    cb.record_failure()
    assert cb.state == CircuitState.OPEN


def test_record_success_resets_failures():
    cb = get_circuit_breaker("pytest_cb_test", failure_threshold=5, recovery_timeout=3600)
    cb.record_failure()
    cb.record_success()
    assert cb.get_status()["failure_count"] == 0


def test_can_execute_when_closed():
    cb = get_circuit_breaker("pytest_cb_test", failure_threshold=3, recovery_timeout=3600)
    assert cb.can_execute() is True


def test_decorated_function_raises_when_circuit_open():
    """PR #34 round 18: pin the invariant that a function wrapped with the
    CircuitBreaker decorator RAISES ``CircuitBreakerOpenError`` (not silently
    returns empty / partial data) when the breaker is open. This protects
    against the silent-skip race the round-13 audit flagged: a collector
    must not be able to process partial data while the circuit is open.

    Uses a UNIQUE breaker name so the test is independent of the shared
    ``pytest_cb_test`` registry (singleton — failure_threshold is sticky
    after first call).
    """
    from resilience import CircuitBreakerOpenError

    name = "pytest_cb_raises_when_open"
    reset_circuit_breaker(name)
    try:
        cb = get_circuit_breaker(name, failure_threshold=1, recovery_timeout=3600)
        cb.record_failure()  # opens the circuit (threshold=1)
        assert cb.state == CircuitState.OPEN
        assert cb.can_execute() is False, "after threshold failures the circuit must be open"

        @cb
        def collect_some_data():
            # In production: this would hit an external API and parse a response.
            # If the breaker is open we MUST never reach this body — otherwise
            # the empty/partial-data race the audit flagged becomes possible.
            return ["some-data"]

        with pytest.raises(CircuitBreakerOpenError):
            collect_some_data()
    finally:
        reset_circuit_breaker(name)


def test_decorated_function_records_failure_on_exception():
    """Companion to test_decorated_function_raises_when_circuit_open: when
    the wrapped function raises, the breaker records the failure (and
    opens after threshold). Pin the contract so a future refactor can't
    silently swallow the exception inside the wrapper."""
    name = "pytest_cb_records_failure"
    reset_circuit_breaker(name)
    try:
        cb = get_circuit_breaker(name, failure_threshold=2, recovery_timeout=3600)

        @cb
        def flaky_call():
            raise RuntimeError("upstream API exploded")

        # First failure leaves the breaker closed.
        with pytest.raises(RuntimeError):
            flaky_call()
        assert cb.state == CircuitState.CLOSED
        # Second failure opens it.
        with pytest.raises(RuntimeError):
            flaky_call()
        assert cb.state == CircuitState.OPEN
    finally:
        reset_circuit_breaker(name)
