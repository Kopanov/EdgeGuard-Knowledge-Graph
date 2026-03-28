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
