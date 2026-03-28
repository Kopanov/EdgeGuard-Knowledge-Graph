"""
Backward-compatible circuit breaker imports.

Prefer in new code::

    from resilience import get_circuit_breaker, CircuitBreaker, CircuitState

The canonical implementation lives in :mod:`resilience` (Prometheus hooks,
HALF_OPEN recovery, shared registry).
"""

from resilience import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    get_circuit_breaker,
)

# Legacy alias used by older code / docs
CircuitOpenError = CircuitBreakerOpenError

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitOpenError",
    "CircuitState",
    "get_circuit_breaker",
]
