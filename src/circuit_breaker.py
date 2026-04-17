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

# PR #34 round 28 (bug-hunter audit): deleted the ``CircuitOpenError`` alias
# (``CircuitOpenError = CircuitBreakerOpenError``). It had ZERO importers across
# src/, scripts/, dags/, tests/ — the migration to ``CircuitBreakerOpenError``
# was complete. The alias just signaled "incomplete refactor" to readers.

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
    "get_circuit_breaker",
]
