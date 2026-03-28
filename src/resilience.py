"""
EdgeGuard Resilience Module

Provides circuit breaker pattern, health checks, and Prometheus metrics
for handling extended outages and graceful degradation.
"""

import logging
import time
from enum import Enum
from functools import wraps
from typing import Any, Callable, Dict

# Prometheus metrics (optional)
try:
    from prometheus_client import Counter, Gauge, Histogram

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

    # Create dummy classes for when prometheus is not available
    class Counter:
        def __init__(self, *args, **kwargs):
            pass

        def labels(self, *args, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            pass

    class Gauge:
        def __init__(self, *args, **kwargs):
            pass

        def labels(self, *args, **kwargs):
            return self

        def set(self, *args, **kwargs):
            pass

        def inc(self, *args, **kwargs):
            pass

        def dec(self, *args, **kwargs):
            pass

    class Histogram:
        def __init__(self, *args, **kwargs):
            pass

        def labels(self, *args, **kwargs):
            return self

        def observe(self, *args, **kwargs):
            pass


logger = logging.getLogger(__name__)

# ================================================================================
# PROMETHEUS METRICS
# ================================================================================

# Track collection failures
COLLECTION_FAILURES = Counter("edgeguard_collection_failures_total", "Collection failures by source", ["source"])

# Track service health (1=up, 0=down)
SERVICE_UP = Gauge("edgeguard_service_up", "Service availability (1=up, 0=down)", ["service"])

# Track last successful sync timestamp
LAST_SUCCESS = Gauge("edgeguard_last_success_timestamp", "Unix timestamp of last successful sync", ["source"])

# Track circuit breaker state
CIRCUIT_BREAKER_STATE = Gauge(
    "edgeguard_circuit_breaker_state", "Circuit breaker state (0=closed, 1=half-open, 2=open)", ["service"]
)

# Track health check latency
HEALTH_CHECK_DURATION = Histogram("edgeguard_health_check_duration_seconds", "Time spent on health checks", ["service"])

# Track consecutive failures
CONSECUTIVE_FAILURES = Gauge("edgeguard_consecutive_failures", "Consecutive failures count", ["service"])


# ================================================================================
# CIRCUIT BREAKER PATTERN
# ================================================================================


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = 0  # Normal operation - requests pass through
    HALF_OPEN = 1  # Testing if service recovered
    OPEN = 2  # Service considered down - fast fail


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for handling service outages.

    - CLOSED: Normal operation, requests pass through
    - OPEN: After threshold failures, stop requests for recovery_timeout
    - HALF_OPEN: After recovery_timeout, allow test request

    Args:
        name: Circuit breaker name (for metrics/logging)
        failure_threshold: Number of consecutive failures to open circuit
        recovery_timeout: Seconds to wait before trying again
        half_open_max_calls: Max calls in half-open state before closing
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: int = 3600,  # 1 hour default
        half_open_max_calls: int = 1,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0

        logger.info(f"CircuitBreaker '{name}' initialized: threshold={failure_threshold}, timeout={recovery_timeout}s")

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    def can_execute(self) -> bool:
        """Check if execution should be allowed."""
        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self._last_failure_time and (time.monotonic() - self._last_failure_time) >= self.recovery_timeout:
                logger.info(f"CircuitBreaker '{self.name}': Recovery timeout passed, entering HALF_OPEN")
                self._state = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                return True
            else:
                # Circuit still open
                return False

        if self._state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            if self._half_open_calls < self.half_open_max_calls:
                self._half_open_calls += 1
                return True
            return False

        return False

    def record_success(self):
        """Record a successful execution."""
        self._failure_count = 0

        if self._state == CircuitState.HALF_OPEN:
            logger.info(f"CircuitBreaker '{self.name}': Service recovered, CLOSING circuit")
            self._state = CircuitState.CLOSED
            self._success_count = 0
            self._half_open_calls = 0

        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            CIRCUIT_BREAKER_STATE.labels(service=self.name).set(self._state.value)
            CONSECUTIVE_FAILURES.labels(service=self.name).set(0)

    def record_failure(self):
        """Record a failed execution."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state == CircuitState.HALF_OPEN:
            # Failed in half-open, go back to open
            logger.warning(f"CircuitBreaker '{self.name}': Failed in HALF_OPEN, re-OPENING circuit")
            self._state = CircuitState.OPEN
            self._success_count = 0
            self._half_open_calls = 0
        elif self._state == CircuitState.CLOSED and self._failure_count >= self.failure_threshold:
            # Threshold reached, open circuit
            logger.warning(
                f"CircuitBreaker '{self.name}': Failure threshold reached ({self._failure_count}), OPENING circuit"
            )
            self._state = CircuitState.OPEN

        # Update Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            CIRCUIT_BREAKER_STATE.labels(service=self.name).set(self._state.value)
            CONSECUTIVE_FAILURES.labels(service=self.name).set(self._failure_count)

    def __call__(self, func: Callable) -> Callable:
        """Decorator to wrap a function with circuit breaker logic."""

        @wraps(func)
        def wrapper(*args, **kwargs):
            if not self.can_execute():
                raise CircuitBreakerOpenError(f"Circuit breaker '{self.name}' is OPEN - service unavailable")

            try:
                result = func(*args, **kwargs)
                self.record_success()
                return result
            except Exception:
                self.record_failure()
                raise

        return wrapper

    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status."""
        return {
            "name": self.name,
            "state": self._state.name,
            "failure_count": self._failure_count,
            "failure_threshold": self.failure_threshold,
            "recovery_timeout": self.recovery_timeout,
            "last_failure_time": self._last_failure_time,
            "seconds_since_last_failure": time.monotonic() - self._last_failure_time
            if self._last_failure_time
            else None,
        }


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""

    pass


# ================================================================================
# HEALTH CHECK UTILITIES
# ================================================================================


def check_service_health(service_name: str, health_func: Callable[[], Dict[str, Any]], timeout: int = 30) -> bool:
    """
    Check if a service is healthy before attempting collection.

    Args:
        service_name: Name of the service (for metrics)
        health_func: Function that returns health check dict
        timeout: Max time to wait for health check

    Returns:
        True if service is healthy, False otherwise
    """
    start_time = time.time()

    try:
        result = health_func()
        is_healthy = result.get("healthy", False)

        # Record health check duration
        duration = time.time() - start_time
        if PROMETHEUS_AVAILABLE:
            HEALTH_CHECK_DURATION.labels(service=service_name).observe(duration)

        # Update service health metric
        if PROMETHEUS_AVAILABLE:
            SERVICE_UP.labels(service=service_name).set(1 if is_healthy else 0)

        if is_healthy:
            logger.info(f"Health check PASSED for {service_name} ({duration:.2f}s)")
        else:
            error = result.get("error", "Unknown error")
            logger.warning(f"Health check FAILED for {service_name}: {error}")

        return is_healthy

    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"Health check ERROR for {service_name}: {type(e).__name__}: {e}")

        if PROMETHEUS_AVAILABLE:
            SERVICE_UP.labels(service=service_name).set(0)
            HEALTH_CHECK_DURATION.labels(service=service_name).observe(duration)

        return False


def record_collection_failure(source: str, error: str = None):
    """Record a collection failure in metrics."""
    logger.error(f"Collection failed for {source}: {error or 'Unknown error'}")

    if PROMETHEUS_AVAILABLE:
        COLLECTION_FAILURES.labels(source=source).inc()


def record_collection_success(source: str):
    """Record a successful collection in metrics."""
    logger.info(f"Collection succeeded for {source}")

    if PROMETHEUS_AVAILABLE:
        LAST_SUCCESS.labels(source=source).set(time.time())


# ================================================================================
# RETRY WITH CIRCUIT BREAKER
# ================================================================================


def retry_with_backoff_and_circuit_breaker(
    max_retries: int = 3, base_delay: float = 2.0, circuit_breaker: CircuitBreaker = None, on_failure: Callable = None
):
    """
    Decorator combining retry logic with circuit breaker.

    Args:
        max_retries: Maximum retry attempts
        base_delay: Base delay for exponential backoff
        circuit_breaker: Optional circuit breaker instance
        on_failure: Optional callback on final failure
    """
    import requests

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    # Record success in circuit breaker if provided
                    if circuit_breaker:
                        circuit_breaker.record_success()
                    return result

                except (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.ReadTimeout,
                    requests.exceptions.ChunkedEncodingError,
                ) as e:
                    last_exception = e

                    # Record failure in circuit breaker if provided
                    if circuit_breaker:
                        circuit_breaker.record_failure()
                        # If circuit is now open, stop retrying
                        if not circuit_breaker.can_execute():
                            logger.warning(f"Circuit breaker open for {func.__name__}, aborting retries")
                            break

                    if attempt < max_retries - 1:
                        delay = base_delay * (2**attempt)
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(f"{func.__name__} failed after {max_retries} attempts")

                except Exception as e:
                    # Non-retryable exception
                    logger.error(f"{func.__name__} failed with non-retryable error: {type(e).__name__}: {e}")
                    if circuit_breaker:
                        circuit_breaker.record_failure()
                    raise

            # All retries exhausted
            if on_failure:
                on_failure(last_exception)

            raise last_exception

        return wrapper

    return decorator


# ================================================================================
# GLOBAL CIRCUIT BREAKER REGISTRY
# ================================================================================

_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """
    Get or create a circuit breaker by name.

    This allows sharing circuit breakers across different parts of the code.
    """
    if name not in _circuit_breakers:
        _circuit_breakers[name] = CircuitBreaker(name, **kwargs)
    return _circuit_breakers[name]


def get_all_circuit_breaker_status() -> Dict[str, Dict[str, Any]]:
    """Get status of all registered circuit breakers."""
    return {name: cb.get_status() for name, cb in _circuit_breakers.items()}


def reset_circuit_breaker(name: str):
    """Reset a circuit breaker to closed state."""
    if name in _circuit_breakers:
        cb = _circuit_breakers[name]
        cb._state = CircuitState.CLOSED
        cb._failure_count = 0
        cb._success_count = 0
        cb._last_failure_time = None
        cb._half_open_calls = 0
        logger.info(f"Circuit breaker '{name}' reset to CLOSED")


def reset_all_circuit_breakers():
    """Reset all circuit breakers."""
    for name in _circuit_breakers:
        reset_circuit_breaker(name)
