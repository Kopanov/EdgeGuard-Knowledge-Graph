## Resilience and Circuit Breaker Configuration

EdgeGuard includes a resilience layer (`resilience.py`) that implements:

- Circuit breaker pattern for external services (MISP, Neo4j, etc.).
- Health check timing and metrics.
- Prometheus metrics for failures, health, and latency.

This guide explains how to tune the most important parameters as an operator.

---

### 1. Circuit breaker basics

Each external service (e.g. `misp`, `neo4j`, `misp_to_neo4j`) is wrapped by a `CircuitBreaker` instance:

- **States**:
  - `CLOSED` – normal operation, all calls go through.
  - `OPEN` – too many failures; calls are short‑circuited to fail fast.
  - `HALF_OPEN` – after a cooldown, a limited number of test calls are allowed.
- **Key parameters (per circuit)**:
  - `failure_threshold` – number of consecutive failures before the circuit opens.
  - `recovery_timeout` – seconds to wait before trying again from `OPEN` to `HALF_OPEN`.
  - `half_open_max_calls` – how many test calls are allowed in `HALF_OPEN` state.

Defaults are defined in `resilience.py` and where the breakers are created (e.g. in `run_misp_to_neo4j.py`).

---

### 2. Where the circuit breakers are used

Examples:

- In `run_misp_to_neo4j.py`:
  - `MISP_CIRCUIT_BREAKER = get_circuit_breaker('misp', failure_threshold=3, recovery_timeout=3600)`
  - `NEO4J_CIRCUIT_BREAKER = get_circuit_breaker('neo4j', failure_threshold=3, recovery_timeout=3600)`
- `check_service_health(...)` and `record_collection_failure(...)` / `record_collection_success(...)` integrate the breakers with Prometheus metrics.

You can see current circuit breaker states via Prometheus metrics:

- `edgeguard_circuit_breaker_state{service="misp"}` – 0=CLOSED, 1=HALF_OPEN, 2=OPEN
- `edgeguard_consecutive_failures{service="misp"}` – current failure streak

---

### 3. Tuning strategy

There is no single perfect configuration, but these guidelines help:

- **Slow or rate‑limited APIs (e.g., VirusTotal)**:
  - Slightly higher `failure_threshold` (e.g. 5) to allow for transient HTTP 429/5xx.
  - Longer `recovery_timeout` (e.g. 900–3600 seconds) if the service enforces backoff.
- **Critical internal services (MISP / Neo4j)**:
  - Lower `failure_threshold` (e.g. 3) to fail fast when something is clearly wrong.
  - Moderate `recovery_timeout` (e.g. 300–900 seconds) to avoid hammering a broken service.
- **Edge deployments (`EDGEGUARD_ENV=edge`)**:
  - Prefer **shorter timeouts and conservative thresholds** – edge devices often have less stable connectivity and you want to degrade gracefully rather than block.

The next section shows how to override these values.

---

### 4. Overriding circuit breaker settings

Currently, circuit breaker parameters are passed when each breaker is created, for example:

```python
MISP_CIRCUIT_BREAKER = get_circuit_breaker('misp', failure_threshold=3, recovery_timeout=3600)
NEO4J_CIRCUIT_BREAKER = get_circuit_breaker('neo4j', failure_threshold=3, recovery_timeout=3600)
```

If you need different values for your deployment, the recommended approach is:

1. Define environment variables for the services you care about, for example:

   ```bash
   export EDGEGUARD_MISP_FAILURE_THRESHOLD=5
   export EDGEGUARD_MISP_RECOVERY_TIMEOUT=900
   export EDGEGUARD_NEO4J_FAILURE_THRESHOLD=3
   export EDGEGUARD_NEO4J_RECOVERY_TIMEOUT=600
   ```

2. Adjust the breaker initialisation in your fork or ops overlay to read from those env vars:

   ```python
   import os

   def _int_env(name: str, default: int) -> int:
       try:
           return int(os.getenv(name, default))
       except ValueError:
           return default

   MISP_CIRCUIT_BREAKER = get_circuit_breaker(
       'misp',
       failure_threshold=_int_env('EDGEGUARD_MISP_FAILURE_THRESHOLD', 3),
       recovery_timeout=_int_env('EDGEGUARD_MISP_RECOVERY_TIMEOUT', 3600),
   )
   ```

This keeps tuning logic in configuration (env) rather than hard‑coded numbers, while still using the same resilience core.

---

### 5. Metrics to watch

Key Prometheus metrics from `resilience.py` and `metrics_server.py`:

- `edgeguard_collection_failures_total{source="misp"}` – rising values indicate persistent problems with a source.
- `edgeguard_service_up{service="misp"}` – 1=healthy, 0=unhealthy as seen by health checks.
- `edgeguard_circuit_breaker_state{service="neo4j"}` – non‑zero means the breaker is not fully closed.
- `edgeguard_health_check_duration_seconds{service="misp"}` – health check latency; spikes often correlate with timeouts.

Use these in Grafana dashboards and alert rules to detect and respond to degraded external services.

---

### 6. Quick operator checklist

- [ ] Circuit breakers are enabled for all critical services (MISP, Neo4j, external feeds).
- [ ] `failure_threshold` and `recovery_timeout` tuned for your environment (prod vs edge).
- [ ] Prometheus + Grafana stack running and scraping `metrics_server.py` (`/metrics`).
- [ ] Alerting on:
  - `edgeguard_circuit_breaker_state != 0`,
  - sustained increase in `edgeguard_collection_failures_total`,
  - `edgeguard_service_up == 0` for core services.



---

_Last updated: 2026-03-17_
