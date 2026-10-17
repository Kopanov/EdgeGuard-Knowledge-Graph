# Resilience and Circuit Breaker Configuration

EdgeGuard includes a resilience layer (`resilience.py`) that implements:

- Circuit breaker pattern for external services (MISP, Neo4j, etc.).
- Health check timing and metrics.
- Prometheus metrics for failures, health, and latency.

This guide explains how to tune the most important parameters as an operator.

---

### 1. Circuit breaker basics

Breakers exist for `misp`, `neo4j`, `nvd` and `otx` (`failure_threshold` 3, `recovery_timeout` 3600) and for `cisa`, `cisa_ics`, `mitre`, `threatfox`, `urlhaus`, `malwarebazaar`, `feodo` and `sslbl` (3, 1800). VirusTotal and AbuseIPDB have none, and `misp_to_neo4j` is a metrics source label, not a breaker. Each breaker is a `CircuitBreaker` instance:

- **States**:
  - `CLOSED` – normal operation, all calls go through.
  - `OPEN` – too many failures; calls are short‑circuited to fail fast.
  - `HALF_OPEN` – after a cooldown, a limited number of test calls are allowed.
- **Key parameters (per circuit)**:
  - `failure_threshold` – number of consecutive failures before the circuit opens.
  - `recovery_timeout` – seconds to wait before trying again from `OPEN` to `HALF_OPEN`.
  - `half_open_max_calls` – how many test calls are allowed in `HALF_OPEN` state.

Defaults are defined in `resilience.py` and where the breakers are created (e.g. in `run_misp_to_neo4j.py`).

**State lives in one process.** A breaker's state lives in the memory of the process that uses it; nothing stores it (the `circuit_breaker_state.json` path named in `src/edgeguard.py` is written by no code). Under Airflow every task is a separate process: each task run starts with every breaker `CLOSED`, and an `OPEN` breaker ends with its task, so `recovery_timeout` only matters inside one long task. `edgeguard_circuit_breaker_state` keeps the last value any process wrote (it is written on a recorded success or failure, not when a breaker is created). After a task that ended with an `OPEN` breaker it stays at 2, and `EdgeGuardCircuitBreakerOpen` keeps firing, until the next task of that service records a success or a failure.

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

- **Slow or rate‑limited APIs (e.g., NVD)**:
  - Slightly higher `failure_threshold` (e.g. 5) to allow for transient HTTP 429/5xx.
  - Longer `recovery_timeout` (e.g. 900–3600 seconds) if the service enforces backoff.
- **Critical internal services (MISP / Neo4j)**:
  - Lower `failure_threshold` (e.g. 3) to fail fast when something is clearly wrong.
  - Moderate `recovery_timeout` (e.g. 300–900 seconds) to avoid hammering a broken service.
- **Edge deployments** (no `EDGEGUARD_ENV` value selects them: `edge` is not one of the non-production labels, so it runs as production; see [ENVIRONMENTS.md](ENVIRONMENTS.md)):
  - Prefer **shorter timeouts and conservative thresholds** – edge devices often have less stable connectivity and you want to degrade gracefully rather than block.

The next section shows how to override these values.

---

### 4. Overriding circuit breaker settings

Circuit breaker parameters are passed when each breaker is created, for example:

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

- `edgeguard_collection_failures_total{source="misp_to_neo4j"}` – rising values indicate persistent problems with a source. It is also recorded for `neo4j`, `otx`, `nvd` and `cisa`; no other collector records it.
- `edgeguard_service_up{service="misp"}` – 1=healthy, 0=unhealthy as seen by health checks.
- `edgeguard_circuit_breaker_state{service="neo4j"}` – non‑zero means the breaker is not fully closed.
- `edgeguard_health_check_duration_seconds{service="misp"}` – health check latency; spikes often correlate with timeouts.

Use these in Grafana dashboards and alert rules to detect and respond to degraded external services.

---

### 6. Quick operator checklist

- [ ] Circuit breakers are in place for MISP, Neo4j and the feeds that have one (NVD, OTX, CISA KEV, CISA ICS, MITRE, ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker, SSL Blacklist); VirusTotal and AbuseIPDB have none.
- [ ] `failure_threshold` and `recovery_timeout` tuned for your environment (prod vs edge).
- [ ] Prometheus + Grafana stack running and scraping the `metrics` service (`metrics:8001/metrics`, `src/metrics_exporter.py`; `metrics_server.py` on a single-process install).
- [ ] Alerting on:
  - `edgeguard_circuit_breaker_state != 0`,
  - sustained increase in `edgeguard_collection_failures_total`,
  - `edgeguard_service_up == 0` for core services.

---

_Last updated: 2026-10-17_

## History

- 2026-10-17 — Change notes moved from the footer to this History section; the main text describes the current behaviour only.
- 2026-10-17 — The breakers that exist are listed (`misp`, `neo4j`, `nvd`, `otx` at 3 / 3600 s; `cisa`, `cisa_ics`, `mitre`, `threatfox`, `urlhaus`, `malwarebazaar`, `feodo`, `sslbl` at 3 / 1800 s; none for VirusTotal and AbuseIPDB, no `misp_to_neo4j` breaker); a breaker's state lives in its task process and the state gauge keeps the last value written; the sources of `edgeguard_collection_failures_total`; Prometheus scrapes the `metrics` service in the Compose deployment; `EDGEGUARD_ENV=edge` selects no edge mode.
- 2026-03-17 — First version.
