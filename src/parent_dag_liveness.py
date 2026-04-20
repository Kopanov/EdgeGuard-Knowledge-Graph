"""
EdgeGuard — Parent-DAG liveness check (PR-F6, Issue #65)
=========================================================

Closes the **orphan collector process** gap surfaced by Bravo's
2026-04-19 / 2026-04-20 baseline investigation. Recap:

  - A failed ``edgeguard_baseline`` DAG run kept its ``collect_nvd``
    Python subprocess alive for 12+ hours after Airflow marked the
    run failed.
  - The orphan eventually pushed 78,313 attributes to MISP **after**
    the next manual run's ``baseline_clean`` had already wiped MISP.
  - Root cause: when a DAG run is marked ``failed`` (because *another*
    task failed), Airflow does NOT auto-kill in-flight tasks of the
    same run. The collector kept running in its worker subprocess
    until it finished naturally.

Design
------

This module provides a **collector-side liveness check** — the
collector polls the Airflow REST API between MISP push batches and
exits cleanly if its parent ``dag_run`` is no longer in a runnable
state. The check fires from inside ``MISPWriter.push_items`` (which
already throttles 5s between batches), so the per-batch overhead is
one small HTTP call + zero added latency.

Why this shape (vs. the alternatives considered in Issue #65):

  - **Clean exit between batches** — the current batch finishes its
    write to MISP; the NEXT batch never starts. No half-written events.
  - **Fail-OPEN** — if the Airflow API is briefly unavailable, the
    check returns "alive" rather than aggressively killing the
    collector on a transient blip. The orphan window is bounded by
    the collector's own ``execution_timeout`` regardless.
  - **Per-collector opt-in** — controlled by
    ``EDGEGUARD_PARENT_DAG_LIVENESS_CHECK`` (default ``true`` for
    baseline; collectors choose whether to install the callback).
  - **No Airflow internals plumbing** — uses the public REST API the
    rest of EdgeGuard already depends on (``src/airflow_client.py``).

Public API
----------

  - :class:`AbortedByDagFailureException` — raised by the callback
    when the parent dag_run is no longer runnable. Catchable by
    callers that want to log + clean up before re-raising.
  - :func:`is_dag_run_alive(dag_id, run_id)` — pure probe; returns
    ``True`` when the run is in ``running`` or ``queued`` state,
    ``False`` for terminal states (``success``, ``failed``,
    ``upstream_failed``, ``skipped``, ``removed``). Fail-OPEN: returns
    ``True`` on any probe error so transient API blips don't false-kill.
  - :func:`make_liveness_callback(dag_id, run_id, *, throttle_sec)` —
    returns a closure ``() -> None`` that raises
    ``AbortedByDagFailureException`` if the parent is dead. Suitable
    as ``MISPWriter.push_items``' per-batch ``liveness_callback``.
    Internally rate-limits to ``throttle_sec`` between actual API
    calls (default 60s) so high-frequency batch pushes don't hammer
    the Airflow API.

Env flags
---------

  - ``EDGEGUARD_PARENT_DAG_LIVENESS_CHECK`` (default ``true``) —
    master switch. When ``false``, ``make_liveness_callback`` returns
    ``None`` and the collector never polls.
  - ``EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC`` (default ``60``) —
    minimum time between actual API calls. The callback is still
    *called* every batch, but only *probes* once per interval.

See also
--------

  - ``src/collectors/misp_writer.py`` — calls the callback between batches
  - ``dags/edgeguard_pipeline.py:run_baseline_collector`` — installs
    the callback for the 4 tier-1 baseline collectors
  - ``docs/AIRFLOW_DAG_DESIGN.md`` § "Parent-DAG liveness check" — operator-facing doc
  - Issue #65 — the original design discussion
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# DAG run states that mean "still runnable, keep going". Anything else
# (success, failed, upstream_failed, skipped, removed, ...) is a signal
# to abort. Per Airflow REST API docs:
# https://airflow.apache.org/docs/apache-airflow/stable/rest-api-ref.html#operation/get_dag_runs
_ALIVE_STATES = frozenset({"running", "queued"})

# Default rate-limit for actual API calls. The callback is called every
# batch (every ~5s due to MISPWriter throttle), but probing every 5s
# would generate ~720 API calls per hour-long collector run. 60s is the
# right balance: catches an orphan within ~1 minute of its parent DAG
# dying, doesn't hammer the API.
_DEFAULT_THROTTLE_SEC = 60.0

# Env flags
_ENV_ENABLED = "EDGEGUARD_PARENT_DAG_LIVENESS_CHECK"
_ENV_THROTTLE = "EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC"


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class AbortedByDagFailureException(Exception):
    """Raised by the per-batch liveness callback when the parent
    ``dag_run`` is no longer in a runnable state.

    Distinct exception type so callers (collectors, tests) can
    distinguish "parent DAG died, exit cleanly" from "MISP write
    actually failed, retry/fail loud". Carries the dag_id, run_id,
    and observed state for the structured log line.
    """

    def __init__(self, dag_id: str, run_id: str, state: Optional[str]):
        self.dag_id = dag_id
        self.run_id = run_id
        self.state = state
        super().__init__(
            f"Parent dag_run {dag_id}/{run_id} is no longer runnable "
            f"(observed state: {state!r}); aborting collector cleanly. "
            "This is the PR-F6 orphan-process safeguard — see "
            "docs/AIRFLOW_DAG_DESIGN.md § 'Parent-DAG liveness check'."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_enabled() -> bool:
    """Return True when the liveness check is enabled by env flag.

    Default is ON — operators must explicitly set the flag to ``false``
    to disable. This is the safe default: if you forget to opt in, you
    get protected anyway.
    """
    raw = os.environ.get(_ENV_ENABLED, "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _throttle_seconds() -> float:
    """Return the configured throttle interval (seconds between actual
    API calls). Default 60s. Invalid values fall back to default."""
    raw = os.environ.get(_ENV_THROTTLE, "").strip()
    if not raw:
        return _DEFAULT_THROTTLE_SEC
    try:
        val = float(raw)
        if val < 0:
            return _DEFAULT_THROTTLE_SEC
        return val
    except (ValueError, TypeError):
        logger.warning("Ignoring invalid %s=%r; using default %ss", _ENV_THROTTLE, raw, _DEFAULT_THROTTLE_SEC)
        return _DEFAULT_THROTTLE_SEC


def is_dag_run_alive(dag_id: str, run_id: str) -> bool:
    """Probe the Airflow REST API: is ``dag_id/run_id`` still in a
    runnable state (``running`` or ``queued``)?

    Returns
    -------
    True
        Run is in ``running`` or ``queued`` state, OR the probe failed
        (fail-OPEN — a transient API blip should NOT cause us to
        false-kill an in-flight collector).
    False
        Run is in a terminal state (``success``, ``failed``,
        ``upstream_failed``, etc.) per the Airflow API response.

    Notes
    -----
    Imports ``airflow_client._get`` lazily to avoid a hard dependency at
    module-import time (the parent_dag_liveness module is loaded by
    collectors that may not have ``requests`` installed in some test
    environments).
    """
    if not dag_id or not run_id:
        # Defensive: can't probe without identifiers. Fail-OPEN.
        return True
    try:
        from airflow_client import _get  # lazy
    except ImportError as e:
        logger.debug("airflow_client not importable (%s) — fail-OPEN", e)
        return True
    try:
        result = _get(f"/dags/{dag_id}/dagRuns/{run_id}")
    except Exception as e:
        # Belt-and-suspenders: _get already catches everything and
        # returns ``{"error": ...}``, but defend against future changes
        # to its contract. Fail-OPEN on any unexpected exception.
        logger.debug("Liveness probe raised unexpectedly (%s) — fail-OPEN", e)
        return True
    if "error" in result:
        # API unreachable / 4xx / 5xx — fail-OPEN.
        logger.debug("Liveness probe API error: %s — fail-OPEN", result.get("error"))
        return True
    state = result.get("state")
    return state in _ALIVE_STATES


def make_liveness_callback(
    dag_id: str,
    run_id: str,
    *,
    throttle_sec: Optional[float] = None,
) -> Optional[Callable[[], None]]:
    """Build a per-batch callback that raises
    :class:`AbortedByDagFailureException` when the parent dag_run is
    no longer runnable.

    Returns ``None`` when the env flag
    ``EDGEGUARD_PARENT_DAG_LIVENESS_CHECK`` is disabled OR when
    ``dag_id`` / ``run_id`` are empty — in either case the caller
    should skip installing a callback and behave as before.

    The returned callback rate-limits its actual API probes to one
    per ``throttle_sec`` (default 60s). Calling the callback at a
    higher frequency is cheap (a single ``time.monotonic()`` check).

    Parameters
    ----------
    dag_id
        The Airflow DAG ID (e.g., ``"edgeguard_baseline"``).
    run_id
        The Airflow dag_run ID (e.g., ``"manual__2026-04-19T22:46:59"``).
    throttle_sec
        Minimum seconds between real API probes. Defaults to the
        ``EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC`` env value (default 60).
    """
    if not _is_enabled():
        logger.info(
            "Parent-DAG liveness check DISABLED (%s != true) — orphan-process safeguard inactive.",
            _ENV_ENABLED,
        )
        return None
    if not dag_id or not run_id:
        logger.info(
            "Parent-DAG liveness check skipped (no dag_id/run_id available); "
            "orphan-process safeguard not installed for this collector run."
        )
        return None

    throttle = throttle_sec if throttle_sec is not None else _throttle_seconds()
    logger.info(
        "Parent-DAG liveness check ENABLED for dag_run=%s/%s (throttle=%.1fs).",
        dag_id,
        run_id,
        throttle,
    )

    # Closure state — separate variables (single-element lists) so mypy
    # can keep distinct types per slot. ``time.monotonic`` is the right
    # clock here (immune to wall-clock jumps from NTP / DST).
    last_probe_at: list[float] = [0.0]

    def _callback() -> None:
        now = time.monotonic()
        if now - last_probe_at[0] < throttle:
            return  # within rate limit, skip
        last_probe_at[0] = now
        if is_dag_run_alive(dag_id, run_id):
            return
        # Probe came back as terminal — fetch the actual state for the
        # exception message. is_dag_run_alive returned False, so the
        # API call succeeded AND the state is not in _ALIVE_STATES.
        # Re-fetch defensively (cheap; happens once per run, on death).
        observed_state: Optional[str] = None
        try:
            from airflow_client import _get  # lazy

            result = _get(f"/dags/{dag_id}/dagRuns/{run_id}")
            if isinstance(result, dict) and "error" not in result:
                observed_state = result.get("state")
        except Exception:
            pass
        logger.warning(
            "[PARENT_DAG_DEAD] dag_run=%s/%s observed state=%r — aborting collector cleanly. "
            "Orphan-process safeguard (PR-F6) prevented late writes to MISP/Neo4j.",
            dag_id,
            run_id,
            observed_state,
        )
        raise AbortedByDagFailureException(dag_id, run_id, observed_state)

    return _callback
