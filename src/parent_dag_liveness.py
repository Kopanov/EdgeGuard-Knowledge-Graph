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


def _probe_dag_run_state(dag_id: str, run_id: str) -> Optional[str]:
    """Return the raw Airflow ``dag_run`` state string, or ``None`` on
    any probe failure.

    Bugbot LOW (PR-F6 commit 2159292): the previous design called
    Airflow twice on parent-death (once via ``is_dag_run_alive`` for the
    bool, once again from the callback for the message text). That
    doubled the API load on death detection AND introduced a TOCTOU
    gap — if state flipped between the two calls, the exception's
    ``observed_state`` could contradict the trigger. Refactored: a
    single probe returns the state, both ``is_dag_run_alive`` and the
    callback consume that one result.

    Returns
    -------
    str
        The raw state from Airflow (e.g., ``"running"``, ``"queued"``,
        ``"success"``, ``"failed"``, ``"upstream_failed"``).
    None
        Probe failed for any reason (missing identifiers, API
        unreachable, non-dict response, error envelope from
        ``airflow_client._get``, unexpected exception). Callers MUST
        treat ``None`` as fail-OPEN — a transient API blip should NOT
        false-kill an in-flight collector.

    Notes
    -----
    Imports ``airflow_client._get`` lazily to avoid a hard dependency at
    module-import time (the parent_dag_liveness module is loaded by
    collectors that may not have ``requests`` installed in some test
    environments).
    """
    if not dag_id or not run_id:
        # Defensive: can't probe without identifiers. Treat as
        # fail-OPEN at the caller (return None signals "unknown").
        return None
    try:
        from airflow_client import _get  # lazy
    except ImportError as e:
        logger.debug("airflow_client not importable (%s) — probe returns None", e)
        return None
    try:
        result = _get(f"/dags/{dag_id}/dagRuns/{run_id}")
    except Exception as e:
        # Belt-and-suspenders: _get already catches everything and
        # returns ``{"error": ...}``, but defend against future changes
        # to its contract.
        logger.debug("Liveness probe raised unexpectedly (%s) — probe returns None", e)
        return None
    if not isinstance(result, dict):
        logger.debug("Liveness probe non-dict response (%r) — probe returns None", type(result))
        return None
    if "error" in result:
        # API unreachable / 4xx / 5xx
        logger.debug("Liveness probe API error: %s — probe returns None", result.get("error"))
        return None
    state = result.get("state")
    return str(state) if state else None


def is_dag_run_alive(dag_id: str, run_id: str) -> bool:
    """Probe the Airflow REST API: is ``dag_id/run_id`` still in a
    runnable state (``running`` or ``queued``)?

    Thin wrapper around :func:`_probe_dag_run_state` that collapses
    the state string to a bool. Fail-OPEN preserved (``None`` from
    the probe → ``True`` here).

    Returns
    -------
    True
        Run is in ``running`` or ``queued`` state, OR the probe failed
        (fail-OPEN — a transient API blip should NOT cause us to
        false-kill an in-flight collector).
    False
        Run is in a terminal state (``success``, ``failed``,
        ``upstream_failed``, etc.) per the Airflow API response.
    """
    state = _probe_dag_run_state(dag_id, run_id)
    if state is None:
        return True  # fail-OPEN
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

    # Closure state — ``time.monotonic`` is the right clock here
    # (immune to wall-clock jumps from NTP / DST). Initialize to
    # ``-inf`` so the FIRST callback invocation always probes
    # regardless of system uptime.
    #
    # Bugbot LOW (PR-F6 commit 2159292): the previous initializer
    # ``0.0`` interacted badly with ``time.monotonic()`` returning
    # seconds-since-boot on Linux. On a freshly-booted host where
    # uptime < throttle (default 60s), ``now - 0.0 < throttle`` was
    # ``True`` so the FIRST probe was silently skipped — leaving the
    # safeguard inactive during early system uptime. ``-inf`` makes
    # the first probe always fire.
    last_probe_at: list[float] = [float("-inf")]

    def _callback() -> None:
        now = time.monotonic()
        if now - last_probe_at[0] < throttle:
            return  # within rate limit, skip
        last_probe_at[0] = now
        # Single probe — get the raw state once. Bugbot LOW
        # (PR-F6 commit 2159292): the previous design called Airflow
        # twice on death (is_dag_run_alive for the bool, then again
        # for the message text), doubling API load AND introducing
        # a TOCTOU gap. Now we consume one probe result for both
        # the alive/dead decision and the exception's state field.
        state = _probe_dag_run_state(dag_id, run_id)
        if state is None:
            # Fail-OPEN — transient API blip, assume alive
            return
        if state in _ALIVE_STATES:
            return  # alive
        # Confirmed terminal state — abort the collector cleanly
        logger.warning(
            "[PARENT_DAG_DEAD] dag_run=%s/%s observed state=%r — aborting collector cleanly. "
            "Orphan-process safeguard (PR-F6) prevented late writes to MISP/Neo4j.",
            dag_id,
            run_id,
            state,
        )
        raise AbortedByDagFailureException(dag_id, run_id, state)

    return _callback
