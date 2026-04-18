"""Centralized "should I sleep between Neo4j writes?" helper.

Why this module exists
----------------------
The proactive audit (Performance Auditor Tier S S10) caught that
EdgeGuard had ~30 hardcoded ``time.sleep(3)`` and ``time.sleep(1)``
sites scattered across 4 files (``build_relationships.py``,
``enrichment_jobs.py``, ``neo4j_client.py`` batch path,
``run_misp_to_neo4j.py`` chunk loop) collectively burning **30
minutes to ~3 hours of pure idle time per baseline run** (and
5–15 minutes per incremental). The sleeps existed to "let Neo4j
flush transactions and reclaim memory" between independent UNWIND
batches — but Neo4j 5.x/2026.x's connection pool already provides
back-pressure via the driver's session-acquisition queue, and the
sleeps were measured net-zero benefit at production scale.

Scope of this helper
--------------------
Replaces the HOT-LOOP PACING sleeps only — the ones that exist
purely to space out independent self-contained transactions. Does
NOT replace:

* ``retry_with_backoff`` exponential-backoff sleeps (correct
  semantics — back off when a transient error fired)
* ``event_fetch_throttle`` outbound rate-limit sleeps (correct
  semantics — respect MISP/upstream API quotas)
* Kept-explicit short sleeps inside collectors that exist to
  satisfy a documented per-vendor rate limit

Default behavior
----------------
``EDGEGUARD_QUERY_PAUSE_SECONDS`` defaults to ``"0"`` (no sleep).
That recovers the 30min-3h per baseline. Operators on memory-
constrained Neo4j who actually NEED the pacing can set
``EDGEGUARD_QUERY_PAUSE_SECONDS=1`` (or whatever) without a code
change. The env name is shared across all hot-loop sites — there's
no operationally-useful reason to tune build_relationships and
enrichment_jobs independently.
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)


_ENV_VAR = "EDGEGUARD_QUERY_PAUSE_SECONDS"

# PR #39 commit X (bugbot LOW): cap the configured pause so a typo'd
# ``inf`` or absurd large value (``EDGEGUARD_QUERY_PAUSE_SECONDS=999999``)
# can't hang the worker indefinitely. 60s is well above the original
# ``time.sleep(3)`` × 12 sites (=36s) that the audit found wasteful;
# operators with a genuine reason to exceed this cap should fix the
# upstream bottleneck instead.
_MAX_PAUSE_SECS = 60


def query_pause_seconds() -> float:
    """Return the configured hot-loop pause in seconds.

    Reads ``EDGEGUARD_QUERY_PAUSE_SECONDS`` on every call so operators
    can change the value without restarting (rare but useful for
    A/B-testing pacing during an incident). Robust to malformed input
    — returns 0.0 on any parse failure with a debug log.
    """
    raw = os.getenv(_ENV_VAR, "0").strip()
    try:
        seconds = float(raw)
        # PR #39 commit X (bugbot LOW): the previous ``not (seconds >= 0)``
        # guard caught negative + NaN but NOT ``inf`` (``inf >= 0`` is True).
        # Setting ``EDGEGUARD_QUERY_PAUSE_SECONDS=inf`` would hang the
        # process forever in ``time.sleep(inf)`` — exactly the failure
        # mode the comment said the guard prevented. Cap to ``_MAX_PAUSE_SECS``
        # explicitly. 60s is generous (more than the original hardcoded
        # ``time.sleep(3)`` × 12 sites = 36s the audit found).
        if not (seconds >= 0):
            logger.debug(f"{_ENV_VAR}={raw!r} parsed to invalid value {seconds!r}; using 0")
            return 0.0
        if seconds > _MAX_PAUSE_SECS:
            logger.warning(
                "%s=%r exceeds the %ss safety cap — clamping. Set a value <= %s.",
                _ENV_VAR,
                seconds,
                _MAX_PAUSE_SECS,
                _MAX_PAUSE_SECS,
            )
            return float(_MAX_PAUSE_SECS)
        return seconds
    except (ValueError, TypeError) as e:
        logger.debug(f"{_ENV_VAR}={raw!r} unparseable ({e}); using 0")
        return 0.0


def query_pause() -> None:
    """Sleep for ``EDGEGUARD_QUERY_PAUSE_SECONDS`` seconds, or skip
    entirely if the env var is unset/0.

    This is the drop-in replacement for the ``time.sleep(3)`` / ``time.sleep(1)``
    calls that used to gate independent Neo4j UNWIND batches. Default
    behavior (no env var set): NO sleep, callers fall straight through.
    """
    seconds = query_pause_seconds()
    if seconds > 0:
        time.sleep(seconds)
