"""
EdgeGuard — Baseline Clean (destructive)
=========================================

Single source of truth for the 3-step "clean slate" used by:

  - CLI ``--fresh-baseline`` flag in ``src/run_pipeline.py``
  - new ``edgeguard fresh-baseline`` operator command in ``src/edgeguard.py``
  - new ``baseline_clean`` Airflow task in ``dags/edgeguard_pipeline.py``
    (gated on ``dag_run.conf={"fresh_baseline": true}``)

Wipe order: checkpoints → Neo4j graph → MISP EdgeGuard events. Each step is
**all-or-nothing** — if any step fails, the function raises
:class:`BaselineCleanError` and downstream collectors MUST NOT run. The
previous in-line code in run_pipeline.py:1117-1198 logged warnings on
failures and continued, leaving operators with a half-cleaned state that
was harder to debug than a clean failure (audit Prod Readiness HIGH).

After the wipe the helper settles briefly (configurable; default 5s) and
runs a verification poll that re-counts everything until all three
datastores read zero or a configurable timeout elapses. If verify fails,
the helper raises — collectors still don't run.

This module is the chokepoint where the audit's "informed consent" UX
gets its data: the pre-wipe counts returned by :func:`probe_baseline_state`
are what the CLI wrapper renders in its blast-radius display.

Why probes are inline (not in their own module)
-----------------------------------------------
PR #47 (closed) tried to extract these probes into ``src/datastore_probes.py``
as an independent module. Devil's Advocate flagged that as premature
abstraction (the probes had no consumers in production until PR-C
needed them). The probes live HERE, inside the only module that calls
them, until a second consumer materializes — at which point we extract
into a shared module on demand.
"""

from __future__ import annotations

import logging
import os
import time
import warnings
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Result types — structured outcomes for callers
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BaselineState:
    """Snapshot of the three baseline-relevant datastores.

    All counts are 0 if the underlying probe failed; check ``ok_*`` flags
    to disambiguate "datastore is empty" from "probe could not run".
    Used by:
      - the CLI wrapper to render the blast-radius display before asking
        for typed confirmation
      - the post-clean verify loop to assert all zeros
      - operators reading log lines emitted by ``log_state``
    """

    neo4j_count: int = 0
    neo4j_breakdown: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    neo4j_ok: bool = False
    neo4j_error: Optional[str] = None

    misp_count: int = 0
    misp_ok: bool = False
    misp_error: Optional[str] = None

    checkpoint_count: int = 0
    checkpoint_ok: bool = False
    checkpoint_error: Optional[str] = None

    @property
    def all_reachable(self) -> bool:
        """True iff all three probes succeeded (regardless of count)."""
        return self.neo4j_ok and self.misp_ok and self.checkpoint_ok

    @property
    def all_zero(self) -> bool:
        """True iff all three datastores are reachable AND empty.
        Used by the post-clean verify loop as the success condition.
        """
        return self.all_reachable and self.neo4j_count == 0 and self.misp_count == 0 and self.checkpoint_count == 0

    def render_summary(self) -> str:
        """Multi-line human-readable summary, suitable for log output.

        Example::

            Neo4j EdgeGuard nodes:        347,197   ✓
                top labels: Indicator=281K, Vulnerability=38K, CVE=22K
            MISP EdgeGuard events:          8,247   ✓
            Checkpoint entries:                12   ✓
        """
        lines = []
        # Neo4j
        if self.neo4j_ok:
            lines.append(f"  Neo4j EdgeGuard nodes:        {self.neo4j_count:>12,}   ✓")
            if self.neo4j_breakdown:
                top5 = ", ".join(f"{lbl}={cnt:,}" for lbl, cnt in self.neo4j_breakdown[:5])
                lines.append(f"      top labels: {top5}")
        else:
            lines.append(f"  Neo4j EdgeGuard nodes:        unreachable: {self.neo4j_error}")
        # MISP
        if self.misp_ok:
            lines.append(f"  MISP EdgeGuard events:        {self.misp_count:>12,}   ✓")
        else:
            lines.append(f"  MISP EdgeGuard events:        unreachable: {self.misp_error}")
        # Checkpoint
        if self.checkpoint_ok:
            lines.append(f"  Checkpoint entries:           {self.checkpoint_count:>12,}   ✓")
        else:
            lines.append(f"  Checkpoint entries:           unreachable: {self.checkpoint_error}")
        return "\n".join(lines)


@dataclass(frozen=True)
class CleanResult:
    """Outcome of a successful :func:`reset_baseline_data` call.

    On failure the helper raises ``BaselineCleanError`` instead — callers
    only see this dataclass on the all-clean path. ``before`` is the
    pre-wipe snapshot (operator wants the actual counts that were
    deleted); ``after`` is the post-verify snapshot (always all-zeros if
    we reach this point).
    """

    before: BaselineState
    after: BaselineState
    duration_seconds: float
    verify_attempts: int


class BaselineCleanError(RuntimeError):
    """Raised when any step of the baseline clean failed.

    Carries the partial state observed at failure time so callers (the
    CLI wrapper, the DAG task) can render a useful error message and
    decide whether the partial-clean is recoverable. The pipeline MUST
    NOT continue to collectors after this is raised.
    """

    def __init__(self, message: str, *, partial_state: Optional[BaselineState] = None):
        super().__init__(message)
        self.partial_state = partial_state


# --------------------------------------------------------------------------- #
# Probes — inline (no separate module; see header rationale)
# --------------------------------------------------------------------------- #


_NEO4J_TOTAL_COUNT_QUERY = """
MATCH (n) WHERE n.edgeguard_managed = true
RETURN count(n) AS cnt
"""

_NEO4J_BREAKDOWN_QUERY = """
MATCH (n) WHERE n.edgeguard_managed = true
RETURN labels(n)[0] AS label, count(n) AS cnt
ORDER BY cnt DESC
LIMIT 10
"""


def _probe_neo4j(client: Any) -> tuple[int, tuple[tuple[str, int], ...], Optional[str]]:
    """Probe Neo4j for EdgeGuard node count + top-10 label breakdown.

    Returns ``(count, breakdown, error)``. ``error`` is None on success;
    ``count`` is 0 sentinel on failure (callers must check ``error``).
    """
    try:
        rows = client.run(_NEO4J_TOTAL_COUNT_QUERY)
        total = int(rows[0].get("cnt") or 0) if rows else 0
        br_rows = client.run(_NEO4J_BREAKDOWN_QUERY)
        breakdown = tuple((str(r.get("label") or "<unknown>"), int(r.get("cnt") or 0)) for r in (br_rows or []))
        return total, breakdown, None
    except Exception as e:
        logger.debug("probe_neo4j failed", exc_info=True)
        return 0, (), f"{type(e).__name__}: {str(e)[:160]}"


def _probe_misp(misp_url: str, misp_api_key: str, ssl_verify: bool) -> tuple[int, Optional[str]]:
    """Probe MISP for EdgeGuard-tagged event count via /events/index.

    Returns ``(count, error)``. Bounded by MISP's default page size; for
    >page-size deployments the count is approximate (the verify loop only
    needs to confirm == 0, so the cap doesn't matter for the post-clean
    path; the pre-wipe display rounds-down).
    """
    if not misp_api_key:
        return 0, "MISP_API_KEY env var not set"
    try:
        import requests as _req
        import urllib3
    except ImportError as e:
        return 0, f"{type(e).__name__}: {e}"

    try:
        with warnings.catch_warnings():
            if not ssl_verify:
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            resp = _req.get(
                f"{misp_url}/events/index",
                headers={"Authorization": misp_api_key, "Accept": "application/json"},
                verify=ssl_verify,
                timeout=(10, 30),
            )
    except Exception as e:
        logger.debug("probe_misp GET failed", exc_info=True)
        return 0, f"{type(e).__name__}: {str(e)[:160]}"

    if resp.status_code != 200:
        return 0, f"MISP returned HTTP {resp.status_code}"

    try:
        body = resp.json()
    except ValueError as e:
        return 0, f"{type(e).__name__}: {e}"

    events: list[Any] = []
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict):
        raw = body.get("response", body.get("Event", []))
        if isinstance(raw, dict):
            events = [raw]
        elif isinstance(raw, list):
            events = raw

    # Client-side filter: events whose `info` contains "EdgeGuard". Matches
    # the MISP-writer event-naming convention (EdgeGuard-{source}-{date}).
    eg_events = [e for e in events if "EdgeGuard" in str(e.get("info", "") or e.get("Event", {}).get("info", ""))]
    return len(eg_events), None


def _probe_checkpoint() -> tuple[int, Optional[str]]:
    """Probe checkpoint state — count per-source entries in the JSON file.

    Returns ``(count, error)``. 0 means the file is missing or empty
    (both are valid clean states). The verify loop only needs == 0.
    """
    try:
        from baseline_checkpoint import load_checkpoint
    except ImportError as e:
        return 0, f"{type(e).__name__}: {e}"
    try:
        data = load_checkpoint()
    except Exception as e:
        logger.debug("probe_checkpoint failed", exc_info=True)
        return 0, f"{type(e).__name__}: {str(e)[:160]}"
    if not isinstance(data, dict):
        return 0, f"checkpoint file malformed (type={type(data).__name__})"
    return len(data), None


def probe_baseline_state(client: Any = None) -> BaselineState:
    """Run all three probes and return a :class:`BaselineState` snapshot.

    Used by:
      - The CLI wrapper's preflight (to display blast radius before asking
        for typed confirmation)
      - The pre-wipe log line in :func:`reset_baseline_data`
      - The post-clean verify loop (poll calls this repeatedly)

    Args:
        client: optional already-open ``Neo4jClient``. If None, opens a
            short-lived connection. Reuse a long-lived client when polling
            (every 2s) to avoid driver churn.
    """
    own_client = False
    drv_client = client
    try:
        if drv_client is None:
            from neo4j_client import Neo4jClient

            drv_client = Neo4jClient()
            own_client = True
            if not drv_client.connect():
                # Neo4j unreachable; still probe MISP + checkpoint.
                drv_client = None

        if drv_client is not None:
            n_count, n_breakdown, n_err = _probe_neo4j(drv_client)
        else:
            n_count, n_breakdown, n_err = 0, (), "Cannot connect to Neo4j"

        # MISP config — lazy-import to avoid hard dep when only Neo4j matters
        misp_url = os.getenv("MISP_URL", "https://localhost:8443")
        misp_api_key = os.getenv("MISP_API_KEY", "")
        try:
            from config import edgeguard_ssl_verify_from_env

            ssl_verify = edgeguard_ssl_verify_from_env()
        except ImportError:
            ssl_verify = os.getenv("EDGEGUARD_SSL_VERIFY", os.getenv("SSL_VERIFY", "true")).strip().lower() == "true"
        m_count, m_err = _probe_misp(misp_url, misp_api_key, ssl_verify)

        c_count, c_err = _probe_checkpoint()

        return BaselineState(
            neo4j_count=n_count,
            neo4j_breakdown=n_breakdown,
            neo4j_ok=n_err is None,
            neo4j_error=n_err,
            misp_count=m_count,
            misp_ok=m_err is None,
            misp_error=m_err,
            checkpoint_count=c_count,
            checkpoint_ok=c_err is None,
            checkpoint_error=c_err,
        )
    finally:
        if own_client and drv_client is not None:
            try:
                drv_client.close()
            except Exception:
                logger.debug("close on probe-owned Neo4jClient failed", exc_info=True)


# --------------------------------------------------------------------------- #
# Wipe — atomic, fail-fast
# --------------------------------------------------------------------------- #


def _wipe_checkpoints() -> None:
    """Step 1: clear all checkpoint state (baseline AND incremental cursors).

    Uses ``include_incremental=True`` so the "true clean slate" semantics
    promised by docs/AIRFLOW_DAGS.md are honored (operator triggering
    fresh-baseline expects EVERYTHING gone, not just baseline cursors).
    """
    from baseline_checkpoint import clear_checkpoint

    clear_checkpoint(include_incremental=True)


def _wipe_neo4j(client: Any) -> None:
    """Step 2: wipe all Neo4j graph data via ``Neo4jClient.clear_all()``.

    Constraints + indexes are preserved (clear_all is documented to keep
    schema). Caller is responsible for the open connection.
    """
    if not client.driver:
        raise RuntimeError("Neo4jClient is not connected — cannot wipe")
    if not client.clear_all():
        raise RuntimeError("Neo4jClient.clear_all() returned False")


def _wipe_misp_events(misp_url: str, misp_api_key: str, ssl_verify: bool, max_pages: int = 20) -> int:
    """Step 3: delete all EdgeGuard-tagged events from MISP.

    Always re-fetches page 1 after each round (deleted events disappear,
    so remaining events shift up). Capped at ``max_pages`` rounds × 500
    events/round = 10K events, which covers any realistic deployment.
    Returns the count actually deleted; raises if the MISP API errors.
    """
    if not misp_api_key:
        raise RuntimeError("MISP_API_KEY env var not set — cannot wipe")
    try:
        import requests as _req
        import urllib3
    except ImportError as e:
        raise RuntimeError(f"requests/urllib3 unavailable: {e}") from e

    try:
        from config import apply_misp_http_host_header
    except ImportError:
        # Defensive fallback: just don't apply the host header. The import
        # branch defines the canonical signature ``(session: _SessionLike) -> None``;
        # this fallback's ``(session: Any) -> None`` mypy considers
        # incompatible (error code "misc"). At runtime they're called the
        # same way, so the type-ignore is correct — we're explicitly opting
        # out of the variant-signature check.
        def apply_misp_http_host_header(session: Any) -> None:  # type: ignore[misc]  # noqa: ARG001
            return

    sess = _req.Session()
    sess.headers.update({"Authorization": misp_api_key, "Accept": "application/json"})
    apply_misp_http_host_header(sess)

    deleted = 0
    for round_idx in range(max_pages):
        with warnings.catch_warnings():
            if not ssl_verify:
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            resp = sess.get(
                f"{misp_url}/events/index",
                params={"searchall": "EdgeGuard", "limit": 500},
                verify=ssl_verify,
                timeout=(15, 60),
            )
        if resp.status_code != 200:
            raise RuntimeError(f"MISP /events/index returned HTTP {resp.status_code} on round {round_idx}")
        try:
            body = resp.json()
        except ValueError as e:
            raise RuntimeError(f"MISP /events/index returned non-JSON: {e}") from e

        events: list[Any] = []
        if isinstance(body, list):
            events = body
        elif isinstance(body, dict):
            raw = body.get("response", body.get("Event", []))
            if isinstance(raw, dict):
                events = [raw]
            elif isinstance(raw, list):
                events = raw

        if not events:
            break  # Done — no more events to delete.

        for ev in events:
            eid = ev.get("id") or ev.get("Event", {}).get("id")
            if not eid:
                continue
            with warnings.catch_warnings():
                if not ssl_verify:
                    warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
                del_resp = sess.delete(
                    f"{misp_url}/events/{eid}",
                    verify=ssl_verify,
                    timeout=(15, 30),
                )
            if del_resp.status_code == 200:
                deleted += 1
            elif del_resp.status_code in (302,):
                # 302 is typically a MISP auth redirect — surface but keep going
                logger.warning("MISP event %s delete returned 302 (likely auth redirect) — skipping", eid)
            else:
                # 4xx/5xx on a delete is a real error — abort the wipe so the verify
                # loop sees the half-clean state and the helper raises.
                raise RuntimeError(f"MISP DELETE /events/{eid} returned HTTP {del_resp.status_code} — aborting wipe")
    return deleted


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def reset_baseline_data(
    *,
    settle_seconds: float = 5.0,
    verify_timeout_seconds: float = 60.0,
    verify_poll_interval_seconds: float = 2.0,
    misp_max_pages: int = 20,
) -> CleanResult:
    """Atomically wipe + verify the three baseline datastores.

    Order:
      1. Probe pre-wipe state (for blast-radius display + audit log).
      2. Wipe checkpoints (idempotent; safe to re-run).
      3. Wipe Neo4j graph data via ``clear_all`` (preserves schema).
      4. Wipe MISP EdgeGuard events via paginated DELETE.
      5. Settle for ``settle_seconds`` (let async commits flush).
      6. Poll-verify every ``verify_poll_interval_seconds`` until all
         three counts are 0 OR ``verify_timeout_seconds`` elapses.

    If ANY step fails (or verify times out non-zero), raises
    :class:`BaselineCleanError` carrying the partial state. Callers (CLI
    wrapper, DAG task) MUST treat the exception as "do not run collectors."

    Args:
        settle_seconds: how long to wait between wipe completion and the
            first verify probe. Default 5s — enough for Neo4j transaction
            commits + MISP database flushes to settle.
        verify_timeout_seconds: max time to spend in the verify poll
            before raising. Default 60s — if anything's still non-zero
            after a minute, something's wrong.
        verify_poll_interval_seconds: how often to re-probe during verify.
            Default 2s.
        misp_max_pages: safety cap on the MISP delete loop (max events
            deleted = pages × 500). Default 20 = 10K events.

    Returns:
        :class:`CleanResult` with the pre-wipe and post-verify snapshots
        plus timing data.

    Raises:
        :class:`BaselineCleanError` on any step failure or verify timeout.
    """
    t0 = time.monotonic()
    logger.info("=" * 70)
    logger.info("BASELINE CLEAN — wipe + verify cycle starting")
    logger.info("=" * 70)

    # Open a single Neo4jClient and reuse it for the pre-probe + wipe + verify
    # poll. Closes in the finally block.
    from neo4j_client import Neo4jClient

    client = Neo4jClient()
    if not client.connect():
        raise BaselineCleanError(
            "Cannot connect to Neo4j — refusing to wipe MISP without Neo4j connectivity",
            partial_state=None,
        )

    try:
        # 1. Pre-wipe state — for blast-radius display + audit log
        before = probe_baseline_state(client=client)
        logger.info("Pre-wipe state:")
        for line in before.render_summary().splitlines():
            logger.info(line)
        logger.info("")

        # Refuse to wipe if any pre-probe failed — operator wouldn't have
        # informed-consent counts to act on.
        if not before.all_reachable:
            raise BaselineCleanError(
                f"Pre-wipe probe failed (Neo4j={before.neo4j_ok}, "
                f"MISP={before.misp_ok}, checkpoint={before.checkpoint_ok}) — "
                "refusing to proceed without complete blast-radius visibility.",
                partial_state=before,
            )

        # 2. Wipe checkpoints
        logger.info("Step 1/3: clearing checkpoints (incl. incremental cursors)…")
        try:
            _wipe_checkpoints()
        except Exception as e:
            raise BaselineCleanError(
                f"Checkpoint wipe failed: {type(e).__name__}: {e}",
                partial_state=before,
            ) from e
        logger.info("  ✓ checkpoints cleared")

        # 3. Wipe Neo4j
        logger.info("Step 2/3: wiping Neo4j graph data via clear_all()…")
        try:
            _wipe_neo4j(client)
        except Exception as e:
            raise BaselineCleanError(
                f"Neo4j wipe failed: {type(e).__name__}: {e}",
                partial_state=before,
            ) from e
        logger.info("  ✓ Neo4j graph cleared (constraints + indexes preserved)")

        # 4. Wipe MISP
        logger.info("Step 3/3: wiping MISP EdgeGuard events…")
        misp_url = os.getenv("MISP_URL", "https://localhost:8443")
        misp_api_key = os.getenv("MISP_API_KEY", "")
        try:
            from config import edgeguard_ssl_verify_from_env

            ssl_verify = edgeguard_ssl_verify_from_env()
        except ImportError:
            ssl_verify = os.getenv("EDGEGUARD_SSL_VERIFY", os.getenv("SSL_VERIFY", "true")).strip().lower() == "true"
        try:
            deleted = _wipe_misp_events(misp_url, misp_api_key, ssl_verify, max_pages=misp_max_pages)
        except Exception as e:
            raise BaselineCleanError(
                f"MISP wipe failed: {type(e).__name__}: {e}",
                partial_state=before,
            ) from e
        logger.info("  ✓ MISP cleared (%d EdgeGuard events deleted)", deleted)

        # 5. Settle
        logger.info("")
        logger.info("Settling %.1fs before post-clean verification…", settle_seconds)
        time.sleep(settle_seconds)

        # 6. Poll-verify
        logger.info(
            "Verifying (poll every %.1fs, timeout %.1fs):", verify_poll_interval_seconds, verify_timeout_seconds
        )
        verify_deadline = time.monotonic() + verify_timeout_seconds
        attempt = 0
        after = before  # init so the variable exists if verify fails on attempt 1
        while time.monotonic() < verify_deadline:
            attempt += 1
            after = probe_baseline_state(client=client)
            if after.all_zero:
                logger.info("  ✓ verified all-zero on attempt #%d", attempt)
                break
            logger.info(
                "  attempt #%d — Neo4j=%d, MISP=%d, checkpoint=%d (not all zero yet)",
                attempt,
                after.neo4j_count,
                after.misp_count,
                after.checkpoint_count,
            )
            time.sleep(verify_poll_interval_seconds)
        else:
            # Loop exhausted without break — verify failed
            raise BaselineCleanError(
                f"Verify failed after {attempt} attempts ({verify_timeout_seconds}s): "
                f"Neo4j={after.neo4j_count}, MISP={after.misp_count}, "
                f"checkpoint={after.checkpoint_count}. "
                "Datastores still hold data — re-trigger fresh-baseline to retry "
                "(the wipe is idempotent).",
                partial_state=after,
            )

        duration = time.monotonic() - t0
        logger.info("")
        logger.info("BASELINE CLEAN complete in %.1fs (verify took %d attempts)", duration, attempt)
        logger.info("=" * 70)
        return CleanResult(
            before=before,
            after=after,
            duration_seconds=duration,
            verify_attempts=attempt,
        )
    finally:
        try:
            client.close()
        except Exception:
            logger.debug("close on baseline-clean Neo4jClient failed", exc_info=True)
