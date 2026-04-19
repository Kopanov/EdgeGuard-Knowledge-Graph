"""
EdgeGuard — Datastore Probes (shared)
=====================================

Single-source-of-truth probes for "how much data is in this datastore right
now, and is it reachable?" — used by every CLI/DAG/operator surface that
needs a uniform answer:

  - ``cmd_doctor``         (diagnostics; needs reachability + scale)
  - ``cmd_validate``       (config validation; future use)
  - ``cmd_clear_*``        (destructive ops; show blast radius pre-wipe;
                            verify post-wipe)
  - ``edgeguard fresh-baseline``  (CLI wrapper; preflight + post-clean
                            verification; informed-consent UX)
  - ``baseline_clean``     (Airflow task; pre/post wipe sanity checks)

Why a shared module
-------------------
Before this module, the same conceptual probes lived inline in 4 different
call sites with 4 subtly different shapes:

  - ``cmd_doctor`` did ``client.run("MATCH (n) WHERE n.edgeguard_managed = true …")``
  - ``cmd_validate`` did a different cypher checking unmanaged + orphan nodes
  - ``cmd_clear_misp`` had its own paginated ``requests.Session`` count loop
    intermixed with the delete loop (hard to reuse the count without re-running
    the delete)
  - ``test_misp_connection`` / ``test_neo4j_connection`` returned ``(bool, str)``
    tuples — useful for reachability but no count

Drift between them was inevitable: change the count query in one, the others
silently disagree. Same lesson as PR #46's apoc.coll.toSet centralisation —
chokepoint the contract so callers can't drift apart.

Shape contract
--------------
Every probe in this module returns a :class:`ProbeResult`. The dataclass is
``frozen`` and the ``ok`` flag is a derived property of ``error is None`` —
impossible to construct an "ok=True with error" half-state by accident.

Probes never raise; they return a ProbeResult with ``error`` set and
``count == 0``. That makes calling code uniform — no ``try/except`` walls
around every probe — and pushes the "what to do on failure" decision up to
the caller (where it belongs).

The optional ``breakdown`` field carries per-subtype counts (Neo4j nodes by
label, etc) for callers that want a richer report. Empty tuple if not
populated. Tuple-of-tuples (not dict) so the dataclass stays hashable +
preserves insertion order from the underlying query.
"""

from __future__ import annotations

import logging
import os
import sys
import warnings
from dataclasses import dataclass, field
from typing import Any, Optional

# Add src to path for sibling imports when invoked directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# ProbeResult — uniform return shape
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a single datastore probe.

    Three valid states:
      - ``error is None`` and ``count >= 0``: probe succeeded, count is real
      - ``error is not None``: probe failed; ``count`` is 0 (sentinel)
      - ``count == 0`` AND ``error is None``: datastore is empty (a *valid*
        success state, distinct from "probe failed")

    The ``ok`` property derives from ``error is None`` — always check ``ok``
    (not ``count > 0``) to disambiguate "empty datastore" from "probe failed".

    Attributes
    ----------
    label : str
        Human-readable name for the probed quantity, e.g.
        ``"Neo4j EdgeGuard nodes"`` or ``"MISP EdgeGuard events"``. Used by
        formatters like ``cmd_doctor``'s output and the post-clean verify
        log lines.
    count : int
        The probed count. **Always 0 on failure** (caller MUST check ``ok``
        before relying on this). On success, the count is the real value
        from the datastore — possibly 0 if the datastore is genuinely empty.
    error : Optional[str]
        ``None`` on success; a short human-readable error string on failure.
        Caps the underlying exception's ``str()`` to ~200 chars to keep log
        lines readable; full exception detail goes to the module logger.
    breakdown : tuple[tuple[str, int], ...]
        Optional per-subtype breakdown. Empty tuple by default. For the
        Neo4j node probe with ``with_breakdown=True``, this holds the top-N
        labels and their counts in descending order. Tuple-of-tuples (not
        dict) so the dataclass stays hashable + preserves the underlying
        query's ORDER BY.
    """

    label: str
    count: int
    error: Optional[str] = None
    breakdown: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True iff the probe completed successfully (regardless of count)."""
        return self.error is None

    def format_line(self) -> str:
        """One-line human-readable summary, suitable for log output.

        Examples::

            "Neo4j EdgeGuard nodes:        347,197   ✓"
            "MISP EdgeGuard events:        unreachable: ConnectionRefusedError"

        Padding mirrors what the post-clean verify task wants in the
        Airflow log; ``cmd_doctor`` may format differently.
        """
        if self.ok:
            return f"{self.label}: {self.count:>12,}   ✓"
        return f"{self.label}: unreachable: {self.error}"


def _short_error(exc: BaseException, *, limit: int = 200) -> str:
    """Render an exception as a short single-line string for logs."""
    name = type(exc).__name__
    msg = str(exc).strip().replace("\n", " ")
    out = f"{name}: {msg}" if msg else name
    return out[:limit]


# --------------------------------------------------------------------------- #
# Neo4j probes
# --------------------------------------------------------------------------- #
#
# Both probes accept an optional ``client`` so callers can reuse an open
# Neo4jClient (avoids opening a fresh driver for every probe). Pass None and
# the probe opens + closes its own short-lived connection.
#
# The default scope is ``edgeguard_managed = true`` to match what every
# call site in the codebase actually wants ("how much EdgeGuard data is
# there?"). Pass ``edgeguard_managed_only=False`` to count every node
# (useful only for diagnostics in mixed graphs).


_NEO4J_COUNT_QUERY_MANAGED = """
MATCH (n)
WHERE n.edgeguard_managed = true
RETURN count(n) AS cnt
"""

_NEO4J_COUNT_QUERY_ALL = """
MATCH (n)
RETURN count(n) AS cnt
"""

_NEO4J_BREAKDOWN_QUERY_MANAGED = """
MATCH (n)
WHERE n.edgeguard_managed = true
RETURN labels(n)[0] AS label, count(n) AS cnt
ORDER BY cnt DESC
LIMIT $top_n
"""

_NEO4J_BREAKDOWN_QUERY_ALL = """
MATCH (n)
RETURN labels(n)[0] AS label, count(n) AS cnt
ORDER BY cnt DESC
LIMIT $top_n
"""


def probe_neo4j_node_count(
    client: Any = None,
    *,
    edgeguard_managed_only: bool = True,
    with_breakdown: bool = False,
    top_n: int = 10,
) -> ProbeResult:
    """Count nodes in Neo4j; optionally include a per-label breakdown.

    Parameters
    ----------
    client : Optional[Neo4jClient]
        Existing open Neo4jClient. If None, the probe opens a short-lived
        connection (and closes it before returning). Reuse a long-lived
        client when probing multiple times back-to-back to avoid driver
        churn.
    edgeguard_managed_only : bool, default True
        If True (default), counts only nodes with ``edgeguard_managed=true``
        — matches the semantics every CLI/DAG caller actually wants. If
        False, counts every node in the graph (rarely useful; pass for
        mixed-graph diagnostics).
    with_breakdown : bool, default False
        If True, populates ``ProbeResult.breakdown`` with the top-N labels
        and their counts in descending order. Costs one extra query (a
        grouped count vs a single count); skip when you only need the total.
    top_n : int, default 10
        How many label entries to include in the breakdown. Ignored when
        ``with_breakdown=False``.

    Returns
    -------
    ProbeResult
        ``label = "Neo4j EdgeGuard nodes"`` (or ``"Neo4j nodes"`` when
        ``edgeguard_managed_only=False``). ``count`` is the total.
        ``breakdown`` is empty unless ``with_breakdown=True``.
    """
    label_text = "Neo4j EdgeGuard nodes" if edgeguard_managed_only else "Neo4j nodes"
    own_client = False
    try:
        if client is None:
            from neo4j_client import Neo4jClient

            client = Neo4jClient()
            # Bugbot LOW (PR #47 audit): set ``own_client = True`` BEFORE
            # the connect attempt so the ``finally`` block always closes
            # any client we instantiated, even when ``connect()`` returned
            # False. Earlier code set ``own_client`` only after a
            # successful connect — the early return below (line 226)
            # then bypassed the finally and leaked the Neo4jClient
            # instance + its underlying driver. ``Neo4jClient.close()``
            # is safe to call even when never-connected (driver is None
            # or already torn down).
            own_client = True
            if not client.connect():
                return ProbeResult(label=label_text, count=0, error="Cannot connect to Neo4j")

        count_query = _NEO4J_COUNT_QUERY_MANAGED if edgeguard_managed_only else _NEO4J_COUNT_QUERY_ALL
        count_rows = client.run(count_query)
        # Defensive ``or 0`` (not ``.get("cnt", 0)``) — Cypher ``count()``
        # never returns NULL in practice, but ``int(None)`` would raise; the
        # cross-checker audit caught this as a thin edge case.
        total = int(count_rows[0].get("cnt") or 0) if count_rows else 0

        breakdown: tuple[tuple[str, int], ...] = ()
        if with_breakdown:
            # Cross-checker audit BUG-1: ``Neo4jClient.run`` takes parameters
            # as a positional ``Dict``, NOT as ``**kwargs``. Earlier draft
            # called ``client.run(br_query, top_n=top_n)`` which would have
            # raised ``TypeError`` in production — the test mock accepted
            # arbitrary kwargs and hid the divergence. Fixed: pass dict.
            br_query = _NEO4J_BREAKDOWN_QUERY_MANAGED if edgeguard_managed_only else _NEO4J_BREAKDOWN_QUERY_ALL
            br_rows = client.run(br_query, {"top_n": int(top_n)})
            breakdown = tuple((str(r.get("label") or "<unknown>"), int(r.get("cnt") or 0)) for r in (br_rows or []))

        return ProbeResult(label=label_text, count=total, breakdown=breakdown)

    except Exception as e:
        logger.debug("probe_neo4j_node_count failed", exc_info=True)
        return ProbeResult(label=label_text, count=0, error=_short_error(e))
    finally:
        if own_client and client is not None:
            try:
                client.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# MISP probes
# --------------------------------------------------------------------------- #
#
# We use a raw ``requests`` session (not pymisp) for two reasons:
#   1. ``cmd_doctor`` already does this — keeping the same shape avoids
#      changing the doctor's exact output text (the regression test pins it).
#   2. PyMISP's startup (importing the SDK + parsing the connection) is
#      slow enough that the post-clean verify loop (poll every 2s) would
#      re-pay the cost on each iteration.
#
# All HTTP calls honour the SSL_VERIFY env knob (PR (security S7) — was
# previously hardcoded ``verify=False`` in some probes, leaking the API key
# over MITM-able TLS). The auth header carries the API key value as-is per
# MISP's convention (no ``Bearer `` prefix).


_MISP_DEFAULT_TIMEOUT = (10, 30)  # (connect_timeout, read_timeout) in seconds
# (No page-limit constant. Bugbot MED on PR #47 noted that the pre-refactor
# inline code in cmd_doctor sent NO ``params`` to ``/events/index`` — the
# response is bounded by MISP's default page size. The probe matches that
# exactly. PR2's post-clean verify queries with ``count == 0`` semantics
# anyway, so the page bound is irrelevant there. PR3's preflight blast-radius
# UI will use the dedicated count endpoint instead, when it ships.)


def probe_misp_event_count(
    *,
    misp_url: Optional[str] = None,
    misp_api_key: Optional[str] = None,
    ssl_verify: Optional[bool] = None,
    edgeguard_only: bool = True,
    timeout: tuple[int, int] = _MISP_DEFAULT_TIMEOUT,
) -> ProbeResult:
    """Count MISP events; optionally filter to EdgeGuard-tagged events only.

    Uses a one-shot ``requests.get`` against ``/events/index``. Does NOT
    paginate — for the typical EdgeGuard deployment (8K events, fits in one
    500-event page after MISP's default response shaping) the count comes
    from the response length. For dramatically larger deployments, callers
    should pass through to the dedicated MISP delete loop in
    ``cmd_clear_misp`` which DOES paginate.

    Parameters
    ----------
    misp_url, misp_api_key, ssl_verify
        Override the env-var defaults. Useful for tests; production should
        pass None and let the function resolve from env.
    edgeguard_only : bool, default True
        If True, returns the count of events whose ``info`` contains
        ``"EdgeGuard"`` (matches doctor's existing filter). If False,
        returns the total event count regardless of source.
    timeout : tuple[int, int]
        ``(connect, read)`` timeout in seconds. Defaults are conservative
        for the post-clean verify loop (re-runs every 2s; don't wait too
        long per attempt).

    Returns
    -------
    ProbeResult
        ``label = "MISP EdgeGuard events"`` or ``"MISP events"``. ``count``
        is the event count. ``breakdown`` is empty (MISP doesn't have a
        cheap grouped count without iterating attributes).
    """
    label_text = "MISP EdgeGuard events" if edgeguard_only else "MISP events"

    # Resolve config (lazy — don't import config module at module load
    # time; the DAG worker may not have all env vars set yet).
    if misp_url is None:
        misp_url = os.getenv("MISP_URL", "https://localhost:8443")
    if misp_api_key is None:
        misp_api_key = os.getenv("MISP_API_KEY", "")
    if ssl_verify is None:
        ssl_verify = _resolve_ssl_verify_env()

    if not misp_api_key:
        return ProbeResult(label=label_text, count=0, error="MISP_API_KEY env var not set")

    try:
        import requests as _req
        import urllib3
    except ImportError as e:
        return ProbeResult(label=label_text, count=0, error=_short_error(e))

    try:
        with warnings.catch_warnings():
            if not ssl_verify:
                warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
            # Cross-checker audit DRIFT-1 + Bugbot MED on PR #47: send NO
            # ``params`` at all to match the pre-refactor inline code in
            # ``cmd_doctor`` exactly. The earlier draft sent
            # ``params={"limit": 500}`` and ``params={"searchall": ...}``
            # — both ABSENT from the pre-refactor code. The pre-refactor
            # response was bounded by MISP's default page size; this probe
            # now produces the same bound for true zero-behavior-change.
            # Filtering to EdgeGuard-tagged events is done client-side
            # below (info-substring match), matching the pre-refactor.
            resp = _req.get(
                f"{misp_url}/events/index",
                headers={"Authorization": misp_api_key, "Accept": "application/json"},
                verify=ssl_verify,
                timeout=timeout,
            )
    except Exception as e:
        logger.debug("probe_misp_event_count GET failed", exc_info=True)
        return ProbeResult(label=label_text, count=0, error=_short_error(e))

    if resp.status_code != 200:
        return ProbeResult(label=label_text, count=0, error=f"MISP returned HTTP {resp.status_code}")

    try:
        body = resp.json()
    except ValueError as e:
        return ProbeResult(label=label_text, count=0, error=_short_error(e))

    # MISP returns either a list (older API) or a dict with "response"/"Event"
    # key. Annotate explicitly so mypy doesn't widen to ``Any | None`` when
    # the dict.get fallback chain is used below.
    events: list[Any] = []
    if isinstance(body, list):
        events = body
    elif isinstance(body, dict):
        raw = body.get("response", body.get("Event", []))
        if isinstance(raw, dict):
            events = [raw]
        elif isinstance(raw, list):
            events = raw

    # Optional client-side filter: ``searchall`` server-side is best-effort
    # (matches event info OR tags OR attributes), so we re-filter on info
    # to match what cmd_doctor used to do inline.
    if edgeguard_only:
        events = [e for e in events if "EdgeGuard" in str(e.get("info", "") or e.get("Event", {}).get("info", ""))]

    return ProbeResult(label=label_text, count=len(events))


def _resolve_ssl_verify_env() -> bool:
    """Resolve the SSL_VERIFY flag using the SAME logic as ``config.py``.

    Cross-checker audit DRIFT-3: an earlier draft inlined a divergent
    deny-list resolution that:
      (a) only checked ``SSL_VERIFY``, missing the ``EDGEGUARD_SSL_VERIFY``
          env-var that the rest of the codebase honours (config.py:340-353).
          A deployment using ``EDGEGUARD_SSL_VERIFY=false`` (the documented
          preferred form) would see the probe default to TLS verify ON,
          breaking self-signed dev MISP probes.
      (b) used a deny-list of disable values (``false``/``0``/``no``/``off``)
          where config.py uses an allow-list (``true`` only enables;
          everything else disables). Different value-mappings = silent drift.

    Fix: lazy-import + delegate to ``config.edgeguard_ssl_verify_from_env``
    so all SSL_VERIFY decisions in EdgeGuard share one implementation. The
    import is lazy because:
      - ``config.py`` reads env at module-load time; tests need to monkeypatch
        and re-resolve, which works iff the import happens inside the
        function (re-reading the live env each call).
      - Avoids a circular import surface on early DAG init paths.

    Falls back to ``os.getenv("SSL_VERIFY") == "true"`` if config.py is
    unavailable (e.g. in a unit test that hasn't installed config's deps).
    """
    try:
        from config import edgeguard_ssl_verify_from_env as _resolve

        return _resolve()
    except ImportError:
        # Defensive fallback: matches config.py's logic but without the import.
        # config.py reads EDGEGUARD_SSL_VERIFY first, then SSL_VERIFY.
        for key in ("EDGEGUARD_SSL_VERIFY", "SSL_VERIFY"):
            raw = os.getenv(key)
            if raw is None:
                continue
            stripped = str(raw).strip()
            if not stripped:
                continue
            return stripped.lower() == "true"
        return True


# --------------------------------------------------------------------------- #
# Checkpoint probe
# --------------------------------------------------------------------------- #
#
# Checkpoints live in a single JSON file (CHECKPOINT_FILE), keyed by
# source. Each source can have:
#   - baseline state (page, pages[], items_collected, completed, started_at)
#   - incremental state (modified_since, etag, …)
# After ``clear_checkpoint(include_incremental=False)`` the file may still
# exist (incremental cursors preserved); after
# ``clear_checkpoint(include_incremental=True)`` the file is removed entirely.
#
# For the post-clean verify, "checkpoint clean" means "file does not exist
# OR file is empty {}". Anything else means we leaked state across the wipe.


def probe_checkpoint_state(*, include_incremental: bool = True) -> ProbeResult:
    """Count checkpoint entries (per-source baseline/incremental state).

    Parameters
    ----------
    include_incremental : bool, default True
        If True (default), counts every per-source entry — both baseline
        and incremental-only entries. Match this to the wipe call's
        ``include_incremental`` so post-clean verify checks the same scope
        as the wipe touched.

    Returns
    -------
    ProbeResult
        ``label = "Checkpoint entries"``. ``count`` is the number of
        per-source entries in the checkpoint file (0 if the file doesn't
        exist or is empty). ``breakdown`` lists ``(source_name, num_keys)``
        pairs sorted by source name for stable ordering.

        On failure (file unreadable, JSON corrupt), returns ``error`` set;
        ``count`` is 0 sentinel. The underlying ``baseline_checkpoint``
        module is forgiving — it returns ``{}`` on parse errors — so the
        only practical failure mode is the import itself failing.
    """
    label_text = "Checkpoint entries"
    try:
        from baseline_checkpoint import load_checkpoint
    except ImportError as e:
        return ProbeResult(label=label_text, count=0, error=_short_error(e))

    try:
        data = load_checkpoint()
    except Exception as e:
        logger.debug("probe_checkpoint_state load failed", exc_info=True)
        return ProbeResult(label=label_text, count=0, error=_short_error(e))

    if not isinstance(data, dict):
        return ProbeResult(label=label_text, count=0, error=f"Checkpoint file malformed: type={type(data).__name__}")

    if not include_incremental:
        # Filter to only sources that have baseline state.
        baseline_keys = ("page", "pages", "items_collected", "completed", "started_at")
        data = {
            src: state
            for src, state in data.items()
            if isinstance(state, dict) and any(k in state for k in baseline_keys)
        }

    breakdown = tuple((str(src), len(state) if isinstance(state, dict) else 0) for src, state in sorted(data.items()))
    return ProbeResult(label=label_text, count=len(data), breakdown=breakdown)


# --------------------------------------------------------------------------- #
# Convenience: probe everything baseline-related at once
# --------------------------------------------------------------------------- #


def probe_all_for_baseline(client: Any = None, *, with_breakdown: bool = False) -> tuple[ProbeResult, ...]:
    """Run all three baseline-relevant probes and return a tuple of results.

    Convenience wrapper for the two callers that need the full picture:
      - ``edgeguard fresh-baseline`` preflight (PR3): show blast radius
        before asking for typed confirmation
      - ``baseline_clean`` post-wipe verify (PR2): assert all three are
        clean before letting collectors proceed

    The tuple order is stable: ``(neo4j, misp, checkpoint)`` — callers
    can unpack positionally or iterate.

    Parameters
    ----------
    client : Optional[Neo4jClient]
        Reused for the Neo4j probe; unused for MISP/checkpoint. Pass an
        already-open client if you have one to skip the connect/close
        round-trip.
    with_breakdown : bool, default False
        Forwarded to ``probe_neo4j_node_count`` (per-label breakdown) and
        ``probe_checkpoint_state`` always returns its breakdown.

    Returns
    -------
    tuple[ProbeResult, ProbeResult, ProbeResult]
        ``(neo4j, misp, checkpoint)``. Inspect each ``.ok`` to know which
        succeeded; failures don't propagate (each probe is independent).
    """
    neo4j = probe_neo4j_node_count(client=client, with_breakdown=with_breakdown)
    misp = probe_misp_event_count()
    checkpoint = probe_checkpoint_state()
    return (neo4j, misp, checkpoint)
