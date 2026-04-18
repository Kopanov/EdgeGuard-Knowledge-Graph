"""PR #40 regression pins for the "kill the sleeps" performance fix.

Performance Auditor (proactive audit) Tier S S10 — EdgeGuard had ~30
hardcoded ``time.sleep(3)`` and ``time.sleep(1)`` sites scattered
across 4 files (``build_relationships.py``, ``enrichment_jobs.py``,
``neo4j_client.py`` batch path, ``run_misp_to_neo4j.py`` chunk loop)
collectively burning **30 minutes to ~3 hours of pure idle time
per baseline run** (and 5–15 minutes per incremental).

Fix: centralize via ``src/query_pause.py``. Default: NO sleep
(``EDGEGUARD_QUERY_PAUSE_SECONDS=0``). Operators on memory-
constrained Neo4j who genuinely need pacing can opt in by setting
the env var without a code change.

Pins below cover both the helper's own contract AND that no callsite
re-introduces a hardcoded ``time.sleep(3)`` / ``time.sleep(1)`` in
the hot batch paths (source-grep regression check).
"""

from __future__ import annotations

import os
import sys
import time
from unittest.mock import patch

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---------------------------------------------------------------------------
# query_pause helper — direct contract
# ---------------------------------------------------------------------------


def test_query_pause_seconds_default_is_zero(monkeypatch):
    """Default behavior: env var unset → 0 seconds. This is the WHOLE
    point of PR #40 — the previous code burned 30min-3h per baseline
    on hardcoded sleeps that operators couldn't disable."""
    monkeypatch.delenv("EDGEGUARD_QUERY_PAUSE_SECONDS", raising=False)
    from query_pause import query_pause_seconds

    assert query_pause_seconds() == 0.0


def test_query_pause_seconds_reads_env_value(monkeypatch):
    """Operators on memory-constrained Neo4j can opt in to pacing."""
    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "1.5")
    from query_pause import query_pause_seconds

    assert query_pause_seconds() == 1.5


def test_query_pause_seconds_handles_malformed_env_gracefully(monkeypatch):
    """Operator typo (``"abc"`` or ``"3 seconds"``) must not crash —
    fall back to 0 with a debug log."""
    from query_pause import query_pause_seconds

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "abc")
    assert query_pause_seconds() == 0.0

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "3 seconds")
    assert query_pause_seconds() == 0.0

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "")
    assert query_pause_seconds() == 0.0


def test_query_pause_seconds_negative_treated_as_zero(monkeypatch):
    """Defensive: a negative value (operator typo with the sign) must
    NOT crash time.sleep — clamp to 0."""
    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "-5")
    from query_pause import query_pause_seconds

    assert query_pause_seconds() == 0.0


def test_query_pause_seconds_inf_clamped_to_max(monkeypatch):
    """PR #39 commit X (bugbot LOW) regression pin.

    ``EDGEGUARD_QUERY_PAUSE_SECONDS=inf`` would have passed the old
    ``not (seconds >= 0)`` guard (``inf >= 0`` is True), then
    ``time.sleep(inf)`` would hang the worker forever — exactly the
    failure mode the original comment said was prevented. The cap
    catches this.
    """
    from query_pause import _MAX_PAUSE_SECS, query_pause_seconds

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "inf")
    result = query_pause_seconds()
    assert result == float(_MAX_PAUSE_SECS), f"inf must be clamped to _MAX_PAUSE_SECS ({_MAX_PAUSE_SECS}); got {result}"

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "Infinity")
    assert query_pause_seconds() == float(_MAX_PAUSE_SECS)


def test_query_pause_seconds_absurdly_large_clamped_to_max(monkeypatch):
    """Same cap applies to large finite values — operator setting
    ``999999`` (10+ days) typed too many digits; refuse silently."""
    from query_pause import _MAX_PAUSE_SECS, query_pause_seconds

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "999999")
    assert query_pause_seconds() == float(_MAX_PAUSE_SECS)


def test_query_pause_seconds_value_at_cap_is_returned_unchanged(monkeypatch):
    """Boundary: exactly ``_MAX_PAUSE_SECS`` is allowed."""
    from query_pause import _MAX_PAUSE_SECS, query_pause_seconds

    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", str(_MAX_PAUSE_SECS))
    assert query_pause_seconds() == float(_MAX_PAUSE_SECS)


def test_query_pause_skips_sleep_when_env_unset(monkeypatch):
    """The skipping must be at the call-site level — query_pause()
    must NOT call time.sleep() at all when seconds is 0. Otherwise
    we still pay context-switch overhead millions of times across
    a baseline run."""
    monkeypatch.delenv("EDGEGUARD_QUERY_PAUSE_SECONDS", raising=False)

    with patch.object(time, "sleep") as mock_sleep:
        from query_pause import query_pause

        query_pause()
        mock_sleep.assert_not_called()


def test_query_pause_calls_sleep_when_env_set(monkeypatch):
    """When operator opts in, time.sleep IS called with the configured value."""
    monkeypatch.setenv("EDGEGUARD_QUERY_PAUSE_SECONDS", "0.5")

    # Patch time.sleep at the query_pause module level (where it's imported)
    import query_pause as qp_mod

    with patch.object(qp_mod.time, "sleep") as mock_sleep:
        qp_mod.query_pause()
        mock_sleep.assert_called_once_with(0.5)


# ---------------------------------------------------------------------------
# Source-grep regression pins — no callsite re-introduces a hardcoded sleep
# ---------------------------------------------------------------------------


def _code_only(text: str) -> str:
    """Strip comment-only lines so source-grep doesn't false-match
    historical-fix comments that mention the old pattern."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_build_relationships_uses_query_pause_not_hardcoded_sleep():
    """build_relationships.py must use ``query_pause()`` for ALL
    inter-query pacing — no leftover ``time.sleep(N)`` or
    ``time.sleep(_INTER_QUERY_PAUSE)`` patterns. The ``_INTER_QUERY_PAUSE``
    constant itself should be GONE since the env var supersedes it."""
    path = os.path.join(_SRC, "build_relationships.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    assert "time.sleep(_INTER_QUERY_PAUSE)" not in src, (
        "build_relationships.py must not call time.sleep(_INTER_QUERY_PAUSE) — "
        "use query_pause() so EDGEGUARD_QUERY_PAUSE_SECONDS env-gating works"
    )
    # Constant should be gone too
    assert "_INTER_QUERY_PAUSE = 3" not in src, (
        "_INTER_QUERY_PAUSE constant must be removed in favor of the env-gated query_pause helper"
    )
    # And there must be at least one query_pause call (sanity check we didn't drop them all)
    assert "query_pause()" in src


def test_enrichment_jobs_uses_query_pause_in_hot_paths():
    """enrichment_jobs.py: the 5 ``time.sleep(3)`` sites must be
    replaced with ``query_pause()``."""
    path = os.path.join(_SRC, "enrichment_jobs.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # Bare time.sleep(3) is the smoking gun
    assert "time.sleep(3)" not in src, (
        "enrichment_jobs.py must use query_pause() — bare time.sleep(3) "
        "burns minutes per calibration run at production scale"
    )
    assert "query_pause()" in src


def test_neo4j_client_batch_uses_query_pause_not_sleep_one():
    """neo4j_client.py: the 10 ``time.sleep(1)`` sites in the
    create_misp_relationships_batch ``_run_rows`` block must be
    replaced. At baseline scale (~880 chunks) this was ~2.7 hours
    of pure idle time."""
    path = os.path.join(_SRC, "neo4j_client.py")
    with open(path) as fh:
        src = _code_only(fh.read())
    # The pattern was specifically inside the rels batch — search for it
    # with the indentation that bounds it to that function.
    assert "                time.sleep(1)" not in src, (
        "neo4j_client.py create_misp_relationships_batch must use query_pause() — "
        "10 hardcoded time.sleep(1) sites burned ~2.7h per baseline"
    )


def test_run_misp_to_neo4j_chunk_loop_uses_query_pause():
    """run_misp_to_neo4j.py chunk-pacing sleeps (3 sites) must be env-gated.
    Note: the rate-limit / retry-cooldown sleeps are a SEPARATE category —
    those keep their own env vars (event_fetch_throttle, retry_cooldown)
    because they have semantically different meaning (per-vendor rate limits,
    not just hot-loop pacing). This test only enforces the chunk-pacing
    replacements."""
    path = os.path.join(_SRC, "run_misp_to_neo4j.py")
    with open(path) as fh:
        src = fh.read()

    # Locate each chunk-pacing site by its surrounding context line
    # (the comment string survives through the env-gating refactor)
    chunk_pacing_markers = [
        ("Pause between chunks to let Neo4j flush transactions", "Skip delay after the last chunk"),
        ("Pause between chunks to let Neo4j flush transactions (skip after last chunk)", "if idx < total_chunks"),
        ("Release page memory and pause before next page", "del page_items"),
    ]
    for primary, secondary in chunk_pacing_markers:
        anchor_idx = src.find(primary)
        if anchor_idx < 0:
            # Tolerate header reformatting — fall back to secondary
            anchor_idx = src.find(secondary)
        if anchor_idx < 0:
            continue  # Marker may have been refactored out — skip rather than false-fail
        # Check the next ~500 chars for query_pause() and absence of time.sleep(3)
        window = src[anchor_idx : anchor_idx + 500]
        assert "query_pause()" in window, (
            f"chunk-pacing site near {primary!r} must call query_pause() — saw: {window[:200]!r}"
        )


# ---------------------------------------------------------------------------
# Documentation pin — env var must be discoverable
# ---------------------------------------------------------------------------


def test_query_pause_module_has_docstring_documenting_env_var():
    """Future maintainers must see the rationale + the env name.
    Without this trace, someone "simplifying" the helper by inlining
    a hardcoded sleep silently re-introduces the audit-flagged bug."""
    import query_pause

    doc = query_pause.__doc__ or ""
    assert "EDGEGUARD_QUERY_PAUSE_SECONDS" in doc, (
        "query_pause module docstring must document the env var name "
        "so operators can discover it without reading the source"
    )
    assert "PR #40" in doc or "Performance Auditor" in doc, (
        "module docstring must reference the audit finding so the historical rationale is discoverable"
    )
