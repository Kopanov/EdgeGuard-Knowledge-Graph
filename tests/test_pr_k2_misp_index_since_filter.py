"""
PR-K2 §1-2 — server-side `timestamp` narrowing on MISP events-index fetch.

Regression coverage for ``_fetch_edgeguard_events_via_requests_index``
in ``src/run_misp_to_neo4j.py``. The function fetches EdgeGuard
events from MISP's ``/events/index`` (or ``/events``) endpoint, page
by page, capped at ``MISP_EVENTS_INDEX_MAX_PAGES``.

The original implementation passed ONLY ``limit`` and ``page`` query
params — no ``timestamp`` filter — even though the function accepted
a ``since`` datetime. Filtering happened client-side after the
pagination loop completed. On a populated MISP (e.g. one that
federates with peers), this meant the function walked up to
100 × 500 = 50,000 event rows of the entire instance before any
filter kicked in. The 100-page cap then silently truncated past
that — events past page 100 never reached Neo4j sync.

PR-K2 fix: when ``since`` is non-None, pass
``timestamp = int(since.timestamp())`` as a query param so MISP
narrows the result set on the server side BEFORE pagination. Same
convention as the PyMISP and ``/events/restSearch`` fallback paths
(lines ~977, ~997). The client-side filter stays as defense-in-depth
for older MISP versions that ignore the param.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int = 200, json_payload=None):
    """Build a fake ``requests.Response``-shaped object for the
    function under test. Only ``status_code`` and ``json()`` are read."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_payload if json_payload is not None else []
    return resp


# ===========================================================================
# Server-side timestamp narrowing
# ===========================================================================


class TestServerSideTimestampNarrowing:
    """When ``since`` is non-None, ``params["timestamp"]`` MUST be
    passed to the MISP GET request so the server narrows the result
    set before pagination."""

    def test_timestamp_param_present_when_since_given(self, monkeypatch):
        """Critical positive case: a ``since`` datetime must produce
        ``params["timestamp"] = int(since.timestamp())`` on every page
        request — the exact contract the audit fix introduces."""
        from run_misp_to_neo4j import _fetch_edgeguard_events_via_requests_index

        session = MagicMock()
        # Return one page with one EdgeGuard-tagged event, then exit
        # the loop via short-page condition.
        session.get.return_value = _make_response(200, json_payload=[])

        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = _fetch_edgeguard_events_via_requests_index(
            session,
            "https://misp.example.com",
            since=since,
        )
        assert result == []  # empty page → empty filtered list

        # Inspect every call to session.get
        assert session.get.called
        for call in session.get.call_args_list:
            kwargs = call.kwargs
            params = kwargs.get("params", {})
            assert "timestamp" in params, (
                f"every page request MUST carry the timestamp param when since is given; got params={params}"
            )
            assert params["timestamp"] == int(since.timestamp()), (
                f"timestamp param MUST equal int(since.timestamp())={int(since.timestamp())}; got {params['timestamp']}"
            )

    def test_timestamp_param_absent_when_since_is_none(self, monkeypatch):
        """Negative case: if no ``since`` provided, no timestamp param
        on the wire. Preserves the existing fetch-everything contract
        for fresh-baseline / first-run scenarios."""
        from run_misp_to_neo4j import _fetch_edgeguard_events_via_requests_index

        session = MagicMock()
        session.get.return_value = _make_response(200, json_payload=[])

        _fetch_edgeguard_events_via_requests_index(
            session,
            "https://misp.example.com",
            since=None,
        )

        for call in session.get.call_args_list:
            params = call.kwargs.get("params", {})
            assert "timestamp" not in params, f"timestamp param MUST be absent when since=None; got params={params}"

    def test_timestamp_value_is_integer_seconds(self):
        """The PyMISP and restSearch fallbacks both use ``int(since.timestamp())``
        — same convention here. A float timestamp would silently change
        MISP server behavior on some versions."""
        from run_misp_to_neo4j import _fetch_edgeguard_events_via_requests_index

        session = MagicMock()
        session.get.return_value = _make_response(200, json_payload=[])

        # Use a since with sub-second precision to force the int() coerce
        # path to be exercised.
        since = datetime(2026, 4, 20, 12, 34, 56, 789000, tzinfo=timezone.utc)
        _fetch_edgeguard_events_via_requests_index(session, "https://misp.example.com", since=since)

        timestamp_value = session.get.call_args_list[0].kwargs["params"]["timestamp"]
        assert isinstance(timestamp_value, int), (
            f"timestamp param MUST be an integer (int(since.timestamp())); got {type(timestamp_value).__name__}"
        )

    def test_limit_and_page_params_still_present(self):
        """Defensive: the original ``limit`` + ``page`` params MUST stay
        in place — the new ``timestamp`` is additive."""
        from run_misp_to_neo4j import (
            MISP_EVENTS_INDEX_PAGE_SIZE,
            _fetch_edgeguard_events_via_requests_index,
        )

        session = MagicMock()
        session.get.return_value = _make_response(200, json_payload=[])

        since = datetime(2026, 1, 1, tzinfo=timezone.utc)
        _fetch_edgeguard_events_via_requests_index(session, "https://misp.example.com", since=since)

        params = session.get.call_args_list[0].kwargs["params"]
        assert params.get("limit") == MISP_EVENTS_INDEX_PAGE_SIZE
        assert params.get("page") == 1


# ===========================================================================
# Source-pin (regex) — guards against silent regression
# ===========================================================================


class TestSourcePinTimestampParam:
    """Guard against a future refactor that drops the timestamp
    narrowing. Source-pin so a regression fails CI even before the
    behavioral tests load the module."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "run_misp_to_neo4j.py").read_text()

    def test_function_passes_timestamp_when_since_given(self, source: str) -> None:
        """The fix: ``params["timestamp"] = int(since.timestamp())``
        must appear inside ``_fetch_edgeguard_events_via_requests_index``."""
        # Locate the function block so we don't accidentally match the
        # PyMISP fallback's identical line later in the file.
        start = source.find("def _fetch_edgeguard_events_via_requests_index")
        assert start > 0, "function not found"
        # End at the next top-level def
        end = source.find("\ndef ", start + 1)
        if end < 0:
            end = len(source)
        body = source[start:end]

        assert 'params["timestamp"] = int(since.timestamp())' in body, (
            "PR-K2 §1-2 fix must include "
            "``params['timestamp'] = int(since.timestamp())`` inside "
            "_fetch_edgeguard_events_via_requests_index — server-side "
            "narrowing on the index endpoint."
        )

    def test_function_guards_with_since_not_none(self, source: str) -> None:
        """The ``timestamp`` assignment must be guarded by
        ``if since is not None:`` so fresh-baseline / first-run
        callers (since=None) keep their current fetch-everything
        behavior."""
        start = source.find("def _fetch_edgeguard_events_via_requests_index")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]
        assert "if since is not None:" in body, (
            "the timestamp narrowing must be conditional on `since is not None` so the no-since "
            "(fresh-baseline) path doesn't change behavior"
        )

    def test_old_unfiltered_get_pattern_is_gone(self, source: str) -> None:
        """The old call site passed ``params={"limit": ..., "page": page}``
        as a literal dict, with no timestamp. That exact pattern must
        not return — if a refactor reverts to the literal-dict form,
        we lose the conditional ``timestamp`` injection."""
        start = source.find("def _fetch_edgeguard_events_via_requests_index")
        end = source.find("\ndef ", start + 1)
        body = source[start:end]

        # The literal dict form ``params={"limit": ..., "page": page}``
        # without an adjacent ``params["timestamp"]`` assignment would
        # signal a regression. Check that the literal isn't on the
        # ``session.get`` call line.
        assert 'params={"limit": MISP_EVENTS_INDEX_PAGE_SIZE, "page": page}' not in body, (
            "the old single-line literal-dict params form is gone — PR-K2 §1-2 introduced "
            "a conditional `params` dict with optional timestamp injection"
        )

    def test_fallback_paths_already_used_timestamp(self, source: str) -> None:
        """Sanity: the PyMISP + restSearch fallback paths already
        carried the ``timestamp = int(since.timestamp())`` convention
        BEFORE PR-K2. The audit's fix brings the index path into
        parity. If a future refactor breaks the fallback paths, the
        whole convention is shaky; pin against it."""
        # Both fallback paths set ``timestamp`` from int(since.timestamp())
        assert source.count('"timestamp"] = int(since.timestamp())') >= 1, (
            "fallback paths in the same module must continue using int(since.timestamp()) "
            "for the timestamp param — convention shared with PR-K2's index-path fix"
        )
