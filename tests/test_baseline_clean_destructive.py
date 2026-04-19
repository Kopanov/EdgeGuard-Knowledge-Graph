"""
Behavioural tests for baseline_clean.py — the destructive wipe orchestrator.

These tests address the **Test Coverage authoritative finding** from the
comprehensive 7-agent audit on PR-C: at the time of audit, ``baseline_clean.py``
had **21% line coverage** with **zero behavioural tests** on the wipe + verify
paths. The existing ``tests/test_pr_c_cli_dag_parity.py`` pinned signatures
(``test_reset_baseline_data_signature``) and dataclass shapes but never
invoked the orchestrator. A refactor that silently no-op'd ``_wipe_misp_events``
would pass all 32 prior tests.

This file fills that gap with mock-driven tests that:

  - Exercise the paginated MISP DELETE loop (``_wipe_misp_events``)
  - Cover the 302-on-DELETE actionable error (Bug Hunter B4)
  - Cover the redirect-disable defense (Red Team H1)
  - Drive the orchestrator end-to-end with all wipe helpers mocked
  - Assert mid-wipe exception → ``BaselineCleanError(partial_state=...)``
  - Cover verify-poll timeout
  - Cover the settle interaction

Coverage target: ``baseline_clean.py`` from 21% → 70%+.

Naming convention: this file is named for the FUNCTION it tests, not the
PR it was added in — addressing the Test Coverage recommendation to retire
the ``test_pr_a_*.py`` / ``test_pr_c_*.py`` convention before it accretes
further. The PR-numbered files remain (and pin their PR contracts) but
new behavioural tests should adopt this naming.
"""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(status_code: int, json_body: Any = None) -> MagicMock:
    """Build a fake requests.Response with ``status_code`` and ``json()``."""
    resp = MagicMock()
    resp.status_code = status_code
    if json_body is not None:
        resp.json = MagicMock(return_value=json_body)
    else:
        resp.json = MagicMock(side_effect=ValueError("no body"))
    return resp


def _make_event_payload(event_ids: list[str]) -> list[dict]:
    """Build a fake MISP /events/index response body."""
    return [{"id": eid, "info": "EdgeGuard test event"} for eid in event_ids]


# ---------------------------------------------------------------------------
# _wipe_misp_events — paginated DELETE loop
# ---------------------------------------------------------------------------


class TestWipeMispEventsPagination:
    """The pagination contract — first page comes back, all events
    DELETE 200, next round comes back empty (the wipe shifts everything
    up so re-fetching page 1 sees the next chunk)."""

    def test_single_round_deletes_all_events_then_exits(self):
        """Round 1: GET returns 3 events, all DELETE 200, round 2 GET
        returns []. ``_wipe_misp_events`` should return 3."""
        from baseline_clean import _wipe_misp_events

        # Two GETs (round 1 = 3 events; round 2 = []), three DELETEs all 200
        get_responses = [
            _make_response(200, _make_event_payload(["1", "2", "3"])),
            _make_response(200, []),
        ]
        delete_responses = [
            _make_response(200, {"saved": True}),
            _make_response(200, {"saved": True}),
            _make_response(200, {"saved": True}),
        ]

        with patch("baseline_clean._req.Session" if False else "requests.Session") as session_factory:
            sess = MagicMock()
            sess.get = MagicMock(side_effect=get_responses)
            sess.delete = MagicMock(side_effect=delete_responses)
            session_factory.return_value = sess

            deleted = _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=5,
            )

        assert deleted == 3
        # Two GETs (page 1 round 1, page 1 round 2 — empty)
        assert sess.get.call_count == 2
        assert sess.delete.call_count == 3

    def test_max_pages_caps_the_loop(self):
        """If the GET loop never returns empty (degenerate MISP), the
        ``max_pages`` cap kicks in and the function returns the count
        deleted so far without raising."""
        from baseline_clean import _wipe_misp_events

        # Always return 1 event; always DELETE 200. With max_pages=3 the
        # loop runs 3 times and deletes 3 events.
        sess = MagicMock()
        sess.get = MagicMock(return_value=_make_response(200, _make_event_payload(["x"])))
        sess.delete = MagicMock(return_value=_make_response(200, {"saved": True}))
        with patch("requests.Session", return_value=sess):
            deleted = _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=3,
            )

        assert deleted == 3
        assert sess.get.call_count == 3


# ---------------------------------------------------------------------------
# _wipe_misp_events — Bug Hunter B4: 302-on-DELETE actionable error
# ---------------------------------------------------------------------------


class TestWipeMispEvents302Handling:
    """The 302-on-DELETE pattern is suspicious — most likely an auth-
    redirect (operator missing purge permission) but could also be a
    DNS hijack. The previous code logged a warning and continued, which
    produced a misleading ``deleted=0`` success log. Now: track the count
    and raise if NOTHING got deleted but 302s were seen."""

    def test_all_302_with_zero_deleted_raises_actionable_error(self):
        """Mock a single round returning 2 events, both DELETE 302.
        Must raise RuntimeError with the actionable message including
        ``'purge permission'`` AND the curl debug command."""
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        sess.get = MagicMock(
            side_effect=[
                _make_response(200, _make_event_payload(["a", "b"])),
                _make_response(200, []),
            ]
        )
        sess.delete = MagicMock(
            side_effect=[
                _make_response(302),
                _make_response(302),
            ]
        )

        with patch("requests.Session", return_value=sess):
            with pytest.raises(RuntimeError) as exc_info:
                _wipe_misp_events(
                    misp_url="https://misp.test",
                    misp_api_key="k" * 40,
                    ssl_verify=True,
                    max_pages=5,
                )

        msg = str(exc_info.value)
        assert "302" in msg
        assert "purge permission" in msg, "operator-actionable hint required"
        assert "curl" in msg, "debug command required for the operator"

    def test_partial_302_does_not_raise_when_some_succeed(self):
        """Mixed 200 + 302: as long as SOMETHING got deleted, we don't
        raise (the operator may have partial purge permission and we
        don't want to abort halfway through a successful wipe)."""
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        sess.get = MagicMock(
            side_effect=[
                _make_response(200, _make_event_payload(["a", "b", "c"])),
                _make_response(200, []),
            ]
        )
        sess.delete = MagicMock(
            side_effect=[
                _make_response(200, {"saved": True}),
                _make_response(302),
                _make_response(200, {"saved": True}),
            ]
        )

        with patch("requests.Session", return_value=sess):
            deleted = _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=5,
            )

        assert deleted == 2  # 2 of the 3 succeeded


# ---------------------------------------------------------------------------
# _wipe_misp_events — Bug Hunter / Red Team: 4xx aborts immediately
# ---------------------------------------------------------------------------


class TestWipeMispEvents4xxAborts:
    """Any 4xx/5xx that isn't 302 should raise immediately so the
    verify-poll sees the half-clean state and the helper raises with a
    meaningful message."""

    def test_404_on_delete_aborts(self):
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        sess.get = MagicMock(return_value=_make_response(200, _make_event_payload(["x", "y"])))
        sess.delete = MagicMock(
            side_effect=[
                _make_response(200, {"saved": True}),
                _make_response(404),
            ]
        )

        with patch("requests.Session", return_value=sess):
            with pytest.raises(RuntimeError) as exc_info:
                _wipe_misp_events(
                    misp_url="https://misp.test",
                    misp_api_key="k" * 40,
                    ssl_verify=True,
                    max_pages=5,
                )

        assert "404" in str(exc_info.value)
        assert "aborting" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Red Team H1 — redirect-following must be disabled
# ---------------------------------------------------------------------------


class TestMispSessionRedirectDefense:
    """Red Team H1: ``requests`` follows 3xx by default and PRESERVES
    the Authorization header — a compromised MISP host could steal the
    API key via ``302 → http://attacker``. The wipe + probe sessions
    must set ``max_redirects=0`` AND pass ``allow_redirects=False`` on
    every call."""

    def test_wipe_session_sets_max_redirects_zero(self):
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        # Configure as a real attribute so we can assert on it post-call
        type(sess).max_redirects = 999  # initial sentinel
        sess.get = MagicMock(return_value=_make_response(200, []))
        sess.delete = MagicMock()

        with patch("requests.Session", return_value=sess):
            _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=2,
            )

        # The function must have set max_redirects to 0 on the session
        assert sess.max_redirects == 0

    def test_wipe_session_calls_get_with_allow_redirects_false(self):
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        sess.get = MagicMock(return_value=_make_response(200, []))
        sess.delete = MagicMock()

        with patch("requests.Session", return_value=sess):
            _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=2,
            )

        # Inspect the kwargs of the GET call
        _, get_kwargs = sess.get.call_args
        assert get_kwargs.get("allow_redirects") is False, "GET must disable redirect-follow"

    def test_wipe_session_calls_delete_with_allow_redirects_false(self):
        from baseline_clean import _wipe_misp_events

        sess = MagicMock()
        sess.get = MagicMock(
            side_effect=[
                _make_response(200, _make_event_payload(["a"])),
                _make_response(200, []),
            ]
        )
        sess.delete = MagicMock(return_value=_make_response(200, {"saved": True}))

        with patch("requests.Session", return_value=sess):
            _wipe_misp_events(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
                max_pages=5,
            )

        # All DELETE calls must have allow_redirects=False
        for call in sess.delete.call_args_list:
            _, kw = call
            assert kw.get("allow_redirects") is False, "DELETE must disable redirect-follow"

    def test_probe_session_sets_max_redirects_zero(self):
        from baseline_clean import _probe_misp

        sess = MagicMock()
        type(sess).max_redirects = 999
        sess.get = MagicMock(return_value=_make_response(200, []))

        with patch("requests.Session", return_value=sess):
            count, err = _probe_misp(
                misp_url="https://misp.test",
                misp_api_key="k" * 40,
                ssl_verify=True,
            )

        assert sess.max_redirects == 0
        assert count == 0
        assert err is None


# ---------------------------------------------------------------------------
# reset_baseline_data — orchestrator with mocked wipe helpers
# ---------------------------------------------------------------------------


class TestResetBaselineDataOrchestrator:
    """Drive the full orchestrator with mocks. Asserts:

    - The three wipe helpers are called in order (checkpoints, neo4j, misp)
    - A mid-wipe exception raises ``BaselineCleanError`` with
      ``partial_state == before``
    - Verify-poll timeout raises ``BaselineCleanError`` with the
      post-wipe state attached
    - Settle interval is honored (we mock ``time.sleep`` to make tests fast)
    """

    def _build_zero_state(self):
        from baseline_clean import BaselineState

        return BaselineState(
            neo4j_count=0,
            neo4j_breakdown=(),
            neo4j_ok=True,
            neo4j_error=None,
            misp_count=0,
            misp_ok=True,
            misp_error=None,
            checkpoint_count=0,
            checkpoint_ok=True,
            checkpoint_error=None,
        )

    def _build_loaded_state(self, *, n=350_000, m=1_000, c=11):
        from baseline_clean import BaselineState

        return BaselineState(
            neo4j_count=n,
            neo4j_breakdown=(("Indicator", n - 1000),),
            neo4j_ok=True,
            neo4j_error=None,
            misp_count=m,
            misp_ok=True,
            misp_error=None,
            checkpoint_count=c,
            checkpoint_ok=True,
            checkpoint_error=None,
        )

    def test_happy_path_calls_helpers_in_order(self, monkeypatch):
        """All wipes succeed; verify-poll returns all-zero on first attempt."""
        from baseline_clean import reset_baseline_data

        before = self._build_loaded_state()
        after = self._build_zero_state()

        # Mock the Neo4jClient connect()
        fake_client = MagicMock()
        fake_client.connect.return_value = True
        monkeypatch.setattr("baseline_clean.Neo4jClient", lambda *a, **kw: fake_client, raising=False)
        # Patch via the actual import path used in the function body
        with patch("neo4j_client.Neo4jClient", return_value=fake_client):
            # Track call order across the three wipe helpers
            call_order: list[str] = []

            def _ck():
                call_order.append("checkpoints")

            def _n4(_c):
                call_order.append("neo4j")

            def _ms(*_a, **_kw):
                call_order.append("misp")
                return 1000  # deleted

            with (
                patch("baseline_clean._wipe_checkpoints", side_effect=_ck),
                patch("baseline_clean._wipe_neo4j", side_effect=_n4),
                patch("baseline_clean._wipe_misp_events", side_effect=_ms),
                patch("baseline_clean.probe_baseline_state", side_effect=[before, after]),
                patch("baseline_clean.time.sleep"),
            ):
                result = reset_baseline_data(
                    settle_seconds=0.0,
                    verify_timeout_seconds=10.0,
                    verify_poll_interval_seconds=0.1,
                )

        assert call_order == ["checkpoints", "neo4j", "misp"], "wipe order must be checkpoints → neo4j → misp"
        assert result.before is before
        assert result.after is after
        assert result.verify_attempts == 1

    def test_mid_wipe_exception_raises_with_partial_state(self, monkeypatch):
        """``_wipe_neo4j`` raises mid-orchestration — must surface as
        ``BaselineCleanError(partial_state=before)``."""
        from baseline_clean import BaselineCleanError, reset_baseline_data

        before = self._build_loaded_state()
        fake_client = MagicMock()
        fake_client.connect.return_value = True

        with (
            patch("neo4j_client.Neo4jClient", return_value=fake_client),
            patch("baseline_clean._wipe_checkpoints"),
            patch("baseline_clean._wipe_neo4j", side_effect=RuntimeError("Cypher exploded")),
            patch("baseline_clean._wipe_misp_events") as wipe_misp,
            patch("baseline_clean.probe_baseline_state", return_value=before),
            patch("baseline_clean.time.sleep"),
        ):
            with pytest.raises(BaselineCleanError) as exc_info:
                reset_baseline_data(
                    settle_seconds=0.0,
                    verify_timeout_seconds=1.0,
                    verify_poll_interval_seconds=0.1,
                )

        # The error must carry the pre-wipe state for operator triage
        assert exc_info.value.partial_state is before
        # The MISP wipe must NOT have been invoked (we aborted at Neo4j)
        assert wipe_misp.call_count == 0
        # The error message must include the wrapped exception
        assert "Cypher exploded" in str(exc_info.value)

    def test_verify_poll_timeout_raises_with_post_wipe_state(self, monkeypatch):
        """All wipes succeed but probe keeps returning non-zero past the
        deadline. Must raise ``BaselineCleanError`` with the post-wipe
        state attached."""
        from baseline_clean import BaselineCleanError, reset_baseline_data

        before = self._build_loaded_state()
        # Verify always sees lingering data — never reaches all-zero
        lingering = self._build_loaded_state(n=42, m=0, c=0)

        fake_client = MagicMock()
        fake_client.connect.return_value = True

        # probe_baseline_state called once for pre-wipe + many times for verify
        # Use side_effect with a long list so we don't run out
        probe_results = [before] + [lingering] * 100

        with (
            patch("neo4j_client.Neo4jClient", return_value=fake_client),
            patch("baseline_clean._wipe_checkpoints"),
            patch("baseline_clean._wipe_neo4j"),
            patch("baseline_clean._wipe_misp_events", return_value=42),
            patch("baseline_clean.probe_baseline_state", side_effect=probe_results),
            patch("baseline_clean.time.sleep"),
            patch("baseline_clean.time.monotonic", side_effect=[0.0, 0.0, 0.5, 1.5, 2.5, 3.5, 999.0]),
        ):
            with pytest.raises(BaselineCleanError) as exc_info:
                reset_baseline_data(
                    settle_seconds=0.0,
                    verify_timeout_seconds=2.0,  # short — gets exhausted by monotonic schedule above
                    verify_poll_interval_seconds=0.1,
                )

        msg = str(exc_info.value)
        assert "Verify failed" in msg
        # Post-wipe state attached for triage (not the pre-wipe state)
        assert exc_info.value.partial_state is lingering

    def test_pre_wipe_probe_failure_refuses_to_proceed(self, monkeypatch):
        """If the pre-wipe probe fails (one datastore unreachable), the
        orchestrator must refuse to wipe — operator wouldn't have
        informed-consent counts."""
        from baseline_clean import BaselineCleanError, BaselineState, reset_baseline_data

        unreachable = BaselineState(
            neo4j_count=0,
            neo4j_breakdown=(),
            neo4j_ok=False,  # unreachable!
            neo4j_error="connection refused",
            misp_count=1_000,
            misp_ok=True,
            misp_error=None,
            checkpoint_count=11,
            checkpoint_ok=True,
            checkpoint_error=None,
        )

        fake_client = MagicMock()
        fake_client.connect.return_value = True

        with (
            patch("neo4j_client.Neo4jClient", return_value=fake_client),
            patch("baseline_clean.probe_baseline_state", return_value=unreachable),
            patch("baseline_clean._wipe_checkpoints") as wck,
            patch("baseline_clean._wipe_neo4j") as wn4,
            patch("baseline_clean._wipe_misp_events") as wms,
        ):
            with pytest.raises(BaselineCleanError) as exc_info:
                reset_baseline_data(
                    settle_seconds=0.0,
                    verify_timeout_seconds=1.0,
                )

        # NONE of the wipes should have been invoked
        assert wck.call_count == 0
        assert wn4.call_count == 0
        assert wms.call_count == 0
        # Error references the failed datastore for the operator
        assert "Pre-wipe probe failed" in str(exc_info.value)

    def test_neo4j_connect_failure_raises_before_any_wipe(self, monkeypatch):
        """If ``client.connect()`` returns False, refuse to wipe
        anything — refusing to wipe MISP without Neo4j connectivity is
        a documented invariant."""
        from baseline_clean import BaselineCleanError, reset_baseline_data

        fake_client = MagicMock()
        fake_client.connect.return_value = False  # connection failed

        with (
            patch("neo4j_client.Neo4jClient", return_value=fake_client),
            patch("baseline_clean._wipe_checkpoints") as wck,
            patch("baseline_clean._wipe_neo4j") as wn4,
            patch("baseline_clean._wipe_misp_events") as wms,
        ):
            with pytest.raises(BaselineCleanError) as exc_info:
                reset_baseline_data(settle_seconds=0.0, verify_timeout_seconds=1.0)

        assert "Cannot connect to Neo4j" in str(exc_info.value)
        assert wck.call_count == 0
        assert wn4.call_count == 0
        assert wms.call_count == 0


# ---------------------------------------------------------------------------
# Probe helpers — _probe_neo4j, _probe_checkpoint, _wipe_checkpoints,
# _wipe_neo4j coverage. Bug Hunter B3 / Cross-Checker F3 territory.
# ---------------------------------------------------------------------------


class TestProbeHelpers:
    """The three probe helpers and the two wipe primitives. Not destructive
    on their own — but covering them gets baseline_clean.py into the 70%+
    coverage band the Test Coverage agent flagged as the line for ship-
    quality on a destructive path."""

    def test_probe_neo4j_returns_count_and_breakdown(self):
        from baseline_clean import _probe_neo4j

        fake_client = MagicMock()
        # First call (count query) → [{"cnt": 350000}]
        # Second call (breakdown query) → list of label rows
        fake_client.run.side_effect = [
            [{"cnt": 350000}],
            [{"label": "Indicator", "cnt": 281000}, {"label": "Vulnerability", "cnt": 38000}],
        ]
        count, breakdown, err = _probe_neo4j(fake_client)
        assert count == 350000
        assert err is None
        assert breakdown[0] == ("Indicator", 281000)
        assert breakdown[1] == ("Vulnerability", 38000)

    def test_probe_neo4j_handles_empty_result(self):
        from baseline_clean import _probe_neo4j

        fake_client = MagicMock()
        fake_client.run.side_effect = [[], []]
        count, breakdown, err = _probe_neo4j(fake_client)
        assert count == 0
        assert breakdown == ()
        assert err is None

    def test_probe_neo4j_catches_exception_and_returns_error(self):
        from baseline_clean import _probe_neo4j

        fake_client = MagicMock()
        fake_client.run.side_effect = RuntimeError("connection refused")
        count, breakdown, err = _probe_neo4j(fake_client)
        assert count == 0
        assert breakdown == ()
        assert err is not None
        assert "RuntimeError" in err
        assert "connection refused" in err

    def test_probe_checkpoint_returns_zero_on_missing_file(self, monkeypatch):
        from baseline_clean import _probe_checkpoint

        with patch("baseline_checkpoint.load_checkpoint", return_value={}):
            count, err = _probe_checkpoint()
        assert count == 0
        assert err is None

    def test_probe_checkpoint_returns_count_of_sources(self):
        from baseline_clean import _probe_checkpoint

        fake_data = {"otx": {"cursor": "..."}, "nvd": {"cursor": "..."}, "cisa": {"cursor": "..."}}
        with patch("baseline_checkpoint.load_checkpoint", return_value=fake_data):
            count, err = _probe_checkpoint()
        assert count == 3
        assert err is None

    def test_probe_checkpoint_handles_load_exception(self):
        from baseline_clean import _probe_checkpoint

        with patch("baseline_checkpoint.load_checkpoint", side_effect=OSError("disk full")):
            count, err = _probe_checkpoint()
        assert count == 0
        assert err is not None
        assert "OSError" in err

    def test_probe_checkpoint_rejects_malformed_data(self):
        """The checkpoint file should hold a dict; if it's been corrupted
        to a list or string, surface as error rather than silently
        returning a misleading count."""
        from baseline_clean import _probe_checkpoint

        with patch("baseline_checkpoint.load_checkpoint", return_value=["not", "a", "dict"]):
            count, err = _probe_checkpoint()
        assert count == 0
        assert err is not None
        assert "malformed" in err

    def test_wipe_checkpoints_calls_clear_with_include_incremental_true(self):
        """``_wipe_checkpoints`` must call ``clear_checkpoint(include_incremental=True)``
        — true clean slate semantics promised in docs/AIRFLOW_DAGS.md."""
        from baseline_clean import _wipe_checkpoints

        with patch("baseline_checkpoint.clear_checkpoint") as clear:
            _wipe_checkpoints()
        clear.assert_called_once()
        # The kwargs MUST request include_incremental=True
        _, kwargs = clear.call_args
        assert kwargs.get("include_incremental") is True

    def test_wipe_neo4j_calls_clear_all(self):
        """``_wipe_neo4j(client)`` must call ``client.clear_all()`` and
        raise if it returns False."""
        from baseline_clean import _wipe_neo4j

        fake_client = MagicMock()
        fake_client.driver = MagicMock()  # truthy "connected" sentinel
        fake_client.clear_all.return_value = True
        _wipe_neo4j(fake_client)
        fake_client.clear_all.assert_called_once()

    def test_wipe_neo4j_raises_when_clear_all_returns_false(self):
        from baseline_clean import _wipe_neo4j

        fake_client = MagicMock()
        fake_client.driver = MagicMock()
        fake_client.clear_all.return_value = False
        with pytest.raises(RuntimeError, match="returned False"):
            _wipe_neo4j(fake_client)

    def test_wipe_neo4j_raises_when_client_not_connected(self):
        from baseline_clean import _wipe_neo4j

        fake_client = MagicMock()
        fake_client.driver = None  # not connected
        with pytest.raises(RuntimeError, match="not connected"):
            _wipe_neo4j(fake_client)


# ---------------------------------------------------------------------------
# Bug Hunter B1 — DAG truthy-string conf parse (regression guard)
# ---------------------------------------------------------------------------


class TestDagFreshBaselineTruthyParse:
    """Pin the explicit truthy-parse for the ``fresh_baseline`` conf
    knob in dags/edgeguard_pipeline.py:_baseline_clean. The previous
    ``bool(conf.get("fresh_baseline", False))`` was wrong: operators
    typing ``{"fresh_baseline": "false"}`` triggered a destructive wipe
    (``bool("false") is True``).

    Source-grep style because the inline function is buried under
    PythonOperator and not unit-importable. The behavioural surface
    (the destructive path triggered by the conf) is covered by
    ``TestResetBaselineDataOrchestrator`` above."""

    def _read_dag_source(self) -> str:
        with open("dags/edgeguard_pipeline.py") as fh:
            return fh.read()

    def test_dag_uses_explicit_truthy_parse_not_bool_str(self):
        src = self._read_dag_source()
        # The fix MUST NOT use ``bool(conf.get(`` for fresh_baseline
        # parsing. Find the _baseline_clean function body specifically
        # so we don't false-fail on an unrelated bool() elsewhere.
        idx = src.find("def _baseline_clean(")
        assert idx > 0
        end = src.find("\nbaseline_clean_task =", idx)
        body = src[idx:end]

        # Strip comment lines — the rationale comment intentionally
        # mentions the bad pattern as the thing we're NOT doing.
        code_only_lines = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
        code_only = "\n".join(code_only_lines)

        # Negative assertion — the buggy pattern must be absent from code
        assert 'bool(conf.get("fresh_baseline"' not in code_only, (
            "Bug Hunter B1: bool() on conf.get returns True for any non-empty string — "
            "use explicit truthy parse instead"
        )
        # Positive assertion — the explicit-parse pattern must be present
        assert "raw_fresh" in code_only and "is True" in code_only, (
            "expected explicit truthy parse with `raw_fresh = ...; if raw_fresh is True:`"
        )
        assert "isinstance(raw_fresh, str)" in code_only, 'string parsing branch required to handle "true" / "1" / etc.'

    def test_dag_baseline_clean_task_has_retries_zero(self):
        """Prod Readiness F1: baseline_dag's default_args have retries=1
        which would re-execute the destructive wipe on a verify-poll
        timeout. baseline_clean_task must override to 0."""
        src = self._read_dag_source()
        idx = src.find("baseline_clean_task = PythonOperator(")
        assert idx > 0
        # Find the matching close-paren of PythonOperator(...) — naive
        # ``find(")", idx)`` would match the first ``)`` which is inside
        # ``timedelta(minutes=20)``. Walk paren depth instead.
        depth = 0
        end = idx
        for i in range(idx, len(src)):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = src[idx:end]
        assert "retries=0" in block, "Prod Readiness F1: destructive task must NOT auto-retry"


# ---------------------------------------------------------------------------
# Bug Hunter B2 + F2 + Maintainer M3 — _trigger_baseline_dag helper
# ---------------------------------------------------------------------------


class TestTriggerBaselineDagHelper:
    """The extracted ``_trigger_baseline_dag`` helper centralizes the
    docker-compose-airflow boilerplate that was previously duplicated
    between ``cmd_fresh_baseline`` and ``cmd_baseline``. It also fixes:

      - Bug Hunter B2: ``subprocess.TimeoutExpired`` was uncaught (bare
        traceback to operator's terminal)
      - Bug Hunter F2: brittle ``line.split("run_id", 1)[1].strip().split()[0]``
        parser would return ``"=manual__..."`` if Airflow ever uses
        ``run_id=...`` format
    """

    def test_helper_returns_run_id_on_success(self):
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        fake_completed = MagicMock()
        fake_completed.returncode = 0
        fake_completed.stdout = (
            "Triggered DAG <DAG: edgeguard_baseline> at 2026-04-19T12:34:56+00:00, run_id manual__2026-04-19T12:34:56\n"
        )
        fake_completed.stderr = ""

        with patch.object(sp, "run", return_value=fake_completed):
            exit_code, run_id = _trigger_baseline_dag('{"baseline_days": 730}')

        assert exit_code == 0
        assert run_id == "manual__2026-04-19T12:34:56"

    def test_helper_handles_run_id_with_equals_separator(self):
        """Bug Hunter F2: previous parser would return ``"=manual__..."``
        for ``run_id=manual__...`` output. Regex must tolerate ``=``,
        ``:``, and whitespace separators."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        fake_completed = MagicMock()
        fake_completed.returncode = 0
        fake_completed.stdout = "Triggered DAG <...> run_id=manual__2026-04-19T12:34:56\n"
        fake_completed.stderr = ""

        with patch.object(sp, "run", return_value=fake_completed):
            exit_code, run_id = _trigger_baseline_dag('{"baseline_days": 730}')

        assert exit_code == 0
        assert run_id == "manual__2026-04-19T12:34:56"
        assert not run_id.startswith("="), "regex must strip the leading separator"

    def test_helper_catches_timeout_expired(self):
        """Bug Hunter B2: ``subprocess.TimeoutExpired`` was uncaught.
        Must be returned as exit code 2 with an actionable message."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        with patch.object(
            sp,
            "run",
            side_effect=sp.TimeoutExpired(cmd=["docker", "compose"], timeout=60),
        ):
            exit_code, msg = _trigger_baseline_dag('{"baseline_days": 730}', timeout=60)

        assert exit_code == 2
        assert "did not respond" in msg
        assert "docker compose ps airflow" in msg, "must give operator a triage command"

    def test_helper_catches_filenotfound(self):
        """``docker`` binary missing on PATH — give the operator the
        Airflow UI fallback instead of a bare traceback."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        with patch.object(sp, "run", side_effect=FileNotFoundError("docker not found")):
            exit_code, msg = _trigger_baseline_dag('{"baseline_days": 730}')

        assert exit_code == 2
        assert "Airflow UI" in msg

    def test_helper_returns_unknown_on_unparseable_run_id(self):
        """If Airflow CLI output ever changes shape entirely, return
        ``<unknown>`` (operator can find run_id in the UI) rather than
        crashing on missing ``run_id`` text."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        fake_completed = MagicMock()
        fake_completed.returncode = 0
        # Deliberately contains no "run_id" substring at all
        fake_completed.stdout = "Triggered DAG successfully (output format changed in Airflow 4.x)\n"
        fake_completed.stderr = ""

        with patch.object(sp, "run", return_value=fake_completed):
            exit_code, run_id = _trigger_baseline_dag("{}")

        assert exit_code == 0
        assert run_id == "<unknown>"

    def test_helper_rejects_run_id_false_positives(self):
        """Bug Hunter H1 (post-PR-C-v2 audit): the loose pattern
        ``run_id[=:\\s]+(\\S+)`` matched noise lines like
        ``"warning: run_id is missing"`` and captured ``"is"``. The
        trigger had succeeded (returncode==0), so no data corruption
        — but operators saw ``[is]`` in the success message and copied
        a junk run_id into ``edgeguard dag status --run-id <id>``.

        Anchored regex now requires Airflow's standard run_id prefixes
        (``manual__``, ``scheduled__``, ``backfill__``,
        ``dataset_triggered__``). Noise lines must produce
        ``<unknown>`` instead of false positives."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        false_positive_outputs = [
            "warning: run_id is missing in the response\n",
            "INFO: run_id check: no existing matches found\n",
            "DEBUG: run_id will be auto-generated\n",
            "[2026-04-19] run_id field absent — that's fine for first triggers\n",
        ]
        for stdout in false_positive_outputs:
            fake_completed = MagicMock()
            fake_completed.returncode = 0
            fake_completed.stdout = stdout
            fake_completed.stderr = ""

            with patch.object(sp, "run", return_value=fake_completed):
                exit_code, run_id = _trigger_baseline_dag("{}")

            assert exit_code == 0
            assert run_id == "<unknown>", (
                f"Bug Hunter H1: noise line {stdout!r} must NOT match the run_id regex; got run_id={run_id!r}"
            )

    def test_helper_accepts_all_airflow_run_id_prefixes(self):
        """Defensive: the regex must accept all 4 standard Airflow
        run_id prefixes (manual__, scheduled__, backfill__,
        dataset_triggered__)."""
        import subprocess as sp

        from edgeguard import _trigger_baseline_dag

        prefixes = ["manual", "scheduled", "backfill", "dataset_triggered"]
        for prefix in prefixes:
            fake_completed = MagicMock()
            fake_completed.returncode = 0
            fake_completed.stdout = (
                f"Triggered DAG <DAG: edgeguard_baseline> at "
                f"2026-04-19T12:34:56+00:00, run_id {prefix}__2026-04-19T12:34:56\n"
            )
            fake_completed.stderr = ""

            with patch.object(sp, "run", return_value=fake_completed):
                exit_code, run_id = _trigger_baseline_dag("{}")

            assert exit_code == 0
            assert run_id == f"{prefix}__2026-04-19T12:34:56", (
                f"prefix {prefix!r} should be accepted; got run_id={run_id!r}"
            )


# ---------------------------------------------------------------------------
# Maintainer/Cross-Checker H1/B1 — baseline_config SSoT actually used
# ---------------------------------------------------------------------------


class TestBaselineConfigSsotIsWired:
    """The SSoT was created in PR-C but only the new ``edgeguard.cmd_*``
    callers used it. PR-C v2 wires it into the legacy paths. These tests
    pin the wiring so a refactor that drops ``baseline_config`` import
    from any of the four call sites breaks loud."""

    def test_run_pipeline_argparse_uses_resolve_baseline_days(self):
        """``src/run_pipeline.py:main`` must defer to ``baseline_config``
        instead of hardcoding ``_bd_default = 730``."""
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        # The hardcoded ``_bd_default = 730`` must NOT exist anymore
        # (the comment-block in PR-C v2 explains why).
        code_only = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        assert "_bd_default = 730" not in code_only, "Maintainer H1: hardcoded literal must be replaced by SSoT"
        # The SSoT import must be present
        assert "from baseline_config import" in src
        assert "resolve_baseline_days" in src

    def test_dag_get_baseline_config_uses_resolve_baseline_days(self):
        """``dags/edgeguard_pipeline.py:get_baseline_config`` must defer
        to ``baseline_config.resolve_baseline_days`` instead of
        re-implementing the precedence math inline."""
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        idx = src.find("def get_baseline_config(")
        assert idx > 0
        end = src.find("\ndef ", idx + 10)
        body = src[idx:end]
        assert "resolve_baseline_days(" in body, "Cross-Checker B1: get_baseline_config must call the SSoT"
        assert "resolve_baseline_collection_limit(" in body, (
            "Cross-Checker B1: same SSoT for the collection_limit field"
        )

    def test_run_pipeline_help_text_no_longer_says_default_365(self):
        """Cross-Checker D4: the ``--baseline-days`` help text said
        ``default: 365`` while the actual default was 730. Both PR-C
        v1's hardcoded literal and the help text are gone now."""
        with open("src/run_pipeline.py") as fh:
            src = fh.read()
        # Strip comment lines — the explanatory comment for this fix
        # mentions the bad pattern as the thing we're NOT doing.
        code_only = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
        assert "default: 365" not in code_only, (
            "Cross-Checker D4: stale 365 in --help text — must reference DEFAULT_BASELINE_DAYS"
        )
        assert "DEFAULT_BASELINE_DAYS" in src
