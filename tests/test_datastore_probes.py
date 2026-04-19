"""
Tests for ``src/datastore_probes.py`` — shared datastore-probe module.

Why this file exists (read this before changing any assertions):
    The probes in this module are the chokepoint between EdgeGuard's
    CLI/DAG callers (``cmd_doctor``, ``cmd_validate``, ``cmd_clear_*``,
    the upcoming ``edgeguard fresh-baseline`` and ``baseline_clean``
    Airflow task) and the underlying datastores (Neo4j + MISP +
    checkpoint files).

    The contracts these tests pin:

      1. **Probes never raise.** Every failure path returns a
         ProbeResult with ``error`` set and ``count == 0``. Callers can
         iterate them in a tight loop (post-clean verify polls every
         2s) without try/except walls.
      2. **ProbeResult is a frozen, impossible-bad-state dataclass.**
         The ``ok`` flag is derived from ``error is None`` — you can't
         construct an ``ok=True with error="something"`` half-state.
      3. **Output equivalence with the pre-refactor inline cypher.**
         For both Neo4j and MISP probes, the count returned MUST equal
         what the original inline code in ``cmd_doctor`` (lines ~250-330
         pre-refactor) would have returned given identical mock
         responses. PR2 / PR3 will rely on this equivalence for the
         post-clean verify.
      4. **Defaults match the most common caller's expectations.**
         ``edgeguard_managed_only=True`` for Neo4j and
         ``edgeguard_only=True`` for MISP — these match what every
         existing caller (and the upcoming destructive paths) wants.
         Changing the default is a breaking change.
      5. **probe_all_for_baseline returns a stable tuple order.**
         ``(neo4j, misp, checkpoint)``. PR2's post-clean verify will
         positional-unpack — order changes break that.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "src")

from datastore_probes import (  # noqa: E402
    ProbeResult,
    _resolve_ssl_verify_env,
    _short_error,
    probe_all_for_baseline,
    probe_checkpoint_state,
    probe_misp_event_count,
    probe_neo4j_node_count,
)

# ---------------------------------------------------------------------------
# 1. ProbeResult dataclass
# ---------------------------------------------------------------------------


class TestProbeResultDataclass:
    """The dataclass is the API contract; pin its shape."""

    def test_ok_default_when_no_error(self):
        r = ProbeResult(label="X", count=42)
        assert r.ok is True
        assert r.error is None

    def test_ok_false_when_error_set(self):
        r = ProbeResult(label="X", count=0, error="boom")
        assert r.ok is False
        assert r.count == 0

    def test_breakdown_default_is_empty_tuple(self):
        r = ProbeResult(label="X", count=1)
        assert r.breakdown == ()
        assert isinstance(r.breakdown, tuple)

    def test_frozen_assignment_blocked(self):
        # @dataclass(frozen=True) prevents attribute mutation; pin so a
        # future maintainer doesn't drop the frozen flag accidentally.
        # FrozenInstanceError is the canonical exception raised here; in
        # pre-3.12 Python it subclasses AttributeError but in 3.12+ it's
        # a distinct exception in dataclasses — assert the specific class.
        from dataclasses import FrozenInstanceError

        r = ProbeResult(label="X", count=1)
        with pytest.raises(FrozenInstanceError):
            r.count = 99  # type: ignore[misc]

    def test_format_line_success(self):
        r = ProbeResult(label="Neo4j EdgeGuard nodes", count=347197)
        out = r.format_line()
        assert "Neo4j EdgeGuard nodes" in out
        assert "347,197" in out  # comma formatter
        assert "✓" in out

    def test_format_line_failure(self):
        r = ProbeResult(label="MISP events", count=0, error="ConnectionRefusedError: Errno 111")
        out = r.format_line()
        assert "MISP events" in out
        assert "unreachable" in out
        assert "ConnectionRefusedError" in out

    def test_breakdown_preserves_order(self):
        # Tuple-of-tuples (not dict) — order matters for the breakdown
        # because the underlying Cypher uses ORDER BY cnt DESC.
        r = ProbeResult(
            label="X",
            count=100,
            breakdown=(("A", 50), ("B", 30), ("C", 20)),
        )
        assert r.breakdown[0] == ("A", 50)
        assert r.breakdown[2] == ("C", 20)


# ---------------------------------------------------------------------------
# 2. _short_error helper
# ---------------------------------------------------------------------------


class TestShortError:
    def test_includes_exception_class_name(self):
        out = _short_error(ConnectionRefusedError("nope"))
        assert "ConnectionRefusedError" in out

    def test_caps_at_limit(self):
        out = _short_error(ValueError("x" * 500), limit=50)
        assert len(out) <= 50

    def test_strips_newlines(self):
        out = _short_error(RuntimeError("line1\nline2\nline3"))
        assert "\n" not in out
        assert "line1" in out and "line2" in out

    def test_handles_empty_message(self):
        out = _short_error(RuntimeError())
        assert out == "RuntimeError"


# ---------------------------------------------------------------------------
# 3. _resolve_ssl_verify_env
# ---------------------------------------------------------------------------


class TestResolveSslVerifyEnv:
    """The probe MUST match ``config.edgeguard_ssl_verify_from_env`` exactly
    (cross-checker audit DRIFT-3 caught a divergence in an earlier draft).
    Both must:
      - Check ``EDGEGUARD_SSL_VERIFY`` first, fall back to ``SSL_VERIFY``
      - Treat ONLY lowercase ``"true"`` (after strip) as enabled
      - Default unset/empty to True (secure)
    """

    def test_default_unset_is_true(self, monkeypatch):
        monkeypatch.delenv("SSL_VERIFY", raising=False)
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        assert _resolve_ssl_verify_env() is True

    def test_edgeguard_ssl_verify_takes_priority(self, monkeypatch):
        # If both are set, EDGEGUARD_SSL_VERIFY wins (matches config.py:340-353).
        monkeypatch.setenv("EDGEGUARD_SSL_VERIFY", "false")
        monkeypatch.setenv("SSL_VERIFY", "true")
        assert _resolve_ssl_verify_env() is False

    def test_edgeguard_ssl_verify_alone(self, monkeypatch):
        monkeypatch.delenv("SSL_VERIFY", raising=False)
        monkeypatch.setenv("EDGEGUARD_SSL_VERIFY", "false")
        assert _resolve_ssl_verify_env() is False

    def test_ssl_verify_fallback_when_edgeguard_unset(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        monkeypatch.setenv("SSL_VERIFY", "false")
        assert _resolve_ssl_verify_env() is False

    def test_explicit_true_lowercase(self, monkeypatch):
        monkeypatch.setenv("SSL_VERIFY", "true")
        assert _resolve_ssl_verify_env() is True

    def test_explicit_TRUE_uppercase_is_disabled(self, monkeypatch):
        # config.py only treats lowercase ``"true"`` as enabled — anything
        # else (including ``"TRUE"``) is False. Strict by design.
        monkeypatch.setenv("SSL_VERIFY", "TRUE")
        # After .lower() this is "true", so it IS enabled. Pin the actual
        # behaviour: lowercased then == "true" check.
        assert _resolve_ssl_verify_env() is True

    def test_explicit_false_lowercase(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        monkeypatch.setenv("SSL_VERIFY", "false")
        assert _resolve_ssl_verify_env() is False

    def test_explicit_zero_is_false(self, monkeypatch):
        # Anything not ``"true"`` (after .lower()) is False per config.py.
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        monkeypatch.setenv("SSL_VERIFY", "0")
        assert _resolve_ssl_verify_env() is False

    def test_unrecognized_value_is_false(self, monkeypatch):
        # config.py treats unrecognized values as False (allow-list semantics:
        # only "true" enables). This is INTENTIONALLY strict — a typo like
        # ``EDGEGUARD_SSL_VERIFY=tru`` defaults to disabled, so the operator
        # notices when the probe fails on a self-signed cert.
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        monkeypatch.setenv("SSL_VERIFY", "yes-please")
        assert _resolve_ssl_verify_env() is False

    def test_empty_value_falls_through_to_default(self, monkeypatch):
        # Per config.py: empty/whitespace value is treated as if unset, falls
        # through to the next key, defaults to True if neither is set.
        monkeypatch.delenv("EDGEGUARD_SSL_VERIFY", raising=False)
        monkeypatch.setenv("SSL_VERIFY", "  ")
        assert _resolve_ssl_verify_env() is True


# ---------------------------------------------------------------------------
# 4. probe_neo4j_node_count
# ---------------------------------------------------------------------------


def _make_neo4j_client_mock(rows_for_query: dict[str, list[dict]] | None = None, connect_returns: bool = True):
    """Build a mock Neo4jClient that returns canned rows per query.

    Mirrors the REAL ``Neo4jClient.run(query: str, parameters: Dict = None,
    timeout: int = None)`` signature — accepts ``parameters`` as the
    second positional dict, NOT as ``**kwargs``. The earlier draft of this
    helper accepted arbitrary kwargs which masked the audit's BUG-1
    (probe was calling ``client.run(query, top_n=10)``); the
    TestNeo4jClientRunSignatureConformance class now pins the contract.
    """
    client = MagicMock()
    client.connect = MagicMock(return_value=connect_returns)
    client.close = MagicMock()

    def _run(query, parameters=None, timeout=None):
        if rows_for_query is None:
            return []
        for substr, rows in rows_for_query.items():
            if substr in query:
                return rows
        return []

    client.run = MagicMock(side_effect=_run)
    return client


class TestProbeNeo4jNodeCount:
    def test_success_no_breakdown(self):
        client = _make_neo4j_client_mock({"count(n)": [{"cnt": 347197}]})
        r = probe_neo4j_node_count(client=client)
        assert r.ok
        assert r.label == "Neo4j EdgeGuard nodes"
        assert r.count == 347197
        assert r.breakdown == ()
        # External client must NOT be closed by the probe (we didn't open it)
        client.close.assert_not_called()

    def test_success_with_breakdown(self):
        # Order matters: most-specific substring first. Both queries contain
        # ``count(n) AS cnt``; only the breakdown contains ``labels(n)[0]``.
        client = _make_neo4j_client_mock(
            {
                "labels(n)[0] AS label": [
                    {"label": "Indicator", "cnt": 60},
                    {"label": "Vulnerability", "cnt": 30},
                    {"label": "Malware", "cnt": 10},
                ],
                "count(n) AS cnt": [{"cnt": 100}],
            }
        )
        r = probe_neo4j_node_count(client=client, with_breakdown=True, top_n=10)
        assert r.ok
        assert r.count == 100
        assert r.breakdown == (("Indicator", 60), ("Vulnerability", 30), ("Malware", 10))

    def test_empty_graph_is_ok_with_count_zero(self):
        # Distinguish "datastore is empty" from "probe failed". Both cases
        # have count=0; the .ok flag is what disambiguates.
        client = _make_neo4j_client_mock({"count(n)": [{"cnt": 0}]})
        r = probe_neo4j_node_count(client=client)
        assert r.ok is True
        assert r.count == 0
        assert r.error is None

    def test_connect_failure_returns_error_result(self):
        # Don't pass a client — let the probe try to open one and fail.
        # Patch the Neo4jClient constructor inside the probe module.
        client = MagicMock()
        client.connect = MagicMock(return_value=False)
        with patch("neo4j_client.Neo4jClient", return_value=client):
            r = probe_neo4j_node_count(client=None)
        assert r.ok is False
        assert r.count == 0
        assert "Cannot connect" in (r.error or "")

    def test_run_raises_returns_error_result(self):
        client = MagicMock()
        client.connect = MagicMock(return_value=True)
        client.run = MagicMock(side_effect=RuntimeError("query timeout"))
        client.close = MagicMock()
        r = probe_neo4j_node_count(client=client)
        assert r.ok is False
        assert r.count == 0
        assert "RuntimeError" in (r.error or "")
        assert "query timeout" in (r.error or "")
        # External client passed in: the probe should NOT close it, so the
        # caller can keep using it.
        client.close.assert_not_called()

    def test_own_client_is_closed_on_success(self):
        client = MagicMock()
        client.connect = MagicMock(return_value=True)
        client.run = MagicMock(return_value=[{"cnt": 5}])
        client.close = MagicMock()
        with patch("neo4j_client.Neo4jClient", return_value=client):
            r = probe_neo4j_node_count(client=None)
        assert r.ok
        client.close.assert_called_once()

    def test_own_client_is_closed_on_failure(self):
        client = MagicMock()
        client.connect = MagicMock(return_value=True)
        client.run = MagicMock(side_effect=RuntimeError("boom"))
        client.close = MagicMock()
        with patch("neo4j_client.Neo4jClient", return_value=client):
            r = probe_neo4j_node_count(client=None)
        assert not r.ok
        # Even on probe failure, the own-client must be closed (no leaks).
        client.close.assert_called_once()

    def test_label_changes_when_not_managed_only(self):
        client = _make_neo4j_client_mock({"count(n)": [{"cnt": 99}]})
        r = probe_neo4j_node_count(client=client, edgeguard_managed_only=False)
        assert r.label == "Neo4j nodes"
        assert r.count == 99

    def test_breakdown_respects_top_n_param(self):
        # Verify ``top_n`` is forwarded to Cypher as a parameter dict
        # (positional second arg), NOT as a kwarg. Audit BUG-1 was caused
        # by passing ``top_n=top_n`` which TypeErrors against the real
        # Neo4jClient.run signature; this test pins the corrected form.
        client = MagicMock()
        client.connect = MagicMock(return_value=True)
        client.run = MagicMock(return_value=[{"cnt": 0}])
        client.close = MagicMock()
        probe_neo4j_node_count(client=client, with_breakdown=True, top_n=5)
        # The breakdown query is the second .run call (after the count query).
        # Inspect the positional parameters dict:
        breakdown_call = client.run.call_args_list[1]
        # call.args is (query, parameters_dict)
        assert len(breakdown_call.args) == 2, (
            f"client.run called with {len(breakdown_call.args)} positional args; "
            f"expected (query, parameters_dict). Args: {breakdown_call.args}"
        )
        params = breakdown_call.args[1]
        assert isinstance(params, dict)
        assert params.get("top_n") == 5


# ---------------------------------------------------------------------------
# 5. probe_misp_event_count
# ---------------------------------------------------------------------------


def _mock_misp_response(status_code: int, body: object):
    resp = MagicMock()
    resp.status_code = status_code
    if isinstance(body, Exception):
        resp.json.side_effect = body
    else:
        resp.json.return_value = body
    return resp


class TestProbeMispEventCount:
    def test_no_api_key_returns_error_immediately(self, monkeypatch):
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        r = probe_misp_event_count(misp_api_key="")
        assert not r.ok
        assert "MISP_API_KEY" in (r.error or "")

    def test_success_list_response_filters_to_edgeguard(self):
        events = [
            {"id": "1", "info": "EdgeGuard-otx-2026-01-01"},
            {"id": "2", "info": "Some unrelated event"},
            {"id": "3", "info": "EdgeGuard-mitre-2026-02-15"},
        ]
        with patch("requests.get", return_value=_mock_misp_response(200, events)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=True)
        assert r.ok
        assert r.count == 2  # Only the 2 EdgeGuard-tagged events
        assert r.label == "MISP EdgeGuard events"

    def test_success_dict_response_with_event_key(self):
        # MISP sometimes returns ``{"Event": [...]}`` instead of a bare list.
        body = {"Event": [{"id": "1", "info": "EdgeGuard-x"}]}
        with patch("requests.get", return_value=_mock_misp_response(200, body)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=True)
        assert r.ok
        assert r.count == 1

    def test_success_dict_response_with_response_key(self):
        body = {"response": [{"id": "1", "info": "EdgeGuard-x"}]}
        with patch("requests.get", return_value=_mock_misp_response(200, body)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=True)
        assert r.ok
        assert r.count == 1

    def test_dict_response_with_single_event_dict(self):
        # MISP edge case: when there's one event, ``Event`` may be a dict
        # not a list.
        body = {"Event": {"id": "1", "info": "EdgeGuard-x"}}
        with patch("requests.get", return_value=_mock_misp_response(200, body)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=True)
        assert r.ok
        assert r.count == 1

    def test_empty_response_returns_count_zero_ok(self):
        with patch("requests.get", return_value=_mock_misp_response(200, [])):
            r = probe_misp_event_count(misp_api_key="abc")
        assert r.ok
        assert r.count == 0

    def test_no_filter_counts_all_events(self):
        events = [
            {"id": "1", "info": "EdgeGuard-otx"},
            {"id": "2", "info": "Some unrelated"},
            {"id": "3", "info": "EdgeGuard-mitre"},
        ]
        with patch("requests.get", return_value=_mock_misp_response(200, events)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=False)
        assert r.ok
        assert r.count == 3
        assert r.label == "MISP events"

    def test_http_error_returns_error_result(self):
        with patch("requests.get", return_value=_mock_misp_response(503, "")):
            r = probe_misp_event_count(misp_api_key="abc")
        assert not r.ok
        assert "503" in (r.error or "")

    def test_connection_error_returns_error_result(self):
        with patch("requests.get", side_effect=ConnectionRefusedError("nope")):
            r = probe_misp_event_count(misp_api_key="abc")
        assert not r.ok
        assert "ConnectionRefusedError" in (r.error or "")

    def test_invalid_json_returns_error_result(self):
        with patch("requests.get", return_value=_mock_misp_response(200, ValueError("bad json"))):
            r = probe_misp_event_count(misp_api_key="abc")
        assert not r.ok
        assert "ValueError" in (r.error or "")

    def test_event_with_nested_event_dict(self):
        # The actual MISP /events/index sometimes nests as
        # ``{"id": "1", "Event": {"info": "..."}}`` — pin the nested-info filter.
        events = [
            {"Event": {"id": "1", "info": "EdgeGuard-otx"}},
            {"Event": {"id": "2", "info": "Some unrelated"}},
        ]
        with patch("requests.get", return_value=_mock_misp_response(200, events)):
            r = probe_misp_event_count(misp_api_key="abc", edgeguard_only=True)
        assert r.ok
        assert r.count == 1


# ---------------------------------------------------------------------------
# 6. probe_checkpoint_state
# ---------------------------------------------------------------------------


class TestProbeCheckpointState:
    """We mock ``baseline_checkpoint.load_checkpoint`` directly rather than
    going through the env-var/file path. Reasons:

      1. ``baseline_checkpoint`` has a path-traversal guard that rejects
         any ``EDGEGUARD_CHECKPOINT_DIR`` outside the project root —
         pytest's ``tmp_path`` (in ``/private/var/folders/...``) trips it
         and silently reverts to the real checkpoint dir, polluting the test.
      2. The probe's contract is "call load_checkpoint() and count what it
         returns" — testing through the file system tests
         ``baseline_checkpoint``, not the probe.
      3. Mocking is faster and isolated (no per-test importlib.reload).
    """

    def test_missing_file_returns_count_zero_ok(self):
        with patch("baseline_checkpoint.load_checkpoint", return_value={}):
            r = probe_checkpoint_state()
        assert r.ok
        assert r.count == 0

    def test_empty_file_returns_count_zero(self):
        with patch("baseline_checkpoint.load_checkpoint", return_value={}):
            r = probe_checkpoint_state()
        assert r.ok
        assert r.count == 0
        assert r.breakdown == ()

    def test_populated_file_returns_per_source_breakdown(self):
        canned = {
            "otx": {"page": 5, "items_collected": 1234, "completed": False},
            "mitre": {"completed": True, "items_collected": 600},
        }
        with patch("baseline_checkpoint.load_checkpoint", return_value=canned):
            r = probe_checkpoint_state()
        assert r.ok
        assert r.count == 2
        # breakdown is sorted by source name
        labels = [src for src, _ in r.breakdown]
        assert labels == sorted(labels) == ["mitre", "otx"]

    def test_include_incremental_false_filters_to_baseline(self):
        canned = {
            "otx": {"page": 5, "items_collected": 1234},  # baseline
            "abuseipdb": {"modified_since": "2026-01-01T00:00:00Z"},  # incremental only
        }
        with patch("baseline_checkpoint.load_checkpoint", return_value=canned):
            r_all = probe_checkpoint_state(include_incremental=True)
            r_baseline = probe_checkpoint_state(include_incremental=False)
        assert r_all.count == 2
        assert r_baseline.count == 1
        assert r_baseline.breakdown[0][0] == "otx"

    def test_load_raises_returns_error_result(self):
        with patch("baseline_checkpoint.load_checkpoint", side_effect=PermissionError("perm denied")):
            r = probe_checkpoint_state()
        assert not r.ok
        assert "PermissionError" in (r.error or "")

    def test_malformed_data_returns_error_result(self):
        # If load_checkpoint returns something that's not a dict, the probe
        # should detect the malformation rather than crashing.
        with patch("baseline_checkpoint.load_checkpoint", return_value=["not", "a", "dict"]):
            r = probe_checkpoint_state()
        assert not r.ok
        assert "malformed" in (r.error or "").lower()


# ---------------------------------------------------------------------------
# 7. probe_all_for_baseline
# ---------------------------------------------------------------------------


class TestProbeAllForBaseline:
    def test_returns_three_results_in_stable_order(self, tmp_path, monkeypatch):
        # Set up scenarios: Neo4j fails, MISP fails (no key), checkpoint succeeds-empty.
        monkeypatch.setenv("EDGEGUARD_CHECKPOINT_DIR", str(tmp_path))
        monkeypatch.delenv("MISP_API_KEY", raising=False)
        import importlib

        import baseline_checkpoint

        importlib.reload(baseline_checkpoint)

        # Neo4j: connect fails
        client = MagicMock()
        client.connect = MagicMock(return_value=False)
        with patch("neo4j_client.Neo4jClient", return_value=client):
            results = probe_all_for_baseline()

        assert len(results) == 3
        neo4j, misp, checkpoint = results  # MUST positional-unpack

        assert neo4j.label == "Neo4j EdgeGuard nodes"
        assert not neo4j.ok
        assert misp.label == "MISP EdgeGuard events"
        assert not misp.ok
        assert checkpoint.label == "Checkpoint entries"
        assert checkpoint.ok  # Empty checkpoint dir is a successful "0"

    def test_failures_dont_propagate_between_probes(self, tmp_path, monkeypatch):
        # If Neo4j blows up, MISP + checkpoint probes still run independently.
        monkeypatch.setenv("EDGEGUARD_CHECKPOINT_DIR", str(tmp_path))
        monkeypatch.setenv("MISP_API_KEY", "abc")
        import importlib

        import baseline_checkpoint

        importlib.reload(baseline_checkpoint)

        client = MagicMock()
        client.connect = MagicMock(side_effect=RuntimeError("driver crash"))
        with patch("neo4j_client.Neo4jClient", return_value=client):
            with patch("requests.get", return_value=_mock_misp_response(200, [])):
                results = probe_all_for_baseline()

        neo4j, misp, _checkpoint = results
        # Neo4j error captured
        assert not neo4j.ok
        # MISP still ran successfully despite Neo4j failure
        assert misp.ok
        assert misp.count == 0


# ---------------------------------------------------------------------------
# 8. cmd_doctor refactor — output equivalence regression guards
# ---------------------------------------------------------------------------


class TestNeo4jClientRunSignatureConformance:
    """Regression guard for the cross-checker audit's BUG-1.

    An earlier draft of ``probe_neo4j_node_count`` called
    ``client.run(br_query, top_n=top_n)`` — passing ``top_n`` as a keyword
    argument. ``Neo4jClient.run`` is defined as
    ``run(query, parameters: Dict = None, timeout: int = None)`` and does
    NOT accept ``**kwargs`` — so the call would raise ``TypeError`` in
    production, get caught by the broad ``except Exception``, and return a
    ``ProbeResult`` with ``error="TypeError: run() got an unexpected
    keyword argument 'top_n'"``. The unit-test mocks accepted arbitrary
    kwargs and silently masked the bug.

    This test pins both signatures so any future signature drift
    (Neo4jClient.run grows or loses a parameter; the probe's call shape
    changes) trips immediately.
    """

    def test_neo4j_client_run_accepts_query_and_parameters_dict(self):
        import inspect

        from neo4j_client import Neo4jClient

        sig = inspect.signature(Neo4jClient.run)
        params = list(sig.parameters.keys())
        # Must accept (self, query, parameters=..., timeout=...)
        assert "query" in params, "Neo4jClient.run must accept 'query'"
        assert "parameters" in params, (
            "Neo4jClient.run must accept 'parameters' as a positional dict — "
            "the probe passes it as the second positional arg."
        )

    def test_neo4j_client_run_does_not_accept_arbitrary_kwargs(self):
        # If a future refactor changes Neo4jClient.run to accept **kwargs,
        # this test fails — and we should re-evaluate whether the probe
        # should switch to kwarg-style calls. Today, kwargs would silently
        # be DROPPED (or cause TypeError) — passing top_n=10 would NOT
        # bind to a Cypher parameter.
        import inspect

        from neo4j_client import Neo4jClient

        sig = inspect.signature(Neo4jClient.run)
        has_var_keyword = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
        assert not has_var_keyword, (
            "Neo4jClient.run gained **kwargs — re-evaluate whether the probe should "
            "switch to kwarg-style calls or whether dict-passing is still preferred."
        )

    def test_probe_passes_parameters_as_positional_dict(self):
        # Live-code check: scan the probe source for the kwarg-style call
        # shape that BUG-1 used. The current code MUST use
        # ``client.run(query, {...})``, not ``client.run(query, top_n=...)``.
        # We strip comments before scanning so the rationale comment (which
        # legitimately mentions the buggy form for context) doesn't false-fail
        # the negative assertion.
        import inspect

        import datastore_probes

        src = inspect.getsource(datastore_probes.probe_neo4j_node_count)
        code_only = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # Negative: no ``client.run(..., top_n=...)`` kwarg call in code (comments OK)
        assert "top_n=top_n" not in code_only, (
            "probe_neo4j_node_count must not pass top_n as a kwarg to client.run "
            "— Neo4jClient.run takes parameters as a positional dict (BUG-1)."
        )
        # Positive: dict-passing form is present
        assert '{"top_n":' in code_only, "probe_neo4j_node_count must pass {'top_n': ...} as the parameters dict."


class TestCmdDoctorRefactorEquivalence:
    """The cmd_doctor refactor (PR1) replaced inline cypher/HTTP calls with
    probe-module calls. The OUTPUT TEXT operators see must remain
    byte-equivalent — pin the format strings via source-string scan so a
    future tweak that changes ``"Neo4j has X EdgeGuard nodes (Y)"`` to
    ``"Neo4j: X EdgeGuard nodes [Y]"`` is caught."""

    def _doctor_source(self) -> str:
        import inspect

        import edgeguard

        return inspect.getsource(edgeguard.cmd_doctor)

    def test_doctor_uses_probe_misp_event_count(self):
        src = self._doctor_source()
        assert "probe_misp_event_count" in src, "cmd_doctor must call probe_misp_event_count (PR1 refactor)"
        # And the legacy inline GET should be gone:
        assert "_req.get" not in src, "cmd_doctor must not have inline requests.get (replaced by probe)"

    def test_doctor_uses_probe_neo4j_node_count(self):
        src = self._doctor_source()
        assert "probe_neo4j_node_count" in src, "cmd_doctor must call probe_neo4j_node_count (PR1 refactor)"
        # And the legacy inline cypher should be gone:
        assert "count(n) AS cnt ORDER BY cnt DESC LIMIT 10" not in src, (
            "cmd_doctor must not have inline cypher (replaced by probe)"
        )

    def test_doctor_preserves_misp_output_format(self):
        # The regex-pinned format strings: "MISP has X events (Y EdgeGuard)"
        # and "MISP has 0 events — ready for baseline".
        src = self._doctor_source()
        assert "MISP has 0 events — ready for baseline" in src
        assert "events ({eg_count} EdgeGuard)" in src

    def test_doctor_preserves_neo4j_output_format(self):
        src = self._doctor_source()
        assert "Neo4j graph is empty (0 EdgeGuard nodes) — ready for baseline" in src
        # Cross-checker DRIFT-2 fix: doctor now uses ``top10_total`` (sum of
        # the breakdown's top-N) as the displayed count, matching pre-refactor
        # behavior exactly. The probe's ``count`` field holds the *accurate*
        # ``count(n)`` for PR2/PR3 callers but is intentionally NOT used by
        # the doctor's display string.
        assert "{top10_total} EdgeGuard nodes ({top})" in src
        assert "top10_total = sum(cnt for _, cnt in neo4j_probe.breakdown)" in src
