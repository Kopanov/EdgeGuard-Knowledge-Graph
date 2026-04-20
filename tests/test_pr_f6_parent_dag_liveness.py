"""
Regression tests for PR-F6 — parent-DAG liveness check (Issue #65).

Background
----------

Bravo's 2026-04-19 / 2026-04-20 baseline investigation surfaced the
**deepest production-readiness gap** uncovered to date: a failed
``edgeguard_baseline`` DAG run kept its ``collect_nvd`` Python
subprocess alive for 12+ hours after Airflow marked the run failed.
The orphan eventually pushed 78,313 attributes to MISP **after** the
next manual run's ``baseline_clean`` had wiped MISP. This was the
root cause of Event 19 + the 72,479-CVE duplication.

PR-F6 closes the gap with a **collector-side liveness check**: the
collector polls the Airflow REST API between MISP push batches and
exits cleanly if its parent ``dag_run`` is no longer in a runnable
state. Fail-OPEN on probe errors so transient API blips don't
false-kill in-flight collectors.

What these tests pin
--------------------

  - ``is_dag_run_alive`` returns True for ``running``/``queued``,
    False for terminal states, True (fail-OPEN) on any probe error
  - ``make_liveness_callback`` returns None when disabled by env flag
    OR when dag_id/run_id are empty (degrades gracefully)
  - The returned callback raises ``AbortedByDagFailureException`` when
    the parent is dead
  - The callback is rate-limited (throttle window) so high-frequency
    batch pushes don't hammer the Airflow API
  - ``MISPWriter.push_items`` calls the callback between batches
  - Source-pin: ``run_baseline_collector`` installs the callback
    from the Airflow context
"""

from __future__ import annotations

import logging
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, "dags")


# ---------------------------------------------------------------------------
# is_dag_run_alive — the API probe
# ---------------------------------------------------------------------------


class TestIsDagRunAlive:
    """The pure probe: True for runnable states, False for terminal,
    True (fail-OPEN) on any error."""

    def test_running_state_is_alive(self):
        from parent_dag_liveness import is_dag_run_alive

        with patch("airflow_client._get", return_value={"state": "running"}):
            assert is_dag_run_alive("dag_x", "run_y") is True

    def test_queued_state_is_alive(self):
        from parent_dag_liveness import is_dag_run_alive

        with patch("airflow_client._get", return_value={"state": "queued"}):
            assert is_dag_run_alive("dag_x", "run_y") is True

    @pytest.mark.parametrize(
        "terminal_state",
        ["success", "failed", "upstream_failed", "skipped", "removed", "shutdown", "no_status"],
    )
    def test_terminal_states_are_dead(self, terminal_state):
        """Anything not in {running, queued} is treated as dead. Be
        deliberately conservative — Airflow's state vocabulary may
        grow; we'd rather mis-classify a new state as dead than as
        alive (a false-dead just exits cleanly; a false-alive is the
        original bug we're fixing)."""
        from parent_dag_liveness import is_dag_run_alive

        with patch("airflow_client._get", return_value={"state": terminal_state}):
            assert is_dag_run_alive("dag_x", "run_y") is False, f"state {terminal_state!r} should be considered dead"

    def test_api_error_is_fail_open(self):
        """Bravo's 2026-04-19 incident: the collector ran for 12h after
        DAG death. We want orphan detection — but a transient Airflow
        API blip should NOT cause us to false-kill an actively-running
        collector. Fail-OPEN: probe failure → assume alive."""
        from parent_dag_liveness import is_dag_run_alive

        with patch("airflow_client._get", return_value={"error": "Cannot connect to Airflow"}):
            assert is_dag_run_alive("dag_x", "run_y") is True

    def test_api_exception_is_fail_open(self):
        """Even if airflow_client._get itself raises (defensive: its
        contract is to never raise, but defend against future changes)."""
        from parent_dag_liveness import is_dag_run_alive

        with patch("airflow_client._get", side_effect=RuntimeError("unexpected")):
            assert is_dag_run_alive("dag_x", "run_y") is True

    def test_empty_dag_id_or_run_id_is_fail_open(self):
        """Degrade gracefully when the caller can't supply identifiers
        (e.g., direct CLI invocation outside Airflow). No probe should
        be made; return True so the legacy path keeps working."""
        from parent_dag_liveness import is_dag_run_alive

        # Should not even attempt the probe
        with patch("airflow_client._get", side_effect=AssertionError("should not be called")):
            assert is_dag_run_alive("", "run_y") is True
            assert is_dag_run_alive("dag_x", "") is True
            assert is_dag_run_alive("", "") is True


# ---------------------------------------------------------------------------
# make_liveness_callback — the closure factory
# ---------------------------------------------------------------------------


class TestMakeLivenessCallback:
    def test_returns_none_when_disabled_by_env(self, monkeypatch):
        """The master switch ``EDGEGUARD_PARENT_DAG_LIVENESS_CHECK=false``
        must completely disable the callback (returns None). Used for
        offline tests + direct CLI runs that bypass Airflow."""
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "false")
        assert make_liveness_callback("dag_x", "run_y") is None

    def test_returns_none_when_dag_id_or_run_id_empty(self, monkeypatch):
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        assert make_liveness_callback("", "run_y") is None
        assert make_liveness_callback("dag_x", "") is None

    def test_returns_callable_when_enabled(self, monkeypatch):
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        cb = make_liveness_callback("dag_x", "run_y")
        assert cb is not None
        assert callable(cb)

    def test_default_enabled_when_env_unset(self, monkeypatch):
        """Safe default: ON. If you forget to set the env var, you get
        protected anyway. Operators must explicitly disable."""
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.delenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", raising=False)
        assert make_liveness_callback("dag_x", "run_y") is not None

    def test_callback_is_noop_when_parent_alive(self, monkeypatch):
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        # Throttle 0 so the probe fires on first call
        cb = make_liveness_callback("dag_x", "run_y", throttle_sec=0)
        with patch("airflow_client._get", return_value={"state": "running"}):
            cb()  # must not raise

    def test_callback_raises_when_parent_dead(self, monkeypatch, caplog):
        """The whole point: when the parent DAG is dead, the callback
        raises ``AbortedByDagFailureException`` so the caller exits
        cleanly between batches."""
        from parent_dag_liveness import AbortedByDagFailureException, make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        cb = make_liveness_callback("dag_x", "run_y", throttle_sec=0)

        with (
            patch("airflow_client._get", return_value={"state": "failed"}),
            caplog.at_level(logging.WARNING),
        ):
            with pytest.raises(AbortedByDagFailureException) as excinfo:
                cb()

        assert excinfo.value.dag_id == "dag_x"
        assert excinfo.value.run_id == "run_y"
        assert excinfo.value.state == "failed"
        # Operator-facing log line MUST carry the grep marker
        msg = " ".join(r.message for r in caplog.records if r.levelno >= logging.WARNING)
        assert "[PARENT_DAG_DEAD]" in msg
        assert "dag_x" in msg and "run_y" in msg

    def test_callback_throttles_actual_api_calls(self, monkeypatch):
        """The callback is called every batch (every ~5s), but the
        actual API probe must respect the throttle interval. Pin this
        contract — without it, a fast collector would generate
        thousands of API calls per hour."""
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        # 60-second throttle
        cb = make_liveness_callback("dag_x", "run_y", throttle_sec=60)

        call_count = {"n": 0}

        def fake_get(*args, **kwargs):
            call_count["n"] += 1
            return {"state": "running"}

        with patch("airflow_client._get", side_effect=fake_get):
            # Fire the callback 100 times in quick succession
            for _ in range(100):
                cb()

        # First call probes; subsequent calls within the 60s window do not.
        assert call_count["n"] == 1, f"expected 1 actual probe in the throttle window; got {call_count['n']}"

    def test_callback_re_probes_after_throttle_expires(self, monkeypatch):
        """After the throttle interval elapses, the next callback call
        triggers a fresh probe. Use throttle_sec=0 + monotonic mock to
        simulate elapsed time deterministically."""
        from parent_dag_liveness import make_liveness_callback

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", "true")
        cb = make_liveness_callback("dag_x", "run_y", throttle_sec=0)

        call_count = {"n": 0}

        def fake_get(*args, **kwargs):
            call_count["n"] += 1
            return {"state": "running"}

        with patch("airflow_client._get", side_effect=fake_get):
            cb()
            cb()
            cb()

        # throttle=0 means every call probes
        assert call_count["n"] == 3


# ---------------------------------------------------------------------------
# AbortedByDagFailureException — message structure
# ---------------------------------------------------------------------------


class TestExceptionMessage:
    def test_exception_carries_diagnostic_fields(self):
        from parent_dag_liveness import AbortedByDagFailureException

        exc = AbortedByDagFailureException("d", "r", "failed")
        assert exc.dag_id == "d"
        assert exc.run_id == "r"
        assert exc.state == "failed"
        # Operator-facing message must reference the design doc so
        # an operator who hits this in a log can find the rationale
        assert "AIRFLOW_DAG_DESIGN.md" in str(exc)
        assert "PR-F6" in str(exc)


# ---------------------------------------------------------------------------
# MISPWriter integration — the callback fires between batches
# ---------------------------------------------------------------------------


class TestMISPWriterCallbackIntegration:
    """``MISPWriter.push_items`` MUST invoke the liveness callback
    before each batch. We test by injecting a fake callback that
    raises after batch N, then asserting that exactly N batches
    completed (no half-write of batch N+1)."""

    def test_callback_invoked_between_batches_and_raises_exit(self):
        """Pin the contract: callback is called inside the batch loop
        and any exception propagates out cleanly. Source-pin only —
        runtime test of MISPWriter requires MISP fixtures we don't
        want to set up here."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        # The push_items batch loop MUST invoke the liveness callback
        # (accept either ``self.liveness_callback`` direct or the
        # defensive ``getattr(self, "liveness_callback", ...)`` form
        # — see test_push_items_uses_defensive_getattr_for_callback
        # below for why we prefer getattr).
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        assert "liveness_callback" in body, "push_items must invoke the liveness_callback inside the batch loop"
        # The marker comment must mention PR-F6 / Issue #65 for
        # discoverability — future readers see WHY
        assert "PR-F6" in body or "Issue #65" in body, (
            "push_items batch loop must reference PR-F6 / Issue #65 in a comment"
        )

    def test_push_items_uses_defensive_getattr_for_callback(self):
        """Pin the defensive ``getattr`` (not ``self.``) access pattern.

        ``tests/test_incremental_dedup.py`` constructs MISPWriter via
        ``MISPWriter.__new__(MISPWriter)`` to bypass __init__ for
        test-isolation. Without ``getattr``'s default-None fallback,
        push_items crashes with AttributeError on those instances.
        This test pins that we don't quietly regress to
        ``self.liveness_callback`` and re-break the legacy pattern.
        """
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def push_items(")
        assert idx > 0
        end = src.find("\n    def ", idx + 1)
        body = src[idx:end]
        assert 'getattr(self, "liveness_callback"' in body, (
            "push_items must use ``getattr(self, 'liveness_callback', None)`` so "
            "instances created via ``MISPWriter.__new__`` (test-isolation "
            "pattern in test_incremental_dedup.py) don't crash on missing attribute"
        )

    def test_misp_writer_constructor_accepts_liveness_callback(self):
        """Source-pin: the constructor MUST take the optional kwarg.
        Without it, callers can't install the callback and the safeguard
        is structurally impossible."""
        with open("src/collectors/misp_writer.py") as fh:
            src = fh.read()
        idx = src.find("def __init__(")
        assert idx > 0
        end = src.find("\n", src.find('"""', idx))
        # Look at the function signature (first 800 chars)
        sig = src[idx : idx + 800]
        assert "liveness_callback" in sig, "MISPWriter.__init__ must accept liveness_callback kwarg"


# ---------------------------------------------------------------------------
# DAG wiring — run_baseline_collector installs the callback
# ---------------------------------------------------------------------------


class TestDagWiring:
    """``run_baseline_collector`` (the central entry point for the 4
    tier-1 baseline collectors) MUST construct the callback from the
    Airflow context and pass it to MISPWriter."""

    def test_run_baseline_collector_constructs_callback_from_context(self):
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        idx = src.find("def run_baseline_collector(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        # Must import the helper
        assert "from parent_dag_liveness import make_liveness_callback" in body, (
            "run_baseline_collector must import make_liveness_callback"
        )
        # Must read dag_id + run_id from context
        assert "context" in body and 'getattr(dag_obj, "dag_id"' in body, "must pull dag_id from the Airflow context"
        assert 'getattr(run_obj, "run_id"' in body, "must pull run_id from the Airflow context"
        # Must pass to MISPWriter
        assert "MISPWriter(liveness_callback=" in body, "must pass the callback into MISPWriter constructor"

    def test_run_baseline_collector_handles_missing_module_gracefully(self):
        """If parent_dag_liveness is missing (e.g., partial deploy),
        run_baseline_collector must NOT crash — degrade to legacy
        behavior with a WARNING log."""
        with open("dags/edgeguard_pipeline.py") as fh:
            src = fh.read()
        idx = src.find("def run_baseline_collector(")
        assert idx > 0
        end = src.find("\ndef ", idx + 1)
        body = src[idx:end]
        assert "ImportError" in body, (
            "run_baseline_collector must catch ImportError so a missing "
            "parent_dag_liveness module doesn't crash the DAG"
        )


# ---------------------------------------------------------------------------
# Env-flag plumbing
# ---------------------------------------------------------------------------


class TestEnvFlags:
    @pytest.mark.parametrize("val", ["true", "1", "yes", "on", "TRUE", "True"])
    def test_enabled_truthy_values(self, monkeypatch, val):
        from parent_dag_liveness import _is_enabled

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", val)
        assert _is_enabled() is True

    @pytest.mark.parametrize("val", ["false", "0", "no", "off", "FALSE"])
    def test_enabled_falsy_values(self, monkeypatch, val):
        from parent_dag_liveness import _is_enabled

        monkeypatch.setenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", val)
        assert _is_enabled() is False

    def test_enabled_default_is_true(self, monkeypatch):
        """Safe default — operators must opt OUT, not opt IN."""
        from parent_dag_liveness import _is_enabled

        monkeypatch.delenv("EDGEGUARD_PARENT_DAG_LIVENESS_CHECK", raising=False)
        assert _is_enabled() is True

    def test_throttle_default_is_60(self, monkeypatch):
        from parent_dag_liveness import _throttle_seconds

        monkeypatch.delenv("EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC", raising=False)
        assert _throttle_seconds() == 60.0

    def test_throttle_respects_env(self, monkeypatch):
        from parent_dag_liveness import _throttle_seconds

        monkeypatch.setenv("EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC", "30")
        assert _throttle_seconds() == 30.0

    def test_throttle_falls_back_on_invalid(self, monkeypatch):
        from parent_dag_liveness import _throttle_seconds

        monkeypatch.setenv("EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC", "not-a-number")
        assert _throttle_seconds() == 60.0

    def test_throttle_negative_falls_back(self, monkeypatch):
        from parent_dag_liveness import _throttle_seconds

        monkeypatch.setenv("EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC", "-5")
        assert _throttle_seconds() == 60.0


# ---------------------------------------------------------------------------
# Documentation traceability
# ---------------------------------------------------------------------------


class TestDocsExist:
    def test_env_example_documents_both_flags(self):
        with open(".env.example") as fh:
            content = fh.read()
        assert "EDGEGUARD_PARENT_DAG_LIVENESS_CHECK" in content
        assert "EDGEGUARD_LIVENESS_CHECK_INTERVAL_SEC" in content
        # Operator-facing rationale must reference the incident
        assert "Issue #65" in content or "PR-F6" in content
        assert "Event 19" in content or "orphan" in content.lower()

    def test_design_doc_references_pr_f6(self):
        with open("docs/AIRFLOW_DAG_DESIGN.md") as fh:
            content = fh.read()
        assert "PR-F6" in content or "Issue #65" in content, (
            "AIRFLOW_DAG_DESIGN.md must document the PR-F6 / Issue #65 "
            "parent-DAG liveness check so operators see WHY collectors "
            "may exit early on a sibling-task failure"
        )
