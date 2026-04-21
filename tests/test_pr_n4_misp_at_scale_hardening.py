"""
PR-N4 — MISP-at-scale hardening.

Closes Prod Readiness #1 / #2 / #11 from the comprehensive 7-agent
audit (``docs/flow_audits/09_comprehensive_audit.md``), motivated by
the on-call report from 2026-04-21 where a 730-day baseline lost
~11,500 attributes (7 OTX + 16 NVD batches × 500) silently to MISP
HTTP 500 errors on large events.

## What PR-N4 adds

1. **Adaptive batch size + throttle** based on the existing event size:
   - ``< 50K`` attrs:  configured defaults (typically 500 / 5s)
   - ``50K – 100K``:   ``min(100, configured)`` / ``max(15s, configured)``
   - ``>= 100K``:      ``min(50, configured)`` / ``max(30s, configured)``
   Per-event, not per-collector — small events stay fast.

2. **Adaptive backoff** after N consecutive 5xx batch failures:
   - Default threshold: 3 failures (env ``EDGEGUARD_MISP_BACKOFF_THRESHOLD``)
   - Default cooldown: 5 minutes (env ``EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC``)
   - Reset on any successful batch
   Pre-PR-N4 the ``@retry_with_backoff(max_retries=4, base_delay=10.0)``
   gave only 10s × 2^n ≈ 150s budget per batch — not enough when MISP
   is sustained-degraded.

3. **Prometheus permanent-failure metric** ``edgeguard_misp_push_permanent_failure_total{source, event_id}``
   — pre-PR-N4 the only signal was a log line operators had to
   hand-count.

4. **Backoff-triggered metric** ``edgeguard_misp_push_backoff_triggered_total{source}``
   — distinguishes occasional flap from sustained backend overload.

5. **Operator runbook** ``docs/MISP_TUNING.md`` with the field-tested
   ``php.ini`` + ``my.cnf`` settings.

## Test strategy

Source-pin every behavioural change so a future refactor that
removes the adaptive logic fails loudly. Behavioural sanity for the
adaptive functions is exercised via ``MISPWriter.__new__`` +
monkeypatched dependencies (the full push_items path requires a
live MISP backend; we test the adaptive logic in isolation).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# misp_writer requires NEO4J_PASSWORD via config import
os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n4")


# ===========================================================================
# Source pins — adaptive scaling logic present in misp_writer.push_items
# ===========================================================================


class TestPushItemsHasAdaptiveScalingSourcePins:
    """The adaptive-scaling logic in ``MISPWriter.push_items`` must
    stay in source. A future cleanup that removed the tier branches
    would silently re-introduce the on-call problem."""

    def _read(self) -> str:
        return (SRC / "collectors" / "misp_writer.py").read_text()

    def test_imports_metrics_optionally(self):
        src = self._read()
        # The metrics are imported optionally so MISPWriter still
        # works in CI / dev shells without prometheus_client
        assert "MISP_PUSH_PERMANENT_FAILURES" in src
        assert "MISP_PUSH_BACKOFF_TRIGGERED" in src
        assert "_METRICS_AVAILABLE = True" in src
        assert "_METRICS_AVAILABLE = False" in src

    def test_threshold_envs_present(self):
        src = self._read()
        for env in (
            "EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_BACKOFF_THRESHOLD",
            "EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC",
        ):
            assert env in src, f"{env} env knob must be present + documented"

    def test_default_thresholds_are_sane(self):
        """Defaults must match docs/MISP_TUNING.md."""
        src = self._read()
        # Large event = 50K
        assert '"EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD", "50000"' in src
        # Huge event = 100K
        assert '"EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD", "100000"' in src
        # Backoff after 3 consecutive failures
        assert '"EDGEGUARD_MISP_BACKOFF_THRESHOLD", "3"' in src
        # 5-minute cooldown
        assert '"EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC", "300.0"' in src

    def test_three_tier_adaptive_logic_present(self):
        src = self._read()
        # Tier 1: huge (100K+) → batch_size=50, throttle=30s
        assert "_huge_threshold" in src
        assert "min(50, batch_size)" in src
        assert "max(30.0, batch_throttle)" in src
        # Tier 2: large (50K-100K) → batch_size=100, throttle=15s
        assert "_large_threshold" in src
        assert "min(100, batch_size)" in src
        assert "max(15.0, batch_throttle)" in src

    def test_consecutive_failure_tracking(self):
        src = self._read()
        # Counter must be tracked, incremented on failure, reset on success
        assert "_consecutive_failures" in src
        assert "_consecutive_failures += 1" in src
        assert "_consecutive_failures = 0" in src

    def test_backoff_cooldown_call_present(self):
        """When threshold hit, must sleep for the cooldown duration
        (test that the time.sleep on the cooldown var is in source)."""
        src = self._read()
        assert "time.sleep(_backoff_cooldown_sec)" in src

    def test_prometheus_failure_metric_increment(self):
        src = self._read()
        # Permanent failure increments the counter with source + event_id labels
        assert "_MISP_PUSH_PERMANENT_FAILURES.labels(" in src
        assert "source=source" in src
        assert "event_id=str(event_id)" in src

    def test_prometheus_backoff_metric_increment(self):
        src = self._read()
        assert "_MISP_BACKOFF_TRIGGERED.labels(source=source).inc()" in src


# ===========================================================================
# Source pins — Prometheus metrics declared in metrics_server
# ===========================================================================


class TestPrometheusMetricsDeclared:
    """The two new counters must exist in metrics_server.py with the
    right metric names + label sets."""

    def _read(self) -> str:
        return (SRC / "metrics_server.py").read_text()

    def test_permanent_failure_counter_declared(self):
        src = self._read()
        assert "MISP_PUSH_PERMANENT_FAILURES = Counter(" in src
        assert '"edgeguard_misp_push_permanent_failure_total"' in src
        assert '["source", "event_id"]' in src

    def test_backoff_triggered_counter_declared(self):
        src = self._read()
        assert "MISP_PUSH_BACKOFF_TRIGGERED = Counter(" in src
        assert '"edgeguard_misp_push_backoff_triggered_total"' in src
        assert '["source"]' in src


# ===========================================================================
# Source pin — runbook exists at the documented location
# ===========================================================================


class TestRunbookExistsAndCoversCriticalSettings:
    """``docs/MISP_TUNING.md`` must exist and contain the canonical
    settings the README points to. Regression: a future docs cleanup
    that deleted the runbook would orphan the README pointer."""

    def _read(self) -> str:
        return (REPO_ROOT / "docs" / "MISP_TUNING.md").read_text()

    def test_runbook_exists(self):
        path = REPO_ROOT / "docs" / "MISP_TUNING.md"
        assert path.exists(), "docs/MISP_TUNING.md must exist (PR-N4 deliverable)"

    def test_runbook_has_php_ini_settings(self):
        src = self._read()
        for setting in (
            "memory_limit = 4096M",
            "max_execution_time = 600",
            "post_max_size = 256M",
            "upload_max_filesize = 256M",
            "max_input_vars = 50000",
        ):
            assert setting in src, f"runbook missing PHP setting: {setting}"

    def test_runbook_has_mysql_settings(self):
        src = self._read()
        for setting in (
            "innodb_buffer_pool_size = 4G",
            "innodb_log_file_size = 512M",
            "max_allowed_packet = 256M",
            "wait_timeout = 600",
        ):
            assert setting in src, f"runbook missing MySQL setting: {setting}"

    def test_runbook_documents_all_env_knobs(self):
        """Every PR-N4 env knob in code must appear in the runbook so
        operators can find what they're tuning."""
        src = self._read()
        for env in (
            "EDGEGUARD_MISP_PUSH_BATCH_SIZE",
            "EDGEGUARD_MISP_BATCH_THROTTLE_SEC",
            "EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_BACKOFF_THRESHOLD",
            "EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC",
        ):
            assert env in src, f"runbook missing env knob: {env}"

    def test_readme_points_to_runbook(self):
        readme = (REPO_ROOT / "README.md").read_text()
        assert "docs/MISP_TUNING.md" in readme, (
            "README must reference docs/MISP_TUNING.md so operators can find the playbook"
        )


# ===========================================================================
# Behavioural — adaptive backoff cooldown actually fires when threshold hit
# ===========================================================================


class TestAdaptiveBackoffBehavioural:
    """End-to-end check that the adaptive cooldown actually pauses
    when consecutive failures hit threshold. Uses ``time.sleep``
    monkeypatch to capture call args without actually sleeping."""

    def _make_writer(self):
        """Build a MISPWriter without going through __init__ (which
        requires a live MISP)."""
        from collectors.misp_writer import MISPWriter

        w = MISPWriter.__new__(MISPWriter)
        # Stub out all the things push_items touches
        w.url = "http://test"
        w.api_key = "test"
        w.session = MagicMock()
        w.verify_ssl = False
        w.SOURCE_TAGS = {}
        w.stats = {
            "events_created": 0,
            "events_existing": 0,
            "attributes_added": 0,
            "attrs_skipped_existing": 0,
            "batches_sent": 0,
            "errors": 0,
        }
        w.CONNECT_TIMEOUT = 30
        w.READ_TIMEOUT = 60
        return w

    def test_extended_cooldown_fires_after_threshold(self, monkeypatch):
        """Drive push_items with a mocked ``_push_batch`` that always
        raises ``MispTransientError``. After 3 consecutive failures
        (default threshold), the next iteration must call
        ``time.sleep(_backoff_cooldown_sec)``."""
        from collectors.misp_writer import MispTransientError

        w = self._make_writer()

        # Make _get_or_create_event return a fixed event id, no real MISP.
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-99")
        # Make existing-attrs lookup return 0 so default tier is selected
        # (not what we're testing here; we want consistent throttle).
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        # Make every batch fail with transient
        monkeypatch.setattr(
            w,
            "_push_batch",
            MagicMock(side_effect=MispTransientError("simulated 500")),
        )
        # Speed: env-tune the cooldown to a tiny value so the test
        # finishes fast (we just want to verify it FIRED, not wait 5min).
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC", "0.01")
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        # Capture sleep calls
        sleep_calls = []
        real_sleep = __import__("time").sleep

        def capture_sleep(secs):
            sleep_calls.append(secs)
            # Don't actually sleep — keep tests fast
            real_sleep(0)

        monkeypatch.setattr("time.sleep", capture_sleep)

        # Build 5 items, batch_size=1, so we get 5 batch attempts.
        # First 3 fail → 4th iteration triggers cooldown.
        items = [{"indicator_type": "ipv4", "value": f"10.0.0.{i}", "tag": "test"} for i in range(1, 6)]
        # Stub create_attribute so it doesn't crash on minimal item shape
        monkeypatch.setattr(
            w,
            "create_attribute",
            lambda item: {"type": "ip-dst", "value": item["value"]},
        )

        success, failed = w.push_items(items, batch_size=1)

        # All 5 batches failed
        assert success == 0
        assert failed == 5
        # The cooldown sleep (0.01s, our test override) must have been
        # called at least once. Also the regular throttle sleeps (0.0s)
        # appear, so check for the COOLDOWN value specifically.
        assert 0.01 in sleep_calls, f"adaptive cooldown sleep did not fire; sleep calls: {sleep_calls}"

    def test_no_cooldown_when_failures_below_threshold(self, monkeypatch):
        """Two consecutive failures (below default threshold of 3)
        must NOT trigger the cooldown."""
        from collectors.misp_writer import MispTransientError

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-99")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(
            w,
            "create_attribute",
            lambda item: {"type": "ip-dst", "value": item["value"]},
        )

        # First 2 batches fail, last 3 succeed — counter never reaches threshold
        push_results = iter(
            [
                MispTransientError("fail 1"),
                MispTransientError("fail 2"),
                (1, 0),  # success
                (1, 0),
                (1, 0),
            ]
        )

        def fake_push(event_id, batch):
            r = next(push_results)
            if isinstance(r, Exception):
                raise r
            return r

        monkeypatch.setattr(w, "_push_batch", fake_push)
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC", "999.0")  # would be glaring if it fired
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        sleep_calls = []
        monkeypatch.setattr("time.sleep", lambda s: sleep_calls.append(s))

        items = [{"indicator_type": "ipv4", "value": f"10.0.0.{i}", "tag": "test"} for i in range(1, 6)]
        w.push_items(items, batch_size=1)

        # Must NOT have invoked the 999s cooldown
        assert 999.0 not in sleep_calls, f"cooldown fired below threshold; sleeps: {sleep_calls}"


# ===========================================================================
# Behavioural — adaptive batch sizing kicks in for large events
# ===========================================================================


class TestAdaptiveBatchSizing:
    """When the target event already has >= LARGE_THRESHOLD existing
    attributes, ``push_items`` must downscale ``batch_size`` to 100
    (large) or 50 (huge)."""

    def _make_writer(self):
        from collectors.misp_writer import MISPWriter

        w = MISPWriter.__new__(MISPWriter)
        w.url = "http://test"
        w.api_key = "test"
        w.session = MagicMock()
        w.verify_ssl = False
        w.SOURCE_TAGS = {}
        w.stats = {
            "events_created": 0,
            "events_existing": 0,
            "attributes_added": 0,
            "attrs_skipped_existing": 0,
            "batches_sent": 0,
            "errors": 0,
        }
        w.CONNECT_TIMEOUT = 30
        w.READ_TIMEOUT = 60
        return w

    def test_huge_event_uses_50_batch_size(self, monkeypatch):
        """Existing attrs >= 100K → batch_size=50 (downscaled from
        the default 500)."""

        w = self._make_writer()
        # Simulate a huge event: 120K existing attrs
        huge_keys = {("ip-dst", f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}") for i in range(120_000)}
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-HUGE")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: huge_keys)
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(
            w,
            "create_attribute",
            lambda item: {"type": "ip-dst", "value": item["value"]},
        )
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)

        # Track batch sizes the writer actually sends
        observed_batch_sizes: list = []

        def capture_batch(event_id, batch):
            observed_batch_sizes.append(len(batch))
            return len(batch), 0

        monkeypatch.setattr(w, "_push_batch", capture_batch)

        # 200 NEW items (not in huge_keys); default batch_size=500
        # → without adaptive scaling, would be 1 batch of 200
        # → with HUGE tier scaling, should be 4 batches of 50
        items = [{"indicator_type": "ipv4", "value": f"203.0.113.{i}", "tag": "test"} for i in range(1, 201)]
        w.push_items(items, batch_size=500)

        # All batches must be <= 50 (the huge tier ceiling)
        assert observed_batch_sizes, "no batches sent"
        assert all(sz <= 50 for sz in observed_batch_sizes), (
            f"huge-event tier should cap batch_size at 50; got {observed_batch_sizes}"
        )
        # Specifically: 200 items / 50 = 4 batches
        assert sum(observed_batch_sizes) == 200
        assert len(observed_batch_sizes) == 4

    def test_default_tier_uses_configured_batch_size(self, monkeypatch):
        """Existing attrs < 50K → use the configured batch_size as-is."""
        w = self._make_writer()
        # Tiny event: only 100 existing
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-TINY")
        monkeypatch.setattr(
            w, "_get_existing_attribute_keys", lambda *a, **k: {("ip-dst", f"x{i}") for i in range(100)}
        )
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(
            w,
            "create_attribute",
            lambda item: {"type": "ip-dst", "value": item["value"]},
        )
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)

        observed: list = []

        def capture_batch(event_id, batch):
            observed.append(len(batch))
            return len(batch), 0

        monkeypatch.setattr(w, "_push_batch", capture_batch)

        # 200 new items, batch_size=500 default → 1 batch of 200 (no downscale)
        items = [{"indicator_type": "ipv4", "value": f"198.51.100.{i}", "tag": "test"} for i in range(1, 201)]
        w.push_items(items, batch_size=500)

        # Default tier: configured batch_size honored, so 200 items
        # = 1 batch of 200 (since 200 < 500)
        assert observed == [200], f"default tier should not downscale; got {observed}"
