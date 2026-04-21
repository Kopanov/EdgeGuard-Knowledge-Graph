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
        """Defaults must match docs/MISP_TUNING.md.

        Round-2 update: env-var parsing now goes through the bounded
        ``_bounded_int_env`` / ``_bounded_float_env`` helper, so the
        default values appear as the second positional arg (an int /
        float, not a string)."""
        src = self._read()
        # Large event = 50K
        assert '"EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD", 50000' in src
        # Huge event = 100K
        assert '"EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD", 100000' in src
        # Backoff after 3 consecutive failures
        assert '"EDGEGUARD_MISP_BACKOFF_THRESHOLD", 3' in src
        # 5-minute cooldown
        assert '"EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC", 300.0' in src

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
        # PR-N4 round 2 (Cross-Checker #2 / Bug Hunter #5): the counter
        # is now an INSTANCE variable (self._misp_push_consecutive_failures)
        # so it persists across push_items calls — see round-2 tests below.
        assert "self._misp_push_consecutive_failures" in src
        assert "self._misp_push_consecutive_failures += 1" in src
        assert "self._misp_push_consecutive_failures = 0" in src

    def test_backoff_cooldown_call_present(self):
        """When threshold hit, must sleep for the cooldown duration.

        PR-N4 round 2 (Logic Tracker #1 / Prod Readiness #3): the
        cooldown is now CHUNKED (30s steps with liveness-callback
        between) rather than a single ``time.sleep(_backoff_cooldown_sec)``
        — see test_cooldown_is_chunked_with_liveness for the round-2
        pin. This test pins the existence of the cooldown logic via
        the cooldown-var reference + chunked-sleep loop."""
        src = self._read()
        # The cooldown variable must still drive a sleep loop
        assert "_backoff_cooldown_sec" in src
        # The chunked-sleep pattern (round 2 replacement for the single sleep)
        assert "while _slept < _backoff_cooldown_sec:" in src

    def test_prometheus_failure_metric_increment(self):
        src = self._read()
        # PR-N4 round 2: permanent-failure metric now ``source``-only
        # (event_id label dropped to keep cardinality bounded — each
        # MISP run creates a date-stamped event id, which would explode
        # the time-series count).
        assert "_MISP_PUSH_PERMANENT_FAILURES.labels(" in src
        assert "_MISP_PUSH_PERMANENT_FAILURES.labels(source=source).inc()" in src
        # event_id label MUST NOT appear in the increment (regression
        # pin: a future maintainer mustn't reintroduce it)
        assert "_MISP_PUSH_PERMANENT_FAILURES.labels(source=source, event_id" not in src

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
        # PR-N4 round 2 (Maintainer Dev #4 / Bug Hunter #4): event_id
        # label dropped — each MISP run creates a date-stamped event,
        # which would explode Prometheus cardinality. Source-only label
        # gives operators the actionable signal without the explosion.
        assert '["source"]' in src
        # Regression pin: event_id MUST NOT come back as a label
        assert '["source", "event_id"]' not in src

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
# Bugbot round 1 regression pins (PR-N4 commit 8ae3f82 → fix)
# ===========================================================================


class TestBugbotRound1Fixes:
    """Pin the four Bugbot findings on PR-N4 commit 8ae3f82 so they
    can't silently regress:

      F1 [HIGH] Prometheus metrics used stale ``source`` from outer loop
      F2 [MED]  Duplicate ``_get_existing_attribute_keys`` call (30-60s
                paginated fetch run twice on the exact large events
                PR-N4 targets)
      F3 [LOW]  ``total_batches`` used wrong batch_size after adaptive
                scaling \u2192 progress log >100% and negative ETAs
      F4 [MED]  ``except Exception: pass`` around metric increments
                silently swallowed errors with no signal
    """

    def _read(self) -> str:
        return (SRC / "collectors" / "misp_writer.py").read_text()

    def test_push_queue_threads_source(self):
        """F1: push_queue tuples must include ``source`` so the second
        loop binds it correctly per-event instead of inheriting the
        last value of the outer loop's ``source`` variable."""
        src = self._read()
        # 4-tuple form (source, event_id, existing_count, attrs)
        assert "push_queue.append((source, event_id, len(per_event_keys), unique_attrs))" in src, (
            "push_queue must thread (source, event_id, existing_count, attrs) "
            "so per-event metric labels are correct in a multi-source push"
        )
        # Inner loop must unpack the 4-tuple
        assert "for source, event_id, existing_attrs_count, unique_attrs in push_queue:" in src

    def test_no_duplicate_existing_attrs_fetch_in_inner_loop(self):
        """F2: the inner loop must NOT re-call
        ``_get_existing_attribute_keys`` for adaptive scaling \u2014 that
        data is now threaded through ``push_queue`` from the dedup
        loop. Pre-fix the call ran a second time per event,
        doubling the prefetch cost on the exact 50K-120K events
        PR-N4 targets.

        Strip Python comment lines first so the historical breadcrumb
        explaining what was removed (which legitimately mentions the
        function name) doesn't false-match."""
        src = self._read()
        loop_idx = src.find("for source, event_id, existing_attrs_count, unique_attrs in push_queue:")
        assert loop_idx != -1, "inner push loop must use the threaded 4-tuple"
        next_def = src.find("\n    def ", loop_idx)
        inner_block = src[loop_idx:next_def] if next_def != -1 else src[loop_idx:]
        # Strip whole-line ``#`` Python comments
        active_inner = "\n".join(line for line in inner_block.splitlines() if not line.lstrip().startswith("#"))
        assert "_get_existing_attribute_keys(event_id)" not in active_inner, (
            "Bugbot F2 regression: inner loop must reuse the existing-count "
            "threaded through push_queue, not re-fetch via "
            "_get_existing_attribute_keys (30-60s paginated REST call)"
        )

    def test_total_batches_uses_adaptive_helper(self):
        """F3: ``total_batches`` must be computed using the same
        ``_adaptive_for`` helper as the inner loop, so progress
        percentages are accurate when scaling kicks in."""
        src = self._read()
        assert "def _adaptive_for(existing_ct: int)" in src, (
            "PR-N4 must define an _adaptive_for helper inside push_items"
        )
        assert "total_batches = sum(" in src
        ts_idx = src.find("total_batches = sum(")
        assert ts_idx != -1
        ts_block = src[ts_idx : ts_idx + 400]
        assert "_adaptive_for(existing_ct)" in ts_block, (
            "Bugbot F3 regression: total_batches must use _adaptive_for "
            "so progress reporting matches the actual batches sent"
        )

    def test_metric_except_blocks_log_with_exc_info(self):
        """F4: the ``except Exception:`` blocks around metric
        increments must log at DEBUG with ``exc_info=True``, not
        silently ``pass``."""
        src = self._read()
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        for needle in ("MISP_BACKOFF_TRIGGERED.labels", "MISP_PUSH_PERMANENT_FAILURES.labels"):
            label_idx = active.find(needle)
            if label_idx == -1:
                continue
            block = active[label_idx : label_idx + 600]
            assert "except Exception as _metric_err:" in block, (
                f"Bugbot F4 regression: except block around {needle} must name the exception as _metric_err for logging"
            )
            assert "logger.debug(" in block and "exc_info=True" in block, (
                f"Bugbot F4 regression: except block around {needle} must "
                "log at DEBUG with exc_info=True (not silently swallow)"
            )


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


# ===========================================================================
# Bugbot round 2 + 7-agent audit regression pins (PR-N4 commit 53c66c1 → fix)
# ===========================================================================


class TestBugbotRound2Fixes:
    """Pin the eight findings from the 7-agent comprehensive audit
    (Red Team / Devil's Advocate / Maintainer Dev / Bug Hunter /
    Cross-Checker / Logic Tracker / Prod Readiness) cross-referenced
    with Bugbot round 2 on commit 53c66c1.

      Fix #1  Validate all 4 env vars on parse (bounds + WARN on bad)
      Fix #2  Drop ``event_id`` label from MISP_PUSH_PERMANENT_FAILURES
              (cardinality explosion: each MISP run mints a new event_id)
      Fix #3  Reset failure counter only after N **consecutive** full
              successes (not on a single success — that masked flapping)
      Fix #4  Promote ``_consecutive_failures`` to instance variable so
              it persists across push_items calls
      Fix #5  Chunked cooldown sleep + liveness check between chunks
              (single ``time.sleep(300)`` blocked DAG-failure detection
              for 5 min)
      Fix #6  Validate ``HUGE > LARGE``; auto-swap + WARN if inverted
      Fix #7  Update push_queue type annotation to 4-tuple
      Fix #8  Sanitize ``event_id`` in log output (strip non-printable
              + cap length 64)
    """

    def _src(self) -> str:
        return (SRC / "collectors" / "misp_writer.py").read_text()

    def _metrics(self) -> str:
        return (SRC / "metrics_server.py").read_text()

    def _docs(self) -> str:
        return (REPO_ROOT / "docs" / "MISP_TUNING.md").read_text()

    # -- Fix #1 ---------------------------------------------------------

    def test_env_vars_use_bounded_helper(self):
        """All 4 PR-N4 env vars must go through ``_bounded_int_env`` /
        ``_bounded_float_env`` so bad operator input is caught + logged
        instead of silently corrupting the adaptive logic."""
        src = self._src()
        assert "def _bounded_int_env(" in src, "round-2 helper missing"
        assert "def _bounded_float_env(" in src, "round-2 helper missing"
        # Each env var must be parsed via the bounded helper
        for env in (
            "EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD",
            "EDGEGUARD_MISP_BACKOFF_THRESHOLD",
        ):
            assert f'_bounded_int_env(\n            "{env}"' in src or f'_bounded_int_env("{env}"' in src, (
                f"{env} must be parsed via _bounded_int_env (round-2 Fix #1)"
            )
        assert "EDGEGUARD_MISP_BACKOFF_COOLDOWN_SEC" in src
        assert "_bounded_float_env(" in src

    def test_bounded_helper_warns_on_bad_input(self):
        """The helper must log a WARNING (not silently default) so an
        operator typo is visible in the logs."""
        src = self._src()
        helper_idx = src.find("def _bounded_int_env(")
        assert helper_idx != -1
        helper_body = src[helper_idx : helper_idx + 800]
        assert "logger.warning" in helper_body, "_bounded_int_env must logger.warning on parse failure / out-of-range"

    # -- Fix #2 ---------------------------------------------------------

    def test_permanent_failure_counter_has_no_event_id_label(self):
        """Cardinality regression pin: ``event_id`` must NOT be a label
        on MISP_PUSH_PERMANENT_FAILURES (date-stamped → unbounded)."""
        m = self._metrics()
        # The Counter declaration block
        idx = m.find("MISP_PUSH_PERMANENT_FAILURES = Counter(")
        assert idx != -1
        block = m[idx : idx + 500]
        assert '["source"]' in block
        assert '"event_id"' not in block, (
            "Round-2 Fix #2 regression: event_id label was DROPPED for cardinality reasons; must not be reintroduced"
        )

    # -- Fix #3 ---------------------------------------------------------

    def test_failure_counter_resets_only_after_consecutive_successes(self):
        """The success branch must increment a ``_consecutive_successes``
        counter and only reset failures after it crosses 2 — a single
        success is not enough to declare recovery."""
        src = self._src()
        # Both counters must exist
        assert "self._misp_push_consecutive_successes" in src
        # Reset condition gated on >= 2 consecutive successes
        success_idx = src.find("self._misp_push_consecutive_successes += 1")
        assert success_idx != -1, "success branch must increment _consecutive_successes"
        nearby = src[success_idx : success_idx + 400]
        assert "self._misp_push_consecutive_successes >= 2" in nearby, (
            "Round-2 Fix #3: reset only after >= 2 consecutive full successes"
        )

    # -- Fix #4 ---------------------------------------------------------

    def test_consecutive_failures_is_instance_variable(self):
        """Counter on ``self`` (not a function-local) so it persists
        across push_items calls and a flapping backend eventually
        trips the cooldown."""
        src = self._src()
        # No more bare ``_consecutive_failures = 0`` initialization
        # at function scope (it's now ``self._misp_push_consecutive_failures``)
        # — search for the bare assignment in active (non-comment) lines.
        active = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
        # The bare local ``_consecutive_failures = 0`` initializer
        # must be gone — only ``self._misp_push_consecutive_failures = 0``
        # is allowed.
        assert "        _consecutive_failures = 0" not in active, (
            "Round-2 Fix #4 regression: failure counter must be instance-scoped, "
            "not local — see round-2 rationale (cross-call persistence)"
        )
        # And the defensive hasattr-init pattern must be present
        assert 'hasattr(self, "_misp_push_consecutive_failures")' in src

    # -- Fix #5 ---------------------------------------------------------

    def test_cooldown_is_chunked_with_liveness(self):
        """The cooldown sleep must be chunked (≤30s steps) with the
        liveness callback called between chunks — single 5-min
        ``time.sleep(_backoff_cooldown_sec)`` blocked sibling DAG
        failure detection."""
        src = self._src()
        # The chunked-loop pattern
        assert "while _slept < _backoff_cooldown_sec:" in src
        # Liveness callback called inside the loop
        chunk_idx = src.find("while _slept < _backoff_cooldown_sec:")
        assert chunk_idx != -1
        chunk_body = src[chunk_idx : chunk_idx + 600]
        assert "_liveness_cb_in_cooldown" in chunk_body
        # The single bare time.sleep(_backoff_cooldown_sec) must be gone
        assert "time.sleep(_backoff_cooldown_sec)" not in src, (
            "Round-2 Fix #5 regression: cooldown must be chunked, not "
            "a single time.sleep that blocks for the full duration"
        )

    # -- Fix #6 ---------------------------------------------------------

    def test_threshold_inversion_warned_and_swapped(self):
        """If an operator sets LARGE=100000, HUGE=50000 (inverted),
        the writer must WARN and auto-swap so the tier resolution
        produces semantically correct labels."""
        src = self._src()
        assert "_huge_threshold <= _large_threshold:" in src
        # Warn + swap pattern
        idx = src.find("_huge_threshold <= _large_threshold:")
        block = src[idx : idx + 600]
        assert "logger.warning" in block, "must warn on inversion"
        assert "_large_threshold, _huge_threshold = _huge_threshold, _large_threshold" in block, (
            "Round-2 Fix #6: must auto-swap inverted thresholds"
        )

    # -- Fix #7 ---------------------------------------------------------

    def test_push_queue_type_annotation_is_4tuple(self):
        """``push_queue`` annotation must reflect the 4-tuple shape
        added in round 1 (Bugbot F1 + F2). Pre-fix the annotation said
        2-tuple while the data was 4-tuple, silently misleading mypy."""
        src = self._src()
        assert "push_queue: List[Tuple[str, str, int, List[Dict]]] = []" in src, (
            "Round-2 Fix #7: push_queue type annotation must match the "
            "4-tuple actually used (source, event_id, existing_count, attrs)"
        )

    # -- Fix #8 ---------------------------------------------------------

    def test_event_id_sanitized_in_error_log(self):
        """``event_id`` going into the error log line must be sanitized
        (printable-only, length-capped) — defense against
        log-injection if the upstream MISP API ever returns a tainted
        id."""
        src = self._src()
        # The sanitization pattern (loose match: ruff may inline or
        # split the .join() call across lines depending on width).
        # Required components: c.isprintable, str(event_id), [:64] cap.
        assert "c.isprintable()" in src and "str(event_id)" in src and "[:64]" in src, (
            "Round-2 Fix #8: event_id sanitization missing the isprintable / [:64] / str(event_id) pattern"
        )
        # Must use _safe_event_id in the error log call (not bare event_id)
        log_idx = src.find('"Batch %s for event %s failed after retries')
        assert log_idx != -1
        log_block = src[log_idx : log_idx + 400]
        assert "_safe_event_id" in log_block, (
            "Round-2 Fix #8: error log line must use _safe_event_id, not the raw event_id"
        )

    # -- Doc round-2 additions -----------------------------------------

    def test_runbook_has_prereq_section(self):
        """Round-2 doc fix: a ``Prerequisites`` section telling
        operators not to apply the TL;DR settings on a 4GB host."""
        d = self._docs()
        assert "Prerequisites" in d, "round-2 doc fix: prereq section missing"
        assert "8 GB" in d or "8GB" in d, "round-2 doc fix: prereq must call out the 8GB minimum"

    def test_runbook_has_rollback_section(self):
        """Round-2 doc fix: a ``Rollback`` section so operators can
        undo a tuning change cleanly."""
        d = self._docs()
        assert "Rollback" in d, "round-2 doc fix: rollback section missing"
        assert "EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD=10000" in d, (
            "round-2 doc fix: rollback must show conservative env values"
        )

    def test_runbook_covers_both_misp_images(self):
        """Round-2 doc fix (post-commit, addressing colleague note):
        the runbook must call out BOTH ``harvarditsecurity/misp`` (the
        currently-deployed Apache mod_php image) and
        ``coolacid/misp-docker`` (the reference php-fpm image). Pre-fix
        the runbook only mentioned a generic Apache path, leaving
        operators of the harvarditsecurity image unsure where to apply
        settings vs operators of the coolacid image who needed the
        ``conf.d/`` mount."""
        d = self._docs()
        assert "harvarditsecurity" in d, "doc fix: must call out the harvarditsecurity/misp image (currently deployed)"
        assert "coolacid" in d, "doc fix: must call out the coolacid/misp-docker image (reference compose)"
        assert "Apache mod_php" in d or "apache2" in d, "doc fix: must distinguish Apache vs php-fpm config paths"
        assert "php-fpm" in d.lower() or "fpm/conf.d" in d, "doc fix: must distinguish Apache vs php-fpm config paths"

    def test_runbook_documents_prefetch_dependency(self):
        """Round-2 doc fix: the prefetch knob row must explain that
        adaptive scaling DEPENDS on it (turning it off defeats the
        whole point of PR-N4)."""
        d = self._docs()
        idx = d.find("EDGEGUARD_MISP_PREFETCH_EXISTING_ATTRS")
        assert idx != -1
        # Find the row containing the env var
        row = d[idx : idx + 800]
        assert "adaptive scaling" in row.lower() or "existing_attrs_count" in row.lower(), (
            "round-2 doc fix: prefetch row must explain the adaptive-scaling dependency"
        )


# ===========================================================================
# Behavioural — round-2 cross-call persistence + chunked cooldown
# ===========================================================================


class TestBugbotRound2Behavioural:
    """Verify the round-2 invariants ACTUALLY hold at runtime, not just
    in source. These complement the source pins in TestBugbotRound2Fixes
    so a refactor that preserves the source patterns but breaks the
    semantics still fails."""

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

    def test_failure_counter_persists_across_push_items_calls(self, monkeypatch):
        """Fix #4 behaviour: two consecutive ``push_items`` calls each
        producing 2 failures must accumulate to 4 on the writer
        instance — pre-fix the counter reset to 0 every call."""
        from collectors.misp_writer import MispTransientError

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-1")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "create_attribute", lambda item: {"type": "ip-dst", "value": item["value"]})
        # Make every batch fail
        monkeypatch.setattr(w, "_push_batch", MagicMock(side_effect=MispTransientError("simulated 500")))
        # Disable the cooldown so the test doesn't trigger it (we're
        # just measuring the counter, not the cooldown side-effect).
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_THRESHOLD", "100")
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)

        # Call 1: 2 failures
        items1 = [{"indicator_type": "ipv4", "value": f"1.0.0.{i}", "tag": "test"} for i in range(1, 3)]
        w.push_items(items1, batch_size=1)
        after_call_1 = w._misp_push_consecutive_failures
        assert after_call_1 == 2, f"after first call counter should be 2, got {after_call_1}"

        # Call 2: 2 more failures
        items2 = [{"indicator_type": "ipv4", "value": f"2.0.0.{i}", "tag": "test"} for i in range(1, 3)]
        w.push_items(items2, batch_size=1)
        after_call_2 = w._misp_push_consecutive_failures
        # Round-2 Fix #4: counter persists, so it's now 4 (2+2), not 2
        assert after_call_2 == 4, (
            f"Fix #4 regression: counter should accumulate across push_items calls (2+2=4); got {after_call_2}"
        )

    def test_failure_counter_only_resets_after_two_successes(self, monkeypatch):
        """Fix #3 behaviour: a SINGLE successful batch between failure
        clusters must NOT reset the counter (chronic flap masking).
        Only after 2 consecutive successes does the counter reset."""
        from collectors.misp_writer import MispTransientError

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-1")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "create_attribute", lambda item: {"type": "ip-dst", "value": item["value"]})

        # fail, fail, success, fail, fail (the lone success must NOT reset)
        push_results = iter(
            [
                MispTransientError("f1"),
                MispTransientError("f2"),
                (1, 0),  # one success
                MispTransientError("f3"),
                MispTransientError("f4"),
            ]
        )

        def fake_push(event_id, batch):
            r = next(push_results)
            if isinstance(r, Exception):
                raise r
            return r

        monkeypatch.setattr(w, "_push_batch", fake_push)
        # Disable cooldown so we can exclusively measure counter behaviour
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_THRESHOLD", "100")
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)

        items = [{"indicator_type": "ipv4", "value": f"3.0.0.{i}", "tag": "test"} for i in range(1, 6)]
        w.push_items(items, batch_size=1)

        # Sequence is [fail, fail, success, fail, fail]:
        #   Pre-Fix-#3 (BUGGY): counter = 0+1=1, +1=2, RESET=0, +1=1, +1=2
        #     final = 2
        #   Post-Fix-#3 (CORRECT): counter = 0+1=1, +1=2, (single success
        #     does NOT reset; success_ct=1 < 2), +1=3, +1=4
        #     final = 4
        assert w._misp_push_consecutive_failures == 4, (
            f"Fix #3 regression: a single successful batch between failure "
            f"clusters reset the counter. After fail-fail-success-fail-fail "
            f"the counter must be 4, got {w._misp_push_consecutive_failures}"
        )

    def test_two_consecutive_successes_DO_reset_failure_counter(self, monkeypatch):
        """Fix #3 complement: two consecutive successes IS enough to
        signal recovery, so the counter must reset."""
        from collectors.misp_writer import MispTransientError

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-1")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "create_attribute", lambda item: {"type": "ip-dst", "value": item["value"]})

        push_results = iter(
            [
                MispTransientError("f1"),
                MispTransientError("f2"),
                (1, 0),
                (1, 0),  # 2 consecutive — should reset
                MispTransientError("f3"),
            ]
        )

        def fake_push(event_id, batch):
            r = next(push_results)
            if isinstance(r, Exception):
                raise r
            return r

        monkeypatch.setattr(w, "_push_batch", fake_push)
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_THRESHOLD", "100")
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)

        items = [{"indicator_type": "ipv4", "value": f"4.0.0.{i}", "tag": "test"} for i in range(1, 6)]
        w.push_items(items, batch_size=1)

        # Sequence [fail, fail, success, success, fail]:
        #   counter: 0,1,2, (success #1: success_ct=1 < 2, no reset; counter=2)
        #            (success #2: success_ct=2 >= 2, RESET; counter=0)
        #            +1 (final fail) = 1
        assert w._misp_push_consecutive_failures == 1, (
            f"Fix #3: after 2 consecutive successes the counter must reset "
            f"to 0, then the final failure increments to 1; got "
            f"{w._misp_push_consecutive_failures}"
        )

    def test_inverted_thresholds_auto_swap(self, monkeypatch, caplog):
        """Fix #6 behaviour: setting LARGE > HUGE must auto-swap (with
        a warning) so the tier resolution works correctly."""
        import logging

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-1")
        # Tiny event so we don't hit the adaptive tiers anyway
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "create_attribute", lambda item: {"type": "ip-dst", "value": item["value"]})
        monkeypatch.setattr(w, "_push_batch", lambda eid, b: (len(b), 0))
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)
        # INVERTED: LARGE > HUGE
        monkeypatch.setenv("EDGEGUARD_MISP_LARGE_EVENT_THRESHOLD", "100000")
        monkeypatch.setenv("EDGEGUARD_MISP_HUGE_EVENT_THRESHOLD", "50000")

        items = [{"indicator_type": "ipv4", "value": "9.0.0.1", "tag": "test"}]
        with caplog.at_level(logging.WARNING):
            w.push_items(items, batch_size=10)

        # Must have warned about the inversion
        assert any("inverted" in rec.message.lower() or "swap" in rec.message.lower() for rec in caplog.records), (
            f"Fix #6: must warn on inverted thresholds; got log: {[r.message for r in caplog.records]}"
        )

    def test_bad_env_var_warns_and_uses_default(self, monkeypatch, caplog):
        """Fix #1 behaviour: an out-of-bounds env value must trigger a
        WARNING and fall back to the default (not silently use the
        bad value)."""
        import logging

        w = self._make_writer()
        monkeypatch.setattr(w, "_get_or_create_event", lambda *a, **k: "EID-1")
        monkeypatch.setattr(w, "_get_existing_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "_get_existing_source_attribute_keys", lambda *a, **k: set())
        monkeypatch.setattr(w, "create_attribute", lambda item: {"type": "ip-dst", "value": item["value"]})
        monkeypatch.setattr(w, "_push_batch", lambda eid, b: (len(b), 0))
        monkeypatch.setenv("EDGEGUARD_MISP_BATCH_THROTTLE_SEC", "0.0")
        monkeypatch.setattr("time.sleep", lambda s: None)
        # Pre-fix this would silently configure threshold=0 → cooldown
        # fires on the very first batch. Now must warn + use default.
        monkeypatch.setenv("EDGEGUARD_MISP_BACKOFF_THRESHOLD", "0")  # below floor of 1

        items = [{"indicator_type": "ipv4", "value": "5.0.0.1", "tag": "test"}]
        with caplog.at_level(logging.WARNING):
            w.push_items(items, batch_size=10)

        assert any("BACKOFF_THRESHOLD" in rec.message and "valid range" in rec.message for rec in caplog.records), (
            f"Fix #1: bad env value must trigger WARNING via _bounded_int_env; "
            f"got log: {[r.message for r in caplog.records]}"
        )
