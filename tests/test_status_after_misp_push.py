"""Tests for collector_utils.status_after_misp_push.

Extended 2026-06 with the Issue-#62 silent-loss gate: a partial MISP push
loss below EDGEGUARD_MISP_MIN_SUCCESS_RATE (default 0.95) now FAILS the
run instead of silently passing (the 2026-04-19 baseline lost 14.7% of NVD
attributes under a green DAG because "1 success out of 92k = success").
"""

import logging

import pytest

from collectors.collector_utils import (
    _DEFAULT_MISP_MIN_SUCCESS_RATE,
    _misp_min_success_rate,
    status_after_misp_push,
)


def test_empty_batch_success():
    st = status_after_misp_push("otx", 0, 0, 0)
    assert st["success"] is True
    assert st["count"] == 0
    assert st["failed"] == 0


def test_all_failed():
    st = status_after_misp_push("otx", 10, 0, 10)
    assert st["success"] is False
    assert st["count"] == 10
    assert st["failed"] == 10
    assert "failures" in st["error"]


def test_all_deduplicated_is_success():
    # 0 pushed, 0 failed = everything already in MISP — zero attempts, no
    # divide-by-zero, and the gate must not fire on a no-op re-run.
    st = status_after_misp_push("otx", 50, 0, 0)
    assert st["success"] is True
    assert st["failed"] == 0


class TestIssue62SuccessRateGate:
    """Partial loss below the threshold fails; at/above passes."""

    def test_partial_loss_below_threshold_now_fails(self):
        # Pre-#62 behavior: 3 pushed / 2 failed (rate 0.6) was a green run —
        # the exact silent-loss class behind the 2026-04-19 incident. The
        # gate (default 0.95) must now mark it failed, loudly.
        st = status_after_misp_push("otx", 10, 3, 2)
        assert st["success"] is False
        assert st["count"] == 10
        assert st["failed"] == 2
        assert "success rate" in st["error"]
        assert "0.600" in st["error"]
        assert "EDGEGUARD_MISP_MIN_SUCCESS_RATE" in st["error"]

    def test_rate_above_threshold_preserves_legacy_success(self):
        # 97 pushed / 3 failed = 0.97 >= 0.95 — small losses still pass.
        st = status_after_misp_push("nvd", 100, 97, 3)
        assert st["success"] is True
        assert st["failed"] == 3
        # make_status only includes "error" when one is provided.
        assert "error" not in st

    def test_rate_exactly_at_threshold_passes(self):
        # Boundary: 95/100 attempted = exactly 0.95 — gate fires only BELOW.
        st = status_after_misp_push("nvd", 100, 95, 5)
        assert st["success"] is True

    def test_rate_just_below_threshold_fails(self):
        # 94/100 = 0.94 < 0.95.
        st = status_after_misp_push("nvd", 100, 94, 6)
        assert st["success"] is False

    def test_rate_computed_over_attempted_not_batch_size(self):
        # Mostly-deduplicated re-run: 1000-item batch, only 20 attempted
        # (19 pushed / 1 failed = 0.95). Rate must use attempted, not
        # num_items — judged on the new items alone.
        st = status_after_misp_push("nvd", 1000, 19, 1)
        assert st["success"] is True

    def test_april_incident_scenario_is_now_red(self):
        # The 2026-04-19 numbers: 78,999 pushed / 13,621 failed = 0.853.
        st = status_after_misp_push("nvd", 92620, 78999, 13621)
        assert st["success"] is False
        assert "0.853" in st["error"]

    def test_zero_disables_gate(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", "0")
        st = status_after_misp_push("otx", 10, 3, 2)
        assert st["success"] is True  # legacy any-success-is-success

    def test_threshold_one_fails_any_loss(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", "1.0")
        st = status_after_misp_push("otx", 100, 99, 1)
        assert st["success"] is False

    def test_all_failed_keeps_legacy_error_not_gate_error(self):
        # The 0-successes path keeps its original, clearer message.
        st = status_after_misp_push("otx", 10, 0, 10)
        assert st["success"] is False
        assert "0 successes" in st["error"]

    def test_collector_summary_line_emitted(self, caplog):
        with caplog.at_level(logging.INFO, logger="collectors.collector_utils"):
            status_after_misp_push("nvd", 100, 97, 3)
        summary = [r.message for r in caplog.records if r.message.startswith("COLLECTOR_SUMMARY")]
        assert len(summary) == 1
        line = summary[0]
        assert "source=nvd" in line
        assert "pushed=97" in line
        assert "failed=3" in line
        assert "success_rate=0.970" in line


class TestMinSuccessRateEnvParsing:
    """Fail-safe parsing: a typo must not silently disable the loss gate."""

    def test_unset_returns_default(self, monkeypatch):
        monkeypatch.delenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", raising=False)
        assert _misp_min_success_rate() == _DEFAULT_MISP_MIN_SUCCESS_RATE

    def test_empty_string_returns_default(self, monkeypatch):
        # docker-compose ${VAR:-} passthrough yields "" when unset in .env.
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", "")
        assert _misp_min_success_rate() == _DEFAULT_MISP_MIN_SUCCESS_RATE

    def test_junk_returns_default_with_warning(self, monkeypatch, caplog):
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", "ninety-five")
        with caplog.at_level(logging.WARNING, logger="collectors.collector_utils"):
            assert _misp_min_success_rate() == _DEFAULT_MISP_MIN_SUCCESS_RATE
        assert any("not a float" in r.message for r in caplog.records)

    @pytest.mark.parametrize("bad", ["-0.1", "1.5", "95"])
    def test_out_of_range_returns_default_with_warning(self, monkeypatch, caplog, bad):
        # "95" guards the percent-vs-fraction typo (95 instead of 0.95).
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", bad)
        with caplog.at_level(logging.WARNING, logger="collectors.collector_utils"):
            assert _misp_min_success_rate() == _DEFAULT_MISP_MIN_SUCCESS_RATE
        assert any("outside [0, 1]" in r.message for r in caplog.records)

    def test_valid_value_parsed(self, monkeypatch):
        monkeypatch.setenv("EDGEGUARD_MISP_MIN_SUCCESS_RATE", "0.8")
        assert _misp_min_success_rate() == 0.8
