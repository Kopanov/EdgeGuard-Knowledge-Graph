"""
PR-M1 — Collector baseline-limit hardening.

Closes the subset of §7 audit findings that are pure wins (no trade-off
against upstream API quotas):

- §7-H3 (NVD): run-level ``limit`` silently truncates the windowed
  baseline collection by up to 99% when an operator leaks an
  incremental-style ``EDGEGUARD_BASELINE_COLLECTION_LIMIT`` into the
  baseline path. Guard: in baseline the limit is IGNORED with a
  WARNING pointing the operator at the leak.

- §7-H6 (VirusTotal): default substitute raised from 20 to 100. VT
  free tier is 4 req/min × 500 req/day; at ``limit=100`` the
  collector consumes ~100-105 API calls (~26 min wall-clock, well
  under the daily quota). Inner per-batch caps raised from 10 → 50
  so the new default actually flows through to the fetchers.

- §7-H7 (Energy / Healthcare placeholders): return
  ``make_skipped_optional_source(..., skip_reason_class="placeholder")``
  instead of silent ``count=0`` so the sector feeds surface on the
  skip dashboard with a clear reason.

- §7-H8 (ThreatFox): baseline_days was sent verbatim even though the
  abuse.ch ``get_iocs`` ``days`` parameter hard-caps at 7 (per docs,
  "Min: 1, Max: 7"). Baseline now clamps ``days`` to 7 and logs a
  pointer to the documented bulk JSON/CSV export for historical >7d.

OTX H1 is deliberately NOT addressed here — the current ``max_pages
= 200`` produces ~100k graph nodes/relationships in production, is
within the free-tier throttle, and raising it is a planned env-knob
follow-up for paid-tier operators (see docs/COLLECTORS.md).

## Test strategy

Source-pin each behaviour change so a future refactor that
regresses to the pre-fix form fails loudly. Runtime behaviour is
covered at unit level where it can be cheaply mocked (placeholders,
ThreatFox clamp).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ===========================================================================
# §7-H3 — NVD: defensive guard against incremental-limit leak
# ===========================================================================


class TestNvdBaselineIgnoresRunLevelLimit:
    """In baseline mode the NVD collector MUST ignore a non-None
    ``limit`` (it would truncate the full windowed collection) and
    emit a WARNING so the operator can see the leak."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "collectors" / "nvd_collector.py").read_text()

    def test_baseline_path_does_not_truncate_all_cves_by_limit(self, source: str) -> None:
        """The old ``vulnerabilities = all_cves if limit is None else
        all_cves[:limit]`` silently truncated a 730-day windowed
        collection to e.g. 200 CVEs when an operator set
        ``EDGEGUARD_BASELINE_COLLECTION_LIMIT=200`` (copy-pasted from
        their incremental config). The fix unconditionally returns
        the full ``all_cves`` in baseline."""
        # Negative pin: the buggy form with ``[:limit]`` must not
        # reappear on the accumulation boundary.
        assert "vulnerabilities = all_cves if limit is None else all_cves[:limit]" not in source, (
            "Regression: the pre-PR-M1 form silently truncated baseline CVEs to the "
            "run-level limit. Baseline must ignore limit entirely and return all_cves."
        )
        # Positive pin: the new unconditional form is present.
        assert "vulnerabilities = all_cves\n" in source, (
            "Baseline must assign ``vulnerabilities = all_cves`` (no slice) so the "
            "full windowed collection reaches the processing loop."
        )

    def test_baseline_to_process_respects_baseline_branch(self, source: str) -> None:
        """The ``to_process = vulnerabilities if limit is None else
        vulnerabilities[:limit]`` slice on the processing side has the
        same leak surface. In baseline the slice MUST be bypassed."""
        assert "to_process = vulnerabilities if (baseline or limit is None) else vulnerabilities[:limit]" in source, (
            "to_process gate must include the baseline branch so the run-level "
            "limit does not truncate the processing loop either"
        )

    def test_baseline_emits_warning_when_limit_is_set(self, source: str) -> None:
        """Observability: operators must see a WARNING explaining that
        their ``limit`` env has been ignored."""
        assert "NVD baseline: ignoring run-level limit=%d" in source, (
            "WARNING log must name the exact limit value and explain that baseline ignored it"
        )


# ===========================================================================
# §7-H6 — VirusTotal: default bumped from 20 to 100
# ===========================================================================


class TestVirusTotalDefaultLimit:
    """The ``vt_collector`` baseline default when ``limit is None``
    MUST be 100 (raised from 20) and the inner per-batch caps raised
    from 10 to 50 so the new default actually flows through."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "collectors" / "vt_collector.py").read_text()

    def test_default_limit_is_100_not_20(self, source: str) -> None:
        """The ``if limit is None: limit = <N>`` default must be 100."""
        start = source.find("def collect(")
        assert start != -1
        end = source.find("\n    def ", start + 1)
        body = source[start:end]
        # Positive pin: new default
        assert "limit = 100" in body, "VT baseline default must be bumped to 100"
        # Negative pin: old default must be gone from the active substitution
        # (the comment mentioning the old value is allowed).
        for line in body.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if stripped == "limit = 20":
                raise AssertionError(
                    f"Regression: pre-PR-M1 VT default ``limit = 20`` found in "
                    f"active (non-comment) code: {line.strip()!r}"
                )

    def test_inner_file_batch_cap_raised_to_50(self, source: str) -> None:
        """The files-per-run cap of 10 must be raised to 50 so
        ``limit=100`` is not silently bounded by the inner batch cap."""
        assert "files_limit = min(limit // 2, 50)" in source, (
            "VT inner files cap must be 50 so limit=100 flows through (was 10)"
        )

    def test_inner_url_batch_cap_raised_to_50(self, source: str) -> None:
        """Same for URLs."""
        assert "urls_limit = min(limit - len(processed), 50)" in source, (
            "VT inner URLs cap must be 50 so limit=100 flows through (was 10)"
        )


# ===========================================================================
# §7-H7 — Energy / Healthcare placeholders return skipped status
# ===========================================================================


class TestPlaceholderCollectorsReturnSkippedStatus:
    """Placeholder sector feeds (``energy_feed_collector``,
    ``healthcare_feed_collector``) MUST return
    ``make_skipped_optional_source`` with
    ``skip_reason_class="placeholder"`` when ``push_to_misp=True``, so
    they appear on the Airflow/Grafana skip dashboard with a clear
    reason instead of silent ``count=0``."""

    def _mk_collector(self, module_name: str, class_name: str):
        # Lazy import — collectors pull in optional deps (MISP, requests)
        # that may be heavy; we only need the class for a placeholder
        # collect() call.
        import importlib

        mod = importlib.import_module(f"collectors.{module_name}")
        cls = getattr(mod, class_name)
        # Inject a MagicMock MISPWriter so we don't need real MISP
        return cls(misp_writer=MagicMock())

    def test_energy_placeholder_returns_skipped_status(self) -> None:
        collector = self._mk_collector("energy_feed_collector", "EnergyCollector")
        result = collector.collect(push_to_misp=True)
        assert isinstance(result, dict), "placeholder collect() must return a status dict, not a list"
        assert result.get("success") is True, "placeholder is not a failure — success must be True"
        assert result.get("skipped") is True, "placeholder must be marked skipped"
        assert result.get("skip_reason_class") == "placeholder", (
            f"placeholder must use skip_reason_class='placeholder', got {result.get('skip_reason_class')!r}"
        )
        assert result.get("count") == 0
        # The reason text should point operators at the implementation plan
        assert "placeholder" in (result.get("skip_reason") or "").lower()

    def test_healthcare_placeholder_returns_skipped_status(self) -> None:
        collector = self._mk_collector("healthcare_feed_collector", "HealthcareCollector")
        result = collector.collect(push_to_misp=True)
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("skipped") is True
        assert result.get("skip_reason_class") == "placeholder"
        assert result.get("count") == 0
        assert "placeholder" in (result.get("skip_reason") or "").lower()

    def test_placeholders_accept_baseline_kwargs(self) -> None:
        """DAG signature-inspection routes based on kwargs; the
        placeholders MUST accept ``baseline`` and ``baseline_days``
        (previously they raised ``TypeError`` and fell into the else
        branch, silently returning ``count=0``)."""
        energy = self._mk_collector("energy_feed_collector", "EnergyCollector")
        healthcare = self._mk_collector("healthcare_feed_collector", "HealthcareCollector")
        # Should not raise
        energy.collect(push_to_misp=True, baseline=True, baseline_days=730)
        healthcare.collect(push_to_misp=True, baseline=True, baseline_days=730)


# ===========================================================================
# §7-H8 — ThreatFox: clamp days to [1, 7] (abuse.ch API hard cap)
# ===========================================================================


class TestThreatFoxDaysClampedToApiMax:
    """The ThreatFox ``get_iocs`` endpoint hard-caps ``days`` at 7
    (abuse.ch docs: "Min: 1, Max: 7"). Baseline MUST clamp the
    request and log a pointer to the bulk export."""

    @pytest.fixture(scope="class")
    def source(self) -> str:
        return (SRC / "collectors" / "global_feed_collector.py").read_text()

    def test_threatfox_clamp_present(self, source: str) -> None:
        """The fix applies ``days = max(1, min(7, int(days)))`` so
        out-of-range values (730, negative, 0) are all bounded."""
        assert "days = max(1, min(7, int(days)))" in source, (
            "ThreatFox baseline must clamp days to [1, 7] — the API hard cap"
        )

    def test_threatfox_clamp_logs_bulk_export_pointer(self, source: str) -> None:
        """When baseline_days > 7 the collector must log an INFO
        pointing operators at the bulk export as the documented
        alternative."""
        assert "https://threatfox.abuse.ch/export/" in source, "clamp log must point at the documented bulk-export URL"
        assert "clamped to days=" in source, "clamp log must say ``clamped to days=`` so operators see the behaviour"

    def test_threatfox_clamp_actually_runs_in_baseline(self, monkeypatch) -> None:
        """Behavioural check: drive ``collect(baseline=True,
        baseline_days=730)`` with a mocked ``_fetch_iocs`` and assert
        the ``days`` argument observed by the fetcher is 7, not 730."""
        import collectors.global_feed_collector as gfc

        collector = gfc.ThreatFoxCollector.__new__(gfc.ThreatFoxCollector)
        collector.source_name = "threatfox"
        collector.api_key = "fake-but-non-placeholder-key"
        collector.misp_writer = MagicMock()
        collector.misp_writer.push_indicators.return_value = (0, 0)

        # Avoid circuit-breaker / rate-limiter side effects
        monkeypatch.setattr(gfc.THREATFOX_CIRCUIT_BREAKER, "can_execute", lambda: True)
        monkeypatch.setattr(gfc.THREATFOX_CIRCUIT_BREAKER, "record_success", lambda: None)
        monkeypatch.setattr(gfc.THREATFOX_RATE_LIMITER, "wait_if_needed", lambda: None)
        # The optional-key check must pass so we don't short-circuit
        monkeypatch.setattr(gfc, "optional_api_key_effective", lambda *a, **k: True)

        observed_days: list = []

        def fake_fetch(days: int):
            observed_days.append(days)
            # Return an empty but well-formed response so collect() exits cleanly
            return {"query_status": "ok", "data": []}

        collector._fetch_iocs = fake_fetch  # type: ignore[method-assign]

        collector.collect(push_to_misp=True, baseline=True, baseline_days=730)

        assert observed_days, "collect() should have invoked _fetch_iocs at least once"
        assert all(d == 7 for d in observed_days), (
            f"ThreatFox baseline must clamp days to 7 (API cap); got {observed_days}"
        )

    def test_threatfox_clamp_log_fires_when_requested_exceeds_7(
        self, monkeypatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The INFO log with the bulk-export pointer fires ONLY when
        the operator actually requested >7 days — an incremental call
        with ``days=3`` should not log the clamp notice."""
        import collectors.global_feed_collector as gfc

        collector = gfc.ThreatFoxCollector.__new__(gfc.ThreatFoxCollector)
        collector.source_name = "threatfox"
        collector.api_key = "fake"
        collector.misp_writer = MagicMock()
        collector.misp_writer.push_indicators.return_value = (0, 0)
        monkeypatch.setattr(gfc.THREATFOX_CIRCUIT_BREAKER, "can_execute", lambda: True)
        monkeypatch.setattr(gfc.THREATFOX_CIRCUIT_BREAKER, "record_success", lambda: None)
        monkeypatch.setattr(gfc.THREATFOX_RATE_LIMITER, "wait_if_needed", lambda: None)
        monkeypatch.setattr(gfc, "optional_api_key_effective", lambda *a, **k: True)

        def fake_fetch(days: int):
            return {"query_status": "ok", "data": []}

        collector._fetch_iocs = fake_fetch  # type: ignore[method-assign]

        # Case 1: baseline with days > 7 → clamp log fires
        with caplog.at_level(logging.INFO, logger=gfc.logger.name):
            collector.collect(push_to_misp=True, baseline=True, baseline_days=365)
        assert any("clamped to days=7" in rec.message for rec in caplog.records), (
            "baseline_days=365 should emit the clamp log"
        )
        caplog.clear()

        # Case 2: incremental with days=3 → no clamp log
        with caplog.at_level(logging.INFO, logger=gfc.logger.name):
            collector.collect(push_to_misp=True, baseline=False, days=3)
        assert not any("clamped to days=" in rec.message for rec in caplog.records), (
            "incremental days=3 is inside the cap — no clamp log should fire"
        )
