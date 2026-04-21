"""
PR-N17 — NVD silent-window-drop hardening (BLOCK).

The overnight collection-pipeline audit found a BLOCK-severity
silent-data-loss vector in the NVD baseline loop:

**Pre-PR-N17 flow** (``nvd_collector.py`` ``_fetch_cves_batch``):

```python
try:
    response = request_with_rate_limit_retries(...)
    if response.status_code != 200:
        logger.warning(...)
        return []  # <-- BUG: caller can't tell this from legit empty
    return response.json().get("vulnerabilities", [])
except Exception as e:
    logger.warning(...)
    return []  # <-- SAME BUG: exception indistinguishable from empty
```

**Caller (baseline loop):**

```python
while consecutive_empty < 3:
    cves = self._fetch_cves_batch(...)
    if not cves:
        consecutive_empty += 1
        if consecutive_empty >= 3:
            break  # window done — advance checkpoint past unfetched data!
        continue
    # ... accumulate ...
update_source_checkpoint(nvd_window_idx=wi + 1)  # <-- advances past lost data
```

**Failure mode at 730d scale:** 12 × 120-day windows × ~50 pages =
~600 NVD API calls. Three consecutive transient errors (DNS flap,
NVD 502 cluster, worker CPU starvation) in ONE window look
indistinguishable from "legit end-of-window empty". The checkpoint
advances past the lost CVEs. Operator sees ``completed: true`` but
entire 120-day windows are missing from Neo4j. **No operator signal.**

## Fix

1. Define ``NvdBatchFetchError`` — specific exception class.
2. ``_fetch_cves_batch`` distinguishes the two cases:
   - API returned 200 with ``vulnerabilities: []`` → return ``[]`` (legit)
   - Non-200 after retries / HTTP exception / JSON parse error →
     raise ``NvdBatchFetchError``
3. Caller catches ``NvdBatchFetchError``, logs ``[NVD-WINDOW-ABORT]``,
   preserves checkpoint at current ``(wi, idx)``, skips to next
   window. If ANY windows aborted, the baseline raises
   ``NvdBatchFetchError`` at the end so the Airflow task fails loudly
   (not silently completes).

## Why this is BLOCK

At 730d scale the silent-window-drop is statistically certain. Same
class as PR-N7 ``<> ''`` silent-zero-edge bug — different layer, same
failure mode. The pre-PR-N17 behaviour was: a ~10% data loss on a
30-hour baseline could complete "successfully" with zero alert.

Post-PR-N17: any fetch failure surfaces as task failure with explicit
``[NVD-WINDOW-ABORT]`` log + preserved checkpoint for resume.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-pr-n17")
os.environ.setdefault("MISP_API_KEY", "test-key-pr-n17")


# ===========================================================================
# Fix #1 — _fetch_cves_batch distinguishes empty from error
# ===========================================================================


class TestFix1FetchBatchDistinguishesEmptyFromError:
    def test_exception_class_exists(self):
        from collectors.nvd_collector import NvdBatchFetchError

        assert issubclass(NvdBatchFetchError, Exception)

    def test_fetch_batch_returns_empty_list_on_legit_empty_response(self):
        """200 with ``vulnerabilities: []`` → return [] (legit end-of-window)."""
        from collectors.nvd_collector import NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"vulnerabilities": []}

        with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
            result = collector._fetch_cves_batch(
                pub_start_iso="2024-01-01T00:00:00.000",
                pub_end_iso="2024-04-30T23:59:59.999",
                start_index=0,
                limit=2000,
            )
        assert result == [], "legit empty NVD response must return []"

    def test_fetch_batch_raises_on_non_200(self):
        """Non-200 after retries → raise NvdBatchFetchError (not return [])."""
        from collectors.nvd_collector import NvdBatchFetchError, NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        response = MagicMock()
        response.status_code = 503

        with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
            with pytest.raises(NvdBatchFetchError, match="503"):
                collector._fetch_cves_batch(
                    pub_start_iso="2024-01-01T00:00:00.000",
                    pub_end_iso="2024-04-30T23:59:59.999",
                    start_index=0,
                    limit=2000,
                )

    def test_fetch_batch_raises_on_http_exception(self):
        """Exception in HTTP call → raise NvdBatchFetchError."""
        from collectors.nvd_collector import NvdBatchFetchError, NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        with patch(
            "collectors.nvd_collector.request_with_rate_limit_retries",
            side_effect=ConnectionError("DNS flap"),
        ):
            with pytest.raises(NvdBatchFetchError, match="ConnectionError|DNS flap"):
                collector._fetch_cves_batch(
                    pub_start_iso="2024-01-01T00:00:00.000",
                    pub_end_iso="2024-04-30T23:59:59.999",
                    start_index=0,
                    limit=2000,
                )

    def test_fetch_batch_raises_on_json_parse_error(self):
        """Non-JSON response (e.g. HTML error page) → raise NvdBatchFetchError."""
        from collectors.nvd_collector import NvdBatchFetchError, NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        response = MagicMock()
        response.status_code = 200
        response.json.side_effect = ValueError("Expecting value: line 1 column 1")

        with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
            with pytest.raises(NvdBatchFetchError, match="not JSON|ValueError"):
                collector._fetch_cves_batch(
                    pub_start_iso="2024-01-01T00:00:00.000",
                    pub_end_iso="2024-04-30T23:59:59.999",
                    start_index=0,
                    limit=2000,
                )

    def test_fetch_batch_returns_vulnerabilities_on_success(self):
        from collectors.nvd_collector import NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        fake_cve = {"cve": {"id": "CVE-2024-0001", "descriptions": []}}
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"vulnerabilities": [fake_cve]}

        with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
            result = collector._fetch_cves_batch(
                pub_start_iso="2024-01-01T00:00:00.000",
                pub_end_iso="2024-04-30T23:59:59.999",
                start_index=0,
                limit=2000,
            )
        assert result == [fake_cve]


# ===========================================================================
# Fix #2 — Baseline loop aborts window on NvdBatchFetchError
# ===========================================================================


class TestFix2BaselineLoopAbortsWindowOnError:
    def test_baseline_loop_catches_nvdbatchfetcherror(self):
        """AST pin: the baseline loop must catch NvdBatchFetchError."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        # Find the baseline for loop. The try/except must be structural.
        idx = src.find("while consecutive_empty < 3:")
        assert idx != -1
        # Scan forward for the try/except around _fetch_cves_batch.
        block = src[idx : idx + 4000]
        assert "except NvdBatchFetchError" in block, (
            "baseline loop must catch NvdBatchFetchError to abort window without advancing checkpoint"
        )
        assert "[NVD-WINDOW-ABORT]" in block, (
            "abort path must emit [NVD-WINDOW-ABORT] log marker for on-call visibility"
        )

    def test_aborted_windows_tracked_and_raised(self):
        """Baseline must track aborted windows and raise at end if any."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        idx = src.find("aborted_windows: list = []")
        assert idx != -1, "aborted_windows tracker must be initialized"
        block = src[idx : idx + 6000]
        assert "aborted_windows.append" in block, "must track aborted windows"
        assert "raise NvdBatchFetchError" in block, (
            "baseline must raise at end if any window aborted (fail task loudly)"
        )

    def test_checkpoint_not_advanced_on_aborted_window(self):
        """AST pin: the ``update_source_checkpoint(..., nvd_window_idx=wi+1, ...)``
        call at end of window MUST be conditional on ``not window_aborted``.
        Pre-PR-N17 it was unconditional."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        idx = src.find("if not window_aborted:")
        assert idx != -1, "the end-of-window checkpoint advance must be gated on `not window_aborted`"
        # Confirm the advance is inside the if-block.
        block = src[idx : idx + 600]
        assert 'extra={"nvd_window_idx": wi + 1' in block, (
            "advance to wi+1 must be inside the `not window_aborted` branch"
        )


# ===========================================================================
# Module import sanity
# ===========================================================================


class TestModuleImportsCleanly:
    def test_nvd_collector_imports(self):
        from collectors import nvd_collector  # noqa: F401

    def test_NvdBatchFetchError_is_exported(self):
        from collectors.nvd_collector import NvdBatchFetchError

        # Must be a distinct class (not `Exception` alias).
        assert NvdBatchFetchError is not Exception
