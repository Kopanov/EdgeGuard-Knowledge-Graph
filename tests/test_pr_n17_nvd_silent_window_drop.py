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

    def test_fetch_batch_raises_on_non_dict_json(self):
        """Cursor-bugbot 2026-04-22 #3: NVD can return valid JSON that
        ISN'T a dict (e.g. a maintenance page returning a JSON array
        or string). Pre-fix, ``data.get("vulnerabilities", [])`` on a
        non-dict raised AttributeError OUTSIDE the JSON-parse try/except,
        bypassing NvdBatchFetchError. Now must raise."""
        from collectors.nvd_collector import NvdBatchFetchError, NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        for bad_json in [["not", "a", "dict"], "string response", None, 42]:
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = bad_json
            with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
                with pytest.raises(NvdBatchFetchError, match="not a dict|expected dict"):
                    collector._fetch_cves_batch(
                        pub_start_iso="2024-01-01T00:00:00.000",
                        pub_end_iso="2024-04-30T23:59:59.999",
                        start_index=0,
                        limit=2000,
                    )

    def test_fetch_batch_raises_on_non_list_vulnerabilities_field(self):
        """Defense-in-depth: ``vulnerabilities`` field must be a list.
        If NVD returns ``{"vulnerabilities": "garbage"}``, raise rather
        than propagate a non-list to downstream iteration."""
        from collectors.nvd_collector import NvdBatchFetchError, NVDCollector

        collector = NVDCollector.__new__(NVDCollector)
        collector.api_key = None
        collector.base_url = "http://fake"
        collector.source_name = "nvd"
        collector.session = MagicMock()

        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"vulnerabilities": "this should be a list"}
        with patch("collectors.nvd_collector.request_with_rate_limit_retries", return_value=response):
            with pytest.raises(NvdBatchFetchError, match="expected list"):
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
        # Widened window for PR-N17 follow-up comments.
        block = src[idx : idx + 10000]
        assert "aborted_windows.append" in block, "must track aborted windows"
        assert "raise NvdBatchFetchError" in block, "baseline must raise if any window aborted (fail task loudly)"

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

    def test_outer_for_loop_breaks_on_first_abort(self):
        """Cursor-bugbot 2026-04-22 #1: the inner ``break`` only exited
        the while loop. The outer for-loop continued with subsequent
        windows whose successful batches called update_source_checkpoint
        with later nvd_window_idx values, OVERWRITING the abort
        checkpoint. Resume then jumped past the aborted window, losing
        its data.

        Fix: ``else: break`` after the ``if not window_aborted: ...``
        block exits the outer for-loop on first abort."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        # Find the gating block + verify the else: break exit.
        idx = src.find("if not window_aborted:")
        assert idx != -1
        # Within ~1500 chars after, must be `else:` + `break  # exit outer for-loop`
        block = src[idx : idx + 1500]
        assert "else:" in block and "exit outer for-loop" in block, (
            "outer for-loop must break on first abort (cursor-bugbot 2026-04-22 #1)"
        )

    def test_outer_except_chain_re_raises_NvdBatchFetchError(self):
        """Cursor-bugbot 2026-04-22 #2: the ``raise NvdBatchFetchError``
        was caught by the outer ``except Exception as e:`` and converted
        to a normal status-dict return. The typed exception was lost.

        Fix: an explicit ``except NvdBatchFetchError: raise`` ahead
        of the broader handlers so the type escapes to Airflow.

        Bugbot 2026-04-22 #4: the prior version of this test walked
        ast.walk (order-dependent) and could match the INNER try/except
        around _fetch_cves_batch — which has ONLY NvdBatchFetchError
        and no Exception handler, so the test returned without
        asserting anything. Rewrote to specifically find the OUTER
        try/except chain (identified by having BOTH the typed handler
        AND an Exception handler), then assert ordering."""
        src = (SRC / "collectors" / "nvd_collector.py").read_text()
        import ast as _ast

        tree = _ast.parse(src)
        matching_outer_trys = []
        for node in _ast.walk(tree):
            if not (isinstance(node, _ast.FunctionDef) and node.name == "collect"):
                continue
            for sub in _ast.walk(node):
                if not isinstance(sub, _ast.Try):
                    continue
                handler_types = []
                for h in sub.handlers:
                    if h.type is None:
                        handler_types.append("Exception")
                    elif isinstance(h.type, _ast.Name):
                        handler_types.append(h.type.id)
                    elif isinstance(h.type, _ast.Attribute):
                        handler_types.append(h.type.attr)
                # The OUTER try/except chain is identified by having
                # BOTH NvdBatchFetchError AND a bare Exception handler.
                # Inner try/excepts (e.g. around _fetch_cves_batch) only
                # catch NvdBatchFetchError, so filtering on the
                # intersection ensures we're testing the right one.
                has_nbfe = "NvdBatchFetchError" in handler_types
                has_exception = "Exception" in handler_types
                if has_nbfe and has_exception:
                    matching_outer_trys.append(handler_types)

        assert matching_outer_trys, (
            "collect() must contain a try/except chain with BOTH "
            "NvdBatchFetchError AND Exception handlers — the outer "
            "chain that guards against the typed exception being "
            "caught by the generic handler."
        )
        for handler_types in matching_outer_trys:
            nbfe_idx = handler_types.index("NvdBatchFetchError")
            exc_idx = handler_types.index("Exception")
            assert nbfe_idx < exc_idx, (
                f"NvdBatchFetchError handler must be ordered BEFORE "
                f"the broader Exception handler. Found order: {handler_types}"
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
