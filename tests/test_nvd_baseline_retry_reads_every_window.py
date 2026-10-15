"""An NVD baseline attempt after a failed one reads every publication window again (2026-10).

The baseline keeps the records of the windows it read in memory and pushes them to MISP after the
last window. When a window fetch failed, the attempt raised with the checkpoint at that window, and
the Airflow retry resumed there: the windows read before the failure (the newest, since the windows
run newest first) were never pushed, and the retry ended in success.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("NEO4J_PASSWORD", "test-pw-nvd-retry")
os.environ.setdefault("MISP_API_KEY", "test-key-nvd-retry")

from collectors import nvd_collector as nc  # noqa: E402


class _Writer:
    def __init__(self):
        self.pushed: list[str] = []

    def push_items(self, items, **_kw):
        self.pushed.extend(item["cve_id"] for item in items)
        return len(items), 0


def test_a_retry_after_a_window_abort_pushes_every_window(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_NVD_BASELINE_KEV_SWEEP", "false")
    monkeypatch.delenv("EDGEGUARD_NVD_EXTRA_CVE_IDS", raising=False)
    store: dict = {}

    def get_checkpoint(source):
        return dict(store.get(source, {}))

    def update_checkpoint(source, page=None, items_collected=None, extra=None, completed=None, **_kw):
        entry = store.setdefault(source, {})
        if page is not None:
            entry["current_page"] = page
        if extra:
            entry.update(extra)
        if completed is not None:
            entry["completed"] = completed

    now = nc._utc_now()
    windows = list(nc.iter_nvd_published_windows(now - nc.timedelta(days=730), now))
    assert len(windows) > 4
    failing_window = nc._to_nvd_pub_iso(windows[3][0])
    attempt = {"n": 1}

    def fetch_batch(self, pub_start_iso=None, pub_end_iso=None, start_index=0, limit=2000, extra_params=None):
        if attempt["n"] == 1 and pub_start_iso == failing_window:
            raise nc.NvdBatchFetchError("ReadTimeout")
        if start_index > 0:
            return []
        return [
            {
                "cve": {
                    "id": f"CVE-W-{pub_start_iso[:19]}",
                    "published": pub_start_iso[:-1],
                    "lastModified": pub_start_iso[:-1],
                    "descriptions": [{"lang": "en", "value": "x"}],
                }
            }
        ]

    with (
        patch.object(nc, "get_source_checkpoint", get_checkpoint),
        patch.object(nc, "update_source_checkpoint", update_checkpoint),
        patch.object(nc, "get_source_incremental", lambda _s: {}),
        patch.object(nc, "update_source_incremental", lambda _s, **_kw: None),
        patch.object(nc.time, "sleep", lambda _s: None),
        patch.object(nc.NVDCollector, "_fetch_cves_batch", fetch_batch),
        patch.object(nc.NVDCollector, "check_service_available", lambda self: True),
    ):
        first = _Writer()
        with pytest.raises(nc.NvdBatchFetchError):
            nc.NVDCollector(misp_writer=first).collect(baseline=True, baseline_days=730)
        assert first.pushed == [], "the failed attempt pushes nothing"
        assert store["nvd"]["nvd_window_idx"] == 3

        attempt["n"] = 2
        second = _Writer()
        status = nc.NVDCollector(misp_writer=second).collect(baseline=True, baseline_days=730)

    assert status.get("success") is True
    expected = {f"CVE-W-{nc._to_nvd_pub_iso(start)[:19]}" for start, _end in windows}
    assert set(second.pushed) == expected, "the retry pushes the windows read before the failure too"
