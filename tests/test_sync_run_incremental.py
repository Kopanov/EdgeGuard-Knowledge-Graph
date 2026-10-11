"""Direct tests of ``MISPToNeo4jSync.run`` window selection (2026-10): incremental = sync interval
+ one day of overlap, explicit ``since`` wins, full sync has no window, unavailable services
short-circuit before any fetch."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import run_misp_to_neo4j as rm  # noqa: E402


def _sync(monkeypatch, events=None, available=(True, "ok")):
    sync = rm.MISPToNeo4jSync(neo4j_client=MagicMock())
    seen = {}
    monkeypatch.setattr(sync, "check_services_available", lambda: available)
    monkeypatch.setattr(sync, "connect", lambda: True)

    def fake_fetch(since=None, sector=None):
        seen["since"], seen["sector"] = since, sector
        return events or []

    monkeypatch.setattr(sync, "fetch_edgeguard_events", fake_fetch)
    monkeypatch.setattr(rm, "record_collection_success", lambda *a, **k: None)
    monkeypatch.setattr(rm, "record_collection_failure", lambda *a, **k: None)
    return sync, seen


def test_incremental_window_is_sync_interval_plus_one_day(monkeypatch):
    monkeypatch.setenv("EDGEGUARD_SYNC_INTERVAL_DAYS", "5")
    sync, seen = _sync(monkeypatch)
    start = datetime.now(timezone.utc)
    assert sync.run(incremental=True) is True
    assert seen["sector"] is None
    window = start - seen["since"]
    assert timedelta(days=6, seconds=-10) <= window <= timedelta(days=6, seconds=10)


def test_default_incremental_window_is_four_days(monkeypatch):
    monkeypatch.delenv("EDGEGUARD_SYNC_INTERVAL_DAYS", raising=False)
    sync, seen = _sync(monkeypatch)
    start = datetime.now(timezone.utc)
    assert sync.run() is True
    assert timedelta(days=4, seconds=-10) <= start - seen["since"] <= timedelta(days=4, seconds=10)


def test_explicit_since_overrides_incremental(monkeypatch):
    sync, seen = _sync(monkeypatch)
    since = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert sync.run(incremental=True, since=since) is True
    assert seen["since"] == since


def test_full_sync_has_no_window(monkeypatch):
    sync, seen = _sync(monkeypatch)
    assert sync.run(incremental=False) is True
    assert seen["since"] is None


def test_unavailable_services_short_circuit_before_fetch(monkeypatch):
    sync, seen = _sync(monkeypatch, available=(False, "MISP unreachable"))
    assert sync.run(incremental=True) is False
    assert seen == {}
    assert sync._last_sync_failure_reason == "MISP unreachable"
    assert sync.stats["end_time"] is not None
