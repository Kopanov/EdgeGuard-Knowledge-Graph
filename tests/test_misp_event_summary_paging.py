"""``edgeguard stats --misp`` counts every page of MISP's ``/events/index`` (2026-10).

The summary read one page (``limit=500``): on a deployment after a 730-day baseline, one
``EdgeGuard-<source>-<date>`` event per source per day, the per-source table covered an arbitrary
first 500 events. It now pages until a short page and reports when it stopped at its page cap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
import requests

import edgeguard


class _Response:
    def __init__(self, payload: Any):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._payload


def _events(source: str, count: int, attributes: int = 2, first_id: int = 1) -> List[Dict[str, Any]]:
    """``count`` index rows with the event ids ``first_id`` onwards (every MISP index row has an id)."""
    return [
        {"id": str(first_id + n), "info": f"EdgeGuard-{source}-2026-01-{n:04d}", "attribute_count": attributes}
        for n in range(count)
    ]


def _install(monkeypatch: pytest.MonkeyPatch, pages: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """MISP answering ``pages`` in order (an empty list after the last); returns the params sent."""
    sent: List[Dict[str, Any]] = []

    class _Session:
        def __init__(self) -> None:
            self.headers: Dict[str, str] = {}

        def get(self, url: str, params: Dict[str, Any], **kwargs: Any) -> _Response:
            assert url.endswith("/events/index")
            sent.append(dict(params))
            page = params["page"]
            return _Response(pages[page - 1] if page <= len(pages) else [])

    monkeypatch.setattr(requests, "Session", _Session)
    # cmd_* load these from config at run time (_ensure_runtime_imports); a test sets them directly.
    monkeypatch.setattr(edgeguard, "MISP_URL", "https://misp.test", raising=False)
    monkeypatch.setattr(edgeguard, "MISP_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(edgeguard, "SSL_VERIFY", True, raising=False)
    return sent


def test_every_page_is_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    size = edgeguard._MISP_SUMMARY_PAGE_SIZE
    sent = _install(
        monkeypatch,
        [_events("nvd", size), _events("otx", size, first_id=size + 1), _events("cisa", 7, first_id=2 * size + 1)],
    )
    summary = edgeguard._fetch_misp_event_summary()
    assert [p["page"] for p in sent] == [1, 2, 3]
    assert all(p["limit"] == size and p["searchall"] == "EdgeGuard" for p in sent)
    assert summary["total_events"] == 2 * size + 7
    assert summary["total_attributes"] == 2 * (2 * size + 7)
    by_source = {row["source"]: row["events"] for row in summary["by_source"]}
    assert by_source == {"nvd": size, "otx": size, "cisa": 7}
    assert summary["truncated"] is False


def test_a_full_last_page_reads_the_next(monkeypatch: pytest.MonkeyPatch) -> None:
    size = edgeguard._MISP_SUMMARY_PAGE_SIZE
    sent = _install(monkeypatch, [_events("nvd", size)])
    summary = edgeguard._fetch_misp_event_summary()
    assert [p["page"] for p in sent] == [1, 2]
    assert summary["total_events"] == size and summary["truncated"] is False


def test_the_page_cap_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(edgeguard, "_MISP_SUMMARY_MAX_PAGES", 2)
    size = edgeguard._MISP_SUMMARY_PAGE_SIZE
    sent = _install(
        monkeypatch,
        [_events("nvd", size), _events("nvd", size, first_id=size + 1), _events("nvd", size, first_id=2 * size + 1)],
    )
    summary = edgeguard._fetch_misp_event_summary()
    assert [p["page"] for p in sent] == [1, 2]
    assert summary["total_events"] == 2 * size and summary["truncated"] is True


def test_the_cli_names_a_stop_at_the_cap(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(edgeguard, "_MISP_SUMMARY_MAX_PAGES", 1)
    size = edgeguard._MISP_SUMMARY_PAGE_SIZE
    _install(monkeypatch, [_events("nvd", size), _events("nvd", 1, first_id=size + 1)])
    warnings: List[str] = []
    monkeypatch.setattr(edgeguard, "warn", lambda msg: warnings.append(msg))
    summary = edgeguard._fetch_misp_event_summary()
    assert summary["truncated"] is True
    edgeguard._print_misp_event_summary(summary)
    out = capsys.readouterr().out
    assert f"MISP Events: {size} events" in out
    assert any("stopped after 1 page(s)" in w for w in warnings)


# 2026-11-02: MISP 2.5.45 ignores the query-string ``limit`` and ``page`` of ``/events/index`` and answers
# the whole listing on every page. Rows of the real answer after the 730-day baseline of 2026-11-01
# (``tests/fixtures/misp_events_index_2026_11_01.json``), with the ids of 600 or 500 events.
_INDEX_ROWS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "misp_events_index_2026_11_01.json").read_text()
)


def _real_rows(count: int) -> List[Dict[str, Any]]:
    return [dict(_INDEX_ROWS[n % len(_INDEX_ROWS)], id=str(n + 1)) for n in range(count)]


@pytest.mark.parametrize("count, gets", [(600, 1), (500, 2), (21, 1)])
def test_a_listing_repeated_on_every_page_counts_each_event_once(monkeypatch, count, gets):
    """600 rows (more than the limit): the whole listing, one GET; 500 rows: the second page brings no
    new id. Before, both read the listing again on every page up to the cap of 200 pages."""
    rows = _real_rows(count)
    sent = _install(monkeypatch, [rows] * edgeguard._MISP_SUMMARY_MAX_PAGES)
    summary = edgeguard._fetch_misp_event_summary()
    assert len(sent) == gets
    assert summary["total_events"] == count and summary["truncated"] is False
    expected = sum(int(r["attribute_count"]) for r in rows)
    assert summary["total_attributes"] == expected
