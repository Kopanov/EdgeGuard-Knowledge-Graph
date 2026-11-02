"""The fresh-baseline wipe counts each MISP event once and logs what it deleted (2026-11-02).

MISP 2.5.45 ignores ``limit`` and ``page`` in the query string of ``/events/index`` and answers the
whole listing on every page. The pre-wipe probe (``baseline_clean._probe_misp``) added up every page
until its 50-round cap, and the ``BASELINE_CLEAN`` line logged that probe as deleted: the 730-day
baseline of 2026-11-01 logged ``MISP EdgeGuard events: 700`` and ``deleted ... 700 MISP events`` for
the 14 events the wipe deleted (``✓ MISP cleared (14 EdgeGuard events deleted)``). The probe now counts
an event id once and stops at a page that brings no new id or is not full; the line takes the counts
the wipe reported, the Neo4j one from the clear of the scope (every node under ``wipe_scope=all``).

The index rows are the real ``/events/index`` answer of the test MISP after the 730-day baseline
(``tests/fixtures/misp_events_index_2026_11_01.json``, 21 events).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, List
from unittest.mock import MagicMock, patch

import pytest

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import baseline_clean  # noqa: E402
import neo4j_client as nc  # noqa: E402

INDEX_ROWS: List[dict] = json.loads((TESTS / "fixtures" / "misp_events_index_2026_11_01.json").read_text())


def _rows(count: int, first_id: int = 1) -> List[dict]:
    """``count`` index rows of the real shape, with the event ids ``first_id`` onwards."""
    rows = []
    for n in range(count):
        row = copy.deepcopy(INDEX_ROWS[n % len(INDEX_ROWS)])
        row["id"] = str(first_id + n)
        rows.append(row)
    return rows


class _Response:
    def __init__(self, body: Any, status_code: int = 200):
        self.body = body
        self.status_code = status_code

    def json(self):
        return self.body


class _Session:
    """``requests.Session`` of a MISP answering ``pages(page)`` to ``GET /events/index``."""

    def __init__(self, pages):
        self.pages = pages
        self.headers: dict = {}
        self.max_redirects = 30
        self.gets: List[dict] = []

    def get(self, url, params=None, **kwargs):
        assert url.endswith("/events/index")
        self.gets.append(dict(params))
        return self.pages(params["page"])


def _probe(monkeypatch, pages):
    session = _Session(pages)
    monkeypatch.setattr("requests.Session", lambda: session)
    return baseline_clean._probe_misp("https://misp.test", "k" * 40, True), session


def test_a_misp_that_ignores_paging_is_counted_once(monkeypatch):
    """The 14 events before the 730-day wipe, answered on every page: 14 after one GET (it was 700 after 50)."""
    rows = INDEX_ROWS[:14]
    (count, error), session = _probe(monkeypatch, lambda page: _Response(rows))
    assert (count, error) == (14, None)
    assert len(session.gets) == 1


def test_a_full_listing_repeated_on_every_page_stops_at_the_second(monkeypatch):
    """500 events (the page size), answered on every page: the second page brings no new id."""
    rows = _rows(500)
    (count, error), session = _probe(monkeypatch, lambda page: _Response(rows))
    assert (count, error) == (500, None)
    assert [g["page"] for g in session.gets] == [1, 2]


def test_a_listing_longer_than_the_limit_is_the_whole_listing(monkeypatch):
    rows = _rows(600)
    (count, _error), session = _probe(monkeypatch, lambda page: _Response(rows))
    assert count == 600 and len(session.gets) == 1


def test_a_misp_that_pages_is_read_to_the_end(monkeypatch):
    pages = {1: _rows(500), 2: _rows(3, first_id=501)}
    (count, error), session = _probe(monkeypatch, lambda page: _Response(pages.get(page, [])))
    assert (count, error) == (503, None)
    assert [g["page"] for g in session.gets] == [1, 2]
    assert all(g["limit"] == 500 and g["searchall"] == "EdgeGuard" for g in session.gets)


def test_rows_in_the_event_wrapper_are_counted_by_their_event_id(monkeypatch):
    rows = [{"Event": row} for row in INDEX_ROWS[:14]]
    (count, error), session = _probe(monkeypatch, lambda page: _Response({"response": rows}))
    assert (count, error) == (14, None) and len(session.gets) == 1
    assert baseline_clean.misp_index_row_id({"Event": {"id": 55}}) == "55"
    assert baseline_clean.misp_index_row_id({"id": "53"}) == "53"
    assert baseline_clean.misp_index_row_id(["not", "a", "row"]) is None


def test_only_edgeguard_events_count(monkeypatch):
    rows = INDEX_ROWS[:3] + [dict(INDEX_ROWS[3], id="999", info="Partner event")]
    (count, _error), _session = _probe(monkeypatch, lambda page: _Response(rows))
    assert count == 3


@pytest.mark.parametrize(
    "response, error",
    [
        (_Response([], status_code=500), "MISP returned HTTP 500"),
        (_Response({"errors": "x"}), None),
    ],
)
def test_the_probe_answers_errors_as_before(monkeypatch, response, error):
    (count, got), _session = _probe(monkeypatch, lambda page: response)
    assert (count, got) == (0, error)


def test_a_row_that_is_not_an_object_does_not_raise(monkeypatch):
    rows = INDEX_ROWS[:2] + ["garbage", None]
    (count, error), _session = _probe(monkeypatch, lambda page: _Response(rows))
    assert (count, error) == (2, None)


# --------------------------------------------------------------------------- what the wipe deleted


def _state(neo4j: int, total: int, misp: int, checkpoints: int):
    return baseline_clean.BaselineState(
        neo4j_count=neo4j,
        neo4j_total_count=total,
        neo4j_ok=True,
        misp_count=misp,
        misp_ok=True,
        checkpoint_count=checkpoints,
        checkpoint_ok=True,
    )


def _reset(monkeypatch, scope, clear_deletes):
    """``reset_baseline_data`` with the 730-day probe figures and a client whose clear deletes
    ``clear_deletes`` nodes (``Neo4jClient.clear_nodes_deleted``)."""
    client = MagicMock()
    client.connect.return_value = True

    def _clear(*_a, **_k):
        client.clear_nodes_deleted += clear_deletes
        return True

    client.clear_all.side_effect = _clear
    client.clear_edgeguard_managed.side_effect = _clear
    before = _state(145_429, 145_434, 700, 2)
    after = _state(0, 0, 0, 0)
    with (
        patch("neo4j_client.Neo4jClient", return_value=client),
        patch("baseline_clean._wipe_checkpoints"),
        patch("baseline_clean._wipe_misp_events", return_value=14),
        patch("baseline_clean.probe_baseline_state", side_effect=[before, after]),
        patch("baseline_clean.time.sleep"),
    ):
        return baseline_clean.reset_baseline_data(
            settle_seconds=0.0, verify_timeout_seconds=10.0, verify_poll_interval_seconds=0.1, wipe_scope=scope
        )


def test_the_summary_states_what_the_wipe_deleted(monkeypatch):
    result = _reset(monkeypatch, baseline_clean.WIPE_SCOPE_EDGEGUARD, 145_429)
    assert (result.neo4j_nodes_deleted, result.misp_events_deleted) == (145_429, 14)
    assert result.before.misp_count == 700, "the probe figure stays in the pre-wipe state"
    summary = result.deleted_summary()
    assert summary.startswith("deleted 145429 Neo4j nodes, 14 MISP events, 2 checkpoint entries (")


def test_wipe_scope_all_reports_every_node_the_clear_deleted(monkeypatch):
    """``clear_all`` deletes every node (145,434 here), not the 145,429 EdgeGuard-managed ones."""
    result = _reset(monkeypatch, baseline_clean.WIPE_SCOPE_ALL, 145_434)
    assert result.deleted_summary().startswith("deleted 145434 Neo4j nodes, 14 MISP events, ")


def test_a_result_without_the_wipe_counts_says_so():
    state = _state(1, 1, 2, 3)
    result = baseline_clean.CleanResult(before=state, after=state, duration_seconds=1.25, verify_attempts=1)
    assert result.deleted_summary() == "deleted unknown Neo4j nodes, unknown MISP events, 3 checkpoint entries (1.2s)"


# --------------------------------------------------------------------------- the Neo4j clears count


def _clear_client(batches):
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    session = client.driver.session.return_value.__enter__.return_value
    session.run.side_effect = batches
    return client


def test_clear_all_counts_the_nodes_it_deleted(monkeypatch):
    monkeypatch.setattr(nc, "record_destructive_op", lambda *a, **k: None)
    # the node count, the relationship pre-pass (empty), two delete batches, the Source nodes
    client = _clear_client(
        [
            MagicMock(single=lambda: {"count": 7}),
            MagicMock(single=lambda: {"deleted": 0}),
            MagicMock(single=lambda: {"deleted": 5}),
            MagicMock(single=lambda: {"deleted": 2}),
            MagicMock(),
        ]
    )
    client.clear_nodes_deleted = 0
    assert client.clear_all() is True
    assert client.clear_nodes_deleted == 7


def test_a_retried_clear_counts_every_attempt(monkeypatch):
    """A transient error after a first batch: the retry deletes the rest, and the count holds both."""
    monkeypatch.setattr(nc, "record_destructive_op", lambda *a, **k: None)
    monkeypatch.setattr(nc.time, "sleep", lambda *_a, **_k: None)
    first = [
        MagicMock(single=lambda: {"count": 5}),
        MagicMock(single=lambda: {"count": 0}),
        MagicMock(single=lambda: {"count": 0}),
        MagicMock(single=lambda: {"deleted": 0}),
        MagicMock(single=lambda: {"deleted": 3}),
    ]
    second = [
        MagicMock(single=lambda: {"count": 2}),
        MagicMock(single=lambda: {"count": 0}),
        MagicMock(single=lambda: {"count": 0}),
        MagicMock(single=lambda: {"deleted": 0}),
        MagicMock(single=lambda: {"deleted": 2}),
    ]
    client = _clear_client(first + [nc.neo4j_exceptions.TransientError("lock wait")] + second)
    assert baseline_clean._wipe_neo4j(client) == 5


def test_a_client_without_the_count_reports_none():
    class _Client:
        driver = object()

        def __setattr__(self, name, value):  # a client that keeps no count
            pass

        def clear_edgeguard_managed(self, label=None):
            return True

    assert baseline_clean._wipe_neo4j(_Client()) is None
