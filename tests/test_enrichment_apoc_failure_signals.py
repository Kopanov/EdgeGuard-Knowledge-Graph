"""Enrichment jobs fail on every ``apoc.periodic.iterate`` failure signal.

Two enrichment steps run ``apoc.periodic.iterate``: the campaign ``link_indicators``
step and the Vulnerability-CVE bridge. The first used to read only ``errorMessages``;
the other yielded only ``total``. A heap OOM inside a batch reports an empty
``errorMessages`` with ``failedBatches=1`` and ``batch.errors`` set (local 800-day
baseline, 2026-09-16), so both logged success over a partially written graph.

Each step now reads every failure column through ``neo4j_client.apoc_iterate_failures``
and raises ``RuntimeError``.
"""

import os
import sys
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

for _mod in ("enrichment_jobs", "neo4j_client"):
    if _mod in sys.modules:
        del sys.modules[_mod]

import enrichment_jobs  # noqa: E402
from neo4j_client import APOC_ITERATE_YIELD, apoc_iterate_failures  # noqa: E402


def _apoc_row(**overrides) -> Dict[str, Any]:
    row = {
        "batches": 1,
        "total": 10,
        "errorMessages": {},
        "failedBatches": 0,
        "failedOperations": 0,
        "wasTerminated": False,
        "batch": {"total": 1, "committed": 1, "failed": 0, "errors": {}},
        "operations": {"total": 10, "committed": 10, "failed": 0, "errors": {}},
        "updateStatistics": {"relationshipsCreated": 10},
    }
    row.update(overrides)
    return row


OOM_ROW = dict(
    failedBatches=1,
    batch={"total": 1, "committed": 0, "failed": 1, "errors": {"java.lang.OutOfMemoryError: Java heap space": 1}},
)
MAP_ERROR_ROW = dict(errorMessages={"/ by zero": 3}, failedBatches=3, failedOperations=3)

FAILURE_CASES = [
    pytest.param(OOM_ROW, "failedBatches=1", id="oom-empty-errorMessages"),
    pytest.param(MAP_ERROR_ROW, "/ by zero", id="errorMessages-map"),
]


class _Session:
    """Answers ``session.run`` by query text, so the call order does not matter."""

    def __init__(
        self,
        iterate_row: Dict[str, Any],
        *,
        records: List[Dict[str, Any]] = None,
    ):
        self.iterate_row = iterate_row
        self.records = records or []
        self.queries: List[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, *args, **params):
        self.queries.append(cypher)
        result = MagicMock()
        if "apoc.periodic.iterate" in cypher:
            row = dict(self.iterate_row)
            result.single = lambda: row
        elif "ThreatActor" in cypher and "RETURN DISTINCT" in cypher:
            result.__iter__ = lambda _self: iter(self.records)
        else:
            result.single = lambda: {
                "updated": 0,
                "campaigns": 1,
                "backfilled": 0,
                "links": 0,
                "removed": 0,
                "pruned": 0,
                "count": 0,
                "linked": 0,
                "c": 0,
                # 2026-10-16: Step 1b, the campaigns deleted for want of evidence
                "deleted": 0,
                "runs_removed": 0,
                "members_removed": 0,
                "names": [],
            }
        return result


def _client(session: _Session) -> MagicMock:
    client = MagicMock()
    client.driver.session = lambda **_kw: session
    return client


class TestHelper:
    def test_yield_constant_lists_every_failure_column(self):
        for column in ("errorMessages", "failedBatches", "failedOperations", "wasTerminated", "batch", "operations"):
            assert column in APOC_ITERATE_YIELD

    def test_clean_row_has_no_failures(self):
        assert apoc_iterate_failures(_apoc_row()) == []

    @pytest.mark.parametrize("overrides, expected", FAILURE_CASES)
    def test_failure_rows_are_reported(self, overrides, expected):
        assert any(expected in f for f in apoc_iterate_failures(_apoc_row(**overrides)))


class TestBridge:
    def test_clean_row_links(self):
        session = _Session(_apoc_row(linked=42))
        result = enrichment_jobs.bridge_vulnerability_cve(_client(session))
        assert result["linked"] == 42

    def test_query_yields_failure_columns(self):
        session = _Session(_apoc_row(linked=0))
        enrichment_jobs.bridge_vulnerability_cve(_client(session))
        query = next(q for q in session.queries if "apoc.periodic.iterate" in q)
        for column in ("failedBatches", "failedOperations", "wasTerminated", "batch", "operations"):
            assert column in query

    @pytest.mark.parametrize("overrides, expected", FAILURE_CASES)
    def test_failure_row_raises(self, overrides, expected):
        session = _Session(_apoc_row(linked=42, **overrides))
        with pytest.raises(RuntimeError, match=r"\[BRIDGE\]") as exc:
            enrichment_jobs.bridge_vulnerability_cve(_client(session))
        assert expected in str(exc.value)


class TestCampaignLinkIndicators:
    def _run(self, overrides):
        session = _Session(_apoc_row(**overrides), records=[{"name": "APT-Test"}])
        with patch.object(enrichment_jobs.time, "sleep", lambda *_: None):
            return enrichment_jobs.build_campaign_nodes(_client(session)), session

    def test_clean_row_completes(self):
        _, session = self._run({})
        query = next(q for q in session.queries if "apoc.periodic.iterate" in q)
        for column in ("failedBatches", "failedOperations", "wasTerminated", "batch", "operations"):
            assert column in query

    @pytest.mark.parametrize("overrides, expected", FAILURE_CASES)
    def test_failure_row_raises(self, overrides, expected):
        with pytest.raises(RuntimeError, match=r"\[CAMPAIGNS\] link_indicators") as exc:
            self._run(overrides)
        assert expected in str(exc.value)
