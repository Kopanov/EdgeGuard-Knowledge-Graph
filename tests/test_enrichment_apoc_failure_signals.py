"""Enrichment jobs fail on every ``apoc.periodic.iterate`` failure signal.

Three enrichment steps run ``apoc.periodic.iterate``: the campaign ``link_indicators``
step, the large-event confidence calibration and the Vulnerability-CVE bridge. The
first used to read only ``errorMessages``; the other two yielded only ``total``. A heap
OOM inside a batch reports an empty ``errorMessages`` with ``failedBatches=1`` and
``batch.errors`` set (local 800-day baseline, 2026-09-16), so all three logged success
over a partially written graph. The calibration job also swallowed a failed tier and
ended "complete".

Each step now reads every failure column through ``neo4j_client.apoc_iterate_failures``
and raises ``RuntimeError``; calibration attempts every tier, then raises if any failed.
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
        fail_small_path: bool = False,
    ):
        self.iterate_row = iterate_row
        self.records = records or []
        self.fail_small_path = fail_small_path
        self.queries: List[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def run(self, cypher: str, *args, **params):
        self.queries.append(cypher)
        if self.fail_small_path and "UNWIND $eids AS eid" in cypher:
            raise RuntimeError("small path boom")
        result = MagicMock()
        if "apoc.periodic.iterate" in cypher:
            row = dict(self.iterate_row)
            result.single = lambda: row
        elif "count(DISTINCT i) AS sz" in cypher:
            result.__iter__ = lambda _self: iter(self.records)
        elif "ThreatActor" in cypher and "RETURN DISTINCT" in cypher:
            result.__iter__ = lambda _self: iter(self.records)
        else:
            result.single = lambda: {
                "updated": 0,
                "campaigns": 1,
                "backfilled": 0,
                "links": 0,
                "pruned": 0,
                "count": 0,
                "linked": 0,
                "c": 0,
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


class TestCalibration:
    """Event sizes drive the tier: 5 indicators → tier 0-10 (small path, one UNWIND
    query); 5,000 → tier 501-inf (apoc path). Tiers run in ascending order."""

    def _run(self, iterate_row, records):
        session = _Session(iterate_row, records=records)
        with patch.object(enrichment_jobs.time, "sleep", lambda *_: None):
            return enrichment_jobs.calibrate_cooccurrence_confidence(_client(session)), session

    def test_clean_large_event_calibrates(self):
        results, session = self._run(_apoc_row(updated=7), [{"eid": "9001", "sz": 5000}])
        assert results["size 501–∞ → conf=0.3"] == 7
        query = next(q for q in session.queries if "apoc.periodic.iterate" in q)
        for column in ("failedBatches", "failedOperations", "wasTerminated", "batch", "operations"):
            assert column in query

    @pytest.mark.parametrize("overrides, expected", FAILURE_CASES)
    def test_failed_large_event_fails_the_job_after_all_tiers(self, overrides, expected, caplog):
        # Event 9001 (5,000 indicators) fails in tier 501-inf; event 7 (5 indicators)
        # sits in tier 0-10 and must still be calibrated through the small path.
        records = [{"eid": "9001", "sz": 5000}, {"eid": "7", "sz": 5}]
        with pytest.raises(RuntimeError, match=r"\[CALIBRATE\] 1 tier\(s\) failed") as exc:
            self._run(_apoc_row(updated=7, **overrides), records)
        assert expected in str(exc.value)
        assert "event 9001" in str(exc.value)

    def test_remaining_tiers_still_run_after_a_failed_tier(self):
        # Tier 0-10 (small path) fails first; tier 501-inf (apoc path) must still run,
        # then the job raises naming the failed tier.
        records = [{"eid": "7", "sz": 5}, {"eid": "9001", "sz": 5000}]
        session = _Session(_apoc_row(updated=7), records=records, fail_small_path=True)
        with patch.object(enrichment_jobs.time, "sleep", lambda *_: None):
            with pytest.raises(RuntimeError, match=r"1 tier\(s\) failed") as exc:
                enrichment_jobs.calibrate_cooccurrence_confidence(_client(session))
        assert "size 0\u201310" in str(exc.value) and "small path boom" in str(exc.value)
        assert any("apoc.periodic.iterate" in q for q in session.queries), "tier 501-inf must still run"
