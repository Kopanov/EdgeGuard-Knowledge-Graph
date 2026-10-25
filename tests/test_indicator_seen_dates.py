"""The seen dates of an indicator (2026-10-25, ``indicator_seen_dates``): the statements that read them.

An indicator's ``SOURCED_FROM`` edges carry the sources' own first-seen / last-seen claims only for
the sources on the reliable first-seen allowlist (never OTX), and every source's latest report
(``r.last_reported_at``). The campaign build read the claims alone, so a campaign whose indicators
all came from OTX took EdgeGuard's import time as its first and last seen. The seen dates take per edge the claim, else the latest report; the
first seen date is never later than the indicator's first import; the indicator's own times only
when no edge dates it. The campaign build and the alert enrichment read the one definition.

Here: the fragments and the statements that carry them, without a database. What the dates come out
as on a real Neo4j (an OTX-only campaign written through the sync's write path, a report after the
first import, the guards of a stored campaign, the alert enrichment) is checked in
``tests/test_campaign_seen_dates_neo4j.py``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from stub_cleanup import clear_graphql_api_magicmock_stubs  # noqa: E402

# tests/test_graphql_api.py replaces neo4j_client (and neo4j) with MagicMocks when it is collected first;
# enrichment_jobs and alert_processor, which bind names of both at import, are then imported afresh.
if any(isinstance(m, MagicMock) for k, m in list(sys.modules.items()) if k == "neo4j_client" or k.startswith("neo4j")):
    clear_graphql_api_magicmock_stubs()
    sys.modules.pop("enrichment_jobs", None)

import indicator_seen_dates  # noqa: E402

FIRST_CLAIM = "coalesce(r.source_reported_first_at, r.last_reported_at)"
LAST_CLAIM = "coalesce(r.source_reported_last_at, r.last_reported_at)"


def _flat(statement: str) -> str:
    return " ".join(statement.split())


def _recording_session(rows_for):
    """A session that records every statement; ``rows_for(query)`` gives the record ``single()``
    returns (None for a statement the caller does not answer)."""
    statements = []
    session_kwargs = []

    def run(query, *args, **kwargs):
        statements.append(query)
        result = MagicMock()
        result.single.return_value = rows_for(query)
        result.__iter__ = lambda _self: iter([])
        return result

    session = MagicMock()
    session.run = run
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: False

    def open_session(**kwargs):
        session_kwargs.append(kwargs)
        return session

    driver = MagicMock()
    driver.session.side_effect = open_session
    return driver, statements, session_kwargs


class TestFragments:
    def test_each_edge_gives_the_claim_else_the_latest_report(self):
        assert indicator_seen_dates.edge_first("r") == FIRST_CLAIM
        assert indicator_seen_dates.edge_last("r") == LAST_CLAIM

    def test_the_first_seen_date_is_never_later_than_the_first_import(self):
        assert indicator_seen_dates.first_seen("x", "i") == (
            "CASE WHEN x IS NULL OR i.first_imported_at < x THEN i.first_imported_at ELSE x END"
        )

    def test_the_last_seen_date_falls_back_to_the_last_write_only_without_a_dated_edge(self):
        assert indicator_seen_dates.last_seen("y", "i") == "coalesce(y, i.last_updated)"

    def test_the_fragments_contain_no_quotes(self):
        for fragment in (
            indicator_seen_dates.edge_first("r"),
            indicator_seen_dates.edge_last("r"),
            indicator_seen_dates.first_seen("x", "i"),
            indicator_seen_dates.last_seen("y", "i"),
        ):
            assert "'" not in fragment and '"' not in fragment


class TestCampaignBuild:
    def test_step_1_aggregates_the_seen_dates_per_indicator_then_per_campaign(self, monkeypatch):
        import enrichment_jobs

        counts = {"campaigns": 0, "backfilled": 0, "deleted": 0, "names": [], "links": 0, "removed": 0, "pruned": 0}
        driver, statements, _ = _recording_session(lambda q: {**counts, "count": 0})
        client = MagicMock()
        client.driver = driver
        monkeypatch.setattr(enrichment_jobs, "query_pause", lambda: None)
        enrichment_jobs.build_campaign_nodes(client)
        (create,) = [s for s in statements if "MERGE (c:Campaign" in s]
        flat = _flat(create)
        per_indicator = (
            "OPTIONAL MATCH (i)-[r:SOURCED_FROM]->(:Source) WITH a, malware_list, i, "
            f"min({FIRST_CLAIM}) AS i_edges_first, max({LAST_CLAIM}) AS i_edges_last"
        )
        per_campaign = (
            "WITH a, malware_list, count(DISTINCT i) AS indicator_total, collect(DISTINCT i) AS all_indicators, "
            "min(CASE WHEN i_edges_first IS NULL OR i.first_imported_at < i_edges_first "
            "THEN i.first_imported_at ELSE i_edges_first END) AS first_seen, "
            "max(coalesce(i_edges_last, i.last_updated)) AS last_seen"
        )
        assert per_indicator in flat
        assert per_campaign in flat
        # The per-indicator stage comes first (one row per indicator, whatever its number of edges),
        # and both come before the campaign is written.
        assert flat.index(per_indicator) < flat.index(per_campaign) < flat.index("MERGE (c:Campaign")
        # No aggregate reads the claims alone any more.
        assert re.search(r"min\(\s*r\.source_reported_first_at\s*\)", create) is None
        assert re.search(r"max\(\s*r\.source_reported_last_at\s*\)", create) is None
        # The stored values still only move earlier / later.
        assert "AND (c.first_seen IS NULL OR first_seen < c.first_seen)" in flat
        assert "AND (c.last_seen IS NULL OR last_seen > c.last_seen)" in flat


class TestAlertEnrichment:
    INDICATOR = {
        "value": "203.0.113.7",
        "indicator_type": "ipv4",
        "zone": ["global"],
        "confidence_score": 0.5,
        "first_imported_at": "2026-10-22T23:00:00+00:00",
        "last_updated": "2026-10-24T22:00:00+00:00",
    }

    def _enrich(self, row):
        import alert_processor

        driver, statements, session_kwargs = _recording_session(lambda q: row if "RETURN i {" in q else None)
        client = MagicMock()
        client.driver = driver
        processor = alert_processor.AlertProcessor(neo4j_client=client)
        alert = alert_processor.ResilMeshAlert.from_dict(
            {"alert_id": "a-1", "zone": "global", "threat": {"indicator": "203.0.113.7", "type": "ip"}}
        )
        out = processor._enrich_indicator("203.0.113.7", "ipv4", alert, read_only=True)
        return out["enrichment"], statements, session_kwargs

    def test_the_indicator_statement_reads_the_seen_dates(self):
        _, statements, session_kwargs = self._enrich(None)
        (query,) = [s for s in statements if "RETURN i {" in s]
        flat = _flat(query)
        assert f"min({FIRST_CLAIM}) AS edges_first, max({LAST_CLAIM}) AS edges_last" in flat
        assert (
            "CASE WHEN edges_first IS NULL OR i.first_imported_at < edges_first "
            "THEN i.first_imported_at ELSE edges_first END AS first_seen"
        ) in flat
        assert "coalesce(edges_last, i.last_updated) AS last_seen" in flat
        assert not re.search(r"\b(CREATE|MERGE|SET|DELETE|REMOVE)\b", query), "the enrichment only reads"
        import alert_processor

        assert session_kwargs and all(
            kw.get("default_access_mode") == alert_processor.READ_ACCESS for kw in session_kwargs
        )

    def test_the_payload_carries_the_statement_dates_not_the_node_times(self):
        """The statement does the fallback; the payload takes its values as they are (an OTX indicator
        imported on 22 October and reported on 15 April is first and last seen on 15 April)."""
        row = {
            "indicator": dict(self.INDICATOR),
            "first_seen": "2026-04-15T00:00:00+00:00",
            "last_seen": "2026-04-15T00:00:00+00:00",
        }
        enrichment, _, _ = self._enrich(row)
        assert enrichment["first_seen"] == "2026-04-15T00:00:00+00:00"
        assert enrichment["last_updated"] == "2026-04-15T00:00:00+00:00"
