"""2026-10 aging logic check (Kalin: "how the updates and aging of the weights is going on").

Two fixes:
1. Decay-retired nodes come back when re-observed. ``decay_ioc_confidence`` tags its retirements
   ``retired_by = 'decay'``; every node write reactivates such nodes (``active = true``,
   ``retired_at`` and the decay tier cleared). A manual decommission (``retired_at`` without the
   tag) still wins, as before.
2. The sync's edge SET never lowers an edge: ``match_type`` follows the stronger evidence and
   ``confidence_score`` keeps the maximum (the TLP ladder rule, applied to edges).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import MagicMock

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import neo4j_client as nc  # noqa: E402
from enrichment_jobs import _ACTOR_ALIAS_MERGE_PROPERTY_STRATEGY as _STRATEGY  # noqa: E402

_CLIENT_SRC = (_SRC / "neo4j_client.py").read_text()
_ENRICH_SRC = (_SRC / "enrichment_jobs.py").read_text()


def _client():
    client = nc.Neo4jClient.__new__(nc.Neo4jClient)
    client.driver = MagicMock()
    client._connection_healthy = True
    session = MagicMock()
    session.run.return_value.single.return_value = None
    client.driver.session.return_value.__enter__ = MagicMock(return_value=session)
    client.driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return client, session


def _cyphers(session):
    return "\n".join(c.args[0] for c in session.run.call_args_list if c.args)


class TestDecayTagsItsRetirements:
    def test_retire_tier_sets_retired_by_decay(self):
        block = _ENRICH_SRC[_ENRICH_SRC.index("SET n.active = false,") :][:200]
        assert "n.retired_at = datetime()" in block and "n.retired_by = 'decay'" in block

    def test_alias_merge_treats_retired_by_as_a_node_local_scalar(self):
        assert _STRATEGY["retired_by"] == "discard" and _STRATEGY["retired_at"] == "discard"


class TestEveryNodeWriteReactivatesDecayRetiredNodes:
    """The old guard ``n.active = CASE WHEN n.retired_at IS NOT NULL THEN n.active ELSE true END`` must be
    gone from every write path and replaced by the helper's text (manual decommission still wins)."""

    def test_old_guard_is_gone(self):
        assert not re.search(
            r"\.active = CASE WHEN [ni]\.retired_at IS NOT NULL THEN [ni]\.active ELSE true END", _CLIENT_SRC
        )

    def test_helper_text_is_spliced_at_every_site(self):
        first_line_n = nc._reactivation_clauses("n").split("\n")[0]
        first_line_i = nc._reactivation_clauses("i").split("\n")[0]
        assert _CLIENT_SRC.count(first_line_n) == 5, "merge_node_with_source, two batch merges, mark_inactive_nodes ×2"
        assert _CLIENT_SRC.count(first_line_i) == 1, "alert path"
        for v in ("n", "i"):
            body = nc._reactivation_clauses(v)
            assert (
                f"{v}.retired_at = CASE WHEN coalesce({v}.retired_by, '') = 'decay' THEN null ELSE {v}.retired_at END"
                in body
            )
            assert f"{v}.last_decayed_tier = null" in body
            # retired_by is cleared LAST so the two CASEs above still read the tag
            assert (
                body.index(f"{v}.retired_by = CASE")
                > body.index(f"{v}.retired_at = CASE")
                > body.index(f"{v}.active = CASE")
            )

    def test_manual_decommission_still_wins(self):
        body = nc._reactivation_clauses("n")
        assert "coalesce(n.retired_by, 'manual') <> 'decay' THEN n.active ELSE true END" in body, (
            "retired_at without the decay tag keeps the node inactive"
        )

    def test_single_merge_emits_the_clauses(self):
        client, session = _client()
        client.merge_actor({"name": "apt28", "tag": "mitre_attck", "zone": ["global"]}, source_id="mitre_attck")
        cy = _cyphers(session)
        assert nc._reactivation_clauses("n").split("\n")[0] in cy and "n.last_decayed_tier = null" in cy

    def test_indicator_batch_emits_the_clauses(self):
        client, session = _client()
        client.merge_indicators_batch(
            [{"indicator_type": "ipv4", "value": "203.0.113.5", "tag": "otx", "zone": ["global"]}], source_id="misp"
        )
        cy = _cyphers(session)
        assert "coalesce(n.retired_by, 'manual') <> 'decay'" in cy and "n.last_decayed_tier = null" in cy


class TestSyncEdgesNeverDowngrade:
    def _set_clause(self):
        start = _CLIENT_SRC.index('f"SET r.sources = {sources_dedup},')
        return _CLIENT_SRC[start : start + 1800]

    def test_confidence_keeps_the_maximum(self):
        body = self._set_clause()
        assert (
            "r.confidence_score = CASE WHEN r.confidence_score IS NULL OR {confidence_expr} > r.confidence_score"
            in body
        )
        assert "THEN {confidence_expr} ELSE r.confidence_score END" in body
        assert 'f"            r.confidence_score = {confidence_expr},' not in body, (
            "the unconditional overwrite is gone"
        )

    def test_label_follows_the_stronger_evidence_and_is_evaluated_first(self):
        body = self._set_clause()
        assert "r.match_type = CASE WHEN r.confidence_score IS NULL OR {confidence_expr} >= r.confidence_score" in body
        assert "THEN coalesce(row.match_type, r.match_type) ELSE r.match_type END" in body
        assert body.index("r.match_type = CASE") < body.index("r.confidence_score = CASE"), (
            "match_type must read the previous confidence"
        )

    def test_rendered_query_carries_both_ladders(self):
        client, session = _client()
        client.create_misp_relationships_batch(
            [
                {
                    "rel_type": "INDICATES",
                    "from_type": "Indicator",
                    "from_key": {"value": "203.0.113.5", "indicator_type": "ipv4"},
                    "to_type": "Malware",
                    "to_key": {"name": "emotet"},
                    "confidence": 0.6,
                    "match_type": "otx_pulse",
                    "misp_event_id": "7",
                }
            ],
            source_id="misp",
        )
        cy = _cyphers(session)
        assert "ELSE r.confidence_score END" in cy and "ELSE r.match_type END" in cy
