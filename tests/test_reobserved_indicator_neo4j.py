"""A refreshed MISP attribute on a real Neo4j (2026-10): what the sync does with it.

``MISPWriter`` moves the ``last_seen`` of an indicator a source reports again
(``tests/test_misp_reobserved_indicator_refresh.py``). The edited attribute is parsed as the sync
parses it and merged with ``merge_indicators_batch`` onto a node that decay retired: the node's
``last_updated`` moves, the decay retirement is lifted, ``first_imported_at`` and the source's
first-seen claim stay where they were, and the source's last-seen claim takes the refreshed date.
Same guards as ``tests/test_actor_alias_merge_neo4j.py``: runs only with
``EDGEGUARD_IT_NEO4J_URI``, writes only nodes labelled ``EdgeGuardIT``, refuses any other node.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TESTS = Path(__file__).resolve().parent
for _p in (TESTS.parent / "src", TESTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from test_actor_alias_merge_neo4j import LABEL, URI, open_test_database  # noqa: E402  (same guards)

import neo4j_client  # noqa: E402

pytestmark = pytest.mark.skipif(not URI, reason="EDGEGUARD_IT_NEO4J_URI is not set (no throwaway Neo4j)")

FIXTURE = f"""
CREATE (s:Source:{LABEL} {{source_id: 'feodo_tracker'}})
CREATE (i:Indicator:{LABEL} {{indicator_type: 'ipv4', value: '203.0.113.10', uuid: 'u-i', source: ['feodo_tracker'],
        zone: ['global'], confidence_score: 0.4, edgeguard_managed: true,
        first_imported_at: datetime('2025-09-01T00:00:00Z'), last_updated: datetime('2025-09-01T00:00:00Z'),
        active: false, retired_at: datetime('2026-09-02T00:00:00Z'), retired_by: 'decay',
        last_decayed_tier: 'indicator-180-365'}})
CREATE (i)-[:SOURCED_FROM {{source: 'feodo_tracker', source_reported_first_at: datetime('2024-05-01T10:00:00Z'),
        source_reported_last_at: datetime('2024-06-01T00:00:00Z')}}]->(s)
"""


@pytest.fixture(scope="module")
def raw_driver():
    yield from open_test_database()


@pytest.fixture
def client(raw_driver):
    with raw_driver.session() as session:
        session.run(f"MATCH (n:{LABEL}) DETACH DELETE n")
        session.run(FIXTURE)
    c = neo4j_client.Neo4jClient(
        URI, os.getenv("EDGEGUARD_IT_NEO4J_USER", "neo4j"), os.getenv("EDGEGUARD_IT_NEO4J_PASSWORD", "")
    )
    assert c.connect()
    yield c
    c.close()


def _edited_attribute(refreshed: datetime) -> dict:
    """The stored Feodo Tracker attribute after the refresh, as MISP 2.5 lists it."""
    return {
        "id": "1203",
        "event_id": "41",
        "type": "ip-dst",
        "category": "Network activity",
        "to_ids": False,
        "uuid": "6f3c1d5e-0000-4000-8000-000000001203",
        "timestamp": str(int(refreshed.timestamp())),
        "comment": 'TF_META:{"malware_family": "Emotet", "last_seen": "2024-06-01", "last_online": "2024-06-01"}',
        "first_seen": "2024-05-01T10:00:00.000000+00:00",
        "last_seen": refreshed.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "value": "203.0.113.10",
        "Tag": [{"name": "source:Feodo-Tracker"}, {"name": "tlp:white"}, {"name": "zone:Global"}],
    }


def test_the_refreshed_attribute_moves_last_updated_and_lifts_the_decay_retirement(client, raw_driver):
    from run_misp_to_neo4j import MISPToNeo4jSync

    refreshed = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(microsecond=0)
    event = {"id": 41, "info": "EdgeGuard-feodo_tracker-2025-09-01", "date": "2025-09-01", "Tag": []}
    item, _ = MISPToNeo4jSync(neo4j_client=MagicMock()).parse_attribute(_edited_attribute(refreshed), event)
    before = datetime.now(timezone.utc)
    ok, errors = client.merge_indicators_batch([item], source_id="feodo_tracker")
    assert (ok, errors) == (1, 0)

    with raw_driver.session() as session:
        row = session.run(
            f"MATCH (i:Indicator:{LABEL} {{value: '203.0.113.10'}})-[r:SOURCED_FROM]->(:Source {{source_id: 'feodo_tracker'}}) "
            "RETURN i.last_updated AS lu, i.first_imported_at AS fi, i.active AS active, i.retired_at AS ra, "
            "i.retired_by AS rb, i.last_decayed_tier AS tier, "
            "r.source_reported_first_at AS first_at, r.source_reported_last_at AS last_at"
        ).single()
    assert row["lu"].to_native() >= before - timedelta(seconds=5), "last_updated moves to the sync's time"
    assert row["fi"].to_native() == datetime(2025, 9, 1, tzinfo=timezone.utc), "first import stays"
    assert row["active"] is True and row["ra"] is None and row["rb"] is None and row["tier"] is None
    assert row["first_at"].to_native() == datetime(2024, 5, 1, 10, tzinfo=timezone.utc), "first-seen claim stays"
    assert row["last_at"].to_native() == refreshed, "the refreshed last-seen claim is the latest"
